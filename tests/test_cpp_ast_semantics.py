"""Parsed C++ name lookup must not fabricate external Entry or call proof."""

from __future__ import annotations

import json
import os
import asyncio
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from harnesscreator.analysis import StaticAnalyzer
from harnesscreator.agents.entry import EntryGeneratorAgent
from harnesscreator.agents.entry import EntryVerifierAgent
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import ProofStatus, Verdict
from harnesscreator.models import EntryRecord, FunctionMetadata
from harnesscreator.agents.scenario import (
    InputActionAgent, _entry_destination_names, _entry_destination_positions,
    _source_output_parameter_field_callers, source_dataflow_consumers,
    source_receiver_field_navigation_candidates,
)


@unittest.skipUnless(shutil.which("clang++"), "Clang C++ compiler unavailable")
class CppAstSemanticsTest(unittest.TestCase):
    def test_uninitialized_file_static_state_declaration_is_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.cpp').write_text(
                'static char saved_key[32];\n'
                'bool matches(char key) { return saved_key[0] == key; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            function = next(item for item in bundle.functions.values()
                            if item.name == 'matches')
            self.assertEqual(
                [(item['name'], item['source'])
                 for item in function.referenced_global_declarations],
                [('saved_key', 'static char saved_key[32]')],
            )

    def test_parsed_handler_calls_remain_selectable_without_branch_fanout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "server.cpp"
            source.write_text(
                '#include <unistd.h>\n'
                'int decode(char const* p) { return p[0]; }\n'
                'int first() { return 1; }\n'
                'int second() { return 2; }\n'
                'void dispatch(char* p) { int cmd = decode(p); '
                'if (cmd == 65) first(); else second(); }\n'
                'void read_request(int fd) { char b[8]; '
                'int n = read(fd, b, sizeof b); if (n > 0) dispatch(b); }\n',
                encoding="utf-8",
            )
            database = root / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang++", "-c", str(source)],
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root, compile_database=database).index()
            functions = {item.name: item for item in bundle.functions.values()}
            entry = EntryRecord(
                entry_id="read", candidate_id="read-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=functions["read_request"].function_id,
                source_api="read", channel_kind="network",
                attacker_control="peer", provenance_path=[],
                consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=1.0, entry_line=6,
            )
            llm = ScriptedLLM([
                {"actions": [], "context_complete": False,
                 "requested_function_ids": [functions["dispatch"].function_id],
                 "rationale": "inspect the input consumer"},
                {"actions": [], "context_complete": True,
                 "requested_function_ids": [],
                 "rationale": "no handler source opened"},
            ])
            agent = InputActionAgent(llm, GraphStore(bundle), budget=2)
            self.assertEqual(asyncio.run(agent.run([entry])), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in llm.calls],
                ["read_request", "dispatch"],
            )
            handler_choices = {
                choice["name"]: choice
                for choice in llm.calls[1]["payload"]["frontier"]
                if choice["name"] in {"first", "second"}
            }
            self.assertEqual(set(handler_choices), {"first", "second"})
            for choice in handler_choices.values():
                self.assertTrue(any(
                    connection.get("edge_lines")
                    and connection.get("proof_policy", "").startswith(
                        "source-located call navigation only"
                    )
                    for connection in choice["connections"]
                ))
            self.assertEqual(agent.operation_seeds, [])

    def test_virtual_override_is_navigation_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'classes.hh').write_text(
                'struct Base { virtual void handle(int) = 0; void run(int); };\n'
                'struct Derived : Base { void handle(int) override; };\n'
                'struct Unrelated { void handle(int); };\n', encoding='utf-8',
            )
            (root / 'base.cpp').write_text(
                '#include "classes.hh"\nvoid Base::run(int x) { handle(x); }\n',
                encoding='utf-8',
            )
            (root / 'derived.cpp').write_text(
                '#include "classes.hh"\n'
                'void Derived::handle(int) {}\n'
                'void Unrelated::handle(int) {}\n', encoding='utf-8',
            )
            database = root / 'compile_commands.json'
            database.write_text(json.dumps([
                {'directory': str(root), 'file': str(root / name),
                 'arguments': ['clang++', '-I.', '-c', name]}
                for name in ('base.cpp', 'derived.cpp')
            ]))
            bundle = StaticAnalyzer(root, compile_database=database).index()
            run = next(item for item in bundle.functions.values()
                       if item.qualified_name == 'Base::run')
            derived = next(item for item in bundle.functions.values()
                           if item.qualified_name == 'Derived::handle')
            unrelated = next(item for item in bundle.functions.values()
                             if item.qualified_name == 'Unrelated::handle')
            candidates = [edge for edge in bundle.edges
                          if edge.caller_id == run.function_id]
            matching = [edge for edge in candidates
                        if edge.callee_id == derived.function_id]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0].kind, 'source_candidate')
            self.assertIn('virtual-override-candidate', matching[0].providers)
            self.assertFalse(any(edge.callee_id == unrelated.function_id
                                 for edge in candidates))
            self.assertEqual(
                GraphStore(bundle).callback_navigation_path(
                    run.function_id, derived.function_id,
                ),
                [run.function_id, derived.function_id],
            )
            self.assertEqual(
                GraphStore(bundle).causal_path_from_entry(
                    run.function_id, derived.function_id,
                    opened_function_ids=[run.function_id, derived.function_id],
                ), [],
            )

    def test_cross_unit_output_parameter_identifies_this_field_caller(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "api.hh").write_text(
                "int acquire(unsigned char *buffer);\n"
                "struct Session { unsigned char bytes[8]; void receive(); };\n",
                encoding="utf-8",
            )
            (root / "reader.cpp").write_text(
                '#include "api.hh"\n#include <unistd.h>\n'
                'int acquire(unsigned char *buffer) { return read(0, buffer, 8); }\n',
                encoding="utf-8",
            )
            (root / "server.cpp").write_text(
                '#include "api.hh"\n'
                'void Session::receive() { acquire(&bytes[0]); }\n'
                'void local_receive() { unsigned char bytes[8]; acquire(bytes); }\n',
                encoding="utf-8",
            )
            database = root / "compile_commands.json"
            database.write_text(json.dumps([
                {"directory": str(root), "file": str(root / name),
                 "arguments": ["clang++", "-I.", "-c", name]}
                for name in ("reader.cpp", "server.cpp")
            ]), encoding="utf-8")
            bundle = StaticAnalyzer(root, compile_database=database).index()
            reader = next(item for item in bundle.functions.values()
                          if item.file == "reader.cpp" and item.name == "acquire")
            session = next(item for item in bundle.functions.values()
                           if item.qualified_name == "Session::receive")
            local = next(item for item in bundle.functions.values()
                         if item.name == "local_receive")
            entry = EntryRecord(
                entry_id="cpp-field", candidate_id="cpp-field-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                entry_line=3, source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[], consumer_hints=[],
                evidence=[], unknowns=[], verifier_confidence=1.0,
            )
            leads = _source_output_parameter_field_callers(
                GraphStore(bundle), entry,
            )
            self.assertEqual(set(leads), {session.function_id})
            self.assertNotIn(local.function_id, leads)
            self.assertEqual(leads[session.function_id][0]["field_name"], "bytes")
            self.assertEqual(leads[session.function_id][0]["receiver_kind"], "this")
            storage_leads = _source_output_parameter_field_callers(
                GraphStore(bundle), entry, include_local=True,
            )
            self.assertEqual(set(storage_leads), {session.function_id, local.function_id})
            self.assertEqual(
                storage_leads[local.function_id][0]["storage_kind"],
                "local_or_parameter",
            )
            self.assertEqual(storage_leads[local.function_id][0]["storage_name"], "bytes")
            llm = ScriptedLLM([{
                "actions": [], "context_complete": False,
                "requested_function_ids": [], "rationale": "inspect caller next",
            }])
            agent = InputActionAgent(llm, GraphStore(bundle), budget=1)
            asyncio.run(agent.run([entry]))
            choice = next(
                item for item in llm.calls[0]["payload"]["frontier"]
                if item["function_id"] == session.function_id
            )
            self.assertTrue(any(
                connection.get("relation")
                == "source_output_parameter_field_handoff_candidate"
                and connection.get("field_name") == "bytes"
                and connection.get("proof_policy", "").startswith("navigation only")
                for connection in choice["connections"]
            ))
            local_choice = next(
                item for item in llm.calls[0]["payload"]["frontier"]
                if item["function_id"] == local.function_id
            )
            self.assertTrue(any(
                connection.get("relation")
                == "source_output_parameter_local_handoff_candidate"
                and connection.get("storage_name") == "bytes"
                and connection.get("proof_policy", "").startswith("navigation only")
                for connection in local_choice["connections"]
            ))

    def test_cross_unit_output_argument_uses_exact_linkage_on_same_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "api.hh").write_text(
                "namespace First { int acquire(char *buffer); }\n"
                "namespace Second { int acquire(char *buffer); }\n",
                encoding="utf-8",
            )
            (root / "reader.cpp").write_text(
                '#include "api.hh"\n#include <unistd.h>\n'
                'int First::acquire(char *buffer) { return read(0, buffer, 8); }\n'
                'int Second::acquire(char *buffer) { return read(0, buffer, 8); }\n',
                encoding="utf-8",
            )
            (root / "server.cpp").write_text(
                '#include "api.hh"\n'
                'void process() { char left[8], right[8]; '
                'First::acquire(left); Second::acquire(right); }\n',
                encoding="utf-8",
            )
            database = root / "compile_commands.json"
            database.write_text(json.dumps([
                {"directory": str(root), "file": str(root / name),
                 "arguments": ["clang++", "-I.", "-c", name]}
                for name in ("reader.cpp", "server.cpp")
            ]), encoding="utf-8")
            bundle = StaticAnalyzer(root, compile_database=database).index()
            graph = GraphStore(bundle)
            first = next(item for item in bundle.functions.values()
                         if item.qualified_name == "First::acquire")
            process = next(item for item in bundle.functions.values()
                           if item.name == "process")
            entry = EntryRecord(
                entry_id="first-read", candidate_id="first-candidate",
                status=Verdict.VERIFIED, entry_function_id=first.function_id,
                entry_line=3, source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[], consumer_hints=[],
                evidence=[], unknowns=[], verifier_confidence=1.0,
            )
            leads = _source_output_parameter_field_callers(
                graph, entry, include_local=True,
            )
            self.assertEqual(set(leads), {process.function_id})
            self.assertEqual(len(leads[process.function_id]), 1)
            self.assertEqual(leads[process.function_id][0]["storage_name"], "left")

    def test_cross_translation_unit_call_is_navigation_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'reader.cpp').write_text(
                'int receive(int value) { return value + 1; }\n', encoding='utf-8',
            )
            (root / 'server.cpp').write_text(
                'int receive(int);\n'
                'int process(int value) { return receive(value); }\n',
                encoding='utf-8',
            )
            database = root / 'compile_commands.json'
            database.write_text(json.dumps([
                {'directory': str(root), 'file': str(root / name),
                 'arguments': ['clang++', '-c', name]}
                for name in ('reader.cpp', 'server.cpp')
            ]))
            bundle = StaticAnalyzer(root, compile_database=database).index()
            reader = next(item for item in bundle.functions.values()
                          if item.file == 'reader.cpp' and item.name == 'receive')
            process = next(item for item in bundle.functions.values()
                           if item.file == 'server.cpp' and item.name == 'process')
            matches = [edge for edge in bundle.edges
                       if edge.caller_id == process.function_id
                       and edge.callee_id == reader.function_id]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].kind, 'source_candidate')
            self.assertIn('linkage-symbol-match', matches[0].providers)
            self.assertEqual(
                GraphStore(bundle).callback_navigation_path(
                    process.function_id, reader.function_id,
                ),
                [process.function_id, reader.function_id],
            )
            self.assertEqual(
                GraphStore(bundle).causal_path_from_entry(
                    process.function_id, reader.function_id,
                    opened_function_ids=[process.function_id, reader.function_id],
                ), [],
            )

    def test_out_of_line_methods_keep_owner_when_scope_operator_is_on_next_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.cpp').write_text(
                'struct Server { struct First { void handle(); }; '
                'struct Second { void handle(); }; };\n'
                'void Server::First\n::handle() {}\n'
                'void Server::Second\n::handle() {}\n',
                encoding='utf-8',
            )
            bundle = StaticAnalyzer(root).index()
            methods = [item for item in bundle.functions.values()
                       if item.name == 'handle' and 'clang-ast-cpp' in item.providers]
            self.assertEqual({item.qualified_name for item in methods}, {
                'Server::First::handle', 'Server::Second::handle',
            })

    def test_selector_call_inside_indirect_callee_is_not_outer_direct_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.cpp').write_text(
                'using Handler = int (*)(int);\n'
                'int first(int value) { return value + 1; }\n'
                'int second(int value) { return value - 1; }\n'
                'Handler handlers[] = {first, second};\n'
                'int select_handler(int value) { return value & 1; }\n'
                'int dispatch(int value) { return handlers[select_handler(value)](value); }\n'
            )
            bundle = StaticAnalyzer(root).index()
            by_name = {function.name: function for function in bundle.functions.values()}
            direct = by_name['dispatch'].direct_call_sites
            self.assertEqual(sum(
                site['callee_function_id'] == by_name['select_handler'].function_id
                for site in direct
            ), 1)
            self.assertFalse(any(
                site['callee_function_id'] in {
                    by_name['first'].function_id, by_name['second'].function_id,
                } for site in direct
            ))
            sites = by_name['dispatch'].indirect_table_call_sites
            self.assertEqual(len(sites), 1)
            self.assertEqual(sites[0]['table_name'], 'handlers')
            self.assertEqual(set(sites[0]['candidate_function_ids']), {
                by_name['first'].function_id, by_name['second'].function_id,
            })
            self.assertEqual(
                by_name['dispatch'].referenced_global_declarations[0]['name'],
                'handlers',
            )

    def test_compile_database_keeps_unrecorded_cpp_without_guessing_ast(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'built.cpp').write_text('int built() { return 1; }\n')
            (root / 'other.cpp').write_text(
                '#include <unavailable_generated_header.hpp>\n'
                'int other() { return 2; }\n'
            )
            database = root / 'compile_commands.json'
            database.write_text(json.dumps([{
                'directory': str(root), 'file': str(root / 'built.cpp'),
                'arguments': ['clang++', '-c', 'built.cpp'],
            }]))
            bundle = StaticAnalyzer(root, compile_database=database).index()
            self.assertEqual(bundle.completeness['clang_cpp_ast_parsed_files'], 1)
            self.assertEqual(bundle.completeness['clang_cpp_ast_failed_files'], 0)
            self.assertEqual(bundle.completeness['clang_cpp_ast_unrecorded_files'], 1)
            self.assertIn('other', {item.name for item in bundle.functions.values()})

    def test_large_source_file_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'large.cpp').write_text(
                '/*' + ('x' * 1_000_001) + '*/\n'
                'int parse_request() { return 1; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            self.assertEqual(bundle.completeness['clang_cpp_ast_parsed_files'], 1)
            self.assertIn('parse_request', {
                function.name for function in bundle.functions.values()
            })

    def test_default_ast_inventory_visits_all_small_cpp_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'first.cpp').write_text('int first() { return 1; }\n')
            (root / 'second.cpp').write_text('int second() { return 2; }\n')
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop('HC_CPP_AST_BUDGET_SECONDS', None)
                bundle = StaticAnalyzer(root).index()
            self.assertEqual(bundle.completeness['clang_cpp_ast_parsed_files'], 2)
            self.assertFalse(bundle.completeness['clang_cpp_ast_budget_exhausted'])

    def test_external_compile_database_supplies_generated_cpp_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            build = Path(temporary) / 'configured-build'
            root.mkdir()
            build.mkdir()
            source = root / 'server.cpp'
            source.write_text(
                '#include <buildconfig.hpp>\n'
                'extern "C" long read(int, void *, unsigned long);\n'
                'int chosen() { return 1; }\n'
                'int receive(int fd) { char data[2]; read(fd, data, 2); '
                'return data[0] ? chosen() : 0; }\n',
                encoding='utf-8',
            )
            (build / 'buildconfig.hpp').write_text('#define READY 1\n', encoding='utf-8')
            database = build / 'compile_commands.json'
            database.write_text(json.dumps([{
                'directory': str(build), 'file': str(source),
                'arguments': ['clang++', '-I', '.', '-std=c++17', '-c', str(source)],
            }]), encoding='utf-8')
            without = StaticAnalyzer(root).index()
            self.assertEqual(without.completeness['clang_cpp_ast_parsed_files'], 0)
            self.assertIn('buildconfig.hpp',
                          without.completeness['clang_cpp_ast_failure_diagnostics'][0]['reason'])
            with_database = StaticAnalyzer(root, compile_database=database).index()
            self.assertEqual(with_database.completeness['clang_cpp_ast_parsed_files'], 1)
            self.assertEqual(with_database.completeness['clang_cpp_ast_failure_diagnostics'], [])
            receiver = next(function for function in with_database.functions.values()
                            if function.name == 'receive')
            self.assertTrue(receiver.guarded_call_sites)

    def test_getline_condition_opens_same_receiver_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "server.cpp").write_text(
                "#include <iostream>\n#include <string>\n"
                "struct Session { std::string line; };\n"
                "void process(Session &s) { if (s.line == \"PING\") "
                "std::cout << \"PONG\\n\"; }\n"
                "int main() { Session s; while (std::getline(std::cin, s.line)) "
                "process(s); }\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
            main = next(item for item in bundle.functions.values()
                        if item.name == "main")
            process = next(item for item in bundle.functions.values()
                           if item.name == "process")
            entry = EntryRecord(
                entry_id="cpp-loop", candidate_id="candidate-cpp-loop",
                status=Verdict.VERIFIED, entry_function_id=main.function_id,
                entry_line=5, source_api="std::getline", channel_kind="stdin",
                attacker_control="local", provenance_path=[], consumer_hints=[],
                evidence=[], unknowns=[], verifier_confidence=1.0,
            )
            self.assertIn(
                process.function_id,
                source_receiver_field_navigation_candidates(
                    GraphStore(bundle), entry,
                ),
            )

    def test_posix_getline_keeps_first_argument_contract(self):
        function = FunctionMetadata.create(
            name="main", signature="int main(void)", file="server.c",
            start_line=1, end_line=1,
            source="int main(void) { char *line; size_t n; "
                   "getline(&line, &n, stdin); return 0; }",
            language="c",
        )
        entry = EntryRecord(
            entry_id="posix-getline", candidate_id="candidate-posix-getline",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            entry_line=1, source_api="getline", channel_kind="stdin",
            attacker_control="local", provenance_path=[], consumer_hints=[],
            evidence=[], unknowns=[], verifier_confidence=1.0,
        )
        self.assertEqual(_entry_destination_positions(function, entry), (0,))
        self.assertEqual(_entry_destination_names(function, entry), {"line"})

    def test_std_getline_taints_string_argument_not_input_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "server.cpp").write_text(
                "#include <iostream>\n"
                "#include <string>\n"
                "void consume(const std::string &line) { "
                "if (line == \"PING\") std::cout << \"PONG\\n\"; }\n"
                "int main() { std::string line; "
                "std::getline(std::cin, line); consume(line); }\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
            main = next(item for item in bundle.functions.values()
                        if item.name == "main")
            consumer = next(item for item in bundle.functions.values()
                            if item.name == "consume")
            entry = EntryRecord(
                entry_id="cpp-getline", candidate_id="candidate-cpp-getline",
                status=Verdict.VERIFIED, entry_function_id=main.function_id,
                entry_line=4, source_api="std::getline", channel_kind="stdin",
                attacker_control="local", provenance_path=[], consumer_hints=[],
                evidence=[], unknowns=[], verifier_confidence=1.0,
            )

            self.assertEqual(_entry_destination_positions(main, entry), (1,))
            self.assertEqual(_entry_destination_names(main, entry), {"line"})
            self.assertEqual(
                _entry_destination_positions(
                    main, replace(entry, source_api="getline"),
                ),
                (),
            )
            navigation, _ = source_dataflow_consumers(
                GraphStore(bundle), entry,
                function_limit=len(bundle.functions),
                include_all_consumers=True, include_candidate_edges=True,
            )
            self.assertIn(consumer.function_id,
                          [function_id for function_id, _, _ in navigation])
            self.assertEqual(
                _entry_destination_positions(
                    main, EntryRecord(
                        entry_id="custom-getline", candidate_id="candidate-custom",
                        status=Verdict.UNRESOLVED,
                        entry_function_id=main.function_id, entry_line=4,
                        source_api="custom::getline", channel_kind="unknown",
                        attacker_control="unknown", provenance_path=[],
                        consumer_hints=[], evidence=[], unknowns=[],
                        verifier_confidence=0.0,
                    ),
                ),
                (),
            )

    def test_qualified_and_unqualified_getline_alias_is_one_entry_site(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "server.cpp"
            source.write_text(
                "#include <iostream>\n"
                "#include <string>\n"
                "int main() { std::string line; "
                "return bool(std::getline(std::cin, line)); }\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
            main = next(item for item in bundle.functions.values()
                        if item.name == "main")
            self.assertIn("std::getline", main.external_calls)
            self.assertIn("getline", main.external_calls)
            candidates = asyncio.run(
                EntryGeneratorAgent(ScriptedLLM([{
                    "candidates": [], "inspected_function_ids": [],
                }])).run(bundle)
            )
            sites = [item for item in candidates
                     if item.function_id == main.function_id
                     and item.source_api.rsplit("::", 1)[-1] == "getline"]
            self.assertEqual(len(sites), 1)
            self.assertEqual(sites[0].source_api, "std::getline")

    def test_standard_cin_read_survives_large_header_ast(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "daemon.cpp"
            source.write_text(
                "#include <iostream>\n"
                "int process(char *buf) { return buf[0]; }\n"
                "int main() { char buf[8]; std::cin.read(buf, 8); "
                "return process(buf); }\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang++", "-std=c++17", "-c", str(source)],
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root).index()
            self.assertEqual(bundle.completeness["clang_cpp_ast_parsed_files"], 1)
            main = next(item for item in bundle.functions.values()
                        if item.name == "main")
            self.assertEqual(main.external_calls, ["std::basic_istream::read"])
            candidates = asyncio.run(
                EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
            )
            sites = [item for item in candidates
                     if item.source_api == "std::basic_istream::read"]
            self.assertEqual(len(sites), 1)
            self.assertEqual(sites[0].channel_hint, "stdin")
            entry = EntryRecord(
                entry_id="cpp-stdin", candidate_id=sites[0].candidate_id,
                status=Verdict.UNRESOLVED,
                entry_function_id=main.function_id,
                source_api=sites[0].source_api,
                channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[],
                unknowns=[], verifier_confidence=0.0,
                entry_line=sites[0].line,
            )
            self.assertEqual(_entry_destination_names(main, entry), {"buf"})
            verified = asyncio.run(EntryVerifierAgent(ScriptedLLM([{
                "status": "VERIFIED", "channel_kind": "stdin",
                "attacker_control": "stdin writer",
                "provenance_path": [{
                    "function_id": main.function_id,
                    "relation": "standard cin receives stdin bytes",
                }],
                "consumer_hints": [],
                "evidence": [{
                    "kind": "clang_ast_call", "function_id": main.function_id,
                    "file": main.file, "line": sites[0].line,
                    "detail": "std::cin.read stores bytes in buf",
                }],
                "unknowns": [], "confidence": 0.99,
                "rationale": "standard cin reads stdin",
                "first_acquisition_confirmed": True,
                "context_complete": True, "requested_function_ids": [],
            }]), GraphStore(bundle)).run(sites[0]))
            self.assertEqual(verified.status, Verdict.VERIFIED)
            self.assertTrue(any(
                edge.caller_id == main.function_id
                and bundle.functions[edge.callee_id].name == "process"
                and edge.kind == "source_candidate"
                for edge in bundle.edges
            ))
            graph = GraphStore(bundle)
            proven_consumers, _ = source_dataflow_consumers(
                graph, entry, function_limit=len(bundle.functions),
                include_all_consumers=True,
            )
            candidate_consumers, _ = source_dataflow_consumers(
                graph, entry, function_limit=len(bundle.functions),
                include_all_consumers=True, include_candidate_edges=True,
            )
            self.assertEqual(proven_consumers, [])
            process = next(item for item in bundle.functions.values()
                           if item.name == "process")
            self.assertEqual([item[0] for item in candidate_consumers],
                             [process.function_id])
            action_llm = ScriptedLLM([
                {"actions": [], "context_complete": True,
                 "requested_function_ids": [], "rationale": "inspect"}
                for _ in range(2)
            ])
            action_agent = InputActionAgent(action_llm, graph)
            self.assertEqual(asyncio.run(action_agent.run([entry])), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in action_llm.calls],
                ["main", "process"],
            )
            citation = [
                {"kind": "source", "function_id": item.function_id,
                 "line": item.start_line, "detail": "source call or result"}
                for item in (main, process)
            ]
            raw = {
                "name": "process byte", "description": "returns first byte",
                "dispatcher_function_id": process.function_id,
                "handler_function_id": process.function_id,
                "discriminator": "", "fields": [],
                "examples": [{"data_hex": "41", "bindings": [],
                              "rationale": "one byte", "origin": "source_candidate",
                              "evidence": citation}],
                "success_markers_hex": [], "failure_markers_hex": [],
                "success_evidence": citation, "failure_evidence": [],
                "response_bindings": [], "evidence": citation,
                "unknowns": [], "confidence": 0.9,
                "action_context_complete": True,
            }
            result = action_agent._validate_actions(
                entry, [raw], [main.function_id, process.function_id], [],
                context_complete=True, direct_consumer_ids=set(),
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, ProofStatus.POSSIBLE)
            self.assertTrue(any("Entry -> dispatcher" in value
                                for value in result[0].unknowns))

    def test_user_defined_member_read_is_not_stdin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "daemon.cpp"
            source.write_text(
                "struct Session { int read(char *p, int n) "
                "{ p[0] = 'X'; return n; } };\n"
                "int main() { char buf[8]; Session session; "
                "return session.read(buf, 8); }\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang++", "-std=c++17", "-c", str(source)],
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root).index()
            candidates = asyncio.run(
                EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
            )
            self.assertFalse(any(
                item.source_api.rsplit("::", 1)[-1] == "read"
                for item in candidates
            ))

    def test_user_defined_namespaced_read_is_not_stdin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "daemon.cpp"
            source.write_text(
                "namespace App { int read(char *p, int n) "
                "{ p[0] = 'X'; return n; } }\n"
                "int main() { char buf[8]; return App::read(buf, 8); }\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang++", "-std=c++17", "-c", str(source)],
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root).index()
            candidates = asyncio.run(
                EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
            )
            self.assertFalse(any(
                item.source_api.rsplit("::", 1)[-1] == "read"
                for item in candidates
            ))

    SOURCE = (
        "#include <sys/socket.h>\n"
        "class Session {\n"
        "public:\n"
        "  int recv(int n) { return n; }\n"
        "  int receive(int fd) { char data[8]; "
        "return ::recv(fd, data, sizeof(data), 0); }\n"
        "  int local(int n) { return recv(n); }\n"
        "};\n"
    )

    def test_global_recv_stays_external_and_member_call_is_only_navigation_without_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "session.cpp").write_text(self.SOURCE, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {item.name: item for item in bundle.functions.values()}
        self.assertEqual(bundle.completeness["clang_cpp_ast_parsed_files"], 1)
        self.assertIn("recv", by_name["receive"].external_calls)
        self.assertNotIn(by_name["recv"].function_id, by_name["receive"].callees)
        self.assertNotIn("recv", by_name["local"].external_calls)
        self.assertTrue(any(
            edge.caller_id == by_name["local"].function_id
            and edge.callee_id == by_name["recv"].function_id
            and edge.kind == "source_candidate"
            for edge in bundle.edges
        ))
        self.assertFalse(any(
            edge.caller_id == by_name["local"].function_id
            and edge.kind == "direct"
            for edge in bundle.edges
        ))

    def test_compile_database_promotes_exact_member_call_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "session.cpp"
            source.write_text(self.SOURCE, encoding="utf-8")
            (root / "compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang++", "-std=c++17", "-c", str(source)],
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {item.name: item for item in bundle.functions.values()}
        self.assertTrue(any(
            edge.caller_id == by_name["local"].function_id
            and edge.callee_id == by_name["recv"].function_id
            and edge.kind == "direct"
            and "clang-ast-cpp" in edge.providers
            for edge in bundle.edges
        ))
        self.assertNotIn(by_name["recv"].function_id, by_name["receive"].callees)

    def test_macro_expanded_global_recv_is_recorded_as_external_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "macro.cpp").write_text(
                "#include <sys/socket.h>\n"
                "#define GET_BYTES(fd, out) ::recv(fd, out, sizeof(out), 0)\n"
                "int receive(int fd) { char data[8]; return GET_BYTES(fd, data); }\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()

        receiver = next(item for item in bundle.functions.values()
                        if item.name == "receive")
        self.assertIn("recv", receiver.external_calls)
        self.assertTrue(any(
            site["api"] == "recv" and site["line"] == 3
            and site["macro_expansion"] is True
            and site["compile_command_available"] is False
            for site in receiver.external_call_sites
        ))
        candidates = asyncio.run(
            EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
        )
        macro_candidates = [
            item for item in candidates
            if item.function_id == receiver.function_id
            and item.source_api == "recv"
        ]
        self.assertEqual(len(macro_candidates), 1)
        self.assertEqual(macro_candidates[0].line, 3)
        self.assertEqual(macro_candidates[0].evidence[0].kind, "clang_ast_call")

        # A model verdict cannot turn a translation unit parsed without the
        # selected build's flags into an executable product Entry proof.
        candidate = macro_candidates[0]
        verdict = {
            "status": "VERIFIED", "channel_kind": "network",
            "attacker_control": "remote client",
            "provenance_path": [{
                "function_id": receiver.function_id,
                "relation": "candidate input acquisition",
            }],
            "consumer_hints": [],
            "evidence": [{
                "kind": "clang_ast_call", "function_id": receiver.function_id,
                "file": receiver.file, "line": candidate.line,
                "detail": "macro expansion resolves to recv",
            }],
            "unknowns": [], "confidence": 0.99,
            "rationale": "macro call", "first_acquisition_confirmed": True,
            "context_complete": True, "requested_function_ids": [],
        }
        for claimed_status in ("VERIFIED", "REJECTED"):
            record = asyncio.run(
                EntryVerifierAgent(
                    ScriptedLLM([{**verdict, "status": claimed_status}]),
                    GraphStore(bundle),
                ).run(candidate)
            )
            self.assertEqual(record.status, Verdict.UNRESOLVED)
            self.assertTrue(any(
                "compilation command" in item for item in record.unknowns
            ))

    def test_macro_site_uses_compile_database_without_inventing_a_textual_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "macro.cpp"
            source.write_text(
                "#include <sys/socket.h>\n"
                "#define GET_BYTES(fd, out) ::recv(fd, out, sizeof(out), 0)\n"
                "int receive(int fd) { char data[8]; return GET_BYTES(fd, data); }\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang++", "-std=c++17", "-c", str(source)],
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        receiver = next(item for item in bundle.functions.values()
                        if item.name == "receive")
        self.assertNotIn("recv(", receiver.source)
        self.assertTrue(any(
            site["api"] == "recv" and site["compile_command_available"] is True
            for site in receiver.external_call_sites
        ))
        candidates = asyncio.run(
            EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
        )
        self.assertEqual(len([
            item for item in candidates
            if item.function_id == receiver.function_id and item.source_api == "recv"
        ]), 1)
        site = next(site for site in receiver.external_call_sites
                    if site['api'] == 'recv')
        entry = EntryRecord(
            entry_id='macro-cpp-entry', candidate_id='macro-cpp-candidate',
            status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
            source_api='recv', channel_kind='network', attacker_control='remote',
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=site['line'],
        )
        self.assertEqual(_entry_destination_names(receiver, entry), {'data'})

    def test_macro_hidden_member_recv_is_not_a_network_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "session.h").write_text(
                "struct Session { int recv(int n) { return n; } };\n",
                encoding="utf-8",
            )
            (root / "main.cpp").write_text(
                '#include "session.h"\n'
                '#define GET_BYTES(s, n) s.recv(n)\n'
                'int receive(Session &s) { return GET_BYTES(s, 4); }\n',
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()

        receiver = next(item for item in bundle.functions.values()
                        if item.name == "receive")
        self.assertFalse(any(
            site["api"] == "recv" for site in receiver.external_call_sites
        ))
        candidates = asyncio.run(
            EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
        )
        self.assertFalse(any(
            item.function_id == receiver.function_id and item.source_api == "recv"
            for item in candidates
        ))

    def test_entry_scan_keeps_global_recv_but_not_member_recv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "session.cpp").write_text(self.SOURCE, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()
        candidates = asyncio.run(
            EntryGeneratorAgent(ScriptedLLM([{"candidates": []}])).run(bundle)
        )
        by_id = bundle.functions
        self.assertTrue(any(
            by_id[item.function_id].name == "receive" and item.source_api == "recv"
            for item in candidates
        ))
        self.assertFalse(any(
            by_id[item.function_id].name == "local" and item.source_api == "recv"
            for item in candidates
        ))
