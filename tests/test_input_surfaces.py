"""Independent input-boundary trials, including a command-free C program."""

from __future__ import annotations

import shutil
import json
import hashlib
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from harnesscreator.agents.entry import EntryGeneratorAgent
from harnesscreator.agents.input_surfaces import (
    InputSurfaceAgent, InputSurfaceCase, _explicit_request_fixtures,
    _source_linked_declaration_artifact,
    raw_case_runtime_action,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.declarations import extract_declarations
from harnesscreator.analysis import StaticAnalyzer, discover_usage_artifacts
from harnesscreator.llm.base import CachingLLM, RecordingLLM, ScriptedLLM
from harnesscreator.models import (
    ActionActor, AnalysisBundle, CallEdge, EntryRecord, EntrySiteKind,
    ActionExample, Evidence, FunctionMetadata, ProjectSpec, ProofStatus,
    ScenarioStatus, UsageArtifact, Verdict,
)
from harnesscreator.agents.scenario import InputActionAgent, ScenarioPlanner
from harnesscreator.orchestrator import (
    _raw_original_trial_project, _raw_trial_feedback,
    _raw_trial_transport_blocker,
    _source_draft_action_is_supported,
)
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier


def function(name: str, source: str, start: int) -> FunctionMetadata:
    return FunctionMetadata.create(
        name=name, signature=f"int {name}(void)", file="src/target.c",
        start_line=start, end_line=start + source.count("\n"), source=source,
    )


def entry_record(fn: FunctionMetadata, *, kind: str = "stdin") -> EntryRecord:
    evidence = Evidence("source", fn.function_id, fn.file, fn.start_line, "external byte acquisition")
    return EntryRecord(
        entry_id="raw-entry", candidate_id="candidate-raw", status=Verdict.VERIFIED,
        entry_function_id=fn.function_id, source_api="fread", channel_kind=kind,
        attacker_control="full", provenance_path=[], consumer_hints=[],
        evidence=[evidence], unknowns=[], verifier_confidence=0.9,
        site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        entry_line=fn.start_line, first_acquisition_confirmed=True,
    )


class InputSurfaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_macro_name_catalog_and_direct_definition_support_input_basis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "wire.h").write_text('#define REQUEST "PING\\r\\n"\n')
            reader = function(
                "receive_one", "int receive_one(void) { return read(0, data, 6); }", 1,
            )
            graph = GraphStore(AnalysisBundle(
                functions={reader.function_id: reader}, edges=[],
                declarations=extract_declarations(root, [root / "wire.h"]).all(),
            ))
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [],
                 "list_declarations": True, "declaration_name_filter": "REQUEST",
                 "context_complete": False, "rationale": "find request constant"},
                {"samples": [], "requested_function_ids": [],
                 "requested_declaration_name": "REQUEST", "list_declarations": False,
                 "context_complete": False, "rationale": "open request constant"},
                {"samples": [{
                    "data_hex": b"PING\r\n".hex(), "rationale": "macro request",
                    "evidence": [{"source_item_id": "wire.h", "line": 1,
                                  "detail": "literal request bytes"}],
                    "connection_prelude_marker_hex": "",
                    "connection_prelude_evidence": [],
                }], "requested_function_ids": [], "list_declarations": False,
                 "requested_declaration_name": "", "context_complete": True,
                 "rationale": "complete"},
            ])
            cases = await InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            ).run([entry_record(reader)])
            self.assertEqual([item["name"] for item in model.calls[1]["payload"]
                              ["current_usage_artifact"]["names"]], ["REQUEST"])
            self.assertIn("#define REQUEST", model.calls[2]["payload"]
                          ["current_usage_artifact"]["source_excerpt"])
            self.assertEqual([case.data_hex for case in cases], [b"PING\r\n".hex()])
            self.assertTrue(cases[0].trial_eligible)

    async def test_selector_inventory_requires_each_input_form_before_completion(self):
        reader = function(
            "receive_one", "int receive_one(void) { return parse(data); }\n", 1,
        )
        parser = function(
            "parse", "int parse(char *data) {\n switch (data[0]) {\n"
            " case 'A': return handle_a();\n"
            " case 'B': return handle_b();\n"
            " }\n return 0;\n}\n", 10,
        )
        handle_a = function("handle_a", "int handle_a(void) { return 1; }\n", 20)
        handle_b = function("handle_b", "int handle_b(void) { return 2; }\n", 21)
        functions = (reader, parser, handle_a, handle_b)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in functions}, edges=[],
        ))
        from harnesscreator.analysis.operation_seeds import extract_operation_seeds
        seeds = {item.discriminator: item for item in extract_operation_seeds([parser], graph)}

        def sample(value, line):
            return {"data_hex": value, "rationale": "complete one-byte input",
                    "evidence": [{"source_item_id": parser.function_id,
                                  "line": line, "detail": "selected input form"}]}

        def review(discriminator, value, line):
            return {"selector_id": seeds[discriminator].operation_seed_id,
                    "disposition": "INPUT_FORM", "data_hex": value,
                    "reason": "external data byte selects this handler",
                    "evidence": [{"source_item_id": parser.function_id,
                                  "line": line, "detail": "case label"}]}

        model = ScriptedLLM([
            {"samples": [], "selector_reviews": [],
             "requested_function_ids": [parser.function_id],
             "context_complete": False, "rationale": "read parser"},
            {"samples": [sample("41", 12)],
             "selector_reviews": [review("'A'", "41", 12)],
             "requested_function_ids": [], "context_complete": True,
             "rationale": "first form found"},
            {"samples": [sample("42", 13)],
             "selector_reviews": [review("'B'", "42", 13)],
             "requested_function_ids": [], "context_complete": True,
             "rationale": "second form found"},
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry_record(reader)])
        self.assertEqual([case.data_hex for case in cases], ["41", "42"])
        self.assertEqual(len(model.calls), 3)
        self.assertEqual(len({call["session_key"] for call in model.calls}), 1)
        self.assertEqual(model.calls[2]["payload"]["input_selector_candidates"][0]["discriminator"], "'B'")
        self.assertEqual([item["status"] for item in agent.selector_audit],
                         ["REVIEWED", "REVIEWED"])

    async def test_source_linked_global_values_can_be_opened_one_at_a_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "replies.h").write_text(
                '#ifndef REPLIES_H\n#define REPLIES_H\n'
                'static const char greeting[] = "220 Ready\\r\\n";\n#endif\n'
            )
            source = (
                '#include "replies.h"\n'
                'static const char commands[] = "PING\\r\\n";\n'
                'int receive_one(int fd) {\n'
                '  char buf[16];\n'
                '  recv(fd, buf, sizeof(buf), 0);\n'
                '  send(fd, greeting, sizeof(greeting)-1, 0);\n'
                '  return memcmp(buf, commands, 6);\n'
                '}\n'
            )
            (root / "daemon.c").write_text(source)
            fn = FunctionMetadata.create(
                name="receive_one", signature="int receive_one(int fd)",
                file="daemon.c", start_line=3, end_line=8,
                source="\n".join(source.splitlines()[2:]),
            )
            graph = GraphStore(AnalysisBundle(functions={fn.function_id: fn}, edges=[]))
            entry = replace(entry_record(fn, kind="tcp"), source_api="recv", entry_line=5)
            model = ScriptedLLM([
                {
                    "samples": [], "requested_function_ids": ["greeting"],
                    "context_complete": False, "rationale": "inspect server greeting",
                },
                {
                    "samples": [], "requested_function_ids": ["commands"],
                    "context_complete": False, "rationale": "inspect input command table",
                },
                {
                    "samples": [{
                        "data_hex": b"PING\r\n".hex(),
                        "rationale": "source-backed trial bytes",
                        "evidence": [{
                            "source_item_id": "daemon.c", "line": 2,
                            "detail": "the input command constant contains PING and CRLF",
                        }],
                        "connection_prelude_marker_hex": b"220".hex(),
                        "connection_prelude_evidence": [{
                            "source_item_id": "replies.h", "line": 3,
                            "detail": "the server greeting begins with 220",
                        }],
                    }],
                    "requested_function_ids": [], "context_complete": True,
                    "rationale": "one input hypothesis",
                },
            ])
            cases = await InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            ).run([entry])
            self.assertEqual(len(model.calls), 3)
            self.assertEqual(
                [call["payload"]["current_usage_artifact"]["path"]
                 for call in model.calls[1:]],
                ["replies.h", "daemon.c"],
            )
            self.assertEqual([case.data_hex for case in cases], [b"PING\r\n".hex()])
            self.assertTrue(cases[0].trial_eligible)
            self.assertEqual(cases[0].connection_prelude_marker_hex, b"220".hex())

    async def test_source_linked_global_lookup_rejects_comments_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one.h").write_text('static const char token[] = "one";\n')
            (root / "two.h").write_text('static const char token[] = "two";\n')
            (root / "daemon.c").write_text(
                '#include "one.h"\n#include "two.h"\n'
                'int receive_one(void) { /* token */ return 0; }\n'
            )
            fn = FunctionMetadata.create(
                name="receive_one", signature="int receive_one(void)",
                file="daemon.c", start_line=3, end_line=3,
                source='int receive_one(void) { /* token */ return 0; }',
            )
            graph = GraphStore(AnalysisBundle(functions={fn.function_id: fn}, edges=[]))
            self.assertIsNone(_source_linked_declaration_artifact(
                root, "token", [fn], graph,
            ))
            fn.source = 'int receive_one(void) { return token[0]; }'
            self.assertIsNone(_source_linked_declaration_artifact(
                root, "token", [fn], graph,
            ))
            (root / "daemon.c").write_text(
                '#if MODE_A\nstatic const char token[] = "one";\n'
                '#else\nstatic const char token[] = "two";\n#endif\n'
                'int receive_one(void) { return token[0]; }\n'
            )
            current = FunctionMetadata.create(
                name="receive_one", signature="int receive_one(void)",
                file="daemon.c", start_line=6, end_line=6,
                source='int receive_one(void) { return token[0]; }',
            )
            current_graph = GraphStore(AnalysisBundle(
                functions={current.function_id: current}, edges=[],
            ))
            self.assertIsNone(_source_linked_declaration_artifact(
                root, "token", [current], current_graph,
            ))

    async def test_ambiguous_socket_entry_still_yields_source_backed_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fn = function(
                "receive_one",
                "int receive_one(int fd) {\n"
                "  unsigned char data[1]; recv(fd, data, 1, 0);\n"
                "  return data[0] == 'A';\n}",
                1,
            )
            graph = GraphStore(AnalysisBundle(
                functions={fn.function_id: fn}, edges=[],
            ))
            entry = replace(
                entry_record(fn, kind="network socket"),
                source_api="recv", entry_line=2,
            )
            model = ScriptedLLM([{
                "samples": [{
                    "data_hex": "41", "rationale": "opened input comparison",
                    "evidence": [{
                        "source_item_id": fn.function_id,
                        "line": 3,
                        "detail": "input byte A is compared here",
                    }],
                }],
                "requested_function_ids": [],
                "context_complete": True,
                "rationale": "one source-backed hypothesis",
            }])
            trial_calls = []

            async def on_trial(_entry, cases):
                trial_calls.extend(cases)

            agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out"),
                on_trial_cases=on_trial,
            )
            cases = await agent.run([entry])
            self.assertEqual(len(model.calls), 1)
            self.assertEqual([case.data_hex for case in cases], ["41"])
            self.assertEqual(trial_calls, [])
            raw_action = raw_case_runtime_action(cases[0], entry, graph)
            self.assertIn(
                "transport is ambiguous",
                _raw_trial_transport_blocker(raw_action, "auto"),
            )
            self.assertEqual(
                _raw_trial_transport_blocker(raw_action, "tcp"), "",
            )
            self.assertTrue(any(
                "trial transport is unavailable" in item
                for item in agent.obligations
            ))

    async def test_same_request_keeps_distinct_server_first_hypothesis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "request.req"
            fixture.write_bytes(b"A")
            fn = function(
                "receive_one",
                'int receive_one(void) {\n  send(fd, "220 Ready\\r\\n", 11, 0);\n  return read(fd, data, 1);\n}',
                1,
            )
            graph = GraphStore(AnalysisBundle(functions={fn.function_id: fn}, edges=[]))
            citation = {"source_item_id": fn.function_id, "line": 2, "detail": "server greeting"}
            model = ScriptedLLM([{
                "samples": [{
                    "data_hex": "41", "rationale": "same request after greeting",
                    "evidence": [citation],
                    "connection_prelude_marker_hex": b"220".hex(),
                    "connection_prelude_evidence": [citation],
                }],
                "requested_function_ids": [], "context_complete": True,
                "rationale": "one input format and two connection-order hypotheses",
            }])
            agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out",
                            scenario_evidence_paths=[fixture]),
            )
            cases = await agent.run([entry_record(fn)])
            self.assertEqual(len(cases), 2)
            self.assertEqual({case.data_hex for case in cases}, {"41"})
            self.assertEqual(
                {case.connection_prelude_marker_hex for case in cases},
                {"", b"220".hex()},
            )

    async def test_early_trial_failure_does_not_reclassify_source_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "request.req"
            fixture.write_bytes(b"A")
            fn = function("receive_one", "int receive_one(void) { return 0; }", 1)
            graph = GraphStore(AnalysisBundle(functions={fn.function_id: fn}, edges=[]))
            model = ScriptedLLM([{
                "samples": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "fixture supplied",
            }])
            delivered = []

            async def trial(_entry, _cases):
                raise OSError("original-program adapter unavailable")

            async def final_delivery(_entry, cases):
                delivered.extend(cases)

            agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out",
                            scenario_evidence_paths=[fixture]),
                on_trial_cases=trial,
                on_entry_cases=final_delivery,
            )
            cases = await agent.run([entry_record(fn)])
            self.assertEqual(len(cases), 1)
            self.assertEqual(delivered, cases)
            self.assertEqual(cases[0].data_hex, "41")
            self.assertTrue(any("early input trial dispatch failed" in item
                                for item in agent.obligations))
            self.assertFalse(any("input hypothesis model failed" in item
                                 for item in agent.obligations))

    async def test_early_trial_programming_error_stops_before_more_source_turns(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "request.req"
            fixture.write_bytes(b"A")
            fn = function("receive_one", "int receive_one(void) { return 0; }", 1)
            graph = GraphStore(AnalysisBundle(functions={fn.function_id: fn}, edges=[]))
            model = ScriptedLLM([{
                "samples": [], "requested_function_ids": [],
                "context_complete": False, "rationale": "more source could be opened",
            }])

            async def broken_trial(_entry, _cases):
                raise NameError("shared trial callback has an unbound local")

            agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out",
                            scenario_evidence_paths=[fixture]),
                on_trial_cases=broken_trial,
            )
            with self.assertRaisesRegex(NameError, "unbound local"):
                await agent.run([entry_record(fn)])
            self.assertEqual(len(model.calls), 1)

    async def test_source_backed_sample_is_published_before_sibling_parser(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_a(char *data) { return data[0] == 'A'; }\n"
                "int parse_b(char *data) { return data[0] == 'B'; }\n"
                "int receive_one(int fd) {\n"
                "  char data[1];\n"
                "  read(fd, data, 1);\n"
                "  return parse_a(data) + parse_b(data);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = replace(entry_record(reader), source_api="read", entry_line=6)
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [
                    by_name["parse_a"].function_id],
                 "context_complete": True, "rationale": "inspect parser"},
                {"samples": [{
                    "data_hex": "41", "rationale": "A format hypothesis",
                    "evidence": [{"source_item_id": by_name["parse_a"].function_id,
                                  "line": 2, "detail": "parser checks A"}],
                }], "requested_function_ids": [by_name["parse_b"].function_id],
                 "context_complete": False, "rationale": "inspect sibling"},
                {"samples": [{
                    "data_hex": "42", "rationale": "B format hypothesis",
                    "evidence": [{"source_item_id": by_name["parse_b"].function_id,
                                  "line": 3, "detail": "parser checks B"}],
                }], "requested_function_ids": [],
                 "context_complete": True, "rationale": "done"},
            ])
            published = []

            async def on_trial_cases(_entry, cases):
                published.append((len(model.calls), [case.data_hex for case in cases]))

            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
                on_trial_cases=on_trial_cases,
            )
            cases = await agent.run([entry])
            self.assertEqual({case.data_hex for case in cases}, {"41", "42"})
            self.assertEqual(published, [(2, ["41"]), (3, ["42"])])

    async def test_first_trial_continues_to_sibling_format_in_same_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_a(char *data) { return data[0] == 'A'; }\n"
                "int parse_b(char *data) { return data[0] == 'B'; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "return parse_a(data) + parse_b(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = replace(entry_record(reader), source_api="read",
                            entry_line=reader.start_line)
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [
                    by_name["parse_a"].function_id],
                 "context_complete": False, "rationale": "inspect first parser"},
                {"samples": [{
                    "data_hex": "41", "rationale": "first parser compares A",
                    "evidence": [{"source_item_id": by_name["parse_a"].function_id,
                                  "line": by_name["parse_a"].start_line,
                                  "detail": "A comparison"}],
                }], "requested_function_ids": [],
                 "context_complete": True, "rationale": "trial hypothesis ready"},
                {"samples": [{
                    "data_hex": "42", "rationale": "second parser compares B",
                    "evidence": [{"source_item_id": by_name["parse_b"].function_id,
                                  "line": by_name["parse_b"].start_line,
                                  "detail": "B comparison"}],
                }], "requested_function_ids": [],
                 "context_complete": True, "rationale": "second format ready"},
            ])
            agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            self.assertEqual([case.data_hex for case in cases], ["41", "42"])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["receive_one", "parse_a", "parse_b"],
            )
            self.assertFalse(any(
                by_name["parse_b"].function_id in item["next_function_ids"]
                for item in agent.continuations
            ))

    async def test_first_entry_cases_are_available_before_second_entry_walk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "request.req"
            fixture.write_bytes(b"X\n")
            first = function("first", "int first(void) { return 0; }", 1)
            second = function("second", "int second(void) { return 0; }", 5)
            graph = GraphStore(AnalysisBundle(
                functions={item.function_id: item for item in (first, second)},
                edges=[],
            ))
            entries = [
                replace(entry_record(first), entry_id="first"),
                replace(entry_record(second), entry_id="second"),
            ]
            response = {
                "samples": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "fixture supplied",
            }
            model = ScriptedLLM([response, response])
            observed = []

            async def on_entry_cases(entry, cases):
                observed.append((entry.entry_id, len(model.calls),
                                 [case.data_hex for case in cases]))

            agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out",
                            scenario_evidence_paths=[fixture]),
                on_entry_cases=on_entry_cases,
            )
            cases = await agent.run(entries)
            self.assertEqual(len(cases), 2)
            self.assertEqual(observed, [
                ("first", 1, [b"X\n".hex()]),
                ("second", 2, [b"X\n".hex()]),
            ])

    async def test_action_walk_preserves_ambiguous_guarded_handoffs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int conditional(char *buf) { return buf[0] == 'A'; }\n"
                "int guarded(char *buf) { return buf[0]; }\n"
                "int else_only(char *buf) { return buf[0] + 2; }\n"
                "int always(char *buf) { return buf[0] + 1; }\n"
                "int receive(int fd) {\n"
                "  char buf[8];\n"
                "  read(fd, buf, sizeof(buf));\n"
                "  if (conditional(buf)) {\n"
                "    guarded(buf);\n"
                "  } else {\n"
                "    else_only(buf);\n"
                "  }\n"
                "  return always(buf);\n"
                "}\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader = by_name["receive"]
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line + 2
            model = ScriptedLLM([{
                "actions": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "ambiguous input uses",
            }])
            agent = InputActionAgent(model, GraphStore(indexed))
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["receive"],
            )
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name[name].function_id for name in
                 ("conditional", "guarded", "else_only", "always")},
            )
            self.assertEqual(agent.planned_branch_validations, 0)

    async def test_action_walk_keeps_direct_consumers_without_auto_sweep(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_a(char *buf) { return buf[0] == 'A'; }\n"
                "int parse_b(char *buf) { return buf[0] == 'B'; }\n"
                "int unrelated(void) { if (1) return 7; return 0; }\n"
                "int receive(int fd) {\n"
                "  char buf[8];\n"
                "  read(fd, buf, sizeof(buf));\n"
                "  parse_a(buf);\n"
                "  parse_b(buf);\n"
                "  return unrelated();\n"
                "}\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader = by_name["receive"]
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line + 2
            model = ScriptedLLM([{
                "actions": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "ambiguous parsers",
            }])
            agent = InputActionAgent(
                model, GraphStore(indexed), budget=3,
            )
            actions = await agent.run([entry])
            self.assertEqual(actions, [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["receive"],
            )
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name["parse_a"].function_id,
                 by_name["parse_b"].function_id},
            )

    async def test_direct_sibling_parsers_are_inspected_after_first_trial_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_a(char *buf) { return buf[0] == 'A'; }\n"
                "int parse_b(char *buf) { return buf[0] == 'B'; }\n"
                "int receive(int fd) {\n"
                "  char buf[8];\n"
                "  read(fd, buf, sizeof(buf));\n"
                "  parse_a(buf);\n"
                "  return parse_b(buf);\n"
                "}\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader, first, second = (
                by_name[name] for name in ("receive", "parse_a", "parse_b")
            )
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line + 2
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [first.function_id],
                 "context_complete": True, "rationale": "read call"},
                {"samples": [{
                    "data_hex": "41", "rationale": "first parser compares A",
                    "evidence": [{"source_item_id": first.function_id,
                                  "line": first.start_line,
                                  "detail": "parse_a compares A"}],
                }], "requested_function_ids": [second.function_id],
                 "context_complete": False, "rationale": "inspect second format"},
                {"samples": [{
                    "data_hex": "42", "rationale": "second parser compares B",
                    "evidence": [{"source_item_id": second.function_id,
                                  "line": second.start_line,
                                  "detail": "parse_b compares B"}],
                }], "requested_function_ids": [],
                 "context_complete": True, "rationale": "second format found"},
            ])
            agent = InputSurfaceAgent(
                model, GraphStore(indexed),
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["receive", "parse_a", "parse_b"],
            )
            self.assertEqual({case.data_hex for case in cases}, {"41", "42"})
            self.assertTrue(all(case.trial_eligible for case in cases))

    async def test_ambiguous_input_format_lead_resumes_without_losing_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_a(char *buf) { return buf[0] == 'A'; }\n"
                "int parse_b(char *buf) { return buf[0] == 'B'; }\n"
                "int receive(int fd) { char buf[1]; read(fd, buf, 1); "
                "return parse_a(buf) + parse_b(buf); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            entry = replace(
                entry_record(by_name["receive"]), source_api="read",
                entry_line=by_name["receive"].start_line,
            )
            project = ProjectSpec(source_root=root, output_root=root / "out")
            first_llm = ScriptedLLM([{
                "samples": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "cannot choose parser",
            }])
            first = InputSurfaceAgent(first_llm, graph, project)
            self.assertEqual(await first.run([entry]), [])
            self.assertEqual(len(first_llm.calls), 1)
            self.assertEqual(
                set(first.continuations[-1]["next_function_ids"])
                & {by_name["parse_a"].function_id, by_name["parse_b"].function_id},
                {by_name["parse_a"].function_id, by_name["parse_b"].function_id},
            )

            resumed_llm = ScriptedLLM([{
                "samples": [], "requested_function_ids": [],
                "context_complete": False, "rationale": "continue parser question",
            }, {
                "samples": [{
                    "data_hex": "41", "rationale": "A format hypothesis",
                    "evidence": [{
                        "source_item_id": by_name["parse_a"].function_id,
                        "line": by_name["parse_a"].start_line,
                        "detail": "A comparison",
                    }],
                }],
                "requested_function_ids": [], "context_complete": True,
                "rationale": "one trial format found",
            }])
            resumed = InputSurfaceAgent(
                resumed_llm, graph, project,
                resume_continuations=first.continuations,
            )
            cases = await resumed.run([entry])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in resumed_llm.calls],
                ["receive", "parse_a"],
            )
            self.assertEqual([case.data_hex for case in cases], ["41"])
            self.assertTrue(cases[0].trial_eligible)
            self.assertTrue(any(
                by_name["parse_b"].function_id in item["next_function_ids"]
                for item in resumed.continuations
            ))

    async def test_large_explicit_input_is_not_silently_cut_at_64k(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "request.req"
            data = b"A" * 70_000
            fixture.write_bytes(data)
            reader = function("receive", "int receive(void) { return 0; }", 1)
            graph = GraphStore(AnalysisBundle(
                functions={reader.function_id: reader}, edges=[],
            ))
            model_response = {
                "samples": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "user supplied bytes",
            }
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_evidence_paths=[fixture],
            )
            cases = await InputSurfaceAgent(
                ScriptedLLM([model_response]), graph, project,
            ).run([entry_record(reader)])
            self.assertEqual(len(cases), 1)
            self.assertEqual(bytes.fromhex(cases[0].data_hex), data)
            self.assertTrue(cases[0].trial_eligible)

            limited = InputSurfaceAgent(
                ScriptedLLM([model_response]), graph,
                replace(project, max_input_trial_bytes=65_536),
            )
            self.assertEqual(await limited.run([entry_record(reader)]), [])
            self.assertTrue(any(
                "operator-selected" in item for item in limited.obligations
            ))

    async def test_local_byte_read_can_find_format_in_unique_caller(self):
        reader_source = (
            "int read_line(int fd, char *out) {\n"
            "  char ch;\n"
            "  read(fd, &ch, 1);\n"
            "  if (ch != '\\n') out[0] = ch;\n"
            "  instrumentation(&ch);\n"
            "  return 1;\n}"
        )
        caller_source = (
            "int negotiate(int fd) {\n"
            "  char line[8];\n"
            "  if (read_line(fd, line) && line[0] == 'S') return 1;\n"
            "  return 0;\n}"
        )
        reader = FunctionMetadata.create(
            name="read_line", signature="int read_line(int fd, char *out)",
            file="src/daemon.c", start_line=1, end_line=7,
            source=reader_source,
        )
        instrumentation = FunctionMetadata.create(
            name="instrumentation", signature="void instrumentation(char *data)",
            file="src/daemon.c", start_line=10, end_line=10,
            source="void instrumentation(char *data) {}",
        )
        caller = FunctionMetadata.create(
            name="negotiate", signature="int negotiate(int fd)",
            file="src/daemon.c", start_line=20, end_line=24,
            source=caller_source,
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, instrumentation, caller)},
            edges=[
                CallEdge("read-instrumentation", reader.function_id,
                         instrumentation.function_id, 5, "direct"),
                CallEdge("negotiate-read", caller.function_id,
                         reader.function_id, 22, "direct"),
            ],
        ))
        entry = entry_record(reader)
        entry.source_api = "read"
        entry.entry_line = 3
        model = ScriptedLLM([
            {"samples": [], "requested_function_ids": [],
             "context_complete": False, "rationale": "format not yet located"},
            {"samples": [], "requested_function_ids": [],
             "context_complete": False, "rationale": "instrumentation is not format"},
            {"samples": [{
                "data_hex": "53", "rationale": "caller compares input with S",
                "evidence": [{"source_item_id": caller.function_id,
                              "line": 22, "detail": "caller checks S"}],
            }], "requested_function_ids": [],
             "context_complete": True, "rationale": "trial hypothesis"},
        ])
        with tempfile.TemporaryDirectory() as temporary:
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(Path(temporary), Path(temporary)),
            )
            cases = await agent.run([entry])
        self.assertEqual([call["payload"]["current_function"]["name"]
                          for call in model.calls],
                         ["read_line", "instrumentation", "negotiate"])
        self.assertEqual(len(cases), 1)
        self.assertTrue(cases[0].trial_eligible)

    async def test_unique_direct_return_caller_opens_before_parser_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; };\n"
                "int read_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return 1; }\n"
                "int parse(struct ctx *c) { return c->buf[0] == 'X'; }\n"
                "int drive(struct ctx *c, int fd) { "
                "if (read_one(c, fd)) return parse(c); return 0; }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader, caller, parser = (
                by_name[name] for name in ("read_one", "drive", "parse")
            )
            entry = entry_record(reader)
            entry.source_api = "read"
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [],
                 "context_complete": True, "rationale": "read wrapper has no format"},
                {"samples": [], "requested_function_ids": [parser.function_id],
                 "context_complete": False, "rationale": "inspect parse"},
                {"samples": [{
                    "data_hex": "58", "rationale": "parser compares X",
                    "evidence": [{
                        "source_item_id": parser.function_id,
                        "line": parser.start_line, "detail": "compares field with X",
                    }],
                }], "requested_function_ids": [],
                 "context_complete": True, "rationale": "byte hypothesis"},
            ])
            agent = InputSurfaceAgent(
                model, GraphStore(indexed),
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["read_one", "drive", "parse"],
            )
            self.assertEqual([case.data_hex for case in cases], ["58"])

            # More than one caller cannot be selected as the actual return
            # path by a count or source-name guess.
            extra = FunctionMetadata.create(
                name="other_caller", signature="int other_caller(struct ctx *c, int fd)",
                file="daemon.c", start_line=10, end_line=10,
                source="int other_caller(struct ctx *c, int fd) { return read_one(c, fd); }",
            )
            ambiguous = GraphStore(AnalysisBundle(
                functions={**indexed.functions, extra.function_id: extra},
                edges=[*indexed.edges, CallEdge(
                    "other-read", extra.function_id, reader.function_id,
                    10, "direct",
                )],
            ))
            stopped_model = ScriptedLLM([{
                "samples": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "unresolved return",
            }])
            stopped_agent = InputSurfaceAgent(
                stopped_model, ambiguous,
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            self.assertEqual(await stopped_agent.run([entry]), [])
            self.assertEqual(len(stopped_model.calls), 1)
            self.assertTrue(stopped_agent.continuations)
            next_ids = stopped_agent.continuations[0]["next_function_ids"]
            self.assertIn(caller.function_id, next_ids)
            self.assertIn(extra.function_id, next_ids)

    async def test_field_read_opens_explicitly_selected_sibling_callbacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; int (*next)(struct ctx *); };\n"
                "int parse_a(struct ctx *c) { return c->buf[0] == 'A'; }\n"
                "int parse_b(struct ctx *c) { return c->buf[0] == 'B'; }\n"
                "int read_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return 1; }\n"
                "int drive(struct ctx *c, int fd) {\n"
                "if (read_one(c, fd))\n"
                "  return c->next(c);\n"
                "return 0; }\n"
                "void setup(struct ctx *c, int mode) { "
                "if (mode) c->next = parse_a; else c->next = parse_b; }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader = by_name["read_one"]
            entry = entry_record(reader)
            entry.source_api = "read"
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [],
                 "context_complete": False, "rationale": "open caller"},
                {"samples": [], "requested_function_ids": [by_name["parse_a"].function_id],
                 "context_complete": False, "rationale": "inspect the first registered parser"},
                {"samples": [{
                    "data_hex": "41", "rationale": "first parser compares A",
                    "evidence": [{
                        "source_item_id": by_name["parse_a"].function_id,
                        "line": by_name["parse_a"].start_line,
                        "detail": "compares received byte with A",
                    }],
                }], "requested_function_ids": [by_name["parse_b"].function_id],
                 "context_complete": False, "rationale": "inspect other registered parser"},
                {"samples": [{
                    "data_hex": "42", "rationale": "parser compares B",
                    "evidence": [{
                        "source_item_id": by_name["parse_b"].function_id,
                        "line": by_name["parse_b"].start_line,
                        "detail": "compares received byte with B",
                    }],
                }], "requested_function_ids": [],
                 "context_complete": True, "rationale": "trial-byte hypothesis"},
            ])
            agent = InputSurfaceAgent(
                model, GraphStore(indexed),
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            opened = [call["payload"]["current_function"]["name"]
                      for call in model.calls]
            self.assertEqual(opened[:2], ["read_one", "drive"])
            self.assertEqual(set(opened[2:]), {"parse_a", "parse_b"})
            self.assertEqual([case.data_hex for case in cases], ["41", "42"])
            self.assertTrue(all(case.trial_eligible for case in cases))

    async def test_nested_read_destination_helper_is_inspected_without_format_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; };\n"
                "char *buffer_ptr(struct ctx *c) { return c->buf; }\n"
                "int read_one(struct ctx *c, int fd) { "
                "return read(fd, buffer_ptr(c), 8); }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            entry = entry_record(by_name["read_one"])
            entry.source_api = "read"
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [],
                 "context_complete": True, "rationale": "format unknown"},
                {"samples": [], "requested_function_ids": [],
                 "context_complete": True, "rationale": "only buffer origin known"},
            ])
            agent = InputSurfaceAgent(
                model, GraphStore(indexed),
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["read_one", "buffer_ptr"],
            )
            self.assertTrue(agent.continuations)

    async def test_multiple_return_callers_remain_unresolved_without_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; int (*next_a)(struct ctx *); "
                "int (*next_b)(struct ctx *); };\n"
                "int parse_a(struct ctx *c) { return c->buf[0] == 'A'; }\n"
                "int parse_b(struct ctx *c) { return c->buf[0] == 'B'; }\n"
                "int read_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return 1; }\n"
                "int drive_a(struct ctx *c, int fd) {\n"
                "if (read_one(c, fd))\n"
                "  return c->next_a(c);\n"
                "return 0; }\n"
                "int drive_b(struct ctx *c, int fd) {\n"
                "if (read_one(c, fd))\n"
                "  return c->next_b(c);\n"
                "return 0; }\n"
                "void setup(struct ctx *c) { c->next_a = parse_a; "
                "c->next_b = parse_b; }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            entry = entry_record(by_name["read_one"])
            entry.source_api = "read"
            model = ScriptedLLM([{
                "samples": [], "requested_function_ids": [],
                "context_complete": False, "rationale": "return caller is ambiguous",
            }])
            agent = InputSurfaceAgent(
                model, GraphStore(indexed),
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"]
                      for call in model.calls]
            self.assertEqual(opened[0], "read_one")
            self.assertEqual(opened, ["read_one"])
            self.assertTrue(agent.continuations)
            next_ids = agent.continuations[0]["next_function_ids"]
            self.assertIn(by_name["drive_a"].function_id, next_ids)
            self.assertIn(by_name["drive_b"].function_id, next_ids)
            resumed_model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [],
                 "context_complete": False, "rationale": "resume return caller"},
                {"samples": [], "requested_function_ids": [],
                 "context_complete": False, "rationale": "other caller remains"},
            ])
            resumed = InputSurfaceAgent(
                resumed_model, GraphStore(indexed),
                ProjectSpec(source_root=root, output_root=root / "out"),
                resume_continuations=agent.continuations,
            )
            self.assertEqual(await resumed.run([entry]), [])
            resumed_names = [
                call["payload"]["current_function"]["name"]
                for call in resumed_model.calls
            ]
            self.assertEqual(resumed_names[0], "read_one")
            self.assertIn(resumed_names[1], {"drive_a", "drive_b"})
            self.assertEqual(len(resumed_names), 2)
            remaining = {
                by_name["drive_a"].function_id,
                by_name["drive_b"].function_id,
            } - {by_name[resumed_names[1]].function_id}
            self.assertTrue(remaining.issubset(
                set(resumed.continuations[0]["next_function_ids"])
            ))




    async def test_field_input_continues_after_premature_model_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; };\n"
                "int handle(struct ctx *x) { return x->buf[0] == 'X'; }\n"
                "int parse(struct ctx *x) { return handle(x); }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return parse(c); }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader, parser, handler = (
                by_name[name] for name in ("receive_one", "parse", "handle")
            )
            entry = entry_record(reader)
            entry.source_api = "read"
            response = lambda: {
                "samples": [], "requested_function_ids": [],
                "context_complete": True, "rationale": "no format here",
            }
            sample = {
                "samples": [{
                    "data_hex": "58", "rationale": "handler checks X",
                    "evidence": [{
                        "source_item_id": handler.function_id,
                        "line": handler.start_line,
                        "detail": "compares the acquired field with X",
                    }],
                }],
                "requested_function_ids": [], "context_complete": True,
                "rationale": "byte hypothesis only",
            }
            model = ScriptedLLM([response(), response(), sample])
            project = ProjectSpec(source_root=root, output_root=root / "out")
            cases = await InputSurfaceAgent(
                model, GraphStore(indexed), project,
            ).run([entry])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["receive_one", "parse", "handle"],
            )
            self.assertEqual([case.data_hex for case in cases], ["58"])
            self.assertTrue(cases[0].trial_eligible)

            # An Introspector/reported edge is a navigation candidate. It
            # cannot silently turn into a direct source path or a byte proof.
            candidate_only = GraphStore(AnalysisBundle(
                functions=indexed.functions,
                edges=[replace(edge, kind="reported")
                       if edge.caller_id == reader.function_id else edge
                       for edge in indexed.edges],
            ))
            candidate_model = ScriptedLLM([response()])
            candidate_agent = InputSurfaceAgent(
                candidate_model, candidate_only, project,
            )
            self.assertEqual(await candidate_agent.run([entry]), [])
            self.assertEqual(len(candidate_model.calls), 1)
            self.assertTrue(candidate_agent.continuations)
            self.assertIn(
                parser.function_id,
                candidate_agent.continuations[0]["next_function_ids"],
            )

    async def test_field_backed_format_reader_is_selectable_beyond_entry_frontier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; };\n"
                "int handle(struct ctx *x) { return x->buf[0] == 'X'; }\n"
                "int parse(struct ctx *x) { return handle(x); }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return parse(c); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader, handler = by_name["receive_one"], by_name["handle"]
            entry = entry_record(reader)
            entry.source_api = "read"
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": [handler.function_id],
                 "context_complete": False, "rationale": "open field consumer"},
                {"samples": [
                    {"data_hex": "58", "rationale": "unsupported first guess"},
                    {"data_hex": "58", "rationale": "source byte hypothesis",
                     "evidence": [{"source_item_id": handler.function_id,
                                   "line": handler.start_line,
                                   "detail": "handler compares input with X"}]},
                ],
                 "requested_function_ids": [], "context_complete": True,
                 "rationale": "trial only"},
            ])
            cases = await InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            ).run([entry])
            first_choices = model.calls[0]["payload"]["available_function_ids"]
            self.assertTrue(any(
                choice["function_id"] == handler.function_id and any(
                    relation["relation"] == "receiver_field_handoff_candidate"
                    for relation in choice["connections"]
                ) for choice in first_choices
            ))
            self.assertEqual(model.calls[1]["payload"]["current_function"]["name"],
                             "handle")
            self.assertEqual([case.data_hex for case in cases], ["58"])
            self.assertTrue(cases[0].trial_eligible)

    async def test_indexed_c_client_remains_available_as_input_usage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "server.c").write_text(
                "#include <unistd.h>\n"
                "int read_record(int fd) { char data[8]; return read(fd, data, 8); }\n",
                encoding="utf-8",
            )
            client = root / "test" / "client.c"
            client.parent.mkdir()
            client.write_text(
                "#include <unistd.h>\n"
                'int send_request(int fd) { return write(fd, "PING\\n", 5); }\n',
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(
                function for function in graph.bundle.functions.values()
                if function.name == "read_record"
            )
            artifacts = discover_usage_artifacts(root, graph.bundle)
            client_artifact = next(
                item for item in artifacts if item.path == "test/client.c"
            )
            self.assertTrue(client_artifact.function_ids)
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": ["test/client.c"],
                 "context_complete": False, "rationale": "read client usage"},
                {"samples": [{"data_hex": b"PING\n".hex(),
                              "rationale": "client source literal",
                              "evidence": [{"source_item_id": "test/client.c",
                                            "line": 2,
                                            "detail": "client writes PING and newline"}]}],
                 "requested_function_ids": [], "context_complete": True,
                 "rationale": "trial only"},
            ])
            project = ProjectSpec(source_root=root, output_root=root / "out")
            cases = await InputSurfaceAgent(
                model, graph, project, usage_artifacts=artifacts,
            ).run([entry_record(reader)])
            self.assertEqual([case.data_hex for case in cases], [b"PING\n".hex()])
            self.assertTrue(cases[0].trial_eligible)
            self.assertEqual(cases[0].inspected_usage_paths, ["test/client.c"])
            self.assertIn('write(fd, "PING',
                          model.calls[1]["payload"]["current_usage_artifact"]["source"])

    async def test_silent_original_trial_preserves_input_without_claiming_delivery(self):
        reader = function("read_record", "int read_record(void) { return 0; }", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        entry = entry_record(reader)
        case = InputSurfaceCase(
            case_id="silent-trial", entry_id=entry.entry_id,
            entry_function_id=reader.function_id,
            source_api="fread", channel_kind="stdin", data_hex="4142",
            origin="user_request_fixture", rationale="supplied request",
        )
        action = raw_case_runtime_action(case, entry, graph)
        feedback = _raw_trial_feedback(action, case.origin, SimpleNamespace(
            observations=[], status=ScenarioStatus.UNPROVEN,
            rationale="no response observed",
        ))
        self.assertEqual(feedback[0]["request_hex"], "4142")
        self.assertEqual(feedback[0]["response_hex"], "")
        self.assertEqual(feedback[0]["request_write_completed"], "false")
        self.assertIn("delivery", feedback[0]["proof_boundary"])
        submitted = _raw_trial_feedback(action, case.origin, SimpleNamespace(
            observations=[SimpleNamespace(
                request_hex="4142", response_hex="",
                request_write_completed=True,
                detail="transport/response failure: TimeoutError",
            )],
            status=ScenarioStatus.UNPROVEN,
        ))
        self.assertEqual(submitted[0]["request_write_completed"], "true")
        self.assertIn("peer receipt", submitted[0]["proof_boundary"])

    async def test_usage_inventory_pages_preserve_later_files(self):
        reader = function("read_record", "int read_record(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        entry = entry_record(reader)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            last = root / "test" / "client_128.py"
            last.parent.mkdir()
            last.write_text('socket.sendall(b"PING\\n")\n', encoding="utf-8")
            artifacts = [UsageArtifact(
                path=f"test/client_{number:03d}.py", kind="test",
                function_ids=[], sha256=(hashlib.sha256(last.read_bytes()).hexdigest()
                                        if number == 128 else "unused"),
                rationale="candidate usage evidence",
            ) for number in range(129)]
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": ["__next_usage_inventory_page__"],
                 "context_complete": False, "rationale": "inspect later paths"},
                {"samples": [], "requested_function_ids": ["test/client_128.py"],
                 "context_complete": False, "rationale": "inspect later page"},
                {"samples": [{"data_hex": "50494e470a", "rationale": "example"}],
                 "requested_function_ids": [], "context_complete": True,
                 "rationale": "unverified byte hypothesis"},
            ])
            project = ProjectSpec(source_root=root, output_root=root / "out").normalized()
            agent = InputSurfaceAgent(
                model, graph, project, usage_artifacts=artifacts,
            )
            cases = await agent.run([entry])
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0].inspected_usage_paths, ["test/client_128.py"])
            self.assertEqual(len(model.calls[0]["payload"]["available_usage_paths"]), 128)
            self.assertEqual(model.calls[0]["payload"]["usage_inventory_remaining"], 1)
            self.assertEqual(model.calls[1]["payload"]["available_usage_paths"], [
                {"path": "test/client_128.py", "kind": "test"},
            ])
            self.assertEqual(model.calls[2]["payload"]["current_usage_artifact"]["path"],
                             "test/client_128.py")

    async def test_large_usage_source_continues_into_next_page(self):
        reader = function("read_record", "int read_record(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            usage_file = root / "test" / "client.py"
            usage_file.parent.mkdir()
            usage_file.write_text("#" * 16000 + 'socket.sendall(b"OK\\n")\n',
                                  encoding="utf-8")
            artifact = UsageArtifact(
                path="test/client.py", kind="test", function_ids=[],
                sha256=hashlib.sha256(usage_file.read_bytes()).hexdigest(),
                rationale="candidate usage evidence",
            )
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": ["test/client.py"],
                 "context_complete": False, "rationale": "inspect example"},
                {"samples": [], "requested_function_ids": ["test/client.py"],
                 "context_complete": False, "rationale": "read remaining file"},
                {"samples": [{"data_hex": "4f4b0a", "rationale": "example"}],
                 "requested_function_ids": [], "context_complete": True,
                 "rationale": "unverified byte hypothesis"},
            ])
            project = ProjectSpec(source_root=root, output_root=root / "out").normalized()
            agent = InputSurfaceAgent(
                model, graph, project, usage_artifacts=[artifact],
            )
            cases = await agent.run([entry_record(reader)])
            self.assertEqual([case.data_hex for case in cases], ["4f4b0a"])
            self.assertEqual(
                len(model.calls[1]["payload"]["current_usage_artifact"]["source"]),
                16000,
            )
            self.assertTrue(model.calls[1]["payload"]["current_usage_artifact"]["has_more"])
            self.assertIn('socket.sendall',
                          model.calls[2]["payload"]["current_usage_artifact"]["source"])

    async def test_unread_usage_source_records_exact_continuation_offset(self):
        reader = function("read_record", "int read_record(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            usage_file = root / "test" / "client.py"
            usage_file.parent.mkdir()
            usage_file.write_text("#" * 16001, encoding="utf-8")
            artifact = UsageArtifact(
                path="test/client.py", kind="test", function_ids=[],
                sha256=hashlib.sha256(usage_file.read_bytes()).hexdigest(),
                rationale="candidate",
            )
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": ["test/client.py"],
                 "context_complete": False, "rationale": "inspect"},
                {"samples": [], "requested_function_ids": [],
                 "context_complete": True, "rationale": "stop"},
            ])
            project = ProjectSpec(source_root=root, output_root=root / "out")
            agent = InputSurfaceAgent(
                model, graph, project, usage_artifacts=[artifact],
            )
            self.assertEqual(await agent.run([entry_record(reader)]), [])
            self.assertEqual(len(model.calls), 2)
            self.assertEqual(agent.continuations[0]["unread_usage_offsets"],
                             {"test/client.py": 16000})

    async def test_usage_discovery_has_no_hidden_2048_file_cutoff(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            test_dir = root / "test"
            test_dir.mkdir()
            for number in range(2049):
                (test_dir / f"client_{number:04d}.py").write_text(
                    "pass\n", encoding="utf-8",
                )
            artifacts = discover_usage_artifacts(
                root, AnalysisBundle(functions={}, edges=[]),
            )
            self.assertEqual(len(artifacts), 2049)
            self.assertEqual(len(discover_usage_artifacts(
                root, AnalysisBundle(functions={}, edges=[]), max_artifacts=3,
            )), 3)

    async def test_unread_usage_inventory_is_reported_without_forced_walk(self):
        reader = function("read_record", "int read_record(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        artifacts = [UsageArtifact(
            path=f"test/client_{number:03d}.py", kind="test",
            function_ids=[], sha256="unused", rationale="candidate",
        ) for number in range(129)]
        model = ScriptedLLM([{
            "samples": [], "requested_function_ids": [],
            "context_complete": True, "rationale": "stop",
        }])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(model, graph, project, usage_artifacts=artifacts)
            self.assertEqual(await agent.run([entry_record(reader)]), [])
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(agent.continuations[0]["usage_inventory_remaining"], 1)
        self.assertIn("__next_usage_inventory_page__",
                      agent.continuations[0]["next_function_ids"])

    async def test_long_usage_paths_are_paged_by_prompt_size(self):
        reader = function("read_record", "int read_record(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        artifacts = [UsageArtifact(
            path=f"test/{number}_" + "x" * 7000, kind="test",
            function_ids=[], sha256="unused", rationale="candidate",
        ) for number in range(2)]
        model = ScriptedLLM([
            {"samples": [], "requested_function_ids": ["__next_usage_inventory_page__"],
             "context_complete": False, "rationale": "next page"},
            {"samples": [], "requested_function_ids": [],
             "context_complete": True, "rationale": "done"},
        ])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(model, graph, project, usage_artifacts=artifacts)
            self.assertEqual(await agent.run([entry_record(reader)]), [])
        self.assertEqual(len(model.calls[0]["payload"]["available_usage_paths"]), 1)
        self.assertEqual(len(model.calls[1]["payload"]["available_usage_paths"]), 1)

    async def test_non_c_project_client_is_opened_as_input_hypothesis(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.c").write_text(
                "int read_record(void) { return 0; }\n", encoding="utf-8",
            )
            test_dir = root / "test"
            test_dir.mkdir()
            (test_dir / "client.py").write_text(
                'socket.sendall(b"PING\\n")\n', encoding="utf-8",
            )
            (test_dir / "client_key.pem").write_text(
                "fixture private key material", encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(iter(graph.bundle.functions.values()))
            entry = entry_record(reader)
            artifacts = discover_usage_artifacts(root, graph.bundle)
            self.assertIn("test/client.py", [item.path for item in artifacts])
            self.assertNotIn("test/client_key.pem", [item.path for item in artifacts])
            model = ScriptedLLM([
                {"samples": [], "requested_function_ids": ["test/client.py"],
                 "context_complete": False, "rationale": "inspect client"},
                {"samples": [{"data_hex": b"PING\n".hex(),
                              "rationale": "client example; unverified"}],
                 "requested_function_ids": [],
                 "context_complete": True, "rationale": "candidate only"},
            ])
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
            ).normalized()
            cases = await InputSurfaceAgent(
                model, graph, project, usage_artifacts=artifacts,
            ).run([entry])
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0].origin, "model_input_hypothesis")
            self.assertEqual(cases[0].inspected_usage_paths, ["test/client.py"])
            self.assertIsNone(model.calls[1]["payload"]["current_function"])
            self.assertEqual(
                model.calls[0]["payload"]["available_usage_paths"],
                [{"path": "test/client.py", "kind": "test"}],
            )
            self.assertEqual(model.calls[1]["payload"]["available_usage_paths"], [])
            self.assertIn(
                'sendall(b"PING',
                model.calls[1]["payload"]["current_usage_artifact"]["source"],
            )

    async def test_shared_field_input_walk_reaches_post_read_parser(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct state { char *readbuf; char *payload; };\n"
                "struct state ses;\n"
                "int acquire(int fd) { return read(fd, ses.readbuf, 1); }\n"
                "void decrypt(void) { ses.payload = ses.readbuf; }\n"
                "int parse(void) { return ses.payload[0]; }\n"
                "void read_packet(int fd) { acquire(fd); decrypt(); }\n"
                "int session_loop(int fd) { read_packet(fd); "
                "if (ses.payload) return parse(); return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(
                item for item in graph.bundle.functions.values()
                if item.name == "acquire"
            )
            entry = entry_record(reader)
            entry.source_api = "read"
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            responses = [{
                "samples": [], "context_complete": False,
                "requested_function_ids": [by_name[name].function_id],
                "rationale": f"inspect {name}",
            } for name in ("read_packet", "session_loop", "decrypt", "parse")]
            responses.append({
                "samples": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "parser inspected",
            })
            responses[-1]["samples"] = [{
                "data_hex": "41", "rationale": "parser byte hypothesis",
            }]
            model = ScriptedLLM(responses)
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            opened = [
                call["payload"]["current_function"]["name"]
                for call in model.calls
            ]
            self.assertEqual(opened, [
                "acquire", "read_packet", "session_loop", "decrypt", "parse",
            ])
            self.assertEqual([case.data_hex for case in cases], ["41"])
            self.assertEqual(cases[0].origin, "model_input_hypothesis")

    async def test_ambiguous_shared_field_callers_remain_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct state { char *readbuf; };\n"
                "struct state ses;\n"
                "int acquire(int fd) { return read(fd, ses.readbuf, 1); }\n"
                "void first(int fd) { acquire(fd); }\n"
                "void second(int fd) { acquire(fd); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            entry = entry_record(by_name["acquire"])
            entry.source_api = "read"
            model = ScriptedLLM([{
                "samples": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "done",
            }])
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(model.calls), 1)
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name["first"].function_id, by_name["second"].function_id},
            )

    async def test_cpp_shared_field_input_walk_reaches_parser(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.cpp").write_text(
                "#include <unistd.h>\n"
                "struct State { char *readbuf; char *payload; };\n"
                "State ses;\n"
                "int acquire(int fd) { return ::read(fd, ses.readbuf, 1); }\n"
                "void decode() { ses.payload = ses.readbuf; }\n"
                "int parse() { return ses.payload[0]; }\n"
                "void read_packet(int fd) { acquire(fd); decode(); }\n"
                "int session_loop(int fd) { read_packet(fd); "
                "if (ses.payload) return parse(); return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(
                item for item in graph.bundle.functions.values()
                if item.name == "acquire"
            )
            entry = entry_record(reader)
            entry.source_api = "read"
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            model = ScriptedLLM([{
                "samples": [], "context_complete": False,
                "requested_function_ids": [by_name[name].function_id],
                "rationale": f"inspect {name}",
            } for name in ("read_packet", "session_loop", "decode", "parse")] + [{
                "samples": [], "context_complete": False,
                "requested_function_ids": [], "rationale": "format unresolved",
            }])
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["acquire", "read_packet", "session_loop", "decode", "parse"],
            )

    async def test_direct_input_consumer_is_opened_before_accepting_completion(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_record(char *data) { return data[0] == 'A'; }\n"
                "int read_record(int fd) { char data[4]; "
                "read(fd, data, 4); return parse_record(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader, parser = by_name["read_record"], by_name["parse_record"]
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line
            model = ScriptedLLM([
                {"samples": [], "context_complete": False,
                 "requested_function_ids": [parser.function_id],
                 "rationale": "inspect input consumer"},
                {"samples": [{"data_hex": "41", "rationale": "parser input",
                             "evidence": [{"source_item_id": parser.function_id,
                                           "line": parser.start_line,
                                           "detail": "parser compares the byte with A"}]}],
                 "context_complete": True, "requested_function_ids": [],
                 "rationale": "format hypothesis"},
            ])
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            self.assertEqual(len(model.calls), 2)
            self.assertEqual(
                model.calls[1]["payload"]["current_function"]["function_id"],
                parser.function_id,
            )
            self.assertEqual([case.data_hex for case in cases], ["41"])
            self.assertFalse(any("input context incomplete" in item
                                 for item in agent.obligations))

    async def test_missing_bytes_continue_to_direct_consumer_without_model_request(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_record(char *data) { return data[0] == 'A'; }\n"
                "int read_record(int fd) { char data[4]; "
                "read(fd, data, 4); return parse_record(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader, parser = by_name["read_record"], by_name["parse_record"]
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line
            model = ScriptedLLM([
                {"samples": [], "context_complete": True,
                 "requested_function_ids": [], "rationale": "no bytes in reader"},
                {"samples": [{"data_hex": "41", "rationale": "parser comparison",
                              "evidence": [{"source_item_id": parser.function_id,
                                            "line": parser.start_line,
                                            "detail": "compares input with A"}]}],
                 "context_complete": True, "requested_function_ids": [],
                 "rationale": "byte hypothesis"},
            ])
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["read_record", "parse_record"],
            )
            self.assertEqual([case.data_hex for case in cases], ["41"])
            self.assertTrue(cases[0].trial_eligible)

    async def test_candidate_call_edge_does_not_trigger_automatic_source_walk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_record(char *data) { return data[0] == 'A'; }\n"
                "int read_record(int fd) { char data[4]; "
                "read(fd, data, 4); return parse_record(data); }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in indexed.functions.values()}
            reader, parser = by_name["read_record"], by_name["parse_record"]
            graph = GraphStore(AnalysisBundle(
                functions=indexed.functions,
                edges=[CallEdge("reported-only", reader.function_id,
                                parser.function_id, reader.start_line, "reported")],
            ))
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line
            model = ScriptedLLM([{
                "samples": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "format unknown",
            }])
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(model.calls), 1)
            self.assertIn(parser.function_id,
                          agent.continuations[0]["next_function_ids"])

    async def test_field_handoff_parser_is_available_for_explicit_source_request(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct state { char *readbuf; char *payload; };\n"
                "struct state ses;\n"
                "int acquire(int fd) { return read(fd, ses.readbuf, 1); }\n"
                "void decode(void) { ses.payload = ses.readbuf; }\n"
                "void read_packet(int fd) { acquire(fd); decode(); }\n"
                "int parse(void) { return ses.payload[0]; }\n"
                "int session_loop(int fd) { read_packet(fd); return parse(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            entry = entry_record(by_name["acquire"])
            entry.source_api = "read"
            agent = InputSurfaceAgent(
                ScriptedLLM([]), graph,
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            opened = [by_name[name].function_id for name in (
                "acquire", "read_packet", "session_loop",
            )]
            choices = agent._choices(opened, entry)
            decode = next(item for item in choices
                          if item["function_id"] == by_name["decode"].function_id)
            self.assertIn(
                "post_read_field_candidate",
                {connection["relation"] for connection in decode["connections"]},
            )
            self.assertTrue(any(
                "navigation only" in connection.get("proof_policy", "")
                for connection in decode["connections"]
            ))
            model = ScriptedLLM([
                {
                    "samples": [], "requested_function_ids": [
                        by_name["read_packet"].function_id,
                    ], "context_complete": False,
                    "rationale": "follow the read wrapper's caller",
                },
                {
                    "samples": [{"data_hex": "41", "rationale": "trial byte"}],
                    "requested_function_ids": [], "context_complete": True,
                    "rationale": "one byte is ready for a trial",
                },
            ])
            running_agent = InputSurfaceAgent(
                model, graph,
                ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await running_agent.run([entry])
            self.assertEqual([item.data_hex for item in cases], ["41"])
            self.assertIn(
                by_name["decode"].function_id,
                running_agent.continuations[0]["next_function_ids"],
            )

    async def test_uncited_sample_keeps_ambiguous_consumers_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int parse_alpha(char *data) { return data[0] == 'A'; }\n"
                "int parse_beta(char *data) { return data[0] == 'B'; }\n"
                "int read_record(int fd) { char data[4]; read(fd, data, 4); "
                "return parse_alpha(data) + parse_beta(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["read_record"]
            entry = entry_record(reader)
            entry.source_api = "read"
            entry.entry_line = reader.start_line
            model = ScriptedLLM([
                {"samples": [{"data_hex": "41", "rationale": "first hypothesis"}],
                 "context_complete": True, "requested_function_ids": [
                     by_name["parse_alpha"].function_id],
                 "rationale": "premature"},
                {"samples": [], "context_complete": True,
                 "requested_function_ids": [by_name["parse_beta"].function_id],
                 "rationale": "first parser"},
                {"samples": [], "context_complete": True,
                 "requested_function_ids": [], "rationale": "second parser"},
            ])
            agent = InputSurfaceAgent(
                model, graph, ProjectSpec(source_root=root, output_root=root / "out"),
            )
            cases = await agent.run([entry])
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0].data_hex, "41")
            self.assertFalse(cases[0].trial_eligible)
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["read_record", "parse_alpha", "parse_beta"],
            )
            self.assertTrue(agent.continuations)
            self.assertTrue(any(
                "no source-backed or user-supplied sample" in obligation
                for obligation in agent.obligations
            ))
            self.assertTrue(any("no source-backed" in item
                                for item in agent.obligations))

    async def test_trial_sample_records_listed_but_unopened_usage_file(self):
        reader = function("read_record", "int read_record(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        artifact = UsageArtifact(
            path="test/client.py", kind="test", function_ids=[],
            sha256="unused", rationale="candidate input example",
        )
        model = ScriptedLLM([{
            "samples": [{"data_hex": "41", "rationale": "trial hypothesis"}],
            "requested_function_ids": [], "context_complete": True,
            "rationale": "try original first",
        }])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(
                model, graph, project, usage_artifacts=[artifact],
            )
            cases = await agent.run([entry_record(reader)])
        self.assertEqual([case.data_hex for case in cases], ["41"])
        self.assertFalse(cases[0].trial_eligible)
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(agent.continuations[0]["unopened_usage_paths"],
                         ["test/client.py"])
        self.assertIn("test/client.py",
                      agent.continuations[0]["next_function_ids"])

    async def test_non_ssl_socket_entry_generates_input_case(self):
        reader = function("tcp_read", "int tcp_read(void) { return read(fd, buf, 4); }\n", 1)
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        for kind, selected in (
            ("Internet TCP non-SSL accepted stream-socket payload read", "auto"),
            ("non-SSL accepted stream-socket payload read", "tcp"),
        ):
            with self.subTest(kind=kind, selected=selected):
                item = entry_record(reader, kind=kind)
                item.source_api = "read"
                model = ScriptedLLM([{
                    "samples": [{"data_hex": "76657273696f6e0d0a", "rationale": "TCP request",
                                 "evidence": [{"source_item_id": reader.function_id,
                                               "line": reader.end_line + 10,
                                               "detail": "invalid invented citation"}]}],
                    "context_complete": True, "requested_function_ids": [], "rationale": "sample",
                }])
                with tempfile.TemporaryDirectory() as td:
                    project = ProjectSpec(
                        source_root=Path(td), output_root=Path(td) / "out",
                        scenario_channel=selected, scenario_port=11211,
                    )
                    agent = InputSurfaceAgent(model, graph, project)
                    cases = await agent.run([item])
                self.assertEqual(len(cases), 1)
                self.assertEqual(len(model.calls), 1)
                self.assertFalse(cases[0].trial_eligible)
                self.assertTrue(any("ineligible for runtime trial" in reason
                                    for reason in agent.obligations))

    async def test_consumer_hint_is_opened_after_premature_completion(self):
        reader = function(
            "read_record", "int read_record(void) { return parse_record(); }\n", 1,
        )
        parser = function(
            "parse_record", "int parse_record(void) { return 0; }\n", 5,
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)},
            edges=[],
        ))
        entry = entry_record(reader)
        entry.consumer_hints = [parser.function_id]
        model = ScriptedLLM([
            {"samples": [], "context_complete": False,
             "requested_function_ids": [parser.function_id],
             "rationale": "inspect consumer hint"},
            {"samples": [{"data_hex": "410a", "rationale": "parser evidence"}],
             "context_complete": True, "requested_function_ids": [],
             "rationale": "format hypothesis"},
        ])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(model, graph, project)
            cases = await agent.run([entry])
        self.assertEqual(len(model.calls), 2)
        self.assertEqual(model.calls[1]["payload"]["current_function"]["function_id"],
                         parser.function_id)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].data_hex, "410a")
        self.assertIn(parser.function_id, cases[0].inspected_function_ids)
        self.assertFalse(any("before opening consumer hint" in item
                             for item in agent.obligations))

    async def test_invalid_model_request_does_not_hide_opened_consumer_hint(self):
        reader = function(
            "read_record", "int read_record(void) { return parse_record(); }\n", 1,
        )
        parser = function(
            "parse_record", "int parse_record(void) { return 0; }\n", 5,
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)},
            edges=[],
        ))
        entry = entry_record(reader)
        entry.consumer_hints = [parser.function_id]
        model = ScriptedLLM([
            {"samples": [], "context_complete": False,
             "requested_function_ids": ["invented_parser"],
             "rationale": "wrong symbol"},
            {"samples": [{"data_hex": "410a", "rationale": "parser evidence"}],
             "context_complete": True, "requested_function_ids": [],
             "rationale": "format hypothesis"},
        ])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(model, graph, project)
            cases = await agent.run([entry])
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(cases, [])
        self.assertIn(parser.function_id,
                      agent.continuations[0]["next_function_ids"])
        self.assertTrue(any("invented_parser" in item for item in agent.obligations))

    async def test_no_fixture_or_model_sample_does_not_invent_trial_bytes(self):
        reader = function("tcp_read", "int tcp_read(void) { return read(fd, buf, 4); }\n", 1)
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "samples": [], "context_complete": False,
            "requested_function_ids": [], "rationale": "format unknown",
        }])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(model, graph, project)
            cases = await agent.run([entry_record(reader, kind="network tcp")])
        self.assertEqual(cases, [])
        self.assertTrue(any("no source-backed or user-supplied" in item
                            for item in agent.obligations))
        self.assertEqual(agent.continuations[0]["stop_reason"],
                         "requested source item unavailable or already opened")

    async def test_explicit_work_budget_preserves_next_source_function(self):
        reader = function("read_record", "int read_record(void) { return parse_record(); }\n", 1)
        parser = function("parse_record", "int parse_record(void) { return buf[0] == 'A'; }\n", 5)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)}, edges=[],
        ))
        model = ScriptedLLM([{
            "samples": [], "context_complete": False,
            "requested_function_ids": ["parse_record"], "rationale": "need parser",
        }])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            agent = InputSurfaceAgent(model, graph, project, max_function_turns=1)
            self.assertEqual(await agent.run([entry_record(reader)]), [])
        self.assertEqual(agent.continuations[0]["next_function_ids"],
                         [parser.function_id])
        self.assertEqual(agent.continuations[0]["stop_reason"],
                         "function work budget exhausted")

    async def test_input_walk_replays_prefix_when_budget_is_raised(self):
        reader = function("read_record", "int read_record(void) { return parse_record(); }\n", 1)
        parser = function("parse_record", "int parse_record(void) { return buf[0] == 'A'; }\n", 5)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)}, edges=[],
        ))
        first = {
            "samples": [], "context_complete": False,
            "requested_function_ids": ["parse_record"], "rationale": "need parser",
        }
        second = {
            "samples": [{"data_hex": "41", "rationale": "parser format",
                         "evidence": [{"source_item_id": parser.function_id,
                                       "line": parser.start_line,
                                       "detail": "parser compares first byte with A"}]}],
            "context_complete": True,
            "requested_function_ids": [], "rationale": "format recovered",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            project = ProjectSpec(source_root=root, output_root=root / "out")
            trajectory = root / "llm.jsonl"
            def persist(record):
                with trajectory.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record) + "\n")
            recorded = RecordingLLM(ScriptedLLM([first]), on_record=persist)
            deferred = InputSurfaceAgent(
                recorded, graph, project, max_function_turns=1,
            )
            self.assertEqual(await deferred.run([entry_record(reader)]), [])
            self.assertEqual(deferred.continuations[0]["next_function_ids"],
                             [parser.function_id])

            cached = CachingLLM(ScriptedLLM([first, second]), trajectory)
            resumed = InputSurfaceAgent(
                cached, graph, project, max_function_turns=2,
            )
            cases = await resumed.run([entry_record(reader)])
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0].data_hex, "41")
            self.assertEqual(resumed.continuations, [])
            self.assertEqual(cached.hits, 1)
            self.assertEqual(cached.rehydrated_calls, 1)

    async def test_model_failure_is_reported_without_discarding_static_entries(self):
        fn1 = function("read_first", "int read_first(void) { recv(1, buf, 4, 0); return 0; }\n", 1)
        fn2 = function("read_second", "int read_second(void) { recv(1, buf, 4, 0); return 0; }\n", 6)
        fn3 = function("read_third", "int read_third(void) { recv(1, buf, 4, 0); return 0; }\n", 11)
        for fn in (fn1, fn2, fn3):
            fn.external_calls = ["recv"]
        class FailedProvider:
            max_concurrency = 1

            async def complete_json(self, **_kwargs):
                raise RuntimeError("context too large")

        bundle = AnalysisBundle(
            functions={item.function_id: item for item in (fn1, fn2, fn3)}, edges=[],
        )
        agent = EntryGeneratorAgent(FailedProvider())
        candidates = await agent.run(bundle)
        self.assertEqual(len(candidates), 3)  # deterministic acquisition site scan
        self.assertEqual(len(agent.incomplete_functions), 3)
        self.assertTrue(all(
            "context too large" in item["reason"]
            for item in agent.incomplete_functions
        ))

    async def test_entry_discovery_sends_one_entire_function_even_when_large(self):
        source = "int input(void) {\n" + ("/* padding padding padding */\n" * 900) + "  return read(0, &buf, 3);\n}\n"
        fn = function("input", source, 1)
        bundle = AnalysisBundle(functions={fn.function_id: fn}, edges=[])
        provider = ScriptedLLM([{"candidates": []}])
        result = await EntryGeneratorAgent(provider, chunk_size=32, max_batch_chars=500).run(bundle)
        self.assertEqual(result, [])
        self.assertEqual(len(provider.calls), 1)
        payload = provider.calls[0]["payload"]["functions"]
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["source"], source)
        self.assertFalse(payload[0]["source_truncated"])

    async def test_raw_input_seeds_do_not_require_commands_or_branches(self):
        reader = function("read_record", "int read_record(void) { return fread(buf, 1, 4, stdin); }\n", 1)
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "samples": [{"data_hex": "41424344", "rationale": "raw four-byte record"}],
            "context_complete": True, "requested_function_ids": [], "rationale": "no dispatcher",
        }])
        with tempfile.TemporaryDirectory() as td:
            project = ProjectSpec(source_root=Path(td), output_root=Path(td) / "out")
            cases = await InputSurfaceAgent(model, graph, project).run([entry_record(reader)])
        self.assertEqual(len(cases), 1)
        self.assertEqual(bytes.fromhex(cases[0].data_hex), b"ABCD")
        runtime_action = raw_case_runtime_action(cases[0], entry_record(reader), graph)
        self.assertEqual(runtime_action.name, "RAW_EXTERNAL_INPUT")
        self.assertEqual(runtime_action.actor, ActionActor.LOCAL_PROCESS_INPUT)
        self.assertEqual(str(runtime_action.status), "POSSIBLE")
        self.assertFalse(_source_draft_action_is_supported(runtime_action))
        planner = ScenarioPlanner()
        scenarios = planner.exploratory_candidates([runtime_action], [])
        self.assertEqual(len(scenarios), 1)
        self.assertEqual(scenarios[0].steps[0].request_hex, "41424344")

    async def test_nonadjacent_but_source_referenced_function_can_be_opened(self):
        first = function("acquire", "int acquire(void) { return create_record(); }\n", 1)
        needed = function("create_record", "int create_record(void) { return 0; }\n", 5)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (first, needed)}, edges=[],
        ))
        provider = ScriptedLLM([
            {"samples": [], "context_complete": False, "requested_function_ids": ["create_record"],
             "rationale": "open source-referenced helper"},
            {"samples": [{"data_hex": "410a", "rationale": "record with terminator"}],
             "context_complete": True, "requested_function_ids": [], "rationale": "format recovered"},
        ])
        with tempfile.TemporaryDirectory() as td:
            result = await InputSurfaceAgent(
                provider, graph, ProjectSpec(source_root=Path(td), output_root=Path(td) / "out"),
            ).run([entry_record(first)])
        self.assertEqual(len(provider.calls), 2)
        self.assertIn(needed.function_id, result[0].inspected_function_ids)
        self.assertEqual(result[0].data_hex, "410a")

    async def test_file_evidence_does_not_replay_pcap_or_document_as_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ("request.bin", "README.md", "capture.pcap", "example.txt"):
                (root / name).write_bytes(b"ABCD")
            chosen = _explicit_request_fixtures([root])
            self.assertEqual([item.name for item in chosen], ["request.bin"])

    async def test_real_command_free_c_stdin_program_receives_raw_experiment(self):
        cc = shutil.which("cc")
        if cc is None:
            self.skipTest("no C compiler")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "raw.c"
            source.write_text(
                "#include <stdio.h>\n"
                "int read_record(void) {\n"
                "  unsigned char data[4];\n"
                "  if (fread(data,1,4,stdin) != 4) return 0;\n"
                "  if (data[0]=='A' && data[1]=='B' && data[2]=='C' && data[3]=='D')\n"
                '    fputs("ACCEPT\\n",stdout);\n'
                '  else fputs("REJECT\\n",stdout);\n'
                "  fflush(stdout); return 1;\n"
                "}\n"
                "int main(void) { read_record(); return 0; }\n",
                encoding="utf-8",
            )
            binary = root / "raw"
            subprocess.run([cc, "-O0", "-g", str(source), "-o", str(binary)], check=True)
            reader = function("read_record", source.read_text(), 1)
            graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
            entry = entry_record(reader)
            model = ScriptedLLM([{
                "samples": [{"data_hex": "41424344", "rationale": "raw four-byte input"}],
                "requested_function_ids": [], "context_complete": True, "rationale": "binary protocol",
            }])
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_command=[str(binary)], scenario_channel="stdin",
                scenario_attribution="gdb", scenario_exploratory_drafts=False,
                scenario_step_timeout=2,
            ).normalized()
            samples = await InputSurfaceAgent(model, graph, project).run([entry])
            action = raw_case_runtime_action(samples[0], entry, graph)
            scenario = ScenarioPlanner().exploratory_candidates([action], [])[0]
            strict_witness = await ScenarioRuntimeVerifier(
                project, [action], graph,
            ).verify(scenario)
            self.assertEqual(strict_witness.observations, [])
            self.assertNotEqual(strict_witness.status, ScenarioStatus.PROVEN_RUNTIME)
            trial_project = _raw_original_trial_project(project)
            self.assertFalse(project.scenario_exploratory_drafts)
            self.assertTrue(trial_project.scenario_exploratory_drafts)
            self.assertFalse(trial_project.scenario_require_target_reach)
            self.assertTrue(project.scenario_require_target_reach)
            witness = await ScenarioRuntimeVerifier(
                trial_project, [action], graph,
            ).verify(scenario)
            self.assertEqual(len(witness.observations), 1, witness.rationale)
            self.assertIn(b"ACCEPT", bytes.fromhex(witness.observations[0].response_hex))
            self.assertNotEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
            # A source-backed semantic candidate with no proven success
            # oracle must likewise reach the original as an experiment.
            # Neither the response nor the opened source is path proof.
            semantic = replace(
                action, action_id="raw-four-byte-action",
                discriminator="ABCD", status=ProofStatus.POSSIBLE,
                evidence=[Evidence("source", reader.function_id, reader.file,
                                   reader.start_line, "source-located reader")],
                examples=[ActionExample(
                    b"ABCD".hex(), origin="product_source",
                    evidence=[Evidence("source", reader.function_id, reader.file,
                                       reader.start_line, "literal input format")],
                )],
                success_markers_hex=[], success_evidence=[],
            )
            self.assertTrue(_source_draft_action_is_supported(semantic))
            semantic_candidate = ScenarioPlanner().exploratory_candidates(
                [semantic], [],
            )[0]
            strict_semantic = await ScenarioRuntimeVerifier(
                project, [semantic], graph,
            ).verify(semantic_candidate)
            self.assertFalse(strict_semantic.observations)
            diagnostic_semantic = await ScenarioRuntimeVerifier(
                trial_project, [semantic], graph,
            ).verify(semantic_candidate)
            self.assertEqual(len(diagnostic_semantic.observations), 1)
            self.assertIn(
                b"ACCEPT",
                bytes.fromhex(diagnostic_semantic.observations[0].response_hex),
            )
            self.assertNotEqual(diagnostic_semantic.status, ScenarioStatus.PROVEN_RUNTIME)

    async def test_original_trial_response_is_visible_as_unproven_action_context(self):
        reader = function(
            "read_record", "int read_record(void) { return parse_record(); }", 1,
        )
        parser = function("parse_record", "int parse_record(void) { return 0; }", 2)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader, parser.function_id: parser},
            edges=[CallEdge(reader.function_id, parser.function_id, "direct", 1)],
        ))
        entry = entry_record(reader)
        feedback = {
            "case_id": "trial-1", "request_hex": "41424344",
            "response_hex": "4143434550540a", "runtime_status": "UNPROVEN",
            "observation": "original response recorded",
            "proof_boundary": "handler and acceptance unproven",
        }
        model = ScriptedLLM([
            {"actions": [], "requested_function_ids": [parser.function_id],
             "context_complete": False, "rationale": "open consumer"},
            {"actions": [], "requested_function_ids": [],
             "context_complete": True, "rationale": "no semantic claim"},
        ])
        agent = InputActionAgent(
            model, graph,
            input_trial_observations={entry.entry_id: [feedback]},
        )
        self.assertEqual(await agent.run([entry]), [])
        self.assertEqual(
            model.calls[0]["payload"]["original_input_trials"], [feedback],
        )
        self.assertEqual(
            model.calls[1]["payload"]["original_input_trials"], [],
        )
        self.assertIn("observations only", model.calls[0]["instructions"])


if __name__ == "__main__":
    unittest.main()
