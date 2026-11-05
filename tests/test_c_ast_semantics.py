"""Source-only C AST regressions: no prewritten LLM actions or OSS-Fuzz recipes."""
from __future__ import annotations

import shutil
import subprocess
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.analysis import StaticAnalyzer
from harnesscreator.agents.entry import EntryGeneratorAgent
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.agents.scenario import InputActionAgent, _entry_destination_names
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import EntryRecord, Verdict
import asyncio


BASE = Path(__file__).parent / 'fixtures' / 'c_ast_semantics'


@unittest.skipUnless(shutil.which('clang'), 'Clang AST required')
class ClangCSourceTests(unittest.TestCase):
    def test_uninitialized_file_static_state_declaration_is_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.c').write_text(
                'static char saved_key[32];\n'
                'int matches(const char *key) { return saved_key[0] == key[0]; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            function = next(item for item in bundle.functions.values()
                            if item.name == 'matches')
            declarations = function.referenced_global_declarations
            self.assertEqual([(item['name'], item['source']) for item in declarations],
                             [('saved_key', 'static char saved_key[32]')])
            from harnesscreator.agents.scenario import _validated_evidence
            evidence = _validated_evidence([{
                'function_id': function.function_id,
                'kind': 'source_declaration',
                'file': 'server.c',
                'line': 1,
                'detail': 'The key buffer has file-static storage.',
            }], {function.function_id}, GraphStore(bundle))
            self.assertEqual(len(evidence), 1)

    def test_header_prototype_uses_active_preprocessor_branch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.h').write_text(
                '#ifdef _WIN32\n'
                'extern int serve(char *p);\n'
                '#else\n'
                'extern void *serve(void *p);\n'
                '#endif\n'
            )
            (root / 'server.c').write_text(
                '#include "server.h"\n'
                'void *serve(void *p) { return p; }\n'
            )
            function = next(item for item in StaticAnalyzer(root).index().functions.values()
                            if item.name == 'serve')
            self.assertEqual(function.declaration, 'extern void *serve(void *p);')
            self.assertEqual(function.headers, ['server.h'])

    def test_conflicting_header_branches_without_ast_do_not_choose_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.h').write_text(
                '#ifdef _WIN32\n'
                'extern int serve(char *p);\n'
                '#else\n'
                'extern void *serve(void *p);\n'
                '#endif\n'
            )
            (root / 'server.c').write_text(
                '#include "server.h"\n'
                'void *serve(void *p) { return p; }\n'
            )
            with patch('harnesscreator.analysis.clang_c.shutil.which', return_value=None):
                function = next(
                    item for item in StaticAnalyzer(root).index().functions.values()
                    if item.name == 'serve'
                )
            self.assertEqual(function.declaration, '')
            self.assertEqual(function.headers, ['server.h'])

    def test_cross_translation_unit_callback_reference_uses_unique_abi(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'active.h').write_text('extern void *worker(void *p);\n')
            (root / 'active.c').write_text(
                '#include "active.h"\n'
                'void *worker(void *p) { return p; }\n'
            )
            (root / 'other.c').write_text('int worker(int p) { return p; }\n')
            (root / 'main.c').write_text(
                '#include "active.h"\n'
                'void launch(void) { void *(*callback)(void *) = &worker; (void)callback; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            active = next(f for f in bundle.functions.values()
                          if f.name == 'worker' and f.file == 'active.c')
            other = next(f for f in bundle.functions.values()
                         if f.name == 'worker' and f.file == 'other.c')
            launch = next(f for f in bundle.functions.values()
                          if f.name == 'launch')
            references = [e for e in bundle.edges
                          if e.caller_id == launch.function_id
                          and e.kind == 'function_reference']
            self.assertEqual([e.callee_id for e in references], [active.function_id])
            self.assertNotEqual(references[0].callee_id, other.function_id)

    def test_expanded_header_macro_is_attached_to_using_function_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'config.h').write_text(
                '#define SECTION "ftpconfig"\n'
                '#define UNUSED "irrelevant"\n'
            )
            (root / 'server.c').write_text(
                '#include "config.h"\n'
                'const char *section(void) { return SECTION; }\n'
                'int unrelated(void) { return 0; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            functions = {item.name: item for item in bundle.functions.values()}
            macros = functions['section'].referenced_macro_definitions
            self.assertEqual([item['name'] for item in macros], ['SECTION'])
            self.assertEqual(macros[0]['file'], 'config.h')
            self.assertEqual(macros[0]['start_line'], 1)
            self.assertIn('ftpconfig', macros[0]['source'])
            self.assertEqual(functions['unrelated'].referenced_macro_definitions, [])
            from harnesscreator.agents.common import function_payload
            self.assertEqual(
                function_payload(functions['section'])['referenced_macro_definitions'],
                macros,
            )

    def test_directly_included_header_constant_is_available_by_ast_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'banner.h').write_text(
                'static const char banner[] = "220 hello\\r\\n";\n'
            )
            (root / 'server.c').write_text(
                '#include "banner.h"\n'
                'const char *greeting(void) { return banner; }\n'
                'int unrelated(void) { return 0; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            functions = {item.name: item for item in bundle.functions.values()}
            greeting = functions['greeting']
            declarations = greeting.referenced_global_declarations
            self.assertEqual(len(declarations), 1)
            self.assertEqual(declarations[0]['name'], 'banner')
            self.assertEqual(declarations[0]['file'], 'banner.h')
            self.assertEqual(declarations[0]['start_line'], 1)
            self.assertEqual(functions['unrelated'].referenced_global_declarations, [])
            from harnesscreator.agents.scenario import _validated_evidence
            evidence = _validated_evidence([{
                'function_id': greeting.function_id,
                'kind': 'source_declaration',
                'file': 'banner.h',
                'line': 1,
                'detail': 'The literal greeting is initialized here.',
            }], {greeting.function_id}, GraphStore(bundle))
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0].file, 'banner.h')
            from harnesscreator.agents.input_surfaces import _validated_sample_basis
            basis = _validated_sample_basis([{
                'source_item_id': greeting.function_id,
                'file': 'banner.h',
                'line': 1,
                'detail': 'The server sends this literal first.',
            }], [greeting.function_id], {}, GraphStore(bundle))
            self.assertEqual(len(basis), 1)
            self.assertEqual(basis[0]['file'], 'banner.h')

    def test_indirect_dispatch_receives_only_referenced_global_initializers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.c').write_text(
                '#include <string.h>\n'
                'typedef int (*Handler)(const char *);\n'
                'int alpha(const char *s) { return s[0]; }\n'
                'int beta(const char *s) { return s[1]; }\n'
                'static const char *names[] = {"ALPHA", "BETA"};\n'
                'static Handler handlers[] = {alpha, beta};\n'
                'static Handler unrelated[] = {beta};\n'
                'int dispatch(const char *s) {\n'
                '  for (int i = 0; i < 2; ++i)\n'
                '    if (!strcmp(s, names[i])) return handlers[i](s);\n'
                '  return -1;\n'
                '}\n'
                'int shadow(void) { int handlers = 3; return handlers; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            functions = {item.name: item for item in bundle.functions.values()}
            dispatch = functions['dispatch']
            declarations = {
                item['name']: item
                for item in dispatch.referenced_global_declarations
            }
            self.assertEqual(set(declarations), {'names', 'handlers'})
            self.assertIn('alpha, beta', declarations['handlers']['source'])
            self.assertEqual(declarations['handlers']['start_line'], 6)
            self.assertEqual(functions['shadow'].referenced_global_declarations, [])
            from harnesscreator.agents.common import resolve_source_linked_function
            graph = GraphStore(bundle)
            self.assertEqual(
                resolve_source_linked_function(
                    'alpha', [dispatch.function_id], [], graph,
                ),
                functions['alpha'].function_id,
            )
            self.assertEqual(
                resolve_source_linked_function(
                    'shadow', [dispatch.function_id], [], graph,
                ),
                functions['shadow'].function_id,
            )
            from harnesscreator.agents.scenario import _validated_evidence
            valid = _validated_evidence([{
                'function_id': dispatch.function_id,
                'kind': 'source_declaration',
                'line': 6,
                'detail': 'The table maps index 0 to alpha and 1 to beta.',
            }], {dispatch.function_id}, graph)
            self.assertEqual(len(valid), 1)
            invalid = _validated_evidence([{
                'function_id': dispatch.function_id,
                'kind': 'source_declaration',
                'line': 7,
                'detail': 'Unrelated table.',
            }], {dispatch.function_id}, graph)
            self.assertEqual(invalid, [])

    def test_compile_database_keeps_unrecorded_source_without_guessing_ast(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'built.c').write_text('int built(void) { return 1; }\n')
            (root / 'other.c').write_text(
                '#include <unavailable_generated_header.h>\n'
                'int other(void) { return 2; }\n'
            )
            database = root / 'compile_commands.json'
            database.write_text(json.dumps([{
                'directory': str(root), 'file': str(root / 'built.c'),
                'arguments': ['clang', '-c', 'built.c'],
            }]))
            bundle = StaticAnalyzer(root, compile_database=database).index()
            self.assertEqual(bundle.completeness['clang_c_ast_parsed_files'], 1)
            self.assertEqual(bundle.completeness['clang_c_ast_failed_files'], 0)
            self.assertEqual(bundle.completeness['clang_c_ast_unrecorded_files'], 1)
            self.assertIn('other', {item.name for item in bundle.functions.values()})

    def test_large_source_file_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'large.c').write_text(
                '/*' + ('x' * 1_000_001) + '*/\n'
                'int parse_request(void) { return 1; }\n'
            )
            bundle = StaticAnalyzer(root).index()
            self.assertEqual(bundle.completeness['clang_c_ast_parsed_files'], 1)
            self.assertIn('parse_request', {
                function.name for function in bundle.functions.values()
            })

    def test_default_ast_inventory_visits_all_small_translation_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'first.c').write_text('int first(void) { return 1; }\n')
            (root / 'second.c').write_text('int second(void) { return 2; }\n')
            with patch.dict(os.environ, {}, clear=False):
                # An absent operator limit, unlike zero, means full inventory.
                os.environ.pop('HC_C_AST_BUDGET_SECONDS', None)
                bundle = StaticAnalyzer(root).index()
            self.assertEqual(bundle.completeness['clang_c_ast_parsed_files'], 2)
            self.assertFalse(bundle.completeness['clang_c_ast_budget_exhausted'])

    def test_invalid_operator_ast_budget_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'first.c').write_text('int first(void) { return 1; }\n')
            with patch.dict(os.environ, {'HC_C_AST_BUDGET_SECONDS': '-1'}):
                with self.assertRaisesRegex(ValueError, 'finite and nonnegative'):
                    StaticAnalyzer(root).index()

    def test_external_compile_database_supplies_generated_header_and_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            build = Path(temporary) / 'configured-build'
            root.mkdir()
            build.mkdir()
            source = root / 'server.c'
            source.write_text(
                '#include <buildconfig.h>\n'
                'extern long read(int, void *, unsigned long);\n'
                'int chosen(void) { return 1; }\n'
                'int receive(int fd) { char data[2]; read(fd, data, 2); '
                'if (data[0]) chosen(); return 0; }\n',
                encoding='utf-8',
            )
            (build / 'buildconfig.h').write_text('#define READY 1\n', encoding='utf-8')
            database = build / 'compile_commands.json'
            database.write_text(json.dumps([{
                'directory': str(build), 'file': str(source),
                'arguments': ['clang', '-I', '.', '-DREADY=1', '-c', str(source)],
            }]), encoding='utf-8')
            without = StaticAnalyzer(root).index()
            self.assertEqual(without.completeness['clang_c_ast_parsed_files'], 0)
            self.assertIn('buildconfig.h',
                          without.completeness['clang_c_ast_failure_diagnostics'][0]['reason'])
            with_database = StaticAnalyzer(root, compile_database=database).index()
            self.assertEqual(with_database.completeness['clang_c_ast_parsed_files'], 1)
            self.assertEqual(with_database.completeness['clang_c_ast_failure_diagnostics'], [])
            self.assertEqual(with_database.completeness['analysis_compile_database'], str(database))
            receiver = next(function for function in with_database.functions.values()
                            if function.name == 'receive')
            self.assertTrue(receiver.guarded_call_sites)
            self.assertTrue(any(
                site.get('api') == 'read' and site.get('compile_command_available')
                for site in receiver.external_call_sites
            ))

    def test_invalid_explicit_compile_database_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            root.mkdir()
            (root / 'server.c').write_text('int main(void) { return 0; }\n')
            database = Path(temporary) / 'compile_commands.json'
            database.write_text('{bad json', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'cannot read analysis compile database'):
                StaticAnalyzer(root, compile_database=database).index()

    def test_explicit_compile_database_for_other_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            other = Path(temporary) / 'other'
            root.mkdir()
            other.mkdir()
            (root / 'server.c').write_text('int receive(void) { return 0; }\n')
            foreign = other / 'server.c'
            foreign.write_text('int receive(void) { return 1; }\n')
            database = other / 'compile_commands.json'
            database.write_text(json.dumps([{
                'directory': str(other), 'file': str(foreign),
                'arguments': ['clang', '-c', str(foreign)],
            }]), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, r'no existing C/C\+\+ translation unit'):
                StaticAnalyzer(root, compile_database=database).index()

    def test_distinct_compile_configs_for_one_unit_remain_unresolved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            build = Path(temporary) / 'build'
            root.mkdir()
            build.mkdir()
            source = root / 'server.c'
            source.write_text('int receive(void) { return 0; }\n', encoding='utf-8')
            database = build / 'compile_commands.json'
            database.write_text(json.dumps([
                {'directory': str(build), 'file': str(source),
                 'arguments': ['clang', '-DPRODUCT_SERVER=1', '-c', str(source)]},
                {'directory': str(build), 'file': str(source),
                 'arguments': ['clang', '-DPRODUCT_CLIENT=1', '-c', str(source)]},
            ]), encoding='utf-8')
            bundle = StaticAnalyzer(root, compile_database=database).index()
            self.assertEqual(bundle.completeness['clang_c_ast_parsed_files'], 0)
            self.assertEqual(bundle.completeness['clang_c_ast_failed_files'], 1)
            self.assertIn('ambiguous compile commands',
                          bundle.completeness['clang_c_ast_failure_diagnostics'][0]['reason'])

    def analyze(self, source: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'server.c').write_text((BASE / source).read_text(encoding='utf-8'))
            compile_result = subprocess.run(
                ['clang', '-fsyntax-only', str(root / 'server.c')],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            bundle = StaticAnalyzer(root).index()
            return bundle

    def test_macro_wrapped_recv_present_as_real_external_api(self):
        bundle = self.analyze('macro_ingress.c')
        by_name = {f.name: f for f in bundle.functions.values()}
        self.assertIn('recv', by_name['read_request'].external_calls)
        self.assertEqual(bundle.completeness['clang_c_ast_parsed_files'], 1)
        receiver = by_name['read_request']
        macro_sites = [
            site for site in receiver.external_call_sites
            if site['api'] == 'recv' and site['macro_expansion'] is True
        ]
        self.assertEqual(len(macro_sites), 1)
        self.assertFalse(macro_sites[0]['compile_command_available'])
        candidates = asyncio.run(
            EntryGeneratorAgent(ScriptedLLM([{'candidates': []}])).run(bundle)
        )
        self.assertEqual(len([
            item for item in candidates
            if item.function_id == receiver.function_id
            and item.source_api == 'recv'
            and item.line == macro_sites[0]['line']
        ]), 1)

    def test_macro_destination_reaches_direct_consumer_only_for_simple_variable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'server.c'
            source.write_text(
                '#include <sys/socket.h>\n'
                '#define GET_BYTES(fd, out) recv(fd, out, sizeof(out), 0)\n'
                'int parse(char *p) { return p[0]; }\n'
                'int receive(int fd) { char data[8]; '
                'int n = GET_BYTES(fd, data); return parse(data) + n; }\n',
                encoding='utf-8',
            )
            (root / 'compile_commands.json').write_text(json.dumps([{
                'directory': str(root), 'file': str(source),
                'arguments': ['clang', '-c', str(source)],
            }]), encoding='utf-8')
            bundle = StaticAnalyzer(root).index()

        by_name = {item.name: item for item in bundle.functions.values()}
        receiver = by_name['receive']
        site = next(item for item in receiver.external_call_sites
                    if item['api'] == 'recv')
        self.assertEqual(site['direct_argument_identifiers'][1], 'data')
        entry = EntryRecord(
            entry_id='macro-c-entry', candidate_id='macro-c-candidate',
            status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
            source_api='recv', channel_kind='network', attacker_control='remote',
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=site['line'],
        )
        self.assertEqual(_entry_destination_names(receiver, entry), {'data'})
        graph = GraphStore(bundle)
        consumers, truncated = InputActionAgent(
            ScriptedLLM([]), graph,
        )._source_dataflow_dispatchers(
            entry, function_limit=len(bundle.functions),
            include_all_consumers=True,
        )
        self.assertFalse(truncated)
        self.assertIn(by_name['parse'].function_id,
                      {item[0] for item in consumers})

        # The AST proves the expanded recv call, while the macro invocation
        # location determines whether parse runs before or after that read.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'server.c'
            source.write_text(
                '#include <sys/socket.h>\n'
                '#define GET_BYTES(fd, out) recv(fd, out, sizeof(out), 0)\n'
                'int parse(char *p) { return p[0]; }\n'
                'int receive(int fd) { char data[8] = {0}; '
                'parse(data); return GET_BYTES(fd, data); }\n',
                encoding='utf-8',
            )
            (root / 'compile_commands.json').write_text(json.dumps([{
                'directory': str(root), 'file': str(source),
                'arguments': ['clang', '-c', str(source)],
            }]), encoding='utf-8')
            earlier_bundle = StaticAnalyzer(root).index()
        earlier_by_name = {item.name: item
                           for item in earlier_bundle.functions.values()}
        earlier_entry = EntryRecord(
            entry_id='macro-before-read', candidate_id='macro-before-candidate',
            status=Verdict.VERIFIED,
            entry_function_id=earlier_by_name['receive'].function_id,
            source_api='recv', channel_kind='network', attacker_control='remote',
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99,
            entry_line=earlier_by_name['receive'].external_call_sites[0]['line'],
        )
        earlier_consumers, earlier_unresolved = InputActionAgent(
            ScriptedLLM([]), GraphStore(earlier_bundle),
        )._source_dataflow_dispatchers(
            earlier_entry, function_limit=len(earlier_bundle.functions),
            include_all_consumers=True,
        )
        self.assertEqual(earlier_consumers, [])
        self.assertFalse(earlier_unresolved)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.c').write_text(
                '#include <sys/socket.h>\n'
                'struct S { char buf[8]; };\n'
                '#define GET_BYTES(fd, out) recv(fd, out, sizeof(out), 0)\n'
                'int receive(int fd, struct S *s) { '
                'return GET_BYTES(fd, s->buf); }\n', encoding='utf-8',
            )
            field_bundle = StaticAnalyzer(root).index()
        field_receiver = next(item for item in field_bundle.functions.values()
                              if item.name == 'receive')
        field_site = next(item for item in field_receiver.external_call_sites
                          if item['api'] == 'recv')
        entry.entry_function_id = field_receiver.function_id
        entry.entry_line = field_site['line']
        self.assertEqual(_entry_destination_names(field_receiver, entry), set())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.c').write_text(
                '#include <sys/socket.h>\n'
                '#define GET_BYTES(fd, out) recv(fd, out, sizeof(out), 0)\n'
                'char shared[8];\n'
                'int receive(int fd) { return GET_BYTES(fd, shared); }\n',
                encoding='utf-8',
            )
            global_bundle = StaticAnalyzer(root).index()
        global_receiver = next(item for item in global_bundle.functions.values()
                               if item.name == 'receive')
        global_site = next(item for item in global_receiver.external_call_sites
                           if item['api'] == 'recv')
        self.assertEqual(global_site['direct_argument_identifiers'][1], '')

    def test_macro_generated_function_is_discovered_not_macro_pseudofunction(self):
        bundle = self.analyze('macro_handler.c')
        by_name = {f.name: f for f in bundle.functions.values()}
        self.assertIn('do_special', by_name)
        self.assertNotIn('MAKE_HANDLER', by_name)
        self.assertIn('clang-ast-c', by_name['do_special'].providers)
        self.assertIn(by_name['do_special'].function_id, by_name['dispatch'].callees)
        self.assertTrue(any(
            e.kind == 'source_candidate' and e.caller_id == by_name['dispatch'].function_id
            and e.callee_id == by_name['do_special'].function_id
            and 'clang-ast-c' in e.providers for e in bundle.edges
        ))

    def test_indirect_table_call_is_not_promoted_to_direct_edge(self):
        bundle = self.analyze('table_dispatch.c')
        by_name = {f.name: f for f in bundle.functions.values()}
        self.assertIn('run', by_name['dispatch'].external_calls)
        direct_to_handler = [
            e for e in bundle.edges
            if e.caller_id == by_name['dispatch'].function_id
            and e.callee_id in (by_name['do_set'].function_id, by_name['do_get'].function_id)
            and e.kind == 'direct'
        ]
        self.assertEqual(direct_to_handler, [], 'table initializer does not prove dispatch target')
        self.assertEqual(by_name['dispatch'].indirect_table_call_sites, [],
                         'a local struct member callback is not a global array call')

    def test_global_function_pointer_table_call_is_source_located(self):
        bundle = self.analyze('global_table_dispatch.c')
        by_name = {f.name: f for f in bundle.functions.values()}
        sites = by_name['dispatch'].indirect_table_call_sites
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]['table_name'], 'handlers')
        self.assertEqual(
            set(sites[0]['candidate_function_ids']),
            {by_name['do_set'].function_id, by_name['do_get'].function_id},
        )
        self.assertGreater(sites[0]['call_line'], 0)
        self.assertEqual(sum(
            site['callee_function_id'] == by_name['select_handler'].function_id
            for site in by_name['dispatch'].direct_call_sites
        ), 1, 'the selector call must not be mistaken for the outer table call')
        from harnesscreator.agents.common import function_payload
        self.assertEqual(function_payload(by_name['dispatch'])['indirect_table_call_sites'], sites)
        from harnesscreator.agents.harness import _source_candidate_return_to_table_routes
        routes = _source_candidate_return_to_table_routes(
            'int LLVMFuzzerTestOneInput(void) { dispatch(0, 0); }',
            'int LLVMFuzzerTestOneInput(void) { dispatch(0, 0); }',
            GraphStore(bundle), by_name['do_set'].function_id,
            [by_name['read_request'].function_id],
        )
        self.assertEqual(len(routes), 1)
        self.assertIn('possible table call handlers', routes[0])
        self.assertEqual(_source_candidate_return_to_table_routes(
            'int LLVMFuzzerTestOneInput(void) { do_set(0, 0); }',
            'int LLVMFuzzerTestOneInput(void) { do_set(0, 0); }',
            GraphStore(bundle), by_name['do_set'].function_id,
            [by_name['read_request'].function_id],
        ), [], 'calling a handler directly cannot satisfy the Entry route')

    def test_direct_call_does_not_lose_existing_source_functions(self):
        bundle = self.analyze('direct_dispatch.c')
        by_name = {f.name: f for f in bundle.functions.values()}
        self.assertTrue({'main', 'dispatch', 'read_request', 'do_set', 'do_get'} <= set(by_name))
        self.assertIn(by_name['dispatch'].function_id, by_name['read_request'].callees)

    def test_failed_ast_keeps_candidate_source_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'server.c').write_text(
                '#include "generated-not-present.h"\nint read_request(void) {return 1;}\n'
            )
            bundle = StaticAnalyzer(root).index()
            self.assertIn('read_request', {f.name for f in bundle.functions.values()})
            self.assertEqual(bundle.completeness['clang_c_ast_failed_files'], 1)
            self.assertFalse(bundle.completeness['authoritative'])

    def test_conflicting_compile_variants_are_not_silently_selected(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'server.c'
            source.write_text('#if SELECT == 1\nint first(void) {return 1;}\n'
                              '#else\nint second(void) {return 2;}\n#endif\n')
            (root / 'compile_commands.json').write_text(json.dumps([
                {'directory': str(root), 'file': 'server.c',
                 'arguments': ['clang', '-DSELECT=1', '-c', 'server.c']},
                {'directory': str(root), 'file': 'server.c',
                 'arguments': ['clang', '-DSELECT=2', '-c', 'server.c']},
            ]))
            from harnesscreator.analysis.clang_c import _compile_flags
            self.assertNotIn(source, _compile_flags(root))
            bundle = StaticAnalyzer(root).index()
            self.assertEqual(bundle.completeness['clang_c_ast_failed_files'], 1)


class ClangNotInstalledFallback(unittest.TestCase):
    def test_source_is_still_indexed_without_ast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 's.c').write_text('int handler(void) {return 2;}\n')
            with patch('harnesscreator.analysis.clang_c.shutil.which', return_value=None):
                bundle = StaticAnalyzer(root).index()
            self.assertIn('handler', {f.name for f in bundle.functions.values()})
            self.assertEqual(bundle.completeness['clang_c_ast_parsed_files'], 0)


if __name__ == '__main__':
    unittest.main()
