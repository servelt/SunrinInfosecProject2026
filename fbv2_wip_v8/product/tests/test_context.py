import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.scan import _fresh_analysis_context, _resolve_verifier_context
from vulnerabilityanalysis.source import SourceRepository


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer"
TARGET = Path("/tmp/va-libyaml")


@unittest.skipUnless(TARGET.is_dir(), "local libyaml checkout required")
class RealContextTest(unittest.TestCase):
    def test_macro_request_expands_only_relevant_source(self):
        harness = HarnessAdapter().load(ARTIFACT, target_repository=TARGET)
        resolver = ContextResolver(SourceRepository(TARGET, harness.function_catalog))
        req = ContextRequest("yaml_parser_scan", "DEQUEUE macro and parser->tokens queue type",
                             "MACRO", "check dequeue bound", "macro body")
        context = resolver.resolve(req)
        self.assertTrue(any("#define DEQUEUE" in item["source"] for item in context))
        self.assertTrue(all(len(item["source"]) <= 8000 for item in context))


class CallRelationContextTest(unittest.TestCase):
    def test_catalog_match_limit_reports_omitted_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int alpha(void) { return 1; }\n"
                "int beta(void) { return 2; }\n"
                "int gamma(void) { return 3; }\n")
            catalog = {name: {"file": "target.c"} for name in
                       ("alpha", "beta", "gamma")}
            resolver = ContextResolver(SourceRepository(root, catalog))
            resolver.resolve(ContextRequest("caller", "alpha beta gamma", "STATE",
                                            "inspect", "definitions"))
            self.assertIn({"kind": "CATALOG_MATCH_LIMIT", "omitted_candidates": 1},
                          resolver.last_limit_events)

    def test_field_hit_and_excerpt_limits_are_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int parse(void) { return 0; }\n" +
                "".join(f"p->count = {index};\n" for index in range(10)))
            resolver = ContextResolver(SourceRepository(root, {"parse": {"file": "target.c"}}),
                                       max_chars=40)
            resolver.resolve(ContextRequest("parse", "p->count", "STATE",
                                            "inspect", "writes"))
            self.assertIn({"kind": "FIELD_HIT_LIMIT", "omitted_candidates": 2},
                          resolver.last_limit_events)
            self.assertTrue(any(row["kind"] == "CONTEXT_SOURCE_CHAR_LIMIT"
                                for row in resolver.last_limit_events))

    def test_native_catalog_source_and_edge_kind_resolve_direct_caller(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = "int target(void) { return 1; }\nint caller(void) { return target(); }\n"
            (root / "target.c").write_text(source)
            catalog = {
                "target": {"function_id": "fn-target", "file": "target.c",
                           "start_line": 1, "source": source.splitlines()[0]},
                "caller": {"function_id": "fn-caller", "file": "target.c",
                           "start_line": 2, "source": source.splitlines()[1]},
            }
            graph = root / "edges.jsonl"
            graph.write_text(json.dumps({
                "caller_id": "fn-caller", "callee_id": "fn-target", "kind": "direct"}) + "\n")
            resolver = ContextResolver(SourceRepository(root, catalog), call_graph_path=graph)
            rows = resolver.resolve(ContextRequest(
                "target", "callers of target", "CALLER", "inspect", "caller source"))
            self.assertEqual([row["function_name"] for row in rows], ["caller"])
            self.assertEqual(rows[0]["relation"], "CALLER_OF")
            self.assertEqual(rows[0]["call_type"], "direct")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'target.c'}:2")
            self.assertTrue(rows[0]["source"].startswith("int caller("))

    def test_named_long_caller_keeps_late_direct_callsites_within_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            filler = "".join(f"  int value_{i} = {i};\n" for i in range(600))
            (root / "target.c").write_text(
                "int target(void) { return 1; }\n"
                "int caller(void) {\n" + filler +
                "  /* target() is only a comment. */\n"
                "  int result = target();\n"
                "  return result;\n}\n")
            resolver = ContextResolver(SourceRepository(root, {
                "target": {"file": "target.c"}, "caller": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest("target", "caller", "FUNCTION",
                                                   "inspect exact caller", "callsite"))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertIn("SOURCE TRUNCATED", row["source"])
            self.assertIn("int result = target();", row["callsite_excerpt"])
            self.assertEqual(row["callsite_locations"],
                             f"{root / 'target.c'}:604")
            self.assertEqual(row["callsite_evidence"],
                             "TEXTUAL_REFERENCE_ONLY_CALL_AND_BUILD_UNVERIFIED")
            self.assertLessEqual(len(row["source"]) + len(row["callsite_excerpt"]), 8000)

    def test_object_macro_in_caller_source_is_fetched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "#define MAX_ITEMS 4096\n"
                "int parse(void) { return MAX_ITEMS; }\n")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest("parse", "MAX_ITEMS", "MACRO",
                                                   "inspect limit", "definition"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_file"], str(root / "target.c"))
            self.assertIn("#define MAX_ITEMS 4096", rows[0]["source"])

    def test_object_macro_requires_unique_reachable_active_definition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "other").mkdir()
            caller = root / "src" / "target.c"
            caller.write_text('#include "limits.h"\nint parse(void) { return MAX_ITEMS; }\n')
            included = root / "src" / "limits.h"
            included.write_text("#define MAX_ITEMS 4096\n")
            (root / "other" / "limits.h").write_text("#define MAX_ITEMS 1\n")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "src/target.c"}}))
            request = ContextRequest("parse", "MAX_ITEMS", "MACRO",
                                     "inspect limit", "definition")
            rows = resolver.resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_file"], str(included))
            included.write_text(
                "#ifdef FEATURE\n#define MAX_ITEMS 4096\n"
                "#else\n#define MAX_ITEMS 2048\n#endif\n")
            self.assertEqual(resolver.resolve(request), [])
            included.write_text(
                "#define MAX_ITEMS 4096\n#define MAX_ITEMS 2048\n")
            self.assertEqual(resolver.resolve(request), [])
            included.write_text(
                "#if 0\n#define MAX_ITEMS 2048\n#endif\n"
                "#define MAX_ITEMS 4096\n")
            rows = resolver.resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertIn("4096", rows[0]["source"])

    def test_macro_definition_must_precede_reference_and_not_be_undefined(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            caller = root / "target.c"
            (root / "limits.h").write_text("#define MAX_ITEMS 4096\n")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "target.c"}}))
            request = ContextRequest("parse", "MAX_ITEMS", "MACRO",
                                     "inspect limit", "definition")
            caller.write_text("int parse(void) { return MAX_ITEMS; }\n"
                              "#define MAX_ITEMS 4096\n")
            self.assertEqual(resolver.resolve(request), [])
            caller.write_text("int parse(void) { return MAX_ITEMS; }\n"
                              '#include "limits.h"\n')
            self.assertEqual(resolver.resolve(request), [])
            caller.write_text('#include "limits.h"\n#undef MAX_ITEMS\n'
                              "int parse(void) { return MAX_ITEMS; }\n")
            self.assertEqual(resolver.resolve(request), [])
            caller.write_text('#include "limits.h"\n'
                              "int parse(void) { return MAX_ITEMS; }\n")
            rows = resolver.resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_file"], str(root / "limits.h"))

    def test_macro_definition_must_be_reachable_not_first_repository_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "rust").mkdir()
            (root / "src" / "target.c").write_text(
                '#include "util.h"\nint parse(void) { return PUSH(1); }\n')
            (root / "rust" / "util.h").write_text('#define PUSH(x) wrong(x)\n')
            (root / "src" / "util.h").write_text('#define PUSH(x) correct(x)\n')
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "src/target.c"}}))
            rows = resolver.resolve(ContextRequest("parse", "PUSH", "MACRO", "inspect", "body"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_file"], str(root / "src" / "util.h"))
            self.assertIn("correct(x)", rows[0]["source"])

    def test_conditional_c_and_cpp_macro_branches_remain_unresolved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "util.h").write_text(
                '#ifdef __cplusplus\n#define PUSH(x) cpp(x)\n'
                '#else\n#define PUSH(x) c(x)\n#endif\n')
            for suffix in ("c", "cpp"):
                source_path = root / "src" / f"target.{suffix}"
                source_path.write_text(
                    '#include "util.h"\nint parse(void) { return PUSH(1); }\n')
                resolver = ContextResolver(SourceRepository(root, {
                    "parse": {"file": f"src/target.{suffix}"}}))
                self.assertEqual(resolver.resolve(ContextRequest(
                    "parse", "PUSH", "MACRO", "inspect", "body")), [])
                compiler = "gcc" if suffix == "c" else "g++"
                if shutil.which(compiler):
                    expanded = subprocess.run(
                        [compiler, "-E", "-P", str(source_path)], check=True,
                        capture_output=True, text=True).stdout
                    self.assertIn("return c(1);" if suffix == "c" else
                                  "return cpp(1);", expanded)

    def test_mixed_project_cpp_caller_uses_its_own_unique_macro(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "c").mkdir()
            (root / "cpp").mkdir()
            (root / "c" / "util.h").write_text('#define PUSH(x) c_wrong(x)\n')
            (root / "cpp" / "util.h").write_text('#define PUSH(x) cpp_right(x)\n')
            (root / "cpp" / "target.cpp").write_text(
                '#include "util.h"\nint parse(void) { return PUSH(1); }\n')
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "cpp/target.cpp"}}))
            rows = resolver.resolve(ContextRequest("parse", "PUSH", "MACRO", "inspect", "body"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_file"], str(root / "cpp" / "util.h"))
            self.assertIn("cpp_right(x)", rows[0]["source"])

    def test_catalog_source_truncation_is_explicit(self):
        source = "int parse(void) { return helper(); }"
        repository = SourceRepository(Path("/tmp"), {"parse": {"source": source}})
        self.assertEqual(repository.open_function("parse"), source)
        self.assertEqual(repository.open_function("parse", max_chars=12),
                         source[:12] + "\n/* SOURCE TRUNCATED */")

    def test_analysis_context_reuses_identical_caller_source_without_losing_new_relation(self):
        held = [{"function_name": "caller", "source_file": "target.c",
                 "source_location": "target.c:10", "source": "void caller(void) { callee(); }",
                 "relation": "CALLER_OF", "related_function": "callee",
                 "callsite_location": "target.c:10", "reason": "first request"}]
        repeated = {**held[0], "reason": "same source requested for another reason"}
        other_relation = {**held[0], "related_function": "other"}
        self.assertEqual(_fresh_analysis_context([repeated], held), [])
        self.assertEqual(_fresh_analysis_context([repeated, other_relation, other_relation], held),
                         [other_relation])

    def test_uncatalogued_direct_callee_is_fetched_only_with_exact_definition_and_callsite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "caller.c").write_text("int helper(void);\nint parse(void) { return helper(); }\n")
            (root / "callee.c").write_text("int helper(void) { return 7; }\n")
            (root / "other.c").write_text(
                "int unrelated(void) { return 1; }\n"
                "int check(void) { if (helper()) { return 1; } return 0; }\n")
            (root / "harness.c").write_text("int HarnessEntry(void) { return 0; }\n")
            resolver = ContextResolver(SourceRepository(root, {"parse": {"file": "caller.c"}}),
                                       harness_path=root / "harness.c")
            rows = resolver.resolve(ContextRequest("parse", "helper", "CALLEE", "inspect", "source"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["function_name"], "helper")
            self.assertEqual(rows[0]["source_location"], f"{root / 'callee.c'}:1")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'caller.c'}:2")
            self.assertEqual(rows[0]["relation_evidence"], "SOURCE_CALLSITE")
            self.assertEqual(resolver.resolve(ContextRequest("parse", "unrelated", "CALLEE",
                                                             "inspect", "source")), [])

    def test_uncatalogued_callee_ambiguous_definition_is_not_fetched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "caller.c").write_text("int helper(void);\nint parse(void) { return helper(); }\n")
            (root / "one.c").write_text("int helper(void) { return 1; }\n")
            (root / "two.c").write_text("int helper(void) { return 2; }\n")
            resolver = ContextResolver(SourceRepository(root, {"parse": {"file": "caller.c"}}))
            self.assertEqual(resolver.resolve(ContextRequest("parse", "helper", "CALLEE",
                                                             "inspect", "source")), [])

    def test_missing_graph_edge_uses_only_confirmed_direct_call_or_macro_invocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "#define PUSH(x) ((x) + 1)\n"
                "int helper(void) { return 1; }\n"
                "int unused(void) { return 2; }\n"
                "int parse(void) { return PUSH(helper()); }\n")
            graph = root / "edges.json"
            graph.write_text("[]")
            catalog = {name: {"file": "target.c"} for name in
                       ("parse", "helper", "unused")}
            resolver = ContextResolver(SourceRepository(root, catalog), call_graph_path=graph)
            helper = resolver.resolve(ContextRequest("parse", "helper", "CALLEE", "inspect", "source"))
            self.assertEqual(len(helper), 1)
            self.assertEqual(helper[0]["relation"], "CALLEE_OF")
            self.assertEqual(helper[0]["relation_evidence"], "SOURCE_CALLSITE")
            self.assertEqual(helper[0]["call_graph_artifact"], "UNKNOWN")
            macro = resolver.resolve(ContextRequest("parse", "PUSH", "CALLEE", "inspect", "macro"))
            self.assertEqual(len(macro), 1)
            self.assertEqual(macro[0]["relation"], "MACRO_INVOKED_BY")
            self.assertIn("#define PUSH", macro[0]["source"])
            request = ContextRequest("parse", "PUSH", "CALLEE", "inspect", "macro")
            expanded, records = _resolve_verifier_context([request], [], set(), 2, resolver)
            self.assertEqual(len(expanded), 1)
            self.assertEqual(records[0]["status"], "FETCHED")
            again, records = _resolve_verifier_context([request], expanded, set(), 2, resolver)
            self.assertFalse(again)
            self.assertEqual(records[0]["status"], "REUSED_EXISTING_CONTEXT")
            self.assertEqual(resolver.resolve(ContextRequest("parse", "unused", "CALLEE",
                                                             "inspect", "source")), [])
            self.assertEqual(resolver.resolve(ContextRequest("unused", "PUSH", "CALLEE",
                                                             "inspect", "macro")), [])

    def test_verifier_can_fetch_confirmed_macro_after_analyzer_uses_its_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "#define TAKE(q) (*(q).head++)\n"
                "int helper(void) { return 1; }\n"
                "int scan(queue_t q) { return TAKE(q) + helper(); }\n")
            resolver = ContextResolver(SourceRepository(root, {
                "scan": {"file": "target.c"}, "helper": {"file": "target.c"}}))
            analyzer_requested = {("initialize", "FUNCTION"), ("fill", "FUNCTION")}
            verifier_requested: set[tuple[str, str]] = set()
            requests = [ContextRequest("scan", "helper", "FUNCTION", "check helper", "body"),
                        ContextRequest("scan", "TAKE", "MACRO", "check queue guard", "macro body")]
            expanded, records = _resolve_verifier_context(
                requests, [], verifier_requested, 2, resolver)
            self.assertEqual([row["status"] for row in records], ["FETCHED", "FETCHED"])
            self.assertEqual(len(expanded), 2)
            self.assertTrue(any("#define TAKE" in row["source"] for row in expanded))
            self.assertEqual(analyzer_requested, {("initialize", "FUNCTION"), ("fill", "FUNCTION")})
            self.assertEqual(verifier_requested, {("helper", "FUNCTION"), ("TAKE", "MACRO")})

    def test_caller_request_returns_only_graph_confirmed_callers_with_source_location(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int parse(void) { return 1; }\n"
                "int actual_caller(void) { return parse(); }\n"
                "int unrelated(void) { return 0; }\n")
            graph = root / "edges.json"
            graph.write_text(json.dumps([
                {"caller_name": "actual_caller", "callee_name": "parse", "call_type": "direct"},
                {"caller_name": "unrelated", "callee_name": "parse", "call_type": "direct"},
            ]))
            catalog = {name: {"file": "target.c"} for name in
                       ("parse", "actual_caller", "unrelated")}
            resolver = ContextResolver(SourceRepository(root, catalog), call_graph_path=graph)
            rows = resolver.resolve(ContextRequest("parse", "callers of parse", "CALLER",
                                                   "check guard", "caller source"))
            self.assertEqual([row["function_name"] for row in rows], ["actual_caller"])
            self.assertEqual(rows[0]["relation"], "CALLER_OF")
            self.assertEqual(rows[0]["related_function"], "parse")
            self.assertEqual(rows[0]["source_location"], f"{root / 'target.c'}:2")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'target.c'}:2")
            self.assertEqual(rows[0]["call_graph_artifact"], str(graph))

    def test_callee_request_requires_real_graph_edge_and_matching_definition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int helper(void) { return 1; }\n"
                "int other(void) { return 2; }\n"
                "int parse(void) { return helper(); }\n")
            graph = root / "edges.json"
            graph.write_text(json.dumps([
                {"caller_name": "parse", "callee_name": "helper", "call_type": "direct"},
                {"caller_name": "parse", "callee_name": "other", "call_type": "direct"},
            ]))
            catalog = {name: {"file": "target.c"} for name in ("parse", "helper", "other")}
            resolver = ContextResolver(SourceRepository(root, catalog), call_graph_path=graph)
            rows = resolver.resolve(ContextRequest("parse", "helper and other", "CALLEE",
                                                   "inspect callees", "definitions"))
            self.assertEqual([row["function_name"] for row in rows], ["helper"])
            self.assertEqual(rows[0]["relation"], "CALLEE_OF")
            self.assertEqual(resolver.resolve(ContextRequest("parse", "missing", "CALLEE",
                                                             "inspect", "definition")), [])

    def test_real_libyaml_caller_is_harness_entry_not_scanner_itself(self):
        target = Path('/tmp/va-ollama-libyaml')
        if not target.is_dir():
            self.skipTest('local libyaml source unavailable')
        harness = HarnessAdapter().load(ARTIFACT, target_repository=target)
        graph = Path(harness.metadata['static_index_path']) / 'edges.json'
        resolver = ContextResolver(SourceRepository(target, harness.function_catalog),
                                   call_graph_path=graph, harness_path=Path(harness.harness_path))
        rows = resolver.resolve(ContextRequest('yaml_parser_scan',
                                               'callers of yaml_parser_scan', 'caller_definition',
                                               'check caller guard', 'callsite'))
        self.assertEqual([row['function_name'] for row in rows], ['LLVMFuzzerTestOneInput'])
        self.assertIn('yaml_parser_scan(', rows[0]['source'])
        self.assertNotEqual(rows[0]['function_name'], 'yaml_parser_scan')


class TypeContextTest(unittest.TestCase):
    def test_inactive_preprocessor_declaration_is_not_a_type_fact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "parser.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'parser.h').write_text(
                '#if 0\ntypedef struct { int unread; } parser_t;\n#endif\n'
                'typedef struct active_s { unsigned long unread; } active_s;\n'
                'typedef active_s parser_t;\n')
            compiler = shutil.which('clang') or shutil.which('cc')
            if compiler:
                built = subprocess.run([compiler, '-fsyntax-only', str(root / 'parse.c')],
                                       capture_output=True, text=True, timeout=10)
                self.assertEqual(built.returncode, 0, built.stderr)
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            rows = resolver.resolve(ContextRequest('parse', 'parser->unread', 'TYPE',
                                                   'check type', 'field declaration'))
            self.assertEqual(rows, [])

    def test_unrelated_header_cannot_supply_receiver_declaration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "active.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'active.h').write_text(
                'typedef struct parser_s { unsigned long unread; } parser_s;\n'
                'typedef parser_s parser_t;\n')
            (root / 'unrelated.h').write_text(
                'typedef struct { int unread; } parser_t;\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            rows = resolver.resolve(ContextRequest('parse', 'parser->unread', 'TYPE',
                                                   'check type', 'field declaration'))
            self.assertEqual(rows, [])

    def test_exact_receiver_type_selects_its_field_declaration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "parser.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'parser.h').write_text(
                'typedef struct parser_s {\n'
                '    struct { char *start; char *end; } buffer;\n'
                '    unsigned long unread;\n'
                '} parser_t;\n')
            (root / 'other.h').write_text(
                'typedef struct other_s {\n'
                '    int buffer;\n'
                '    long unread;\n'
                '} other_t;\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            for field, declaration, line in (
                ('buffer', 'struct { char *start; char *end; } buffer;', 2),
                ('unread', 'unsigned long unread;', 3),
            ):
                with self.subTest(field=field):
                    rows = resolver.resolve(ContextRequest('parse', f'parser->{field}', 'TYPE',
                                                           'check type', 'field declaration'))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]['source'], declaration)
                    self.assertEqual(rows[0]['source_location'], f"{root / 'parser.h'}:{line}")
                    self.assertEqual(rows[0]['declaring_type'], 'parser_t')
                    self.assertEqual(rows[0]['receiver_declaration'], 'parser_t *parser')
                    self.assertNotIn('other_t', rows[0]['source'])

    def test_tagged_forward_type_keeps_unconditional_field_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "parser.h"\n'
                'int parse(parser_t *parser) { return parser->count; }\n')
            (root / 'parser.h').write_text(
                'typedef struct parser_s parser_t;\n'
                'struct parser_s {\n'
                '    unsigned long count;\n'
                '#ifdef WIDE_BUFFER\n'
                '    char buffer[256];\n'
                '#else\n'
                '    char buffer[128];\n'
                '#endif\n'
                '};\n'
                '#ifdef OPTIONAL_HELPER\n'
                'int helper(parser_t *parser);\n'
                '#endif\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            request = lambda field: ContextRequest('parse', f'parser->{field}', 'TYPE',
                                                   'check field', 'field declaration')
            rows = resolver.resolve(request('count'))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['source'], 'unsigned long count;')
            self.assertEqual(rows[0]['relation_evidence'],
                             'FUNCTION_RECEIVER_AND_TAGGED_TYPE_DEFINITION')
            self.assertEqual(resolver.resolve(request('buffer')), [])

    def test_ambiguous_type_or_missing_receiver_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text('int parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'one.h').write_text('typedef struct { size_t unread; } parser_t;\n')
            (root / 'two.h').write_text('typedef struct { int other; } parser_t;\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            request = lambda target: ContextRequest('parse', target, 'TYPE', 'check type', 'declaration')
            self.assertEqual(resolver.resolve(request('parser->unread')), [])
            self.assertEqual(resolver.resolve(request('unknown->unread')), [])

    def test_real_libyaml_type_without_build_include_path_is_unknown(self):
        target = Path('/tmp/va-ollama-libyaml')
        if not target.is_dir():
            self.skipTest('local libyaml source unavailable')
        resolver = ContextResolver(SourceRepository(target, {
            'yaml_parser_fetch_next_token': {'file': 'src/scanner.c'},
        }))
        # scanner.c includes yaml_private.h, which uses <yaml.h>.  Without
        # the build's -I path, the project header cannot be identified safely.
        for field in ('buffer', 'unread'):
            with self.subTest(field=field):
                rows = resolver.resolve(ContextRequest('yaml_parser_fetch_next_token',
                                                       f'parser->{field}', 'TYPE',
                                                       'verify type', 'actual field declaration'))
                self.assertEqual(rows, [])

    def test_unknown_build_macro_does_not_select_a_conditional_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "parser.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'parser.h').write_text(
                '#ifdef USE_OLD_LAYOUT\n'
                'typedef struct { int unread; } parser_t;\n'
                '#endif\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            self.assertEqual(resolver.resolve(ContextRequest('parse', 'parser->unread',
                'TYPE', 'check macro layout', 'field declaration')), [])

    def test_unknown_member_layout_is_not_selected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "parser.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'parser.h').write_text(
                'typedef struct {\n#ifdef WIDE_UNREAD\n'
                'unsigned long unread;\n#else\nint unread;\n#endif\n} parser_t;\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            self.assertEqual(resolver.resolve(ContextRequest('parse', 'parser->unread',
                'TYPE', 'check field layout', 'field declaration')), [])

    def test_literal_preprocessor_branch_keeps_active_type(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "parser.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'parser.h').write_text(
                '#if 0\ntypedef struct { int unread; } parser_t;\n'
                '#else\ntypedef struct { unsigned long unread; } parser_t;\n#endif\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            rows = resolver.resolve(ContextRequest('parse', 'parser->unread',
                'TYPE', 'check active layout', 'field declaration'))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['source'], 'unsigned long unread;')

    def test_unincluded_duplicate_does_not_hide_quoted_include_type(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'parse.c').write_text(
                '#include "active.h"\nint parse(parser_t *parser) { return parser->unread; }\n')
            (root / 'active.h').write_text('typedef struct { size_t unread; } parser_t;\n')
            (root / 'other.h').write_text('typedef struct { int unread; } parser_t;\n')
            resolver = ContextResolver(SourceRepository(root, {'parse': {'file': 'parse.c'}}))
            rows = resolver.resolve(ContextRequest('parse', 'parser->unread',
                'TYPE', 'check type', 'field declaration'))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['source_file'], str(root / 'active.h'))
            self.assertEqual(rows[0]['source'], 'size_t unread;')


if __name__ == "__main__":
    unittest.main()
