"""Exact mixed-case C macro requests must retain source and caller provenance."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class MixedCaseMacroContextTest(unittest.TestCase):
    def test_exact_function_like_macro_used_by_selected_function(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "typedef struct { int length; } parse_buffer;\n"
                "#define can_access_at_index(buf, index) ((index) < (buf)->length)\n"
                "int parse(parse_buffer *buf) { return can_access_at_index(buf, 0); }\n")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest(
                "parse", "can_access_at_index", "MACRO", "inspect bound", "definition"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["definition_kind"], "FUNCTION_LIKE_MACRO")
            self.assertEqual(rows[0]["related_function"], "parse")
            self.assertEqual(rows[0]["source_location"], f"{root / 'target.c'}:2")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'target.c'}:3")

    def test_exact_macro_used_by_verified_caller_of_selected_function(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if not compiler:
            self.skipTest("Clang needed to prove active caller")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "typedef struct { int length; } parse_buffer;\n"
                "#define can_access_at_index(buf, index) ((index) < (buf)->length)\n"
                "int parse_string(parse_buffer *buf) { return *buf; }\n"
                "int parse_value(parse_buffer *buf) {\n"
                "  if (can_access_at_index(buf, 0)) return parse_string(buf);\n"
                "  return 0;\n}\n")
            graph = root / "edges.jsonl"
            graph.write_text(json.dumps({"caller_name": "parse_value",
                                         "callee_name": "parse_string",
                                         "call_type": "direct"}) + "\n")
            catalog = {name: {"file": "target.c"}
                       for name in ("parse_string", "parse_value")}
            resolver = ContextResolver(SourceRepository(root, catalog), call_graph_path=graph, build_command=[compiler, "{source}"])
            rows = resolver.resolve(ContextRequest(
                "parse_string", "can_access_at_index", "MACRO",
                "inspect caller bound", "definition"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["definition_kind"], "FUNCTION_LIKE_MACRO")
            self.assertEqual(rows[0]["related_function"], "parse_value")
            self.assertEqual(rows[0]["source_location"], f"{root / 'target.c'}:2")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'target.c'}:5")
            self.assertIn("can_access_at_index", rows[0]["source"])
            resolver_without_edge = ContextResolver(SourceRepository(root, catalog))
            self.assertEqual(resolver_without_edge.resolve(ContextRequest(
                "parse_string", "can_access_at_index", "MACRO",
                "inspect caller bound", "definition")), [])

    def test_unrelated_caller_macro_is_not_connected_by_graph_name_only(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if not compiler:
            self.skipTest("Clang needed to prove active caller")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "typedef struct { int length; } parse_buffer;\n"
                "#define can_access_at_index(buf, index) ((index) < (buf)->length)\n"
                "int parse_string(parse_buffer *buf) { return *buf; }\n"
                "int parse_value(parse_buffer *buf) { return can_access_at_index(buf, 0); }\n")
            graph = root / "edges.jsonl"
            graph.write_text(json.dumps({"caller_name": "parse_value",
                                         "callee_name": "parse_string",
                                         "call_type": "direct"}) + "\n")
            catalog = {name: {"file": "target.c"}
                       for name in ("parse_string", "parse_value")}
            resolver = ContextResolver(SourceRepository(root, catalog), call_graph_path=graph, build_command=[compiler, "{source}"])
            self.assertEqual(resolver.resolve(ContextRequest(
                "parse_string", "can_access_at_index", "MACRO", "inspect", "definition")), [])

    def test_inactive_caller_branch_does_not_supply_macro(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if not compiler:
            self.skipTest("Clang needed to prove active caller")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "typedef struct { int length; } parse_buffer;\n"
                "#define can_access_at_index(buf, index) ((index) < (buf)->length)\n"
                "int parse_string(parse_buffer *buf) { return buf->length; }\n"
                "int parse_value(parse_buffer *buf) {\n"
                "#if 0\n"
                "  if (can_access_at_index(buf, 0)) return parse_string(buf);\n"
                "#endif\n"
                "  return 0;\n}\n")
            graph = root / "edges.jsonl"
            graph.write_text(json.dumps({"caller_name": "parse_value",
                                         "callee_name": "parse_string",
                                         "call_type": "direct"}) + "\n")
            catalog = {name: {"file": "target.c"}
                       for name in ("parse_string", "parse_value")}
            resolver = ContextResolver(SourceRepository(root, catalog),
                                       call_graph_path=graph,
                                       build_command=[compiler, "{source}"])
            self.assertEqual(resolver.resolve(ContextRequest(
                "parse_string", "can_access_at_index", "MACRO", "inspect", "definition")), [])


if __name__ == "__main__":
    unittest.main()
