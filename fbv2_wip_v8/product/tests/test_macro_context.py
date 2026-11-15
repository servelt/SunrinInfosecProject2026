"""Focused regression tests for bounded, evidence-labelled macro-wrapped context."""
import tempfile
import unittest
from pathlib import Path
import os
import shutil

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.macro_functions import wrapped_function_source
from vulnerabilityanalysis.source import SourceRepository


PNG_MALLOC = """/* allocator */
PNG_FUNCTION(png_voidp,PNGAPI
png_calloc,(png_const_structrp png_ptr, png_alloc_size_t size),
PNG_ALLOCATED)
{
    png_voidp ret = png_malloc(png_ptr, size);
    if (ret != NULL) memset(ret, 0, size);
    return ret;
}
"""
PNG_CREATE = """PNG_FUNCTION(png_structrp, png_create_png_struct,
(png_const_charp version, int flags), PNG_ALLOCATED)
{
    return create_alloc(flags);
}
"""


class MacroWrappedContextTests(unittest.TestCase):
    def test_exact_build_resolves_active_macro_behind_header_guard(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if not compiler:
            self.skipTest("Clang is needed to prove the active build macro")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "util.h").write_text(
                "#ifndef UTIL_H\n#define UTIL_H\n#define LIMIT 4\n#endif\n",
                encoding="utf-8")
            (root / "target.c").write_text(
                '#include "util.h"\nint target(int n) { return n + LIMIT; }\n',
                encoding="utf-8")
            repository = SourceRepository(root, {"target": {"file": "target.c"}})
            request = ContextRequest("target", "LIMIT", "MACRO", "check bound", "active value")
            self.assertEqual(ContextResolver(repository).resolve(request), [])
            resolver = ContextResolver(repository, build_command=[compiler, "{source}"])
            rows = resolver.resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_location"], f"{root / 'util.h'}:3")
            self.assertEqual(rows[0]["source"], "#define LIMIT 4")
            self.assertEqual(rows[0]["build_activation"], "EXACT_BUILD_PREPROCESSOR")

    def test_exact_build_does_not_return_macro_used_only_in_inactive_branch(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if not compiler:
            self.skipTest("Clang is needed to prove branch activation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "util.h").write_text(
                "#ifndef UTIL_H\n#define UTIL_H\n#define HIDDEN 7\n#endif\n",
                encoding="utf-8")
            (root / "target.c").write_text(
                '#include "util.h"\nint target(int n) {\n#if 0\n'
                '  return n + HIDDEN;\n#endif\n  return n;\n}\n', encoding="utf-8")
            repository = SourceRepository(root, {"target": {"file": "target.c"}})
            resolver = ContextResolver(repository, build_command=[compiler, "{source}"])
            request = ContextRequest("target", "HIDDEN", "MACRO", "check", "active value")
            self.assertEqual(resolver.resolve(request), [])

    def test_exact_build_ignores_same_name_in_unrelated_language_port(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if not compiler:
            self.skipTest("Clang is needed to prove the active build macro")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "c").mkdir()
            (root / "rust_port").mkdir()
            (root / "c" / "util.h").write_text(
                "#ifndef C_UTIL_H\n#define C_UTIL_H\n#define LIMIT 4\n#endif\n",
                encoding="utf-8")
            (root / "c" / "target.c").write_text(
                '#include "util.h"\nint target(int n) { return n + LIMIT; }\n',
                encoding="utf-8")
            (root / "rust_port" / "util.h").write_text(
                "#define LIMIT 999\n", encoding="utf-8")
            repository = SourceRepository(root, {"target": {"file": "c/target.c"}})
            resolver = ContextResolver(repository, build_command=[compiler, "{source}"])
            rows = resolver.resolve(ContextRequest(
                "target", "LIMIT", "MACRO", "check bound", "active value"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_location"], f"{root / 'c' / 'util.h'}:3")
            self.assertEqual(rows[0]["source"], "#define LIMIT 4")

    def test_macro_signature_exact_name_prototype_excluded(self):
        text = ("PNG_FUNCTION(void, png_calloc, (int x), PNG_ALLOCATED);\n" + PNG_MALLOC)
        actual = wrapped_function_source(text, "png_calloc", 8000)
        self.assertIsNotNone(actual)
        self.assertTrue(actual.startswith("PNG_FUNCTION(png_voidp,PNGAPI"))
        self.assertIn("return ret;", actual)
        self.assertIsNone(wrapped_function_source(text, "png_cal", 8000))
        self.assertIsNone(wrapped_function_source(text, "png_malloc", 8000))

    def test_duplicate_macro_definitions_refused(self):
        self.assertIsNone(wrapped_function_source(PNG_MALLOC + "\n" + PNG_MALLOC,
                                                  "png_calloc", 8000))

    def test_macro_invocation_without_function_body_refused(self):
        invalid = """#define PNG_FUNCTION(a,b,c,d) a b c
PNG_FUNCTION(void,png_calloc,(int x),PNG_ALLOCATED);
int parse(void) { PNG_FUNCTION(void,png_calloc,(int x),PNG_ALLOCATED); return 0; }
"""
        self.assertIsNone(wrapped_function_source(invalid, "png_calloc", 8000))

    def test_named_function_uncatalogued_and_source_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pngmem.c").write_text(PNG_MALLOC, encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {}))
            req = ContextRequest("caller", "png_calloc", "FUNCTION", "check alloc", "body")
            rows = resolver.resolve(req)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_file"], str(root / "pngmem.c"))
            self.assertEqual(rows[0]["source_location"], f"{root / 'pngmem.c'}:2")
            self.assertEqual(rows[0]["definition_kind"], "MACRO_WRAPPED_SOURCE_DEFINITION")
            self.assertEqual(rows[0]["build_activation"], "UNKNOWN")
            self.assertIn("png_malloc(png_ptr, size)", rows[0]["source"])

    def test_catalogued_macro_definition_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "png.c").write_text(PNG_CREATE, encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {
                "png_create_png_struct": {"file": "png.c"}}))
            rows = resolver.resolve(ContextRequest(
                "caller", "png_create_png_struct", "FUNCTION", "check", "definition"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_location"], f"{root / 'png.c'}:1")
            self.assertIn("return create_alloc(flags)", rows[0]["source"])

    def test_uncatalogued_callee_requires_real_callsite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pngmem.c").write_text(PNG_MALLOC, encoding="utf-8")
            (root / "target.c").write_text(
                "int png_calloc(void *, int);\n"
                "int parse(void) { return png_calloc(0, 8) != 0; }\n"
                "int unrelated(void) { return 0; }\n", encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "target.c"},
                "unrelated": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest("parse", "png_calloc", "CALLEE", "check", "body"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["relation_evidence"], "SOURCE_CALLSITE")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'target.c'}:2")
            self.assertEqual(rows[0]["build_activation"], "UNKNOWN")
            self.assertEqual(resolver.resolve(ContextRequest("unrelated", "png_calloc", "CALLEE",
                                                             "check", "body")), [])

    def test_named_function_includes_only_proven_direct_callsite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pngmem.c").write_text(PNG_MALLOC, encoding="utf-8")
            (root / "target.c").write_text(
                "int png_calloc(void *, int);\n"
                "int parse(void) { return png_calloc(0, 8) != 0; }\n", encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {"parse": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest("parse", "png_calloc", "FUNCTION", "check", "body"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["relation_evidence"], "SOURCE_CALLSITE")
            self.assertEqual(rows[0]["callsite_location"], f"{root / 'target.c'}:2")

    def test_named_function_unproven_caller_does_not_claim_callsite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pngmem.c").write_text(PNG_MALLOC, encoding="utf-8")
            (root / "target.c").write_text(
                "int parse(void) { return 1; }\n", encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {"parse": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest("parse", "png_calloc", "FUNCTION", "check", "body"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["relation_evidence"], "SOURCE_DEFINITION_ONLY")
            self.assertEqual(rows[0]["callsite_location"], "UNKNOWN")

    def test_multiple_source_files_refused_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pngmem.c").write_text(PNG_MALLOC, encoding="utf-8")
            (root / "other.c").write_text(PNG_MALLOC, encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {}))
            self.assertEqual(resolver.resolve(ContextRequest(
                "caller", "png_calloc", "FUNCTION", "check", "body")), [])

    def test_normal_function_lookup_not_regressed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "normal.c").write_text("int helper(void) { return 42; }\n", encoding="utf-8")
            resolver = ContextResolver(SourceRepository(root, {"helper": {"file": "normal.c"}}))
            rows = resolver.resolve(ContextRequest("caller", "helper", "FUNCTION", "check", "body"))
            self.assertEqual(len(rows), 1)
            self.assertNotIn("definition_kind", rows[0])
            self.assertEqual(rows[0]["source_location"], f"{root / 'normal.c'}:1")


if __name__ == "__main__":
    unittest.main()
