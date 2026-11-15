"""Selected source must be the exact checkout definition and stable span."""

import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.source import SourceRepository


class SourceSpanIntegrityTests(unittest.TestCase):
    def test_stale_embedded_catalog_source_is_not_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.c").write_text("int parse(void) { return 0; }\n")
            repository = SourceRepository(root, {"parse": {
                "name": "parse", "file": "target.c", "start_line": 1,
                "source": "parse(void) { dangerous_copy(); }"}})
            with self.assertRaisesRegex(ValueError, "Catalog source does not match"):
                repository.open_function("parse")

    def test_identical_bodies_keep_selected_definition_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.cpp").write_text(
                "namespace A {\nint A::parse() { return 0; }\n}\n"
                "namespace B {\nint B::parse() { return 0; }\n}\n")
            repository = SourceRepository(root, {
                "a": {"function_id": "a", "name": "A::parse", "file": "target.cpp", "start_line": 2},
                "b": {"function_id": "b", "name": "B::parse", "file": "target.cpp", "start_line": 5},
            })
            first = repository.open_function_span("a")
            second = repository.open_function_span("b")
            self.assertEqual((first.start_line, second.start_line), (2, 5))
            self.assertIn("int A::parse", first.source)
            self.assertIn("int B::parse", second.source)
            self.assertNotEqual(first.source_file_sha256, "")

    def test_full_declaration_and_cpp_trailing_return(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.cpp").write_text(
                "static unsigned long parse(int x) { return x; }\n"
                "auto check(int x) -> bool { return x != 0; }\n")
            repository = SourceRepository(root, {
                "parse": {"name": "parse", "file": "target.cpp", "start_line": 1},
                "check": {"name": "check", "file": "target.cpp", "start_line": 2},
            })
            self.assertTrue(repository.open_function_span("parse").source.startswith(
                "static unsigned long parse"))
            self.assertTrue(repository.open_function_span("check").source.startswith(
                "auto check(int x) -> bool"))

    def test_return_type_on_preceding_line_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.c").write_text(
                "void\nparse(void) { return; }\n")
            repository = SourceRepository(root, {"parse": {
                "name": "parse", "file": "target.c", "start_line": 2,
                "end_line": 2, "source": "parse(void) { return; }"}})
            span = repository.open_function_span("parse")
            self.assertEqual(span.start_line, 1)
            self.assertTrue(span.source.startswith("void\nparse"))


if __name__ == "__main__":
    unittest.main()
