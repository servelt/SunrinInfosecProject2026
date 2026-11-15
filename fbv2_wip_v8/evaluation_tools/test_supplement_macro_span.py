"""Generic Clang AST macro-span regression; no target-specific identifiers."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import subprocess

from supplement_compiled_catalog import _row_from_definition, nm_code_pairs


class MacroSpanTests(unittest.TestCase):
    def test_archive_member_with_plain_object_suffix_requires_build_mapping(self):
        output = "sample.o:\n00000000 T parse\n"
        with patch("supplement_compiled_catalog.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, output, "")):
            with self.assertRaisesRegex(ValueError, "object-to-source mapping required"):
                nm_code_pairs(Path("archive.a"), Path("nm"),
                              {"sample.c": "src/sample.c"})
            self.assertEqual(nm_code_pairs(Path("archive.a"), Path("nm"),
                                           {"sample.c": "src/sample.c"},
                                           {"sample.o": "sample.c"}),
                             {("src/sample.c", "parse")})

    def test_plain_object_suffix_with_ambiguous_source_stem_fails(self):
        output = "sample.o:\n00000000 T parse\n"
        with patch("supplement_compiled_catalog.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, output, "")):
            with self.assertRaisesRegex(ValueError, "object-to-source mapping required"):
                nm_code_pairs(Path("archive.a"), Path("nm"),
                              {"sample.c": "src/sample.c", "sample.cc": "src/sample.cc"})

    def test_unrecognized_archive_member_cannot_inherit_previous_source(self):
        output = ("sample.c.o:\n00000000 T first\n"
                  "other.obj:\n00000000 T phantom\n")
        with patch("supplement_compiled_catalog.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, output, "")):
            with self.assertRaisesRegex(ValueError, "unsupported archive member"):
                nm_code_pairs(Path("archive.a"), Path("nm"),
                              {"sample.c": "src/sample.c"},
                              {"sample.c.o": "sample.c"})

    def test_export_macro_expansion_uses_source_span(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.c"
            text = "API int parse(void) { return 1; }\n"
            source.write_text(text)
            node = {
                "name": "parse",
                "loc": {"line": 1, "offset": 8},
                "range": {
                    "begin": {"expansionLoc": {"file": str(source), "offset": 0,
                                               "tokLen": 3},
                              "spellingLoc": {"file": str(root / "macro.h"),
                                              "offset": 0, "tokLen": 3}},
                    "end": {"offset": text.index("}"), "tokLen": 1},
                },
            }
            row = _row_from_definition(node, source, root)
            self.assertEqual(row["file"], "sample.c")
            self.assertEqual(row["source"], text.strip())

    def test_cross_file_range_fails_closed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.c"
            second = root / "second.c"
            first.write_text("API int parse(void) { return 1; }\n")
            second.write_text("}\n")
            node = {"name": "parse", "loc": {},
                    "range": {"begin": {"file": str(first), "offset": 0,
                                        "tokLen": 3},
                              "end": {"file": str(second), "offset": 0,
                                      "tokLen": 1}}}
            with self.assertRaisesRegex(ValueError, "multiple source files"):
                _row_from_definition(node, first, root)


if __name__ == "__main__":
    unittest.main()
