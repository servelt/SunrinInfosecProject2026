"""Regression tests for exact, active named compound TYPE declarations."""

import shutil
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class NamedCompoundTypeTest(unittest.TestCase):
    def _resolver(self, root: Path, *, build=False, max_chars=8000):
        command = ([shutil.which("cc"), "-DWIDE", "{source}", "-o", "{binary}"]
                   if build else None)
        return ContextResolver(
            SourceRepository(root, {"parse": {"file": "parse.c"}}),
            build_command=command, max_chars=max_chars)

    @staticmethod
    def _request(name="profile_t"):
        return ContextRequest("parse", name, "TYPE", "inspect profile layout",
                              "active complete typedef declaration")

    @staticmethod
    def _source(root: Path, header: str):
        (root / "parse.c").write_text(
            '#include "profile.h"\nint parse(profile_t *profile) { return profile->count; }\n')
        (root / "profile.h").write_text(header)

    def test_unconditional_named_compound_from_reachable_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            declaration = ("typedef struct profile_s {\n"
                           "    struct { int start; int end; } bounds;\n"
                           "    unsigned long count;\n"
                           "} profile_t;")
            self._source(root, declaration + "\n")
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source"], declaration)
            self.assertEqual(rows[0]["source_location"], f"{root / 'profile.h'}:1")
            self.assertEqual(rows[0]["build_evidence"],
                             "STATIC_QUOTED_INCLUDE_AND_ACTIVE_SOURCE")
            self.assertEqual(rows[0]["sizeof_proven"], "false")

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_build_active_compound_selects_one_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._source(root,
                "#ifdef WIDE\n"
                "typedef struct { unsigned long count; } profile_t;\n"
                "#else\n"
                "typedef struct { unsigned char count; } profile_t;\n"
                "#endif\n")
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual(len(rows), 1)
            self.assertIn("unsigned long count", rows[0]["source"])
            self.assertNotIn("unsigned char count", rows[0]["source"])
            self.assertEqual(rows[0]["build_evidence"],
                             "EXACT_COMMAND_PREPROCESSED_DECLARATION")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    def test_inactive_branch_and_unrelated_same_name_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._source(root,
                "#if 0\n"
                "typedef struct { int count; } profile_t;\n"
                "#endif\n"
                "typedef struct { unsigned count; } profile_t;\n")
            (root / "unrelated.h").write_text(
                "typedef struct { char count; } profile_t;\n")
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source"],
                             "typedef struct { unsigned count; } profile_t;")

    def test_unknown_branch_and_duplicate_active_definitions_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._source(root,
                "#ifdef FEATURE\n"
                "typedef struct { int count; } profile_t;\n"
                "#else\n"
                "typedef struct { unsigned count; } profile_t;\n"
                "#endif\n")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])
            self._source(root,
                "typedef struct { int count; } profile_t;\n"
                "typedef struct { unsigned count; } profile_t;\n")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    def test_oversized_declaration_and_different_alias_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._source(root,
                "typedef struct { " + "int pad; " * 25 + "int count; } profile_t;\n")
            self.assertEqual(self._resolver(root, max_chars=100).resolve(self._request()), [])
            self._source(root,
                "typedef struct { int count; } profile_t_extra;\n")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    def test_unknown_conditional_inside_compound_does_not_leak_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._source(root,
                "typedef struct {\n"
                "#ifdef FEATURE\nint count;\n#else\nunsigned count;\n#endif\n"
                "} profile_t;\n")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])


if __name__ == "__main__":
    unittest.main()
