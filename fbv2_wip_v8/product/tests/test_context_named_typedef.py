"""Named TYPE context must come from a reachable, unambiguous declaration."""

import shutil
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class NamedTypedefContextTest(unittest.TestCase):
    def _resolver(self, root: Path, *, build: bool = False) -> ContextResolver:
        command = ([shutil.which("cc"), "-DWIDE", "{source}", "-o", "{binary}"]
                   if build else None)
        return ContextResolver(SourceRepository(root, {"parse": {"file": "parse.c"}}),
                               build_command=command)

    @staticmethod
    def _request(target: str = "alias_t") -> ContextRequest:
        return ContextRequest("parse", target, "TYPE", "inspect element type",
                              "active typedef and size relation")

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_active_typedef_from_reachable_header(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "active.h"\nint parse(alias_t value) { return value; }\n')
            (root / "active.h").write_text(
                '#ifdef WIDE\ntypedef long alias_t;\n'
                '#else\ntypedef int alias_t;\n#endif\n')
            (root / "unrelated.h").write_text("typedef char alias_t;\n")
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source"], "typedef long alias_t;")
            self.assertEqual(rows[0]["source_location"], f"{root / 'active.h'}:2")
            self.assertEqual(rows[0]["build_evidence"],
                             "EXACT_COMMAND_PREPROCESSED_DECLARATION")
            self.assertEqual(rows[0]["sizeof_proven"], "false")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_conditional_include_uses_exact_build_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#ifdef WIDE\n#include "active.h"\n#endif\n'
                'int parse(alias_t value) { return value; }\n')
            (root / "active.h").write_text("typedef long alias_t;\n")
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual([row["source"] for row in rows],
                             ["typedef long alias_t;"])
            self.assertEqual(rows[0]["build_evidence"],
                             "EXACT_COMMAND_PREPROCESSED_DECLARATION")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    def test_unreferenced_or_duplicate_alias_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "one.h"\n#include "two.h"\n'
                'int parse(alias_t value) { return value; }\n')
            (root / "one.h").write_text("typedef int alias_t;\n")
            (root / "two.h").write_text("typedef long alias_t;\n")
            resolver = self._resolver(root)
            self.assertEqual(resolver.resolve(self._request()), [])
            self.assertEqual(resolver.resolve(self._request("unused_t")), [])

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_active_macro_spelling_links_to_typedef(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "active.h"\n#define SZ      alias_t\n'
                'int parse(SZ value) { return value; }\n')
            (root / "active.h").write_text(
                '#ifdef WIDE\ntypedef unsigned alias_t;\n#endif\n')
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual([row["source"] for row in rows],
                             ["typedef unsigned alias_t;"])
            self.assertEqual(rows[0]["macro_alias"], "SZ")
            self.assertEqual(rows[0]["macro_alias_source_location"],
                             f"{root / 'parse.c'}:2")
            self.assertEqual(rows[0]["relation_evidence"],
                             "FUNCTION_ACTIVE_MACRO_ALIAS_AND_TYPEDEF_DECLARATION")
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_inactive_macro_spelling_does_not_link_to_typedef(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "active.h"\n#if 0\n#define SZ alias_t\n#endif\n'
                '#define SZ int\nint parse(SZ value) { return value; }\n')
            (root / "active.h").write_text("typedef unsigned alias_t;\n")
            self.assertEqual(self._resolver(root, build=True).resolve(
                self._request()), [])

    def test_single_unconditional_quoted_include_without_build(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "active.h"\nint parse(alias_t value) { return value; }\n')
            (root / "active.h").write_text(
                '#if 0\ntypedef long alias_t;\n#endif\n'
                'typedef int alias_t;\n')
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual([row["source"] for row in rows], ["typedef int alias_t;"])
            self.assertEqual(rows[0]["build_evidence"],
                             "STATIC_QUOTED_INCLUDE_AND_ACTIVE_SOURCE")

    def test_forward_compound_alias_returns_reachable_complete_body(self):
        for kind, member in (("struct", "int count;"),
                             ("union", "int value;"),
                             ("enum", "ONE, TWO")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "parse.c").write_text(
                    '#include "alias.h"\nint parse(alias_t *value) { return value != 0; }\n')
                (root / "alias.h").write_text(
                    f'#include "body.h"\ntypedef {kind} tag_t alias_t;\n')
                (root / "body.h").write_text(
                    f"{kind} tag_t {{ {member} }};\n")
                rows = self._resolver(root).resolve(self._request())
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]["source"],
                                 f"typedef {kind} tag_t alias_t;")
                self.assertIn(member, rows[1]["source"])
                self.assertEqual(rows[1]["source_file"], str(root / "body.h"))
                self.assertEqual(rows[1]["sizeof_proven"], "false")

    def test_forward_compound_alias_rejects_ambiguous_body(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "alias.h"\nint parse(alias_t *value) { return value != 0; }\n')
            (root / "alias.h").write_text(
                'typedef struct tag_t alias_t;\n'
                'struct tag_t { int first; };\n'
                'struct tag_t { int second; };\n')
            self.assertEqual(self._resolver(root).resolve(self._request()), [])

    def test_forward_compound_alias_same_source_and_inactive_alternative(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                'typedef struct tag_t alias_t;\n'
                '#if 0\nstruct tag_t { int inactive; };\n#endif\n'
                'struct tag_t { int active; };\n'
                'int parse(alias_t *value) { return value->active; }\n')
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual(len(rows), 2)
            self.assertIn("int active;", rows[1]["source"])
            self.assertNotIn("inactive", rows[1]["source"])

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_forward_compound_alias_uses_exact_build_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include "types.h"\nint parse(alias_t *value) { return value->count; }\n')
            (root / "types.h").write_text(
                'typedef struct tag_t alias_t;\n'
                '#ifdef WIDE\nstruct tag_t { long count; };\n'
                '#else\nstruct tag_t { int count; };\n#endif\n')
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual(len(rows), 2)
            self.assertIn("long count;", rows[1]["source"])
            self.assertNotIn("int count;", rows[1]["source"])
            self.assertEqual(rows[1]["build_evidence"],
                             "EXACT_COMMAND_PREPROCESSED_DECLARATION")

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_conditional_fields_inside_active_compound_body(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                'typedef struct tag_t alias_t;\n'
                'struct tag_t {\n'
                '#ifdef WIDE\nint wide[128];\n'
                '#else\nint narrow[8];\n#endif\n};\n'
                'int parse(alias_t *value) { return value->wide[0]; }\n')
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual(len(rows), 2)
            self.assertIn('int wide[128];', rows[1]['source'])
            self.assertNotIn('int narrow[8];', rows[1]['source'])
            self.assertEqual(rows[1]['build_evidence'],
                             'EXACT_COMMAND_PREPROCESSED_DECLARATION')
            self.assertEqual(len(self._resolver(root).resolve(self._request())), 1)

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_compound_body_uses_its_own_translation_unit_with_header(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'z_header.h').write_text('typedef int unrelated_t;\n')
            (root / 'parse.c').write_text(
                '#include "z_header.h"\n'
                'typedef struct tag_t alias_t;\n'
                'struct tag_t {\n#ifdef WIDE\nint wide[128];\n'
                '#else\nint narrow[8];\n#endif\n};\n'
                'int parse(alias_t *value) { return value->wide[0]; }\n')
            rows = self._resolver(root, build=True).resolve(self._request())
            self.assertEqual(len(rows), 2)
            self.assertTrue(rows[1]['source'].startswith('struct tag_t {'))
            self.assertIn('int wide[128];', rows[1]['source'])
            self.assertNotIn('int narrow[8];', rows[1]['source'])


if __name__ == "__main__":
    unittest.main()
