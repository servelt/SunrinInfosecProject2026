"""A requested inner macro needs a proven expansion chain from a function."""
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class NestedMacroContextTest(unittest.TestCase):
    def _resolve(self, source: str, header: str | None = None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            if header is not None:
                (root / "defs.h").write_text(header)
            (root / "target.c").write_text(source)
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "target.c"}}))
            return resolver.resolve(ContextRequest(
                "parse", "INNER", "MACRO", "inspect inner expansion", "definition"))

    def test_direct_wrapper_recovers_inner_macro(self):
        rows = self._resolve(
            "#define INNER() consume()\n"
            "#define OUTER() INNER()\n"
            "int parse(void) { OUTER(); return 0; }\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["relation"], "MACRO_INVOKED_THROUGH_MACRO")
        self.assertEqual(rows[0]["via_macro"], "OUTER")
        self.assertIn("#define INNER() consume()", rows[0]["source"])
        self.assertTrue(rows[0]["callsite_location"].endswith("target.c:2"))
        self.assertTrue(rows[0]["expansion_callsite_location"].endswith("target.c:3"))

    def test_wrapper_and_inner_in_included_header(self):
        rows = self._resolve(
            '#include "defs.h"\nint parse(void) { OUTER(); return 0; }\n',
            "#define INNER() consume()\n#define OUTER() INNER()\n")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["source_file"].endswith("defs.h"))

    def test_undefined_or_uncertain_inner_definition_is_not_claimed(self):
        self.assertEqual(self._resolve(
            "#define INNER() consume()\n#define OUTER() INNER()\n"
            "#undef INNER\nint parse(void) { OUTER(); return 0; }\n"), [])
        self.assertEqual(self._resolve(
            "#ifdef FEATURE\n#define INNER() consume()\n#endif\n"
            "#define OUTER() INNER()\n"
            "int parse(void) { OUTER(); return 0; }\n"), [])

    def test_unrelated_or_commented_reference_is_not_a_chain(self):
        self.assertEqual(self._resolve(
            "#define INNER() consume()\n#define OUTER() do_work() /* INNER() */\n"
            "int parse(void) { OUTER(); return 0; }\n"), [])
        self.assertEqual(self._resolve(
            "#define INNER() consume()\n#define OUTER() INNER()\n"
            "int parse(void) { return 0; }\n"), [])


if __name__ == "__main__":
    unittest.main()
