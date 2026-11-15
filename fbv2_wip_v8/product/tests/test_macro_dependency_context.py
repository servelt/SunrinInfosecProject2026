"""A requested function carries only proven active local macro dependencies."""
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class MacroDependencyContextTest(unittest.TestCase):
    def _resolved(self, source):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(source)
            (root / "unrelated.cpp").write_text(
                "#define STRCMP(a,b) unrelated_cpp(a,b)\n")
            resolver = ContextResolver(SourceRepository(root, {
                "lookup": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest(
                "lookup", "lookup", "FUNCTION", "inspect key equality", "definition"))
            self.assertEqual(len(rows), 1)
            return rows[0].get("macro_dependencies", [])

    def test_local_unconditional_define_resolves_active_branch(self):
        rows = self._resolved(
            "#define CASE_INSENSITIVE\n#ifdef CASE_INSENSITIVE\n"
            "#define STRCMP(a,b) strcasecmp(a,b)\n#else\n"
            "#define STRCMP(a,b) strcmp(a,b)\n#endif\n"
            "int lookup(const char *a, const char *b) { return STRCMP(a,b); }\n")
        self.assertEqual(len(rows), 1)
        self.assertIn("strcasecmp", rows[0]["source"])
        self.assertNotIn("unrelated_cpp", rows[0]["source"])

    def test_unknown_build_branch_is_not_selected(self):
        rows = self._resolved(
            "#ifdef FEATURE\n#define STRCMP(a,b) strcasecmp(a,b)\n"
            "#else\n#define STRCMP(a,b) strcmp(a,b)\n#endif\n"
            "int lookup(const char *a, const char *b) { return STRCMP(a,b); }\n")
        self.assertEqual(rows, [])

    def test_later_definition_does_not_apply_retroactively(self):
        rows = self._resolved(
            "int lookup(const char *a, const char *b) { return STRCMP(a,b); }\n"
            "#define STRCMP(a,b) strcasecmp(a,b)\n")
        self.assertEqual(rows, [])

    def test_unknown_redefinition_does_not_claim_build_activation(self):
        rows = self._resolved(
            "#define STRCMP(a,b) strcasecmp(a,b)\n"
            "#ifdef FEATURE\n#undef STRCMP\n"
            "#define STRCMP(a,b) strcmp(a,b)\n#endif\n"
            "int lookup(const char *a, const char *b) { return STRCMP(a,b); }\n")
        self.assertEqual(rows, [])
