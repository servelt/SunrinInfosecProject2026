import shutil
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository
from vulnerabilityanalysis.scan import _resolve_verifier_context


@unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
class ApiDocumentationTest(unittest.TestCase):
    def _resolver(self, root: Path, *, with_build: bool = True) -> ContextResolver:
        return ContextResolver(SourceRepository(root, {"parse": {"file": "parse.c"}}),
                               build_command=([shutil.which("cc"), "-I", str(root),
                                               "{source}", "-o", "{binary}"]
                                              if with_build else None))

    @staticmethod
    def _request() -> ContextRequest:
        return ContextRequest("parse", "parse", "FUNCTION", "verify API contract",
                              "declaration-adjacent documentation of return value")

    def test_exact_build_active_api_comment_is_attached_to_same_request(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text('#include <api.h>\nint parse(int x) { return x; }\n')
            (root / "api.h").write_text(
                '#ifndef API_H\n#define API_H\n'
                '/** Return zero on failure. */\nint parse(int x);\n#endif\n')
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["relation_evidence"], "SOURCE_DEFINITION_ONLY")
            self.assertEqual(rows[1]["evidence_kind"], "ACTIVE_BUILD_API_DOCUMENTATION")
            self.assertIn("Return zero on failure", rows[1]["source"])
            self.assertEqual(rows[1]["semantic_contract_proven"], "false")
            expanded, records = _resolve_verifier_context(
                [self._request()], [], set(), 2, self._resolver(root))
            self.assertEqual(len(expanded), 2)
            self.assertEqual(records[0]["status"], "FETCHED")
            self.assertEqual(records[0]["expected_information_status"], "UNASSESSED")
            self.assertIn("ACTIVE_BUILD_API_DOCUMENTATION",
                          records[0]["retrieved_evidence_kinds"])

    def test_missing_build_does_not_guess_angle_include(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text('#include <api.h>\nint parse(int x) { return x; }\n')
            (root / "api.h").write_text('/** Return zero. */\nint parse(int x);\n')
            rows = self._resolver(root, with_build=False).resolve(self._request())
            self.assertEqual(len(rows), 1)

    def test_inactive_or_unincluded_comment_is_not_selected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text('#include <api.h>\nint parse(int x) { return x; }\n')
            (root / "api.h").write_text(
                '#if 0\n/** Wrong inactive contract. */\nint parse(int x);\n#endif\n')
            (root / "other.h").write_text('/** Wrong unrelated contract. */\nint parse(int x);\n')
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual(len(rows), 1)

    def test_multiple_active_declarations_are_unsupported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include <one.h>\n#include <two.h>\nint parse(int x) { return x; }\n')
            (root / "one.h").write_text('/** First contract. */\nint parse(int x);\n')
            (root / "two.h").write_text('/** Second contract. */\nint parse(int x);\n')
            rows = self._resolver(root).resolve(self._request())
            self.assertEqual(len(rows), 1)

    def test_type_field_uses_exact_build_active_header(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text(
                '#include <api.h>\nint parse(parser_t *parser) { return parser->count; }\n')
            (root / "api.h").write_text(
                'typedef struct {\n#ifdef WIDE\nsize_t count;\n'
                '#else\nint count;\n#endif\n} parser_t;\n')
            resolver = ContextResolver(SourceRepository(root, {"parse": {"file": "parse.c"}}),
                                       build_command=[shutil.which("cc"), "-DWIDE", "-I",
                                                      str(root), "{source}", "-o", "{binary}"])
            request = ContextRequest("parse", "parser->count", "TYPE",
                                     "inspect count", "exact type declaration")
            rows = resolver.resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source"], "size_t count;")
            self.assertEqual(self._resolver(root, with_build=False).resolve(request), [])


if __name__ == "__main__":
    unittest.main()
