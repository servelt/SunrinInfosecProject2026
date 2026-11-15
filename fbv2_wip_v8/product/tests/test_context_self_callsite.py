import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class FunctionDefinitionRequestTest(unittest.TestCase):
    def test_same_function_request_is_definition_not_callsite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int target(int x) {\n    return x + 1;\n}\n")
            resolver = ContextResolver(SourceRepository(
                root, {"target": {"file": "target.c"}}))
            request = ContextRequest("target", "target", "FUNCTION",
                                     "inspect API contract", "declaration documentation")
            rows = resolver.resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["relation_evidence"], "SOURCE_DEFINITION_ONLY")
            self.assertEqual(rows[0]["callsite_location"], "UNKNOWN")

    def test_recursive_callsite_points_into_body(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int target(int x) {\n    if (x) return target(x-1);\n"
                "    return 0;\n}\n")
            resolver = ContextResolver(SourceRepository(
                root, {"target": {"file": "target.c"}}))
            request = ContextRequest("target", "target", "CALLEE",
                                     "inspect recursion", "actual callsite")
            row = resolver._function_context("target", request, relation="CALLEE_OF",
                                             related="target", call_type="direct")
            self.assertEqual(row["callsite_location"], f"{root / 'target.c'}:2")


if __name__ == "__main__":
    unittest.main()
