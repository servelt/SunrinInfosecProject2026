import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.candidate_location import resolve_hp_location


class CandidateLocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "target.c"
        self.source.write_text(
            "int parse(int *p, int n) {\n"
            "  int *q = malloc(n);\n"
            "  q[n] = 0;\n"
            "  return 0;\n"
            "}\n")
        self.function = self.source.read_text()

    def resolve(self, claim):
        return resolve_hp_location(
            claim, source_file="target.c", source_path=self.source,
            target_root=self.root, function_source=self.function,
            function_start_line=1)

    def test_exact_single_line_quote_is_accepted_before_runtime(self):
        result = self.resolve("target.c:2:   int *q = malloc(n);")
        self.assertEqual(result.status, "VERIFIED_SINGLE_LINE")
        self.assertEqual(result.source_line, 2)
        self.assertEqual(result.code_location, "target.c:2")

    def test_allocation_location_is_not_shifted_to_later_crash_line(self):
        result = self.resolve("target.c:2:   int *q = malloc(n);")
        self.assertEqual(result.code_location, "target.c:2")
        self.assertNotEqual(result.code_location, "target.c:3")

    def test_range_multiline_bare_line_and_wrong_quote_are_unknown(self):
        claims = (
            "target.c:2-3: int *q = malloc(n);",
            "target.c:2~3: int *q = malloc(n);",
            "target.c:2: int *q = malloc(n);\nq[n] = 0;",
            "target.c:2",
            "target.c:2: q[n] = 0;",
            "elsewhere.c:2: int *q = malloc(n);",
            "parse: q[n] = 0;",
        )
        for claim in claims:
            with self.subTest(claim=claim):
                result = self.resolve(claim)
                self.assertEqual(result.status, "UNKNOWN")
                self.assertIsNone(result.source_line)

    def test_location_outside_selected_function_or_checkout_is_unknown(self):
        self.source.write_text("int before(void) { return 1; }\n" + self.function)
        result = resolve_hp_location(
            "target.c:1: int before(void) { return 1; }",
            source_file="target.c", source_path=self.source,
            target_root=self.root, function_source=self.function,
            function_start_line=2)
        self.assertEqual(result.status, "UNKNOWN")
        external = self.root.parent / "external.c"
        external.write_text(self.function)
        self.addCleanup(lambda: external.unlink(missing_ok=True))
        outside = resolve_hp_location(
            "target.c:2: int *q = malloc(n);",
            source_file="target.c", source_path=external,
            target_root=self.root, function_source=self.function,
            function_start_line=1)
        self.assertEqual(outside.status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
