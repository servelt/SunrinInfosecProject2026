"""The same C/C++ source suffixes must survive location and Crash evidence paths."""
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.models import RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.final_verification import classify_crash_relation
from vulnerabilityanalysis.runtime import parse_sp_trace
from vulnerabilityanalysis.scan import _exact_sp_location
from vulnerabilityanalysis.scheduler import semantic_sp_duplicate


def point(file: str, sp_id: str) -> SuspiciousPoint:
    return SuspiciousPoint(sp_id, "w", "d", "parse", file, f"{file}:1",
                           "read ptr", "heap buffer overflow at read", ["input index controls read"],
                           "input bytes", ["index exceeds allocation"], [], [], [], source_line=1,
                           source_excerpt="return *ptr;")


class CppSourceSuffixConsistencyTest(unittest.TestCase):
    def test_cxx_and_hxx_locations_reach_runtime_relation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for suffix in ("cpp", "cxx", "hxx"):
                with self.subTest(suffix=suffix):
                    source = root / f"parse.{suffix}"
                    source.write_text("return *ptr;\n")
                    candidate = point(source.name, "sp-a")
                    self.assertEqual(_exact_sp_location(candidate.code_location, root),
                                     f"{source}:1")
                    stderr = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                              f"#0 0x1 in parse {source}:1:2\n")
                    result = RuntimeResult(-6, "", stderr, 6, False,
                                           "AddressSanitizer: heap-buffer-overflow",
                                           None, "SANITIZER_CRASH")
                    relation = classify_crash_relation(result, candidate, root,
                                                       root / "harness.cc")
                    self.assertEqual(relation.relation, "EXACT")
                    trace = f"Breakpoint 1, parse () at {source}:1\n$1 = 1\n"
                    self.assertEqual(parse_sp_trace(trace, f"{source}:1"), (True, True))
                    self.assertTrue(semantic_sp_duplicate(candidate, point(source.name, "sp-b")))

    def test_unsupported_suffix_does_not_gain_exact_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "parse.txt").write_text("return *ptr;\n")
            self.assertIsNone(_exact_sp_location("parse.txt:1", root))


if __name__ == "__main__":
    unittest.main()
