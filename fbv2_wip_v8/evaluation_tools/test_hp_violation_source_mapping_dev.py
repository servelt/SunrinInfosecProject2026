"""Provider-free checks for the public HP refinement source line pin."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "review_tools"), str(HERE),
                "/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src"]

from run_hp_violation_refinement_component import verify_source_mapping  # noqa: E402


class HPViolationSourceMappingTests(unittest.TestCase):
    def test_full_file_starts_at_one(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "target.c"
            source.write_text("#include <stdint.h>\nvoid target(void) {}\n")
            verify_source_mapping(source.read_text(), source, 1)

    def test_full_file_shifted_by_three_is_rejected(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "target.c"
            source.write_text("#include <stdint.h>\nvoid target(void) {}\n")
            with self.assertRaisesRegex(ValueError, "line map differs"):
                verify_source_mapping(source.read_text(), source, 4)

    def test_real_snippet_offset_is_accepted(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "target.c"
            source.write_text("#include <stdint.h>\nvoid target(void) {}\n")
            verify_source_mapping("void target(void) {}\n", source, 2)


if __name__ == "__main__":
    unittest.main()
