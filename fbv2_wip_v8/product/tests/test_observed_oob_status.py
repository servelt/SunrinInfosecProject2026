"""Observed OOB reports must not be mislabeled as source provenance failures."""

import json
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.models import PoC, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.scan import _verify_observed_target_crash


class ObservedOOBStatusTest(unittest.TestCase):
    def test_non_target_overflow_is_not_recorded_as_pending_target_cause(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            crash_path = root / "runtime" / "crashes" / "crash-harness.json"
            crash_path.parent.mkdir(parents=True)
            crash_path.write_text("{}")
            point = SuspiciousPoint(
                "sp-original", "worker", "direction", "parse", "parser.c", "parser.c:10",
                "parse input", "possible OOB", [], "UNKNOWN", [], [], [], [],
            )
            poc = PoC("poc", point.sp_id, "", None, None, "")
            result = RuntimeResult(
                1, "", "ERROR: AddressSanitizer: heap-buffer-overflow", 6, False,
                "AddressSanitizer: heap-buffer-overflow", None, "SANITIZER_CRASH",
                crash_triage={"category": "HARNESS_CRASH"},
            )

            _verify_observed_target_crash(root, crash_path, poc, point, result,
                                          root, root / "harness.c", None, None)

            record = json.loads(crash_path.read_text())
            self.assertEqual(record["independent_verification_status"],
                             "BLOCKED_SOURCE_PROVENANCE")
            self.assertNotEqual(record["independent_hypothesis"].get("blocker"),
                                "CAUSAL_EVIDENCE_REQUIRED")

    def test_oob_without_post_runtime_hypothesis_preserves_original_sp_and_source_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            crash_path = root / "runtime" / "crashes" / "crash-oob.json"
            crash_path.parent.mkdir(parents=True)
            crash_path.write_text(json.dumps({
                "source_provenance": {"method": "DWARF_PATH_RELATIVE_PATH_SHA256"},
                "observations": [],
            }))
            point = SuspiciousPoint(
                "sp-original", "worker", "direction", "parse", "cJSON.c", "cJSON.c:1182",
                "parse input", "NUL termination could cause an OOB", [], "UNKNOWN", [], [], [], [],
            )
            poc = PoC("poc", point.sp_id, "", None, None, "")
            result = RuntimeResult(
                -6, "", "ERROR: AddressSanitizer: heap-buffer-overflow", 6, False,
                "AddressSanitizer: heap-buffer-overflow", None, "SANITIZER_CRASH",
                crash_triage={"category": "TARGET_CRASH"},
            )

            _verify_observed_target_crash(root, crash_path, poc, point, result,
                                          root, root / "harness.c", None, None)

            record = json.loads(crash_path.read_text())
            self.assertEqual(record["independent_verification_status"],
                             "TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE")
            self.assertEqual(record["independent_hypothesis"]["blocker"],
                             "CAUSAL_EVIDENCE_REQUIRED")
            self.assertEqual(record["source_provenance"]["method"],
                             "DWARF_PATH_RELATIVE_PATH_SHA256")
            self.assertEqual(point.status, "OPEN")
            self.assertFalse((root / "runtime" / "crash_candidates").exists())


if __name__ == "__main__":
    unittest.main()
