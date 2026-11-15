"""Direct callback measurements remain separate from trusted Harness validity."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.direct_input import CallbackProbe
from vulnerabilityanalysis.final_verification import check_security_property
from vulnerabilityanalysis.models import PoC, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.scan import _automatic_direct_input_evidence, execute_poc


class DirectInputReceiptTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "fuzzer"
        self.binary.write_bytes(b"fixed binary")
        self.input = self.root / "pov.bin"
        self.input.write_bytes(b"exact PoV")
        (self.root / "run.json").write_text(json.dumps({"run_id": "run-1"}))
        self.point = SuspiciousPoint(
            "sp-1", "worker", "direction", "target", "target.c", "target.c:1",
            "write", "hypothesis", [], "file input", [], [], [], [])
        self.poc = PoC("pov-1", "sp-1", "generator", str(self.input), None, "crash")
        self.runtime = RuntimeResult(
            1, "", "AddressSanitizer", None, False,
            "AddressSanitizer: heap-buffer-overflow", "#0 target", "CRASH")
        self.runtime.crash_triage = {"category": "TARGET_CRASH"}

    def test_exact_callback_produces_a_scoped_measurement_not_gate_evidence(self):
        digest = hashlib.sha256(self.input.read_bytes()).hexdigest()
        with patch("vulnerabilityanalysis.scan.probe_libfuzzer_callback",
                   return_value=CallbackProbe(True, self.input.stat().st_size,
                                              digest, "exact callback bytes measured")):
            evidence = _automatic_direct_input_evidence(
                self.root, self.poc, self.point, self.binary, self.runtime)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].type, "INPUT_CONSUMPTION")
        self.assertFalse(evidence[0].supports)
        receipt = json.loads(Path(evidence[0].artifact_path).read_text())
        self.assertEqual(receipt["run_id"], "run-1")
        self.assertEqual(receipt["candidate_id"], "sp-1")
        self.assertEqual(receipt["pov_id"], "pov-1")
        self.assertEqual(receipt["callback_sha256"], digest)
        self.assertEqual(receipt["binary_sha256"],
                         hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_measurement_failure_or_wrong_bytes_is_recorded_as_unknown(self):
        for probe in (CallbackProbe(False, None, None, "ptrace denied"),
                      CallbackProbe(True, self.input.stat().st_size, "0" * 64,
                                    "wrong bytes")):
            with self.subTest(probe=probe), patch(
                    "vulnerabilityanalysis.scan.probe_libfuzzer_callback",
                    return_value=probe):
                evidence = _automatic_direct_input_evidence(
                    self.root, self.poc, self.point, self.binary, self.runtime)
                self.assertEqual(len(evidence), 1)
                self.assertFalse(evidence[0].supports)
                receipt = json.loads(Path(evidence[0].artifact_path).read_text())
                self.assertEqual(receipt["status"], "UNKNOWN")

    def test_execute_poc_invokes_direct_measurement_only_for_exact_binary(self):
        clean = RuntimeResult(0, "", "", None, False, None, None, "COMPLETED")
        with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run", return_value=clean), \
             patch("vulnerabilityanalysis.scan._automatic_direct_input_evidence",
                   return_value=[]) as issue:
            execute_poc(self.poc, self.point, [str(self.binary), "{input}"],
                        self.root, auto_input_receipt=True, target_binary=self.binary)
            issue.assert_called_once()

    def test_callback_receipt_alone_cannot_confirm_security_property(self):
        digest = hashlib.sha256(self.input.read_bytes()).hexdigest()
        with patch("vulnerabilityanalysis.scan.probe_libfuzzer_callback",
                   return_value=CallbackProbe(True, self.input.stat().st_size,
                                              digest, "exact callback bytes measured")):
            evidence = _automatic_direct_input_evidence(
                self.root, self.poc, self.point, self.binary, self.runtime)
        security = check_security_property(self.point, evidence)
        self.assertEqual(security.status, "UNKNOWN")
        self.assertEqual(security.external_input_evidence, [])
        self.assertEqual(security.harness_validity_evidence, [])

    def test_malformed_run_record_never_issues_a_receipt(self):
        (self.root / "run.json").write_text("[")
        self.assertEqual(_automatic_direct_input_evidence(
            self.root, self.poc, self.point, self.binary, self.runtime), [])


if __name__ == "__main__":
    unittest.main()
