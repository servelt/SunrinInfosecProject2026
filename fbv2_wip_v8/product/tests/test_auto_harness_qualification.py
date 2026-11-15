"""Automatic Reference qualification is bound to a product execution."""
import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.final_verification import check_security_property
from vulnerabilityanalysis.models import Evidence, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.scan import _automatic_reference_harness_evidence


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AutomaticHarnessQualificationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.point = SuspiciousPoint(
            "crash-1", "w", "d", "target", "src/target.c", "src/target.c:1",
            "read", "observed UAF", [], "UNKNOWN", [], [], [], [])
        self.point.external_input_relation = "product-observed TCP input"
        self.binding = {
            "candidate_id": "crash-1", "run_id": "pov-run",
            "input_sha256": "1" * 64, "binary_sha256": "2" * 64,
            "runner_sha256": "3" * 64, "source_sha256": "4" * 64,
        }
        self.delivery = self.root / "delivery.json"
        self.delivery.write_text("{}")
        self.impact = self.root / "impact.json"
        self.impact.write_text("{}")
        self.evidence = [
            Evidence("input", "EXTERNAL_INPUT", "TEST", "crash-1", "sent",
                     str(self.delivery), True, False),
            Evidence("impact", "SECURITY_IMPACT", "TEST", "crash-1", "UAF",
                     str(self.impact), True, False),
        ]
        target_runtime = self.root / "target.runtime.json"
        target_runtime.write_text(json.dumps({
            "sanitizer": "AddressSanitizer: heap-use-after-free",
            "crash_triage": {"category": "TARGET_CRASH"},
            "stack_trace": "#0 in target /src/target.c:1",
        }))
        checks = {}
        for label in ("normal", "malformed"):
            runtime = self.root / f"{label}.runtime.json"
            receipt = self.root / f"{label}.receipt.json"
            runtime.write_text(json.dumps({
                "exit_code": 0, "timed_out": False, "sanitizer": None,
                "stdout": ("HTTP/1.1 200 OK\n\nOK" if label == "normal" else
                           "HTTP/1.0 400 Bad Request\n"),
            }))
            receipt.write_text(json.dumps({
                "run_id": f"pov-run:qualification:{label}:crash-1",
                "input_sha256": ("5" if label == "normal" else "6") * 64,
                "binary_sha256": self.binding["binary_sha256"],
                "runner_sha256": self.binding["runner_sha256"],
                "send_success": True, "target_pid": 123,
                "destination": "127.0.0.1:12345", "bytes_sent": 10,
                "origin_state": {"accepted": True, "response_sent": True,
                                 "request_bytes": 10},
                "response_bytes": 20,
            }))
            checks[label] = {
                "run_id": f"pov-run:qualification:{label}:crash-1",
                "input_sha256": ("5" if label == "normal" else "6") * 64,
                "runtime_path": str(runtime), "runtime_sha256": digest(runtime),
                "receipt_path": str(receipt), "receipt_sha256": digest(receipt),
            }
        self.payload = {
            "kind": "HARNESS_QUALIFICATION", "issuer": "PRODUCT_RUNTIME",
            "qualified": True, "binding": self.binding,
            "target_function_reached": True,
            "target_runtime_path": str(target_runtime),
            "target_runtime_sha256": digest(target_runtime),
            "normal_run_id": checks["normal"]["run_id"],
            "malformed_run_id": checks["malformed"]["run_id"],
            "checks": checks,
        }
        self.artifact = self.root / "qualification.json"
        self._write_payload()
        self.proof = Evidence(
            "harness", "HARNESS_VALIDITY", "AUTOMATIC_HARNESS_QUALIFICATION",
            "crash-1", "product checks", str(self.artifact), True, False)

    def _write_payload(self):
        self.artifact.write_text(json.dumps(self.payload, sort_keys=True))
        return {"artifact_path": str(self.artifact),
                "artifact_sha256": digest(self.artifact)}

    def _status(self, proof=None, trusted=None, binding=None):
        return check_security_property(
            self.point, self.evidence + [proof or self.proof],
            trusted_binding=binding or self.binding,
            trusted_qualification=trusted).status

    def test_product_issued_proof_confirms_only_exact_binding(self):
        trusted = self._write_payload()
        self.assertEqual(self._status(trusted=trusted), "CONFIRMED")
        for field in ("runner_sha256", "binary_sha256", "source_sha256",
                      "input_sha256", "run_id", "candidate_id"):
            with self.subTest(field=field):
                original = self.payload["binding"]
                self.payload["binding"] = {**original, field: "mismatch"}
                changed = self._write_payload()
                self.assertEqual(self._status(trusted=changed), "UNKNOWN")
                self.payload["binding"] = original
        self._write_payload()

    def test_tampered_artifact_or_reused_receipt_is_rejected(self):
        trusted = self._write_payload()
        self.payload["qualified"] = False
        self._write_payload()
        self.assertEqual(self._status(trusted=trusted), "UNKNOWN")
        self.payload["qualified"] = True
        self.payload["checks"]["normal"]["receipt_path"] = str(self.delivery)
        self.payload["checks"]["normal"]["receipt_sha256"] = digest(self.delivery)
        changed = self._write_payload()
        self.assertEqual(self._status(trusted=changed), "UNKNOWN")
        self.payload["checks"]["normal"]["receipt_path"] = str(self.root / "normal.receipt.json")
        receipt = Path(self.payload["checks"]["normal"]["receipt_path"])
        receipt.write_text("[]")
        self.payload["checks"]["normal"]["receipt_sha256"] = digest(receipt)
        self.assertEqual(self._status(trusted=self._write_payload()), "UNKNOWN")

    def test_missing_reachability_or_bad_normal_run_is_rejected(self):
        self.payload["target_function_reached"] = False
        self.assertEqual(self._status(trusted=self._write_payload()), "UNKNOWN")
        self.payload["target_function_reached"] = True
        self.payload["normal_run_id"] = "other"
        self.assertEqual(self._status(trusted=self._write_payload()), "UNKNOWN")
        self.payload["normal_run_id"] = self.payload["checks"]["normal"]["run_id"]
        target = Path(self.payload["target_runtime_path"])
        target.write_text(json.dumps({"sanitizer": "AddressSanitizer: UAF",
                                      "crash_triage": {"category": "TARGET_CRASH"},
                                      "stack_trace": "#0 in unrelated /src/other.c:1"}))
        self.payload["target_runtime_sha256"] = digest(target)
        self.assertEqual(self._status(trusted=self._write_payload()), "UNKNOWN")

    def test_receipt_renaming_wrong_candidate_and_missing_runtime_are_rejected(self):
        trusted = self._write_payload()
        receipt_proof = Evidence(**{**asdict(self.proof),
                                   "artifact_path": str(self.delivery)})
        self.assertEqual(self._status(proof=receipt_proof, trusted=trusted), "UNKNOWN")
        other = Evidence(**{**asdict(self.proof), "related_candidate": "crash-2"})
        self.assertEqual(self._status(proof=other, trusted=trusted), "UNKNOWN")
        Path(self.payload["checks"]["malformed"]["runtime_path"]).unlink()
        self.assertEqual(self._status(trusted=trusted), "UNKNOWN")

    def test_failed_normal_http_check_never_issues_qualification(self):
        source_root = self.root / "source"
        source = source_root / "src/target.c"
        source.parent.mkdir(parents=True)
        source.write_text("int target(void) { return 0; }\n")
        binary = self.root / "target"
        binary.write_bytes(b"target binary")
        runner = self.root / "runner.py"
        runner.write_text("# reference runner\n")
        archive = self.root / "source.tar.gz"
        archive.write_bytes(b"source archive")
        normal, malformed = self.root / "normal", self.root / "malformed"
        normal.write_bytes(b"normal")
        malformed.write_bytes(b"bad")
        run = self.root / "run"
        run.mkdir()
        request = {
            "kind": "REFERENCE_HTTP_PROCESS_V1", "source_archive": str(archive),
            "source_archive_sha512": hashlib.sha512(archive.read_bytes()).hexdigest(),
            "source_file": "src/target.c", "source_sha256": digest(source),
            "binary": str(binary), "binary_sha256": digest(binary),
            "runner": str(runner), "runner_sha256": digest(runner),
            "normal_input": str(normal), "malformed_input": str(malformed),
        }
        request_path = run / "harness_qualification_request.json"
        request_path.write_text(json.dumps(request))
        (run / "run.json").write_text(json.dumps({
            "run_id": "pov-run", "harness_qualification_request_sha256": digest(request_path),
        }))
        target_runtime = run / "target.runtime.json"
        target_runtime.write_text("{}")
        binding = {**self.binding, "binary_sha256": digest(binary),
                   "runner_sha256": digest(runner), "source_sha256": digest(source)}
        result = RuntimeResult(1, "", "", None, False, "AddressSanitizer: UAF",
                               "#0 in target /src/target.c:1", "TARGET_CRASH",
                               crash_triage={"category": "TARGET_CRASH"})
        failed_check = RuntimeResult(0, "DEBUG only\n", "", None, False, None,
                                     None, "UNKNOWN")
        command = ["/usr/bin/python3", str(runner), str(binary), "{input}"]
        with patch("vulnerabilityanalysis.scan.RuntimeExecutor") as executor:
            executor.return_value.run.return_value = failed_check
            proof, trusted = _automatic_reference_harness_evidence(
                run, self.point, result, target_runtime, command,
                source_root, binary, binding)
        self.assertEqual((proof, trusted), ([], None))
        self.assertTrue((run / "security/qualification/crash-1/normal.runtime.json").is_file())
        self.assertFalse((run / "security/crash-1.harness_qualification.json").exists())


if __name__ == "__main__":
    unittest.main()
