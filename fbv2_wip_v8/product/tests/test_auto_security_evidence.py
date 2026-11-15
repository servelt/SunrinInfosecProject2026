"""Automatic Evidence must bind to the product's actual execution identity."""
import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from vulnerabilityanalysis.final_verification import check_security_property
from vulnerabilityanalysis.models import Evidence, PoC, SuspiciousPoint
from vulnerabilityanalysis.scan import _automatic_input_evidence


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AutomaticSecurityEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "src"
        self.source.mkdir()
        (self.source / "target.c").write_text("int target(void) { return 0; }\n")
        self.binary = self.root / "target"
        self.binary.write_bytes(b"binary")
        self.runner = self.root / "runner.py"
        self.runner.write_text("# runner\n")
        self.input = self.root / "input.bin"
        self.input.write_bytes(b"input")
        self.receipt = self.root / "receipt.json"
        self.run = self.root / "run"
        self.run.mkdir()
        self.point = SuspiciousPoint("crash-test", "w", "d", "target", "src/target.c",
                                     "src/target.c:1", "read", "possible UAF", [],
                                     "UNKNOWN", [], [], [], [])
        self.poc = PoC("poc-test", "original-sp", "def build(): return b'input'",
                       str(self.input), None, "crash")
        self.profile = {"runner": str(self.runner), "receipt": str(self.receipt),
                        "run_id": "run-test", "input_sha256": sha(self.input),
                        "binary_sha256": sha(self.binary), "runner_sha256": sha(self.runner)}

    def write_receipt(self, **changes):
        row = {"run_id": "run-test", "input_sha256": sha(self.input),
               "binary_sha256": sha(self.binary), "runner_sha256": sha(self.runner),
               "bytes_sent": self.input.stat().st_size, "send_success": True,
               "target_pid": 123, "destination": "127.0.0.1:12345"}
        row.update(changes)
        self.receipt.write_text(json.dumps(row))

    def test_exact_receipt_binds_to_run_input_binary_runner_source_and_candidate(self):
        self.write_receipt()
        evidence, binding = _automatic_input_evidence(
            self.run, self.point.sp_id, self.poc, self.point, self.root,
            self.binary, self.profile)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(binding["source_sha256"], sha(self.source / "target.c"))
        self.assertEqual(binding["candidate_id"], self.point.sp_id)
        self.point.external_input_relation = "verified external receipt"
        impact = Evidence("impact", "SECURITY_IMPACT", "runtime", self.point.sp_id,
                          "oracle", str(self.receipt), True, False)
        self.assertEqual(check_security_property(self.point, evidence + [impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        harness = Evidence("harness", "HARNESS_VALIDITY", "AUTOMATIC_RUNTIME",
                           self.point.sp_id, "qualified fixture", evidence[0].artifact_path,
                           True, False)
        self.assertEqual(check_security_property(self.point, evidence + [harness, impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        renamed = Evidence(**{**asdict(harness), "source": "AUTOMATIC_HARNESS_QUALIFICATION"})
        self.assertEqual(check_security_property(self.point, evidence + [renamed, impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        manual_name = Evidence(**{**asdict(harness), "source": "EVALUATOR"})
        self.assertEqual(check_security_property(self.point, evidence + [manual_name, impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        separate = self.root / "untrusted_qualification.json"
        separate.write_text(json.dumps({"kind": "HARNESS_QUALIFICATION",
                                        "qualified": True, "binding": binding}))
        untrusted = Evidence(**{**asdict(renamed), "artifact_path": str(separate)})
        self.assertEqual(check_security_property(self.point, evidence + [untrusted, impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        manual_artifact = self.root / "independent_manual_qualification.json"
        manual_artifact.write_text(json.dumps({"kind": "EVALUATOR_ATTACHED_HARNESS_VALIDITY"}))
        manual_harness = Evidence(**{**asdict(manual_name), "artifact_path": str(manual_artifact)})
        self.assertEqual(check_security_property(self.point, evidence + [manual_harness, impact],
                                                  trusted_binding=binding).status, "CONFIRMED")
        spoofed_impact = Evidence(**{**asdict(harness), "type": "SECURITY_IMPACT"})
        self.assertEqual(check_security_property(self.point, evidence + [spoofed_impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        for field in ("input_sha256", "binary_sha256", "runner_sha256",
                      "source_sha256", "run_id", "candidate_id"):
            wrong = {**binding, field: "wrong"}
            self.assertEqual(check_security_property(self.point, evidence + [harness, impact],
                                                     trusted_binding=wrong).status, "UNKNOWN", field)
        self.assertEqual(check_security_property(self.point, evidence + [harness, impact]).status,
                         "UNKNOWN")
        payload = json.loads(Path(evidence[0].artifact_path).read_text())
        Path(evidence[0].artifact_path).write_text(json.dumps({**payload, "kind": "HARNESS_QUALIFICATION"}))
        self.assertEqual(check_security_property(self.point, evidence + [impact],
                                                  trusted_binding=binding).status, "UNKNOWN")
        wrong_candidate = Evidence(**{**asdict(evidence[0]), "related_candidate": "other"})
        self.assertEqual(check_security_property(self.point, [wrong_candidate, harness, impact],
                                                 trusted_binding=binding).status, "UNKNOWN")

    def test_runner_receipt_mismatch_or_failed_send_is_rejected(self):
        for change in ({"input_sha256": "0" * 64}, {"binary_sha256": "0" * 64},
                       {"runner_sha256": "0" * 64}, {"run_id": "other"},
                       {"send_success": False}, {"bytes_sent": 0},
                       {"target_pid": None}):
            with self.subTest(change=change):
                self.write_receipt(**change)
                evidence, binding = _automatic_input_evidence(
                    self.run, self.point.sp_id, self.poc, self.point, self.root,
                    self.binary, self.profile)
                self.assertEqual((evidence, binding), ([], None))

    def test_post_execution_input_binary_or_runner_change_is_rejected(self):
        for path in (self.input, self.binary, self.runner):
            with self.subTest(path=path.name):
                self.write_receipt()
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                try:
                    evidence, binding = _automatic_input_evidence(
                        self.run, self.point.sp_id, self.poc, self.point, self.root,
                        self.binary, self.profile)
                    self.assertEqual((evidence, binding), ([], None))
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
