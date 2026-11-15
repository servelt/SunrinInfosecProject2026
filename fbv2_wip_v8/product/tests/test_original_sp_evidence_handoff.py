"""Original SP replay must submit product-bound automatic proofs to the existing gate."""

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.models import (
    Evidence, IndependentValidation, PoC, RootCauseResult, RuntimeResult,
    SecurityPropertyResult, SuspiciousPoint,
)
from vulnerabilityanalysis.scan import execute_poc


class OriginalSPEvidenceHandoffTest(unittest.TestCase):
    def test_product_bound_receipt_and_qualification_reach_real_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text("int target(void) { return 0; }\n")
            binary = root / "target"
            binary.write_bytes(b"binary fixture")
            runner = root / "runner.py"
            runner.write_text("# runner fixture\n")
            seed = root / "seed.bin"
            seed.write_bytes(b"input")
            run = root / "run"
            run.mkdir()
            (run / "run.json").write_text(json.dumps({"run_id": "run-1"}))
            point = SuspiciousPoint(
                "sp-1", "worker", "direction", "target", "target.c", "target.c:1",
                "read", "use-after-free at target", [], "external bytes reach target",
                [], [], [], [],
            )
            command = [sys.executable, str(runner), str(binary), "{input}"]
            poc = PoC("poc-1", point.sp_id, "def build(): return b'input'\n",
                      str(seed), command, "test")
            runtime = RuntimeResult(
                1, "", "ERROR: AddressSanitizer: heap-use-after-free\n"
                "#0 0x1 in target /fixture/target.c:1:1\n",
                None, False, "AddressSanitizer: heap-use-after-free",
                "#0 0x1 in target /fixture/target.c:1:1", "SANITIZER_CRASH",
            )
            triage = {"category": "TARGET_CRASH", "sp_linked": True,
                      "top_source_frame": "/fixture/target.c"}
            root_result = RootCauseResult(
                point.sp_id, "crash-fixture", "EXACT", "target", "target.c:1",
                runtime.sanitizer, [], [], [], point.external_input_relation, "",
                ["source-backed fixture"], [], [], "CONFIRMED",
            )
            replay = IndependentValidation(
                poc.poc_id, point.sp_id, "REPRODUCED", runtime.sanitizer,
                "target:/fixture/target.c:1", None, "same oracle",
            )

            def digest(path):
                return hashlib.sha256(Path(path).read_bytes()).hexdigest()

            def runtime_with_receipt(command_arg, input_arg, *, extra_env=None):
                self.assertEqual(command_arg, command)
                self.assertEqual(input_arg, seed)
                self.assertIsNotNone(extra_env)
                receipt = Path(extra_env["VA_RUNTIME_RECEIPT"])
                receipt.parent.mkdir(parents=True, exist_ok=True)
                receipt.write_text(json.dumps({
                    "run_id": extra_env["VA_RUN_ID"],
                    "input_sha256": digest(seed),
                    "binary_sha256": digest(binary),
                    "runner_sha256": digest(runner),
                    "bytes_sent": seed.stat().st_size,
                    "send_success": True,
                    "target_pid": 123,
                    "destination": "127.0.0.1:12345",
                }))
                return runtime

            def product_qualification(run_dir, candidate, result, target_runtime,
                                      run_command, source_root, target_binary, binding):
                self.assertEqual(candidate.sp_id, point.sp_id)
                self.assertEqual(run_command, command)
                self.assertEqual(source_root, root)
                self.assertEqual(target_binary, binary)
                self.assertEqual(binding["input_sha256"], digest(seed))
                self.assertEqual(binding["source_sha256"], digest(source))
                checks = {}
                for label in ("normal", "malformed"):
                    check_run_id = f"run-1:qualification:{label}:{point.sp_id}"
                    output = ("HTTP/1.1 200 OK\n\nOK" if label == "normal" else
                              "HTTP/1.0 400 Bad Request\n")
                    control_runtime = run / f"{label}.runtime.json"
                    control_runtime.write_text(json.dumps({
                        "exit_code": 0, "timed_out": False, "sanitizer": None,
                        "stdout": output,
                    }))
                    control_receipt = run / f"{label}.receipt.json"
                    control_receipt.write_text(json.dumps({
                        "run_id": check_run_id,
                        "input_sha256": label,
                        "binary_sha256": binding["binary_sha256"],
                        "runner_sha256": binding["runner_sha256"],
                        "send_success": True,
                        "target_pid": 123,
                        "destination": "127.0.0.1:12345",
                        "bytes_sent": 5,
                        "origin_state": {"accepted": True, "response_sent": True,
                                         "request_bytes": 5},
                        "response_bytes": 5,
                    }))
                    checks[label] = {
                        "run_id": check_run_id,
                        "input_sha256": label,
                        "runtime_path": str(control_runtime),
                        "runtime_sha256": digest(control_runtime),
                        "receipt_path": str(control_receipt),
                        "receipt_sha256": digest(control_receipt),
                    }
                artifact = run / "qualification.json"
                artifact.write_text(json.dumps({
                    "kind": "HARNESS_QUALIFICATION",
                    "issuer": "PRODUCT_RUNTIME",
                    "qualified": True,
                    "binding": binding,
                    "target_function_reached": True,
                    "target_runtime_path": str(target_runtime),
                    "target_runtime_sha256": digest(target_runtime),
                    "normal_run_id": checks["normal"]["run_id"],
                    "malformed_run_id": checks["malformed"]["run_id"],
                    "checks": checks,
                }))
                proof = Evidence(
                    "harness-proof", "HARNESS_VALIDITY",
                    "AUTOMATIC_HARNESS_QUALIFICATION", point.sp_id,
                    "product-bound controls", str(artifact), True, False,
                )
                return [proof], {"artifact_path": str(artifact),
                                 "artifact_sha256": digest(artifact)}

            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run",
                       side_effect=runtime_with_receipt), \
                 patch("vulnerabilityanalysis.scan.triage_crash", return_value=triage), \
                 patch("vulnerabilityanalysis.scan.verify_root_cause", return_value=root_result), \
                 patch("vulnerabilityanalysis.scan.independent_replay", return_value=replay), \
                 patch("vulnerabilityanalysis.scan._verify_observed_target_crash"), \
                 patch("vulnerabilityanalysis.scan._automatic_reference_harness_evidence",
                       side_effect=product_qualification), \
                 patch("vulnerabilityanalysis.scan.promote_verified"):
                evidence = execute_poc(
                    poc, point, command, run, target_repository=root,
                    harness_path=runner, target_binary=binary, auto_input_receipt=True,
                )

            security = json.loads((run / "security" / f"{point.sp_id}.json").read_text())
            self.assertEqual(security["status"], "CONFIRMED")
            self.assertEqual(len(security["external_input_evidence"]), 1)
            self.assertEqual(security["harness_validity_evidence"], ["harness-proof"])
            self.assertEqual(len(security["impact_evidence"]), 1)
            self.assertTrue(any(item.type == "EXTERNAL_INPUT" for item in evidence))
            self.assertTrue(any(item.type == "HARNESS_VALIDITY" for item in evidence))

    def test_confirmed_original_sp_passes_existing_automatic_proofs_to_security_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text("int target(void) { return 0; }\n")
            binary = root / "target"
            binary.write_bytes(b"binary fixture")
            runner = root / "runner.py"
            runner.write_text("# runner fixture\n")
            seed = root / "seed.bin"
            seed.write_bytes(b"input")
            run = root / "run"
            run.mkdir()
            (run / "run.json").write_text(json.dumps({"run_id": "run-1"}))
            point = SuspiciousPoint(
                "sp-1", "worker", "direction", "target", "target.c", "target.c:1",
                "read", "use-after-free at target", [], "external bytes reach target",
                [], [], [], [],
            )
            command = [sys.executable, str(runner), str(binary), "{input}"]
            poc = PoC("poc-1", point.sp_id, "def build(): return b'input'\n",
                      str(seed), command, "test")
            runtime = RuntimeResult(
                1, "", "ERROR: AddressSanitizer: heap-use-after-free\n"
                "#0 0x1 in target /fixture/target.c:1:1\n",
                None, False, "AddressSanitizer: heap-use-after-free",
                "#0 0x1 in target /fixture/target.c:1:1", "SANITIZER_CRASH",
            )
            triage = {"category": "TARGET_CRASH", "sp_linked": True,
                      "top_source_frame": "/fixture/target.c"}
            root_result = RootCauseResult(
                point.sp_id, "crash-fixture", "EXACT", "target", "target.c:1",
                runtime.sanitizer, [], [], [], point.external_input_relation, "",
                ["source-backed fixture"], [], [], "CONFIRMED",
            )
            replay = IndependentValidation(
                poc.poc_id, point.sp_id, "REPRODUCED", runtime.sanitizer,
                "target:/fixture/target.c:1", None, "same oracle",
            )
            input_artifact = root / "delivery.json"
            input_artifact.write_text('{"kind":"EXTERNAL_INPUT_DELIVERY"}')
            harness_artifact = root / "qualification.json"
            harness_artifact.write_text('{"kind":"HARNESS_QUALIFICATION"}')
            external = Evidence("input-proof", "EXTERNAL_INPUT", "AUTOMATIC_RUNTIME",
                                point.sp_id, "bound receipt", str(input_artifact), True, False)
            harness = Evidence("harness-proof", "HARNESS_VALIDITY",
                               "AUTOMATIC_HARNESS_QUALIFICATION", point.sp_id,
                               "bound qualification", str(harness_artifact), True, False)
            binding = {"candidate_id": point.sp_id, "run_id": "run-1"}
            qualification = {"artifact_path": str(harness_artifact)}

            def input_proof(*args):
                self.assertEqual(args[1], point.sp_id)
                self.assertIsNotNone(args[-1])
                self.assertEqual(args[-1]["run_id"], "run-1")
                return [external], binding

            def harness_proof(*args):
                self.assertEqual(args[1].sp_id, point.sp_id)
                self.assertEqual(args[-1], binding)
                return [harness], qualification

            def existing_gate(candidate, evidence, **trusted):
                kinds = {item.type for item in evidence
                         if item.related_candidate == candidate.sp_id and item.supports}
                valid = (trusted.get("trusted_binding") == binding and
                         trusted.get("trusted_qualification") == qualification and
                         {"EXTERNAL_INPUT", "HARNESS_VALIDITY", "SECURITY_IMPACT"} <= kinds)
                return SecurityPropertyResult(
                    candidate.sp_id, "CONFIRMED" if valid else "UNKNOWN",
                    [external.evidence_id] if valid else [],
                    [harness.evidence_id] if valid else [],
                    ["impact"] if valid else [],
                    [] if valid else ["automatic evidence not bound to original SP"],
                )

            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run", return_value=runtime), \
                 patch("vulnerabilityanalysis.scan.triage_crash", return_value=triage), \
                 patch("vulnerabilityanalysis.scan.verify_root_cause", return_value=root_result), \
                 patch("vulnerabilityanalysis.scan.independent_replay", return_value=replay), \
                 patch("vulnerabilityanalysis.scan._verify_observed_target_crash"), \
                 patch("vulnerabilityanalysis.scan._automatic_input_evidence",
                       side_effect=input_proof) as automatic_input, \
                 patch("vulnerabilityanalysis.scan._automatic_reference_harness_evidence",
                       side_effect=harness_proof) as automatic_harness, \
                 patch("vulnerabilityanalysis.scan.check_security_property",
                       side_effect=existing_gate), \
                 patch("vulnerabilityanalysis.scan.promote_verified"):
                execute_poc(
                    poc, point, command, run, target_repository=root,
                    harness_path=runner, target_binary=binary, auto_input_receipt=True,
                )

            automatic_input.assert_called_once()
            automatic_harness.assert_called_once()
            security = json.loads((run / "security" / f"{point.sp_id}.json").read_text())
            self.assertEqual(security["status"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
