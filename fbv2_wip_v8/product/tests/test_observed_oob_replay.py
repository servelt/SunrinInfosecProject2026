"""Observed OOB replay confirms only a symptom, never a causal Gate finding."""

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_official_v2_contract import Fixture
from vulnerabilityanalysis.final_verification import replay_observed_oob_without_cause
from vulnerabilityanalysis.models import PoC, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop
from vulnerabilityanalysis.scan import _verify_observed_target_crash


def _runtime(source: Path, oracle: str = "heap-buffer-overflow") -> RuntimeResult:
    stderr = (f"ERROR: AddressSanitizer: {oracle} on address 0x1234\n"
              f"    #0 0x1234 in target {source}:1\n")
    return RuntimeResult(1, "", stderr, 6, False,
                         f"AddressSanitizer: {oracle} on address 0x1234",
                         None, "SANITIZER_CRASH",
                         crash_triage={"category": "TARGET_CRASH"})


class ObservedOOBReplayTest(unittest.TestCase):
    def test_matching_observation_never_creates_causal_or_gate_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            source = q.source_root / "target.c"
            primary = _runtime(source)
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()
            envelope = SimpleNamespace(deadline_monotonic=time.monotonic() + 30)
            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run',
                       return_value=_runtime(source)) as run, patch(
                       'vulnerabilityanalysis.final_verification.triage_crash',
                       return_value={"category": "TARGET_CRASH"}):
                receipt = replay_observed_oob_without_cause(
                    primary, retained, expected, [str(q.binary), "{input}"], q,
                    root / "observation", process_envelope=envelope)
            self.assertEqual(receipt["status"], "REPRODUCED_OBSERVATION_ONLY")
            self.assertFalse(receipt["gate_evaluated"])
            self.assertFalse(receipt["causal_evidence_issued"])
            self.assertIs(run.call_args.kwargs["process_envelope"], envelope)
            self.assertEqual(run.call_args.kwargs["process_segment"],
                             "pov.observed_oob_replay")
            self.assertEqual(run.call_args.args[1].read_bytes(), retained.read_bytes())
            self.assertFalse((root / "observation" / "fixed.json").exists())

    def test_changed_harness_and_changed_input_block_transport(self):
        for changed in ("harness", "input"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                q = Fixture(root / "authority").issue()
                primary = _runtime(q.source_root / "target.c")
                retained = root / "retained.bin"
                retained.write_bytes(b"controlled-input")
                expected = hashlib.sha256(retained.read_bytes()).hexdigest()
                if changed == "harness":
                    q.harness.write_text(q.harness.read_text() + "\n// drift\n")
                else:
                    retained.write_bytes(b"changed-input")
                with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run') as run:
                    receipt = replay_observed_oob_without_cause(
                        primary, retained, expected, [str(q.binary), "{input}"], q,
                        root / "observation", process_envelope=SimpleNamespace(
                            deadline_monotonic=time.monotonic() + 30))
                self.assertEqual(receipt["status"], "NOT_ADMITTED")
                run.assert_not_called()

    def test_changed_replay_oracle_cannot_confirm_observation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            source = q.source_root / "target.c"
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()
            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run',
                       return_value=_runtime(source, "stack-buffer-overflow")), patch(
                       'vulnerabilityanalysis.final_verification.triage_crash',
                       return_value={"category": "TARGET_CRASH"}):
                receipt = replay_observed_oob_without_cause(
                    _runtime(source), retained, expected,
                    [str(q.binary), "{input}"], q, root / "observation",
                    process_envelope=SimpleNamespace(
                        deadline_monotonic=time.monotonic() + 30))
            self.assertEqual(receipt["status"], "INCONSISTENT_OBSERVATION")
            self.assertFalse(receipt["gate_evaluated"])

    def test_source_change_during_replay_invalidates_observation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            source = q.source_root / "target.c"
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()

            def fake_run(*_args, **_kwargs):
                source.write_text(source.read_text() + "\n// changed during replay\n")
                return _runtime(source)

            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run',
                       side_effect=fake_run):
                receipt = replay_observed_oob_without_cause(
                    _runtime(source), retained, expected,
                    [str(q.binary), "{input}"], q, root / "observation",
                    process_envelope=SimpleNamespace(
                        deadline_monotonic=time.monotonic() + 30))
            self.assertEqual(receipt["status"], "AUTHORITY_OR_INPUT_CHANGED")
            self.assertFalse(receipt["gate_evaluated"])

    def test_process_stop_preserves_original_error_and_prevents_resend(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()
            output = root / "observation"
            stopped = ProcessEnvelopeStop("PENDING_PHYSICAL_BUDGET", "no lease")
            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run',
                       side_effect=stopped) as run:
                with self.assertRaises(ProcessEnvelopeStop) as raised:
                    replay_observed_oob_without_cause(
                        _runtime(q.source_root / "target.c"), retained, expected,
                        [str(q.binary), "{input}"], q, output,
                        process_envelope=SimpleNamespace(
                            deadline_monotonic=time.monotonic() + 30))
                self.assertIs(raised.exception, stopped)
                with self.assertRaisesRegex(ValueError, "already exists"):
                    replay_observed_oob_without_cause(
                        _runtime(q.source_root / "target.c"), retained, expected,
                        [str(q.binary), "{input}"], q, output,
                        process_envelope=SimpleNamespace(
                            deadline_monotonic=time.monotonic() + 30))
            self.assertEqual(run.call_count, 1)
            receipt = json.loads((output / "observation_replay.json").read_text())
            self.assertEqual(receipt["status"], "INCOMPLETE_REPLAY_EXCEPTION")
            self.assertEqual(receipt["error_type"], "ProcessEnvelopeStop")
            self.assertEqual(receipt["process_stop_status"], "PENDING_PHYSICAL_BUDGET")
            self.assertFalse(receipt["gate_evaluated"])

    def test_triage_error_keeps_runtime_and_failure_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            source = q.source_root / "target.c"
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()
            output = root / "observation"
            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run',
                       return_value=_runtime(source)), patch(
                       'vulnerabilityanalysis.final_verification.triage_crash',
                       side_effect=RuntimeError("source inspection failed")):
                with self.assertRaisesRegex(RuntimeError, "source inspection failed"):
                    replay_observed_oob_without_cause(
                        _runtime(source), retained, expected,
                        [str(q.binary), "{input}"], q, output,
                        process_envelope=SimpleNamespace(
                            deadline_monotonic=time.monotonic() + 30))
            receipt = json.loads((output / "observation_replay.json").read_text())
            self.assertEqual(receipt["status"], "INCOMPLETE_REPLAY_EXCEPTION")
            self.assertEqual(receipt["error_type"], "RuntimeError")
            self.assertTrue(Path(receipt["runtime_artifact"]).is_file())

    def test_triage_source_drift_prevents_positive_observation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            source = q.source_root / "target.c"
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()

            def drifting_triage(*_args, **_kwargs):
                source.write_text(source.read_text() + "\n// changed in triage\n")
                return {"category": "TARGET_CRASH"}

            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run',
                       return_value=_runtime(source)), patch(
                       'vulnerabilityanalysis.final_verification.triage_crash',
                       side_effect=drifting_triage):
                receipt = replay_observed_oob_without_cause(
                    _runtime(source), retained, expected,
                    [str(q.binary), "{input}"], q, root / "observation",
                    process_envelope=SimpleNamespace(
                        deadline_monotonic=time.monotonic() + 30))
            self.assertEqual(receipt["status"], "AUTHORITY_OR_INPUT_CHANGED")

    def test_deadline_shortfall_blocks_replay_before_transport(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            expected = hashlib.sha256(retained.read_bytes()).hexdigest()
            with patch('vulnerabilityanalysis.final_verification.RuntimeExecutor.run') as run:
                receipt = replay_observed_oob_without_cause(
                    _runtime(q.source_root / "target.c"), retained, expected,
                    [str(q.binary), "{input}"], q, root / "observation",
                    process_envelope=SimpleNamespace(
                        deadline_monotonic=time.monotonic() + 30),
                    observation_deadline_monotonic=time.monotonic() + 1)
            self.assertEqual(receipt["status"], "PENDING_PROCESS_DEADLINE")
            run.assert_not_called()

    def test_scan_keeps_observation_pending_even_when_replay_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            q = Fixture(root / "authority").issue()
            retained = root / "retained.bin"
            retained.write_bytes(b"controlled-input")
            crash_path = root / "runtime" / "crashes" / "crash-oob.json"
            crash_path.parent.mkdir(parents=True)
            poc = PoC("poc-1", "sp-original", "", str(retained),
                      [str(q.binary), "{input}"], "")
            crash_path.write_text(json.dumps({"observations": [{
                "poc_id": poc.poc_id,
                "runtime_artifact": str(root / "runtime" / "poc-1.json"),
                "input_sha256": hashlib.sha256(retained.read_bytes()).hexdigest(),
            }]}))
            point = SuspiciousPoint(
                "sp-original", "worker", "direction", "target", "target.c", "target.c:1",
                "possible OOB", "possible OOB", [], "UNKNOWN", [], [], [], [],
            )
            def fake_replay(*args, **_kwargs):
                output = args[5]
                output.mkdir(parents=True)
                (output / "observation_replay.json").write_text(json.dumps({
                    "status": "REPRODUCED_OBSERVATION_ONLY"}))
                return {"status": "REPRODUCED_OBSERVATION_ONLY"}

            with patch('vulnerabilityanalysis.scan.replay_observed_oob_without_cause',
                       side_effect=fake_replay) as replay:
                deadline = time.monotonic() + 30
                _verify_observed_target_crash(
                    root, crash_path, poc, point, _runtime(q.source_root / "target.c"),
                    q.source_root, q.harness, q.binary, None,
                    official_qualification=q, process_envelope=object(),
                    observation_deadline_monotonic=deadline)
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(replay.call_args.kwargs["observation_deadline_monotonic"],
                             deadline)
            record = json.loads(crash_path.read_text())
            self.assertEqual(record["independent_verification_status"],
                             "TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE")
            self.assertEqual(record["observation_replay_status"],
                             "REPRODUCED_OBSERVATION_ONLY")
            replay_artifact = Path(record["observation_replay_artifact"])
            self.assertEqual(record["observation_replay_artifact_sha256"],
                             hashlib.sha256(replay_artifact.read_bytes()).hexdigest())
            self.assertEqual(record["independent_gate_trace"], {
                "crash_id": "crash-oob",
                "security_property_attempted": False,
                "security_property_evaluated": False,
                "security_property_state": "NOT_STARTED",
                "promotion_attempted": False,
                "promotion_state": "NOT_STARTED",
                "promotion_result": None,
                "promotion_error_type": None,
            })
            self.assertFalse((root / "root_cause").exists())
            self.assertFalse((root / "security").exists())


if __name__ == "__main__":
    unittest.main()
