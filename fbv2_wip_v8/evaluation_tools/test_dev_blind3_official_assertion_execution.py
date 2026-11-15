"""Stage16 fixed synthetic Assertion API wiring; no Target or Provider calls."""
from __future__ import annotations

from functools import partial
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / "src"), str(Path(__file__).resolve().parent)]

import dev_blind3_official_assertion_execution as stage16  # noqa: E402
import dev_blind3_official_assertion_handoff as stage15  # noqa: E402
import test_dev_blind3_official_assertion_handoff as fixture_mod  # noqa: E402
from dev_blind3_official_interleaved_adapter import sha256  # noqa: E402
from vulnerabilityanalysis import assertions, runtime  # noqa: E402


class OfficialAssertionExecutionStage16Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = fixture_mod.OfficialAssertionHandoffStage15Tests(
            "test_pinned_handoff_preserves_proposal_and_spends_nothing")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.adapter = fixture.adapter
        self.handoff_path = stage15.handoff_next_assertion(
            self.adapter, 0, fixture.contract_path, fixture.contract_sha)
        self.handoff_sha = sha256(self.handoff_path)
        self.proposal_sha = sha256(Path(self.adapter.read()["role_turns"][-1]
                                         ["artifact_path"]))
        self.contract = {
            "kind": stage16.KIND, "status": stage16.STATUS,
            "route_sha256": self.adapter.route_sha256,
            "stage15_contract_path": str(fixture.contract_path),
            "stage15_contract_sha256": fixture.contract_sha,
            "harness_sha256": self.adapter.qualification.harness_sha256,
            "binary_sha256": self.adapter.qualification.binary_sha256,
            "seed_sha256": self.adapter.qualification.normal_seed_sha256,
            "builder_sha256": fixture.contract["builder_sha256"],
            "manifest_sha256": fixture.contract["manifest_sha256"],
            "runtime_path": str(Path(runtime.__file__).resolve()),
            "runtime_sha256": sha256(Path(runtime.__file__)),
            "product_handoff_validator_sha256": sha256(Path(
                stage16.interleaved_assertion_dev.__file__)),
            "stage16_adapter_path": str(Path(stage16.__file__).resolve()),
            "stage16_adapter_sha256": sha256(Path(stage16.__file__)),
            "wall_process_envelope": "UNPROVEN_BLOCK_ACTUAL",
            "synthetic_guided_seconds": 3,
            "oracle_queries": 0, "blind3_runs": 0, "target_executions": 0,
        }
        self.path = fixture.fixture.fixture.root / "stage16-contract.json"
        self._write_contract()

    def _write_contract(self) -> None:
        self.path.write_text(json.dumps(self.contract, sort_keys=True),
                             encoding="utf-8")
        self.path.chmod(0o600)
        self.contract_sha = sha256(self.path)

    def _run(self, calls: stage16.SyntheticProductCalls):
        return stage16.run_synthetic_assertion_wiring(
            self.adapter, 0, 0, self.path, self.contract_sha,
            synthetic_calls=calls)

    def test_synthetic_signatures_share_hp_ledger_without_target(self) -> None:
        model_before = sha256(self.adapter.ledger.checkpoint_path)
        physical_before = sha256(self.adapter.physical_ledger.path)
        calls = stage16.SyntheticProductCalls()
        with (patch.object(assertions, "execute_assertion", side_effect=AssertionError(
                  "real Target execution forbidden")),
              patch.object(assertions, "guided_fuzz_assertion", side_effect=AssertionError(
                  "real Guided execution forbidden"))):
            path = self._run(calls)
        row = json.loads(path.read_text())
        self.assertEqual(row["status"], "SYNTHETIC_WIRING_ONLY")
        self.assertEqual([call["api"] for call in calls.calls],
                         ["execute_assertion", "guided_fuzz_assertion"])
        self.assertEqual(calls.guided_runner.ledger, self.adapter.physical_ledger)
        self.assertIs(calls.guided_runner.ledger, self.adapter.physical_ledger)
        self.assertEqual(calls.calls[0]["seed"],
                         str(self.adapter.qualification.normal_seed))
        self.assertEqual(calls.calls[1]["seconds"], 3)
        for field in ("instrumented_assertion_state", "test_original_target_state",
                      "official_asan_replay_state", "root_cause_state",
                      "gate_state"):
            self.assertEqual(row[field], "NOT_RUN")
        self.assertFalse(row["verified"])
        self.assertEqual(row["target_execution_count"], 0)
        self.assertEqual(row["guided_fuzz_seconds"], 0)
        self.assertEqual(sha256(self.handoff_path), self.handoff_sha)
        self.assertEqual(sha256(self.adapter.ledger.checkpoint_path), model_before)
        self.assertEqual(sha256(self.adapter.physical_ledger.path), physical_before)
        self.assertEqual(self.adapter.read()["scan_count"], 0)
        self.assertFalse((self.adapter.state_path.parent / "scan.json").exists())
        with self.assertRaises(ValueError):
            self._run(stage16.SyntheticProductCalls())
        from blind2_runner_draft import preflight_live
        with self.assertRaisesRegex(ValueError, "not frozen"):
            preflight_live(self.path)

    def test_actual_or_wrapped_callbacks_rejected_before_reservation(self) -> None:
        before = sha256(self.adapter.state_path)
        with self.assertRaisesRegex(RuntimeError, "ENVELOPE_UNPROVEN"):
            stage16.run_synthetic_assertion_wiring(
                self.adapter, 0, 0, self.path, self.contract_sha)
        for wrapper in (partial(assertions.execute_assertion),
                        lambda *_args, **_kwargs: None):
            with self.assertRaisesRegex(RuntimeError, "ENVELOPE_UNPROVEN"):
                stage16.run_synthetic_assertion_wiring(
                    self.adapter, 0, 0, self.path, self.contract_sha,
                    synthetic_calls=wrapper)
        self.assertEqual(sha256(self.adapter.state_path), before)
        self.assertNotIn("assertion_execution_attempts", self.adapter.read())

    def test_partial_runtime_cleanup_error_preserved_and_no_retry(self) -> None:
        model_before = sha256(self.adapter.ledger.checkpoint_path)
        physical_before = sha256(self.adapter.physical_ledger.path)
        calls = stage16.SyntheticProductCalls(
            failure_mode="AFTER_PARTIAL_RUNTIME")
        with self.assertRaisesRegex(runtime.RuntimeCleanupError,
                                    "synthetic cleanup failure"):
            self._run(calls)
        raw = json.loads(self.adapter.state_path.read_text())
        anchor = raw["assertion_execution_attempts"][0]
        receipt = json.loads(Path(anchor["attempt_path"]).read_text())
        self.assertEqual(anchor["status"], "ARMED")
        self.assertEqual(receipt["status"], "ARMED")
        self.assertEqual([call["api"] for call in calls.calls],
                         ["execute_assertion"])
        self.assertTrue((Path(anchor["attempt_path"]).parent /
                         "synthetic-output/runtime.json").is_file())
        self.assertEqual(json.loads((self.adapter.state_path.parent /
                         "ROLE_GUARD.json").read_text())["status"], "PENDING")
        self.assertEqual(sha256(self.adapter.ledger.checkpoint_path), model_before)
        self.assertEqual(sha256(self.adapter.physical_ledger.path), physical_before)
        self.assertEqual(sha256(self.handoff_path), self.handoff_sha)
        with self.assertRaises(ValueError):
            self._run(calls)
        self.assertEqual(len(calls.calls), 1)

    def test_identity_drift_and_wrong_return_never_promote(self) -> None:
        self.contract["runtime_sha256"] = "0" * 64
        self._write_contract()
        calls = stage16.SyntheticProductCalls()
        with self.assertRaises(ValueError):
            self._run(calls)
        self.assertEqual(calls.calls, [])
        self.assertNotIn("assertion_execution_attempts", self.adapter.read())
        self.contract["runtime_sha256"] = sha256(Path(runtime.__file__))
        self._write_contract()
        bad = stage16.SyntheticProductCalls(failure_mode="DRIFT_ASSERTION_ID")
        with self.assertRaisesRegex(ValueError, "return identity changed"):
            self._run(bad)
        self.assertEqual([call["api"] for call in bad.calls],
                         ["execute_assertion"])
        raw = json.loads(self.adapter.state_path.read_text())
        self.assertEqual(raw["assertion_execution_attempts"][0]["status"],
                         "ARMED")
        self.assertEqual(sha256(self.handoff_path), self.handoff_sha)

    def test_manifest_drift_after_fake_call_stays_armed(self) -> None:
        previous = os.environ["VA_ASSERTION_BUILD_MANIFEST"]
        bad = stage16.SyntheticProductCalls(
            manifest_drift_to=self.fixture.fixture.fixture.root / "other-manifest")
        try:
            with self.assertRaisesRegex(ValueError,
                                        "manifest environment differs"):
                self._run(bad)
        finally:
            os.environ["VA_ASSERTION_BUILD_MANIFEST"] = previous
        raw = json.loads(self.adapter.state_path.read_text())
        self.assertEqual(raw["assertion_execution_attempts"][0]["status"],
                         "ARMED")
        self.assertEqual([call["api"] for call in bad.calls],
                         ["execute_assertion"])
        self.assertEqual(json.loads((self.adapter.state_path.parent /
                         "ROLE_GUARD.json").read_text())["status"], "PENDING")
        self.assertEqual(sha256(self.handoff_path), self.handoff_sha)

    def test_synthetic_output_symlink_cannot_escape(self) -> None:
        outside = self.fixture.fixture.fixture.root / "outside"
        outside.mkdir(mode=0o700)
        output = self.handoff_path.parent / "synthetic-output"
        output.symlink_to(outside, target_is_directory=True)
        calls = stage16.SyntheticProductCalls(
            failure_mode="AFTER_PARTIAL_RUNTIME")
        with self.assertRaises((ValueError, FileExistsError)):
            self._run(calls)
        self.assertEqual(calls.calls, [])
        self.assertEqual(list(outside.iterdir()), [])
        raw = json.loads(self.adapter.state_path.read_text())
        self.assertEqual(raw["assertion_execution_attempts"][0]["status"],
                         "ARMED")


if __name__ == "__main__":
    unittest.main()
