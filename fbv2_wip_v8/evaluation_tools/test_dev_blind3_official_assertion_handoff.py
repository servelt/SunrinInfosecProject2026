"""Stage15 official V2 Assertion handoff without Provider or Target calls."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / "src"), str(Path(__file__).resolve().parent)]

import dev_blind3_official_assertion_handoff as stage15  # noqa: E402
from dev_blind3_official_interleaved_adapter import sha256  # noqa: E402
import test_dev_blind3_official_hp_vertical_stage14 as stage14  # noqa: E402
from test_dev_interleaved_crossrole_stage import _wire_sp_response  # noqa: E402
import vulnerabilityanalysis.interleaved_dev as base  # noqa: E402


class OfficialAssertionHandoffStage15Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = stage14.OfficialHPVerticalStage14Tests(
            "test_official_context_followup_assertion_one_ledger_no_target")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.adapter = fixture.adapter
        self._complete_proposal()
        root = Path(__file__).resolve().parents[1]
        manifest_path = root / "tools/multi_tu_assertion_build_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        old_manifest = os.environ.get("VA_ASSERTION_BUILD_MANIFEST")
        os.environ["VA_ASSERTION_BUILD_MANIFEST"] = str(manifest_path)
        self.addCleanup(self._restore_manifest, old_manifest)
        q = self.adapter.qualification
        self.contract = {
            "kind": stage15.KIND, "status": stage15.STATUS,
            "route_sha256": self.adapter.route_sha256,
            "qualification_source_root": str(q.source_root),
            "qualification_harness": str(q.harness),
            "qualification_harness_sha256": q.harness_sha256,
            "qualification_binary": str(q.binary),
            "qualification_binary_sha256": q.binary_sha256,
            "qualification_seed": str(q.normal_seed),
            "qualification_seed_sha256": q.normal_seed_sha256,
            "builder_path": str(root / "tools/multi_tu_assertion_build.py"),
            "builder_sha256": sha256(root / "tools/multi_tu_assertion_build.py"),
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256(manifest_path),
            "toolchain_files_sha256": stage15._canonical_sha(
                manifest["toolchain_files"]),
            "toolchain_trees_sha256": stage15._canonical_sha(
                manifest["toolchain_trees"]),
            "product_assertions_sha256": sha256(Path(stage15.assertions.__file__)),
            "product_interleaved_sha256": sha256(Path(base.__file__)),
            "product_handoff_validator_sha256": sha256(
                Path(stage15.interleaved_assertion_dev.__file__)),
            "handoff_adapter_sha256": sha256(Path(stage15.__file__)),
            "physical_adapter_sha256": sha256(
                Path(stage15.__file__).with_name(
                    "dev_product_fuzz_physical_adapter.py")),
            "build_command": [str(root / "tools/multi_tu_assertion_build.py"),
                              "{source}", "-o", "{binary}"],
            "run_command": ["{binary}", "{input}"],
            "oracle_queries": 0, "blind3_runs": 0, "target_executions": 0,
        }
        self.contract_path = self.fixture.fixture.root / "assertion-contract.json"
        self._write_contract()

    @staticmethod
    def _restore_manifest(previous: str | None) -> None:
        if previous is None:
            os.environ.pop("VA_ASSERTION_BUILD_MANIFEST", None)
        else:
            os.environ["VA_ASSERTION_BUILD_MANIFEST"] = previous

    def _write_contract(self) -> None:
        self.contract_path.write_text(json.dumps(self.contract, sort_keys=True),
                                      encoding="utf-8")
        self.contract_path.chmod(0o600)
        self.contract_sha = sha256(self.contract_path)

    def _complete_proposal(self) -> None:
        f = self.fixture
        item = f.item
        claim = "Scripted input relation for provider-free role wiring"
        f.adapter.backend.responses = [
            _wire_sp_response(f.repository, item, 1),
            stage14._analysis(item, f.span, request=True, safe=False),
            stage14._analysis(item, f.span, request=False, safe=True),
            {"assertions": [{"safe_id": 0, "safe_assumption": claim,
                "runtime_expression": "size > 0",
                "source_line": f.span.start_line + 4,
                "required_context": [], "rationale": "scripted provider-free test"}],
             "dispositions": [{"safe_id": 0, "safe_assumption": claim,
                "status": "PROPOSED", "reason": "scripted provider-free test"}]},
        ]

        async def sequence() -> None:
            await f.adapter.sp(0)
            await f.adapter.hp(0)
            await f.adapter.hp_context(0)
            await f.adapter.hp_followup(0)
            await f.adapter.assertions(0)

        with f._wire():
            asyncio.run(sequence())

    def test_pinned_handoff_preserves_proposal_and_spends_nothing(self) -> None:
        proposal = Path(self.adapter.read()["role_turns"][-1]["artifact_path"])
        proposal_sha = sha256(proposal)
        model_before = sha256(self.adapter.ledger.checkpoint_path)
        physical_before = sha256(self.adapter.physical_ledger.path)
        actual_runner = stage15.ProductFuzzPhysicalRunner
        with (patch.object(stage15.assertions, "execute_assertion",
                           side_effect=AssertionError("Target execution forbidden")),
              patch.object(stage15, "ProductFuzzPhysicalRunner",
                           wraps=actual_runner) as runner_constructor):
            result = stage15.handoff_next_assertion(
                self.adapter, 0, self.contract_path, self.contract_sha)
        runner_constructor.assert_called_once_with(self.adapter.physical_ledger,
                                                   kind="HP")
        row = json.loads(result.read_text())
        self.assertEqual(row["status"], "EXECUTION_HANDOFF_READY")
        self.assertEqual(row["execution_count"], 0)
        self.assertEqual(row["guided_fuzz_seconds"], 0)
        self.assertEqual(row["official_replay_count"], 0)
        self.assertEqual(sha256(proposal), proposal_sha)
        self.assertEqual(sha256(self.adapter.ledger.checkpoint_path), model_before)
        self.assertEqual(sha256(self.adapter.physical_ledger.path), physical_before)
        saved = self.adapter.read()
        self.assertEqual(saved["work_items"][0]["hp_state"],
                         "PENDING_ASSERTION_EXECUTION")
        self.assertEqual(saved["scan_count"], 0)
        self.assertFalse((self.adapter.state_path.parent / "scan.json").exists())
        self.assertFalse((self.adapter.state_path.parent /
                          "four_phase_scan_complete.json").exists())
        real_hash = base._sha
        validator_path = Path(stage15.interleaved_assertion_dev.__file__).resolve()
        with patch.object(base, "_sha", side_effect=lambda path: (
                "0" * 64 if Path(path) == validator_path else real_hash(path))):
            with self.assertRaises(ValueError):
                self.adapter.read()
        with self.assertRaises(ValueError):
            stage15.handoff_next_assertion(
                self.adapter, 0, self.contract_path, self.contract_sha)

    def test_wrong_manifest_or_execution_pin_blocks_before_handoff(self) -> None:
        with patch.dict(os.environ, {"VA_ASSERTION_BUILD_MANIFEST": ""}):
            with self.assertRaises(ValueError):
                stage15.handoff_next_assertion(
                    self.adapter, 0, self.contract_path, self.contract_sha)
        self.contract["physical_adapter_sha256"] = "0" * 64
        self._write_contract()
        with self.assertRaises(ValueError):
            stage15.handoff_next_assertion(
                self.adapter, 0, self.contract_path, self.contract_sha)
        self.assertNotIn("assertion_execution_handoffs", self.adapter.read())
        state = self.adapter.read()
        scope = state["work_items"][0]["work_item_id"]
        orphan = (self.adapter.state_path.parent / "work_items" /
                  f"000000-{scope}" / "assertion_execution/000000" /
                  "ASSERTION_EXECUTION_STATE.json")
        orphan.parent.mkdir(mode=0o700, parents=True)
        orphan.write_text("{}", encoding="utf-8")
        orphan.chmod(0o600)
        with self.assertRaises(ValueError):
            self.adapter.read()

    def test_missing_and_changed_companion_fail_closed(self) -> None:
        receipt = stage15.handoff_next_assertion(
            self.adapter, 0, self.contract_path, self.contract_sha)
        original = receipt.read_bytes()
        receipt.unlink()
        with self.assertRaises(ValueError):
            self.adapter.read()
        receipt.write_bytes(original)
        receipt.chmod(0o600)
        changed = json.loads(receipt.read_text())
        changed["execution_count"] = 1
        receipt.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.adapter.read()

    def test_anchor_write_gap_stops_before_execution_and_model(self) -> None:
        model_before = sha256(self.adapter.ledger.checkpoint_path)
        physical_before = sha256(self.adapter.physical_ledger.path)
        with patch.object(stage15, "_private_companion_json", side_effect=OSError(
                "scripted crash between anchor and companion")):
            with self.assertRaisesRegex(OSError, "between anchor and companion"):
                stage15.handoff_next_assertion(
                    self.adapter, 0, self.contract_path, self.contract_sha)
        self.assertEqual(sha256(self.adapter.ledger.checkpoint_path), model_before)
        self.assertEqual(sha256(self.adapter.physical_ledger.path), physical_before)
        self.assertTrue((self.adapter.state_path.parent /
                         "OFFICIAL_PIN_FAILURE.json").is_file())
        with self.assertRaises(ValueError):
            self.adapter.read()

    def test_preexisting_companion_parent_symlink_cannot_escape(self) -> None:
        state = self.adapter.read()
        scope = state["work_items"][0]["work_item_id"]
        parent = (self.adapter.state_path.parent / "work_items" /
                  f"000000-{scope}" / "assertion_execution")
        outside = self.fixture.fixture.root / "outside"
        outside.mkdir(mode=0o700)
        parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            stage15.handoff_next_assertion(
                self.adapter, 0, self.contract_path, self.contract_sha)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.adapter.ledger.physical, 4)

    def test_manifest_environment_drift_before_ready_stays_armed(self) -> None:
        model_before = sha256(self.adapter.ledger.checkpoint_path)
        physical_before = sha256(self.adapter.physical_ledger.path)
        manifest = os.environ["VA_ASSERTION_BUILD_MANIFEST"]
        write = stage15._private_companion_json

        def drift_after_armed(path, root, value, *, replace):
            write(path, root, value, replace=replace)
            if not replace:
                os.environ["VA_ASSERTION_BUILD_MANIFEST"] = str(
                    self.fixture.fixture.root / "different-manifest.json")

        try:
            with patch.object(stage15, "_private_companion_json",
                              side_effect=drift_after_armed):
                with self.assertRaisesRegex(ValueError,
                                            "manifest environment differs"):
                    stage15.handoff_next_assertion(
                        self.adapter, 0, self.contract_path, self.contract_sha)
        finally:
            os.environ["VA_ASSERTION_BUILD_MANIFEST"] = manifest
        raw = json.loads(self.adapter.state_path.read_text())
        anchor = raw["assertion_execution_handoffs"][0]
        companion = json.loads(Path(anchor["companion_path"]).read_text())
        self.assertEqual(anchor["status"], "ARMED")
        self.assertEqual(companion["status"], "ARMED")
        self.assertEqual(sha256(self.adapter.ledger.checkpoint_path), model_before)
        self.assertEqual(sha256(self.adapter.physical_ledger.path), physical_before)
        self.assertEqual(json.loads((self.adapter.state_path.parent /
                         "ROLE_GUARD.json").read_text())["status"], "PENDING")
        with self.assertRaises(ValueError):
            self.adapter.read()

    def test_manifest_environment_drift_before_return_keeps_pending_guard(self) -> None:
        model_before = sha256(self.adapter.ledger.checkpoint_path)
        physical_before = sha256(self.adapter.physical_ledger.path)
        manifest = os.environ["VA_ASSERTION_BUILD_MANIFEST"]
        check = self.adapter._check_identity

        def drift_after_postcheck(*args, **kwargs):
            check(*args, **kwargs)
            if kwargs.get("allow_pending_guard"):
                os.environ["VA_ASSERTION_BUILD_MANIFEST"] = str(
                    self.fixture.fixture.root / "different-manifest.json")

        try:
            with patch.object(self.adapter, "_check_identity",
                              side_effect=drift_after_postcheck):
                with self.assertRaisesRegex(ValueError,
                                            "manifest environment differs"):
                    stage15.handoff_next_assertion(
                        self.adapter, 0, self.contract_path, self.contract_sha)
        finally:
            os.environ["VA_ASSERTION_BUILD_MANIFEST"] = manifest
        self.assertEqual(sha256(self.adapter.ledger.checkpoint_path), model_before)
        self.assertEqual(sha256(self.adapter.physical_ledger.path), physical_before)
        self.assertEqual(json.loads((self.adapter.state_path.parent /
                         "ROLE_GUARD.json").read_text())["status"], "PENDING")
        self.assertTrue((self.adapter.state_path.parent /
                         "OFFICIAL_PIN_FAILURE.json").is_file())
        with self.assertRaises(ValueError):
            self.adapter.read()


if __name__ == "__main__":
    unittest.main()
