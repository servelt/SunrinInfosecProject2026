"""Provider-free proof that Global and validation processes share one cap."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dev_accounted_global_campaign import AccountedGlobalCampaign
from dev_global_campaign import DevGlobalCampaign
from dev_persistent_physical_fuzz_ledger import PhysicalBudgetExhausted
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from test_dev_global_campaign import make_plan, make_seed
from test_official_v2_contract import Fixture


class AccountedGlobalTests(unittest.TestCase):
    def _no_seed_fixture(self, root: Path):
        q = Fixture(root / "authority").issue()
        ledger = PersistentProcessLedgerV2.create(
            root / "physical-process.json", wall_total_seconds=25,
            fuzz_total_seconds=20)
        envelope = DevelopmentProcessEnvelopeV2(
            ledger, work_item_id="task", assertion_id="global_consumer",
            attempt_id="first", output_limit_bytes=4096,
            total_wall_seconds=60,
            pin_hook=lambda _phase, _command: None)
        campaign = DevGlobalCampaign(
            root / "output", q, total_fuzz_seconds=40,
            global_seconds=1, global_wall_reservation_seconds=14,
            replay_limit=1, process_envelope=envelope,
            require_accounted_consumer=True)
        wrapper = AccountedGlobalCampaign(
            campaign, ledger, reservation_key="GLOBAL_FUZZ:task:first")
        plan, plan_sha = make_plan(root)
        records = [{"role": "seed", "owner_id": "direction-one",
                    "request_id": "seed-one", "status": "COMPLETED",
                    "tool_events": []}]
        gate = SimpleNamespace(
            campaign_id="first",
            snapshot=lambda: {"campaign_id": "first", "records": records},
            verify_response_evidence=lambda _id: {"status": "VERIFIED"},
            verify_tool_event=lambda _request, _call: {"status": "VERIFIED"})
        return wrapper, campaign, ledger, plan, plan_sha, gate, records

    def test_clean_no_seed_has_durable_zero_physical_receipt(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger, plan, plan_sha, gate, records = (
                self._no_seed_fixture(Path(tmp)))
            result = wrapper.record_clean_no_seed(
                plan_path=plan, plan_sha256=plan_sha,
                direction_ids=["direction-one"], model_gate=gate)
            self.assertEqual(result["status"], "SKIPPED_NO_SEED")
            self.assertEqual(result["physical_seconds"], 0)
            self.assertEqual(ledger.snapshot()["finished"], [])
            self.assertIsNone(campaign.process)
            self.assertEqual(wrapper.final_result, result)
            with self.assertRaises((RuntimeError, ValueError)):
                wrapper.record_clean_no_seed(
                    plan_path=plan, plan_sha256=plan_sha,
                    direction_ids=["direction-one"], model_gate=gate)
            records[0]["status"] = "UNCERTAIN"
            with self.assertRaises(ValueError):
                _ = wrapper.final_result

    def test_no_seed_receipt_detects_later_manifest_and_direction_tamper(self):
        for changed in ("DIRECTION_SEEDS.json", "DEV_GLOBAL_RESULT.json",
                        "CORPUS", "DIRECTION_MODEL"):
            with self.subTest(changed=changed), TemporaryDirectory() as tmp:
                wrapper, campaign, ledger, plan, plan_sha, gate, records = (
                    self._no_seed_fixture(Path(tmp)))
                records.insert(0, {"role": "direction", "owner_id": "task",
                                   "request_id": "direction-one-turn",
                                   "status": "COMPLETED", "tool_events": []})
                wrapper.record_clean_no_seed(
                    plan_path=plan, plan_sha256=plan_sha,
                    direction_ids=["direction-one"], model_gate=gate)
                if changed == "CORPUS":
                    (campaign.run_dir / "corpus" / "global" / "injected").write_bytes(b"X")
                elif changed == "DIRECTION_MODEL":
                    records[0]["status"] = "UNCERTAIN"
                else:
                    (campaign.run_dir / changed).write_text('{}')
                with self.assertRaises((RuntimeError, ValueError)):
                    _ = wrapper.final_result

    def test_no_seed_refuses_missing_model_proof_before_staging(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger, plan, plan_sha, gate, records = (
                self._no_seed_fixture(Path(tmp)))
            records[0]["status"] = "UNCERTAIN"
            with self.assertRaises(ValueError):
                wrapper.record_clean_no_seed(
                    plan_path=plan, plan_sha256=plan_sha,
                    direction_ids=["direction-one"], model_gate=gate)
            self.assertFalse(campaign.run_dir.exists())
            self.assertIsNone(wrapper.final_result)
            self.assertEqual(ledger.snapshot()["finished"], [])

    def test_no_seed_refuses_uncertain_prior_direction_turn(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger, plan, plan_sha, gate, records = (
                self._no_seed_fixture(Path(tmp)))
            records.append({"role": "direction", "owner_id": "task",
                            "request_id": "direction-uncertain",
                            "status": "UNCERTAIN", "tool_events": []})
            with self.assertRaises(ValueError):
                wrapper.record_clean_no_seed(
                    plan_path=plan, plan_sha256=plan_sha,
                    direction_ids=["direction-one"], model_gate=gate)
            self.assertFalse(campaign.run_dir.exists())
            self.assertEqual(ledger.snapshot()["finished"], [])

    def _fixture(self, root: Path, *, wall: float = 25, fuzz: float = 20):
        q = Fixture(root / "authority").issue()
        self.assertIsNotNone(q)
        ledger = PersistentProcessLedgerV2.create(
            root / "physical-process.json", wall_total_seconds=wall,
            fuzz_total_seconds=fuzz)
        envelope = DevelopmentProcessEnvelopeV2(
            ledger, work_item_id="task", assertion_id="global_consumer",
            attempt_id="first", output_limit_bytes=4096,
            total_wall_seconds=60,
            pin_hook=lambda _phase, _command: None)
        campaign = DevGlobalCampaign(
            root / "output", q, total_fuzz_seconds=40,
            global_seconds=1, global_wall_reservation_seconds=14,
            replay_limit=1, process_envelope=envelope,
            require_accounted_consumer=True)
        plan, plan_sha = make_plan(root)
        campaign.stage_direction_seeds(plan, plan_sha, [make_seed(root)])
        wrapper = AccountedGlobalCampaign(
            campaign, ledger, reservation_key="GLOBAL_FUZZ:task:first")
        return wrapper, campaign, ledger

    @staticmethod
    def _fake_start(campaign, ledger, key):
        assert ledger.snapshot()["active"][key]["kind"] == "GLOBAL_FUZZ"
        campaign.budget.reserve("GLOBAL", campaign.global_wall_reservation_seconds)
        return "ACTIVE"

    @staticmethod
    def _fake_result(campaign, measured, *, status="RAN", cleanup=True):
        secondary = campaign.budget.finish("GLOBAL", measured)
        return {"status": status, "physical_seconds": measured,
                "cleanup_complete": cleanup,
                "global_budget_charge": secondary,
                "consumer_rows": []}

    def test_global_predebit_and_aux_share_one_wall_and_fuzz_cap(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp), wall=20, fuzz=20)
            key = wrapper.reservation_key
            with patch.object(campaign, "start",
                              side_effect=lambda: self._fake_start(
                                  campaign, ledger, key)):
                self.assertEqual(wrapper.start(), "ACTIVE")
            with self.assertRaises(PhysicalBudgetExhausted):
                ledger.reserve("AUX:too-much", "AUX_PROCESS", 7)
            ledger.reserve("AUX:within-cap", "AUX_PROCESS", 5)
            ledger.finish("AUX:within-cap", physical_seconds=1,
                          cleanup_complete=True)
            with patch.object(campaign, "finish",
                              side_effect=lambda: self._fake_result(campaign, 3)):
                receipt = wrapper.finish()
            self.assertEqual(receipt["status"], "RAN")
            self.assertEqual(receipt["durable_global_charge"]["kind"], "GLOBAL_FUZZ")
            self.assertEqual(receipt["global_budget_charge"]["physical_seconds"], 3)
            self.assertEqual(receipt["durable_global_charge"]["physical_seconds"], 3)
            snap = ledger.snapshot()
            self.assertEqual(snap["wall_spent_seconds"], 4)
            self.assertEqual(snap["fuzz_spent_seconds"], 3)
            self.assertEqual(snap["active"], {})
            with self.assertRaisesRegex(RuntimeError, "retried"):
                wrapper.start()

    def test_abort_settles_same_durable_charge_once(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start", side_effect=lambda:
                              self._fake_start(campaign, ledger,
                                               wrapper.reservation_key)):
                wrapper.start()
            with patch.object(campaign, "abort", side_effect=lambda:
                              self._fake_result(campaign, 2,
                                                status="STOPPED_ABORTED")) as abort:
                first = wrapper.abort()
                second = wrapper.abort()
            self.assertIs(first, second)
            self.assertEqual(abort.call_count, 1)
            self.assertEqual(ledger.snapshot()["wall_spent_seconds"], 2)
            self.assertEqual(ledger.snapshot()["fuzz_spent_seconds"], 2)

    def test_overrun_stops_ledger_even_if_secondary_status_says_ran(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start", side_effect=lambda:
                              self._fake_start(campaign, ledger,
                                               wrapper.reservation_key)):
                wrapper.start()
            with patch.object(campaign, "finish", side_effect=lambda:
                              self._fake_result(campaign, 15)):
                result = wrapper.finish()
            self.assertEqual(result["status"], "STOPPED_PHYSICAL_CAP_UNPROVEN")
            self.assertEqual(result["original_global_status"], "RAN")
            self.assertEqual(ledger.snapshot()["fuzz_spent_seconds"], 15)
            with self.assertRaises(RuntimeError):
                ledger.reserve("AUX:after-overrun", "AUX_PROCESS", 1)

    def test_failed_finish_after_secondary_charge_does_not_abort_twice(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start", side_effect=lambda:
                              self._fake_start(campaign, ledger,
                                               wrapper.reservation_key)):
                wrapper.start()

            def charged_then_failed():
                campaign.budget.finish("GLOBAL", 2)
                raise RuntimeError("report parse failed after physical charge")

            with patch.object(campaign, "finish", side_effect=charged_then_failed), \
                 patch.object(campaign, "abort") as abort:
                with self.assertRaisesRegex(RuntimeError, "report parse failed"):
                    wrapper.finish()
            abort.assert_not_called()
            snap = ledger.snapshot()
            self.assertEqual(snap["fuzz_spent_seconds"], 2)
            self.assertEqual(snap["stop_status"], "STOPPED_CLEANUP_INCOMPLETE")
            self.assertEqual(len([row for row in snap["finished"]
                                  if row["kind"] == "GLOBAL_FUZZ"]), 1)

    def test_postcommit_receipt_failure_never_exposes_raw_ran_on_repeat(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start", side_effect=lambda:
                              self._fake_start(campaign, ledger,
                                               wrapper.reservation_key)):
                wrapper.start()

            def finish_and_store():
                campaign.final_result = self._fake_result(campaign, 2)
                return campaign.final_result

            with patch.object(campaign, "finish", side_effect=finish_and_store) as finish, \
                 patch.object(ledger, "receipt_snapshot",
                              side_effect=OSError("checkpoint read failed")):
                with self.assertRaisesRegex(OSError, "checkpoint read failed"):
                    wrapper.finish()
            self.assertEqual(finish.call_count, 1)
            self.assertEqual(ledger.snapshot()["fuzz_spent_seconds"], 2)
            self.assertEqual(ledger.snapshot()["stop_status"], "STOPPED_PIN_DRIFT")
            self.assertIsNone(wrapper.final_result)
            self.assertEqual(campaign.final_result["status"], "RAN")
            with patch.object(campaign, "abort") as abort:
                with self.assertRaisesRegex(RuntimeError, "receipt is incomplete"):
                    wrapper.finish()
                with self.assertRaisesRegex(RuntimeError, "receipt is incomplete"):
                    wrapper.abort()
            abort.assert_not_called()
            self.assertEqual(finish.call_count, 1)

    def test_stop_before_atomic_receipt_cannot_return_ran(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start", side_effect=lambda:
                              self._fake_start(campaign, ledger,
                                               wrapper.reservation_key)):
                wrapper.start()
            original_receipt = ledger.receipt_snapshot

            def stop_then_receipt():
                ledger.mark_stop("STOPPED_PIN_DRIFT", "concurrent pin check failed")
                return original_receipt()

            with patch.object(campaign, "finish", side_effect=lambda:
                              self._fake_result(campaign, 2)), \
                 patch.object(ledger, "receipt_snapshot",
                              side_effect=stop_then_receipt):
                result = wrapper.finish()
            self.assertEqual(result["status"], "STOPPED_PIN_DRIFT")
            self.assertEqual(result["original_global_status"], "RAN")
            self.assertEqual(result["durable_process_ledger_sha256"],
                             original_receipt()[1])

    def test_later_ledger_stop_invalidates_cached_global_ran(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start", side_effect=lambda:
                              self._fake_start(campaign, ledger,
                                               wrapper.reservation_key)):
                wrapper.start()
            with patch.object(campaign, "finish", side_effect=lambda:
                              self._fake_result(campaign, 2)) as finish:
                self.assertEqual(wrapper.finish()["status"], "RAN")
                ledger.reserve("AUX:later-pov", "AUX_PROCESS", 1)
                ledger.finish("AUX:later-pov", physical_seconds=0.1,
                              cleanup_complete=True)
                self.assertEqual(wrapper.final_result["status"], "RAN")
                ledger.mark_stop("STOPPED_PIN_DRIFT", "later authority failure")
                with self.assertRaisesRegex(RuntimeError, "later stop changed"):
                    wrapper.finish()
                with self.assertRaisesRegex(RuntimeError, "later stop changed"):
                    _ = wrapper.final_result
            self.assertEqual(finish.call_count, 1)

    def test_uncertain_start_has_durable_active_stop_and_no_retry(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))
            with patch.object(campaign, "start",
                              side_effect=RuntimeError("unknown launch")) as start:
                with self.assertRaisesRegex(RuntimeError, "unknown launch"):
                    wrapper.start()
            self.assertEqual(start.call_count, 1)
            snap = ledger.snapshot()
            self.assertEqual(snap["stop_status"], "STOPPED_UNCERTAIN_PROCESS")
            self.assertIn(wrapper.reservation_key, snap["active"])
            with self.assertRaisesRegex(RuntimeError, "retried"):
                wrapper.start()
            with self.assertRaises(RuntimeError):
                ledger.reserve("AUX:after-uncertain", "AUX_PROCESS", 1)
            restored = PersistentProcessLedgerV2.restore(
                ledger.path, wall_total_seconds=25, fuzz_total_seconds=20)
            self.assertEqual(restored.snapshot()["stop_status"],
                             "STOPPED_UNCERTAIN_PROCESS")

    def test_launch_receipt_failure_aborts_and_charges_observed_physical_time(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp))

            def start_after_launch():
                self._fake_start(campaign, ledger, wrapper.reservation_key)
                campaign.process = SimpleNamespace(pid=424242)
                raise RuntimeError("launch receipt missing")

            with patch.object(campaign, "start", side_effect=start_after_launch), \
                 patch.object(campaign, "abort", side_effect=lambda:
                              self._fake_result(campaign, 2,
                                                status="STOPPED_ABORTED")) as abort:
                with self.assertRaisesRegex(RuntimeError, "launch receipt missing"):
                    wrapper.start()
            self.assertEqual(abort.call_count, 1)
            self.assertEqual(ledger.snapshot()["fuzz_spent_seconds"], 2)
            self.assertEqual(ledger.snapshot()["active"], {})
            with self.assertRaisesRegex(RuntimeError, "retried"):
                wrapper.start()

    def test_fuzz_cap_blocks_global_before_start(self):
        with TemporaryDirectory() as tmp:
            wrapper, campaign, ledger = self._fixture(Path(tmp), fuzz=10)
            with patch.object(campaign, "start") as start:
                with self.assertRaises(PhysicalBudgetExhausted):
                    wrapper.start()
            start.assert_not_called()
            self.assertEqual(ledger.snapshot()["active"], {})


if __name__ == "__main__":
    unittest.main()
