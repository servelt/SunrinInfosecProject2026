"""Provider-free failure and opportunity checks for the development ledger."""

from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev_global_request_ledger import (DevelopmentBudget,
                                       DevelopmentBudgetExhausted,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)


HASH = "a" * 64
OTHER_HASH = "b" * 64


def budget(*, physical: int = 5, initial: int = 1,
           logical: int = 10, retries: int = 1) -> DevelopmentBudget:
    return DevelopmentBudget(physical_max=physical, logical_max=logical,
                             retries_max=retries, wall_seconds=60,
                             initial_starts_required=initial)


def completed(ledger: DevelopmentRequestLedger, scope: str, role: str) -> int:
    ledger.begin_turn(scope, role, HASH)
    ordinal = ledger.start_attempt(HASH)
    ledger.finish_attempt(completed=True)
    return ordinal


class DevelopmentLedgerTests(unittest.TestCase):
    def test_global_only_profile_allows_fifth_sp_and_restores_exact_kind(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            cap = DevelopmentBudget(physical_max=8, logical_max=8,
                                    retries_max=0, wall_seconds=60,
                                    initial_starts_required=1,
                                    profile=GLOBAL_ONLY_DEV_PROFILE)
            ledger = DevelopmentRequestLedger.create(cap, path)
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            self.assertTrue(ledger.select_function("fn-A"))
            for _ in range(5):
                completed(ledger, "fn-A", "sp_verifier")
            saved = json.loads(path.read_text())
            self.assertEqual(saved["kind"], "DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1")
            self.assertEqual(saved["budget"]["profile"], GLOBAL_ONLY_DEV_PROFILE)
            restored = DevelopmentRequestLedger.restore(path, cap)
            self.assertEqual(restored.function_counts["fn-A"]["sp_verifier"], 5)
            self.assertEqual((restored.logical, restored.physical), (6, 6))

    def test_legacy_profile_still_blocks_fifth_sp_and_preserves_v2_schema(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            cap = budget(physical=8, logical=8, retries=0)
            ledger = DevelopmentRequestLedger.create(cap, path)
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            self.assertTrue(ledger.select_function("fn-A"))
            for _ in range(4):
                completed(ledger, "fn-A", "sp_verifier")
            with self.assertRaisesRegex(ValueError, "function role limit"):
                ledger.begin_turn("fn-A", "sp_verifier", HASH)
            saved = json.loads(path.read_text())
            self.assertEqual(saved["kind"], "DEV_GLOBAL_REQUEST_LEDGER_V2")
            self.assertNotIn("profile", saved["budget"])
            self.assertEqual((ledger.logical, ledger.physical), (5, 5))

    def test_global_only_profile_still_stops_at_total_physical_and_logical(self):
        for physical, logical in ((5, 10), (10, 5)):
            with self.subTest(physical=physical, logical=logical), TemporaryDirectory() as temp:
                cap = DevelopmentBudget(physical_max=physical, logical_max=logical,
                                        retries_max=0, wall_seconds=60,
                                        initial_starts_required=1,
                                        profile=GLOBAL_ONLY_DEV_PROFILE)
                ledger = DevelopmentRequestLedger.create(cap, Path(temp) / "ledger.json")
                ledger.register_direction("plan")
                completed(ledger, "plan", "direction_generator")
                self.assertTrue(ledger.select_function("fn-A"))
                for _ in range(4):
                    completed(ledger, "fn-A", "sp_verifier")
                with self.assertRaisesRegex(DevelopmentBudgetExhausted, "not eligible"):
                    ledger.begin_turn("fn-A", "sp_verifier", HASH)
                self.assertEqual((ledger.logical, ledger.physical), (5, 5))
                self.assertIsNone(ledger.active_turn)

    def test_invalid_identity_precedes_exhausted_global_credit(self):
        for profile in (None, GLOBAL_ONLY_DEV_PROFILE):
            with self.subTest(profile=profile), TemporaryDirectory() as temp:
                fields = dict(physical_max=1, logical_max=3, retries_max=0,
                              wall_seconds=60, initial_starts_required=1)
                cap = DevelopmentBudget(**fields, **(
                    {"profile": profile} if profile else {}))
                ledger = DevelopmentRequestLedger.create(cap, Path(temp) / "ledger.json")
                ledger.register_direction("plan")
                self.assertTrue(ledger.select_function("fn-A"))
                completed(ledger, "plan", "direction_generator")
                for scope, role, digest, message in (
                        ("wrong-plan", "direction_generator", HASH, "Direction scope"),
                        ("wrong-function", "sp_verifier", HASH, "function scope"),
                        ("fn-A", "unregistered", HASH, "model role"),
                        ("fn-A", "sp_verifier", "bad-hash", "not eligible")):
                    with self.assertRaisesRegex(ValueError, message) as raised:
                        ledger.begin_turn(scope, role, digest)
                    self.assertIs(type(raised.exception), ValueError)
                with self.assertRaisesRegex(DevelopmentBudgetExhausted, "not eligible"):
                    ledger.begin_turn("fn-A", "sp_verifier", HASH)
                self.assertEqual((ledger.logical, ledger.physical), (1, 1))
                self.assertIsNone(ledger.active_turn)

    def test_wall_exhaustion_has_distinct_budget_error_type(self):
        with TemporaryDirectory() as temp:
            cap = budget(physical=2)
            ledger = DevelopmentRequestLedger.create(cap, Path(temp) / "ledger.json",
                                                     started_at=1.0)
            with self.assertRaisesRegex(DevelopmentBudgetExhausted, "wall limit"):
                ledger.wall(now=1.0 + cap.wall_seconds)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_checkpoint_profile_confusion_is_rejected_both_ways(self):
        for writer_profile, reader_profile in ((None, GLOBAL_ONLY_DEV_PROFILE),
                                               (GLOBAL_ONLY_DEV_PROFILE, None)):
            with self.subTest(writer=writer_profile), TemporaryDirectory() as temp:
                fields = dict(physical_max=8, logical_max=8, retries_max=0,
                              wall_seconds=60, initial_starts_required=1)
                writer = DevelopmentBudget(**fields, **(
                    {"profile": writer_profile} if writer_profile else {}))
                reader = DevelopmentBudget(**fields, **(
                    {"profile": reader_profile} if reader_profile else {}))
                path = Path(temp) / "ledger.json"
                DevelopmentRequestLedger.create(writer, path)
                with self.assertRaisesRegex(ValueError, "contract changed"):
                    DevelopmentRequestLedger.restore(path, reader)

    def test_global_only_keeps_direction_role_hash_and_prewire_checkpoint(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            cap = DevelopmentBudget(physical_max=8, logical_max=8,
                                    retries_max=0, wall_seconds=60,
                                    initial_starts_required=1,
                                    profile=GLOBAL_ONLY_DEV_PROFILE)
            ledger = DevelopmentRequestLedger.create(cap, path)
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            with self.assertRaisesRegex(ValueError, "Direction scope"):
                ledger.begin_turn("plan", "direction_generator", HASH)
            self.assertTrue(ledger.select_function("fn-A"))
            with self.assertRaisesRegex(ValueError, "unregistered model role"):
                ledger.begin_turn("fn-A", "unknown", HASH)
            with self.assertRaisesRegex(ValueError, "not eligible"):
                ledger.begin_turn("fn-A", "sp_verifier", "bad-hash")
            ledger.begin_turn("fn-A", "sp_verifier", HASH)
            with self.assertRaisesRegex(ValueError, "content changed"):
                ledger.start_attempt(OTHER_HASH)
            self.assertEqual(ledger.physical, 1)
            ledger.start_attempt(HASH)
            saved = json.loads(path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(saved["physical"], 2)
            self.assertEqual(saved["attempts"][-1]["status"], "STARTED")
            self.assertEqual(saved["attempts"][-1]["request_hash"], HASH)
            ledger.finish_attempt(completed=True)

    def test_direction_and_function_roles_use_one_durable_physical_chain(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=4), path)
            ledger.register_direction("direction-plan")
            self.assertEqual(completed(ledger, "direction-plan", "direction_generator"), 1)
            self.assertTrue(ledger.select_function("fn-A"))
            self.assertEqual(completed(ledger, "fn-A", "sp_generation"), 2)
            self.assertEqual(completed(ledger, "fn-A", "function_analysis"), 3)
            ledger.mark_scan_recorded("fn-A")
            self.assertTrue(ledger.select_function("fn-B"))
            ledger.begin_turn("fn-B", "sp_generation", HASH)
            self.assertEqual(ledger.start_attempt(HASH), 4)
            self.assertEqual(json.loads(path.read_text())["physical"], 4)
            ledger.finish_attempt(completed=True)
            with self.assertRaisesRegex(ValueError, "not eligible"):
                ledger.begin_turn("fn-B", "function_analysis", HASH)
            self.assertEqual([row["physical"] for row in ledger.attempts],
                             [1, 2, 3, 4])

    def test_explicit_start_reservation_preserves_no_opportunity(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(
                budget(physical=4, initial=2), Path(temp) / "ledger.json")
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            self.assertTrue(ledger.select_function("fn-A"))
            completed(ledger, "fn-A", "sp_generation")
            completed(ledger, "fn-A", "function_analysis")
            ledger.mark_scan_recorded("fn-A")
            self.assertFalse(ledger.select_function("fn-B"))
            summary = ledger.summary(["fn-A", "fn-B"])
            self.assertEqual(summary["K_observed"], 1)
            self.assertEqual(summary["no_opportunity"]["fn-B"],
                             "NO_OPPORTUNITY_BUDGET")
            self.assertEqual(summary["physical"], 3)  # one unusable remainder
            self.assertEqual(summary["status"], "BUDGET_EXHAUSTED")

    def test_completed_job_then_physical_stop_is_terminal_after_restore(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=5), path)
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            self.assertTrue(ledger.select_function("fn-A"))
            completed(ledger, "fn-A", "sp_generation")
            ledger.mark_scan_recorded("fn-A")
            ledger.mark_no_opportunity("fn-B", "NO_OPPORTUNITY_PHYSICAL_STOP")

            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(restored.function_states["fn-A"], "SCAN_RECORDED")
            self.assertEqual(restored.no_opportunity["fn-B"],
                             "NO_OPPORTUNITY_PHYSICAL_STOP")
            self.assertEqual(restored.summary(["fn-A", "fn-B"])['status'],
                             "INCOMPLETE")
            before = (restored.logical, restored.physical,
                      len(restored.selected_functions))
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.select_function("fn-C")
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.begin_turn("fn-A", "sp_verifier", HASH)
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.register_direction("another-plan")
            self.assertEqual((restored.logical, restored.physical,
                              len(restored.selected_functions)), before)

    def test_budget_no_opportunity_does_not_create_physical_terminal_stop(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=5), path)
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            ledger.mark_no_opportunity("fn-A", "NO_OPPORTUNITY_BUDGET")
            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertTrue(restored.select_function("fn-B"))
            completed(restored, "fn-B", "sp_generation")
            self.assertEqual(restored.physical, 2)

    def test_logical_exhaustion_prevents_selected_but_unstartable_function(self):
        with TemporaryDirectory() as temp:
            cap = DevelopmentBudget(physical_max=3, logical_max=1,
                                    retries_max=0, wall_seconds=60,
                                    initial_starts_required=2)
            ledger = DevelopmentRequestLedger.create(cap,
                                                     Path(temp) / "ledger.json")
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            self.assertFalse(ledger.select_function("fn-A"))
            summary = ledger.summary(["fn-A"])
            self.assertEqual(summary["status"], "BUDGET_EXHAUSTED")
            self.assertEqual(summary["no_opportunity"]["fn-A"],
                             "NO_OPPORTUNITY_BUDGET")
            self.assertEqual(summary["K_observed"], 0)

    def test_unknown_role_rejected_before_transport_or_logical_charge(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(),
                                                     Path(temp) / "ledger.json")
            ledger.register_direction("plan")
            with self.assertRaisesRegex(ValueError, "unregistered model role"):
                ledger.begin_turn("plan", "root_cause_unknown", HASH)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))
            self.assertIsNone(ledger.active_turn)

    def test_eligible_retry_charged_and_changed_request_rejected(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(physical=3),
                                                     Path(temp) / "ledger.json")
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            self.assertEqual(ledger.start_attempt(HASH), 2)
            eligible = ledger.finish_attempt(
                completed=False, error="stream disconnected before completion",
                accepted=True, visible=False, response_saved=False)
            self.assertTrue(eligible)
            with self.assertRaisesRegex(ValueError, "content changed"):
                ledger.start_attempt(OTHER_HASH, retry=True)
            self.assertEqual(ledger.start_attempt(HASH, retry=True), 3)
            ledger.finish_attempt(completed=True)
            self.assertEqual((ledger.logical, ledger.physical, ledger.retries),
                             (2, 3, 1))
            self.assertEqual(ledger.attempts[1]["status"], "ERROR")
            self.assertEqual(ledger.attempts[2]["status"], "COMPLETED")

    def test_visible_output_and_cancellation_have_no_retry(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(physical=3),
                                                     Path(temp) / "ledger.json")
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            self.assertFalse(ledger.finish_attempt(
                completed=False, error="stream disconnected before completion",
                accepted=True, visible=True))
            with self.assertRaisesRegex(ValueError, "retry rejected"):
                ledger.start_attempt(HASH, retry=True)
            ledger.abandon_turn("VISIBLE_PARTIAL_OUTPUT")
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                ledger.begin_turn("fn-A", "function_analysis", HASH)
            second = DevelopmentRequestLedger.create(
                budget(physical=3), Path(temp) / "second.json")
            second.select_function("fn-A")
            second.begin_turn("fn-A", "function_analysis", HASH)
            second.start_attempt(HASH)
            second.abandon_turn("CANCELLED")
            self.assertEqual(second.attempts[-1]["status"],
                             "INTERRUPTED_UNCERTAIN_REMOTE_STATE")
            self.assertEqual(second.retries, 0)
            self.assertEqual(second.function_states["fn-A"],
                             "INCOMPLETE_INTERRUPTED")

    def test_completed_server_product_error_is_durable_incomplete_stop(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=3), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            ledger.attempts[-1].update(
                app_server_turn_id="server-turn-1",
                server_terminal_status="completed",
                product_response_error_type="JSONDecodeError",
                product_response_error_sha256=HASH)
            ledger.finish_attempt(completed=False, error="invalid JSON",
                                  accepted=True, visible=True)
            ledger.abandon_turn("JSONDecodeError",
                                completed_server_product_error=True)
            self.assertEqual(ledger.function_states["fn-A"],
                             "INCOMPLETE_PRODUCT_RESPONSE")
            self.assertEqual(ledger.turns[-1]["status"],
                             "INCOMPLETE_PRODUCT_RESPONSE")
            self.assertEqual(ledger.pending_work[-1]["state"],
                             "INCOMPLETE_PRODUCT_RESPONSE")
            self.assertEqual(ledger.summary(["fn-A"])["status"], "INCOMPLETE")
            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(restored.function_states["fn-A"],
                             "INCOMPLETE_PRODUCT_RESPONSE")
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.begin_turn("fn-A", "function_analysis", HASH)

    def test_forged_completed_server_product_error_is_rejected(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(
                budget(physical=3), Path(temp) / "ledger.json")
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            ledger.finish_attempt(completed=False, error="stream failed",
                                  accepted=True, visible=True)
            with self.assertRaises(ValueError):
                ledger.abandon_turn("JSONDecodeError",
                                    completed_server_product_error=True)
            self.assertIsNotNone(ledger.active_turn)

    def test_restore_between_error_settlement_and_terminal_receipt_stops(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=3), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            ledger.attempts[-1].update(
                app_server_turn_id="server-turn-1",
                server_terminal_status="completed",
                product_response_error_type="JSONDecodeError",
                product_response_error_sha256=HASH)
            ledger.finish_attempt(completed=False, error="invalid JSON",
                                  accepted=True, visible=True)
            # A crash here has no terminal product-error checkpoint yet.
            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(restored.turns[-1]["status"],
                             "INCOMPLETE_INTERRUPTED")
            self.assertEqual(restored.pending_work[-1]["state"],
                             "INCOMPLETE_UNCERTAIN_REMOTE_STATE")
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.begin_turn("fn-A", "function_analysis", HASH)

    def test_restore_never_resends_in_flight_start(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(restored.physical, 1)
            self.assertEqual(restored.attempts[0]["status"],
                             "INTERRUPTED_UNCERTAIN_REMOTE_STATE")
            self.assertEqual(restored.pending_work[0]["state"],
                             "INCOMPLETE_UNCERTAIN_REMOTE_STATE")
            self.assertEqual(restored.function_states["fn-A"],
                             "INCOMPLETE_INTERRUPTED")
            self.assertIsNone(restored.active_turn)
            with self.assertRaisesRegex(ValueError, "physical start rejected"):
                restored.start_attempt(HASH, retry=True)
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.begin_turn("fn-A", "sp_generation", HASH)
            again = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(again.physical, 1)
            self.assertEqual(len(again.pending_work), 1)
            self.assertEqual(again.pending_work[0]["state"],
                             "INCOMPLETE_UNCERTAIN_REMOTE_STATE")

    def test_restore_before_any_physical_start_is_not_budget_pending(self):
        for profile in (None, GLOBAL_ONLY_DEV_PROFILE):
            with self.subTest(profile=profile), TemporaryDirectory() as temp:
                cap = DevelopmentBudget(physical_max=4, logical_max=4,
                                        retries_max=0, wall_seconds=60,
                                        initial_starts_required=1,
                                        **({"profile": profile} if profile else {}))
                path = Path(temp) / "ledger.json"
                ledger = DevelopmentRequestLedger.create(cap, path)
                ledger.select_function("fn-A")
                turn_id = ledger.begin_turn("fn-A", "sp_generation", HASH)
                restored = DevelopmentRequestLedger.restore(path, cap)
                self.assertEqual((restored.logical, restored.physical), (1, 0))
                self.assertEqual(restored.pending_work, [{
                    "id": turn_id, "scope_id": "fn-A", "work_kind": "SCAN",
                    "state": "INCOMPLETE_PRE_SEND_MODEL_TURN",
                    "reason": "INCONCLUSIVE_INTERRUPTED_MODEL_TURN",
                }])
                self.assertEqual(restored.summary(["fn-A"])["status"], "INCOMPLETE")
                self.assertEqual(DevelopmentRequestLedger.restore(path, cap).pending_work,
                                 restored.pending_work)

    def test_legacy_interrupted_pending_is_normalized_on_restore(self):
        for profile in (None, GLOBAL_ONLY_DEV_PROFILE):
            with self.subTest(profile=profile), TemporaryDirectory() as temp:
                path = Path(temp) / "ledger.json"
                cap = DevelopmentBudget(physical_max=5, logical_max=10,
                                        retries_max=1, wall_seconds=60,
                                        initial_starts_required=1,
                                        **({"profile": profile} if profile else {}))
                ledger = DevelopmentRequestLedger.create(cap, path)
                ledger.select_function("fn-A")
                ledger.begin_turn("fn-A", "sp_generation", HASH)
                ledger.start_attempt(HASH)
                ledger.abandon_turn("CANCELLED")
                record = json.loads(path.read_text())
                record["pending_work"][0]["state"] = "PENDING_BUDGET"
                path.write_text(json.dumps(record))
                path.chmod(0o600)
                restored = DevelopmentRequestLedger.restore(path, cap)
                self.assertEqual(restored.pending_work[0]["state"],
                                 "INCOMPLETE_UNCERTAIN_REMOTE_STATE")
                self.assertEqual(json.loads(path.read_text())["pending_work"][0]["state"],
                                 "INCOMPLETE_UNCERTAIN_REMOTE_STATE")

    def test_budget_pending_cannot_relabel_or_duplicate_active_turn(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            ledger.select_function("fn-A")
            ledger.mark_pending("sp-1", "fn-A", "SP_VERIFIER", "NO_BUDGET")
            self.assertEqual(ledger.pending_work[0]["state"], "PENDING_BUDGET")
            with self.assertRaisesRegex(ValueError, "pending work identity"):
                ledger.mark_pending("sp-1", "fn-A", "SP_VERIFIER", "NO_BUDGET")
            turn_id = ledger.begin_turn("fn-A", "sp_generation", HASH)
            with self.assertRaisesRegex(ValueError, "pending work identity"):
                ledger.mark_pending(turn_id, "fn-A", "SCAN", "NO_BUDGET")

    def test_future_turn_id_cannot_be_reserved_or_fail_after_mutation(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            ledger.select_function("fn-A")
            with self.assertRaisesRegex(ValueError, "pending work identity"):
                ledger.mark_pending("L000001", "fn-A", "SP_VERIFIER", "NO_BUDGET")
            self.assertEqual(ledger.pending_work, [])
            # A manually modified in-memory ledger must also reject before
            # begin_turn debits a role or logical count.
            ledger.pending_work.append({"id": "L000001", "scope_id": "fn-A",
                                        "work_kind": "SP_VERIFIER",
                                        "state": "PENDING_BUDGET",
                                        "reason": "FORGED_FUTURE_ID"})
            with self.assertRaisesRegex(ValueError, "turn identity"):
                ledger.begin_turn("fn-A", "sp_generation", HASH)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))
            self.assertEqual(ledger.function_counts["fn-A"], {})
            self.assertIsNone(ledger.active_turn)

    def test_two_owners_cannot_both_debit_same_physical_start(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            first = DevelopmentRequestLedger.create(budget(physical=4), path)
            first.select_function("fn-A")
            first.begin_turn("fn-A", "sp_generation", HASH)
            second = deepcopy(first)
            self.assertEqual(first.start_attempt(HASH), 1)
            with self.assertRaisesRegex(ValueError, "checkpoint.*changed"):
                second.start_attempt(HASH)
            self.assertTrue(second.tainted)
            saved = json.loads(path.read_text())
            self.assertEqual(saved["physical"], 1)
            self.assertEqual(len(saved["attempts"]), 1)
            with self.assertRaisesRegex(ValueError, "physical start rejected"):
                second.start_attempt(HASH)

    def test_racing_owners_have_exactly_one_durable_start(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            owner = DevelopmentRequestLedger.create(budget(physical=4), path)
            owner.select_function("fn-A")
            owner.begin_turn("fn-A", "sp_generation", HASH)
            owners = [deepcopy(owner), deepcopy(owner)]
            ready = Barrier(2)

            def start(ledger: DevelopmentRequestLedger) -> str:
                ready.wait(timeout=5)
                try:
                    return f"STARTED:{ledger.start_attempt(HASH)}"
                except ValueError:
                    self.assertTrue(ledger.tainted)
                    return "STALE_REJECTED"

            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(start, owners))
            self.assertCountEqual(results, ["STARTED:1", "STALE_REJECTED"])
            saved = json.loads(path.read_text())
            self.assertEqual(saved["physical"], 1)
            self.assertEqual(len(saved["attempts"]), 1)

    def test_restore_rejects_symlinked_parent_before_loading(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            cap = budget()
            DevelopmentRequestLedger.create(cap, real / "ledger.json")
            with self.assertRaisesRegex(ValueError, "linked"):
                DevelopmentRequestLedger.restore(alias / "ledger.json", cap)

    def test_checkpoint_hardlink_alias_and_noncanonical_paths_are_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            cap = budget(physical=1, logical=1)
            ledger = DevelopmentRequestLedger.create(cap, root / "ledger.json")
            alias = root / "alias.json"
            os.link(root / "ledger.json", alias)
            with self.assertRaisesRegex(ValueError, "hardlink|linked"):
                DevelopmentRequestLedger.restore(alias, cap)
            with self.assertRaisesRegex(ValueError, "hardlink|linked"):
                ledger.checkpoint()
            self.assertTrue(ledger.tainted)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sub").mkdir()
            noncanonical = root / "sub" / ".." / "ledger.json"
            with self.assertRaisesRegex(ValueError, "canonical"):
                DevelopmentRequestLedger.create(budget(), noncanonical)
            relative = Path(os.path.relpath(root / "relative.json", Path.cwd()))
            with self.assertRaisesRegex(ValueError, "absolute"):
                DevelopmentRequestLedger.create(budget(), relative)

    def test_terminal_model_turn_blocks_changed_hash_and_other_function(self):
        for physical_start in (False, True):
            with self.subTest(physical_start=physical_start), TemporaryDirectory() as temp:
                path = Path(temp) / "ledger.json"
                ledger = DevelopmentRequestLedger.create(budget(physical=8), path)
                ledger.select_function("fn-A")
                ledger.begin_turn("fn-A", "sp_generation", HASH)
                if physical_start:
                    ledger.start_attempt(HASH)
                restored = DevelopmentRequestLedger.restore(path, ledger.budget)
                self.assertEqual(restored.pending_work[0]["state"],
                                 ("INCOMPLETE_UNCERTAIN_REMOTE_STATE" if physical_start
                                  else "INCOMPLETE_PRE_SEND_MODEL_TURN"))
                with self.assertRaisesRegex(ValueError, "terminal model turn"):
                    restored.register_direction("another-plan")
                with self.assertRaisesRegex(ValueError, "terminal model turn"):
                    restored.select_function("fn-B")
                with self.assertRaisesRegex(ValueError, "terminal model turn"):
                    restored.begin_turn("fn-A", "function_analysis", OTHER_HASH)
                with self.assertRaisesRegex(ValueError, "terminal model turn"):
                    restored.begin_turn("fn-A", "sp_generation", HASH)
                self.assertEqual((restored.logical, restored.physical),
                                 (1, int(physical_start)))

    def test_pool_selection_exhausted_with_pending_is_not_workflow_complete(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(),
                                                     Path(temp) / "ledger.json")
            ledger.select_function("fn-A")
            ledger.mark_scan_recorded("fn-A")
            ledger.mark_pending("sp-1", "fn-A", "SP_VERIFIER", "NO_BUDGET")
            self.assertEqual(ledger.summary(["fn-A"])["status"],
                             "POOL_SELECTION_EXHAUSTED_PENDING_WORK")
            self.assertEqual(ledger.summary(["fn-A"])["pending_work"][0]["state"],
                             "PENDING_BUDGET")

    def test_contract_mismatch_and_counter_tamper_rejected_on_restore(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            with self.assertRaisesRegex(ValueError, "contract changed"):
                DevelopmentRequestLedger.restore(path, budget(physical=6))
            record = json.loads(path.read_text())
            record["physical"] = 1
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "checkpoint counters"):
                DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_active_attempt_count_tamper_cannot_hide_a_physical_start(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            record = json.loads(path.read_text())
            record["active_turn"]["attempts"] = 0
            path.write_text(json.dumps(record))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "active turn disagrees"):
                DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_role_relabel_with_same_total_cannot_reopen_sp_cap(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=6), path)
            ledger.select_function("fn-A")
            for _ in range(4):
                completed(ledger, "fn-A", "sp_generation")
            record = json.loads(path.read_text())
            # Preserve the logical total and all individual HP caps; this
            # formerly let a fifth SP request start after restore.
            record["function_counts"]["fn-A"] = {
                "function_analysis": 3, "assertion_generator": 1}
            path.write_text(json.dumps(record))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "role history|role count"):
                DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_no_direction_turn_cannot_claim_workflow_complete(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(),
                                                     Path(temp) / "ledger.json")
            ledger.register_direction("plan")
            ledger.select_function("fn-A")
            ledger.mark_scan_recorded("fn-A")
            self.assertEqual(ledger.summary(["fn-A"])["status"],
                             "DIRECTION_NOT_ACCOUNTED")

    def test_completed_accounting_still_awaits_external_evidence(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(),
                                                     Path(temp) / "ledger.json")
            ledger.register_direction("plan")
            completed(ledger, "plan", "direction_generator")
            ledger.select_function("fn-A")
            completed(ledger, "fn-A", "sp_generation")
            ledger.mark_scan_recorded("fn-A")
            self.assertEqual(ledger.summary(["fn-A"])["status"],
                             "ACCOUNTING_COMPLETE_AWAITING_EVIDENCE")

    def test_zero_attempt_abandon_is_durable_and_consumes_role_cap(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=8), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.abandon_turn("CANCELLED_BEFORE_SEND")
            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(restored.turns[0]["status"],
                             "INCOMPLETE_INTERRUPTED")
            self.assertEqual(restored.function_counts["fn-A"]["sp_generation"], 1)
            self.assertEqual(restored.physical, 0)
            with self.assertRaisesRegex(ValueError, "terminal model turn"):
                restored.begin_turn("fn-A", "sp_generation", HASH)
            self.assertEqual(restored.function_counts["fn-A"]["sp_generation"], 1)

    def test_legacy_checkpoint_schema_is_not_silently_inferred(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            record = json.loads(path.read_text())
            record["kind"] = "DEV_GLOBAL_REQUEST_LEDGER_V1"
            record.pop("turns")
            path.write_text(json.dumps(record))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "contract changed"):
                DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_attempt_identity_and_retry_chain_must_match_turn_history(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=4), path)
            ledger.select_function("fn-A")
            completed(ledger, "fn-A", "sp_generation")
            original = json.loads(path.read_text())
            for field, value in (("role", "function_analysis"),
                                 ("request_hash", OTHER_HASH),
                                 ("retry", True)):
                with self.subTest(field=field):
                    record = json.loads(json.dumps(original))
                    record["attempts"][0][field] = value
                    if field == "retry":
                        record["retries"] = 1
                    path.write_text(json.dumps(record))
                    path.chmod(0o600)
                    with self.assertRaises(ValueError):
                        DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_second_non_retry_attempt_cannot_be_restored(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(physical=4), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            ledger.finish_attempt(completed=False, error="non-retryable")
            record = json.loads(path.read_text())
            second = dict(record["attempts"][0])
            second["physical"] = 2
            second["status"] = "COMPLETED"
            second["retry"] = False
            record["attempts"].append(second)
            record["physical"] = 2
            record["active_turn"]["attempts"] = 2
            path.write_text(json.dumps(record))
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_forged_retry_eligibility_does_not_survive_restore(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            self.assertFalse(ledger.finish_attempt(
                completed=False, error="stream disconnected before completion",
                accepted=True, visible=True))
            record = json.loads(path.read_text())
            record["attempts"][0]["retry_eligible"] = True
            path.write_text(json.dumps(record))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "retry eligibility"):
                DevelopmentRequestLedger.restore(path, ledger.budget)

    def test_incomplete_function_cannot_be_overwritten_as_scan_recorded(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(budget(),
                                                     Path(temp) / "ledger.json")
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            ledger.start_attempt(HASH)
            ledger.abandon_turn("CANCELLED")
            self.assertEqual(ledger.function_states["fn-A"],
                             "INCOMPLETE_INTERRUPTED")
            with self.assertRaisesRegex(ValueError, "incomplete|not eligible"):
                ledger.mark_scan_recorded("fn-A")
            self.assertEqual(ledger.function_states["fn-A"],
                             "INCOMPLETE_INTERRUPTED")

    def test_failed_durable_checkpoint_taints_ledger_before_transport(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            ledger = DevelopmentRequestLedger.create(budget(), path)
            ledger.select_function("fn-A")
            ledger.begin_turn("fn-A", "sp_generation", HASH)
            with patch("dev_global_request_ledger.os.replace",
                       side_effect=OSError("synthetic disk failure")):
                with self.assertRaisesRegex(OSError, "synthetic disk failure"):
                    ledger.start_attempt(HASH)
            self.assertTrue(ledger.tainted)
            self.assertEqual(json.loads(path.read_text())["physical"], 0)
            with self.assertRaisesRegex(ValueError, "physical start rejected"):
                ledger.start_attempt(HASH)

    def test_wall_cap_and_role_cap_are_distinct(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(
                budget(physical=6), Path(temp) / "wall.json", started_at=100.0)
            with self.assertRaisesRegex(ValueError, "wall limit"):
                ledger.wall(now=160.0)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=6), Path(temp) / "roles.json")
            ledger.select_function("fn-A")
            for _ in range(4):
                completed(ledger, "fn-A", "sp_generation")
            with self.assertRaisesRegex(ValueError, "role limit"):
                ledger.begin_turn("fn-A", "sp_generation", HASH)

    def test_invalid_budget_values_rejected(self):
        with self.assertRaises(ValueError):
            budget(physical=0)
        with self.assertRaises(ValueError):
            budget(physical=1, initial=2)
        with self.assertRaises(ValueError):
            DevelopmentBudget(physical_max=2, logical_max=1, retries_max=0,
                              wall_seconds=float("inf"), initial_starts_required=1)

    def test_empty_pool_does_not_claim_completed_analysis(self):
        with TemporaryDirectory() as temp:
            ledger = DevelopmentRequestLedger.create(
                budget(), Path(temp) / "ledger.json")
            self.assertEqual(ledger.summary([])["status"], "POOL_EMPTY")


if __name__ == "__main__":
    unittest.main()
