"""Provider-free public three-function K-free accounting gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev_global_request_ledger import (DevelopmentBudget,
                                       DevelopmentBudgetExhausted,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)
from dev_no_k_three_function_gate import (make_public_fixture,
                                          run_public_three_function_gate,
                                          selection_only_order)

PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests')]
from vulnerabilityanalysis.workflow import run_phase1, continue_phase1


class NoKThreeFunctionGateTests(unittest.TestCase):
    def test_product_first_pass_order_and_global_stop_are_distinct_evidence(self):
        with TemporaryDirectory() as temp:
            receipt_path = run_public_three_function_gate(Path(temp))
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(receipt['selection_only_order'],
                             ['fn-a', 'fn-c', 'fn-b'])
            self.assertEqual(receipt['actual_model_transports'], 0)
            self.assertEqual(receipt['product_scans_completed'], 0)
            self.assertEqual(receipt['simulated_debits'], [
                {'scope_id': 'public-direction-plan', 'role': 'direction_generator',
                 'physical': 1},
                {'scope_id': 'fn-a', 'role': 'sp_generation', 'physical': 2},
                {'scope_id': 'fn-a', 'role': 'function_analysis', 'physical': 3},
            ])
            summary = receipt['ledger_summary']
            self.assertEqual(summary['status'], 'BUDGET_EXHAUSTED')
            self.assertEqual(summary['K_observed'], 1)
            self.assertEqual(summary['selected_functions'], ['fn-a'])
            self.assertEqual(summary['no_opportunity'], {
                'fn-c': 'NO_OPPORTUNITY_BUDGET',
                'fn-b': 'NO_OPPORTUNITY_BUDGET',
            })
            self.assertEqual(summary['pending_work'], [{
                'id': 'public-sp-a-verifier', 'scope_id': 'fn-a',
                'work_kind': 'SP_VERIFIER', 'state': 'PENDING_BUDGET',
                'reason': 'GLOBAL_MODEL_BUDGET_EXHAUSTED',
            }])
            self.assertEqual(summary['physical'], 3)
            self.assertEqual(summary['logical'], 3)
            self.assertEqual(summary['function_states']['fn-a'],
                             'SELECTED_NOT_STARTED')

    def test_restored_checkpoint_rejects_changed_contract_or_attempt(self):
        with TemporaryDirectory() as temp:
            receipt_path = run_public_three_function_gate(Path(temp))
            receipt = json.loads(receipt_path.read_text())
            checkpoint = Path(receipt['ledger_checkpoint'])
            budget = DevelopmentBudget(
                physical_max=3, logical_max=3, retries_max=0,
                wall_seconds=60, initial_starts_required=2,
                profile=GLOBAL_ONLY_DEV_PROFILE)
            restored = DevelopmentRequestLedger.restore(checkpoint, budget)
            self.assertEqual(restored.summary(receipt['selection_only_order']),
                             receipt['ledger_summary'])
            changed = DevelopmentBudget(
                physical_max=4, logical_max=3, retries_max=0,
                wall_seconds=60, initial_starts_required=2,
                profile=GLOBAL_ONLY_DEV_PROFILE)
            with self.assertRaisesRegex(ValueError, 'contract changed'):
                DevelopmentRequestLedger.restore(checkpoint, changed)
            saved = json.loads(checkpoint.read_text())
            saved['attempts'][0]['request_hash'] = 'f' * 64
            checkpoint.write_text(json.dumps(saved) + '\n')
            with self.assertRaisesRegex(ValueError, 'physical attempt chain'):
                DevelopmentRequestLedger.restore(checkpoint, budget)

    def test_product_continuation_rejects_changed_direction_plan(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo, plan = make_public_fixture(root)
            self.assertEqual(selection_only_order(artifact, repo, plan,
                                                  root / 'dry'),
                             ['fn-a', 'fn-c', 'fn-b'])
            run = run_phase1(artifact, repo / 'tampered_runs',
                             target_repository=repo, direction_plan=plan,
                             selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            selected = json.loads((run / 'selection.json').read_text())
            (run / 'scan.json').write_text(json.dumps({
                'selected_function': selected['function_name'],
                'selected_function_id': selected['function_id'],
                'target_repository': str(repo),
                'synthetic_identity_only': True,
            }))
            (run / 'direction_plan.json').write_bytes(b'{"changed":true}')
            with self.assertRaisesRegex(ValueError, 'Direction plan.*SHA-256'):
                continue_phase1(run)

    def test_wall_limit_blocks_new_attempt_without_extra_physical_debit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(DevelopmentBudget(
                physical_max=4, logical_max=4, retries_max=0,
                wall_seconds=10, initial_starts_required=2,
                profile=GLOBAL_ONLY_DEV_PROFILE), root / 'ledger.json',
                started_at=time.time())
            ledger.register_direction('plan')
            digest = hashlib.sha256(b'direction').hexdigest()
            ledger.begin_turn('plan', 'direction_generator', digest)
            ledger.start_attempt(digest)
            ledger.finish_attempt(completed=True)
            self.assertTrue(ledger.select_function('fn-a'))
            sp_hash = hashlib.sha256(b'first-sp').hexdigest()
            ledger.begin_turn('fn-a', 'sp_generation', sp_hash)
            before = ledger.physical
            with patch('dev_global_request_ledger.time.time',
                       return_value=ledger.started_at + 10):
                with self.assertRaisesRegex(DevelopmentBudgetExhausted,
                                            'wall limit'):
                    ledger.start_attempt(sp_hash)
            self.assertEqual(ledger.physical, before)
            ledger.abandon_turn('WALL_LIMIT_BEFORE_PHYSICAL_START',
                                budget_exhausted=True)
            self.assertEqual(ledger.pending_work[0]['state'],
                             'INCOMPLETE_PRE_SEND_MODEL_TURN')
            self.assertEqual(ledger.function_states['fn-a'], 'INCOMPLETE_BUDGET')


if __name__ == '__main__':
    unittest.main()
