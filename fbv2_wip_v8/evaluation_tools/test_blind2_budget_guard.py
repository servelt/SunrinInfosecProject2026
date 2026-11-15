"""The evaluator must allow legitimate post-Assertion HP work."""
import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from blind2_budget_guard import Blind2Ledger


def turn(ledger, role):
    request_hash = 'a' * 64
    ledger.begin_turn('fn', role, request_hash)
    ledger.start_attempt(request_hash)
    ledger.finish_attempt(completed=True)


class LaterHpAccountingTests(unittest.TestCase):
    def test_hp_refinement_after_sp_does_not_invalidate_no_transfer_snapshot(self):
        with TemporaryDirectory() as temp:
            run = Path(temp)
            (run / 'sp').mkdir()
            ledger = Blind2Ledger(time.time())
            ledger.select('fn')
            ledger.bind_run('fn', run)
            turn(ledger, 'sp_generation')
            turn(ledger, 'function_analysis')
            turn(ledger, 'assertion_generator')
            (run / 'sp' / 'turn_budget.json').write_text(json.dumps({
                'function_id': 'fn', 'original_sp_limit': 4,
                'original_hp_limit': 4, 'hp_calls_before_transfer': 2,
                'safe_assumption_count': 1, 'assertion_proposal_count': 1,
                'checkable_assertion_count': 1,
                'assertion_generation_status': 'COMPLETED',
                'effective_sp_limit': 4, 'transferred_hp_calls': 0,
                'combined_limit': 8, 'reason': 'HP_ASSERTION_PATH',
            }))
            turn(ledger, 'sp_verifier')
            turn(ledger, 'function_analysis')
            ledger.validate_scan('fn', {
                'selected_function_id': 'fn', 'sp_llm_calls': 2,
                'hp_llm_calls': 3, 'effective_sp_llm_call_limit': 4,
                'combined_llm_call_limit': 8,
            })

    def test_transferred_hp_turn_cannot_be_spent_again(self):
        with TemporaryDirectory() as temp:
            run = Path(temp)
            (run / 'sp').mkdir()
            ledger = Blind2Ledger(time.time())
            ledger.select('fn')
            ledger.bind_run('fn', run)
            turn(ledger, 'function_analysis')
            (run / 'sp' / 'turn_budget.json').write_text(json.dumps({
                'function_id': 'fn', 'original_sp_limit': 4,
                'original_hp_limit': 4, 'hp_calls_before_transfer': 1,
                'safe_assumption_count': 0, 'assertion_proposal_count': 0,
                'checkable_assertion_count': 0,
                'assertion_generation_status': 'NO_SAFE',
                'effective_sp_limit': 7, 'transferred_hp_calls': 3,
                'combined_limit': 8, 'reason': 'HP_NO_ASSERTION_UNUSED_CALLS',
            }))
            with self.assertRaisesRegex(ValueError, 'logical turn limit'):
                ledger.begin_turn('fn', 'function_analysis', 'a' * 64)


if __name__ == '__main__':
    unittest.main()
