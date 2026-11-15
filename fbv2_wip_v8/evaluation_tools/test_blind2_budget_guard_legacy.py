"""Model-free tests for the future blind evaluator's transferred-turn guard."""
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest

from blind2_budget_guard import Blind2Ledger


def turn(ledger, role):
    digest = 'a' * 64
    ledger.begin_turn('fn', role, digest)
    ledger.start_attempt(digest)
    ledger.finish_attempt(completed=True)


class Blind2BudgetGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name)
        (self.run / 'sp').mkdir()
        self.ledger = Blind2Ledger(time.time())
        self.ledger.select('fn')
        self.ledger.bind_run('fn', self.run)

    def transfer(self, *, hp_used=3, safe_count=0, assertion_count=0,
                 checkable_count=None,
                 assertion_status=None, effective=5):
        if checkable_count is None:
            checkable_count = assertion_count
        if assertion_status is None:
            assertion_status = 'COMPLETED' if safe_count else 'NO_SAFE'
        (self.run / 'sp' / 'turn_budget.json').write_text(json.dumps({
            'function_id': 'fn', 'original_sp_limit': 4, 'original_hp_limit': 4,
            'hp_calls_before_transfer': hp_used,
            'safe_assumption_count': safe_count,
            'assertion_proposal_count': assertion_count,
            'checkable_assertion_count': checkable_count,
            'assertion_generation_status': assertion_status,
            'effective_sp_limit': effective,
            'transferred_hp_calls': effective - 4,
            'combined_limit': 8,
            'reason': 'HP_NO_ASSERTION_UNUSED_CALLS' if effective > 4 else 'HP_ASSERTION_PATH'}))

    def test_fifth_sp_turn_requires_recorded_safe_free_transfer(self):
        turn(self.ledger, 'sp_generation')
        for _ in range(3):
            turn(self.ledger, 'function_analysis')
        for _ in range(3):
            turn(self.ledger, 'sp_verifier')
        with self.assertRaisesRegex(ValueError, 'logical turn limit'):
            self.ledger.begin_turn('fn', 'poc_generator', 'a' * 64)
        self.transfer()
        turn(self.ledger, 'poc_generator')
        self.assertEqual(self.ledger.counts['fn']['poc_generator'], 1)
        self.ledger.validate_scan('fn', {
            'selected_function_id': 'fn', 'sp_llm_calls': 5,
            'hp_llm_calls': 3, 'effective_sp_llm_call_limit': 5,
            'combined_llm_call_limit': 8})

    def test_safe_or_extra_ninth_turn_is_rejected(self):
        turn(self.ledger, 'sp_generation')
        for _ in range(3):
            turn(self.ledger, 'function_analysis')
        for _ in range(3):
            turn(self.ledger, 'sp_verifier')
        self.transfer(safe_count=1, assertion_count=1)
        with self.assertRaisesRegex(ValueError, 'invalid product turn-budget'):
            self.ledger.begin_turn('fn', 'poc_generator', 'a' * 64)
        self.transfer()
        turn(self.ledger, 'poc_generator')
        with self.assertRaisesRegex(ValueError, 'logical turn limit'):
            self.ledger.begin_turn('fn', 'poc_generator', 'a' * 64)

    def test_budget_record_cannot_claim_unspent_hp_calls(self):
        turn(self.ledger, 'function_analysis')
        self.transfer(hp_used=3)
        with self.assertRaisesRegex(ValueError, 'invalid product turn-budget'):
            self.ledger.begin_turn('fn', 'sp_verifier', 'a' * 64)

    def test_safe_with_zero_assertions_can_transfer_after_generator_finishes(self):
        turn(self.ledger, 'sp_generation')
        for _ in range(2):
            turn(self.ledger, 'function_analysis')
        turn(self.ledger, 'assertion_generator')
        for _ in range(3):
            turn(self.ledger, 'sp_verifier')
        self.transfer(safe_count=3, assertion_count=0)
        turn(self.ledger, 'poc_generator')
        self.assertEqual(self.ledger.counts['fn']['poc_generator'], 1)

    def test_safe_with_unfinished_assertion_generation_cannot_transfer(self):
        turn(self.ledger, 'sp_generation')
        for _ in range(3):
            turn(self.ledger, 'function_analysis')
        for _ in range(3):
            turn(self.ledger, 'sp_verifier')
        self.transfer(safe_count=3, assertion_status='PENDING_HP_BUDGET')
        with self.assertRaisesRegex(ValueError, 'invalid product turn-budget'):
            self.ledger.begin_turn('fn', 'poc_generator', 'a' * 64)

    def test_invalid_proposal_does_not_block_recorded_transfer(self):
        turn(self.ledger, 'sp_generation')
        for _ in range(2):
            turn(self.ledger, 'function_analysis')
        turn(self.ledger, 'assertion_generator')
        for _ in range(3):
            turn(self.ledger, 'sp_verifier')
        self.transfer(safe_count=1, assertion_count=1, checkable_count=0)
        turn(self.ledger, 'poc_generator')


if __name__ == '__main__':
    unittest.main()
