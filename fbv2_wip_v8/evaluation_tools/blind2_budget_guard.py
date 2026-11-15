"""Turn accounting for a future blind runner; the frozen first runner is unchanged.

The product writes sp/turn_budget.json after HP completes and before it can
make an SP request above the original four-turn cap.  A future evaluator must
bind each selected run with ``bind_run`` before entering scan_selected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from blind_runner_guards import (HP_ANALYSIS_MAX, HP_ASSERT_MAX, HP_ROLES,
                                 LOGICAL_MAX, PHYSICAL_MAX, SP_ROLES, Ledger)


@dataclass
class Blind2Ledger(Ledger):
    run_paths: dict[str, str] = field(default_factory=dict)

    def bind_run(self, function_id: str, run: Path) -> None:
        if function_id not in self.counts or function_id in self.run_paths:
            raise ValueError('selected function must bind exactly one run')
        self.run_paths[function_id] = str(run.resolve())

    def _effective_sp_cap(self, function_id: str) -> int:
        run = self.run_paths.get(function_id)
        if run is None:
            raise ValueError('selected function has no bound run')
        path = Path(run) / 'sp' / 'turn_budget.json'
        if not path.is_file():
            return 4
        row = json.loads(path.read_text())
        counts = self.counts[function_id]
        hp_used = sum(counts.get(role, 0) for role in HP_ROLES)
        original_sp = row.get('original_sp_limit')
        original_hp = row.get('original_hp_limit')
        effective = row.get('effective_sp_limit')
        transfer = row.get('transferred_hp_calls')
        safe_count = row.get('safe_assumption_count')
        assertion_count = row.get('assertion_proposal_count')
        checkable_count = row.get('checkable_assertion_count')
        assertion_status = row.get('assertion_generation_status')
        hp_at_transfer = row.get('hp_calls_before_transfer')
        if (row.get('function_id') != function_id or original_sp != 4 or
                original_hp != 4 or row.get('combined_limit') != 8 or
                not isinstance(hp_at_transfer, int) or isinstance(hp_at_transfer, bool) or
                not 0 <= hp_at_transfer <= hp_used <= 4 or
                not isinstance(effective, int) or isinstance(effective, bool) or
                not isinstance(transfer, int) or isinstance(transfer, bool) or
                (transfer > 0 and hp_at_transfer != hp_used) or
                not isinstance(safe_count, int) or isinstance(safe_count, bool) or
                not isinstance(assertion_count, int) or isinstance(assertion_count, bool) or
                not isinstance(checkable_count, int) or isinstance(checkable_count, bool) or
                safe_count < 0 or assertion_count < 0 or
                not 0 <= checkable_count <= assertion_count or effective != 4 + transfer or
                not 0 <= transfer <= 4 - hp_at_transfer or
                not 4 <= effective <= 8 - hp_used or
                (transfer > 0 and (checkable_count != 0 or
                 row.get('reason') != 'HP_NO_ASSERTION_UNUSED_CALLS' or
                 (safe_count == 0 and assertion_status != 'NO_SAFE') or
                 (safe_count > 0 and assertion_status != 'COMPLETED')))):
            raise ValueError('invalid product turn-budget record')
        return effective

    def begin_turn(self, function_id: str, role: str, request_hash: str) -> str:
        self.wall()
        if self.active_turn or self.active_fuzz or function_id not in self.counts:
            raise ValueError('turn outside selected idle function')
        if role not in SP_ROLES | HP_ROLES or len(request_hash) != 64:
            raise ValueError('unapproved role or unpinned request')
        counts = self.counts[function_id]
        sp = sum(counts.get(r, 0) for r in SP_ROLES)
        hp = sum(counts.get(r, 0) for r in HP_ROLES)
        cap = self._effective_sp_cap(function_id)
        if (self.logical >= LOGICAL_MAX or self.physical >= PHYSICAL_MAX or
                sp + hp >= 8 or
                role in SP_ROLES and sp >= cap or
                role in HP_ROLES and cap > 4 or
                role == 'function_analysis' and counts.get(role, 0) >= HP_ANALYSIS_MAX or
                role == 'assertion_generator' and counts.get(role, 0) >= HP_ASSERT_MAX):
            raise ValueError('logical turn limit reached')
        self.logical += 1
        counts[role] = counts.get(role, 0) + 1
        turn_id = f'L{self.logical:03d}'
        self.active_turn = {'id': turn_id, 'function_id': function_id,
                            'role': role, 'hash': request_hash, 'attempts': 0}
        return turn_id

    def validate_scan(self, function_id: str, scan: dict) -> None:
        counts = self.counts[function_id]
        sp = sum(counts.get(role, 0) for role in SP_ROLES)
        hp = sum(counts.get(role, 0) for role in HP_ROLES)
        if (scan.get('selected_function_id') != function_id or
                scan.get('sp_llm_calls') != sp or scan.get('hp_llm_calls') != hp or
                scan.get('effective_sp_llm_call_limit') != self._effective_sp_cap(function_id) or
                scan.get('combined_llm_call_limit') != 8 or sp + hp > 8):
            raise ValueError('product scan and evaluator turn accounting differ')
