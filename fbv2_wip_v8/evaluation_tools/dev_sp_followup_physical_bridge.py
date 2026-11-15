"""Development-only physical ledger callback for failed-PoV SP followups.

Pass an instance as ``run_failed_pov_followups(..., fuzzer_call=callback)``.
The existing runner's logical meter remains separate. This callback admits
one pinned libFuzzer mutation through a durable physical ledger; it does not
authorize Blind 3 or establish a frozen campaign-wide budget.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
from dev_product_fuzz_physical_adapter import (
    PhysicalFuzzLedgerStop, ProductFuzzPhysicalRunner)
from vulnerabilityanalysis import runtime, scan


def _fatal(message: str) -> PhysicalFuzzLedgerStop:
    return PhysicalFuzzLedgerStop('STOPPED_PHYSICAL_LEDGER_ERROR', message)


def _canonical(path: Path) -> bool:
    return (isinstance(path, Path) and path.is_absolute() and
            '..' not in path.parts and path.resolve(strict=False) == path)


def _sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class DevSpFollowupPhysicalCall:
    """Pin one SP's binary, corpus, role, and physical budget before mutation."""

    def __init__(self, *, physical_runner: ProductFuzzPhysicalRunner,
                 contract_ledger_path: Path, contract_total_seconds: float,
                 expected_run: Path, expected_binary: Path,
                 expected_binary_sha256: str, expected_sp_id: str,
                 fuzz_seconds: int):
        if (type(physical_runner) is not ProductFuzzPhysicalRunner or
                physical_runner.kind != 'SP' or
                type(physical_runner.ledger) is not PersistentPhysicalFuzzLedger or
                not _canonical(contract_ledger_path) or
                not _canonical(expected_run) or
                not _canonical(expected_binary) or
                type(contract_total_seconds) not in (int, float) or
                not math.isfinite(contract_total_seconds) or
                contract_total_seconds <= 0 or
                type(expected_binary_sha256) is not str or
                len(expected_binary_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in expected_binary_sha256) or
                type(expected_sp_id) is not str or not expected_sp_id or
                '/' in expected_sp_id or expected_sp_id in {'.', '..'} or
                type(fuzz_seconds) is not int or fuzz_seconds not in {1, 2}):
            raise _fatal('invalid development SP followup physical pins')
        self.physical_runner = physical_runner
        self.contract_ledger_path = contract_ledger_path
        self.contract_total_seconds = float(contract_total_seconds)
        self.expected_run = expected_run
        self.expected_binary = expected_binary
        self.expected_binary_sha256 = expected_binary_sha256
        self.expected_sp_id = expected_sp_id
        self.fuzz_seconds = fuzz_seconds
        self.expected_corpus = (expected_run / 'corpus' / 'candidate' /
                                expected_sp_id)
        self.guarded_invocations = 0
        self._preflight(require_corpus=False)

    def _preflight(self, *, require_corpus: bool) -> dict[str, Any]:
        ledger = self.physical_runner.ledger
        if (ledger.path != self.contract_ledger_path or
                ledger.lock_path != self.contract_ledger_path.with_name(
                    self.contract_ledger_path.name + '.lock') or
                not _canonical(self.expected_run) or
                not _canonical(self.expected_binary) or
                not _canonical(self.expected_corpus) or
                not self.expected_binary.is_file() or
                self.expected_binary.is_symlink() or
                require_corpus and (not self.expected_corpus.is_dir() or
                                    self.expected_corpus.is_symlink())):
            raise _fatal('development SP followup pins changed')
        try:
            if _sha256(self.expected_binary) != self.expected_binary_sha256:
                raise _fatal('development SP followup binary pin changed')
        except OSError as exc:
            raise _fatal('development SP followup binary became unreadable') from exc
        try:
            ledger._verify_checkpoint_current()
            state = ledger.snapshot()
        except (OSError, RuntimeError, ValueError) as exc:
            raise _fatal('development SP physical checkpoint is untrusted') from exc
        if (state['total_seconds'] != self.contract_total_seconds or
                state['stop_status'] is not None or state['active']):
            raise _fatal('development SP physical ledger contract or state changed')
        return state

    def __call__(self, point: Any, binary: Path, run: Path,
                 retry_ledger: Any, evidence_ids: list[str], *,
                 seconds: int) -> Any:
        if (getattr(point, 'sp_id', None) != self.expected_sp_id or
                not isinstance(binary, Path) or binary != self.expected_binary or
                not isinstance(run, Path) or run != self.expected_run or
                type(seconds) is not int or seconds < 1):
            raise _fatal('development SP followup target or meter changed')
        state = self._preflight(require_corpus=True)
        if seconds < self.fuzz_seconds:
            return {'status': 'PENDING_PHYSICAL_FUZZ_BUDGET',
                    'reason': 'logical meter granted less than pinned physical run',
                    'physical_started': False}
        reserved = (self.fuzz_seconds + 15 +
                    self.physical_runner.cleanup_envelope_seconds)
        if state['available_seconds'] < reserved:
            return {'status': 'PENDING_PHYSICAL_FUZZ_BUDGET',
                    'reason': 'no physical reservation before launch',
                    'physical_started': False}

        # The formal runner owns this fixed max_len through
        # SharedFuzzMeter.patch_guided; changing it is a new run.
        expected_argv = [str(self.expected_binary), str(self.expected_corpus),
                         f'-max_total_time={self.fuzz_seconds}',
                         '-max_len=8388608', '-print_final_stats=1']

        def guarded(argv: list[str], *, cwd: Path,
                    timeout: float) -> Any:
            if (argv != expected_argv or cwd != self.expected_corpus or
                    timeout != self.fuzz_seconds + 15):
                raise _fatal('development SP libFuzzer argv or cwd changed')
            self._preflight(require_corpus=True)
            self.guarded_invocations += 1
            return self.physical_runner(argv, cwd=cwd, timeout=timeout)

        try:
            return scan.run_targeted_fuzz(
                point, binary, run, retry_ledger, evidence_ids,
                seconds=self.fuzz_seconds, guarded_runner=guarded)
        except runtime.PhysicalFuzzBudgetPending:
            return {'status': 'PENDING_PHYSICAL_FUZZ_BUDGET',
                    'reason': 'physical reservation was refused before launch',
                    'physical_started': False}
