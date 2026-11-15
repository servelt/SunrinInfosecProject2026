"""Provider-free, development-only four-phase campaign accounting shell.

This joins pinned Phase 1 work items to one durable global model ledger. It
never contacts a model or runs a Target, Assertion, or Fuzzer. Its scripted
SP Generator returns no candidates. The saved Direction plan and caller's
official-qualification object are development inputs, not a Blind 3 Freeze.
Physical SP/HP/Global fuzz receipts are deliberately outside this shell.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from dev_four_phase_budget_progress import freeze_pending_budget
from dev_global_appserver_bridge import request_hash
from dev_global_request_ledger import (DevelopmentBudgetExhausted,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)
from dev_persistent_physical_fuzz_ledger import (PersistentPhysicalFuzzLedger,
                                                 PhysicalModelStartBlocked)
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import (continue_four_phase_dev,
                                             start_four_phase_dev,
                                             validate_four_phase_dev_selection)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'missing or linked development evidence: {path}')
    row = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(row, dict):
        raise ValueError(f'development evidence is not an object: {path}')
    return row


def _write_private(path: Path, row: dict) -> None:
    """Replace a progress checkpoint after fsync; reject unsafe prior files."""
    if path.is_symlink() or (path.exists() and (
            not path.is_file() or path.stat().st_nlink != 1 or
            path.stat().st_mode & 0o777 != 0o600)):
        raise ValueError('development progress file is linked or unsafe')
    temporary = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
    content = (json.dumps(row, sort_keys=True, indent=2,
                          allow_nan=False) + '\n').encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


class ScriptedCampaignProvider:
    """One zero-candidate SP answer, with a persisted physical start first."""

    def __init__(self, ledger: DevelopmentRequestLedger,
                 physical_ledger: PersistentPhysicalFuzzLedger, scope_id: str, *,
                 cancel_after_start: bool = False):
        self.ledger, self.physical_ledger, self.scope_id = (
            ledger, physical_ledger, scope_id)
        self.cancel_after_start = cancel_after_start
        self.calls: list[str] = []
        self.backend = SimpleNamespace(ledger=ledger, scope_id=scope_id,
                                       _request=self._forbid_transport)

    @staticmethod
    async def _forbid_transport(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError('real App Server transport is forbidden')

    async def generate(self, request: Any) -> dict:
        digest = request_hash(request)
        # The physical STOP commit and this durable model start share the
        # physical ledger's local and file locks. A preflight check alone can
        # race with a concurrent HP/SP/Global cleanup failure.
        with self.physical_ledger.model_start_guard():
            self.ledger.begin_turn(self.scope_id, request.role, digest)
            self.ledger.start_attempt(digest)
        self.calls.append(request.role)
        if self.cancel_after_start:
            raise asyncio.CancelledError('scripted physical turn interrupted')
        if request.role != 'sp_generation':
            raise AssertionError(f'unexpected scripted role: {request.role}')
        self.ledger.finish_attempt(completed=True)
        return {'suspicious_points': []}


def _physical_stop(ledger: PersistentPhysicalFuzzLedger) -> str | None:
    # This only detects a prior physical stop. The toy invokes no Fuzzer.
    ledger._verify_checkpoint_current()
    state = ledger.snapshot()
    if state['active']:
        return 'STOPPED_UNCERTAIN_PROCESS'
    return state['stop_status']


async def run_scripted_four_phase_campaign(
        *, source_run: Path, worklist_path: Path,
        expected_worklist_sha256: str, first_run: Path, campaign_output: Path,
        target_repository: Path, target_binary: Path,
        official_qualification: Any,
        model_ledger: DevelopmentRequestLedger,
        physical_ledger: PersistentPhysicalFuzzLedger,
        cancel_on_ordinal: int | None = None) -> dict:
    """Run each scheduled job until global credit or an uncertain stop.

    No fixed K, SP4/HP4, per-job candidate cap, or target execution is
    authorized. ``max_candidates=1`` below is an enable flag for the dev
    queue; product external mode does not use it as a candidate count.
    """
    if (type(model_ledger) is not DevelopmentRequestLedger or
            model_ledger.budget.profile != GLOBAL_ONLY_DEV_PROFILE or
            type(physical_ledger) is not PersistentPhysicalFuzzLedger or
            model_ledger.selected_functions or model_ledger.active_turn or
            model_ledger.tainted or not model_ledger.direction_counts or
            any(count != 1 for count in model_ledger.direction_counts.values()) or
            cancel_on_ordinal is not None and (
                type(cancel_on_ordinal) is not int or cancel_on_ordinal < 0)):
        raise ValueError('scripted campaign requires one settled Direction and fresh global ledger')
    model_ledger.checkpoint()
    initial_physical_stop = _physical_stop(physical_ledger)
    if initial_physical_stop is not None:
        raise ValueError('physical fuzz ledger already stopped before campaign')
    campaign_output = Path(campaign_output)
    if campaign_output.exists() or campaign_output.is_symlink():
        raise ValueError('development campaign output already exists')
    campaign_output.mkdir(mode=0o700, parents=True)
    progress_path = campaign_output / 'CAMPAIGN_PROGRESS.json'
    run = start_four_phase_dev(Path(source_run), Path(worklist_path),
                               expected_worklist_sha256, Path(first_run))
    completed: list[dict] = []
    attempts: list[dict] = []

    def progress(status: str, current: Path | None, **extra: Any) -> dict:
        row = {
            'kind': 'SCRIPTED_FOUR_PHASE_CAMPAIGN_DEV_V1',
            'status': status, 'source_phase1_run': str(Path(source_run).resolve()),
            'worklist_sha256': expected_worklist_sha256,
            'model_ledger_checkpoint_sha256': _sha(model_ledger.checkpoint_path),
            'physical_ledger_checkpoint_sha256': _sha(physical_ledger.path),
            'current_run': str(current) if current is not None else None,
            'completed': list(completed), 'attempts': list(attempts),
            'physical_model_starts': model_ledger.physical,
            'logical_model_turns': model_ledger.logical,
            'global_budget': {
                'physical_max': model_ledger.budget.physical_max,
                'logical_max': model_ledger.budget.logical_max,
                'wall_seconds': model_ledger.budget.wall_seconds,
                'profile': model_ledger.budget.profile,
            },
            'target_runs': 0, 'fuzz_seconds': 0,
            'assurance_scope': 'SCRIPTED_PROVIDER_NO_TARGET_NO_FREEZE',
            **extra,
        }
        _write_private(progress_path, row)
        return row

    progress('READY', run)
    while True:
        run_row, selection, item = validate_four_phase_dev_selection(run)
        scope_id = item['work_item_id']
        if scope_id in model_ledger.function_counts or scope_id in model_ledger.no_opportunity:
            raise ValueError('four-phase job was already selected or stopped')
        stop = _physical_stop(physical_ledger)
        if stop is not None:
            model_ledger.mark_no_opportunity(scope_id, 'NO_OPPORTUNITY_PHYSICAL_STOP')
            return progress(stop, run,
                            remaining_status='NO_OPPORTUNITY_PHYSICAL_STOP')
        try:
            selected = model_ledger.select_function(scope_id)
        except DevelopmentBudgetExhausted:
            model_ledger.mark_no_opportunity(scope_id, 'NO_OPPORTUNITY_BUDGET')
            selected = False
        if not selected:
            pending_path = campaign_output / 'PENDING_WORKLIST.json'
            frozen = freeze_pending_budget(run, model_ledger, pending_path)
            return progress('BUDGET_EXHAUSTED_PENDING_WORK', run,
                            pending_sha256=_sha(pending_path),
                            pending_count=len(frozen['pending']))
        provider = ScriptedCampaignProvider(
            model_ledger, physical_ledger, scope_id,
            cancel_after_start=item['ordinal'] == cancel_on_ordinal)
        progress('SELECTED_NOT_STARTED', run, selected_work_item_id=scope_id)
        try:
            await scan_selected(
                run, provider, target_repository=Path(target_repository),
                target_binary=Path(target_binary),
                official_qualification=official_qualification,
                external_turn_budget=model_ledger,
                external_multifunction_dev=True,
                candidate_budget_policy='QUEUE_FIRST_DEV', max_candidates=1,
                targeted_fuzz_seconds=0, assertion_fuzz_seconds=0,
                global_fuzz_enabled=False, hallucination_prevent='off')
            scan = _read(run / 'scan.json')
            if (scan.get('four_phase_work_item_id') != scope_id or
                    scan.get('selected_direction_id') != item['direction_id'] or
                    scan.get('selected_function_id') != item['function_id'] or
                    scan.get('budget_authority') != 'EXTERNAL_GLOBAL_DEV' or
                    scan.get('global_budget_profile') != GLOBAL_ONLY_DEV_PROFILE):
                raise ValueError('scripted Scan does not match selected work item')
            # A separate STOP may commit after Scan returns. Settle the model
            # checkpoint while holding the same physical admission lock used
            # by reserve/finish, so STOP and SCAN_RECORDED have one order.
            with physical_ledger.model_start_guard():
                model_ledger.mark_scan_recorded(scope_id)
            completed.append({'work_item_id': scope_id,
                              'ordinal': item['ordinal'],
                              'direction_id': item['direction_id'],
                              'function_id': item['function_id'],
                              'scan_sha256': _sha(run / 'scan.json'),
                              'terminal_sha256': _sha(run / 'four_phase_scan_complete.json')})
            attempts.append({'ordinal': item['ordinal'], 'work_item_id': scope_id,
                             'model_roles': list(provider.calls),
                             'status': 'SCAN_RECORDED'})
            progress('SCAN_RECORDED', run)
        except PhysicalModelStartBlocked as exc:
            # The failed guard made no new model start. Earlier turns and even
            # the product Scan may have completed; evaluator settlement did not.
            try:
                model_ledger.mark_selected_physical_stop(scope_id, exc.status)
            except BaseException as audit_exc:
                exc.add_note('selected physical stop checkpoint also failed: ' +
                             type(audit_exc).__name__ + ': ' + str(audit_exc))
                attempts.append({'ordinal': item['ordinal'], 'work_item_id': scope_id,
                                 'model_roles': list(provider.calls),
                                 'status': 'STOPPED_AUDIT_INCOMPLETE',
                                 'physical_stop_status': exc.status,
                                 'audit_error_type': type(audit_exc).__name__})
                try:
                    progress('STOPPED_AUDIT_INCOMPLETE', run,
                             selected_work_item_id=scope_id,
                             physical_stop_status=exc.status,
                             audit_error_type=type(audit_exc).__name__,
                             audit_error_message=str(audit_exc))
                except BaseException as receipt_exc:
                    exc.add_note('campaign progress write also failed: ' +
                                 type(receipt_exc).__name__)
                raise exc
            attempts.append({'ordinal': item['ordinal'], 'work_item_id': scope_id,
                             'model_roles': list(provider.calls),
                             'status': 'INCOMPLETE_PHYSICAL_STOP',
                             'physical_stop_status': exc.status})
            try:
                return progress(exc.status, run, selected_work_item_id=scope_id,
                                selected_work_item_status='INCOMPLETE_PHYSICAL_STOP',
                                remaining_status='NO_OPPORTUNITY_PHYSICAL_STOP')
            except BaseException as receipt_exc:
                exc.add_note('campaign progress write also failed: ' +
                             type(receipt_exc).__name__)
                raise exc
        except BaseException as exc:
            audit_exc: BaseException | None = None
            if model_ledger.active_turn is not None:
                try:
                    model_ledger.abandon_turn(type(exc).__name__)
                except BaseException as failure:
                    audit_exc = failure
                    exc.add_note('model turn abandonment also failed: ' +
                                 type(failure).__name__ + ': ' + str(failure))
            receipt_status = ('STOPPED_AUDIT_INCOMPLETE' if audit_exc is not None
                              else 'INCOMPLETE_INTERRUPTED')
            attempts.append({'ordinal': item['ordinal'], 'work_item_id': scope_id,
                             'model_roles': list(provider.calls),
                             'status': receipt_status,
                             'error_type': type(exc).__name__,
                             'audit_error_type': (type(audit_exc).__name__
                                                  if audit_exc is not None else None)})
            try:
                progress(receipt_status, run,
                         selected_work_item_id=scope_id,
                         error_type=type(exc).__name__,
                         audit_error_type=(type(audit_exc).__name__
                                           if audit_exc is not None else None),
                         audit_error_message=(str(audit_exc)
                                              if audit_exc is not None else None))
            except BaseException as receipt_exc:
                exc.add_note('campaign progress write also failed: ' +
                             type(receipt_exc).__name__)
            raise
        try:
            run = continue_four_phase_dev(run)
        except BaseException as exc:
            if isinstance(exc, ValueError) and 'worklist exhausted' in str(exc):
                return progress('ACCOUNTING_COMPLETE_AWAITING_EVIDENCE', run,
                                completed_job_count=len(completed))
            try:
                progress('STOPPED_CONTINUATION_ERROR', run,
                         error_type=type(exc).__name__,
                         error_message=str(exc))
            except BaseException as audit_exc:
                exc.add_note('campaign continuation receipt also failed: ' +
                             type(audit_exc).__name__)
            raise
