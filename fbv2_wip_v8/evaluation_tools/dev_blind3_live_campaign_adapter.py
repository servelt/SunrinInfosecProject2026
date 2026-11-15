"""One development four-phase work item with a guarded role-model backend.

The saved Direction is a pinned input to this component, not a physical model
call in its ledger. The caller must establish official V2 qualification and
pre-import source/code pins before invoking this function in a supervised
child. Target execution, Assertion execution, Fuzzing, and Blind 3 are outside
this component and fail closed if reached.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from unittest.mock import patch


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DevelopmentExecutionForbidden(BaseException):
    """Stop before a Target side effect; product ordinary handlers cannot hide it."""


def _forbid_execution(*_args: Any, **_kwargs: Any) -> Any:
    raise DevelopmentExecutionForbidden('development model-only boundary reached Target execution')


def _physical_stop(physical: Any) -> str | None:
    physical._verify_checkpoint_current()
    state = physical.snapshot()
    return ('STOPPED_UNCERTAIN_PROCESS' if state['active'] else
            state['stop_status'])


async def run_one_development_work_item(
        *, source_run: Path, worklist_path: Path,
        expected_worklist_sha256: str, first_run: Path,
        target_repository: Path, target_binary: Path,
        official_qualification: Any, backend: Any,
        model_ledger: Any, physical_ledger: Any,
        role_models: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Drive one pinned job; return a boundary receipt, never a Blind verdict.

    The caller owns the App Server lifetime and must supervise this function.
    This component intentionally has no Direction debit. A saved plan cannot
    be presented as a newly issued physical model request.
    """
    tools = Path(__file__).resolve().parent
    review_tools = tools.parent / 'review_tools'
    if str(review_tools) not in sys.path:
        sys.path.insert(0, str(review_tools))
    from dev_global_appserver_bridge import (DevelopmentGlobalAppServer,
                                             verify_model_event_order,
                                             verify_product_request_order)
    from dev_global_appserver_product_flow import (DevelopmentBudgetStop,
                                                   ProductBudgetAdapter)
    from dev_global_request_ledger import (DevelopmentBudgetExhausted,
                                           DevelopmentRequestLedger,
                                           GLOBAL_ONLY_DEV_PROFILE,
                                           TERMINAL_PENDING_STATES)
    from dev_persistent_physical_fuzz_ledger import (PersistentPhysicalFuzzLedger,
                                                     PhysicalModelStartBlocked)
    from vulnerabilityanalysis.official_harness import OfficialPinnedQualification
    from vulnerabilityanalysis.scan import scan_selected
    from vulnerabilityanalysis.workflow import (require_four_phase_continuable_scan,
                                                start_four_phase_dev,
                                                validate_four_phase_dev_selection,
                                                verify_four_phase_terminal_marker)

    source_run, worklist_path, first_run, target_repository, target_binary = map(
        Path, (source_run, worklist_path, first_run, target_repository, target_binary))
    if (type(model_ledger) is not DevelopmentRequestLedger or
            model_ledger.budget.profile != GLOBAL_ONLY_DEV_PROFILE or
            type(physical_ledger) is not PersistentPhysicalFuzzLedger or
            not isinstance(backend, DevelopmentGlobalAppServer) or
            backend.ledger is not model_ledger or
            backend.physical_ledger is not physical_ledger or
            backend.scope_id is not None or
            backend.role_models != role_models or
            backend.event_log_path is None or
            model_ledger.logical != 0 or model_ledger.physical != 0 or
            model_ledger.direction_counts or model_ledger.selected_functions or
            model_ledger.active_turn is not None or model_ledger.tainted or
            not isinstance(official_qualification, OfficialPinnedQualification) or
            not getattr(official_qualification, 'product_issued', False) or
            target_repository.resolve(strict=True) !=
                getattr(official_qualification, 'source_root', None) or
            target_binary.resolve(strict=True) !=
                getattr(official_qualification, 'binary', None)):
        raise ValueError('one-work-item live development authority changed')
    if (not source_run.is_absolute() or not worklist_path.is_absolute() or
            not first_run.is_absolute() or not target_repository.is_absolute() or
            not target_binary.is_absolute() or
            not all(isinstance(route, dict) and set(route) == {'model', 'reasoning'}
                    for route in role_models.values())):
        raise ValueError('one-work-item input route changed')
    # The product validates the official class and Artifact pin before the
    # first request. This preliminary check rejects a wrong target sooner.
    run = start_four_phase_dev(source_run, worklist_path,
                               expected_worklist_sha256, first_run)
    _run, selection, item = validate_four_phase_dev_selection(run)
    scope_id = item['work_item_id']
    stop = _physical_stop(physical_ledger)
    if stop is not None:
        model_ledger.mark_no_opportunity(scope_id, 'NO_OPPORTUNITY_PHYSICAL_STOP')
        return {'kind': 'ONE_WORK_ITEM_LIVE_MODEL_COMPONENT_DEV_V1',
                'status': stop, 'analysis_complete': False,
                'work_item_id': scope_id, 'selected_function_id': item['function_id'],
                'direction_source': 'PINNED_PLAN_INPUT_UNACCOUNTED_IN_THIS_LEDGER',
                'model_physical_starts': 0, 'model_logical_turns': 0,
                'target_runs': 0, 'fuzz_seconds': 0,
                'no_opportunity': 'NO_OPPORTUNITY_PHYSICAL_STOP'}
    try:
        selected = model_ledger.select_function(scope_id)
    except DevelopmentBudgetExhausted:
        model_ledger.mark_no_opportunity(scope_id, 'NO_OPPORTUNITY_BUDGET')
        selected = False
    if not selected:
        return {'kind': 'ONE_WORK_ITEM_LIVE_MODEL_COMPONENT_DEV_V1',
                'status': 'NO_OPPORTUNITY_BUDGET', 'analysis_complete': False,
                'work_item_id': scope_id, 'selected_function_id': item['function_id'],
                'direction_source': 'PINNED_PLAN_INPUT_UNACCOUNTED_IN_THIS_LEDGER',
                'model_physical_starts': 0, 'model_logical_turns': 0,
                'target_runs': 0, 'fuzz_seconds': 0,
                'no_opportunity': 'NO_OPPORTUNITY_BUDGET'}
    backend.bind_scope(scope_id)
    provider = ProductBudgetAdapter(backend, model_ledger, scope_id)

    def settle_physical_stop(reason: str) -> str:
        if model_ledger.active_turn is not None:
            raise RuntimeError('physical STOP left an unsettled model turn')
        state = model_ledger.function_states.get(scope_id)
        if state == 'SELECTED_NOT_STARTED':
            model_ledger.mark_selected_physical_stop(scope_id, reason)
        elif state != 'INCOMPLETE_INTERRUPTED' or not any(
                row.get('scope_id') == scope_id and
                row.get('state') in TERMINAL_PENDING_STATES
                for row in model_ledger.pending_work):
            raise RuntimeError('physical STOP lacks terminal function evidence')
        return reason

    try:
        with (patch('vulnerabilityanalysis.scan.execute_poc', _forbid_execution),
              patch('vulnerabilityanalysis.scan.run_assertions_for_scan',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.run_global_fuzz',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.fuzz_locally',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                    _forbid_execution)):
            await scan_selected(
                run, provider, target_repository=target_repository,
                target_binary=target_binary,
                official_qualification=official_qualification,
                role_models=role_models, external_turn_budget=model_ledger,
                external_multifunction_dev=True,
                candidate_budget_policy='QUEUE_FIRST_DEV', max_candidates=1,
                targeted_fuzz_seconds=0, assertion_fuzz_seconds=0,
                global_fuzz_enabled=False, hallucination_prevent='on')
    except PhysicalModelStartBlocked as exc:
        status = settle_physical_stop(exc.status)
    except DevelopmentBudgetStop:
        if provider.rejected_prewire is None:
            raise RuntimeError('budget STOP has no pre-wire denial')
        status = 'INCOMPLETE_BUDGET'
    except DevelopmentExecutionForbidden:
        status = 'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN'
    else:
        scan_path = run / 'scan.json'
        terminal = run / 'four_phase_scan_complete.json'
        if not scan_path.is_file() or not terminal.is_file():
            status = 'INCOMPLETE_SCAN_EVIDENCE'
        else:
            scan = json.loads(scan_path.read_text(encoding='utf-8'))
            verify_four_phase_terminal_marker(run, _run, item)
            try:
                require_four_phase_continuable_scan(scan)
            except ValueError:
                status = 'INCOMPLETE_PENDING_WORK'
            else:
                if (scan.get('four_phase_work_item_id') != scope_id or
                        scan.get('selected_direction_id') != item['direction_id'] or
                        scan.get('selected_function_id') != item['function_id'] or
                        scan.get('budget_authority') != 'EXTERNAL_GLOBAL_DEV' or
                        scan.get('global_budget_profile') != GLOBAL_ONLY_DEV_PROFILE):
                    raise ValueError('one-work-item Scan identity changed')
                if (backend.forbidden_tool_event or backend.audit_log_failed or
                        backend.provider_safety_refused or model_ledger.tainted or
                        model_ledger.active_turn is not None or
                        any(row.get('state') in TERMINAL_PENDING_STATES
                            for row in model_ledger.pending_work)):
                    raise ValueError('one-work-item provider or ledger is incomplete')
                scope_turns = [turn for turn in model_ledger.turns
                               if turn['scope_id'] == scope_id]
                if not any(turn['role'] == 'sp_generation' and
                           turn['status'] == 'COMPLETED' and
                           any(attempt['turn_id'] == turn['id'] and
                               attempt['status'] == 'COMPLETED' and
                               attempt.get('app_server_turn_id')
                               for attempt in model_ledger.attempts)
                           for turn in scope_turns):
                    raise ValueError('one-work-item Scan lacks accepted SP model turn')
                rows_path = run / 'logs/agent_requests.jsonl'
                rows = ([json.loads(line) for line in
                         rows_path.read_text(encoding='utf-8').splitlines()]
                        if rows_path.is_file() else [])
                verify_product_request_order(
                    model_ledger,
                    [Path(row['request_artifact']) for row in rows],
                    scope_id=scope_id)
                if backend.event_log_path is not None:
                    verify_model_event_order(model_ledger, backend.event_log_path)
                try:
                    with physical_ledger.model_start_guard():
                        model_ledger.mark_scan_recorded(scope_id)
                except PhysicalModelStartBlocked as exc:
                    status = settle_physical_stop(exc.status)
                else:
                    status = 'SCAN_RECORDED'
    finally:
        backend.unbind_scope()
    return {
        'kind': 'ONE_WORK_ITEM_LIVE_MODEL_COMPONENT_DEV_V1',
        'status': status, 'analysis_complete': status == 'SCAN_RECORDED',
        'work_item_id': scope_id, 'selected_function_id': item['function_id'],
        'selected_direction_id': item['direction_id'],
        'direction_source': 'PINNED_PLAN_INPUT_UNACCOUNTED_IN_THIS_LEDGER',
        'model_physical_starts': model_ledger.physical,
        'model_logical_turns': model_ledger.logical,
        'model_ledger_sha256': _sha(model_ledger.checkpoint_path),
        'model_event_log_sha256': (_sha(backend.event_log_path)
                                   if backend.event_log_path.is_file() else None),
        'physical_ledger_sha256': _sha(physical_ledger.path),
        'scan_sha256': _sha(run / 'scan.json') if (run / 'scan.json').is_file() else None,
        'terminal_sha256': (_sha(run / 'four_phase_scan_complete.json')
                            if (run / 'four_phase_scan_complete.json').is_file()
                            else None),
        'target_runs': 0, 'fuzz_seconds': 0,
        'scope': 'DEVELOPMENT_ONE_WORK_ITEM_NO_TARGET_NO_BLIND',
    }
