"""Freeze unfinished four-phase development jobs after a global budget stop."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any


def freeze_pending_budget(run_dir: Path, ledger: Any, output: Path) -> dict:
    """Report pending work; never authorize a model request or a retry."""
    from vulnerabilityanalysis.workflow import (_four_phase_job_id,
                                                require_four_phase_continuable_scan,
                                                validate_four_phase_dev_selection,
                                                verify_four_phase_terminal_marker)
    from vulnerabilityanalysis.scan import _external_multifunction_checkpoint

    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    run_dir = run_dir.resolve(strict=True)
    run, _, current = validate_four_phase_dev_selection(run_dir)
    worklist = json.loads((run_dir / 'four_phase_worklist.json').read_text())
    rows = worklist['worklist']
    ordinal = current['ordinal']
    ids = [_four_phase_job_id(run['direction_plan_sha256'], n, row)
           for n, row in enumerate(rows)]
    budget = ledger.budget
    required = budget.initial_starts_required
    exhausted = (budget.physical_max - ledger.physical < required or
                 budget.logical_max - ledger.logical < required or
                 time.time() - ledger.started_at >= budget.wall_seconds)
    if (not exhausted or ledger.active_turn is not None or ledger.tainted or
            ledger.selected_functions != ids[:ordinal] or
            any(ledger.function_states.get(job_id) != 'SCAN_RECORDED'
                for job_id in ids[:ordinal]) or
            current['work_item_id'] not in ledger.no_opportunity or
            ledger.no_opportunity[current['work_item_id']] != 'NO_OPPORTUNITY_BUDGET'):
        raise ValueError('four-phase pending budget lacks a completed prefix and stop proof')
    _external_multifunction_checkpoint(ledger)
    folder = run_dir
    for expected_ordinal in range(ordinal - 1, -1, -1):
        parent_id = json.loads((folder / 'run.json').read_text()).get('parent_run_id')
        if (not isinstance(parent_id, str) or
                not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', parent_id)):
            raise ValueError('four-phase completed prefix has no parent Run')
        folder = folder.parent / parent_id
        prior_run, _, prior = validate_four_phase_dev_selection(folder)
        verify_four_phase_terminal_marker(folder, prior_run, prior)
        scan_path = folder / 'scan.json'
        if scan_path.is_symlink() or not scan_path.is_file():
            raise ValueError('four-phase completed prefix has no Scan evidence')
        scan = json.loads(scan_path.read_text())
        require_four_phase_continuable_scan(scan)
        if (prior['ordinal'] != expected_ordinal or
                prior['work_item_id'] != ids[expected_ordinal] or
                scan.get('four_phase_work_item_id') != prior['work_item_id'] or
                scan.get('selected_direction_id') != prior['direction_id'] or
                scan.get('four_phase') != prior['phase']):
            raise ValueError('four-phase completed prefix Scan identity changed')
    checkpoint = ledger.checkpoint_path
    if checkpoint.is_symlink() or not checkpoint.is_file():
        raise ValueError('global budget checkpoint missing or linked')
    completed = [{'work_item_id': ids[n], 'ordinal': n,
                  'phase': rows[n]['phase']}
                 for n in range(ordinal)]
    pending = [{'work_item_id': ids[n], 'ordinal': n,
                'phase': row['phase'], 'direction_id': row['direction_id'],
                'function_id': row['function_id'], 'state': 'PENDING_BUDGET'}
               for n, row in enumerate(rows) if n >= ordinal]
    done_counts = Counter(row['phase'] for row in completed)
    pending_counts = Counter(row['phase'] for row in pending)
    phases = worklist['phase_order']
    report = {
        'kind': 'FBV2_FOUR_PHASE_GLOBAL_BUDGET_STOP_V1',
        'status': 'BUDGET_EXHAUSTED_PENDING_WORK',
        'worklist_sha256': run['four_phase_worklist_sha256'],
        'phase_semantics_status': run['phase_semantics_status'],
        'independent_freeze_status': run['independent_freeze_status'],
        'ledger_checkpoint_sha256': hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
        'completed': completed, 'pending': pending,
        'phase_counts': {phase: {'completed': done_counts[phase],
                                'pending': pending_counts[phase]}
                         for phase in phases},
        'starved_phases': [phase for phase in phases
                           if pending_counts[phase] and not done_counts[phase]],
        'physical_used': ledger.physical, 'logical_used': ledger.logical,
        'cost': {'model_calls_started_by_this_report': 0,
                 'target_runs': 0, 'fuzz_seconds': 0},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    return report
