"""Provider-free public control for first-pass order and global request stops.

This deliberately does not call ``scan_selected`` or a model. Its request
debits are scripted accounting examples. The product currently rejects a
multi-function GLOBAL_ONLY_DEV ledger, so this is not a K-free campaign runner.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests')]

from test_direction_plan import fixture as direction_fixture  # noqa: E402
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1  # noqa: E402
from dev_global_request_ledger import (DevelopmentBudget,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def make_public_fixture(root: Path) -> tuple[Path, Path, Path]:
    """Make a public A→B→C call chain with a pinned development Direction."""
    root.mkdir(parents=True, exist_ok=True)
    artifact, repo, plan = direction_fixture(root)
    (repo / 'target.c').write_text(
        'int C(void) { return 0; }\n'
        'int B(void) { return C(); }\n'
        'int A(void) { return B(); }\n', encoding='utf-8')
    analysis = repo / 'analysis'
    (analysis / 'functions.jsonl').write_text(''.join(
        json.dumps({'function_id': f'fn-{name.lower()}', 'name': name,
                    'file': 'target.c'}, sort_keys=True) + '\n'
        for name in 'ABC'), encoding='utf-8')
    (analysis / 'edges.jsonl').write_text(''.join(
        json.dumps({'caller_id': f'fn-{caller.lower()}',
                    'callee_id': f'fn-{callee.lower()}',
                    'kind': 'SOURCE_DIRECT_COMPILED'}, sort_keys=True) + '\n'
        for caller, callee in (('A', 'B'), ('B', 'C'))), encoding='utf-8')
    (analysis / 'indirect_edges.jsonl').write_text('', encoding='utf-8')
    proposal = _read(plan)
    for key, filename in (('functions_sha256', 'functions.jsonl'),
                          ('edges_sha256', 'edges.jsonl'),
                          ('indirect_edges_sha256', 'indirect_edges.jsonl')):
        proposal[key] = _sha(analysis / filename)
    proposal['response']['directions'][0]['core_function_ids'] = ['fn-c']
    plan.write_text(json.dumps(proposal, sort_keys=True) + '\n',
                    encoding='utf-8')
    return artifact, repo, plan


def selection_only_order(artifact: Path, repo: Path, plan: Path,
                         run_root: Path) -> list[str]:
    """Ask the real Phase 1 selector for each first visit, without Scan.

    Synthetic identity-only ``scan.json`` files are restricted to this dry
    enumeration; no analysis, model or Target work is represented by them.
    """
    run = run_phase1(artifact, run_root, target_repository=repo,
                     direction_plan=plan,
                     selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
    pool = _read(run / 'function_pool.json')
    pool_ids = [row['function_id'] for row in pool]
    if set(pool_ids) != {'fn-a', 'fn-b', 'fn-c'} or len(pool_ids) != 3:
        raise ValueError('public fixture pool changed')
    order: list[str] = []
    for index in range(len(pool_ids)):
        selected = _read(run / 'selection.json')
        function_id = selected['function_id']
        if function_id not in pool_ids or function_id in order:
            raise ValueError('product first-pass order repeated or unknown')
        order.append(function_id)
        if index + 1 < len(pool_ids):
            (run / 'scan.json').write_text(json.dumps({
                'selected_function': selected['function_name'],
                'selected_function_id': function_id,
                'target_repository': str(repo),
                'synthetic_identity_only': True,
            }, sort_keys=True) + '\n', encoding='utf-8')
            run = continue_phase1(run)
    return order


def _scripted_debit(ledger: DevelopmentRequestLedger, scope_id: str,
                    role: str) -> dict[str, Any]:
    """Exercise durable debit order with no backend transport."""
    digest = hashlib.sha256(
        f'PUBLIC_ACCOUNTING_CONTROL:{scope_id}:{role}'.encode()).hexdigest()
    ledger.begin_turn(scope_id, role, digest)
    physical = ledger.start_attempt(digest)
    ledger.finish_attempt(completed=True)
    return {'scope_id': scope_id, 'role': role, 'physical': physical}


def run_public_three_function_gate(root: Path) -> Path:
    """Record Direction1 + A SP/HP2, then pending A and B/C without K."""
    root.mkdir(parents=True, exist_ok=True)
    artifact, repo, plan = make_public_fixture(root / 'fixture')
    order = selection_only_order(artifact, repo, plan,
                                 root / 'selection_only_runs')
    budget = DevelopmentBudget(physical_max=3, logical_max=3, retries_max=0,
                               wall_seconds=60, initial_starts_required=2,
                               profile=GLOBAL_ONLY_DEV_PROFILE)
    checkpoint = root / 'MODEL_LEDGER_SIMULATED.json'
    ledger = DevelopmentRequestLedger.create(budget, checkpoint)
    ledger.register_direction('public-direction-plan')
    debits = [_scripted_debit(ledger, 'public-direction-plan',
                              'direction_generator')]
    first = order[0]
    if not ledger.select_function(first):
        raise ValueError('first function unexpectedly lacks two initial starts')
    debits.append(_scripted_debit(ledger, first, 'sp_generation'))
    debits.append(_scripted_debit(ledger, first, 'function_analysis'))
    ledger.mark_pending('public-sp-a-verifier', first, 'SP_VERIFIER',
                        'GLOBAL_MODEL_BUDGET_EXHAUSTED')
    # There was no product Scan, so SELECTED_NOT_STARTED remains the truthful
    # state even though the scripted ledger contains two illustrative starts.
    for function_id in order[1:]:
        if ledger.select_function(function_id):
            raise ValueError('new function selected despite exhausted total')
    summary = ledger.summary(order)
    restored = DevelopmentRequestLedger.restore(checkpoint, budget)
    if restored.summary(order) != summary:
        raise ValueError('durable model accounting differs after restore')
    receipt = {
        'kind': 'PUBLIC_NO_K_THREE_FUNCTION_ACCOUNTING_CONTROL_V1',
        'scope': 'PROVIDER_FREE_SELECTION_AND_LEDGER_ONLY',
        'interpretation': (
            'All ledger starts are simulated accounting debits; K_observed is '
            'the count of functions admitted by the budget gate, not the '
            'count of product Scans completed.'),
        'not_claimed': ['multi-function product Scan integration',
                        'real model or Target/Fuzzer execution',
                        'cross-function pending queue policy',
                        'Blind 3 readiness or performance'],
        'direction_plan_sha256': _sha(plan),
        'catalog_sha256': _sha(repo / 'analysis/functions.jsonl'),
        'selection_only_order': order,
        'simulated_debits': debits,
        'actual_model_transports': 0,
        'actual_target_executions': 0,
        'product_scans_completed': 0,
        'ledger_checkpoint': str(checkpoint),
        'ledger_checkpoint_sha256': _sha(checkpoint),
        'ledger_summary': summary,
    }
    output = root / 'PUBLIC_NO_K_GATE_RECEIPT.json'
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n',
                      encoding='utf-8')
    return output
