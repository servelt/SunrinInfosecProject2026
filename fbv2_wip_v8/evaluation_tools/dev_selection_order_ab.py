"""Compare two existing first-pass selectors on one pinned public Pool.

This evaluation-only tool does not call a model, execute a target, fuzz, read
an evaluator Oracle, or claim to reproduce FBv2's per-Direction reanalysis.
The historical K=24 is reported as a comparison marker, not a stopping rule.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any

PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path.insert(0, str(PRODUCT / 'src'))

from vulnerabilityanalysis.direction_plan import (  # noqa: E402
    DEV_FIRST_PASS_POLICY, validate_dev_direction_outputs)
from vulnerabilityanalysis.models import (  # noqa: E402
    FunctionPoolItem, NormalizedHarness)
from vulnerabilityanalysis.scheduler import (  # noqa: E402
    Scheduler, source_evidence_for_pool)
from vulnerabilityanalysis.workflow import _dev_priority_keys  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'pinned input missing or linked: {path.name}')
    return json.loads(path.read_text(encoding='utf-8'))


def _order_sha(order: list[str]) -> str:
    return hashlib.sha256(json.dumps(order, separators=(',', ':')).encode()).hexdigest()


def _reset_pool(rows: list[dict]) -> list[FunctionPoolItem]:
    pool = [FunctionPoolItem(**row) for row in rows]
    for item in pool:
        item.analyzed = False
        item.analysis_count = 0
        item.wait_age = 0
        item.last_result = None
    return pool


def _product_hashes() -> dict[str, str]:
    paths = {
        'scheduler.py': PRODUCT / 'src/vulnerabilityanalysis/scheduler.py',
        'direction_plan.py': PRODUCT / 'src/vulnerabilityanalysis/direction_plan.py',
        'workflow.py': PRODUCT / 'src/vulnerabilityanalysis/workflow.py',
        'default.yaml': PRODUCT / 'config/default.yaml',
    }
    return {name: _sha(path) for name, path in paths.items()}


def compare_run(run_dir: Path) -> dict[str, Any]:
    """Replay SCORE and the existing unique-first-pass Direction adapter.

    A saved Phase 1 run reserves its first choice and ages the other rows.
    Both arms therefore start from the same unvisited, zero-age Pool snapshot.
    No scan feedback is available in this offline comparison.
    """
    started = time.monotonic()
    run_dir = run_dir.resolve(strict=True)
    code_before = _product_hashes()
    names = ('run.json', 'harness.json', 'directions.json',
             'function_pool.json', 'direction_plan.json', 'selection.json')
    if any((run_dir / name).is_symlink() or not (run_dir / name).is_file()
           for name in names):
        raise ValueError('pinned input is missing or linked')
    input_hashes = {name: _sha(run_dir / name) for name in names}
    run, harness_row, directions, rows, selected = (
        _json(run_dir / name) for name in names[:4] + names[5:])
    plan_path = run_dir / 'direction_plan.json'
    if (run.get('selection_policy') != DEV_FIRST_PASS_POLICY or
            run.get('direction_source_kind') != 'PINNED_MODEL_PROPOSAL' or
            run.get('source_kind') != 'official_oss_fuzz' or
            run.get('direction_plan_sha256') != input_hashes['direction_plan.json']):
        raise ValueError('Direction plan or development policy is not pinned')
    if (not isinstance(rows, list) or not rows or
            run.get('function_count') != len(rows) or
            not isinstance(directions, list) or
            run.get('direction_count') != len(directions) or
            not isinstance(selected, dict)):
        raise ValueError('Pool or Direction count changed')
    pool_ids = [row.get('function_id') for row in rows]
    reserved_id = selected.get('function_id')
    if (any(not isinstance(fid, str) or not fid for fid in pool_ids) or
            len(set(pool_ids)) != len(pool_ids) or
            any(row.get('analyzed') is not False or
                row.get('analysis_count') != int(row.get('function_id') == reserved_id)
                for row in rows)):
        raise ValueError('Pool is not a unique, first-selection reservation snapshot')
    harness = NormalizedHarness(**harness_row)
    if harness.source_kind != 'official_oss_fuzz' or not harness.target_repository:
        raise ValueError('official Harness source root missing')
    catalog_ids = [row.get('function_id') for row in harness.function_catalog.values()]
    if (len(set(catalog_ids)) != len(catalog_ids) or
            set(catalog_ids) != set(pool_ids)):
        raise ValueError('Pool IDs differ from official Catalog')
    validate_dev_direction_outputs(harness, plan_path,
                                   input_hashes['direction_plan.json'], directions)
    priority_keys, index_sha = _dev_priority_keys(
        harness, directions, _reset_pool(rows))
    if index_sha != run.get('direction_index_sha256'):
        raise ValueError('Direction priority index changed')
    pool = _reset_pool(rows)
    sources = source_evidence_for_pool(harness, pool)
    if set(sources) != set(pool_ids):
        raise ValueError('Pool source evidence incomplete')
    source_hash = hashlib.sha256(json.dumps(
        sources, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False).encode()).hexdigest()
    orders: dict[str, list[str]] = {}
    for mode in ('SCORE', DEV_FIRST_PASS_POLICY):
        arm_pool = _reset_pool(rows)
        scheduler = Scheduler.default()
        order = []
        for _ in arm_pool:
            chosen = (scheduler.select(arm_pool, sources=sources)
                      if mode == 'SCORE' else
                      scheduler.select_first_pass_unique_dev(
                          arm_pool, priority_keys, sources=sources))
            order.append(chosen.function_id)
        if len(set(order)) != len(pool_ids) or set(order) != set(pool_ids):
            raise ValueError(f'{mode} did not preserve every Pool function')
        orders[mode] = order
    if (selected.get('function_id') != orders[DEV_FIRST_PASS_POLICY][0] or
            run.get('selected_function_id') != selected.get('function_id')):
        raise ValueError('stored first selection differs from development selector')
    first_count = min(24, len(pool_ids))
    score_first = orders['SCORE'][:first_count]
    tier_first = orders[DEV_FIRST_PASS_POLICY][:first_count]
    code_after = _product_hashes()
    if code_before != code_after or input_hashes != {
            name: _sha(run_dir / name) for name in names}:
        raise ValueError('comparison source or pinned input changed during replay')
    return {
        'kind': 'DEVELOPMENT_SELECTION_ORDER_AB_V1',
        'status': 'PASS',
        'scope': 'PROVIDER_FREE_FIRST_PASS_ONLY',
        'limitations': [
            'The Direction arm is a unique-function first-pass adapter, not '
            'the original FBv2 small/new, small/re, big/new, big/re reanalysis.',
            'Target source is read from the current checkout. This saved Phase 1 '
            'run has no per-source expected digest, so byte identity with the '
            'original Phase 1 source is unproven.',
            'No model, target, fuzzing, scan feedback, or Blind 3 evaluation ran.',
            'K=24 is a historical Blind 2 comparison marker, not this run stop.',
        ],
        'input_hashes': input_hashes,
        'product_hashes': code_before,
        'input_validation': {
            'direction_plan_sha256': input_hashes['direction_plan.json'],
            'direction_index_sha256': index_sha,
            'direction_count': len(directions),
            'direction_risk_counts': dict(sorted(Counter(
                row['risk_level'] for row in directions).items())),
            'pool_unique_functions': len(pool_ids),
            'pool_role_counts': dict(sorted(Counter(
                row['role'] for row in rows).items())),
            'source_evidence_count': len(sources),
            'source_evidence_sha256': source_hash,
            'source_identity_scope': 'CURRENT_CHECKOUT_ONLY_PHASE1_BYTES_UNPROVEN',
            'stored_dev_first_selection_matches': True,
        },
        'arms': {mode: {'unique_functions': len(order), 'order': order,
                        'order_sha256': _order_sha(order),
                        'first_historical_24': order[:first_count]}
                 for mode, order in orders.items()},
        'comparison': {
            'legacy_k_reference': 24,
            'compared_first_count': first_count,
            'first_set_overlap': len(set(score_first) & set(tier_first)),
            'first_position_matches': sum(a == b for a, b in
                                          zip(score_first, tier_first, strict=True)),
            'only_score_first': sorted(set(score_first) - set(tier_first)),
            'only_direction_first': sorted(set(tier_first) - set(score_first)),
            'full_order_equal': orders['SCORE'] == orders[DEV_FIRST_PASS_POLICY],
        },
        'cost': {'model_calls': 0, 'target_runs': 0, 'fuzz_seconds': 0,
                 'wall_seconds': round(time.monotonic() - started, 6)},
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(args.out)
    report = compare_run(args.run)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n',
                        encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
