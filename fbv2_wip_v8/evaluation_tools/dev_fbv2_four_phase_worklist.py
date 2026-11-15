"""Build a pinned, provider-free FBv2 four-phase development worklist.

This is an evaluation artifact, not the product Scheduler or a Scan runner.
The upstream phase partition is snapshotted once before analysis. Small is
Entry union Core regardless of direct reachability, as in upstream FBv2.
Big needs a direct Entry path; indirect-only claims remain UNASSIGNED.
"""

from __future__ import annotations

from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
PHASES = ('small/new', 'small/re', 'big/new', 'big/re')
RISK_ORDER = {'HIGH': 0, 'NORMAL': 1, 'LOW': 2, 'UNKNOWN': 3}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'pinned input missing or linked: {path}')
    return json.loads(path.read_text(encoding='utf-8'))


def _walk(entries: set[str], direct: dict[str, set[str]]) -> set[str]:
    reached = set(entries)
    queue = deque(sorted(entries))
    while queue:
        for callee in sorted(direct.get(queue.popleft(), ())):
            if callee not in reached:
                reached.add(callee)
                queue.append(callee)
    return reached


def build_phase_worklist(
    catalog: dict[str, dict], directions: list[dict],
    direct: dict[str, set[str]], history: dict[str, list[str]],
    indirect_candidates: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    """Create `(Direction, function, phase)` jobs from one history snapshot.

    Catalog keys and graph nodes use the same unique function reference. A
    function in two Directions remains two jobs, including in the new phase.
    """
    if not isinstance(catalog, dict) or not catalog:
        raise ValueError('nonempty Catalog required')
    ids = {ref: row.get('function_id') for ref, row in catalog.items()
           if isinstance(ref, str) and ref and isinstance(row, dict)}
    if (len(ids) != len(catalog) or
            any(not isinstance(fid, str) or not fid for fid in ids.values()) or
            len(set(ids.values())) != len(ids)):
        raise ValueError('unique Catalog function IDs required')
    if not isinstance(directions, list) or not isinstance(history, dict):
        raise ValueError('Directions and history must have the declared shape')
    if (set(history) - set(ids.values()) or
            any(not isinstance(v, list) or
                    any(not isinstance(did, str) or not did for did in v)
                    or len(set(v)) != len(v) for v in history.values())):
        raise ValueError('history contains unknown function or malformed direction IDs')
    indirect_candidates = indirect_candidates or {}
    direction_ids = [d.get('direction_id') for d in directions if isinstance(d, dict)]
    if (len(direction_ids) != len(directions) or
            any(not isinstance(did, str) or not did for did in direction_ids) or
            len(set(direction_ids)) != len(direction_ids) or
            set(indirect_candidates) - set(direction_ids)):
        raise ValueError('unique Direction IDs and known indirect groups required')
    refs_by_id = {fid: ref for ref, fid in ids.items()}
    history_warnings = [
        {'direction_id': did, 'function_id': fid,
         'function_name': refs_by_id[fid],
         'reason': 'HISTORICAL_DIRECTION_NOT_IN_CURRENT_PLAN'}
        for fid, prior in history.items() for did in prior
        if did not in direction_ids]
    for caller, callees in direct.items():
        if caller not in catalog or not isinstance(callees, (set, list, tuple)) or not set(callees) <= set(catalog):
            raise ValueError('direct graph contains unknown Catalog reference')
    for did, refs in indirect_candidates.items():
        if not isinstance(refs, (set, list, tuple)) or not set(refs) <= set(catalog):
            raise ValueError(f'indirect candidates for {did} contain unknown reference')

    by_phase: dict[str, list[dict]] = {phase: [] for phase in PHASES}
    unassigned: list[dict] = []
    warnings: list[dict] = history_warnings
    mentioned: set[str] = set()
    for direction in sorted(directions, key=lambda d: (
            RISK_ORDER.get(d.get('risk_level'), 99), d['direction_id'])):
        did = direction['direction_id']
        risk = direction.get('risk_level')
        if risk not in RISK_ORDER:
            raise ValueError(f'unknown Direction risk: {risk}')
        parts: dict[str, set[str]] = {}
        for field in ('entry_functions', 'core_functions', 'related_functions'):
            refs = direction.get(field)
            if not isinstance(refs, list) or any(ref not in catalog for ref in refs):
                raise ValueError(f'{did} has invalid {field}')
            parts[field] = set(refs)
        entries, cores, related = (
            parts['entry_functions'], parts['core_functions'],
            parts['related_functions'])
        indirect = set(indirect_candidates.get(did, set()))
        mentioned.update(entries | cores | related | indirect)
        reached = _walk(entries, direct)
        small = entries | cores
        big = reached - small
        for ref in sorted(cores - reached, key=ids.__getitem__):
            warnings.append({'direction_id': did, 'function_id': ids[ref],
                             'function_name': ref,
                             'reason': ('CORE_WITHOUT_ENTRY_BFS' if not entries
                                        else 'CORE_NOT_DIRECT_REACHABLE')})
        # An indirect-only candidate may be omitted from related_functions.
        # Retain its Direction provenance once, without promoting it to Big.
        for ref in sorted((related | indirect) - reached - cores,
                          key=ids.__getitem__):
            reason = ('NO_ENTRY_FOR_BIG_POOL' if not entries else
                      'UNVERIFIED_INDIRECT_PATH'
                      if ref in indirect else
                      'NO_DIRECT_ENTRY_PATH')
            unassigned.append({'direction_id': did, 'function_id': ids[ref],
                               'function_name': ref, 'reason': reason})
        for part, refs in (('small', small), ('big', big)):
            for ref in sorted(refs, key=ids.__getitem__):
                phase = f'{part}/{"re" if history.get(ids[ref]) else "new"}'
                by_phase[phase].append({
                    'direction_id': did, 'function_id': ids[ref],
                    'function_name': ref, 'phase': phase, 'risk_level': risk,
                    'prior_direction_ids': sorted(set(history.get(ids[ref], []))),
                })
    assigned_ids = {row['function_id'] for rows in by_phase.values() for row in rows}
    unassigned_ids = {row['function_id'] for row in unassigned}
    for ref in sorted(set(catalog) - mentioned -
                      {row['function_name'] for rows in by_phase.values() for row in rows},
                      key=ids.__getitem__):
        unassigned.append({'direction_id': None, 'function_id': ids[ref],
                           'function_name': ref, 'reason': 'NO_DIRECTION_MEMBERSHIP'})
        unassigned_ids.add(ids[ref])
    worklist = [row for phase in PHASES for row in by_phase[phase]]
    if assigned_ids | unassigned_ids != set(ids.values()):
        raise ValueError('Catalog accounting is incomplete')
    unassigned.sort(key=lambda row: (str(row['direction_id']),
                                     row['function_id'], row['reason']))
    return {
        'kind': 'FBV2_FOUR_PHASE_DEVELOPMENT_WORKLIST_V1',
        'policy': ['ORIGINAL_PHASE_SNAPSHOT', 'ORIGINAL_SMALL_ENTRY_UNION_CORE',
                   'ADAPT_DETERMINISTIC_ORDER',
                   'ADAPT_DIRECT_CALL_EVIDENCE_FOR_BIG_ONLY'],
        'phase_order': list(PHASES),
        'worklist': worklist,
        'unassigned': unassigned,
        'warnings': sorted(warnings, key=lambda row: (
            row['direction_id'], row['function_id'], row['reason'])),
        'counts': {
            'catalog_functions': len(ids),
            'distinct_functions_scanned_if_executed': len(assigned_ids),
            'direction_function_jobs': len(worklist),
            'distinct_catalog_functions_accounted': len(assigned_ids | unassigned_ids),
            'unassigned_records': len(unassigned),
            'warning_records': len(warnings),
            'phases': {phase: len(by_phase[phase]) for phase in PHASES},
            'unassigned_reasons': dict(sorted(Counter(
                row['reason'] for row in unassigned).items())),
        },
    }


def build_from_pinned_run(run_dir: Path, history_path: Path | None = None) -> dict[str, Any]:
    """Validate a saved dev Direction run and emit a worklist only."""
    sys.path.insert(0, str(PRODUCT / 'src'))
    from vulnerabilityanalysis.direction_plan import (  # noqa: E402
        DEV_FIRST_PASS_POLICY, validate_dev_direction_outputs)
    from vulnerabilityanalysis.models import NormalizedHarness  # noqa: E402
    from vulnerabilityanalysis.scheduler import (  # noqa: E402
        _indirect_candidate_walk, _load_call_graph, _static_walk)

    run_dir = run_dir.resolve(strict=True)
    names = ('run.json', 'harness.json', 'workers.json', 'directions.json',
             'function_pool.json', 'direction_plan.json')
    paths = {name: run_dir / name for name in names}
    input_hashes = {name: _sha(path) for name, path in paths.items()
                    if path.is_file() and not path.is_symlink()}
    if len(input_hashes) != len(paths):
        raise ValueError('pinned run input missing or linked')
    run, harness_row, directions, pool_rows = (
        _read_json(paths[name]) for name in
        ('run.json', 'harness.json', 'directions.json', 'function_pool.json'))
    if (run.get('selection_policy') != DEV_FIRST_PASS_POLICY or
            run.get('source_kind') != 'official_oss_fuzz' or
            run.get('direction_source_kind') != 'PINNED_MODEL_PROPOSAL' or
            run.get('direction_plan_sha256') != input_hashes['direction_plan.json'] or
            run.get('function_count') != len(pool_rows) or
            run.get('direction_count') != len(directions)):
        raise ValueError('run lacks pinned development Direction inputs')
    harness = NormalizedHarness(**harness_row)
    validate_dev_direction_outputs(harness, paths['direction_plan.json'],
                                   input_hashes['direction_plan.json'], directions)
    catalog = harness.function_catalog
    if (not isinstance(pool_rows, list) or
            {r.get('function_id') for r in pool_rows} !=
            {r.get('function_id') for r in catalog.values()} or
            len(pool_rows) != len(catalog)):
        raise ValueError('Pool and official Catalog identities differ')
    direct, _, graph_path, audit = _load_call_graph(harness)
    if (audit['graph_state'] != 'READ' or
            any(row['status'] != 'RESOLVED_EDGE' for row in audit['rows']) or
            not graph_path):
        raise ValueError('direct call graph is not wholly resolved')
    indirect: dict[str, set[str]] = {}
    for row in directions:
        entries = row['entry_functions']
        reached, _ = _static_walk(entries, direct)
        candidates, _ = _indirect_candidate_walk(harness, reached, direct)
        indirect[row['direction_id']] = set(candidates)
    if history_path is None:
        history: dict[str, list[str]] = {}
        history_status = 'NO_PRIOR_ANALYSIS_RECORDED'
    else:
        history_row = _read_json(history_path)
        if (not isinstance(history_row, dict) or
                history_row.get('kind') != 'FBV2_DIRECTION_ANALYSIS_HISTORY_V1' or
                not isinstance(history_row.get('analyzed_by_directions'), dict)):
            raise ValueError('history requires explicit per-function Direction IDs')
        history = history_row['analyzed_by_directions']
        history_status = 'EXPLICIT_PINNED_HISTORY'
        input_hashes['analysis_history.json'] = _sha(history_path)
    result = build_phase_worklist(catalog, directions, direct, history,
                                  indirect_candidates=indirect)
    result.update({
        'scope': 'PROVIDER_FREE_WORKLIST_ONLY_NO_SCAN',
        'history_status': history_status,
        'input_hashes': input_hashes,
        'graph_sha256': _sha(Path(graph_path)),
        'graph_audit': {k: audit[k] for k in ('graph_state', 'resolved_edges',
                                             'ambiguous_graph_rows',
                                             'unknown_id_rows')},
        'cost': {'model_calls': 0, 'target_runs': 0, 'fuzz_seconds': 0},
        'limitations': [
            'No Direction, function, SP/HP, Target, or Fuzzer execution occurred.',
            'Job count is a precomputed worklist size, not executed scans or cost.',
            'Without explicit history, saved selection reservations are not prior analyses.',
            'History Direction IDs outside the current plan still count as prior analysis; '
            'their provenance is unverified and reported as warnings.',
            'The worklist is not product Scheduler integration or Blind 3 readiness.',
            'Core stays in Small without a direct Entry path; warnings record that gap.',
            'No-Entry Directions have no Big pool; unverified indirect paths remain UNASSIGNED.',
            'Order within each Direction/phase is function_id order; upstream set order is unstable.',
            'Unresolved direct-edge rows cause a fail-closed stop; upstream may skip such rows.',
            'The saved run pins direction_plan.json SHA; the plan pins Catalog and graph SHA. '
            'This tool validates their current bytes but makes no Target execution claim.',
        ],
    })
    if input_hashes != {name: _sha(path) for name, path in paths.items()} | (
            {'analysis_history.json': _sha(history_path)} if history_path else {}):
        raise ValueError('pinned input changed while building worklist')
    return result


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--history', type=Path)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(args.out)
    result = build_from_pinned_run(args.run, args.history)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n',
                        encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
