"""A lossless view of a completed or interrupted HarnessCreator run.

This tool NEVER infers proof from a generated filename, backend success, or
an uncorrelated response. It can read partial run artifacts while a run is
still in progress and names exactly which stage lacks evidence.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None
    except (OSError, ValueError):
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    try:
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except ValueError:
                    # An interrupted JSONL append must not hide earlier rows.
                    continue
                if isinstance(data, dict):
                    rows.append(data)
    except OSError:
        return rows
    return rows


def summarize_run(run_root: Path) -> dict[str, Any]:
    run_root = run_root.expanduser().resolve()
    if not run_root.is_dir():
        raise ValueError(f'run directory not found: {run_root}')
    summary = _read_json(run_root/'summary.json')
    lifecycle = _read_jsonl(run_root/'workflow/candidate-lifecycle.jsonl')
    raw_actions = _read_jsonl(run_root/'actions/inventory.jsonl')
    scenarios = _read_jsonl(run_root/'scenarios/candidates.jsonl')
    planned = _read_jsonl(run_root/'harness-plans/plans.jsonl')
    readiness = _read_json(run_root/'harness-plans/build-readiness.json')
    attrition = _read_json(run_root/'workflow/attrition.json')
    preflight = _read_json(run_root/'workflow/capability-preflight.json')
    blockers = Counter()
    for row in lifecycle:
        for item in row.get('obligations', []):
            if isinstance(item, str):
                blockers[item.split(':',1)[0]] += 1
    if isinstance(readiness, dict):
        for item in readiness.get('plans', []):
            if isinstance(item, dict) and item.get('status') == 'UNRESOLVED':
                blockers['BUILD_CLOSURE_UNRESOLVED'] += 1
    if isinstance(preflight, dict):
        for item in preflight.get('verification_blockers', []):
            blockers[str(item).split(':',1)[0]] += 1
    if not lifecycle and raw_actions:
        # Not a substitute for the lifecycle ledger, but enough to see where
        # the pipeline was interrupted without pretending absent = rejected.
        blockers['CANDIDATE_LIFECYCLE_NOT_YET_WRITTEN'] += 1
    report = {
        'run_root': str(run_root),
        'completed': isinstance(summary, dict),
        'summary': summary,
        'action_inventory_count': len(raw_actions),
        'candidate_lifecycle_count': len(lifecycle),
        'scenario_candidates_count': len(scenarios),
        'harness_plans_count': len(planned),
        'build_readiness': readiness,
        'attrition': attrition,
        'blocker_counts': dict(blockers.most_common()),
        'actions': [{
            'action_id': row.get('action_id'),
            'disposition': row.get('disposition','UNKNOWN'),
            'discovery_proof': row.get('discovery_proof'),
            'scenarios': len(row.get('scenario_ids', [])),
            'plans': len(row.get('plan_ids', [])),
            'generated': len(row.get('generated_harness_ids', [])),
            'builds': len(row.get('build_verified_ids', [])),
            'backend_verified': len(row.get('backend_verified_ids', [])),
            'semantic_verified': len(row.get('semantic_verified_ids', [])),
            'obligations': row.get('obligations', []),
        } for row in lifecycle],
        'policy': 'report-only; never upgrades candidate proof or qualification',
    }
    return report


def format_run_report(report: dict[str, Any]) -> str:
    lines = [
        f"Run: {report['run_root']}",
        f"Completed: {report['completed']}",
        f"Actions: {report['action_inventory_count']} discovered / {report['candidate_lifecycle_count']} accounted",
        f"Scenarios: {report['scenario_candidates_count']}, Plans: {report['harness_plans_count']}",
    ]
    if not report['completed']:
        lines.append('Run has no summary.json; counts reflect only written checkpoints.')
    lines.append('Blockers:')
    for name, count in report['blocker_counts'].items():
        lines.append(f'  {name}: {count}')
    if not report['blocker_counts']:
        lines.append('  none recorded (NOT a claim of success)')
    lines.append('Per Action:')
    for action in report['actions']:
        lines.append(
            f"  {action['action_id']}: {action['disposition']}; "
            f"scenarios={action['scenarios']}, plans={action['plans']}, "
            f"generated={action['generated']}, built={action['builds']}, "
            f"semantic={action['semantic_verified']}"
        )
    return '\n'.join(lines)
