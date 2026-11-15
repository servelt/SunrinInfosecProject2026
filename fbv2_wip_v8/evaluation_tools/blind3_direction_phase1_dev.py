"""Development-only model Direction to product Phase 1 integration.

The caller pins this code, supervises the provider and audits events. This
module has no live CLI and does not authorize a Blind 3 execution.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

PREP = Path(__file__).resolve().parents[1]
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path[:0] = [str(PREP / 'review_tools'), str(PRODUCT / 'src')]

from development_direction_study import (  # noqa: E402
    INSTRUCTIONS, SCHEMA, build_context_from_artifact, entry_core_gaps,
    validate_response)
from blind3_direction_context_windows_dev import (  # noqa: E402
    build_windowed_context_from_artifact)
from dev_global_appserver_bridge import artifact_hash, request_hash  # noqa: E402
from dev_global_request_ledger import DevelopmentRequestLedger  # noqa: E402
from vulnerabilityanalysis.adapter import HarnessAdapter  # noqa: E402
from vulnerabilityanalysis.direction_plan import (  # noqa: E402
    DEV_FIRST_PASS_POLICY, build_planned_directions)
from vulnerabilityanalysis.llm import LLMRequest  # noqa: E402
from vulnerabilityanalysis.scheduler import build_workers  # noqa: E402
from vulnerabilityanalysis.workflow import direction_worker_ids, run_phase1  # noqa: E402


# FBv2's Direction Agent uses tools iteratively. This opt-in, tool-free graph
# correction is a bounded development adaptation, not execution equivalence.
GRAPH_PATH_INSTRUCTIONS = INSTRUCTIONS + (
    "Every Core must have a supplied direct or indirect graph path from an "
    "Entry in the same Direction. An Entry may appear in multiple Directions "
    "when the graph supports both claims. Indirect references are candidate "
    "evidence, not runtime proof. Change unsupported role memberships rather "
    "than inventing edges or vulnerabilities.\n")
REPAIR_INSTRUCTIONS = GRAPH_PATH_INSTRUCTIONS + (
    "Correct the listed Entry-to-Core graph gaps in the previous response. "
    "Return the complete JSON response under the same schema.\n")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_json(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def plain(path: Path, *, directory: bool) -> None:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or
            not (path.is_dir() if directory else path.is_file())):
        raise ValueError(f'Direction input missing or linked: {path}')


async def execute_direction_phase1(
        *, output: Path, artifact: Path, target_repository: Path,
        oss_fuzz_checkout: Path, upstream_checkout: Path, backend: Any,
        ledger: DevelopmentRequestLedger,
        role_models: dict[str, dict[str, str]], scope_id: str,
        source_mode: str = 'all_catalog_prefix',
        direction_graph_repair_max_turns: int = 1) -> dict:
    """Spend one or two accounted Direction turns before explicit Phase 1."""
    output, artifact, target_repository = map(
        Path, (output, artifact, target_repository))
    oss_fuzz_checkout, upstream_checkout = map(
        Path, (oss_fuzz_checkout, upstream_checkout))
    if (not output.is_absolute() or output.exists() or output.is_symlink() or
            not output.parent.is_dir() or output.parent.is_symlink() or
            any(parent.is_symlink() for parent in output.parents) or
            output.parent.resolve(strict=True) != output.parent):
        raise ValueError('Direction output must be a fresh absolute directory')
    for path in (artifact, target_repository, oss_fuzz_checkout, upstream_checkout):
        plain(path, directory=True)
    route = role_models.get('direction_generator')
    if (source_mode not in {'graph24', 'all_catalog_prefix',
                            'stratified_callsite_800'} or
            not isinstance(scope_id, str) or not scope_id or
            backend.ledger is not ledger or
            not isinstance(route, dict) or set(route) != {'model', 'reasoning'} or
            any(not isinstance(value, str) or not value for value in route.values()) or
            getattr(backend, 'scope_id', None) is not None or
            type(direction_graph_repair_max_turns) is not int or
            direction_graph_repair_max_turns not in (1, 2) or
            direction_graph_repair_max_turns == 2 and
                ledger.budget.direction_turns_per_scope != 2):
        raise ValueError('Direction development route or scope invalid')
    guarded_routes = getattr(backend, 'role_models', None)
    if (guarded_routes is not None and
            guarded_routes.get('direction_generator') != route):
        raise ValueError('Direction model differs from guarded route')
    ledger.wall()
    def inputs() -> tuple[dict, dict]:
        if source_mode == 'stratified_callsite_800':
            return build_windowed_context_from_artifact(
                artifact, target_repository, oss_fuzz_checkout=oss_fuzz_checkout,
                upstream_checkout=upstream_checkout)
        return build_context_from_artifact(
            artifact, target_repository, oss_fuzz_checkout=oss_fuzz_checkout,
            upstream_checkout=upstream_checkout, source_mode=source_mode)
    context, pins = inputs()
    needed = {'harness_sha256', 'functions_sha256', 'edges_sha256',
              'indirect_edges_sha256', 'source_files_sha256'}
    if (not isinstance(context, dict) or not isinstance(pins, dict) or
            not needed <= pins.keys() or
            not isinstance(pins['source_files_sha256'], dict)):
        raise ValueError('Direction context has incomplete source pins')
    def recheck() -> None:
        if inputs() != (context, pins):
            raise ValueError('Direction input changed during model or Phase 1')
    output.mkdir(mode=0o700)
    if stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise ValueError('Direction output is not private')
    private_json(output / 'DIRECTION_INPUT_PINS.json', {
        'kind': 'BLIND3_DIRECTION_INPUT_DEV_V1', 'source_mode': source_mode,
        'pins': pins, 'context_sha256': hashlib.sha256(json.dumps(
            context, sort_keys=True, ensure_ascii=False,
            separators=(',', ':')).encode()).hexdigest()})
    if scope_id in ledger.direction_counts:
        raise ValueError('Direction scope already registered')
    initial_logical, initial_physical = ledger.logical, ledger.physical
    async def generate(instructions: str, payload: dict, request_name: str,
                       raw_name: str) -> tuple[dict, Path, Path]:
        request_path, raw_path = output / request_name, output / raw_name
        request = LLMRequest(
            role='direction_generator', instructions=instructions, payload=payload,
            output_schema=SCHEMA, model=route['model'], effort=route['reasoning'],
            raw_response_path=raw_path)
        private_json(request_path, {
            'role': request.role, 'instructions': request.instructions,
            'payload': request.payload, 'output_schema': request.output_schema,
            'model': request.model, 'reasoning': request.effort})
        digest = request_hash(request)
        if artifact_hash(json.loads(request_path.read_text())) != digest:
            raise ValueError('Direction request artifact differs from guarded request')
        if ledger.logical == initial_logical:
            ledger.register_direction(scope_id)
        before_logical, before_physical = ledger.logical, ledger.physical
        backend.bind_scope(scope_id)
        try:
            response = await backend.generate(request)
        finally:
            backend.unbind_scope()
        if (ledger.tainted or ledger.active_turn is not None or
                ledger.direction_counts.get(scope_id) !=
                    ledger.logical - initial_logical or
                ledger.logical != before_logical + 1 or
                ledger.physical <= before_physical or
                ledger.turns[-1]['status'] != 'COMPLETED' or
                ledger.turns[-1]['hash'] != digest or
                not any(row['scope_id'] == scope_id and
                        row['request_hash'] == digest and row['status'] == 'COMPLETED'
                        for row in ledger.attempts[before_physical:])):
            raise ValueError('Direction request lacks a completed physical ledger record')
        if (not raw_path.is_file() or raw_path.is_symlink() or
                stat.S_IMODE(raw_path.stat().st_mode) != 0o600):
            raise ValueError('Direction raw response missing or not private')
        try:
            recorded_response = json.loads(raw_path.read_text(encoding='utf-8'))
        except (UnicodeError, ValueError) as exc:
            raise ValueError('Direction raw response is not valid JSON') from exc
        if recorded_response != response:
            raise ValueError('Direction raw response differs from returned model object')
        ledger.wall()
        recheck()
        return response, request_path, raw_path

    response, request_path, raw_path = await generate(
        GRAPH_PATH_INSTRUCTIONS if direction_graph_repair_max_turns == 2 else INSTRUCTIONS,
        context, 'DIRECTION_REQUEST.json', 'DIRECTION_RAW.txt')
    repair_request_path = repair_raw_path = repair_status_path = None
    try:
        validated = validate_response(response, context)
    except ValueError as exc:
        if (direction_graph_repair_max_turns != 2 or
                str(exc) != 'Direction Entry-to-Core graph path is not established'):
            raise
        gaps = entry_core_gaps(response, context)
        if not gaps:
            raise
        gap_ids = {fid for gap in gaps for fid in
                   gap['entry_function_ids'] + gap['core_ids_without_path']}
        payload = {'original_context': context, 'previous_response': response,
                   'graph_gaps': gaps,
                   'adjacent_recorded_edges': [list(edge) for edge in
                       context['direct_edges'] +
                       context['indirect_references_unverified']
                       if edge[0] in gap_ids or edge[1] in gap_ids]}
        try:
            repaired, repair_request_path, repair_raw_path = await generate(
                REPAIR_INSTRUCTIONS, payload, 'DIRECTION_REPAIR_REQUEST.json',
                'DIRECTION_REPAIR_RAW.txt')
            validated = validate_response(repaired, context)
        except BaseException as repair_exc:
            # A status-write failure must never replace a provider, cleanup,
            # cancellation, or budget exception from the physical turn.
            try:
                private_json(output / 'DIRECTION_REPAIR_STATUS.json', {
                    'kind': 'DIRECTION_GRAPH_REPAIR_DEV_V1', 'status': 'REJECTED',
                    'reason_type': type(repair_exc).__name__,
                    'first_request_sha256': sha(request_path),
                    'first_raw_sha256': sha(raw_path),
                    'repair_request_sha256': sha(output / 'DIRECTION_REPAIR_REQUEST.json')
                        if (output / 'DIRECTION_REPAIR_REQUEST.json').is_file() else None,
                    'repair_raw_sha256': sha(output / 'DIRECTION_REPAIR_RAW.txt')
                        if (output / 'DIRECTION_REPAIR_RAW.txt').is_file() else None,
                    'direction_turn_count': ledger.direction_counts[scope_id]})
            except BaseException:
                pass
            raise
        response = repaired
        repair_status_path = output / 'DIRECTION_REPAIR_STATUS.json'
        private_json(repair_status_path, {
            'kind': 'DIRECTION_GRAPH_REPAIR_DEV_V1', 'status': 'VALIDATED',
            'reason_type': None, 'first_request_sha256': sha(request_path),
            'first_raw_sha256': sha(raw_path),
            'repair_request_sha256': sha(repair_request_path),
            'repair_raw_sha256': sha(repair_raw_path),
            'direction_turn_count': ledger.direction_counts[scope_id]})
    plan = {'kind': 'DEVELOPMENT_DIRECTION_PLAN_V1',
            **{name: pins[name] for name in (
                'harness_sha256', 'functions_sha256', 'edges_sha256',
                'indirect_edges_sha256')}, 'response': validated}
    plan_path = output / 'DIRECTION_PLAN.json'
    plan_bytes = (json.dumps(plan, sort_keys=True, ensure_ascii=False, indent=2)
                  + '\n').encode()
    plan_sha = hashlib.sha256(plan_bytes).hexdigest()
    harness = HarnessAdapter().load(artifact, target_repository=target_repository)
    for worker in build_workers(harness):
        build_planned_directions(harness, worker, plan, plan_path=plan_path,
                                 plan_sha256=plan_sha, stable_unscoped_id=True)
    recheck()
    private_json(plan_path, plan)
    if sha(plan_path) != plan_sha:
        raise ValueError('Direction plan serialization changed')
    run = run_phase1(artifact, output / 'product_runs',
                     target_repository=target_repository,
                     direction_plan=plan_path,
                     selection_policy=DEV_FIRST_PASS_POLICY)
    recheck()
    run_row = json.loads((run / 'run.json').read_text())
    directions = json.loads((run / 'directions.json').read_text())
    pool = json.loads((run / 'function_pool.json').read_text())
    workers = json.loads((run / 'workers.json').read_text())
    owners = direction_worker_ids(directions)
    ids = {row['function_id'] for row in harness.function_catalog.values()}
    expected = {(worker['worker_id'], fid) for worker in workers for fid in ids}
    actual = [(owners.get(row['direction_id']), row['function_id']) for row in pool]
    if (run_row.get('direction_source_kind') != 'PINNED_MODEL_PROPOSAL' or
            run_row.get('direction_plan_sha256') != plan_sha or
            run_row.get('selection_policy') != DEV_FIRST_PASS_POLICY or
            (run / 'direction_plan.json').read_bytes() != plan_bytes or
            len(actual) != len(set(actual)) or set(actual) != expected):
        raise ValueError('Phase 1 did not preserve pinned Direction and full Pool')
    result = {
        'kind': 'BLIND3_DIRECTION_PHASE1_DEV_V1',
        'status': 'DIRECTION_PHASE1_PREPARED_DEV',
        'scope': 'development integration only; no Blind 3 execution approval',
        'phase1_run': str(run), 'selection_policy': DEV_FIRST_PASS_POLICY,
        'direction_plan_sha256': plan_sha,
        'direction_request_sha256': sha(request_path),
        'direction_raw_sha256': sha(raw_path),
        'direction_logical_turn_id': ledger.turns[-1]['id'],
        'direction_physical_starts': ledger.physical - initial_physical,
        'ledger_checkpoint_sha256': sha(ledger.checkpoint_path),
        'source_pins_sha256': sha(output / 'DIRECTION_INPUT_PINS.json'),
        'worker_count': len(workers), 'direction_count': len(directions),
        'pool_count': len(pool)}
    if direction_graph_repair_max_turns == 2:
        result.update({
            'direction_turn_count': ledger.logical - initial_logical,
            'direction_repair_request_sha256': sha(repair_request_path)
                if repair_request_path else None,
            'direction_repair_raw_sha256': sha(repair_raw_path)
                if repair_raw_path else None,
            'direction_repair_status_sha256': sha(repair_status_path)
                if repair_status_path else None})
    private_json(output / 'DIRECTION_PHASE1_RESULT.json', result)
    return result
