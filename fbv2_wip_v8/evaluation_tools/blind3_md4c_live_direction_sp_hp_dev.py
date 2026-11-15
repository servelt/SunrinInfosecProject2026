"""Official V2 md4c Direction -> Phase 1 -> SP/HP development smoke bridge.

This is an opt-in library, not a Blind 3 runner or approval path. The caller
owns the App Server, process supervisor, and externally pinned role routes.
Matching caller/backend routes here is not live execution authorization.
This bridge checks the first SP/HP turns only; a full candidate worklist needs
a separate, explicitly supervised development driver.
"""

from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
PREP = HERE.parent
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path[:0] = [str(HERE), str(PREP / 'review_tools'), str(PRODUCT / 'src')]

from blind3_direction_phase1_dev import (  # noqa: E402
    execute_direction_phase1, plain, private_json, sha)
from blind3_direction_context_windows_dev import (  # noqa: E402
    build_windowed_context_from_artifact)
from dev_global_appserver_bridge import (  # noqa: E402
    DevelopmentGlobalAppServer, artifact_hash, verify_model_event_order,
    verify_product_request_order)
from dev_global_appserver_product_flow import (  # noqa: E402
    DevelopmentBudgetStop, ProductBudgetAdapter)
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE,
    PER_FUNCTION_V2_PROFILE)
from dev_phase1_chain_pin import (  # noqa: E402
    issue_pin, verify_pin, verify_pin_after_model)
from development_direction_study import build_context_from_artifact  # noqa: E402
from vulnerabilityanalysis.direction_plan import DEV_FIRST_PASS_POLICY  # noqa: E402
from vulnerabilityanalysis.official_harness import (  # noqa: E402
    OfficialPinnedQualification, _qualification_pins_ok)
from vulnerabilityanalysis.scan import scan_selected  # noqa: E402


V2_KIND = 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2'
ROLES = ('direction_generator', 'sp_generation', 'function_analysis')


def _phase1_pin_path(output: Path) -> Path:
    return output / 'EVALUATOR_PHASE1_PINS' / 'PHASE1_PREMODEL_PIN.json'


class SmokeBoundaryStop(BaseException):
    """The narrow bridge must not dispatch later SP/HP or runtime stages."""


class _SmokeProductBudgetAdapter(ProductBudgetAdapter):
    def __init__(self, backend, ledger, scope_id: str, pin_path: Path):
        super().__init__(backend, ledger, scope_id)
        self.pin_path = Path(pin_path)

    async def generate(self, request):
        if request.role not in ROLES[1:]:
            raise SmokeBoundaryStop(
                f'SP/HP smoke bridge cannot send role {request.role}')
        try:
            pin = verify_pin_after_model(self.pin_path)
            if pin['selected_function_id'] != self.scope_id:
                raise ValueError('selected function differs from Phase 1 pin')
        except ValueError as exc:
            raise SmokeBoundaryStop(
                'Phase 1 evaluator pin changed before model request') from exc
        return await super().generate(request)


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def _direction_pins_unchanged(output: Path, artifact: Path,
                              target_repository: Path, oss_fuzz_checkout: Path,
                              upstream_checkout: Path, source_mode: str) -> bool:
    saved = _read(output / 'DIRECTION_INPUT_PINS.json')
    if source_mode == 'stratified_callsite_800':
        context, pins = build_windowed_context_from_artifact(
            artifact, target_repository, oss_fuzz_checkout=oss_fuzz_checkout,
            upstream_checkout=upstream_checkout)
    else:
        context, pins = build_context_from_artifact(
            artifact, target_repository, oss_fuzz_checkout=oss_fuzz_checkout,
            upstream_checkout=upstream_checkout, source_mode=source_mode)
    digest = hashlib.sha256(json.dumps(
        context, sort_keys=True, ensure_ascii=False,
        separators=(',', ':')).encode()).hexdigest()
    return (saved.get('source_mode') == source_mode and
            saved.get('pins') == pins and saved.get('context_sha256') == digest)


def _official_preflight(artifact: Path, target_repository: Path,
                        oss_fuzz_checkout: Path, upstream_checkout: Path,
                        qualification: OfficialPinnedQualification) -> None:
    for path in (artifact, target_repository, oss_fuzz_checkout, upstream_checkout):
        plain(path, directory=True)
    if (not isinstance(qualification, OfficialPinnedQualification) or
            not qualification.product_issued or
            qualification.contract_kind != V2_KIND or
            qualification.source_root != target_repository or
            qualification.oss_fuzz_checkout != oss_fuzz_checkout or
            qualification.upstream_checkout != upstream_checkout or
            qualification.harness.parent != artifact or
            not _qualification_pins_ok(qualification)):
        raise ValueError('official V2 qualification or local pins differ')


def _postcheck(output: Path, artifact: Path, target_repository: Path,
               oss_fuzz_checkout: Path, upstream_checkout: Path,
               qualification: OfficialPinnedQualification,
               source_mode: str, direction: dict,
               ledger: DevelopmentRequestLedger,
               backend: DevelopmentGlobalAppServer,
               pool_ids: list[str], *, phase1_pin: Path | None = None) -> None:
    """Require unchanged inputs and a restorable ledger before any result."""
    _official_preflight(artifact, target_repository, oss_fuzz_checkout,
                        upstream_checkout, qualification)
    if phase1_pin is not None:
        pin = verify_pin_after_model(phase1_pin)
        if (pin['run_dir'] != direction['phase1_run'] or
                pin['direction_plan_sha256'] != direction['direction_plan_sha256']):
            raise ValueError('Phase 1 evaluator pin identity changed')
    evidence_paths = {
        'direction_request_sha256': output / 'DIRECTION_REQUEST.json',
        'direction_raw_sha256': output / 'DIRECTION_RAW.txt',
        'direction_plan_sha256': output / 'DIRECTION_PLAN.json',
        'source_pins_sha256': output / 'DIRECTION_INPUT_PINS.json',
    }
    direction_turn_count = direction.get('direction_turn_count', 1)
    if direction_turn_count not in (1, 2):
        raise ValueError('Direction turn count invalid')
    if direction_turn_count == 2:
        evidence_paths.update({
            'direction_repair_request_sha256': output / 'DIRECTION_REPAIR_REQUEST.json',
            'direction_repair_raw_sha256': output / 'DIRECTION_REPAIR_RAW.txt',
            'direction_repair_status_sha256': output / 'DIRECTION_REPAIR_STATUS.json',
        })
    elif any(direction.get(name) is not None for name in (
            'direction_repair_request_sha256', 'direction_repair_raw_sha256',
            'direction_repair_status_sha256')):
        raise ValueError('Direction repair evidence without second turn')
    result_path = output / 'DIRECTION_PHASE1_RESULT.json'
    for path in (*evidence_paths.values(), result_path,
                 Path(direction['phase1_run']) / 'direction_plan.json'):
        plain(path, directory=False)
    if (_read(result_path) != direction or any(
            sha(path) != direction.get(field)
            for field, path in evidence_paths.items()) or
            sha(Path(direction['phase1_run']) / 'direction_plan.json') !=
            direction.get('direction_plan_sha256')):
        raise ValueError('Direction stored request, raw or plan evidence changed')
    request_paths = [output / 'DIRECTION_REQUEST.json']
    if direction_turn_count == 2:
        request_paths.append(output / 'DIRECTION_REPAIR_REQUEST.json')
        repair = _read(output / 'DIRECTION_REPAIR_STATUS.json')
        if (repair.get('kind') != 'DIRECTION_GRAPH_REPAIR_DEV_V1' or
                repair.get('status') != 'VALIDATED' or
                repair.get('direction_turn_count') != 2 or
                repair.get('first_request_sha256') != direction['direction_request_sha256'] or
                repair.get('first_raw_sha256') != direction['direction_raw_sha256'] or
                repair.get('repair_request_sha256') !=
                    direction['direction_repair_request_sha256'] or
                repair.get('repair_raw_sha256') !=
                    direction['direction_repair_raw_sha256']):
            raise ValueError('Direction repair result or evidence changed')
    scopes = ledger.direction_scopes
    if (len(scopes) != 1 or
            ledger.direction_counts.get(scopes[0]) != direction_turn_count or
            len(ledger.turns) < direction_turn_count or
            direction.get('direction_logical_turn_id') !=
                ledger.turns[direction_turn_count - 1]['id'] or
            direction.get('direction_physical_starts') != sum(
                attempt.get('scope_id') == scopes[0]
                for attempt in ledger.attempts) or
            any(turn['scope_id'] != scopes[0] or
                turn['role'] != 'direction_generator' or
                turn['status'] != 'COMPLETED' or
                turn['hash'] != artifact_hash(_read(path))
                for turn, path in zip(ledger.turns[:direction_turn_count],
                                      request_paths))):
        raise ValueError('Direction requests differ from physical ledger')
    if not _direction_pins_unchanged(
            output, artifact, target_repository, oss_fuzz_checkout,
            upstream_checkout, source_mode):
        raise ValueError('Direction input pins changed during development flow')
    if ledger.tainted or ledger.active_turn is not None:
        raise ValueError('development ledger is active or tainted')
    restored = DevelopmentRequestLedger.restore(ledger.checkpoint_path,
                                                ledger.budget)
    if (any(getattr(restored, field.name) != getattr(ledger, field.name)
            for field in fields(DevelopmentRequestLedger)) or
            restored.summary(pool_ids) != ledger.summary(pool_ids)):
        raise ValueError('restored development opportunity differs')
    verify_model_event_order(restored, backend.event_log_path)
    log = Path(direction['phase1_run']) / 'logs/agent_requests.jsonl'
    rows = [json.loads(line) for line in log.read_text().splitlines()] if \
        log.is_file() else []
    if not restored.selected_functions:
        if rows:
            raise ValueError('unselected development Scan has product requests')
        return
    if len(restored.selected_functions) != 1:
        raise ValueError('development Scan selected more than one function')
    fid = restored.selected_functions[0]
    turns = [row for row in restored.turns if row['scope_id'] == fid]
    if (len(rows) < len(turns) or len(rows) > len(turns) + 1 or
            len(rows) > len(turns) and (
                restored.function_states[fid] != 'INCOMPLETE_BUDGET' or
                rows[-1].get('status') != 'INCOMPLETE')):
        raise ValueError('product request count differs from restored ledger')
    verify_product_request_order(
        restored, [Path(row['request_artifact']) for row in rows[:len(turns)]],
        scope_id=fid)


def _result(output: Path, run: Path, direction: dict, ledger: DevelopmentRequestLedger,
            pool_count: int, status: str, *, scan: bool,
            external_global_dev: bool = False) -> dict:
    row = {
        'kind': 'BLIND3_MD4C_DIRECTION_SP_HP_DEV_V1', 'status': status,
        'scope': ('official V2 md4c development only; caller must pin role '
                  'routes externally; not live authorization or Blind 3 approval'),
        'phase1_run': str(run), 'pool_count': pool_count,
        'selection_policy': DEV_FIRST_PASS_POLICY,
        'direction_plan_sha256': direction['direction_plan_sha256'],
        'physical': ledger.physical, 'logical': ledger.logical,
        'retries': ledger.retries, 'target_runs': 0, 'fuzz_seconds': 0,
        'vulnerability_verdict': 'NOT_EVALUATED',
        'ledger_checkpoint_sha256': sha(ledger.checkpoint_path),
        'phase1_pin_sha256': sha(_phase1_pin_path(output)),
    }
    if scan:
        row['scan_sha256'] = sha(run / 'scan.json')
    if external_global_dev:
        row['budget_profile'] = GLOBAL_ONLY_DEV_PROFILE
    private_json(output / 'DEV_DIRECTION_SP_HP_RESULT.json', row)
    return row


async def execute_official_v2_direction_sp_hp(
        *, output: Path, artifact: Path, target_repository: Path,
        oss_fuzz_checkout: Path, upstream_checkout: Path,
        qualification: OfficialPinnedQualification,
        backend: DevelopmentGlobalAppServer, ledger: DevelopmentRequestLedger,
        role_models: dict[str, dict[str, str]], scope_id: str,
        source_mode: str = 'all_catalog_prefix',
        external_global_dev: bool = False) -> dict:
    """Account for live Direction, then one SP and one HP on its Phase 1 pick.

    The provider is caller-owned. No verifier, PoV, Assertion or Fuzzer runs.
    Every result remains unverified; this function cannot issue a finding.
    """
    output, artifact, target_repository = map(
        Path, (output, artifact, target_repository))
    oss_fuzz_checkout, upstream_checkout = map(
        Path, (oss_fuzz_checkout, upstream_checkout))
    _official_preflight(artifact, target_repository, oss_fuzz_checkout,
                        upstream_checkout, qualification)
    routes = getattr(backend, 'role_models', None)
    if (type(external_global_dev) is not bool or
            ledger.budget.profile != (GLOBAL_ONLY_DEV_PROFILE if
                                      external_global_dev else
                                      PER_FUNCTION_V2_PROFILE)):
        raise ValueError('development budget profile or adapter opt-in differs')
    if (external_global_dev and
            min(ledger.budget.physical_max, ledger.budget.logical_max) > 4):
        raise ValueError('SP/HP smoke bridge cannot run verifier or PoV turns')
    if (backend.ledger is not ledger or
            getattr(backend, 'scope_id', None) is not None or
            ledger.tainted or ledger.active_turn is not None or
            ledger.logical != 0 or ledger.physical != 0 or
            ledger.direction_scopes or ledger.selected_functions or
            ledger.budget.initial_starts_required != 2 or
            not external_global_dev and (
                ledger.budget.sp_per_function != 1 or
                ledger.budget.hp_per_function != 1 or
                ledger.budget.combined_per_function != 2 or
                ledger.budget.hp_analysis_per_function != 1) or
            ledger.budget.retries_max != 0 or
            not isinstance(routes, dict) or
            not all(role in role_models and role_models[role] == routes.get(role)
                    for role in ROLES)):
        raise ValueError('development ledger, role route or SP/HP cap differs')
    direction = await execute_direction_phase1(
        output=output, artifact=artifact,
        target_repository=target_repository,
        oss_fuzz_checkout=oss_fuzz_checkout,
        upstream_checkout=upstream_checkout, backend=backend,
        ledger=ledger, role_models=role_models, scope_id=scope_id,
        source_mode=source_mode)
    if (direction['status'] != 'DIRECTION_PHASE1_PREPARED_DEV' or
            ledger.physical != 1 or ledger.logical != 1 or
            ledger.turns[0]['role'] != 'direction_generator' or
            ledger.turns[0]['status'] != 'COMPLETED'):
        raise ValueError('Direction and Phase 1 lack one completed model turn')
    _official_preflight(artifact, target_repository, oss_fuzz_checkout,
                        upstream_checkout, qualification)
    run = Path(direction['phase1_run'])
    selection, phase1, pool = (_read(run / name) for name in (
        'selection.json', 'run.json', 'function_pool.json'))
    ids = [row['function_id'] for row in pool]
    fid = selection.get('function_id')
    if (not isinstance(fid, str) or len(ids) != len(set(ids)) or
            fid not in ids or phase1.get('selected_function_id') != fid or
            phase1.get('direction_source_kind') != 'PINNED_MODEL_PROPOSAL' or
            phase1.get('direction_plan_sha256') != direction['direction_plan_sha256'] or
            phase1.get('selection_policy') != DEV_FIRST_PASS_POLICY or
            direction['selection_policy'] != DEV_FIRST_PASS_POLICY or
            sha(run / 'direction_plan.json') != direction['direction_plan_sha256']):
        raise ValueError('selected Phase 1 identity or pinned policy changed')
    pin_path = _phase1_pin_path(output)
    pin_path.parent.mkdir(mode=0o700)
    issued_pin = issue_pin(run, pin_path)
    if (issued_pin['selected_function_id'] != fid or
            verify_pin(pin_path) != issued_pin):
        raise ValueError('Phase 1 evaluator pin differs before model request')
    if not ledger.select_function(fid):
        _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
                   upstream_checkout, qualification, source_mode, direction,
                   ledger, backend, ids, phase1_pin=pin_path)
        return _result(output, run, direction, ledger, len(ids),
                       'NO_OPPORTUNITY_BUDGET', scan=False,
                       external_global_dev=external_global_dev)
    backend.bind_scope(fid)
    provider = _SmokeProductBudgetAdapter(backend, ledger, fid, pin_path)
    stopped = False
    try:
        budget_options = ({'external_turn_budget': ledger,
                           'candidate_budget_policy': 'DRAIN_RANKED_DEV'}
                          if external_global_dev else
                          {'sp_llm_call_limit': 1, 'hp_llm_call_limit': 1})
        await scan_selected(
            run, provider, target_repository=target_repository,
            target_binary=qualification.binary,
            official_qualification=qualification, role_models=role_models,
            hallucination_prevent='on', hp_context_round_limit=0,
            max_candidates=2, targeted_fuzz_seconds=0,
            assertion_fuzz_seconds=0, global_fuzz_enabled=False,
            run_command=None, initial_inputs=None, **budget_options)
    except DevelopmentBudgetStop:
        if (run / 'scan.json').exists():
            raise ValueError('budget-stopped Scan was saved as complete')
        stopped = True
    finally:
        backend.unbind_scope()
    if stopped:
        _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
                   upstream_checkout, qualification, source_mode, direction,
                   ledger, backend, ids, phase1_pin=pin_path)
        return _result(output, run, direction, ledger, len(ids),
                       'PENDING_BUDGET', scan=False,
                       external_global_dev=external_global_dev)
    scan = _read(run / 'scan.json')
    if (ledger.physical != 3 or ledger.logical != 3 or ledger.retries != 0 or
            ledger.tainted or ledger.active_turn is not None or
            [row['role'] for row in ledger.turns] != list(ROLES) or
            any(row['status'] != 'COMPLETED' for row in ledger.turns) or
            len(ledger.attempts) != 3 or
            any(row['status'] != 'COMPLETED' or
                row.get('accepted') is not True or
                row.get('response_saved') is not True
                for row in ledger.attempts) or
            scan.get('selected_function_id') != fid or
            scan.get('sp_llm_calls') != 1 or scan.get('hp_llm_calls') != 1 or
            not external_global_dev and
                scan.get('effective_candidate_limit') != 0 or
            scan.get('poc_count') != 0 or scan.get('assertion_count') != 0 or
            scan.get('fuzz_seconds_allocated') != 0 or
            scan.get('verification_artifact_sha256') or scan.get('hp_error')):
        raise ValueError('development Scan or physical request ledger changed')
    if external_global_dev and (
            scan.get('budget_authority') != 'EXTERNAL_GLOBAL_DEV' or
            scan.get('global_budget_profile') != GLOBAL_ONLY_DEV_PROFILE or
            scan.get('candidate_budget_policy') != 'DRAIN_RANKED_DEV' or
            scan.get('sp_llm_call_limit', 'missing') is not None or
            scan.get('hp_llm_call_limit', 'missing') is not None or
            scan.get('global_logical_used') != ledger.logical or
            scan.get('global_physical_used') != ledger.physical or
            scan.get('selected_sp_ids') or
            sorted(scan.get('queued_sp_ids', [])) !=
                sorted(scan.get('pending_sp_ids', []))):
        raise ValueError('global development budget was not applied to Scan')
    log = run / 'logs/agent_requests.jsonl'
    rows = [json.loads(line) for line in log.read_text().splitlines()] if \
        log.is_file() else []
    if len(rows) != 2 or any(row.get('status') != 'COMPLETED' for row in rows):
        raise ValueError('product SP/HP request artifacts not complete')
    verify_product_request_order(
        ledger, [Path(row['request_artifact']) for row in rows], scope_id=fid)
    verify_model_event_order(ledger, backend.event_log_path)
    _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
               upstream_checkout, qualification, source_mode, direction,
               ledger, backend, ids, phase1_pin=pin_path)
    ledger.mark_scan_recorded(fid)
    _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
               upstream_checkout, qualification, source_mode, direction,
               ledger, backend, ids, phase1_pin=pin_path)
    return _result(output, run, direction, ledger, len(ids),
                   'PENDING_UNVERIFIED_DEV', scan=True,
                   external_global_dev=external_global_dev)
