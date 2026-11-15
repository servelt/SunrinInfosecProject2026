"""Provider-free official V2 one-function SP/HP candidate handoff test.

This is a development integration fixture, not a live-model or Blind 3 runner.
Its App Server must be a scripted transport. The product may generate a PoV
input, but target execution, Assertion execution, and fuzzing are blocked.
The caller cannot supply an arbitrary product provider: this module creates
ProductBudgetAdapter around the same ledger and scripted backend itself.
The product DRAIN queue interleaves Verifier/PoV; it is not FBV2's separate
pending_verify/pending_pov queues. A real model run needs a physical supervisor
as well as the ledger's pre-request wall check.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
from unittest.mock import patch

from blind3_direction_phase1_dev import execute_direction_phase1, private_json, sha
from blind3_md4c_live_direction_sp_hp_dev import (
    _official_preflight, _postcheck, _read)
from dev_global_appserver_bridge import DevelopmentGlobalAppServer
from dev_global_appserver_product_flow import (
    DevelopmentBudgetStop, ProductBudgetAdapter, ScriptedAppServer)
from dev_global_request_ledger import (
    DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE, FUNCTION_ROLES)
from vulnerabilityanalysis.direction_plan import DEV_FIRST_PASS_POLICY
from vulnerabilityanalysis.official_harness import OfficialPinnedQualification
from vulnerabilityanalysis.scan import scan_selected


ROLES = frozenset(FUNCTION_ROLES | {'direction_generator'})
SAFE = 'synthetic input relation holds at the selected function entry'
_SCRIPTED_METHODS = {name: getattr(ScriptedAppServer, name)
    for name in ('start', '_transport_request', '_thread_for',
                 '_delete_ephemeral_thread', 'close')}


def _source_line(payload: dict) -> tuple[int, str]:
    for row in payload['source'].splitlines():
        match = re.fullmatch(r'(\d+): (.*)', row)
        if match and match.group(2).strip():
            return int(match.group(1)), match.group(2)
    raise AssertionError('selected function source has no numbered line')


class FixedCandidateScriptedAppServer(ScriptedAppServer):
    """Exact fixture type with fixed scripted transport and deterministic replies."""

    def __init__(self, ledger: DevelopmentRequestLedger, root: Path,
                 direction_answer: dict, role_models: dict[str, dict[str, str]],
                 *, fault_mode: str = 'none') -> None:
        if fault_mode not in {'none', 'tool_event_at_verifier',
                              'timeout_at_verifier', 'mutate_route_after_pov'}:
            raise ValueError('unsupported scripted fault')
        super().__init__(ledger, root, direction_answer)
        self.role_models = {role: dict(route) for role, route in role_models.items()}
        self.current_request = None
        self.fault_mode = fault_mode

    async def generate(self, request):
        self.current_request = request
        return await super().generate(request)

    async def _collect(self, thread_id: str, turn_id: str) -> str:
        request = self.current_request
        role = self.ledger.active_turn['role']
        if role == 'sp_verifier' and self.fault_mode == 'timeout_at_verifier':
            raise TimeoutError('scripted provider response deadline')
        payload = request.payload
        if role == 'direction_generator':
            answer = self.direction_answer
        elif role == 'sp_generation':
            line, quote = _source_line(payload)
            answer = {'suspicious_points': [{
                'source_file': payload['analysis']['source_file'],
                'source_line': line, 'source_excerpt': quote,
                'sp_condition': '',
                'suspicious_operation': 'synthetic candidate operation',
                'vulnerability_hypothesis': 'scripted candidate needs verification',
                'trigger_conditions': ['input reaches selected function'],
                'external_input_relation': 'harness input may affect the operation',
                'required_state': [], 'security_property': 'memory safety',
                'supporting_evidence': [], 'contradicting_evidence': [],
                'unknowns': [],
            }]}
        elif role == 'function_analysis':
            line, quote = _source_line(payload)
            answer = {'summary': 'scripted safe premise for model turn handoff',
                'input_flow': 'harness input', 'state_dependencies': [],
                'context_requests': [], 'safe_assumptions': [SAFE],
                'unknowns': [], 'input_sources': [],
                'security_sensitive_operations': [], 'validations': [],
                'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': [{
                    'source_location': f"{payload['source_file']}:{line}",
                    'security_property': 'memory safety',
                    'source_file': payload['source_file'],
                    'source_line': line, 'source_quote': quote,
                    'input_influence': 'INPUT_DEPENDENT',
                    'hypothesis': 'scripted bounded relation',
                    'judgment': 'EXPLICIT_SAFE_JUDGMENT',
                    'reason': 'provider-free stage connection only',
                    'safe_assumption': SAFE,
                }]}
        elif role == 'assertion_generator':
            line, _ = _source_line(payload)
            answer = {'assertions': [{
                'safe_id': 0, 'safe_assumption': SAFE,
                'runtime_expression': '1', 'source_line': line,
                'required_context': [],
                'rationale': 'scripted Assertion handoff, not proof of safety',
            }], 'dispositions': [{
                'safe_id': 0, 'safe_assumption': SAFE,
                'status': 'PROPOSED', 'reason': 'scripted proposed assertion',
            }]}
        elif role == 'sp_verifier':
            answer = {'status': 'PLAUSIBLE', 'supporting_evidence': [],
                'contradicting_evidence': [], 'unknowns': [],
                'rationale': 'scripted candidate remains open',
                'reachability': 'UNKNOWN', 'controllability': 'UNKNOWN',
                'guards': [], 'required_state': [],
                'contradiction_snippet': '', 'contradiction_scope': 'UNKNOWN',
                'context_requests': [],
                'recommended_next_action': 'GENERATE_POC'}
        elif role == 'poc_generator':
            answer = {'generator_script': "def build():\n    return b'A'\n",
                'expected_behavior': 'scripted input, runtime deferred',
                'trigger_rationale': 'provider-free PoV handoff only'}
        else:
            raise AssertionError(f'unexpected scripted role {role}')
        item_type = ('commandExecution' if self.fault_mode ==
                     'tool_event_at_verifier' and role == 'sp_verifier' else
                     'agentMessage')
        self._record_server_event({'method': 'turn/completed', 'params': {
            'threadId': thread_id,
            'turn': {'id': turn_id, 'status': 'completed',
                     'items': [{'type': item_type}]}}})
        if role == 'poc_generator' and self.fault_mode == 'mutate_route_after_pov':
            self.role_models['sp_verifier']['reasoning'] = 'changed-after-turn'
        return json.dumps(answer, sort_keys=True)


_FIXED_GENERATE = FixedCandidateScriptedAppServer.generate
_FIXED_COLLECT = FixedCandidateScriptedAppServer._collect


class DevelopmentExecutionBoundary(BaseException):
    """A provider-free test attempted to run a target, Assertion, or Fuzzer."""


def _forbid_execution(*_args, **_kwargs):
    raise DevelopmentExecutionBoundary('provider-free candidate test cannot run a target')


def _defer_pov_runtime(poc, *_args, **_kwargs):
    # Keep the model-authored PoV input, but never treat it as runtime evidence.
    poc.status = 'PENDING_RUNTIME_DEV'
    poc.actual_behavior = 'Target was not executed in provider-free development test'
    return []


def _record_stop(output: Path, ledger: DevelopmentRequestLedger,
                 exc: BaseException, status: str = 'INCOMPLETE') -> None:
    """Best-effort diagnostic; never replace the original stopping reason."""
    if not output.is_dir():
        return
    if status == 'INCOMPLETE':
        if isinstance(exc, asyncio.CancelledError):
            status = 'INCOMPLETE_CANCELLED'
        elif isinstance(exc, TimeoutError) or isinstance(exc.__cause__, TimeoutError):
            status = 'INCOMPLETE_TIMEOUT'
    try:
        private_json(output / 'DEV_FULL_CANDIDATE_STOP.json', {
            'kind': 'BLIND3_MD4C_FULL_CANDIDATE_PROVIDER_FREE_STOP_V1',
            'status': status, 'error_type': type(exc).__name__,
            'cause_type': (type(exc.__cause__).__name__
                           if exc.__cause__ is not None else None),
            'physical': ledger.physical, 'logical': ledger.logical,
            'ledger_checkpoint_sha256': (sha(ledger.checkpoint_path)
                                         if ledger.checkpoint_path.is_file() else None),
            'success_result_written': False,
        })
    except Exception:
        pass


def _summary(output: Path, run: Path, direction: dict,
             ledger: DevelopmentRequestLedger, scan: dict) -> dict:
    roles = [row['role'] for row in ledger.turns]
    if (not roles or roles[0] != 'direction_generator' or
            any(role not in ROLES for role in roles) or
            scan.get('budget_authority') != 'EXTERNAL_GLOBAL_DEV' or
            scan.get('global_budget_profile') != GLOBAL_ONLY_DEV_PROFILE or
            scan.get('candidate_budget_policy') != 'DRAIN_RANKED_DEV' or
            scan.get('global_logical_used') != ledger.logical or
            scan.get('global_physical_used') != ledger.physical or
            scan.get('sp_llm_call_limit', 'missing') is not None or
            scan.get('hp_llm_call_limit', 'missing') is not None or
            ledger.tainted or ledger.active_turn is not None):
        raise ValueError('candidate Scan and global physical ledger differ')
    row = {
        'kind': 'BLIND3_MD4C_FULL_CANDIDATE_PROVIDER_FREE_DEV_V1',
        'status': 'PENDING_UNVERIFIED_DEV',
        'scope': ('scripted App Server and one official V2 development function; '
                  'no target, Fuzzer, Guided execution, Gate, or Blind 3 approval'),
        'phase1_run': str(run), 'selection_policy': DEV_FIRST_PASS_POLICY,
        'direction_plan_sha256': direction['direction_plan_sha256'],
        'scan_sha256': sha(run / 'scan.json'),
        'ledger_checkpoint_sha256': sha(ledger.checkpoint_path),
        'budget_profile': GLOBAL_ONLY_DEV_PROFILE,
        'budget_physical_max': ledger.budget.physical_max,
        'budget_logical_max': ledger.budget.logical_max,
        'budget_wall_seconds': ledger.budget.wall_seconds,
        'budget_initial_starts_required': ledger.budget.initial_starts_required,
        'physical': ledger.physical, 'logical': ledger.logical,
        'retries': ledger.retries, 'roles': roles,
        'sp_generated': scan.get('sp_count'),
        'sp_verified': len(scan.get('selected_sp_ids', [])),
        'sp_pending': len(scan.get('pending_sp_ids', [])),
        'pov_model_calls': roles.count('poc_generator'),
        'hp_analysis_model_calls': roles.count('function_analysis'),
        'assertion_model_calls': roles.count('assertion_generator'),
        'safe_assumptions': scan.get('safe_assumption_count'),
        'assertion_generation_status': scan.get('assertion_generation_status'),
        'pov_count': scan.get('poc_count'),
        'runtime_status': 'NOT_EXECUTED_DEV',
        'target_runs': 0, 'fuzz_seconds': 0,
        'vulnerability_verdict': 'NOT_EVALUATED',
        'fbv2_queue_parity': 'NOT_EQUIVALENT_INTERLEAVED_DRAIN',
    }
    private_json(output / 'DEV_FULL_CANDIDATE_RESULT.json', row)
    return row


async def _execute_provider_free_full_candidate_inner(
        *, output: Path, artifact: Path, target_repository: Path,
        oss_fuzz_checkout: Path, upstream_checkout: Path,
        qualification: OfficialPinnedQualification,
        backend: DevelopmentGlobalAppServer,
        ledger: DevelopmentRequestLedger,
        role_models: dict[str, dict[str, str]], scope_id: str,
        source_mode: str = 'all_catalog_prefix') -> dict:
    """Use one externally budgeted ledger from Direction through model PoV.

    A caller supplies explicit physical/logical/wall limits in ``ledger``.
    The driver adds no candidate count or SP4/HP4 cap. Product verifier
    attempt and Context limits still apply and must be reported separately.
    """
    output, artifact, target_repository = map(
        Path, (output, artifact, target_repository))
    oss_fuzz_checkout, upstream_checkout = map(
        Path, (oss_fuzz_checkout, upstream_checkout))
    _official_preflight(artifact, target_repository, oss_fuzz_checkout,
                        upstream_checkout, qualification)
    routes = getattr(backend, 'role_models', None)
    if (type(backend) is not FixedCandidateScriptedAppServer or
            any(getattr(type(backend), name) is not method or
                getattr(getattr(backend, name), '__func__', None) is not method
                for name, method in _SCRIPTED_METHODS.items()) or
            getattr(type(backend), 'generate') is not _FIXED_GENERATE or
            getattr(backend.generate, '__func__', None) is not _FIXED_GENERATE or
            getattr(type(backend), '_collect') is not _FIXED_COLLECT or
            getattr(backend._collect, '__func__', None) is not _FIXED_COLLECT or
            ledger.budget.profile != GLOBAL_ONLY_DEV_PROFILE or
            backend.ledger is not ledger or backend.scope_id is not None or
            ledger.tainted or ledger.active_turn is not None or
            ledger.logical != 0 or ledger.physical != 0 or
            ledger.selected_functions or ledger.direction_scopes or
            not isinstance(routes, dict) or
            set(role_models) != ROLES or
            any(not isinstance(route, dict) or
                set(route) != {'model', 'reasoning'} or
                any(not isinstance(value, str) or not value
                    for value in route.values())
                for route in role_models.values()) or
            any(routes.get(role) != role_models.get(role) for role in ROLES)):
        raise ValueError('provider-free global development boundary differs')
    pinned_routes = {role: dict(role_models[role]) for role in ROLES}
    def recheck_routes() -> None:
        if role_models != pinned_routes or backend.role_models != pinned_routes:
            raise ValueError('development role routes changed during execution')
    try:
        direction = await execute_direction_phase1(
            output=output, artifact=artifact, target_repository=target_repository,
            oss_fuzz_checkout=oss_fuzz_checkout,
            upstream_checkout=upstream_checkout, backend=backend, ledger=ledger,
            role_models=role_models, scope_id=scope_id, source_mode=source_mode)
    except BaseException as exc:
        _record_stop(output, ledger, exc)
        raise
    if (direction['status'] != 'DIRECTION_PHASE1_PREPARED_DEV' or
            ledger.logical != 1 or ledger.physical != 1 or
            ledger.turns[0]['role'] != 'direction_generator' or
            ledger.turns[0]['status'] != 'COMPLETED' or
            role_models != pinned_routes or backend.role_models != pinned_routes):
        raise ValueError('Direction lacks one completed physical request')
    _official_preflight(artifact, target_repository, oss_fuzz_checkout,
                        upstream_checkout, qualification)
    run = Path(direction['phase1_run'])
    selection, phase1, pool = (_read(run / name) for name in (
        'selection.json', 'run.json', 'function_pool.json'))
    ids = [row['function_id'] for row in pool]
    fid = selection.get('function_id')
    if (not isinstance(fid, str) or fid not in ids or
            len(ids) != len(set(ids)) or
            phase1.get('selected_function_id') != fid or
            phase1.get('direction_source_kind') != 'PINNED_MODEL_PROPOSAL' or
            phase1.get('selection_policy') != DEV_FIRST_PASS_POLICY or
            phase1.get('direction_plan_sha256') !=
                direction['direction_plan_sha256'] or
            sha(run / 'direction_plan.json') !=
                direction['direction_plan_sha256']):
        raise ValueError('selected Phase 1 identity or policy changed')
    if not ledger.select_function(fid):
        recheck_routes()
        _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
                   upstream_checkout, qualification, source_mode, direction,
                   ledger, backend, ids)
        row = {
            'kind': 'BLIND3_MD4C_FULL_CANDIDATE_PROVIDER_FREE_DEV_V1',
            'status': 'NO_OPPORTUNITY_BUDGET', 'phase1_run': str(run),
            'phase1_sha256': sha(run / 'run.json'),
            'direction_plan_sha256': direction['direction_plan_sha256'],
            'ledger_checkpoint_sha256': sha(ledger.checkpoint_path),
            'budget_profile': GLOBAL_ONLY_DEV_PROFILE,
            'budget_initial_starts_required': ledger.budget.initial_starts_required,
            'physical': ledger.physical, 'logical': ledger.logical,
            'vulnerability_verdict': 'NOT_EVALUATED',
        }
        private_json(output / 'DEV_FULL_CANDIDATE_RESULT.json', row)
        return row
    backend.bind_scope(fid)
    provider = ProductBudgetAdapter(backend, ledger, fid)
    try:
        # Patching the named product call sites makes accidental target or
        # fuzz execution fail closed. PoV input generation remains observable.
        with (patch('vulnerabilityanalysis.scan.execute_poc',
                    _defer_pov_runtime),
              patch('vulnerabilityanalysis.scan.run_assertions_for_scan',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.fuzz_locally',
                    _forbid_execution),
              patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                    _forbid_execution)):
            await scan_selected(
                run, provider, target_repository=target_repository,
                target_binary=qualification.binary,
                official_qualification=qualification,
                role_models=role_models, hallucination_prevent='on',
                external_turn_budget=ledger,
                candidate_budget_policy='DRAIN_RANKED_DEV',
                max_candidates=1,  # External mode: 0 disables; positive is no cap.
                targeted_fuzz_seconds=0, global_fuzz_enabled=False,
                assertion_fuzz_seconds=0, run_command=None,
                initial_inputs=None, pov_feedback_revisions=0)
    except DevelopmentBudgetStop as exc:
        if (run / 'scan.json').is_file():
            raise ValueError('budget-stopped Scan was saved as complete')
        recheck_routes()
        _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
                   upstream_checkout, qualification, source_mode, direction,
                   ledger, backend, ids)
        _record_stop(output, ledger, exc, 'PENDING_BUDGET')
        return {'status': 'PENDING_BUDGET', 'physical': ledger.physical,
                'logical': ledger.logical, 'phase1_run': str(run)}
    except BaseException as exc:
        _record_stop(output, ledger, exc)
        raise
    finally:
        backend.unbind_scope()
    try:
        scan = _read(run / 'scan.json')
        recheck_routes()
        _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
                   upstream_checkout, qualification, source_mode, direction,
                   ledger, backend, ids)
        ledger.mark_scan_recorded(fid)
        _postcheck(output, artifact, target_repository, oss_fuzz_checkout,
                   upstream_checkout, qualification, source_mode, direction,
                   ledger, backend, ids)
        return _summary(output, run, direction, ledger, scan)
    except BaseException as exc:
        _record_stop(output, ledger, exc)
        raise


async def execute_provider_free_full_candidate(
        *, output: Path, artifact: Path, target_repository: Path,
        oss_fuzz_checkout: Path, upstream_checkout: Path,
        qualification: OfficialPinnedQualification,
        backend: DevelopmentGlobalAppServer,
        ledger: DevelopmentRequestLedger,
        role_models: dict[str, dict[str, str]], scope_id: str,
        source_mode: str = 'all_catalog_prefix') -> dict:
    """Record every post-Direction failure without replacing its exception."""
    try:
        return await _execute_provider_free_full_candidate_inner(
            output=output, artifact=artifact,
            target_repository=target_repository,
            oss_fuzz_checkout=oss_fuzz_checkout,
            upstream_checkout=upstream_checkout,
            qualification=qualification, backend=backend, ledger=ledger,
            role_models=role_models, scope_id=scope_id,
            source_mode=source_mode)
    except BaseException as exc:
        if ledger.logical > 0:
            _record_stop(Path(output), ledger, exc)
        raise
