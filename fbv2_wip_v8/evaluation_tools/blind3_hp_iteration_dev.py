"""Provider-free development boundary for one HP assertion refinement.

This is not a Blind 3 execution or approval runner. Frozen Blind 2 files stay
unchanged; this module accepts one prebuilt public Phase 1 run only.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any, Callable

import blind2_runner_draft as legacy
from blind_runner_guards import HP_ROLES, SP_ROLES, Ledger
from vulnerabilityanalysis.runtime import RuntimeCleanupError


@dataclass(frozen=True)
class DevHPPolicy:
    k_functions: int = 1
    sp_per_function: int = 3
    hp_per_function: int = 5
    function_analysis_max: int = 3
    assertion_generator_max: int = 2
    combined_per_function: int = 8
    hp_context_round_limit: int = 1
    logical_max: int = 8
    physical_max: int = 8
    retry_max: int = 0
    wall_seconds: int = 300
    fuzz_seconds_combined: int = 4
    assertion_fuzz_job_seconds: int = 1


def load_dev_contract(path: Path, expected_sha256: str) -> tuple[DevHPPolicy, str]:
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise ValueError('development contract SHA-256 changed')
    row = json.loads(raw)
    if set(row) != {'kind', 'limits'} or row['kind'] != 'BLIND3_HP_ITERATION_DEV':
        raise ValueError('wrong development contract kind')
    if not isinstance(row['limits'], dict) or set(row['limits']) != set(asdict(DevHPPolicy())):
        raise ValueError('incomplete development contract limits')
    if any(type(value) is not int for value in row['limits'].values()):
        raise ValueError('development limits must be integers')
    policy = DevHPPolicy(**row['limits'])
    if policy != DevHPPolicy():
        raise ValueError('unapproved development policy')
    return policy, actual


@dataclass
class DevHPLedger(Ledger):
    policy: dict[str, int] = field(default_factory=dict)
    contract_sha256: str = ''
    run_paths: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.policy != asdict(DevHPPolicy()) or len(self.contract_sha256) != 64:
            raise ValueError('development ledger policy is not pinned')

    def wall(self, now: float | None = None) -> None:
        if (time.time() if now is None else now) - self.started_at >= self.policy['wall_seconds']:
            raise ValueError('development wall limit reached')

    def select(self, function_id: str) -> None:
        self.wall()
        if function_id in self.functions or len(self.functions) >= self.policy['k_functions']:
            raise ValueError('development selection not eligible')
        self.functions.append(function_id)
        self.counts[function_id] = {}

    def bind_run(self, function_id: str, run: Path) -> None:
        if function_id not in self.counts or function_id in self.run_paths:
            raise ValueError('development run must bind exactly once')
        self.run_paths[function_id] = str(run.resolve())

    def _effective_sp_cap(self, function_id: str) -> int:
        run = self.run_paths.get(function_id)
        if run is None:
            raise ValueError('selected function has no bound development run')
        budget_path = Path(run) / 'sp' / 'turn_budget.json'
        base = self.policy['sp_per_function']
        if not budget_path.is_file():
            return base
        row = json.loads(budget_path.read_text())
        counts = self.counts[function_id]
        hp_used = sum(counts.get(role, 0) for role in HP_ROLES)
        initial_hp = row.get('hp_calls_before_transfer')
        transfer = row.get('transferred_hp_calls')
        effective = row.get('effective_sp_limit')
        checkable = row.get('checkable_assertion_count')
        if (row.get('function_id') != function_id or
                row.get('original_sp_limit') != base or
                row.get('original_hp_limit') != self.policy['hp_per_function'] or
                row.get('combined_limit') != self.policy['combined_per_function'] or
                type(initial_hp) is not int or type(transfer) is not int or
                type(effective) is not int or type(checkable) is not int or
                not 0 <= initial_hp <= hp_used <= self.policy['hp_per_function'] or
                not 0 <= transfer <= self.policy['hp_per_function'] - initial_hp or
                effective != base + transfer or
                effective + hp_used > self.policy['combined_per_function'] or
                (transfer > 0 and (checkable != 0 or initial_hp != hp_used or
                                   row.get('reason') != 'HP_NO_ASSERTION_UNUSED_CALLS')) or
                (checkable > 0 and transfer != 0)):
            raise ValueError('invalid development product turn-budget record')
        return effective

    def begin_turn(self, function_id: str, role: str, request_hash: str) -> str:
        self.wall()
        if (self.active_turn or self.active_fuzz or function_id not in self.counts or
                role not in SP_ROLES | HP_ROLES or len(request_hash) != 64):
            raise ValueError('development turn outside selected idle function')
        counts = self.counts[function_id]
        sp = sum(counts.get(item, 0) for item in SP_ROLES)
        hp = sum(counts.get(item, 0) for item in HP_ROLES)
        cap = self._effective_sp_cap(function_id)
        if (self.logical >= self.policy['logical_max'] or
                self.physical >= self.policy['physical_max'] or
                sp + hp >= self.policy['combined_per_function'] or
                role in SP_ROLES and sp >= cap or
                role in HP_ROLES and (hp >= self.policy['hp_per_function'] or
                                      cap > self.policy['sp_per_function']) or
                role == 'function_analysis' and
                counts.get(role, 0) >= self.policy['function_analysis_max'] or
                role == 'assertion_generator' and
                counts.get(role, 0) >= self.policy['assertion_generator_max']):
            raise ValueError('development logical turn limit reached')
        self.logical += 1
        counts[role] = counts.get(role, 0) + 1
        turn_id = f'L{self.logical:03d}'
        self.active_turn = {'id': turn_id, 'function_id': function_id,
                            'role': role, 'hash': request_hash, 'attempts': 0}
        return turn_id

    def start_attempt(self, request_hash: str, retry: bool = False) -> int:
        if retry or self.physical >= self.policy['physical_max']:
            raise ValueError('development physical attempt limit reached')
        return super().start_attempt(request_hash, retry=False)

    def begin_fuzz(self, item_id: str, kind: str, requested: float) -> float:
        self.wall()
        if (self.active_turn or self.active_fuzz or not math.isfinite(requested) or
                requested <= 0 or kind != 'ASSERTION'):
            raise ValueError('development Fuzz job not eligible')
        if self.fuzz_overrun_blocked:
            self.mark_pending(item_id, 'PENDING_FUZZ_OVERRUN_LOCKOUT')
            return 0.0
        allowed = int(min(requested, self.policy['assertion_fuzz_job_seconds'],
                          self.policy['fuzz_seconds_combined'] - self.fuzz_budget_used()))
        if allowed < 1:
            self.mark_pending(item_id, 'PENDING_FUZZ_BUDGET')
            return 0.0
        self.active_fuzz = {'id': item_id, 'kind': kind, 'reserved': allowed}
        return allowed

    def validate_scan(self, function_id: str, scan: dict[str, Any]) -> dict[str, Any] | None:
        counts = self.counts[function_id]
        sp = sum(counts.get(role, 0) for role in SP_ROLES)
        hp = sum(counts.get(role, 0) for role in HP_ROLES)
        cap = self._effective_sp_cap(function_id)
        if (scan.get('selected_function_id') != function_id or
                type(scan.get('effective_sp_llm_call_limit')) is not int or
                type(scan.get('combined_llm_call_limit')) is not int or
                scan.get('effective_sp_llm_call_limit') != cap or
                scan.get('combined_llm_call_limit') != self.policy['combined_per_function'] or
                sp + hp > self.policy['combined_per_function']):
            raise ValueError('development product and evaluator turn accounting differ')
        product_sp, product_hp = scan.get('sp_llm_calls'), scan.get('hp_llm_calls')
        if type(product_sp) is not int or type(product_hp) is not int:
            raise ValueError('development product and evaluator turn accounting differ')
        if (product_sp, product_hp) == (sp, hp):
            return None
        # The product can record an HP request that did not reach this ledger.
        # It remains an incomplete HP error only if the missing turn could
        # actually have started under the same role and budget contract.
        hp_error = scan.get('hp_error')
        stage_to_role = {'FUNCTION_ANALYSIS': 'function_analysis',
                         'ASSERTION_GENERATION': 'assertion_generator'}
        stage = hp_error.get('stage') if type(hp_error) is dict else None
        role = stage_to_role.get(stage) if type(stage) is str else None
        role_max = {'function_analysis': 'function_analysis_max',
                    'assertion_generator': 'assertion_generator_max'}
        if (role is not None and
                type(hp_error.get('type')) is str and hp_error['type'] and
                product_sp == sp and product_hp == hp + 1 and
                cap == self.policy['sp_per_function'] and
                counts.get(role, 0) < self.policy[role_max[role]] and
                product_hp <= self.policy['hp_per_function'] and
                sp + product_hp <= self.policy['combined_per_function'] and
                self.logical < self.policy['logical_max'] and
                self.physical < self.policy['physical_max'] and
                time.time() - self.started_at < self.policy['wall_seconds'] and
                self.active_turn is None and self.active_fuzz is None):
            return {'error_type': 'ValueError',
                    'message': 'product counted one HP turn absent from evaluator ledger',
                    'hp_error_present': True,
                    'hp_error_stage': stage,
                    'product_sp_calls': product_sp, 'evaluator_sp_calls': sp,
                    'product_hp_calls': product_hp, 'evaluator_hp_calls': hp}
        raise ValueError('development product and evaluator turn accounting differ')

    @classmethod
    def restore_for_contract(cls, path: Path, expected_sha256: str) -> 'DevHPLedger':
        saved = json.loads(path.read_text())
        if saved.get('contract_sha256') != expected_sha256:
            raise ValueError('development checkpoint contract changed')
        ledger = Ledger.restore.__func__(cls, path)
        if len(ledger.functions) > 1 or ledger.logical > ledger.policy['logical_max'] or \
                ledger.physical > ledger.policy['physical_max'] or \
                ledger.retries > ledger.policy['retry_max'] or \
                ledger.fuzz_actual > ledger.policy['fuzz_seconds_combined']:
            raise ValueError('development checkpoint budget changed')
        for function_id, counts in ledger.counts.items():
            sp = sum(counts.get(role, 0) for role in SP_ROLES)
            hp = sum(counts.get(role, 0) for role in HP_ROLES)
            if (sp + hp > ledger.policy['combined_per_function'] or
                    hp > ledger.policy['hp_per_function'] or
                    counts.get('function_analysis', 0) > ledger.policy['function_analysis_max'] or
                    counts.get('assertion_generator', 0) > ledger.policy['assertion_generator_max']):
                raise ValueError(f'development checkpoint role count changed: {function_id}')
        return ledger


class DevHPMeter(legacy.SharedFuzzMeter):
    """Preserve the old Guided meter while allowing one accounted refinement."""

    @contextmanager
    def patch_guided(self):
        original_refinement = legacy.scan_mod.refine_overstrong_assertions
        with super().patch_guided():
            legacy_wrapper = legacy.scan_mod.refine_overstrong_assertions

            async def refinement(run_dir: Path, *args: Any, **kwargs: Any):
                function_id = kwargs.get('function_id')
                counts = self.ledger.counts.get(function_id, {})
                results = Path(run_dir) / 'assertions' / 'results.json'
                rows = json.loads(results.read_text()) if results.is_file() else []
                eligible = []
                for row in rows:
                    if row.get('status') != 'VIOLATED' or not row.get('execution_result'):
                        continue
                    triage = Path(row['execution_result']).parent / 'triage.json'
                    if (triage.is_file() and
                            json.loads(triage.read_text()).get('classification') ==
                            'OVERSTRONG_ASSUMPTION'):
                        eligible.append(row['assertion_id'])
                if not eligible:
                    report = {'status': 'NO_ELIGIBLE_VIOLATION', 'llm_calls': 0,
                              'refinements': [], 'guided_fuzz_reserved_seconds': 0}
                    legacy.write_json(Path(run_dir) / 'assertions' /
                                      'refinement_history.json', report)
                    return report
                hp = sum(counts.get(role, 0) for role in HP_ROLES)
                sp = sum(counts.get(role, 0) for role in SP_ROLES)
                policy = self.ledger.policy
                enough = (kwargs.get('max_llm_calls', 0) >= 2 and
                          policy['hp_per_function'] - hp >= 2 and
                          policy['function_analysis_max'] -
                          counts.get('function_analysis', 0) >= 1 and
                          policy['assertion_generator_max'] -
                          counts.get('assertion_generator', 0) >= 1 and
                          policy['combined_per_function'] - hp - sp >= 2 and
                          policy['logical_max'] - self.ledger.logical >= 2 and
                          policy['physical_max'] - self.ledger.physical >= 2)
                if not enough:
                    for item_id in eligible:
                        self.ledger.mark_pending(item_id, 'PENDING_ROLE_BUDGET')
                    report = {'status': 'PENDING_ROLE_BUDGET', 'llm_calls': 0,
                              'refinements': [], 'pending_refinement_ids': eligible,
                              'guided_fuzz_reserved_seconds': 0}
                    legacy.write_json(Path(run_dir) / 'assertions' /
                                      'refinement_history.json', report)
                    self.ledger.checkpoint(self.checkpoint)
                    return report
                before = hp
                report = await original_refinement(run_dir, *args, **kwargs)
                after = sum(self.ledger.counts[function_id].get(role, 0)
                            for role in HP_ROLES)
                if report.get('llm_calls') != after - before:
                    raise ValueError('refinement model calls differ from development ledger')
                legacy.write_json(Path(run_dir) / 'assertions' /
                                  'refinement_history.json', report)
                return report

            legacy.scan_mod.refine_overstrong_assertions = refinement
            try:
                yield
            finally:
                legacy.scan_mod.refine_overstrong_assertions = legacy_wrapper


async def _run_sequence_core(first_run: Path, provider: Any, ledger: DevHPLedger,
                             target_repository: Path, checkpoint: Path, *,
                             policy: DevHPPolicy, contract_path: Path,
                             contract_loader: Callable[[Path, str], tuple[DevHPPolicy, str]],
                             expected_policy: DevHPPolicy,
                             provider_check: Callable[[Any], bool],
                             scan_options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Shared public-toy accounting core; callers authenticate their own mode."""
    loaded_policy, _ = contract_loader(contract_path, ledger.contract_sha256)
    if loaded_policy != policy:
        raise ValueError('development run policy differs from pinned contract')
    if (policy != expected_policy or ledger.policy != asdict(policy) or
            getattr(provider, 'ledger', None) is not ledger or
            not provider_check(provider)):
        raise ValueError('unapproved development provider or budget')
    options = dict(scan_options or {})
    forbidden = {'sp_llm_call_limit', 'hp_llm_call_limit', 'hp_context_round_limit',
                 'evaluation_fuzz_limit_seconds', 'fuzz_budget_seconds',
                 'assertion_fuzz_seconds', 'targeted_fuzzer_binary',
                 'targeted_fuzz_seconds', 'global_fuzz_enabled',
                 'global_fuzz_seconds', 'max_candidates', 'candidate_budget_policy'}
    if forbidden & options.keys():
        raise ValueError('development runner owns all model and Fuzz budgets')
    run = first_run.resolve()
    selection = json.loads((run / 'selection.json').read_text())
    function_id = selection['function_id']
    ledger.select(function_id)
    ledger.bind_run(function_id, run)
    ledger.checkpoint(checkpoint)
    meter = DevHPMeter(ledger, checkpoint)
    status, error = 'COMPLETE', None
    fatal: BaseException | None = None
    auxiliary: list[dict[str, str]] = []
    provider_started = False
    try:
        provider.begin_function(function_id)
        provider_started = True
        remaining_wall = ledger.started_at + policy.wall_seconds - time.time()
        if remaining_wall <= 0:
            raise TimeoutError('development wall limit reached before function')
        with meter.patch_guided():
            await asyncio.wait_for(legacy.scan_mod.scan_selected(
                run, provider, target_repository=target_repository,
                max_candidates=2,
                sp_llm_call_limit=policy.sp_per_function,
                hp_llm_call_limit=policy.hp_per_function,
                hp_context_round_limit=policy.hp_context_round_limit,
                evaluation_fuzz_limit_seconds=policy.fuzz_seconds_combined,
                fuzz_budget_seconds=max(0, int(policy.fuzz_seconds_combined -
                                               ledger.fuzz_budget_used())),
                assertion_fuzz_seconds=policy.assertion_fuzz_job_seconds,
                targeted_fuzzer_binary=None, targeted_fuzz_seconds=0,
                global_fuzz_enabled=False, global_fuzz_seconds=0,
                scan_deadline_monotonic=time.monotonic() + remaining_wall,
                **options), timeout=remaining_wall)
        scan = json.loads((run / 'scan.json').read_text())
        accounting_note = ledger.validate_scan(function_id, scan)
        if accounting_note is not None:
            legacy.write_json(run / 'runtime' / 'hp_accounting_discrepancy.json',
                              accounting_note)
        if scan.get('hp_error') is not None:
            status = 'INCOMPLETE_HP_ERROR'
            ledger.mark_pending(function_id, 'HP analysis incomplete')
        elif any(item['reason'] == 'PENDING_ROLE_BUDGET'
                 for item in ledger.pending):
            status = 'INCOMPLETE_HP_ITERATION_BUDGET'
        elif scan.get('assertion_execution', {}).get('status') in {
                'PENDING_HP_BUDGET', 'INCOMPLETE_HP_ERROR'}:
            status = 'INCOMPLETE_HP_ITERATION'
        else:
            history = run / 'assertions' / 'refinement_history.json'
            report = json.loads(history.read_text()) if history.is_file() else {}
            status = ('BOUNDARY_ACCOUNTED' if any(
                item.get('status') == 'REFINED_AND_TESTED'
                for item in report.get('refinements', [])) else
                'INCONCLUSIVE_NO_REFINED_ASSERTION')
    except BaseException as exc:
        fatal = exc
        status = ('STOPPED_CLEANUP_INCOMPLETE' if isinstance(exc, RuntimeCleanupError)
                  else 'STOPPED_WALL_LIMIT' if isinstance(exc, TimeoutError)
                  else 'STOPPED_FAIL_CLOSED')
        error = f'{type(exc).__name__}: {exc}'
        ledger.mark_pending(function_id, error)
        if not (run / 'scan.json').is_file():
            try:
                legacy.mark_inconclusive_scan(run, target_repository, error)
            except BaseException as secondary:
                auxiliary.append({'stage': 'PARTIAL_SCAN',
                                  'error_type': type(secondary).__name__,
                                  'message': str(secondary)})
    finally:
        def preserve(stage: str, action):
            try:
                return action()
            except BaseException as exc:
                auxiliary.append({'stage': stage, 'error_type': type(exc).__name__,
                                  'message': str(exc)})
                return None

        if provider_started:
            preserve('PROVIDER_END', provider.end_function)
        preserve('FUZZ_JOB_RECEIPT', lambda: legacy.write_json(
            run / 'runtime' / 'runner_fuzz_jobs.json', meter.records))
        if isinstance(fatal, RuntimeCleanupError):
            preserve('RUNTIME_CLEANUP_EVIDENCE', lambda:
                legacy.record_runtime_cleanup_evidence(run, function_id, fatal))
        if auxiliary and fatal is None:
            status = 'INCOMPLETE_DEV_AUDIT'
        if auxiliary:
            preserve('AUXILIARY_ERRORS', lambda: legacy.write_json(
                run / 'runtime' / 'dev_auxiliary_errors.json', auxiliary))
        preserve('LEDGER_CHECKPOINT', lambda: ledger.checkpoint(checkpoint))
        checkpoint_file = preserve('FUNCTION_CHECKPOINT', lambda:
            legacy.checkpoint_run(run, status, ledger))
        resource = preserve('RESOURCE_SUMMARY', lambda:
            legacy.summarize_resource_exhaustion(run))
        if resource is None:
            if fatal is None:
                status = 'INCOMPLETE_DEV_AUDIT'
            preserve('AUXILIARY_ERRORS', lambda: legacy.write_json(
                run / 'runtime' / 'dev_auxiliary_errors.json', auxiliary))
            preserve('LEDGER_CHECKPOINT', lambda: ledger.checkpoint(checkpoint))
            checkpoint_file = preserve('FUNCTION_CHECKPOINT', lambda:
                legacy.checkpoint_run(run, status, ledger))
    if fatal is not None:
        raise fatal
    if auxiliary:
        raise RuntimeError('development audit incomplete: ' +
                           ', '.join(item['stage'] for item in auxiliary))
    return [{'function_id': function_id, 'run': str(run), 'status': status,
             'error': error, 'checkpoint': str(checkpoint_file),
             'resource_exhaustion_artifact_count':
                 resource['resource_exhaustion_artifact_count']}]


async def run_sequence_dev(first_run: Path, provider: Any, ledger: DevHPLedger,
                           target_repository: Path, checkpoint: Path, *,
                           policy: DevHPPolicy, contract_path: Path,
                           scan_options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Exercise one public Phase 1 run with scripted responses only."""
    return await _run_sequence_core(
        first_run, provider, ledger, target_repository, checkpoint,
        policy=policy, contract_path=contract_path,
        contract_loader=load_dev_contract, expected_policy=DevHPPolicy(),
        provider_check=lambda item: getattr(item, 'provider_free', False) is True,
        scan_options=scan_options)
