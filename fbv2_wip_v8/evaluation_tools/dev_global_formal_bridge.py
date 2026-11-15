"""Development wrapper around the real two-function runner loop.

This is an experiment, not a frozen Global ON route. It does not change the
Blind 2 runner or its hardcoded product Global OFF setting.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
from pathlib import Path
import subprocess
import time
from typing import Any
from unittest.mock import patch

import blind2_runner_draft as runner
import dev_global_campaign as global_dev
from vulnerabilityanalysis.runtime import RuntimeCleanupError


class SharedPhysicalBudgetExceeded(ValueError):
    """The combined development Global/SP/HP physical allocation is exhausted."""


def _run_guarded_consumer_command(command: list[str], log_path: Path, *,
                                  wall_seconds: float,
                                  environment: dict[str, str] | None = None) -> dict[str, Any]:
    """Physically stop one synchronous consumer and its detached descendants."""
    if (type(wall_seconds) not in (int, float) or
            not math.isfinite(wall_seconds) or wall_seconds <= 0):
        raise ValueError('Global consumer physical wall must be positive')
    started = time.monotonic()
    child = None
    status_read = None
    cleanup_complete = True
    timed_out = False
    return_code = None
    original: BaseException | None = None
    try:
        with log_path.open('xb') as log:
            child, status_read = runner._launch_guarded(
                command, stdout=log, stderr=subprocess.STDOUT,
                **({'env': environment} if environment is not None else {}))
            try:
                child.wait(timeout=wall_seconds)
                return_code = runner._guarded_return_code(child, status_read)
                cleanup_complete = return_code != -32768
            except subprocess.TimeoutExpired:
                timed_out = True
                cleanup_complete = runner._request_guard_cleanup(child, status_read)
            except BaseException as exc:
                original = exc
                try:
                    cleanup_complete = runner._request_guard_cleanup(child, status_read)
                except BaseException:
                    cleanup_complete = False
    finally:
        if child is not None:
            try:
                runner._kill_process_group(child.pid)
            except BaseException:
                cleanup_complete = False
        if status_read is not None:
            try:
                os.close(status_read)
            except OSError:
                cleanup_complete = False
    result = {
        'status': ('STOPPED_CLEANUP_INCOMPLETE' if not cleanup_complete else
                   'STOPPED_GLOBAL_CONSUMER_WALL' if timed_out else
                   'GLOBAL_CONSUMER_COMPLETE' if return_code == 0 else
                   'GLOBAL_CONSUMER_CHILD_ERROR'),
        'cleanup_complete': cleanup_complete,
        'timed_out': timed_out,
        'return_code': return_code,
        'physical_seconds': max(0.0, time.monotonic() - started),
    }
    if original is not None:
        raise original
    return result


class BridgeMeter(runner.SharedFuzzMeter):
    def __init__(self, *args: Any, bridge: 'GlobalFormalDevBridge', **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.bridge = bridge
        self.next_id = 0

    def invoke(self, item_id: str, kind: str, requested: int,
               function: Any, *args: Any, **kwargs: Any) -> Any:
        if self.ledger.fuzz_overrun_policy != 'PHYSICAL_DEBIT_V1':
            raise ValueError('development shared fuzz requires physical debit policy')
        self.next_id += 1
        key = f'{kind}:{item_id}:{self.next_id}'
        # Admission includes an explicit cleanup allowance. This prevents a
        # nominally fitting SP/HP job from starting when Global has already
        # reserved the rest. A separate per-job hard wall is still required
        # before claiming the aggregate physical cap is enforced.
        physical_envelope = requested + self.bridge.termination_grace_seconds
        try:
            self.bridge.campaign.budget.reserve(key, physical_envelope)
        except ValueError as exc:
            self.bridge.shared_budget_failed = True
            try:
                self.bridge.write_budget()
            except BaseException as audit_error:
                self.bridge.accounting_errors.append({
                    'key': key, 'error_type': type(audit_error).__name__})
            raise SharedPhysicalBudgetExceeded(
                f'shared physical fuzz reservation refused for {key}') from exc
        try:
            self.bridge.write_budget()
        except BaseException as audit_error:
            self.bridge.campaign.budget.reservations.pop(key, None)
            self.bridge.shared_budget_failed = True
            self.bridge.accounting_errors.append({
                'key': key, 'error_type': type(audit_error).__name__,
                'stage': 'POST_RESERVATION_CHECKPOINT'})
            try:
                self.bridge.write_budget()
            except BaseException:
                pass  # Preserve the first audit write failure and stop.
            raise SharedPhysicalBudgetExceeded(
                f'shared physical budget checkpoint failed for {key}') from audit_error
        started = time.monotonic()
        prior = len(self.records)
        original_error: BaseException | None = None
        try:
            return super().invoke(item_id, kind, requested, function,
                                  *args, **kwargs)
        except BaseException as exc:
            original_error = exc
            raise
        finally:
            physical = (self.records[-1].get('physical_actual')
                        if len(self.records) > prior else None)
            if (type(physical) not in (int, float) or
                    not math.isfinite(physical) or physical < 0):
                physical = max(0.0, time.monotonic() - started)
            try:
                charge = self.bridge.campaign.budget.finish(key, physical)
                self.bridge.write_budget()
            except BaseException as accounting_error:
                self.bridge.shared_budget_failed = True
                self.bridge.accounting_errors.append({
                    'key': key, 'error_type': type(accounting_error).__name__})
                if original_error is None:
                    raise SharedPhysicalBudgetExceeded(
                        f'shared physical accounting failed for {key}') from accounting_error
            else:
                if charge['overrun']:
                    budget = self.bridge.campaign.budget
                    self.bridge.physical_debit_overruns.append(dict(charge))
                    if budget.available < -1e-9:
                        self.bridge.shared_budget_failed = True
                        if original_error is None:
                            raise SharedPhysicalBudgetExceeded(
                                f'shared physical total exceeded for {key}')


class GlobalFormalDevBridge:
    def __init__(self, campaign: global_dev.DevGlobalCampaign, *,
                 consumer_wall_seconds: float,
                 termination_grace_seconds: float):
        if (type(consumer_wall_seconds) not in (int, float) or
                not math.isfinite(consumer_wall_seconds) or
                not 0 < consumer_wall_seconds <= 120):
            raise ValueError('Global consumer wall budget must be explicit and <=120s')
        if (type(termination_grace_seconds) not in (int, float) or
                not math.isfinite(termination_grace_seconds) or
                termination_grace_seconds < 0 or
                campaign.global_wall_reservation_seconds <
                campaign.global_seconds + termination_grace_seconds):
            raise ValueError('Global physical reservation must include termination grace')
        self.campaign = campaign
        self.consumer_wall_seconds = float(consumer_wall_seconds)
        self.termination_grace_seconds = float(termination_grace_seconds)
        self.overrun_policy = 'PHYSICAL_DEBIT_DEV_V1'
        self.consumer_wall_elapsed = 0.0
        self.consumer_wall_overrun = False
        self.consumer_hard_wall_enforced = False
        self.consumer_guard_status: str | None = None
        self.consumer_authority_status = 'NOT_STARTED'
        self.consumer_result_sha256: str | None = None
        self.shared_budget_failed = False
        self.accounting_errors: list[dict[str, str]] = []
        self.physical_debit_overruns: list[dict[str, Any]] = []
        self.result_write_error_type: str | None = None
        self.meter: BridgeMeter | None = None
        self.result_path = campaign.output / 'DEV_GLOBAL_FORMAL_BRIDGE_RESULT.json'

    def write_budget(self) -> None:
        global_dev.write_json(self.campaign.output / 'DEV_SHARED_FUZZ_BUDGET.json',
                              self.campaign.budget.snapshot())

    def _meter(self, *args: Any, **kwargs: Any) -> BridgeMeter:
        self.meter = BridgeMeter(*args, bridge=self, **kwargs)
        return self.meter

    def _abort_preserving_error(self) -> dict[str, Any]:
        try:
            result = self.campaign.abort()
        except BaseException as exc:
            return {'status': 'STOPPED_CLEANUP_INCOMPLETE',
                    'cleanup_complete': False,
                    'cleanup_error_type': type(exc).__name__}
        if not isinstance(result, dict) or result.get('cleanup_complete') is not True:
            return {'status': 'STOPPED_CLEANUP_INCOMPLETE',
                    'cleanup_complete': False,
                    'abort_result_status': result.get('status')
                    if isinstance(result, dict) else None}
        return result

    def _record_preserving_error(self, *args: Any, **kwargs: Any) -> None:
        try:
            self._write_result(*args, **kwargs)
        except BaseException as exc:
            self.result_write_error_type = type(exc).__name__

    async def _wait_for_guard_child(self) -> bool:
        """Wait until the subreaper has installed its handler and spawned a child."""
        process = self.campaign.process
        if process is None:
            return False
        children_path = Path(f'/proc/{process.pid}/task/{process.pid}/children')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                if children_path.read_text().split():
                    return True
            except OSError:
                pass
            await asyncio.sleep(0.01)
        return False

    async def run_sequence(self, first_run: Path, provider: Any,
                           ledger: runner.Ledger, target_repository: Path,
                           checkpoint: Path, **kwargs: Any) -> dict[str, Any]:
        """Start one Global before first scan; keep product per-function Global OFF."""
        if self.campaign.final_result is not None:
            raise ValueError('Global development campaign was already consumed')
        if (ledger.active_fuzz is not None or ledger.fuzz_actual != 0 or
                ledger.fuzz_physical_actual != 0):
            raise ValueError('development shared fuzz requires a fresh ledger')
        ledger.fuzz_overrun_policy = 'PHYSICAL_DEBIT_V1'
        start_stage = 'START'
        try:
            start_status = self.campaign.start()
            self.write_budget()
            start_stage = 'GUARD_READY'
            if start_status == 'ACTIVE' and not await self._wait_for_guard_child():
                raise ValueError('Global guard did not become ready before first function')
        except BaseException as exc:
            stopped = self._abort_preserving_error()
            self._record_preserving_error(
                'STOPPED_GLOBAL_START_ERROR' if start_stage == 'START'
                else 'STOPPED_GLOBAL_GUARD_NOT_READY', [], ledger, stopped, exc)
            raise
        original_scan = runner.scan_mod.scan_selected

        async def scan_with_global_marker(run: Path, scan_provider: Any,
                                          **scan_options: Any) -> Any:
            if (scan_options.get('global_fuzz_enabled') is not False or
                    scan_options.get('global_fuzz_seconds') != 0):
                raise ValueError('product per-function Global must stay OFF')
            if start_status == 'ACTIVE':
                selection = json.loads((run / 'selection.json').read_text())
                self.campaign.mark_function(selection['function_id'])
            return await original_scan(run, scan_provider, **scan_options)

        rows: list[dict[str, Any]] = []
        original_error: BaseException | None = None
        try:
            with patch.object(runner, 'SharedFuzzMeter', self._meter), \
                 patch.object(runner.scan_mod, 'scan_selected', scan_with_global_marker):
                rows = await runner.run_sequence(
                    first_run, provider, ledger, target_repository,
                    checkpoint, **kwargs)
        except BaseException as exc:
            original_error = exc
            raise
        finally:
            if original_error is not None:
                global_result = self._abort_preserving_error()
                self._record_preserving_error(
                    'STOPPED_CLEANUP_INCOMPLETE'
                    if isinstance(original_error, RuntimeCleanupError)
                    else 'STOPPED_SHARED_FUZZ_BUDGET'
                    if isinstance(original_error, SharedPhysicalBudgetExceeded)
                    else 'STOPPED_SEQUENCE_ERROR', rows, ledger,
                    global_result, original_error)

        if start_status == 'ACTIVE':
            def bounded_consumer(*args: Any, **consumer_options: Any) -> Any:
                started = time.monotonic()
                remaining = self.consumer_wall_seconds - self.consumer_wall_elapsed
                run_dir, report = args[:2]
                qualification = self.campaign.q
                authority_path = run_dir / 'DEV_GLOBAL_CONSUMER_AUTHORITY.json'
                if (remaining <= global_dev.GUARD_CLEANUP_ENVELOPE_SECONDS or
                        qualification.oss_fuzz_checkout is None or
                        qualification.upstream_checkout is None):
                    self.consumer_wall_overrun = True
                    self.consumer_authority_status = 'BLOCKED_BEFORE_CHILD'
                    raise TimeoutError('Global consumer wall cannot include cleanup')
                report_path = run_dir / 'runtime' / 'global_fuzz.json'
                if (report_path.is_symlink() or not report_path.is_file() or
                        json.loads(report_path.read_text()) != report):
                    raise ValueError('Global consumer report changed before child')
                spec_path = run_dir / 'consumer_worker_spec.json'
                result_path = run_dir / 'runtime' / 'dev_global_consumer_result.json'
                pycache_prefix = run_dir / 'consumer_worker_pycache'
                if spec_path.exists() or result_path.exists() or authority_path.exists():
                    raise ValueError('Global consumer attempt already exists')
                pycache_prefix.mkdir(mode=0o700)
                pycache_prefix.chmod(0o700)
                spec = {
                    'kind': 'DEV_GLOBAL_CONSUMER_WORKER_V1',
                    'run_dir': str(run_dir),
                    'report_sha256': global_dev.digest(report_path),
                    'contract_path': str(qualification.contract_path),
                    'contract_sha256': qualification.contract_sha256,
                    'source_root': str(qualification.source_root),
                    'harness': str(qualification.harness),
                    'binary': str(qualification.binary),
                    'binary_sha256': qualification.binary_sha256,
                    'normal_seed': str(qualification.normal_seed),
                    'oss_fuzz_checkout': str(qualification.oss_fuzz_checkout),
                    'upstream_checkout': str(qualification.upstream_checkout),
                    'replay_limit': self.campaign.replay_limit,
                    'pycache_prefix': str(pycache_prefix),
                    'deadline_monotonic': min(
                        consumer_options['deadline_monotonic'],
                        started + remaining - global_dev.GUARD_CLEANUP_ENVELOPE_SECONDS),
                }
                global_dev.write_json(spec_path, spec)
                spec_sha = global_dev.digest(spec_path)
                global_dev.write_json(authority_path, {
                    'status': 'IN_PROGRESS', 'gate_eligible': False,
                    'spec_sha256': spec_sha})
                try:
                    self.consumer_hard_wall_enforced = True
                    guarded = _run_guarded_consumer_command(
                        global_dev._consumer_worker_command(
                            spec_path, spec_sha, pycache_prefix),
                        run_dir / 'consumer_worker.log',
                        wall_seconds=remaining -
                        global_dev.GUARD_CLEANUP_ENVELOPE_SECONDS,
                        environment={
                            **os.environ,
                            global_dev._PRODUCT_SRC_ENV: str(global_dev.PRODUCT_SRC),
                            global_dev._WORKER_PYCACHE_ENV: str(pycache_prefix),
                        })
                    self.consumer_guard_status = guarded['status']
                    if guarded['status'] == 'STOPPED_GLOBAL_CONSUMER_WALL':
                        self.consumer_wall_overrun = True
                        raise TimeoutError('Global consumer physical wall exceeded')
                    if guarded['status'] != 'GLOBAL_CONSUMER_COMPLETE':
                        raise ValueError('Global consumer child or cleanup failed')
                    if result_path.is_symlink() or not result_path.is_file():
                        raise ValueError('Global consumer result missing')
                    result = json.loads(result_path.read_text())
                    if (not isinstance(result, dict) or
                            set(result) != {'kind', 'status', 'rows', 'spec_sha256',
                                            'report_sha256', 'contract_sha256',
                                            'binary_sha256'} or
                            result['kind'] != 'DEV_GLOBAL_CONSUMER_RESULT_V1' or
                            result['status'] != 'COMPLETED' or
                            not isinstance(result['rows'], list) or
                            result['spec_sha256'] != spec_sha or
                            result['report_sha256'] != spec['report_sha256'] or
                            result['contract_sha256'] != qualification.contract_sha256 or
                            result['binary_sha256'] != qualification.binary_sha256 or
                            not self.campaign._authority_ok()):
                        raise ValueError('Global consumer result authority changed')
                    self.consumer_result_sha256 = global_dev.digest(result_path)
                    self.consumer_authority_status = 'COMPLETED'
                    global_dev.write_json(authority_path, {
                        'status': 'COMPLETED', 'gate_eligible': True,
                        'spec_sha256': spec_sha,
                        'result_sha256': self.consumer_result_sha256})
                    return result['rows']
                except BaseException:
                    self.consumer_authority_status = 'INCOMPLETE'
                    try:
                        global_dev.write_json(authority_path, {
                            'status': 'INCOMPLETE', 'gate_eligible': False,
                            'spec_sha256': spec_sha,
                            'guard_status': self.consumer_guard_status})
                    except BaseException:
                        pass
                    raise
                finally:
                    self.consumer_wall_elapsed += time.monotonic() - started
                    self.consumer_wall_overrun = (
                        self.consumer_wall_overrun or
                        self.consumer_wall_elapsed > self.consumer_wall_seconds)

            try:
                with patch.object(global_dev, 'consume_global_fuzzer_observations',
                                  bounded_consumer):
                    global_result = self.campaign.finish()
            except BaseException as exc:
                stopped = self._abort_preserving_error()
                self._record_preserving_error('INCOMPLETE_GLOBAL_FINISH_ERROR',
                                              rows, ledger, stopped, exc)
                raise
        else:
            global_result = self.campaign.final_result or {
                'status': 'NOT_STARTED_NO_DIRECTION_SEED'}
        self.write_budget()
        charged_non_global = sum(
            row['physical_seconds'] for row in self.campaign.budget.records
            if row['key'] != 'GLOBAL')
        ledger_physical = ledger.fuzz_physical_actual
        mismatch = abs(charged_non_global - ledger_physical) > 0.01
        if (mismatch or self.consumer_wall_overrun or
                self.shared_budget_failed or
                global_result.get('status') not in {
                    'RAN', 'CRASH_OBSERVED_INCOMPLETE',
                    'NOT_STARTED_NO_DIRECTION_SEED'}):
            status = ('STOPPED_SHARED_LEDGER_MISMATCH' if mismatch else
                      'INCOMPLETE_GLOBAL_CONSUMER_WALL_OVERRUN'
                      if self.consumer_wall_overrun else
                      'STOPPED_SHARED_FUZZ_BUDGET' if self.shared_budget_failed else
                      'STOPPED_GLOBAL_CAMPAIGN')
            result = self._write_result(status, rows, ledger, global_result)
            raise SharedPhysicalBudgetExceeded(status)
        return self._write_result('DEV_SEQUENCE_COMPLETE', rows, ledger, global_result)

    def _write_result(self, status: str, rows: list[dict[str, Any]],
                      ledger: runner.Ledger, global_result: dict[str, Any],
                      error: BaseException | None = None) -> dict[str, Any]:
        result = {
            'status': ('STOPPED_CLEANUP_INCOMPLETE'
                       if (global_result.get('status') == 'STOPPED_CLEANUP_INCOMPLETE' or
                           self.consumer_guard_status == 'STOPPED_CLEANUP_INCOMPLETE')
                       else status),
            'function_rows': rows,
            'global_result_status': global_result.get('status'),
            'global_cleanup_complete': global_result.get('cleanup_complete'),
            'global_function_windows': self.campaign.function_windows,
            'shared_physical_budget': self.campaign.budget.snapshot(),
            'runner_sp_hp_physical_seconds': ledger.fuzz_physical_actual,
            'consumer_wall_seconds': self.consumer_wall_elapsed,
            'consumer_wall_limit_seconds': self.consumer_wall_seconds,
            'consumer_wall_overrun': self.consumer_wall_overrun,
            'consumer_hard_wall_enforced': self.consumer_hard_wall_enforced,
            'consumer_guard_status': self.consumer_guard_status,
            'consumer_authority_status': self.consumer_authority_status,
            'consumer_result_sha256': self.consumer_result_sha256,
            'consumer_wall_scope': 'GUARDED_CHILD_WITH_CLEANUP_ENVELOPE',
            'accounting_errors': self.accounting_errors,
            'physical_debit_overruns': self.physical_debit_overruns,
            'overrun_policy': self.overrun_policy,
            'global_termination_grace_seconds': self.termination_grace_seconds,
            'runner_fuzz_overrun_policy': ledger.fuzz_overrun_policy,
            'parallel_physical_hard_cap_enforced': False,
            'parallel_physical_cap_scope': 'POSTCHARGE_DETECTION_ONLY',
            'error_type': type(error).__name__ if error else None,
        }
        global_dev.write_json(self.result_path, result)
        return result
