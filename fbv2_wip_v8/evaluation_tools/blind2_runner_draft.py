"""Blind evaluation runner under construction; --execute requires frozen approval.

Import and dry-run tests have no model or mutation Fuzzing side effects.
"""
from __future__ import annotations
import sys

# Python otherwise searches the script directory before importing stdlib
# modules below. An execution must enter in isolated mode from the start.
if __name__ == '__main__' and '--execute' in sys.argv and not sys.flags.isolated:
    raise SystemExit('Blind 2 execution requires python -I')

import atexit
import argparse
import asyncio
import ctypes
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import tomllib
from typing import Any

HERE = Path(__file__).resolve().parent
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path.insert(0, str(HERE))


def _early_digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_preimport_execution_authority(contract_path: Path, runner_path: Path,
                                         reference_root: Path, *, child: bool) -> None:
    """Anchor the first imported Freeze helper to the one-use approval."""
    root = reference_root.resolve(strict=True)
    contract_path = contract_path.resolve(strict=True)
    runner_path = runner_path.resolve(strict=True)
    if (not contract_path.is_relative_to(root) or
            not runner_path.is_relative_to(root)):
        raise ValueError('bootstrap approval paths outside reference root')
    vault = root / 'approval_runs'
    slot = vault / _early_digest(contract_path)
    receipt = slot / ('APPROVAL_CONSUMED.json' if child else 'APPROVAL.json')
    if (vault.is_symlink() or slot.is_symlink() or receipt.is_symlink() or
            not receipt.is_file()):
        raise ValueError('bootstrap approval unavailable or linked')
    row = json.loads(receipt.read_text())
    if (row.get('approved') is not True or
            row.get('contract_sha256') != _early_digest(contract_path) or
            row.get('runner_sha256') != _early_digest(runner_path)):
        raise ValueError('bootstrap approval does not bind contract and runner')


def verify_preimport_helper_pins(contract: dict, reference_root: Path,
                                 tools_dir: Path, runner_path: Path) -> None:
    """Authenticate the Freeze verifier before importing it or product code."""
    root = reference_root.resolve(strict=True)
    tools_dir = tools_dir.resolve(strict=True)
    if (contract.get('freeze_spec') != 'tools/freeze_spec.json' or
            contract.get('freeze_manifest') != 'public/FREEZE_MANIFEST.json'):
        raise ValueError('bootstrap freeze paths changed')
    spec = root / contract['freeze_spec']
    manifest = root / contract['freeze_manifest']
    if (_early_digest(spec) != contract.get('freeze_spec_sha256') or
            _early_digest(manifest) != contract.get('freeze_manifest_sha256')):
        raise ValueError('bootstrap freeze digest changed')
    rows = json.loads(manifest.read_text()).get('entries')
    if not isinstance(rows, list):
        raise ValueError('bootstrap Manifest entries unavailable')
    for name, actual in ((runner_path.name, runner_path),
                         ('blind2_freeze_contract.py', tools_dir / 'blind2_freeze_contract.py'),
                         ('create_freeze_manifest.py', tools_dir / 'create_freeze_manifest.py'),
                         ('blind2_model_sandbox.py', tools_dir / 'blind2_model_sandbox.py')):
        expected = tools_dir / name
        if (actual.resolve(strict=True) != expected or actual.is_symlink() or
                not expected.is_file() or expected.is_symlink()):
            raise ValueError(f'bootstrap helper path changed: {name}')
        relative = expected.relative_to(root).as_posix()
        matched = [row for row in rows if isinstance(row, dict) and
                   row.get('root') == 'reference' and
                   row.get('group') == 'evaluation_tools' and
                   row.get('path') == relative]
        if len(matched) != 1 or matched[0].get('sha256') != _early_digest(expected):
            raise ValueError(f'bootstrap helper missing from frozen Manifest: {name}')


def verify_loaded_module_origins(modules: dict, tools_dir: Path,
                                  product_src: Path) -> None:
    """Reject evaluation-helper shadowing and sourceless product imports."""
    tools_dir = tools_dir.resolve(strict=True)
    product_src = product_src.resolve(strict=True)
    package = (product_src / 'vulnerabilityanalysis').resolve(strict=True)
    helpers = ('blind_runner_guards', 'blind2_budget_guard',
               'blind2_freeze_contract', 'create_freeze_manifest',
               'catalog_build_integrity', 'pinned_codex_delta_protocol')
    for name in helpers:
        module = modules.get(name)
        if module is None or Path(str(getattr(module, '__file__', ''))).resolve() != tools_dir / f'{name}.py':
            raise ValueError(f'loaded module origin changed: {name}')
    yaml_module = modules.get('yaml')
    yaml_path = Path(str(getattr(yaml_module, '__file__', ''))).resolve()
    if (yaml_module is None or yaml_path.is_relative_to(tools_dir) or
            yaml_path.is_relative_to(product_src)):
        raise ValueError('loaded module origin changed: yaml')
    for name, module in modules.items():
        if name != 'vulnerabilityanalysis' and not name.startswith('vulnerabilityanalysis.'):
            continue
        path = Path(str(getattr(module, '__file__', ''))).resolve()
        if path.suffix != '.py' or not path.is_relative_to(package):
            raise ValueError(f'loaded module origin changed: {name}')


def _fresh_execution_pycache() -> None:
    """Re-exec with a new cache before any evaluator or product import."""
    current_pid = str(os.getpid())
    prefix = os.environ.get('PYTHONPYCACHEPREFIX')
    if os.environ.get('VA_BLIND2_PYCACHE_PID') == current_pid:
        if (not prefix or sys.pycache_prefix != prefix or
                not Path(prefix).is_dir() or Path(prefix).is_symlink()):
            raise ValueError('isolated Python cache not active')
        # A forged marker can name a pre-populated -X cache. The interpreter
        # may have already cached stdlib modules, but it must not have project
        # code cached before the Freeze check and product/helper imports.
        for project in (HERE, PRODUCT):
            relative = project.resolve().relative_to(project.anchor)
            if (Path(prefix) / relative).exists():
                raise ValueError('isolated project bytecode cache is not empty')
        atexit.register(shutil.rmtree, prefix, ignore_errors=True)
        return
    directory = Path(tempfile.mkdtemp(prefix='va-blind2-pycache-'))
    directory.chmod(0o700)
    environment = {**os.environ, 'PYTHONPYCACHEPREFIX': str(directory),
                   'VA_BLIND2_PYCACHE_PID': current_pid}
    os.execve(sys.executable, [sys.executable, '-I', '-X',
                               f'pycache_prefix={directory}',
                               str(Path(__file__).resolve()),
                               *sys.argv[1:]], environment)
    raise RuntimeError('fresh Python cache exec did not replace the process')


def _preimport_execution_check() -> None:
    _fresh_execution_pycache()
    try:
        contract_arg = sys.argv[sys.argv.index('--contract') + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError('frozen contract path required before import') from exc
    contract_path = Path(contract_arg).resolve(strict=True)
    reference = HERE.parent.resolve(strict=True)
    if not contract_path.is_file() or not contract_path.is_relative_to(reference):
        raise ValueError('frozen contract outside approved reference root')
    verify_preimport_execution_authority(
        contract_path, Path(__file__), reference, child='--child' in sys.argv)
    contract = json.loads(contract_path.read_text())
    verify_preimport_helper_pins(contract, reference, HERE, Path(__file__).resolve())
    from blind2_freeze_contract import verify_frozen_surface as early_verify
    early_verify(contract, reference, PRODUCT.parent)


if __name__ == '__main__' and '--execute' in sys.argv:
    _preimport_execution_check()

# Import YAML and evaluator helpers before adding product/src to the search
# path. This prevents a same-named top-level product file from shadowing them.
import yaml
from blind_runner_guards import check_contract, consume_approval, digest  # noqa: E402
from blind2_budget_guard import Blind2Ledger as Ledger  # noqa: E402
from blind2_freeze_contract import verify_frozen_surface  # noqa: E402
from catalog_build_integrity import audit_catalog_build  # noqa: E402
sys.path.insert(1, str(PRODUCT / 'src'))
from pinned_codex_delta_protocol import PinnedCodexDeltaGuard  # noqa: E402
from vulnerabilityanalysis import scan as scan_mod  # noqa: E402
from vulnerabilityanalysis import assertions as assertion_mod  # noqa: E402
from vulnerabilityanalysis import workflow as workflow_mod  # noqa: E402
from vulnerabilityanalysis.adapter import HarnessAdapter  # noqa: E402
from vulnerabilityanalysis.llm import (AppServerError, CodexAppServerClient,
                                       ModelToolEventError, ModelAuditError,
                                       ProviderSafetyRefusedError)  # noqa: E402
from vulnerabilityanalysis.official_harness import issue_official_pinned_qualification  # noqa: E402
from vulnerabilityanalysis.official_harness import (OfficialPinnedQualification,
    _qualification_pins_ok)  # noqa: E402
from vulnerabilityanalysis.fuzzer_crash_consumer import (
    MAX_RETAINED_INPUT_BYTES, consume_fuzzer_crash_observation)  # noqa: E402
from vulnerabilityanalysis.runtime import (  # noqa: E402
    PhysicalFuzzBudgetPending, PhysicalFuzzStop, RuntimeCleanupError)
from vulnerabilityanalysis.source import SourceRepository  # noqa: E402
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1, write_json  # noqa: E402

if __name__ == '__main__' and '--execute' in sys.argv:
    verify_loaded_module_origins(sys.modules, HERE, PRODUCT / 'src')


def request_digest(request: Any) -> str:
    value = {'role': request.role, 'instructions': request.instructions,
             'payload': request.payload, 'schema': request.output_schema,
             'session_key': request.session_key, 'model': request.model,
             'effort': request.effort}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


PHYSICAL_FUZZ_TERMINAL_STATUSES = frozenset({
    'STOPPED_PHYSICAL_LEDGER_ERROR', 'STOPPED_UNCERTAIN_PROCESS',
    'STOPPED_PHYSICAL_CAP_UNPROVEN', 'STOPPED_CLEANUP_INCOMPLETE',
    'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE', 'PENDING_SHARED_PHYSICAL_BUDGET',
})


class FuzzMeterAccountingError(ValueError):
    """The evaluator cannot certify a started Fuzzing job's settlement."""


def classify_scan_interruption(exc: BaseException) -> str:
    """Record response deadlines separately from other inconclusive stops."""
    if isinstance(exc, (ModelAuditError, FatalModelAuditFailure)):
        return 'INCOMPLETE_AUDIT_ERROR'
    if isinstance(exc, (ProviderSafetyRefusedError, FatalProviderSafetyRefusal)):
        return 'PROVIDER_SAFETY_REFUSED'
    if isinstance(exc, ModelToolEventError):
        return 'INCOMPLETE_TOOL_EVENT'
    if isinstance(exc, FuzzMeterAccountingError):
        return 'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE'
    if isinstance(exc, PhysicalFuzzBudgetPending):
        return 'PENDING_SHARED_PHYSICAL_BUDGET'
    if isinstance(exc, PhysicalFuzzStop):
        return (exc.status if exc.status in PHYSICAL_FUZZ_TERMINAL_STATUSES
                else 'STOPPED_PHYSICAL_LEDGER_ERROR')
    if isinstance(exc, RuntimeCleanupError):
        return 'STOPPED_CLEANUP_INCOMPLETE'
    if isinstance(exc, asyncio.CancelledError):
        return 'INCOMPLETE_CANCELLED'
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return 'INCOMPLETE_TIMEOUT'
    if isinstance(exc, AppServerError) and ('timed out' in str(exc).lower() or
                                            'wall deadline' in str(exc).lower()):
        return 'INCOMPLETE_TIMEOUT'
    return 'INCONCLUSIVE'


def assert_model_input_blind(request: Any) -> None:
    """Reject evaluator-only artifact paths before any model transport attempt."""
    model_input = json.dumps({'instructions': request.instructions,
                              'payload': request.payload,
                              'schema': request.output_schema},
                             ensure_ascii=False, sort_keys=True).lower()
    forbidden = ('evaluator_only', 'evaluator-only', 'oracle_manifest.json',
                 'seal.json', 'oracle_input.bin', 'oracle_stack')
    if any(marker in model_input for marker in forbidden):
        raise ValueError('evaluator-only or Oracle artifact marker in model input')


def output_event(message: dict, turn_id: str | None) -> bool:
    params = message.get('params') or {}
    if not turn_id or params.get('turnId') != turn_id:
        return False
    if message.get('method') == 'item/agentMessage/delta':
        return bool(params.get('delta'))
    if message.get('method') == 'item/completed':
        item = params.get('item') or {}
        return item.get('type') == 'agentMessage' and bool(item.get('text'))
    return False


async def check_live_route(client: CodexAppServerClient, route_sha256: str,
                           role_models: dict[str, dict[str, str]]) -> None:
    """Read only live Provider metadata; never start a model thread or turn."""
    await client.start()
    account = await client._request('account/read', {'refreshToken': False})
    route = account.get('workspaceRouting')
    if account.get('requiresOpenaiAuth') is not True or not isinstance(route, dict):
        raise ValueError('workspace route unavailable')
    observed = hashlib.sha256(json.dumps(route, sort_keys=True).encode()).hexdigest()
    if observed != route_sha256:
        raise ValueError('workspace route changed')
    rows = (await client._request('model/list', {'includeHidden': True})).get('data', [])
    available = {row.get('id') or row.get('model') for row in rows if isinstance(row, dict)}
    if any(row['model'] not in available for row in role_models.values()):
        raise ValueError('pinned model unavailable')


class FatalProviderSafetyRefusal(BaseException):
    """Stop the entire blind run even when product stages catch Exception."""


class FatalModelAuditFailure(BaseException):
    """Stop the entire blind run when the private model audit is incomplete."""


class GuardedAppServer(PinnedCodexDeltaGuard, CodexAppServerClient):
    """Guard actual turn/start attempts, model route, partial output and retries."""

    # Product acceptance checks explicitly use the base class 4 KiB limit.
    # Only this evaluator's private non-delta recorder uses ``self``; preserve
    # complete turn summaries for the formal post-run event audit.
    STARTUP_NOTIFICATION_AUDIT_MAX_BYTES = 64 * 1024

    def __init__(self, *, ledger: Ledger, checkpoint: Path,
                 route_sha256: str, role_models: dict[str, dict[str, str]],
                 codex_executable_path: Path, codex_executable_sha256: str,
                 **kwargs: Any):
        super().__init__(**kwargs)
        self.ledger, self.checkpoint_path = ledger, checkpoint
        self.route_sha256, self.role_models = route_sha256, role_models
        self.codex_executable_path = codex_executable_path
        self.codex_executable_sha256 = codex_executable_sha256
        self.function_id: str | None = None
        self.request_hash: str | None = None
        self.accepted_turn_id: str | None = None
        self.visible_output = False
        self.internal_retry_signal = False
        self.server_terminal_status: str | None = None

    async def start(self) -> None:
        # A failed turn may restart App Server, so every physical start must
        # recheck the exact executable named in the frozen contract.
        pinned = verify_pinned_codex_executable({
            'codex_executable_path': str(self.codex_executable_path),
            'codex_executable_sha256': self.codex_executable_sha256})
        if Path(self.executable).resolve() != pinned:
            raise ValueError('Codex executable changed before physical launch')
        await super().start()

    def begin_function(self, function_id: str) -> None:
        if self.function_id is not None:
            raise ValueError('previous function active')
        self.function_id = function_id

    def end_function(self) -> None:
        self.function_id = None

    async def verify_route(self) -> None:
        await check_live_route(self, self.route_sha256, self.role_models)

    async def _request(self, method: str, params: dict) -> dict:
        if method != 'turn/start':
            return await super()._request(method, params)
        if self.function_id is None or self.request_hash is None:
            raise ValueError('model start outside guarded function')
        role = self.ledger.active_turn['role']
        route = self.role_models[role]
        if params.get('model') != route['model'] or params.get('effort') != route['reasoning']:
            raise ValueError('model route changed')
        self.ledger.start_attempt(self.request_hash,
                                  retry=self.ledger.active_turn['attempts'] > 0)
        self.ledger.attempts[-1]['role'] = role
        self.ledger.attempts[-1]['model'] = route['model']
        self.ledger.checkpoint(self.checkpoint_path)
        response = await super()._request(method, params)
        self.accepted_turn_id = (response.get('turn') or {}).get('id')
        self.ledger.attempts[-1]['app_server_turn_id'] = self.accepted_turn_id
        self.ledger.checkpoint(self.checkpoint_path)
        return response

    async def _read(self) -> dict:
        message = await super()._read()
        if (message.get('method') == 'error' and
                (message.get('params') or {}).get('willRetry') is True):
            self.internal_retry_signal = True
            if self._process and self._process.returncode is None:
                self._process.kill()
            raise AppServerError('internal retry announced; stopped')
        if output_event(message, self.accepted_turn_id):
            self.visible_output = True
        return message

    async def _collect(self, thread_id: str, turn_id: str) -> str:
        # turn/start can queue deltas before returning the accepted turn ID.
        for message in self._notifications:
            self._guard_pinned_delta(
                message, expected_thread=thread_id, expected_turn=turn_id)
        if any(row.get('method') == 'error' and
               (row.get('params') or {}).get('willRetry') is True
               for row in self._notifications):
            self.internal_retry_signal = True
            raise AppServerError('queued internal retry announced; stopped')
        if any(output_event(row, turn_id) for row in self._notifications):
            self.visible_output = True
        result = await super()._collect(thread_id, turn_id)
        # Parsing or output-schema validation can fail after the server has
        # completed. Preserve that distinction in the physical ledger.
        self.server_terminal_status = 'completed'
        return result

    async def generate(self, request: Any) -> dict:
        assert_model_input_blind(request)
        if self.provider_safety_refused:
            raise FatalProviderSafetyRefusal(
                'PROVIDER_SAFETY_REFUSED: provider session already blocked')
        if self.audit_log_failed:
            raise FatalModelAuditFailure('MODEL_AUDIT_WRITE_FAILED: provider session already tainted')
        if self.function_id is None or request.role not in self.role_models:
            raise ValueError('unapproved model role or no selected function')
        route = self.role_models[request.role]
        if ((request.model or self.model) != route['model'] or
                (request.effort or self.effort) != route['reasoning']):
            raise ValueError('role model or effort mismatch')
        self.request_hash = request_digest(request)
        self.ledger.begin_turn(self.function_id, request.role, self.request_hash)
        self.ledger.checkpoint(self.checkpoint_path)
        try:
            for ordinal in (1, 2):
                self.accepted_turn_id = None
                self.visible_output = False
                self.internal_retry_signal = False
                self.server_terminal_status = None
                try:
                    remaining = self.ledger.started_at + 86400 - time.time()
                    if remaining <= 0:
                        raise TimeoutError('blind wall deadline reached')
                    result = await asyncio.wait_for(super().generate(request),
                        timeout=min(self.timeout_seconds, remaining))
                    self.ledger.finish_attempt(completed=True, accepted=True,
                        visible=self.visible_output,
                        response_saved=bool(request.raw_response_path and
                                            request.raw_response_path.is_file()))
                    self.ledger.checkpoint(self.checkpoint_path)
                    return result
                except AppServerError as exc:
                    if not self.ledger.attempts or self.ledger.attempts[-1]['status'] != 'STARTED':
                        raise
                    error = str(exc)
                    ids = re.findall(r'request ID ([A-Za-z0-9-]+)', error)
                    if self.server_terminal_status is not None:
                        self.ledger.attempts[-1]['server_terminal_status'] = (
                            self.server_terminal_status)
                    eligible = self.ledger.finish_attempt(completed=False,
                        error=error, accepted=bool(self.accepted_turn_id),
                        visible=self.visible_output,
                        response_saved=bool(request.raw_response_path and
                                            request.raw_response_path.is_file()),
                        internal_retry=self.internal_retry_signal,
                        request_id=ids[-1] if ids else None)
                    self.ledger.checkpoint(self.checkpoint_path)
                    if isinstance(exc, ProviderSafetyRefusedError):
                        raise FatalProviderSafetyRefusal(str(exc)) from exc
                    if isinstance(exc, ModelAuditError):
                        raise FatalModelAuditFailure(str(exc)) from exc
                    if not eligible or ordinal == 2:
                        raise
                    await self.verify_route()
            raise RuntimeError('manual retry exhausted')
        except BaseException as exc:
            if (self.ledger.active_turn and self.ledger.attempts and
                    self.ledger.attempts[-1]['status'] == 'STARTED'):
                if self.server_terminal_status is not None:
                    self.ledger.attempts[-1]['server_terminal_status'] = (
                        self.server_terminal_status)
                self.ledger.finish_attempt(completed=False, error=str(exc),
                    accepted=bool(self.accepted_turn_id), visible=self.visible_output,
                    internal_retry=self.internal_retry_signal)
            if self.ledger.active_turn:
                self.ledger.abandon_turn(self.function_id, type(exc).__name__)
            self.ledger.checkpoint(self.checkpoint_path)
            raise
        finally:
            self.request_hash = None


def verify_formal_model_event_order(ledger: Ledger, event_log: Path) -> dict[str, Any]:
    """Bind private App Server events to the formal physical-call ledger.

    This is an evaluator-side audit of the pinned product client's accepted
    notifications. Delta contents are intentionally not logged; their shape
    needs the separate prefreeze protocol check before a full no-tool claim.
    """
    if event_log.is_symlink() or not event_log.is_file():
        raise ValueError('model event log missing or linked')
    info = event_log.stat()
    parent = event_log.parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077 or event_log.parent.is_symlink() or
            not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or
            parent.st_mode & 0o077):
        raise ValueError('model event log is not private')
    attempts = ledger.attempts
    if (len(attempts) != ledger.physical or
            any(row.get('physical') != index or
                row.get('status') not in ('COMPLETED', 'ERROR') or
                not isinstance(row.get('request_hash'), str) or
                len(row['request_hash']) != 64
                for index, row in enumerate(attempts, 1))):
        raise ValueError('physical model ledger is incomplete')
    accepted = [row for row in attempts
                if isinstance(row.get('app_server_turn_id'), str) and
                row['app_server_turn_id']]
    if any(row['status'] == 'COMPLETED' and
           not (isinstance(row.get('app_server_turn_id'), str) and
                row['app_server_turn_id']) for row in attempts):
        raise ValueError('completed model turn has no App Server identity')
    turn_ids = [row['app_server_turn_id'] for row in accepted]
    if len(turn_ids) != len(set(turn_ids)):
        raise ValueError('duplicate App Server turn identity')
    positions = {turn_id: index for index, turn_id in enumerate(turn_ids)}
    attempts_by_id = {row['app_server_turn_id']: row for row in accepted}
    delta_methods = frozenset({
        'item/agentMessage/delta', 'item/reasoning/textDelta',
        'item/reasoning/summaryTextDelta',
    })
    allowed_methods = frozenset({
        '<response>', 'account/rateLimits/updated',
        'thread/started', 'thread/status/changed',
        'thread/tokenUsage/updated', 'thread/settings/updated',
        'turn/started', 'turn/completed', 'turn/moderationMetadata',
        'model/safetyBuffering/updated',
        'item/started', 'item/updated', 'item/completed',
        'item/reasoning/summaryPartAdded', *delta_methods,
        'error', *CodexAppServerClient.PURE_STARTUP_NOTIFICATIONS,
    })
    completed: list[str] = []
    started: set[str] = set()
    terminal: set[str] = set()
    terminal_status: dict[str, str] = {}
    terminal_raw: dict[str, dict[str, Any]] = {}
    turn_threads: dict[str, str] = {}
    safety_events: dict[str, dict[str, Any]] = {}
    safety_summaries: set[str] = set()
    stale_pending: tuple[str, str] | None = None
    stale_summary_count = 0
    latest_position = -1
    event_count = 0
    with event_log.open('r', encoding='utf-8') as stream:
        for line in stream:
            event_count += 1
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('invalid model event audit row')
            classification = row.get('classification')
            if stale_pending is not None and classification != 'STALE_OR_UNRELATED_TURN_EVENT':
                raise ValueError('stale turn summary missing after duplicate')
            if classification == 'STALE_OR_UNRELATED_TURN_EVENT':
                if (set(row) != {'method', 'classification', 'thread_id', 'turn_id'} or
                        row['method'] != 'turn/completed' or
                        stale_pending != (row['thread_id'], row['turn_id'])):
                    raise ValueError('stale turn summary differs from bound duplicate')
                stale_pending = None
                stale_summary_count += 1
                continue
            if classification == 'PROVIDER_SAFETY_BUFFERING':
                expected_keys = {
                    'classification', 'buffered', 'thread_id', 'turn_id',
                    'role', 'requested_model', 'faster_models', 'reasons',
                    'use_cases', 'buffer_to_turn_end_seconds',
                    'buffer_to_stop_seconds', 'turn_status',
                }
                turn_id = row.get('turn_id')
                raw = safety_events.get(turn_id)
                attempt = attempts_by_id.get(turn_id)
                if (set(row) != expected_keys or not isinstance(turn_id, str) or
                        turn_id in safety_summaries or raw is None or
                        attempt is None or not isinstance(row.get('thread_id'), str) or
                        row['thread_id'] != raw['thread_id'] or
                        row['thread_id'] != turn_threads.get(turn_id) or
                        row.get('role') != attempt.get('role') or
                        row.get('requested_model') != attempt.get('model') or
                        row['requested_model'] != raw['model'] or
                        type(row.get('buffered')) is not bool or
                        row['buffered'] != raw['buffered'] or
                        row.get('faster_models') != sorted(raw['faster_models']) or
                        row.get('reasons') != sorted(raw['reasons']) or
                        row.get('use_cases') != sorted(raw['use_cases']) or
                        row.get('turn_status') not in
                        ('completed', 'incomplete', 'provider_safety_refused')):
                    raise ValueError('provider safety summary differs from raw turn')
                end = row['buffer_to_turn_end_seconds']
                stop = row['buffer_to_stop_seconds']
                if (row['buffered'] and (
                        row['turn_status'] == 'completed' and
                        (type(end) not in (int, float) or
                         not math.isfinite(end) or end < 0 or stop is not None) or
                        row['turn_status'] != 'completed' and
                        (type(stop) not in (int, float) or
                         not math.isfinite(stop) or stop < 0 or end is not None)) or
                        not row['buffered'] and (end is not None or stop is not None)):
                    raise ValueError('provider safety duration differs from status')
                if (row['turn_status'] == 'completed' and
                        terminal_status.get(turn_id) != 'completed' or
                        row['turn_status'] == 'incomplete' and
                        attempt['status'] != 'ERROR'):
                    raise ValueError('provider safety terminal status differs from ledger')
                if row['turn_status'] == 'provider_safety_refused':
                    raise ValueError('provider safety refusal cannot finalize a run')
                safety_summaries.add(turn_id)
                continue
            if classification == 'PROVIDER_SAFETY_REFUSED':
                if (set(row) != {'classification', 'thread_id', 'turn_id', 'role'} or
                        row.get('turn_id') not in attempts_by_id or
                        row.get('thread_id') != turn_threads.get(row['turn_id']) or
                        row.get('role') != attempts_by_id[row['turn_id']].get('role')):
                    raise ValueError('provider refusal summary not bound to a turn')
                raise ValueError('provider safety refusal cannot finalize a run')
            if classification is not None:
                raise ValueError('unknown model event audit classification')
            if (row.get('method') not in allowed_methods or
                    row.get('server_request') is not False or
                    row.get('item_type') not in (None, 'userMessage',
                                                  'agentMessage', 'reasoning') or
                    not isinstance(row.get('thread_id'), str) or
                    not isinstance(row.get('turn_id'), str)):
                raise ValueError('model event log contains a tool or server request')
            method = row['method']
            params = row.get('params')
            if method == '<response>':
                if (params is not None or row['thread_id'] or row['turn_id'] or
                        row['item_type'] is not None):
                    raise ValueError('invalid App Server response audit row')
                continue
            if method in delta_methods:
                if (params is not None or row['item_type'] is not None or
                        not row['thread_id'] or not row['turn_id']):
                    raise ValueError('invalid model delta audit row')
            else:
                if not isinstance(params, dict):
                    raise ValueError('model notification params unavailable')
                if CodexAppServerClient._unapproved_event_label(
                        {'method': method, 'params': params}) is not None:
                    raise ValueError('model event log contains a tool or server request')
                if row['thread_id'] != str(params.get('threadId', '')):
                    raise ValueError('model event thread identity changed')
                if method in ('item/started', 'item/updated', 'item/completed'):
                    item = params.get('item')
                    if (not isinstance(item, dict) or
                            row['item_type'] != item.get('type')):
                        raise ValueError('model event item identity changed')
                elif row['item_type'] is not None:
                    raise ValueError('model event item identity changed')
                if method != 'turn/completed' and row['turn_id'] != str(
                        params.get('turnId', '')):
                    raise ValueError('model event turn identity changed')
            turn_id = row['turn_id']
            if method == 'turn/started':
                turn = params.get('turn')
                if not isinstance(turn, dict) or not isinstance(turn.get('id'), str):
                    raise ValueError('started App Server turn identity missing')
                turn_id = turn['id']
                if turn_id in started:
                    raise ValueError('duplicate App Server turn start')
                started.add(turn_id)
            elif method == 'turn/completed':
                turn = params.get('turn')
                if (not isinstance(turn, dict) or not isinstance(turn.get('id'), str)
                        or not row['thread_id'] or row['turn_id'] != turn['id']):
                    raise ValueError('completed App Server turn identity changed')
            if method in ('turn/started', 'turn/completed') and 'items' in turn:
                items = turn['items']
                if (not isinstance(items, list) or any(
                        not isinstance(item, dict) or item.get('type') not in
                        ('userMessage', 'agentMessage', 'reasoning')
                        for item in items)):
                    raise ValueError('model event log contains a tool or server request')
            if turn_id:
                if turn_id not in positions:
                    raise ValueError('model event turn order differs from ledger')
                if (turn_id in turn_threads and
                        turn_threads[turn_id] != row['thread_id']):
                    raise ValueError('model event thread identity changed')
                turn_threads[turn_id] = row['thread_id']
                if method == 'turn/completed' and turn_id in terminal:
                    if params != terminal_raw.get(turn_id):
                        raise ValueError('stale turn completion changed')
                    stale_pending = (row['thread_id'], turn_id)
                elif positions[turn_id] < latest_position:
                    raise ValueError('model event turn order differs from ledger')
                latest_position = max(latest_position, positions[turn_id])
            if method == 'model/safetyBuffering/updated':
                if not turn_id or turn_id in safety_summaries:
                    raise ValueError('late or unbound safety buffering notification')
                raw = safety_events.setdefault(turn_id, {
                    'thread_id': row['thread_id'], 'model': params['model'],
                    'buffered': False, 'faster_models': set(),
                    'reasons': set(), 'use_cases': set(),
                })
                if raw['model'] != params['model'] or raw['thread_id'] != row['thread_id']:
                    raise ValueError('safety buffering model or thread changed')
                raw['buffered'] |= params['showBufferingUi']
                raw['reasons'].update(params['reasons'])
                raw['use_cases'].update(params['useCases'])
                if params['fasterModel'] is not None:
                    raw['faster_models'].add(params['fasterModel'])
            if method == 'error':
                attempt = attempts_by_id.get(turn_id)
                will_retry = params.get('willRetry', False)
                if (not row['thread_id'] or not turn_id or attempt is None or
                        attempt['status'] != 'ERROR' or type(will_retry) is not bool or
                        bool(attempt.get('internal_retry')) != will_retry or
                        CodexAppServerClient._has_embedded_item(params)):
                    raise ValueError('Provider error differs from ledger outcome')
            if method == 'turn/completed':
                if turn_id in terminal:
                    if stale_pending == (row['thread_id'], turn_id):
                        continue
                    raise ValueError('duplicate or unbound turn completion')
                terminal.add(turn_id)
                status = params['turn'].get('status')
                terminal_status[turn_id] = status
                terminal_raw[turn_id] = params
                attempt_status = attempts_by_id[turn_id]['status']
                if status == 'completed':
                    if (attempt_status != 'COMPLETED' and
                            not (attempt_status == 'ERROR' and
                                 attempts_by_id[turn_id].get(
                                     'server_terminal_status') == 'completed')):
                        raise ValueError('App Server success differs from ledger outcome')
                    if attempt_status == 'COMPLETED':
                        completed.append(turn_id)
                elif not isinstance(status, str) or attempt_status != 'ERROR':
                    raise ValueError('App Server failure differs from ledger outcome')
    expected = [row['app_server_turn_id'] for row in accepted
                if row['status'] == 'COMPLETED']
    if stale_pending is not None or set(safety_events) != safety_summaries:
        raise ValueError('model event summary lineage incomplete')
    if completed != expected or any(turn_id not in started for turn_id in expected):
        raise ValueError('completed App Server turns differ from ledger')
    return {'status': 'PASS_EVENT_LINEAGE', 'event_rows': event_count,
            'physical_attempts': len(attempts), 'accepted_turns': len(accepted),
            'completed_turns': len(completed),
            'safety_summary_rows': len(safety_summaries),
            'stale_summary_rows': stale_summary_count,
            'event_log_sha256': digest(event_log),
            'delta_params_scope': 'METHOD_AND_TURN_ID_ONLY'}

class SharedFuzzMeter:
    """Serialize and charge HP guided and SP failed-PoV Fuzzing to one ledger."""
    def __init__(self, ledger: Ledger, checkpoint: Path, clock=time.monotonic,
                 prior_corpus: Path | None = None):
        self.ledger, self.checkpoint, self.clock = ledger, checkpoint, clock
        self.prior_corpus = prior_corpus
        self.records: list[dict] = []
        self.zero_budget_assertion_runs: set[Path] = set()
        self.lowlevel_fuzz_seconds = 0.0
        self.patch_depth = 0
        self.settlement_failed = False

    def invoke(self, item_id: str, kind: str, requested: int,
               function: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            seconds = self.ledger.begin_fuzz(item_id, kind, requested)
            self.ledger.checkpoint(self.checkpoint)
        except Exception as exc:
            raise FuzzMeterAccountingError('fuzz start accounting failed') from exc
        if seconds <= 0:
            pending_status = ('PENDING_FUZZ_OVERRUN_LOCKOUT'
                              if self.ledger.fuzz_overrun_blocked else
                              'PENDING_FUZZ_BUDGET')
            self.records.append({'id': item_id, 'kind': kind,
                                 'function_id': self.ledger.functions[-1]
                                 if self.ledger.functions else None,
                                 'status': pending_status, 'actual': 0})
            return {'status': pending_status}
        started = self.clock()
        lowlevel_before = self.lowlevel_fuzz_seconds
        error = None
        primary_error: BaseException | None = None
        result = None
        try:
            result = function(*args, seconds=int(seconds), **kwargs)
            return result
        except BaseException as exc:
            primary_error = exc
            error = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            try:
                elapsed = max(0.0, self.clock() - started)
                lowlevel = self.lowlevel_fuzz_seconds - lowlevel_before
                reported = (result.get('fuzz_seconds_actual')
                            if kind == 'ASSERTION' and isinstance(result, dict) else None)
                measured = (float(reported) if isinstance(reported, (int, float)) and
                            math.isfinite(reported) and reported >= 0 else
                            lowlevel if kind == 'FAILED_POV_SEED' and self.patch_depth else
                            lowlevel if lowlevel > 0 else elapsed)
                if not math.isfinite(measured):
                    measured = elapsed
                charged = min(measured, seconds)
                result_status = (str(result.get('status') or 'UNKNOWN_RESULT')
                                 if isinstance(result, dict) else
                                 'RAN' if result is not None else 'BLOCKED')
                record = self.ledger.finish_fuzz(charged, error or result_status,
                                                 physical_actual=measured)
                if kind == 'ASSERTION' and isinstance(result, dict):
                    if result.get('violation_witnesses'):
                        stop_reason = 'ASSERTION_VIOLATION'
                    elif result.get('other_crash_artifacts'):
                        stop_reason = 'OTHER_CRASH'
                    elif result.get('status') in {'BLOCKED', 'UNSUPPORTED', 'ERROR'}:
                        stop_reason = 'PRE_FUZZ_BLOCKED_OR_UNSUPPORTED'
                    elif measured < seconds - 1:
                        stop_reason = 'EARLY_RETURN_NO_WITNESS'
                    else:
                        stop_reason = 'TIME_BUDGET_OR_NORMAL_COMPLETION'
                elif kind == 'FAILED_POV_SEED' and result_status != 'RAN':
                    stop_reason = result_status
                elif kind == 'FAILED_POV_SEED' and lowlevel <= 0:
                    stop_reason = 'PRE_FUZZ_BLOCKED'
                else:
                    stop_reason = 'UNKNOWN_UNTIL_RESULT_TRIAGE'
                record.update(function_id=self.ledger.functions[-1] if self.ledger.functions else None,
                              observed_elapsed=elapsed, measured_fuzz_seconds=measured,
                              result_status=result_status,
                              termination_reason=stop_reason)
                self.records.append(record)
                self.ledger.checkpoint(self.checkpoint)
            except BaseException as settlement_error:
                self.settlement_failed = True
                if primary_error is not None:
                    # Preserve the original process/cleanup failure while
                    # marking this session fatal even if its type would
                    # normally be an inconclusive, recoverable tool error.
                    setattr(primary_error, 'fuzz_accounting_failed', True)
                    primary_error.add_note(
                        'fuzz settlement also failed: '
                        f'{type(settlement_error).__name__}: {settlement_error}')
                elif isinstance(settlement_error, (
                        asyncio.CancelledError, TimeoutError,
                        RuntimeCleanupError, PhysicalFuzzStop,
                        PhysicalFuzzBudgetPending)):
                    raise
                else:
                    raise FuzzMeterAccountingError(
                        'fuzz settlement or checkpoint failed') from settlement_error

    @contextmanager
    def patch_guided(self):
        original = scan_mod.guided_fuzz_assertion
        original_assertions = scan_mod.run_assertions_for_scan
        original_refinement = scan_mod.refine_overstrong_assertions
        original_sp_fuzz = scan_mod.fuzz_locally
        original_hp_fuzz = assertion_mod.fuzz_locally
        def bounded(assertion, *args: Any, seconds: int, **kwargs: Any):
            if self.prior_corpus is not None:
                kwargs['prior_corpus'] = self.prior_corpus
            return self.invoke(assertion.assertion_id, 'ASSERTION', seconds,
                               original, assertion, *args, **kwargs)
        def assertions_for_scan(run_dir: Path, *args: Any, **kwargs: Any):
            if kwargs.get('fuzz_seconds') == 0:
                self.zero_budget_assertion_runs.add(Path(run_dir).resolve())
            return original_assertions(run_dir, *args, **kwargs)
        async def refinement(run_dir: Path, *args: Any, **kwargs: Any):
            function_id = kwargs.get('function_id')
            counts = self.ledger.counts.get(function_id, {})
            if counts.get('assertion_generator', 0) < 1:
                return await original_refinement(run_dir, *args, **kwargs)
            results_path = Path(run_dir) / 'assertions' / 'results.json'
            rows = json.loads(results_path.read_text()) if results_path.is_file() else []
            pending = []
            for row in rows:
                runtime = row.get('execution_result')
                if row.get('status') != 'VIOLATED' or not runtime:
                    continue
                triage_path = Path(runtime).parent / 'triage.json'
                if (triage_path.is_file() and
                        json.loads(triage_path.read_text()).get('classification') ==
                        'OVERSTRONG_ASSUMPTION'):
                    pending.append(row['assertion_id'])
                    self.ledger.mark_pending(row['assertion_id'], 'PENDING_ROLE_BUDGET')
            report = {'status': ('PENDING_ROLE_BUDGET' if pending else
                                 'NO_ELIGIBLE_VIOLATION'), 'llm_calls': 0,
                      'refinements': [], 'pending_refinement_ids': pending,
                      'guided_fuzz_reserved_seconds': 0}
            write_json(Path(run_dir) / 'assertions' / 'refinement_history.json', report)
            self.ledger.checkpoint(self.checkpoint)
            return report
        def sp_fuzz(*args: Any, **kwargs: Any):
            if 'max_len' in kwargs:
                raise ValueError('runner owns fixed libFuzzer max_len')
            began = self.clock()
            try:
                return original_sp_fuzz(*args, max_len=8 * 1024 * 1024, **kwargs)
            finally:
                self.lowlevel_fuzz_seconds += max(0.0, self.clock() - began)
        def hp_fuzz(*args: Any, **kwargs: Any):
            if 'max_len' in kwargs:
                raise ValueError('runner owns fixed libFuzzer max_len')
            began = self.clock()
            try:
                return original_hp_fuzz(*args, max_len=8 * 1024 * 1024, **kwargs)
            finally:
                self.lowlevel_fuzz_seconds += max(0.0, self.clock() - began)
        scan_mod.guided_fuzz_assertion = bounded
        scan_mod.run_assertions_for_scan = assertions_for_scan
        scan_mod.refine_overstrong_assertions = refinement
        scan_mod.fuzz_locally = sp_fuzz
        assertion_mod.fuzz_locally = hp_fuzz
        self.patch_depth += 1
        try:
            yield
        finally:
            self.patch_depth -= 1
            scan_mod.guided_fuzz_assertion = original
            scan_mod.run_assertions_for_scan = original_assertions
            scan_mod.refine_overstrong_assertions = original_refinement
            scan_mod.fuzz_locally = original_sp_fuzz
            assertion_mod.fuzz_locally = original_hp_fuzz


def crash_free_pov_rows(run_dir: Path) -> list[dict]:
    path = run_dir / 'poc' / 'pocs.json'
    if not path.is_file():
        return []
    rows = json.loads(path.read_text())
    result = []
    for row in rows:
        runtime = row.get('execution_log')
        if row.get('status') != 'EXECUTED_UNRESOLVED' or not runtime:
            continue
        record_path = Path(runtime)
        if not record_path.is_file():
            continue
        record = json.loads(record_path.read_text())
        if (record.get('exit_code') == 0 and not record.get('timed_out') and
                not record.get('sanitizer') and record.get('signal') is None):
            result.append(row)
    return result


def prepare_prior_corpus(seeds: list[Path], output: Path) -> Path:
    """Copy the contract's normal Seeds under supported SHA1 names."""
    if not 1 <= len(seeds) <= 128 or len(set(seeds)) != len(seeds):
        raise ValueError('normal Seed count or paths are invalid')
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for seed in seeds:
        if (not seed.is_file() or seed.is_symlink() or
                'evaluator_only' in str(seed.resolve()).lower()):
            raise ValueError('untrusted normal Seed path')
        data = seed.read_bytes()
        name = hashlib.sha1(data).hexdigest()
        destination = output / name
        if destination.exists():
            raise ValueError('duplicate normal Seed bytes')
        destination.write_bytes(data)
        rows.append({'source': str(seed), 'sha256': hashlib.sha256(data).hexdigest(),
                     'copied': str(destination)})
    write_json(output.parent / 'NORMAL_CORPUS_MANIFEST.json', rows)
    return output


def ensure_clean_pov_seed(run: Path, poc: dict,
                          prior_corpus: Path | None = None) -> dict:
    """Bind candidate Fuzzing to the exact clean model-generated PoV bytes."""
    raw = poc.get('generated_input')
    if not raw:
        return {'status': 'BLOCKED_NO_GENERATED_POV'}
    source = Path(raw)
    if (not source.is_file() or source.is_symlink() or
            not source.resolve().is_relative_to(run.resolve())):
        return {'status': 'BLOCKED_POV_OUTSIDE_RUN'}
    source_hash = digest(source)
    corpus = run / 'corpus' / 'candidate' / poc['sp_id']
    corpus.mkdir(parents=True, exist_ok=True)
    if not corpus.resolve().is_relative_to(run.resolve()):
        return {'status': 'BLOCKED_CORPUS_OUTSIDE_RUN'}
    normal_count = 0
    if prior_corpus is not None:
        normal = sorted(prior_corpus.iterdir())
        manifest_path = prior_corpus.parent / 'NORMAL_CORPUS_MANIFEST.json'
        if not manifest_path.is_file():
            return {'status': 'BLOCKED_NORMAL_CORPUS_MANIFEST'}
        try:
            registered = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError):
            return {'status': 'BLOCKED_NORMAL_CORPUS_MANIFEST'}
        if (not isinstance(registered, list) or
                not 1 <= len(registered) <= 128 or
                len(normal) != len(registered)):
            return {'status': 'BLOCKED_NORMAL_CORPUS_COUNT'}
        registered_hashes = {str(row.get('sha256')) for row in registered
                             if isinstance(row, dict)}
        if len(registered_hashes) != len(registered):
            return {'status': 'BLOCKED_NORMAL_CORPUS_MANIFEST'}
        for seed in normal:
            if not seed.is_file() or seed.is_symlink() or not re.fullmatch(r'[0-9a-f]{40}', seed.name):
                return {'status': 'BLOCKED_NORMAL_CORPUS_FORMAT'}
            seed_bytes = seed.read_bytes()
            if (hashlib.sha1(seed_bytes).hexdigest() != seed.name or
                    hashlib.sha256(seed_bytes).hexdigest() not in registered_hashes):
                return {'status': 'BLOCKED_NORMAL_SEED_MISMATCH'}
            destination = corpus / seed.name
            if destination.exists() and digest(destination) != digest(seed):
                return {'status': 'BLOCKED_NORMAL_SEED_MISMATCH'}
            if not destination.exists():
                shutil.copyfile(seed, destination)
            normal_count += 1
    destination = corpus / f'clean_pov_{source_hash}.bin'
    if destination.exists():
        if destination.is_symlink() or digest(destination) != source_hash:
            return {'status': 'BLOCKED_CORPUS_SEED_MISMATCH'}
    else:
        shutil.copyfile(source, destination)
    return {'status': 'BOUND_CLEAN_POV', 'sha256': source_hash,
            'size': source.stat().st_size, 'corpus_path': str(destination),
            'normal_seed_count': normal_count}


def checkpoint_run(run: Path, status: str, ledger: Ledger) -> Path:
    files = {str(path.relative_to(run)): digest(path)
             for path in sorted(run.rglob('*')) if path.is_file()
             and path.name != 'FUNCTION_CHECKPOINT.json'}
    destination = run / 'FUNCTION_CHECKPOINT.json'
    write_json(destination, {'status': status, 'function_run': str(run),
                             'file_sha256': files, 'logical': ledger.logical,
                             'physical': ledger.physical, 'pending': ledger.pending})
    return destination


def record_runtime_cleanup_evidence(run: Path, function_id: str,
                                    error: RuntimeCleanupError) -> Path:
    """Save unverified partial output before the function checkpoint hashes it."""
    stdout = error.stdout or ''
    stderr = error.stderr or ''
    destination = run / 'runtime' / 'cleanup_incomplete.json'
    write_json(destination, {
        'status': 'STOPPED_CLEANUP_INCOMPLETE',
        'function_id': function_id,
        'error_type': type(error).__name__,
        'reason': str(error),
        'partial_stdout': stdout,
        'partial_stderr': stderr,
        'partial_stdout_sha256': hashlib.sha256(stdout.encode()).hexdigest(),
        'partial_stderr_sha256': hashlib.sha256(stderr.encode()).hexdigest(),
        'verified': False,
        'evidence_scope': 'PARTIAL_RUNTIME_OUTPUT_ONLY',
    })
    return destination


def summarize_resource_exhaustion(run: Path) -> dict[str, Any]:
    """Count saved execution artifacts, retaining their original ASan output."""
    from vulnerabilityanalysis.runtime import asan_resource_kind

    runtime = run / 'runtime'
    candidates = (list(runtime.rglob('*.json')) if runtime.is_dir() else [])
    candidates += list((run / 'assertions').rglob('fuzzer-runtime.json'))
    resources: list[dict[str, str]] = []
    environment: list[dict[str, str]] = []
    malformed_json: list[dict[str, str]] = []
    for path in sorted(set(candidates)):
        if not path.is_file() or path.is_symlink() or path.name == 'runner_resource_exhaustion.json':
            continue
        raw = path.read_bytes()
        relative = path.relative_to(run).as_posix()
        try:
            row = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            malformed_json.append({'artifact': relative,
                                   'artifact_sha256': hashlib.sha256(raw).hexdigest(),
                                   'error_type': type(exc).__name__})
            continue
        if not isinstance(row, dict):
            continue
        stderr = row.get('stderr')
        sanitizer = row.get('sanitizer')
        if not isinstance(stderr, str):
            continue
        kind = asan_resource_kind(sanitizer if isinstance(sanitizer, str) else None,
                                  stderr)
        triage = row.get('crash_triage')
        category = triage.get('category') if isinstance(triage, dict) else None
        if kind and not row.get('timed_out') and row.get('exit_code') is not None:
            resources.append({'artifact': relative, 'artifact_sha256': digest(path),
                              'raw_log_sha256': hashlib.sha256(stderr.encode()).hexdigest(),
                              'kind': kind, 'category': 'RESOURCE_EXHAUSTION'})
        elif category == 'ENVIRONMENT_ERROR' or row.get('failure_classification') == 'ENVIRONMENT_ERROR':
            environment.append({'artifact': relative, 'artifact_sha256': digest(path),
                                'category': 'ENVIRONMENT_ERROR'})
    report = {'kind': 'RUNTIME_RESOURCE_ACCOUNTING_V1',
              'unit': 'saved_execution_artifact',
              'resource_exhaustion_artifact_count': len(resources),
              'environment_error_artifact_count': len(environment),
              'resource_events': resources, 'environment_events': environment,
              'malformed_json_artifacts': malformed_json}
    write_json(runtime / 'runner_resource_exhaustion.json', report)
    return report


def record_unfuzzed_assertions(run: Path, ledger: Ledger,
                               *, effective_fuzz_seconds: int) -> list[dict]:
    """Make zero-Fuzz selected Assertions explicit without changing results.json."""
    if effective_fuzz_seconds != 0:
        return []
    path = run / 'assertions' / 'results.json'
    rows = json.loads(path.read_text()) if path.is_file() else []
    pending = []
    for row in rows:
        if row.get('status') not in {'HELD_FOR_EXECUTION', 'VIOLATED', 'HELD'}:
            continue
        item_id = row['assertion_id']
        ledger.mark_pending(item_id, 'PENDING_FUZZ_BUDGET')
        pending.append({'assertion_id': item_id, 'status': 'PENDING_FUZZ_BUDGET',
                        'actual_fuzz_seconds': 0})
    write_json(run / 'assertions' / 'runner_fuzz_pending.json', pending)
    return pending


def mark_inconclusive_scan(run: Path, target_repository: Path,
                           reason: str) -> None:
    """Preserve an interrupted selection so continue_phase1 can move onward."""
    path = run / 'scan.json'
    if path.is_file():
        return
    selection = json.loads((run / 'selection.json').read_text())
    candidates = run / 'sp' / 'candidates.json'
    rows = json.loads(candidates.read_text()) if candidates.is_file() else []
    pending = [row['sp_id'] for row in rows]
    write_json(path, {'selected_function': selection['function_name'],
        'selected_function_id': selection['function_id'],
        'target_repository': str(target_repository.resolve()),
        'runner_disposition': 'INCONCLUSIVE_NO_COMPLETE_SCAN',
        'runner_error': reason, 'pending_sp_ids': pending,
        'sp_verification_status': {item: 'PENDING_INTERRUPTED_FUNCTION'
                                   for item in pending}})


async def run_sequence(first_run: Path, provider: Any, ledger: Ledger,
                       target_repository: Path, checkpoint: Path,
                       *, max_functions: int = 24,
                       scan_options: dict[str, Any] | None = None,
                       prior_corpus: Path | None = None,
                       followup_fuzzer: Path | None = None,
                       consumer_budget: dict[str, float] | None = None) -> list[dict]:
    """Drive the existing Phase 1 selector and scan without reading Oracle/rank."""
    if getattr(provider, 'ledger', None) is not ledger:
        raise ValueError('provider must account all turns in this ledger')
    if max_functions < 1 or max_functions > 24:
        raise ValueError('K may not exceed 24')
    options = dict(scan_options or {})
    if followup_fuzzer is not None and consumer_budget is None:
        raise ValueError('formal followup crash consumer budget is not preregistered')
    forbidden = {'sp_llm_call_limit', 'hp_llm_call_limit',
                 'evaluation_fuzz_limit_seconds', 'fuzz_budget_seconds',
                 'targeted_fuzzer_binary', 'targeted_fuzz_seconds',
                 'global_fuzz_enabled', 'global_fuzz_seconds', 'max_candidates',
                 'candidate_budget_policy'}
    if forbidden & options.keys():
        raise ValueError('runner owns all fixed budget and Fuzzing controls')
    run = first_run.resolve()
    rows: list[dict] = []
    meter = SharedFuzzMeter(ledger, checkpoint, prior_corpus=prior_corpus)
    consumer_budget_state = {'spent_seconds': 0.0}
    for index in range(max_functions):
        ledger.wall()
        remaining_wall = ledger.started_at + 86400 - time.time()
        if remaining_wall <= 0:
            raise TimeoutError('blind wall limit reached before function')
        scan_deadline = time.monotonic() + remaining_wall
        selection = json.loads((run / 'selection.json').read_text())
        function_id = selection['function_id']
        ledger.select(function_id)
        ledger.bind_run(function_id, run)
        ledger.checkpoint(checkpoint)
        provider.begin_function(function_id)
        fuzz_records_before = len(meter.records)
        status = 'COMPLETE'
        error = None
        fatal: BaseException | None = None
        try:
            with meter.patch_guided():
                await scan_mod.scan_selected(run, provider,
                    target_repository=target_repository,
                    max_candidates=2, sp_llm_call_limit=4, hp_llm_call_limit=4,
                    evaluation_fuzz_limit_seconds=7200,
                    fuzz_budget_seconds=max(0, int(7200 - ledger.fuzz_budget_used())),
                    assertion_fuzz_seconds=600,
                    targeted_fuzzer_binary=None, targeted_fuzz_seconds=0,
                    global_fuzz_enabled=False, global_fuzz_seconds=0,
                    scan_deadline_monotonic=scan_deadline,
                    **options)
            if getattr(provider, 'forbidden_tool_event', False):
                raise ModelToolEventError('FORBIDDEN_MODEL_TOOL_EVENT: model tool event was suppressed')
            if getattr(provider, 'provider_safety_refused', False):
                raise ProviderSafetyRefusedError(
                    'PROVIDER_SAFETY_REFUSED: provider blocked a model turn')
            if getattr(provider, 'audit_log_failed', False):
                raise ModelAuditError('MODEL_AUDIT_WRITE_FAILED: provider audit incomplete')
            scan = json.loads((run / 'scan.json').read_text())
            if run.resolve() in meter.zero_budget_assertion_runs:
                record_unfuzzed_assertions(run, ledger,
                                           effective_fuzz_seconds=0)
            counts = ledger.counts[function_id]
            observed_sp = sum(counts.get(role, 0) for role in
                              ('sp_generation', 'sp_verifier', 'poc_generator'))
            observed_hp = counts.get('function_analysis', 0) + counts.get('assertion_generator', 0)
            ledger.validate_scan(function_id, scan)
            if scan.get('hp_error') is not None:
                status = 'INCOMPLETE_HP_ERROR'
                error = 'HP analysis incomplete; details retained in scan.json hp_error'
                ledger.mark_pending(function_id, error)
            if followup_fuzzer is not None:
                with meter.patch_guided():
                    followup_receipts = run_failed_pov_followups(run, followup_fuzzer, meter,
                        replay_command=options.get('run_command'))
                consumer_rows = consume_reproduced_sp_followups(
                    run, followup_receipts,
                    binary=options['target_binary'],
                    target_repository=target_repository,
                    harness_path=options['official_qualification'].harness,
                    command=options['run_command'],
                    official_qualification=options['official_qualification'],
                    ledger=ledger, checkpoint=checkpoint,
                    budget_checkpoint=checkpoint.parent / 'CRASH_CONSUMER_BUDGET.json',
                    budget=consumer_budget, budget_state=consumer_budget_state)
                if any(row.get('budget_status') == 'CONSUMER_WALL_OVERRUN'
                       for row in consumer_rows):
                    ledger.mark_pending(f'SP_CONSUMER_FUNCTION:{function_id}:OVERRUN',
                                        'INCOMPLETE_CONSUMER_WALL_OVERRUN')
                    if status == 'COMPLETE':
                        status = 'INCOMPLETE_CONSUMER_WALL_OVERRUN'
                        error = 'SP followup consumer exceeded preregistered wall budget'
                    else:
                        error = ((error + '; ') if error else '') + (
                            'SP followup consumer exceeded preregistered wall budget')
                if any(row.get('status') == 'PENDING_CONSUMER_WALL_LIMIT'
                       for row in consumer_rows):
                    ledger.mark_pending(f'SP_CONSUMER_FUNCTION:{function_id}:LIMIT',
                                        'INCOMPLETE_CONSUMER_WALL_LIMIT')
                    if status == 'COMPLETE':
                        status = 'INCOMPLETE_CONSUMER_WALL_LIMIT'
                    error = ((error + '; ') if error else '') + (
                        'SP followup consumer had no remaining wall opportunity')
        except BaseException as exc:
            settlement_failed = getattr(meter, 'settlement_failed', False) is True
            fatal = (exc if settlement_failed or isinstance(exc, (ValueError, TimeoutError,
                                             asyncio.CancelledError,
                                             RuntimeCleanupError,
                                             PhysicalFuzzStop,
                                             PhysicalFuzzBudgetPending,
                                             FatalProviderSafetyRefusal,
                                             FatalModelAuditFailure,
                                             ProviderSafetyRefusedError)) or
                     isinstance(exc, ModelToolEventError) or
                     isinstance(exc, AppServerError) and 'internal retry' in str(exc)
                     else None)
            # Keep a recognized primary stop reason in both the function and
            # top-level receipts. An ordinary error becomes a fatal accounting
            # stop when its Fuzzing settlement also failed.
            interruption = classify_scan_interruption(exc)
            if settlement_failed and interruption == 'INCONCLUSIVE':
                interruption = 'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE'
            status = (interruption if interruption in ({'INCOMPLETE_TIMEOUT',
                                                     'INCOMPLETE_TOOL_EVENT',
                                                     'PROVIDER_SAFETY_REFUSED',
                                                     'INCOMPLETE_AUDIT_ERROR',
                                                     'INCOMPLETE_CANCELLED'} |
                                                    PHYSICAL_FUZZ_TERMINAL_STATUSES) else
                      'STOPPED_FAIL_CLOSED' if fatal else 'INCONCLUSIVE')
            error = f'{type(exc).__name__}: {exc}'
            ledger.mark_pending(function_id, error)
            if fatal is None:
                mark_inconclusive_scan(run, target_repository, error)
        finally:
            try:
                provider.end_function()
                write_json(run / 'runtime' / 'runner_fuzz_jobs.json',
                           meter.records[fuzz_records_before:])
                if isinstance(fatal, RuntimeCleanupError):
                    record_runtime_cleanup_evidence(run, function_id, fatal)
                ledger.checkpoint(checkpoint)
                checkpoint_file = checkpoint_run(run, status, ledger)
                resource_report = summarize_resource_exhaustion(run)
                rows.append({'index': index, 'function_id': function_id,
                             'run': str(run), 'status': status, 'error': error,
                             'resource_exhaustion_artifact_count':
                                 resource_report['resource_exhaustion_artifact_count'],
                             'environment_error_artifact_count':
                                 resource_report['environment_error_artifact_count'],
                             'checkpoint': str(checkpoint_file)})
            except BaseException:
                if fatal is None:
                    raise
        if fatal is not None:
            raise fatal
        if index + 1 >= max_functions:
            break
        try:
            ledger.wall()
            run = continue_phase1(run)
        except ValueError as exc:
            if 'pool exhausted' in str(exc):
                break
            raise
    return rows


def _sync_sp_followup_crash_summary(run: Path, observed_id: str,
                                    reproduced: bool = False) -> None:
    """Keep Fuzzer observation distinct from original replay and VERIFIED."""
    scan_mod._sync_scan_crash_index(run)
    summary_path = run / 'scan.json'
    if not summary_path.is_file():
        return
    summary = json.loads(summary_path.read_text())
    summary['sp_followup_observed_crash_ids'] = sorted(
        set(summary.get('sp_followup_observed_crash_ids', [])) | {observed_id})
    if reproduced:
        summary['sp_followup_reproduced_crash_ids'] = sorted(
            set(summary.get('sp_followup_reproduced_crash_ids', [])) | {observed_id})
    summary['sp_followup_verification_scope'] = (
        'ORIGINAL_BINARY_SANITIZER_ONLY; ROOT_CAUSE_AND_INDEPENDENT_VALIDATION_PENDING')
    write_json(summary_path, summary)


def run_failed_pov_followups(run: Path, binary: Path, meter: SharedFuzzMeter,
                             fuzzer_call: Any = None,
                             replay_command: list[str] | None = None) -> list[dict]:
    """Only cleanly completed, crash-free PoVs seed a separate SP Fuzz pass."""
    from vulnerabilityanalysis.analysis import RetryLedger
    from vulnerabilityanalysis.models import SuspiciousPoint
    call = fuzzer_call or scan_mod.run_targeted_fuzz
    candidate_path = run / 'sp' / 'candidates.json'
    points = ({row['sp_id']: SuspiciousPoint(**row)
               for row in json.loads(candidate_path.read_text())}
              if candidate_path.is_file() else {})
    receipts = []
    seen_sp: set[str] = set()
    for poc in crash_free_pov_rows(run):
        if poc['sp_id'] in seen_sp:
            receipts.append({'sp_id': poc['sp_id'], 'poc_id': poc['poc_id'],
                             'status': 'SKIPPED_CANDIDATE_ALREADY_FUZZED'})
            continue
        point = points.get(poc['sp_id'])
        if point is None:
            receipts.append({'sp_id': poc['sp_id'], 'status': 'BLOCKED_MISSING_SP'})
            continue
        handoff = ensure_clean_pov_seed(run, poc, meter.prior_corpus)
        if handoff['status'] != 'BOUND_CLEAN_POV':
            receipts.append({'sp_id': point.sp_id, 'poc_id': poc['poc_id'], **handoff})
            continue
        # A rejected PoV has not consumed the one Fuzzing opportunity for this SP.
        seen_sp.add(poc['sp_id'])
        item_id = f"SP_FOLLOWUP:{poc['poc_id']}"
        candidate_corpus = run / 'corpus' / 'candidate' / point.sp_id
        prior_crashes = {path.name: digest(path) for path in candidate_corpus.glob('crash-*')
                         if path.is_file() and not path.is_symlink()}
        before = len(meter.records)
        evidence = meter.invoke(item_id, 'FAILED_POV_SEED', 300, call,
            point, binary, run, RetryLedger(max_attempts=1), [])
        record = dict(meter.records[-1]) if len(meter.records) > before else {}
        result_status = (str(evidence.get('status') or 'UNKNOWN_RESULT')
                         if isinstance(evidence, dict) else
                         'RAN' if evidence is not None else 'BLOCKED')
        record.update(sp_id=point.sp_id, poc_id=poc['poc_id'],
                      seed_handoff=handoff,
                      corpus_provenance='MIXED_SEEDS',
                      model_pov_contribution='UNDETERMINED',
                      status=(record['status'] if
                              str(record.get('status', '')).startswith('PENDING_') else
                              'FUZZ_RETURNED' if result_status == 'RAN' else
                              f'FUZZ_{result_status}'))
        new_crashes = [path for path in sorted(candidate_corpus.glob('crash-*'))
            if path.is_file() and not path.is_symlink() and
            prior_crashes.get(path.name) != digest(path)]
        record['new_fuzzer_crash_count'] = len(new_crashes)
        if new_crashes:
            record['termination_reason'] = 'FUZZER_CRASH'
        elif str(record.get('status', '')).startswith('PENDING_'):
            record['termination_reason'] = record['status']
        elif result_status != 'RAN':
            record['termination_reason'] = result_status
        elif record.get('termination_reason') != 'PRE_FUZZ_BLOCKED':
            record['termination_reason'] = (
                'EARLY_RETURN_NO_CRASH' if record.get('actual', 0) < 299
                else 'TIME_BUDGET_NO_CRASH')
        if len(meter.records) > before:
            meter.records[-1]['termination_reason'] = record['termination_reason']
        record['original_replays'] = []
        from dataclasses import asdict
        from vulnerabilityanalysis.runtime import RuntimeExecutor
        binary_hash = digest(binary) if new_crashes and binary.is_file() else None
        for index, input_path in enumerate(new_crashes):
            size = input_path.stat().st_size
            crash_hash = digest(input_path)
            replay_row = {'sha256': crash_hash, 'size': size,
                          'source': 'SP_FOLLOWUP_FUZZER'}
            trusted = (input_path.resolve().is_relative_to(run.resolve()) and
                       binary_hash is not None)
            if not trusted:
                replay_row['status'] = 'BLOCKED_CRASH_INPUT_UNTRUSTED'
            else:
                crash_id = scan_mod.stable_id('sp-fuzzer-input', binary_hash, crash_hash)
                replay_row['observed_crash_id'] = crash_id
                observation_path = (run / 'runtime' /
                    f'{crash_id}.followup_observed.json')
                replay_row['status'] = 'OBSERVED_PENDING_REPLAY'
                write_json(observation_path, replay_row)
                crash_input = {
                    'sha256': crash_hash, 'size': size, 'poc_id': poc['poc_id'],
                    'candidate_path': str(input_path.resolve())}
                central_path = scan_mod._record_fuzzer_crash(
                    run, crash_id, 'SP_FOLLOWUP_FUZZER', observation_path,
                    point.sp_id, crash_input)
                _sync_sp_followup_crash_summary(run, crash_id)
                if size > 8 * 1024 * 1024:
                    replay_row['status'] = 'PENDING_INPUT_SIZE_LIMIT'
                    meter.ledger.mark_pending(crash_id, 'PENDING_ORIGINAL_REPLAY_SIZE_LIMIT')
                elif replay_command is None:
                    replay_row['status'] = 'PENDING_REPLAY_COMMAND'
                    meter.ledger.mark_pending(crash_id, 'PENDING_ORIGINAL_REPLAY')
                elif index >= 16:
                    replay_row['status'] = 'PENDING_REPLAY_LIMIT'
                    meter.ledger.mark_pending(crash_id, 'PENDING_ORIGINAL_REPLAY')
                else:
                    meter.ledger.wall()
                    remaining = meter.ledger.started_at + 86400 - time.time()
                    observed = RuntimeExecutor(timeout_seconds=min(10, remaining)).run(
                        replay_command, input_path)
                    replay = run / 'runtime' / f'{crash_id}.original_replay.json'
                    write_json(replay, asdict(observed))
                    replay_row.update(status='REPLAYED', artifact=str(replay),
                                      artifact_sha256=digest(replay),
                                      input_path=str(input_path.resolve()),
                                      command=list(replay_command),
                                      binary_sha256=digest(Path(replay_command[0])),
                                      exit_code=observed.exit_code,
                                      sanitizer=observed.sanitizer,
                                      timed_out=observed.timed_out,
                                      reproduction_scope='ORIGINAL_BINARY_SANITIZER_ONLY')
                write_json(observation_path, replay_row)
                central = json.loads(central_path.read_text())
                central.setdefault('runner_original_replays', {})[crash_hash] = replay_row
                reproduced = (replay_row['status'] == 'REPLAYED' and
                              bool(observed.sanitizer) and
                              not observed.timed_out and
                              observed.exit_code not in (None, 0))
                if reproduced:
                    # The original binary reproduced a sanitizer failure; no
                    # source-level causal relation or security verdict follows
                    # from that observation alone.
                    central['status'] = 'REPRODUCED_ORIGINAL_BINARY_PENDING_ROOT_CAUSE'
                    central['verification_scope'] = 'ORIGINAL_BINARY_SANITIZER_ONLY'
                    tasks_path = run / 'runtime' / 'reanalysis_requests.json'
                    tasks = (json.loads(tasks_path.read_text())
                             if tasks_path.is_file() else [])
                    if not any(row.get('crash_id') == crash_id and
                               row.get('action') == 'REANALYZE_FUZZ_CRASH'
                               for row in tasks):
                        tasks.append({
                            'crash_id': crash_id, 'sp_id': point.sp_id,
                            'crash_artifact': str(central_path),
                            'runtime_artifact': str(replay),
                            'action': 'REANALYZE_FUZZ_CRASH',
                            'status': 'PENDING_SOURCE_CAUSAL_EVIDENCE',
                            'reason': 'original-binary sanitizer replay does not establish the model SP relation',
                        })
                        write_json(tasks_path, tasks)
                elif replay_row['status'] == 'REPLAYED':
                    central['status'] = ('ORIGINAL_REPLAY_TIMEOUT' if observed.timed_out
                                         else 'ORIGINAL_REPLAY_NOT_REPRODUCED')
                    central['verification_scope'] = 'ORIGINAL_BINARY_ONLY'
                write_json(central_path, central)
                _sync_sp_followup_crash_summary(
                    run, crash_id, reproduced=reproduced)
            record['original_replays'].append(replay_row)
        receipts.append(record)
    report_path = run / 'runtime' / 'runner_sp_followup_fuzz.json'
    write_json(report_path, receipts)
    return receipts


def require_formal_crash_consumer_budget(contract: dict) -> dict[str, float]:
    """Require new, explicitly preregistered consumer wall limits.

    These limits are admission and postcharge limits. The process supervisor
    supplies the hard 24-hour wall stop; the product bounds each subprocess.
    """
    value = contract.get('sp_followup_crash_consumer_wall')
    if not isinstance(value, dict) or set(value) != {
            'per_item_wall_seconds', 'combined_wall_seconds'}:
        raise ValueError('formal crash consumer wall budget missing from contract')
    if any(type(value[key]) not in (int, float) or
           not math.isfinite(value[key]) or not 0 < value[key] <= 86400
           for key in value):
        raise ValueError('formal crash consumer wall budget is invalid')
    if value['per_item_wall_seconds'] > value['combined_wall_seconds']:
        raise ValueError('formal crash consumer item budget exceeds combined budget')
    return {key: float(number) for key, number in value.items()}


def validate_formal_crash_consumer_authority(*, binary: Path,
        target_repository: Path, harness_path: Path, command: list[str],
        official_qualification: OfficialPinnedQualification) -> None:
    """Keep the in-memory product token and every original replay pin bound."""
    q = official_qualification
    try:
        pinned = (isinstance(q, OfficialPinnedQualification) and q.product_issued and
                  binary.resolve() == q.binary and digest(binary) == q.binary_sha256 and
                  harness_path.resolve() == q.harness and
                  digest(harness_path) == q.harness_sha256 and
                  target_repository.resolve() == q.source_root and
                  command == [str(binary), '{input}'] and _qualification_pins_ok(q))
    except (OSError, TypeError, ValueError):
        pinned = False
    if not pinned:
        raise ValueError('formal crash consumer official source/Harness/binary pin changed')


def _formal_crash_input_status(run: Path, central: dict, input_sha: str,
                               size: int) -> str | None:
    """Classify inputs that the product consumer must not receive."""
    observations = central.get('observations', [])
    if not isinstance(observations, list):
        return 'BLOCKED_CONSUMER_INPUT_AMBIGUOUS'
    rows = [row.get('crash_input') for row in observations
            if isinstance(row, dict) and isinstance(row.get('crash_input'), dict)
            and row['crash_input'].get('sha256') == input_sha]
    raw_paths = [row.get('candidate_path') for row in rows]
    if not raw_paths or not all(isinstance(path, str) for path in raw_paths):
        return 'BLOCKED_CONSUMER_INPUT_AMBIGUOUS'
    paths = set(raw_paths)
    if len(paths) != 1:
        return 'BLOCKED_CONSUMER_INPUT_AMBIGUOUS'
    candidate = Path(next(iter(paths)))
    corpus = run / 'corpus'
    try:
        relative = candidate.relative_to(corpus)
    except ValueError:
        return 'BLOCKED_CONSUMER_INPUT_UNTRUSTED'
    if (not relative.parts or not candidate.is_file() or
            any((corpus.joinpath(*relative.parts[:index])).is_symlink()
                for index in range(len(relative.parts) + 1)) or
            not candidate.resolve().is_relative_to(corpus.resolve())):
        return 'BLOCKED_CONSUMER_INPUT_UNTRUSTED'
    if size > MAX_RETAINED_INPUT_BYTES or candidate.stat().st_size > MAX_RETAINED_INPUT_BYTES:
        return 'BLOCKED_CONSUMER_INPUT_SIZE_UNSUPPORTED'
    if (candidate.stat().st_size != size or
            any(row.get('size') != size for row in rows) or
            digest(candidate) != input_sha):
        return 'BLOCKED_CONSUMER_INPUT_CHANGED'
    return None


def consume_reproduced_sp_followups(run: Path, receipts: list[dict], *,
        binary: Path, target_repository: Path, harness_path: Path,
        command: list[str], official_qualification: OfficialPinnedQualification,
        ledger: Ledger, checkpoint: Path, budget_checkpoint: Path,
        budget: dict[str, float], budget_state: dict | None = None,
        consumer: Any = None) -> list[dict]:
    """Send reproduced SP Fuzzer inputs to the existing qualified product Gate.

    Every Runtime child is bounded by the product. Whole-consumer per-item
    limits are admission/postcharge, not an interrupting deadline. A formal
    outer supervisor retains the hard global wall limit.
    """
    if (run.is_symlink() or (run / 'runtime').is_symlink() or
            (run / 'runtime' / 'fuzzer_crashes').is_symlink()):
        raise ValueError('formal crash consumer run has linked evidence directory')
    checked = require_formal_crash_consumer_budget(
        {'sp_followup_crash_consumer_wall': budget})
    validate_formal_crash_consumer_authority(
        binary=binary, target_repository=target_repository,
        harness_path=harness_path, command=command,
        official_qualification=official_qualification)
    state = budget_state if budget_state is not None else {'spent_seconds': 0.0}
    spent = state.get('spent_seconds')
    if type(spent) not in (int, float) or not math.isfinite(spent) or spent < 0:
        raise ValueError('formal consumer wall checkpoint is invalid')
    state.setdefault('had_overrun', False)
    if type(state['had_overrun']) is not bool:
        raise ValueError('formal consumer wall overrun flag is invalid')
    call = consumer or consume_fuzzer_crash_observation
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    report_path = run / 'runtime' / 'runner_sp_followup_consumer.json'

    def checkpoint_state(status: str, observation_id: str | None = None) -> None:
        write_json(report_path, rows)
        if rows and observation_id:
            latest = rows[-1]
            central_path = run / 'runtime' / 'fuzzer_crashes' / f'{observation_id}.json'
            if central_path.is_file() and not central_path.is_symlink():
                central = json.loads(central_path.read_text())
                if isinstance(central, dict) and central.get('crash_id') == observation_id:
                    handoff = central.setdefault('runner_consumer_handoff', {})
                    if not isinstance(handoff, dict):
                        raise ValueError('formal crash handoff index malformed')
                    handoff[
                        latest['input_sha256']] = {
                            'status': latest['status'],
                            'gate_status': latest.get('gate_status'),
                            'consumer_wall_seconds': latest.get('consumer_wall_seconds'),
                            'authority_changed_after_consumer': latest.get(
                                'authority_changed_after_consumer', False),
                            'discarded_consumer_status': latest.get(
                                'discarded_consumer_status')}
                    write_json(central_path, central)
            scan_path = run / 'scan.json'
            if scan_path.is_file():
                scan = json.loads(scan_path.read_text())
                if isinstance(scan, dict):
                    scan['sp_followup_consumer_handoff'] = [{
                        'observation_id': row['observation_id'],
                        'input_sha256': row['input_sha256'],
                        'status': row['status'],
                        'gate_status': row.get('gate_status')}
                        for row in rows]
                    if any(row.get('authority_changed_after_consumer') for row in rows):
                        scan['sp_followup_consumer_authority_invalidated'] = True
                    write_json(scan_path, scan)
        write_json(budget_checkpoint, {
            'spent_seconds': state['spent_seconds'],
            'had_overrun': state['had_overrun'],
            'per_item_wall_seconds': checked['per_item_wall_seconds'],
            'combined_wall_seconds': checked['combined_wall_seconds'],
            'last_observation_id': observation_id, 'last_status': status,
            'enforcement': 'ADMISSION_POSTCHARGE_WITH_SUPERVISOR_HARD_WALL',
        })
        ledger.checkpoint(checkpoint)

    checkpoint_state('READY')
    for receipt in receipts:
        for replay in receipt.get('original_replays', []):
            observation_id = replay.get('observed_crash_id')
            input_sha = replay.get('sha256')
            if not isinstance(observation_id, str) or not isinstance(input_sha, str):
                continue  # No trusted indexed observation was created.
            row = {'observation_id': observation_id, 'input_sha256': input_sha,
                   'source': 'SP_FOLLOWUP_FUZZER', 'status': 'PENDING_ORIGINAL_REPLAY'}
            rows.append(row)
            key = (observation_id, input_sha)
            if key in seen:
                row['status'] = 'SKIPPED_DUPLICATE_CONSUMER_REQUEST'
                checkpoint_state(row['status'], observation_id)
                continue
            seen.add(key)
            central_path = run / 'runtime' / 'fuzzer_crashes' / f'{observation_id}.json'
            if (not re.fullmatch(r'[A-Za-z0-9_-]+', observation_id) or
                    not re.fullmatch(r'[0-9a-f]{64}', input_sha) or
                    central_path.is_symlink() or not central_path.is_file()):
                row['status'] = 'BLOCKED_CONSUMER_OBSERVATION_IDENTITY'
                checkpoint_state(row['status'], observation_id)
                continue
            central = json.loads(central_path.read_text())
            if not isinstance(central, dict) or central.get('crash_id') != observation_id:
                row['status'] = 'BLOCKED_CONSUMER_OBSERVATION_IDENTITY'
                checkpoint_state(row['status'], observation_id)
                continue
            if replay.get('status') == 'REPLAYED' and not replay.get('sanitizer') and not replay.get('timed_out'):
                row['status'] = 'BLOCKED_ORIGINAL_REPLAY_NOT_REPRODUCED'
                checkpoint_state(row['status'], observation_id)
                continue
            if (replay.get('status') != 'REPLAYED' or not replay.get('sanitizer') or
                    replay.get('timed_out') or
                    central.get('status') != 'REPRODUCED_ORIGINAL_BINARY_PENDING_ROOT_CAUSE'):
                checkpoint_state(row['status'], observation_id)
                continue
            size = replay.get('size')
            if type(size) is not int or size < 0:
                row['status'] = 'BLOCKED_CONSUMER_INPUT_CHANGED'
            else:
                row['status'] = _formal_crash_input_status(run, central, input_sha, size) or row['status']
            if row['status'].startswith('BLOCKED_'):
                checkpoint_state(row['status'], observation_id)
                continue
            replay_artifact = run / 'runtime' / f'{observation_id}.original_replay.json'
            try:
                actual_replay = (json.loads(replay_artifact.read_text())
                                 if replay.get('artifact') == str(replay_artifact) and
                                 replay_artifact.is_file() and
                                 not replay_artifact.is_symlink() else {})
            except (OSError, ValueError, TypeError):
                actual_replay = {}
            central_replay = central.get('runner_original_replays', {})
            matching_paths = {item.get('crash_input', {}).get('candidate_path')
                for item in central.get('observations', []) if isinstance(item, dict)
                and isinstance(item.get('crash_input'), dict)
                and item['crash_input'].get('sha256') == input_sha}
            if (actual_replay.get('sanitizer') != replay.get('sanitizer') or
                    actual_replay.get('timed_out') is not False or
                    type(actual_replay.get('exit_code')) is not int or
                    actual_replay['exit_code'] == 0 or
                    replay.get('exit_code') != actual_replay['exit_code'] or
                    replay.get('artifact_sha256') != digest(replay_artifact) or
                    replay.get('command') != command or
                    replay.get('binary_sha256') != official_qualification.binary_sha256 or
                    not isinstance(central_replay, dict) or
                    central_replay.get(input_sha) != replay or
                    len(matching_paths) != 1 or
                    not all(isinstance(path, str) for path in matching_paths) or
                    replay.get('input_path') != str(Path(next(iter(matching_paths))).resolve())):
                row['status'] = 'BLOCKED_ORIGINAL_REPLAY_ARTIFACT'
                checkpoint_state(row['status'], observation_id)
                continue
            try:
                validate_formal_crash_consumer_authority(
                    binary=binary, target_repository=target_repository,
                    harness_path=harness_path, command=command,
                    official_qualification=official_qualification)
            except ValueError:
                row['status'] = 'STOPPED_CONSUMER_AUTHORITY_CHANGED'
                checkpoint_state(row['status'], observation_id)
                raise
            remaining = min(checked['combined_wall_seconds'] - state['spent_seconds'],
                            ledger.started_at + 86400 - time.time())
            if remaining <= 0:
                row['status'] = 'PENDING_CONSUMER_WALL_LIMIT'
                ledger.mark_pending(f'SP_CONSUMER:{observation_id}', row['status'])
                checkpoint_state(row['status'], observation_id)
                continue
            timeout = min(10.0, checked['per_item_wall_seconds'], remaining)
            row['status'] = 'CONSUMER_ACTIVE'
            row['requested_runtime_timeout_seconds'] = timeout
            checkpoint_state(row['status'], observation_id)
            started = time.monotonic()
            original_error: BaseException | None = None
            try:
                result = call(run, observation_id, input_sha,
                    binary=binary, expected_binary_sha256=official_qualification.binary_sha256,
                    command=command, target_repository=target_repository,
                    harness_path=harness_path, timeout_seconds=timeout,
                    official_qualification=official_qualification)
                if not isinstance(result, dict) or not isinstance(result.get('status'), str):
                    raise ValueError('formal Fuzzer consumer returned no status')
                row['status'] = result['status']
                row['gate_status'] = result.get('gate_status')
                row['consumer_result'] = result
            except BaseException as exc:
                original_error = exc
                row['status'] = (
                    'STOPPED_CLEANUP_INCOMPLETE' if isinstance(exc, RuntimeCleanupError) else
                    'INCOMPLETE_CONSUMER_TIMEOUT' if isinstance(exc, TimeoutError) else
                    'INCOMPLETE_CANCELLED' if isinstance(exc, asyncio.CancelledError) else
                    'STOPPED_CONSUMER_ERROR')
                row['error_type'] = type(exc).__name__
            finally:
                try:
                    validate_formal_crash_consumer_authority(
                        binary=binary, target_repository=target_repository,
                        harness_path=harness_path, command=command,
                        official_qualification=official_qualification)
                except ValueError as pin_error:
                    row['authority_changed_after_consumer'] = True
                    discarded = row.pop('consumer_result', None)
                    if isinstance(discarded, dict):
                        row['discarded_consumer_status'] = discarded.get('status')
                    row.pop('gate_status', None)
                    if original_error is None:
                        original_error = pin_error
                        row['status'] = 'STOPPED_CONSUMER_AUTHORITY_CHANGED'
                elapsed = max(0.0, time.monotonic() - started)
                state['spent_seconds'] += elapsed
                row['consumer_wall_seconds'] = elapsed
                row['item_wall_overrun_seconds'] = max(
                    0.0, elapsed - checked['per_item_wall_seconds'])
                row['combined_wall_overrun_seconds'] = max(
                    0.0, state['spent_seconds'] - checked['combined_wall_seconds'])
                if (row['item_wall_overrun_seconds'] > 0 or
                        row['combined_wall_overrun_seconds'] > 0):
                    row['budget_status'] = 'CONSUMER_WALL_OVERRUN'
                    state['had_overrun'] = True
                    ledger.mark_pending(f'SP_CONSUMER:{observation_id}',
                                        'INCOMPLETE_CONSUMER_WALL_OVERRUN')
                try:
                    checkpoint_state(row['status'], observation_id)
                except BaseException:
                    if original_error is None:
                        raise
            if original_error is not None:
                raise original_error
    checkpoint_state('COMPLETE_WITH_CONSUMER_WALL_OVERRUN' if state['had_overrun']
        else 'COMPLETE')
    return rows


def check_zero_retry_config(path: Path, model: str, effort: str) -> None:
    codex_config = tomllib.loads(path.read_text())
    provider_name = codex_config.get('model_provider')
    providers = codex_config.get('model_providers')
    provider = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
    # A model-side extension can be declared in config even when thread/start
    # sends dynamicTools=[]. Accept only the measured minimal provider file.
    features = codex_config.get('features')
    if (set(codex_config) != {'model', 'model_provider', 'model_reasoning_effort',
                             'model_providers', 'features'} or
            not isinstance(features, dict) or set(features) != {'apps'} or
            features['apps'] is not False or
            not isinstance(providers, dict) or
            set(providers) != {provider_name} or
            not isinstance(provider, dict) or
            set(provider) != {'name', 'wire_api', 'requires_openai_auth',
                              'supports_websockets', 'request_max_retries',
                              'stream_max_retries'} or
            provider.get('wire_api') != 'responses' or
            provider.get('requires_openai_auth') is not True or
            provider.get('supports_websockets') is not False or
            provider.get('request_max_retries') != 0 or
            provider.get('stream_max_retries') != 0 or
            codex_config.get('model') != model or
            codex_config.get('model_reasoning_effort') != effort):
        raise ValueError('zero-retry Provider configuration changed')


def verify_pinned_codex_executable(contract: dict) -> Path:
    """Require the CLI found on PATH to match the frozen canonical path and bytes."""
    raw_path = contract.get('codex_executable_path')
    expected_sha = contract.get('codex_executable_sha256')
    if (not isinstance(raw_path, str) or not raw_path or
            not isinstance(expected_sha, str) or
            not re.fullmatch(r'[0-9a-f]{64}', expected_sha)):
        raise ValueError('Codex executable path and SHA-256 must be frozen')
    pinned = Path(raw_path)
    discovered = shutil.which('codex')
    if (not pinned.is_absolute() or not discovered or pinned.is_symlink() or
            not pinned.is_file() or not os.access(pinned, os.X_OK)):
        raise ValueError('pinned Codex executable unavailable')
    if (pinned.resolve(strict=True) != pinned or
            Path(discovered).resolve(strict=True) != pinned or
            digest(pinned) != expected_sha):
        raise ValueError('Codex executable identity changed')
    return pinned


def verify_pinned_asan_symbolizer(contract: dict) -> Path:
    """Bind ASan stack symbolization to the reviewed local LLVM binary."""
    checks = (
        ('asan_symbolizer_path', 'asan_symbolizer_sha256'),
        ('asan_symbolizer_libllvm_path', 'asan_symbolizer_libllvm_sha256'),
    )
    resolved = []
    for path_key, sha_key in checks:
        raw_path, expected_sha = contract.get(path_key), contract.get(sha_key)
        if (not isinstance(raw_path, str) or not isinstance(expected_sha, str)
                or not re.fullmatch(r'[0-9a-f]{64}', expected_sha)):
            raise ValueError('ASan symbolizer path or digest missing')
        path = Path(raw_path)
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or path.resolve(strict=True) != path or digest(path) != expected_sha):
            raise ValueError('ASan symbolizer file identity changed')
        resolved.append(path)
    symbolizer = resolved[0]
    alias_value = contract.get('asan_symbolizer_libllvm_alias')
    alias = Path(alias_value) if isinstance(alias_value, str) else Path()
    if (not alias.is_absolute() or not alias.is_symlink() or
            alias.resolve(strict=True) != resolved[1]):
        raise ValueError('ASan symbolizer libLLVM loader alias changed')
    if not os.access(symbolizer, os.X_OK):
        raise ValueError('ASan symbolizer is not executable')
    for name in ('ASAN_SYMBOLIZER_PATH', 'LLVM_SYMBOLIZER_PATH'):
        prior = os.environ.get(name)
        if prior not in (None, '', str(symbolizer)):
            raise ValueError(f'{name} conflicts with frozen symbolizer')
        os.environ[name] = str(symbolizer)
    return symbolizer


def enforce_asan_environment() -> str:
    """Apply exact preregistered ASan setting or refuse a conflicting environment."""
    existing = os.environ.get('ASAN_OPTIONS', '')
    if existing not in ('', 'detect_leaks=0'):
        raise ValueError('ASAN_OPTIONS differs from detect_leaks=0')
    os.environ['ASAN_OPTIONS'] = 'detect_leaks=0'
    return os.environ['ASAN_OPTIONS']


def verify_gdb_runtime_available() -> None:
    """Reject a blind run before selection if GDB cannot trace this host."""
    try:
        result = subprocess.run(
            ['gdb', '-nx', '--batch', '-q', '-ex', 'set pagination off',
             '-ex', 'set debuginfod enabled off',
             '-ex', 'set startup-with-shell off', '-ex', 'run',
             '--args', '/bin/true'],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('GDB ptrace unavailable') from exc
    output = result.stdout + '\n' + result.stderr
    if result.returncode != 0 or 'exited normally' not in output or re.search(
            r'ptrace:|Could not trace the inferior process', output, re.I):
        raise ValueError('GDB ptrace unavailable')


def preflight_live(contract_path: Path) -> dict:
    contract = json.loads(contract_path.read_text())
    if contract.get('status') != 'FROZEN_READY':
        raise ValueError('contract is not frozen and ready')
    if contract.get('harness_trust') != 'QUALIFIED_TRUSTED_EVIDENCE':
        raise ValueError('official Harness trust remains unresolved')
    if not contract.get('route_sha256') or not contract.get('role_models'):
        raise ValueError('provider route/model list not pinned')
    if any(set(settings) != {'model', 'reasoning'} or
           not settings['model'] or not settings['reasoning']
           for settings in contract['role_models'].values()):
        raise ValueError('role model schema must use model and reasoning')
    if (not isinstance(contract.get('normal_seeds'), list) or
            not 1 <= len(contract['normal_seeds']) <= 128 or
            len(set(contract['normal_seeds'])) != len(contract['normal_seeds']) or
            contract.get('assertion_seed') not in contract['normal_seeds']):
        raise ValueError('Assertion Seed must be one of the registered normal Seeds')
    required = {'sp_generation', 'sp_verifier', 'poc_generator',
                'function_analysis', 'assertion_generator'}
    if set(contract['role_models']) != required:
        raise ValueError('role model set changed')
    product_config = yaml.safe_load((PRODUCT / 'config/default.yaml').read_text())
    if (product_config['llm']['provider'] != 'codex' or
            any(contract['role_models'][role] != product_config['models'][role]
                for role in required)):
        raise ValueError('product Provider or role mapping changed')
    config_path = (HERE.parent / contract['codex_config']).resolve()
    if not config_path.is_relative_to(HERE.parent) or not config_path.is_file():
        raise ValueError('private zero-retry provider config unavailable')
    check_zero_retry_config(config_path, contract['default_model'],
                            contract['default_effort'])
    verify_pinned_codex_executable(contract)
    verify_pinned_asan_symbolizer(contract)
    verify_frozen_surface(contract, HERE.parent, PRODUCT.parent)
    check_contract(contract, {'reference': HERE.parent.parent,
                              'product': PRODUCT.parent})
    require_formal_crash_consumer_budget(contract)
    qualified = require_official_qualification(contract)
    verify_gdb_runtime_available()
    counts = rehearse_selection_inputs(contract, official_qualification=qualified)
    print('READ_ONLY_PRESELECTION_REHEARSAL ' + json.dumps(counts, sort_keys=True),
          flush=True)
    return contract


def require_official_qualification(contract: dict):
    """Reject a trust label unless the product issues a same-process token."""
    path_value = contract.get('official_harness_contract')
    pinned = contract.get('official_harness_contract_sha256')
    harness_value = contract.get('official_harness_path')
    artifact_value = contract.get('artifact')
    artifact_path = Path(artifact_value) if isinstance(artifact_value, str) else Path()
    harness_path = Path(harness_value) if isinstance(harness_value, str) else Path()
    if (path_value != 'public/OFFICIAL_HARNESS_CONTRACT.json' or
            not isinstance(pinned, str) or
            not re.fullmatch(r'[0-9a-f]{64}', pinned) or
            not isinstance(artifact_value, str) or not artifact_value or
            artifact_path.is_absolute() or '..' in artifact_path.parts or
            artifact_path.name != 'attempt' or
            not isinstance(harness_value, str) or not harness_value or
            harness_path.is_absolute() or '..' in harness_path.parts or
            harness_path.parent != artifact_path or
            harness_path.suffix not in {'.c', '.cc', '.cpp', '.cxx'}):
        raise ValueError('official Harness review contract is not pinned')
    official_contract = resolve_reference_file(path_value)
    try:
        official_kind = json.loads(official_contract.read_text()).get('kind')
    except (OSError, ValueError, AttributeError) as exc:
        raise ValueError('official Harness contract is unreadable') from exc
    harness = resolve_reference_file(harness_value)
    source = (HERE.parent / contract['target_repository']).resolve()
    binary = resolve_reference_file(contract['asan_binary'])
    normal_seed = resolve_reference_file(contract['assertion_seed'])
    extra = {}
    if official_kind == 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2':
        extra = {
            'oss_fuzz_checkout': resolve_reference_directory(
                contract.get('oss_fuzz_checkout'), HERE.parent),
            'upstream_checkout': resolve_reference_directory(
                contract.get('upstream_checkout'), HERE.parent),
        }
    elif official_kind != 'OFFICIAL_OSS_FUZZ_HARNESS_V1':
        raise ValueError('unsupported official Harness contract kind')
    qualified = issue_official_pinned_qualification(
        contract_path=official_contract,
        approved_contract_sha256=pinned,
        source_root=source,
        harness=harness,
        binary=binary,
        normal_seed=normal_seed, **extra)
    if qualified is None or not qualified.product_issued:
        raise ValueError('official Harness live qualification is not issued')
    return qualified


def prepare_private_codex_state(config_path: Path) -> Path:
    """Select pinned zero-retry config with existing ChatGPT auth, no API key."""
    auth = Path.home() / '.codex' / 'auth.json'
    if not auth.is_file():
        raise ValueError('ChatGPT authentication unavailable')
    state = Path(tempfile.mkdtemp(prefix='codex-blind-zero-retry-'))
    state.chmod(0o700)
    # The model app-server runs with the ordinary home tree hidden. Keep only
    # these pinned credentials/configuration inside its private mounted state.
    try:
        for source, name in ((auth, 'auth.json'), (config_path.resolve(), 'config.toml')):
            destination = state / name
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output_stream, source.open('rb') as input_stream:
                shutil.copyfileobj(input_stream, output_stream)
    except BaseException:
        shutil.rmtree(state, ignore_errors=True)
        raise
    os.environ['CODEX_HOME'] = str(state)
    return state


@contextmanager
def private_codex_state(config_path: Path):
    previous = os.environ.get('CODEX_HOME')
    state = prepare_private_codex_state(config_path)
    try:
        yield state
    finally:
        if previous is None:
            os.environ.pop('CODEX_HOME', None)
        else:
            os.environ['CODEX_HOME'] = previous
        shutil.rmtree(state, ignore_errors=True)


def _protected_model_paths(contract: dict) -> tuple[Path, ...]:
    """Select real host paths whose absence the sandbox must demonstrate."""
    reference = HERE.parent.resolve(strict=True)
    product = PRODUCT.resolve(strict=True)
    target_name = contract.get('target_repository')
    if not isinstance(target_name, str) or not target_name:
        raise ValueError('target Source is unavailable for model isolation test')
    target = (reference / target_name).resolve(strict=True)
    git_metadata = (target / '.git').resolve(strict=True)
    evaluator = (reference.parent / 'blind2_candidate_20261027' / 'evaluator_only').resolve(strict=True)
    if (not target.is_relative_to(reference) or not target.is_dir() or
            not git_metadata.is_dir() or not evaluator.is_dir()):
        raise ValueError('protected model paths are unavailable')
    return reference, product, target, git_metadata, evaluator


def verify_model_namespace_sandbox(executable: Path,
                                   protected_paths: tuple[Path, ...]) -> dict[str, bool]:
    """Require a separate, empty model filesystem before any live turn."""
    launcher = HERE / 'blind2_model_sandbox.py'
    if (not launcher.is_file() or launcher.is_symlink() or
            not executable.is_file()):
        raise ValueError('model filesystem isolation launcher unavailable')
    if (len(protected_paths) < 5 or len(set(protected_paths)) != len(protected_paths) or
            any(not path.is_absolute() or not path.exists() for path in protected_paths)):
        raise ValueError('protected model path set is incomplete')
    try:
        result = subprocess.run(
            [sys.executable, str(launcher), '--self-test', str(executable),
             *(part for path in protected_paths for part in ('--deny-path', str(path)))],
            capture_output=True, text=True, check=False, timeout=20)
        evidence = json.loads(result.stdout.strip())
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
        raise ValueError('model filesystem isolation self-test failed') from exc
    required = {'cwd_is_empty_work', 'host_home_hidden', 'host_mnt_hidden',
                'model_state_copied', 'private_proc', 'capabilities_dropped',
                'contract_paths_hidden'}
    checks = evidence.get('checks') if isinstance(evidence, dict) else None
    if (result.returncode != 0 or evidence.get('status') != 'PASS' or
            evidence.get('deny_path_count') != len(protected_paths) or
            not isinstance(checks, dict) or set(checks) != required or
            any(checks[name] is not True for name in required)):
        raise ValueError('model filesystem isolation self-test failed')
    return checks


def verify_parent_route(contract: dict) -> None:
    """Check the pinned live route before consuming one-use approval."""
    source = (HERE.parent / contract['target_repository']).resolve()
    config = (HERE.parent / contract['codex_config']).resolve()
    if (not source.is_relative_to(HERE.parent) or
            not config.is_relative_to(HERE.parent)):
        raise ValueError('Provider preflight path outside approved root')
    with private_codex_state(config), \
         tempfile.TemporaryDirectory(prefix='va-blind2-model-cwd-') as temporary:
        pinned_executable = verify_pinned_codex_executable(contract)
        verify_model_namespace_sandbox(pinned_executable, _protected_model_paths(contract))
        model_cwd = Path(temporary)
        model_cwd.chmod(0o700)

        async def probe() -> None:
            client = CodexAppServerClient(cwd=model_cwd, wire_cwd='/work',
                launch_prefix=[sys.executable, str(HERE / 'blind2_model_sandbox.py')],
                executable=str(pinned_executable),
                executable_sha256=contract['codex_executable_sha256'],
                model=contract['default_model'], effort=contract['default_effort'],
                timeout_seconds=30)
            async with client:
                await check_live_route(client, contract['route_sha256'],
                                       contract['role_models'])

        asyncio.run(probe())


def _kill_process_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


_LIBC = ctypes.CDLL(None, use_errno=True)
_PR_SET_PDEATHSIG = 1


def _set_parent_death_signal(expected_parent: int, signum: int) -> None:
    """Run in a forked child before exec; reject a parent-death setup race."""
    if (_LIBC.prctl(_PR_SET_PDEATHSIG, signum, 0, 0, 0) != 0 or
            os.getppid() != expected_parent):
        os._exit(126)


_PROCESS_GROUP_GUARD = '''
import ctypes, os, signal, subprocess, sys, time
expected_parent = int(sys.argv[1])
status_fd = int(sys.argv[2])
guard_pid = os.getpid()
libc = ctypes.CDLL(None, use_errno=True)
class ParentStopped(BaseException):
    pass
def parent_stopped(_signum, _frame):
    raise ParentStopped()
signal.signal(signal.SIGTERM, parent_stopped)
def adopted_children():
    with open(f'/proc/{guard_pid}/task/{guard_pid}/children') as stream:
        return [int(row) for row in stream.read().split()]
def reap_exited():
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
def stop_descendants():
    deadline = time.monotonic() + 5
    while True:
        reap_exited()
        children = adopted_children()
        if not children:
            return True
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(.01)
def child_guard():
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != guard_pid:
        os._exit(126)
code = 126
try:
    if os.getppid() != expected_parent:
        raise ParentStopped()
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError('Linux subreaper unavailable')
    adopted_children()  # Fail closed before command launch if procfs is absent.
    child = subprocess.Popen(sys.argv[3:], close_fds=True, preexec_fn=child_guard)
    code = child.wait()
except ParentStopped:
    code = 126
except Exception as exc:
    print(f'process guard failed: {type(exc).__name__}: {exc}', file=sys.stderr)
    code = 126
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        cleaned = stop_descendants()
    except Exception as exc:
        print(f'process tree cleanup failed: {type(exc).__name__}: {exc}', file=sys.stderr)
        cleaned = False
    payload = str(code) + '\\n' if cleaned else 'CLEANUP_INCOMPLETE\\n'
    try:
        os.write(status_fd, payload.encode('ascii'))
    except OSError:
        pass  # The supervisor may already have exited.
    os.close(status_fd)
    os.killpg(os.getpgrp(), signal.SIGKILL)
'''


def _guarded_command(command: list[str], status_fd: int) -> tuple[list[str], int]:
    """A parent-death guarded group leader owns every child in the PGID."""
    if not command:
        raise ValueError('supervised command is empty')
    parent_pid = os.getpid()
    return ([sys.executable, '-I', '-c', _PROCESS_GROUP_GUARD,
             str(parent_pid), str(status_fd), *command], parent_pid)


def _launch_guarded(command: list[str], **popen_kwargs: Any) -> tuple[subprocess.Popen, int]:
    status_read, status_write = os.pipe()
    try:
        guarded, parent_pid = _guarded_command(command, status_write)
        child = subprocess.Popen(guarded, start_new_session=True,
            pass_fds=(status_write,), preexec_fn=lambda: _set_parent_death_signal(
                parent_pid, signal.SIGTERM), **popen_kwargs)
        return child, status_read
    except BaseException:
        os.close(status_read)
        raise
    finally:
        os.close(status_write)


def _guarded_return_code(child: subprocess.Popen, status_read: int) -> int:
    payload = os.read(status_read, 64)
    if payload == b'CLEANUP_INCOMPLETE\n':
        return -32768
    if re.fullmatch(rb'-?\d+\n', payload):
        return int(payload)
    return child.returncode if child.returncode not in (None, 0) else 1


def _request_guard_cleanup(child: subprocess.Popen, status_read: int) -> bool:
    """Allow the subreaper to kill setsid descendants before hard fallback."""
    try:
        os.kill(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=7)  # The guard's descendant cleanup has a 5s cap.
    except subprocess.TimeoutExpired:
        _kill_process_group(child.pid)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return False
        return False
    payload = os.read(status_read, 64)
    return bool(re.fullmatch(rb'-?\d+\n', payload))


def _bounded_preapproval_process(command: list[str], *, timeout_seconds: float = 90) -> None:
    """Run the route probe under a separate physical wall cap before approval use."""
    if not 0 < timeout_seconds <= 120:
        raise ValueError('route preflight wall limit is invalid')
    child, status_read = _launch_guarded(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        try:
            child.wait(timeout=timeout_seconds)
            return_code = _guarded_return_code(child, status_read)
        except subprocess.TimeoutExpired as exc:
            if not _request_guard_cleanup(child, status_read):
                raise TimeoutError('route preflight cleanup deadline exceeded') from exc
            raise TimeoutError('route preflight physical wall deadline exceeded') from exc
        if return_code == -32768:
            raise ValueError('route preflight process tree cleanup incomplete')
        if return_code != 0:
            raise ValueError('route preflight failed before approval consumption')
    finally:
        # A completed leader can leave App Server descendants in its process group.
        _kill_process_group(child.pid)
        os.close(status_read)
        if child.poll() is None:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError('route preflight cleanup deadline exceeded') from exc


def supervise_preapproval_route(contract_path: Path, *, timeout_seconds: float = 90) -> None:
    """The route process runs the same early Freeze checks as the main runner."""
    _bounded_preapproval_process([
        sys.executable, '-I', str(Path(__file__).resolve()), '--execute',
        '--route-probe', '--contract', str(contract_path.resolve(strict=True)),
    ], timeout_seconds=timeout_seconds)


def _terminal_selection_fields(output: Path, *, max_functions: int = 24) -> dict:
    """Bind an early stop to completed checkpoints and unselected K slots."""
    checkpoints = sorted(path for path in output.rglob('FUNCTION_CHECKPOINT.json')
                         if path.is_file() and not path.is_symlink())
    rows = []
    for path in checkpoints:
        row = {'path': str(path.relative_to(output)), 'sha256': None,
               'status': 'INCOMPLETE_CHECKPOINT_UNREADABLE'}
        try:
            row['sha256'] = digest(path)
        except OSError as exc:
            row['checkpoint_hash_error'] = f'{type(exc).__name__}: {exc}'
        try:
            record = json.loads(path.read_text())
            if not isinstance(record, dict):
                raise ValueError('function checkpoint must be a JSON object')
            row['status'] = record.get('status')
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            row['checkpoint_read_error'] = f'{type(exc).__name__}: {exc}'
        rows.append(row)
    budget = output / 'BUDGET_CHECKPOINT.json'
    result = {
        'function_checkpoints': rows,
        'processed_function_count': len(rows),
        'remaining_selection_slots': max(0, max_functions - len(rows)),
        'remaining_selection_status': 'NO_OPPORTUNITY',
        'checkpoint_overflow_count': max(0, len(rows) - max_functions),
        'budget_checkpoint_sha256': None,
    }
    if budget.is_file():
        result['budget_checkpoint_path'] = str(budget.relative_to(output))
        try:
            result['budget_checkpoint_sha256'] = digest(budget)
        except OSError as exc:
            result['budget_checkpoint_hash_error'] = f'{type(exc).__name__}: {exc}'
        try:
            json.loads(budget.read_text())
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            result['budget_checkpoint_read_error'] = f'{type(exc).__name__}: {exc}'
    return result


def _load_child_result_or_preserve(output: Path) -> tuple[dict | None, dict]:
    """Keep a partial child result intact before the supervisor writes its stop."""
    recorded = output / 'RUNNER_RESULT.json'
    if not recorded.is_file():
        return None, {}
    try:
        row = json.loads(recorded.read_text())
        if not isinstance(row, dict):
            raise ValueError('child result must be a JSON object')
        return row, {}
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        partial = output / f'RUNNER_RESULT.partial.{time.time_ns()}.json'
        recorded.rename(partial)
        return None, {
            'child_result_partial_path': str(partial.relative_to(output)),
            'child_result_partial_sha256': digest(partial),
            'child_result_read_error': f'{type(exc).__name__}: {exc}',
        }


def _preserve_valid_child_result(output: Path, row: dict) -> dict:
    """Keep a complete child record when supervisor status must replace it."""
    recorded = output / 'RUNNER_RESULT.json'
    prior = output / f'RUNNER_RESULT.child.{time.time_ns()}.json'
    recorded.rename(prior)
    return {
        'child_result_prior_path': str(prior.relative_to(output)),
        'child_result_prior_sha256': digest(prior),
        'child_result_prior_status': row.get('status'),
    }


def supervise_child(command: list[str], output: Path, *,
                    timeout_seconds: float = 86400) -> str:
    """Enforce the wall cap outside the process that may block in a build/Fuzzer."""
    if not 0 < timeout_seconds <= 86400:
        raise ValueError('supervisor wall limit must be within 24 hours')
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path = output.parent / f'{output.name}.supervisor.log'
    started_at = time.time()
    with log_path.open('wb') as log:
        child, status_read = _launch_guarded(
            command, stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, 'BLIND_RUN_STARTED_AT': str(started_at)})
        try:
            child.wait(timeout=timeout_seconds)
            return_code = _guarded_return_code(child, status_read)
        except subprocess.TimeoutExpired:
            # SIGTERM asks the guard to reap adopted setsid() descendants.
            # A direct SIGKILL of the PGID would leave those children alive.
            cleanup_incomplete = not _request_guard_cleanup(child, status_read)
            stop_status = ('STOPPED_CLEANUP_INCOMPLETE' if cleanup_incomplete else
                           'STOPPED_WALL_LIMIT')
            os.close(status_read)
            output.mkdir(parents=True, exist_ok=True)
            checkpoint = output / 'BUDGET_CHECKPOINT.json'
            budget_read_error = None
            if checkpoint.is_file():
                try:
                    ledger = Ledger.restore(checkpoint)
                    item = ledger.functions[-1] if ledger.functions else 'UNSTARTED_SELECTION'
                    ledger.mark_pending(item, stop_status)
                    ledger.checkpoint(checkpoint)
                except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
                    budget_read_error = f'{type(exc).__name__}: {exc}'
            child_row, child_result_evidence = _load_child_result_or_preserve(output)
            if child_row is not None:
                child_result_evidence.update(_preserve_valid_child_result(output, child_row))
            selection_evidence = _terminal_selection_fields(output)
            if budget_read_error is not None:
                selection_evidence['budget_checkpoint_read_error'] = budget_read_error
            write_json(output / 'RUNNER_RESULT.json', {
                'status': stop_status, 'original_stop_reason': 'STOPPED_WALL_LIMIT',
                'supervisor_started_at': started_at,
                'wall_seconds': timeout_seconds, 'checkpoint': str(checkpoint)
                if checkpoint.is_file() else None,
                'cleanup_incomplete': cleanup_incomplete,
                'model_turns_stopped': True,
                **selection_evidence, **child_result_evidence})
            return stop_status
        os.close(status_read)
        # Reap descendants even if the leader exited normally or with an error.
        _kill_process_group(child.pid)
    if return_code != 0:
        output.mkdir(parents=True, exist_ok=True)
        recorded = output / 'RUNNER_RESULT.json'
        row, child_result_evidence = _load_child_result_or_preserve(output)
        if row is not None:
            if row.get('cleanup_incomplete') is True:
                child_result_evidence.update(_preserve_valid_child_result(output, row))
                row['original_stop_reason'] = row.get('status', 'CHILD_ERROR')
                row['status'] = 'STOPPED_CLEANUP_INCOMPLETE'
                row['exit_code'] = return_code
                row['model_turns_stopped'] = True
                row.update(_terminal_selection_fields(output))
                row.update(child_result_evidence)
                write_json(recorded, row)
                return 'STOPPED_CLEANUP_INCOMPLETE'
            if (return_code != -32768 and
                    row.get('status') in {'INCOMPLETE_TOOL_EVENT', 'PROVIDER_SAFETY_REFUSED',
                                          'INCOMPLETE_AUDIT_ERROR',
                                          'INCOMPLETE_CANCELLED',
                                          'INCOMPLETE_TIMEOUT',
                                          'STOPPED_CLEANUP_INCOMPLETE'} |
                                         PHYSICAL_FUZZ_TERMINAL_STATUSES):
                return row['status']
        checkpoint = output / 'BUDGET_CHECKPOINT.json'
        selection_evidence = _terminal_selection_fields(output)
        state = {}
        if checkpoint.is_file():
            try:
                state = json.loads(checkpoint.read_text())
                if not isinstance(state, dict):
                    raise ValueError('budget checkpoint must be a JSON object')
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                state = {}
                selection_evidence['budget_checkpoint_read_error'] = (
                    f'{type(exc).__name__}: {exc}')
        function_checkpoints = sorted(
            output.rglob('FUNCTION_CHECKPOINT.json'),
            key=lambda path: (path.stat().st_mtime_ns, str(path)))
        cleanup_incomplete = return_code == -32768
        if row is not None:
            child_result_evidence.update(_preserve_valid_child_result(output, row))
        result = {
            'status': ('STOPPED_CLEANUP_INCOMPLETE' if cleanup_incomplete else
                       'CHILD_ERROR'),
            'original_stop_reason': 'CHILD_ERROR', 'exit_code': return_code,
            'cleanup_incomplete': cleanup_incomplete,
            'supervisor_log': str(log_path),
            'checkpoint': str(checkpoint) if checkpoint.is_file() else None,
            'last_function_checkpoint': (str(function_checkpoints[-1])
                                         if function_checkpoints else None),
            'processed_function_count': len(function_checkpoints),
            'pending_count': len(state.get('pending', []))}
        result.update(selection_evidence)
        result['model_turns_stopped'] = True
        result.update(child_result_evidence)
        write_json(output / 'RUNNER_RESULT.json', result)
        return 'STOPPED_CLEANUP_INCOMPLETE' if cleanup_incomplete else 'CHILD_ERROR'
    recorded = output / 'RUNNER_RESULT.json'
    row, child_result_evidence = _load_child_result_or_preserve(output)
    if row is None and not child_result_evidence:
        output.mkdir(parents=True, exist_ok=True)
        write_json(recorded, {
            'status': 'CHILD_ERROR',
            'original_stop_reason': 'CHILD_RESULT_MISSING',
            'cleanup_incomplete': False,
            'model_turns_stopped': True,
            **_terminal_selection_fields(output)})
        return 'CHILD_ERROR'
    if row is None:
        write_json(recorded, {
            'status': 'CHILD_ERROR',
            'original_stop_reason': 'CHILD_RESULT_UNREADABLE',
            'cleanup_incomplete': False,
            'model_turns_stopped': True,
            **_terminal_selection_fields(output), **child_result_evidence})
        return 'CHILD_ERROR'
    if (row.get('cleanup_incomplete') is True or
            row.get('status') == 'STOPPED_CLEANUP_INCOMPLETE'):
        child_result_evidence.update(_preserve_valid_child_result(output, row))
        row['original_stop_reason'] = row.get('status', 'COMPLETE_OR_INCONCLUSIVE')
        row['status'] = 'STOPPED_CLEANUP_INCOMPLETE'
        row['cleanup_incomplete'] = True
        row['model_turns_stopped'] = True
        row.update(_terminal_selection_fields(output))
        row.update(child_result_evidence)
        write_json(recorded, row)
        return 'STOPPED_CLEANUP_INCOMPLETE'
    if row.get('status') in {'INCOMPLETE_TOOL_EVENT', 'PROVIDER_SAFETY_REFUSED',
                             'INCOMPLETE_AUDIT_ERROR',
                             'INCOMPLETE_CANCELLED',
                             'INCOMPLETE_TIMEOUT'} | PHYSICAL_FUZZ_TERMINAL_STATUSES:
        return row['status']
    return 'COMPLETE_OR_INCONCLUSIVE'


def _record_terminal_stop(output: Path, status: str, *, max_functions: int = 24) -> None:
    """Preserve the stop reason and hash completed function checkpoints."""
    output.mkdir(parents=True, exist_ok=True)
    write_exclusive_json(output / 'RUNNER_RESULT.json', {
        'status': status,
        'model_turns_stopped': True,
        **_terminal_selection_fields(output, max_functions=max_functions),
    })


def record_tool_event_stop(output: Path, *, max_functions: int = 24) -> None:
    _record_terminal_stop(output, 'INCOMPLETE_TOOL_EVENT', max_functions=max_functions)


def record_provider_safety_stop(output: Path, *, max_functions: int = 24) -> None:
    _record_terminal_stop(output, 'PROVIDER_SAFETY_REFUSED', max_functions=max_functions)


def record_model_audit_stop(output: Path, *, max_functions: int = 24) -> None:
    _record_terminal_stop(output, 'INCOMPLETE_AUDIT_ERROR', max_functions=max_functions)


def record_cancelled_stop(output: Path, *, max_functions: int = 24) -> None:
    _record_terminal_stop(output, 'INCOMPLETE_CANCELLED', max_functions=max_functions)


def record_timeout_stop(output: Path, *, max_functions: int = 24) -> None:
    _record_terminal_stop(output, 'INCOMPLETE_TIMEOUT', max_functions=max_functions)


def record_cleanup_incomplete_stop(output: Path, *, max_functions: int = 24) -> None:
    _record_terminal_stop(output, 'STOPPED_CLEANUP_INCOMPLETE', max_functions=max_functions)


def record_physical_fuzz_stop(output: Path, status: str,
                              *, max_functions: int = 24) -> None:
    if status not in PHYSICAL_FUZZ_TERMINAL_STATUSES:
        raise ValueError('unknown physical Fuzzing stop status')
    _record_terminal_stop(output, status, max_functions=max_functions)


def write_exclusive_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def claim_child_launch(launch: Path, contract: Path, runner: Path,
                       output: Path) -> None:
    """Bind the already-consumed approval to exactly one child and output."""
    row = json.loads(launch.read_text())
    if (row.get('contract_sha256') != digest(contract) or
            row.get('runner_sha256') != digest(runner)):
        raise ValueError('child launch contract or runner changed')
    if row.get('output') != str(output.resolve()):
        raise ValueError('child launch output changed')
    started = output.with_name(output.name + '.CHILD_STARTED.json')
    write_exclusive_json(started, row)


def approval_record_paths(contract: Path) -> tuple[Path, Path, Path]:
    """Keep each frozen contract's one-use receipts without erasing old runs."""
    vault = HERE.parent / 'approval_runs'
    slot = vault / digest(contract)
    if (vault.is_symlink() or slot.is_symlink() or
            vault.exists() and not vault.is_dir() or
            slot.exists() and not slot.is_dir() or
            not slot.resolve().is_relative_to(HERE.parent.resolve())):
        raise ValueError('approval record directory is unsafe')
    return (slot / 'APPROVAL.json', slot / 'APPROVAL_CONSUMED.json',
            slot / 'LAUNCH.json')


def resolve_reference_file(value: str, reference_root: Path = HERE.parent) -> Path:
    root = reference_root.resolve()
    path = Path(value)
    resolved = (path if path.is_absolute() else root / path).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError('execution file outside reference root')
    if not resolved.is_file():
        raise ValueError('execution file unavailable')
    return resolved


def resolve_reference_directory(value: str, reference_root: Path = HERE.parent) -> Path:
    root = reference_root.resolve()
    if not isinstance(value, str) or not value:
        raise ValueError('official repository checkout path missing')
    path = Path(value)
    resolved = (path if path.is_absolute() else root / path).resolve()
    if (not resolved.is_relative_to(root) or not resolved.is_dir() or
            (path if path.is_absolute() else root / path).is_symlink()):
        raise ValueError('official repository checkout outside approved root')
    return resolved


def rehearse_function_sources(harness: Any) -> dict[str, int]:
    """Follow Phase 1 until source lookup, without scoring or selecting."""
    workers = workflow_mod.build_workers(harness)
    directions = [direction for worker in workers
                  for direction in workflow_mod.build_directions(harness, worker)]
    pool = workflow_mod.build_pool(harness, directions)
    if not workers or not directions or not pool:
        raise ValueError('preselection Worker, Direction, or Pool is empty')
    sources = workflow_mod.source_evidence_for_pool(harness, pool)
    function_ids = {item.function_id for item in pool}
    missing_ids = function_ids - sources.keys()
    repo = SourceRepository(Path(harness.target_repository), harness.function_catalog)
    for function_id in function_ids:
        try:
            repo.source_path(function_id)
        except (KeyError, OSError, ValueError):
            missing_ids.add(function_id)
    # Embedded source text can hide a broken header path in open_function.
    # Check every compiled Clang supplement, including headers outside the Pool.
    supplemented_headers = 0
    for key, row in harness.function_catalog.items():
        if ('clang-ast-compiled-nm' not in (row.get('providers') or []) or
                not str(row.get('file') or row.get('file_path') or '').endswith('.h')):
            continue
        supplemented_headers += 1
        ref = str(row.get('function_id') or key)
        try:
            repo.source_path(ref)
        except (KeyError, OSError, ValueError):
            missing_ids.add(ref)
    missing = len(missing_ids)
    counts = {'worker_count': len(workers),
              'direction_count': len(directions),
              'pool_size': len(pool),
              'source_lookup_failure_count': missing,
              'supplemented_header_checked_count': supplemented_headers}
    if missing:
        raise ValueError(f'preselection source lookup failures: {missing}')
    return counts


def require_catalog_build_integrity(contract: dict, harness: Any,
                                    source_root: Path) -> dict:
    """Block selection until role-specific build provenance is pinned and consistent."""
    root = HERE.parent.resolve()
    run_root_value = harness.metadata.get('run_root')
    receipt_value = contract.get('catalog_build_receipt')
    receipt_sha = contract.get('catalog_build_receipt_sha256')
    if (not isinstance(run_root_value, str) or not run_root_value or
            not isinstance(receipt_value, str) or
            not isinstance(receipt_sha, str) or
            not re.fullmatch(r'[0-9a-f]{64}', receipt_sha)):
        raise ValueError('frozen Catalog build provenance is unavailable')
    run_root = Path(run_root_value).resolve()
    if not run_root.is_relative_to(root):
        raise ValueError('Catalog root outside approved reference root')
    receipt = resolve_reference_file(receipt_value, root)
    result = audit_catalog_build(run_root / 'analysis/functions.jsonl',
                                 run_root / 'analysis/edges.jsonl', source_root,
                                 receipt, receipt_sha, evaluator_root=root)
    if result['status'] != 'ATTESTED_RECEIPT_CONSISTENT':
        raise ValueError('Catalog build provenance blocked: ' +
                         ', '.join(result.get('reasons') or []))
    # The receipt pins a source-side reference file, while Scheduler reads
    # its Artifact copy. Bind the actual consumer input before selection.
    receipt_data = json.loads(receipt.read_text(encoding='utf-8'))
    if receipt_data.get('schema') != 'EVALUATOR_CATALOG_BUILD_RECEIPT_V2':
        raise ValueError('Blind 2 requires a V2 Catalog receipt')
    expected = (receipt_data.get('indirect_edges') or {}).get('sha256')
    sidecar = run_root / 'analysis/indirect_edges.jsonl'
    if (not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected)
            or sidecar.is_symlink() or not sidecar.is_file()
            or not sidecar.resolve().is_relative_to(run_root)
            or digest(sidecar) != expected):
        raise ValueError('Catalog indirect edge Artifact binding blocked')
    # The Catalog must describe the same role binaries the evaluator will
    # execute. A valid receipt for a different build cannot qualify this run.
    for role, field in (('asan', 'asan_binary'), ('coverage', 'coverage_fuzzer')):
        value = contract.get(field)
        expected_binary = ((receipt_data.get('roles') or {}).get(role) or {}).get('binary') or {}
        expected_sha = expected_binary.get('sha256')
        if (not isinstance(value, str) or not isinstance(expected_sha, str)
                or not re.fullmatch(r'[0-9a-f]{64}', expected_sha)):
            raise ValueError(f'Catalog {role} binary binding unavailable')
        binary = resolve_reference_file(value, root)
        if digest(binary) != expected_sha:
            raise ValueError(f'Catalog {role} binary hash mismatch')
    return result


def verify_preselection_official_binding(harness: Any, qualification: Any,
                                        source: Path) -> None:
    """Match the loaded Artifact to its issued authority before approval use."""
    if (not getattr(qualification, 'product_issued', False) or
            harness.source_kind != 'official_oss_fuzz' or
            Path(harness.harness_path).resolve() != qualification.harness or
            source.resolve() != qualification.source_root or
            not scan_mod._official_pin_matches_qualification(
                harness.metadata.get('official_pin'), qualification)):
        raise ValueError('preselection official Artifact/qualification mismatch')


def rehearse_selection_inputs(contract: dict, *, official_qualification: Any) -> dict[str, int]:
    """Load every selection input before approval, without scheduling a function."""
    root = HERE.parent.resolve()
    artifact = (root / contract['artifact']).resolve()
    source = (root / contract['target_repository']).resolve()
    if (not artifact.is_relative_to(root) or not artifact.is_dir() or
            not source.is_relative_to(root) or not source.is_dir()):
        raise ValueError('Artifact or Source directory unavailable')
    # This parses the same persisted Artifact that run_phase1 will consume.
    # It does not call build_pool, Scheduler.select, or run_phase1.
    normalized_harness = HarnessAdapter().load(artifact, target_repository=source)
    verify_preselection_official_binding(normalized_harness, official_qualification, source)
    catalog_audit = require_catalog_build_integrity(contract, normalized_harness, source)

    seeds = [resolve_reference_file(value, root)
             for value in contract['normal_seeds']]
    assertion_seed = resolve_reference_file(contract['assertion_seed'], root)
    if not 1 <= len(seeds) <= 128 or len(set(seeds)) != len(seeds) or assertion_seed not in seeds:
        raise ValueError('normal or Assertion Seed set changed')

    binaries = [resolve_reference_file(contract[key], root)
                for key in ('asan_binary', 'coverage_fuzzer')]
    for binary in binaries:
        if not os.access(binary, os.X_OK):
            raise ValueError('pinned target binary is not executable')
        with binary.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise ValueError('pinned target binary is not ELF')

    build_manifest = resolve_reference_file(contract['assertion_build_manifest'], root)
    try:
        build = json.loads(build_manifest.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError('Assertion build Manifest cannot be read') from exc
    harness = resolve_reference_file(contract['official_harness_path'], root)
    if (not isinstance(build, dict) or
            build.get('schema') != 'MULTI_TU_ASSERTION_BUILD_V1' or
            Path(str(build.get('source_root') or '')).resolve() != source or
            Path(str(build.get('harness_source') or '')).resolve() != harness):
        raise ValueError('Assertion build Manifest does not match Source or Harness')

    builder_command = contract['assertion_build_command']
    if (len(builder_command) != 4 or builder_command[1:] !=
            ['{source}', '-o', '{binary}']):
        raise ValueError('Assertion build command changed')
    builder = resolve_reference_file(builder_command[0], root)
    if not os.access(builder, os.X_OK):
        raise ValueError('Assertion builder is not executable')
    config = resolve_reference_file(contract['codex_config'], root)
    check_zero_retry_config(config, contract['default_model'],
                            contract['default_effort'])
    if (contract['run_command'] != [contract['asan_binary'], '{input}'] or
            contract['assertion_run_command'] != ['{binary}', '{input}']):
        raise ValueError('runtime command changed from frozen contract')
    counts = rehearse_function_sources(normalized_harness)
    counts['catalog_build_role_count'] = sum(
        key in catalog_audit['counts'] for key in
        ('asan_active_definitions', 'coverage_active_definitions'))
    return counts


def build_provider_safety_report(backend: CodexAppServerClient) -> dict[str, Any]:
    """Summarize explicit provider metadata without reading model text or Oracle."""
    buffering = backend.safety_buffering_summaries
    summarized = {(str(row['thread_id']), str(row['turn_id'])) for row in buffering}
    summarized_buffered = {(str(row['thread_id']), str(row['turn_id']))
                           for row in buffering if row.get('buffered')}
    observed = backend.safety_notification_observations
    refusals = {(row['thread_id'], row['turn_id'])
                for row in backend.provider_safety_refusal_records}
    censored = set(observed) - summarized
    unclassified_blocks = backend.structured_safety_block_observations - refusals
    return {
        'aggregate_complete': not censored and not unclassified_blocks,
        'status': ('CHILD_COLLECTED' if not censored and not unclassified_blocks
                   else 'CHILD_CENSORED_BEFORE_COLLECT'),
        'safety_event_turn_count': len(set(observed) | summarized),
        'buffered_turn_count': sum(bool(row.get('buffered')) for row in buffering),
        'buffered_turn_count_lower_bound': len(
            {key for key, shown in observed.items() if shown} | summarized_buffered),
        'buffered_incomplete_turn_count': sum(
            bool(row.get('buffered')) and row.get('turn_status') != 'completed'
            for row in buffering),
        'duration_censored_turn_count': len(censored),
        'buffer_to_turn_end_seconds_total': round(sum(
            float(row['buffer_to_turn_end_seconds'] or 0) for row in buffering), 6),
        'buffer_to_stop_seconds_total': round(sum(
            float(row['buffer_to_stop_seconds'] or 0) for row in buffering), 6),
        'provider_safety_refused_count': len(refusals),
        'provider_safety_refused_count_lower_bound': len(
            refusals | backend.structured_safety_block_observations),
        'unclassified_block_observation_count': len(unclassified_blocks),
        'buffered_turns': buffering,
        'provider_safety_refusals': backend.provider_safety_refusal_records,
        'classification_scope': 'explicit structured provider signals only; '
            'free-form text is not inferred as a safety refusal',
    }


def ensure_model_safety_summary(output: Path) -> None:
    """Mark censored telemetry after a hard child stop without reading model text."""
    destination = output / 'MODEL_SAFETY_SUMMARY.json'
    partial_evidence: dict[str, str] = {}
    if destination.is_file():
        try:
            existing = json.loads(destination.read_text())
            if (isinstance(existing, dict) and (
                    existing.get('aggregate_complete') is True and
                    isinstance(existing.get('buffered_turn_count'), int) and
                    isinstance(existing.get('provider_safety_refused_count'), int) or
                    existing.get('status') == 'CHILD_CENSORED_BEFORE_COLLECT' and
                    all(isinstance(existing.get(key), int) for key in (
                        'buffered_turn_count_lower_bound',
                        'provider_safety_refused_count_lower_bound',
                        'duration_censored_turn_count')) or
                    existing.get('status') == 'PARENT_FALLBACK_AFTER_CHILD_STOP' and
                    all(isinstance(existing.get(key), int) for key in (
                        'buffered_turn_count_lower_bound',
                        'provider_safety_refused_count_lower_bound',
                        'duration_censored_turn_count')) or
                    existing.get('status') == 'UNAVAILABLE_NO_EVENT_LOG' and
                    not (output / 'MODEL_EVENT_TYPES.jsonl').is_file())):
                return
            raise ValueError('incomplete safety summary record')
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            previous_sha = digest(destination)
            partial = output / f'MODEL_SAFETY_SUMMARY.partial.{time.time_ns()}.json'
            destination.rename(partial)
            partial_evidence = {
                'prior_partial_summary_sha256': previous_sha,
                'prior_partial_summary_path': str(partial),
                'prior_partial_summary_error_type': type(exc).__name__,
            }
    source = output / 'MODEL_EVENT_TYPES.jsonl'
    if not source.is_file():
        write_json(destination, {'aggregate_complete': False,
                                 'status': 'UNAVAILABLE_NO_EVENT_LOG',
                                 **partial_evidence})
        return
    raw_turns: set[tuple[str, str]] = set()
    buffered_turns: set[tuple[str, str]] = set()
    summarized_turns: set[tuple[str, str]] = set()
    refusals: set[tuple[str, str]] = set()
    raw_structured_blocks: set[tuple[str, str]] = set()
    completed_seconds = 0.0
    stopped_seconds = 0.0
    with source.open('rb') as stream:
        for line in stream:
            if not (line.startswith(b'{"item_type": null, "method": "model/safetyBuffering/updated"') or
                    line.startswith(b'{"item_type": null, "method": "turn/moderationMetadata"') or
                    line.startswith(b'{"item_type": null, "method": "turn/completed"') or
                    line.startswith(b'{"buffer_to_stop_seconds":') or
                    line.startswith(b'{"classification": "PROVIDER_SAFETY_REFUSED"')):
                continue
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            key = (str(row.get('thread_id') or ''), str(row.get('turn_id') or ''))
            if row.get('method') == 'model/safetyBuffering/updated':
                raw_turns.add(key)
                if (row.get('params') or {}).get('showBufferingUi') is True:
                    buffered_turns.add(key)
            elif row.get('method') == 'turn/moderationMetadata':
                params = row.get('params')
                if row.get('structured_safety_block_observed') is True or (
                        isinstance(params, dict) and
                        CodexAppServerClient._explicit_provider_safety_refusal(
                            params, 'turn/moderationMetadata', key[0], key[1])):
                    raw_structured_blocks.add(key)
            elif row.get('method') == 'turn/completed':
                params = row.get('params')
                turn = params.get('turn') if isinstance(params, dict) else None
                error = turn.get('error') if isinstance(turn, dict) else None
                if row.get('structured_safety_refusal_observed') is True or (
                        isinstance(params, dict) and isinstance(turn, dict) and
                        params.get('threadId') == key[0] and turn.get('id') == key[1] and
                        turn.get('status') != 'completed' and
                        isinstance(error, dict) and error.get('codexErrorInfo') in
                            ('cyberPolicy', 'misalignmentPolicyViolation')):
                    raw_structured_blocks.add(key)
            elif row.get('classification') == 'PROVIDER_SAFETY_BUFFERING':
                summarized_turns.add(key)
                if row.get('buffered') is True:
                    buffered_turns.add(key)
                completed_seconds += float(row.get('buffer_to_turn_end_seconds') or 0)
                stopped_seconds += float(row.get('buffer_to_stop_seconds') or 0)
            elif row.get('classification') == 'PROVIDER_SAFETY_REFUSED':
                refusals.add(key)
    write_json(destination, {
        'aggregate_complete': False,
        'status': 'PARENT_FALLBACK_AFTER_CHILD_STOP',
        'safety_event_turn_count_lower_bound': len(raw_turns | summarized_turns),
        'buffered_turn_count_lower_bound': len(buffered_turns),
        'provider_safety_refused_count_lower_bound': len(refusals | raw_structured_blocks),
        'raw_structured_block_turn_count': len(raw_structured_blocks),
        'buffer_to_turn_end_seconds_total_observed': round(completed_seconds, 6),
        'buffer_to_stop_seconds_total_observed': round(stopped_seconds, 6),
        'duration_censored_turn_count': len(raw_turns - summarized_turns),
        'classification_scope': 'metadata only; hard-stop durations can be censored',
        **partial_evidence,
    })


async def execute_live(contract: dict, output: Path) -> list[dict]:
    """Run only after preflight/approval; no evaluator-only path is read here."""
    config = (HERE.parent / contract['codex_config']).resolve()
    with private_codex_state(config), \
         tempfile.TemporaryDirectory(prefix='va-blind2-model-cwd-') as temporary:
        model_cwd = Path(temporary)
        model_cwd.chmod(0o700)
        return await _execute_live_with_cwd(contract, output, model_cwd)


async def _execute_live_with_cwd(contract: dict, output: Path,
                                 model_cwd: Path) -> list[dict]:
    """Hold the empty model cwd for the lifetime of the guarded app-server."""
    artifact = (HERE.parent / contract['artifact']).resolve()
    source = (HERE.parent / contract['target_repository']).resolve()
    if not artifact.is_relative_to(HERE.parent) or not source.is_relative_to(HERE.parent):
        raise ValueError('model-visible target outside approved root')
    consumer_budget = require_formal_crash_consumer_budget(contract)
    official_qualification = require_official_qualification(contract)
    asan_options = enforce_asan_environment()
    build_manifest = (HERE.parent / contract['assertion_build_manifest']).resolve()
    if (not build_manifest.is_relative_to(HERE.parent) or
            not build_manifest.is_file()):
        raise ValueError('pinned Assertion build manifest unavailable')
    os.environ['VA_ASSERTION_BUILD_MANIFEST'] = str(build_manifest)
    pinned_executable = verify_pinned_codex_executable(contract)
    sandbox_checks = verify_model_namespace_sandbox(
        pinned_executable, _protected_model_paths(contract))
    started_at = float(os.environ.get('BLIND_RUN_STARTED_AT', time.time()))
    ledger = Ledger(started_at=started_at,
                    fuzz_overrun_policy=contract.get('fuzz_overrun_policy', 'LOCKOUT_V1'))
    checkpoint = output / 'BUDGET_CHECKPOINT.json'
    # The App Server can emit notifications during start and route inspection.
    # Open the private audit boundary before __aenter__, not after the first
    # model request. A consumed approval still owns this fresh output path.
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    output.chmod(0o700)
    backend = GuardedAppServer(ledger=ledger, checkpoint=checkpoint,
        route_sha256=contract['route_sha256'], role_models=contract['role_models'],
        codex_executable_path=pinned_executable,
        codex_executable_sha256=contract['codex_executable_sha256'],
        cwd=model_cwd, wire_cwd='/work',
        launch_prefix=[sys.executable, str(HERE / 'blind2_model_sandbox.py')],
        executable=str(pinned_executable),
        executable_sha256=contract['codex_executable_sha256'],
        model=contract['default_model'],
        effort=contract['default_effort'], timeout_seconds=600)
    backend.event_log_path = output / 'MODEL_EVENT_TYPES.jsonl'
    async with backend:
        try:
            await backend.verify_route()
        except Exception as exc:
            write_json(output / 'ROUTE_RECHECK_FAILURE.json', {
                'status': 'CHILD_ROUTE_RECHECK_FAILED',
                'error_type': type(exc).__name__,
                'reason': str(exc) if isinstance(exc, ValueError)
                          else 'Provider metadata request failed',
                'model_starts': ledger.physical,
                'selection_started': False,
                'approval_consumed': True})
            raise
        write_json(output / 'EXECUTION_ENVIRONMENT.json', {
            'ASAN_OPTIONS': asan_options,
            'ASAN_SYMBOLIZER_PATH': os.environ['ASAN_SYMBOLIZER_PATH'],
            'asan_symbolizer_sha256': contract['asan_symbolizer_sha256'],
            'asan_symbolizer_libllvm_sha256': contract['asan_symbolizer_libllvm_sha256'],
            'VA_ASSERTION_BUILD_MANIFEST': str(build_manifest),
            'model_cwd_kind': 'PRIVATE_EMPTY_TEMPORARY',
            'model_server_launcher': 'blind2_model_sandbox.py',
            'model_event_audit': 'MODEL_EVENT_TYPES.jsonl',
            'codex_executable_path': str(pinned_executable),
            'codex_executable_sha256': contract['codex_executable_sha256'],
            'model_sandbox_self_test': sandbox_checks})
        normal_seeds = [resolve_reference_file(path) for path in contract['normal_seeds']]
        asan_binary = resolve_reference_file(contract['asan_binary'])
        coverage_fuzzer = resolve_reference_file(contract['coverage_fuzzer'])
        if (contract['run_command'] != [contract['asan_binary'], '{input}'] or
                contract['assertion_run_command'] != ['{binary}', '{input}']):
            raise ValueError('runtime command changed from frozen contract')
        prior_corpus = prepare_prior_corpus(normal_seeds, output / 'normal_corpus')
        first = run_phase1(artifact, output / 'runs', target_repository=source)
        run_error: BaseException | None = None
        try:
            rows = await run_sequence(first, backend, ledger, source, checkpoint,
                max_functions=24, scan_options={
                    'run_command': [str(asan_binary), '{input}'],
                    'runtime_sanitizers': contract['runtime_sanitizers'],
                    'target_binary': asan_binary,
                    'assertion_build_command': contract['assertion_build_command'],
                    'assertion_run_command': contract['assertion_run_command'],
                    'assertion_seed': resolve_reference_file(contract['assertion_seed']),
                    'initial_inputs': normal_seeds,
                    'hallucination_prevent': 'on',
                    'role_models': contract['role_models'],
                    'official_qualification': official_qualification,
                }, prior_corpus=prior_corpus,
                   followup_fuzzer=coverage_fuzzer,
                   consumer_budget=consumer_budget)
        except BaseException as exc:
            run_error = exc
            raise
        finally:
            try:
                write_json(output / 'MODEL_SAFETY_SUMMARY.json',
                           build_provider_safety_report(backend))
            except Exception:
                if run_error is None:
                    raise
    try:
        audit = verify_formal_model_event_order(ledger, backend.event_log_path)
    except Exception as exc:
        write_json(output / 'MODEL_EVENT_AUDIT.json', {
            'status': 'HOLD_EVENT_AUDIT',
            'error_type': type(exc).__name__, 'reason': str(exc),
            'event_log_sha256': (digest(backend.event_log_path)
                                 if backend.event_log_path.is_file() else None)})
        raise FatalModelAuditFailure('HOLD_EVENT_AUDIT: formal model event lineage') from exc
    write_json(output / 'MODEL_EVENT_AUDIT.json', audit)
    write_json(output / 'RUNNER_RESULT.json', {
        'status': 'COMPLETE' if rows and all(row['status'] == 'COMPLETE' for row in rows)
                  else 'INCOMPLETE',
        'functions': rows,
        'ledger': ledger.__dict__})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--route-probe', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--contract', type=Path, required=True)
    arguments = parser.parse_args()
    if not arguments.execute:
        print('Runner draft: no model or Fuzzing execution. Frozen contract required.')
        return
    contract = preflight_live(arguments.contract)
    approval, consumed, launch = approval_record_paths(arguments.contract)
    if arguments.route_probe:
        if arguments.child:
            raise ValueError('route probe cannot consume child launch receipt')
        verify_parent_route(contract)
        return
    if arguments.child:
        receipt = json.loads(consumed.read_text()) if consumed.is_file() else {}
        if (receipt.get('contract_sha256') != digest(arguments.contract) or
                receipt.get('runner_sha256') != digest(Path(__file__)) or
                not arguments.output or
                not arguments.output.resolve().is_relative_to(
                    (HERE.parent / 'runs').resolve())):
            raise ValueError('child lacks matching one-use execution receipt')
        claim_child_launch(launch, arguments.contract,
                           Path(__file__), arguments.output)
        try:
            asyncio.run(execute_live(contract, arguments.output))
        except FatalProviderSafetyRefusal:
            record_provider_safety_stop(arguments.output)
            raise
        except ProviderSafetyRefusedError:
            record_provider_safety_stop(arguments.output)
            raise
        except (FatalModelAuditFailure, ModelAuditError):
            record_model_audit_stop(arguments.output)
            raise
        except ModelToolEventError:
            record_tool_event_stop(arguments.output)
            raise
        except RuntimeCleanupError:
            record_cleanup_incomplete_stop(arguments.output)
            raise
        except (FuzzMeterAccountingError, PhysicalFuzzStop,
                PhysicalFuzzBudgetPending) as exc:
            record_physical_fuzz_stop(arguments.output,
                                      classify_scan_interruption(exc))
            raise
        except asyncio.CancelledError:
            record_cancelled_stop(arguments.output)
            raise
        except TimeoutError:
            record_timeout_stop(arguments.output)
            raise
        except BaseException as exc:
            if getattr(exc, 'fuzz_accounting_failed', False):
                record_physical_fuzz_stop(
                    arguments.output, 'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE')
            raise
        return
    supervise_preapproval_route(arguments.contract)
    consume_approval(approval, consumed, arguments.contract, Path(__file__))
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    output = HERE.parent / 'runs' / stamp
    write_exclusive_json(launch, {
        'contract_sha256': digest(arguments.contract),
        'runner_sha256': digest(Path(__file__)),
        'output': str(output.resolve())})
    try:
        status = supervise_child([sys.executable, '-I', str(Path(__file__).resolve()),
            '--execute', '--child', '--contract', str(arguments.contract.resolve()),
            '--output', str(output)], output)
    finally:
        try:
            ensure_model_safety_summary(output)
        except Exception:
            # The supervisor's original stop reason remains authoritative.
            pass
    if status != 'COMPLETE_OR_INCONCLUSIVE':
        raise RuntimeError(f'blind child stopped: {status}')


if __name__ == '__main__':
    main()
