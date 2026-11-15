"""One-function HP live-development wire boundary; never a Blind 3 approval.

No model is launched by importing this module. The development entrypoint
requires a pinned public toy plus namespace sandbox and route preflight before
the first model turn.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable
from uuid import uuid4

from blind3_hp_iteration_dev import DevHPLedger, DevHPPolicy, _run_sequence_core, legacy
from dev_global_appserver_bridge import (
    DevelopmentGlobalAppServer, request_hash, verify_model_event_order,
)
from vulnerabilityanalysis.llm import (
    AppServerError, CodexAppServerClient, LLMRequest, ModelAuditError,
    ModelToolEventError, ProviderSafetyRefusedError,
)


@dataclass(frozen=True)
class LiveHPPolicy(DevHPPolicy):
    # A public toy actually required 331.915s before refinement. This 3300s
    # development ceiling repeats its earlier preflight envelope, not Blind 3.
    sp_per_function: int = 1
    combined_per_function: int = 6
    logical_max: int = 6
    physical_max: int = 5
    wall_seconds: int = 3300
    fuzz_seconds_combined: int = 10
    assertion_fuzz_job_seconds: int = 2


@dataclass(frozen=True)
class LiveHPContract:
    policy: LiveHPPolicy
    role_models: dict[str, dict[str, str]]
    route_sha256: str
    target_repository: Path
    source_tree_sha256: str
    selected_function_id: str
    phase1_run: Path
    phase1_files_sha256: dict[str, str]
    artifact_path: Path
    artifact_sha256: str
    scan_options_sha256: str
    scan_input_files_sha256: dict[str, str]
    codex_executable: Path
    codex_executable_sha256: str
    sandbox_launcher: Path
    sandbox_launcher_sha256: str
    python_executable: Path
    python_executable_sha256: str
    config_file: Path
    config_sha256: str


def _file_pin(path_text: Any, digest: Any) -> Path:
    if (not isinstance(path_text, str) or not isinstance(digest, str) or
            not re.fullmatch(r'[0-9a-f]{64}', digest)):
        raise ValueError('live development file pin missing')
    path = Path(path_text)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or not path.is_file() or
            hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise ValueError('live development file pin changed')
    return path


def _tree_digest(root: Path) -> str:
    if (not root.is_absolute() or root.is_symlink() or
            any(parent.is_symlink() for parent in root.parents) or
            not root.is_dir()):
        raise ValueError('public toy source root changed')
    digest = hashlib.sha256()
    files = 0
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('public toy source contains symlink')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            content = path.read_bytes()
            digest.update(name.encode() + b'\0' +
                          hashlib.sha256(content).digest() + b'\0')
            files += 1
    if not files:
        raise ValueError('public toy source tree empty')
    return digest.hexdigest()


PHASE1_FILES = frozenset({
    'run.json', 'harness.json', 'workers.json', 'directions.json',
    'function_pool.json', 'selection.json',
})
SCAN_OPTIONS_ALLOWED = frozenset({
    'run_command', 'runtime_sanitizers', 'trace_reachability',
    'assertion_build_command', 'assertion_run_command', 'assertion_seed',
    'target_binary', 'role_models', 'initial_inputs',
    'hallucination_prevent', 'pov_feedback_revisions',
})


def _phase1_digests(run: Path) -> dict[str, str]:
    if (not run.is_absolute() or run.is_symlink() or
            any(parent.is_symlink() for parent in run.parents) or
            run.resolve(strict=True) != run or not run.is_dir()):
        raise ValueError('public Phase 1 run path changed')
    rows = {}
    for name in sorted(PHASE1_FILES):
        path = run / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('public Phase 1 input missing or linked')
        rows[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return rows


def _normal_json(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if value is None or type(value) in (str, int, float, bool):
        return value
    if isinstance(value, (list, tuple)):
        return [_normal_json(item) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {key: _normal_json(item) for key, item in value.items()}
    raise ValueError('unreviewable scan option value')


def _scan_options_digest(options: dict[str, Any]) -> str:
    if set(options) - SCAN_OPTIONS_ALLOWED:
        raise ValueError('unapproved live development scan option')
    normalized = _normal_json(options)
    raw = json.dumps(normalized, sort_keys=True, separators=(',', ':'),
                     allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _scan_options_for_product(options: dict[str, Any] | None) -> dict[str, Any]:
    """Restore JSON-pinned file paths to the Path types expected by Scan."""
    result = dict(options or {})
    for key in ('assertion_seed', 'target_binary'):
        value = result.get(key)
        if value is not None:
            if type(value) is not str and not isinstance(value, Path):
                raise ValueError(f'live scan {key} must be a file path')
            result[key] = Path(value)
    supplied = result.get('initial_inputs')
    if supplied is not None:
        if type(supplied) is not list or any(type(item) is not str and
                                               not isinstance(item, Path)
                                               for item in supplied):
            raise ValueError('live scan initial_inputs must be file paths')
        result['initial_inputs'] = [Path(item) for item in supplied]
    return result


def _option_input_paths(options: dict[str, Any]) -> set[str]:
    normalized = _normal_json(options)
    result: set[str] = set()
    for key in ('assertion_seed', 'target_binary'):
        value = normalized.get(key)
        if value is not None:
            result.add(value)
    for value in normalized.get('initial_inputs') or []:
        result.add(value)
    for key in ('run_command', 'assertion_build_command',
                'assertion_run_command'):
        for value in normalized.get(key) or []:
            if isinstance(value, str) and value.startswith('/') and Path(value).is_file():
                result.add(value)
    if any(not isinstance(path, str) or not Path(path).is_absolute()
           for path in result):
        raise ValueError('live scan input must use absolute path')
    return result


def _artifact_digest(path: Path) -> str:
    if path.is_dir():
        return _tree_digest(path)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            not path.is_file()):
        raise ValueError('public Harness artifact missing or linked')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_live_contract(path: Path, expected_sha256: str) -> tuple[LiveHPContract, str]:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError('live development contract linked')
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise ValueError('live development contract SHA-256 changed')
    row = json.loads(raw)
    if (set(row) != {'kind', 'limits', 'role_models', 'pins',
                     'route_sha256', 'public_toy'} or
            row['kind'] != 'BLIND3_HP_LIVE_DEV_V1' or
            not isinstance(row['limits'], dict) or
            row['limits'] != asdict(LiveHPPolicy())):
        raise ValueError('unapproved live development limits')
    routes = row['role_models']
    if (not isinstance(routes, dict) or
            set(routes) != {'function_analysis', 'assertion_generator'} or
            any(not isinstance(route, dict) or
                    set(route) != {'model', 'reasoning'} or
                    any(not isinstance(value, str) or not value
                        for value in route.values())
                    for route in routes.values())):
        raise ValueError('unapproved live development role route')
    route_sha = row['route_sha256']
    toy = row['public_toy']
    if (not isinstance(route_sha, str) or
            not re.fullmatch(r'[0-9a-f]{64}', route_sha) or
            not isinstance(toy, dict) or set(toy) != {
                'target_repository', 'source_tree_sha256',
                'selected_function_id', 'phase1_run', 'phase1_files_sha256',
                'artifact_path', 'artifact_sha256', 'scan_options_sha256',
                'scan_input_files_sha256'} or
            not isinstance(toy['target_repository'], str) or
            not isinstance(toy['source_tree_sha256'], str) or
            not re.fullmatch(r'[0-9a-f]{64}', toy['source_tree_sha256']) or
            not isinstance(toy['selected_function_id'], str) or
            not toy['selected_function_id'] or
            not isinstance(toy['phase1_run'], str) or
            not isinstance(toy['phase1_files_sha256'], dict) or
            set(toy['phase1_files_sha256']) != PHASE1_FILES or
            not isinstance(toy['artifact_path'], str) or
            not isinstance(toy['artifact_sha256'], str) or
            not re.fullmatch(r'[0-9a-f]{64}', toy['artifact_sha256']) or
            not isinstance(toy['scan_options_sha256'], str) or
            not re.fullmatch(r'[0-9a-f]{64}', toy['scan_options_sha256']) or
            not isinstance(toy['scan_input_files_sha256'], dict)):
        raise ValueError('public toy or Provider route pin incomplete')
    target = Path(toy['target_repository'])
    if _tree_digest(target) != toy['source_tree_sha256']:
        raise ValueError('public toy source tree changed')
    phase1_run = Path(toy['phase1_run'])
    artifact = Path(toy['artifact_path'])
    if (_phase1_digests(phase1_run) != toy['phase1_files_sha256'] or
            _artifact_digest(artifact) != toy['artifact_sha256'] or
            json.loads((phase1_run / 'run.json').read_text()).get('artifact') !=
            str(artifact)):
        raise ValueError('public Phase 1 or Harness artifact changed')
    scan_pins = toy['scan_input_files_sha256']
    if any(not isinstance(name, str) or not isinstance(digest, str) or
           not re.fullmatch(r'[0-9a-f]{64}', digest)
           for name, digest in scan_pins.items()):
        raise ValueError('public scan input pin invalid')
    for name, digest in scan_pins.items():
        _file_pin(name, digest)
    pins = row['pins']
    names = {'codex_executable', 'sandbox_launcher', 'python_executable',
             'config_file'}
    if not isinstance(pins, dict) or set(pins) != names | {
            name + '_sha256' for name in names}:
        raise ValueError('live development pins incomplete')
    files = {name: _file_pin(pins[name], pins[name + '_sha256']) for name in names}
    if files['python_executable'] != Path(sys.executable).resolve():
        raise ValueError('live development Python identity changed')
    if files['sandbox_launcher'] != Path(__file__).with_name(
            'blind2_model_sandbox.py').resolve(strict=True):
        raise ValueError('live development sandbox launcher changed')
    # A byte pin alone could approve a config with Provider retries enabled.
    # Validate the same minimal route contract used by the frozen evaluator.
    legacy.check_zero_retry_config(
        files['config_file'], routes['function_analysis']['model'],
        routes['function_analysis']['reasoning'])
    return LiveHPContract(
        policy=LiveHPPolicy(), role_models=routes,
        route_sha256=route_sha, target_repository=target,
        source_tree_sha256=toy['source_tree_sha256'],
        selected_function_id=toy['selected_function_id'],
        phase1_run=phase1_run,
        phase1_files_sha256=toy['phase1_files_sha256'],
        artifact_path=artifact, artifact_sha256=toy['artifact_sha256'],
        scan_options_sha256=toy['scan_options_sha256'],
        scan_input_files_sha256=scan_pins,
        codex_executable=files['codex_executable'],
        codex_executable_sha256=pins['codex_executable_sha256'],
        sandbox_launcher=files['sandbox_launcher'],
        sandbox_launcher_sha256=pins['sandbox_launcher_sha256'],
        python_executable=files['python_executable'],
        python_executable_sha256=pins['python_executable_sha256'],
        config_file=files['config_file'], config_sha256=pins['config_file_sha256']), actual


def verify_live_state(contract: LiveHPContract) -> None:
    """Bind the actual App Server state directory to the reviewed config."""
    raw = os.environ.get('CODEX_HOME')
    if not raw:
        raise ValueError('live development CODEX_HOME missing')
    home = Path(raw)
    if (not home.is_absolute() or home.is_symlink() or
            any(parent.is_symlink() for parent in home.parents) or
            home.resolve(strict=True) != home or
            stat.S_IMODE(home.stat().st_mode) != 0o700 or
            home / 'config.toml' != contract.config_file):
        raise ValueError('live development CODEX_HOME changed')
    _file_pin(str(home / 'config.toml'), contract.config_sha256)
    auth = home / 'auth.json'
    if (auth.is_symlink() or not auth.is_file() or
            stat.S_IMODE(auth.stat().st_mode) != 0o600):
        raise ValueError('live development auth state unavailable')


def verify_execution_inputs(contract: LiveHPContract, first_run: Path,
                            target_repository: Path,
                            scan_options: dict[str, Any] | None) -> dict[str, str]:
    """Recheck every reviewed Phase 1 byte and scan input before each HP send."""
    run = first_run
    target = target_repository
    if (not run.is_absolute() or run.is_symlink() or
            not target.is_absolute() or target.is_symlink() or
            run.resolve(strict=True) != contract.phase1_run or
            target.resolve(strict=True) != contract.target_repository or
            _tree_digest(target) != contract.source_tree_sha256 or
            _phase1_digests(run) != contract.phase1_files_sha256 or
            _artifact_digest(contract.artifact_path) != contract.artifact_sha256):
        raise ValueError('public Phase 1 execution inputs changed')
    run_row = json.loads((run / 'run.json').read_text())
    selection = json.loads((run / 'selection.json').read_text())
    pool = json.loads((run / 'function_pool.json').read_text())
    source_name = selection.get('source_file') if isinstance(selection, dict) else None
    source = Path(source_name) if isinstance(source_name, str) else Path()
    if (not isinstance(run_row, dict) or
            run_row.get('artifact') != str(contract.artifact_path) or
            not isinstance(selection, dict) or
            selection.get('function_id') != contract.selected_function_id or
            not isinstance(selection.get('function_name'), str) or
            not source_name or source.is_absolute() or '..' in source.parts or
            not (target / source).is_file() or
            not isinstance(pool, list) or
            not any(isinstance(row, dict) and
                    row.get('function_id') == selection['function_id'] and
                    row.get('function_name') == selection['function_name'] and
                    row.get('source_file') == source_name for row in pool)):
        raise ValueError('public Phase 1 selection or SourceSpan changed')
    options = dict(scan_options or {})
    # The scan must use the role routes approved by the live contract. A
    # self-consistent options SHA could otherwise pin an omitted route and
    # yield HP requests with model=None/effort=None.
    if options.get('role_models') != contract.role_models:
        raise ValueError('public scan role_models differ from live development route')
    if (_scan_options_digest(options) != contract.scan_options_sha256 or
            _option_input_paths(options) !=
            set(contract.scan_input_files_sha256)):
        raise ValueError('public scan options or input files changed')
    for name, digest in contract.scan_input_files_sha256.items():
        _file_pin(name, digest)
    return {'phase1_sha256': hashlib.sha256(json.dumps(
                contract.phase1_files_sha256, sort_keys=True).encode()).hexdigest(),
            'scan_options_sha256': contract.scan_options_sha256,
            'artifact_sha256': contract.artifact_sha256}


def verify_live_request_artifacts(ledger: 'LiveHPLedger', run: Path) -> None:
    """Bind the exact private request bytes to every physical HP attempt."""
    for attempt in ledger.attempts:
        name, digest = attempt.get('request_artifact'), attempt.get(
            'request_artifact_sha256')
        path = _file_pin(name, digest)
        if (not path.is_relative_to(run / 'runtime' / 'live_model_requests') or
                stat.S_IMODE(path.stat().st_mode) != 0o600):
            raise ValueError('live model request artifact scope changed')
        row = json.loads(path.read_text())
        if (not isinstance(row, dict) or
                row.get('request_sha256') != attempt['request_hash'] or
                row.get('role') != attempt.get('role') or
                row.get('model') != attempt.get('model') or
                row.get('effort') != attempt.get('effort')):
            raise ValueError('live model request artifact differs from ledger')


async def perform_live_preflight(contract: LiveHPContract, app: 'LiveHPAppServer',
                                 first_run: Path, target_repository: Path,
                                 scan_options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Require public source, namespace isolation, and read-only route probe."""
    identity = verify_execution_inputs(contract, first_run,
                                       target_repository, scan_options)
    run = first_run.resolve(strict=True)
    target = target_repository.resolve(strict=True)
    selection = run / 'selection.json'
    protected = (Path(__file__).parent.parent.resolve(strict=True),
                 Path(legacy.PRODUCT).resolve(strict=True),
                 target, run, Path(os.environ['CODEX_HOME']))
    checks = legacy.verify_model_namespace_sandbox(
        contract.codex_executable, protected)
    if not isinstance(checks, dict) or not checks or any(
            value is not True for value in checks.values()):
        raise ValueError('live development sandbox self-test incomplete')
    await legacy.check_live_route(app, contract.route_sha256, contract.role_models)
    return {'status': 'PASS', 'contract_sha256': app.ledger.contract_sha256,
            'source_tree_sha256': contract.source_tree_sha256,
            'selection_sha256': hashlib.sha256(selection.read_bytes()).hexdigest(),
            'route_sha256': contract.route_sha256,
            'sandbox_checks': checks, **identity}


@dataclass
class LiveHPLedger(DevHPLedger):
    checkpoint_path: str = ''
    scripted_controls: list[dict[str, str]] = field(default_factory=list)
    fuzz_overrun_policy: str = 'PHYSICAL_DEBIT_V1'
    audit_tainted: bool = False

    def __post_init__(self) -> None:
        if (self.policy != asdict(LiveHPPolicy()) or
                not re.fullmatch(r'[0-9a-f]{64}', self.contract_sha256) or
                not Path(self.checkpoint_path).is_absolute() or
                self.fuzz_overrun_policy != 'PHYSICAL_DEBIT_V1'):
            raise ValueError('live development ledger contract changed')

    def checkpoint(self, path: Path | None = None) -> None:
        destination = Path(self.checkpoint_path)
        if (self.audit_tainted or path is not None and path != destination or
                destination.is_symlink() or
                any(parent.is_symlink() for parent in destination.parents)):
            raise ValueError('live development checkpoint path changed')
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (stat.S_IMODE(destination.parent.stat().st_mode) != 0o700 or
                destination.exists() and
                stat.S_IMODE(destination.stat().st_mode) != 0o600):
            raise ValueError('live development checkpoint permissions changed')
        temporary = destination.with_name(destination.name + '.' + uuid4().hex + '.tmp')
        try:
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(self.__dict__, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            directory_fd = os.open(destination.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            self.audit_tainted = True
            temporary.unlink(missing_ok=True)
            raise

    def start_attempt(self, request_hash: str, retry: bool = False, *,
                      model: str, effort: str) -> int:
        if self.audit_tainted or not model or not effort:
            raise ValueError('live development physical start not eligible')
        number = super().start_attempt(request_hash, retry=retry)
        self.attempts[-1].update(role=self.active_turn['role'],
                                 model=model, effort=effort,
                                 request_artifact=self.active_turn.get(
                                     'request_artifact'),
                                 request_artifact_sha256=self.active_turn.get(
                                     'request_artifact_sha256'))
        # This method must return before transport; failure prevents the wire.
        self.checkpoint()
        return number

    def finish_scripted_sp(self, digest: str) -> None:
        turn = self.active_turn
        if (turn is None or turn['role'] != 'sp_generation' or
                turn['hash'] != digest or turn['attempts'] != 0):
            raise ValueError('scripted SP control changed')
        self.scripted_controls.append({'turn_id': turn['id'], 'role': turn['role'],
                                       'request_hash': digest})
        self.active_turn = None
        self.checkpoint()


class LiveHPAppServer(DevelopmentGlobalAppServer):
    """Reuse the pinned product/event collector with one durable HP ledger."""

    def __init__(self, *, ledger: LiveHPLedger, contract: LiveHPContract,
                 cwd: Path, event_log_path: Path, timeout_seconds: float = 600):
        if (timeout_seconds > 600 or timeout_seconds <= 0 or
                event_log_path.is_symlink() or
                event_log_path.parent.stat().st_mode & 0o777 != 0o700):
            raise ValueError('live development timeout or event path changed')
        super().__init__(
            ledger=ledger, role_models=contract.role_models, cwd=cwd,
            model=contract.role_models['function_analysis']['model'],
            effort=contract.role_models['function_analysis']['reasoning'],
            timeout_seconds=timeout_seconds,
            executable=str(contract.codex_executable),
            executable_sha256=contract.codex_executable_sha256,
            event_log_path=event_log_path,
            launch_prefix=[str(contract.python_executable),
                           str(contract.sandbox_launcher)], wire_cwd='/work')
        self.contract = contract
        self._dev_tainted = False
        self._preflight_verified = False
        self._input_guard: Callable[[], Any] | None = None
        self._request_artifact_root: Path | None = None

    async def _request(self, method: str, params: dict, *, response_envelope=None) -> dict:
        if method in {'thread/start', 'turn/start'}:
            if not self._preflight_verified:
                raise ValueError('live development model start before preflight')
            if self._input_guard is None:
                raise ValueError('live execution input guard missing')
            self._input_guard()
        if method != 'turn/start':
            return await self._transport_request(method, params, response_envelope=response_envelope)
        turn = self.ledger.active_turn
        if (self._dev_tainted or turn is None or
                turn['function_id'] != self.scope_id or
                turn['hash'] != self._request_hash):
            raise ValueError('live development turn outside pinned scope')
        route = self.role_models[turn['role']]
        if params.get('model') != route['model'] or params.get('effort') != route['reasoning']:
            raise ValueError('live development model or effort changed')
        self.ledger.start_attempt(self._request_hash,
                                  model=route['model'], effort=route['reasoning'])
        response = await self._transport_request(method, params, response_envelope=response_envelope)
        self._accepted_turn_id = (response.get('turn') or {}).get('id')
        if not isinstance(self._accepted_turn_id, str) or not self._accepted_turn_id:
            raise AppServerError('turn/start returned no turn id')
        self.ledger.attempts[-1]['app_server_turn_id'] = self._accepted_turn_id
        self.ledger.checkpoint()
        return response

    async def generate(self, request: LLMRequest) -> dict[str, Any]:
        if self.forbidden_tool_event:
            raise ModelToolEventError('FORBIDDEN_MODEL_TOOL_EVENT: provider session tainted')
        if self.audit_log_failed:
            raise ModelAuditError('MODEL_AUDIT_WRITE_FAILED: provider session tainted')
        if self.provider_safety_refused:
            raise ProviderSafetyRefusedError('PROVIDER_SAFETY_REFUSED: provider session blocked')
        if (self._dev_tainted or not self._preflight_verified or
                self.scope_id is None or
                request.role not in self.role_models):
            raise ValueError('live development provider no longer eligible')
        route = self.role_models[request.role]
        if request.model != route['model'] or request.effort != route['reasoning']:
            raise ValueError('live development model or effort changed')
        digest = request_hash(request)
        root = self._request_artifact_root
        if root is None or root.is_symlink() or not root.is_absolute():
            raise ValueError('live model request artifact root missing')
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise ValueError('live model request artifact directory not private')
        request_file = root / f'L{self.ledger.logical + 1:03d}_{digest[:16]}.json'
        request_row = {'role': request.role, 'instructions': request.instructions,
                       'payload': request.payload,
                       'output_schema': request.output_schema,
                       'model': request.model, 'effort': request.effort,
                       'request_sha256': digest}
        data = json.dumps(request_row, sort_keys=True, ensure_ascii=False).encode()
        descriptor = os.open(request_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                             0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        request_file_sha = hashlib.sha256(data).hexdigest()
        self._request_hash = digest
        self._accepted_turn_id = None
        self._visible_output = False
        self._internal_retry = False
        self._server_terminal_status = None
        self.ledger.begin_turn(self.scope_id, request.role, digest)
        self.ledger.active_turn.update(
            request_artifact=str(request_file),
            request_artifact_sha256=request_file_sha)
        try:
            self.ledger.checkpoint()
            result = await CodexAppServerClient.generate(self, request)
            self.ledger.finish_attempt(completed=True,
                accepted=bool(self._accepted_turn_id), visible=self._visible_output,
                response_saved=bool(request.raw_response_path and
                                    request.raw_response_path.is_file()))
            self.ledger.checkpoint()
            return result
        except BaseException as original:
            self._dev_tainted = True
            try:
                row = self.ledger.attempts[-1] if self.ledger.attempts else None
                if (self.ledger.active_turn is not None and row is not None and
                        row['turn_id'] == self.ledger.active_turn['id'] and
                        row['status'] == 'STARTED'):
                    self.ledger.finish_attempt(completed=False, error=str(original),
                        accepted=bool(self._accepted_turn_id),
                        visible=self._visible_output,
                        response_saved=bool(request.raw_response_path and
                                            request.raw_response_path.is_file()),
                        internal_retry=self._internal_retry)
                if self.ledger.active_turn is not None:
                    self.ledger.abandon_turn(self.scope_id, type(original).__name__)
                if not self.ledger.audit_tainted:
                    self.ledger.checkpoint()
            except BaseException:
                self.ledger.audit_tainted = True
            raise original
        finally:
            self._request_hash = None


class LiveHPProvider:
    """Explicitly distinguish one scripted SP control from physical HP turns."""
    provider_free = False

    def __init__(self, ledger: LiveHPLedger, app: LiveHPAppServer):
        if app.ledger is not ledger:
            raise ValueError('live provider ledger identity changed')
        self.ledger, self.app = ledger, app
        self.function_id: str | None = None

    def begin_function(self, function_id: str) -> None:
        if self.function_id is not None:
            raise ValueError('live development function already active')
        self.function_id = function_id
        self.app.bind_scope(function_id)

    def end_function(self) -> None:
        self.app.unbind_scope()
        self.function_id = None

    async def generate(self, request: LLMRequest) -> dict[str, Any]:
        if self.function_id is None:
            raise ValueError('live development function not active')
        if request.role == 'sp_generation':
            digest = request_hash(request)
            self.ledger.begin_turn(self.function_id, request.role, digest)
            self.ledger.checkpoint()
            self.ledger.finish_scripted_sp(digest)
            return {'suspicious_points': []}
        if request.role not in {'function_analysis', 'assertion_generator'}:
            raise ValueError('live development role outside HP control')
        return await self.app.generate(request)


def refined_guided_observation(run: Path) -> dict[str, Any]:
    """Keep revised Assertion execution separate from a second RAN Guided job."""
    history_file = run / 'assertions' / 'refinement_history.json'
    jobs_file = run / 'runtime' / 'runner_fuzz_jobs.json'
    if not history_file.is_file() or not jobs_file.is_file():
        return {'status': 'NO_REFINED_ASSERTION'}
    history = json.loads(history_file.read_text())
    jobs = json.loads(jobs_file.read_text())
    if not isinstance(history, dict) or not isinstance(jobs, list):
        raise ValueError('live refinement evidence has invalid shape')
    first_ids = {row.get('id') for row in jobs if isinstance(row, dict) and
                 row.get('kind') == 'ASSERTION' and
                 row.get('result_status') == 'RAN' and
                 isinstance(row.get('physical_actual'), (int, float)) and
                 row['physical_actual'] > 0}
    for lineage in history.get('refinements', []):
        if not isinstance(lineage, dict) or lineage.get('status') != 'REFINED_AND_TESTED':
            continue
        for revision in lineage.get('revisions', []):
            if not isinstance(revision, dict):
                continue
            assertion = revision.get('assertion')
            if not isinstance(assertion, dict):
                continue
            revised_id = assertion.get('assertion_id')
            if (not isinstance(revised_id, str) or
                    assertion.get('status') not in {'HELD_FOR_EXECUTION', 'VIOLATED'}):
                continue
            artifact_name = revision.get('guided_fuzz')
            if not isinstance(artifact_name, str):
                return {'status': 'REFINED_ASSERTION_TESTED_GUIDED_NOT_RAN',
                        'assertion_id': revised_id}
            artifact = Path(artifact_name)
            if (artifact.is_symlink() or not artifact.is_file() or
                    not artifact.resolve().is_relative_to(run.resolve())):
                raise ValueError('live revised Guided artifact missing or outside run')
            report = json.loads(artifact.read_text())
            matching = [row for row in jobs if isinstance(row, dict) and
                        row.get('id') == revised_id and
                        row.get('kind') == 'ASSERTION' and
                        row.get('result_status') == 'RAN' and
                        isinstance(row.get('physical_actual'), (int, float)) and
                        row['physical_actual'] > 0]
            if (len(first_ids - {revised_id}) >= 1 and len(matching) == 1 and
                    isinstance(report, dict) and report.get('status') == 'RAN' and
                    isinstance(report.get('fuzz_seconds_actual'), (int, float)) and
                    report['fuzz_seconds_actual'] > 0):
                return {'status': 'REPORTED_SECOND_GUIDED_RAN',
                        'evidence_scope': 'MUTABLE_REPORTS_ONLY',
                        'assertion_id': revised_id,
                        'artifact': str(artifact),
                        'artifact_sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}
            return {'status': 'REFINED_ASSERTION_TESTED_GUIDED_NOT_RAN',
                    'assertion_id': revised_id}
    return {'status': 'NO_VALID_REFINED_ASSERTION'}


async def run_sequence_live_dev(first_run: Path, provider: LiveHPProvider,
                                ledger: LiveHPLedger, target_repository: Path,
                                checkpoint: Path, *, contract_path: Path,
                                contract_sha256: str,
                                scan_options: dict[str, Any] | None = None):
    """One public-toy development function, never a Blind 3 evaluation."""
    contract, observed = load_live_contract(contract_path, contract_sha256)
    if (observed != ledger.contract_sha256 or
            not isinstance(provider, LiveHPProvider) or
            not isinstance(ledger, LiveHPLedger) or
            provider.app.contract != contract or provider.ledger is not ledger or
            checkpoint != Path(ledger.checkpoint_path)):
        raise ValueError('live development execution contract changed')
    original: BaseException | None = None
    deadline: float | None = None
    try:
        product_scan_options = _scan_options_for_product(scan_options)
        provider.app._preflight_verified = False
        verify_live_state(contract)
        deadline = ledger.started_at + contract.policy.wall_seconds
        remaining = deadline - time.time()
        if remaining <= 0:
            raise TimeoutError('live development wall limit before preflight')
        preflight = await asyncio.wait_for(
            perform_live_preflight(contract, provider.app, first_run,
                                   target_repository, scan_options), timeout=remaining)
        legacy.write_json(first_run.resolve() / 'runtime' /
                          'live_preflight.json', preflight)
        provider.app._input_guard = lambda: verify_execution_inputs(
            contract, first_run, target_repository, scan_options)
        provider.app._request_artifact_root = (first_run.resolve() / 'runtime' /
                                               'live_model_requests')
        provider.app._preflight_verified = True
        remaining = deadline - time.time()
        if remaining <= 0:
            raise TimeoutError('live development wall limit before scan')
        rows = await asyncio.wait_for(_run_sequence_core(
            first_run, provider, ledger, target_repository, checkpoint,
            policy=contract.policy, contract_path=contract_path,
            contract_loader=lambda path, sha: (load_live_contract(path, sha)[0].policy, sha),
            expected_policy=LiveHPPolicy(),
            provider_check=lambda item: item is provider and item.provider_free is False,
            scan_options=product_scan_options), timeout=remaining)
        if time.time() >= deadline:
            raise TimeoutError('live development wall limit after scan')
        try:
            verify_live_request_artifacts(ledger, first_run.resolve())
            verify_model_event_order(ledger, provider.app.event_log_path)
            observation = refined_guided_observation(first_run.resolve())
        except BaseException as audit_error:
            provider.app._dev_tainted = True
            run = first_run.resolve()
            for action in (
                lambda: legacy.write_json(run / 'runtime' /
                    'live_evidence_audit_error.json',
                    {'error_type': type(audit_error).__name__,
                     'message': str(audit_error)}),
                lambda: ledger.mark_pending(run.name, 'LIVE_EVIDENCE_AUDIT_INCOMPLETE'),
                lambda: ledger.checkpoint(checkpoint),
                lambda: legacy.checkpoint_run(run, 'STOPPED_FAIL_CLOSED', ledger),
            ):
                try:
                    action()
                except BaseException:
                    pass
            raise ModelAuditError('LIVE_EVIDENCE_AUDIT_INCOMPLETE') from audit_error
        legacy.write_json(first_run.resolve() / 'runtime' /
                          'live_refined_guided_observation.json', observation)
        rows[0]['refined_guided_observation'] = observation['status']
        if rows[0]['status'] == 'BOUNDARY_ACCOUNTED':
            rows[0]['status'] = (
                'INCONCLUSIVE_REPORTED_GUIDED_RAN' if
                observation['status'] == 'REPORTED_SECOND_GUIDED_RAN' else
                'INCONCLUSIVE_REFINED_GUIDED_NOT_RAN')
        ledger.checkpoint(checkpoint)
        legacy.checkpoint_run(first_run.resolve(), rows[0]['status'], ledger)
        if time.time() >= deadline:
            raise TimeoutError('live development wall limit after evidence audit')
        return rows
    except BaseException as exc:
        original = exc
        provider.app._dev_tainted = True
        if isinstance(exc, (TimeoutError, asyncio.CancelledError)):
            run = first_run.resolve()
            for action in (
                lambda: ledger.mark_pending(run.name,
                    'STOPPED_WALL_LIMIT' if isinstance(exc, TimeoutError)
                    else 'STOPPED_CANCELLED'),
                lambda: ledger.checkpoint(checkpoint),
                lambda: legacy.checkpoint_run(run,
                    'STOPPED_WALL_LIMIT' if isinstance(exc, TimeoutError)
                    else 'STOPPED_CANCELLED', ledger),
            ):
                try:
                    action()
                except BaseException:
                    pass
        raise
    finally:
        # One public-toy run consumes this provider even on success.
        provider.app._preflight_verified = False
        provider.app._dev_tainted = True
        provider.app._input_guard = None
        provider.app._request_artifact_root = None
        try:
            await provider.app.close()
        except BaseException as cleanup:
            if original is None:
                try:
                    run = first_run.resolve()
                    legacy.write_json(run / 'runtime' / 'live_provider_cleanup_error.json',
                                      {'error_type': type(cleanup).__name__,
                                       'message': str(cleanup)})
                    ledger.mark_pending(run.name, 'PROVIDER_CLEANUP_INCOMPLETE')
                    ledger.checkpoint(checkpoint)
                    legacy.checkpoint_run(run, 'STOPPED_CLEANUP_INCOMPLETE', ledger)
                except BaseException:
                    pass
                raise
            # The original model/runtime failure is the primary evidence.
            try:
                run = first_run.resolve()
                legacy.write_json(run / 'runtime' / 'live_provider_cleanup_error.json',
                                  {'error_type': type(cleanup).__name__,
                                   'message': str(cleanup)})
                ledger.checkpoint(checkpoint)
                legacy.checkpoint_run(run, 'STOPPED_CLEANUP_INCOMPLETE', ledger)
            except BaseException:
                pass
        if original is None and deadline is not None and time.time() >= deadline:
            run = first_run.resolve()
            for action in (
                lambda: ledger.mark_pending(run.name, 'STOPPED_WALL_LIMIT'),
                lambda: ledger.checkpoint(checkpoint),
                lambda: legacy.checkpoint_run(run, 'STOPPED_WALL_LIMIT', ledger),
            ):
                try:
                    action()
                except BaseException:
                    pass
            raise TimeoutError('live development wall limit during provider close')
