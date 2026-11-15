"""Pinned, physically supervised public-toy Direction -> Phase1 -> SP/HP.

Evaluation-only. ``--prepare`` and ``--preflight-only`` make no model request.
The live path requires an explicit ``--run-live`` and an externally checked
spec SHA. This is neither an official qualification nor a Blind 3 runner.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
CONTRACT = ROOT / 'tools/FROZEN_CONTRACT_ATTEMPT3.json'
RESULT_NAME = 'DEV_LIVE_SUPERVISOR_RESULT.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
LEDGER_NAME = 'GLOBAL_LEDGER.json'
SPEC_NAME = 'DEV_LIVE_DIRECTION_SP_HP_SPEC.json'
WALL_SECONDS = 1200
HEX = re.compile(r'[0-9a-f]{64}\Z')
INLINE_BOOTSTRAP = '''\
import hashlib, pathlib, sys
source = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
if (not source.is_absolute() or source.is_symlink() or
        any(parent.is_symlink() for parent in source.parents) or
        source.resolve(strict=True) != source):
    raise ValueError('bootstrap source changed: linked path')
raw = source.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected:
    raise ValueError('bootstrap source changed: SHA-256')
sys.argv = [str(source), *sys.argv[3:]]
exec(compile(raw, str(source), 'exec'), {
    '__name__': '__main__', '__file__': str(source),
    '__VA_SOURCE_BOOTSTRAP_SHA__': expected})
'''


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _plain_path(path: Path, *, directory: bool) -> None:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or
            not (path.is_dir() if directory else path.is_file())):
        raise ValueError(f'pinned path missing or symlinked: {path}')


def _private_dir(path: Path) -> None:
    _plain_path(path, directory=True)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError(f'private output mode changed: {path}')


def _fresh_cache(output: Path, name: str) -> Path:
    """Choose an empty cache before importing pinned evaluation/product code.

    Python -B suppresses cache writes but may read an existing stale pyc.
    ``sys.pycache_prefix`` changes where importlib looks for it.
    """
    cache = output / name
    if cache.exists() or cache.is_symlink():
        raise ValueError('dedicated Python cache already exists')
    cache.mkdir(mode=0o700)
    _private_dir(cache)
    sys.pycache_prefix = str(cache)
    os.environ['PYTHONPYCACHEPREFIX'] = str(cache)
    return cache


@contextmanager
def _preflight_cache(output: Path):
    """Use a fresh import cache for each repeatable read-only preflight."""
    _private_dir(output)
    previous_prefix = sys.pycache_prefix
    previous_env = os.environ.get('PYTHONPYCACHEPREFIX')
    with tempfile.TemporaryDirectory(prefix='preflight_pycache_', dir=output) as name:
        cache = Path(name)
        _private_dir(cache)
        sys.pycache_prefix = name
        os.environ['PYTHONPYCACHEPREFIX'] = name
        try:
            yield cache
        finally:
            sys.pycache_prefix = previous_prefix
            if previous_env is None:
                os.environ.pop('PYTHONPYCACHEPREFIX', None)
            else:
                os.environ['PYTHONPYCACHEPREFIX'] = previous_env


def _route_pinned_codex(contract: dict[str, Any]) -> None:
    executable = Path(contract['codex_executable_path'])
    _plain_path(executable, directory=False)
    if sha(executable) != contract['codex_executable_sha256']:
        raise ValueError('Codex executable differs from contract')
    os.environ['PATH'] = str(executable.parent) + os.pathsep + os.environ.get('PATH', '')
    if Path(shutil.which('codex') or '/missing').resolve() != executable:
        raise ValueError('pinned Codex executable route changed')


def tree_digest(root: Path, suffixes: set[str] | None) -> str:
    """Hash all selected bytes; reject linked paths and executable bypasses."""
    _plain_path(root, directory=True)
    entries: list[tuple[str, str]] = []
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in names:
            if (base / name).is_symlink():
                raise ValueError(f'source tree symlink: {base / name}')
        for name in files:
            path = base / name
            if path.is_symlink():
                raise ValueError(f'source tree symlink: {path}')
            if path.suffix in {'.so', '.pyd', '.dll', '.dylib'}:
                raise ValueError(f'unreviewed native extension: {path}')
            if path.suffix == '.pyc':
                if path.parent.name != '__pycache__' or '.cpython-' not in name:
                    raise ValueError(f'loose bytecode: {path}')
                source = path.parent.parent / (name.split('.cpython-', 1)[0] + '.py')
                if not source.is_file() or source.is_symlink():
                    raise ValueError(f'sourceless bytecode: {path}')
                continue
            if suffixes is None or path.suffix in suffixes:
                entries.append((path.relative_to(root).as_posix(), sha(path)))
    if not entries:
        raise ValueError(f'source tree empty: {root}')
    return hashlib.sha256(json.dumps(sorted(entries),
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def require_tree_digest(root: Path, suffixes: set[str] | None,
                        expected: str) -> None:
    if not isinstance(expected, str) or not HEX.fullmatch(expected):
        raise ValueError('source tree pin invalid')
    if tree_digest(root, suffixes) != expected:
        raise ValueError(f'source tree changed: {root}')


def _code_pins() -> dict[str, str]:
    pyproject = PRODUCT / 'pyproject.toml'
    _plain_path(pyproject, directory=False)
    return {
        'product_pyproject': sha(pyproject),
        'product_src': tree_digest(PRODUCT / 'src', {'.py'}),
        'product_prompts': tree_digest(PRODUCT / 'prompts', {'.md'}),
        'product_config': tree_digest(PRODUCT / 'config', {'.yaml', '.yml'}),
        'product_tests': tree_digest(PRODUCT / 'tests', {'.py'}),
        'evaluation_tools': tree_digest(ROOT / 'evaluation_tools', {'.py'}),
        'review_tools': tree_digest(ROOT / 'review_tools', {'.py'}),
    }


def _dependency_pins() -> dict[str, str]:
    return {name: metadata.version(name) for name in ('PyYAML', 'jsonschema')}


def _write_once(path: Path, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True,
                      ensure_ascii=False) + '\n').encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _write_once_at(directory_fd: int, name: str, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True,
                      ensure_ascii=False) + '\n').encode()
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory_fd)


def _evidence_at(directory_fd: int, output: Path, name: str) -> dict[str, Any]:
    result: dict[str, Any] = {'path': str(output / name), 'sha256': None}
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                     dir_fd=directory_fd)
    except OSError:
        return result
    with os.fdopen(fd, 'rb') as stream:
        if stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            result['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return result


def _evidence(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {'path': str(path), 'sha256': None}
    if path.is_file() and not path.is_symlink():
        result['sha256'] = sha(path)
    return result


def prepare(output: Path) -> tuple[Path, str]:
    """Create a new immutable-input spec without starting Codex or a model."""
    if (output.exists() or output.is_symlink() or not output.is_absolute() or
            output.parent.resolve(strict=True) != (ROOT / 'review').resolve()):
        raise ValueError('new public-toy output must be in the Linux review root')
    pins = _code_pins()
    _plain_path(CONTRACT, directory=False)
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    config = ROOT / contract['codex_config']
    executable = Path(contract['codex_executable_path'])
    interpreter = Path('/usr/bin/python3.12')
    for path in (config, executable, interpreter):
        _plain_path(path, directory=False)
    if sha(executable) != contract['codex_executable_sha256']:
        raise ValueError('Codex executable differs from contract')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    output_stat = output.stat()
    _fresh_cache(output, 'prepare_pycache')
    # The fixture is generated before review; its exact bytes are later pinned.
    sys.path[:0] = [str(ROOT / 'review_tools'), str(PRODUCT / 'src'),
                    str(PRODUCT / 'tests')]
    from dev_budgeted_product_flow import create_public_fixture
    create_public_fixture(output / 'fixture')
    row = {
        'kind': 'DEV_LIVE_DIRECTION_SP_HP_SUPERVISED_V1',
        'scope': 'public toy only; no target execution or Blind 3',
        'output_dir': str(output),
        'output_identity': {'dev': output_stat.st_dev,
                            'ino': output_stat.st_ino},
        'product_root': str(PRODUCT),
        'reference_root': str(ROOT),
        'code_pins': pins,
        'dependency_versions': _dependency_pins(),
        'driver_sha256': sha(Path(__file__)),
        'fixture_sha256': tree_digest(output / 'fixture', None),
        'contract_path': str(CONTRACT),
        'contract_sha256': sha(CONTRACT),
        'codex_config_sha256': sha(config),
        'codex_executable_sha256': sha(executable),
        'python_path': str(interpreter),
        'python_sha256': sha(interpreter),
        'global_budget': {'physical': 3, 'logical': 3, 'retries': 0,
                          'wall_seconds': WALL_SECONDS},
    }
    spec = output / SPEC_NAME
    _write_once(spec, row)
    return spec, sha(spec)


def load_spec(path: Path, expected_sha256: str) -> dict[str, Any]:
    """Authenticate all code and fixture bytes before non-stdlib imports."""
    if (not isinstance(expected_sha256, str) or
            not HEX.fullmatch(expected_sha256) or not path.is_file() or
            path.is_symlink() or sha(path) != expected_sha256):
        raise ValueError('development spec pin changed')
    row = json.loads(path.read_text(encoding='utf-8'))
    required = {'kind', 'scope', 'output_dir', 'output_identity', 'product_root',
                'reference_root', 'code_pins', 'fixture_sha256',
                'driver_sha256', 'dependency_versions',
                'contract_path', 'contract_sha256', 'codex_config_sha256',
                'codex_executable_sha256', 'python_path', 'python_sha256',
                'global_budget'}
    if (not isinstance(row, dict) or set(row) != required or
            row['kind'] != 'DEV_LIVE_DIRECTION_SP_HP_SUPERVISED_V1' or
            row['scope'] != 'public toy only; no target execution or Blind 3' or
            row['product_root'] != str(PRODUCT) or
            row['reference_root'] != str(ROOT) or
            row['contract_path'] != str(CONTRACT) or
            row['python_path'] != '/usr/bin/python3.12' or
            row['global_budget'] != {'physical': 3, 'logical': 3,
                                     'retries': 0, 'wall_seconds': WALL_SECONDS} or
            not isinstance(row['code_pins'], dict) or
            set(row['code_pins']) != set(_code_pins()) or
            row['dependency_versions'] != _dependency_pins()):
        raise ValueError('development spec shape or route changed')
    output = Path(row['output_dir'])
    _private_dir(output)
    current_identity = output.stat()
    if row['output_identity'] != {'dev': current_identity.st_dev,
                                  'ino': current_identity.st_ino}:
        raise ValueError('development output inode changed')
    if path != output / SPEC_NAME or not output.is_relative_to(ROOT / 'review'):
        raise ValueError('development spec output route changed')
    if row['driver_sha256'] != sha(Path(__file__)):
        raise ValueError('development driver source changed')
    for name, value in _code_pins().items():
        if value != row['code_pins'][name]:
            raise ValueError(f'source tree changed: {name}')
    require_tree_digest(output / 'fixture', None, row['fixture_sha256'])
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    config = ROOT / contract['codex_config']
    executable = Path(contract['codex_executable_path'])
    for item, expected in ((CONTRACT, row['contract_sha256']),
                           (config, row['codex_config_sha256']),
                           (executable, row['codex_executable_sha256']),
                           (Path(row['python_path']), row['python_sha256'])):
        _plain_path(item, directory=False)
        if not isinstance(expected, str) or sha(item) != expected:
            raise ValueError(f'development file pin changed: {item}')
    if row['codex_executable_sha256'] != contract['codex_executable_sha256']:
        raise ValueError('Codex executable differs from contract')
    return row


def _imports():
    sys.path[:0] = [str(ROOT / 'review_tools'), str(ROOT / 'evaluation_tools'),
                    str(PRODUCT / 'src'), str(PRODUCT / 'tests')]
    import blind2_runner_draft as runner
    import dev_live_toy_global_appserver as toy
    from dev_global_appserver_bridge import DevelopmentGlobalAppServer
    from dev_global_request_ledger import DevelopmentBudget, DevelopmentRequestLedger
    return runner, toy, DevelopmentGlobalAppServer, DevelopmentBudget, DevelopmentRequestLedger


def offline_preflight(row: dict[str, Any]) -> dict[str, Any]:
    """Validate the pinned contract, roles and public toy before any model use."""
    with _preflight_cache(Path(row['output_dir'])):
        return _offline_preflight_body(row)


def _offline_preflight_body(row: dict[str, Any]) -> dict[str, Any]:
    runner, toy, _app, _budget, _ledger = _imports()
    if _code_pins() != row['code_pins']:
        raise ValueError('source tree changed during preflight import')
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    config = ROOT / contract['codex_config']
    _route_pinned_codex(contract)
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    executable = runner.verify_pinned_codex_executable(contract)
    roles = toy.live_role_models(contract)
    fixture = Path(row['output_dir']) / 'fixture'
    _context, input_pins = toy.prepare_toy_direction_context(
        fixture / 'attempt', fixture)
    if tree_digest(fixture, None) != row['fixture_sha256']:
        raise ValueError('public toy input changed during preflight')
    return {'status': 'PREFLIGHT_PASS_NO_MODEL_CALL',
            'contract_sha256': row['contract_sha256'],
            'codex_executable_sha256': sha(executable),
            'dependency_versions': row['dependency_versions'],
            'role_models': roles, 'fixture_inputs': input_pins}


async def _run_child(row: dict[str, Any]) -> dict[str, Any]:
    runner, toy, AppServer, Budget, Ledger = _imports()
    if _code_pins() != row['code_pins']:
        raise ValueError('source tree changed during live import')
    output = Path(row['output_dir'])
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    config = ROOT / contract['codex_config']
    _route_pinned_codex(contract)
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    executable = runner.verify_pinned_codex_executable(contract)
    roles = toy.live_role_models(contract)
    repo = output / 'fixture'
    artifact = repo / 'attempt'
    model_cwd = output / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    _private_dir(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('model cwd must be empty')
    _write_once(output / 'PRECHECK.json', {
        'kind': 'DEV_LIVE_TOY_PINNED_PRECHECK_V1',
        'spec_sha256': sha(output / SPEC_NAME),
        'code_pins': row['code_pins'],
        'fixture_sha256': row['fixture_sha256'],
        'contract_sha256': row['contract_sha256'],
        'codex_config_sha256': row['codex_config_sha256'],
        'codex_executable_sha256': row['codex_executable_sha256'],
        'dependency_versions': row['dependency_versions'],
        'role_models': roles,
    })
    ledger = Ledger.create(Budget(
        physical_max=3, logical_max=3, retries_max=0,
        wall_seconds=WALL_SECONDS, initial_starts_required=2,
        sp_per_function=1, hp_per_function=1,
        combined_per_function=2, hp_analysis_per_function=1,
        hp_assertion_per_function=1), output / LEDGER_NAME)
    with runner.private_codex_state(config):
        sandbox = runner.verify_model_namespace_sandbox(
            executable, (*runner._protected_model_paths(contract), repo))
        _write_once(output / 'SANDBOX_SELF_TEST.json', sandbox)
        backend = AppServer(
            ledger=ledger, role_models=roles, cwd=model_cwd,
            wire_cwd='/work',
            launch_prefix=[sys.executable,
                str(ROOT / 'evaluation_tools/blind2_model_sandbox.py')],
            executable=str(executable),
            executable_sha256=contract['codex_executable_sha256'],
            model=contract['default_model'],
            effort=contract['default_effort'], timeout_seconds=300,
            event_log_path=output / 'MODEL_EVENTS.jsonl')
        async with backend:
            await asyncio.wait_for(runner.check_live_route(
                backend, contract['route_sha256'], roles), timeout=120)
            result = await asyncio.wait_for(toy.execute_toy_flow(
                output=output, artifact=artifact, repo=repo,
                ledger=ledger, backend=backend,
                role_models=roles), timeout=1000)
    return result


def _child(spec: Path, expected_sha256: str) -> int:
    row = load_spec(spec, expected_sha256)
    output = Path(row['output_dir'])
    cache = output / 'pycache'
    _private_dir(cache)
    if sys.pycache_prefix != str(cache) or any(cache.iterdir()):
        raise ValueError('fresh dedicated Python cache prefix required')
    try:
        result = asyncio.run(_run_child(row))
        if _code_pins() != row['code_pins'] or tree_digest(
                output / 'fixture', None) != row['fixture_sha256']:
            raise ValueError('code or fixture changed during live trace')
        _write_once(output / CHILD_NAME, result)
        return 0 if result['status'] == 'BOUNDED_TOY_TRACE_COMPLETE' else 1
    except BaseException as exc:
        if not (output / CHILD_NAME).exists():
            _write_once(output / CHILD_NAME, {
                'status': 'STOPPED', 'error_type': type(exc).__name__,
                'error': str(exc)[:1024],
                'ledger': _evidence(output / LEDGER_NAME),
                'model_events': _evidence(output / 'MODEL_EVENTS.jsonl')})
        raise


def supervise_command(command: list[str], output: Path, *, wall_seconds: float,
                      runner: Any = None,
                      spec_sha256: str | None = None,
                      completion_predicate: Callable[[dict, int, Path], bool] | None = None,
                      expected_output_identity: tuple[int, int] | None = None
                      ) -> dict[str, Any]:
    """Use the existing subreaper under a hard wall, including stopped children."""
    if not 0 < wall_seconds <= WALL_SECONDS:
        raise ValueError('development physical wall limit invalid')
    _private_dir(output)
    if (output / RESULT_NAME).exists():
        raise ValueError('supervised result already exists')
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_identity = os.fstat(directory_fd)
    if (expected_output_identity is not None and
            (directory_identity.st_dev, directory_identity.st_ino) !=
                expected_output_identity):
        os.close(directory_fd)
        raise ValueError('development output inode changed before launch')
    if runner is None:
        _fresh_cache(output, 'supervisor_pycache')
        sys.path.insert(0, str(ROOT / 'evaluation_tools'))
        import blind2_runner_draft as runner
    started = time.monotonic()
    reason, code, cleanup = 'CHILD_EXITED', None, True
    child = None
    status_fd = None
    primary_error: str | None = None
    cleanup_error: str | None = None
    try:
        log_fd = os.open('supervisor.log', os.O_CREAT | os.O_EXCL |
                         os.O_WRONLY | os.O_NOFOLLOW, 0o600,
                         dir_fd=directory_fd)
        with os.fdopen(log_fd, 'wb') as log:
            child, status_fd = runner._launch_guarded(
                command, stdout=log, stderr=subprocess.STDOUT,
                env={**os.environ, 'PYTHONUNBUFFERED': '1'})
            try:
                child.wait(timeout=wall_seconds)
                code = runner._guarded_return_code(child, status_fd)
                if code == -32768:
                    reason, cleanup = 'CHILD_ERROR', False
            except subprocess.TimeoutExpired:
                reason = 'STOPPED_WALL_LIMIT'
                try:
                    cleanup = runner._request_guard_cleanup(child, status_fd)
                except BaseException as exc:
                    cleanup = False
                    cleanup_error = type(exc).__name__
            except BaseException as exc:
                reason = 'CHILD_ERROR'
                primary_error = type(exc).__name__
                try:
                    cleanup = runner._request_guard_cleanup(child, status_fd)
                except BaseException as stopped:
                    cleanup = False
                    cleanup_error = type(stopped).__name__
    except BaseException as exc:
        reason = 'CHILD_ERROR'
        primary_error = type(exc).__name__
        if child is not None and status_fd is not None and child.poll() is None:
            try:
                cleanup = runner._request_guard_cleanup(child, status_fd)
            except BaseException as stopped:
                cleanup = False
                cleanup_error = type(stopped).__name__
    finally:
        if child is not None:
            try:
                runner._kill_process_group(child.pid)
                if child.poll() is None:
                    child.wait(timeout=5)
            except BaseException as exc:
                cleanup = False
                cleanup_error = type(exc).__name__
        if status_fd is not None:
            try:
                os.close(status_fd)
            except OSError as exc:
                cleanup = False
                cleanup_error = type(exc).__name__
    output_identity_ok = True
    try:
        current = os.stat(output, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or
                (current.st_dev, current.st_ino) !=
                (directory_identity.st_dev, directory_identity.st_ino)):
            output_identity_ok = False
    except OSError:
        output_identity_ok = False
    completed_trace = False
    child_result_path = output / CHILD_NAME
    if code == 0:
        try:
            child_fd = os.open(CHILD_NAME,
                               os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                               dir_fd=directory_fd)
            with os.fdopen(child_fd, 'rb') as stream:
                metadata = os.fstat(stream.fileno())
                if (stat.S_ISREG(metadata.st_mode) and
                        metadata.st_size <= 1_000_000):
                    child_row = json.loads(stream.read().decode('utf-8'))
                else:
                    child_row = {}
                if completion_predicate is None:
                    completed_trace = (child_row.get('status') ==
                        'BOUNDED_TOY_TRACE_COMPLETE' and
                        child_row.get('physical') == 3 and
                        child_row.get('logical') == 3 and
                        child_row.get('retries') == 0 and
                        _evidence_at(directory_fd, output, LEDGER_NAME)['sha256'] is not None)
                else:
                    completed_trace = bool(completion_predicate(
                        child_row, directory_fd, output))
        except (OSError, ValueError, TypeError, UnicodeError):
            completed_trace = False
    status = ('STOPPED_CLEANUP_INCOMPLETE' if not cleanup else
              'STOPPED_OUTPUT_IDENTITY_CHANGED' if not output_identity_ok else
              reason if reason != 'CHILD_EXITED' else
              'CHILD_EXITED_COMPLETE' if code == 0 and completed_trace else
              'CHILD_EXITED_INCONCLUSIVE' if code == 0 else 'CHILD_ERROR')
    result = {'status': status, 'original_stop_reason': reason,
              'wall_seconds': wall_seconds,
              'elapsed_seconds': time.monotonic() - started,
              'return_code': code, 'cleanup_incomplete': not cleanup,
              'output_identity_ok': output_identity_ok,
              'output_dev': directory_identity.st_dev,
              'output_ino': directory_identity.st_ino,
              'child_result': _evidence_at(directory_fd, output, CHILD_NAME),
              'physical_ledger': _evidence_at(directory_fd, output, LEDGER_NAME),
              'supervisor_log': _evidence_at(directory_fd, output, 'supervisor.log')}
    if spec_sha256 is not None:
        result['spec_sha256'] = spec_sha256
    if primary_error is not None:
        result['primary_error_type'] = primary_error
    if cleanup_error is not None:
        result['cleanup_error_type'] = cleanup_error
    try:
        _write_once_at(directory_fd, RESULT_NAME, result)
    finally:
        os.close(directory_fd)
    return result


def run_supervised(spec: Path, digest: str) -> dict[str, Any]:
    row = load_spec(spec, digest)
    output = Path(row['output_dir'])
    if (output / LEDGER_NAME).exists() or (output / CHILD_NAME).exists():
        raise ValueError('development attempt already started')
    _fresh_cache(output, 'parent_pycache')
    cache = output / 'pycache'
    cache.mkdir(mode=0o700)
    _private_dir(cache)
    if any(cache.iterdir()):
        raise ValueError('development cache is not fresh')
    sys.path.insert(0, str(ROOT / 'evaluation_tools'))
    import blind2_runner_draft as runner
    if _code_pins() != row['code_pins']:
        raise ValueError('source tree changed during supervisor import')
    command = [row['python_path'], '-I', '-B', '-X',
               f'pycache_prefix={cache}', '-c', INLINE_BOOTSTRAP,
               str(Path(__file__).resolve()), row['driver_sha256'],
               '--child', str(spec), digest]
    result = supervise_command(command, output, wall_seconds=WALL_SECONDS,
                               runner=runner, spec_sha256=digest)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--preflight-only', action='store_true')
    group.add_argument('--run-live', action='store_true')
    group.add_argument('--child', action='store_true')
    parser.add_argument('path', type=Path)
    parser.add_argument('sha256', nargs='?')
    args = parser.parse_args(argv)
    if (sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('use /usr/bin/python3.12 -I -B')
    if (args.run_live or args.child) and globals().get(
            '__VA_SOURCE_BOOTSTRAP_SHA__') != sha(Path(__file__)):
        raise ValueError('live execution requires external source pin')
    if args.prepare:
        spec, digest = prepare(args.path)
        print(json.dumps({'status': 'PREPARED_NO_MODEL_CALL',
                          'spec': str(spec), 'sha256': digest}))
        return 0
    if not args.sha256:
        parser.error('reviewed spec SHA-256 required')
    if args.preflight_only:
        row = load_spec(args.path, args.sha256)
        print(json.dumps(offline_preflight(row), sort_keys=True))
        return 0
    if args.child:
        return _child(args.path, args.sha256)
    result = run_supervised(args.path, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
