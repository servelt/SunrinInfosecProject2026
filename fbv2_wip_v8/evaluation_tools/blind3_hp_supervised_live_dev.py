"""Physical supervisor for one public-toy HP live-development run.

This is an evaluation-only boundary. It does not approve or execute Blind 3.
The child runs the existing live-dev pipeline; the parent enforces its wall
deadline even while the child is blocked in synchronous compiler/runtime code.
"""
from __future__ import annotations

import argparse
import atexit
import asyncio
import builtins
from dataclasses import asdict, dataclass
import hashlib
from importlib.machinery import EXTENSION_SUFFIXES
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


HERE = Path(__file__).resolve().parent
# This literal is supplied to Python -c by an external, reviewed command for
# the parent. The parent uses the same verified literal for its child.  It
# compiles the bytes it hashed, so replacing the path after the read cannot
# change the entrypoint that executes.
BOOTSTRAP_CODE = '''
import builtins, hashlib, pathlib, sys
script = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
if (not script.is_absolute() or script.is_symlink() or
        any(parent.is_symlink() for parent in script.parents) or
        not script.is_file() or len(expected) != 64 or
        any(letter not in '0123456789abcdef' for letter in expected)):
    raise SystemExit('external bootstrap path or SHA invalid')
raw = script.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit('external bootstrap script SHA changed')
builtins._VA_HP_BOOTSTRAP = (str(script), expected)
sys.argv = [str(script), *sys.argv[3:]]
scope = {'__name__': '__main__', '__file__': str(script),
         '__package__': None, '__builtins__': builtins.__dict__}
exec(compile(raw, str(script), 'exec'), scope)'''


def _require_external_bootstrap() -> None:
    attestation = getattr(builtins, '_VA_HP_BOOTSTRAP', None)
    script = Path(__file__).resolve()
    if (not isinstance(attestation, tuple) or len(attestation) != 2 or
            attestation[0] != str(script) or
            not isinstance(attestation[1], str) or
            hashlib.sha256(script.read_bytes()).hexdigest() != attestation[1] or
            getattr(sys, '_va_hp_private_pycache', None) != sys.pycache_prefix or
            not isinstance(sys.pycache_prefix, str) or
            not Path(sys.pycache_prefix).is_dir()):
        raise ValueError('external bootstrap and private cache required')


def _runtime_code_files() -> tuple[str, ...]:
    # The live entrypoint imports helpers transitively. Pin the complete
    # evaluation runtime set so a newly added helper cannot evade the spec.
    for path in HERE.iterdir():
        if path.is_symlink():
            raise ValueError(f'development evaluation contains symlink: {path}')
        if path.is_dir() and path.name != '__pycache__':
            raise ValueError(f'development evaluation has unregistered package: {path}')
        if path.is_file() and (
                path.suffix == '.pyc' or
                any(path.name.endswith(suffix) for suffix in EXTENSION_SUFFIXES) or
                path.suffix in {'.pyd', '.dll'}):
            raise ValueError(f'development evaluation has unregistered executable: {path}')
    return tuple(sorted(path.name for path in HERE.glob('*.py')
                        if not path.name.startswith('test_') and
                        path.name != Path(__file__).name))


CODE_FILES = _runtime_code_files()
RESULT_NAME = 'HP_SUPERVISOR_RESULT.json'
CHILD_NAME = 'HP_LIVE_DEV_CHILD_RESULT.json'
LEDGER_NAME = 'HP_LIVE_DEV_LEDGER.json'
HEX = re.compile(r'[0-9a-f]{64}\Z')
# Must match LiveHPPolicy.wall_seconds. Child load_live_contract enforces the
# full frozen policy before the first model turn. Parent preflight is moved
# inside this physically supervised child.
SUPERVISED_WALL_SECONDS = 3300


def _fresh_private_pycache() -> None:
    """Avoid preexisting project bytecode before the first evaluation import."""
    directory = Path(tempfile.mkdtemp(prefix='va-hp-dev-pycache-'))
    directory.chmod(0o700)
    if any(directory.iterdir()):
        raise ValueError('development Python cache is not empty')
    sys.pycache_prefix = str(directory)
    sys._va_hp_private_pycache = str(directory)
    atexit.register(shutil.rmtree, directory, ignore_errors=True)


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _plain_private_dir(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or not path.is_dir() or
            stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError(f'private development directory changed: {path}')


def _pinned_file(path: Path, digest: str) -> None:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or not path.is_file() or
            not HEX.fullmatch(digest) or sha(path) != digest):
        raise ValueError(f'development file pin changed: {path}')


def _source_digest(root: Path) -> str:
    """Hash executable product Python and model-facing prompt/config bytes."""
    if (not root.is_absolute() or root.is_symlink() or
            any(parent.is_symlink() for parent in root.parents) or
            root.resolve(strict=True) != root or not root.is_dir()):
        raise ValueError('development product root changed')
    digest = hashlib.sha256()
    found = 0
    for folder in ('src', 'prompts', 'config'):
        base = root / folder
        if not base.is_dir() or base.is_symlink():
            raise ValueError(f'development product folder missing: {folder}')
        for path in sorted(base.rglob('*')):
            if path.is_symlink():
                raise ValueError('development product contains symlink')
            if path.is_file() and (
                    (path.suffix == '.pyc' and '__pycache__' not in path.parts) or
                    any(path.name.endswith(suffix) for suffix in EXTENSION_SUFFIXES) or
                    path.suffix in {'.pyd', '.dll'}):
                raise ValueError(f'development product has unregistered executable: {path}')
            if path.is_file() and path.suffix in {'.py', '.md', '.yaml', '.yml'}:
                digest.update(path.relative_to(root).as_posix().encode() + b'\0')
                digest.update(bytes.fromhex(sha(path)))
                found += 1
    if not found:
        raise ValueError('development product source empty')
    return digest.hexdigest()


@dataclass(frozen=True)
class SupervisedSpec:
    contract_path: Path
    contract_sha256: str
    output_dir: Path
    product_root: Path
    product_source_sha256: str
    evaluation_sha256: dict[str, str]
    scan_options: dict[str, Any]
    output_dir_device: int
    output_dir_inode: int
    spec_sha256: str


def load_spec(path: Path, expected_sha256: str) -> SupervisedSpec:
    """Authenticate script and product bytes before importing either product."""
    _pinned_file(path, expected_sha256)
    row = json.loads(path.read_text())
    if (not isinstance(row, dict) or set(row) != {
            'kind', 'contract_path', 'contract_sha256', 'output_dir',
            'product_root', 'product_source_sha256', 'evaluation_sha256',
            'scan_options'} or row['kind'] != 'BLIND3_HP_SUPERVISED_DEV_V1' or
            not isinstance(row['evaluation_sha256'], dict) or
            set(CODE_FILES) != set(_runtime_code_files()) or
            set(row['evaluation_sha256']) != set(CODE_FILES) | {Path(__file__).name} or
            not isinstance(row['scan_options'], dict)):
        raise ValueError('development supervisor spec shape changed')
    for name, digest in row['evaluation_sha256'].items():
        _pinned_file(HERE / name, digest)
    product_root = Path(row['product_root'])
    if _source_digest(product_root) != row['product_source_sha256']:
        raise ValueError('development product source changed')
    contract_path = Path(row['contract_path'])
    _pinned_file(contract_path, row['contract_sha256'])
    output_dir = Path(row['output_dir'])
    _plain_private_dir(output_dir)
    output_stat = os.stat(output_dir, follow_symlinks=False)
    if ((output_dir / RESULT_NAME).exists() or
            (output_dir / CHILD_NAME).exists() or
            (output_dir / LEDGER_NAME).exists()):
        raise ValueError('development supervised attempt already exists')
    return SupervisedSpec(contract_path, row['contract_sha256'], output_dir,
                          product_root, row['product_source_sha256'],
                          row['evaluation_sha256'], row['scan_options'],
                          output_stat.st_dev, output_stat.st_ino,
                          expected_sha256)


def _import_live(spec: SupervisedSpec):
    # Spec pins have been checked before any evaluation/product imports.
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    if str(spec.product_root.parent) not in sys.path:
        sys.path.insert(1, str(spec.product_root.parent))
    import blind3_hp_iteration_live_dev as live
    return live


def preflight(spec: SupervisedSpec):
    live = _import_live(spec)
    contract, _ = live.load_live_contract(spec.contract_path,
                                          spec.contract_sha256)
    live.verify_live_state(contract)
    live.verify_execution_inputs(contract, contract.phase1_run,
                                 contract.target_repository, spec.scan_options)
    return live, contract


def _write_once(path: Path, row: dict[str, Any]) -> None:
    raw = (json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n').encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    dirfd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def _evidence_file(path: Path) -> dict[str, Any]:
    row: dict[str, Any] = {'path': str(path), 'sha256': None}
    if path.is_file() and not path.is_symlink():
        try:
            row['sha256'] = sha(path)
        except OSError as exc:
            row['read_error'] = type(exc).__name__
    return row


def _open_private_dir_fd(path: Path) -> int:
    """Walk each component without following a symlink; retain its inode."""
    _plain_private_dir(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            raise ValueError('development output directory mode changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _path_matches_dir_fd(path: Path, fd: int) -> bool:
    try:
        by_path = os.lstat(path)
        held = os.fstat(fd)
        return (stat.S_ISDIR(by_path.st_mode) and
                by_path.st_dev == held.st_dev and
                by_path.st_ino == held.st_ino and
                stat.S_IMODE(by_path.st_mode) == 0o700 and
                not any(parent.is_symlink() for parent in path.parents))
    except OSError:
        return False


def _write_once_at(dirfd: int, name: str, row: dict[str, Any]) -> None:
    if '/' in name or name in {'', '.', '..'}:
        raise ValueError('development output name changed')
    raw = (json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n').encode()
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(dirfd)


def _evidence_file_at(dirfd: int, output: Path, name: str) -> dict[str, Any]:
    row: dict[str, Any] = {'path': str(output / name), 'sha256': None}
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=dirfd)
    except FileNotFoundError:
        return row
    except OSError as exc:
        row['read_error'] = type(exc).__name__
        return row
    try:
        with os.fdopen(fd, 'rb') as stream:
            observed = os.fstat(stream.fileno())
            if not stat.S_ISREG(observed.st_mode):
                row['read_error'] = 'NotRegularFile'
                return row
            row['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            row['size'] = observed.st_size
    except OSError as exc:
        row['read_error'] = type(exc).__name__
    return row


def _child(spec: SupervisedSpec) -> int:
    live, contract = preflight(spec)
    model_cwd = spec.output_dir / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    _plain_private_dir(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('development model cwd is not empty')
    checkpoint = spec.output_dir / LEDGER_NAME
    ledger = live.LiveHPLedger(started_at=time.time(),
        policy=asdict(contract.policy), contract_sha256=spec.contract_sha256,
        checkpoint_path=str(checkpoint))
    app = live.LiveHPAppServer(ledger=ledger, contract=contract, cwd=model_cwd,
                              event_log_path=spec.output_dir / 'events.jsonl')
    provider = live.LiveHPProvider(ledger, app)
    try:
        rows = asyncio.run(live.run_sequence_live_dev(
            contract.phase1_run, provider, ledger, contract.target_repository,
            checkpoint, contract_path=spec.contract_path,
            contract_sha256=spec.contract_sha256,
            scan_options=spec.scan_options))
        _write_once(spec.output_dir / CHILD_NAME, {
            'status': 'CHILD_RETURNED', 'scope': 'PUBLIC_TOY_DEVELOPMENT_ONLY',
            'rows': rows, 'physical': ledger.physical,
            'logical': ledger.logical, 'ledger': _evidence_file(checkpoint)})
        return 0
    except BaseException as exc:
        # The physical-attempt checkpoint is not rewritten or discarded.
        try:
            _write_once(spec.output_dir / CHILD_NAME, {
                'status': 'CHILD_ERROR', 'error_type': type(exc).__name__,
                'error': str(exc)[:1024], 'physical': ledger.physical,
                'logical': ledger.logical, 'ledger': _evidence_file(checkpoint)})
        except BaseException:
            pass
        raise


def supervise_command(command: list[str], output: Path, *, wall_seconds: float,
                      runner: Any = None,
                      provenance: dict[str, str] | None = None,
                      expected_output_identity: tuple[int, int] | None = None
                      ) -> dict[str, Any]:
    """Run one command under Blind 2's subreaper, retaining primary failures.

    This helper is also used by no-model synthetic regression commands.
    """
    if not 0 < wall_seconds <= 86400:
        raise ValueError('development physical wall limit invalid')
    if provenance is not None and (
            set(provenance) != {'spec_sha256', 'contract_sha256',
                                'product_source_sha256',
                                'evaluation_source_sha256'} or
            any(not isinstance(value, str) or not HEX.fullmatch(value)
                for value in provenance.values())):
        raise ValueError('development supervisor provenance incomplete')
    dirfd = _open_private_dir_fd(output)
    try:
        if expected_output_identity is not None:
            held_before = os.fstat(dirfd)
            if ((held_before.st_dev, held_before.st_ino) !=
                    expected_output_identity or
                    not _path_matches_dir_fd(output, dirfd)):
                raise ValueError('development output directory identity changed before launch')
        try:
            os.stat(RESULT_NAME, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('development supervised result already exists')
        if runner is None:
            # The live caller has already authenticated every evaluation file.
            if str(HERE) not in sys.path:
                sys.path.insert(0, str(HERE))
            import blind2_runner_draft as runner
            if Path(runner.__file__).resolve() != HERE / 'blind2_runner_draft.py':
                raise ValueError('development supervisor helper origin changed')
        started = time.monotonic()
        reason, return_code, cleanup_ok = 'CHILD_EXITED', None, True
        status_read = None
        child = None
        original: BaseException | None = None
        cleanup_error: str | None = None
        try:
            logfd = os.open('supervisor.log', os.O_CREAT | os.O_EXCL |
                            os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=dirfd)
            with os.fdopen(logfd, 'wb') as log:
                child, status_read = runner._launch_guarded(
                    command, stdout=log, stderr=subprocess.STDOUT,
                    env={**os.environ, 'PYTHONUNBUFFERED': '1'})
                try:
                    child.wait(timeout=wall_seconds)
                    return_code = runner._guarded_return_code(child, status_read)
                    if return_code == -32768:
                        reason, cleanup_ok = 'CHILD_ERROR', False
                except subprocess.TimeoutExpired:
                    reason = 'STOPPED_WALL_LIMIT'
                    try:
                        cleanup_ok = runner._request_guard_cleanup(child, status_read)
                    except BaseException as exc:
                        cleanup_ok = False
                        cleanup_error = type(exc).__name__
                except BaseException as exc:
                    original = exc
                    reason = type(exc).__name__
                    try:
                        cleanup_ok = runner._request_guard_cleanup(child, status_read)
                    except BaseException as cleanup:
                        cleanup_ok = False
                        cleanup_error = type(cleanup).__name__
        except BaseException as exc:
            if original is None:
                original = exc
            if child is not None and status_read is not None and child.poll() is None:
                try:
                    cleanup_ok = runner._request_guard_cleanup(child, status_read)
                except BaseException as cleanup:
                    cleanup_ok = False
                    cleanup_error = type(cleanup).__name__
        finally:
            if child is not None:
                try:
                    runner._kill_process_group(child.pid)
                except BaseException:
                    cleanup_ok = False
            if status_read is not None:
                try:
                    os.close(status_read)
                except OSError as exc:
                    cleanup_ok = False
                    cleanup_error = type(exc).__name__
        elapsed = time.monotonic() - started
        output_changed = not _path_matches_dir_fd(output, dirfd)
        status = ('STOPPED_CLEANUP_INCOMPLETE' if not cleanup_ok else
                  'STOPPED_OUTPUT_PATH_CHANGED' if output_changed else
                  reason if reason != 'CHILD_EXITED' else
                  'CHILD_EXITED_INCONCLUSIVE' if return_code == 0 else
                  'CHILD_ERROR')
        held = os.fstat(dirfd)
        row = {
            'status': status, 'original_stop_reason': reason,
            'scope': 'PUBLIC_TOY_DEVELOPMENT_ONLY', 'wall_seconds': wall_seconds,
            'elapsed_seconds': elapsed, 'return_code': return_code,
            'cleanup_incomplete': not cleanup_ok,
            'output_path_changed': output_changed,
            'output_dir_device': held.st_dev,
            'output_dir_inode': held.st_ino,
            'child_result': _evidence_file_at(dirfd, output, CHILD_NAME),
            'physical_attempt_ledger': _evidence_file_at(dirfd, output,
                                                        LEDGER_NAME),
            'supervisor_log': _evidence_file_at(dirfd, output,
                                               'supervisor.log'),
            'model_event_log': _evidence_file_at(dirfd, output, 'events.jsonl'),
        }
        if provenance is None:
            row['provenance_status'] = 'UNBOUND_SYNTHETIC'
        else:
            row.update(provenance)
        if original is not None:
            row['primary_error_type'] = type(original).__name__
        if cleanup_error is not None:
            row['cleanup_error_type'] = cleanup_error
        try:
            _write_once_at(dirfd, RESULT_NAME, row)
        except BaseException:
            if original is None:
                raise
        if original is not None:
            raise original
        return row
    finally:
        os.close(dirfd)


def run_supervised(spec_path: Path, expected_sha256: str) -> dict[str, Any]:
    if not sys.flags.isolated:
        raise ValueError('development supervisor requires Python -I')
    _require_external_bootstrap()
    spec = load_spec(spec_path, expected_sha256)
    # The parent does not import the live pipeline before the physical guard.
    # Its cheap raw-policy check must still agree with the child's exact
    # LiveHPPolicy validation before any model turn.
    contract_row = json.loads(spec.contract_path.read_text())
    if (not isinstance(contract_row, dict) or
            not isinstance(contract_row.get('limits'), dict) or
            contract_row['limits'].get('wall_seconds') != SUPERVISED_WALL_SECONDS):
        raise ValueError('development supervisor wall differs from contract')
    script = Path(__file__).resolve()
    # This child executes exactly the entrypoint bytes already pinned by the
    # parent. Its own load_spec/preflight then run inside the wall supervisor.
    command = [sys.executable, '-I', '-B', '-c', BOOTSTRAP_CODE,
               str(script), spec.evaluation_sha256[script.name],
               '--child', str(spec_path), expected_sha256]
    provenance = {
        'spec_sha256': expected_sha256,
        'contract_sha256': spec.contract_sha256,
        'product_source_sha256': spec.product_source_sha256,
        'evaluation_source_sha256': hashlib.sha256(json.dumps(
            spec.evaluation_sha256, sort_keys=True).encode()).hexdigest(),
    }
    row = supervise_command(command, spec.output_dir,
                            wall_seconds=SUPERVISED_WALL_SECONDS,
                            provenance=provenance,
                            expected_output_identity=(spec.output_dir_device,
                                                      spec.output_dir_inode))
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--supervise', action='store_true')
    group.add_argument('--child', action='store_true')
    group.add_argument('--preflight-only', action='store_true')
    parser.add_argument('spec', type=Path)
    parser.add_argument('sha256')
    args = parser.parse_args(argv)
    if not sys.flags.isolated:
        raise ValueError('development HP CLI requires Python -I')
    _fresh_private_pycache()
    _require_external_bootstrap()
    spec = load_spec(args.spec, args.sha256)
    if args.preflight_only:
        preflight(spec)
        print(json.dumps({'status': 'PREFLIGHT_PASS',
                          'scope': 'PUBLIC_TOY_DEVELOPMENT_ONLY',
                          'private_fresh_pycache': True}))
        return 0
    if args.child:
        return _child(spec)
    result = run_supervised(args.spec, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_INCONCLUSIVE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
