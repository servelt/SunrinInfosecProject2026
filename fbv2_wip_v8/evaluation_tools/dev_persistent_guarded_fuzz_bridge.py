"""Development-only durable cap around guarded Global, SP, and HP commands.

The persisted reservation is written before ``DevGuardedPhysicalFuzzGroup``
launches a child. That group supplies the existing subreaper cleanup receipt
and physical wall measurement. This accepts external commands only. Product
``fuzz_locally`` calls and the frozen runner are not connected to this module.
The same-UID checkpoint rollback and copied-ledger fork limitations of
``PersistentPhysicalFuzzLedger`` also apply here.

Pinned and legacy calls cannot overlap on one bridge instance. Legacy-only
jobs may still run concurrently and have physical ledger rows without pinned
receipts. Cross-process coordination of receipt admission is not provided.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import threading
import time
from typing import Any
from uuid import uuid4

from dev_global_physical_cap import DevGuardedPhysicalFuzzGroup
from dev_persistent_physical_fuzz_ledger import (
    PersistentPhysicalFuzzLedger, PhysicalBudgetExhausted)


def _cleanup_envelope(value: float) -> float:
    if (type(value) not in (int, float) or not math.isfinite(value) or
            value < 12.5):
        raise ValueError('cleanup envelope must cover guarded 7+5s wait')
    return float(value)


PINNED_RECEIPT_KIND = 'DEV_PINNED_PHYSICAL_FUZZ_RECEIPT_V1'


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def _plain_path(path: Path, *, directory: bool) -> Path:
    path = Path(path)
    if (not path.is_absolute() or '..' in path.parts or
            any(part.is_symlink() for part in (path, *path.parents))):
        raise ValueError('pinned binary or corpus path is missing, linked, or not canonical')
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(
            'pinned binary or corpus path is missing, linked, or not canonical') from exc
    if (resolved != path or
            not (path.is_dir() if directory else path.is_file())):
        raise ValueError('pinned binary or corpus path is missing, linked, or not canonical')
    return path


def _file_digest(path: Path) -> tuple[str, int]:
    """Hash a plain file through one fd and reject changes during that read."""
    if path.is_symlink():
        raise ValueError('pinned input is a symlink')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('pinned input must be a single-link regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns)):
            raise ValueError('pinned input changed while it was hashed')
        return digest, before.st_size
    finally:
        os.close(fd)


def _corpus_files(corpus: Path) -> list[dict[str, Any]]:
    corpus = _plain_path(corpus, directory=True)
    rows: list[dict[str, Any]] = []
    def walk_error(exc: OSError) -> None:
        raise exc

    for base, directories, files in os.walk(corpus, followlinks=False,
                                            onerror=walk_error):
        current = Path(base)
        _plain_path(current, directory=True)
        for name in sorted(directories):
            _plain_path(current / name, directory=True)
        for name in sorted(files):
            path = _plain_path(current / name, directory=False)
            digest, size = _file_digest(path)
            rows.append({'path': path.relative_to(corpus).as_posix(),
                         'sha256': digest, 'size': size})
            if len(rows) > 10000:
                raise ValueError('pinned corpus exceeds 10000 files')
    return sorted(rows, key=lambda row: row['path'])


def _receipt_file(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError('pinned receipt became a symlink')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('pinned receipt ownership or mode changed')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for key, value in pairs:
        if key in row:
            raise ValueError('duplicate pinned receipt JSON key')
        row[key] = value
    return row


def _corpus_manifest_consistent(files: Any, sha256: Any) -> bool:
    if type(files) is not list or len(files) > 10000 or not isinstance(sha256, str):
        return False
    names: list[str] = []
    for row in files:
        if type(row) is not dict or set(row) != {'path', 'sha256', 'size'}:
            return False
        name = row['path']
        if (type(name) is not str or not name or
                PurePosixPath(name).is_absolute() or
                '..' in PurePosixPath(name).parts or
                type(row['size']) is not int or row['size'] < 0 or
                type(row['sha256']) is not str or
                not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
            return False
        names.append(name)
    return names == sorted(set(names)) and _digest(_json_bytes(files)) == sha256


def _restored_receipt_consistent(row: Any, filename: str,
                                 finished: list[dict[str, Any]]) -> bool:
    if type(row) is not dict or row.get('kind') != PINNED_RECEIPT_KIND:
        return False
    job_id = row.get('logical_job_id')
    role = row.get('role')
    argv = row.get('argv')
    binary_sha256 = row.get('binary_sha256')
    if (type(job_id) is not str or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}', job_id) or
            filename != _digest(job_id.encode()) + '.json' or
            role not in {'GLOBAL', 'SP', 'HP'} or
            type(argv) is not list or not argv or
            any(type(arg) is not str or not arg for arg in argv) or
            argv[0] != row.get('binary') or row.get('corpus') not in argv or
            type(binary_sha256) is not str or
            not re.fullmatch(r'[0-9a-f]{64}', binary_sha256) or
            _digest(json.dumps(argv, ensure_ascii=False,
                               separators=(',', ':')).encode()) !=
            row.get('argv_sha256') or
            not _corpus_manifest_consistent(row.get('pre_corpus_files'),
                                            row.get('pre_corpus_sha256'))):
        return False
    if row.get('status') == 'PENDING_SHARED_PHYSICAL_BUDGET':
        return (row.get('persistent_key') is None and
                row.get('ledger_finished_row') is None and
                row.get('post_corpus_files') is None)
    if row.get('status') != 'FINISHED':
        return False
    charged = row.get('ledger_finished_row')
    return (type(charged) is dict and charged in finished and
            row.get('persistent_key') == charged.get('key') and
            role == charged.get('kind') and
            row.get('cleanup_complete') is True and
            row.get('post_binary_sha256') == binary_sha256 and
            _corpus_manifest_consistent(row.get('post_corpus_files'),
                                        row.get('post_corpus_sha256')))


class PersistentGuardedFuzzBridge:
    """One owner and many threads; every guarded process has a durable claim."""

    def __init__(self, output: Path, ledger: PersistentPhysicalFuzzLedger, *,
                 cleanup_envelope_seconds: float):
        self.output = Path(output)
        self.ledger = ledger
        self.cleanup_envelope_seconds = _cleanup_envelope(cleanup_envelope_seconds)
        self._pinned_tainted = False
        self._pinned_lock = threading.Lock()
        self._mode_lock = threading.Lock()
        self._pinned_active = False
        self._legacy_active = 0
        self._receipt_dir = self.output / 'PINNED_FUZZ_RECEIPTS'
        if self._receipt_dir.exists() or self._receipt_dir.is_symlink():
            self._check_receipt_dir()
            try:
                finished = ledger.snapshot()['finished']
                for entry in self._receipt_dir.iterdir():
                    row = json.loads(_receipt_file(entry),
                                     object_pairs_hook=_unique_pairs)
                    if not _restored_receipt_consistent(row, entry.name, finished):
                        self._pinned_tainted = True
                        break
            except (OSError, ValueError, TypeError, AttributeError):
                self._pinned_tainted = True
        session = self.output / ('guarded_jobs_' + uuid4().hex)
        session.mkdir(mode=0o700)
        self.command_group = DevGuardedPhysicalFuzzGroup(
            session, total_seconds=ledger.snapshot()['total_seconds'],
            cleanup_envelope_seconds=cleanup_envelope_seconds)

    @classmethod
    def create(cls, output: Path, *, total_seconds: float,
               cleanup_envelope_seconds: float = 12.5) -> 'PersistentGuardedFuzzBridge':
        output = Path(output)
        _cleanup_envelope(cleanup_envelope_seconds)
        ledger = PersistentPhysicalFuzzLedger.create(
            output / 'DEV_PERSISTENT_PHYSICAL_FUZZ_LEDGER.json',
            total_seconds=total_seconds)
        return cls(output, ledger,
                   cleanup_envelope_seconds=cleanup_envelope_seconds)

    @classmethod
    def restore(cls, output: Path, *, total_seconds: float,
                cleanup_envelope_seconds: float = 12.5) -> 'PersistentGuardedFuzzBridge':
        output = Path(output)
        _cleanup_envelope(cleanup_envelope_seconds)
        ledger = PersistentPhysicalFuzzLedger.restore(
            output / 'DEV_PERSISTENT_PHYSICAL_FUZZ_LEDGER.json',
            total_seconds=total_seconds)
        return cls(output, ledger,
                   cleanup_envelope_seconds=cleanup_envelope_seconds)

    def snapshot(self) -> dict[str, Any]:
        return self.ledger.snapshot()

    def _check_receipt_dir(self) -> None:
        directory = _plain_path(self._receipt_dir, directory=True)
        info = directory.stat()
        if (info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('pinned receipt directory must be owned mode 0700')

    def _receipt_path(self, job_id: str) -> Path:
        return self._receipt_dir / (_digest(job_id.encode()) + '.json')

    def _new_receipt(self, path: Path, row: dict[str, Any]) -> bytes:
        if not self._receipt_dir.exists():
            self._receipt_dir.mkdir(mode=0o700, exist_ok=True)
            _fsync_dir(self.output)
        self._check_receipt_dir()
        payload = _json_bytes(row)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(self._receipt_dir)
        return payload

    def _update_receipt(self, path: Path, prior: bytes,
                        row: dict[str, Any]) -> bytes:
        self._check_receipt_dir()
        if _receipt_file(path) != prior:
            raise ValueError('pinned receipt changed outside owner')
        payload = _json_bytes(row)
        temporary = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(fd)
            if _receipt_file(path) != prior:
                raise ValueError('pinned receipt changed during update')
            os.replace(temporary, path)
            _fsync_dir(self._receipt_dir)
        finally:
            os.close(fd)
            temporary.unlink(missing_ok=True)
        return payload

    def run_pinned(self, kind: str, command: list[str], *,
                   requested_seconds: float, job_id: str, binary: Path,
                   expected_binary_sha256: str, corpus: Path,
                   expected_argv_sha256: str) -> dict[str, Any]:
        """Serialize receipt admission so an audit stop blocks later launches."""
        if not self._pinned_lock.acquire(blocking=False):
            raise ValueError('concurrent pinned jobs are not admitted')
        try:
            with self._mode_lock:
                if self._legacy_active:
                    raise ValueError('pinned and legacy guarded jobs may not overlap')
                self._pinned_active = True
            try:
                return self._run_pinned_locked(
                    kind, command, requested_seconds=requested_seconds,
                    job_id=job_id, binary=binary,
                    expected_binary_sha256=expected_binary_sha256,
                    corpus=corpus, expected_argv_sha256=expected_argv_sha256)
            finally:
                with self._mode_lock:
                    self._pinned_active = False
        finally:
            self._pinned_lock.release()

    def _run_pinned_locked(self, kind: str, command: list[str], *,
                           requested_seconds: float, job_id: str, binary: Path,
                           expected_binary_sha256: str, corpus: Path,
                           expected_argv_sha256: str) -> dict[str, Any]:
        """Opt-in pinned development job, with a durable prechild receipt.

        This binds one external command to one logical job and a corpus below
        the private output root. Expected binary and argv hashes come from the
        caller; this does not prove formal Freeze identity or that the child
        actually consumed the corpus. FINISHED means physical accounting
        settled, not that the child succeeded: consumers must inspect
        result_status. A PENDING budget receipt is a final record for that
        logical ID, not a resumable queue item. The bridge does not authorize
        Blind 3, prevent a same-UID adversary from racing exec, or detect
        rollback of both receipt and physical ledger checkpoints.
        """
        if self._pinned_tainted:
            raise ValueError('pinned receipt state is incomplete or tainted')
        if (kind not in {'GLOBAL', 'SP', 'HP'} or
                type(job_id) is not str or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}', job_id) or
                not isinstance(command, list) or not command or
                any(type(arg) is not str or not arg for arg in command) or
                type(requested_seconds) not in (int, float) or
                not math.isfinite(requested_seconds) or requested_seconds <= 0 or
                any(type(value) is not str or
                    not re.fullmatch(r'[0-9a-f]{64}', value)
                    for value in (expected_binary_sha256, expected_argv_sha256))):
            raise ValueError('invalid pinned development fuzz job')
        binary = _plain_path(binary, directory=False)
        corpus = _plain_path(corpus, directory=True)
        if not corpus.is_relative_to(self.output):
            raise ValueError('pinned corpus must remain below private output root')
        frozen_command = list(command)
        if frozen_command[0] != str(binary) or str(corpus) not in frozen_command:
            raise ValueError('pinned binary or corpus is absent from exact argv')
        argv_sha256 = _digest(json.dumps(
            frozen_command, ensure_ascii=False, separators=(',', ':')).encode())
        binary_sha256, binary_size = _file_digest(binary)
        if (binary_sha256 != expected_binary_sha256 or
                argv_sha256 != expected_argv_sha256):
            raise ValueError('pinned binary or argv differs from expected digest')
        pre_corpus_files = _corpus_files(corpus)
        path = self._receipt_path(job_id)
        row: dict[str, Any] = {
            'kind': PINNED_RECEIPT_KIND, 'status': 'PREPARED',
            'logical_job_id': job_id, 'role': kind,
            'binary': str(binary), 'binary_sha256': binary_sha256,
            'binary_size': binary_size, 'argv': frozen_command,
            'argv_sha256': argv_sha256, 'corpus': str(corpus),
            'pre_corpus_files': pre_corpus_files,
            'pre_corpus_sha256': _digest(_json_bytes(pre_corpus_files)),
            'requested_seconds': float(requested_seconds),
            'assurance_scope': 'NO_SAME_UID_RACE_OR_ROLLBACK_GUARANTEE',
            'persistent_key': None, 'ledger_revision_before_child': None,
            'ledger_sha256_before_child': None,
            'ledger_finished_row': None, 'cleanup_complete': None,
            'ledger_stop_status': None, 'observed_bridge_wall_seconds': None,
            'post_binary_sha256': None,
            'post_corpus_files': None, 'post_corpus_sha256': None,
            'result_status': None,
        }
        try:
            prior = self._new_receipt(path, row)
        except BaseException:
            self._pinned_tainted = True
            raise
        key = f'{kind}:{uuid4().hex}'
        envelope = float(requested_seconds) + self.cleanup_envelope_seconds
        try:
            self.ledger.reserve(key, kind, envelope)
        except PhysicalBudgetExhausted:
            row['status'] = 'PENDING_SHARED_PHYSICAL_BUDGET'
            try:
                self._update_receipt(path, prior, row)
            except BaseException:
                self._pinned_tainted = True
                raise
            return {'kind': kind, 'status': row['status'],
                    'persistent_key': None, 'physical_seconds': 0.0,
                    'cleanup_complete': True, 'pinned_receipt': str(path)}
        except BaseException as exc:
            row['status'] = 'STOPPED_PRELAUNCH_LEDGER'
            row['result_status'] = type(exc).__name__
            self._pinned_tainted = True
            try:
                self._update_receipt(path, prior, row)
            except BaseException as audit_exc:
                exc.add_note('pinned receipt update failed: ' + type(audit_exc).__name__)
            raise
        row['persistent_key'] = key
        try:
            ledger_bytes = _receipt_file(self.ledger.path)
            ledger_state = json.loads(ledger_bytes)
            if key not in ledger_state['active']:
                raise ValueError('persistent reservation disappeared before child')
            row['ledger_revision_before_child'] = ledger_state['revision']
            row['ledger_sha256_before_child'] = _digest(ledger_bytes)
            row['status'] = 'RESERVED_PRELAUNCH'
            prior = self._update_receipt(path, prior, row)
            rehash, resize = _file_digest(binary)
            if (rehash != binary_sha256 or resize != binary_size or
                    _corpus_files(corpus) != pre_corpus_files or
                    _digest(json.dumps(frozen_command, ensure_ascii=False,
                                       separators=(',', ':')).encode()) != argv_sha256):
                raise ValueError('pinned inputs changed before child launch')
            if _receipt_file(path) != prior:
                raise ValueError('pinned receipt changed before child launch')
        except BaseException as exc:
            self._pinned_tainted = True
            try:
                charged = self.ledger.finish(key, physical_seconds=0.0,
                                             cleanup_complete=True)
                row['ledger_finished_row'] = charged
                row['cleanup_complete'] = True
            except BaseException as audit_exc:
                exc.add_note('prelaunch physical release failed: ' +
                             type(audit_exc).__name__)
            row['status'] = 'STOPPED_PRELAUNCH_PIN'
            row['result_status'] = type(exc).__name__
            try:
                self._update_receipt(path, prior, row)
            except BaseException as audit_exc:
                exc.add_note('pinned receipt update failed: ' + type(audit_exc).__name__)
            raise
        started = time.monotonic()
        original_error: BaseException | None = None
        result: dict[str, Any] | None = None
        try:
            result = self.command_group.run(
                kind, frozen_command, requested_seconds=requested_seconds)
        except BaseException as exc:
            original_error = exc
        elapsed = max(0.0, time.monotonic() - started)
        valid = (isinstance(result, dict) and
                 type(result.get('status')) is str and
                 type(result.get('physical_seconds')) in (int, float) and
                 math.isfinite(result['physical_seconds']) and
                 result['physical_seconds'] >= 0 and
                 type(result.get('cleanup_complete')) is bool)
        cleanup_complete = (original_error is None and valid and
                            result['cleanup_complete'] and
                            result.get('status') != 'PENDING_SHARED_PHYSICAL_BUDGET')
        row['observed_bridge_wall_seconds'] = elapsed
        try:
            charged = self.ledger.finish(
                key, physical_seconds=max(float(result['physical_seconds']), elapsed)
                if valid else elapsed, cleanup_complete=cleanup_complete)
        except BaseException as exc:
            self._pinned_tainted = True
            if original_error is not None:
                original_error.add_note('physical settlement failed: ' + type(exc).__name__)
                raise original_error
            raise
        try:
            state = self.ledger.snapshot()
        except BaseException:
            self._pinned_tainted = True
            raise
        finished = [item for item in state['finished'] if item['key'] == key]
        if len(finished) != 1 or finished[0] != charged:
            self._pinned_tainted = True
            raise ValueError('persistent finished row differs from charged job')
        row['ledger_finished_row'] = charged
        row['cleanup_complete'] = cleanup_complete
        row['ledger_stop_status'] = state['stop_status']
        row['result_status'] = (result.get('status') if valid else
                                type(original_error).__name__ if original_error else
                                'INVALID_GUARD_RECEIPT')
        try:
            post_binary_sha256, _ = _file_digest(binary)
            if post_binary_sha256 != binary_sha256:
                raise ValueError('pinned binary changed during guarded job')
            row['post_binary_sha256'] = post_binary_sha256
            post = _corpus_files(corpus)
            row['post_corpus_files'] = post
            row['post_corpus_sha256'] = _digest(_json_bytes(post))
        except BaseException as exc:
            self._pinned_tainted = True
            row['status'] = 'STOPPED_POST_CORPUS_UNTRUSTED'
            try:
                self._update_receipt(path, prior, row)
            except BaseException as audit_exc:
                exc.add_note('pinned receipt update failed: ' + type(audit_exc).__name__)
            if original_error is not None:
                original_error.add_note('post-corpus pin failed: ' + type(exc).__name__)
                raise original_error
            raise
        record = {**result, 'persistent_key': key,
                  'persistent_charge': charged,
                  'persistent_stop_status': state['stop_status']} if valid else None
        if not cleanup_complete:
            row['status'] = 'STOPPED_CLEANUP_INCOMPLETE'
            if record is not None:
                record['status'] = row['status']
        elif charged['overrun']:
            row['status'] = 'STOPPED_PHYSICAL_CAP_UNPROVEN'
            if record is not None:
                record['status'] = row['status']
        else:
            row['status'] = 'FINISHED'
        try:
            final_bytes = self._update_receipt(path, prior, row)
        except BaseException as exc:
            self._pinned_tainted = True
            if original_error is not None:
                original_error.add_note('pinned receipt update failed: ' + type(exc).__name__)
                raise original_error
            raise
        if original_error is not None:
            raise original_error
        if not valid:
            raise ValueError('guarded process returned no trustworthy cleanup receipt')
        record['pinned_receipt'] = str(path)
        record['pinned_receipt_sha256'] = _digest(final_bytes)
        return record

    def run(self, kind: str, command: list[str], *,
            requested_seconds: float) -> dict[str, Any]:
        with self._mode_lock:
            if self._pinned_active:
                raise ValueError('pinned and legacy guarded jobs may not overlap')
            if self._pinned_tainted:
                raise ValueError('pinned receipt state is incomplete or tainted')
            self._legacy_active += 1
        try:
            return self._run_legacy(kind, command,
                                    requested_seconds=requested_seconds)
        finally:
            with self._mode_lock:
                self._legacy_active -= 1

    def _run_legacy(self, kind: str, command: list[str], *,
                    requested_seconds: float) -> dict[str, Any]:
        if (kind not in {'GLOBAL', 'SP', 'HP'} or
                not isinstance(command, list) or not command or
                any(not isinstance(arg, str) or not arg for arg in command) or
                type(requested_seconds) not in (int, float) or
                not math.isfinite(requested_seconds) or requested_seconds <= 0):
            raise ValueError('invalid guarded development fuzz job')
        envelope = float(requested_seconds) + self.cleanup_envelope_seconds
        key = f'{kind}:{uuid4().hex}'
        try:
            self.ledger.reserve(key, kind, envelope)
        except PhysicalBudgetExhausted:
            return {'kind': kind, 'status': 'PENDING_SHARED_PHYSICAL_BUDGET',
                    'persistent_key': None, 'physical_seconds': 0.0,
                    'cleanup_complete': True}
        started = time.monotonic()
        try:
            result = self.command_group.run(
                kind, command, requested_seconds=requested_seconds)
        except BaseException as exc:
            # The inner guard may have launched before raising. No successful
            # cleanup receipt exists, so stop this ledger rather than refund.
            try:
                self.ledger.finish(
                    key, physical_seconds=max(0.0, time.monotonic() - started),
                    cleanup_complete=False)
            except BaseException as audit_exc:
                exc.add_note(f'physical ledger stop failed: {type(audit_exc).__name__}')
            raise
        if (not isinstance(result, dict) or
                type(result.get('physical_seconds')) not in (int, float) or
                not math.isfinite(result['physical_seconds']) or
                result['physical_seconds'] < 0 or
                type(result.get('cleanup_complete')) is not bool):
            self.ledger.finish(
                key, physical_seconds=max(0.0, time.monotonic() - started),
                cleanup_complete=False)
            raise ValueError('guarded process returned no trustworthy cleanup receipt')
        cleanup_complete = (result['cleanup_complete'] and
                            result.get('status') != 'PENDING_SHARED_PHYSICAL_BUDGET')
        charged = self.ledger.finish(
            key, physical_seconds=float(result['physical_seconds']),
            cleanup_complete=cleanup_complete)
        record = {**result, 'persistent_key': key,
                  'persistent_charge': charged,
                  'persistent_stop_status': self.ledger.snapshot()['stop_status']}
        if not cleanup_complete:
            record['status'] = 'STOPPED_CLEANUP_INCOMPLETE'
        elif charged['overrun']:
            record['status'] = 'STOPPED_PHYSICAL_CAP_UNPROVEN'
        return record
