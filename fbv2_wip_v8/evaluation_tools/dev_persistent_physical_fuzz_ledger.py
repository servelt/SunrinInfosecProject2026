"""Development-only durable reservations for physical fuzz process time.

This is an evaluator component, not a product or Blind 3 runner. A single
supervisor owns one ledger instance and calls ``reserve`` before launching a
guarded process, reserving requested wall time plus its cleanup envelope.
The supervisor supplies measured physical wall time to ``finish`` only after
descendant cleanup. If a process dies with an active reservation, restore
permanently stops admission. This ledger cannot itself prove the measurement
or cleanup or resist a writer with the same UID; those require the guarded
executor and an external freeze/hash authority. No product fuzzer uses it yet.
"""

from __future__ import annotations

import asyncio
import copy
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import stat
import threading
from typing import Any
from uuid import uuid4


KIND = 'DEV_PERSISTENT_PHYSICAL_FUZZ_LEDGER_V1'
KINDS = frozenset({'GLOBAL', 'SP', 'HP'})
STOPPED = frozenset({
    'STOPPED_UNCERTAIN_PROCESS', 'STOPPED_PHYSICAL_CAP_UNPROVEN',
    'STOPPED_CLEANUP_INCOMPLETE',
})


class PhysicalBudgetExhausted(ValueError):
    """Only insufficient reserved seconds; never an audit-integrity error."""


class PhysicalModelStartBlocked(asyncio.CancelledError):
    """Terminal physical STOP; product HP must not normalize it as an error.

    Cancellation ancestry also makes the product App Server close its process
    before propagating this development-only stop to the supervisor.
    """

    def __init__(self, status: str):
        super().__init__(f'physical model start blocked: {status}')
        self.status = status


FIELDS = frozenset({
    'kind', 'total_seconds', 'spent_seconds', 'active', 'finished',
    'stop_status', 'revision',
})


def _number(value: Any, *, positive: bool = False) -> float:
    if (type(value) not in (int, float) or not math.isfinite(value) or
            value < 0 or positive and value == 0):
        raise ValueError('invalid physical seconds')
    return float(value)


def _plain_parent(path: Path) -> Path:
    path = Path(path)
    if (not path.is_absolute() or '..' in path.parts or
            path.resolve(strict=False) != path):
        raise ValueError('physical ledger path must be absolute and canonical')
    parent = path.parent
    if (not parent.is_dir() or any(part.is_symlink() for part in
            (parent, *parent.parents)) or parent.resolve() != parent):
        raise ValueError('physical ledger directory is missing or linked')
    metadata = parent.stat()
    if (metadata.st_uid != os.getuid() or
            stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError('physical ledger directory must be owned mode 0700')
    return path


def _file_bytes(path: Path) -> bytes:
    path = _plain_parent(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('physical ledger is missing or linked')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        metadata = os.fstat(fd)
        # Two hardlink names could otherwise take different .lock files and
        # independently spend the same initial checkpoint.
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError('physical ledger must be a single-link owned mode 0600 file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate physical ledger JSON key')
        result[key] = value
    return result


def _validate(state: dict[str, Any]) -> None:
    if type(state) is not dict or set(state) != FIELDS or state['kind'] != KIND:
        raise ValueError('physical ledger schema changed')
    total = _number(state['total_seconds'], positive=True)
    spent = _number(state['spent_seconds'])
    active, finished = state['active'], state['finished']
    if (type(active) is not dict or type(finished) is not list or
            type(state['revision']) is not int or state['revision'] < 0 or
            state['stop_status'] is not None and state['stop_status'] not in STOPPED):
        raise ValueError('physical ledger state malformed')
    reserved = 0.0
    for key, row in active.items():
        if (type(key) is not str or not key or type(row) is not dict or
                set(row) != {'kind', 'reserved_seconds'} or
                row['kind'] not in KINDS):
            raise ValueError('physical reservation malformed')
        reserved += _number(row['reserved_seconds'], positive=True)
    keys: set[str] = set()
    measured: list[float] = []
    cumulative = 0.0
    any_overrun = False
    any_cleanup_failure = False
    for row in finished:
        if (type(row) is not dict or set(row) !=
                {'key', 'kind', 'reserved_seconds', 'physical_seconds',
                 'cleanup_complete', 'overrun'} or
                type(row['key']) is not str or not row['key'] or
                row['key'] in keys or row['key'] in active or
                row['kind'] not in KINDS or
                type(row['cleanup_complete']) is not bool or
                type(row['overrun']) is not bool):
            raise ValueError('physical completion record malformed')
        keys.add(row['key'])
        reservation = _number(row['reserved_seconds'], positive=True)
        physical = _number(row['physical_seconds'])
        measured.append(physical)
        cumulative = math.fsum(measured)
        expected_overrun = physical > reservation or cumulative > total
        if row['overrun'] != expected_overrun:
            raise ValueError('physical overrun evidence changed')
        any_overrun |= expected_overrun
        any_cleanup_failure |= not row['cleanup_complete']
    if not math.isclose(spent, math.fsum(measured), abs_tol=1e-9, rel_tol=0):
        raise ValueError('physical spent seconds differ from records')
    if (state['stop_status'] is None and
            (any_overrun or any_cleanup_failure or spent + reserved > total + 1e-9) or
            state['stop_status'] == 'STOPPED_PHYSICAL_CAP_UNPROVEN' and
            not any_overrun or
            state['stop_status'] == 'STOPPED_CLEANUP_INCOMPLETE' and
            not any_cleanup_failure or
            state['stop_status'] == 'STOPPED_UNCERTAIN_PROCESS' and not active):
        raise ValueError('physical stop status disagrees with evidence')


class PersistentPhysicalFuzzLedger:
    """Single-supervisor, thread-safe reservation ledger; no auto resume."""

    def __init__(self, path: Path, state: dict[str, Any]):
        self.path = path
        self.lock_path = path.with_name(path.name + '.lock')
        self._state = state
        self._lock = threading.RLock()
        self._owner_pid = os.getpid()
        self._tainted = False
        # Only reservations started by this live owner may be settled after
        # another concurrent job stops admission. Restored active work has
        # uncertain process state and cannot acquire ownership here.
        self._owned_active_keys: set[str] = set()

    @classmethod
    def create(cls, path: Path, *, total_seconds: float) -> 'PersistentPhysicalFuzzLedger':
        path = _plain_parent(path)
        total = _number(total_seconds, positive=True)
        lock_path = path.with_name(path.name + '.lock')
        if path.exists() or path.is_symlink() or lock_path.exists() or lock_path.is_symlink():
            raise FileExistsError(path)
        state = {'kind': KIND, 'total_seconds': total, 'spent_seconds': 0.0,
                 'active': {}, 'finished': [], 'stop_status': None,
                 'revision': 0}
        _validate(state)
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.close(lock_fd)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(cls._encode(state))
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        _file_bytes(path)
        lock_fd = cls._check_lock_file(lock_path)
        os.close(lock_fd)
        cls._sync_parent(path)
        return cls(path, state)

    @classmethod
    def restore(cls, path: Path, *, total_seconds: float) -> 'PersistentPhysicalFuzzLedger':
        path = _plain_parent(path)
        lock_fd = cls._check_lock_file(path.with_name(path.name + '.lock'))
        os.close(lock_fd)
        data = _file_bytes(path)
        state = json.loads(data, object_pairs_hook=_unique_pairs)
        _validate(state)
        if _number(total_seconds, positive=True) != state['total_seconds']:
            raise ValueError('physical budget contract changed')
        if data != cls._encode(state):
            raise ValueError('physical checkpoint is not canonical')
        ledger = cls(path, state)
        if state['active'] and state['stop_status'] is None:
            stopped = copy.deepcopy(state)
            stopped['stop_status'] = 'STOPPED_UNCERTAIN_PROCESS'
            stopped['revision'] += 1
            ledger._commit(stopped)
        return ledger

    @staticmethod
    def _encode(state: dict[str, Any]) -> bytes:
        return (json.dumps(state, sort_keys=True, separators=(',', ':'),
                           allow_nan=False) + '\n').encode('utf-8')

    @staticmethod
    def _sync_parent(path: Path) -> None:
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _check_lock_file(path: Path) -> int:
        path = _plain_parent(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError('physical lock is missing or linked')
        fd = os.open(path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            os.close(fd)
            raise ValueError('physical lock must be single-link owned mode 0600')
        return fd

    @contextmanager
    def _cross_process_lock(self):
        fd = self._check_lock_file(self.lock_path)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError('physical ledger has another active writer') from exc
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def _commit(self, state: dict[str, Any]) -> None:
        if self._tainted or os.getpid() != self._owner_pid:
            raise RuntimeError('physical ledger owner or audit state changed')
        _validate(state)
        with self._cross_process_lock():
            if _file_bytes(self.path) != self._encode(self._state):
                self._tainted = True
                raise RuntimeError('physical checkpoint changed outside owner')
            temp = self.path.with_name(self.path.name + '.' + uuid4().hex + '.tmp')
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, 'O_NOFOLLOW', 0), 0o600)
                try:
                    with os.fdopen(fd, 'wb', closefd=False) as stream:
                        stream.write(self._encode(state))
                        stream.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(temp, self.path)
                self._sync_parent(self.path)
            except BaseException:
                self._tainted = True
                temp.unlink(missing_ok=True)
                raise
        self._state = state

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = copy.deepcopy(self._state)
            result['reserved_seconds'] = math.fsum(
                row['reserved_seconds'] for row in result['active'].values())
            result['available_seconds'] = (result['total_seconds'] -
                                           result['spent_seconds'] -
                                           result['reserved_seconds'])
            return result

    def _verify_checkpoint_current(self) -> None:
        """Reject a stale or unreadable disk checkpoint before a no-write decision."""
        with self._lock:
            try:
                with self._cross_process_lock():
                    self._verify_checkpoint_current_locked()
            except BaseException:
                self._tainted = True
                raise

    def _verify_checkpoint_current_locked(self) -> None:
        """Verify the durable state while the local and cross-process locks are held."""
        if self._tainted or os.getpid() != self._owner_pid:
            raise RuntimeError('physical ledger owner or audit state changed')
        try:
            if _file_bytes(self.path) != self._encode(self._state):
                raise RuntimeError('physical checkpoint changed outside owner')
        except BaseException:
            self._tainted = True
            raise

    @contextmanager
    def model_start_guard(self):
        """Serialize a model start with physical reserve/finish commits.

        Callers must durably record the model's physical start before leaving
        this guard. Lock order is physical local lock, physical file lock, then
        any model-ledger lock. This is read-only for the physical checkpoint.
        """
        with self._lock:
            with self._cross_process_lock():
                self._verify_checkpoint_current_locked()
                if self._state['active']:
                    raise PhysicalModelStartBlocked('STOPPED_UNCERTAIN_PROCESS')
                if self._state['stop_status'] is not None:
                    raise PhysicalModelStartBlocked(self._state['stop_status'])
                yield

    def reserve(self, key: str, kind: str, reserved_seconds: float) -> None:
        reserved = _number(reserved_seconds, positive=True)
        with self._lock:
            # Even a request that cannot fit must not be reported as ordinary
            # budget exhaustion when the durable checkpoint is missing,
            # corrupted, or no longer owned. _commit repeats the CAS for a
            # request that does fit.
            self._verify_checkpoint_current()
            if self._state['stop_status'] is not None or self._tainted:
                raise RuntimeError('physical ledger stopped; no auto resume')
            if (type(key) is not str or not key or kind not in KINDS or
                    key in self._state['active'] or
                    any(row['key'] == key for row in self._state['finished'])):
                raise ValueError('physical reservation not eligible')
            if reserved > self.snapshot()['available_seconds']:
                raise PhysicalBudgetExhausted('physical reservation exceeds available seconds')
            state = copy.deepcopy(self._state)
            state['active'][key] = {'kind': kind, 'reserved_seconds': reserved}
            state['revision'] += 1
            try:
                self._commit(state)
            except BaseException:
                self._tainted = True
                raise
            self._owned_active_keys.add(key)

    def finish(self, key: str, *, physical_seconds: float,
               cleanup_complete: bool = True) -> dict[str, Any]:
        physical = _number(physical_seconds)
        if type(cleanup_complete) is not bool:
            raise ValueError('cleanup status must be boolean')
        with self._lock:
            if self._tainted or self._state['stop_status'] == 'STOPPED_UNCERTAIN_PROCESS':
                raise RuntimeError('physical ledger stopped; no auto resume')
            if (self._state['stop_status'] is not None and
                    key not in self._owned_active_keys):
                raise RuntimeError('physical active job owner is unproven')
            if key not in self._state['active']:
                raise ValueError('physical reservation not active')
            if key not in self._owned_active_keys:
                raise RuntimeError('physical active job owner is unproven')
            state = copy.deepcopy(self._state)
            active = state['active'].pop(key)
            state['spent_seconds'] = math.fsum(
                [row['physical_seconds'] for row in state['finished']] + [physical])
            overrun = (physical > active['reserved_seconds'] or
                       state['spent_seconds'] > state['total_seconds'])
            row = {'key': key, 'kind': active['kind'],
                   'reserved_seconds': active['reserved_seconds'],
                   'physical_seconds': physical,
                   'cleanup_complete': cleanup_complete, 'overrun': overrun}
            state['finished'].append(row)
            state['revision'] += 1
            if not cleanup_complete:
                state['stop_status'] = 'STOPPED_CLEANUP_INCOMPLETE'
            elif overrun and state['stop_status'] is None:
                state['stop_status'] = 'STOPPED_PHYSICAL_CAP_UNPROVEN'
            try:
                self._commit(state)
            except BaseException:
                self._tainted = True
                raise
            self._owned_active_keys.remove(key)
            return copy.deepcopy(row)
