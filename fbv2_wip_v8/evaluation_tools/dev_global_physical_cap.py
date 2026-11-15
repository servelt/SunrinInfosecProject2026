"""Development-only physical cap for concurrent guarded fuzz *commands*.

This boundary accepts external commands, not in-process Python fuzz callables.
It does not turn Global ON in a frozen runner or authorize Blind 3.
"""

from __future__ import annotations

import copy
import math
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Any

import blind2_runner_draft as runner
from dev_global_campaign import SharedPhysicalFuzzBudget, write_json


def _strict_guard_status(status_fd: int) -> int:
    """An absent subreaper receipt cannot certify descendant cleanup."""
    payload = os.read(status_fd, 64)
    if payload == b'CLEANUP_INCOMPLETE\n':
        return -32768
    if re.fullmatch(rb'-?\d+\n', payload):
        return int(payload)
    return -32768


class DevGuardedPhysicalFuzzGroup:
    """Reserve every active guard's requested wall plus bounded cleanup.

The shared cap is valid for complete-cleanup records only. An unproven
    cleanup or an envelope overrun taints the group and stops new admission.
    """

    def __init__(self, output: Path, *, total_seconds: float,
                 cleanup_envelope_seconds: float = 12.5):
        if (type(cleanup_envelope_seconds) not in (int, float) or
                not math.isfinite(cleanup_envelope_seconds) or
                cleanup_envelope_seconds < 12.5):
            raise ValueError('cleanup envelope must cover guarded 7+5s wait')
        self.output = Path(output)
        if (self.output.is_symlink() or not self.output.is_dir() or
                any(parent.is_symlink() for parent in self.output.parents)):
            raise ValueError('development physical-cap output must be a plain directory')
        self.budget = SharedPhysicalFuzzBudget(total_seconds)
        self.cleanup_envelope_seconds = float(cleanup_envelope_seconds)
        self._lock = threading.RLock()
        self._launch_lock = threading.Lock()
        self._serial = 0
        self._tainted = False
        self._stop_status: str | None = None
        self.results: list[dict[str, Any]] = []

    def _snapshot_locked(self) -> dict[str, Any]:
        budget = self.budget.snapshot()
        return {
            **budget,
            'status': self._stop_status or 'DEV_GUARDED_COMMAND_CAP_ACTIVE',
            'scope': 'DEV_EXTERNAL_COMMANDS_ONLY',
            'cleanup_envelope_seconds': self.cleanup_envelope_seconds,
            'parallel_physical_hard_cap_enforced': not self._tainted,
            'results': copy.deepcopy(self.results),
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._snapshot_locked())

    def _checkpoint_locked(self) -> None:
        write_json(self.output / 'DEV_SHARED_GUARDED_PHYSICAL_CAP.json',
                   self._snapshot_locked())

    def run(self, kind: str, command: list[str], *,
            requested_seconds: float) -> dict[str, Any]:
        if (kind not in {'GLOBAL', 'SP', 'HP'} or
                not isinstance(command, list) or not command or
                any(not isinstance(arg, str) or not arg for arg in command) or
                type(requested_seconds) not in (int, float) or
                not math.isfinite(requested_seconds) or requested_seconds <= 0):
            raise ValueError('invalid guarded development fuzz job')
        envelope = float(requested_seconds) + self.cleanup_envelope_seconds
        with self._lock:
            if self._tainted:
                return {'kind': kind, 'status': self._stop_status,
                        'cleanup_complete': False, 'physical_seconds': 0.0}
            self._serial += 1
            key = f'{kind}:{self._serial}'
            try:
                self.budget.reserve(key, envelope)
            except ValueError:
                result = {'key': key, 'kind': kind,
                          'status': 'PENDING_SHARED_PHYSICAL_BUDGET',
                          'cleanup_complete': True, 'physical_seconds': 0.0,
                          'requested_seconds': requested_seconds,
                          'reserved_seconds': 0.0}
                self.results.append(result)
                self._checkpoint_locked()
                return result
            try:
                self._checkpoint_locked()
            except BaseException:
                self.budget.reservations.pop(key, None)
                self._tainted = True
                self._stop_status = 'STOPPED_AUDIT_WRITE_FAILURE'
                raise

        started = time.monotonic()
        child = None
        status_fd = None
        timed_out = False
        cleanup_complete = True
        return_code = None
        error_type = None
        try:
            log_path = self.output / f'{key.replace(":", "_")}.log'
            with log_path.open('xb') as log:
                # The existing guard's preexec_fn is serialized at launch.
                with self._launch_lock:
                    child, status_fd = runner._launch_guarded(
                        command, stdout=log, stderr=subprocess.STDOUT)
                remaining = max(0.0, requested_seconds -
                                (time.monotonic() - started))
                try:
                    child.wait(timeout=remaining)
                    return_code = _strict_guard_status(status_fd)
                    cleanup_complete = return_code != -32768
                except subprocess.TimeoutExpired:
                    timed_out = True
                    cleanup_complete = runner._request_guard_cleanup(child, status_fd)
                except BaseException as exc:
                    error_type = type(exc).__name__
                    try:
                        cleanup_complete = runner._request_guard_cleanup(child, status_fd)
                    except BaseException:
                        cleanup_complete = False
        except BaseException as exc:
            error_type = error_type or type(exc).__name__
            if child is not None and status_fd is not None and child.poll() is None:
                try:
                    cleanup_complete = runner._request_guard_cleanup(child, status_fd)
                except BaseException:
                    cleanup_complete = False
        finally:
            if child is not None:
                try:
                    runner._kill_process_group(child.pid)
                except BaseException:
                    cleanup_complete = False
            if status_fd is not None:
                try:
                    os.close(status_fd)
                except OSError:
                    cleanup_complete = False
        physical = max(0.0, time.monotonic() - started)
        with self._lock:
            charge = self.budget.finish(key, physical)
            if not cleanup_complete:
                self._tainted = True
                status = 'STOPPED_CLEANUP_INCOMPLETE'
            elif charge['overrun'] or self.budget.available < 0:
                self._tainted = True
                status = 'STOPPED_PHYSICAL_CAP_UNPROVEN'
            else:
                status = ('STOPPED_JOB_WALL' if timed_out else
                          'COMPLETED' if return_code == 0 else
                          'CHILD_ERROR')
            if status in {'STOPPED_CLEANUP_INCOMPLETE',
                          'STOPPED_PHYSICAL_CAP_UNPROVEN'} and self._stop_status is None:
                self._stop_status = status
            result = {
                'key': key, 'kind': kind, 'status': status,
                'cleanup_complete': cleanup_complete,
                'timed_out': timed_out, 'return_code': return_code,
                'error_type': error_type,
                'requested_seconds': requested_seconds,
                'reserved_seconds': envelope,
                'physical_seconds': physical,
                'charge_overrun': charge['overrun'],
            }
            self.results.append(result)
            try:
                self._checkpoint_locked()
            except BaseException:
                self._tainted = True
                self._stop_status = 'STOPPED_AUDIT_WRITE_FAILURE'
                raise
            return result
