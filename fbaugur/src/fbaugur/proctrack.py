"""Child processes of one session, so that stopping or deleting it ends them.

The preparation of a scan (clone, prepare.sh, the preparation agent and its builds) runs inside the
web server's thread before any pipeline PID exists.  Stopping or deleting such a session used to end
nothing.  Every process the preparation starts goes through spawn()/run() here, in its own process
group, recorded under the session id; cancel() ends all of them and makes later spawns refuse.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Any

_lock = threading.Lock()
_groups: dict[str, set[int]] = {}
_cancelled: set[str] = set()


class Cancelled(RuntimeError):
    pass


def spawn(key: str | None, argv: list[str], **kwargs: Any) -> subprocess.Popen:
    if key and cancelled(key):
        raise Cancelled("stopped by the user")
    kwargs.setdefault("start_new_session", True)
    process = subprocess.Popen(argv, **kwargs)
    if key:
        with _lock:
            _groups.setdefault(key, set()).add(process.pid)
    return process


def forget(key: str | None, process: subprocess.Popen) -> None:
    if key:
        with _lock:
            _groups.get(key, set()).discard(process.pid)


def run(key: str | None, argv: list[str], *, timeout: float | None = None, input: str | None = None,
        **kwargs: Any) -> subprocess.CompletedProcess:
    """subprocess.run with the process group recorded and killed on timeout or cancel."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    if input is not None:
        kwargs["stdin"] = subprocess.PIPE
    process = spawn(key, argv, **kwargs)
    try:
        out, err = process.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(process.pid)
        out, err = process.communicate()
        forget(key, process)
        raise subprocess.TimeoutExpired(argv, timeout or 0, out, err)
    forget(key, process)
    if key and cancelled(key):
        raise Cancelled("stopped by the user")
    return subprocess.CompletedProcess(argv, process.returncode, out, err)


def kill_group(pid: int, grace: float = 5.0) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + grace
    while time.time() < deadline:
        try:
            os.killpg(pid, 0)
        except OSError:
            return
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def cancel(key: str) -> int:
    """End every recorded process group of `key`; returns how many were signalled."""
    with _lock:
        _cancelled.add(key)
        pids = list(_groups.pop(key, set()))
    for pid in pids:
        threading.Thread(target=kill_group, args=(pid,), daemon=True).start()
    return len(pids)


def reset(key: str) -> None:
    """Allow spawning again for `key` (a stopped session that is resumed)."""
    with _lock:
        _cancelled.discard(key)


def cancelled(key: str) -> bool:
    with _lock:
        return key in _cancelled
