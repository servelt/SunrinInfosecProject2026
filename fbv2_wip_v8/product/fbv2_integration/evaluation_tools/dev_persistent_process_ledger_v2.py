"""Development-only V2 process ledger with separate wall and fuzz accounts.

V1 fuzz checkpoints are never loaded or reinterpreted by this module.  One
V2 checkpoint owns every auxiliary, HP, SP, and Global fuzz process in a worklist.
The official Blind 3 runner has no admission path for this development kind.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import threading
from typing import Any
from uuid import uuid4

from dev_persistent_physical_fuzz_ledger import (
    PersistentPhysicalFuzzLedger, PhysicalBudgetExhausted,
    _file_bytes, _number, _plain_parent, _unique_pairs,
)


KIND = "DEV_PERSISTENT_PROCESS_LEDGER_V2"
KINDS = frozenset({"AUX_PROCESS", "HP_FUZZ", "GLOBAL_FUZZ", "SP_FUZZ"})
FUZZ_KINDS = frozenset({"HP_FUZZ", "GLOBAL_FUZZ", "SP_FUZZ"})
STOPS = frozenset({
    "STOPPED_UNCERTAIN_PROCESS", "STOPPED_CLEANUP_INCOMPLETE",
    "STOPPED_OUTPUT_LIMIT", "STOPPED_PHYSICAL_CAP_UNPROVEN",
    "STOPPED_PIN_DRIFT", "STOPPED_WALL_LIMIT",
})
FIELDS = frozenset({
    "kind", "wall_total_seconds", "fuzz_total_seconds",
    "wall_spent_seconds", "fuzz_spent_seconds", "active", "finished",
    "stop_status", "stop_event", "revision",
})


def _validate(state: dict[str, Any]) -> None:
    if type(state) is not dict or set(state) != FIELDS or state["kind"] != KIND:
        raise ValueError("V2 process ledger schema changed")
    wall_total = _number(state["wall_total_seconds"], positive=True)
    fuzz_total = _number(state["fuzz_total_seconds"])
    wall_spent = _number(state["wall_spent_seconds"])
    fuzz_spent = _number(state["fuzz_spent_seconds"])
    active, finished = state["active"], state["finished"]
    if (type(active) is not dict or type(finished) is not list or
            type(state["revision"]) is not int or state["revision"] < 0 or
            state["stop_status"] is not None and state["stop_status"] not in STOPS):
        raise ValueError("V2 process ledger state malformed")
    event = state["stop_event"]
    if event is not None and (type(event) is not dict or
                              set(event) != {"status", "detail"} or
                              event["status"] != state["stop_status"] or
                              type(event["detail"]) is not str or not event["detail"]):
        raise ValueError("V2 stop event malformed")
    reserved_wall = reserved_fuzz = 0.0
    for key, row in active.items():
        if (type(key) is not str or not key or type(row) is not dict or
                set(row) != {"kind", "reserved_seconds"} or
                row["kind"] not in KINDS):
            raise ValueError("V2 active reservation malformed")
        amount = _number(row["reserved_seconds"], positive=True)
        reserved_wall += amount
        if row["kind"] in FUZZ_KINDS:
            reserved_fuzz += amount
    seen: set[str] = set()
    actual_wall = actual_fuzz = 0.0
    any_overrun = any_cleanup = any_output = False
    for row in finished:
        if (type(row) is not dict or set(row) != {
                "key", "kind", "reserved_seconds", "physical_seconds",
                "cleanup_complete", "output_limited", "overrun"} or
                type(row["key"]) is not str or not row["key"] or
                row["key"] in seen or row["key"] in active or
                row["kind"] not in KINDS or
                type(row["cleanup_complete"]) is not bool or
                type(row["output_limited"]) is not bool or
                type(row["overrun"]) is not bool):
            raise ValueError("V2 completion record malformed")
        seen.add(row["key"])
        reserved = _number(row["reserved_seconds"], positive=True)
        physical = _number(row["physical_seconds"])
        actual_wall = math.fsum((actual_wall, physical))
        if row["kind"] in FUZZ_KINDS:
            actual_fuzz = math.fsum((actual_fuzz, physical))
        overrun = (physical > reserved or actual_wall > wall_total or
                   actual_fuzz > fuzz_total)
        if row["overrun"] != overrun:
            raise ValueError("V2 overrun evidence differs")
        any_overrun |= overrun
        any_cleanup |= not row["cleanup_complete"]
        any_output |= row["output_limited"]
    if (not math.isclose(wall_spent, actual_wall, abs_tol=1e-9, rel_tol=0) or
            not math.isclose(fuzz_spent, actual_fuzz, abs_tol=1e-9, rel_tol=0) or
            wall_spent + reserved_wall > wall_total + 1e-9 and
            state["stop_status"] is None or
            fuzz_spent + reserved_fuzz > fuzz_total + 1e-9 and
            state["stop_status"] is None):
        raise ValueError("V2 process ledger totals differ")
    status = state["stop_status"]
    if (status is None and (any_overrun or any_cleanup or any_output or event) or
            status == "STOPPED_UNCERTAIN_PROCESS" and not active or
            status == "STOPPED_CLEANUP_INCOMPLETE" and not any_cleanup or
            status == "STOPPED_OUTPUT_LIMIT" and not any_output or
            status == "STOPPED_PHYSICAL_CAP_UNPROVEN" and not any_overrun or
            status in {"STOPPED_PIN_DRIFT", "STOPPED_WALL_LIMIT"} and event is None):
        raise ValueError("V2 stop status differs from evidence")


class PersistentProcessLedgerV2:
    """One durable, single-owner V2 ledger for auxiliary and fuzz processes."""

    def __init__(self, path: Path, state: dict[str, Any]):
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")
        self._state = state
        self._lock = threading.RLock()
        self._owner_pid = os.getpid()
        self._tainted = False
        self._owned_active_keys: set[str] = set()

    @staticmethod
    def _encode(state: dict[str, Any]) -> bytes:
        return (json.dumps(state, sort_keys=True, separators=(",", ":"),
                           allow_nan=False) + "\n").encode()

    @classmethod
    def create(cls, path: Path, *, wall_total_seconds: float,
               fuzz_total_seconds: float) -> "PersistentProcessLedgerV2":
        path = _plain_parent(path)
        wall_total = _number(wall_total_seconds, positive=True)
        fuzz_total = _number(fuzz_total_seconds)
        lock_path = path.with_name(path.name + ".lock")
        if (path.exists() or path.is_symlink() or lock_path.exists() or
                lock_path.is_symlink()):
            raise FileExistsError(path)
        state = {"kind": KIND, "wall_total_seconds": wall_total,
                 "fuzz_total_seconds": fuzz_total, "wall_spent_seconds": 0.0,
                 "fuzz_spent_seconds": 0.0, "active": {}, "finished": [],
                 "stop_status": None, "stop_event": None, "revision": 0}
        _validate(state)
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(lock_fd)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(cls._encode(state))
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        _file_bytes(path)
        lock_fd = PersistentPhysicalFuzzLedger._check_lock_file(lock_path)
        os.close(lock_fd)
        PersistentPhysicalFuzzLedger._sync_parent(path)
        return cls(path, state)

    @classmethod
    def restore(cls, path: Path, *, wall_total_seconds: float,
                fuzz_total_seconds: float) -> "PersistentProcessLedgerV2":
        path = _plain_parent(path)
        fd = PersistentPhysicalFuzzLedger._check_lock_file(
            path.with_name(path.name + ".lock"))
        os.close(fd)
        raw = _file_bytes(path)
        state = json.loads(raw, object_pairs_hook=_unique_pairs)
        _validate(state)
        if (state["wall_total_seconds"] != _number(wall_total_seconds, positive=True) or
                state["fuzz_total_seconds"] != _number(fuzz_total_seconds) or
                raw != cls._encode(state)):
            raise ValueError("V2 process budget or canonical checkpoint changed")
        ledger = cls(path, state)
        if state["active"] and state["stop_status"] is None:
            stopped = copy.deepcopy(state)
            stopped["stop_status"] = "STOPPED_UNCERTAIN_PROCESS"
            stopped["stop_event"] = {"status": "STOPPED_UNCERTAIN_PROCESS",
                                     "detail": "restored active process reservation"}
            stopped["revision"] += 1
            ledger._commit(stopped)
        return ledger

    def _commit(self, state: dict[str, Any]) -> None:
        if self._tainted or os.getpid() != self._owner_pid:
            raise RuntimeError("V2 process ledger owner or audit state changed")
        _validate(state)
        fd = PersistentPhysicalFuzzLedger._check_lock_file(self.lock_path)
        temp = self.path.with_name(self.path.name + "." + uuid4().hex + ".tmp")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if _file_bytes(self.path) != self._encode(self._state):
                raise RuntimeError("V2 process checkpoint changed outside owner")
            out_fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(out_fd, "wb", closefd=False) as stream:
                    stream.write(self._encode(state))
                    stream.flush()
                    os.fsync(out_fd)
            finally:
                os.close(out_fd)
            os.replace(temp, self.path)
            PersistentPhysicalFuzzLedger._sync_parent(self.path)
        except BaseException:
            self._tainted = True
            temp.unlink(missing_ok=True)
            raise
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self._state = state

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = copy.deepcopy(self._state)
            result["wall_reserved_seconds"] = math.fsum(
                row["reserved_seconds"] for row in result["active"].values())
            result["fuzz_reserved_seconds"] = math.fsum(
                row["reserved_seconds"] for row in result["active"].values()
                if row["kind"] in FUZZ_KINDS)
            return result

    def receipt_snapshot(self) -> tuple[dict[str, Any], str]:
        """Read one canonical checkpoint and its state under the owner lock."""
        with self._lock:
            raw = _file_bytes(self.path)
            if raw != self._encode(self._state):
                self._tainted = True
                raise RuntimeError("V2 process receipt differs from owner state")
            result = copy.deepcopy(self._state)
            result["wall_reserved_seconds"] = math.fsum(
                row["reserved_seconds"] for row in result["active"].values())
            result["fuzz_reserved_seconds"] = math.fsum(
                row["reserved_seconds"] for row in result["active"].values()
                if row["kind"] in FUZZ_KINDS)
            return result, hashlib.sha256(raw).hexdigest()

    def reserve(self, key: str, kind: str, reserved_seconds: float) -> None:
        reserved = _number(reserved_seconds, positive=True)
        with self._lock:
            if self._tainted or os.getpid() != self._owner_pid:
                raise RuntimeError("V2 process ledger is tainted or not owned")
            if _file_bytes(self.path) != self._encode(self._state):
                self._tainted = True
                raise RuntimeError("V2 process checkpoint changed outside owner")
            if self._state["stop_status"] is not None:
                raise RuntimeError("V2 process ledger stopped; no auto resume")
            if (type(key) is not str or not key or kind not in KINDS or
                    key in self._state["active"] or
                    any(row["key"] == key for row in self._state["finished"])):
                raise ValueError("V2 process reservation not eligible")
            snap = self.snapshot()
            wall_available = (snap["wall_total_seconds"] - snap["wall_spent_seconds"] -
                              snap["wall_reserved_seconds"])
            fuzz_available = (snap["fuzz_total_seconds"] - snap["fuzz_spent_seconds"] -
                              snap["fuzz_reserved_seconds"])
            if reserved > wall_available or kind in FUZZ_KINDS and reserved > fuzz_available:
                raise PhysicalBudgetExhausted("V2 process reservation exceeds a cap")
            state = copy.deepcopy(self._state)
            state["active"][key] = {"kind": kind, "reserved_seconds": reserved}
            state["revision"] += 1
            self._commit(state)
            self._owned_active_keys.add(key)

    def finish(self, key: str, *, physical_seconds: float,
               cleanup_complete: bool, output_limited: bool = False
               ) -> dict[str, Any]:
        physical = _number(physical_seconds)
        if type(cleanup_complete) is not bool or type(output_limited) is not bool:
            raise ValueError("V2 process completion flags must be boolean")
        with self._lock:
            if self._tainted or key not in self._owned_active_keys:
                raise RuntimeError("V2 active process owner is unproven")
            state = copy.deepcopy(self._state)
            active = state["active"].pop(key)
            state["wall_spent_seconds"] = math.fsum(
                (state["wall_spent_seconds"], physical))
            if active["kind"] in FUZZ_KINDS:
                state["fuzz_spent_seconds"] = math.fsum(
                    (state["fuzz_spent_seconds"], physical))
            overrun = (physical > active["reserved_seconds"] or
                       state["wall_spent_seconds"] > state["wall_total_seconds"] or
                       state["fuzz_spent_seconds"] > state["fuzz_total_seconds"])
            row = {"key": key, "kind": active["kind"],
                   "reserved_seconds": active["reserved_seconds"],
                   "physical_seconds": physical,
                   "cleanup_complete": cleanup_complete,
                   "output_limited": output_limited, "overrun": overrun}
            state["finished"].append(row)
            if not cleanup_complete:
                state["stop_status"] = "STOPPED_CLEANUP_INCOMPLETE"
            elif output_limited:
                state["stop_status"] = "STOPPED_OUTPUT_LIMIT"
            elif overrun and state["stop_status"] is None:
                state["stop_status"] = "STOPPED_PHYSICAL_CAP_UNPROVEN"
            state["revision"] += 1
            self._commit(state)
            self._owned_active_keys.remove(key)
            return copy.deepcopy(row)

    def mark_stop(self, status: str, detail: str) -> None:
        if (status not in {"STOPPED_PIN_DRIFT", "STOPPED_WALL_LIMIT",
                           "STOPPED_UNCERTAIN_PROCESS"} or
                type(detail) is not str or not detail):
            raise ValueError("V2 manual stop is invalid")
        with self._lock:
            if self._state["stop_status"] is not None:
                return
            if status == "STOPPED_UNCERTAIN_PROCESS" and not self._state["active"]:
                raise ValueError("uncertain process stop needs an active reservation")
            state = copy.deepcopy(self._state)
            state["stop_status"] = status
            state["stop_event"] = {"status": status, "detail": detail}
            state["revision"] += 1
            self._commit(state)
