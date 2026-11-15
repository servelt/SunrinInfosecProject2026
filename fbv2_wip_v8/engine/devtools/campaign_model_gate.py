"""Opt-in, single-process development gate for FBv2 model transports.

Every role client shares one instance.  A reservation is durable before the
wrapped transport is invoked.  This module does not settle FBv2 candidates or
authorize a blind campaign; the caller must persist PENDING_BUDGET itself.
The checksum detects accidental changes, not a hostile process with the same
UID that can rewrite the JSON and recompute SHA. Run target code under a
separate isolation boundary before using this for a live development campaign.
"""

from __future__ import annotations

import asyncio
from dataclasses import is_dataclass, replace
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import stat
import threading
import time
from typing import Any, Callable, Mapping
from uuid import uuid4

from fuzzingbrain.tool_call_canonical import (
    ToolProposalCanonicalizationError,
    canonicalize_tool_proposal,
)

from .ledgered_provider import LedgeredProvider, _request_hash


ROLES = frozenset({
    "direction", "seed", "sp", "sp_large", "verifier", "pov",
    "function_analysis", "assertion_generator",
})


def campaign_candidate_owner_id(*, agent_id: str, task_id: str,
                                harness_name: str, sanitizer: str,
                                sp_id: str) -> str:
    """Build one ledger owner identity per task/Harness/SP contributor."""
    values = (agent_id, task_id, harness_name, sanitizer, sp_id)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("campaign candidate owner identity is incomplete")
    identity = json.dumps({
        "task_id": task_id,
        "harness_name": harness_name,
        "sanitizer": sanitizer,
    }, sort_keys=True, separators=(",", ":")).encode()
    return f"{agent_id}:{hashlib.sha256(identity).hexdigest()}:{sp_id}"
_KIND = "FBV2_DEV_CAMPAIGN_MODEL_GATE_V1"
_STATUSES = frozenset({
    "STARTED", "COMPLETED", "UNCERTAIN", "PENDING_BUDGET", "PENDING_STOP",
})
_SHA_CHARS = frozenset("0123456789abcdef")
_AUDIT_LIMIT = 16_000_000


def _boot_id() -> str:
    """A monotonic deadline is valid only while the same Linux boot is active."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError as exc:
        raise CampaignGateError("cannot pin campaign monotonic clock boot") from exc
    if not value:
        raise CampaignGateError("cannot pin campaign monotonic clock boot")
    return value


class CampaignGateError(RuntimeError):
    """The campaign model gate cannot safely admit more work."""


class CampaignPendingBudget(CampaignGateError):
    """The request was denied before transport and is PENDING_BUDGET."""

    fbv2_stop_reason = "budget_before_transport"


class CampaignStopping(CampaignGateError):
    """The request was refused before transport after graceful stop began."""

    fbv2_stop_reason = "user_stop_before_transport"


class CampaignUncertain(CampaignGateError):
    """A previously started remote turn has uncertain completion."""

    fbv2_stop_reason = "uncertain_remote"


class CampaignDuplicateRequest(CampaignGateError):
    """A request identity was already reserved and cannot be resent."""


def _canonical(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path != path.resolve(strict=False):
        raise ValueError("campaign ledger path must be absolute and canonical")
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("campaign ledger path contains a symbolic link")
    return path


def _encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    return {"payload": payload,
            "sha256": hashlib.sha256(_encoded(payload)).hexdigest()}


def _check_file(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise CampaignGateError("campaign ledger file is unsafe")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_bytes(path: Path, *, missing_ok: bool = False,
                   sync: bool = False) -> bytes | None:
    """Read one private artifact without following a link or a replaced inode."""
    path = _canonical(path)
    try:
        # O_NONBLOCK is essential before fstat: opening a FIFO for reading can
        # otherwise wait forever before the regular-file check is reached.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                     getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        if missing_ok:
            return None
        raise CampaignGateError("model response artifact is missing") from None
    try:
        _check_file(fd)
        info = os.fstat(fd)
        if info.st_size > _AUDIT_LIMIT:
            raise CampaignGateError("model response artifact is too large")
        data = os.read(fd, _AUDIT_LIMIT + 1)
        if len(data) != info.st_size:
            raise CampaignGateError("model response artifact changed while reading")
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise CampaignGateError("model response artifact was replaced")
        if sync:
            os.fsync(fd)
        return data
    finally:
        os.close(fd)


def _event_identity(row: dict[str, Any]) -> tuple[str, str]:
    params = row.get("params")
    params = params if type(params) is dict else {}
    turn = params.get("turn")
    turn = turn if type(turn) is dict else {}
    return (str(row.get("thread_id") or params.get("threadId") or ""),
            str(row.get("turn_id") or params.get("turnId") or turn.get("id") or ""))


def _turn_from_events(event_segment: bytes, response_sha: str) -> tuple[str, str]:
    """Require one completed physical turn and its final message commitment."""
    if not event_segment or not event_segment.endswith(b"\n"):
        raise ValueError("App Server event segment is incomplete")
    try:
        rows = [json.loads(line) for line in event_segment.splitlines()]
    except (ValueError, UnicodeError) as exc:
        raise ValueError("App Server event segment is malformed") from exc
    if any(type(row) is not dict or row.get("server_request") is True
           for row in rows):
        raise ValueError("App Server event segment contains a server tool request")
    starts = [(index, _event_identity(row)) for index, row in enumerate(rows)
              if row.get("method") == "turn/started"]
    completes = [(index, row) for index, row in enumerate(rows)
                 if row.get("method") == "turn/completed"]
    if len(starts) != 1 or len(completes) != 1 or not all(starts[0][1]):
        raise ValueError("App Server turn start/completion is not unique")
    completed = completes[0][1]
    if (_event_identity(completed) != starts[0][1] or
            completed.get("turn_status") != "completed"):
        raise ValueError("App Server turn did not complete as requested")
    messages = [(index, row) for index, row in enumerate(rows)
                if row.get("method") == "item/completed" and
                   row.get("item_type") == "agentMessage"]
    if (not messages or any(
            _event_identity(row)[1] != starts[0][1][1] or
            _event_identity(row)[0] not in ("", starts[0][1][0]) or
            not starts[0][0] < index < completes[0][0]
            for index, row in messages) or
            messages[-1][1].get("agent_message_sha256") != response_sha):
        raise ValueError("App Server final message differs from retained response")
    return starts[0][1]


def _response_evidence(*, request_id: str, raw_path: Path, event_path: Path,
                       event_before: bytes, result: Any) -> dict[str, Any]:
    raw = _private_bytes(raw_path, sync=True)
    event = _private_bytes(event_path, sync=True)
    assert raw is not None and event is not None
    if (not event.startswith(event_before) or
            event_before and not event_before.endswith(b"\n")):
        raise ValueError("App Server event log prefix changed")
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("retained model response is malformed") from exc
    if type(parsed) is not dict or parsed != result:
        raise ValueError("retained model response differs from transport result")
    response_sha = _sha(raw)
    thread_id, turn_id = _turn_from_events(event[len(event_before):], response_sha)
    return {"status": "VERIFIED", "request_id": request_id,
            "thread_id": thread_id, "turn_id": turn_id,
            "response_path": str(raw_path), "response_sha256": response_sha,
            "event_log_path": str(event_path),
            "event_prefix_sha256": _sha(event_before),
            "event_start": len(event_before), "event_end": len(event),
            "event_segment_sha256": _sha(event[len(event_before):]),
            "event_log_sha256": _sha(event)}


class CampaignModelGate:
    """Durable pre-send count for concurrent asyncio roles in one process.

    A restored STARTED record is terminal UNCERTAIN; the same request is never
    resent.  Multiple processes must not run the same campaign concurrently.
    """

    def __init__(self, path: Path, campaign_id: str, physical_max: int | None,
                 wall_seconds: float | None, *, create: bool = False) -> None:
        self.path = _canonical(Path(path))
        if (not isinstance(campaign_id, str) or not campaign_id or
                (physical_max is not None and
                 (type(physical_max) is not int or physical_max < 1)) or
                (wall_seconds is not None and
                 (type(wall_seconds) not in (float, int) or
                  not math.isfinite(wall_seconds) or wall_seconds <= 0))):
            raise ValueError("invalid campaign model budget")
        self.campaign_id = campaign_id
        self.physical_max = physical_max
        self.wall_seconds = None if wall_seconds is None else float(wall_seconds)
        self._lock_path = _canonical(self.path.with_name(self.path.name + ".lock"))
        self._active: set[str] = set()
        self._transport_started: set[str] = set()
        # A signal handler only flips this process-local flag.  It performs no
        # file IO and cannot deadlock by re-entering the durable ledger lock.
        # The durable request rows still prove which turns had crossed the
        # pre-send boundary before the stop was observed.
        self._admission_closed = threading.Event()
        self._admission_stop_reason: str | None = None
        self._tainted = False
        self._last_read_sha256: str | None = None
        if create:
            if not self.path.parent.is_dir():
                raise ValueError("campaign ledger parent does not exist")
            with self._locked():
                if self.path.exists():
                    raise FileExistsError(self.path)
                self._write({"kind": _KIND, "campaign_id": campaign_id,
                             "physical_max": physical_max,
                             "wall_seconds": self.wall_seconds,
                             "started_at": time.time(),
                             "started_monotonic": time.monotonic(),
                             "boot_id": _boot_id(), "physical": 0,
                             "records": []})
        else:
            with self._locked():
                payload = self._read()
                interrupted = False
                for row in payload["records"]:
                    if row["status"] == "STARTED":
                        row["status"] = "UNCERTAIN"
                        row["ended_at"] = time.time()
                        row["error"] = "PROCESS_RESTART_UNCERTAIN_REMOTE_STATE"
                        interrupted = True
                if interrupted:
                    self._write(payload)

    def _locked(self):
        """Use a stable lock inode; the checkpoint itself is atomically replaced."""
        class Lock:
            def __enter__(inner):
                _canonical(self._lock_path)
                inner.fd = os.open(self._lock_path,
                                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                try:
                    _check_file(inner.fd)
                    deadline = time.monotonic() + 10.0
                    while True:
                        try:
                            fcntl.flock(inner.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise CampaignGateError("campaign lock timed out") from None
                            time.sleep(0.01)
                    _check_file(inner.fd)
                    name_info = os.lstat(self._lock_path)
                    fd_info = os.fstat(inner.fd)
                    if (name_info.st_dev, name_info.st_ino) != (
                            fd_info.st_dev, fd_info.st_ino):
                        raise CampaignGateError("campaign lock replaced")
                except BaseException:
                    os.close(inner.fd)
                    raise
                return inner

            def __exit__(inner, *_):
                fcntl.flock(inner.fd, fcntl.LOCK_UN)
                os.close(inner.fd)
        return Lock()

    def _read(self) -> dict[str, Any]:
        _canonical(self.path)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            _check_file(fd)
            if os.fstat(fd).st_size > 16_000_000:
                raise CampaignGateError("campaign ledger too large")
            raw = os.read(fd, 16_000_001)
            info = os.lstat(self.path)
            check = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (check.st_dev, check.st_ino):
                raise CampaignGateError("campaign ledger replaced")
        finally:
            os.close(fd)
        try:
            envelope = json.loads(raw)
            if set(envelope) != {"payload", "sha256"}:
                raise ValueError("unexpected campaign envelope")
            if raw != _encoded(envelope):
                raise ValueError("campaign ledger bytes are not canonical")
            payload = envelope["payload"]
            if hashlib.sha256(_encoded(payload)).hexdigest() != envelope["sha256"]:
                raise ValueError("campaign ledger checksum changed")
            self._validate(payload)
            self._last_read_sha256 = hashlib.sha256(raw).hexdigest()
            return payload
        except (TypeError, ValueError, KeyError) as exc:
            raise CampaignGateError("campaign ledger is corrupt or inconsistent") from exc

    def _validate(self, payload: dict[str, Any]) -> None:
        names = {"kind", "campaign_id", "physical_max", "wall_seconds",
                 "started_at", "started_monotonic", "boot_id", "physical",
                 "records"}
        if (type(payload) is not dict or set(payload) != names or
                payload["kind"] != _KIND or
                payload["campaign_id"] != self.campaign_id or
                payload["physical_max"] != self.physical_max or
                payload["wall_seconds"] != self.wall_seconds or
                type(payload["started_at"]) not in (float, int) or
                not math.isfinite(payload["started_at"]) or
                type(payload["started_monotonic"]) not in (float, int) or
                not math.isfinite(payload["started_monotonic"]) or
                payload["started_monotonic"] > time.monotonic() + 1 or
                payload["boot_id"] != _boot_id() or
                type(payload["physical"]) is not int or
                type(payload["records"]) is not list):
            raise ValueError("campaign budget or schema changed")
        ids: set[str] = set()
        proven_turns: set[tuple[str, str]] = set()
        proven_segments: set[tuple[str, int, int]] = set()
        tool_orders: set[int] = set()
        debits = 0
        for i, row in enumerate(payload["records"], 1):
            base_fields = {"sequence", "request_id", "role", "owner_id",
                           "request_sha256", "status", "started_at",
                           "ended_at", "error"}
            optional_fields = {"response_evidence", "tool_events"}
            optional_fields.add("transport_started_at")
            if (type(row) is not dict or
                    not base_fields <= set(row) <= base_fields | optional_fields or
                    type(row["sequence"]) is not int or row["sequence"] != i or
                    type(row["request_id"]) is not str or
                    not row["request_id"] or row["request_id"] in ids or
                    row["role"] not in ROLES or
                    type(row["owner_id"]) is not str or not row["owner_id"] or
                    type(row["request_sha256"]) is not str or
                    len(row["request_sha256"]) != 64 or
                    any(c not in _SHA_CHARS for c in row["request_sha256"]) or
                    row["status"] not in _STATUSES or
                    type(row["started_at"]) not in (int, float) or
                    not math.isfinite(row["started_at"]) or
                    (row["ended_at"] is not None and
                     (type(row["ended_at"]) not in (int, float) or
                      not math.isfinite(row["ended_at"]))) or
                    (row["error"] is not None and type(row["error"]) is not str)):
                raise ValueError("campaign request record changed")
            transport_started_at = row.get("transport_started_at")
            if (transport_started_at is not None and
                    (type(transport_started_at) not in (int, float) or
                     not math.isfinite(transport_started_at) or
                     transport_started_at < row["started_at"])):
                raise ValueError("campaign transport boundary changed")
            if ((row["status"] == "STARTED" and
                 (row["ended_at"] is not None or row["error"] is not None)) or
                (row["status"] != "STARTED" and row["ended_at"] is None) or
                (row["status"] == "COMPLETED" and row["error"] is not None) or
                (row["status"] == "PENDING_STOP" and
                 transport_started_at is not None) or
                (row["status"] in {
                    "UNCERTAIN", "PENDING_BUDGET", "PENDING_STOP"
                } and
                 not row["error"])):
                raise ValueError("campaign request status evidence changed")
            evidence = row.get("response_evidence")
            if evidence is not None:
                if (row["status"] != "COMPLETED" or type(evidence) is not dict or
                        evidence.get("request_id") != row["request_id"] or
                        evidence.get("status") not in {"VERIFIED", "UNPROVEN"}):
                    raise ValueError("campaign response evidence changed")
                if evidence["status"] == "UNPROVEN":
                    if (set(evidence) != {"status", "request_id", "reason"} or
                            type(evidence["reason"]) is not str or
                            not evidence["reason"]):
                        raise ValueError("campaign unproven evidence changed")
                else:
                    names = {"status", "request_id", "thread_id", "turn_id",
                             "response_path", "response_sha256",
                             "event_log_path", "event_prefix_sha256",
                             "event_start", "event_end", "event_segment_sha256",
                             "event_log_sha256"}
                    if (set(evidence) != names or
                            any(type(evidence[key]) is not str or not evidence[key]
                                for key in ("thread_id", "turn_id")) or
                            any(type(evidence[key]) is not str or
                                len(evidence[key]) != 64 or
                                any(char not in _SHA_CHARS for char in evidence[key])
                                for key in ("response_sha256", "event_prefix_sha256",
                                            "event_segment_sha256", "event_log_sha256")) or
                            type(evidence["event_start"]) is not int or
                            type(evidence["event_end"]) is not int or
                            not 0 <= evidence["event_start"] < evidence["event_end"] or
                            any(type(evidence[key]) is not str
                                for key in ("response_path", "event_log_path"))):
                        raise ValueError("campaign verified evidence changed")
                    try:
                        _canonical(Path(evidence["response_path"]))
                        _canonical(Path(evidence["event_log_path"]))
                    except ValueError as exc:
                        raise ValueError("campaign evidence path changed") from exc
                    if evidence["response_path"] != str(self.path.with_name(
                            self.path.name + "." + row["request_id"] + ".raw.json")):
                        raise ValueError("campaign response belongs to another request")
                    turn_key = (evidence["thread_id"], evidence["turn_id"])
                    segment_key = (evidence["event_log_path"],
                                   evidence["event_start"], evidence["event_end"])
                    if turn_key in proven_turns or segment_key in proven_segments:
                        raise ValueError("campaign response evidence was reused")
                    proven_turns.add(turn_key)
                    proven_segments.add(segment_key)
            tool_events = row.get("tool_events", [])
            if type(tool_events) is not list or (tool_events and
                    (row["status"] != "COMPLETED" or
                     evidence is None or evidence["status"] != "VERIFIED")):
                raise ValueError("campaign tool evidence has no verified model response")
            tool_ids: set[str] = set()
            for event in tool_events:
                required = {"call_id", "proposal_index", "name",
                            "arguments_sha256", "status", "result_sha256",
                            "result_path", "error"}
                optional = {"agent_id", "start_order", "complete_order"}
                if (type(event) is not dict or
                        not required <= set(event) <= required | optional or
                        type(event["proposal_index"]) is not int or
                        event["proposal_index"] < 0 or
                        event["call_id"] !=
                        f"bridge_{row['request_id']}_{event['proposal_index']}" or
                        event["call_id"] in tool_ids or
                        type(event["name"]) is not str or not event["name"] or
                        event["status"] not in {"STARTED", "COMPLETED", "INCOMPLETE"} or
                        ("agent_id" in event and event["agent_id"] is not None and
                         (type(event["agent_id"]) is not str or
                          len(event["agent_id"]) != 24 or
                          any(char not in "0123456789abcdef" for char in
                              event["agent_id"]))) or
                        ("start_order" in event and
                         (type(event["start_order"]) is not int or
                          event["start_order"] < 1)) or
                        ("complete_order" in event and
                         event["complete_order"] is not None and
                         (type(event["complete_order"]) is not int or
                          event["complete_order"] < 1)) or
                        (event.get("complete_order") is not None and
                         ("start_order" not in event or
                          event["complete_order"] <= event["start_order"] or
                          event["status"] != "COMPLETED")) or
                        any(type(event[key]) is not str or len(event[key]) != 64 or
                            any(char not in _SHA_CHARS for char in event[key])
                            for key in ("arguments_sha256",)) or
                        (event["status"] == "COMPLETED" and
                         (type(event["result_sha256"]) is not str or
                          len(event["result_sha256"]) != 64 or
                          any(char not in _SHA_CHARS for char in event["result_sha256"]) or
                          event["result_path"] != str(self.path.with_name(
                              self.path.name + "." + row["request_id"] + "." +
                              str(event["proposal_index"]) + ".tool.txt")) or
                          event["error"] is not None)) or
                        (event["status"] != "COMPLETED" and
                         (event["result_sha256"] is not None or
                          event["result_path"] is not None or
                          (event["status"] == "STARTED" and event["error"] is not None) or
                          (event["status"] == "INCOMPLETE" and
                           (type(event["error"]) is not str or not event["error"]))))):
                    raise ValueError("campaign tool evidence changed")
                for order in (event.get("start_order"),
                              event.get("complete_order")):
                    if order is not None:
                        if order in tool_orders:
                            raise ValueError("campaign tool ordering duplicated")
                        tool_orders.add(order)
                tool_ids.add(event["call_id"])
            ids.add(row["request_id"])
            if row["status"] not in {"PENDING_BUDGET", "PENDING_STOP"}:
                debits += 1
        if (payload["physical"] != debits or debits < 0 or
                (self.physical_max is not None and debits > self.physical_max)):
            raise ValueError("campaign physical count changed")

    def _write(self, payload: dict[str, Any]) -> None:
        self._validate(payload)
        _canonical(self.path)
        data = _encoded(_seal(payload))
        tmp = self.path.with_name(self.path.name + "." + uuid4().hex + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.exists():
                old = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    _check_file(old)
                    old_bytes = os.read(old, 16_000_001)
                    if hashlib.sha256(old_bytes).hexdigest() != self._last_read_sha256:
                        raise CampaignGateError("campaign ledger changed before write")
                finally:
                    os.close(old)
            elif self._last_read_sha256 is not None:
                raise CampaignGateError("campaign ledger disappeared before write")
            os.replace(tmp, self.path)
            parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self._last_read_sha256 = hashlib.sha256(data).hexdigest()
        finally:
            tmp.unlink(missing_ok=True)

    def _mutate(self, action):
        if self._tainted:
            raise CampaignGateError("campaign ledger is tainted")
        try:
            with self._locked():
                payload = self._read()
                result = action(payload)
                self._write(payload)
                return result
        except (CampaignStopping, CampaignUncertain, CampaignDuplicateRequest):
            # These policy refusals happen before a write or transport.
            raise
        except ValueError as exc:
            self._tainted = True
            raise CampaignGateError("campaign ledger mutation violated schema") from exc
        except BaseException:
            # An exception after a pre-send write may leave a durable debit.
            # Never guess and transmit after any ledger failure.
            self._tainted = True
            raise

    def reserve(self, *, request_id: str, role: str, owner_id: str,
                request_sha256: str) -> None:
        if (type(request_id) is not str or not request_id or
                role not in ROLES or type(owner_id) is not str or not owner_id or
                type(request_sha256) is not str or len(request_sha256) != 64 or
                any(c not in "0123456789abcdef" for c in request_sha256)):
            raise ValueError("invalid campaign request identity")

        if self._admission_closed.is_set():
            raise CampaignStopping("campaign is draining after a stop request")

        def action(payload):
            if self._admission_closed.is_set():
                raise CampaignStopping("campaign is draining after a stop request")
            if any(row["request_id"] == request_id for row in payload["records"]):
                raise CampaignDuplicateRequest("campaign request ID already used")
            if any(row["status"] == "UNCERTAIN" for row in payload["records"]):
                raise CampaignUncertain("uncertain remote turn blocks new work")
            if any(event["status"] != "COMPLETED"
                   for row in payload["records"]
                   for event in row.get("tool_events", [])):
                raise CampaignUncertain("incomplete host tool blocks new work")
            # STARTED rows are allowed only when this same gate owns them.
            if any(row["status"] == "STARTED" and
                   row["request_id"] not in self._active
                   for row in payload["records"]):
                raise CampaignUncertain("unowned started turn blocks new work")
            now = time.time()
            denied = ((self.physical_max is not None and
                       payload["physical"] >= self.physical_max) or
                      (self.wall_seconds is not None and
                       time.monotonic() - payload["started_monotonic"] >=
                       self.wall_seconds))
            row = {"sequence": len(payload["records"]) + 1,
                   "request_id": request_id, "role": role,
                   "owner_id": owner_id, "request_sha256": request_sha256,
                   "status": "PENDING_BUDGET" if denied else "STARTED",
                   "started_at": now, "ended_at": now if denied else None,
                   "error": "GLOBAL_BUDGET_EXHAUSTED" if denied else None}
            payload["records"].append(row)
            if not denied:
                payload["physical"] += 1
            return denied

        denied = self._mutate(action)
        if denied:
            raise CampaignPendingBudget("model request pending global budget")
        self._active.add(request_id)

    def close_admission(self, reason: str) -> None:
        """Refuse future reservations without cancelling owned remote turns.

        This method is deliberately safe to call from Python's signal handler:
        it only updates process-local primitives.  Requests already present in
        ``_active`` retain their normal completion/UNCERTAIN accounting.
        """
        if not isinstance(reason, str) or not reason:
            raise ValueError("graceful stop reason is required")
        if self._admission_stop_reason is None:
            self._admission_stop_reason = reason
        self._admission_closed.set()

    @staticmethod
    def require_transport_thread() -> None:
        """Enforce the signal-linearization thread before any predebit."""
        if threading.current_thread() is not threading.main_thread():
            raise CampaignGateError(
                "model transport must execute on the main signal thread")

    def confirm_transport_admission(self, request_id: str) -> None:
        """Linearize provider admission after predebit and before transport.

        ``transport_started_at`` is the auditable boundary: a later stop treats
        this request as already in flight even if the provider coroutine has
        not yet reached its first suspension point. A stop observed before
        this mutation produces ``PENDING_STOP`` and no provider call.
        """
        self.require_transport_thread()
        if request_id not in self._active:
            raise CampaignGateError("request not active before transport")

        def action(payload):
            rows = [row for row in payload["records"]
                    if row["request_id"] == request_id]
            if len(rows) != 1 or rows[0]["status"] != "STARTED":
                raise CampaignGateError("request has no pre-transport reservation")
            row = rows[0]
            def refuse_before_transport():
                row.pop("transport_started_at", None)
                row["status"] = "PENDING_STOP"
                row["ended_at"] = time.time()
                row["error"] = "USER_STOP_BEFORE_TRANSPORT"
                payload["physical"] -= 1
                return False
            if self._admission_closed.is_set():
                return refuse_before_transport()
            # Wall clocks can step backwards between reservation and
            # transport admission. Preserve the causal record ordering; the
            # elapsed campaign budget is measured separately by monotonic.
            row["transport_started_at"] = max(row["started_at"], time.time())
            # Also closes a process-local caller/thread race. POSIX signal
            # delivery itself is masked across this whole mutation below.
            if self._admission_closed.is_set():
                return refuse_before_transport()
            return True

        # Mask process stop signals only across the flag check and durable
        # dispatch-lease mutation. This gives one auditable ordering: either
        # the stop handler ran first (PENDING_STOP), or the lease became
        # durable first and the request is already in-flight by contract.
        # Signals are never masked across the remote provider call.
        if not hasattr(signal, "pthread_sigmask"):
            raise CampaignGateError("transport admission needs POSIX signal masking")
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            admitted = self._mutate(action)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if not admitted:
            self._active.remove(request_id)
            raise CampaignStopping("campaign stopped before model transport")
        self._transport_started.add(request_id)

    @property
    def admission_open(self) -> bool:
        return not self._admission_closed.is_set()

    def stop_snapshot(self) -> dict[str, Any]:
        return {
            "admission_open": self.admission_open,
            "reason": self._admission_stop_reason,
            "active_request_ids": sorted(self._active),
            "transport_started_request_ids": sorted(self._transport_started),
        }

    def finish(self, request_id: str, *, completed: bool,
               error: str | None = None,
               response_evidence: dict[str, Any] | None = None) -> None:
        if request_id not in self._active:
            raise CampaignGateError("request not active in this process")

        def action(payload):
            rows = [row for row in payload["records"]
                    if row["request_id"] == request_id]
            if len(rows) != 1 or rows[0]["status"] != "STARTED":
                raise CampaignGateError("request has no started reservation")
            row = rows[0]
            row["status"] = "COMPLETED" if completed else "UNCERTAIN"
            row["ended_at"] = time.time()
            row["error"] = None if completed else (error or "REMOTE_UNCERTAIN")
            if response_evidence is not None:
                if not completed:
                    raise CampaignGateError("uncertain turn cannot have response evidence")
                row["response_evidence"] = response_evidence

        self._mutate(action)
        self._active.remove(request_id)
        self._transport_started.discard(request_id)

    def snapshot(self) -> dict[str, Any]:
        if self._tainted:
            raise CampaignGateError("campaign ledger is tainted")
        try:
            with self._locked():
                return self._read()
        except BaseException:
            self._tainted = True
            raise

    def check_remaining_envelope(
        self, *, minimum_calls: int, minimum_wall_seconds: float,
    ) -> dict[str, Any]:
        """Atomically check a signed start envelope without spending it.

        This boundary is for a serial scheduler that has already drained its
        downstream queue.  It never cancels or times out an owned turn.  A
        caller may start one new unit of work only when the remaining global
        call and wall budgets both cover the signed minimum.
        """
        if (type(minimum_calls) is not int or minimum_calls < 1 or
                type(minimum_wall_seconds) not in (int, float) or
                not math.isfinite(minimum_wall_seconds) or
                minimum_wall_seconds <= 0 or self.physical_max is None or
                self.wall_seconds is None):
            raise ValueError("remaining model envelope is invalid")
        try:
            with self._locked():
                payload = self._read()
                if any(row["status"] == "UNCERTAIN"
                       for row in payload["records"]):
                    raise CampaignUncertain(
                        "uncertain remote turn blocks envelope admission")
                if any(event["status"] != "COMPLETED"
                       for row in payload["records"]
                       for event in row.get("tool_events", [])):
                    raise CampaignUncertain(
                        "incomplete host tool blocks envelope admission")
                if self._active or any(
                        row["status"] == "STARTED"
                        for row in payload["records"]):
                    raise CampaignGateError(
                        "remaining envelope requires a settled serial gate")
                elapsed = time.monotonic() - payload["started_monotonic"]
                remaining_calls = self.physical_max - payload["physical"]
                remaining_wall = max(0.0, self.wall_seconds - elapsed)
                return {
                    "admitted": (remaining_calls >= minimum_calls and
                                 remaining_wall >= minimum_wall_seconds),
                    "physical_used": payload["physical"],
                    "physical_max": self.physical_max,
                    "remaining_calls": remaining_calls,
                    "elapsed_wall_seconds": elapsed,
                    "wall_seconds": self.wall_seconds,
                    "remaining_wall_seconds": remaining_wall,
                    "minimum_calls": minimum_calls,
                    "minimum_wall_seconds": float(minimum_wall_seconds),
                }
        except CampaignGateError:
            raise
        except BaseException:
            self._tainted = True
            raise

    def verify_response_evidence(
        self, request_id: str, *, _validated_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Re-read current artifacts; a V1 completed row stays UNPROVEN."""
        payload = (self.snapshot() if _validated_snapshot is None else
                   _validated_snapshot)
        rows = [row for row in payload["records"]
                if row["request_id"] == request_id]
        if len(rows) != 1:
            raise CampaignGateError("campaign request is absent or duplicated")
        row = rows[0]
        evidence = row.get("response_evidence")
        if row["status"] != "COMPLETED" or evidence is None:
            return {"status": "UNPROVEN", "request_id": request_id,
                    "reason": "NO_COMPLETED_RESPONSE_EVIDENCE"}
        if evidence["status"] != "VERIFIED":
            return dict(evidence)
        try:
            raw_path = Path(evidence["response_path"])
            event_path = Path(evidence["event_log_path"])
            raw = _private_bytes(raw_path)
            event = _private_bytes(event_path)
            assert raw is not None and event is not None
            if (len(event) < evidence["event_end"] or
                    _sha(event[:evidence["event_start"]]) !=
                    evidence["event_prefix_sha256"] or
                    _sha(event[evidence["event_start"]:evidence["event_end"]]) !=
                    evidence["event_segment_sha256"] or
                    _sha(event[:evidence["event_end"]]) !=
                    evidence["event_log_sha256"] or
                    _sha(raw) != evidence["response_sha256"]):
                raise ValueError("response or event bytes changed")
            thread_id, turn_id = _turn_from_events(
                event[evidence["event_start"]:evidence["event_end"]], _sha(raw))
            if (thread_id != evidence["thread_id"] or
                    turn_id != evidence["turn_id"] or
                    type(json.loads(raw)) is not dict):
                raise ValueError("response turn or body changed")
        except (CampaignGateError, ValueError, UnicodeError, TypeError):
            return {"status": "UNPROVEN", "request_id": request_id,
                    "reason": "RESPONSE_ARTIFACT_VERIFICATION_FAILED"}
        return dict(evidence)

    def begin_tool_event(self, request_id: str,
                         tool_call: dict[str, Any], *,
                         agent_id: str | None = None) -> dict[str, Any]:
        """Durably claim a model-proposed host tool before any side effect."""
        evidence = self.verify_response_evidence(request_id)
        if evidence["status"] != "VERIFIED":
            raise CampaignGateError("host tool has no verified model response")
        if type(tool_call) is not dict or type(tool_call.get("function")) is not dict:
            raise CampaignGateError("invalid host tool call")
        call_id = tool_call.get("id")
        prefix = f"bridge_{request_id}_"
        if type(call_id) is not str or not call_id.startswith(prefix):
            raise CampaignGateError("host tool call belongs to another request")
        suffix = call_id[len(prefix):]
        if not suffix.isdecimal() or str(int(suffix)) != suffix:
            raise CampaignGateError("invalid host tool proposal index")
        index = int(suffix)
        try:
            snapshot = self.snapshot()
            request_rows = [row for row in snapshot["records"]
                            if row["request_id"] == request_id]
            if len(request_rows) != 1:
                raise ValueError("tool request row is absent")
            role = request_rows[0]["role"]
            raw = _private_bytes(Path(evidence["response_path"]))
            assert raw is not None
            response = json.loads(raw)
            proposal = response["tool_calls"][index]
            function = tool_call["function"]
            proposed_name, proposed_args = canonicalize_tool_proposal(
                proposal, role=role)
            executed_args = json.loads(function["arguments"])
            if (proposed_name != function["name"] or
                    type(proposed_args) is not dict or
                    proposed_args != executed_args):
                raise ValueError("tool call differs from model proposal")
        except (ToolProposalCanonicalizationError, ValueError, IndexError,
                KeyError, TypeError) as exc:
            raise CampaignGateError("host tool call differs from model proposal") from exc
        event = {"call_id": call_id, "proposal_index": index,
                 "name": function["name"],
                 "agent_id": agent_id,
                 "arguments_sha256": _sha(_encoded(executed_args)),
                 "status": "STARTED", "result_sha256": None,
                 "result_path": None, "error": None,
                 "start_order": None, "complete_order": None}

        def action(payload):
            if any(row["status"] == "UNCERTAIN" for row in payload["records"]):
                raise CampaignUncertain("uncertain remote turn blocks host tools")
            if any(item["status"] != "COMPLETED"
                   for row in payload["records"]
                   for item in row.get("tool_events", [])):
                raise CampaignUncertain("incomplete host tool blocks host tools")
            rows = [row for row in payload["records"]
                    if row["request_id"] == request_id]
            if (len(rows) != 1 or rows[0]["status"] != "COMPLETED" or
                    rows[0].get("response_evidence") != evidence or
                    any(item["call_id"] == call_id for item in
                        rows[0].get("tool_events", []))):
                raise CampaignGateError("host tool response changed or duplicated")
            previous = [order for row in payload["records"]
                        for item in row.get("tool_events", [])
                        for order in (item.get("start_order"),
                                      item.get("complete_order"))
                        if order is not None]
            event["start_order"] = max(previous, default=0) + 1
            rows[0].setdefault("tool_events", []).append(event)

        self._mutate(action)
        return dict(event)

    def complete_tool_event(self, request_id: str, call_id: str,
                            tool_result: str) -> dict[str, Any]:
        """Settle the preclaimed call after its result is durably retained."""
        if type(tool_result) is not str:
            raise CampaignGateError("host tool result is not text")
        rows = [row for row in self.snapshot()["records"]
                if row["request_id"] == request_id]
        events = [event for event in rows[0].get("tool_events", [])
                  if event["call_id"] == call_id]
        if len(events) != 1 or events[0]["status"] != "STARTED":
            raise CampaignGateError("host tool was not claimed before execution")
        index = events[0]["proposal_index"]
        result_path = self.path.with_name(
            self.path.name + "." + request_id + "." + str(index) + ".tool.txt")
        result_bytes = tool_result.encode("utf-8")
        if len(result_bytes) > _AUDIT_LIMIT:
            raise CampaignGateError("host tool result exceeds audit limit")
        fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(result_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            parent_fd = os.open(result_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except BaseException:
            result_path.unlink(missing_ok=True)
            raise
        def action(payload):
            rows = [row for row in payload["records"]
                    if row["request_id"] == request_id]
            events = [event for event in rows[0].get("tool_events", [])
                      if event["call_id"] == call_id]
            if len(events) != 1 or events[0]["status"] != "STARTED":
                raise CampaignGateError("host tool claim changed before completion")
            events[0]["status"] = "COMPLETED"
            previous = [order for row in payload["records"]
                        for item in row.get("tool_events", [])
                        for order in (item.get("start_order"),
                                      item.get("complete_order"))
                        if order is not None]
            events[0]["complete_order"] = max(previous, default=0) + 1
            events[0]["result_sha256"] = _sha(result_bytes)
            events[0]["result_path"] = str(result_path)
            return dict(events[0])

        return self._mutate(action)

    def fail_tool_event(self, request_id: str, call_id: str,
                        error: str) -> None:
        """Leave a terminal, non-replayable record after a known exception."""
        if type(error) is not str or not error:
            raise ValueError("host tool error type is required")

        def action(payload):
            rows = [row for row in payload["records"]
                    if row["request_id"] == request_id]
            events = [event for event in rows[0].get("tool_events", [])
                      if event["call_id"] == call_id]
            if len(events) != 1 or events[0]["status"] != "STARTED":
                raise CampaignGateError("host tool claim changed before failure")
            events[0]["status"] = "INCOMPLETE"
            events[0]["error"] = error[:160]

        self._mutate(action)

    def record_tool_event(self, request_id: str, tool_call: dict[str, Any],
                          tool_result: str) -> dict[str, Any]:
        """Provider-free convenience path; production uses begin/complete."""
        started = self.begin_tool_event(request_id, tool_call)
        return self.complete_tool_event(request_id, started["call_id"], tool_result)

    def verify_tool_event(
        self, request_id: str, call_id: str, *,
        _validated_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Independently re-read both model and tool artifacts."""
        evidence = self.verify_response_evidence(
            request_id, _validated_snapshot=_validated_snapshot)
        if evidence["status"] != "VERIFIED":
            return {"status": "UNPROVEN", "reason": "MODEL_RESPONSE_UNPROVEN"}
        payload = (self.snapshot() if _validated_snapshot is None else
                   _validated_snapshot)
        rows = [row for row in payload["records"]
                if row["request_id"] == request_id]
        events = [event for event in rows[0].get("tool_events", [])
                  if event["call_id"] == call_id]
        if len(events) != 1 or events[0]["status"] != "COMPLETED":
            return {"status": "UNPROVEN", "reason": "TOOL_EVENT_ABSENT"}
        event = events[0]
        try:
            raw = _private_bytes(Path(evidence["response_path"]))
            result = _private_bytes(Path(event["result_path"]))
            assert raw is not None and result is not None
            proposal = json.loads(raw)["tool_calls"][event["proposal_index"]]
            proposed_name, proposed_args = canonicalize_tool_proposal(
                proposal, role=rows[0]["role"])
            if (proposed_name != event["name"] or
                    _sha(_encoded(proposed_args)) !=
                    event["arguments_sha256"] or
                    _sha(result) != event["result_sha256"]):
                raise ValueError("tool artifact does not match receipt")
        except (CampaignGateError, ToolProposalCanonicalizationError, ValueError,
                IndexError, KeyError, TypeError):
            return {"status": "UNPROVEN", "reason": "TOOL_ARTIFACT_CHANGED"}
        return {**event, "tool_state": event["status"], "status": "VERIFIED"}


class CampaignLedgeredProvider:
    """One debit for each transport call; no hidden smoke ledger stacking."""

    requires_response_lineage = True

    def __init__(self, provider: Any, gate: CampaignModelGate, *,
                 role: str, owner_id: str,
                 boundary_lock: asyncio.Lock | None = None) -> None:
        if (role not in ROLES or not owner_id or
                isinstance(provider, (LedgeredProvider, CampaignLedgeredProvider))):
            raise ValueError("invalid or already ledgered campaign provider")
        self.provider = provider
        self.gate = gate
        self.role = role
        self.owner_id = owner_id
        self.last_request_id: str | None = None
        self.last_response_evidence: dict[str, Any] | None = None
        # Every request ID this provider reserved, in order. A caller can bind
        # a settlement to its own turns instead of an owner-wide ledger scan.
        self.issued_request_ids: list[str] = []
        self._generate_lock = asyncio.Lock()
        self._boundary_lock = boundary_lock

    async def generate(self, request: Any) -> Any:
        # One transport owns one event log. Capture its append boundary only
        # after any prior use of this provider has fully settled.
        async with self._generate_lock:
            return await self._generate_serialized(request)

    async def _generate_serialized(self, request: Any) -> Any:
        self.last_request_id = None
        self.last_response_evidence = None
        if request.role != self.role:
            raise ValueError("campaign request role differs from client role")
        # This invariant must be checked before reserve(): otherwise a caller
        # moved to a worker thread would leave an untransported STARTED row.
        self.gate.require_transport_thread()
        request_id = uuid4().hex
        event_path_value = getattr(self.provider, "event_log_path", None)
        raw_path: Path | None = None
        event_path: Path | None = None
        event_before = b""
        if event_path_value is not None and is_dataclass(request):
            if getattr(request, "raw_response_path", None) is not None:
                raise ValueError("campaign response path must be gate-owned")
            event_path = _canonical(Path(event_path_value))
            event_before = _private_bytes(event_path, missing_ok=True) or b""
            raw_path = _canonical(self.gate.path.with_name(
                self.gate.path.name + "." + request_id + ".raw.json"))
            if raw_path.exists() or raw_path.is_symlink():
                raise CampaignGateError("campaign response path already exists")
            request = replace(request, raw_response_path=raw_path)
        if self._boundary_lock is None:
            self.gate.reserve(request_id=request_id, role=self.role,
                              owner_id=self.owner_id,
                              request_sha256=_request_hash(request))
        else:
            async with self._boundary_lock:
                self.gate.reserve(request_id=request_id, role=self.role,
                                  owner_id=self.owner_id,
                                  request_sha256=_request_hash(request))
        self.issued_request_ids.append(request_id)
        # A stop signal can arrive after the durable reservation but before
        # Python enters the provider. Convert that row to a proved
        # pre-transport refusal instead of transmitting or fabricating an
        # UNCERTAIN remote turn.
        self.gate.confirm_transport_admission(request_id)
        try:
            if self.gate.wall_seconds is None:
                # The full scan has no campaign-wide model clock. The App
                # Server provider retains its own per-request timeout.
                result = await self.provider.generate(request)
            else:
                deadline = (self.gate.snapshot()["started_monotonic"] +
                            self.gate.wall_seconds)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("campaign model wall deadline passed after predebit")
                result = await asyncio.wait_for(self.provider.generate(request),
                                                timeout=remaining)
                # wait_for can return a result *after* its timeout when a provider
                # suppresses cancellation. That response is not a valid completion.
                if time.monotonic() >= deadline:
                    raise TimeoutError("campaign model response exceeded wall deadline")
        except BaseException as original:
            try:
                self.gate.finish(request_id, completed=False,
                                 error=type(original).__name__)
            except BaseException as cleanup:
                original.add_note(f"campaign ledger cleanup failed: {type(cleanup).__name__}")
            if isinstance(original, Exception):
                raise CampaignUncertain("model transport did not complete conclusively") from original
            raise
        evidence: dict[str, Any]
        if event_path is None or raw_path is None:
            evidence = {"status": "UNPROVEN", "request_id": request_id,
                        "reason": "NO_APP_SERVER_EVENT_SOURCE"}
        else:
            try:
                evidence = _response_evidence(
                    request_id=request_id, raw_path=raw_path,
                    event_path=event_path, event_before=event_before,
                    result=result)
            except (CampaignGateError, ValueError, UnicodeError, TypeError,
                    OSError) as exc:
                evidence = {"status": "UNPROVEN", "request_id": request_id,
                            "reason": type(exc).__name__}
        self.gate.finish(request_id, completed=True, response_evidence=evidence)
        self.last_request_id = request_id
        self.last_response_evidence = dict(evidence)
        return result

    async def close(self) -> None:
        await self.provider.close()

    def record_tool_result(self, request_id: str,
                           tool_call: dict[str, Any], tool_result: str
                           ) -> dict[str, Any]:
        return self.gate.record_tool_event(request_id, tool_call, tool_result)

    def begin_tool_result(self, request_id: str,
                          tool_call: dict[str, Any], *,
                          agent_id: str | None = None) -> dict[str, Any]:
        return self.gate.begin_tool_event(request_id, tool_call,
                                          agent_id=agent_id)

    def complete_tool_result(self, request_id: str, call_id: str,
                             tool_result: str) -> dict[str, Any]:
        return self.gate.complete_tool_event(request_id, call_id, tool_result)

    def fail_tool_result(self, request_id: str, call_id: str,
                         error: str) -> None:
        self.gate.fail_tool_event(request_id, call_id, error)


def wrap_campaign_client_factory(
    gate: CampaignModelGate, bridge_builder: Callable[[str, str], Any], *,
    parallel_agents: bool = False
) -> Callable[[str, str], Any]:
    """Adapt the original Fullscan ``llm_client_factory(role, owner_id)``.

    The builder returns a fresh CodexToolBridge-like client with an unledgered
    transport.  All returned clients share this one gate; callers must not also
    wrap them in the older per-smoke DevelopmentRequestLedger.
    """
    # Keep the old serial policy for bounded diagnostics. The full scan locks
    # only reservation and host-tool spans, so independent model transports
    # can overlap while each tool claim and side effect remains atomic.
    invocation_lock = asyncio.Lock()
    boundary_lock = asyncio.Lock() if parallel_agents else None

    def factory(role: str, owner_id: str) -> Any:
        if role not in ROLES or not owner_id:
            raise ValueError("unknown campaign client identity")
        bridge = bridge_builder(role, owner_id)
        if (bridge is None or getattr(bridge, "role", None) != role or
                not hasattr(bridge, "provider")):
            raise ValueError("campaign builder returned invalid role client")
        bridge.provider = CampaignLedgeredProvider(
            bridge.provider, gate, role=role, owner_id=owner_id,
            boundary_lock=boundary_lock)
        if boundary_lock is not None:
            bridge._fbv2_campaign_boundary_lock = boundary_lock
        return bridge

    factory._fbv2_campaign_invocation_lock = (
        None if parallel_agents else invocation_lock)
    factory._fbv2_campaign_gate = gate
    factory._fbv2_campaign_boundary_lock = boundary_lock
    return factory


def product_campaign_client_factory(
    gate: CampaignModelGate, *, cwd: Path, codex_model: str,
    max_calls_per_agent: int | None, executable: str,
    executable_sha256: str, event_log_dir: Path,
    response_stream_limit_bytes: int,
    effort: str = "medium", turn_timeout_seconds: float | None = None,
    parallel_agents: bool = False,
    role_models: Mapping[str, Mapping[str, str]] | None = None,
) -> Callable[[str, str], Any]:
    """Build fresh opt-in FBv2 role clients with one physical-call gate.

    Construction has no model call.  Every App Server event log is separate,
    so a later audit can compare observed turns to conservative predebits.
    """
    from fuzzingbrain.llms.codex_tool_bridge import product_codex_bridge

    event_log_dir = _canonical(Path(event_log_dir))
    if turn_timeout_seconds is None:
        turn_timeout_seconds = (300.0 if gate.wall_seconds is None else
                                min(300.0, gate.wall_seconds))
    if (not event_log_dir.is_dir() or
            (max_calls_per_agent is not None and
             (type(max_calls_per_agent) is not int or max_calls_per_agent < 1)) or
            type(turn_timeout_seconds) not in (int, float) or
            not math.isfinite(turn_timeout_seconds) or
            not 0 < turn_timeout_seconds or
            type(response_stream_limit_bytes) is not int or
            response_stream_limit_bytes < 4096 or
            (gate.wall_seconds is not None and
             turn_timeout_seconds > gate.wall_seconds) or
            not executable_sha256):
        raise ValueError("invalid campaign client factory configuration")

    if role_models is not None:
        if (set(role_models) != ROLES or
                any(type(row) is not dict or set(row) != {"model", "reasoning"} or
                    not isinstance(row["model"], str) or not row["model"] or
                    row["reasoning"] not in {"low", "medium", "high", "xhigh", "max"}
                    for row in role_models.values())):
            raise ValueError("invalid campaign role model profile")

    def builder(role: str, _owner_id: str):
        event_log = event_log_dir / f"{role}_{uuid4().hex}.jsonl"
        route = role_models[role] if role_models is not None else None
        return product_codex_bridge(
            cwd=Path(cwd),
            codex_model=(route["model"] if route is not None else codex_model),
            role=role, max_calls=max_calls_per_agent,
            effort=(route["reasoning"] if route is not None else effort),
            executable=executable,
            executable_sha256=executable_sha256,
            event_log_path=event_log,
            timeout_seconds=turn_timeout_seconds,
            response_stream_limit_bytes=response_stream_limit_bytes,
            disable_codex_mcp=True,
        )

    return wrap_campaign_client_factory(
        gate, builder, parallel_agents=parallel_agents)
