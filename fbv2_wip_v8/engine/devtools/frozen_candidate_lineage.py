"""Read-only, manifest-bound replay of archived FBv2 candidate lineage.

This module never contacts a provider, target, or database.  It authenticates
an extracted archive and lets the current lineage checker consume the original
logical artifact paths plus a hash-pinned JSON snapshot.  Archive replay is
never discovery or Security Gate credit.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import time
from typing import Any

from .campaign_model_gate import (
    CampaignGateError,
    CampaignModelGate,
    _AUDIT_LIMIT,
    _boot_id,
    _encoded,
    _sha,
    _turn_from_events,
)
from .model_candidate_lineage import (
    find_candidate_lineage,
    verify_candidate_lineage,
)
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.pov import POV
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint


_MANIFEST_KIND = "FBV2_FROZEN_ARTIFACT_MANIFEST_V1"
_SNAPSHOT_KIND = "FBV2_FROZEN_LINEAGE_DB_SNAPSHOT_V1"
_MAX_ARCHIVE_FILE = 128_000_000
_HEX = frozenset("0123456789abcdef")


def _valid_sha(value: Any) -> bool:
    return (type(value) is str and len(value) == 64 and
            all(char in _HEX for char in value))


class FrozenArchiveError(CampaignGateError):
    """An archive cannot be trusted or is incomplete."""


class FrozenArtifactResolver:
    """Resolve exact historical absolute paths inside one verified archive."""

    def __init__(self, archive_root: Path, manifest_path: str, *,
                 manifest_sha256: str) -> None:
        root = Path(archive_root)
        if (not root.is_absolute() or not root.is_dir() or root.is_symlink() or
                root != root.resolve(strict=True) or
                any(parent.is_symlink() for parent in root.parents)):
            raise FrozenArchiveError("archive root is not a canonical directory")
        if not _valid_sha(manifest_sha256):
            raise FrozenArchiveError("manifest SHA-256 is invalid")
        relative = self._relative(manifest_path)
        self.root = root
        raw = self._read_relative(relative, limit=_AUDIT_LIMIT)
        if _sha(raw) != manifest_sha256:
            raise FrozenArchiveError("manifest SHA-256 mismatch")
        try:
            manifest = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise FrozenArchiveError("manifest is not valid JSON") from exc
        if (type(manifest) is not dict or
                set(manifest) != {"kind", "artifacts"} or
                manifest.get("kind") != _MANIFEST_KIND or
                type(manifest.get("artifacts")) is not list):
            raise FrozenArchiveError("manifest schema is invalid")
        entries: dict[str, dict[str, Any]] = {}
        archive_names: set[str] = set()
        for row in manifest["artifacts"]:
            if (type(row) is not dict or
                    set(row) != {"logical_path", "archive_path", "sha256", "size"} or
                    type(row["logical_path"]) is not str or
                    type(row["archive_path"]) is not str or
                    not _valid_sha(row["sha256"]) or
                    type(row["size"]) is not int or
                    not 0 <= row["size"] <= _MAX_ARCHIVE_FILE):
                raise FrozenArchiveError("manifest artifact entry is invalid")
            logical = Path(row["logical_path"])
            if (not logical.is_absolute() or ".." in logical.parts or
                    str(logical) != row["logical_path"]):
                raise FrozenArchiveError("logical artifact path is invalid")
            archived = self._relative(row["archive_path"])
            archived_name = archived.as_posix()
            if (row["logical_path"] in entries or archived_name in archive_names or
                    archived == relative):
                raise FrozenArchiveError("manifest artifact mapping is duplicated")
            entries[row["logical_path"]] = {**row, "archive_path": archived_name}
            archive_names.add(archived_name)
        self._entries = entries
        self.manifest_sha256 = manifest_sha256

    @staticmethod
    def _relative(value: str) -> PurePosixPath:
        if type(value) is not str or not value or "\\" in value:
            raise FrozenArchiveError("archive-relative path is invalid")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise FrozenArchiveError("archive-relative path escapes its root")
        return path

    def _read_relative(self, relative: PurePosixPath, *, limit: int) -> bytes:
        candidate = self.root.joinpath(*relative.parts)
        try:
            if (candidate.is_symlink() or
                    any(parent != self.root and parent.is_symlink()
                        for parent in candidate.parents if self.root in parent.parents) or
                    candidate.resolve(strict=True).parent !=
                    candidate.parent.resolve(strict=True)):
                raise FrozenArchiveError("archive artifact traverses a symbolic link")
            fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW |
                         getattr(os, "O_NONBLOCK", 0))
        except (OSError, RuntimeError) as exc:
            if isinstance(exc, FrozenArchiveError):
                raise
            raise FrozenArchiveError("archive artifact is missing or unsafe") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    info.st_nlink != 1 or info.st_size > limit):
                raise FrozenArchiveError("archive artifact is not a safe regular file")
            raw = os.read(fd, limit + 1)
            current = os.lstat(candidate)
            if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or
                    len(raw) != info.st_size):
                raise FrozenArchiveError("archive artifact changed while reading")
            return raw
        finally:
            os.close(fd)

    def read(self, logical_path: str | Path, *,
             expected_sha256: str | None = None) -> bytes:
        logical = str(logical_path)
        row = self._entries.get(logical)
        if row is None:
            raise FrozenArchiveError("logical artifact is absent from manifest")
        if expected_sha256 is not None and expected_sha256 != row["sha256"]:
            raise FrozenArchiveError("receipt and manifest SHA-256 disagree")
        raw = self._read_relative(
            self._relative(row["archive_path"]), limit=_MAX_ARCHIVE_FILE)
        if len(raw) != row["size"] or _sha(raw) != row["sha256"]:
            raise FrozenArchiveError("archived artifact bytes do not match manifest")
        return raw

    def artifact_sha256(self, logical_path: str | Path) -> str:
        row = self._entries.get(str(logical_path))
        if row is None:
            raise FrozenArchiveError("logical artifact is absent from manifest")
        return row["sha256"]


class FrozenCampaignModelGate(CampaignModelGate):
    """Immutable historical gate whose artifacts come only from a resolver."""

    archive_replay = True

    def __init__(self, resolver: FrozenArtifactResolver,
                 ledger_logical_path: str) -> None:
        self.resolver = resolver
        self.path = Path(ledger_logical_path)
        raw = resolver.read(ledger_logical_path)
        try:
            envelope = json.loads(raw)
            if (type(envelope) is not dict or
                    set(envelope) != {"payload", "sha256"} or
                    raw != _encoded(envelope)):
                raise ValueError("ledger envelope is not canonical")
            payload = envelope["payload"]
            if (_sha(_encoded(payload)) != envelope["sha256"] or
                    type(payload) is not dict or
                    type(payload.get("started_monotonic")) not in (int, float) or
                    not math.isfinite(payload["started_monotonic"]) or
                    type(payload.get("boot_id")) is not str or
                    not payload["boot_id"]):
                raise ValueError("ledger seal is invalid")
            self.campaign_id = payload["campaign_id"]
            self.physical_max = payload["physical_max"]
            self.wall_seconds = payload["wall_seconds"]
            # Reuse the production structural validator while replacing only
            # host-local clock facts that cannot survive archival transfer.
            structural = copy.deepcopy(payload)
            structural["started_monotonic"] = max(0.0, time.monotonic() - 1.0)
            structural["boot_id"] = _boot_id()
            CampaignModelGate._validate(self, structural)
        except (CampaignGateError, KeyError, TypeError, ValueError,
                UnicodeError) as exc:
            raise FrozenArchiveError("frozen campaign ledger is invalid") from exc
        self._frozen_snapshot = copy.deepcopy(payload)
        self.ledger_sha256 = _sha(raw)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self._frozen_snapshot)

    def read_artifact(self, logical_path: str | Path, *,
                      expected_sha256: str) -> bytes:
        return self.resolver.read(
            logical_path, expected_sha256=expected_sha256)

    def verify_response_evidence(
        self, request_id: str, *,
        _validated_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = self.snapshot() if _validated_snapshot is None else _validated_snapshot
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
            raw = self.read_artifact(
                evidence["response_path"],
                expected_sha256=evidence["response_sha256"])
            # App Server logs can contain later turns.  The manifest binds the
            # final whole file; the response receipt separately binds the
            # prefix ending at this turn's event_end boundary.
            event = self.resolver.read(evidence["event_log_path"])
            if (len(raw) > _AUDIT_LIMIT or len(event) > _AUDIT_LIMIT or
                    len(event) < evidence["event_end"] or
                    _sha(event[:evidence["event_start"]]) !=
                    evidence["event_prefix_sha256"] or
                    _sha(event[evidence["event_start"]:evidence["event_end"]]) !=
                    evidence["event_segment_sha256"] or
                    _sha(event[:evidence["event_end"]]) !=
                    evidence["event_log_sha256"]):
                raise ValueError("response or event bytes changed")
            thread_id, turn_id = _turn_from_events(
                event[evidence["event_start"]:evidence["event_end"]], _sha(raw))
            if (thread_id != evidence["thread_id"] or
                    turn_id != evidence["turn_id"] or
                    type(json.loads(raw)) is not dict):
                raise ValueError("response turn or body changed")
        except (FrozenArchiveError, ValueError, UnicodeError, TypeError):
            return {"status": "UNPROVEN", "request_id": request_id,
                    "reason": "RESPONSE_ARTIFACT_VERIFICATION_FAILED"}
        return dict(evidence)

    def verify_tool_event(
        self, request_id: str, call_id: str, *,
        _validated_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = self.snapshot() if _validated_snapshot is None else _validated_snapshot
        evidence = self.verify_response_evidence(
            request_id, _validated_snapshot=payload)
        if evidence["status"] != "VERIFIED":
            return {"status": "UNPROVEN", "reason": "MODEL_RESPONSE_UNPROVEN"}
        rows = [row for row in payload["records"]
                if row["request_id"] == request_id]
        events = [event for event in rows[0].get("tool_events", [])
                  if event["call_id"] == call_id]
        if len(events) != 1 or events[0]["status"] != "COMPLETED":
            return {"status": "UNPROVEN", "reason": "TOOL_EVENT_ABSENT"}
        event = events[0]
        try:
            raw = self.read_artifact(
                evidence["response_path"],
                expected_sha256=evidence["response_sha256"])
            result = self.read_artifact(
                event["result_path"],
                expected_sha256=event["result_sha256"])
            proposal = json.loads(raw)["tool_calls"][event["proposal_index"]]
            arguments = json.loads(proposal["arguments"])
            if (proposal["name"] != event["name"] or
                    _sha(_encoded(arguments)) != event["arguments_sha256"] or
                    _sha(result) != event["result_sha256"]):
                raise ValueError("tool artifact does not match receipt")
        except (FrozenArchiveError, ValueError, IndexError, KeyError,
                TypeError, UnicodeError):
            return {"status": "UNPROVEN", "reason": "TOOL_ARTIFACT_CHANGED"}
        return {**event, "tool_state": event["status"], "status": "VERIFIED"}

    @staticmethod
    def _readonly(*_args, **_kwargs):
        raise CampaignGateError("frozen campaign gate is read-only")

    reserve = _readonly
    close_admission = _readonly
    confirm_transport_admission = _readonly
    finish = _readonly
    begin_tool_event = _readonly
    complete_tool_event = _readonly
    fail_tool_event = _readonly
    record_tool_event = _readonly
    check_remaining_envelope = _readonly


class _FrozenRepository:
    def __init__(self, rows: list[Any], id_field: str) -> None:
        values: dict[str, Any] = {}
        for row in rows:
            identity = getattr(row, id_field)
            if type(identity) is not str or not identity or identity in values:
                raise FrozenArchiveError("frozen DB identity is invalid or duplicated")
            values[identity] = row
        self._values = values

    def find_by_id(self, identity: str) -> Any | None:
        return self._values.get(identity)

    def find_by_task(self, task_id: str) -> list[Any]:
        return [row for row in self._values.values()
                if getattr(row, "task_id", None) == task_id]


class FrozenRepos:
    """Mongo-free repositories loaded from one hash-pinned JSON snapshot."""

    def __init__(self, resolver: FrozenArtifactResolver,
                 snapshot_logical_path: str, *, snapshot_sha256: str) -> None:
        if not _valid_sha(snapshot_sha256):
            raise FrozenArchiveError("snapshot SHA-256 is invalid")
        raw = resolver.read(
            snapshot_logical_path, expected_sha256=snapshot_sha256)
        try:
            value = json.loads(raw)
            if (type(value) is not dict or
                    set(value) != {"kind", "functions", "suspicious_points", "povs"} or
                    value["kind"] != _SNAPSHOT_KIND or
                    any(type(value[name]) is not list for name in (
                        "functions", "suspicious_points", "povs")) or
                    any(type(row) is not dict for name in (
                        "functions", "suspicious_points", "povs")
                        for row in value[name])):
                raise ValueError("snapshot schema")
            functions = [Function.from_dict(row) for row in value["functions"]]
            points = [SuspiciousPoint.from_dict(row)
                      for row in value["suspicious_points"]]
            povs = [POV.from_dict(row) for row in value["povs"]]
        except (TypeError, ValueError, KeyError, UnicodeError) as exc:
            raise FrozenArchiveError("frozen DB snapshot is invalid") from exc
        self.functions = _FrozenRepository(functions, "function_id")
        self.suspicious_points = _FrozenRepository(
            points, "suspicious_point_id")
        self.povs = _FrozenRepository(povs, "pov_id")
        self.snapshot_sha256 = snapshot_sha256


def revalidate_archived_candidate_lineage(
    gate: FrozenCampaignModelGate, repos: FrozenRepos, *,
    task_id: str, pov_id: str,
    exact_lineage: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run current lineage logic without granting new-discovery credit."""
    if not isinstance(gate, FrozenCampaignModelGate) or not isinstance(repos, FrozenRepos):
        return {"status": "ARCHIVE_REPLAY_UNPROVEN",
                "reason": "FROZEN_REPLAY_TYPES_REQUIRED",
                "automatic_discovery": False,
                "discovery_credit": "NOT_CREDITED_ARCHIVE_REPLAY"}
    if exact_lineage is None:
        result = find_candidate_lineage(
            gate, repos, task_id=task_id, pov_id=pov_id)
    else:
        required = {
            "direction_id", "sp_id", "sp_request_id", "sp_call_id",
            "verifier_request_id", "verifier_call_id", "pov_request_id",
            "pov_call_id",
        }
        if type(exact_lineage) is not dict or set(exact_lineage) != required or any(
                type(exact_lineage[key]) is not str or not exact_lineage[key]
                for key in required):
            result = {"status": "UNPROVEN",
                      "reason": "EXACT_ARCHIVE_LINEAGE_INVALID"}
        else:
            result = verify_candidate_lineage(
                gate, repos, task_id=task_id,
                direction_id=exact_lineage["direction_id"],
                sp_id=exact_lineage["sp_id"],
                sp_request_id=exact_lineage["sp_request_id"],
                sp_call_id=exact_lineage["sp_call_id"],
                verifier_request_id=exact_lineage["verifier_request_id"],
                verifier_call_id=exact_lineage["verifier_call_id"],
                pov_request_id=exact_lineage["pov_request_id"],
                pov_call_id=exact_lineage["pov_call_id"])
    if result.get("status") != "ARCHIVED_LINEAGE_REVALIDATED":
        return {**result, "status": "ARCHIVE_REPLAY_UNPROVEN",
                "automatic_discovery": False,
                "discovery_credit": "NOT_CREDITED_ARCHIVE_REPLAY"}
    return {**result,
            "kind": "FBV2_ARCHIVED_CANDIDATE_LINEAGE_REVALIDATION_V1",
            "archive_manifest_sha256": gate.resolver.manifest_sha256,
            "archive_ledger_sha256": gate.ledger_sha256,
            "frozen_db_snapshot_sha256": repos.snapshot_sha256,
            "automatic_discovery": False,
            "discovery_credit": "NOT_CREDITED_ARCHIVE_REPLAY",
            "security_gate_status": "NOT_EVALUATED_BY_ARCHIVE_REPLAY"}
