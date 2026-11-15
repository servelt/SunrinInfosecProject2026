"""Build and replay a provider-free FBv2 candidate-lineage archive."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .frozen_candidate_lineage import (
    FrozenArtifactResolver,
    FrozenCampaignModelGate,
    FrozenRepos,
    revalidate_archived_candidate_lineage,
)


def _encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(path: Path, *, limit: int = 128_000_000) -> bytes:
    path = Path(path)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents)):
        raise ValueError(f"unsafe input path: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_size > limit:
            raise ValueError(f"input exceeds archive limit: {path}")
        raw = os.read(fd, limit + 1)
        if len(raw) != info.st_size:
            raise ValueError(f"input changed while reading: {path}")
        return raw
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _plain(value: Any) -> Any:
    """Convert Mongo Extended JSON into the model classes' plain JSON form."""
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$oid"} and isinstance(value["$oid"], str):
            return value["$oid"]
        if set(value) == {"$date"}:
            return _plain(value["$date"])
        if set(value) in ({"$numberLong"}, {"$numberInt"}, {"$numberDouble"}):
            key = next(iter(value))
            text = value[key]
            return float(text) if key == "$numberDouble" else int(text)
        return {key: _plain(item) for key, item in value.items()}
    return value


def _load_json(path: Path) -> Any:
    return json.loads(_read(path))


def _matching_file(root: Path, logical_path: str, *,
                   expected_sha256: str | None = None,
                   prefix_end: int | None = None,
                   prefix_sha256: str | None = None) -> Path:
    name = Path(logical_path).name
    matches = []
    for candidate in root.rglob(name):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        raw = _read(candidate)
        if expected_sha256 is not None and _sha(raw) != expected_sha256:
            continue
        if (prefix_end is not None and prefix_sha256 is not None and
                (len(raw) < prefix_end or _sha(raw[:prefix_end]) != prefix_sha256)):
            continue
        matches.append(candidate)
    if len(matches) != 1:
        raise ValueError(
            f"expected one archived match for {logical_path}, found {len(matches)}")
    return matches[0]


def _build(args: argparse.Namespace) -> dict[str, Any]:
    source_root = args.source_root.resolve(strict=True)
    output = args.output
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True, mode=0o700)
    ledger_path = args.ledger.resolve(strict=True)
    ledger_raw = _read(ledger_path)
    envelope = json.loads(ledger_raw)
    payload = envelope["payload"]
    records = {row["request_id"]: row for row in payload["records"]}
    if len(records) != len(payload["records"]):
        raise ValueError("ledger request IDs are duplicated")

    origin = _load_json(args.origin_lineage)
    lineage = origin.get("lineage")
    turns = lineage.get("model_tool_turns") if isinstance(lineage, dict) else None
    if not isinstance(turns, list) or [turn.get("role") for turn in turns] != [
            "sp", "verifier", "pov"]:
        raise ValueError("origin lineage does not contain one SP/verifier/PoV chain")
    task_id = origin.get("task_id")
    pov_id = origin.get("pov_id")
    sp_id = lineage.get("sp_id")
    direction_id = lineage.get("direction_id")
    if not all(isinstance(value, str) and value for value in (
            task_id, pov_id, sp_id, direction_id)):
        raise ValueError("origin lineage identity is incomplete")

    functions = _plain(_load_json(args.functions))
    points = _plain(_load_json(args.suspicious_points))
    povs = _plain(_load_json(args.povs))
    if not all(isinstance(rows, list) for rows in (functions, points, povs)):
        raise ValueError("DB exports must be JSON arrays")
    selected_points = [row for row in points
                       if row.get("suspicious_point_id") == sp_id]
    selected_povs = [row for row in povs if row.get("pov_id") == pov_id]
    if len(selected_points) != 1 or len(selected_povs) != 1:
        raise ValueError("origin candidate is absent or duplicated in DB exports")

    artifacts: dict[str, bytes] = {}

    def add(logical_path: str, raw: bytes) -> None:
        path = Path(logical_path)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError(f"logical path is not canonical: {logical_path}")
        old = artifacts.get(logical_path)
        if old is not None and old != raw:
            raise ValueError(f"logical path maps to different bytes: {logical_path}")
        artifacts[logical_path] = raw

    ledger_logicals = set()
    exact: dict[str, str] = {"direction_id": direction_id, "sp_id": sp_id}
    role_names = {
        "sp": "create_suspicious_point",
        "verifier": "update_suspicious_point",
        "pov": "create_pov",
    }
    pov_tool_result = None
    for turn in turns:
        role = turn["role"]
        request_id = turn["request_id"]
        call_id = turn["tool_call_id"]
        row = records.get(request_id)
        if row is None or row.get("role") not in ({"sp", "sp_large"}
                                                  if role == "sp" else {role}):
            raise ValueError(f"ledger role is missing for {role}")
        events = [event for event in row.get("tool_events", [])
                  if event.get("call_id") == call_id]
        if len(events) != 1 or events[0].get("name") != role_names[role]:
            raise ValueError(f"ledger tool event is missing for {role}")
        event = events[0]
        evidence = row.get("response_evidence")
        response_path = evidence["response_path"]
        suffix = f".{request_id}.raw.json"
        if not response_path.endswith(suffix):
            raise ValueError("response path does not identify its ledger")
        ledger_logicals.add(response_path[:-len(suffix)])
        response_file = _matching_file(
            source_root, response_path,
            expected_sha256=evidence["response_sha256"])
        result_file = _matching_file(
            source_root, event["result_path"],
            expected_sha256=event["result_sha256"])
        event_file = _matching_file(
            source_root, evidence["event_log_path"],
            prefix_end=evidence["event_end"],
            prefix_sha256=evidence["event_log_sha256"])
        add(response_path, _read(response_file))
        add(event["result_path"], _read(result_file))
        add(evidence["event_log_path"], _read(event_file))
        exact[f"{role}_request_id"] = request_id
        exact[f"{role}_call_id"] = call_id
        if role == "pov":
            pov_tool_result = json.loads(_read(result_file))
    if len(ledger_logicals) != 1:
        raise ValueError("lineage turns refer to different model ledgers")
    ledger_logical = next(iter(ledger_logicals))
    add(ledger_logical, ledger_raw)

    if (not isinstance(pov_tool_result, dict) or
            not isinstance(pov_tool_result.get("pov_ids"), list)):
        raise ValueError("PoV tool result does not list generated PoVs")
    pov_by_id = {row.get("pov_id"): row for row in povs}
    for generated_id in pov_tool_result["pov_ids"]:
        row = pov_by_id.get(generated_id)
        if row is None or not isinstance(row.get("blob"), str):
            raise ValueError(f"generated PoV is absent from DB export: {generated_id}")
        blob = base64.b64decode(row["blob"], validate=True)
        blob_path = row.get("blob_path")
        if not isinstance(blob_path, str) or not blob_path:
            raise ValueError(f"generated PoV has no retained blob path: {generated_id}")
        blob_file = _matching_file(
            source_root, blob_path, expected_sha256=_sha(blob))
        add(blob_path, _read(blob_file))

    snapshot = {
        "kind": "FBV2_FROZEN_LINEAGE_DB_SNAPSHOT_V1",
        "functions": functions,
        "suspicious_points": points,
        "povs": povs,
    }
    snapshot_raw = _encoded(snapshot)
    snapshot_logical = f"/fbv2-frozen/{task_id}/{pov_id}/db_snapshot.json"
    add(snapshot_logical, snapshot_raw)

    manifest_rows = []
    for index, (logical, raw) in enumerate(sorted(artifacts.items())):
        relative = f"artifacts/{index:03d}-{_sha(raw)}.bin"
        _write_new(output / relative, raw)
        manifest_rows.append({
            "logical_path": logical,
            "archive_path": relative,
            "sha256": _sha(raw),
            "size": len(raw),
        })
    manifest = {"kind": "FBV2_FROZEN_ARTIFACT_MANIFEST_V1",
                "artifacts": manifest_rows}
    manifest_raw = _encoded(manifest)
    _write_new(output / "MANIFEST.json", manifest_raw)
    config = {
        "kind": "FBV2_FROZEN_CANDIDATE_REPLAY_CONFIG_V1",
        "manifest_path": "MANIFEST.json",
        "manifest_sha256": _sha(manifest_raw),
        "ledger_logical_path": ledger_logical,
        "ledger_sha256": _sha(ledger_raw),
        "snapshot_logical_path": snapshot_logical,
        "snapshot_sha256": _sha(snapshot_raw),
        "task_id": task_id,
        "pov_id": pov_id,
        "exact_lineage": exact,
        "source_inputs": {
            "ledger_sha256": _sha(ledger_raw),
            "functions_sha256": _sha(_read(args.functions)),
            "suspicious_points_sha256": _sha(_read(args.suspicious_points)),
            "povs_sha256": _sha(_read(args.povs)),
            "origin_lineage_sha256": _sha(_read(args.origin_lineage)),
        },
    }
    config_raw = _encoded(config)
    _write_new(output / "REPLAY_CONFIG.json", config_raw)
    return {"status": "FROZEN_ARCHIVE_BUILT",
            "archive_root": str(output.resolve()),
            "artifact_count": len(manifest_rows),
            "manifest_sha256": _sha(manifest_raw),
            "config_sha256": _sha(config_raw)}


def _replay(args: argparse.Namespace) -> dict[str, Any]:
    config_raw = _read(args.config)
    if _sha(config_raw) != args.config_sha256:
        raise ValueError("replay config SHA-256 mismatch")
    config = json.loads(config_raw)
    required = {
        "kind", "manifest_path", "manifest_sha256", "ledger_logical_path",
        "ledger_sha256", "snapshot_logical_path", "snapshot_sha256",
        "task_id", "pov_id", "exact_lineage", "source_inputs",
    }
    if (not isinstance(config, dict) or set(config) != required or
            config["kind"] != "FBV2_FROZEN_CANDIDATE_REPLAY_CONFIG_V1"):
        raise ValueError("replay config schema is invalid")
    resolver = FrozenArtifactResolver(
        args.archive_root.resolve(strict=True), config["manifest_path"],
        manifest_sha256=config["manifest_sha256"])
    if resolver.artifact_sha256(
            config["ledger_logical_path"]) != config["ledger_sha256"]:
        raise ValueError("ledger pin disagrees with manifest")
    gate = FrozenCampaignModelGate(resolver, config["ledger_logical_path"])
    repos = FrozenRepos(
        resolver, config["snapshot_logical_path"],
        snapshot_sha256=config["snapshot_sha256"])
    return revalidate_archived_candidate_lineage(
        gate, repos, task_id=config["task_id"], pov_id=config["pov_id"],
        exact_lineage=config["exact_lineage"])


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--ledger", type=Path, required=True)
    build.add_argument("--functions", type=Path, required=True)
    build.add_argument("--suspicious-points", type=Path, required=True)
    build.add_argument("--povs", type=Path, required=True)
    build.add_argument("--origin-lineage", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    replay = sub.add_parser("replay")
    replay.add_argument("--archive-root", type=Path, required=True)
    replay.add_argument("--config", type=Path, required=True)
    replay.add_argument("--config-sha256", required=True)
    replay.add_argument("--result", type=Path)
    args = parser.parse_args()
    result = _build(args) if args.command == "build" else _replay(args)
    if args.command == "replay" and args.result is not None:
        _write_new(args.result, _encoded(result))
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
