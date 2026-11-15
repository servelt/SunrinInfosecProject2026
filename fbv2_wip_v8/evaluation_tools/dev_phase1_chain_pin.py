"""Evaluator-owned, pre-model Phase 1 input pin for development runs.

Issue immediately after ``run_phase1`` or ``continue_phase1`` and verify before
starting a selected-function model turn. The Direction model may already have
run to produce the Phase 1 plan. Mode 0600 prevents other UIDs from writing the pin,
not the evaluator's own UID. An external Freeze Spec must separately name and
hash the pin before it can authorize a Blind run. This module also cannot prove
that the pinned selection was the scheduler's correct choice or that the
Artifact was officially qualified; the product preflight must check both.
Nor can it prove that an earlier Scan was genuine: a continuation only binds
its existing bytes.
The target source checkout, model settings, and execution contract remain
outside this pin and must be frozen by the external evaluation contract.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


KIND = "DEV_PHASE1_CHAIN_PIN_V1"
POLICY = "FBV2_FIRST_PASS_UNIQUE_DEV"
PHASE1_FILES = frozenset({
    "run.json", "harness.json", "direction_plan.json", "workers.json",
    "directions.json", "function_pool.json", "selection.json",
})
INITIAL_ONLY = "call_graph_audit.json"
RECORD_KEYS = frozenset({
    "kind", "state", "pin_path", "run_dir", "run_id", "artifact_path",
    "artifact_sha256", "direction_plan_input", "direction_plan_sha256",
    "phase1_files_sha256", "selected_function_id", "parent_run_id",
    "parent_pin_path", "parent_pin_sha256", "parent_scan_sha256",
})


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_file(path: Path) -> Any:
    data = _regular_bytes(path)
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_path(path: Path, *, existing: bool = True) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must be absolute without traversal: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if existing:
                raise ValueError(f"missing path component: {current}") from None
            break
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlink in path: {current}")
    if existing and not path.exists():
        raise ValueError(f"missing path: {path}")
    if path != path.resolve(strict=existing):
        raise ValueError(f"noncanonical path: {path}")
    return path


def _regular_bytes(path: Path) -> bytes:
    path = _canonical_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or
                (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError(f"file changed while opening: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
    finally:
        os.close(fd)
    return data


def _artifact_digest(path: Path, *, allow_empty: bool = False) -> str:
    path = _canonical_path(path)
    if path.is_file():
        return _sha(_regular_bytes(path))
    if not path.is_dir():
        raise ValueError("artifact is not a file or directory")
    rows: list[tuple[str, str]] = []
    for child in sorted(path.rglob("*")):
        _canonical_path(child)
        if child.is_dir():
            continue
        rows.append((child.relative_to(path).as_posix(), _sha(_regular_bytes(child))))
    if not rows and not allow_empty:
        raise ValueError("empty artifact")
    return _sha(json.dumps(rows, separators=(",", ":")).encode("utf-8"))


def _pin_file_bytes(path: Path) -> bytes:
    path = _canonical_path(path)
    metadata = path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError("pin must be evaluator-owned regular mode 0600")
    return _regular_bytes(path)


def _pin_parent(path: Path) -> None:
    parent = _canonical_path(path.parent)
    metadata = parent.stat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("pin directory must be evaluator-owned mode 0700")


def _phase1_state(run_dir: Path, *, pre_model: bool) -> tuple[dict, dict, list[dict], dict[str, str]]:
    run_dir = _canonical_path(run_dir)
    if not run_dir.is_dir():
        raise ValueError("Phase 1 run directory missing")
    run = _json_file(run_dir / "run.json")
    selection = _json_file(run_dir / "selection.json")
    pool = _json_file(run_dir / "function_pool.json")
    if not isinstance(run, dict) or not isinstance(selection, dict) or not isinstance(pool, list):
        raise ValueError("malformed Phase 1 JSON")
    if (run.get("run_id") != run_dir.name or run.get("selection_policy") != POLICY
            or run.get("source_kind") != "official_oss_fuzz"
            or run.get("direction_source_kind") != "PINNED_MODEL_PROPOSAL"
            or not isinstance(run.get("selected_function_id"), str)):
        raise ValueError("Phase 1 policy or run identity mismatch")
    selected_id = run["selected_function_id"]
    if selection.get("function_id") != selected_id:
        raise ValueError("selection disagrees with run")
    matching = [row for row in pool if isinstance(row, dict) and row.get("function_id") == selected_id]
    if len(matching) != 1 or run.get("function_count") != len(pool):
        raise ValueError("selected function absent or duplicate in Pool")
    if any(matching[0].get(key) != selection.get(key) for key in
           ("function_name", "direction_id", "role")):
        raise ValueError("selection disagrees with Pool")
    initial = "parent_run_id" not in run
    hp_state = run.get("hp_project_state_dev") is True
    expected = PHASE1_FILES | ({INITIAL_ONLY} if initial else set())
    if hp_state:
        expected = expected | {"hp_project_state.json"}
        if not initial:
            expected = expected | {"hp_guided_corpus"}
    if pre_model and {x.name for x in run_dir.iterdir()} != expected:
        raise ValueError("run is not exactly in the pre-model Phase 1 state")
    hashes = {name: (_artifact_digest(run_dir / name, allow_empty=True)
                     if name == "hp_guided_corpus"
                     else _sha(_regular_bytes(run_dir / name)))
              for name in sorted(expected)}
    if hp_state and run.get("hp_project_state_sha256") != hashes["hp_project_state.json"]:
        raise ValueError("HP project state SHA-256 mismatch")
    return run, selection, pool, hashes


def _record_for_run(run_dir: Path, *, pin_path: Path, parent_pin: Path | None,
                    pre_model: bool, visited: set[Path] | None = None) -> dict[str, Any]:
    run_dir = _canonical_path(run_dir)
    run, _, _, file_hashes = _phase1_state(run_dir, pre_model=pre_model)
    artifact = _canonical_path(Path(run["artifact"]))
    plan_input = _canonical_path(Path(run["direction_plan_input"]))
    plan_sha = _sha(_regular_bytes(plan_input))
    if plan_sha != run.get("direction_plan_sha256") or plan_sha != file_hashes["direction_plan.json"]:
        raise ValueError("Direction plan bytes mismatch")
    parent_id = run.get("parent_run_id")
    if bool(parent_id) != bool(parent_pin):
        raise ValueError("continuation must provide exactly one parent pin")
    parent_path: str | None = None
    parent_sha: str | None = None
    parent_scan_sha: str | None = None
    if parent_pin is not None:
        parent_pin = _canonical_path(parent_pin)
        parent_data = _pin_file_bytes(parent_pin)
        parent = _verify_pin(parent_pin, pre_model=False,
                             visited=visited if visited is not None else set())
        if parent["run_id"] != parent_id or Path(parent["run_dir"]).parent != run_dir.parent:
            raise ValueError("parent pin does not match continuation")
        if (parent["artifact_path"] != str(artifact)
                or parent["artifact_sha256"] != _artifact_digest(artifact)
                or parent["direction_plan_sha256"] != plan_sha
                or any(parent["phase1_files_sha256"].get(name) != file_hashes[name]
                       for name in ("harness.json", "workers.json", "directions.json"))):
            raise ValueError("continuation changed fixed Phase 1 inputs")
        parent_run_dir = Path(parent["run_dir"])
        scan_path = parent_run_dir / "scan.json"
        scan = _json_file(scan_path)
        parent_selection = _json_file(parent_run_dir / "selection.json")
        parent_harness = _json_file(parent_run_dir / "harness.json")
        if (not isinstance(scan, dict)
                or scan.get("selected_function_id") != parent["selected_function_id"]
                or scan.get("selected_function") != parent_selection.get("function_name")
                or scan.get("target_repository") != parent_harness.get("target_repository")):
            raise ValueError("parent Scan does not match selected function")
        parent_path, parent_sha = str(parent_pin), _sha(parent_data)
        parent_scan_sha = _sha(_regular_bytes(scan_path))
    return {
        "kind": KIND, "state": "PRE_MODEL", "pin_path": str(pin_path),
        "run_dir": str(run_dir),
        "run_id": run["run_id"], "artifact_path": str(artifact),
        "artifact_sha256": _artifact_digest(artifact),
        "direction_plan_input": str(plan_input), "direction_plan_sha256": plan_sha,
        "phase1_files_sha256": file_hashes,
        "selected_function_id": run["selected_function_id"],
        "parent_run_id": parent_id, "parent_pin_path": parent_path,
        "parent_pin_sha256": parent_sha, "parent_scan_sha256": parent_scan_sha,
    }


def issue_pin(run_dir: Path, pin_path: Path, *, parent_pin: Path | None = None) -> dict[str, Any]:
    """Write once, with mode 0600, before a selected-function model turn."""
    pin_path = Path(pin_path)
    _pin_parent(pin_path)
    if not pin_path.is_absolute() or ".." in pin_path.parts:
        raise ValueError("pin path must be canonical and absolute")
    if pin_path.exists() or pin_path.is_symlink():
        raise FileExistsError(pin_path)
    record = _record_for_run(run_dir, pin_path=pin_path, parent_pin=parent_pin,
                             pre_model=True)
    _pin_location_allowed(pin_path, record)
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(pin_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(pin_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return verify_pin(pin_path)


def _pin_location_allowed(pin_path: Path, record: dict[str, Any]) -> None:
    harness = _json_file(Path(record["run_dir"]) / "harness.json")
    if not isinstance(harness, dict) or not isinstance(harness.get("target_repository"), str):
        raise ValueError("Phase 1 Harness has no target repository")
    target_repository = _canonical_path(Path(harness["target_repository"]))
    if any(pin_path.is_relative_to(path) for path in
           (Path(record["run_dir"]), Path(record["artifact_path"]), target_repository)):
        raise ValueError("pin must live outside run, artifact and target repository")


def _verify_pin(pin_path: Path, *, pre_model: bool, visited: set[Path]) -> dict[str, Any]:
    pin_path = _canonical_path(pin_path)
    if pin_path in visited:
        raise ValueError("parent pin cycle")
    visited.add(pin_path)
    _pin_parent(pin_path)
    data = _pin_file_bytes(pin_path)
    record = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs)
    if (not isinstance(record, dict) or set(record) != RECORD_KEYS
            or record.get("kind") != KIND or record.get("state") != "PRE_MODEL"):
        raise ValueError("invalid pin schema or state")
    if data != (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"):
        raise ValueError("pin is not canonical")
    run_dir = _canonical_path(Path(record["run_dir"]))
    _pin_location_allowed(pin_path, record)
    parent_path = record["parent_pin_path"]
    expected = _record_for_run(run_dir, pin_path=pin_path,
                               parent_pin=Path(parent_path) if parent_path else None,
                               pre_model=pre_model, visited=visited)
    if record != expected:
        raise ValueError("pin values, hashes, or state no longer match Phase 1")
    return record


def verify_pin(pin_path: Path) -> dict[str, Any]:
    """Fail closed unless the pinned run remains in its pre-model state."""
    return _verify_pin(Path(pin_path), pre_model=True, visited=set())


def verify_pin_after_model(pin_path: Path) -> dict[str, Any]:
    """Recheck frozen Phase 1 bytes after Scan has added its own outputs.

    This accepts extra Scan artifacts but still checks every Phase 1 input,
    the pinned Artifact, and any parent pin and parent Scan linkage.
    """
    return _verify_pin(Path(pin_path), pre_model=False, visited=set())
