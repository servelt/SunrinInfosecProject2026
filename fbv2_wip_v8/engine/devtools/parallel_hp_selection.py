"""Unsigned preparation for an HP track alongside SP work.

This module freezes selection only. It does not admit model/target work,
alter the signed post-Worker path, or grant vulnerability credit.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterable

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OBJECT_ID = re.compile(r"[0-9a-f]{24}\Z")


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _private_run_dir(path: Path) -> bool:
    try:
        return (path.is_absolute() and path == path.resolve(strict=True) and
                path.is_dir() and not path.is_symlink() and
                path.stat().st_uid == os.getuid() and
                stat.S_IMODE(path.stat().st_mode) == 0o700)
    except (OSError, RuntimeError, ValueError):
        return False


def freeze_parallel_hp_selection(
    *, run_dir: Path, task_id: str, run_id: str, fuzzer: str,
    spec_sha256: str, direction_plan_sha256: str,
    function_catalog_sha256: str,
    directions: Iterable[Direction], functions: Iterable[Function],
) -> tuple[tuple[Function, Direction] | None, str]:
    """Pin one pre-SP Function/Direction pair from the shared preparation.

    Direction order is the verified plan order. Within a Direction, model
    core functions precede entry functions. Each name resolves through the
    pinned Function catalog. SP's mutable analysis marker is deliberately
    excluded from the identity so concurrent SP progress cannot invalidate
    an otherwise unchanged HP selection.
    """
    run_dir = Path(run_dir)
    if (not _private_run_dir(run_dir) or
            any(type(value) is not str or not _OBJECT_ID.fullmatch(value)
                for value in (task_id, run_id)) or
            type(fuzzer) is not str or not fuzzer or
            any(type(value) is not str or not _SHA256.fullmatch(value)
                for value in (spec_sha256, direction_plan_sha256,
                              function_catalog_sha256))):
        raise ValueError("PARALLEL_HP_SELECTION_IDENTITY_INVALID")
    directions = list(directions)
    functions = list(functions)
    if any(type(row) is not Direction for row in directions):
        raise ValueError("PARALLEL_HP_CATALOG_INVALID")
    eligible_names = {
        name for row in directions
        for name in [*(row.core_functions or []),
                     *(row.entry_functions or [])]
        if type(name) is str
    }
    if (not directions or
            any(type(row) is not Direction or row.task_id != task_id or
                row.fuzzer != fuzzer or not row.direction_id or
                any(type(name) is not str or not name for name in
                    [*(row.core_functions or []), *(row.entry_functions or [])])
                for row in directions) or
            len({row.direction_id for row in directions}) != len(directions) or
            any(type(row) is not Function or row.task_id != task_id or
                not row.function_id or not row.name or not row.file_path or
                type(row.start_line) is not int or
                type(row.end_line) is not int or
                not (row.start_line >= 1 and
                     row.end_line >= row.start_line or
                     row.name == fuzzer and row.name not in eligible_names and
                     row.start_line == row.end_line == 0)
                for row in functions) or
            len({row.function_id for row in functions}) != len(functions) or
            len({row.name for row in functions}) != len(functions)):
        raise ValueError("PARALLEL_HP_CATALOG_INVALID")

    by_name = {row.name: row for row in functions}
    selected = None
    eligible = []
    for direction in directions:
        for name in dict.fromkeys([*(direction.core_functions or []),
                                   *(direction.entry_functions or [])]):
            function = by_name.get(name)
            if function is None:
                continue
            eligible.append([function.function_id, direction.direction_id])
            if selected is None:
                selected = (function, direction)

    catalog = sorted(({
        "function_id": row.function_id, "name": row.name,
        "file_path": row.file_path, "start_line": row.start_line,
        "end_line": row.end_line, "language": row.language,
    } for row in functions), key=lambda row: row["function_id"])
    plan = [{"direction_id": row.direction_id,
             "core_functions": list(row.core_functions or []),
             "entry_functions": list(row.entry_functions or [])}
            for row in directions]
    receipt = {
        "kind": "FBV2_PARALLEL_HP_PRE_SP_SELECTION_V1",
        "task_id": task_id, "run_id": run_id, "fuzzer": fuzzer,
        "spec_sha256": spec_sha256,
        "direction_plan_sha256": direction_plan_sha256,
        "function_catalog_sha256": function_catalog_sha256,
        "catalog_metadata_sha256": hashlib.sha256(_canonical(catalog)).hexdigest(),
        "plan_metadata_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
        "eligible_pairs": eligible,
        "selected_pair": (list(eligible[0]) if eligible else None),
        "selection_status": ("SELECTED" if eligible else
                             "HP_NO_ELIGIBLE_FUNCTION"),
        "selection_policy": "PLAN_ORDER_CORE_THEN_ENTRY_PRE_SP_V1",
        "model_calls": 0, "target_calls": 0,
    }
    data = _canonical(receipt)
    path = run_dir / "HP_PARALLEL_SELECTION.json"
    if path.exists() or path.is_symlink():
        if (path.is_symlink() or not path.is_file() or
                path.stat().st_uid != os.getuid() or
                stat.S_IMODE(path.stat().st_mode) != 0o600 or
                path.read_bytes() != data):
            raise ValueError("PARALLEL_HP_SELECTION_CHANGED")
    else:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600)
        except FileExistsError as exc:
            raise ValueError("PARALLEL_HP_SELECTION_CHANGED") from exc
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return selected, hashlib.sha256(data).hexdigest()


def claim_parallel_hp_execution(
    *, run_dir: Path, task_id: str, run_id: str,
    spec_sha256: str, selection_receipt_sha256: str,
) -> str:
    """Consume one selected HP opportunity before constructing role clients.

    A matching existing claim is still a duplicate. The caller must never
    infer that the old attempt did not reach a remote model or target.
    """
    run_dir = Path(run_dir)
    if (not _private_run_dir(run_dir) or
            any(type(value) is not str or not _OBJECT_ID.fullmatch(value)
                for value in (task_id, run_id)) or
            any(type(value) is not str or not _SHA256.fullmatch(value)
                for value in (spec_sha256, selection_receipt_sha256))):
        raise ValueError("PARALLEL_HP_CLAIM_IDENTITY_INVALID")
    selection_path = run_dir / "HP_PARALLEL_SELECTION.json"
    if (selection_path.is_symlink() or not selection_path.is_file() or
            selection_path.stat().st_uid != os.getuid() or
            stat.S_IMODE(selection_path.stat().st_mode) != 0o600):
        raise ValueError("PARALLEL_HP_SELECTION_UNAVAILABLE")
    raw = selection_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != selection_receipt_sha256:
        raise ValueError("PARALLEL_HP_SELECTION_CHANGED")
    try:
        selection = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("PARALLEL_HP_SELECTION_INVALID") from exc
    pair = selection.get("selected_pair") if type(selection) is dict else None
    eligible = selection.get("eligible_pairs") if type(selection) is dict else None
    if (type(selection) is not dict or
            selection.get("kind") != "FBV2_PARALLEL_HP_PRE_SP_SELECTION_V1" or
            selection.get("task_id") != task_id or
            selection.get("run_id") != run_id or
            selection.get("spec_sha256") != spec_sha256 or
            selection.get("selection_status") != "SELECTED" or
            selection.get("model_calls") != 0 or
            selection.get("target_calls") != 0 or
            type(pair) is not list or len(pair) != 2 or
            any(type(value) is not str or not value for value in pair) or
            type(eligible) is not list or not eligible or eligible[0] != pair):
        raise ValueError("PARALLEL_HP_SELECTION_INVALID")
    claim = {
        "kind": "FBV2_PARALLEL_HP_RUN_CLAIM_V1",
        "task_id": task_id, "run_id": run_id,
        "spec_sha256": spec_sha256,
        "selection_receipt_sha256": selection_receipt_sha256,
        "selected_pair": pair,
        "model_calls": 0, "target_calls": 0,
    }
    data = _canonical(claim)
    path = run_dir / "HP_PARALLEL_RUN_CLAIM.json"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
    except FileExistsError as exc:
        raise ValueError("PARALLEL_HP_ALREADY_CLAIMED") from exc
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return hashlib.sha256(data).hexdigest()


def verify_parallel_hp_execution_claim(
    *, run_dir: Path, task_id: str, run_id: str, spec_sha256: str,
    function_id: str, direction_id: str,
    direction_plan_sha256: str, function_catalog_sha256: str,
    selection_receipt_sha256: str, execution_claim_sha256: str,
) -> bool:
    """Re-read both private receipts before an HP model or physical step."""
    run_dir = Path(run_dir)
    if (not _private_run_dir(run_dir) or
            any(type(value) is not str or not value for value in
                (task_id, run_id, function_id, direction_id)) or
            any(type(value) is not str or not _SHA256.fullmatch(value)
            for value in (spec_sha256, direction_plan_sha256,
                          function_catalog_sha256,
                          selection_receipt_sha256, execution_claim_sha256))):
        return False
    rows = []
    for name, expected_sha in (
            ("HP_PARALLEL_SELECTION.json", selection_receipt_sha256),
            ("HP_PARALLEL_RUN_CLAIM.json", execution_claim_sha256)):
        path = run_dir / name
        try:
            if (path.is_symlink() or not path.is_file() or
                    path.stat().st_uid != os.getuid() or
                    stat.S_IMODE(path.stat().st_mode) != 0o600):
                return False
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_sha:
                return False
            row = json.loads(raw)
            if type(row) is not dict or _canonical(row) != raw:
                return False
            rows.append(row)
        except (OSError, UnicodeError, TypeError, ValueError,
                json.JSONDecodeError):
            return False
    selection, claim = rows
    pair = [function_id, direction_id]
    eligible = selection.get("eligible_pairs")
    return (
        selection.get("kind") == "FBV2_PARALLEL_HP_PRE_SP_SELECTION_V1" and
        selection.get("task_id") == task_id and
        selection.get("run_id") == run_id and
        selection.get("spec_sha256") == spec_sha256 and
        selection.get("direction_plan_sha256") == direction_plan_sha256 and
        selection.get("function_catalog_sha256") ==
            function_catalog_sha256 and
        selection.get("selection_status") == "SELECTED" and
        selection.get("selected_pair") == pair and
        type(eligible) is list and bool(eligible) and eligible[0] == pair and
        selection.get("model_calls") == 0 and
        selection.get("target_calls") == 0 and
        set(claim) == {"kind", "task_id", "run_id", "spec_sha256",
                       "selection_receipt_sha256", "selected_pair",
                       "model_calls", "target_calls"} and
        claim.get("kind") == "FBV2_PARALLEL_HP_RUN_CLAIM_V1" and
        claim.get("task_id") == task_id and
        claim.get("run_id") == run_id and
        claim.get("spec_sha256") == spec_sha256 and
        claim.get("selection_receipt_sha256") == selection_receipt_sha256 and
        claim.get("selected_pair") == pair and
        claim.get("model_calls") == 0 and claim.get("target_calls") == 0)
