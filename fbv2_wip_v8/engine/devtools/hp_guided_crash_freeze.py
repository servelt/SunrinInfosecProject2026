"""Freeze an HP Guided crash *lead* under its own identity.

This step performs no replay and grants no Gate or discovery credit.  A later
HP Gate must re-read the frozen input and all receipts before deciding anything.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _regular_bytes(path: Path, root: Path, limit: int) -> bytes:
    """Read one local regular file from an already trusted output directory."""
    if (not path.is_absolute() or not root.is_absolute() or
            path != path.resolve(strict=True) or
            not path.is_relative_to(root) or
            any(part.is_symlink() for part in (path, *path.parents))):
        raise ValueError("HP evidence path is not canonical and local")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or before.st_size > limit):
            raise ValueError("HP evidence file is not an admitted regular file")
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise ValueError("HP evidence file exceeds size limit")
        after = os.fstat(fd)
        linked = os.lstat(path)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if (identity(before) != identity(after) or
                identity(after) != identity(linked)):
            raise ValueError("HP evidence changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _regular_sha(path: Path, root: Path, limit: int) -> str:
    """Hash a potentially large binary without retaining it in memory."""
    if (not path.is_absolute() or not root.is_absolute() or
            path != path.resolve(strict=True) or
            not path.is_relative_to(root) or
            any(part.is_symlink() for part in (path, *path.parents))):
        raise ValueError("HP binary path is not canonical and local")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or before.st_size > limit):
            raise ValueError("HP binary is not an admitted regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError("HP binary exceeds size limit")
            digest.update(chunk)
        after = os.fstat(fd)
        linked = os.lstat(path)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if (identity(before) != identity(after) or
                identity(after) != identity(linked)):
            raise ValueError("HP binary changed during read")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate HP report key")
        result[key] = value
    return result


def freeze_hp_guided_crash_lead(
    *, handoff: dict[str, Any], task_id: str, run_id: str,
    worker_id: str, function_id: str, direction_id: str,
    assertion_id: str, guided_dir: Path, crash_path: Path,
    claim_root: Path, process_ledger: Any,
) -> dict[str, Any]:
    """Create a one-shot frozen input and receipt for a Guided crash lead.

    The caller supplies trusted HP IDs and the owner ledger.  The disk report,
    selected file, producer pin and finished Guided process must all agree.
    No sanitizer or source/impact judgment is made here.
    """
    from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2

    ids = (task_id, run_id, worker_id, function_id, direction_id, assertion_id)
    if (any(type(value) is not str or not _ID.fullmatch(value) for value in ids) or
            type(handoff) is not dict or
            handoff.get("status") != "HP_GUIDED_CRASH_OBSERVED_UNGATED" or
            handoff.get("function_id") != function_id or
            handoff.get("direction_id") != direction_id or
            handoff.get("assertion_id") != assertion_id or
            handoff.get("security_gate_credit") != "NOT_CREDITED" or
            handoff.get("discovery_credit") != "NOT_CREDITED" or
            handoff.get("sp_global_effect") != "UNCHANGED" or
            type(process_ledger) is not PersistentProcessLedgerV2):
        raise ValueError("HP handoff or owner identity is invalid")
    guided_dir = Path(guided_dir)
    crash_path = Path(crash_path)
    claim_root = Path(claim_root)
    if (not guided_dir.is_absolute() or guided_dir.is_symlink() or
            guided_dir != guided_dir.resolve(strict=True) or
            not claim_root.is_absolute() or claim_root.is_symlink() or
            claim_root != claim_root.resolve(strict=False)):
        raise ValueError("HP evidence root is invalid")
    report_path = guided_dir / "guided_fuzz.json"
    report_raw = _regular_bytes(report_path, guided_dir, 16_000_000)
    report = json.loads(report_raw, object_pairs_hook=_unique_pairs)
    if (type(report) is not dict or report != handoff.get("guided_report") or
            report.get("assertion_id") != assertion_id or
            handoff.get("physical_observations", {}).get(
                "guided_crash_observed_ungated") is not True):
        raise ValueError("HP Guided report is not bound to the handoff")
    initial_crash = (report.get("status") == "CRASH_OBSERVED_INCOMPLETE" or
                     report.get("initial_segment_status") ==
                     "CRASH_OBSERVED_INCOMPLETE")
    continuation = report.get("continuation")
    continuation_crash = (type(continuation) is dict and
                          continuation.get("status") ==
                          "CRASH_OBSERVED_INCOMPLETE")
    selected = str(crash_path)
    segment = None
    pins = None
    initial_artifacts = report.get("other_crash_artifacts")
    continuation_artifacts = (continuation.get("crash_artifacts")
                              if type(continuation) is dict else None)
    if (initial_crash and type(initial_artifacts) is list and
            selected in initial_artifacts):
        segment = "initial"
        pins = report.get("other_crash_artifact_pins")
    elif (continuation_crash and type(continuation_artifacts) is list and
          selected in continuation_artifacts):
        segment = "continuation"
        pins = continuation.get("crash_artifact_pins")
    if (segment is None or type(pins) is not list or
            sum(type(row) is dict and row.get("path") == selected
                for row in pins) != 1 or
            not crash_path.name.startswith("crash-")):
        raise ValueError("HP selected input is not a unique crash lead")
    pin = next(row for row in pins if type(row) is dict and row.get("path") == selected)
    expected_sha = pin.get("sha256")
    if type(expected_sha) is not str or not _SHA.fullmatch(expected_sha):
        raise ValueError("HP selected input has no valid producer pin")
    input_raw = _regular_bytes(crash_path, guided_dir, 2_097_152)
    if hashlib.sha256(input_raw).hexdigest() != expected_sha:
        raise ValueError("HP crash input differs from producer pin")
    runtime_path = (guided_dir / "fuzzer-runtime.json" if segment == "initial" else
                    guided_dir / "continuation" / "fuzzer-runtime.json")
    reported_runtime_path = (report.get("fuzzer_runtime") if segment == "initial"
                             else continuation.get("runtime_artifact"))
    if reported_runtime_path != str(runtime_path):
        raise ValueError("HP Guided runtime path differs from report")
    runtime_raw = _regular_bytes(runtime_path, guided_dir, 16_000_000)
    runtime = json.loads(runtime_raw, object_pairs_hook=_unique_pairs)
    if (type(runtime) is not dict or
            type(runtime.get("sanitizer")) is not str or
            not runtime["sanitizer"] or
            type(runtime.get("stderr")) is not str or
            type(runtime.get("timed_out")) is not bool or
            runtime["timed_out"] or
            type(runtime.get("exit_code")) is not int or
            runtime.get("failure_classification") == "ENVIRONMENT_ERROR"):
        raise ValueError("HP Guided runtime does not prove a completed sanitizer crash")
    from vulnerabilityanalysis.runtime import parse_sanitizer, asan_resource_kind
    if (parse_sanitizer(runtime["stderr"]) != runtime["sanitizer"] or
            asan_resource_kind(runtime["sanitizer"], runtime["stderr"]) is not None):
        raise ValueError("HP Guided sanitizer report differs from runtime")
    reported_exit = (report.get("fuzzer_exit_code") if segment == "initial"
                     else continuation.get("exit_code"))
    reported_timeout = (report.get("fuzzer_timed_out") if segment == "initial"
                        else continuation.get("timed_out"))
    if (reported_exit != runtime["exit_code"] or
            reported_timeout is not runtime["timed_out"]):
        raise ValueError("HP Guided segment result differs from runtime")
    binary_path = (guided_dir / "guided-target" if segment == "initial" else
                   guided_dir / "continuation" / "guided-target")
    reported_binary_path = (report.get("binary") if segment == "initial" else
                            continuation.get("binary"))
    if reported_binary_path != str(binary_path):
        raise ValueError("HP Guided binary path differs from report")
    binary_sha = _regular_sha(binary_path, guided_dir, 512_000_000)
    state, ledger_sha = process_ledger.receipt_snapshot()
    prefix = f"{task_id}:{assertion_id}:{run_id}:"
    if type(state) is not dict:
        raise ValueError("HP Process Ledger snapshot is invalid")
    # receipt_snapshot already proved the on-disk checkpoint under its owner
    # lock. Re-encode that exact returned state; re-reading the live ledger
    # here would race unrelated SP reservations in a parallel campaign.
    raw_state = {key: value for key, value in state.items()
                 if key not in {"wall_reserved_seconds",
                                "fuzz_reserved_seconds"}}
    ledger_raw = process_ledger._encode(raw_state)
    if hashlib.sha256(ledger_raw).hexdigest() != ledger_sha:
        raise ValueError("HP Process Ledger changed during freeze")
    needed_suffix = (":guided.initial_campaign" if segment == "initial" else
                     ":guided.continuation_campaign")
    finished = state.get("finished") if type(state) is dict else None
    matching = ([row for row in finished if type(row) is dict and
                 type(row.get("key")) is str and
                 row["key"].startswith(prefix) and
                 row["key"].endswith(needed_suffix)]
                if type(finished) is list else [])
    active = state.get("active") if type(state) is dict else None
    if (type(state) is not dict or state.get("stop_status") is not None or
            type(active) is not dict or
            any(key.startswith(prefix) for key in active) or
            len(matching) != 1 or matching[0].get("kind") != "HP_FUZZ" or
            matching[0].get("cleanup_complete") is not True or
            matching[0].get("output_limited") is not False or
            matching[0].get("overrun") is not False):
        raise ValueError("HP Guided physical process is not settled")
    input_sha = hashlib.sha256(input_raw).hexdigest()
    # One run/segment/path gets one attempt even if its bytes and report are
    # later rewritten. The digest is evidence, not part of the claim key.
    claim_id = hashlib.sha256(("\0".join((*ids, segment, selected)))
                              .encode()).hexdigest()
    if any(parent.is_symlink() for parent in claim_root.parents):
        raise ValueError("HP claim root parent is linked")
    claim_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _sync_dir(claim_root.parent)
    claim_dir = claim_root / claim_id
    claim_dir.mkdir(mode=0o700, exist_ok=False)
    _sync_dir(claim_root)
    frozen_path = claim_dir / "input.bin"
    _write_new(frozen_path, input_raw)
    ledger_snapshot_path = claim_dir / "process-ledger-before.json"
    _write_new(ledger_snapshot_path, ledger_raw)
    receipt = {
        "kind": "FBV2_HP_GUIDED_CRASH_LEAD_V1",
        "status": "HP_CRASH_INPUT_FROZEN_UNVERIFIED",
        "task_id": task_id, "run_id": run_id, "worker_id": worker_id,
        "function_id": function_id, "direction_id": direction_id,
        "assertion_id": assertion_id, "segment": segment,
        "input_path": str(crash_path), "input_sha256": input_sha,
        "frozen_input_path": str(frozen_path),
        "guided_report_path": str(report_path),
        "guided_report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "guided_runtime_path": str(runtime_path),
        "guided_runtime_sha256": hashlib.sha256(runtime_raw).hexdigest(),
        "guided_binary_path": str(binary_path),
        "guided_binary_sha256": binary_sha,
        "process_ledger_sha256": ledger_sha,
        "process_ledger_path": str(process_ledger.path),
        "process_ledger_snapshot_path": str(ledger_snapshot_path),
        "process_ledger_snapshot_sha256": ledger_sha,
        "guided_process_key": matching[0]["key"],
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    receipt_path = claim_dir / "claim.json"
    receipt_sha = _write_new(receipt_path, (json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode())
    _sync_dir(claim_dir)
    return {**receipt, "claim_path": str(receipt_path),
            "claim_sha256": receipt_sha}


def freeze_reported_hp_guided_crash_leads(
    *, handoff: dict[str, Any], task_id: str, run_id: str,
    worker_id: str, function_id: str, direction_id: str,
    assertion_id: str, guided_dir: Path, claim_root: Path,
    process_ledger: Any,
) -> dict[str, Any]:
    """Attempt every reported input once; retain failures and Gate noncredit."""
    if (type(handoff) is not dict or
            handoff.get("status") != "HP_GUIDED_CRASH_OBSERVED_UNGATED"):
        raise ValueError("HP handoff has no Guided crash observation")
    report = handoff.get("guided_report")
    if type(report) is not dict:
        raise ValueError("HP handoff Guided report is invalid")
    initial = report.get("other_crash_artifacts")
    continuation = report.get("continuation")
    later = (continuation.get("crash_artifacts")
             if type(continuation) is dict else None)
    paths = []
    for rows in (initial, later):
        if rows is None:
            continue
        if type(rows) is not list or any(type(item) is not str for item in rows):
            raise ValueError("HP crash artifact list is invalid")
        paths.extend(rows)
    paths = sorted(set(paths))
    frozen = []
    rejected = []
    for name in paths:
        try:
            frozen.append(freeze_hp_guided_crash_lead(
                handoff=handoff, task_id=task_id, run_id=run_id,
                worker_id=worker_id, function_id=function_id,
                direction_id=direction_id, assertion_id=assertion_id,
                guided_dir=guided_dir, crash_path=Path(name),
                claim_root=claim_root, process_ledger=process_ledger))
        except (OSError, ValueError, TypeError) as exc:
            rejected.append({"path": name, "error_type": type(exc).__name__})
    return {
        "status": ("HP_CRASH_LEADS_FROZEN_UNVERIFIED" if frozen and not rejected else
                   "INCOMPLETE_HP_CRASH_LEAD_FREEZE"),
        "reported_lead_count": len(paths),
        "frozen_leads": frozen,
        "rejected_leads": rejected,
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }


def admit_hp_original_replay(
    *, lead: dict[str, Any], physical_claim_path: Path,
    physical_claim_sha256: str, qualification: Any,
    process_ledger: Any,
) -> dict[str, Any]:
    """Re-prove frozen HP evidence and qualified original target before replay.

    Admission is read-only. It does not execute the target or issue a Gate
    decision; the caller must still make a separate one-shot replay claim.
    """
    from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
    from vulnerabilityanalysis.official_harness import (
        OfficialPinnedQualification, _qualification_pins_ok)

    if (type(lead) is not dict or
            lead.get("status") != "HP_CRASH_INPUT_FROZEN_UNVERIFIED" or
            lead.get("security_gate_credit") != "NOT_CREDITED" or
            lead.get("discovery_credit") != "NOT_CREDITED" or
            type(process_ledger) is not PersistentProcessLedgerV2 or
            not isinstance(qualification, OfficialPinnedQualification) or
            qualification.product_issued is not True or
            not _qualification_pins_ok(qualification)):
        raise ValueError("HP frozen lead or official qualification is invalid")
    claim_path = Path(lead.get("claim_path", ""))
    expected_claim_sha = lead.get("claim_sha256")
    if (claim_path.name != "claim.json" or
            type(expected_claim_sha) is not str or
            not _SHA.fullmatch(expected_claim_sha)):
        raise ValueError("HP frozen claim locator is invalid")
    claim_raw = _regular_bytes(claim_path, claim_path.parent, 16_000_000)
    claim = json.loads(claim_raw, object_pairs_hook=_unique_pairs)
    expected_row = {key: value for key, value in lead.items()
                    if key not in {"claim_path", "claim_sha256"}}
    if (type(claim) is not dict or claim != expected_row or
            hashlib.sha256(claim_raw).hexdigest() != expected_claim_sha or
            claim.get("kind") != "FBV2_HP_GUIDED_CRASH_LEAD_V1"):
        raise ValueError("HP frozen claim differs from returned evidence")
    frozen_input = claim_path.parent / "input.bin"
    if claim.get("frozen_input_path") != str(frozen_input):
        raise ValueError("HP frozen input locator is invalid")
    input_raw = _regular_bytes(frozen_input, claim_path.parent, 2_097_152)
    if hashlib.sha256(input_raw).hexdigest() != claim.get("input_sha256"):
        raise ValueError("HP frozen input changed")
    report_path = Path(claim.get("guided_report_path", ""))
    guided_dir = report_path.parent
    if (report_path.name != "guided_fuzz.json" or
            hashlib.sha256(_regular_bytes(
                report_path, guided_dir, 16_000_000)).hexdigest() !=
            claim.get("guided_report_sha256")):
        raise ValueError("HP Guided report changed after freeze")
    runtime_path = Path(claim.get("guided_runtime_path", ""))
    if (hashlib.sha256(_regular_bytes(
            runtime_path, guided_dir, 16_000_000)).hexdigest() !=
            claim.get("guided_runtime_sha256")):
        raise ValueError("HP Guided runtime changed after freeze")
    binary_path = Path(claim.get("guided_binary_path", ""))
    if (_regular_sha(binary_path, guided_dir, 512_000_000) != claim.get(
            "guided_binary_sha256")):
        raise ValueError("HP instrumented binary changed after freeze")
    parent_path = Path(physical_claim_path)
    if (parent_path.name != "HP_PHYSICAL_CLAIM.json" or
            type(physical_claim_sha256) is not str or
            not _SHA.fullmatch(physical_claim_sha256)):
        raise ValueError("HP parent physical claim locator is invalid")
    parent_raw = _regular_bytes(parent_path, parent_path.parent, 16_000_000)
    parent = json.loads(parent_raw, object_pairs_hook=_unique_pairs)
    if (hashlib.sha256(parent_raw).hexdigest() != physical_claim_sha256 or
            type(parent) is not dict or
            parent.get("kind") != "FBV2_HP_PHYSICAL_CLAIM_V1" or
            any(parent.get(key) != claim.get(key) for key in (
                "task_id", "run_id", "worker_id", "function_id",
                "direction_id", "assertion_id")) or
            type(parent.get("assertion_selection")) is not dict or
            parent["assertion_selection"].get(
                "selected_assertion_id") != claim.get("assertion_id") or
            parent.get("binary_sha256") != qualification.binary_sha256 or
            parent.get("harness_sha256") != qualification.harness_sha256 or
            parent.get("source_tree_sha256") != qualification.source_tree_sha256 or
            claim.get("process_ledger_path") != str(process_ledger.path)):
        raise ValueError("HP frozen lead differs from physical claim or target")
    original_binary = Path(qualification.binary)
    normal_seed = Path(qualification.normal_seed)
    if (_regular_sha(original_binary, original_binary.parent, 512_000_000) !=
            qualification.binary_sha256 or
            hashlib.sha256(_regular_bytes(
                normal_seed, normal_seed.parent, 2_097_152)).hexdigest() !=
            qualification.normal_seed_sha256):
        raise ValueError("HP qualified original binary or normal seed changed")
    snapshot_path = claim_path.parent / "process-ledger-before.json"
    if (claim.get("process_ledger_snapshot_path") != str(snapshot_path) or
            claim.get("process_ledger_snapshot_sha256") !=
                claim.get("process_ledger_sha256")):
        raise ValueError("HP frozen Process Ledger snapshot locator changed")
    snapshot_raw = _regular_bytes(snapshot_path, claim_path.parent, 16_000_000)
    if hashlib.sha256(snapshot_raw).hexdigest() != claim.get(
            "process_ledger_snapshot_sha256"):
        raise ValueError("HP frozen Process Ledger snapshot changed")
    frozen_ledger = json.loads(snapshot_raw, object_pairs_hook=_unique_pairs)
    from dev_persistent_process_ledger_v2 import _validate as validate_ledger
    validate_ledger(frozen_ledger)
    ledger_state, ledger_sha = process_ledger.receipt_snapshot()
    saved_finished = frozen_ledger.get("finished")
    current_finished = ledger_state.get("finished")
    active = ledger_state.get("active")
    prefix = (f"{claim['task_id']}:{claim['assertion_id']}:"
              f"{claim['run_id']}:")
    if (type(saved_finished) is not list or
            type(current_finished) is not list or
            current_finished[:len(saved_finished)] != saved_finished or
            ledger_state.get("revision", -1) < frozen_ledger["revision"] or
            ledger_state.get("stop_status") is not None or
            type(active) is not dict or
            any(key.startswith(prefix) for key in active) or
            not any(type(row) is dict and
                    row.get("key") == claim.get("guided_process_key") and
                    row.get("kind") == "HP_FUZZ" and
                    row.get("cleanup_complete") is True and
                    row.get("output_limited") is False and
                    row.get("overrun") is False
                    for row in current_finished)):
        raise ValueError("HP frozen lead Process Ledger changed or is unsettled")
    return {
        "status": "HP_ORIGINAL_REPLAY_ADMITTED_UNVERIFIED",
        "lead_claim_path": str(claim_path),
        "lead_claim_sha256": expected_claim_sha,
        "physical_claim_path": str(parent_path),
        "physical_claim_sha256": physical_claim_sha256,
        "task_id": claim["task_id"], "run_id": claim["run_id"],
        "worker_id": claim["worker_id"],
        "function_id": claim["function_id"],
        "direction_id": claim["direction_id"],
        "assertion_id": claim["assertion_id"],
        "input_path": str(frozen_input),
        "input_sha256": claim["input_sha256"],
        "original_binary_path": str(qualification.binary),
        "original_binary_sha256": qualification.binary_sha256,
        "normal_seed_path": str(qualification.normal_seed),
        "normal_seed_sha256": qualification.normal_seed_sha256,
        "source_tree_sha256": qualification.source_tree_sha256,
        "harness_sha256": qualification.harness_sha256,
        "process_ledger_path": str(process_ledger.path),
        "process_ledger_sha256_at_freeze": claim["process_ledger_sha256"],
        "process_ledger_sha256": ledger_sha,
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
