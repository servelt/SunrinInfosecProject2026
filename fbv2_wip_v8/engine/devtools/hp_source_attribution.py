"""Account for HP-origin source attribution after an exact original replay.

This stage can identify a target source frame. It never grants security or
discovery credit; an HP-specific security-property Gate remains separate.
"""

from __future__ import annotations

from dataclasses import asdict, fields
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from devtools.hp_guided_crash_freeze import (
    _regular_bytes, _sync_dir, _unique_pairs, _write_new)
from devtools.hp_original_replay import reprove_hp_original_replay


def attribute_hp_replayed_crash_source(
    *, replay_result: dict[str, Any], lead: dict[str, Any],
    physical_claim_path: Path, physical_claim_sha256: str,
    qualification: Any, process_ledger: Any, output_dir: Path,
    wall_seconds: float, output_limit_bytes: int,
) -> dict[str, Any]:
    """Run Product DWARF source triage under a one-shot HP process claim."""
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.direct_input import probe_libfuzzer_callback
    from vulnerabilityanalysis.official_harness import _qualification_pins_ok
    from vulnerabilityanalysis.runtime import (
        CLEAN_RUNTIME_ENVIRONMENT, triage_crash)

    if (type(wall_seconds) not in (int, float) or
            not math.isfinite(wall_seconds) or wall_seconds <= 0 or
            type(output_limit_bytes) is not int or
            not 0 < output_limit_bytes <= 16_000_000):
        raise ValueError("HP source attribution budget is invalid")
    proof_args = dict(replay_result=replay_result, lead=lead,
                      physical_claim_path=physical_claim_path,
                      physical_claim_sha256=physical_claim_sha256,
                      qualification=qualification,
                      process_ledger=process_ledger)
    proof = reprove_hp_original_replay(**proof_args)
    if (proof.get("status") !=
            "HP_REPLAY_EVIDENCE_REPROVED_PENDING_SECURITY" or
            not _qualification_pins_ok(qualification)):
        raise ValueError("HP source attribution requires physical replay")
    replay_path = Path(replay_result["result_path"])
    primary_path = replay_path.parent / "original_observation-runtime.json"
    primary_raw = _regular_bytes(primary_path, replay_path.parent, 16_000_000)
    primary_row = replay_result["observations"][1]
    if (primary_row.get("runtime_path") != str(primary_path) or
            hashlib.sha256(primary_raw).hexdigest() !=
                primary_row.get("runtime_sha256")):
        raise ValueError("HP source primary runtime changed")
    primary_payload = json.loads(primary_raw, object_pairs_hook=_unique_pairs)
    if type(primary_payload) is not dict or set(primary_payload) != {
            field.name for field in fields(RuntimeResult)}:
        raise ValueError("HP source primary runtime schema differs")
    primary = RuntimeResult(**primary_payload)
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.is_symlink() or
            output_dir != output_dir.resolve(strict=False) or
            any(parent.is_symlink() for parent in output_dir.parents)):
        raise ValueError("HP source attribution output path is invalid")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    _sync_dir(output_dir.parent)
    claim = {
        "kind": "FBV2_HP_SOURCE_ATTRIBUTION_CLAIM_V1",
        "status": "STARTED",
        "task_id": proof["task_id"], "run_id": proof["run_id"],
        "assertion_id": proof["assertion_id"],
        "replay_result_path": str(replay_path),
        "replay_result_sha256": replay_result["result_sha256"],
        "primary_runtime_sha256": hashlib.sha256(primary_raw).hexdigest(),
        "input_sha256": proof["input_sha256"],
        "original_binary_sha256": proof["original_binary_sha256"],
        "source_tree_sha256": qualification.source_tree_sha256,
        "harness_sha256": qualification.harness_sha256,
        "process_ledger_path": str(process_ledger.path),
        "source_inventory_environment": dict(CLEAN_RUNTIME_ENVIRONMENT),
        "wall_seconds": float(wall_seconds),
        "output_limit_bytes": output_limit_bytes,
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    claim_raw = (json.dumps(claim, sort_keys=True, separators=(",", ":"),
                            allow_nan=False) + "\n").encode()
    claim_path = output_dir / "HP_SOURCE_CLAIM.json"
    claim_sha = _write_new(claim_path, claim_raw)
    _sync_dir(output_dir)

    def pin(_phase: str, _command: list[str]) -> None:
        current = reprove_hp_original_replay(**proof_args)
        if (current != proof or not _qualification_pins_ok(qualification) or
                hashlib.sha256(_regular_bytes(
                    claim_path, output_dir, 16_000_000)).hexdigest() !=
                claim_sha):
            raise ValueError("HP source attribution pin changed")

    prefix_id = "hp_source_" + hashlib.sha256(
        str(replay_path).encode()).hexdigest()[:24]
    try:
        envelope = DevelopmentProcessEnvelopeV2(
            process_ledger, work_item_id=proof["task_id"],
            assertion_id=prefix_id, attempt_id=proof["run_id"],
            output_limit_bytes=output_limit_bytes,
            total_wall_seconds=wall_seconds, pin_hook=pin,
            wall_limit_scope="LOCAL")
        triage = triage_crash(
            primary, str(qualification.source_root),
            str(qualification.harness),
            target_binary=Path(qualification.binary),
            process_envelope=envelope,
            source_inventory_env=dict(CLEAN_RUNTIME_ENVIRONMENT))
        input_path = Path(lead["frozen_input_path"])
        input_raw = _regular_bytes(input_path, input_path.parent, 2_097_152)
        if hashlib.sha256(input_raw).hexdigest() != proof["input_sha256"]:
            raise ValueError("HP source callback input differs from replay")
        callback = probe_libfuzzer_callback(
            Path(qualification.binary), input_path,
            process_envelope=envelope,
            env=dict(CLEAN_RUNTIME_ENVIRONMENT))
        pin("after_triage", [])
        state, ledger_sha = process_ledger.receipt_snapshot()
        prefix = f"{proof['task_id']}:{prefix_id}:{proof['run_id']}:"
        active = state.get("active")
        rows = [row for row in state.get("finished", []) if
                type(row) is dict and
                type(row.get("key")) is str and
                row["key"].startswith(prefix)]
        if (state.get("stop_status") is not None or
                type(active) is not dict or
                any(key.startswith(prefix) for key in active) or
                any(row.get("kind") != "AUX_PROCESS" or
                    not row["key"].endswith((
                        ":assertion.gdb_source_inventory",
                        ":harness.callback_probe")) or
                    row.get("cleanup_complete") is not True or
                    row.get("output_limited") is not False or
                    row.get("overrun") is not False for row in rows)):
            raise ValueError("HP source inventory process is unsettled")
        provenance = (triage.get("source_provenance")
                      if type(triage) is dict else None)
        attributed = (type(triage) is dict and
                      triage.get("category") == "TARGET_CRASH" and
                      triage.get("sp_linked") is False and
                      triage.get("verification_eligible") is False and
                      type(provenance) is dict and
                      provenance.get("method") ==
                          "DWARF_PATH_RELATIVE_PATH_SHA256" and
                      provenance.get("binary") ==
                          str(Path(qualification.binary).resolve()) and
                      type(provenance.get("sha256")) is str and
                      any(row["key"].endswith(
                          ":assertion.gdb_source_inventory")
                          for row in rows))
        if attributed:
            source = Path(provenance["checkout_source"])
            observed = Path(provenance["observed_source"])
            attributed = (source.is_file() and observed.is_file() and
                          source.resolve().is_relative_to(
                              Path(qualification.source_root).resolve()) and
                          hashlib.sha256(source.read_bytes()).hexdigest() ==
                              provenance["sha256"] and
                          hashlib.sha256(observed.read_bytes()).hexdigest() ==
                              provenance["sha256"])
        callback_row = any(row["key"].endswith(":harness.callback_probe")
                           for row in rows)
        delivery_measured = (callback_row and callback.measured is True and
                             callback.input_size == len(input_raw) and
                             callback.input_sha256 == proof["input_sha256"])
        status = ("HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY" if
                  attributed else "HP_SOURCE_UNPROVEN_PENDING_SECURITY")
        result = {
            "kind": "FBV2_HP_SOURCE_ATTRIBUTION_RESULT_V1",
            "status": status, "task_id": proof["task_id"],
            "run_id": proof["run_id"],
            "assertion_id": proof["assertion_id"],
            "input_sha256": proof["input_sha256"],
            "crash_fingerprint": proof["crash_fingerprint"],
            "replay_result_sha256": replay_result["result_sha256"],
            "original_binary_sha256": proof["original_binary_sha256"],
            "source_tree_sha256": qualification.source_tree_sha256,
            "harness_sha256": qualification.harness_sha256,
            "process_ledger_path": str(process_ledger.path),
            "source_claim_sha256": claim_sha,
            "triage": triage, "source_inventory_processes": rows,
            "callback_probe": asdict(callback),
            "input_delivery_measured": delivery_measured,
            "process_ledger_sha256": ledger_sha,
            "security_gate_credit": "NOT_CREDITED",
            "discovery_credit": "NOT_CREDITED",
        }
        raw = (json.dumps(result, sort_keys=True, separators=(",", ":"),
                          allow_nan=False) + "\n").encode()
        result_path = output_dir / "HP_SOURCE_RESULT.json"
        result_sha = _write_new(result_path, raw)
        _sync_dir(output_dir)
        return {**result, "result_path": str(result_path),
                "result_sha256": result_sha}
    except BaseException as original:
        failure = {"status": "INCOMPLETE_HP_SOURCE_ATTRIBUTION",
                   "error_type": type(original).__name__,
                   "security_gate_credit": "NOT_CREDITED",
                   "discovery_credit": "NOT_CREDITED"}
        try:
            _write_new(output_dir / "HP_SOURCE_RESULT.json", (
                json.dumps(failure, sort_keys=True, separators=(",", ":")) +
                "\n").encode())
            _sync_dir(output_dir)
        except BaseException as receipt_error:
            original.add_note("HP source failure receipt: " +
                              type(receipt_error).__name__)
        raise


def reprove_hp_source_attribution(
    *, source_result: dict[str, Any], replay_result: dict[str, Any],
    lead: dict[str, Any], physical_claim_path: Path,
    physical_claim_sha256: str, qualification: Any,
    process_ledger: Any,
) -> dict[str, Any]:
    """Read-only proof of HP target source, still without security credit."""
    from vulnerabilityanalysis.official_harness import _qualification_pins_ok
    from vulnerabilityanalysis.runtime import CLEAN_RUNTIME_ENVIRONMENT

    proof = reprove_hp_original_replay(
        replay_result=replay_result, lead=lead,
        physical_claim_path=physical_claim_path,
        physical_claim_sha256=physical_claim_sha256,
        qualification=qualification, process_ledger=process_ledger)
    if (proof.get("status") !=
            "HP_REPLAY_EVIDENCE_REPROVED_PENDING_SECURITY" or
            not _qualification_pins_ok(qualification) or
            type(source_result) is not dict or
            source_result.get("status") !=
                "HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY" or
            source_result.get("security_gate_credit") != "NOT_CREDITED" or
            source_result.get("discovery_credit") != "NOT_CREDITED"):
        raise ValueError("HP source proof is not an attributed physical lead")
    result_path = Path(source_result.get("result_path", ""))
    if result_path.name != "HP_SOURCE_RESULT.json":
        raise ValueError("HP source result locator is invalid")
    raw = _regular_bytes(result_path, result_path.parent, 16_000_000)
    saved = json.loads(raw, object_pairs_hook=_unique_pairs)
    expected = {key: value for key, value in source_result.items()
                if key not in {"result_path", "result_sha256"}}
    if (type(saved) is not dict or saved != expected or
            hashlib.sha256(raw).hexdigest() !=
                source_result.get("result_sha256") or
            saved.get("kind") != "FBV2_HP_SOURCE_ATTRIBUTION_RESULT_V1" or
            saved.get("status") !=
                "HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY" or
            saved.get("security_gate_credit") != "NOT_CREDITED" or
            saved.get("discovery_credit") != "NOT_CREDITED"):
        raise ValueError("HP source result differs from persisted evidence")
    claim_path = result_path.parent / "HP_SOURCE_CLAIM.json"
    claim_raw = _regular_bytes(claim_path, result_path.parent, 16_000_000)
    claim = json.loads(claim_raw, object_pairs_hook=_unique_pairs)
    if (type(claim) is not dict or
            hashlib.sha256(claim_raw).hexdigest() !=
                saved.get("source_claim_sha256") or
            claim.get("kind") != "FBV2_HP_SOURCE_ATTRIBUTION_CLAIM_V1" or
            claim.get("status") != "STARTED" or
            claim.get("source_inventory_environment") !=
                CLEAN_RUNTIME_ENVIRONMENT or
            claim.get("process_ledger_path") != str(process_ledger.path) or
            claim.get("replay_result_path") !=
                replay_result.get("result_path") or
            claim.get("replay_result_sha256") !=
                replay_result.get("result_sha256") or
            claim.get("primary_runtime_sha256") !=
                replay_result["observations"][1].get("runtime_sha256") or
            claim.get("security_gate_credit") != "NOT_CREDITED" or
            claim.get("discovery_credit") != "NOT_CREDITED" or
            claim.get("input_sha256") != proof["input_sha256"] or
            claim.get("original_binary_sha256") !=
                proof["original_binary_sha256"] or
            claim.get("source_tree_sha256") !=
                qualification.source_tree_sha256 or
            claim.get("harness_sha256") != qualification.harness_sha256 or
            any(claim.get(key) != proof.get(key) or
                saved.get(key) != proof.get(key)
                for key in ("task_id", "run_id", "assertion_id",
                            "input_sha256")) or
            saved.get("replay_result_sha256") !=
                replay_result.get("result_sha256") or
            saved.get("crash_fingerprint") != proof["crash_fingerprint"] or
            saved.get("original_binary_sha256") !=
                proof["original_binary_sha256"] or
            saved.get("source_tree_sha256") !=
                qualification.source_tree_sha256 or
            saved.get("harness_sha256") != qualification.harness_sha256 or
            saved.get("process_ledger_path") != str(process_ledger.path)):
        raise ValueError("HP source claim or replay identity differs")
    triage = saved.get("triage")
    provenance = (triage.get("source_provenance")
                  if type(triage) is dict else None)
    if (type(triage) is not dict or
            triage.get("category") != "TARGET_CRASH" or
            triage.get("sp_linked") is not False or
            triage.get("verification_eligible") is not False or
            type(provenance) is not dict or
            provenance.get("method") !=
                "DWARF_PATH_RELATIVE_PATH_SHA256" or
            provenance.get("binary") !=
                str(Path(qualification.binary).resolve())):
        raise ValueError("HP source target provenance is not re-proven")
    source = Path(provenance.get("checkout_source", ""))
    observed = Path(provenance.get("observed_source", ""))
    root = Path(qualification.source_root).resolve()
    if (not source.is_file() or source.is_symlink() or
            not source.resolve().is_relative_to(root) or
            not observed.is_file() or observed.is_symlink() or
            type(provenance.get("sha256")) is not str or
            hashlib.sha256(source.read_bytes()).hexdigest() !=
                provenance["sha256"] or
            hashlib.sha256(observed.read_bytes()).hexdigest() !=
                provenance["sha256"]):
        raise ValueError("HP source bytes or path changed")
    state, _ = process_ledger.receipt_snapshot()
    prefix_id = "hp_source_" + hashlib.sha256(
        str(Path(replay_result["result_path"])).encode()).hexdigest()[:24]
    prefix = f"{proof['task_id']}:{prefix_id}:{proof['run_id']}:"
    active = state.get("active")
    current = [row for row in state.get("finished", []) if
               type(row) is dict and
               type(row.get("key")) is str and
               row["key"].startswith(prefix)]
    if (state.get("stop_status") is not None or
            type(active) is not dict or
            any(key.startswith(prefix) for key in active) or
            not any(row["key"].endswith(
                ":assertion.gdb_source_inventory") for row in current) or
            current != saved.get("source_inventory_processes") or
            any(row.get("kind") != "AUX_PROCESS" or
                not row["key"].endswith((
                    ":assertion.gdb_source_inventory",
                    ":harness.callback_probe")) or
                row.get("cleanup_complete") is not True or
                row.get("output_limited") is not False or
                row.get("overrun") is not False for row in current)):
        raise ValueError("HP source physical evidence is not re-proven")
    callback = saved.get("callback_probe")
    frozen_input = Path(lead.get("frozen_input_path", ""))
    input_raw = _regular_bytes(frozen_input, frozen_input.parent, 2_097_152)
    has_probe_row = any(row["key"].endswith(":harness.callback_probe")
                        for row in current)
    measured = (type(callback) is dict and
                callback.get("measured") is True and
                callback.get("input_size") == len(input_raw) and
                callback.get("input_sha256") == proof["input_sha256"] and
                hashlib.sha256(input_raw).hexdigest() == proof["input_sha256"] and
                has_probe_row)
    if saved.get("input_delivery_measured") is not measured:
        raise ValueError("HP callback input delivery differs from physical evidence")
    return {
        "status": "HP_SOURCE_EVIDENCE_REPROVED_PENDING_SECURITY",
        "task_id": proof["task_id"], "run_id": proof["run_id"],
        "assertion_id": proof["assertion_id"],
        "input_sha256": proof["input_sha256"],
        "crash_fingerprint": proof["crash_fingerprint"],
        "source_sha256": provenance["sha256"],
        "input_delivery_measured": measured,
        "source_result_sha256": source_result["result_sha256"],
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
