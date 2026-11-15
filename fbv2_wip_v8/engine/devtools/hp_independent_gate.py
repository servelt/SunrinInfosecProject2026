"""HP-origin memory-safety Gate under HP Assertion/run identity.

The verdict is separate from SP verification and automatic discovery credit.
The public runner must explicitly admit and re-prove it before counting it.
"""

from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from devtools.hp_guided_crash_freeze import (
    _regular_bytes, _sync_dir, _unique_pairs, _write_new)
from devtools.hp_original_replay import reprove_hp_original_replay
from devtools.hp_source_attribution import reprove_hp_source_attribution


_SUPPORTED_MEMORY_FAULT_LABELS = (
    "heap-use-after-free", "stack-use-after-free",
    "heap-buffer-overflow", "stack-buffer-overflow",
    "global-buffer-overflow", "heap-buffer-underflow",
    "stack-buffer-underflow", "global-buffer-underflow",
    "attempting double-free", "stack-use-after-return",
    "stack-use-after-scope", "alloc-dealloc-mismatch",
)


def _supported_memory_fault(oracle: str) -> bool:
    """Match the ASan diagnostic label, not words elsewhere in its header."""
    return any(re.match(
        r"^AddressSanitizer:\s+" + re.escape(label) + r"(?=\s|$)",
        oracle) is not None for label in _SUPPORTED_MEMORY_FAULT_LABELS)


def _hp_gate_evidence(
    *, replay_result: dict[str, Any], source_result: dict[str, Any],
    lead: dict[str, Any], physical_claim_path: Path,
    physical_claim_sha256: str, qualification: Any,
    process_ledger: Any,
) -> dict[str, Any]:
    from vulnerabilityanalysis.final_verification import (
        completed_asan_crash, crash_fingerprint)
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.official_harness import _qualification_pins_ok

    common = dict(replay_result=replay_result, lead=lead,
                  physical_claim_path=physical_claim_path,
                  physical_claim_sha256=physical_claim_sha256,
                  qualification=qualification, process_ledger=process_ledger)
    replay_proof = reprove_hp_original_replay(**common)
    source_proof = reprove_hp_source_attribution(
        source_result=source_result, **common)
    if (replay_proof.get("status") !=
            "HP_REPLAY_EVIDENCE_REPROVED_PENDING_SECURITY" or
            source_proof.get("status") !=
            "HP_SOURCE_EVIDENCE_REPROVED_PENDING_SECURITY" or
            replay_result.get("execution_origin") !=
            "PINNED_RUNTIME_EXECUTOR" or
            source_proof.get("crash_fingerprint") !=
            replay_proof.get("crash_fingerprint") or
            not _qualification_pins_ok(qualification)):
        raise ValueError("HP Gate physical evidence is not re-proven")
    replay_path = Path(replay_result["result_path"])
    primary_path = replay_path.parent / "original_observation-runtime.json"
    raw = _regular_bytes(primary_path, replay_path.parent, 16_000_000)
    if (replay_result["observations"][1].get("runtime_path") !=
            str(primary_path) or hashlib.sha256(raw).hexdigest() !=
            replay_result["observations"][1].get("runtime_sha256")):
        raise ValueError("HP Gate primary runtime bytes changed")
    payload = json.loads(raw, object_pairs_hook=_unique_pairs)
    if type(payload) is not dict or set(payload) != {
            item.name for item in fields(RuntimeResult)}:
        raise ValueError("HP Gate primary runtime schema changed")
    primary = RuntimeResult(**payload)
    if (not completed_asan_crash(primary) or
            crash_fingerprint(primary) !=
                replay_proof["crash_fingerprint"]):
        raise ValueError("HP Gate primary ASan impact is not re-proven")
    memory_fault_supported = _supported_memory_fault(primary.sanitizer)
    delivery_measured = source_proof.get("input_delivery_measured") is True
    return {
        "task_id": replay_proof["task_id"],
        "run_id": replay_proof["run_id"],
        "assertion_id": replay_proof["assertion_id"],
        "input_sha256": replay_proof["input_sha256"],
        "original_binary_sha256": replay_proof["original_binary_sha256"],
        "source_sha256": source_proof["source_sha256"],
        "crash_fingerprint": replay_proof["crash_fingerprint"],
        "asan_oracle": primary.sanitizer,
        "memory_fault_supported": memory_fault_supported,
        "input_delivery_measured": delivery_measured,
        "official_harness_pinned": True,
        "normal_control_clean": True,
        "independent_replay_exact": True,
        "target_source_attributed": True,
        "replay_result_sha256": replay_result["result_sha256"],
        "source_result_sha256": source_result["result_sha256"],
        "status": ("HP_GATE_VERIFIED_DISCOVERY_UNPROVEN" if
                   memory_fault_supported and delivery_measured else
                   "HP_GATE_PENDING_INPUT_DELIVERY" if
                   not delivery_measured else
                   "HP_GATE_PENDING_UNSUPPORTED_ORACLE"),
    }


def issue_hp_independent_gate(
    *, replay_result: dict[str, Any], source_result: dict[str, Any],
    lead: dict[str, Any], physical_claim_path: Path,
    physical_claim_sha256: str, qualification: Any,
    process_ledger: Any, output_dir: Path,
) -> dict[str, Any]:
    """Issue one HP Gate verdict; no SP or discovery credit is created."""
    evidence = _hp_gate_evidence(
        replay_result=replay_result, source_result=source_result,
        lead=lead, physical_claim_path=physical_claim_path,
        physical_claim_sha256=physical_claim_sha256,
        qualification=qualification, process_ledger=process_ledger)
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.is_symlink() or
            output_dir != output_dir.resolve(strict=False) or
            any(parent.is_symlink() for parent in output_dir.parents)):
        raise ValueError("HP Gate result directory is invalid")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    _sync_dir(output_dir.parent)
    result = {
        "kind": "FBV2_HP_INDEPENDENT_GATE_RESULT_V1",
        **evidence,
        "security_gate_credit": ("HP_GATE_VERIFIED" if
                                 evidence["status"] ==
                                 "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN"
                                 else "NOT_CREDITED"),
        "discovery_credit": "NOT_CREDITED",
        "hp_assertion_causal_relation_status": "UNPROVEN",
        "sp_global_effect": "UNCHANGED",
    }
    raw = (json.dumps(result, sort_keys=True, separators=(",", ":"),
                      allow_nan=False) + "\n").encode()
    result_path = output_dir / "HP_GATE_RESULT.json"
    digest = _write_new(result_path, raw)
    _sync_dir(output_dir)
    return {**result, "result_path": str(result_path),
            "result_sha256": digest}


def reprove_hp_independent_gate(
    *, gate_result: dict[str, Any], replay_result: dict[str, Any],
    source_result: dict[str, Any], lead: dict[str, Any],
    physical_claim_path: Path, physical_claim_sha256: str,
    qualification: Any, process_ledger: Any,
) -> dict[str, Any]:
    """Only this read-only consumer may count an HP Gate VERIFIED result."""
    evidence = _hp_gate_evidence(
        replay_result=replay_result, source_result=source_result,
        lead=lead, physical_claim_path=physical_claim_path,
        physical_claim_sha256=physical_claim_sha256,
        qualification=qualification, process_ledger=process_ledger)
    if type(gate_result) is not dict:
        raise ValueError("HP Gate result is invalid")
    result_path = Path(gate_result.get("result_path", ""))
    if result_path.name != "HP_GATE_RESULT.json":
        raise ValueError("HP Gate result locator is invalid")
    raw = _regular_bytes(result_path, result_path.parent, 16_000_000)
    saved = json.loads(raw, object_pairs_hook=_unique_pairs)
    expected = {key: value for key, value in gate_result.items()
                if key not in {"result_path", "result_sha256"}}
    wanted_credit = ("HP_GATE_VERIFIED" if evidence["status"] ==
                     "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN" else
                     "NOT_CREDITED")
    if (type(saved) is not dict or saved != expected or
            hashlib.sha256(raw).hexdigest() !=
                gate_result.get("result_sha256") or
            saved.get("kind") != "FBV2_HP_INDEPENDENT_GATE_RESULT_V1" or
            any(saved.get(key) != value for key, value in evidence.items()) or
            saved.get("security_gate_credit") != wanted_credit or
            saved.get("discovery_credit") != "NOT_CREDITED" or
            saved.get("hp_assertion_causal_relation_status") != "UNPROVEN" or
            saved.get("sp_global_effect") != "UNCHANGED"):
        raise ValueError("HP Gate result is not re-proven")
    return {"status": evidence["status"],
            "task_id": evidence["task_id"], "run_id": evidence["run_id"],
            "assertion_id": evidence["assertion_id"],
            "input_sha256": evidence["input_sha256"],
            "crash_fingerprint": evidence["crash_fingerprint"],
            "security_gate_credit": wanted_credit,
            "discovery_credit": "NOT_CREDITED"}
