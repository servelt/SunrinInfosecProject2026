"""Run a bounded HP-origin Gate chain for frozen Guided crash inputs.

Each lead keeps its HP Assertion identity. The SP result and discovery credit
are never changed by this module.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any

from devtools.hp_guided_crash_freeze import (
    _regular_bytes, _unique_pairs, _write_new)


_SHA = re.compile(r"[0-9a-f]{64}\Z")


def validate_hp_gate_policy(policy: object, *, max_wall_seconds: float,
                            max_output_bytes: int) -> dict[str, Any]:
    if (type(max_wall_seconds) not in (int, float) or
            not math.isfinite(max_wall_seconds) or
            max_wall_seconds <= 0 or
            type(max_output_bytes) is not int or max_output_bytes <= 0 or
            type(policy) is not dict or set(policy) != {
            "enabled", "max_leads", "replay_timeout_seconds",
            "replay_wall_seconds", "source_wall_seconds",
            "output_limit_bytes"} or policy.get("enabled") is not True or
            type(policy.get("max_leads")) is not int or
            not 1 <= policy["max_leads"] <= 3 or
            type(policy.get("replay_timeout_seconds")) is not int or
            not 1 <= policy["replay_timeout_seconds"] <= 30 or
            type(policy.get("replay_wall_seconds")) is not int or
            not 30 <= policy["replay_wall_seconds"] <= 180 or
            type(policy.get("source_wall_seconds")) is not int or
            not 30 <= policy["source_wall_seconds"] <= 180 or
            type(policy.get("output_limit_bytes")) is not int or
            not 1 <= policy["output_limit_bytes"] <= max_output_bytes or
            policy["max_leads"] * (
                policy["replay_wall_seconds"] +
                policy["source_wall_seconds"]) > max_wall_seconds):
        raise ValueError("HP Gate budget policy is invalid")
    return dict(policy)


def run_hp_gate_handoff(*, physical_row: dict[str, Any],
                        qualification: Any, process_ledger: Any,
                        output_dir: Path, policy: dict[str, Any],
                        max_wall_seconds: float,
                        max_output_bytes: int) -> dict[str, Any]:
    """Consume at most the signed number of frozen leads, once each."""
    from devtools.hp_original_replay import replay_hp_original_crash
    from devtools.hp_source_attribution import attribute_hp_replayed_crash_source
    from devtools.hp_independent_gate import (
        issue_hp_independent_gate, reprove_hp_independent_gate)

    validate_hp_gate_policy(
        policy, max_wall_seconds=max_wall_seconds,
        max_output_bytes=max_output_bytes)
    freeze = physical_row.get("hp_crash_freeze")
    claim_path = Path(physical_row.get("physical_claim_path", ""))
    claim_sha = physical_row.get("physical_claim_sha256")
    claim_raw = (claim_path.read_bytes() if claim_path.is_file() and
                 not claim_path.is_symlink() else None)
    try:
        claim = json.loads(claim_raw) if claim_raw is not None else None
    except (TypeError, UnicodeError, ValueError):
        claim = None
    if (physical_row.get("status") !=
            "HP_GUIDED_CRASH_OBSERVED_UNGATED" or
            type(freeze) is not dict or
            freeze.get("status") not in {
                "HP_CRASH_LEADS_FROZEN_UNVERIFIED",
                "INCOMPLETE_HP_CRASH_LEAD_FREEZE"} or
            type(freeze.get("frozen_leads")) is not list or
            type(freeze.get("rejected_leads")) is not list or
            type(freeze.get("reported_lead_count")) is not int or
            freeze["reported_lead_count"] !=
                len(freeze["frozen_leads"]) +
                len(freeze["rejected_leads"]) or
            type(claim_sha) is not str or not _SHA.fullmatch(claim_sha) or
            claim_raw is None or
            hashlib.sha256(claim_raw).hexdigest() != claim_sha or
            type(claim) is not dict or
            claim.get("kind") != "FBV2_HP_PHYSICAL_CLAIM_V1" or
            claim.get("status") not in (None, "STARTED") or
            type(physical_row.get("assertion_id")) is not str or
            claim.get("assertion_id") != physical_row["assertion_id"] or
            type(claim.get("task_id")) is not str or
            type(claim.get("run_id")) is not str):
        raise ValueError("HP Gate handoff is not a claimed Guided crash")
    leads = freeze["frozen_leads"]
    if (any(type(lead) is not dict or
            type(lead.get("claim_sha256")) is not str or
            not _SHA.fullmatch(lead["claim_sha256"]) or
            lead.get("assertion_id") != physical_row["assertion_id"] or
            lead.get("task_id") != claim["task_id"] or
            lead.get("run_id") != claim["run_id"]
            for lead in leads) or
            len({lead["claim_sha256"] for lead in leads}) != len(leads)):
        raise ValueError("HP Gate frozen lead identity is invalid")
    ordered = sorted(leads, key=lambda lead: lead["claim_sha256"])
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.is_symlink() or
            output_dir != output_dir.resolve(strict=False) or
            output_dir.exists()):
        raise ValueError("HP Gate handoff output directory is invalid")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows = []
    for lead in ordered[:policy["max_leads"]]:
        root = output_dir / lead["claim_sha256"]
        item = {"lead_claim_sha256": lead["claim_sha256"],
                "status": "HP_GATE_PENDING_REPLAY",
                "security_gate_credit": "NOT_CREDITED"}
        try:
            replay = replay_hp_original_crash(
                lead=lead, physical_claim_path=claim_path,
                physical_claim_sha256=claim_sha,
                qualification=qualification, process_ledger=process_ledger,
                output_dir=root / "replay",
                timeout_seconds=policy["replay_timeout_seconds"],
                wall_seconds=policy["replay_wall_seconds"],
                output_limit_bytes=policy["output_limit_bytes"])
            item["replay_path"] = replay["result_path"]
            item["replay_sha256"] = replay["result_sha256"]
            if replay.get("status") != "HP_REPLAY_MATCHED_PENDING_SECURITY":
                item["status"] = "HP_GATE_PENDING_REPLAY"
            else:
                source = attribute_hp_replayed_crash_source(
                    replay_result=replay, lead=lead,
                    physical_claim_path=claim_path,
                    physical_claim_sha256=claim_sha,
                    qualification=qualification,
                    process_ledger=process_ledger,
                    output_dir=root / "source",
                    wall_seconds=policy["source_wall_seconds"],
                    output_limit_bytes=policy["output_limit_bytes"])
                item["source_path"] = source["result_path"]
                item["source_sha256"] = source["result_sha256"]
                if (source.get("status") !=
                        "HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY"):
                    item["status"] = "HP_GATE_PENDING_SOURCE"
                else:
                    gate = issue_hp_independent_gate(
                        replay_result=replay, source_result=source,
                        lead=lead, physical_claim_path=claim_path,
                        physical_claim_sha256=claim_sha,
                        qualification=qualification,
                        process_ledger=process_ledger,
                        output_dir=root / "gate")
                    proof = reprove_hp_independent_gate(
                        gate_result=gate, replay_result=replay,
                        source_result=source, lead=lead,
                        physical_claim_path=claim_path,
                        physical_claim_sha256=claim_sha,
                        qualification=qualification,
                        process_ledger=process_ledger)
                    item["gate_path"] = gate["result_path"]
                    item["gate_sha256"] = gate["result_sha256"]
                    item["status"] = proof["status"]
                    item["security_gate_credit"] = proof["security_gate_credit"]
        except Exception as exc:
            item["status"] = "HP_GATE_INCOMPLETE"
            item["error_type"] = type(exc).__name__
        rows.append(item)
    result = {
        "kind": "FBV2_HP_PARALLEL_GATE_HANDOFF_V1",
        "task_id": claim["task_id"],
        "run_id": claim["run_id"],
        "assertion_id": physical_row["assertion_id"],
        "physical_claim_sha256": claim_sha,
        "reported_lead_count": freeze["reported_lead_count"],
        "frozen_lead_count": len(leads),
        "processed_lead_count": len(rows),
        "unprocessed_lead_count": len(leads) - len(rows),
        "rejected_lead_count": len(freeze["rejected_leads"]),
        "pending_lead_count": sum(
            row["security_gate_credit"] != "HP_GATE_VERIFIED"
            for row in rows),
        "lead_results": rows,
        "status": ("HP_GATE_VERIFIED_DISCOVERY_UNPROVEN" if any(
            row["security_gate_credit"] == "HP_GATE_VERIFIED" for row in rows)
            else "HP_GATE_PENDING_OR_INCOMPLETE"),
        "security_gate_credit": ("HP_GATE_VERIFIED" if any(
            row["security_gate_credit"] == "HP_GATE_VERIFIED" for row in rows)
            else "NOT_CREDITED"),
        "discovery_credit": "NOT_CREDITED",
        "sp_global_effect": "UNCHANGED",
    }
    raw = (json.dumps(result, sort_keys=True, separators=(",", ":"),
                      allow_nan=False) + "\n").encode()
    path = output_dir / "HP_PARALLEL_GATE_RESULT.json"
    digest = _write_new(path, raw)
    return {**result, "result_path": str(path), "result_sha256": digest}


def reprove_hp_gate_handoff(*, result: dict[str, Any],
                            physical_row: dict[str, Any],
                            qualification: Any, process_ledger: Any,
                            output_dir: Path, policy: dict[str, Any],
                            max_wall_seconds: float,
                            max_output_bytes: int,
                            task_id: str, run_id: str) -> dict[str, Any]:
    """Count HP Gate credit only after replaying every stored proof check."""
    from devtools.hp_independent_gate import reprove_hp_independent_gate

    validate_hp_gate_policy(
        policy, max_wall_seconds=max_wall_seconds,
        max_output_bytes=max_output_bytes)
    output_dir = Path(output_dir)
    if type(result) is not dict or result.get("result_path") != str(
            output_dir / "HP_PARALLEL_GATE_RESULT.json"):
        raise ValueError("HP Gate handoff locator differs")
    raw = _regular_bytes(Path(result["result_path"]), output_dir, 16_000_000)
    if hashlib.sha256(raw).hexdigest() != result.get("result_sha256"):
        raise ValueError("HP Gate handoff bytes changed")
    saved = json.loads(raw, object_pairs_hook=_unique_pairs)
    expected = {key: value for key, value in result.items()
                if key not in {"result_path", "result_sha256"}}
    freeze = physical_row.get("hp_crash_freeze")
    claim_path = Path(physical_row.get("physical_claim_path", ""))
    claim_raw = _regular_bytes(claim_path, claim_path.parent, 16_000_000)
    claim = json.loads(claim_raw, object_pairs_hook=_unique_pairs)
    if (type(saved) is not dict or saved != expected or
            saved.get("kind") != "FBV2_HP_PARALLEL_GATE_HANDOFF_V1" or
            saved.get("task_id") != task_id or
            saved.get("run_id") != run_id or
            type(claim) is not dict or
            claim.get("kind") != "FBV2_HP_PHYSICAL_CLAIM_V1" or
            claim.get("task_id") != task_id or
            claim.get("run_id") != run_id or
            claim.get("assertion_id") != physical_row.get("assertion_id") or
            hashlib.sha256(claim_raw).hexdigest() !=
                physical_row.get("physical_claim_sha256") or
            type(freeze) is not dict or
            type(freeze.get("frozen_leads")) is not list or
            type(freeze.get("rejected_leads")) is not list or
            saved.get("frozen_lead_count") != len(freeze["frozen_leads"]) or
            saved.get("rejected_lead_count") != len(freeze["rejected_leads"]) or
            saved.get("reported_lead_count") !=
                freeze.get("reported_lead_count") or
            saved.get("reported_lead_count") !=
                len(freeze["frozen_leads"]) +
                len(freeze["rejected_leads"]) or
            saved.get("physical_claim_sha256") !=
                physical_row.get("physical_claim_sha256") or
            saved.get("assertion_id") != physical_row.get("assertion_id")):
        raise ValueError("HP Gate handoff receipt differs")
    leads = sorted(freeze["frozen_leads"],
                   key=lambda lead: lead["claim_sha256"])
    if (len({lead["claim_sha256"] for lead in leads}) != len(leads) or
            any(type(lead.get("claim_sha256")) is not str or
                not _SHA.fullmatch(lead["claim_sha256"])
                for lead in leads)):
        raise ValueError("HP Gate lead claim set differs")
    if any(lead.get("task_id") != task_id or
           lead.get("run_id") != run_id or
           lead.get("assertion_id") != saved.get("assertion_id")
           for lead in leads):
        raise ValueError("HP Gate lead identity differs")
    rows = saved.get("lead_results")
    if (type(rows) is not list or len(rows) !=
            min(len(leads), policy["max_leads"]) or
            saved.get("processed_lead_count") != len(rows) or
            saved.get("unprocessed_lead_count") != len(leads) - len(rows)):
        raise ValueError("HP Gate handoff lead accounting differs")

    def stage(item, root, name, path_key, sha_key):
        path = root / name
        if item.get(path_key) != str(path):
            raise ValueError("HP Gate stage locator differs")
        content = _regular_bytes(path, root, 16_000_000)
        if hashlib.sha256(content).hexdigest() != item.get(sha_key):
            raise ValueError("HP Gate stage bytes changed")
        row = json.loads(content, object_pairs_hook=_unique_pairs)
        if type(row) is not dict:
            raise ValueError("HP Gate stage schema differs")
        return {**row, "result_path": str(path),
                "result_sha256": item[sha_key]}

    verified = 0
    for lead, item in zip(leads, rows):
        if (type(item) is not dict or
                item.get("lead_claim_sha256") != lead["claim_sha256"]):
            raise ValueError("HP Gate lead selection differs")
        root = output_dir / lead["claim_sha256"]
        if "replay_path" in item:
            replay = stage(item, root / "replay", "HP_REPLAY_RESULT.json",
                           "replay_path", "replay_sha256")
        if "source_path" in item:
            if "replay_path" not in item:
                raise ValueError("HP Gate source lacks replay")
            source = stage(item, root / "source", "HP_SOURCE_RESULT.json",
                           "source_path", "source_sha256")
        if "gate_path" in item:
            if "source_path" not in item:
                raise ValueError("HP Gate result lacks source")
            gate = stage(item, root / "gate", "HP_GATE_RESULT.json",
                         "gate_path", "gate_sha256")
            proof = reprove_hp_independent_gate(
                gate_result=gate, replay_result=replay,
                source_result=source, lead=lead,
                physical_claim_path=Path(
                    physical_row["physical_claim_path"]),
                physical_claim_sha256=
                    physical_row["physical_claim_sha256"],
                qualification=qualification,
                process_ledger=process_ledger)
            if (proof.get("status") != item.get("status") or
                    proof.get("security_gate_credit") !=
                        item.get("security_gate_credit")):
                raise ValueError("HP Gate verdict differs from physical proof")
            verified += proof["security_gate_credit"] == "HP_GATE_VERIFIED"
        elif (item.get("security_gate_credit") != "NOT_CREDITED" or
              item.get("status") not in {
                  "HP_GATE_PENDING_REPLAY", "HP_GATE_PENDING_SOURCE",
                  "HP_GATE_INCOMPLETE"}):
            raise ValueError("HP Gate pending lead claims credit")
    wanted_credit = "HP_GATE_VERIFIED" if verified else "NOT_CREDITED"
    wanted_status = ("HP_GATE_VERIFIED_DISCOVERY_UNPROVEN" if verified else
                     "HP_GATE_PENDING_OR_INCOMPLETE")
    pending_count = len(rows) - verified
    if (saved.get("security_gate_credit") != wanted_credit or
            saved.get("status") != wanted_status or
            saved.get("pending_lead_count") != pending_count or
            saved.get("discovery_credit") != "NOT_CREDITED" or
            saved.get("sp_global_effect") != "UNCHANGED"):
        raise ValueError("HP Gate handoff summary differs")
    return {"status": wanted_status,
            "security_gate_credit": wanted_credit,
            "discovery_credit": "NOT_CREDITED",
            "processed_lead_count": len(rows),
            "unprocessed_lead_count": len(leads) - len(rows),
            "rejected_lead_count": len(freeze["rejected_leads"]),
            "pending_lead_count": pending_count}
