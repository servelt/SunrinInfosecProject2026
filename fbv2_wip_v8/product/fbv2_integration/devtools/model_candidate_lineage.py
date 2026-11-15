"""Independently check a completed FBv2 SP -> verifier -> PoV lineage.

The campaign ledger authenticates the model response and host tool result
within the development process.  This module checks that the tool results
actually name the current database objects.  It never grants vulnerability or
automatic-discovery credit; Runtime and the product Gate make those decisions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from bson import ObjectId

from .campaign_model_gate import CampaignGateError, CampaignModelGate, _private_bytes


def _unproven(reason: str) -> dict[str, Any]:
    return {"status": "UNPROVEN", "reason": reason}


def _tool(gate: CampaignModelGate, request_id: str, call_id: str,
          expected_role: str | frozenset[str], expected_name: str
          ) -> tuple[dict, dict, dict, dict, dict]:
    response = gate.verify_response_evidence(request_id)
    event = gate.verify_tool_event(request_id, call_id)
    if response.get("status") != "VERIFIED" or event.get("status") != "VERIFIED":
        raise ValueError("MODEL_OR_TOOL_EVIDENCE_UNPROVEN")
    rows = [row for row in gate.snapshot()["records"]
            if row["request_id"] == request_id]
    roles = ({expected_role} if type(expected_role) is str else expected_role)
    if (len(rows) != 1 or rows[0]["role"] not in roles or
            event["name"] != expected_name):
        raise ValueError("ROLE_OR_TOOL_MISMATCH")
    raw_bytes = _private_bytes(Path(response["response_path"]))
    result_bytes = _private_bytes(Path(event["result_path"]))
    if (raw_bytes is None or result_bytes is None or
            hashlib.sha256(raw_bytes).hexdigest() != response["response_sha256"] or
            hashlib.sha256(result_bytes).hexdigest() != event["result_sha256"]):
        raise ValueError("TOOL_ARTIFACT_CHANGED_AFTER_GATE_CHECK")
    raw = json.loads(raw_bytes)
    proposal = raw["tool_calls"][event["proposal_index"]]
    args = json.loads(proposal["arguments"])
    result = json.loads(result_bytes)
    if (type(args) is not dict or type(result) is not dict or
            proposal["name"] != expected_name):
        raise ValueError("TOOL_PAYLOAD_INVALID")
    return rows[0], args, result, response, event


def _owner(prefix: str, sp_id: str, value: str) -> bool:
    return re.fullmatch(rf"{prefix}_[1-9][0-9]*:{re.escape(sp_id)}", value) is not None


def verify_candidate_lineage(
    gate: CampaignModelGate, repos: Any, *, task_id: str,
    direction_id: str, sp_id: str,
    sp_request_id: str, sp_call_id: str,
    verifier_request_id: str, verifier_call_id: str,
    pov_request_id: str, pov_call_id: str,
) -> dict[str, Any]:
    """Return VERIFIED linkage or UNPROVEN, never a security Gate verdict.

    Full IDs and original tool result artifacts are required.  Older truncated
    SP results and records without model receipts deliberately remain UNPROVEN.
    """
    if (not all(type(value) is str and ObjectId.is_valid(value)
                for value in (task_id, direction_id, sp_id)) or
            not isinstance(gate, CampaignModelGate) or
            len({sp_request_id, verifier_request_id, pov_request_id}) != 3):
        return _unproven("INVALID_LINEAGE_IDENTITY")
    try:
        sp_row, sp_args, sp_result, sp_response, sp_event = _tool(
            gate, sp_request_id, sp_call_id, frozenset({"sp", "sp_large"}),
            "create_suspicious_point")
        verify_row, verify_args, verify_result, verify_response, verify_event = _tool(
            gate, verifier_request_id, verifier_call_id, "verifier",
            "update_suspicious_point")
        pov_row, pov_args, pov_result, pov_response, pov_event = _tool(
            gate, pov_request_id, pov_call_id, "pov", "create_pov")
        if not (sp_row["sequence"] < verify_row["sequence"] < pov_row["sequence"]):
            return _unproven("ROLE_ORDER_MISMATCH")
        completed = [sp_event.get("complete_order"),
                     verify_event.get("complete_order"),
                     pov_event.get("complete_order")]
        started = [sp_event.get("start_order"),
                   verify_event.get("start_order"),
                   pov_event.get("start_order")]
        if (any(type(value) is not int for value in completed + started) or
                not (started[0] < completed[0] < started[1] < completed[1]
                     < started[2] < completed[2])):
            return _unproven("TOOL_EXECUTION_ORDER_UNPROVEN")
        if (sp_result.get("success") is not True or
                sp_result.get("created") is not True or
                sp_result.get("merged") is not False or
                sp_result.get("id") != sp_id or
                not ObjectId.is_valid(sp_result["id"])):
            return _unproven("SP_CREATE_RESULT_UNPROVEN")
        owner_prefix = f"{direction_id}:"
        sp_owner = sp_row["owner_id"]
        if not sp_owner.startswith(owner_prefix):
            return _unproven("SP_DB_OR_OWNER_MISMATCH")
        owner_tail = sp_owner[len(owner_prefix):]
        if ":" not in owner_tail:
            return _unproven("SP_DB_OR_OWNER_MISMATCH")
        function_id, sp_owner_index = owner_tail.rsplit(":", 1)
        if (not function_id or not sp_owner_index.isdecimal() or
                str(int(sp_owner_index)) != sp_owner_index):
            return _unproven("SP_DB_OR_OWNER_MISMATCH")
        function = repos.functions.find_by_id(function_id)
        point = repos.suspicious_points.find_by_id(sp_id)
        # The original SP document records only function_name.  Even when the
        # campaign owner names an exact function ID, two same-name functions
        # cannot be distinguished in that document after the fact.
        same_name = [item for item in repos.functions.find_by_task(task_id)
                     if item.name == sp_args.get("function_name")]
        if len(same_name) != 1:
            return _unproven("SP_FUNCTION_NAME_AMBIGUOUS")
        if (function is None or point is None or
                function.function_id != function_id or
                function.task_id != task_id or
                function.name != sp_args.get("function_name") or
                point.task_id != task_id or point.direction_id != direction_id or
                point.function_name != function.name or
                point.description != sp_args.get("description") or
                point.vuln_type != sp_args.get("vuln_type") or
                not point.created_by_agent_id or
                point.created_by_agent_id != sp_event.get("agent_id") or
                not ObjectId.is_valid(point.created_by_agent_id)):
            return _unproven("SP_DB_OR_OWNER_MISMATCH")
        if (not _owner("verify", sp_id, verify_row["owner_id"]) or
                verify_args.get("suspicious_point_id") != sp_id or
                verify_args.get("is_checked") is not True or
                verify_args.get("is_important") is not True or
                verify_result.get("success") is not True or
                verify_result.get("updated") is not True or
                verify_result.get("server_result", {}).get("updated") is not True or
                not point.is_checked or not point.is_important or
                not point.verified_by_agent_id or
                point.verified_by_agent_id != verify_event.get("agent_id") or
                not ObjectId.is_valid(point.verified_by_agent_id)):
            return _unproven("VERIFIER_DB_OR_OWNER_MISMATCH")
        if ("score" in verify_args and point.score != verify_args["score"] or
                "verification_notes" in verify_args and
                point.verification_notes != verify_args["verification_notes"] or
                "pov_guidance" in verify_args and
                point.pov_guidance != verify_args["pov_guidance"] or
                "is_real" in verify_args and point.is_real != verify_args["is_real"]):
            return _unproven("VERIFIER_RESULT_MISMATCH")
        if (not _owner("pov", sp_id, pov_row["owner_id"]) or
                pov_result.get("success") is not True or
                type(pov_args.get("generator_code")) is not str or
                not pov_args["generator_code"] or
                type(pov_result.get("pov_ids")) is not list or
                not pov_result["pov_ids"] or
                len(set(pov_result["pov_ids"])) != len(pov_result["pov_ids"]) or
                pov_result.get("count") != len(pov_result["pov_ids"])):
            return _unproven("POV_TOOL_OR_OWNER_MISMATCH")
        inputs = []
        generation_ids = set()
        pov_agent_ids = set()
        for pov_id in pov_result["pov_ids"]:
            if type(pov_id) is not str or not ObjectId.is_valid(pov_id):
                return _unproven("POV_ID_INVALID")
            pov = repos.povs.find_by_id(pov_id)
            if (pov is None or pov.task_id != task_id or
                    pov.suspicious_point_id != sp_id or pov.source != "agent" or
                    pov.gen_blob != pov_args["generator_code"] or
                    not pov.agent_id or pov.agent_id != pov_event.get("agent_id") or
                    not ObjectId.is_valid(pov.agent_id) or
                    type(pov.blob) is not str or
                    pov.attempt != pov_result.get("attempt")):
                return _unproven("POV_DB_IDENTITY_MISMATCH")
            try:
                blob = base64.b64decode(pov.blob, validate=True)
                if not 0 < len(blob) <= 2_097_152:
                    raise ValueError("PoV blob size")
                if pov.blob_path is not None:
                    path = Path(pov.blob_path)
                    if (not path.is_absolute() or path.is_symlink() or
                            any(parent.is_symlink() for parent in path.parents) or
                            path.read_bytes() != blob):
                        raise ValueError("PoV blob path mismatch")
            except (ValueError, OSError, binascii.Error):
                return _unproven("POV_BLOB_MISMATCH")
            generation_ids.add(pov.generation_id)
            pov_agent_ids.add(pov.agent_id)
            inputs.append({"pov_id": pov_id,
                           "input_sha256": hashlib.sha256(blob).hexdigest()})
        if (len(generation_ids) != 1 or not next(iter(generation_ids)) or
                len(pov_agent_ids) != 1):
            return _unproven("POV_GENERATION_MISMATCH")
        turns = []
        for role, row, response, event in (
            ("sp", sp_row, sp_response, sp_event),
            ("verifier", verify_row, verify_response, verify_event),
            ("pov", pov_row, pov_response, pov_event),
        ):
            turns.append({"role": role, "request_id": row["request_id"],
                          "thread_id": response["thread_id"],
                          "turn_id": response["turn_id"],
                          "response_sha256": response["response_sha256"],
                          "tool_call_id": event["call_id"],
                          "arguments_sha256": event["arguments_sha256"],
                          "result_sha256": event["result_sha256"]})
        return {"status": "VERIFIED", "campaign_id": gate.campaign_id,
                "task_id": task_id, "direction_id": direction_id,
                "sp_id": sp_id, "sp_request_id": sp_request_id,
                "verifier_request_id": verifier_request_id,
                "pov_request_id": pov_request_id, "model_tool_turns": turns,
                "pov_inputs": inputs,
                "discovery_credit": "NOT_CREDITED_BY_LINEAGE_ONLY"}
    except (CampaignGateError, ValueError, TypeError, KeyError, IndexError,
            AttributeError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unproven(type(exc).__name__ + ":" + str(exc)[:120])


def find_candidate_lineage(gate: CampaignModelGate, repos: Any, *,
                           task_id: str, pov_id: str) -> dict[str, Any]:
    """Find one unambiguous model/tool chain for a saved PoV, if it exists.

    The caller supplies a PoV ID observed in this run.  Tool results, not
    model claims or a PoV's ``source`` field, select the three role receipts.
    """
    if (type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
            type(task_id) is not str or not ObjectId.is_valid(task_id)):
        return _unproven("INVALID_POV_IDENTITY")
    try:
        pov = repos.povs.find_by_id(pov_id)
        if pov is None or pov.task_id != task_id:
            return _unproven("POV_NOT_IN_TASK")
        point = repos.suspicious_points.find_by_id(pov.suspicious_point_id)
        if point is None or point.task_id != task_id or not point.direction_id:
            return _unproven("SP_DIRECTION_UNPROVEN")
        matches: dict[str, list[tuple[str, str]]] = {
            "sp": [], "verifier": [], "pov": []}
        for row in gate.snapshot()["records"]:
            for event in row.get("tool_events", []):
                kind = event.get("name")
                role = row.get("role")
                if (kind == "create_suspicious_point" and
                        role in {"sp", "sp_large"}):
                    selected = "sp"
                elif kind == "update_suspicious_point" and role == "verifier":
                    selected = "verifier"
                elif kind == "create_pov" and role == "pov":
                    selected = "pov"
                else:
                    continue
                try:
                    _, args, result, _, _ = _tool(
                        gate, row["request_id"], event["call_id"],
                        frozenset({"sp", "sp_large"}) if selected == "sp"
                        else selected, kind)
                except (CampaignGateError, ValueError, TypeError, KeyError,
                        IndexError, AttributeError, OSError, UnicodeError,
                        json.JSONDecodeError):
                    continue
                if (selected == "sp" and result.get("id") ==
                        pov.suspicious_point_id or
                    selected == "verifier" and
                        args.get("suspicious_point_id") ==
                        pov.suspicious_point_id or
                    selected == "pov" and
                        pov_id in result.get("pov_ids", [])):
                    matches[selected].append((row["request_id"],
                                              event["call_id"]))
        if any(len(items) != 1 for items in matches.values()):
            return _unproven("MODEL_TOOL_CHAIN_MISSING_OR_AMBIGUOUS")
        return verify_candidate_lineage(
            gate, repos, task_id=task_id, direction_id=point.direction_id,
            sp_id=pov.suspicious_point_id,
            sp_request_id=matches["sp"][0][0],
            sp_call_id=matches["sp"][0][1],
            verifier_request_id=matches["verifier"][0][0],
            verifier_call_id=matches["verifier"][0][1],
            pov_request_id=matches["pov"][0][0],
            pov_call_id=matches["pov"][0][1])
    except (CampaignGateError, ValueError, TypeError, KeyError, IndexError,
            AttributeError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unproven(type(exc).__name__ + ":" + str(exc)[:120])
