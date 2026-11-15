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
import math
from pathlib import Path
import re
from typing import Any

from bson import ObjectId

from .campaign_model_gate import (
    CampaignGateError, CampaignModelGate, _private_bytes,
    campaign_candidate_owner_id,
)


def _unproven(reason: str) -> dict[str, Any]:
    return {"status": "UNPROVEN", "reason": reason}


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _artifact_bytes(gate: CampaignModelGate, path: str, expected_sha256: str) -> bytes:
    """Read live bytes normally or an exact logical path from a frozen archive."""
    reader = getattr(gate, "read_artifact", None)
    if callable(reader):
        raw = reader(path, expected_sha256=expected_sha256)
    else:
        raw = _private_bytes(Path(path))
    if (raw is None or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError("artifact changed after receipt verification")
    return raw


def _authenticated_untrusted_hypothesis(
    *, task_id: str, direction_id: str, sp_id: str, function_id: str,
    sp_args: dict[str, Any], verify_args: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Freeze only the semantic SP identity authenticated by tool receipts.

    A create-SP tool call identifies a function, not an exact source line.  In
    particular, a later Function DB index must not silently turn the function
    start line into the model's claimed bug location.  The product Gate may
    use this untrusted hypothesis as a lead, but independent runtime/root-cause
    evidence remains responsible for source attribution and verification.
    """
    function_name = sp_args.get("function_name")
    description = sp_args.get("description")
    vulnerability_type = sp_args.get("vuln_type")
    if (not all(type(value) is str and value.strip() for value in (
            function_name, description, vulnerability_type)) or
            type(function_id) is not str or not function_id):
        raise ValueError("authenticated SP hypothesis is incomplete")
    controlflow = sp_args.get("important_controlflow", [])
    if type(controlflow) is not list:
        raise ValueError("authenticated SP control flow is invalid")
    sp_score = sp_args.get("score")
    if (sp_score is not None and
            (type(sp_score) not in (int, float) or
             not math.isfinite(float(sp_score)))):
        raise ValueError("authenticated SP score is invalid")
    verifier_score = verify_args.get("score")
    if (verifier_score is not None and
            (type(verifier_score) not in (int, float) or
             not math.isfinite(float(verifier_score)))):
        raise ValueError("authenticated verifier score is invalid")
    verifier_fields = {
        key: verify_args.get(key) for key in (
            "is_checked", "is_real", "is_important", "score",
            "reachability_status", "reachability_multiplier",
            "reachability_reason", "verification_notes", "pov_guidance",
        )
    }
    hypothesis = {
        "kind": "FBV2_AUTHENTICATED_UNTRUSTED_SP_HYPOTHESIS_V1",
        "trust": "UNTRUSTED_MODEL_HYPOTHESIS",
        "task_id": task_id,
        "direction_id": direction_id,
        "sp_id": sp_id,
        "campaign_function_id": function_id,
        "function_name": function_name,
        "source_file": None,
        "code_location": "UNKNOWN",
        "exact_source_location_status": "UNPROVEN",
        "vulnerability_type": vulnerability_type,
        "hypothesis": description,
        "important_controlflow": controlflow,
        "sp_score": sp_score,
        "verifier": verifier_fields,
        "pov_guidance": verifier_fields["pov_guidance"]
            if type(verifier_fields["pov_guidance"]) is str else None,
        "evidence_authority": "NONE",
        "automatic_discovery": False,
        "discovery_credit": "NOT_CREDITED_BY_LINEAGE_ONLY",
    }
    return hypothesis, _canonical_json_sha256(hypothesis)


_POV_ADMISSION_MODES = frozenset({"legacy_score", "explicit_disposition"})
_ENABLED_DISPOSITIONS = frozenset({"TESTABLE_UNCERTAIN", "SUPPORTED"})


def _verifier_admitted(mode: str, verify_args: dict, point: Any) -> bool:
    """Apply the run's signed Verifier-to-PoV admission rule to one verdict.

    explicit_disposition admits a low-score candidate by its disposition, so
    is_important must not be required there; legacy_score keeps its rule.
    """
    if mode == "explicit_disposition":
        disposition = verify_args.get("verification_disposition")
        return (disposition in _ENABLED_DISPOSITIONS and
                point.verification_disposition == disposition)
    return (verify_args.get("is_important") is True and
            point.is_important is True)


def _tool(gate: CampaignModelGate, request_id: str, call_id: str,
          expected_role: str | frozenset[str], expected_name: str, *,
          validated_snapshot: dict[str, Any] | None = None,
          ) -> tuple[dict, dict, dict, dict, dict]:
    response = gate.verify_response_evidence(
        request_id, _validated_snapshot=validated_snapshot)
    event = gate.verify_tool_event(
        request_id, call_id, _validated_snapshot=validated_snapshot)
    if response.get("status") != "VERIFIED" or event.get("status") != "VERIFIED":
        raise ValueError("MODEL_OR_TOOL_EVIDENCE_UNPROVEN")
    payload = gate.snapshot() if validated_snapshot is None else validated_snapshot
    rows = [row for row in payload["records"]
            if row["request_id"] == request_id]
    roles = ({expected_role} if type(expected_role) is str else expected_role)
    if (len(rows) != 1 or rows[0]["role"] not in roles or
            event["name"] != expected_name):
        raise ValueError("ROLE_OR_TOOL_MISMATCH")
    raw_bytes = _artifact_bytes(
        gate, response["response_path"], response["response_sha256"])
    result_bytes = _artifact_bytes(
        gate, event["result_path"], event["result_sha256"])
    raw = json.loads(raw_bytes)
    proposal = raw["tool_calls"][event["proposal_index"]]
    args = json.loads(proposal["arguments"])
    result = json.loads(result_bytes)
    if (type(args) is not dict or type(result) is not dict or
            proposal["name"] != expected_name):
        raise ValueError("TOOL_PAYLOAD_INVALID")
    return rows[0], args, result, response, event


def _owner(prefix: str, sp_id: str, value: str, *, task_id: str,
           sources: list[dict], expected_harness_name: str | None = None,
           expected_sanitizer: str | None = None) -> bool:
    contributors = {
        (source.get("harness_name"), source.get("sanitizer"))
        for source in sources if isinstance(source, dict) and
        isinstance(source.get("harness_name"), str) and
        isinstance(source.get("sanitizer"), str)
    } if isinstance(sources, list) else set()
    expected = (expected_harness_name, expected_sanitizer)
    if ((expected_harness_name is None) != (expected_sanitizer is None) or
            expected_harness_name is not None and expected not in contributors):
        return False
    # Retain verification of frozen pre-change campaigns.
    if re.fullmatch(rf"{prefix}_[1-9][0-9]*:{re.escape(sp_id)}", value):
        # A legacy owner carries no contributor identity. It can prove that
        # identity only for a frozen single-Harness candidate.
        return expected_harness_name is None or contributors == {expected}
    match = re.fullmatch(
        rf"({prefix}_[1-9][0-9]*):[0-9a-f]{{64}}:{re.escape(sp_id)}", value)
    if match is None or not isinstance(sources, list):
        return False
    candidate_sources = (sources if expected_harness_name is None else [{
        "harness_name": expected_harness_name,
        "sanitizer": expected_sanitizer,
    }])
    for source in candidate_sources:
        if (not isinstance(source, dict) or
                not isinstance(source.get("harness_name"), str) or
                not isinstance(source.get("sanitizer"), str)):
            continue
        if value == campaign_candidate_owner_id(
                agent_id=match.group(1), task_id=task_id,
                harness_name=source["harness_name"],
                sanitizer=source["sanitizer"], sp_id=sp_id):
            return True
    return False


def _event_candidate_hint(gate: CampaignModelGate, row: dict, event: dict, *, selected: str,
                          sp_id: str, pov_id: str) -> str:
    """Cheap fail-closed selector before full artifact verification.

    The bytes read here are not trusted. A positive hint merely selects at
    most a few events for the complete response/tool receipt verification in
    ``_tool``; it never grants lineage credit.
    """
    try:
        if selected in {"sp", "pov"}:
            result_bytes = _artifact_bytes(
                gate, event["result_path"], event["result_sha256"])
            result = json.loads(result_bytes)
            matched = (result.get("id") == sp_id if selected == "sp" else
                       pov_id in result.get("pov_ids", []))
            return "MATCH" if matched else "NO_MATCH"
        evidence = row.get("response_evidence")
        if not isinstance(evidence, dict):
            return "CORRUPT"
        raw_bytes = _artifact_bytes(
            gate, evidence["response_path"], evidence["response_sha256"])
        raw = json.loads(raw_bytes)
        proposal = raw["tool_calls"][event["proposal_index"]]
        args = json.loads(proposal["arguments"])
        return ("MATCH" if args.get("suspicious_point_id") == sp_id else
                "NO_MATCH")
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            CampaignGateError, json.JSONDecodeError):
        return "CORRUPT"


def verify_candidate_lineage(
    gate: CampaignModelGate, repos: Any, *, task_id: str,
    direction_id: str, sp_id: str,
    sp_request_id: str, sp_call_id: str,
    verifier_request_id: str, verifier_call_id: str,
    pov_request_id: str, pov_call_id: str,
    _validated_snapshot: dict[str, Any] | None = None,
    pov_admission_mode: str = "legacy_score",
) -> dict[str, Any]:
    """Return VERIFIED linkage or UNPROVEN, never a security Gate verdict.

    Full IDs and original tool result artifacts are required.  Older truncated
    SP results and records without model receipts deliberately remain UNPROVEN.
    ``pov_admission_mode`` is the signed Verifier-to-PoV policy of the run; it
    is passed explicitly and never inferred from which fields are present.
    """
    if pov_admission_mode not in _POV_ADMISSION_MODES:
        return _unproven("POV_ADMISSION_MODE_INVALID")
    if (not all(type(value) is str and ObjectId.is_valid(value)
                for value in (task_id, direction_id, sp_id)) or
            not isinstance(gate, CampaignModelGate) or
            len({sp_request_id, verifier_request_id, pov_request_id}) != 3):
        return _unproven("INVALID_LINEAGE_IDENTITY")
    try:
        validated_snapshot = (gate.snapshot() if _validated_snapshot is None
                              else _validated_snapshot)
        sp_row, sp_args, sp_result, sp_response, sp_event = _tool(
            gate, sp_request_id, sp_call_id, frozenset({"sp", "sp_large"}),
            "create_suspicious_point",
            validated_snapshot=validated_snapshot)
        verify_row, verify_args, verify_result, verify_response, verify_event = _tool(
            gate, verifier_request_id, verifier_call_id, "verifier",
            "update_suspicious_point",
            validated_snapshot=validated_snapshot)
        pov_row, pov_args, pov_result, pov_response, pov_event = _tool(
            gate, pov_request_id, pov_call_id, "pov", "create_pov",
            validated_snapshot=validated_snapshot)
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
                ("merged" in sp_result and sp_result["merged"] is not False) or
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
        if (not _owner("verify", sp_id, verify_row["owner_id"],
                       task_id=task_id, sources=point.sources) or
                verify_args.get("suspicious_point_id") != sp_id or
                verify_args.get("is_checked") is not True or
                not _verifier_admitted(pov_admission_mode, verify_args, point) or
                verify_result.get("success") is not True or
                verify_result.get("updated") is not True or
                verify_result.get("server_result", {}).get("updated") is not True or
                not point.is_checked or
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
        if (not _owner("pov", sp_id, pov_row["owner_id"],
                       task_id=task_id, sources=point.sources) or
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
        pov_contributors = set()
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
                    if not path.is_absolute():
                        raise ValueError("PoV blob path mismatch")
                    if callable(getattr(gate, "read_artifact", None)):
                        saved_blob = gate.read_artifact(
                            str(path),
                            expected_sha256=hashlib.sha256(blob).hexdigest())
                    else:
                        if (path.is_symlink() or
                                any(parent.is_symlink() for parent in path.parents)):
                            raise ValueError("PoV blob path mismatch")
                        saved_blob = path.read_bytes()
                    if saved_blob != blob:
                        raise ValueError("PoV blob path mismatch")
            except (ValueError, OSError, binascii.Error):
                return _unproven("POV_BLOB_MISMATCH")
            generation_ids.add(pov.generation_id)
            pov_agent_ids.add(pov.agent_id)
            pov_contributors.add((pov.harness_name, pov.sanitizer))
            inputs.append({"pov_id": pov_id,
                           "input_sha256": hashlib.sha256(blob).hexdigest()})
        if (len(generation_ids) != 1 or not next(iter(generation_ids)) or
                len(pov_agent_ids) != 1 or len(pov_contributors) != 1):
            return _unproven("POV_GENERATION_MISMATCH")
        pov_harness, pov_sanitizer = next(iter(pov_contributors))
        if (not isinstance(pov_harness, str) or not pov_harness or
                not isinstance(pov_sanitizer, str) or not pov_sanitizer or
                not _owner("pov", sp_id, pov_row["owner_id"], task_id=task_id,
                           sources=point.sources,
                           expected_harness_name=pov_harness,
                           expected_sanitizer=pov_sanitizer)):
            return _unproven("POV_OWNER_HARNESS_MISMATCH")
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
        hypothesis, hypothesis_sha = _authenticated_untrusted_hypothesis(
            task_id=task_id, direction_id=direction_id, sp_id=sp_id,
            function_id=function_id, sp_args=sp_args,
            verify_args=verify_args)
        archived = getattr(gate, "archive_replay", False) is True
        return {"status": ("ARCHIVED_LINEAGE_REVALIDATED" if archived else
                           "VERIFIED"),
                "campaign_id": gate.campaign_id,
                "task_id": task_id, "direction_id": direction_id,
                "sp_id": sp_id, "sp_request_id": sp_request_id,
                "verifier_request_id": verifier_request_id,
                "pov_request_id": pov_request_id, "model_tool_turns": turns,
                "pov_inputs": inputs,
                "untrusted_sp_hypothesis": hypothesis,
                "untrusted_sp_hypothesis_sha256": hypothesis_sha,
                "automatic_discovery": False,
                "discovery_credit": ("NOT_CREDITED_ARCHIVE_REPLAY" if archived
                                     else "NOT_CREDITED_BY_LINEAGE_ONLY")}
    except (CampaignGateError, ValueError, TypeError, KeyError, IndexError,
            AttributeError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unproven(type(exc).__name__ + ":" + str(exc)[:120])


def find_candidate_lineage(gate: CampaignModelGate, repos: Any, *,
                           task_id: str, pov_id: str,
                           pov_admission_mode: str = "legacy_score",
                           ) -> dict[str, Any]:
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
        validated_snapshot = gate.snapshot()
        for row in validated_snapshot["records"]:
            for event in row.get("tool_events", []):
                # A STARTED/INCOMPLETE host-tool event has no authenticated
                # result artifact and therefore cannot be the producer of an
                # already-saved PoV.  In particular, a trailing tool cancelled
                # at the campaign budget boundary must not make every earlier,
                # fully-receipted candidate look corrupt.  Completed events
                # remain fail-closed below: any unreadable result still makes
                # the lineage unproven rather than silently disappearing from
                # the uniqueness check.
                if event.get("status") != "COMPLETED":
                    continue
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
                hint = _event_candidate_hint(
                    gate, row, event, selected=selected,
                    sp_id=pov.suspicious_point_id, pov_id=pov_id)
                if hint == "CORRUPT":
                    return _unproven(
                        "CANDIDATE_HINT_ARTIFACT_CHANGED_OR_UNREADABLE")
                if hint != "MATCH":
                    continue
                try:
                    _, args, result, _, _ = _tool(
                        gate, row["request_id"], event["call_id"],
                        frozenset({"sp", "sp_large"}) if selected == "sp"
                        else selected, kind,
                        validated_snapshot=validated_snapshot)
                except (CampaignGateError, ValueError, TypeError, KeyError,
                        IndexError, AttributeError, OSError, UnicodeError,
                        json.JSONDecodeError):
                    # A matching related event that cannot be authenticated is
                    # not absence of evidence. Dropping it could turn two
                    # candidates into an apparently unique lineage.
                    return _unproven(
                        "MATCHING_CANDIDATE_AUTHENTICATION_FAILED")
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
            pov_call_id=matches["pov"][0][1],
            _validated_snapshot=validated_snapshot,
            pov_admission_mode=pov_admission_mode)
    except (CampaignGateError, ValueError, TypeError, KeyError, IndexError,
            AttributeError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unproven(type(exc).__name__ + ":" + str(exc)[:120])
