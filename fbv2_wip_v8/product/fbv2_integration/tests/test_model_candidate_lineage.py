"""Provider-free evidence and DB boundary checks for candidate lineage."""

import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId

from devtools.campaign_model_gate import (
    CampaignModelGate, _response_evidence,
)
from devtools.model_candidate_lineage import (
    find_candidate_lineage, verify_candidate_lineage,
)
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.pov import POV
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _private(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _record(gate, request_id, role, owner_id, tool_name, args, result,
            agent_id):
    call_id = f"bridge_{request_id}_0"
    response = {"content": "", "tool_calls": [{"name": tool_name,
                 "arguments": json.dumps(args)}]}
    raw_path = gate.path.with_name(gate.path.name + f".{request_id}.raw.json")
    raw = _json_bytes(response)
    _private(raw_path, raw)
    event_path = gate.path.with_name(gate.path.name + f".{request_id}.events.jsonl")
    thread_id, turn_id = f"thread-{request_id}", f"turn-{request_id}"
    events = [
        {"method": "turn/started", "thread_id": thread_id,
         "turn_id": turn_id},
        {"method": "item/completed", "item_type": "agentMessage",
         "thread_id": thread_id, "turn_id": turn_id,
         "agent_message_sha256": hashlib.sha256(raw).hexdigest()},
        {"method": "turn/completed", "thread_id": thread_id,
         "turn_id": turn_id, "turn_status": "completed"},
    ]
    _private(event_path, b"".join(_json_bytes(row) + b"\n" for row in events))
    gate.reserve(request_id=request_id, role=role, owner_id=owner_id,
                 request_sha256=hashlib.sha256(request_id.encode()).hexdigest())
    evidence = _response_evidence(
        request_id=request_id, raw_path=raw_path, event_path=event_path,
        event_before=b"", result=response)
    gate.finish(request_id, completed=True, response_evidence=evidence)
    gate.begin_tool_event(request_id, {"id": call_id, "function": {
        "name": tool_name, "arguments": json.dumps(args)}}, agent_id=agent_id)
    gate.complete_tool_event(request_id, call_id, json.dumps(result))
    return call_id


def _case(tmp_path, repos, *, sp_result_override=None,
          verifier_sp_id_override=None, duplicate_function_name=False):
    task_id, direction_id, sp_id, pov_id = (str(ObjectId()) for _ in range(4))
    creator, verifier, pov_agent = (str(ObjectId()) for _ in range(3))
    function_name = "parse_input"
    if duplicate_function_name:
        assert repos.functions.save(Function(
            task_id=task_id, name=function_name,
            file_path="first.c", content="int parse_input(void) {return 1;}"))
    function = Function(
        function_id=(f"{task_id}_{function_name}::selected"
                     if duplicate_function_name else ""),
        task_id=task_id, name=function_name,
        file_path="parse.c", content="int parse_input(void) {return 0;}")
    assert repos.functions.save(function)
    assert repos.suspicious_points.save(SuspiciousPoint(
        suspicious_point_id=sp_id, task_id=task_id,
        direction_id=direction_id, function_name=function_name,
        description="candidate", vuln_type="buffer-overflow",
        score=0.9, is_checked=True, is_important=True,
        verification_notes="checked", pov_guidance="target input",
        created_by_agent_id=creator,
        verified_by_agent_id=verifier))
    code = "def generate(variant): return b'abc'"
    assert repos.povs.save(POV(
        pov_id=pov_id, task_id=task_id, suspicious_point_id=sp_id,
        generation_id=str(ObjectId()), agent_id=pov_agent, source="agent",
        gen_blob=code, blob=base64.b64encode(b"abc").decode()))
    gate = CampaignModelGate(tmp_path / "campaign.json", "provider-free-fixture",
                             4, 60, create=True)
    sp_result = {"success": True, "created": True, "merged": False, "id": sp_id}
    if sp_result_override:
        sp_result.update(sp_result_override)
    sp_call = _record(gate, "sp1", "sp",
                      f"{direction_id}:{function.function_id}:0",
                      "create_suspicious_point",
                      {"function_name": function_name, "description": "candidate",
                       "vuln_type": "buffer-overflow"}, sp_result, creator)
    verifier_call = _record(gate, "verify1", "verifier", f"verify_1:{sp_id}",
                            "update_suspicious_point",
                            {"suspicious_point_id":
                             verifier_sp_id_override or sp_id,
                             "is_checked": True,
                             "is_important": True, "score": 0.9,
                             "verification_notes": "checked",
                             "pov_guidance": "target input"},
                            {"success": True, "updated": True,
                             "server_result": {"updated": True}}, verifier)
    pov_call = _record(gate, "pov1", "pov", f"pov_1:{sp_id}",
                       "create_pov", {"generator_code": code},
                       {"success": True, "pov_ids": [pov_id],
                        "count": 1, "attempt": 1}, pov_agent)
    args = dict(gate=gate, repos=repos, task_id=task_id,
                direction_id=direction_id, sp_id=sp_id,
                sp_request_id="sp1", sp_call_id=sp_call,
                verifier_request_id="verify1", verifier_call_id=verifier_call,
                pov_request_id="pov1", pov_call_id=pov_call)
    return args, pov_id


def test_model_to_sp_verifier_pov_input_lineage(tmp_path, repos):
    args, pov_id = _case(tmp_path, repos)
    result = verify_candidate_lineage(**args)
    assert result["status"] == "VERIFIED"
    assert result["pov_inputs"] == [{
        "pov_id": pov_id, "input_sha256": hashlib.sha256(b"abc").hexdigest()}]
    assert result["discovery_credit"] == "NOT_CREDITED_BY_LINEAGE_ONLY"
    assert [turn["role"] for turn in result["model_tool_turns"]] == [
        "sp", "verifier", "pov"]
    discovered = find_candidate_lineage(args["gate"], repos,
                                        task_id=args["task_id"], pov_id=pov_id)
    assert discovered == result


def test_model_tool_db_input_and_qualified_runtime_in_one_chain(tmp_path, repos):
    product_src = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
    if str(product_src) not in sys.path:
        sys.path.insert(0, str(product_src))
    from devtools.product_qualified_runtime import (
        ProductQualifiedPoVAdapter, consume_qualified_pov_observation,
        verify_qualified_pov_runtime_lineage)
    from vulnerabilityanalysis import official_harness
    from vulnerabilityanalysis import scan
    from vulnerabilityanalysis.final_verification import crash_fingerprint
    from vulnerabilityanalysis.models import RuntimeResult
    from dataclasses import asdict

    args, pov_id = _case(tmp_path, repos)
    gate = args["gate"]
    candidate = find_candidate_lineage(gate, repos,
                                        task_id=args["task_id"], pov_id=pov_id)
    assert candidate["status"] == "VERIFIED"
    root = tmp_path / "qualified-runtime"
    attempt = root / pov_id
    attempt.mkdir(parents=True, mode=0o700)
    binary = tmp_path / "target"
    binary.write_bytes(b"provider-free binary fixture")
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    input_path = attempt / "input.bin"
    _private(input_path, b"abc")
    lease = {"key": f'{args["task_id"]}:{args["sp_id"]}:{pov_id}:'
                    '000000:pov.qualified_direct',
             "kind": "AUX_PROCESS", "cleanup_complete": True,
             "output_limited": False, "overrun": False}
    physical = {
        "kind": "FBV2_DEV_QUALIFIED_POV_PHYSICAL_V1",
        "task_id": args["task_id"], "work_item_id": args["task_id"],
        "run_id": gate.campaign_id, "sp_id": args["sp_id"],
        "pov_id": pov_id, "input_sha256": hashlib.sha256(b"abc").hexdigest(),
        "input_path": str(input_path), "binary_sha256": binary_sha,
        "ledger_path": str(tmp_path / "physical-ledger.json"), "lease": lease}
    physical_path = attempt / "physical.json"
    _private(physical_path, _json_bytes(physical))
    runtime = {
        "kind": "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1",
        "task_id": args["task_id"], "work_item_id": args["task_id"],
        "run_id": gate.campaign_id, "sp_id": args["sp_id"],
        "pov_id": pov_id, "input_sha256": physical["input_sha256"],
        "input_path": str(input_path), "binary_sha256": binary_sha,
        "physical_receipt_sha256": hashlib.sha256(physical_path.read_bytes()).hexdigest(),
        "status": "NO_CRASH", "source": "FBV2_POV",
        "command": [str(binary), str(input_path)],
        "runtime": {"exit_code": 0, "stdout": "", "stderr": "",
                    "signal": None, "timed_out": False, "sanitizer": None,
                    "stack_trace": None, "failure_classification": "NONE"}}
    runtime_path = attempt / "runtime.json"
    _private(runtime_path, _json_bytes(runtime))
    repos.povs.collection.update_one(
        {"_id": ObjectId(pov_id)}, {"$set": {
            "harness_name": "fuzz_fixture", "sanitizer": "address",
            "qualified_runtime": {
                "status": "NO_CRASH", "input_sha256": physical["input_sha256"],
                "binary_sha256": binary_sha,
                "runtime_receipt_path": str(runtime_path),
                "runtime_receipt_sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
                "physical_receipt_path": str(physical_path),
                "physical_receipt_sha256": hashlib.sha256(physical_path.read_bytes()).hexdigest()}}})
    adapter = object.__new__(ProductQualifiedPoVAdapter)
    adapter.root = root
    adapter.repos = repos
    adapter.task_id = args["task_id"]
    adapter.work_item_id = args["task_id"]
    adapter.run_id = gate.campaign_id
    adapter.fuzzer = "fuzz_fixture"
    adapter.sanitizer = "address"
    adapter.ledger = SimpleNamespace(
        path=tmp_path / "physical-ledger.json",
        snapshot=lambda: {"finished": [lease]})
    adapter.binding = SimpleNamespace(
        qualification=SimpleNamespace(
            source_root=tmp_path, harness=tmp_path / "harness.c",
            source_tree_sha256="1" * 64,
            harness_sha256="2" * 64, contract_sha256="3" * 64),
        pinned_binary=lambda: (binary, binary_sha))
    adapter.binding.qualification.harness.write_text("// fixture\n")
    adapter.output_limit_bytes = 4_000_000
    adapter.wall_seconds = 30
    adapter._envelope_type = lambda ledger, **_kwargs: SimpleNamespace(ledger=ledger)
    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(official_harness, "_qualification_pins_ok",
                      return_value=True):
        combined = verify_qualified_pov_runtime_lineage(
            adapter, pov_id, gate, recheck=lambda: None)
        assert combined["status"] == "VERIFIED"
        assert [row["role"] for row in combined["model_tool_turns"]] == [
            "sp", "verifier", "pov"]
        assert combined["discovery_credit"] == "NOT_CREDITED_BY_LINEAGE_ONLY"
        crash_runtime = dict(runtime)
        crash_runtime["status"] = "CRASH_OBSERVED"
        crash_runtime["runtime"] = {
            **runtime["runtime"], "exit_code": 1,
            "sanitizer": "AddressSanitizer: heap-buffer-overflow",
            "stderr": "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                      "#0 0x1 in target /tmp/target.c:1:1\n",
            "stack_trace": "#0 target /tmp/target.c:1:1"}
        runtime_path.write_bytes(_json_bytes(crash_runtime))
        repos.povs.collection.update_one(
            {"_id": ObjectId(pov_id)}, {"$set": {
                "qualified_runtime.status": "CRASH_OBSERVED",
                "qualified_runtime.runtime_receipt_sha256":
                    hashlib.sha256(runtime_path.read_bytes()).hexdigest()}})

        def fake_product_gate(poc, _point, _command, run_dir, **_kwargs):
            result = RuntimeResult(**crash_runtime["runtime"])
            output = run_dir / "runtime"
            (output / "crashes").mkdir(parents=True)
            (output / f"{poc.poc_id}.json").write_text(json.dumps(asdict(result)))
            crash_id = crash_fingerprint(result)
            (output / "crashes" / f"{crash_id}.json").write_text(json.dumps({
                "independent_verification_status": "PENDING_CAUSAL_EVIDENCE",
                "independent_gate_trace": {"crash_id": crash_id,
                                           "security_property_state": "NOT_STARTED",
                                           "promotion_state": "NOT_STARTED"}}))
            return []

        with patch.object(scan, "execute_poc", side_effect=fake_product_gate):
            consumed = consume_qualified_pov_observation(
                adapter, pov_id, recheck=lambda: None, timeout_seconds=2,
                model_gate=gate)
        assert consumed["origin_verification_status"] == (
            "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE")
        origin = json.loads(Path(consumed["origin_lineage_receipt_path"]).read_text())
        assert origin["lineage"]["model_tool_turns"] == combined["model_tool_turns"]
        assert consumed["automatic_discovery"] is False
        assert consumed["discovery_credit"] == "NOT_CREDITED"
        assert consumed["product_gate_status"] == "PENDING_CAUSAL_EVIDENCE"
        input_path.write_bytes(b"changed")
        assert verify_qualified_pov_runtime_lineage(
            adapter, pov_id, gate, recheck=lambda: None)["status"] == "UNPROVEN"


def test_selected_overload_cannot_claim_sp_db_binding_by_name(tmp_path, repos):
    args, _ = _case(tmp_path, repos, duplicate_function_name=True)
    first = repos.functions.find_by_name(args["task_id"], "parse_input")
    assert first.function_id == f'{args["task_id"]}_parse_input'
    assert "::selected:" in args["gate"].snapshot()["records"][0]["owner_id"]
    assert verify_candidate_lineage(**args)["reason"] == "SP_FUNCTION_NAME_AMBIGUOUS"


def test_truncated_or_merged_sp_result_is_unproven(tmp_path, repos):
    args, _ = _case(tmp_path, repos,
                    sp_result_override={"id": "deadbeef", "merged": True,
                                        "created": False})
    assert verify_candidate_lineage(**args)["reason"] == "SP_CREATE_RESULT_UNPROVEN"


def test_wrong_pov_candidate_or_blob_is_unproven(tmp_path, repos):
    args, pov_id = _case(tmp_path, repos)
    repos.povs.collection.update_one({"_id": ObjectId(pov_id)},
                                     {"$set": {"suspicious_point_id": ObjectId()}})
    assert verify_candidate_lineage(**args)["reason"] == "POV_DB_IDENTITY_MISMATCH"
    repos.povs.collection.update_one({"_id": ObjectId(pov_id)},
                                     {"$set": {"suspicious_point_id":
                                               ObjectId(args["sp_id"]),
                                               "blob": "!!not-base64!!"}})
    assert verify_candidate_lineage(**args)["reason"] == "POV_BLOB_MISMATCH"


def test_changed_model_response_is_unproven(tmp_path, repos):
    args, _ = _case(tmp_path, repos)
    raw = args["gate"].path.with_name("campaign.json.sp1.raw.json")
    raw.write_bytes(raw.read_bytes() + b" ")
    assert verify_candidate_lineage(**args)["status"] == "UNPROVEN"



def test_verifier_on_other_sp_or_missing_tool_event_is_unproven(tmp_path, repos):
    args, _ = _case(tmp_path, repos, verifier_sp_id_override=str(ObjectId()))
    assert verify_candidate_lineage(**args)["reason"] == "VERIFIER_DB_OR_OWNER_MISMATCH"
    args["pov_call_id"] = "bridge_pov1_1"
    assert verify_candidate_lineage(**args)["status"] == "UNPROVEN"


def test_db_agent_ids_must_match_host_tool_context(tmp_path, repos):
    args, pov_id = _case(tmp_path, repos)
    repos.suspicious_points.collection.update_one(
        {"_id": ObjectId(args["sp_id"])},
        {"$set": {"created_by_agent_id": ObjectId()}})
    assert verify_candidate_lineage(**args)["reason"] == "SP_DB_OR_OWNER_MISMATCH"

    creator = args["gate"].snapshot()["records"][0]["tool_events"][0]["agent_id"]
    repos.suspicious_points.collection.update_one(
        {"_id": ObjectId(args["sp_id"])},
        {"$set": {"created_by_agent_id": ObjectId(creator),
                  "verified_by_agent_id": ObjectId()}})
    assert verify_candidate_lineage(**args)["reason"] == "VERIFIER_DB_OR_OWNER_MISMATCH"

    verifier = args["gate"].snapshot()["records"][1]["tool_events"][0]["agent_id"]
    repos.suspicious_points.collection.update_one(
        {"_id": ObjectId(args["sp_id"])},
        {"$set": {"verified_by_agent_id": ObjectId(verifier)}})
    repos.povs.collection.update_one(
        {"_id": ObjectId(pov_id)}, {"$set": {"agent_id": ObjectId()}})
    assert verify_candidate_lineage(**args)["reason"] == "POV_DB_IDENTITY_MISMATCH"


def test_model_request_order_does_not_substitute_for_tool_order(tmp_path, repos):
    args, _ = _case(tmp_path, repos)
    def reorder(payload):
        verify = payload["records"][1]["tool_events"][0]
        pov = payload["records"][2]["tool_events"][0]
        verify["start_order"], pov["start_order"] = (
            pov["start_order"], verify["start_order"])
        verify["complete_order"], pov["complete_order"] = (
            pov["complete_order"], verify["complete_order"])
    args["gate"]._mutate(reorder)
    assert verify_candidate_lineage(**args)["reason"] == "TOOL_EXECUTION_ORDER_UNPROVEN"
