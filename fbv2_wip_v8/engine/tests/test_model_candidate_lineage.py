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
import pytest

from devtools.campaign_model_gate import (
    CampaignModelGate, _response_evidence, campaign_candidate_owner_id,
)
from devtools.model_candidate_lineage import (
    _owner, find_candidate_lineage, verify_candidate_lineage,
)
from devtools.frozen_candidate_lineage import (
    FrozenArchiveError,
    FrozenArtifactResolver,
    FrozenCampaignModelGate,
    FrozenRepos,
    revalidate_archived_candidate_lineage,
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
            agent_id, *, incomplete_error=None):
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
    if incomplete_error is None:
        gate.complete_tool_event(request_id, call_id, json.dumps(result))
    else:
        gate.fail_tool_event(request_id, call_id, incomplete_error)
    return call_id


def _case(tmp_path, repos, *, sp_result_override=None,
          verifier_sp_id_override=None, duplicate_function_name=False,
          new_pov_owner=False):
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
    point = SuspiciousPoint(
        suspicious_point_id=sp_id, task_id=task_id,
        direction_id=direction_id, function_name=function_name,
        description="candidate", vuln_type="buffer-overflow",
        score=0.9, is_checked=True, is_important=True,
        verification_notes="checked", pov_guidance="target input",
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        created_by_agent_id=creator,
        verified_by_agent_id=verifier)
    repos.suspicious_points.collection.insert_one(point.to_dict())
    code = "def generate(variant): return b'abc'"
    assert repos.povs.save(POV(
        pov_id=pov_id, task_id=task_id, suspicious_point_id=sp_id,
        generation_id=str(ObjectId()), agent_id=pov_agent, source="agent",
        harness_name="fuzz", sanitizer="address",
        gen_blob=code, blob=base64.b64encode(b"abc").decode()))
    gate = CampaignModelGate(tmp_path / "campaign.json", "provider-free-fixture",
                             4, 60, create=True)
    # The real create_suspicious_point tool omits `merged` on new candidates.
    sp_result = {"success": True, "created": True, "id": sp_id}
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
    pov_owner = (campaign_candidate_owner_id(
        agent_id="pov_1", task_id=task_id, harness_name="fuzz",
        sanitizer="address", sp_id=sp_id) if new_pov_owner else
        f"pov_1:{sp_id}")
    pov_call = _record(gate, "pov1", "pov", pov_owner,
                       "create_pov", {"generator_code": code},
                       {"success": True, "pov_ids": [pov_id],
                        "count": 1, "attempt": 1}, pov_agent)
    args = dict(gate=gate, repos=repos, task_id=task_id,
                direction_id=direction_id, sp_id=sp_id,
                sp_request_id="sp1", sp_call_id=sp_call,
                verifier_request_id="verify1", verifier_call_id=verifier_call,
                pov_request_id="pov1", pov_call_id=pov_call)
    return args, pov_id


def _frozen_case(tmp_path, repos, *, omit_pov=False, grow_event_log=False):
    args, pov_id = _case(tmp_path, repos)
    gate = args["gate"]
    if grow_event_log:
        evidence = gate.snapshot()["records"][0]["response_evidence"]
        event_path = Path(evidence["event_log_path"])
        event_path.write_bytes(
            event_path.read_bytes() +
            _json_bytes({"method": "unrelated/later-turn"}) + b"\n")
    archive = tmp_path / "archive"
    artifacts = archive / "artifacts"
    artifacts.mkdir(parents=True)
    function_id = gate.snapshot()["records"][0]["owner_id"].split(":", 1)[1]
    function_id = function_id.rsplit(":", 1)[0]
    function = repos.functions.find_by_id(function_id)
    point = repos.suspicious_points.find_by_id(args["sp_id"])
    pov = repos.povs.find_by_id(pov_id)
    snapshot = {
        "kind": "FBV2_FROZEN_LINEAGE_DB_SNAPSHOT_V1",
        "functions": [{
            "function_id": function.function_id,
            "task_id": function.task_id,
            "name": function.name,
            "file_path": function.file_path,
            "start_line": function.start_line,
            "end_line": function.end_line,
            "content": function.content,
        }],
        "suspicious_points": [{
            "suspicious_point_id": point.suspicious_point_id,
            "task_id": point.task_id,
            "direction_id": point.direction_id,
            "function_name": point.function_name,
            "created_by_agent_id": point.created_by_agent_id,
            "verified_by_agent_id": point.verified_by_agent_id,
            "sources": point.sources,
            "description": point.description,
            "vuln_type": point.vuln_type,
            "is_checked": point.is_checked,
            "is_real": point.is_real,
            "score": point.score,
            "is_important": point.is_important,
            "verification_notes": point.verification_notes,
            "pov_guidance": point.pov_guidance,
        }],
        "povs": ([] if omit_pov else [{
            "pov_id": pov.pov_id,
            "task_id": pov.task_id,
            "suspicious_point_id": pov.suspicious_point_id,
            "generation_id": pov.generation_id,
            "agent_id": pov.agent_id,
            "source": pov.source,
            "attempt": pov.attempt,
            "blob": pov.blob,
            "blob_path": pov.blob_path,
            "gen_blob": pov.gen_blob,
            "harness_name": pov.harness_name,
            "sanitizer": pov.sanitizer,
        }]),
    }
    snapshot_logical = "/frozen/db_snapshot.json"
    snapshot_bytes = _json_bytes(snapshot)
    paths = {str(gate.path): gate.path.read_bytes(),
             snapshot_logical: snapshot_bytes}
    for row in gate.snapshot()["records"]:
        evidence = row.get("response_evidence")
        if evidence and evidence.get("status") == "VERIFIED":
            paths[evidence["response_path"]] = Path(
                evidence["response_path"]).read_bytes()
            paths[evidence["event_log_path"]] = Path(
                evidence["event_log_path"]).read_bytes()
        for event in row.get("tool_events", []):
            if event.get("result_path"):
                paths[event["result_path"]] = Path(event["result_path"]).read_bytes()
    manifest_rows = []
    for index, (logical, raw) in enumerate(sorted(paths.items())):
        relative = f"artifacts/{index:03d}.bin"
        _private(archive / relative, raw)
        manifest_rows.append({
            "logical_path": logical,
            "archive_path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        })
    manifest = {"kind": "FBV2_FROZEN_ARTIFACT_MANIFEST_V1",
                "artifacts": manifest_rows}
    manifest_bytes = _json_bytes(manifest)
    _private(archive / "manifest.json", manifest_bytes)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    resolver = FrozenArtifactResolver(
        archive, "manifest.json", manifest_sha256=manifest_sha)
    frozen_gate = FrozenCampaignModelGate(resolver, str(gate.path))
    frozen_repos = FrozenRepos(
        resolver, snapshot_logical,
        snapshot_sha256=hashlib.sha256(snapshot_bytes).hexdigest())
    return {
        "archive": archive,
        "manifest": manifest,
        "manifest_sha": manifest_sha,
        "resolver": resolver,
        "gate": frozen_gate,
        "repos": frozen_repos,
        "task_id": args["task_id"],
        "direction_id": args["direction_id"],
        "sp_id": args["sp_id"],
        "pov_id": pov_id,
    }


def test_model_to_sp_verifier_pov_input_lineage(tmp_path, repos):
    args, pov_id = _case(tmp_path, repos)
    result = verify_candidate_lineage(**args)
    assert result["status"] == "VERIFIED"
    assert result["pov_inputs"] == [{
        "pov_id": pov_id, "input_sha256": hashlib.sha256(b"abc").hexdigest()}]
    assert result["discovery_credit"] == "NOT_CREDITED_BY_LINEAGE_ONLY"
    hypothesis = result["untrusted_sp_hypothesis"]
    assert hypothesis["function_name"] == "parse_input"
    assert hypothesis["vulnerability_type"] == "buffer-overflow"
    assert hypothesis["source_file"] is None
    assert hypothesis["code_location"] == "UNKNOWN"
    assert hypothesis["exact_source_location_status"] == "UNPROVEN"
    assert result["untrusted_sp_hypothesis_sha256"] == hashlib.sha256(
        json.dumps(hypothesis, sort_keys=True, separators=(",", ":"),
                   allow_nan=False).encode()).hexdigest()
    assert [turn["role"] for turn in result["model_tool_turns"]] == [
        "sp", "verifier", "pov"]
    discovered = find_candidate_lineage(args["gate"], repos,
                                        task_id=args["task_id"], pov_id=pov_id)
    assert discovered == result


def test_candidate_lookup_validates_large_ledger_once(tmp_path, repos):
    args, pov_id = _case(tmp_path, repos)
    gate = args["gate"]
    with patch.object(gate, "snapshot", wraps=gate.snapshot) as snapshot:
        result = find_candidate_lineage(
            gate, repos, task_id=args["task_id"], pov_id=pov_id)
    assert result["status"] == "VERIFIED"
    assert snapshot.call_count == 1


def test_model_tool_db_input_and_qualified_runtime_in_one_chain(tmp_path, repos):
    product_src = Path(__file__).resolve().parents[2] / "product" / "src"
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
    repos.suspicious_points.collection.update_one(
        {"_id": ObjectId(args["sp_id"])}, {"$set": {"sources": [
            {"harness_name": "fuzz_fixture", "sanitizer": "address"}]}})
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


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("description", "mutated after receipt", "SP_DB_OR_OWNER_MISMATCH"),
    ("vuln_type", "different-family", "SP_DB_OR_OWNER_MISMATCH"),
    ("pov_guidance", "mutated verifier guidance",
     "VERIFIER_RESULT_MISMATCH"),
])
def test_mutable_sp_db_cannot_rewrite_authenticated_hypothesis(
    tmp_path, repos, field, value, reason,
):
    args, _ = _case(tmp_path, repos)
    repos.suspicious_points.collection.update_one(
        {"_id": ObjectId(args["sp_id"])}, {"$set": {field: value}})
    result = verify_candidate_lineage(**args)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == reason


def test_function_index_location_is_not_promoted_to_model_sp_location(
    tmp_path, repos,
):
    args, _ = _case(tmp_path, repos)
    first = verify_candidate_lineage(**args)
    function_id = first["untrusted_sp_hypothesis"]["campaign_function_id"]
    repos.functions.collection.update_one(
        {"_id": function_id},
        {"$set": {"file_path": "changed/location.c", "start_line": 999}})
    second = verify_candidate_lineage(**args)
    assert second["status"] == "VERIFIED"
    assert second["untrusted_sp_hypothesis"] == first[
        "untrusted_sp_hypothesis"]
    assert second["untrusted_sp_hypothesis"]["source_file"] is None
    assert second["untrusted_sp_hypothesis"]["code_location"] == "UNKNOWN"


def test_matching_event_authentication_failure_is_not_silently_dropped(
    tmp_path, repos,
):
    args, pov_id = _case(tmp_path, repos)
    raw = args["gate"].path.with_name("campaign.json.sp1.raw.json")
    raw.write_bytes(raw.read_bytes() + b" ")
    result = find_candidate_lineage(
        args["gate"], repos, task_id=args["task_id"], pov_id=pov_id)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == "MATCHING_CANDIDATE_AUTHENTICATION_FAILED"


def test_changed_hint_artifact_cannot_disappear_from_uniqueness_check(
    tmp_path, repos,
):
    args, pov_id = _case(tmp_path, repos)
    result_path = args["gate"].path.with_name(
        "campaign.json.sp1.0.tool.txt")
    result_path.write_bytes(result_path.read_bytes() + b" ")
    result = find_candidate_lineage(
        args["gate"], repos, task_id=args["task_id"], pov_id=pov_id)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == \
        "CANDIDATE_HINT_ARTIFACT_CHANGED_OR_UNREADABLE"


def test_trailing_incomplete_tool_does_not_corrupt_prior_pov_lineage(
    tmp_path, repos,
):
    args, pov_id = _case(tmp_path, repos)
    point = repos.suspicious_points.find_by_id(args["sp_id"])
    pov_agent = str(ObjectId())
    _record(
        args["gate"], "pov2", "pov", f"pov_2:{args['sp_id']}",
        "create_pov", {"generator_code": "def generate(n): return b'x'"},
        {}, pov_agent, incomplete_error="CancelledError")

    result = find_candidate_lineage(
        args["gate"], repos, task_id=args["task_id"], pov_id=pov_id)

    assert point is not None
    assert result["status"] == "VERIFIED"
    assert result["pov_inputs"] == [{
        "pov_id": pov_id,
        "input_sha256": hashlib.sha256(b"abc").hexdigest(),
    }]



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


def test_new_candidate_owner_is_bound_to_task_harness_and_sanitizer():
    task_id = str(ObjectId())
    sp_id = str(ObjectId())
    sources = [{"harness_name": "fuzz-a", "sanitizer": "address"}]
    owner = campaign_candidate_owner_id(
        agent_id="pov_1", task_id=task_id, harness_name="fuzz-a",
        sanitizer="address", sp_id=sp_id)
    assert _owner("pov", sp_id, owner, task_id=task_id, sources=sources)
    assert not _owner(
        "pov", sp_id, owner, task_id=task_id,
        sources=[{"harness_name": "fuzz-b", "sanitizer": "address"}])


def test_new_owner_must_match_actual_pov_harness(tmp_path, repos):
    args, pov_id = _case(tmp_path, repos, new_pov_owner=True)
    assert repos.suspicious_points.add_source(
        args["sp_id"], "other", "address")
    repos.povs.collection.update_one(
        {"_id": ObjectId(pov_id)}, {"$set": {"harness_name": "other"}})
    assert verify_candidate_lineage(**args)["reason"] == \
        "POV_OWNER_HARNESS_MISMATCH"


def test_frozen_archive_revalidates_without_discovery_credit(tmp_path, repos):
    case = _frozen_case(tmp_path, repos)
    result = revalidate_archived_candidate_lineage(
        case["gate"], case["repos"],
        task_id=case["task_id"], pov_id=case["pov_id"])
    assert result["status"] == "ARCHIVED_LINEAGE_REVALIDATED"
    assert result["automatic_discovery"] is False
    assert result["discovery_credit"] == "NOT_CREDITED_ARCHIVE_REPLAY"
    assert result["security_gate_status"] == "NOT_EVALUATED_BY_ARCHIVE_REPLAY"
    assert result["archive_manifest_sha256"] == case["manifest_sha"]
    assert result["frozen_db_snapshot_sha256"] == case["repos"].snapshot_sha256


def test_frozen_archive_accepts_exact_preidentified_lineage(tmp_path, repos):
    case = _frozen_case(tmp_path, repos)
    rows = case["gate"].snapshot()["records"]
    by_role = {row["role"]: row for row in rows}
    result = revalidate_archived_candidate_lineage(
        case["gate"], case["repos"],
        task_id=case["task_id"], pov_id=case["pov_id"],
        exact_lineage={
            "direction_id": case["direction_id"],
            "sp_id": case["sp_id"],
            "sp_request_id": by_role["sp"]["request_id"],
            "sp_call_id": by_role["sp"]["tool_events"][0]["call_id"],
            "verifier_request_id": by_role["verifier"]["request_id"],
            "verifier_call_id": by_role["verifier"]["tool_events"][0]["call_id"],
            "pov_request_id": by_role["pov"]["request_id"],
            "pov_call_id": by_role["pov"]["tool_events"][0]["call_id"],
        })
    assert result["status"] == "ARCHIVED_LINEAGE_REVALIDATED"
    assert result["discovery_credit"] == "NOT_CREDITED_ARCHIVE_REPLAY"


def test_frozen_archive_event_manifest_binds_full_file_and_receipt_prefix(
    tmp_path, repos,
):
    case = _frozen_case(tmp_path, repos, grow_event_log=True)
    result = revalidate_archived_candidate_lineage(
        case["gate"], case["repos"],
        task_id=case["task_id"], pov_id=case["pov_id"])
    assert result["status"] == "ARCHIVED_LINEAGE_REVALIDATED"


def test_frozen_repositories_and_gate_are_read_only(tmp_path, repos):
    case = _frozen_case(tmp_path, repos)
    assert not hasattr(case["repos"].povs, "save")
    assert not hasattr(case["repos"].povs, "collection")
    with pytest.raises(Exception, match="read-only"):
        case["gate"].reserve(
            request_id="new", role="sp", owner_id="owner",
            request_sha256="0" * 64)


def test_frozen_archive_wrong_manifest_hash_is_rejected(tmp_path, repos):
    case = _frozen_case(tmp_path, repos)
    with pytest.raises(FrozenArchiveError, match="manifest SHA-256 mismatch"):
        FrozenArtifactResolver(
            case["archive"], "manifest.json", manifest_sha256="0" * 64)


def test_frozen_archive_changed_artifact_fails_closed(tmp_path, repos):
    case = _frozen_case(tmp_path, repos)
    tool_row = next(row for row in case["manifest"]["artifacts"]
                    if row["logical_path"].endswith(".tool.txt"))
    artifact = case["archive"] / tool_row["archive_path"]
    artifact.write_bytes(artifact.read_bytes() + b"changed")
    result = revalidate_archived_candidate_lineage(
        case["gate"], case["repos"],
        task_id=case["task_id"], pov_id=case["pov_id"])
    assert result["status"] == "ARCHIVE_REPLAY_UNPROVEN"
    assert result["discovery_credit"] == "NOT_CREDITED_ARCHIVE_REPLAY"


def test_frozen_archive_symlink_artifact_is_rejected(tmp_path, repos):
    case = _frozen_case(tmp_path, repos)
    tool_row = next(row for row in case["manifest"]["artifacts"]
                    if row["logical_path"].endswith(".tool.txt"))
    artifact = case["archive"] / tool_row["archive_path"]
    saved = artifact.read_bytes()
    artifact.unlink()
    target = case["archive"] / "target.bin"
    _private(target, saved)
    artifact.symlink_to(target)
    with pytest.raises(FrozenArchiveError):
        case["resolver"].read(tool_row["logical_path"])


def test_frozen_archive_traversal_mapping_is_rejected(tmp_path):
    archive = tmp_path / "archive"
    archive.mkdir()
    manifest = {"kind": "FBV2_FROZEN_ARTIFACT_MANIFEST_V1",
                "artifacts": [{
                    "logical_path": "/old/file",
                    "archive_path": "../outside",
                    "sha256": "0" * 64,
                    "size": 0,
                }]}
    raw = _json_bytes(manifest)
    _private(archive / "manifest.json", raw)
    with pytest.raises(FrozenArchiveError, match="escapes"):
        FrozenArtifactResolver(
            archive, "manifest.json",
            manifest_sha256=hashlib.sha256(raw).hexdigest())


def test_frozen_snapshot_missing_pov_is_unproven(tmp_path, repos):
    case = _frozen_case(tmp_path, repos, omit_pov=True)
    result = revalidate_archived_candidate_lineage(
        case["gate"], case["repos"],
        task_id=case["task_id"], pov_id=case["pov_id"])
    assert result == {
        "status": "ARCHIVE_REPLAY_UNPROVEN",
        "reason": "POV_NOT_IN_TASK",
        "automatic_discovery": False,
        "discovery_credit": "NOT_CREDITED_ARCHIVE_REPLAY",
    }
