"""A settled malformed PoV proposal is a candidate failure, not a worker stop."""

import json
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bson import ObjectId
import mongomock

from devtools.campaign_model_gate import (
    CampaignLedgeredProvider, CampaignModelGate,
    campaign_candidate_owner_id,
)
from fuzzingbrain.agents.pov_agent import POVAgent
from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.worker.pipeline import AgentPipeline
from fuzzingbrain.worker.pipeline import PipelineStats


def _local_case(tmp_path: Path):
    gate = CampaignModelGate(tmp_path / "model.json", "fixture", None, None,
                             create=True)
    owner = f"pov_2:{ObjectId()}"
    provider = CampaignLedgeredProvider(object(), gate, role="pov",
                                        owner_id=owner)
    client = SimpleNamespace(provider=provider, agent_id=str(ObjectId()))
    factory = SimpleNamespace(_fbv2_campaign_gate=gate)
    pipeline = AgentPipeline.__new__(AgentPipeline)
    pipeline.llm_client_factory = factory
    agent = SimpleNamespace(stop_reason="invalid_model_tool_json",
                            max_pov_attempts=20)
    result = SimpleNamespace(success=False, crashed=False, pending_runtime=False,
                             pending_validation=False, pov_attempts=11,
                             error_msg=None, completed_at=object())
    paths = []
    rows = []
    for index in range(2):
        path = tmp_path / f"response-{index}.json"
        path.write_text(json.dumps({"tool_calls": [{"name": "create_pov",
                                                  "arguments": '{"x":'}]}))
        path.chmod(0o600)
        paths.append(path)
        rows.append({"role": "pov", "owner_id": owner,
                     "request_id": f"request-{index}", "status": "COMPLETED",
                     "tool_events": []})
    def evidence(request_id):
        return {"status": "VERIFIED",
                "response_path": str(paths[int(request_id.split("-")[-1])])}
    return pipeline, gate, client, agent, result, owner, rows, evidence


def test_settled_invalid_pov_json_is_local(tmp_path):
    pipeline, gate, client, agent, result, owner, rows, evidence = _local_case(
        tmp_path)
    with patch.object(gate, "snapshot", return_value={"records": rows}), patch.object(
            gate, "verify_response_evidence", side_effect=evidence):
        assert pipeline._settled_local_pov_json_failure(
            client, agent, result, owner)


def test_first_settled_invalid_pov_json_is_already_local(tmp_path):
    pipeline, gate, client, agent, result, owner, rows, evidence = _local_case(
        tmp_path)
    with patch.object(gate, "snapshot", return_value={"records": rows[:1]}), \
            patch.object(gate, "verify_response_evidence", side_effect=evidence):
        assert pipeline._settled_local_pov_json_failure(
            client, agent, result, owner)


def test_unrelated_incomplete_owner_does_not_poison_local_json_proof(tmp_path):
    pipeline, gate, client, agent, result, owner, rows, evidence = _local_case(
        tmp_path)
    for changed in (
        {"role": "verifier", "owner_id": "other", "request_id": "other",
         "status": "UNCERTAIN", "tool_events": []},
        {"role": "pov", "owner_id": "other", "request_id": "stopped",
         "status": "PENDING_STOP", "tool_events": []},
        {"role": "pov", "owner_id": "other", "request_id": "other",
         "status": "COMPLETED", "tool_events": [{"status": "INCOMPLETE"}]},
    ):
        with patch.object(gate, "snapshot", return_value={"records": [*rows, changed]}), \
                patch.object(gate, "verify_response_evidence", side_effect=evidence):
            assert pipeline._settled_local_pov_json_failure(
                client, agent, result, owner)


def test_own_remote_uncertainty_still_blocks_local_json_proof(tmp_path):
    pipeline, gate, client, agent, result, owner, rows, evidence = _local_case(
        tmp_path)
    own_uncertain = {**rows[-1], "status": "UNCERTAIN"}
    with patch.object(gate, "snapshot", return_value={
            "records": [*rows[:-1], own_uncertain]}), patch.object(
            gate, "verify_response_evidence", side_effect=evidence):
        assert not pipeline._settled_local_pov_json_failure(
            client, agent, result, owner)


def test_same_sp_different_harness_has_distinct_local_owner(tmp_path):
    pipeline, gate, client, agent, result, _owner_id, rows, evidence = _local_case(
        tmp_path)
    sp_id = str(ObjectId())
    owner_a = campaign_candidate_owner_id(
        agent_id="pov_1", task_id="task", harness_name="fuzz-a",
        sanitizer="address", sp_id=sp_id)
    owner_b = campaign_candidate_owner_id(
        agent_id="pov_1", task_id="task", harness_name="fuzz-b",
        sanitizer="address", sp_id=sp_id)
    assert owner_a != owner_b
    client.provider.owner_id = owner_b
    own_rows = [{**row, "owner_id": owner_b} for row in rows]
    stopped_a = {"role": "pov", "owner_id": owner_a,
                 "request_id": "stopped-a", "status": "PENDING_STOP",
                 "tool_events": []}
    with patch.object(gate, "snapshot", return_value={
            "records": [*own_rows, stopped_a]}), patch.object(
            gate, "verify_response_evidence", side_effect=evidence):
        assert pipeline._settled_local_pov_json_failure(
            client, agent, result, owner_b)


def test_other_candidate_in_flight_is_not_cancelled_by_local_json(tmp_path):
    pipeline, gate, client, agent, result, owner, rows, evidence = _local_case(
        tmp_path)
    other = {"role": "pov", "owner_id": "pov_3:other",
             "request_id": "other", "status": "COMPLETED",
             "tool_events": [{"status": "STARTED"}]}
    with patch.object(gate, "snapshot", return_value={"records": [*rows, other]}), \
            patch.object(gate, "verify_response_evidence", side_effect=evidence):
        assert pipeline._settled_local_pov_json_failure(
            client, agent, result, owner)
        assert other["tool_events"][0]["status"] == "STARTED"


def test_valid_last_proposal_is_not_a_local_json_failure(tmp_path):
    pipeline, gate, client, agent, result, owner, rows, evidence = _local_case(
        tmp_path)
    path = Path(evidence("request-1")["response_path"])
    path.write_text(json.dumps({"tool_calls": [
        {"name": "create_pov", "arguments": '{"x":1}'}]}))
    with patch.object(gate, "snapshot", return_value={"records": rows}), patch.object(
            gate, "verify_response_evidence", side_effect=evidence):
        assert not pipeline._settled_local_pov_json_failure(
            client, agent, result, owner)


def _claim_record(source, processor_id):
    return {**source, "processor_id": processor_id,
            "claim_token": f"token-{processor_id}"}


def _claim_kwargs(processor_id):
    return {"processor_id": processor_id,
            "claim_token": f"token-{processor_id}"}


def test_local_failure_reason_is_saved_without_no_crash_completion():
    db = mongomock.MongoClient().db
    repo = SuspiciousPointRepository(db)
    sp_id = str(ObjectId())
    source = {"harness_name": "fuzz-mdhtml", "sanitizer": "address"}
    db.suspicious_points.insert_one({
        "_id": ObjectId(sp_id), "status": "generating_pov",
        "pov_success_by": None,
        "sources": [source], "pov_attempted_by": [source],
        "pov_active_claims": [_claim_record(source, "pov-a")],
    })
    assert repo.complete_pov(
        sp_id, success=False, harness_name="fuzz-mdhtml",
        sanitizer="address", local_failure_reason="invalid_model_tool_json",
        local_failure_attempts=11, **_claim_kwargs("pov-a"))
    saved = db.suspicious_points.find_one({"_id": ObjectId(sp_id)})
    assert saved["status"] == "failed"
    assert saved["pov_local_failures"] == [{
        "harness_name": "fuzz-mdhtml", "sanitizer": "address",
        "reason": "invalid_model_tool_json", "pov_attempts": 11}]
    assert "pov_id" not in saved


def test_parallel_local_failure_does_not_block_other_contributor():
    db = mongomock.MongoClient().db
    repo = SuspiciousPointRepository(db)
    sp_id = str(ObjectId())
    sources = [{"harness_name": name, "sanitizer": "address"}
               for name in ("fuzz-a", "fuzz-b")]
    db.suspicious_points.insert_one({
        "_id": ObjectId(sp_id), "status": "generating_pov",
        "pov_success_by": None, "sources": sources,
        "pov_attempted_by": sources,
        "pov_active_claims": [
            _claim_record(source, f"pov-{index}")
            for index, source in enumerate(sources)],
    })

    assert repo.complete_pov(
        sp_id, success=False, harness_name="fuzz-a", sanitizer="address",
        local_failure_reason="invalid_model_tool_json",
        local_failure_attempts=11, **_claim_kwargs("pov-0"))
    interim = repo.find_by_id(sp_id)
    assert interim.status == "generating_pov"
    assert interim.pov_failed_by == [sources[0]]
    assert repo.complete_pov(
        sp_id, pov_id=str(ObjectId()), success=True,
        harness_name="fuzz-b", sanitizer="address", **_claim_kwargs("pov-1"))
    final = repo.find_by_id(sp_id)
    assert final.status == "pov_generated"
    assert final.pov_success_by == sources[1]
    assert final.pov_local_failures[0]["pov_attempts"] == 11


def test_all_parallel_contributors_must_finish_before_failure():
    db = mongomock.MongoClient().db
    repo = SuspiciousPointRepository(db)
    sp_id = str(ObjectId())
    sources = [{"harness_name": name, "sanitizer": "address"}
               for name in ("fuzz-a", "fuzz-b")]
    db.suspicious_points.insert_one({
        "_id": ObjectId(sp_id), "status": "generating_pov",
        "pov_success_by": None, "sources": sources,
        "pov_attempted_by": sources,
        "pov_active_claims": [
            _claim_record(source, f"pov-{index}")
            for index, source in enumerate(sources)],
    })
    for index, source in enumerate(sources):
        assert repo.complete_pov(
            sp_id, success=False, **source,
            local_failure_reason="invalid_model_tool_json",
            local_failure_attempts=11, **_claim_kwargs(f"pov-{index}"))
        saved = repo.find_by_id(sp_id)
        assert saved.status == ("generating_pov" if index == 0 else "failed")
    assert len(saved.pov_failed_by) == 2
    assert len(saved.pov_local_failures) == 2


def test_new_source_during_last_failure_keeps_candidate_open():
    db = mongomock.MongoClient().db
    repo = SuspiciousPointRepository(db)
    sp_id = str(ObjectId())
    first = {"harness_name": "fuzz-a", "sanitizer": "address"}
    second = {"harness_name": "fuzz-b", "sanitizer": "address"}
    db.suspicious_points.insert_one({
        "_id": ObjectId(sp_id), "status": "generating_pov",
        "pov_success_by": None, "sources": [first],
        "pov_attempted_by": [first],
        "pov_active_claims": [_claim_record(first, "pov-a")],
    })
    original_find = repo.find_by_id
    source_added = False

    def add_source_after_snapshot(candidate_id):
        nonlocal source_added
        snapshot = original_find(candidate_id)
        if not source_added:
            db.suspicious_points.update_one(
                {"_id": ObjectId(sp_id)}, {"$addToSet": {"sources": second}})
            source_added = True
        return snapshot

    with patch.object(repo, "find_by_id", side_effect=add_source_after_snapshot):
        assert repo.complete_pov(
            sp_id, success=False, harness_name="fuzz-a",
            sanitizer="address", local_failure_reason="invalid_model_tool_json",
            local_failure_attempts=11, **_claim_kwargs("pov-a"))
    saved = original_find(sp_id)
    assert saved.status == "generating_pov"
    assert saved.sources == [first, second]
    assert saved.pov_failed_by == [first]


def test_local_failure_evidence_survives_model_roundtrip_with_insert_only_save():
    db = mongomock.MongoClient().db
    repo = SuspiciousPointRepository(db)
    sp_id = str(ObjectId())
    failure = {"harness_name": "fuzz-a", "sanitizer": "address",
               "reason": "invalid_model_tool_json", "pov_attempts": 11}
    db.suspicious_points.insert_one({
        "_id": ObjectId(sp_id), "suspicious_point_id": sp_id,
        "status": "failed", "pov_failed_by": [{
            "harness_name": "fuzz-a", "sanitizer": "address"}],
        "pov_local_failures": [failure],
    })
    point = repo.find_by_id(sp_id)
    assert point.pov_local_failures == [failure]
    assert point.to_dict()["pov_local_failures"] == [failure]
    assert not repo.save(point)
    saved = db.suspicious_points.find_one({"_id": ObjectId(sp_id)})
    assert saved["pov_local_failures"] == [failure]


async def _run_one_local_failure(pipeline, sp, result):
    class FakePOVAgent:
        stop_reason = "invalid_model_tool_json"
        max_pov_attempts = 20

        def __init__(self, **kwargs):
            pass

        async def generate_pov_async(self, _):
            return result

    @asynccontextmanager
    async def fake_client(_factory, _role, _owner):
        yield SimpleNamespace(agent_id=str(ObjectId()))

    with patch("fuzzingbrain.worker.pipeline.POVAgent", FakePOVAgent), \
            patch("fuzzingbrain.worker.pipeline.injected_agent_client",
                  fake_client), \
            patch.object(pipeline, "_settled_local_pov_json_failure",
                         return_value=True), \
            patch.object(pipeline, "_qualified_no_crash_input_count",
                         return_value=0):
        await pipeline._run_pov_agent("pov_2")


def test_one_local_failure_keeps_other_agents_running():
    import asyncio
    sp_id = str(ObjectId())
    sp = SimpleNamespace(suspicious_point_id=sp_id, function_name="md_add_mark",
                         pov_claim_token="claim-token",
                         to_dict=lambda: {"suspicious_point_id": sp_id})
    result = SimpleNamespace(success=False, crashed=False,
                             pending_runtime=False, pending_validation=False,
                             pov_attempts=11, error_msg=None,
                             completed_at=object(), pov_id="")
    candidates = [sp]
    def claim(*args, **kwargs):
        return candidates.pop() if candidates else None

    repo = SimpleNamespace(
        claim_for_pov=Mock(side_effect=claim),
        count_by_status=Mock(return_value=0),
        complete_pov=Mock(return_value=True),
        collection=SimpleNamespace(find_one=Mock(return_value={"_id": ObjectId(sp_id)})),
        release_claim=Mock(),
    )
    pipeline = AgentPipeline.__new__(AgentPipeline)
    pipeline.repos = SimpleNamespace(suspicious_points=repo)
    pipeline.task_id = str(ObjectId())
    pipeline.worker_id = ""
    pipeline.fuzzer = "fuzz-mdhtml"
    pipeline.sanitizer = "address"
    pipeline.mcp_socket_path = None
    pipeline.llm_client_factory = object()
    pipeline._fuzzer_manager = None
    pipeline.qualified_runtime_binding = None
    pipeline.output_dir = None
    pipeline.log_dir = None
    pipeline.workspace_path = None
    pipeline.fuzzer_code = ""
    pipeline.config = SimpleNamespace(poll_interval=0, max_iterations=100,
                                      max_pov_attempts=20, fuzzer_path=None,
                                      docker_image=None, pov_min_score=0.5)
    pipeline.stats = PipelineStats()
    pipeline._shutdown = False
    pipeline._sp_finding_done = True
    pipeline._incomplete_error = None
    pipeline._incomplete_reason = None
    asyncio.run(_run_one_local_failure(pipeline, sp, result))
    assert pipeline._shutdown is False
    assert pipeline._incomplete_error is None
    assert pipeline.stats.pov_failed == 1
    assert repo.complete_pov.call_args.kwargs["local_failure_reason"] == \
        "invalid_model_tool_json"
    repo.release_claim.assert_not_called()


def test_invalid_json_summary_is_not_a_clean_no_crash_result():
    agent = POVAgent.__new__(POVAgent)
    agent.start_time = None
    agent.end_time = None
    agent.suspicious_point = {"function_name": "md_add_mark"}
    agent.stop_reason = "invalid_model_tool_json"
    agent.pov_success = False
    agent.fuzzer = "fuzz-mdhtml"
    agent.sanitizer = "address"
    agent.total_iterations = 17
    agent.pov_attempts = 11
    agent.max_pov_attempts = 20
    summary = agent._get_summary_table()
    assert "INCOMPLETE - Agent did not finish conclusively" in summary
    assert "COMPLETED - No crash found" not in summary
