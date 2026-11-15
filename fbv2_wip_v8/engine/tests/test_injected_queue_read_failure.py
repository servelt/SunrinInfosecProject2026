"""Injected SP pipeline must distinguish an empty queue from a broken DB."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId

from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)


@pytest.mark.parametrize(
    "operation,collection_method",
    [
        ("claim_for_verify", "find_one_and_update"),
        ("claim_for_pov", "find_one_and_update"),
        ("count_by_status", "count_documents"),
    ],
)
def test_repository_strict_queue_reads_propagate_storage_errors(
    operation, collection_method,
):
    db = MagicMock()
    repo = SuspiciousPointRepository(db)
    getattr(repo.collection, collection_method).side_effect = OSError("mongo unavailable")
    kwargs = {"status": "pending_verify"} if operation == "count_by_status" else {
        "processor_id": "verify_1"}
    if operation == "claim_for_pov":
        kwargs.update(harness_name="fixture", sanitizer="address")
    method = getattr(repo, operation)
    task_id = str(ObjectId())

    # Preserve the original non-injected repository behavior.
    assert method(task_id, **kwargs) in (None, 0)
    with pytest.raises(OSError, match="mongo unavailable"):
        method(task_id, raise_on_error=True, **kwargs)


@pytest.mark.parametrize("role,failing_read", [
    ("verify", "claim_for_verify"),
    ("verify", "count_by_status"),
    ("pov", "claim_for_pov"),
    ("pov", "count_by_status"),
])
def test_injected_pipeline_does_not_complete_after_queue_read_error(
    role, failing_read,
):
    repos = MagicMock()
    repos.suspicious_points.claim_for_verify.return_value = None
    repos.suspicious_points.claim_for_pov.return_value = None
    repos.suspicious_points.count_by_status.return_value = 0
    getattr(repos.suspicious_points, failing_read).side_effect = OSError(
        "mongo unavailable")
    config = PipelineConfig(
        num_verify_agents=int(role == "verify"),
        num_pov_agents=int(role == "pov"), poll_interval=0,
    )
    pipeline = AgentPipeline(
        str(ObjectId()), repos, fuzzer="fixture", sanitizer="address",
        config=config, llm_client_factory=lambda role, owner: None,
    )
    pipeline._sp_finding_done = True

    with pytest.raises(IncompleteInjectedAgent, match="mongo unavailable"):
        asyncio.run(pipeline.run())


def test_injected_pipeline_empty_queues_can_finish_normally():
    repos = MagicMock()
    repos.suspicious_points.claim_for_verify.return_value = None
    repos.suspicious_points.claim_for_pov.return_value = None
    repos.suspicious_points.count_by_status.return_value = 0
    pipeline = AgentPipeline(
        str(ObjectId()), repos, fuzzer="fixture", sanitizer="address",
        config=PipelineConfig(
            num_verify_agents=1, num_pov_agents=1, poll_interval=0),
        llm_client_factory=lambda role, owner: None,
    )
    pipeline._sp_finding_done = True

    stats = asyncio.run(pipeline.run())
    assert stats.end_time is not None
    assert pipeline._incomplete_error is None
    assert repos.suspicious_points.claim_for_verify.call_count >= 5
    assert repos.suspicious_points.claim_for_pov.call_count >= 5


@pytest.mark.parametrize("role", ["verify", "pov"])
def test_injected_pipeline_does_not_report_success_after_result_write_failure(
    role,
):
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id=str(ObjectId()), function_name="fixture",
        verification_claim_token="claim-token",
            pov_claim_token="pov-claim-token",
        to_dict=lambda: {"suspicious_point_id": "fixture"},
    )
    repos.suspicious_points.claim_for_verify.return_value = point
    repos.suspicious_points.claim_for_pov.return_value = point
    repos.suspicious_points.find_by_id.return_value = SimpleNamespace(
        is_checked=True, is_important=False, is_real=False,
        score=0.1, verification_notes="checked",
        verification_disposition=None,
        status="generating_pov", pov_success_by=None,
    )
    repos.suspicious_points.complete_verify.return_value = False
    repos.suspicious_points.complete_pov.return_value = False
    config = PipelineConfig(
        num_verify_agents=int(role == "verify"),
        num_pov_agents=int(role == "pov"), poll_interval=0,
    )

    class Client:
        last_agent_response_was_final = True

        async def close(self):
            pass

    pipeline = AgentPipeline(
        str(ObjectId()), repos, fuzzer="fixture", sanitizer="address",
        config=config, llm_client_factory=lambda role, owner: Client(),
    )
    pipeline._sp_finding_done = True

    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier, patch(
        "fuzzingbrain.worker.pipeline.POVAgent") as pov:
        verifier.return_value.run_async = AsyncMock(return_value="done")
        verifier.return_value.stop_reason = None
        pov.return_value.generate_pov_async = AsyncMock(
            return_value=SimpleNamespace(success=False, pov_id=None))
        pov.return_value.stop_reason = None
        with pytest.raises(IncompleteInjectedAgent) as error:
            asyncio.run(pipeline.run())

    assert error.value.reason == "candidate_state_write_failed"
    assert pipeline.stats.sp_verified == 0
    assert pipeline.stats.pov_generated == 0
    call = repos.suspicious_points.preserve_incomplete_candidate.call_args
    assert call.args[1]["status"] == "incomplete_uncertain"
    assert call.kwargs["stage"] == ("verifier" if role == "verify" else "pov")


def test_injected_verifier_missing_candidate_is_incomplete():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id=str(ObjectId()), function_name="fixture",
        verification_claim_token="claim-token",
        to_dict=lambda: {"suspicious_point_id": "fixture"},
    )
    repos.suspicious_points.claim_for_verify.return_value = point
    repos.suspicious_points.find_by_id.return_value = None

    class Client:
        last_agent_response_was_final = True

        async def close(self):
            pass

    pipeline = AgentPipeline(
        str(ObjectId()), repos, fuzzer="fixture", sanitizer="address",
        config=PipelineConfig(
            num_verify_agents=1, num_pov_agents=0, poll_interval=0),
        llm_client_factory=lambda role, owner: Client(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(return_value="done")
        verifier.return_value.stop_reason = None
        with pytest.raises(IncompleteInjectedAgent) as error:
            asyncio.run(pipeline.run())

    assert error.value.reason == "candidate_state_read_failed"
    repos.suspicious_points.release_claim.assert_not_called()


def test_pipeline_settles_sibling_after_queue_failure():
    pipeline = AgentPipeline(
        str(ObjectId()), MagicMock(),
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=1),
        llm_client_factory=lambda role, owner: None,
    )
    sibling_started = asyncio.Event()
    sibling_settled = asyncio.Event()

    async def waiting_pov(_agent_id):
        sibling_started.set()
        while not pipeline._shutdown:
            await asyncio.sleep(0)
        sibling_settled.set()

    async def failing_verify(_agent_id):
        await sibling_started.wait()
        raise OSError("mongo unavailable")

    pipeline._run_verify_agent = failing_verify
    pipeline._run_pov_agent = waiting_pov

    with pytest.raises(IncompleteInjectedAgent, match="mongo unavailable"):
        asyncio.run(pipeline.run())
    assert pipeline._shutdown
    assert sibling_settled.is_set()


def test_pipeline_settles_sibling_after_incomplete_verifier_turn():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id=str(ObjectId()), function_name="fixture",
        verification_claim_token="claim-token",
        to_dict=lambda: {"suspicious_point_id": "fixture"},
    )
    repos.suspicious_points.claim_for_verify.return_value = point
    pipeline = AgentPipeline(
        str(ObjectId()), repos, fuzzer="fixture", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=1),
        llm_client_factory=lambda role, owner: SimpleNamespace(
            close=AsyncMock(), last_agent_response_was_final=True),
    )
    sibling_started = asyncio.Event()
    sibling_settled = asyncio.Event()

    async def waiting_pov(_agent_id):
        sibling_started.set()
        while not pipeline._shutdown:
            await asyncio.sleep(0)
        sibling_settled.set()

    async def incomplete_verifier(*args, **kwargs):
        await sibling_started.wait()

    pipeline._run_pov_agent = waiting_pov
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(side_effect=incomplete_verifier)
        verifier.return_value.stop_reason = "llm_error"
        with pytest.raises(IncompleteInjectedAgent) as error:
            asyncio.run(pipeline.run())

    assert error.value.reason == "llm_error"
    assert sibling_settled.is_set()
    repos.suspicious_points.preserve_incomplete_candidate.assert_called_once()
