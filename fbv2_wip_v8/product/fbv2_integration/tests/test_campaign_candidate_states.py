"""Interrupted injected roles preserve SP evidence without automatic resend."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bson import ObjectId
import mongomock
import pytest

from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint, SPStatus
from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)


class FinalClient:
    last_agent_response_was_final = True

    async def close(self):
        pass


def setup_candidate(status: SPStatus):
    db = mongomock.MongoClient()["campaign_candidate_states"]
    repo = SuspiciousPointRepository(db)
    task_id = str(ObjectId())
    point = SuspiciousPoint(
        task_id=task_id, function_name="parse_input", description="original cause",
        vuln_type="buffer-overflow", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
    )
    point.status = status.value
    if status == SPStatus.PENDING_POV:
        point.is_checked = True
        point.is_real = True
        point.is_important = True
    assert repo.save(point)
    repos = SimpleNamespace(suspicious_points=repo)
    return task_id, point, repo, repos


@pytest.mark.parametrize("reason, expected_status", [
    ("budget_before_transport", SPStatus.PENDING_BUDGET),
    ("uncertain_remote", SPStatus.INCOMPLETE_UNCERTAIN),
])
def test_verifier_interruption_preserves_candidate_and_stops_campaign(
    reason, expected_status
):
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: FinalClient(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(return_value="unfinished")
        verifier.return_value.stop_reason = reason
        with pytest.raises(IncompleteInjectedAgent) as caught:
            asyncio.run(pipeline.run())

    assert caught.value.reason == reason
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.description == "original cause"
    assert stored.vuln_type == "buffer-overflow"
    assert stored.status == expected_status.value
    assert stored.processor_id is None
    assert not stored.is_checked
    assert not stored.is_real
    assert not stored.is_important
    assert stored.pipeline_incomplete_reason == reason
    assert stored.pipeline_incomplete_stage == "verifier"
    assert repo.claim_for_verify(task_id, "different-worker", "fuzz", "address") is None
    assert not repo.is_pipeline_complete(task_id)
    assert not repo.is_pipeline_complete(task_id, "fuzz", "address")


@pytest.mark.parametrize("reason, expected_status", [
    ("budget_before_transport", SPStatus.PENDING_BUDGET),
    ("uncertain_remote", SPStatus.INCOMPLETE_UNCERTAIN),
])
def test_pov_interruption_preserves_verified_candidate_without_pov_success(
    reason, expected_status
):
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_POV)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=0, num_pov_agents=1,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: FinalClient(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as pov:
        # Even an apparent successful result cannot be promoted after an
        # interrupted model turn; candidate and original notes survive.
        pov.return_value.generate_pov_async = AsyncMock(return_value=SimpleNamespace(
            success=True, pov_id="untrusted"))
        pov.return_value.stop_reason = reason
        with pytest.raises(IncompleteInjectedAgent) as caught:
            asyncio.run(pipeline.run())

    assert caught.value.reason == reason
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.description == "original cause"
    assert stored.vuln_type == "buffer-overflow"
    assert stored.status == expected_status.value
    assert stored.processor_id is None
    assert stored.is_checked  # Prior Verifier evidence remains distinct.
    assert stored.pov_id is None
    assert stored.pov_success_by is None
    assert stored.pipeline_incomplete_reason == reason
    assert stored.pipeline_incomplete_stage == "pov"
    assert repo.claim_for_pov(task_id, "different-worker", 0.5,
                              "fuzz", "address") is None
    assert not repo.is_pipeline_complete(task_id)
    assert not repo.is_pipeline_complete(task_id, "fuzz", "address")


def test_cancelled_verifier_turn_is_not_reclaimed_for_automatic_resend():
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: FinalClient(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(
            side_effect=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(pipeline.run())

    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.INCOMPLETE_UNCERTAIN.value
    assert stored.processor_id is None
    assert stored.pipeline_incomplete_reason == "uncertain_remote"
    assert stored.pipeline_incomplete_stage == "verifier"
    assert not stored.is_checked
    assert repo.claim_for_verify(task_id, "different-worker", "fuzz", "address") is None
    assert not repo.is_pipeline_complete(task_id)


def test_cancelled_pov_turn_is_not_reclaimed_for_automatic_resend():
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_POV)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=0, num_pov_agents=1,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: FinalClient(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as pov:
        pov.return_value.generate_pov_async = AsyncMock(
            side_effect=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(pipeline.run())

    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.INCOMPLETE_UNCERTAIN.value
    assert stored.processor_id is None
    assert stored.pipeline_incomplete_reason == "uncertain_remote"
    assert stored.pipeline_incomplete_stage == "pov"
    assert stored.is_checked
    assert stored.pov_id is None
    assert repo.claim_for_pov(task_id, "different-worker", 0.5,
                              "fuzz", "address") is None
    assert not repo.is_pipeline_complete(task_id)
