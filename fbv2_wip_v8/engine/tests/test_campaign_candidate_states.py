"""Interrupted injected roles preserve SP evidence without automatic resend."""

import asyncio
import base64
import hashlib
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bson import ObjectId
import mongomock
from pymongo import MongoClient
import pytest
from uuid import uuid4

from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint, SPStatus
from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)
from devtools.campaign_model_gate import (
    CampaignLedgeredProvider, CampaignModelGate, CampaignStopping,
)


class FinalClient:
    last_agent_response_was_final = True

    async def close(self):
        pass


class LocalLimitClient(FinalClient):
    last_agent_response_was_final = False
    agent_id = "a" * 24


def _campaign_client(gate, owner):
    provider = CampaignLedgeredProvider(
        SimpleNamespace(), gate, role="verifier", owner_id=owner)
    return SimpleNamespace(provider=provider)


def test_settled_cancel_at_wall_cap_is_budget_not_remote_uncertainty(tmp_path):
    owner = "verifier-owner"
    gate = CampaignModelGate(
        tmp_path / "model-ledger.json", "settled-wall-cancel",
        physical_max=10, wall_seconds=30, create=True)
    gate.reserve(request_id="request-1", role="verifier", owner_id=owner,
                 request_sha256="a" * 64)
    gate.finish("request-1", completed=True)
    deadline = gate.snapshot()["started_monotonic"] + gate.wall_seconds

    with patch("fuzzingbrain.worker.pipeline.time.monotonic",
               return_value=deadline):
        assert AgentPipeline._settled_campaign_cancellation_reason(
            _campaign_client(gate, owner), owner) == "budget_before_transport"


def test_cancel_with_started_remote_turn_remains_uncertain(tmp_path):
    owner = "verifier-owner"
    gate = CampaignModelGate(
        tmp_path / "model-ledger.json", "active-wall-cancel",
        physical_max=1, wall_seconds=30, create=True)
    gate.reserve(request_id="request-1", role="verifier", owner_id=owner,
                 request_sha256="a" * 64)

    with patch("fuzzingbrain.worker.pipeline.time.monotonic",
               return_value=gate.snapshot()["started_monotonic"] + 31):
        assert AgentPipeline._settled_campaign_cancellation_reason(
            _campaign_client(gate, owner), owner) is None


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
    repo.collection.insert_one(point.to_dict())
    repos = SimpleNamespace(suspicious_points=repo)
    return task_id, point, repo, repos


def _active_pov_claim(repo, sp_id, harness_name, sanitizer="address"):
    """Return the opaque lease capability held by a test PoV worker."""
    row = repo.collection.find_one({"_id": ObjectId(sp_id)})
    matches = [claim for claim in row.get("pov_active_claims", [])
               if claim.get("harness_name") == harness_name and
               claim.get("sanitizer") == sanitizer]
    assert len(matches) == 1
    return {
        "processor_id": matches[0]["processor_id"],
        "claim_token": matches[0]["claim_token"],
    }


def test_parallel_verifiers_cannot_claim_same_candidate_twice():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)

    async def compete():
        return await asyncio.gather(*(
            asyncio.to_thread(repo.claim_for_verify, task_id, owner,
                              "fuzz", "address", True)
            for owner in ("verifier-A", "verifier-B")))

    claims = asyncio.run(compete())
    winners = [claim for claim in claims if claim is not None]
    assert len(winners) == 1
    assert winners[0].suspicious_point_id == point.suspicious_point_id
    assert repo.find_by_id(point.suspicious_point_id).processor_id in {
        "verifier-A", "verifier-B"}


def test_equal_priority_verify_claim_has_stable_id_tiebreak():
    db = mongomock.MongoClient()["deterministic_candidate_claim"]
    repo = SuspiciousPointRepository(db)
    task_id = str(ObjectId())
    created = datetime(2026, 1, 1)
    low_id = "000000000000000000000001"
    high_id = "000000000000000000000002"
    for sp_id in (high_id, low_id):
        point = SuspiciousPoint(
            suspicious_point_id=sp_id,
            task_id=task_id,
            function_name="same",
            description="same",
            vuln_type="same",
            score=0.5,
            created_at=created,
            sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        )
        repo.collection.insert_one(point.to_dict())
    claimed = repo.claim_for_verify(task_id, "worker", "fuzz", "address")
    assert claimed.suspicious_point_id == low_id


def test_real_mongo_queue_streams_discovery_verify_and_pov_concurrently():
    """Exercise the production Repository CAS while Discovery is still live."""
    db = mongomock.MongoClient()["persistent_concurrent_pipeline"]
    repo = SuspiciousPointRepository(db)
    task_id = str(ObjectId())
    repos = SimpleNamespace(suspicious_points=repo)
    pipeline = AgentPipeline(
        task_id=task_id, repos=repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(
            num_verify_agents=2, num_pov_agents=2,
            poll_interval=0.001, max_idle_cycles=10,
            pov_admission_mode="explicit_disposition"),
    )
    first_claimed = asyncio.Event()
    discovery_finished = asyncio.Event()
    verify_claims = []
    pov_claims = []

    async def verify_worker(agent_id):
        idle = 0
        while True:
            point = repo.claim_for_verify(
                task_id, agent_id, "fuzz", "address", raise_on_error=True)
            if point is None:
                idle += 1
                if pipeline._sp_finding_done and idle >= 5:
                    return
                await asyncio.sleep(0.001)
                continue
            idle = 0
            verify_claims.append(point.suspicious_point_id)
            first_claimed.set()
            token = point.verification_claim_token
            assert repo.update_verifier_fields(
                point.suspicious_point_id, {
                    "is_checked": True,
                    "is_real": False,
                    "is_important": False,
                    "score": 0.1,
                    "verification_disposition": "TESTABLE_UNCERTAIN",
                    "pov_guidance": "exercise the retained hypothesis",
                }, processor_id=agent_id, claim_token=token)
            assert repo.complete_verify(
                point.suspicious_point_id, is_real=False, score=0.1,
                is_important=False, proceed_to_pov=True,
                processor_id=agent_id, claim_token=token,
                verification_disposition="TESTABLE_UNCERTAIN")

    async def pov_worker(agent_id):
        idle = 0
        while True:
            point = repo.claim_for_pov(
                task_id, agent_id, min_score=0.0,
                harness_name="fuzz", sanitizer="address",
                raise_on_error=True)
            if point is None:
                idle += 1
                unfinished = repo.collection.count_documents({
                    "task_id": ObjectId(task_id),
                    "status": {"$in": [
                        SPStatus.PENDING_VERIFY.value,
                        SPStatus.VERIFYING.value,
                        SPStatus.PENDING_POV.value,
                        SPStatus.GENERATING_POV.value,
                    ]},
                })
                if pipeline._sp_finding_done and unfinished == 0 and idle >= 5:
                    return
                await asyncio.sleep(0.001)
                continue
            idle = 0
            pov_claims.append(point.suspicious_point_id)
            assert repo.complete_pov(
                point.suspicious_point_id, pov_id=str(ObjectId()), success=True,
                    harness_name="fuzz", sanitizer="address", require_claim=True,
                    processor_id=agent_id, claim_token=point.pov_claim_token)

    pipeline._run_verify_agent = verify_worker
    pipeline._run_pov_agent = pov_worker

    async def discover():
        first = SuspiciousPoint(
            task_id=task_id, function_name="first",
            description="first retained hypothesis", vuln_type="uaf",
            score=0.1,
            sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        )
        second = SuspiciousPoint(
            task_id=task_id, function_name="second",
            description="second retained hypothesis", vuln_type="oob",
            score=0.1,
            sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        )
        assert repo.save(first)
        await asyncio.wait_for(first_claimed.wait(), 1)
        # Discovery continues while a Verifier owns the first Mongo claim.
        assert not discovery_finished.is_set()
        assert repo.save(second)
        discovery_finished.set()
        pipeline._sp_finding_done = True
        return first, second

    async def run_all():
        pipeline_task = asyncio.create_task(pipeline.run())
        first, second = await discover()
        await asyncio.wait_for(pipeline_task, 2)
        return first, second

    first, second = asyncio.run(run_all())
    assert sorted(verify_claims) == sorted([
        first.suspicious_point_id, second.suspicious_point_id])
    assert sorted(pov_claims) == sorted(verify_claims)
    assert len(verify_claims) == len(set(verify_claims)) == 2
    assert len(pov_claims) == len(set(pov_claims)) == 2
    for point in (first, second):
        settled = repo.find_by_id(point.suspicious_point_id)
        assert settled.status == SPStatus.POV_GENERATED.value


def test_high_recall_testable_candidate_reaches_pov_despite_low_priority():
    point = SimpleNamespace(
        verification_disposition="TESTABLE_UNCERTAIN",
        score=0.1,
        is_important=False,
    )
    config = PipelineConfig(pov_min_score=0.5,
                            pov_admission_mode="explicit_disposition")
    assert AgentPipeline._should_admit_pov(config, point)


def test_high_recall_refuted_candidate_does_not_reach_pov_despite_score():
    point = SimpleNamespace(
        verification_disposition="REFUTED",
        score=0.99,
        is_important=True,
    )
    config = PipelineConfig(pov_min_score=0.5,
                            pov_admission_mode="explicit_disposition")
    with pytest.raises(IncompleteInjectedAgent):
        AgentPipeline._should_admit_pov(config, point)


def test_legacy_pov_admission_preserves_score_and_importance_gate():
    config = PipelineConfig(pov_min_score=0.5,
                            pov_admission_mode="legacy_score")
    assert not AgentPipeline._should_admit_pov(
        config, SimpleNamespace(score=0.9, is_important=False))
    assert AgentPipeline._should_admit_pov(
        config, SimpleNamespace(score=0.5, is_important=True))


def test_verifier_prompts_match_disabled_terminal_refuted_contract():
    prompt_dir = Path(__file__).parents[1] / "fuzzingbrain/agents/prompts"
    for name in (
        "verify_suspicious_points_prompt.md",
        "verify_suspicious_points_delta_prompt.md",
    ):
        text = (prompt_dir / name).read_text(encoding="utf-8")
        assert "Terminal REFUTED" in text
        assert "disabled" in text
        assert "LITERAL_FALSE_GUARD" not in text


def test_late_verifier_completion_cannot_reopen_sealed_candidate():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    claim = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert claim
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.INCOMPLETE_UNCERTAIN.value}, stage="verifier",
        processor_id="verifier-A",
        claim_token=claim.verification_claim_token)

    assert not repo.complete_verify(
        point.suspicious_point_id, is_real=True, score=0.95,
        is_important=True, proceed_to_pov=True,
        processor_id="verifier-A",
        claim_token=claim.verification_claim_token)
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.INCOMPLETE_UNCERTAIN.value
    assert not stored.is_checked


def test_late_verifier_tool_result_cannot_mark_sealed_candidate_checked():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    claim = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert claim
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.INCOMPLETE_UNCERTAIN.value}, stage="verifier",
        processor_id="verifier-A",
        claim_token=claim.verification_claim_token)

    assert not repo.update_verifier_fields(
        point.suspicious_point_id, {"is_checked": True, "score": 0.95})
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.INCOMPLETE_UNCERTAIN.value
    assert not stored.is_checked

    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    claim = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert claim
    assert repo.update_verifier_fields(
        point.suspicious_point_id, {"is_checked": True, "score": 0.95},
        claim_token=claim.verification_claim_token)


def test_verifier_disposition_write_requires_claim_owner_and_is_persisted():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    owner = str(ObjectId())
    intruder = str(ObjectId())
    claim = repo.claim_for_verify(task_id, owner, "fuzz", "address")
    assert claim
    updates = {
        "is_checked": True,
        "verification_disposition": "TESTABLE_UNCERTAIN",
        "verification_notes": "not disproven",
    }
    assert not repo.update_verifier_fields(
        point.suspicious_point_id, updates, processor_id=intruder,
        claim_token=claim.verification_claim_token)
    assert repo.update_verifier_fields(
        point.suspicious_point_id, updates, processor_id=owner,
        claim_token=claim.verification_claim_token)
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.verification_disposition == "TESTABLE_UNCERTAIN"
    assert not repo.complete_verify(
        point.suspicious_point_id,
        is_real=False,
        score=0.1,
        is_important=False,
        proceed_to_pov=False,
        processor_id=owner,
        claim_token=claim.verification_claim_token,
    )
    assert repo.complete_verify(
        point.suspicious_point_id,
        is_real=False,
        score=0.1,
        is_important=False,
        proceed_to_pov=True,
        processor_id=owner,
        claim_token=claim.verification_claim_token,
        verification_disposition="TESTABLE_UNCERTAIN",
    )
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.PENDING_POV.value


def test_repository_rejects_new_terminal_refuted_record_and_completion():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    owner = str(ObjectId())
    claim = repo.claim_for_verify(task_id, owner, "fuzz", "address")
    assert claim
    token = claim.verification_claim_token

    assert not repo.update_verifier_fields(
        point.suspicious_point_id,
        {
            "is_checked": True,
            "verification_disposition": "REFUTED",
            "verification_refutation_evidence": {"forged": True},
        },
        processor_id=owner,
        claim_token=token,
    )
    assert not repo.update_verifier_fields(
        point.suspicious_point_id,
        {"verification_refutation_evidence": {"forged": True}},
        processor_id=owner,
        claim_token=token,
    )
    assert not repo.update_verifier_fields(
        point.suspicious_point_id,
        {"verification_disposition": "UNKNOWN_TERMINAL"},
        processor_id=owner,
        claim_token=token,
    )

    # Even a directly seeded legacy-shaped result cannot use the public
    # completion API to create a new terminal REFUTED transition.
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {
            "is_checked": True,
            "verification_disposition": "REFUTED",
            "verification_refutation_evidence": {"forged": True},
            "verification_result_claim_token": token,
        }},
    )
    assert not repo.complete_verify(
        point.suspicious_point_id,
        is_real=False,
        score=0.0,
        proceed_to_pov=False,
        processor_id=owner,
        claim_token=token,
        verification_disposition="REFUTED",
    )
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.VERIFYING.value


def test_historical_refuted_row_remains_readable():
    db = mongomock.MongoClient()["historical_refuted_row"]
    repo = SuspiciousPointRepository(db)
    task_id = str(ObjectId())
    point = SuspiciousPoint(
        task_id=task_id, function_name="historical",
        description="frozen legacy result", vuln_type="unknown",
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
    )
    row = point.to_dict()
    row["status"] = SPStatus.REFUTED.value
    row["verification_disposition"] = "REFUTED"
    repo.collection.insert_one(row)
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.task_id == task_id
    assert stored.status == SPStatus.REFUTED.value


def test_suspicious_point_save_is_insert_only_and_rejects_refuted_state():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    claim = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert claim

    stale = SuspiciousPoint.from_dict(point.to_dict())
    stale.status = SPStatus.REFUTED.value
    stale.verification_disposition = "REFUTED"
    assert not repo.save(stale)
    current = repo.find_by_id(point.suspicious_point_id)
    assert current.status == SPStatus.VERIFYING.value
    assert current.verification_claim_token == claim.verification_claim_token

    duplicate = SuspiciousPoint.from_dict(point.to_dict())
    duplicate.status = SPStatus.PENDING_VERIFY.value
    duplicate.verification_disposition = None
    assert not repo.save(duplicate)
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.VERIFYING.value

    fresh = SuspiciousPoint(
        task_id=task_id, function_name="forged", description="forged",
        vuln_type="unknown",
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
    )
    fresh.status = SPStatus.REFUTED.value
    assert not repo.save(fresh)
    assert repo.find_by_id(fresh.suspicious_point_id) is None


def test_claim_owner_is_required_for_injected_verifier_completion():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    claim = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert claim
    assert not repo.complete_verify(
        point.suspicious_point_id, is_real=True, score=0.95,
        processor_id="verifier-B", claim_token=claim.verification_claim_token)
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.VERIFYING.value
    assert repo.update_verifier_fields(
        point.suspicious_point_id, {"is_checked": True},
        processor_id="verifier-A", claim_token=claim.verification_claim_token)
    assert repo.complete_verify(
        point.suspicious_point_id, is_real=False, score=0.2,
        processor_id="verifier-A", claim_token=claim.verification_claim_token)


def test_verifier_claim_token_blocks_same_slot_aba_late_writes():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    first = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert first and first.verification_claim_token
    old_token = first.verification_claim_token
    assert "verification_claim_token" not in first.to_dict()
    assert repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_VERIFY.value,
        processor_id="verifier-A", claim_token=old_token)

    second = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert second and second.verification_claim_token != old_token
    new_token = second.verification_claim_token

    assert not repo.update_verifier_fields(
        point.suspicious_point_id, {"is_checked": True},
        processor_id="verifier-A", claim_token=old_token)
    assert not repo.complete_verify(
        point.suspicious_point_id, is_real=False, score=0.1,
        processor_id="verifier-A", claim_token=old_token)
    assert not repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.INCOMPLETE_UNCERTAIN.value}, stage="verifier",
        processor_id="verifier-A", claim_token=old_token)
    assert not repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_VERIFY.value,
        processor_id="verifier-A", claim_token=old_token)

    current = repo.find_by_id(point.suspicious_point_id)
    assert current.status == SPStatus.VERIFYING.value
    assert current.verification_claim_token == new_token
    assert repo.update_verifier_fields(
        point.suspicious_point_id,
        {"is_checked": True, "verification_notes": "current claim"},
        # AgentContext ID intentionally differs from the reusable worker slot;
        # possession of the trusted token is the lease capability.
        claim_token=new_token)


def test_reclaim_cannot_complete_with_predecessor_verdict():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    first = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert first and repo.update_verifier_fields(
        point.suspicious_point_id,
        {"is_checked": True, "is_real": False,
         "verification_disposition": "SUPPORTED"},
        processor_id="verifier-A",
        claim_token=first.verification_claim_token)
    assert repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_VERIFY.value,
        processor_id="verifier-A",
        claim_token=first.verification_claim_token)

    second = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert second and second.verification_claim_token != \
        first.verification_claim_token
    current = repo.find_by_id(point.suspicious_point_id)
    assert not current.is_checked
    assert current.verification_disposition is None
    assert not repo.complete_verify(
        point.suspicious_point_id, is_real=False, score=0.95,
        is_important=True, proceed_to_pov=True,
        verification_disposition="SUPPORTED", processor_id="verifier-A",
        claim_token=second.verification_claim_token)
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.VERIFYING.value

    assert repo.update_verifier_fields(
        point.suspicious_point_id,
        {"is_checked": True, "is_real": False,
         "verification_disposition": "SUPPORTED"},
        processor_id="verifier-A",
        claim_token=second.verification_claim_token)
    assert repo.complete_verify(
        point.suspicious_point_id, is_real=False, score=0.95,
        is_important=True, proceed_to_pov=True,
        verification_disposition="SUPPORTED", processor_id="verifier-A",
        claim_token=second.verification_claim_token)


def test_tokenless_release_cannot_mutate_active_verifier_claim():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_VERIFY)
    claim = repo.claim_for_verify(task_id, "verifier-A", "fuzz", "address")
    assert claim
    assert not repo.release_claim(point.suspicious_point_id)
    assert not repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_VERIFY.value,
        processor_id="verifier-A")
    current = repo.find_by_id(point.suspicious_point_id)
    assert current.status == SPStatus.VERIFYING.value
    assert current.processor_id == "verifier-A"
    assert current.verification_claim_token == claim.verification_claim_token


def test_late_claim_release_cannot_requeue_success_or_uncertainty():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    claim = repo.claim_for_pov(task_id, "pov-A", 0.5, "fuzz", "address")
    assert claim
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="valid-pov", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov-A", claim_token=claim.pov_claim_token)
    assert not repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_POV.value,
        harness_name="fuzz", sanitizer="address")
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.POV_GENERATED.value


def test_pov_success_requires_id_and_claim_in_injected_path():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    claim = repo.claim_for_pov(task_id, "pov-A", 0.5, "fuzz", "address")
    assert claim
    assert not repo.complete_pov(point.suspicious_point_id)
    assert not repo.complete_pov(
        point.suspicious_point_id, pov_id="pov-1", success=True,
        harness_name="other", sanitizer="address", require_claim=True)
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.GENERATING_POV.value
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="pov-1", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov-A", claim_token=claim.pov_claim_token)


def test_settled_local_verifier_limit_without_verdict_only_fails_candidate():
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: LocalLimitClient(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier, patch.object(
        pipeline, "_settled_local_verifier_limit", return_value=0
    ) as settle:
        verifier.return_value.run_async = AsyncMock(return_value="local limit")
        verifier.return_value.stop_reason = "max_iterations"
        asyncio.run(pipeline.run())

    settle.assert_called_once()
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.FAILED.value
    assert not stored.is_checked
    assert stored.verification_notes == (
        "Verifier reached local max_iterations without verdict")
    assert not pipeline._shutdown


@pytest.mark.parametrize("disposition", ["TESTABLE_UNCERTAIN", "SUPPORTED"])
def test_explicit_no_verdict_is_retained_while_next_candidate_is_admitted(disposition):
    task_id, first, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    second = SuspiciousPoint(
        task_id=task_id, function_name="second", description="still suspicious",
        vuln_type="buffer-overflow", score=0.1,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}])
    repo.collection.insert_one(second.to_dict())
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              poll_interval=0,
                              pov_admission_mode="explicit_disposition"),
        llm_client_factory=lambda role, owner: LocalLimitClient())
    pipeline._sp_finding_done = True
    visited = []

    async def verify(**kwargs):
        point = kwargs["suspicious_point"]
        current_id = str(point.get("suspicious_point_id") or point["_id"])
        visited.append(current_id)
        if current_id == second.suspicious_point_id:
            current = repo.find_by_id(current_id)
            assert repo.update_verifier_fields(
                current_id, {"is_checked": True, "is_real": False,
                             "is_important": False, "score": 0.1,
                             "verification_disposition": disposition,
                             "verified_by_agent_id": "a" * 24},
                processor_id="verify_1",
                claim_token=current.verification_claim_token)
        return "local limit"

    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier, patch.object(
            pipeline, "_settled_local_verifier_limit", side_effect=[0, 1]):
        verifier.return_value.run_async = AsyncMock(side_effect=verify)
        verifier.return_value.stop_reason = "max_iterations"
        with pytest.raises(IncompleteInjectedAgent) as error:
            asyncio.run(pipeline.run())
    assert error.value.reason == "verifier_no_verdict"
    assert visited == [first.suspicious_point_id, second.suspicious_point_id]
    unresolved = repo.find_by_id(first.suspicious_point_id)
    assert unresolved.status == SPStatus.INCOMPLETE_UNCERTAIN.value
    assert unresolved.description == "original cause" and not unresolved.is_checked
    assert unresolved.pipeline_incomplete_reason == "verifier_no_verdict"
    assert unresolved.verification_claim_token is None
    assert repo.find_by_id(second.suspicious_point_id).status == SPStatus.PENDING_POV.value
    assert pipeline.stats.verifier_unresolved == 1
    assert pipeline.stats.sp_verified_fp == pipeline.stats.sp_verified_real == 0
    assert pipeline.stats.sp_testable_uncertain == (disposition == "TESTABLE_UNCERTAIN")
    assert pipeline.stats.sp_supported == (disposition == "SUPPORTED")
    assert not pipeline._shutdown


def test_settled_local_verifier_limit_accepts_only_its_written_verdict():
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: LocalLimitClient(),
    )
    pipeline._sp_finding_done = True

    async def write_verdict(**kwargs):
        current = repo.find_by_id(point.suspicious_point_id)
        assert repo.update_verifier_fields(
            point.suspicious_point_id, {
                "is_checked": True, "is_real": False,
                "is_important": False, "score": 0.1,
                "verified_by_agent_id": "a" * 24,
                "verification_notes": "reviewed source"},
            processor_id="verify_1",
            claim_token=current.verification_claim_token)
        return "local limit"

    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier, patch.object(
        pipeline, "_settled_local_verifier_limit", return_value=1
    ) as settle:
        verifier.return_value.run_async = AsyncMock(side_effect=write_verdict)
        verifier.return_value.stop_reason = "max_iterations"
        asyncio.run(pipeline.run())

    settle.assert_called_once()
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.REVIEWED_NOT_ADMITTED.value
    assert stored.is_checked and not stored.is_real
    assert stored.verified_by_agent_id == "a" * 24
    assert not pipeline._shutdown


def test_parallel_pov_loser_does_not_overwrite_winning_candidate():
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    losing_claim = repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert losing_claim is not None
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="winning-pov", success=True,
        harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.INCOMPLETE_UNCERTAIN.value,
         "pipeline_incomplete_reason": "uncertain_remote"}, stage="pov",
        harness_name="other", sanitizer="address",
        processor_id="b", claim_token=losing_claim.pov_claim_token)

    pipeline = AgentPipeline(
        task_id, repos, fuzzer="other", sanitizer="address",
        config=PipelineConfig(num_verify_agents=0, num_pov_agents=1,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: FinalClient(),
    )
    pipeline._sp_finding_done = True
    with patch.object(repo, "claim_for_pov",
                      side_effect=[losing_claim] + [None] * 6), patch(
        "fuzzingbrain.worker.pipeline.POVAgent") as pov:
        pov.return_value.generate_pov_async = AsyncMock(
            return_value=SimpleNamespace(success=True, pov_id="losing-pov"))
        pov.return_value.stop_reason = None
        asyncio.run(pipeline.run())

    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.POV_GENERATED.value
    assert stored.pov_id == "winning-pov"
    assert pipeline.stats.pov_generated == 0


def test_stopped_pov_contributor_does_not_block_parallel_success():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))

    during = repo.find_by_id(point.suspicious_point_id)
    assert during.status == SPStatus.GENERATING_POV.value
    assert during.pov_incomplete_by == [{
        "harness_name": "fuzz", "sanitizer": "address",
        "reason": "user_stop_before_transport"}]
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="parallel-winner", success=True,
        harness_name="other", sanitizer="address", require_claim=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.POV_GENERATED.value
    assert stored.pov_id == "parallel-winner"


def test_stopped_and_failed_pov_contributors_settle_as_pending_stop():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    assert repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="other", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_STOP.value
    assert stored.pipeline_incomplete_reason == "user_stop_before_transport"
    assert stored.pov_success_by is None


def test_stopped_pov_contributor_cannot_late_complete_itself():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    assert not repo.complete_pov(
        point.suspicious_point_id, pov_id="late-a", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="a", claim_token="consumed-token")
    assert not repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="fuzz", sanitizer="address")
    during = repo.find_by_id(point.suspicious_point_id)
    assert during.status == SPStatus.GENERATING_POV.value
    assert during.pov_failed_by == []
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="winner-b", success=True,
        harness_name="other", sanitizer="address", require_claim=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))


def test_released_pov_contributor_does_not_requeue_active_sibling():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_POV.value,
        harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    during = repo.find_by_id(point.suspicious_point_id)
    assert during.status == SPStatus.GENERATING_POV.value
    assert during.pov_attempted_by == [
        {"harness_name": "other", "sanitizer": "address"}]
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="winner-b", success=True,
        harness_name="other", sanitizer="address", require_claim=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))


def _insert_crash_pov(repo, tmp_path, *, task_id, sp_id, harness_name):
    blob = b"crashing-input"
    pov_id = str(ObjectId())
    runtime_receipt = tmp_path / f"{pov_id}.runtime.json"
    physical_receipt = tmp_path / f"{pov_id}.physical.json"
    runtime_receipt.write_bytes(b"runtime")
    physical_receipt.write_bytes(b"physical")
    repo.db["povs"].insert_one({
        "_id": ObjectId(pov_id), "task_id": ObjectId(task_id),
        "suspicious_point_id": ObjectId(sp_id),
        "harness_name": harness_name, "sanitizer": "address",
        "is_successful": False, "is_active": True,
        "blob": base64.b64encode(blob).decode(),
        "qualified_runtime": {
            "status": "CRASH_OBSERVED",
            "input_sha256": hashlib.sha256(blob).hexdigest(),
            "binary_sha256": "a" * 64,
            "sanitizer": "heap-use-after-free",
            "runtime_receipt_path": str(runtime_receipt),
            "runtime_receipt_sha256": hashlib.sha256(
                runtime_receipt.read_bytes()).hexdigest(),
            "physical_receipt_path": str(physical_receipt),
            "physical_receipt_sha256": hashlib.sha256(
                physical_receipt.read_bytes()).hexdigest(),
        },
    })
    return pov_id


def test_stopped_contributor_allows_parallel_pending_validation(tmp_path):
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    pov_id = _insert_crash_pov(
        repo, tmp_path, task_id=task_id,
        sp_id=point.suspicious_point_id, harness_name="other")
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [pov_id], task_id=task_id,
        harness_name="other", sanitizer="address",
        validation_pending=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_INDEPENDENT_VALIDATION.value
    assert stored.pending_pov_ids == [pov_id]


def test_two_parallel_crashes_are_both_retained(tmp_path):
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    first = _insert_crash_pov(
        repo, tmp_path, task_id=task_id,
        sp_id=point.suspicious_point_id, harness_name="fuzz")
    second = _insert_crash_pov(
        repo, tmp_path, task_id=task_id,
        sp_id=point.suspicious_point_id, harness_name="other")
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [first], task_id=task_id,
        harness_name="fuzz", sanitizer="address", validation_pending=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [second], task_id=task_id,
        harness_name="other", sanitizer="address", validation_pending=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_INDEPENDENT_VALIDATION.value
    assert set(stored.pending_pov_ids) == {first, second}
    assert {(row["harness_name"], row["sanitizer"])
            for row in stored.pending_pov_artifacts} == {
                ("fuzz", "address"), ("other", "address")}


def test_sibling_pending_validation_is_authoritative_for_losing_completion(
    tmp_path,
):
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    crash = _insert_crash_pov(
        repo, tmp_path, task_id=task_id,
        sp_id=point.suspicious_point_id, harness_name="other")
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [crash], task_id=task_id,
        harness_name="other", sanitizer="address", validation_pending=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    assert not repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="fuzz", sanitizer="address")
    stored = repo.find_by_id(point.suspicious_point_id)
    assert AgentPipeline._parallel_pov_outcome_already_settled(stored)


def test_sibling_pending_validation_preserves_late_user_stop(tmp_path):
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    crash = _insert_crash_pov(
        repo, tmp_path, task_id=task_id,
        sp_id=point.suspicious_point_id, harness_name="other")
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [crash], task_id=task_id,
        harness_name="other", sanitizer="address", validation_pending=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))

    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_INDEPENDENT_VALIDATION.value
    assert stored.pending_pov_ids == [crash]
    assert {(row["harness_name"], row["sanitizer"], row["reason"])
            for row in stored.pov_incomplete_by} == {
                ("fuzz", "address", "user_stop_before_transport")}


def test_sibling_pending_alone_does_not_claim_unrecorded_stop(tmp_path):
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    # Only B owns a claim. Its retained crash cannot be used as proof that an
    # unrelated A stop was durably recorded.
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    crash = _insert_crash_pov(
        repo, tmp_path, task_id=task_id,
        sp_id=point.suspicious_point_id, harness_name="other")
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [crash], task_id=task_id,
        harness_name="other", sanitizer="address", validation_pending=True,
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    assert not repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address")
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_INDEPENDENT_VALIDATION.value
    assert stored.pov_incomplete_by == []


def test_failed_contributor_cannot_gain_late_incomplete_state():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    assert not repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address")
    during = repo.find_by_id(point.suspicious_point_id)
    assert during.pov_incomplete_by == []
    assert repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="other", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "other"))
    assert repo.find_by_id(point.suspicious_point_id).status == SPStatus.FAILED.value


def test_interrupted_contributor_cannot_reclaim_after_release():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.PENDING_STOP.value,
         "pipeline_incomplete_reason": "user_stop_before_transport"},
        stage="pov", harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    assert repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_POV.value,
        harness_name="fuzz", sanitizer="address",
        processor_id="a", claim_token="consumed-token") is False
    assert repo.claim_for_pov(
        task_id, "a-retry", 0.5, "fuzz", "address") is None


def test_release_claim_retries_when_sibling_fails_between_read_and_write():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$set": {"sources": [
            {"harness_name": "fuzz", "sanitizer": "address"},
            {"harness_name": "other", "sanitizer": "address"},
        ]}},
    )
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    original_update = repo.collection.update_one
    injected = False

    def update_with_sibling_failure(query, update, *args, **kwargs):
        nonlocal injected
        is_release = (not injected and
                      query.get("pov_attempted_by") == [
                          {"harness_name": "fuzz", "sanitizer": "address"},
                          {"harness_name": "other", "sanitizer": "address"},
                      ] and "pov_failed_by" in query and
                      update.get("$set", {}).get("pov_attempted_by") == [
                          {"harness_name": "other", "sanitizer": "address"}])
        if is_release:
            injected = True
            assert repo.complete_pov(
                point.suspicious_point_id, success=False,
                harness_name="other", sanitizer="address",
                **_active_pov_claim(repo, point.suspicious_point_id, "other"))
        return original_update(query, update, *args, **kwargs)

    with patch.object(repo.collection, "update_one",
                      side_effect=update_with_sibling_failure):
        assert repo.release_claim(
            point.suspicious_point_id, SPStatus.PENDING_POV.value,
            harness_name="fuzz", sanitizer="address",
            **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
    stored = repo.find_by_id(point.suspicious_point_id)
    active = (repo._pov_contributor_keys(stored.pov_attempted_by) -
              repo._pov_contributor_keys(stored.pov_failed_by) -
              repo._pov_contributor_keys(stored.pov_incomplete_by))
    assert not active
    assert stored.status != SPStatus.GENERATING_POV.value


def test_real_mongo_stopped_contributor_does_not_block_parallel_success():
    client = MongoClient("mongodb://127.0.0.1:27027/?directConnection=true",
                         serverSelectionTimeoutMS=500)
    try:
        client.admin.command("ping")
    except Exception as exc:
        client.close()
        pytest.skip(f"local development MongoDB unavailable: {type(exc).__name__}")
    db_name = "fbv2_stop_contributor_" + uuid4().hex
    try:
        repo = SuspiciousPointRepository(client[db_name])
        task_id = str(ObjectId())
        point = SuspiciousPoint(
            task_id=task_id, function_name="parse_input",
            description="shared candidate", vuln_type="buffer-overflow",
            score=0.9, sources=[
                {"harness_name": "fuzz", "sanitizer": "address"},
                {"harness_name": "other", "sanitizer": "address"},
            ],
        )
        point.status = SPStatus.PENDING_POV.value
        point.is_checked = point.is_real = point.is_important = True
        repo.collection.insert_one(point.to_dict())
        assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
        assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
        assert repo.preserve_incomplete_candidate(
            point.suspicious_point_id,
            {"status": SPStatus.PENDING_STOP.value,
             "pipeline_incomplete_reason": "user_stop_before_transport"},
            stage="pov", harness_name="fuzz", sanitizer="address",
            **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
        assert repo.complete_pov(
            point.suspicious_point_id, pov_id="mongo-winner", success=True,
            harness_name="other", sanitizer="address", require_claim=True,
            **_active_pov_claim(repo, point.suspicious_point_id, "other"))
        stored = repo.find_by_id(point.suspicious_point_id)
        assert stored.status == SPStatus.POV_GENERATED.value
        assert stored.pov_id == "mongo-winner"
    finally:
        client.drop_database(db_name)
        client.close()


def test_real_mongo_stopped_contributor_allows_pending_validation(tmp_path):
    client = MongoClient("mongodb://127.0.0.1:27027/?directConnection=true",
                         serverSelectionTimeoutMS=500)
    try:
        client.admin.command("ping")
    except Exception as exc:
        client.close()
        pytest.skip(f"local development MongoDB unavailable: {type(exc).__name__}")
    db_name = "fbv2_stop_pending_validation_" + uuid4().hex
    try:
        repo = SuspiciousPointRepository(client[db_name])
        task_id = str(ObjectId())
        point = SuspiciousPoint(
            task_id=task_id, function_name="parse_input",
            description="shared candidate", vuln_type="use-after-free",
            score=0.9, sources=[
                {"harness_name": "fuzz", "sanitizer": "address"},
                {"harness_name": "other", "sanitizer": "address"},
            ])
        point.status = SPStatus.PENDING_POV.value
        point.is_checked = point.is_real = point.is_important = True
        repo.collection.insert_one(point.to_dict())
        assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
        assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
        assert repo.preserve_incomplete_candidate(
            point.suspicious_point_id,
            {"status": SPStatus.PENDING_STOP.value,
             "pipeline_incomplete_reason": "user_stop_before_transport"},
            stage="pov", harness_name="fuzz", sanitizer="address",
            **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
        pov_id = _insert_crash_pov(
            repo, tmp_path, task_id=task_id,
            sp_id=point.suspicious_point_id, harness_name="other")
        assert repo.preserve_pov_pending_runtime(
            point.suspicious_point_id, [pov_id], task_id=task_id,
            harness_name="other", sanitizer="address",
            validation_pending=True,
            **_active_pov_claim(repo, point.suspicious_point_id, "other"))
        stored = repo.find_by_id(point.suspicious_point_id)
        assert stored.status == SPStatus.PENDING_INDEPENDENT_VALIDATION.value
    finally:
        client.drop_database(db_name)
        client.close()


def test_real_mongo_two_parallel_crashes_are_both_retained(tmp_path):
    client = MongoClient("mongodb://127.0.0.1:27027/?directConnection=true",
                         serverSelectionTimeoutMS=500)
    try:
        client.admin.command("ping")
    except Exception as exc:
        client.close()
        pytest.skip(f"local development MongoDB unavailable: {type(exc).__name__}")
    db_name = "fbv2_two_crashes_" + uuid4().hex
    try:
        repo = SuspiciousPointRepository(client[db_name])
        task_id = str(ObjectId())
        point = SuspiciousPoint(
            task_id=task_id, function_name="parse_input",
            description="shared candidate", vuln_type="use-after-free",
            score=0.9, sources=[
                {"harness_name": "fuzz", "sanitizer": "address"},
                {"harness_name": "other", "sanitizer": "address"},
            ])
        point.status = SPStatus.PENDING_POV.value
        point.is_checked = point.is_real = point.is_important = True
        repo.collection.insert_one(point.to_dict())
        assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
        assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
        first = _insert_crash_pov(
            repo, tmp_path, task_id=task_id,
            sp_id=point.suspicious_point_id, harness_name="fuzz")
        second = _insert_crash_pov(
            repo, tmp_path, task_id=task_id,
            sp_id=point.suspicious_point_id, harness_name="other")
        assert repo.preserve_pov_pending_runtime(
            point.suspicious_point_id, [first], task_id=task_id,
            harness_name="fuzz", sanitizer="address",
            validation_pending=True,
            **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))
        assert repo.preserve_pov_pending_runtime(
            point.suspicious_point_id, [second], task_id=task_id,
            harness_name="other", sanitizer="address",
            validation_pending=True,
            **_active_pov_claim(repo, point.suspicious_point_id, "other"))
        stored = repo.find_by_id(point.suspicious_point_id)
        assert set(stored.pending_pov_ids) == {first, second}
    finally:
        client.drop_database(db_name)
        client.close()


def test_late_pov_success_cannot_unseal_interrupted_candidate():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.preserve_incomplete_candidate(
        point.suspicious_point_id,
        {"status": SPStatus.INCOMPLETE_UNCERTAIN.value,
         "pipeline_incomplete_reason": "uncertain_remote"}, stage="pov",
        harness_name="fuzz", sanitizer="address",
        **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))

    assert not repo.complete_pov(
        point.suspicious_point_id, pov_id="late-pov", success=True,
        harness_name="fuzz", sanitizer="address")
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.INCOMPLETE_UNCERTAIN.value
    assert stored.pov_id is None


def test_late_pov_failure_cannot_overwrite_parallel_success():
    task_id, point, repo, _ = setup_candidate(SPStatus.PENDING_POV)
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$push": {"sources": {
            "harness_name": "other", "sanitizer": "address"}}})
    assert repo.claim_for_pov(task_id, "a", 0.5, "fuzz", "address")
    assert repo.claim_for_pov(task_id, "b", 0.5, "other", "address")
    stale_snapshot = repo.find_by_id(point.suspicious_point_id)
    original_find = repo.find_by_id

    def winner_after_failure_read(_sp_id):
        assert repo.complete_pov(
            point.suspicious_point_id, pov_id="winning-pov", success=True,
            harness_name="other", sanitizer="address",
            **_active_pov_claim(repo, point.suspicious_point_id, "other"))
        return stale_snapshot

    with patch.object(repo, "find_by_id", side_effect=winner_after_failure_read):
        assert not repo.complete_pov(
            point.suspicious_point_id, success=False,
            harness_name="fuzz", sanitizer="address",
            **_active_pov_claim(repo, point.suspicious_point_id, "fuzz"))

    stored = original_find(point.suspicious_point_id)
    assert stored.status == SPStatus.POV_GENERATED.value
    assert stored.pov_id == "winning-pov"


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


def test_verifier_user_stop_is_not_remote_uncertainty():
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=lambda role, owner: FinalClient(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(return_value="stopped")
        verifier.return_value.stop_reason = "user_stop_before_transport"
        asyncio.run(pipeline.run())

    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_STOP.value
    assert stored.pipeline_incomplete_reason == "user_stop_before_transport"
    assert stored.processor_id is None
    assert repo.claim_for_verify(
        task_id, "different-worker", "fuzz", "address") is None
    assert not repo.is_pipeline_complete(task_id, "fuzz", "address")


def test_pretransport_stopped_verifier_does_not_cancel_inflight_sibling():
    task_id, first, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    second = SuspiciousPoint(
        task_id=task_id, function_name="second", description="second cause",
        vuln_type="buffer-overflow", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
    )
    assert repo.save(second)
    first_started = asyncio.Event()
    allow_first_finish = asyncio.Event()

    class Agent:
        stop_reason = None

        def __init__(self, *, target_name, **_kwargs):
            self.target_name = target_name
            self.context = None

        def set_context(self, *, suspicious_point):
            self.context = suspicious_point

        async def run_async(self, **_kwargs):
            if self.target_name == "parse_input":
                first_started.set()
                await allow_first_finish.wait()
                from fuzzingbrain.tools.suspicious_points import (
                    get_sp_verification_claim_token,
                )
                assert repo.update_verifier_fields(
                    self.context["suspicious_point_id"],
                    {"is_checked": True, "is_real": False,
                     "is_important": False, "score": 0.1,
                     "verification_notes": "settled sibling"},
                    claim_token=get_sp_verification_claim_token())

    def client_factory(_role, owner):
        if owner.endswith(second.suspicious_point_id):
            assert first_started.is_set()
            allow_first_finish.set()
            raise CampaignStopping("stopped before transport")
        return FinalClient()

    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=2, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=client_factory,
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier", side_effect=Agent):
        asyncio.run(pipeline.run())

    settled = repo.find_by_id(first.suspicious_point_id)
    stopped = repo.find_by_id(second.suspicious_point_id)
    assert settled.status == SPStatus.REVIEWED_NOT_ADMITTED.value
    assert stopped.status == SPStatus.PENDING_STOP.value
    assert stopped.pipeline_incomplete_reason == "user_stop_before_transport"
    assert pipeline._incomplete_reason is None


def test_user_stop_does_not_hide_inflight_hard_failure():
    task_id, first, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    second = SuspiciousPoint(
        task_id=task_id, function_name="second", description="second cause",
        vuln_type="buffer-overflow", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
    )
    assert repo.save(second)
    first_started = asyncio.Event()
    allow_first_fail = asyncio.Event()

    class Agent:
        stop_reason = None

        def __init__(self, *, target_name, **_kwargs):
            self.target_name = target_name

        def set_context(self, *, suspicious_point):
            self.context = suspicious_point

        async def run_async(self, **_kwargs):
            if self.target_name == "parse_input":
                first_started.set()
                await allow_first_fail.wait()
                raise IncompleteInjectedAgent(
                    "durable candidate write failed",
                    reason="candidate_state_write_failed")

    def client_factory(_role, owner):
        if owner.endswith(second.suspicious_point_id):
            assert first_started.is_set()
            allow_first_fail.set()
            raise CampaignStopping("stopped before transport")
        return FinalClient()

    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address",
        config=PipelineConfig(num_verify_agents=2, num_pov_agents=0,
                              poll_interval=0),
        llm_client_factory=client_factory,
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier", side_effect=Agent):
        with pytest.raises(IncompleteInjectedAgent) as caught:
            asyncio.run(pipeline.run())

    assert caught.value.reason == "candidate_state_write_failed"
    assert pipeline._incomplete_reason == "candidate_state_write_failed"
    stopped = repo.find_by_id(second.suspicious_point_id)
    assert stopped.status == SPStatus.PENDING_STOP.value
    assert stopped.pipeline_incomplete_reason == "user_stop_before_transport"


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


def test_pov_user_stop_preserves_prior_verdict_without_uncertainty():
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
            return_value=SimpleNamespace(success=False, crashed=False,
                                         pending_runtime=False,
                                         pending_validation=False,
                                         error_msg=None, completed_at=None,
                                         pov_attempts=0, pov_id=None))
        pov.return_value.stop_reason = "user_stop_before_transport"
        asyncio.run(pipeline.run())

    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.PENDING_STOP.value
    assert stored.is_checked
    assert stored.pov_id is None
    assert stored.pov_success_by is None
    assert stored.pipeline_incomplete_reason == "user_stop_before_transport"
    assert repo.claim_for_pov(
        task_id, "different-worker", 0.5, "fuzz", "address") is None


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
