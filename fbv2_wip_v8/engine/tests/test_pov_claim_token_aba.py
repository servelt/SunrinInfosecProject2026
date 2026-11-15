"""PoV contributor claims are generation-bound, not worker-name leases."""

import base64

from bson import ObjectId
import mongomock
from pymongo import MongoClient
import pytest
from uuid import uuid4

from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint, SPStatus
from fuzzingbrain.db.repository import SuspiciousPointRepository


def _candidate():
    repo = SuspiciousPointRepository(mongomock.MongoClient()["pov_claim_aba"])
    task_id = str(ObjectId())
    point = SuspiciousPoint(
        task_id=task_id,
        function_name="parse",
        description="candidate",
        vuln_type="use-after-free",
        score=0.9,
        is_checked=True,
        verification_disposition="SUPPORTED",
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        status=SPStatus.PENDING_POV.value,
    )
    repo.collection.insert_one(point.to_dict())
    return repo, task_id, point


def _claim(repo, task_id, processor="pov_1"):
    claim = repo.claim_for_pov(
        task_id, processor, min_score=0,
        harness_name="fuzz", sanitizer="address", raise_on_error=True)
    assert claim is not None
    assert claim.pov_claim_token
    assert "pov_claim_token" not in claim.to_dict()
    return claim


def test_release_reclaim_rejects_stale_success_and_failure():
    repo, task_id, point = _candidate()
    first = _claim(repo, task_id)
    assert repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_POV.value,
        harness_name="fuzz", sanitizer="address", processor_id="pov_1",
        claim_token=first.pov_claim_token)

    second = _claim(repo, task_id)
    assert second.pov_claim_token != first.pov_claim_token

    assert not repo.complete_pov(
        point.suspicious_point_id, pov_id="stale", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=first.pov_claim_token)
    assert not repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=first.pov_claim_token)

    current = repo.find_by_id(point.suspicious_point_id)
    assert current.status == SPStatus.GENERATING_POV.value
    assert current.pov_id is None
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="fresh", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=second.pov_claim_token)
    assert repo.find_by_id(point.suspicious_point_id).pov_id == "fresh"


def test_tokenless_and_wrong_release_cannot_mutate_active_claim():
    repo, task_id, point = _candidate()
    claim = _claim(repo, task_id)
    kwargs = dict(
        revert_status=SPStatus.PENDING_POV.value,
        harness_name="fuzz", sanitizer="address", processor_id="pov_1")
    assert not repo.release_claim(point.suspicious_point_id, **kwargs)
    assert not repo.release_claim(
        point.suspicious_point_id, claim_token="wrong", **kwargs)
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.GENERATING_POV.value
    assert repo.release_claim(
        point.suspicious_point_id, claim_token=claim.pov_claim_token, **kwargs)


def test_unisolated_pov_claim_is_rejected():
    repo, task_id, _ = _candidate()
    assert repo.claim_for_pov(task_id, "pov_1", min_score=0) is None


@pytest.mark.parametrize("field,value", [
    ("suspicious_point_id", str(ObjectId())),
    ("task_id", ObjectId()),
    ("direction_id", ObjectId()),
    ("function_name", "forged"),
    ("sources.0.harness_name", "forged"),
    ("description", "forged hypothesis"),
    ("vuln_type", "forged-type"),
    ("pov_success_by", {"harness_name": "forged", "sanitizer": "address"}),
    ("pov_id", ObjectId()),
    ("pov_attempted_by", []),
    ("pov_failed_by", []),
    ("pov_incomplete_by", []),
    ("pending_pov_ids", [str(ObjectId())]),
    ("pending_pov_artifacts", [{"pov_id": str(ObjectId())}]),
    ("pipeline_incomplete_reason", "forged"),
])
def test_generic_update_cannot_mutate_pov_owned_state(field, value):
    repo, task_id, point = _candidate()
    claim = _claim(repo, task_id)
    assert not repo.update(point.suspicious_point_id, {field: value})
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.GENERATING_POV.value
    assert stored.pov_success_by is None
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="fresh", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=claim.pov_claim_token)


def test_generic_dotted_update_cannot_replace_active_claim_token():
    repo, task_id, point = _candidate()
    claim = _claim(repo, task_id)
    assert not repo.update(point.suspicious_point_id, {
        "pov_active_claims.0.claim_token": "forged-token"})
    assert not repo.complete_pov(
        point.suspicious_point_id, pov_id="forged", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token="forged-token")
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="fresh", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=claim.pov_claim_token)


def test_every_persisted_suspicious_point_field_has_an_explicit_writer():
    persisted = set(SuspiciousPoint().to_dict())
    assert persisted <= SuspiciousPointRepository._PIPELINE_OWNED_FIELDS


def test_save_accepts_only_clean_initial_candidate():
    repo = SuspiciousPointRepository(mongomock.MongoClient()["clean_creation"])
    task_id = str(ObjectId())
    clean = SuspiciousPoint(
        task_id=task_id, function_name="parse", description="candidate",
        vuln_type="use-after-free", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}])
    assert repo.save(clean)

    forged = SuspiciousPoint(
        task_id=task_id, function_name="parse", description="forged",
        vuln_type="use-after-free", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        status=SPStatus.POV_GENERATED.value, is_real=True,
        pov_id=str(ObjectId()),
        pov_success_by={"harness_name": "fuzz", "sanitizer": "address"})
    assert not repo.save(forged)

    invalid = SuspiciousPoint(
        task_id=task_id, function_name="parse", description="invalid source",
        vuln_type="use-after-free", sources=[{
            "harness_name": ObjectId(), "sanitizer": ObjectId()}])
    assert not repo.save(invalid)


@pytest.mark.parametrize("mutation", [
    lambda point: setattr(point, "task_id", ""),
    lambda point: setattr(point, "function_name", ObjectId()),
    lambda point: setattr(point, "description", ObjectId()),
    lambda point: setattr(point, "vuln_type", ObjectId()),
    lambda point: setattr(point, "score", "high"),
    lambda point: setattr(point, "verification_notes", "preverified"),
    lambda point: setattr(point, "verified_by_agent_id", str(ObjectId())),
    lambda point: setattr(point, "checked_at", "2026-11-10T00:00:00"),
    lambda point: setattr(point, "pov_guidance", "preloaded"),
    lambda point: setattr(point, "important_controlflow", ["raw expression"]),
])
def test_save_rejects_malformed_or_preverified_candidate(mutation):
    repo = SuspiciousPointRepository(mongomock.MongoClient()["strict_creation"])
    point = SuspiciousPoint(
        task_id=str(ObjectId()), function_name="parse",
        description="candidate", vuln_type="use-after-free", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}])
    mutation(point)
    assert not repo.save(point)
    assert repo.collection.count_documents({}) == 0


def test_generic_update_rejects_hostile_string_subclass_key():
    class HostileKey(str):
        def split(self, *_args, **_kwargs):
            return ["description"]

    repo, task_id, point = _candidate()
    claim = _claim(repo, task_id)
    key = HostileKey("pov_active_claims.0.claim_token")
    assert not repo.update(point.suspicious_point_id, {key: "forged-token"})
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="fresh", success=True,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=claim.pov_claim_token)


@pytest.mark.parametrize("harness_name,sanitizer", [
    ("", ""),
    (ObjectId(), ObjectId()),
    ("fuzz", ObjectId()),
])
def test_add_source_rejects_unclaimable_contributor(harness_name, sanitizer):
    repo, _, point = _candidate()
    assert not repo.add_source(
        point.suspicious_point_id, harness_name, sanitizer)
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.sources == [
        {"harness_name": "fuzz", "sanitizer": "address"}]


def test_distinct_contributors_receive_independent_tokens():
    repo, task_id, point = _candidate()
    repo.collection.update_one(
        {"_id": ObjectId(point.suspicious_point_id)},
        {"$push": {"sources": {
            "harness_name": "other", "sanitizer": "address"}}})
    first = _claim(repo, task_id, "pov_1")
    second = repo.claim_for_pov(
        task_id, "pov_2", min_score=0,
        harness_name="other", sanitizer="address", raise_on_error=True)
    assert second is not None
    assert second.pov_claim_token != first.pov_claim_token
    assert repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=first.pov_claim_token)
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="winner", success=True,
        harness_name="other", sanitizer="address", require_claim=True,
        processor_id="pov_2", claim_token=second.pov_claim_token)
    stored = repo.collection.find_one({"_id": ObjectId(point.suspicious_point_id)})
    assert stored["pov_active_claims"] == []


def test_new_source_reopens_candidate_after_prior_contributors_failed():
    repo, task_id, point = _candidate()
    first = _claim(repo, task_id)
    assert repo.complete_pov(
        point.suspicious_point_id, success=False,
        harness_name="fuzz", sanitizer="address", require_claim=True,
        processor_id="pov_1", claim_token=first.pov_claim_token)
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.FAILED.value

    assert repo.add_source(
        point.suspicious_point_id, "other", "address")
    assert repo.find_by_id(point.suspicious_point_id).status == \
        SPStatus.PENDING_POV.value
    second = repo.claim_for_pov(
        task_id, "pov_2", min_score=0,
        harness_name="other", sanitizer="address", raise_on_error=True)
    assert second is not None
    assert repo.complete_pov(
        point.suspicious_point_id, pov_id="winner", success=True,
        harness_name="other", sanitizer="address", require_claim=True,
        processor_id="pov_2", claim_token=second.pov_claim_token)


def test_source_merge_survives_failure_between_add_and_reopen(monkeypatch):
    repo, task_id, point = _candidate()
    first = _claim(repo, task_id)
    original_update_one = repo.collection.update_one
    calls = 0

    def racing_update_one(query, update, *args, **kwargs):
        nonlocal calls
        result = original_update_one(query, update, *args, **kwargs)
        calls += 1
        if calls == 1:
            # Force the old contributor's terminal transition immediately
            # after the new source becomes durable and before reopen.
            original_update_one(
                {"_id": ObjectId(point.suspicious_point_id)},
                {"$set": {"status": SPStatus.FAILED.value},
                 "$addToSet": {"pov_failed_by": {
                     "harness_name": "fuzz", "sanitizer": "address"}},
                 "$pull": {"pov_active_claims": {
                     "claim_token": first.pov_claim_token}}})
        return result

    monkeypatch.setattr(repo.collection, "update_one", racing_update_one)
    assert repo.add_source(point.suspicious_point_id, "other", "address")
    stored = repo.find_by_id(point.suspicious_point_id)
    assert {"harness_name": "other", "sanitizer": "address"} in stored.sources
    assert stored.status == SPStatus.PENDING_POV.value
    assert repo.claim_for_pov(
        task_id, "pov_2", min_score=0,
        harness_name="other", sanitizer="address", raise_on_error=True)


def test_duplicate_source_retry_recovers_crash_before_reopen(monkeypatch):
    repo, task_id, point = _candidate()
    original_update_one = repo.collection.update_one
    crashed = False

    def crash_after_source_add(query, update, *args, **kwargs):
        nonlocal crashed
        result = original_update_one(query, update, *args, **kwargs)
        if not crashed and "$addToSet" in update:
            crashed = True
            original_update_one(
                {"_id": ObjectId(point.suspicious_point_id)},
                {"$set": {"status": SPStatus.FAILED.value},
                 "$addToSet": {"pov_failed_by": {
                     "harness_name": "fuzz", "sanitizer": "address"}}})
            raise RuntimeError("injected crash after durable source add")
        return result

    monkeypatch.setattr(repo.collection, "update_one", crash_after_source_add)
    assert not repo.add_source(
        point.suspicious_point_id, "other", "address")
    after_crash = repo.find_by_id(point.suspicious_point_id)
    assert after_crash.status == SPStatus.FAILED.value
    assert {"harness_name": "other", "sanitizer": "address"} in \
        after_crash.sources

    monkeypatch.setattr(repo.collection, "update_one", original_update_one)
    assert repo.add_source(
        point.suspicious_point_id, "other", "address")
    recovered = repo.find_by_id(point.suspicious_point_id)
    assert recovered.status == SPStatus.PENDING_POV.value
    assert repo.claim_for_pov(
        task_id, "pov_2", min_score=0,
        harness_name="other", sanitizer="address", raise_on_error=True)


def test_new_source_cannot_bypass_failed_verifier():
    repo = SuspiciousPointRepository(
        mongomock.MongoClient()["failed_verifier_source"])
    task_id = str(ObjectId())
    point = SuspiciousPoint(
        task_id=task_id, function_name="parse", description="candidate",
        vuln_type="use-after-free", score=0.9,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        status=SPStatus.FAILED.value, is_checked=False)
    repo.collection.insert_one(point.to_dict())

    assert repo.add_source(
        point.suspicious_point_id, "other", "address")
    stored = repo.find_by_id(point.suspicious_point_id)
    assert stored.status == SPStatus.FAILED.value
    assert {"harness_name": "other", "sanitizer": "address"} in stored.sources
    assert repo.claim_for_pov(
        task_id, "pov_2", min_score=0,
        harness_name="other", sanitizer="address") is None


def test_stale_claim_cannot_preserve_interruption_or_runtime():
    repo, task_id, point = _candidate()
    first = _claim(repo, task_id)
    assert repo.release_claim(
        point.suspicious_point_id, SPStatus.PENDING_POV.value,
        harness_name="fuzz", sanitizer="address", processor_id="pov_1",
        claim_token=first.pov_claim_token)
    second = _claim(repo, task_id)

    updates = {
        "status": SPStatus.INCOMPLETE_UNCERTAIN.value,
        "pipeline_incomplete_reason": "uncertain_remote",
    }
    assert not repo.preserve_incomplete_candidate(
        point.suspicious_point_id, updates, stage="pov",
        harness_name="fuzz", sanitizer="address", processor_id="pov_1",
        claim_token=first.pov_claim_token)

    pov_id = str(ObjectId())
    repo.db["povs"].insert_one({
        "_id": ObjectId(pov_id),
        "task_id": ObjectId(task_id),
        "suspicious_point_id": ObjectId(point.suspicious_point_id),
        "harness_name": "fuzz", "sanitizer": "address",
        "is_successful": False, "is_active": True,
        "blob": base64.b64encode(b"candidate-input").decode(),
    })
    assert not repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [pov_id], task_id=task_id,
        harness_name="fuzz", sanitizer="address", processor_id="pov_1",
        claim_token=first.pov_claim_token)
    assert repo.preserve_pov_pending_runtime(
        point.suspicious_point_id, [pov_id], task_id=task_id,
        harness_name="fuzz", sanitizer="address", processor_id="pov_1",
        claim_token=second.pov_claim_token)


def test_real_mongo_release_reclaim_rejects_stale_completion():
    client = MongoClient(
        "mongodb://127.0.0.1:27027/?directConnection=true",
        serverSelectionTimeoutMS=500)
    try:
        client.admin.command("ping")
    except Exception as exc:
        client.close()
        pytest.skip(f"local development MongoDB unavailable: {type(exc).__name__}")
    db_name = "fbv2_pov_claim_aba_" + uuid4().hex
    try:
        repo = SuspiciousPointRepository(client[db_name])
        task_id = str(ObjectId())
        point = SuspiciousPoint(
            task_id=task_id, function_name="parse", description="candidate",
            vuln_type="use-after-free", score=0.9,
            sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
            status=SPStatus.PENDING_POV.value)
        repo.collection.insert_one(point.to_dict())
        first = _claim(repo, task_id)
        assert not repo.update(point.suspicious_point_id, {
            "pov_success_by": {
                "harness_name": "forged", "sanitizer": "address"}})
        assert not repo.update(point.suspicious_point_id, {
            "pov_active_claims.0.claim_token": "forged-token"})
        assert not repo.update(point.suspicious_point_id, {
            "suspicious_point_id": str(ObjectId())})
        assert not repo.update(point.suspicious_point_id, {
            "task_id": ObjectId()})
        assert not repo.update(point.suspicious_point_id, {
            "sources.0.harness_name": "forged"})
        assert not repo.add_source(point.suspicious_point_id, "", "")
        assert not repo.add_source(
            point.suspicious_point_id, ObjectId(), ObjectId())
        assert not repo.complete_pov(
            point.suspicious_point_id, pov_id="forged", success=True,
            harness_name="fuzz", sanitizer="address", require_claim=True,
            processor_id="pov_1", claim_token="forged-token")
        assert repo.release_claim(
            point.suspicious_point_id, SPStatus.PENDING_POV.value,
            harness_name="fuzz", sanitizer="address", processor_id="pov_1",
            claim_token=first.pov_claim_token)
        second = _claim(repo, task_id)
        assert not repo.complete_pov(
            point.suspicious_point_id, pov_id="stale", success=True,
            harness_name="fuzz", sanitizer="address", require_claim=True,
            processor_id="pov_1", claim_token=first.pov_claim_token)
        assert repo.complete_pov(
            point.suspicious_point_id, pov_id="fresh", success=True,
            harness_name="fuzz", sanitizer="address", require_claim=True,
            processor_id="pov_1", claim_token=second.pov_claim_token)
        stored = repo.collection.find_one(
            {"_id": ObjectId(point.suspicious_point_id)})
        assert stored["pov_active_claims"] == []
    finally:
        client.drop_database(db_name)
        client.close()

