import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from bson import ObjectId
import mongomock
import pytest

from devtools.candidate_claim_settlement import candidate_claim_snapshot


def fixture_rows():
    db = mongomock.MongoClient().claims
    task = ObjectId()
    repos = SimpleNamespace(
        directions=SimpleNamespace(collection=db.directions),
        suspicious_points=SimpleNamespace(collection=db.suspicious_points))
    db.directions.insert_one({"task_id": task, "status": "completed",
                              "processor_id": None})
    db.suspicious_points.insert_one({
        "task_id": task, "status": "pending_independent_validation",
        "processor_id": None, "verification_claim_token": None,
        "pov_active_claims": []})
    return repos, task, db


def test_pending_validation_is_not_an_active_lease_or_validation_success():
    repos, task, _ = fixture_rows()
    row = candidate_claim_snapshot(repos, str(task))
    assert row["status"] == "NO_ACTIVE_CLAIMS"
    assert row["active_document_count"] == 0
    assert row["document_count"] == 2
    assert any(item["status"] == "pending_independent_validation"
               for item in row["rows"])


@pytest.mark.parametrize("update", [
    {"processor_id": "worker"}, {"verification_claim_token": "token"},
    {"pov_active_claims": [{"claim_token": "secret"}]},
    {"status": "verifying"}, {"status": "generating_pov"},
])
def test_each_lease_indicator_prevents_zero_claim_proof(update):
    repos, task, db = fixture_rows()
    db.suspicious_points.update_one({"task_id": task}, {"$set": update})
    row = candidate_claim_snapshot(repos, str(task))
    assert row["status"] == "ACTIVE"
    assert row["active_document_count"] == 1
    assert "secret" not in str(row)


def test_direction_claims_count_and_other_tasks_are_excluded():
    repos, task, db = fixture_rows()
    db.directions.update_one({"task_id": task}, {"$set": {"status": "in_progress"}})
    db.suspicious_points.insert_one({"task_id": ObjectId(), "processor_id": "other"})
    row = candidate_claim_snapshot(repos, str(task))
    assert row["active_documents_by_collection"] == {
        "directions": 1, "suspicious_points": 0}


@pytest.mark.parametrize("field", ["processor_id", "verification_claim_token",
                                    "pov_active_claims", "status"])
def test_missing_lease_field_is_unproven(field):
    repos, task, db = fixture_rows()
    db.suspicious_points.update_one({"task_id": task}, {"$unset": {field: ""}})
    row = candidate_claim_snapshot(repos, str(task))
    assert row["status"] == "UNPROVEN"
    assert row["active_document_count"] is None


def test_failed_database_read_is_not_zero():
    repos, task, _ = fixture_rows()
    repos.directions.collection = MagicMock()
    repos.directions.collection.find.side_effect = RuntimeError("offline")
    row = candidate_claim_snapshot(repos, str(task))
    assert row["status"] == "UNPROVEN"
    assert row["active_document_count"] is None


@pytest.mark.parametrize("collection", ["directions", "suspicious_points"])
@pytest.mark.parametrize("alias", ["lower", "upper", "mixed"])
def test_string_task_alias_cannot_hide_active_claim(collection, alias):
    repos, task, db = fixture_rows()
    text = str(task)
    task_alias = (text if alias == "lower" else text.upper() if alias == "upper"
                  else "".join(c.upper() if i % 2 else c for i, c in enumerate(text)))
    db[collection].insert_one({"task_id": task_alias, "status": "verifying",
                               "processor_id": "drifted-writer"})
    row = candidate_claim_snapshot(repos, text)
    assert row["status"] == "UNPROVEN"
    assert row["active_document_count"] is None


@pytest.mark.parametrize("case", ["settled", "active", "missing", "read_error",
                                  "string_task"])
def test_public_result_binds_snapshot_and_preserves_failed_proof(
        tmp_path, monkeypatch, case):
    from tests.test_goal_a_v3r6_contracts import _public_dev

    def setup(repos, task_id):
        row = {"task_id": ObjectId(task_id), "status": "pov_generated",
               "processor_id": None, "verification_claim_token": None,
               "pov_active_claims": []}
        if case == "active":
            row.update(status="verifying", processor_id="worker",
                       verification_claim_token="private-token")
        elif case == "missing":
            del row["verification_claim_token"]
        elif case == "string_task":
            row.update(task_id=task_id, status="verifying", processor_id="worker")
        repos.suspicious_points.collection.insert_one(row)
        if case == "read_error":
            monkeypatch.setattr(repos.directions.collection, "find",
                                MagicMock(side_effect=RuntimeError("offline")))

    result = _public_dev(tmp_path, monkeypatch, {}, setup_repos=setup)
    receipt_path = Path(result["claim_settlement_receipt_path"])
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == result["claim_settlement_receipt_sha256"]
    assert receipt["task_id"] == result["task_id"]
    assert receipt["run_id"] == result["run_id"]
    assert result["claim_settlement_phase"] == receipt["phase"] == "POST_WORKER_POST_GATE"
    assert receipt["process_receipt_sha256"] == result["process_receipt_sha256"]
    assert "private-token" not in raw.decode()
    if case == "settled":
        assert result["claim_settlement_status"] == "NO_ACTIVE_CLAIMS"
        assert result["active_repository_claim_document_count"] == 0
        assert result["execution_status"] == "EXECUTED"
    else:
        assert result["claim_settlement_status"] == "UNPROVEN"
        assert result["status"] == result["execution_status"] == "INCOMPLETE"
        assert result["active_repository_claim_document_count"] == (
            1 if case == "active" else None)


@pytest.mark.parametrize("case", ["active_process", "uncertain_model"])
def test_zero_repository_claims_does_not_hide_other_active_work(
        tmp_path, monkeypatch, case):
    from tests.test_goal_a_v3r6_contracts import _public_dev
    kwargs = ({"process_active": {"work": {"pid": 42}}}
              if case == "active_process" else
              {"model_records": [{"status": "UNCERTAIN"}]})
    result = _public_dev(tmp_path, monkeypatch, {}, **kwargs)
    assert result["active_repository_claim_document_count"] == 0
    assert result["claim_settlement_status"] == "UNPROVEN"
    assert result["status"] == result["execution_status"] == "INCOMPLETE"


@pytest.mark.parametrize("after_worker", ["clean", "lease", "process", "model",
                                         "read_error", "already_incomplete"])
def test_final_snapshot_rechecks_after_worker_state(tmp_path, monkeypatch, after_worker):
    from tests.test_goal_a_v3r6_contracts import _public_dev
    from devtools.original_public_live import finalize_public_claim_settlement
    captured = []
    result = _public_dev(tmp_path, monkeypatch, {}, capture_bound=captured.append)
    bound = captured[0]
    worker_path = Path(result["claim_settlement_receipt_path"])
    worker_bytes = worker_path.read_bytes()
    if after_worker == "lease":
        bound.server.repos.directions.collection.insert_one({
            "task_id": ObjectId(result["task_id"]), "status": "in_progress",
            "processor_id": "late-worker"})
    elif after_worker == "process":
        process, sha = bound.process_ledger.receipt_snapshot()
        process["active"] = {"late-process": {}}
    elif after_worker == "model":
        bound.model_gate.snapshot = lambda: {"physical": 1,
                                             "records": [{"status": "UNCERTAIN"}]}
    elif after_worker == "read_error":
        monkeypatch.setattr(bound.server.repos.directions.collection, "find",
                            MagicMock(side_effect=RuntimeError("offline")))
    elif after_worker == "already_incomplete":
        result.update(status="INCOMPLETE", execution_status="INCOMPLETE")
    final = finalize_public_claim_settlement(bound, result)
    assert worker_path.read_bytes() == worker_bytes
    assert final["worker_claim_settlement_receipt_path"] == str(worker_path)
    assert final["claim_settlement_phase"] == "FINAL_POST_HP"
    raw = Path(final["claim_settlement_receipt_path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == final["claim_settlement_receipt_sha256"]
    if after_worker in {"clean", "already_incomplete"}:
        assert final["claim_settlement_status"] == "NO_ACTIVE_CLAIMS"
    else:
        assert final["claim_settlement_status"] == "UNPROVEN"
    assert (final["status"] == "INCOMPLETE") == (after_worker != "clean")


def test_final_claim_rejects_injected_hp_gate_credit(tmp_path, monkeypatch):
    from tests.test_goal_a_v3r6_contracts import _public_dev
    from devtools.original_public_live import finalize_public_claim_settlement

    captured = []
    result = _public_dev(tmp_path, monkeypatch, {}, capture_bound=captured.append)
    forged = {**result, "parallel_hp_diagnostic": {
        "analysis_status": "HP_PARALLEL_ANALYSIS_COMPLETE",
        "security_gate_credit": "HP_GATE_VERIFIED",
        "discovery_credit": "NOT_CREDITED",
        "gate_status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
        "gate_result_sha256": "a" * 64,
    }}
    with pytest.raises(ValueError, match="worker Claim settlement evidence"):
        finalize_public_claim_settlement(captured[0], forged)


@pytest.mark.parametrize("damage_after_first_proof", [False, True])
def test_final_claim_reproves_saved_parallel_hp_evidence(
        tmp_path, monkeypatch, damage_after_first_proof):
    from tests.test_goal_a_v3r6_contracts import _public_dev
    from devtools.original_public_live import (
        _parallel_hp_settlement_evidence, finalize_public_claim_settlement)
    from devtools.parallel_hp_analysis import reprove_parallel_hp_diagnostic

    captured = []
    result = _public_dev(tmp_path, monkeypatch, {}, capture_bound=captured.append)
    bound = captured[0]
    analysis = {
        "kind": "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1",
        "status": "HP_PARALLEL_ANALYSIS_COMPLETE",
        "task_id": result["task_id"], "run_id": result["run_id"],
        "analysis": {"status": "NO_SAFE_ASSUMPTION"},
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    analysis_path = bound.identity.run_dir / "HP_PARALLEL_ANALYSIS_RESULT.json"
    analysis_path.write_text(json.dumps(analysis, sort_keys=True) + "\n")
    analysis_path.chmod(0o600)
    parallel_row = {
        **analysis, "result_path": str(analysis_path),
        "result_sha256": hashlib.sha256(analysis_path.read_bytes()).hexdigest(),
    }
    bound.strategy = SimpleNamespace(_parallel_hp_result=parallel_row)
    diagnostic = reprove_parallel_hp_diagnostic(
        bound.identity.run_dir, task_id=result["task_id"],
        run_id=result["run_id"], result=parallel_row)
    result["parallel_hp_diagnostic"] = diagnostic
    worker_path = Path(result["claim_settlement_receipt_path"])
    worker_receipt = json.loads(worker_path.read_bytes())
    worker_receipt["parallel_hp_evidence"] = (
        _parallel_hp_settlement_evidence(diagnostic))
    worker_path.write_text(json.dumps(worker_receipt, sort_keys=True) + "\n")
    result["claim_settlement_receipt_sha256"] = hashlib.sha256(
        worker_path.read_bytes()).hexdigest()
    spec = tmp_path / "parallel-final-spec.json"
    spec.write_text('{"hp":{"physical":{"output_limit_bytes":4000000}}}\n')
    spec_sha = hashlib.sha256(spec.read_bytes()).hexdigest()
    if damage_after_first_proof:
        # The first proof was valid; the finalizer must notice later damage.
        analysis_path.write_text('{"status":"DAMAGED"}\n')
        with pytest.raises(ValueError, match="parallel HP result hash changed"):
            finalize_public_claim_settlement(
                bound, result, parallel_hp_spec_path=spec,
                parallel_hp_spec_sha256=spec_sha)
        assert not (bound.identity.run_dir / "final-claim-settlement.json").exists()
    else:
        final = finalize_public_claim_settlement(
            bound, result, parallel_hp_spec_path=spec,
            parallel_hp_spec_sha256=spec_sha)
        assert final["claim_settlement_status"] == "NO_ACTIVE_CLAIMS"
        assert Path(final["claim_settlement_receipt_path"]).is_file()


def test_public_consumer_reads_pinned_spec_before_hp_gate_reproof(
        tmp_path, monkeypatch):
    from tests.test_goal_a_v3r6_contracts import _public_dev
    from devtools import parallel_hp_analysis

    calls = []
    diagnostic = {
        "analysis_status": "HP_PARALLEL_ANALYSIS_COMPLETE",
        "analysis_outcome": "ASSERTIONS_PROPOSED_UNVERIFIED",
        "physical_status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
        "gate_status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
        "security_gate_credit": "HP_GATE_VERIFIED",
        "discovery_credit": "NOT_CREDITED",
    }

    def reprove(*_args, **kwargs):
        calls.append(kwargs)
        return dict(diagnostic)

    monkeypatch.setattr(parallel_hp_analysis,
                        "reprove_parallel_hp_diagnostic", reprove)

    def configure(bound):
        bound.executor.parallel_hp_async_factory = object()

        def run():
            strategy = bound.executor._get_strategy()
            strategy._parallel_hp_result = {
                "result_path": str(bound.identity.run_dir /
                                   "HP_PARALLEL_ANALYSIS_RESULT.json"),
                "gate_result_path": str(bound.identity.run_dir /
                                        "hp-gate" /
                                        "HP_PARALLEL_GATE_RESULT.json"),
            }
            return {"pov_generated": 0}

        bound.executor.run = run

    result = _public_dev(tmp_path, monkeypatch, {},
                         capture_bound=configure)
    assert len(calls) == 1
    assert result["parallel_hp_diagnostic"] == diagnostic
    assert result["claim_settlement_status"] == "NO_ACTIVE_CLAIMS"
