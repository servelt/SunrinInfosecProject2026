"""Provider-free checks for the signed FullScan Gate stop boundary."""

import asyncio
import json
import threading
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from bson import ObjectId

PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
EVAL_TOOLS = Path(__file__).resolve().parents[2] / "evaluation_tools"
for source in (PRODUCT_SRC, EVAL_TOOLS):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from devtools import model_candidate_lineage, original_public_live
from devtools import product_qualified_runtime
from devtools.original_public_live import QualifiedGateStop
from devtools.original_public_live_entry import _live_result_exit_ok
from fuzzingbrain.worker.pipeline import AgentPipeline, IncompleteInjectedAgent
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


def _coordinator(tmp_path):
    adapter_root = tmp_path / "pov-runtime"
    adapter_root.mkdir()
    bound = SimpleNamespace(
        identity=SimpleNamespace(run_dir=tmp_path, task_id=str(ObjectId())),
        server=SimpleNamespace(repos=object()),
        pov_adapter=SimpleNamespace(root=adapter_root),
        caps=SimpleNamespace(pov_timeout_seconds=10,
                             gate_aux_reservation_seconds_per_observation=600),
        process_ledger=SimpleNamespace(
            snapshot=lambda: {"stop_status": None, "active": {}}),
        model_gate=object(), recheck=lambda: None,
    )
    return QualifiedGateStop(bound)


def test_gate_pending_continues_and_each_input_is_consumed_once(tmp_path, monkeypatch):
    coordinator = _coordinator(tmp_path)
    pov_id = str(ObjectId())
    calls = []

    def consume(_adapter, actual_id, **kwargs):
        calls.append((actual_id, kwargs["gate_wall_seconds"]))
        row = {"pov_id": actual_id,
               "product_gate_status": "TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE",
               "origin_verification_status":
                   "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE"}
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        (target / "outcome.json").write_text(json.dumps(row))
        return row

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    assert coordinator.consume([pov_id]) is False
    assert coordinator.consume([pov_id]) is False
    assert calls == [(pov_id, 600)]
    assert coordinator.retained_row(pov_id)["pov_id"] == pov_id


def test_settled_gate_local_exception_is_retained_without_fullscan_stop(
        tmp_path, monkeypatch):
    coordinator = _coordinator(tmp_path)
    pov_id = str(ObjectId())

    def consume(_adapter, actual_id, **_kwargs):
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        receipt = {
            "kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1",
            "task_id": coordinator.bound.identity.task_id,
            "run_id": "fixture", "pov_id": actual_id,
            "input_sha256": "0" * 64, "stage": "PRODUCT_POSTPROCESS",
            "error_type": "ValueError", "stop_status": None,
            "physical_finished": 1, "physical_active": 3,
            "physical_ledger_receipt_sha256": "1" * 64,
        }
        (target / "incomplete.json").write_text(json.dumps(receipt))
        raise ValueError("Gate-local postprocessing failed")

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    assert coordinator.consume([pov_id]) is False
    row = coordinator.retained_row(pov_id)
    assert row["kind"] == "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1"
    assert row["stage"] == "PRODUCT_POSTPROCESS"
    assert coordinator.verified.is_set() is False


def test_shared_stop_is_never_reclassified_as_gate_local(tmp_path, monkeypatch):
    coordinator = _coordinator(tmp_path)
    coordinator.bound.process_ledger = SimpleNamespace(
        snapshot=lambda: {"stop_status": "STOPPED_PIN_DRIFT", "active": {}})
    pov_id = str(ObjectId())

    def consume(_adapter, actual_id, **_kwargs):
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        (target / "incomplete.json").write_text(json.dumps({
            "kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1",
            "pov_id": actual_id, "stage": "PRODUCT_EXECUTION",
            "error_type": "ValueError", "stop_status": None,
        }))
        raise ValueError("shared pin drift")

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    with pytest.raises(ValueError, match="shared pin drift"):
        coordinator.consume([pov_id])


def test_gate_local_failure_pin_recheck_escalates_to_shared_stop(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.runtime import ProcessEnvelopeStop

    coordinator = _coordinator(tmp_path)
    state = {"stop_status": None, "active": {}}

    class Ledger:
        def snapshot(self):
            return dict(state)

        def mark_stop(self, status, _detail):
            state["stop_status"] = status

    coordinator.bound.process_ledger = Ledger()
    coordinator.bound.recheck = lambda: (_ for _ in ()).throw(
        ValueError("source pin changed"))
    pov_id = str(ObjectId())

    def consume(_adapter, actual_id, **_kwargs):
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        (target / "incomplete.json").write_text(json.dumps({
            "kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1",
            "pov_id": actual_id, "stage": "PRODUCT_POSTPROCESS",
            "error_type": "RuntimeError", "stop_status": None,
        }))
        raise RuntimeError("local postprocess error")

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    with pytest.raises(ProcessEnvelopeStop) as stopped:
        coordinator.consume([pov_id])
    assert stopped.value.status == "STOPPED_PIN_DRIFT"
    assert state["stop_status"] == "STOPPED_PIN_DRIFT"


def test_verified_outcome_is_cached_only_after_lineage_and_rechecked_read_only(
        tmp_path, monkeypatch):
    coordinator = _coordinator(tmp_path)
    pov_id = str(ObjectId())
    calls = []

    def consume(_adapter, actual_id, **_kwargs):
        calls.append(actual_id)
        row = {
            "kind": "FBV2_POV_PRODUCT_GATE_OUTCOME_V1",
            "pov_id": actual_id, "product_gate_status": "VERIFIED",
            "origin_verification_status":
                "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE",
            "security_gate_state": "COMPLETED",
            "security_gate_result": True,
        }
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        (target / "outcome.json").write_text(json.dumps(row))
        return row

    lineage_calls = 0

    def candidate(*_args, **_kwargs):
        nonlocal lineage_calls
        lineage_calls += 1
        if lineage_calls == 1:
            raise ValueError("lineage read failed")
        return {"status": "VERIFIED"}

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    monkeypatch.setattr(model_candidate_lineage, "find_candidate_lineage",
                        candidate)
    monkeypatch.setattr(product_qualified_runtime,
                        "verify_qualified_pov_runtime_lineage",
                        lambda *_args, **_kwargs: {"status": "VERIFIED"})
    monkeypatch.setattr(
        original_public_live, "_model_lineage_gate_verified_pov_ids",
        lambda _root, _lineage, rows: [rows[0]["pov_id"]])
    # Goal A.1.2: the replay-identity proof is exercised by the real-path tests
    # in test_goal_a1_gate_resolution.py; here it is satisfied for the row.
    monkeypatch.setattr(
        original_public_live, "_authenticated_verified_gate_pov_ids",
        lambda _identity, rows, _observed, _finished: {rows[0]["pov_id"]})
    with pytest.raises(ValueError, match="lineage read failed"):
        coordinator.consume([pov_id])
    assert pov_id not in coordinator._rows
    assert coordinator.consume([pov_id]) is True
    assert calls == [pov_id]  # no second physical product Gate invocation
    assert coordinator.retained_row(pov_id)["product_gate_status"] == "VERIFIED"


def test_gate_local_wall_stop_is_retained_without_stopping_fullscan(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.runtime import ProcessEnvelopeStop

    coordinator = _coordinator(tmp_path)
    pov_id = str(ObjectId())

    def consume(_adapter, actual_id, **_kwargs):
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        receipt = {
            "kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1",
            "task_id": coordinator.bound.identity.task_id,
            "run_id": "fixture", "pov_id": actual_id,
            "input_sha256": "0" * 64, "stage": "PRODUCT_EXECUTION",
            "error_type": "ProcessEnvelopeStop",
            "stop_status": "STOPPED_LOCAL_WALL_LIMIT",
            "physical_finished": 1, "physical_active": 0,
            "physical_ledger_receipt_sha256": "1" * 64,
        }
        (target / "incomplete.json").write_text(json.dumps(receipt))
        raise ProcessEnvelopeStop(
            "STOPPED_LOCAL_WALL_LIMIT", "Gate-local deadline expired")

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    assert coordinator.consume([pov_id]) is False
    assert coordinator.verified.is_set() is False
    assert coordinator.retained_row(pov_id)["stop_status"] == (
        "STOPPED_LOCAL_WALL_LIMIT")
    # The terminal local claim is not retried.
    assert coordinator.consume([pov_id]) is False


def test_only_origin_bound_product_verified_requests_stop(tmp_path, monkeypatch):
    coordinator = _coordinator(tmp_path)
    unproven_id, label_only_id, verified_id = (
        str(ObjectId()), str(ObjectId()), str(ObjectId()))

    def consume(_adapter, actual_id, **_kwargs):
        row = {"pov_id": actual_id, "product_gate_status": "VERIFIED",
               "origin_verification_status": (
                   "UNVERIFIED_LINEAGE" if actual_id == unproven_id else
                   "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE"),
               "security_gate_state": "COMPLETED",
               "security_gate_result": actual_id != label_only_id}
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        (target / "outcome.json").write_text(json.dumps(row))
        return row

    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    monkeypatch.setattr(model_candidate_lineage, "find_candidate_lineage",
                        lambda *_args, **_kwargs: {"status": "VERIFIED"})
    monkeypatch.setattr(product_qualified_runtime,
                        "verify_qualified_pov_runtime_lineage",
                        lambda *_args, **_kwargs: {"status": "VERIFIED"})
    monkeypatch.setattr(
        original_public_live, "_model_lineage_gate_verified_pov_ids",
        lambda _root, _lineage, gate_rows: [gate_rows[0]["pov_id"]]
        if gate_rows[0].get("security_gate_result") is True else [])
    monkeypatch.setattr(
        original_public_live, "_authenticated_verified_gate_pov_ids",
        lambda _identity, rows, _observed, _finished: {rows[0]["pov_id"]})
    assert coordinator.consume([unproven_id]) is False
    assert coordinator.consume([label_only_id]) is False
    assert coordinator.consume([verified_id]) is True
    assert coordinator.verified.is_set()
    outcome = tmp_path / "pov-validation" / verified_id / "outcome.json"
    outcome.write_text('{"pov_id":"tampered"}')
    with pytest.raises(ValueError, match="outcome changed"):
        coordinator.retained_row(verified_id)


def test_pipeline_does_not_call_pending_validation_complete_after_verified_gate():
    stop = SimpleNamespace(verified=threading.Event())
    pipeline = AgentPipeline(
        task_id="fixture", repos=SimpleNamespace(), llm_client_factory=object(),
        qualified_gate_stop=stop)
    pipeline.serial_bounded_dev = True
    pipeline._sp_finding_done = True

    async def verify(_agent_id):
        return None

    async def pov(_agent_id):
        pipeline.stats.pov_pending_validation = 1

    pipeline._run_verify_agent = verify
    pipeline._run_pov_agent = pov
    with pytest.raises(IncompleteInjectedAgent) as exc:
        asyncio.run(pipeline.run())
    assert exc.value.reason == "validation_pending"
    stop.verified.set()
    assert asyncio.run(pipeline.run()).pov_pending_validation == 1


def test_verified_gate_stops_new_verifier_and_pov_claims():
    stop = SimpleNamespace(verified=threading.Event())
    stop.verified.set()
    repos = SimpleNamespace(suspicious_points=MagicMock())
    pipeline = AgentPipeline(
        task_id="fixture", repos=repos, llm_client_factory=object(),
        qualified_gate_stop=stop)
    asyncio.run(pipeline._run_verify_agent("verify_1"))
    asyncio.run(pipeline._run_pov_agent("pov_1"))
    repos.suspicious_points.claim_for_verify.assert_not_called()
    repos.suspicious_points.claim_for_pov.assert_not_called()


def test_queued_sp_functions_skip_after_verified_gate(tmp_path):
    stop = SimpleNamespace(verified=threading.Event())
    stop.verified.set()
    strategy = POVFullscanStrategy.__new__(POVFullscanStrategy)
    strategy.executor = SimpleNamespace(qualified_gate_stop=stop)
    strategy._full_nohint_sp = True
    strategy.num_parallel_agents = 2
    strategy.llm_client_factory = object()
    strategy._development_sp_queue_drain = False
    strategy._development_auto_scope = None

    async def forbidden(**_kwargs):
        raise AssertionError("a new SP analysis started after Gate VERIFIED")

    strategy._analyze_single_function_v2 = forbidden
    work = [(SimpleNamespace(function_id="a"), "direction"),
            (SimpleNamespace(function_id="b"), "direction")]
    asyncio.run(strategy._run_function_batch(work, tmp_path))


def test_running_sp_turns_settle_and_queued_functions_do_not_start(tmp_path):
    stop = SimpleNamespace(verified=threading.Event())
    strategy = POVFullscanStrategy.__new__(POVFullscanStrategy)
    strategy.executor = SimpleNamespace(qualified_gate_stop=stop)
    strategy._full_nohint_sp = True
    strategy.num_parallel_agents = 2
    strategy.llm_client_factory = object()
    strategy._development_sp_queue_drain = False
    strategy._development_auto_scope = None
    strategy._active_pipeline_task = None
    strategy.fuzzer = "fixture"
    strategy.sanitizer = "address"
    started = []

    async def run_batch():
        release = asyncio.Event()
        both_started = asyncio.Event()

        async def analyze(**kwargs):
            started.append(kwargs["func"].function_id)
            if len(started) == 2:
                both_started.set()
            await release.wait()
            return {"success": True}

        strategy._analyze_single_function_v2 = analyze
        work = [(SimpleNamespace(function_id=str(i)), "direction")
                for i in range(5)]
        batch = asyncio.create_task(strategy._run_function_batch(work, tmp_path))
        await asyncio.wait_for(both_started.wait(), 2)
        stop.verified.set()
        release.set()
        await batch

    asyncio.run(run_batch())
    assert started == ["0", "1"]


def test_signed_entry_accepts_gate_verified_early_stop():
    assert _live_result_exit_ok(
        {"status": "EXECUTED_VERIFIED_EARLY_STOP"}, hp_required=False)


def test_unproven_verified_label_does_not_stop_the_queue(tmp_path, monkeypatch):
    # Goal A.1.2: lineage alone is not enough; a VERIFIED label whose replay
    # identity cannot be re-proven from hash-bound artifacts never stops FullScan.
    coordinator = _coordinator(tmp_path)
    pov_id = str(ObjectId())

    def consume(_adapter, actual_id, **_kwargs):
        row = {"kind": "FBV2_POV_PRODUCT_GATE_OUTCOME_V1", "pov_id": actual_id,
               "product_gate_status": "VERIFIED", "gate_resolution": "VERIFIED",
               "gate_resolution_reason": "GATE_VERIFIED",
               "task_id": coordinator.bound.identity.task_id, "run_id": "run",
               "origin_verification_status": "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE",
               "security_gate_state": "COMPLETED", "security_gate_result": True}
        target = tmp_path / "pov-validation" / actual_id
        target.mkdir(parents=True)
        (target / "outcome.json").write_text(json.dumps(row))
        return row

    coordinator.bound.identity.run_id = "run"
    monkeypatch.setattr(product_qualified_runtime,
                        "consume_qualified_pov_observation", consume)
    monkeypatch.setattr(model_candidate_lineage, "find_candidate_lineage",
                        lambda *_args, **_kwargs: {"status": "VERIFIED"})
    monkeypatch.setattr(product_qualified_runtime,
                        "verify_qualified_pov_runtime_lineage",
                        lambda *_args, **_kwargs: {"status": "VERIFIED"})
    monkeypatch.setattr(
        original_public_live, "_model_lineage_gate_verified_pov_ids",
        lambda _root, _lineage, rows: [rows[0]["pov_id"]])
    assert coordinator.consume([pov_id]) is False
    assert not coordinator.verified.is_set()
