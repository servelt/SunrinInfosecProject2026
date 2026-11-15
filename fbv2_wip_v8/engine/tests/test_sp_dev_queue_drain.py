"""The signed SP development scope drains the original candidate queues."""

import asyncio
import hashlib
from types import SimpleNamespace

from bson import ObjectId
import pytest

from devtools.campaign_model_gate import CampaignModelGate
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


class _Collection:
    def __init__(self):
        self.rows = []
        self.error = None

    def find(self, query, projection):
        if self.error is not None:
            raise self.error
        assert isinstance(query["task_id"], ObjectId)
        assert projection == {"status": 1, "sources": 1}
        return list(self.rows)


def _strategy(tmp_path):
    gate = CampaignModelGate(
        tmp_path / "model-ledger.json", "provider-free-drain",
        physical_max=4, wall_seconds=10, create=True)
    collection = _Collection()
    strategy = object.__new__(POVFullscanStrategy)
    strategy.task_id = str(ObjectId())
    strategy.fuzzer = "fuzz-mdhtml"
    strategy.sanitizer = "address"
    strategy.llm_client_factory = object()
    strategy._development_auto_scope = None
    strategy._development_sp_queue_drain = True
    strategy.num_parallel_agents = 1
    strategy.executor = SimpleNamespace(
        _fuzzer_manager=SimpleNamespace(model_gate=gate))
    strategy.repos = SimpleNamespace(
        suspicious_points=SimpleNamespace(collection=collection))
    return strategy, collection


@pytest.mark.asyncio
async def test_dev_sp_candidate_drains_verifier_and_pov_before_next_function(tmp_path):
    strategy, collection = _strategy(tmp_path)
    events = []
    first_sp_done = asyncio.Event()
    pipeline_may_finish = asyncio.Event()

    async def analyze(*, func, **_kwargs):
        events.append(func.name)
        if func.name == "first":
            collection.rows.append({"status": "pending_verify"})
            first_sp_done.set()
        return {"success": True}

    async def original_pipeline():
        await first_sp_done.wait()
        collection.rows[0]["status"] = "verifying"
        events.append("verifier")
        await asyncio.sleep(0)
        collection.rows[0]["status"] = "pending_pov"
        events.append("pov_queued")
        await asyncio.sleep(0)
        collection.rows[0]["status"] = "generating_pov"
        await asyncio.sleep(0)
        collection.rows[0]["status"] = "pov_generated"
        events.append("pov_done")
        await pipeline_may_finish.wait()

    strategy._analyze_single_function_v2 = analyze
    pipeline = asyncio.create_task(original_pipeline())
    strategy._active_pipeline_task = pipeline
    try:
        await strategy._run_function_batch(
            [(SimpleNamespace(name="first"), "direction-1"),
             (SimpleNamespace(name="second"), "direction-1")],
            agent_log_dir=tmp_path)
        assert events == ["first", "verifier", "pov_queued", "pov_done", "second"]
    finally:
        pipeline_may_finish.set()
        await pipeline


@pytest.mark.asyncio
async def test_concurrent_queue_does_not_wait_for_candidate_before_next_function(
        tmp_path):
    strategy, collection = _strategy(tmp_path)
    strategy._development_sp_queue_drain = False
    strategy._development_sp_concurrent_queue = True
    strategy._development_sp_start_envelope = None
    strategy.num_parallel_agents = 1
    events = []

    async def analyze(*, func, **_kwargs):
        events.append(f"discover:{func.name}")
        if func.name == "first":
            collection.rows.append({"status": "pending_verify"})
        return {"success": True}

    strategy._analyze_single_function_v2 = analyze
    await strategy._run_function_batch(
        [(SimpleNamespace(name="first", function_id="function-1"),
          "direction-1"),
         (SimpleNamespace(name="second", function_id="function-2"),
          "direction-1")],
        agent_log_dir=tmp_path)

    assert events == ["discover:first", "discover:second"]
    assert collection.rows == [{"status": "pending_verify"}]


def test_concurrent_queue_rejects_downstream_reserve(tmp_path):
    strategy, _collection = _strategy(tmp_path)
    strategy._development_sp_queue_drain = False
    strategy._development_sp_concurrent_queue = True
    strategy._development_sp_start_envelope = {
        "minimum_calls": 1, "minimum_wall_seconds": 1}
    with pytest.raises(RuntimeError, match="cannot use a downstream reserve"):
        strategy._admit_next_development_sp(
            SimpleNamespace(name="first", function_id="function-1"),
            "direction-1")


@pytest.mark.asyncio
async def test_signed_start_envelope_stops_before_unfunded_next_sp(tmp_path):
    strategy, _collection = _strategy(tmp_path)
    gate = strategy.executor._fuzzer_manager.model_gate
    strategy._development_sp_start_envelope = {
        "minimum_calls": 4, "minimum_wall_seconds": 1}
    strategy._development_sp_scope = {
        "status": "PARTIAL_SEED_SCOPE", "function_outcomes": []}
    pipeline_may_finish = asyncio.Event()
    observed = []

    async def analyze(*, func, **_kwargs):
        observed.append(func.name)
        gate.reserve(request_id="first-turn", role="sp",
                     owner_id=func.function_id,
                     request_sha256=hashlib.sha256(b"first-turn").hexdigest())
        gate.finish("first-turn", completed=True)
        return {"success": True}

    async def original_pipeline():
        await pipeline_may_finish.wait()

    strategy._analyze_single_function_v2 = analyze
    pipeline = asyncio.create_task(original_pipeline())
    strategy._active_pipeline_task = pipeline
    try:
        await strategy._run_function_batch(
            [(SimpleNamespace(name="first", function_id="function-1"),
              "direction-1"),
             (SimpleNamespace(name="second", function_id="function-2"),
              "direction-1")],
            agent_log_dir=tmp_path)
        assert observed == ["first"]
        assert strategy._development_sp_scope["status"] == (
            "DOWNSTREAM_RESERVE_STOP")
        decisions = strategy._development_sp_scope[
            "sp_start_envelope_observations"]
        assert [row["admitted"] for row in decisions] == [True, False]
        assert decisions[1]["remaining_calls"] == 3
        assert gate.snapshot()["physical"] == 1
    finally:
        pipeline_may_finish.set()
        await pipeline


@pytest.mark.asyncio
async def test_graceful_stop_does_not_start_queued_function(tmp_path):
    strategy, _collection = _strategy(tmp_path)
    strategy._development_sp_queue_drain = False
    strategy._active_pipeline_task = None
    started = asyncio.Event()
    release = asyncio.Event()
    observed = []

    async def analyze(*, func, **_kwargs):
        observed.append(func.name)
        started.set()
        await release.wait()
        return {"success": True}

    strategy._analyze_single_function_v2 = analyze
    running = asyncio.create_task(strategy._run_function_batch(
        [(SimpleNamespace(name="active"), "direction-1"),
         (SimpleNamespace(name="queued"), "direction-1")],
        agent_log_dir=tmp_path))
    await started.wait()
    strategy.request_graceful_stop()
    release.set()
    await running
    assert observed == ["active"]


@pytest.mark.asyncio
async def test_sp_pretransport_stop_does_not_cancel_active_pipeline(tmp_path):
    strategy, _collection = _strategy(tmp_path)
    strategy._development_sp_queue_drain = False
    pipeline_release = asyncio.Event()

    async def active_pipeline():
        await pipeline_release.wait()

    pipeline_task = asyncio.create_task(active_pipeline())
    strategy._active_pipeline_task = pipeline_task

    async def stopped_analysis(**_kwargs):
        return {"success": False,
                "incomplete_reason": "user_stop_before_transport"}

    strategy._analyze_single_function_v2 = stopped_analysis
    try:
        await strategy._run_function_batch(
            [(SimpleNamespace(name="stopped"), "direction-1")],
            agent_log_dir=tmp_path)
        assert not pipeline_task.done()
        assert not pipeline_task.cancelled()
    finally:
        pipeline_release.set()
        await pipeline_task


@pytest.mark.asyncio
async def test_dev_sp_drain_stops_before_next_function_on_pipeline_error(tmp_path):
    strategy, collection = _strategy(tmp_path)
    events = []
    first_sp_done = asyncio.Event()

    async def analyze(*, func, **_kwargs):
        events.append(func.name)
        if func.name == "first":
            collection.rows.append({"status": "pending_verify"})
            first_sp_done.set()
        return {"success": True}

    async def original_pipeline():
        await first_sp_done.wait()
        raise RuntimeError("Verifier failed")

    strategy._analyze_single_function_v2 = analyze
    pipeline = asyncio.create_task(original_pipeline())
    strategy._active_pipeline_task = pipeline
    with pytest.raises(RuntimeError, match="Verifier failed"):
        await strategy._run_function_batch(
            [(SimpleNamespace(name="first"), "direction-1"),
             (SimpleNamespace(name="second"), "direction-1")],
            agent_log_dir=tmp_path)
    assert events == ["first"]


@pytest.mark.asyncio
async def test_dev_sp_drain_fails_closed_on_candidate_read_error(tmp_path):
    strategy, collection = _strategy(tmp_path)
    collection.error = RuntimeError("database unavailable")
    pipeline_may_finish = asyncio.Event()
    events = []

    async def analyze(*, func, **_kwargs):
        events.append(func.name)
        return {"success": True}

    async def original_pipeline():
        await pipeline_may_finish.wait()

    strategy._analyze_single_function_v2 = analyze
    pipeline = asyncio.create_task(original_pipeline())
    strategy._active_pipeline_task = pipeline
    try:
        with pytest.raises(IncompleteInjectedAgent) as error:
            await strategy._run_function_batch(
                [(SimpleNamespace(name="first"), "direction-1"),
                 (SimpleNamespace(name="second"), "direction-1")],
                agent_log_dir=tmp_path)
        assert error.value.reason == "candidate_state_read_failed"
        assert events == ["first"]
    finally:
        pipeline_may_finish.set()
        await pipeline


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["pending_budget", "incomplete_uncertain",
                                     "pending_qualified_runtime"])
async def test_dev_sp_drain_never_relabels_incomplete_candidate(tmp_path, status):
    strategy, collection = _strategy(tmp_path)
    pipeline_may_finish = asyncio.Event()
    events = []

    async def analyze(*, func, **_kwargs):
        events.append(func.name)
        collection.rows.append({"status": status})
        return {"success": True}

    async def original_pipeline():
        await pipeline_may_finish.wait()

    strategy._analyze_single_function_v2 = analyze
    pipeline = asyncio.create_task(original_pipeline())
    strategy._active_pipeline_task = pipeline
    try:
        with pytest.raises(IncompleteInjectedAgent) as error:
            await strategy._run_function_batch(
                [(SimpleNamespace(name="first"), "direction-1"),
                 (SimpleNamespace(name="second"), "direction-1")],
                agent_log_dir=tmp_path)
        assert error.value.reason == "candidate_queue_incomplete"
        assert collection.rows == [{"status": status}]
        assert events == ["first"]
    finally:
        pipeline_may_finish.set()
        await pipeline


@pytest.mark.asyncio
async def test_dev_sp_drain_keeps_gate_pending_without_stopping_other_sp(tmp_path):
    strategy, collection = _strategy(tmp_path)
    pipeline_may_finish = asyncio.Event()
    events = []

    async def analyze(*, func, **_kwargs):
        events.append(func.name)
        if func.name == "first":
            collection.rows.append({"status": "pending_independent_validation"})
        return {"success": True}

    async def original_pipeline():
        await pipeline_may_finish.wait()

    strategy._analyze_single_function_v2 = analyze
    pipeline = asyncio.create_task(original_pipeline())
    strategy._active_pipeline_task = pipeline
    try:
        await strategy._run_function_batch(
            [(SimpleNamespace(name="first"), "direction-1"),
             (SimpleNamespace(name="second"), "direction-1")],
            agent_log_dir=tmp_path)
        assert events == ["first", "second"]
        assert collection.rows == [{"status": "pending_independent_validation"}]
    finally:
        pipeline_may_finish.set()
        await pipeline


@pytest.mark.asyncio
async def test_dev_verifier_waits_for_its_pov_before_claiming_another_candidate():
    state = SimpleNamespace(status="pending_pov")
    pipeline = object.__new__(AgentPipeline)
    pipeline._shutdown = False
    pipeline.config = SimpleNamespace(poll_interval=0.001)
    pipeline.repos = SimpleNamespace(suspicious_points=SimpleNamespace(
        find_by_id=lambda sp_id: state if sp_id == "first" else None))

    waiting = asyncio.create_task(pipeline._wait_for_pov_after_verify("first"))
    await asyncio.sleep(0.01)
    assert not waiting.done()
    state.status = "generating_pov"
    await asyncio.sleep(0.01)
    assert not waiting.done()
    state.status = "failed"  # Qualified Runtime saw no crash.
    await waiting


@pytest.mark.asyncio
async def test_dev_verifier_never_treats_missing_pov_state_as_completed():
    pipeline = object.__new__(AgentPipeline)
    pipeline._shutdown = False
    pipeline.config = SimpleNamespace(poll_interval=0.001)
    pipeline.repos = SimpleNamespace(suspicious_points=SimpleNamespace(
        find_by_id=lambda _sp_id: None))
    with pytest.raises(IncompleteInjectedAgent) as error:
        await pipeline._wait_for_pov_after_verify("missing")
    assert error.value.reason == "candidate_state_read_failed"


@pytest.mark.asyncio
async def test_dev_verifier_never_advances_past_pending_qualified_runtime():
    pipeline = object.__new__(AgentPipeline)
    pipeline._shutdown = False
    pipeline.config = SimpleNamespace(poll_interval=0.001)
    pipeline.repos = SimpleNamespace(suspicious_points=SimpleNamespace(
        find_by_id=lambda _sp_id: SimpleNamespace(
            status="pending_qualified_runtime")))
    with pytest.raises(IncompleteInjectedAgent) as error:
        await pipeline._wait_for_pov_after_verify("pending")
    assert error.value.reason == "runtime_pending"


@pytest.mark.asyncio
async def test_dev_verifier_claims_second_candidate_only_after_first_pov(monkeypatch):
    events = []
    first_verified = asyncio.Event()
    second_verified = asyncio.Event()
    candidates = {}
    for sp_id in ("first", "second"):
        point = SimpleNamespace(
            suspicious_point_id=sp_id, status="pending_verify",
            is_checked=False, is_important=False, is_real=False,
            score=0.0, verification_notes="", function_name="fixture",
            verification_disposition=None,
            verification_claim_token=None)
        point.to_dict = lambda sp_id=sp_id: {"suspicious_point_id": sp_id}
        candidates[sp_id] = point

    def claim_for_verify(*_args, **_kwargs):
        for sp_id, point in candidates.items():
            if point.status == "pending_verify":
                point.status = "verifying"
                point.verification_claim_token = "claim-" + sp_id
                events.append("claim:" + sp_id)
                return point
        return None

    def complete_verify(sp_id, **kwargs):
        candidates[sp_id].status = (
            "pending_pov" if kwargs["proceed_to_pov"] else
            "reviewed_not_admitted")
        events.append("verified:" + sp_id)
        (first_verified if sp_id == "first" else second_verified).set()
        return True

    repo = SimpleNamespace(
        claim_for_verify=claim_for_verify,
        find_by_id=lambda sp_id: candidates.get(sp_id),
        complete_verify=complete_verify,
        count_by_status=lambda *_args, **_kwargs: sum(
            point.status == "pending_verify" for point in candidates.values()),
    )

    class Client:
        last_agent_response_was_final = True

        async def close(self):
            pass

    class Verifier:
        stop_reason = None

        def __init__(self, **_kwargs):
            pass

        def set_context(self, *, suspicious_point):
            self.sp_id = suspicious_point["suspicious_point_id"]

        async def run_async(self, **_kwargs):
            point = candidates[self.sp_id]
            point.is_checked = True
            point.is_important = True
            point.score = 0.8

    monkeypatch.setattr("fuzzingbrain.worker.pipeline.SPVerifier", Verifier)
    pipeline = AgentPipeline(
        task_id="fixture", repos=SimpleNamespace(suspicious_points=repo),
        fuzzer="fixture", sanitizer="address",
        config=PipelineConfig(poll_interval=0.001),
        llm_client_factory=lambda _role, _owner: Client(),
    )
    pipeline._sp_finding_done = True
    pipeline.prefer_pov_after_verify = True
    task = asyncio.create_task(pipeline._run_verify_agent("verify_1"))
    try:
        await asyncio.wait_for(first_verified.wait(), 1)
        await asyncio.sleep(0.01)
        assert events == ["claim:first", "verified:first"]
        candidates["first"].status = "failed"  # PoV finished without a crash.
        await asyncio.wait_for(second_verified.wait(), 1)
        assert events == ["claim:first", "verified:first",
                          "claim:second", "verified:second"]
        candidates["second"].status = "failed"
        await asyncio.wait_for(task, 1)
    finally:
        task.cancel()
