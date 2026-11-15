"""Qualified PoV Runtime callback keeps physical evidence separate from FBv2 success."""

import hashlib
import asyncio
import json
from pathlib import Path
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import mongomock
import pytest
from bson import ObjectId

from fuzzingbrain.core.models import SPStatus, SuspiciousPoint
from fuzzingbrain.core.utils import generate_id
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.agents.pov_agent import POVAgent
from fuzzingbrain.tools.pov import (
    clear_pov_context, create_pov_impl, set_pov_context, verify_pov_impl,
)
from fuzzingbrain.tools.qualified_runtime import (
    QualifiedRuntimeBinding, QualifiedRuntimeOutcome, QualifiedRuntimeRequest,
    validate_outcome,
)
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)


def test_gate_thread_settles_before_cancelled_waiter_returns():
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def consume(_ids):
        started.set()
        release.wait(2)
        finished.set()
        return False

    pipeline = AgentPipeline.__new__(AgentPipeline)
    pipeline.qualified_gate_stop = SimpleNamespace(consume=consume)

    async def run():
        task = asyncio.create_task(pipeline._consume_qualified_gate(["pov-1"]))
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()  # repeated Pipeline cancellation must not orphan thread
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert finished.is_set()


def test_secondary_cancellation_does_not_overwrite_first_failure_reason():
    pipeline = AgentPipeline.__new__(AgentPipeline)
    pipeline._incomplete_error = "Gate lineage failed"
    pipeline._incomplete_reason = "gate_lineage_unproven"
    pipeline._secondary_incomplete_events = []
    pipeline._record_injected_cancellation("PoV")
    assert pipeline._incomplete_error == "Gate lineage failed"
    assert pipeline._incomplete_reason == "gate_lineage_unproven"
    assert pipeline._secondary_incomplete_events == [{
        "stage": "PoV", "reason": "uncertain_remote",
        "error": "injected PoV turn was cancelled"}]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _setup(tmp_path, callback):
    repos = RepositoryManager(mongomock.MongoClient().qualified_callback)
    task_id, sp_id = generate_id(), generate_id()
    point = SuspiciousPoint(
        suspicious_point_id=sp_id, task_id=task_id, function_name="target",
        status=SPStatus.PENDING_POV.value, score=0.9,
        sources=[{"harness_name": "main", "sanitizer": "address"}],
    )
    # Staged pipeline fixture; production save() is creation-only.
    repos.suspicious_points.collection.insert_one(point.to_dict())
    claim = repos.suspicious_points.claim_for_pov(
        task_id, "pov_1", harness_name="main", sanitizer="address")
    assert claim
    repos._test_pov_claim = claim
    binary = tmp_path / "official-fuzzer"
    binary.write_bytes(b"pinned binary fixture")
    binding = QualifiedRuntimeBinding(qualification=object(), execute=callback)
    set_pov_context(
        task_id=task_id, worker_id="qualified-callback", output_dir=tmp_path,
        repos=repos, fuzzer="main", sanitizer="address",
        suspicious_point_id=sp_id, fuzzer_path=binary,
        qualified_runtime_required=True, qualified_runtime_binding=binding,
    )
    return repos, task_id, sp_id, binding, binary


def _outcome(request, tmp_path, status):
    runtime = tmp_path / f"{request.pov_id}-runtime.json"
    physical = tmp_path / f"{request.pov_id}-physical.json"
    runtime.write_text('{"exit": "observed"}')
    physical.write_text('{"physical": 1}')
    return QualifiedRuntimeOutcome(
        status=status, pov_id=request.pov_id,
        input_sha256=request.input_sha256,
        binary_sha256=request.binary_sha256,
        runtime_receipt_path=runtime, runtime_receipt_sha256=_sha(runtime),
        physical_receipt_path=physical, physical_receipt_sha256=_sha(physical),
        sanitizer="AddressSanitizer: heap-buffer-overflow"
        if status == "CRASH_OBSERVED" else None,
    )


def test_crash_observation_is_retained_for_gate_without_legacy_success(tmp_path):
    calls = []

    def callback(request):
        calls.append(request)
        return _outcome(request, tmp_path, "CRASH_OBSERVED")

    repos, task_id, sp_id, binding, binary = _setup(tmp_path, callback)
    try:
        with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                          return_value=(binary, _sha(binary))), \
             patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)), \
             patch("fuzzingbrain.tools.pov._run_fuzzer_docker",
                   side_effect=AssertionError("legacy Docker reached")), \
             patch("fuzzingbrain.tools.pov._verify_blob_on_fuzzer",
                   side_effect=AssertionError("cross fuzzer reached")):
            generated = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-callback")
            assert generated["runtime_status"] == "PENDING_INDEPENDENT_VALIDATION"
            assert generated["verified"] == generated["crashed"] == 0
            assert generated["runtime_crashes"] == 1
            assert len(calls) == 1
            assert [request.input_bytes for request in calls] == [b"one"]
            assert all(request.input_sha256 == hashlib.sha256(
                request.input_bytes).hexdigest() for request in calls)
            pov_id = generated["pov_ids"][0]
            again = verify_pov_impl(pov_id, worker_id="qualified-callback")
            assert again["validation_pending"] is True
            assert again["crashed"] is False
            assert len(calls) == 1  # Cached receipt never reruns the target.
            for later in generated["pov_ids"][1:]:
                assert repos.povs.find_by_id(later).is_successful is False
                assert "qualified_runtime" not in repos.povs.collection.find_one(
                    {"_id": ObjectId(later)})
            assert repos.suspicious_points.preserve_pov_pending_runtime(
                sp_id, generated["validation_pending_pov_ids"],
                task_id=task_id, harness_name="main", sanitizer="address",
                validation_pending=True, processor_id="pov_1",
                claim_token=repos._test_pov_claim.pov_claim_token)
            retained = repos.suspicious_points.find_by_id(sp_id)
            assert retained.status == SPStatus.PENDING_INDEPENDENT_VALIDATION.value
            assert not repos.suspicious_points.is_pipeline_complete(task_id)
    finally:
        clear_pov_context("qualified-callback")


def test_no_crash_is_feedback_and_receipt_tamper_is_incomplete(tmp_path):
    calls = []

    def callback(request):
        calls.append(request)
        return _outcome(request, tmp_path, "NO_CRASH")

    repos, _, _, _, binary = _setup(tmp_path, callback)
    try:
        with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                          return_value=(binary, _sha(binary))), \
             patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)):
            generated = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-callback")
            assert generated["runtime_status"] == "NO_CRASH"
            assert generated["runtime_crashes"] == 0
            assert len(calls) == 3
            pov_id = generated["pov_ids"][0]
            first = verify_pov_impl(pov_id, worker_id="qualified-callback")
            assert first["runtime_status"] == "NO_CRASH"
            assert len(calls) == 3
            receipt = Path(repos.povs.collection.find_one(
                {"_id": ObjectId(pov_id)})[
                    "qualified_runtime"]["runtime_receipt_path"])
            receipt.write_text("tampered")
            bad = verify_pov_impl(pov_id, worker_id="qualified-callback")
            assert bad["incomplete"] is True
            assert len(calls) == 3
    finally:
        clear_pov_context("qualified-callback")


def test_later_observed_crash_stops_before_third_target_call(tmp_path):
    calls = []

    def callback(request):
        calls.append(request)
        status = "NO_CRASH" if len(calls) == 1 else "CRASH_OBSERVED"
        return _outcome(request, tmp_path, status)

    repos, _, _, _, binary = _setup(tmp_path, callback)
    try:
        with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                          return_value=(binary, _sha(binary))), \
             patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)):
            generated = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-callback")
        assert [request.input_bytes for request in calls] == [b"one", b"two"]
        assert generated["runtime_status"] == "PENDING_INDEPENDENT_VALIDATION"
        assert generated["runtime_crashes"] == 1
        assert generated["validation_pending_pov_ids"] == [generated["pov_ids"][1]]
        assert "qualified_runtime" not in repos.povs.collection.find_one(
            {"_id": ObjectId(generated["pov_ids"][2])})
    finally:
        clear_pov_context("qualified-callback")


def test_callback_failure_is_not_retried_or_promoted(tmp_path):
    callback = Mock(side_effect=RuntimeError("remote state uncertain"))
    repos, _, _, _, binary = _setup(tmp_path, callback)
    try:
        with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                          return_value=(binary, _sha(binary))), \
             patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)):
            generated = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-callback")
            assert generated["runtime_status"] == "INCOMPLETE_QUALIFIED_RUNTIME"
            assert generated["verified"] == generated["crashed"] == 0
            pov_id = generated["pov_ids"][0]
            first = verify_pov_impl(pov_id, worker_id="qualified-callback")
            assert first["incomplete"] is True
            assert callback.call_count == 1
            for later in generated["pov_ids"][1:]:
                assert "qualified_runtime" not in repos.povs.collection.find_one(
                    {"_id": ObjectId(later)})
            assert repos.povs.find_by_id(pov_id).is_successful is False
    finally:
        clear_pov_context("qualified-callback")


def test_unissued_qualification_fails_before_callback(tmp_path):
    callback = Mock()
    _, _, _, _, _ = _setup(tmp_path, callback)
    try:
        with patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)):
            generated = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-callback")
            assert generated["runtime_status"] == "INCOMPLETE_QUALIFIED_RUNTIME"
            callback.assert_not_called()
    finally:
        clear_pov_context("qualified-callback")


def test_mismatched_outcome_and_sanitizer_claims_fail_closed(tmp_path):
    def callback(request):
        outcome = _outcome(request, tmp_path, "CRASH_OBSERVED")
        return QualifiedRuntimeOutcome(
            **{**outcome.__dict__, "input_sha256": "0" * 64})

    _, _, _, _, binary = _setup(tmp_path, callback)
    try:
        with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                          return_value=(binary, _sha(binary))), \
             patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)):
            result = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-callback")
            assert result["runtime_status"] == "INCOMPLETE_QUALIFIED_RUNTIME"
            assert result["runtime_crashes"] == result["crashed"] == 0
    finally:
        clear_pov_context("qualified-callback")


def test_status_sanitizer_contradictions_are_rejected(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(b"binary")
    request = QualifiedRuntimeRequest(
        task_id="task", suspicious_point_id="sp", pov_id="pov",
        harness_name="main", sanitizer="address", input_bytes=b"input",
        input_sha256=hashlib.sha256(b"input").hexdigest(),
        binary_path=binary, binary_sha256=_sha(binary),
    )
    crash = _outcome(request, tmp_path, "CRASH_OBSERVED")
    no_crash = _outcome(request, tmp_path, "NO_CRASH")
    from dataclasses import replace
    with pytest.raises(ValueError):
        validate_outcome(replace(crash, sanitizer=None), request)
    with pytest.raises(ValueError):
        validate_outcome(replace(no_crash, sanitizer="AddressSanitizer"), request)


def test_agent_and_pipeline_keep_observed_crash_pending_gate():
    llm = MagicMock()
    llm.config.default_model.id = "fake"
    llm.acall_with_tools = AsyncMock(return_value=SimpleNamespace(
        content="", input_tokens=1,
        tool_calls=[{"id": "tool-1", "function": {
            "name": "create_pov", "arguments": "{}"}}],
    ))
    agent = POVAgent(
        llm_client=llm, model="fake", max_iterations=3,
        qualified_runtime_required=True,
    )
    observed = json.dumps({
        "success": True, "runtime_status": "PENDING_INDEPENDENT_VALIDATION",
        "pov_ids": ["pov-1", "pov-2"],
        "validation_pending_pov_ids": ["pov-1"],
        "verified": 0, "crashed": 0, "runtime_crashes": 1,
    })
    with patch.object(agent, "_get_tools", new=AsyncMock(return_value=[{
            "function": {"name": "create_pov"}}])), \
         patch.object(agent, "_execute_tool", new=AsyncMock(return_value=observed)), \
         patch.object(agent, "_log_conversation"):
        response = asyncio.run(agent._run_agent_loop(object(), "Find a PoV"))
    assert response == "Runtime crash observed; independent validation pending."
    assert agent.pov_validation_pending is True
    assert agent.pov_success is False
    assert agent.generated_pov_ids == ["pov-1"]

    pipeline = AgentPipeline(
        "task", MagicMock(), fuzzer="main", sanitizer="address",
        config=PipelineConfig(num_verify_agents=0, num_pov_agents=1),
        llm_client_factory=lambda role, owner: object(),
    )

    async def retain_one(_):
        pipeline.stats.pov_pending_validation += 1

    pipeline._run_pov_agent = retain_one
    try:
        asyncio.run(pipeline.run())
    except IncompleteInjectedAgent as exc:
        assert exc.reason == "validation_pending"
        assert exc.campaign_status == "INCOMPLETE_VALIDATION_PENDING"
    else:
        raise AssertionError("observed crash was treated as a complete pipeline")


def test_pipeline_persists_gate_pending_state_without_completing_pov():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id="sp-id", function_name="target",
        pov_claim_token="claim-token",
        to_dict=lambda: {"suspicious_point_id": "sp-id"},
    )
    repos.suspicious_points.claim_for_pov.side_effect = [point] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    repos.suspicious_points.preserve_pov_pending_runtime.return_value = True
    import threading
    verified_stop = threading.Event()

    def consume_after_persist(ids):
        assert ids == ["pov-1"]
        repos.suspicious_points.preserve_pov_pending_runtime.assert_called_once()
        verified_stop.set()

    gate_stop = SimpleNamespace(verified=verified_stop,
                                consume=Mock(side_effect=consume_after_persist))

    class _Client:
        last_agent_response_was_final = False

        async def close(self):
            pass

    pipeline = AgentPipeline(
        "task", repos, fuzzer="main", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
        llm_client_factory=lambda role, owner: _Client(),
        qualified_gate_stop=gate_stop,
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as agent_type:
        agent = MagicMock()
        agent.stop_reason = None
        agent.generate_pov_async = AsyncMock(return_value=SimpleNamespace(
            success=False, crashed=False, pending_runtime=False,
            pending_validation=True, generated_pov_ids=["pov-1"], pov_id=""))
        agent_type.return_value = agent
        asyncio.run(pipeline._run_pov_agent("pov_1"))

    repos.suspicious_points.preserve_pov_pending_runtime.assert_called_once_with(
        "sp-id", ["pov-1"], task_id="task", harness_name="main",
        sanitizer="address", processor_id="pov_1",
        claim_token="claim-token", validation_pending=True)
    repos.suspicious_points.complete_pov.assert_not_called()
    gate_stop.consume.assert_called_once_with(["pov-1"])
    assert verified_stop.is_set()
    assert pipeline.stats.pov_pending_validation == 1
    assert pipeline.stats.pov_generated == pipeline.stats.pov_failed == 0


def test_gate_consumption_error_keeps_retained_crash_candidate_sealed():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id="sp-id", function_name="target",
        pov_claim_token="claim-token",
        to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_pov.return_value = point
    repos.suspicious_points.preserve_pov_pending_runtime.return_value = True

    class _Client:
        last_agent_response_was_final = False

        async def close(self):
            pass

    gate_stop = SimpleNamespace(
        verified=__import__("threading").Event(),
        consume=Mock(side_effect=RuntimeError("Gate replay failed")))
    pipeline = AgentPipeline(
        "task", repos, fuzzer="main", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
        llm_client_factory=lambda role, owner: _Client(),
        qualified_gate_stop=gate_stop)
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as agent_type:
        agent = MagicMock()
        agent.stop_reason = None
        agent.generate_pov_async = AsyncMock(return_value=SimpleNamespace(
            success=False, crashed=False, pending_runtime=False,
            pending_validation=True, generated_pov_ids=["pov-1"], pov_id=""))
        agent_type.return_value = agent
        with pytest.raises(IncompleteInjectedAgent) as exc:
            asyncio.run(pipeline._run_pov_agent("pov_1"))
    assert exc.value.reason == "gate_consumption_failed"
    repos.suspicious_points.preserve_pov_pending_runtime.assert_called_once()
    repos.suspicious_points.preserve_incomplete_candidate.assert_not_called()
    repos.suspicious_points.release_claim.assert_not_called()
