"""Injected PoV generation retains inputs without using original Docker runners."""

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import mongomock
import pytest

from fuzzingbrain.core.models import SPStatus, SuspiciousPoint
from fuzzingbrain.core.utils import generate_id
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.agents.pov_agent import POVAgent
from fuzzingbrain.tools.pov import (
    _trace_pov_core, clear_pov_context, create_pov_impl, get_pov_context,
    set_pov_context, trace_pov_impl, verify_pov_impl,
)
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)


class _Povs:
    def __init__(self):
        self.rows = {}

    def save(self, pov):
        self.rows[pov.pov_id] = pov
        return True

    def find_by_id(self, pov_id):
        return self.rows.get(pov_id)


def _context(tmp_path, *, qualified):
    povs = _Povs()
    other_fuzzer = SimpleNamespace(fuzzer_name="other", binary_path="/fake/other")
    repos = SimpleNamespace(
        povs=povs,
        fuzzers=SimpleNamespace(find_by_task=lambda _: [other_fuzzer]),
    )
    manager = SimpleNamespace(add_pov_blob=Mock(side_effect=AssertionError(
        "unqualified SP Fuzzer corpus handoff")))
    set_pov_context(
        task_id="task", worker_id="qualified-pov-test", output_dir=tmp_path,
        repos=repos, fuzzer="main", suspicious_point_id="sp-1",
        fuzzer_path=tmp_path / "fake-fuzzer", docker_image="untrusted:latest",
        fuzzer_manager=manager, qualified_runtime_required=qualified,
    )
    return povs, manager


def test_qualified_pov_preserves_generated_inputs_without_running_target(tmp_path):
    povs, manager = _context(tmp_path, qualified=True)
    try:
        with patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)), \
             patch("fuzzingbrain.tools.pov._run_fuzzer_docker",
                   side_effect=AssertionError("legacy Docker launched")), \
             patch("fuzzingbrain.tools.pov._verify_blob_on_fuzzer",
                   side_effect=AssertionError("cross fuzzer launched")):
            result = create_pov_impl("def generate(n): return b'x'",
                                     worker_id="qualified-pov-test")
        assert result["success"] is True
        assert result["runtime_status"] == "PENDING_QUALIFIED_RUNTIME"
        assert result["verified"] == result["crashed"] == 0
        assert len(povs.rows) == 3
        assert {row.blob_path and Path(row.blob_path).read_bytes()
                for row in povs.rows.values()} == {b"one", b"two", b"three"}
        assert all(row.is_successful is False for row in povs.rows.values())
        assert all(row["runtime_status"] == "PENDING_QUALIFIED_RUNTIME"
                   for row in result["verify_details"])
        manager.add_pov_blob.assert_not_called()
    finally:
        clear_pov_context("qualified-pov-test")


def test_qualified_pov_verify_and_trace_cannot_reach_legacy_runners(tmp_path):
    povs, _ = _context(tmp_path, qualified=True)
    try:
        with patch("fuzzingbrain.tools.pov._run_fuzzer_docker",
                   side_effect=AssertionError("legacy Docker launched")), \
             patch("fuzzingbrain.tools.pov.run_gdb_trace",
                   side_effect=AssertionError("legacy GDB launched")), \
             patch("fuzzingbrain.tools.pov.run_coverage_fuzzer",
                   side_effect=AssertionError("legacy coverage launched")), \
             patch("fuzzingbrain.tools.pov._execute_generator_code",
                   side_effect=AssertionError("trace should wait for runtime")):
            for result in (
                verify_pov_impl("missing", worker_id="qualified-pov-test"),
                trace_pov_impl("def generate(n): return b'x'",
                               worker_id="qualified-pov-test"),
                _trace_pov_core("missing", worker_id="qualified-pov-test"),
            ):
                assert result["status"] == "PENDING_QUALIFIED_RUNTIME"
                assert result["success"] is result["crashed"] is False
        assert not povs.rows
        assert get_pov_context("qualified-pov-test")["qualified_runtime_required"] is True
    finally:
        clear_pov_context("qualified-pov-test")


def test_injected_pipeline_requires_qualified_runtime_and_skips_sp_fuzzer():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id="sp-1", function_name="target",
        to_dict=lambda: {"suspicious_point_id": "sp-1"},
    )
    repos.suspicious_points.claim_for_pov.side_effect = [point] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    manager = SimpleNamespace(
        start_sp_fuzzer=AsyncMock(return_value=True),
        stop_sp_fuzzer=AsyncMock(),
    )

    class _Client:
        last_agent_response_was_final = True

        async def close(self):
            pass

    pipeline = AgentPipeline(
        "task", repos, fuzzer="main", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
        llm_client_factory=lambda role, owner: _Client(),
    )
    pipeline._fuzzer_manager = manager
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as agent_type:
        agent = MagicMock()
        agent.stop_reason = None
        agent.generate_pov_async = AsyncMock(return_value=SimpleNamespace(
            success=False, pov_id=None))
        agent_type.return_value = agent
        asyncio.run(pipeline._run_pov_agent("pov_1"))

    kwargs = agent_type.call_args.kwargs
    assert kwargs["qualified_runtime_required"] is True
    assert kwargs["fuzzer_manager"] is None
    manager.start_sp_fuzzer.assert_not_awaited()
    manager.stop_sp_fuzzer.assert_not_awaited()


def test_generated_pov_bytes_keep_candidate_pending_and_nonclaimable(tmp_path):
    repos = RepositoryManager(mongomock.MongoClient().pov_pending)
    task_id = generate_id()
    sp_id = generate_id()
    sp = SuspiciousPoint(
        suspicious_point_id=sp_id, task_id=task_id, function_name="target",
        status=SPStatus.PENDING_POV.value, score=0.9,
        sources=[{"harness_name": "main", "sanitizer": "address"}],
    )
    assert repos.suspicious_points.save(sp)
    assert repos.suspicious_points.claim_for_pov(
        task_id, "pov_1", harness_name="main", sanitizer="address")
    set_pov_context(
        task_id=task_id, worker_id="qualified-pov-test", output_dir=tmp_path,
        repos=repos, fuzzer="main", sanitizer="address",
        suspicious_point_id=sp_id, qualified_runtime_required=True,
    )
    try:
        with patch("fuzzingbrain.tools.pov._execute_generator_code",
                   return_value=([b"one", b"two", b"three"], None)):
            generated = create_pov_impl(
                "def generate(n): return b'x'", worker_id="qualified-pov-test")
        assert generated["runtime_status"] == "PENDING_QUALIFIED_RUNTIME"
        assert repos.suspicious_points.preserve_pov_pending_runtime(
            sp_id, generated["pov_ids"], task_id=task_id,
            harness_name="main", sanitizer="address")
        retained = repos.suspicious_points.find_by_id(sp_id)
        assert retained.status == SPStatus.PENDING_QUALIFIED_RUNTIME.value
        assert retained.pending_pov_ids == generated["pov_ids"]
        assert retained.pov_id is None and retained.pov_success_by is None
        assert len(retained.pending_pov_artifacts) == 3
        for artifact in retained.pending_pov_artifacts:
            pov = repos.povs.find_by_id(artifact["pov_id"])
            blob = base64.b64decode(pov.blob, validate=True)
            assert pov.suspicious_point_id == sp_id
            assert pov.is_successful is False
            assert Path(artifact["blob_path"]).read_bytes() == blob
            assert artifact["blob_sha256"] == hashlib.sha256(blob).hexdigest()
        assert repos.suspicious_points.claim_for_pov(
            task_id, "pov_2", harness_name="main", sanitizer="address") is None
        assert not repos.suspicious_points.is_pipeline_complete(task_id)
        assert not repos.suspicious_points.is_pipeline_complete(
            task_id, "main", "address")
    finally:
        clear_pov_context("qualified-pov-test")


def test_injected_pipeline_does_not_complete_pending_pov_as_failure():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id="sp-id", function_name="target",
        to_dict=lambda: {"suspicious_point_id": "sp-id"},
    )
    repos.suspicious_points.claim_for_pov.side_effect = [point] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    repos.suspicious_points.preserve_pov_pending_runtime.return_value = True

    class _Client:
        last_agent_response_was_final = False

        async def close(self):
            pass

    pipeline = AgentPipeline(
        "task", repos, fuzzer="main", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
        llm_client_factory=lambda role, owner: _Client(),
    )
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as agent_type:
        agent = MagicMock()
        agent.stop_reason = None
        agent.generate_pov_async = AsyncMock(return_value=SimpleNamespace(
            success=False, crashed=False, pending_runtime=True,
            generated_pov_ids=["pov-1", "pov-2"], pov_id=""))
        agent_type.return_value = agent
        asyncio.run(pipeline._run_pov_agent("pov_1"))

    repos.suspicious_points.preserve_pov_pending_runtime.assert_called_once_with(
        "sp-id", ["pov-1", "pov-2"], task_id="task",
        harness_name="main", sanitizer="address")
    repos.suspicious_points.complete_pov.assert_not_called()
    repos.suspicious_points.release_claim.assert_not_called()
    assert pipeline.stats.pov_pending_runtime == 1
    assert pipeline.stats.pov_generated == pipeline.stats.pov_failed == 0


def test_pov_agent_stops_after_retaining_inputs_without_fake_success():
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
    pending_result = json.dumps({
        "success": True, "runtime_status": "PENDING_QUALIFIED_RUNTIME",
        "pov_ids": ["pov-1", "pov-2"], "verified": 0, "crashed": 0,
    })
    with patch.object(agent, "_get_tools", new=AsyncMock(return_value=[{
            "function": {"name": "create_pov"}}])), \
         patch.object(agent, "_execute_tool", new=AsyncMock(return_value=pending_result)), \
         patch.object(agent, "_log_conversation"):
        response = asyncio.run(agent._run_agent_loop(object(), "Find a PoV"))
    assert response == "PoV bytes retained; qualified Runtime is pending."
    assert agent.pov_runtime_pending is True
    assert agent.generated_pov_ids == ["pov-1", "pov-2"]
    assert agent.pov_success is False
    llm.acall_with_tools.assert_awaited_once()


def test_pipeline_does_not_report_complete_with_pending_qualified_runtime():
    pipeline = AgentPipeline(
        "task", MagicMock(), fuzzer="main", sanitizer="address",
        config=PipelineConfig(num_verify_agents=0, num_pov_agents=1),
        llm_client_factory=lambda role, owner: object(),
    )

    async def retain_one(_):
        pipeline.stats.pov_pending_runtime += 1

    pipeline._run_pov_agent = retain_one
    with pytest.raises(IncompleteInjectedAgent) as caught:
        asyncio.run(pipeline.run())
    assert caught.value.reason == "runtime_pending"
    assert caught.value.campaign_status == "INCOMPLETE_RUNTIME_PENDING"
    assert pipeline.stats.pov_generated == pipeline.stats.pov_failed == 0
