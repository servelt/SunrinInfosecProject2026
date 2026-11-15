"""Provider-free checks for the opt-in original Fullscan model-client seam."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig, injected_agent_client,
)
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


class FakeClient:
    def __init__(self, *, close_error=None):
        self.closed = 0
        self.close_error = close_error
        self.last_agent_response_was_final = True

    async def close(self):
        self.closed += 1
        if self.close_error:
            raise self.close_error


class RecordingFactory:
    def __init__(self):
        self.created = []

    def __call__(self, role, owner_id):
        client = FakeClient()
        self.created.append((role, owner_id, client))
        return client


def make_strategy(factory):
    repos = MagicMock()
    executor = SimpleNamespace(
        workspace_path=Path("/tmp/fbv2-worker"),
        task_workspace_path=Path("/tmp/fbv2-task"),
        project_name="fixture", fuzzer="fixture_fuzzer",
        sanitizer="address", task_id="task", worker_id="worker",
        repos=repos, log_dir=Path("/tmp/fbv2-logs"),
        results_path=Path("/tmp/fbv2-results"),
        crashes_path=Path("/tmp/fbv2-crashes"),
        povs_path=Path("/tmp/fbv2-povs"),
        patches_path=Path("/tmp/fbv2-patches"),
        analysis_socket_path=None, fuzzer_manager=None,
        fuzzer_binary_path=None,
    )
    with patch.object(POVFullscanStrategy, "_setup_tool_contexts"):
        strategy = POVFullscanStrategy(executor, llm_client_factory=factory)
    return strategy, repos


def test_injected_client_close_failure_preserves_agent_error():
    client = FakeClient(close_error=RuntimeError("close failed"))

    async def run():
        async with injected_agent_client(lambda role, owner: client,
                                         "direction", "worker"):
            raise ValueError("original agent error")

    try:
        asyncio.run(run())
    except ValueError as exc:
        assert str(exc) == "original agent error"
        assert "injected client close failed" in " ".join(exc.__notes__)
    else:
        raise AssertionError("original agent error was masked")
    assert client.closed == 1


def test_original_direction_agent_receives_owned_client():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    stored = SimpleNamespace(direction_id="new-direction-id")
    repos.directions.find_pending.return_value = [stored]
    strategy._get_fuzzer_source_code = lambda: "int LLVMFuzzerTestOneInput() {}"
    strategy._get_reachable_function_count = lambda: 2

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(
            return_value={"directions_created": 1,
                          "direction_ids": ["new-direction-id"]})
        cls.return_value.stop_reason = None
        result = asyncio.run(strategy._run_direction_planning_async())

    assert result == [stored]
    assert cls.call_args.kwargs["llm_client"] is factory.created[0][2]
    assert factory.created[0][:2] == ("direction", "worker")
    assert factory.created[0][2].closed == 1


def test_direction_plan_does_not_reuse_an_older_pending_direction():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    stale = SimpleNamespace(direction_id="older-direction-id")
    repos.directions.find_pending.return_value = [stale]
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 2

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(return_value={
            "success": True, "directions_created": 0, "direction_ids": [],
        })
        cls.return_value.stop_reason = None
        assert asyncio.run(strategy._run_direction_planning_async()) == []

    assert factory.created[0][2].closed == 1


def test_direction_plan_only_uses_ids_created_by_this_agent_call():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    stale = SimpleNamespace(direction_id="older-direction-id")
    fresh = SimpleNamespace(direction_id="new-direction-id")
    repos.directions.find_pending.return_value = [stale, fresh]
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 2

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(return_value={
            "success": True, "directions_created": 1,
            "direction_ids": ["new-direction-id"],
        })
        cls.return_value.stop_reason = None
        assert asyncio.run(strategy._run_direction_planning_async()) == [fresh]

    assert factory.created[0][2].closed == 1


def test_failed_verifier_pipeline_prevents_next_sp_phase():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    direction = SimpleNamespace(
        direction_id="direction-id", name="feature", risk_level="high",
        core_functions=["target"], entry_functions=[])
    function = SimpleNamespace(name="target")
    strategy._build_direction_pools = lambda _: [(
        direction, {"small/new": [function], "big/new": [function]})]
    batches = []

    async def one_batch(**kwargs):
        batches.append(kwargs["work"])
        await asyncio.sleep(0)

    class FailedPipeline:
        def __init__(self, **kwargs):
            self._sp_finding_done = False

        async def run(self):
            raise RuntimeError("verifier failed")

        def shutdown(self):
            pass

    strategy._run_function_batch = one_batch
    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", FailedPipeline):
        with pytest.raises(RuntimeError, match="verifier failed"):
            asyncio.run(strategy._run_v2_pipeline([direction]))
    assert len(batches) == 1


def test_partial_seed_agent_failure_does_not_start_global_fuzzer():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    strategy.executor.fuzzer_manager = manager
    directions = [SimpleNamespace(
        direction_id=name, name=name, risk_level="high",
        risk_reason="fixture", core_functions=["target"])
        for name in ("A", "B")]

    def seed_agent(**kwargs):
        agent = MagicMock()
        if kwargs["target_name"] == "B":
            agent.stop_reason = "llm_error"
            agent.generate_direction_seeds = AsyncMock(return_value={
                "success": True, "seeds_generated": 0})
        else:
            agent.stop_reason = None
            agent.generate_direction_seeds = AsyncMock(return_value={
                "success": True, "seeds_generated": 1})
        return agent

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent",
               side_effect=seed_agent):
        with pytest.raises(RuntimeError, match="Seed phase is incomplete"):
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                directions))
    manager.start_global_fuzzer.assert_not_awaited()


def test_failed_seed_tool_is_not_a_completed_zero_seed_phase():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    strategy.executor.fuzzer_manager = manager
    direction = SimpleNamespace(
        direction_id="direction-id", name="feature", risk_level="high",
        risk_reason="fixture", core_functions=["target"])

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent") as cls:
        cls.return_value.generate_direction_seeds = AsyncMock(return_value={
            "success": True, "seeds_generated": 0, "seed_tool_failures": 1,
        })
        cls.return_value.stop_reason = None
        with pytest.raises(RuntimeError, match="Seed phase is incomplete"):
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction]))
    manager.start_global_fuzzer.assert_not_awaited()


def test_seed_sandbox_cleanup_failure_blocks_global_even_after_earlier_seed():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    strategy.executor.fuzzer_manager = manager
    direction = SimpleNamespace(
        direction_id="direction-id", name="feature", risk_level="high",
        risk_reason="fixture", core_functions=["target"])

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent") as cls:
        cls.return_value.generate_direction_seeds = AsyncMock(return_value={
            "success": True, "seeds_generated": 1,
            "fatal_seed_cleanup": True,
        })
        cls.return_value.stop_reason = None
        with pytest.raises(RuntimeError, match="Seed phase is incomplete"):
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction]))
    manager.start_global_fuzzer.assert_not_awaited()


def test_injected_global_start_failure_is_not_a_completed_seed_phase():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=False)
    strategy.executor.fuzzer_manager = manager
    direction = SimpleNamespace(
        direction_id="direction-id", name="feature", risk_level="high",
        risk_reason="fixture", core_functions=["target"])

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent") as cls:
        cls.return_value.generate_direction_seeds = AsyncMock(return_value={
            "success": True, "seeds_generated": 1,
        })
        cls.return_value.stop_reason = None
        with pytest.raises(RuntimeError, match="Global Fuzzer did not start"):
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction]))
    manager.start_global_fuzzer.assert_awaited_once()


def test_original_sp_and_seed_agents_get_distinct_owned_clients():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    repos.callgraph_nodes.find_callers.return_value = []
    repos.callgraph_nodes.find_callees.return_value = []
    strategy._get_fuzzer_source_code = lambda: "/* harness */"
    func = SimpleNamespace(
        name="target", function_id="function-id", content="int target() {}",
        file_path="target.c", start_line=1, end_line=1)

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator") as small, \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.LargeFullSPGenerator") as large, \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent") as seed:
        large.LARGE_FUNCTION_THRESHOLD = 3
        small.return_value.analyze_async = AsyncMock(return_value={"sp_created": False})
        large.return_value.analyze_async = AsyncMock(return_value={"sp_created": False})
        seed.return_value.generate_direction_seeds = AsyncMock(
            return_value={"success": False, "seeds_generated": 0})
        small.return_value.stop_reason = None
        large.return_value.stop_reason = None
        seed.return_value.stop_reason = None

        async def run():
            await strategy._analyze_single_function_v2(func, 0, 2, None, "direction-id")
            func.content = "line\n" * 5
            await strategy._analyze_single_function_v2(func, 1, 2, None, "direction-id")
            # A Manager must exist for original SeedAgent creation.
            strategy.executor.fuzzer_manager = MagicMock()
            direction = SimpleNamespace(
                direction_id="direction-id", name="feature", risk_level="high",
                risk_reason="fixture", core_functions=["target"])
            await strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction])

        asyncio.run(run())

        assert small.call_args.kwargs["llm_client"] is factory.created[0][2]
        assert large.call_args.kwargs["llm_client"] is factory.created[1][2]
        assert seed.call_args.kwargs["llm_client"] is factory.created[2][2]

    assert [row[0] for row in factory.created] == ["sp", "sp_large", "seed"]
    assert len({id(row[2]) for row in factory.created}) == 3
    assert all(row[2].closed == 1 for row in factory.created)


def test_original_verify_and_pov_agents_get_distinct_owned_clients():
    factory = RecordingFactory()
    repos = MagicMock()
    sp = SimpleNamespace(suspicious_point_id="sp-id", function_name="target",
                         to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_verify.side_effect = [sp] + [None] * 6
    repos.suspicious_points.claim_for_pov.side_effect = [sp] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    repos.suspicious_points.find_by_id.return_value = SimpleNamespace(
        is_checked=True, is_important=False, is_real=False,
        score=0.1, verification_notes="fixture")
    pipeline = AgentPipeline(
        "task", repos, fuzzer="fixture_fuzzer", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
        llm_client_factory=factory,
    )
    pipeline._sp_finding_done = True

    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier, \
         patch("fuzzingbrain.worker.pipeline.POVAgent") as pov:
        verifier.return_value.run_async = AsyncMock(return_value="done")
        pov.return_value.generate_pov_async = AsyncMock(
            return_value=SimpleNamespace(success=False, pov_id=None))
        verifier.return_value.stop_reason = None
        pov.return_value.stop_reason = None

        async def run():
            await pipeline._run_verify_agent("verify_1")
            await pipeline._run_pov_agent("pov_1")

        asyncio.run(run())
        assert verifier.call_args.kwargs["llm_client"] is factory.created[0][2]
        assert pov.call_args.kwargs["llm_client"] is factory.created[1][2]

    assert [row[0] for row in factory.created] == ["verifier", "pov"]
    assert len({id(row[2]) for row in factory.created}) == 2
    assert all(row[2].closed == 1 for row in factory.created)


def test_partial_direction_after_model_error_does_not_enter_fullscan():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    repos.directions.find_pending.return_value = ["partially-stored-direction"]
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 2

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(return_value={
            "success": True, "response": "Agent failed: budget",
            "directions_created": 1,
        })
        # A context-compression response could have been final immediately
        # before the budget error, so the Agent stop reason must also count.
        cls.return_value.stop_reason = "llm_error"
        with pytest.raises(IncompleteInjectedAgent) as interrupted:
            asyncio.run(strategy._run_direction_planning_async())
        assert interrupted.value.campaign_status == "INCOMPLETE_UNCERTAIN"

    repos.directions.find_pending.assert_not_called()
    assert factory.created[0][2].closed == 1


def test_sp_budget_error_never_marks_function_analyzed():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    repos.callgraph_nodes.find_callers.return_value = []
    repos.callgraph_nodes.find_callees.return_value = []
    func = SimpleNamespace(
        name="target", function_id="function-id", content="int target() {}",
        file_path="target.c", start_line=1, end_line=1)
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator") as cls:
        cls.return_value.analyze_async = AsyncMock(return_value={
            "success": True, "sp_created": False,
            "response": "Agent failed: budget",
        })
        cls.return_value.stop_reason = "llm_error"
        result = asyncio.run(strategy._analyze_single_function_v2(
            func, 0, 1, None, "direction-id"))

    assert result["success"] is False
    repos.functions.mark_analyzed_by_direction.assert_not_called()
    assert factory.created[0][2].closed == 1


def test_unchecked_verifier_candidate_is_preserved_without_pov_pass_through():
    factory = RecordingFactory()
    repos = MagicMock()
    sp = SimpleNamespace(suspicious_point_id="sp-id", function_name="target",
                         to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_verify.side_effect = [sp] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    repos.suspicious_points.find_by_id.return_value = SimpleNamespace(
        is_checked=False, is_important=False, is_real=False,
        score=0.9, verification_notes="")
    pipeline = AgentPipeline(
        "task", repos, fuzzer="fixture_fuzzer", sanitizer="address",
        config=PipelineConfig(poll_interval=0), llm_client_factory=factory)
    pipeline._sp_finding_done = True

    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(return_value="done")
        verifier.return_value.stop_reason = None
        asyncio.run(pipeline._run_verify_agent("verify_1"))

    repos.suspicious_points.complete_verify.assert_not_called()
    repos.suspicious_points.release_claim.assert_called_once_with(
        "sp-id", "failed")
    assert pipeline.stats.sp_verified == 0


def test_incomplete_pov_cannot_be_recorded_as_success_or_retried():
    factory = RecordingFactory()
    repos = MagicMock()
    sp = SimpleNamespace(suspicious_point_id="sp-id", function_name="target",
                         to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_pov.side_effect = [sp]
    pipeline = AgentPipeline(
        "task", repos, fuzzer="fixture_fuzzer", sanitizer="address",
        config=PipelineConfig(poll_interval=0), llm_client_factory=factory)

    with patch("fuzzingbrain.worker.pipeline.POVAgent") as pov:
        pov.return_value.generate_pov_async = AsyncMock(return_value=
            SimpleNamespace(success=True, pov_id="untrusted-id"))
        pov.return_value.stop_reason = "llm_error"
        asyncio.run(pipeline._run_pov_agent("pov_1"))

    repos.suspicious_points.complete_pov.assert_not_called()
    repos.suspicious_points.release_claim.assert_not_called()
    repos.suspicious_points.update.assert_called_once_with(
        "sp-id", {
            "status": "incomplete_uncertain", "processor_id": None,
            "pipeline_incomplete_reason": "llm_error",
            "pipeline_incomplete_stage": "pov",
        })
    assert pipeline._incomplete_error is not None
    assert repos.suspicious_points.claim_for_pov.call_count == 1


def test_seed_budget_error_does_not_start_global_fuzzer():
    factory = RecordingFactory()
    strategy, _ = make_strategy(factory)
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    strategy.executor.fuzzer_manager = manager
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    direction = SimpleNamespace(
        direction_id="direction-id", name="feature", risk_level="high",
        risk_reason="fixture", core_functions=["target"])

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent") as cls:
        cls.return_value.generate_direction_seeds = AsyncMock(return_value={
            "success": True, "seeds_generated": 1,
        })
        cls.return_value.stop_reason = "llm_error"
        with pytest.raises(RuntimeError, match="Seed phase is incomplete"):
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction]))

    manager.start_global_fuzzer.assert_not_called()
    assert factory.created[0][2].closed == 1


def test_seed_budget_refusal_remains_pending_budget_at_campaign_boundary():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    strategy.executor.fuzzer_manager = manager
    direction = SimpleNamespace(
        direction_id="direction-id", name="feature", risk_level="high",
        risk_reason="fixture", core_functions=["target"])

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent") as cls:
        cls.return_value.generate_direction_seeds = AsyncMock(return_value={
            "success": False, "seeds_generated": 0,
        })
        cls.return_value.stop_reason = "budget_before_transport"
        with pytest.raises(IncompleteInjectedAgent) as interrupted:
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction]))
    assert interrupted.value.reason == "budget_before_transport"
    assert interrupted.value.campaign_status == "INCOMPLETE_BUDGET"
    manager.start_global_fuzzer.assert_not_awaited()


def test_injected_batch_stops_after_first_incomplete_function():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    strategy.num_parallel_agents = 1
    first = SimpleNamespace(name="first")
    second = SimpleNamespace(name="second")
    entered = []

    async def analyze(*, func, **kwargs):
        entered.append(func.name)
        if func is first:
            return {"success": False, "error": "budget exhausted"}
        return {"success": True}

    strategy._analyze_single_function_v2 = analyze

    async def run():
        await strategy._run_function_batch(
            [(first, "direction-id"), (second, "direction-id")], None)

    try:
        asyncio.run(run())
    except RuntimeError as exc:
        assert "incomplete function" in str(exc)
    else:
        raise AssertionError("injected batch silently accepted failed SP")

    assert entered == ["first"]
    repos.functions.mark_analyzed_by_direction.assert_not_called()
