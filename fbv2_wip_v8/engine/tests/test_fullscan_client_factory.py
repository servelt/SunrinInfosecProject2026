"""Provider-free checks for the opt-in original Fullscan model-client seam."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from fuzzingbrain.fuzzer.seed_sandbox import MAX_SEED_BYTES

from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig, injected_agent_client,
)
from fuzzingbrain.worker.strategies.pov_fullscan import (
    POVFullscanStrategy, _ContextInsufficientSPAnalysis,
    _VerifiedBoundedSPExhaustion,
    line_scaled_sp_iteration_limit,
)
from devtools.original_public_live import FULL_NOHINT_SP_ITERATION_POLICY


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


def test_fullscan_sp_iteration_ceiling_scales_with_function_lines():
    policy = FULL_NOHINT_SP_ITERATION_POLICY
    assert line_scaled_sp_iteration_limit(80, policy) == 8
    assert line_scaled_sp_iteration_limit(200, policy) == 12
    assert line_scaled_sp_iteration_limit(416, policy) == 24
    assert line_scaled_sp_iteration_limit(800, policy) == 32
    assert line_scaled_sp_iteration_limit(1500, policy) == 40
    assert line_scaled_sp_iteration_limit(2001, policy) == 58
    assert line_scaled_sp_iteration_limit(10000, policy) == 64


def test_fullscan_passes_the_416_line_ceiling_to_the_sp_agent():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    strategy._full_nohint_sp = True
    strategy._development_sp_scope = {
        "status": "FULL_FUNCTION_POOL", "function_outcomes": [],
        "sp_iteration_policy": dict(FULL_NOHINT_SP_ITERATION_POLICY),
    }
    repos.callgraph_nodes.find_callers.return_value = []
    repos.callgraph_nodes.find_callees.return_value = []
    repos.functions.mark_analyzed_by_direction.return_value = True
    function = SimpleNamespace(
        name="large_small_function", function_id="function-416",
        content="\n".join("int value_%d = %d;" % (i, i) for i in range(416)),
        file_path="target.c", start_line=1, end_line=416)
    agent = SimpleNamespace(
        analyze_async=AsyncMock(return_value={"success": True, "sp_created": False}),
        stop_reason=None, sp_created=False)
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator",
               return_value=agent) as generator:
        result = asyncio.run(strategy._analyze_single_function_v2(
            function, 0, 1, None, "direction"))
    assert result["success"] is True
    assert generator.call_args.kwargs["max_iterations"] == 24


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
        qualified_seed_generator=lambda **kwargs: None,
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


def test_settled_campaign_turn_yields_to_waiting_owner():
    factory = RecordingFactory()
    factory._fbv2_campaign_invocation_lock = asyncio.Lock()
    factory._fbv2_campaign_gate = SimpleNamespace(snapshot=lambda: {
        "records": [{"status": "COMPLETED", "tool_events": [
            {"status": "COMPLETED"}]}]})
    order = []

    async def first():
        async with injected_agent_client(factory, "sp", "first") as client:
            order.append("first:model-and-tools")
            second_task = asyncio.create_task(second())
            await asyncio.sleep(0)
            await client._fbv2_yield_campaign_turn()
            order.append("first:next-turn")
            await second_task

    async def second():
        async with injected_agent_client(factory, "pov", "second"):
            order.append("second:model-and-tools")

    asyncio.run(first())
    assert order == ["first:model-and-tools", "second:model-and-tools",
                     "first:next-turn"]
    assert all(client.closed == 1 for _, _, client in factory.created)


def test_unsettled_host_tool_cannot_yield_campaign_turn():
    factory = RecordingFactory()
    factory._fbv2_campaign_invocation_lock = asyncio.Lock()
    factory._fbv2_campaign_gate = SimpleNamespace(snapshot=lambda: {
        "records": [{"status": "COMPLETED", "tool_events": [
            {"status": "STARTED"}]}]})

    async def run():
        async with injected_agent_client(factory, "sp", "first") as client:
            with pytest.raises(RuntimeError, match="not fully settled"):
                await client._fbv2_yield_campaign_turn()
            assert factory._fbv2_campaign_invocation_lock.locked()

    asyncio.run(run())
    assert not factory._fbv2_campaign_invocation_lock.locked()


def test_cancelled_turn_waiter_never_releases_another_owners_lock():
    factory = RecordingFactory()
    factory._fbv2_campaign_invocation_lock = asyncio.Lock()
    factory._fbv2_campaign_gate = SimpleNamespace(snapshot=lambda: {
        "records": [{"status": "COMPLETED", "tool_events": []}]})

    async def run():
        first_entered = asyncio.Event()
        second_entered = asyncio.Event()
        release_second = asyncio.Event()

        async def second():
            async with injected_agent_client(factory, "pov", "second"):
                second_entered.set()
                await release_second.wait()

        async def first_with_yield():
            async with injected_agent_client(factory, "sp", "first") as client:
                first_entered.set()
                await asyncio.sleep(0)
                await client._fbv2_yield_campaign_turn()

        first_task = asyncio.create_task(first_with_yield())
        await first_entered.wait()
        second_task = asyncio.create_task(second())
        await second_entered.wait()
        first_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_task
        assert factory._fbv2_campaign_invocation_lock.locked()
        release_second.set()
        await second_task
        assert not factory._fbv2_campaign_invocation_lock.locked()

    asyncio.run(run())


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


def test_direction_plan_accepts_five_tool_writes_before_local_budget_denial():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    ids = [f"direction-{index}" for index in range(5)]
    stored = [SimpleNamespace(direction_id=value) for value in ids]
    repos.directions.find_pending.return_value = stored
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 162

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(return_value={
            "success": True, "directions_created": 5,
            "direction_ids": ids,
        })
        cls.return_value.max_directions = 5
        cls.return_value.stop_reason = "budget_before_transport"
        factory.created.clear()
        result = asyncio.run(strategy._run_direction_planning_async())

    assert result == stored
    assert factory.created[0][2].closed == 1


def test_bounded_direction_plan_accepts_required_breadth_before_budget_denial():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    strategy._development_auto_scope = {
        "seed_directions": 2, "sp_functions": 3, "sp_max_iterations": 7}
    ids = [f"direction-{index}" for index in range(3)]
    stored = [SimpleNamespace(direction_id=value) for value in ids]
    repos.directions.find_pending.return_value = stored
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 162

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(return_value={
            "success": True, "directions_created": 3,
            "direction_ids": ids,
        })
        cls.return_value.max_directions = 5
        cls.return_value.stop_reason = "budget_before_transport"
        result = asyncio.run(strategy._run_direction_planning_async())

    assert result == stored
    assert factory.created[0][2].closed == 1


def test_bounded_direction_plan_rejects_insufficient_breadth_before_budget_denial():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    strategy._development_auto_scope = {
        "seed_directions": 2, "sp_functions": 3, "sp_max_iterations": 7}
    ids = [f"direction-{index}" for index in range(2)]
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 162

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent") as cls:
        cls.return_value.plan_directions_async = AsyncMock(return_value={
            "success": True, "directions_created": 2,
            "direction_ids": ids,
        })
        cls.return_value.max_directions = 5
        cls.return_value.stop_reason = "budget_before_transport"
        with pytest.raises(IncompleteInjectedAgent) as interrupted:
            asyncio.run(strategy._run_direction_planning_async())

    assert interrupted.value.campaign_status == "INCOMPLETE_BUDGET"
    repos.directions.find_pending.assert_not_called()
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
    observed_pov_input_limit = []

    async def one_batch(**kwargs):
        batches.append(kwargs["work"])
        await asyncio.sleep(0)

    class FailedPipeline:
        def __init__(self, **kwargs):
            self._sp_finding_done = False
            observed_pov_input_limit.append(
                kwargs["config"].pov_input_bytes_max)

        async def run(self):
            raise RuntimeError("verifier failed")

        def shutdown(self):
            pass

    strategy._run_function_batch = one_batch
    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", FailedPipeline):
        with pytest.raises(RuntimeError, match="verifier failed"):
            asyncio.run(strategy._run_v2_pipeline([direction]))
    assert len(batches) == 1
    assert observed_pov_input_limit == [MAX_SEED_BYTES]


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


def test_injected_seed_agents_do_not_overlap_host_tool_phases():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy.executor.qualified_seed_generator = lambda **kwargs: None
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    strategy.executor.fuzzer_manager = manager
    directions = [SimpleNamespace(
        direction_id=name, name=name, risk_level="high",
        risk_reason="fixture", core_functions=["target"])
        for name in ("A", "B", "C")]
    active = 0
    peak = 0
    observed = []

    def seed_agent(**kwargs):
        agent = MagicMock()
        agent.stop_reason = None

        async def generate_direction_seeds(**_):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            observed.append(kwargs["target_name"])
            await asyncio.sleep(0)
            active -= 1
            return {"success": True, "seeds_generated": 1}

        agent.generate_direction_seeds = generate_direction_seeds
        return agent

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent",
               side_effect=seed_agent):
        asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
            directions))
    assert peak == 1
    assert observed == ["A", "B", "C"]
    manager.start_global_fuzzer.assert_awaited_once()


@pytest.mark.parametrize("function_limit,expected", [
    (3, [("b", "D1"), ("c", "D2"), ("a", "D1")]),
    (1, [("b", "D1")]),
])
def test_bounded_nohint_sp_selects_model_order_round_robin_distinct_functions(
        tmp_path, function_limit, expected):
    strategy, _ = make_strategy(RecordingFactory())
    strategy.results_path = tmp_path
    strategy.executor.development_run_id = "run-id"
    strategy._development_auto_scope = {"seed_directions": 2,
                                        "sp_functions": function_limit,
                                        "sp_max_iterations": 7}
    # Bounded selection must preserve model order without relying on the
    # separate full-nohint ordering flag.
    strategy._full_nohint_sp = False
    strategy._development_direction_plan = (Path("/tmp/pinned-plan"), "a" * 64)
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._log_coverage_report = lambda *_: None
    directions = [
        SimpleNamespace(direction_id="D1", name="D1", risk_level="high",
                        core_functions=["b", "a"], entry_functions=[]),
        SimpleNamespace(direction_id="D2", name="D2", risk_level="high",
                        core_functions=["c", "a"], entry_functions=[]),
    ]
    def fn(name, line):
        return SimpleNamespace(function_id=name, name=name,
                               file_path="target.c", start_line=line, content="")
    a, b, c, d = (fn("a", 10), fn("b", 20), fn("c", 30), fn("d", 40))
    empty = lambda: {"small/new": [], "small/re": [],
                     "big/new": [], "big/re": []}
    first, second = empty(), empty()
    first["small/new"] = [b, a]
    first["big/new"] = [d]
    second["small/new"] = [c, a]
    strategy._build_direction_pools = lambda _: [(directions[0], first),
                                                  (directions[1], second)]
    selected = []

    async def record_batch(**kwargs):
        selected.extend((func.function_id, direction_id)
                        for func, direction_id in kwargs["work"])

    strategy._run_function_batch = record_batch

    class WaitingPipeline:
        def __init__(self, **kwargs):
            self._sp_finding_done = False

        async def run(self):
            while not self._sp_finding_done:
                await asyncio.sleep(0)
            return SimpleNamespace()

        def shutdown(self):
            pass

    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", WaitingPipeline):
        asyncio.run(strategy._run_v2_pipeline(directions))
    assert selected == expected
    scope = strategy._development_sp_scope
    assert scope["status"] == "PARTIAL_SCOPE"
    assert scope["candidate_occurrences"] == 5
    assert scope["distinct_function_count"] == 4
    assert [row["function_id"] for row in scope["selected_functions"]] == [
        row[0] for row in expected]
    assert scope["function_limit"] == function_limit
    assert scope["selection"] == (
        "DIRECTION_RISK_PHASE_GENERIC_SURFACE_MODEL_TIE_V4")
    receipt = tmp_path / "BOUNDED_AUTO_SELECTION.json"
    assert receipt.is_file()
    assert scope["selection_receipt_sha256"] == hashlib.sha256(
        receipt.read_bytes()).hexdigest()


def test_bounded_nohint_sp_finishes_high_risk_round_robin_before_medium():
    strategy, _ = make_strategy(RecordingFactory())

    def fn(name):
        return SimpleNamespace(function_id=name, name=name,
                               file_path="target.c", start_line=1)

    directions = [
        SimpleNamespace(direction_id="H1", risk_level="high"),
        SimpleNamespace(direction_id="H2", risk_level="high"),
        SimpleNamespace(direction_id="M1", risk_level="medium"),
    ]
    pools = [
        (directions[0], {"small/new": [fn("h1-a"), fn("h1-b")]}),
        (directions[1], {"small/new": [fn("h2-a"), fn("h2-b")]}),
        (directions[2], {"small/new": [fn("m1-a")]}),
    ]
    work = strategy._bounded_phase_work_for_directions(pools, "small/new")
    assert [(func.name, direction_id) for func, direction_id in work] == [
        ("h1-a", "H1"), ("h2-a", "H2"),
        ("h1-b", "H1"), ("h2-b", "H2"),
        ("m1-a", "M1"),
    ]


def test_full_nohint_sp_interleaves_all_directions_in_model_function_order(
        tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy._full_nohint_sp = True
    strategy.results_path = tmp_path
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._log_coverage_report = lambda *_: None
    directions = [
        SimpleNamespace(direction_id="D1", name="first", risk_level="high",
                        core_functions=["b", "a"], entry_functions=[]),
        SimpleNamespace(direction_id="D2", name="second", risk_level="high",
                        core_functions=["d", "c"], entry_functions=[]),
    ]
    functions = {name: SimpleNamespace(name=name, file_path="target.c",
                                       start_line=index)
                 for index, name in enumerate("abcd", start=1)}
    empty = lambda: {"small/new": [], "small/re": [],
                     "big/new": [], "big/re": []}
    first, second = empty(), empty()
    first["small/new"] = [functions["a"], functions["b"]]
    second["small/new"] = [functions["c"], functions["d"]]
    strategy._build_direction_pools = lambda _: [(directions[0], first),
                                                  (directions[1], second)]
    observed = []

    async def record_batch(**kwargs):
        observed.extend((func.name, direction_id)
                        for func, direction_id in kwargs["work"])

    strategy._run_function_batch = record_batch

    class WaitingPipeline:
        def __init__(self, **kwargs):
            self._sp_finding_done = False

        async def run(self):
            while not self._sp_finding_done:
                await asyncio.sleep(0)
            return SimpleNamespace()

        def shutdown(self):
            pass

    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", WaitingPipeline):
        asyncio.run(strategy._run_v2_pipeline(directions))

    assert observed == [("b", "D1"), ("d", "D2"),
                        ("a", "D1"), ("c", "D2")]
    assert len(observed) == sum(len(pools["small/new"])
                                for pools in (first, second))


def test_full_nohint_sp_prioritizes_generic_source_risk_before_model_tie(
        tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy._full_nohint_sp = True
    strategy.results_path = tmp_path
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    strategy.sanitizer = "address"
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._log_coverage_report = lambda *_: None
    direction = SimpleNamespace(
        direction_id="D1", name="first", risk_level="high",
        core_functions=["wrapper", "complex"], entry_functions=[])
    wrapper = SimpleNamespace(
        function_id="wrapper", name="wrapper", file_path="target.c",
        start_line=1, content="int wrapper(Node *n) { return n->value; }")
    complex_surface = SimpleNamespace(
        function_id="complex", name="complex", file_path="target.c",
        start_line=2, content=(
            "int complex(Table *t, int i, int n) { "
            "if (i + 1 < n && t->used <= t->capacity) "
            "return t->rows[i + 1]; return 0; }"))
    pools = {"small/new": [wrapper, complex_surface], "small/re": [],
             "big/new": [], "big/re": []}
    strategy._build_direction_pools = lambda _: [(direction, pools)]
    observed = []

    async def record_batch(**kwargs):
        observed.extend(func.name for func, _ in kwargs["work"])

    strategy._run_function_batch = record_batch

    class WaitingPipeline:
        def __init__(self, **kwargs):
            self._sp_finding_done = False

        async def run(self):
            while not self._sp_finding_done:
                await asyncio.sleep(0)
            return SimpleNamespace()

        def shutdown(self):
            pass

    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", WaitingPipeline):
        asyncio.run(strategy._run_v2_pipeline([direction]))

    assert observed == ["complex", "wrapper"]


def test_invariant_family_selects_direction_and_function_without_name_hints():
    strategy, repos = make_strategy(RecordingFactory())
    strategy._development_sp_queue_drain = True
    strategy._development_security_invariant_focus = "BOUNDS_EXTENT"
    strategy._development_pov_attempts_per_candidate = 3
    indexed = SimpleNamespace(
        name="alpha", content="int f(T *t, int i) { return t->rows[i + 1]; }")
    lifetime = SimpleNamespace(
        name="beta", content="void f(Node *n) { free(n); use(n->value); }")
    functions = {"alpha": indexed, "beta": lifetime}
    repos.functions.find_by_name.side_effect = lambda _task, name: functions[name]
    bounds_direction = SimpleNamespace(
        direction_id="D2", risk_level="high", core_functions=["alpha"],
        entry_functions=[])
    lifetime_direction = SimpleNamespace(
        direction_id="D1", risk_level="high", core_functions=["beta"],
        entry_functions=[])

    ordered = strategy._sort_directions_for_campaign(
        [lifetime_direction, bounds_direction])
    assert [row.direction_id for row in ordered] == ["D2", "D1"]
    assert strategy._function_campaign_priority(indexed) > \
        strategy._function_campaign_priority(lifetime)
    pools = [
        (bounds_direction, {"small/new": [indexed, indexed]}),
        (lifetime_direction, {"small/new": [lifetime, lifetime]}),
    ]
    assert [direction_id for _, direction_id in
            strategy._phase_work_for_directions(pools, "small/new")] == [
                "D2", "D1"]


def test_full_nohint_deduplicates_same_function_across_directions():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._full_nohint_sp = True
    shared = SimpleNamespace(function_id="shared", name="shared",
                             file_path="target.c", start_line=7)
    unique = SimpleNamespace(function_id="unique", name="unique",
                             file_path="target.c", start_line=9)
    pools = [
        (SimpleNamespace(direction_id="D1"), {"small/new": [shared]}),
        (SimpleNamespace(direction_id="D2"),
         {"small/new": [shared, unique]}),
    ]

    work = strategy._phase_work_for_directions(pools, "small/new")

    assert [(func.function_id, direction_id)
            for func, direction_id in work] == [
                ("shared", "D1"), ("unique", "D2")]


def test_full_nohint_prioritizes_function_risk_across_directions():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._full_nohint_sp = True
    low = SimpleNamespace(function_id="low", name="low", content="int f(void) { return 0; }")
    high = SimpleNamespace(function_id="high", name="high",
                           content="void f(char *p, int i) { p[i] = 1; free(p); }")
    pools = [
        (SimpleNamespace(direction_id="D1"), {"small/new": [low]}),
        (SimpleNamespace(direction_id="D2"), {"small/new": [high]}),
    ]

    assert [(func.function_id, direction_id) for func, direction_id in
            strategy._phase_work_for_directions(pools, "small/new")] == [
                ("high", "D2"), ("low", "D1")]


def test_full_nohint_deduplicates_same_function_across_phases():
    strategy, _ = make_strategy(RecordingFactory())
    strategy._full_nohint_sp = True
    shared = SimpleNamespace(function_id="shared", name="shared",
                             file_path="target.c", start_line=7)
    unique = SimpleNamespace(function_id="unique", name="unique",
                             file_path="target.c", start_line=9)
    empty = lambda: {"small/new": [], "small/re": [],
                     "big/new": [], "big/re": []}
    first, second = empty(), empty()
    first["small/new"] = [shared]
    second["big/new"] = [shared, unique]
    pools = [
        (SimpleNamespace(direction_id="D1"), first),
        (SimpleNamespace(direction_id="D2"), second),
    ]

    plan = strategy._unique_phase_work_plan(
        pools, ["small/new", "small/re", "big/new", "big/re"])

    assert [(func.function_id, direction_id)
            for func, direction_id in plan["small/new"]] == [
                ("shared", "D1")]
    assert [(func.function_id, direction_id)
            for func, direction_id in plan["big/new"]] == [
                ("unique", "D2")]


def test_nohint_sp_function_selection_receipt_records_cross_phase_duplicates(
        tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy.results_path = tmp_path
    strategy.executor.development_run_id = "run-id"
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    shared = SimpleNamespace(function_id="shared", name="shared",
                             file_path="target.c", start_line=7)
    unique = SimpleNamespace(function_id="unique", name="unique",
                             file_path="target.c", start_line=9)
    empty = lambda: {"small/new": [], "small/re": [],
                     "big/new": [], "big/re": []}
    first, second = empty(), empty()
    first["small/new"] = [shared]
    second["big/new"] = [shared, unique]
    pools = [
        (SimpleNamespace(direction_id="D1"), first),
        (SimpleNamespace(direction_id="D2"), second),
    ]
    phases = ["small/new", "small/re", "big/new", "big/re"]
    plan = strategy._unique_phase_work_plan(pools, phases)

    receipt = strategy._write_sp_function_selection_receipt(
        pools, phases, plan)

    path = tmp_path / "SP_FUNCTION_SELECTION_RECEIPT.json"
    payload = json.loads(path.read_text())
    assert receipt["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert payload["candidate_occurrence_count"] == 3
    assert payload["selected_function_count"] == 2
    assert [row["disposition"] for row in payload["occurrences"]] == [
        "SELECTED_FIRST_OCCURRENCE", "SKIPPED_DUPLICATE",
        "SELECTED_FIRST_OCCURRENCE"]
    assert [row["canonical_identity"]["value"]
            for row in payload["selected_functions"]] == [
                "shared", "unique"]


def test_nohint_function_selection_receipt_is_bound_to_analysis_scope(tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy.results_path = tmp_path
    strategy.executor.development_run_id = "run-id"
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    receipt_path = tmp_path / "SP_FUNCTION_SELECTION_RECEIPT.json"
    receipt_path.write_text("{}\n")
    receipt = {"path": str(receipt_path),
               "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest()}
    strategy._development_sp_scope = {
        "kind": "FULL_NOHINT_SP_V1", "status": "FULL_FUNCTION_POOL",
        "function_outcomes": []}

    strategy._bind_sp_function_selection_receipt(receipt)

    assert strategy._development_sp_scope[
        "function_selection_receipt_path"] == str(receipt_path)
    assert strategy._development_sp_scope[
        "function_selection_receipt_sha256"] == receipt["sha256"]


def test_nohint_selection_receipt_exists_before_first_sp_batch(tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy.results_path = tmp_path
    strategy.executor.development_run_id = "run-id"
    strategy._full_nohint_sp = True
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    strategy._development_sp_scope = {
        "kind": "FULL_NOHINT_SP_V1", "status": "FULL_FUNCTION_POOL",
        "function_outcomes": []}
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._log_coverage_report = lambda *_: None
    function = SimpleNamespace(function_id="f", name="f",
                               file_path="target.c", start_line=1, content="")
    direction = SimpleNamespace(
        direction_id="D1", name="D1", risk_level="high",
        core_functions=["f"], entry_functions=[])
    strategy._build_direction_pools = lambda _: [(direction, {
        "small/new": [function], "small/re": [],
        "big/new": [], "big/re": []})]
    observed = []

    async def record_batch(**kwargs):
        receipt = tmp_path / "SP_FUNCTION_SELECTION_RECEIPT.json"
        assert receipt.is_file()
        assert strategy._development_sp_scope[
            "function_selection_receipt_path"] == str(receipt)
        assert strategy._development_sp_scope[
            "function_selection_receipt_sha256"] == hashlib.sha256(
                receipt.read_bytes()).hexdigest()
        observed.extend(func.function_id for func, _ in kwargs["work"])

    strategy._run_function_batch = record_batch

    class WaitingPipeline:
        def __init__(self, **kwargs):
            self._sp_finding_done = False

        async def run(self):
            while not self._sp_finding_done:
                await asyncio.sleep(0)
            return SimpleNamespace()

        def shutdown(self):
            pass

    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", WaitingPipeline):
        asyncio.run(strategy._run_v2_pipeline([direction]))

    assert observed == ["f"]


def test_nohint_sp_function_selection_receipt_is_exclusive(tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy.results_path = tmp_path
    strategy.executor.development_run_id = "run-id"
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    function = SimpleNamespace(function_id="f", name="f",
                               file_path="target.c", start_line=1)
    pools = [(SimpleNamespace(direction_id="D1"), {
        "small/new": [function], "small/re": [],
        "big/new": [], "big/re": []})]
    phases = ["small/new", "small/re", "big/new", "big/re"]
    plan = strategy._unique_phase_work_plan(pools, phases)

    strategy._write_sp_function_selection_receipt(pools, phases, plan)
    with pytest.raises(FileExistsError):
        strategy._write_sp_function_selection_receipt(pools, phases, plan)


def test_direction_selection_receipt_records_pre_execution_ranking(tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy.results_path = tmp_path
    strategy.executor.development_run_id = "run-id"
    strategy._development_direction_plan = (
        tmp_path / "DIRECTION_PLAN.json", "a" * 64)
    directions = [
        SimpleNamespace(direction_id="D-low", name="low", risk_level="low",
                        core_functions=[], entry_functions=[]),
        SimpleNamespace(direction_id="D-high", name="high", risk_level="high",
                        core_functions=[], entry_functions=[]),
    ]
    ranked = strategy._sort_directions_for_campaign(directions)

    receipt = strategy._write_direction_selection_receipt(
        directions, ranked, seed_limit=1)

    payload = json.loads((tmp_path / "DIRECTION_SELECTION_RECEIPT.json").read_text())
    assert receipt["sha256"] == hashlib.sha256(
        (tmp_path / "DIRECTION_SELECTION_RECEIPT.json").read_bytes()).hexdigest()
    assert payload["direction_plan_sha256"] == "a" * 64
    assert [row["direction_id"] for row in payload["ranked_directions"]] == [
        "D-high", "D-low"]
    assert [row["selected"] for row in payload["ranked_directions"]] == [
        True, False]


def test_executor_propagates_generic_family_and_candidate_attempt_cap():
    from fuzzingbrain.worker.executor import WorkerExecutor

    executor = object.__new__(WorkerExecutor)
    executor.task_type = "pov"
    executor.scan_mode = "full"
    executor.llm_client_factory = RecordingFactory()
    executor.development_seed_limit = 1
    executor.development_sp_queue_drain = True
    executor.development_security_invariant_focus = "BOUNDS_EXTENT"
    executor.development_pov_attempts_per_candidate = 3
    with patch("fuzzingbrain.worker.strategies.POVFullscanStrategy") as cls:
        strategy = executor._get_strategy()
    assert strategy._development_security_invariant_focus == "BOUNDS_EXTENT"
    assert strategy._development_pov_attempts_per_candidate == 3


def test_executor_propagates_concurrent_queue_worker_pool_without_drain():
    from fuzzingbrain.worker.executor import WorkerExecutor

    executor = object.__new__(WorkerExecutor)
    executor.task_type = "pov"
    executor.scan_mode = "full"
    executor.llm_client_factory = RecordingFactory()
    executor.development_sp_concurrent_queue = True
    executor.development_sp_discovery_agents = 3
    executor.development_sp_verify_agents = 2
    executor.development_sp_pov_agents = 2
    with patch("fuzzingbrain.worker.strategies.POVFullscanStrategy") as cls:
        cls.return_value._development_sp_queue_drain = False
        strategy = executor._get_strategy()
    assert strategy._development_sp_concurrent_queue is True
    assert strategy._development_sp_queue_drain is False
    assert strategy.num_parallel_agents == 3
    assert strategy._development_verify_agents == 2
    assert strategy._development_pov_agents == 2


def test_concurrent_queue_starts_explicit_verifier_and_pov_pools_during_discovery(
        tmp_path):
    strategy, _ = make_strategy(RecordingFactory())
    strategy._development_sp_concurrent_queue = True
    strategy._development_sp_queue_drain = False
    strategy.num_parallel_agents = 3
    strategy._development_verify_agents = 2
    strategy._development_pov_agents = 2
    strategy.results_path = tmp_path
    strategy.sanitizer = "address"
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._log_coverage_report = lambda *_: None
    direction = SimpleNamespace(
        direction_id="D1", name="first", risk_level="high",
        core_functions=["target"], entry_functions=[])
    target = SimpleNamespace(
        function_id="target", name="target", file_path="target.c",
        start_line=1, content="int target(void) { return 0; }")
    pools = {"small/new": [target], "small/re": [],
             "big/new": [], "big/re": []}
    strategy._build_direction_pools = lambda _: [(direction, pools)]
    started = asyncio.Event()
    observed = {}

    class StreamingPipeline:
        def __init__(self, **kwargs):
            self.config = kwargs["config"]
            self._sp_finding_done = False
            self.serial_bounded_dev = False
            self.prefer_pov_after_verify = False
            observed["pipeline"] = self

        async def run(self):
            started.set()
            while not self._sp_finding_done:
                await asyncio.sleep(0)
            return SimpleNamespace()

        def shutdown(self):
            pass

    async def record_batch(**_kwargs):
        await asyncio.wait_for(started.wait(), 1)
        observed["pipeline_was_live_during_discovery"] = True

    strategy._run_function_batch = record_batch
    with patch("fuzzingbrain.worker.pipeline.AgentPipeline", StreamingPipeline):
        asyncio.run(strategy._run_v2_pipeline([direction]))

    pipeline = observed["pipeline"]
    assert observed["pipeline_was_live_during_discovery"] is True
    assert pipeline.config.num_verify_agents == 2
    assert pipeline.config.num_pov_agents == 2
    assert pipeline.config.pov_admission_mode == "explicit_disposition"
    assert pipeline.serial_bounded_dev is False
    assert pipeline.prefer_pov_after_verify is False


def test_global_fuzzer_is_started_before_and_remains_live_during_sp_pipeline():
    strategy, _ = make_strategy(RecordingFactory())
    global_live = False
    observed = []

    async def start_global(_directions):
        nonlocal global_live
        global_live = True
        observed.append("global_started")

    async def run_sp(_directions):
        assert global_live is True
        observed.append("sp_pipeline_running")
        await asyncio.sleep(0)
        assert global_live is True
        return SimpleNamespace()

    strategy._generate_direction_seeds_and_start_global_fuzzer = start_global
    strategy._run_v2_pipeline = run_sp
    asyncio.run(strategy._run_v2_pipeline_with_fuzzer_init([
        SimpleNamespace(direction_id="D1")]))
    assert observed == ["global_started", "sp_pipeline_running"]


def test_original_phase_order_remains_direction_contiguous():
    strategy, _ = make_strategy(RecordingFactory())
    a, b = SimpleNamespace(name="a"), SimpleNamespace(name="b")
    pools = [(SimpleNamespace(direction_id="D1"), {"small/new": [a]}),
             (SimpleNamespace(direction_id="D2"), {"small/new": [b]})]
    strategy._full_nohint_sp = False
    assert strategy._phase_work_for_directions(pools, "small/new") == [
        (a, "D1"), (b, "D2")]


def test_bounded_scope_reaches_the_strategy_created_at_worker_execution():
    from fuzzingbrain.worker.executor import WorkerExecutor

    executor = object.__new__(WorkerExecutor)
    executor.task_type = "pov"
    executor.scan_mode = "full"
    executor.llm_client_factory = RecordingFactory()
    executor.development_auto_scope = {"seed_directions": 2,
                                       "sp_functions": 3,
                                       "sp_max_iterations": 7}
    with patch("fuzzingbrain.worker.strategies.POVFullscanStrategy") as cls:
        strategy = executor._get_strategy()
    assert strategy is cls.return_value
    assert strategy._development_auto_scope == executor.development_auto_scope
    assert strategy.num_parallel_agents == 1


def test_bounded_model_queue_drains_verifier_before_pov():
    pipeline = AgentPipeline(
        task_id="task", repos=MagicMock(), fuzzer="fixture_fuzzer",
        sanitizer="address", llm_client_factory=RecordingFactory(),
    )
    pipeline.serial_bounded_dev = True
    pipeline._sp_finding_done = True
    order = []

    async def verify(_):
        order.append("verifier")
        await asyncio.sleep(0)

    async def pov(_):
        order.append("pov")

    pipeline._run_verify_agent = verify
    pipeline._run_pov_agent = pov
    asyncio.run(pipeline.run())
    assert order == ["verifier", "pov"]


@pytest.mark.parametrize("model_status,should_advance", [
    ("COMPLETED", True), ("UNCERTAIN", False),
])
def test_one_invalid_seed_proposal_is_isolated_only_after_ledger_settlement(
        model_status, should_advance):
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    manager.direction_seeds = [SimpleNamespace(direction_id="A")]
    manager._authority_ok.return_value = True
    manager.model_gate.snapshot.return_value = {"records": [
        {"request_id": "a", "role": "seed", "owner_id": "A",
         "status": "COMPLETED", "tool_events": []},
        {"request_id": "b", "role": "seed", "owner_id": "B",
         "status": model_status, "tool_events": []},
    ]}
    manager.model_gate.verify_response_evidence.return_value = {
        "status": "VERIFIED"}
    manager.campaign.ledger.snapshot.return_value = {
        "active": {}, "stop_status": None}
    strategy.executor.fuzzer_manager = manager
    directions = [SimpleNamespace(
        direction_id=name, name=name, risk_level="high",
        risk_reason="fixture", core_functions=["target"])
        for name in ("A", "B")]

    def seed_agent(**kwargs):
        agent = MagicMock()
        agent.stop_reason = (None if kwargs["target_name"] == "A"
                             else "invalid_model_tool_json")
        agent.generate_direction_seeds = AsyncMock(return_value={
            "success": True,
            "seeds_generated": 1 if kwargs["target_name"] == "A" else 0,
        })
        return agent

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent",
               side_effect=seed_agent):
        if should_advance:
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                directions))
            manager.start_global_fuzzer.assert_awaited_once()
            assert strategy._direction_seed_phase == {
                "status": "PARTIAL_INVALID_MODEL_TOOL_JSON",
                "seeds_generated": 1,
                "failed_direction_ids": ["B"],
            }
        else:
            with pytest.raises(IncompleteInjectedAgent) as interrupted:
                asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                    directions))
            assert interrupted.value.reason == "invalid_model_tool_json"
            manager.start_global_fuzzer.assert_not_awaited()


@pytest.mark.parametrize(
    "tool_name,tool_status,tool_evidence,response_evidence,stop_reason,should_advance", [
    ("search_code", "COMPLETED", "VERIFIED", "VERIFIED", "invalid_model_tool_json", True),
    ("create_seed", "COMPLETED", "VERIFIED", "VERIFIED", "invalid_model_tool_json", False),
    ("search_code", "STARTED", "VERIFIED", "VERIFIED", "invalid_model_tool_json", False),
    ("search_code", "COMPLETED", "UNPROVEN", "VERIFIED", "invalid_model_tool_json", False),
    ("search_code", "COMPLETED", "VERIFIED", "UNPROVEN", "invalid_model_tool_json", False),
    ("search_code", "COMPLETED", "VERIFIED", "VERIFIED", "uncertain_remote", False),
    ("search_code", "COMPLETED", "VERIFIED", "VERIFIED", "budget_before_transport", False),
    ("search_code", "COMPLETED", "VERIFIED", "VERIFIED", "llm_error", False),
])
def test_invalid_seed_proposal_isolated_only_after_verified_read_only_lookup(
        tool_name, tool_status, tool_evidence, response_evidence, stop_reason,
        should_advance):
    strategy, _ = make_strategy(RecordingFactory())
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    manager = MagicMock()
    manager.start_global_fuzzer = AsyncMock(return_value=True)
    manager.direction_seeds = [SimpleNamespace(direction_id="A")]
    manager._authority_ok.return_value = True
    manager.model_gate.snapshot.return_value = {"records": [
        {"request_id": "a", "role": "seed", "owner_id": "A",
         "status": "COMPLETED", "tool_events": []},
        {"request_id": "b1", "role": "seed", "owner_id": "B",
         "status": "COMPLETED", "tool_events": [
             {"call_id": "lookup", "name": tool_name, "status": tool_status},
         ]},
        {"request_id": "b2", "role": "seed", "owner_id": "B",
         "status": "COMPLETED", "tool_events": []},
    ]}
    manager.model_gate.verify_response_evidence.return_value = {
        "status": response_evidence}
    manager.model_gate.verify_tool_event.return_value = {
        "status": tool_evidence}
    manager.campaign.ledger.snapshot.return_value = {
        "active": {}, "stop_status": None}
    strategy.executor.fuzzer_manager = manager
    directions = [SimpleNamespace(
        direction_id=name, name=name, risk_level="high",
        risk_reason="fixture", core_functions=["target"])
        for name in ("A", "B")]

    def seed_agent(**kwargs):
        agent = MagicMock()
        agent.stop_reason = (None if kwargs["target_name"] == "A"
                             else stop_reason)
        agent.generate_direction_seeds = AsyncMock(return_value={
            "success": True,
            "seeds_generated": 1 if kwargs["target_name"] == "A" else 0,
        })
        return agent

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent",
               side_effect=seed_agent):
        if should_advance:
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                directions))
            manager.start_global_fuzzer.assert_awaited_once()
            assert strategy._direction_seed_phase["failed_direction_ids"] == ["B"]
        else:
            with pytest.raises(IncompleteInjectedAgent) as interrupted:
                asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                    directions))
            if stop_reason == "invalid_model_tool_json":
                assert interrupted.value.reason == "invalid_model_tool_json"
            manager.start_global_fuzzer.assert_not_awaited()


@pytest.mark.parametrize("empty_error", [RuntimeError(), TimeoutError()])
def test_empty_message_seed_exception_blocks_global_after_earlier_success(
        empty_error):
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
        agent.stop_reason = None
        if kwargs["target_name"] == "A":
            agent.generate_direction_seeds = AsyncMock(return_value={
                "success": True, "seeds_generated": 1,
            })
        else:
            agent.generate_direction_seeds = AsyncMock(
                side_effect=empty_error)
        return agent

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent",
               side_effect=seed_agent):
        with pytest.raises(IncompleteInjectedAgent) as interrupted:
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                directions))
    assert interrupted.value.reason == "incomplete_unknown"
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
                         verification_claim_token="claim-token",
                             pov_claim_token="pov-claim-token",
                         to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_verify.side_effect = [sp] + [None] * 6
    repos.suspicious_points.claim_for_pov.side_effect = [sp] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    repos.suspicious_points.find_by_id.return_value = SimpleNamespace(
        is_checked=True, is_important=False, is_real=False,
        score=0.1, verification_notes="fixture",
        verification_disposition=None)
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


def test_sp_persistence_failure_is_primary_and_never_marks_function_analyzed():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    strategy._development_sp_concurrent_queue = True
    strategy._development_sp_scope = {
        "status": "FULL_FUNCTION_POOL", "function_outcomes": []}
    repos.callgraph_nodes.find_callers.return_value = []
    repos.callgraph_nodes.find_callees.return_value = []
    func = SimpleNamespace(
        name="target", function_id="function-id", content="int target() {}",
        file_path="target.c", start_line=1, end_line=1)
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator") as cls:
        cls.return_value.analyze_async = AsyncMock(return_value={
            "success": True, "sp_created": False,
            "response": "No candidate remains after analysis.",
        })
        cls.return_value.stop_reason = "sp_persistence_failure"
        result = asyncio.run(strategy._analyze_single_function_v2(
            func, 0, 1, None, "direction-id"))

    assert result["success"] is False
    assert result["incomplete_reason"] == "sp_persistence_failure"
    repos.functions.mark_analyzed_by_direction.assert_not_called()
    assert strategy._development_sp_scope["function_outcomes"] == []


def test_concurrent_persistence_failure_outranks_sibling_max_iterations():
    factory = RecordingFactory()
    strategy, _repos = make_strategy(factory)
    strategy.num_parallel_agents = 3
    strategy._development_sp_concurrent_queue = True
    strategy._require_pipeline_active_during_sp = lambda: None
    strategy._admit_next_development_sp = lambda *_args: None
    all_started = asyncio.Event()
    started = 0

    async def analyze(func, *_args, **_kwargs):
        nonlocal started
        started += 1
        if started == 3:
            all_started.set()
        await all_started.wait()
        if func.name == "persistence":
            await asyncio.sleep(0.01)
            return {"success": False, "function_name": func.name,
                    "error_type": "IncompleteInjectedAgent",
                    "incomplete_reason": "sp_persistence_failure"}
        await asyncio.sleep(0.015 if func.name == "late-max" else 0.005)
        return {"success": False, "function_name": func.name,
                "error_type": "IncompleteInjectedAgent",
                "incomplete_reason": "max_iterations"}

    strategy._analyze_single_function_v2 = analyze
    work = [
        (SimpleNamespace(name="max", function_id="max"), "direction"),
        (SimpleNamespace(name="persistence", function_id="persist"), "direction"),
        (SimpleNamespace(name="late-max", function_id="late-max"), "direction"),
    ]
    with pytest.raises(IncompleteInjectedAgent) as failure:
        asyncio.run(strategy._run_function_batch(work, None))
    assert failure.value.reason == "sp_persistence_failure"


@pytest.mark.parametrize("scope", ["one_seed", "full_nohint"])
def test_strict_nohint_context_insufficient_does_not_mark_function_analyzed(scope):
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    strategy._development_sp_queue_drain = scope == "one_seed"
    strategy._full_nohint_sp = scope == "full_nohint"
    strategy._development_sp_scope = {
        "status": "FULL_FUNCTION_POOL", "function_outcomes": [],
    }
    repos.callgraph_nodes.find_callers.return_value = []
    repos.callgraph_nodes.find_callees.return_value = []
    func = SimpleNamespace(
        name="inspect", function_id="function-id",
        content="void inspect(char *p, int n) { use(p[n - 1]); }",
        file_path="target.c", start_line=1, end_line=1)
    result_row = {
        "success": False,
        "sp_created": False,
        "analysis_completion": {
            "valid": True,
            "context_sufficiency": "INSUFFICIENT",
            "unresolved_preconditions": ["allocation extent is unknown"],
        },
    }
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator") as cls:
        cls.return_value.analyze_async = AsyncMock(return_value=result_row)
        cls.return_value.stop_reason = None
        cls.return_value.sp_created = False
        result = asyncio.run(strategy._analyze_single_function_v2(
            func, 0, 1, None, "direction-id"))

    assert isinstance(result, _ContextInsufficientSPAnalysis)
    repos.functions.mark_analyzed_by_direction.assert_not_called()
    assert strategy._development_sp_scope["function_outcomes"] == [{
        "success": False,
        "function_name": "inspect",
        "function_id": "function-id",
        "direction_id": "direction-id",
        "opportunity_status": "NO_SP_CONTEXT_INSUFFICIENT",
        "context_sufficiency": "INSUFFICIENT",
        "unresolved_preconditions": ["allocation extent is unknown"],
    }]


def test_missing_sp_source_never_starts_model_analysis():
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    func = SimpleNamespace(name="target", function_id="function-id",
                           content="", file_path="target.c")
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator") as cls:
        result = asyncio.run(strategy._analyze_single_function_v2(
            func, 0, 1, None, "direction-id"))
    assert result["success"] is False
    assert result["incomplete_reason"] == "function_source_unavailable"
    assert factory.created == []
    cls.assert_not_called()
    repos.functions.mark_analyzed_by_direction.assert_not_called()


@pytest.mark.parametrize("agent_result,marker_result,reason", [
    ({"success": False, "sp_created": False}, True, "function_analysis_failed"),
    ({"success": True, "sp_created": False}, False,
     "function_state_write_failed"),
])
def test_sp_function_is_not_reported_done_when_result_or_db_write_fails(
        agent_result, marker_result, reason):
    factory = RecordingFactory()
    strategy, repos = make_strategy(factory)
    repos.callgraph_nodes.find_callers.return_value = []
    repos.callgraph_nodes.find_callees.return_value = []
    repos.functions.mark_analyzed_by_direction.return_value = marker_result
    func = SimpleNamespace(name="target", function_id="function-id",
                           content="int target(void) { return 0; }",
                           file_path="target.c", start_line=1, end_line=1)
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator") as cls:
        cls.return_value.analyze_async = AsyncMock(return_value=agent_result)
        cls.return_value.stop_reason = None
        result = asyncio.run(strategy._analyze_single_function_v2(
            func, 0, 1, None, "direction-id"))
    assert result["success"] is False
    assert result["incomplete_reason"] == reason
    if reason == "function_analysis_failed":
        repos.functions.mark_analyzed_by_direction.assert_not_called()


def test_unchecked_verifier_candidate_is_preserved_without_pov_pass_through():
    factory = RecordingFactory()
    repos = MagicMock()
    sp = SimpleNamespace(suspicious_point_id="sp-id", function_name="target",
                         verification_claim_token="claim-token",
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
        "sp-id", "failed", processor_id="verify_1",
        claim_token="claim-token")
    assert pipeline.stats.sp_verified == 0


def test_unchecked_verifier_claim_release_failure_stops_queue():
    factory = RecordingFactory()
    repos = MagicMock()
    sp = SimpleNamespace(suspicious_point_id="sp-id", function_name="target",
                         verification_claim_token="claim-token",
                         to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_verify.return_value = sp
    repos.suspicious_points.find_by_id.return_value = SimpleNamespace(
        is_checked=False, is_important=False, is_real=False,
        score=0.9, verification_notes="")
    repos.suspicious_points.release_claim.return_value = False
    pipeline = AgentPipeline(
        "task", repos, fuzzer="fixture_fuzzer", sanitizer="address",
        config=PipelineConfig(poll_interval=0), llm_client_factory=factory)
    pipeline._sp_finding_done = True
    with patch("fuzzingbrain.worker.pipeline.SPVerifier") as verifier:
        verifier.return_value.run_async = AsyncMock(return_value="done")
        verifier.return_value.stop_reason = None
        with pytest.raises(IncompleteInjectedAgent) as caught:
            asyncio.run(pipeline._run_verify_agent("verify_1"))
    assert caught.value.reason == "candidate_state_write_failed"
    assert repos.suspicious_points.claim_for_verify.call_count == 1
    assert pipeline.stats.sp_verified == 0


def test_pipeline_preserves_primary_failure_while_sibling_settles():
    pipeline = AgentPipeline(
        "task", MagicMock(), fuzzer="fixture_fuzzer", sanitizer="address",
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=1),
        llm_client_factory=RecordingFactory())

    async def verifier(_agent_id):
        while not pipeline._shutdown:
            await asyncio.sleep(0)

    async def pov(_agent_id):
        await asyncio.sleep(0)
        raise IncompleteInjectedAgent("PoV receipt validation failed",
                                      reason="missing_final_response")

    pipeline._run_verify_agent = verifier
    pipeline._run_pov_agent = pov
    with pytest.raises(IncompleteInjectedAgent) as caught:
        asyncio.run(pipeline.run())
    assert caught.value.reason == "missing_final_response"
    assert "PoV receipt validation failed" in str(caught.value)


def test_incomplete_pov_cannot_be_recorded_as_success_or_retried():
    factory = RecordingFactory()
    repos = MagicMock()
    sp = SimpleNamespace(suspicious_point_id="sp-id", function_name="target",
                         pov_claim_token="pov-claim-token",
                         to_dict=lambda: {"suspicious_point_id": "sp-id"})
    repos.suspicious_points.claim_for_pov.side_effect = [sp]
    pipeline = AgentPipeline(
        "task", repos, fuzzer="fixture_fuzzer", sanitizer="address",
        config=PipelineConfig(poll_interval=0), llm_client_factory=factory)

    with patch("fuzzingbrain.worker.pipeline.POVAgent") as pov:
        pov.return_value.generate_pov_async = AsyncMock(return_value=
            SimpleNamespace(success=True, pov_id="untrusted-id"))
        pov.return_value.stop_reason = "llm_error"
        with pytest.raises(IncompleteInjectedAgent) as caught:
            asyncio.run(pipeline._run_pov_agent("pov_1"))

    assert caught.value.reason == "llm_error"

    repos.suspicious_points.complete_pov.assert_not_called()
    repos.suspicious_points.release_claim.assert_not_called()
    repos.suspicious_points.preserve_incomplete_candidate.assert_called_once_with(
        "sp-id", {
            "status": "incomplete_uncertain", "processor_id": None,
            "pipeline_incomplete_reason": "llm_error",
            "pipeline_incomplete_stage": "pov",
        }, stage="pov", harness_name="fixture_fuzzer",
        sanitizer="address", processor_id="pov_1",
        claim_token="pov-claim-token")
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


@pytest.mark.parametrize("scope", ["bounded", "one_seed", "full_nohint"])
def test_bounded_batch_continues_only_after_explicit_local_exhaustion(scope):
    strategy, repos = make_strategy(RecordingFactory())
    strategy._development_auto_scope = ({"sp_functions": 2}
                                        if scope == "bounded" else None)
    strategy._development_sp_queue_drain = scope == "one_seed"
    strategy._full_nohint_sp = scope == "full_nohint"
    if scope == "one_seed":
        strategy._drain_development_sp_queue = AsyncMock()
    strategy.num_parallel_agents = 1
    first = SimpleNamespace(name="first", function_id="function-1")
    second = SimpleNamespace(name="second", function_id="function-2")
    entered = []

    async def analyze(*, func, **kwargs):
        entered.append(func.name)
        if func is first:
            return _VerifiedBoundedSPExhaustion(
                function_id="function-1", owner_id="direction-id:function-1:0")
        return {"success": True}

    strategy._analyze_single_function_v2 = analyze
    asyncio.run(strategy._run_function_batch(
        [(first, "direction-id"), (second, "direction-id")], None))
    assert entered == ["first", "second"]
    repos.functions.mark_analyzed_by_direction.assert_not_called()

    async def forged(*, func, **kwargs):
        return {"success": False,
                "opportunity_status": "NO_OPPORTUNITY_MAX_ITERATIONS"}

    strategy._analyze_single_function_v2 = forged
    with pytest.raises(IncompleteInjectedAgent):
        asyncio.run(strategy._run_function_batch(
            [(first, "direction-id")], None))


@pytest.mark.parametrize("scope", ["bounded", "one_seed", "full_nohint"])
def test_bounded_local_sp_exhaustion_requires_verified_read_only_owner(tmp_path, scope):
    from devtools.campaign_model_gate import (
        CampaignLedgeredProvider, CampaignModelGate,
    )

    strategy, repos = make_strategy(RecordingFactory())
    strategy._development_auto_scope = ({"sp_functions": 2,
                                         "sp_max_iterations": 7}
                                        if scope == "bounded" else None)
    strategy._development_sp_queue_drain = scope == "one_seed"
    strategy._full_nohint_sp = scope == "full_nohint"
    strategy.executor.development_process_ledger = MagicMock()
    strategy.executor.development_process_ledger.snapshot.return_value = {
        "stop_status": None}
    repos.suspicious_points.find_by_task.return_value = []
    gate = CampaignModelGate(tmp_path / "model-ledger.json", "run", 10, 60,
                             create=True)
    owner = "direction:function:0"
    event = {"status": "COMPLETED", "name": "get_function_source",
             "call_id": "call-id"}
    row = {"owner_id": owner, "role": "sp", "status": "COMPLETED",
           "request_id": "request-id", "tool_events": [event]}
    gate.snapshot = MagicMock(return_value={"records": [row]})
    gate.verify_response_evidence = MagicMock(return_value={"status": "VERIFIED"})
    gate.verify_tool_event = MagicMock(return_value={"status": "VERIFIED"})
    provider = CampaignLedgeredProvider(object(), gate, role="sp", owner_id=owner)
    strategy.executor.fuzzer_manager = SimpleNamespace(
        model_gate=gate,
        campaign=SimpleNamespace(
            ledger=strategy.executor.development_process_ledger))
    client = SimpleNamespace(provider=provider,
                             last_agent_response_was_final=False)
    agent = SimpleNamespace(stop_reason="max_iterations", sp_created=False)
    check = lambda: strategy._bounded_local_sp_exhaustion_verified(
        client=client, agent=agent, role="sp", owner=owner,
        before_ids=None if scope == "full_nohint" else ())

    assert check() == (1, 1)
    event["name"] = "record_local_risk_inventory"
    assert check() == (1, 1)
    event["name"] = "create_suspicious_point"
    assert check() is None
    event["name"] = "get_function_source"
    gate.verify_tool_event.return_value = {"status": "UNPROVEN"}
    assert check() is None
    gate.verify_tool_event.return_value = {"status": "VERIFIED"}
    row["status"] = "UNCERTAIN"
    assert check() is None
    row["status"] = "COMPLETED"
    strategy.executor.development_process_ledger.snapshot.return_value = {
        "stop_status": "STOPPED"}
    assert check() is None
    strategy.executor.development_process_ledger.snapshot.return_value = {
        "stop_status": None}
    repos.suspicious_points.find_by_task.return_value = [
        SimpleNamespace(suspicious_point_id="new-candidate")]
    assert check() == ((1, 1) if scope == "full_nohint" else None)


@pytest.mark.parametrize("case,expected", [
    ("sibling", (1, 1)), ("own_candidate", None),
    ("unknown_writer", None), ("deleted_baseline", None),
    ("uncertain", None), ("wrong_event_agent", None),
    ("foreign_request", None), ("wrong_context", None),
    ("no_candidate", (1, 1)), ("wrong_task", None),
    ("write_event", None), ("own_baseline", None),
    ("duplicate_id", None), ("started_event", None),
    ("large_window", (1, 1)),
])
def test_concurrent_sp_local_limit_distinguishes_sibling_writer(tmp_path, case, expected):
    from devtools.campaign_model_gate import CampaignLedgeredProvider, CampaignModelGate

    strategy, repos = make_strategy(RecordingFactory())
    strategy._development_sp_concurrent_queue = True
    ledger = SimpleNamespace(snapshot=lambda: {"stop_status": None})
    strategy.executor.development_process_ledger = ledger
    gate = CampaignModelGate(tmp_path / "ledger.json", "run", 10, 60, create=True)
    owner, agent_id = "direction:function:0", "current-agent"
    event = {"status": "COMPLETED", "name": "get_function_source",
             "call_id": "call-1", "agent_id": agent_id}
    row = {"owner_id": owner, "role": "sp", "status": "COMPLETED",
           "request_id": "request-1", "tool_events": [event]}
    gate.snapshot = MagicMock(return_value={"records": [row]})
    gate.verify_response_evidence = MagicMock(return_value={"status": "VERIFIED"})
    gate.verify_tool_event = MagicMock(return_value={"status": "VERIFIED"})
    provider = CampaignLedgeredProvider(object(), gate, role="sp", owner_id=owner)
    provider.issued_request_ids.append("request-1")
    client = SimpleNamespace(provider=provider, agent_id=agent_id,
                             last_agent_response_was_final=False)
    agent = SimpleNamespace(stop_reason="max_iterations", sp_created=False,
                            _context=SimpleNamespace(agent_id=agent_id))
    strategy.executor.fuzzer_manager = SimpleNamespace(
        model_gate=gate, campaign=SimpleNamespace(ledger=ledger))
    baseline = SimpleNamespace(suspicious_point_id="baseline", task_id="task",
                               created_by_agent_id="older-agent")
    sibling = SimpleNamespace(suspicious_point_id="sibling", task_id="task",
                              created_by_agent_id="sibling-agent")
    candidates = [baseline, sibling]
    if case == "own_candidate": sibling.created_by_agent_id = agent_id
    if case == "unknown_writer": sibling.created_by_agent_id = None
    if case == "deleted_baseline": candidates.remove(baseline)
    if case == "uncertain": row["status"] = "UNCERTAIN"
    if case == "wrong_event_agent": event["agent_id"] = "sibling-agent"
    if case == "foreign_request": provider.issued_request_ids[:] = ["other-request"]
    if case == "wrong_context": agent._context.agent_id = "sibling-agent"
    if case == "no_candidate": candidates.remove(sibling)
    if case == "wrong_task": sibling.task_id = "another-task"
    if case == "write_event": event["name"] = "create_suspicious_point"
    if case == "own_baseline": baseline.created_by_agent_id = agent_id
    if case == "duplicate_id": sibling.suspicious_point_id = "baseline"
    if case == "started_event": event["status"] = "STARTED"
    if case == "large_window":
        event["name"] = "get_next_function_window"
        row["role"] = provider.role = "sp_large"
    repos.suspicious_points.find_by_task.return_value = candidates
    assert strategy._bounded_local_sp_exhaustion_verified(
        client=client, agent=agent, role=provider.role, owner=owner,
        before_ids=("baseline",)) == expected


@pytest.mark.parametrize("scope", ["bounded", "one_seed", "full_nohint"])
def test_bounded_sp_agent_local_exhaustion_continues_without_analyzed_mark(tmp_path, scope):
    from devtools.campaign_model_gate import (
        CampaignLedgeredProvider, CampaignModelGate,
    )

    gate = CampaignModelGate(tmp_path / "model-ledger.json", "run", 10, 60,
                             create=True)
    clients = []

    def factory(role, owner):
        client = FakeClient()
        client.last_agent_response_was_final = len(clients) != 0
        client.provider = CampaignLedgeredProvider(
            object(), gate, role=role, owner_id=owner)
        clients.append(client)
        return client

    strategy, repos = make_strategy(factory)
    strategy._development_auto_scope = ({"sp_functions": 2,
                                         "sp_max_iterations": 7}
                                        if scope == "bounded" else None)
    strategy._development_sp_queue_drain = scope == "one_seed"
    strategy._full_nohint_sp = scope == "full_nohint"
    if scope == "one_seed":
        strategy._drain_development_sp_queue = AsyncMock()
    strategy._development_sp_scope = {"status": "PARTIAL_SCOPE"}
    strategy.num_parallel_agents = 1
    repos.suspicious_points.find_by_task.return_value = []
    repos.functions.mark_analyzed_by_direction.return_value = True
    ledger = SimpleNamespace(snapshot=lambda: {"stop_status": None})
    strategy.executor.development_process_ledger = ledger
    strategy.executor.fuzzer_manager = SimpleNamespace(
        model_gate=gate, campaign=SimpleNamespace(ledger=ledger))
    row = {"owner_id": "direction:function-1:0", "role": "sp",
           "status": "COMPLETED", "request_id": "request-id",
           "tool_events": [{"status": "COMPLETED", "name": "get_callers",
                            "call_id": "call-id"}]}
    gate.snapshot = MagicMock(return_value={"records": [row]})
    gate.verify_response_evidence = MagicMock(return_value={"status": "VERIFIED"})
    gate.verify_tool_event = MagicMock(return_value={"status": "VERIFIED"})
    first_agent = SimpleNamespace(
        analyze_async=AsyncMock(return_value={"success": True, "sp_created": False}),
        stop_reason="max_iterations", sp_created=False)
    second_agent = SimpleNamespace(
        analyze_async=AsyncMock(return_value={"success": True, "sp_created": False}),
        stop_reason=None, sp_created=False)
    functions = [SimpleNamespace(name=f"function-{i}", function_id=f"function-{i}",
                                 content="int f(void) { return 0; }",
                                 file_path="source.c", start_line=i,
                                 end_line=i + 1)
                 for i in (1, 2)]
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator",
               side_effect=[first_agent, second_agent]) as generator:
        asyncio.run(strategy._run_function_batch(
            [(functions[0], "direction"), (functions[1], "direction")], None))

    assert all(call.kwargs["max_iterations"] == (7 if scope == "bounded" else 5)
               for call in generator.call_args_list)
    assert all(call.kwargs["require_context_sufficiency"] is
               (scope in {"one_seed", "full_nohint"})
               for call in generator.call_args_list)
    assert len(clients) == 2 and all(client.closed == 1 for client in clients)
    repos.functions.mark_analyzed_by_direction.assert_called_once_with(
        "function-2", "direction")
    outcomes = strategy._development_sp_scope["function_outcomes"]
    assert outcomes[0] == {
        "success": False, "function_name": "function-1",
        "function_id": "function-1", "direction_id": "direction",
        "opportunity_status": "NO_OPPORTUNITY_MAX_ITERATIONS",
        "model_turns": 1, "verified_read_only_tool_events": 1,
    }
    assert outcomes[1] == {
        "success": True, "function_name": "function-2",
        "function_id": "function-2", "direction_id": "direction",
        "opportunity_status": "ANALYZED_NO_SP_CONTEXT_SUFFICIENT",
        "context_sufficiency": "UNKNOWN", "analysis_result": "UNKNOWN",
        "model_turns": None, "created_sp_ids": [],
    }


def test_full_sp_created_at_iteration_limit_keeps_other_functions_running(tmp_path):
    """v9: an owned SP write in the final turn is a local partial outcome."""
    from devtools.campaign_model_gate import CampaignLedgeredProvider, CampaignModelGate

    gate = CampaignModelGate(tmp_path / "model-ledger.json", "run", 10, 60,
                             create=True)
    receipt_path = tmp_path / "created-sp.txt"
    receipt_bytes = json.dumps({"success": True, "created": True,
                                "id": "created-sp"}).encode()
    receipt_path.write_bytes(receipt_bytes)
    receipt_path.chmod(0o600)
    event = {"status": "COMPLETED", "name": "create_suspicious_point",
             "call_id": "call-id", "agent_id": "agent-1",
             "result_path": str(receipt_path),
             "result_sha256": hashlib.sha256(receipt_bytes).hexdigest()}
    row = {"owner_id": "direction:function-1:0", "role": "sp",
           "status": "COMPLETED", "request_id": "request-id",
           "tool_events": [event]}
    gate.snapshot = MagicMock(return_value={"records": [row]})
    gate.verify_response_evidence = MagicMock(return_value={"status": "VERIFIED"})
    gate.verify_tool_event = MagicMock(return_value={"status": "VERIFIED"})
    clients = []

    def factory(role, owner):
        client = FakeClient()
        client.last_agent_response_was_final = bool(clients)
        client.agent_id = "agent-1" if not clients else "agent-2"
        client.provider = CampaignLedgeredProvider(
            object(), gate, role=role, owner_id=owner)
        clients.append(client)
        return client

    strategy, repos = make_strategy(factory)
    strategy._full_nohint_sp = True
    strategy._development_sp_scope = {"status": "FULL_FUNCTION_POOL",
                                      "function_outcomes": []}
    strategy.num_parallel_agents = 1
    ledger = SimpleNamespace(snapshot=lambda: {"stop_status": None})
    strategy.executor.development_process_ledger = ledger
    strategy.executor.fuzzer_manager = SimpleNamespace(
        model_gate=gate, campaign=SimpleNamespace(ledger=ledger))
    candidate = SimpleNamespace(
        suspicious_point_id="created-sp", task_id="task",
        function_name="function-1", direction_id="direction",
        created_by_agent_id="agent-1", status="pending_verify",
        pipeline_incomplete_reason=None,
        sources=[{"harness_name": "fixture_fuzzer", "sanitizer": "address"}])
    repos.suspicious_points.find_by_id.return_value = candidate
    repos.functions.mark_analyzed_by_direction.return_value = True
    first_agent = SimpleNamespace(
        analyze_async=AsyncMock(return_value={"success": True, "sp_created": True}),
        stop_reason="max_iterations", sp_created=True,
        sp_details={"sp_id": "created-sp", "function_name": "function-1"},
        _context=SimpleNamespace(agent_id="agent-1"))
    second_agent = SimpleNamespace(
        analyze_async=AsyncMock(return_value={"success": True, "sp_created": False}),
        stop_reason=None, sp_created=False)
    functions = [SimpleNamespace(
        name=f"function-{i}", function_id=f"function-{i}",
        content="int f(void) { return 0; }", file_path="source.c",
        start_line=i, end_line=i + 1) for i in (1, 2)]
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator",
               side_effect=[first_agent, second_agent]):
        asyncio.run(strategy._run_function_batch(
            [(functions[0], "direction"), (functions[1], "direction")], None))

    repos.functions.mark_analyzed_by_direction.assert_called_once_with(
        "function-2", "direction")
    outcomes = strategy._development_sp_scope["function_outcomes"]
    assert outcomes[0] == {
        "success": False, "function_name": "function-1",
        "function_id": "function-1", "direction_id": "direction",
        "opportunity_status": "SP_CREATED_MAX_ITERATIONS",
        "model_turns": 1, "verified_tool_events": 1,
        "created_sp_ids": ["created-sp"],
    }
    assert outcomes[1] == {
        "success": True, "function_name": "function-2",
        "function_id": "function-2", "direction_id": "direction",
        "opportunity_status": "ANALYZED_NO_SP_CONTEXT_SUFFICIENT",
        "context_sufficiency": "UNKNOWN", "analysis_result": "UNKNOWN",
        "model_turns": None, "created_sp_ids": [],
    }
    assert len(clients) == 2 and all(c.closed == 1 for c in clients)

    # A saved candidate with the wrong owner cannot seal this local stop.
    candidate.created_by_agent_id = "another-agent"
    assert strategy._settled_created_sp_limit_verified(
        client=clients[0], agent=first_agent, role="sp",
        owner="direction:function-1:0", function_name="function-1",
        direction_id="direction") is None
    candidate.created_by_agent_id = "agent-1"
    event["result_sha256"] = "0" * 64
    assert strategy._settled_created_sp_limit_verified(
        client=clients[0], agent=first_agent, role="sp",
        owner="direction:function-1:0", function_name="function-1",
        direction_id="direction") is None
    event["result_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    row["status"] = "UNCERTAIN"
    assert strategy._settled_created_sp_limit_verified(
        client=clients[0], agent=first_agent, role="sp",
        owner="direction:function-1:0", function_name="function-1",
        direction_id="direction") is None
    row["status"] = "COMPLETED"
    row["role"] = clients[0].provider.role = "sp_large"
    window = {"status": "COMPLETED", "name": "get_next_function_window",
              "agent_id": "agent-1", "call_id": "window-call"}
    row["tool_events"].append(window)
    check_large = lambda: strategy._settled_created_sp_limit_verified(
        client=clients[0], agent=first_agent, role="sp_large",
        owner="direction:function-1:0", function_name="function-1",
        direction_id="direction")
    assert check_large() == (1, 2, ("created-sp",))
    window["status"] = "STARTED"
    assert check_large() is None
    window["status"] = "COMPLETED"
    window["name"] = "unrecognized_tool"
    assert check_large() is None
