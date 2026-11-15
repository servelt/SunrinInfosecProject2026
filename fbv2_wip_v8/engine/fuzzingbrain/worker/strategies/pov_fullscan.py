"""
POV Full-scan Strategy

Strategy for full-scan mode: analyzes all reachable functions for vulnerabilities.

Breadth-First Per-Direction Architecture:
1. Direction Planning: Divides call graph into logical directions (HIGH/MEDIUM/LOW risk)
2. SP Finding (breadth-first across directions):
   - Phase 1: Small Pool (unanalyzed) — core+entry functions, HIGH→MEDIUM→LOW
   - Phase 2: Small Pool (re-analyzed) — overlapping functions from other directions
   - Phase 3: Big Pool (unanalyzed) — reachable via call graph BFS, minus small pool
   - Phase 4: Big Pool (re-analyzed) — overlapping big pool functions
3. Parallel Pipeline: Verify SPs and generate POVs concurrently
"""

import asyncio
import hashlib
import inspect
import json
import math
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Callable, List, Optional

from .pov_base import POVBaseStrategy
from ...agents import (
    DirectionPlanningAgent,
    FullSPGenerator,
    LargeFullSPGenerator,
)
from ...agents.sp_generators import (
    generic_security_family_priority,
    generic_security_risk_priority,
)
from ...llms.models import CLAUDE_OPUS_4_5, CLAUDE_SONNET_4_5
from ...tools.directions import set_direction_context
from ...tools.suspicious_points import set_sp_context
from ...fuzzer import SeedAgent
from ...fuzzer.seed_sandbox import MAX_SEED_BYTES
from ..pipeline import (
    IncompleteInjectedAgent, injected_agent_client, require_injected_agent_complete,
    public_incomplete_reason,
)


def line_scaled_sp_iteration_limit(
        function_lines: int, policy: Dict[str, Any]) -> int:
    """Return the signed FullScan SP turn ceiling for one function.

    The ceiling is deliberately a maximum, not a target. Agents still stop as
    soon as they finish. Large functions use the same 100-line/20-line-overlap
    geometry as ``LargeFullSPGenerator`` so their allowance reflects the
    number of windows that can actually need inspection.
    """
    lines = max(1, function_lines)
    for threshold, key in ((100, "up_to_100"), (250, "up_to_250"),
                           (500, "up_to_500"), (1000, "up_to_1000"),
                           (2000, "up_to_2000")):
        if lines <= threshold:
            return policy[key]
    window_lines = policy["large_window_lines"]
    step = window_lines - policy["large_window_overlap"]
    windows = 1 + math.ceil(max(0, lines - window_lines) / step)
    return min(policy["large_max"], max(
        policy["up_to_2000"],
        policy["large_base"] + policy["large_turns_per_window"] * windows))


@dataclass(frozen=True)
class _VerifiedBoundedSPExhaustion:
    """Private in-process marker; never represents an analyzed or safe function."""

    function_id: str
    owner_id: str
    created_sp_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ContextInsufficientSPAnalysis:
    """A local no-SP result whose required input context remains unproven."""

    function_id: str
    owner_id: str


@dataclass(frozen=True)
class _VerifiedGateEarlyStop:
    """A queued function skipped after a product Gate verified stop."""


@dataclass(frozen=True)
class _GracefulUserStop:
    """A queued function never started after graceful stop admission closed."""


@dataclass(frozen=True)
class _DownstreamReserveStop:
    """A queued function was not started to preserve signed downstream budget."""

    function_id: str


class POVFullscanStrategy(POVBaseStrategy):
    """
    POV Strategy for Full-scan mode with streaming pipeline.

    All agent pools run concurrently:
    1. Direction Planning Agent: Divides call graph into logical directions
    2. SP Find Pool: Analyze directions, create SPs
    3. Verify Pool: Verify SPs as they are created
    4. POV Pool: Generate POVs for verified SPs
    """

    def __init__(
        self,
        executor,
        use_pipeline: bool = True,
        num_parallel_agents: int = 5,
        llm_client_factory: Optional[Callable[[str, str], Any]] = None,
    ):
        """
        Initialize POV Full-scan Strategy.

        Args:
            executor: WorkerExecutor instance
            use_pipeline: Whether to use parallel pipeline (default: True)
            num_parallel_agents: Number of concurrent SP Find agents (default: 5)
            llm_client_factory: Optional process-local (role, owner_id) factory;
                each call must return a fresh async-closeable client.
        """
        super().__init__(executor, use_pipeline)
        self.num_parallel_agents = num_parallel_agents
        self.llm_client_factory = llm_client_factory
        self._sp_finding_done = asyncio.Event()  # Signal when SP finding is complete
        self._development_direction_plan = None
        self._direction_seed_phase = None
        self._development_auto_scope = None
        self._development_seed_limit = None
        self._development_sp_scope = None
        self._development_sp_queue_drain = False
        # Scheduling and High-Recall admission are separate contracts. The
        # legacy signed diagnostic drains per candidate; this opt-in streams
        # durable candidates to the existing Verifier/PoV worker pools.
        self._development_sp_concurrent_queue = False
        self._development_verify_agents = 2
        self._development_pov_agents = 2
        self._development_security_invariant_focus = None
        self._development_pov_attempts_per_candidate = None
        self._development_sp_start_envelope = None
        self._development_sp_reserve_exhausted = False
        self._full_nohint_sp = False
        self._user_stop_requested = threading.Event()

    def request_graceful_stop(self) -> None:
        """Stop queue admission while allowing owned turns to settle."""
        event = getattr(self, "_user_stop_requested", None)
        if event is None:
            event = self._user_stop_requested = threading.Event()
        event.set()
        pipeline = getattr(self, "_active_pipeline", None)
        if pipeline is not None:
            pipeline.request_graceful_stop_from_signal()

    def _user_stop_is_set(self) -> bool:
        event = getattr(self, "_user_stop_requested", None)
        return bool(event is not None and event.is_set())

    def _gate_verified_stop_requested(self) -> bool:
        gate_stop = getattr(self.executor, "qualified_gate_stop", None)
        return bool(getattr(self, "_full_nohint_sp", False) and
                    gate_stop is not None and
                    gate_stop.verified.is_set())

    @property
    def strategy_name(self) -> str:
        return "POV Fullscan Strategy (Streaming)"

    def _find_suspicious_points(self) -> List:
        """
        Not used in Full-scan strategy.

        Full-scan uses a streaming pipeline with Direction Planning and
        parallel SP finding, which bypasses this method entirely.
        The execute() method is overridden to implement the full pipeline.
        """
        return []

    def _directions_from_this_planning_call(self, result: Dict[str, Any]) -> List:
        """Never run an earlier pending plan after a zero/partial new plan."""
        ids = result.get("direction_ids")
        count = result.get("directions_created")
        if (not isinstance(ids, list) or not ids or
                not isinstance(count, int) or count != len(ids) or
                any(not isinstance(value, str) or not value for value in ids) or
                len(set(ids)) != len(ids)):
            return []
        pending = self.repos.directions.find_pending(self.task_id, self.fuzzer)
        by_id = {direction.direction_id: direction for direction in pending}
        if any(direction_id not in by_id for direction_id in ids):
            return []
        return [by_id[direction_id] for direction_id in ids]

    def execute(self) -> Dict[str, Any]:
        """
        Execute streaming pipeline - all pools run concurrently.

        Returns:
            Result dictionary with findings
        """
        start_time = time.time()

        self.log_info(f"========== {self.strategy_name} Start ==========")
        self.log_info(f"Fuzzer: {self.fuzzer}, Mode: {self.scan_mode}")

        result = {
            "strategy": self.strategy_name,
            "scan_mode": self.scan_mode,
            "reachable": True,
            "suspicious_points_found": 0,
            "suspicious_points_verified": 0,
            "verifier_processed": 0,
            "crash_observed": 0,
            "gate_verified": 0,
            "high_confidence_bugs": 0,
            "high_priority_candidates": 0,
            "pov_generated": 0,
        }

        try:
            # Run everything in a single event loop to avoid litellm client caching issues
            set_direction_context(self.fuzzer)
            pipeline_stats = asyncio.run(self._run_full_pipeline())

            # Collect results
            all_points = self.repos.suspicious_points.find_by_task(self.task_id)
            result["suspicious_points_found"] = len(all_points)
            result["verifier_processed"] = pipeline_stats.sp_verified
            result["pov_generated"] = pipeline_stats.pov_generated
            result["gate_verified_early_stop"] = (
                self._gate_verified_stop_requested())
            result["gate_verified"] = int(
                result["gate_verified_early_stop"])
            result["suspicious_points_verified"] = result["gate_verified"]
            result["crash_observed"] = pipeline_stats.pov_pending_validation
            if getattr(self.executor, "parallel_hp_async_factory", None) is not None:
                hp_row = getattr(self, "_parallel_hp_result", None)
                if (type(hp_row) is not dict or
                        hp_row.get("kind") !=
                            "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1" or
                        type(hp_row.get("status")) is not str or
                        hp_row.get("status") not in {
                            "HP_PARALLEL_ANALYSIS_COMPLETE",
                            "HP_PARALLEL_ANALYSIS_INCOMPLETE",
                            "HP_PARALLEL_ANALYSIS_BLOCKED"} or
                        hp_row.get("security_gate_credit") != "NOT_CREDITED" or
                        hp_row.get("discovery_credit") != "NOT_CREDITED"):
                    raise RuntimeError("parallel HP analysis result is invalid")
                # This is a diagnostic handoff. The public join must reread
                # the pinned HP artifact before assigning any result credit.
                result["parallel_hp_analysis"] = {
                    "status": hp_row["status"],
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED",
                }
            if self._direction_seed_phase is not None:
                result["direction_seed_phase"] = self._direction_seed_phase
            if self._development_sp_scope is not None:
                result["analysis_scope"] = self._development_sp_scope

            # Priority is a queue hint, not a verified vulnerability.
            incomplete = {"pending_budget", "pending_stop",
                          "incomplete_uncertain"}
            high_conf = [p for p in all_points
                         if p.status not in incomplete and
                         (p.is_important or p.score >= 0.9)]
            result["high_priority_candidates"] = len(high_conf)
            result["high_confidence_bugs"] = result["gate_verified"]

            # Save results
            sorted_points = self._sort_by_priority(all_points)
            self._save_results(sorted_points)

            total_time = time.time() - start_time
            self.log_info(f"========== {self.strategy_name} Complete ==========")
            self.log_info(f"Total time: {total_time:.1f}s")
            self.log_info(
                f"Results: {result['suspicious_points_found']} found, "
                f"{result['verifier_processed']} verifier-processed, "
                f"{result['suspicious_points_verified']} Gate-verified, "
                f"{result['pov_generated']} POV generated"
            )

            return result

        except Exception as e:
            self.log_error(f"Strategy failed: {e}")
            raise

    def _run_direction_planning(self) -> List:
        """Run direction planning phase."""
        if self.llm_client_factory is not None:
            # The injected client has an async lifecycle. Use the same original
            # planning agent through the async path so it is always closed.
            return asyncio.run(self._run_direction_planning_async())
        self.log_info("=== Phase 1: Direction Planning ===")
        phase1_start = time.time()

        fuzzer_code = self._get_fuzzer_source_code()
        reachable_count = self._get_reachable_function_count()

        self.log_info(f"Fuzzer: {self.fuzzer}, Reachable functions: {reachable_count}")

        agent_log_dir = self.agent_log_dir
        planning_agent = DirectionPlanningAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            model=CLAUDE_OPUS_4_5,  # Force Opus for direction planning
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            max_iterations=100,
        )

        try:
            result = planning_agent.plan_directions_sync(
                fuzzer_code=fuzzer_code,
                reachable_count=reachable_count,
            )
            self.log_info(
                f"Direction planning completed: {result.get('directions_created', 0)} directions"
            )
        except Exception as e:
            self.log_error(f"Direction planning failed: {e}")
            return []

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        return self._directions_from_this_planning_call(result)

    async def _run_direction_planning_async(self) -> List:
        """Run direction planning phase asynchronously."""
        self._development_direction_plan = None
        self.log_info("=== Phase 1: Direction Planning ===")
        phase1_start = time.time()

        fuzzer_code = self._get_fuzzer_source_code()
        reachable_count = self._get_reachable_function_count()

        self.log_info(f"Fuzzer: {self.fuzzer}, Reachable functions: {reachable_count}")

        agent_log_dir = self.agent_log_dir
        try:
            async with injected_agent_client(
                self.llm_client_factory, "direction", self.worker_id
            ) as client:
                planning_agent = DirectionPlanningAgent(
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    llm_client=client,
                    model=CLAUDE_OPUS_4_5,  # Original planning model by default
                    task_id=self.task_id,
                    worker_id=self.worker_id,
                    log_dir=agent_log_dir,
                    max_iterations=100,
                )
                result = await planning_agent.plan_directions_async(
                    fuzzer_code=fuzzer_code,
                    reachable_count=reachable_count,
                )
                direction_ids = result.get("direction_ids")
                max_directions = getattr(planning_agent, "max_directions", 5)
                required_directions = max_directions
                if isinstance(self._development_auto_scope, dict):
                    bounded_widths = [
                        self._development_auto_scope.get("seed_directions"),
                        self._development_auto_scope.get("sp_functions"),
                    ]
                    if all(type(value) is int and value > 0
                           for value in bounded_widths):
                        required_directions = min(
                            max_directions,
                            max(bounded_widths))
                budget_terminal = (
                    planning_agent.stop_reason == "budget_before_transport" and
                    type(result.get("directions_created")) is int and
                    required_directions <= result["directions_created"] <=
                        max_directions and
                    isinstance(direction_ids, list) and
                    len(direction_ids) == result["directions_created"] and
                    len(set(direction_ids)) == len(direction_ids) and
                    all(isinstance(value, str) and value
                        for value in direction_ids)
                )
                if not budget_terminal:
                    require_injected_agent_complete(client, planning_agent)
                else:
                    self.log_info(
                        "Direction plan completed by enough verified tool writes "
                        "for the signed bounded breadth; "
                        "the untransported final-text request hit its local cap")
                if getattr(self.executor, "require_original_global_bridge", False):
                    # The plan is derived from the actual original Agent tool
                    # results and the matching pending DB rows, before Seed
                    # Agents are allowed to create any corpus files.
                    from devtools.original_global_bridge import (
                        export_completed_direction_plan,
                    )
                    self._development_direction_plan = export_completed_direction_plan(
                        repos=self.repos, task_id=self.task_id,
                        fuzzer=self.fuzzer,
                        agent_id=planning_agent.mcp_context_id,
                        agent_result=result,
                        agent_final=(
                            (client.last_agent_response_was_final is True and
                             planning_agent.stop_reason is None) or
                            budget_terminal),
                        output_path=self.results_path / "DIRECTION_PLAN.json",
                    )
            self.log_info(
                f"Direction planning completed: {result.get('directions_created', 0)} directions"
            )
        except Exception as e:
            self.log_error(f"Direction planning failed: {e}")
            if self.llm_client_factory is not None:
                if isinstance(e, IncompleteInjectedAgent):
                    raise
                raise IncompleteInjectedAgent(
                    str(e), reason=getattr(e, "fbv2_stop_reason", "incomplete_unknown")
                ) from e
            return []

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        return self._directions_from_this_planning_call(result)

    async def _run_full_pipeline(self):
        """
        Run the full pipeline in a single event loop.

        This includes:
        1. Direction Planning (async)
        2. Direction Seeds generation + Global Fuzzer startup
        3. SP Finding (breadth-first per-direction architecture)

        Running everything in one event loop avoids litellm client caching issues
        where HTTP clients get bound to a closed event loop.
        """
        # Phase 1: Direction Planning
        directions = await self._run_direction_planning_async()

        if not directions:
            if self.llm_client_factory is not None:
                raise RuntimeError("injected Direction planning did not complete")
            self.log_warning("No directions created, cannot continue")
            # Return empty stats
            from ..pipeline import PipelineStats

            return PipelineStats()

        parallel_hp_factory = getattr(
            self.executor, "parallel_hp_async_factory", None)
        if (parallel_hp_factory is not None and
                not inspect.iscoroutinefunction(parallel_hp_factory)):
            raise RuntimeError("parallel HP factory must be async")
        bridge = None
        if getattr(self.executor, "require_original_global_bridge", False):
            factory = self.executor.original_global_bridge_factory
            if not callable(factory) or self._development_direction_plan is None:
                raise RuntimeError("qualified development Global bridge is missing")
            plan_path, plan_sha256 = self._development_direction_plan
            bridge = factory(plan_path, plan_sha256)
            self.executor.install_original_global_bridge(
                bridge, plan_path=plan_path, plan_sha256=plan_sha256)

        # A separately admitted parallel profile may install a bound HP
        # coroutine after shared Direction preparation. It runs on this
        # main-thread loop alongside SP model transports. The historical
        # post-Worker profile installs no factory.
        parallel_hp_task = None
        if parallel_hp_factory is not None:
            parallel_hp_task = asyncio.create_task(
                parallel_hp_factory(self, directions),
                name="parallel_hp_track")

        # Phase 2+: SP Finding with breadth-first per-direction architecture
        try:
            self.log_info(
                f"=== SP Find: Breadth-First Per-Direction ({len(directions)} directions) ==="
            )
            stats = await self._run_v2_pipeline_with_fuzzer_init(directions)
        except BaseException as original:
            if bridge is not None:
                try:
                    # A failure in SP, PoV, or the caller does not erase
                    # observations from an already running, independently
                    # guarded Global campaign. Normal settlement consumes
                    # those inputs when its pinned authority remains valid;
                    # the product campaign itself refuses unsafe reports.
                    if bridge._started:
                        await bridge.stop_global_fuzzer()
                    else:
                        await bridge.abort()
                except BaseException as cleanup:
                    original.add_note(
                        "development Global settlement failed: "
                        f"{type(cleanup).__name__}: {cleanup}")
                    if bridge._started:
                        try:
                            await bridge.abort()
                        except BaseException as abort_error:
                            original.add_note(
                                "development Global abort after settlement failed: "
                                f"{type(abort_error).__name__}: {abort_error}")
                if (not bridge._started and
                        (bridge.final_result is None or
                         bridge.final_result.get("cleanup_complete") is True)):
                    try:
                        self.executor.release_original_global_bridge(bridge)
                    except BaseException as cleanup:
                        original.add_note(
                            "development Global registry release failed: "
                            f"{type(cleanup).__name__}: {cleanup}")
            if parallel_hp_task is not None:
                try:
                    self._parallel_hp_result = await parallel_hp_task
                except BaseException as hp_error:
                    original.add_note(
                        "parallel HP settlement failed: "
                        f"{type(hp_error).__name__}: {hp_error}")
            raise
        if bridge is not None:
            try:
                await bridge.stop_global_fuzzer()
            except BaseException as original:
                if bridge._started:
                    try:
                        await bridge.abort()
                    except BaseException as cleanup:
                        original.add_note(
                            "development Global abort after finish failed: "
                            f"{type(cleanup).__name__}: {cleanup}")
                if (not bridge._started and
                        (bridge.final_result is None or
                         bridge.final_result.get("cleanup_complete") is True)):
                    try:
                        self.executor.release_original_global_bridge(bridge)
                    except BaseException as cleanup:
                        original.add_note(
                            "development Global registry release failed: "
                            f"{type(cleanup).__name__}: {cleanup}")
                if parallel_hp_task is not None:
                    try:
                        self._parallel_hp_result = await parallel_hp_task
                    except BaseException as hp_error:
                        original.add_note(
                            "parallel HP settlement failed: "
                            f"{type(hp_error).__name__}: {hp_error}")
                raise
            try:
                self.executor.release_original_global_bridge(bridge)
            except BaseException as original:
                if parallel_hp_task is not None:
                    try:
                        self._parallel_hp_result = await parallel_hp_task
                    except BaseException as hp_error:
                        original.add_note(
                            "parallel HP settlement failed: "
                            f"{type(hp_error).__name__}: {hp_error}")
                raise
        if parallel_hp_task is not None:
            self._parallel_sp_stats = stats
            try:
                self._parallel_hp_result = await parallel_hp_task
            except Exception as hp_error:
                self._parallel_hp_result = {
                    "status": "HP_PARALLEL_ANALYSIS_INCOMPLETE",
                    "error_type": type(hp_error).__name__,
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED",
                }
                raise
        return stats

        # Note: Buffer is NOT stopped here - it's shared across tasks
        # Buffer shutdown happens when Celery worker exits

    async def _run_v2_pipeline_with_fuzzer_init(self, directions: List):
        """
        Wrapper that initializes fuzzer (Direction Seeds + Global Fuzzer)
        before running the v2 pipeline.

        This ensures all async operations run in the same event loop.
        """
        # Generate Direction Seeds and start Global Fuzzer first
        await self._generate_direction_seeds_and_start_global_fuzzer(directions)

        # Then run the v2 pipeline
        return await self._run_v2_pipeline(directions)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _get_fuzzer_source_code(self) -> str:
        """Get the exact selected fuzzer source for Full-scan context."""
        try:
            from ...analyzer import AnalysisClient

            if not self.executor.analysis_socket_path:
                return ""

            client = AnalysisClient(
                self.executor.analysis_socket_path,
                client_id=f"fullscan_strategy_{self.worker_id}",
            )

            result = client.get_fuzzer_source(self.fuzzer)
            if (isinstance(result, dict) and
                    result.get("fuzzer") == self.fuzzer and
                    isinstance(result.get("source"), str) and
                    result["source"]):
                return result["source"]

            return ""
        except Exception as e:
            self.log_warning(f"Could not get fuzzer source code: {e}")
            return ""

    def _get_unique_caller_source(self, caller_name: str) -> str:
        """Return a caller body only when its pinned source identity is unique.

        The legacy function collection is keyed by name and can collapse
        duplicate static symbols.  Before preloading a body, scan the pinned
        repository conservatively and require exactly one definition bearing
        the name, in the catalogued file, with the catalogued bytes present.
        Ambiguity or any unscannable eligible file fails closed.
        """
        if re.fullmatch(r"[A-Za-z_]\w*", caller_name or "") is None:
            return ""
        caller = self.repos.functions.find_by_name(self.task_id, caller_name)
        source = str(getattr(caller, "content", "") or "")
        file_path = str(getattr(caller, "file_path", "") or "")
        workspace = getattr(self.executor, "task_workspace_path", None)
        repo = Path(workspace) / "repo" if workspace is not None else None
        if not source or not file_path or repo is None or not repo.is_dir():
            return ""
        repo = repo.resolve()
        selected = (repo / file_path).resolve(strict=False)
        if repo not in selected.parents or not selected.is_file():
            return ""
        definition = re.compile(
            # Deliberately over-approximate the post-parameter C++ suffix.
            # Missing a duplicate is unsafe; treating a call/control construct
            # as ambiguous merely omits optional preload context.
            rf"\b{re.escape(caller_name)}\b"
            rf"(?:\s+[A-Za-z_]\w*)*\s*\([^;{{}}]*\)[^;{{}}]*\{{",
            re.DOTALL,
        )
        matches: list[Path] = []
        files_seen = 0
        from ...analyzer.prebuilt_adapter import _strip_c_comments_and_literals
        for path in sorted(repo.rglob("*")):
            if path.is_symlink():
                return ""
            if path.suffix.lower() not in {
                    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp",
                    ".inc", ".inl", ".def", ".ipp", ".tpp", ".txx",
                    ".ixx", ".hxx", ".h++", ".c++", ".m", ".mm",
                    ".cu", ".cuh"}:
                continue
            files_seen += 1
            if files_seen > 4096:
                return ""
            try:
                if not path.is_file() or path.stat().st_size > 2_000_000:
                    return ""
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""
            # Match structure on a byte-position-preserving mask so braces or
            # semicolons in default arguments, attributes, comments and string
            # literals cannot hide a duplicate definition.
            masked = _strip_c_comments_and_literals(text)
            # Apply translation-phase line splicing before scanning the
            # declarator shape; otherwise ``helper\\\n(`` evades the exact
            # identifier/parameter boundary.
            masked = re.sub(r"(?:\\|\?\?/)\r?\n", "", masked)
            found = list(definition.finditer(masked))
            if found:
                matches.extend([path.resolve()] * len(found))
                if len(matches) > 1:
                    return ""
        try:
            selected_text = selected.read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if matches != [selected] or source not in selected_text:
            return ""
        return source

    def _get_initial_sp_source_context(
        self, callers: List[str]
    ) -> tuple[str, Dict[str, str]]:
        """Return bounded, already-pinned source context for one SP analysis.

        ``FullSPGenerator`` has always supported an entry-point source and up
        to three caller sources, but the full-scan path did not connect those
        inputs.  That forced the model to spend its bounded evidence turns
        rediscovering source already present in the task's imported catalog.
        Keep this target-independent: use only the selected fuzzer and the
        recorded direct callers, and let the generator apply its existing
        rendering bounds.
        """
        fuzzer_source = self._get_fuzzer_source_code()
        caller_sources: Dict[str, str] = {}
        for caller_name in callers[:3]:
            source = self._get_unique_caller_source(caller_name)
            if source:
                caller_sources[caller_name] = source
        return fuzzer_source, caller_sources

    def _get_reachable_function_count(self) -> int:
        """Get count of functions reachable from fuzzer."""
        try:
            from ...analyzer import AnalysisClient

            if not self.executor.analysis_socket_path:
                return 0

            client = AnalysisClient(
                self.executor.analysis_socket_path,
                client_id=f"fullscan_strategy_{self.worker_id}",
            )

            functions = client.get_reachable_functions(self.fuzzer)
            return len(functions) if functions else 0
        except Exception as e:
            self.log_warning(f"Could not get reachable function count: {e}")
            return 0

    # =========================================================================
    # SP Find v2: Breadth-First Per-Direction Architecture
    # =========================================================================

    async def _run_v2_pipeline(self, directions: List):
        """
        Run SP Find v2 per-direction pipeline with streaming verification.

        For each direction (sorted HIGH → MEDIUM → LOW):
          1. Analyze small pool (core_functions + entry_functions) - unanalyzed first
          2. Analyze big pool (reachable via call graph - small pool) - unanalyzed first
          Overlapping functions are re-analyzed from each direction's perspective.

        Priority within each direction:
          1. Small pool, not yet analyzed by any direction (highest)
          2. Small pool, already analyzed by another direction
          3. Big pool, not yet analyzed by any direction
          4. Big pool, already analyzed by another direction (lowest)

        Returns:
            PipelineStats with execution statistics
        """
        from ..pipeline import AgentPipeline, PipelineConfig
        from ...tools.coverage import set_coverage_context, get_coverage_context

        # Setup coverage context
        coverage_fuzzer_dir, _, _ = get_coverage_context()
        if coverage_fuzzer_dir:
            set_coverage_context(
                coverage_fuzzer_dir=coverage_fuzzer_dir,
                project_name=self.project_name,
                src_dir=self.executor.task_workspace_path / "repo",
                docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
                work_dir=self.results_path / "coverage_work",
            )

        fuzzer_code = self._get_fuzzer_source_code()
        agent_log_dir = self.agent_log_dir

        # Configure pipeline for verification and POV
        bounded = getattr(self, "_development_auto_scope", None) is not None
        concurrent_queue = bool(
            getattr(self, "_development_sp_concurrent_queue", False) and
            self.llm_client_factory is not None)
        if self._development_sp_queue_drain and concurrent_queue:
            raise RuntimeError("SP queue policies are mutually exclusive")
        if concurrent_queue and any(
                type(value) is not int or not 1 <= value <= 8
                for value in (
                    self.num_parallel_agents,
                    self._development_verify_agents,
                    self._development_pov_agents)):
            raise RuntimeError("concurrent SP worker counts are invalid")
        prefer_pov = bool((self._development_sp_queue_drain or
                           concurrent_queue) and
                          self.llm_client_factory is not None)
        configured_candidate_attempts = getattr(
            self, "_development_pov_attempts_per_candidate", None)
        candidate_attempts = (
            configured_candidate_attempts
            if prefer_pov and
            configured_candidate_attempts is not None
            else 20)
        config = PipelineConfig(
            num_verify_agents=(
                self._development_verify_agents if concurrent_queue else
                1 if bounded or prefer_pov else 5),
            num_pov_agents=(
                self._development_pov_agents if concurrent_queue else
                1 if bounded or prefer_pov else 5),
            pov_min_score=0.5,
            pov_admission_mode=(
                "explicit_disposition" if prefer_pov else "legacy_score"),
            poll_interval=2.0,
            max_idle_cycles=30,
            max_pov_attempts=candidate_attempts,
            fuzzer_path=self.executor.fuzzer_binary_path,
            docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
            # Injected public-development PoVs are generated by the qualified
            # seed sandbox. Tell the Verifier its real per-input ceiling so a
            # trigger that provably needs a larger input is not sent to PoV.
            pov_input_bytes_max=(
                MAX_SEED_BYTES if self.llm_client_factory is not None else None
            ),
        )
        # Record the executed policy so post-Worker lineage uses the same
        # signed admission rule instead of inferring it from candidate fields.
        self.executor.development_pov_admission_mode = config.pov_admission_mode

        pipeline = AgentPipeline(
            task_id=self.task_id,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode="full",
            config=config,
            output_dir=self.results_path / "povs",
            log_dir=self.agent_log_dir,
            workspace_path=self.executor.task_workspace_path,
            fuzzer_code=fuzzer_code,
            mcp_socket_path=self.executor.analysis_socket_path,
            worker_id=self.worker_id,
            llm_client_factory=self.llm_client_factory,
            qualified_runtime_binding=getattr(
                self.executor, "qualified_pov_runtime_binding", None),
            qualified_gate_stop=getattr(
                self.executor, "qualified_gate_stop", None),
        )
        self._active_pipeline = pipeline

        # The signed bounded run drains the original queues after SP finding,
        # so its model/tool turns cannot race with a later SP turn.
        pipeline.serial_bounded_dev = bounded and not concurrent_queue
        pipeline.prefer_pov_after_verify = (
            prefer_pov and not concurrent_queue)
        pipeline_task = (None if pipeline.serial_bounded_dev else asyncio.create_task(
            pipeline.run(), name="verify_pov_pipeline"))
        self._active_pipeline_task = pipeline_task

        # Sort directions: HIGH → MEDIUM → LOW
        risk_order = {"high": 0, "medium": 1, "low": 2}
        sorted_directions = self._sort_directions_for_campaign(
            directions, risk_order)

        self.log_info(
            f"=== SP Find v2: Processing {len(sorted_directions)} directions ==="
        )
        for i, d in enumerate(sorted_directions):
            self.log_info(
                f"  Direction {i + 1}: {d.name} [{d.risk_level}] "
                f"(core={len(d.core_functions or [])}, "
                f"entry={len(d.entry_functions or [])})"
            )

        # Build per-direction pools
        direction_pools = self._build_direction_pools(sorted_directions)

        if ((self._full_nohint_sp or bounded or
             self._development_sp_queue_drain or
             getattr(self, "_development_sp_concurrent_queue", False)) and
                self.llm_client_factory is not None):
            # Preserve the model's order as a tie-breaker, but spend the
            # bounded breadth budget first on functions whose own pinned source
            # exposes more sanitizer-relevant operations.  The score is a
            # generic lexical inventory: no target/function/input identity is
            # part of it, and it never creates or verifies an SP.
            for direction, pools in direction_pools:
                ordered_names = list(dict.fromkeys(
                    [*(direction.core_functions or []),
                     *(direction.entry_functions or [])]))
                order = {name: index for index, name in
                         enumerate(ordered_names)}
                for phase_key in ("small/new", "small/re", "big/new", "big/re"):
                    pools[phase_key].sort(key=lambda func: (
                        -self._function_campaign_priority(func),
                        order.get(func.name, len(order)), func.name,
                        str(getattr(func, "file_path", "")),
                        int(getattr(func, "start_line", 0) or 0)))

        # Run breadth-first: pool type > risk level > new/re-analyzed
        # Phase 1: All small pools (unanalyzed) - breadth across directions
        # Phase 2: All small pools (re-analyzed) - breadth across directions
        # Phase 3: All big pools (unanalyzed) - breadth across directions
        # Phase 4: All big pools (re-analyzed) - breadth across directions
        phase_labels = [
            ("small/new", "Small Pool - Unanalyzed"),
            ("small/re", "Small Pool - Re-analyzed"),
            ("big/new", "Big Pool - Unanalyzed"),
            ("big/re", "Big Pool - Re-analyzed"),
        ]

        # Pre-compute grand total for consistent log display
        grand_total = 0
        for _, pools in direction_pools:
            for (
                key,
                _,
            ) in phase_labels:
                grand_total += len(pools.get(key, []))

        bounded_work = None
        nohint_phase_work = None
        if bounded:
            plan = self._development_direction_plan
            if (not isinstance(plan, tuple) or len(plan) != 2 or
                    not isinstance(plan[1], str) or len(plan[1]) != 64):
                raise RuntimeError("bounded automatic SP selection lacks pinned Direction plan")
            all_work = []
            seen_functions = set()
            selected = []
            bounded_work = {phase_key: [] for phase_key, _ in phase_labels}
            for phase_key, _ in phase_labels:
                phase_work = self._bounded_phase_work_for_directions(
                    direction_pools, phase_key)
                for func, direction_id in phase_work:
                    function_id = str(getattr(func, "function_id", ""))
                    if not function_id:
                        raise RuntimeError("bounded SP function identity is absent")
                    all_work.append(function_id)
                    if (function_id in seen_functions or
                            len(selected) >= self._development_auto_scope["sp_functions"]):
                        continue
                    seen_functions.add(function_id)
                    bounded_work[phase_key].append((func, direction_id))
                    selected.append({
                        "function_id": function_id,
                        "function_name": str(func.name),
                        "file_path": str(func.file_path),
                        "start_line": int(func.start_line),
                        "direction_id": direction_id,
                        "phase": phase_key,
                        "generic_security_risk": generic_security_risk_priority(
                            str(getattr(func, "content", "") or ""),
                            self.sanitizer,
                        ),
                    })
            self._development_sp_scope = {
                "kind": "BOUNDED_NOHINT_SELECTION_V1",
                "status": "PARTIAL_SCOPE" if selected else "NO_FUNCTION_SELECTED",
                "task_id": self.task_id,
                "run_id": getattr(self.executor, "development_run_id", None),
                "selection": "DIRECTION_RISK_PHASE_GENERIC_SURFACE_MODEL_TIE_V4",
                "direction_plan_sha256": plan[1],
                "candidate_occurrences": len(all_work),
                "distinct_function_count": len(set(all_work)),
                "selected_functions": selected,
                "function_limit": self._development_auto_scope["sp_functions"],
            }

            receipt_path = self.results_path / "BOUNDED_AUTO_SELECTION.json"
            content = (json.dumps(self._development_sp_scope, sort_keys=True) +
                       "\n").encode()
            fd = os.open(receipt_path,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
            with os.fdopen(fd, "wb") as receipt:
                receipt.write(content)
                receipt.flush()
                os.fsync(receipt.fileno())
            parent_fd = os.open(receipt_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self._development_sp_scope["selection_receipt_path"] = str(receipt_path)
            self._development_sp_scope["selection_receipt_sha256"] = (
                hashlib.sha256(content).hexdigest())
            self.log_info("Bounded automatic SP selection: " +
                          json.dumps(self._development_sp_scope, sort_keys=True))
            if not selected:
                raise RuntimeError("bounded no-hint SP scope selected no functions")
            grand_total = len(selected)
        elif ((self._full_nohint_sp or
               self._development_security_invariant_focus is not None) and
              self.llm_client_factory is not None):
            # Historical FullScan intentionally re-analyzed a function once
            # per Direction. A no-hint breadth campaign instead measures
            # unique function coverage. Keep one identity set across all four
            # phases so a function cannot reappear after moving from one
            # Direction's small pool to another Direction's reachable pool.
            nohint_phase_work = self._unique_phase_work_plan(
                direction_pools, [key for key, _ in phase_labels])
            grand_total = sum(len(work) for work in nohint_phase_work.values())
            self._sp_function_selection_receipt = (
                self._write_sp_function_selection_receipt(
                    direction_pools,
                    [key for key, _ in phase_labels],
                    nohint_phase_work,
                )
            )
            self._bind_sp_function_selection_receipt(
                self._sp_function_selection_receipt)

        try:
            global_index = 0
            for phase_key, phase_label in phase_labels:
                if self._user_stop_is_set():
                    break
                self._require_pipeline_active_during_sp()
                phase_start = time.time()
                if bounded_work is not None:
                    phase_work = bounded_work[phase_key]
                elif nohint_phase_work is not None:
                    phase_work = nohint_phase_work[phase_key]
                else:
                    phase_work = self._phase_work_for_directions(
                        direction_pools, phase_key)

                if not phase_work:
                    self.log_info(f"=== {phase_label}: 0 functions, skipping ===")
                    continue

                self.log_info(f"=== {phase_label}: {len(phase_work)} functions ===")
                await self._run_function_batch(
                    work=phase_work,
                    agent_log_dir=agent_log_dir,
                    global_index_start=global_index,
                    grand_total=grand_total,
                )
                if self._user_stop_is_set():
                    break
                if self._gate_verified_stop_requested():
                    self.log_info("Product Gate VERIFIED; settled active SP turns and stopped queued work")
                    break
                self._require_pipeline_active_during_sp()
                global_index += len(phase_work)
                self.log_info(
                    f"  {phase_label} completed in {time.time() - phase_start:.1f}s"
                )

            if (self._gate_verified_stop_requested() and
                    self._development_sp_scope is not None):
                self._development_sp_scope["status"] = "GATE_VERIFIED_EARLY_STOP"

            # Log coverage report
            self._log_coverage_report(sorted_directions)

            # Signal pipeline that SP finding is complete
            self._sp_finding_done.set()
            pipeline._sp_finding_done = True
            self.log_info("Bounded SP selection completed, draining queues..."
                          if bounded else
                          "SP Find v2 completed, waiting for pipeline to drain...")

            pipeline_result = (await pipeline.run()
                               if pipeline_task is None else
                               await pipeline_task)
            if self._user_stop_is_set():
                raise IncompleteInjectedAgent(
                    "user stop drained active model turns and queued work was not started",
                    reason="user_stop_settled")
            return pipeline_result
        except BaseException:
            pipeline.shutdown()
            if pipeline_task is not None:
                pipeline_task.cancel()
                try:
                    await pipeline_task
                except BaseException:
                    pass  # Preserve the original SP/pipeline failure.
            raise
        finally:
            self._active_pipeline_task = None
            self._active_pipeline = None

    def _function_campaign_priority(self, func) -> int:
        """Return the signed generic breadth priority for one function."""
        source = str(getattr(func, "content", "") or "")
        family = getattr(self, "_development_security_invariant_focus", None)
        if family is not None:
            return generic_security_family_priority(
                source, self.sanitizer, family)["family_score"]
        return generic_security_risk_priority(source, self.sanitizer)["score"]

    def _direction_campaign_priority(self, direction) -> tuple[int, int]:
        """Aggregate family/source risk without using target identities."""
        values = []
        names = dict.fromkeys([
            *(direction.core_functions or []),
            *(direction.entry_functions or []),
        ])
        for name in names:
            func = self.repos.functions.find_by_name(self.task_id, name)
            if func is not None:
                values.append(self._function_campaign_priority(func))
        values.sort(reverse=True)
        return (values[0] if values else 0, sum(values[:3]))

    def _sort_directions_for_campaign(self, directions, risk_order=None):
        """Use model risk, then generic source risk, then model order."""
        risk_order = risk_order or {"high": 0, "medium": 1, "low": 2}
        if (self.llm_client_factory is None or
                getattr(self, "_development_security_invariant_focus",
                        None) is None):
            return sorted(
                directions, key=lambda d: risk_order.get(d.risk_level, 3))
        original = {id(direction): index
                    for index, direction in enumerate(directions)}
        priorities = {
            id(direction): self._direction_campaign_priority(direction)
            for direction in directions
        }
        return sorted(directions, key=lambda direction: (
            risk_order.get(direction.risk_level, 3),
            -priorities[id(direction)][0],
            -priorities[id(direction)][1],
            original[id(direction)],
        ))

    def _write_direction_selection_receipt(
        self, directions: List, sorted_directions: List, seed_limit: int
    ) -> Optional[Dict[str, str]]:
        """Persist the pre-execution Direction ranking and selection basis."""
        plan = getattr(self, "_development_direction_plan", None)
        if self.llm_client_factory is None or plan is None:
            return None
        model_order = {
            direction.direction_id: index
            for index, direction in enumerate(directions)
        }
        selected_ids = {
            direction.direction_id for direction in sorted_directions[:seed_limit]
        }
        focus = getattr(self, "_development_security_invariant_focus", None)
        rows = []
        for rank, direction in enumerate(sorted_directions):
            priority = (self._direction_campaign_priority(direction)
                        if focus is not None else None)
            rows.append({
                "direction_id": direction.direction_id,
                "name": str(getattr(direction, "name", "")),
                "risk_level": str(getattr(direction, "risk_level", "")),
                "model_order": model_order[direction.direction_id],
                "generic_source_priority": list(priority)
                    if priority is not None else None,
                "final_rank": rank,
                "selected": direction.direction_id in selected_ids,
            })
        payload = {
            "kind": "FBV2_DIRECTION_SELECTION_RECEIPT_V1",
            "task_id": self.task_id,
            "run_id": getattr(self.executor, "development_run_id", None),
            "direction_plan_sha256": plan[1],
            "policy": (
                "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1"
                if focus is not None else "MODEL_RISK_ORDER"
            ),
            "security_invariant_focus": focus,
            "seed_limit": seed_limit,
            "ranked_directions": rows,
        }
        content = (json.dumps(payload, sort_keys=True) + "\n").encode()
        receipt_path = self.results_path / "DIRECTION_SELECTION_RECEIPT.json"
        fd = os.open(
            receipt_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as receipt:
            receipt.write(content)
            receipt.flush()
            os.fsync(receipt.fileno())
        parent_fd = os.open(receipt_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return {
            "path": str(receipt_path),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def _require_pipeline_active_during_sp(self) -> None:
        """Do not start another injected SP turn after Verify/PoV has failed."""
        if self.llm_client_factory is None:
            return
        if self._gate_verified_stop_requested():
            return
        pipeline_task = getattr(self, "_active_pipeline_task", None)
        if pipeline_task is not None and pipeline_task.done():
            # Propagate the actual failure when present. A successful early
            # return is still incomplete while SP finding remains active.
            pipeline_task.result()
            raise RuntimeError("Verifier/PoV pipeline ended before SP finding")

    async def _drain_development_sp_queue(self) -> None:
        """Let the original Verifier/PoV workers settle before the next SP.

        This is only a signed development execution order. It does not verify
        a candidate, change its status, or treat the partial Seed scope as a
        full automatic-discovery evaluation.
        """
        if not self._development_sp_queue_drain:
            return
        if (self.llm_client_factory is None or
                self._development_auto_scope is not None or
                self.num_parallel_agents != 1 or
                getattr(self, "_active_pipeline_task", None) is None):
            raise RuntimeError("development SP queue drain is not attached to a live pipeline")

        from bson import ObjectId
        from devtools.campaign_model_gate import CampaignModelGate

        bridge = getattr(self.executor, "_fuzzer_manager", None)
        gate = getattr(bridge, "model_gate", None)
        if not isinstance(gate, CampaignModelGate):
            raise RuntimeError("development SP queue drain lacks the campaign model gate")
        pending = {"pending_verify", "verifying", "pending_pov", "generating_pov"}
        # Independent validation is a downstream Gate task. Its pending
        # verdict must remain pending, but it no longer holds a model queue
        # slot or prevent another SP function from being analyzed.
        terminal = {"verified", "refuted", "reviewed_not_admitted",
                    "pov_generated", "failed", "skipped",
                    "pending_independent_validation"}
        incomplete = {"pending_budget", "incomplete_uncertain",
                      "pending_qualified_runtime"}
        while True:
            self._require_pipeline_active_during_sp()
            try:
                state = gate.snapshot()
                if any(row.get("status") == "UNCERTAIN"
                       for row in state["records"]):
                    raise IncompleteInjectedAgent(
                        "development SP queue has an uncertain model turn",
                        reason="uncertain_remote")
                rows = list(self.repos.suspicious_points.collection.find(
                    {"task_id": ObjectId(self.task_id)},
                    {"status": 1, "sources": 1}))
            except IncompleteInjectedAgent:
                raise
            except Exception as exc:
                raise IncompleteInjectedAgent(
                    "development SP candidate queue could not be read",
                    reason="candidate_state_read_failed") from exc

            statuses = [row.get("status") for row in rows]
            if any(status in incomplete for status in statuses):
                raise IncompleteInjectedAgent(
                    "development SP candidate queue has an incomplete candidate",
                    reason="candidate_queue_incomplete")
            if any(status not in pending | terminal for status in statuses):
                raise IncompleteInjectedAgent(
                    "development SP candidate queue has an unknown status",
                    reason="candidate_state_read_failed")
            if not any(status in pending for status in statuses):
                return
            remaining = state["started_monotonic"] + gate.wall_seconds - time.monotonic()
            if remaining <= 0:
                raise IncompleteInjectedAgent(
                    "development SP candidate queue did not drain before the model wall cap",
                    reason="budget_before_transport")
            await asyncio.sleep(min(0.1, remaining))

    def _admit_next_development_sp(self, func, direction_id: str
                                   ) -> _DownstreamReserveStop | None:
        """Stop before a new SP owner when its signed envelope is unavailable.

        The priority-one profile is deliberately serial and drains every
        Verifier/PoV candidate before reaching this boundary.  Consequently a
        settled gate snapshot can safely decide whether to start one more SP
        function without cancelling an in-flight transport or racing another
        model owner.  The envelope is target- and function-agnostic.
        """
        envelope = getattr(self, "_development_sp_start_envelope", None)
        if getattr(self, "_development_sp_concurrent_queue", False):
            if envelope is not None:
                raise RuntimeError(
                    "concurrent SP queue cannot use a downstream reserve")
            return None
        if envelope is None:
            return None
        function_id = str(getattr(func, "function_id", "") or "")
        if (not self._development_sp_queue_drain or
                self.num_parallel_agents != 1 or not function_id or
                type(envelope) is not dict or set(envelope) != {
                    "minimum_calls", "minimum_wall_seconds"} or
                not isinstance(getattr(self, "_development_sp_scope", None), dict)):
            raise RuntimeError("development SP start envelope is not pinned")
        if getattr(self, "_development_sp_reserve_exhausted", False):
            return _DownstreamReserveStop(function_id)

        from devtools.campaign_model_gate import CampaignModelGate

        bridge = getattr(self.executor, "_fuzzer_manager", None)
        gate = getattr(bridge, "model_gate", None)
        if not isinstance(gate, CampaignModelGate):
            raise RuntimeError("development SP start envelope lacks model gate")
        decision = gate.check_remaining_envelope(
            minimum_calls=envelope["minimum_calls"],
            minimum_wall_seconds=envelope["minimum_wall_seconds"],
        )
        observation = {
            "function_id": function_id,
            "function_name": str(getattr(func, "name", "")),
            "direction_id": direction_id,
            **decision,
        }
        self._development_sp_scope.setdefault(
            "sp_start_envelope_observations", []).append(observation)
        if decision["admitted"]:
            return None
        self._development_sp_reserve_exhausted = True
        self._development_sp_scope["status"] = "DOWNSTREAM_RESERVE_STOP"
        self._development_sp_scope["downstream_reserve_stop"] = observation
        self.log_info(
            "Signed downstream reserve stopped new SP function admission: " +
            json.dumps(observation, sort_keys=True))
        return _DownstreamReserveStop(function_id)

    def _find_reachable_from_entries(self, entry_functions: List[str]) -> set:
        """
        BFS from entry_functions through call graph to find all reachable functions.
        """
        reachable = set()
        queue = list(entry_functions)
        visited = set(entry_functions)

        while queue:
            func_name = queue.pop(0)
            reachable.add(func_name)

            callees = self.repos.callgraph_nodes.find_callees(
                self.task_id, self.fuzzer, func_name
            )
            for callee in callees or []:
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)

        return reachable

    def _phase_work_for_directions(self, direction_pools: List[tuple],
                                   phase_key: str) -> List[tuple]:
        """Schedule fair full-nohint turns without duplicate function work."""
        groups = [[(func, direction.direction_id)
                   for func in pools.get(phase_key, [])]
                  for direction, pools in direction_pools]
        fair_directions = (
            (self._full_nohint_sp or
             getattr(self, "_development_security_invariant_focus",
                     None) is not None) and
            self.llm_client_factory is not None)
        if not fair_directions:
            return [item for group in groups for item in group]
        interleaved = [
            group[index]
            for index in range(max((len(group) for group in groups), default=0))
            for group in groups if index < len(group)
        ]
        if self._full_nohint_sp:
            # Prefer sanitizer-relevant source surfaces across the entire
            # phase.  The interleaved position remains the stable tie breaker,
            # so equal scores retain Direction breadth and model order.
            interleaved.sort(
                key=lambda item: -self._function_campaign_priority(item[0]))
        unique = []
        seen = set()
        for func, direction_id in interleaved:
            function_id = getattr(func, "function_id", None)
            identity = function_id or (
                getattr(func, "file_path", None),
                getattr(func, "start_line", None),
                getattr(func, "name", None),
            )
            if identity in seen:
                continue
            seen.add(identity)
            unique.append((func, direction_id))
        return unique

    def _unique_phase_work_plan(
        self, direction_pools: List[tuple], phase_keys: List[str]
    ) -> Dict[str, List[tuple]]:
        """Keep the first fair occurrence of a function across all phases."""
        seen = set()
        plan: Dict[str, List[tuple]] = {}
        for phase_key in phase_keys:
            unique = []
            for func, direction_id in self._phase_work_for_directions(
                    direction_pools, phase_key):
                function_id = getattr(func, "function_id", None)
                identity = function_id or (
                    getattr(func, "file_path", None),
                    getattr(func, "start_line", None),
                    getattr(func, "name", None),
                )
                if identity in seen:
                    continue
                seen.add(identity)
                unique.append((func, direction_id))
            plan[phase_key] = unique
        return plan

    @staticmethod
    def _function_receipt_identity(func) -> tuple[tuple, dict[str, Any]]:
        """Return a stable scheduling key and its JSON receipt form."""
        function_id = getattr(func, "function_id", None)
        if function_id:
            value = str(function_id)
            return ("FUNCTION_ID", value), {
                "kind": "FUNCTION_ID", "value": value}
        file_path = str(getattr(func, "file_path", "") or "")
        start_line = int(getattr(func, "start_line", 0) or 0)
        name = str(getattr(func, "name", "") or "")
        key = ("SOURCE_LOCATION", file_path, start_line, name)
        return key, {
            "kind": "SOURCE_LOCATION", "file_path": file_path,
            "start_line": start_line, "function_name": name,
        }

    def _write_sp_function_selection_receipt(
        self, direction_pools: List[tuple], phase_keys: List[str],
        selected_plan: Dict[str, List[tuple]],
    ) -> Dict[str, str]:
        """Seal unique-function scheduling before the first SP model turn."""
        plan = getattr(self, "_development_direction_plan", None)
        if (not isinstance(plan, tuple) or len(plan) != 2 or
                not isinstance(plan[1], str) or len(plan[1]) != 64):
            raise RuntimeError(
                "injected no-hint SP selection lacks a pinned Direction plan")

        selected = {}
        selected_order = 0
        for phase_key in phase_keys:
            for func, direction_id in selected_plan[phase_key]:
                key, identity = self._function_receipt_identity(func)
                selected[key] = {
                    "selection_order": selected_order,
                    "phase": phase_key,
                    "direction_id": direction_id,
                    "canonical_identity": identity,
                }
                selected_order += 1

        occurrences = []
        occurrence_order = 0
        first_seen = set()
        for phase_key in phase_keys:
            groups = [[(func, direction.direction_id)
                       for func in pools.get(phase_key, [])]
                      for direction, pools in direction_pools]
            rows = [
                group[index]
                for index in range(max((len(group) for group in groups), default=0))
                for group in groups if index < len(group)
            ]
            for func, direction_id in rows:
                key, identity = self._function_receipt_identity(func)
                chosen = key in selected and key not in first_seen
                first_seen.add(key)
                selected_row = selected.get(key)
                occurrences.append({
                    "occurrence_order": occurrence_order,
                    "phase": phase_key,
                    "direction_id": direction_id,
                    "function_name": str(getattr(func, "name", "") or ""),
                    "canonical_identity": identity,
                    "selected": chosen,
                    "selected_order": (
                        selected_row["selection_order"]
                        if selected_row is not None else None),
                    "disposition": (
                        "SELECTED_FIRST_OCCURRENCE" if chosen else
                        "SKIPPED_DUPLICATE" if key in selected else
                        "NOT_SELECTED"),
                })
                occurrence_order += 1

        payload = {
            "kind": "FBV2_SP_FUNCTION_SELECTION_RECEIPT_V1",
            "task_id": self.task_id,
            "run_id": getattr(self.executor, "development_run_id", None),
            "direction_plan_sha256": plan[1],
            "policy": "FIRST_CANONICAL_OCCURRENCE_ACROSS_PHASES_V1",
            "phase_order": phase_keys,
            "candidate_occurrence_count": len(occurrences),
            "selected_function_count": len(selected),
            "occurrences": occurrences,
            "selected_functions": sorted(
                selected.values(), key=lambda row: row["selection_order"]),
        }
        content = (json.dumps(payload, sort_keys=True) + "\n").encode()
        receipt_path = self.results_path / "SP_FUNCTION_SELECTION_RECEIPT.json"
        fd = os.open(
            receipt_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as receipt:
            receipt.write(content)
            receipt.flush()
            os.fsync(receipt.fileno())
        parent_fd = os.open(receipt_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return {
            "path": str(receipt_path),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def _bind_sp_function_selection_receipt(
        self, receipt: Dict[str, str]
    ) -> None:
        """Carry the pre-execution function receipt into the final result."""
        if not isinstance(self._development_sp_scope, dict):
            self._development_sp_scope = {
                "kind": "NOHINT_SP_FUNCTION_SELECTION_V1",
                "status": "FUNCTION_SELECTION_READY",
                "function_outcomes": [],
            }
        self._development_sp_scope.update({
            "function_selection_receipt_path": receipt["path"],
            "function_selection_receipt_sha256": receipt["sha256"],
        })

    @staticmethod
    def _bounded_phase_work_for_directions(direction_pools: List[tuple],
                                           phase_key: str) -> List[tuple]:
        """Preserve risk/model order and round-robin peer Directions."""
        work = []
        start = 0
        while start < len(direction_pools):
            risk = getattr(direction_pools[start][0], "risk_level", None)
            end = start + 1
            while (end < len(direction_pools) and
                   getattr(direction_pools[end][0], "risk_level", None) == risk):
                end += 1
            groups = [[(func, direction.direction_id)
                       for func in pools.get(phase_key, [])]
                      for direction, pools in direction_pools[start:end]]
            work.extend(
                group[index]
                for index in range(max((len(group) for group in groups), default=0))
                for group in groups if index < len(group)
            )
            start = end
        return work

    def _build_direction_pools(self, sorted_directions: List) -> List[tuple]:
        """
        Build per-direction pools partitioned into 4 priority categories.

        For each direction:
          - Small pool = core_functions + entry_functions
          - Reachable = BFS from entry_functions through call graph
          - Big pool = reachable - small pool

        Each pool is partitioned by analyzed status:
          - "small/new": small pool functions not yet analyzed by any direction
          - "small/re": small pool functions already analyzed by another direction
          - "big/new": big pool functions not yet analyzed by any direction
          - "big/re": big pool functions already analyzed by another direction

        Returns:
            List of (direction, pools_dict) tuples, where pools_dict maps
            phase keys to lists of resolved function objects.
        """
        result = []

        for direction in sorted_directions:
            # Build small pool names
            small_pool_names = set(direction.core_functions or [])
            small_pool_names.update(direction.entry_functions or [])

            # Find reachable functions from this direction's entry points
            reachable = self._find_reachable_from_entries(
                direction.entry_functions or []
            )

            # Big pool = reachable - small pool
            big_pool_names = reachable - small_pool_names

            self.log_info(
                f"  [{direction.name}] Small: {len(small_pool_names)}, "
                f"Big: {len(big_pool_names)}, "
                f"Total reachable: {len(reachable)}"
            )

            # Resolve function objects and partition by analyzed status
            pools = {
                "small/new": [],
                "small/re": [],
                "big/new": [],
                "big/re": [],
            }

            for name in small_pool_names:
                func = self.repos.functions.find_by_name(self.task_id, name)
                if not func:
                    continue
                if not func.analyzed_by_directions:
                    pools["small/new"].append(func)
                else:
                    pools["small/re"].append(func)

            for name in big_pool_names:
                func = self.repos.functions.find_by_name(self.task_id, name)
                if not func:
                    continue
                if not func.analyzed_by_directions:
                    pools["big/new"].append(func)
                else:
                    pools["big/re"].append(func)

            self.log_info(
                f"    small/new={len(pools['small/new'])}, "
                f"small/re={len(pools['small/re'])}, "
                f"big/new={len(pools['big/new'])}, "
                f"big/re={len(pools['big/re'])}"
            )

            result.append((direction, pools))

        return result

    async def _run_function_batch(
        self,
        work: List[tuple],
        agent_log_dir,
        global_index_start: int = 0,
        grand_total: int = 0,
    ) -> None:
        """
        Run a batch of (function, direction_id) pairs with semaphore-limited concurrency.

        Each function is analyzed by _analyze_single_function_v2 with the correct
        direction_id set via set_sp_context (ContextVar, per-asyncio-task).

        Args:
            work: List of (func_object, direction_id) tuples
            agent_log_dir: Directory for agent log files
            global_index_start: Starting index for log numbering
            grand_total: Total functions across all phases (for log display)
        """
        if not work:
            return

        semaphore = asyncio.Semaphore(self.num_parallel_agents)
        total = grand_total if grand_total > 0 else len(work)
        injected_failure = asyncio.Event()
        injected_failure_reason = None

        def record_injected_failure(reason: str) -> None:
            """Keep candidate loss sticky across concurrent completions."""
            nonlocal injected_failure_reason
            if injected_failure_reason == "sp_persistence_failure":
                return
            if (reason == "sp_persistence_failure" or
                    injected_failure_reason is None):
                injected_failure_reason = reason

        async def analyze_one(func, direction_id: str, index: int):
            nonlocal injected_failure_reason
            async with semaphore:
                if self._user_stop_is_set():
                    return _GracefulUserStop()
                if self._gate_verified_stop_requested():
                    return _VerifiedGateEarlyStop()
                self._require_pipeline_active_during_sp()
                if self.llm_client_factory is not None and injected_failure.is_set():
                    return {"success": False, "error": "prior injected SP failure",
                            "incomplete_reason": injected_failure_reason or
                            "incomplete_unknown"}
                reserve_stop = self._admit_next_development_sp(
                    func, direction_id)
                if reserve_stop is not None:
                    return reserve_stop
                set_sp_context(self.fuzzer, self.sanitizer, direction_id)
                try:
                    result = await self._analyze_single_function_v2(
                        func=func,
                        index=global_index_start + index,
                        total=total,
                        agent_log_dir=agent_log_dir,
                        direction_id=direction_id,
                    )
                except BaseException as exc:
                    reason = getattr(
                        exc, "reason", getattr(exc, "fbv2_stop_reason",
                                              "incomplete_unknown"))
                    if reason in {
                            "user_stop_before_transport", "user_stop_settled"}:
                        return _GracefulUserStop()
                    record_injected_failure(reason)
                    injected_failure.set()
                    raise
                if isinstance(result, (_VerifiedBoundedSPExhaustion,
                                       _ContextInsufficientSPAnalysis)) and (
                    not (self._development_auto_scope is not None or
                         self._development_sp_queue_drain or
                         getattr(self, "_development_sp_concurrent_queue", False) or
                         self._full_nohint_sp) or
                    result.function_id != str(getattr(func, "function_id", "")) or
                    result.owner_id != f"{direction_id}:{result.function_id}:"
                                       f"{global_index_start + index}"
                ):
                    record_injected_failure("invalid_local_exhaustion_marker")
                    injected_failure.set()
                    raise RuntimeError("bounded SP exhaustion owner changed")
                if (self.llm_client_factory is not None and
                        not isinstance(result, (_VerifiedBoundedSPExhaustion,
                                               _ContextInsufficientSPAnalysis)) and
                        (not isinstance(result, dict) or
                         result.get("success") is not True)):
                    reason = (
                        result.get("incomplete_reason", "incomplete_unknown")
                        if isinstance(result, dict) else "incomplete_unknown")
                    if reason in {
                            "user_stop_before_transport", "user_stop_settled"}:
                        return _GracefulUserStop()
                    record_injected_failure(reason)
                    injected_failure.set()
                elif self._development_sp_queue_drain:
                    try:
                        await self._drain_development_sp_queue()
                    except BaseException as exc:
                        record_injected_failure(getattr(
                            exc, "reason", "candidate_queue_incomplete"))
                        injected_failure.set()
                        raise
                return result

        if self.llm_client_factory is None:
            tasks = [
                analyze_one(func, direction_id, i)
                for i, (func, direction_id) in enumerate(work)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
            return

        # The opt-in model path must not silently turn budget or transport
        # failure into "function analyzed" for a whole precomputed phase.
        tasks = [
            asyncio.create_task(analyze_one(func, direction_id, i))
            for i, (func, direction_id) in enumerate(work)
        ]
        try:
            for completed in asyncio.as_completed(tasks):
                result = await completed
                if isinstance(result, (_VerifiedGateEarlyStop,
                                       _GracefulUserStop,
                                       _DownstreamReserveStop)):
                    continue
                if (not isinstance(result, (_VerifiedBoundedSPExhaustion,
                                           _ContextInsufficientSPAnalysis)) and
                        (not isinstance(result, dict) or
                         result.get("success") is not True)):
                    detail = (f" function={result.get('function_name', 'unknown')}"
                              f" error_type={result.get('error_type', 'unknown')}"
                              if isinstance(result, dict) else "")
                    raise IncompleteInjectedAgent(
                        "injected SP batch has an incomplete function" + detail,
                        reason=(result.get("incomplete_reason", "incomplete_unknown")
                                if isinstance(result, dict) else "incomplete_unknown"),
                    )
        finally:
            injected_failure.set()
            # Already transmitting turns may have uncertain remote state. Let
            # them settle; queued functions observe the failure flag and never
            # start another model request.
            await asyncio.gather(*tasks, return_exceptions=True)
            # Candidate persistence is a stronger settlement failure than a
            # sibling agent merely exhausting its local turn ceiling.  Do not
            # let completion order in a concurrent batch hide the fact that a
            # model produced a candidate which the product failed to retain.
            if injected_failure_reason == "sp_persistence_failure":
                raise IncompleteInjectedAgent(
                    "SP candidate persistence failed in concurrent batch",
                    reason="sp_persistence_failure")

    def _bounded_sp_ids(self) -> tuple[str, ...]:
        """Take a strict task SP snapshot for the bounded local-exhaustion check."""
        rows = self.repos.suspicious_points.find_by_task(self.task_id)
        ids = [getattr(row, "suspicious_point_id", None) for row in rows]
        if any(not isinstance(value, str) or not value for value in ids):
            raise ValueError("bounded SP snapshot contains an unidentified candidate")
        if len(ids) != len(set(ids)):
            raise ValueError("bounded SP snapshot contains duplicate candidate IDs")
        return tuple(sorted(ids))

    def _sp_context_sufficiency_required(self) -> bool:
        """Whether this signed no-hint profile requires strict settlement.

        The full-pool profile and the separately admitted priority-one Seed
        diagnostic both need fail-closed per-function analysis.  Keep this
        distinct from ``_full_nohint_sp`` because the priority-one profile
        retains its finite campaign and model caps.
        """
        return bool(self._full_nohint_sp or
                    self._development_sp_queue_drain or
                    getattr(self, "_development_sp_concurrent_queue", False))

    def _bounded_local_sp_exhaustion_verified(
        self, *, client, agent, role: str, owner: str,
        before_ids: tuple[str, ...] | None
    ) -> tuple[int, int] | None:
        """Only a settled, read-only SP owner may forfeit one bounded attempt."""
        concurrent = bool(getattr(self, "_development_sp_concurrent_queue", False))
        if (not (self._development_auto_scope is not None or
                 self._development_sp_queue_drain or
                 getattr(self, "_development_sp_concurrent_queue", False) or
                 self._full_nohint_sp) or
                getattr(agent, "stop_reason", None) != "max_iterations" or
                getattr(agent, "sp_created", None) is not False or
                getattr(client, "last_agent_response_was_final", None) is not False or
                (not concurrent and before_ids is not None and
                 self._bounded_sp_ids() != before_ids)):
            return None
        from devtools.campaign_model_gate import (
            CampaignLedgeredProvider, CampaignModelGate,
        )
        provider = getattr(client, "provider", None)
        if (not isinstance(provider, CampaignLedgeredProvider) or
                provider.role != role or provider.owner_id != owner or
                role not in {"sp", "sp_large"} or
                not isinstance(provider.gate, CampaignModelGate)):
            return None
        gate = provider.gate
        ledger = getattr(self.executor, "development_process_ledger", None)
        bridge = self.executor.fuzzer_manager
        if (ledger is None or bridge.model_gate is not gate or
                bridge.campaign.ledger is not ledger or
                ledger.snapshot()["stop_status"] is not None):
            return None
        rows = [row for row in gate.snapshot()["records"]
                if row.get("owner_id") == owner]
        if concurrent:
            # Other discovery agents may insert candidates while this owner
            # reads. Bind the local stop to this invocation rather than task
            # cardinality, while retaining evidence of unexplained writes.
            agent_id = getattr(client, "agent_id", None)
            issued = getattr(provider, "issued_request_ids", None)
            if (not isinstance(agent_id, str) or not agent_id or
                    getattr(getattr(agent, "_context", None), "agent_id", None)
                    != agent_id or not isinstance(issued, list) or not issued or
                    len(issued) != len(set(issued)) or
                    len(rows) != len(issued) or
                    {row.get("request_id") for row in rows} != set(issued) or
                    before_ids is None):
                return None
            candidates = self.repos.suspicious_points.find_by_task(self.task_id)
            ids = [getattr(candidate, "suspicious_point_id", None)
                   for candidate in candidates]
            if (any(not isinstance(value, str) or not value for value in ids) or
                    len(ids) != len(set(ids)) or
                    not set(before_ids).issubset(ids)):
                return None
            for candidate in candidates:
                writer = getattr(candidate, "created_by_agent_id", None)
                if (writer == agent_id or
                        (candidate.suspicious_point_id not in before_ids and
                         (getattr(candidate, "task_id", None) != self.task_id or
                          not isinstance(writer, str) or not writer))):
                    return None
        if not rows or any(row.get("role") != role or
                           row.get("status") != "COMPLETED" or
                           gate.verify_response_evidence(
                               row["request_id"]).get("status") != "VERIFIED"
                           for row in rows):
            return None
        tool_count = 0
        read_only_tools = {
            "get_function_source", "get_callers", "get_callees",
            "search_code", "get_diff",
            FullSPGenerator.TOOL_RECORD_LOCAL_RISK_INVENTORY,
            LargeFullSPGenerator.TOOL_GET_NEXT_FUNCTION_WINDOW,
        }
        for row in rows:
            for event in row.get("tool_events", []):
                if (event.get("status") != "COMPLETED" or
                        event.get("name") not in read_only_tools or
                        (concurrent and event.get("agent_id") != agent_id) or
                        gate.verify_tool_event(
                            row["request_id"], event["call_id"]
                        ).get("status") != "VERIFIED"):
                    return None
                tool_count += 1
        return len(rows), tool_count

    def _settled_seed_corpus_ready(self, *, client, agent, direction_id: str,
                                   bridge) -> bool:
        """Accept a tool-completed Seed run only from its own settled receipts.

        Every request this injected client issued must be COMPLETED and
        verified, every tool event must belong to this Seed Agent context, and
        the Seeds counted toward K must be new digest-verified files produced
        by this agent. Concurrent HP work is settled at the campaign boundary.
        """
        from devtools.campaign_model_gate import (
            CampaignGateError, CampaignLedgeredProvider, CampaignModelGate,
            _private_bytes,
        )
        required = getattr(agent, "required_unique_seed_count", None)
        baseline = getattr(agent, "seed_corpus_baseline", None)
        provider = getattr(client, "provider", None)
        agent_id = getattr(client, "agent_id", None)
        context = getattr(agent, "_context", None)
        if (type(required) is not int or required < 1 or
                not isinstance(baseline, frozenset) or
                getattr(agent, "completion_reason", None) != "SEED_CORPUS_READY" or
                getattr(agent, "stop_reason", None) is not None or
                getattr(agent, "fatal_seed_cleanup", None) is not False or
                not isinstance(provider, CampaignLedgeredProvider) or
                provider.role != "seed" or provider.owner_id != direction_id or
                not isinstance(provider.gate, CampaignModelGate) or
                not isinstance(agent_id, str) or not agent_id or
                getattr(context, "agent_id", None) != agent_id):
            return False
        issued = list(getattr(provider, "issued_request_ids", []))
        if not issued or len(set(issued)) != len(issued):
            return False
        gate = provider.gate
        try:
            ledger = bridge.campaign.ledger
            if (getattr(bridge, "model_gate", None) is not gate or
                    not bridge._authority_ok()):
                return False
            physical = ledger.snapshot()
            if physical.get("stop_status") is not None:
                return False
            rows = gate.snapshot()["records"]
            own = [row for row in rows if row.get("request_id") in issued]
            if (len(own) != len(issued) or any(
                    row.get("status") != "COMPLETED" or any(
                    event.get("status") != "COMPLETED"
                    for event in row.get("tool_events", []))
                    for row in own)):
                return False
            produced: set[str] = set()
            prefix = f"direction_{direction_id}_"
            for row in own:
                if (row.get("role") != "seed" or
                        row.get("owner_id") != direction_id or
                        gate.verify_response_evidence(
                            row["request_id"]).get("status") != "VERIFIED"):
                    return False
                for event in row.get("tool_events", []):
                    if (event.get("agent_id") != agent_id or
                            gate.verify_tool_event(
                                row["request_id"], event["call_id"]
                            ).get("status") != "VERIFIED"):
                        return False
                    if event.get("name") != "create_seed":
                        continue
                    raw = _private_bytes(Path(event["result_path"]))
                    if (raw is None or hashlib.sha256(raw).hexdigest() !=
                            event.get("result_sha256")):
                        return False
                    result = json.loads(raw)
                    if type(result) is not dict:
                        return False
                    if result.get("fatal_sandbox_cleanup") is True:
                        return False
                    if result.get("success") is not True:
                        continue  # A settled generator failure is not fatal.
                    for value in result.get("seed_paths", []):
                        name = Path(value).name if type(value) is str else ""
                        if not name.startswith(prefix):
                            return False
                        produced.add(name[len(prefix):])
            current = bridge.verified_direction_seed_digests(direction_id)
            new = current - baseline
            return bool(len(new) >= required and
                        new == agent.new_unique_seed_digests and
                        new <= produced)
        except (CampaignGateError, AttributeError, KeyError, OSError,
                TypeError, ValueError, json.JSONDecodeError):
            return False

    def _settled_created_sp_limit_verified(
        self, *, client, agent, role: str, owner: str,
        function_name: str, direction_id: str,
    ) -> tuple[int, int, tuple[str, ...]] | None:
        """Settle a local limit only when every created SP has an owned DB receipt."""
        if (not (self._development_auto_scope is not None or
                 self._development_sp_queue_drain or
                 getattr(self, "_development_sp_concurrent_queue", False) or
                 self._full_nohint_sp) or
                getattr(agent, "stop_reason", None) != "max_iterations" or
                getattr(agent, "sp_created", None) is not True or
                getattr(client, "last_agent_response_was_final", None) is not False):
            return None
        from devtools.campaign_model_gate import (
            CampaignGateError, CampaignLedgeredProvider, CampaignModelGate,
            _private_bytes,
        )
        provider = getattr(client, "provider", None)
        agent_id = getattr(client, "agent_id", None)
        context = getattr(agent, "_context", None)
        if (not isinstance(provider, CampaignLedgeredProvider) or
                provider.role != role or provider.owner_id != owner or
                role not in {"sp", "sp_large"} or
                not isinstance(provider.gate, CampaignModelGate) or
                not isinstance(agent_id, str) or not agent_id or
                getattr(context, "agent_id", None) != agent_id):
            return None
        gate = provider.gate
        ledger = getattr(self.executor, "development_process_ledger", None)
        bridge = self.executor.fuzzer_manager
        if (ledger is None or bridge.model_gate is not gate or
                bridge.campaign.ledger is not ledger or
                ledger.snapshot()["stop_status"] is not None):
            return None
        rows = [row for row in gate.snapshot()["records"]
                if row.get("owner_id") == owner]
        if not rows or any(row.get("role") != role or
                           row.get("status") != "COMPLETED" or
                           gate.verify_response_evidence(
                               row["request_id"]).get("status") != "VERIFIED"
                           for row in rows):
            return None
        tool_count = 0
        created_ids: list[str] = []
        read_only_tools = {
            "get_function_source", "get_callers", "get_callees",
            "search_code", "get_diff",
            FullSPGenerator.TOOL_RECORD_LOCAL_RISK_INVENTORY,
            LargeFullSPGenerator.TOOL_GET_NEXT_FUNCTION_WINDOW,
        }
        for row in rows:
            for event in row.get("tool_events", []):
                name = event.get("name")
                if (event.get("status") != "COMPLETED" or
                        event.get("agent_id") != agent_id or
                        name not in read_only_tools | {"create_suspicious_point"} or
                        gate.verify_tool_event(
                            row["request_id"], event["call_id"]
                        ).get("status") != "VERIFIED"):
                    return None
                tool_count += 1
                if name != "create_suspicious_point":
                    continue
                path = event.get("result_path")
                if not isinstance(path, str) or not path:
                    return None
                try:
                    result_bytes = _private_bytes(Path(path))
                    if (result_bytes is None or
                            hashlib.sha256(result_bytes).hexdigest() !=
                            event.get("result_sha256")):
                        return None
                    receipt = json.loads(result_bytes)
                except (CampaignGateError, OSError, ValueError, TypeError):
                    return None
                if not isinstance(receipt, dict):
                    return None
                sp_id = receipt.get("id")
                if (receipt.get("success") is not True or
                        receipt.get("created") is not True or
                        not isinstance(sp_id, str) or not sp_id or
                        sp_id in created_ids):
                    return None
                candidate = self.repos.suspicious_points.find_by_id(sp_id)
                if (candidate is None or
                        candidate.suspicious_point_id != sp_id or
                        candidate.task_id != self.task_id or
                        candidate.function_name != function_name or
                        candidate.direction_id != direction_id or
                        candidate.created_by_agent_id != agent_id or
                        {"harness_name": self.fuzzer,
                         "sanitizer": self.sanitizer} not in candidate.sources or
                        candidate.status in {"pending_budget", "incomplete_uncertain"} or
                        candidate.pipeline_incomplete_reason is not None):
                    return None
                created_ids.append(sp_id)
        details = getattr(agent, "sp_details", None)
        if (not created_ids or not isinstance(details, dict) or
                details.get("sp_id") not in created_ids or
                details.get("function_name") != function_name):
            return None
        return len(rows), tool_count, tuple(created_ids)

    async def _analyze_single_function_v2(
        self,
        func,
        index: int,
        total: int,
        agent_log_dir,
        direction_id: str,
    ) -> dict:
        """
        Analyze a single function using FullSPGenerator (v2 small agent).
        """
        func_start = time.time()

        self.log_debug(f"[{index + 1}/{total}] Analyzing: {func.name}")

        # Get caller/callee info
        callers = []
        callees = []
        try:
            callers = (
                self.repos.callgraph_nodes.find_callers(
                    self.task_id, self.fuzzer, func.name
                )
                or []
            )
            callees = (
                self.repos.callgraph_nodes.find_callees(
                    self.task_id, self.fuzzer, func.name
                )
                or []
            )
        except Exception:
            pass

        # Get function source - use DB content or fetch via tree-sitter fallback
        func_source = func.content or ""
        if not func_source and self.executor.analysis_socket_path:
            try:
                from ...analyzer import AnalysisClient

                client = AnalysisClient(
                    self.executor.analysis_socket_path,
                    client_id=f"fullscan_func_{self.worker_id}_{index}",
                )
                func_source = client.get_function_source(func.name) or ""
            except Exception:
                pass

        # Determine function size based on actual source
        func_lines = func_source.count("\n") + 1 if func_source else 0
        is_large = func_lines > LargeFullSPGenerator.LARGE_FUNCTION_THRESHOLD

        try:
            if self.llm_client_factory is not None and not func_source.strip():
                raise IncompleteInjectedAgent(
                    "SP function source is unavailable",
                    reason="function_source_unavailable")
            role = "sp_large" if is_large else "sp"
            owner = f"{direction_id}:{getattr(func, 'function_id', func.name)}:{index}"
            strict_context_closure = self._sp_context_sufficiency_required()
            fuzzer_source, caller_sources = self._get_initial_sp_source_context(
                callers
            )
            before_ids = (self._bounded_sp_ids()
                          if (self._development_auto_scope is not None or
                              self._development_sp_queue_drain or
                              getattr(self, "_development_sp_concurrent_queue", False)) else None)
            exhausted = None
            exhausted_created = None
            async with injected_agent_client(
                self.llm_client_factory, role, owner
            ) as client:
                generator = LargeFullSPGenerator if is_large else FullSPGenerator
                iteration_policy = (
                    self._development_sp_scope.get("sp_iteration_policy")
                    if self._full_nohint_sp and
                    isinstance(self._development_sp_scope, dict) else None)
                max_iterations = (
                    line_scaled_sp_iteration_limit(func_lines, iteration_policy)
                    if iteration_policy is not None else
                    self._development_auto_scope["sp_max_iterations"]
                    if self._development_auto_scope is not None else
                    6 if is_large else 5)
                agent = generator(
                    function_name=func.name,
                    function_source=func_source,  # Use fetched source
                    function_file=func.file_path or "",
                    function_lines=(func.start_line or 0, func.end_line or 0),
                    callers=callers,
                    callees=callees,
                    fuzzer_source=fuzzer_source,
                    caller_sources=caller_sources,
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    llm_client=client,
                    model=CLAUDE_OPUS_4_5 if is_large else CLAUDE_SONNET_4_5,
                    direction_id=direction_id,
                    task_id=self.task_id,
                    worker_id=self.worker_id,
                    log_dir=agent_log_dir,
                    max_iterations=max_iterations,
                    index=index,  # Log file naming: SPG_{index}_{function_name}.log
                    require_context_sufficiency=strict_context_closure,
                )
                if is_large and strict_context_closure:
                    # A strict negative conclusion is not eligible until the
                    # model has received every host-pinned source window. The
                    # campaign's signed call/wall gate remains the outer cap;
                    # insufficient campaign budget settles INCOMPLETE rather
                    # than silently treating an unread suffix as safe.
                    agent.max_iterations = max(
                        agent.max_iterations,
                        agent.minimum_strict_iterations(),
                    )
                result = await agent.analyze_async()
                try:
                    require_injected_agent_complete(client, agent)
                except IncompleteInjectedAgent as exc:
                    if (exc.reason != "max_iterations" or
                            (before_ids is None and not strict_context_closure)):
                        raise
                    if agent.sp_created:
                        exhausted_created = self._settled_created_sp_limit_verified(
                            client=client, agent=agent, role=role, owner=owner,
                            function_name=func.name, direction_id=direction_id)
                    else:
                        exhausted = self._bounded_local_sp_exhaustion_verified(
                            client=client, agent=agent, role=role, owner=owner,
                            before_ids=before_ids)
                    if exhausted is None and exhausted_created is None:
                        raise

            if exhausted is not None or exhausted_created is not None:
                outcome = {
                    "success": False,
                    "function_name": func.name,
                    "function_id": getattr(func, "function_id", None),
                    "direction_id": direction_id,
                    "opportunity_status": (
                        "SP_CREATED_MAX_ITERATIONS" if exhausted_created is not None
                        else "NO_OPPORTUNITY_MAX_ITERATIONS"),
                    "model_turns": (exhausted_created or exhausted)[0],
                }
                if exhausted_created is not None:
                    outcome["verified_tool_events"] = exhausted_created[1]
                    outcome["created_sp_ids"] = list(exhausted_created[2])
                else:
                    outcome["verified_read_only_tool_events"] = exhausted[1]
                if self._development_sp_scope is not None:
                    self._development_sp_scope.setdefault(
                        "function_outcomes", []).append(outcome)
                self.log_warning(
                    f"[{index + 1}/{total}] {func.name}: local SP iteration "
                    "limit; verified candidate write or no opportunity recorded, "
                    "continuing function pool")
                return _VerifiedBoundedSPExhaustion(
                    function_id=str(getattr(func, "function_id", "")),
                    owner_id=owner,
                    created_sp_ids=(exhausted_created[2]
                                    if exhausted_created is not None else ()))

            if (self.llm_client_factory is not None and
                    (not isinstance(result, dict) or
                     result.get("success") is not True)):
                completion = (result.get("analysis_completion", {})
                              if isinstance(result, dict) else {})
                if (strict_context_closure and
                        not result.get("sp_created") and
                        (completion.get("valid") is False or
                         completion.get("context_sufficiency") != "SUFFICIENT")):
                    outcome = {
                        "success": False,
                        "function_name": func.name,
                        "function_id": getattr(func, "function_id", None),
                        "direction_id": direction_id,
                        "opportunity_status": "NO_SP_CONTEXT_INSUFFICIENT",
                        "context_sufficiency": completion.get(
                            "context_sufficiency", "UNKNOWN"),
                        "unresolved_preconditions": completion.get(
                            "unresolved_preconditions", []),
                    }
                    if self._development_sp_scope is not None:
                        self._development_sp_scope.setdefault(
                            "function_outcomes", []).append(outcome)
                    self.log_warning(
                        f"[{index + 1}/{total}] {func.name}: no SP, but the "
                        "negative conclusion lacks required context; continuing "
                        "without marking the function analyzed")
                    return _ContextInsufficientSPAnalysis(
                        function_id=str(getattr(func, "function_id", "")),
                        owner_id=owner)
                raise IncompleteInjectedAgent(
                    "SP function analysis did not complete successfully",
                    reason="function_analysis_failed")
            # Mark function as analyzed by this direction
            if hasattr(func, "function_id") and func.function_id:
                marked = self.repos.functions.mark_analyzed_by_direction(
                    func.function_id, direction_id
                )
                if self.llm_client_factory is not None and marked is not True:
                    raise IncompleteInjectedAgent(
                        "SP function analysis marker could not be persisted",
                        reason="function_state_write_failed")

            # Record every settled function, not only incomplete/max-iteration
            # rows.  The previous partial ledger hid context-sufficient
            # no-candidate screens (two such functions in V11), making an
            # honest partial scan look like it contained only failures.
            if self._development_sp_scope is not None:
                completion = result.get("analysis_completion", {})
                created_ids = sorted(getattr(agent, "created_sp_ids", set()))
                outcome = {
                    "success": True,
                    "function_name": func.name,
                    "function_id": getattr(func, "function_id", None),
                    "direction_id": direction_id,
                    "opportunity_status": (
                        "SP_CREATED" if result.get("sp_created") else
                        "ANALYZED_NO_SP_CONTEXT_SUFFICIENT"),
                    "context_sufficiency": completion.get(
                        "context_sufficiency", result.get(
                            "context_sufficiency", "UNKNOWN")),
                    "analysis_result": completion.get(
                        "analysis_result", result.get(
                            "analysis_result", "UNKNOWN")),
                    "model_turns": result.get("iterations_used"),
                    "created_sp_ids": created_ids,
                }
                self._development_sp_scope.setdefault(
                    "function_outcomes", []).append(outcome)

            func_duration = time.time() - func_start
            sp_status = "SP!" if result.get("sp_created") else "OK"
            self.log_debug(
                f"[{index + 1}/{total}] Done: {func.name} in {func_duration:.1f}s - {sp_status}"
            )

            # Note: Agent logs are now written directly to SPG_{index}_{function_name}.log
            # No need for separate combined log file

            return result

        except Exception as e:
            self.log_error(f"[{index + 1}/{total}] Failed: {func.name} - {e}")
            return {"success": False, "error": str(e),
                    "function_name": func.name,
                    "error_type": type(e).__name__,
                    "incomplete_reason": getattr(
                        e, "reason", getattr(e, "fbv2_stop_reason",
                                            "incomplete_unknown"))}

    def _log_coverage_report(self, directions: List) -> None:
        """
        Log detailed coverage statistics.
        """
        self.log_info("=== SP Find v2 Coverage Report ===")

        # Small pool stats
        small_pool_total = 0
        for direction in directions:
            small_pool_total += len(direction.core_functions or [])
            small_pool_total += len(direction.entry_functions or [])

        # Big pool stats
        all_functions = self.repos.functions.find_by_task(self.task_id)
        big_pool_total = len(all_functions) if all_functions else 0

        # Analyzed counts
        analyzed_count = sum(
            1
            for f in (all_functions or [])
            if f.analyzed_by_directions and len(f.analyzed_by_directions) > 0
        )

        self.log_info(f"  Small Pool: {small_pool_total} functions")
        self.log_info(f"  Big Pool: {big_pool_total} total reachable functions")
        self.log_info(f"  Analyzed: {analyzed_count} functions")
        self.log_info(
            f"  Coverage: {analyzed_count}/{big_pool_total} ({100 * analyzed_count / max(big_pool_total, 1):.1f}%)"
        )

    # =========================================================================
    # Fuzzer Worker Integration
    # =========================================================================

    async def _generate_direction_seeds_and_start_global_fuzzer(
        self,
        directions: List,
    ) -> None:
        """
        Generate Direction Seeds using SeedAgent and start Global Fuzzer.

        Called after Direction Planning completes.
        Flow: Direction Agent completes → SeedAgent generates initial seeds → Global Fuzzer starts

        Args:
            directions: List of Direction objects from Direction Planning
        """
        # Check if FuzzerManager is available
        fuzzer_manager = getattr(self.executor, "fuzzer_manager", None)
        if not fuzzer_manager:
            self.log_debug(
                "FuzzerManager not available, skipping Direction Seeds generation"
            )
            return

        self.log_info("=== Generating Direction Seeds ===")

        fuzzer_code = self._get_fuzzer_source_code()
        agent_log_dir = self.agent_log_dir

        # Generate seeds for each direction (high-risk first)
        sorted_directions = POVFullscanStrategy._sort_directions_for_campaign(
            self, directions)
        scope = getattr(self, "_development_auto_scope", None)
        seed_dev_limit = getattr(self, "_development_seed_limit", None)
        seed_limit = (scope["seed_directions"] if scope is not None else
                      seed_dev_limit if seed_dev_limit is not None else 5)
        seed_directions = sorted_directions[:seed_limit]
        selection_receipt = POVFullscanStrategy._write_direction_selection_receipt(
            self, directions, sorted_directions, seed_limit)

        # Create tasks for parallel execution (top 5 directions)
        async def run_seed_agent(seed_index: int, direction) -> dict:
            """Run a single SeedAgent and return result."""
            try:
                qualified_seed = getattr(
                    self.executor, "qualified_seed_generator", None)
                if (self.llm_client_factory is not None and
                        not callable(qualified_seed)):
                    raise RuntimeError(
                        "injected Direction Seed process account unavailable")
                required_unique = (
                    getattr(self, "_development_seed_required_unique", None)
                    if self.llm_client_factory is not None else None)
                async with injected_agent_client(
                    self.llm_client_factory, "seed", direction.direction_id
                ) as client:
                    seed_agent = SeedAgent(
                        task_id=self.task_id,
                        worker_id=self.worker_id,  # ObjectId for MongoDB linking
                        fuzzer=self.fuzzer,
                        sanitizer=self.sanitizer,
                        llm_client=client,
                        model=CLAUDE_OPUS_4_5,  # Original seed model by default
                        fuzzer_manager=fuzzer_manager,
                        repos=self.repos,
                        fuzzer_source=fuzzer_code,
                        log_dir=agent_log_dir,
                        max_iterations=20,
                        index=seed_index,
                        target_name=direction.name,
                        qualified_seed_generator=qualified_seed,
                        qualified_seed_required=self.llm_client_factory is not None,
                        required_unique_seed_count=required_unique,
                        seed_corpus_snapshot=(
                            (lambda direction_id=direction.direction_id:
                             fuzzer_manager.verified_direction_seed_digests(
                                 direction_id))
                            if required_unique is not None else None),
                    )

                    result = await seed_agent.generate_direction_seeds(
                        direction_id=direction.direction_id,
                        target_functions=direction.core_functions or [],
                        risk_level=direction.risk_level,
                        risk_reason=direction.risk_reason or "",
                    )
                    if (self.llm_client_factory is not None and
                            result.get("fatal_seed_cleanup") is True):
                        raise IncompleteInjectedAgent(
                            "Direction Seed sandbox cleanup is uncertain",
                            reason="sandbox_cleanup_uncertain")
                    if (required_unique is not None and
                            seed_agent.completion_reason == "SEED_CORPUS_READY"):
                        if not self._settled_seed_corpus_ready(
                                client=client, agent=seed_agent,
                                direction_id=direction.direction_id,
                                bridge=fuzzer_manager):
                            raise IncompleteInjectedAgent(
                                "Direction Seed corpus completion is unproven",
                                reason="seed_corpus_unverified")
                        require_injected_agent_complete(
                            client, seed_agent, tool_success=True)
                    else:
                        require_injected_agent_complete(client, seed_agent)
                    if (self.llm_client_factory is not None and
                            result.get("seeds_generated", 0) == 0 and
                            result.get("seed_tool_failures", 0) > 0):
                        raise IncompleteInjectedAgent(
                            "Direction Seed tool failed without a seed",
                            reason="seed_tool_failed_without_seed")
                return {"direction": direction, "result": result}

            except Exception as e:
                self.log_warning(
                    f"  Failed to generate seeds for {direction.name}: {e}"
                )
                return {"direction": direction, "result": None,
                        "error": str(e), "exception": e}

        # The injected campaign gate cannot reserve a new model turn while a
        # sibling's host tool (including the Seed Docker run) is in flight.
        # Keep the original parallel behavior for the unmodified client path.
        if self.llm_client_factory is not None:
            results = []
            for idx, direction in enumerate(seed_directions, start=1):
                results.append(await run_seed_agent(idx, direction))
        else:
            tasks = [
                run_seed_agent(idx, d)
                for idx, d in enumerate(seed_directions, start=1)
            ]
            results = await asyncio.gather(*tasks)

        # Collect results
        seeds_generated = 0
        new_unique_seeds = 0
        for item in results:
            direction = item["direction"]
            result = item.get("result")
            if result and result.get("success"):
                count = result.get("seeds_generated", 0)
                seeds_generated += count
                new_unique_seeds += result.get("new_unique_seed_count", 0)
                self.log_info(
                    f"  Generated {count} seeds "
                    f"for direction: {direction.name} ({direction.risk_level})"
                )
        if scope is not None or seed_dev_limit is not None:
            self._direction_seed_phase = {
                "status": ("PARTIAL_SEED_SCOPE" if seed_dev_limit is not None
                           else "PARTIAL_SCOPE"),
                "selected_direction_ids": [d.direction_id for d in seed_directions],
                "skipped_direction_ids": [d.direction_id
                                          for d in sorted_directions[seed_limit:]],
                "seeds_generated": seeds_generated,
                "seed_creation_events": seeds_generated,
                "new_unique_seeds": new_unique_seeds,
                "required_unique_seed_count": getattr(
                    self, "_development_seed_required_unique", None),
                "run_id": getattr(self.executor, "development_run_id", None),
                "security_invariant_focus":
                    getattr(self, "_development_security_invariant_focus",
                            None),
                "direction_selection": (
                    "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1"
                    if getattr(self, "_development_security_invariant_focus",
                               None) is not None
                    else "MODEL_RISK_ORDER"),
            }
            if selection_receipt is not None:
                self._direction_seed_phase.update({
                    "selection_receipt_path": selection_receipt["path"],
                    "selection_receipt_sha256": selection_receipt["sha256"],
                })

        failed_seed_turns = [item for item in results
                             if item.get("exception") is not None]
        if self.llm_client_factory is not None and failed_seed_turns:
            # Only an invalid JSON proposal from a conclusively completed
            # model turn can be isolated to its Direction. In particular,
            # llm_error, uncertain transport, budget denial and unfinished
            # host tools remain campaign-wide stops.
            def settled_invalid_proposals() -> bool:
                if (seeds_generated <= 0 or any(
                        not isinstance(item.get("exception"), IncompleteInjectedAgent) or
                        item["exception"].reason != "invalid_model_tool_json"
                        for item in failed_seed_turns)):
                    return False
                gate = getattr(fuzzer_manager, "model_gate", None)
                ledger = getattr(getattr(fuzzer_manager, "campaign", None),
                                 "ledger", None)
                if (gate is None or ledger is None or
                        not callable(getattr(gate, "snapshot", None)) or
                        not callable(getattr(ledger, "snapshot", None)) or
                        not callable(getattr(fuzzer_manager, "_authority_ok", None))):
                    return False
                try:
                    model = gate.snapshot()
                    physical = ledger.snapshot()
                    rows = model["records"]
                    if (not isinstance(rows, list) or not rows or
                            type(physical) is not dict or
                            "stop_status" not in physical or
                            type(physical.get("active")) is not dict or
                            any(row.get("status") != "COMPLETED" for row in rows) or
                            physical.get("active") != {} or
                            physical.get("stop_status") is not None or
                            not fuzzer_manager.direction_seeds or
                            not fuzzer_manager._authority_ok()):
                        return False
                    failed_ids = {
                        item["direction"].direction_id
                        for item in failed_seed_turns
                    }
                    # A failed owner's earlier source lookup is harmless only
                    # when its completed, pinned receipt is verified below.
                    # Keep create_seed and every other tool disqualifying.
                    failed_read_only_tools = {"search_code"}
                    if (any(not any(row.get("role") == "seed" and
                                    row.get("owner_id") == direction_id and
                                    not row.get("tool_events")
                                    for row in rows)
                            for direction_id in failed_ids) or
                            any(row.get("role") == "seed" and
                                row.get("owner_id") in failed_ids and
                                any(event.get("name") not in
                                    failed_read_only_tools
                                    for event in row.get("tool_events", []))
                                for row in rows) or
                            any(seed.direction_id in failed_ids
                                for seed in fuzzer_manager.direction_seeds)):
                        return False
                    for row in rows:
                        request_id = row["request_id"]
                        if gate.verify_response_evidence(request_id).get("status") != "VERIFIED":
                            return False
                        for event in row.get("tool_events", []):
                            if (event.get("status") != "COMPLETED" or
                                    gate.verify_tool_event(
                                        request_id, event["call_id"]
                                    ).get("status") != "VERIFIED"):
                                return False
                    return True
                except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
                    return False

            if settled_invalid_proposals():
                phase = self._direction_seed_phase or {}
                phase.update({
                    "status": ("PARTIAL_SCOPE_WITH_INVALID_MODEL_TOOL_JSON"
                               if scope is not None else
                               "PARTIAL_INVALID_MODEL_TOOL_JSON"),
                    "seeds_generated": seeds_generated,
                    "failed_direction_ids": [item["direction"].direction_id
                                             for item in failed_seed_turns],
                })
                self._direction_seed_phase = phase
                for item in failed_seed_turns:
                    self.log_warning(
                        "  Direction Seed isolated after verified invalid "
                        f"model tool JSON: {item['direction'].direction_id}"
                    )
            else:
                first = failed_seed_turns[0].get("exception")
                reasons = [
                    (exc.reason if isinstance(exc, IncompleteInjectedAgent)
                     else getattr(exc, "fbv2_stop_reason", "incomplete_unknown"))
                    for exc in (item.get("exception") for item in failed_seed_turns)
                ]
                graceful = {
                    "user_stop_before_transport", "user_stop_settled"}
                reason = ("user_stop_before_transport"
                          if reasons and all(value in graceful
                                             for value in reasons)
                          else "budget_before_transport"
                          if all(value == "budget_before_transport" for value in reasons)
                          else "invalid_model_tool_json"
                          if reasons and all(value == "invalid_model_tool_json"
                                             for value in reasons)
                          else "uncertain_remote" if "uncertain_remote" in reasons
                          else None)
                detail = None
                if reason is None:
                    # Preserve one shared structured reason (for example
                    # max_iterations) instead of collapsing it to unknown.
                    public = {public_incomplete_reason(value)[0]
                              for value in reasons}
                    reason = (public.pop() if len(public) == 1 else
                              "incomplete_unknown")
                    if reason == "incomplete_unknown":
                        detail = ",".join(sorted({
                            public_incomplete_reason(value)[1] or value
                            for value in reasons}))[:256]
                raise IncompleteInjectedAgent(
                    "injected Direction Seed phase is incomplete", reason=reason,
                    detail=detail,
                ) from first

        self.log_info(
            f"Direction Seeds generation complete: {seeds_generated} total seeds"
        )

        # Start Global Fuzzer with generated seeds
        if seeds_generated > 0:
            self.log_info("┌─────────────────────────────────────────┐")
            self.log_info("│  Starting Global Fuzzer...              │")
            self.log_info("└─────────────────────────────────────────┘")
            try:
                success = await fuzzer_manager.start_global_fuzzer()
                if not success:
                    self.log_warning("Failed to start Global Fuzzer")
            except Exception as e:
                self.log_warning(f"Error starting Global Fuzzer: {e}")
                if self.llm_client_factory is not None:
                    raise RuntimeError("injected Global Fuzzer start is incomplete") from e
            else:
                if self.llm_client_factory is not None and not success:
                    raise RuntimeError("injected Global Fuzzer did not start")
        else:
            self.log_info(
                "No Direction Seeds generated, skipping Global Fuzzer startup"
            )
            if getattr(self.executor, "require_original_global_bridge", False):
                if (not callable(getattr(fuzzer_manager,
                                         "record_clean_no_seed", None)) or
                        getattr(fuzzer_manager, "model_gate", None) is None):
                    raise RuntimeError("qualified no-seed Global proof is unavailable")
                fuzzer_manager.record_clean_no_seed(
                    seed_results=results,
                    expected_direction_ids=[direction.direction_id
                                            for direction in seed_directions],
                    model_gate=fuzzer_manager.model_gate)
