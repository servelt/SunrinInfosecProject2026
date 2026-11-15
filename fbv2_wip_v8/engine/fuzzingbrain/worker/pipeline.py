"""
All-in-Agent Pipeline

Parallel pipeline for SP verification and POV generation.
Uses asyncio + MongoDB for concurrent agent execution with claim-based task distribution.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │   SP Verify Agent Pool       POV Generate Agent Pool                │
    │   ┌─────────────┐           ┌─────────────┐                        │
    │   │  Agent 1    │           │  Agent 1    │                        │
    │   │  Agent 2    │──Queue──>│  Agent 2    │                        │
    │   │  ...        │           │  ...        │                        │
    │   │  Agent y    │           │  Agent z    │                        │
    │   └─────────────┘           └─────────────┘                        │
    └─────────────────────────────────────────────────────────────────────┘
"""

import asyncio
import base64
import binascii
import hashlib
import json
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from bson import ObjectId
from loguru import logger

from ..agents import SPVerifier, POVAgent
from ..core.models import SPStatus
from ..db import RepositoryManager
from ..tools.analyzer import set_analyzer_context
from ..tools.qualified_runtime import (
    QualifiedRuntimeOutcome, QualifiedRuntimeRequest, validate_outcome,
)
from ..fuzzer import FuzzerManager, get_fuzzer_manager
from ..llms import CLAUDE_SONNET_4_5


_GRACEFUL_USER_STOP_REASONS = frozenset({
    "user_stop_before_transport", "user_stop_settled",
})


# Structured incomplete reasons that may appear in a public result. Any other
# internal value is reported as incomplete_unknown with a separate detail.
PUBLIC_INCOMPLETE_REASONS = frozenset({
    "budget_before_transport", "cancelled", "candidate_claim_invalid",
    "candidate_queue_incomplete", "candidate_state_read_failed",
    "candidate_state_write_failed", "error", "function_analysis_failed",
    "function_source_unavailable", "function_state_write_failed",
    "gate_consumption_failed", "incomplete_unknown", "invalid_model_tool_json",
    "llm_error", "max_iterations", "missing_final_response",
    "pov_pending_persist_failed", "qualified_runtime_incomplete",
    "runtime_pending", "sandbox_cleanup_uncertain", "seed_corpus_unverified",
    "seed_tool_failed_without_seed", "sp_incomplete",
    "sp_persistence_failure", "uncertain_remote",
    "user_stop_before_transport", "user_stop_settled", "validation_pending",
    "verifier_no_verdict",
})


def public_incomplete_reason(value: object) -> tuple[str, str | None]:
    """Return (public_reason, internal_detail) for one structured reason."""
    if type(value) is str and value in PUBLIC_INCOMPLETE_REASONS:
        return value, None
    detail = value if type(value) is str else type(value).__name__
    return "incomplete_unknown", re.sub(r"[^A-Za-z0-9_.:-]", "_", detail)[:64]


class IncompleteInjectedAgent(RuntimeError):
    """An opt-in model client did not finish an agent turn conclusively."""

    def __init__(self, message: str, *, reason: str = "incomplete_unknown",
                 detail: str | None = None):
        super().__init__(message)
        self.reason = reason
        # Unpublished diagnostic for a reason outside the public allowlist.
        self.detail = detail
        self.campaign_status = (
            "INCOMPLETE_BUDGET" if reason == "budget_before_transport"
            else "INCOMPLETE_USER_STOP" if reason == "user_stop_before_transport"
            else "INCOMPLETE_RUNTIME_PENDING" if reason == "runtime_pending"
            else "INCOMPLETE_VALIDATION_PENDING" if reason == "validation_pending"
            else "INCOMPLETE_UNCERTAIN"
        )


def require_injected_agent_complete(client, agent, *, tool_success: bool = False):
    """Do not turn a swallowed model error into a completed role result.

    POV can finish through a successful verify_pov tool call without a final
    text response. Other roles must end with an actual final model response.
    """
    if client is None:
        return
    reason = getattr(agent, "stop_reason", None)
    final = getattr(client, "last_agent_response_was_final", None)
    if reason is not None or (not tool_success and final is not True):
        raise IncompleteInjectedAgent(
            f"{type(agent).__name__} incomplete: stop_reason={reason}, "
            f"final_response={final}",
            reason=reason or "missing_final_response",
        )


def _invalid_tool_argument_json(raw: str) -> bool:
    try:
        json.loads(raw)
    except json.JSONDecodeError:
        return True
    return False


@asynccontextmanager
async def injected_agent_client(
    factory: Optional[Callable[[str, str], Any]], role: str, owner_id: str
):
    """Own one opt-in client for one agent invocation.

    The default FBv2 path still lets each agent construct its usual LLMClient.
    An injected client must be fresh and expose async ``close``. The factory
    is responsible for its model and physical request budget.
    """
    if factory is None:
        yield None
        return
    invocation_lock = getattr(factory, "_fbv2_campaign_invocation_lock", None)
    campaign_gate = getattr(factory, "_fbv2_campaign_gate", None)
    if invocation_lock is not None:
        await invocation_lock.acquire()
    lock_owned = invocation_lock is not None
    try:
        client = factory(role, owner_id)
        if client is None or not callable(getattr(client, "close", None)):
            raise TypeError("injected agent client must expose async close")
        if invocation_lock is not None and campaign_gate is not None:
            async def yield_campaign_turn():
                nonlocal lock_owned
                if not lock_owned:
                    raise RuntimeError("campaign turn lock is not owned")
                # Only a fully settled response/tool span may give another
                # Agent a turn. An incomplete host tool must block the next
                # model reservation, including across different owners.
                snapshot = campaign_gate.snapshot()
                if any(row.get("status") != "COMPLETED" or any(
                        event.get("status") != "COMPLETED"
                        for event in row.get("tool_events", []))
                        for row in snapshot["records"]):
                    raise RuntimeError("campaign turn is not fully settled")
                lock_owned = False
                invocation_lock.release()
                await asyncio.sleep(0)
                await invocation_lock.acquire()
                lock_owned = True

            client._fbv2_yield_campaign_turn = yield_campaign_turn
        try:
            yield client
        except BaseException as original:
            try:
                await client.close()
            except BaseException as cleanup:
                original.add_note(f"injected client close failed: {type(cleanup).__name__}")
            raise
        else:
            await client.close()
    finally:
        if lock_owned:
            invocation_lock.release()


@dataclass
class PipelineConfig:
    """Configuration for the pipeline."""

    # Agent pool sizes
    num_verify_agents: int = 2  # Number of verification agents
    num_pov_agents: int = 1  # Number of POV generation agents

    # Thresholds
    pov_min_score: float = 0.5  # Minimum score to proceed to POV generation
    # legacy_score preserves the original score+importance gate.  Explicit
    # disposition is the high-recall contract: terminal REFUTED is disabled;
    # TESTABLE_UNCERTAIN and SUPPORTED receive a physical PoV attempt.
    pov_admission_mode: str = "legacy_score"

    # Timeouts
    poll_interval: float = 1.0  # Seconds between polling for new tasks
    max_idle_cycles: int = 10  # Max cycles with no work before agent exits

    # POV Agent settings
    max_iterations: int = 100  # Max agent loop iterations
    max_pov_attempts: int = 20  # Max POV generation attempts
    verifier_max_iterations: int = 15  # Preserve original Verifier default
    # Optional hard bound exposed to the Verifier. It is set only by an
    # execution path whose PoV generator actually enforces the same limit.
    pov_input_bytes_max: Optional[int] = None

    # Fuzzer settings (for POV verification)
    fuzzer_path: Optional[Path] = None  # Path to fuzzer binary
    docker_image: Optional[str] = None  # Docker image for running fuzzer


@dataclass
class PipelineStats:
    """Statistics for pipeline execution."""

    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Counts
    sp_verified: int = 0
    sp_verified_real: int = 0
    sp_verified_fp: int = 0
    sp_testable_uncertain: int = 0
    sp_supported: int = 0
    verifier_unresolved: int = 0
    pov_generated: int = 0
    pov_no_crash_inputs_executed: int = 0
    pov_pending_runtime: int = 0
    pov_pending_validation: int = 0
    pov_failed: int = 0

    # Time tracking (cumulative seconds across all agents)
    verify_time_total: float = 0.0  # Total time spent on verification
    pov_time_total: float = 0.0  # Total time spent on POV generation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds()
            if self.end_time
            else None,
            "sp_verified": self.sp_verified,
            "verifier_processed": self.sp_verified,
            "sp_verified_real": self.sp_verified_real,
            "sp_verified_fp": self.sp_verified_fp,
            "sp_testable_uncertain": self.sp_testable_uncertain,
            "sp_supported": self.sp_supported,
            "verifier_unresolved": self.verifier_unresolved,
            "pov_generated": self.pov_generated,
            "pov_no_crash_inputs_executed": self.pov_no_crash_inputs_executed,
            "pov_pending_runtime": self.pov_pending_runtime,
            "pov_pending_validation": self.pov_pending_validation,
            "pov_failed": self.pov_failed,
            "verify_time_total": self.verify_time_total,
            "pov_time_total": self.pov_time_total,
        }


class AgentPipeline:
    """
    Parallel pipeline for SP verification and POV generation.

    Uses claim-based task distribution:
    - Agents atomically claim tasks from MongoDB
    - Priority queue: is_important > score
    - Automatic load balancing (fast agents do more work)
    """

    @staticmethod
    def _should_admit_pov(config: PipelineConfig, point) -> bool:
        """Return the explicit verifier-to-PoV handoff decision."""
        if config.pov_admission_mode == "explicit_disposition":
            disposition = point.verification_disposition
            if disposition not in {"TESTABLE_UNCERTAIN", "SUPPORTED"}:
                raise IncompleteInjectedAgent(
                    "Verifier omitted an enabled explicit candidate disposition",
                    reason="candidate_state_write_failed",
                )
            return True
        if config.pov_admission_mode == "legacy_score":
            return point.score >= config.pov_min_score and point.is_important
        raise ValueError("unknown PoV admission mode")

    def __init__(
        self,
        task_id: str,
        repos: RepositoryManager,
        fuzzer: str = "",
        sanitizer: str = "address",
        scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
        config: PipelineConfig = None,
        output_dir: Path = None,
        log_dir: Path = None,
        workspace_path: Path = None,
        fuzzer_code: str = "",
        mcp_socket_path: str = None,
        worker_id: str = None,
        llm_client_factory: Optional[Callable[[str, str], Any]] = None,
        qualified_runtime_binding: Any = None,
        qualified_gate_stop: Any = None,
    ):
        """
        Initialize the pipeline.

        Args:
            task_id: Task ID
            repos: Database repository manager
            fuzzer: Fuzzer name (for agent context)
            sanitizer: Sanitizer type
            config: Pipeline configuration
            output_dir: Directory for POV output
            log_dir: Directory for agent logs
            workspace_path: Path to workspace (for reading source code)
            fuzzer_code: Fuzzer source code (for verify agent context)
            mcp_socket_path: MCP socket path for analyzer context
            worker_id: Worker ID for FuzzerManager lookup
            llm_client_factory: Optional process-local (role, owner_id) factory;
                each call must return a fresh async-closeable client.
        """
        self.task_id = task_id
        self.repos = repos
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.scan_mode = scan_mode
        self.config = config or PipelineConfig()
        self.output_dir = output_dir
        self.log_dir = log_dir
        self.workspace_path = workspace_path
        self.fuzzer_code = fuzzer_code
        self.mcp_socket_path = mcp_socket_path
        self.worker_id = worker_id
        self.llm_client_factory = llm_client_factory
        if qualified_runtime_binding is not None and llm_client_factory is None:
            raise ValueError("qualified PoV Runtime requires an injected model path")
        self.qualified_runtime_binding = qualified_runtime_binding
        self.qualified_gate_stop = qualified_gate_stop

        # Statistics
        self.stats = PipelineStats()

        # Shutdown flag
        self._shutdown = False
        self._incomplete_error: Optional[str] = None
        self._incomplete_reason: Optional[str] = None
        self._secondary_incomplete_events: list[dict[str, str]] = []

        # Upstream completion flags (for streaming pipeline)
        self._sp_finding_done = False  # Set when SP Find pool completes
        self._verify_done = False  # Set when Verify pool completes
        self.serial_bounded_dev = False
        self.prefer_pov_after_verify = False

        # FuzzerManager for SP Fuzzer lifecycle
        self._fuzzer_manager: Optional[FuzzerManager] = None

    def _gate_verified_stop_requested(self) -> bool:
        gate_stop = getattr(self, "qualified_gate_stop", None)
        return bool(gate_stop is not None and gate_stop.verified.is_set())

    @property
    def fuzzer_manager(self) -> Optional[FuzzerManager]:
        """Get FuzzerManager (lazy lookup by worker_id)."""
        if self._fuzzer_manager is None and self.worker_id:
            self._fuzzer_manager = get_fuzzer_manager(self.worker_id)
        return self._fuzzer_manager

    async def run(self) -> PipelineStats:
        """
        Run the pipeline until all SPs are processed.

        Returns:
            Pipeline statistics
        """
        logger.info(f"[Pipeline] Starting pipeline for task {self.task_id}")
        logger.info(
            f"[Pipeline] Config: {self.config.num_verify_agents} verify agents, {self.config.num_pov_agents} POV agents"
        )

        self.stats = PipelineStats()

        tasks = []
        try:
            if self.serial_bounded_dev:
                if not self._sp_finding_done or self.llm_client_factory is None:
                    raise RuntimeError("bounded model queue lacks completed SP phase")
                # The campaign gate forbids a new model turn while another
                # role's host tool is in flight. Drain the original queues in
                # order for this signed development scope only.
                await self._run_verify_agent("verify_1")
                await self._run_pov_agent("pov_1")
            else:
                # Original FBv2 streaming behavior.
                for i in range(self.config.num_verify_agents):
                    agent_id = f"verify_{i + 1}"
                    tasks.append(asyncio.create_task(self._run_verify_agent(agent_id)))
                for i in range(self.config.num_pov_agents):
                    agent_id = f"pov_{i + 1}"
                    tasks.append(asyncio.create_task(self._run_pov_agent(agent_id)))
                await asyncio.gather(*tasks)

        except BaseException as e:
            # gather propagates the first exception without stopping siblings.
            # An injected campaign must not make another model request after
            # its queue or evidence account has failed. For an ordinary
            # failure, signal shutdown and let already-started bounded turns
            # settle; cancelling them would manufacture UNCERTAIN remote
            # states and overwrite the useful first-cause evidence. External
            # cancellation/interrupt still cancels immediately.
            self._shutdown = True
            if not isinstance(e, Exception):
                for task in tasks:
                    if not task.done():
                        task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if not isinstance(e, Exception):
                raise
            logger.exception(f"[Pipeline] Pipeline error: {e}")
            if self.llm_client_factory is not None:
                primary_error = str(e)
                if (self._incomplete_error and
                        self._incomplete_error != primary_error):
                    self._incomplete_error = (
                        f"{primary_error}; secondary interruption: "
                        f"{self._incomplete_error}")
                else:
                    self._incomplete_error = primary_error
                # A cancelled sibling may still have uncertain remote state.
                # Keep that conservative status, while reporting the first
                # exception that caused gather() to cancel its siblings.
                self._incomplete_reason = self._incomplete_reason or getattr(
                    e, "reason", "incomplete_unknown")

        finally:
            self.stats.end_time = datetime.now()

        # A retained, unexecuted PoV is not a completed campaign.
        incomplete = bool(
            self._incomplete_error or
            (self.llm_client_factory is not None and
             (self.stats.pov_pending_runtime or
              (self.stats.pov_pending_validation and
               not self._gate_verified_stop_requested()))))
        logger.info("[Pipeline] Pipeline incomplete" if incomplete
                    else "[Pipeline] Pipeline completed")
        logger.info(f"[Pipeline] Stats: {self.stats.to_dict()}")

        if self._incomplete_error:
            raise IncompleteInjectedAgent(
                self._incomplete_error,
                reason=self._incomplete_reason or "incomplete_unknown",
            )
        if self.llm_client_factory is not None and self.stats.pov_pending_runtime:
            raise IncompleteInjectedAgent(
                f"{self.stats.pov_pending_runtime} SPs have retained PoV inputs "
                "pending qualified Runtime",
                reason="runtime_pending",
            )
        if (self.llm_client_factory is not None and
                self.stats.pov_pending_validation and
                not self._gate_verified_stop_requested()):
            raise IncompleteInjectedAgent(
                f"{self.stats.pov_pending_validation} SPs have Runtime crash "
                "observations pending independent validation",
                reason="validation_pending",
            )

        return self.stats

    def shutdown(self):
        """Signal all agents to shutdown."""
        logger.info("[Pipeline] Shutdown requested")
        self._shutdown = True

    def request_graceful_stop_from_signal(self) -> None:
        """Signal-safe queue stop: mutate flags only, without logging or IO."""
        self._shutdown = True
        self._graceful_user_stop = True

    def _record_injected_cancellation(
        self, stage: str, *, reason: str = "uncertain_remote"
    ) -> None:
        """Preserve the first failure and record cancellation as secondary."""
        cancellation_error = f"injected {stage} turn was cancelled"
        if self._incomplete_reason is None:
            self._incomplete_error = cancellation_error
            self._incomplete_reason = reason
            return
        events = getattr(self, "_secondary_incomplete_events", None)
        if events is None:
            events = self._secondary_incomplete_events = []
        events.append({"stage": stage, "reason": reason,
                       "error": cancellation_error})

    @staticmethod
    def _settled_campaign_cancellation_reason(client, owner: str | None) -> str | None:
        """Recognize a local budget cancellation with no remote turn in flight.

        A parent queue-drain task can observe the campaign wall deadline and
        cancel a Verifier/PoV coroutine between two model turns.  Treating that
        cancellation as remote uncertainty loses the stronger durable fact:
        every request owned by the candidate had already completed and the
        gate refused any new transport.  Any STARTED/UNCERTAIN row, active
        request, changed gate type, or unreadable ledger remains fail-closed.
        """
        try:
            from devtools.campaign_model_gate import (
                CampaignLedgeredProvider, CampaignModelGate,
            )

            provider = getattr(client, "provider", None)
            if (not isinstance(provider, CampaignLedgeredProvider) or
                    not isinstance(provider.gate, CampaignModelGate) or
                    not isinstance(owner, str) or not owner or
                    provider.owner_id != owner):
                return None
            gate = provider.gate
            state = gate.snapshot()
            own = [row for row in state["records"]
                   if row.get("owner_id") == owner]
            if any(row.get("status") != "COMPLETED" for row in own):
                return None
            active = set(gate.stop_snapshot()["active_request_ids"])
            if any(row.get("request_id") in active for row in own):
                return None
            physical_exhausted = (
                gate.physical_max is not None and
                state["physical"] >= gate.physical_max)
            wall_exhausted = (
                gate.wall_seconds is not None and
                time.monotonic() >=
                state["started_monotonic"] + gate.wall_seconds)
            if physical_exhausted or wall_exhausted:
                return "budget_before_transport"
        except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            return None
        return None

    def _preserve_incomplete_candidate(self, sp_id: str, *, stage: str,
                                       reason: str,
                                       processor_id: str = None,
                                       claim_token: str = None) -> None:
        """Atomically stop auto-claim while preserving candidate source fields.

        There is no resume contract yet. PENDING_BUDGET means this candidate's
        turn was refused before transport; all other incomplete injected turns
        are conservatively terminal until their remote state is reconciled.
        """
        status = (SPStatus.PENDING_BUDGET if reason == "budget_before_transport"
                  else SPStatus.PENDING_STOP
                  if reason == "user_stop_before_transport"
                  else SPStatus.INCOMPLETE_UNCERTAIN)
        updates = {
            "status": status.value,
            "processor_id": None,
            "pipeline_incomplete_reason": reason,
            "pipeline_incomplete_stage": stage,
        }
        if stage == "verifier":
            # A partially written tool verdict cannot become a checked result.
            updates.update({"is_checked": False, "is_real": False,
                            "is_important": False})
        preserve_kwargs = {
            "stage": stage,
            "harness_name": self.fuzzer if stage == "pov" else None,
            "sanitizer": self.sanitizer if stage == "pov" else None,
        }
        if stage in {"verifier", "pov"}:
            preserve_kwargs.update(
                processor_id=processor_id, claim_token=claim_token)
        if not self.repos.suspicious_points.preserve_incomplete_candidate(
                sp_id, updates, **preserve_kwargs):
            raise IncompleteInjectedAgent(
                f"cannot persist incomplete {stage} candidate {sp_id}",
                reason="candidate_state_write_failed",
            )

    async def _wait_for_pov_after_verify(self, sp_id: str) -> None:
        """In the signed development scope, finish one candidate before the next.

        The original streaming queue remains unchanged. This wait only changes
        which candidate receives the existing model budget first; it never
        relabels a pending or failed PoV as verified.
        """
        pending = {SPStatus.PENDING_POV.value, SPStatus.GENERATING_POV.value}
        terminal = {SPStatus.POV_GENERATED.value, SPStatus.FAILED.value,
                    SPStatus.PENDING_INDEPENDENT_VALIDATION.value}
        while not self._shutdown and not self._gate_verified_stop_requested():
            try:
                current = self.repos.suspicious_points.find_by_id(sp_id)
            except Exception as exc:
                raise IncompleteInjectedAgent(
                    "development PoV candidate could not be read back",
                    reason="candidate_state_read_failed") from exc
            if current is None:
                raise IncompleteInjectedAgent(
                    "development PoV candidate disappeared",
                    reason="candidate_state_read_failed")
            if current.status in terminal:
                return
            if current.status == SPStatus.PENDING_QUALIFIED_RUNTIME.value:
                raise IncompleteInjectedAgent(
                    "development PoV candidate still needs qualified Runtime",
                    reason="runtime_pending")
            if current.status not in pending:
                raise IncompleteInjectedAgent(
                    f"development PoV candidate has unexpected status {current.status}",
                    reason="candidate_state_read_failed")
            await asyncio.sleep(self.config.poll_interval)

    def _settled_local_verifier_limit(self, client, agent, owner: str
                                     ) -> int | None:
        """Prove a Verifier iteration limit was local and all its tools settled.

        Return the count of verified verdict writes (zero or one). A remote
        uncertainty, unknown tool, or incomplete receipt keeps the existing
        campaign-wide stop. The caller must still read back the claimed SP.
        """
        if (getattr(agent, "stop_reason", None) != "max_iterations" or
                getattr(client, "last_agent_response_was_final", None) is not False or
                not isinstance(getattr(client, "agent_id", None), str)):
            return None
        from devtools.campaign_model_gate import (
            CampaignGateError, CampaignLedgeredProvider, CampaignModelGate,
            _private_bytes,
        )
        provider = getattr(client, "provider", None)
        if (not isinstance(provider, CampaignLedgeredProvider) or
                provider.role != "verifier" or provider.owner_id != owner or
                not isinstance(provider.gate, CampaignModelGate) or
                getattr(self.llm_client_factory, "_fbv2_campaign_gate", None)
                is not provider.gate):
            return None
        gate = provider.gate
        rows = gate.snapshot()["records"]
        own = [row for row in rows if row["owner_id"] == owner]
        if not own:
            return None
        if any(row["status"] in {
                "UNCERTAIN", "PENDING_BUDGET", "PENDING_STOP"
        } for row in own):
            return None
        read_only = {
            "analyzer_status", "get_function", "get_functions_by_file",
            "search_functions", "get_function_source", "get_callers",
            "get_callees", "get_call_graph", "find_all_paths",
            "check_reachability", "get_reachable_functions",
            "get_unreached_functions", "get_fuzzers", "get_fuzzer_source",
            "get_build_paths", "get_diff", "get_file_content",
            "search_code", "list_files", "list_suspicious_points",
            "get_suspicious_point",
        }
        verdict_writes = 0
        for row in own:
            if (row["role"] != "verifier" or row["status"] != "COMPLETED" or
                    gate.verify_response_evidence(
                        row["request_id"]).get("status") != "VERIFIED"):
                return None
            for event in row.get("tool_events", []):
                if (event["status"] != "COMPLETED" or
                        event.get("agent_id") != client.agent_id or
                        gate.verify_tool_event(
                            row["request_id"], event["call_id"]
                        ).get("status") != "VERIFIED"):
                    return None
                if event["name"] == "update_suspicious_point":
                    try:
                        retained = _private_bytes(Path(event["result_path"]))
                        if (retained is None or
                                hashlib.sha256(retained).hexdigest() !=
                                event["result_sha256"]):
                            return None
                        tool_result = json.loads(retained)
                    except (CampaignGateError, OSError, ValueError, TypeError):
                        return None
                    if (type(tool_result) is not dict or
                            tool_result.get("success") is not True or
                            tool_result.get("updated") is not True or
                            type(tool_result.get("server_result")) is not dict or
                            tool_result["server_result"].get("updated") is not True):
                        return None
                    verdict_writes += 1
                    if verdict_writes > 1:
                        return None
                elif event["name"] not in read_only:
                    return None
        return verdict_writes

    async def _run_verify_agent(self, agent_id: str):
        """
        Run a verification agent loop.

        Agent continuously:
        1. Claims a pending_verify SP
        2. Verifies it using SPVerifier
        3. Updates status (verified or pending_pov)
        4. Repeats until no more work

        Args:
            agent_id: Unique agent identifier
        """
        # Set analyzer context for this task (ContextVar needs to be set per-task)
        if self.mcp_socket_path:
            set_analyzer_context(self.mcp_socket_path, client_id=agent_id)
            logger.debug(
                f"[Pipeline:{agent_id}] Set analyzer context: {self.mcp_socket_path}"
            )

        logger.info(f"[Pipeline:{agent_id}] Verification agent started")
        idle_cycles = 0

        while not self._shutdown and not self._gate_verified_stop_requested():
            # Try to claim a task (filter by fuzzer/sanitizer for worker isolation)
            sp = self.repos.suspicious_points.claim_for_verify(
                self.task_id,
                agent_id,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
                raise_on_error=self.llm_client_factory is not None,
            )

            if sp is None:
                # No work available - check if we should exit
                idle_cycles += 1

                # Only consider exiting if upstream (SP Finding) is done
                if self._sp_finding_done:
                    # Check if there are any remaining pending_verify SPs
                    pending_count = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="pending_verify",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        raise_on_error=self.llm_client_factory is not None,
                    )
                    if pending_count == 0 and idle_cycles >= 5:
                        # SP Finding done + no pending work + waited a bit = exit
                        logger.info(
                            f"[Pipeline:{agent_id}] SP Finding done, no more work, exiting"
                        )
                        break

                # Log status periodically
                if idle_cycles % 30 == 0:
                    status = (
                        "waiting for SP Finding"
                        if not self._sp_finding_done
                        else "draining queue"
                    )
                    logger.debug(
                        f"[Pipeline:{agent_id}] Idle cycle {idle_cycles}, {status}"
                    )

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the SP with time tracking
            import time as time_module

            sp_start_time = time_module.time()
            claimed_sp_id = sp.suspicious_point_id
            claim_token = sp.verification_claim_token
            if not claim_token:
                raise IncompleteInjectedAgent(
                    "Verifier claim did not return a claim token",
                    reason="candidate_claim_invalid")
            wait_for_pov = False
            local_verifier_writes = None
            admission_mode_token = None
            injected_client = None
            injected_owner = None
            try:
                logger.info(
                    f"[Pipeline:{agent_id}] Verifying SP {sp.suspicious_point_id}"
                )

                # Run verification agent
                # Extract index from agent_id (e.g., "verify_1" -> 1)
                agent_index = int(agent_id.split("_")[1]) if "_" in agent_id else 0
                from devtools.campaign_model_gate import (
                    campaign_candidate_owner_id,
                )
                owner = campaign_candidate_owner_id(
                    agent_id=agent_id, task_id=self.task_id,
                    harness_name=self.fuzzer, sanitizer=self.sanitizer,
                    sp_id=sp.suspicious_point_id)
                injected_owner = owner
                from ..tools.suspicious_points import (
                    set_sp_pov_admission_mode, set_sp_verification_claim_token,
                )
                set_sp_verification_claim_token(claim_token)
                admission_mode_token = set_sp_pov_admission_mode(
                    getattr(self.config, "pov_admission_mode", "legacy_score"))
                async with injected_agent_client(
                    self.llm_client_factory, "verifier", owner
                ) as client:
                    injected_client = client
                    verify_agent = SPVerifier(
                        # Note: mode removed - SPVerifier is always for verification
                        fuzzer=self.fuzzer,
                        sanitizer=self.sanitizer,
                        scan_mode=self.scan_mode,  # Use pipeline's scan_mode
                        llm_client=client,
                        model=CLAUDE_SONNET_4_5,  # Original model by default
                        max_iterations=self.config.verifier_max_iterations,
                        task_id=self.task_id,
                        worker_id=self.worker_id,  # Use actual worker_id, not agent_id
                        log_dir=self.log_dir,
                        index=agent_index,
                        target_name=sp.function_name or "",
                        pov_input_bytes_max=self.config.pov_input_bytes_max,
                    )
                    verify_agent.set_context(suspicious_point=sp.to_dict())

                    # Run async with fuzzer code for context
                    await verify_agent.run_async(
                        suspicious_point=sp.to_dict(),
                        fuzzer_code=self.fuzzer_code,
                    )
                    try:
                        require_injected_agent_complete(client, verify_agent)
                    except IncompleteInjectedAgent as exc:
                        if exc.reason != "max_iterations":
                            raise
                        local_verifier_writes = self._settled_local_verifier_limit(
                            client, verify_agent, owner)
                        if local_verifier_writes is None:
                            raise

                # Get updated SP from database (agent should have updated it via tools)
                updated_sp = self.repos.suspicious_points.find_by_id(
                    sp.suspicious_point_id
                )

                if updated_sp:
                    if local_verifier_writes is not None and (
                            updated_sp.status != SPStatus.VERIFYING.value or
                            updated_sp.processor_id != agent_id or
                            updated_sp.verification_claim_token != claim_token or
                            updated_sp.is_checked is not bool(local_verifier_writes) or
                            (local_verifier_writes == 1 and
                             updated_sp.verified_by_agent_id != client.agent_id)):
                        raise IncompleteInjectedAgent(
                            "Verifier local limit candidate state did not match receipts",
                            reason="candidate_state_read_failed")
                    # A completed Agent without a verdict is still unchecked.
                    # Preserve the candidate as failed processing, with no PoV
                    # opportunity and no automatic re-claim loop.
                    if not updated_sp.is_checked:
                        if (self.llm_client_factory is not None and
                                self.config.pov_admission_mode == "explicit_disposition"):
                            # A settled local turn without a verdict is an
                            # unresolved candidate, never a negative finding.
                            # Keep draining other candidates, but report this
                            # campaign incomplete after the queue settles.
                            self._preserve_incomplete_candidate(
                                sp.suspicious_point_id, stage="verifier",
                                reason="verifier_no_verdict",
                                processor_id=agent_id, claim_token=claim_token)
                            claimed_sp_id = None
                            self.stats.verifier_unresolved += 1
                            self._incomplete_error = self._incomplete_error or (
                                "Verifier left a candidate without a verdict")
                            self._incomplete_reason = (
                                self._incomplete_reason or "verifier_no_verdict")
                            continue
                        logger.warning(
                            f"[Pipeline:{agent_id}] Agent did not update SP {sp.suspicious_point_id}, "
                            "leaving it unverified"
                        )
                        noted = self.repos.suspicious_points.update_verifier_fields(
                            sp.suspicious_point_id,
                            {"verification_notes": (
                                "Verifier reached local max_iterations without verdict"
                                if local_verifier_writes == 0 else
                                "Verifier completed without verdict")},
                            processor_id=agent_id,
                            claim_token=claim_token,
                        )
                        released = self.repos.suspicious_points.release_claim(
                            sp.suspicious_point_id, SPStatus.FAILED.value,
                            processor_id=agent_id,
                            claim_token=claim_token,
                        )
                        if (self.llm_client_factory is not None and
                                (not noted or not released)):
                            raise IncompleteInjectedAgent(
                                "Verifier no-verdict state could not be persisted",
                                reason="candidate_state_write_failed")
                        claimed_sp_id = None
                        continue

                    is_important = updated_sp.is_important
                    is_real = updated_sp.is_real
                    score = updated_sp.score
                    notes = updated_sp.verification_notes

                    # Determine if this candidate was actually admitted.  In
                    # high-recall mode confidence and priority only order the
                    # queue; they cannot silently override an explicit
                    # TESTABLE_UNCERTAIN/SUPPORTED verdict.
                    proceed_to_pov = self._should_admit_pov(
                        self.config, updated_sp)

                    # Complete verification
                    completed = self.repos.suspicious_points.complete_verify(
                        sp.suspicious_point_id,
                        is_real=is_real,
                        score=score,
                        notes=notes,
                        is_important=is_important,
                        proceed_to_pov=proceed_to_pov,
                        processor_id=agent_id,
                        claim_token=claim_token,
                        verification_disposition=(
                            updated_sp.verification_disposition),
                    )
                    if self.llm_client_factory is not None and not completed:
                        raise IncompleteInjectedAgent(
                            "Verifier verdict could not be persisted",
                            reason="candidate_state_write_failed",
                        )
                    claimed_sp_id = None  # Successfully processed
                    wait_for_pov = proceed_to_pov

                    # Update stats
                    self.stats.sp_verified += 1
                    if self.config.pov_admission_mode == "explicit_disposition":
                        if updated_sp.verification_disposition == "SUPPORTED":
                            self.stats.sp_supported += 1
                        else:
                            self.stats.sp_testable_uncertain += 1
                    elif is_real:
                        self.stats.sp_verified_real += 1
                    else:
                        self.stats.sp_verified_fp += 1

                    logger.info(
                        f"[Pipeline:{agent_id}] Verified SP {sp.suspicious_point_id}: "
                        f"score={score:.2f}, real={is_real}, "
                        f"proceed_to_pov={proceed_to_pov}"
                    )
                else:
                    # An injected Verifier completed a remote turn, but the
                    # candidate disappeared or could not be read back. Do not
                    # report this as an empty queue or release it for retry.
                    if self.llm_client_factory is not None:
                        raise IncompleteInjectedAgent(
                            "Verifier candidate could not be read back",
                            reason="candidate_state_read_failed",
                        )
                    # Original non-injected behavior: release a missing SP.
                    self.repos.suspicious_points.release_claim(
                        sp.suspicious_point_id,
                        SPStatus.FAILED.value,
                        processor_id=agent_id,
                        claim_token=claim_token,
                    )
                    claimed_sp_id = None  # Handled

            except IncompleteInjectedAgent as e:
                if e.reason in _GRACEFUL_USER_STOP_REASONS:
                    claimed_sp_id = None
                    self._preserve_incomplete_candidate(
                        sp.suspicious_point_id, stage="verifier",
                        reason="user_stop_before_transport",
                        processor_id=agent_id, claim_token=claim_token)
                    return
                logger.error(
                    f"[Pipeline:{agent_id}] Incomplete verification for "
                    f"{sp.suspicious_point_id}: {e}"
                )
                self._incomplete_error = str(e)
                self._incomplete_reason = e.reason
                self._shutdown = True
                claimed_sp_id = None
                self._preserve_incomplete_candidate(
                    sp.suspicious_point_id, stage="verifier", reason=e.reason,
                    processor_id=agent_id, claim_token=claim_token)
                raise
            except asyncio.CancelledError as original:
                if self.llm_client_factory is not None:
                    # The remote request may have started. Never release this
                    # claim to an automatically retried pending_verify state.
                    reason = self._settled_campaign_cancellation_reason(
                        injected_client, injected_owner) or "uncertain_remote"
                    self._shutdown = True
                    self._record_injected_cancellation(
                        "Verifier", reason=reason)
                    claimed_sp_id = None
                    try:
                        self._preserve_incomplete_candidate(
                            sp.suspicious_point_id, stage="verifier",
                            reason=reason, processor_id=agent_id,
                            claim_token=claim_token)
                    except BaseException as cleanup:
                        original.add_note(
                            "Verifier cancellation state write failed: "
                            f"{type(cleanup).__name__}: {cleanup}")
                raise
            except Exception as e:
                logger.exception(
                    f"[Pipeline:{agent_id}] Error verifying SP {sp.suspicious_point_id}: {e}"
                )
                if self.llm_client_factory is not None:
                    reason = getattr(
                        e, "fbv2_stop_reason", "incomplete_unknown")
                    if reason in _GRACEFUL_USER_STOP_REASONS:
                        claimed_sp_id = None
                        self._preserve_incomplete_candidate(
                            sp.suspicious_point_id, stage="verifier",
                            reason="user_stop_before_transport",
                            processor_id=agent_id, claim_token=claim_token)
                        return
                    self._incomplete_error = str(e)
                    self._incomplete_reason = reason
                    self._shutdown = True
                    claimed_sp_id = None
                    self._preserve_incomplete_candidate(
                        sp.suspicious_point_id, stage="verifier",
                        reason=self._incomplete_reason,
                        processor_id=agent_id, claim_token=claim_token)
                    raise IncompleteInjectedAgent(
                        str(e), reason=self._incomplete_reason) from e
            finally:
                # Release claim if not successfully completed
                # Catches all exit paths including KeyboardInterrupt/CancelledError
                if claimed_sp_id:
                    try:
                        self.repos.suspicious_points.release_claim(
                            claimed_sp_id,
                            SPStatus.PENDING_VERIFY.value,
                            processor_id=agent_id,
                            claim_token=claim_token,
                        )
                    except Exception:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to release claim for {claimed_sp_id}"
                        )
                try:
                    from ..tools.suspicious_points import (
                        reset_sp_pov_admission_mode,
                        set_sp_verification_claim_token,
                    )
                    set_sp_verification_claim_token(None)
                    if admission_mode_token is not None:
                        reset_sp_pov_admission_mode(admission_mode_token)
                        admission_mode_token = None
                except Exception:
                    logger.warning(
                        f"[Pipeline:{agent_id}] Failed to clear verifier claim context")
                # Track verification time
                sp_duration = time_module.time() - sp_start_time
                self.stats.verify_time_total += sp_duration

            if self.prefer_pov_after_verify and wait_for_pov:
                await self._wait_for_pov_after_verify(sp.suspicious_point_id)

        logger.info(f"[Pipeline:{agent_id}] Verification agent stopped")

    def _settled_local_pov_json_failure(self, client, agent, result,
                                        owner: str) -> bool:
        """Recognize a local malformed proposal only from settled own turns.

        This is a failed PoV generation, not a completed NO_CRASH search. A
        transport uncertainty or any incomplete host side effect still stops
        the campaign through the ordinary injected-agent check.
        """
        if (self.llm_client_factory is None or
                getattr(agent, "stop_reason", None) != "invalid_model_tool_json" or
                result.success or result.crashed or result.pending_runtime or
                result.pending_validation or result.error_msg is not None or
                result.completed_at is None or
                type(result.pov_attempts) is not int or
                not 0 <= result.pov_attempts < agent.max_pov_attempts or
                not isinstance(getattr(client, "agent_id", None), str)):
            return False
        from devtools.campaign_model_gate import (
            CampaignGateError, CampaignLedgeredProvider, CampaignModelGate,
            _private_bytes,
        )
        provider = getattr(client, "provider", None)
        if (not isinstance(provider, CampaignLedgeredProvider) or
                provider.role != "pov" or provider.owner_id != owner or
                not isinstance(provider.gate, CampaignModelGate) or
                getattr(self.llm_client_factory, "_fbv2_campaign_gate", None)
                is not provider.gate):
            return False
        gate = provider.gate
        try:
            rows = gate.snapshot()["records"]
            own = [row for row in rows if row["owner_id"] == owner]
            if not own:
                return False
            if any(row["status"] in {
                    "UNCERTAIN", "PENDING_BUDGET", "PENDING_STOP"
            } for row in own):
                return False
            if any(event["status"] == "INCOMPLETE"
                   for row in own for event in row.get("tool_events", [])):
                return False
            for row in own:
                if (row["role"] != "pov" or row["status"] != "COMPLETED" or
                        gate.verify_response_evidence(
                            row["request_id"]).get("status") != "VERIFIED"):
                    return False
                for event in row.get("tool_events", []):
                    if (event["status"] != "COMPLETED" or
                            event.get("agent_id") != client.agent_id or
                            gate.verify_tool_event(
                                row["request_id"], event["call_id"]
                            ).get("status") != "VERIFIED"):
                        return False
            # One settled malformed proposal is already a deterministic local
            # generation failure when the response evidence is verified and
            # no host tool side effect occurred. Requiring two consecutive
            # malformed turns lets the first one escape to the campaign-wide
            # incomplete path without adding any stronger provenance.
            for row in own[-1:]:
                if row.get("tool_events"):
                    return False
                evidence = gate.verify_response_evidence(row["request_id"])
                raw = _private_bytes(Path(evidence["response_path"]))
                proposals = json.loads(raw)["tool_calls"]
                if (type(proposals) is not list or not proposals or
                        not any(
                            type(proposal) is dict and
                            type(proposal.get("arguments")) is str and
                            _invalid_tool_argument_json(proposal["arguments"])
                            for proposal in proposals)):
                    return False
            return True
        except (CampaignGateError, OSError, ValueError, TypeError, KeyError,
                IndexError):
            return False

    def _qualified_no_crash_input_count(self, sp, result, agent) -> int:
        """Recognize exhausted PoV attempts only from saved NO_CRASH receipts.

        The last completed model response may be a tool call, so a separate
        final text turn is not required after all bounded attempts. Missing or
        changed physical evidence remains incomplete, never a clean failure.
        """
        if (self.llm_client_factory is None or
                self.qualified_runtime_binding is None or
                agent.stop_reason is not None or result.error_msg is not None or
                result.completed_at is None or result.success or
                result.pending_runtime or result.pending_validation or
                type(result.pov_attempts) is not int or
                result.pov_attempts != agent.max_pov_attempts or
                result.pov_attempts < 1 or
                type(agent.total_tool_calls) is not int or
                agent.total_tool_calls < result.pov_attempts or
                result.total_variants != 3 * result.pov_attempts):
            return 0
        try:
            binding = self.qualified_runtime_binding
            adapter = getattr(binding.execute, "__self__", None)
            if (adapter is None or getattr(adapter, "binding", None) is not binding or
                    adapter.task_id != self.task_id or
                    adapter.fuzzer != self.fuzzer or
                    adapter.sanitizer != self.sanitizer or
                    adapter.repos is not self.repos):
                return 0
            process_state, _ = adapter.ledger.receipt_snapshot()
            active = process_state.get("active")
            # Other SP/PoV/Global workers legitimately share this physical
            # ledger. Their active leases cannot change this candidate's
            # immutable input and Runtime receipts. Each of this PoV's leases
            # is checked below against the durable finished list; a shared
            # stop remains campaign-fatal.
            if (process_state.get("stop_status") is not None or
                    type(active) is not dict or
                    type(process_state.get("finished")) is not list):
                return 0
            binary, binary_sha = binding.pinned_binary()
            rows = list(self.repos.povs.collection.find({
                "task_id": ObjectId(self.task_id),
                "suspicious_point_id": ObjectId(sp.suspicious_point_id),
                "agent_id": ObjectId(agent.mcp_context_id),
            }))
            if len(rows) != result.total_variants:
                return 0
            variants = set()
            successful_attempts = set()
            for raw in rows:
                pov_id = raw["pov_id"]
                attempt = raw["attempt"]
                variant = raw["variant"]
                saved = raw["qualified_runtime"]
                if (type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
                        raw["_id"] != ObjectId(pov_id) or
                        type(attempt) is not int or
                        not 1 <= attempt <= agent.total_tool_calls or
                        type(variant) is not int or not 1 <= variant <= 3 or
                        (attempt, variant) in variants or
                        raw["harness_name"] != self.fuzzer or
                        raw["sanitizer"] != self.sanitizer or
                        raw["is_successful"] is not False or
                        raw.get("is_active") is not True or
                        type(saved) is not dict or
                        saved.get("status") != "NO_CRASH"):
                    return 0
                variants.add((attempt, variant))
                successful_attempts.add(attempt)
                data = base64.b64decode(raw["blob"], validate=True)
                input_sha = hashlib.sha256(data).hexdigest()
                root = adapter.root / pov_id
                input_path = root / "input.bin"
                runtime_path = root / "runtime.json"
                physical_path = root / "physical.json"
                if (root.is_symlink() or root.resolve() != root or
                        input_path.is_symlink() or not input_path.is_file() or
                        input_path.read_bytes() != data or
                        saved.get("input_sha256") != input_sha or
                        saved.get("binary_sha256") != binary_sha or
                        saved.get("runtime_receipt_path") != str(runtime_path) or
                        saved.get("physical_receipt_path") != str(physical_path)):
                    return 0
                runtime = json.loads(runtime_path.read_bytes())
                physical = json.loads(physical_path.read_bytes())
                measured = runtime.get("runtime")
                lease = physical.get("lease")
                identity = {
                    "task_id": self.task_id,
                    "run_id": adapter.run_id,
                    "work_item_id": adapter.work_item_id,
                    "sp_id": sp.suspicious_point_id,
                    "pov_id": pov_id,
                    "input_sha256": input_sha,
                    "binary_sha256": binary_sha,
                }
                key_prefix = (f"{self.task_id}:{sp.suspicious_point_id}:"
                              f"{pov_id}:")
                if (type(runtime) is not dict or type(physical) is not dict or
                        type(measured) is not dict or type(lease) is not dict or
                        runtime.get("kind") !=
                            "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1" or
                        physical.get("kind") !=
                            "FBV2_DEV_QUALIFIED_POV_PHYSICAL_V1" or
                        any(runtime.get(k) != v or physical.get(k) != v
                            for k, v in identity.items()) or
                        runtime.get("status") != "NO_CRASH" or
                        runtime.get("source") != "FBV2_POV" or
                        runtime.get("command") !=
                            [str(binary), str(input_path)] or
                        runtime.get("input_path") != str(input_path) or
                        physical.get("input_path") != str(input_path) or
                        runtime.get("physical_receipt_sha256") !=
                            hashlib.sha256(physical_path.read_bytes()).hexdigest() or
                        measured.get("exit_code") != 0 or
                        measured.get("timed_out") is not False or
                        measured.get("sanitizer") is not None or
                        physical.get("ledger_path") != str(adapter.ledger.path) or
                        lease.get("kind") != "AUX_PROCESS" or
                        type(lease.get("key")) is not str or
                        re.fullmatch(re.escape(key_prefix) +
                                     r"[0-9]{6,}:pov\.qualified_direct",
                                     lease["key"]) is None or
                        lease.get("cleanup_complete") is not True or
                        lease.get("output_limited") is not False or
                        lease.get("overrun") is not False or
                        any(type(key) is str and key.startswith(key_prefix)
                            for key in active) or
                        [item for item in process_state["finished"]
                         if type(item) is dict and
                            type(item.get("key")) is str and
                            item["key"].startswith(key_prefix)] != [lease]):
                    return 0
                request = QualifiedRuntimeRequest(
                    task_id=self.task_id, suspicious_point_id=sp.suspicious_point_id,
                    pov_id=pov_id, harness_name=self.fuzzer,
                    sanitizer=self.sanitizer, input_bytes=data,
                    input_sha256=input_sha, binary_path=binary,
                    binary_sha256=binary_sha)
                outcome = QualifiedRuntimeOutcome(
                    status="NO_CRASH", pov_id=pov_id,
                    input_sha256=saved["input_sha256"],
                    binary_sha256=saved["binary_sha256"],
                    runtime_receipt_path=Path(saved["runtime_receipt_path"]),
                    runtime_receipt_sha256=saved["runtime_receipt_sha256"],
                    physical_receipt_path=Path(saved["physical_receipt_path"]),
                    physical_receipt_sha256=saved["physical_receipt_sha256"],
                    output_summary=saved.get("output_summary", ""),
                    sanitizer=saved.get("sanitizer"))
                validate_outcome(outcome, request)
            # The generator numbers every create_pov call, including failed
            # calls. The agent counts only successful batches. Require one
            # complete, receipt-backed triple per successful batch while
            # preserving the original (possibly gapped) attempt numbers.
            if len(successful_attempts) != result.pov_attempts:
                return 0
            return len(rows)
        except (KeyError, ValueError, TypeError, AttributeError, RuntimeError,
                OSError, binascii.Error, json.JSONDecodeError):
            return 0

    @staticmethod
    def _parallel_pov_outcome_already_settled(point) -> bool:
        """Recognize a sibling's authoritative result without double credit."""
        return bool(point is not None and (
            (point.status == SPStatus.POV_GENERATED.value and
             point.pov_success_by is not None) or
            (point.status in {
                SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
             } and point.pending_pov_ids)))

    async def _consume_qualified_gate(self, pov_ids: list[str]) -> bool:
        """Settle an already-started Gate thread before task cancellation.

        Cancelling an ``asyncio.to_thread`` waiter does not stop its worker
        thread. Without shielding, Pipeline cleanup can race the Gate's DB,
        process-ledger, and receipt writes. The Gate remains bounded by its own
        process envelope; this method only keeps one owner until it records a
        terminal outcome.
        """
        task = asyncio.create_task(asyncio.to_thread(
            self.qualified_gate_stop.consume, pov_ids))
        first_cancellation: asyncio.CancelledError | None = None
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as cancellation:
                if first_cancellation is None:
                    first_cancellation = cancellation
                current = asyncio.current_task()
                if current is not None:
                    current.uncancel()
        if first_cancellation is not None:
            try:
                task.result()
            except BaseException as cleanup:
                first_cancellation.add_note(
                    "Gate settlement after Pipeline cancellation failed: "
                    f"{type(cleanup).__name__}: {cleanup}")
            raise first_cancellation
        return task.result()

    async def _run_pov_agent(self, agent_id: str):
        """
        Run a POV generation agent loop.

        Agent continuously:
        1. Claims a pending_pov SP
        2. Generates POV using POVAgent
        3. Updates status (pov_generated or failed)
        4. Repeats until no more work

        Args:
            agent_id: Unique agent identifier
        """
        # Set analyzer context for this task (ContextVar needs to be set per-task)
        if self.mcp_socket_path:
            set_analyzer_context(self.mcp_socket_path, client_id=agent_id)
            logger.debug(
                f"[Pipeline:{agent_id}] Set analyzer context: {self.mcp_socket_path}"
            )

        logger.info(f"[Pipeline:{agent_id}] POV generation agent started")
        idle_cycles = 0

        while not self._shutdown and not self._gate_verified_stop_requested():
            # Try to claim a task (filter by fuzzer/sanitizer for worker isolation)
            claim_min_score = (
                0.0 if getattr(
                    self.config, "pov_admission_mode", "legacy_score"
                ) == "explicit_disposition"
                else self.config.pov_min_score)
            sp = self.repos.suspicious_points.claim_for_pov(
                self.task_id,
                agent_id,
                min_score=claim_min_score,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
                raise_on_error=self.llm_client_factory is not None,
            )

            if sp is None:
                # No work available - check if we should exit
                idle_cycles += 1

                # Only consider exiting if upstream (SP Finding) is done
                # Once SP Finding is done, both verify and POV will drain their queues
                if self._sp_finding_done:
                    # Check if there are any remaining pending_pov or verifying SPs
                    pending_pov = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="pending_pov",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        raise_on_error=self.llm_client_factory is not None,
                    )
                    # Also check if verify is still producing (pending_verify or verifying)
                    pending_verify = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="pending_verify",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        raise_on_error=self.llm_client_factory is not None,
                    )
                    verifying = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="verifying",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        raise_on_error=self.llm_client_factory is not None,
                    )
                    generating_pov = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="generating_pov",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        raise_on_error=self.llm_client_factory is not None,
                    )

                    # Exit only when: SP Finding done + no pending_pov + no pending_verify + no verifying
                    if (
                        pending_pov == 0
                        and pending_verify == 0
                        and verifying == 0
                        and generating_pov == 0
                        and idle_cycles >= 5
                    ):
                        logger.info(
                            f"[Pipeline:{agent_id}] All upstream done, no more work, exiting"
                        )
                        break

                # Log status periodically
                if idle_cycles % 30 == 0:
                    status = (
                        "waiting for upstream"
                        if not self._sp_finding_done
                        else "draining queue"
                    )
                    logger.debug(
                        f"[Pipeline:{agent_id}] Idle cycle {idle_cycles}, {status}"
                    )

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the SP with time tracking
            import time as time_module

            sp_start_time = time_module.time()
            sp_fuzzer_started = False
            claimed_sp_id = sp.suspicious_point_id
            retained_pov_claim = False
            injected_client = None
            injected_owner = None
            pov_claim_token = sp.pov_claim_token
            if not isinstance(pov_claim_token, str) or not pov_claim_token:
                raise IncompleteInjectedAgent(
                    "PoV claim lacks a generation token",
                    reason="candidate_state_read_failed")

            try:
                logger.info(
                    f"[Pipeline:{agent_id}] Generating POV for SP {sp.suspicious_point_id}"
                )

                # Acquire the opt-in model client before starting a physical SP
                # Fuzzer. A pre-send budget refusal must not launch that Fuzzer.
                # With no factory, the original start-before-Agent order stays.
                from devtools.campaign_model_gate import (
                    campaign_candidate_owner_id,
                )
                owner = campaign_candidate_owner_id(
                    agent_id=agent_id, task_id=self.task_id,
                    harness_name=self.fuzzer, sanitizer=self.sanitizer,
                    sp_id=sp.suspicious_point_id)
                injected_owner = owner
                async with injected_agent_client(
                    self.llm_client_factory, "pov", owner
                ) as client:
                    injected_client = client
                    # Start SP Fuzzer for this SP (starts when POV Agent begins processing SP)
                    if self.fuzzer_manager and self.llm_client_factory is None:
                        try:
                            sp_fuzzer_started = await self.fuzzer_manager.start_sp_fuzzer(
                                sp.suspicious_point_id
                            )
                            if sp_fuzzer_started:
                                logger.debug(
                                    f"[Pipeline:{agent_id}] Started SP Fuzzer for {sp.suspicious_point_id}"
                                )
                        except Exception as e:
                            logger.warning(
                                f"[Pipeline:{agent_id}] Failed to start SP Fuzzer: {e}"
                            )

                    # Run POV agent with fuzzer code
                    # Extract index from agent_id (e.g., "pov_1" -> 1)
                    agent_index = int(agent_id.split("_")[1]) if "_" in agent_id else 0
                    pov_agent = POVAgent(
                        fuzzer=self.fuzzer,
                        sanitizer=self.sanitizer,
                        llm_client=client,
                        model=CLAUDE_SONNET_4_5,  # Original model by default
                        task_id=self.task_id,
                        worker_id=self.worker_id,  # Use actual worker_id, not agent_id
                        output_dir=self.output_dir,
                        log_dir=self.log_dir,
                        repos=self.repos,
                        max_iterations=self.config.max_iterations,
                        max_pov_attempts=self.config.max_pov_attempts,
                        fuzzer_path=self.config.fuzzer_path,
                        docker_image=self.config.docker_image,
                        workspace_path=self.workspace_path,
                        fuzzer_code=self.fuzzer_code,
                        fuzzer_manager=(self.fuzzer_manager
                                        if self.llm_client_factory is None else None),
                        qualified_runtime_required=self.llm_client_factory is not None,
                        qualified_runtime_binding=self.qualified_runtime_binding,
                        index=agent_index,
                        target_name=sp.function_name or "",
                    )

                    result = await pov_agent.generate_pov_async(sp.to_dict())
                    no_crash_inputs = self._qualified_no_crash_input_count(
                        sp, result, pov_agent)
                    local_json_failure = self._settled_local_pov_json_failure(
                        client, pov_agent, result, owner)
                    pending_runtime = bool(
                        self.llm_client_factory is not None and
                        getattr(result, "pending_runtime", False))
                    pending_validation = bool(
                        self.llm_client_factory is not None and
                        getattr(result, "pending_validation", False))
                    if not local_json_failure:
                        require_injected_agent_complete(
                            client, pov_agent,
                            tool_success=bool(result.success or pending_runtime or
                                              pending_validation or no_crash_inputs)
                        )

                if pending_runtime or pending_validation:
                    ids = getattr(result, "generated_pov_ids", None)
                    if (result.success or getattr(result, "crashed", False) or
                            not isinstance(ids, list) or not ids or
                            not self.repos.suspicious_points.preserve_pov_pending_runtime(
                                sp.suspicious_point_id, ids, task_id=self.task_id,
                                harness_name=self.fuzzer,
                                sanitizer=self.sanitizer,
                                processor_id=agent_id,
                                claim_token=pov_claim_token,
                                **({"validation_pending": True}
                                   if pending_validation else {}))):
                        raise IncompleteInjectedAgent(
                            "generated PoV inputs could not be retained for qualified Runtime",
                            reason="pov_pending_persist_failed")
                    claimed_sp_id = None
                    retained_pov_claim = True
                    if pending_validation:
                        self.stats.pov_pending_validation += 1
                    else:
                        self.stats.pov_pending_runtime += 1
                    logger.info(
                        f"[Pipeline:{agent_id}] Retained {len(ids)} PoV inputs "
                        f"pending qualified Runtime for SP {sp.suspicious_point_id}"
                    )
                    if pending_validation and self.qualified_gate_stop is not None:
                        # The model turn and its host tools have settled. The
                        # product consumer owns any replay and records its
                        # decision before it may request an early stop.
                        try:
                            await self._consume_qualified_gate(ids)
                        except Exception as exc:
                            raise IncompleteInjectedAgent(
                                "independent Gate consumption is incomplete",
                                reason="gate_consumption_failed") from exc
                    continue

                # Complete POV generation
                # On failure, pass harness_name/sanitizer so other contributors can retry
                completed = self.repos.suspicious_points.complete_pov(
                    sp.suspicious_point_id,
                    pov_id=result.pov_id if result.success else None,
                    success=result.success,
                    harness_name=self.fuzzer,
                    sanitizer=self.sanitizer,
                    require_claim=True,
                    processor_id=agent_id,
                    claim_token=pov_claim_token,
                    **({"local_failure_reason": "invalid_model_tool_json",
                        "local_failure_attempts": result.pov_attempts}
                       if local_json_failure else {}),
                )
                if self.llm_client_factory is not None and local_json_failure:
                    failure = {"harness_name": self.fuzzer,
                               "sanitizer": self.sanitizer,
                               "reason": "invalid_model_tool_json",
                               "pov_attempts": result.pov_attempts}
                    recorded = self.repos.suspicious_points.collection.find_one(
                        {"_id": ObjectId(sp.suspicious_point_id),
                         "pov_local_failures": failure},
                        {"_id": 1},
                    )
                    if completed and recorded is None:
                        raise IncompleteInjectedAgent(
                            "local PoV failure was not persisted",
                            reason="candidate_state_write_failed")
                if self.llm_client_factory is not None and not completed:
                    current = self.repos.suspicious_points.find_by_id(
                        sp.suspicious_point_id)
                    if self._parallel_pov_outcome_already_settled(current):
                        # Another contributor already persisted an
                        # authoritative success or qualified evidence. A
                        # losing normal completion is not a DB failure and
                        # must not cancel that sibling's Runtime/Gate work.
                        claimed_sp_id = None
                        continue
                    raise IncompleteInjectedAgent(
                        "PoV outcome could not be persisted",
                        reason="candidate_state_write_failed",
                    )
                claimed_sp_id = None  # Successfully processed

                # Update stats
                self.stats.pov_no_crash_inputs_executed += no_crash_inputs
                if result.success:
                    self.stats.pov_generated += 1
                    logger.info(
                        f"[Pipeline:{agent_id}] Generated POV {result.pov_id} for SP {sp.suspicious_point_id}"
                    )
                else:
                    self.stats.pov_failed += 1
                    logger.warning(
                        f"[Pipeline:{agent_id}] Failed to generate POV for SP {sp.suspicious_point_id}"
                    )

            except IncompleteInjectedAgent as e:
                if e.reason in _GRACEFUL_USER_STOP_REASONS:
                    claimed_sp_id = None
                    if not retained_pov_claim:
                        self._preserve_incomplete_candidate(
                            sp.suspicious_point_id, stage="pov",
                            reason="user_stop_before_transport",
                            processor_id=agent_id,
                            claim_token=pov_claim_token)
                    return
                logger.error(
                    f"[Pipeline:{agent_id}] Incomplete POV for "
                    f"{sp.suspicious_point_id}: {e}"
                )
                self._incomplete_error = str(e)
                self._incomplete_reason = e.reason
                self._shutdown = True
                claimed_sp_id = None
                if not retained_pov_claim:
                    self._preserve_incomplete_candidate(
                        sp.suspicious_point_id, stage="pov", reason=e.reason,
                        processor_id=agent_id,
                        claim_token=pov_claim_token)
                self.stats.pov_failed += 1
                raise
            except asyncio.CancelledError as original:
                if self.llm_client_factory is not None:
                    # Cancellation after a possible physical model start must
                    # not make this verified candidate eligible for a resend.
                    reason = self._settled_campaign_cancellation_reason(
                        injected_client, injected_owner) or "uncertain_remote"
                    self._shutdown = True
                    self._record_injected_cancellation("PoV", reason=reason)
                    claimed_sp_id = None
                    try:
                        if not retained_pov_claim:
                            self._preserve_incomplete_candidate(
                                sp.suspicious_point_id, stage="pov",
                                reason=reason, processor_id=agent_id,
                                claim_token=pov_claim_token)
                    except BaseException as cleanup:
                        original.add_note(
                            "PoV cancellation state write failed: "
                            f"{type(cleanup).__name__}: {cleanup}")
                raise
            except Exception as e:
                logger.exception(
                    f"[Pipeline:{agent_id}] Error generating POV for SP {sp.suspicious_point_id}: {e}"
                )
                self.stats.pov_failed += 1
                if self.llm_client_factory is not None:
                    reason = getattr(
                        e, "fbv2_stop_reason", "incomplete_unknown")
                    if reason in _GRACEFUL_USER_STOP_REASONS:
                        claimed_sp_id = None
                        if not retained_pov_claim:
                            self._preserve_incomplete_candidate(
                                sp.suspicious_point_id, stage="pov",
                                reason="user_stop_before_transport",
                                processor_id=agent_id,
                                claim_token=pov_claim_token)
                        return
                    self._incomplete_error = str(e)
                    self._incomplete_reason = reason
                    self._shutdown = True
                    claimed_sp_id = None
                    if not retained_pov_claim:
                        self._preserve_incomplete_candidate(
                            sp.suspicious_point_id, stage="pov",
                            reason=self._incomplete_reason,
                            processor_id=agent_id,
                            claim_token=pov_claim_token)
                    raise IncompleteInjectedAgent(
                        str(e), reason=self._incomplete_reason) from e
            finally:
                # Release claim if not successfully completed
                # Catches all exit paths including KeyboardInterrupt/CancelledError
                # Pass harness_name/sanitizer to also clean pov_attempted_by
                # so the same worker can retry after crash recovery
                if claimed_sp_id:
                    try:
                        self.repos.suspicious_points.release_claim(
                            claimed_sp_id,
                            SPStatus.PENDING_POV.value,
                            harness_name=self.fuzzer,
                            sanitizer=self.sanitizer,
                            processor_id=agent_id,
                            claim_token=pov_claim_token,
                        )
                    except Exception:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to release claim for {claimed_sp_id}"
                        )

                # Stop SP Fuzzer (stops when POV succeeds or fails)
                if sp_fuzzer_started and self.fuzzer_manager:
                    try:
                        await self.fuzzer_manager.stop_sp_fuzzer(sp.suspicious_point_id)
                        logger.debug(
                            f"[Pipeline:{agent_id}] Stopped SP Fuzzer for {sp.suspicious_point_id}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to stop SP Fuzzer: {e}"
                        )

                # Track POV generation time
                sp_duration = time_module.time() - sp_start_time
                self.stats.pov_time_total += sp_duration

        logger.info(f"[Pipeline:{agent_id}] POV generation agent stopped")


async def run_pipeline(
    task_id: str,
    repos: RepositoryManager,
    fuzzer: str = "",
    sanitizer: str = "address",
    scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
    num_verify_agents: int = 2,
    num_pov_agents: int = 1,
    pov_min_score: float = 0.5,
    output_dir: Path = None,
    log_dir: Path = None,
    fuzzer_path: Path = None,
    docker_image: str = None,
    max_iterations: int = 200,
    max_pov_attempts: int = 40,
    workspace_path: Path = None,
    fuzzer_code: str = "",
    sp_finding_done: bool = True,  # Default True for delta mode
    worker_id: str = None,
) -> PipelineStats:
    """
    Convenience function to run the pipeline.

    Args:
        task_id: Task ID
        repos: Database repository manager
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        num_verify_agents: Number of verification agents
        num_pov_agents: Number of POV generation agents
        pov_min_score: Minimum score for POV generation
        output_dir: Directory for POV output
        log_dir: Directory for agent logs
        fuzzer_path: Path to fuzzer binary (for POV verification)
        docker_image: Docker image for running fuzzer
        max_iterations: Max POV agent iterations
        max_pov_attempts: Max POV generation attempts
        workspace_path: Path to workspace (for reading source code)
        fuzzer_code: Fuzzer source code (for verify agent context)
        sp_finding_done: Whether SP finding is already complete (True for delta mode)
        worker_id: Worker ID for FuzzerManager lookup

    Returns:
        Pipeline statistics
    """
    config = PipelineConfig(
        num_verify_agents=num_verify_agents,
        num_pov_agents=num_pov_agents,
        pov_min_score=pov_min_score,
        fuzzer_path=fuzzer_path,
        docker_image=docker_image,
        max_iterations=max_iterations,
        max_pov_attempts=max_pov_attempts,
    )

    pipeline = AgentPipeline(
        task_id=task_id,
        repos=repos,
        fuzzer=fuzzer,
        sanitizer=sanitizer,
        scan_mode=scan_mode,
        config=config,
        output_dir=output_dir,
        log_dir=log_dir,
        workspace_path=workspace_path,
        fuzzer_code=fuzzer_code,
        worker_id=worker_id,
    )

    # Set SP finding done flag so agents can exit when queue is empty
    pipeline._sp_finding_done = sp_finding_done

    return await pipeline.run()
