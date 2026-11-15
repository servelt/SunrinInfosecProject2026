"""One provider-free task through original FBv2 orchestration and queues.

Scripted role outcomes replace model transport, and a protected Global
campaign fake replaces physical execution. This proves handoff/order only;
it is not a live vulnerability-discovery or Gate test.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId

from devtools.original_global_bridge import OriginalGlobalBridge
from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.suspicious_point import SPStatus, SuspiciousPoint
from fuzzingbrain.fuzzer import get_fuzzer_manager
from fuzzingbrain.tools.pov import clear_pov_context, create_pov_impl, set_pov_context
from fuzzingbrain.tools.qualified_runtime import (
    QualifiedRuntimeBinding, QualifiedRuntimeOutcome,
)
from fuzzingbrain.worker.executor import WorkerExecutor
from fuzzingbrain.worker.pipeline import PipelineConfig
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


def test_original_direction_seed_global_sp_verify_pov_one_task(tmp_path, repos):
    task_id = str(ObjectId())
    direction_id = str(ObjectId())
    agent_id = str(ObjectId())
    binary = tmp_path / "qualified-fuzzer"
    binary.write_bytes(b"provider-free pinned binary")
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert repos.functions.save(Function(
        task_id=task_id, name="parse_input", file_path="parse.c",
        start_line=1, end_line=1,
        content="int parse_input(const char *p) { return *p; }"))
    events: list[str] = []
    clients: list[str] = []
    candidate_id = str(ObjectId())
    callback_requests = []

    def qualified_runtime(request):
        callback_requests.append(request)
        events.append("qualified_runtime")
        runtime_receipt = tmp_path / f"{request.pov_id}.runtime.json"
        physical_receipt = tmp_path / f"{request.pov_id}.physical.json"
        runtime_receipt.write_text('{"fixture": "crash observation"}')
        physical_receipt.write_text('{"fixture": "one physical execution"}')
        return QualifiedRuntimeOutcome(
            status="NO_CRASH", pov_id=request.pov_id,
            input_sha256=request.input_sha256,
            binary_sha256=request.binary_sha256,
            runtime_receipt_path=runtime_receipt,
            runtime_receipt_sha256=hashlib.sha256(runtime_receipt.read_bytes()).hexdigest(),
            physical_receipt_path=physical_receipt,
            physical_receipt_sha256=hashlib.sha256(physical_receipt.read_bytes()).hexdigest(),
            sanitizer=None,
        )

    qualified_binding = QualifiedRuntimeBinding(object(), qualified_runtime)

    class ScriptedClient:
        last_agent_response_was_final = True

        def __init__(self, role):
            self.role = role
            clients.append(role)

        async def close(self):
            pass

    class ProtectedGlobalCampaign:
        def __init__(self):
            self.q = SimpleNamespace(
                product_issued=True,
                contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
                binary=binary, binary_sha256=binary_sha)
            self.global_seconds = 2
            self.global_wall_reservation_seconds = 4
            self.require_accounted_consumer = True
            self.process = None
            self.staged = None

        def _authority_ok(self):
            return True

        def stage_direction_seeds(self, plan, sha, seeds):
            assert hashlib.sha256(plan.read_bytes()).hexdigest() == sha
            assert [(seed.direction_id, seed.path.read_bytes())
                    for seed in seeds] == [(direction_id, b"seed-from-direction")]
            self.staged = (plan, sha, seeds)
            events.append("global_stage")

        def start(self):
            assert self.staged is not None
            events.append("global_start")
            return "ACTIVE"

        def finish(self):
            events.append("global_finish")
            return {"status": "RAN", "cleanup_complete": True,
                    "consumer_rows": []}

        def abort(self):
            events.append("global_abort")
            return {"status": "STOPPED_ABORTED", "cleanup_complete": True}

    campaign = ProtectedGlobalCampaign()

    def bridge_factory(path: Path, sha: str):
        return OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=path,
            direction_plan_sha256=sha, seed_spool=tmp_path / "seed-spool",
            expected_binary_sha256=binary_sha)

    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fuzz_input", sanitizer="address", task_type="pov",
        repos=repos, task_id=task_id, fuzzer_binary_path=str(binary),
        llm_client_factory=lambda role, owner: ScriptedClient(role),
        qualified_seed_generator=lambda **kwargs: [],
        qualified_pov_runtime_binding=qualified_binding,
        require_original_global_bridge=True,
        original_global_bridge_factory=bridge_factory)
    strategy = POVFullscanStrategy(
        executor, llm_client_factory=executor.llm_client_factory)

    class DirectionRole:
        stop_reason = None
        mcp_context_id = agent_id

        def __init__(self, **_kwargs):
            pass

        async def plan_directions_async(self, **_kwargs):
            events.append("direction")
            assert repos.directions.save(Direction(
                direction_id=direction_id, task_id=task_id,
                fuzzer="fuzz_input", created_by_agent_id=agent_id,
                name="input parser", risk_level="high",
                core_functions=["parse_input"], entry_functions=[]))
            return {"success": True, "directions_created": 1,
                    "direction_ids": [direction_id]}

    class SeedRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.manager = kwargs["fuzzer_manager"]

        async def generate_direction_seeds(self, *, direction_id, **_kwargs):
            events.append("seed")
            self.manager.add_direction_seed(b"seed-from-direction", direction_id)
            return {"success": True, "seeds_generated": 1}

    class SPRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.direction_id = kwargs["direction_id"]

        async def analyze_async(self):
            events.append("sp")
            assert repos.suspicious_points.save(SuspiciousPoint(
                suspicious_point_id=candidate_id, task_id=task_id,
                function_name="parse_input", direction_id=self.direction_id,
                description="scripted hypothesis", vuln_type="buffer-overflow",
                score=0.9, sources=[{"harness_name": "fuzz_input",
                                     "sanitizer": "address"}]))
            return {"success": True, "sp_created": True}

    class VerifierRole:
        stop_reason = None

        def __init__(self, **kwargs):
            assert kwargs["max_iterations"] == 6
            self.sp_id = None

        def set_context(self, *, suspicious_point):
            self.sp_id = suspicious_point["suspicious_point_id"]

        async def run_async(self, **_kwargs):
            events.append("verify")
            assert self.sp_id == candidate_id
            current = repos.suspicious_points.find_by_id(self.sp_id)
            assert repos.suspicious_points.update_verifier_fields(
                self.sp_id, {
                    "is_checked": True, "is_real": False,
                    "is_important": True, "score": 0.9,
                    "verification_notes": "scripted queue handoff only"},
                claim_token=current.verification_claim_token)
            return "scripted verdict"

    class PoVRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.ctx_id = kwargs["worker_id"]
            self.kwargs = kwargs

        async def generate_pov_async(self, suspicious_point):
            events.append("pov")
            assert suspicious_point["suspicious_point_id"] == candidate_id
            set_pov_context(
                task_id=task_id, worker_id=self.ctx_id,
                output_dir=self.kwargs["output_dir"], repos=repos,
                fuzzer="fuzz_input", sanitizer="address",
                suspicious_point_id=candidate_id, fuzzer_path=binary,
                qualified_runtime_required=True,
                qualified_runtime_binding=self.kwargs["qualified_runtime_binding"],
            )
            try:
                generated = create_pov_impl(
                    "def generate(variant): return bytes([variant])",
                    worker_id=self.ctx_id)
            finally:
                clear_pov_context(self.ctx_id)
            assert generated["runtime_status"] == "NO_CRASH"
            return SimpleNamespace(
                success=False, crashed=False, pending_runtime=False,
                pending_validation=False, pov_id=None,
                error_msg="scripted no-crash result",
                generated_pov_ids=generated["pov_ids"])

    original_config = PipelineConfig

    def quick_config(**kwargs):
        kwargs.update(num_verify_agents=1, num_pov_agents=1,
                      poll_interval=0.005, max_idle_cycles=6,
                      verifier_max_iterations=6)
        return original_config(**kwargs)

    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent",
               return_value=DirectionRole()), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent", SeedRole), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator", SPRole), \
         patch("fuzzingbrain.worker.pipeline.SPVerifier", VerifierRole), \
         patch("fuzzingbrain.worker.pipeline.POVAgent", PoVRole), \
         patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)), \
         patch("fuzzingbrain.tools.pov._execute_generator_code",
               return_value=([b"A", b"B", b"C"], None)), \
         patch("fuzzingbrain.worker.pipeline.PipelineConfig",
               side_effect=quick_config):
        stats = asyncio.run(strategy._run_full_pipeline())

    stored = repos.suspicious_points.find_by_id(candidate_id)
    assert stored.description == "scripted hypothesis"
    assert stored.is_checked is True
    assert stored.pov_id is None
    assert stats.sp_verified == 1
    assert stats.pov_failed == 1
    assert len(callback_requests) == 3
    assert all(request.suspicious_point_id == candidate_id
               for request in callback_requests)
    assert [request.input_bytes for request in callback_requests] == [b"A", b"B", b"C"]
    assert all(request.input_sha256 == hashlib.sha256(request.input_bytes).hexdigest()
               for request in callback_requests)
    assert len(repos.povs.find_by_task(task_id)) == 3
    assert stored.status != SPStatus.PENDING_INDEPENDENT_VALIDATION.value
    assert events == ["direction", "seed", "global_stage", "global_start",
                      "sp", "verify", "pov", "qualified_runtime",
                      "qualified_runtime", "qualified_runtime", "global_finish"]
    assert clients == ["direction", "seed", "sp", "verifier", "pov"]
    assert get_fuzzer_manager(executor.worker_id) is None
    assert campaign.staged is not None
    assert (executor.results_path / "DIRECTION_PLAN.json").is_file()
