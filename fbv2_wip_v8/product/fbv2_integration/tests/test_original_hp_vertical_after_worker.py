"""Provider-free original Worker completion followed by opt-in product HP.

Original Direction/Seed/SP/Verifier/PoV roles and Global are scripted here.
The original WorkerContext and queue execute; this is no live model, Target,
Guided Fuzzing, or vulnerability-discovery evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId

from devtools.original_global_bridge import OriginalGlobalBridge
from devtools.original_hp_post_worker import run_post_worker_hp
from devtools.original_hp_preparation import (
    prepare_hp_function, run_prepared_hp_assertion_handoff,
)
from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint
from fuzzingbrain.core.models.worker import WorkerStatus
from fuzzingbrain.worker.executor import WorkerExecutor
from fuzzingbrain.worker.pipeline import PipelineConfig
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from vulnerabilityanalysis import official_harness
from vulnerabilityanalysis.agents import AgentPipeline


def test_original_worker_finishes_before_hp_and_preserves_original_result(
        tmp_path, monkeypatch, mock_db, repos):
    task_id, direction_id, candidate_id, agent_id = (
        str(ObjectId()) for _ in range(4))
    run_id = "provider_free_hp_vertical"
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = "int parse_input(const char *p) {\n  return *p;\n}\n"
    (source_root / "parser.c").write_text(source)
    harness = tmp_path / "fuzzer.cc"
    harness.write_text("int LLVMFuzzerTestOneInput() {return 0;}\n")
    binary = tmp_path / "fuzzer"
    binary.write_bytes(b"provider-free binary fixture")

    class Qualification:
        def __init__(self):
            self.product_issued = True
            self.contract_kind = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"
            self.source_tree_sha256 = "1" * 64
            self.contract_sha256 = "2" * 64
            self.source_root = source_root
            self.harness = harness
            self.binary = binary
            self.harness_sha256 = hashlib.sha256(harness.read_bytes()).hexdigest()
            self.binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    q = Qualification()
    q.normal_seed = tmp_path / "normal_seed"
    q.normal_seed.write_bytes(b"A")
    q.normal_seed_sha256 = hashlib.sha256(q.normal_seed.read_bytes()).hexdigest()
    monkeypatch.setattr(official_harness, "OfficialPinnedQualification", Qualification)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok", lambda row: row is q)
    assert repos.functions.save(Function(
        task_id=task_id, name="parse_input", file_path="parser.c",
        start_line=1, end_line=3, content=source))
    events: list[str] = []

    class ScriptedClient:
        last_agent_response_was_final = True

        async def close(self):
            return None

    process = {"stop_status": None, "active": {}, "revision": 1}
    process_sha = "a" * 64
    process_ledger = SimpleNamespace(
        snapshot=lambda: process,
        receipt_snapshot=lambda: (process, process_sha))
    model = {"campaign_id": run_id, "physical": 0, "records": []}
    model_gate = SimpleNamespace(campaign_id=run_id, snapshot=lambda: model)

    class ProtectedGlobalCampaign:
        global_seconds = 2
        global_wall_reservation_seconds = 4
        require_accounted_consumer = True

        def __init__(self):
            self.q = q
            self.ledger = process_ledger
            self.campaign = SimpleNamespace(process_envelope=SimpleNamespace(
                ledger=process_ledger))
            self.reservation_key = f"GLOBAL_FUZZ:{task_id}:{run_id}"
            self.process = None
            self.final_result = None

        def _authority_ok(self):
            return official_harness._qualification_pins_ok(q)

        def stage_direction_seeds(self, plan, sha, seeds):
            assert hashlib.sha256(plan.read_bytes()).hexdigest() == sha
            assert [(row.direction_id, row.path.read_bytes()) for row in seeds] == [
                (direction_id, b"fixture-seed")]
            events.append("global_stage")

        def start(self):
            events.append("global_start")
            return "ACTIVE"

        def finish(self):
            events.append("global_finish")
            self.final_result = {"status": "RAN", "cleanup_complete": True}
            return self.final_result

        def abort(self):
            events.append("global_abort")
            self.final_result = {"status": "STOPPED_ABORTED", "cleanup_complete": True}
            return self.final_result

    campaign = ProtectedGlobalCampaign()

    def global_factory(path, sha):
        return OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=path,
            direction_plan_sha256=sha, seed_spool=tmp_path / "seed-spool",
            expected_binary_sha256=q.binary_sha256)

    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fuzz_fixture", sanitizer="address", task_type="pov",
        repos=repos, task_id=task_id, fuzzer_binary_path=str(binary),
        llm_client_factory=lambda _role, _owner: ScriptedClient(),
        require_original_global_bridge=True,
        original_global_bridge_factory=global_factory)
    strategy = POVFullscanStrategy(executor, llm_client_factory=executor.llm_client_factory)

    class DirectionRole:
        stop_reason = None
        mcp_context_id = agent_id

        async def plan_directions_async(self, **_kwargs):
            events.append("direction")
            assert repos.directions.save(Direction(
                direction_id=direction_id, task_id=task_id,
                fuzzer="fuzz_fixture", created_by_agent_id=agent_id,
                name="parser", core_functions=["parse_input"],
                entry_functions=[]))
            return {"success": True, "directions_created": 1,
                    "direction_ids": [direction_id]}

    class SeedRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.manager = kwargs["fuzzer_manager"]

        async def generate_direction_seeds(self, *, direction_id, **_kwargs):
            events.append("seed")
            self.manager.add_direction_seed(b"fixture-seed", direction_id)
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
                score=0.9, sources=[{"harness_name": "fuzz_fixture",
                                     "sanitizer": "address"}]))
            return {"success": True, "sp_created": True}

    class VerifierRole:
        stop_reason = None

        def __init__(self, **_kwargs):
            pass

        def set_context(self, *, suspicious_point):
            assert suspicious_point["suspicious_point_id"] == candidate_id

        async def run_async(self, **_kwargs):
            events.append("verify")
            assert repos.suspicious_points.update(candidate_id, {
                "is_checked": True, "is_important": True,
                "verification_notes": "fixture only"})
            return "fixture verdict"

    class PoVRole:
        stop_reason = None

        def __init__(self, **_kwargs):
            pass

        async def generate_pov_async(self, suspicious_point):
            assert suspicious_point["suspicious_point_id"] == candidate_id
            events.append("pov")
            return SimpleNamespace(
                success=False, crashed=False, pending_runtime=False,
                pending_validation=False, pov_id=None, generated_pov_ids=[])

    original_config = PipelineConfig

    def quick_config(**kwargs):
        kwargs.update(num_verify_agents=1, num_pov_agents=1,
                      poll_interval=0.005, max_idle_cycles=6)
        return original_config(**kwargs)

    with patch("fuzzingbrain.db.get_database", return_value=mock_db), \
         patch("fuzzingbrain.llms.buffer.WorkerLLMBuffer"), \
         patch("fuzzingbrain.llms.buffer.set_worker_buffer"), \
         patch.object(executor, "_get_strategy", return_value=strategy), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent",
               return_value=DirectionRole()), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent", SeedRole), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator", SPRole), \
         patch("fuzzingbrain.worker.pipeline.SPVerifier", VerifierRole), \
         patch("fuzzingbrain.worker.pipeline.POVAgent", PoVRole), \
         patch("fuzzingbrain.worker.pipeline.PipelineConfig", side_effect=quick_config):
        original = executor.run()

    assert events == ["direction", "seed", "global_stage", "global_start",
                      "sp", "verify", "pov", "global_finish"]
    assert executor._worker_context.status == "completed"
    stored_worker = repos.workers.find_by_id(original["worker_id"])
    assert stored_worker.status == WorkerStatus.COMPLETED
    assert stored_worker.result_summary == original
    analyzed = repos.functions.find_by_name(task_id, "parse_input")
    assert analyzed.analyzed_by_directions == [direction_id]
    plan = strategy._development_direction_plan
    assert plan is not None

    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id=task_id, run_id=run_id,
                                 run_dir=tmp_path / "run"),
        executor=executor, strategy=strategy,
        server=SimpleNamespace(repos=repos),
        admission=SimpleNamespace(qualification=q,
                                  prepared={"fuzzer_name": "fuzz_fixture"}),
        model_gate=model_gate, process_ledger=process_ledger,
        global_campaign=campaign, recheck=lambda: None)
    receipt = {
        "kind": "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1",
        "task_id": task_id, "run_id": run_id,
        "execution_status": "EXECUTED", "global_status": "RAN",
        "original_result": original, "model_physical_calls": 0,
        "process_receipt_sha256": process_sha,
        "process_stop_status": None,
    }

    class HPProvider:
        def __init__(self, role, response):
            self.role = role
            self.response = response
            self.requests = []
            self.closed = False

        async def generate(self, request):
            self.requests.append(request)
            events.append("hp_" + self.role)
            return self.response

        async def close(self):
            self.closed = True

    analysis = HPProvider("function_analysis", {
        "summary": "Reads p", "input_flow": "p comes from input",
        "state_dependencies": [], "context_requests": [],
        "safe_assumptions": [], "unknowns": [], "input_sources": ["p"],
        "security_sensitive_operations": ["*p"], "validations": [],
        "memory_operations": ["read *p"], "evidence": ["return *p;"],
        "hypothesis_evaluations": [],
    })
    assertion = HPProvider("assertion_generator", {})
    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(analysis),
        assertion_pipeline_factory=lambda _work: AgentPipeline(assertion),
        max_items=1, provider_free_fixture=True))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["selected_count"] == 1
    assert result["rows"][0]["status"] == "NO_SAFE_ASSUMPTION"
    assert result["original_result"] == original
    assert stored_worker.result_summary == original
    assert result["sp_global_effect"] == "UNCHANGED"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert len(analysis.requests) == 1 and assertion.requests == []
    assert analysis.closed and assertion.closed
    assert events[-1] == "hp_function_analysis"

    safe = "The input pointer is not null"
    positive_analysis = HPProvider("function_analysis", {
        "summary": "Reads p", "input_flow": "p comes from input",
        "state_dependencies": [], "context_requests": [],
        "safe_assumptions": [safe], "unknowns": [], "input_sources": ["p"],
        "security_sensitive_operations": ["*p"], "validations": [],
        "memory_operations": ["read *p"], "evidence": ["return *p;"],
        "hypothesis_evaluations": [{
            "source_location": "parser.c:2", "source_file": "parser.c",
            "source_line": 2, "source_quote": "return *p;",
            "security_property": "valid memory read",
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": "p may be null",
            "judgment": "EXPLICIT_SAFE_JUDGMENT",
            "reason": "the read requires a valid pointer",
            "safe_assumption": safe,
        }],
    })
    positive_assertion = HPProvider("assertion_generator", {
        "assertions": [{"safe_id": 0, "safe_assumption": safe,
                        "runtime_expression": "p != 0", "source_line": 2,
                        "required_context": [], "rationale": "check before read"}],
        "dispositions": [{"safe_id": 0, "safe_assumption": safe,
                          "status": "PROPOSED", "reason": "expressible"}],
    })
    positive = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(positive_analysis),
        assertion_pipeline_factory=lambda _work: AgentPipeline(positive_assertion),
        max_items=1, provider_free_fixture=True))
    assert positive["status"] == "HP_POST_WORKER_COMPLETE"
    row = positive["rows"][0]
    assert row["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert row["proposed_assertion_count"] == 1
    assert row["assertion_proposals"][0]["generation_method"] == "PROVIDER_FREE_FIXTURE"
    prepared = prepare_hp_function(
        function=analyzed, direction=repos.directions.find_by_id(direction_id),
        qualification=q, fuzzer="fuzz_fixture", sanitizer="address")
    proposal_id = row["assertion_proposals"][0]["assertion_id"]
    calls = []

    def execute(assertion, source, line, seed, output, build, run, **_kwargs):
        calls.append(("execute", assertion.assertion_id, source, line, seed))
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    def guided(assertion, source, line, seed, output, build, run, **kwargs):
        calls.append(("guided", assertion.assertion_id, source, line, seed))
        assert kwargs["seconds"] == 1
        return {"status": "RAN", "violation_witnesses": []}

    handoff = run_prepared_hp_assertion_handoff(
        work=prepared, qualification=q, analysis_result=row,
        worker_id=original["worker_id"], assertion_id=proposal_id,
        output_dir=tmp_path / "hp-assertion-output",
        build_command=["clang", "-fsanitize=fuzzer,address", "{source}",
                       str(harness), "-o", "{binary}"],
        run_command=["{binary}", "{input}"], guided_seconds=1,
        provider_free_fixture=True, execute_callback=execute,
        guided_callback=guided)
    assert [call[0] for call in calls] == ["execute", "guided"]
    assert all(call[1:] == (proposal_id, source_root / "parser.c", 2,
                             q.normal_seed) for call in calls)
    assert handoff["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert handoff["guided_status"] == "RAN"
    assert handoff["security_gate_credit"] == "NOT_CREDITED"
    assert stored_worker.result_summary == original
