"""Provider-free checks for the opt-in original Worker to product HP seam."""

import asyncio
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from bson import ObjectId

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint
from fuzzingbrain.core.models.worker import Worker, WorkerStatus

PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from vulnerabilityanalysis import official_harness
from vulnerabilityanalysis.agents import AgentPipeline
from devtools.original_hp_post_worker import run_post_worker_hp
from devtools import original_hp_post_worker as post_worker
from devtools import original_hp_live_optin as hp_live
from devtools.original_hp_preparation import prepare_hp_function
from devtools.campaign_model_gate import CampaignLedgeredProvider


def test_hp_preflight_rejects_partial_bounded_sp_before_live_work():
    assert post_worker._preflight(
        object(), {"sp_analysis_status":
                   "PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED"}) == "SP_ANALYSIS_PARTIAL"


class FakeQualification:
    def __init__(self, root, harness, normal_seed):
        self.product_issued = True
        self.contract_kind = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"
        self.source_root = root
        self.harness = harness
        self.source_tree_sha256 = "1" * 64
        self.harness_sha256 = hashlib.sha256(harness.read_bytes()).hexdigest()
        self.binary_sha256 = "2" * 64
        self.contract_sha256 = "3" * 64
        self.normal_seed = normal_seed
        self.normal_seed_sha256 = hashlib.sha256(normal_seed.read_bytes()).hexdigest()


class ScriptedProvider:
    def __init__(self, role, response):
        self.role = role
        self.response = response
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    async def close(self):
        return None


def _analysis_reply():
    return {"summary": "Reads input", "input_flow": "p comes from input",
            "state_dependencies": [], "context_requests": [],
            "safe_assumptions": [], "unknowns": [], "input_sources": ["p"],
            "security_sensitive_operations": ["*p"],
            "validations": [], "memory_operations": ["read *p"],
            "evidence": ["return *p"], "safe_assumption_lifecycle": [],
            "hypothesis_evaluations": []}


def _case(tmp_path, monkeypatch, repos, *, partial=False):
    root = tmp_path / "repo"
    root.mkdir()
    source = ("int first(const char *p) {\n  return *p;\n}\n"
              "int second(const char *p) {\n  return *p;\n}\n")
    (root / "parser.c").write_text(source)
    harness = tmp_path / "fuzzer.cc"
    harness.write_text("int LLVMFuzzerTestOneInput() {return 0;}\n")
    normal_seed = tmp_path / "seed"
    normal_seed.write_bytes(b"normal")
    qualification = FakeQualification(root, harness, normal_seed)
    monkeypatch.setattr(official_harness, "OfficialPinnedQualification",
                        FakeQualification)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda candidate: candidate is qualification)
    task_id, run_id, worker_id = (str(ObjectId()),
                                  str(ObjectId()) if partial else "run_fixture",
                                  str(ObjectId()))
    direction = Direction(task_id=task_id, fuzzer="fuzz_fixture",
                          name="parser", status="pending")
    assert repos.directions.save(direction)
    plan_path = tmp_path / "direction-plan.json"
    plan = {"kind": "FBV2_DEV_DIRECTION_PLAN_V1", "status": "COMPLETED",
            "task_id": task_id, "fuzzer": "fuzz_fixture",
            "direction_ids": [direction.direction_id], "direction_count": 1}
    plan_path.write_text(json.dumps(plan, sort_keys=True))
    plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    first = Function(task_id=task_id, name="first", file_path="parser.c",
                     start_line=1, end_line=3, content=source.split("int second")[0],
                     analyzed_by_directions=[direction.direction_id])
    second = Function(task_id=task_id, name="second", file_path="parser.c",
                      start_line=4, end_line=6,
                      content="int second" + source.split("int second")[1],
                      analyzed_by_directions=[direction.direction_id])
    assert repos.functions.save(first)
    assert repos.functions.save(second)
    original = {"worker_id": worker_id, "task_type": "pov",
                "fuzzer": "fuzz_fixture", "sanitizer": "address",
                "strategy": "POV Fullscan Strategy (Streaming)"}
    if partial:
        original.update(suspicious_points_found=0, pov_generated=0)
    worker = Worker(worker_id=worker_id, task_id=task_id, fuzzer="fuzz_fixture",
                    sanitizer="address", status=WorkerStatus.COMPLETED,
                    finished_at=datetime.now(), result_summary=original)
    assert repos.workers.save(worker)
    process = {"stop_status": None, "active": {}, "finished": [], "revision": 1}
    process_sha = "a" * 64
    process_ledger = SimpleNamespace(
        snapshot=lambda: process,
        receipt_snapshot=lambda: (process, "b" * 64 if process["finished"]
                                  else process_sha))
    model = {"campaign_id": run_id, "physical": 0, "records": []}
    model_gate = SimpleNamespace(campaign_id=run_id, snapshot=lambda: model)
    global_result = {"status": "RAN", "cleanup_complete": True}
    campaign = SimpleNamespace(
        ledger=process_ledger,
        campaign=SimpleNamespace(process_envelope=SimpleNamespace(
            ledger=process_ledger)),
        reservation_key=f"GLOBAL_FUZZ:{task_id}:{run_id}",
        final_result=global_result)
    executor = SimpleNamespace(
        task_id=task_id, fuzzer="fuzz_fixture", repos=repos,
        _worker_context=SimpleNamespace(worker_id=worker_id,
                                        status="completed"))
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id=task_id, run_id=run_id),
        executor=executor,
        strategy=SimpleNamespace(executor=executor,
                                 _development_direction_plan=(plan_path, plan_sha)),
        server=SimpleNamespace(repos=repos),
        admission=SimpleNamespace(qualification=qualification,
                                  prepared={"fuzzer_name": "fuzz_fixture"}),
        model_gate=model_gate, process_ledger=process_ledger,
        global_campaign=campaign, recheck=lambda: None)
    receipt = {"kind": "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1",
               "task_id": task_id, "run_id": run_id,
               "status": "EXECUTED_UNVERIFIED",
               "execution_status": "EXECUTED", "global_status": "RAN",
               "sp_analysis_status": "COMPLETED",
               "verification_status": "NO_PENDING_OBSERVATION",
               "pending_global_crashes": 0,
               "pov_crashes_pending_independent_validation": 0,
               "original_result": original, "model_physical_calls": 0,
               "process_receipt_sha256": process_sha,
               "process_stop_status": None}
    return bound, receipt, first, second


def test_combined_selection_receipt_binds_full_pair_set_and_queue_settlement(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(tmp_path, monkeypatch, repos)
    run_dir = tmp_path / "combined-run"
    run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = run_dir
    bound.caps = SimpleNamespace(
        bounded_nohint_dev=False, sp_concurrent_queue=True)
    spec = {
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
            "seed_directions": 1, "sp_function_limit": None,
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "security_invariant_focus": "LIFETIME_OWNERSHIP",
            "direction_selection":
                "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
            "pov_attempts_per_candidate": 3,
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "hp": {"enabled": True, "max_items": 1,
               "max_model_calls": 3}}
    spec_path = tmp_path / "combined-spec.json"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    repos.suspicious_points.collection.insert_one({
        "_id": ObjectId(), "task_id": ObjectId(bound.identity.task_id),
        "status": "pov_generated", "processor_id": None,
        "verification_claim_token": None, "pov_active_claims": [],
        "pending_pov_ids": [], "pending_pov_artifacts": [],
    })
    reviewed = SuspiciousPoint(
        task_id=bound.identity.task_id, function_name="reviewed",
        description="legacy score gate candidate", vuln_type="null-pointer",
        score=0.1, sources=[{"harness_name": "fuzz_fixture",
                             "sanitizer": "address"}])
    assert repos.suspicious_points.save(reviewed)
    claimed = repos.suspicious_points.claim_for_verify(
        bound.identity.task_id, "verifier-fixture")
    assert claimed is not None and claimed.verification_claim_token
    assert repos.suspicious_points.update_verifier_fields(
        claimed.suspicious_point_id,
        {"is_checked": True, "is_real": False, "score": 0.1,
         "is_important": False, "verification_notes": "not admitted"},
        processor_id="verifier-fixture",
        claim_token=claimed.verification_claim_token)
    assert repos.suspicious_points.complete_verify(
        claimed.suspicious_point_id, False, 0.1,
        notes="not admitted", is_important=False, proceed_to_pov=False,
        processor_id="verifier-fixture",
        claim_token=claimed.verification_claim_token)

    selected, receipt_sha = hp_live._combined_concurrent_hp_selection(
        bound, receipt, spec_path, spec_sha)
    expected = sorted(
        [(first.function_id, first.analyzed_by_directions[0]),
         (second.function_id, second.analyzed_by_directions[0])],
        key=lambda pair: (pair[1], pair[0]))[0]
    assert selected == expected
    selection = json.loads(
        (run_dir / "HP_POST_WORKER_SELECTION.json").read_text())
    assert selection["selected_pair"] == list(expected)
    assert len(selection["eligible_pairs"]) == 2
    assert selection["queue_candidate_count"] == 2
    assert hashlib.sha256(
        (run_dir / "HP_POST_WORKER_SELECTION.json").read_bytes()
    ).hexdigest() == receipt_sha

    # The write-once receipt binds the complete eligible set, not just the
    # selected first pair.
    second.analyzed_by_directions = []
    assert repos.functions.save(second)
    with pytest.raises(ValueError, match="SELECTION_CHANGED"):
        hp_live._combined_concurrent_hp_selection(
            bound, receipt, spec_path, spec_sha)
    second.analyzed_by_directions = [expected[1]]
    assert repos.functions.save(second)

    # A newly pending candidate invalidates the frozen queue settlement.
    point = SuspiciousPoint(
        task_id=bound.identity.task_id, function_name="pending",
        description="candidate", vuln_type="buffer-overflow", score=0.5,
        sources=[{"harness_name": "fuzz_fixture",
                  "sanitizer": "address"}])
    assert repos.suspicious_points.save(point)
    with pytest.raises(ValueError, match="QUEUE_UNSETTLED"):
        hp_live._combined_concurrent_hp_selection(
            bound, receipt, spec_path, spec_sha)


@pytest.mark.parametrize(("field", "value"), [
    ("status", "pending_pov"),
    ("status", "pending_budget"),
    ("status", "pending_stop"),
    ("status", "incomplete_uncertain"),
    ("status", "pending_qualified_runtime"),
    ("status", "pending_independent_validation"),
    ("status", "future_unknown_status"),
    ("processor_id", "stale-worker"),
    ("verification_claim_token", "stale-token"),
    ("pov_active_claims", [{"token": "stale"}]),
    ("pending_pov_ids", ["stale-pov"]),
    ("pending_pov_artifacts", [{"id": "stale-artifact"}]),
])
def test_combined_selection_fails_closed_on_each_unsettled_queue_field(
        tmp_path, monkeypatch, repos, field, value):
    bound, receipt, _first, _second = _case(tmp_path, monkeypatch, repos)
    run_dir = tmp_path / "combined-unsettled"
    run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = run_dir
    bound.caps = SimpleNamespace(
        bounded_nohint_dev=False, sp_concurrent_queue=True)
    spec = {
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
            "seed_directions": 1, "sp_function_limit": None,
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "security_invariant_focus": "LIFETIME_OWNERSHIP",
            "direction_selection":
                "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
            "pov_attempts_per_candidate": 3,
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "hp": {"enabled": True, "max_items": 1,
               "max_model_calls": 3}}
    spec_path = tmp_path / "combined-unsettled-spec.json"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    row = {
        "_id": ObjectId(), "task_id": ObjectId(bound.identity.task_id),
        "status": "pov_generated", "processor_id": None,
        "verification_claim_token": None, "pov_active_claims": [],
        "pending_pov_ids": [], "pending_pov_artifacts": [],
    }
    row[field] = value
    repos.suspicious_points.collection.insert_one(row)
    with pytest.raises(ValueError, match="QUEUE_UNSETTLED"):
        hp_live._combined_concurrent_hp_selection(
            bound, receipt, spec_path, spec_sha)


@pytest.mark.parametrize(("field", "value"), [
    ("sp_analysis_status", "PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED"),
    ("status", "INCOMPLETE"),
    ("execution_status", "INCOMPLETE"),
    ("verification_status", "PENDING_INDEPENDENT_VALIDATION"),
    ("pending_global_crashes", 1),
    ("pov_crashes_pending_independent_validation", 1),
])
def test_combined_selection_requires_fully_settled_sp_worker_receipt(
        tmp_path, monkeypatch, repos, field, value):
    bound, receipt, _first, _second = _case(tmp_path, monkeypatch, repos)
    run_dir = tmp_path / "combined-partial"
    run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = run_dir
    bound.caps = SimpleNamespace(
        bounded_nohint_dev=False, sp_concurrent_queue=True)
    receipt[field] = value
    spec = {
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
            "seed_directions": 1, "sp_function_limit": None,
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "security_invariant_focus": "LIFETIME_OWNERSHIP",
            "direction_selection":
                "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
            "pov_attempts_per_candidate": 3,
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "hp": {"enabled": True, "max_items": 1,
               "max_model_calls": 3}}
    spec_path = tmp_path / "combined-partial-spec.json"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="WORKER_RECEIPT"):
        hp_live._combined_concurrent_hp_selection(
            bound, receipt, spec_path, spec_sha)


def test_concurrent_selection_does_not_borrow_bounded_context_authority(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(tmp_path, monkeypatch, repos)
    second.analyzed_by_directions = []
    assert repos.functions.save(second)
    bound.caps = SimpleNamespace(
        bounded_nohint_dev=False, sp_concurrent_queue=True)
    observed = []

    async def analysis(**kwargs):
        observed.append(kwargs)
        return {"status": "NO_SAFE_ASSUMPTION",
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED"}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", analysis)
    monkeypatch.setattr(post_worker, "_live_pipelines_bound",
                        lambda *_args: True)
    monkeypatch.setattr(post_worker, "_claim_live_hp_pair",
                        lambda *_args: None)
    factory = lambda _work: AgentPipeline(
        ScriptedProvider("function_analysis", _analysis_reply()))
    pair = (first.function_id, first.analyzed_by_directions[0])
    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=factory,
        assertion_pipeline_factory=factory,
        max_items=1, expected_selected_pair=pair,
        hp_run_claim_sha256="b" * 64,
        signed_post_worker_selection_sha256="a" * 64,
        selection_contract_kind=
            "SIGNED_CONCURRENT_POST_WORKER_SELECTION_V1"))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert len(observed) == 1
    assert "bounded_nohint_hp_context" not in observed[0]
    assert "max_context_reanalyses" not in observed[0]


def test_concurrent_signed_first_pair_allows_multiple_analyzed_markers(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(tmp_path, monkeypatch, repos)
    bound.caps = SimpleNamespace(
        bounded_nohint_dev=False, sp_concurrent_queue=True)
    observed = []

    async def analysis(**kwargs):
        observed.append(kwargs["work"].function_id)
        return {"status": "NO_SAFE_ASSUMPTION",
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED"}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", analysis)
    monkeypatch.setattr(post_worker, "_live_pipelines_bound",
                        lambda *_args: True)
    monkeypatch.setattr(post_worker, "_claim_live_hp_pair",
                        lambda *_args: None)
    factory = lambda _work: AgentPipeline(
        ScriptedProvider("function_analysis", _analysis_reply()))
    directions = list(repos.directions.find_by_fuzzer(
        bound.identity.task_id, bound.executor.fuzzer))
    expected = sorted(
        [(first.function_id, first.analyzed_by_directions[0]),
         (second.function_id, second.analyzed_by_directions[0])],
        key=lambda pair: (pair[1], pair[0]))[0]
    assert directions and expected[1] == directions[0].direction_id
    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=factory,
        assertion_pipeline_factory=factory,
        max_items=1, expected_selected_pair=expected,
        hp_run_claim_sha256="b" * 64,
        signed_post_worker_selection_sha256="a" * 64,
        selection_contract_kind=
            "SIGNED_CONCURRENT_POST_WORKER_SELECTION_V1"))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert observed == [expected[0]]


def _partial_auto_receipt(tmp_path, bound, receipt, first, second):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    (root / "worker" / "results").mkdir(parents=True)
    bound.identity.run_dir = root
    bound.caps = SimpleNamespace(bounded_nohint_dev=True)
    bound.strategy.results_path = root / "worker" / "results"
    bound.admission.summary = {"manifest_path": str(tmp_path / "manifest.json"),
                               "manifest_sha256": "f" * 64}
    first.analyzed_by_directions = []
    second.analyzed_by_directions = []
    assert bound.server.repos.functions.save(first)
    assert bound.server.repos.functions.save(second)
    selected = {"function_id": first.function_id,
                "direction_id": next(iter(
                    bound.server.repos.directions.find_by_fuzzer(
                        bound.identity.task_id, bound.executor.fuzzer)
                )).direction_id,
                "function_name": first.name,
                "file_path": first.file_path,
                "start_line": first.start_line}
    selection = {"kind": "BOUNDED_NOHINT_SELECTION_V1",
                 "status": "PARTIAL_SCOPE",
                 "task_id": bound.identity.task_id,
                 "run_id": bound.identity.run_id,
                 "selection": "DIRECTION_RISK_PHASE_CANONICAL_V1",
                 "function_limit": 1,
                 "direction_plan_sha256":
                     bound.strategy._development_direction_plan[1],
                 "selected_functions": [selected]}
    selection_path = bound.strategy.results_path / "BOUNDED_AUTO_SELECTION.json"
    selection_path.write_text(json.dumps(selection, sort_keys=True))
    selection_sha = hashlib.sha256(selection_path.read_bytes()).hexdigest()
    receipt.update(status="INCOMPLETE", execution_status="EXECUTED",
                   sp_analysis_status="PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED",
                   original_worker_status="PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED",
                   verification_status="NO_PENDING_OBSERVATION",
                   pending_global_crashes=0,
                   pov_crashes_pending_independent_validation=0,
                   analysis_scope={"function_limit": 1,
                                   "direction_plan_sha256":
                                       bound.strategy._development_direction_plan[1],
                                   "selected_functions": [selected],
                                   "selection_receipt_path": str(selection_path),
                                   "selection_receipt_sha256": selection_sha,
                                   "function_outcomes": [{**selected,
                                       "opportunity_status":
                                           "NO_OPPORTUNITY_MAX_ITERATIONS",
                                       "success": False}]})
    claim = {"kind": "FBV2_HP_RUN_CLAIM_V1",
             "task_id": bound.identity.task_id,
             "run_id": bound.identity.run_id,
             "worker_id": receipt["original_result"]["worker_id"],
             "spec_sha256": "e" * 64,
             "original_result_sha256": hashlib.sha256(json.dumps(
                 receipt["original_result"], sort_keys=True,
                 separators=(",", ":")).encode()).hexdigest(),
             "model_physical_before": 0,
             "process_receipt_sha256_before": receipt["process_receipt_sha256"]}
    claim_path = root / "HP_RUN_CLAIM.json"
    claim_path.write_text(json.dumps(claim, sort_keys=True))
    return (first.function_id, selected["direction_id"]), hashlib.sha256(
        claim_path.read_bytes()).hexdigest()


def _run(bound, receipt, *, max_items=None, analysis_factory=None,
         expected_selected_pair=None):
    providers = []

    def first_factory(work):
        provider = (analysis_factory(work) if analysis_factory else
                    ScriptedProvider("function_analysis", _analysis_reply()))
        providers.append(provider)
        return AgentPipeline(provider)

    def second_factory(_work):
        return AgentPipeline(ScriptedProvider("assertion_generator", {}))

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=first_factory,
        assertion_pipeline_factory=second_factory,
        max_items=max_items, provider_free_fixture=True,
        expected_selected_pair=expected_selected_pair))
    return result, providers


def test_settled_local_sp_exhaustion_uses_separate_auto_hp_origin(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(
        tmp_path, monkeypatch, repos, partial=True)
    pair, claim_sha = _partial_auto_receipt(
        tmp_path, bound, receipt, first, second)
    analyzed = []

    async def analysis(**kwargs):
        analyzed.append(kwargs["work"])
        return {"status": "NO_SAFE_ASSUMPTION",
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED"}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", analysis)
    monkeypatch.setattr(post_worker, "_live_pipelines_bound",
                        lambda *_args: True)
    monkeypatch.setattr(post_worker, "_claim_live_hp_pair",
                        lambda *_args: None)
    factory = lambda role: lambda _work: AgentPipeline(
        ScriptedProvider(role, _analysis_reply()))
    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=factory("function_analysis"),
        assertion_pipeline_factory=factory("assertion_generator"),
        max_items=1, expected_selected_pair=pair,
        hp_run_claim_sha256=claim_sha,
        selection_contract_kind="SIGNED_BOUNDED_AUTO_SELECTION_V1"))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert len(analyzed) == 1, result["rows"]
    assert analyzed[0].selection_origin == (
        "SIGNED_AUTO_HP_AFTER_LOCAL_SP_EXHAUSTION")
    assert result["selection_basis"] == (
        "SIGNED_AUTO_SELECTION_AFTER_LOCAL_SP_EXHAUSTION")
    assert receipt["sp_analysis_status"] == "PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert repos.functions.find_by_id(first.function_id).analyzed_by_directions == []

    # A changed selection or a pre-existing SP marker cannot borrow the claim.
    changed = {**receipt, "analysis_scope": {
        **receipt["analysis_scope"], "selection_receipt_sha256": "0" * 64}}
    blocked = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=changed,
        analysis_pipeline_factory=factory("function_analysis"),
        assertion_pipeline_factory=factory("assertion_generator"),
        max_items=1, expected_selected_pair=pair,
        hp_run_claim_sha256=claim_sha,
        selection_contract_kind="SIGNED_BOUNDED_AUTO_SELECTION_V1"))
    assert blocked["reason"] == "HP_SIGNED_PARTIAL_SELECTION_UNPROVEN"

    first.name = "renamed_after_selection"
    assert repos.functions.save(first)
    blocked = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=factory("function_analysis"),
        assertion_pipeline_factory=factory("assertion_generator"),
        max_items=1, expected_selected_pair=pair,
        hp_run_claim_sha256=claim_sha,
        selection_contract_kind="SIGNED_BOUNDED_AUTO_SELECTION_V1"))
    assert blocked["reason"] == "HP_SIGNED_SELECTION_DB_MISMATCH"


@pytest.mark.parametrize("change", [
    {"sp_analysis_status": "PARTIAL_MODEL_UNCERTAIN"},
    {"verification_status": "PENDING_CAUSAL_EVIDENCE"},
    {"pending_global_crashes": 1},
    {"global_status": "INCOMPLETE"},
])
def test_local_sp_exhaustion_hp_rejects_other_incomplete_states(
        tmp_path, monkeypatch, repos, change):
    bound, receipt, first, second = _case(
        tmp_path, monkeypatch, repos, partial=True)
    pair, claim_sha = _partial_auto_receipt(
        tmp_path, bound, receipt, first, second)
    receipt.update(change)
    calls = []

    def pipeline(_work):
        calls.append(True)
        raise AssertionError("model pipeline must not start")

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=pipeline,
        assertion_pipeline_factory=pipeline,
        max_items=1, expected_selected_pair=pair,
        hp_run_claim_sha256=claim_sha,
        selection_contract_kind="SIGNED_BOUNDED_AUTO_SELECTION_V1"))
    assert result["status"] == "HP_POST_WORKER_BLOCKED"
    assert calls == []


@pytest.mark.parametrize("verification_status", [
    "NO_PENDING_OBSERVATION",
    "PRODUCT_CONSUMER_VERIFIED_ORIGIN_UNPROVEN",
    "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN",
])
def test_settled_local_sp_exhaustion_accepts_terminal_verification_status(
        tmp_path, monkeypatch, repos, verification_status):
    bound, receipt, first, second = _case(
        tmp_path, monkeypatch, repos, partial=True)
    _partial_auto_receipt(tmp_path, bound, receipt, first, second)
    receipt["verification_status"] = verification_status
    assert post_worker._preflight(bound, receipt) is None


def test_unsupported_hp_preparation_is_not_reported_as_analysis_complete(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(tmp_path, monkeypatch, repos)
    second.analyzed_by_directions = []
    assert repos.functions.save(second)
    monkeypatch.setattr(post_worker, "prepare_hp_function",
                        lambda **_kwargs: {"status": "HP_UNSUPPORTED",
                                           "reason": "SOURCE_SPAN_UNAVAILABLE"})
    calls = []

    def pipeline(_work):
        calls.append(True)
        raise AssertionError("model pipeline must not start")

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=pipeline,
        assertion_pipeline_factory=pipeline,
        max_items=1, provider_free_fixture=True))
    assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert result["reason"] == "HP_ITEM_NOT_ANALYZED"
    assert result["rows"][0]["status"] == "HP_UNSUPPORTED"
    assert calls == []


def test_bounded_hp_rejects_extra_or_wrong_analyzed_pair_before_model(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(tmp_path, monkeypatch, repos)
    selected_pair = (first.function_id, first.analyzed_by_directions[0])
    # max_items=1 must not hide a second marker in the same Direction.
    result, providers = _run(bound, receipt, max_items=1,
                             expected_selected_pair=selected_pair)
    assert result["reason"] == "HP_SIGNED_SELECTION_DB_MISMATCH"
    assert providers == []

    second.analyzed_by_directions = []
    assert repos.functions.save(second)
    wrong_pair = (second.function_id, selected_pair[1])
    result, providers = _run(bound, receipt, max_items=1,
                             expected_selected_pair=wrong_pair)
    assert result["reason"] == "HP_SIGNED_SELECTION_DB_MISMATCH"
    assert providers == []

    result, providers = _run(bound, receipt, max_items=1,
                             expected_selected_pair=selected_pair)
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert len(providers) == 1


def test_provider_free_physical_handoff_runs_after_provider_close(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    providers = []

    class ClosableProvider(ScriptedProvider):
        closed = False

        async def close(self):
            self.closed = True

    def pipeline(_work):
        provider = ClosableProvider("fixture", {})
        providers.append(provider)
        return AgentPipeline(provider)

    async def proposed(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                "assertion_proposals": [{"assertion_id": "assertion-one",
                                         "status": "PROPOSED"}],
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED"}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", proposed)
    called = []

    def physical(work, row):
        assert all(provider.closed for provider in providers)
        assert bound.process_ledger.snapshot()["active"] == {}
        assert row["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
        called.append(work.function_id)
        bound.process_ledger.snapshot()["finished"].append({
            "key": f"{bound.identity.task_id}:assertion-one:"
                   f"{bound.identity.run_id}:000000:guided.initial_campaign",
            "kind": "HP_FUZZ", "cleanup_complete": True, "overrun": False})
        return {"status": "HP_ASSERTION_HANDOFF_COMPLETE",
                "function_id": work.function_id,
                "direction_id": work.direction_id,
                "assertion_id": "assertion-one",
                "source_sha256": work.source_sha256,
                "seed_sha256": bound.admission.qualification.normal_seed_sha256,
                "guided_status": "RAN",
                "guided_report": {"status": "RAN", "assertion_id": "assertion-one",
                                  "fuzzer_run_count": 1},
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED"}

    def forged(_work, _row):
        return {"status": "HP_ASSERTION_HANDOFF_COMPLETE",
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED"}

    forged_result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=pipeline,
        assertion_pipeline_factory=pipeline,
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=forged))
    assert forged_result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert forged_result["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"

    def failed(_work, _row):
        raise RuntimeError("physical fixture failure")

    incomplete = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=pipeline,
        assertion_pipeline_factory=pipeline,
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=failed))
    assert incomplete["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert incomplete["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"
    assert incomplete["original_result"] == receipt["original_result"]
    assert incomplete["security_gate_credit"] == "NOT_CREDITED"

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=pipeline,
        assertion_pipeline_factory=pipeline,
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=physical))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["analysis_status"] == "COMPLETE"
    assert result["physical_execution_status"] == "COMPLETE"
    observations = result["rows"][0]["physical_observations"]
    assert observations["initial_assertion_reached"] is None
    assert observations["guided_assertion_reached_count"] is None
    assert observations["security_gate_credit"] == "NOT_CREDITED"
    assert len(called) == 1
    assert result["rows"][0]["physical_handoff"]["status"] == \
        "HP_ASSERTION_HANDOFF_COMPLETE"
    assert result["original_result"] == receipt["original_result"]
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert result["rows"][0]["physical_process_receipt_sha256"] == "b" * 64

    def malformed_physical(work, row):
        payload = physical(work, row)
        payload["guided_status"] = []
        payload["guided_report"]["status"] = []
        return payload

    bound.process_ledger.snapshot()["finished"].clear()
    malformed = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=pipeline,
        assertion_pipeline_factory=pipeline,
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=malformed_physical))
    assert malformed["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert malformed["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"


def test_proposed_safe_without_physical_optin_is_analysis_only(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)

    async def proposed(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                "assertion_proposals": [{"assertion_id": "fixture-assertion",
                                         "status": "PROPOSED"}]}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", proposed)
    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("function_analysis", {})),
        assertion_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("assertion_generator", {})),
        max_items=1, provider_free_fixture=True))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["analysis_status"] == "COMPLETE"
    assert result["physical_execution_status"] == "NOT_REQUESTED"
    assert all("physical_handoff" not in row for row in result["rows"])


def test_model_safe_with_no_proposed_assertion_has_no_physical_opportunity(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)

    async def no_assertion(**_kwargs):
        return {"status": "NO_ASSERTION_PROPOSAL",
                "safe_assumption_count": 1,
                "assertion_count": 0,
                "proposed_assertion_count": 0,
                "assertion_proposals": [],
                "assertion_execution": "NOT_RUN",
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED"}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", no_assertion)
    called = []

    def physical(_work, _row):
        called.append(True)
        raise AssertionError("no assertion can enter physical execution")

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("function_analysis", {})),
        assertion_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("assertion_generator", {})),
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=physical))
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["analysis_status"] == "COMPLETE"
    assert result["physical_execution_status"] == "NOT_RUN_NO_PROPOSAL"
    assert result["rows"][0]["safe_assumption_count"] == 1
    assert result["rows"][0]["proposed_assertion_count"] == 0
    assert result["rows"][0]["assertion_execution"] == "NOT_RUN"
    assert "physical_handoff" not in result["rows"][0]
    assert called == []
    assert result["security_gate_credit"] == "NOT_CREDITED"


def test_physical_handoff_rejects_unrelated_process_charge(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)

    async def proposed(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                "assertion_proposals": [{"assertion_id": "fixture-assertion",
                                         "status": "PROPOSED"}]}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", proposed)

    def physical(work, _row):
        finished = bound.process_ledger.snapshot()["finished"]
        finished.extend([
            {"key": "unrelated:assertion:run:000000:guided.initial_campaign",
             "kind": "HP_FUZZ", "cleanup_complete": True,
             "overrun": False},
            {"key": f"{bound.identity.task_id}:fixture-assertion:"
                    f"{bound.identity.run_id}:000000:guided.initial_campaign",
             "kind": "HP_FUZZ", "cleanup_complete": True,
             "overrun": False},
        ])
        return {"status": "HP_ASSERTION_HANDOFF_COMPLETE",
                "function_id": work.function_id,
                "direction_id": work.direction_id,
                "assertion_id": "fixture-assertion",
                "source_sha256": work.source_sha256,
                "seed_sha256": bound.admission.qualification.normal_seed_sha256,
                "guided_status": "RAN",
                "guided_report": {"status": "RAN",
                                  "assertion_id": "fixture-assertion",
                                  "fuzzer_run_count": 1},
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED"}

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("function_analysis", {})),
        assertion_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("assertion_generator", {})),
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=physical))
    assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert result["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"


def test_physical_callback_failure_preserves_charged_process_receipt(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)

    async def proposed(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                "assertion_proposals": [{"assertion_id": "assertion-one",
                                         "status": "PROPOSED"}]}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", proposed)

    def failed(_work, _row):
        bound.process_ledger.snapshot()["finished"].append({
            "key": f"{bound.identity.task_id}:assertion-one:"
                   f"{bound.identity.run_id}:000000:guided.initial_campaign",
            "kind": "HP_FUZZ", "physical_seconds": 0.25,
            "cleanup_complete": True, "overrun": False})
        raise RuntimeError("fixture failed after charged work")

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("analysis", {})),
        assertion_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("assertion", {})),
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=failed))
    assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert result["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"
    row = result["rows"][0]
    assert row["physical_process_receipt_sha256"] == "b" * 64
    assert row["physical_process_delta"][0]["physical_seconds"] == 0.25
    assert row["physical_handoff"]["error_type"] == "RuntimeError"
    assert result["original_result"] == receipt["original_result"]


def test_discarded_assertion_cannot_complete_physical_handoff(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)

    async def proposed(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                "assertion_proposals": [
                    {"assertion_id": "valid", "status": "PROPOSED"},
                    {"assertion_id": "discarded", "status": "DISCARDED"}]}

    monkeypatch.setattr(post_worker, "run_prepared_hp_analysis", proposed)

    def discarded(work, _row):
        bound.process_ledger.snapshot()["finished"].append({
            "key": f"{bound.identity.task_id}:discarded:"
                   f"{bound.identity.run_id}:000000:guided.initial_campaign",
            "kind": "HP_FUZZ", "cleanup_complete": True, "overrun": False})
        return {"status": "HP_ASSERTION_HANDOFF_COMPLETE",
                "function_id": work.function_id,
                "direction_id": work.direction_id,
                "assertion_id": "discarded",
                "source_sha256": work.source_sha256,
                "seed_sha256": bound.admission.qualification.normal_seed_sha256,
                "guided_status": "RAN",
                "guided_report": {"status": "RAN", "assertion_id": "discarded",
                                  "fuzzer_run_count": 1},
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED"}

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("analysis", {})),
        assertion_pipeline_factory=lambda _work: AgentPipeline(
            ScriptedProvider("assertion", {})),
        max_items=1, provider_free_fixture=True,
        physical_handoff_factory=discarded))
    assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert result["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"
    assert len(result["rows"][0]["physical_process_delta"]) == 1


def test_completed_worker_selects_only_sp_marked_pairs_and_preserves_result(
        tmp_path, monkeypatch, repos):
    bound, receipt, first, second = _case(tmp_path, monkeypatch, repos)
    # A same-task Direction from another run and a different task's Function
    # cannot enter this HP batch, even if the stale direction says completed.
    extra = Direction(task_id=bound.identity.task_id, fuzzer="fuzz_fixture",
                      name="other", status="completed")
    repos.directions.save(extra)
    other = Function(task_id=str(ObjectId()), name="foreign",
                     file_path="parser.c", analyzed_by_directions=[extra.direction_id])
    assert repos.functions.save(other)
    first.analyzed_by_directions.append(extra.direction_id)
    assert repos.functions.save(first)
    original_copy = dict(receipt["original_result"])
    result, providers = _run(bound, receipt)
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["selected_count"] == 2
    assert {(r["function_id"], r["direction_id"]) for r in result["rows"]} == {
        (first.function_id, first.analyzed_by_directions[0]),
        (second.function_id, second.analyzed_by_directions[0])}
    assert all(row["status"] == "NO_SAFE_ASSUMPTION" for row in result["rows"])
    assert len(providers) == 2 and all(len(p.requests) == 1 for p in providers)
    assert result["original_result"] == original_copy
    assert result["original_global_status"] == "RAN"
    assert result["security_gate_credit"] == "NOT_CREDITED"


def test_explicit_cap_and_hp_error_do_not_change_worker(tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    result, _ = _run(bound, receipt, max_items=1,
                     analysis_factory=lambda _work: ScriptedProvider(
                         "function_analysis", RuntimeError("local fixture error")))
    assert result["selected_count"] == 1
    assert result["rows"][0]["status"] == "INCOMPLETE_HP_ERROR"
    assert bound.server.repos.workers.find_by_id(
        receipt["original_result"]["worker_id"]).status == WorkerStatus.COMPLETED
    assert result["sp_global_effect"] == "UNCHANGED"


def test_hp_item_error_isolated_and_next_marked_function_runs(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    result, providers = _run(
        bound, receipt,
        analysis_factory=lambda work: ScriptedProvider(
            "function_analysis", RuntimeError("fixture error")
            if work.function_name == "first" else _analysis_reply()))
    assert result["selected_count"] == 2
    assert [row["status"] for row in result["rows"]] == [
        "INCOMPLETE_HP_ERROR", "NO_SAFE_ASSUMPTION"]
    assert len(providers) == 2
    assert all(len(provider.requests) == 1 for provider in providers)


def test_last_hp_item_cannot_hide_uncertain_shared_model_turn(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)

    class UnsettlingProvider(ScriptedProvider):
        async def generate(self, request):
            response = await super().generate(request)
            bound.model_gate.snapshot = lambda: {
                "campaign_id": bound.identity.run_id, "physical": 1,
                "records": [{"request_id": "uncertain", "status": "STARTED"}]}
            return response

    result, _ = _run(bound, receipt, max_items=1,
                     analysis_factory=lambda _work: UnsettlingProvider(
                         "function_analysis", _analysis_reply()))
    assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert result["reason"] == "HP_SHARED_ACCOUNT_UNSETTLED"
    assert len(result["rows"]) == 1
    assert result["security_gate_credit"] == "NOT_CREDITED"


def test_missing_worker_global_or_model_proof_blocks_before_pipeline(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    receipt["original_result"] = {**receipt["original_result"],
                                  "worker_id": str(ObjectId())}
    result, providers = _run(bound, receipt)
    assert result["status"] == "HP_POST_WORKER_BLOCKED"
    assert providers == []
    receipt["original_result"] = bound.server.repos.workers.find_by_task(
        bound.identity.task_id)[0].result_summary
    receipt["global_status"] = None
    receipt["execution_status"] = "INCOMPLETE"
    result, providers = _run(bound, receipt)
    assert result["status"] == "HP_POST_WORKER_BLOCKED"
    assert providers == []
    receipt["global_status"] = "RAN"
    receipt["execution_status"] = "EXECUTED"
    bound.model_gate.snapshot = lambda: {
        "campaign_id": bound.identity.run_id, "physical": 0,
        "records": [{"request_id": "r1", "status": "COMPLETED",
                     "response_evidence": {"status": "VERIFIED"}}]}
    bound.model_gate.verify_response_evidence = lambda _request: {
        "status": "UNPROVEN"}
    result, providers = _run(bound, receipt)
    assert result["reason"] == "MODEL_OR_PROCESS_ACTIVITY_UNSETTLED"
    assert providers == []


def test_live_mode_without_durable_hp_claim_and_changed_plan_fail_closed(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=lambda _work: None,
        assertion_pipeline_factory=lambda _work: None))
    assert result["reason"] == "LIVE_HP_IDEMPOTENCE_CLAIM_MISSING"
    assert bound.model_gate.snapshot()["physical"] == 0
    plan_path = bound.strategy._development_direction_plan[0]
    plan_path.write_text("{}")
    result, providers = _run(bound, receipt)
    assert result["reason"] == "CURRENT_DIRECTION_PLAN_UNPROVEN"
    assert providers == []


def test_hp_accepts_only_matching_clean_no_seed_settlement(
        tmp_path, monkeypatch, repos):
    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    plan_sha = bound.strategy._development_direction_plan[1]
    clean_skip = {
        "status": "SKIPPED_NO_SEED", "cleanup_complete": True,
        "seed_count": 0, "physical_seconds": 0.0,
        "global_charge_relation": "NO_PHYSICAL_GLOBAL_RUN",
        "direction_plan_sha256": plan_sha,
    }
    bound.global_campaign.final_result = clean_skip
    receipt["global_status"] = "SKIPPED_NO_SEED"
    result, providers = _run(bound, receipt, max_items=1)
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["original_global_status"] == "SKIPPED_NO_SEED"
    assert len(providers) == 1

    clean_skip["direction_plan_sha256"] = "0" * 64
    result, providers = _run(bound, receipt, max_items=1)
    assert result["reason"] == "GLOBAL_SETTLEMENT_UNPROVEN"
    assert providers == []


def _run_live_fixture(bound, receipt, *, analysis_gate=None,
                      close_fails=False, max_items=1):
    providers = []

    class RoleProvider(ScriptedProvider):
        async def close(self):
            if close_fails and self.role == "function_analysis":
                raise RuntimeError("cannot confirm session close")

    def factory(role, gate):
        def create(_work):
            provider = RoleProvider(role, _analysis_reply())
            providers.append(provider)
            return AgentPipeline(CampaignLedgeredProvider(
                provider, gate, role=role, owner_id="hp-test"))
        return create

    result = asyncio.run(run_post_worker_hp(
        bound=bound, worker_receipt=receipt,
        analysis_pipeline_factory=factory(
            "function_analysis", analysis_gate or bound.model_gate),
        assertion_pipeline_factory=factory(
            "assertion_generator", bound.model_gate),
        max_items=max_items))
    return result, providers


def test_live_hp_claim_persists_and_duplicate_cannot_call_role(
        tmp_path, monkeypatch, repos):
    import devtools.original_hp_post_worker as bridge

    bound, receipt, first_function, _ = _case(tmp_path, monkeypatch, repos)
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = run_dir
    calls = []

    async def fake_analysis(**kwargs):
        calls.append(kwargs["work"].function_id)
        return {"status": "NO_SAFE_ASSUMPTION",
                "function_id": kwargs["work"].function_id}

    monkeypatch.setattr(bridge, "run_prepared_hp_analysis", fake_analysis)
    first, providers = _run_live_fixture(bound, receipt)
    assert first["status"] == "HP_POST_WORKER_COMPLETE"
    assert len(calls) == 1 and len(providers) == 2
    files = list((run_dir / "hp-claims").glob("hp-*.claim.json"))
    assert len(files) == 1 and files[0].stat().st_mode & 0o777 == 0o600
    claim = json.loads(files[0].read_bytes())
    assert claim["run_id"] == bound.identity.run_id
    assert claim["binary_sha256"] == bound.admission.qualification.binary_sha256
    direction = bound.server.repos.directions.find_by_fuzzer(
        bound.identity.task_id, bound.executor.fuzzer)[0]
    prepared = prepare_hp_function(
        function=first_function, direction=direction,
        qualification=bound.admission.qualification,
        fuzzer=bound.executor.fuzzer, sanitizer="address")
    assert bridge._claim_live_hp_pair(bound, "different_worker", prepared) == (
        "LIVE_HP_PAIR_ALREADY_CLAIMED")
    second, providers = _run_live_fixture(bound, receipt)
    assert second["reason"] == "LIVE_HP_PAIR_ALREADY_CLAIMED"
    assert second["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert len(calls) == 1 and providers == []


def test_live_hp_rejects_other_gate_before_model_and_closes_factories(
        tmp_path, monkeypatch, repos):
    import devtools.original_hp_post_worker as bridge

    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = run_dir
    called = []

    async def fake_analysis(**_kwargs):
        called.append(True)
        return {"status": "NO_SAFE_ASSUMPTION"}

    monkeypatch.setattr(bridge, "run_prepared_hp_analysis", fake_analysis)
    result, providers = _run_live_fixture(
        bound, receipt, analysis_gate=object())
    assert result["rows"][0]["status"] == "INCOMPLETE_HP_MODEL_GATE_MISMATCH"
    assert called == [] and all(not p.requests for p in providers)


def test_live_hp_close_failure_blocks_next_pair(
        tmp_path, monkeypatch, repos):
    import devtools.original_hp_post_worker as bridge

    bound, receipt, _, _ = _case(tmp_path, monkeypatch, repos)
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = run_dir
    called = []

    async def fake_analysis(**kwargs):
        called.append(kwargs["work"].function_id)
        return {"status": "NO_SAFE_ASSUMPTION"}

    monkeypatch.setattr(bridge, "run_prepared_hp_analysis", fake_analysis)
    result, providers = _run_live_fixture(
        bound, receipt, close_fails=True, max_items=2)
    assert result["reason"] == "HP_PROVIDER_CLOSE_UNPROVEN"
    assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
    assert len(called) == 1 and len(providers) == 2
    assert len(list((run_dir / "hp-claims").glob("hp-*.claim.json"))) == 1
