"""Provider-free checks for the opt-in original Worker to product HP seam."""

import asyncio
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from bson import ObjectId

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.worker import Worker, WorkerStatus

PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from vulnerabilityanalysis import official_harness
from vulnerabilityanalysis.agents import AgentPipeline
from devtools.original_hp_post_worker import run_post_worker_hp
from devtools import original_hp_post_worker as post_worker
from devtools.original_hp_preparation import prepare_hp_function
from devtools.campaign_model_gate import CampaignLedgeredProvider


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
            "evidence": ["return *p"], "hypothesis_evaluations": []}


def _case(tmp_path, monkeypatch, repos):
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
    task_id, run_id, worker_id = str(ObjectId()), "run_fixture", str(ObjectId())
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
               "execution_status": "EXECUTED", "global_status": "RAN",
               "original_result": original, "model_physical_calls": 0,
               "process_receipt_sha256": process_sha,
               "process_stop_status": None}
    return bound, receipt, first, second


def _run(bound, receipt, *, max_items=None, analysis_factory=None):
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
        max_items=max_items, provider_free_fixture=True))
    return result, providers


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
    assert len(called) == 1
    assert result["rows"][0]["physical_handoff"]["status"] == \
        "HP_ASSERTION_HANDOFF_COMPLETE"
    assert result["original_result"] == receipt["original_result"]
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert result["rows"][0]["physical_process_receipt_sha256"] == "b" * 64


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
