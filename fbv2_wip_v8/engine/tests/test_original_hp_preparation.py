"""Provider-free FBv2 function to existing product HP source boundary."""

from dataclasses import asdict, replace
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from bson import ObjectId

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy

PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from vulnerabilityanalysis import official_harness
from vulnerabilityanalysis.models import FunctionAnalysis, stable_id
from vulnerabilityanalysis.llm import LLMRequest
from vulnerabilityanalysis.agents import AgentPipeline as ProductAgentPipeline
from devtools.campaign_model_gate import (
    CampaignLedgeredProvider, CampaignModelGate,
)
from devtools.original_hp_preparation import (
    PreparedHPFunction, _bounded_context, _pinned_initial_context_plan,
    _last_unresolved_context_status, _pinned_static_call_path,
    _qualified_context_build_command,
    _qualified_relink_recipe_ok, _reviewed_relink_build_command,
    classify_hp_analysis, prepare_hp_function,
    run_prepared_hp_analysis, run_prepared_hp_assertion_handoff,
)
from devtools.parallel_hp_selection import (
    claim_parallel_hp_execution, freeze_parallel_hp_selection)
from devtools.parallel_hp_analysis import (
    reprove_parallel_hp_diagnostic, run_parallel_hp_analysis)
from devtools import original_hp_live_optin as hp_live
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2


def AgentPipeline(provider, *args, **kwargs):
    """Run the historical scripted fixtures through the explicit legacy path."""
    kwargs.setdefault("legacy_offline_replay", True)
    return ProductAgentPipeline(provider, *args, **kwargs)


class FakeQualification:
    def __init__(self, root, harness):
        self.product_issued = True
        self.contract_kind = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"
        self.source_root = root
        self.harness = harness
        self.source_tree_sha256 = "1" * 64
        self.harness_sha256 = hashlib.sha256(harness.read_bytes()).hexdigest()
        self.binary_sha256 = "2" * 64
        self.contract_sha256 = "3" * 64


def _case(tmp_path, monkeypatch, *, source=None, content=None, start_line=1):
    root = tmp_path / "repo"
    root.mkdir()
    source = source or (
        "int parse_input(const char *p) {\n"
        "  return *p;\n"
        "}\n")
    path = root / "parser.c"
    path.write_text(source)
    harness = tmp_path / "fuzzer.cc"
    harness.write_text("int LLVMFuzzerTestOneInput() {return 0;}\n")
    q = FakeQualification(root, harness)
    q.normal_seed = tmp_path / "normal_seed"
    q.normal_seed.write_bytes(b"A")
    q.normal_seed_sha256 = hashlib.sha256(q.normal_seed.read_bytes()).hexdigest()
    monkeypatch.setattr(official_harness, "OfficialPinnedQualification",
                        FakeQualification)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda candidate: candidate is q)
    task_id, direction_id = str(ObjectId()), str(ObjectId())
    func = Function(task_id=task_id, name="parse_input",
                    file_path="parser.c", start_line=start_line,
                    end_line=3, content=source if content is None else content,
                    analyzed_by_directions=[direction_id])
    direction = Direction(task_id=task_id, direction_id=direction_id,
                          fuzzer="fuzz_fixture", name="input parser",
                          core_functions=["parse_input"])
    return q, func, direction, path


def test_exact_function_span_prepared_without_changing_fbv2_state(
        tmp_path, monkeypatch):
    q, func, direction, path = _case(tmp_path, monkeypatch)
    before = (asdict(func), asdict(direction))
    result = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert isinstance(result, PreparedHPFunction)
    assert result.source_file == str(path)
    assert result.source_start_line == 1
    assert result.source_end_line == 3
    assert result.source_file_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result.harness_sha256 == q.harness_sha256
    assert result.analysis_scope["selected_function"]["runtime_reachable"] == (
        "UNPROVEN_BY_HP_PREPARATION")
    assert result.receipt()["security_gate_credit"] == "NOT_CREDITED"
    assert (asdict(func), asdict(direction)) == before


def test_hp_requires_completed_original_sp_selection(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    result = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "FBV2_SP_SELECTION_NOT_COMPLETED"
    assert result["sp_global_effect"] == "UNCHANGED"


def test_parallel_hp_pre_sp_claim_reaches_existing_hp_roles(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    run_dir = tmp_path / "parallel-run"
    run_dir.mkdir(mode=0o700)
    run_id = "c" * 24
    spec_sha = "d" * 64
    plan_sha = "e" * 64
    catalog_sha = "f" * 64
    selected, selection_sha = freeze_parallel_hp_selection(
        run_dir=run_dir, task_id=func.task_id, run_id=run_id,
        fuzzer=direction.fuzzer, spec_sha256=spec_sha,
        direction_plan_sha256=plan_sha,
        function_catalog_sha256=catalog_sha,
        directions=[direction], functions=[func])
    assert selected == (func, direction)
    claim_sha = claim_parallel_hp_execution(
        run_dir=run_dir, task_id=func.task_id, run_id=run_id,
        spec_sha256=spec_sha, selection_receipt_sha256=selection_sha)
    evidence = {
        "origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
        "task_id": func.task_id, "run_id": run_id,
        "function_id": func.function_id,
        "direction_id": direction.direction_id,
        "source_tree_sha256": q.source_tree_sha256,
        "contract_sha256": q.contract_sha256,
        "spec_sha256": spec_sha,
        "direction_plan_sha256": plan_sha,
        "function_catalog_sha256": catalog_sha,
        "selection_receipt_sha256": selection_sha,
        "execution_claim_sha256": claim_sha,
        "run_dir": str(run_dir),
    }
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer=direction.fuzzer, sanitizer="address",
        parallel_hp_selection_evidence=evidence)
    assert isinstance(work, PreparedHPFunction)
    assert work.selection_origin == "PARALLEL_HP_PRE_SP_SELECTION_V1"
    assert work.analysis_scope["selection_evidence"] == evidence

    analysis, assertion, provider, _ = _pipelines(_analysis_reply(safe=True))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, worker_id="parallel-hp-fixture",
        provider_free_fixture=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert len(provider.requests) == 1
    assert result["security_gate_credit"] == "NOT_CREDITED"

    changed = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer=direction.fuzzer, sanitizer="address",
        parallel_hp_selection_evidence={**evidence,
                                        "execution_claim_sha256": "0" * 64})
    assert changed["reason"] == "PARALLEL_HP_SELECTION_EVIDENCE_INVALID"

    claim_path = run_dir / "HP_PARALLEL_RUN_CLAIM.json"
    analysis, assertion, provider, assertion_provider = _pipelines(
        _analysis_reply(safe=True),
        analysis_callback=lambda: claim_path.write_bytes(b"changed\n"))
    stopped_between_roles = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, worker_id="parallel-hp-fixture",
        provider_free_fixture=True))
    assert stopped_between_roles["status"] == "HP_UNSUPPORTED"
    assert len(provider.requests) == 1
    assert assertion_provider.requests == []

    analysis, assertion, provider, _ = _pipelines(_analysis_reply(safe=True))
    stopped = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, worker_id="parallel-hp-fixture",
        provider_free_fixture=True))
    assert stopped["status"] == "HP_UNSUPPORTED"
    assert stopped["reason"] == "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"
    assert provider.requests == []


def _fixture_selection(q, func, direction):
    return {"origin": "PROVIDER_FREE_FIXTURE", "task_id": func.task_id,
            "function_id": func.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": q.source_tree_sha256,
            "contract_sha256": q.contract_sha256}


def _signed_manual_selection(q, func, direction):
    return {"origin": "SIGNED_MANUAL_HP_CONTROL", "task_id": func.task_id,
            "run_id": "a" * 24, "function_id": func.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": q.source_tree_sha256,
            "contract_sha256": q.contract_sha256,
            "spec_sha256": "b" * 64,
            "selection_claim_sha256": "c" * 64}


def _signed_auto_selection(q, func, direction):
    return {"origin": "SIGNED_AUTO_HP_AFTER_LOCAL_SP_EXHAUSTION",
            "task_id": func.task_id, "run_id": "a" * 24,
            "function_id": func.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": q.source_tree_sha256,
            "contract_sha256": q.contract_sha256,
            "spec_sha256": "b" * 64,
            "selection_receipt_sha256": "c" * 64,
            "hp_run_claim_sha256": "d" * 64}


def test_signed_auto_hp_selection_preserves_partial_sp_provenance(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    evidence = _signed_auto_selection(q, func, direction)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        signed_auto_hp_selection_evidence=evidence)
    assert isinstance(work, PreparedHPFunction)
    assert work.selection_origin == "SIGNED_AUTO_HP_AFTER_LOCAL_SP_EXHAUSTION"
    assert work.analysis_scope["selection_evidence"] == evidence
    assert "no SP completion" in work.analysis_scope["provenance_note"]
    assert work.receipt()["security_gate_credit"] == "NOT_CREDITED"

    invalid = {**evidence, "selection_receipt_sha256": "bad"}
    blocked = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        signed_auto_hp_selection_evidence=invalid)
    assert blocked["reason"] == "SIGNED_AUTO_HP_SELECTION_EVIDENCE_INVALID"


def test_signed_manual_hp_selection_is_explicit_and_not_discovery(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    evidence = _signed_manual_selection(q, func, direction)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        signed_manual_hp_selection_evidence=evidence)
    assert isinstance(work, PreparedHPFunction)
    assert work.selection_origin == "SIGNED_MANUAL_HP_CONTROL"
    assert work.analysis_scope["selection_evidence"] == evidence
    assert "no FBv2 SP completion" in work.analysis_scope["provenance_note"]
    assert "automatic discovery" in work.analysis_scope["provenance_note"]
    assert work.receipt()["security_gate_credit"] == "NOT_CREDITED"


@pytest.mark.parametrize("changed", [
    {"origin": "FBV2_SP_SELECTION"}, {"run_id": "bad"},
    {"function_id": "other"}, {"direction_id": "other"},
    {"source_tree_sha256": "0" * 64},
    {"spec_sha256": "not-a-digest"},
    {"selection_claim_sha256": "not-a-digest"},
    {"extra": "unexpected"},
])
def test_signed_manual_hp_selection_rejects_invalid_evidence(
        tmp_path, monkeypatch, changed):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    evidence = {**_signed_manual_selection(q, func, direction), **changed}
    result = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        signed_manual_hp_selection_evidence=evidence)
    assert result["reason"] == "SIGNED_MANUAL_HP_SELECTION_EVIDENCE_INVALID"


def test_signed_manual_and_fixture_selection_cannot_mix(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    result = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        provider_free_selection_evidence=_fixture_selection(q, func, direction),
        signed_manual_hp_selection_evidence=_signed_manual_selection(
            q, func, direction))
    assert result["reason"] == "HP_SELECTION_ORIGINS_CONFLICT"


def test_fixture_selection_without_sp_completion_reuses_hp_roles(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    before = (asdict(func), asdict(direction))
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        provider_free_selection_evidence=_fixture_selection(q, func, direction))
    assert isinstance(work, PreparedHPFunction)
    assert work.analysis_scope["selection_origin"] == "PROVIDER_FREE_FIXTURE"
    assert "no FBv2 SP completion" in work.analysis_scope["provenance_note"]
    assert work.receipt()["security_gate_credit"] == "NOT_CREDITED"
    assert (asdict(func), asdict(direction)) == before

    first, second, first_provider, _ = _pipelines(_analysis_reply(safe=True))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert len(first_provider.requests) == 1
    assert result["security_gate_credit"] == "NOT_CREDITED"

    proposal_id = result["assertion_proposals"][0]["assertion_id"]

    def execute(assertion, *args, **kwargs):
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    physical = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "fixture-output",
        build_command=["clang", "-fsanitize=fuzzer,address", "{source}",
                       str(q.harness), "-o", "{binary}"],
        run_command=["{binary}", "{input}"], guided_seconds=1,
        provider_free_fixture=True,
        execute_callback=execute,
        guided_callback=lambda *args, **kwargs: {
            "status": "RAN", "violation_witnesses": []})
    assert physical["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert physical["security_gate_credit"] == "NOT_CREDITED"
    assert physical["discovery_credit"] == "NOT_CREDITED"

    first, second, first_provider, _ = _pipelines(_analysis_reply(safe=True))
    live = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert live["reason"] == "PROVIDER_FREE_SELECTION_CANNOT_RUN_LIVE"
    assert first_provider.requests == []

    handoff = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result={}, worker_id="worker",
        assertion_id="assertion", output_dir=tmp_path / "output",
        build_command=["true"], run_command=["true"])
    assert handoff["reason"] == "PROVIDER_FREE_SELECTION_CANNOT_RUN_LIVE"

    # The display scope is mutable; changing it must not promote fixture work.
    work.analysis_scope["selection_origin"] = "FBV2_SP_SELECTION"
    assert work.selection_origin == "PROVIDER_FREE_FIXTURE"
    first, second, first_provider, _ = _pipelines(_analysis_reply(safe=True))
    live_after_mutation = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert live_after_mutation["reason"] == "PROVIDER_FREE_SELECTION_CANNOT_RUN_LIVE"
    assert first_provider.requests == []
    handoff_after_mutation = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result={}, worker_id="worker",
        assertion_id="assertion", output_dir=tmp_path / "output2",
        build_command=["true"], run_command=["true"])
    assert handoff_after_mutation["reason"] == "PROVIDER_FREE_SELECTION_CANNOT_RUN_LIVE"


@pytest.mark.parametrize("altered", [
    {"origin": "FBV2_SP_SELECTION"},
    {"function_id": "wrong"},
    {"direction_id": "wrong"},
    {"task_id": "wrong"},
    {"source_tree_sha256": "0" * 64},
    {"contract_sha256": "0" * 64},
    {"extra": "unexpected"},
])
def test_fixture_selection_rejects_wrong_origin_function_direction_or_pins(
        tmp_path, monkeypatch, altered):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    evidence = {**_fixture_selection(q, func, direction), **altered}
    result = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        provider_free_selection_evidence=evidence)
    assert result["reason"] == "PROVIDER_FREE_SELECTION_EVIDENCE_INVALID"


def test_fixture_selection_rejects_unqualified_or_changed_source(
        tmp_path, monkeypatch):
    q, func, direction, path = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    evidence = _fixture_selection(q, func, direction)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda _: False)
    invalid = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        provider_free_selection_evidence=evidence)
    assert invalid["reason"] == "OFFICIAL_HARNESS_QUALIFICATION_INVALID"

    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda candidate: candidate is q)
    path.write_text("int parse_input(const char *p) { return 0; }\n")
    changed = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        provider_free_selection_evidence=evidence)
    assert changed["status"] == "HP_UNSUPPORTED"
    assert changed["reason"] in {
        "FBV2_CONTENT_NOT_EXACT_DEFINITION", "SOURCE_CHANGED_DURING_SPAN_LOOKUP"}


def test_ambiguous_or_stale_source_is_isolated_hp_unsupported(tmp_path, monkeypatch):
    source = ("int parse_input(int x) {return x;}\n"
              "int parse_input(char x) {return x;}\n")
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=source, content="", start_line=0)
    ambiguous = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert ambiguous["status"] == "HP_UNSUPPORTED"
    assert ambiguous["reason"].startswith("EXACT_SOURCE_SPAN_UNAVAILABLE")
    assert ambiguous["sp_global_effect"] == "UNCHANGED"

    func.content = "int parse_input(int x) {return x + 1;}"
    stale = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert stale["status"] == "HP_UNSUPPORTED"


def test_prefix_or_comment_content_cannot_bind_as_function_definition(
        tmp_path, monkeypatch):
    comment = "/* int parse_input(const char *p) { return 0; } */\n"
    actual = "int parse_input(const char *p) { return *p; }\n"
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=comment + actual,
        content="int parse_input", start_line=2)
    prefix = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert prefix["reason"] == "FBV2_CONTENT_NOT_EXACT_DEFINITION"
    func.content = comment.strip()[3:-3].strip()
    fake_in_comment = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert fake_in_comment["reason"] == "FBV2_CONTENT_NOT_EXACT_DEFINITION"


def test_unissued_qualification_is_rejected_before_source_read(tmp_path, monkeypatch):
    q, func, direction, path = _case(tmp_path, monkeypatch)
    q.product_issued = False
    path.unlink()
    result = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert result["reason"] == "OFFICIAL_HARNESS_QUALIFICATION_INVALID"


def test_no_safe_and_hp_error_never_change_sp_global_or_gate(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert isinstance(work, PreparedHPFunction)
    analysis = FunctionAnalysis(
        work.function_id, work.function_name, work.source_file,
        "summary", "input", [], [], [], [], direction_id=work.direction_id)
    no_safe = classify_hp_analysis(work, analysis)
    assert no_safe["status"] == "NO_SAFE_ASSUMPTION"
    assert no_safe["safe_selection_observation"] == {
        "retained_safe_count": 0,
        "unlinked_proposal_count": 0,
        "unlisted_explicit_count": 0,
        "selection_reason": "NO_SAFE_PROPOSAL_OBSERVED"}
    assert no_safe["sp_global_effect"] == "UNCHANGED"
    assert no_safe["security_gate_credit"] == "NOT_CREDITED"
    analysis.unknowns = [
        "Unlinked proposed safety assumption (not an Assertion candidate): "
        "model proposed a condition without an explicit safe judgment"]
    filtered = classify_hp_analysis(work, analysis)
    assert filtered["status"] == "NO_SAFE_ASSUMPTION"
    assert filtered["safe_selection_observation"] == {
        "retained_safe_count": 0,
        "unlinked_proposal_count": 1,
        "unlisted_explicit_count": 0,
        "selection_reason": "UNLINKED_PROPOSAL_FILTERED"}
    analysis.unknowns = []
    failed = classify_hp_analysis(work, error=RuntimeError("provider refused"))
    assert failed["status"] == "INCOMPLETE_HP_ERROR"
    assert failed["error_type"] == "RuntimeError"
    assert failed["sp_global_effect"] == "UNCHANGED"
    analysis.direction_id = str(ObjectId())
    wrong_direction = classify_hp_analysis(work, analysis)
    assert wrong_direction["status"] == "INCOMPLETE_HP_RESULT_MISMATCH"
    assert wrong_direction["sp_global_effect"] == "UNCHANGED"


class ScriptedProvider:
    def __init__(self, role, response, on_generate=None):
        self.role = role
        self.response = response
        self.on_generate = on_generate
        self.requests = []

    async def generate(self, request):
        assert request.role == self.role
        self.requests.append(request)
        if self.on_generate is not None:
            self.on_generate()
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class SequencedProvider(ScriptedProvider):
    def __init__(self, role, responses, on_generate=None):
        super().__init__(role, None, on_generate)
        self.responses = iter(responses)

    async def generate(self, request):
        assert request.role == self.role
        self.requests.append(request)
        if self.on_generate is not None:
            self.on_generate()
        return next(self.responses)


def _analysis_reply(*, safe=False):
    assumption = "The input pointer is not null"
    return {
        "summary": "Read from an input pointer", "input_flow": "p is an input",
        "state_dependencies": [], "context_requests": [],
        "safe_assumptions": [assumption] if safe else [], "unknowns": [],
        "input_sources": ["p"], "security_sensitive_operations": ["*p"],
        "validations": [], "memory_operations": ["read *p"],
        "evidence": ["return *p"],
        "safe_assumption_lifecycle": [],
        "hypothesis_evaluations": ([{
            "source_location": "parser.c:2", "source_file": "parser.c",
            "source_line": 2, "source_quote": "return *p;",
            "security_property": "valid memory read",
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": "p may be null",
            "judgment": "EXPLICIT_SAFE_JUDGMENT",
            "reason": "the read requires a valid pointer",
            "safe_assumption": assumption,
        }] if safe else []),
    }


def _assertion_reply():
    assumption = "The input pointer is not null"
    return {
        "assertions": [{"safe_id": 0, "safe_assumption": assumption,
                        "runtime_expression": "p != 0", "source_line": 2,
                        "required_context": [], "rationale": "check before read"}],
        "dispositions": [{"safe_id": 0, "safe_assumption": assumption,
                          "status": "PROPOSED", "reason": "expressible"}],
    }


def _lifecycle_row(disposition, *, assumption_id="", assumption=None,
                   location="parser.c:2", security_property="valid memory read",
                   required_context=None, evidence_dependencies=None):
    return {
        "assumption_id": assumption_id,
        "safe_assumption": assumption or "The input pointer is not null",
        "source_location": location,
        "security_property": security_property,
        "disposition": disposition,
        "reason": "provider-free lifecycle disposition",
        "required_context": required_context or [],
        "evidence_dependencies": evidence_dependencies or ["SELECTED_SOURCE"],
    }


def _lifecycle_reply(disposition, *, safe=True, assumption_id="",
                     requests=None, required_context=None):
    reply = _analysis_reply(safe=safe)
    reply["context_requests"] = requests or []
    reply["safe_assumption_lifecycle"] = [_lifecycle_row(
        disposition, assumption_id=assumption_id,
        required_context=required_context)]
    return reply


def _pipelines(analysis_reply, *, assertion_reply=None, analysis_callback=None):
    analysis_provider = ScriptedProvider(
        "function_analysis", analysis_reply, analysis_callback)
    assertion_provider = ScriptedProvider(
        "assertion_generator", assertion_reply or _assertion_reply())
    return (AgentPipeline(analysis_provider), AgentPipeline(assertion_provider),
            analysis_provider, assertion_provider)


def test_parallel_sp_loop_runs_existing_hp_safe_and_assertion_roles(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    run_dir = tmp_path / "parallel-loop"
    run_dir.mkdir(mode=0o700)
    run_id, spec_sha, plan_sha, catalog_sha = (
        "c" * 24, "d" * 64, "e" * 64, "f" * 64)
    _, selection_sha = freeze_parallel_hp_selection(
        run_dir=run_dir, task_id=func.task_id, run_id=run_id,
        fuzzer=direction.fuzzer, spec_sha256=spec_sha,
        direction_plan_sha256=plan_sha,
        function_catalog_sha256=catalog_sha,
        directions=[direction], functions=[func])
    claim_sha = claim_parallel_hp_execution(
        run_dir=run_dir, task_id=func.task_id, run_id=run_id,
        spec_sha256=spec_sha, selection_receipt_sha256=selection_sha)
    evidence = {
        "origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
        "task_id": func.task_id, "run_id": run_id,
        "function_id": func.function_id,
        "direction_id": direction.direction_id,
        "source_tree_sha256": q.source_tree_sha256,
        "contract_sha256": q.contract_sha256,
        "spec_sha256": spec_sha, "direction_plan_sha256": plan_sha,
        "function_catalog_sha256": catalog_sha,
        "selection_receipt_sha256": selection_sha,
        "execution_claim_sha256": claim_sha,
        "run_dir": str(run_dir),
    }
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer=direction.fuzzer, sanitizer="address",
        parallel_hp_selection_evidence=evidence)
    assert isinstance(work, PreparedHPFunction)

    hp_model_entered = asyncio.Event()
    sp_running = asyncio.Event()
    hp_finished = asyncio.Event()

    class HeldAnalysis(ScriptedProvider):
        async def generate(self, request):
            hp_model_entered.set()
            await asyncio.wait_for(sp_running.wait(), timeout=2)
            return await super().generate(request)

    analysis_provider = HeldAnalysis("function_analysis",
                                    _analysis_reply(safe=True))
    assertion_provider = ScriptedProvider("assertion_generator",
                                          _assertion_reply())

    async def planning():
        return [direction]

    async def sp_pipeline(_directions):
        await asyncio.wait_for(hp_model_entered.wait(), timeout=2)
        sp_running.set()
        await asyncio.wait_for(hp_finished.wait(), timeout=2)
        return "SP_COMPLETED"

    async def hp_factory(_strategy, directions):
        assert directions == [direction]
        result = await run_prepared_hp_analysis(
            work=work, qualification=q,
            analysis_pipeline=AgentPipeline(analysis_provider),
            assertion_pipeline=AgentPipeline(assertion_provider),
            worker_id="parallel-hp-fixture", provider_free_fixture=True)
        hp_finished.set()
        return result

    strategy = object.__new__(POVFullscanStrategy)
    strategy.executor = SimpleNamespace(
        require_original_global_bridge=False,
        parallel_hp_async_factory=hp_factory)
    strategy.llm_client_factory = object()
    strategy.log_info = lambda _message: None
    strategy._run_direction_planning_async = planning
    strategy._run_v2_pipeline_with_fuzzer_init = sp_pipeline
    assert asyncio.run(strategy._run_full_pipeline()) == "SP_COMPLETED"
    assert strategy._parallel_hp_result["status"] == (
        "ASSERTIONS_PROPOSED_UNVERIFIED")
    assert len(analysis_provider.requests) == 1
    assert len(assertion_provider.requests) == 1
    assert strategy._parallel_hp_result["security_gate_credit"] == "NOT_CREDITED"


def test_existing_hp_analysis_no_safe_skips_assertion_and_keeps_sp_global(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, first_provider, second_provider = _pipelines(
        _analysis_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert result["sp_global_effect"] == "UNCHANGED"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert len(first_provider.requests) == 1
    assert first_provider.requests[0].payload["source_start_line"] == 1
    assert first_provider.requests[0].payload["harness_source"]
    assert second_provider.requests == []


def test_hp_receipt_distinguishes_unlinked_safe_from_no_safe(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    reply = _analysis_reply(safe=True)
    reply["hypothesis_evaluations"][0]["judgment"] = "UNKNOWN"
    reply["hypothesis_evaluations"][0]["safe_assumption"] = ""
    first, second, _, second_provider = _pipelines(reply)
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert result["safe_selection_observation"] == {
        "retained_safe_count": 0,
        "unlinked_proposal_count": 1,
        "unlisted_explicit_count": 0,
        "selection_reason": "UNLINKED_PROPOSAL_FILTERED"}
    assert second_provider.requests == []


def test_unbudgeted_hp_provider_is_rejected_before_any_request(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, first_provider, second_provider = _pipelines(
        _analysis_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert result["reason"] == "HP_SHARED_MODEL_LEDGER_REQUIRED"
    assert first_provider.requests == second_provider.requests == []


def test_existing_hp_analysis_safe_calls_assertion_but_never_gate(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, first_provider, second_provider = _pipelines(
        _analysis_reply(safe=True))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["safe_assumption_count"] == 1
    assert result["assertion_count"] == 1
    assert result["proposed_assertion_count"] == 1
    assert result["assertion_execution"] == "NOT_RUN"
    assert result["assertion_proposals"][0]["runtime_expression"] == "p != 0"
    assert result["assertion_proposals"][0]["status"] == "PROPOSED"
    assert result["assertion_proposals_sha256"] == hashlib.sha256(
        json.dumps(result["assertion_proposals"], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    assert result["prepared_work_sha256"] == hashlib.sha256(
        json.dumps(asdict(work), sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert len(first_provider.requests) == len(second_provider.requests) == 1


def test_model_discarded_safe_is_recorded_without_an_assertion(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    safe = "The input pointer is not null"
    reply = {"assertions": [], "dispositions": [{
        "safe_id": 0, "safe_assumption": safe,
        "status": "NOT_INPUT_DEPENDENT",
        "reason": "The caller fixes this pointer independently of input bytes"}]}
    first, second, _, assertion_provider = _pipelines(
        _analysis_reply(safe=True), assertion_reply=reply)
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "NO_ASSERTION_PROPOSAL"
    assert result["safe_assumption_count"] == 1
    assert result["assertion_count"] == 0
    assert result["assertion_proposals"] == []
    assert result["assertion_dispositions"][0]["status"] == (
        "NOT_INPUT_DEPENDENT")
    assert len(assertion_provider.requests) == 1
    assert result["security_gate_credit"] == "NOT_CREDITED"


def test_hp_proposal_handoff_uses_existing_execution_and_guided_functions(
        tmp_path, monkeypatch):
    q, func, direction, path = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, _, _ = _pipelines(_analysis_reply(safe=True))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    proposal_id = result["assertion_proposals"][0]["assertion_id"]
    build = ["clang", "-fsanitize=fuzzer,address", "{source}",
             str(q.harness), "-o", "{binary}"]
    run = ["{binary}", "{input}"]
    observed = []

    def execute(assertion, source, line, seed, output, build_command,
                run_command, **kwargs):
        observed.append("execute")
        assert assertion.assertion_id == proposal_id
        assert assertion.source_location == f"{path}:2"
        assert source == path and line == 2 and seed == q.normal_seed
        assert output == tmp_path / "hp-output" / "execution"
        assert build_command == build and run_command == run
        assert kwargs["timeout_seconds"] == 5
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    def guided(assertion, source, line, seed, output, build_command,
               run_command, **kwargs):
        observed.append("guided")
        assert assertion.status == "HELD_FOR_EXECUTION"
        assert source == path and line == 2 and seed == q.normal_seed
        assert output == tmp_path / "hp-output" / "guided"
        assert build_command == build and run_command == run
        assert kwargs["seconds"] == 1
        return {"status": "RAN", "violation_witnesses": []}

    handoff = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "hp-output", build_command=build,
        run_command=run, guided_seconds=1, timeout_seconds=5,
        provider_free_fixture=True, execute_callback=execute,
        guided_callback=guided)
    assert observed == ["execute", "guided"]
    assert handoff["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert handoff["assertion_status"] == "HELD_FOR_EXECUTION"
    assert handoff["guided_status"] == "RAN"
    assert handoff["security_gate_credit"] == "NOT_CREDITED"
    assert handoff["discovery_credit"] == "NOT_CREDITED"

    not_reached_calls = []

    def not_reached_execute(assertion, *_args, **_kwargs):
        assertion.status = "NOT_REACHED"
        return assertion, None

    def not_reached_guided(*_args, **_kwargs):
        not_reached_calls.append("guided")
        return {"status": "RAN", "violation_witnesses": []}

    not_reached = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "not-reached-output", build_command=build,
        run_command=run, guided_seconds=1, timeout_seconds=5,
        provider_free_fixture=True, execute_callback=not_reached_execute,
        guided_callback=not_reached_guided)
    assert not_reached_calls == ["guided"]
    assert not_reached["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert not_reached["assertion_status"] == "NOT_REACHED"
    assert not_reached["guided_status"] == "RAN"

    incomplete_guided = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "incomplete-corpus-output", build_command=build,
        run_command=run, guided_seconds=1, timeout_seconds=5,
        provider_free_fixture=True, execute_callback=not_reached_execute,
        guided_callback=lambda *_args, **_kwargs: {
            "status": "INCOMPLETE_CORPUS_RETENTION"})
    assert incomplete_guided["status"] == "INCOMPLETE_HP_ASSERTION_HANDOFF"
    assert incomplete_guided["guided_status"] == "INCOMPLETE_CORPUS_RETENTION"

    crash_guided = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "observed-guided-crash", build_command=build,
        run_command=run, guided_seconds=1, timeout_seconds=5,
        provider_free_fixture=True, execute_callback=not_reached_execute,
        guided_callback=lambda *_args, **_kwargs: {
            "status": "CRASH_OBSERVED_INCOMPLETE",
            "other_crash_artifacts": ["crash"],
            "violation_witnesses": []})
    assert crash_guided["status"] == "HP_GUIDED_CRASH_OBSERVED_UNGATED"
    assert crash_guided["physical_observations"][
        "guided_crash_observed_ungated"] is True
    assert crash_guided["security_gate_credit"] == "NOT_CREDITED"

    interrupted_after_crash = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "interrupted-after-guided-crash", build_command=build,
        run_command=run, guided_seconds=1, timeout_seconds=5,
        provider_free_fixture=True, execute_callback=not_reached_execute,
        guided_callback=lambda *_args, **_kwargs: {
            "status": "INCOMPLETE_CONTINUATION",
            "initial_segment_status": "CRASH_OBSERVED_INCOMPLETE",
            "continuation": {"status": "ERROR"}})
    assert interrupted_after_crash["status"] == (
        "HP_GUIDED_CRASH_OBSERVED_UNGATED")
    assert interrupted_after_crash["security_gate_credit"] == "NOT_CREDITED"

    for index, malformed in enumerate(({"status": []}, {"status": {}}, ["RAN"])):
        malformed_result = run_prepared_hp_assertion_handoff(
            work=work, qualification=q, analysis_result=result,
            worker_id="worker", assertion_id=proposal_id,
            output_dir=tmp_path / f"malformed-guided-{index}", build_command=build,
            run_command=run, guided_seconds=1, timeout_seconds=5,
            provider_free_fixture=True, execute_callback=not_reached_execute,
            guided_callback=lambda *_args, value=malformed, **_kwargs: value)
        assert malformed_result["status"] == "INCOMPLETE_HP_ASSERTION_HANDOFF"
        assert malformed_result["security_gate_credit"] == "NOT_CREDITED"

    builder = tmp_path / "multi_tu_assertion_build.py"
    builder.write_text("#!/usr/bin/python3\n")
    q.binary = tmp_path / "official-binary"
    q.binary.write_bytes(b"fixture binary")
    manifest = builder.with_name("multi_tu_assertion_build_manifest.json")
    rel = path.relative_to(q.source_root).as_posix()
    manifest.write_text(json.dumps({
        "schema": "MULTI_TU_ASSERTION_BUILD_V1",
        "kind": "MD4C_ISOLATED_ASSERTION_RELINK_V1",
        "builder_sha256": hashlib.sha256(builder.read_bytes()).hexdigest(),
        "source_root": str(q.source_root.resolve()),
        "harness_source": str(q.harness.resolve()),
        "official_binary": str(q.binary.resolve()),
        "official_binary_sha256": q.binary_sha256,
        "source_files": {rel: work.source_file_sha256,
                         f"test/fuzzers/{q.harness.name}": q.harness_sha256},
        "allowed_translation_units": {rel: 0},
    }, sort_keys=True))
    relink_build = [str(builder), "{source}", "-o", "{binary}"]
    relink_observed = []

    def relink_execute(assertion, *_args, **_kwargs):
        relink_observed.append("execute")
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    def relink_guided(*_args, **_kwargs):
        relink_observed.append("guided")
        return {"status": "RAN"}

    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    relink = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "relink-output", build_command=relink_build,
        run_command=run, guided_seconds=1, provider_free_fixture=True,
        execute_callback=relink_execute, guided_callback=relink_guided,
        builder_manifest_path=manifest, builder_manifest_sha256=manifest_sha)
    assert relink["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert relink_observed == ["execute", "guided"]
    manifest.write_text(manifest.read_text() + " ")
    denied_relink = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "relink-output", build_command=relink_build,
        run_command=run, guided_seconds=1, provider_free_fixture=True,
        execute_callback=relink_execute, guided_callback=relink_guided,
        builder_manifest_path=manifest, builder_manifest_sha256=manifest_sha)
    assert denied_relink["reason"] == "HP_INSTRUMENTED_BUILD_RECIPE_UNSUPPORTED"
    assert relink_observed == ["execute", "guided"]
    manifest.write_text(manifest.read_text().rstrip())
    restored_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

    def mutate_relink_during_execution(assertion, *_args, **_kwargs):
        manifest.write_text(manifest.read_text() + " ")
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    incomplete_relink = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "relink-output", build_command=relink_build,
        run_command=run, guided_seconds=1, provider_free_fixture=True,
        execute_callback=mutate_relink_during_execution,
        guided_callback=relink_guided,
        builder_manifest_path=manifest, builder_manifest_sha256=restored_sha)
    assert incomplete_relink["reason"] == "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"
    assert relink_observed == ["execute", "guided"]

    unbound = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "hp-output", build_command=build,
        run_command=run, guided_seconds=1, provider_free_fixture=True)
    assert unbound["reason"] == "HP_FIXTURE_EXECUTION_CALLBACK_REQUIRED"
    live = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "hp-output", build_command=build,
        run_command=run, guided_seconds=1, execute_callback=execute,
        guided_callback=guided)
    assert live["reason"] == "LIVE_HP_INSTRUMENTED_BUILD_AND_ENVELOPE_NOT_ADMITTED"
    assert observed == ["execute", "guided"]

    tampered = {**result, "assertion_proposals": [
        {**result["assertion_proposals"][0], "runtime_expression": "0"}]}
    denied = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=tampered,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "hp-output", build_command=build,
        run_command=run, provider_free_fixture=True,
        execute_callback=execute)
    assert denied["reason"] == "HP_PROPOSAL_RECEIPT_MISMATCH"
    assert observed == ["execute", "guided"]

    wrong_location = {**result, "assertion_proposals": [
        {**result["assertion_proposals"][0],
         "source_location": "other.c:2"}]}
    wrong_location["assertion_proposals_sha256"] = hashlib.sha256(
        json.dumps(wrong_location["assertion_proposals"], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    denied = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=wrong_location,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "hp-output", build_command=build,
        run_command=run, provider_free_fixture=True,
        execute_callback=execute)
    assert denied["reason"] == "HP_ASSERTION_SOURCE_OR_SEED_MISMATCH"
    q.normal_seed.write_bytes(b"changed")
    denied = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "hp-output", build_command=build,
        run_command=run, provider_free_fixture=True,
        execute_callback=execute)
    assert denied["reason"] == "HP_ASSERTION_SOURCE_OR_SEED_MISMATCH"
    assert observed == ["execute", "guided"]


def test_hp_no_safe_handoff_never_executes(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, _, _ = _pipelines(_analysis_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SAFE 0 must not execute or fuzz an Assertion")

    handoff = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id="none",
        output_dir=tmp_path / "hp-output", build_command=[],
        run_command=[], provider_free_fixture=True,
        execute_callback=forbidden, guided_callback=forbidden)
    assert handoff["status"] == "HP_ASSERTION_NOT_APPLICABLE"
    assert handoff["security_gate_credit"] == "NOT_CREDITED"


def test_bounded_hp_context_reanalysis_and_assertion_share_same_source(
        tmp_path, monkeypatch):
    first_source = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    source = first_source + "int helper(const char *p) {\n  return *p;\n}\n"
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=source, content=first_source)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    assert isinstance(work, PreparedHPFunction)
    request = {"target": "helper", "request_type": "FUNCTION",
               "reason": "input reaches helper", "expected_information": "read bounds"}
    initial = _analysis_reply()
    initial["context_requests"] = [request]
    second = _analysis_reply(safe=True)
    analysis_provider = SequencedProvider("function_analysis", [initial, second])
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_request_count"] == 1
    assert result["context_provided_count"] == 1
    assert result["context_reanalysis_count"] == 1
    assert result["context_requests"][0]["status"] == "FETCHED"
    assert result["context_evidence"][0]["source_file_sha256"] == hashlib.sha256(
        (q.source_root / "parser.c").read_bytes()).hexdigest()
    assert len(analysis_provider.requests) == 2
    assert len(assertion_provider.requests) == 1
    expanded = analysis_provider.requests[1].payload["context"]
    assert expanded == assertion_provider.requests[0].payload["context"]
    assert expanded[0]["function_name"] == "helper"
    assert result["security_gate_credit"] == "NOT_CREDITED"


def test_per_assumption_validated_safe_does_not_bypass_unverified_context(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    unrelated = {"target": "unrelated_helper", "request_type": "FUNCTION",
                 "reason": "different hypothesis",
                 "expected_information": "unrelated source"}
    second_assumption = "The unrelated helper preserves an independent bound"
    response = _lifecycle_reply(
        "VALIDATED_SAFE", requests=[unrelated])
    response["safe_assumptions"].append(second_assumption)
    response["hypothesis_evaluations"].append({
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return *p;",
        "security_property": "independent helper bound",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "helper may exceed a bound", "judgment": "EXPLICIT_SAFE_JUDGMENT",
        "reason": "more helper evidence is required",
        "safe_assumption": second_assumption,
    })
    response["safe_assumption_lifecycle"].append(_lifecycle_row(
        "NEEDS_CONTEXT", assumption=second_assumption,
        security_property="independent helper bound",
        required_context=[{
            "target": "unrelated_helper", "request_type": "FUNCTION"}]))
    analysis_provider = ScriptedProvider(
        "function_analysis", response)
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "INCOMPLETE_HP_ASSUMPTION_EVIDENCE"
    assert result["context_reanalysis_count"] == 0
    assert result["context_request_count"] == 1
    assert result["context_requests"][0]["status"] == "NOT_FOUND"
    assert len(analysis_provider.requests) == 1
    assert assertion_provider.requests == []
    assert [row["disposition"] for row in
            result["assumption_lifecycle_history"]] == [
                "VALIDATED_SAFE", "NEEDS_CONTEXT"]
    assert result["assumption_lifecycle_history"][0]["assertion_eligible"] is True
    assert result["assumption_lifecycle_history"][1]["assertion_eligible"] is False


def test_per_assumption_new_needs_context_unknown_gets_host_id_without_safe():
    """A pre-SAFE candidate may request Context without weakening SAFE rules."""
    assumption = "The caller supplies at least one readable input byte"
    request = {
        "target": "helper", "request_type": "FUNCTION",
        "reason": "helper determines the readable input extent",
        "expected_information": "the exact pointer and length relation",
        "hypothesis_index": 0,
    }
    reply = _analysis_reply()
    reply["context_requests"] = [request]
    reply["hypothesis_evaluations"] = [{
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return *p;",
        "security_property": "valid memory read",
        "input_influence": "UNKNOWN",
        "hypothesis": "helper must provide a readable pointer",
        "judgment": "UNKNOWN",
        "reason": "the helper body is required",
        "safe_assumption": "",
    }]
    reply["safe_assumption_lifecycle"] = [_lifecycle_row(
        "NEEDS_CONTEXT", assumption=assumption,
        required_context=[{
            "target": "helper", "request_type": "FUNCTION"}])]
    analysis = asyncio.run(AgentPipeline(
        ScriptedProvider("function_analysis", reply)).analyze_function(
            "fn-needs-context", "parse_input", "parser.c",
            "int parse_input(const char *p) {\n  return *p;\n}\n",
            source_start_line=1,
            assumption_lifecycle_contract={
                "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                "available_evidence": [{
                    "evidence_id": "SELECTED_SOURCE"}]},
            prior_safe_assumptions=[]))
    assert analysis.safe_assumptions == []
    assert len(analysis.context_requests) == 1
    assert len(analysis.safe_assumption_lifecycle) == 1
    row = analysis.safe_assumption_lifecycle[0]
    assert row["assumption_id"]
    assert row["disposition"] == "NEEDS_CONTEXT"
    assert row["safe_assumption"] == assumption


def test_per_assumption_new_proposed_unknown_gets_host_id_without_safe():
    assumption = "The caller supplies at least one readable input byte"
    reply = _analysis_reply()
    reply["hypothesis_evaluations"] = [{
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return *p;",
        "security_property": "valid memory read",
        "input_influence": "UNKNOWN",
        "hypothesis": "the readable extent is not established",
        "judgment": "UNKNOWN", "reason": "more evidence may be needed",
        "safe_assumption": "",
    }]
    reply["safe_assumption_lifecycle"] = [_lifecycle_row(
        "PROPOSED", assumption=assumption)]

    analysis = asyncio.run(AgentPipeline(
        ScriptedProvider("function_analysis", reply)).analyze_function(
            "fn-proposed", "parse_input", "parser.c",
            "int parse_input(const char *p) {\n  return *p;\n}\n",
            source_start_line=1,
            assumption_lifecycle_contract={
                "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                "available_evidence": [{"evidence_id": "SELECTED_SOURCE"}]},
            prior_safe_assumptions=[]))

    assert analysis.safe_assumptions == []
    assert analysis.safe_assumption_lifecycle[0]["assumption_id"]
    assert analysis.safe_assumption_lifecycle[0]["disposition"] == "PROPOSED"


@pytest.mark.parametrize("failure_kind", [
    "ambiguous", "nonempty_evaluation_safe", "unpinned_quote",
])
def test_per_assumption_new_provisional_candidate_fails_closed(failure_kind):
    assumption = "The caller supplies at least one readable input byte"
    evaluation = {
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return *p;",
        "security_property": "valid memory read",
        "input_influence": "UNKNOWN",
        "hypothesis": "the readable extent is not established",
        "judgment": "UNKNOWN", "reason": "the helper body is required",
        "safe_assumption": "",
    }
    reply = _analysis_reply()
    reply["hypothesis_evaluations"] = [evaluation]
    if failure_kind == "ambiguous":
        reply["hypothesis_evaluations"].append(dict(evaluation))
    elif failure_kind == "nonempty_evaluation_safe":
        evaluation["safe_assumption"] = assumption
    else:
        evaluation["source_quote"] = "return p[999];"
    reply["safe_assumption_lifecycle"] = [_lifecycle_row(
        "NEEDS_CONTEXT", assumption=assumption,
        required_context=[{
            "target": "helper", "request_type": "FUNCTION"}])]

    with pytest.raises(
            ValueError, match="not uniquely linked to pinned source identity"):
        asyncio.run(AgentPipeline(
            ScriptedProvider("function_analysis", reply)).analyze_function(
                "fn-provisional-negative", "parse_input", "parser.c",
                "int parse_input(const char *p) {\n  return *p;\n}\n",
                source_start_line=1,
                assumption_lifecycle_contract={
                    "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                    "available_evidence": [{
                        "evidence_id": "SELECTED_SOURCE"}]},
                prior_safe_assumptions=[]))


def test_per_assumption_terminal_candidate_cannot_revive_via_property_alias():
    """Model-authored property synonyms must not mint a new terminal lineage."""
    assumption = "The input pointer is not null"
    prior = _lifecycle_row(
        "INVALIDATED", assumption_id="safe-terminal", assumption=assumption,
        security_property="bounded read")
    reply = _analysis_reply(safe=True)
    reply["hypothesis_evaluations"][0]["security_property"] = (
        "read remains within bounds")
    reply["safe_assumption_lifecycle"] = [
        prior,
        _lifecycle_row(
            "VALIDATED_SAFE", assumption=assumption,
            security_property="read remains within bounds"),
    ]

    with pytest.raises(
            ValueError, match="reintroduces a known canonical identity"):
        asyncio.run(AgentPipeline(
            ScriptedProvider("function_analysis", reply)).analyze_function(
                "fn-terminal-alias", "parse_input", "parser.c",
                "int parse_input(const char *p) {\n  return *p;\n}\n",
                source_start_line=1,
                assumption_lifecycle_contract={
                    "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                    "available_evidence": [{
                        "evidence_id": "SELECTED_SOURCE"}]},
                prior_safe_assumptions=[prior]))


def test_per_assumption_terminal_anchor_rejects_assumption_paraphrase():
    """Model prose cannot rebase a terminal candidate at the same anchor."""
    old_assumption = "The input pointer is not null"
    new_assumption = "The input points to at least one readable byte"
    prior = _lifecycle_row(
        "INVALIDATED", assumption_id="safe-terminal", assumption=old_assumption,
        security_property="pointer validity")
    reply = _analysis_reply()
    reply["safe_assumptions"] = [new_assumption]
    reply["hypothesis_evaluations"] = [{
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return *p;",
        "security_property": "readable extent",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "the readable extent may be zero",
        "judgment": "EXPLICIT_SAFE_JUDGMENT",
        "reason": "the dereference requires one readable byte",
        "safe_assumption": new_assumption,
    }]
    reply["safe_assumption_lifecycle"] = [
        prior,
        _lifecycle_row(
            "VALIDATED_SAFE", assumption=new_assumption,
            security_property="readable extent"),
    ]

    with pytest.raises(
            ValueError, match="terminal source anchor"):
        asyncio.run(AgentPipeline(
            ScriptedProvider("function_analysis", reply)).analyze_function(
                "fn-distinct-anchor", "parse_input", "parser.c",
                "int parse_input(const char *p) {\n  return *p;\n}\n",
                source_start_line=1,
                assumption_lifecycle_contract={
                    "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                    "available_evidence": [{
                        "evidence_id": "SELECTED_SOURCE"}]},
                prior_safe_assumptions=[prior]))


def test_per_assumption_validated_safe_with_unattributed_request_fails_closed(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    request = {"target": "missing_helper", "request_type": "FUNCTION",
               "reason": "may affect the same path",
               "expected_information": "helper contract"}
    analysis_provider = ScriptedProvider(
        "function_analysis", _lifecycle_reply(
            "VALIDATED_SAFE", requests=[request]))
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_requests"][0]["status"] == "NOT_FOUND"
    assert assertion_provider.requests == []


def test_per_assumption_validated_safe_survives_fetched_context_monotonically(
        tmp_path, monkeypatch):
    selected = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    source = selected + "int helper(const char *p) {\n  return *p;\n}\n"
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=source, content=selected)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    request = {"target": "helper", "request_type": "FUNCTION",
               "reason": "confirm helper behavior",
               "expected_information": "helper source"}
    first = _lifecycle_reply("VALIDATED_SAFE", requests=[request])
    first["hypothesis_evaluations"][0]["source_quote"] = "return helper(p);"
    assumption = first["safe_assumptions"][0]
    assumption_id = stable_id(
        "safe", work.function_id,
        str(Path(work.source_file).resolve(strict=False)), 2,
        "valid memory read",
        " ".join(assumption.split()))
    second = _lifecycle_reply(
        "VALIDATED_SAFE", assumption_id=assumption_id)
    second["hypothesis_evaluations"][0]["source_quote"] = "return helper(p);"
    analysis_provider = SequencedProvider("function_analysis", [first, second])
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 1
    assert result["context_requests"][0]["status"] == "FETCHED"
    assert [row["disposition"] for row in result[
        "assumption_lifecycle_history"]] == [
            "VALIDATED_SAFE", "VALIDATED_SAFE"]
    assert len(assertion_provider.requests) == 1


def test_per_assumption_host_incomplete_survives_context_round_and_omission(
        tmp_path, monkeypatch):
    first_source = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    source = first_source + "int helper(const char *p) {\n  return *p;\n}\n"
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=source, content=first_source)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    request = {"target": "helper", "request_type": "FUNCTION",
               "reason": "confirm owner", "expected_information": "source"}
    first = _lifecycle_reply(
        "VALIDATED_SAFE", requests=[request],
        required_context=[{"target": "helper", "request_type": "FUNCTION"}])
    first["hypothesis_evaluations"][0]["source_quote"] = "return helper(p);"
    second = _analysis_reply()
    second["safe_assumption_lifecycle"] = []
    analysis_provider = SequencedProvider("function_analysis", [first, second])
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "INCOMPLETE_HP_ASSUMPTION_EVIDENCE"
    assert result["reason"] == "ASSUMPTION_EVIDENCE_NOT_CLOSED"
    assert result["context_reanalysis_count"] == 1
    assert result["context_requests"][0]["status"] == "FETCHED"
    assert analysis_provider.requests[1].payload["prior_safe_assumptions"][0][
        "disposition"] == "INCOMPLETE"
    assert result["assumption_lifecycle_ledger"][0]["disposition"] == (
        "INCOMPLETE")
    assert result["assumption_lifecycle_ledger"][0]["reason"] == (
        "OMITTED_PRIOR_SAFE_DISPOSITION")
    assert assertion_provider.requests == []


def test_per_assumption_parse_array_style_reclassification_blocks_assertion(
        tmp_path, monkeypatch):
    first_source = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    source = first_source + "int helper(const char *p) {\n  return *p;\n}\n"
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=source, content=first_source)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    request = {"target": "helper", "request_type": "FUNCTION",
               "reason": "confirm guard semantics",
               "expected_information": "helper source"}
    first = _lifecycle_reply("PROPOSED", requests=[request])
    first["hypothesis_evaluations"][0]["source_quote"] = "return helper(p);"
    probe = AgentPipeline(ScriptedProvider("function_analysis", first))
    first_analysis = asyncio.run(probe.analyze_function(
        work.function_id, work.function_name, work.source_file, work.source,
            assumption_lifecycle_contract={
                "kind": "probe",
                "available_evidence": [{"evidence_id": "SELECTED_SOURCE"}]},
        prior_safe_assumptions=[]))
    assumption_id = first_analysis.safe_assumption_lifecycle[0]["assumption_id"]
    second = _lifecycle_reply(
        "RECLASSIFIED_VALIDATION", safe=False, assumption_id=assumption_id)
    second["validations"] = [
        "The existing increment and guard already prevent underflow."]
    analysis_provider = SequencedProvider("function_analysis", [first, second])
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert assertion_provider.requests == []
    assert [row["disposition"] for row in
            result["assumption_lifecycle_history"]] == [
                "PROPOSED", "RECLASSIFIED_VALIDATION"]


def test_per_assumption_omission_is_incomplete_not_implicit_retention(
        tmp_path, monkeypatch):
    first_source = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    source = first_source + "int helper(const char *p) {\n  return *p;\n}\n"
    q, func, direction, _ = _case(
        tmp_path, monkeypatch, source=source, content=first_source)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    request = {"target": "helper", "request_type": "FUNCTION",
               "reason": "confirm owner", "expected_information": "source"}
    first = _lifecycle_reply("PROPOSED", requests=[request])
    first["hypothesis_evaluations"][0]["source_quote"] = "return helper(p);"
    second = _analysis_reply()
    second["safe_assumption_lifecycle"] = []
    analysis_provider = SequencedProvider("function_analysis", [first, second])
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "INCOMPLETE_HP_ASSUMPTION_EVIDENCE"
    assert result["reason"] == "ASSUMPTION_EVIDENCE_NOT_CLOSED"
    assert assertion_provider.requests == []
    assert result["assumption_lifecycle_history"][-1]["reason"] == (
        "OMITTED_PRIOR_SAFE_DISPOSITION")


def test_per_assumption_validated_safe_with_dependency_fails_closed(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    dependency = [{"target": "owner", "request_type": "FUNCTION"}]
    analysis_provider = ScriptedProvider(
        "function_analysis", _lifecycle_reply(
            "VALIDATED_SAFE", required_context=dependency))
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))

    assert result["status"] == "INCOMPLETE_HP_ASSUMPTION_EVIDENCE"
    assert result["assumption_lifecycle_history"][0]["disposition"] == (
        "INCOMPLETE")
    assert assertion_provider.requests == []


def test_per_assumption_live_use_requires_new_signed_approval(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    analysis_provider = ScriptedProvider(
        "function_analysis", _lifecycle_reply("VALIDATED_SAFE"))
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=False,
        per_assumption_evidence_closure=True))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == (
        "HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_REQUIRED")
    assert analysis_provider.requests == [] and assertion_provider.requests == []


def test_provider_free_fixture_cannot_reuse_live_admission_token(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    analysis_provider = ScriptedProvider(
        "function_analysis", _lifecycle_reply("VALIDATED_SAFE"))
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True,
        assumption_lifecycle_live_admission={"kind": "forged"}))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_INVALID"
    assert analysis_provider.requests == [] and assertion_provider.requests == []


def test_per_assumption_provider_free_physical_vertical_reaches_guided(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.assertions import (
        execute_assertion, guided_fuzz_assertion)

    q, func, direction, _ = _case(tmp_path, monkeypatch)
    q.harness.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n"
        "extern \"C\" int parse_input(const char *);\n"
        "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "  if (size) (void)parse_input((const char *)data);\n"
        "  return 0;\n}\n")
    q.harness_sha256 = hashlib.sha256(q.harness.read_bytes()).hexdigest()
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    analysis_provider = ScriptedProvider(
        "function_analysis", _lifecycle_reply("VALIDATED_SAFE"))
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True,
        per_assumption_evidence_closure=True))
    proposal_id = result["assertion_proposals"][0]["assertion_id"]
    clang = Path(os.environ.get(
        "VA_TEST_CLANG",
        "/home/dawne/SunrinInfosecProject2026/reference/"
        "blind2_v2_preparation_20261027/review_tools/local_clang/clang"))
    if not clang.is_file():
        pytest.skip("pinned test Clang unavailable")
    build = [str(clang), "-fsanitize=fuzzer,address", "-O0", "-g",
             "{source}", str(q.harness), "-o", "{binary}"]

    handoff = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=result,
        worker_id="worker", assertion_id=proposal_id,
        output_dir=tmp_path / "closure-physical", build_command=build,
        run_command=["{binary}", "{input}"], guided_seconds=1,
        timeout_seconds=30, provider_free_fixture=True,
        execute_callback=execute_assertion,
        guided_callback=guided_fuzz_assertion)

    assert handoff["status"] == "HP_ASSERTION_HANDOFF_COMPLETE", json.dumps(
        handoff, sort_keys=True)
    assert handoff["guided_status"] in {"RAN", "ASSERTION_WITNESS_OBSERVED"}
    assert handoff["security_gate_credit"] == "NOT_CREDITED"
    assert handoff["discovery_credit"] == "NOT_CREDITED"


def _lifecycle_provenance_fixture(name):
    path = (Path(__file__).parent / "fixtures" / "hp_assumption_lifecycle" /
            name)
    return json.loads(path.read_text())


def test_archived_parse_array_fixture_is_explicit_reclassification_not_safe():
    fixture = _lifecycle_provenance_fixture(
        "parse_array_reclassified_validation.json")
    assert fixture["credit"] == "NONE_PROVIDER_FREE_NEGATIVE_FIXTURE"
    assert len(fixture["source_archive_sha256"]) == 64
    candidate = fixture["candidate"]
    first = _analysis_reply()
    first["safe_assumptions"] = [candidate["safe_assumption"]]
    first["hypothesis_evaluations"] = [{
        "source_location": candidate["source_location"],
        "source_file": "cJSON.c", "source_line": 1474,
        "source_quote": "input_buffer->offset--;",
        "security_property": candidate["security_property"],
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "offset may underflow", "judgment": "EXPLICIT_SAFE_JUDGMENT",
        "reason": "opening bracket incremented offset",
        "safe_assumption": candidate["safe_assumption"],
    }]
    first["safe_assumption_lifecycle"] = [{
        **_lifecycle_row(
            "PROPOSED", assumption=candidate["safe_assumption"],
            location=candidate["source_location"],
            security_property=candidate["security_property"]),
        "evidence_dependencies": [fixture["rounds"][0]["response_sha256"]],
    }]
    first_analysis = asyncio.run(AgentPipeline(
        ScriptedProvider("function_analysis", first)).analyze_function(
            "fn-parse-array", "parse_array", "cJSON.c",
            "input_buffer->offset--;", source_start_line=1474,
            assumption_lifecycle_contract={
                "kind": fixture["kind"],
                "available_evidence": [{
                    "evidence_id": fixture["rounds"][0]["response_sha256"]}]},
            prior_safe_assumptions=[]))
    assumption_id = first_analysis.safe_assumption_lifecycle[0]["assumption_id"]
    second = _analysis_reply()
    second["validations"] = [fixture["rounds"][1]["validation"]]
    second["safe_assumption_lifecycle"] = [_lifecycle_row(
        fixture["expected_disposition"], assumption_id=assumption_id,
        assumption=candidate["safe_assumption"],
        location=candidate["source_location"],
        security_property=candidate["security_property"],
        evidence_dependencies=[fixture["rounds"][1]["response_sha256"]])]
    final = asyncio.run(AgentPipeline(
        ScriptedProvider("function_analysis", second)).analyze_function(
            "fn-parse-array", "parse_array", "cJSON.c", "offset--;",
            assumption_lifecycle_contract={
                "kind": fixture["kind"],
                "available_evidence": [{
                    "evidence_id": fixture["rounds"][1]["response_sha256"]}]},
            prior_safe_assumptions=first_analysis.safe_assumption_lifecycle))
    assert final.safe_assumptions == []
    assert final.safe_assumption_lifecycle[0]["disposition"] == (
        "RECLASSIFIED_VALIDATION")


def test_archived_parse_object_fixture_remains_assertion_eligible_without_credit():
    fixture = _lifecycle_provenance_fixture(
        "parse_object_validated_safe.json")
    assert fixture["credit"] == "NONE_PROVIDER_FREE_POSITIVE_FIXTURE"
    candidate = fixture["candidate"]
    reply = _analysis_reply()
    reply["safe_assumptions"] = [candidate["safe_assumption"]]
    reply["hypothesis_evaluations"] = [{
        "source_location": candidate["source_location"],
        "source_file": "cJSON.c", "source_line": 1670,
        "source_quote": "current_item->valuestring = NULL;",
        "security_property": candidate["security_property"],
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "key may retain two field owners",
        "judgment": "EXPLICIT_SAFE_JUDGMENT",
        "reason": "the transfer clears valuestring",
        "safe_assumption": candidate["safe_assumption"],
    }]
    reply["safe_assumption_lifecycle"] = [{
        **_lifecycle_row(
            fixture["expected_disposition"],
            assumption=candidate["safe_assumption"],
            location=candidate["source_location"],
            security_property=candidate["security_property"]),
        "evidence_dependencies": [
            fixture["final_function_analysis"]["response_sha256"]],
    }]
    analysis = asyncio.run(AgentPipeline(
        ScriptedProvider("function_analysis", reply)).analyze_function(
            "fn-parse-object", "parse_object", "cJSON.c",
            "current_item->valuestring = NULL;", source_start_line=1670,
            assumption_lifecycle_contract={
                "kind": fixture["kind"],
                "available_evidence": [{
                    "evidence_id": fixture["final_function_analysis"][
                        "response_sha256"]}]},
            prior_safe_assumptions=[]))
    assertion_reply = {
        "assertions": [{
            "safe_id": 0, "safe_assumption": candidate["safe_assumption"],
            "runtime_expression": fixture["runtime_expression"],
            "source_line": 1670, "required_context": [],
            "rationale": "archived model-derived expression"}],
        "dispositions": [{
            "safe_id": 0, "safe_assumption": candidate["safe_assumption"],
            "status": "PROPOSED", "reason": "runtime expressible"}],
    }
    proposals = asyncio.run(AgentPipeline(
        ScriptedProvider("assertion_generator", assertion_reply)).generate_assertions(
            analysis, "fixture-worker", "fixture-direction",
            "valuestring = NULL;", source_start_line=1670))
    assert analysis.safe_assumptions == [candidate["safe_assumption"]]
    assert analysis.safe_assumption_lifecycle[0]["disposition"] == "VALIDATED_SAFE"
    assert len(proposals) == 1
    assert proposals[0].runtime_expression == fixture["runtime_expression"]
    assert proposals[0].generation_method == "LLM"


def _signed_two_round_case(tmp_path, monkeypatch, *, automatic=False):
    selected = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    helper = "int helper(const char *p) {\n  return second(p);\n}\n"
    second = "int second(const char *p) {\n  return *p;\n}\n"
    caller = "int caller(const char *p) {\n  return parse_input(p);\n}\n"
    q, func, direction, path = _case(
        tmp_path, monkeypatch, source=selected + helper + second + caller,
        content=selected)
    q.harness.write_text("int test(void) { return caller(\"x\"); }\n")
    q.harness_sha256 = hashlib.sha256(q.harness.read_bytes()).hexdigest()
    if not automatic:
        func.analyzed_by_directions.clear()
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address",
        **({} if automatic else {
            "signed_manual_hp_selection_evidence":
            _signed_manual_selection(q, func, direction)}))
    assert isinstance(work, PreparedHPFunction)
    ids = ["fn-" + digit * 20 for digit in "abcd"]
    functions = tmp_path / "functions.jsonl"
    functions.write_text("".join(json.dumps({
        "function_id": ids[index], "name": name, "file": "parser.c",
        "start_line": 1 + 3 * index, "end_line": 3 + 3 * index,
        "source": source.strip(),
    }) + "\n" for index, (name, source) in enumerate((
        ("parse_input", selected), ("helper", helper),
        ("second", second), ("caller", caller)))))
    edges = tmp_path / "edges.jsonl"
    edges.write_text(json.dumps({
        "edge_id": "direct-1", "line": 11, "caller_id": ids[3],
        "callee_id": ids[0], "kind": "DIRECT_AST_ID"}) + "\n")
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "catalog": {"functions": {"path": str(functions),
                                   "sha256": sha(functions)},
                    "edges": {"path": str(edges), "sha256": sha(edges)}},
        "source_files": {"parser.c": sha(path)},
        "asan_binary": {"sha256": q.binary_sha256},
        "entry_function": "caller"}))
    return q, work, manifest, edges


def _context_request(target):
    return {"target": target, "request_type": "FUNCTION",
            "reason": "inspect input flow", "expected_information": "read bounds"}


def _attributed_context_request(target, hypothesis_index):
    return {**_context_request(target),
            "hypothesis_index": hypothesis_index}


def _independent_safe_with_context_request(*, hypothesis_index):
    reply = _analysis_reply(safe=True)
    reply["hypothesis_evaluations"][0]["source_quote"] = "return helper(p);"
    reply["safe_assumption_lifecycle"] = [
        _lifecycle_row("VALIDATED_SAFE")]
    reply["hypothesis_evaluations"].append({
        "source_location": "parser.c:1", "source_file": "parser.c",
        "source_line": 1,
        "source_quote": "int parse_input(const char *p) {",
        "security_property": "semantic output integrity",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "parse_input callers may require another contract",
        "judgment": "POSSIBLE_BUG",
        "reason": "parse_input caller behavior is not in the selected body",
        "safe_assumption": "",
    })
    reply["context_requests"] = [{
        **_attributed_context_request("parse_input", hypothesis_index),
        "request_type": "CALLER",
    }]
    return reply


def test_generic_initial_context_bundle_uses_pinned_graph_source_and_build(
        tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    macro = (
        "#define READ_AT(p) (*(p))\n"
        "#define CHECK_AT(p) ((p) != 0)\n"
        "#define ADVANCE_AT(p) ((p) + 1)\n"
        "#define UNUSED_AT(p) (*(p))\n")
    initializer = "static int global_hooks = 7;\n"
    leaf = (
        "int leaf(const char *p) {\n"
        "#ifdef FEATURE_X\n"
        "  return ADVANCE_AT(p) != 0;\n"
        "#else\n"
        "  return 0;\n"
        "#endif\n"
        "}\n")
    allocator = "int allocator(void) {\n  return 1;\n}\n"
    selected = (
        "int parse_input(const char *p) {\n"
        "  return READ_AT(p) + CHECK_AT(p) + global_hooks + leaf(p) +\n"
        "    BUILD_A + BUILD_B + BUILD_C + BUILD_D + BUILD_E;\n"
        "}\n")
    middle = (
        "int middle(const char *p) {\n"
        "  int allocated = allocator();\n"
        "  return parse_input(p) + allocated;\n"
        "}\n")
    entry = "int entry(const char *p) {\n  return middle(p);\n}\n"
    chunks = [macro, initializer, leaf, allocator, selected, middle, entry]
    source = "".join(chunks)
    source_path = root / "parser.c"
    source_path.write_text(source)
    harness = tmp_path / "fuzzer.c"
    harness.write_text("int test(const char *p) { return entry(p); }\n")
    q = FakeQualification(root, harness)
    ids = {name: "fn-" + digit * 20 for name, digit in (
        ("leaf", "a"), ("allocator", "b"), ("parse_input", "c"),
        ("middle", "d"), ("entry", "e"))}
    definitions = {
        "leaf": leaf, "allocator": allocator, "parse_input": selected,
        "middle": middle, "entry": entry,
    }
    rows = []
    for name, body in definitions.items():
        offset = source.index(body)
        start = source.count("\n", 0, offset) + 1
        rows.append({
            "function_id": ids[name], "name": name, "file": "parser.c",
            "start_line": start,
            "end_line": start + len(body.splitlines()) - 1,
            "source": body.strip(),
        })
    functions = tmp_path / "functions.jsonl"
    functions.write_text("".join(json.dumps(row) + "\n" for row in rows))
    line = lambda text: source.count("\n", 0, source.index(text)) + 1
    edge_rows = [
        {"edge_id": "edge-entry-middle", "line": line("middle(p)"),
         "caller_id": ids["entry"], "callee_id": ids["middle"],
         "kind": "DIRECT_AST_ID"},
        {"edge_id": "edge-middle-allocator", "line": line("allocator()"),
         "caller_id": ids["middle"], "callee_id": ids["allocator"],
         "kind": "DIRECT_AST_ID"},
        {"edge_id": "edge-middle-selected", "line": line("parse_input(p)"),
         "caller_id": ids["middle"], "callee_id": ids["parse_input"],
         "kind": "DIRECT_AST_ID"},
        {"edge_id": "edge-selected-leaf", "line": line("leaf(p)"),
         "caller_id": ids["parse_input"], "callee_id": ids["leaf"],
         "kind": "DIRECT_AST_ID"},
    ]
    edges = tmp_path / "edges.jsonl"
    edges.write_text("".join(json.dumps(row) + "\n" for row in edge_rows))
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "catalog": {
            "functions": {"path": str(functions), "sha256": sha(functions)},
            "edges": {"path": str(edges), "sha256": sha(edges)},
        },
        "source_files": {"parser.c": sha(source_path)},
        "asan_binary": {"sha256": q.binary_sha256},
        "entry_function": "entry",
    }))
    selected_row = next(row for row in rows if row["name"] == "parse_input")
    work = PreparedHPFunction(
        task_id="task", function_id="selected", function_name="parse_input",
        direction_id="direction", source_file=str(source_path),
        source=selected.strip(), source_start_line=selected_row["start_line"],
        source_end_line=selected_row["end_line"],
        source_sha256=hashlib.sha256(selected.strip().encode()).hexdigest(),
        source_file_sha256=sha(source_path), harness_path=str(harness),
        harness_sha256=sha(harness), binary_sha256=q.binary_sha256,
        source_tree_sha256=q.source_tree_sha256,
        contract_sha256=q.contract_sha256, analysis_scope={},
        selection_origin="SIGNED_MANUAL_HP_CONTROL")
    digest = sha(manifest)
    static_path, _ = _pinned_static_call_path(
        work, q, manifest, digest)
    plan, build_rows, audit = _pinned_initial_context_plan(
        work, q, manifest, digest, static_path,
        ["/pinned/clang", "-DFEATURE_X", "-DBUILD_A=1", "-DBUILD_B=2",
         "-DBUILD_C=3", "-DBUILD_D=4", "-DBUILD_E=5", "-DUNUSED",
         "{source}"])

    assert [(row["target"], row["request_type"]) for row in plan] == [
        ("entry", "FUNCTION"),
        ("middle", "FUNCTION"),
        ("leaf", "FUNCTION"),
        ("allocator", "FUNCTION"),
        ("global_hooks", "INITIALIZER"),
        ("READ_AT", "MACRO"),
        ("CHECK_AT", "MACRO"),
        ("ADVANCE_AT", "MACRO"),
    ]
    assert [row["target"] for row in build_rows] == [
        "FEATURE_X", "BUILD_A", "BUILD_B", "BUILD_C"]
    assert build_rows[0]["build_flag"] == "-DFEATURE_X"
    assert audit == [
        {"target": "BUILD_D", "request_type": "BUILD_MACRO", "round": -1,
         "status": "NOT_PRELOADED_BUNDLE_LIMIT",
         "evidence_kind": "PINNED_ACTIVE_BUILD_DEFINE"},
        {"target": "BUILD_E", "request_type": "BUILD_MACRO", "round": -1,
         "status": "NOT_PRELOADED_BUNDLE_LIMIT",
         "evidence_kind": "PINNED_ACTIVE_BUILD_DEFINE"},
    ]

    from vulnerabilityanalysis.models import ContextRequest
    helper_context, helper_records, _ = _bounded_context(
        work, [ContextRequest(
            requesting_function=work.function_id, target="leaf",
            request_type="FUNCTION", reason="pinned helper",
            expected_information="helper source")], q,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest,
        enforce_manifest_source_pins=True,
        seen_requests=set(), attempted_requests=set())
    macro_context, macro_records, _ = _bounded_context(
        work, [ContextRequest(
            requesting_function=work.function_id, target="ADVANCE_AT",
            request_type="MACRO", reason="helper dependency",
            expected_information="active macro definition")], q,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest,
        enforce_manifest_source_pins=True,
        prior_context=helper_context,
        seen_requests={('leaf', 'FUNCTION')},
        attempted_requests={('leaf', 'FUNCTION')})
    initializer_context, initializer_records, _ = _bounded_context(
        work, [ContextRequest(
            requesting_function=work.function_id, target="global_hooks",
            request_type="INITIALIZER", reason="selected dependency",
            expected_information="file-scope initial declaration")], q,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest,
        enforce_manifest_source_pins=True,
        seen_requests=set(), attempted_requests=set())

    assert helper_records[0]["status"] == "FETCHED"
    assert macro_records[0]["status"] == "FETCHED"
    assert macro_records[0]["evidence_kind"] == (
        "PINNED_PROVIDED_FUNCTION_MACRO_ONLY")
    assert "#define ADVANCE_AT" in macro_context[0]["source"]
    assert initializer_records[0]["status"] == "FETCHED"
    assert initializer_context[0]["source"] == "static int global_hooks = 7;"
    assert initializer_context[0]["runtime_immutability_proven"] == "false"

    monkeypatch.setattr(official_harness, "OfficialPinnedQualification",
                        FakeQualification)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda candidate: candidate is q)
    provider = SequencedProvider("function_analysis", [_analysis_reply()])
    integrated = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(ScriptedProvider(
            "assertion_generator", _assertion_reply())),
        worker_id="worker", provider_free_fixture=True,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest,
        max_context_reanalyses=2))
    assert integrated["status"] == "NO_SAFE_ASSUMPTION"
    assert all(row["status"] == "FETCHED"
               for row in integrated["context_requests"])
    assert ("ADVANCE_AT", "MACRO") in {
        (row["target"], row["request_type"])
        for row in integrated["context_requests"]}
    assert [row["function_name"] for row in
            provider.requests[0].payload["context"]
            if row.get("request_type") == "FUNCTION"] == [
                "entry", "middle", "leaf", "allocator"]

    for changed in (
            {**helper_context[0], "function_id": "fn-unissued"},
            {**helper_context[0], "source": helper_context[0]["source"] +
             "\n/* changed */"}):
        denied, denied_records, _ = _bounded_context(
            work, [ContextRequest(
                requesting_function=work.function_id, target="ADVANCE_AT",
                request_type="MACRO", reason="helper dependency",
                expected_information="active macro definition")], q,
            catalog_manifest_path=manifest,
            catalog_manifest_sha256=digest,
            enforce_manifest_source_pins=True,
            prior_context=[changed], seen_requests=set(),
            attempted_requests=set())
        assert denied == []
        assert denied_records[0]["status"] == "NOT_FOUND"

    source_path.write_text(source + "/* changed */\n")
    denied, denied_records, _ = _bounded_context(
        work, [ContextRequest(
            requesting_function=work.function_id, target="ADVANCE_AT",
            request_type="MACRO", reason="helper dependency",
            expected_information="active macro definition")], q,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest,
        enforce_manifest_source_pins=True,
        prior_context=helper_context, seen_requests=set(),
        attempted_requests=set())
    assert denied == []
    assert denied_records[0]["status"] == "NOT_FOUND"


@pytest.mark.parametrize("change", ["edge", "source"])
def test_generic_initial_context_bundle_fails_closed_on_pinned_change(
        tmp_path, monkeypatch, change):
    q, work, manifest, _ = _signed_two_round_case(
        tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    static_path, _ = _pinned_static_call_path(
        work, q, manifest, digest)
    if change == "edge":
        static_path["edges"][0]["edge_id"] = "unissued-edge"
    else:
        Path(work.source_file).write_text(
            Path(work.source_file).read_text() + "/* changed */\n")

    with pytest.raises(ValueError, match="changed|differs"):
        _pinned_initial_context_plan(
            work, q, manifest, digest, static_path, None)


def test_generic_initial_context_bundle_records_bounded_source_omission(
        tmp_path, monkeypatch):
    from devtools import original_hp_preparation as preparation

    q, work, manifest, _ = _signed_two_round_case(
        tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    static_path, _ = _pinned_static_call_path(
        work, q, manifest, digest)
    monkeypatch.setattr(preparation, "_INITIAL_CONTEXT_MAX_SOURCE_CHARS", 1)

    plan, build_rows, audit = _pinned_initial_context_plan(
        work, q, manifest, digest, static_path, None)

    assert plan == []
    assert build_rows == []
    assert audit == [{
        "target": "caller", "request_type": "FUNCTION", "round": -1,
        "status": "NOT_PRELOADED_BUNDLE_LIMIT",
        "evidence_kind": "PINNED_STATIC_PATH_FUNCTION",
    }]


def test_deep_pinned_path_omission_is_explicitly_audited(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    names = ["entry", *(f"c{index}" for index in range(1, 8)), "target"]
    definitions = []
    for index, name in enumerate(names):
        body = (f"int {name}(void) {{\n  return {names[index + 1]}();\n}}\n"
                if index + 1 < len(names)
                else f"int {name}(void) {{\n  return 1;\n}}\n")
        definitions.append(body)
    source = "".join(definitions)
    source_path = root / "deep.c"
    source_path.write_text(source)
    harness = tmp_path / "fuzzer.c"
    harness.write_text("int test(void) { return entry(); }\n")
    q = FakeQualification(root, harness)
    ids = ["fn-" + format(index + 1, "x") * 20
           for index in range(len(names))]
    rows = []
    for index, (name, body) in enumerate(zip(names, definitions)):
        offset = source.index(body)
        start = source.count("\n", 0, offset) + 1
        rows.append({
            "function_id": ids[index], "name": name, "file": "deep.c",
            "start_line": start, "end_line": start + 2,
            "source": body.strip(),
        })
    functions = tmp_path / "functions.jsonl"
    functions.write_text("".join(json.dumps(row) + "\n" for row in rows))
    edges = tmp_path / "edges.jsonl"
    edges.write_text("".join(json.dumps({
        "edge_id": f"edge-{index}",
        "line": rows[index]["start_line"] + 1,
        "caller_id": ids[index], "callee_id": ids[index + 1],
        "kind": "DIRECT_AST_ID",
    }) + "\n" for index in range(len(names) - 1)))
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "catalog": {
            "functions": {"path": str(functions), "sha256": sha(functions)},
            "edges": {"path": str(edges), "sha256": sha(edges)},
        },
        "source_files": {"deep.c": sha(source_path)},
        "asan_binary": {"sha256": q.binary_sha256},
        "entry_function": "entry",
    }))
    selected = rows[-1]
    work = PreparedHPFunction(
        task_id="task", function_id=selected["function_id"],
        function_name="target", direction_id="direction",
        source_file=str(source_path), source=selected["source"],
        source_start_line=selected["start_line"],
        source_end_line=selected["end_line"],
        source_sha256=hashlib.sha256(selected["source"].encode()).hexdigest(),
        source_file_sha256=sha(source_path), harness_path=str(harness),
        harness_sha256=sha(harness), binary_sha256=q.binary_sha256,
        source_tree_sha256=q.source_tree_sha256,
        contract_sha256=q.contract_sha256, analysis_scope={},
        selection_origin="SIGNED_MANUAL_HP_CONTROL")
    digest = sha(manifest)
    static_path, _ = _pinned_static_call_path(work, q, manifest, digest)

    plan, build_rows, audit = _pinned_initial_context_plan(
        work, q, manifest, digest, static_path, None)

    assert [row["target"] for row in plan] == names[:7]
    assert build_rows == []
    assert audit == [{
        "target": "c7", "request_type": "FUNCTION", "round": -1,
        "status": "NOT_PRELOADED_BUNDLE_LIMIT",
        "evidence_kind": "PINNED_STATIC_PATH_FUNCTION",
    }]
    assert _last_unresolved_context_status(audit) == (
        "NOT_PRELOADED_BUNDLE_LIMIT")


def test_required_path_bundle_omission_is_not_counted_as_safe_zero(
        tmp_path, monkeypatch):
    from devtools import original_hp_preparation as preparation

    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    monkeypatch.setattr(preparation, "_INITIAL_CONTEXT_MAX_SOURCE_CHARS", 1)
    provider = SequencedProvider("function_analysis", [_analysis_reply()])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))

    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_reanalysis_count"] == 0
    assert result["context_requests"] == [{
        "target": "caller", "request_type": "FUNCTION", "round": -1,
        "status": "NOT_PRELOADED_BUNDLE_LIMIT",
        "evidence_kind": "PINNED_STATIC_PATH_FUNCTION",
    }]
    assert len(provider.requests) == 1 and assertion.requests == []


def test_bounded_nohint_hp_two_catalog_context_rounds_without_manual_path(
        tmp_path, monkeypatch):
    q, work, manifest, edges = _signed_two_round_case(
        tmp_path, monkeypatch, automatic=True)
    # No direct Harness-to-target edge exists. Automatic K=1 source context
    # must not inherit the stronger manual HP call-path claim.
    edges.write_text("")
    body = json.loads(manifest.read_text())
    body["catalog"]["edges"]["sha256"] = hashlib.sha256(b"").hexdigest()
    manifest.write_text(json.dumps(body))
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("second")]
    provider = SequencedProvider("function_analysis", [
        first, middle, _analysis_reply(safe=True)])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest, max_context_reanalyses=2,
        bounded_nohint_hp_context=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 2
    assert [row["status"] for row in result["context_requests"]] == [
        "FETCHED", "FETCHED"]
    assert len(provider.requests) == 3 and len(assertion.requests) == 1
    assert "static_call_path" not in result
    scope = provider.requests[0].payload["analysis_scope"]
    assert scope["runtime_reachability"] == "UNPROVEN_FOR_ANY_INPUT"
    assert scope["context_catalog_evidence"] == "PINNED_CATALOG_SOURCE_ONLY"


def test_bounded_nohint_hp_third_context_round_keeps_assertion_slot(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(
        tmp_path, monkeypatch, automatic=True)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    second = _analysis_reply()
    second["context_requests"] = [_context_request("second")]
    third = _analysis_reply()
    third["context_requests"] = [_context_request("caller")]
    gate = CampaignModelGate(tmp_path / "campaign-five.json",
                             "hp-three-rounds", 5, 60, create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [
            first, second, third, _analysis_reply(safe=True)])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    analysis = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis"))
    assertion = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:assertion_generator"))
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, worker_id="worker",
        catalog_manifest_path=manifest, catalog_manifest_sha256=digest,
        max_context_reanalyses=3, bounded_nohint_hp_context=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 3
    assert [row["status"] for row in result["context_requests"]] == [
        "FETCHED", "FETCHED", "FETCHED", "ALREADY_REQUESTED"]
    assert result["context_requests"][0]["round"] == -1
    assert result["context_requests"][0]["target"] == "caller"
    assert analysis_transport.calls == 4 and assertion_transport.calls == 1
    assert len(result["hp_model_provenance"]["function_analysis_turns"]) == 4
    assert [row["status"] for row in gate.snapshot()["records"]] == [
        "COMPLETED"] * 5
    with pytest.raises(ValueError, match="provenance is incomplete"):
        hp_live._verified_hp_provenance(
            gate, work, "worker", result, max_analysis_turns=3)
    assert hp_live._verified_hp_provenance(
        gate, work, "worker", result, max_analysis_turns=4) == (
            result["hp_model_provenance"])


def test_manual_hp_cannot_expand_to_third_context_round(tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(SequencedProvider(
            "function_analysis", [_analysis_reply()])),
        assertion_pipeline=AgentPipeline(ScriptedProvider(
            "assertion_generator", _assertion_reply())),
        worker_id="worker", provider_free_fixture=True,
        catalog_manifest_path=manifest, catalog_manifest_sha256=digest,
        max_context_reanalyses=3))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "HP_CONTEXT_ROUND_CONTRACT_INVALID"

    admitted = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(SequencedProvider(
            "function_analysis", [_analysis_reply()])),
        assertion_pipeline=AgentPipeline(ScriptedProvider(
            "assertion_generator", _assertion_reply())),
        worker_id="worker", provider_free_fixture=True,
        catalog_manifest_path=manifest, catalog_manifest_sha256=digest,
        max_context_reanalyses=3,
        signed_manual_third_context_round=True))
    assert admitted["status"] == "NO_SAFE_ASSUMPTION"


def test_signed_manual_hp_third_context_round_preserves_assertion_slot(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    second = _analysis_reply()
    second["context_requests"] = [_context_request("second")]
    third = _analysis_reply()
    third["context_requests"] = [_context_request("caller")]
    analysis = SequencedProvider(
        "function_analysis", [first, second, third,
                              _analysis_reply(safe=True)])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest, max_context_reanalyses=3,
        signed_manual_third_context_round=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 3
    assert len(analysis.requests) == 4
    assert len(assertion.requests) == 1


def test_bounded_nohint_hp_supplies_only_pinned_static_path(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(
        tmp_path, monkeypatch, automatic=True)
    provider = SequencedProvider("function_analysis", [_analysis_reply()])
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(ScriptedProvider(
            "assertion_generator", _assertion_reply())),
        worker_id="worker", provider_free_fixture=True,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2, bounded_nohint_hp_context=True))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    path = provider.requests[0].payload["analysis_scope"]["static_call_path"]
    assert path["evidence_level"] == "PINNED_STATIC_DIRECT_CALL_PATH_ONLY"
    assert path["runtime_reachability"] == "UNPROVEN_FOR_ANY_INPUT"
    assert [(edge["caller"], edge["callee"]) for edge in path["edges"]] == [
        ("caller", "parse_input")]
    assert result["static_call_path"] == path


def test_bounded_nohint_hp_macro_callsite_keeps_catalog_without_path_claim(
        tmp_path, monkeypatch):
    q, work, manifest, edges = _signed_two_round_case(
        tmp_path, monkeypatch, automatic=True)
    source = Path(work.source_file)
    source.write_text(source.read_text().replace(
        "int caller(const char *p) {\n  return parse_input(p);",
        "#define CALL_PARSE(p) parse_input(p)\n"
        "int caller(const char *p) {\n  return CALL_PARSE(p);"))
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    work = replace(work, source_file_sha256=digest)
    rows = [json.loads(line) for line in
            (tmp_path / "functions.jsonl").read_text().splitlines()]
    caller = next(row for row in rows if row["name"] == "caller")
    caller["start_line"] += 1
    caller["end_line"] += 1
    caller["source"] = caller["source"].replace(
        "parse_input(p);", "CALL_PARSE(p);")
    functions = tmp_path / "functions.jsonl"
    functions.write_text("".join(json.dumps(row) + "\n" for row in rows))
    edge = json.loads(edges.read_text())
    edge["line"] += 1
    edges.write_text(json.dumps(edge) + "\n")
    body = json.loads(manifest.read_text())
    body["source_files"]["parser.c"] = digest
    body["catalog"]["functions"]["sha256"] = hashlib.sha256(
        functions.read_bytes()).hexdigest()
    body["catalog"]["edges"]["sha256"] = hashlib.sha256(
        edges.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(body))
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    provider = SequencedProvider("function_analysis", [_analysis_reply()])
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(ScriptedProvider(
            "assertion_generator", _assertion_reply())),
        worker_id="worker", provider_free_fixture=True,
        catalog_manifest_path=manifest, catalog_manifest_sha256=manifest_sha,
        max_context_reanalyses=2, bounded_nohint_hp_context=True))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    scope = provider.requests[0].payload["analysis_scope"]
    assert scope["static_call_path_status"] == "SOURCE_CALLSITE_UNPROVEN"
    assert "static_call_path" not in scope
    assert scope["runtime_reachability"] == "UNPROVEN_FOR_ANY_INPUT"


def test_bounded_nohint_hp_requires_mode_and_manifest_pin_before_model(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(
        tmp_path, monkeypatch, automatic=True)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    for mode, sha, reason in ((False, digest,
                               "HP_CONTEXT_ROUND_CONTRACT_INVALID"),
                              (True, "0" * 64,
                               "PINNED_CONTEXT_CATALOG_UNAVAILABLE")):
        provider = SequencedProvider("function_analysis", [])
        row = asyncio.run(run_prepared_hp_analysis(
            work=work, qualification=q,
            analysis_pipeline=AgentPipeline(provider),
            assertion_pipeline=AgentPipeline(ScriptedProvider(
                "assertion_generator", _assertion_reply())),
            worker_id="worker", provider_free_fixture=True,
            catalog_manifest_path=manifest, catalog_manifest_sha256=sha,
            max_context_reanalyses=2,
            bounded_nohint_hp_context=mode))
        assert row["reason"] == reason
        assert provider.requests == []


def test_bounded_nohint_hp_rejects_unpinned_related_context_before_reanalysis(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(
        tmp_path, monkeypatch, automatic=True)
    body = json.loads(manifest.read_text())
    functions = Path(body["catalog"]["functions"]["path"])
    rows = [json.loads(line) for line in functions.read_text().splitlines()]
    helper = tmp_path / "repo" / "helper.c"
    helper.write_text("int helper(const char *p) {\n  return second(p);\n}\n")
    rows[1]["file"] = "helper.c"
    rows[1]["start_line"] = 1
    rows[1]["end_line"] = 3
    functions.write_text("".join(json.dumps(row) + "\n" for row in rows))
    body["catalog"]["functions"]["sha256"] = hashlib.sha256(
        functions.read_bytes()).hexdigest()
    body["source_files"]["helper.c"] = "0" * 64
    manifest.write_text(json.dumps(body))
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    provider = SequencedProvider("function_analysis", [first])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2, bounded_nohint_hp_context=True))
    assert result["status"] == "INCOMPLETE_HP_ERROR"
    assert result["error_type"] == "ValueError"
    assert len(provider.requests) == 1 and assertion.requests == []


def test_signed_hp_second_context_round_uses_two_pinned_sources_and_assertion(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("second")]
    provider = SequencedProvider("function_analysis", [
        first, middle, _analysis_reply(safe=True)])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 2
    assert [row["status"] for row in result["context_requests"]] == [
        "FETCHED", "FETCHED", "FETCHED"]
    assert result["context_requests"][0]["round"] == -1
    assert result["context_requests"][0]["target"] == "caller"
    assert len(provider.requests) == 3 and len(assertion.requests) == 1
    assert [row["function_name"] for row in
            provider.requests[0].payload["context"]] == ["caller"]
    assert [row["function_name"] for row in
            assertion.requests[0].payload["context"]] == [
                "caller", "helper", "second"]


def test_signed_hp_context_round_limit_is_not_counted_as_safe_zero(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("second")]
    final = _analysis_reply()
    final["context_requests"] = [_context_request("caller")]
    provider = SequencedProvider("function_analysis", [first, middle, final])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_ROUND_LIMIT"
    assert result["safe_selection_observation"]["retained_safe_count"] == 0
    assert result["context_reanalysis_count"] == 2
    assert result["context_requests"][-1] == {
        "target": "caller", "request_type": "FUNCTION",
        "request_reason": "inspect input flow",
        "expected_information": "read bounds", "round": 2,
        "status": "SKIPPED_CONTEXT_ROUND_LIMIT"}
    assert len(provider.requests) == 3 and assertion.requests == []


def test_per_assumption_closure_enters_assertion_for_unrelated_context_stop(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["hypothesis_evaluations"] = [{
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return helper(p);",
        "security_property": "callee input bounds",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "helper may dereference the input",
        "judgment": "UNKNOWN", "reason": "helper body is required",
        "safe_assumption": "",
    }]
    first["context_requests"] = [
        _attributed_context_request("helper", 0)]
    final = _independent_safe_with_context_request(hypothesis_index=1)
    provider = SequencedProvider("function_analysis", [first, final])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=ProductAgentPipeline(provider),
        assertion_pipeline=ProductAgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=1,
        per_assumption_evidence_closure=True))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED", (
        result.get("error_type"), result.get("error"), result)
    assert result["candidate_context_closure"][
        "unresolved_context_count"] == 1
    assert len(result["candidate_context_closure"][
        "eligible_assumption_ids"]) == 1
    assert result["candidate_context_closure"][
        "blocked_assumption_ids"] == {}
    assert result["context_requests"][-1]["attribution_verified"] is True
    assert result["context_requests"][-1][
        "related_security_property"] == "semantic output integrity"
    assert len(provider.requests) == 2 and len(assertion.requests) == 1


def test_per_assumption_closure_blocks_safe_related_context_stop(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["hypothesis_evaluations"] = [{
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return helper(p);",
        "security_property": "callee input bounds",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "helper may dereference the input",
        "judgment": "UNKNOWN", "reason": "helper body is required",
        "safe_assumption": "",
    }]
    first["context_requests"] = [
        _attributed_context_request("helper", 0)]
    final = _independent_safe_with_context_request(hypothesis_index=0)
    provider = SequencedProvider("function_analysis", [first, final])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=ProductAgentPipeline(provider),
        assertion_pipeline=ProductAgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=1,
        per_assumption_evidence_closure=True))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT", (
        result.get("error_type"), result.get("error"), result)
    assert result["reason"] == "CONTEXT_ROUND_LIMIT"
    assert result["candidate_context_closure"][
        "eligible_assumption_ids"] == []
    assert len(result["candidate_context_closure"][
        "blocked_assumption_ids"]) == 1
    assert len(provider.requests) == 2 and assertion.requests == []


def test_per_assumption_closure_rejects_duplicate_safe_text_before_assertion(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["hypothesis_evaluations"] = [{
        "source_location": "parser.c:2", "source_file": "parser.c",
        "source_line": 2, "source_quote": "return helper(p);",
        "security_property": "callee input bounds",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "helper may dereference the input",
        "judgment": "UNKNOWN", "reason": "helper body is required",
        "safe_assumption": "",
    }]
    first["context_requests"] = [_attributed_context_request("helper", 0)]

    final = _independent_safe_with_context_request(hypothesis_index=2)
    duplicate = dict(final["hypothesis_evaluations"][0])
    duplicate.update({
        "source_location": "parser.c:1", "source_line": 1,
        "source_quote": "int parse_input(const char *p) {",
        "security_property": "entry pointer validity",
    })
    final["hypothesis_evaluations"].insert(1, duplicate)
    final["safe_assumption_lifecycle"].append(_lifecycle_row(
        "VALIDATED_SAFE", location="parser.c:1",
        security_property="entry pointer validity"))

    provider = SequencedProvider("function_analysis", [first, final])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=ProductAgentPipeline(provider),
        assertion_pipeline=ProductAgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=1,
        per_assumption_evidence_closure=True))
    assert result["status"] == "INCOMPLETE_HP_ASSUMPTION_EVIDENCE"
    assert assertion.requests == []
    assert len(result["unresolved_assumption_ids"]) == 2


def test_signed_hp_preloaded_context_repeat_gets_bounded_reanalysis(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("caller")]
    provider = SequencedProvider("function_analysis", [
        first, _analysis_reply()])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert result["context_reanalysis_count"] == 1
    assert [(row["target"], row["status"]) for row in
            result["context_requests"]] == [
                ("caller", "FETCHED"),
                ("caller", "ALREADY_REQUESTED")]
    assert len(provider.requests) == 2 and assertion.requests == []
    assert [row["function_name"] for row in
            provider.requests[1].payload["context"]] == ["caller"]


def test_signed_hp_failed_preload_repeat_is_unresolved_not_safe_zero(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.context import ContextResolver

    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    original = ContextResolver.resolve
    calls = 0

    def fail_only_preload(self, request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return []
        return original(self, request)

    monkeypatch.setattr(ContextResolver, "resolve", fail_only_preload)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("caller")]
    provider = SequencedProvider("function_analysis", [first])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_reanalysis_count"] == 0
    assert [(row["target"], row["status"]) for row in
            result["context_requests"]] == [
                ("caller", "NOT_FOUND"),
                ("caller", "PREVIOUSLY_UNRESOLVED")]
    assert calls == 1
    assert len(provider.requests) == 1 and assertion.requests == []


def test_signed_hp_failed_preload_without_followup_is_not_safe_zero(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.context import ContextResolver

    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    calls = 0

    def fail_preload(self, request):
        nonlocal calls
        calls += 1
        return []

    monkeypatch.setattr(ContextResolver, "resolve", fail_preload)
    provider = SequencedProvider("function_analysis", [_analysis_reply()])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_reanalysis_count"] == 0
    assert [(row["target"], row["status"]) for row in
            result["context_requests"]] == [("caller", "NOT_FOUND")]
    assert calls == 1
    assert len(provider.requests) == 1 and assertion.requests == []


def test_signed_hp_prior_unresolved_context_survives_final_empty_request(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [
        _context_request("helper"), _context_request("missing_context")]
    provider = SequencedProvider("function_analysis", [
        first, _analysis_reply()])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())

    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(
            manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))

    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_reanalysis_count"] == 1
    assert [(row["target"], row["status"]) for row in
            result["context_requests"]] == [
                ("caller", "FETCHED"),
                ("helper", "FETCHED"),
                ("missing_context", "NOT_FOUND"),
            ]
    assert len(provider.requests) == 2 and assertion.requests == []


def test_signed_hp_second_round_duplicate_and_pin_change_fail_closed(
        tmp_path, monkeypatch):
    q, work, manifest, edges = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("helper")]
    provider = SequencedProvider("function_analysis", [
        first, middle, _analysis_reply()])
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(provider),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest, max_context_reanalyses=2))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert result["context_reanalysis_count"] == 2
    assert [row["status"] for row in result["context_requests"]] == [
        "FETCHED", "FETCHED", "ALREADY_REQUESTED"]
    assert len(provider.requests) == 3 and assertion.requests == []
    edges.write_text(edges.read_text() + "\n")
    denied = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(ScriptedProvider(
            "function_analysis", first)),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest, max_context_reanalyses=2))
    assert denied["reason"] == "PINNED_STATIC_CALL_PATH_UNAVAILABLE"


def test_signed_hp_live_ledger_caps_two_context_rounds_and_reserves_assertion(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("second")]
    gate = CampaignModelGate(tmp_path / "campaign-four.json",
                             "hp-two-rounds", 4, 60, create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [first, middle,
                                        _analysis_reply(safe=True)])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    analysis = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis",
        owner_id="hp-function"))
    assertion = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id="hp-assertion"))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, worker_id="worker",
        catalog_manifest_path=manifest, catalog_manifest_sha256=digest,
        max_context_reanalyses=2))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 2
    assert [row["status"] for row in gate.snapshot()["records"]] == [
        "COMPLETED"] * 4
    assert analysis_transport.calls == 3 and assertion_transport.calls == 1
    assert len({row["request_id"] for row in result["hp_model_provenance"][
        "function_analysis_turns"]}) == 3


def _signed_three_analysis_provenance(tmp_path, monkeypatch):
    """Three real ledgered analysis receipts plus one Assertion receipt."""
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    second = _analysis_reply()
    second["context_requests"] = [_context_request("second")]
    gate = CampaignModelGate(tmp_path / "three-analysis-gate.json",
                             "hp-three-analysis", 5, 60, create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis",
        [first, second, _analysis_reply(safe=True)])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    analysis = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis"))
    assertion = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:assertion_generator"))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, worker_id="worker",
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        max_context_reanalyses=2))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 2
    assert [receipt["role"] for receipt in gate.snapshot()["records"]] == [
        "function_analysis", "function_analysis", "function_analysis",
        "assertion_generator"]
    assert all(gate.verify_response_evidence(turn["request_id"])["status"] ==
               "VERIFIED" for turn in [
                   *result["hp_model_provenance"]["function_analysis_turns"],
                   result["hp_model_provenance"]["assertion_generator_turn"]])
    return gate, work, result, analysis_transport


def test_signed_manual_hp_three_analysis_receipts_are_verified_only_at_cap_three(
        tmp_path, monkeypatch):
    gate, work, result, _ = _signed_three_analysis_provenance(
        tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="provenance is incomplete"):
        hp_live._verified_hp_provenance(gate, work, "worker", result,
                                        max_analysis_turns=2)
    assert hp_live._verified_hp_provenance(
        gate, work, "worker", result, max_analysis_turns=3) == (
            result["hp_model_provenance"])


@pytest.mark.parametrize("change", ["duplicate", "sha", "cross_role",
                                    "different_final_safe", "fourth_turn"])
def test_signed_manual_hp_three_analysis_receipts_reject_false_provenance(
        tmp_path, monkeypatch, change):
    gate, work, result, transport = _signed_three_analysis_provenance(
        tmp_path, monkeypatch)
    provenance = result["hp_model_provenance"]
    turns = provenance["function_analysis_turns"]
    if change == "duplicate":
        turns[2] = dict(turns[0])
    elif change == "sha":
        turns[2]["response_sha256"] = "0" * 64
    elif change == "cross_role":
        turns[2] = dict(provenance["assertion_generator_turn"])
    else:
        transport.responses.append(_analysis_reply(safe=change == "fourth_turn"))
        provider = CampaignLedgeredProvider(
            transport, gate, role="function_analysis",
            owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis")
        pipeline = AgentPipeline(provider)
        asyncio.run(pipeline.analyze_function(
            work.function_id, work.function_name, work.source_file,
            work.source))
        evidence = gate.verify_response_evidence(provider.last_request_id)
        assert evidence["status"] == "VERIFIED"
        turn = {"role": "function_analysis", "owner_id": provider.owner_id,
                "request_id": provider.last_request_id,
                "response_sha256": evidence["response_sha256"],
                "thread_id": evidence["thread_id"],
                "turn_id": evidence["turn_id"]}
        if change == "different_final_safe":
            turns[2] = turn
        else:
            turns.append(turn)
    with pytest.raises(ValueError, match="provenance|response|SAFE|Assertion"):
        hp_live._verified_hp_provenance(
            gate, work, "worker", result, max_analysis_turns=3)


def test_signed_hp_second_round_skips_when_assertion_slot_would_be_spent(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("second")]
    gate = CampaignModelGate(tmp_path / "campaign-three.json",
                             "hp-low-budget", 3, 60, create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [first, middle])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(CampaignLedgeredProvider(
            analysis_transport, gate, role="function_analysis",
            owner_id="hp-function")),
        assertion_pipeline=AgentPipeline(CampaignLedgeredProvider(
            assertion_transport, gate, role="assertion_generator",
            owner_id="hp-assertion")), worker_id="worker",
        catalog_manifest_path=manifest, catalog_manifest_sha256=digest,
        max_context_reanalyses=2))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "MODEL_CALL_BUDGET_RESERVED"
    assert [row["status"] for row in result["context_requests"]] == [
        "FETCHED", "FETCHED", "SKIPPED_LLM_BUDGET"]
    assert analysis_transport.calls == 2 and assertion_transport.calls == 0


def test_signed_hp_context_reanalysis_with_no_shared_call_count_cap(
        tmp_path, monkeypatch):
    q, work, manifest, _ = _signed_two_round_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    gate = CampaignModelGate(tmp_path / "campaign-no-call-cap.json",
                             "hp-no-call-cap", None, 60, create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [first, _analysis_reply(safe=True)])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(CampaignLedgeredProvider(
            analysis_transport, gate, role="function_analysis",
            owner_id="hp-function")),
        assertion_pipeline=AgentPipeline(CampaignLedgeredProvider(
            assertion_transport, gate, role="assertion_generator",
            owner_id="hp-assertion")), worker_id="worker",
        catalog_manifest_path=manifest, catalog_manifest_sha256=digest,
        max_context_reanalyses=2))
    assert result["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["context_reanalysis_count"] == 1
    assert result["context_requests"]
    assert all(row["status"] == "FETCHED" for row in result["context_requests"])
    assert gate.snapshot()["physical"] == 3


def test_signed_hp_second_round_pin_change_after_model_turn_blocks_assertion(
        tmp_path, monkeypatch):
    q, work, manifest, edges = _signed_two_round_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    first = _analysis_reply()
    first["context_requests"] = [_context_request("helper")]
    middle = _analysis_reply()
    middle["context_requests"] = [_context_request("second")]
    turns = 0

    def change_after_second_turn():
        nonlocal turns
        turns += 1
        if turns == 2:
            edges.write_text(edges.read_text() + "\n")

    analysis = SequencedProvider("function_analysis", [first, middle],
                                 on_generate=change_after_second_turn)
    assertion = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis),
        assertion_pipeline=AgentPipeline(assertion), worker_id="worker",
        provider_free_fixture=True, catalog_manifest_path=manifest,
        catalog_manifest_sha256=digest, max_context_reanalyses=2))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"
    assert len(analysis.requests) == 2 and assertion.requests == []


def test_hp_duplicate_missing_and_over_limit_context_are_incomplete(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    request = {"target": "missing_helper", "request_type": "FUNCTION",
               "reason": "possible call", "expected_information": "definition"}
    initial = _analysis_reply()
    initial["context_requests"] = [request, dict(request),
                                    {**request, "target": "third"}]
    analysis_provider = ScriptedProvider("function_analysis", initial)
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_PER_TURN_LIMIT"
    assert [row["status"] for row in result["context_requests"]] == [
        "NOT_FOUND", "PREVIOUSLY_UNRESOLVED", "SKIPPED_PER_TURN_LIMIT"]
    assert result["context_request_count"] == 3
    assert result["context_provided_count"] == 0
    assert result["context_reanalysis_count"] == 0
    assert len(analysis_provider.requests) == 1
    assert assertion_provider.requests == []


def test_hp_context_outside_source_root_is_not_delivered(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.context import ContextResolver

    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    outside = tmp_path / "foreign.c"
    outside.write_text("int foreign(void) { return 0; }\n")
    monkeypatch.setattr(ContextResolver, "resolve", lambda _self, _request: [{
        "target": "foreign", "source_file": str(outside),
        "source_location": f"{outside}:1",
        "source": outside.read_text(),
    }])
    initial = _analysis_reply()
    initial["context_requests"] = [{
        "target": "foreign", "request_type": "FUNCTION",
        "reason": "candidate", "expected_information": "definition"}]
    analysis_provider = ScriptedProvider("function_analysis", initial)
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_requests"][0]["status"] == (
        "OUTSIDE_QUALIFIED_SOURCE_ROOT")
    assert len(analysis_provider.requests) == 1
    assert assertion_provider.requests == []


def test_hp_context_change_during_reanalysis_cannot_be_no_safe(
        tmp_path, monkeypatch):
    source = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    q, func, direction, _ = _case(tmp_path, monkeypatch, source=source)
    helper = q.source_root / "helper.c"
    helper.write_text("int helper(const char *p) {\n  return *p;\n}\n")
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    initial = _analysis_reply()
    initial["context_requests"] = [{
        "target": "helper", "request_type": "FUNCTION",
        "reason": "input reaches helper", "expected_information": "read bounds"}]
    seen = []

    def mutate_on_second():
        seen.append(True)
        if len(seen) == 2:
            helper.write_text("int helper(const char *p) {\n  return p[1];\n}\n")

    analysis_provider = SequencedProvider(
        "function_analysis", [initial, _analysis_reply()], mutate_on_second)
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"
    assert result["context_reanalysis_count"] == 1
    assert len(analysis_provider.requests) == 2
    assert assertion_provider.requests == []


def test_hp_initial_safe_zero_source_change_is_incomplete(
        tmp_path, monkeypatch):
    q, func, direction, path = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    analysis_provider = ScriptedProvider(
        "function_analysis", _analysis_reply(),
        on_generate=lambda: path.write_text(path.read_text() + "// changed\n"))
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"
    assert len(analysis_provider.requests) == 1
    assert assertion_provider.requests == []


def test_hp_assertion_turn_source_change_cannot_report_proposed(
        tmp_path, monkeypatch):
    source = "int parse_input(const char *p) {\n  return helper(p);\n}\n"
    q, func, direction, _ = _case(tmp_path, monkeypatch, source=source)
    helper = q.source_root / "helper.c"
    helper.write_text("int helper(const char *p) {\n  return *p;\n}\n")
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    initial = _analysis_reply()
    initial["context_requests"] = [{
        "target": "helper", "request_type": "FUNCTION",
        "reason": "input reaches helper", "expected_information": "read bounds"}]
    analysis_provider = SequencedProvider(
        "function_analysis", [initial, _analysis_reply(safe=True)])
    assertion_provider = ScriptedProvider(
        "assertion_generator", _assertion_reply(),
        on_generate=lambda: helper.write_text(
            "int helper(const char *p) {\n  return p[1];\n}\n"))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"
    assert result["context_reanalysis_count"] == 1
    assert len(assertion_provider.requests) == 1
    assert result["security_gate_credit"] == "NOT_CREDITED"


def test_hp_composite_context_is_explicitly_unsupported(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.context import ContextResolver

    q, func, direction, path = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    monkeypatch.setattr(ContextResolver, "resolve", lambda _self, _request: [{
        "target": "parse_input", "source_file": str(path),
        "source_location": f"{path}:1",
        "source": "int parse_input /* SOURCE TRUNCATED */",
        "callsite_excerpt": f"{path}:2: return *p;",
    }])
    initial = _analysis_reply()
    initial["context_requests"] = [{
        "target": "parse_input", "request_type": "FUNCTION",
        "reason": "late call", "expected_information": "callsite"}]
    analysis_provider = ScriptedProvider("function_analysis", initial)
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "CONTEXT_EVIDENCE_UNAVAILABLE"
    assert result["context_requests"][0]["status"] == (
        "UNSUPPORTED_COMPOSITE_CONTEXT")
    assert result["context_reanalysis_count"] == 0
    assert len(analysis_provider.requests) == 1


def test_hp_missing_context_location_uses_unique_source_excerpt(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.context import ContextResolver

    q, func, direction, path = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    monkeypatch.setattr(ContextResolver, "resolve", lambda _self, _request: [{
        "target": "parse_input", "source_file": str(path),
        "source": "return *p;",
    }])
    initial = _analysis_reply()
    initial["context_requests"] = [{
        "target": "parse_input", "request_type": "FUNCTION",
        "reason": "read", "expected_information": "source"}]
    analysis_provider = SequencedProvider(
        "function_analysis", [initial, _analysis_reply()])
    assertion_provider = ScriptedProvider("assertion_generator", _assertion_reply())
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q,
        analysis_pipeline=AgentPipeline(analysis_provider),
        assertion_pipeline=AgentPipeline(assertion_provider),
        worker_id="worker", provider_free_fixture=True))
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert result["context_requests"][0]["status"] == "FETCHED"
    assert result["context_reanalysis_count"] == 1
    assert analysis_provider.requests[1].payload["context"][0][
        "source_location"] == f"{path}:2"


def test_hp_source_change_blocks_before_or_between_role_calls(tmp_path, monkeypatch):
    q, func, direction, path = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, first_provider, second_provider = _pipelines(
        _analysis_reply(safe=True))
    path.write_text(path.read_text() + "// changed\n")
    blocked = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert blocked["status"] == "HP_UNSUPPORTED"
    assert first_provider.requests == second_provider.requests == []

    path.write_text(func.content)
    first, second, first_provider, second_provider = _pipelines(
        _analysis_reply(safe=True), analysis_callback=lambda: path.write_text(
            path.read_text() + "// changed after first model turn\n"))
    blocked_after = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert blocked_after["status"] == "HP_UNSUPPORTED"
    assert len(first_provider.requests) == 1
    assert second_provider.requests == []


def test_hp_rejects_harness_bytes_read_different_from_pin(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, first_provider, second_provider = _pipelines(
        _analysis_reply(safe=True))
    original_read_text = Path.read_text

    def changed_read(path, *args, **kwargs):
        if path == q.harness:
            return "changed after pin check"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", changed_read)
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "HP_UNSUPPORTED"
    assert result["reason"] == "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"
    assert first_provider.requests == second_provider.requests == []


def test_hp_provider_error_is_local_incomplete(tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first, second, first_provider, second_provider = _pipelines(
        RuntimeError("synthetic refusal"))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker",
        provider_free_fixture=True))
    assert result["status"] == "INCOMPLETE_HP_ERROR"
    assert result["error_type"] == "RuntimeError"
    assert result["sp_global_effect"] == "UNCHANGED"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert len(first_provider.requests) == 1
    assert second_provider.requests == []


class ScriptedReceiptTransport:
    """Local output and completed-turn events in the product provider shape."""

    def __init__(self, root, role, responses):
        self.event_log_path = root / f"{role}.jsonl"
        self.responses = list(responses)
        self.calls = 0

    async def generate(self, request):
        assert request.raw_response_path is not None
        assert request.role == self.event_log_path.stem
        self.calls += 1
        response = self.responses.pop(0)
        raw = json.dumps(response, sort_keys=True).encode()
        descriptor = os.open(request.raw_response_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        thread, turn = (f"thread-{request.role}-{self.calls}",
                        f"turn-{request.role}-{self.calls}")
        events = [
            {"method": "turn/started", "thread_id": thread, "turn_id": turn},
            {"method": "item/completed", "thread_id": thread,
             "turn_id": turn, "item_type": "agentMessage",
             "agent_message_sha256": hashlib.sha256(raw).hexdigest()},
            {"method": "turn/completed", "thread_id": thread,
             "turn_id": turn, "turn_status": "completed"},
        ]
        descriptor = os.open(self.event_log_path,
                             os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            for event in events:
                stream.write((json.dumps(event, sort_keys=True) + "\n").encode())
        return response

    async def close(self):
        pass


def test_parallel_hp_analysis_runner_uses_pinned_selection_and_shared_gate(
        tmp_path, monkeypatch):
    from devtools import original_hp_live_optin as hp_optin

    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    q.harness.write_text(
        'int LLVMFuzzerTestOneInput() {return parse_input("x");}\n')
    q.harness_sha256 = hashlib.sha256(q.harness.read_bytes()).hexdigest()
    run_dir = tmp_path / "parallel-runner"
    run_dir.mkdir(mode=0o700)
    plan_path = tmp_path / "direction-plan.json"
    plan_path.write_text(json.dumps({
        "kind": "FBV2_DEV_DIRECTION_PLAN_V1",
        "status": "COMPLETED", "task_id": func.task_id,
        "fuzzer": direction.fuzzer,
        "direction_ids": [direction.direction_id],
        "direction_count": 1,
    }))
    plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    manifest = tmp_path / "catalog.json"
    functions = tmp_path / "parallel-functions.jsonl"
    functions.write_text(json.dumps({
        "function_id": "fn-" + "a" * 20,
        "name": func.name, "file": func.file_path,
        "start_line": func.start_line, "end_line": func.end_line,
        "source": func.content.strip(),
    }) + "\n")
    edges = tmp_path / "parallel-edges.jsonl"
    edges.write_text("")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({
        "catalog": {
            "functions": {"path": str(functions), "sha256": digest(functions)},
            "edges": {"path": str(edges), "sha256": digest(edges)}},
        "source_files": {func.file_path: digest(q.source_root / func.file_path)},
        "asan_binary": {"sha256": q.binary_sha256},
        "entry_function": func.name,
    }))
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    hp = {"enabled": True, "max_items": 1, "max_model_calls": 3,
          "assets": hp_optin.hp_asset_hashes(PRODUCT_SRC)}
    run_id = "c" * 24
    spec_path = tmp_path / "parallel-spec.json"
    spec_path.write_text(json.dumps({
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1",
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "identity": {"task_id": func.task_id, "run_id": run_id},
        "hp": hp,
    }))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    gate = CampaignModelGate(tmp_path / "parallel-runner-gate.json",
                             "parallel-runner", 3, 60, create=True)
    sp_entered = asyncio.Event()
    hp_entered = asyncio.Event()
    physical_entered = asyncio.Event()
    owner_loop = {}
    overlap = []

    class HeldSP(ScriptedReceiptTransport):
        async def generate(self, request):
            sp_entered.set()
            await asyncio.wait_for(hp_entered.wait(), timeout=2)
            await asyncio.wait_for(physical_entered.wait(), timeout=2)
            return await super().generate(request)

    class HeldHP(ScriptedReceiptTransport):
        async def generate(self, request):
            hp_entered.set()
            await asyncio.wait_for(sp_entered.wait(), timeout=2)
            overlap.append({row["role"]: row["status"]
                            for row in gate.snapshot()["records"]})
            return await super().generate(request)

    transports = {
        "function_analysis": HeldHP(
            tmp_path, "function_analysis", [_analysis_reply(safe=True)]),
        "assertion_generator": ScriptedReceiptTransport(
            tmp_path, "assertion_generator", [_assertion_reply()]),
    }
    sp_transport = HeldSP(tmp_path, "sp", [{"fixture": "sp"}])
    sp_provider = CampaignLedgeredProvider(
        sp_transport, gate, role="sp", owner_id="sp:direction")

    def fake_pipeline_factory(_bound, _hp, role, _path, _sha,
                              extra_check=None):
        def build(work):
            assert extra_check is not None
            extra_check()
            return AgentPipeline(CampaignLedgeredProvider(
                transports[role], gate, role=role,
                owner_id=f"hp:{work.function_id}:{work.direction_id}:{role}"))
        return build

    monkeypatch.setattr(hp_optin, "_pipeline_factory", fake_pipeline_factory)
    hp["physical"] = {"scripted_parallel_physical": True}
    spec_path.write_text(json.dumps({
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1",
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "identity": {"task_id": func.task_id, "run_id": run_id},
        "hp": hp,
    }))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    monkeypatch.setattr(hp_optin, "validate_hp_spec",
                        lambda *_args, **_kwargs: None)
    physical_calls = []

    def fake_physical_factory(_bound, _hp, worker_receipt, _path, _sha,
                              *, actor_id, extra_check,
                              parallel_hp_execution):
        assert worker_receipt is None and parallel_hp_execution is True
        assert actor_id == "parallel-worker"

        def handoff(work, row):
            extra_check()
            physical_calls.append((work.function_id, row["status"]))
            owner_loop["loop"].call_soon_threadsafe(physical_entered.set)
            return {"status": "HP_ASSERTION_HANDOFF_COMPLETE",
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED"}

        return handoff

    monkeypatch.setattr(hp_optin, "_physical_handoff_factory",
                        fake_physical_factory)
    executor = SimpleNamespace(fuzzer=direction.fuzzer,
                               _worker_context=SimpleNamespace(
                                   worker_id="parallel-worker"))
    strategy = object.__new__(POVFullscanStrategy)
    strategy.executor = executor
    strategy._development_direction_plan = (plan_path, plan_sha)
    strategy.llm_client_factory = object()
    strategy.log_info = lambda _message: None
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id=func.task_id, run_id=run_id,
                                 run_dir=run_dir, product_src=PRODUCT_SRC),
        admission=SimpleNamespace(qualification=q, summary={
            "manifest_path": str(manifest),
            "manifest_sha256": manifest_sha}),
        caps=SimpleNamespace(sp_concurrent_queue=True),
        server=SimpleNamespace(repos=SimpleNamespace(
            functions=SimpleNamespace(find_by_task=lambda _task: [func]))),
        executor=executor, strategy=strategy, model_gate=gate,
        recheck=lambda: None)

    async def planning():
        owner_loop["loop"] = asyncio.get_running_loop()
        return [direction]

    async def sp_pipeline(_directions):
        return await sp_provider.generate(LLMRequest(
            role="sp", instructions="fixture", payload={"x": 1},
            output_schema={"type": "object"}, model="fixture", effort="low"))

    async def hp_factory(current_strategy, directions):
        return await run_parallel_hp_analysis(
            bound, current_strategy, directions, hp=hp,
            spec_path=spec_path, spec_sha256=spec_sha)

    executor.parallel_hp_async_factory = hp_factory
    strategy._run_direction_planning_async = planning
    strategy._run_v2_pipeline_with_fuzzer_init = sp_pipeline
    assert asyncio.run(strategy._run_full_pipeline()) == {"fixture": "sp"}
    result = strategy._parallel_hp_result
    assert result["status"] == "HP_PARALLEL_ANALYSIS_COMPLETE"
    assert result["analysis"]["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert overlap == [{"sp": "STARTED", "function_analysis": "STARTED"}]
    assert len(result["model_request_ids"]) == 2
    assert result["physical_status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert physical_calls == [(func.function_id,
                               "ASSERTIONS_PROPOSED_UNVERIFIED")]
    physical_path = Path(result["physical_result_path"])
    assert physical_path.is_file()
    assert hashlib.sha256(physical_path.read_bytes()).hexdigest() == (
        result["physical_result_sha256"])
    diagnostic = reprove_parallel_hp_diagnostic(
        run_dir, task_id=func.task_id, run_id=run_id, result=result)
    assert diagnostic["physical_status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert diagnostic["security_gate_credit"] == "NOT_CREDITED"
    with pytest.raises(ValueError, match="identity"):
        reprove_parallel_hp_diagnostic(
            run_dir, task_id=func.task_id, run_id="f" * 24, result=result)
    forged = {**result, "physical_status": "HP_GATE_VERIFIED"}
    with pytest.raises(ValueError, match="physical receipt changed"):
        reprove_parallel_hp_diagnostic(
            run_dir, task_id=func.task_id, run_id=run_id, result=forged)
    assert gate.snapshot()["physical"] == 3
    assert Path(result["result_path"]).is_file()
    assert hashlib.sha256(Path(result["result_path"]).read_bytes()).hexdigest() == (
        result["result_sha256"])

    # A DB Function with a matching name is insufficient if the issued
    # catalog no longer contains that exact source span. The fresh run must
    # settle without sending another HP model request.
    previous_calls = {name: transport.calls for name, transport in
                      transports.items()}
    functions.write_text("")
    manifest_body = json.loads(manifest.read_text())
    manifest_body["catalog"]["functions"]["sha256"] = digest(functions)
    manifest.write_text(json.dumps(manifest_body))
    bound.admission.summary["manifest_sha256"] = digest(manifest)
    second_run_dir = tmp_path / "parallel-runner-missing-function"
    second_run_dir.mkdir(mode=0o700)
    bound.identity.run_dir = second_run_dir
    missing = asyncio.run(run_parallel_hp_analysis(
        bound, strategy, [direction], hp=hp,
        spec_path=spec_path, spec_sha256=spec_sha))
    assert missing["status"] == "HP_PARALLEL_ANALYSIS_INCOMPLETE"
    assert missing["analysis"]["reason"] == "PINNED_CONTEXT_CATALOG_UNAVAILABLE"
    assert {name: transport.calls for name, transport in
            transports.items()} == previous_calls


def test_parallel_sp_and_hp_roles_share_real_campaign_gate(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    func.analyzed_by_directions.clear()
    run_dir = tmp_path / "parallel-gate-run"
    run_dir.mkdir(mode=0o700)
    run_id, spec_sha, plan_sha, catalog_sha = (
        "c" * 24, "d" * 64, "e" * 64, "f" * 64)
    _, selection_sha = freeze_parallel_hp_selection(
        run_dir=run_dir, task_id=func.task_id, run_id=run_id,
        fuzzer=direction.fuzzer, spec_sha256=spec_sha,
        direction_plan_sha256=plan_sha,
        function_catalog_sha256=catalog_sha,
        directions=[direction], functions=[func])
    claim_sha = claim_parallel_hp_execution(
        run_dir=run_dir, task_id=func.task_id, run_id=run_id,
        spec_sha256=spec_sha, selection_receipt_sha256=selection_sha)
    evidence = {
        "origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
        "task_id": func.task_id, "run_id": run_id,
        "function_id": func.function_id,
        "direction_id": direction.direction_id,
        "source_tree_sha256": q.source_tree_sha256,
        "contract_sha256": q.contract_sha256,
        "spec_sha256": spec_sha, "direction_plan_sha256": plan_sha,
        "function_catalog_sha256": catalog_sha,
        "selection_receipt_sha256": selection_sha,
        "execution_claim_sha256": claim_sha,
        "run_dir": str(run_dir),
    }
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer=direction.fuzzer, sanitizer="address",
        parallel_hp_selection_evidence=evidence)
    assert isinstance(work, PreparedHPFunction)
    gate = CampaignModelGate(tmp_path / "parallel-gate.json",
                             "sp-hp-real-roles", 3, 60, create=True)
    sp_entered = asyncio.Event()
    hp_entered = asyncio.Event()
    overlap = []

    class HeldSP(ScriptedReceiptTransport):
        async def generate(self, request):
            sp_entered.set()
            await asyncio.wait_for(hp_entered.wait(), timeout=2)
            return await super().generate(request)

    class HeldHP(ScriptedReceiptTransport):
        async def generate(self, request):
            hp_entered.set()
            await asyncio.wait_for(sp_entered.wait(), timeout=2)
            overlap.append({row["role"]: row["status"]
                            for row in gate.snapshot()["records"]})
            return await super().generate(request)

    sp_transport = HeldSP(tmp_path, "sp", [{"fixture": "sp"}])
    analysis_transport = HeldHP(
        tmp_path, "function_analysis", [_analysis_reply(safe=True)])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    sp_provider = CampaignLedgeredProvider(
        sp_transport, gate, role="sp", owner_id="sp:direction")
    analysis = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis"))
    assertion = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:assertion_generator"))

    async def planning():
        return [direction]

    async def sp_pipeline(_directions):
        return await sp_provider.generate(LLMRequest(
            role="sp", instructions="fixture", payload={"x": 1},
            output_schema={"type": "object"}, model="fixture", effort="low"))

    async def hp_factory(_strategy, _directions):
        return await run_prepared_hp_analysis(
            work=work, qualification=q, analysis_pipeline=analysis,
            assertion_pipeline=assertion, worker_id="parallel-worker")

    strategy = object.__new__(POVFullscanStrategy)
    strategy.executor = SimpleNamespace(
        require_original_global_bridge=False,
        parallel_hp_async_factory=hp_factory)
    strategy.llm_client_factory = object()
    strategy.log_info = lambda _message: None
    strategy._run_direction_planning_async = planning
    strategy._run_v2_pipeline_with_fuzzer_init = sp_pipeline
    assert asyncio.run(strategy._run_full_pipeline()) == {"fixture": "sp"}
    assert overlap == [{"sp": "STARTED", "function_analysis": "STARTED"}]
    assert strategy._parallel_hp_result["status"] == (
        "ASSERTIONS_PROPOSED_UNVERIFIED")
    assert strategy._parallel_hp_result["security_gate_credit"] == "NOT_CREDITED"
    assert {row["role"]: row["status"] for row in gate.snapshot()["records"]} == {
        "sp": "COMPLETED", "function_analysis": "COMPLETED",
        "assertion_generator": "COMPLETED"}
    assert gate.snapshot()["physical"] == 3


def test_hp_context_reanalysis_reserves_assertion_model_slot(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    first_response = _analysis_reply()
    first_response["context_requests"] = [{
        "target": "missing_helper", "request_type": "FUNCTION",
        "reason": "needs definition", "expected_information": "bounds"}]
    gate = CampaignModelGate(tmp_path / "campaign-context.json",
                             "hp-context-budget", 2, 60, create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [first_response])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    first = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis", owner_id="hp-function"))
    second = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id="hp-assertion"))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert result["status"] == "INCOMPLETE_HP_CONTEXT"
    assert result["reason"] == "MODEL_CALL_BUDGET_RESERVED"
    assert result["context_requests"][0]["status"] == "SKIPPED_LLM_BUDGET"
    assert result["context_reanalysis_count"] == 0
    assert gate.snapshot()["physical"] == 1
    assert analysis_transport.calls == 1 and assertion_transport.calls == 0


def test_hp_roles_share_existing_campaign_gate_and_account_every_turn(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    gate = CampaignModelGate(tmp_path / "campaign.json", "hp-fixture", 3, 60,
                             create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [_analysis_reply(safe=True),
                                        _analysis_reply()])
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    first = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis", owner_id="hp-function"))
    second = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id="hp-assertion"))
    safe = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert safe["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert gate.snapshot()["physical"] == 2
    no_safe = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert no_safe["status"] == "NO_SAFE_ASSUMPTION"
    assert gate.snapshot()["physical"] == 3
    assert analysis_transport.calls == 2
    assert assertion_transport.calls == 1
    for row in gate.snapshot()["records"]:
        assert row["status"] == "COMPLETED"
        assert gate.verify_response_evidence(row["request_id"])["status"] == "VERIFIED"
    exhausted = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert exhausted["status"] == "INCOMPLETE_HP_ERROR"
    assert exhausted["error_type"] == "CampaignPendingBudget"
    assert exhausted["sp_global_effect"] == "UNCHANGED"
    assert gate.snapshot()["physical"] == 3
    assert analysis_transport.calls == 2


def test_unproven_hp_model_response_does_not_reach_assertion(
        tmp_path, monkeypatch):
    q, func, direction, _ = _case(tmp_path, monkeypatch)
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    gate = CampaignModelGate(tmp_path / "campaign.json", "hp-unproven", 2, 60,
                             create=True)
    analysis_transport = ScriptedReceiptTransport(
        tmp_path, "function_analysis", [_analysis_reply(safe=True)])
    original_generate = analysis_transport.generate

    async def tampered_response(request):
        result = await original_generate(request)
        Path(request.raw_response_path).write_text('{"changed":true}')
        return result

    analysis_transport.generate = tampered_response
    assertion_transport = ScriptedReceiptTransport(
        tmp_path, "assertion_generator", [_assertion_reply()])
    first = AgentPipeline(CampaignLedgeredProvider(
        analysis_transport, gate, role="function_analysis", owner_id="hp-function"))
    second = AgentPipeline(CampaignLedgeredProvider(
        assertion_transport, gate, role="assertion_generator",
        owner_id="hp-assertion"))
    result = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert result["status"] == "INCOMPLETE_HP_MODEL_PROVENANCE"
    assert result["phase"] == "FUNCTION_ANALYSIS"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert gate.snapshot()["physical"] == 1
    assert assertion_transport.calls == 0


def _signed_physical_case(tmp_path, monkeypatch, *, analysis_reply=None,
                          assertion_reply=None, real_physical=False):
    """Create one scripted model-shaped SAFE; physical execution is optional."""
    q, func, direction, source = _case(tmp_path, monkeypatch)
    if real_physical:
        q.harness.write_text(
            "#include <stddef.h>\n#include <stdint.h>\n"
            "extern \"C\" int parse_input(const char *);\n"
            "extern \"C\" int LLVMFuzzerTestOneInput("
            "const uint8_t *data, size_t size) {\n"
            "  if (size) (void)parse_input((const char *)data);\n"
            "  return 0;\n}\n")
        q.harness_sha256 = hashlib.sha256(q.harness.read_bytes()).hexdigest()
    q.binary = tmp_path / "official-binary"
    q.binary.write_bytes(b"pinned binary fixture")
    q.binary_sha256 = hashlib.sha256(q.binary.read_bytes()).hexdigest()
    work = prepare_hp_function(
        function=func, direction=direction, qualification=q,
        fuzzer="fuzz_fixture", sanitizer="address")
    gate = CampaignModelGate(tmp_path / "hp-model-gate.json",
                             "hp-physical-fixture", 3, 60, create=True)
    analysis = ScriptedReceiptTransport(
        tmp_path, "function_analysis",
        [analysis_reply or _analysis_reply(safe=True)])
    assertions = ScriptedReceiptTransport(
        tmp_path, "assertion_generator",
        [assertion_reply or _assertion_reply()])
    first = AgentPipeline(CampaignLedgeredProvider(
        analysis, gate, role="function_analysis",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis"))
    second = AgentPipeline(CampaignLedgeredProvider(
        assertions, gate, role="assertion_generator",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:assertion_generator"))
    row = asyncio.run(run_prepared_hp_analysis(
        work=work, qualification=q, analysis_pipeline=first,
        assertion_pipeline=second, worker_id="worker"))
    assert row["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
    assert row["proposal_origin"] == "VERIFIED_CAMPAIGN_MODEL"
    assert all(gate.verify_response_evidence(turn["request_id"])["status"] ==
               "VERIFIED" for turn in [
                   *row["hp_model_provenance"]["function_analysis_turns"],
                   row["hp_model_provenance"]["assertion_generator_turn"]])
    assert row["safe_selection_observation"]["retained_safe_count"] >= 1
    builder = tmp_path / "multi_tu_assertion_build.py"
    if real_physical:
        clang = Path(os.environ.get(
            "VA_TEST_CLANG",
            "/home/dawne/SunrinInfosecProject2026/reference/"
            "blind2_v2_preparation_20261027/review_tools/local_clang/clang"))
        if not clang.is_file():
            pytest.skip("pinned test Clang unavailable")
        clang_sha = hashlib.sha256(clang.read_bytes()).hexdigest()
        builder.write_text(
            f"#!{sys.executable}\n"
            "import hashlib, os, sys\n"
            f"clang = {str(clang)!r}\n"
            f"clang_sha256 = {clang_sha!r}\n"
            f"harness = {str(q.harness)!r}\n"
            "with open(clang, 'rb') as stream:\n"
            "    if hashlib.sha256(stream.read()).hexdigest() != clang_sha256:\n"
            "        raise SystemExit('pinned compiler changed')\n"
            "if len(sys.argv) == 3 and sys.argv[1] == '-fsyntax-only':\n"
            "    os.execv(clang, [clang, '-fsyntax-only', sys.argv[2]])\n"
            "if len(sys.argv) != 4 or sys.argv[2] != '-o':\n"
            "    raise SystemExit(2)\n"
            "os.execv(clang, [clang, '-fsanitize=fuzzer,address', '-O0', "
            "'-g', sys.argv[1], harness, '-o', sys.argv[3]])\n")
        builder.chmod(0o700)
    else:
        builder.write_text("# pinned fixture builder\n")
    manifest = builder.with_name("multi_tu_assertion_build_manifest.json")
    manifest.write_text(json.dumps({
        "schema": "MULTI_TU_ASSERTION_BUILD_V1",
        "kind": "MD4C_ISOLATED_ASSERTION_RELINK_V1",
        "builder_sha256": hashlib.sha256(builder.read_bytes()).hexdigest(),
        "source_root": str(q.source_root.resolve()),
        "harness_source": str(q.harness.resolve()),
        "official_binary": str(q.binary.resolve()),
        "official_binary_sha256": q.binary_sha256,
        "source_files": {source.name: work.source_file_sha256,
                         q.harness.name: q.harness_sha256},
        "allowed_translation_units": {source.name: 0},
    }, sort_keys=True))
    monkeypatch.setattr(hp_live, "_TRUSTED_MD4C_BUILDER", builder)
    monkeypatch.setattr(hp_live, "_TRUSTED_MD4C_BUILDER_SHA256",
                        hashlib.sha256(builder.read_bytes()).hexdigest())
    monkeypatch.setattr(hp_live, "_TRUSTED_MD4C_MANIFEST_SHA256",
                        hashlib.sha256(manifest.read_bytes()).hexdigest())
    product = tmp_path / "product"
    product_src = product / "src"
    product_src.mkdir(parents=True)
    for relative in hp_live._HP_ASSETS.values():
        asset = product / relative
        asset.parent.mkdir(exist_ok=True)
        asset.write_text("pinned fixture asset\n")
    physical = {
        "enabled": True, "builder_path": str(builder),
        "builder_sha256": hashlib.sha256(builder.read_bytes()).hexdigest(),
        "manifest_path": str(manifest),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "guided_seconds": 1, "total_wall_seconds": 120,
        "output_limit_bytes": 4_000_000,
    }
    hp = {"enabled": True, "max_items": 1, "max_model_calls": 3,
          "assets": hp_live.hp_asset_hashes(product_src),
          "physical": physical}
    spec = tmp_path / "hp-spec.json"
    spec.write_text(json.dumps({"hp": hp}, sort_keys=True))
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    ledger = PersistentProcessLedgerV2.create(
        run_dir / "process.json", wall_total_seconds=150,
        fuzz_total_seconds=40)
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id=work.task_id, run_id="run",
                                 run_dir=run_dir, product_src=product_src),
        admission=SimpleNamespace(qualification=q), process_ledger=ledger,
        model_gate=gate, analysis_transport=analysis,
        assertion_transport=assertions,
        recheck=lambda: None)
    worker = {"original_result": {"worker_id": "worker"}}
    return (bound, worker, hp, spec, work, row, source, builder, manifest)


def test_exact_cjson_candidate_is_bound_to_official_qualification(monkeypatch):
    """The second target is exact-pinned, not a generic custom-builder path."""
    candidate = (Path(__file__).resolve().parents[3] / "_HISTORY" /
                 "legacy_2026-10_11" /
                 "hp_cjson_official_qualification_toctou_v2_20261108")
    builder = candidate / "cjson_assertion_build.py"
    manifest = candidate / "cjson_assertion_build_manifest.json"
    # Relocation affects only this historical integration fixture's path.
    # Keep production's reviewed builder/manifest digests and all data pins.
    monkeypatch.setattr(hp_live, "_TRUSTED_CJSON_BUILDER", builder)
    recipe = json.loads(manifest.read_text())
    source_root = Path(recipe["source_root"])
    source = source_root / "cJSON.c"
    harness = Path(recipe["harness_source"]["path"])
    binary = Path(recipe["official_binary"]["path"])
    q = SimpleNamespace(
        source_root=source_root, harness=harness, binary=binary,
        harness_sha256=recipe["harness_source"]["sha256"],
        binary_sha256=recipe["official_binary"]["sha256"])
    work = SimpleNamespace(
        source_file=str(source),
        source_file_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    physical = {
        "enabled": True, "builder_path": str(builder),
        "builder_sha256": hashlib.sha256(builder.read_bytes()).hexdigest(),
        "manifest_path": str(manifest),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "guided_seconds": 1, "total_wall_seconds": 120,
        "output_limit_bytes": 4_000_000,
    }

    hp_live._validate_hp_physical_spec(physical)
    command = _reviewed_relink_build_command(
        builder, manifest, physical["manifest_sha256"])
    assert command == [
        recipe["interpreter"]["path"], "-I", str(builder),
        "--manifest-sha256", physical["manifest_sha256"],
        "{source}", "-o", "{binary}"]
    assert _qualified_relink_recipe_ok(
        work=work, qualification=q, build_command=command,
        manifest_path=manifest,
        manifest_sha256=physical["manifest_sha256"])
    context_command, source_pins, environment = (
        _qualified_context_build_command(work, q, physical))
    assert context_command == [
        recipe["compiler"]["path"], *recipe["fixed_flags"],
        "-I" + str(source_root.resolve()), "{source}"]
    assert source_pins == recipe["source_files"]
    assert set(environment) == {"HOME", "PATH", "TMPDIR", "LC_ALL", "LANG"}
    assert environment["PATH"] == "/usr/bin:/bin"

    crossed = SimpleNamespace(**vars(q))
    crossed.binary_sha256 = "0" * 64
    assert not _qualified_relink_recipe_ok(
        work=work, qualification=crossed, build_command=command,
        manifest_path=manifest,
        manifest_sha256=physical["manifest_sha256"])
    changed = dict(physical)
    changed["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="recipe pin changed"):
        hp_live._validate_hp_physical_spec(changed)


def test_signed_hp_physical_handoff_reuses_product_callbacks_with_shared_ledger(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis import assertions as product_assertions

    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    calls = []

    def execute(assertion, *_args, process_envelope=None, **_kwargs):
        calls.append("execute")
        lease = process_envelope.before_process(
            ["fixture-build"], cwd=None, env=None, timeout=0.01,
            kind="AUX_PROCESS", segment="assertion.build")
        process_envelope.after_process(
            lease, elapsed_seconds=0.001, cleanup_complete=True,
            output_limited=False, error=None)
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    def guided(assertion, *_args, process_envelope=None, **_kwargs):
        calls.append("guided")
        lease = process_envelope.before_process(
            ["fixture-fuzz"], cwd=None, env=None, timeout=0.01,
            kind="HP_FUZZ", segment="guided.initial_campaign")
        process_envelope.after_process(
            lease, elapsed_seconds=0.001, cleanup_complete=True,
            output_limited=False, error=None)
        return {"status": "RAN", "assertion_id": assertion.assertion_id,
                "fuzzer_run_count": 1, "violation_witnesses": []}

    monkeypatch.setattr(product_assertions, "execute_assertion", execute)
    monkeypatch.setattr(product_assertions, "guided_fuzz_assertion", guided)
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    outcome = factory(work, row)
    assert outcome["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert outcome["assertion_execution"] == "PINNED_PRODUCT_CALLBACK_RESULT"
    assert outcome["proposal_origin"] == "PINNED_HP_PROPOSAL_UNCREDITED"
    assert outcome["security_gate_credit"] == "NOT_CREDITED"
    assert outcome["discovery_credit"] == "NOT_CREDITED"
    assert calls == ["execute", "guided"]
    state = bound.process_ledger.snapshot()
    assert not state["active"] and state["stop_status"] is None
    assert [x["kind"] for x in state["finished"]] == [
        "AUX_PROCESS", "HP_FUZZ"]
    claim = json.loads(Path(outcome["physical_claim_path"]).read_text())
    assert claim["hp_model_provenance"] == row["hp_model_provenance"]
    assert claim["hp_model_provenance_sha256"] == hashlib.sha256(
        json.dumps(row["hp_model_provenance"], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(FileExistsError):
        factory(work, row)
    assert calls == ["execute", "guided"]


def test_parallel_hp_physical_capacity_accounts_for_active_sp_reservations(
        tmp_path):
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "process-ledger.json", wall_total_seconds=150,
        fuzz_total_seconds=40)
    physical = {"total_wall_seconds": 120, "guided_seconds": 1}
    available = hp_live._hp_physical_budget_available

    ledger.reserve("sp:small", "AUX_PROCESS", 10)
    state, _ = ledger.receipt_snapshot()
    assert not available(state, physical, parallel_hp_execution=False)
    assert available(state, physical, parallel_hp_execution=True)
    ledger.finish("sp:small", physical_seconds=0,
                  cleanup_complete=True)

    ledger.reserve("sp:large", "AUX_PROCESS", 40)
    state, _ = ledger.receipt_snapshot()
    assert not available(state, physical, parallel_hp_execution=True)
    ledger.finish("sp:large", physical_seconds=0,
                  cleanup_complete=True)

    ledger.reserve("sp:fuzz", "SP_FUZZ", 20)
    state, _ = ledger.receipt_snapshot()
    assert not available(state, physical, parallel_hp_execution=True)
    ledger.finish("sp:fuzz", physical_seconds=0,
                  cleanup_complete=True)


def test_parallel_hp_real_factory_handoff_preserves_active_sp_lease(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis import assertions as product_assertions

    bound, _, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    bound.identity.run_id = "c" * 24
    bound.caps = SimpleNamespace(sp_concurrent_queue=True,
                                 bounded_nohint_dev=False)
    selection_args = dict(
        run_dir=bound.identity.run_dir, task_id=work.task_id,
        run_id=bound.identity.run_id, fuzzer="fuzz_fixture",
        spec_sha256=hashlib.sha256(spec.read_bytes()).hexdigest(),
        direction_plan_sha256="d" * 64,
        function_catalog_sha256="e" * 64,
        directions=[Direction(task_id=work.task_id,
                              direction_id=work.direction_id,
                              fuzzer="fuzz_fixture",
                              core_functions=[work.function_name])],
        functions=[Function(task_id=work.task_id,
                            function_id=work.function_id,
                            name=work.function_name,
                            file_path=Path(work.source_file).name,
                            start_line=work.source_start_line,
                            end_line=work.source_end_line)],
    )
    _, selection_sha = freeze_parallel_hp_selection(**selection_args)
    claim_sha = claim_parallel_hp_execution(
        run_dir=bound.identity.run_dir, task_id=work.task_id,
        run_id=bound.identity.run_id,
        spec_sha256=selection_args["spec_sha256"],
        selection_receipt_sha256=selection_sha)
    evidence = {
        "origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
        "task_id": work.task_id, "run_id": bound.identity.run_id,
        "function_id": work.function_id,
        "direction_id": work.direction_id,
        "source_tree_sha256": work.source_tree_sha256,
        "contract_sha256": work.contract_sha256,
        "spec_sha256": selection_args["spec_sha256"],
        "direction_plan_sha256": "d" * 64,
        "function_catalog_sha256": "e" * 64,
        "selection_receipt_sha256": selection_sha,
        "execution_claim_sha256": claim_sha,
        "run_dir": str(bound.identity.run_dir),
    }
    scope = {**work.analysis_scope,
             "selection_origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
             "selection_evidence": evidence}
    work = replace(work, analysis_scope=scope,
                   selection_origin="PARALLEL_HP_PRE_SP_SELECTION_V1")
    row["prepared_work_sha256"] = hashlib.sha256(json.dumps(
        asdict(work), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def execute(assertion, *_args, process_envelope=None, **_kwargs):
        lease = process_envelope.before_process(
            ["fixture-build"], cwd=None, env=None, timeout=0.01,
            kind="AUX_PROCESS", segment="assertion.build")
        process_envelope.after_process(
            lease, elapsed_seconds=0.001, cleanup_complete=True,
            output_limited=False, error=None)
        assertion.status = "HELD_FOR_EXECUTION"
        return assertion, None

    def guided(assertion, *_args, process_envelope=None, **_kwargs):
        lease = process_envelope.before_process(
            ["fixture-fuzz"], cwd=None, env=None, timeout=0.01,
            kind="HP_FUZZ", segment="guided.initial_campaign")
        process_envelope.after_process(
            lease, elapsed_seconds=0.001, cleanup_complete=True,
            output_limited=False, error=None)
        return {"status": "RAN", "assertion_id": assertion.assertion_id,
                "fuzzer_run_count": 1, "violation_witnesses": []}

    monkeypatch.setattr(product_assertions, "execute_assertion", execute)
    monkeypatch.setattr(product_assertions, "guided_fuzz_assertion", guided)
    ledger = bound.process_ledger
    ledger.reserve("sp:active", "SP_FUZZ", 10)
    factory = hp_live._physical_handoff_factory(
        bound, hp, None, spec, selection_args["spec_sha256"],
        actor_id="worker", extra_check=lambda: None,
        parallel_hp_execution=True)
    result = factory(work, row)
    assert result["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    active = ledger.snapshot()["active"]
    assert set(active) == {"sp:active"}
    ledger.finish("sp:active", physical_seconds=0.01,
                  cleanup_complete=True)
    assert ledger.snapshot()["active"] == {}


def test_signed_hp_auto_selects_model_assertion_and_reaches_real_guided_triage(
        tmp_path, monkeypatch):
    """Compose model-shaped SAFE/Assertion with the real physical callbacks."""
    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, real_physical=True)
    assert len(row["assertion_proposals"]) == 1
    proposed_id = row["assertion_proposals"][0]["assertion_id"]

    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    outcome = factory(work, row)

    assert outcome["status"] == "HP_ASSERTION_HANDOFF_COMPLETE", json.dumps(
        outcome, sort_keys=True)
    assert outcome["assertion_selection"]["selected_assertion_id"] == proposed_id
    assert outcome["assertion_selection"]["not_run"] == []
    assert outcome["security_gate_credit"] == "NOT_CREDITED"
    assert outcome["discovery_credit"] == "NOT_CREDITED"
    physical_root = Path(outcome["physical_claim_path"]).parent / (
        "hp-physical/" + proposed_id)
    for relative in (
            "execution/syntax.log", "execution/build.log",
            "execution/runtime.json", "execution/instrumented-target"):
        assert (physical_root / relative).is_file(), relative
    triage = list(physical_root.rglob("triage.json"))
    guided = list(physical_root.rglob("guided_fuzz.json"))
    assert triage, sorted(str(path.relative_to(physical_root))
                          for path in physical_root.rglob("*"))
    assert guided, sorted(str(path.relative_to(physical_root))
                          for path in physical_root.rglob("*"))
    guided_row = json.loads(guided[0].read_text())
    assert guided_row["assertion_id"] == proposed_id
    assert guided_row["source_sha256"] == work.source_file_sha256
    assert guided_row["seed_sha256"] == (
        bound.admission.qualification.normal_seed_sha256)
    triage_row = json.loads(triage[0].read_text())
    assert triage_row.get("assertion_id") == proposed_id
    assert triage_row["classification"] == "NOT_A_VIOLATION"
    assert triage_row["security_verdict"] == "UNKNOWN"
    claim = json.loads(Path(outcome["physical_claim_path"]).read_text())
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()
    assert claim["proposal_sha256"] == hashlib.sha256(canonical(row)).hexdigest()
    assert claim["source_sha256"] == work.source_sha256
    assert claim["hp_model_provenance"] == row["hp_model_provenance"]
    assert claim["hp_model_provenance_sha256"] == hashlib.sha256(
        canonical(row["hp_model_provenance"])).hexdigest()
    state = bound.process_ledger.snapshot()
    assert state["active"] == {} and state["stop_status"] is None
    assert any(item["kind"] == "HP_FUZZ" for item in state["finished"])
    with pytest.raises(FileExistsError):
        factory(work, row)


@pytest.mark.parametrize("change", ["builder", "source", "proposal",
                                    "signed_cap", "budget", "unsettled"])
def test_signed_hp_physical_handoff_fails_before_launch(
        tmp_path, monkeypatch, change):
    from vulnerabilityanalysis import assertions as product_assertions

    bound, worker, hp, spec, work, row, source, builder, _ = (
        _signed_physical_case(tmp_path, monkeypatch))
    calls = []
    monkeypatch.setattr(product_assertions, "execute_assertion",
                        lambda *_a, **_k: calls.append("execute"))
    monkeypatch.setattr(product_assertions, "guided_fuzz_assertion",
                        lambda *_a, **_k: calls.append("guided"))
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    if change == "builder":
        builder.write_text("# tampered\n")
    elif change == "source":
        source.write_text(source.read_text() + "/* changed */\n")
    elif change == "proposal":
        row["assertion_proposals"][0]["runtime_expression"] = "false"
    elif change == "signed_cap":
        hp["physical"]["guided_seconds"] = 2
    elif change == "budget":
        bound.process_ledger = PersistentProcessLedgerV2.create(
            bound.identity.run_dir / "low_process.json",
            wall_total_seconds=100, fuzz_total_seconds=40)
    else:
        bound.process_ledger.reserve("unsettled", "AUX_PROCESS", 1)
    with pytest.raises((ValueError, RuntimeError)):
        factory(work, row)
    assert calls == []
    assert not list((bound.identity.run_dir / "hp-physical").glob("**/*"))


def test_non_md4c_relink_recipe_is_held_before_model_factory(
        tmp_path, monkeypatch):
    bound, worker, hp, spec, _, _, _, _, manifest = _signed_physical_case(
        tmp_path, monkeypatch)
    recipe = json.loads(manifest.read_text())
    recipe["kind"] = "OTHER_TARGET_RELINK_V1"
    manifest.write_text(json.dumps(recipe, sort_keys=True))
    hp["physical"]["manifest_sha256"] = hashlib.sha256(
        manifest.read_bytes()).hexdigest()
    monkeypatch.setattr(hp_live, "_TRUSTED_MD4C_MANIFEST_SHA256",
                        hp["physical"]["manifest_sha256"])
    spec.write_text(json.dumps({"hp": hp}, sort_keys=True))
    with pytest.raises(ValueError, match="not qualified for this target"):
        hp_live._physical_handoff_factory(
            bound, hp, worker, spec,
            hashlib.sha256(spec.read_bytes()).hexdigest())
    assert not (bound.identity.run_dir / "HP_PHYSICAL_CLAIM.json").exists()


def test_self_signed_builder_is_not_a_trusted_physical_recipe(
        tmp_path, monkeypatch):
    bound, worker, hp, spec, _, _, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    monkeypatch.setattr(hp_live, "_TRUSTED_MD4C_BUILDER", Path(
        "/home/dawne/SunrinInfosecProject2026/reference/"
        "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py"))
    with pytest.raises(ValueError, match="builder is not trusted"):
        hp_live._physical_handoff_factory(
            bound, hp, worker, spec,
            hashlib.sha256(spec.read_bytes()).hexdigest())
    assert not (bound.identity.run_dir / "HP_PHYSICAL_CLAIM.json").exists()


@pytest.mark.parametrize("change", ["missing", "sha", "raw", "cross_role",
                                    "cross_function_analysis", "fixture"])
def test_hp_physical_rejects_missing_or_crossed_model_turns_before_claim(
        tmp_path, monkeypatch, change):
    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    provenance = row["hp_model_provenance"]
    if change == "missing":
        provenance["assertion_generator_turn"]["request_id"] = ""
    elif change == "sha":
        provenance["assertion_generator_turn"]["response_sha256"] = "0" * 64
    elif change == "raw":
        evidence = bound.model_gate.verify_response_evidence(
            provenance["assertion_generator_turn"]["request_id"])
        Path(evidence["response_path"]).write_text('{"changed":true}')
    elif change == "cross_role":
        provenance["assertion_generator_turn"] = dict(
            provenance["function_analysis_turns"][0])
    elif change == "cross_function_analysis":
        transport = bound.analysis_transport
        transport.responses.append(_analysis_reply(safe=False))
        provider = CampaignLedgeredProvider(
            transport, bound.model_gate, role="function_analysis",
            owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis")
        pipeline = AgentPipeline(provider)
        asyncio.run(pipeline.analyze_function(
            work.function_id, work.function_name, work.source_file,
            work.source))
        evidence = bound.model_gate.verify_response_evidence(
            provider.last_request_id)
        provenance["function_analysis_turns"][0] = {
            "role": "function_analysis", "owner_id": provider.owner_id,
            "request_id": provider.last_request_id,
            "response_sha256": evidence["response_sha256"],
            "thread_id": evidence["thread_id"], "turn_id": evidence["turn_id"]}
    else:
        row["proposal_origin"] = "PROVIDER_FREE_FIXTURE"
        row["hp_model_provenance"] = None
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="provenance|response|Assertion|Function Analysis"):
        factory(work, row)
    assert not (bound.identity.run_dir / "HP_PHYSICAL_CLAIM.json").exists()


def test_hp_provenance_uses_product_safe_id_normalization(
        tmp_path, monkeypatch):
    analysis_reply = _analysis_reply(safe=True)
    analysis_reply["safe_assumptions"].insert(0, "unlinked model suggestion")
    assertion_reply = _assertion_reply()
    assertion_reply["assertions"][0]["safe_assumption"] = "model shorthand"
    assertion_reply["dispositions"][0]["safe_assumption"] = "other wording"
    bound, worker, _, _, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, analysis_reply=analysis_reply,
        assertion_reply=assertion_reply)
    assert row["assertion_proposals"][0]["safe_assumption"] == (
        "The input pointer is not null")
    assert row["safe_selection_observation"]["unlinked_proposal_count"] == 1
    assert hp_live._verified_hp_provenance(
        bound.model_gate, work, worker["original_result"]["worker_id"],
        row) == row["hp_model_provenance"]


def test_hp_provenance_uses_scoped_assertion_input_safe_order(
        tmp_path, monkeypatch):
    """A blocked raw SAFE before the eligible SAFE must not shift safe_id."""
    from vulnerabilityanalysis.llm import LLMRequest

    eligible = "The input pointer is not null"
    blocked = "A separate state transition is safe"
    analysis_reply = _analysis_reply(safe=True)
    analysis_reply["safe_assumptions"].insert(0, blocked)
    analysis_reply["hypothesis_evaluations"].insert(0, {
        **analysis_reply["hypothesis_evaluations"][0],
        "source_location": "parser.c:1", "source_line": 1,
        "source_quote": "int parse_input(const char *p) {",
        "security_property": "state transition",
        "safe_assumption": blocked,
    })
    initial_assertion = _assertion_reply()
    initial_assertion["assertions"][0]["safe_id"] = 1
    initial_assertion["dispositions"][0]["safe_id"] = 1
    bound, worker, _, _, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, analysis_reply=analysis_reply,
        assertion_reply=initial_assertion)

    # Candidate-scoped closure hands only the eligible second raw SAFE to the
    # Assertion Generator, where it is positional safe_id 0.
    row["assertion_input_safe_assumptions"] = [eligible]
    row["assertion_input_safe_assumptions_sha256"] = hashlib.sha256(
        json.dumps([eligible], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    eligible_id = "safe-eligible"
    row["candidate_context_closure"] = {
        "policy": "HP_HOST_BOUND_INDEXED_REQUEST_ATTRIBUTION_V2",
        "unresolved_context_count": 1,
        "eligible_assumption_ids": [eligible_id],
        "blocked_assumption_ids": {},
    }
    row["assumption_lifecycle_ledger"] = [{
        "assumption_id": eligible_id,
        "safe_assumption": eligible,
        "source_location": "parser.c:2",
        "security_property": "entry pointer validity",
        "disposition": "VALIDATED_SAFE",
        "required_context": [],
        "evidence_dependencies": ["SELECTED_SOURCE"],
    }]

    scoped_response = _assertion_reply()
    transport = bound.assertion_transport
    transport.responses.append(scoped_response)
    provider = CampaignLedgeredProvider(
        transport, bound.model_gate, role="assertion_generator",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:assertion_generator")
    asyncio.run(provider.generate(LLMRequest(
        role="assertion_generator", instructions="fixture",
        payload={}, output_schema={})))
    evidence = bound.model_gate.verify_response_evidence(
        provider.last_request_id)
    row["hp_model_provenance"]["assertion_generator_turn"] = {
        "role": "assertion_generator", "owner_id": provider.owner_id,
        "request_id": provider.last_request_id,
        "response_sha256": evidence["response_sha256"],
        "thread_id": evidence["thread_id"], "turn_id": evidence["turn_id"],
    }

    assert hp_live._verified_hp_provenance(
        bound.model_gate, work, worker["original_result"]["worker_id"],
        row) == row["hp_model_provenance"]

    row["assertion_input_safe_assumptions_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="input SAFE handoff changed"):
        hp_live._verified_hp_provenance(
            bound.model_gate, work, worker["original_result"]["worker_id"],
            row)


def test_hp_provenance_rejects_crossed_canonical_safe_id(
        tmp_path, monkeypatch):
    first_safe = "The input pointer is not null"
    second_safe = "The pointer has enough bytes"
    analysis_reply = _analysis_reply(safe=True)
    analysis_reply["safe_assumptions"].append(second_safe)
    analysis_reply["hypothesis_evaluations"].append({
        **analysis_reply["hypothesis_evaluations"][0],
        "safe_assumption": second_safe})
    assertion_reply = _assertion_reply()
    assertion_reply["assertions"][0]["safe_id"] = 1
    assertion_reply["assertions"][0]["safe_assumption"] = second_safe
    assertion_reply["dispositions"][0]["safe_id"] = 1
    assertion_reply["dispositions"][0]["safe_assumption"] = second_safe
    bound, worker, _, _, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, analysis_reply=analysis_reply,
        assertion_reply=assertion_reply)
    assert row["assertion_proposals"][0]["safe_assumption"] == second_safe
    row["assertion_proposals"][0]["safe_assumption"] = first_safe
    with pytest.raises(ValueError, match="model response"):
        hp_live._verified_hp_provenance(
            bound.model_gate, work, worker["original_result"]["worker_id"],
            row)


def test_hp_provenance_rejects_duplicate_disposition_in_crossed_turn(
        tmp_path, monkeypatch):
    from vulnerabilityanalysis.llm import LLMRequest

    bound, worker, _, _, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    response = _assertion_reply()
    response["dispositions"].append({
        **response["dispositions"][0], "status": "OTHER"})
    transport = bound.assertion_transport
    transport.responses.append(response)
    provider = CampaignLedgeredProvider(
        transport, bound.model_gate, role="assertion_generator",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:assertion_generator")
    asyncio.run(provider.generate(LLMRequest(
        role="assertion_generator", instructions="fixture",
        payload={}, output_schema={})))
    evidence = bound.model_gate.verify_response_evidence(
        provider.last_request_id)
    row["hp_model_provenance"]["assertion_generator_turn"] = {
        "role": "assertion_generator", "owner_id": provider.owner_id,
        "request_id": provider.last_request_id,
        "response_sha256": evidence["response_sha256"],
        "thread_id": evidence["thread_id"], "turn_id": evidence["turn_id"]}
    with pytest.raises(ValueError, match="identity differs"):
        hp_live._verified_hp_provenance(
            bound.model_gate, work, worker["original_result"]["worker_id"],
            row)


def test_hp_provenance_rejects_scalar_safe_list_in_crossed_turn(
        tmp_path, monkeypatch):
    bound, worker, _, _, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    response = _analysis_reply(safe=True)
    response["safe_assumptions"] = "The input pointer is not null"
    transport = bound.analysis_transport
    transport.responses.append(response)
    provider = CampaignLedgeredProvider(
        transport, bound.model_gate, role="function_analysis",
        owner_id=f"hp:{work.function_id}:{work.direction_id}:function_analysis")
    pipeline = AgentPipeline(provider)
    asyncio.run(pipeline.analyze_function(
        work.function_id, work.function_name, work.source_file,
        work.source))
    evidence = bound.model_gate.verify_response_evidence(
        provider.last_request_id)
    row["hp_model_provenance"]["function_analysis_turns"][0] = {
        "role": "function_analysis", "owner_id": provider.owner_id,
        "request_id": provider.last_request_id,
        "response_sha256": evidence["response_sha256"],
        "thread_id": evidence["thread_id"], "turn_id": evidence["turn_id"]}
    with pytest.raises(ValueError, match="SAFE or Assertion body"):
        hp_live._verified_hp_provenance(
            bound.model_gate, work, worker["original_result"]["worker_id"],
            row)


def _two_assertion_reply():
    response = _assertion_reply()
    first = response["assertions"][0]
    response["assertions"] = [
        {**first, "source_line": 3, "runtime_expression": "p == 0"},
        first,
    ]
    return response


def test_hp_two_model_assertions_select_one_deterministically(
        tmp_path, monkeypatch):
    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, assertion_reply=_two_assertion_reply())
    assert row["proposed_assertion_count"] == 2
    seen = []

    def handoff(**kwargs):
        seen.append(kwargs["assertion_id"])
        return {"status": "HP_ASSERTION_HANDOFF_COMPLETE",
                "assertion_id": kwargs["assertion_id"],
                "sp_global_effect": "UNCHANGED",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED"}

    # The factory imports the lower handoff lazily from its owning module.
    from devtools import original_hp_preparation as preparation
    monkeypatch.setattr(preparation, "run_prepared_hp_assertion_handoff", handoff)
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    result = factory(work, row)
    by_line = sorted(row["assertion_proposals"], key=lambda item: (
        int(item["source_location"].rsplit(":", 1)[1]),
        item["assertion_id"]))
    assert seen == [by_line[0]["assertion_id"]]
    assert result["assertion_selection"] == {
        "policy": "SOURCE_LINE_THEN_ASSERTION_ID_V1",
        "proposed_count": 2,
        "selected_assertion_id": by_line[0]["assertion_id"],
        "not_run": [{"assertion_id": by_line[1]["assertion_id"],
                     "status": "NOT_RUN", "reason": "BUDGET_NOT_SELECTED"}],
    }
    claim = json.loads(Path(result["physical_claim_path"]).read_text())
    assert claim["assertion_selection"] == result["assertion_selection"]
    with pytest.raises(FileExistsError):
        factory(work, row)
    assert len(seen) == 1


def test_signed_hp_physical_factory_uses_explicit_four_turn_provenance_cap(
        tmp_path, monkeypatch):
    bound, _, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    hp["max_model_calls"] = 5
    spec.write_text(json.dumps({"hp": hp}, sort_keys=True))
    observed_caps = []
    original_verify = hp_live._verified_hp_provenance

    def verify(gate, actual_work, worker_id, actual_row, *,
               max_analysis_turns=2):
        observed_caps.append(max_analysis_turns)
        # This fixture has one analysis turn. Re-run the real verifier with
        # its narrow fixture cap after proving what the factory supplied.
        return original_verify(
            gate, actual_work, worker_id, actual_row,
            max_analysis_turns=2)

    def handoff(**kwargs):
        return {
            "status": "HP_ASSERTION_HANDOFF_COMPLETE",
            "assertion_id": kwargs["assertion_id"],
            "sp_global_effect": "UNCHANGED",
            "security_gate_credit": "NOT_CREDITED",
            "discovery_credit": "NOT_CREDITED",
        }

    from devtools import original_hp_preparation as preparation
    monkeypatch.setattr(hp_live, "_verified_hp_provenance", verify)
    monkeypatch.setattr(preparation, "run_prepared_hp_assertion_handoff",
                        handoff)
    factory = hp_live._physical_handoff_factory(
        bound, hp, None, spec, hashlib.sha256(spec.read_bytes()).hexdigest(),
        actor_id="worker", signed_max_analysis_turns=4)
    result = factory(work, row)
    assert observed_caps == [4]
    assert result["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
    claim = json.loads(Path(result["physical_claim_path"]).read_text())
    assert len(claim["hp_model_provenance"]["function_analysis_turns"]) == 1


def test_signed_hp_physical_factory_rejects_unsigned_provenance_cap(
        tmp_path, monkeypatch):
    bound, worker, hp, spec, _, _, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="signed analysis-turn"):
        hp_live._physical_handoff_factory(
            bound, hp, worker, spec, digest,
            signed_max_analysis_turns=4)


def test_hp_duplicate_assertion_id_blocks_all_physical_claims(
        tmp_path, monkeypatch):
    response = _assertion_reply()
    response["assertions"].append(dict(response["assertions"][0]))
    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, assertion_reply=response)
    assert row["proposed_assertion_count"] == 2
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="Assertion response|duplicated"):
        factory(work, row)
    assert not (bound.identity.run_dir / "HP_PHYSICAL_CLAIM.json").exists()


def test_hp_missing_model_assertion_blocks_before_one_shot_claim(
        tmp_path, monkeypatch):
    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch, assertion_reply=_two_assertion_reply())
    row["assertion_proposals"] = row["assertion_proposals"][1:]
    row["assertion_count"] = 1
    row["proposed_assertion_count"] = 1
    row["assertion_proposals_sha256"] = hashlib.sha256(json.dumps(
        row["assertion_proposals"], sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="count differs"):
        factory(work, row)
    assert not (bound.identity.run_dir / "HP_PHYSICAL_CLAIM.json").exists()


def test_static_rule_assertion_requires_original_context_excerpt_receipt(
        tmp_path, monkeypatch):
    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)
    row["assertion_proposals"][0]["generation_method"] = "STATIC_RULE"
    row["assertion_proposals_sha256"] = hashlib.sha256(json.dumps(
        row["assertion_proposals"], sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    result = factory(work, row)
    assert result["status"] == "HP_ASSERTION_HANDOFF_BLOCKED"
    assert result["reason"] == "MODEL_SAFE_STATIC_ASSERTION_CONTEXT_UNPROVEN"
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert result["discovery_credit"] == "NOT_CREDITED"
    assert not (bound.identity.run_dir / "HP_PHYSICAL_CLAIM.json").exists()


def test_signed_hp_handoff_freezes_scripted_guided_crash_without_gate_credit(
        tmp_path, monkeypatch):
    """Exercise the real factory and handoff, with scripted physical callbacks."""
    from vulnerabilityanalysis import assertions as assertions_module

    bound, worker, hp, spec, work, row, _, _, _ = _signed_physical_case(
        tmp_path, monkeypatch)

    def execute(assertion, *_args, **_kwargs):
        assertion.status = "NOT_REACHED"
        return assertion, None

    def guided(assertion, _source, _line, _seed, output, _build, _run,
               *, process_envelope, **_kwargs):
        output.mkdir(parents=True)
        crash = output / "crash-scripted"
        crash.write_bytes(b"scripted input")
        binary = output / "guided-target"
        binary.write_bytes(b"scripted instrumented binary")
        runtime = {"sanitizer": "AddressSanitizer: heap-buffer-overflow",
                   "stderr": "ERROR: AddressSanitizer: heap-buffer-overflow\n",
                   "exit_code": 1, "timed_out": False,
                   "failure_classification": "TARGET_CRASH"}
        (output / "fuzzer-runtime.json").write_text(json.dumps(runtime))
        key = (f"{work.task_id}:{assertion.assertion_id}:run:000000:"
               "guided.initial_campaign")
        process_envelope.ledger.reserve(key, "HP_FUZZ", 2)
        process_envelope.ledger.finish(
            key, physical_seconds=1, cleanup_complete=True)
        report = {"assertion_id": assertion.assertion_id,
                  "status": "CRASH_OBSERVED_INCOMPLETE",
                  "binary": str(binary),
                  "other_crash_artifacts": [str(crash)],
                  "other_crash_artifact_pins": [{
                      "path": str(crash),
                      "sha256": hashlib.sha256(crash.read_bytes()).hexdigest()}],
                  "fuzzer_runtime": str(output / "fuzzer-runtime.json"),
                  "fuzzer_exit_code": 1, "fuzzer_timed_out": False}
        (output / "guided_fuzz.json").write_text(json.dumps(report))
        return report

    monkeypatch.setattr(assertions_module, "execute_assertion", execute)
    monkeypatch.setattr(assertions_module, "guided_fuzz_assertion", guided)
    factory = hp_live._physical_handoff_factory(
        bound, hp, worker, spec, hashlib.sha256(spec.read_bytes()).hexdigest())
    result = factory(work, row)
    assert result["status"] == "HP_GUIDED_CRASH_OBSERVED_UNGATED"
    freeze = result["hp_crash_freeze"]
    assert freeze["status"] == "HP_CRASH_LEADS_FROZEN_UNVERIFIED"
    assert freeze["reported_lead_count"] == 1
    assert len(freeze["frozen_leads"]) == 1
    assert Path(freeze["frozen_leads"][0]["frozen_input_path"]).read_bytes() == (
        b"scripted input")
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert freeze["security_gate_credit"] == "NOT_CREDITED"
    assert result["physical_claim_sha256"] == hashlib.sha256(
        Path(result["physical_claim_path"]).read_bytes()).hexdigest()
