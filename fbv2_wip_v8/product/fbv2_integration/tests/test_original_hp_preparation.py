"""Provider-free FBv2 function to existing product HP source boundary."""

from dataclasses import asdict
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

PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from vulnerabilityanalysis import official_harness
from vulnerabilityanalysis.models import FunctionAnalysis
from vulnerabilityanalysis.agents import AgentPipeline
from devtools.campaign_model_gate import (
    CampaignLedgeredProvider, CampaignModelGate,
)
from devtools.original_hp_preparation import (
    PreparedHPFunction, classify_hp_analysis, prepare_hp_function,
    run_prepared_hp_analysis, run_prepared_hp_assertion_handoff,
)
from devtools import original_hp_live_optin as hp_live
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2


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


def _pipelines(analysis_reply, *, assertion_reply=None, analysis_callback=None):
    analysis_provider = ScriptedProvider(
        "function_analysis", analysis_reply, analysis_callback)
    assertion_provider = ScriptedProvider(
        "assertion_generator", assertion_reply or _assertion_reply())
    return (AgentPipeline(analysis_provider), AgentPipeline(assertion_provider),
            analysis_provider, assertion_provider)


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


def test_hp_duplicate_missing_and_over_limit_context_do_not_reanalyze(
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
    assert result["status"] == "NO_SAFE_ASSUMPTION"
    assert [row["status"] for row in result["context_requests"]] == [
        "NOT_FOUND", "ALREADY_REQUESTED", "SKIPPED_PER_TURN_LIMIT"]
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
    assert result["status"] == "NO_SAFE_ASSUMPTION"
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
    assert result["status"] == "NO_SAFE_ASSUMPTION"
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
    assert result["status"] == "NO_SAFE_ASSUMPTION"
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
                          assertion_reply=None):
    """One model-shaped SAFE, but no model or target subprocess."""
    q, func, direction, source = _case(tmp_path, monkeypatch)
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
