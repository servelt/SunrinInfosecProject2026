"""Invariant tests for uncertain inputs and non-trusting build/runtime boundaries."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import asyncio
import builtins
import shutil
import subprocess
import sys
import pytest

from harnesscreator.agents.scenario import ScenarioPlanner
from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.models import (
    ActionExample, ActionStateContract, Evidence, ExternalActionSchema,
    ProofStatus, ScenarioStatus, ScenarioWitness, StateDependencyGraph,
    StateRequirement, VerificationResult, RuntimeStepObservation,
    ScenarioCandidate, ScenarioStep,
)
from harnesscreator.runtime.contracts import audit_harness_plan
from harnesscreator.runtime.qualification_audit import audit_qualification
from harnesscreator.runtime.workflow_evidence import candidate_lifecycle
from harnesscreator.runtime.preflight import inspect_capabilities, _embedded_gdb_line_info
from harnesscreator.models import ProjectSpec
from harnesscreator.cli import build_parser, _run
from harnesscreator.runtime.scenario import (
    ScenarioRuntimeVerifier, _crash_replay_has_exact_input_acquisition,
)


def action(name: str, payload: bytes = b"X", status=ProofStatus.POSSIBLE) -> ExternalActionSchema:
    evidence = [Evidence("source", name, "sample.c", 10, "the opened original handler")]
    return ExternalActionSchema(
        action_id=name, entry_id="entry", name=name, description=name,
        dispatcher_function_id=name, handler_function_id=name, discriminator=name,
        channel_kind="stdin", fields=[], examples=[ActionExample(payload.hex(), {})],
        success_markers_hex=[b"OK\n".hex()], failure_markers_hex=[],
        evidence=evidence, inspected_function_ids=[name], status=status,
        entry_function_id=name, source_api="fread",
    )


def test_unknown_action_is_not_lost_or_falsely_qualified():
    a = action("read")
    a.examples = []
    ledger = candidate_lifecycle([a])
    assert len(ledger) == 1
    assert ledger[0].disposition == "ACTION_NOT_PLANNED"
    assert "REQUEST_EXAMPLE_MISSING" in ledger[0].obligations
    assert "NO_SCENARIO_SCHEDULED" in ledger[0].obligations


def test_failed_original_execution_preserves_a_source_only_harness_plan():
    a = action("read", b"READ")
    scenario = ScenarioPlanner().exploratory_candidates([a], [])[0]
    failed = ScenarioWitness(
        witness_id="failed-run", scenario_id=scenario.scenario_id,
        target_action_id="read", steps=scenario.steps, observations=[],
        command=["/unavailable"], channel="stdin", process_returncode=None,
        status=ScenarioStatus.INFRASTRUCTURE_FAILED,
        rationale="debugger did not start; no handler evidence",)
    plan = build_harness_plan(
        failed, action_function_ids={"read": ("read", "handler")},
        allow_unproven=True,
    )
    assert plan.boundary_contract["status"] == "SOURCE_ONLY_UNVERIFIED"
    assert plan.boundary_contract["reset_is_verified"] is False
    assert audit_harness_plan(failed, plan, allow_unproven=True).passed
    assert not audit_harness_plan(failed, plan).passed
    lifecycle = candidate_lifecycle([a], [scenario], [failed], [plan])
    assert lifecycle[0].disposition == "PLANNED_NOT_GENERATED"
    assert any("ORIGINAL_RUNTIME_NOT_PROVEN" in b for b in lifecycle[0].obligations)


def test_uncertain_state_dependency_generates_trial_post_fuzz_not_proof():
    set_action = action("set", b"SET k")
    get_action = action("get", b"GET k")
    evidence = set_action.evidence
    resource = StateRequirement("item", "", "exists", evidence, ProofStatus.POSSIBLE)
    deps = StateDependencyGraph([
        ActionStateContract("set", [], [resource], [], "stored", evidence, ["set"], ProofStatus.POSSIBLE),
        ActionStateContract("get", [resource], [], [], "retrieved", evidence, ["get"], ProofStatus.POSSIBLE),
    ], [], [])
    planner = ScenarioPlanner(max_steps=4)
    exploratory = planner.exploratory_candidates([set_action, get_action], [], dependencies=deps)
    trial_post = planner.post_fuzz_candidates(
        [set_action, get_action], deps, exploratory, allow_hypotheses=True,
    )
    assert any([s.action_id for s in item.steps] == ["set", "get"]
               and item.fuzz_step_index == 0 for item in trial_post)
    assert any("PROVISIONAL_STATE_DEPENDENCY" in e
               for item in trial_post for e in item.planning_evidence)
    assert not planner.post_fuzz_candidates([set_action, get_action], deps, exploratory)


def test_backend_qualified_is_not_semantic_equivalence():
    from harnesscreator.models import CommandReport
    report = CommandReport(["clang"], 0, "", "", 0.1, False)
    result = VerificationResult(
        qualified=True, build=report, replays=[], fuzz=report,
        harness_faults=[], target_findings=[], coverage_grew=True,
        reachable_seed_count=1, reason="backend reached code",
    )
    audit = audit_qualification(result, witness=None, differential_evidence=False)
    assert audit.accepted is False
    assert "ORIGINAL_HARNESS_EQUIVALENCE_NOT_VERIFIED" in audit.blockers


def test_preflight_does_not_abort_source_discovery_without_compiler(tmp_path: Path, monkeypatch):
    import harnesscreator.runtime.preflight as preflight
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    spec = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path / "out",
        build_command=["python", "-m", "harnesscreator.runtime.native_build"],
    ).normalized()
    result = inspect_capabilities(spec)
    assert result["native_build_selected"]
    assert result["verification_blockers"]
    assert "non-blocking" in result["policy"]


def test_preflight_reports_gdb_request_attribution_blocker_before_analysis(tmp_path: Path):
    executable = tmp_path / "daemon"
    executable.write_text("fixture")
    spec = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path / "out",
        scenario_command=[str(executable)], scenario_attribution="gdb",
    ).normalized()
    result = inspect_capabilities(spec)
    assert not result["strict_request_attribution_configured"]
    assert any(
        item.startswith("EXACT_REQUEST_ATTRIBUTION_UNAVAILABLE:")
        for item in result["verification_blockers"]
    )


def test_preflight_distinguishes_gdb_line_tables_before_exploration(tmp_path: Path):
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("C compiler unavailable")
    source = tmp_path / "daemon.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    for flags, expected in ((["-g"], True), (["-g0"], False)):
        executable = tmp_path / ("debug" if expected else "release")
        subprocess.run([cc, *flags, str(source), "-o", str(executable)], check=True)
        spec = ProjectSpec(
            source_root=tmp_path, output_root=tmp_path / "out",
            scenario_command=[str(executable)], scenario_attribution="gdb",
            scenario_exploratory_drafts=True,
        ).normalized()
        report = inspect_capabilities(spec)
        assert report["gdb_embedded_line_info"] is expected
        assert any(
            item.startswith("GDB_SOURCE_LINES_NOT_EMBEDDED:")
            for item in report["verification_blockers"]
        ) is not expected


def test_preflight_missing_optional_elf_reader_is_unknown(tmp_path: Path, monkeypatch):
    binary = tmp_path / "daemon"
    binary.write_bytes(b"not an ELF file")
    original_import = builtins.__import__

    def missing_elftools(name, *args, **kwargs):
        if name.startswith("elftools"):
            raise ImportError("optional ELF reader unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_elftools)
    assert _embedded_gdb_line_info(binary) is None


def test_preflight_trace_is_only_a_configured_contract(tmp_path: Path):
    executable = tmp_path / "daemon"
    executable.write_text("fixture")
    spec = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path / "out",
        scenario_command=[str(executable)], scenario_attribution="trace",
    ).normalized()
    result = inspect_capabilities(spec)
    assert result["strict_request_attribution_configured"]
    assert "must actually emit" in result["strict_request_attribution_note"]
    assert not any(
        item.startswith("EXACT_REQUEST_ATTRIBUTION_UNAVAILABLE:")
        for item in result["verification_blockers"]
    )


def test_preflight_reports_native_oss_fuzz_cannot_qualify(tmp_path: Path):
    executable = tmp_path / "daemon"
    executable.write_text("fixture")
    spec = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path / "out",
        scenario_command=[str(executable)], scenario_attribution="trace",
        verification_backend="oss-fuzz", oss_fuzz_project="sample",
        oss_fuzz_fuzzer="fuzzer_sample", oss_fuzz_source_path="/src/sample",
    ).normalized()
    result = inspect_capabilities(spec)
    assert result["strict_request_attribution_configured"]
    assert any(
        item.startswith("OSS_FUZZ_NATIVE_DIAGNOSTIC_ONLY:")
        for item in result["verification_blockers"]
    )


def test_default_run_stops_before_analysis_when_gdb_cannot_qualify(tmp_path: Path):
    args = build_parser().parse_args([
        "run", str(tmp_path), "--output", str(tmp_path / "out"),
        "--scenario-command", "/bin/true",
    ])
    assert args.source_only_drafts is None
    with pytest.raises(ValueError, match="cannot QUALIFY a harness"):
        asyncio.run(_run(args))
    assert not (tmp_path / "out").exists()


def test_matching_startup_crash_is_not_attributed_to_unread_request():
    planned = ScenarioPlanner().exploratory_candidates([action("read", b"READ")], [])[0]
    step = planned.steps[0]
    observation = RuntimeStepObservation(
        index=step.index, action_id=step.action_id,
        request_hex=step.request_hex, response_hex="", success=False,
        detail="original crashed", duration_seconds=0.01,
        request_write_completed=True,
        entry_reached=True,
        target_probe="GDB ordered Entry-to-handler breakpoint trace",
    )
    witness = ScenarioWitness(
        witness_id="crash", scenario_id=planned.scenario_id,
        target_action_id=planned.target_action_id,
        steps=planned.steps, observations=[observation],
        command=["daemon"], channel="tcp", process_returncode=-11,
        status=ScenarioStatus.REJECTED, rationale="crashed",
        original_program_crashed=True, fuzz_step_index=step.index,
    )
    assert not _crash_replay_has_exact_input_acquisition(witness, step.index)
    traced = replace(observation,
        target_probe="request-correlated-jsonl-v1",
        probe_trace=["acquire:reader:req-1:connection-1"],
    )
    assert _crash_replay_has_exact_input_acquisition(
        replace(witness, observations=[traced]), step.index,
    )


def test_one_shot_original_crash_keeps_signature_without_claiming_input_cause(
    tmp_path: Path,
):
    diagnostic = (
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "#0 0x1 in parse /src/parser.c:42\n"
    )
    script = (
        "import os,sys; sys.stderr.write(" + repr(diagnostic) + "); "
        "sys.stderr.flush(); os.abort()"
    )
    project = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path / "out",
        scenario_command=[sys.executable, "-c", script, "{input_arg}"],
        scenario_channel="argv", scenario_require_target_reach=False,
    ).normalized()
    candidate = ScenarioCandidate(
        scenario_id="one-shot", target_action_id="arg",
        steps=[ScenarioStep(0, "arg", "entry", b"X".hex(), {}, [])],
        required_entries=["entry"], satisfied_resources=[],
        planning_evidence=[], fuzz_step_index=0,
    )
    original = replace(action("arg"), channel_kind="argv", source_api="argv")
    witness = asyncio.run(ScenarioRuntimeVerifier(
        project, [original],
    ).verify(candidate, use_cache=False))
    assert witness.original_program_crashed
    assert witness.crash_signature is not None
    assert witness.crash_signature.normalized_frames[0] == "parse@parser.c:42"
    assert not _crash_replay_has_exact_input_acquisition(witness, 0)


