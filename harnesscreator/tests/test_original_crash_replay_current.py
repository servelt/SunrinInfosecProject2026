"""Current crash gate: only a matching fresh original-process crash is reportable."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.models import (
    ActionExample, CrashReproductionStatus, Evidence, ExternalActionSchema,
    ProjectSpec, ProofStatus, ScenarioStatus, ScenarioStep, ScenarioWitness,
    SeedSpec,
)
from harnesscreator.runtime.crash import extract_crash_signature
from harnesscreator.runtime.scenario import OriginalCrashReproducer, ScenarioRuntimeVerifier


def test_harness_only_crash_is_not_promoted_and_matching_original_is(tmp_path: Path):
    asyncio.run(_exercise_crash_replay(tmp_path))


async def _exercise_crash_replay(tmp_path: Path):
    diagnostic = (
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "#0 0x1 in target_bug /src/target.c:42\n"
    )
    script = (
        "import os,sys\n"
        "for line in sys.stdin.buffer:\n"
        f"  if line.startswith(b'CRASH'): sys.stderr.write({diagnostic!r}); "
        "sys.stderr.flush(); os.abort()\n"
        "  sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
    )
    project = ProjectSpec(
        source_root=tmp_path,
        output_root=tmp_path / "runs",
        require_fuzz_introspector=False,
        scenario_command=[sys.executable, "-u", "-c", script],
        scenario_channel="stdin",
        scenario_attribution="trace",
        scenario_require_target_reach=False,
    ).normalized()
    evidence = [Evidence("source", "fn-request", "target.c", 42, "fixture")]
    action = ExternalActionSchema(
        action_id="request", entry_id="entry-stdin", name="request",
        description="request", dispatcher_function_id="fn-request",
        handler_function_id="fn-request", discriminator="request",
        channel_kind="stdin", fields=[],
        examples=[ActionExample(b"OK\n".hex(), {})],
        success_markers_hex=[b"OK\n".hex()], failure_markers_hex=[],
        evidence=evidence, inspected_function_ids=["fn-request"],
        status=ProofStatus.POSSIBLE, source_api="read",
        entry_function_id="fn-entry",
    )
    step = ScenarioStep(0, "request", "entry-stdin", b"OK\n".hex(), {}, [b"OK\n".hex()])
    # This observation deliberately has no correlated trace. The plan is an
    # explicit diagnostic draft; the crash replay test does not promote it.
    draft_witness = ScenarioWitness(
        witness_id="draft", scenario_id="draft", target_action_id="request",
        steps=[step], observations=[], command=project.scenario_command,
        channel="stdin", process_returncode=0,
        status=ScenarioStatus.OBSERVED_RUNTIME, rationale="diagnostic draft",
    )
    plan = build_harness_plan(
        draft_witness,
        action_function_ids={"request": ("fn-entry", "fn-request")},
        allow_observed=True,
    )
    verifier = ScenarioRuntimeVerifier(project, [action])
    expected = extract_crash_signature(diagnostic)
    replays = await OriginalCrashReproducer(verifier).reproduce(
        "harness-draft", plan,
        [
            SeedSpec("harness-only", b"BAD\n".hex(), "diagnostic", crash_signature=expected),
            SeedSpec("original-crash", b"CRASH\n".hex(), "diagnostic", crash_signature=expected),
        ],
    )
    assert replays[0].status is CrashReproductionStatus.UNCONFIRMED
    assert replays[1].status is CrashReproductionStatus.ORIGINAL_REPRODUCED, (
        replays[1].observation.status, replays[1].observation.rationale,
        replays[1].observation.sanitizer_output,
        replays[1].observation.process_returncode,
    )
    assert replays[1].input_attributed is False
    assert "causality" in replays[1].rationale
    assert replays[1].signature_matched
