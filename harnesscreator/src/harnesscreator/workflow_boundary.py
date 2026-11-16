"""Default evidence-led workflow for non-library C programs and daemons.

No Action enumeration, branch taxonomy, SmallFeature, or LargeFeature is
required to produce an independently reviewed harness draft.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .agents.behavior import BehaviorRecoveryAgent
from .agents.boundary_harness import BoundaryHarnessGeneratorAgent, BoundaryStaticGate
from .agents.common import concurrent_map
from .agents.execution_contract import ExecutionContractAgent
from .agents.harness import CHECKLIST_NAMES, SEED_SCHEMA
from .agents.input_surfaces import InputSurfaceAgent
from .analysis.graph import GraphStore
from .llm.base import LLMProvider, close_llm_session, is_terminal_llm_infrastructure_error
from .models import (
    AnalysisBundle, CheckStatus, EntryRecord, EntrySiteKind, ProjectSpec,
    ScenarioRunSummary, SeedSpec, Verdict, as_json, unique_strings,
)
from .runtime.boundary import BoundaryTrialRunner, select_backend, source_transport
from .runtime.runner import CommandRunner, HarnessVerifierAgent
from .storage import ArtifactStore
from .tracing import TraceCallback


async def _adversarial_seeds(
    llm: LLMProvider, draft: Any, *, feedback: list[str],
) -> tuple[list[SeedSpec], list[str]]:
    """Independent P1/P2 adversarial samples; fallback runtime seeds remain."""
    key = f"boundary_seed_planner:{draft.manifest.harness_id}"
    problems: list[str] = []
    try:
        response = await llm.complete_json(
            role="harness_verifier", session_key=key, output_schema=SEED_SCHEMA,
            instructions=(
                "Propose 14-24 bounded adversarial raw byte inputs for this actual "
                "C libFuzzer callback. Do not assume commands, selectors, network "
                "framing, protocol states, or actions absent from the opened source. "
                "Target zero/minimum/boundary/maximum lengths, truncations, malformed "
                "length fields when applicable, embedded NULs, resource cleanup, "
                "lifecycle failures, repeated calls and state contamination. "
                "At least five candidates should seek to exercise real application "
                "calls if the declared input binding supports that. Every sample "
                "must be hex and no longer than the declared maximum. Connect "
                "each sample to applicable HC01..HC16. These samples are hypotheses "
                "and do not prove a real target defect."
            ),
            payload={
                "manifest": as_json(draft.manifest),
                "code": draft.code,
                "operation_protocols": draft.operation_protocols,
                "known_failure_feedback": feedback,
            },
        )
        used: set[bytes] = set()
        seeds = []
        for index, raw in enumerate(response.get("seeds", [])):
            if not isinstance(raw, dict):
                continue
            try:
                data = bytes.fromhex(str(raw.get("data_hex", "")))
            except ValueError:
                continue
            if len(data) > min(draft.manifest.max_size, 65_536) or data in used:
                continue
            used.add(data)
            checks = [str(check) for check in raw.get("check_ids", [])
                      if str(check) in CHECKLIST_NAMES]
            seeds.append(SeedSpec(
                name=f"adversarial-{index:02d}", data_hex=data.hex(),
                rationale=str(raw.get("rationale", "")), check_ids=checks,
            ))
        if len(seeds) < 12:
            problems.append(f"only {len(seeds)} unique bounded adversarial seeds")
        return seeds, problems
    except Exception as exc:
        problems.append(f"adversarial seed planning unavailable: {type(exc).__name__}: {exc}")
        return [], problems
    finally:
        await close_llm_session(llm, key)


async def run_boundary_workflow(
    *, project: ProjectSpec, run_id: str, store: ArtifactStore,
    analysis: AnalysisBundle, graph: GraphStore, llm: LLMProvider,
    trace: TraceCallback | None, candidates: list[Any],
    verified: list[EntryRecord], unresolved: list[EntryRecord],
    uninspected_functions: int, max_generation_attempts: int,
    dynamic_verification: bool,
    progress: Callable[[str], None] | None = None,
) -> ScenarioRunSummary:
    from .workflow_boundary_v2 import run_boundary_workflow_v2

    return await run_boundary_workflow_v2(
        project=project, run_id=run_id, store=store, analysis=analysis,
        graph=graph, llm=llm, trace=trace, candidates=candidates,
        verified=verified, unresolved=unresolved,
        uninspected_functions=uninspected_functions,
        max_generation_attempts=max_generation_attempts,
        dynamic_verification=dynamic_verification, progress=progress,
    )
