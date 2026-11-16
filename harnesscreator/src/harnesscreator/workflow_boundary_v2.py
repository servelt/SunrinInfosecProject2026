"""Incremental post-Entry scheduler for source-backed C boundaries."""

from __future__ import annotations

import asyncio
import hashlib
from itertools import count
import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from .agents.behavior import BehaviorCandidate, BehaviorRecoveryAgent
from .agents.boundary_harness import BoundaryHarnessGeneratorAgent, BoundaryStaticGate
from .agents.execution_contract import ExecutionContract, ExecutionContractAgent, LifecycleCall
from .agents.input_surfaces import InputSurfaceAgent, InputSurfaceCase
from .analysis.graph import GraphStore
from .llm.base import LLMProvider, is_terminal_llm_infrastructure_error
from .models import (
    AnalysisBundle, CheckStatus, EntryRecord, EntrySiteKind, Evidence, ProofStatus,
    ProjectSpec, ScenarioRunSummary, SeedSpec, Verdict, unique_strings,
)
from .runtime.boundary import BoundaryTrialRunner, select_backend, source_transport
from .runtime.boundary_work import (
    WorkLedger, canonicalize_behaviors, plan_entries,
    prioritize_work_units, snapshot_path,
)
from .runtime.runner import CommandRunner, HarnessVerifierAgent
from .storage import ArtifactStore
from .tracing import TraceCallback


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _boundary_status(
    *, has_entries: bool, has_behaviors: bool, has_build: bool,
    has_generated: bool, blocked_statuses: set[str],
) -> str:
    if not has_entries:
        return "NO_EXTERNAL_ENTRIES"
    if not has_behaviors:
        return "NO_SOURCE_BEHAVIOR"
    if has_build:
        return "BUILD_VERIFIED_UNQUALIFIED"
    if has_generated:
        return "SOURCE_DRAFTS_UNQUALIFIED"
    unsupported = "BLOCKED_UNSUPPORTED_BACKEND" in blocked_statuses
    evidence = "BLOCKED_EVIDENCE" in blocked_statuses
    if unsupported and evidence:
        return "BLOCKED_UNSUPPORTED_BACKEND_AND_EVIDENCE"
    if unsupported:
        return "BLOCKED_UNSUPPORTED_BACKEND"
    if evidence:
        return "BLOCKED_EVIDENCE"
    return "INCOMPLETE_SOURCE_OR_LIFECYCLE_EVIDENCE"


def _evidence(raw: dict) -> Evidence:
    return Evidence(**raw)


def _behavior(raw: dict) -> BehaviorCandidate:
    raw["evidence"] = [_evidence(item) for item in raw.get("evidence", [])]
    raw["status"] = ProofStatus(raw.get("status", "POSSIBLE"))
    return BehaviorCandidate(**raw)


def _contract(raw: dict) -> ExecutionContract:
    raw["calls"] = [LifecycleCall(**{
        **item, "evidence": [_evidence(e) for e in item.get("evidence", [])]
    }) for item in raw.get("calls", [])]
    raw["repeatability_evidence"] = [
        _evidence(item) for item in raw.get("repeatability_evidence", [])
    ]
    return ExecutionContract(**raw)


def _case(raw: dict) -> InputSurfaceCase:
    raw["evidence"] = [_evidence(item) for item in raw.get("evidence", [])]
    return InputSurfaceCase(**raw)


def _merge_unique(rows: list[Any], additions: list[Any], key: str) -> None:
    indices = {
        (row.get(key) if isinstance(row, dict) else getattr(row, key)): index
        for index, row in enumerate(rows)
    }
    for row in additions:
        identifier = row.get(key) if isinstance(row, dict) else getattr(row, key)
        if identifier in indices:
            rows[indices[identifier]] = row
        else:
            indices[identifier] = len(rows)
            rows.append(row)


def _load_completed_work(store: ArtifactStore) -> tuple[
    list[BehaviorCandidate], list[ExecutionContract], list[InputSurfaceCase], list[dict],
]:
    """Rebuild cumulative inventories from immutable per-work snapshots."""
    root = store.root / "workflow" / "work-items"
    behaviors: list[BehaviorCandidate] = []
    contracts: list[ExecutionContract] = []
    cases: list[InputSurfaceCase] = []
    trials: list[dict] = []
    if not root.exists():
        return behaviors, contracts, cases, trials
    for folder in sorted(path for path in root.iterdir() if path.is_dir()):
        completed = folder / "behavior.json"
        partial = folder / "behavior.partial-candidates.json"
        source = completed if completed.is_file() else partial
        if source.is_file():
            _merge_unique(behaviors, [_behavior(row) for row in _read_json(source)], "behavior_id")
        contract = folder / "contract.json"
        if contract.is_file():
            _merge_unique(contracts, [_contract(_read_json(contract))], "contract_id")
        input_surfaces = folder / "input-surfaces.json"
        if input_surfaces.is_file():
            _merge_unique(cases, [_case(row) for row in _read_json(input_surfaces)], "case_id")
        trial = folder / "original-trial.json"
        if trial.is_file():
            _merge_unique(trials, [_read_json(trial)], "trial_id")
    return behaviors, contracts, cases, trials


async def run_boundary_workflow_v2(
    *, project: ProjectSpec, run_id: str, store: ArtifactStore,
    analysis: AnalysisBundle, graph: GraphStore, llm: LLMProvider,
    trace: TraceCallback | None, candidates: list[Any],
    verified: list[EntryRecord], unresolved: list[EntryRecord],
    uninspected_functions: int, max_generation_attempts: int,
    dynamic_verification: bool,
    progress: Callable[[str], None] | None = None,
) -> ScenarioRunSummary:
    def emit(message: str) -> None:
        if progress:
            progress(message)

    started = time.monotonic()
    deadline = started + project.boundary_total_seconds
    ledger = WorkLedger(store)
    uncertain = [item for item in unresolved
                 if item.status is Verdict.UNRESOLVED
                 and item.site_kind in {EntrySiteKind.DIRECT_ACQUISITION,
                                        EntrySiteKind.EXTERNAL_CALLBACK}
                 and item.entry_function_id in graph.bundle.functions
                 and item.entry_line is not None
                 and any(e.function_id == item.entry_function_id and e.line == item.entry_line
                         for e in item.evidence)]
    entries = [*verified, *uncertain]
    by_entry = {item.entry_id: item for item in entries}
    decisions = plan_entries(
        entries, scenario_channel=project.scenario_channel,
        scenario_command=project.scenario_command, scenario_port=project.scenario_port,
        scenario_input_env=project.scenario_input_env,
    )
    store.write_jsonl("workflow/entry-decisions.jsonl", decisions)
    emit(f"post-Entry: {len(entries)} source candidates; "
         f"{sum(d.disposition == 'SELECTED' for d in decisions)} configured trial candidates")

    behaviors, contracts, raw_cases, trials = _load_completed_work(store)
    engine_plans: list[Any] = []
    obligations: list[str] = []
    inventory_path = store.root / "harnesses" / "inventory.jsonl"
    harness_rows: list[dict[str, Any]] = [
        json.loads(line) for line in inventory_path.read_text(encoding="utf-8").splitlines()
        if line
    ] if inventory_path.exists() else []
    unit_inventory_path = store.root / "workflow" / "work-unit-inventory.jsonl"
    unit_ids = {
        json.loads(line)["work_id"]
        for line in unit_inventory_path.read_text(encoding="utf-8").splitlines() if line
    } if unit_inventory_path.exists() else set()
    generated_ids: set[str] = set()
    static_passed_ids: set[str] = set()
    build_passed_ids: set[str] = set()
    blocked = 0
    attempts = len({(row.get("work_id", row.get("behavior_id")), row.get("attempt"))
                    for row in harness_rows})
    infra_errors: list[str] = []
    verify_infra: list[str] = []
    for row in harness_rows:
        key = row.get("work_id", row.get("behavior_id", ""))
        if row.get("generated"):
            generated_ids.add(key)
        if row.get("static_passed"):
            static_passed_ids.add(key)
        if row.get("build_ok"):
            build_passed_ids.add(key)
    drafts_started = len({row.get("work_id", row.get("behavior_id")) for row in harness_rows})
    trial_runner = BoundaryTrialRunner(project)
    generator = BoundaryHarnessGeneratorAgent(
        llm, graph, project,
        max_function_turns=project.boundary_function_turns or None, trace=trace,
    )
    static_gate = BoundaryStaticGate(graph)
    verifier = HarnessVerifierAgent(CommandRunner(), project, graph, progress=progress)

    async def bounded(stage: str, work_id: str, operation: Any) -> Any:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # Callers construct the coroutine before entering this helper.
            # Close it when the resource budget has already expired.
            if hasattr(operation, "close"):
                operation.close()
            ledger.mark(work_id, stage, "DEFERRED_BUDGET", "total boundary time budget exhausted")
            return None
        ledger.mark(work_id, stage, "STARTED", "stage execution started",
                    resource_seconds=min(project.boundary_task_seconds, remaining))
        stage_started = time.monotonic()
        try:
            result = await asyncio.wait_for(
                operation, timeout=min(project.boundary_task_seconds, remaining),
            )
        except asyncio.TimeoutError:
            ledger.mark(work_id, stage, "DEFERRED_BUDGET",
                        "resource time exhausted; path remains unresolved",
                        elapsed_seconds=round(time.monotonic() - stage_started, 3))
            return None
        except Exception as exc:
            if is_terminal_llm_infrastructure_error(exc):
                raise
            problem = f"{type(exc).__name__}: {exc}"
            ledger.mark(work_id, stage, "FAILED_IMPLEMENTATION", problem,
                        elapsed_seconds=round(time.monotonic() - stage_started, 3))
            infra_errors.append(f"{work_id}/{stage}: {problem}")
            return None
        ledger.mark(work_id, stage, "COMPLETED", "stage output persisted",
                    elapsed_seconds=round(time.monotonic() - stage_started, 3))
        return result

    # Product-specific request vectors belong to independent regression
    # fixtures. A protocol parser choice or source directory name does not
    # establish which functions or startup flags the product uses.
    runtime_navigation_hints: dict[str, list[str]] = {}

    pending_units: list[tuple[EntryRecord, list[BehaviorCandidate], Any]] = []

    async def process_unit(
        entry: EntryRecord, entry_behaviors: list[BehaviorCandidate], unit: Any,
    ) -> None:
        nonlocal blocked, attempts, drafts_started
        if time.monotonic() >= deadline:
            ledger.mark(unit.work_id, "selection", "DEFERRED_BUDGET",
                        "total resource budget exhausted; effect remains possible")
            return
        representative = next(row for row in entry_behaviors
                              if row.behavior_id == unit.behavior_ids[0])
        merged = replace(representative, evidence=unit.evidence,
                         unknowns=unit.unknowns,
                         path_variants=unit.path_variants)
        contract_path = snapshot_path(store, unit.work_id, "contract")
        if ledger.finished(unit.work_id, "contract") and contract_path.exists():
            contract = _contract(_read_json(contract_path))
        else:
            contract_partial = store.root / "workflow" / "work-items" / unit.work_id / "contract.partial.json"
            initial_contract_state = _read_json(contract_partial) if contract_partial.exists() else None
            def checkpoint(_behavior_id: str, partial: dict[str, Any]) -> None:
                store.write_json(
                    f"workflow/work-items/{unit.work_id}/contract.partial.json", partial,
                )
            agent = ExecutionContractAgent(
                llm, graph,
                max_function_turns=project.boundary_function_turns or None,
                trace=trace, checkpoint=checkpoint,
                initial_state=initial_contract_state,
            )
            async def recover_contract() -> ExecutionContract | None:
                result = await agent.run([merged], {entry.entry_id: source_transport(entry)})
                if result:
                    store.write_json(
                        f"workflow/work-items/{unit.work_id}/contract.json", result[0],
                    )
                return result[0] if result else None
            contract = await bounded("contract", unit.work_id, recover_contract())
            obligations.extend(agent.obligations)
        if contract is None:
            ledger.mark(unit.work_id, "backend", "BLOCKED_EVIDENCE",
                        "execution contract missing; required lifecycle and repeatability evidence")
            blocked += 1
            return
        _merge_unique(contracts, [contract], "contract_id")
        store.write_jsonl("execution-contracts/candidates.jsonl", contracts)
        if project.scenario_attribution == "trace" and project.scenario_command:
            relevant_cases = [case for case in raw_cases if case.entry_id == entry.entry_id]
            for case in relevant_cases[:project.max_scenario_candidates]:
                stage = f"attributed-trial-{case.case_id}"
                trial_path = snapshot_path(store, unit.work_id, f"attributed-{case.case_id}")
                if ledger.finished(unit.work_id, stage) and trial_path.exists():
                    continue
                trace_file = store.root / "boundary-trials" / "request-traces" / (
                    f"{unit.work_id}-{case.case_id}.jsonl"
                )
                async def attributed() -> Any:
                    trial = await trial_runner.run_attributed(
                        case, entry, merged.target_function_id,
                        trace_file,
                    )
                    store.write_json(
                        f"workflow/work-items/{unit.work_id}/attributed-{case.case_id}.json",
                        trial,
                    )
                    return trial
                trial = await bounded(stage, unit.work_id, attributed())
                if trial is not None:
                    store.append_jsonl("boundary-trials/attributed-observations.jsonl", trial)
            for case in relevant_cases[project.max_scenario_candidates:]:
                ledger.mark(unit.work_id, f"attributed-trial-{case.case_id}",
                            "SKIPPED_LIMIT", "configured trial resource limit reached")
        plan = select_backend(contract)
        engine_plans.append(plan)
        store.write_jsonl("execution-contracts/backend-plans.jsonl", engine_plans)
        if not plan.backend_implemented:
            status = ("BLOCKED_EVIDENCE" if plan.selected_backend == "none"
                      else "BLOCKED_UNSUPPORTED_BACKEND")
            ledger.mark(unit.work_id, "backend", status, plan.rationale,
                        required_execution=plan.required_execution,
                        selected_backend=plan.selected_backend)
            blocked += 1
            return
        ledger.mark(unit.work_id, "backend", "COMPLETED", plan.rationale,
                    selected_backend=plan.selected_backend)
        if drafts_started >= project.max_source_drafts:
            ledger.mark(unit.work_id, "generation", "SKIPPED_LIMIT",
                        "configured source draft capacity reached; path remains possible")
            return
        if ledger.finished(unit.work_id, "generation"):
            return
        drafts_started += 1
        feedback: list[str] = []
        seen_failed_drafts: set[tuple[str, tuple[str, ...]]] = set()
        latest_draft_digest = ''
        success = False
        try:
            for attempt in (count(1) if max_generation_attempts == 0
                            else range(1, max_generation_attempts + 1)):
                feedback_start = len(feedback)
                attempt_stage = f"generation-attempt-{attempt}"
                previous = next((row for row in harness_rows
                                 if row.get("work_id") == unit.work_id
                                 and row.get("attempt") == attempt), None)
                if ledger.finished(unit.work_id, attempt_stage) and previous is not None:
                    feedback = list(previous.get("blockers", []))
                    if previous.get("build_verified_draft"):
                        success = True
                        break
                    continue
                attempts += 1
                attempt_dir = f"harnesses/{unit.work_id}/attempt-{attempt}"
                target_dir = store.directory(attempt_dir)
                async def generate_attempt() -> bool:
                    nonlocal latest_draft_digest
                    result = await generator.run(merged, contract, feedback=feedback)
                    draft = result.draft
                    latest_draft_digest = hashlib.sha256(
                        draft.code.encode('utf-8')
                    ).hexdigest()
                    store.write_json(f"{attempt_dir}/draft.json", draft)
                    if draft.code:
                        store.write_text(f"{attempt_dir}/{draft.manifest.source_file}", draft.code)
                        generated_ids.add(unit.work_id)
                    gate = static_gate.check(draft, merged, contract)
                    store.write_json(f"{attempt_dir}/static-gate.json", gate)
                    if not draft.code:
                        feedback.extend(draft.generation_blockers)
                        return False
                    independent = await generator.review(merged, contract, draft, gate)
                    store.write_json(f"{attempt_dir}/independent-audit.json", independent)
                    if independent.passed and not gate.has_failures and not draft.generation_blockers:
                        static_passed_ids.add(unit.work_id)
                    feedback.extend(
                        f"{check.check_id}: {check.evidence}; repair: {check.remediation}"
                        for report in (gate, independent)
                        for check in report.checks if check.status is not CheckStatus.PASS
                    )
                    feedback.extend(draft.generation_blockers)
                    report = None
                    if not gate.has_failures and not draft.generation_blockers:
                        seeds: list[SeedSpec] = []
                        if dynamic_verification:
                            from .workflow_boundary import _adversarial_seeds
                            original_cases = [
                                case for case in raw_cases if case.entry_id == entry.entry_id
                            ]
                            seeds.extend(SeedSpec(
                                name=f"original-{case.case_id}", data_hex=case.data_hex,
                                rationale=case.rationale, check_ids=[],
                            ) for case in original_cases)
                            adversarial, problems = await _adversarial_seeds(
                                llm, draft, feedback=feedback,
                            )
                            seeds.extend(adversarial)
                            store.write_json(f"{attempt_dir}/adversarial-seeds.json",
                                             {"seeds": seeds, "obligations": problems})
                        report = await verifier.verify(
                            draft, target_dir, seeds, runtime_checks=dynamic_verification,
                        )
                        store.write_json(f"{attempt_dir}/verification.json", report)
                        if report.infrastructure_error:
                            verify_infra.append(report.infrastructure_error)
                        if report.build_ok:
                            build_passed_ids.add(unit.work_id)
                        if report.reason:
                            feedback.append(f"independent verifier: {report.reason}")
                        feedback.extend(report.harness_faults)
                    achieved = bool(
                        report and report.build_ok and independent.passed
                        and not gate.has_failures and not draft.generation_blockers
                        and not report.harness_faults
                        and (not dynamic_verification or (
                            report.fuzz is not None and report.fuzz.returncode == 0
                            and not report.fuzz.timed_out
                            and all(replay.returncode == 0 and not replay.timed_out
                                    for replay in report.replays)
                        ))
                    )
                    row = {
                        "work_id": unit.work_id, "behavior_id": merged.behavior_id,
                        "attempt": attempt, "generated": bool(draft.code),
                        "static_passed": unit.work_id in static_passed_ids,
                        "build_ok": bool(report and report.build_ok),
                        "replay_executed": bool(report and report.replays),
                        "fuzz_executed": bool(report and report.fuzz),
                        "coverage_grew": report.coverage_grew if report else None,
                        "build_verified_draft": achieved, "qualified": False,
                        "original_handler_attributed": False,
                        "blockers": unique_strings(feedback),
                    }
                    harness_rows.append(row)
                    store.write_jsonl("harnesses/inventory.jsonl", harness_rows)
                    return achieved
                outcome = await bounded(attempt_stage, unit.work_id,
                                        generate_attempt())
                if outcome:
                    success = True
                    break
                if outcome is None:
                    break
                failure_signature = (
                    latest_draft_digest,
                    tuple(sorted(set(feedback[feedback_start:]))),
                )
                if failure_signature in seen_failed_drafts:
                    feedback.append(
                        "generation stopped: identical draft and failure evidence repeated"
                    )
                    break
                seen_failed_drafts.add(failure_signature)
        finally:
            await generator.close_session(merged)
        ledger.mark(unit.work_id, "generation",
                    "COMPLETED" if success else "BLOCKED_EVIDENCE",
                    "build-verified draft; differential path proof still required" if success
                    else "; ".join(unique_strings(feedback)) or "generation or verification incomplete")
        if not success:
            blocked += 1
    for decision in decisions:
        entry = by_entry[decision.entry_id]
        if decision.disposition != "SELECTED":
            ledger.mark(entry.entry_id, "selection", "DEFERRED_CONFIGURATION", decision.reason)
            continue
        if time.monotonic() >= deadline:
            ledger.mark(entry.entry_id, "selection", "DEFERRED_BUDGET",
                        "total boundary time budget exhausted; Entry not disproven")
            continue
        ledger.mark(entry.entry_id, "selection", "COMPLETED", decision.reason)
        behavior_path = snapshot_path(store, entry.entry_id, "behavior")
        if ledger.finished(entry.entry_id, "behavior") and behavior_path.exists():
            entry_behaviors = [_behavior(row) for row in _read_json(behavior_path)]
        else:
            partial_path = store.root / "workflow" / "work-items" / entry.entry_id / "behavior.partial.json"
            initial_state = _read_json(partial_path) if partial_path.exists() else None
            def behavior_checkpoint(_entry_id: str, partial: dict[str, Any]) -> None:
                store.write_json(
                    f"workflow/work-items/{entry.entry_id}/behavior.partial.json", partial,
                )
            agent = BehaviorRecoveryAgent(
                llm, graph,
                max_function_turns=project.boundary_function_turns or None,
                trace=trace, checkpoint=behavior_checkpoint,
                initial_state=initial_state,
                runtime_navigation_hints=runtime_navigation_hints,
            )
            # Persist before logging completion, so an interrupted run can
            # reuse the exact finished work without another model call.
            async def recover() -> list[BehaviorCandidate]:
                result = await agent.run([entry])
                store.write_json(f"workflow/work-items/{entry.entry_id}/behavior.json", result)
                return result
            entry_behaviors = await bounded("behavior", entry.entry_id, recover())
            if entry_behaviors is None and partial_path.exists():
                partial = _read_json(partial_path)
                entry_behaviors = agent.materialize(
                    entry, partial.get("opened_function_ids", []),
                    partial.get("raw_behaviors", []), False,
                )
                store.write_json(
                    f"workflow/work-items/{entry.entry_id}/behavior.partial-candidates.json",
                    entry_behaviors,
                )
            entry_behaviors = entry_behaviors or []
            obligations.extend(agent.obligations)
        _merge_unique(behaviors, entry_behaviors, "behavior_id")
        store.write_jsonl("behaviors/candidates.jsonl", behaviors)

        case_path = snapshot_path(store, entry.entry_id, "input-surfaces")
        if ledger.finished(entry.entry_id, "input-surfaces") and case_path.exists():
            entry_cases = [_case(row) for row in _read_json(case_path)]
        else:
            agent = InputSurfaceAgent(
                llm, graph, project,
                max_function_turns=project.boundary_function_turns,
                trace=trace,
            )
            async def sample() -> list[InputSurfaceCase]:
                result = await agent.run([entry])
                store.write_json(f"workflow/work-items/{entry.entry_id}/input-surfaces.json", result)
                return result
            entry_cases = await bounded("input-surfaces", entry.entry_id, sample()) or []
            obligations.extend(agent.obligations)
        _merge_unique(raw_cases, entry_cases, "case_id")
        store.write_jsonl("input-surfaces/inventory.jsonl", raw_cases)
        for case in entry_cases:
            if not project.scenario_command:
                ledger.mark(case.case_id, "original-trial", "DEFERRED_CONFIGURATION",
                            "trusted original command absent")
                continue
            trial_path = snapshot_path(store, case.case_id, "original-trial")
            if ledger.finished(case.case_id, "original-trial") and trial_path.exists():
                trial = _read_json(trial_path)
            else:
                async def replay() -> Any:
                    result = await trial_runner.run(case, entry)
                    store.write_json(f"workflow/work-items/{case.case_id}/original-trial.json", result)
                    return result
                trial = await bounded("original-trial", case.case_id, replay())
            if trial is not None:
                _merge_unique(trials, [trial], "trial_id")
                store.write_jsonl("boundary-trials/original-observations.jsonl", trials)

        units = canonicalize_behaviors(entry_behaviors)
        ranked_units = prioritize_work_units(
            units, entry_behaviors, runtime_navigation_hints.get(entry.entry_id, []),
        )
        store.write_json(f"workflow/work-items/{entry.entry_id}/units.json",
                         [unit for unit, _signals in ranked_units])
        for index, (unit, signals) in enumerate(ranked_units):
            if unit.work_id not in unit_ids:
                store.append_jsonl("workflow/work-unit-inventory.jsonl", unit)
                unit_ids.add(unit.work_id)
            if index == 0:
                ledger.mark(unit.work_id, "selection", "PRIORITIZED",
                            "source evidence and runtime navigation hint priority; "
                            "effect remains unproven", **signals)
                await process_unit(entry, entry_behaviors, unit)
            else:
                ledger.mark(unit.work_id, "selection", "QUEUED",
                            "queued behind higher-priority source candidate for this Entry",
                            **signals)
                pending_units.append((entry, entry_behaviors, unit))

    for entry, entry_behaviors, unit in pending_units:
        await process_unit(entry, entry_behaviors, unit)
    store.write_json("workflow/boundary-evidence-audit.json", {
        "mode": "boundary-v2", "source_obligations": unique_strings(obligations),
        "model_errors": infra_errors, "verifier_errors": verify_infra,
        "original_trials": len(trials), "runtime_attribution": "NOT_ESTABLISHED",
        "qualification": "UNQUALIFIED until request-correlated original/harness path comparison",
        "elapsed_seconds": round(time.monotonic() - started, 3),
    })
    blocked_events = [
        event for event in ledger.latest_events()
        if event["stage"] in {"backend", "generation"}
        and event["status"] in {"BLOCKED_UNSUPPORTED_BACKEND", "BLOCKED_EVIDENCE"}
    ]
    blocked_ids = {event["work_id"] for event in blocked_events}
    status = _boundary_status(
        has_entries=bool(entries), has_behaviors=bool(behaviors),
        has_build=bool(build_passed_ids), has_generated=bool(generated_ids),
        blocked_statuses={event["status"] for event in blocked_events},
    )
    summary = ScenarioRunSummary(
        run_id=run_id, analysis_functions=len(analysis.functions),
        analysis_provider=str(analysis.completeness.get("provider", "unknown")),
        analysis_authoritative=bool(analysis.completeness.get("authoritative", False)),
        fuzz_introspector_used=bool(analysis.completeness.get("fuzz_introspector_used", False)),
        svf_status=str(analysis.completeness.get("svf_status", "UNKNOWN")),
        svf_used=bool(analysis.completeness.get("svf_used", False)),
        svf_indirect_edges_reported=int(analysis.completeness.get("svf_indirect_edges_reported", 0)),
        svf_indirect_edges_mapped=int(analysis.completeness.get("svf_indirect_edges_mapped", 0)),
        svf_indirect_edges_unmapped=len(analysis.completeness.get("svf_mapping_failures", []) or []),
        candidates=len(candidates), verified_entries=len(verified), unresolved_entries=len(unresolved),
        action_schemas=0, state_contracts=0, scenario_candidates=0,
        scenario_witnesses=0, unproven_scenarios=0,
        harness_plans=drafts_started, generation_attempts=attempts,
        harnesses_generated=len(generated_ids), harnesses_static_passed=len(static_passed_ids),
        harnesses_build_passed=len(build_passed_ids), harnesses_blocked=len(blocked_ids),
        harnesses_qualified=0, original_crashes_reproduced=0,
        harness_artifacts=len(harness_rows), status=status, output_root=str(store.root),
        agent_infrastructure_failures=len(infra_errors),
        verification_infrastructure_failures=len(verify_infra),
        in_scope_unresolved_entries=len(uncertain),
        entry_generator_uninspected_functions=uninspected_functions,
        input_surface_cases=len(raw_cases), input_surface_runtime_trials=len(trials),
        input_surface_obligations=len(obligations), behavior_candidates=len(behaviors),
        execution_contracts=len(contracts), boundary_trials=len(trials),
    )
    store.write_json("summary.json", summary)
    emit(f"boundary workflow finished: {status}; generated={len(generated_ids)}; "
         f"build={len(build_passed_ids)}; qualified=0")
    return summary
