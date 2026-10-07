from __future__ import annotations

from dataclasses import replace
import re
import time
from pathlib import Path
from typing import Any, Callable

from .agents import (
    EntryGeneratorAgent,
    EntryVerifierAgent,
    HarnessGeneratorAgent,
    LargeFeatureAgent,
    SmallFeatureAgent,
)
from .agents.harness import _HarnessVerifierSeedPlanner, StaticHarnessGate
from .agents.common import concurrent_map
from .analysis import (
    FuzzIntrospectorError,
    FuzzIntrospectorRunner,
    GraphStore,
    StaticAnalyzer,
)
from .llm.base import LLMProvider, RecordingLLM
from .models import (
    AnalysisBundle,
    CheckStatus,
    EntryRecord,
    GateReport,
    HarnessDisposition,
    ProjectSpec,
    RunSummary,
    SeedSpec,
    VerificationResult,
    Verdict,
    as_json,
    large_feature_schedule_key,
    stable_id,
    unique_strings,
)
from .runtime import CommandRunner, HarnessVerifierAgent, QuartetOssFuzzVerifierAgent
from .storage import ArtifactStore
from .tracing import AgentTraceLogger


class HarnessCreator:
    def __init__(
        self,
        project: ProjectSpec,
        llm: LLMProvider,
        *,
        max_generation_attempts: int = 8,
        dynamic_verification: bool = True,
        progress: Callable[[str], None] | None = None,
        agent_debug_console: bool = False,
        precomputed_analysis: AnalysisBundle | None = None,
    ):
        self.project = project.normalized()
        self.llm = llm
        self.max_generation_attempts = max(1, max_generation_attempts)
        self.dynamic_verification = dynamic_verification
        self.progress = progress
        self.agent_debug_console = agent_debug_console
        self.precomputed_analysis = precomputed_analysis

    async def run(self) -> RunSummary:
        run_id = self._run_id()
        store = ArtifactStore(self.project.output_root / run_id)
        self._emit(f"run {run_id} started; artifacts={store.root}")
        analysis = self._prepare_static_analysis()
        effective_concurrency = int(getattr(self.llm, "max_concurrency", 1))
        role_models = dict(getattr(self.llm, "role_models", {}))
        reasoning_effort = getattr(self.llm, "effort", None)
        self._emit(f"effective LLM concurrency: {effective_concurrency}")
        self._emit(
            "LLM context sessions: sticky per Candidate/Feature/Harness; "
            "worker recycle is deferred until session close; same-thread "
            "context compaction is enabled"
        )
        store.write_json("project.json", self.project)
        store.write_json(
            "workflow.json",
            {
                "dynamic_verification": self.dynamic_verification,
                "max_generation_attempts": self.max_generation_attempts,
                "role_models": role_models,
                "reasoning_effort": reasoning_effort,
                "llm_session_policy": {
                    "stateful_context_walks": True,
                    "worker_affinity": True,
                    "recycle_deferred_until_session_close": True,
                    "stateful_resume_cache": True,
                    "stateful_resume_policy": "exact_ordered_whole_session",
                    "same_thread_context_compaction": True,
                    "context_compact_ratio": 0.70,
                    "context_token_reserve": 32000,
                    "small_feature_source_delta_turns": True,
                },
            },
        )
        trace_logger = AgentTraceLogger(
            store,
            console=self._emit if self.agent_debug_console else None,
        )
        trace = trace_logger.emit
        trace(
            "orchestrator",
            "run_started",
            {
                "message": f"run {run_id} started with LLM concurrency {effective_concurrency}",
                "run_id": run_id,
                "project": as_json(self.project),
                "effective_llm_concurrency": effective_concurrency,
                "role_models": role_models,
                "reasoning_effort": reasoning_effort,
            },
        )
        reported_records = 0

        def persist_record(record: dict[str, Any]) -> None:
            nonlocal reported_records
            store.append_jsonl("trajectories/llm.jsonl", record)
            if record.get("record_type") == "session_closed":
                return
            reported_records += 1
            self._emit(
                f"LLM {record.get('role')} {record.get('status')} "
                f"({float(record.get('duration_seconds', 0)):.1f}s, call {reported_records})"
            )

        traced_llm = RecordingLLM(self.llm, on_record=persist_record)

        store.write_jsonl("analysis/functions.jsonl", analysis.function_list())
        store.write_jsonl("analysis/edges.jsonl", analysis.edges)
        store.write_json("analysis/completeness.json", analysis.completeness)
        graph = GraphStore(analysis)
        self._emit(f"static analysis completed: {len(analysis.functions)} functions, {len(analysis.edges)} edges")
        if not analysis.completeness.get("authoritative", False):
            self._emit(f"WARNING: {analysis.completeness.get('warning', 'non-authoritative analysis')}")
        trace(
            "static_analysis",
            "completed",
            {
                "message": f"indexed {len(analysis.functions)} functions and {len(analysis.edges)} edges",
                "function_count": len(analysis.functions),
                "edge_count": len(analysis.edges),
                "completeness": analysis.completeness,
            },
        )

        entry_generator = EntryGeneratorAgent(
            traced_llm, chunk_size=self.project.entry_batch_size, trace=trace
        )
        estimated_batches = len(entry_generator.batches(analysis))
        self._emit(f"entry generation started: {estimated_batches} LLM batches")
        candidates = await entry_generator.run(analysis)
        store.write_jsonl("entries/candidates.jsonl", candidates)
        self._emit(f"entry generation completed: {len(candidates)} deduplicated candidates")

        verifier = EntryVerifierAgent(
            traced_llm,
            graph,
            depth=self.project.context_depth,
            budget=self.project.max_context_functions,
            trace=trace,
        )
        self._emit(f"entry verification started: {len(candidates)} candidates")
        verified_progress = 0

        async def verify_candidate(item: tuple[int, Any]) -> tuple[int, EntryRecord]:
            nonlocal verified_progress
            index, candidate = item
            record = await verifier.run(candidate)
            verified_progress += 1
            self._emit(f"entry verification {verified_progress}/{len(candidates)}")
            return index, record

        indexed_entries = await concurrent_map(
            list(enumerate(candidates)),
            verify_candidate,
            getattr(traced_llm, "max_concurrency", 1),
        )
        entries = [record for _, record in sorted(indexed_entries, key=lambda item: item[0])]
        raw_verified = [entry for entry in entries if entry.status is Verdict.VERIFIED]
        unresolved = [entry for entry in entries if entry.status is Verdict.UNRESOLVED]
        verified, duplicate_entries = _deduplicate_verified_entries(raw_verified)
        store.write_jsonl("entries/verified-raw.jsonl", raw_verified)
        store.write_jsonl("entries/verified.jsonl", verified)
        store.write_jsonl(
            "entries/rejected.jsonl",
            (entry for entry in entries if entry.status is Verdict.REJECTED),
        )
        store.write_jsonl(
            "entries/unresolved.jsonl",
            unresolved,
        )
        store.write_json("entries/deduplication.json", duplicate_entries)
        trace(
            "entry_verifier",
            "deduplicated",
            {
                "message": (
                    f"deduplicated {len(raw_verified)} verified records into "
                    f"{len(verified)} Entry Sites"
                ),
                "raw_verified": len(raw_verified),
                "deduplicated_verified": len(verified),
                "groups": duplicate_entries,
            },
        )
        self._emit(
            f"entry verification completed: {len(verified)} verified, "
            f"{sum(entry.status is Verdict.UNRESOLVED for entry in entries)} unresolved"
        )

        # Small Feature recovery is the final context-growing phase.  Definite
        # Entries participate immediately; unresolved candidates continue from
        # the functions already inspected by EntryVerifier and may be promoted
        # while the operation/lifecycle is recovered.  Anything still
        # unresolved when this phase ends is dropped rather than leaking into
        # harness planning.
        feature_entries = [*verified, *unresolved]
        trace(
            "orchestrator",
            "verified_entries_selected",
            {
                "message": (
                    f"selected {len(verified)} verified Entries and continued "
                    f"{len(unresolved)} unresolved candidates in Small Feature recovery"
                ),
                "verified_entry_ids": [entry.entry_id for entry in verified],
                "continued_unresolved_entry_ids": [
                    entry.entry_id for entry in unresolved
                ],
            },
        )
        self._emit(
            f"small-feature recovery started: {len(verified)} verified + "
            f"{len(unresolved)} unresolved Entry contexts"
        )
        small_feature_agent = SmallFeatureAgent(
            traced_llm,
            graph,
            depth=self.project.context_depth + 1,
            budget=max(self.project.max_context_functions, 24),
            trace=trace,
        )
        recovered_small_features = (
            await small_feature_agent.run(feature_entries) if feature_entries else []
        )
        small_features = []
        for feature in recovered_small_features:
            checked = _apply_backend_readiness(feature, self.project, graph)
            small_features.append(checked)
            if feature.planning_complete and not checked.planning_complete:
                new_blockers = [
                    blocker for blocker in checked.planning_blockers
                    if blocker not in feature.planning_blockers
                ]
                trace(
                    "orchestrator",
                    "backend_readiness_blocked",
                    {
                        "message": (
                            f"blocked {checked.small_feature_id} before Large Feature grouping: "
                            + "; ".join(new_blockers)
                        ),
                        "small_feature_id": checked.small_feature_id,
                        "name": checked.name,
                        "blockers": new_blockers,
                    },
                )
        promoted_entries = list(small_feature_agent.last_promoted_entries)
        final_feature_entries = (
            list(small_feature_agent.last_final_entries)
            if feature_entries
            else []
        )
        dropped_entry_outcomes = list(
            small_feature_agent.last_dropped_entry_outcomes
        )
        store.write_jsonl("entries/promoted-during-small.jsonl", promoted_entries)
        store.write_jsonl("entries/verified-final.jsonl", final_feature_entries)
        store.write_jsonl(
            "entries/dropped-after-small.jsonl",
            dropped_entry_outcomes,
        )
        trace(
            "orchestrator",
            "small_feature_entry_resolution_completed",
            {
                "message": (
                    f"Small Feature recovery promoted {len(promoted_entries)} unresolved Entries "
                    f"and dropped {len(dropped_entry_outcomes)}"
                ),
                "promoted_entry_ids": [
                    entry.entry_id for entry in promoted_entries
                ],
                "dropped_entries": dropped_entry_outcomes,
            },
        )
        self._emit(
            f"entry final resolution completed: {len(promoted_entries)} promoted, "
            f"{len(dropped_entry_outcomes)} dropped, "
            f"{len(final_feature_entries)} final verified"
        )
        harness_ready_small_features = [
            feature for feature in small_features if feature.planning_complete
        ]
        self._emit(
            f"small-feature recovery completed: {len(small_features)} semantic features, "
            f"{len(harness_ready_small_features)} harness-ready"
        )
        for feature in small_features:
            store.write_json(Path("features/small") / f"{feature.small_feature_id}.json", feature)
        store.write_json(
            "features/small-readiness.json",
            {
                "semantic_feature_count": len(small_features),
                "harness_ready_count": len(harness_ready_small_features),
                "ready_small_feature_ids": [
                    feature.small_feature_id for feature in harness_ready_small_features
                ],
                "blocked": [
                    {
                        "small_feature_id": feature.small_feature_id,
                        "name": feature.name,
                        "planning_blockers": feature.planning_blockers,
                    }
                    for feature in small_features
                    if not feature.planning_complete
                ],
            },
        )

        self._emit(
            f"large-feature grouping started: {len(harness_ready_small_features)} "
            "harness-ready small features"
        )
        large_feature_candidates = (
            await LargeFeatureAgent(traced_llm, graph, trace=trace).run(
                harness_ready_small_features
            )
            if harness_ready_small_features else []
        )
        discarded_large_features = [
            item for item in large_feature_candidates
            if item.security_priority.disposition is HarnessDisposition.DISCARD
        ]
        large_features = [
            item for item in large_feature_candidates
            if item.security_priority.disposition is HarnessDisposition.KEEP
        ]
        self._emit(
            f"large-feature grouping completed: {len(large_feature_candidates)} groups; "
            f"scheduled={len(large_features)}, discarded={len(discarded_large_features)}"
        )
        for large_candidate in large_feature_candidates:
            store.write_json(
                Path("features/large") / f"{large_candidate.large_feature_id}.json",
                large_candidate,
            )
        store.write_json(
            "features/large-priority.json",
            {
                "scheduled_large_feature_ids": [
                    item.large_feature_id for item in large_features
                ],
                "discarded": [
                    {
                        "large_feature_id": item.large_feature_id,
                        "name": item.name,
                        "security_priority": as_json(item.security_priority),
                    }
                    for item in discarded_large_features
                ],
                "priorities": [
                    {
                        "large_feature_id": item.large_feature_id,
                        "name": item.name,
                        "security_priority": as_json(item.security_priority),
                    }
                    for item in large_feature_candidates
                ],
            },
        )

        generator = HarnessGeneratorAgent(
            traced_llm, graph, self.project, trace=trace
        )
        static_gate = StaticHarnessGate(graph, self.project)
        dynamic = (
            QuartetOssFuzzVerifierAgent(
                self.project, graph, progress=self._emit
            )
            if self.project.verification_backend == "oss-fuzz"
            else HarnessVerifierAgent(
                CommandRunner(), self.project, graph, progress=self._emit
            )
        )
        seed_planner = _HarnessVerifierSeedPlanner(traced_llm)
        generation_attempts = 0
        generated_ids: set[str] = set()
        static_passed_ids: set[str] = set()
        build_passed_ids: set[str] = set()
        qualified_ids: set[str] = set()
        verification_infrastructure_errors: list[str] = []
        blocked_features = 0
        known_small_ids = {item.small_feature_id for item in small_features}
        known_large_ids = {
            item.large_feature_id for item in large_feature_candidates
        }
        superseded_large_ids: set[str] = set()
        replan_depth = {item.large_feature_id: 0 for item in large_features}
        entry_by_id = {item.entry_id: item for item in final_feature_entries}

        # LargeFeatureAgent returns the initial batch in priority order, but a
        # structural harness failure can discover replacement Large Features
        # while this loop is already running.  Iterating ``large_features``
        # directly used to append those replacements at the very end, so a
        # newly discovered unauthenticated-network feature could run after
        # every low-priority local or trusted-component feature.  Keep the
        # complete inventory in ``large_features`` and schedule from a
        # separately re-sorted pending queue instead.
        pending_large_features = list(large_features)
        while pending_large_features:
            pending_large_features.sort(key=large_feature_schedule_key)
            large = pending_large_features.pop(0)
            feedback: list[str] = []
            regression_seeds: list[SeedSpec] = []
            feature_static_passed = False
            feature_build_passed = False
            feature_qualified = False
            feature_infrastructure_blocked = False
            structural_feedback: list[str] = []
            exclude_current_anchor_on_replan = False
            members = [item for item in small_features if item.small_feature_id in large.small_feature_ids]
            for attempt in range(1, self.max_generation_attempts + 1):
                self._emit(
                    f"harness {large.large_feature_id}: generation attempt "
                    f"{attempt}/{self.max_generation_attempts}"
                )
                trace(
                    "harness_generator",
                    "attempt_started",
                    {
                        "message": f"generate harness for {large.large_feature_id}, attempt {attempt}",
                        "large_feature": as_json(large),
                        "small_features": [as_json(item) for item in members],
                        "attempt": attempt,
                        "feedback": feedback,
                    },
                )
                draft = await generator.run(large, members, feedback=feedback)
                generation_attempts += 1
                if draft.code.strip():
                    generated_ids.add(draft.manifest.harness_id)
                attempt_dir = Path("harnesses") / draft.manifest.harness_id / f"attempt-{attempt}"
                source_filename = Path(draft.manifest.source_file).name
                draft.manifest.source_file = str(attempt_dir / source_filename)
                absolute_attempt_dir = store.directory(attempt_dir)
                store.write_text(attempt_dir / source_filename, draft.code)
                store.write_json(attempt_dir / "manifest.json", draft.manifest)
                store.write_json(attempt_dir / "generator-audit.json", draft.self_audit)
                store.write_json(
                    attempt_dir / "generator-context.json",
                    {
                        "context_function_ids": draft.context_function_ids,
                        "generation_blockers": draft.generation_blockers,
                    },
                )
                trace(
                    "harness_generator",
                    "draft_created",
                    {
                        "message": (
                            f"created {draft.manifest.harness_id} with "
                            f"{len(draft.self_audit)} generator audit records"
                        ),
                        "large_feature_id": large.large_feature_id,
                        "attempt": attempt,
                        "manifest": as_json(draft.manifest),
                        "self_audit": draft.self_audit,
                    },
                )

                report = static_gate.check(draft, large, members)
                store.write_json(attempt_dir / "static-audit.json", report)
                trace(
                    "static_harness_gate",
                    "decision",
                    {
                        "message": (
                            f"harness {draft.manifest.harness_id}: "
                            f"{'PASS' if report.passed else 'FAIL'}"
                        ),
                        "harness_id": draft.manifest.harness_id,
                        "attempt": attempt,
                        "report": as_json(report),
                    },
                )
                if report.has_failures:
                    feedback = _gate_feedback(report)
                    self._emit(
                        f"harness {draft.manifest.harness_id}: static gate failed "
                        f"({len(feedback)} failures)"
                    )
                    # An evidence-validated context dependency and a
                    # deterministically missing indexed function are immediate
                    # structural blockers. Other generator/lifecycle findings
                    # remain repair feedback; the high attempt limit is only a
                    # runaway-loop safety valve.
                    if any(
                        blocker.startswith("CONTEXT_BLOCKED:")
                        for blocker in draft.generation_blockers
                    ):
                        exclude_current_anchor_on_replan = True
                        structural_feedback = unique_strings([
                            *draft.generation_blockers,
                            *feedback,
                        ])
                        break
                    if any(
                        check.check_id in {"HC14", "HC19"}
                        and check.status is CheckStatus.FAIL
                        for check in report.checks
                    ):
                        # Feature-boundary and missing-analysis errors cannot be repaired by rewriting C++ alone.
                        structural_feedback = unique_strings([
                            *draft.generation_blockers,
                            *feedback,
                        ])
                        break
                    if attempt >= self.max_generation_attempts:
                        structural_feedback = unique_strings([
                            *draft.generation_blockers,
                            *feedback,
                        ])
                    continue
                if not report.passed:
                    self._emit(
                        f"harness {draft.manifest.harness_id}: static gate has "
                        "unresolved warnings; forwarding them to independent review"
                    )
                independent_report = await generator.review(
                    draft, large, members, report
                )
                store.write_json(
                    attempt_dir / "independent-generator-audit.json",
                    independent_report,
                )
                trace(
                    "harness_generator",
                    "independent_audit",
                    {
                        "message": (
                            f"independent audit for {draft.manifest.harness_id}: "
                            f"{'PASS' if independent_report.passed else 'FAIL'}"
                        ),
                        "harness_id": draft.manifest.harness_id,
                        "attempt": attempt,
                        "report": as_json(independent_report),
                    },
                )
                if not independent_report.passed:
                    feedback = _gate_feedback(
                        independent_report,
                        include_warnings=True,
                    )
                    self._emit(
                        f"harness {draft.manifest.harness_id}: independent generator audit "
                        f"failed ({len(feedback)} findings)"
                    )
                    if _independent_review_requires_replan(
                        independent_report,
                        attempt=attempt,
                        max_attempts=self.max_generation_attempts,
                    ):
                        structural_feedback = list(feedback)
                    continue
                feature_static_passed = True
                static_passed_ids.add(draft.manifest.harness_id)
                if not self.dynamic_verification:
                    verification = await dynamic.verify(
                        draft,
                        absolute_attempt_dir,
                        runtime_checks=False,
                    )
                    store.write_json(
                        attempt_dir / "build-validation.json", verification
                    )
                    trace(
                        "harness_verifier",
                        "build_only_decision",
                        {
                            "message": (
                                f"harness {draft.manifest.harness_id}: "
                                f"{'BUILD PASS' if verification.build_ok else 'BUILD FAIL'} - "
                                f"{verification.reason}"
                            ),
                            "harness_id": draft.manifest.harness_id,
                            "attempt": attempt,
                            "verification": as_json(verification),
                        },
                    )
                    if verification.build_ok:
                        feature_build_passed = True
                        build_passed_ids.add(draft.manifest.harness_id)
                        self._emit(
                            f"harness {draft.manifest.harness_id}: build passed; "
                            "runtime replay/reachability/coverage qualification was disabled"
                        )
                        break
                    if verification.infrastructure_error:
                        verification_infrastructure_errors.append(
                            verification.infrastructure_error
                        )
                        feature_infrastructure_blocked = True
                        self._emit(
                            f"harness {draft.manifest.harness_id}: build verification "
                            "infrastructure failed; code regeneration stopped: "
                            f"{verification.infrastructure_error}"
                        )
                        break
                    self._emit(
                        f"harness {draft.manifest.harness_id}: build validation failed: "
                        f"{verification.reason}"
                    )
                    feedback = _verification_feedback(verification)
                    if attempt >= self.max_generation_attempts:
                        structural_feedback = list(feedback)
                    continue
                llm_seeds: list[SeedSpec] = []
                if (
                    draft.manifest.verification_backend == "oss-fuzz"
                    or draft.manifest.build_command
                ):
                    proposed_seeds = await seed_planner.run(draft, large, report)
                    store.write_json(
                        attempt_dir / "seeds" / "llm-seeds.json", proposed_seeds
                    )
                    llm_seeds = _deduplicate_seed_specs([
                        *regression_seeds, *proposed_seeds
                    ])
                    store.write_json(
                        attempt_dir / "seeds" / "validation-seeds.json", llm_seeds
                    )
                runtime_verification: VerificationResult | None = None
                for seed_round in range(1, 3):
                    # The Harness Generator and Harness Verifier own stateful
                    # threads for this feature. Killing the worker here would
                    # erase the source context needed by a repair/refinement turn.
                    runtime_verification = await dynamic.verify(
                        draft, absolute_attempt_dir, llm_seeds
                    )
                    store.write_json(
                        attempt_dir / f"validation-round-{seed_round}.json",
                        runtime_verification,
                    )
                    if not _seed_refinement_needed(runtime_verification) or seed_round >= 2:
                        break
                    self._emit(
                        f"harness {draft.manifest.harness_id}: reachability seed refinement "
                        f"{seed_round}/1 started"
                    )
                    additional_seeds = await seed_planner.run(
                        draft,
                        large,
                        report,
                        validation_feedback=_verification_feedback(runtime_verification),
                        existing_seeds=llm_seeds,
                    )
                    llm_seeds = _deduplicate_seed_specs([
                        *llm_seeds, *additional_seeds
                    ])
                    store.write_json(
                        attempt_dir / "seeds" / "validation-seeds.json", llm_seeds
                    )
                assert runtime_verification is not None
                verification = runtime_verification
                store.write_json(attempt_dir / "validation.json", verification)
                if verification.build_ok:
                    feature_build_passed = True
                    build_passed_ids.add(draft.manifest.harness_id)
                trace(
                    "harness_verifier",
                    "decision",
                    {
                        "message": (
                            f"harness {draft.manifest.harness_id}: "
                            f"{'QUALIFIED' if verification.qualified else 'FAILED'} - {verification.reason}"
                        ),
                        "harness_id": draft.manifest.harness_id,
                        "attempt": attempt,
                        "verification": as_json(verification),
                    },
                )
                if verification.target_findings:
                    for index, finding in enumerate(verification.target_findings):
                        finding_id = stable_id("finding", draft.manifest.harness_id, attempt, index, finding)
                        finding_seed = (
                            verification.target_finding_seeds[index]
                            if index < len(verification.target_finding_seeds)
                            else None
                        )
                        store.write_json(
                            Path("findings") / finding_id / "attribution.json",
                            {
                                "finding_id": finding_id,
                                "harness_id": draft.manifest.harness_id,
                                "detail": finding,
                                "seed": as_json(finding_seed) if finding_seed else None,
                            },
                        )
                        if finding_seed is not None:
                            store.write_bytes(
                                Path("findings") / finding_id / "input",
                                bytes.fromhex(finding_seed.data_hex),
                            )
                if verification.qualified:
                    qualified_ids.add(draft.manifest.harness_id)
                    feature_qualified = True
                    self._emit(f"harness {draft.manifest.harness_id}: qualified")
                    break
                self._emit(
                    f"harness {draft.manifest.harness_id}: dynamic verification failed: "
                    f"{verification.reason}"
                )
                if verification.infrastructure_error:
                    verification_infrastructure_errors.append(
                        verification.infrastructure_error
                    )
                    feature_infrastructure_blocked = True
                    self._emit(
                        f"harness {draft.manifest.harness_id}: verification infrastructure "
                        f"failed; code regeneration stopped: {verification.infrastructure_error}"
                    )
                    break
                feedback = _verification_feedback(verification)
                if (
                    attempt >= self.max_generation_attempts
                    and verification.reason
                    == "expected application anchor reachability was not established"
                ):
                    structural_feedback = list(feedback)
                if verification.harness_fault_seeds:
                    regression_seeds = _deduplicate_seed_specs([
                        *regression_seeds, *verification.harness_fault_seeds
                    ])
                    self._emit(
                        f"harness {draft.manifest.harness_id}: retained "
                        f"{len(regression_seeds)} regression crash seeds for the next attempt"
                    )
                if verification.build is None:
                    break
            if not feature_static_passed or not feature_build_passed or (
                self.dynamic_verification
                and not feature_qualified
                and structural_feedback
            ) or feature_infrastructure_blocked:
                replanned = False
                current_replan_depth = replan_depth.get(large.large_feature_id, 0)
                if structural_feedback and current_replan_depth < 1:
                    relevant_entry_ids = unique_strings(
                        entry_id
                        for member in members
                        for entry_id in [*member.root_entries, *member.supporting_entries]
                    )
                    relevant_entries = [
                        entry_by_id[entry_id]
                        for entry_id in relevant_entry_ids
                        if entry_id in entry_by_id
                    ]
                    if relevant_entries:
                        self._emit(
                            f"harness {large.large_feature_id}: structural blocker; "
                            "returning to Small Feature boundary recovery"
                        )
                        trace(
                            "orchestrator",
                            "harness_backtrack_started",
                            {
                                "message": (
                                    f"replan {large.large_feature_id} from {len(relevant_entries)} "
                                    "Entry contexts after structural harness failure"
                                ),
                                "large_feature_id": large.large_feature_id,
                                "blocked_anchor": large.common_anchor,
                                "entry_ids": relevant_entry_ids,
                                "feedback": structural_feedback,
                            },
                        )
                        refined = await small_feature_agent.run(
                            relevant_entries,
                            harness_feedback=structural_feedback,
                            excluded_anchors=(
                                [large.common_anchor]
                                if exclude_current_anchor_on_replan
                                else []
                            ),
                        )
                        refined = [
                            _apply_backend_readiness(item, self.project, graph)
                            for item in refined
                        ]
                        refined = [
                            item for item in refined
                            if item.small_feature_id not in known_small_ids
                        ]
                        # Keep the backtrack audit total even when recovery
                        # discovers no new semantic feature.  Previously this
                        # variable was created only inside ``if refined`` and
                        # the audit path itself crashed with UnboundLocalError.
                        replacements = []
                        if refined:
                            for item in refined:
                                known_small_ids.add(item.small_feature_id)
                                small_features.append(item)
                                store.write_json(
                                    Path("features/small") / f"{item.small_feature_id}.json",
                                    item,
                                )
                            ready_refined = [
                                item for item in refined if item.planning_complete
                            ]
                            replacement_candidates = await LargeFeatureAgent(
                                traced_llm, graph, trace=trace
                            ).run(
                                ready_refined,
                                priority_context=[
                                    *large_features,
                                    *discarded_large_features,
                                ],
                            ) if ready_refined else []
                            replacements = [
                                item for item in replacement_candidates
                                if item.large_feature_id not in known_large_ids
                            ]
                            for replacement in replacements:
                                known_large_ids.add(replacement.large_feature_id)
                                store.write_json(
                                    Path("features/large") / f"{replacement.large_feature_id}.json",
                                    replacement,
                                )
                                if replacement.security_priority.disposition is HarnessDisposition.DISCARD:
                                    discarded_large_features.append(replacement)
                                else:
                                    replan_depth[replacement.large_feature_id] = current_replan_depth + 1
                                    large_features.append(replacement)
                                    pending_large_features.append(replacement)
                            scheduled_replacements = [
                                item for item in replacements
                                if item.security_priority.disposition is HarnessDisposition.KEEP
                            ]
                            if scheduled_replacements:
                                pending_large_features.sort(
                                    key=large_feature_schedule_key
                                )
                                self._emit(
                                    "large-feature schedule reprioritized after replan: "
                                    + ", ".join(
                                        f"{item.large_feature_id}="
                                        f"{item.security_priority.priority_score}"
                                        for item in pending_large_features
                                    )
                                )
                                superseded_large_ids.add(large.large_feature_id)
                                replanned = True
                        trace(
                            "orchestrator",
                            "harness_backtrack_completed",
                            {
                                "message": (
                                    f"replan {large.large_feature_id}: {len(refined)} new Small Features, "
                                    f"replacements={replanned}"
                                ),
                                "large_feature_id": large.large_feature_id,
                                "refined_small_feature_ids": [
                                    item.small_feature_id for item in refined
                                ],
                                "discarded_replacement_ids": [
                                    item.large_feature_id for item in replacements
                                    if item.security_priority.disposition is HarnessDisposition.DISCARD
                                ],
                                "superseded": replanned,
                            },
                        )
                if not replanned:
                    blocked_features += 1

            # A Large Feature is the lifetime boundary of both harness-stage
            # agent sessions. Releasing them here permits deferred worker
            # recycling without losing context between generation attempts.
            await generator.close_session(large)
            await seed_planner.close_session(draft)
            close_harness = getattr(dynamic, "close_harness", None)
            if callable(close_harness):
                await close_harness(draft.manifest.harness_id)

        terminal_large_features = sorted([
            item for item in large_features
            if item.large_feature_id not in superseded_large_ids
        ], key=large_feature_schedule_key)
        store.write_json(
            "features/large-priority.json",
            {
                "scheduled_large_feature_ids": [
                    item.large_feature_id for item in terminal_large_features
                ],
                "discarded": [
                    {
                        "large_feature_id": item.large_feature_id,
                        "name": item.name,
                        "security_priority": as_json(item.security_priority),
                    }
                    for item in discarded_large_features
                ],
                "priorities": [
                    {
                        "large_feature_id": item.large_feature_id,
                        "name": item.name,
                        "security_priority": as_json(item.security_priority),
                    }
                    for item in [*terminal_large_features, *discarded_large_features]
                ],
            },
        )
        final_ready_small_features = [
            feature for feature in small_features if feature.planning_complete
        ]
        store.write_json(
            "features/small-readiness.json",
            {
                "semantic_feature_count": len(small_features),
                "harness_ready_count": len(final_ready_small_features),
                "ready_small_feature_ids": [
                    feature.small_feature_id for feature in final_ready_small_features
                ],
                "blocked": [
                    {
                        "small_feature_id": feature.small_feature_id,
                        "name": feature.name,
                        "planning_blockers": feature.planning_blockers,
                    }
                    for feature in small_features
                    if not feature.planning_complete
                ],
            },
        )
        if not terminal_large_features:
            run_status = (
                "FILTERED_NO_ATTACKER_REALISTIC_HARNESS"
                if discarded_large_features
                else "FAILED_NO_HARNESSABLE_FEATURES"
                if small_features
                else "FAILED_NO_FEATURES"
            )
        elif not static_passed_ids:
            run_status = "FAILED_NO_VALID_HARNESS"
        elif verification_infrastructure_errors and not qualified_ids:
            # A missing/crashed build, debugger, container, or coverage
            # runner is not evidence that the generated C/C++ is wrong.
            # Preserve that distinction even when the infrastructure failed
            # before a build report could be produced.
            run_status = "FAILED_VERIFICATION_INFRASTRUCTURE"
        elif not build_passed_ids:
            run_status = "FAILED_NO_BUILDABLE_HARNESS"
        elif not self.dynamic_verification:
            run_status = (
                "BUILD_VERIFIED_DRAFT_COMPLETE"
                if len(build_passed_ids) == len(terminal_large_features)
                else "BUILD_VERIFIED_DRAFT_PARTIAL"
            )
        elif not qualified_ids:
            run_status = "FAILED_NO_QUALIFIED_HARNESS"
        elif len(qualified_ids) == len(terminal_large_features):
            run_status = "COMPLETED"
        else:
            run_status = "PARTIAL"

        summary = RunSummary(
            run_id=run_id,
            analysis_functions=len(analysis.functions),
            analysis_provider=str(analysis.completeness.get("provider", "unknown")),
            analysis_authoritative=bool(analysis.completeness.get("authoritative", False)),
            fuzz_introspector_used=bool(
                analysis.completeness.get("fuzz_introspector_used", False)
            ),
            candidates=len(candidates),
            verified_entries=len(final_feature_entries),
            unresolved_entries=0,
            small_features=len(small_features),
            harness_ready_small_features=sum(
                feature.planning_complete for feature in small_features
            ),
            large_features=len(terminal_large_features),
            discarded_large_features=len(discarded_large_features),
            generation_attempts=generation_attempts,
            harnesses_generated=len(generated_ids),
            harnesses_static_passed=len(static_passed_ids),
            harnesses_build_passed=len(build_passed_ids),
            harnesses_blocked=blocked_features,
            harnesses_qualified=len(qualified_ids),
            status=run_status,
            output_root=str(store.root),
            initial_unresolved_entries=len(unresolved),
            promoted_entries_during_small_feature=len(promoted_entries),
            dropped_entries_after_small_feature=len(dropped_entry_outcomes),
            verification_infrastructure_failures=len(
                verification_infrastructure_errors
            ),
        )
        store.write_json("summary.json", summary)
        trace(
            "orchestrator",
            "run_completed",
            {
                "message": f"run {run_id} finished with status {run_status}",
                "summary": as_json(summary),
            },
        )
        self._emit(
            f"run {run_status}: attempts={generation_attempts}, generated={len(generated_ids)}, "
            f"static_passed={len(static_passed_ids)}, build_passed={len(build_passed_ids)}, "
            f"qualified={len(qualified_ids)}, "
            f"summary={store.root / 'summary.json'}"
        )
        close_dynamic = getattr(dynamic, "close", None)
        if callable(close_dynamic):
            await close_dynamic()
        return summary

    def _prepare_static_analysis(self) -> AnalysisBundle:
        if self.precomputed_analysis is not None:
            self._emit("static analysis started (precomputed FI metadata)")
            return self.precomputed_analysis

        excluded_paths = (
            [self.project.output_root]
            if self.project.source_root in self.project.output_root.parents
            else []
        )
        report = self.project.fuzz_introspector
        if report is None:
            try:
                report = FuzzIntrospectorRunner(
                    self.project.source_root,
                    self.project.output_root / ".fuzz-introspector",
                    excluded_paths=excluded_paths,
                    progress=self._emit,
                ).run().report
            except FuzzIntrospectorError as exc:
                if self.project.require_fuzz_introspector:
                    raise ValueError(
                        "automatic Fuzz Introspector analysis is required but failed: "
                        + str(exc)
                    ) from exc
                self._emit(
                    "WARNING: automatic Fuzz Introspector analysis failed; "
                    f"bootstrap source analysis was explicitly allowed: {exc}"
                )
        self.project = replace(self.project, fuzz_introspector=report)
        self._emit("static analysis started")
        return StaticAnalyzer(
            self.project.source_root,
            report,
            require_fuzz_introspector=self.project.require_fuzz_introspector,
            excluded_paths=excluded_paths,
        ).index()

    def _run_id(self) -> str:
        timestamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        return f"{timestamp}-{stable_id('run', self.project.name, time.time_ns()).split('-', 1)[1][:8]}"

    def _emit(self, message: str) -> None:
        if self.progress:
            self.progress(message)


def _gate_feedback(
    report: GateReport,
    *,
    include_warnings: bool = False,
) -> list[str]:
    return [
        f"{check.check_id} {check.name}: {check.evidence}. {check.remediation}".strip()
        for check in report.checks
        if check.status is CheckStatus.FAIL
        or (include_warnings and check.status is CheckStatus.WARN)
    ]


def _independent_review_requires_replan(
    report: GateReport,
    *,
    attempt: int,
    max_attempts: int,
) -> bool:
    """Backtrack only after harness-local repair attempts are exhausted.

    In particular, stale state is commonly repaired by bounded draining or an
    evidenced reset in the harness itself.  Treating the first HC03 finding as
    a Small Feature boundary failure caused expensive full-stage reruns and
    prevented the generator from applying its own remediation.
    """

    if attempt < max_attempts:
        return False
    structural_ids = {
        "HC03", "HC08", "HC09", "HC10", "HC11", "HC13",
        "HC14", "HC15", "HC16",
    }
    return any(
        check.check_id in structural_ids
        and check.status is not CheckStatus.PASS
        for check in report.checks
    )


def _apply_backend_readiness(
    feature: Any,
    project: ProjectSpec,
    graph: GraphStore,
) -> Any:
    """Keep semantic features while blocking provably unbuildable harnesses.

    Fuzz Introspector can index every auxiliary executable in a repository.
    That does not make a standalone tool's ``main`` available to the selected
    OSS-Fuzz fuzzer link.  Likewise the current verifier is an in-process
    libFuzzer backend and cannot honestly qualify a feature whose normal
    execution necessarily forks or execs.  Record those as planning blockers
    before generation instead of spending repair attempts on impossible C.
    """

    blockers = list(feature.planning_blockers)
    if feature.isolation_mode in {"fork_per_input", "subprocess"}:
        blockers.append(
            "the selected libFuzzer backend cannot preserve a required fork/subprocess execution boundary"
        )
    if project.verification_backend == "oss-fuzz":
        anchor = graph.bundle.functions.get(feature.harness_anchor)
        if anchor is None:
            blockers.append("Common Anchor is absent from authoritative function metadata")
        elif not anchor.build_targets:
            blockers.append(
                "Common Anchor has no Fuzz Introspector build-target evidence for the selected OSS-Fuzz link"
            )
        elif feature.build_target.strip().casefold() in {
            "", "default", "unknown", "unresolved"
        }:
            blockers.append(
                "Small Feature has no resolved project build target for the selected OSS-Fuzz link"
            )
        elif feature.build_target not in anchor.build_targets:
            blockers.append(
                "Small Feature build target does not match the Common Anchor build-target metadata"
            )
    blockers = unique_strings(blockers)
    if blockers == feature.planning_blockers:
        return feature
    return replace(
        feature,
        planning_complete=False,
        planning_blockers=blockers,
        unknowns=unique_strings([*feature.unknowns, *blockers]),
    )


def _verification_feedback(result: Any) -> list[str]:
    feedback = [str(result.reason)]
    feedback.extend(str(item) for item in result.harness_faults)
    if result.build and result.build.returncode != 0:
        feedback.append(
            "build diagnostics:\n" + _build_failure_excerpt(result.build.stderr)
        )
    return feedback


def _build_failure_excerpt(output: str, *, limit: int = 20_000) -> str:
    """Keep compiler/linker diagnostics instead of the final Docker summary."""

    lines = output.splitlines()
    diagnostic = re.compile(
        r"(?:fatal error:|\berror:|undefined reference|multiple definition|"
        r"ld(?:\.lld)?: |linker command failed|collect2:|ninja: build stopped|"
        r"make(?:\[\d+\])?: \*\*\*)",
        re.IGNORECASE,
    )
    selected_indexes: set[int] = set()
    for index, line in enumerate(lines):
        if diagnostic.search(line):
            selected_indexes.update(
                range(max(0, index - 2), min(len(lines), index + 3))
            )
    if selected_indexes:
        excerpt = "\n".join(lines[index] for index in sorted(selected_indexes))
        if len(excerpt) > limit:
            excerpt = excerpt[-limit:]
        return excerpt
    return output[-limit:]


def _seed_refinement_needed(result: Any) -> bool:
    """Retry input synthesis before rewriting C++ for a pure reachability miss."""

    reachability_details = "\n".join(str(item) for item in result.harness_faults)
    seed_addressable = bool(
        re.search(
            r"(?:deterministic seeds reached expected anchor|"
            r"selector .+ did not reach Small Feature target)",
            reachability_details,
        )
    )
    return bool(
        not result.qualified
        and result.reason == "expected application anchor reachability was not established"
        and seed_addressable
        and not result.target_findings
        and not result.harness_fault_seeds
        and result.build is not None
        and result.build.returncode == 0
        and not result.build.timed_out
    )


def _deduplicate_seed_specs(seeds: list[SeedSpec]) -> list[SeedSpec]:
    result: list[SeedSpec] = []
    seen: set[str] = set()
    for seed in seeds:
        normalized = seed.data_hex.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(seed)
    return result


def _deduplicate_verified_entries(
    entries: list[EntryRecord],
) -> tuple[list[EntryRecord], list[dict[str, Any]]]:
    """Merge repeated verifier results that identify the same concrete site."""
    grouped: dict[tuple[str, str, int | None], list[EntryRecord]] = {}
    for entry in entries:
        tokens = re.findall(r"[a-z_][a-z0-9_]*", entry.source_api.casefold())
        source_name = tokens[0] if tokens else entry.source_api.casefold().strip()
        source_lines = [
            evidence.line
            for evidence in entry.evidence
            if evidence.function_id == entry.entry_function_id and evidence.line is not None
        ]
        line = entry.entry_line if entry.entry_line is not None else (
            min(source_lines) if source_lines else None
        )
        grouped.setdefault((entry.entry_function_id, source_name, line), []).append(entry)

    merged: list[EntryRecord] = []
    diagnostics: list[dict[str, Any]] = []
    for (function_id, source_name, line), records in grouped.items():
        canonical = max(records, key=lambda item: item.verifier_confidence)
        evidence = []
        seen_evidence: set[tuple[Any, ...]] = set()
        for record in records:
            for item in record.evidence:
                key = (item.kind, item.function_id, item.file, item.line, item.detail)
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    evidence.append(item)
        entry_id = (
            canonical.entry_id
            if len(records) == 1
            else stable_id("entry", function_id, source_name, line)
        )
        merged.append(replace(
            canonical,
            entry_id=entry_id,
            consumer_hints=list(dict.fromkeys(
                hint for record in records for hint in record.consumer_hints
            )),
            provenance_path=list({
                tuple(sorted(step.items())): step
                for record in records for step in record.provenance_path
            }.values()),
            evidence=evidence,
            unknowns=list(dict.fromkeys(
                unknown for record in records for unknown in record.unknowns
            )),
            verifier_confidence=max(record.verifier_confidence for record in records),
        ))
        if len(records) > 1:
            diagnostics.append({
                "entry_id": entry_id,
                "entry_function_id": function_id,
                "source_api": source_name,
                "line": line,
                "merged_entry_ids": [record.entry_id for record in records],
                "merged_candidate_ids": [record.candidate_id for record in records],
            })
    merged.sort(key=lambda item: (item.entry_function_id, item.source_api, item.entry_id))
    return merged, diagnostics
