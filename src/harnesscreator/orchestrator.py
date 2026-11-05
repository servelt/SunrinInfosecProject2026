from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import replace
import hashlib
from itertools import count
import json
import re
import time
from pathlib import Path
from typing import Any, Callable

from .agents import (
    EntryGeneratorAgent,
    EntryVerifierAgent,
    HarnessGeneratorAgent,
    InputActionAgent,
    LargeFeatureAgent,
    ScenarioHarnessGeneratorAgent,
    ScenarioHarnessVerifierSeedPlanner,
    ScenarioPlanner,
    ScenarioStaticHarnessGate,
    SmallFeatureAgent,
    StateDependencyAgent,
    build_harness_plan,
)
from .agents.harness import _HarnessVerifierSeedPlanner, StaticHarnessGate
from .agents.behavior import BEHAVIOR_SCHEMA
from .agents.execution_contract import EXECUTION_CONTRACT_SCHEMA
from .agents.boundary_harness import BOUNDARY_CONTEXT_SCHEMA, BOUNDARY_HARNESS_SCHEMA
from .workflow_boundary import run_boundary_workflow
from .agents.entry import ENTRY_GENERATOR_SCHEMA, ENTRY_VERIFIER_SCHEMA
from .agents.scenario import (
    SEMANTIC_INPUT_ACTION_SCHEMA,
    STATE_DEPENDENCY_SCHEMA,
    GROUP_STATE_DEPENDENCY_SCHEMA,
)
from .agents.action_selection import (
    ActionSelectionAgent, ACTION_SELECTION_SCHEMA, ACTION_GROUP_SCHEMA,
    build_action_effect_families, validate_action_groups,
)
from .agents.action_requests import ActionRequestAgent, ACTION_REQUEST_SCHEMA
from .agents.scenario_refine import ScenarioRequestRefiner, REQUEST_REFINEMENT_SCHEMA
from .agents.input_surfaces import (
    InputSurfaceAgent, INPUT_SAMPLE_SCHEMA, raw_case_runtime_action,
)
from .agents.scenario_harness import (
    SCENARIO_CONTEXT_SCHEMA,
    SCENARIO_HARNESS_SCHEMA,
    SCENARIO_REVIEW_SCHEMA,
    SCENARIO_SEED_SCHEMA,
    action_harness_function_ids,
)
from .agents.contracts import assess_small_feature
from .agents.common import concurrent_map
from .analysis import (
    FuzzIntrospectorError,
    FuzzIntrospectorRunner,
    GraphStore,
    SVFError,
    StaticAnalyzer,
    UpstreamProcessResult,
    UpstreamToolError,
    UsageEvidenceBundle,
    discover_usage_artifacts,
    fuzzgen_reports_to_rubick_a2dg,
    load_upstream_revisions,
    load_usage_evidence,
    load_netlifter_grammars,
    prepare_svf_analysis,
    run_rubick_a2dg,
)
from .analysis.operation_seeds import merge_operation_seed_records
from .analysis.binary_sources import linked_source_priority, selected_binary_is_program
from .analysis.target_manifest import linked_make_sources
from .analysis.fuzz_introspector import default_fi_cache_root
from .analysis.svf import default_svf_cache_root
from .input_transport import permits_explicit_socket_trial
from .llm.base import (
    InvalidOutputSchemaError,
    LLMProvider,
    RecordingLLM,
    is_terminal_llm_infrastructure_error,
    is_transient_llm_transport_error,
    validate_strict_output_schema,
)
from .models import (
    AnalysisBundle,
    CheckStatus,
    EntryRecord,
    Evidence,
    AnalysisDisposition,
    EntrySiteKind,
    ExternalActionSchema,
    GateReport,
    HarnessDisposition,
    CrashReproductionStatus,
    ProjectSpec,
    ProofStatus,
    RunSummary,
    StateDependencyGraph,
    ScenarioRunSummary,
    ScenarioStatus,
    SeedSpec,
    RetryDisposition,
    VerificationResult,
    VerificationFailureKind,
    Verdict,
    as_json,
    large_feature_schedule_key,
    stable_id,
    unique_strings,
)
from .runtime.workflow_evidence import candidate_lifecycle, schedule_generation
from .runtime.preflight import (
    inspect_capabilities, safe_inspect_build_closure_for_plan,
    source_analysis_binary,
)
from .runtime.network_harness import NetworkHarnessConfig
from .runtime.stateafl_seeds import export_stateafl_seeds
from .runtime import (
    CommandRunner,
    HarnessVerifierAgent,
    OriginalCrashReproducer,
    ScenarioRuntimeVerifier,
)
from .storage import ArtifactStore
from .tracing import AgentTraceLogger


_ACTIVE_OUTPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "entry_generator": ENTRY_GENERATOR_SCHEMA,
    "entry_verifier": ENTRY_VERIFIER_SCHEMA,
    "input_surface": INPUT_SAMPLE_SCHEMA,
    "input_action": SEMANTIC_INPUT_ACTION_SCHEMA,
    "action_selection": ACTION_SELECTION_SCHEMA,
    "action_group": ACTION_GROUP_SCHEMA,
    "action_request": ACTION_REQUEST_SCHEMA,
    "state_dependency": STATE_DEPENDENCY_SCHEMA,
    "state_dependency_group": GROUP_STATE_DEPENDENCY_SCHEMA,
    "scenario_context": SCENARIO_CONTEXT_SCHEMA,
    "scenario_harness": SCENARIO_HARNESS_SCHEMA,
    "scenario_review": SCENARIO_REVIEW_SCHEMA,
    "scenario_seed": SCENARIO_SEED_SCHEMA,
    "scenario_refiner": REQUEST_REFINEMENT_SCHEMA,
    "behavior_recovery": BEHAVIOR_SCHEMA,
    "execution_contract": EXECUTION_CONTRACT_SCHEMA,
    "boundary_context": BOUNDARY_CONTEXT_SCHEMA,
    "boundary_harness": BOUNDARY_HARNESS_SCHEMA,
}

_BOUNDARY_SCHEMAS = frozenset({
    "entry_generator", "entry_verifier", "input_surface",
    "behavior_recovery", "execution_contract",
    "boundary_context", "boundary_harness",
})


def _preferred_entry_source_files(
    binary_report: dict[str, Any], completeness: dict[str, Any],
) -> tuple[set[str], str]:
    """Use compiled-source evidence to order inspection, never to exclude files."""
    matched = {str(item) for item in binary_report.get('matched_files') or []}
    if matched:
        return matched, 'linked_binary_source_match'
    hints = {str(item) for item in binary_report.get('symbol_file_hints') or []}
    if hints:
        return hints, 'linked_binary_symbol_file_hint'
    compiled = {str(item) for item in
                completeness.get('analysis_compile_database_files') or []}
    return compiled, ('observed_compile_command' if compiled else 'none')


async def _generate_and_verify_entries(
    generator: EntryGeneratorAgent, verifier: EntryVerifierAgent,
    analysis: AnalysisBundle, *, max_concurrency: int,
) -> tuple[list[Any], list[EntryRecord]]:
    """Verify finalized Entry candidates while later inventory is running."""
    semaphore = asyncio.Semaphore(max(1, max_concurrency))
    finalized: list[Any] = []
    tasks: list[asyncio.Task[tuple[int, EntryRecord]]] = []

    async def verify(index: int, candidate: Any) -> tuple[int, EntryRecord]:
        async with semaphore:
            return index, await verifier.run(candidate)

    def on_final_candidates(batch: list[Any]) -> None:
        for candidate in batch:
            index = len(finalized)
            finalized.append(candidate)
            tasks.append(asyncio.create_task(verify(index, candidate)))

    try:
        candidates = await generator.run(analysis, on_final_candidates=on_final_candidates)
        finalized_by_id = {item.candidate_id: item for item in finalized}
        returned_by_id = {item.candidate_id: item for item in candidates}
        if (len(finalized_by_id) != len(finalized)
            or len(returned_by_id) != len(candidates)
            or finalized_by_id != returned_by_id):
            raise ValueError('Entry candidates changed after finalization')
        indexed = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        raise
    records_by_id = {
        finalized[index].candidate_id: record for index, record in indexed
    }
    return candidates, [records_by_id[item.candidate_id] for item in candidates]


def _harness_action_function_ids(
    actions: list[ExternalActionSchema], entry_functions: dict[str, str],
) -> dict[str, tuple[str, ...]]:
    """Preserve the selected handler as each Action's final plan anchor."""
    return {
        action.action_id: action_harness_function_ids(
            action, entry_functions.get(action.entry_id, ""),
        )
        for action in actions
    }


def _raw_original_trial_project(project: ProjectSpec) -> ProjectSpec:
    """Permit a transport trial without turning it into a proof claim."""
    return replace(project, scenario_exploratory_drafts=True,
                   scenario_require_target_reach=False)


def _raw_trial_feedback(
    action: ExternalActionSchema, origin: str, witness: Any,
) -> list[dict[str, str]]:
    """Record what the transport did without inferring parser acceptance."""
    observation = next(iter(witness.observations), None)
    request_hex = (str(observation.request_hex) if observation is not None
                   else action.examples[0].data_hex if action.examples else '')
    submitted = bool(getattr(observation, 'request_write_completed', False))
    return [{
        'action_id': action.action_id,
        'origin': origin,
        'request_hex': request_hex,
        'response_hex': (str(observation.response_hex)
                         if observation is not None else ''),
        'request_write_completed': 'true' if submitted else 'false',
        'proof_boundary': (
            'request write does not prove peer receipt or handler success'
            if submitted else
            'delivery was not observed; no peer receipt or handler claim'
        ),
    }]


def _entry_walk_draft_witness_allowed(
    witness: Any, *, exploratory: bool, source_only: bool,
) -> bool:
    if witness.status is ScenarioStatus.PROVEN_RUNTIME:
        return True
    if source_only and witness.status in {
        ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME,
        ScenarioStatus.UNPROVEN,
    }:
        return True
    return exploratory and witness.status is ScenarioStatus.OBSERVED_RUNTIME


def _scenario_transport_blocker(
    candidate: Any, actions: dict[str, ExternalActionSchema], channel: str,
) -> str:
    from .runtime.scenario import _action_transport
    transports = {_action_transport(actions[step.action_id])
                  for step in candidate.steps if step.action_id in actions}
    if not transports or '' in transports:
        return 'original-program transport could not be established'
    if len(transports) > 1:
        return 'scenario uses different original-program transports'
    actual = next(iter(transports))
    if channel != 'auto' and actual != channel:
        return f'selected original-program executor uses {channel}; scenario needs {actual}'
    return ''


def _raw_trial_transport_blocker(
    action: ExternalActionSchema, channel: str,
) -> str:
    from .runtime.scenario import _action_transport
    transport = _action_transport(action)
    if channel == 'auto':
        return '' if transport else 'raw trial transport is ambiguous'
    if transport == channel or (not transport and permits_explicit_socket_trial(
        action.channel_kind, action.source_api, channel,
    )):
        return ''
    return f'raw trial transport {transport or "unknown"} cannot use {channel}'


def _scenario_independent_review_allows_deferred(report: GateReport) -> bool:
    return bool(report.checks) and all(
        check.status is CheckStatus.PASS or
        (check.check_id in {'HC08', 'HC10'} and check.status is CheckStatus.WARN)
        for check in report.checks
    )


def _scenario_sibling_static_deferred(
    report: GateReport, project: ProjectSpec, independent_review: bool,
) -> bool:
    return (independent_review and project.verification_backend == 'command'
            and project.scenario_attribution == 'trace'
            and _scenario_independent_review_allows_deferred(report)
            and any(check.status is CheckStatus.WARN for check in report.checks))


def _persist_imported_entries(store: ArtifactStore, entry_dir: Path) -> None:
    """Make an imported Entry verdict set self-contained and resumable."""
    for source in sorted(entry_dir.iterdir()):
        if source.is_file() and source.suffix in {".json", ".jsonl"}:
            store.write_bytes(Path("entries") / source.name, source.read_bytes())


def _source_draft_action_is_supported(action: ExternalActionSchema) -> bool:
    """Keep unresolved causal paths as drafts only, not proof.

    Require independently opened dispatcher + handler source and a concrete
    external request.  This predicate grants discovery eligibility, NEVER
    verification qualification. Runtime proof is a separate verifier result.
    """
    return (
        action.status in {ProofStatus.PROVEN_STATIC, ProofStatus.POSSIBLE}
        and bool(action.examples)
        and action.discriminator != 'UNCLASSIFIED_INPUT'
        and any(item.line is not None for item in action.entry_probe_evidence)
        and not _is_source_literal_runtime_trial(action)
        and not _is_matched_source_case_runtime_trial(action)
        and {action.dispatcher_function_id, action.handler_function_id}.issubset(
            {e.function_id for e in action.evidence if e.line is not None}
        )
    )


def _is_source_literal_runtime_trial(action: ExternalActionSchema) -> bool:
    return any(
        example.origin == "source_literal_runtime_hypothesis"
        for example in action.examples
    )


def _is_matched_source_case_runtime_trial(action: ExternalActionSchema) -> bool:
    """A cited source case permits an original-program trial, never proof."""
    return (
        action.status in {ProofStatus.POSSIBLE, ProofStatus.PROVEN_STATIC}
        and any(
            example.origin == "matched_source_case_hypothesis"
            and any(item.line is not None for item in example.evidence)
            for example in action.examples
        )
        and any(item.line is not None for item in action.success_evidence)
    )


def _preflight_round_robin(
    actions: list[ExternalActionSchema],
) -> list[ExternalActionSchema]:
    """Give each external Entry a runtime attempt before sampling it again."""
    buckets: dict[str, deque[ExternalActionSchema]] = {}
    for action in actions:
        buckets.setdefault(action.entry_id, deque()).append(action)
    result: list[ExternalActionSchema] = []
    while buckets:
        for entry_id in list(buckets):
            bucket = buckets[entry_id]
            result.append(bucket.popleft())
            if not bucket:
                del buckets[entry_id]
    return result


def validate_active_output_schemas(workflow_mode: str = "boundary") -> None:
    """Fail before analysis or LLM work if any active role schema is invalid.

    Provider-side structured-output rejection is deterministic.  Discovering
    it only when a late workflow role first runs wastes every earlier analysis
    turn and can fan one defect out into hundreds of identical branch errors.
    """

    for role, schema in _ACTIVE_OUTPUT_SCHEMAS.items():
        if workflow_mode == "boundary" and role not in _BOUNDARY_SCHEMAS:
            continue
        try:
            validate_strict_output_schema(schema)
        except InvalidOutputSchemaError as exc:
            raise InvalidOutputSchemaError(
                f"active output schema for {role!r} is invalid: {exc}"
            ) from exc


class HarnessCreator:
    def __init__(
        self,
        project: ProjectSpec,
        llm: LLMProvider,
        *,
        max_generation_attempts: int = 0,
        dynamic_verification: bool = True,
        progress: Callable[[str], None] | None = None,
        agent_debug_console: bool = False,
        precomputed_analysis: AnalysisBundle | None = None,
        precomputed_usage_evidence: UsageEvidenceBundle | None = None,
        precomputed_upstream_runs: list[UpstreamProcessResult] | None = None,
        action_resume_continuations: list[dict[str, Any]] | None = None,
        surface_resume_continuations: list[dict[str, Any]] | None = None,
        request_resume_root: Path | None = None,
    ):
        self.project = project.normalized()
        self.llm = llm
        if max_generation_attempts < 0:
            raise ValueError("max_generation_attempts must be nonnegative")
        self.max_generation_attempts = max_generation_attempts
        self.dynamic_verification = dynamic_verification
        self.progress = progress
        self.agent_debug_console = agent_debug_console
        self.precomputed_analysis = precomputed_analysis
        self.precomputed_usage_evidence = precomputed_usage_evidence
        self.precomputed_upstream_runs = list(precomputed_upstream_runs or [])
        self.action_resume_continuations = list(action_resume_continuations or [])
        self.surface_resume_continuations = list(surface_resume_continuations or [])
        self.request_resume_root = request_resume_root

    async def run(self) -> ScenarioRunSummary:
        self._run_started_monotonic = time.monotonic()
        # This must precede static analysis, artifact creation, and every LLM
        # call.  A schema bug is configuration/infrastructure failure, not a
        # per-Entry semantic failure that should be repeated across branches.
        validate_active_output_schemas(self.project.workflow_mode)
        self._network_harness_config = (
            NetworkHarnessConfig.load(self.project.network_harness_config)
            if self.project.network_harness_config is not None else None
        )
        if self._network_harness_config is not None:
            if self.project.workflow_mode != 'action':
                raise ValueError('network harness config requires the Action workflow')
            self._network_harness_config.preflight(self.project.source_root)
        run_id = self.project.resume_run_id or self._run_id()
        if self.project.resume_run_id and not (self.project.output_root / run_id).is_dir():
            raise ValueError(f"resume run directory does not exist: {run_id}")
        store = ArtifactStore(self.project.output_root / run_id)
        self._emit(f"run {run_id} started; artifacts={store.root}")
        # Toolchain incompatibilities are known before spending LLM turns.
        # They are per-verification blockers, never a reason to discard
        # valid source-derived Entry or Action candidates.
        capability_report = inspect_capabilities(self.project)
        for message in capability_report["verification_blockers"]:
            self._emit("WARNING: " + message)
        analysis = self._prepare_static_analysis()
        if self.project.workflow_mode == "boundary" and self.project.resume_run_id:
            # Check the exact indexed product source and execution settings
            # before touching any existing run artifact. A mismatched resume
            # must not overwrite its previous analysis, Entry, or summary.
            resume_targets = unique_strings([
                self.project.name, self.project.oss_fuzz_project or "",
                Path(self.project.scenario_command[0]).name
                if self.project.scenario_command else "",
            ])
            resume_ids = EntryGeneratorAgent(
                self.llm, chunk_size=self.project.entry_batch_size,
                target_names=resume_targets,
            ).product_function_ids(analysis)
            resume_signature = {
                "source_root": str(self.project.source_root),
                "functions": [
                    (fid, analysis.functions[fid].source) for fid in sorted(resume_ids)
                ],
                "scenario_command": self.project.scenario_command,
                "scenario_channel": self.project.scenario_channel,
                "scenario_port": self.project.scenario_port,
                "scenario_attribution": self.project.scenario_attribution,
                "verification_backend": self.project.verification_backend,
                "build_command": self.project.build_command,
            }
            expected = hashlib.sha256(json.dumps(
                resume_signature, sort_keys=True, ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            resume_file = store.root / "workflow" / "resume-fingerprint.json"
            if not resume_file.is_file() or json.loads(
                resume_file.read_text(encoding="utf-8")
            ).get("sha256") != expected:
                raise ValueError("resume source/command/backend fingerprint differs from saved run")
        store.write_json("workflow/capability-preflight.json", capability_report)
        effective_concurrency = int(getattr(self.llm, "max_concurrency", 1))
        role_models = dict(getattr(self.llm, "role_models", {}))
        reasoning_effort = getattr(self.llm, "effort", None)
        self._emit(f"effective LLM concurrency: {effective_concurrency}")
        supports_compaction = getattr(self.llm, "supports_context_compaction", True)
        session_roles = (
            "Entry/Behavior/ExecutionContract/Harness"
            if self.project.workflow_mode == "boundary" else "Entry/Action/State/Harness"
        )
        if supports_compaction:
            self._emit(
                f"LLM context sessions: sticky per {session_roles}; "
                "worker recycle is deferred until session close; same-thread "
                "context compaction is enabled"
            )
        else:
            self._emit(f"LLM context sessions: sticky per {session_roles}; "
                       "full message history is sent; automatic compaction is unavailable")
        store.write_json("project.json", self.project)
        store.write_json(
            "workflow.json",
            {
                "dynamic_verification": self.dynamic_verification,
                "workflow_mode": self.project.workflow_mode,
                "max_generation_attempts": self.max_generation_attempts,
                "role_models": role_models,
                "reasoning_effort": reasoning_effort,
                "role_efforts": dict(getattr(self.llm, "role_efforts", {})),
                "llm_session_policy": {
                    "stateful_context_walks": True,
                    "worker_affinity": True,
                    "recycle_deferred_until_session_close": supports_compaction,
                    "stateful_resume_cache": True,
                    "stateful_resume_policy": "exact_ordered_whole_session",
                    "same_thread_context_compaction": supports_compaction,
                    "context_compact_ratio": 0.70 if supports_compaction else None,
                    "context_token_reserve": 32000 if supports_compaction else None,
                    "one_function_per_context_turn": True,
                    "runtime_witness_required_for_final_qualification": True,
                    "source_only_drafts_permitted": (
                        self.project.workflow_mode == "boundary"
                        or self.project.scenario_source_drafts
                    ),
                    "exploratory_build_only": self.project.scenario_exploratory_drafts,
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
        if self.precomputed_usage_evidence is not None:
            usage_evidence = self.precomputed_usage_evidence
            for index, upstream_run in enumerate(self.precomputed_upstream_runs):
                store.write_json(
                    Path("analysis/upstream")
                    / f"{upstream_run.provider.casefold()}-run-{index + 1}.json",
                    upstream_run,
                )
        else:
            rubick_nfa_inputs = list(self.project.rubick_nfa)
            rubick_a2dg_inputs = list(self.project.rubick_a2dg)
            if self.project.fuzzgen_evidence:
                rubick_a2dg_inputs.extend(fuzzgen_reports_to_rubick_a2dg(
                    self.project.fuzzgen_evidence,
                    store.root / "analysis" / "upstream" / "rubick-input",
                ))
            if rubick_a2dg_inputs:
                if self.project.research_repos_root is None:
                    raise UpstreamToolError(
                        "RUBICK A2DG inputs require --research-repos-root"
                    )
                rubick_output = store.root / "analysis" / "upstream" / "rubick-nfa.json"
                try:
                    rubick_run = run_rubick_a2dg(
                        self.project.research_repos_root,
                        rubick_a2dg_inputs,
                        rubick_output,
                    )
                except UpstreamToolError as exc:
                    store.write_json(
                        "analysis/upstream/rubick-run.json",
                        {
                            "provider": "RUBICK",
                            "state": "ERROR",
                            "inputs": [str(path) for path in rubick_a2dg_inputs],
                            "reason": str(exc),
                        },
                    )
                    raise
                store.write_json("analysis/upstream/rubick-run.json", rubick_run)
                rubick_nfa_inputs.append(rubick_run.output)
                self._emit(
                    f"RUBICK original A2DG engine completed: {len(rubick_a2dg_inputs)} input graph(s)"
                )
            usage_evidence = load_usage_evidence(
                analysis,
                fuzzgen_reports=self.project.fuzzgen_evidence,
                hopper_constraints=self.project.hopper_constraints,
                winnie_reports=self.project.winnie_evidence,
                rubick_nfas=rubick_nfa_inputs,
                upstream_revisions=load_upstream_revisions(
                    self.project.research_repos_root
                ),
            )
        store.write_json("analysis/upstream-usage-evidence.json", usage_evidence)
        usage_artifacts = discover_usage_artifacts(
            self.project.source_root,
            analysis,
            self.project.scenario_evidence_paths,
        )
        store.write_json(
            "analysis/project-usage-artifacts.json",
            {
                "count": len(usage_artifacts),
                "policy": (
                    "usage artifacts are request-layout/order candidates and "
                    "never product Entries or runtime reachability proof"
                ),
                "artifacts": usage_artifacts,
            },
        )
        provider_errors = [
            item for item in usage_evidence.providers if item.state == "ERROR"
        ]
        if provider_errors:
            raise UpstreamToolError(
                "configured upstream evidence failed validation: "
                + "; ".join(
                    f"{item.provider} {item.source}: {item.reason}"
                    for item in provider_errors
                )
            )
        used_providers = list(dict.fromkeys(
            item.provider for item in usage_evidence.providers if item.state == "USED"
        ))
        self._emit(
            "upstream usage evidence: "
            + (
                f"used={','.join(used_providers)}, "
                f"constraints={len(usage_evidence.constraints)}, "
                f"sequences={len(usage_evidence.sequences)}"
                if used_providers
                else "no project-specific upstream output supplied; no provider was claimed as used"
            )
        )
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

        entry_target_names = unique_strings([
            self.project.name,
            self.project.oss_fuzz_project or "",
            (
                Path(self.project.scenario_command[0]).name
                if self.project.scenario_command else ""
            ),
        ])
        binary_report: dict[str, Any] = {}
        if self.project.analysis_binary:
            binary_report = linked_source_priority(
                self.project.analysis_binary, self.project.source_root,
                sorted({function.file for function in analysis.functions.values()}),
            )
        preferred_files, source_priority_provider = _preferred_entry_source_files(
            binary_report, analysis.completeness,
        )
        store.write_json('analysis/entry-source-priority.json', {
            'provider': source_priority_provider,
            'preferred_files': sorted(preferred_files),
            'policy': 'inspection order only; no source file excluded',
        })
        target_binary = source_analysis_binary(self.project)
        target_closure = (
            linked_make_sources(
                target_binary, self.project.source_root,
                self.project.analysis_compile_database,
            )
            if target_binary else {
                "status": "unresolved", "source_files": [],
                "reason": "no selected target binary",
            }
        )
        store.write_json("analysis/target-source-closure.json", target_closure)
        configured_target_files = (
            set(target_closure["source_files"])
            if target_closure.get("status") == "configured_target_closure"
            else None
        )
        entry_generator = EntryGeneratorAgent(
            traced_llm,
            chunk_size=self.project.entry_batch_size,
            target_names=entry_target_names,
            preferred_source_files=preferred_files,
            configured_target_files=configured_target_files,
            trace=trace,
        )
        product_function_ids = entry_generator.product_function_ids(analysis)
        product_analysis = AnalysisBundle(
            functions={
                function_id: analysis.functions[function_id]
                for function_id in sorted(product_function_ids)
            },
            edges=[
                edge for edge in analysis.edges
                if edge.caller_id in product_function_ids
                and edge.callee_id in product_function_ids
            ],
            completeness={
                **analysis.completeness,
                "product_scope": {
                    "target_names": entry_target_names,
                    "function_count": len(product_function_ids),
                    "excluded_function_count": (
                        len(analysis.functions) - len(product_function_ids)
                    ),
                },
            },
            declarations=list(analysis.declarations),
        )
        graph = GraphStore(product_analysis)
        store.write_jsonl("analysis/source-declarations.jsonl", analysis.declarations)
        store.write_jsonl(
            "analysis/product-functions.jsonl",
            product_analysis.function_list(),
        )
        store.write_jsonl("analysis/product-edges.jsonl", product_analysis.edges)
        store.write_json(
            "analysis/product-scope.json",
            product_analysis.completeness["product_scope"],
        )
        self._emit(
            "product analysis scope: "
            f"{len(product_analysis.functions)}/{len(analysis.functions)} functions, "
            f"{len(product_analysis.edges)}/{len(analysis.edges)} edges"
        )
        trace(
            "static_analysis",
            "product_scope_selected",
            {
                "message": (
                    f"selected {len(product_analysis.functions)} functions for "
                    f"targets {entry_target_names}"
                ),
                "target_names": entry_target_names,
                "function_count": len(product_analysis.functions),
                "edge_count": len(product_analysis.edges),
                "excluded_function_count": (
                    len(analysis.functions) - len(product_analysis.functions)
                ),
            },
        )

        if self.project.workflow_mode == "boundary":
            signature_input = {
                "source_root": str(self.project.source_root),
                "functions": [
                    (fid, fn.source) for fid, fn in sorted(product_analysis.functions.items())
                ],
                "scenario_command": self.project.scenario_command,
                "scenario_channel": self.project.scenario_channel,
                "scenario_port": self.project.scenario_port,
                "scenario_attribution": self.project.scenario_attribution,
                "verification_backend": self.project.verification_backend,
                "build_command": self.project.build_command,
            }
            fingerprint = hashlib.sha256(json.dumps(
                signature_input, sort_keys=True, ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            fingerprint_path = store.root / "workflow" / "resume-fingerprint.json"
            if self.project.resume_run_id:
                if not fingerprint_path.is_file() or json.loads(
                    fingerprint_path.read_text(encoding="utf-8")
                ).get("sha256") != fingerprint:
                    raise ValueError("resume source/command/backend fingerprint differs from saved run")
            else:
                store.write_json("workflow/resume-fingerprint.json", {"sha256": fingerprint})

        if self.project.workflow_mode == "boundary" and (
            self.project.resume_run_id or self.project.entry_artifacts_from
        ):
            artifact_root = self.project.entry_artifacts_from or store.root
            if self.project.entry_artifacts_from:
                old_functions = artifact_root / "analysis" / "product-functions.jsonl"
                if not old_functions.is_file():
                    raise ValueError("Entry import requires saved product function sources")
                old_source = {
                    row["function_id"]: row["source"] for row in (
                        json.loads(line) for line in old_functions.read_text(
                            encoding="utf-8"
                        ).splitlines() if line
                    )
                }
                new_source = {
                    fid: fn.source for fid, fn in product_analysis.functions.items()
                }
                if old_source != new_source:
                    raise ValueError("Entry import rejected: indexed product source differs")
            entry_dir = artifact_root / "entries"
            required = ("candidates.jsonl", "verified.jsonl", "unresolved.jsonl")
            if not all((entry_dir / name).is_file() for name in required):
                raise ValueError("resume requires complete saved Entry candidate and verdict artifacts")
            def load_rows(name: str) -> list[dict[str, Any]]:
                return [json.loads(line) for line in (entry_dir / name).read_text(
                    encoding="utf-8"
                ).splitlines() if line]
            def load_entry(row: dict[str, Any]) -> EntryRecord:
                row["status"] = Verdict(row["status"])
                row["site_kind"] = EntrySiteKind(row.get("site_kind", "DIRECT_ACQUISITION"))
                row["analysis_disposition"] = AnalysisDisposition(
                    row.get("analysis_disposition", "COMPLETE")
                )
                row["evidence"] = [Evidence(**item) for item in row.get("evidence", [])]
                return EntryRecord(**row)
            candidates = load_rows("candidates.jsonl")
            verified = [load_entry(row) for row in load_rows("verified.jsonl")]
            unresolved = [load_entry(row) for row in load_rows("unresolved.jsonl")]
            uninspected_file = entry_dir / "uninspected-functions.json"
            uninspected = json.loads(uninspected_file.read_text(encoding="utf-8")).get(
                "count", 0
            ) if uninspected_file.is_file() else 0
            self._emit(f"Entry reuse: reused {len(verified)} verified and "
                       f"{len(unresolved)} unresolved records without model calls")
            if self.project.entry_artifacts_from:
                _persist_imported_entries(store, entry_dir)
                store.write_json("workflow/entry-provenance.json", {
                    "source_run": str(artifact_root),
                    "validation": "exact indexed product function source equality",
                })
            return await run_boundary_workflow(
                project=self.project, run_id=run_id, store=store, analysis=analysis,
                graph=graph, llm=traced_llm, trace=trace, candidates=candidates,
                verified=verified, unresolved=unresolved,
                uninspected_functions=uninspected,
                max_generation_attempts=self.max_generation_attempts,
                dynamic_verification=self.dynamic_verification, progress=self.progress,
            )
        estimated_batches = len(entry_generator.batches(analysis))
        self._emit(f"entry generation started: {estimated_batches} LLM batches")
        verifier = EntryVerifierAgent(
            traced_llm,
            graph,
            depth=self.project.context_depth,
            budget=self.project.max_context_functions,
            selected_program=selected_binary_is_program(target_binary),
            trace=trace,
        )
        candidates, entries = await _generate_and_verify_entries(
            entry_generator, verifier, analysis,
            max_concurrency=getattr(traced_llm, 'max_concurrency', 1),
        )
        store.write_jsonl("entries/candidates.jsonl", candidates)
        store.write_json("entries/uninspected-functions.json", {
            "count": len(entry_generator.incomplete_functions),
            "functions": entry_generator.incomplete_functions,
            "policy": "failed or deferred function inspection is unknown, never a negative Entry finding",
        })
        self._emit(f"entry generation completed: {len(candidates)} deduplicated candidates")

        self._emit(f"entry verification completed: {len(entries)} candidates")
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

        if self.project.workflow_mode == "boundary":
            return await run_boundary_workflow(
                project=self.project,
                run_id=run_id, store=store, analysis=analysis, graph=graph,
                llm=traced_llm, trace=trace, candidates=candidates,
                verified=verified, unresolved=unresolved,
                uninspected_functions=len(entry_generator.incomplete_functions),
                max_generation_attempts=self.max_generation_attempts,
                dynamic_verification=self.dynamic_verification,
                progress=self.progress,
            )

        # Legacy Action/Scenario path is opt-in for regression comparisons.
        return await self._run_scenario_pipeline(
            run_id=run_id,
            store=store,
            analysis=analysis,
            graph=graph,
            traced_llm=traced_llm,
            trace=trace,
            usage_evidence=usage_evidence,
            usage_artifacts=usage_artifacts,
            candidates=candidates,
            verified=verified,
            unresolved=unresolved,
            uninspected_functions=len(entry_generator.incomplete_functions),
        )

        # Small Feature recovery is the final context-growing phase. Definite
        # Entries participate immediately; unresolved candidates may be
        # promoted while the operation/lifecycle is recovered. Entries that
        # remain unresolved are deferred with their evidence gap -- an
        # exhausted source walk or app-server loss is not contrary evidence.
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
            usage_evidence=usage_evidence,
        )
        recovered_small_features = (
            await small_feature_agent.run(feature_entries) if feature_entries else []
        )
        operation_seeds = list(small_feature_agent.last_operation_seeds)
        store.write_json(
            "features/operation-seeds.json",
            {
                "count": len(operation_seeds),
                "status_counts": {
                    status.value: sum(
                        item.status is status for item in operation_seeds
                    )
                    for status in ProofStatus
                },
                "seeds": [as_json(item) for item in operation_seeds],
            },
        )
        agent_infrastructure_errors = list(
            small_feature_agent.last_infrastructure_failures
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
        deferred_entry_outcomes = list(
            small_feature_agent.last_deferred_entry_outcomes
        )
        store.write_jsonl("entries/promoted-during-small.jsonl", promoted_entries)
        store.write_jsonl("entries/verified-final.jsonl", final_feature_entries)
        store.write_jsonl(
            "entries/dropped-after-small.jsonl",
            dropped_entry_outcomes,
        )
        store.write_jsonl(
            "entries/deferred-after-small.jsonl",
            deferred_entry_outcomes,
        )
        trace(
            "orchestrator",
            "small_feature_entry_resolution_completed",
            {
                "message": (
                    f"Small Feature recovery promoted {len(promoted_entries)} unresolved Entries "
                    f"and dropped {len(dropped_entry_outcomes)}, deferred "
                    f"{len(deferred_entry_outcomes)}"
                ),
                "promoted_entry_ids": [
                    entry.entry_id for entry in promoted_entries
                ],
                "dropped_entries": dropped_entry_outcomes,
                "deferred_entries": deferred_entry_outcomes,
            },
        )
        self._emit(
            f"entry final resolution completed: {len(promoted_entries)} promoted, "
            f"{len(dropped_entry_outcomes)} dropped, "
            f"{len(deferred_entry_outcomes)} deferred, "
            f"{len(final_feature_entries)} final verified"
        )
        semantic_small_features = [
            feature for feature in small_features
            if _eligible_for_large_feature(feature)
        ]
        harness_ready_small_features = [
            feature for feature in semantic_small_features
            if feature.planning_complete
        ]
        self._emit(
            f"small-feature recovery completed: {len(small_features)} semantic features, "
            f"{len(semantic_small_features)} eligible for Large Feature composition, "
            f"{len(harness_ready_small_features)} already protocol-ready"
        )
        for feature in small_features:
            store.write_json(Path("features/small") / f"{feature.small_feature_id}.json", feature)
        store.write_json(
            "features/small-readiness.json",
            {
                "semantic_feature_count": len(small_features),
                "large_feature_eligible_count": len(semantic_small_features),
                "harness_ready_count": len(harness_ready_small_features),
                "large_feature_eligible_ids": [
                    feature.small_feature_id for feature in semantic_small_features
                ],
                "ready_small_feature_ids": [
                    feature.small_feature_id for feature in harness_ready_small_features
                ],
                "blocked": [
                    {
                        "small_feature_id": feature.small_feature_id,
                        "name": feature.name,
                        "semantic_complete": feature.semantic_complete,
                        "semantic_blockers": feature.semantic_blockers,
                        "planning_blockers": feature.planning_blockers,
                        "proof_obligations": [
                            as_json(item) for item in feature.proof_obligations
                        ],
                    }
                    for feature in small_features
                    if not feature.planning_complete
                ],
            },
        )
        self._emit(
            f"large-feature grouping started: {len(semantic_small_features)} "
            "semantic Small Features; unresolved executable facts remain as proof obligations"
        )
        large_feature_candidates = (
            await LargeFeatureAgent(traced_llm, graph, trace=trace).run(
                semantic_small_features
            )
            if semantic_small_features else []
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
        dynamic = HarnessVerifierAgent(
            CommandRunner(), self.project, graph, progress=self._emit
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
            repeated_failure_counts: dict[str, int] = {}
            members = [item for item in small_features if item.small_feature_id in large.small_feature_ids]
            for attempt in (count(1) if self.max_generation_attempts == 0
                            else range(1, self.max_generation_attempts + 1)):
                self._emit(
                    f"harness {large.large_feature_id}: generation attempt "
                    f"{attempt}/"
                    f"{self.max_generation_attempts or 'unbounded'}"
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
                    generated_by_action.setdefault(plan.target_action_id, []).append(
                        draft.manifest.harness_id
                    )
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
                        "operation_protocols": draft.operation_protocols,
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
                    static_signature = _gate_report_signature("static", report)
                    repeated_failure_counts[static_signature] = (
                        repeated_failure_counts.get(static_signature, 0) + 1
                    )
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
                        # Missing source/type/callback facts block this draft;
                        # they do not prove that Entry or feature recovery was
                        # wrong, so preserve the evidence and stop here.
                        feature_infrastructure_blocked = True
                        break
                    if any(
                        check.check_id in {"HC14", "HC19"}
                        and check.status is CheckStatus.FAIL
                        for check in report.checks
                    ):
                        feature_infrastructure_blocked = True
                        break
                    if repeated_failure_counts[static_signature] >= 2:
                        feature_infrastructure_blocked = True
                        break
                    if (self.max_generation_attempts
                        and attempt >= self.max_generation_attempts):
                        feature_infrastructure_blocked = True
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
                    review_signature = _gate_report_signature(
                        "independent-review", independent_report
                    )
                    repeated_failure_counts[review_signature] = (
                        repeated_failure_counts.get(review_signature, 0) + 1
                    )
                    self._emit(
                        f"harness {draft.manifest.harness_id}: independent generator audit "
                        f"failed ({len(feedback)} findings)"
                    )
                    if _independent_review_requires_stop(
                        independent_report,
                        attempt=attempt,
                        max_attempts=self.max_generation_attempts,
                    ):
                        feature_infrastructure_blocked = True
                        break
                    if repeated_failure_counts[review_signature] >= 2:
                        feature_infrastructure_blocked = True
                        break
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
                    failure = verification.failure
                    if failure is not None:
                        repeated_failure_counts[failure.signature] = (
                            repeated_failure_counts.get(failure.signature, 0) + 1
                        )
                        if repeated_failure_counts[failure.signature] >= 2:
                            feature_infrastructure_blocked = True
                            break
                    if (self.max_generation_attempts
                        and attempt >= self.max_generation_attempts):
                        feature_infrastructure_blocked = True
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
                if (
                    not verification.qualified
                    and verification.failure is not None
                    and verification.failure.kind
                    is VerificationFailureKind.REACHABILITY
                ):
                    # The loop above already performed the one bounded seed
                    # refinement allowed by the verifier workflow. A remaining
                    # miss is an input-binding/action-plan problem, not a reason
                    # to regenerate equivalent C up to eight times.
                    verification.failure.disposition = RetryDisposition.STOP
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
                if verification.harness_fault_seeds:
                    regression_seeds = _deduplicate_seed_specs([
                        *regression_seeds, *verification.harness_fault_seeds
                    ])
                    self._emit(
                        f"harness {draft.manifest.harness_id}: retained "
                        f"{len(regression_seeds)} regression crash seeds for the next attempt"
                    )
                failure = verification.failure
                if failure is not None:
                    repeated_failure_counts[failure.signature] = (
                        repeated_failure_counts.get(failure.signature, 0) + 1
                    )
                    trace(
                        "harness_verifier",
                        "retry_routed",
                        {
                            "message": (
                                f"{failure.kind} at {failure.phase} -> "
                                f"{failure.disposition}"
                            ),
                            "harness_id": draft.manifest.harness_id,
                            "attempt": attempt,
                            "failure": as_json(failure),
                            "repeat_count": repeated_failure_counts[
                                failure.signature
                            ],
                        },
                    )
                    if failure.disposition is RetryDisposition.REPLAN_FEATURE:
                        # A feature recovery pass requires a typed,
                        # source-evidenced contract conflict. Ordinary
                        # reachability/coverage misses are not that evidence.
                        if _has_evidenced_feature_contract_conflict(feedback):
                            structural_feedback = unique_strings(feedback)
                        else:
                            feature_infrastructure_blocked = True
                        break
                    if failure.disposition is RetryDisposition.STOP:
                        feature_infrastructure_blocked = True
                        break
                    if repeated_failure_counts[failure.signature] >= 2:
                        feature_infrastructure_blocked = True
                        break
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
                            excluded_anchors=[],
                        )
                        operation_seeds = merge_operation_seed_records([
                            *operation_seeds,
                            *small_feature_agent.last_operation_seeds,
                        ])
                        agent_infrastructure_errors.extend(
                            small_feature_agent.last_infrastructure_failures
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
                                item for item in refined
                                if _eligible_for_large_feature(item)
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
        final_semantic_small_features = [
            feature for feature in small_features
            if _eligible_for_large_feature(feature)
        ]
        store.write_json(
            "features/small-readiness.json",
            {
                "semantic_feature_count": len(small_features),
                "large_feature_eligible_count": len(final_semantic_small_features),
                "harness_ready_count": len(final_ready_small_features),
                "large_feature_eligible_ids": [
                    feature.small_feature_id
                    for feature in final_semantic_small_features
                ],
                "ready_small_feature_ids": [
                    feature.small_feature_id for feature in final_ready_small_features
                ],
                "blocked": [
                    {
                        "small_feature_id": feature.small_feature_id,
                        "name": feature.name,
                        "semantic_complete": feature.semantic_complete,
                        "semantic_blockers": feature.semantic_blockers,
                        "planning_blockers": feature.planning_blockers,
                        "proof_obligations": [
                            as_json(item) for item in feature.proof_obligations
                        ],
                    }
                    for feature in small_features
                    if not feature.planning_complete
                ],
            },
        )
        # Structural replanning can expose a nested dispatcher that was not
        # present during the initial Entry pass. Rewrite the inventory after
        # all replans so omission accounting reflects the complete run rather
        # than only its first Small Feature pass.
        store.write_json(
            "features/operation-seeds.json",
            {
                "count": len(operation_seeds),
                "status_counts": {
                    status.value: sum(
                        item.status is status for item in operation_seeds
                    )
                    for status in ProofStatus
                },
                "seeds": [as_json(item) for item in operation_seeds],
            },
        )
        store.write_json(
            "features/evidence-ledger.json",
            {
                "operation_seeds": [
                    as_json(item) for item in operation_seeds
                ],
                "entries": [
                    {
                        "entry_id": entry.entry_id,
                        "status": entry.status,
                        "analysis_disposition": entry.analysis_disposition,
                        "inspected_function_ids": entry.inspected_function_ids,
                        "evidence": [as_json(item) for item in entry.evidence],
                    }
                    for entry in final_feature_entries
                ],
                "small_features": [
                    {
                        "small_feature_id": feature.small_feature_id,
                        "semantic_complete": feature.semantic_complete,
                        "semantic_blockers": feature.semantic_blockers,
                        "protocol_ready_before_p2": feature.planning_complete,
                        "operation_seed_ids": feature.operation_seed_ids,
                        "proof_obligations": [
                            as_json(item) for item in feature.proof_obligations
                        ],
                    }
                    for feature in small_features
                ],
                "large_features": [
                    {
                        "large_feature_id": feature.large_feature_id,
                        "small_feature_ids": feature.small_feature_ids,
                        "protocol_ready_before_p2": feature.protocol_ready,
                        "dependencies": [
                            as_json(item) for item in feature.dependencies
                        ],
                        "proof_obligations": [
                            as_json(item) for item in feature.proof_obligations
                        ],
                    }
                    for feature in [
                        *terminal_large_features, *discarded_large_features
                    ]
                ],
                "accounting": {
                    "semantic_small_features": len(small_features),
                    "large_feature_eligible_small_features": len(
                        final_semantic_small_features
                    ),
                    "large_features": len(terminal_large_features),
                    "discarded_large_features": len(discarded_large_features),
                },
            },
        )
        if not terminal_large_features and agent_infrastructure_errors:
            run_status = "FAILED_AGENT_INFRASTRUCTURE"
        elif not terminal_large_features and deferred_entry_outcomes:
            run_status = "PARTIAL_ANALYSIS_INCOMPLETE"
        elif not terminal_large_features:
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
        elif (
            len(qualified_ids) == len(terminal_large_features)
            and not agent_infrastructure_errors
        ):
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
            svf_status=str(analysis.completeness.get("svf_status", "UNKNOWN")),
            svf_used=bool(analysis.completeness.get("svf_used", False)),
            svf_indirect_edges_reported=int(
                analysis.completeness.get("svf_indirect_edges_reported", 0)
            ),
            svf_indirect_edges_mapped=int(
                analysis.completeness.get("svf_indirect_edges_mapped", 0)
            ),
            svf_indirect_edges_unmapped=len(
                analysis.completeness.get("svf_mapping_failures", []) or []
            ),
            candidates=len(candidates),
            verified_entries=len(final_feature_entries),
            unresolved_entries=len(deferred_entry_outcomes),
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
            deferred_entries_after_small_feature=len(deferred_entry_outcomes),
            verification_infrastructure_failures=len(
                verification_infrastructure_errors
            ),
            agent_infrastructure_failures=len(agent_infrastructure_errors),
            large_feature_eligible_small_features=len(
                final_semantic_small_features
            ),
            open_proof_obligations=sum(
                obligation.status not in {
                    ProofStatus.PROVEN_STATIC, ProofStatus.PROVEN_RUNTIME
                }
                for feature in terminal_large_features
                for obligation in feature.proof_obligations
            ),
            operation_seeds=len(operation_seeds),
            unresolved_operation_seeds=sum(
                item.status is ProofStatus.POSSIBLE
                for item in operation_seeds
            ),
        )
        store.write_jsonl(
            "debug/agent-infrastructure-failures.jsonl",
            agent_infrastructure_errors,
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

    async def _run_scenario_pipeline(
        self,
        *,
        run_id: str,
        store: ArtifactStore,
        analysis: AnalysisBundle,
        graph: GraphStore,
        traced_llm: LLMProvider,
        trace: Callable[[str, str, dict[str, Any]], None],
        usage_evidence: UsageEvidenceBundle,
        usage_artifacts: list[Any],
        candidates: list[Any],
        verified: list[EntryRecord],
        unresolved: list[EntryRecord],
        uninspected_functions: int = 0,
    ) -> ScenarioRunSummary:
        agent_infrastructure_errors: list[str] = []
        grammars = load_netlifter_grammars(self.project.netlifter_bnf)
        store.write_json(
            "analysis/netlifter-grammars.json",
            {
                "count": len(grammars),
                "grammars": [grammar.prompt_payload(limit=256) for grammar in grammars],
                "policy": (
                    "original Popeye output constrains input layout; source and runtime "
                    "evidence remain required for reachability"
                ),
            },
        )

        # Unresolved-but-source-located direct acquisitions are never
        # reclassified as VERIFIED. Exploration may still test their external
        # behavior; downstream actions remain POSSIBLE until new evidence.
        # Source-located, unresolved external acquisitions are valuable
        # recall candidates independent of whether runtime exploration was
        # explicitly requested. They remain POSSIBLE, never VERIFIED.
        uncertain_entries: list[EntryRecord] = [
            entry for entry in unresolved
            if entry.status is Verdict.UNRESOLVED
            # An unresolved site may be explored only when the verifier has
            # at least partial evidence of external control.  An unknown FD
            # producer (for example a program-created notification pipe) is
            # retained as an Entry obligation, not sent into an expensive
            # Action walk that would turn internal operations into Actions.
            and entry.attacker_control in {"full", "partial"}
            and entry.site_kind in {
                EntrySiteKind.DIRECT_ACQUISITION,
                EntrySiteKind.EXTERNAL_CALLBACK,
            }
            and entry.entry_function_id in graph.bundle.functions
            and entry.entry_line is not None
            and any(
                evidence.function_id == entry.entry_function_id
                and evidence.line == entry.entry_line
                for evidence in entry.evidence
            )
        ]
        analyzed_entries = [*verified, *uncertain_entries]
        # First identify semantic Actions from source. No request bytes are
        # synthesized or sent to the original program before selection.
        self._emit(
            f"input-action reconstruction started: {len(verified)} verified, "
            f"{len(uncertain_entries)} unresolved exploratory Entries"
        )
        action_agent = InputActionAgent(
            traced_llm, graph,
            source_root=self.project.source_root,
            budget=self.project.max_context_functions,
            max_branch_validations=self.project.max_scenario_candidates,
            netlifter=grammars,
            scenario_channel=self.project.scenario_channel,
            scenario_response_protocol=self.project.scenario_response_protocol,
            usage_artifacts=usage_artifacts,
            resume_continuations=self.action_resume_continuations,
            trace=trace,
            checkpoint=lambda payload: store.write_json("actions/progress.json", payload),
            include_source_literal_trials=False,
        )
        semantic_actions = (
            await action_agent.run(analyzed_entries) if analyzed_entries else []
        )
        discovered_action_entry_ids = {item.entry_id for item in semantic_actions}
        store.write_jsonl("actions/discovered-semantic.jsonl", semantic_actions)

        # A model may reject incidental setup only from the source it cited.
        # Missing examples and uncertain usefulness keep an Action available.
        selection_agent = ActionSelectionAgent(traced_llm, graph)
        selection = await selection_agent.run(semantic_actions)
        source_groups = selection_agent.last_groups
        store.write_jsonl("actions/source-groups.jsonl", source_groups)
        self._emit(
            "Action source grouping completed: "
            f"{len(semantic_actions)} candidates in {len(source_groups)} review groups; "
            f"shared_effect={sum(group.relation == 'SAME_SOURCE_EFFECT' for group in source_groups)}, "
            f"unresolved={sum(group.relation == 'UNRESOLVED' for group in source_groups)}"
        )
        store.write_jsonl("actions/selection.jsonl", selection)
        for item in selection:
            self._emit(
                f"[ACTION SELECT] {item.action_id} -> {item.disposition} | "
                f"{item.reason[:180]}"
            )
        selected_ids = {item.action_id for item in selection
                        if item.disposition != "DROP"}
        store.write_jsonl("actions/dropped-before-harness.jsonl", [
            item for item in selection if item.disposition == "DROP"
        ])
        store.write_jsonl("actions/unresolved-selection.jsonl", [
            item for item in selection if item.disposition == "UNRESOLVED"
        ])
        semantic_actions = [
            item for item in semantic_actions if item.action_id in selected_ids
        ]
        self._emit(
            f"Action selection before input generation: retained={len(semantic_actions)}, "
            f"dropped={sum(item.disposition == 'DROP' for item in selection)}, "
            f"unresolved={sum(item.disposition == 'UNRESOLVED' for item in selection)}"
        )

        # Source-backed request synthesis happens once, after selection, for
        # every retained semantic Action. A missing request stays an obligation.
        request_agent = ActionRequestAgent(
            traced_llm, graph, source_root=self.project.source_root,
            checkpoint_store=store,
            resume_checkpoint_dir=self.request_resume_root,
            progress=lambda decision, completed, total, reused: self._emit(
                f"[ACTION REQUEST] {completed}/{total} {decision.action_id} "
                f"-> {decision.disposition} | examples={decision.example_count} "
                f"| opened={len(decision.opened_function_ids)} "
                f"| cached={reused}"
            ),
        )
        retained_selection_ids = {item.action_id for item in semantic_actions}
        shared_effects = {
            action_id: {
                "group_id": group.group_id,
                "action_ids": [item for item in group.action_ids
                               if item in retained_selection_ids],
                "source_summary": group.reason,
                "source_evidence": group.source_evidence,
            }
            for group in source_groups
            if group.relation == "SAME_SOURCE_EFFECT"
            for action_id in group.action_ids
            if action_id in retained_selection_ids
        }
        semantic_actions, request_decisions = await request_agent.run(
            semantic_actions, shared_effects=shared_effects,
        )
        store.write_jsonl("actions/request-decisions.jsonl", request_decisions)
        request_dropped = {item.action_id for item in request_decisions
                           if item.disposition == "DROP"}
        store.write_jsonl("actions/request-refutations.jsonl", [
            item for item in request_decisions if item.disposition == "DROP"
        ])
        semantic_actions = [item for item in semantic_actions
                            if item.action_id not in request_dropped]
        effect_families, input_routes = build_action_effect_families(
            source_groups, semantic_actions,
        )
        store.write_jsonl("actions/effect-families.jsonl", effect_families)
        store.write_jsonl("actions/input-routes.jsonl", input_routes)
        self._emit(
            f"Action effects: {len(effect_families)} families, "
            f"{len(input_routes)} retained input routes; "
            f"shared={sum(len(item.action_ids) > 1 for item in effect_families)}"
        )
        missing_action_inputs = [
            {
                "action_id": item.action_id,
                "entry_id": item.entry_id,
                "name": item.name,
                "entry_function_id": item.entry_function_id,
                "dispatcher_function_id": item.dispatcher_function_id,
                "handler_function_id": item.handler_function_id,
                "reason": "No source-backed complete request was resolved after Action selection",
            }
            for item in semantic_actions
            if not item.examples and item.status is not ProofStatus.REFUTED
        ]
        store.write_jsonl("actions/missing-input-obligations.jsonl", missing_action_inputs)
        if missing_action_inputs:
            self._emit(
                f"request synthesis left {len(missing_action_inputs)} Action(s) "
                "without a source-backed request; recorded as unresolved"
            )

        # An Entry with no named Action can still accept a raw file, stream,
        # argument, or environment value. Explore that boundary only now,
        # after the semantic Action inventory and selection. A rejected named
        # Action is not reintroduced as an unclassified raw Action.
        fallback_entries = [entry for entry in analyzed_entries
                            if entry.entry_id not in discovered_action_entry_ids]
        surface_agent = InputSurfaceAgent(
            traced_llm, graph, self.project,
            max_function_turns=self.project.max_context_functions,
            trace=trace,
            resume_continuations=self.surface_resume_continuations,
        )
        raw_input_cases = (
            await surface_agent.run(fallback_entries) if fallback_entries else []
        )
        store.write_jsonl("input-surfaces/inventory.jsonl", raw_input_cases)
        store.write_jsonl("input-surfaces/selector-audit.jsonl", surface_agent.selector_audit)
        store.write_json("input-surfaces/obligations.json", {
            "obligations": surface_agent.obligations,
            "policy": (
                "raw inputs are hypotheses for Entries with no named Action; "
                "no raw input is static, semantic, or runtime proof"
            ),
        })
        entry_by_id = {entry.entry_id: entry for entry in fallback_entries}
        raw_runtime_actions = [
            raw_case_runtime_action(case, entry_by_id[case.entry_id], graph)
            for case in raw_input_cases if case.entry_id in entry_by_id
        ]
        early_runtime_witnesses: dict[str, Any] = {}
        first_fastlane_original_request_elapsed: float | None = None
        raw_trial_count = 0
        store.write_json("input-surfaces/runtime-trials.json", {
            "case_count": len(raw_input_cases),
            "tried": 0,
            "deferred": len(raw_input_cases),
            "executor_configured": bool(self.project.scenario_command),
            "witnesses": [],
            "policy": "Raw candidates are sent only in the later original-program preflight",
        })

        # A *runnable* semantic Action supersedes the generic raw trial in
        # later planning. A named branch without a concrete request example
        # must never remove the only executable hypothesis for that Entry.
        # Raw trials remain in their own inventory regardless of this choice.
        semantically_covered_entries = {
            item.entry_id for item in semantic_actions
            if item.examples and item.status is not ProofStatus.REFUTED
        }
        unmatched_raw_actions = [
            item for item in raw_runtime_actions
            if item.entry_id not in semantically_covered_entries
        ]
        actions = [*semantic_actions, *unmatched_raw_actions]
        store.write_jsonl("actions/inventory.jsonl", actions)
        store.write_jsonl("actions/selected-for-planning.jsonl", actions)
        retained_ids = {item.action_id for item in actions}
        early_runtime_witnesses = {
            key: witness for key, witness in early_runtime_witnesses.items()
            if witness.target_action_id in retained_ids
        }
        uncertain_ids = {entry.entry_id for entry in uncertain_entries}
        actions = [
            replace(
                action,
                status=ProofStatus.POSSIBLE,
                unknowns=unique_strings([
                    *action.unknowns,
                    "external Entry provenance is unresolved; exploratory only",
                ]),
            ) if action.entry_id in uncertain_ids and action.status is not ProofStatus.REFUTED else action
            for action in actions
        ]
        agent_infrastructure_errors.extend(action_agent.infrastructure_failures)
        # Preserve every unresolved Entry in the discovery/summary audit.
        # A runtime adapter may decline an individual scenario later, but it
        # must not erase the corresponding input surface from the inventory.
        in_scope_unresolved: list[EntryRecord] = list(unresolved)
        # An interrupted run must still account for every discovered Action.
        # This is a replace-atomic checkpoint, updated as scenarios/harnesses
        # progress, never a proof/qualification claim.
        store.write_jsonl("workflow/candidate-lifecycle.jsonl", candidate_lifecycle(actions))
        store.write_json(
            "actions/operation-seeds.json",
            {
                "count": len(action_agent.operation_seeds),
                "planned_branch_validations": (
                    action_agent.planned_branch_validations
                ),
                "planned_source_path_groups": action_agent.planned_branch_groups,
                "source_path_group_size": action_agent.branch_group_size,
                "grouped_case_individual_fallbacks": action_agent.branch_group_fallbacks,
                "max_branch_validations": action_agent.max_branch_validations,
                "seeds": [as_json(item) for item in action_agent.operation_seeds],
                "open_obligations": action_agent.inventory_obligations,
            },
        )
        store.write_json(
            "actions/skipped-entries.json",
            {
                "scenario_channel": self.project.scenario_channel,
                "count": len(action_agent.skipped_entries),
                "entries": action_agent.skipped_entries,
            },
        )
        from .runtime.scenario import _action_transport
        store.write_json("actions/execution-surfaces.json", {
            "discovery_scope": "all_product_entries_unfiltered",
            "configured_executor": self.project.scenario_channel,
            "configured_command": bool(self.project.scenario_command),
            "actions": [
                {
                    "action_id": action.action_id,
                    "entry_id": action.entry_id,
                    "channel_kind": action.channel_kind,
                    "source_api": action.source_api,
                    "inferred_adapter": _action_transport(action) or "UNRESOLVED",
                    "source_proof": str(action.status),
                }
                for action in actions
            ],
            "policy": "Unsupported or unconfigured runtime adapters retain their source analysis; never imply dynamic proof",
        })
        self._emit(
            f"input-action reconstruction completed: {len(actions)} actions, "
            f"{sum(item.status is ProofStatus.PROVEN_STATIC for item in actions)} statically proven"
        )

        # The first executable request must not wait for hundreds of source-
        # only state-contract sessions.  Try independent one-shot requests on
        # the ORIGINAL program first.  This is a front-running sample, not an
        # Action-discovery filter: the full planner still sees every action.
        scenario_runtime = ScenarioRuntimeVerifier(self.project, actions, graph)
        early_preflight_start = time.monotonic()
        overall_run_start = getattr(
            self, "_run_started_monotonic", early_preflight_start,
        )
        first_original_request_elapsed: float | None = first_fastlane_original_request_elapsed
        first_early_draft_elapsed: float | None = None
        preflight_witnesses: dict[str, Any] = dict(early_runtime_witnesses)
        preflight_drafts: dict[str, tuple[str, ScenarioStatus, Any]] = {}
        preflight_obligations: list[str] = []
        preflight_terminal_failure = ""
        source_supported_actions = {
            action.action_id for action in actions
            if _source_draft_action_is_supported(action)
        }
        preflight_actions = _preflight_round_robin(sorted(
            [
                action for action in actions
                if (action.status is ProofStatus.PROVEN_STATIC
                    or action.action_id in source_supported_actions
                    or (self.project.scenario_exploratory_drafts
                        and _is_source_literal_runtime_trial(action)
                        and bool(action.entry_probe_evidence)
                        and bool(action.dispatch_probe_evidence)))
            ],
            key=lambda action: (
                {"client_to_program": 0, "local_to_program": 1,
                 "unknown": 2, "peer_to_program": 3}.get(action.direction, 2),
                0 if action.status is ProofStatus.PROVEN_STATIC else 1,
                action.action_id,
            ),
        ))
        preflight_planner = ScenarioPlanner(
            max_steps=self.project.max_scenario_steps,
            max_candidates=self.project.max_scenario_candidates,
            max_variants_per_action=1,
            max_search_states=self.project.max_scenario_search_states,
        )
        preflight_candidates = preflight_planner.exploratory_candidates(
            preflight_actions, [],
            limit=min(len(preflight_actions), self.project.max_scenario_candidates),
        )
        first_replayable_witness = None
        for candidate in preflight_candidates:
            if candidate.scenario_id in preflight_witnesses:
                continue
            if first_original_request_elapsed is None:
                first_original_request_elapsed = time.monotonic() - overall_run_start
            witness = await scenario_runtime.verify(candidate)
            preflight_witnesses[candidate.scenario_id] = witness
            store.write_json(
                Path("scenarios/witnesses") / f"{witness.witness_id}.json", witness
            )
            trace("scenario_runtime", "preflight_witness", {
                "message": witness.rationale,
                "scenario_id": candidate.scenario_id,
                "status": str(witness.status),
            })
            if witness.status is ScenarioStatus.PROVEN_RUNTIME:
                first_replayable_witness = witness
                break
        if first_replayable_witness is None:
            # An observed handler without exact request attribution does not
            # become PROVEN_RUNTIME.  A source-only draft is still useful for
            # testing build closure when the user explicitly opted into it.
            eligible_early = [
                witness for witness in preflight_witnesses.values()
                if (
                    self.project.scenario_exploratory_drafts
                    and witness.status in {
                        ScenarioStatus.OBSERVED_RUNTIME,
                        ScenarioStatus.REPLAYED_RUNTIME,
                    }
                ) or (
                    self.project.scenario_source_drafts
                    and witness.status in {
                        ScenarioStatus.UNPROVEN,
                        ScenarioStatus.INFRASTRUCTURE_FAILED,
                    }
                    and witness.target_action_id in source_supported_actions
                )
            ]
            if eligible_early:
                first_replayable_witness = eligible_early[0]

        if first_replayable_witness is not None:
            early_witness = first_replayable_witness
            try:
                entry_functions = {
                    item.entry_id: item.entry_function_id for item in analyzed_entries
                }
                early_action_functions = _harness_action_function_ids(
                    actions, entry_functions,
                )
                early_plan = build_harness_plan(
                    early_witness,
                    action_function_ids=early_action_functions,
                    action_schemas={action.action_id: action for action in actions},
                    function_sources={fid: item.file for fid, item in graph.bundle.functions.items()},
                    build_target="UNRESOLVED",
                    allow_observed=self.project.scenario_exploratory_drafts,
                    allow_unproven=self.project.scenario_source_drafts,
                )
                from .runtime.contracts import audit_harness_plan
                audit = audit_harness_plan(
                    early_witness, early_plan,
                    allow_unproven=(self.project.scenario_source_drafts
                                    and early_witness.status in {
                                        ScenarioStatus.UNPROVEN,
                                        ScenarioStatus.INFRASTRUCTURE_FAILED,
                                    }),
                )
                if audit.passed:
                    early_generator = ScenarioHarnessGeneratorAgent(
                        traced_llm, graph, self.project, trace=trace,
                    )
                    try:
                        draft = await early_generator.run(early_plan, early_witness)
                    finally:
                        await early_generator.close_session(early_plan)
                    if draft.code.strip():
                        early_dir = Path("harnesses/preflight") / draft.manifest.harness_id
                        store.write_text(early_dir / Path(draft.manifest.source_file).name, draft.code)
                        store.write_json(early_dir / "manifest.json", draft.manifest)
                        store.write_json(early_dir / "witness.json", early_witness)
                        store.write_json(early_dir / "plan.json", early_plan)
                        early_static = ScenarioStaticHarnessGate(graph).check(
                            draft, early_plan, early_witness,
                        )
                        store.write_json(early_dir / "static-audit.json", early_static)
                        preflight_drafts[early_plan.scenario_id] = (
                            early_plan.plan_id, early_witness.status, draft,
                        )
                        first_early_draft_elapsed = time.monotonic() - overall_run_start
                        self._emit(
                            f"early harness source generated before state analysis: "
                            f"{draft.manifest.harness_id} "
                            f"(witness={early_witness.status}, static={early_static.passed})"
                        )
                    else:
                        preflight_obligations.extend(draft.generation_blockers)
                else:
                    preflight_obligations.append(
                        f"{early_plan.plan_id}: preflight contract audit blocked generation"
                    )
            except Exception as exc:
                message = (
                    f"early harness generation failed with {type(exc).__name__}: {exc}"
                )
                preflight_obligations.append(message)
                agent_infrastructure_errors.append(message)
                if is_terminal_llm_infrastructure_error(exc):
                    preflight_terminal_failure = message
        else:
            preflight_obligations.append(
                "early preflight disabled until exploratory/source-draft mode is enabled"
                if not (self.project.scenario_exploratory_drafts
                        or self.project.scenario_source_drafts)
                else "no one-shot runtime witness or opted-in source-draft candidate "
                     "was available before state-dependency analysis"
            )
        store.write_json("workflow/early-harness-preflight.json", {
            "one_shot_candidates_tried": len(preflight_witnesses),
            "runtime_proven": sum(
                witness.status is ScenarioStatus.PROVEN_RUNTIME
                for witness in preflight_witnesses.values()
            ),
            "early_harness_drafts": list(preflight_drafts),
            "pending_action_schemas": len(actions),
            "seconds_before_first_original_trial": first_original_request_elapsed,
            "seconds_before_first_early_draft": first_early_draft_elapsed,
            "preflight_elapsed_seconds": time.monotonic() - early_preflight_start,
            "obligations": preflight_obligations,
            "rule": "early draft is not qualified until the ordinary build, sanitizer and semantic gates pass",
        })
        self._emit(
            f"one-shot original-program preflight: {len(preflight_witnesses)} requests, "
            f"{len(preflight_drafts)} early harness drafts; now analyzing state dependencies"
        )

        state_agent = StateDependencyAgent(
            traced_llm,
            graph,
            usage_evidence,
            budget=self.project.max_context_functions,
            usage_artifacts=usage_artifacts,
            original_trial_feedback={
                action.action_id: [
                    item for witness in preflight_witnesses.values()
                    if witness.target_action_id == action.action_id
                    for item in _raw_trial_feedback(action, 'original_program', witness)
                ]
                for action in actions
            },
            trace=trace,
        )
        # A source-supported POSSIBLE Action can be tested in the original
        # program. Its source status remains POSSIBLE; only the separate
        # request-correlated runtime verifier may produce a proven witness.
        eligible_actions = [
            action for action in actions
            if action.examples and (
                action.status is ProofStatus.PROVEN_STATIC
                or (action.action_id in source_supported_actions
                    and action.status is ProofStatus.POSSIBLE)
            ) and (
                not _is_source_literal_runtime_trial(action)
                or any(
                    witness.status is ScenarioStatus.PROVEN_RUNTIME
                    and witness.target_action_id == action.action_id
                    for witness in preflight_witnesses.values()
                )
            )
        ]
        skipped_actions = [action for action in actions if action not in eligible_actions]
        self._emit(f"state-dependency analysis started: {len(eligible_actions)} eligible actions; "
                   f"{len(skipped_actions)} unproven or example-less actions remain obligations")
        dependencies = (
            await state_agent.run(
                eligible_actions,
                source_group_ids={
                    action_id: family.effect_id
                    for family in effect_families if len(family.action_ids) > 1
                    for action_id in family.action_ids
                },
            )
            if eligible_actions and not preflight_terminal_failure else None
        )
        agent_infrastructure_errors.extend(state_agent.infrastructure_failures)
        if dependencies is None:
            dependencies = StateDependencyGraph([], [], [])
        if preflight_terminal_failure:
            dependencies.open_obligations.extend(
                f"{action.action_id}: State analysis deferred after terminal "
                "harness preflight provider failure"
                for action in eligible_actions
            )
        dependencies.open_obligations.extend(
            f"{action.action_id}: action is not eligible for planning until "
            "its static proof and concrete example are established"
            for action in skipped_actions
        )
        store.write_json("scenarios/state-dependency-graph.json", dependencies)
        store.write_json("scenarios/state-source-group-metrics.json", {
            "eligible_actions": len(eligible_actions),
            "planned_shared_handler_groups": state_agent.planned_state_groups,
            "individual_state_fallbacks": state_agent.state_group_fallbacks,
            "processed_contracts": len(dependencies.contracts),
            "note": "group counts are work units, not exact provider model call counts",
        })
        self._emit(
            f"state-dependency analysis completed: {len(dependencies.contracts)} contracts, "
            f"{len(dependencies.open_obligations)} open obligations"
        )

        planner = ScenarioPlanner(
            max_steps=self.project.max_scenario_steps,
            max_candidates=self.project.max_scenario_candidates,
            max_variants_per_action=self.project.max_scenario_variants_per_action,
            max_search_states=self.project.max_scenario_search_states,
        )
        scenario_candidates = planner.plan(actions, dependencies)
        # Source-derived trial sequences and post-action consumers share one
        # scheduling pool. A NOT-PROVEN state edge is a hypothesis, never a
        # reason to erase the operation from the candidate inventory.
        exploratory_candidates = planner.exploratory_candidates(
            eligible_actions, scenario_candidates, dependencies=dependencies,
        )
        post_candidates = (
            planner.post_fuzz_candidates(
                actions, dependencies,
                [*scenario_candidates, *exploratory_candidates],
                limit=self.project.max_scenario_candidates,
                allow_hypotheses=(
                    self.project.scenario_exploratory_drafts
                    or self.project.scenario_source_drafts
                ),
            ) if self.project.scenario_post_fuzz else []
        )
        scenario_candidates.extend(exploratory_candidates)
        scenario_candidates.extend(post_candidates)
        # Preserve front-running original-program trials even if the later
        # state planner chose a different candidate ordering or exhausted its
        # own limit.  A completed early witness is not re-executed or lost.
        planned_ids = {candidate.scenario_id for candidate in scenario_candidates}
        for candidate in preflight_candidates:
            if (candidate.scenario_id in preflight_witnesses
                and candidate.scenario_id not in planned_ids):
                scenario_candidates.append(candidate)
                planned_ids.add(candidate.scenario_id)
        store.write_jsonl("scenarios/post-fuzz-candidates.jsonl", post_candidates)
        store.write_jsonl("scenarios/candidates.jsonl", scenario_candidates)
        store.write_jsonl(
            "workflow/candidate-lifecycle.jsonl",
            candidate_lifecycle(actions, scenario_candidates),
        )
        store.write_json("scenarios/exploratory-candidates.json", {
            "enabled": self.project.scenario_exploratory_drafts,
            "count": len(exploratory_candidates),
            "candidates": [as_json(item) for item in exploratory_candidates],
            "rule": "source-derived single requests only; no invented state contract",
        })
        store.write_json(
            "scenarios/planning-obligations.json",
            {
                "count": len(planner.obligations),
                "obligations": planner.obligations,
            },
        )
        plannable = [
            item for item in scenario_candidates
            if item.status is ScenarioStatus.CANDIDATE
        ]
        self._emit(
            f"scenario planning completed: {len(plannable)} executable candidates, "
            f"{len(scenario_candidates) - len(plannable)} unproven"
        )
        trace("scenario_planner", "completed", {
            "message": "deterministic scenario planning completed",
            "candidate_count": len(scenario_candidates),
            "executable_count": len(plannable),
        })

        witnesses = [
            preflight_witnesses[candidate.scenario_id]
            if candidate.scenario_id in preflight_witnesses
            else await scenario_runtime.verify(candidate)
            for candidate in scenario_candidates
        ]
        for witness in witnesses:
            store.write_json(
                Path("scenarios/witnesses") / f"{witness.witness_id}.json",
                witness,
            )
            trace("scenario_runtime", "witness", {
                "message": witness.rationale,
                "scenario_id": witness.scenario_id,
                "witness_id": witness.witness_id,
                "status": str(witness.status),
                "step_count": len(witness.steps),
            })
        # Retry rejected *request formats* only. State-contract failures and
        # unattributed target observations are not repairable by changing C.
        # Each retry gets a fresh isolated original-program replay and is
        # labeled exploratory until a real causal witness is produced.
        if (self.project.scenario_exploratory_drafts
            and exploratory_candidates and not preflight_terminal_failure):
            refiner = ScenarioRequestRefiner(traced_llm, graph)
            witness_for = {item.scenario_id: item for item in witnesses}
            original_ids = {item.scenario_id for item in scenario_candidates}
            retry_candidates = []
            by_action = {item.action_id: item for item in actions}
            retry_budget = min(16, self.project.max_scenario_candidates)
            for candidate in exploratory_candidates:
                if len(retry_candidates) >= retry_budget:
                    break
                witness = witness_for.get(candidate.scenario_id)
                action = by_action.get(candidate.target_action_id)
                if witness is None or action is None or witness.status is not ScenarioStatus.UNPROVEN:
                    continue
                if not witness.observations or witness.observations[-1].response_success:
                    continue
                try:
                    examples = await refiner.repair(action, witness)
                except Exception as exc:
                    agent_infrastructure_errors.append(
                        f"{candidate.scenario_id}: request repair raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    if is_terminal_llm_infrastructure_error(exc):
                        break
                    continue
                refined_action = replace(action, examples=examples)
                for retry in planner.exploratory_candidates(
                    [refined_action], [], limit=min(2, retry_budget-len(retry_candidates))
                ):
                    if retry.scenario_id in original_ids:
                        continue
                    retry.planning_evidence.append(
                        f"response-guided one-shot repair of {candidate.scenario_id}"
                    )
                    retry_candidates.append(retry)
                    original_ids.add(retry.scenario_id)
            if retry_candidates:
                retry_witnesses = await scenario_runtime.verify_many(retry_candidates)
                witnesses.extend(retry_witnesses)
                scenario_candidates.extend(retry_candidates)
                store.write_jsonl("scenarios/refined-candidates.jsonl", retry_candidates)
                for witness in retry_witnesses:
                    store.write_json(
                        Path("scenarios/witnesses") / f"{witness.witness_id}.json", witness
                    )
                    trace("scenario_runtime", "refined_witness", {
                        "message": witness.rationale,
                        "scenario_id": witness.scenario_id,
                        "status": str(witness.status),
                    })
        proven_witnesses = [
            item for item in witnesses
            if item.status is ScenarioStatus.PROVEN_RUNTIME
        ]
        observed_witnesses = [
            item for item in witnesses
            if item.status in {ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME}
        ]
        expected_target_actions = {
            item.action_id for item in actions
            if item.status is ProofStatus.PROVEN_STATIC and item.examples
        }
        proven_target_actions = {
            item.target_action_id for item in proven_witnesses
        }
        unproven_target_actions = expected_target_actions - proven_target_actions
        self._emit(
            f"original-program scenario verification completed: "
            f"{len(proven_witnesses)} proven, {len(observed_witnesses)} "
            f"observed-unattributed, {len(witnesses)} total"
        )
        group_validation = validate_action_groups(
            source_groups, actions, dependencies, witnesses,
        )
        store.write_jsonl("actions/group-validation.jsonl", group_validation)
        self._emit(
            "Action route grouping audit completed: "
            f"runtime_supported={sum(item.status == 'ROUTES_SUPPORTED' for item in group_validation)}, "
            f"state_mismatch={sum(item.status == 'STATE_MISMATCH' for item in group_validation)}, "
            f"unresolved={sum(item.status in {'STATE_UNRESOLVED', 'RUNTIME_UNRESOLVED'} for item in group_validation)}"
        )
        if self._network_harness_config is not None:
            export_stateafl_seeds(store, witnesses)

        entry_functions = {
            item.entry_id: item.entry_function_id for item in analyzed_entries
        }
        action_functions = _harness_action_function_ids(actions, entry_functions)
        source_supported_actions = {
            action.action_id for action in actions
            if _source_draft_action_is_supported(action)
        }
        store.write_jsonl(
            "workflow/candidate-lifecycle.jsonl",
            candidate_lifecycle(actions, scenario_candidates, witnesses),
        )
        generation_schedule = schedule_generation(
            witnesses,
            source_supported_actions=source_supported_actions,
            exploratory_enabled=self.project.scenario_exploratory_drafts,
            source_drafts_enabled=self.project.scenario_source_drafts,
            max_source_drafts=self.project.max_source_drafts,
        )
        source_only_witnesses = generation_schedule.source_only
        store.write_json("scenarios/source-only-drafts.json", {
            "enabled": self.project.scenario_source_drafts,
            "limit": self.project.max_source_drafts,
            "selected_scenarios": [item.scenario_id for item in source_only_witnesses],
            "excluded_scenarios": generation_schedule.excluded,
            "proof_status": "SOURCE/OBSERVED UNVERIFIED; NEVER QUALIFIED WITHOUT RUNTIME AND DIFFERENTIAL EVIDENCE",
        })
        plan_witnesses = generation_schedule.selected
        plans = [
            build_harness_plan(
                witness,
                action_function_ids=action_functions,
                action_schemas={item.action_id: item for item in actions},
                function_sources={
                    item.function_id: item.file for item in graph.bundle.functions.values()
                },
                build_target="UNRESOLVED",
                allow_observed=(self.project.scenario_exploratory_drafts or self.project.scenario_source_drafts),
                allow_unproven=(self.project.scenario_source_drafts
                                and witness.status in {ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED}),
            )
            for witness in plan_witnesses
        ]
        # A runtime witness is the scheduling unit. Network-facing witnesses
        # are attempted first; no semantic grouping or one-Entry/one-harness
        # constraint is introduced.
        action_by_id = {item.action_id: item for item in actions}
        plans.sort(key=lambda item: (
            0 if action_by_id.get(item.target_action_id, None)
            and "network" in action_by_id[item.target_action_id].channel_kind.casefold()
            else 1,
            item.plan_id,
        ))
        witness_by_id = {item.witness_id: item for item in plan_witnesses}
        from .runtime.contracts import audit_harness_plan
        plan_audits = [
            audit_harness_plan(
                witness_by_id[item.witness_id], item,
                allow_unproven=(self.project.scenario_source_drafts
                                and witness_by_id[item.witness_id].status in {ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED}),
            ) for item in plans
        ]
        store.write_json("harness-plans/contract-audits.json", {
            "audits": [as_json(item) for item in plan_audits],
            "failed": sum(not audit.passed for audit in plan_audits),
        })
        contract_blocked_plans = {
            audit.plan_id for audit in plan_audits if not audit.passed
        }
        plans = [item for item in plans if item.plan_id not in contract_blocked_plans]
        store.write_jsonl("harness-plans/plans.jsonl", plans)
        store.write_jsonl(
            "workflow/candidate-lifecycle.jsonl",
            candidate_lifecycle(actions, scenario_candidates, witnesses, plans),
        )
        # Build closure discovery must not be deferred until after expensive
        # LLM source generation. These diagnoses never reject an Action or
        # assert successful compilation: they remain actionable obligations.
        closure_assessments = [
            safe_inspect_build_closure_for_plan(self.project, plan) for plan in plans
        ]
        store.write_json("harness-plans/build-readiness.json", {
            "plans": closure_assessments,
            "unresolved": sum(row["status"] == "UNRESOLVED" for row in closure_assessments),
            "policy": "diagnostic only; source-backed drafts remain eligible",
        })
        for row in closure_assessments:
            if row["status"] == "UNRESOLVED":
                self._emit(f"WARNING: {row['plan_id']}: build closure unresolved: {row.get('reason')}")

        generator = ScenarioHarnessGeneratorAgent(
            traced_llm, graph, self.project, trace=trace
        )
        static_gate = ScenarioStaticHarnessGate(graph)
        seed_planner = ScenarioHarnessVerifierSeedPlanner(traced_llm)
        dynamic = HarnessVerifierAgent(
            CommandRunner(), self.project, graph, progress=self._emit
        )
        crash_reproducer = OriginalCrashReproducer(scenario_runtime)

        generation_attempts = 0
        generated_ids: set[str] = set()
        static_passed_ids: set[str] = set()
        build_passed_ids: set[str] = set()
        qualified_ids: set[str] = set()
        exploratory_build_ids: set[str] = set()
        source_only_draft_ids: set[str] = set()
        backend_verified_ids: set[str] = set()
        generated_by_action: dict[str, list[str]] = {}
        blocked_plans: set[str] = set(contract_blocked_plans)
        verification_infrastructure_errors: list[str] = []
        original_reproduced: set[str] = set()
        harness_artifacts: set[str] = set()
        consecutive_transport_failed_plans = 0

        if preflight_terminal_failure:
            blocked_plans.update(item.plan_id for item in plans)
        for plan_index, plan in enumerate(
            plans if not preflight_terminal_failure else []
        ):
            witness = witness_by_id[plan.witness_id]
            feedback: list[str] = []
            seen_failures: set[str] = set()
            last_draft = None
            plan_done = False
            terminal_agent_failure = ""
            transient_transport_failure = False
            for attempt in (count(1) if self.max_generation_attempts == 0
                            else range(1, self.max_generation_attempts + 1)):
                self._emit(
                    f"harness plan {plan.plan_id}: generation attempt "
                    f"{attempt}/"
                    f"{self.max_generation_attempts or 'unbounded'}"
                )
                trace("harness_generator", "attempt_started", {
                    "message": f"generate harness for scenario {plan.scenario_id}",
                    "scenario_id": plan.scenario_id,
                    "plan_id": plan.plan_id,
                    "attempt": attempt,
                    "feedback": feedback,
                })
                try:
                    cached_early = preflight_drafts.get(plan.scenario_id)
                    if (
                        attempt == 1 and cached_early is not None
                        and cached_early[0] == plan.plan_id
                        and cached_early[1] is witness.status
                    ):
                        draft = cached_early[2]
                        self._emit(
                            f"harness plan {plan.plan_id}: reusing the early "
                            "source draft (no duplicate LLM generation)"
                        )
                    else:
                        draft = await generator.run(plan, witness, feedback=feedback)
                except Exception as exc:
                    failure = (
                        f"{plan.plan_id}: harness generator raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    agent_infrastructure_errors.append(failure)
                    if is_terminal_llm_infrastructure_error(exc):
                        terminal_agent_failure = failure
                    elif is_transient_llm_transport_error(exc):
                        transient_transport_failure = True
                    blocked_plans.add(plan.plan_id)
                    break
                last_draft = draft
                generation_attempts += 1
                trace("harness_generator", "draft_created", {
                    "message": f"generated harness draft for {plan.scenario_id}",
                    "scenario_id": plan.scenario_id,
                    "plan_id": plan.plan_id,
                    "attempt": attempt,
                    "manifest": as_json(draft.manifest),
                    "generation_blockers": draft.generation_blockers,
                })
                if draft.code.strip():
                    generated_ids.add(draft.manifest.harness_id)
                    generated_by_action.setdefault(plan.target_action_id, []).append(
                        draft.manifest.harness_id
                    )
                attempt_dir = Path("harnesses") / draft.manifest.harness_id / f"attempt-{attempt}"
                source_name = Path(draft.manifest.source_file).name
                draft.manifest.source_file = str(attempt_dir / source_name)
                absolute_attempt_dir = store.directory(attempt_dir)
                store.write_text(attempt_dir / source_name, draft.code)
                store.write_json(attempt_dir / "manifest.json", draft.manifest)
                store.write_json(attempt_dir / "generator-audit.json", draft.self_audit)
                store.write_json(attempt_dir / "scenario-witness.json", witness)
                store.write_json(attempt_dir / "harness-plan.json", plan)
                # Preserve each generated draft even if later compiler/LLM
                # stages are interrupted. This MUST use the scenario pipeline's
                # generated_by_action mapping (the legacy pipeline is dead code).
                store.write_jsonl(
                    "workflow/candidate-lifecycle.jsonl",
                    candidate_lifecycle(
                        actions, scenario_candidates, witnesses, plans,
                        generated=generated_by_action, built=build_passed_ids,
                        backend_verified=backend_verified_ids,
                        semantic_verified=qualified_ids,
                    ),
                )

                report = static_gate.check(draft, plan, witness)
                store.write_json(attempt_dir / "static-audit.json", report)
                trace("static_harness_gate", "decision", {
                    "message": f"harness {draft.manifest.harness_id}: {'PASS' if report.passed else 'FAIL'}",
                    "harness_id": draft.manifest.harness_id,
                    "scenario_id": plan.scenario_id,
                    "attempt": attempt,
                    "report": as_json(report),
                })
                if witness.status in {ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED}:
                    # The initial code is useful for later verification, but
                    # no original runtime causal evidence exists. Keep every
                    # static finding, never call it VERIFIED or QUALIFIED.
                    has_code = bool(draft.code.strip())
                    if has_code:
                        source_only_draft_ids.add(draft.manifest.harness_id)
                    store.write_json(attempt_dir / "source-only-status.json", {
                        "status": "UNVERIFIED_SOURCE_DRAFT" if has_code else "NO_SOURCE_DRAFT_GENERATED",
                        "qualified": False,
                        "runtime_witness": False,
                        "static_checks": [as_json(item) for item in report.checks],
                        "reason": witness.rationale,
                        "next_steps": "original execution, build, sanitizer, semantic equivalence",
                    })
                    # Build-only is allowed if an independent build backend is
                    # configured; this result can never elevate proof status.
                    if not has_code:
                        blocked_plans.add(plan.plan_id)
                        break
                    if self.project.build_command or self.project.verification_backend == "oss-fuzz":
                        try:
                            verification = await dynamic.verify(
                                draft, absolute_attempt_dir, runtime_checks=False
                            )
                            store.write_json(attempt_dir / "source-only-build.json", verification)
                            if verification.build_ok:
                                build_passed_ids.add(draft.manifest.harness_id)
                            if verification.infrastructure_error:
                                verification_infrastructure_errors.append(verification.infrastructure_error)
                        except Exception as exc:
                            verification_infrastructure_errors.append(
                                f"{plan.plan_id}: source-only build failed: {type(exc).__name__}: {exc}"
                            )
                    plan_done = True
                    break

                if witness.status in {ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME}:
                    # HC11/HC16 deliberately fail because unattributed traces
                    # are not proof. Keep the other checklist gates intact.
                    # An exploratory draft may be compile-tested but cannot
                    # pass independent validation or be marked QUALIFIED.
                    nonproof_failures = [
                        check for check in report.checks
                        if check.status is not CheckStatus.PASS
                        and check.check_id not in {"HC11", "HC16"}
                    ]
                    store.write_json(attempt_dir / "exploratory-status.json", {
                        "status": (
                            "REPLAYED_UNATTRIBUTED" if witness.status is ScenarioStatus.REPLAYED_RUNTIME
                            else "OBSERVED_UNATTRIBUTED"
                        ),
                        "qualified": False,
                        "not_proven_check_ids": ["HC11", "HC16"],
                        "nonproof_failures": [as_json(item) for item in nonproof_failures],
                    })
                    if nonproof_failures:
                        blocked_plans.add(plan.plan_id)
                        break
                    try:
                        verification = await dynamic.verify(
                            draft, absolute_attempt_dir, runtime_checks=False
                        )
                    except Exception as exc:
                        verification_infrastructure_errors.append(
                            f"{plan.plan_id}: exploratory build raised "
                            f"{type(exc).__name__}: {exc}"
                        )
                        blocked_plans.add(plan.plan_id)
                        break
                    store.write_json(attempt_dir / "exploratory-build.json", verification)
                    if verification.infrastructure_error:
                        verification_infrastructure_errors.append(
                            verification.infrastructure_error
                        )
                    if verification.build_ok:
                        build_passed_ids.add(draft.manifest.harness_id)
                        exploratory_build_ids.add(draft.manifest.harness_id)
                        plan_done = True
                    else:
                        blocked_plans.add(plan.plan_id)
                    break

                if not report.passed:
                    signature = _gate_report_signature("scenario-static", report)
                    if signature in seen_failures:
                        blocked_plans.add(plan.plan_id)
                        break
                    seen_failures.add(signature)
                    feedback = _gate_feedback(report, include_warnings=True)
                    if any(item.startswith("CONTEXT_BLOCKED:") for item in draft.generation_blockers):
                        blocked_plans.add(plan.plan_id)
                        break
                    continue

                try:
                    independent = await generator.review(draft, plan, witness, report)
                except Exception as exc:
                    failure = (
                        f"{plan.plan_id}: independent harness review raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    agent_infrastructure_errors.append(failure)
                    if is_terminal_llm_infrastructure_error(exc):
                        terminal_agent_failure = failure
                    elif is_transient_llm_transport_error(exc):
                        transient_transport_failure = True
                    blocked_plans.add(plan.plan_id)
                    break
                store.write_json(attempt_dir / "independent-audit.json", independent)
                if not independent.passed:
                    signature = _gate_report_signature("scenario-independent", independent)
                    if signature in seen_failures:
                        blocked_plans.add(plan.plan_id)
                        break
                    seen_failures.add(signature)
                    feedback = _gate_feedback(independent, include_warnings=True)
                    continue
                static_passed_ids.add(draft.manifest.harness_id)

                if not self.dynamic_verification:
                    try:
                        verification = await dynamic.verify(
                            draft, absolute_attempt_dir, runtime_checks=False
                        )
                    except Exception as exc:
                        verification_infrastructure_errors.append(
                            f"{plan.plan_id}: build verifier raised {type(exc).__name__}: {exc}"
                        )
                        blocked_plans.add(plan.plan_id)
                        break
                    store.write_json(attempt_dir / "build-validation.json", verification)
                    trace("harness_verifier", "decision", {
                        "message": verification.reason,
                        "harness_id": draft.manifest.harness_id,
                        "scenario_id": plan.scenario_id,
                        "verification": as_json(verification),
                    })
                    if verification.build_ok:
                        build_passed_ids.add(draft.manifest.harness_id)
                        plan_done = True
                        break
                    if verification.infrastructure_error:
                        verification_infrastructure_errors.append(verification.infrastructure_error)
                        blocked_plans.add(plan.plan_id)
                        break
                    signature = verification.failure.signature if verification.failure else stable_id("build-failure", verification.reason)
                    if signature in seen_failures:
                        blocked_plans.add(plan.plan_id)
                        break
                    seen_failures.add(signature)
                    feedback = _verification_feedback(verification)
                    continue

                try:
                    seeds = await seed_planner.run(draft, plan, witness)
                except Exception as exc:
                    failure = (
                        f"{plan.plan_id}: verifier seed planning raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    agent_infrastructure_errors.append(failure)
                    if is_terminal_llm_infrastructure_error(exc):
                        terminal_agent_failure = failure
                    elif is_transient_llm_transport_error(exc):
                        transient_transport_failure = True
                    blocked_plans.add(plan.plan_id)
                    break
                store.write_json(attempt_dir / "seeds" / "validation-seeds.json", seeds)
                try:
                    verification = await dynamic.verify(draft, absolute_attempt_dir, seeds)
                except Exception as exc:
                    verification_infrastructure_errors.append(
                        f"{plan.plan_id}: verifier raised {type(exc).__name__}: {exc}"
                    )
                    blocked_plans.add(plan.plan_id)
                    break
                # One seed-only repair is allowed for reachability. Rebuilding
                # equivalent C cannot repair a missing input shape.
                if (
                    verification.failure is not None
                    and verification.failure.kind is VerificationFailureKind.REACHABILITY
                ):
                    try:
                        refined = await seed_planner.run(
                            draft, plan, witness,
                            feedback=_verification_feedback(verification),
                            existing=seeds,
                        )
                    except Exception as exc:
                        failure = (
                            f"{plan.plan_id}: verifier seed refinement raised "
                            f"{type(exc).__name__}: {exc}"
                        )
                        agent_infrastructure_errors.append(failure)
                        if is_terminal_llm_infrastructure_error(exc):
                            terminal_agent_failure = failure
                        elif is_transient_llm_transport_error(exc):
                            transient_transport_failure = True
                        blocked_plans.add(plan.plan_id)
                        break
                    seeds = _deduplicate_seed_specs([*seeds, *refined])
                    store.write_json(attempt_dir / "seeds" / "validation-seeds-refined.json", seeds)
                    try:
                        verification = await dynamic.verify(draft, absolute_attempt_dir, seeds)
                    except Exception as exc:
                        verification_infrastructure_errors.append(
                            f"{plan.plan_id}: verifier after seed refinement raised "
                            f"{type(exc).__name__}: {exc}"
                        )
                        blocked_plans.add(plan.plan_id)
                        break
                # Optional independent semantic comparison. An ordinary GDB
                # breakpoint hit is not proof of equivalent request handling.
                # A source-instrumented original and harness must publish
                # matching request-correlated result records to pass this gate.
                differential_passed = False
                if self.project.require_differential_validation and verification.qualified:
                    from .runtime.differential import DifferentialVerifier
                    differential = await DifferentialVerifier().verify(
                        draft=draft, plan=plan, witness=witness,
                        artifact_dir=absolute_attempt_dir,
                        source_root=self.project.source_root,
                    )
                    store.write_json(attempt_dir / "differential-validation.json", differential)
                    differential_passed = differential.passed
                    if not differential.passed:
                        verification = replace(
                            verification,
                            qualified=False,
                            reason=(
                                "differential validation " + differential.status
                                + ": " + differential.detail
                            ),
                            failure=None,
                        )
                    trace("differential_verifier", "decision", {
                        "harness_id": draft.manifest.harness_id,
                        "status": differential.status,
                        "detail": differential.detail,
                    })
                store.write_json(attempt_dir / "validation.json", verification)
                trace("harness_verifier", "decision", {
                    "message": verification.reason,
                    "harness_id": draft.manifest.harness_id,
                    "scenario_id": plan.scenario_id,
                    "verification": as_json(verification),
                })
                if verification.build_ok:
                    build_passed_ids.add(draft.manifest.harness_id)
                if verification.infrastructure_error:
                    verification_infrastructure_errors.append(verification.infrastructure_error)
                    blocked_plans.add(plan.plan_id)
                    break

                crash_seeds = _deduplicate_seed_specs([
                    *verification.harness_fault_seeds,
                    *verification.target_finding_seeds,
                ])
                replays = await crash_reproducer.reproduce(
                    draft.manifest.harness_id, plan, crash_seeds
                )
                current_artifacts: list[str] = []
                for replay in replays:
                    store.write_json(
                        Path("findings") / replay.replay_id / "original-replay.json",
                        replay,
                    )
                    if replay.status is CrashReproductionStatus.ORIGINAL_REPRODUCED:
                        original_reproduced.add(replay.replay_id)
                    elif replay.status is CrashReproductionStatus.HARNESS_ARTIFACT:
                        harness_artifacts.add(replay.replay_id)
                        current_artifacts.append(replay.replay_id)

                target_replays = [
                    replay for replay in replays
                    if replay.seed in verification.target_finding_seeds
                ]
                target_findings_valid = not verification.target_finding_seeds or (
                    target_replays and all(
                        replay.status is CrashReproductionStatus.ORIGINAL_REPRODUCED
                        for replay in target_replays
                    )
                )
                # A backend's qualified=True is NOT a claim that the harness
                # and the original program implement the same semantics.
                from .runtime.qualification_audit import audit_qualification
                qualification = audit_qualification(
                    verification, witness,
                    differential_evidence=differential_passed,
                )
                store.write_json(attempt_dir / "qualification-evidence.json", {
                    "accepted_as_semantically_equivalent": qualification.accepted,
                    "blockers": list(qualification.blockers),
                    "observed": list(qualification.observed),
                    "backend_claimed_qualified": verification.qualified,
                    "differential_validation_requested": self.project.require_differential_validation,
                })
                if verification.qualified and target_findings_valid:
                    backend_verified_ids.add(draft.manifest.harness_id)
                    # A backend build/fuzz verdict is deliberately not the
                    # independent original-versus-harness semantic verdict.
                    if qualification.accepted:
                        qualified_ids.add(draft.manifest.harness_id)
                    plan_done = True
                    break
                if current_artifacts:
                    feedback = [
                        "independent evidence identified a harness-owned fault; "
                        "repair only harness-owned input/lifetime code"
                    ]
                elif any(item.status is CrashReproductionStatus.UNCONFIRMED
                         for item in target_replays):
                    # Absence of reproduction is not proof that the harness is
                    # faulty. Do not regenerate source based on that guess.
                    feedback = ["original-program crash cause remains UNCONFIRMED"]
                    blocked_plans.add(plan.plan_id)
                    break
                else:
                    feedback = _verification_feedback(verification)
                signature = verification.failure.signature if verification.failure else stable_id("verification", verification.reason, *feedback)
                if signature in seen_failures:
                    blocked_plans.add(plan.plan_id)
                    break
                seen_failures.add(signature)
                # Coverage and a second reachability miss are observations,
                # not harness-source repair requests.
                if verification.failure and verification.failure.kind in {
                    VerificationFailureKind.COVERAGE,
                    VerificationFailureKind.REACHABILITY,
                    VerificationFailureKind.RUNTIME_DISABLED,
                    VerificationFailureKind.DIFFERENTIAL,
                }:
                    blocked_plans.add(plan.plan_id)
                    break
                # Only a typed, repairable failure may trigger another source
                # attempt. Exact repeats and non-repairable categories above
                # stop independently of the optional attempt-count budget.
                if not verification.failure or verification.failure.kind not in {
                    VerificationFailureKind.BUILD,
                    VerificationFailureKind.HARNESS_FAULT,
                }:
                    blocked_plans.add(plan.plan_id)
                    break
            if not plan_done and last_draft is not None and last_draft.manifest.harness_id not in qualified_ids:
                blocked_plans.add(plan.plan_id)
            try:
                await generator.close_session(plan)
            except Exception as exc:
                agent_infrastructure_errors.append(
                    f"{plan.plan_id}: closing harness session raised {type(exc).__name__}: {exc}"
                )
            if last_draft is not None:
                try:
                    await seed_planner.close_session(last_draft)
                except Exception as exc:
                    agent_infrastructure_errors.append(
                        f"{plan.plan_id}: closing verifier session raised {type(exc).__name__}: {exc}"
                    )
                close_harness = getattr(dynamic, "close_harness", None)
                if callable(close_harness):
                    await close_harness(last_draft.manifest.harness_id)

            # A verifier may finish long before the remaining candidates.
            # Never make the partial-run report wait for the final summary.
            store.write_jsonl(
                "workflow/candidate-lifecycle.jsonl",
                candidate_lifecycle(
                    actions, scenario_candidates, witnesses, plans,
                    generated=generated_by_action, built=build_passed_ids,
                    backend_verified=backend_verified_ids,
                    semantic_verified=qualified_ids,
                ),
            )
            remaining_plans = plans[plan_index + 1:]
            if terminal_agent_failure:
                blocked_plans.update(item.plan_id for item in remaining_plans)
                trace("orchestrator", "harness_agent_circuit_opened", {
                    "message": (
                        "aborted all remaining harness plans after a terminal "
                        "LLM infrastructure failure"
                    ),
                    "failed_plan_id": plan.plan_id,
                    "remaining_plan_ids": [item.plan_id for item in remaining_plans],
                    "reason": terminal_agent_failure,
                    "failure_class": "terminal",
                })
                break
            if transient_transport_failure:
                consecutive_transport_failed_plans += 1
            else:
                consecutive_transport_failed_plans = 0
            if remaining_plans and consecutive_transport_failed_plans >= 2:
                blocked_plans.update(item.plan_id for item in remaining_plans)
                reason = (
                    "aborted all remaining harness plans after two consecutive "
                    "plans failed in the shared LLM transport"
                )
                agent_infrastructure_errors.append(reason)
                trace("orchestrator", "harness_agent_circuit_opened", {
                    "message": reason,
                    "failed_plan_id": plan.plan_id,
                    "remaining_plan_ids": [item.plan_id for item in remaining_plans],
                    "reason": reason,
                    "failure_class": "transient_transport",
                })
                break

        incomplete_analysis = bool(
            agent_infrastructure_errors
            or uninspected_functions
            or in_scope_unresolved
            or action_agent.inventory_obligations
            or dependencies.open_obligations
            or planner.obligations
            or unproven_target_actions
        )
        incomplete_verification = bool(
            verification_infrastructure_errors or blocked_plans
        )

        if not proven_witnesses and source_only_draft_ids:
            run_status = "SOURCE_ONLY_DRAFTS_NOT_QUALIFIED"
        elif not proven_witnesses and exploratory_build_ids:
            run_status = "EXPLORATORY_BUILD_VERIFIED_NOT_QUALIFIED"
        elif not proven_witnesses and observed_witnesses:
            run_status = "EXPLORATORY_OBSERVED_NO_BUILD"
        elif not proven_witnesses:
            run_status = (
                "FAILED_AGENT_INFRASTRUCTURE"
                if agent_infrastructure_errors
                else "FAILED_SCENARIO_INFRASTRUCTURE"
                if any(item.status is ScenarioStatus.INFRASTRUCTURE_FAILED for item in witnesses)
                else "FAILED_NO_RUNTIME_WITNESS"
            )
        elif not plans:
            run_status = "FAILED_NO_HARNESS_PLAN"
        elif agent_infrastructure_errors and not build_passed_ids:
            # A provider/schema/session failure is not evidence that the
            # generated program logic was invalid.  Preserve the operational
            # cause instead of misreporting it as NO_VALID/NO_BUILDABLE.
            run_status = "FAILED_AGENT_INFRASTRUCTURE"
        elif not static_passed_ids:
            run_status = "FAILED_NO_VALID_HARNESS"
        elif verification_infrastructure_errors and not build_passed_ids:
            run_status = "FAILED_VERIFICATION_INFRASTRUCTURE"
        elif not build_passed_ids:
            run_status = "FAILED_NO_BUILDABLE_HARNESS"
        elif not self.dynamic_verification:
            run_status = (
                "BUILD_VERIFIED_DRAFT_COMPLETE"
                if (
                    len(build_passed_ids) == len(plans)
                    and not incomplete_analysis
                    and not incomplete_verification
                )
                else "BUILD_VERIFIED_DRAFT_PARTIAL"
            )
        elif not qualified_ids and backend_verified_ids:
            run_status = "BACKEND_VERIFIED_EQUIVALENCE_UNPROVEN"
        elif not qualified_ids:
            run_status = "FAILED_NO_QUALIFIED_HARNESS"
        elif (
            len(qualified_ids) == len(plans)
            and not incomplete_analysis
            and not incomplete_verification
        ):
            run_status = "COMPLETED"
        else:
            run_status = "PARTIAL"

        summary = ScenarioRunSummary(
            run_id=run_id,
            analysis_functions=len(analysis.functions),
            analysis_provider=str(analysis.completeness.get("provider", "unknown")),
            analysis_authoritative=bool(analysis.completeness.get("authoritative", False)),
            fuzz_introspector_used=bool(analysis.completeness.get("fuzz_introspector_used", False)),
            svf_status=str(analysis.completeness.get("svf_status", "UNKNOWN")),
            svf_used=bool(analysis.completeness.get("svf_used", False)),
            svf_indirect_edges_reported=int(
                analysis.completeness.get("svf_indirect_edges_reported", 0)
            ),
            svf_indirect_edges_mapped=int(
                analysis.completeness.get("svf_indirect_edges_mapped", 0)
            ),
            svf_indirect_edges_unmapped=len(
                analysis.completeness.get("svf_mapping_failures", []) or []
            ),
            candidates=len(candidates),
            verified_entries=len(verified),
            unresolved_entries=len(unresolved),
            action_schemas=len(actions),
            state_contracts=len(dependencies.contracts),
            scenario_candidates=len(scenario_candidates),
            scenario_witnesses=len(proven_witnesses),
            unproven_scenarios=sum(item.status is not ScenarioStatus.PROVEN_RUNTIME for item in witnesses),
            harness_plans=len(plans),
            generation_attempts=generation_attempts,
            harnesses_generated=len(generated_ids),
            harnesses_static_passed=len(static_passed_ids),
            harnesses_build_passed=len(build_passed_ids),
            harnesses_blocked=len(blocked_plans),
            harnesses_qualified=len(qualified_ids),
            harnesses_backend_qualified=len(backend_verified_ids),
            original_crashes_reproduced=len(original_reproduced),
            harness_artifacts=len(harness_artifacts),
            status=run_status,
            output_root=str(store.root),
            agent_infrastructure_failures=len(agent_infrastructure_errors),
            verification_infrastructure_failures=len(verification_infrastructure_errors),
            operation_inventory_obligations=len(action_agent.inventory_obligations),
            state_dependency_obligations=len(dependencies.open_obligations),
            unproven_target_actions=len(unproven_target_actions),
            scenario_planning_obligations=len(planner.obligations),
            in_scope_unresolved_entries=len(in_scope_unresolved),
            scenario_skipped_entries=len(action_agent.skipped_entries),
            exploratory_scenarios=len(exploratory_candidates),
            observed_scenarios=len(observed_witnesses),
            exploratory_builds=len(exploratory_build_ids),
            entry_generator_uninspected_functions=uninspected_functions,
            input_surface_cases=len(raw_input_cases),
            input_surface_runtime_trials=raw_trial_count,
            input_surface_obligations=len(surface_agent.obligations),
        )
        store.write_jsonl("debug/agent-infrastructure-failures.jsonl", agent_infrastructure_errors)
        # Account for all input Actions, including those the planner or
        # runtime could not handle. Reconstructing this from only output
        # harnesses would silently lose the most important failures.
        inventory = candidate_lifecycle(
            actions, scenario_candidates, witnesses, plans,
            generated=generated_by_action, built=build_passed_ids,
            backend_verified=backend_verified_ids,
            semantic_verified=qualified_ids,
        )
        store.write_jsonl("workflow/candidate-lifecycle.jsonl", inventory)
        store.write_json("workflow/attrition.json", {
            "actions_discovered": len(actions),
            "actions_without_scenarios": sum(not row.scenario_ids for row in inventory),
            "actions_without_plans": sum(not row.plan_ids for row in inventory),
            "actions_with_generated_drafts": sum(bool(row.generated_harness_ids) for row in inventory),
            "actions_with_builds": sum(bool(row.build_verified_ids) for row in inventory),
            "actions_backend_verified": sum(bool(row.backend_verified_ids) for row in inventory),
            "actions_semantically_verified": sum(bool(row.semantic_verified_ids) for row in inventory),
            "dispositions": {row.action_id: row.disposition for row in inventory},
        })
        store.write_json("summary.json", summary)
        if self._network_harness_config is not None:
            network_result = await asyncio.to_thread(
                self._network_harness_config.prepare_or_run,
                store.root, self.project.source_root,
            )
            store.write_json("research/stateafl/network-harness-result.json", network_result)
            self._emit(
                "network harness " + str(network_result.get("status", "UNKNOWN"))
                + "; result=" + str(
                    store.root / "research/stateafl/network-harness-result.json"
                )
            )
        trace("orchestrator", "run_completed", {
            "message": f"run {run_id} finished with status {run_status}",
            "summary": as_json(summary),
        })
        self._emit(
            f"run {run_status}: witnesses={len(proven_witnesses)}, plans={len(plans)}, "
            f"generated={len(generated_ids)}, build_passed={len(build_passed_ids)}, "
            f"qualified={len(qualified_ids)}, summary={store.root / 'summary.json'}"
        )
        close_dynamic = getattr(dynamic, "close", None)
        if callable(close_dynamic):
            await close_dynamic()
        return summary

    def _prepare_static_analysis(self) -> AnalysisBundle:
        if self.precomputed_analysis is not None:
            self._emit("static analysis started (precomputed FI metadata)")
            if not self.precomputed_analysis.declarations:
                from .analysis.declarations import extract_declarations
                from .analysis.indexer import _iter_project_files
                self.precomputed_analysis.declarations = extract_declarations(
                    self.project.source_root,
                    _iter_project_files(self.project.source_root),
                ).all()
                self.precomputed_analysis.completeness["source_declaration_count"] = (
                    len(self.precomputed_analysis.declarations))
            return self._prepare_indirect_calls(self.precomputed_analysis)

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
                    default_fi_cache_root(self.project.source_root),
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
        from .runtime.preflight import source_analysis_binary
        analysis = StaticAnalyzer(
            self.project.source_root,
            report,
            require_fuzz_introspector=self.project.require_fuzz_introspector,
            excluded_paths=excluded_paths,
            compile_database=self.project.analysis_compile_database,
            target_binary=source_analysis_binary(self.project),
        ).index()
        return self._prepare_indirect_calls(analysis)

    def _prepare_indirect_calls(self, analysis: AnalysisBundle) -> AnalysisBundle:
        if analysis.completeness.get("svf_status") in {"USED", "DISABLED", "UNAVAILABLE"}:
            return analysis
        try:
            return prepare_svf_analysis(
                analysis,
                source_root=self.project.source_root,
                cache_root=default_svf_cache_root(self.project.source_root),
                research_repos_root=self.project.research_repos_root,
                enabled=self.project.svf_enabled,
                required=self.project.require_svf,
                evidence_path=self.project.svf_callgraph,
                bitcode=self.project.svf_bitcode,
                compile_database=self.project.analysis_compile_database,
                progress=self._emit,
            )
        except SVFError as exc:
            raise ValueError(f"SVF indirect-call analysis failed: {exc}") from exc

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


def _independent_review_requires_stop(
    report: GateReport,
    *,
    attempt: int,
    max_attempts: int,
) -> bool:
    """Stop after harness-local repair attempts are exhausted.

    In particular, stale state is commonly repaired by bounded draining or an
    evidenced reset in the harness itself. Treating the first HC03 finding as
    a Small Feature boundary failure caused expensive full-stage reruns.
    """

    if max_attempts == 0 or attempt < max_attempts:
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


def _has_evidenced_feature_contract_conflict(feedback: list[str]) -> bool:
    """Permit semantic recovery only for an explicit source-grounded conflict.

    Static checklist failures, missing generator context, build logs, coverage
    plateaus, and reachability misses do not establish that the recovered
    operation is semantically wrong.  A source-proven action/dependency
    contradiction must be recorded before the Small Feature stage is rerun.
    """

    return any(
        item.startswith((
            "FEATURE_CONTRACT_EVIDENCE:",
            "SOURCE_DEPENDENCY_CONFLICT:",
        ))
        for item in feedback
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
    completion_action_id = str(
        getattr(feature, "completion_action_id", "")
    ).strip()
    if not completion_action_id and len(feature.actions) == 1:
        completion_action_id = str(
            feature.actions[0].get("action_id", "")
        ).strip()
    completion_action = next(
        (
            action for action in feature.actions
            if str(action.get("action_id", "")) == completion_action_id
        ),
        None,
    )
    completion_function_id = (
        str(completion_action.get("function_id", ""))
        if completion_action is not None else ""
    )
    if completion_action is None:
        blockers.append(
            "Small Feature has no explicit semantic completion action"
        )
    elif completion_function_id not in graph.bundle.functions:
        blockers.append(
            "Small Feature completion action has no authoritative function metadata"
        )
    elif not any(
        evidence.function_id == completion_function_id
        and evidence.line is not None
        for evidence in feature.evidence
    ):
        blockers.append(
            "Small Feature completion action has no exact source-line evidence"
        )
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
        return assess_small_feature(feature)
    return assess_small_feature(replace(
        feature,
        planning_complete=False,
        planning_blockers=blockers,
        unknowns=unique_strings([*feature.unknowns, *blockers]),
    ))


def _verification_feedback(result: Any) -> list[str]:
    feedback = [str(result.reason)]
    feedback.extend(str(item) for item in result.harness_faults)
    if result.build and result.build.returncode != 0:
        feedback.append(
            "build diagnostics:\n" + _build_failure_excerpt(result.build.stderr)
        )
    return feedback


def _gate_report_signature(stage: str, report: GateReport) -> str:
    """Stable no-progress key based on failed contracts, not prose wording."""

    material = "\n".join([
        stage,
        *sorted(
            f"{check.check_id}:{check.status}"
            for check in report.checks
            if check.status is not CheckStatus.PASS
        ),
    ])
    return stable_id("repair-failure", material)


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
            r"selector .+ did not reach (?:Small Feature target|the complete evidenced action chain))",
            reachability_details,
        )
    )
    return bool(
        not result.qualified
        and result.failure is not None
        and result.failure.kind is VerificationFailureKind.REACHABILITY
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


def _eligible_for_large_feature(feature: Any) -> bool:
    """Large Feature consumes semantic operations, not only P2-ready drafts.

    ``getattr`` keeps old serialized/test fixtures compatible.  New Small
    Feature objects always carry the explicit semantic contract.
    """

    return bool(getattr(feature, "semantic_complete", True))


def _deduplicate_verified_entries(
    entries: list[EntryRecord],
) -> tuple[list[EntryRecord], list[dict[str, Any]]]:
    """Merge repeated verifier results that identify the same concrete site."""
    grouped: dict[tuple[str, str, int | None], list[EntryRecord]] = {}
    def site_line(record: EntryRecord) -> int | None:
        lines = [item.line for item in record.evidence
                 if item.function_id == record.entry_function_id
                 and item.line is not None]
        return record.entry_line if record.entry_line is not None else (
            min(lines) if lines else None)

    for entry in entries:
        source_name = entry.source_api.casefold().strip()
        line = site_line(entry)
        if source_name.startswith('std::') and not any(
            other.entry_function_id == entry.entry_function_id
            and site_line(other) == line
            and other.source_api.casefold().endswith(
                '::' + source_name.removeprefix('std::'))
            and not other.source_api.casefold().startswith('std::')
            for other in entries
        ):
            # std::getline and the unqualified lookup of that same API can
            # describe one concrete source site when no competing qualified
            # API of that name is present at the same source line.
            source_name = source_name.removeprefix('std::')
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
