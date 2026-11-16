"""Lossless, proof-separated tracking of generated-harness candidates.

The ledger is an inventory/audit, never a source of runtime verification.
It deliberately records failures and untested candidates instead of filtering
those items from downstream reporting. All stage statuses are orthogonal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..models import (
    ExternalActionSchema, HarnessPlan, ProofStatus, ScenarioCandidate,
    ScenarioStatus, ScenarioWitness,
)


@dataclass(slots=True)
class CandidateLifecycle:
    action_id: str
    entry_id: str
    discovery_proof: str
    source_evidence_count: int
    example_count: int
    scenario_ids: list[str] = field(default_factory=list)
    runtime_statuses: dict[str, str] = field(default_factory=dict)
    plan_ids: list[str] = field(default_factory=list)
    generated_harness_ids: list[str] = field(default_factory=list)
    build_verified_ids: list[str] = field(default_factory=list)
    backend_verified_ids: list[str] = field(default_factory=list)
    semantic_verified_ids: list[str] = field(default_factory=list)
    obligations: list[str] = field(default_factory=list)
    disposition: str = "DISCOVERED"


def candidate_lifecycle(
    actions: Iterable[ExternalActionSchema],
    scenarios: Iterable[ScenarioCandidate] = (),
    witnesses: Iterable[ScenarioWitness] = (),
    plans: Iterable[HarnessPlan] = (),
    *,
    generated: dict[str, list[str]] | None = None,
    built: set[str] | None = None,
    backend_verified: set[str] | None = None,
    semantic_verified: set[str] | None = None,
) -> list[CandidateLifecycle]:
    """Account for *every* Action, including refuted/unsupported actions.

    The final disposition is not a global approval decision. A runtime-proven
    action may still lack a buildable harness; a source-backed draft may exist
    without any runtime evidence. This function never upgrades proof status.
    """
    rows: dict[str, CandidateLifecycle] = {}
    for action in actions:
        obligations = list(action.unknowns)
        if not action.examples:
            obligations.append("REQUEST_EXAMPLE_MISSING")
        if not action.evidence:
            obligations.append("SOURCE_EVIDENCE_MISSING")
        if not action.handler_function_id or not action.entry_function_id:
            obligations.append("INPUT_TO_HANDLER_BOUNDARY_UNRESOLVED")
        if action.status is ProofStatus.REFUTED:
            obligations.append("REFUTED_BY_SOURCE_EVIDENCE")
        rows[action.action_id] = CandidateLifecycle(
            action_id=action.action_id,
            entry_id=action.entry_id,
            discovery_proof=str(action.status),
            source_evidence_count=len(action.evidence),
            example_count=len(action.examples),
            obligations=obligations,
        )
    for scenario in scenarios:
        row = rows.get(scenario.target_action_id)
        if row is None:
            continue
        if scenario.scenario_id not in row.scenario_ids:
            row.scenario_ids.append(scenario.scenario_id)
        if scenario.status is not ScenarioStatus.CANDIDATE:
            row.obligations.append("SCENARIO_BLOCKED: " + scenario.blocker)
    for witness in witnesses:
        row = rows.get(witness.target_action_id)
        if row is None:
            continue
        row.runtime_statuses[witness.scenario_id] = str(witness.status)
        if witness.status is not ScenarioStatus.PROVEN_RUNTIME:
            row.obligations.append(
                "ORIGINAL_RUNTIME_NOT_PROVEN: " + witness.rationale[:240]
            )
    for plan in plans:
        row = rows.get(plan.target_action_id)
        if row and plan.plan_id not in row.plan_ids:
            row.plan_ids.append(plan.plan_id)
    generated = generated or {}
    built = built or set()
    backend_verified = backend_verified or set()
    semantic_verified = semantic_verified or set()
    for action_id, row in rows.items():
        row.generated_harness_ids = list(dict.fromkeys(generated.get(action_id, [])))
        row.build_verified_ids = [item for item in row.generated_harness_ids if item in built]
        row.backend_verified_ids = [item for item in row.generated_harness_ids if item in backend_verified]
        row.semantic_verified_ids = [item for item in row.generated_harness_ids if item in semantic_verified]
        if row.semantic_verified_ids:
            row.disposition = "SEMANTIC_VERIFIED"
        elif row.backend_verified_ids:
            row.disposition = "BACKEND_VERIFIED_EQUIVALENCE_UNKNOWN"
        elif row.build_verified_ids:
            row.disposition = "BUILD_VERIFIED_EQUIVALENCE_UNKNOWN"
        elif row.generated_harness_ids:
            row.disposition = "GENERATED_UNVERIFIED"
        elif row.plan_ids:
            row.disposition = "PLANNED_NOT_GENERATED"
        elif row.scenario_ids:
            row.disposition = "SCENARIO_ONLY"
        elif row.discovery_proof == str(ProofStatus.REFUTED):
            row.disposition = "REFUTED"
        else:
            row.disposition = "ACTION_NOT_PLANNED"
            row.obligations.append("NO_SCENARIO_SCHEDULED")
        row.obligations = list(dict.fromkeys(row.obligations))
    return list(rows.values())


@dataclass(slots=True)
class GenerationSchedule:
    """An explicit, proof-preserving inventory of all runtime witnesses.

    A response/handler *observation* is not target-reach proof; it may still
    be used to produce a clearly unqualified source-level draft. We separate
    scheduling from proof and expose exclusions instead of silently dropping
    viable analyses between pipeline stages.
    """

    proven: list[ScenarioWitness]
    observed: list[ScenarioWitness]
    source_only: list[ScenarioWitness]
    excluded: dict[str, str]

    @property
    def selected(self) -> list[ScenarioWitness]:
        return [*self.proven, *self.observed, *self.source_only]


def schedule_generation(
    witnesses: Iterable[ScenarioWitness],
    *,
    source_supported_actions: set[str],
    exploratory_enabled: bool,
    source_drafts_enabled: bool,
    max_source_drafts: int,
) -> GenerationSchedule:
    """Select by evidence strength, then by distinct Action coverage.

    In particular, with source-only drafts enabled and exploratory mode off,
    observed / replayed witnesses MUST NOT disappear. They have an input
    response or temporal observation but lack strong request attribution.
    Their generation is permitted, their qualification remains forbidden.
    """
    all_witnesses = list(witnesses)
    proven = [w for w in all_witnesses if w.status is ScenarioStatus.PROVEN_RUNTIME]
    observed_all = [w for w in all_witnesses if w.status in {
        ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME,
    }]
    source_all = [w for w in all_witnesses if w.status in {
        ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED,
    }]
    selected_ids = {w.scenario_id for w in proven}
    excluded: dict[str, str] = {}

    def by_distinct_actions(items: list[ScenarioWitness]) -> list[ScenarioWitness]:
        seen_actions: set[str] = set()
        primary: list[ScenarioWitness] = []
        alternatives: list[ScenarioWitness] = []
        for w in items:
            if w.target_action_id in seen_actions:
                alternatives.append(w)
            else:
                seen_actions.add(w.target_action_id)
                primary.append(w)
        return [*primary, *alternatives]

    # Existing explicitly requested exploratory mode retains observed trials.
    observed = observed_all if exploratory_enabled else []
    for w in observed:
        selected_ids.add(w.scenario_id)
    # Source-only budget is shared between source-only observations and failed
    # executions when exploratory mode is disabled, so all function types get
    # a fair chance rather than the first Action consuming the whole budget.
    source_pool = [
        w for w in [*observed_all, *source_all]
        if w.scenario_id not in selected_ids and w.steps
        and w.target_action_id in source_supported_actions
    ] if source_drafts_enabled else []
    source_only = by_distinct_actions(source_pool)[:max(0, max_source_drafts)]
    selected_ids.update(w.scenario_id for w in source_only)
    for w in all_witnesses:
        if w.scenario_id in selected_ids:
            continue
        if w.status is ScenarioStatus.PROVEN_RUNTIME:
            excluded[w.scenario_id] = "DUPLICATE_SCENARIO"
        elif w.target_action_id not in source_supported_actions:
            excluded[w.scenario_id] = "SOURCE_CONTRACT_INCOMPLETE"
        elif not w.steps:
            excluded[w.scenario_id] = "REQUEST_SEQUENCE_MISSING"
        elif w.status in {
            ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME,
            ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED,
        } and not (source_drafts_enabled or exploratory_enabled):
            excluded[w.scenario_id] = "DRAFT_GENERATION_DISABLED"
        else:
            excluded[w.scenario_id] = "SOURCE_DRAFT_BUDGET_EXHAUSTED_OR_NOT_EXECUTABLE"
    return GenerationSchedule(proven, observed, source_only, excluded)
