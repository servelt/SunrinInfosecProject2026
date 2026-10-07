from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    EntryRecord,
    EntrySiteKind,
    Evidence,
    SmallFeatureSpec,
    Verdict,
    as_json,
    evidence_from_dict,
    stable_id,
    unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from .common import (
    concurrent_map,
    function_payload,
    function_ref,
    is_non_product_build_target,
    object_list,
    prefer_product_build_targets,
    string_list,
)
from .features import SMALL_FEATURE_DISCOVERY_SCHEMA, SMALL_FEATURE_RECONCILIATION_SCHEMA


MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND = 3
DEFAULT_MAX_SMALL_FEATURE_TURNS = 64
MAX_FULL_OPERATION_INVENTORY = 12
# Once the active source window is full, opening another implementation detail
# necessarily evicts evidence the model just used. At that point completed
# operation contracts are more reliable than an unbounded descent through
# allocator/container internals. Keep this aligned with the default 24-function
# Small Feature working set; callers with a larger budget still require at
# least their full active window below.
MAX_OPERATION_CONTEXT_BEFORE_CONTRACT_STOP = 24
MAX_STALLED_SMALL_FEATURE_TURNS = 4
INITIAL_REQUEST_RESERVE = 6


@dataclass(slots=True)
class _Proposal:
    proposal_id: str
    seed_entry_id: str
    feature: SmallFeatureSpec


@dataclass(slots=True)
class _DiscoveryResult:
    proposals: list[_Proposal]
    entry_resolutions: dict[str, EntryRecord]


class SmallFeatureAgent:
    """Recover operations from Entry contexts with a many-to-many relation.

    Every Entry is independently used as a context seed.  A seed may expose zero,
    one, or several operations; each operation may reference several Entries; and
    the same Entry may legitimately occur in several operations.  Only operation
    proposals are reconciled/deduplicated -- Entries are never claimed or consumed.
    """

    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        *,
        depth: int = 4,
        budget: int = 24,
        max_turns: int = DEFAULT_MAX_SMALL_FEATURE_TURNS,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.depth = depth
        self.budget = budget
        self.max_turns = max(1, max_turns)
        self.trace = trace
        self.last_promoted_entries: list[EntryRecord] = []
        self.last_final_entries: list[EntryRecord] = []
        self.last_dropped_entry_outcomes: list[dict[str, Any]] = []

    async def run(
        self,
        entries: list[EntryRecord],
        *,
        harness_feedback: list[str] | None = None,
        excluded_anchors: list[str] | None = None,
    ) -> list[SmallFeatureSpec]:
        async def discover(entry: EntryRecord) -> _DiscoveryResult:
            return await self._discover_from_entry(
                entry,
                entries,
                harness_feedback=harness_feedback or [],
                excluded_anchors=set(excluded_anchors or []),
            )

        discovered = await concurrent_map(
            entries,
            discover,
            getattr(self.llm, "max_concurrency", 1),
        )
        claims_by_entry: dict[str, list[EntryRecord]] = {
            entry.entry_id: [] for entry in entries if entry.status is Verdict.UNRESOLVED
        }
        for result in discovered:
            for entry_id, resolution in result.entry_resolutions.items():
                if entry_id in claims_by_entry:
                    claims_by_entry[entry_id].append(resolution)

        final_entry_by_id: dict[str, EntryRecord] = {
            entry.entry_id: entry for entry in entries if entry.status is Verdict.VERIFIED
        }
        promoted: list[EntryRecord] = []
        dropped: list[dict[str, Any]] = []
        for entry in entries:
            if entry.status is not Verdict.UNRESOLVED:
                continue
            resolution, drop_reason = _merge_entry_resolution_claims(
                entry,
                claims_by_entry.get(entry.entry_id, []),
            )
            if resolution.status is Verdict.VERIFIED:
                final_entry_by_id[entry.entry_id] = resolution
                promoted.append(resolution)
            else:
                dropped.append({
                    "entry": as_json(resolution),
                    "drop_reason": drop_reason,
                })

        verified_entry_ids = set(final_entry_by_id)
        proposals: list[_Proposal] = []
        for result in discovered:
            for proposal in result.proposals:
                members = set([
                    *proposal.feature.root_entries,
                    *proposal.feature.supporting_entries,
                ])
                if members <= verified_entry_ids:
                    proposals.append(proposal)
                    continue
                emit_trace(
                    self.trace,
                    "small_feature",
                    "proposal_rejected",
                    (
                        f"{proposal.proposal_id}: Entry membership remained unresolved "
                        "or was rejected at the end of Small Feature recovery"
                    ),
                    proposal_id=proposal.proposal_id,
                    unverified_entry_ids=sorted(members - verified_entry_ids),
                    reason="only VERIFIED Entries may belong to a Small Feature",
                )

        self.last_promoted_entries = promoted
        self.last_final_entries = list(final_entry_by_id.values())
        self.last_dropped_entry_outcomes = dropped
        recovery_mode = bool(harness_feedback or excluded_anchors)
        proposal_label = (
            "accepted replacement operation proposals"
            if recovery_mode
            else "operation proposals"
        )
        emit_trace(
            self.trace,
            "small_feature",
            "discovery_completed",
            f"discovered {len(proposals)} {proposal_label} from {len(entries)} Entry contexts",
            entry_count=len(entries),
            proposal_count=len(proposals),
            recovery_mode=recovery_mode,
            proposals_per_entry={
                entry.entry_id: sum(
                    proposal.seed_entry_id == entry.entry_id for proposal in proposals
                )
                for entry in entries
            },
        )
        if not proposals:
            return []

        final: list[SmallFeatureSpec] = []
        for component in _proposal_components(proposals):
            groups = await self._reconcile_component(component)
            for group in groups:
                final.append(self._merge_group(group, final_entry_by_id))

        # A collision means reconciliation failed to distinguish the same operation
        # signature. Keep one canonical object, but never consume Entry membership.
        final = list({feature.small_feature_id: feature for feature in final}.values())
        concrete_operation_entries = {
            entry_id
            for feature in final
            if any(
                value.startswith("command:")
                for value in _operation_discriminators(feature)
            )
            for entry_id in [*feature.root_entries, *feature.supporting_entries]
        }
        filtered_final: list[SmallFeatureSpec] = []
        for feature in final:
            members = set([*feature.root_entries, *feature.supporting_entries])
            if (
                _is_generic_dispatcher_family(feature)
                and bool(members & concrete_operation_entries)
            ):
                emit_trace(
                    self.trace,
                    "small_feature",
                    "feature_rejected",
                    (
                        f"rejected {feature.small_feature_id} '{feature.name}': "
                        "generic dispatcher is not one requested job"
                    ),
                    small_feature_id=feature.small_feature_id,
                    entry_ids=sorted(members),
                    reason=(
                        "concrete requested operations were recovered for the same "
                        "Entry; transport/parser/dispatcher family is context only"
                    ),
                )
                continue
            filtered_final.append(feature)
        final = filtered_final
        entry_feature_map: dict[str, list[str]] = {entry.entry_id: [] for entry in entries}
        for feature in final:
            for entry_id in unique_strings([*feature.root_entries, *feature.supporting_entries]):
                if entry_id in entry_feature_map:
                    entry_feature_map[entry_id].append(feature.small_feature_id)
        emit_trace(
            self.trace,
            "small_feature",
            "completed",
            f"reconciled {len(proposals)} proposals into {len(final)} Small Features",
            proposal_count=len(proposals),
            feature_count=len(final),
            entry_feature_map=entry_feature_map,
            feature_ids=[feature.small_feature_id for feature in final],
        )
        return final

    async def _discover_from_entry(
        self,
        seed: EntryRecord,
        entries: list[EntryRecord],
        *,
        harness_feedback: list[str],
        excluded_anchors: set[str],
    ) -> _DiscoveryResult:
        session_key = f"small_feature:{seed.entry_id}"
        emit_trace(
            self.trace,
            "small_feature",
            "entry_started",
            f"enumerate operations visible from Entry context {seed.entry_id}",
            entry=as_json(seed),
            root_function=function_ref(self.graph.get(seed.entry_function_id)),
        )
        # Entry verification may already have inspected enough functions to fill
        # the entire Small Feature prompt.  Keep that useful history, but reserve
        # room for the operation agent's targeted requests.  Without the reserve,
        # a request such as ``tcp_read`` resolves successfully and is then silently
        # starved by a full context window on every subsequent turn.
        initial_context_limit = max(
            1,
            self.budget - min(INITIAL_REQUEST_RESERVE, max(0, self.budget - 1)),
        )
        inspected_history_ids = [
            function_id for function_id in unique_strings([
                seed.entry_function_id,
                *seed.inspected_function_ids,
            ])
            if function_id in self.graph.bundle.functions
        ]
        selected_function_ids = inspected_history_ids[:initial_context_limit]
        discovery_by_id: dict[str, dict[str, Any]] = {
            function_id: {
                "depth": 0,
                "discovered_from": None,
                "relation": (
                    "root"
                    if function_id == seed.entry_function_id
                    else "retained_context"
                    if function_id in selected_function_ids
                    else "previously_inspected"
                ),
            }
            for function_id in inspected_history_ids
        }
        local_entry_by_id = {entry.entry_id: entry for entry in entries}
        local_resolutions: dict[str, EntryRecord] = {}
        previous_response: dict[str, Any] = {}
        proposal_by_key: dict[str, _Proposal] = {}
        contextual_by_id: dict[str, EntryRecord] = {}
        response: dict[str, Any] = {}
        stop_reason = "hard Small Feature turn safety limit reached"
        authoritative = bool(self.graph.bundle.completeness.get("authoritative", False))
        # The stateful Codex thread retains source from earlier turns. Re-sending
        # the full growing source set every round duplicates code in the thread
        # history and can exhaust its context window prematurely.
        supplied_source_ids: set[str] = set()
        partition_checkpoint_sent = False
        incremental_partition_checkpoint_sent = False
        contract_stop_checkpoint_sent = False

        stalled_turns = 0
        for round_number in range(1, self.max_turns + 1):
            final_safety_turn = round_number >= self.max_turns
            context = [
                self.graph.get(function_id)
                for function_id in selected_function_ids[: self.budget]
            ]
            active_function_ids = {
                function.function_id for function in context
            }
            new_context = [
                function for function in context
                if function.function_id not in supplied_source_ids
            ]
            walk = []
            for function in context:
                walk.append({
                    "function_id": function.function_id,
                    "name": function.name,
                    "file": function.file,
                    "start_line": function.start_line,
                    **discovery_by_id[function.function_id],
                })
            # ``selected_function_ids`` is only the bounded working-set used
            # to choose the next graph move.  It is not the agent's evidence
            # history.  A function whose source was opened earlier remains
            # valid evidence in this stateful session even after it is evicted
            # from the working set to make room for another requested source.
            # Treating only the final 24 active functions as allowed used to
            # invalidate already-proven callers such as memcached's
            # event_handler and silently replace the anchor with the lower
            # recvfrom Entry function.
            evidence_function_ids = [
                function_id
                for function_id in discovery_by_id
                if (
                    function_id in supplied_source_ids
                    or function_id in active_function_ids
                )
            ]
            allowed_functions = {
                function_id: self.graph.get(function_id)
                for function_id in evidence_function_ids
            }
            frontier = self.graph.frontier(selected_function_ids)
            pending_entries_by_function: dict[str, list[str]] = {}
            for entry in local_entry_by_id.values():
                if entry.status is Verdict.UNRESOLVED:
                    pending_entries_by_function.setdefault(
                        entry.entry_function_id, []
                    ).append(entry.entry_id)
            for choice in frontier:
                choice["pending_unresolved_entry_ids"] = pending_entries_by_function.get(
                    str(choice["function_id"]),
                    [],
                )
            frontier_by_id = {
                str(item["function_id"]): item for item in frontier
            }
            contextual_entries = [
                entry for entry in local_entry_by_id.values()
                if entry.entry_function_id in allowed_functions
            ]
            for entry in contextual_entries:
                if entry.status is not Verdict.UNRESOLVED:
                    continue
                updated = replace(
                    entry,
                    inspected_function_ids=unique_strings([
                        *entry.inspected_function_ids,
                        *allowed_functions,
                    ]),
                    verification_rounds=entry.verification_rounds + 1,
                )
                local_entry_by_id[entry.entry_id] = updated
                local_resolutions[entry.entry_id] = updated
            contextual_entries = [
                local_entry_by_id[entry.entry_id] for entry in contextual_entries
            ]
            contextual_by_id = {entry.entry_id: entry for entry in contextual_entries}
            focus_line_by_function = {
                entry.entry_function_id: entry.entry_line
                for entry in contextual_entries
                if entry.entry_line is not None
            }
            function_names = {function.function_id: function.name for function in context}
            walk_summary = [
                (
                    f"root:{item['name']}"
                    if item["relation"] == "root"
                    else (
                        f"{item['relation']}:{item['name']}<-"
                        f"{function_names.get(str(item['discovered_from']), item['discovered_from'])}"
                    )
                )
                for item in walk
            ]
            emit_trace(
                self.trace,
                "small_feature",
                "context_walk",
                (
                    f"{seed.entry_id} round {round_number}: selected {len(context)} functions and "
                    f"{len(contextual_entries)} contextual Entries; walk={walk_summary}"
                ),
                entry_id=seed.entry_id,
                round=round_number,
                expansion_mode="model_requested_only",
                selected_function_ids=list(selected_function_ids),
                root_function_id=seed.entry_function_id,
                depth_limit=self.depth,
                function_budget=self.budget,
                analysis_authoritative=authoritative,
                contextual_entry_ids=list(contextual_by_id),
                functions=[function_ref(item) for item in context],
                available_context_functions=frontier,
                walk=walk,
                walk_summary=walk_summary,
                graph_edges=self.graph.induced_edges(active_function_ids),
            )
            previous_blocker_map = previous_response.get("planning_blockers", {})
            previous_blockers = (
                [
                    str(blocker)
                    for blockers in previous_blocker_map.values()
                    if isinstance(blockers, list)
                    for blocker in blockers
                ]
                if isinstance(previous_blocker_map, dict)
                else []
            )
            operation_partition_required = bool(harness_feedback) or any(
                "concrete requested operation boundary is unresolved" in blocker
                for blocker in previous_blockers
            )
            incremental_partition = (
                operation_partition_required
                and len(proposal_by_key) >= MAX_FULL_OPERATION_INVENTORY
            )
            contract_stop_required = bool(
                incremental_partition
                and len(evidence_function_ids)
                >= max(
                    MAX_OPERATION_CONTEXT_BEFORE_CONTRACT_STOP,
                    self.budget,
                )
            )
            operation_partition_instruction = (
                " A Small Feature must be one concrete requested job whose success, rejection, "
                "or failure can be decided. A socket receive loop, protocol selector, parser "
                "family, command dispatcher, or generic response transmitter is not one Small "
                "Feature when it branches into semantically distinct requested commands. Do not "
                "return that generic dispatcher as a feature. Instead, use it only to discover "
                "the individual handlers, request/open those handlers one at a time, and return "
                "one Small Feature per evidenced command or operation. Reuse the same Entry in "
                "every applicable feature. Do not mark context_complete while unopened "
                "command-specific handlers can change prerequisites, state, results, responses, "
                "success/failure, or cleanup. When harness_feedback reports stale state or an "
                "incomplete reset, identify the concrete operation that owns that state and open "
                "its exact initialization, reset, or cleanup implementation. When "
                "stateful_resume_checkpoint is present, it contains the complete source evidence "
                "opened before this partitioning turn and replaces any need for earlier chat turns."
                + (
                    " The client has already retained the previously accepted concrete operations. "
                    "To keep this large inventory bounded, return only operations newly discovered "
                    "from the latest sources or earlier operations whose semantic actions, lifecycle, "
                    "or completion result materially changed. Do not repeat unchanged operations."
                    if incremental_partition
                    else ""
                )
                + (
                    " Treat a project function's evidenced call, checked return value, and documented "
                    "state/resource effect as a sufficient callable contract. Do not recursively open "
                    "allocator, container, statistics, serialization, response-buffer, or cleanup "
                    "implementation internals merely to restate that contract. Request another "
                    "function only when its body can still change the operation boundary, required "
                    "call order, fuzzer-input delivery, success/failure decision, stable post-state, "
                    "or whether cleanup is actually invoked. Otherwise finish the concrete operation "
                    "inventory with context_complete=true. For this bounded transition, "
                    "stateful_resume_checkpoint.functions is the complete active source working set, "
                    "while retained_operations is the compact authoritative record of operations "
                    "accepted from older source; do not reopen old implementation internals merely "
                    "because their full source was retired from the working set."
                    if contract_stop_required
                    else ""
                )
                if operation_partition_required
                else ""
            )
            needs_partition_checkpoint = bool(
                operation_partition_required
                and (
                    not partition_checkpoint_sent
                    or (
                        incremental_partition
                        and not incremental_partition_checkpoint_sent
                    )
                    or (
                        contract_stop_required
                        and not contract_stop_checkpoint_sent
                    )
                )
            )
            checkpoint_function_ids = (
                selected_function_ids[: self.budget]
                if contract_stop_required
                else evidence_function_ids
            )
            checkpoint_functions = []
            checkpoint_metadata_only_functions = []
            if needs_partition_checkpoint:
                for function_id in checkpoint_function_ids:
                    item = function_payload(self.graph.get(function_id))
                    if str(item.get("source", "")).strip():
                        checkpoint_functions.append(item)
                    else:
                        checkpoint_metadata_only_functions.append(
                            function_ref(self.graph.get(function_id))
                        )
            stateful_resume_checkpoint = (
                {
                    "complete": True,
                    "functions": checkpoint_functions,
                    **(
                        {
                            "metadata_only_functions": (
                                checkpoint_metadata_only_functions
                            ),
                        }
                        if checkpoint_metadata_only_functions
                        else {}
                    ),
                    **(
                        {
                            "retained_operations": [
                                {
                                    "name": proposal.feature.name,
                                    "root_entries": proposal.feature.root_entries,
                                    "supporting_entries": proposal.feature.supporting_entries,
                                    "harness_anchor": proposal.feature.harness_anchor,
                                    "action_functions": unique_strings(
                                        str(action.get("function_id", ""))
                                        for action in proposal.feature.actions
                                    ),
                                    "completion_oracle": proposal.feature.completion_oracle,
                                    "stable_post_state": proposal.feature.stable_post_state,
                                    "planning_complete": proposal.feature.planning_complete,
                                    "planning_blockers": proposal.feature.planning_blockers,
                                }
                                for proposal in proposal_by_key.values()
                            ],
                        }
                        if contract_stop_required
                        else {}
                    ),
                }
                if needs_partition_checkpoint
                else None
            )
            response = await self.llm.complete_json(
                role="small_feature",
                instructions=(
                    "Enumerate minimal requested operations, not Entry sites. From seed_entry and caller/callee context, "
                    "return zero, one, or multiple distinct Small Features. One Entry may participate in multiple "
                    "operations and one operation may require multiple root/supporting Entries. Reconstruct the real "
                    "operation steps and any initialization, prerequisite state, result handling, or cleanup that the "
                    "supplied source actually shows. These lifecycle categories are optional: do not invent or search "
                    "for initialization, objects, callbacks, reset, cleanup, or prerequisite state merely because that "
                    "category can exist in other programs. In preconditions, record only program state that must exist "
                    "before the first Entry (for example session, authentication, configuration, connection, object, "
                    "or mode state). Opcode, command token, packet framing, byte/length restrictions, and other "
                    "per-request shapes are input construction constraints: record those in input_bindings.transform "
                    "and the applicable action contract, not in preconditions. Give every action a unique action_id; "
                    "allowed_after may contain only action_id values that "
                    "occur earlier in the returned action list. entry_call_order must list every root/supporting Entry ID "
                    "at least once in runtime order; repeat an Entry ID when the real lifecycle invokes the same Entry Site "
                    "multiple times. The harness_anchor is not automatically the Input Entry: choose the highest evidenced "
                    "normal application boundary that executes the operation and is realistically invocable through a "
                    "declared API or a process/event dispatcher. Never select a lower parser merely because it is easy. "
                    "Small Feature discovery is semantic grouping: if the operation is evidenced but a normal lifecycle "
                    "anchor is still unresolved, return the operation with boundary_preserved=false and describe the "
                    "missing setup instead of omitting the feature. That feature will be retained but blocked from harness "
                    "generation until the boundary is proven. context_complete describes whether the semantic operation "
                    "inventory is complete; do not keep it false merely to prove final harness compileability or a public "
                    "anchor. "
                    "For every root Entry, describe how per-iteration fuzzer bytes reach its real network/file/stdin/argv/"
                    "environment/IPC transport. Only functions in context or opened_context_functions have had source "
                    "supplied in this same stateful agent session and may be used as evidence. context contains only "
                    "source newly opened in this round; do not mistake that delta for loss of earlier source history. "
                    "Acquiring argc/argv at process start is not sufficient input flow when the real function "
                    "body never reads those parameters: retain that semantic feature if useful, but its input binding "
                    "must remain unresolved and it must not become harness-ready. Never claim a binding is proven while "
                    "also stating that the supplied bytes are unused, not consumed, or do not influence a branch. "
                    "available_context_functions contains source-free direct caller/callee choices. Request "
                    "the smallest necessary set of IDs from that list. For a callback target, function-pointer "
                    "assignment, state writer, registration function, or dispatcher named in supplied source, you may "
                    "also request that exact project function ID or unique function name even when it is absent from "
                    "available_context_functions; only names resolving to the project analysis database will open. "
                    "opened_context_functions lists the active bounded functions whose source has been shown in this "
                    "session, while previously_opened_context_functions lists source shown here and later evicted. "
                    "previously_inspected_entry_functions is metadata inherited from Entry verification in a different "
                    "session and is NOT source evidence; explicitly request one when its source is needed. Do not request "
                    "a source already shown in this session again unless exact text is strictly needed for the final decision. "
                    "Requested functions will be opened on the next round. Some context_entries may still be UNRESOLVED from Entry verification. Resolve "
                    "each such Entry while reconstructing the operation: VERIFIED requires external-data provenance, "
                    "the exact first acquisition site, valid line evidence, and confidence >= 0.80; REJECTED requires "
                    "affirmative contrary evidence; otherwise keep it UNRESOLVED and request the exact adjacent source "
                    "needed. An UNRESOLVED Entry may become visible while walking another Entry's dependencies. If it is "
                    "VERIFIED and participates in the same operation, include it in that Small Feature as a root or "
                    "supporting Entry. Never include an Entry in a feature before verifying it. Continue opening relevant "
                    "source while it can change an Entry or lifecycle decision. Do not leave context_complete=false or an "
                    "Entry UNRESOLVED without either requesting the exact next function or explaining that no remaining "
                    "project source can resolve it. Once evidence is sufficient, directly decide VERIFIED or REJECTED. "
                    "The high turn limit is only a stuck-loop safety valve, not a normal stopping target. On a "
                    "final_safety_turn, request nothing further and make the strongest evidence-grounded final decision. "
                    "Entries still unresolved when the Small Feature safety limit ends will be dropped. A missing edge in non-authoritative bootstrap analysis is uncertainty, "
                    "not proof that two functions are unrelated. Set context_complete=false for initialization, callback "
                    "registration, input delivery, cleanup, or an observable result only when a concrete call, state check, "
                    "resource acquisition, function-pointer use, or established Feature requirement proves that item is "
                    "required and its implementation remains unresolved. The absence of an optional lifecycle category is "
                    "a complete result, not a reason to expand context. Request the exact graph-visible function IDs needed "
                    "for another round. Do not claim "
                    "context_complete while selecting a static/private callback with no evidenced setup path. Every "
                    "returned feature must contain seed_entry as a root or supporting Entry. Distinct requested commands "
                    "or operations remain distinct, but success, rejection, and failure branches of the SAME request are "
                    "outcomes inside one Small Feature, not separate Small Features. Represent them through action guards, "
                    "success_condition, completion_oracle, and success/failure cleanup. On every context round, return the complete operation "
                    "inventory still supported by the evidence, not only the proposal changed in that round. isolation_mode "
                    "describes a boundary required by the real application operation, not a harness workaround: choose "
                    "fork_per_input or subprocess only when opened application source proves that this operation itself "
                    "must cross a fork/exec/process boundary. Never choose them merely to reset globals, contain crashes, "
                    "or compensate for unresolved cleanup. Use loopback_network when preserving the real socket transport "
                    "is required, and in_process_reset for directly repeatable in-process operations. Use only "
                    "supplied IDs and source evidence."
                    + operation_partition_instruction
                ),
                payload={
                    "seed_entry": _entry_payload(local_entry_by_id[seed.entry_id]),
                    "context_entries": [_entry_payload(entry) for entry in contextual_entries],
                    "pending_unresolved_entries": [
                        _entry_payload(entry) for entry in contextual_entries
                        if entry.status is Verdict.UNRESOLVED
                    ],
                    "context": [
                        function_payload(
                            function,
                            focus_line=focus_line_by_function.get(function.function_id),
                        )
                        for function in new_context
                    ],
                    "opened_context_functions": [
                        function_ref(function) for function in context
                    ],
                    "available_context_functions": frontier,
                    "context_round": round_number,
                    "context_limits": {
                        "max_turns": self.max_turns,
                        "graph_path_depth": self.depth,
                        "final_safety_turn": final_safety_turn,
                        "max_functions": self.budget,
                        "max_new_functions_per_round": (
                            MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND
                        ),
                        "expansion_mode": "model_requested_only",
                        "analysis_authoritative": authoritative,
                    },
                    "previous_round": _small_feature_round_digest(previous_response),
                    "previously_opened_context_functions": [
                        function_ref(self.graph.get(function_id))
                        for function_id in supplied_source_ids
                        if function_id not in active_function_ids
                    ],
                    "previously_inspected_entry_functions": [
                        function_ref(self.graph.get(function_id))
                        for function_id in discovery_by_id
                        if function_id not in active_function_ids
                        and function_id not in supplied_source_ids
                    ],
                    "harness_feedback": harness_feedback,
                    "excluded_anchors": sorted(excluded_anchors),
                    **(
                        {"stateful_resume_checkpoint": stateful_resume_checkpoint}
                        if stateful_resume_checkpoint is not None
                        else {}
                    ),
                },
                output_schema=SMALL_FEATURE_DISCOVERY_SCHEMA,
                session_key=session_key,
            )
            if stateful_resume_checkpoint is not None:
                partition_checkpoint_sent = True
                if incremental_partition:
                    incremental_partition_checkpoint_sent = True
                if contract_stop_required:
                    contract_stop_checkpoint_sent = True
            supplied_source_ids.update(
                function.function_id for function in new_context
            )

            for raw_resolution in object_list(response.get("entry_resolutions")):
                entry_id = str(raw_resolution.get("entry_id", ""))
                unresolved_entry = contextual_by_id.get(entry_id)
                if (
                    unresolved_entry is None
                    or unresolved_entry.status is not Verdict.UNRESOLVED
                ):
                    continue
                resolution = self._normalize_entry_resolution(
                    raw_resolution,
                    unresolved_entry,
                    allowed_functions,
                )
                local_entry_by_id[entry_id] = resolution
                local_resolutions[entry_id] = resolution
                emit_trace(
                    self.trace,
                    "small_feature",
                    "entry_resolution",
                    (
                        f"{entry_id}: {unresolved_entry.status} -> {resolution.status}; "
                        f"{resolution.rationale or 'no rationale'}"
                    ),
                    seed_entry_id=seed.entry_id,
                    entry_id=entry_id,
                    previous_status=str(unresolved_entry.status),
                    final_status=str(resolution.status),
                    resolution=as_json(resolution),
                    model_response=raw_resolution,
                )

            contextual_by_id = {
                entry_id: local_entry_by_id[entry_id]
                for entry_id in contextual_by_id
            }
            feature_contextual_by_id = {
                entry_id: entry
                for entry_id, entry in contextual_by_id.items()
                if entry.status is Verdict.VERIFIED
            }
            current: list[_Proposal] = []
            raw_features = object_list(response.get("small_features"))
            for index, raw in enumerate(raw_features):
                normalized = self._normalize_proposal(
                    raw,
                    seed=seed,
                    index=index,
                    contextual_by_id=feature_contextual_by_id,
                    allowed_functions=allowed_functions,
                    analysis_authoritative=authoritative,
                    excluded_anchors=excluded_anchors,
                )
                if normalized is not None:
                    current.append(normalized)
            scope_incomplete_proposals = [
                proposal for proposal in current
                if (
                    "concrete requested operation boundary is unresolved"
                    in proposal.feature.planning_blockers
                )
            ]
            if current:
                for proposal in current:
                    # A generic dispatcher family is an exploration result, not
                    # a semantic Small Feature. Keeping it in proposal_by_key
                    # made the session permanently incomplete even after the
                    # model later returned concrete command operations.
                    if proposal in scope_incomplete_proposals:
                        continue
                    revision_key = _proposal_revision_key(proposal)
                    previous = proposal_by_key.get(revision_key)
                    if (
                        previous is None
                        or _proposal_quality(proposal) >= _proposal_quality(previous)
                    ):
                        proposal_by_key[revision_key] = proposal

            incomplete_proposals = [
                proposal for proposal in proposal_by_key.values()
                if not proposal.feature.planning_complete
            ]
            contract_stop_enforced = bool(
                contract_stop_required
                and any(
                    proposal.feature.planning_complete
                    for proposal in proposal_by_key.values()
                )
            )

            requested_raw = string_list(response.get("requested_function_ids"))
            resolved_requests = self._resolve_function_requests(requested_raw)
            # A model occasionally names a needed function in a proposal but
            # forgets to repeat it in requested_function_ids. Preserve the
            # multi-round behavior deterministically.
            for raw in raw_features:
                implicit = self._resolve_function_requests([
                    str(raw.get("harness_anchor", "")),
                    *string_list(raw.get("required_functions")),
                    *[
                        str(action.get("function_id", ""))
                        for action in object_list(raw.get("actions"))
                    ],
                ])
                resolved_requests.extend(
                    function_id for function_id in implicit
                    if function_id not in allowed_functions
                )
            resolved_requests = unique_strings(resolved_requests)
            eligible_requests = (
                []
                if contract_stop_enforced
                else [
                    function_id for function_id in resolved_requests
                    if function_id in self.graph.bundle.functions
                    and function_id not in allowed_functions
                ]
            )
            non_frontier_requests = [
                function_id for function_id in eligible_requests
                if function_id not in frontier_by_id
            ]
            # Explicit model requests have priority over stale retained context.
            # If the prompt window is full, evict old non-essential context rather
            # than pretending the requested project function cannot be opened.
            protected_function_ids = {
                seed.entry_function_id,
                *(entry.entry_function_id for entry in contextual_entries),
            }
            for raw in raw_features:
                protected_function_ids.update(
                    self._resolve_function_requests([
                        str(raw.get("harness_anchor", "")),
                        *string_list(raw.get("required_functions")),
                        *[
                            str(action.get("function_id", ""))
                            for action in object_list(raw.get("actions"))
                        ],
                    ])
                )
            requested_capacity = min(
                len(eligible_requests),
                MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND,
            )
            evicted_function_ids: list[str] = []
            while (
                requested_capacity > max(0, self.budget - len(selected_function_ids))
                and len(selected_function_ids) > 1
            ):
                eviction = next(
                    (
                        function_id for function_id in selected_function_ids
                        if function_id not in protected_function_ids
                    ),
                    None,
                )
                if eviction is None:
                    break
                selected_function_ids.remove(eviction)
                evicted_function_ids.append(eviction)

            # A model may conservatively list every source it has seen as a
            # required/action function.  That must not permanently lock the
            # window.  Exact new requests win over old proposal references;
            # seed and contextual Entry functions remain non-evictable.
            core_function_ids = {
                seed.entry_function_id,
                *(entry.entry_function_id for entry in contextual_entries),
            }
            while (
                requested_capacity > max(0, self.budget - len(selected_function_ids))
                and len(selected_function_ids) > len(core_function_ids)
            ):
                eviction = next(
                    (
                        function_id for function_id in selected_function_ids
                        if function_id not in core_function_ids
                    ),
                    None,
                )
                if eviction is None:
                    break
                selected_function_ids.remove(eviction)
                evicted_function_ids.append(eviction)

            remaining_budget = max(0, self.budget - len(selected_function_ids))
            addition_limit = min(
                remaining_budget,
                MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND,
            )
            expansion_allowed = not final_safety_turn
            requested = (
                eligible_requests[:addition_limit]
                if expansion_allowed else []
            )
            deferred_requests = (
                eligible_requests[addition_limit:]
                if expansion_allowed else eligible_requests
            )
            rejected_requests = [
                function_id for function_id in resolved_requests
                if function_id not in self.graph.bundle.functions
            ]
            already_supplied_requests = [
                function_id for function_id in resolved_requests
                if function_id in allowed_functions
            ]
            context_complete = bool(response.get("context_complete", True))
            recoverable_failure = bool(raw_features) and not current and (
                bool(requested)
                or any(
                    str(raw.get("harness_anchor", "")) in excluded_anchors
                    for raw in raw_features
                )
            )
            planning_incomplete = bool(incomplete_proposals)
            operation_scope_incomplete = bool(scope_incomplete_proposals)
            round_incomplete_proposals = [
                *incomplete_proposals,
                *scope_incomplete_proposals,
            ]
            decision_complete = (
                contract_stop_enforced
                or (
                    context_complete
                    and not recoverable_failure
                    and not operation_scope_incomplete
                )
            )
            seed_resolution = local_entry_by_id[seed.entry_id]
            next_stalled_turns = stalled_turns + 1
            if seed_resolution.status is Verdict.REJECTED:
                stop_reason = "seed Entry was rejected during Small Feature recovery"
            elif final_safety_turn:
                stop_reason = "hard Small Feature turn safety limit reached"
            elif not remaining_budget:
                stop_reason = "context function budget exhausted"
            elif requested:
                stop_reason = "open the explicitly requested project functions"
            elif contract_stop_enforced:
                stop_reason = (
                    "bounded operation contract reached; retain completed operations "
                    "and stop descending into implementation internals"
                )
            elif operation_scope_incomplete:
                stop_reason = (
                    "retry broad dispatcher proposal and require concrete operation partitioning"
                )
            elif decision_complete:
                stop_reason = "model marked context complete"
            elif next_stalled_turns >= MAX_STALLED_SMALL_FEATURE_TURNS:
                stop_reason = "repeated unresolved response made no context progress"
            else:
                stop_reason = "retry unresolved response and require a decision or exact function request"

            # Apply requests before calling them accepted.  On the old path the
            # final round emitted accepted_requested_function_ids and then
            # broke before selected_function_ids was updated.
            opened_requests: list[str] = []
            if seed_resolution.status is not Verdict.REJECTED:
                for function_id in requested:
                    frontier_choice = frontier_by_id.get(function_id)
                    if frontier_choice is not None:
                        connections = frontier_choice.get("connections", [])
                        connection = (
                            connections[0]
                            if isinstance(connections, list) and connections
                            else {}
                        )
                        parent_id = str(connection.get(
                            "connected_function_id", seed.entry_function_id
                        ))
                        relation = str(connection.get(
                            "relation", "requested_adjacent"
                        ))
                    else:
                        parent_id = _source_reference_parent(
                            self.graph,
                            selected_function_ids,
                            function_id,
                        ) or seed.entry_function_id
                        relation = "requested_source_reference"
                    parent_depth = int(
                        discovery_by_id.get(parent_id, {}).get("depth", 0)
                    )
                    discovery_by_id[function_id] = {
                        "depth": parent_depth + 1,
                        "discovered_from": parent_id,
                        "relation": relation,
                    }
                    selected_function_ids.append(function_id)
                    opened_requests.append(function_id)
            requested = opened_requests
            emit_trace(
                self.trace,
                "small_feature",
                "round_decision",
                (
                    f"{seed.entry_id} round {round_number}: accepted {len(current)}/{len(raw_features)} "
                    f"proposals; context_complete={context_complete}; "
                    f"requests={[self.graph.get(item).name for item in requested] or ['none']}; {stop_reason}"
                ),
                entry_id=seed.entry_id,
                round=round_number,
                accepted_proposal_count=len(current),
                raw_proposal_count=len(raw_features),
                context_complete=context_complete,
                recoverable_failure=recoverable_failure,
                planning_incomplete=planning_incomplete,
                operation_scope_incomplete=operation_scope_incomplete,
                contract_stop_enforced=contract_stop_enforced,
                stalled_turns=(0 if requested else next_stalled_turns),
                planning_blockers={
                    proposal.proposal_id: proposal.feature.planning_blockers
                    for proposal in round_incomplete_proposals
                },
                requested_function_ids=requested_raw,
                accepted_requested_function_ids=requested,
                deferred_requested_function_ids=deferred_requests,
                already_supplied_requested_function_ids=already_supplied_requests,
                rejected_requested_function_ids=rejected_requests,
                non_frontier_requested_function_ids=non_frontier_requests,
                evicted_function_ids=evicted_function_ids,
                stop_reason=stop_reason,
                model_response=response,
            )
            previous_response = {
                "small_features": raw_features,
                "entry_resolutions": object_list(response.get("entry_resolutions")),
                "unrelated_entries": string_list(response.get("unrelated_entries")),
                "accepted_proposal_count": len(current),
                "planning_blockers": {
                    proposal.proposal_id: proposal.feature.planning_blockers
                    for proposal in round_incomplete_proposals
                },
                "accepted_requested_function_ids": requested,
                "deferred_requested_function_ids": deferred_requests,
                "rejected_requested_function_ids": rejected_requests,
                "evicted_function_ids": evicted_function_ids,
            }
            if seed_resolution.status is Verdict.REJECTED:
                break
            if requested:
                stalled_turns = 0
                continue
            if decision_complete or not remaining_budget or final_safety_turn:
                break
            stalled_turns = next_stalled_turns
            if stalled_turns >= MAX_STALLED_SMALL_FEATURE_TURNS:
                break

        emit_trace(
            self.trace,
            "small_feature",
            "entry_enumerated",
            f"{seed.entry_id}: accepted {len(proposal_by_key)} operation proposals; {stop_reason}",
            entry_id=seed.entry_id,
            proposal_ids=[proposal.proposal_id for proposal in proposal_by_key.values()],
            unrelated_entry_ids=[
                item for item in string_list(response.get("unrelated_entries"))
                if item in contextual_by_id
            ],
            model_response=response,
            stop_reason=stop_reason,
        )
        await close_llm_session(self.llm, session_key)
        return _DiscoveryResult(
            proposals=list(proposal_by_key.values()),
            entry_resolutions=local_resolutions,
        )

    def _normalize_entry_resolution(
        self,
        raw: dict[str, Any],
        entry: EntryRecord,
        allowed_functions: dict[str, Any],
    ) -> EntryRecord:
        try:
            status = Verdict(str(raw.get("status", "UNRESOLVED")))
        except ValueError:
            status = Verdict.UNRESOLVED

        provenance = []
        for item in object_list(raw.get("provenance_path")):
            function_id = self._resolve_allowed_function_identifier(
                str(item.get("function_id", "")), allowed_functions
            )
            if function_id is not None:
                provenance.append({
                    "function_id": function_id,
                    "relation": str(item.get("relation", "")),
                })
        evidence: list[Evidence] = []
        for item in object_list(raw.get("evidence")):
            function_id = self._resolve_allowed_function_identifier(
                str(item.get("function_id", "")), allowed_functions
            )
            function = allowed_functions.get(function_id or "")
            if function is None:
                continue
            parsed = evidence_from_dict(
                {**item, "function_id": function.function_id}, function
            )
            if parsed.file != function.file:
                continue
            if parsed.line is not None and not (
                function.start_line <= parsed.line <= function.end_line
            ):
                continue
            evidence.append(parsed)

        confidence = _number(raw.get("confidence"))
        first_acquisition = raw.get("first_acquisition_confirmed") is True
        unknowns = unique_strings(string_list(raw.get("unknowns")))
        if status is Verdict.VERIFIED and not first_acquisition:
            status = Verdict.REJECTED
            unknowns.append(
                "Small Feature recovery found that this site is not the first external data acquisition"
            )
        if status is Verdict.VERIFIED and confidence < 0.80:
            status = Verdict.UNRESOLVED
            unknowns.append(
                f"Small Feature Entry confidence {confidence:.2f} is below 0.80"
            )
        if status is Verdict.VERIFIED and not evidence:
            status = Verdict.UNRESOLVED
            unknowns.append("Small Feature Entry promotion had no valid line evidence")
        if status is Verdict.VERIFIED and (
            not provenance
            or entry.entry_function_id not in {
                item["function_id"] for item in provenance
            }
        ):
            status = Verdict.UNRESOLVED
            unknowns.append(
                "Small Feature Entry promotion provenance did not reach the Entry Function"
            )
        if status is Verdict.REJECTED and not evidence:
            status = Verdict.UNRESOLVED
            unknowns.append(
                "Small Feature Entry rejection had no affirmative line evidence"
            )
        if status is Verdict.UNRESOLVED:
            unknowns = unique_strings([*entry.unknowns, *unknowns])

        consumer_hints = unique_strings(
            function_id
            for value in string_list(raw.get("consumer_hints"))
            for function_id in [self._resolve_allowed_function_identifier(
                value, allowed_functions
            )]
            if function_id is not None
        )
        result = replace(
            entry,
            status=status,
            channel_kind=str(raw.get("channel_kind", entry.channel_kind)),
            attacker_control=str(raw.get("attacker_control", entry.attacker_control)),
            provenance_path=provenance,
            consumer_hints=consumer_hints,
            evidence=evidence if evidence else entry.evidence,
            unknowns=unique_strings(unknowns),
            verifier_confidence=confidence,
            rationale=str(raw.get("rationale", "")),
            first_acquisition_confirmed=(
                first_acquisition and status is Verdict.VERIFIED
            ),
            inspected_function_ids=unique_strings([
                *entry.inspected_function_ids,
                *allowed_functions,
            ]),
        )
        result.validate()
        return result

    def _resolve_function_requests(self, values: list[str]) -> list[str]:
        result: list[str] = []
        by_name: dict[str, list[str]] = {}
        for function in self.graph.bundle.functions.values():
            by_name.setdefault(function.name, []).append(function.function_id)
            by_name.setdefault(function.qualified_name, []).append(function.function_id)
            by_name.setdefault(function.name.casefold(), []).append(function.function_id)
            by_name.setdefault(function.qualified_name.casefold(), []).append(
                function.function_id
            )
        for value in values:
            if value in self.graph.bundle.functions:
                result.append(value)
                continue
            decorated = re.match(r"^(fn-[A-Za-z0-9]+)(?=$|::|:|\s)", value)
            if decorated and decorated.group(1) in self.graph.bundle.functions:
                result.append(decorated.group(1))
                continue
            matches = unique_strings([
                *by_name.get(value, []),
                *by_name.get(value.casefold(), []),
            ])
            if len(matches) > 1:
                # Fuzz Introspector commonly reports a product function and a
                # same-named test/fuzzer helper (for example memcached.c and
                # testapp.c both define tcp_read).  A model request by the
                # exact visible name should keep following the production
                # lifecycle when that removes the ambiguity.  Do not guess
                # when more than one product implementation remains.
                product_matches = [
                    function_id
                    for function_id in matches
                    if any(
                        not is_non_product_build_target(target)
                        for target in self.graph.get(function_id).build_targets
                    )
                ]
                if len(product_matches) == 1:
                    matches = product_matches
            if len(matches) == 1:
                result.append(matches[0])
        return unique_strings(result)

    @staticmethod
    def _resolve_allowed_function_identifier(
        value: str,
        allowed_functions: dict[str, Any],
    ) -> str | None:
        """Resolve model-facing function spellings to one opened function ID.

        Agent prompts expose both IDs and names, while human-readable debug
        references use ``fn-id::name``.  Reject ambiguous names, but do not
        invalidate an already-opened function merely because the model used
        one of those explicitly supplied spellings instead of the raw ID.
        """

        normalized = value.strip()
        if normalized in allowed_functions:
            return normalized
        decorated = re.match(r"^(fn-[A-Za-z0-9]+)(?=$|::|:|\s)", normalized)
        if decorated and decorated.group(1) in allowed_functions:
            return decorated.group(1)
        folded = normalized.casefold()
        matches = unique_strings(
            function_id
            for function_id, function in allowed_functions.items()
            if folded in {
                str(function.name).casefold(),
                str(function.qualified_name).casefold(),
            }
        )
        return matches[0] if len(matches) == 1 else None

    def _normalize_proposal(
        self,
        raw: dict[str, Any],
        *,
        seed: EntryRecord,
        index: int,
        contextual_by_id: dict[str, EntryRecord],
        allowed_functions: dict[str, Any],
        analysis_authoritative: bool,
        excluded_anchors: set[str],
    ) -> _Proposal | None:
        normalization: list[dict[str, Any]] = []
        roots = unique_strings(
            item for item in string_list(raw.get("root_entries"))
            if item in contextual_by_id
        )
        supporting = unique_strings(
            item for item in string_list(raw.get("supporting_entries"))
            if item in contextual_by_id and item not in roots
        )
        if seed.entry_id not in roots and seed.entry_id not in supporting:
            emit_trace(
                self.trace,
                "small_feature",
                "proposal_rejected",
                f"{seed.entry_id} proposal {index}: seed was not a member",
                entry_id=seed.entry_id,
                proposal_index=index,
                proposal=raw,
                reason="every operation discovered from an Entry must identify that Entry's role",
            )
            return None
        if not roots:
            emit_trace(
                self.trace,
                "small_feature",
                "proposal_rejected",
                f"{seed.entry_id} proposal {index}: no root Entry",
                entry_id=seed.entry_id,
                proposal_index=index,
                proposal=raw,
                reason="a Small Feature requires at least one root Entry",
            )
            return None

        expected_entries = unique_strings([*roots, *supporting])
        raw_entry_order = string_list(raw.get("entry_call_order"))
        proposed_entry_order = [
            entry_id for entry_id in raw_entry_order
            if entry_id in contextual_by_id
        ]
        entry_order_complete = bool(
            proposed_entry_order
            and len(proposed_entry_order) == len(raw_entry_order)
            and set(proposed_entry_order) == set(expected_entries)
        )
        entry_call_order = (
            proposed_entry_order if entry_order_complete else expected_entries
        )
        if not entry_order_complete:
            normalization.append({
                "field": "entry_call_order",
                "proposed": proposed_entry_order,
                "accepted_as_unresolved": entry_call_order,
                "reason": "Entry runtime order was missing, referenced an unknown Entry, or did not cover every member Entry",
            })

        proposed_anchor = str(raw.get("harness_anchor", seed.entry_function_id))
        resolved_anchor = self._resolve_allowed_function_identifier(
            proposed_anchor, allowed_functions
        )
        anchor = resolved_anchor or seed.entry_function_id
        if anchor in excluded_anchors:
            emit_trace(
                self.trace,
                "small_feature",
                "proposal_needs_context",
                f"{seed.entry_id} proposal {index}: previously blocked anchor was reused",
                entry_id=seed.entry_id,
                proposal_index=index,
                proposal=raw,
                anchor=proposed_anchor,
                reason="harness feedback requires a different, higher normal-flow boundary",
            )
            return None
        boundary_preserved = bool(raw.get("boundary_preserved", False))
        if resolved_anchor is None:
            boundary_preserved = False
            normalization.append({
                "field": "harness_anchor",
                "proposed": proposed_anchor,
                "accepted": anchor,
                "reason": "proposed anchor was outside supplied context",
            })

        raw_required = [
            self._resolve_allowed_function_identifier(value, allowed_functions)
            or value
            for value in string_list(raw.get("required_functions"))
        ]
        raw_actions = []
        for raw_action in object_list(raw.get("actions")):
            value = str(raw_action.get("function_id", ""))
            raw_actions.append({
                **raw_action,
                "function_id": (
                    self._resolve_allowed_function_identifier(
                        value, allowed_functions
                    )
                    or value
                ),
            })
        raw_action_function_ids = [
            str(action.get("function_id", "")) for action in raw_actions
        ]
        unresolved_function_ids = unique_strings(
            identifier
            for identifier in [*raw_required, *raw_action_function_ids]
            if identifier not in allowed_functions
        )
        function_references_complete = not unresolved_function_ids
        if unresolved_function_ids:
            normalization.append({
                "field": "function_references",
                "unresolved": unresolved_function_ids,
                "reason": (
                    "required/action functions outside the supplied context were not silently discarded"
                ),
            })
        required = [
            item for item in raw_required
            if item in allowed_functions
        ]
        if anchor not in required:
            required.insert(0, anchor)
        actions = [
            action for action in raw_actions
            if str(action.get("function_id", "")) in allowed_functions
        ]
        if not actions:
            emit_trace(
                self.trace,
                "small_feature",
                "proposal_rejected",
                f"{seed.entry_id} proposal {index}: no evidenced application action",
                entry_id=seed.entry_id,
                proposal_index=index,
                proposal=raw,
                reason="a Small Feature must execute at least one real project function",
            )
            return None
        action_functions = {
            str(action.get("function_id", "")) for action in actions
        }
        action_ids = [str(action.get("action_id", "")).strip() for action in actions]
        prior_action_ids: set[str] = set()
        invalid_action_constraints: list[str] = []
        if any(not action_id for action_id in action_ids) or len(set(action_ids)) != len(action_ids):
            invalid_action_constraints.append("action IDs are missing or duplicated")
        for action, action_id in zip(actions, action_ids):
            predecessors = string_list(action.get("allowed_after"))
            invalid = [item for item in predecessors if item not in prior_action_ids]
            if invalid:
                invalid_action_constraints.append(
                    f"action {action_id or '<missing>'} references non-prior allowed_after IDs {invalid}"
                )
            if action_id:
                prior_action_ids.add(action_id)
        action_order_complete = not invalid_action_constraints
        if anchor not in action_functions:
            normalization.append({
                "field": "actions",
                "anchor": anchor,
                "reason": (
                    "anchor invocation is not an explicit operation action; retained as an "
                    "unresolved planning fact instead of discarding the semantic feature"
                ),
            })
        entry_paths: dict[str, list[str]] = {}
        unresolved_paths: list[str] = []
        for entry_id in unique_strings([*roots, *supporting]):
            entry_function_id = contextual_by_id[entry_id].entry_function_id
            if entry_function_id not in required:
                required.append(entry_function_id)
            path = self.graph.shortest_path(
                anchor,
                entry_function_id,
                max_depth=max(self.depth + 2, 4),
            )
            if not path:
                reverse_path = self.graph.shortest_path(
                    entry_function_id,
                    anchor,
                    max_depth=max(self.depth + 2, 4),
                )
                if reverse_path:
                    boundary_preserved = False
                    unresolved_paths.append(entry_id)
                    normalization.append({
                        "field": "harness_anchor",
                        "anchor": anchor,
                        "entry_id": entry_id,
                        "reverse_path": reverse_path,
                        "reason": (
                            "proposed anchor is below the proven Entry boundary; retain the semantic "
                            "feature but block this anchor from harness planning"
                        ),
                    })
                    continue
                unresolved_paths.append(entry_id)
                normalization.append({
                    "field": "entry_path",
                    "anchor": anchor,
                    "entry_id": entry_id,
                    "analysis_authoritative": analysis_authoritative,
                    "reason": (
                        "call path is unresolved; absence is not treated as contradiction, "
                        "especially for callbacks and partial bootstrap graphs"
                    ),
                })
                continue
            entry_paths[entry_id] = path
        if (
            anchor not in action_functions
            and boundary_preserved
            and not unresolved_paths
        ):
            # harness_anchor is the real normal-flow function invoked by the
            # eventual harness. Models often list only the downstream semantic
            # handlers in actions even though the proven graph path starts at
            # this anchor. Once the anchor and every Entry path are evidenced,
            # recording that invocation is the executable first step that the
            # proposal already selected, not an invented application action.
            existing_action_ids = {
                str(action.get("action_id", "")) for action in actions
            }
            anchor_action_id = "invoke_harness_anchor"
            suffix = 2
            while anchor_action_id in existing_action_ids:
                anchor_action_id = f"invoke_harness_anchor_{suffix}"
                suffix += 1
            actions.insert(0, {
                "action_id": anchor_action_id,
                "function_id": anchor,
                "consumes": ["operation input and evidenced prerequisite state"],
                "produces": ["normal application operation dispatch"],
                "allowed_after": [],
                "success_condition": (
                    "the normal-flow anchor is invoked and reaches the evidenced Entry path"
                ),
            })
            action_functions.add(anchor)
            normalization.append({
                "field": "actions",
                "anchor": anchor,
                "reason": (
                    "inserted the proposal's graph-proven normal-flow anchor as the "
                    "explicit first harness action"
                ),
            })
        input_bindings = [
            {key: str(value) for key, value in item.items()}
            for item in object_list(raw.get("input_bindings"))
        ]
        input_bindings = [
            binding for binding in input_bindings
            if binding.get("source", "").strip() and binding.get("destination", "").strip()
        ]
        input_binding_proven = _bindings_cover_entries(
            input_bindings,
            [contextual_by_id[entry_id] for entry_id in roots],
            allowed_functions,
        )
        if not input_binding_proven:
            input_bindings = [
                {
                    "source": f"per-iteration fuzzer bytes via {contextual_by_id[entry_id].channel_kind}",
                    "destination": (
                        f"{allowed_functions[contextual_by_id[entry_id].entry_function_id].name}::"
                        f"{contextual_by_id[entry_id].source_api}"
                    ),
                    "transform": "transport adapter is unresolved and must preserve the real input boundary",
                }
                for entry_id in roots
                if contextual_by_id[entry_id].entry_function_id in allowed_functions
            ]
            normalization.append({
                "field": "input_bindings",
                "reason": (
                    "model omitted or did not substantiate a concrete binding; retained the Entry-derived transport requirement "
                    "for later context expansion/harness planning"
                ),
            })
        if not str(raw.get("completion_oracle", "")).strip():
            emit_trace(
                self.trace,
                "small_feature",
                "proposal_rejected",
                f"{seed.entry_id} proposal {index}: no completion oracle",
                entry_id=seed.entry_id,
                proposal_index=index,
                proposal=raw,
                reason="success or failure must be observable for a Small Feature",
            )
            return None
        if not boundary_preserved:
            # Small Feature discovery is semantic partitioning, not the final
            # harnessability gate.  Missing proof of a normal lifecycle anchor
            # must block later harness generation without erasing the operation
            # that was recovered from the Entry context.  A *proven* anchor
            # below the Entry boundary is still rejected above via reverse-path
            # evidence.
            normalization.append({
                "field": "boundary_preserved",
                "accepted_as_unresolved": False,
                "reason": (
                    "normal lifecycle/security boundary is not yet evidenced; "
                    "retain the semantic feature but block harness planning"
                ),
            })
        evidence: list[Evidence] = []
        for item in object_list(raw.get("evidence")):
            function_id = self._resolve_allowed_function_identifier(
                str(item.get("function_id", "")), allowed_functions
            )
            function = allowed_functions.get(function_id or "")
            if function is None:
                continue
            parsed = evidence_from_dict(
                {**item, "function_id": function.function_id}, function
            )
            if parsed.file != function.file:
                continue
            if parsed.line is not None and not (
                function.start_line <= parsed.line <= function.end_line
            ):
                continue
            evidence.append(parsed)
        if not evidence:
            evidence = list(seed.evidence)
            normalization.append({
                "field": "evidence",
                "reason": "no valid proposal evidence remained; inherited seed evidence",
            })

        action_signature = [str(action.get("function_id", "")) for action in actions]
        proposed_build_target = str(raw.get("build_target", "default")).strip()
        target_candidates = prefer_product_build_targets(
            target
            for function_id in [anchor, *required]
            for target in allowed_functions[function_id].build_targets
            if function_id in allowed_functions
        )
        product_targets = [
            target for target in target_candidates if not is_non_product_build_target(target)
        ]
        if (
            proposed_build_target in target_candidates
            and not (product_targets and is_non_product_build_target(proposed_build_target))
        ):
            build_target = proposed_build_target
        elif target_candidates:
            build_target = target_candidates[0]
        else:
            build_target = "UNRESOLVED"
        if build_target != proposed_build_target:
            normalization.append({
                "field": "build_target",
                "proposed": proposed_build_target,
                "accepted": build_target,
                "reason": "selected from project build metadata with product targets preferred",
            })
        proposal_id = stable_id(
            "sfp",
            seed.entry_id,
            index,
            *sorted(unique_strings([*roots, *supporting])),
            anchor,
            json.dumps(action_signature),
            str(raw.get("completion_oracle", "")),
        )
        entry_paths_complete = not unresolved_paths
        anchor_action_complete = anchor in action_functions
        operation_scope_blockers = _operation_scope_blockers(raw)
        planning_blockers = unique_strings([
            *operation_scope_blockers,
            *(
                ["normal lifecycle/security boundary preservation is unresolved"]
                if not boundary_preserved else []
            ),
            *(
                ["per-iteration fuzzer bytes are not concretely bound to every root Entry"]
                if not input_binding_proven else []
            ),
            *[
                f"call path from harness anchor to Entry {entry_id} is unresolved"
                for entry_id in unresolved_paths
            ],
            *(
                ["harness anchor invocation is not present in the recovered action list"]
                if not anchor_action_complete else []
            ),
            *invalid_action_constraints,
            *(
                [f"required/action function references are unresolved: {unresolved_function_ids}"]
                if not function_references_complete else []
            ),
            *(
                ["runtime Entry call order is unresolved"]
                if not entry_order_complete else []
            ),
        ])
        planning_complete = bool(
            boundary_preserved
            and input_binding_proven
            and entry_paths_complete
            and anchor_action_complete
            and action_order_complete
            and function_references_complete
            and entry_order_complete
            and not operation_scope_blockers
        )
        unknowns = unique_strings([
            *string_list(raw.get("unknowns")),
            *planning_blockers,
        ])
        isolation_mode = str(raw.get("isolation_mode", "in_process_reset"))
        if isolation_mode not in {
            "in_process_reset", "fork_per_input", "subprocess", "loopback_network"
        }:
            isolation_mode = "in_process_reset"
        feature = SmallFeatureSpec(
            small_feature_id=proposal_id,
            name=str(raw.get("name", f"feature around {allowed_functions[anchor].name}")),
            description=str(raw.get("description", "")),
            root_entries=roots,
            supporting_entries=supporting,
            harness_anchor=anchor,
            anchor_rationale=str(raw.get("anchor_rationale", "")),
            boundary_preserved=boundary_preserved,
            preconditions=unique_strings(string_list(raw.get("preconditions"))),
            initialization=unique_strings(string_list(raw.get("initialization"))),
            required_functions=unique_strings(required),
            actions=actions,
            input_bindings=input_bindings,
            cleanup_success=unique_strings(string_list(raw.get("cleanup_success"))),
            cleanup_failure=unique_strings(string_list(raw.get("cleanup_failure"))),
            stable_post_state=str(raw.get("stable_post_state", "unknown")),
            completion_oracle=str(raw.get("completion_oracle", "operation returns")),
            evidence=evidence,
            unknowns=unknowns,
            confidence=_number(raw.get("confidence")),
            channel_kind=_feature_channel_kind(
                [contextual_by_id[entry_id] for entry_id in roots]
            ),
            build_target=build_target,
            isolation_mode=isolation_mode,
            input_binding_proven=input_binding_proven,
            entry_paths_complete=entry_paths_complete,
            anchor_action_complete=anchor_action_complete,
            action_order_complete=action_order_complete,
            function_references_complete=function_references_complete,
            entry_call_order=entry_call_order,
            entry_order_complete=entry_order_complete,
            planning_complete=planning_complete,
            planning_blockers=planning_blockers,
        )
        emit_trace(
            self.trace,
            "small_feature",
            "model_proposal",
            (
                f"{seed.entry_id}: proposal {proposal_id} '{feature.name}' "
                f"roots={roots}, supporting={supporting}"
            ),
            entry_id=seed.entry_id,
            proposal_id=proposal_id,
            feature=as_json(feature),
            normalization=normalization,
            entry_paths=entry_paths,
        )
        return _Proposal(proposal_id, seed.entry_id, feature)

    async def _reconcile_component(
        self,
        component: list[_Proposal],
    ) -> list[list[_Proposal]]:
        if len(component) == 1:
            return [component]
        by_id = {proposal.proposal_id: proposal for proposal in component}
        response = await self.llm.complete_json(
            role="small_feature",
            instructions=(
                "Reconcile operation proposals produced from different Entry contexts. Group proposals only when they "
                "describe the same requested operation with the same material lifecycle and prerequisite state. Shared "
                "Entry IDs, shared anchors, or similar names alone are not sufficient: one Entry may feed multiple distinct "
                "commands. Keep different requested commands or operations separate, but merge success, rejection, resource-"
                "failure, and error-path proposals when they are outcomes of the same request. "
                "A proposal that stops at a low-level read helper and another that extends the same request through its "
                "state machine, event callback, parser, or normal caller are partial and complete views of ONE operation, "
                "not separate operations. Likewise, UNRESOLVED versus concrete build_target and a progressively higher "
                "normal harness anchor are evidence refinements, not operation boundaries. Prefer the most complete normal "
                "lifecycle as canonical. Each proposal ID must occur in exactly one group. Choose the best-evidenced proposal as "
                "canonical_proposal_id for each group."
            ),
            payload={
                "proposals": [_reconciliation_payload(proposal) for proposal in component]
            },
            output_schema=SMALL_FEATURE_RECONCILIATION_SCHEMA,
        )
        assigned: set[str] = set()
        groups: list[list[_Proposal]] = []
        decisions: list[dict[str, Any]] = []
        for raw in object_list(response.get("operation_groups")):
            ids = unique_strings(
                item for item in string_list(raw.get("proposal_ids"))
                if item in by_id and item not in assigned
            )
            if not ids:
                continue
            requested_canonical = str(raw.get("canonical_proposal_id", ""))
            for partition_ids in _compatible_reconciliation_partitions(
                ids,
                by_id,
                requested_canonical,
            ):
                canonical_id = (
                    requested_canonical
                    if requested_canonical in partition_ids
                    else max(partition_ids, key=lambda item: _proposal_quality(by_id[item]))
                )
                partition_ids.remove(canonical_id)
                partition_ids.insert(0, canonical_id)
                group = [by_id[item] for item in partition_ids]
                groups.append(group)
                assigned.update(partition_ids)
                decisions.append({
                    "canonical_proposal_id": canonical_id,
                    "proposal_ids": partition_ids,
                    "hard_compatibility": {
                        "build_targets": unique_strings(
                            by_id[item].feature.build_target for item in partition_ids
                        ),
                        "isolation_mode": by_id[canonical_id].feature.isolation_mode,
                    },
                    "reason": str(raw.get("reason", "")),
                })
        for proposal in component:
            if proposal.proposal_id not in assigned:
                groups.append([proposal])
                decisions.append({
                    "canonical_proposal_id": proposal.proposal_id,
                    "proposal_ids": [proposal.proposal_id],
                    "reason": "model left proposal unassigned; preserved as a distinct operation",
                })
        model_group_count = len(groups)
        groups = _coalesce_reconciliation_groups(groups)
        emit_trace(
            self.trace,
            "small_feature",
            "proposals_reconciled",
            f"reconciled component of {len(component)} proposals into {len(groups)} operations",
            proposal_ids=list(by_id),
            decisions=decisions,
            model_group_count=model_group_count,
            final_group_count=len(groups),
            final_groups=[
                [proposal.proposal_id for proposal in group]
                for group in groups
            ],
            model_response=response,
        )
        return groups

    def _merge_group(
        self,
        group: list[_Proposal],
        entry_by_id: dict[str, EntryRecord],
    ) -> SmallFeatureSpec:
        group = sorted(group, key=_proposal_quality, reverse=True)
        members = [proposal.feature for proposal in group]
        # _reconcile_component places the strong model's selected canonical
        # proposal first. Keep that semantic choice, then conservatively merge
        # lifecycle facts learned from the other Entry-context views.
        canonical = members[0]
        roots = unique_strings(
            entry_id for feature in members for entry_id in feature.root_entries
        )
        supporting = unique_strings(
            entry_id
            for feature in members
            for entry_id in feature.supporting_entries
            if entry_id not in roots
        )
        # The executable plan belongs to the quality-ranked canonical view.
        # Unioning historical required-function lists leaked parser siblings
        # from stale broad proposals into an otherwise precise operation.
        # Supplemental views still contribute evidence and lifecycle facts,
        # but they cannot expand the final call plan.
        required = unique_strings(canonical.required_functions)
        evidence = _unique_evidence(
            item for feature in members for item in feature.evidence
        )
        input_bindings = _unique_bindings(
            binding
            for feature in members
            if feature.input_binding_proven
            for binding in feature.input_bindings
        )
        if not input_bindings:
            input_bindings = list(canonical.input_bindings)
        actions = list(canonical.actions)
        # Members are alternate views/refinements of one operation.  A stale,
        # partial view must not poison a later complete view with an ``all()``
        # merge.  The best-evidenced canonical member controls readiness while
        # evidence and lifecycle facts are still accumulated from every view.
        planning_blockers = list(canonical.planning_blockers)
        input_binding_proven = canonical.input_binding_proven
        entry_paths_complete = canonical.entry_paths_complete
        anchor_action_complete = canonical.anchor_action_complete
        action_order_complete = canonical.action_order_complete
        function_references_complete = canonical.function_references_complete
        entry_call_order = [*canonical.entry_call_order]
        for entry_id in [*roots, *supporting]:
            if entry_id not in entry_call_order:
                entry_call_order.append(entry_id)
        entry_order_complete = bool(
            canonical.entry_order_complete
            and set(entry_call_order) == set([*roots, *supporting])
        )
        if not entry_order_complete:
            planning_blockers = unique_strings([
                *planning_blockers,
                "reconciled proposals disagree on runtime Entry call order",
            ])
        unknowns = unique_strings([
            *canonical.unknowns,
            *planning_blockers,
        ])
        planning_complete = bool(
            canonical.boundary_preserved
            and input_binding_proven
            and entry_paths_complete
            and anchor_action_complete
            and action_order_complete
            and function_references_complete
            and entry_order_complete
        )
        operation_signature = {
            "actions": actions,
            "completion_oracle": " ".join(
                canonical.completion_oracle.casefold().split()
            ),
            "stable_post_state": " ".join(
                canonical.stable_post_state.casefold().split()
            ),
            "input_bindings": input_bindings,
            "entry_call_order": entry_call_order,
        }
        identifier = stable_id(
            "sf",
            canonical.harness_anchor,
            *sorted(unique_strings([*roots, *supporting])),
            json.dumps(operation_signature, sort_keys=True),
        )
        feature = replace(
            canonical,
            small_feature_id=identifier,
            root_entries=roots,
            supporting_entries=supporting,
            preconditions=_merge_resolved_lifecycle_facts(
                canonical.preconditions,
                (item for feature in members[1:] for item in feature.preconditions),
            ),
            initialization=_merge_resolved_lifecycle_facts(
                canonical.initialization,
                (item for feature in members[1:] for item in feature.initialization),
            ),
            required_functions=required,
            actions=actions,
            evidence=evidence,
            unknowns=unknowns,
            input_bindings=input_bindings,
            cleanup_success=_merge_resolved_lifecycle_facts(
                canonical.cleanup_success,
                (item for feature in members[1:] for item in feature.cleanup_success),
            ),
            cleanup_failure=_merge_resolved_lifecycle_facts(
                canonical.cleanup_failure,
                (item for feature in members[1:] for item in feature.cleanup_failure),
            ),
            confidence=max(member.confidence for member in members),
            build_target=_best_build_target(members, canonical.build_target),
            channel_kind=_feature_channel_kind(
                [entry_by_id[entry_id] for entry_id in roots if entry_id in entry_by_id]
            ),
            input_binding_proven=input_binding_proven,
            entry_paths_complete=entry_paths_complete,
            anchor_action_complete=anchor_action_complete,
            action_order_complete=action_order_complete,
            function_references_complete=function_references_complete,
            entry_call_order=entry_call_order,
            entry_order_complete=entry_order_complete,
            planning_complete=planning_complete,
            planning_blockers=planning_blockers,
        )
        emit_trace(
            self.trace,
            "small_feature",
            "feature_created",
            (
                f"created {feature.small_feature_id} '{feature.name}' from "
                f"{len(group)} reconciled proposals"
            ),
            proposal_ids=[proposal.proposal_id for proposal in group],
            seed_entry_ids=unique_strings(proposal.seed_entry_id for proposal in group),
            feature=as_json(feature),
        )
        return feature


def _proposal_components(proposals: list[_Proposal]) -> list[list[_Proposal]]:
    parents = list(range(len(proposals)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(proposals)):
        for right in range(left + 1, len(proposals)):
            if _may_describe_same_operation(proposals[left], proposals[right]):
                union(left, right)
    components: dict[int, list[_Proposal]] = {}
    for index, proposal in enumerate(proposals):
        components.setdefault(find(index), []).append(proposal)
    return list(components.values())


def _proposal_quality(proposal: _Proposal) -> tuple[Any, ...]:
    feature = proposal.feature
    invariant_score = sum((
        feature.boundary_preserved,
        feature.input_binding_proven,
        feature.entry_paths_complete,
        feature.anchor_action_complete,
        feature.action_order_complete,
        feature.function_references_complete,
        feature.entry_order_complete,
    ))
    return (
        feature.planning_complete,
        invariant_score,
        not _unresolved_build_target(feature.build_target),
        feature.confidence,
        len(feature.actions),
        len(feature.evidence),
        len(feature.required_functions),
    )


def _unresolved_build_target(value: str) -> bool:
    return value.strip().casefold() in {"", "default", "unknown", "unresolved"}


def _build_targets_compatible(left: str, right: str) -> bool:
    return (
        _unresolved_build_target(left)
        or _unresolved_build_target(right)
        or left == right
    )


def _compatible_reconciliation_partitions(
    proposal_ids: list[str],
    by_id: dict[str, _Proposal],
    requested_canonical: str,
) -> list[list[str]]:
    """Split only genuinely incompatible build/isolation plans.

    An unresolved build target is incomplete evidence, not a different
    operation.  The previous exact tuple partition duplicated every operation
    once as ``UNRESOLVED`` and again as its later discovered product target.
    """

    # A strong-model reconciliation decision cannot merge distinct requested
    # commands. Earlier, all proposals sharing one recvfrom Entry formed one
    # component and the model occasionally grouped VERSION with FLUSH, leaking
    # FLUSH state into the VERSION feature. Command/mode/variant identity is a
    # hard semantic boundary; lifecycle refinements of the same command keep
    # the same discriminator set and still reconcile normally.
    by_operation: dict[tuple[str, ...], list[str]] = {}
    for proposal_id in proposal_ids:
        discriminators = tuple(sorted(
            value
            for value in _operation_discriminators(by_id[proposal_id].feature)
            if value.startswith(("command:", "mode:", "variant:"))
        ))
        by_operation.setdefault(
            discriminators or ("operation:undiscriminated",),
            [],
        ).append(proposal_id)

    partitions: list[list[str]] = []
    for operation_ids in by_operation.values():
        by_isolation: dict[str, list[str]] = {}
        for proposal_id in operation_ids:
            by_isolation.setdefault(
                by_id[proposal_id].feature.isolation_mode,
                [],
            ).append(proposal_id)
        for isolation_ids in by_isolation.values():
            concrete_targets = unique_strings(
                by_id[proposal_id].feature.build_target
                for proposal_id in isolation_ids
                if not _unresolved_build_target(
                    by_id[proposal_id].feature.build_target
                )
            )
            if len(concrete_targets) <= 1:
                partitions.append(list(isolation_ids))
                continue

            unresolved = [
                proposal_id for proposal_id in isolation_ids
                if _unresolved_build_target(by_id[proposal_id].feature.build_target)
            ]
            target_groups = {
                target: [
                    proposal_id for proposal_id in isolation_ids
                    if by_id[proposal_id].feature.build_target == target
                ]
                for target in concrete_targets
            }
            canonical_target = (
                by_id[requested_canonical].feature.build_target
                if requested_canonical in by_id
                else ""
            )
            attachment_target = (
                canonical_target
                if canonical_target in target_groups
                else concrete_targets[0]
            )
            target_groups[attachment_target].extend(unresolved)
            partitions.extend(target_groups.values())
    return partitions


def _coalesce_reconciliation_groups(
    groups: list[list[_Proposal]],
) -> list[list[_Proposal]]:
    """Merge stale/partial views that the model split by analysis depth.

    Different requested operations remain separate.  We only coalesce exact
    semantic names or strict action-slice refinements for the same Entry set.
    The latter turns ``read helper``, ``state-machine read`` and ``event read``
    snapshots into one lifecycle instead of one Small Feature per opened caller.
    """

    result: list[list[_Proposal]] = []
    for group in groups:
        merged = False
        for existing in result:
            if any(
                _same_operation_refinement(left, right)
                for left in existing
                for right in group
            ):
                existing.extend(group)
                existing.sort(key=_proposal_quality, reverse=True)
                merged = True
                break
        if not merged:
            result.append(sorted(group, key=_proposal_quality, reverse=True))

    # A merge can bridge two groups that were compared before the bridge was
    # visible.  Collapse to a fixed point; proposal counts are small here.
    changed = True
    while changed:
        changed = False
        for left_index in range(len(result)):
            for right_index in range(left_index + 1, len(result)):
                if any(
                    _same_operation_refinement(left, right)
                    for left in result[left_index]
                    for right in result[right_index]
                ):
                    result[left_index].extend(result.pop(right_index))
                    result[left_index].sort(key=_proposal_quality, reverse=True)
                    changed = True
                    break
            if changed:
                break
    return result


def _same_operation_refinement(left: _Proposal, right: _Proposal) -> bool:
    first = left.feature
    second = right.feature
    if first.isolation_mode != second.isolation_mode:
        return False
    if not _build_targets_compatible(first.build_target, second.build_target):
        return False
    first_entries = set([*first.root_entries, *first.supporting_entries])
    second_entries = set([*second.root_entries, *second.supporting_entries])
    if first_entries != second_entries:
        return False

    first_name = " ".join(first.name.casefold().split())
    second_name = " ".join(second.name.casefold().split())
    if first_name and first_name == second_name:
        return True

    first_actions = {
        str(action.get("function_id", ""))
        for action in first.actions
        if str(action.get("function_id", ""))
    }
    second_actions = {
        str(action.get("function_id", ""))
        for action in second.actions
        if str(action.get("function_id", ""))
    }
    strict_refinement = bool(
        first_actions and second_actions
        and (first_actions < second_actions or second_actions < first_actions)
    )
    if not strict_refinement:
        return False

    first_discriminators = _operation_discriminators(first)
    second_discriminators = _operation_discriminators(second)
    for prefix in ("literal:", "command:", "mode:"):
        first_kind = {
            item for item in first_discriminators if item.startswith(prefix)
        }
        second_kind = {
            item for item in second_discriminators if item.startswith(prefix)
        }
        if bool(first_kind) != bool(second_kind):
            return False
        if first_kind and second_kind and first_kind.isdisjoint(second_kind):
            return False
    return True


def _operation_discriminators(feature: SmallFeatureSpec) -> set[str]:
    text = " ".join((
        feature.name,
        feature.description,
        feature.completion_oracle,
        feature.stable_post_state,
    ))
    values = {
        "literal:" + value.casefold().strip()
        for quoted, backticked in re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`]+)`', text)
        for value in (quoted or backticked,)
        if value.strip()
    }
    command_words = {
        "command:" + token
        for token in re.findall(
            r"\b(?:getk?|gatk?|set|add|replace|delete|touch|incr(?:ement)?|"
            r"decr(?:ement)?|append|prepend|flush|noop|quit|version|stat(?:s)?|"
            r"sasl|mg|md|ms|ma|metadump|mgdump)\b",
            text.casefold(),
        )
    }
    mode_words = {
        "mode:" + token
        for token in re.findall(
            r"\b(?:ascii|binary|validate|validation|normal|reload|hup)\b",
            feature.name.casefold(),
        )
    }
    variant_words = {
        "variant:" + token
        for token in re.findall(
            r"\b(?:reset|settings|detail|dump|named|list|mechanisms?|"
            r"authenticate|authentication|step|all)\b",
            feature.name.casefold(),
        )
    }
    return values | command_words | mode_words | variant_words


def _operation_scope_blockers(raw: dict[str, Any]) -> list[str]:
    """Reject a transport/dispatcher family masquerading as one operation."""

    for unknown in string_list(raw.get("unknowns")):
        normalized = " ".join(unknown.casefold().split())
        branch_family = re.search(
            r"(?:command[- ]specific|individual (?:command|operation)|"
            r"(?:command|operation|protocol) dispatcher|"
            r"downstream (?:command|operation)|parser family)",
            normalized,
        )
        material_effect = re.search(
            r"(?:state|response|result|success|failure|cleanup|prerequisite|lifecycle)",
            normalized,
        )
        unresolved = re.search(
            r"(?:unresolved|unknown|not (?:opened|supplied|shown|evidenced)|"
            r"further affect|can (?:further )?(?:affect|change)|below .+ affect)",
            normalized,
        )
        if branch_family and material_effect and unresolved:
            return [
                "concrete requested operation boundary is unresolved; a dispatcher family with materially different handlers cannot be one Small Feature"
            ]
    return []


def _is_generic_dispatcher_family(feature: SmallFeatureSpec) -> bool:
    """Return whether a semantic context wrapper is not one requested job."""

    if any(
        value.startswith("command:")
        for value in _operation_discriminators(feature)
    ):
        return False
    name = " ".join(feature.name.casefold().split())
    return bool(
        re.search(r"\b(?:dispatch|dispatcher|parser|protocol selection)\b", name)
        and re.search(
            r"\b(?:command|request|protocol|ascii|binary|datagram|socket|event)\b",
            name,
        )
    )


def _best_build_target(
    members: list[SmallFeatureSpec],
    fallback: str,
) -> str:
    concrete = unique_strings(
        feature.build_target for feature in members
        if not _unresolved_build_target(feature.build_target)
    )
    return concrete[0] if concrete else fallback


def _merge_resolved_lifecycle_facts(
    canonical: list[str],
    supplemental: Any,
) -> list[str]:
    uncertainty_markers = (
        "unresolved",
        "unknown",
        "not supplied",
        "not evidenced",
        "missing",
        "todo",
    )
    return unique_strings([
        *canonical,
        *(
            item for item in supplemental
            if not any(marker in item.casefold() for marker in uncertainty_markers)
        ),
    ])


def _proposal_revision_key(proposal: _Proposal) -> str:
    """Identify one requested operation across successive context refinements.

    Anchors, action slices, names, and completion wording legitimately improve
    while source is opened. Command/mode/variant discriminators keep distinct
    operations separate without retaining every stale partial revision.
    """

    feature = proposal.feature
    discriminators = sorted(_operation_discriminators(feature))
    semantic_operation = (
        json.dumps(discriminators, sort_keys=True)
        if discriminators
        else " ".join(feature.name.casefold().split())
    )
    return stable_id(
        "sf-revision",
        proposal.seed_entry_id,
        semantic_operation,
        *sorted(unique_strings([*feature.root_entries, *feature.supporting_entries])),
        feature.isolation_mode,
    )


def _may_describe_same_operation(left: _Proposal, right: _Proposal) -> bool:
    first = left.feature
    second = right.feature
    first_entries = set(first.root_entries) | set(first.supporting_entries)
    second_entries = set(second.root_entries) | set(second.supporting_entries)
    if first_entries & second_entries:
        return True
    if first.harness_anchor == second.harness_anchor:
        return True
    first_actions = tuple(str(item.get("function_id", "")) for item in first.actions)
    second_actions = tuple(str(item.get("function_id", "")) for item in second.actions)
    if first_actions and first_actions == second_actions:
        return True
    first_required = set(first.required_functions)
    second_required = set(second.required_functions)
    smaller = min(len(first_required), len(second_required))
    return bool(smaller and len(first_required & second_required) / smaller >= 0.6)


def _reconciliation_payload(proposal: _Proposal) -> dict[str, Any]:
    feature = proposal.feature
    return {
        "proposal_id": proposal.proposal_id,
        "seed_entry_id": proposal.seed_entry_id,
        "name": feature.name,
        "description": feature.description,
        "root_entries": feature.root_entries,
        "supporting_entries": feature.supporting_entries,
        "entry_call_order": feature.entry_call_order,
        "harness_anchor": feature.harness_anchor,
        "preconditions": feature.preconditions,
        "initialization": feature.initialization,
        "actions": feature.actions,
        "completion_oracle": feature.completion_oracle,
        "stable_post_state": feature.stable_post_state,
        "required_functions": feature.required_functions,
        "channel_kind": feature.channel_kind,
        "build_target": feature.build_target,
        "isolation_mode": feature.isolation_mode,
        "confidence": feature.confidence,
        "function_references_complete": feature.function_references_complete,
    }


def _entry_payload(entry: EntryRecord) -> dict[str, Any]:
    return {
        "entry_id": entry.entry_id,
        "status": str(entry.status),
        "entry_function_id": entry.entry_function_id,
        "entry_line": entry.entry_line,
        "source_api": entry.source_api,
        "channel_kind": entry.channel_kind,
        "attacker_control": entry.attacker_control,
        "provenance_path": entry.provenance_path,
        "consumer_hints": entry.consumer_hints,
        "unknowns": entry.unknowns,
        "first_acquisition_confirmed": entry.first_acquisition_confirmed,
        "verifier_confidence": entry.verifier_confidence,
        "inspected_function_ids": entry.inspected_function_ids,
        "verification_rounds": entry.verification_rounds,
    }


def _feature_channel_kind(entries: list[EntryRecord]) -> str:
    families = unique_strings(_channel_family(entry.channel_kind) for entry in entries)
    if not families:
        return "unknown"
    if len(families) == 1:
        return families[0]
    return "multi:" + ",".join(sorted(families))


def _channel_family(channel: str) -> str:
    value = channel.casefold().replace("-", "_")
    if any(token in value for token in ("tls", "network", "socket", "recv", "accept")):
        return "network"
    if any(token in value for token in ("file", "filesystem", "path", "directory")):
        return "file"
    if "stdin" in value or "terminal" in value:
        return "stdin"
    if "argv" in value or "command_line" in value:
        return "argv"
    if "environment" in value or "getenv" in value:
        return "environment"
    if any(token in value for token in ("ipc", "rpc", "message_queue", "pipe")):
        return "ipc"
    if any(token in value for token in ("device", "ioctl")):
        return "device"
    if "callback" in value:
        return "callback"
    return value or "unknown"


def _source_reference_parent(
    graph: GraphStore,
    selected_function_ids: list[str],
    requested_function_id: str,
) -> str | None:
    """Find the opened function that names a non-callgraph dependency.

    Fuzz Introspector call edges cannot represent every callback assignment,
    state-table registration, or function-pointer target.  A model may request
    such a project function by its exact ID or unique name.  Preserve the most
    useful walk provenance by attaching it to an opened source body that names
    the target; fall back to the seed when no lexical reference is available.
    """

    requested = graph.bundle.functions.get(requested_function_id)
    if requested is None or not requested.name:
        return None
    pattern = re.compile(rf"\b{re.escape(requested.name)}\b")
    for function_id in reversed(selected_function_ids):
        function = graph.bundle.functions.get(function_id)
        if function is not None and pattern.search(function.source):
            return function_id
    return None


def _bindings_cover_entries(
    bindings: list[dict[str, str]],
    entries: list[EntryRecord],
    allowed_functions: dict[str, Any],
) -> bool:
    """Require an explicit per-iteration source and a destination for every root Entry.

    This is deliberately a planning check, not proof that generated C/C++ is correct.
    The static harness gate checks the resulting code again.  Its purpose here is to
    prevent an invented placeholder binding from becoming a harnessable feature.
    """

    usable: list[str] = []
    verified_entry_ids = {
        entry.entry_id.casefold() for entry in entries
    }
    negative_flow_phrases = (
        "not read",
        "never read",
        "not used",
        "never used",
        "not consumed",
        "does not consume",
        "do not consume",
        "does not influence",
        "do not influence",
        "does not show",
        "do not show",
        "no evidenced branch",
        "not evidenced",
    )
    for binding in bindings:
        source = binding.get("source", "").casefold()
        destination = binding.get("destination", "").casefold()
        transform = binding.get("transform", "").casefold()
        if not source.strip() or not destination.strip() or not transform.strip():
            continue
        binding_text = f"{source} {destination} {transform}"
        explicitly_names_entry = any(
            entry_id and entry_id in source
            for entry_id in verified_entry_ids
        )
        if (
            not explicitly_names_entry
            and not any(
                token in binding_text
                for token in ("fuzz", "input", "data", "per-iteration")
            )
        ):
            continue
        if any(token in transform for token in ("unresolved", "unknown", "todo", "placeholder")):
            continue
        if any(phrase in binding_text for phrase in negative_flow_phrases):
            continue
        usable.append(f"{destination} {transform}")
    if not usable or not entries:
        return False

    family_tokens = {
        "network": ("network", "socket", "packet", "tls", "ssl", "recv", "accept"),
        "file": ("file", "path", "filesystem", "read"),
        "stdin": ("stdin", "pipe", "stream", "read"),
        "argv": ("argv", "argument", "command line"),
        "environment": ("environment", "env", "getenv"),
        "ipc": ("ipc", "rpc", "pipe", "queue", "message"),
        "device": ("device", "ioctl"),
        "callback": ("callback", "event"),
    }
    for entry in entries:
        function = allowed_functions.get(entry.entry_function_id)
        if not _entry_value_is_consumed(entry, function):
            return False
        markers = {
            entry.source_api.casefold(),
            _channel_family(entry.channel_kind),
        }
        if function is not None:
            markers.update((function.name.casefold(), function.qualified_name.casefold()))
        family = _channel_family(entry.channel_kind)
        markers.update(family_tokens.get(family, (family,)))
        markers.discard("")
        if not any(any(marker in text for marker in markers) for text in usable):
            return False
    return True


def _entry_value_is_consumed(entry: EntryRecord, function: Any | None) -> bool:
    """Reject acquisition-only process parameters that never affect the operation.

    ``main(argc, argv)`` is a legitimate first-acquisition Entry even when a
    utility ignores both parameters.  That does not make the utility a useful
    fuzz operation: copying bytes into an unused argv vector cannot increase
    application coverage.  Keep the Entry, but prevent a Small Feature from
    becoming harness-ready until the acquired process-start data is read by the
    real function body.
    """

    process_start = entry.site_kind is EntrySiteKind.PROCESS_START
    channel = entry.channel_kind.casefold()
    source_api = entry.source_api.casefold()
    if not process_start and "argv" not in channel and "argv" not in source_api:
        return True
    if function is None:
        return False

    source = str(getattr(function, "source", ""))
    opening = source.find("{")
    if opening < 0:
        return False
    body = _strip_c_comments_and_literals(source[opening + 1:])

    candidate_names = {"argc", "argv", "envp"}
    signature = str(getattr(function, "signature", ""))
    parameter_text = signature
    if "(" in signature and ")" in signature:
        parameter_text = signature.split("(", 1)[1].rsplit(")", 1)[0]
    for index, parameter in enumerate(parameter_text.split(",")):
        identifiers = re.findall(r"[A-Za-z_]\w*", parameter)
        if not identifiers:
            continue
        name = identifiers[-1]
        lowered = parameter.casefold()
        if (
            (
                process_start
                and index < 3
                and name not in {
                    "void", "int", "char", "const", "unsigned", "signed",
                }
            )
            or
            name in candidate_names
            or "char" in lowered and "*" in parameter
            or "int" in lowered and name.casefold().startswith("arg")
        ):
            candidate_names.add(name)
    return any(
        re.search(rf"\b{re.escape(name)}\b", body)
        for name in candidate_names
    )


def _strip_c_comments_and_literals(source: str) -> str:
    pattern = re.compile(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        re.DOTALL,
    )
    return pattern.sub(
        lambda match: "".join("\n" if char == "\n" else " " for char in match.group(0)),
        source,
    )


def _unique_bindings(items: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        normalized = {
            "source": str(item.get("source", "")),
            "destination": str(item.get("destination", "")),
            "transform": str(item.get("transform", "")),
        }
        key = (
            normalized["source"], normalized["destination"], normalized["transform"]
        )
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def _entry_orders_compatible(orders: list[list[str]]) -> bool:
    nonempty = [order for order in orders if order]
    for left_index, left in enumerate(nonempty):
        for right in nonempty[left_index + 1:]:
            # Different context views may omit an occurrence, but they must not
            # reverse the observed sequence. This also permits A,B,A lifecycles,
            # which a simple pairwise precedence set incorrectly treats as a
            # cycle even though the repeated Entry invocation is intentional.
            if not (_is_subsequence(left, right) or _is_subsequence(right, left)):
                return False
    return True


def _is_subsequence(candidate: list[str], sequence: list[str]) -> bool:
    iterator = iter(sequence)
    return all(any(item == expected for item in iterator) for expected in candidate)


def _unique_evidence(items: Any) -> list[Evidence]:
    result: list[Evidence] = []
    seen: set[tuple[Any, ...]] = set()
    for item in items:
        key = (item.kind, item.function_id, item.file, item.line, item.detail)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _merge_entry_resolution_claims(
    original: EntryRecord,
    claims: list[EntryRecord],
) -> tuple[EntryRecord, str]:
    if not claims:
        return (
            replace(
                original,
                unknowns=unique_strings([
                    *original.unknowns,
                    "Entry remained unresolved through all Small Feature context rounds",
                ]),
            ),
            "small_feature_context_exhausted",
        )

    inspected = unique_strings([
        *original.inspected_function_ids,
        *(
            function_id
            for claim in claims
            for function_id in claim.inspected_function_ids
        ),
    ])
    rounds = max([
        original.verification_rounds,
        *(claim.verification_rounds for claim in claims),
    ])
    definite_statuses = {
        claim.status for claim in claims
        if claim.status in {Verdict.VERIFIED, Verdict.REJECTED}
    }
    if definite_statuses == {Verdict.VERIFIED, Verdict.REJECTED}:
        best = max(claims, key=lambda item: item.verifier_confidence)
        return (
            replace(
                best,
                status=Verdict.UNRESOLVED,
                first_acquisition_confirmed=False,
                inspected_function_ids=inspected,
                verification_rounds=rounds,
                unknowns=unique_strings([
                    *best.unknowns,
                    "Conflicting VERIFIED and REJECTED judgments were produced during Small Feature recovery",
                ]),
                rationale="conflicting Entry resolutions across Small Feature contexts",
            ),
            "conflicting_small_feature_entry_resolutions",
        )

    verified = [claim for claim in claims if claim.status is Verdict.VERIFIED]
    if verified:
        best = max(verified, key=lambda item: item.verifier_confidence)
        return (
            replace(
                best,
                inspected_function_ids=inspected,
                verification_rounds=rounds,
            ),
            "promoted",
        )

    rejected = [claim for claim in claims if claim.status is Verdict.REJECTED]
    if rejected:
        best = max(rejected, key=lambda item: item.verifier_confidence)
        return (
            replace(
                best,
                inspected_function_ids=inspected,
                verification_rounds=rounds,
            ),
            "affirmatively_rejected_during_small_feature",
        )

    best = max(
        claims,
        key=lambda item: (
            len(item.inspected_function_ids),
            item.verifier_confidence,
        ),
    )
    return (
        replace(
            best,
            status=Verdict.UNRESOLVED,
            first_acquisition_confirmed=False,
            inspected_function_ids=inspected,
            verification_rounds=rounds,
            unknowns=unique_strings([
                *best.unknowns,
                "Entry remained unresolved through all Small Feature context rounds",
            ]),
        ),
        "small_feature_context_exhausted",
    )


def _small_feature_round_digest(response: dict[str, Any]) -> dict[str, Any]:
    """Carry control metadata without duplicating the prior model response.

    The full response already exists in the stateful app-server thread. Keeping
    only this bounded digest in the next input prevents feature proposals and
    rationales from being copied into the conversation on every context turn.
    """

    if not response:
        return {}
    return {
        "context_complete": bool(response.get("context_complete", False)),
        "requested_function_ids": string_list(
            response.get("requested_function_ids")
        ),
        "small_feature_count": len(object_list(response.get("small_features"))),
        "entry_resolutions": [
            {
                "entry_id": str(item.get("entry_id", "")),
                "status": str(item.get("status", "")),
            }
            for item in object_list(response.get("entry_resolutions"))
        ],
        "unrelated_entry_ids": string_list(response.get("unrelated_entries")),
    }


def _number(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
