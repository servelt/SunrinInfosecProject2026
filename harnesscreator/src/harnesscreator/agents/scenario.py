from __future__ import annotations

import re
from pathlib import Path
from collections import deque
from dataclasses import replace
from typing import Any, Awaitable, Callable

from ..analysis.graph import GraphStore, _code_only
from ..analysis.netlifter import NetLifterGrammar
from ..analysis.operation_seeds import extract_operation_seeds, merge_operation_seed_records
from ..analysis.request_hypotheses import source_literal_request_trials
from ..analysis.usage_evidence import UsageEvidenceBundle
from ..analysis.usage_artifacts import relevant_usage_functions
from ..llm.base import (
    LLMProvider,
    close_llm_session,
    is_terminal_llm_infrastructure_error,
)
from ..models import (
    ActionActor,
    ActionExample,
    ActionOrderingConstraint,
    ActionStateContract,
    EntryRecord,
    EntrySiteKind,
    Evidence,
    ExternalActionSchema,
    FunctionMetadata,
    InputFieldConstraint,
    OperationSeed,
    ProofStatus,
    RequestBindingUse,
    ResponseBindingExtractor,
    ScenarioCandidate,
    ScenarioStatus,
    ScenarioStep,
    StateDependencyGraph,
    StateRequirement,
    UsageArtifact,
    stable_id,
    unique_strings,
)
from ..runtime.request_ir import render_request, request_ir_summary
from ..analysis.declarations import DeclarationIndex
from ..tracing import TraceCallback, emit_trace
from .common import (
    concurrent_map, function_payload, function_ref, object_list, string_list,
    resolve_source_linked_function, _source_linked_declaration_artifact,
)
from .entry_action_screen import EntryActionScreenResult


_EVIDENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "function_id", "line", "detail"],
    "properties": {
        "kind": {"type": "string"},
        "function_id": {"type": "string"},
        "line": {"type": ["integer", "null"]},
        "detail": {"type": "string"},
    },
}


SOURCE_CASE_MATCH_SCHEMA: dict[str, Any] = {
    'type': 'object', 'additionalProperties': False,
    'required': ['matches', 'rationale'],
    'properties': {
        'matches': {'type': 'array', 'items': {
            'type': 'object', 'additionalProperties': False,
            'required': ['action_name', 'handler_function_id', 'case_id',
                         'rationale', 'evidence'],
            'properties': {
                'action_name': {'type': 'string'},
                'handler_function_id': {'type': 'string'},
                'case_id': {'type': 'string'},
                'rationale': {'type': 'string'},
                'evidence': {'type': 'array', 'items': _EVIDENCE_SCHEMA},
            },
        }},
        'rationale': {'type': 'string'},
    },
}


INPUT_ACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "actions", "context_complete", "requested_function_ids", "rationale",
        "branch_disposition", "branch_disposition_evidence",
    ],
    "properties": {
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "name", "description", "dispatcher_function_id",
                    "handler_function_id", "discriminator", "fields", "examples",
                    "success_markers_hex", "failure_markers_hex", "success_evidence",
                    "failure_evidence", "response_bindings", "evidence",
                    "selection_evidence", "effect_evidence",
                    "unknowns", "confidence",
                ],
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "dispatcher_function_id": {"type": "string"},
                    "handler_function_id": {"type": "string"},
                    "discriminator": {"type": "string"},
                    "fields": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "name", "offset", "width", "encoding", "binding",
                                "relation", "evidence",
                            ],
                            "properties": {
                                "name": {"type": "string"},
                                "offset": {"type": "integer", "minimum": 0},
                                "width": {"type": "integer", "minimum": 1},
                                "encoding": {"type": "string"},
                                "binding": {"type": "string"},
                                "relation": {"type": "string"},
                                "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                            },
                        },
                    },
                    "examples": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "data_hex", "bindings", "rationale", "origin", "evidence",
                            ],
                            "properties": {
                                "data_hex": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
                                "bindings": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "required": ["name", "value_hex"],
                                        "properties": {
                                            "name": {"type": "string", "minLength": 1},
                                            "value_hex": {
                                                "type": "string",
                                                "pattern": "^[0-9a-fA-F]*$",
                                            },
                                        },
                                    },
                                },
                                "rationale": {"type": "string"},
                                "origin": {"type": "string"},
                                "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                            },
                        },
                    },
                    "success_markers_hex": {
                        "type": "array", "items": {"type": "string", "pattern": "^[0-9a-fA-F]+$"},
                    },
                    "failure_markers_hex": {
                        "type": "array", "items": {"type": "string", "pattern": "^[0-9a-fA-F]+$"},
                    },
                    "success_evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                    "failure_evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                    "response_bindings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "binding", "offset", "width", "encoding", "evidence",
                            ],
                            "properties": {
                                "binding": {"type": "string", "minLength": 1},
                                "offset": {"type": "integer", "minimum": 0},
                                "width": {"type": "integer", "minimum": 1},
                                "encoding": {"type": "string"},
                                "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                            },
                        },
                    },
                    "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                    "selection_evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                    "effect_evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                    "unknowns": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        },
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {
            "type": "array", "maxItems": 1, "items": {"type": "string"},
        },
        "rationale": {"type": "string"},
        "branch_disposition": {
            "type": "string",
            "enum": ["ACTION", "NOT_ACTION", "UNRESOLVED"],
        },
        "branch_disposition_evidence": {
            "type": "array", "items": _EVIDENCE_SCHEMA,
        },
    },
}


# Multiple external request cases may share an Entry -> dispatcher -> handler
# path.  One source walk can classify those cases together, but each case
# retains a separate disposition and its own source-evidence requirements.
# Unknown cases MUST be returned to the ordinary single-case worker.
GROUP_INPUT_ACTION_SCHEMA: dict[str, Any] = {
    **INPUT_ACTION_SCHEMA,
    "required": [
        "actions", "context_complete", "requested_function_ids", "rationale",
        "branch_dispositions",
    ],
    "properties": {
        **{
            key: value for key, value in INPUT_ACTION_SCHEMA["properties"].items()
            if key not in {"branch_disposition", "branch_disposition_evidence"}
        },
        "branch_dispositions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["operation_seed_id", "disposition", "evidence"],
                "properties": {
                    "operation_seed_id": {"type": "string"},
                    "disposition": {
                        "type": "string",
                        "enum": ["ACTION", "NOT_ACTION", "UNRESOLVED"],
                    },
                    "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
                },
            },
        },
    },
}


_SEMANTIC_ACTION_ITEM_SCHEMA = {
    **INPUT_ACTION_SCHEMA['properties']['actions']['items'],
    'required': [
        *INPUT_ACTION_SCHEMA['properties']['actions']['items']['required'],
        'action_context_complete',
    ],
    'properties': {
        **INPUT_ACTION_SCHEMA['properties']['actions']['items']['properties'],
        'action_context_complete': {'type': 'boolean'},
    },
}
SEMANTIC_INPUT_ACTION_SCHEMA: dict[str, Any] = {
    **INPUT_ACTION_SCHEMA,
    'required': [
        key for key in INPUT_ACTION_SCHEMA['required']
        if key not in {'branch_disposition', 'branch_disposition_evidence'}
    ] + ['tree_focus_function_id', 'jump_target_function_id',
         'requested_declaration_name', 'list_declarations',
         'declaration_name_filter'],
    'properties': {
        **{
            key: value for key, value in INPUT_ACTION_SCHEMA['properties'].items()
            if key not in {'branch_disposition', 'branch_disposition_evidence'}
        },
        'actions': {
            **INPUT_ACTION_SCHEMA['properties']['actions'],
            'items': _SEMANTIC_ACTION_ITEM_SCHEMA,
        },
        'tree_focus_function_id': {'type': 'string'},
        'jump_target_function_id': {'type': 'string'},
        'requested_declaration_name': {'type': 'string'},
        'list_declarations': {'type': 'boolean'},
        'declaration_name_filter': {'type': 'string'},
    },
}


_REQUIREMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "resource", "binding", "binding_value_hex", "predicate",
        "scope", "owner_binding", "evidence",
    ],
    "properties": {
        "resource": {"type": "string"},
        "binding": {"type": "string"},
        "binding_value_hex": {
            "type": ["string", "null"],
            "pattern": "^[0-9a-fA-F]*$",
        },
        "predicate": {"type": "string"},
        "scope": {"type": "string", "enum": ["global", "connection", "session", "object"]},
        "owner_binding": {"type": "string"},
        "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
    },
}


STATE_DEPENDENCY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "consumes", "produces", "invalidates", "initial_resources",
        "success_condition", "evidence", "unknowns", "context_complete",
        "requested_function_ids", "rationale",
    ],
    "properties": {
        "consumes": {"type": "array", "items": _REQUIREMENT_SCHEMA},
        "produces": {"type": "array", "items": _REQUIREMENT_SCHEMA},
        "invalidates": {"type": "array", "items": _REQUIREMENT_SCHEMA},
        "initial_resources": {"type": "array", "items": _REQUIREMENT_SCHEMA},
        "success_condition": {"type": "string"},
        "evidence": {"type": "array", "items": _EVIDENCE_SCHEMA},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {
            "type": "array", "maxItems": 1, "items": {"type": "string"},
        },
        "rationale": {"type": "string"},
    },
}


GROUP_STATE_DEPENDENCY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["contracts", "context_complete", "requested_function_ids", "rationale"],
    "properties": {
        "contracts": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "action_id", "consumes", "produces", "invalidates",
                    "initial_resources", "success_condition", "evidence", "unknowns",
                    "action_context_complete",
                ],
                "properties": {
                    "action_id": {"type": "string"},
                    "action_context_complete": {"type": "boolean"},
                    **{
                        key: value
                        for key, value in STATE_DEPENDENCY_SCHEMA["properties"].items()
                        if key not in {
                            "context_complete", "requested_function_ids", "rationale"
                        }
                    },
                },
            },
        },
        "context_complete": {"type": "boolean"},
        "requested_function_ids": STATE_DEPENDENCY_SCHEMA["properties"]["requested_function_ids"],
        "rationale": {"type": "string"},
    },
}



def _looks_like_external_command_selector(condition: str) -> bool:
    """Cheap scheduling heuristic; never a proof of request reachability.

    Preserve recognizable protocol/command selection branches even when the
    router uses if/else instead of switch. Ordinary guards remain evidence in
    their parent's branch session and do not recursively create LLM work.
    """
    import re

    text = condition.casefold()
    # These are syntactic hints only, not a protocol-specific allowlist.
    return bool(re.search(
        r"\b(?:strncmp|strcmp|strcasecmp|strncasecmp|memcmp)\s*\("
        r"|\b(?:opcode|command|cmd_type|request_type|message_type)\b"
        r"|\b(?:cmd_|op_)\w+",
        text,
    ))


class InputActionAgent:
    """Forward reconstruction of external request actions.

    Exactly one function body is added per turn.  Dispatcher syntax and
    NetLifter grammar are candidate evidence; only source-located actions are
    promoted to ``PROVEN_STATIC``.
    """

    def _navigation_tree(
        self, entry_id: str, focus_id: str, path: list[str],
        opened: list[str], jumps_used: int,
    ) -> dict[str, Any]:
        """Show one expandable call-graph level without opening source."""
        focus = self.graph.get(focus_id)
        return {
            'entry_function_id': entry_id,
            'focus': function_ref(focus),
            'path': [function_ref(self.graph.get(item)) for item in path
                     if item in self.graph.bundle.functions],
            'children': [
                {**choice, 'already_opened': choice['function_id'] in opened}
                for choice in self.graph.frontier([focus_id])
            ],
            'jumps_used': jumps_used,
            'proof_policy': 'tree edges are navigation hints, not input-flow or execution proof',
        }

    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        *,
        budget: int = 0,
        semantic_action_mode: bool = True,
        max_branch_validations: int = 256,
        branch_context_budget: int = 4,
        per_entry_branch_budget: int = 24,
        branch_group_size: int = 8,
        netlifter: list[NetLifterGrammar] | None = None,
        source_root: Any | None = None,
        resume_continuations: list[dict[str, Any]] | None = None,
        input_case_hypotheses: dict[str, list[dict[str, Any]]] | None = None,
        input_trial_observations: dict[str, list[dict[str, Any]]] | None = None,
        scenario_channel: str = "disabled",
        scenario_response_protocol: str = "markers",
        usage_artifacts: list[UsageArtifact] | None = None,
        trace: TraceCallback | None = None,
        checkpoint: Callable[[dict[str, Any]], None] | None = None,
        early_runtime_hook: Callable[[list[ExternalActionSchema]], Awaitable[None]] | None = None,
        include_source_literal_trials: bool = True,
        entry_routes: dict[str, EntryActionScreenResult] | None = None,
    ):
        if not semantic_action_mode:
            raise ValueError('syntax-branch Action discovery is retired')
        self.semantic_action_mode = True
        self.llm = llm
        self.graph = graph
        # The indexed function set is a finite source-navigation bound.  A
        # fixed number of turns is not evidence that the path is complete.
        self.budget = max(1, budget or len(graph.bundle.functions))
        self.max_branch_validations = max(1, max_branch_validations)
        self.branch_context_budget = max(2, branch_context_budget)
        self.per_entry_branch_budget = max(1, per_entry_branch_budget)
        self.branch_group_size = max(1, branch_group_size)
        self.netlifter = list(netlifter or [])
        self.source_root = source_root
        self.resume_continuations = list(resume_continuations or [])
        self.input_case_hypotheses = dict(input_case_hypotheses or {})
        self.input_trial_observations = dict(input_trial_observations or {})
        self._trial_feedback_sent: set[str] = set()
        self.continuations: list[dict[str, Any]] = []
        self.scenario_channel = scenario_channel.casefold()
        self.scenario_response_protocol = scenario_response_protocol
        self.usage_artifacts = list(usage_artifacts or [])
        self.trace = trace
        self.checkpoint = checkpoint
        self.early_runtime_hook = early_runtime_hook
        self.include_source_literal_trials = include_source_literal_trials
        self.entry_routes = dict(entry_routes or {})
        self.source_coverage: list[dict[str, Any]] = []
        self.selector_hints: list[dict[str, Any]] = []
        self._consumer_cache: dict[tuple[str, bool], tuple[list[tuple[str, list[str], set[str]]], bool]] = {}
        self._early_trial_entries: set[str] = set()
        self.operation_seeds: list[OperationSeed] = []
        self._seeds_by_entry: dict[str, list[OperationSeed]] = {}
        self._input_symbols_by_entry: dict[str, dict[str, set[str]]] = {}
        self.inventory_obligations: list[str] = []
        self.infrastructure_failures: list[str] = []
        self.skipped_entries: list[dict[str, str]] = []
        self.planned_branch_validations = 0
        self.planned_branch_groups = 0
        self.branch_group_fallbacks = 0

    @staticmethod
    def session_key(entry: EntryRecord) -> str:
        return f"input_action:{entry.entry_id}"

    def _group_branch_items(
        self,
        items: list[tuple[EntryRecord, OperationSeed, str]],
    ) -> list[list[tuple[EntryRecord, OperationSeed, str]]]:
        """Batch cases sharing the same concrete source path, without losing any case.

        The source excerpt must contain *every* grouped discriminator line.
        Unrelated handlers, uncertain conditional guards, and paths with
        different Entry navigation evidence remain independent workers.
        """
        result: list[list[tuple[EntryRecord, OperationSeed, str]]] = []
        latest_by_path: dict[tuple[str, str, str, tuple[str, ...]], int] = {}
        for item in items:
            entry, seed, handler_id = item
            if (self.branch_group_size == 1 or seed.evidence_kind != "switch_case"
                or seed.discriminator.strip() == "default"):
                result.append([item])
                continue
            key = (
                entry.entry_id, seed.dispatcher_function_id, handler_id,
                tuple(seed.entry_path_function_ids),
            )
            index = latest_by_path.get(key)
            if index is not None:
                existing = result[index]
                first_seed = existing[0][1]
                source = self.graph.bundle.functions.get(seed.dispatcher_function_id)
                excerpt = function_payload(
                    source, source_limit=max(1, len(source.source) + 1),
                    focus_line=first_seed.line,
                ) if source else None
                if (len(existing) < self.branch_group_size
                    and excerpt is not None
                    and excerpt["source_excerpt_start_line"] <= seed.line
                    <= excerpt["source_excerpt_end_line"]):
                    existing.append(item)
                    continue
            latest_by_path[key] = len(result)
            result.append([item])
        return result

    async def run(self, entries: list[EntryRecord]) -> list[ExternalActionSchema]:
        self.operation_seeds = []
        self._seeds_by_entry = {}
        self.continuations = []
        self.inventory_obligations = []
        self.infrastructure_failures = []
        self.planned_branch_validations = 0
        self.planned_branch_groups = 0
        self.branch_group_fallbacks = 0
        self._early_trial_entries = set()
        self._trial_feedback_sent = set()
        self.source_coverage = []
        self.selector_hints = []
        self._consumer_cache = {}
        async def walk_and_trial(entry: EntryRecord):
            result = await self._run_entry(entry)
            if (self.early_runtime_hook is not None
                and entry.entry_id not in self._early_trial_entries):
                await self.early_runtime_hook(result[0])
                self._early_trial_entries.add(entry.entry_id)
            return result
        batches = await concurrent_map(
            entries, walk_and_trial,
            max(1, int(getattr(self.llm, 'max_concurrency', 1))),
        )
        actions: list[ExternalActionSchema] = []
        for entry, (found, _unused_seeds) in zip(entries, batches):
            actions.extend(found)
            if not found and not any(
                entry.entry_id in failure for failure in self.infrastructure_failures
            ) and not any(
                item.startswith(f'{entry.entry_id}: no external Action reconstructed')
                for item in self.inventory_obligations
            ):
                self.inventory_obligations.append(
                    f'{entry.entry_id}: no external Action reconstructed; '
                    'produced no source-backed external Action candidate'
                )
        return _merge_actions(actions)

    def _source_consumers(
        self, entry: EntryRecord, *, include_candidate_edges: bool,
    ) -> tuple[list[tuple[str, list[str], set[str]]], bool]:
        """Cache the same source flow used for navigation and work accounting."""
        key = (entry.entry_id, include_candidate_edges)
        if key not in self._consumer_cache:
            self._consumer_cache[key] = source_dataflow_consumers(
                self.graph, entry,
                function_limit=len(self.graph.bundle.functions),
                include_all_consumers=True,
                include_candidate_edges=include_candidate_edges,
            )
        return self._consumer_cache[key]

    async def _legacy_run_retired(self, entries: list[EntryRecord]) -> list[ExternalActionSchema]:
        # Inventory is a deterministic, cheap syntax/data-flow pass.  It keeps
        # possible branches visible for audit, but a branch becomes an
        # independent semantic-validation session only after the Entry-scoped
        # walk classifies its containing function as an external request
        # dispatcher with source evidence.
        self.operation_seeds = []
        self._seeds_by_entry = {}
        self.inventory_obligations = []
        self.infrastructure_failures = []
        self.skipped_entries = []
        self.planned_branch_validations = 0
        self.planned_branch_groups = 0
        self.branch_group_fallbacks = 0
        # The executor selection is NOT a product Entry discovery policy.
        # Keep network, file, argv, environment, callback and IPC Entries in
        # the Action inventory even when the current runtime adapter cannot
        # replay them. Unsupported execution is reported after planning.
        # Previously this branch silently discarded other input surfaces.
        direct_entries: list[EntryRecord] = []
        for entry in entries:
            seeds, truncated = self._inventory_entry(entry)
            # Syntax inventory is recall evidence only.  Do not fan every
            # switch/if seed out into an LLM session until the containing
            # function has been classified, with opened-source evidence, as
            # an external request dispatcher.  This keeps lifecycle/backend
            # state machines visible in the audit without multiplying them
            # into pseudo-actions.
            self._seeds_by_entry[entry.entry_id] = []
            self.operation_seeds.extend(seeds)
            if truncated:
                self.inventory_obligations.append(
                    f"{entry.entry_id}: operation inventory was truncated"
                )
            direct_entries.append(entry)

        self._publish_checkpoint(
            "inventory_complete", [], completed_branch_validations=0,
            remaining_branch_validations=0,
        )

        # A transport outage is shared by every branch on the same provider.
        # Scheduling the whole list at once made a reconnect failure fan out to
        # every direct Entry before the orchestrator could react.  Work in
        # bounded waves and open the circuit after two completely failed waves,
        # matching the independently validated branch-worker policy below.
        direct_results: list[
            tuple[EntryRecord, tuple[list[ExternalActionSchema], list[OperationSeed]]]
        ] = []
        pending_direct: deque[EntryRecord] = deque(direct_entries)
        direct_concurrency = max(
            1, int(getattr(self.llm, "max_concurrency", 1))
        )
        consecutive_direct_infrastructure_waves = 0
        while pending_direct:
            wave = [
                pending_direct.popleft()
                for _ in range(min(direct_concurrency, len(pending_direct)))
            ]
            failures_before_wave = len(self.infrastructure_failures)
            wave_results = await concurrent_map(
                wave, self._run_entry, direct_concurrency
            )
            direct_results.extend(zip(wave, wave_results))
            wave_failures = (
                len(self.infrastructure_failures) - failures_before_wave
            )
            if wave_failures == len(wave):
                consecutive_direct_infrastructure_waves += 1
            else:
                consecutive_direct_infrastructure_waves = 0
            if (
                pending_direct
                and consecutive_direct_infrastructure_waves >= 2
            ):
                reason = (
                    "aborted remaining direct Entry analyses after every Entry "
                    "in two consecutive worker waves failed in the LLM "
                    "infrastructure"
                )
                self.inventory_obligations.append(
                    f"{reason}; {len(pending_direct)} queued"
                )
                emit_trace(
                    self.trace,
                    "input_action",
                    "direct_entry_infrastructure_aborted",
                    reason,
                    completed_direct_entries=len(direct_results),
                    remaining_direct_entries=len(pending_direct),
                    consecutive_failed_waves=(
                        consecutive_direct_infrastructure_waves
                    ),
                )
                break
        direct_batches: list[list[ExternalActionSchema]] = []
        for entry, (batch, discovered_seeds) in direct_results:
            direct_batches.append(batch)
            if discovered_seeds:
                merged = merge_operation_seed_records(discovered_seeds)
                self._seeds_by_entry[entry.entry_id] = merged
                self.operation_seeds.extend(discovered_seeds)
                for seed in merged:
                    if (
                        seed.status is not ProofStatus.REFUTED
                        and seed.unresolved_call_names
                        and not seed.handler_function_ids
                    ):
                        self.inventory_obligations.append(
                            f"{entry.entry_id}/{seed.operation_seed_id}: confirmed "
                            "external dispatcher branch "
                            f"{seed.discriminator!r} has no resolved direct or "
                            "possible indirect handler target for "
                            f"{', '.join(seed.unresolved_call_names)}"
                        )
        result = [item for batch in direct_batches for item in batch]
        self._publish_checkpoint(
            "direct_entries_complete", result,
            completed_branch_validations=0,
            remaining_branch_validations=0,
        )
        # Reach the ORIGINAL program before potentially hundreds of costly
        # branch-validation LLM calls. Only source-located, Entry-walk-confirmed
        # command literals are tried here; hypotheses remain POSSIBLE.
        if self.early_runtime_hook is not None:
            early_trials = self._add_source_literal_runtime_trials(
                entries, _merge_actions(result),
            )
            try:
                await self.early_runtime_hook(early_trials)
            except Exception as exc:
                # A runtime adapter failure must not erase the complete
                # source inventory; it is independently recoverable later.
                message = (
                    "Entry-walk original runtime trial failed before branch "
                    f"validation: {type(exc).__name__}: {exc}"
                )
                self.infrastructure_failures.append(message)
                self.inventory_obligations.append(message)
                emit_trace(
                    self.trace, "input_action", "early_runtime_trial_failed",
                    message,
                )
        entry_by_id = {item.entry_id: item for item in entries}
        queued: deque[tuple[EntryRecord, OperationSeed, str]] = deque()
        scheduled: set[tuple[str, str, str]] = set()
        for entry_id, seeds in self._seeds_by_entry.items():
            entry = entry_by_id.get(entry_id)
            if entry is None:
                continue
            for seed in seeds:
                if seed.status is ProofStatus.REFUTED:
                    continue
                if (
                    seed.unresolved_call_names
                    and not seed.handler_function_ids
                ):
                    # There is no concrete selected handler to inspect.  The
                    # unresolved callback remains an explicit obligation; do
                    # not mislabel the dispatcher itself as an inline handler
                    # and spend an LLM branch session that cannot resolve it.
                    continue
                handler_ids = (
                    seed.handler_function_ids
                    or [seed.dispatcher_function_id]
                )
                for handler_id in handler_ids:
                    if _operation_seed_is_covered(
                        entry, seed, handler_id, result
                    ):
                        self.operation_seeds.append(replace(
                            seed, status=ProofStatus.PROVEN_STATIC
                        ))
                        continue
                    key = (entry_id, seed.operation_seed_id, handler_id)
                    if key not in scheduled:
                        scheduled.add(key)
                        queued.append((entry, seed, handler_id))

        self.planned_branch_validations = len(queued)
        self._publish_checkpoint(
            "branch_plan_complete", result,
            completed_branch_validations=0,
            remaining_branch_validations=len(queued),
        )
        emit_trace(
            self.trace,
            "input_action",
            "branch_plan",
            (
                f"planned {len(queued)} top-level source-located branch "
                f"validation(s) from {len(self.operation_seeds)} operation seed(s)"
            ),
            branch_validation_count=len(queued),
            operation_seed_count=len(self.operation_seeds),
            max_branch_validations=self.max_branch_validations,
        )
        # Isolate an imprecise Entry instead of allowing it to poison every
        # other Entry in the run.  The old all-or-nothing guard correctly
        # stopped a 6,000-branch explosion, but also discarded an unrelated
        # TCP request dispatcher that had a small, valid plan.
        planned_by_entry: dict[str, int] = {}
        for entry, _seed, _handler_id in queued:
            planned_by_entry[entry.entry_id] = (
                planned_by_entry.get(entry.entry_id, 0) + 1
            )
        oversized_entries = {
            entry_id for entry_id, count in planned_by_entry.items()
            if count > (
                self.max_branch_validations * self.branch_group_size
                if self.max_branch_validations > 1
                else self.max_branch_validations
            )
        }
        if oversized_entries:
            for entry_id in sorted(oversized_entries):
                count = planned_by_entry[entry_id]
                self.inventory_obligations.append(
                    f"{entry_id}: operation inventory produced {count} branch "
                    "validations, exceeding the configured safety limit of "
                    f"{self.max_branch_validations} group(s) of at most "
                    f"{self.branch_group_size} cases; only this Entry was skipped "
                    "because its call-target or dispatcher expansion is imprecise"
                )
                emit_trace(
                    self.trace,
                    "input_action",
                    "entry_branch_plan_rejected",
                    (
                        f"rejected abnormal {count}-branch plan for {entry_id} "
                        f"before LLM execution (limit={self.max_branch_validations})"
                    ),
                    entry_id=entry_id,
                    branch_validation_count=count,
                    max_branch_validations=self.max_branch_validations,
                )
            queued = deque(
                item for item in queued
                if item[0].entry_id not in oversized_entries
            )

        # A budget limits costly LLM validation, never discovery. Keep every
        # candidate in operation_seeds; deferred work is explicitly audited.
        # Prioritize command-like switch cases over generic guard conditions
        # so productive actions can reach scenario generation sooner.
        def seed_priority(item: tuple[EntryRecord, OperationSeed, str]) -> tuple[int, int]:
            _entry, seed, _handler = item
            discriminator = seed.discriminator.strip()
            meaningful_case = (
                seed.evidence_kind == "switch_case"
                and discriminator != "default"
            )
            return (0 if meaningful_case else 1, seed.line)

        # Work is budgeted by shared *source path*, not by individual switch
        # labels.  Every source-backed case is still represented, including
        # those that the group model cannot resolve (individual fallback).
        grouped = self._group_branch_items(sorted(queued, key=seed_priority))
        self.planned_branch_groups = len(grouped)
        emit_trace(
            self.trace, "input_action", "branch_groups_planned",
            f"{self.planned_branch_validations} cases use {len(grouped)} source walks",
            operation_seed_count=self.planned_branch_validations,
            source_group_count=len(grouped),
            grouped_cases=sum(len(items) for items in grouped if len(items) > 1),
        )
        # Prioritize lower-trust external clients, without silently removing
        # backend/file/local Entries from the complete candidate inventory.
        def actor_priority(group: list[tuple[EntryRecord, OperationSeed, str]]) -> int:
            entry = group[0][0]
            actor = _entry_actor(entry, self.graph)
            return {
                ActionActor.INBOUND_CLIENT: 0,
                ActionActor.LOCAL_PROCESS_INPUT: 1,
                ActionActor.UNKNOWN: 2,
                ActionActor.OUTBOUND_PEER: 3,
            }[actor]

        grouped.sort(key=actor_priority)
        # The limit applies to expensive source-path workers, not labels in
        # one switch.  Deferred groups retain an obligation for *each* case.
        by_entry_count: dict[str, int] = {}
        limited: deque[list[tuple[EntryRecord, OperationSeed, str]]] = deque()
        for group in grouped:
            eid = group[0][0].entry_id
            count = by_entry_count.get(eid, 0)
            if count >= self.per_entry_branch_budget:
                self.inventory_obligations.extend(
                    f"{eid}/{item[1].operation_seed_id}: source-path group "
                    "deferred by per-Entry LLM budget; source candidate retained"
                    for item in group
                )
                continue
            by_entry_count[eid] = count + 1
            limited.append(group)
        queued_groups = limited

        # Several individually precise Entries may still exceed the run-wide
        # cost ceiling. Select in round-robin Entry order so one larger plan
        # cannot consume the whole budget and explicitly retain obligations
        # for every deferred branch.
        if len(queued_groups) > self.max_branch_validations:
            buckets: dict[str, deque[list[tuple[EntryRecord, OperationSeed, str]]]] = {}
            for group in queued_groups:
                buckets.setdefault(group[0][0].entry_id, deque()).append(group)
            selected: list[list[tuple[EntryRecord, OperationSeed, str]]] = []
            entry_order = list(buckets)
            while entry_order and len(selected) < self.max_branch_validations:
                next_order: list[str] = []
                for entry_id in entry_order:
                    bucket = buckets[entry_id]
                    if bucket and len(selected) < self.max_branch_validations:
                        selected.append(bucket.popleft())
                    if bucket:
                        next_order.append(entry_id)
                entry_order = next_order
            deferred_by_entry = {
                entry_id: sum(len(group) for group in bucket)
                for entry_id, bucket in buckets.items()
                if bucket
            }
            for entry_id, count in sorted(deferred_by_entry.items()):
                self.inventory_obligations.append(
                    f"{entry_id}: deferred {count} source-located cases after the "
                    f"run-wide source-path limit of {self.max_branch_validations}"
                )
            emit_trace(
                self.trace,
                "input_action",
                "branch_plan_bounded",
                (
                    f"selected {len(selected)} source-path groups fairly across "
                    f"Entries; deferred {sum(deferred_by_entry.values())} cases"
                ),
                selected_branch_validations=sum(len(group) for group in selected),
                deferred_branch_validations=sum(deferred_by_entry.values()),
                deferred_by_entry=deferred_by_entry,
                max_branch_validations=self.max_branch_validations,
            )
            queued_groups = deque(selected)

        # A grouped result is split back into independently audited branch
        # records.  Nested source-located selectors remain separate jobs.
        branch_count = 0
        processed_seed_count = 0
        consecutive_infrastructure_waves = 0
        infrastructure_abort_reason = ""
        while queued_groups and branch_count < self.max_branch_validations:
            wave: list[list[tuple[EntryRecord, OperationSeed, str]]] = []
            concurrency = max(1, int(getattr(self.llm, "max_concurrency", 1)))
            wave_limit = min(
                self.max_branch_validations - branch_count,
                concurrency,
            )
            while queued_groups and len(wave) < wave_limit:
                wave.append(queued_groups.popleft())
            failures_before_wave = len(self.infrastructure_failures)
            branch_results = await concurrent_map(
                wave,
                self._run_seed_group,
                concurrency,
            )
            for group, group_results in zip(wave, branch_results):
                branch_count += 1
                if len(group_results) != len(group):
                    raise RuntimeError("source-path group omitted a branch result")
                for (entry, seed, handler_id), (
                    branch_actions, nested, branch_status, branch_rationale
                ) in zip(group, group_results):
                    processed_seed_count += 1
                    result.extend(branch_actions)
                    if branch_status is ProofStatus.PROVEN_STATIC:
                        self.operation_seeds.append(replace(
                            seed, status=ProofStatus.PROVEN_STATIC
                        ))
                    elif branch_status is ProofStatus.REFUTED:
                        self.operation_seeds.append(replace(
                            seed, status=ProofStatus.REFUTED
                        ))
                    else:
                        self.inventory_obligations.append(
                            f"{entry.entry_id}/{seed.operation_seed_id}/{handler_id}: "
                            "semantic branch validation produced no statically proven "
                            f"external action; {branch_rationale or 'no disposition'}"
                        )
                    for nested_seed in nested:
                        self.operation_seeds.append(nested_seed)
                        # Nested guards remain local unless their source
                        # expression selects an external request operation.
                        if (
                            nested_seed.evidence_kind == "conditional_branch"
                            and not _looks_like_external_command_selector(
                                nested_seed.discriminator
                            )
                        ):
                            continue
                        if nested_seed.status is ProofStatus.REFUTED:
                            continue
                        if (
                            nested_seed.unresolved_call_names
                            and not nested_seed.handler_function_ids
                        ):
                            continue
                        nested_handlers = (
                            nested_seed.handler_function_ids
                            or [nested_seed.dispatcher_function_id]
                        )
                        for nested_handler_id in nested_handlers:
                            nested_key = (
                                entry.entry_id,
                                nested_seed.operation_seed_id,
                                nested_handler_id,
                            )
                            if nested_key in scheduled:
                                continue
                            scheduled.add(nested_key)
                            queued_groups.append([(
                                entry, nested_seed, nested_handler_id,
                            )])
                            self.planned_branch_validations += 1
                            self.planned_branch_groups += 1
            self._publish_checkpoint(
                "branch_wave_complete", result,
                completed_branch_validations=processed_seed_count,
                remaining_branch_validations=sum(len(group) for group in queued_groups),
            )
            wave_infrastructure_failures = (
                len(self.infrastructure_failures) - failures_before_wave
            )
            if wave_infrastructure_failures == len(wave):
                consecutive_infrastructure_waves += 1
            else:
                consecutive_infrastructure_waves = 0
            if queued_groups and consecutive_infrastructure_waves >= 2:
                infrastructure_abort_reason = (
                    "aborted remaining branch validations after every branch in "
                    "two consecutive worker waves failed in the LLM "
                    "infrastructure"
                )
                self.inventory_obligations.append(
                    f"{infrastructure_abort_reason}; {sum(len(group) for group in queued_groups)} queued cases"
                )
                emit_trace(
                    self.trace,
                    "input_action",
                    "branch_plan_infrastructure_aborted",
                    infrastructure_abort_reason,
                    completed_branch_validations=processed_seed_count,
                    remaining_branch_validations=sum(len(group) for group in queued_groups),
                    consecutive_failed_waves=consecutive_infrastructure_waves,
                )
                break
        if queued_groups:
            if not infrastructure_abort_reason:
                self.inventory_obligations.append(
                    "operation branch validation stopped at the "
                    f"{self.max_branch_validations}-source-path safety limit; "
                    f"{sum(len(group) for group in queued_groups)} queued cases"
                )
        # An Entry-wide walk normally proves only that an opened function is
        # an external request dispatcher.  Its actions are established later
        # by the isolated branch workers, so reporting a missing action before
        # those workers finish creates a false open obligation on every valid
        # dispatcher.  Decide this only from the complete per-Entry result.
        for entry in entries:
            if not any(
                action.entry_id == entry.entry_id
                and action.status is ProofStatus.PROVEN_STATIC
                for action in result
            ):
                self.inventory_obligations.append(
                    f"{entry.entry_id}: action reconstruction produced no "
                    "statically proven external action"
                )
        self.inventory_obligations = unique_strings(self.inventory_obligations)
        self.operation_seeds = merge_operation_seed_records(self.operation_seeds)
        merged_result = _merge_actions(result)
        if self.include_source_literal_trials:
            merged_result = self._add_source_literal_runtime_trials(entries, merged_result)
        self._publish_checkpoint(
            "complete", merged_result,
            completed_branch_validations=processed_seed_count,
            remaining_branch_validations=sum(len(group) for group in queued_groups),
        )
        return merged_result

    def _add_source_literal_runtime_trials(
        self,
        entries: list[EntryRecord],
        actions: list[ExternalActionSchema],
    ) -> list[ExternalActionSchema]:
        """Convert recognized parser literals to runtime *hypotheses*.

        This is not a fallback static proof or a guessed operation inventory.
        It runs only on an Entry-walk-discovered dispatcher with a literal
        string-comparison branch. Every proposed byte string remains POSSIBLE
        until the original program executes the intended acquisition/handler.
        """
        by_seed_id = {item.operation_seed_id: item for item in self.operation_seeds}
        results = list(actions)
        for entry in entries:
            actor = _entry_actor(entry, self.graph)
            if actor in {ActionActor.OUTBOUND_PEER, ActionActor.LOCAL_PROCESS_INPUT}:
                continue
            attempted = 0
            for seed in self._seeds_by_entry.get(entry.entry_id, []):
                status = by_seed_id.get(seed.operation_seed_id, seed).status
                if (status is ProofStatus.REFUTED
                    or seed.evidence_kind not in {"conditional_branch", "switch_case"}
                    or entry.entry_function_id not in seed.entry_path_function_ids):
                    continue
                if seed.dispatcher_function_id not in self.graph.bundle.functions:
                    continue
                request_bytes = source_literal_request_trials(
                    seed.discriminator, channel=entry.channel_kind,
                    response_protocol=self.scenario_response_protocol,
                )
                if not request_bytes:
                    continue
                handlers = seed.handler_function_ids or [seed.dispatcher_function_id]
                for handler_id in handlers:
                    if handler_id not in self.graph.bundle.functions:
                        continue
                    existing_index = next((index for index, action in enumerate(results)
                                           if action.entry_id == entry.entry_id
                                           and seed.operation_seed_id in action.operation_seed_ids
                                           and action.handler_function_id == handler_id), None)
                    if existing_index is not None and results[existing_index].examples:
                        continue
                    attempted += 1
                    dispatcher = self.graph.get(seed.dispatcher_function_id)
                    line_evidence = Evidence(
                        kind="source_literal_request_hypothesis",
                        function_id=dispatcher.function_id,
                        file=dispatcher.file,
                        line=seed.line,
                        detail=("literal external command comparison; trial bytes "
                                "must be verified on the original program"),
                    )
                    samples = [ActionExample(
                        data_hex=item.hex(), origin="source_literal_runtime_hypothesis",
                        rationale="tentative command/framing template awaiting original-program proof",
                        evidence=[line_evidence],
                    ) for item in request_bytes]
                    if existing_index is not None:
                        action = results[existing_index]
                        results[existing_index] = replace(
                            action, examples=samples, status=ProofStatus.POSSIBLE,
                            unknowns=unique_strings([
                                *action.unknowns,
                                "source-literal request trial has not been runtime verified",
                            ]),
                        )
                        continue
                    handler = self.graph.get(handler_id)
                    entry_fn = self.graph.get(entry.entry_function_id)
                    entry_probe = (
                        [Evidence(
                            kind="entry_acquisition_trial",
                            function_id=entry_fn.function_id, file=entry_fn.file,
                            line=entry.entry_line,
                            detail="candidate external acquisition; exact runtime proof required",
                        )] if entry.entry_line is not None else []
                    )
                    results.append(ExternalActionSchema(
                        action_id=stable_id(
                            "runtime-hypothesis", entry.entry_id,
                            seed.operation_seed_id, handler_id,
                        ),
                        entry_id=entry.entry_id,
                        name=seed.discriminator[:100],
                        description="source-literal request trial, not a verified Action",
                        dispatcher_function_id=dispatcher.function_id,
                        handler_function_id=handler.function_id,
                        discriminator=seed.discriminator,
                        channel_kind=entry.channel_kind,
                        fields=[], examples=samples,
                        success_markers_hex=[], failure_markers_hex=[],
                        evidence=[line_evidence],
                        inspected_function_ids=unique_strings([
                            *seed.entry_path_function_ids, dispatcher.function_id,
                        ]),
                        operation_seed_ids=[seed.operation_seed_id],
                        status=ProofStatus.POSSIBLE,
                        unknowns=[
                            "source-literal request trial has not been runtime verified",
                            "handler and framing require independent runtime attribution",
                        ],
                        confidence=0.0,
                        source_api=entry.source_api,
                        actor=actor,
                        direction=_entry_direction(entry, self.graph),
                        entry_function_id=entry.entry_function_id,
                        entry_probe_evidence=entry_probe,
                        dispatch_probe_evidence=[line_evidence],
                    ))
            if attempted:
                emit_trace(
                    self.trace, "input_action", "source_literal_trial_candidates",
                    f"created {attempted} request trial hypothesis(es) for {entry.entry_id}",
                    entry_id=entry.entry_id,
                    count=attempted,
                    proof_status="POSSIBLE",
                )
        return _merge_actions(results)

    def _publish_checkpoint(
        self,
        phase: str,
        actions: list[ExternalActionSchema],
        *,
        completed_branch_validations: int,
        remaining_branch_validations: int,
    ) -> None:
        """Durably expose completed Action work through the orchestrator.

        The callback is synchronous by design: the artifact store publishes by
        atomic replacement and fsyncs before this method returns.  Completed
        waves therefore remain available as a forensic/recovery artifact after
        interruption.  This method does not claim automatic cross-process
        resume of an unfinished run.
        """

        if self.checkpoint is None:
            return
        self.checkpoint({
            "phase": phase,
            "actions": _merge_actions(actions),
            "operation_seeds": merge_operation_seed_records(
                self.operation_seeds
            ),
            "open_obligations": unique_strings(self.inventory_obligations),
            "infrastructure_failures": list(self.infrastructure_failures),
            "skipped_entries": list(self.skipped_entries),
            "planned_branch_validations": self.planned_branch_validations,
            "planned_source_path_groups": self.planned_branch_groups,
            "source_path_group_size": self.branch_group_size,
            "grouped_case_individual_fallbacks": self.branch_group_fallbacks,
            "completed_branch_validations": completed_branch_validations,
            "remaining_branch_validations": remaining_branch_validations,
        })

    def _inventory_entry(
        self,
        entry: EntryRecord,
        *,
        function_limit: int | None = None,
    ) -> tuple[list[OperationSeed], bool]:
        root = entry.entry_function_id
        if root not in self.graph.bundle.functions:
            return [], False
        if function_limit is None:
            function_limit = len(self.graph.bundle.functions)
        # Inventory only dispatchers explicitly tied to the Entry by verified
        # consumer hints.  A generic call-graph reachability walk is not data
        # flow: it previously swept in allocators, hash functions, response
        # handlers, and every switch below them as external request actions.
        targets: list[tuple[str, list[str], set[str]]] = [
            (root, [root], _entry_destination_names(self.graph.get(root), entry))
        ]
        targets.extend(source_dataflow_consumers(
            self.graph, entry, function_limit=function_limit,
            include_all_consumers=True,
        )[0])
        # ``consumer_hints`` identify where acquired bytes are used next; they
        # do not assert that the function is an external-operation dispatcher.
        # Treating every hint as a dispatcher classified connection-state,
        # allocator, retry, and error switches as request operations (hundreds
        # of validations for a single state dispatcher). Hints remain the
        # forced navigation path in ``_direct_entry_path``.  A dispatcher is
        # added here only when the deterministic direct data-flow walk above
        # ties the acquired value to its branch, or later when the focused LLM
        # walk marks the opened function ACTION with source evidence.

        unique_targets: list[tuple[str, list[str], set[str]]] = []
        target_ids: set[str] = set()
        for function_id, path, names in targets:
            if function_id in target_ids:
                continue
            target_ids.add(function_id)
            unique_targets.append((function_id, path, names))

        seen: set[str] = set()
        result: list[OperationSeed] = []
        for function_id, path, names in unique_targets:
            if function_id in seen:
                continue
            seen.add(function_id)
            function = self.graph.get(function_id)
            for seed in extract_operation_seeds(
                [function], self.graph, input_symbols=names,
            ):
                result.append(replace(seed, entry_path_function_ids=list(path)))
            if len(seen) >= function_limit:
                break
        return merge_operation_seed_records(result), len(seen) < len(unique_targets)

    def _source_dataflow_dispatchers(
        self, entry: EntryRecord, *, function_limit: int,
        include_all_consumers: bool = False,
    ) -> tuple[list[tuple[str, list[str]]], bool]:
        consumers, unresolved = source_dataflow_consumers(
            self.graph, entry, function_limit=function_limit,
            include_all_consumers=include_all_consumers,
        )
        return [(function_id, path) for function_id, path, _names in consumers], unresolved

    def scenario_incompatibility(self, entry: EntryRecord) -> str:
        """Return a configured-transport scope mismatch, if any.

        A run configured for one concrete transport (for example raw TCP) is
        complete relative to that transport.  File, environment, UDP, TLS, or
        outbound connected-peer Entries remain in the skip audit, but are not open
        analysis obligations for the selected run.
        """

        return self._scenario_incompatibility(entry)

    def _scenario_incompatibility(self, entry: EntryRecord) -> str:
        channel = self.scenario_channel
        if channel == "disabled":
            return ""
        if entry.entry_function_id not in self.graph.bundle.functions:
            return "Entry is outside the selected product build target"
        if entry.site_kind not in {
            EntrySiteKind.DIRECT_ACQUISITION,
            EntrySiteKind.EXTERNAL_CALLBACK,
        }:
            return f"{entry.site_kind} is not supplied by the runtime request transport"

        source_api = entry.source_api.rsplit("::", 1)[-1].casefold()
        entry_channel = entry.channel_kind.casefold()
        narrative = " ".join([
            entry.boundary_subject,
            entry.rationale,
            *(str(item.get("relation", "")) for item in entry.provenance_path),
            *(item.detail for item in entry.evidence),
        ]).casefold()
        network_api = source_api in {
            "recv", "recvfrom", "recvmsg", "read", "readv", "ssl_read",
            "ssl_read_ex", "bio_read", "wsarecv", "wsarecvfrom",
            "gnutls_record_recv",
        }
        explicit_udp = "udp" in entry_channel
        explicit_tcp = "tcp" in entry_channel
        is_tls = source_api in {
            "ssl_read", "ssl_read_ex", "bio_read", "gnutls_record_recv",
        } or "tls" in entry_channel
        socket_specific_api = source_api in {
            "recv", "recvfrom", "recvmsg", "ssl_read", "ssl_read_ex",
            "bio_read", "wsarecv", "wsarecvfrom", "gnutls_record_recv",
        }
        is_network = network_api and (
            socket_specific_api
            or any(
                marker in f"{entry_channel} {narrative}"
                for marker in ("network", "socket", "tcp", "tls", "udp")
            )
        )
        if channel == "tcp" and (not is_network or explicit_udp):
            return "Entry does not acquire bytes from the configured TCP request channel"
        if channel == "tcp" and is_tls:
            return (
                "Entry receives decrypted TLS application data, but the configured "
                "scenario runner injects raw TCP bytes and has no TLS endpoint"
            )
        if channel == "udp" and (not is_network or explicit_tcp):
            return "Entry does not acquire bytes from the configured UDP request channel"
        if channel == "stdin":
            # A FILE * read is not inherently stdin: require the verifier's
            # concrete provenance to name the standard-input stream.  Models
            # may describe the same stream as "stdio standard input" instead
            # of using the C identifier `stdin` in channel_kind.
            is_stdin = bool(re.search(
                r"\b(?:stdin|standard[\s-]+input)\b",
                f"{entry_channel} {narrative}",
            )) or source_api in {
                "getchar", "getchar_unlocked", "scanf",
            }
            if not is_stdin:
                return "Entry does not acquire bytes from the configured stdin channel"

        if channel in {"tcp", "udp"}:
            # Direction must come from the actual provenance/evidence chain.
            # ``inspected_function_ids`` is merely every body opened while the
            # verifier searched; an unrelated helper containing connect(2)
            # must not turn a valid inbound server Entry into an outbound-peer
            # response Entry.
            context_ids = {
                entry.entry_function_id,
                *(str(item.get("function_id", "")) for item in entry.provenance_path),
                *(item.function_id for item in entry.evidence),
            }
            context_source = "\n".join(
                self.graph.get(function_id).source
                for function_id in context_ids
                if function_id in self.graph.bundle.functions
            )
            has_outbound_connect = bool(
                re.search(r"(?<![.>])\bconnect\s*\(", context_source)
            )
            has_inbound_setup = bool(
                re.search(
                    r"(?<![.>])\b(?:accept|accept4|bind|listen)\s*\(",
                    context_source,
                )
            )
            # Do not classify direction from model-authored subject/direction
            # labels. Such prose is neither stable across projects nor proof
            # of the descriptor's origin.
            # Exclude an Entry only when the source bodies cited by its own
            # provenance/evidence contain concrete client-side connect setup
            # and no server-side accept/listen setup.  If lifecycle evidence is
            # incomplete, keep the Entry in scope and let analysis record the
            # unresolved obligation instead of guessing from prose.
            if has_outbound_connect and not has_inbound_setup:
                return (
                    "Entry receives data from an outbound-connected peer, while the "
                    "configured transport injects inbound client requests"
                )
        return ""

    async def _run_entry(
        self, entry: EntryRecord,
    ) -> tuple[list[ExternalActionSchema], list[OperationSeed]]:
        root = entry.entry_function_id
        declaration_index = DeclarationIndex(self.graph.bundle.declarations)
        if root not in self.graph.bundle.functions:
            return [], []
        route = self.entry_routes.get(entry.entry_id)
        route_path = (
            list(route.path_function_ids)
            if route is not None and route.disposition == 'SELECTED'
            and route.path_function_ids
            and route.path_function_ids[0] == root
            and all(item in self.graph.bundle.functions for item in route.path_function_ids)
            else []
        )
        # The screen already inspected this path. Give the Action model those
        # exact source bodies and start at its last node instead of repeating
        # the Entry walk. The screen's finding is a candidate, not proof.
        opened: list[str] = list(dict.fromkeys(route_path[:-1]))
        pending = route_path[-1] if route_path else root
        proved_consumers, proved_flow_incomplete = self._source_consumers(
            entry, include_candidate_edges=False,
        )
        candidate_consumers, candidate_flow_incomplete = self._source_consumers(
            entry, include_candidate_edges=True,
        )
        proved_paths = {
            function_id: path for function_id, path, _names in proved_consumers
        }
        candidate_paths = {
            function_id: path for function_id, path, _names in candidate_consumers
        }
        required_consumers = sorted(
            proved_paths, key=lambda item: (len(proved_paths[item]), item),
        )
        raw_actions: list[dict[str, Any]] = []
        early_submitted: set[str] = set()
        attempted_case_matches: set[tuple[str, str]] = set()
        artifact_pending: dict[str, Any] | None = None
        artifact_targets: list[str] = []
        review_only = False
        stale_action_drafts: list[dict[str, Any]] = []
        complete = False
        infrastructure_failure = ""
        jumps_used = 0
        jump_history: list[dict[str, str]] = []
        pending_jump_from = ''
        tree_focus = root
        tree_path = [root]
        tree_browse_only = False
        declaration_queries_seen: set[tuple[str, str]] = set()
        source_walk_states_seen: set[tuple[object, ...]] = set()
        resumed = next((item for item in self.resume_continuations
                        if item.get('entry_id') == entry.entry_id), None)
        recorded_next: list[str] = []
        resumed_lead_consumed = False
        if resumed:
            fingerprints = resumed.get('source_fingerprints') or {}
            recorded_next = [str(item) for item in
                             resumed.get('next_function_ids') or []]
            if any(
                function_id not in self.graph.bundle.functions or
                fingerprints.get(function_id) != stable_id(
                    'source', self.graph.get(function_id).source,
                )
                for function_id in recorded_next
            ):
                self.inventory_obligations.append(
                    f'{entry.entry_id}: recorded Action frontier does not match '
                    'current source; continuation invalidated'
                )
                recorded_next = []
            else:
                raw_actions = list(resumed.get('partial_action_drafts') or [])
                jump_history = [item for item in resumed.get('jump_history', [])
                                if isinstance(item, dict)]
                jumps_used = len(jump_history)
        try:
            round_index = 0
            while True:
                round_index += 1
                walk_state = (
                    pending, tuple(opened), tree_focus, tuple(tree_path),
                    bool(review_only), bool(tree_browse_only),
                    str((artifact_pending or {}).get('kind') or ''),
                    str((artifact_pending or {}).get('name') or ''),
                    str((artifact_pending or {}).get('name_filter') or ''),
                    str((artifact_pending or {}).get('symbol') or ''),
                    tuple(sorted(_raw_action_identity(item) for item in raw_actions)),
                )
                if walk_state in source_walk_states_seen:
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: Action source navigation repeated '
                        'without new source or Action evidence')
                    self._record_action_continuation(
                        entry, opened, [pending], raw_actions,
                        jump_history=jump_history,
                    )
                    break
                source_walk_states_seen.add(walk_state)
                if pending not in opened and len(opened) >= self.budget:
                    self._record_action_continuation(
                        entry, opened, [pending], raw_actions,
                        jump_history=jump_history,
                    )
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: uninspected source function '
                        f'{pending} remains after the configured function budget'
                    )
                    break
                if ((pending in opened and artifact_pending is None and not review_only
                     and not tree_browse_only and not pending_jump_from)
                    or pending not in self.graph.bundle.functions):
                    break
                if pending_jump_from:
                    jumps_used += 1
                    jump_history.append({'from_function_id': pending_jump_from,
                                         'to_function_id': pending})
                    emit_trace(
                        self.trace, 'input_action', 'tree_jump',
                        f'{entry.entry_id}: jumped to {self.graph.get(pending).name} '
                        f'(jump {jumps_used})',
                        entry_id=entry.entry_id,
                        from_function_id=pending_jump_from,
                        to_function_id=pending,
                        jumps_used=jumps_used,
                    )
                    pending_jump_from = ''
                    tree_focus = pending
                    tree_path = [pending]
                tree_browse_only = False
                if pending not in opened:
                    opened.append(pending)
                    tree_focus = pending
                    tree_path = [pending]
                current = self.graph.get(pending)
                choices = self._choices(opened, [], entry,
                                        focus_function_id=pending)
                tree_view = self._navigation_tree(
                    root, tree_focus, tree_path, opened, jumps_used,
                )
                for target_id in artifact_targets:
                    if target_id in opened or target_id not in self.graph.bundle.functions:
                        continue
                    if not any(str(item['function_id']) == target_id for item in choices):
                        choices.append({
                            **function_ref(self.graph.get(target_id)),
                            'connections': [{
                                'relation': 'source_linked_table_target_candidate',
                                'proof_policy': 'navigation only; table selection unproven',
                            }],
                        })
                emit_trace(
                    self.trace, 'input_action', 'function_opened',
                    f'{entry.entry_id}: opened {current.name}',
                    entry_id=entry.entry_id, round=round_index,
                    function=function_ref(current),
                    opened_function_ids=list(opened),
                    candidate_function_ids=[str(item['function_id'])
                                            for item in choices],
                )
                checkpoint = None
                if resumed and round_index > 1:
                    checkpoint = {
                        'functions': [function_payload(
                            self.graph.get(function_id),
                            source_limit=max(1, len(self.graph.get(function_id).source)+1),
                        ) for function_id in opened],
                        'partial_action_drafts': raw_actions,
                    }
                instructions = (
                    'Reconstruct externally selectable Actions from this exact '
                    'first-acquisition Entry. Read one full function source per '
                    'turn and request the next indexed function if needed. '
                    'A source branch is a navigation hint, never an Action by '
                    'itself. An Action is an input-selectable operation with '
                    'a distinct program effect. A parser helper, guard, or '
                    'callback wrapper is not a separate Action without its '
                    'own externally selectable effect. Record source locations '
                    'for the input selector in selection_evidence and the '
                    'resulting effect in effect_evidence. If either is '
                    'unresolved, retain the candidate with an explicit unknown. '
                    'Record '
                    'the selector, handler effect, success evidence, and '
                    'unresolved assumptions. Exact request bytes, numeric '
                    'constants, and examples are resolved AFTER Action selection; '
                    'leave examples empty when unknown, and never withhold an '
                    'otherwise supported Action only because bytes are unknown. '
                    'Inventory externally selectable operations here. Do not '
                    'open a downstream helper solely because it is reachable '
                    'or listed in the navigation frontier. After examining '
                    'source-evidenced selectors and their selected handlers, '
                    'mark context_complete even when speculative graph '
                    'neighbors remain. Record uncertain effects or responses '
                    'as unresolved assumptions for later Action analysis. '
                    'When the current source is a handler named by an earlier '
                    'Action draft, check that draft against the opened body. '
                    'Revise its effect evidence or mark the effect unresolved; '
                    'reading the body alone is not proof. '
                    'Do not claim runtime reachability from source. '
                    'The navigation_tree shows an expandable caller/callee view. '
                    'Set tree_focus_function_id to a shown OR previously opened '
                    'indexed function to browse its children without opening '
                    'source. Set jump_target_function_id to an indexed function '
                    'to continue source reading there; '
                    'Use at most one of tree_focus_function_id, '
                    'jump_target_function_id, requested_function_ids, '
                    'requested_declaration_name, and list_declarations per turn. '
                    'For a macro, struct, union, enum, or class, request its '
                    'name in requested_declaration_name. This direct name lookup '
                    'does not depend on the function tree. Set list_declarations '
                    'to true to list indexed names, optionally narrowed with '
                    'declaration_name_filter. Ambiguous names require file:NAME '
                    'or file:line:NAME. '
                    'The returned source is lexical and may be inactive under '
                    'the build preprocessor configuration.'
                )
                if checkpoint:
                    instructions += (
                        ' Read the full source bodies in the stateful resume '
                        'checkpoint before continuing.'
                    )
                trial_feedback = (
                    self.input_trial_observations.get(entry.entry_id, [])
                    if entry.entry_id not in self._trial_feedback_sent else []
                )
                if trial_feedback:
                    instructions += (
                        ' Original-program input trials are observations only; '
                        'a response alone does not prove Action selection or success.'
                    )
                response = await self.llm.complete_json(
                    role='input_action', instructions=instructions,
                    payload={
                        'entry': _entry_payload(entry),
                        'screened_input_route': ({
                            'path_function_ids': route_path,
                            'evidence': route.evidence if route else [],
                            'source_bodies': [function_payload(self.graph.get(item))
                                              for item in route_path[:-1]]
                                             if round_index == 1 else [],
                            'proof_policy': 'screened path is a source-located candidate, not runtime proof',
                        } if route_path else {}),
                        'input_consumer_worklist': [
                            {'function_id': item, 'path_function_ids': proved_paths[item]}
                            for item in required_consumers if item not in opened
                        ],
                        'round': round_index,
                        'current_function': function_payload(
                            current, source_limit=max(1,len(current.source)+1),
                        ),
                        'opened_functions': [function_ref(self.graph.get(item))
                                             for item in opened],
                        'frontier': choices,
                        'navigation_tree': tree_view,
                        'jump_history': list(jump_history),
                        'operation_seed_hints': [],
                        'netlifter_grammars': [item.prompt_payload()
                                               for item in self.netlifter],
                        'source_backed_input_cases': (
                            self.input_case_hypotheses.get(entry.entry_id, [])
                            if round_index == 1 else []
                        ),
                        'original_input_trials': trial_feedback,
                        **({'current_source_artifact': artifact_pending}
                           if artifact_pending else {}),
                        'declaration_index_count': len(declaration_index),
                        'previous_action_summaries': [
                            _raw_action_summary(item) for item in raw_actions
                        ],
                        'handler_source_review': [
                            _raw_action_summary(item) for item in raw_actions
                            if str(item.get('handler_function_id') or '') ==
                            current.function_id
                        ],
                        **({'review_only': True,
                            'stale_action_drafts': stale_action_drafts,
                            'already_opened_source_bodies': [function_payload(
                                current, source_limit=max(1, len(current.source)+1),
                            )]} if review_only else {}),
                        **({'stateful_resume_checkpoint': checkpoint}
                           if checkpoint else {}),
                    },
                    output_schema=SEMANTIC_INPUT_ACTION_SCHEMA,
                    session_key=self.session_key(entry),
                )
                if trial_feedback:
                    self._trial_feedback_sent.add(entry.entry_id)
                new_actions = object_list(response.get('actions'))
                if review_only:
                    old_keys = {_raw_action_identity(item) for item in raw_actions}
                    reviewed = [item for item in new_actions
                                if _raw_action_identity(item) in old_keys]
                    raw_actions = _merge_raw_action_turn(raw_actions, reviewed)
                    review_only = False
                    stale_action_drafts = []
                else:
                    previous_drafts = [item for item in raw_actions
                        if current.function_id in {
                            str(item.get('handler_function_id') or ''),
                            str(item.get('dispatcher_function_id') or ''),
                        }]
                    new_keys = {_raw_action_identity(item) for item in new_actions}
                    # A navigation-only response is not a revision of Actions
                    # already reported for this function. In particular, do
                    # not let a review turn consume the requested next target.
                    navigating = bool(
                        response.get('requested_function_ids')
                        or response.get('tree_focus_function_id')
                        or response.get('jump_target_function_id')
                        or response.get('requested_declaration_name')
                        or response.get('list_declarations')
                    )
                    stale_action_drafts = ([] if navigating else [
                        item for item in previous_drafts
                        if _raw_action_identity(item) not in new_keys
                    ])
                    raw_actions = _merge_raw_action_turn(raw_actions, new_actions)
                if raw_actions and self.input_case_hypotheses.get(entry.entry_id):
                    await self._match_source_cases_for_ready_actions(
                        entry, raw_actions, opened, {}, attempted_case_matches,
                    )
                if self.early_runtime_hook is not None and raw_actions:
                    trial_actions = self._validate_actions(
                        entry, raw_actions, opened, [], context_complete=False,
                    )
                    fresh = [item for item in trial_actions
                             if item.action_id not in early_submitted]
                    if fresh:
                        await self.early_runtime_hook(fresh)
                        self._early_trial_entries.add(entry.entry_id)
                        early_submitted.update(item.action_id for item in fresh)
                artifact_pending = None
                requested = string_list(response.get('requested_function_ids'))
                tree_request = str(response.get('tree_focus_function_id') or '').strip()
                jump_request = str(response.get('jump_target_function_id') or '').strip()
                declaration_request = str(
                    response.get('requested_declaration_name') or '').strip()
                list_request = bool(response.get('list_declarations'))
                if sum(bool(item) for item in (requested, tree_request,
                                                jump_request, declaration_request,
                                                list_request)) > 1:
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: multiple source-navigation requests '
                        'in one turn; only one is accepted'
                    )
                    if jump_request:
                        requested = []
                        tree_request = ''
                        declaration_request = ''
                        list_request = False
                    elif tree_request:
                        requested = []
                        declaration_request = ''
                        list_request = False
                    elif requested:
                        declaration_request = ''
                        list_request = False
                    elif declaration_request:
                        list_request = False
                if list_request:
                    query = str(response.get('declaration_name_filter') or '')
                    if ('list', query) in declaration_queries_seen:
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: declaration catalog query repeated '
                            f'without a new source question: {query!r}')
                        break
                    declaration_queries_seen.add(('list', query))
                    artifact_pending = {
                        'kind': 'declaration_catalog',
                        'name_filter': query,
                        'names': declaration_index.names(query),
                    }
                    pending = current.function_id
                    continue
                if declaration_request:
                    if ('open', declaration_request) in declaration_queries_seen:
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: declaration already opened: '
                            f'{declaration_request}')
                        break
                    declaration_queries_seen.add(('open', declaration_request))
                    matches = declaration_index.lookup(declaration_request)
                    if len(matches) == 1:
                        definition = matches[0]
                        artifact_pending = {
                            **definition.summary(),
                            'source_excerpt': definition.source,
                        }
                    else:
                        artifact_pending = {
                            'kind': 'declaration_lookup',
                            'requested_name': declaration_request,
                            'reason': ('ambiguous; request file:NAME or file:line:NAME'
                                       if matches
                                       else 'name absent from static declaration index'),
                            'candidates': [item.summary() for item in matches],
                        }
                    pending = current.function_id
                    continue
                if requested and response.get('context_complete'):
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: model claimed Action context complete '
                        'while requesting another source function'
                    )
                selected = ''
                explicit_jump = False
                if jump_request:
                    if jump_request in self.graph.bundle.functions:
                        selected = jump_request
                        explicit_jump = True
                    else:
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: jump target is absent from the '
                            f'indexed functions: {jump_request}'
                        )
                        self._record_action_continuation(
                            entry, opened, [], raw_actions,
                            jump_history=jump_history,
                        )
                        break
                elif tree_request:
                    visible_tree_ids = {
                        tree_view['focus']['function_id'],
                        *(item['function_id'] for item in tree_view['path']),
                        *(item['function_id'] for item in tree_view['children']),
                    }
                    if (tree_request not in visible_tree_ids
                        and tree_request not in opened):
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: requested tree node is not a '
                            f'visible or previously opened indexed function: {tree_request}'
                        )
                        self._record_action_continuation(
                            entry, opened, [], raw_actions,
                            jump_history=jump_history,
                        )
                        break
                    if tree_request == tree_focus:
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: requested tree node is already in focus: '
                            f'{tree_request}'
                        )
                        self._record_action_continuation(
                            entry, opened, [], raw_actions,
                            jump_history=jump_history,
                        )
                        break
                    tree_focus = tree_request
                    if tree_request in opened and tree_request not in tree_path:
                        tree_path = [tree_request]
                    elif tree_request in tree_path:
                        tree_path = tree_path[:tree_path.index(tree_request) + 1]
                    else:
                        tree_path.append(tree_request)
                    pending = current.function_id
                    tree_browse_only = True
                    emit_trace(
                        self.trace, 'input_action', 'tree_expanded',
                        f'{entry.entry_id}: expanded call tree at '
                        f'{self.graph.get(tree_request).name}',
                        entry_id=entry.entry_id,
                        tree_focus_function_id=tree_request,
                        jumps_used=jumps_used,
                    )
                    continue
                else:
                    for item in requested:
                        # Returning to an already read dispatcher is a normal
                        # source-navigation step.  Its body remains in the
                        # stateful session even when it is no longer shown by
                        # the current one-level tree.
                        if item in opened and item in self.graph.bundle.functions:
                            selected = item
                            break
                        selected = resolve_source_linked_function(
                            item, opened, choices, self.graph,
                        )
                        if selected:
                            break
                if not selected and requested and self.source_root:
                    for symbol in requested:
                        definitions = declaration_index.lookup(symbol)
                        if definitions:
                            if ('open', symbol) in declaration_queries_seen:
                                self.inventory_obligations.append(
                                    f'{entry.entry_id}: declaration already opened: '
                                    f'{symbol}')
                                break
                            declaration_queries_seen.add(('open', symbol))
                            artifact_pending = (
                                {**definitions[0].summary(),
                                 'source_excerpt': definitions[0].source}
                                if len(definitions) == 1 else {
                                    'kind': 'declaration_lookup',
                                    'requested_name': symbol,
                                    'reason': 'ambiguous; request file:NAME or file:line:NAME',
                                    'candidates': [item.summary()
                                                   for item in definitions],
                                }
                            )
                            selected = current.function_id
                            break
                        located = _source_linked_declaration_artifact(
                            Path(self.source_root), symbol,
                            [self.graph.get(item) for item in opened],
                            self.graph,
                        )
                        if located is None:
                            continue
                        artifact, offset = located
                        source_path = Path(self.source_root) / artifact.path
                        raw_source = source_path.read_text(encoding='utf-8')
                        # A source initializer is a navigation aid only. Keep
                        # the exact file identity and source bytes visible.
                        referenced = [
                            str(item.get('source') or '')
                            for item in current.referenced_global_declarations
                            if (item.get('file') == artifact.path
                                and item.get('name')
                                and re.search(r'\b' + re.escape(str(item['name']))
                                              + r'\b', _code_only(current.source)))
                        ]
                        excerpt = '\n'.join(referenced) if referenced else raw_source[offset:offset + 4096]
                        artifact_pending = {
                            'path': artifact.path,
                            'sha256': artifact.sha256,
                            'symbol': symbol,
                            'source_excerpt': excerpt,
                        }
                        for candidate in self.graph.bundle.functions.values():
                            if (candidate.function_id not in artifact_targets
                                and re.search(r'\b' + re.escape(candidate.name)
                                              + r'\b', excerpt)):
                                artifact_targets.append(candidate.function_id)
                        selected = current.function_id
                        break
                if artifact_pending:
                    pending = current.function_id
                    continue
                if stale_action_drafts:
                    review_only = True
                    pending = current.function_id
                    stale_action_drafts = list(stale_action_drafts)
                    continue
                # The model may finish the dispatcher walk after naming
                # several selected handlers. Read every indexed source body
                # named by those drafts before validating the Actions; an
                # uninspected handler must not silently remove the candidate.
                if not selected:
                    for draft in raw_actions:
                        for source_id in (
                            str(draft.get('dispatcher_function_id') or ''),
                            str(draft.get('handler_function_id') or ''),
                        ):
                            if (source_id in self.graph.bundle.functions
                                and source_id not in opened):
                                selected = source_id
                                break
                        if selected:
                            break
                if not selected and recorded_next and not resumed_lead_consumed:
                    selected = next((item for item in recorded_next
                                     if item not in opened and item in
                                     self.graph.bundle.functions), '')
                    if selected:
                        recorded_next.remove(selected)
                        resumed_lead_consumed = True
                priority_relations = {
                    'source_linked_value_handoff_candidate',
                    'source_guarded_call_candidate',
                    'parser_output_guard_candidate',
                    'same_receiver_field_candidate',
                    'source_output_parameter_storage_handoff_candidate',
                    'post_read_field_candidate',
                    'post_read_return_caller_candidate',
                    'input_destination_helper_candidate',
                    'same_receiver_return_caller_candidate',
                    'same_receiver_callback_target_candidate',
                    'same_receiver_field_forward_candidate',
                    'same_receiver_field_guard_candidate',
                    'shared_field_return_caller_candidate',
                    'source_field_return_caller_candidate',
                    'source_field_return_consumer_candidate',
                    'source_linked_table_target_candidate',
                    'callback_registration_candidate',
                    'callback_candidate_caller',
                    'callback_candidate',
                }
                remaining = [str(choice['function_id']) for choice in choices
                             if str(choice['function_id']) not in opened
                             and any(connection.get('relation') in priority_relations
                                     for connection in choice.get('connections', [])
                                     if isinstance(connection, dict))]
                if resumed_lead_consumed and recorded_next and not requested:
                    remaining = unique_strings([*recorded_next, *remaining])
                # Only a source-located input handoff or an input-controlled
                # call is compulsory for the Action inventory. The other
                # relations are valuable navigation leads, but chasing every
                # receiver/callback/helper neighbor made a single UDP Entry
                # walk more than a hundred functions without finding new
                # externally selectable operations. Keep those leads in the
                # continuation instead of silently treating them as proved.
                mandatory_remaining = [function_id for function_id in remaining
                    if any(
                        connection.get('relation') == 'source_guarded_call_candidate'
                        or (connection.get('relation') ==
                            'source_linked_value_handoff_candidate'
                            and connection.get('source_located_direct_handoff'))
                        for choice in choices
                        if str(choice['function_id']) == function_id
                        for connection in choice.get('connections', [])
                        if isinstance(connection, dict))]
                if (not selected and len(mandatory_remaining) == 1
                    and not (resumed_lead_consumed and recorded_next)):
                    selected = mandatory_remaining[0]
                if not selected and not raw_actions and len(remaining) > 1:
                    # Before the first Action, an input field may pass through
                    # one return/callback bridge before any direct handoff is
                    # visible. Follow a unique source-connected bridge, but
                    # do not use this rule to sweep effect helpers after the
                    # first external selector has been identified.
                    bridge_relations = {
                        'same_receiver_return_caller_candidate',
                        'same_receiver_callback_target_candidate',
                        'same_receiver_field_forward_candidate',
                        'same_receiver_field_guard_candidate',
                        'source_guarded_call_candidate',
                        'parser_output_guard_candidate',
                        'source_linked_value_handoff_candidate',
                    }
                    bridges = [function_id for function_id in remaining
                        if any(connection.get('relation') in bridge_relations
                               for choice in choices
                               if str(choice['function_id']) == function_id
                               for connection in choice.get('connections', [])
                               if isinstance(connection, dict))]
                    if len(bridges) == 1:
                        selected = bridges[0]
                if (not selected and not raw_actions and len(remaining) == 1
                    and not (resumed_lead_consumed and recorded_next)):
                    only = next((choice for choice in choices
                                 if str(choice['function_id']) == remaining[0]), None)
                    connections = only.get('connections', []) if only else []
                    tentative_only = bool(connections) and all(
                        connection.get('relation') in {
                            'source_linked_table_target_candidate',
                            'callback_registration_candidate',
                            'shared_typed_field_candidate',
                        } or (connection.get('relation') ==
                              'source_linked_value_handoff_candidate'
                              and not connection.get('source_located_direct_handoff'))
                        for connection in connections
                        if isinstance(connection, dict))
                    if not tentative_only:
                        selected = remaining[0]
                if selected:
                    local_targets = {
                        str(item['function_id']) for item in
                        self.graph.frontier([current.function_id])
                    }
                    local_targets.update(
                        str(choice['function_id']) for choice in choices
                        if any(
                            connection.get('source_function_id') == current.function_id
                            or connection.get('connected_function_id') == current.function_id
                            for connection in choice.get('connections', [])
                            if isinstance(connection, dict)
                        )
                    )
                    if explicit_jump or selected not in local_targets:
                        pending_jump_from = current.function_id
                    pending = selected
                    continue
                complete = bool(response.get('context_complete')) and not remaining
                if not response.get('context_complete'):
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: Action source walk is incomplete at '
                        f'{current.function_id}; no next function was requested'
                    )
                if remaining:
                    tentative = [function_id for function_id in remaining
                                 if any(
                                     connection.get('relation') ==
                                     'source_linked_value_handoff_candidate'
                                     and not connection.get(
                                         'source_located_direct_handoff')
                                     for choice in choices
                                     if str(choice['function_id']) == function_id
                                     for connection in choice.get('connections', [])
                                     if isinstance(connection, dict))]
                    if tentative:
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: source-linked input-consumer '
                            'candidate(s) need further evidence: '
                            + ', '.join(tentative)
                        )
                    else:
                        self.inventory_obligations.append(
                            f'{entry.entry_id}: direct input-fed function(s) remained '
                            'uninspected: ' + ', '.join(remaining)
                        )
                self._record_action_continuation(entry, opened, remaining,
                                                 raw_actions,
                                                 jump_history=jump_history)
                if requested and not selected:
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: requested Action function is absent '
                        'from the index, ambiguous, or already opened: '
                        + ', '.join(requested)
                    )
                break
            else:
                choices = self._choices(opened, [], entry)
                remaining = [str(item['function_id']) for item in choices
                             if str(item['function_id']) not in opened]
                self._record_action_continuation(entry, opened, remaining,
                                                 raw_actions,
                                                 jump_history=jump_history)
                if remaining:
                    self.inventory_obligations.append(
                        f'{entry.entry_id}: source walk stopped with uninspected '
                        'functions: ' + ', '.join(remaining)
                    )
        except Exception as exc:
            infrastructure_failure = (
                f'{entry.entry_id}: input-action session interrupted with '
                f'{type(exc).__name__}: {exc}'
            )
            self.infrastructure_failures.append(infrastructure_failure)
            if raw_actions:
                self._record_action_continuation(
                    entry, opened, [pending] if pending not in opened else [],
                    raw_actions, jump_history=jump_history,
                )
            if (_is_non_retryable_infrastructure_failure(exc)
                or isinstance(exc, (NameError, TypeError, AttributeError))):
                raise
        finally:
            await close_llm_session(self.llm, self.session_key(entry))
        root_function = self.graph.get(root)
        if (not _entry_destination_names(root_function, entry)
            and _entry_destination_helper_ids(root_function, entry, self.graph)):
            self.inventory_obligations.append(
                f'{entry.entry_id}: acquisition destination was not resolved '
                'through the opened helper source'
            )
            complete = False
        if (not root_function.external_call_sites
            and _entry_destination_names(root_function, entry)):
            self.inventory_obligations.append(
                f'{entry.entry_id}: input-control analysis did not complete; '
                'Clang declaration identity is unavailable'
            )
            complete = False
        callback_invokers = {invoker_id for invoker_id, _target_id
                             in self.graph._callback_slot_hints()}
        for caller in self.graph.callers(entry.entry_function_id):
            if (caller.function_id in callback_invokers
                and caller.function_id not in opened
                and not _same_receiver_return_callbacks(
                    self.graph, entry, caller,
                )):
                self.inventory_obligations.append(
                    f'{entry.entry_id}: callback caller {caller.function_id} '
                    'has unresolved input-value flow on the acquisition receiver'
                )
        # A model's context_complete response cannot close input-bearing
        # source consumers that have never been inspected. Preserve them as
        # obligations without launching one LLM turn per possible helper.
        complete = complete and all(item in opened for item in required_consumers)
        unread_action_sources = unique_strings(
            source_id
            for draft in raw_actions
            for source_id in (
                str(draft.get('dispatcher_function_id') or ''),
                str(draft.get('handler_function_id') or ''),
            )
            if source_id and source_id not in opened
        )
        if unread_action_sources:
            self.inventory_obligations.append(
                f'{entry.entry_id}: Action source bodies were not inspected: '
                + ', '.join(unread_action_sources)
            )
            self._record_action_continuation(
                entry, opened,
                [item for item in unread_action_sources
                 if item in self.graph.bundle.functions],
                raw_actions, jump_history=jump_history,
            )
            complete = False
        actions = self._validate_actions(
            entry, raw_actions, opened, [],
            context_complete=complete and not infrastructure_failure,
            direct_consumer_ids=set(proved_paths),
        )
        source_work_ids = set(candidate_paths) | set(proved_paths) | set(route_path)
        for function_id in sorted(source_work_ids):
            if function_id == root:
                continue
            path = proved_paths.get(function_id) or candidate_paths.get(function_id) or route_path
            basis = ('source_located_direct_handoff' if function_id in proved_paths
                     else 'screened_route' if function_id in route_path
                     else 'candidate_handoff')
            disposition = ('INSPECTED' if function_id in opened
                           else 'UNRESOLVED')
            self.source_coverage.append({
                'entry_id': entry.entry_id,
                'function_id': function_id,
                'path_function_ids': path,
                'basis': basis,
                'disposition': disposition,
                'action_ids': [item.action_id for item in actions
                               if item.dispatcher_function_id == function_id
                               or item.handler_function_id == function_id],
            })
            if disposition == 'UNRESOLVED':
                self.inventory_obligations.append(
                    f'{entry.entry_id}: input-consumer {function_id} remains '
                    f'uninspected ({basis})'
                )
        if proved_flow_incomplete or candidate_flow_incomplete:
            self.inventory_obligations.append(
                f'{entry.entry_id}: input-consumer source analysis was incomplete'
            )
        flow_names = {
            function_id: names
            for function_id, _path, names in [*proved_consumers, *candidate_consumers]
        }
        input_route_functions = {root, *route_path, *proved_paths, *candidate_paths}
        for function_id in opened:
            if function_id not in input_route_functions:
                continue
            function = self.graph.get(function_id)
            names = (_entry_destination_names(function, entry)
                     if function_id == root else flow_names.get(function_id))
            for seed in extract_operation_seeds(
                [function], self.graph, input_symbols=names,
            ):
                if seed.status is ProofStatus.REFUTED:
                    continue
                if (seed.evidence_kind != 'switch_case'
                    and not _looks_like_external_command_selector(seed.discriminator)):
                    continue
                matches = [action.action_id for action in actions
                           if action.dispatcher_function_id == function_id
                           and _discriminator_key(action.discriminator)
                               == _discriminator_key(seed.discriminator)]
                self.selector_hints.append({
                    'entry_id': entry.entry_id,
                    'function_id': function_id,
                    'line': seed.line,
                    'discriminator': seed.discriminator,
                    'evidence_kind': seed.evidence_kind,
                    'disposition': ('ACTION_CANDIDATE' if matches
                                    else 'UNREVIEWED_SYNTAX_HINT'),
                    'action_ids': matches,
                    'proof_policy': (
                        'syntax in an input-route function is only a recall hint; '
                        'it does not prove external selection or an Action'
                    ),
                })
        if infrastructure_failure:
            actions = [replace(action, status=ProofStatus.POSSIBLE,
                               unknowns=unique_strings([
                                   *action.unknowns,
                                   'input-action source session interrupted',
                               ])) for action in actions]
        if not actions and not infrastructure_failure:
            self.inventory_obligations.append(
                f'{entry.entry_id}: no external Action reconstructed; '
                'produced no source-backed external Action candidate'
            )
        emit_trace(
            self.trace, 'input_action', 'entry_completed',
            f'{entry.entry_id}: reconstructed {len(actions)} actions',
            entry_id=entry.entry_id, actions=actions,
            opened_function_ids=opened,
        )
        return actions, []

    async def _match_source_cases_for_ready_actions(
        self, entry: EntryRecord, raw_actions: list[dict[str, Any]],
        opened: list[str], _known: dict[str, Any],
        attempted: set[tuple[str, str]],
    ) -> None:
        """Attach a source-cited input hypothesis for original-program trial.

        A match remains a POSSIBLE request hypothesis. It never proves byte
        selection, handler reachability, success, or a valid harness.
        """
        cases = {str(item.get('case_id') or ''): item for item in
                 self.input_case_hypotheses.get(entry.entry_id, [])
                 if isinstance(item, dict) and item.get('case_id')}
        ready = [item for item in raw_actions
                 if item.get('handler_function_id') in opened
                 and item.get('dispatcher_function_id') in opened
                 and not item.get('examples')]
        for action in ready:
            handler_id = str(action.get('handler_function_id') or '')
            available_case_ids = [case_id for case_id in cases
                                  if (handler_id, case_id) not in attempted]
            if not available_case_ids:
                continue
            attempted.update((handler_id, case_id)
                             for case_id in available_case_ids)
            # Keep the same one-source-body-per-turn contract as the Action
            # walk. The dispatcher is the relevant source for byte selection;
            # use a branchless handler when no dispatcher body was opened.
            source_id = str(action.get('dispatcher_function_id') or '')
            if source_id not in opened:
                source_id = handler_id
            if source_id not in opened or source_id not in self.graph.bundle.functions:
                continue
            source = self.graph.get(source_id)
            response = await self.llm.complete_json(
                role='input_action',
                instructions=(
                    'Match only exact supplied input cases to this opened Action source. '
                    'Cite a line in the single supplied function body. A match is '
                    'trial-only and does not prove runtime selection or success.'
                ),
                payload={
                    'entry': _entry_payload(entry),
                    'actions': [_raw_action_summary(action)],
                    'cases': [cases[case_id] for case_id in available_case_ids],
                    'current_function': function_payload(
                        source, source_limit=max(1, len(source.source)+1)),
                },
                output_schema=SOURCE_CASE_MATCH_SCHEMA,
                session_key=self.session_key(entry),
            )
            for match in object_list(response.get('matches')):
                case = cases.get(str(match.get('case_id') or ''))
                if (case is None
                    or match.get('case_id') not in available_case_ids
                    or action.get('name') != match.get('action_name')
                    or handler_id != match.get('handler_function_id')):
                    continue
                evidence = _validated_evidence(match.get('evidence'), {source_id},
                                               self.graph)
                if not any(item.line is not None for item in evidence):
                    continue
                data_hex = str(case.get('data_hex') or '').lower()
                if not _valid_hex(data_hex, allow_empty=False):
                    continue
                action.setdefault('examples', []).append({
                    'data_hex': data_hex, 'bindings': [],
                    'rationale': str(match.get('rationale') or ''),
                    'origin': 'matched_source_case_hypothesis',
                    'evidence': [dict(kind=item.kind,
                        function_id=item.function_id, line=item.line,
                        detail=item.detail) for item in evidence],
                })

    def _record_action_continuation(
        self, entry: EntryRecord, opened: list[str], remaining: list[str],
        raw_actions: list[dict[str, Any]],
        *, jump_history: list[dict[str, str]] | None = None,
    ) -> None:
        self.continuations = [item for item in self.continuations
                              if item.get('entry_id') != entry.entry_id]
        self.continuations.append({
            'entry_id': entry.entry_id,
            'opened_function_ids': list(opened),
            'next_function_ids': unique_strings(remaining),
            'partial_action_drafts': list(raw_actions),
            'jump_history': list(jump_history or []),
            'source_fingerprints': {
                function_id: stable_id(
                    'source', self.graph.get(function_id).source,
                ) for function_id in unique_strings([*opened, *remaining])
                if function_id in self.graph.bundle.functions
            },
        })

    def _direct_entry_path(self, entry: EntryRecord) -> list[str]:
        result = [entry.entry_function_id]
        inspected = set(entry.inspected_function_ids)
        # Preserve verifier-opened callback registrations. They are needed to
        # turn a line-less points-to candidate into an evidenced callback
        # return path during action validation.
        result.extend(
            edge.caller_id
            for edge in self.graph.bundle.edges
            if edge.kind == "function_reference"
            and edge.line is not None
            and edge.callee_id == entry.entry_function_id
            and edge.caller_id in inspected
        )
        registration_ids = set(result[1:])
        if not entry.consumer_hints:
            result.extend(
                function.function_id
                for function in self.graph.callback_invocation_callers(
                    entry.entry_function_id,
                    registration_function_ids=registration_ids,
                )
                if function.function_id in inspected
            )
        by_name: dict[str, list[str]] = {}
        for function in self.graph.bundle.functions.values():
            by_name.setdefault(function.name, []).append(function.function_id)
        for hint in entry.consumer_hints:
            matches = (
                [hint]
                if hint in self.graph.bundle.functions
                else by_name.get(hint, [])
            )
            if len(matches) != 1:
                continue
            path = self.graph.causal_path_from_entry(
                entry.entry_function_id,
                matches[0],
                opened_function_ids={
                    entry.entry_function_id,
                    matches[0],
                    *entry.inspected_function_ids,
                },
                max_return_depth=len(self.graph.bundle.functions),
                max_forward_depth=len(self.graph.bundle.functions),
            )
            # A model-authored consumer hint is navigation guidance, not
            # provenance.  Only force it into the immutable Entry prefix when
            # the source graph actually connects it to the acquisition
            # function.  Unconnected hints remain selectable in ``_choices``
            # and cannot fabricate an Entry-to-dispatcher proof.
            if path:
                result.extend(path)
        return unique_strings(result)

    def _candidate_entry_path(self, entry: EntryRecord) -> list[str]:
        """Open a source-located callback route without granting proof.

        Consumer hints are not evidence. They only restrict the otherwise
        enormous number of possible targets for a bounded navigation pass.
        Source proof is recomputed independently in `_validate_actions`.
        """
        root = entry.entry_function_id
        functions_by_name: dict[str, list[str]] = {}
        for function in self.graph.bundle.functions.values():
            functions_by_name.setdefault(function.name, []).append(function.function_id)
        for hint in entry.consumer_hints:
            candidates = (
                [hint] if hint in self.graph.bundle.functions
                else functions_by_name.get(hint, [])
            )
            if len(candidates) != 1:
                continue
            path = self.graph.callback_navigation_path(root, candidates[0])
            if len(path) > 1 and len(path) <= self.budget:
                return path
        return []

    async def _run_seed_group(
        self,
        items: list[tuple[EntryRecord, OperationSeed, str]],
    ) -> list[tuple[list[ExternalActionSchema], list[OperationSeed], ProofStatus, str]]:
        """One source walk per shared path; unresolved cases fall back individually.

        A group never receives shared proof merely because another case in
        that group was understood.  Every action must match its own extracted
        discriminator and handler, and every negative verdict cites source.
        """
        if len(items) == 1:
            return [await self._run_seed_branch(items[0])]
        entry, first_seed, handler_id = items[0]
        seeds = [item[1] for item in items]
        if any(
            item[0].entry_id != entry.entry_id
            or item[1].dispatcher_function_id != first_seed.dispatcher_function_id
            or item[2] != handler_id
            for item in items
        ):
            raise ValueError("grouped action cases have different source paths")

        navigation = [
            function_id for function_id in unique_strings([
                *first_seed.entry_path_function_ids, entry.entry_function_id,
            ]) if function_id in self.graph.bundle.functions
        ]
        forced = [
            function_id for function_id in unique_strings([
                first_seed.dispatcher_function_id, handler_id,
            ]) if function_id in self.graph.bundle.functions
        ]
        if handler_id not in forced:
            return [([], [], ProofStatus.POSSIBLE, "selected handler is absent") for _ in items]

        opened: list[str] = []
        raw_actions: list[dict[str, Any]] = []
        per_seed_disposition: dict[str, tuple[str, list[Evidence]]] = {}
        discovered: list[OperationSeed] = []
        complete = False
        infrastructure_failure = ""
        latest_rationale = ""
        pending = forced[0]
        session = "input_action:group:" + stable_id(
            "action-path", entry.entry_id, handler_id,
            *[seed.operation_seed_id for seed in seeds],
        )
        try:
            for round_index in range(1, min(self.budget, self.branch_context_budget) + 1):
                if pending in opened or pending not in self.graph.bundle.functions:
                    break
                current = self.graph.get(pending)
                opened.append(pending)
                next_forced = next((fid for fid in forced if fid not in opened), "")
                choices = self._branch_choices(
                    opened,
                    dispatcher_function_id=first_seed.dispatcher_function_id,
                    handler_function_id=handler_id,
                    return_path_function_ids=navigation,
                    discriminator=" ".join(seed.discriminator for seed in seeds),
                )
                if next_forced:
                    choices = [
                        {**function_ref(self.graph.get(next_forced)),
                         "connections": [{"relation": "required_seed_path"}]},
                        *[choice for choice in choices
                          if str(choice["function_id"]) != next_forced],
                    ]
                emit_trace(
                    self.trace, "input_action", "branch_group_function_opened",
                    f"opened {current.name} once for {len(seeds)} operation cases",
                    entry_id=entry.entry_id,
                    operation_seed_ids=[seed.operation_seed_id for seed in seeds],
                    handler_function_id=handler_id,
                    round=round_index,
                    function=function_ref(current),
                )
                response = await self.llm.complete_json(
                    role="input_action",
                    instructions=(
                        "Analyze this exact shared Entry/dispatcher/handler source path for "
                        "ALL selected_operation_seeds in one pass. Every seed is a "
                        "different possible EXTERNAL request branch. Return a separate "
                        "branch_dispositions record for EVERY seed ID, including unresolved "
                        "ones. Emit an action for each independently source-supported "
                        "request, with its exact discriminator and selected handler. "
                        "Reconstruct complete external wire bytes, not a post-parse value. "
                        "Do not claim a command is client-controlled if these bytes "
                        "actually originate from a remote-backend response or lifecycle "
                        "state. Return NOT_ACTION only with opened dispatcher-line evidence. "
                        "Never transfer evidence or proof between cases. Cite exact opened "
                        "dispatcher and handler lines for every action, and cite separately "
                        "any success/failure response markers. Treat paths containing "
                        "unproven callback links as navigation hints, not causal proof. "
                        "Request at most one next function. Do not invent state, "
                        "request bytes, or runtime success."
                    ),
                    payload={
                        "entry": _entry_payload(entry),
                        "selected_operation_seeds": [_seed_payload(seed) for seed in seeds],
                        "selected_handler_function_id": handler_id,
                        "entry_navigation_path": [
                            function_ref(self.graph.get(fid)) for fid in navigation
                        ],
                        "entry_path_proof_statuses": {
                            seed.operation_seed_id: str(seed.status) for seed in seeds
                        },
                        "round": round_index,
                        "current_function": function_payload(
                            current,
                            focus_line=(first_seed.line if current.function_id
                                        == first_seed.dispatcher_function_id else None),
                        ),
                        "opened_functions": [
                            function_ref(self.graph.get(fid)) for fid in opened
                        ],
                        "frontier": choices,
                        "nested_operation_seed_hints": [
                            _seed_payload(seed) for seed in extract_operation_seeds(
                                [current], self.graph
                            )
                        ],
                        "netlifter_grammars": [g.prompt_payload() for g in self.netlifter],
                        "previous_action_summaries": [
                            _raw_action_summary(action) for action in raw_actions
                        ],
                    },
                    output_schema=GROUP_INPUT_ACTION_SCHEMA,
                    session_key=session,
                )
                raw_actions.extend(object_list(response.get("actions")))
                latest_rationale = str(response.get("rationale", ""))
                allowed_seed_ids = {seed.operation_seed_id for seed in seeds}
                for disposition in object_list(response.get("branch_dispositions")):
                    seed_id = str(disposition.get("operation_seed_id", ""))
                    if seed_id not in allowed_seed_ids:
                        continue
                    evidence = _validated_evidence(
                        disposition.get("evidence"), set(opened), self.graph,
                    )
                    per_seed_disposition[seed_id] = (
                        str(disposition.get("disposition", "UNRESOLVED")),
                        evidence,
                    )
                if next_forced:
                    pending = next_forced
                    continue
                complete = bool(response.get("context_complete", False))
                if complete:
                    break
                requested = string_list(response.get("requested_function_ids"))
                allowed = {str(choice["function_id"]) for choice in choices}
                pending = resolve_source_linked_function(
                    requested[0] if requested else "", opened, choices, self.graph,
                )
                if not pending:
                    break
        except Exception as exc:
            infrastructure_failure = (
                f"shared branch source walk failed with {type(exc).__name__}: {exc}"
            )
            self.infrastructure_failures.append(infrastructure_failure)
            if _is_non_retryable_infrastructure_failure(exc):
                raise
        finally:
            await close_llm_session(self.llm, session)

        if infrastructure_failure:
            return [([], [], ProofStatus.POSSIBLE, infrastructure_failure) for _ in items]

        validated = self._validate_actions(
            entry, raw_actions, opened, seeds,
            context_complete=complete, proof_path_ids=navigation,
        )
        # A nested dispatcher discovered in a shared handler belongs to that
        # source path, not one arbitrarily chosen discriminator. Include it in
        # the first result only. The outer scheduler deduplicates every seed ID.
        if any(
            disposition == "ACTION"
            and any(item.function_id == handler_id for item in evidence)
            for disposition, evidence in per_seed_disposition.values()
        ):
            handler = self.graph.get(handler_id)
            for nested in extract_operation_seeds([handler], self.graph):
                if nested.operation_seed_id not in {
                    seed.operation_seed_id for seed in seeds
                }:
                    discovered.append(replace(
                        nested,
                        entry_path_function_ids=unique_strings([
                            *navigation, first_seed.dispatcher_function_id,
                            handler_id,
                        ]),
                    ))

        results: list[tuple[list[ExternalActionSchema], list[OperationSeed], ProofStatus, str]] = []
        for index, item in enumerate(items):
            seed = item[1]
            matching = [
                action for action in validated
                if seed.operation_seed_id in action.operation_seed_ids
                and action.handler_function_id == handler_id
            ]
            if matching and complete:
                status = (
                    ProofStatus.PROVEN_STATIC if any(
                        action.status is ProofStatus.PROVEN_STATIC for action in matching
                    ) else ProofStatus.POSSIBLE
                )
                results.append((matching, discovered if index == 0 else [], status,
                                latest_rationale))
                continue
            # A group-wide negative classification is not enough to erase a
            # candidate. Confirm it with the existing isolated worker, just
            # like an omitted or unresolved group label.
            self.branch_group_fallbacks += 1
            fallback = await self._run_seed_branch(item)
            results.append((fallback[0], [*(discovered if index == 0 else []),
                                          *fallback[1]], fallback[2],
                            "group unresolved; " + fallback[3]))
        emit_trace(
            self.trace, "input_action", "branch_group_completed",
            f"reviewed {len(items)} cases on a shared source path",
            entry_id=entry.entry_id,
            handler_function_id=handler_id,
            operation_seed_ids=[seed.operation_seed_id for seed in seeds],
            static_actions=sum(
                action.status is ProofStatus.PROVEN_STATIC
                for actions, *_ in results for action in actions
            ),
        )
        return results

    async def _run_seed_branch(
        self,
        item: tuple[EntryRecord, OperationSeed, str],
    ) -> tuple[
        list[ExternalActionSchema], list[OperationSeed], ProofStatus, str
    ]:
        entry, root_seed, handler_id = item
        # The prefix may be a callback NAVIGATION CANDIDATE, not a proven
        # causal path. Avoid reopening the same source in every branch, but
        # never turn this saved prefix into a trusted provenance fact.
        entry_navigation_path = unique_strings([
            *root_seed.entry_path_function_ids,
            entry.entry_function_id,
        ])
        entry_navigation_path = [
            value for value in entry_navigation_path
            if value in self.graph.bundle.functions
        ]
        forced = unique_strings([
            root_seed.dispatcher_function_id,
            handler_id,
        ])
        forced = [item for item in forced if item in self.graph.bundle.functions]
        if handler_id not in forced:
            return [], [], ProofStatus.POSSIBLE, "selected handler is absent"
        opened: list[str] = []
        raw_actions: list[dict[str, Any]] = []
        discovered: list[OperationSeed] = []
        pending = forced[0]
        complete = False
        latest_response: dict[str, Any] = {}
        root_disposition = ""
        root_disposition_evidence: list[Evidence] = []
        infrastructure_failure = ""
        session_key = (
            f"input_action:{entry.entry_id}:{root_seed.operation_seed_id}:{handler_id}"
        )
        try:
            for round_index in range(1, min(self.budget, self.branch_context_budget) + 1):
                if pending in opened or pending not in self.graph.bundle.functions:
                    break
                opened.append(pending)
                current = self.graph.get(pending)
                # These local branches help the model understand the selected
                # handler, but are not enqueued as new external operations.
                nested = extract_operation_seeds([current], self.graph)
                choices = self._branch_choices(
                    opened,
                    dispatcher_function_id=root_seed.dispatcher_function_id,
                    handler_function_id=handler_id,
                    return_path_function_ids=entry_navigation_path,
                    discriminator=root_seed.discriminator,
                )
                next_forced = next(
                    (function_id for function_id in forced if function_id not in opened),
                    "",
                )
                if next_forced:
                    choices = [
                        {
                            **function_ref(self.graph.get(next_forced)),
                            "connections": [{"relation": "required_seed_path"}],
                        },
                        *[
                            choice for choice in choices
                            if str(choice["function_id"]) != next_forced
                        ],
                    ]
                emit_trace(
                    self.trace, "input_action", "branch_function_opened",
                    f"{root_seed.operation_seed_id} ({root_seed.discriminator}): opened {current.name}",
                    entry_id=entry.entry_id,
                    operation_seed_id=root_seed.operation_seed_id,
                    discriminator=root_seed.discriminator,
                    handler_function_id=handler_id,
                    round=round_index,
                    function=function_ref(current),
                    opened_function_ids=list(opened),
                )
                response = await self.llm.complete_json(
                    role="input_action",
                    instructions=(
                        "Validate exactly one source-located dispatcher branch as an externally expressible action. "
                        "The Entry-to-dispatcher navigation prefix MAY include unproven callback links; "
                        "do not cite it as causal proof. Only opened source and exact runtime attribution may "
                        "establish reachability. The dispatcher and selected handler "
                        "are opened one function per turn before free exploration. Reconstruct complete external "
                        "request bytes, not a post-parse object. If length/checksum fields are source-proven, "
                        "use relation=length_of(field_name) or crc32_of(field_name) and include each referenced field "
                        "in the request fields with line evidence. Never invent a checksum algorithm. "
                        "An opened project usage candidate may establish request "
                        "layout or ordering; label and cite it, but never treat it as a product Entry or reachability proof. Cite the "
                        "real dispatcher and handler lines. Return literal success/failure response markers only "
                        "when separately cited success_evidence/failure_evidence establishes their meanings. If this "
                        "action returns a fixed-width value that a later external request must reuse, report it in "
                        "response_bindings with the exact byte offset/width in the external response and cite the "
                        "opened response-serialization source. Do not describe a variable-length or inferred token as "
                        "fixed-width. If this "
                        "current opened function contains a nested dispatcher, report its actions "
                        "but do not collapse unrelated operations. branch_disposition always classifies branches "
                        "of current_function: ACTION only when they select operations controlled by bytes from the "
                        "verified external request, NOT_ACTION for lifecycle, allocator, retry, response-state, or "
                        "ordinary validation branches, and UNRESOLVED otherwise. Cite current_function in "
                        "branch_disposition_evidence. Request at most one next function and never claim runtime "
                        "reachability or state prerequisites."
                    ),
                    payload={
                        "entry": _entry_payload(entry),
                        "selected_operation_seed": _seed_payload(root_seed),
                        "selected_handler_function_id": handler_id,
                        "entry_navigation_path": [
                            function_ref(self.graph.get(value))
                            for value in entry_navigation_path
                        ],
                        "entry_path_proof_status": str(root_seed.status),
                        "round": round_index,
                        "current_function": function_payload(
                            current,
                            source_limit=max(1, len(current.source) + 1),
                            focus_line=(
                                root_seed.line
                                if current.function_id
                                == root_seed.dispatcher_function_id
                                else None
                            ),
                        ),
                        "opened_functions": [function_ref(self.graph.get(value)) for value in opened],
                        "frontier": choices,
                        "nested_operation_seed_hints": [_seed_payload(value) for value in nested],
                        "netlifter_grammars": [value.prompt_payload() for value in self.netlifter],
                        "previous_action_summaries": [_raw_action_summary(value) for value in raw_actions],
                    },
                    output_schema=INPUT_ACTION_SCHEMA,
                    session_key=session_key,
                )
                latest_response = response
                raw_actions.extend(object_list(response.get("actions")))
                current_disposition = str(
                    response.get("branch_disposition", "")
                )
                current_disposition_evidence = _validated_evidence(
                    response.get("branch_disposition_evidence"),
                    set(opened),
                    self.graph,
                )
                if current.function_id == root_seed.dispatcher_function_id:
                    root_disposition = current_disposition
                    root_disposition_evidence = current_disposition_evidence
                if (
                    nested
                    and current_disposition == "ACTION"
                    and current.function_id in {
                        item.function_id
                        for item in current_disposition_evidence
                    }
                ):
                    nested_path = self.graph.causal_path_from_entry(
                        handler_id,
                        current.function_id,
                        opened_function_ids=opened,
                        max_return_depth=0,
                        max_forward_depth=64,
                    )
                    if current.function_id == handler_id:
                        nested_path = [handler_id]
                    if nested_path:
                        discovered.extend(
                            replace(
                                item,
                                entry_path_function_ids=unique_strings([
                                    *entry_navigation_path,
                                    root_seed.dispatcher_function_id,
                                    *nested_path,
                                ]),
                            )
                            for item in nested
                            if item.operation_seed_id
                            != root_seed.operation_seed_id
                        )
                if next_forced:
                    pending = next_forced
                    continue
                complete = bool(response.get("context_complete", False))
                if complete:
                    break
                requested = string_list(response.get("requested_function_ids"))
                allowed = {str(choice["function_id"]) for choice in choices}
                pending = resolve_source_linked_function(
                    requested[0] if requested else "", opened, choices, self.graph,
                )
                if not pending:
                    break
        except Exception as exc:
            infrastructure_failure = (
                f"{root_seed.operation_seed_id}/{handler_id}: input-action branch "
                f"failed with {type(exc).__name__}: {exc}"
            )
            self.infrastructure_failures.append(infrastructure_failure)
            if _is_non_retryable_infrastructure_failure(exc):
                raise
        finally:
            await close_llm_session(self.llm, session_key)
        actions = (
            [] if infrastructure_failure else
            self._validate_actions(
                entry, raw_actions, opened, [root_seed],
                context_complete=complete,
                proof_path_ids=entry_navigation_path,
            )
        )
        # A branch session cannot validate a different top-level handler by
        # accident.  Nested seeds are returned separately only after the
        # containing function was explicitly classified as an external
        # dispatcher above; they receive their own later-wave validation and
        # cannot masquerade as the selected parent handler here.
        actions = [
            action for action in actions
            if action.handler_function_id == handler_id
        ]
        proven = any(
            action.status is ProofStatus.PROVEN_STATIC for action in actions
        )
        branch_status = (
            ProofStatus.PROVEN_STATIC if proven else ProofStatus.POSSIBLE
        )
        branch_rationale = str(latest_response.get("rationale", "")).strip()
        if (
            not proven
            and complete
            and root_disposition == "NOT_ACTION"
        ):
            if root_seed.dispatcher_function_id in {
                item.function_id for item in root_disposition_evidence
            }:
                branch_status = ProofStatus.REFUTED
            else:
                branch_rationale = (
                    branch_rationale
                    + "; NOT_ACTION lacked dispatcher source evidence"
                ).strip("; ")
        emit_trace(
            self.trace, "input_action", "branch_completed",
            f"{root_seed.operation_seed_id}: validated {len(actions)} actions",
            entry_id=entry.entry_id,
            operation_seed_id=root_seed.operation_seed_id,
            discriminator=root_seed.discriminator,
            handler_function_id=handler_id,
            actions=actions,
            branch_status=branch_status,
            branch_rationale=branch_rationale,
            infrastructure_failure=infrastructure_failure,
        )
        return (
            actions,
            merge_operation_seed_records(discovered),
            branch_status,
            branch_rationale,
        )

    def _choices(
        self, opened: list[str], seeds: list[OperationSeed],
        entry: EntryRecord, *, focus_function_id: str = "",
    ) -> list[dict[str, object]]:
        """Offer source-linked input consumers without making branch jobs."""
        choices: dict[str, dict[str, object]] = {}
        opened_set = set(opened)

        def add(function_id: str, relation: str, **details: object) -> None:
            function = self.graph.bundle.functions.get(function_id)
            if function is None or function_id in opened_set:
                return
            connection = {"relation": relation, **details}
            if function_id not in choices:
                choices[function_id] = {
                    **function_ref(function), "connections": [connection],
                }
            elif connection not in choices[function_id]["connections"]:
                choices[function_id]["connections"].append(connection)

        leads, _ = self._source_consumers(entry, include_candidate_edges=True)
        proved_leads, _ = self._source_consumers(entry, include_candidate_edges=False)
        proved_ids = {item[0] for item in proved_leads}
        taint_by_function: dict[str, set[str]] = {}
        for function_id, path, names in leads:
            taint_by_function.setdefault(function_id, set()).update(names)
            source_id = path[-2] if len(path) > 1 else entry.entry_function_id
            if source_id not in opened_set:
                continue
            edge_lines = [edge.line for edge in self.graph.bundle.edges
                          if edge.caller_id == source_id
                          and edge.callee_id == function_id
                          and edge.line is not None]
            add(function_id, "source_linked_value_handoff_candidate",
                source_function_id=source_id,
                source_line=min(edge_lines) if edge_lines else None,
                source_located_direct_handoff=function_id in proved_ids,
                proof_policy="navigation only; original runtime must confirm")

        for function_id in opened:
            function = self.graph.bundle.functions.get(function_id)
            if function is None:
                continue
            names = (_entry_destination_names(function, entry)
                     if function_id == entry.entry_function_id
                     else taint_by_function.get(function_id, set()))
            if names:
                guarded, unresolved = _input_controlled_call_candidates(
                    self.graph, function, names,
                    entry=entry if function_id == entry.entry_function_id else None,
                )
                for target_id in guarded:
                    source_guard = next((site for site in function.guarded_call_sites
                        if _resolve_guard_target(self.graph, function, site)[0]
                           == target_id), {})
                    add(target_id, "source_guarded_call_candidate",
                        source_function_id=function_id,
                        source_line=source_guard.get('call_line'),
                        guard_line=source_guard.get('guard_line'),
                        proof_policy="navigation only; input guard is not an Action")
                for reason in unresolved:
                    if reason not in self.inventory_obligations:
                        self.inventory_obligations.append(reason)
            producer_ids = {str(site.get("callee_function_id") or "")
                            for site in function.direct_call_sites
                            if site.get("callee_function_id") in self.graph.bundle.functions}
            for target_id in _producer_output_guard_candidates(
                self.graph, function, producer_ids,
            ):
                add(target_id, "parser_output_guard_candidate",
                    source_function_id=function_id,
                    proof_policy="navigation only; parser output requires validation")

        root = self.graph.bundle.functions.get(entry.entry_function_id)
        if root is not None:
            for target_id in _entry_destination_helper_ids(root, entry, self.graph):
                add(target_id, "input_destination_helper_candidate")
            for target_id in source_receiver_field_navigation_candidates(
                self.graph, entry,
            ):
                add(target_id, "same_receiver_field_candidate")
            receiver_fields = _entry_receiver_field_names(root, entry)
            for opened_id in opened:
                if opened_id == root.function_id:
                    continue
                current = self.graph.bundle.functions.get(opened_id)
                if current is None:
                    continue
                code = _code_only(current.source)
                parameter_ids = {str(item.get('declaration_id') or '')
                                 for item in current.ast_parameter_declarations}
                parameter_names = {str(item.get('name') or '')
                                   for item in current.ast_parameter_declarations}
                touches_field = any(
                    re.search(r'\b' + re.escape(owner) +
                              r'\s*(?:->|\.)\s*' + re.escape(field) + r'\b',
                              code)
                    for owner in parameter_names for field in receiver_fields
                )
                if not touches_field:
                    continue
                for site in current.direct_call_sites:
                    target_id = str(site.get('callee_function_id') or '')
                    if target_id not in self.graph.bundle.functions:
                        continue
                    argument_ids = set(map(str,
                        site.get('direct_argument_declaration_ids') or []))
                    if argument_ids & parameter_ids:
                        add(target_id, 'same_receiver_field_forward_candidate',
                            source_function_id=opened_id)
                for site in current.guarded_call_sites:
                    target_id = str(site.get('callee_function_id') or '')
                    if target_id not in self.graph.bundle.functions:
                        continue
                    condition_ids = set(map(str,
                        site.get('condition_content_declaration_ids') or []))
                    if condition_ids & parameter_ids:
                        add(target_id, 'same_receiver_field_guard_candidate',
                            source_function_id=opened_id)
            for caller_id, targets in _source_field_return_callers(
                self.graph, entry,
            ).items():
                add(caller_id, 'source_field_return_caller_candidate')
                if caller_id in opened_set:
                    for target_id in targets:
                        add(target_id, 'source_field_return_consumer_candidate',
                            source_function_id=caller_id)
            output_callers = _source_output_parameter_field_callers(
                self.graph, entry, include_local=True,
            )
            for caller_id, records in output_callers.items():
                add(caller_id, "source_output_parameter_storage_handoff_candidate",
                    storage_handoffs=records)
                for record in records:
                    if record.get('storage_kind') == 'field':
                        add(caller_id,
                            'source_output_parameter_field_handoff_candidate',
                            field_name=record.get('field_name'),
                            receiver_declaration_id=record.get(
                                'receiver_declaration_id'),
                            call_line=record.get('call_line'),
                            proof_policy='navigation only; cross-unit link and '
                                         'shared object identity remain unproven')
                    elif record.get('storage_kind') == 'local_or_parameter':
                        add(caller_id,
                            'source_output_parameter_local_handoff_candidate',
                            storage_name=record.get('storage_name'),
                            storage_declaration_id=record.get(
                                'storage_declaration_id'),
                            call_line=record.get('call_line'),
                            proof_policy='navigation only; cross-unit link and '
                                         'runtime data flow remain unproven')
            root_fields = _entry_shared_field_paths(root, entry)
            if root_fields:
                possible_transforms = [lead[0] for lead in
                    _shared_field_handoff_candidates(
                        self.graph, entry, opened, root_fields,
                    )]
                possible_fields = _shared_field_aliases(
                    self.graph, [*opened, *possible_transforms], root_fields,
                )
                for opened_id in opened:
                    for caller in self.graph.callers(opened_id):
                        if caller.function_id in opened_set:
                            continue
                        if not any(site.get('callee_function_id') == opened_id
                                   for site in caller.direct_call_sites):
                            continue
                        if opened_id != root.function_id:
                            code = _code_only(caller.source)
                            if not any(re.search(
                                r'\b' + re.escape(field.split('.', 1)[0])
                                + r'\s*(?:\.|->)\s*'
                                + re.escape(field.split('.', 1)[1]) + r'\b',
                                code,
                            ) for field in possible_fields):
                                continue
                        add(caller.function_id,
                            'shared_field_return_caller_candidate',
                            connected_function_id=opened_id)
            for target_id, caller_id, field in _shared_field_handoff_candidates(
                self.graph, entry, opened, root_fields,
            ):
                add(target_id, "post_read_field_candidate",
                    connected_function_id=caller_id, field_name=field)
            for target_id, callee_id in _shared_field_return_callers(
                self.graph, opened, root_fields, entry.entry_function_id,
            ):
                add(target_id, "post_read_return_caller_candidate",
                    connected_function_id=callee_id)
            for caller in self.graph.callers(entry.entry_function_id):
                callbacks = _same_receiver_return_callbacks(
                    self.graph, entry, caller,
                )
                if callbacks:
                    add(caller.function_id,
                        "same_receiver_return_caller_candidate")
                    if caller.function_id in opened_set:
                        for target_id in callbacks:
                            add(target_id,
                                "same_receiver_callback_target_candidate",
                                source_function_id=caller.function_id)
            for target_id in _callback_registration_leads(
                self.graph, opened, {entry.entry_function_id},
            ):
                add(target_id, "callback_registration_candidate")

        for choice in self.graph.callback_slot_candidates(opened):
            function_id = str(choice.get("function_id") or "")
            for connection in choice.get("connections", []):
                if isinstance(connection, dict):
                    if (connection.get('relation') == 'callback_candidate_callee'
                        and entry.entry_function_id in opened
                        and connection.get('connected_function_id') ==
                            entry.entry_function_id):
                        # A callback reached directly from the acquisition
                        # body may only handle EOF/error or lifecycle state.
                        # Do not call it an input-value consumer from the
                        # callback-slot name alone.
                        continue
                    add(function_id,
                        str(connection.get("relation") or "callback_candidate"),
                        **{key: value for key, value in connection.items()
                           if key != "relation"})
        for choice in self.graph.callback_registration_candidates(opened):
            function_id = str(choice.get("function_id") or "")
            for connection in choice.get("connections", []):
                if isinstance(connection, dict):
                    target_id = str(connection.get('callback_target_function_id') or '')
                    if target_id and target_id not in self.graph.bundle.functions:
                        continue
                    add(function_id,
                        str(connection.get("relation") or "callback_candidate"),
                        **{key: value for key, value in connection.items()
                           if key != "relation"})
        for function_id in entry.inspected_function_ids:
            add(function_id, "entry_verifier_opened_navigation")
        if opened:
            current = self.graph.bundle.functions.get(opened[-1])
            if current is not None:
                for site in current.direct_call_sites:
                    target_id = str(site.get('callee_function_id') or '')
                    if target_id in choices and isinstance(
                        site.get('line'), int,
                    ):
                        add(target_id, 'source_located_call_candidate',
                            edge_lines=[site['line']],
                            proof_policy='source-located call navigation only; '
                                         'external input selection remains unproven')
        if opened:
            root_function = self.graph.bundle.functions.get(entry.entry_function_id)
            acquired_fields = (
                _entry_receiver_field_names(root_function, entry)
                if root_function else set()
            )
            for choice in self.graph.shared_field_candidates(
                opened[-1:], limit=len(self.graph.bundle.functions),
            ):
                function_id = str(choice.get("function_id") or "")
                for connection in choice.get("connections", []):
                    if not isinstance(connection, dict):
                        continue
                    if (opened[-1] == entry.entry_function_id
                        and acquired_fields
                        and connection.get('field_name') not in acquired_fields):
                        continue
                    add(function_id,
                        str(connection.get("relation") or "shared_typed_field_candidate"),
                        **{key: value for key, value in connection.items()
                           if key != "relation"})
        for choice in choices.values():
            choice["connections"].sort(key=lambda connection: {
                "entry_verifier_opened_navigation": 0,
                "callback_registration_candidate": 1,
            }.get(str(connection.get("relation") or ""), 2))
        return list(choices.values())

    def _branch_choices(
        self,
        opened: list[str],
        *,
        dispatcher_function_id: str,
        handler_function_id: str,
        return_path_function_ids: list[str] | None = None,
        discriminator: str = "",
    ) -> list[dict[str, object]]:
        """Expose handler callees and only proven-path response callers.

        Entry-to-dispatcher reachability is already immutable proof when a
        branch session starts.  Re-exposing callers of the dispatcher or
        handler lets the model walk backward into connection lifecycle,
        backend, and event-loop code once per command.  That was the dominant
        repeated path in the audited long-running trace. Action semantics,
        response serialization and parser helpers are normally forward
        callees.  Some APIs instead serialize a response after the handler
        returns; those callers are admitted only when they are members of the
        already proven Entry-to-dispatcher path.  Arbitrary lifecycle callers
        remain unavailable.
        """

        branch_context = [
            function_id for function_id in opened
            if function_id != dispatcher_function_id
            and function_id in self.graph.bundle.functions
        ]
        # An inline branch has no separately selected handler subtree, so its
        # focused dispatcher excerpt supplies branch semantics and the forward
        # set stays empty.  Proven return-path callers below may still be
        # needed to interpret the handler status as an external response.
        branch_context_set = set(branch_context)
        choices_by_id: dict[str, dict[str, object]] = {}
        for choice in self.graph.frontier(branch_context):
            connections = [
                connection
                for connection in choice.get("connections", [])
                if isinstance(connection, dict)
                and connection.get("relation") == "callee_of"
                and connection.get("connected_function_id")
                in branch_context_set
            ]
            if not connections:
                continue
            choices_by_id[str(choice["function_id"])] = {
                **choice,
                "connections": connections,
            }

        # A handler may return a status that an Entry-path caller turns into
        # the external response.  Use the full opened set here so the caller
        # of the dispatcher itself is visible, but admit only IDs from the
        # independently established path supplied to this branch worker.
        allowed_return_path = set(return_path_function_ids or [])
        opened_set = set(opened)
        for choice in self.graph.frontier(opened):
            function_id = str(choice["function_id"])
            if function_id not in allowed_return_path:
                continue
            connections = [
                connection
                for connection in choice.get("connections", [])
                if isinstance(connection, dict)
                and connection.get("relation") == "caller_of"
                and connection.get("connected_function_id") in opened_set
            ]
            if not connections:
                continue
            existing = choices_by_id.get(function_id)
            if existing is None:
                choices_by_id[function_id] = {
                    **choice,
                    "connections": connections,
                }
            else:
                existing_connections = existing.get("connections", [])
                assert isinstance(existing_connections, list)
                existing_connections.extend(connections)
        handler = self.graph.bundle.functions.get(handler_function_id)
        usage_discriminators = [discriminator]
        if handler is not None:
            usage_discriminators.extend([handler.name, handler.qualified_name])
        for function_id in relevant_usage_functions(
            self.usage_artifacts,
            self.graph.bundle,
            discriminators=usage_discriminators,
            opened=opened,
        ):
            function = self.graph.get(function_id)
            choices_by_id.setdefault(function_id, {
                **function_ref(function),
                "connections": [{
                    "relation": "project_usage_candidate",
                    "proof_policy": (
                        "may supply request bytes/order only; handler semantics "
                        "and runtime reach still require product/runtime evidence"
                    ),
                }],
            })
        return list(choices_by_id.values())

    def _validate_actions(
        self,
        entry: EntryRecord,
        raw_actions: list[dict[str, Any]],
        opened: list[str],
        operation_seeds: list[OperationSeed],
        *,
        context_complete: bool,
        proof_path_ids: list[str] | None = None,
        direct_consumer_ids: set[str] | None = None,
        direct_consumer_taint_names: dict[str, set[str]] | None = None,
    ) -> list[ExternalActionSchema]:
        opened_set = set(opened)
        proof_path_set = {
            function_id for function_id in (proof_path_ids or [])
            if function_id in self.graph.bundle.functions
        }
        causal_context = opened_set | proof_path_set
        result: list[ExternalActionSchema] = []
        for raw in raw_actions:
            handler = str(raw.get("handler_function_id") or "")
            dispatcher = str(raw.get("dispatcher_function_id") or handler)
            if dispatcher not in opened_set or handler not in opened_set:
                continue
            evidence = _validated_evidence(raw.get("evidence"), opened_set, self.graph)
            selection_evidence = _validated_evidence(
                raw.get("selection_evidence"), opened_set, self.graph,
            )
            effect_evidence = _validated_evidence(
                raw.get("effect_evidence"), opened_set, self.graph,
            )
            success_evidence = _validated_evidence(
                raw.get("success_evidence"), opened_set, self.graph
            )
            failure_evidence = _validated_evidence(
                raw.get("failure_evidence"), opened_set, self.graph
            )
            response_bindings = _response_binding_extractors(
                raw.get("response_bindings"), opened_set, self.graph
            )
            invalid_response_bindings = _invalid_response_binding_count(
                raw.get("response_bindings"), opened_set, self.graph
            )
            examples = _examples(raw.get("examples"), opened_set, self.graph)
            fields = _fields(raw.get("fields"), opened_set, self.graph, examples)
            confidence = _confidence(raw.get("confidence"))
            unknowns = string_list(raw.get("unknowns"))
            if not selection_evidence:
                unknowns.append('source-located external Action selection is unresolved')
            if not effect_evidence:
                unknowns.append('source-located distinct handler effect is unresolved')
            if not context_complete and not raw.get('action_context_complete', False):
                unknowns.append("input-action context walk did not complete")
            if not raw.get('action_context_complete', False):
                unknowns.append("this Action's source context is incomplete")
            if invalid_response_bindings:
                unknowns.append(
                    f"{invalid_response_bindings} response binding extractor(s) "
                    "lacked a valid fixed-width opened-source contract"
                )
            unknowns = unique_strings(unknowns)
            evidence_functions = {item.function_id for item in evidence}
            required_evidence_functions = {dispatcher, handler}
            source_path_proven = required_evidence_functions.issubset(
                evidence_functions
            )
            entry_to_dispatcher = (
                entry.entry_function_id == dispatcher
                or bool(self.graph.causal_path_from_entry(
                    entry.entry_function_id,
                    dispatcher,
                    opened_function_ids=causal_context,
                    max_return_depth=6,
                    max_forward_depth=64,
                ))
            )
            dispatcher_to_handler = (
                dispatcher == handler
                or bool(self.graph.causal_path_from_entry(
                    dispatcher,
                    handler,
                    opened_function_ids=causal_context,
                    max_return_depth=0,
                    max_forward_depth=64,
                ))
            )
            if not entry_to_dispatcher or not dispatcher_to_handler:
                unknowns = unique_strings([
                    *unknowns,
                    "the opened source graph does not establish Entry -> dispatcher -> handler",
                ])
            if (direct_consumer_ids is not None
                and dispatcher not in direct_consumer_ids
                and dispatcher != entry.entry_function_id):
                unknowns = unique_strings([
                    *unknowns,
                    'input-value flow into the claimed dispatcher is unproven',
                    'acquired input use is not visible in the claimed dispatcher',
                ])
            if direct_consumer_taint_names and dispatcher in direct_consumer_taint_names:
                dispatcher_body = _code_only(self.graph.get(dispatcher).source)
                dispatcher_body = dispatcher_body.split('{', 1)[-1]
                if not any(re.search(r'\b' + re.escape(name) + r'\b', dispatcher_body)
                           for name in direct_consumer_taint_names[dispatcher]):
                    unknowns = unique_strings([
                        *unknowns,
                        'acquired input use is not visible in the claimed dispatcher',
                    ])
            success_markers = _hex_list(
                raw.get("success_markers_hex"), allow_empty=False
            )
            failure_markers = _hex_list(
                raw.get("failure_markers_hex"), allow_empty=False
            )
            discriminator = str(raw.get('discriminator') or '').strip()
            input_symbols = (
                _entry_destination_names(self.graph.get(entry.entry_function_id), entry)
                if dispatcher == entry.entry_function_id else set()
            )
            source_seeds = extract_operation_seeds(
                [self.graph.get(dispatcher)], self.graph,
                input_symbols=input_symbols if input_symbols else None,
            )
            source_selection = (
                not discriminator and not source_seeds
            ) or any(
                _discriminator_key(seed.discriminator)
                == _discriminator_key(discriminator)
                and (
                    handler in seed.handler_function_ids
                    or not seed.handler_function_ids and handler == dispatcher
                )
                and seed.status is not ProofStatus.REFUTED
                for seed in source_seeds
            )
            if not source_selection:
                unknowns = unique_strings([
                    *unknowns,
                    'action selector and handler lack independent source selection evidence',
                ])
            if dispatcher == entry.entry_function_id and not discriminator and handler != dispatcher:
                unknowns = unique_strings([
                    *unknowns,
                    'an internal guard in the Entry is not by itself an external Action selector',
                ])
            if raw.get('examples') and (not examples or not all(
                any(item.line is not None for item in example.evidence)
                for example in examples
            )):
                unknowns = unique_strings([
                    *unknowns,
                    'complete external request lacks a source-located example',
                ])
            status = ProofStatus.POSSIBLE
            matching_seeds = [
                seed for seed in operation_seeds
                if seed.dispatcher_function_id == dispatcher
                and _discriminator_key(seed.discriminator)
                == _discriminator_key(discriminator)
                and (
                    handler in seed.handler_function_ids
                    or (
                        not seed.handler_function_ids
                        and handler == dispatcher
                    )
                )
            ]
            if operation_seeds and not matching_seeds:
                unknowns = unique_strings([
                    *unknowns,
                    "the claimed action discriminator/handler does not match "
                    "a source-extracted branch in the opened dispatcher",
                ])
                status = ProofStatus.POSSIBLE
            # This locator supplies source-navigation and original-program
            # trial hypotheses. It does not compute a complete data/control
            # dependence from acquired bytes to the claimed effect, so a
            # model-authored Action cannot be statically certified here.
            status = ProofStatus.POSSIBLE
            unknowns = unique_strings([
                *unknowns,
                'input-to-effect data or control dependence is not established by the current source locator',
                'call/callback path alone does not establish that acquired bytes select the effect',
            ])
            if any(edge.kind == 'indirect_possible'
                   and edge.caller_id == dispatcher and edge.callee_id == handler
                   for edge in self.graph.bundle.edges):
                unknowns = unique_strings([
                    *unknowns,
                    'possible indirect callback edge is navigation, not proof',
                ])
            name = str(raw.get("name", "")).strip() or discriminator or self.graph.get(handler).name
            entry_function = self.graph.get(entry.entry_function_id)
            entry_probe_evidence = (
                [Evidence(
                    kind="verified_entry_acquisition_site",
                    function_id=entry.entry_function_id,
                    file=entry_function.file,
                    line=entry.entry_line,
                    detail=(
                        f"verified first-acquisition call {entry.source_api} "
                        "used as the runtime Entry probe"
                    ),
                )]
                if entry.entry_line is not None
                else []
            )
            dispatch_probe_evidence = [
                Evidence(
                    kind="operation_seed_branch",
                    function_id=seed.dispatcher_function_id,
                    file=self.graph.get(seed.dispatcher_function_id).file,
                    line=seed.line,
                    detail=(
                        f"source-extracted dispatcher branch {seed.discriminator!r} "
                        "used as the runtime action probe"
                    ),
                )
                for seed in matching_seeds
            ]
            result.append(ExternalActionSchema(
                action_id=stable_id("action", entry.entry_id, dispatcher,
                                    handler, discriminator, name),
                entry_id=entry.entry_id,
                name=name,
                description=str(raw.get("description", "")).strip(),
                dispatcher_function_id=dispatcher,
                handler_function_id=handler,
                discriminator=discriminator,
                channel_kind=entry.channel_kind,
                fields=fields,
                examples=examples,
                success_markers_hex=success_markers,
                failure_markers_hex=failure_markers,
                evidence=evidence,
                selection_evidence=selection_evidence,
                effect_evidence=effect_evidence,
                inspected_function_ids=unique_strings([
                    *(proof_path_ids or []), *opened,
                ]),
                operation_seed_ids=sorted(
                    seed.operation_seed_id for seed in matching_seeds
                ),
                status=status,
                unknowns=unknowns,
                confidence=confidence,
                source_api=entry.source_api,
                success_evidence=success_evidence,
                failure_evidence=failure_evidence,
                response_bindings=response_bindings,
                actor=_entry_actor(entry, self.graph),
                direction=_entry_direction(entry, self.graph),
                entry_function_id=entry.entry_function_id,
                entry_probe_evidence=entry_probe_evidence,
                dispatch_probe_evidence=dispatch_probe_evidence,
            ))
        return _consolidate_same_request_actions(result)


def _consolidate_same_request_actions(
    actions: list[ExternalActionSchema],
) -> list[ExternalActionSchema]:
    """Avoid treating identical external bytes as many proven operations.

    Distinct effects are retained as alternatives, but shared bytes cannot
    independently prove which effect the original program will select.
    """
    groups: dict[tuple[str, tuple[str, ...]], list[ExternalActionSchema]] = {}
    result: list[ExternalActionSchema] = []
    for action in actions:
        if not action.examples:
            result.append(action)
            continue
        key = (action.entry_id, tuple(sorted(example.data_hex
                                           for example in action.examples)))
        groups.setdefault(key, []).append(action)
    for group in groups.values():
        effects: dict[tuple[str, str, str], ExternalActionSchema] = {}
        for action in group:
            key = (action.dispatcher_function_id,
                   action.handler_function_id, action.description)
            if key not in effects:
                effects[key] = action
        variants = list(effects.values())
        distinct_claims = {
            (action.name, action.discriminator,
             action.handler_function_id, action.description)
            for action in group
        }
        if len(distinct_claims) > 1:
            variants = [replace(
                action,
                status=ProofStatus.POSSIBLE,
                unknowns=unique_strings([
                    *action.unknowns,
                    'same complete external request bytes were assigned to '
                    'different Action claims',
                ]),
            ) for action in variants]
        result.extend(variants)
    return result


def _entry_actor(entry: EntryRecord, graph: GraphStore) -> ActionActor:
    channel = entry.channel_kind.casefold().replace("-", "_")
    source_api = entry.source_api.rsplit("::", 1)[-1].casefold()
    # An argv/environment Entry belongs to the process launcher regardless
    # of socket calls appearing later in main().  Guessing its actor from
    # the enclosing file's bind()/accept() calls mislabels process flags as
    # network-client commands.
    if (entry.site_kind is EntrySiteKind.PROCESS_START
        or source_api in {"argv", "argc", "getenv", "envp", "environ"}
        or any(token in channel for token in (
            "stdin", "standard input", "argv", "command_line", "command line",
            "argument", "environment", "envp",
        ))
        or source_api in {"getchar", "getchar_unlocked", "scanf", "fgets", "gets"}):
        return ActionActor.LOCAL_PROCESS_INPUT
    context_ids = {
        entry.entry_function_id,
        *(str(item.get("function_id", "")) for item in entry.provenance_path),
        *(item.function_id for item in entry.evidence),
    }
    source = "\n".join(
        graph.get(function_id).source
        for function_id in context_ids
        if function_id in graph.bundle.functions
    )
    has_connect = bool(re.search(r"(?<![.>])\bconnect\s*\(", source))
    has_server_setup = bool(re.search(
        r"(?<![.>])\b(?:accept|accept4|bind|listen)\s*\(", source
    ))
    if has_connect and not has_server_setup:
        return ActionActor.OUTBOUND_PEER
    if has_server_setup and not has_connect:
        return ActionActor.INBOUND_CLIENT
    return ActionActor.UNKNOWN


def _entry_direction(entry: EntryRecord, graph: GraphStore) -> str:
    actor = _entry_actor(entry, graph)
    return {
        ActionActor.INBOUND_CLIENT: "client_to_program",
        ActionActor.OUTBOUND_PEER: "peer_to_program",
        ActionActor.LOCAL_PROCESS_INPUT: "local_to_program",
        ActionActor.UNKNOWN: "unknown",
    }[actor]


class _StateGroupReplay:
    """Replay grouped model evidence through the unchanged per-action validator.

    This provider never calls a model.  It refuses to substitute an opened
    function different from the one that the group model actually inspected.
    """

    max_concurrency = 1

    def __init__(self, snapshots: list[tuple[str, dict[str, Any]]]):
        self.snapshots = snapshots
        self.index = 0
        self.mismatch = False

    async def complete_json(self, *, payload: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        current = str(payload.get("current_function", {}).get("function_id", ""))
        if self.index >= len(self.snapshots):
            self.mismatch = True
            raise ValueError("group replay requested a function not opened by the model")
        function_id, snapshot = self.snapshots[self.index]
        if current != function_id:
            self.mismatch = True
            raise ValueError("group replay source path diverged from inspected functions")
        self.index += 1
        return snapshot

    async def close_session(self, _key: str) -> None:
        pass


class StateDependencyAgent:
    """Backward, source-evidenced state analysis for reconstructed actions."""

    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        usage_evidence: UsageEvidenceBundle,
        *,
        budget: int = 32,
        usage_artifacts: list[UsageArtifact] | None = None,
        original_trial_feedback: dict[str, list[dict[str, str]]] | None = None,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.usage_evidence = usage_evidence
        self.usage_artifacts = list(usage_artifacts or [])
        self.original_trial_feedback = dict(original_trial_feedback or {})
        self.budget = max(1, budget or len(graph.bundle.functions))
        self.trace = trace
        self.infrastructure_failures: list[str] = []
        self.planned_state_groups = 0
        self.state_group_fallbacks = 0
        self._shared_source_group_ids: dict[str, str] = {}

    @staticmethod
    def session_key(action: ExternalActionSchema) -> str:
        return f"state_dependency:{action.action_id}"

    async def run(
        self, actions: list[ExternalActionSchema], *,
        source_group_ids: dict[str, str] | None = None,
    ) -> StateDependencyGraph:
        self.infrastructure_failures = []
        self.state_group_fallbacks = 0
        self._shared_source_group_ids = dict(source_group_ids or {})
        # A source-reviewed shared effect may reuse one handler walk across
        # Entries. Otherwise retain the established Entry+handler boundary.
        # Every action keeps its own state contract and must pass the original
        # per-action proof validator through source-checked local replay.
        groups: list[list[ExternalActionSchema]] = []
        last_group: dict[tuple[str, str], int] = {}
        for action in actions:
            key = (
                self._shared_source_group_ids.get(action.action_id)
                or str(getattr(action, "entry_id", id(action))),
                str(getattr(action, "handler_function_id", id(action))),
            )
            index = last_group.get(key)
            if index is not None and len(groups[index]) < 6:
                groups[index].append(action)
            else:
                last_group[key] = len(groups)
                groups.append([action])
        self.planned_state_groups = len(groups)
        emit_trace(
            self.trace, "state_dependency", "shared_handler_groups_planned",
            f"{len(actions)} actions assigned to {len(groups)} handler source walks",
            action_count=len(actions), shared_handler_groups=len(groups),
        )
        # Do not let a shared provider outage multiply into every remaining
        # handler group; keep unprocessed actions as explicit obligations.
        analyzed: list[tuple[ActionStateContract, list[StateRequirement]]] = []
        pending_groups: deque[list[ExternalActionSchema]] = deque(groups)
        concurrency = max(1, int(getattr(self.llm, "max_concurrency", 1)))
        consecutive_infrastructure_waves = 0
        infrastructure_abort_obligations: list[str] = []
        while pending_groups:
            wave = [
                pending_groups.popleft()
                for _ in range(min(concurrency, len(pending_groups)))
            ]
            failures_before_wave = len(self.infrastructure_failures)
            group_results = await concurrent_map(
                wave, self._run_state_group, concurrency,
            )
            for group, group_result in zip(wave, group_results):
                if len(group_result) != len(group):
                    raise RuntimeError("state source group omitted an action contract")
                analyzed.extend(group_result)
            wave_failures = (
                len(self.infrastructure_failures) - failures_before_wave
            )
            if wave_failures == len(wave):
                consecutive_infrastructure_waves += 1
            else:
                consecutive_infrastructure_waves = 0
            if pending_groups and consecutive_infrastructure_waves >= 2:
                reason = (
                    "aborted remaining state-dependency analyses after every "
                    "action in two consecutive worker waves failed in the LLM "
                    "infrastructure"
                )
                infrastructure_abort_obligations.extend(
                    f"{action.action_id}: {reason}"
                    for group in pending_groups for action in group
                )
                emit_trace(
                    self.trace,
                    "state_dependency",
                    "analysis_infrastructure_aborted",
                    reason,
                    completed_actions=len(analyzed),
                    remaining_actions=sum(len(group) for group in pending_groups),
                    consecutive_failed_waves=consecutive_infrastructure_waves,
                )
                break
        contracts: list[ActionStateContract] = []
        obligations: list[str] = list(infrastructure_abort_obligations)
        for contract, _action_initial in analyzed:
            contracts.append(contract)
            if contract.status is not ProofStatus.PROVEN_STATIC:
                obligations.extend(
                    contract.unknowns
                    or [f"state contract unresolved for {contract.action_id}"]
                )
        providers = unique_strings(
            item.provider for item in self.usage_evidence.providers if item.state == "USED"
        )
        ordering, ordering_obligations, blocked_consumers = (
            self._ordering_constraints(actions)
        )
        obligations.extend(ordering_obligations)
        for contract in contracts:
            blockers = blocked_consumers.get(contract.action_id, [])
            if not blockers:
                continue
            contract.status = ProofStatus.POSSIBLE
            contract.unknowns = unique_strings([
                *contract.unknowns,
                *blockers,
            ])
            obligations.extend(blockers)
        # An upstream ordering blocker can demote a previously proven contract.
        # Its claimed startup resources must be demoted with it.
        initial = [
            item
            for contract, action_initial in analyzed
            if contract.status is ProofStatus.PROVEN_STATIC
            for item in action_initial
        ]
        return StateDependencyGraph(
            contracts=contracts,
            initial_resources=_merge_requirements(initial),
            open_obligations=unique_strings(obligations),
            evidence_providers=providers,
            ordering_constraints=ordering,
        )

    def _ordering_constraints(
        self,
        actions: list[ExternalActionSchema],
    ) -> tuple[
        list[ActionOrderingConstraint],
        list[str],
        dict[str, list[str]],
    ]:
        result: list[ActionOrderingConstraint] = []
        obligations: list[str] = []
        blocked_consumers: dict[str, list[str]] = {}
        for constraint in self.usage_evidence.constraints:
            strength = constraint.strength.upper()
            if strength not in {"REQUIRED", "FORBIDDEN"}:
                continue
            producers = [
                action for action in actions
                if action.handler_function_id in constraint.producer_function_ids
                or action.dispatcher_function_id in constraint.producer_function_ids
            ]
            consumers = [
                action for action in actions
                if action.handler_function_id in constraint.consumer_function_ids
                or action.dispatcher_function_id in constraint.consumer_function_ids
            ]
            if not producers or not consumers:
                detail = (
                    f"{constraint.constraint_id}: upstream action mapping is incomplete "
                    f"(producers={len(producers)}, consumers={len(consumers)})"
                )
                obligations.append(detail)
                for consumer in consumers:
                    blocked_consumers.setdefault(consumer.action_id, []).append(
                        detail
                    )
                continue
            if len(producers) != 1 or len(consumers) != 1:
                detail = (
                    f"{constraint.constraint_id}: upstream action mapping is ambiguous "
                    f"(producers={len(producers)}, consumers={len(consumers)})"
                )
                obligations.append(detail)
                for consumer in consumers:
                    blocked_consumers.setdefault(consumer.action_id, []).append(
                        detail
                    )
                continue
            producer = producers[0]
            consumer = consumers[0]
            if producer.action_id == consumer.action_id:
                detail = (
                    f"{constraint.constraint_id}: predecessor and successor resolve to the same action"
                )
                obligations.append(detail)
                blocked_consumers.setdefault(consumer.action_id, []).append(
                    detail
                )
                continue
            result.append(ActionOrderingConstraint(
                constraint_id=stable_id(
                    "action-order", constraint.constraint_id,
                    producer.action_id, consumer.action_id,
                ),
                predecessor_action_id=producer.action_id,
                successor_action_id=consumer.action_id,
                strength=strength,
                provider=constraint.provider,
                rationale=constraint.detail or (
                    f"{constraint.producer} -> {constraint.consumer}"
                ),
            ))
        return result, unique_strings(obligations), {
            action_id: unique_strings(values)
            for action_id, values in blocked_consumers.items()
        }

    async def _run_state_group(
        self,
        actions: list[ExternalActionSchema],
    ) -> list[tuple[ActionStateContract, list[StateRequirement]]]:
        if len(actions) == 1:
            return [await self._run_action(actions[0])]
        root = actions[0].handler_function_id
        if root not in self.graph.bundle.functions:
            return [await self._run_action(action) for action in actions]
        shared_id = self._shared_source_group_ids.get(actions[0].action_id)
        if any(action.handler_function_id != root or (
            action.entry_id != actions[0].entry_id
            and (not shared_id
                 or self._shared_source_group_ids.get(action.action_id) != shared_id)
        ) for action in actions):
            raise ValueError("state group contains unrelated handlers")

        opened: list[str] = []
        round_history: list[tuple[str, dict[str, Any]]] = []
        pending = root
        session = "state_dependency:group:" + stable_id(
            "state-handler", root, *[action.action_id for action in actions],
        )
        infrastructure_failure = ""
        try:
            for round_index in range(1, self.budget + 1):
                if pending in opened or pending not in self.graph.bundle.functions:
                    break
                opened.append(pending)
                current = self.graph.get(pending)
                frontier_by_id = {
                    str(item["function_id"]): item
                    for item in self.graph.frontier(opened)
                }
                for function_id in relevant_usage_functions(
                    self.usage_artifacts, self.graph.bundle,
                    discriminators=[
                        item for action in actions
                        for item in (action.discriminator, action.name)
                    ],
                    opened=opened,
                ):
                    function = self.graph.get(function_id)
                    frontier_by_id.setdefault(function_id, {
                        **function_ref(function),
                        "connections": [{
                            "relation": "project_usage_candidate",
                            "proof_policy": "request-order hint only; not source state proof",
                        }],
                    })
                frontier = list(frontier_by_id.values())
                emit_trace(
                    self.trace, "state_dependency", "shared_handler_function_opened",
                    f"opened {current.name} for {len(actions)} action state contracts",
                    action_ids=[action.action_id for action in actions],
                    function=function_ref(current), round=round_index,
                )
                response = await self.llm.complete_json(
                    role="state_dependency",
                    instructions=(
                        "Find consumed, produced and invalidated state for EVERY action in "
                        "the selected_actions list. They share a real C handler but may "
                        "have DIFFERENT command discriminators and state requirements. "
                        "Return a separate full contract for EVERY action_id on EVERY "
                        "turn; action_context_complete is true only when all necessary "
                        "source is already opened for that specific action. If a different "
                        "function is needed for some actions, set those flags false and "
                        "request one source function at a time. Cite actual opened product "
                        "lines for each predicate and success guard. Never copy an unrelated "
                        "action's state claims, infer state from names alone, or equate "
                        "session, connection and global resources. Initial bindings require "
                        "a source-proven concrete value. Bindings consumed in requests "
                        "or produced in responses must use independently source-evidenced "
                        "fields. Usage evidence supplies hints, NOT state proof. When the "
                        "shared walk cannot resolve an action, report unknowns explicitly; "
                        "it will receive its own independent source walk."
                    ),
                    payload={
                        "selected_actions": [_action_payload(action) for action in actions],
                        "original_trial_feedback": {
                            action.action_id: self.original_trial_feedback.get(action.action_id, [])
                            for action in actions
                        },
                        "round": round_index,
                        "current_function": function_payload(current),
                        "opened_functions": [
                            function_ref(self.graph.get(fid)) for fid in opened
                        ],
                        "frontier": frontier,
                        "upstream_usage_evidence": self.usage_evidence.relevant_payload(opened),
                        "previous_contract_summaries": [
                            {
                                "action_id": action.action_id,
                                "summary": _contract_summary(next((
                                    item for item in object_list(round_history[-1][1].get("contracts"))
                                    if item.get("action_id") == action.action_id
                                ), {})) if round_history else {},
                            }
                            for action in actions
                        ],
                    },
                    output_schema=GROUP_STATE_DEPENDENCY_SCHEMA,
                    session_key=session,
                )
                round_history.append((pending, response))
                if bool(response.get("context_complete", False)):
                    break
                requested = string_list(response.get("requested_function_ids"))
                pending = (
                    requested[0] if requested and requested[0] in frontier_by_id
                    else ""
                )
                if not pending:
                    break
        except Exception as exc:
            infrastructure_failure = (
                f"shared state source walk failed with {type(exc).__name__}: {exc}"
            )
            self.infrastructure_failures.append(infrastructure_failure)
            if _is_non_retryable_infrastructure_failure(exc):
                raise
        finally:
            await close_llm_session(self.llm, session)
        if infrastructure_failure:
            return [(
                ActionStateContract(
                    action_id=action.action_id,
                    consumes=[], produces=[], invalidates=[], success_condition="",
                    evidence=[], inspected_function_ids=opened,
                    status=ProofStatus.POSSIBLE,
                    unknowns=[infrastructure_failure],
                ), []
            ) for action in actions]

        results: list[tuple[ActionStateContract, list[StateRequirement]]] = []
        for action in actions:
            snapshots: list[tuple[str, dict[str, Any]]] = []
            missing = False
            for function_id, response in round_history:
                matches = [
                    item for item in object_list(response.get("contracts"))
                    if item.get("action_id") == action.action_id
                ]
                if len(matches) != 1:
                    missing = True
                    break
                contract = matches[0]
                if (bool(response.get("context_complete", False))
                    and not bool(contract.get("action_context_complete", False))):
                    missing = True
                    break
                snapshots.append((function_id, {
                    **{key: value for key, value in contract.items()
                       if key not in {"action_id", "action_context_complete"}},
                    "context_complete": (
                        bool(response.get("context_complete", False))
                        and bool(contract.get("action_context_complete", False))
                    ),
                    "requested_function_ids": response.get("requested_function_ids", []),
                    "rationale": response.get("rationale", ""),
                }))
            if snapshots and not snapshots[-1][1]["context_complete"]:
                missing = True
            if missing or not snapshots:
                self.state_group_fallbacks += 1
                results.append(await self._run_action(action))
                continue
            # Execute the original, independently guarded state-contract
            # validator with a model-free, exact-source replay transcript.
            replay = _StateGroupReplay(snapshots)
            validator = StateDependencyAgent(
                replay, self.graph, self.usage_evidence,
                budget=self.budget, usage_artifacts=self.usage_artifacts,
            )
            contract, initial = await validator._run_action(action)
            if replay.mismatch or validator.infrastructure_failures:
                self.state_group_fallbacks += 1
                results.append(await self._run_action(action))
            else:
                results.append((contract, initial))
        emit_trace(
            self.trace, "state_dependency", "shared_handler_group_completed",
            f"{len(actions)} independently validated action state contracts",
            action_ids=[action.action_id for action in actions],
            source_functions_opened=opened,
        )
        return results

    async def _run_action(
        self, action: ExternalActionSchema
    ) -> tuple[ActionStateContract, list[StateRequirement]]:
        root = action.handler_function_id
        if root not in self.graph.bundle.functions:
            return ActionStateContract(
                action_id=action.action_id, consumes=[], produces=[], invalidates=[],
                success_condition="", evidence=[], inspected_function_ids=[],
                status=ProofStatus.POSSIBLE,
                unknowns=["handler is absent from the analysis graph"],
            ), []
        opened: list[str] = []
        pending = root
        latest: dict[str, Any] = {}
        response_history: list[dict[str, Any]] = []
        complete = False
        infrastructure_failure = ""
        try:
            for round_index in range(1, self.budget + 1):
                if pending in opened or pending not in self.graph.bundle.functions:
                    break
                opened.append(pending)
                current = self.graph.get(pending)
                frontier = self.graph.frontier(opened)
                frontier_by_id = {
                    str(item["function_id"]): item for item in frontier
                }
                for function_id in relevant_usage_functions(
                    self.usage_artifacts,
                    self.graph.bundle,
                    discriminators=[
                        action.discriminator,
                        action.name,
                        self.graph.get(root).name,
                    ],
                    opened=opened,
                ):
                    function = self.graph.get(function_id)
                    frontier_by_id.setdefault(function_id, {
                        **function_ref(function),
                        "connections": [{
                            "relation": "project_usage_candidate",
                            "proof_policy": (
                                "observed request ordering/layout only; server "
                                "state predicates still require handler evidence"
                            ),
                        }],
                    })
                frontier = list(frontier_by_id.values())
                emit_trace(
                    self.trace, "state_dependency", "function_opened",
                    f"{action.action_id}: opened {current.name}",
                    action_id=action.action_id,
                    round=round_index,
                    function=function_ref(current),
                    opened_function_ids=list(opened),
                    candidate_function_ids=[str(item["function_id"]) for item in frontier],
                )
                latest = await self.llm.complete_json(
                    role="state_dependency",
                    instructions=(
                        "Starting at the real action handler, work backward from success guards and state lookups to "
                        "identify state predicates consumed by this action, then identify state it produces or "
                        "invalidates after success. Request at most one next function. Distinguish process-start "
                        "initialization from externally creatable state. Mark a resource initial only when opened "
                        "source proves it exists before any external request. If an initial resource uses a symbolic "
                        "binding, binding_value_hex must contain the concrete source-proven initial value; otherwise "
                        "leave it unresolved. Cite exact opened source for every "
                        "predicate. State may have scope global/connection/session/object and owner_binding; "
                        "emit those fields only when source identifies their ownership. Do not equate "
                        "same-named resources across different scopes or sessions. "
                        "Upstream FuzzGen/Hopper/WINNIE/RUBICK records are ordering evidence, not permission "
                        "to invent a state relation. Project test/client usage candidates may demonstrate an observed "
                        "request order, but every state predicate must also be supported by opened product-handler source. "
                        "A consumed binding must map to an opened request field. A produced "
                        "binding must map either to a request field or to the action's source-proven response_bindings "
                        "slice. Never claim runtime proof and never generate request order here. "
                        "Every response is a complete current contract snapshot. On the final "
                        "context_complete turn, restate every still-supported state claim, the "
                        "success condition, and handler evidence. Do not silently drop a prior "
                        "claim; unresolved or refuted claims must be reported in unknowns."
                    ),
                    payload={
                        "action": _action_payload(action),
                        "original_trial_feedback": self.original_trial_feedback.get(action.action_id, []),
                        "round": round_index,
                        "current_function": function_payload(current),
                        "opened_functions": [function_ref(self.graph.get(item)) for item in opened],
                        "frontier": frontier,
                        "upstream_usage_evidence": self.usage_evidence.relevant_payload(opened),
                        "previous_contract_summary": _contract_summary(latest),
                    },
                    output_schema=STATE_DEPENDENCY_SCHEMA,
                    session_key=self.session_key(action),
                )
                response_history.append(latest)
                complete = bool(latest.get("context_complete", False))
                if complete:
                    break
                requested = string_list(latest.get("requested_function_ids"))
                allowed = {str(item["function_id"]) for item in frontier}
                pending = requested[0] if requested and requested[0] in allowed else ""
                if not pending:
                    break
        except Exception as exc:
            infrastructure_failure = (
                f"{action.action_id}: state-dependency session failed with "
                f"{type(exc).__name__}: {exc}"
            )
            self.infrastructure_failures.append(infrastructure_failure)
            if _is_non_retryable_infrastructure_failure(exc):
                raise
        finally:
            await close_llm_session(self.llm, self.session_key(action))

        if infrastructure_failure:
            return ActionStateContract(
                action_id=action.action_id,
                consumes=[], produces=[], invalidates=[], success_condition="",
                evidence=[], inspected_function_ids=opened,
                status=ProofStatus.POSSIBLE,
                unknowns=[infrastructure_failure],
            ), []

        opened_set = set(opened)
        consumes = _merge_requirements([
            item
            for historical_response in response_history
            for item in _requirements(
                historical_response.get("consumes"), opened_set, self.graph
            )
        ])
        produces = _merge_requirements([
            item
            for historical_response in response_history
            for item in _requirements(
                historical_response.get("produces"), opened_set, self.graph
            )
        ])
        invalidates = _merge_requirements([
            item
            for historical_response in response_history
            for item in _requirements(
                historical_response.get("invalidates"), opened_set, self.graph
            )
        ])
        initial = _merge_requirements([
            item
            for historical_response in response_history
            for item in _requirements(
                historical_response.get("initial_resources"),
                opened_set,
                self.graph,
            )
        ])
        evidence_by_key = {
            (
                item.function_id, item.file, item.line,
                item.kind, item.detail,
            ): item
            for historical_response in response_history
            for item in _validated_evidence(
                historical_response.get("evidence"), opened_set, self.graph
            )
        }
        evidence = list(evidence_by_key.values())
        unknowns = string_list(latest.get("unknowns"))
        invalid_state_claims = sum(
            _invalid_requirement_count(
                historical_response.get(field), opened_set, self.graph
            )
            for historical_response in response_history
            for field in (
                "consumes", "produces", "invalidates", "initial_resources"
            )
        )
        if invalid_state_claims:
            unknowns.append(
                f"{invalid_state_claims} state claim(s) lacked valid opened-source evidence"
            )
        # Historical claims may be retained for diagnosis, but the final model
        # turn must explicitly reaffirm them before the contract is promoted.
        prior_claims = {
            (field, item.resource, item.binding, item.predicate, item.binding_value_hex)
            for historical_response in response_history[:-1]
            for field in ("consumes", "produces", "invalidates", "initial_resources")
            for item in _requirements(
                historical_response.get(field), opened_set, self.graph
            )
        }
        final_claims = {
            (field, item.resource, item.binding, item.predicate, item.binding_value_hex)
            for field in ("consumes", "produces", "invalidates", "initial_resources")
            for item in _requirements(latest.get(field), opened_set, self.graph)
        }
        if prior_claims - final_claims:
            unknowns.append("prior state claim(s) were not reaffirmed in the final snapshot")
        unresolved_initial_bindings = [
            item.binding for item in initial
            if item.binding and item.binding_value_hex is None
        ]
        if unresolved_initial_bindings:
            unknowns.append(
                "initial state has symbolic binding(s) without concrete value: "
                + ", ".join(sorted(set(unresolved_initial_bindings)))
            )
        request_binding_names = {
            item.binding for item in action.fields if item.binding
        }
        response_binding_names = {
            item.binding for item in action.response_bindings if item.binding
        }
        unmapped_consumed_bindings = sorted({
            item.binding for item in consumes
            if item.binding and item.binding not in request_binding_names
        })
        unmapped_produced_bindings = sorted({
            item.binding for item in produces
            if item.binding
            and item.binding not in request_binding_names
            and item.binding not in response_binding_names
        })
        owners_missing = sorted({
            item.owner_binding for item in [*consumes, *produces, *invalidates]
            if item.owner_binding
            and item.owner_binding not in request_binding_names
            and item.owner_binding not in response_binding_names
        })
        if owners_missing:
            unknowns.append(
                "state owner(s) have no source-proven request/response binding: "
                + ", ".join(owners_missing)
            )
        if unmapped_consumed_bindings:
            unknowns.append(
                "consumed binding(s) have no source-proven request field: "
                + ", ".join(unmapped_consumed_bindings)
            )
        if unmapped_produced_bindings:
            unknowns.append(
                "produced binding(s) have no request or response source: "
                + ", ".join(unmapped_produced_bindings)
            )
        success_condition = str(latest.get("success_condition", "")).strip()
        if not success_condition:
            unknowns.append("the action success condition was not established")
        final_evidence = _validated_evidence(
            latest.get("evidence"), opened_set, self.graph
        )
        if not any(item.function_id == root for item in final_evidence):
            unknowns.append("final state snapshot lacks handler evidence")
        unknowns = unique_strings(unknowns)
        status = (
            ProofStatus.PROVEN_STATIC
            if (
                complete
                and evidence
                and any(item.function_id == root for item in evidence)
                and success_condition
                and not unknowns
            )
            else ProofStatus.POSSIBLE
        )
        if evidence and not any(item.function_id == root for item in evidence):
            unknowns = unique_strings([
                *unknowns,
                "state contract lacks evidence from the product action handler",
            ])
        contract = ActionStateContract(
            action_id=action.action_id,
            consumes=consumes,
            produces=produces,
            invalidates=invalidates,
            success_condition=success_condition,
            evidence=evidence,
            inspected_function_ids=opened,
            status=status,
            unknowns=unknowns + ([] if complete else ["state context walk did not complete"]),
        )
        emit_trace(
            self.trace, "state_dependency", "action_completed",
            f"{action.action_id}: {status}",
            action_id=action.action_id,
            contract=contract,
            initial_resources=initial,
        )
        return contract, initial


class ScenarioPlanner:
    """Deterministic RESTler-style producer/consumer sequence search."""

    def __init__(
        self,
        *,
        max_steps: int = 0,
        max_candidates: int = 256,
        max_variants_per_action: int = 0,
        max_search_states: int = 4096,
    ):
        self.max_steps = max(0, max_steps)
        self.max_candidates = max(1, max_candidates)
        self.max_variants_per_action = max(0, max_variants_per_action)
        self.max_search_states = max(1, max_search_states)
        self.obligations: list[str] = []

    def plan(
        self,
        actions: list[ExternalActionSchema],
        dependencies: StateDependencyGraph,
    ) -> list[ScenarioCandidate]:
        self.obligations = []
        usable_actions = {
            item.action_id: item for item in actions
            if item.status is ProofStatus.PROVEN_STATIC and item.examples
        }
        contracts = {
            item.action_id: item for item in dependencies.contracts
            if item.status is ProofStatus.PROVEN_STATIC and item.action_id in usable_actions
        }
        initial = {
            _resource_key(item) for item in dependencies.initial_resources
            if item.status is ProofStatus.PROVEN_STATIC
            and (not item.binding or item.binding_value_hex is not None)
        }
        initial_bindings: dict[str, str] = {}
        conflicting_initial_bindings: set[str] = set()
        for item in dependencies.initial_resources:
            if item.status is not ProofStatus.PROVEN_STATIC or not item.binding:
                continue
            if item.binding_value_hex is None:
                self.obligations.append(
                    f"initial resource {item.resource!r} has binding "
                    f"{item.binding!r} without a concrete value"
                )
                continue
            previous = initial_bindings.get(item.binding)
            if previous is not None and previous != item.binding_value_hex:
                conflicting_initial_bindings.add(item.binding)
                self.obligations.append(
                    f"initial binding {item.binding!r} has conflicting concrete values"
                )
                continue
            initial_bindings[item.binding] = item.binding_value_hex
        for binding in conflicting_initial_bindings:
            initial_bindings.pop(binding, None)
            initial = {
                key for key in initial
                if key.split("\x1f", 2)[1] != binding
            }
        result: list[ScenarioCandidate] = []
        per_target_limit = self.max_variants_per_action or self.max_candidates
        target_ids = list(usable_actions)
        for target_index, target_id in enumerate(target_ids):
            if target_id not in contracts:
                result.append(_blocked_candidate(target_id, "state contract is not statically proven"))
                continue
            search_results, search_exhausted = self._search_many(
                target_id,
                usable_actions,
                contracts,
                initial,
                initial_bindings,
                dependencies.ordering_constraints,
                limit=per_target_limit,
            )
            if search_exhausted:
                self.obligations.append(
                    f"{target_id}: scenario search exhausted the "
                    f"{self.max_search_states}-state safety limit"
                )
            if not search_results:
                missing = sorted(
                    _resource_key(item) for item in contracts[target_id].consumes
                    if _resource_key(item) not in initial
                )
                missing.extend(
                    f"required predecessor {item.predecessor_action_id}"
                    for item in dependencies.ordering_constraints
                    if item.strength == "REQUIRED"
                    and item.successor_action_id == target_id
                )
                result.append(_blocked_candidate(
                    target_id,
                    (f"producer sequence unresolved; unexplored states remaining "
                     if search_exhausted else "no producer sequence satisfies: ")
                    + ", ".join(missing),
                ))
                continue
            for steps, final_resources in search_results:
                scenario_id = stable_id(
                    "scenario", target_id,
                    *[
                        f"{step.action_id}:{step.request_hex}:"
                        + ",".join(
                            f"{item.binding}@{item.producer_step_index}:"
                            f"{item.offset}+{item.width}"
                            for item in step.request_binding_uses
                        )
                        for step in steps
                    ],
                )
                result.append(ScenarioCandidate(
                    scenario_id=scenario_id,
                    target_action_id=target_id,
                    steps=steps,
                    required_entries=unique_strings(step.entry_id for step in steps),
                    satisfied_resources=sorted(final_resources),
                    planning_evidence=[
                        "deterministic producer/consumer search: "
                        + " -> ".join(step.action_id for step in steps),
                        *[
                            f"{item.provider} {item.strength}: "
                            f"{item.predecessor_action_id} -> {item.successor_action_id}"
                            for item in dependencies.ordering_constraints
                            if item.predecessor_action_id in {step.action_id for step in steps}
                            and item.successor_action_id in {step.action_id for step in steps}
                        ],
                    ],
                ))
        grouped: dict[str, list[ScenarioCandidate]] = {
            target_id: [] for target_id in target_ids
        }
        for candidate in result:
            grouped[candidate.target_action_id].append(candidate)
        scheduled: list[ScenarioCandidate] = []
        # A work cap may trim alternatives, but cannot erase the sole outcome
        # for a later target. Round robin preserves every target first.
        for target_id in target_ids:
            if grouped[target_id]:
                scheduled.append(grouped[target_id].pop(0))
        if len(scheduled) > self.max_candidates:
            self.obligations.append(
                'retaining one planning outcome per target beyond the configured '
                f'{self.max_candidates}-candidate work budget'
            )
        while len(scheduled) < self.max_candidates and any(grouped.values()):
            for target_id in target_ids:
                if len(scheduled) >= self.max_candidates:
                    break
                if grouped[target_id]:
                    scheduled.append(grouped[target_id].pop(0))
        for target_id, pending in grouped.items():
            if pending or len(usable_actions[target_id].examples) > per_target_limit:
                self.obligations.append(
                    f'{target_id}: variant work budget left request alternatives untested'
                )
        return scheduled

    def post_fuzz_candidates(
        self,
        actions: list[ExternalActionSchema],
        dependencies: StateDependencyGraph,
        base_candidates: list[ScenarioCandidate],
        *,
        limit: int | None = None,
        allow_hypotheses: bool = False,
    ) -> list[ScenarioCandidate]:
        """Construct a bounded Setup → Fuzz → Post producer/consumer witness.

        Fuzz mutates an external action that *produces* state, while a normal
        following action observes that state. Every post must be an existing
        source-backed action with a valid concrete request. No new callback or
        state transition is invented. Separate baseline replay still required.
        """
        by_action = {
            item.action_id: item for item in actions
            if item.examples and (item.status is ProofStatus.PROVEN_STATIC or (
                allow_hypotheses and item.status is ProofStatus.POSSIBLE and item.evidence
            ))
        }
        by_contract = {
            item.action_id: item for item in dependencies.contracts
            if item.action_id in by_action and (
                item.status is ProofStatus.PROVEN_STATIC or (
                    allow_hypotheses and item.status is ProofStatus.POSSIBLE and item.evidence
                )
            )
        }
        result: list[ScenarioCandidate] = []
        distinct: set[tuple[str, ...]] = set()
        for candidate in base_candidates:
            if (candidate.status is not ScenarioStatus.CANDIDATE
                or not candidate.steps or len(candidate.steps) >= (self.max_steps or len(actions) + 1)
                or candidate.target_action_id not in by_contract):
                continue
            producer_contract = by_contract[candidate.target_action_id]
            if not producer_contract.produces:
                continue
            for consumer_id, contract in by_contract.items():
                if consumer_id == candidate.target_action_id:
                    continue
                if not contract.consumes or not _requirements_satisfied(
                    contract.consumes, frozenset(candidate.satisfied_resources)
                ):
                    continue
                # The successor must actually consume a state produced by
                # the fuzzed action rather than an unrelated initial state.
                if not ({_resource_key(item) for item in producer_contract.produces}
                        & {_resource_key(item) for item in contract.consumes}):
                    continue
                if not _ordering_allows(consumer_id,
                                        tuple(step.action_id for step in candidate.steps),
                                        dependencies.ordering_constraints):
                    continue
                last = candidate.steps[-1]
                # Only constant, source-backed bindings are supported here.
                # A response-produced token needs post-fuzz dynamic extraction
                # and cannot silently be hard-coded to the baseline value.
                if last.response_binding_extractors:
                    continue
                for successor, _new_bindings in _materialize_action(
                    by_action[consumer_id], len(candidate.steps), last.bindings
                ):
                    if successor.request_binding_uses:
                        continue
                    steps = [*candidate.steps, successor]
                    signature = tuple(f"{item.action_id}:{item.request_hex}" for item in steps)
                    if signature in distinct:
                        continue
                    distinct.add(signature)
                    fuzz_index = len(candidate.steps) - 1
                    result.append(ScenarioCandidate(
                        scenario_id=stable_id("post-fuzz", candidate.scenario_id, *signature),
                        target_action_id=candidate.target_action_id,
                        steps=steps,
                        required_entries=unique_strings(item.entry_id for item in steps),
                        satisfied_resources=list(candidate.satisfied_resources),
                        planning_evidence=[
                            *candidate.planning_evidence,
                            f"POST_FUZZ: {candidate.target_action_id} produces "
                            f"state consumed by {consumer_id}; post-step observes the effect",
                            *( ["PROVISIONAL_STATE_DEPENDENCY: source-based hypothesis, "
                                "not a runtime-proven order"] if (
                                producer_contract.status is not ProofStatus.PROVEN_STATIC
                                or contract.status is not ProofStatus.PROVEN_STATIC
                            ) else [] ),
                        ],
                        fuzz_step_index=fuzz_index,
                    ))
        if limit is None:
            return result
        grouped: dict[str, list[ScenarioCandidate]] = {}
        for item in result:
            grouped.setdefault(item.target_action_id, []).append(item)
        selected: list[ScenarioCandidate] = []
        for target_id in grouped:
            selected.append(grouped[target_id].pop(0))
        if len(selected) > limit:
            self.obligations.append(
                'retaining one post-fuzz planning outcome per state producer '
                f'beyond the configured {limit}-candidate work budget'
            )
        while len(selected) < limit and any(grouped.values()):
            for target_id in grouped:
                if len(selected) >= limit:
                    break
                if grouped[target_id]:
                    selected.append(grouped[target_id].pop(0))
        if any(grouped.values()):
            self.obligations.append(
                'post-fuzz variant work budget left alternatives untested'
            )
        return selected

    def exploratory_candidates(
        self,
        actions: list[ExternalActionSchema],
        strict_candidates: list[ScenarioCandidate],
        *,
        dependencies: StateDependencyGraph | None = None,
        limit: int | None = None,
    ) -> list[ScenarioCandidate]:
        """Build bounded trial sequences without promoting uncertain contracts.

        Source-located action examples and provisional producer/consumer
        relations can generate experiments. Both remain hypotheses until the
        original-program run and the resulting harness have been checked.
        Successful strict scenarios always take precedence over these trials.
        """
        scheduled = {
            candidate.target_action_id for candidate in strict_candidates
            if candidate.status is ScenarioStatus.CANDIDATE
        }
        remaining = min(
            max(0, self.max_candidates - sum(
                item.status is ScenarioStatus.CANDIDATE
                for item in strict_candidates
            )),
            limit if limit is not None else self.max_candidates,
        )
        eligible: dict[str, ExternalActionSchema] = {
            action.action_id: action for action in actions
            if action.status is not ProofStatus.REFUTED
            and action.examples
            and action.evidence
            and action.entry_function_id
            and action.handler_function_id
            # A silent command-line/file operation can still produce a
            # buildable draft. The absence of an output oracle blocks runtime
            # verification, not source-level candidate inventory.
        }
        unscheduled_targets = [action_id for action_id in eligible
                               if action_id not in scheduled]
        if len(unscheduled_targets) > remaining and limit is None:
            self.obligations.append(
                'reserving one trial slot per target beyond the configured '
                f'{remaining}-candidate work budget'
            )
            remaining = len(unscheduled_targets)
        elif len(unscheduled_targets) > remaining:
            self.obligations.append(
                'explicit diagnostic limit omitted target action(s): '
                + ', '.join(unscheduled_targets[remaining:])
            )
        provisional_contracts = {
            item.action_id: item for item in (dependencies.contracts if dependencies else [])
            if item.action_id in eligible and item.status is not ProofStatus.REFUTED
        }
        # Never assume unproven startup resources are present.
        initial_resources = {
            _resource_key(item) for item in (dependencies.initial_resources if dependencies else [])
            if item.status is ProofStatus.PROVEN_STATIC
            and (not item.binding or item.binding_value_hex is not None)
        }
        initial_bindings = {
            item.binding: item.binding_value_hex
            for item in (dependencies.initial_resources if dependencies else [])
            if item.status is ProofStatus.PROVEN_STATIC
            and item.binding and item.binding_value_hex is not None
        }
        ordering = dependencies.ordering_constraints if dependencies else []
        per_action: dict[str, list[ScenarioCandidate]] = {}
        variant_limit = self.max_variants_per_action or self.max_candidates
        for action in eligible.values():
            if action.action_id in scheduled:
                continue
            search_results: list[tuple[list[ScenarioStep], set[str]]] = []
            if action.action_id in provisional_contracts:
                search_results, search_exhausted = self._search_many(
                    action.action_id, eligible, provisional_contracts,
                    initial_resources, initial_bindings, ordering,
                    limit=variant_limit,
                )
                if search_exhausted:
                    self.obligations.append(
                        f'{action.action_id}: additional prerequisite sequences '
                        'remain unresolved'
                    )
            if not search_results:
                # When no provisional state producer can be found, preserve
                # the action as a direct input trial. A failed response can
                # inform the next source-guided request repair.
                search_results = [
                    ([step], set())
                    for step, _bindings in _materialize_action(action, 0, {})
                    if not step.request_binding_uses
                ][:variant_limit]
            if not search_results:
                self.obligations.append(
                    f'{action.action_id}: no concrete standalone request could '
                    'be rendered from the available examples and bindings'
                )
            for steps, final_resources in search_results:
                signature = [
                    f"{step.action_id}:{step.request_hex}:"
                    + ",".join(f"{use.binding}@{use.producer_step_index}"
                               for use in step.request_binding_uses)
                    for step in steps
                ]
                per_action.setdefault(action.action_id, []).append(ScenarioCandidate(
                    scenario_id=stable_id(
                        "exploratory-scenario", action.action_id, *signature,
                    ),
                    target_action_id=action.action_id,
                    steps=steps,
                    required_entries=unique_strings(step.entry_id for step in steps),
                    satisfied_resources=sorted(final_resources),
                    planning_evidence=[
                        "EXPLORATORY: source-supported request candidate",
                        "state prerequisites and request-to-handler causality are not proven",
                        "tentative producer/consumer sequence: "
                        + " -> ".join(step.action_id for step in steps),
                    ],
                ))
        results: list[ScenarioCandidate] = []
        target_ids = list(per_action)
        while remaining > 0 and any(per_action.values()):
            for target_id in target_ids:
                if remaining <= 0:
                    break
                if per_action[target_id]:
                    results.append(per_action[target_id].pop(0))
                    remaining -= 1
        for target_id, pending in per_action.items():
            if pending:
                self.obligations.append(
                    f'{target_id}: exploratory variant work budget left alternatives untested'
                )
        return results

    def _search_many(
        self,
        target_id: str,
        actions: dict[str, ExternalActionSchema],
        contracts: dict[str, ActionStateContract],
        initial: set[str],
        initial_bindings: dict[str, str],
        ordering: list[ActionOrderingConstraint],
        *,
        limit: int,
    ) -> tuple[list[tuple[list[ScenarioStep], set[str]]], bool]:
        queue: deque[
            tuple[tuple[ScenarioStep, ...], frozenset[str], tuple[tuple[str, str], ...]]
        ] = deque([(
            (), frozenset(initial), tuple(sorted(initial_bindings.items()))
        )])
        seen: set[
            tuple[
                frozenset[str],
                frozenset[str],
                tuple[tuple[str, str], ...],
                tuple[tuple[str, str], ...],
            ]
        ] = set()
        results: list[tuple[list[ScenarioStep], set[str]]] = []
        result_signatures: set[tuple[tuple[str, str], ...]] = set()
        required_resources = {
            _resource_key(item) for item in contracts[target_id].consumes
        }
        required_ordering = {
            item.predecessor_action_id for item in ordering
            if item.strength == 'REQUIRED'
            and item.successor_action_id == target_id
        }
        relevant_ids: set[str] = set()
        changed = True
        while changed:
            changed = False
            for action_id, contract in contracts.items():
                if action_id == target_id or action_id in relevant_ids:
                    continue
                if (action_id not in required_ordering
                    and not ({_resource_key(item) for item in contract.produces}
                             & required_resources)):
                    continue
                relevant_ids.add(action_id)
                required_resources.update(_resource_key(item)
                                          for item in contract.consumes)
                required_ordering.update(
                    item.predecessor_action_id for item in ordering
                    if item.strength == 'REQUIRED'
                    and item.successor_action_id == action_id
                )
                changed = True
        ordered_ids = sorted(relevant_ids)
        explored = 0
        while (
            queue
            and len(results) < max(1, limit)
            and explored < self.max_search_states
        ):
            steps, resources, frozen_bindings = queue.popleft()
            explored += 1
            bindings = dict(frozen_bindings)
            performed = tuple(step.action_id for step in steps)
            path_signature = tuple(
                (step.action_id, step.request_hex) for step in steps
            )
            state_key = (
                resources,
                frozenset(performed),
                frozen_bindings,
                path_signature,
            )
            if state_key in seen:
                continue
            seen.add(state_key)
            target_contract = contracts[target_id]
            if (
                _requirements_satisfied(target_contract.consumes, resources)
                and _ordering_allows(target_id, performed, ordering)
            ):
                materialized = _materialize_action(actions[target_id], len(steps), bindings)
                for target_step, _ in materialized:
                    signature = (*path_signature, (target_step.action_id, target_step.request_hex))
                    if signature in result_signatures:
                        continue
                    result_signatures.add(signature)
                    final_resources = _apply_contract(resources, target_contract)
                    results.append(([*steps, target_step], final_resources))
                    if len(results) >= max(1, limit):
                        break
                if materialized:
                    # BFS has found the shortest valid prefix for this state.
                    # Do not append unrelated extra setup actions after a
                    # materializable target; alternate examples were retained
                    # above and alternate prefixes remain queued separately.
                    continue
            if len(steps) >= (self.max_steps or len(actions)) - 1:
                continue
            for action_id in ordered_ids:
                if action_id == target_id or action_id not in contracts:
                    continue
                contract = contracts[action_id]
                if (
                    not _requirements_satisfied(contract.consumes, resources)
                    or not _ordering_allows(action_id, performed, ordering)
                ):
                    continue
                next_resources = _apply_contract(resources, contract)
                required_for_later = any(
                    item.strength == "REQUIRED"
                    and item.predecessor_action_id == action_id
                    and item.successor_action_id not in performed
                    for item in ordering
                )
                if next_resources == resources and (
                    action_id in performed or not required_for_later
                ):
                    continue
                for step, next_bindings in _materialize_action(
                    actions[action_id], len(steps), bindings
                ):
                    queue.append((
                        (*steps, step),
                        frozenset(next_resources),
                        tuple(sorted(next_bindings.items())),
                    ))
        exhausted = bool(
            queue
            and len(results) < max(1, limit)
            and explored >= self.max_search_states
        )
        return results, exhausted


_ENTRY_DESTINATION_ARGUMENTS: dict[str, tuple[int, ...]] = {
    "read": (1,),
    "pread": (1,),
    "readv": (1,),
    "preadv": (1,),
    "recv": (1,),
    "recvfrom": (1,),
    "recvmsg": (1,),
    "wsarecv": (1,),
    "wsarecvfrom": (1,),
    "ssl_read": (1,),
    "ssl_read_ex": (1,),
    "bio_read": (1,),
    "gnutls_record_recv": (1,),
    "fread": (0,),
    "fread_unlocked": (0,),
    "fgets": (0,),
    "getline": (0,),
    "getdelim": (0,),
    "readlink": (1,),
}



def _source_field_return_callers(
    graph: GraphStore, entry: EntryRecord,
) -> dict[str, list[str]]:
    """Locate a caller reusing the same local object's acquired field."""
    reader = graph.bundle.functions.get(entry.entry_function_id)
    if reader is None:
        return {}
    sites = [site for site in reader.external_call_sites
             if site.get('api') == entry.source_api
             and (entry.entry_line is None or site.get('line') == entry.entry_line)]
    if len(sites) != 1:
        return {}
    bindings = sites[0].get('direct_argument_field_bindings') or []
    reader_params = [str(item.get('declaration_id') or '')
                     for item in reader.ast_parameter_declarations]
    output_bindings = [(reader_params.index(str(binding.get('receiver_declaration_id'))),
                        str(binding.get('field_declaration_id') or ''))
                       for index in _entry_destination_positions(reader, entry)
                       if index < len(bindings) and bindings[index]
                       for binding in [bindings[index]]
                       if str(binding.get('receiver_declaration_id') or '')
                       in reader_params and binding.get('field_declaration_id')]
    result: dict[str, list[str]] = {}
    for caller in graph.callers(reader.function_id):
        root_calls = [site for site in caller.direct_call_sites
                      if site.get('callee_function_id') == reader.function_id]
        for root_call in root_calls:
            args = root_call.get('direct_argument_declaration_ids') or []
            start = root_call.get('offset')
            for position, field_id in output_bindings:
                if position >= len(args) or not args[position]:
                    continue
                receiver_id = str(args[position])
                for later in caller.direct_call_sites:
                    if (later.get('callee_function_id') == reader.function_id
                        or not isinstance(start, int)
                        or not isinstance(later.get('offset'), int)
                        or later['offset'] <= start):
                        continue
                    if any(
                        isinstance(binding, dict)
                        and binding.get('receiver_declaration_id') == receiver_id
                        and binding.get('field_declaration_id') == field_id
                        for binding in later.get('direct_argument_field_bindings') or []
                    ):
                        target_id = str(later.get('callee_function_id') or '')
                        if target_id in graph.bundle.functions:
                            targets = result.setdefault(caller.function_id, [])
                            if target_id not in targets:
                                targets.append(target_id)
    return result


def _entry_shared_field_paths(
    function: FunctionMetadata, entry: EntryRecord,
) -> set[str]:
    """Identify file-scope object fields directly targeted by an Entry read."""
    globals_by_name = {str(item.get('name') or '')
                       for item in function.referenced_global_declarations}
    if not globals_by_name:
        return set()
    code = _code_only(function.source)
    calls = [item for item in _named_source_calls(function, entry.source_api)
             if entry.entry_line is None or item[0] == entry.entry_line]
    if len(calls) != 1:
        return set()
    _line, arguments, _offset = calls[0]
    paths: set[str] = set()
    for position in _entry_destination_positions(function, entry):
        if position >= len(arguments):
            continue
        for owner, field in re.findall(
            r'\b([A-Za-z_]\w*)\s*(?:\.|->)\s*([A-Za-z_]\w*)\b',
            arguments[position],
        ):
            if owner in globals_by_name:
                paths.add(f'{owner}.{field}')
    return paths


def _shared_field_aliases(
    graph: GraphStore, opened_ids: list[str], root_fields: set[str],
) -> set[str]:
    fields = set(root_fields)
    for _ in range(len(opened_ids) + 1):
        before = len(fields)
        for function_id in opened_ids:
            function = graph.bundle.functions.get(function_id)
            if function is None:
                continue
            code = _code_only(function.source)
            for destination, origin in re.findall(
                r'\b([A-Za-z_]\w*\s*(?:\.|->)\s*[A-Za-z_]\w*)'
                r'\s*=\s*'
                r'([A-Za-z_]\w*\s*(?:\.|->)\s*[A-Za-z_]\w*)\b',
                code,
            ):
                normal_origin = re.sub(r'\s*(?:\.|->)\s*', '.', origin)
                normal_destination = re.sub(r'\s*(?:\.|->)\s*', '.', destination)
                if normal_origin in fields:
                    fields.add(normal_destination)
        if len(fields) == before:
            break
    return fields


def _shared_field_handoff_candidates(
    graph: GraphStore, entry: EntryRecord, opened_ids: list[str],
    root_fields: set[str],
) -> list[tuple[str, str, str]]:
    """Offer source-located shared-field transforms reachable for inspection."""
    fields = _shared_field_aliases(graph, opened_ids, root_fields)
    opened = set(opened_ids)
    result: list[tuple[str, str, str]] = []
    for function in graph.bundle.functions.values():
        if function.function_id in opened:
            continue
        code = _code_only(function.source)
        for field in sorted(fields):
            owner, member = field.split('.', 1)
            pattern = (r'\b' + re.escape(owner) + r'\s*(?:\.|->)\s*'
                       + re.escape(member) + r'\b')
            if not re.search(pattern, code):
                continue
            # A candidate must either transform the field or consume it in
            # a function already selected by the opened call path. The
            # former is the missing source-linked field handoff.
            transform = re.search(
                r'\b[A-Za-z_]\w*\s*(?:\.|->)\s*[A-Za-z_]\w*'
                r'\s*=\s*' + pattern, code,
            )
            callers = [edge.caller_id for edge in graph.bundle.edges
                       if edge.callee_id == function.function_id
                       and edge.caller_id in opened]
            if not transform and not callers:
                continue
            related = callers[0] if callers else entry.entry_function_id
            item = (function.function_id, related, field)
            if item not in result:
                result.append(item)
    return result


def _shared_field_return_callers(
    graph: GraphStore, opened_ids: list[str], root_fields: set[str],
    entry_function_id: str,
) -> list[tuple[str, str]]:
    """Find caller bodies that use a field after an opened read wrapper."""
    fields = _shared_field_aliases(graph, opened_ids, root_fields)
    opened = set(opened_ids)
    result: list[tuple[str, str]] = []
    for edge in graph.bundle.edges:
        if (edge.callee_id not in opened
            or edge.caller_id in opened
            or edge.callee_id == entry_function_id
            or edge.kind not in {'direct', 'source_candidate'}):
            continue
        caller = graph.bundle.functions.get(edge.caller_id)
        callee = graph.bundle.functions.get(edge.callee_id)
        if caller is None or callee is None:
            continue
        call_sites = [site for site in caller.direct_call_sites
                      if site.get('callee_function_id') == callee.function_id]
        if not call_sites:
            continue
        code = _code_only(caller.source)
        for field in fields:
            owner, member = field.split('.', 1)
            pattern = (r'\b' + re.escape(owner) + r'\s*(?:\.|->)\s*'
                       + re.escape(member) + r'\b')
            if re.search(pattern, code):
                item = (caller.function_id, callee.function_id)
                if item not in result:
                    result.append(item)
                break
    return result


def _source_output_parameter_field_callers(
    graph: GraphStore, entry: EntryRecord, *, include_local: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Locate callers passing field/local storage to an Entry output parameter.

    This supplies source-navigation leads. It does not prove the caller runs,
    the read succeeds, or that a downstream consumer observes those bytes.
    """
    reader = graph.bundle.functions.get(entry.entry_function_id)
    if reader is None:
        return {}
    positions = _entry_destination_positions(reader, entry)
    sites = [site for site in reader.external_call_sites
             if site.get("api") == entry.source_api
             and (entry.entry_line is None or site.get("line") == entry.entry_line)]
    if len(sites) != 1:
        return {}
    site = sites[0]
    arguments = site.get("direct_argument_declaration_ids") or []
    parameter_ids = [str(item.get("declaration_id") or "")
                     for item in reader.ast_parameter_declarations]
    output_parameters = {parameter_ids.index(str(arguments[index]))
                         for index in positions
                         if index < len(arguments)
                         and str(arguments[index]) in parameter_ids
                         and arguments[index]}
    if not output_parameters:
        return {}
    result: dict[str, list[dict[str, Any]]] = {}
    for caller in graph.callers(reader.function_id):
        for call in caller.direct_call_sites:
            if call.get("callee_function_id") != reader.function_id:
                continue
            field_bindings = call.get("direct_argument_field_bindings") or []
            identifiers = call.get("direct_argument_identifiers") or []
            declarations = call.get("direct_argument_declaration_ids") or []
            for index in sorted(output_parameters):
                if index < len(field_bindings) and field_bindings[index]:
                    binding = field_bindings[index]
                    record = {
                        "storage_kind": "field",
                        "field_name": str(binding.get("field_name") or ""),
                        "receiver_kind": str(binding.get("receiver_kind") or ""),
                        "receiver_declaration_id": str(
                            binding.get("receiver_declaration_id") or ""
                        ),
                        "call_line": call.get("line"),
                    }
                elif include_local and index < len(declarations) and declarations[index]:
                    record = {
                        "storage_kind": "local_or_parameter",
                        "storage_name": str(identifiers[index] or "")
                        if index < len(identifiers) else "",
                        "storage_declaration_id": str(declarations[index]),
                        "call_line": call.get("line"),
                    }
                else:
                    continue
                records = result.setdefault(caller.function_id, [])
                if record not in records:
                    records.append(record)
    return result


def _entry_api_call_pattern(api: str) -> re.Pattern[str]:
    if '::' not in api:
        # A C API may be called with the C++ global-scope qualifier ::read.
        # A member or namespace-qualified lookalike stays excluded.
        return re.compile(r'(?<![\w:])(?:::)?' + re.escape(api) + r'\s*\(')
    return re.compile(r'(?<![\w:])' + re.escape(api) + r'\s*\(')


def _external_site_matches_entry(
    function: FunctionMetadata, site: dict[str, Any], entry: EntryRecord,
) -> bool:
    api = str(site.get('api') or '')
    if entry.entry_line is not None and site.get('line') != entry.entry_line:
        return False
    if api == entry.source_api:
        return True
    if (entry.source_api == 'std::getline' and api == 'getline'
        and any(function.start_line + function.source.count('\n', 0, match.start())
                == site.get('line')
                for match in _entry_api_call_pattern(entry.source_api).finditer(
                    function.source))):
        return True
    return False


def _entry_destination_positions(
    function: FunctionMetadata, entry: EntryRecord,
) -> tuple[int, ...]:
    """Identify the written argument of this exact external acquisition.

    A qualified C++ API is matched as qualified; an unrelated function with
    the same last component is not evidence of the same acquisition site.
    The result is a navigation fact, never proof of byte-level aliasing.
    """
    api = entry.source_api.strip()
    if not api:
        return ()
    sites = [site for site in function.external_call_sites
             if _external_site_matches_entry(function, site, entry)]
    for site in sites:
        positions = site.get('destination_argument_positions')
        if isinstance(positions, list) and positions:
            return tuple(index for index in positions
                         if isinstance(index, int) and index >= 0)
    if api.startswith('std::'):
        if api != 'std::getline':
            return ()
        positions = (1,)
    elif '::' in api:
        return ()
    else:
        positions = _ENTRY_DESTINATION_ARGUMENTS.get(api.casefold(), ())
    if not positions:
        return ()
    pattern = _entry_api_call_pattern(api)
    if len(sites) == 1 and sites[0].get('macro_expansion'):
        # Clang identifies the expanded call and its argument declarations;
        # the function body legitimately contains only the macro invocation.
        return positions
    if not any(
        entry.entry_line is None
        or function.start_line + function.source.count('\n', 0, m.start())
           == entry.entry_line
        for m in pattern.finditer(function.source)
    ):
        return ()
    return positions


def _written_buffer_names(expression: str) -> set[str]:
    """Keep only a direct local destination, not an owning object or index."""
    expression = expression.strip()
    match = re.match(r'^&?\s*([A-Za-z_]\w*)\b', expression)
    if not match:
        return set()
    name = match.group(1)
    remainder = expression[match.end():].lstrip()
    if remainder.startswith(('->', '.')):
        return set()
    if remainder.startswith('['):
        # Taking an indexed address identifies a buffer only for a plain
        # local array, not a field/owner expression.
        return {name} if expression.startswith('&' + name + '[') else set()
    if not remainder or remainder.startswith(('+', '-')):
        return {name}
    return set()





def source_receiver_field_navigation_candidates(
    graph: GraphStore, entry: EntryRecord, *, direct_edges_only: bool = False,
) -> list[str]:
    """Follow a read receiver through direct calls to a field user.

    This is a navigational slice, not a claim of object identity or feasible
    execution. AST declaration identity prevents same-spelled other objects
    from being conflated. A direct call after acquisition is required in both
    modes; the flag keeps the Input Surface caller's stricter API explicit.
    """
    root = graph.bundle.functions.get(entry.entry_function_id)
    if root is None:
        return []
    sites = [site for site in root.external_call_sites
             if _external_site_matches_entry(root, site, entry)]
    if len(sites) != 1:
        return []
    site = sites[0]
    owner_ids: set[str] = set()
    owner_names: set[str] = set()
    bindings = site.get('direct_argument_field_bindings') or []
    for index in _entry_destination_positions(root, entry):
        if index >= len(bindings) or not bindings[index]:
            continue
        binding = bindings[index]
        identifier = str(binding.get('receiver_declaration_id') or '')
        if identifier:
            owner_ids.add(identifier)
    for param in root.ast_parameter_declarations:
        if str(param.get('declaration_id') or '') in owner_ids:
            owner_names.add(str(param.get('name') or ''))
    if not owner_ids:
        return []
    if not owner_names:
        # The receiver may be a local object rather than a parameter (for
        # example `std::getline(stream, session.line)` in main). The Clang
        # field binding gives its declaration ID; recover its spelling only
        # from the exact cited call argument.
        for match in _entry_api_call_pattern(entry.source_api).finditer(root.source):
            line = root.start_line + root.source.count('\n', 0, match.start())
            if entry.entry_line is not None and line != entry.entry_line:
                continue
            opening = root.source.find('(', match.start())
            closing = _matching_source_paren(root.source, opening)
            if closing < 0:
                continue
            arguments = _split_source_arguments(root.source[opening + 1:closing])
            for index in _entry_destination_positions(root, entry):
                if index >= len(arguments) or index >= len(bindings):
                    continue
                binding = bindings[index]
                if not binding or str(binding.get('receiver_declaration_id') or '') not in owner_ids:
                    continue
                owner = re.match(r'\s*([A-Za-z_]\w*)\s*(?:->|\.)',
                                 arguments[index])
                if owner:
                    owner_names.add(owner.group(1))
    fields: set[str] = set()
    for owner in owner_names:
        fields.update(_entry_receiver_field_names(root, entry, owner_filter=owner))
    if not fields:
        return []
    queue: deque[tuple[str, set[str], set[str], list[str]]] = deque([
        (root.function_id, owner_ids, owner_names, [])
    ])
    seen: set[tuple[str, tuple[str, ...]]] = set()
    paths_to_users: list[list[str]] = []
    while queue:
        function_id, current_ids, current_names, path = queue.popleft()
        key = (function_id, tuple(sorted(current_ids)))
        if key in seen:
            continue
        seen.add(key)
        function = graph.bundle.functions[function_id]
        if function_id != root.function_id:
            code = _code_only(function.source)
            if any(re.search(r'\b' + re.escape(owner) +
                             r'\s*(?:->|\.)\s*' + re.escape(field) + r'\b',
                             code)
                   for owner in current_names for field in fields):
                paths_to_users.append(path)
        for call in function.direct_call_sites:
            target_id = str(call.get('callee_function_id') or '')
            callee = graph.bundle.functions.get(target_id)
            if callee is None:
                continue
            if function_id == root.function_id:
                source_offset = site.get('offset')
                call_offset = call.get('offset')
                if (isinstance(source_offset, int)
                    and isinstance(call_offset, int)
                    and call_offset <= source_offset):
                    continue
            identities = call.get('direct_argument_declaration_ids') or []
            indices = [index for index, identifier in enumerate(identities)
                       if str(identifier) in current_ids and identifier]
            if not indices:
                continue
            next_ids: set[str] = set()
            next_names: set[str] = set()
            for index in indices:
                if index >= len(callee.ast_parameter_declarations):
                    continue
                param = callee.ast_parameter_declarations[index]
                identifier = str(param.get('declaration_id') or '')
                name = str(param.get('name') or '')
                if identifier and name:
                    next_ids.add(identifier)
                    next_names.add(name)
            if next_ids:
                queue.append((callee.function_id, next_ids, next_names,
                              [*path, callee.function_id]))
    result: list[str] = []
    for path in paths_to_users:
        for function_id in path:
            if function_id not in result:
                result.append(function_id)
    return result


def _entry_receiver_field_names(
    function: FunctionMetadata,
    entry: EntryRecord,
    *,
    owner_filter: str = '',
) -> set[str]:
    """Collect fields directly receiving bytes and same-owner field aliases.

    This remains a source-navigation relation. Pointer copies do not prove
    lifetime, alias equality, or that a later handler executes.
    """
    api = entry.source_api.strip()
    if not api:
        return set()
    code = _code_only(function.source)
    pattern = _entry_api_call_pattern(api)
    matches = [match for match in pattern.finditer(code)
               if entry.entry_line is None
               or function.start_line + code.count('\n', 0, match.start())
                  == entry.entry_line]
    if len(matches) != 1:
        return set()
    match = matches[0]
    opening = code.find('(', match.start())
    closing = _matching_source_paren(code, opening)
    if closing < 0:
        return set()
    arguments = _split_source_arguments(code[opening + 1:closing])
    fields: set[str] = set()
    owner = ''
    for position in _entry_destination_positions(function, entry):
        if position >= len(arguments):
            continue
        selected = re.match(
            r'\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)',
            arguments[position],
        )
        if not selected:
            continue
        if owner_filter and selected.group(1) != owner_filter:
            continue
        if owner and owner != selected.group(1):
            return set()
        owner = selected.group(1)
        fields.add(selected.group(2))
    if not owner:
        return set()
    assignment = re.compile(
        r'\b' + re.escape(owner)
        + r'\s*(?:->|\.)\s*([A-Za-z_]\w*)\s*=\s*'
        + re.escape(owner)
        + r'\s*(?:->|\.)\s*([A-Za-z_]\w*)\b'
    )
    changed = True
    while changed:
        changed = False
        for alias in assignment.finditer(code):
            destination, source = alias.groups()
            if source in fields and destination not in fields:
                fields.add(destination)
                changed = True
    return fields

def _producer_output_guard_candidates(
    graph: GraphStore, function: FunctionMetadata,
    producer_function_ids: set[str],
) -> list[str]:
    """Locate guards reading a parser's explicit output parameter storage.

    This is a source-navigation lead. It neither proves that the parser writes
    this value on the executed path nor that the guarded call is feasible.
    """
    produced: dict[str, tuple[int, str]] = {}
    for site in function.direct_call_sites:
        producer_id = str(site.get('callee_function_id') or '')
        if producer_id not in producer_function_ids:
            continue
        producer = graph.bundle.functions.get(producer_id)
        if producer is None:
            continue
        ids = site.get('direct_argument_declaration_ids') or []
        unit = str(site.get('analysis_unit') or '')
        offset = site.get('offset')
        for index in producer.parameter_output_positions:
            if index < len(ids) and ids[index] and isinstance(offset, int):
                produced[str(ids[index])] = (offset, unit)
    result: list[str] = []
    for guard in function.guarded_call_sites:
        target_id = str(guard.get('callee_function_id') or '')
        if target_id not in graph.bundle.functions:
            continue
        guard_offset = guard.get('guard_offset')
        if not isinstance(guard_offset, int):
            continue
        unit = str(guard.get('analysis_unit') or '')
        content_ids = set(map(str, guard.get('condition_content_declaration_ids') or []))
        for identifier in content_ids:
            record = produced.get(identifier)
            if record is None:
                continue
            source_offset, source_unit = record
            if source_offset < guard_offset and (not source_unit or not unit or source_unit == unit):
                if target_id not in result:
                    result.append(target_id)
                break
    return result


def _resolve_guard_target(
    graph: GraphStore, function: FunctionMetadata, guard: dict[str, Any],
) -> tuple[str, str]:
    target_id = str(guard.get('callee_function_id') or '')
    if target_id in graph.bundle.functions:
        return target_id, ''
    name = str(guard.get('callee_name') or 'unknown')
    symbol = str(guard.get('callee_linkage_symbol') or '')
    typ = str(guard.get('callee_linkage_type') or '')
    candidates = [candidate for candidate in graph.bundle.functions.values()
                  if symbol and candidate.linkage_symbol == symbol
                  and (not typ or candidate.linkage_type == typ)]
    if not candidates:
        candidates = [candidate for candidate in graph.bundle.functions.values()
                      if candidate.name == name and not symbol]
    source_unit = str(guard.get('analysis_unit') or '')
    compatible = [candidate for candidate in candidates
                  if candidate.linkage_external
                  or (source_unit and any(
                      source_unit == str(record.get('analysis_unit') or '')
                      for record in candidate.ast_parameter_declarations))]
    if len(compatible) == 1:
        return compatible[0].function_id, ''
    if len(compatible) > 1:
        return '', f'{name}() has ambiguous cross-unit source definitions'
    return '', f'{name}() has no resolved source definition'


def _input_controlled_call_candidates(
    graph: GraphStore,
    function: FunctionMetadata,
    tainted_names: set[str],
    *,
    entry: EntryRecord | None = None,
) -> tuple[list[str], list[str]]:
    """Find calls guarded by declarations that can hold acquired input.

    Clang declaration IDs and source order are used only to select source
    functions for inspection. They do not prove a feasible path or an Action.
    Without the required AST identity, the question stays unresolved.
    """
    unresolved: list[str] = []
    identities: dict[str, bool] = {}  # declaration ID -> scalar input
    source_units: set[str] = set()
    acquisition_offsets: list[int] = []
    if entry is not None:
        positions = _entry_destination_positions(function, entry)
        sites = [site for site in function.external_call_sites
                 if str(site.get('api') or '') == entry.source_api
                 and (entry.entry_line is None
                      or site.get('line') == entry.entry_line)]
        if len(sites) > 1:
            return [], [
                f'{function.name}: multiple acquisition calls share the Entry '
                'line; exact input site could not be bound'
            ]
        for site in sites:
            unit = str(site.get('analysis_unit') or '')
            if unit:
                source_units.add(unit)
            offset = site.get('offset')
            if isinstance(offset, int):
                acquisition_offsets.append(offset)
            ids = site.get('direct_argument_declaration_ids') or []
            addressed = site.get('direct_argument_addressed_scalar_declaration_ids') or []
            for position in positions:
                if position >= len(ids) or not ids[position]:
                    continue
                identifier = str(ids[position])
                scalar = position < len(addressed) and addressed[position] == identifier
                identities[identifier] = bool(scalar)
        if not identities and tainted_names:
            unresolved.append(
                f'{function.name}: acquired destination could not be bound '
                'to a compiler declaration identity'
            )
            return [], unresolved
    else:
        for parameter in function.ast_parameter_declarations:
            if parameter.get('name') not in tainted_names:
                continue
            identifier = str(parameter.get('declaration_id') or '')
            if not identifier:
                continue
            typ = str(parameter.get('type') or '')
            identities[identifier] = not any(symbol in typ for symbol in ('*', '&', '['))
            unit = str(parameter.get('analysis_unit') or '')
            if unit:
                source_units.add(unit)
        if not identities and tainted_names:
            unresolved.append(
                f'{function.name}: consumer declaration AST unavailable for '
                f'{", ".join(sorted(tainted_names))}'
            )
            return [], unresolved
    if not function.guarded_call_sites:
        if identities:
            unresolved.append(f'{function.name}: guarded-call AST unavailable')
        return [], unresolved
    candidates: list[str] = []
    for guard in function.guarded_call_sites:
        unit = str(guard.get('analysis_unit') or '')
        if unit and source_units and unit not in source_units:
            continue
        guard_offset = guard.get('guard_offset')
        if (entry is not None and acquisition_offsets
            and isinstance(guard_offset, int)
            and guard_offset <= min(acquisition_offsets)):
            continue
        conditions = set(map(str, guard.get('condition_declaration_ids') or []))
        contents = set(map(str, guard.get('condition_content_declaration_ids') or []))
        tainted = set(identities)
        scalar = {identifier for identifier, is_scalar in identities.items()
                  if is_scalar}
        relevant = contents & tainted | conditions & scalar
        if not relevant:
            for origin in guard.get('condition_initializer_sources') or []:
                source_id = str(origin.get('source_declaration_id') or '')
                if source_id in tainted:
                    relevant.add(str(origin.get('condition_declaration_id') or ''))
        target_id, target_issue = _resolve_guard_target(graph, function, guard)
        target_name = str(guard.get('callee_name') or target_id or 'unknown')
        if not relevant:
            if (conditions & tainted) and not (contents & tainted):
                unresolved.append(
                    f'{function.name}: {target_name} guard reads a pointer or '
                    'address, not acquired input bytes'
                )
            continue
        overwrite = False
        for record in guard.get('preceding_constant_scalar_overwrites') or []:
            identifier = str(record.get('declaration_id') or '')
            offset = record.get('offset')
            if identifier not in relevant:
                continue
            if (entry is None or not acquisition_offsets
                or not isinstance(offset, int)
                or offset > min(acquisition_offsets)):
                overwrite = True
                break
        if overwrite:
            unresolved.append(
                f'{function.name}: acquired scalar was overwritten by a literal '
                f'before {target_name} guard'
            )
            continue
        if target_id in graph.bundle.functions:
            if target_id not in candidates:
                candidates.append(target_id)
        else:
            unresolved.append(
                target_issue or f'{function.name}: {target_name} guarded target unresolved'
            )
    return candidates, unresolved

def _callback_registration_leads(
    graph: GraphStore, opened_ids: list[str], target_ids: set[str],
) -> list[str]:
    """Return source-located registration functions for exact callback targets."""
    opened = set(opened_ids)
    leads: list[str] = []
    for (_invoker, target_id), records in graph._callback_slot_hints().items():
        if target_id not in target_ids:
            continue
        for record in records:
            registration_id = str(record.get("registration_id") or "")
            if (registration_id in graph.bundle.functions
                and registration_id not in opened
                and registration_id not in leads):
                leads.append(registration_id)
    return leads


def _same_receiver_return_callbacks(
    graph: GraphStore, entry: EntryRecord, caller: FunctionMetadata,
) -> list[str]:
    """Offer callbacks returned after an external read on the same receiver.

    This is a source-navigation lead. Matching a receiver spelling and a
    registered slot does not prove object identity or that this branch runs.
    """
    if caller.function_id == entry.entry_function_id:
        return []
    source_function = graph.bundle.functions.get(entry.entry_function_id)
    if source_function is None:
        return []
    owner_parameters: set[int] = set()
    api = entry.source_api.strip()
    pattern = _entry_api_call_pattern(api)
    parameter_names = _function_parameter_names(source_function.signature)
    for match in pattern.finditer(source_function.source):
        line = source_function.start_line + source_function.source.count('\n', 0, match.start())
        if entry.entry_line is not None and line != entry.entry_line:
            continue
        opening = source_function.source.find('(', match.start())
        closing = _matching_source_paren(source_function.source, opening)
        if closing < 0:
            continue
        arguments = _split_source_arguments(source_function.source[opening + 1:closing])
        for position in _entry_destination_positions(source_function, entry):
            if position >= len(arguments):
                continue
            owner = re.match(r'\s*([A-Za-z_]\w*)\s*(?:->|\.)', arguments[position])
            if owner and owner.group(1) in parameter_names:
                owner_parameters.add(parameter_names.index(owner.group(1)))
    if not owner_parameters:
        return []
    code = _code_only(caller.source)
    receiver_calls: list[tuple[str, int]] = []
    for site in caller.direct_call_sites:
        if site.get('callee_function_id') != entry.entry_function_id:
            continue
        for line, arguments, offset in _named_source_calls(caller, source_function.name):
            if site.get('line') != line:
                continue
            for position in owner_parameters:
                if position >= len(arguments):
                    continue
                argument = arguments[position].strip()
                if re.fullmatch(r'[A-Za-z_]\w*', argument):
                    receiver_calls.append((argument, offset))
    if not receiver_calls:
        return []
    hints = graph._callback_slot_hints()
    result: list[str] = []
    for (invoker_id, target_id), records in hints.items():
        if invoker_id != caller.function_id:
            continue
        for record in records:
            slot = str(record.get('slot') or '')
            if not slot:
                continue
            for receiver, offset in receiver_calls:
                invocation = re.search(
                    r'\breturn\s+' + re.escape(receiver)
                    + r'\s*(?:->|\.)\s*' + re.escape(slot) + r'\s*\(',
                    code[offset:],
                )
                if invocation and target_id not in result:
                    result.append(target_id)
    return result

def _entry_destination_helper_ids(
    function: FunctionMetadata, entry: EntryRecord, graph: GraphStore,
) -> list[str]:
    """Find user-defined calls nested in the acquisition's output argument.

    The helper only identifies the destination expression to inspect. It
    does not establish input format, accepted bytes, or runtime reachability.
    """
    positions = _entry_destination_positions(function, entry)
    if not positions:
        return []
    api = entry.source_api.strip()
    pattern = _entry_api_call_pattern(api)
    result: list[str] = []
    for match in pattern.finditer(function.source):
        line = function.start_line + function.source.count('\n', 0, match.start())
        if entry.entry_line is not None and line != entry.entry_line:
            continue
        opening = function.source.find('(', match.start())
        closing = _matching_source_paren(function.source, opening)
        if closing < 0:
            continue
        args = _split_source_arguments(function.source[opening + 1:closing])
        for position in positions:
            if position >= len(args):
                continue
            for nested in re.finditer(r'(?<![\w:.>])([A-Za-z_]\w*)\s*\(', args[position]):
                name = nested.group(1)
                for site in function.direct_call_sites:
                    target_id = str(site.get('callee_function_id') or '')
                    target = graph.bundle.functions.get(target_id)
                    if (target and target.name == name
                        and site.get('line') == line
                        and target_id not in result):
                        result.append(target_id)
    return result

def _entry_destination_names(
    function: FunctionMetadata,
    entry: EntryRecord,
) -> set[str]:
    """Return local names written at the concrete acquisition call site."""
    api = entry.source_api.strip()
    if not api:
        return set()
    pattern = _entry_api_call_pattern(api)
    positions = _entry_destination_positions(function, entry)
    result: set[str] = set()
    matches = [match for match in pattern.finditer(function.source)
               if entry.entry_line is None
               or function.start_line + function.source.count('\n', 0, match.start())
                  == entry.entry_line]
    if not matches:
        # Macro-expanded calls can be present in Clang's AST without a
        # textual API spelling in the function body. Accept only one exact
        # AST site with a declaration-identified destination.
        sites = [site for site in function.external_call_sites
                 if site.get('api') == api
                 and (entry.entry_line is None
                      or site.get('line') == entry.entry_line)]
        if len(sites) == 1 and positions:
            identifiers = sites[0].get('direct_argument_identifiers') or []
            declarations = sites[0].get('direct_argument_declaration_ids') or []
            return {str(identifiers[index]) for index in positions
                    if index < len(identifiers) and index < len(declarations)
                    and identifiers[index] and declarations[index]}
    if len(matches) != 1:
        return result
    for match in matches:
        opening = function.source.find('(', match.start())
        closing = _matching_source_paren(function.source, opening)
        if closing < 0:
            continue
        arguments = _split_source_arguments(function.source[opening + 1:closing])
        selected = positions
        if api.casefold() in {'scanf', 'fscanf', 'sscanf'}:
            selected = tuple(range(1, len(arguments)))
        for index in selected:
            if index < len(arguments):
                result.update(_written_buffer_names(arguments[index]))
        if selected:
            continue
        if api.casefold() in {'getc', 'getchar', 'getchar_unlocked'}:
            statement_start = max(
                function.source.rfind(';', 0, match.start()),
                function.source.rfind('\n', 0, match.start()),
                function.source.rfind('{', 0, match.start()),
            )
            before = function.source[statement_start + 1:match.start()]
            assignment = re.search(r'([A-Za-z_]\w*)\s*=\s*$', before)
            if assignment:
                result.add(assignment.group(1))
    return result


def _source_call_span(function: FunctionMetadata, name: str, line: int,
                      *, occurrence: int = 0) -> tuple[int, int] | None:
    calls = [item for item in _named_source_calls(function, name)
             if item[0] == line]
    if occurrence >= len(calls):
        return None
    start = calls[occurrence][2]
    opening = function.source.find("(", start)
    end = _matching_source_paren(function.source, opening)
    return (start, end + 1) if end >= 0 else None


def _entry_acquisition_site(
    function: FunctionMetadata, entry: EntryRecord,
) -> tuple[int | None, set[str], str]:
    sites = [site for site in function.external_call_sites
             if _external_site_matches_entry(function, site, entry)]
    if len(sites) != 1:
        return None, set(), "" if not sites else "ambiguous"
    site = sites[0]
    identifiers = site.get("direct_argument_declaration_ids") or []
    positions = _entry_destination_positions(function, entry)
    declarations = {str(identifiers[index]) for index in positions
                    if index < len(identifiers) and identifiers[index]}
    return site.get("offset"), declarations, str(site.get("analysis_unit") or "")


def _tainted_call_positions(
    caller: FunctionMetadata, callee_name: str, edge_line: int,
    tainted_names: set[str], *, callee_function_id: str = "",
    entry: EntryRecord | None = None,
    tainted_declarations: set[str] | None = None,
    source_unit: str = "",
    acquisition_offset: int | None = None,
    include_ambiguous: bool = False,
) -> set[int]:
    """Select direct argument handoffs; AST identities outrank spelling.

    This is source navigation, not a proof of path feasibility or consumption.
    """
    result: set[int] = set()
    sites = [site for site in caller.direct_call_sites
             if site.get("line") == edge_line
             and (not callee_function_id or
                  site.get("callee_function_id") == callee_function_id)]
    if sites:
        for site in sites:
            unit = str(site.get("analysis_unit") or "")
            if source_unit and unit and source_unit != unit:
                continue
            offset = site.get("offset")
            if isinstance(acquisition_offset, int) and isinstance(offset, int):
                if offset <= acquisition_offset and not include_ambiguous:
                    continue
            ids = site.get("direct_argument_declaration_ids") or []
            names = site.get("direct_argument_identifiers") or []
            if tainted_declarations is not None:
                for index, identifier in enumerate(ids):
                    if identifier and str(identifier) in tainted_declarations:
                        result.add(index)
            elif ids:
                for index, name in enumerate(names):
                    if name in tainted_names:
                        result.add(index)
            else:
                for index, name in enumerate(names):
                    if name in tainted_names:
                        result.add(index)
        return result
    # Source-only fallback is a candidate when no compiler identity exists.
    if tainted_declarations is not None:
        return set()
    calls = [item for item in _named_source_calls(caller, callee_name)
             if item[0] == edge_line]
    if len(calls) != 1:
        return set()
    _, arguments, offset = calls[0]
    if isinstance(acquisition_offset, int) and offset <= acquisition_offset:
        return set()
    for index, argument in enumerate(arguments):
        if _identifier_names(argument) & tainted_names:
            result.add(index)
    return result


def _sibling_nested_calls_ambiguous(
    function: FunctionMetadata, first: tuple[int, int],
    second: tuple[int, int],
) -> bool:
    """Detect two calls in separate arguments of a common call expression."""
    code = _code_only(function.source)
    for match in re.finditer(r"\b[A-Za-z_]\w*\s*\(", code):
        opening = code.find("(", match.start())
        closing = _matching_source_paren(code, opening)
        if closing < 0 or not (opening < first[0] and second[1] <= closing):
            continue
        # Simpler and robust for comma-separated call arguments: the top-level
        # comma between the two spans belongs to this parent call.
        between = code[first[1]:second[0]] if first[1] <= second[0] else ""
        if "," in between and first[0] > opening and second[1] <= closing:
            return True
    return False


def source_dataflow_consumers(
    graph: GraphStore, entry: EntryRecord, *, function_limit: int,
    include_all_consumers: bool = False,
    include_candidate_edges: bool = False,
) -> tuple[list[tuple[str, list[str], set[str]]], bool]:
    """Navigate direct input-buffer handoffs from one exact Entry site.

    Compiler identity and source order avoid the common false links caused by
    shadowed names and calls preceding acquisition. The returned paths are
    inspection candidates; downstream proof still requires runtime attribution.
    """
    root_id = entry.entry_function_id
    root = graph.bundle.functions.get(root_id)
    if root is None or function_limit <= 0:
        return [], False
    initial_names = _entry_destination_names(root, entry)
    if not initial_names:
        return [], False
    acquisition_offset, initial_ids, source_unit = _entry_acquisition_site(root, entry)
    if not initial_ids and root.external_call_sites:
        return [], True
    queue: deque[tuple[str, set[str], set[str] | None, str, int | None, list[str]]] = deque([
        (root_id, initial_names, initial_ids if initial_ids else None,
         source_unit, acquisition_offset, [root_id])
    ])
    visited: set[tuple[str, tuple[str, ...], tuple[str, ...]]] = set()
    results: list[tuple[str, list[str], set[str]]] = []
    unresolved = False
    while queue:
        function_id, names, declarations, unit, start_offset, path = queue.popleft()
        key = (function_id, tuple(sorted(names)), tuple(sorted(declarations or ())))
        if key in visited:
            continue
        if len(visited) >= function_limit:
            return results, True
        visited.add(key)
        caller = graph.bundle.functions[function_id]
        for edge in graph.bundle.edges:
            if edge.caller_id != function_id or edge.line is None:
                continue
            callee = graph.bundle.functions.get(edge.callee_id)
            if callee is None:
                continue
            sites = [site for site in caller.direct_call_sites
                     if site.get("callee_function_id") == callee.function_id
                     and site.get("line") == edge.line]
            ast_backed = any(str(site.get("provider") or "").startswith("clang-ast")
                             for site in sites)
            authoritative = edge.kind == "direct" and (ast_backed or (
                "fuzz-introspector" in edge.providers
            ))
            if not authoritative and not include_candidate_edges:
                continue
            if edge.kind not in {"direct", "source_candidate", "reported"}:
                continue
            call_span = _source_call_span(caller, callee.name, edge.line)
            if call_span is None:
                continue
            if function_id == root_id:
                acquire_span = _source_call_span(caller, entry.source_api,
                                                 entry.entry_line or edge.line)
                if acquire_span is None:
                    ast_sites = [site for site in caller.external_call_sites
                                 if _external_site_matches_entry(caller, site, entry)
                                 and str(site.get('provider') or '').startswith('clang-ast')]
                    direct_sites = [site for site in sites
                                    if isinstance(site.get('offset'), int)]
                    if (len(ast_sites) == 1 and len(direct_sites) == 1
                        and isinstance(ast_sites[0].get('offset'), int)):
                        # Translate two Clang offsets from the same parsed
                        # translation unit into this function's source slice.
                        # The expansion must point to a complete lexical macro
                        # call so sibling-call ordering can still be checked.
                        relative = (ast_sites[0]['offset']
                                    - direct_sites[0]['offset'] + call_span[0])
                        if 0 <= relative < len(caller.source):
                            lexical = re.match(r'[A-Za-z_][\w:.]*\s*\(',
                                               caller.source[relative:])
                            if lexical:
                                opening = relative + lexical.group().rfind('(')
                                closing = _matching_source_paren(caller.source, opening)
                                if closing >= opening:
                                    acquire_span = (relative, closing + 1)
                if acquire_span is None:
                    continue
                if _sibling_nested_calls_ambiguous(caller, acquire_span, call_span):
                    unresolved = True
                    if not include_candidate_edges:
                        continue
                if call_span[0] < acquire_span[1]:
                    # C/C++ argument evaluation order does not establish a
                    # post-read handoff between sibling nested calls.
                    if acquire_span[0] < call_span[0] and call_span[1] <= acquire_span[1]:
                        continue
                    if call_span[0] < acquire_span[0] < call_span[1]:
                        if not include_candidate_edges:
                            unresolved = True
                            continue
                        unresolved = True
                    elif not include_candidate_edges:
                        continue
            positions = _tainted_call_positions(
                caller, callee.name, edge.line, names,
                callee_function_id=callee.function_id,
                tainted_declarations=declarations,
                source_unit=unit, acquisition_offset=start_offset,
                include_ambiguous=include_candidate_edges,
            )
            if not positions:
                continue
            params = _function_parameter_names(callee.signature)
            next_names = {params[index] for index in positions
                          if index < len(params) and params[index]}
            if not next_names:
                continue
            next_ids = {str(param.get("declaration_id"))
                        for index, param in enumerate(callee.ast_parameter_declarations)
                        if index in positions and param.get("declaration_id")}
            next_unit = str(callee.ast_parameter_declarations[0].get("analysis_unit") or "") if callee.ast_parameter_declarations else ""
            next_path = [*path, callee.function_id]
            if callee.function_id != root_id:
                results.append((callee.function_id, next_path, next_names))
                if not include_all_consumers:
                    continue
            queue.append((callee.function_id, next_names,
                          next_ids if next_ids else None, next_unit, None,
                          next_path))
    # Multiple graph providers may report the same handoff.
    deduped: dict[str, tuple[str, list[str], set[str]]] = {}
    for item in results:
        deduped.setdefault(item[0], item)
    return list(deduped.values()), unresolved


def _named_source_calls(
    function: FunctionMetadata,
    callee_name: str,
) -> list[tuple[int, list[str], int]]:
    result: list[tuple[int, list[str], int]] = []
    pattern = re.compile(rf"\b{re.escape(callee_name)}\s*\(")
    for match in pattern.finditer(function.source):
        opening = function.source.find("(", match.start())
        closing = _matching_source_paren(function.source, opening)
        if closing < 0:
            continue
        line = function.start_line + function.source.count("\n", 0, match.start())
        arguments = _split_source_arguments(
            function.source[opening + 1:closing]
        )
        result.append((line, arguments, match.start()))
    return result


def _matching_source_paren(source: str, opening: int) -> int:
    if opening < 0 or opening >= len(source) or source[opening] != "(":
        return -1
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, len(source)):
        character = source[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_source_arguments(value: str) -> list[str]:
    if not value.strip():
        return []
    result: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    quote = ""
    escaped = False
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in depths:
            depths[character] += 1
        elif character in closing:
            opener = closing[character]
            depths[opener] = max(0, depths[opener] - 1)
        elif character == "," and not any(depths.values()):
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return result


def _identifier_names(value: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", value))


def _function_parameter_names(signature: str) -> list[str]:
    opening = signature.find("(")
    closing = _matching_source_paren(signature, opening)
    if opening < 0 or closing < 0:
        return []
    result: list[str] = []
    type_words = {
        "void", "const", "volatile", "restrict", "signed", "unsigned",
        "short", "long", "int", "char", "float", "double", "struct",
        "union", "enum", "size_t", "ssize_t",
    }
    for parameter in _split_source_arguments(signature[opening + 1:closing]):
        identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", parameter)
        names = [item for item in identifiers if item.casefold() not in type_words]
        result.append(names[-1] if names else "")
    return result


def _entry_payload(entry: EntryRecord) -> dict[str, Any]:
    return {
        "entry_id": entry.entry_id,
        "entry_function_id": entry.entry_function_id,
        "entry_line": entry.entry_line,
        "source_api": entry.source_api,
        "channel_kind": entry.channel_kind,
        "boundary_subject": entry.boundary_subject,
        "consumer_hints": entry.consumer_hints,
        "provenance_path": entry.provenance_path,
    }


def _seed_payload(seed: OperationSeed) -> dict[str, Any]:
    return {
        "operation_seed_id": seed.operation_seed_id,
        "dispatcher_function_id": seed.dispatcher_function_id,
        "discriminator": seed.discriminator,
        "line": seed.line,
        "handler_function_ids": seed.handler_function_ids,
        "evidence_kind": seed.evidence_kind,
        "status": seed.status,
        "entry_path_function_ids": seed.entry_path_function_ids,
        "unresolved_call_names": seed.unresolved_call_names,
    }


def _action_payload(action: ExternalActionSchema) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "entry_id": action.entry_id,
        "name": action.name,
        "description": action.description,
        "dispatcher_function_id": action.dispatcher_function_id,
        "handler_function_id": action.handler_function_id,
        "discriminator": action.discriminator,
        "source_api": action.source_api,
        "request_ir": request_ir_summary(action.fields),
        "fields": [
            {
                "name": item.name, "offset": item.offset, "width": item.width,
                "encoding": item.encoding, "binding": item.binding,
                "relation": item.relation,
            }
            for item in action.fields
        ],
        "examples": [
            {"data_hex": item.data_hex, "bindings": item.bindings}
            for item in action.examples
        ],
        "success_markers_hex": action.success_markers_hex,
        "failure_markers_hex": action.failure_markers_hex,
        "response_bindings": [
            {
                "binding": item.binding,
                "offset": item.offset,
                "width": item.width,
                "encoding": item.encoding,
                "evidence": item.evidence,
            }
            for item in action.response_bindings
        ],
    }


def _raw_action_summary(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        key: raw.get(key)
        for key in (
            "name", "dispatcher_function_id", "handler_function_id",
            "discriminator", "unknowns", "confidence",
        )
    }


def _contract_summary(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        key: raw.get(key, [])
        for key in ("consumes", "produces", "invalidates", "initial_resources", "unknowns")
    }


def _validated_evidence(
    value: Any,
    opened: set[str],
    graph: GraphStore,
) -> list[Evidence]:
    result: list[Evidence] = []
    for raw in object_list(value):
        function_id = str(raw.get("function_id", ""))
        if function_id not in opened or function_id not in graph.bundle.functions:
            continue
        function = graph.get(function_id)
        line_value = raw.get("line")
        line = int(line_value) if isinstance(line_value, int) else None
        kind = str(raw.get("kind", "source"))
        cited_file = str(raw.get("file") or "")
        evidence_file = function.file
        if kind == 'source_declaration':
            declaration = next((item for item in function.referenced_global_declarations
                if (line is not None
                    and item.get('start_line') is not None
                    and int(item['start_line']) <= line <= int(item.get('end_line') or item['start_line'])
                    and (not cited_file or cited_file == str(item.get('file') or '')))), None)
            if declaration is None:
                continue
            evidence_file = str(declaration.get('file') or function.file)
        elif ((line is not None
               and not function.start_line <= line <= function.end_line)
              or (cited_file and cited_file != function.file)):
            continue
        detail = str(raw.get("detail", "")).strip()
        if not detail:
            continue
        result.append(Evidence(
            kind=kind,
            function_id=function_id,
            file=evidence_file,
            line=line,
            detail=detail,
        ))
    return result


def _examples(
    value: Any,
    opened: set[str] | None = None,
    graph: GraphStore | None = None,
    source_declaration_ranges: dict[str, list[tuple[int, int]]] | None = None,
) -> list[ActionExample]:
    result: list[ActionExample] = []
    seen: set[str] = set()
    for raw in object_list(value):
        data_hex = str(raw.get("data_hex", "")).lower()
        if data_hex in seen or not _valid_hex(data_hex, allow_empty=False):
            continue
        if len(data_hex) > 2 * 1_048_576:
            continue
        bindings_raw = raw.get("bindings")
        # Strict structured output cannot express a free-form JSON object map,
        # so current responses use fixed-shape key/value records. Keep the old
        # dict form readable for already completed trajectories.
        if isinstance(bindings_raw, list):
            binding_items = (
                (
                    str(item.get("name", "")).strip(),
                    str(item.get("value_hex", "")).lower(),
                )
                for item in object_list(bindings_raw)
            )
        elif isinstance(bindings_raw, dict):
            binding_items = (
                (str(key).strip(), str(item).lower())
                for key, item in bindings_raw.items()
            )
        else:
            binding_items = iter(())
        bindings = {
            key: item
            for key, item in binding_items
            if key and _valid_hex(item, allow_empty=True)
        }
        example_evidence = (
            _validated_evidence(raw.get("evidence"), opened, graph)
            if opened is not None and graph is not None else []
        )
        for citation in object_list(raw.get('evidence')):
            if citation.get('kind') != 'source_declaration':
                continue
            source_file = str(citation.get('function_id') or '')
            line = citation.get('line')
            ranges = (source_declaration_ranges or {}).get(source_file, [])
            if (isinstance(line, int)
                and any(start <= line <= end for start, end in ranges)
                and citation.get('detail')):
                example_evidence.append(Evidence(
                    kind='source_declaration_lexical', function_id=source_file,
                    file=source_file, line=line,
                    detail=str(citation['detail']),
                ))
        result.append(ActionExample(
            data_hex=data_hex,
            bindings=bindings,
            rationale=str(raw.get("rationale", "")),
            origin=str(raw.get("origin", "model_candidate")),
            evidence=example_evidence,
        ))
        seen.add(data_hex)
    return result


def _is_non_retryable_infrastructure_failure(exc: BaseException) -> bool:
    """Identify deterministic request failures that another branch cannot fix."""

    return is_terminal_llm_infrastructure_error(exc)


def _fields(
    value: Any,
    opened: set[str],
    graph: GraphStore,
    examples: list[ActionExample],
    source_declaration_ranges: dict[str, list[tuple[int, int]]] | None = None,
) -> list[InputFieldConstraint]:
    maximum = max((len(bytes.fromhex(item.data_hex)) for item in examples), default=0)
    result: list[InputFieldConstraint] = []
    for raw in object_list(value):
        offset = raw.get("offset")
        width = raw.get("width")
        if not isinstance(offset, int) or not isinstance(width, int):
            continue
        if offset < 0 or width < 1 or offset + width > maximum:
            continue
        evidence = _validated_evidence(raw.get("evidence"), opened, graph)
        for citation in object_list(raw.get("evidence")):
            if citation.get("kind") != "source_declaration":
                continue
            source_file = str(citation.get("function_id") or "")
            line = citation.get("line")
            if (isinstance(line, int) and citation.get("detail")
                and any(start <= line <= end for start, end in
                        (source_declaration_ranges or {}).get(source_file, []))):
                evidence.append(Evidence(
                    kind="source_declaration_lexical", function_id=source_file,
                    file=source_file, line=line, detail=str(citation["detail"]),
                ))
        if not evidence:
            continue
        result.append(InputFieldConstraint(
            name=str(raw.get("name", "field")),
            offset=offset,
            width=width,
            encoding=str(raw.get("encoding", "bytes")),
            binding=str(raw.get("binding", "")),
            relation=str(raw.get("relation", "opaque")),
            evidence=evidence,
        ))
    return result


def _response_binding_extractors(
    value: Any,
    opened: set[str],
    graph: GraphStore,
) -> list[ResponseBindingExtractor]:
    result: list[ResponseBindingExtractor] = []
    seen: set[str] = set()
    for raw in object_list(value):
        binding = str(raw.get("binding", "")).strip()
        offset = raw.get("offset")
        width = raw.get("width")
        evidence = _validated_evidence(raw.get("evidence"), opened, graph)
        if (
            not binding
            or binding in seen
            or not isinstance(offset, int)
            or not isinstance(width, int)
            or offset < 0
            or width < 1
            or width > 65_536
            or not evidence
        ):
            continue
        seen.add(binding)
        result.append(ResponseBindingExtractor(
            binding=binding,
            offset=offset,
            width=width,
            encoding=str(raw.get("encoding", "bytes")) or "bytes",
            evidence=evidence,
        ))
    return result


def _invalid_response_binding_count(
    value: Any,
    opened: set[str],
    graph: GraphStore,
) -> int:
    raw_values = object_list(value)
    return len(raw_values) - len(
        _response_binding_extractors(raw_values, opened, graph)
    )


def _requirements(
    value: Any,
    opened: set[str],
    graph: GraphStore,
) -> list[StateRequirement]:
    result: list[StateRequirement] = []
    for raw in object_list(value):
        resource = str(raw.get("resource", "")).strip()
        evidence = _validated_evidence(raw.get("evidence"), opened, graph)
        if not resource or not evidence:
            continue
        result.append(StateRequirement(
            resource=resource,
            binding=str(raw.get("binding", "")).strip(),
            predicate=str(raw.get("predicate", "exists")).strip() or "exists",
            evidence=evidence,
            status=ProofStatus.PROVEN_STATIC,
            scope=(
                str(raw.get("scope", "global"))
                if str(raw.get("scope", "global")) in {"global", "connection", "session", "object"}
                else "global"
            ),
            owner_binding=str(raw.get("owner_binding", "")).strip(),
            binding_value_hex=(
                str(raw.get("binding_value_hex", "")).lower()
                if isinstance(raw.get("binding_value_hex"), str)
                and _valid_hex(str(raw.get("binding_value_hex")), allow_empty=True)
                else None
            ),
        ))
    return _merge_requirements(result)


def _invalid_requirement_count(
    value: Any,
    opened: set[str],
    graph: GraphStore,
) -> int:
    """Count state claims that cannot be tied to opened source.

    Silently dropping a malformed ``consumes`` claim turns a stateful action
    into an apparently stateless one.  That is unsound because the planner can
    then skip the missing producer.  Every model-reported state claim must
    either survive validation or keep the whole contract at ``POSSIBLE``.
    """

    invalid = 0
    for raw in object_list(value):
        resource = str(raw.get("resource", "")).strip()
        evidence = _validated_evidence(raw.get("evidence"), opened, graph)
        if not resource or not evidence:
            invalid += 1
    return invalid


def _merge_requirements(values: list[StateRequirement]) -> list[StateRequirement]:
    result: dict[tuple[str, str, str, str | None, str, str], StateRequirement] = {}
    for item in values:
        key = (
            item.resource, item.binding, item.predicate,
            item.binding_value_hex, item.scope, item.owner_binding,
        )
        if key not in result:
            result[key] = item
        else:
            result[key].evidence.extend(item.evidence)
            if item.status is ProofStatus.PROVEN_STATIC:
                result[key].status = ProofStatus.PROVEN_STATIC
    return list(result.values())


def _operation_seed_is_covered(
    entry: EntryRecord,
    seed: OperationSeed,
    handler_id: str,
    actions: list[ExternalActionSchema],
) -> bool:
    """Avoid regenerating a branch already proven in the discovery session."""

    discriminator = seed.discriminator.strip().casefold()
    return any(
        action.entry_id == entry.entry_id
        and action.dispatcher_function_id == seed.dispatcher_function_id
        and action.handler_function_id == handler_id
        and action.discriminator.strip().casefold() == discriminator
        and action.status is ProofStatus.PROVEN_STATIC
        for action in actions
    )


def _discriminator_key(value: str) -> str:
    """Normalize only spelling noise, never semantic aliases.

    A model may render ``case 'G'`` as either ``'G'`` or ``G``.  It may not
    substitute a different opcode name or condition: those require their own
    source-extracted operation seed.
    """

    normalized = " ".join(str(value).strip().split()).casefold()
    if (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in {"'", '"'}
    ):
        normalized = normalized[1:-1]
    return normalized



def _raw_action_identity(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return tuple(str(item.get(name) or '') for name in (
        'entry_id', 'name', 'dispatcher_function_id',
        'handler_function_id', 'discriminator',
    ))


def _preserve_matched_source_case(
    previous: dict[str, Any], current: dict[str, Any],
) -> dict[str, Any]:
    """Carry only an independently matched trial across a draft revision."""
    if _raw_action_identity(previous) != _raw_action_identity(current):
        return current
    retained = [example for example in previous.get('examples', [])
                if isinstance(example, dict)
                and example.get('origin') == 'matched_source_case_hypothesis']
    if not retained:
        return current
    revised = dict(current)
    examples = list(current.get('examples', []))
    existing = {(item.get('data_hex'), item.get('origin'))
                for item in examples if isinstance(item, dict)}
    for example in retained:
        key = (example.get('data_hex'), example.get('origin'))
        if key not in existing:
            examples.append(example)
            existing.add(key)
    revised['examples'] = examples
    return revised


def _merge_raw_action_turn(
    previous: list[dict[str, Any]], current: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Update matching Action drafts while retaining unrelated candidates."""
    merged = list(previous)
    positions = {_raw_action_identity(item): index
                 for index, item in enumerate(merged)}
    for item in current:
        key = _raw_action_identity(item)
        if key in positions:
            index = positions[key]
            merged[index] = _preserve_matched_source_case(merged[index], item)
        else:
            positions[key] = len(merged)
            merged.append(item)
    return merged


def _replace_raw_action_drafts(
    previous: list[dict[str, Any]], current: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Replace a reviewed draft set, preserving only matched trial bytes."""
    old_by_key = {_raw_action_identity(item): item for item in previous}
    return [
        _preserve_matched_source_case(old_by_key[key], item)
        if (key := _raw_action_identity(item)) in old_by_key else item
        for item in current
    ]

def _merge_actions(values: list[ExternalActionSchema]) -> list[ExternalActionSchema]:
    grouped: dict[str, ExternalActionSchema] = {}
    for item in values:
        previous = grouped.get(item.action_id)
        if previous is None or (
            item.status is ProofStatus.PROVEN_STATIC
            and previous.status is not ProofStatus.PROVEN_STATIC
        ) or len(item.evidence) > len(previous.evidence):
            grouped[item.action_id] = item
    return sorted(grouped.values(), key=lambda item: (item.entry_id, item.name, item.action_id))


def _resource_key(requirement: StateRequirement) -> str:
    base = (requirement.resource, requirement.binding, requirement.predicate)
    if requirement.scope == "global" and not requirement.owner_binding:
        return "\x1f".join(base)
    return "\x1f".join((*base, requirement.scope, requirement.owner_binding))


def _requirements_satisfied(
    requirements: list[StateRequirement], resources: frozenset[str] | set[str]
) -> bool:
    return all(_resource_key(item) in resources for item in requirements)


def _apply_contract(
    resources: frozenset[str] | set[str], contract: ActionStateContract
) -> set[str]:
    result = set(resources)
    for item in contract.invalidates:
        result.discard(_resource_key(item))
    result.update(_resource_key(item) for item in contract.produces)
    return result


def _ordering_allows(
    action_id: str,
    performed: tuple[str, ...],
    constraints: list[ActionOrderingConstraint],
) -> bool:
    completed = set(performed)
    for constraint in constraints:
        if constraint.successor_action_id != action_id:
            continue
        predecessor_seen = constraint.predecessor_action_id in completed
        if constraint.strength == "REQUIRED" and not predecessor_seen:
            return False
        if constraint.strength == "FORBIDDEN" and predecessor_seen:
            return False
    return True


def _materialize_action(
    action: ExternalActionSchema,
    index: int,
    bindings: dict[str, str],
) -> list[tuple[ScenarioStep, dict[str, str]]]:
    """Build source-grounded requests with positional recomputation.

    An annotated variable field can grow or shrink. `length_of(field)` and
    `crc32_of(field)` are recomputed by the deterministic renderer, not by an
    LLM rewriting byte offsets. Unknown relations or inconsistent source
    annotations reject this candidate without inventing missing rules.
    """
    result: list[tuple[ScenarioStep, dict[str, str]]] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for example in action.examples:
        if any(
            name in bindings and not _is_runtime_binding_ref(bindings[name])
            and bindings[name] != value
            for name, value in example.bindings.items()
        ):
            continue
        candidate_bindings = dict(bindings)
        for name, value in example.bindings.items():
            if name not in candidate_bindings or not _is_runtime_binding_ref(candidate_bindings[name]):
                candidate_bindings[name] = value
        overrides = {}
        for name, value in candidate_bindings.items():
            if _is_runtime_binding_ref(value):
                continue
            try:
                overrides[name] = bytes.fromhex(value)
            except ValueError:
                break
        else:
            try:
                rendered = render_request(example, action.fields, override_bindings=overrides)
            except (ValueError, OverflowError):
                # Do not silently accept contradictory or unsupported source rules.
                continue
            final_bindings = dict(candidate_bindings)
            final_bindings.update({name: value.hex() for name, value in rendered.bindings.items()})
            uses: list[RequestBindingUse] = []
            for field in action.fields:
                if not field.binding or field.binding not in candidate_bindings:
                    continue
                original_binding = candidate_bindings[field.binding]
                if not _is_runtime_binding_ref(original_binding):
                    continue
                producer = _runtime_binding_step(original_binding)
                bounds = rendered.offsets.get(field.name)
                if producer is None or bounds is None or bounds[1] != field.width:
                    break
                uses.append(RequestBindingUse(
                    binding=field.binding, offset=bounds[0], width=bounds[1],
                    producer_step_index=producer, encoding=field.encoding,
                ))
            else:
                step_bindings = {
                    name: value for name, value in final_bindings.items()
                    if not _is_runtime_binding_ref(value)
                }
                produced = dict(final_bindings)
                for extractor in action.response_bindings:
                    produced[extractor.binding] = _runtime_binding_ref(index)
                key = (rendered.data.hex(), tuple(sorted(final_bindings.items())))
                if key in seen:
                    continue
                seen.add(key)
                result.append((ScenarioStep(
                    index=index, action_id=action.action_id,
                    entry_id=action.entry_id, request_hex=rendered.data.hex(),
                    bindings=step_bindings,
                    expected_success_markers_hex=list(action.success_markers_hex),
                    request_template_hex=rendered.data.hex(),
                    request_binding_uses=uses,
                    response_binding_extractors=list(action.response_bindings),
                ), produced))
    return result


_RUNTIME_BINDING_PREFIX = "@runtime-step:"


def _runtime_binding_ref(step_index: int) -> str:
    return f"{_RUNTIME_BINDING_PREFIX}{step_index}"


def _is_runtime_binding_ref(value: str) -> bool:
    return value.startswith(_RUNTIME_BINDING_PREFIX)


def _runtime_binding_step(value: str) -> int | None:
    if not _is_runtime_binding_ref(value):
        return None
    try:
        result = int(value[len(_RUNTIME_BINDING_PREFIX):])
    except ValueError:
        return None
    return result if result >= 0 else None


def _blocked_candidate(target_id: str, blocker: str) -> ScenarioCandidate:
    return ScenarioCandidate(
        scenario_id=stable_id("scenario-unproven", target_id, blocker),
        target_action_id=target_id,
        steps=[],
        required_entries=[],
        satisfied_resources=[],
        planning_evidence=[],
        status=ScenarioStatus.UNPROVEN,
        blocker=blocker,
    )


def _hex_list(value: Any, *, allow_empty: bool) -> list[str]:
    return unique_strings(
        text.lower() for text in string_list(value)
        if _valid_hex(text, allow_empty=allow_empty)
    )


def _valid_hex(value: str, *, allow_empty: bool) -> bool:
    if not value:
        return allow_empty
    if len(value) % 2:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _confidence(value: Any) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
