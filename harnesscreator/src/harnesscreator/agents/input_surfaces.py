"""External input discovery that does not presume a command dispatcher.

An Entry can consume a whole file, byte stream, datagram, environment value,
or process argument without selecting a named Action. Input hypotheses are
kept separate from semantic Actions. They become executable trials through a
compatibility adapter, but are never source or runtime proof on their own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any, Awaitable, Callable

from ..analysis.graph import GraphStore, _code_only
from ..analysis.declarations import DeclarationIndex, SourceDeclaration
from ..analysis.operation_seeds import extract_operation_seeds
from ..input_transport import permits_explicit_socket_trial, source_transport
from ..llm.base import LLMProvider, close_llm_session, is_terminal_llm_infrastructure_error
from ..models import (
    ActionActor, ActionExample, EntryRecord, EntrySiteKind, Evidence,
    ExternalActionSchema, FunctionMetadata, ProofStatus, ProjectSpec, UsageArtifact,
    stable_id, unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from .common import (
    concurrent_map, function_payload, function_ref, object_list, string_list,
    resolve_source_linked_function, _source_linked_declaration_artifact,
)
from .scenario import (
    _entry_actor, _entry_destination_helper_ids,
    _entry_receiver_field_names, _entry_shared_field_paths,
    _shared_field_handoff_candidates,
    _shared_field_return_callers, _same_receiver_return_callbacks,
    _named_source_calls, source_dataflow_consumers,
    source_receiver_field_navigation_candidates,
)


_RAW_FIXTURE_EXTENSIONS = {".bin", ".raw", ".seed", ".input", ".dat", ".req"}
_USAGE_INVENTORY_PAGE_ITEMS = 128
_USAGE_INVENTORY_PAGE_CHARS = 12_000
_USAGE_SOURCE_PAGE_CHARS = 16_000
_NEXT_USAGE_INVENTORY_PAGE = "__next_usage_inventory_page__"
_DECLARATION_CATALOG = "__declaration_catalog__"
_DECLARATION_PREFIX = "__declaration__:"


@dataclass(slots=True)
class InputSurfaceCase:
    """A concrete *hypothesis* at an external acquisition site, not an Action."""

    case_id: str
    entry_id: str
    entry_function_id: str
    source_api: str
    channel_kind: str
    data_hex: str
    origin: str
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    inspected_function_ids: list[str] = field(default_factory=list)
    inspected_usage_paths: list[str] = field(default_factory=list)
    # A model-proposed byte string without a source-located format/example
    # basis remains visible in the inventory but is not scheduled for replay.
    sample_basis: list[dict[str, object]] = field(default_factory=list)
    trial_eligible: bool = False
    connection_prelude_marker_hex: str = ""
    connection_prelude_basis: list[dict[str, object]] = field(default_factory=list)


INPUT_SAMPLE_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["samples", "requested_function_ids", "requested_declaration_name",
                 "list_declarations", "declaration_name_filter",
                 "context_complete", "rationale", "selector_reviews"],
    "properties": {
        "samples": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "data_hex", "rationale", "evidence",
                    "connection_prelude_marker_hex", "connection_prelude_evidence",
                ],
                "properties": {
                    "data_hex": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
                    "rationale": {"type": "string"},
                    "connection_prelude_marker_hex": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
                    "connection_prelude_evidence": {"type": "array", "items": {
                        "type": "object", "additionalProperties": False,
                        "required": ["source_item_id", "line", "detail"],
                        "properties": {
                            "source_item_id": {"type": "string"},
                            "line": {"type": "integer", "minimum": 1},
                            "detail": {"type": "string"},
                        },
                    }},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object", "additionalProperties": False,
                            "required": ["source_item_id", "line", "detail"],
                            "properties": {
                                "source_item_id": {"type": "string"},
                                "line": {"type": "integer", "minimum": 1},
                                "detail": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "requested_function_ids": {"type": "array", "maxItems": 1, "items": {"type": "string"}},
        "requested_declaration_name": {"type": "string"},
        "list_declarations": {"type": "boolean"},
        "declaration_name_filter": {"type": "string"},
        "context_complete": {"type": "boolean"},
        "rationale": {"type": "string"},
        "selector_reviews": {
            "type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "required": ["selector_id", "disposition", "data_hex", "reason", "evidence"],
                "properties": {
                    "selector_id": {"type": "string"},
                    "disposition": {"type": "string", "enum": [
                        "INPUT_FORM", "NOT_EXTERNAL_INPUT_FORM", "NEEDS_SOURCE",
                    ]},
                    "data_hex": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
                    "reason": {"type": "string"},
                    "evidence": {"type": "array", "items": {
                        "type": "object", "additionalProperties": False,
                        "required": ["source_item_id", "line", "detail"],
                        "properties": {
                            "source_item_id": {"type": "string"},
                            "line": {"type": "integer", "minimum": 1},
                            "detail": {"type": "string"},
                        },
                    }},
                },
            },
        },
    },
}


class InputSurfaceAgent:
    """Produce trial bytes independent of branch inventory or Action count.

    Full source bodies are opened one at a time. Followup navigation reuses
    Entry-verifier evidence and source-located graph neighbours. An optional
    work budget never turns exhaustion into negative input proof.
    """

    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        project: ProjectSpec,
        *,
        max_function_turns: int = 0,
        usage_artifacts: list[UsageArtifact] | None = None,
        trace: TraceCallback | None = None,
        on_entry_cases: Callable[[EntryRecord, list[InputSurfaceCase]], Awaitable[None]] | None = None,
        on_trial_cases: Callable[[EntryRecord, list[InputSurfaceCase]], Awaitable[None]] | None = None,
        resume_continuations: list[dict[str, Any]] | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.project = project
        if max_function_turns < 0:
            raise ValueError("max_function_turns cannot be negative")
        self.usage_artifacts = list(usage_artifacts or [])
        # Inventory pages are transport units, never evidence that all
        # possible inputs have been inspected.
        # A long path can occupy a page by itself, so the work allowance must
        # cover that case without treating the transport page size as a cap.
        usage_pages = len(self.usage_artifacts)
        source_pages = 0
        for artifact in self.usage_artifacts:
            path = Path(artifact.path)
            if not path.is_absolute():
                path = project.source_root / path
            try:
                source_pages += max(
                    1, (path.stat().st_size + _USAGE_SOURCE_PAGE_CHARS - 1)
                    // _USAGE_SOURCE_PAGE_CHARS,
                )
            except OSError:
                source_pages += 1
        self.max_function_turns = max_function_turns or (
            len(graph.bundle.functions) + source_pages + usage_pages + 1
        )
        if project.max_input_trial_bytes < 0:
            raise ValueError("input trial byte limit cannot be negative")
        self.max_input_bytes = project.max_input_trial_bytes
        self.trace = trace
        self.on_entry_cases = on_entry_cases
        self.on_trial_cases = on_trial_cases
        self.resume_continuations = {
            str(item.get("entry_id", "")): item
            for item in (resume_continuations or [])
            if isinstance(item, dict) and str(item.get("entry_id", ""))
        }
        self.obligations: list[str] = []
        self.continuations: list[dict[str, object]] = []
        self.selector_audit: list[dict[str, object]] = []

    async def run(self, entries: list[EntryRecord]) -> list[InputSurfaceCase]:
        self.obligations = []
        self.continuations = []
        self.selector_audit = []
        files = _explicit_request_fixtures(self.project.scenario_evidence_paths)
        # Indexed C/C++ test and client files are still usage evidence. The
        # source indexer finding functions in a file must not remove that
        # file from the raw-input inventory: request construction may live
        # outside those function bodies or in a different language entirely.
        usage_by_path = {
            artifact.path: artifact for artifact in self.usage_artifacts
        }
        usage_inventory = list(usage_by_path.values())
        # Reuse the same direct-argument source walk used by Action discovery.
        # It supplies parser navigation only; it cannot establish accepted
        # bytes, field aliases, or callback execution.
        async def inspect_entry(entry: EntryRecord) -> list[InputSurfaceCase]:
            if entry.entry_function_id not in self.graph.bundle.functions:
                self.obligations.append(f"{entry.entry_id}: Entry function not indexed")
                return []
            trial_transport_supported = _supports_trial_transport(
                entry, self.project.scenario_channel,
            )
            if not trial_transport_supported:
                self.obligations.append(
                    f"{entry.entry_id}: original-program trial transport is "
                    "unavailable; source-backed input hypotheses remain "
                    "eligible for analysis"
                )
            inspected = [entry.entry_function_id]
            destination_helper_ids = _entry_destination_helper_ids(
                self.graph.get(entry.entry_function_id), entry, self.graph,
            )
            direct_consumers, direct_flow_truncated = (
                source_dataflow_consumers(
                    self.graph, entry,
                    function_limit=len(self.graph.bundle.functions),
                    include_all_consumers=True,
                    include_candidate_edges=True,
                )
            )
            direct_consumer_ids = unique_strings(
                function_id for function_id, _path, _names in direct_consumers
            )
            proven_consumers, proven_flow_truncated = source_dataflow_consumers(
                self.graph, entry,
                function_limit=len(self.graph.bundle.functions),
                include_all_consumers=True,
                include_candidate_edges=False,
            )
            proven_consumer_ids = unique_strings(
                function_id for function_id, _path, _names in proven_consumers
            )
            receiver_handoff_ids = source_receiver_field_navigation_candidates(
                self.graph, entry,
            )
            # A direct call can pass the receiver containing the acquired
            # field to a function that actually refers to that field. Follow
            # this source-located path one body at a time when no trial bytes
            # have been found. Reported/possible edges stay selectable leads,
            # never automatic evidence that the input reached their target.
            direct_receiver_handoff_ids = (
                source_receiver_field_navigation_candidates(
                    self.graph, entry, direct_edges_only=True,
                )
            )
            # A read wrapper can copy acquired bytes into an output parameter
            # and leave the format check to its caller.  The caller is a
            # source-located navigation question even when no receiver field
            # is involved; its call edge alone proves neither byte flow nor
            # the validity of any candidate input.
            direct_return_callers = unique_strings(
                edge.caller_id for edge in self.graph.bundle.edges
                if edge.callee_id == entry.entry_function_id
                and edge.kind == "direct" and edge.line is not None
                and edge.caller_id in self.graph.bundle.functions
                and any(
                    line == edge.line for line, _args, _offset in
                    _named_source_calls(
                        self.graph.get(edge.caller_id),
                        self.graph.get(entry.entry_function_id).name,
                    )
                )
            )
            callback_return_callers = [
                caller_id for caller_id in direct_return_callers
                if _same_receiver_return_callbacks(
                    self.graph, entry, self.graph.get(caller_id),
                )
            ]
            shared_field_roots = _entry_shared_field_paths(
                self.graph.get(entry.entry_function_id), entry,
            )
            shared_root_callers = unique_strings(
                edge.caller_id for edge in self.graph.bundle.edges
                if shared_field_roots
                and edge.callee_id == entry.entry_function_id
                and edge.line is not None
                and edge.kind in {"direct", "reported", "source_candidate"}
                and edge.caller_id in self.graph.bundle.functions
                and any(
                    line == edge.line for line, _args, _offset in
                    _named_source_calls(
                        self.graph.get(edge.caller_id),
                        self.graph.get(entry.entry_function_id).name,
                    )
                )
            )
            if direct_flow_truncated or proven_flow_truncated:
                self.obligations.append(
                    f"{entry.entry_id}: direct input-consumer navigation was truncated"
                )
            samples: list[tuple[bytes, str, str, list[dict[str, object]], str, list[dict[str, object]]]] = []
            for fixture in files:
                try:
                    data = fixture.read_bytes()
                except OSError as exc:
                    self.obligations.append(f"{entry.entry_id}: cannot read {fixture}: {exc}")
                    continue
                if self.max_input_bytes and len(data) > self.max_input_bytes:
                    self.obligations.append(
                        f"{entry.entry_id}: fixture {fixture} exceeds the "
                        f"operator-selected {self.max_input_bytes}-byte trial limit"
                    )
                    continue
                samples.append((data, "user_request_fixture", str(fixture), [], "", []))
            session_key = f"input_surface:{entry.entry_id}"
            pending = entry.entry_function_id
            opened: list[str] = []
            published_trial_values: set[tuple[bytes, str]] = set()
            prior = self.resume_continuations.get(entry.entry_id)
            resume_next_ids: list[str] = []
            if prior is not None:
                fingerprints = prior.get("source_fingerprints")
                prior_ids = unique_strings(string_list(prior.get("next_function_ids")))
                expected_ids = [
                    function_id for function_id in unique_strings([
                        *string_list(prior.get("opened_function_ids")),
                        *prior_ids,
                    ]) if function_id in self.graph.bundle.functions
                ]
                if (
                    prior.get("entry_fingerprint") == _surface_entry_fingerprint(entry)
                    and isinstance(fingerprints, dict)
                    and all(
                        function_id in self.graph.bundle.functions
                        for function_id in fingerprints
                    )
                    and all(
                        fingerprints.get(function_id)
                        == _surface_function_fingerprint(self.graph.get(function_id))
                        for function_id in expected_ids
                    )
                ):
                    resume_next_ids = prior_ids
                else:
                    self.obligations.append(
                        f"{entry.entry_id}: prior Input Surface continuation does "
                        "not match the current Entry/source; restarting source walk"
                    )
            resume_selection_used = False
            def next_direct_consumer() -> str:
                """Select an unambiguous or explicitly resumed input handoff.

                A lexical handoff is a source navigation lead. It does not
                prove alias identity, feasible execution, or accepted input.
                """
                nonlocal resume_selection_used
                eligible: list[str] = []
                for function_id in direct_consumer_ids:
                    if (function_id in opened
                        or function_id not in self.graph.bundle.functions):
                        continue
                    if any(
                        edge.caller_id in opened
                        and edge.callee_id == function_id
                        and edge.kind == "direct"
                        and edge.line is not None
                        for edge in self.graph.bundle.edges
                    ):
                        eligible.append(function_id)
                if len(eligible) == 1 and not resume_selection_used:
                    return eligible[0]
                if not resume_selection_used:
                    selected = next((
                        function_id for function_id in resume_next_ids
                        if function_id in eligible
                    ), "")
                    if selected:
                        resume_selection_used = True
                        return selected
                return ""

            def next_post_read_callback() -> str:
                nonlocal resume_selection_used
                candidates: list[str] = []
                for caller_id in direct_return_callers:
                    if caller_id not in opened:
                        continue
                    for function_id in _same_receiver_return_callbacks(
                        self.graph, entry, self.graph.get(caller_id),
                    ):
                        if function_id not in opened:
                            candidates.append(function_id)
                for caller_id in callback_return_callers:
                    if caller_id not in opened:
                        candidates.append(caller_id)
                # Registration and a post-read invocation identify possible
                # targets, but do not select the target used by this request.
                # An ambiguous set stays in the continuation until the model
                # explicitly chooses a source-linked question or runtime
                # evidence narrows it. Source order is not path evidence.
                unique = unique_strings(candidates)
                if len(unique) == 1 and not resume_selection_used:
                    return unique[0]
                if not resume_selection_used:
                    selected = next((
                        function_id for function_id in resume_next_ids
                        if function_id in unique
                    ), "")
                    if selected:
                        resume_selection_used = True
                        return selected
                return ""

            opened_usage: list[str] = []
            declaration_index = DeclarationIndex(self.graph.bundle.declarations)
            declaration_requests: dict[str, SourceDeclaration] = {}
            opened_declaration_keys: set[str] = set()
            declaration_queries_seen: set[tuple[str, str]] = set()
            declaration_filter = ""
            declaration_lookup_message = ""
            linked_declarations: dict[str, UsageArtifact] = {}
            opened_usage_lines: dict[str, list[tuple[int, int]]] = {}
            usage_offsets: dict[str, int] = {}
            usage_pages_remaining: set[str] = set()
            usage_inventory_offset = 0
            context_complete = False
            stop_reason = "source walk did not complete"
            last_choice_ids: list[str] = []
            selector_candidates: dict[str, Any] = {}
            selector_reviews: dict[str, dict[str, object]] = {}
            review_only = False

            def case_for(
                value: bytes, origin: str, rationale: str,
                basis: list[dict[str, object]],
                prelude_marker_hex: str = "",
                prelude_basis: list[dict[str, object]] | None = None,
            ) -> InputSurfaceCase:
                return InputSurfaceCase(
                    case_id=stable_id(
                        "input-surface-case", entry.entry_id, value.hex(),
                        *([prelude_marker_hex] if prelude_marker_hex else []),
                    ),
                    entry_id=entry.entry_id,
                    entry_function_id=entry.entry_function_id,
                    source_api=entry.source_api,
                    channel_kind=entry.channel_kind,
                    data_hex=value.hex(),
                    origin=origin,
                    rationale=rationale,
                    evidence=[
                        item for item in entry.evidence
                        if item.function_id == entry.entry_function_id
                    ],
                    inspected_function_ids=unique_strings([*inspected, *opened]),
                    inspected_usage_paths=list(opened_usage),
                    sample_basis=basis,
                    trial_eligible=(origin == "user_request_fixture" or bool(basis)),
                    connection_prelude_marker_hex=prelude_marker_hex,
                    connection_prelude_basis=list(prelude_basis or []),
                )

            try:
                turn = 0
                available_turns = self.max_function_turns
                while turn < available_turns:
                    _turn = turn
                    turn += 1
                    inventory_page_turn = pending == _NEXT_USAGE_INVENTORY_PAGE
                    declaration_catalog_turn = pending == _DECLARATION_CATALOG
                    declaration_turn = pending.startswith(_DECLARATION_PREFIX)
                    if (not pending or (pending in opened and not review_only) or
                        (pending in opened_usage and pending not in usage_pages_remaining) or
                        (declaration_turn and pending in opened_declaration_keys)):
                        stop_reason = "no new source item to open"
                        break
                    current = (None if inventory_page_turn or declaration_catalog_turn
                               or declaration_turn else
                               self.graph.bundle.functions.get(pending))
                    current_usage = None
                    if current is not None:
                        if pending not in opened:
                            opened.append(pending)
                    elif declaration_catalog_turn:
                        current_usage = {
                            "kind": "declaration_catalog",
                            "name_filter": declaration_filter,
                            "names": declaration_index.names(declaration_filter),
                            "lookup_message": declaration_lookup_message,
                        }
                        declaration_lookup_message = ""
                    elif declaration_turn:
                        definition = declaration_requests.get(pending)
                        if definition is None:
                            stop_reason = "requested declaration is unavailable"
                            break
                        opened_declaration_keys.add(pending)
                        current_usage = {
                            **definition.summary(),
                            "source_excerpt": definition.source,
                            "has_more": False,
                        }
                        if definition.file not in opened_usage:
                            opened_usage.append(definition.file)
                        opened_usage_lines.setdefault(definition.file, []).append((
                            definition.start_line, definition.end_line))
                    elif not inventory_page_turn:
                        artifact = linked_declarations.get(pending) or usage_by_path.get(pending)
                        if artifact is None:
                            stop_reason = "requested usage artifact is unavailable"
                            break
                        current_usage = self._read_usage_artifact(
                            artifact, usage_offsets.get(pending, 0),
                        )
                        if current_usage is None:
                            self.obligations.append(
                                f"{entry.entry_id}: usage artifact changed or is unreadable: {pending}"
                            )
                            stop_reason = "usage artifact changed or is unreadable"
                            break
                        if pending not in opened_usage:
                            opened_usage.append(pending)
                        opened_usage_lines.setdefault(pending, []).append((
                            int(current_usage["start_line"]),
                            int(current_usage["end_line"]),
                        ))
                        usage_offsets[pending] = int(current_usage["next_offset"])
                        if current_usage["has_more"]:
                            usage_pages_remaining.add(pending)
                        else:
                            usage_pages_remaining.discard(pending)
                    review_only = False
                    usage_page = []
                    if _turn == 0 or inventory_page_turn:
                        page_chars = 0
                        for artifact in usage_inventory[usage_inventory_offset:]:
                            item_chars = len(artifact.path) + len(artifact.kind) + 32
                            if usage_page and (
                                len(usage_page) >= _USAGE_INVENTORY_PAGE_ITEMS
                                or page_chars + item_chars > _USAGE_INVENTORY_PAGE_CHARS
                            ):
                                break
                            usage_page.append(artifact)
                            page_chars += item_chars
                        usage_inventory_offset += len(usage_page)
                    choices = self._choices(opened, entry, receiver_handoff_ids)
                    last_choice_ids = [
                        str(item["function_id"]) for item in choices
                    ]
                    prior_sample_count = len(samples)
                    prior_selector_count = len(selector_candidates)
                    prior_review_count = len(selector_reviews)
                    response = await self.llm.complete_json(
                        role="input_surface",
                        instructions=(
                            "Independently recover concrete bytes supplied to the original external Entry. "
                            "An input does NOT need a command name, switch branch, or request handler: "
                            "raw files, binary records, datagrams, stdin streams, argv and environment "
                            "are all valid input surfaces. Consider real framing, checksums, length fields, "
                            "initialization and state. Do not assume that any input is accepted. "
                            "Any bytes you propose are experimental HYPOTHESES, not static or runtime proof. "
                            "For each proposed byte string, cite a line in an opened parser, "
                            "request constructor, or usage file that supports its layout or value. "
                            "Use the exact function ID or opened file path as source_item_id; "
                            "an acquisition call alone does not support a particular byte value. "
                            "If the server emits a complete line before the first client write, "
                            "provide connection_prelude_marker_hex and cite the opened source "
                            "in connection_prelude_evidence. A current function's "
                            "referenced_global_declarations are Clang-confirmed "
                            "initializers it directly reads; cite their shown line using "
                            "that function's ID as source_item_id. This is a runtime hypothesis; "
                            "leave both empty if the sequence is unknown. "
                            "If no opened source supports concrete bytes, return no samples "
                            "and request the next relevant source item. "
                            "Return hex bytes only, including newline or protocol header if necessary. "
                            "Project test/client files are input-layout HYPOTHESES only. "
                            "They cannot prove product reachability or accepted bytes. "
                            "available_usage_paths is one page of the inventory; "
                            "usage_inventory_remaining reports paths not shown yet. "
                            f"Request {_NEXT_USAGE_INVENTORY_PAGE} in requested_function_ids "
                            "to inspect the next path page. "
                            "A usage file may also have more source pages; request "
                            "the same path again to read its next page. "
                            "To inspect one, put its exact path from available_usage_paths "
                            "in requested_function_ids. Otherwise request one relevant function "
                            "from the graph choices "
                            "or by an exact unique symbol referenced in already opened source. "
                            "For a global constant or table referenced by opened source, "
                            "request its exact identifier; the system may open its definition "
                            "in the same source file or a directly included local header. "
                            "For a macro, struct, union, enum, or class, set "
                            "requested_declaration_name to its exact name. This works "
                            "without following the function tree. Set list_declarations "
                            "to true to list all indexed names, or provide a literal "
                            "declaration_name_filter. For ambiguous names use "
                            "file:NAME or file:line:NAME. "
                            "Definitions in conditional source are lexical candidates, "
                            "not proof that the build selected that branch. "
                            "This lexical link is an inspection lead, not build or execution proof. "
                            "Request only one source item per turn. "
                            "Do not fabricate function IDs. Use context_complete=false if evidence is incomplete."
                            " A first valid sample is not completion. Inspect all distinct input formats "
                            "supported by opened parser source. The selector candidates below are syntax "
                            "recall hints, not Actions or proof that input selects them. For each candidate "
                            "report INPUT_FORM with a complete source-backed sample, "
                            "NOT_EXTERNAL_INPUT_FORM with a source-line reason, or NEEDS_SOURCE and "
                            "request the next relevant function. Do not mark complete while an input "
                            "selector remains unresolved. Branchless input formats still need samples."
                        ),
                        payload={
                            "entry": {
                                "entry_id": entry.entry_id,
                                "source_api": entry.source_api,
                                "channel_kind": entry.channel_kind,
                                "site_kind": str(entry.site_kind),
                                "unknowns": entry.unknowns,
                            },
                            "current_function": (
                                function_payload(
                                    current, source_limit=max(1, len(current.source) + 1),
                                ) if current is not None else None
                            ),
                            "current_usage_artifact": current_usage,
                            "opened_functions": [
                                function_ref(self.graph.get(value)) for value in opened
                            ],
                            "opened_usage_paths": list(opened_usage),
                            "available_usage_paths": [
                                {"path": artifact.path, "kind": artifact.kind}
                                for artifact in usage_page
                            ],
                            "usage_inventory_count": len(usage_by_path),
                            "declaration_index_count": len(declaration_index),
                            "usage_inventory_remaining": (
                                len(usage_inventory) - usage_inventory_offset
                            ),
                            "available_function_ids": choices,
                            "input_selector_candidates": [
                                {
                                    "selector_id": seed.operation_seed_id,
                                    "function_id": seed.dispatcher_function_id,
                                    "line": seed.line,
                                    "discriminator": seed.discriminator,
                                    "kind": seed.evidence_kind,
                                    "handler_function_ids": seed.handler_function_ids,
                                }
                                for seed in selector_candidates.values()
                                if seed.operation_seed_id not in selector_reviews
                            ],
                            "source_backed_samples_so_far": [
                                {"data_hex": value.hex(), "basis": basis}
                                for value, origin, _rationale, basis, _marker, _prelude in samples
                                if basis or origin == "user_request_fixture"
                            ],
                        },
                        output_schema=INPUT_SAMPLE_SCHEMA,
                        session_key=session_key,
                    )
                    for item in object_list(response.get("samples")):
                        raw = str(item.get("data_hex", ""))
                        try:
                            payload = bytes.fromhex(raw)
                        except ValueError:
                            continue
                        if not self.max_input_bytes or len(payload) <= self.max_input_bytes:
                            basis = _validated_sample_basis(
                                item.get("evidence"), opened,
                                opened_usage_lines, self.graph,
                            )
                            if not basis:
                                self.obligations.append(
                                    f"{entry.entry_id}: model input {payload.hex()} "
                                    "has no opened, source-located format/example basis; "
                                    "recorded but ineligible for runtime trial"
                                )
                            marker = str(item.get("connection_prelude_marker_hex", ""))
                            try:
                                marker_bytes = bytes.fromhex(marker)
                            except ValueError:
                                marker_bytes = b""
                            prelude_basis = _validated_sample_basis(
                                item.get("connection_prelude_evidence"), opened,
                                opened_usage_lines, self.graph,
                            ) if marker_bytes else []
                            sample = (
                                payload, "model_input_hypothesis",
                                str(item.get("rationale", "")), basis,
                                marker_bytes.hex() if prelude_basis else "",
                                prelude_basis,
                            )
                            if not any(
                                old[0] == sample[0] and old[4] == sample[4]
                                and old[3] == sample[3]
                                for old in samples
                            ):
                                samples.append(sample)
                    # A sample can cite several parser/dispatcher functions.
                    # Inspect selector syntax in exactly those cited sources;
                    # these are recall obligations, never Action definitions.
                    for _value, _origin, _rationale, basis, _marker, _prelude in samples:
                        for citation in basis:
                            function_id = str(citation.get("source_item_id") or "")
                            if (function_id not in opened
                                or function_id not in self.graph.bundle.functions):
                                continue
                            for seed in extract_operation_seeds(
                                [self.graph.get(function_id)], self.graph,
                            ):
                                if (seed.status is ProofStatus.REFUTED
                                    or seed.operation_seed_id in selector_candidates):
                                    continue
                                selector_candidates[seed.operation_seed_id] = seed
                                # One source-review turn per discovered source
                                # question is an evidence-derived allowance,
                                # not a fixed context or Action-count limit.
                                available_turns += 1
                    source_backed_values = {
                        value.hex() for value, origin, _rationale, basis,
                        _marker, _prelude in samples
                        if basis or origin == "user_request_fixture"
                    }
                    for review in object_list(response.get("selector_reviews")):
                        selector_id = str(review.get("selector_id") or "")
                        seed = selector_candidates.get(selector_id)
                        if seed is None or selector_id in selector_reviews:
                            continue
                        disposition = str(review.get("disposition") or "")
                        if disposition not in {"INPUT_FORM", "NOT_EXTERNAL_INPUT_FORM"}:
                            continue
                        cited = _validated_sample_basis(
                            review.get("evidence"), opened,
                            opened_usage_lines, self.graph,
                        )
                        if not any(
                            item.get("source_item_id") in {
                                seed.dispatcher_function_id,
                                *seed.handler_function_ids,
                            }
                            for item in cited
                        ):
                            continue
                        data_hex = str(review.get("data_hex") or "").lower()
                        if (disposition == "INPUT_FORM"
                            and data_hex not in source_backed_values):
                            continue
                        reason = str(review.get("reason") or "").strip()
                        if not reason:
                            continue
                        selector_reviews[selector_id] = {
                            "selector_id": selector_id,
                            "disposition": disposition,
                            "data_hex": data_hex if disposition == "INPUT_FORM" else "",
                            "reason": reason,
                            "evidence": cited,
                        }
                    has_trial_sample = any(
                        origin == "user_request_fixture" or bool(basis)
                        for _value, origin, _rationale, basis, _marker, _prelude_basis in samples
                    )
                    if (self.on_trial_cases is not None and has_trial_sample
                        and trial_transport_supported):
                        ready = []
                        for value, origin, rationale, basis, marker, prelude_basis in samples:
                            if ((value, marker) in published_trial_values
                                or not (origin == "user_request_fixture" or basis)):
                                continue
                            ready.append(case_for(value, origin, rationale, basis, marker, prelude_basis))
                        if ready:
                            try:
                                await self.on_trial_cases(entry, ready)
                            except Exception as exc:
                                if isinstance(exc, NameError):
                                    # A deterministic programming error in
                                    # the shared trial callback will recur for
                                    # every candidate. Preserve its traceback
                                    # instead of consuming source turns.
                                    raise
                                # The original-program trial is a separate
                                # experiment. Its adapter/storage failure is
                                # not an LLM failure or evidence against the
                                # source-backed bytes. Keep these cases for
                                # the final per-Entry delivery attempt.
                                self.obligations.append(
                                    f"{entry.entry_id}: early input trial "
                                    f"dispatch failed: {type(exc).__name__}: {exc}"
                                )
                            else:
                                published_trial_values.update(
                                    (bytes.fromhex(case.data_hex), case.connection_prelude_marker_hex)
                                    for case in ready
                                )
                    requested = string_list(response.get("requested_function_ids"))
                    declaration_request = str(
                        response.get("requested_declaration_name") or "").strip()
                    list_request = bool(response.get("list_declarations"))
                    if response.get("context_complete") is True and requested:
                        self.obligations.append(
                            f"{entry.entry_id}: model claimed complete context while "
                            "requesting another source item; continuing source walk"
                        )
                    pending = ""
                    if list_request:
                        declaration_filter = str(response.get("declaration_name_filter") or "")
                        if ("list", declaration_filter) in declaration_queries_seen:
                            stop_reason = "declaration catalog query repeated without new evidence"
                            break
                        declaration_queries_seen.add(("list", declaration_filter))
                        pending = _DECLARATION_CATALOG
                        available_turns += 1
                        continue
                    if declaration_request:
                        if ("open", declaration_request) in declaration_queries_seen:
                            stop_reason = "declaration lookup repeated without new evidence"
                            break
                        declaration_queries_seen.add(("open", declaration_request))
                        matches = declaration_index.lookup(declaration_request)
                        if len(matches) == 1:
                            definition = matches[0]
                            pending = (_DECLARATION_PREFIX + definition.file + ":"
                                       + definition.name + ":" + str(definition.start_line))
                            declaration_requests[pending] = definition
                        else:
                            declaration_lookup_message = (
                                "ambiguous; request file:NAME or file:line:NAME"
                                if matches else
                                "name absent from static declaration index")
                            pending = _DECLARATION_CATALOG
                            declaration_filter = declaration_request.rsplit(":", 1)[-1]
                        available_turns += 1
                        continue
                    if requested:
                        if requested[0] == _NEXT_USAGE_INVENTORY_PAGE:
                            if usage_inventory_offset < len(usage_inventory):
                                pending = requested[0]
                        elif requested[0] in usage_by_path or requested[0] in linked_declarations:
                            if (requested[0] not in opened_usage or
                                requested[0] in usage_pages_remaining):
                                pending = requested[0]
                        else:
                            pending = resolve_source_linked_function(
                                requested[0], opened, choices, self.graph,
                            )
                            if not pending:
                                matches = declaration_index.lookup(requested[0])
                                if len(matches) == 1:
                                    definition = matches[0]
                                    pending = (_DECLARATION_PREFIX + definition.file + ":"
                                               + definition.name + ":" + str(definition.start_line))
                                    declaration_requests[pending] = definition
                                    available_turns += 1
                            if not pending:
                                linked = _source_linked_declaration_artifact(
                                    self.project.source_root, requested[0],
                                    [self.graph.get(function_id) for function_id in opened],
                                    self.graph,
                                )
                                if linked is not None:
                                    artifact, offset = linked
                                    linked_declarations[artifact.path] = artifact
                                    usage_offsets[artifact.path] = offset
                                    header = self.project.source_root / artifact.path
                                    try:
                                        header_bytes = header.stat().st_size
                                    except OSError:
                                        header_bytes = 0
                                    available_turns += max(
                                        1,
                                        (header_bytes + _USAGE_SOURCE_PAGE_CHARS - 1)
                                        // _USAGE_SOURCE_PAGE_CHARS,
                                    )
                                    pending = artifact.path
                    if requested and not pending:
                        self.obligations.append(
                            f"{entry.entry_id}: requested source item "
                            f"{requested[0]!r} is unavailable or not source linked"
                        )
                    unreviewed_selectors = [
                        seed for seed in selector_candidates.values()
                        if seed.operation_seed_id not in selector_reviews
                    ]
                    if unreviewed_selectors and not pending:
                        made_progress = (
                            len(samples) > prior_sample_count
                            or len(selector_candidates) > prior_selector_count
                            or len(selector_reviews) > prior_review_count
                        )
                        if made_progress:
                            # Reopen the exact source containing an unresolved
                            # selector in the same Entry session. This is a
                            # focused review of an already opened parser,
                            # not a second Action-analysis pass.
                            pending = unreviewed_selectors[0].dispatcher_function_id
                            review_only = pending in opened
                            continue
                        stop_reason = (
                            "input selector inventory remains unresolved: "
                            + ", ".join(seed.operation_seed_id
                                        for seed in unreviewed_selectors)
                        )
                        self.obligations.append(f"{entry.entry_id}: {stop_reason}")
                        break
                    if not pending and not requested and not has_trial_sample:
                        pending = next((
                            function_id for function_id in destination_helper_ids
                            if function_id not in opened
                            and function_id in self.graph.bundle.functions
                        ), "")
                        if pending:
                            # This helper supplies the acquisition buffer;
                            # reading it does not establish accepted bytes.
                            continue
                        # A completed model turn at the acquisition call is
                        # not evidence that the input format is absent. Open
                        # the next source-located direct argument or receiver
                        # field consumer before ending this search. A field
                        # match is navigation only, not byte-flow proof.
                        # Reported calls and callback guesses remain explicit
                        # requests and unresolved continuation leads.
                        source_leads = unique_strings(
                            function_id for function_id in unique_strings([
                                *proven_consumer_ids,
                                *direct_receiver_handoff_ids,
                            ])
                            if function_id not in opened
                            and function_id in self.graph.bundle.functions
                        )
                        # A direct, located transfer can have several sibling
                        # consumers. Keep every sibling as a continuation,
                        # but do not select one by source order. Candidate,
                        # indirect and field-only edges remain questions;
                        # this walk does not prove alias identity or runtime
                        # feasibility.
                        pending = next_direct_consumer()
                        if not pending:
                            # Preserve the prior narrow receiver-field
                            # navigation when it has one located immediate
                            # successor. Its possible field alias remains
                            # unresolved until the next body is inspected.
                            immediate_receivers = [
                                function_id for function_id in
                                direct_receiver_handoff_ids
                                if function_id not in opened
                                and any(
                                    edge.caller_id == opened[-1]
                                    and edge.callee_id == function_id
                                    and edge.kind == "direct"
                                    and edge.line is not None
                                    for edge in self.graph.bundle.edges
                                )
                            ]
                            if len(immediate_receivers) == 1:
                                pending = immediate_receivers[0]
                        if pending:
                            continue
                        # An acquisition wrapper may return an output buffer
                        # to its caller before the input format is checked.
                        # A unique, located direct caller can be inspected as
                        # a question. Multiple callers remain unresolved.
                        if not source_leads and len(direct_return_callers) == 1:
                            candidate = direct_return_callers[0]
                            if candidate not in opened:
                                pending = candidate
                                continue
                        # Once a return caller is open, a field-backed read
                        # may lead to several source-registered callbacks.
                        # Inspect only callbacks whose invocation is located
                        # after the read and whose bodies reference the
                        # acquired field.  They are format-search questions,
                        # never evidence that a particular request uses them.
                        if not source_leads:
                            pending = next_post_read_callback()
                        if pending:
                            continue
                    if (not pending and not requested and has_trial_sample
                        and response.get("context_complete") is not True):
                        # A source-backed sample permits an original-program
                        # trial. Continue exploring only when the model says
                        # that its input-format question remains open. Action
                        # discovery independently walks the other consumers;
                        # this stage must not exhaust that same worklist just
                        # to publish one trial hypothesis. Any skipped leads
                        # are recorded in the continuation below.
                        pending = next_direct_consumer() or next_post_read_callback()
                        if pending:
                            continue
                    if (not pending and not requested and has_trial_sample
                        and response.get("context_complete") is True):
                        # A first example does not close an input-format walk.
                        # Inspect the next uniquely linked consumer before
                        # accepting completion. Ambiguous leads stay explicit
                        # obligations; no arbitrary source-order choice.
                        pending = next_direct_consumer() or next_post_read_callback()
                        if pending:
                            continue
                        remaining_consumers = unique_strings([
                            *entry.consumer_hints, *destination_helper_ids,
                            *direct_consumer_ids,
                            *receiver_handoff_ids,
                            *direct_return_callers,
                            *shared_root_callers,
                        ])
                        remaining_consumers = [
                            function_id for function_id in remaining_consumers
                            if function_id not in opened
                            and function_id in self.graph.bundle.functions
                        ]
                        remaining_source_leads = [
                            function_id for function_id in last_choice_ids
                            if function_id not in opened
                            and function_id in self.graph.bundle.functions
                        ]
                        unopened_usage_paths = [
                            artifact.path for artifact in usage_inventory
                            if artifact.path not in opened_usage
                        ]
                        remaining_usage = (
                            bool(usage_pages_remaining)
                            or bool(unopened_usage_paths)
                            or usage_inventory_offset < len(usage_inventory)
                        )
                        if remaining_consumers or remaining_source_leads:
                            self.obligations.append(
                                f"{entry.entry_id}: trial bytes proposed before "
                                "all input paths were inspected; remaining "
                                "functions are Action navigation leads: "
                                + ", ".join(unique_strings([
                                    *remaining_consumers, *remaining_source_leads,
                                ]))
                            )
                        if remaining_usage:
                            self.obligations.append(
                                f"{entry.entry_id}: trial bytes proposed while "
                                "usage evidence remains uninspected"
                            )
                        if remaining_consumers or remaining_source_leads or remaining_usage:
                            self.continuations.append({
                                "entry_id": entry.entry_id,
                                "opened_function_ids": list(opened),
                                "opened_usage_paths": list(opened_usage),
                                "next_function_ids": unique_strings([
                                    *remaining_consumers,
                                    *remaining_source_leads,
                                    *unopened_usage_paths,
                                    *([_NEXT_USAGE_INVENTORY_PAGE]
                                      if usage_inventory_offset < len(usage_inventory)
                                      else []),
                                    *sorted(usage_pages_remaining),
                                ]),
                                "unopened_usage_paths": unopened_usage_paths,
                                "unread_usage_pages": sorted(usage_pages_remaining),
                                "unread_usage_offsets": {
                                    path: usage_offsets[path]
                                    for path in sorted(usage_pages_remaining)
                                },
                                "usage_inventory_offset": usage_inventory_offset,
                                "usage_inventory_remaining": (
                                    len(usage_inventory) - usage_inventory_offset
                                ),
                                "stop_reason": (
                                    "trial-byte hypothesis ready; remaining "
                                    "input consumers or usage evidence are uninspected"
                                ),
                                "policy": (
                                    "trial bytes are not accepted-request or "
                                    "Action-inventory proof"
                                ),
                            })
                        # A replayable byte string is enough for an original
                        # program experiment. It does not close other
                        # source-linked input consumers or unread usage
                        # evidence. Preserve the incomplete inventory for
                        # later analysis while still returning the sample.
                        context_complete = not (
                            remaining_consumers or remaining_source_leads
                            or remaining_usage
                        )
                        stop_reason = (
                            "trial-byte hypothesis ready; input inventory incomplete"
                            if not context_complete else
                            "trial-byte hypothesis ready for original execution"
                        )
                        break
                    # A completion claim without concrete bytes cannot
                    # establish a usable external-input hypothesis.
                    context_complete = (
                        response.get("context_complete") is True
                        and not requested
                        and has_trial_sample
                        and not usage_pages_remaining
                        and usage_inventory_offset == len(usage_inventory)
                    )
                    if context_complete:
                        pending = ""
                        stop_reason = "model marked input context complete"
                        break
                    if not pending:
                        if usage_pages_remaining:
                            stop_reason = "selected usage file has unread source pages"
                        elif usage_inventory_offset < len(usage_inventory):
                            stop_reason = "usage path inventory has unread pages"
                        elif not has_trial_sample and (entry.consumer_hints or direct_consumer_ids):
                            stop_reason = "input bytes unresolved; source-linked consumer leads remain"
                        else:
                            stop_reason = "requested source item unavailable or already opened"
                        if not requested:
                            self.obligations.append(
                                f"{entry.entry_id}: input context incomplete: {stop_reason}"
                            )
                        break
                else:
                    stop_reason = "function work budget exhausted"
            except Exception as exc:
                if isinstance(exc, NameError):
                    raise
                if is_terminal_llm_infrastructure_error(exc):
                    raise
                # Keep user corpus and deterministic probes for a transient
                # model failure. Preserve the exact failure in the inventory.
                self.obligations.append(
                    f"{entry.entry_id}: input hypothesis model failed: {type(exc).__name__}: {exc}"
                )
                stop_reason = f"model failure: {type(exc).__name__}: {exc}"
            finally:
                await close_llm_session(self.llm, session_key)
            inspected.extend(opened)
            unresolved_selector_ids = [
                seed.operation_seed_id for seed in selector_candidates.values()
                if seed.operation_seed_id not in selector_reviews
            ]
            for seed in selector_candidates.values():
                self.selector_audit.append({
                    "entry_id": entry.entry_id,
                    "selector_id": seed.operation_seed_id,
                    "function_id": seed.dispatcher_function_id,
                    "line": seed.line,
                    "discriminator": seed.discriminator,
                    "review": selector_reviews.get(seed.operation_seed_id),
                    "status": (
                        "REVIEWED" if seed.operation_seed_id in selector_reviews
                        else "UNRESOLVED"
                    ),
                })
            if unresolved_selector_ids:
                context_complete = False
                self.obligations.append(
                    f"{entry.entry_id}: input selector review unresolved: "
                    + ", ".join(unresolved_selector_ids)
                )
                for continuation in self.continuations:
                    if continuation.get("entry_id") == entry.entry_id:
                        continuation["unresolved_selector_ids"] = unresolved_selector_ids
                        continuation["next_function_ids"] = unique_strings([
                            *string_list(continuation.get("next_function_ids")),
                            *(seed.dispatcher_function_id
                              for seed in selector_candidates.values()
                              if seed.operation_seed_id in unresolved_selector_ids),
                        ])
            unresolved_root_callers = [
                function_id for function_id in shared_root_callers
                if function_id not in opened
            ]
            if not samples and len(shared_root_callers) > 1 and unresolved_root_callers:
                context_complete = False
                stop_reason = "multiple source-located input return callers unresolved"
                self.obligations.append(
                    f"{entry.entry_id}: multiple source-located callers could "
                    "continue the shared-field input path; no caller selected: "
                    + ", ".join(unresolved_root_callers)
                )
            unresolved_leads: list[str] = []
            if shared_field_roots and not samples:
                unresolved_leads = [
                    *[lead[0] for lead in _shared_field_return_callers(
                        self.graph, opened, shared_field_roots,
                        entry.entry_function_id,
                    )],
                    *[lead[0] for lead in _shared_field_handoff_candidates(
                        self.graph, entry, opened, shared_field_roots,
                    ) if lead[0] not in opened],
                ]
                if unresolved_leads:
                    self.obligations.append(
                        f"{entry.entry_id}: source-linked shared-field input "
                        "candidates remain unopened: "
                        + ", ".join(unique_strings(unresolved_leads))
                    )
            if not context_complete:
                remaining_consumers = [
                    function_id for function_id in unique_strings([
                        *entry.consumer_hints, *destination_helper_ids,
                        *direct_consumer_ids,
                        *receiver_handoff_ids,
                        *direct_return_callers,
                    ])
                    if function_id in self.graph.bundle.functions
                    and function_id not in opened
                ]
                unopened_usage_paths = [
                    artifact.path for artifact in usage_inventory
                    if artifact.path not in opened_usage
                ]
                self.continuations.append({
                    "entry_id": entry.entry_id,
                    "unresolved_selector_ids": unresolved_selector_ids,
                    "opened_function_ids": list(opened),
                    "opened_usage_paths": list(opened_usage),
                    "next_function_ids": unique_strings([
                        *([pending] if pending and pending not in opened else []),
                        *(seed.dispatcher_function_id
                          for seed in selector_candidates.values()
                          if seed.operation_seed_id in unresolved_selector_ids),
                        *remaining_consumers,
                        *unresolved_root_callers,
                        *unresolved_leads,
                        *last_choice_ids,
                        *unopened_usage_paths,
                        *([_NEXT_USAGE_INVENTORY_PAGE]
                          if usage_inventory_offset < len(usage_inventory) else []),
                        *sorted(usage_pages_remaining),
                    ]),
                    "unread_usage_pages": sorted(usage_pages_remaining),
                    "unopened_usage_paths": unopened_usage_paths,
                    "unread_usage_offsets": {
                        path: usage_offsets[path]
                        for path in sorted(usage_pages_remaining)
                    },
                    "usage_inventory_offset": usage_inventory_offset,
                    "usage_inventory_remaining": (
                        len(usage_inventory) - usage_inventory_offset
                    ),
                    "stop_reason": stop_reason,
                    "policy": "incomplete input context is not an accepted-request claim",
                })
                if stop_reason == "function work budget exhausted":
                    self.obligations.append(
                        f"{entry.entry_id}: input context incomplete; {stop_reason}; "
                        f"next function: {pending or 'none'}"
                    )
            for continuation in self.continuations:
                if continuation.get("entry_id") != entry.entry_id:
                    continue
                continuation["entry_fingerprint"] = _surface_entry_fingerprint(entry)
                continuation["source_fingerprints"] = {
                    function_id: _surface_function_fingerprint(
                        self.graph.get(function_id)
                    )
                    for function_id in unique_strings([
                        *string_list(continuation.get("opened_function_ids")),
                        *string_list(continuation.get("next_function_ids")),
                    ]) if function_id in self.graph.bundle.functions
                }
            if not any(
                origin == "user_request_fixture" or bool(basis)
                for _value, origin, _rationale, basis, _marker, _prelude_basis in samples
            ):
                self.obligations.append(
                    f"{entry.entry_id}: no source-backed or user-supplied "
                    "sample eligible for original runtime trial"
                )
            by_value: dict[tuple[bytes, str], tuple[str, str, list[dict[str, object]], list[dict[str, object]]]] = {}
            for value, origin, rationale, basis, marker, prelude_basis in samples:
                key = (value, marker)
                previous = by_value.get(key)
                if previous is None or (
                    not previous[2] and basis
                    and previous[0] != "user_request_fixture"
                ):
                    by_value[key] = (origin, rationale, basis, prelude_basis)
            entry_cases: list[InputSurfaceCase] = []
            for (value, marker), (origin, rationale, basis, prelude_basis) in by_value.items():
                entry_cases.append(case_for(value, origin, rationale, basis, marker, prelude_basis))
            emit_trace(
                self.trace, "input_surface", "entry_complete",
                f"{entry.entry_id}: {len(by_value)} possible raw inputs from {len(opened)} opened functions",
                entry_id=entry.entry_id, sample_count=len(by_value), function_ids=opened,
            )
            if self.on_entry_cases is not None:
                await self.on_entry_cases(entry, entry_cases)
            return entry_cases

        # Every Entry owns its own stateful model session. Let independent
        # source walks progress on the configured model workers so one long
        # unresolved Entry cannot prevent later Entries from supplying
        # original-program trials. Preserve the caller's Entry order in the
        # returned inventory; completion order is only a scheduling detail.
        groups = await concurrent_map(
            entries, inspect_entry,
            max(1, int(getattr(self.llm, "max_concurrency", 1))),
        )
        return [case for group in groups for case in group]

    def _read_usage_artifact(
        self, artifact: UsageArtifact, offset: int = 0,
    ) -> dict[str, object] | None:
        path = Path(artifact.path)
        if not path.is_absolute():
            path = self.project.source_root / path
        try:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != artifact.sha256:
                return None
            source = data.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        end = min(len(source), offset + _USAGE_SOURCE_PAGE_CHARS)
        return {
            "path": artifact.path, "kind": artifact.kind,
            "source": source[offset:end], "start_offset": offset,
            "start_line": source.count("\n", 0, offset) + 1,
            "end_line": source.count("\n", 0, end) + 1,
            "next_offset": end, "has_more": end < len(source),
        }

    def _choices(
        self, opened: list[str], entry: EntryRecord,
        receiver_handoff_ids: list[str] | None = None,
    ) -> list[dict[str, object]]:
        choices = {str(item["function_id"]): item for item in self.graph.frontier(opened)}

        def add_navigation(choice: dict[str, object]) -> None:
            function_id = str(choice["function_id"])
            existing = choices.get(function_id)
            if existing is None:
                choices[function_id] = choice
                return
            connections = existing.get("connections")
            additions = choice.get("connections")
            if isinstance(connections, list) and isinstance(additions, list):
                for connection in additions:
                    if connection not in connections:
                        connections.append(connection)

        # A parser may run after a read wrapper returns or through a
        # source-registered callback. Expose these as selectable questions;
        # a shared field spelling or callback slot is never proof that the
        # same external bytes reached the candidate.
        root_fields = _entry_shared_field_paths(
            self.graph.get(entry.entry_function_id), entry,
        )
        for function_id, caller_id, field_name in _shared_field_handoff_candidates(
            self.graph, entry, opened, root_fields,
        ):
            add_navigation({
                **function_ref(self.graph.get(function_id)),
                "connections": [{
                    "relation": "post_read_field_candidate",
                    "connected_function_id": caller_id,
                    "field_name": field_name,
                    "proof_policy": "navigation only; object and byte identity unproven",
                }],
            })
        for function_id, callee_id in _shared_field_return_callers(
            self.graph, opened, root_fields, entry.entry_function_id,
        ):
            add_navigation({
                **function_ref(self.graph.get(function_id)),
                "connections": [{
                    "relation": "post_read_return_caller_candidate",
                    "connected_function_id": callee_id,
                    "proof_policy": "navigation only; return path and byte identity unproven",
                }],
            })
        for choice in self.graph.callback_slot_candidates(opened):
            add_navigation(choice)
        for choice in self.graph.callback_registration_candidates(opened):
            add_navigation(choice)
        # After a direct caller of a read wrapper is opened, a call through
        # the same receiver's callback slot can reveal the parser. These
        # targets remain selectable, never automatically proven or opened.
        for caller_id in opened:
            if caller_id == entry.entry_function_id:
                continue
            caller = self.graph.bundle.functions.get(caller_id)
            if caller is None:
                continue
            if not any(
                edge.caller_id == caller_id
                and edge.callee_id == entry.entry_function_id
                and edge.kind == "direct" and edge.line is not None
                for edge in self.graph.bundle.edges
            ):
                continue
            for function_id in _same_receiver_return_callbacks(
                self.graph, entry, caller,
            ):
                if function_id in opened:
                    continue
                add_navigation({
                    **function_ref(self.graph.get(function_id)),
                    "connections": [{
                        "relation": "same_receiver_return_callback_candidate",
                        "connected_function_id": caller_id,
                        "proof_policy": (
                            "navigation only; callback target and execution "
                            "require separate source and runtime evidence"
                        ),
                    }],
                })
        for function_id in (
            receiver_handoff_ids if receiver_handoff_ids is not None
            else source_receiver_field_navigation_candidates(self.graph, entry)
        ):
            if function_id in opened:
                continue
            add_navigation({
                **function_ref(self.graph.get(function_id)),
                "connections": [{
                    "relation": "receiver_field_handoff_candidate",
                    "proof_policy": (
                        "navigation only; source-located receiver transfer "
                        "does not prove byte identity or runtime reachability"
                    ),
                }],
            })
        for function_id in unique_strings([
            *entry.inspected_function_ids, *entry.consumer_hints,
        ]):
            if function_id in opened or function_id not in self.graph.bundle.functions:
                continue
            choices.setdefault(function_id, {
                **function_ref(self.graph.get(function_id)),
                "connections": [{"relation": "entry_provenance_navigation_only"}],
            })
        return list(choices.values())


def _validated_sample_basis(
    raw: object,
    opened_function_ids: list[str],
    opened_usage_lines: dict[str, list[tuple[int, int]]],
    graph: GraphStore,
) -> list[dict[str, object]]:
    """Check citation location, without treating the cited bytes as accepted."""
    result: list[dict[str, object]] = []
    for item in object_list(raw):
        source_item_id = str(item.get("source_item_id", ""))
        line = item.get("line")
        detail = str(item.get("detail", "")).strip()
        if type(line) is not int or not detail:
            continue
        function = graph.bundle.functions.get(source_item_id)
        stated_file = str(item.get("file") or "")
        evidence_file = ""
        if function is not None:
            if source_item_id not in opened_function_ids:
                continue
            function_line = (
                function.start_line <= line <= function.end_line
                and (not stated_file or stated_file == function.file)
            )
            matches = [
                declaration for declaration
                in [
                    *function.referenced_global_declarations,
                    *function.referenced_macro_definitions,
                ]
                if declaration.get("start_line", 0) <= line
                <= declaration.get("end_line", 0)
                and (not stated_file or stated_file == declaration.get("file"))
            ]
            if function_line and matches and not stated_file:
                continue  # same numeric line in two files is ambiguous
            if function_line:
                evidence_file = function.file
            else:
                if len(matches) != 1:
                    continue
                evidence_file = str(matches[0]["file"])
        elif not any(
            start <= line <= end
            for start, end in opened_usage_lines.get(source_item_id, [])
        ):
            continue
        citation = {
            "source_item_id": source_item_id,
            "line": line,
            "detail": detail,
        }
        if evidence_file:
            citation["file"] = evidence_file
        result.append(citation)
    return result


def _explicit_request_fixtures(paths: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file():
            # An explicit .txt is a possible request; a README or PCAP is not
            # raw application payload and requires a separate parser.
            if path.suffix.lower() in _RAW_FIXTURE_EXTENSIONS | {".txt"}:
                files.add(path)
        elif path.is_dir():
            files.update(
                item for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() in _RAW_FIXTURE_EXTENSIONS
            )
    return sorted(files)


def _surface_entry_fingerprint(entry: EntryRecord) -> str:
    return stable_id(
        "surface-entry", entry.entry_id, entry.entry_function_id,
        entry.entry_line, entry.source_api, entry.channel_kind,
    )


def _surface_function_fingerprint(function: Any) -> str:
    return hashlib.sha256(
        (function.file + "\n" + function.signature + "\n" + function.source)
        .encode("utf-8")
    ).hexdigest()


def _supports_trial_transport(entry: EntryRecord, selected_channel: str = "auto") -> bool:
    if entry.site_kind is EntrySiteKind.EXPORTED_API:
        return False
    if source_transport(entry) in {
        "tcp", "udp", "unix_stream", "stdin", "file", "argv", "env",
    }:
        return True
    # Source-ambiguous socket inputs can still yield byte-layout hypotheses
    # when the operator selected a concrete local trial. The selected
    # executor does not prove that the Entry uses that transport.
    return permits_explicit_socket_trial(
        entry.channel_kind, entry.source_api, selected_channel,
    )


def raw_case_runtime_action(case: InputSurfaceCase, entry: EntryRecord, graph: GraphStore) -> ExternalActionSchema:
    """Compatibility with the current runtime, without asserting an Action."""
    actor = _entry_actor(entry, graph)
    entry_evidence = list(case.evidence)
    return ExternalActionSchema(
        action_id=case.case_id, entry_id=entry.entry_id,
        name="RAW_EXTERNAL_INPUT", description="unclassified raw input boundary experiment",
        dispatcher_function_id=case.entry_function_id,
        handler_function_id=case.entry_function_id,
        discriminator="UNCLASSIFIED_INPUT", channel_kind=case.channel_kind,
        fields=[], examples=[ActionExample(
            data_hex=case.data_hex, rationale=case.rationale,
            origin=case.origin, evidence=entry_evidence,
        )],
        success_markers_hex=[], failure_markers_hex=[], evidence=entry_evidence,
        inspected_function_ids=case.inspected_function_ids,
        status=ProofStatus.POSSIBLE,
        unknowns=["input acceptance unproven", "semantic handler not identified"],
        source_api=case.source_api,
        actor=actor,
        entry_function_id=case.entry_function_id,
        entry_probe_evidence=entry_evidence,
        dispatch_probe_evidence=[],
        connection_prelude_marker_hex=case.connection_prelude_marker_hex,
    )
