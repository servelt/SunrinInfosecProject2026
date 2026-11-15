"""Recover concrete external requests only after semantic Action selection."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from ..analysis.graph import GraphStore
from ..analysis.declarations import DeclarationIndex, SourceDeclaration
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    ActionExample, Evidence, ExternalActionSchema, InputFieldConstraint,
    ProofStatus, as_json, unique_strings,
)
from ..storage import ArtifactStore
from .common import (
    concurrent_map, function_payload, function_ref,
    resolve_source_linked_function, source_linked_numeric_definitions,
)
from .scenario import INPUT_ACTION_SCHEMA, _examples, _fields, _validated_evidence

_ACTION_PROPERTIES = INPUT_ACTION_SCHEMA["properties"]["actions"]["items"]["properties"]
_REQUEST_CHECKPOINT_SCHEMA_VERSION = 2
ACTION_REQUEST_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["decision", "examples", "fields", "requested_function_id",
                 "requested_declaration_name", "list_declarations",
                 "declaration_name_filter", "reason", "drop_evidence"],
    "properties": {
        "decision": {"type": "string", "enum": ["READY", "CONTINUE", "DROP", "UNRESOLVED"]},
        "examples": _ACTION_PROPERTIES["examples"],
        "fields": _ACTION_PROPERTIES["fields"],
        "requested_function_id": {"type": "string"},
        "requested_declaration_name": {"type": "string"},
        "list_declarations": {"type": "boolean"},
        "declaration_name_filter": {"type": "string"},
        "reason": {"type": "string"},
        "drop_evidence": _ACTION_PROPERTIES["evidence"],
    },
}


@dataclass(slots=True)
class ActionRequestDecision:
    action_id: str
    disposition: str
    reason: str
    opened_function_ids: list[str]
    example_count: int = 0
    requested_function_id: str = ""


class ActionRequestAgent:
    """Open one linked source at a time until an Action request is resolved."""

    def __init__(self, llm: LLMProvider, graph: GraphStore,
                 source_root: Path | None = None, *,
                 checkpoint_store: ArtifactStore | None = None,
                 resume_checkpoint_dir: Path | None = None,
                 progress: Callable[[ActionRequestDecision, int, int, bool], None] | None = None):
        self.llm = llm
        self.graph = graph
        self.declarations = DeclarationIndex(graph.bundle.declarations)
        self.source_root = source_root
        self.checkpoint_store = checkpoint_store
        self.resume_checkpoint_dir = resume_checkpoint_dir
        self.progress = progress
        self._numeric_definitions_by_function: dict[str, list[dict[str, object]]] = {}
        self._shared_effects: dict[str, dict[str, Any]] = {}

    async def run(
        self, actions: list[ExternalActionSchema], *,
        shared_effects: dict[str, dict[str, Any]] | None = None,
    ) -> tuple[list[ExternalActionSchema], list[ActionRequestDecision]]:
        self._shared_effects = dict(shared_effects or {})
        source_digest = self._source_digest()
        completed = 0

        async def resolve_and_record(action: ExternalActionSchema
                                     ) -> tuple[ExternalActionSchema, ActionRequestDecision]:
            nonlocal completed
            input_digest = hashlib.sha256(json.dumps(
                {
                    "action": as_json(action),
                    "shared_source_effect": self._shared_effects.get(action.action_id),
                }, sort_keys=True, ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            cached = (
                self._load_checkpoint(action, input_digest, source_digest)
                if source_digest is not None else None
            )
            reused = cached is not None
            result = cached if cached is not None else await self._resolve(action)
            if not reused and self.checkpoint_store is not None:
                self.checkpoint_store.write_json(
                    self._checkpoint_name(action.action_id), {
                        "schema_version": _REQUEST_CHECKPOINT_SCHEMA_VERSION,
                        "input_digest": input_digest,
                        "source_digest": source_digest,
                        "resolved_action": result[0],
                        "decision": result[1],
                    },
                )
            completed += 1
            if self.progress is not None:
                self.progress(result[1], completed, len(actions), reused)
            return result

        results = await concurrent_map(
            actions, resolve_and_record,
            max(1, int(getattr(self.llm, "max_concurrency", 1))),
        )
        return [action for action, _ in results], [decision for _, decision in results]

    @staticmethod
    def _checkpoint_name(action_id: str) -> Path:
        name = hashlib.sha256(action_id.encode("utf-8")).hexdigest()
        return Path("actions/request-checkpoints") / f"{name}.json"

    def _source_digest(self) -> str | None:
        """Invalidate request checkpoints when indexed code or local headers change."""
        digest = hashlib.sha256()
        for function_id, function in sorted(self.graph.bundle.functions.items()):
            digest.update(function_id.encode("utf-8"))
            digest.update(b"\0")
            digest.update(function.source.encode("utf-8"))
            digest.update(b"\0")
        for declaration in self.declarations.all():
            digest.update(declaration.name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(declaration.file.encode("utf-8"))
            digest.update(b"\0")
            digest.update(declaration.source.encode("utf-8"))
            digest.update(b"\0")
        if self.source_root is not None:
            try:
                for path in sorted(self.source_root.rglob("*")):
                    if path.suffix.lower() not in {".h", ".hh", ".hpp", ".hxx", ".inc", ".def"}:
                        continue
                    if not path.is_file():
                        continue
                    digest.update(str(path.relative_to(self.source_root)).encode("utf-8"))
                    digest.update(b"\0")
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1 << 20), b""):
                            digest.update(block)
                    digest.update(b"\0")
            except OSError:
                # Reading source for caching must never block request analysis.
                return None
        return digest.hexdigest()

    def _load_checkpoint(
        self, action: ExternalActionSchema, input_digest: str, source_digest: str,
    ) -> tuple[ExternalActionSchema, ActionRequestDecision] | None:
        locations: list[Path] = []
        if self.checkpoint_store is not None:
            locations.append(self.checkpoint_store.root)
        if self.resume_checkpoint_dir is not None:
            locations.append(self.resume_checkpoint_dir)
        for root in locations:
            path = root / self._checkpoint_name(action.action_id)
            if not path.is_file():
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                checkpoint_version = raw.get("schema_version")
                if (checkpoint_version not in (1, _REQUEST_CHECKPOINT_SCHEMA_VERSION)
                    or raw.get("input_digest") != input_digest
                    or raw.get("source_digest") != source_digest):
                    continue
                saved = raw["resolved_action"]
                decision_raw = raw["decision"]
                # The old request loop ended after an invalid READY or an
                # incomplete CONTINUE. Revisit only old unresolved results;
                # already accepted requests and source-backed drops are reusable.
                if (checkpoint_version == 1
                    and decision_raw.get("disposition") == "UNRESOLVED"):
                    continue
                if (saved["action_id"] != action.action_id
                    or decision_raw["action_id"] != action.action_id):
                    continue
                evidence = lambda values: [Evidence(**item) for item in values]
                examples = [ActionExample(
                    data_hex=item["data_hex"], bindings=item.get("bindings", {}),
                    rationale=item.get("rationale", ""), origin=item.get("origin", "model_candidate"),
                    evidence=evidence(item.get("evidence", [])),
                ) for item in saved["examples"]]
                fields = [InputFieldConstraint(
                    name=item["name"], offset=item["offset"], width=item["width"],
                    encoding=item.get("encoding", "bytes"), binding=item.get("binding", ""),
                    relation=item.get("relation", "opaque"),
                    evidence=evidence(item.get("evidence", [])),
                ) for item in saved["fields"]]
                resolved = replace(
                    action, examples=examples, fields=fields,
                    evidence=evidence(saved["evidence"]),
                    inspected_function_ids=list(saved["inspected_function_ids"]),
                    unknowns=list(saved["unknowns"]),
                    status=ProofStatus(saved["status"]),
                )
                decision = ActionRequestDecision(**decision_raw)
                if decision.disposition not in {"READY", "DROP", "UNRESOLVED"}:
                    continue
                return resolved, decision
            except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
                continue
        return None

    async def _resolve(self, action: ExternalActionSchema
                       ) -> tuple[ExternalActionSchema, ActionRequestDecision]:
        if action.status is ProofStatus.REFUTED:
            return action, ActionRequestDecision(
                action.action_id, "DROP", "Action was source-refuted", [],
            )
        functions = self.graph.bundle.functions
        anchors = list(dict.fromkeys([
            action.entry_function_id, action.dispatcher_function_id,
            action.handler_function_id,
        ]))
        if not all(function_id in functions for function_id in anchors):
            return replace(action, examples=[], unknowns=unique_strings([
                *action.unknowns,
                "ACTION_INPUT_UNRESOLVED: required source is not indexed",
            ])), ActionRequestDecision(
                action.action_id, "UNRESOLVED",
                "The acquisition, selector, or handler source is not indexed", [],
            )
        opened: list[str] = []
        pending = list(anchors)
        opened_declarations: list[SourceDeclaration] = []
        opened_declaration_keys: set[tuple[str, str, int]] = set()
        declaration_queries_seen: set[tuple[str, str]] = set()
        next_declaration: SourceDeclaration | None = None
        catalog_query: str | None = None
        lookup_message: str | None = None
        current_id = ""
        session = f"action_request:{action.action_id}"
        payload = as_json(action)
        payload.pop("inspected_function_ids", None)
        reason = ""
        requested = ""
        validation_feedback = ""
        rejected_without_new_source: set[tuple[tuple[str, ...], tuple[tuple[str, str, int], ...], str]] = set()
        numeric_definitions: dict[tuple[str, str, int], dict[str, object]] = {}
        try:
            while (pending or next_declaration is not None or catalog_query is not None
                   or lookup_message is not None or validation_feedback):
                if (next_declaration is None and catalog_query is None
                    and lookup_message is None):
                    if pending:
                        current_id = pending.pop(0)
                        if current_id in opened:
                            continue
                        opened.append(current_id)
                feedback_view = validation_feedback
                validation_feedback = ""
                declaration_view = next_declaration
                next_declaration = None
                if declaration_view is not None:
                    opened_declarations.append(declaration_view)
                    opened_declaration_keys.add((declaration_view.name,
                                                 declaration_view.file,
                                                 declaration_view.start_line))
                catalog_view = (self.declarations.names(catalog_query)
                                if catalog_query is not None else None)
                catalog_query = None
                message_view = lookup_message
                lookup_message = None
                current = functions[current_id]
                if self.source_root is not None:
                    if current_id not in self._numeric_definitions_by_function:
                        self._numeric_definitions_by_function[current_id] = (
                            source_linked_numeric_definitions(self.source_root, current)
                        )
                    for definition in self._numeric_definitions_by_function[current_id]:
                        key = (str(definition["name"]), str(definition["file"]),
                               int(definition["line"]))
                        numeric_definitions[key] = definition
                frontier = [item for item in self.graph.frontier([current_id])
                            if item["function_id"] not in opened]
                response = await self.llm.complete_json(
                    role="input_action",
                    instructions=(
                        "For this ONE selected Action, recover every distinct complete external "
                        "request form supported by the opened source. The acquisition, selection, "
                        "and effect functions are opened one at a time in this same session. "
                        "Do not finish after the first request if another format, opcode, or "
                        "required field remains unresolved. Give exact request bytes and "
                        "source-line evidence for their framing, lengths, and variable fields. "
                        "Existing examples are hypotheses; validate them or replace them. "
                        "The source_linked_numeric_definitions are exact local-source "
                        "lines from the opened function's include chain. Use only "
                        "unambiguous definitions, and cite a used definition with "
                        "kind=source_declaration, function_id=<file>, line=<line>. "
                        "A numeric definition alone does not establish a complete "
                        "request: each READY example must also cite an opened "
                        "function line supporting its request framing or payload. "
                        "Request the exact next linked function ID or uniquely named source symbol "
                        "when parser or callback evidence is missing. For a macro, struct, "
                        "union, enum, or class, request its exact name in "
                        "requested_declaration_name. You may request any indexed name "
                        "directly without following the function tree. Set list_declarations "
                        "to true to receive all indexed names; use declaration_name_filter "
                        "for a literal name substring. If a name has multiple definitions, "
                        "request file:NAME or file:line:NAME to disambiguate. "
                        "Opened declarations are lexical "
                        "source candidates, not proof of the compiler-selected #if branch; "
                        "cite their file and line with kind=source_declaration, and verify "
                        "request framing against an opened function. "
                        "READY requires at least one complete cited request and no known unexplored "
                        "request form for this Action. DROP only if cited selection and handler "
                        "source establish that the purported Action cannot be selected by external "
                        "input. Missing examples or an unavailable runtime executor are not DROP. "
                        "If no further source can resolve the missing fact, return UNRESOLVED. "
                        "These requests are source hypotheses until original-program execution. "
                        "A shared source effect is only a review hint; validate this Action's "
                        "own Entry, selector, framing, and response independently."
                    ),
                    payload={
                        "action": payload,
                        "shared_source_effect": self._shared_effects.get(action.action_id),
                        "current_function": function_payload(
                            current, source_limit=max(1, len(current.source) + 1)),
                        "opened_functions": [function_ref(functions[fid]) for fid in opened],
                        "required_anchors_remaining": [fid for fid in anchors if fid not in opened],
                        "source_frontier": frontier,
                        "source_linked_numeric_definitions": list(
                            numeric_definitions.values()),
                        "declaration_index_count": len(self.declarations),
                        "declaration_catalog": catalog_view,
                        "opened_declaration": (
                            {**declaration_view.summary(), "source": declaration_view.source}
                            if declaration_view is not None else None),
                        "opened_declarations": [item.summary() for item in opened_declarations],
                        "declaration_lookup_message": message_view,
                        **({"validation_feedback": feedback_view}
                           if feedback_view else {}),
                        "previous_reason": reason,
                    },
                    output_schema=ACTION_REQUEST_SCHEMA,
                    session_key=session,
                )
                reason = str(response.get("reason") or "").strip()
                verdict = str(response.get("decision") or "UNRESOLVED")
                requested = str(response.get("requested_function_id") or "").strip()
                selected = resolve_source_linked_function(
                    requested, opened, frontier, self.graph,
                )
                requested_declaration = str(
                    response.get("requested_declaration_name") or "").strip()
                if requested and not selected and not requested_declaration:
                    # Older model trajectories used the function request field
                    # for macro/type names. Resolve them through the same index.
                    requested_declaration = requested
                if response.get("list_declarations"):
                    query = str(response.get("declaration_name_filter") or "")
                    if ("list", query) in declaration_queries_seen:
                        reason = f"Declaration name query repeated without new evidence: {query!r}"
                        break
                    declaration_queries_seen.add(("list", query))
                    catalog_query = query
                    continue
                if requested_declaration:
                    if ("open", requested_declaration) in declaration_queries_seen:
                        reason = ("Declaration lookup repeated without new evidence: "
                                  + requested_declaration)
                        break
                    declaration_queries_seen.add(("open", requested_declaration))
                    matches = self.declarations.lookup(requested_declaration)
                    if len(matches) == 1:
                        definition = matches[0]
                        key = (definition.name, definition.file, definition.start_line)
                        if key in opened_declaration_keys:
                            lookup_message = (f"{requested_declaration} is already opened; "
                                              "use its source or request a different name")
                        else:
                            next_declaration = definition
                    elif matches:
                        lookup_message = (
                            f"{requested_declaration} is ambiguous; request "
                            "file:NAME or file:line:NAME. "
                            f"Candidates: {[item.summary() for item in matches]}")
                    else:
                        lookup_message = f"{requested_declaration} is absent from the source declaration index"
                    continue
                if any(fid not in opened for fid in anchors):
                    if selected and selected not in pending:
                        pending.append(selected)
                    continue
                if verdict == "READY":
                    declaration_ranges: dict[str, list[tuple[int, int]]] = {}
                    for definition in numeric_definitions.values():
                        if definition["ambiguous"]:
                            continue
                        file = str(definition["file"])
                        line = int(definition["line"])
                        declaration_ranges.setdefault(file, []).append((line, line))
                    for definition in opened_declarations:
                        declaration_ranges.setdefault(definition.file, []).append(
                            (definition.start_line, definition.end_line))
                    parsed_examples = _examples(
                        response.get("examples"), set(opened), self.graph,
                        source_declaration_ranges=declaration_ranges,
                    )
                    examples = [replace(item, origin="product_source")
                                for item in parsed_examples
                                if any(citation.line is not None
                                       and citation.function_id in opened
                                       for citation in item.evidence)]
                    if not examples and not response.get("examples"):
                        examples = [item for item in action.examples
                                    if any(citation.line is not None
                                           and citation.function_id in opened
                                           for citation in item.evidence)]
                    if examples and not requested:
                        fields = _fields(
                            response.get("fields"), set(opened), self.graph, examples,
                            source_declaration_ranges=declaration_ranges,
                        )
                        resolved = replace(
                            action, examples=examples,
                            fields=[*action.fields, *fields],
                            inspected_function_ids=unique_strings([
                                *action.inspected_function_ids, *opened,
                            ]),
                            unknowns=[item for item in action.unknowns
                                      if item != "complete external request lacks a source-located example"],
                        )
                        return resolved, ActionRequestDecision(
                            action.action_id, "READY", reason, opened,
                            example_count=len(examples),
                        )
                    if not response.get("examples") and not action.examples:
                        failure = "empty_examples"
                        reason = ("READY requires at least one complete request in "
                                  "examples[].data_hex; fields and reason are not request examples")
                    elif not parsed_examples and not action.examples:
                        failure = "invalid_examples"
                        reason = ("READY examples have no valid nonempty hex request in "
                                  "examples[].data_hex")
                    elif not examples:
                        failure = "uncited_examples"
                        reason = ("READY examples need a source-line citation from an "
                                  "opened function for request framing or payload")
                    else:
                        failure = "pending_source"
                        reason = "READY still requested another source"
                    if not selected and not pending and not requested_declaration:
                        source_state = (
                            tuple(opened),
                            tuple(sorted(opened_declaration_keys)),
                            failure,
                        )
                        if source_state in rejected_without_new_source:
                            reason += "; repeated after validation feedback with no new source"
                            break
                        rejected_without_new_source.add(source_state)
                        validation_feedback = (
                            reason + ". Re-submit a complete cited request in "
                            "examples[].data_hex, request the exact missing source, "
                            "or return UNRESOLVED with the missing fact. Do not "
                            "invent bytes from the field description."
                        )
                        continue
                elif verdict == "DROP":
                    citations = [item for item in _validated_evidence(
                        response.get("drop_evidence"), set(opened), self.graph,
                    ) if item.line is not None]
                    cited_ids = {item.function_id for item in citations}
                    if (reason and action.dispatcher_function_id in cited_ids
                        and action.handler_function_id in cited_ids):
                        resolved = replace(
                            action, status=ProofStatus.REFUTED,
                            evidence=[*action.evidence, *citations],
                            unknowns=unique_strings([
                                *action.unknowns,
                                "ACTION_DROPPED_BY_SOURCE: " + reason,
                            ]),
                        )
                        return resolved, ActionRequestDecision(
                            action.action_id, "DROP", reason, opened,
                        )
                    reason = "DROP lacked source-line evidence for selection and handler"
                elif verdict == "CONTINUE" and not selected and not pending:
                    failure = "continue_without_source"
                    source_state = (
                        tuple(opened), tuple(sorted(opened_declaration_keys)), failure,
                    )
                    if source_state in rejected_without_new_source:
                        reason = ("CONTINUE repeated without a resolvable source request "
                                  "or new evidence")
                        break
                    rejected_without_new_source.add(source_state)
                    validation_feedback = (
                        "CONTINUE needs requested_function_id set to the exact "
                        "indexed function ID or unique function name. If the "
                        "missing source is a macro or type, set "
                        "requested_declaration_name. If no source can resolve "
                        "the missing fact, return UNRESOLVED; do not invent bytes."
                    )
                    continue
                if selected and selected not in pending:
                    pending.append(selected)
                elif not pending:
                    break
        except Exception as exc:
            reason = f"Request analysis unavailable: {type(exc).__name__}: {exc}"
        finally:
            await close_llm_session(self.llm, session)
        reason = reason or "Complete external request remains unresolved"
        resolved = replace(
            action, examples=[],
            unknowns=unique_strings([*action.unknowns, "ACTION_INPUT_UNRESOLVED: " + reason]),
            inspected_function_ids=unique_strings([*action.inspected_function_ids, *opened]),
        )
        return resolved, ActionRequestDecision(
            action.action_id, "UNRESOLVED", reason, opened,
            requested_function_id=requested,
        )
