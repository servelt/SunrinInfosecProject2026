"""Evidence-linked request repair after a source-classified original rejection.

The previous request and response are failure feedback. Corrected bytes must
cite opened source, and no repair result is promoted to PROVEN_STATIC.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import ActionExample, Evidence, ExternalActionSchema, ScenarioWitness, unique_strings
from .common import (
    function_payload, function_ref, object_list, resolve_source_linked_function,
    string_list,
)
from .scenario import _materialize_action


REQUEST_REFINEMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["requests", "requested_function_ids", "context_complete", "rationale"],
    "properties": {
        "requests": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["data_hex", "rationale", "evidence"],
                "properties": {
                    "data_hex": {
                        "type": "string", "pattern": "^[0-9a-fA-F]*$",
                    },
                    "rationale": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["function_id", "line", "detail"],
                            "properties": {
                                "function_id": {"type": "string"},
                                "line": {"type": "integer", "minimum": 1},
                                "detail": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "requested_function_ids": {
            "type": "array", "maxItems": 1, "items": {"type": "string"},
        },
        "context_complete": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
}


class ScenarioRequestRefiner:
    """Inspect one source body per turn before proposing a request repair."""

    def __init__(self, llm: LLMProvider, graph: GraphStore, *, max_bytes: int = 0):
        if max_bytes < 0:
            raise ValueError("request repair byte limit cannot be negative")
        self.llm = llm
        self.graph = graph
        self.max_bytes = max_bytes
        self.unresolved_reasons: list[str] = []

    async def repair(
        self,
        action: ExternalActionSchema,
        witness: ScenarioWitness,
    ) -> list[ActionExample]:
        if not witness.observations or witness.target_action_id != action.action_id:
            return []
        observation = witness.observations[-1]
        if observation.response_success or not observation.response_hex:
            return []
        # A missing success marker is not evidence that the server rejected
        # the request. Only a source-backed failure oracle observed by the
        # original runner justifies spending a syntax-repair turn.
        if (not any(item.line is not None for item in action.failure_evidence)
            or not action.failure_markers_hex
            or not observation.detail.startswith("matched failure marker ")):
            self.unresolved_reasons.append(
                f"{witness.scenario_id}: response was not classified by a "
                "source-backed failure marker; request syntax is unresolved"
            )
            return []
        function_ids = unique_strings([
            action.entry_function_id,
            action.dispatcher_function_id,
            action.handler_function_id,
            *action.inspected_function_ids,
        ])
        available = [
            identifier for identifier in function_ids
            if identifier in self.graph.bundle.functions
        ]
        if not available:
            self.unresolved_reasons.append(
                f"{witness.scenario_id}: no indexed source body for request repair"
            )
            return []
        # The failure may be detected by a parser before the handler. Open
        # the known dispatch body first; the model chooses further source
        # questions from the already evidenced action path or graph frontier.
        pending = (action.dispatcher_function_id
                   if action.dispatcher_function_id in available else available[0])
        opened: list[str] = []
        proposals: list[dict[str, Any]] = []
        session_key = f"scenario_refiner:{witness.scenario_id}"
        try:
            while pending and pending not in opened:
                current = self.graph.get(pending)
                opened.append(pending)
                choices = {
                    str(item["function_id"]): item
                    for item in self.graph.frontier(opened)
                    if str(item["function_id"]) not in opened
                }
                for identifier in available:
                    if identifier not in opened:
                        choices.setdefault(identifier, {
                            **function_ref(self.graph.get(identifier)),
                            "connections": [{"relation": "inspected_action_source_candidate"}],
                        })
                response = await self.llm.complete_json(
                    role="scenario_refiner",
                    instructions=(
                        "The original request produced a failure observation. "
                        "Inspect the supplied source body, then request at most "
                        "one next relevant function body. A source-linked function "
                        "may be in available_functions or may be a unique indexed "
                        "symbol named in already opened source. Do not assume the "
                        "failure is syntax: missing state, authorization, transport "
                        "or process setup may also explain it. Propose corrected "
                        "complete external bytes only when opened parser or request "
                        "constructor lines support them. Cite exact source lines. "
                        "On each turn, return the complete replacement list of "
                        "still-supported request hypotheses; remove any earlier "
                        "guess refuted by the newly opened source. "
                        "Do not repeat previously rejected bytes or infer success "
                        "from a response substring. If a required source body remains "
                        "unopened, request it and set context_complete=false. "
                        "If source cannot distinguish the cause, return no requests "
                        "and explain the unresolved question. A repair is a trial "
                        "hypothesis, never static or runtime proof."
                    ),
                    payload={
                        "action_id": action.action_id,
                        "action_description": action.description,
                        "source_discriminator": action.discriminator,
                        "field_constraints": [
                            {"name": item.name, "offset": item.offset,
                             "width": item.width, "encoding": item.encoding,
                             "binding": item.binding, "relation": item.relation}
                            for item in action.fields
                        ],
                        "original_request_hex": observation.request_hex,
                        "original_response_hex": observation.response_hex,
                        "failure_detail": observation.detail,
                        "current_function": function_payload(
                            current, source_limit=max(1, len(current.source) + 1),
                        ),
                        "opened_functions": [
                            function_ref(self.graph.get(identifier))
                            for identifier in opened
                        ],
                        "available_functions": list(choices.values()),
                    },
                    output_schema=REQUEST_REFINEMENT_SCHEMA,
                    session_key=session_key,
                )
                # A later source body may refute an earlier guess. Treat each
                # turn as a complete replacement, not an accumulating union.
                proposals = object_list(response.get("requests"))
                requested = string_list(response.get("requested_function_ids"))
                if requested:
                    pending = resolve_source_linked_function(
                        requested[0], opened, list(choices.values()), self.graph,
                    )
                    if not pending:
                        self.unresolved_reasons.append(
                            f"{witness.scenario_id}: requested source "
                            f"{requested[0]!r} was unavailable or not linked"
                        )
                        break
                    continue
                if response.get("context_complete") is False:
                    self.unresolved_reasons.append(
                        f"{witness.scenario_id}: request repair context incomplete: "
                        + str(response.get("rationale", "no next source supplied"))
                    )
                    proposals = []
                break
        finally:
            await close_llm_session(self.llm, session_key)
        allowed = {identifier: self.graph.get(identifier) for identifier in opened}
        result: list[ActionExample] = []
        rejected = {item.request_hex for item in witness.steps}
        rejected.update(item.data_hex for item in action.examples)
        for raw in proposals:
            candidate_hex = str(raw.get("data_hex", "")).lower()
            try:
                data = bytes.fromhex(candidate_hex)
            except ValueError:
                continue
            if (not data or (self.max_bytes and len(data) > self.max_bytes)
                or candidate_hex in rejected):
                continue
            evidence: list[Evidence] = []
            for item in object_list(raw.get("evidence")):
                function_id = str(item.get("function_id", ""))
                function = allowed.get(function_id)
                line = item.get("line")
                if (
                    function is None
                    or not isinstance(line, int)
                    or not (function.start_line <= line <= function.end_line)
                ):
                    continue
                evidence.append(Evidence(
                    kind="source", function_id=function_id, file=function.file,
                    line=line, detail=str(item.get("detail", "")),
                ))
            if not evidence:
                continue
            example = ActionExample(
                data_hex=candidate_hex,
                bindings={},
                rationale=str(raw.get("rationale", "")),
                origin="runtime_feedback_source_candidate",
                evidence=evidence,
            )
            # Reuse field-range and binding consistency checks. A malformed
            # request must not alter the action contract or become a retry.
            if not _materialize_action(replace(action, examples=[example]), 0, {}):
                continue
            result.append(example)
            rejected.add(candidate_hex)
        return result
