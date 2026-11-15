"""Recover source-located input-to-effect paths without assuming commands.

The unit of work is an external acquisition and an observed downstream effect.
It is *not* a switch branch, an Action, or an arbitrarily sized function group.
All model inferences remain hypotheses until source and runtime evidence agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session, is_terminal_llm_infrastructure_error
from ..models import EntryRecord, Evidence, ProofStatus, stable_id, unique_strings
from ..tracing import TraceCallback, emit_trace
from .common import (
    function_payload, function_ref, object_list, string_list,
    resolve_source_linked_function,
)


@dataclass(slots=True)
class BehaviorCandidate:
    """Potential effect of externally supplied bytes; never a runtime witness."""

    behavior_id: str
    entry_id: str
    entry_function_id: str
    target_function_id: str
    kind: str
    summary: str
    path_function_ids: list[str]
    evidence: list[Evidence] = field(default_factory=list)
    inspected_function_ids: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    status: ProofStatus = ProofStatus.POSSIBLE
    # Structural identity is separate from prose and citation locations.
    input_flow: str = ""
    effect: str = ""
    prior_state: str = ""
    execution_mode: str = ""
    path_variants: list[list[str]] = field(default_factory=list)


BEHAVIOR_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["behaviors", "requested_function_ids", "context_complete", "rationale"],
    "properties": {
        "behaviors": {
            "type": "array", "maxItems": 16,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["target_function_id", "kind", "summary", "input_flow",
                             "effect", "prior_state", "execution_mode",
                             "path_function_ids", "evidence"],
                "properties": {
                    "target_function_id": {"type": "string"},
                    "kind": {"type": "string", "enum": [
                        "parsing", "state_change", "computation", "output",
                        "persistent_storage", "unknown",
                    ]},
                    "summary": {"type": "string"},
                    "input_flow": {"type": "string"},
                    "effect": {"type": "string"},
                    "prior_state": {"type": "string"},
                    "execution_mode": {"type": "string"},
                    "path_function_ids": {"type": "array", "items": {"type": "string"}},
                    "evidence": {
                        "type": "array", "items": {
                            "type": "object", "additionalProperties": False,
                            "required": ["function_id", "line", "detail"],
                            "properties": {
                                "function_id": {"type": "string"},
                                "line": {"type": "integer"},
                                "detail": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "requested_function_ids": {"type": "array", "maxItems": 1, "items": {"type": "string"}},
        "context_complete": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
}


class BehaviorRecoveryAgent:
    """Track input-derived behavior by opening one complete source function/turn.

    A work budget bounds runtime cost, not the size of a reachable call graph.
    Missing evidence is recorded instead of converting hypotheses to negatives.
    """

    def __init__(
        self, llm: LLMProvider, graph: GraphStore, *,
        max_function_turns: int | None = None, trace: TraceCallback | None = None,
        checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
        initial_state: dict[str, Any] | None = None,
        runtime_navigation_hints: dict[str, list[str]] | None = None,
    ):
        self.llm = llm
        self.graph = graph
        # An implicit arbitrary graph-depth/width cap loses effects in large
        # C programs. An explicit caller budget is a resource limit, not a
        # semantic stop condition. By default allow every indexed function.
        self.max_function_turns = (
            max(1, max_function_turns) if max_function_turns is not None
            else max(1, len(graph.bundle.functions))
        )
        self.trace = trace
        self.checkpoint = checkpoint
        self.initial_state = initial_state or {}
        self.runtime_navigation_hints = runtime_navigation_hints or {}
        self.obligations: list[str] = []

    async def run(self, entries: list[EntryRecord]) -> list[BehaviorCandidate]:
        self.obligations = []
        results: list[BehaviorCandidate] = []
        for entry in entries:
            if entry.entry_function_id not in self.graph.bundle.functions:
                self.obligations.append(f"{entry.entry_id}: Entry source unavailable")
                continue
            session = f"behavior_recovery:{entry.entry_id}"
            opened: list[str] = list(self.initial_state.get("opened_function_ids", []))
            pending = self.initial_state.get("pending_function_id", entry.entry_function_id)
            navigation_queue = list(self.initial_state.get(
                "navigation_queue", self.runtime_navigation_hints.get(entry.entry_id, []),
            ))
            navigation_queue = [fid for fid in unique_strings(navigation_queue)
                                if fid not in opened and fid != pending]
            requested_queue = list(self.initial_state.get("requested_queue", []))
            raw_behaviors: list[dict[str, Any]] = list(self.initial_state.get("raw_behaviors", []))
            complete = bool(self.initial_state.get("complete", False))
            try:
                for _ in range(max(0, self.max_function_turns - len(opened))):
                    if not pending or pending in opened:
                        break
                    fn = self.graph.get(pending)
                    opened.append(pending)
                    choices = self._choices(opened, entry)
                    response = await self.llm.complete_json(
                        role="behavior_recovery",
                        session_key=session,
                        output_schema=BEHAVIOR_SCHEMA,
                        instructions=(
                            "Discover distinct external-input-to-processing/effect paths. "
                            "There need not be any command, switch, parser, callback, or state machine. "
                            "Do not treat ordinary control-flow branches as external commands. "
                            "Trace the actual input object and how its bytes reach code with a "
                            "meaningful effect. Do not group unrelated effects merely because they "
                            "share an initializer, worker, or entry function. "
                            "Open one additional relevant full function if the source is insufficient. "
                            "Use only exact IDs in available_function_ids or a unique "
                            "target of a located call/function reference, or a function "
                            "named by a Clang-confirmed referenced initializer. A name "
                            "inside a comment or string is not a link. If Clang source "
                            "analysis is unavailable, a code-only call spelling is a "
                            "question to inspect, never a proven call. Cite actual source lines. "
                            "Report unknown paths rather than fabricating edges, states or input bytes. "
                            "Every proposed behavior is only POSSIBLE until independently tested."
                            " For each behavior identify the input data flow, one concrete effect, "
                            "prior state and execution mode in structured fields. Use short stable "
                            "labels for these four fields, not explanatory sentences; put explanations "
                            "in summary and evidence. Reuse the same labels for a truly identical "
                            "flow/effect/state/mode across alternate paths; never combine distinct effects."
                            " Use 'none' for prior state only if source shows no prerequisite; "
                            "otherwise use 'unknown'. Name the execution mode or use 'unknown'. "
                            "Runtime navigation hints are temporal debugger observations, not "
                            "proof that this input reached a hinted function. Inspect their source "
                            "for a downstream effect; preserve unresolved flow edges. "
                            "Buffer copying, length counters and transport statistics are data-flow "
                            "steps unless they are themselves the intended externally testable effect."
                        ),
                        payload={
                            "entry": {
                                "entry_id": entry.entry_id,
                                "source_api": entry.source_api,
                                "channel_kind": entry.channel_kind,
                                "entry_line": entry.entry_line,
                                "provenance_path": entry.provenance_path,
                                "consumer_hints": entry.consumer_hints,
                            },
                            "current_function": function_payload(
                                fn, source_limit=max(1, len(fn.source) + 1),
                            ),
                            "opened_function_ids": opened,
                            "available_function_ids": choices,
                            "runtime_navigation_hints": self.runtime_navigation_hints.get(
                                entry.entry_id, []
                            ),
                        },
                    )
                    raw_behaviors.extend(object_list(response.get("behaviors")))
                    complete = response.get("context_complete") is True
                    if len(object_list(response.get("behaviors"))) >= 16:
                        # The provider returned the schema maximum. Treat
                        # the inventory as possibly truncated; never infer
                        # that the remaining effects do not exist.
                        complete = False
                        self.obligations.append(
                            f"{entry.entry_id}: per-turn behavior inventory saturated at 16"
                        )
                    requested = string_list(response.get("requested_function_ids"))
                    requested_id = resolve_source_linked_function(
                        requested[0] if requested else "", opened, choices, self.graph,
                    )
                    if requested_id and requested_id not in requested_queue:
                        requested_queue.append(requested_id)
                    while navigation_queue and navigation_queue[0] in opened:
                        navigation_queue.pop(0)
                    pending = (navigation_queue.pop(0) if navigation_queue else
                               requested_queue.pop(0) if requested_queue and not complete else "")
                    if pending in requested_queue:
                        requested_queue.remove(pending)
                    if self.checkpoint:
                        self.checkpoint(entry.entry_id, {
                            "opened_function_ids": list(opened),
                            "pending_function_id": pending or "",
                            "raw_behaviors": raw_behaviors,
                            "complete": bool(complete and not pending),
                            "navigation_queue": list(navigation_queue),
                            "requested_queue": list(requested_queue),
                        })
                    if not pending:
                        if not complete:
                            self.obligations.append(
                                f"{entry.entry_id}: required function not navigable from inspected evidence"
                            )
                        break
            except Exception as exc:
                if is_terminal_llm_infrastructure_error(exc):
                    raise
                self.obligations.append(
                    f"{entry.entry_id}: behavior model failed: {type(exc).__name__}: {exc}"
                )
            finally:
                await close_llm_session(self.llm, session)

            entry_results = self.materialize(entry, opened, raw_behaviors, complete)
            results.extend(entry_results)
            emit_trace(
                self.trace, "behavior_recovery", "entry_complete",
                f"{entry.entry_id}: {len(entry_results)} behavior hypotheses",
                entry_id=entry.entry_id, opened_function_ids=opened,
                complete=complete,
            )
        return results

    def materialize(
        self, entry: EntryRecord, opened: list[str],
        raw_behaviors: list[dict[str, Any]], complete: bool,
    ) -> list[BehaviorCandidate]:
        per_entry: dict[tuple[str, str, str], BehaviorCandidate] = {}
        for raw_index, raw in enumerate(raw_behaviors):
            target = str(raw.get("target_function_id", ""))
            if target not in opened:
                self.obligations.append(
                    f"{entry.entry_id}: target {target} was not opened in the behavior session"
                )
                continue
            kind = str(raw.get("kind", "unknown"))
            if kind not in {
                "parsing", "state_change", "computation", "output", "persistent_storage", "unknown"
            }:
                kind = "unknown"
            path = unique_strings(string_list(raw.get("path_function_ids")))
            unknowns = []
            if not path or path[0] != entry.entry_function_id or path[-1] != target:
                unknowns.append("no complete Entry-to-effect function path")
            if any(identifier not in opened for identifier in path):
                unknowns.append("path references unopened source")
            for caller_id, callee_id in zip(path, path[1:]):
                if (caller_id not in opened or callee_id not in opened):
                    continue
                caller = self.graph.get(caller_id)
                callee = self.graph.get(callee_id)
                # A direct call graph edge or source-level mention is a
                # navigation witness, not dataflow or runtime proof.
                if not (
                    (caller_id, callee_id) in self.graph._edges_by_pair
                    or re.search(rf"\b{re.escape(callee.name)}\b", caller.source)
                ):
                    unknowns.append(
                        f"path step not linked by opened source: {caller_id} -> {callee_id}"
                    )
            evidence: list[Evidence] = []
            for item in object_list(raw.get("evidence")):
                fid = str(item.get("function_id", ""))
                if fid not in opened:
                    unknowns.append(f"unopened evidence function: {fid}")
                    continue
                fn = self.graph.get(fid)
                try:
                    line = int(item.get("line", -1))
                except (ValueError, TypeError):
                    line = -1
                if line < fn.start_line or line > fn.end_line:
                    unknowns.append(f"evidence line is not in function {fid}: {line}")
                    continue
                evidence.append(Evidence(
                    kind="source", function_id=fid, file=fn.file,
                    line=line, detail=str(item.get("detail", "")),
                ))
            if not evidence:
                unknowns.append("no valid source line evidence for the effect")
            if not complete:
                unknowns.append("function context exploration incomplete")
            structure = tuple(
                re.sub(r"\s+", " ", str(raw.get(field_name, "")).strip().casefold())
                for field_name in ("input_flow", "effect", "prior_state", "execution_mode")
            )
            identified = all(
                value and not value.startswith(("unknown", "unresolved"))
                for value in structure
            )
            # Free-text summary and citation lines are evidence, not the
            # identity of an effect. Unknown structural fields cannot justify
            # merging two apparently similar effects.
            fingerprint = repr(structure if identified else ("unresolved", raw_index))
            key = (target, kind, fingerprint)
            prior = per_entry.get(key)
            if prior is not None:
                previous_variant_complete = not prior.unknowns
                current_variant_complete = not unknowns
                seen = {(item.function_id, item.file, item.line, item.detail)
                        for item in prior.evidence}
                prior.evidence.extend(item for item in evidence
                                      if (item.function_id, item.file, item.line, item.detail)
                                      not in seen)
                if path not in prior.path_variants:
                    prior.path_variants.append(path)
                # These proposals are alternative paths for the same effect.
                # An invalid earlier citation cannot veto a later complete
                # path; retain its diagnostics only when no complete variant
                # has been observed.
                if current_variant_complete and not previous_variant_complete:
                    prior.path_function_ids = path
                prior.unknowns = (
                    [] if previous_variant_complete or current_variant_complete
                    else unique_strings([*prior.unknowns, *unknowns])
                )
                prior.inspected_function_ids = unique_strings([
                    *prior.inspected_function_ids, *opened,
                ])
                continue
            per_entry[key] = BehaviorCandidate(
                behavior_id=stable_id("behavior", entry.entry_id, target, kind, fingerprint),
                entry_id=entry.entry_id,
                entry_function_id=entry.entry_function_id,
                target_function_id=target, kind=kind,
                summary=str(raw.get("summary", "")),
                path_function_ids=path,
                path_variants=[path],
                inspected_function_ids=list(opened),
                evidence=evidence, unknowns=unique_strings(unknowns),
                input_flow=str(raw.get("input_flow", "")),
                effect=str(raw.get("effect", "")),
                prior_state=str(raw.get("prior_state", "")),
                execution_mode=str(raw.get("execution_mode", "")),
            )
        if not per_entry:
            # A source-located acquisition remains a candidate even if
            # every semantic hypothesis failed. Never invent a parser.
            per_entry[(entry.entry_function_id, "unknown", "unclassified")] = BehaviorCandidate(
                behavior_id=stable_id("behavior", entry.entry_id, "unclassified"),
                entry_id=entry.entry_id,
                entry_function_id=entry.entry_function_id,
                target_function_id=entry.entry_function_id,
                kind="unknown",
                summary="external acquisition with no independently established processing effect",
                path_function_ids=[entry.entry_function_id],
                inspected_function_ids=list(opened),
                evidence=[e for e in entry.evidence if e.function_id == entry.entry_function_id],
                unknowns=["processing effect not yet located"],
            )
        return list(per_entry.values())

    def _choices(self, opened: list[str], entry: EntryRecord) -> list[dict[str, object]]:
        result = {str(item["function_id"]): item for item in self.graph.frontier(opened)}
        for identifier in unique_strings([
            *entry.inspected_function_ids, *entry.consumer_hints,
        ]):
            if identifier in opened or identifier not in self.graph.bundle.functions:
                continue
            result.setdefault(identifier, {
                **function_ref(self.graph.get(identifier)),
                "connections": [{"relation": "Entry-evidence-navigation-only"}],
            })
        for identifier in self.runtime_navigation_hints.get(entry.entry_id, []):
            if identifier in opened or identifier not in self.graph.bundle.functions:
                continue
            result.setdefault(identifier, {
                **function_ref(self.graph.get(identifier)),
                "connections": [{"relation": "temporal-runtime-navigation-only"}],
            })
        return list(result.values())
