"""Source-backed triage between external acquisition and Action discovery.

This is a recall-preserving screen, not an Entry verdict or a reachability proof.
An incomplete screen remains an explicit obligation instead of becoming a
negative result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable

from ..analysis.graph import GraphStore, _code_only
from ..llm.base import LLMProvider, close_llm_session
from ..models import EntryRecord
from ..tracing import TraceCallback, emit_trace
from .common import concurrent_map, function_payload, function_ref, resolve_source_linked_function


ENTRY_ACTION_SCREEN_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["disposition", "path_function_ids", "evidence", "requested_function_ids", "rationale"],
    "properties": {
        "disposition": {"type": "string", "enum": ["SELECTED", "INCOMPLETE"]},
        "path_function_ids": {"type": "array", "items": {"type": "string"}},
        "evidence": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["function_id", "line", "source_text", "data_relation"],
            "properties": {
                "function_id": {"type": "string"},
                "line": {"type": "integer"},
                "source_text": {"type": "string"},
                "data_relation": {"type": "string"},
            },
        }},
        "requested_function_ids": {"type": "array", "maxItems": 1, "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
}


@dataclass(slots=True)
class EntryActionScreenResult:
    entry_id: str
    disposition: str
    path_function_ids: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    inspected_function_ids: list[str] = field(default_factory=list)
    pending_function_ids: list[str] = field(default_factory=list)
    rationale: str = ""


class EntryActionScreenAgent:
    """Find one source-supported input-to-processing route per Entry.

    A call edge is only a navigation lead. The model must identify actual
    input-bearing statements on a path before promotion. This stage deliberately
    does not enumerate operations, which remains InputActionAgent's job.
    """

    def __init__(
        self, llm: LLMProvider, graph: GraphStore, *,
        trace: TraceCallback | None = None,
        checkpoint: Callable[[list[EntryActionScreenResult]], None] | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.trace = trace
        self.checkpoint = checkpoint

    async def run(self, entries: list[EntryRecord]) -> list[EntryActionScreenResult]:
        completed: dict[str, EntryActionScreenResult] = {}

        async def screened(entry: EntryRecord) -> EntryActionScreenResult:
            try:
                result = await self._run_entry(entry)
            except Exception as exc:
                # Screening only supplies a navigation hint. A malformed
                # response or provider failure cannot veto a source-located
                # Entry before the independent Action reconstruction pass.
                rationale = f"Screening failed ({type(exc).__name__}: {exc})"
                emit_trace(self.trace, "entry_action_screen", "incomplete", rationale,
                           entry_id=entry.entry_id)
                result = EntryActionScreenResult(
                    entry.entry_id, "INCOMPLETE", rationale=rationale,
                )
            completed[entry.entry_id] = result
            if self.checkpoint:
                self.checkpoint([completed[item.entry_id] for item in entries
                                 if item.entry_id in completed])
            return result

        return await concurrent_map(
            entries, screened,
            max(1, int(getattr(self.llm, "max_concurrency", 1))),
        )

    def _supported_evidence(self, raw: Any, opened: list[str]) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        result: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            function_id, line, source_text = (
                item.get("function_id"), item.get("line"), item.get("source_text")
            )
            if function_id not in opened or not isinstance(line, int) or not isinstance(source_text, str):
                continue
            function = self.graph.get(function_id)
            lines = function.source.splitlines()
            offset = line - function.start_line
            if offset < 0 or offset >= len(lines) or not source_text.strip():
                continue
            quoted_lines = source_text.strip().splitlines()
            if offset + len(quoted_lines) > len(lines):
                continue
            originals = lines[offset:offset + len(quoted_lines)]
            code_quote_found = False
            quote_valid = True
            for quoted, original in zip(quoted_lines, originals):
                fragment = quoted.strip()
                position = original.find(fragment)
                if position < 0:
                    quote_valid = False
                    break
                if _code_only(original)[position:position + len(fragment)].strip():
                    code_quote_found = True
            if not quote_valid or not code_quote_found:
                continue
            result.append({
                "function_id": function_id, "line": line,
                "source_text": source_text, "data_relation": str(item.get("data_relation", "")),
            })
        return result

    def _supported_path(
        self, raw: Any, entry_id: str, opened: list[str],
        evidence: list[dict[str, Any]],
    ) -> list[str]:
        if not isinstance(raw, list) or not raw or raw[0] != entry_id:
            return []
        if any(item not in opened for item in raw):
            return []
        # An acquisition helper can return bytes or fill a caller-owned
        # output buffer (for example tcp_read). Both caller and callee edges
        # are navigation leads; source evidence must still explain the value
        # handoff, and original execution later confirms the route.
        for before, after in zip(raw, raw[1:]):
            neighbours = {
                item.function_id for item in
                [*self.graph.callees(before), *self.graph.callers(before)]
            }
            if after != before and after not in neighbours and not self._callback_link(
                before, after, evidence
            ):
                return []
        return list(raw)

    def _callback_link(
        self, before: str, after: str, evidence: list[dict[str, Any]],
    ) -> bool:
        """Accept a source-quoted callback assignment and matching invocation as a lead.

        This only links the navigation path. It does not establish that the
        callback ran in the original program or that two objects are identical.
        """
        for callee_id, caller_id in ((before, after), (after, before)):
            callee_name = self.graph.get(callee_id).name
            if not re.fullmatch(r"[A-Za-z_]\w*", callee_name):
                continue
            assignment = re.compile(
                r"(?:->|\.)\s*([A-Za-z_]\w*)\s*=\s*&?\s*"
                + re.escape(callee_name) + r"\b"
            )
            slots = {
                match.group(1)
                for item in evidence
                for match in assignment.finditer(item["source_text"])
            }
            if any(
                item["function_id"] == caller_id
                and re.search(r"(?:->|\.)\s*" + re.escape(slot) + r"\s*\(",
                              item["source_text"])
                for item in evidence for slot in slots
            ):
                return True
        return False

    async def _run_entry(self, entry: EntryRecord) -> EntryActionScreenResult:
        root = entry.entry_function_id
        if root not in self.graph.bundle.functions:
            return EntryActionScreenResult(entry.entry_id, "INCOMPLETE", rationale="Entry source body unavailable")
        opened: list[str] = []
        pending = [root]
        unavailable_request = ""
        session = f"entry_action_screen:{entry.entry_id}"
        rationale = "No source-supported input-to-processing route established"
        try:
            # The only bound is the finite set of indexed source functions.
            # A stopped walk is never interpreted as evidence of no Action.
            while pending:
                current_id = pending.pop(0)
                if current_id in opened:
                    continue
                opened.append(current_id)
                current = self.graph.get(current_id)
                frontier = self.graph.frontier([current_id])
                response = await self.llm.complete_json(
                    role="entry_action_screen",
                    instructions=(
                        "Decide whether externally acquired bytes/values at this Entry can reach "
                        "a distinct input-dependent operation (parse, dispatch, query, update, "
                        "delete, or other substantive handling). Follow the value, not merely "
                        "calls, control-flow branches, initialization, or function names. "
                        "An acquisition helper may return bytes or fill its caller's "
                        "buffer: inspect callers as well as callees and cite the "
                        "source statement that hands the value onward. "
                        "Open one source function when needed. Report SELECTED only after the "
                        "opened source shows the acquisition and a connected input-bearing "
                        "operation. Quote exact code text and line numbers for each path hop. "
                        "A call graph edge alone is insufficient. Stop after the first supported "
                        "operation; Action enumeration happens later. If evidence is missing, "
                        "report INCOMPLETE and the next function to inspect, or explain why "
                        "none can be identified. Never infer that no Action exists from a "
                        "missing function, analysis limit, or source gap."
                    ),
                    payload={
                        "entry": {
                            "entry_id": entry.entry_id,
                            "entry_function_id": root,
                            "entry_line": entry.entry_line,
                            "source_api": entry.source_api,
                            "channel_kind": entry.channel_kind,
                            "consumer_hints": entry.consumer_hints,
                            "verifier_status": entry.status.value,
                        },
                        "current_function": function_payload(current),
                        "opened_functions": [function_ref(self.graph.get(item)) for item in opened],
                        "frontier": frontier,
                        "navigation_policy": "function links are leads, not data-flow proof",
                    },
                    output_schema=ENTRY_ACTION_SCREEN_SCHEMA,
                    session_key=session,
                )
                rationale = str(response.get("rationale") or rationale)
                evidence = self._supported_evidence(response.get("evidence"), opened)
                path = self._supported_path(
                    response.get("path_function_ids"), root, opened, evidence
                )
                if (
                    response.get("disposition") == "SELECTED"
                    and path and evidence
                    and any(
                        item["function_id"] == root
                        and (
                            entry.entry_line is None
                            or item["line"] <= entry.entry_line
                            < item["line"] + len(item["source_text"].splitlines())
                        )
                        for item in evidence
                    )
                    and {item["function_id"] for item in evidence} >= set(path)
                ):
                    emit_trace(self.trace, "entry_action_screen", "selected", entry.entry_id,
                               entry_id=entry.entry_id, path=path)
                    return EntryActionScreenResult(
                        entry.entry_id, "SELECTED", path, evidence, opened, [], rationale
                    )
                requests = response.get("requested_function_ids") or []
                requested = requests[0] if isinstance(requests, list) and requests else ""
                next_id = resolve_source_linked_function(requested, opened, frontier, self.graph)
                if next_id:
                    pending.append(next_id)
                else:
                    if response.get("disposition") == "SELECTED":
                        rationale = "Claimed input route lacks source-linked evidence: " + rationale
                    elif requested:
                        rationale = "Requested function is unavailable or already inspected: " + rationale
                    if requested and requested not in opened:
                        unavailable_request = requested
                    break
        finally:
            await close_llm_session(self.llm, session)
        emit_trace(self.trace, "entry_action_screen", "incomplete", rationale,
                   entry_id=entry.entry_id, inspected=len(opened))
        return EntryActionScreenResult(
            entry.entry_id, "INCOMPLETE", inspected_function_ids=opened,
            pending_function_ids=[*pending, *([unavailable_request] if unavailable_request else [])],
            rationale=rationale,
        )
