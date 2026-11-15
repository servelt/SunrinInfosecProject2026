"""Recover lifecycle requirements for input-derived behavior, not Actions.

State is modeled as an evidenced prerequisite of a processing effect.
An absent prerequisite is valid; a missing prerequisite is an obligation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
import re

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session, is_terminal_llm_infrastructure_error
from ..models import Evidence, stable_id, unique_strings
from ..tracing import TraceCallback, emit_trace
from .behavior import BehaviorCandidate
from .common import (
    function_payload, function_ref, object_list, string_list,
    resolve_source_linked_function,
)


@dataclass(slots=True)
class LifecycleCall:
    category: str
    function_id: str
    callsite_function_id: str
    callsite_line: int
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class ExecutionContract:
    contract_id: str
    behavior_id: str
    entry_function_id: str
    target_function_id: str
    transport: str
    input_binding: str
    calls: list[LifecycleCall]
    prerequisite_bytes_hex: list[str]
    isolation: str
    result_condition: str
    inspected_function_ids: list[str]
    evidence_complete: bool
    unknowns: list[str] = field(default_factory=list)
    repeatability_evidence: list[Evidence] = field(default_factory=list)


EXECUTION_CONTRACT_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": [
        "input_binding", "calls", "prerequisite_bytes_hex", "isolation",
        "result_condition", "requested_function_ids", "context_complete", "unknowns", "rationale",
        "repeatability_evidence",
    ],
    "properties": {
        "input_binding": {"type": "string"},
        "calls": {
            "type": "array", "maxItems": 32,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["category", "function_id", "callsite_function_id", "callsite_line", "rationale"],
                "properties": {
                    "category": {"type": "string", "enum": [
                        "initialization", "prerequisite", "co_call",
                        "lifecycle", "result_check", "cleanup",
                    ]},
                    "function_id": {"type": "string"},
                    "callsite_function_id": {"type": "string"},
                    "callsite_line": {"type": "integer"},
                    "rationale": {"type": "string"},
                },
            },
        },
        "prerequisite_bytes_hex": {
            "type": "array", "maxItems": 12,
            "items": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
        },
        "isolation": {"type": "string", "enum": [
            "in_process_reset", "process_isolation_required", "unknown",
        ]},
        "result_condition": {"type": "string"},
        "repeatability_evidence": {
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
        "requested_function_ids": {"type": "array", "maxItems": 1, "items": {"type": "string"}},
        "context_complete": {"type": "boolean"},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
}


class ExecutionContractAgent:
    """Examine setup, co-calls, return values, cleanup and reset per behavior."""

    def __init__(
        self, llm: LLMProvider, graph: GraphStore, *,
        max_function_turns: int | None = None, trace: TraceCallback | None = None,
        checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
        initial_state: dict[str, Any] | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.max_function_turns = (
            max(1, max_function_turns) if max_function_turns is not None
            else max(1, len(graph.bundle.functions))
        )
        self.trace = trace
        self.checkpoint = checkpoint
        self.initial_state = initial_state or {}
        self.obligations: list[str] = []

    async def run(self, behaviors: list[BehaviorCandidate], channels: dict[str, str]) -> list[ExecutionContract]:
        self.obligations = []
        contracts: list[ExecutionContract] = []
        for behavior in behaviors:
            session = f"execution_contract:{behavior.behavior_id}"
            saved = self.initial_state if self.initial_state.get("behavior_id") == behavior.behavior_id else {}
            opened: list[str] = list(saved.get("opened_function_ids", []))
            requirements = unique_strings([
                behavior.entry_function_id,
                *behavior.path_function_ids,
                *(fid for path in behavior.path_variants for fid in path),
                behavior.target_function_id,
            ])
            queued = list(saved.get("queued_function_ids", requirements))
            complete = bool(saved.get("complete", False))
            response: dict[str, Any] = {}
            accumulated: dict[str, Any] = {
                "calls": [], "prerequisite_bytes_hex": [],
                "repeatability_evidence": [], "unknowns": [],
            }
            accumulated.update(saved.get("accumulated", {}))
            errors: list[str] = list(saved.get("errors", []))
            try:
                for _ in range(max(0, self.max_function_turns - len(opened))):
                    if not queued:
                        break
                    function_id = queued.pop(0)
                    if function_id in opened:
                        continue
                    if function_id not in self.graph.bundle.functions:
                        errors.append(f"required function not indexed: {function_id}")
                        continue
                    fn = self.graph.get(function_id)
                    opened.append(function_id)
                    choices = self._choices(opened, requirements)
                    response = await self.llm.complete_json(
                        role="execution_contract",
                        session_key=session,
                        output_schema=EXECUTION_CONTRACT_SCHEMA,
                        instructions=(
                            "For this input-derived effect, recover only the source-required startup, "
                            "function call order, required earlier external bytes, return-value handling, "
                            "cleanup and per-input reset. These categories are OPTIONAL. Never invent "
                            "setup, a session, a state machine or an Action if source does not require one. "
                            "A code-level dependency means a prerequisite only when the specific "
                            "value/state produced is used by the target. Source citation lines must be "
                            "real call sites, not guessed from function names. Previous external bytes "
                            "are hypotheses until sent to the original program. "
                            "Do not conclude in-process reset from an absence of explicit globals. "
                            "Cite exact inspected source lines establishing per-input reset or "
                            "stateless repeatability; absence of a global in one file is insufficient. "
                            "If evidence is incomplete request one linked whole function and report unknowns."
                        ),
                        payload={
                            "behavior": {
                                "behavior_id": behavior.behavior_id,
                                "entry_function_id": behavior.entry_function_id,
                                "target_function_id": behavior.target_function_id,
                                "kind": behavior.kind,
                                "path_function_ids": behavior.path_function_ids,
                                "path_variants": behavior.path_variants,
                                "evidence": [
                                    {"function_id": e.function_id, "line": e.line, "detail": e.detail}
                                    for e in behavior.evidence
                                ],
                                "unknowns": behavior.unknowns,
                            },
                            "current_function": function_payload(
                                fn, source_limit=max(1, len(fn.source) + 1),
                            ),
                            "opened_function_ids": opened,
                            "required_function_ids": requirements,
                            "available_function_ids": choices,
                        },
                    )
                    for field_name in (
                        "calls", "prerequisite_bytes_hex", "repeatability_evidence", "unknowns"
                    ):
                        for value in response.get(field_name, []):
                            if value not in accumulated[field_name]:
                                accumulated[field_name].append(value)
                    for field_name in ("input_binding", "isolation", "result_condition"):
                        value = response.get(field_name)
                        if value and value != "unknown":
                            accumulated[field_name] = value
                    complete = response.get("context_complete") is True
                    requested = string_list(response.get("requested_function_ids"))
                    if requested and not complete:
                        target = resolve_source_linked_function(
                            requested[0], opened, choices, self.graph,
                        )
                        if target and target not in opened and target not in queued:
                            queued.append(target)
                        elif not target:
                            errors.append(f"requested function not source linked: {requested[0]}")
                    if self.checkpoint:
                        self.checkpoint(behavior.behavior_id, {
                            "status": "IN_PROGRESS", "behavior_id": behavior.behavior_id,
                            "opened_function_ids": list(opened),
                            "queued_function_ids": list(queued),
                            "accumulated": accumulated, "complete": complete,
                            "errors": errors,
                        })
                    if complete and not queued:
                        break
                if queued:
                    errors.append("context work budget exhausted before required source could be opened")
            except Exception as exc:
                if is_terminal_llm_infrastructure_error(exc):
                    raise
                errors.append(f"model failure: {type(exc).__name__}: {exc}")
            finally:
                await close_llm_session(self.llm, session)

            # Later turns may discuss a different function; they cannot erase
            # an earlier cited dependency or repeatability observation.
            response = {**response, **accumulated}

            calls: list[LifecycleCall] = []
            if len(object_list(response.get("calls"))) >= 32:
                errors.append("lifecycle list reached 32-item schema ceiling; further prerequisites may be omitted")
            for raw in object_list(response.get("calls")):
                target = str(raw.get("function_id", ""))
                caller = str(raw.get("callsite_function_id", ""))
                try:
                    line = int(raw.get("callsite_line", -1))
                except (ValueError, TypeError):
                    line = -1
                if target not in opened or caller not in opened:
                    errors.append(f"lifecycle references unopened source: {caller} -> {target}")
                    continue
                fn = self.graph.get(caller)
                if not (fn.start_line <= line <= fn.end_line):
                    errors.append(f"lifecycle call site outside {caller}: {line}")
                    continue
                source_lines = fn.source.splitlines()
                offset = line - fn.start_line
                if 0 <= offset < len(source_lines):
                    neighborhood = "\n".join(source_lines[max(0, offset - 2):offset + 3])
                    called_name = self.graph.get(target).name
                    if not re.search(rf"\b{re.escape(called_name)}\b", neighborhood):
                        errors.append(f"lifecycle call site does not name {called_name}: {caller}:{line}")
                        continue
                calls.append(LifecycleCall(
                    category=str(raw.get("category", "unknown")),
                    function_id=target, callsite_function_id=caller,
                    callsite_line=line, rationale=str(raw.get("rationale", "")),
                    evidence=[Evidence("source", caller, fn.file, line, str(raw.get("rationale", "")))],
                ))
            prior: list[str] = []
            for value in string_list(response.get("prerequisite_bytes_hex")):
                try:
                    data = bytes.fromhex(value)
                except ValueError:
                    errors.append("invalid prerequisite bytes")
                    continue
                if len(data) > 65536:
                    errors.append("prerequisite exceeds 65536 bytes")
                    continue
                prior.append(data.hex())
            isolation = str(response.get("isolation", "unknown"))
            if isolation not in {
                "in_process_reset", "process_isolation_required", "unknown"
            }:
                isolation = "unknown"
            errors.extend(string_list(response.get("unknowns")))
            repeatability_evidence: list[Evidence] = []
            for item in object_list(response.get("repeatability_evidence")):
                fid = str(item.get("function_id", ""))
                line = item.get("line")
                if fid not in opened or type(line) is not int:
                    errors.append("repeatability citation references unopened source")
                    continue
                fn = self.graph.get(fid)
                if not fn.start_line <= line <= fn.end_line:
                    errors.append(f"repeatability citation line outside function {fid}")
                    continue
                repeatability_evidence.append(Evidence(
                    "source", fid, fn.file, line, str(item.get("detail", "")),
                ))
            if isolation == "unknown":
                errors.append("in-process reset or isolation not established")
            if isolation == "in_process_reset" and not repeatability_evidence:
                errors.append("claimed in-process reset has no source citation")
            if not complete:
                errors.append("lifecycle context incomplete")
            if not response.get("input_binding"):
                errors.append("fuzzer byte delivery to external Entry unknown")
            contract = ExecutionContract(
                contract_id=stable_id("execution-contract", behavior.behavior_id),
                behavior_id=behavior.behavior_id,
                entry_function_id=behavior.entry_function_id,
                target_function_id=behavior.target_function_id,
                transport=channels.get(behavior.entry_id, "unknown"),
                input_binding=str(response.get("input_binding", "")),
                calls=calls, prerequisite_bytes_hex=prior,
                isolation=isolation, result_condition=str(response.get("result_condition", "")),
                inspected_function_ids=opened, evidence_complete=complete and not errors,
                unknowns=unique_strings(errors),
                repeatability_evidence=repeatability_evidence,
            )
            contracts.append(contract)
            self.obligations.extend(
                f"{behavior.behavior_id}: {error}" for error in contract.unknowns
            )
            emit_trace(
                self.trace, "execution_contract", "completed",
                f"{behavior.behavior_id}: {len(calls)} call requirements, complete={contract.evidence_complete}",
                behavior_id=behavior.behavior_id, opened_function_ids=opened,
            )
        return contracts

    def _choices(self, opened: list[str], required: list[str]) -> list[dict[str, object]]:
        choices = {str(item["function_id"]): item for item in self.graph.frontier(opened)}
        for fid in required:
            if fid in opened or fid not in self.graph.bundle.functions:
                continue
            choices.setdefault(fid, {
                **function_ref(self.graph.get(fid)),
                "connections": [{"relation": "previous_behavior_provenance_navigation"}],
            })
        return list(choices.values())
