"""Evidence-scoped harness generation independent of Action/Feature grouping.

Only complete functions are opened in model turns. The generated harness is
always an *unqualified draft* until independent build and runtime gates prove
otherwise; model self-audits cannot discharge those gates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    CheckStatus, GateCheck, GateReport, HarnessDraft, HarnessManifest,
    ProjectSpec, as_json, stable_id, unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from .behavior import BehaviorCandidate
from .common import (
    function_payload, function_ref, object_list, string_list,
    resolve_source_linked_function,
)
from .execution_contract import ExecutionContract
from .harness import (
    CHECKLIST_NAMES, CHECKLIST_CONTRACTS, HARNESS_REVIEW_SCHEMA,
    _code_only, _resource_cleanup_issues, _fuzzer_function_body,
    _fuzzer_parameter_names, _function_invoked,
)


BOUNDARY_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["requested_function_ids", "context_complete", "blocking_unknowns", "rationale"],
    "properties": {
        "requested_function_ids": {"type": "array", "maxItems": 1, "items": {"type": "string"}},
        "context_complete": {"type": "boolean"},
        "blocking_unknowns": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
}


BOUNDARY_HARNESS_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["code", "manifest", "checklist", "generation_blockers", "input_delivery_evidence"],
    "properties": {
        "code": {"type": "string"},
        "manifest": {
            "type": "object", "additionalProperties": False,
            "required": ["build_target", "headers", "libraries", "min_size", "max_size"],
            "properties": {
                "build_target": {"type": "string"},
                "headers": {"type": "array", "items": {"type": "string"}},
                "libraries": {"type": "array", "items": {"type": "string"}},
                "min_size": {"type": "integer", "minimum": 0},
                "max_size": {"type": "integer", "minimum": 1},
            },
        },
        "checklist": {
            "type": "array", "minItems": 16, "maxItems": 16,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["check_id", "status", "evidence"],
                "properties": {
                    "check_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["PASS", "WARN", "FAIL"]},
                    "evidence": {"type": "string"},
                },
            },
        },
        "generation_blockers": {"type": "array", "items": {"type": "string"}},
        "input_delivery_evidence": {
            "type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "required": ["function_id", "line", "detail"],
                "properties": {
                    "function_id": {"type": "string"}, "line": {"type": "integer"},
                    "detail": {"type": "string"},
                },
            },
        },
    },
}


@dataclass(slots=True)
class BoundaryGeneration:
    draft: HarnessDraft
    context_obligations: list[str]


class BoundaryHarnessGeneratorAgent:
    def __init__(
        self, llm: LLMProvider, graph: GraphStore, project: ProjectSpec,
        *, max_function_turns: int | None = None, trace: TraceCallback | None = None,
    ):
        self.llm, self.graph, self.project = llm, graph, project
        self.max_function_turns = (
            max(1, max_function_turns) if max_function_turns is not None
            else max(1, len(graph.bundle.functions))
        )
        self.trace = trace
        self._state: dict[str, dict[str, Any]] = {}

    @staticmethod
    def session_key(behavior: BehaviorCandidate) -> str:
        return f"harness_generator:{behavior.behavior_id}"

    async def close_session(self, behavior: BehaviorCandidate) -> None:
        await close_llm_session(self.llm, self.session_key(behavior))
        self._state.pop(behavior.behavior_id, None)

    async def run(
        self, behavior: BehaviorCandidate, contract: ExecutionContract,
        *, feedback: list[str] | None = None,
    ) -> BoundaryGeneration:
        # Keep the same model session across repairs. No full-source-file
        # slicing and no guessed caller/callee depth cutoffs.
        session = self.session_key(behavior)
        state = self._state.setdefault(behavior.behavior_id, {
            "opened": [], "complete": False,
            "source_unknowns": [], "current_unknowns": [],
        })
        opened: list[str] = state["opened"]
        required = unique_strings([
            behavior.entry_function_id, *behavior.path_function_ids,
            behavior.target_function_id, *contract.inspected_function_ids,
            *(call.function_id for call in contract.calls),
        ])
        queue = [identifier for identifier in required if identifier not in opened]
        for _ in range(self.max_function_turns):
            if not queue:
                break
            fid = queue.pop(0)
            if fid in opened:
                continue
            if fid not in self.graph.bundle.functions:
                state["source_unknowns"].append(f"required source missing: {fid}")
                continue
            fn = self.graph.get(fid)
            opened.append(fid)
            choices = self._choices(opened, required)
            response = await self.llm.complete_json(
                role="harness_generator", session_key=session,
                output_schema=BOUNDARY_CONTEXT_SCHEMA,
                instructions=(
                    "Recover C declarations, call sites, state ownership, input delivery, "
                    "and repeatability for ONE candidate Entry-to-effect path. "
                    "This turn opens EXACTLY one complete real function, with no truncation. "
                    "The entry is a source-located acquisition, not necessarily a parser, "
                    "command, request, action or state machine. Use no unopened function "
                    "as authority for a call. Request one source-linked function if needed. "
                    "Never infer an in-process reset from absence of visible global state. "
                    "Report outstanding context as unknown, never as absent behavior."
                ),
                payload={
                    "behavior": as_json(behavior),
                    "execution_contract": as_json(contract),
                    "current_function": function_payload(
                        fn, source_limit=max(1, len(fn.source) + 1),
                    ),
                    "opened_function_ids": opened,
                    "available_function_ids": choices,
                    "repair_feedback": feedback or [],
                },
            )
            state["complete"] = response.get("context_complete") is True
            # A later function can resolve an earlier request. Preserve only
            # the latest model verdict; missing source is tracked separately.
            state["current_unknowns"] = string_list(response.get("blocking_unknowns"))
            if state["complete"] and not queue:
                break
            requested = string_list(response.get("requested_function_ids"))
            if requested:
                next_id = resolve_source_linked_function(
                    requested[0], opened, choices, self.graph,
                )
                if next_id and next_id not in queue and next_id not in opened:
                    queue.append(next_id)
                elif not next_id:
                    state["current_unknowns"].append(
                        f"requested function not linked to opened source: {requested[0]}"
                    )
        run_unknowns = unique_strings([
            *state["source_unknowns"], *state["current_unknowns"],
        ])
        if queue:
            run_unknowns.append("context exploration budget exhausted")
        if not state["complete"]:
            run_unknowns.append("complete function context not established")

        language = "C" if self.project.harness_source_filename.endswith(".c") else "C++"
        response = await self.llm.complete_json(
            role="harness_generator", session_key=session,
            output_schema=BOUNDARY_HARNESS_SCHEMA,
            instructions=(
                f"Write one {language} LLVMFuzzerTestOneInput harness for the actual "
                "source-located external input-to-effect path. Use only exact public "
                "C declarations and linkable application symbols opened in this session. "
                "The external transport is NOT automatically equivalent to calling an "
                "internal parser. Show exact source evidence for how Data/Size reach real "
                "application logic, or block. Startup/prerequisite/callback/result/cleanup "
                "requirements are conditional on evidence. Preserve all required ordering "
                "and any earlier input bytes only when justified by source or original trace. "
                "Never invent lifecycle calls, source symbols, build flags or reset paths. "
                "Never call fork/exec/system or child process from the in-process libFuzzer "
                "callback. Never include application .c/.cc/.cpp implementations directly. "
                "If there is no usable linkable in-process boundary, or repeatable reset "
                "is not established, return empty code and explain an explicit blocker. "
                "Do not duplicate a target parser or emulate its business logic. "
                "Provide all sixteen HC01..HC16 self-audits separately with specific evidence. "
                "A self-audit does not prove safety and compilation must be independently tested."
            ),
            payload={
                "behavior": as_json(behavior),
                "contract": as_json(contract),
                "opened_function_ids": opened,
                "source_obligations": unique_strings(run_unknowns),
                "existing_build_configuration": {
                    "harness_source_filename": self.project.harness_source_filename,
                    "verification_backend": self.project.verification_backend,
                    "trusted_build_command_configured": bool(self.project.build_command),
                },
                "feedback": feedback or [],
                "checklist": [
                    {"check_id": key, "name": value, "contract": CHECKLIST_CONTRACTS[key]}
                    for key, value in CHECKLIST_NAMES.items()
                ],
            },
        )
        raw_manifest = response.get("manifest") or {}
        max_size = min(65_536, max(1, int(raw_manifest.get("max_size", 4096))))
        min_size = max(0, min(max_size, int(raw_manifest.get("min_size", 0))))
        identifier = stable_id("boundary-harness", behavior.behavior_id)
        manifest = HarnessManifest(
            harness_id=identifier,
            source_file=self.project.harness_source_filename,
            build_target=str(raw_manifest.get("build_target", "")),
            engine="libfuzzer", sanitizers=["address", "undefined"],
            execution_model="in_process_reset",
            headers=string_list(raw_manifest.get("headers")),
            libraries=string_list(raw_manifest.get("libraries")),
            min_size=min_size, max_size=max_size,
            dispatch_strategy="single_input_boundary",
            expected_anchors=[behavior.entry_function_id],
            expected_consumers=[behavior.target_function_id],
            verification_backend=self.project.verification_backend,
            build_command=list(self.project.build_command),
            binary=str(self.project.harness_binary) if self.project.harness_binary else None,
        )
        evidence = []
        for item in object_list(response.get("input_delivery_evidence")):
            fid = str(item.get("function_id", ""))
            line = item.get("line")
            if fid not in opened or type(line) is not int:
                continue
            fn = self.graph.get(fid)
            if fn.start_line <= line <= fn.end_line:
                evidence.append(item)
        blockers = string_list(response.get("generation_blockers"))
        if not evidence:
            blockers.append("input delivery lacks an opened function and actual source line")
        if contract.isolation != "in_process_reset" or not contract.evidence_complete:
            blockers.append("in-process repeatability/lifecycle contract is unproven")
        if behavior.unknowns or run_unknowns:
            blockers.extend(behavior.unknowns)
            blockers.extend(run_unknowns)
        # A source-only draft may still be retained with obligations. They
        # must not be silently promoted to a qualified target.
        draft = HarnessDraft(
            manifest=manifest, code=str(response.get("code", "")),
            self_audit=[item for item in object_list(response.get("checklist"))],
            generation_blockers=unique_strings(blockers),
            context_function_ids=list(opened),
            operation_protocols=[{
                "behavior_id": behavior.behavior_id,
                "input_delivery_evidence": evidence,
                "lifecycle_call_order": [as_json(call) for call in contract.calls],
                "unknowns": contract.unknowns,
            }],
        )
        emit_trace(self.trace, "boundary_harness", "draft", identifier,
                   behavior_id=behavior.behavior_id, functions_opened=len(opened),
                   blockers=len(draft.generation_blockers))
        return BoundaryGeneration(draft, unique_strings(run_unknowns))

    def _choices(self, opened: list[str], required: list[str]) -> list[dict[str, object]]:
        choices = {str(item["function_id"]): item for item in self.graph.frontier(opened)}
        for fid in required:
            if fid in opened or fid not in self.graph.bundle.functions:
                continue
            choices.setdefault(fid, {
                **function_ref(self.graph.get(fid)),
                "connections": [{"relation": "prior_source_obligation"}],
            })
        return list(choices.values())

    async def review(
        self, behavior: BehaviorCandidate, contract: ExecutionContract,
        draft: HarnessDraft, deterministic: GateReport,
    ) -> GateReport:
        key = f"boundary_harness_review:{behavior.behavior_id}"
        needed = unique_strings([
            behavior.entry_function_id, behavior.target_function_id,
            *contract.inspected_function_ids, *draft.context_function_ids,
        ])
        opened: list[str] = []
        incomplete = False
        try:
            for fid in needed:
                if fid not in self.graph.bundle.functions:
                    incomplete = True
                    continue
                if len(opened) >= self.max_function_turns:
                    incomplete = True
                    break
                fn = self.graph.get(fid)
                opened.append(fid)
                await self.llm.complete_json(
                    role="harness_verifier", session_key=key,
                    output_schema=BOUNDARY_CONTEXT_SCHEMA,
                    instructions=(
                        "Independently inspect this ONE FULL application function. "
                        "Retain evidence for an HC01..HC16 audit on the next turn. "
                        "Check whether the harness actually delivers external input, "
                        "respects lifecycle and resets process state. An absent "
                        "branch, action or state machine is not a defect. "
                        "Do not claim a function is inspected unless opened."
                    ),
                    payload={
                        "function": function_payload(fn, source_limit=len(fn.source) + 1),
                        "opened_function_ids": opened,
                        "behavior_id": behavior.behavior_id,
                        "harness_code": draft.code,
                    },
                )
            response = await self.llm.complete_json(
                role="harness_verifier",
                output_schema=HARNESS_REVIEW_SCHEMA,
                session_key=key,
                instructions=(
                    "Independent audit: compare C harness against the entire source "
                    "opened one function per previous turn. Evaluate exactly HC01-HC16. "
                    "A missing lifecycle category is not an error unless source proves "
                    "it required. Model self-audit and lexical lint cannot prove "
                    "sanitizer safety or input equivalence. PASS only with direct "
                    "evidence. WARN if evidence cannot decide, FAIL on a concrete "
                    "conflict. Do not invent APIs, actions, states or build results."
                ),
                payload={
                    "behavior": as_json(behavior),
                    "contract": as_json(contract),
                    "draft": as_json(draft),
                    "opened_source_function_ids": opened,
                    "source_incomplete": incomplete,
                    "deterministic_checks": as_json(deterministic),
                    "checklist": [
                        {"check_id": ident, "name": name, "contract": CHECKLIST_CONTRACTS[ident]}
                        for ident, name in CHECKLIST_NAMES.items()
                    ],
                },
            )
        finally:
            await close_llm_session(self.llm, key)
        by_id: dict[str, list[dict[str, Any]]] = {}
        for item in object_list(response.get("checks")):
            key = str(item.get("check_id", "")).upper()
            if key in CHECKLIST_NAMES:
                by_id.setdefault(key, []).append(item)
        checks: list[GateCheck] = []
        for key, name in CHECKLIST_NAMES.items():
            if len(by_id.get(key, [])) != 1:
                checks.append(GateCheck(key, name, CheckStatus.FAIL,
                    "missing or duplicated independent check", "repeat independent review"))
                continue
            item = by_id[key][0]
            try:
                status = CheckStatus(str(item.get("status", "FAIL")).upper())
            except ValueError:
                status = CheckStatus.FAIL
            evidence = str(item.get("evidence", "")).strip()
            if not evidence:
                status = CheckStatus.FAIL
            elif incomplete and status is CheckStatus.PASS:
                status = CheckStatus.WARN
                evidence += "; required source review incomplete"
            checks.append(GateCheck(key, name, status,
                evidence or "independent auditor provided no evidence",
                str(item.get("remediation", ""))))
        return GateReport(checks)


class BoundaryStaticGate:
    """Deterministic P1/P2 checks with uncertainty retained as WARN.

    Regex absence is never evidence that reset, ownership, or API invocation
    semantics are correct. This gate is a triage layer, not semantic proof.
    """

    def __init__(self, graph: GraphStore):
        self.graph = graph

    def check(
        self, draft: HarnessDraft, behavior: BehaviorCandidate,
        contract: ExecutionContract,
    ) -> GateReport:
        code = _code_only(draft.code)
        checks: list[GateCheck] = []

        def add(key: str, status: CheckStatus, evidence: str, fix: str = "") -> None:
            checks.append(GateCheck(key, CHECKLIST_NAMES[key], status, evidence, fix))

        if not code.strip():
            return GateReport([
                GateCheck(key, CHECKLIST_NAMES[key], CheckStatus.FAIL,
                          "no generated harness code", "resolve generation blockers")
                for key in CHECKLIST_NAMES
            ])
        if not re.search(r"\bLLVMFuzzerTestOneInput\s*\(", code):
            return GateReport([
                GateCheck(key, CHECKLIST_NAMES[key], CheckStatus.FAIL,
                          "missing LLVMFuzzerTestOneInput", "write a libFuzzer callback")
                for key in CHECKLIST_NAMES
            ])
        leaks = _resource_cleanup_issues(_fuzzer_function_body(code))
        add("HC01", CheckStatus.FAIL if leaks else CheckStatus.WARN,
            f"lexical per-iteration resource imbalance: {leaks}" if leaks
            else "no obvious unmatched resource families; ownership needs dynamic evidence")
        add("HC02", CheckStatus.WARN, "UAF requires ownership reasoning and sanitizer replay")
        add("HC03", CheckStatus.WARN if contract.isolation == "in_process_reset" else CheckStatus.FAIL,
            f"in-process reset claim: {contract.isolation}; repeated-run replay required")
        data, size = _fuzzer_parameter_names(code)
        body = _fuzzer_function_body(code)
        uses_both = bool(data and size and
            re.search(rf"\b{re.escape(data)}\b", body) and
            re.search(rf"\b{re.escape(size)}\b", body))
        # A void cast, length guard, or local read of Data is not input flow.
        # This conservative lexical test only rejects an *obvious* bypass.
        # Aliases, wrappers and implicit transport still need independent
        # source review and instrumented reachability.
        called_targets = [self.graph.get(fid).name for fid in unique_strings([
            behavior.entry_function_id, behavior.target_function_id,
            *contract.inspected_function_ids,
        ]) if fid in self.graph.bundle.functions]
        named_fuzzer_input = bool(data and re.search(
            rf"\b(?:memcpy|memmove|fmemopen|write|send|sendto|fwrite|fputs)\s*\([^;]*\b{re.escape(data)}\b",
            body,
        ))
        passed_to_target = bool(data and any(re.search(
            rf"\b{re.escape(name)}\s*\([^;]*\b{re.escape(data)}\b", body,
        ) for name in called_targets))
        # Also detect a source-backed data provider called with fuzzer bytes;
        # calls to arbitrary library functions are not by themselves proof.
        has_plausible_binding = passed_to_target or named_fuzzer_input
        add("HC04", CheckStatus.WARN if uses_both and has_plausible_binding else CheckStatus.FAIL,
            "plausible fuzz-byte transfer; actual target consumption unproven"
            if has_plausible_binding and uses_both else
            "no visible Data-to-application input transfer")
        unsafe = bool(data and re.search(
            rf"\b(?:strcpy|strcat|sprintf|strlen)\s*\(\s*{re.escape(data)}\b", code))
        add("HC05", CheckStatus.FAIL if unsafe else CheckStatus.WARN,
            "unbounded string function applied directly to fuzz bytes" if unsafe
            else "no simple unbounded input-string pattern; ASan remains necessary")
        add("HC06", CheckStatus.WARN, "bounds and integer length guards require path-sensitive review")
        process_created = bool(re.search(
            r"\b(?:fork|vfork|execve|posix_spawn|system|popen)\s*\(", body))
        add("HC07", CheckStatus.FAIL if process_created else CheckStatus.WARN,
            "process creation is not a valid in-process libFuzzer target"
            if process_created
            else "undefined behavior requires UBSan and independent analysis")
        targets = [self.graph.get(fid) for fid in unique_strings([
            behavior.entry_function_id, behavior.target_function_id,
            *contract.inspected_function_ids,
        ]) if fid in self.graph.bundle.functions]
        actual = [fn.name for fn in targets if _function_invoked(code, fn.name)]
        add("HC08", CheckStatus.WARN if actual else CheckStatus.FAIL,
            f"candidate real application calls: {actual}" if actual else
            "no opened real application function is called")
        for key, category in [
            ("HC09", "initialization"), ("HC11", "lifecycle"),
            ("HC12", "result_check"), ("HC13", "cleanup"),
            ("HC15", "co_call"), ("HC16", "prerequisite"),
        ]:
            needed = [call for call in contract.calls if call.category == category]
            missing = [call.function_id for call in needed
                       if call.function_id in self.graph.bundle.functions
                       and not _function_invoked(code, self.graph.get(call.function_id).name)]
            add(key, CheckStatus.FAIL if missing else CheckStatus.WARN,
                f"required calls absent: {missing}" if missing
                else f"{category}: no visible missing required call; exact order/semantics unproven")
        add("HC10", CheckStatus.WARN if contract.input_binding and uses_both else CheckStatus.FAIL,
            f"declared binding: {contract.input_binding or 'missing'}; equivalence not yet proven")
        referenced_unknown = [name for name in re.findall(
            r"\b([A-Za-z_]\w*)\s*\(", body
        ) if name not in {fn.name for fn in targets}]
        add("HC14", CheckStatus.WARN,
            f"external call names require link/build proof: {unique_strings(referenced_unknown)[:24]}")
        if len(checks) != 16:
            raise AssertionError(f"expected exactly 16 checks, got {len(checks)}")
        return GateReport(checks)
