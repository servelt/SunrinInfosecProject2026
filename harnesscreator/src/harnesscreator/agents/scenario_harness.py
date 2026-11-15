from __future__ import annotations

import ast
from collections import deque
import re
from pathlib import Path
from typing import Any

from ..analysis.graph import GraphStore
from ..analysis.value_flow import direct_sibling_buffer_handoffs
from ..llm.base import LLMProvider, close_llm_session
from ..runtime.request_ir import request_ir_summary
from ..runtime.request_trace import response_hex_attested
from ..models import (
    CheckStatus,
    ExternalActionSchema,
    GateCheck,
    GateReport,
    HarnessDraft,
    HarnessManifest,
    HarnessPlan,
    ProjectSpec,
    ScenarioStatus,
    ScenarioWitness,
    SeedSpec,
    stable_id,
    unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from .common import (
    function_payload,
    function_ref,
    object_list,
    prefer_product_build_targets,
    resolve_source_linked_function,
    string_list,
)
from .harness import (
    CHECKLIST_CONTRACTS,
    CHECKLIST_NAMES,
    _code_only,
    _fuzzer_function_body,
    _fuzzer_parameter_names,
    _execution_model_visible,
    _has_mutable_static_object,
    _function_invoked,
    _function_or_source_alias_invoked,
    _invoked_application_entrances_to,
    _invoked_application_entrances_through,
    _source_candidate_return_to_table_routes,
    _resource_cleanup_issues,
)


SCENARIO_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "context_complete", "requested_function_ids", "established_facts",
        "blocking_dependencies", "resolved_blocking_dependencies",
        "verification_obligations",
        "terminal_backend_blocker", "rationale",
    ],
    "properties": {
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {
            "type": "array", "maxItems": 1, "items": {"type": "string"},
        },
        "established_facts": {"type": "array", "items": {"type": "string"}},
        "verification_obligations": {
            "type": "array", "items": {"type": "string"},
        },
        "blocking_dependencies": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["description", "required_for", "function_id", "line"],
                "properties": {
                    "description": {"type": "string"},
                    "required_for": {"type": "string"},
                    "function_id": {"type": "string"},
                    "line": {"type": ["integer", "null"]},
                },
            },
        },
        "resolved_blocking_dependencies": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["blocker_id", "function_id", "line", "explanation"],
                "properties": {
                    "blocker_id": {"type": "string"},
                    "function_id": {"type": "string"},
                    "line": {"type": "integer"},
                    "explanation": {"type": "string"},
                },
            },
        },
        "terminal_backend_blocker": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
}


SCENARIO_HARNESS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["code", "manifest", "checklist", "implemented_step_indexes", "generation_blockers"],
    "properties": {
        "code": {"type": "string"},
        "manifest": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "build_target", "headers", "libraries", "min_size", "max_size",
                "execution_model",
            ],
            "properties": {
                "build_target": {"type": "string"},
                "headers": {"type": "array", "items": {"type": "string"}},
                "libraries": {"type": "array", "items": {"type": "string"}},
                "min_size": {"type": "integer", "minimum": 0},
                "max_size": {"type": "integer", "minimum": 1},
                "execution_model": {
                    "type": "string", "enum": ["in_process_reset", "loopback_network"],
                },
            },
        },
        "checklist": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["check_id", "status", "evidence"],
                "properties": {
                    "check_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["PASS", "WARN", "FAIL"]},
                    "evidence": {"type": "string"},
                },
            },
        },
        "implemented_step_indexes": {"type": "array", "items": {"type": "integer", "minimum": 0}},
        "generation_blockers": {"type": "array", "items": {"type": "string"}},
    },
}


SCENARIO_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["checks", "summary"],
    "properties": {
        "checks": {
            "type": "array", "minItems": 16, "maxItems": 16,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["check_id", "status", "evidence", "remediation"],
                "properties": {
                    "check_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["PASS", "WARN", "FAIL"]},
                    "evidence": {"type": "string"},
                    "remediation": {"type": "string"},
                },
            },
        },
        "summary": {"type": "string"},
    },
}


SCENARIO_REVIEW_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["context_complete", "requested_function_ids", "rationale"],
    "properties": {
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {
            "type": "array", "maxItems": 1, "items": {"type": "string"},
        },
        "rationale": {"type": "string"},
    },
}


SCENARIO_SEED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["seeds"],
    "properties": {
        "seeds": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "data_hex", "rationale", "check_ids"],
                "properties": {
                    "name": {"type": "string"},
                    "data_hex": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
                    "rationale": {"type": "string"},
                    "check_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
}


class ScenarioHarnessGeneratorAgent:
    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        project: ProjectSpec,
        *,
        max_context_turns: int | None = None,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.project = project
        if max_context_turns is not None and max_context_turns < 0:
            raise ValueError("harness context work budget cannot be negative")
        # Zero is an exhaustive indexed-function cycle guard. An explicitly
        # supplied positive value limits work, not the meaning of completion.
        self.max_context_turns = max_context_turns or len(graph.bundle.functions)
        self.trace = trace
        self._context_cache: dict[str, tuple[list[Any], dict[str, Any]]] = {}

    def _opened_function_payload(self, function: Any) -> dict[str, Any]:
        payload = function_payload(
            function, source_limit=max(1, len(function.source) + 1),
        )
        completeness = self.graph.bundle.completeness
        database = str(completeness.get("analysis_compile_database") or "")
        if database:
            recorded = set(completeness.get("analysis_compile_database_files") or [])
            payload["recorded_compilation"] = (
                "RECORDED" if function.file in recorded else "NOT_RECORDED"
            )
            payload["recorded_compilation_meaning"] = (
                "A compile command is positive parsing evidence, not proof of "
                "linkage. A missing command may reflect an incremental capture "
                "or another build configuration; verify build availability."
            )
        else:
            payload["recorded_compilation"] = "UNKNOWN"
        return payload

    @staticmethod
    def session_key(plan: HarnessPlan) -> str:
        return f"harness_generator:{plan.plan_id}"

    async def close_session(self, plan: HarnessPlan) -> None:
        self._context_cache.pop(plan.plan_id, None)
        await close_llm_session(self.llm, self.session_key(plan))

    def _trusted_build_configuration(self) -> dict[str, Any]:
        config: dict[str, Any] = {
            "verification_backend": self.project.verification_backend,
            "build_command_configured": bool(self.project.build_command),
            "harness_source_filename": self.project.harness_source_filename,
            "oss_fuzz_project": self.project.oss_fuzz_project,
            "oss_fuzz_fuzzer": self.project.oss_fuzz_fuzzer,
        }
        if (
            self.project.native_default_build
            and self.project.verification_backend == "command"
            and self.project.build_command[1:3]
                == ["-m", "harnesscreator.runtime.native_build"]
        ):
            config["native_builder_main_contract"] = (
                "The selected bundled native builder compiles a selected original "
                "translation unit containing main with "
                "-Dmain=hc_native_original_main. The generated harness may call "
                "hc_native_original_main with the original main signature, if the "
                "opened declaration establishes it. The builder rejects multiple "
                "selected main definitions and unresolved source or link closure. "
                "This is a provisional build capability, not proof of a successful "
                "link or safe per-input execution; verify both later."
            )
        return config

    async def run(
        self,
        plan: HarnessPlan,
        witness: ScenarioWitness,
        *,
        feedback: list[str] | None = None,
    ) -> HarnessDraft:
        opened, discovery = await self._discover_context(plan, witness, feedback or [])
        known = {item.function_id for item in opened}
        blockers = [
            "CONTEXT_BLOCKED: " + str(item.get("description", "unresolved dependency"))
            + (
                f" (source {item['function_id']}:{item['line']})"
                if item.get("function_id") in known
                and isinstance(item.get("line"), int)
                and self.graph.get(str(item["function_id"])).start_line
                    <= item["line"]
                    <= self.graph.get(str(item["function_id"])).end_line
                else " (source location unverified)"
            )
            for item in object_list(discovery.get("blocking_dependencies"))
        ]
        if not bool(discovery.get("context_complete", False)):
            blockers.append(
                "CONTEXT_BLOCKED: "
                + str(discovery.get("stop_reason") or
                      "required harness evidence remains unresolved")
            )
        if witness.status is not ScenarioStatus.PROVEN_RUNTIME and not (
            ((self.project.scenario_exploratory_drafts
              or self.project.scenario_source_drafts)
             and witness.status in {ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME})
            or (self.project.scenario_source_drafts
                and witness.status in {ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED})
        ):
            blockers.append("WITNESS_BLOCKED: scenario is not PROVEN_RUNTIME")
        emit_trace(
            self.trace, "harness_generator", "context_decision",
            f"{plan.plan_id}: "
            + ("generation blocked" if blockers else "source generation ready"),
            scenario_id=plan.scenario_id,
            plan_id=plan.plan_id,
            opened_function_ids=[item.function_id for item in opened],
            context_complete=bool(discovery.get("context_complete", False)),
            stop_reason=str(discovery.get("stop_reason", "")),
            next_function_ids=string_list(discovery.get("next_function_ids")),
            blockers=list(blockers),
            verification_obligations=string_list(
                discovery.get("verification_obligations")
            ),
        )
        if blockers:
            response: dict[str, Any] = {
                "code": "", "manifest": {}, "checklist": [],
                "implemented_step_indexes": [], "generation_blockers": blockers,
            }
        else:
            language = "C" if Path(self.project.harness_source_filename).suffix.lower() == ".c" else "C++"
            response = await self.llm.complete_json(
                role="harness_generator",
                instructions=(
                    "Generate one libFuzzer harness from the supplied source scenario and, when present, original-execution ScenarioWitness. "
                    "UNPROVEN or INFRASTRUCTURE_FAILED means SOURCE-ONLY UNQUALIFIED DRAFT, possibly after a failed original execution: "
                    "do not imply any successful original execution, initialization, or response oracle replay. "
                    "If status is OBSERVED_RUNTIME or REPLAYED_RUNTIME this is an EXPLORATORY draft, not verified proof. "
                    "Never claim request-level causality from an unattributed GDB trace. The witness is "
                    "the executable contract: reproduce setup requests in their exact order, then map fuzzer Data/Size "
                    "to the selected external fuzz request, then execute any witnessed post requests. "
                    "Implement every context_discovery.verification_obligation in the harness where possible. "
                    "If safe per-input delivery, completion, state isolation, or crash attribution cannot be "
                    "implemented from the opened source and selected backend, return empty code with the "
                    "specific unsatisfied obligation; do not call a source-only draft verified. "
                    "If the first step has connection_prelude_marker_hex, a fresh stream connection "
                    "must read and validate the original server-first line before any request write. "
                    "Use hc_connection_prelude_marker, hc_connection_prelude_response, and a real "
                    "read/recv result; reject that iteration if the marker is absent. Never synthesize "
                    "the prelude or treat it as the response to the first request. "
                    "Use the real target parser and dispatcher. A "
                    "NOT_RECORDED compilation status does not prove a helper is absent, "
                    "but it cannot establish that the selected original build links it. "
                    "Treat such source as reference until build availability is verified. Use only "
                    "opened current-checkout functions/declarations. Preserve real result checks and stop after a failed "
                    "setup action. Lifecycle categories are optional: do not invent initialization, reset, cleanup, "
                    "callbacks, or objects when source/witness does not require them. Never include application .c/.cc "
                    "implementation files, fork/exec from LLVMFuzzerTestOneInput, or model-provided shell commands. "
                    f"Emit strict {language}. Name each fixed setup byte array hc_setup_step_N so the independent gate "
                    "can verify that every witnessed prerequisite is present, and name its source-proven success "
                    "oracle bytes hc_success_step_N. Execute and validate setup steps in ascending N before delivering "
                    "each setup array through its plan-mapped Entry (or transport) with `sizeof(hc_setup_step_N)`. "
                    "Capture each real setup reply through read/recv/recvfrom/fread/SSL_read into "
                    "hc_response_step_N and assign the returned length to hc_response_step_N_size; a fabricated "
                    "constant response is forbidden. Check each response before the next step with an `if` condition calling "
                    "`hc_response_contains` (or a standard byte comparison) on hc_success_step_N and its `sizeof`. "
                    "For every response_binding_extractor, retain the received bytes as hc_response_step_N with "
                    "hc_response_step_N_size, bounds-check offset+width, then copy the exact slice into the supplied "
                    "binding_symbol. For every later request_binding_use, copy that binding_symbol into the specified "
                    "fixed offset/width of a mutable request copy before delivery. Name setup copies "
                    "hc_setup_request_N. For a dynamically patched final request, first copy Data/Size into "
                    "hc_fuzz_request_storage, bounds-check every patch, apply it, and bind hc_fuzz_request to that "
                    "storage. Never hard-code a value that the witness marks as runtime-produced. "
                    "Deliver the final fuzz request only through fuzz_entry_function_id. Bind the unmodified final request as `const uint8_t *hc_fuzz_request = "
                    "Data` when there are no dynamic uses, or bind it to hc_fuzz_request_storage after the required "
                    "copy and patches. Always use `size_t hc_fuzz_request_size = Size`, and use those aliases at the application "
                    "Entry or transport write. For every post_step after the fuzz input, define "
                    "hc_post_step_N with the exact source-backed raw bytes, deliver it via the specified "
                    "post_entry_function_ids, and use sizeof(hc_post_step_N). Capture its real response "
                    "as hc_response_step_N and compare to the witnessed hc_success_step_N oracle before "
                    "moving on. The post action is a real follow-up to the fuzz input, not a new "
                    "interpretation of the fuzz data. If the fuzz request is rejected and the post "
                    "state is unavailable, exit the iteration cleanly. The final fuzz bytes are one raw request, "
                    "not a selector or an already-parsed structure. If opened evidence cannot reproduce the witness, "
                    "return empty code and a precise blocker. Audit HC01..HC16 individually."
                ),
                payload={
                    "harness_plan": _plan_payload(plan),
                    "scenario_witness": _witness_payload(witness),
                    "context_discovery": discovery,
                    "opened_functions": [
                        self._opened_function_payload(item) for item in opened
                    ],
                    "trusted_build_configuration": self._trusted_build_configuration(),
                    "checklist": [
                        {"check_id": key, "name": CHECKLIST_NAMES[key], "contract": CHECKLIST_CONTRACTS[key]}
                        for key in CHECKLIST_NAMES
                    ],
                    "previous_attempt_feedback": feedback or [],
                },
                output_schema=SCENARIO_HARNESS_SCHEMA,
                session_key=self.session_key(plan),
            )

        harness_id = stable_id("harness", plan.plan_id)
        raw_manifest = response.get("manifest") if isinstance(response.get("manifest"), dict) else {}
        build_targets = prefer_product_build_targets(
            target for function in opened for target in function.build_targets
        )
        requested_target = str(raw_manifest.get("build_target", ""))
        if requested_target in build_targets:
            build_target = requested_target
        elif build_targets:
            build_target = build_targets[0]
        elif self.project.verification_backend == "oss-fuzz":
            build_target = f"oss-fuzz:{self.project.oss_fuzz_project}/{self.project.oss_fuzz_fuzzer}"
        elif self.project.build_command:
            build_target = "trusted-cli-build-command"
        else:
            build_target = "UNRESOLVED"
        code = str(response.get("code", ""))
        implemented = [
            item for item in response.get("implemented_step_indexes", [])
            if isinstance(item, int)
        ] if isinstance(response.get("implemented_step_indexes"), list) else []
        expected_indexes = [step.index for step in witness.steps]
        if implemented != expected_indexes:
            blockers.append(
                f"SCENARIO_STEP_BLOCKED: implemented={implemented}, expected={expected_indexes}"
            )
        blockers.extend(string_list(response.get("generation_blockers")))
        manifest = HarnessManifest(
            harness_id=harness_id,
            scenario_id=plan.scenario_id,
            source_file=f"harnesses/{harness_id}/{self.project.harness_source_filename}",
            build_target=build_target,
            engine="libfuzzer",
            sanitizers=["address"] if self.project.verification_backend == "oss-fuzz" else ["address", "undefined"],
            execution_model=(
                str(raw_manifest.get("execution_model"))
                if str(raw_manifest.get("execution_model")) in {"in_process_reset", "loopback_network"}
                else plan.reset_strategy
            ),
            headers=unique_strings(string_list(raw_manifest.get("headers"))),
            libraries=unique_strings(string_list(raw_manifest.get("libraries"))),
            min_size=max(0, int(raw_manifest.get("min_size", plan.min_size))),
            max_size=min(1_048_576, max(1, int(raw_manifest.get("max_size", plan.max_size)))),
            dispatch_strategy="one_scenario_per_harness",
            expected_anchors=([plan.required_function_ids[-1]] if plan.required_function_ids else []),
            expected_consumers=list(plan.required_function_ids),
            variant_count=1,
            variant_targets=[],
            verification_backend=self.project.verification_backend,
            backend_target=(
                f"{self.project.oss_fuzz_project}/{self.project.oss_fuzz_fuzzer}"
                if self.project.verification_backend == "oss-fuzz" else None
            ),
            build_command=list(self.project.build_command),
            binary=str(self.project.harness_binary) if self.project.harness_binary else None,
        )
        audit = object_list(response.get("checklist"))
        if blockers:
            audit.append({
                "check_id": "generation_blockers", "status": "FAIL",
                "evidence": "; ".join(blockers),
            })
        return HarnessDraft(
            manifest=manifest,
            code=code,
            self_audit=audit,
            generation_blockers=unique_strings(blockers),
            context_function_ids=sorted(known),
            operation_protocols=[{
                "scenario_id": plan.scenario_id,
                "implemented_step_indexes": implemented,
                "input_mapping": plan.input_mapping,
            }],
        )

    async def _discover_context(
        self,
        plan: HarnessPlan,
        witness: ScenarioWitness,
        feedback: list[str],
    ) -> tuple[list[Any], dict[str, Any]]:
        cached = self._context_cache.get(plan.plan_id)
        if cached is not None and not feedback:
            return cached
        roots = unique_strings(
            item for item in [
                plan.fuzz_entry_function_id,
                *plan.entry_function_ids,
                *plan.required_function_ids,
            ]
            if item in self.graph.bundle.functions
        )
        if not roots:
            return [], {
                "context_complete": False,
                "stop_reason": "no ScenarioPlan function exists in static analysis",
                "established_facts": [],
                "blocking_dependencies": [{
                    "description": "no ScenarioPlan function exists in static analysis",
                    "required_for": "calling the witnessed application path",
                    "function_id": "", "line": None,
                }],
            }
        opened: list[str] = []
        pending = roots[0]
        deferred_requests: deque[str] = deque()
        facts: list[str] = []
        unresolved_blockers: dict[str, dict[str, Any]] = {}
        latest: dict[str, Any] = {}
        stop_reason = ""
        if cached is not None:
            cached_functions, cached_discovery = cached
            opened = unique_strings(
                item.function_id for item in cached_functions
                if item.function_id in self.graph.bundle.functions
            )
            facts = string_list(cached_discovery.get("established_facts"))
            choices = {
                str(item["function_id"]): item
                for item in self.graph.frontier(opened)
            }
            repair = await self.llm.complete_json(
                role="harness_generator",
                instructions=(
                    "Review the new evidence-bearing harness failure against the already opened context. "
                    "If another function body is required to repair that exact failure, request at most one "
                    "function from the supplied source-free frontier. Otherwise mark context complete so the "
                    "harness source can be regenerated from the existing context. Distinguish a missing fact "
                    "about existing application source (blocking_dependencies) from a property that the "
                    "generated harness must implement and later verify (verification_obligations). Do not "
                    "invent a dependency."
                ),
                payload={
                    "harness_plan": _plan_payload(plan),
                    "witness_summary": _witness_payload(
                        witness, include_responses=False
                    ),
                    "opened_functions": [
                        function_ref(self.graph.get(item)) for item in opened
                    ],
                    "candidate_functions": list(choices.values()),
                    "established_facts": facts,
                    "verification_obligations": string_list(
                        cached_discovery.get("verification_obligations")
                    ),
                    "verification_feedback": feedback,
                    "trusted_build_configuration": self._trusted_build_configuration(),
                },
                output_schema=SCENARIO_CONTEXT_SCHEMA,
                session_key=self.session_key(plan),
            )
            facts = unique_strings([
                *facts,
                *string_list(repair.get("established_facts")),
            ])
            verification_obligations = unique_strings([
                *string_list(cached_discovery.get("verification_obligations")),
                *string_list(repair.get("verification_obligations")),
            ])
            requested = string_list(repair.get("requested_function_ids"))
            pending = resolve_source_linked_function(
                requested[0] if requested else "", opened,
                list(choices.values()), self.graph,
            ) if requested else ""
            latest = repair
            emit_trace(
                self.trace, "harness_generator", "context_repair_reviewed",
                f"{plan.plan_id}: reviewed verifier feedback against cached context",
                scenario_id=plan.scenario_id,
                plan_id=plan.plan_id,
                requested_function_id=pending,
                feedback=feedback,
            )
            if not pending:
                unresolved_request = bool(requested)
                repair_stop_reason = (
                    "requested source-linked function unavailable"
                    if unresolved_request else
                    "feedback review left required harness context incomplete"
                    if not bool(repair.get("context_complete", False)) else ""
                )
                result = [self.graph.get(item) for item in opened], {
                    "context_complete": (
                        bool(repair.get("context_complete", False))
                        and not unresolved_request
                    ),
                    "opened_function_ids": opened,
                    "established_facts": facts,
                    "verification_obligations": verification_obligations,
                    "blocking_dependencies": object_list(
                        repair.get("blocking_dependencies")
                    ),
                    "rationale": (
                        str(repair.get("rationale", ""))
                        + (f"; {repair_stop_reason}" if repair_stop_reason else "")
                    ),
                    "stop_reason": repair_stop_reason,
                }
                if (
                    result[1]["context_complete"]
                    and not result[1]["blocking_dependencies"]
                ):
                    self._context_cache[plan.plan_id] = result
                return result
        # Every plan root is required evidence; a smaller user work budget
        # cannot silently omit one and still call the context complete.
        turn_limit = max(self.max_context_turns, len(roots))
        verification_obligations: list[str] = []
        for turn in range(1, turn_limit + 1):
            if pending in opened or pending not in self.graph.bundle.functions:
                stop_reason = "next function was already opened or unavailable"
                break
            opened.append(pending)
            current = self.graph.get(pending)
            choices = {str(item["function_id"]): item for item in self.graph.frontier(opened)}
            for function_id in roots:
                if function_id not in opened:
                    choices.setdefault(function_id, function_ref(self.graph.get(function_id)))
            next_forced = next(
                (function_id for function_id in roots if function_id not in opened),
                "",
            )
            emit_trace(
                self.trace, "harness_generator", "context_function_opened",
                f"{plan.plan_id}: opened {current.name}",
                scenario_id=plan.scenario_id,
                plan_id=plan.plan_id,
                function=function_ref(current),
                opened_function_ids=list(opened),
            )
            latest = await self.llm.complete_json(
                role="harness_generator",
                instructions=(
                    "Inspect exactly this newly opened function in the existing harness-generation session. Decide "
                    "whether the observed scenario can be reproduced with the opened public declarations and "
                    "the selected in-process libFuzzer execution model; "
                    "respect witness.status because replay without request-correlated handler attribution is not proof. "
                    "Inspect every required plan function before deciding whether this execution model can "
                    "reproduce the witnessed path. A source line showing a server loop, long-lived thread, "
                    "network transport, or absent cleanup is a lifecycle question, not by itself proof that "
                    "an in-process target is impossible. Identify the exact per-input state, synchronization, "
                    "or input-delivery requirement that remains unresolved, citing opened source. "
                    "A long-lived worker is acceptable only if the generated target can keep it idle outside "
                    "the fuzz callback and verify completion of each input before returning. Do not assert "
                    "that such a design is safe without source and dynamic evidence. The terminal_backend_blocker "
                    "field is an advisory hypothesis; it cannot skip required source inspection. "
                    "Earlier blocking_dependencies remain unresolved across turns. If this newly opened "
                    "function supplies source evidence resolving one, return its blocker_id, this function's ID "
                    "and exact line, and an explanation in resolved_blocking_dependencies. Otherwise leave it "
                    "unresolved; omitting it from the current blocking_dependencies is not a resolution. "
                    "A separate process-based server fuzzer requires its own instrumented binary and is not "
                    "a libFuzzer harness. "
                    "Context_complete means that the existing application source needed to ATTEMPT code "
                    "generation has been inspected; it does not assert that the generated harness works. "
                    "Put duties of code that has not yet been generated, such as delivering each fuzz input, "
                    "waiting for a request to finish, resetting state, and proving crash attribution, in "
                    "verification_obligations. These are mandatory for code generation and dynamic review, "
                    "but their absence from the original application source is not a source-context blocker. "
                    "Use blocking_dependencies only for a specific missing fact about EXISTING application "
                    "source, such as an unknown callback target, required initializer, public declaration, "
                    "or build-visible type. Cite the opened statement that requires that fact and request "
                    "the next source-linked function only if it could establish that fact. Do not repeat "
                    "a verification obligation as a new source blocker on each turn. If source evidence "
                    "shows the selected execution model cannot safely meet an obligation, record the reason "
                    "and let code generation return an empty draft with that precise blocker. "
                    "The current_function payload includes any Clang-confirmed global initializers and "
                    "object macros used by that function; use those source-located definitions directly "
                    "rather than requesting a macro name as if it were a function. "
                    "Its recorded_compilation field describes only the supplied build capture; "
                    "NOT_RECORDED is unknown linkage, not proof of absence. "
                    "Request at most one next function from the supplied source-free candidates. Missing optional "
                    "initialization/cleanup is not a blocker; report a blocker only when an evidenced required call, "
                    "type, callback target, input-delivery path, or build-visible declaration is still unavailable."
                ),
                payload={
                    "harness_plan": _plan_payload(plan),
                    "selected_execution_model": {
                        "engine": "libfuzzer",
                        "iteration_model": plan.reset_strategy,
                        "internal_boundary_approved": bool(
                            plan.boundary_contract.get("internal_boundary_is_approved", False)
                        ),
                        "reset_verified": bool(
                            plan.boundary_contract.get("reset_is_verified", False)
                        ),
                    },
                    "witness_summary": _witness_payload(witness, include_responses=False),
                    "turn": turn,
                    "current_function": self._opened_function_payload(current),
                    "opened_functions": [function_ref(self.graph.get(item)) for item in opened],
                    "candidate_functions": list(choices.values()),
                    "established_facts": facts,
                    "verification_obligations": verification_obligations,
                    "unresolved_blocking_dependencies": list(unresolved_blockers.values()),
                    "previous_attempt_feedback": feedback,
                    "trusted_build_configuration": self._trusted_build_configuration(),
                },
                output_schema=SCENARIO_CONTEXT_SCHEMA,
                session_key=self.session_key(plan),
            )
            facts = unique_strings([*facts, *string_list(latest.get("established_facts"))])
            verification_obligations = unique_strings([
                *verification_obligations,
                *string_list(latest.get("verification_obligations")),
            ])
            for resolved in object_list(latest.get("resolved_blocking_dependencies")):
                blocker_id = str(resolved.get("blocker_id", ""))
                if (
                    blocker_id in unresolved_blockers
                    and resolved.get("function_id") == current.function_id
                    and isinstance(resolved.get("line"), int)
                    and current.start_line <= resolved["line"] <= current.end_line
                    and str(resolved.get("explanation", "")).strip()
                ):
                    unresolved_blockers.pop(blocker_id)
            for blocker in object_list(latest.get("blocking_dependencies")):
                cited_id = str(blocker.get("function_id", ""))
                cited_line = blocker.get("line")
                if (
                    cited_id not in opened
                    or not isinstance(cited_line, int)
                    or not self.graph.get(cited_id).start_line <= cited_line
                        <= self.graph.get(cited_id).end_line
                ):
                    continue
                blocker_id = stable_id(
                    "harness-context-blocker",
                    str(blocker.get("required_for", "")),
                    str(blocker.get("function_id", "")),
                    str(blocker.get("line", "")),
                    str(blocker.get("description", "")),
                )
                unresolved_blockers[blocker_id] = {
                    **blocker, "blocker_id": blocker_id,
                }
            # The model's terminal flag and an in-range line are not a proof
            # of impossibility. In particular, a server loop may be started
            # once while the fuzz callback sends one request and waits for a
            # quiescent worker. Preserve the blocker as an unresolved claim,
            # but inspect every plan root before making a generation decision.
            requested = string_list(latest.get("requested_function_ids"))
            if requested:
                resolved = resolve_source_linked_function(
                    requested[0], opened, list(choices.values()), self.graph,
                )
                if resolved and resolved not in opened and resolved not in deferred_requests:
                    deferred_requests.append(resolved)
                elif not resolved:
                    stop_reason = f"requested source-linked function unavailable: {requested[0]}"
            if next_forced:
                pending = next_forced
                continue
            while deferred_requests and deferred_requests[0] in opened:
                deferred_requests.popleft()
            if deferred_requests:
                pending = deferred_requests.popleft()
                continue
            if bool(latest.get("context_complete", False)) and not requested and not stop_reason:
                pending = ""
                break
            pending = ""
            if not stop_reason:
                stop_reason = "model left required harness context incomplete"
            break
        else:
            if pending and pending not in opened:
                stop_reason = "harness context work budget exhausted"
        outstanding_roots = [item for item in roots if item not in opened]
        outstanding_requests = [item for item in deferred_requests if item not in opened]
        context_complete = (
            bool(latest.get("context_complete", False))
            and not unresolved_blockers
            and not outstanding_roots
            and not outstanding_requests
            and not pending
            and not stop_reason
        )
        result = [self.graph.get(item) for item in opened], {
            "context_complete": context_complete,
            "opened_function_ids": opened,
            "established_facts": facts,
            "verification_obligations": verification_obligations,
            "blocking_dependencies": list(unresolved_blockers.values()),
            "rationale": (
                str(latest.get("rationale", ""))
                + (f"; {stop_reason}" if stop_reason else "")
            ),
            "stop_reason": stop_reason,
            "next_function_ids": unique_strings([
                *outstanding_roots, *outstanding_requests,
                *([pending] if pending and pending not in opened else []),
            ]),
        }
        if result[1]["context_complete"] and not result[1]["blocking_dependencies"]:
            self._context_cache[plan.plan_id] = result
        return result

    async def review(
        self,
        draft: HarnessDraft,
        plan: HarnessPlan,
        witness: ScenarioWitness,
        static_report: GateReport,
    ) -> GateReport:
        session_key = f"harness_verifier:{draft.manifest.harness_id}"
        # The independent reviewer must see the application source that the
        # generator used. Source is opened one function per turn in the same
        # session; a name-only plan and the generator's self-audit cannot prove
        # initialization, result handling, or cleanup.
        roots = unique_strings([
            *plan.entry_function_ids,
            *plan.required_function_ids,
        ])
        if not roots:
            roots = unique_strings(draft.context_function_ids)
        source_candidates = unique_strings(draft.context_function_ids)
        if not roots:
            return self._review_context_blocked(
                "independent source review has no indexed application function"
            )
        missing = [item for item in roots if item not in self.graph.bundle.functions]
        if missing:
            return self._review_context_blocked(
                f"independent source review cannot open required functions: {missing}"
            )
        opened: list[str] = []
        deferred_requests: deque[str] = deque()
        pending = roots[0] if roots else ""
        complete = not roots
        stop_reason = ""
        turn_limit = max(self.max_context_turns, len(roots))
        for _ in range(turn_limit):
            if not pending:
                break
            if pending in opened:
                stop_reason = f"independent source review repeated {pending}"
                break
            current = self.graph.get(pending)
            opened.append(pending)
            choices = {str(item["function_id"]): item for item in self.graph.frontier(opened)}
            for function_id in source_candidates:
                if function_id in self.graph.bundle.functions and function_id not in opened:
                    choices.setdefault(function_id, function_ref(self.graph.get(function_id)))
            for function_id in roots:
                if function_id not in opened:
                    choices.setdefault(function_id, function_ref(self.graph.get(function_id)))
            emit_trace(
                self.trace, "harness_verifier", "context_function_opened",
                f"{draft.manifest.harness_id}: opened {current.name}",
                harness_id=draft.manifest.harness_id,
                function=function_ref(current),
                opened_function_ids=list(opened),
            )
            response = await self.llm.complete_json(
                role="harness_verifier",
                instructions=(
                    "Independently inspect exactly this newly opened application function in the same "
                    "harness-review session. Check its relationship to the generated harness, including "
                    "input acquisition, initialization, result handling, and cleanup where the source "
                    "requires them. Do not infer missing lifecycle calls merely from their absence. "
                    "Request at most one source-linked function when another body is needed. "
                    "context_complete means the source needed for the independent HC01..HC16 review "
                    "has been inspected; it does not mean that the harness passes those checks."
                ),
                payload={
                    "current_function": self._opened_function_payload(current),
                    "opened_functions": [function_ref(self.graph.get(item)) for item in opened],
                    "candidate_functions": list(choices.values()),
                    **({
                        "harness_code": draft.code,
                        "harness_plan": _plan_payload(plan),
                        "scenario_witness": _witness_payload(witness, include_responses=False),
                    "static_findings": [
                        {"check_id": item.check_id, "status": item.status,
                         "evidence": item.evidence}
                        for item in static_report.checks
                        if item.status is not CheckStatus.PASS
                    ],
                    "checklist": [
                        {"check_id": key, "contract": CHECKLIST_CONTRACTS[key]}
                        for key in CHECKLIST_NAMES
                    ],
                    } if len(opened) == 1 else {}),
                },
                output_schema=SCENARIO_REVIEW_CONTEXT_SCHEMA,
                session_key=session_key,
            )
            requested = string_list(response.get("requested_function_ids"))
            if requested:
                resolved = resolve_source_linked_function(
                    requested[0], opened, list(choices.values()), self.graph,
                )
                if resolved and resolved not in deferred_requests:
                    deferred_requests.append(resolved)
                elif not resolved:
                    stop_reason = (
                        f"independent source review requested unavailable or "
                        f"unlinked function: {requested[0]}"
                    )
                    break
            forced = next((item for item in roots if item not in opened), "")
            if forced:
                pending = forced
                continue
            while deferred_requests and deferred_requests[0] in opened:
                deferred_requests.popleft()
            if deferred_requests:
                pending = deferred_requests.popleft()
                continue
            complete = bool(response.get("context_complete", False)) and not requested
            pending = ""
            if not complete:
                stop_reason = "independent source review left its context incomplete"
            break
        if pending and not stop_reason:
            stop_reason = "independent source review work budget exhausted"
        if stop_reason or not complete:
            return self._review_context_blocked(stop_reason or "independent source review incomplete")

        response = await self.llm.complete_json(
            role="harness_verifier",
            instructions=(
                "Independently audit the generated harness against HC01..HC16 and the supplied witness. "
                "Respect its proof status; a replayed request is not an attributed handler trace. "
                "Do not accept the generator's self-audit as evidence. Check that setup steps retain their order, "
                "fuzz bytes are the final raw external request, real target code is called, and harness-owned faults "
                "are not confused with target crashes. Return exactly one record per check."
            ),
            payload={
                "harness_code": draft.code,
                "manifest": _manifest_payload(draft.manifest),
                "harness_plan": _plan_payload(plan),
                "scenario_witness": _witness_payload(witness),
                "static_report": [
                    {"check_id": item.check_id, "status": item.status, "evidence": item.evidence}
                    for item in static_report.checks
                ],
                "opened_function_ids": opened,
            },
            output_schema=SCENARIO_REVIEW_SCHEMA,
            session_key=session_key,
        )
        by_id = {str(item.get("check_id", "")): item for item in object_list(response.get("checks"))}
        checks: list[GateCheck] = []
        for check_id in CHECKLIST_NAMES:
            raw = by_id.get(check_id)
            if raw is None:
                checks.append(GateCheck(
                    check_id, CHECKLIST_NAMES[check_id], CheckStatus.FAIL,
                    "independent review omitted this check", "perform the missing review",
                ))
                continue
            status_text = str(raw.get("status", "FAIL"))
            status = CheckStatus(status_text) if status_text in {item.value for item in CheckStatus} else CheckStatus.FAIL
            checks.append(GateCheck(
                check_id, CHECKLIST_NAMES[check_id], status,
                str(raw.get("evidence", "")), str(raw.get("remediation", "")),
            ))
        return GateReport(checks)

    @staticmethod
    def _review_context_blocked(reason: str) -> GateReport:
        return GateReport([
            GateCheck(
                "HC14", CHECKLIST_NAMES["HC14"], CheckStatus.FAIL,
                reason, "inspect the missing source before independent review",
            )
        ])


class ScenarioStaticHarnessGate:
    def __init__(self, graph: GraphStore):
        self.graph = graph

    def check(
        self,
        draft: HarnessDraft,
        plan: HarnessPlan,
        witness: ScenarioWitness,
    ) -> GateReport:
        code = draft.code
        semantic = _code_only(code)
        body = _fuzzer_function_body(semantic)
        data_name, size_name = _fuzzer_parameter_names(semantic)
        checks: list[GateCheck] = []

        def add(check_id: str, passed: bool, evidence: str, remediation: str = "") -> None:
            checks.append(GateCheck(
                check_id, CHECKLIST_NAMES[check_id],
                CheckStatus.PASS if passed else CheckStatus.FAIL,
                evidence, remediation,
            ))

        def defer(check_id: str, evidence: str) -> None:
            checks.append(GateCheck(
                check_id, CHECKLIST_NAMES[check_id], CheckStatus.WARN,
                evidence,
                "require request-correlated original-versus-harness validation before qualification",
            ))

        cleanup_issues = _resource_cleanup_issues(body)
        add("HC01", not cleanup_issues, "no unmatched per-iteration resource family" if not cleanup_issues else str(cleanup_issues))
        uaf = bool(re.search(r"(?:free\s*\((\w+)\)|delete\s+(\w+)).{0,300}\b(?:\1|\2)\b", semantic, re.DOTALL))
        add("HC02", not uaf, "no simple post-release reuse pattern" if not uaf else "textual post-release reuse")
        mutable_static = _has_mutable_static_object(semantic)
        isolation_visible = _execution_model_visible(
            semantic, draft.manifest.execution_model
        )
        isolation_required = (
            mutable_static
            or draft.manifest.execution_model == "loopback_network"
        )
        add(
            "HC03",
            not isolation_required or isolation_visible,
            "declared per-iteration isolation/reset is visible"
            if isolation_visible else
            "declared isolation/reset is not visible in harness code",
        )
        uses_input = bool(data_name and size_name and re.search(rf"\b{re.escape(data_name)}\b", body) and re.search(rf"\b{re.escape(size_name)}\b", body))
        add("HC04", uses_input, "Data and Size materially occur in LLVMFuzzerTestOneInput")
        unsafe_string = bool(data_name and re.search(rf"\b(?:strlen|strcpy|strcat|sprintf)\s*\([^;]*\b{re.escape(data_name)}\b", semantic))
        add("HC05", not unsafe_string, "no obvious unbounded string operation on fuzz bytes")
        indexed = bool(data_name and re.search(rf"\b{re.escape(data_name)}\s*\[", semantic))
        guarded = bool(size_name and re.search(rf"(?:if\s*\([^)]*\b{re.escape(size_name)}\b|\b{re.escape(size_name)}\b\s*[<>=])", semantic))
        add("HC06", not indexed or guarded, "direct input indexing is guarded" if indexed else "no direct input indexing")
        typed_deref = bool(data_name and re.search(rf"\*\s*\(\s*(?:u?int(?:16|32|64)_t|size_t)\s*\*\s*\)\s*{re.escape(data_name)}", semantic))
        add("HC07", not typed_deref, "no obvious unaligned typed dereference")

        target = plan.required_function_ids[-1] if plan.required_function_ids else ""
        native_builder = any(
            "harnesscreator.runtime.native_build" in part
            for part in draft.manifest.build_command
        )
        invocation_aliases = (
            {"main": ("hc_native_original_main",)} if native_builder else {}
        )
        entrances = (
            _invoked_application_entrances_to(
                semantic, code, self.graph, target, invocation_aliases
            ) if target in self.graph.bundle.functions else []
        )
        final_entry_ids = (
            [plan.fuzz_entry_function_id]
            if plan.fuzz_entry_function_id in self.graph.bundle.functions
            else list(plan.entry_function_ids)
        )
        entry_entrances = (
            _invoked_application_entrances_through(
                semantic,
                code,
                self.graph,
                target,
                final_entry_ids,
                invocation_aliases,
            )
            if target in self.graph.bundle.functions
            else []
        )
        # A receive function commonly returns bytes to its caller, which then
        # calls the parser/handler.  In that shape the Entry and handler are
        # sibling calls: no call-graph path can *cross* the Entry.  Report the
        # missing value-flow proof accurately instead of claiming that the
        # generated harness necessarily bypasses the Entry.  The native
        # builder renames the product's main symbol at link time; this is a
        # builder contract, not a product-specific source-name guess.
        native_main_called = (
            native_builder
            and _function_invoked(semantic, "hc_native_original_main")
        )
        sibling_entry_callers: list[str] = []
        sibling_buffer_handoffs: list[str] = []
        if target in self.graph.bundle.functions and not entry_entrances:
            invoked_entrances = [
                function for function in self.graph.bundle.functions.values()
                if _function_or_source_alias_invoked(
                    semantic, code, function.name
                ) or (native_main_called and function.name == "main")
            ]
            for entry_id in final_entry_ids:
                if entry_id not in self.graph.bundle.functions:
                    continue
                for handoff in direct_sibling_buffer_handoffs(
                    self.graph, entry_id, target
                ):
                    if not any(
                        self.graph.shortest_path(
                            entrance.function_id, handoff.caller_function_id,
                            max_depth=64,
                        ) for entrance in invoked_entrances
                    ):
                        continue
                    caller = self.graph.get(handoff.caller_function_id)
                    sibling_buffer_handoffs.append(
                        f"{caller.qualified_name or caller.name}:"
                        f"{handoff.entry_call_line} -> "
                        f"{self.graph.get(target).qualified_name or self.graph.get(target).name}:"
                        f"{handoff.target_call_line} shares local {handoff.buffer_name}; "
                        f"{handoff.acquisition_api} output at Entry:{handoff.acquisition_line}"
                    )
                for parent in self.graph.callers(entry_id):
                    if not self.graph.shortest_path(
                        parent.function_id, target, max_depth=64
                    ):
                        continue
                    for entrance in invoked_entrances:
                        if self.graph.shortest_path(
                            entrance.function_id, parent.function_id, max_depth=64
                        ):
                            sibling_entry_callers.append(
                                parent.qualified_name or parent.name
                            )
                            break
        sibling_entry_callers = unique_strings(sibling_entry_callers)
        sibling_buffer_handoffs = unique_strings(sibling_buffer_handoffs)
        correlated_sibling_route = bool(
            sibling_buffer_handoffs
            and _witness_confirms_fuzz_entry_and_target(
                witness, plan, final_entry_ids, target
            )
        )
        source_candidate_routes = (
            _source_candidate_return_to_table_routes(
                semantic, code, self.graph, target, final_entry_ids
            )
            if target in self.graph.bundle.functions else []
        )
        entry_names = unique_strings(
            self.graph.get(function_id).name
            for function_id in final_entry_ids
            if function_id in self.graph.bundle.functions
        )
        dynamic_final = bool(plan.fuzz_step.request_binding_uses)
        raw_aliases = (
            _dynamic_fuzz_mapping_present(
                semantic, body, data_name, size_name, plan.fuzz_step
            )
            if dynamic_final else
            _raw_fuzz_aliases_present(semantic, data_name, size_name)
        )
        final_delivery_position = _fuzz_request_delivery_position(
            body, entry_names
        )
        if correlated_sibling_route and not entry_entrances:
            defer(
                "HC08",
                "original request-correlated trace and AST identify a sibling "
                "Entry-to-handler buffer handoff; generated-harness delivery "
                f"remains unproven: {sibling_buffer_handoffs}",
            )
        else:
            add(
                "HC08",
                bool(entry_entrances),
                (
                    "real application entrances preserve Entry-to-target path: "
                    f"{entry_entrances}"
                    if entry_entrances else
                    "Entry and target have a reachable common caller, but are sibling "
                    "calls rather than a call path; byte flow and generated-harness "
                    f"delivery remain unproven: {sibling_entry_callers}; "
                    f"AST direct-buffer handoff candidates (not proof): {sibling_buffer_handoffs}"
                    if sibling_entry_callers else
                    "source-located Entry-return-table route is only a possible "
                    f"handler path; request-specific selection is unproven: {source_candidate_routes}"
                    if source_candidate_routes else
                    "an application function reaches the target, but the invoked path "
                    f"bypasses every witnessed Entry; target-only entrances={entrances}"
                ),
            )
        audit = _audit_by_id(draft.self_audit)
        prelude_marker = (
            plan.setup_steps[0].connection_prelude_marker_hex
            if plan.setup_steps else plan.fuzz_step.connection_prelude_marker_hex
        )
        prelude_visible = _prelude_check_before_delivery(
            code, body, prelude_marker, final_delivery_position,
        )
        add(
            "HC09", _audit_passes(audit, "HC09") and prelude_visible,
            "startup order and server-first line check visible" if prelude_visible
            else "original server-first line was not received and checked before request delivery",
        )
        raw_request_mapping = plan.input_mapping in {
            "raw_final_request", "raw_final_request_with_runtime_bindings",
            "raw_fuzz_request", "raw_fuzz_request_with_runtime_bindings",
        }
        # A transport write in a helper/callback is only a lead.  The static
        # gate cannot follow Data through an arbitrary thread argument.  This
        # may advance only as WARN and only if the original request has an
        # exact correlated Entry/handler witness. The differential gate must
        # later observe the fuzz bytes at that Entry in the built harness.
        transport_write_visible = any(
            _function_invoked(semantic, callee)
            for callee in ("send", "sendto", "write", "writev", "fwrite")
        )
        if (
            correlated_sibling_route and uses_input and raw_request_mapping
            and raw_aliases and transport_write_visible
            and not (entry_entrances and final_delivery_position >= 0)
        ):
            defer(
                "HC10",
                "Data/Size aliases and a transport write are visible, but "
                "callback/helper byte delivery is not proven by the static "
                f"gate; sibling source candidates: {sibling_buffer_handoffs}",
            )
        else:
            add(
                "HC10",
                uses_input and raw_request_mapping and bool(entry_entrances)
                and raw_aliases and final_delivery_position >= 0,
                (
                    "the Data/Size aliases are delivered as one raw final request through a witnessed Entry"
                    if (
                        entry_entrances and raw_aliases
                        and final_delivery_position >= 0
                    ) else
                    "raw fuzz bytes are not explicitly bound and delivered through the witnessed Entry path"
                    + (
                        f"; AST direct-buffer handoff candidates (not proof): {sibling_buffer_handoffs}"
                        if sibling_buffer_handoffs else ""
                    )
                ),
            )
        add("HC11", witness.status is ScenarioStatus.PROVEN_RUNTIME, "scenario lifecycle was observed in the original program")
        add("HC12", _audit_passes(audit, "HC12"), "generator records concrete result/response handling")
        add("HC13", not cleanup_issues and _audit_passes(audit, "HC13"), "cleanup audit and resource-family check pass")
        missing = [item for item in plan.required_function_ids if item not in self.graph.bundle.functions]
        unopened = [item for item in plan.required_function_ids if item not in draft.context_function_ids]
        add("HC14", not missing and not unopened, f"missing={missing}; unopened={unopened}")
        setup_definition_positions = [
            _setup_step_position(
                semantic,
                step.index,
                step.request_template_hex or step.request_hex,
            )
            for step in plan.setup_steps
        ]
        setup_execution_positions: list[int] = []
        for offset, step in enumerate(plan.setup_steps):
            mapped_entry = (
                plan.setup_entry_function_ids[offset]
                if offset < len(plan.setup_entry_function_ids)
                else ""
            )
            setup_entry_names = (
                [self.graph.get(mapped_entry).name]
                if mapped_entry in self.graph.bundle.functions
                else entry_names
            )
            request_name = (
                f"hc_setup_request_{step.index}"
                if step.request_binding_uses else
                f"hc_setup_step_{step.index}"
            )
            setup_execution_positions.append(
                _named_request_delivery_position(
                    body,
                    request_name,
                    setup_entry_names,
                    extent_name=f"hc_setup_step_{step.index}",
                )
            )
        setup_names_present = all(
            position >= 0 for position in setup_definition_positions
        )
        setup_executed = all(position >= 0 for position in setup_execution_positions)
        setup_ordered = (
            setup_names_present
            and setup_executed
            and setup_execution_positions == sorted(setup_execution_positions)
            and (
                not setup_execution_positions
                or final_delivery_position > max(setup_execution_positions)
            )
        )
        post_definition_positions = [
            _setup_step_position(
                semantic, step.index, step.request_template_hex or step.request_hex,
                prefix="post",
            ) for step in plan.post_steps
        ]
        post_execution_positions: list[int] = []
        for offset, step in enumerate(plan.post_steps):
            mapped_entry = (
                plan.post_entry_function_ids[offset]
                if offset < len(plan.post_entry_function_ids) else ""
            )
            post_entry_names = (
                [self.graph.get(mapped_entry).name]
                if mapped_entry in self.graph.bundle.functions else entry_names
            )
            post_execution_positions.append(_named_request_delivery_position(
                body, f"hc_post_step_{step.index}", post_entry_names,
            ))
        post_ordered = (
            all(index >= 0 for index in post_definition_positions)
            and all(index >= 0 for index in post_execution_positions)
            and post_execution_positions == sorted(post_execution_positions)
            and (not post_execution_positions or min(post_execution_positions) > final_delivery_position)
        )
        add(
            "HC15",
            setup_ordered and post_ordered,
            "all witnessed setup byte arrays execute in order before the final fuzz request"
            if setup_ordered else
            "setup byte arrays missing, unused, or reordered: "
            f"definitions={setup_definition_positions}, uses={setup_execution_positions}",
        )
        setup_oracle_positions = [
            _success_oracle_check_position(
                semantic, body, step.index, step.expected_success_markers_hex
            )
            for step in plan.setup_steps
        ]
        setup_response_positions = [
            _response_acquisition_position(body, step.index)
            for step in plan.setup_steps
        ]
        dynamic_binding_ok, dynamic_binding_evidence = _dynamic_binding_flow_check(
            body,
            [*plan.setup_steps, plan.fuzz_step],
            setup_execution_positions,
            setup_oracle_positions,
            final_delivery_position,
        )
        oracle_ordered = all(
            setup_response_positions[index] > setup_execution_positions[index]
            and oracle_position > setup_response_positions[index]
            and oracle_position < (
                setup_execution_positions[index + 1]
                if index + 1 < len(setup_execution_positions)
                else final_delivery_position
            )
            for index, oracle_position in enumerate(setup_oracle_positions)
        )
        post_oracle_positions = [
            _success_oracle_check_position(semantic, body, step.index,
                                           step.expected_success_markers_hex)
            for step in plan.post_steps
        ]
        post_response_positions = [
            _response_acquisition_position(body, step.index)
            for step in plan.post_steps
        ]
        post_oracles_valid = all(
            post_execution_positions[i] >= 0
            and post_response_positions[i] > post_execution_positions[i]
            and post_oracle_positions[i] > post_response_positions[i]
            and (i + 1 == len(post_execution_positions)
                 or post_oracle_positions[i] < post_execution_positions[i + 1])
            for i in range(len(post_execution_positions))
        )
        add(
            "HC16",
            setup_ordered and post_ordered and post_oracles_valid
            and all(position >= 0 for position in setup_response_positions)
            and all(position >= 0 for position in setup_oracle_positions)
            and oracle_ordered
            and dynamic_binding_ok
            and witness.status is ScenarioStatus.PROVEN_RUNTIME,
            "setup requests and their source-derived success oracles are executed in order; "
            f"witness status is {witness.status}"
            if (
                setup_ordered
                and all(position >= 0 for position in setup_response_positions)
                and all(position >= 0 for position in setup_oracle_positions)
                and oracle_ordered
                and dynamic_binding_ok
            ) else
            "setup success-oracle checks are missing or out of order: "
            f"responses={setup_response_positions}; oracles={setup_oracle_positions}; "
            f"dynamic={dynamic_binding_evidence}",
        )

        if (plan.boundary_contract and
            draft.manifest.execution_model != plan.reset_strategy):
            checks.append(GateCheck(
                "HC21", "Execution boundary contract", CheckStatus.FAIL,
                f"plan={plan.reset_strategy}, generated={draft.manifest.execution_model}",
                "use the witnessed external transport; do not silently switch to an internal entry",
            ))
        if draft.generation_blockers:
            checks.append(GateCheck(
                "HC17", "Generation blockers", CheckStatus.FAIL,
                "; ".join(draft.generation_blockers), "resolve the evidenced blocker",
            ))
        expected_audits = set(CHECKLIST_NAMES)
        # HC20 checks whether the generator reported every principle honestly.
        # A source-backed WARN is an unresolved obligation, not a malformed
        # self-audit or permission to qualify the harness.  Individual checks
        # and the independent/runtime gates still decide that obligation.
        # The generator adds one diagnostic row when it explicitly refuses
        # to emit source. HC17 owns that blocker; it is not a seventeenth
        # checklist item or a malformed HC01..HC16 self-audit.
        diagnostic_ids = (
            {"generation_blockers"}
            if draft.generation_blockers
            and audit.get("generation_blockers", {}).get("status") == "FAIL"
            else set()
        )
        if set(audit) - diagnostic_ids != expected_audits or not all(
            _audit_is_recorded(audit, item) for item in expected_audits
        ):
            checks.append(GateCheck(
                "HC20", "Generator self-audit", CheckStatus.FAIL,
                f"expected={sorted(expected_audits)}; received={sorted(audit)}",
                "return exactly one evidence-bearing PASS or WARN for HC01..HC16; a FAIL remains a blocker",
            ))
        return GateReport(checks)


def _witness_confirms_fuzz_entry_and_target(
    witness: ScenarioWitness,
    plan: HarnessPlan,
    entry_ids: list[str],
    target_id: str,
) -> bool:
    """Require an exact original request trace before deferring a static proof.

    This says nothing about the generated harness. Its byte delivery is a
    separate obligation for differential verification of the built binary.
    """
    if witness.status is not ScenarioStatus.PROVEN_RUNTIME or not target_id:
        return False
    if witness.witness_id != plan.witness_id or witness.target_action_id != plan.target_action_id:
        return False
    if not entry_ids:
        return False
    for observation in witness.observations:
        if (
            observation.index != plan.fuzz_step.index
            or observation.action_id != plan.target_action_id
            or observation.request_hex != plan.fuzz_step.request_hex
            or observation.entry_function_id not in entry_ids
            or observation.target_function_id != target_id
            or observation.target_probe != "request-correlated-jsonl-v1"
            or not observation.success
            or not observation.entry_reached
            or not observation.target_reached
            or not response_hex_attested(observation.probe_trace, observation.response_hex)
        ):
            continue
        prefix = f"acquire:{observation.entry_function_id}:"
        for event in observation.probe_trace:
            if not event.startswith(prefix):
                continue
            request_id = event[len(prefix):].split(":", 1)[0]
            if request_id and f"handler:{target_id}:{request_id}" in observation.probe_trace:
                return True
    return False


class ScenarioHarnessVerifierSeedPlanner:
    def __init__(self, llm: LLMProvider):
        self.llm = llm

    async def close_session(self, draft: HarnessDraft) -> None:
        await close_llm_session(self.llm, f"harness_verifier:{draft.manifest.harness_id}")

    async def run(
        self,
        draft: HarnessDraft,
        plan: HarnessPlan,
        witness: ScenarioWitness,
        *,
        feedback: list[str] | None = None,
        existing: list[SeedSpec] | None = None,
    ) -> list[SeedSpec]:
        response = await self.llm.complete_json(
            role="harness_verifier",
            instructions=(
                "Propose raw *fuzz-step* inputs for adversarial harness validation only when the "
                "witnessed request or opened source supports a concrete mutation. The exact "
                "witnessed request is added by the runner; do not repeat it. Consider truncation, "
                "extension, malformed lengths, embedded NUL, and field boundaries only where "
                "the observed format or cited source makes that case meaningful. Do not prepend "
                "a selector: one ScenarioWitness maps to one harness. "
                "Each seed must remain raw bytes accepted at the original Entry and be at most the manifest max_size. "
                "Follow source-cited request_rules when making structurally valid length/CRC samples; "
                "also include deliberately invalid relationship cases to reach parser error handling. "
                "Do not infer a missing checksum or use a post-step request as the fuzz seed."
            ),
            payload={
                "manifest": _manifest_payload(draft.manifest),
                "harness_plan": _plan_payload(plan),
                "witness_fuzz_request_hex": (
                    plan.fuzz_step.request_template_hex
                    or plan.fuzz_step.request_hex
                ),
                "feedback": feedback or [],
                "existing": [item.data_hex for item in (existing or [])],
            },
            output_schema=SCENARIO_SEED_SCHEMA,
            session_key=f"harness_verifier:{draft.manifest.harness_id}",
        )
        result: list[SeedSpec] = [SeedSpec(
            name="runtime-witness-fuzz-request",
            data_hex=(
                plan.fuzz_step.request_template_hex
                or plan.fuzz_step.request_hex
            ),
            rationale="exact fuzz-step request from the original-program scenario",
            check_ids=["HC04", "HC10", "HC11", "HC16"],
        )]
        seen = {result[0].data_hex}
        for index, raw in enumerate(object_list(response.get("seeds"))):
            data_hex = str(raw.get("data_hex", "")).lower()
            if data_hex in seen or len(data_hex) % 2 or len(data_hex) > draft.manifest.max_size * 2:
                continue
            try:
                bytes.fromhex(data_hex)
            except ValueError:
                continue
            seen.add(data_hex)
            result.append(SeedSpec(
                name=re.sub(r"[^A-Za-z0-9_.-]+", "-", str(raw.get("name", f"seed-{index}")))[:80],
                data_hex=data_hex,
                rationale=str(raw.get("rationale", "")),
                check_ids=unique_strings(string_list(raw.get("check_ids"))),
            ))
        return result


def action_harness_function_ids(
    action: ExternalActionSchema,
    entry_function_id: str = "",
) -> tuple[str, ...]:
    """Select source-located Action path evidence, not the inspection history.

    ``inspected_function_ids`` records every function opened while exploring
    alternatives.  It must not become a list of required harness calls or
    context roots.  Keep the acquisition, dispatch and handler anchors plus
    source locations cited for the selected Action and its observed outcome.
    The handler stays last because plan construction uses that position as
    the target anchor.
    """
    handler = action.handler_function_id
    cited = [
        evidence.function_id
        for evidence in [
            *action.evidence,
            *action.success_evidence,
            *action.failure_evidence,
            *(evidence for binding in action.response_bindings
              for evidence in binding.evidence),
        ]
        if evidence.line is not None and evidence.function_id != handler
    ]
    entry = entry_function_id or action.entry_function_id
    # The entry and target positions are semantic anchors.  A branchless
    # action may use its handler as the dispatcher, and an entry can itself
    # be the handler.  Deduplicate only the intermediate functions so the
    # final position always identifies the actual target handler.
    intermediate = [
        function_id for function_id in unique_strings([
            action.dispatcher_function_id,
            *cited,
        ])
        if function_id not in {entry, handler}
    ]
    return tuple(function_id for function_id in [entry, *intermediate, handler] if function_id)


def build_harness_plan(
    witness: ScenarioWitness,
    *,
    action_function_ids: dict[str, tuple[str, ...]],
    action_schemas: dict[str, ExternalActionSchema] | None = None,
    function_sources: dict[str, str] | None = None,
    build_target: str = "UNRESOLVED",
    allow_observed: bool = False,
    allow_unproven: bool = False,
) -> HarnessPlan:
    allowed = witness.status is ScenarioStatus.PROVEN_RUNTIME or (
        allow_observed and witness.status in {ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME}
    ) or (allow_unproven and witness.status in {ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED})
    if not allowed or not witness.steps:
        raise ValueError("HarnessPlan requires evidence-backed runtime witness or explicit source-only draft opt-in")
    required: list[str] = []
    entries: list[str] = []
    step_entries: list[str] = []
    for step in witness.steps:
        function_ids = action_function_ids.get(step.action_id, ())
        if function_ids:
            entries.append(function_ids[0])
            step_entries.append(function_ids[0])
            required.extend(function_ids[1:])
        else:
            step_entries.append("")
    target_tuple = action_function_ids.get(witness.target_action_id, ())
    target_handler = target_tuple[-1] if target_tuple else ""
    target_schema = action_schemas.get(witness.target_action_id) if action_schemas else None
    if target_schema and target_handler != target_schema.handler_function_id:
        raise ValueError(
            "HarnessPlan target anchor differs from the selected Action handler"
        )
    required = unique_strings(required)
    if target_handler in required:
        required.remove(target_handler)
        required.append(target_handler)
    fuzz_index = (witness.fuzz_step_index if witness.fuzz_step_index >= 0
                  else len(witness.steps) - 1)
    if not 0 <= fuzz_index < len(witness.steps):
        raise ValueError("fuzz index is outside the original scenario")
    if witness.steps[fuzz_index].action_id != witness.target_action_id:
        raise ValueError("fuzz step must be the scenario target action")
    fuzz_step = witness.steps[fuzz_index]
    first_marker = witness.steps[0].connection_prelude_marker_hex
    if first_marker and not any(
        line.startswith(bytes.fromhex(first_marker))
        for line in bytes.fromhex(witness.connection_prelude_hex).splitlines(keepends=True)
    ):
        raise ValueError("HarnessPlan requires an observed server-first line before request delivery")
    final_size = len(bytes.fromhex(fuzz_step.request_hex))
    # A network transport witness preserves the original inbound interface.
    # No internal entry may silently bypass its parser/authorization guards.
    # The source-linked optimization is a later, separately audited decision.
    boundary = {
        "mode": (
            "original_input_transport" if witness.channel in {"tcp", "udp", "unix_stream", "stdin"}
            else "original_one_shot_process_input" if witness.channel in {"file", "argv", "env"}
            else "unsupported_transport"
        ),
        "external_input_function_id": step_entries[fuzz_index],
        "selected_function_id": step_entries[fuzz_index],
        "transport": witness.channel,
        "connection_prelude_hex": witness.connection_prelude_hex,
        "connection_prelude_marker_hex": first_marker,
        "status": (
            "SOURCE_ONLY_UNVERIFIED" if witness.status in {ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED}
            else "OBSERVED_ONLY" if witness.status is not ScenarioStatus.PROVEN_RUNTIME
            else "SOURCE_AND_RUNTIME_EVIDENCED"
        ),
        "internal_boundary_is_approved": False,
        "reset_is_verified": False,
        "candidate_boundaries": [
            {
                "kind": "original_transport",
                "preserves_external_parser": True,
                "requires": ["original initialization", "per-iteration lifecycle isolation", "real input delivery"],
                "proof": "OPEN",
            },
            {
                "kind": "source_function_entry",
                "preserves_external_parser": "UNKNOWN",
                "requires": ["demonstrate equivalent input-to-target dispatch", "complete initializer closure", "reset globals and resources"],
                "proof": "OPEN",
            },
        ],
        "obligations": [
            "selected entry must preserve original parser and authorization checks",
            "generated code must initialize and reset the required runtime state",
            "in-process concurrency/resource isolation needs independent verification",
            *(["one-shot file/argv/env replay does not prove libFuzzer in-process reset or execution equivalence"]
              if witness.channel in {"file", "argv", "env"} else []),
        ],
    }
    return HarnessPlan(
        plan_id=stable_id("harness-plan", witness.witness_id),
        witness_id=witness.witness_id,
        scenario_id=witness.scenario_id,
        target_action_id=witness.target_action_id,
        setup_steps=list(witness.steps[:fuzz_index]),
        fuzz_step=fuzz_step,
        post_steps=list(witness.steps[fuzz_index + 1:]),
        fuzz_step_index=fuzz_index,
        required_function_ids=required,
        entry_function_ids=unique_strings(entries),
        input_mapping=(
            ("raw_fuzz_request_with_runtime_bindings" if witness.steps[fuzz_index + 1:]
             else "raw_final_request_with_runtime_bindings")
            if fuzz_step.request_binding_uses
            else ("raw_fuzz_request" if witness.steps[fuzz_index + 1:]
                  else "raw_final_request")
        ),
        reset_strategy="loopback_network" if witness.channel in {"tcp", "udp", "unix_stream"} else "in_process_reset",
        build_target=build_target,
        min_size=0,
        max_size=max(4096, final_size * 4, 1),
        setup_entry_function_ids=step_entries[:fuzz_index],
        fuzz_entry_function_id=step_entries[fuzz_index],
        post_entry_function_ids=step_entries[fuzz_index + 1:],
        boundary_contract=boundary,
        required_source_files=unique_strings(
            function_sources[identifier]
            for identifier in [*required, *entries]
            if function_sources and identifier in function_sources
        ),
        request_rules=request_ir_summary(action_schemas[witness.target_action_id].fields)
        if action_schemas and witness.target_action_id in action_schemas else [],
    )


def _plan_payload(plan: HarnessPlan) -> dict[str, Any]:
    return {
        "plan_id": plan.plan_id,
        "witness_id": plan.witness_id,
        "scenario_id": plan.scenario_id,
        "target_action_id": plan.target_action_id,
        "setup_steps": [_step_payload(item) for item in plan.setup_steps],
        "fuzz_step": _step_payload(plan.fuzz_step),
        "fuzz_step_index": plan.fuzz_step_index,
        "post_steps": [_step_payload(item) for item in plan.post_steps],
        "boundary_contract": plan.boundary_contract,
        "request_rules": plan.request_rules,
        "required_source_files": plan.required_source_files,
        "required_function_ids": plan.required_function_ids,
        "entry_function_ids": plan.entry_function_ids,
        "setup_entry_function_ids": plan.setup_entry_function_ids,
        "fuzz_entry_function_id": plan.fuzz_entry_function_id,
        "input_mapping": plan.input_mapping,
        "reset_strategy": plan.reset_strategy,
        "build_target": plan.build_target,
        "min_size": plan.min_size,
        "max_size": plan.max_size,
    }


def _witness_payload(
    witness: ScenarioWitness, *, include_responses: bool = True
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "witness_id": witness.witness_id,
        "scenario_id": witness.scenario_id,
        "target_action_id": witness.target_action_id,
        "steps": [_step_payload(item) for item in witness.steps],
        "fuzz_step_index": witness.fuzz_step_index,
        "channel": witness.channel,
        "status": witness.status,
        "rationale": witness.rationale,
        "connection_prelude_hex": witness.connection_prelude_hex,
    }
    if include_responses:
        payload["observations"] = [
            {
                "index": item.index, "action_id": item.action_id,
                "response_hex": item.response_hex, "success": item.success,
                "detail": item.detail,
                "extracted_bindings": item.extracted_bindings,
            }
            for item in witness.observations
        ]
    return payload


def _step_payload(step: Any) -> dict[str, Any]:
    return {
        "index": step.index,
        "action_id": step.action_id,
        "entry_id": step.entry_id,
        "request_hex": step.request_hex,
        "request_template_hex": step.request_template_hex or step.request_hex,
        "bindings": step.bindings,
        "expected_success_markers_hex": step.expected_success_markers_hex,
        "connection_prelude_marker_hex": step.connection_prelude_marker_hex,
        "request_binding_uses": [
            {
                "binding": item.binding,
                "binding_symbol": _binding_symbol(item.binding),
                "offset": item.offset,
                "width": item.width,
                "producer_step_index": item.producer_step_index,
                "encoding": item.encoding,
            }
            for item in step.request_binding_uses
        ],
        "response_binding_extractors": [
            {
                "binding": item.binding,
                "binding_symbol": _binding_symbol(item.binding),
                "offset": item.offset,
                "width": item.width,
                "encoding": item.encoding,
                "evidence": item.evidence,
            }
            for item in step.response_binding_extractors
        ],
    }


def _binding_symbol(binding: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_]+", "_", binding).strip("_")[:32]
    if not readable or readable[0].isdigit():
        readable = f"value_{readable}" if readable else "value"
    suffix = stable_id("binding", binding).split("-", 1)[1][:8]
    return f"hc_binding_{readable}_{suffix}"


def _manifest_payload(manifest: HarnessManifest) -> dict[str, Any]:
    return {
        "harness_id": manifest.harness_id,
        "scenario_id": manifest.scenario_id,
        "build_target": manifest.build_target,
        "execution_model": manifest.execution_model,
        "min_size": manifest.min_size,
        "max_size": manifest.max_size,
        "expected_anchors": manifest.expected_anchors,
        "expected_consumers": manifest.expected_consumers,
    }


def _audit_by_id(values: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for item in values:
        check_id = str(item.get("check_id", ""))
        if check_id in result:
            duplicates.add(check_id)
        result[check_id] = item
    for check_id in duplicates:
        result[check_id] = {"check_id": check_id, "status": "FAIL", "evidence": "duplicate audit"}
    return result


def _audit_passes(audit: dict[str, dict[str, Any]], check_id: str) -> bool:
    item = audit.get(check_id, {})
    return str(item.get("status", "")) == "PASS" and bool(str(item.get("evidence", "")).strip())


def _audit_is_recorded(audit: dict[str, dict[str, Any]], check_id: str) -> bool:
    item = audit.get(check_id, {})
    return (
        str(item.get("status", "")) in {"PASS", "WARN"}
        and bool(str(item.get("evidence", "")).strip())
    )


def _setup_step_position(code: str, index: int, data_hex: str, *, prefix: str = "setup") -> int:
    """Locate one named setup/post array and its exact witnessed bytes."""

    match = re.search(rf"\bhc_{re.escape(prefix)}_step_{index}\b", code)
    if match is None:
        return -1
    window = code[match.start():match.start() + max(2048, len(data_hex) * 8)]
    expected = bytes.fromhex(data_hex)
    cursor = 0
    for value in expected:
        token = re.search(rf"0[xX]0*{value:02x}\b", window[cursor:], re.IGNORECASE)
        if token is None:
            return -1
        cursor += token.end()
    return match.start()


def _named_request_delivery_position(
    body: str,
    buffer_name: str,
    entry_names: list[str],
    *,
    extent_name: str | None = None,
) -> int:
    """Find delivery of a fixed request and its exact array extent."""

    callees = unique_strings([
        *entry_names,
        "send", "sendto", "write", "fwrite",
    ])
    extent = extent_name or buffer_name
    size_pattern = re.compile(
        rf"\bsizeof\s*(?:\(\s*{re.escape(extent)}\s*\)|"
        rf"\s+{re.escape(extent)}\b)"
    )
    positions: list[int] = []
    for callee in callees:
        for position, arguments in _call_arguments(body, callee):
            if (
                re.search(rf"\b{re.escape(buffer_name)}\b", arguments)
                and size_pattern.search(arguments)
            ):
                positions.append(position)
    return min(positions) if positions else -1


def _prelude_check_before_delivery(
    code: str,
    body: str,
    marker_hex: str,
    delivery_position: int,
) -> bool:
    """Recognize an exact server-first line checked before a fuzzed request.

    This is a narrow static observation, not proof that the worker receives
    the request or that a response belongs to it.
    """

    if not marker_hex:
        return True
    if delivery_position < 0:
        return False
    raw_body = _fuzzer_function_body(code)
    marker_definition = re.search(
        r'\bhc_connection_prelude_marker\s*\[\s*\]\s*=\s*'
        r'(?P<literal>"(?:\\.|[^"\\])*")\s*;',
        raw_body,
    )
    if marker_definition is None:
        return False
    try:
        literal = ast.literal_eval(marker_definition.group("literal"))
        if not isinstance(literal, str) or literal.encode("latin-1") != bytes.fromhex(marker_hex):
            return False
    except (SyntaxError, ValueError, UnicodeEncodeError):
        return False

    receive_positions = [
        position
        for callee in ("read", "recv", "SSL_read", "fread")
        for position, arguments in _call_arguments(body, callee)
        if re.search(r"\bhc_connection_prelude_response\b", arguments)
    ]
    if not receive_positions:
        return False

    size_mismatch = re.compile(
        r"\bhc_connection_prelude_response_size\s*!=\s*"
        r"sizeof\s*\(\s*hc_connection_prelude_marker\s*\)\s*-\s*1\b"
    )
    memcmp_mismatch = re.compile(
        r"\bmemcmp\s*\(\s*hc_connection_prelude_response\s*,\s*"
        r"hc_connection_prelude_marker\s*,\s*"
        r"sizeof\s*\(\s*hc_connection_prelude_marker\s*\)\s*-\s*1\s*\)\s*!=\s*0\b"
    )
    contains_mismatch = re.compile(
        r"!\s*hc_response_contains\s*\(\s*hc_connection_prelude_response\s*,\s*"
        r"hc_connection_prelude_response_size\s*,\s*"
        r"(?:\(\s*const\s+uint8_t\s*\*\s*\)\s*)?"
        r"hc_connection_prelude_marker\s*,\s*"
        r"sizeof\s*\(\s*hc_connection_prelude_marker\s*\)\s*-\s*1\s*\)"
    )
    for position, condition in _control_conditions(body, "if"):
        if position >= delivery_position or "&&" in condition:
            continue
        if not (
            (size_mismatch.search(condition) and memcmp_mismatch.search(condition))
            or contains_mismatch.search(condition)
        ):
            continue
        opening = body.find("(", position)
        closing = _matching_paren(body, opening)
        if (
            marker_definition.start() < position
            and any(receive_position < position for receive_position in receive_positions)
            and closing >= 0
            and re.match(r"\s*(?:\{\s*)?return\b", body[closing + 1:])
        ):
            return True
    return False


def _success_oracle_check_position(
    code: str,
    body: str,
    index: int,
    markers_hex: list[str],
) -> int:
    name = f"hc_success_step_{index}"
    pattern = rf"\b{re.escape(name)}\b"
    if len(list(re.finditer(pattern, code))) < 2 or not re.search(pattern, body):
        return -1
    definition = re.search(rf"\b{re.escape(name)}\b", code)
    if definition is None:
        return -1
    window = code[definition.start():definition.start() + 4096]
    exact_marker = False
    for marker_hex in markers_hex:
        marker = bytes.fromhex(marker_hex)
        cursor = 0
        for value in marker:
            token = re.search(
                rf"0[xX]0*{value:02x}\b", window[cursor:], re.IGNORECASE
            )
            if token is None:
                break
            cursor += token.end()
        else:
            exact_marker = True
            break
    if not exact_marker:
        return -1

    size_pattern = re.compile(
        rf"\bsizeof\s*(?:\(\s*{re.escape(name)}\s*\)|\s+{re.escape(name)}\b)"
    )
    response_name = f"hc_response_step_{index}"
    response_size_name = f"hc_response_step_{index}_size"
    comparison_pattern = re.compile(
        r"\b(?:hc_response_contains|memcmp|strncmp|strcmp|memmem|strstr|equal)\s*\("
    )
    for position, condition in _control_conditions(body, "if"):
        if (
            re.search(pattern, condition)
            and size_pattern.search(condition)
            and comparison_pattern.search(condition)
            and re.search(rf"\b{re.escape(response_name)}\b", condition)
            and re.search(rf"\b{re.escape(response_size_name)}\b", condition)
        ):
            return position
    return -1


def _response_acquisition_position(body: str, index: int) -> int:
    response_name = f"hc_response_step_{index}"
    size_name = f"hc_response_step_{index}_size"
    for callee in (
        "read", "recv", "recvfrom", "recvmsg", "fread", "SSL_read",
    ):
        for position, arguments in _call_arguments(body, callee):
            if not re.search(rf"\b{re.escape(response_name)}\b", arguments):
                continue
            prefix = body[max(0, position - 192):position]
            if (
                re.search(rf"\b{re.escape(size_name)}\b\s*=\s*$", prefix)
                or re.search(
                    rf"\b{re.escape(size_name)}\b[^;=]{{0,80}}=\s*$",
                    prefix,
                )
            ):
                return position
    return -1


def _call_arguments(body: str, callee: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for match in re.finditer(rf"\b{re.escape(callee)}\s*\(", body):
        opening = body.find("(", match.start())
        closing = _matching_paren(body, opening)
        if closing >= 0:
            result.append((match.start(), body[opening + 1:closing]))
    return result


def _control_conditions(body: str, keyword: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for match in re.finditer(rf"\b{re.escape(keyword)}\s*\(", body):
        opening = body.find("(", match.start())
        closing = _matching_paren(body, opening)
        if closing >= 0:
            result.append((match.start(), body[opening + 1:closing]))
    return result


def _matching_paren(text: str, opening: int) -> int:
    if opening < 0 or opening >= len(text) or text[opening] != "(":
        return -1
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, len(text)):
        character = text[index]
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
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _raw_fuzz_aliases_present(
    code: str,
    data_name: str,
    size_name: str,
) -> bool:
    if not data_name or not size_name:
        return False
    data_alias = re.search(
        rf"\bhc_fuzz_request\b\s*=\s*(?:\([^;]*\)\s*)?\b{re.escape(data_name)}\b",
        code,
    )
    size_alias = re.search(
        rf"\bhc_fuzz_request_size\b\s*=\s*(?:\([^;]*\)\s*)?\b{re.escape(size_name)}\b",
        code,
    )
    return data_alias is not None and size_alias is not None


def _dynamic_fuzz_mapping_present(
    code: str,
    body: str,
    data_name: str,
    size_name: str,
    step: Any,
) -> bool:
    if not data_name or not size_name or not step.request_binding_uses:
        return False
    copy_positions = [
        position
        for callee in ("memcpy", "memmove")
        for position, arguments in _call_arguments(body, callee)
        if re.search(r"\bhc_fuzz_request_storage\b", arguments)
        and re.search(rf"\b{re.escape(data_name)}\b", arguments)
        and re.search(rf"\b{re.escape(size_name)}\b", arguments)
    ]
    data_alias = re.search(
        r"\bhc_fuzz_request\b\s*=\s*(?:\([^;]*\)\s*)?"
        r"\bhc_fuzz_request_storage\b",
        code,
    )
    size_alias = re.search(
        rf"\bhc_fuzz_request_size\b\s*=\s*(?:\([^;]*\)\s*)?"
        rf"\b{re.escape(size_name)}\b",
        code,
    )
    if not copy_positions or data_alias is None or size_alias is None:
        return False
    copy_position = min(copy_positions)
    for use in step.request_binding_uses:
        patch_position = _binding_patch_position(
            body, "hc_fuzz_request_storage", use
        )
        if (
            patch_position <= copy_position
            or not _size_guard_before(
                body, size_name, use.offset + use.width, patch_position
            )
        ):
            return False
    return True


def _dynamic_binding_flow_check(
    body: str,
    steps: list[Any],
    setup_execution_positions: list[int],
    setup_oracle_positions: list[int],
    final_delivery_position: int,
) -> tuple[bool, str]:
    uses = [
        (step, use)
        for step in steps
        for use in step.request_binding_uses
    ]
    if not uses:
        return True, "no runtime-produced request bindings"
    by_index = {step.index: step for step in steps}
    setup_delivery = {
        step.index: setup_execution_positions[offset]
        for offset, step in enumerate(steps[:-1])
        if offset < len(setup_execution_positions)
    }
    setup_oracle = {
        step.index: setup_oracle_positions[offset]
        for offset, step in enumerate(steps[:-1])
        if offset < len(setup_oracle_positions)
    }
    failures: list[str] = []
    for consumer, use in uses:
        producer = by_index.get(use.producer_step_index)
        extractor = next((
            item for item in (
                producer.response_binding_extractors if producer else []
            )
            if item.binding == use.binding and item.width == use.width
        ), None)
        if producer is None or extractor is None:
            failures.append(
                f"{use.binding}: producer/extractor contract is missing"
            )
            continue
        extract_position = _binding_extraction_position(
            body, producer.index, extractor
        )
        producer_delivery = setup_delivery.get(producer.index, -1)
        oracle_position = setup_oracle.get(producer.index, -1)
        if consumer is steps[-1]:
            request_buffer = "hc_fuzz_request_storage"
            consumer_delivery = final_delivery_position
        else:
            request_buffer = f"hc_setup_request_{consumer.index}"
            consumer_delivery = setup_delivery.get(consumer.index, -1)
            template_copy = _template_copy_position(body, consumer.index)
            if template_copy < 0:
                failures.append(
                    f"{use.binding}: setup step {consumer.index} has no exact template copy"
                )
        patch_position = _binding_patch_position(
            body, request_buffer, use
        )
        if not (
            producer_delivery >= 0
            and oracle_position > producer_delivery
            and extract_position > oracle_position
            and patch_position > extract_position
            and consumer_delivery > patch_position
        ):
            failures.append(
                f"{use.binding}: order delivery={producer_delivery}, "
                f"oracle={oracle_position}, extract={extract_position}, "
                f"patch={patch_position}, consume={consumer_delivery}"
            )
    return not failures, "; ".join(failures) if failures else "all dynamic bindings flow through witnessed responses"


def _binding_extraction_position(
    body: str,
    step_index: int,
    extractor: Any,
) -> int:
    binding_symbol = _binding_symbol(extractor.binding)
    response_name = f"hc_response_step_{step_index}"
    for callee in ("memcpy", "memmove"):
        for position, arguments in _call_arguments(body, callee):
            if (
                re.search(rf"\b{re.escape(binding_symbol)}\b", arguments)
                and _offset_expression_present(
                    arguments, response_name, extractor.offset
                )
                and _width_expression_present(
                    arguments, binding_symbol, extractor.width
                )
                and _size_guard_before(
                    body,
                    f"hc_response_step_{step_index}_size",
                    extractor.offset + extractor.width,
                    position,
                )
            ):
                return position
    return -1


def _binding_patch_position(
    body: str,
    request_buffer: str,
    use: Any,
) -> int:
    binding_symbol = _binding_symbol(use.binding)
    for callee in ("memcpy", "memmove"):
        for position, arguments in _call_arguments(body, callee):
            if (
                _offset_expression_present(arguments, request_buffer, use.offset)
                and re.search(rf"\b{re.escape(binding_symbol)}\b", arguments)
                and _width_expression_present(arguments, binding_symbol, use.width)
            ):
                return position
    return -1


def _template_copy_position(body: str, step_index: int) -> int:
    target = f"hc_setup_request_{step_index}"
    source = f"hc_setup_step_{step_index}"
    for callee in ("memcpy", "memmove"):
        for position, arguments in _call_arguments(body, callee):
            if (
                re.search(rf"\b{re.escape(target)}\b", arguments)
                and re.search(rf"\b{re.escape(source)}\b", arguments)
                and re.search(
                    rf"\bsizeof\s*(?:\(\s*{re.escape(source)}\s*\)|"
                    rf"\s+{re.escape(source)}\b)",
                    arguments,
                )
            ):
                return position
    return -1


def _offset_expression_present(arguments: str, name: str, offset: int) -> bool:
    escaped = re.escape(name)
    if offset == 0 and re.search(rf"\b{escaped}\b", arguments):
        return True
    return bool(
        re.search(rf"\b{escaped}\b\s*\+\s*{offset}\b", arguments)
        or re.search(rf"&\s*{escaped}\s*\[\s*{offset}\s*\]", arguments)
    )


def _width_expression_present(arguments: str, symbol: str, width: int) -> bool:
    return bool(
        re.search(rf"(?:^|,)\s*{width}\s*(?:,|$)", arguments)
        or re.search(
            rf"\bsizeof\s*(?:\(\s*{re.escape(symbol)}\s*\)|"
            rf"\s+{re.escape(symbol)}\b)",
            arguments,
        )
    )


def _size_guard_before(
    body: str,
    size_name: str,
    minimum: int,
    before: int,
) -> bool:
    for position, condition in _control_conditions(body[:max(0, before)], "if"):
        if (
            re.search(rf"\b{re.escape(size_name)}\b", condition)
            and re.search(rf"\b{minimum}\b", condition)
        ):
            return True
    return False


def _fuzz_request_delivery_position(
    body: str,
    entry_names: list[str],
) -> int:
    """Locate a concrete delivery of the final raw request.

    This is intentionally conservative.  It recognizes direct calls to a
    witnessed Entry and standard byte/transport writes.  More elaborate
    wrappers must be opened and emitted so that one of these concrete delivery
    boundaries remains visible to the static gate.
    """

    callees = unique_strings([
        *entry_names,
        "send", "sendto", "write", "writev", "fwrite",
    ])
    positions: list[int] = []
    for callee in callees:
        for position, arguments in _call_arguments(body, callee):
            if (
                re.search(r"\bhc_fuzz_request\b", arguments)
                and re.search(r"\bhc_fuzz_request_size\b", arguments)
            ):
                positions.append(position)
    return min(positions) if positions else -1
