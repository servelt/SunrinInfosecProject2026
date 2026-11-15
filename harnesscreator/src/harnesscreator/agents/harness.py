from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, cast

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    CheckStatus,
    GateCheck,
    GateReport,
    FunctionMetadata,
    HarnessDraft,
    HarnessManifest,
    LargeFeatureSpec,
    ProjectSpec,
    SeedSpec,
    SmallFeatureSpec,
    as_json,
    stable_id,
    unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from .common import (
    function_payload,
    function_ref,
    is_non_product_build_target,
    object_list,
    prefer_product_build_targets,
    string_list,
)


HARNESS_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "context_complete",
        "candidate_function_ids",
        "blocking_dependencies",
        "lifecycle_facts",
        "type_and_build_facts",
        "unresolved_questions",
        "rationale",
    ],
    "properties": {
        "context_complete": {"type": "boolean"},
        "candidate_function_ids": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 8,
        },
        "blocking_dependencies": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "description",
                    "required_for",
                    "evidence_kind",
                    "evidence_id",
                    "evidence_line",
                ],
                "properties": {
                    "description": {"type": "string"},
                    "required_for": {"type": "string"},
                    "evidence_kind": {
                        "type": "string",
                        "enum": ["source", "small_feature"],
                    },
                    "evidence_id": {"type": "string"},
                    "evidence_line": {"type": ["integer", "null"]},
                },
            },
        },
        "lifecycle_facts": {"type": "array", "items": {"type": "string"}},
        "type_and_build_facts": {"type": "array", "items": {"type": "string"}},
        "unresolved_questions": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
}


HARNESS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "code", "manifest", "checklist", "generation_blockers",
        "operation_protocols",
    ],
    "properties": {
        "code": {"type": "string"},
        "manifest": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "build_target", "engine", "sanitizers", "execution_model", "headers", "libraries",
                "min_size", "max_size", "dispatch_strategy", "expected_anchors", "expected_consumers",
            ],
            "properties": {
                "build_target": {"type": "string"},
                # Dynamic replay, corpus invocation, and coverage parsing below
                # are libFuzzer-specific.  Other engines need dedicated adapters
                # before they can be accepted honestly.
                "engine": {"type": "string", "enum": ["libfuzzer"]},
                "sanitizers": {"type": "array", "items": {"type": "string"}},
                "execution_model": {
                    "type": "string",
                    "enum": ["in_process_reset", "loopback_network"],
                },
                "headers": {"type": "array", "items": {"type": "string"}},
                "libraries": {"type": "array", "items": {"type": "string"}},
                "min_size": {"type": "integer", "minimum": 0},
                "max_size": {"type": "integer", "minimum": 1},
                "dispatch_strategy": {
                    "type": "string",
                    "enum": ["selector_byte", "shared_selector_byte", "one_job_per_feature"],
                },
                "expected_anchors": {"type": "array", "items": {"type": "string"}},
                "expected_consumers": {"type": "array", "items": {"type": "string"}},
            },
        },
        "checklist": {
            "type": "array",
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
        "operation_protocols": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "small_feature_id", "ordered_function_ids",
                    "input_delivery_function_id", "completion_function_id",
                    "evidence", "rationale",
                ],
                "properties": {
                    "small_feature_id": {"type": "string"},
                    "ordered_function_ids": {
                        "type": "array", "items": {"type": "string"},
                    },
                    "input_delivery_function_id": {"type": "string"},
                    "completion_function_id": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["function_id", "line", "detail"],
                            "properties": {
                                "function_id": {"type": "string"},
                                "line": {"type": "integer"},
                                "detail": {"type": "string"},
                            },
                        },
                    },
                    "rationale": {"type": "string"},
                },
            },
        },
    },
}


HARNESS_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["checks", "summary"],
    "properties": {
        "checks": {
            "type": "array",
            "minItems": 16,
            "maxItems": 16,
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


SEED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["seeds"],
    "properties": {
        "seeds": {
            "type": "array",
            "minItems": 14,
            "maxItems": 24,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "data_hex", "rationale", "check_ids"],
                "properties": {
                    "name": {"type": "string"},
                    "data_hex": {"type": "string", "pattern": "^[0-9a-fA-F]*$"},
                    "rationale": {"type": "string"},
                    "check_ids": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "pattern": "^HC(?:0[1-9]|1[0-6])$"},
                    },
                },
            },
        }
    },
}


class HarnessGeneratorAgent:
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
        # One function is opened per turn and an opened function is not opened
        # again in this discovery. The number of indexed functions is therefore
        # a structural termination bound, not an arbitrary completeness claim.
        # A positive operator budget remains an explicit work limit.
        self.max_context_turns = (
            max_context_turns
            if max_context_turns is not None and max_context_turns > 0
            else project.max_context_functions
            if project.max_context_functions > 0
            else len(graph.bundle.functions)
        )
        self.trace = trace
        self._canonical_reference: dict[str, Any] | None = None
        # Generation repairs for one Large Feature stay in the same Codex
        # session. Keep the deterministic side of that context as well so a
        # second attempt continues after the last opened function instead of
        # reopening the whole chain from the Common Anchor.
        self._context_state: dict[str, dict[str, Any]] = {}

    @staticmethod
    def session_key(large: LargeFeatureSpec) -> str:
        return f"harness_generator:{large.large_feature_id}"

    async def close_session(self, large: LargeFeatureSpec) -> None:
        await close_llm_session(self.llm, self.session_key(large))
        self._context_state.pop(large.large_feature_id, None)

    async def run(
        self,
        large: LargeFeatureSpec,
        small_features: list[SmallFeatureSpec],
        feedback: list[str] | None = None,
    ) -> HarnessDraft:
        relevant = [item for item in small_features if item.small_feature_id in large.small_feature_ids]
        feedback_context_text = "\n".join(
            item for item in (feedback or []) if "HC23" in item
        )
        feedback_function_ids = unique_strings(
            function.function_id
            for function in self.graph.bundle.functions.values()
            if function.name
            and re.search(
                rf"\b{re.escape(function.name)}\b",
                feedback_context_text,
            )
        )
        goal_function_ids = unique_strings(
            [large.common_anchor, *large.required_functions]
            + [identifier for item in relevant for identifier in item.required_functions]
            + feedback_function_ids
        )
        canonical_reference = self._load_canonical_oss_fuzz_reference()
        functions, context_discovery = await self._discover_context(
            large,
            relevant,
            goal_function_ids,
            feedback or [],
            canonical_reference,
        )
        opened_ids = {function.function_id for function in functions}
        if context_discovery.get("generation_blocked", False):
            response = {
                "code": "",
                "manifest": {},
                "checklist": [],
                "generation_blockers": [
                    "CONTEXT_BLOCKED: " + _blocking_dependency_text(item)
                    for item in object_list(
                        context_discovery.get("blocking_dependencies")
                    )
                ] or [
                    "CONTEXT_BLOCKED: sequential context discovery could not establish the Common Anchor"
                ],
            }
        else:
            source_language = (
                "C"
                if Path(self.project.harness_source_filename).suffix.lower() == ".c"
                else "C++"
            )
            response = await self.llm.complete_json(
                role="harness_generator",
                instructions=(
                    "Generate one buildable fuzz harness for this Large Feature. Call the real application APIs exactly as "
                    "shown; never reimplement parsers, dispatch, protocols, state transitions, authentication, or feature "
                    "logic. Harness-only code may bound, split, copy, terminate, or transport fuzz bytes. Preserve every "
                    "startup step, prerequisite, result check, state transition, and cleanup action that the supplied "
                    "evidence actually requires. These lifecycle categories are optional: do not invent initialization, "
                    "objects, callbacks, reset, cleanup, or prerequisite state when the evidenced operation has none. "
                    f"Use a selector only when variants exist. Generate strict {source_language} source suitable for "
                    f"the trusted filename {self.project.harness_source_filename!r}; do not use constructs from the "
                    f"other language. The code must define LLVMFuzzerTestOneInput for libFuzzer. "
                    "The current execution backend is in-process libFuzzer. Never call fork, vfork, exec, posix_spawn, "
                    "or another process from LLVMFuzzerTestOneInput: ordinary child execution hides target coverage and "
                    "can swallow sanitizer crashes. Never include an application .c/.cc/.cpp implementation file into "
                    "the harness; call declarations from real public/project headers and let the trusted project build "
                    "link the implementation. If the established operation cannot be repeated safely in-process and no "
                    "evidenced reset/cleanup path exists, return empty code with an ENGINE_UNSUPPORTED generation blocker "
                    "instead of inventing fork-based isolation. "
                    "Use only functions opened by sequential_context_discovery and their supplied "
                    "header/declaration/build-target metadata; unopened Feature goals are not source evidence. "
                    "For every Small Feature, return an operation_protocols item. It is the P2 executable contract: "
                    "list the real opened project functions in runtime order, identify the opened function that "
                    "delivers fuzzer input across the real Entry boundary, and identify the opened application "
                    "function whose result establishes the requested operation completion. Cite exact opened source "
                    "lines for both decisions. This protocol may close an obligation left open by Small Feature "
                    "semantic discovery, but it must not invent a new operation or use an unopened function. "
                    "For every Large Feature dependency, the consumer protocol must include the producer's real "
                    "operation before the consumer; repeated function IDs are allowed when both operations pass "
                    "through the same dispatcher. If source cannot prove the dependency or its execution order, "
                    "return a generation blocker rather than silently targeting only the consumer's failure/miss path. "
                    "canonical_oss_fuzz_reference is the pinned same-project integration used by the verifier. "
                    "Use it to avoid guessing canonical headers, language, process initialization, and build linkage, "
                    "but never copy an unrelated feature path from it and never treat a function appearing only there "
                    "as authorization to call it. Opened local FunctionMetadata and the established Feature remain "
                    "the authority for target behavior. A successfully preflighted canonical integration may establish "
                    "compile-time configuration and a harness-fixture pattern that uses exported current-checkout data "
                    "with an opened current-checkout function. This is build/lifecycle evidence only: reproduce its "
                    "public pattern with explicit bounds, never access the target's file-scope static state, and leave "
                    "actual compilation and runtime validation to the verifier. "
                    "Do not invent declarations. Absence of a "
                    "configured dynamic build command alone is not a reason to return empty code when exact declarations, "
                    "headers, source bodies, and a project build target are supplied. Direct harness code may reference "
                    "only externally linkable functions and data declared by opened current-checkout project metadata "
                    "or headers. A function used by the canonical same-project harness must still be opened in this "
                    "stateful session before generated code may call it. Never reference or assign a file-scope static implementation symbol "
                    "(for example an internal fd-limit variable) merely because its name appears inside an opened function; "
                    "use the public initialization path or the canonical integration pattern instead. "
                    "Return empty code only when generating "
                    "a semantically correct source file would require inventing a function, type, evidenced lifecycle, or "
                    "evidenced prerequisite. Audit all 16 checklist items explicitly. Never put shell/build commands in the output."
                ),
                payload={
                    "large_feature": _large_payload(large),
                    "small_features": [_small_payload(item) for item in relevant],
                    "sequential_context_discovery": context_discovery,
                    "functions": _bounded_harness_function_payloads(
                        functions,
                        primary_ids=set(goal_function_ids) & opened_ids,
                        focus_lines={
                            evidence.function_id: evidence.line
                            for feature in relevant
                            for evidence in feature.evidence
                            if evidence.line is not None
                        },
                    ),
                    "trusted_build_configuration": {
                        "verification_backend": self.project.verification_backend,
                        "has_build_command": bool(self.project.build_command),
                        "configured_binary": str(self.project.harness_binary) if self.project.harness_binary else None,
                        "harness_source_filename": self.project.harness_source_filename,
                        "oss_fuzz_project": self.project.oss_fuzz_project,
                        "oss_fuzz_fuzzer": self.project.oss_fuzz_fuzzer,
                        "oss_fuzz_source_path": self.project.oss_fuzz_source_path,
                        "oss_fuzz_revision": self.project.oss_fuzz_revision,
                    },
                    "canonical_oss_fuzz_reference": canonical_reference,
                    "analysis_completeness": self.graph.bundle.completeness,
                    "checklist": [
                        {
                            "check_id": check_id,
                            "name": CHECKLIST_NAMES[check_id],
                            "contract": CHECKLIST_CONTRACTS[check_id],
                        }
                        for check_id in CHECKLIST_NAMES
                    ],
                    "previous_attempt_feedback": feedback or [],
                },
                output_schema=HARNESS_SCHEMA,
                session_key=self.session_key(large),
            )
        harness_id = stable_id("harness", large.large_feature_id)
        raw_manifest: dict[str, Any] = (
            cast(dict[str, Any], response["manifest"])
            if isinstance(response.get("manifest"), dict)
            else {}
        )
        requested_build_target = str(raw_manifest.get("build_target", "")).strip()
        build_target_candidates = prefer_product_build_targets(
            [
                item.build_target for item in relevant
                if item.build_target.strip().lower() not in {"", "default", "unresolved", "unknown"}
            ]
            + [target for function in functions for target in function.build_targets]
        )
        product_targets = [
            target for target in build_target_candidates if not is_non_product_build_target(target)
        ]
        if (
            requested_build_target in build_target_candidates
            and not (product_targets and is_non_product_build_target(requested_build_target))
        ):
            build_target = requested_build_target
        elif build_target_candidates:
            build_target = build_target_candidates[0]
        elif self.project.verification_backend == "oss-fuzz":
            build_target = (
                f"oss-fuzz:{self.project.oss_fuzz_project}/{self.project.oss_fuzz_fuzzer}"
            )
        elif self.project.build_command:
            build_target = "trusted-cli-build-command"
        else:
            build_target = "UNRESOLVED"
        known_function_ids = {function.function_id for function in functions}
        feature_by_id = {item.small_feature_id: item for item in relevant}
        operation_protocols, protocol_errors = _validated_operation_protocols(
            response.get("operation_protocols"),
            relevant,
            functions,
        )
        protocol_by_feature = {
            str(item.get("small_feature_id", "")): item
            for item in operation_protocols
        }
        variant_targets: list[dict[str, Any]] = []
        for index, variant in enumerate(large.variants):
            feature = feature_by_id.get(str(variant.get("small_feature_id", "")))
            action_by_id = {
                str(action.get("action_id", "")): action
                for action in (feature.actions if feature else [])
            }
            protocol = (
                protocol_by_feature.get(feature.small_feature_id)
                if feature else None
            )
            target = (
                str(protocol.get("completion_function_id", ""))
                if protocol is not None else
                _completion_target_function_id(feature, known_function_ids)
                if feature else ""
            )
            dependency_targets = unique_strings(
                str(action_by_id.get(dependency.producer_action_id, {}).get(
                    "function_id", ""
                ))
                for dependency in (feature.dependencies if feature else [])
                if str(action_by_id.get(dependency.producer_action_id, {}).get(
                    "function_id", ""
                )) in known_function_ids
            )
            variant_targets.append({
                "selector": str(index),
                "small_feature_id": feature.small_feature_id if feature else "",
                "function_id": target,
                "prerequisite_function_ids": dependency_targets,
                "ordered_function_ids": (
                    list(protocol.get("ordered_function_ids", []))
                    if protocol is not None else []
                ),
                "input_delivery_function_id": (
                    str(protocol.get("input_delivery_function_id", ""))
                    if protocol is not None else ""
                ),
                "protocol_evidence": (
                    list(protocol.get("evidence", []))
                    if protocol is not None else []
                ),
            })
        requested_dispatch = str(raw_manifest.get("dispatch_strategy", ""))
        accepted_dispatch = (
            requested_dispatch
            if requested_dispatch in {
                "selector_byte", "shared_selector_byte", "one_job_per_feature"
            }
            else large.dispatch_strategy
        )
        if len(large.variants) > 1 and accepted_dispatch == "one_job_per_feature":
            accepted_dispatch = large.dispatch_strategy
            if accepted_dispatch == "one_job_per_feature":
                accepted_dispatch = "selector_byte"
        manifest = HarnessManifest(
            harness_id=harness_id,
            large_feature_id=large.large_feature_id,
            source_file=(
                f"harnesses/{harness_id}/{self.project.harness_source_filename}"
            ),
            build_target=build_target or "UNRESOLVED",
            engine="libfuzzer",
            # The OSS-Fuzz/Quartet path currently performs its runtime replay
            # with an address build and a separate coverage build.  Do not
            # claim UBSan was executed there.  Custom command builds retain the
            # ASan+UBSan contract and verify both instrumentation markers.
            sanitizers=(
                ["address"]
                if self.project.verification_backend == "oss-fuzz"
                else unique_strings([
                    "address", "undefined", *string_list(raw_manifest.get("sanitizers"))
                ])
            ),
            execution_model=(
                str(raw_manifest.get("execution_model"))
                if str(raw_manifest.get("execution_model", "")) in {
                    "in_process_reset", "loopback_network"
                }
                else large.isolation_mode
            ),
            headers=unique_strings(string_list(raw_manifest.get("headers"))),
            libraries=unique_strings(string_list(raw_manifest.get("libraries"))),
            min_size=max(0, _integer(raw_manifest.get("min_size"), 0)),
            max_size=min(1_048_576, max(1, _integer(raw_manifest.get("max_size"), 1_048_576))),
            dispatch_strategy=accepted_dispatch,
            expected_anchors=[large.common_anchor],
            expected_consumers=unique_strings(
                [
                    identifier for identifier in string_list(raw_manifest.get("expected_consumers"))
                    if identifier in known_function_ids
                ]
                + large.required_functions
            ),
            variant_count=max(1, len(large.variants)),
            variant_targets=variant_targets,
            verification_backend=self.project.verification_backend,
            backend_target=(
                f"{self.project.oss_fuzz_project}/{self.project.oss_fuzz_fuzzer}"
                if self.project.verification_backend == "oss-fuzz"
                else None
            ),
            # Commands are trusted configuration, never model output.
            build_command=list(self.project.build_command),
            binary=str(self.project.harness_binary) if self.project.harness_binary else None,
        )
        audit = object_list(response.get("checklist"))
        blockers = string_list(response.get("generation_blockers"))
        blockers.extend(
            f"FEATURE_CONTRACT_BLOCKED: {error}" for error in protocol_errors
        )
        missing_completion_targets = [
            str(variant.get("small_feature_id", ""))
            for variant in variant_targets
            if not variant.get("function_id")
        ]
        if missing_completion_targets:
            blockers.append(
                "FEATURE_CONTRACT_BLOCKED: completion target is unresolved for "
                + ", ".join(missing_completion_targets)
            )
        if blockers:
            audit.append({"check_id": "generation_blockers", "status": "FAIL", "evidence": "; ".join(blockers)})
        if manifest.min_size > manifest.max_size:
            manifest.min_size = manifest.max_size
        return HarnessDraft(
            manifest=manifest,
            code=str(response.get("code", "")),
            self_audit=audit,
            generation_blockers=blockers,
            context_function_ids=list(opened_ids),
            operation_protocols=operation_protocols,
        )

    async def _discover_context(
        self,
        large: LargeFeatureSpec,
        relevant: list[SmallFeatureSpec],
        goal_function_ids: list[str],
        feedback: list[str],
        canonical_reference: dict[str, Any] | None = None,
    ) -> tuple[list[FunctionMetadata], dict[str, Any]]:
        """Let the model open exactly one function source per discovery turn.

        The old implementation unconditionally expanded the Large Feature into
        a caller/callee neighbourhood of at least 48 functions.  That made the
        generation model sift through source it had never selected and obscured
        which lifecycle fact came from which move.  Here the Common Anchor is
        the sole root.  Every later source must be the first eligible function
        in the model's ranked candidates; no BFS fallback exists.
        """

        canonical_reference = canonical_reference or {}
        if large.common_anchor not in self.graph.bundle.functions:
            return [], {
                "opened_function_ids": [],
                "lifecycle_facts": [],
                "type_and_build_facts": [],
                "unresolved_questions": [
                    f"Common Anchor is absent from static analysis: {large.common_anchor}"
                ],
                "blocking_dependencies": [{
                    "description": "Common Anchor is absent from static analysis",
                    "required_for": "invoking the established Large Feature boundary",
                    "evidence_kind": "small_feature",
                    "evidence_id": relevant[0].small_feature_id if relevant else "large-feature",
                    "evidence_line": None,
                }],
                "generation_blocked": True,
                "stop_reason": "common anchor is unavailable",
                "rounds": 0,
            }

        prior = self._context_state.get(large.large_feature_id, {})
        opened_ids = [
            identifier
            for identifier in prior.get("opened_function_ids", [])
            if identifier in self.graph.bundle.functions
        ]
        prior_discovery = prior.get("discovery_moves", {})
        discovery: dict[str, dict[str, Any]] = {
            str(identifier): dict(move)
            for identifier, move in (
                prior_discovery.items()
                if isinstance(prior_discovery, dict) else []
            )
            if identifier in self.graph.bundle.functions
            and isinstance(move, dict)
        }
        discovery.setdefault(large.common_anchor, {
            "discovered_from": None,
            "discovered_from_name": None,
            "relation": "root",
        })
        if not opened_ids:
            current_id = large.common_anchor
        else:
            current_id = opened_ids[-1]
            discovery.setdefault(current_id, {
                "discovered_from": None,
                "discovered_from_name": None,
                "relation": "retained_context",
            })
        lifecycle_facts = string_list(prior.get("lifecycle_facts"))
        type_and_build_facts = string_list(prior.get("type_and_build_facts"))
        unresolved_questions = string_list(prior.get("unresolved_questions"))
        blocking_dependencies = object_list(prior.get("blocking_dependencies"))
        rejected_blocking_dependencies = object_list(
            prior.get("rejected_blocking_dependencies")
        )
        previous_round: dict[str, Any] = {}
        stop_reason = "maximum sequential context turns reached"
        rounds = 0
        canonical_function_ids = self._canonical_reference_function_ids(
            canonical_reference
        )

        for round_number in range(1, self.max_context_turns + 1):
            rounds = round_number
            current = self.graph.get(current_id)
            revisiting_retained_context = current_id in opened_ids
            if not revisiting_retained_context:
                opened_ids.append(current_id)

            move = discovery[current_id]
            emit_trace(
                self.trace,
                "harness_generator",
                (
                    "context_function_revisited"
                    if revisiting_retained_context
                    else "context_function_opened"
                ),
                (
                    f"revisit retained {current.name} for repair context round {round_number}"
                    if revisiting_retained_context
                    else f"open {current.name} as sequential harness context round {round_number}"
                ),
                large_feature_id=large.large_feature_id,
                round=round_number,
                function=function_ref(current),
                discovered_from=move["discovered_from"],
                discovered_from_name=move["discovered_from_name"],
                relation=move["relation"],
                opened_function_ids=list(opened_ids),
            )

            frontier = self.graph.frontier(opened_ids)
            response = await self.llm.complete_json(
                role="harness_generator",
                instructions=(
                    "This is sequential source discovery before harness generation. Read exactly the one source in "
                    "current_function as the newly opened function. This stateful agent session retains the exact "
                    "Clang-confirmed referenced_global_declarations and referenced_macro_definitions in "
                    "current_function are source-located context for that function; use them before requesting "
                    "another function to resolve a constant or dispatch table. "
                    "source shown in every earlier discovery turn: reason over that cumulative source history together "
                    "with current_function, and never reduce an earlier source body to only the free-form fact lists. "
                    "Do not generate harness code yet. Use the established Large/Small Feature "
                    "contract and accumulated facts to decide whether another function must be opened. "
                    "The pinned canonical OSS-Fuzz files are a same-project integration reference for headers, build "
                    "shape, and known initialization patterns only. They may suggest which local function to request, "
                    "but they are not a substitute for opening that function in the current checkout and must not "
                    "introduce unrelated feature behavior. When that preflighted integration allocates an exported "
                    "fixture/table and calls an already-opened current-checkout function, it may settle a compile-time "
                    "configuration fact even if the function also contains an assertion over inaccessible file-scope "
                    "static state. Do not chase or access that static solely to re-prove the canonical build setting; "
                    "require the generated code to reproduce the exported pattern and bound every index itself. "
                    "Initialization, "
                    "objects, prerequisite state, callback registration, result handling, reset, and cleanup are NOT "
                    "mandatory categories: a valid operation may require none of them. Determine applicability from "
                    "concrete source or Feature evidence first, and never open functions merely to prove that an optional "
                    "category is absent. Follow only dependencies that the opened code or established Feature actually "
                    "requires, including input delivery and any applicable declarations/types/headers/build visibility. "
                    "available_context_functions and unopened_feature_goals contain source-free identities, not evidence. "
                    "A possible_indirect_target/indirect_possible edge is points-to evidence only: inspect the "
                    "real assignment/registration and build branch, and never hard-code one possible target as "
                    "the selected callback without runtime reachability evidence. "
                    "Return candidate_function_ids in best-first order. The orchestrator will validate "
                    "them and open EXACTLY ONE eligible function in the next turn. Prefer a direct caller/callee from "
                    "available_context_functions. A non-frontier function is eligible when it is an already established "
                    "unopened_feature_goal or when its exact function name is visibly referenced by the current source, "
                    "which permits required lifecycle helpers and real indirect callback targets without speculative "
                    "graph expansion. Never request an already opened function. Set "
                    "context_complete=true when the opened evidence is sufficient to write a buildable, "
                    "lifecycle-correct harness without invention; this includes a stateless direct call for which the "
                    "source shows that initialization, callback setup, and cleanup are not applicable. Put a question in "
                    "unresolved_questions only when a concrete call, type use, state check, resource acquisition, or "
                    "Feature requirement demonstrates that the missing fact matters. Every fact that is REQUIRED before "
                    "generation must be returned in blocking_dependencies with either an exact opened source line or an "
                    "established Small Feature ID. Optional questions belong only in unresolved_questions and never make "
                    "context incomplete. A candidate_function_id is actionable only when at least one evidence-backed "
                    "blocking dependency remains. If such required evidence is insufficient, name the smallest next "
                    "candidate; do not ask for broad BFS context."
                ),
                payload={
                    "large_feature": _large_payload(large),
                    "small_features": [_small_payload(item) for item in relevant],
                    "current_function": function_payload(
                        current,
                        source_limit=max(32_000, min(len(current.source), 96_000)),
                    ),
                    "opened_functions": [
                        function_ref(self.graph.get(identifier))
                        for identifier in opened_ids
                    ],
                    "available_context_functions": frontier,
                    "unopened_feature_goals": [
                        function_ref(self.graph.get(identifier))
                        for identifier in goal_function_ids
                        if identifier in self.graph.bundle.functions
                        and identifier not in opened_ids
                    ],
                    "accumulated_facts": {
                        "lifecycle": lifecycle_facts,
                        "type_and_build": type_and_build_facts,
                        "unresolved_questions": unresolved_questions,
                        "blocking_dependencies": blocking_dependencies,
                    },
                    "previous_round": previous_round,
                    "previous_attempt_feedback": feedback,
                    "canonical_oss_fuzz_reference": (
                        canonical_reference
                        if round_number == 1
                        else {
                            "retained_in_agent_session": bool(canonical_reference),
                            "source_filename": canonical_reference.get("source_filename"),
                            "revision": canonical_reference.get("revision"),
                        }
                    ),
                    "context_limits": {
                        "max_turns": self.max_context_turns,
                        "functions_opened_this_turn": 1,
                        "automatic_graph_expansion": False,
                        "source_history": "retained_in_same_agent_session",
                    },
                },
                output_schema=HARNESS_CONTEXT_SCHEMA,
                session_key=self.session_key(large),
            )

            lifecycle_facts = unique_strings([
                *lifecycle_facts,
                *string_list(response.get("lifecycle_facts")),
            ])
            type_and_build_facts = unique_strings([
                *type_and_build_facts,
                *string_list(response.get("type_and_build_facts")),
            ])
            unresolved_questions = unique_strings(
                string_list(response.get("unresolved_questions"))
            )
            (
                blocking_dependencies,
                rejected_round_blockers,
            ) = self._validated_blocking_dependencies(
                response.get("blocking_dependencies"),
                opened_ids=set(opened_ids),
                small_feature_ids={item.small_feature_id for item in relevant},
            )
            rejected_blocking_dependencies.extend(rejected_round_blockers)

            requested = string_list(response.get("candidate_function_ids"))
            next_choice = self._select_next_context_function(
                requested,
                frontier,
                current,
                set(opened_ids),
                set(goal_function_ids),
                canonical_function_ids,
            )
            model_context_complete = bool(response.get("context_complete", False))
            # An evidence-backed blocker is mandatory.  In addition, when the
            # model says the cumulative source context is incomplete and names
            # an eligible next function, honor that one-function move even if
            # the missing fact is not yet strong enough to be a hard blocker.
            # This preserves the requested read -> choose -> read workflow
            # without letting a bare boolean block generation forever when no
            # actionable function can be identified.
            exploratory_move = bool(
                not model_context_complete
                and not blocking_dependencies
                and next_choice is not None
            )
            context_complete = not blocking_dependencies and not exploratory_move
            safety_limit_exhausted = bool(
                round_number >= self.max_context_turns
                and not context_complete
            )
            if round_number >= self.max_context_turns:
                stop_reason = (
                    "maximum sequential context turns reached with evidence-backed blockers"
                    if blocking_dependencies
                    else "maximum sequential context turns reached with a pending model-selected function"
                    if exploratory_move
                    else "no evidence-backed blocking dependency remains"
                )
            elif blocking_dependencies and next_choice is not None:
                stop_reason = "open one candidate for the evidence-backed dependency"
            elif blocking_dependencies:
                stop_reason = "evidence-backed dependency has no eligible next function"
            elif exploratory_move:
                stop_reason = "open one model-selected context function"
            else:
                stop_reason = "no evidence-backed blocking dependency remains"

            emit_trace(
                self.trace,
                "harness_generator",
                "context_round_decision",
                (
                    f"{large.large_feature_id} round {round_number}: "
                    f"candidates={requested or ['none']}; {stop_reason}"
                ),
                large_feature_id=large.large_feature_id,
                round=round_number,
                current_function=function_ref(current),
                candidate_function_ids=requested,
                selected_function_id=(next_choice or {}).get("function_id"),
                context_complete=context_complete,
                model_context_complete=model_context_complete,
                blocking_dependencies=blocking_dependencies,
                rejected_blocking_dependencies=rejected_round_blockers,
                stop_reason=stop_reason,
                model_response=response,
            )
            previous_round = {
                **response,
                "selected_function_id": (next_choice or {}).get("function_id"),
            }

            if (
                round_number >= self.max_context_turns
                or context_complete
                or next_choice is None
            ):
                break

            next_id = str(next_choice["function_id"])
            discovery[next_id] = {
                "discovered_from": str(next_choice["discovered_from"]),
                "discovered_from_name": str(next_choice["discovered_from_name"]),
                "relation": str(next_choice["relation"]),
            }
            current_id = next_id

        result = {
                "opened_function_ids": opened_ids,
                "opened_functions": [
                    function_ref(self.graph.get(identifier)) for identifier in opened_ids
                ],
                "lifecycle_facts": lifecycle_facts,
                "type_and_build_facts": type_and_build_facts,
                "unresolved_questions": unresolved_questions,
                "blocking_dependencies": blocking_dependencies,
                "rejected_blocking_dependencies": rejected_blocking_dependencies,
                "generation_blocked": bool(
                    blocking_dependencies or safety_limit_exhausted
                ),
                "context_complete": context_complete,
                "stop_reason": stop_reason,
                "rounds": rounds,
                "one_function_per_turn": True,
                "automatic_graph_expansion": False,
                "resumed_prior_context": bool(prior),
                "discovery_moves": discovery,
            }
        self._context_state[large.large_feature_id] = result
        return ([self.graph.get(identifier) for identifier in opened_ids], result)

    def _canonical_reference_function_ids(
        self,
        canonical_reference: dict[str, Any],
    ) -> set[str]:
        files = canonical_reference.get("files", {})
        if not isinstance(files, dict):
            return set()
        source = "\n".join(str(value) for value in files.values())
        return {
            function.function_id
            for function in self.graph.bundle.functions.values()
            if function.name
            and re.search(rf"\b{re.escape(function.name)}\b", source)
        }

    def _load_canonical_oss_fuzz_reference(self) -> dict[str, Any]:
        """Read the pinned same-project harness and build recipe.

        These files are integration guidance, not evidence that an API exists
        in the user's checkout. Calls still require opened local metadata.
        """

        if self._canonical_reference is not None:
            return self._canonical_reference
        if (
            self.project.verification_backend != "oss-fuzz"
            or self.project.oss_fuzz_dir is None
            or not self.project.oss_fuzz_project
        ):
            self._canonical_reference = {}
            return self._canonical_reference

        relative_root = Path("projects") / self.project.oss_fuzz_project
        filenames = unique_strings([
            self.project.harness_source_filename,
            "build.sh",
            "Dockerfile",
            (
                f"{self.project.oss_fuzz_fuzzer}.options"
                if self.project.oss_fuzz_fuzzer else ""
            ),
        ])
        files: dict[str, str] = {}
        for filename in filenames:
            if not filename:
                continue
            relative = relative_root / filename
            content = ""
            if self.project.oss_fuzz_revision:
                try:
                    result = subprocess.run(
                        [
                            "git", "show",
                            f"{self.project.oss_fuzz_revision}:{relative.as_posix()}",
                        ],
                        cwd=self.project.oss_fuzz_dir,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError):
                    result = None
                if result is not None and result.returncode == 0:
                    content = result.stdout
            if not content:
                candidate = self.project.oss_fuzz_dir / relative
                if candidate.is_file():
                    content = candidate.read_text(
                        encoding="utf-8", errors="replace"
                    )
            if content:
                files[filename] = content[:120_000]

        self._canonical_reference = {
            "project": self.project.oss_fuzz_project,
            "fuzzer": self.project.oss_fuzz_fuzzer,
            "source_filename": self.project.harness_source_filename,
            "application_source_path": self.project.oss_fuzz_source_path,
            "revision": self.project.oss_fuzz_revision,
            "local_checkout_preflight": {
                "performed": self.project.canonical_oss_fuzz_preflight_passed,
                "canonical_build_passed": self.project.canonical_oss_fuzz_preflight_passed,
                "canonical_runtime_probe_passed": False,
                "source_root": str(self.project.source_root),
                "build_contract_evidence": _local_build_contract_evidence(
                    self.project.source_root
                ),
            },
            "files": files,
            "usage_contract": (
                "Same-project build/lifecycle reference only. When local_checkout_preflight.performed is true, "
                "the native backend has built the canonical integration against the requested local checkout, "
                "but has not established canonical runtime behavior or full target coverage. "
                "Local FunctionMetadata "
                "and Feature evidence remain authoritative. Reuse compatible exported fixture allocation, "
                "headers, and initialization patterns only when the invoked current-checkout functions have "
                "been opened, every array/index has an explicit harness-side bound, and no inaccessible "
                "file-scope target state is accessed. Do not copy unrelated feature logic."
            ),
        }
        return self._canonical_reference

    def _validated_blocking_dependencies(
        self,
        raw_value: Any,
        *,
        opened_ids: set[str],
        small_feature_ids: set[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for raw in object_list(raw_value):
            description = str(raw.get("description", "")).strip()
            required_for = str(raw.get("required_for", "")).strip()
            evidence_kind = str(raw.get("evidence_kind", ""))
            evidence_id = str(raw.get("evidence_id", ""))
            raw_line = raw.get("evidence_line")
            line: int | None = None
            reason = ""
            if not description or not required_for:
                reason = "blocking dependency lacks a description or required purpose"
            elif evidence_kind == "source":
                function = self.graph.bundle.functions.get(evidence_id)
                try:
                    line = int(str(raw_line))
                except (TypeError, ValueError):
                    line = None
                if function is None or evidence_id not in opened_ids:
                    reason = "source evidence is not an opened project function"
                elif line is None or not (
                    function.start_line <= line <= function.end_line
                ):
                    reason = "source evidence line is absent or outside the opened function"
            elif evidence_kind == "small_feature":
                line = None
                if evidence_id not in small_feature_ids:
                    reason = "Small Feature evidence ID is not a selected member"
            else:
                reason = "unsupported blocker evidence kind"
            normalized = {
                "description": description,
                "required_for": required_for,
                "evidence_kind": evidence_kind,
                "evidence_id": evidence_id,
                "evidence_line": line,
            }
            if reason:
                rejected.append({"dependency": normalized, "reason": reason})
                continue
            key = tuple(normalized.values())
            if key not in seen:
                seen.add(key)
                accepted.append(normalized)
        return accepted, rejected

    def _select_next_context_function(
        self,
        requested: list[str],
        frontier: list[dict[str, object]],
        current: FunctionMetadata,
        opened_ids: set[str],
        established_goal_ids: set[str] | None = None,
        canonical_reference_ids: set[str] | None = None,
    ) -> dict[str, str] | None:
        """Resolve ranked model candidates and accept only the first valid one."""

        established_goal_ids = established_goal_ids or set()
        canonical_reference_ids = canonical_reference_ids or set()
        frontier_by_id = {
            str(item.get("function_id", "")): item for item in frontier
        }
        frontier_aliases: dict[str, list[str]] = {}
        for identifier, item in frontier_by_id.items():
            for value in (item.get("name"), item.get("qualified_name")):
                alias = str(value or "").strip().casefold()
                if alias:
                    frontier_aliases.setdefault(alias, []).append(identifier)

        for raw in requested:
            value = raw.strip()
            if not value:
                continue
            identifier = value if value in frontier_by_id else ""
            if not identifier:
                matches = unique_strings(frontier_aliases.get(value.casefold(), []))
                matches = self._prefer_unique_product_definition(matches)
                if len(matches) == 1:
                    identifier = matches[0]
            if identifier and identifier not in opened_ids:
                connections = frontier_by_id[identifier].get("connections", [])
                connection = connections[0] if isinstance(connections, list) and connections else {}
                parent_id = str(
                    connection.get("connected_function_id", current.function_id)
                )
                return {
                    "function_id": identifier,
                    "relation": str(
                        connection.get("relation", "model_selected_adjacent")
                    ),
                    "discovered_from": parent_id,
                    "discovered_from_name": str(
                        connection.get(
                            "connected_function_name",
                            self.graph.get(parent_id).name
                            if parent_id in self.graph.bundle.functions
                            else current.name,
                        )
                    ),
                }

            # Fuzz Introspector may miss function-pointer edges. Permit a
            # source-named jump first; an already established Feature goal is
            # the other non-adjacent path accepted below.
            source_matches = self._source_referenced_function_ids(current.source, value)
            source_matches = [
                item for item in source_matches if item not in opened_ids
            ]
            if len(source_matches) == 1:
                return {
                    "function_id": source_matches[0],
                    "relation": "source_reference",
                    "discovered_from": current.function_id,
                    "discovered_from_name": current.name,
                }
            reference_matches = self._resolve_function_identifiers(value)
            reference_matches = [
                item for item in reference_matches
                if item in canonical_reference_ids and item not in opened_ids
            ]
            if len(reference_matches) == 1:
                return {
                    "function_id": reference_matches[0],
                    "relation": "canonical_oss_fuzz_reference",
                    "discovered_from": current.function_id,
                    "discovered_from_name": current.name,
                }
            goal_matches = self._resolve_function_identifiers(value)
            goal_matches = [
                item for item in goal_matches
                if item in established_goal_ids and item not in opened_ids
            ]
            if len(goal_matches) == 1:
                return {
                    "function_id": goal_matches[0],
                    "relation": "established_feature_goal",
                    "discovered_from": current.function_id,
                    "discovered_from_name": current.name,
                }
        return None

    def _resolve_function_identifiers(self, requested: str) -> list[str]:
        normalized = requested.strip()
        decorated = re.match(r"^(fn-[A-Za-z0-9]+)(?=$|::|:|\s)", normalized)
        direct_id = decorated.group(1) if decorated else normalized
        direct = self.graph.bundle.functions.get(direct_id)
        candidates = [direct] if direct is not None else [
            function
            for function in self.graph.bundle.functions.values()
            if normalized.casefold() in {
                function.name.casefold(), function.qualified_name.casefold()
            }
        ]
        identifiers = unique_strings(
            function.function_id for function in candidates if function is not None
        )
        return self._prefer_unique_product_definition(identifiers)

    def _prefer_unique_product_definition(self, identifiers: list[str]) -> list[str]:
        if len(identifiers) <= 1:
            return identifiers
        product = [
            identifier
            for identifier in identifiers
            if any(
                not is_non_product_build_target(target)
                for target in self.graph.get(identifier).build_targets
            )
        ]
        return product if len(product) == 1 else identifiers

    def _source_referenced_function_ids(self, source: str, requested: str) -> list[str]:
        candidates = [
            self.graph.bundle.functions[identifier]
            for identifier in self._resolve_function_identifiers(requested)
        ]
        return unique_strings(
            function.function_id
            for function in candidates
            if function is not None
            and re.search(rf"\b{re.escape(function.name)}\b", source)
        )

    async def review(
        self,
        draft: HarnessDraft,
        large: LargeFeatureSpec,
        small_features: list[SmallFeatureSpec],
        deterministic_report: GateReport,
    ) -> GateReport:
        """Independently audit a draft inside the Harness Generator role.

        The generation call's self-audit is not independent evidence.  This
        second pass adapts QuartetFuzz's detection/triage idea to the six-agent
        HarnessCreator design: it does not introduce another agent or another
        feature model, and it checks the user's HC01..HC16 contract verbatim.
        Compilation and runtime probes remain the Harness Verifier's job.
        """

        relevant = [
            item for item in small_features
            if item.small_feature_id in large.small_feature_ids
        ]
        function_ids = unique_strings(
            [large.common_anchor, *large.required_functions, *draft.context_function_ids]
            + [
                identifier
                for item in relevant
                for identifier in item.required_functions
            ]
        )
        functions = [
            self.graph.get(identifier)
            for identifier in function_ids
            if identifier in self.graph.bundle.functions
        ]
        response = await self.llm.complete_json(
            role="harness_generator",
            instructions=(
                "Independently audit the generated harness against exactly HC01..HC16. "
                "Do not trust the generator self-audit and do not invent a new feature, Entry, "
                "anchor, API, build target, or policy. Compare the code with the supplied real "
                "function declarations/source and the already established Small/Large Feature "
                "lifecycle. Report exactly one record for every HC01 through HC16. PASS requires "
                "concrete source/code evidence; uncertainty is WARN; a demonstrated violation is "
                "FAIL. For P1-style harness defects and P2-style API/lifecycle misuse, give the "
                "smallest repair in remediation. Entry adequacy and security-boundary observations "
                "must use the supplied Feature/Entry decisions rather than redefining Input Entry. "
                "The pinned canonical OSS-Fuzz files are same-project build/lifecycle guidance, not authority for "
                "calls absent from the opened current-checkout functions and not permission to import unrelated logic. "
                "The workflow has already built and run that pinned canonical integration against the requested local "
            "checkout when canonical_oss_fuzz_reference.local_checkout_preflight explicitly records both build "
            "and runtime success. Therefore an exact canonical pattern that allocates exported fixture state and invokes an "
                "opened current-checkout function may establish its compile-time configuration contract even when an "
                "assertion mentions inaccessible file-scope static state; require explicit adapter bounds and never "
                "require the harness to access that static. When the opened function uses a prerequisite only inside "
                "assert(), the local build-contract evidence proves NDEBUG for that function's object, and the harness "
                "independently bounds the actual array index, treat the removed assertion as compile-time evidence rather "
                "than demanding access to the internal variable. "
                "Initialization, object creation, callbacks, reset, cleanup, and prerequisite state are optional. "
                "Do not WARN or FAIL merely because one of these categories is absent; do so only when supplied "
                "source or Feature evidence establishes that the operation requires it and the harness violates it. "
                "A successfully initialized fixture retained by LLVMFuzzerInitialize for the fuzz-process lifetime is "
                "not a per-input resource leak. If a fixture is irrevocably disabled and every later invocation returns "
                "before allocating or dereferencing it, target-owned fixture objects may likewise remain until process "
                "exit when the opened application exposes no valid public teardown API; per-input responses and temporary "
                "objects must still be released before disabling. Do not demand that a harness call an internal-linkage "
                "teardown function or reimplement it merely to free process-lifetime target state. "
                "Partial initialization failure must still release harness-owned "
                "resources created before irreversible application worker startup, and LLVMFuzzerTestOneInput must not "
                "accumulate new resources across iterations. "
                "Do not treat compilation, linking, sanitizer execution, GDB reachability, or "
                "coverage as proven by static inspection."
            ),
            payload={
                "large_feature": _large_payload(large),
                "small_features": [_small_payload(item) for item in relevant],
                "harness_manifest": as_json(draft.manifest),
                "harness_code": draft.code,
                "generator_self_audit": draft.self_audit,
                "deterministic_lint": as_json(deterministic_report),
                "canonical_oss_fuzz_reference": self._load_canonical_oss_fuzz_reference(),
                "real_functions": _bounded_harness_function_payloads(
                    functions,
                    primary_ids=set(function_ids),
                    focus_lines={},
                    total_source_chars=220_000,
                ),
                "checklist": [
                    {
                        "check_id": check_id,
                        "name": CHECKLIST_NAMES[check_id],
                        "contract": CHECKLIST_CONTRACTS[check_id],
                    }
                    for check_id in CHECKLIST_NAMES
                ],
            },
            output_schema=HARNESS_REVIEW_SCHEMA,
            session_key=self.session_key(large),
        )

        by_id: dict[str, list[dict[str, Any]]] = {}
        for item in object_list(response.get("checks")):
            check_id = str(item.get("check_id", "")).upper()
            if check_id in CHECKLIST_NAMES:
                by_id.setdefault(check_id, []).append(item)

        checks: list[GateCheck] = []
        malformed: list[str] = []
        for check_id, name in CHECKLIST_NAMES.items():
            items = by_id.get(check_id, [])
            if len(items) != 1:
                malformed.append(f"{check_id}: expected one record, got {len(items)}")
                checks.append(GateCheck(
                    check_id,
                    name,
                    CheckStatus.FAIL,
                    "independent audit did not return exactly one check",
                    "re-audit and provide one evidence-bearing result",
                ))
                continue
            item = items[0]
            try:
                status = CheckStatus(str(item.get("status", "FAIL")).upper())
            except ValueError:
                status = CheckStatus.FAIL
            evidence = str(item.get("evidence", "")).strip()
            remediation = str(item.get("remediation", "")).strip()
            if not evidence:
                status = CheckStatus.FAIL
                evidence = "independent audit returned no evidence"
            # The user's generation contract requires every checklist item to
            # be affirmatively satisfied.  WARN is retained in the artifact but
            # is not accepted as a clean generator review.
            checks.append(GateCheck(check_id, name, status, evidence, remediation))

        nonpassing = [
            check.check_id for check in checks
            if check.status is not CheckStatus.PASS
        ]
        if malformed or nonpassing:
            checks.append(GateCheck(
                "HC21",
                "Independent generator audit",
                CheckStatus.FAIL,
                f"malformed={malformed}; nonpassing={nonpassing}; summary={str(response.get('summary', ''))}",
                "apply the independent audit's minimal remediations and regenerate the same Large Feature harness",
            ))
        return GateReport(checks)


CHECKLIST_NAMES = {
    "HC01": "Resource leaks",
    "HC02": "Use-after-free",
    "HC03": "Stale state",
    "HC04": "Input flow",
    "HC05": "Buffer safety",
    "HC06": "Size checks",
    "HC07": "Undefined behaviour",
    "HC08": "No reimplementation",
    "HC09": "Startup / Init sequence",
    "HC10": "Input construction",
    "HC11": "State lifecycle",
    "HC12": "Result / Response handling",
    "HC13": "Cleanup sequence",
    "HC14": "Entry / Function existence",
    "HC15": "Required co-calls and ordering",
    "HC16": "Prerequisite state",
}

CHECKLIST_CONTRACTS = {
    "HC01": "Every harness-owned malloc/new/open/file/session/connection resource is released before the iteration ends on both success and failure paths.",
    "HC02": "No pointer, object, descriptor, or borrowed view is read or written after its lifetime ends.",
    "HC03": "Per-input mutable global/static/application state is reset before the next iteration or isolated in a fresh process.",
    "HC04": "Fuzzer Data and Size materially reach the application input path; the target input is not replaced entirely by constants.",
    "HC05": "No operation reads beyond fuzz bytes, and string APIs receive bounded storage with a terminator only when the real API requires one.",
    "HC06": "Every index, header, length field, selector, and minimum input requirement is guarded before use.",
    "HC07": "Harness code introduces no null dereference, OOB access, signed overflow, invalid shift, unaligned typed access, or other undefined behavior.",
    "HC08": "The harness calls real application parser/protocol/dispatch/state logic and does not reimplement or bypass it.",
    "HC09": "Configuration, context creation, subsystem startup, and other initialization occur in the same required order as the application path.",
    "HC10": "Network, argv, stdin, file, environment, IPC/RPC, or device input is constructed and delivered in the form the real Entry accepts.",
    "HC11": "The real state lifecycle is preserved, including sequences such as connect/authenticate/request/disconnect or create/start/use/stop/destroy.",
    "HC12": "Return values, status codes, responses, and failure states are handled, and later actions do not run after a failed prerequisite.",
    "HC13": "Success and every failure path clean sessions, descriptors, files, temporary objects, threads, and processes in the application's valid shutdown order.",
    "HC14": "Every called Entry, handler, parser, dispatcher, and helper exists in the supplied codebase and belongs to an evidenced execution path.",
    "HC15": "When source requires paired calls, preserve their order, including connect/disconnect, login/logout, begin/commit, and create/destroy.",
    "HC16": "Session, authentication, configuration, connection, object, and mode prerequisites are created through real application behavior before target input is used.",
}


class StaticHarnessGate:
    """Conservative, evidence-producing pre-build checks for the 16-item contract."""

    def __init__(self, graph: GraphStore, project: ProjectSpec | None = None):
        self.graph = graph
        self.project = project

    def check(
        self,
        draft: HarnessDraft,
        large: LargeFeatureSpec,
        small_features: list[SmallFeatureSpec],
    ) -> GateReport:
        code = draft.code
        semantic_code = _code_only(code)
        checks: list[GateCheck] = []
        selected_features = [
            feature for feature in small_features
            if feature.small_feature_id in large.small_feature_ids
        ]
        add = lambda item, status, evidence, remediation="": checks.append(
            GateCheck(item, CHECKLIST_NAMES[item], status, evidence, remediation)
        )

        # Objects created once by LLVMFuzzerInitialize intentionally live for
        # the fuzzer process, as in the canonical OSS-Fuzz harness. HC01 is
        # about resources acquired by an iteration (including helper calls),
        # not those process-lifetime fixtures.
        per_iteration_code = _without_named_function_body(
            semantic_code, "LLVMFuzzerInitialize"
        )
        resource_issues = _resource_cleanup_issues(per_iteration_code)
        add("HC01", CheckStatus.PASS if not resource_issues else CheckStatus.FAIL,
            "every visible allocation/open family has a matching cleanup family" if not resource_issues else f"unmatched resource families: {resource_issues}",
            "route every allocation/open through one cleanup path")

        uaf = bool(re.search(
            r"(?:free\s*\((\w+)\)|delete\s+(\w+)).{0,300}\b(?:\1|\2)\b",
            semantic_code,
            re.DOTALL,
        ))
        # Textual reuse after free also matches valid ``ptr = NULL`` and
        # cleanup bookkeeping. Keep the hit as audit evidence, but let the
        # independent review and sanitizer replay decide whether it is a real
        # P1 defect instead of rejecting a harness on regex alone.
        add("HC02", CheckStatus.WARN if uaf else CheckStatus.PASS,
            "textual post-release reuse requires independent triage" if uaf else "no simple post-release use pattern detected")

        mutable_static = _has_mutable_static_object(semantic_code)
        isolation_visible = _execution_model_visible(
            semantic_code, draft.manifest.execution_model
        )
        stale_state = mutable_static and not isolation_visible
        declared_isolation_missing = (
            draft.manifest.execution_model
            in {"fork_per_input", "subprocess", "loopback_network"}
            and not isolation_visible
        )
        add("HC03", CheckStatus.FAIL if stale_state or declared_isolation_missing else CheckStatus.PASS,
            (
                f"declared {draft.manifest.execution_model} isolation is implemented"
                if isolation_visible and draft.manifest.execution_model != "in_process_reset"
                else f"declared {draft.manifest.execution_model} isolation is not present in harness code"
                if declared_isolation_missing
                else "mutable harness static has no independently proven per-iteration reset"
                if stale_state
                else "no mutable harness static detected"
            ),
            "remove harness-owned mutable static state or use an isolated execution model")

        fuzzer_body = _fuzzer_function_body(semantic_code)
        data_name, size_name = _fuzzer_parameter_names(semantic_code)
        input_body = fuzzer_body
        if data_name and size_name:
            input_body = re.sub(
                rf"\(\s*void\s*\)\s*(?:{re.escape(data_name)}|{re.escape(size_name)})\s*;",
                "",
                input_body,
            )
        uses_input = bool(
            data_name and size_name
            and re.search(rf"\b{re.escape(data_name)}\b", input_body)
            and re.search(rf"\b{re.escape(size_name)}\b", input_body)
        )
        add("HC04", CheckStatus.PASS if uses_input else CheckStatus.FAIL,
            "fuzzer Data and Size are both used beyond the ABI declaration" if uses_input else "fuzzer Data/Size are absent or only discarded")

        unsafe_string = bool(data_name and re.search(
            rf"\b(strlen|strcpy|strcat|sprintf)\s*\([^;]*\b{re.escape(data_name)}\b",
            semantic_code,
        ))
        add("HC05", CheckStatus.FAIL if unsafe_string else CheckStatus.PASS,
            "unbounded string operation on fuzz bytes" if unsafe_string else "no obvious unbounded string operation on fuzz bytes")

        indexes_input = bool(data_name and re.search(
            rf"\b{re.escape(data_name)}\s*\[", semantic_code
        ))
        has_size_guard = bool(size_name and re.search(
            rf"(?:if\s*\([^)]*\b{re.escape(size_name)}\b|\b{re.escape(size_name)}\b\s*[<>=])",
            semantic_code,
        ))
        add("HC06", CheckStatus.PASS if not indexes_input or has_size_guard else CheckStatus.FAIL,
            "input indexing is guarded by a size condition" if indexes_input and has_size_guard else "no direct input indexing" if not indexes_input else "input indexed without a visible size guard")

        obvious_ub = bool(data_name and re.search(
            rf"\*\s*\(\s*(?:u?int(?:16|32|64)_t|size_t)\s*\*\s*\)\s*{re.escape(data_name)}\b",
            semantic_code,
        ))
        add("HC07", CheckStatus.FAIL if obvious_ub else CheckStatus.PASS,
            "unaligned typed dereference of fuzz bytes" if obvious_ub else "no obvious unaligned typed dereference detected")

        anchor = self.graph.bundle.functions.get(large.common_anchor)
        anchor_entrances = (
            _invoked_application_entrances_to(
                semantic_code,
                code,
                self.graph,
                large.common_anchor,
            )
            if anchor else []
        )
        anchor_called = bool(anchor_entrances)
        add("HC08", CheckStatus.PASS if anchor_called else CheckStatus.FAIL,
            (
                f"real application call path reaches anchor {anchor.name}: {anchor_entrances}"
                if anchor_called and anchor else "no invoked real application function has a graph path to the anchor"
            ),
            "call the application anchor or an evidenced real caller that reaches it instead of duplicating its behavior")

        # The Small Feature agent has already walked the source one function at
        # a time and records whether every anchor/action/Entry edge is proven.
        # Fuzz Introspector can legitimately omit callback and function-pointer
        # edges.  Preserve the proven source walk here instead of undoing it by
        # requiring the incomplete FI graph to rediscover the same path.
        protocol_by_feature = {
            str(item.get("small_feature_id", "")): item
            for item in draft.operation_protocols
        }
        feature_paths_proven = bool(selected_features) and all(
            bool(getattr(feature, "semantic_complete", True))
            and (
                (
                    feature.boundary_preserved
                    and feature.entry_paths_complete
                    and feature.anchor_action_complete
                    and feature.action_order_complete
                    and getattr(feature, "function_references_complete", True)
                    and feature.entry_order_complete
                )
                or feature.small_feature_id in protocol_by_feature
            )
            for feature in selected_features
        )
        proven_feature_function_ids = {
            identifier
            for feature in selected_features
            for identifier in getattr(feature, "required_functions", [])
        }

        required_initialization = unique_strings(
            step for feature in selected_features for step in feature.initialization
        )
        init_status, init_evidence = _lifecycle_step_status(
            required_initialization,
            semantic_code,
            self.graph,
            large.common_anchor,
            proven_function_ids=proven_feature_function_ids,
            proven_anchor_path=anchor_called and feature_paths_proven,
        )
        add(
            "HC09",
            init_status,
            init_evidence,
        )

        binding_known = bool(selected_features) and all(
            (feature.input_binding_proven and feature.input_bindings)
            or bool(protocol_by_feature.get(feature.small_feature_id, {}).get(
                "input_delivery_function_id"
            ))
            for feature in selected_features
        )
        add("HC10", CheckStatus.PASS if binding_known and uses_input else CheckStatus.FAIL,
            "fuzz bytes follow a substantiated input binding for every root Entry" if binding_known and uses_input else "input transport equivalence is not established for every root Entry")

        planning_ok = feature_paths_proven
        planning_blockers = unique_strings(
            blocker for feature in selected_features for blocker in feature.planning_blockers
        )
        add("HC11", CheckStatus.PASS if planning_ok else CheckStatus.FAIL,
            "every semantic Small Feature has either its original proven plan or a source-validated P2 operation protocol" if planning_ok else f"feature lifecycle/input path remains unresolved after P2: {planning_blockers}")

        action_function_ids = unique_strings(
            [large.common_anchor]
            + [
            str(action.get("function_id", ""))
            for feature in selected_features
            for action in feature.actions
            ]
        )
        nonvoid_actions = [
            self.graph.bundle.functions[function_id]
            for function_id in action_function_ids
            if function_id in self.graph.bundle.functions
            and not _function_returns_void(self.graph.bundle.functions[function_id])
        ]
        unhandled_results = [
            function.name for function in nonvoid_actions
            if _function_invoked(semantic_code, function.name)
            and not _call_result_handled(semantic_code, function.name)
        ]
        result_checked = not unhandled_results
        add("HC12", CheckStatus.PASS if result_checked else CheckStatus.FAIL,
            "all non-void application action results are checked or propagated" if result_checked else f"unhandled non-void action results: {unhandled_results}")

        required_cleanup = unique_strings(
            step
            for feature in selected_features
            for step in [*feature.cleanup_success, *feature.cleanup_failure]
        )
        cleanup_status, cleanup_evidence = _lifecycle_step_status(
            required_cleanup,
            semantic_code,
            self.graph,
            large.common_anchor,
            proven_function_ids=proven_feature_function_ids,
            proven_anchor_path=anchor_called and feature_paths_proven,
        )
        add(
            "HC13",
            cleanup_status,
            cleanup_evidence,
        )

        missing = [identifier for identifier in large.required_functions if identifier not in self.graph.bundle.functions]
        add("HC14", CheckStatus.FAIL if missing else CheckStatus.PASS,
            f"unknown function IDs: {missing}" if missing else "all referenced function IDs exist in the analysis bundle")

        # The sequential Harness Generator is only allowed to call project
        # functions whose current-checkout source it opened in this agent
        # session.  A canonical OSS-Fuzz harness may suggest an initializer,
        # but it is not evidence that the same API/lifecycle still applies to
        # the checkout under analysis.  Keep this as a repairable harness-
        # context failure (rather than HC14's missing-codebase failure) so the
        # next attempt can open the exact functions one at a time.
        unopened_project_calls: list[str] = []
        if draft.context_function_ids:
            opened_names = {
                self.graph.bundle.functions[identifier].name
                for identifier in draft.context_function_ids
                if identifier in self.graph.bundle.functions
            }
            invoked_names = {
                function.name
                for function in self.graph.bundle.functions.values()
                if _function_invoked(semantic_code, function.name)
            }
            unopened_project_calls = sorted(invoked_names - opened_names)
        checks.append(GateCheck(
            "HC23",
            "Opened current-checkout source",
            CheckStatus.FAIL if unopened_project_calls else CheckStatus.PASS,
            (
                f"project functions called without opening their current source: {unopened_project_calls}"
                if unopened_project_calls
                else "every detected project function call is backed by source opened in this harness session"
            ),
            "open each required current-checkout function in the same stateful Harness Generator session before regenerating",
        ))

        variants_ok = len(large.variants) <= 1 or (
            draft.manifest.dispatch_strategy in {"selector_byte", "shared_selector_byte", "one_job_per_feature"}
            and has_size_guard
        )
        action_contract_ok = bool(selected_features) and all(
            (feature.action_order_complete and feature.entry_order_complete)
            or feature.small_feature_id in protocol_by_feature
            for feature in selected_features
        )
        dependency_contract_ok = bool(selected_features) and all(
            _feature_dependencies_match_actions(feature)
            for feature in selected_features
        ) and _large_dependencies_match_protocols(
            large, selected_features, protocol_by_feature,
            set(self.graph.bundle.functions),
        )
        completion_contract_ok = bool(selected_features) and all(
            bool(protocol_by_feature.get(feature.small_feature_id, {}).get(
                "completion_function_id"
            ))
            or bool(_completion_target_function_id(
                feature, set(self.graph.bundle.functions)
            ))
            for feature in selected_features
        )
        expected_action_functions: list[tuple[SmallFeatureSpec, str]] = []
        for feature in selected_features:
            expected_action_functions.extend(
                (feature, str(action.get("function_id", "")))
                for action in feature.actions
            )
            expected_action_functions.extend(
                (feature, function_id)
                for function_id in string_list(
                    protocol_by_feature.get(feature.small_feature_id, {}).get(
                        "ordered_function_ids"
                    )
                )
            )
        missing_action_calls = unique_strings(
            self.graph.bundle.functions[function_id].name
            for feature, function_id in expected_action_functions
            if function_id in self.graph.bundle.functions
            and not _function_invoked(
                semantic_code, self.graph.bundle.functions[function_id].name
            )
            and not self.graph.shortest_path(
                large.common_anchor, function_id, max_depth=12
            )
            and not (
                anchor_called
                and feature.small_feature_id not in protocol_by_feature
                and feature.anchor_action_complete
                and feature.entry_paths_complete
                and getattr(feature, "function_references_complete", True)
                and function_id in feature.required_functions
            )
        )
        action_calls_ok = not missing_action_calls
        action_state_ok = (
            variants_ok
            and action_contract_ok
            and dependency_contract_ok
            and completion_contract_ok
            and action_calls_ok
        )
        add("HC15", CheckStatus.PASS if action_state_ok else CheckStatus.FAIL,
            "variant dispatch is guarded and every evidenced dependency/action is ordered with an explicit semantic completion target that is directly invoked or reachable from the real anchor" if action_state_ok else f"action/state constraints incomplete: variants_ok={variants_ok}, contract_ok={action_contract_ok}, dependency_contract_ok={dependency_contract_ok}, completion_contract_ok={completion_contract_ok}, unreachable_actions={missing_action_calls}")

        prerequisite_status, prerequisite_evidence = _lifecycle_step_status(
            large.prerequisite_state,
            semantic_code,
            self.graph,
            large.common_anchor,
            proven_function_ids=proven_feature_function_ids,
            proven_anchor_path=anchor_called and feature_paths_proven,
        )
        add(
            "HC16",
            prerequisite_status,
            prerequisite_evidence,
        )

        if not code.strip():
            checks.append(GateCheck("HC00", "Generated source exists", CheckStatus.FAIL, "generator returned empty source"))
        if draft.manifest.engine == "libfuzzer":
            if "LLVMFuzzerTestOneInput" not in semantic_code:
                checks.append(GateCheck(
                    "HC17", "Fuzzer ABI", CheckStatus.FAIL,
                    "LLVMFuzzerTestOneInput is missing",
                ))
            elif Path(draft.manifest.source_file).suffix.lower() != ".c" and not re.search(
                r'extern\s+"C"\s+(?:[^;{}]*?\s+)?LLVMFuzzerTestOneInput\s*\(',
                code,
            ):
                checks.append(GateCheck(
                    "HC17", "Fuzzer ABI", CheckStatus.FAIL,
                    "C++ harness does not export LLVMFuzzerTestOneInput with C linkage",
                    'define it as extern "C" int LLVMFuzzerTestOneInput(...)',
                ))
        if draft.generation_blockers:
            checks.append(GateCheck(
                "HC18",
                "Generator blockers",
                CheckStatus.FAIL,
                "; ".join(draft.generation_blockers),
                "resolve analysis/build/lifecycle evidence before regenerating",
            ))
        unresolved_target = not draft.manifest.build_target.strip() or (
            draft.manifest.build_target.strip().upper() == "UNRESOLVED"
        )
        trusted_build_integration = bool(
            (draft.manifest.build_command and draft.manifest.binary)
            or (
                draft.manifest.verification_backend == "oss-fuzz"
                and draft.manifest.backend_target
            )
        )
        checks.append(GateCheck(
            "HC19",
            "Build integration target",
            (
                CheckStatus.PASS
                if not unresolved_target and trusted_build_integration
                else CheckStatus.FAIL
            ),
            (
                "manifest build target is unresolved"
                if unresolved_target
                else (
                    f"trusted {draft.manifest.verification_backend} build integration is configured for target: "
                    f"{draft.manifest.build_target}"
                    if trusted_build_integration
                    else (
                        f"target {draft.manifest.build_target} is named, but no trusted "
                        "build command/binary pair is configured"
                    )
                )
            ),
            "supply a trusted command build/binary pair or an OSS-Fuzz project/fuzzer integration; a target name alone is not build integration",
        ))

        process_calls = unique_strings(
            match.group(1)
            for match in re.finditer(
                r"\b(fork|vfork|execv|execve|execvp|execl|execlp|posix_spawn|posix_spawnp|system|popen)\s*\(",
                semantic_code,
            )
        )
        process_model = draft.manifest.execution_model in {
            "fork_per_input", "subprocess"
        }
        checks.append(GateCheck(
            "HC21",
            "Fuzzer feedback boundary",
            CheckStatus.FAIL if process_calls or process_model else CheckStatus.PASS,
            (
                "libFuzzer target code remains in the instrumented process"
                if not process_calls and not process_model
                else (
                    "ordinary child/subprocess execution is incompatible with the current "
                    f"in-process libFuzzer verifier; execution_model={draft.manifest.execution_model}; "
                    f"calls={process_calls}"
                )
            ),
            (
                "invoke the application path in-process with evidenced reset/cleanup, or add a real "
                "forkserver/subprocess backend that transports coverage and crash status"
            ),
        ))

        included_implementations = unique_strings(
            match.group(1)
            for match in re.finditer(
                r'^[ \t]*#\s*include\s*["<]([^">]+\.(?:c|cc|cpp|cxx))[">]',
                code,
                re.MULTILINE | re.IGNORECASE,
            )
        )
        internal_linkage = (
            _internal_linkage_references(
                semantic_code,
                self.project.source_root,
                self.graph,
            )
            if self.project is not None
            else []
        )
        checks.append(GateCheck(
            "HC22",
            "Build boundary",
            (
                CheckStatus.FAIL
                if included_implementations or internal_linkage
                else CheckStatus.PASS
            ),
            (
                "application implementations are linked by the project build"
                if not included_implementations and not internal_linkage
                else "; ".join(filter(None, [
                    (
                        "harness directly includes application implementation files: "
                        f"{included_implementations}"
                        if included_implementations else ""
                    ),
                    (
                        "harness references file-scope static application symbols that are "
                        f"not externally linkable: {internal_linkage}"
                        if internal_linkage else ""
                    ),
                ]))
            ),
            "use declarations from real headers and public initialization APIs; never access a file-scope static implementation symbol from the harness",
        ))
        audit_by_id: dict[str, list[dict[str, Any]]] = {}
        for item in draft.self_audit:
            check_id = str(item.get("check_id", ""))
            if check_id in CHECKLIST_NAMES:
                audit_by_id.setdefault(check_id, []).append(item)
        missing_audits = [check_id for check_id in CHECKLIST_NAMES if check_id not in audit_by_id]
        duplicate_audits = [check_id for check_id, items in audit_by_id.items() if len(items) != 1]
        nonpassing_audits = [
            check_id
            for check_id, items in audit_by_id.items()
            if len(items) != 1
            or str(items[0].get("status", "")).upper() != "PASS"
            or not str(items[0].get("evidence", "")).strip()
        ]
        if missing_audits or duplicate_audits or nonpassing_audits:
            checks.append(GateCheck(
                "HC20",
                "Generator self-audit",
                CheckStatus.FAIL,
                (
                    f"missing={missing_audits}; duplicate={duplicate_audits}; "
                    f"nonpassing_or_empty={nonpassing_audits}"
                ),
                "return exactly one PASS record with concrete evidence for every HC01..HC16 item",
            ))
        return GateReport(checks)


class _HarnessVerifierSeedPlanner:
    """Internal seed-planning step of the Harness Verifier Agent.

    This is intentionally not a seventh agent.  It uses the fixed
    ``harness_verifier`` model role and prepares adversarial inputs for that
    agent's deterministic replay/debug/fuzz loop.
    """

    def __init__(self, llm: LLMProvider):
        self.llm = llm

    @staticmethod
    def session_key(draft: HarnessDraft) -> str:
        return f"harness_verifier:{draft.manifest.harness_id}"

    async def close_session(self, draft: HarnessDraft) -> None:
        await close_llm_session(self.llm, self.session_key(draft))

    async def run(
        self,
        draft: HarnessDraft,
        large: LargeFeatureSpec,
        static_report: GateReport,
        *,
        validation_feedback: list[str] | None = None,
        existing_seeds: list[SeedSpec] | None = None,
    ) -> list[SeedSpec]:
        response = await self.llm.complete_json(
            role="harness_verifier",
            instructions=(
                "Propose 14-24 bounded adversarial raw inputs that are likely to expose faults in the generated harness itself. "
                "Include at least five inputs expected to reach the application anchor. For every selector N, include "
                "at least one input named variant-N-reach whose first byte selects N and whose remaining bytes satisfy "
                "the minimum real protocol/state shape needed to reach that variant target. Also cover "
                "zero/minimum/just-below boundaries, selector variants, embedded NUL, maximum encoded lengths, cleanup "
                "failure paths, repeated state transitions, and malformed transport framing. Seeds must exercise the "
                "declared input contract; do not assume functions not shown. Return raw bytes as even-length hex. Keep "
                "each seed at most 65536 bytes. These seeds validate the harness; a target crash will be attributed "
                "separately with sanitizer/GDB evidence. Attach check_ids to every seed. Collectively challenge every "
                "runtime-testable checklist item: HC01, HC02, HC03, HC04, HC05, HC06, HC07, HC09, HC10, HC11, HC12, "
                "HC13, HC15, and HC16. HC08 and HC14 are source/build facts and are not fabricated as input tests."
            ),
            payload={
                "manifest": {
                    "min_size": draft.manifest.min_size,
                    "max_size": draft.manifest.max_size,
                    "dispatch_strategy": draft.manifest.dispatch_strategy,
                    "execution_model": draft.manifest.execution_model,
                    "expected_anchors": draft.manifest.expected_anchors,
                    "expected_consumers": draft.manifest.expected_consumers,
                    "variant_targets": draft.manifest.variant_targets,
                },
                "large_feature": _large_payload(large),
                "harness_code": draft.code,
                "previous_validation_feedback": validation_feedback or [],
                "existing_seed_summaries": [
                    {
                        "name": seed.name,
                        "length": len(seed.data_hex) // 2,
                        "data_hex_prefix": seed.data_hex[:1024],
                        "rationale": seed.rationale,
                        "check_ids": seed.check_ids,
                    }
                    for seed in (existing_seeds or [])
                ],
                "static_warnings": [
                    {"check_id": check.check_id, "evidence": check.evidence}
                    for check in static_report.checks
                    if check.status is CheckStatus.WARN
                ],
            },
            output_schema=SEED_SCHEMA,
            session_key=self.session_key(draft),
        )
        seeds: list[SeedSpec] = []
        seen: set[bytes] = set()
        maximum = min(max(draft.manifest.max_size, 0), 65_536)
        for index, raw in enumerate(object_list(response.get("seeds"))):
            data_hex = str(raw.get("data_hex", ""))
            if len(data_hex) % 2 or len(data_hex) > maximum * 2:
                continue
            try:
                data = bytes.fromhex(data_hex)
            except ValueError:
                continue
            if data in seen:
                continue
            seen.add(data)
            raw_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(raw.get("name", f"llm-{index}"))).strip(".-")
            seeds.append(
                SeedSpec(
                    name=(raw_name or f"llm-{index}")[:80],
                    data_hex=data.hex(),
                    rationale=str(raw.get("rationale", "")),
                    check_ids=unique_strings(string_list(raw.get("check_ids"))),
                )
            )
        return seeds


def _large_payload(feature: LargeFeatureSpec) -> dict[str, Any]:
    return {
        "large_feature_id": feature.large_feature_id,
        "name": feature.name,
        "description": feature.description,
        "small_feature_ids": feature.small_feature_ids,
        "small_feature_names": feature.small_feature_names,
        "common_anchor": feature.common_anchor,
        "common_initialization": feature.common_initialization,
        "common_cleanup": feature.common_cleanup,
        "common_cleanup_failure": feature.common_cleanup_failure,
        "prerequisite_state": feature.prerequisite_state,
        "isolation_mode": feature.isolation_mode,
        "dispatch_strategy": feature.dispatch_strategy,
        "variants": feature.variants,
        "entry_call_graph": feature.entry_call_graph,
        "required_functions": feature.required_functions,
        "security_priority": as_json(feature.security_priority),
        "dependencies": [as_json(item) for item in feature.dependencies],
        "proof_obligations": [as_json(item) for item in feature.proof_obligations],
        "protocol_ready": feature.protocol_ready,
    }


def _small_payload(feature: SmallFeatureSpec) -> dict[str, Any]:
    return {
        "small_feature_id": feature.small_feature_id,
        "name": feature.name,
        "description": feature.description,
        "root_entries": feature.root_entries,
        "supporting_entries": feature.supporting_entries,
        "entry_call_order": feature.entry_call_order,
        "harness_anchor": feature.harness_anchor,
        "preconditions": feature.preconditions,
        "initialization": feature.initialization,
        "required_functions": feature.required_functions,
        "actions": feature.actions,
        "completion_action_id": feature.completion_action_id,
        "dependencies": [as_json(item) for item in feature.dependencies],
        "input_bindings": feature.input_bindings,
        "cleanup_success": feature.cleanup_success,
        "cleanup_failure": feature.cleanup_failure,
        "stable_post_state": feature.stable_post_state,
        "completion_oracle": feature.completion_oracle,
        "unknowns": feature.unknowns,
        "input_binding_proven": feature.input_binding_proven,
        "entry_paths_complete": feature.entry_paths_complete,
        "anchor_action_complete": feature.anchor_action_complete,
        "action_order_complete": feature.action_order_complete,
        "function_references_complete": feature.function_references_complete,
        "entry_order_complete": feature.entry_order_complete,
        "planning_complete": feature.planning_complete,
        "planning_blockers": feature.planning_blockers,
        "semantic_complete": feature.semantic_complete,
        "semantic_blockers": feature.semantic_blockers,
        "proof_obligations": [as_json(item) for item in feature.proof_obligations],
        "operation_seed_ids": feature.operation_seed_ids,
    }


def _feature_dependencies_match_actions(feature: SmallFeatureSpec) -> bool:
    """Recheck dependency endpoints/order at the final static gate."""

    positions = {
        str(action.get("action_id", "")): index
        for index, action in enumerate(feature.actions)
        if str(action.get("action_id", ""))
    }
    for dependency in getattr(feature, "dependencies", []):
        producer = positions.get(dependency.producer_action_id)
        consumer = positions.get(dependency.consumer_action_id)
        if producer is None or consumer is None or producer >= consumer:
            return False
        predecessors = feature.actions[consumer].get("allowed_after", [])
        if not isinstance(predecessors, list):
            predecessors = [predecessors]
        if dependency.producer_action_id not in {
            str(value) for value in predecessors
        }:
            return False
    return True


def _completion_target_function_id(
    feature: SmallFeatureSpec,
    known_function_ids: set[str],
) -> str:
    """Resolve the explicit semantic completion action, never list tail.

    QuartetFuzz's reachability primitive checks a caller-supplied target; it
    does not infer which action represents feature completion. Selecting the
    last action can therefore turn trailing cleanup into a false target.
    """

    action_by_id = {
        str(action.get("action_id", "")): action
        for action in feature.actions
        if str(action.get("action_id", ""))
    }
    completion_action_id = str(
        getattr(feature, "completion_action_id", "")
    ).strip()
    if not completion_action_id and len(action_by_id) == 1:
        # Unambiguous compatibility for old programmatic single-action specs.
        # New model output is schema-required to name this field.
        completion_action_id = next(iter(action_by_id))
    action = action_by_id.get(completion_action_id)
    if action is None:
        return ""
    function_id = str(action.get("function_id", ""))
    return function_id if function_id in known_function_ids else ""


def _large_dependencies_match_protocols(
    large: LargeFeatureSpec,
    features: list[SmallFeatureSpec],
    protocol_by_feature: dict[str, dict[str, Any]],
    known_function_ids: set[str],
) -> bool:
    if not getattr(large, "dependencies", []):
        return True
    feature_by_id = {feature.small_feature_id: feature for feature in features}
    for dependency in large.dependencies:
        producer = feature_by_id.get(dependency.producer_small_feature_id)
        consumer = feature_by_id.get(dependency.consumer_small_feature_id)
        if producer is None or consumer is None:
            return False
        producer_protocol = protocol_by_feature.get(producer.small_feature_id, {})
        consumer_protocol = protocol_by_feature.get(consumer.small_feature_id, {})
        producer_target = str(
            producer_protocol.get("completion_function_id", "")
        ) or _completion_target_function_id(producer, known_function_ids)
        consumer_target = str(
            consumer_protocol.get("completion_function_id", "")
        ) or _completion_target_function_id(consumer, known_function_ids)
        consumer_order = string_list(
            consumer_protocol.get("ordered_function_ids")
        )
        if (
            not producer_target
            or not consumer_target
            or producer_target not in consumer_order
            or consumer_target not in consumer_order
            or consumer_order.index(producer_target)
            >= (
                len(consumer_order) - 1
                - consumer_order[::-1].index(consumer_target)
            )
        ):
            return False
    return True


def _validated_operation_protocols(
    raw_value: Any,
    features: list[SmallFeatureSpec],
    functions: list[FunctionMetadata],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate P2 plans against source opened in this exact agent session."""

    feature_ids = {feature.small_feature_id for feature in features}
    function_by_id = {function.function_id: function for function in functions}
    accepted: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for raw in object_list(raw_value):
        feature_id = str(raw.get("small_feature_id", "")).strip()
        if feature_id not in feature_ids:
            errors.append(
                f"operation protocol references unknown Small Feature {feature_id or '<missing>'}"
            )
            continue
        if feature_id in seen:
            errors.append(f"duplicate operation protocol for {feature_id}")
            continue
        # Repeated calls are meaningful (for example SET then GET through the
        # same dispatcher), so preserve order and multiplicity.
        ordered = string_list(raw.get("ordered_function_ids"))
        input_function_id = str(
            raw.get("input_delivery_function_id", "")
        ).strip()
        completion_function_id = str(
            raw.get("completion_function_id", "")
        ).strip()
        unknown = [
            identifier for identifier in [*ordered, input_function_id, completion_function_id]
            if identifier not in function_by_id
        ]
        if unknown:
            errors.append(
                f"{feature_id} protocol uses unopened function IDs: {unique_strings(unknown)}"
            )
            continue
        if not ordered or input_function_id not in ordered or completion_function_id not in ordered:
            errors.append(
                f"{feature_id} protocol order does not contain its input-delivery and completion functions"
            )
            continue
        evidence: list[dict[str, Any]] = []
        evidenced_ids: set[str] = set()
        for item in object_list(raw.get("evidence")):
            function_id = str(item.get("function_id", "")).strip()
            function = function_by_id.get(function_id)
            try:
                line = int(item.get("line"))
            except (TypeError, ValueError):
                continue
            if function is None or not (
                function.start_line <= line <= function.end_line
            ):
                continue
            detail = str(item.get("detail", "")).strip()
            if not detail:
                continue
            evidence.append({
                "function_id": function_id,
                "file": function.file,
                "line": line,
                "detail": detail,
            })
            evidenced_ids.add(function_id)
        required_evidence = {input_function_id, completion_function_id}
        if not required_evidence <= evidenced_ids:
            errors.append(
                f"{feature_id} protocol lacks exact opened-source evidence for "
                f"{sorted(required_evidence - evidenced_ids)}"
            )
            continue
        seen.add(feature_id)
        accepted.append({
            "small_feature_id": feature_id,
            "ordered_function_ids": ordered,
            "input_delivery_function_id": input_function_id,
            "completion_function_id": completion_function_id,
            "evidence": evidence,
            "rationale": str(raw.get("rationale", "")).strip(),
            "status": "PROVEN_STATIC",
        })
    return accepted, unique_strings(errors)


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _blocking_dependency_text(item: dict[str, Any]) -> str:
    location = str(item.get("evidence_id", "unknown evidence"))
    if item.get("evidence_line") is not None:
        location += f":{item['evidence_line']}"
    return (
        f"{item.get('description', 'required dependency is unresolved')} "
        f"(required for {item.get('required_for', 'harness generation')}; evidence={location})"
    )


def _bounded_harness_function_payloads(
    functions: list[FunctionMetadata],
    *,
    primary_ids: set[str],
    focus_lines: dict[str, int],
    total_source_chars: int = 300_000,
) -> list[dict[str, Any]]:
    """Keep one generator turn bounded while retaining every function identity.

    Sequential discovery decides which functions are eligible for generation.
    This second bound prevents that explicitly opened set from producing an
    oversized final prompt; it never adds another function.
    """

    primary = [item for item in functions if item.function_id in primary_ids]
    secondary = [item for item in functions if item.function_id not in primary_ids]
    if not secondary:
        primary_budget = total_source_chars
        secondary_budget = 0
    else:
        primary_budget = int(total_source_chars * 0.8) if primary else 0
        secondary_budget = total_source_chars - primary_budget

    def render(group: list[FunctionMetadata], budget: int) -> list[dict[str, Any]]:
        if not group:
            return []
        # Water-fill the budget. The old equal slice discarded every byte a
        # short helper did not use, while truncating a long state machine at
        # exactly the point where its cleanup branch lived. Give each opened
        # function a floor, then redistribute unused capacity up to 24 KiB.
        caps = [max(1, min(24_000, len(function.source))) for function in group]
        floor = max(1, min(1_024, budget // len(group))) if budget > 0 else 1
        allocations = [min(cap, floor) for cap in caps]
        remaining = max(0, budget - sum(allocations))
        active = [index for index, cap in enumerate(caps) if allocations[index] < cap]
        while remaining and active:
            share = max(1, remaining // len(active))
            progressed = False
            for index in active:
                increment = min(caps[index] - allocations[index], share, remaining)
                if increment:
                    allocations[index] += increment
                    remaining -= increment
                    progressed = True
                if not remaining:
                    break
            if not progressed:
                break
            active = [
                index for index in active
                if allocations[index] < caps[index]
            ]
        return [
            function_payload(
                function,
                source_limit=allocations[index],
                focus_line=focus_lines.get(function.function_id),
            )
            for index, function in enumerate(group)
        ]

    return [*render(primary, primary_budget), *render(secondary, secondary_budget)]


def _local_build_contract_evidence(source_root: Path) -> list[dict[str, Any]]:
    """Return small, exact build-file facts relevant to assertion/config gates.

    These snippets are not inferred compiler flags. They become authoritative
    only together with the successful canonical/local-checkout preflight flag
    carried in the same payload.
    """

    candidates = (
        "Makefile.am", "Makefile.in", "CMakeLists.txt", "meson.build",
        "configure.ac", "configure.in",
    )
    relevant = re.compile(r"(?:NDEBUG|FUZZING_BUILD_MODE|CPPFLAGS|CFLAGS)")
    evidence: list[dict[str, Any]] = []
    root = source_root.resolve()
    for relative in candidates:
        path = root / relative
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            if relevant.search(line):
                evidence.append({
                    "file": relative,
                    "line": number,
                    "text": line[:1_000],
                })
                if len(evidence) >= 32:
                    return evidence
    return evidence


def _token_mentioned(description: str, code: str) -> bool:
    tokens = re.findall(r"[A-Za-z_]\w+", description)
    significant = [token for token in tokens if len(token) >= 4]
    return any(re.search(rf"\b{re.escape(token)}\b", code, re.IGNORECASE) for token in significant)


def _lifecycle_step_status(
    steps: list[str],
    code: str,
    graph: GraphStore,
    anchor_id: str,
    *,
    proven_function_ids: set[str] | None = None,
    proven_anchor_path: bool = False,
) -> tuple[CheckStatus, str]:
    proven_function_ids = proven_function_ids or set()
    if not steps:
        return CheckStatus.PASS, "no lifecycle steps are required by the selected features"
    represented: list[str] = []
    explicit_missing: list[str] = []
    descriptive_unresolved: list[str] = []
    for step in steps:
        normalized = " ".join(step.casefold().replace("_", " ").split())
        mentioned_functions = [
            function
            for function in graph.bundle.functions.values()
            if len(function.name) >= 4
            # A lifecycle sentence can mention an alternative/error branch
            # that does not belong to the selected operation.  Planning-complete
            # Small Features already enumerate the functions their lifecycle
            # requires; only those IDs may become an explicit invocation
            # obligation.  Otherwise a sentence such as "FLUSH disabled calls
            # an unrelated handler name can incorrectly make a harness call
            # the unrelated FLUSH handler.
            and (
                not proven_function_ids
                or function.function_id in proven_function_ids
            )
            and re.search(
                rf"\b{re.escape(' '.join(function.name.casefold().replace('_', ' ').split()))}\b",
                normalized,
            )
        ]
        if mentioned_functions:
            if any(
                _function_invoked(code, function.name)
                or graph.shortest_path(anchor_id, function.function_id, max_depth=12)
                or (
                    proven_anchor_path
                    and function.function_id in proven_function_ids
                )
                for function in mentioned_functions
            ):
                represented.append(step)
            else:
                explicit_missing.append(step)
        elif _token_mentioned(step, code):
            represented.append(step)
        elif proven_anchor_path:
            # Source-complete Small Feature planning already proved this
            # descriptive state requirement on the invoked anchor path. A
            # lexical token match is not a second semantic proof obligation.
            represented.append(step)
        else:
            descriptive_unresolved.append(step)
    if explicit_missing:
        return (
            CheckStatus.FAIL,
            f"explicit lifecycle functions are absent from harness code: {explicit_missing}",
        )
    if descriptive_unresolved:
        return (
            CheckStatus.WARN,
            f"natural-language lifecycle steps need build/runtime confirmation: {descriptive_unresolved}; visible={represented}",
        )
    return CheckStatus.PASS, f"visible lifecycle references: {represented}"


def _function_returns_void(function: Any) -> bool:
    declaration = function.declaration or function.signature
    return bool(
        re.search(
            rf"(?:^|\s)void\s+\**\s*(?:{re.escape(function.qualified_name)}|{re.escape(function.name)})\s*\(",
            declaration,
        )
    )


def _call_result_handled(code: str, function_name: str) -> bool:
    found = False
    for match in re.finditer(rf"\b{re.escape(function_name)}\s*\(", code):
        line_start = code.rfind("\n", 0, match.start()) + 1
        line_end = code.find("\n", match.end())
        if line_end < 0:
            line_end = len(code)
        line = code[line_start:line_end]
        prefix = line[:match.start() - line_start]
        suffix = line[match.end() - line_start:]
        before = prefix.strip()
        typeish = bool(before) and bool(
            re.fullmatch(r'(?:extern\s+"C"\s+)?[A-Za-z_][\w:<>,*&\s]*', before)
        )
        # A type-only prefix identifies a declaration/definition even when its
        # parameter list and terminating ';'/'{' continue on later lines.
        if typeish:
            continue
        found = True
        if (
            re.search(r"\b(return|if|while|switch|assert)\b", prefix)
            or re.search(r"\)\s*(?:==|!=|<|>|<=|>=)", suffix)
        ):
            continue
        assignment = re.search(r"\b([A-Za-z_]\w*)\s*=\s*$", prefix)
        if assignment:
            result_name = assignment.group(1)
            statement_end = code.find(";", match.end())
            remaining = code[statement_end + 1:] if statement_end >= 0 else ""
            # Merely assigning the result and silencing the compiler with
            # ``(void)rc`` is not result handling.  Require a subsequent
            # semantic use such as a branch, return, comparison, propagation,
            # or another call argument.
            remaining = re.sub(
                rf"\(\s*void\s*\)\s*{re.escape(result_name)}\s*;",
                "",
                remaining,
            )
            if re.search(rf"\b{re.escape(result_name)}\b", remaining):
                continue
        return False
    return found


def _has_mutable_static_object(code: str) -> bool:
    """Distinguish persistent objects from ordinary static helper functions."""

    for match in re.finditer(r"\bstatic\s+(?!const\b)([^;{}]+);", code):
        declaration = match.group(1).strip()
        # A function prototype has no persistent per-input state. Initializers
        # and function-pointer objects remain state and are intentionally kept.
        if "=" not in declaration and re.search(r"\w\s*\([^()]*\)\s*$", declaration):
            continue
        return True
    return False


def _execution_model_visible(code: str, execution_model: str) -> bool:
    """Confirm that manifest isolation exists in the generated source."""

    if execution_model == "in_process_reset":
        return True
    if execution_model == "fork_per_input":
        return bool(
            re.search(r"\b(?:fork|vfork)\s*\(", code)
            and re.search(r"\b(?:wait|waitpid|waitid)\s*\(", code)
        )
    if execution_model == "subprocess":
        return bool(re.search(
            r"\b(?:fork|vfork|execv(?:e|p)?|posix_spawn(?:p)?|CreateProcess[A-Z]*)\s*\(",
            code,
        ))
    if execution_model == "loopback_network":
        # ``socketpair`` already creates both connected endpoints.  Requiring
        # an additional connect/accept call rejects the smallest faithful
        # transport adapter even though target code still receives bytes
        # through its real read/recv path.
        if re.search(r"\bsocketpair\s*\(", code):
            return True
        return bool(
            re.search(r"\bsocket\s*\(", code)
            and re.search(r"\b(?:connect|accept|accept4|bind)\s*\(", code)
        )
    return False


def _resource_cleanup_issues(code: str) -> list[str]:
    pairs = {
        "heap": (r"\b(?:malloc|calloc|realloc)\s*\(", r"\bfree\s*\("),
        "new": (r"\bnew\b", r"\bdelete\b"),
        "stdio": (r"\bfopen\s*\(", r"\bfclose\s*\("),
        "fd": (r"(?<![A-Za-z_])open\s*\(", r"(?<![A-Za-z_])close\s*\("),
    }
    return [
        family for family, (acquire, release) in pairs.items()
        if re.search(acquire, code) and not re.search(release, code)
    ]


def _without_named_function_body(code: str, function_name: str) -> str:
    """Blank one function body while preserving surrounding helper source."""

    for marker in re.finditer(rf"\b{re.escape(function_name)}\s*\(", code):
        opening = code.find("{", marker.end())
        terminator = code.find(";", marker.end())
        if opening < 0 or (terminator >= 0 and terminator < opening):
            continue
        depth = 0
        for index in range(opening, len(code)):
            if code[index] == "{":
                depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0:
                    return (
                        code[:opening + 1]
                        + (" " * (index - opening - 1))
                        + code[index:]
                    )
    return code


def _fuzzer_function_body(code: str) -> str:
    marker = code.find("LLVMFuzzerTestOneInput")
    if marker < 0:
        return ""
    opening = code.find("{", marker)
    if opening < 0:
        return ""
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[opening + 1:index]
    return code[opening + 1:]


def _fuzzer_parameter_names(code: str) -> tuple[str, str]:
    marker = code.find("LLVMFuzzerTestOneInput")
    if marker < 0:
        return "", ""
    opening = code.find("(", marker)
    if opening < 0:
        return "", ""
    depth = 0
    closing = -1
    for index in range(opening, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        return "", ""
    parameters = code[opening + 1:closing].split(",")
    names: list[str] = []
    for parameter in parameters[:2]:
        identifiers = re.findall(r"[A-Za-z_]\w*", parameter)
        names.append(identifiers[-1] if identifiers else "")
    while len(names) < 2:
        names.append("")
    return names[0], names[1]


def _function_invoked(code: str, function_name: str) -> bool:
    """Accept direct or helper-contained calls while ignoring plain declarations."""

    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for match in pattern.finditer(code):
        line_start = code.rfind("\n", 0, match.start()) + 1
        line_end = code.find("\n", match.end())
        if line_end < 0:
            line_end = len(code)
        before = code[line_start:match.start()].strip()
        # A declaration/definition has only a type-ish prefix before the name.
        # Calls either start the statement or are preceded by assignment,
        # control-flow, return, a comma, or another expression operator.
        typeish = bool(before) and bool(
            re.fullmatch(r"(?:extern\s+\"C\"\s+)?[A-Za-z_][\w:<>,*&\s]*", before)
        )
        first_token = before.split(maxsplit=1)[0] if before else ""
        if first_token in {"return", "if", "while", "switch", "case"}:
            typeish = False
        if typeish:
            continue
        return True
    return False


def _internal_linkage_references(
    code: str,
    source_root: Path,
    graph: GraphStore,
) -> list[str]:
    """Find application file-scope ``static`` symbols used by the harness.

    The generated file is linked as a separate translation unit, so these
    names can never be valid direct dependencies even though they may appear
    in an opened function body. Limit scanning to source files represented in
    the authoritative analysis bundle rather than walking generated run data.
    """

    source_files = unique_strings(
        function.file
        for function in graph.bundle.functions.values()
        if Path(function.file).suffix.casefold()
        in {".c", ".cc", ".cpp", ".cxx"}
    )
    internal_names: set[str] = set()
    declaration = re.compile(
        r"^[ \t]*static\b[^\n;{}]*?\b([A-Za-z_]\w*)\s*(?=\(|\[|=|;)",
        re.MULTILINE,
    )
    root = source_root.resolve()
    for relative in source_files:
        candidate = Path(relative)
        path = candidate if candidate.is_absolute() else root / candidate
        try:
            path = path.resolve()
            path.relative_to(root)
        except (OSError, ValueError):
            continue
        if not path.is_file():
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        internal_names.update(declaration.findall(source))
    harness_local_names = set(declaration.findall(code))
    return sorted(
        name
        for name in internal_names - harness_local_names
        if re.search(rf"\b{re.escape(name)}\b", code)
    )


def _function_or_source_alias_invoked(
    semantic_code: str,
    original_code: str,
    function_name: str,
    extra_aliases: tuple[str, ...] = (),
) -> bool:
    """Recognize a real source-included anchor renamed for libFuzzer linkage.

    C/C++ harnesses commonly include a utility source with ``#define main
    project_main`` so libFuzzer can provide the process main.  Calling that
    alias still calls the real application body; treating it as absent caused
    a false HC08 failure.
    """

    if _function_invoked(semantic_code, function_name):
        return True
    aliases = unique_strings([
        *extra_aliases,
        *(
            match.group(1)
            for match in re.finditer(
                rf"^[ \t]*#\s*define\s+{re.escape(function_name)}\s+([A-Za-z_]\w*)\b",
                original_code,
                re.MULTILINE,
            )
        ),
    ])
    return any(_function_invoked(semantic_code, alias) for alias in aliases)


def _invoked_application_entrances_to(
    semantic_code: str,
    original_code: str,
    graph: GraphStore,
    target_function_id: str,
    invocation_aliases: dict[str, tuple[str, ...]] | None = None,
) -> list[str]:
    """Return real project calls in the harness that can reach ``target``.

    Internal/static anchors are not valid link boundaries.  A normal harness
    may call a public caller and reach the anchor through the unchanged
    application graph.  We accept only functions actually invoked in the
    generated source; mere reverse reachability in the project graph is not
    enough.  Runtime qualification still has to hit the anchor under GDB.
    """

    aliases = invocation_aliases or {}
    entrances: list[str] = []
    for function in graph.bundle.functions.values():
        invoked = _function_or_source_alias_invoked(
            semantic_code, original_code, function.name,
            aliases.get(function.name, ()),
        )
        if not invoked:
            continue
        if function.function_id == target_function_id or graph.shortest_path(
            function.function_id, target_function_id, max_depth=16
        ):
            entrances.append(function.qualified_name or function.name)
    return unique_strings(entrances)


def _invoked_application_entrances_through(
    semantic_code: str,
    original_code: str,
    graph: GraphStore,
    target_function_id: str,
    required_path_function_ids: list[str],
    invocation_aliases: dict[str, tuple[str, ...]] | None = None,
) -> list[str]:
    """Return invoked project functions whose path crosses a required Entry.

    Reaching a handler is insufficient for a scenario harness: calling that
    handler directly can bypass the acquisition, parser, and dispatcher that
    the original runtime witness exercised.  This helper accepts an invoked
    application entrance only when one static path to the target contains at
    least one witnessed Entry function.  Runtime reachability remains the
    final proof for possible indirect edges.
    """

    required = {
        function_id for function_id in required_path_function_ids
        if function_id in graph.bundle.functions
    }
    if not required:
        return []
    aliases = invocation_aliases or {}
    entrances: list[str] = []
    for function in graph.bundle.functions.values():
        if not _function_or_source_alias_invoked(
            semantic_code, original_code, function.name,
            aliases.get(function.name, ()),
        ):
            continue
        path = (
            [function.function_id]
            if function.function_id == target_function_id
            else graph.shortest_path(
                function.function_id, target_function_id, max_depth=64
            )
        )
        if path and required.intersection(path):
            entrances.append(function.qualified_name or function.name)
    return unique_strings(entrances)


def _source_candidate_return_to_table_routes(
    semantic_code: str,
    original_code: str,
    graph: GraphStore,
    target_function_id: str,
    required_entry_ids: list[str],
) -> list[str]:
    """Report possible Entry-return-table routes without approving HC08.

    The compiler can locate a call to an Entry before a call through a global
    function-pointer array in the same function. Its initializer is only a
    set of possible handlers. Neither the table contents nor source order
    proves which request reached which handler at runtime.
    """

    required = set(required_entry_ids)
    routes: list[str] = []
    for caller in graph.bundle.functions.values():
        if not _function_or_source_alias_invoked(
            semantic_code, original_code, caller.name
        ):
            continue
        for direct in caller.direct_call_sites:
            if direct.get('callee_function_id') not in required:
                continue
            entry_line = direct.get('line')
            if not isinstance(entry_line, int):
                continue
            for indirect in caller.indirect_table_call_sites:
                call_line = indirect.get('call_line')
                if (
                    isinstance(call_line, int)
                    and entry_line < call_line
                    and target_function_id in indirect.get('candidate_function_ids', ())
                ):
                    routes.append(
                        f"{caller.qualified_name or caller.name}: Entry call at "
                        f"{caller.file}:{entry_line}, possible table call "
                        f"{indirect.get('table_name')} at {caller.file}:{call_line}"
                    )
    return unique_strings(routes)


def _code_only(code: str) -> str:
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)
    return pattern.sub(lambda match: "".join("\n" if char == "\n" else " " for char in match.group(0)), code)
