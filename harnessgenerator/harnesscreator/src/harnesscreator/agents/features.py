from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import replace
from typing import Any

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    AttackAccess,
    AttackerFeasibility,
    HarnessDisposition,
    ImpactScope,
    LargeFeaturePriority,
    LargeFeatureSpec,
    SmallFeatureSpec,
    as_json,
    large_feature_schedule_key,
    stable_id,
    unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from .common import object_list, string_list


EVIDENCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "function_id", "file", "line", "detail"],
    "properties": {
        "kind": {"type": "string"},
        "function_id": {"type": "string"},
        "file": {"type": "string"},
        "line": {"type": ["integer", "null"]},
        "detail": {"type": "string"},
    },
}

ENTRY_RESOLUTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "entry_id", "status", "channel_kind", "attacker_control",
        "first_acquisition_confirmed", "provenance_path", "consumer_hints",
        "evidence", "unknowns", "confidence", "rationale",
    ],
    "properties": {
        "entry_id": {"type": "string"},
        "status": {
            "type": "string",
            "enum": ["VERIFIED", "REJECTED", "UNRESOLVED"],
        },
        "channel_kind": {"type": "string"},
        "attacker_control": {"type": "string"},
        "first_acquisition_confirmed": {"type": "boolean"},
        "provenance_path": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_id", "relation"],
                "properties": {
                    "function_id": {"type": "string"},
                    "relation": {"type": "string"},
                },
            },
        },
        "consumer_hints": {"type": "array", "items": {"type": "string"}},
        "evidence": {"type": "array", "items": EVIDENCE_SCHEMA},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
    },
}

SMALL_FEATURE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "name", "description", "root_entries", "supporting_entries", "entry_call_order", "harness_anchor",
        "anchor_rationale", "boundary_preserved", "preconditions", "initialization",
        "required_functions", "actions", "input_bindings", "cleanup_success", "cleanup_failure",
        "stable_post_state", "completion_oracle", "evidence", "unknowns", "confidence",
        "build_target", "isolation_mode",
    ],
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "root_entries": {"type": "array", "items": {"type": "string"}},
        "supporting_entries": {"type": "array", "items": {"type": "string"}},
        "entry_call_order": {"type": "array", "items": {"type": "string"}},
        "harness_anchor": {"type": "string"},
        "anchor_rationale": {"type": "string"},
        "boundary_preserved": {"type": "boolean"},
        "preconditions": {"type": "array", "items": {"type": "string"}},
        "initialization": {"type": "array", "items": {"type": "string"}},
        "required_functions": {"type": "array", "items": {"type": "string"}},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["action_id", "function_id", "consumes", "produces", "allowed_after", "success_condition"],
                "properties": {
                    "action_id": {"type": "string"}, "function_id": {"type": "string"},
                    "consumes": {"type": "array", "items": {"type": "string"}},
                    "produces": {"type": "array", "items": {"type": "string"}},
                    "allowed_after": {"type": "array", "items": {"type": "string"}},
                    "success_condition": {"type": "string"},
                },
            },
        },
        "input_bindings": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["source", "destination", "transform"],
                "properties": {
                    "source": {"type": "string"}, "destination": {"type": "string"},
                    "transform": {"type": "string"},
                },
            },
        },
        "cleanup_success": {"type": "array", "items": {"type": "string"}},
        "cleanup_failure": {"type": "array", "items": {"type": "string"}},
        "stable_post_state": {"type": "string"},
        "completion_oracle": {"type": "string"},
        "evidence": {"type": "array", "items": EVIDENCE_SCHEMA},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "build_target": {"type": "string"},
        "isolation_mode": {
            "type": "string",
            "enum": ["in_process_reset", "fork_per_input", "subprocess", "loopback_network"],
        },
    },
}

SMALL_FEATURE_DISCOVERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "small_features", "unrelated_entries", "context_complete",
        "requested_function_ids", "entry_resolutions",
    ],
    "properties": {
        "small_features": {
            "type": "array",
            "items": SMALL_FEATURE_SCHEMA,
        },
        "unrelated_entries": {"type": "array", "items": {"type": "string"}},
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {"type": "array", "items": {"type": "string"}},
        "entry_resolutions": {
            "type": "array",
            "items": ENTRY_RESOLUTION_SCHEMA,
        },
    },
}

SMALL_FEATURE_RECONCILIATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["operation_groups"],
    "properties": {
        "operation_groups": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["canonical_proposal_id", "proposal_ids", "reason"],
                "properties": {
                    "canonical_proposal_id": {"type": "string"},
                    "proposal_ids": {"type": "array", "items": {"type": "string"}},
                    "reason": {"type": "string"},
                },
            },
        }
    },
}

LARGE_FEATURE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["large_features"],
    "properties": {
        "large_features": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "name", "description", "small_feature_ids", "common_anchor",
                    "common_initialization", "common_cleanup", "prerequisite_state",
                    "isolation_mode", "isolation_rationale", "dispatch_strategy",
                    "variants", "required_functions",
                ],
                "properties": {
                    "name": {"type": "string"}, "description": {"type": "string"},
                    "small_feature_ids": {"type": "array", "items": {"type": "string"}},
                    "common_anchor": {"type": "string"},
                    "common_initialization": {"type": "array", "items": {"type": "string"}},
                    "common_cleanup": {"type": "array", "items": {"type": "string"}},
                    "prerequisite_state": {"type": "array", "items": {"type": "string"}},
                    "isolation_mode": {
                        "type": "string",
                        "enum": ["in_process_reset", "fork_per_input", "subprocess", "loopback_network"],
                    },
                    "isolation_rationale": {"type": "string"},
                    "dispatch_strategy": {
                        "type": "string", "enum": ["selector_byte", "shared_selector_byte", "one_job_per_feature"]
                    },
                    "variants": {
                        "type": "array",
                        "items": {
                            "type": "object", "additionalProperties": False,
                            "required": ["selector", "small_feature_id"],
                            "properties": {"selector": {"type": "string"}, "small_feature_id": {"type": "string"}},
                        },
                    },
                    "required_functions": {"type": "array", "items": {"type": "string"}},
                },
            },
        }
    },
}


LARGE_FEATURE_PRIORITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["subjects", "feature_subjects"],
    "properties": {
        "subjects": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "subject_id", "name", "capabilities", "attack_access",
                    "rationale", "confidence",
                ],
                "properties": {
                    "subject_id": {"type": "string"},
                    "name": {"type": "string"},
                    "capabilities": {
                        "type": "array", "items": {"type": "string"},
                    },
                    "attack_access": {
                        "type": "string",
                        "enum": [
                            "UNAUTHENTICATED_REMOTE", "AUTHENTICATED_ORDINARY_USER",
                            "LOCAL_ORDINARY_USER", "PRIVILEGED_USER",
                            "TRUSTED_COMPONENT_CONTROL", "IMPLAUSIBLE", "UNKNOWN",
                        ],
                    },
                    "rationale": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        },
        "feature_subjects": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "large_feature_id", "subject_id", "impact_scope",
                    "rationale", "impact_rationale", "confidence",
                ],
                "properties": {
                    "large_feature_id": {"type": "string"},
                    "subject_id": {"type": "string"},
                    "impact_scope": {
                        "type": "string",
                        "enum": [
                            "ORDINARY_USER_PROCESS", "SENSITIVE_DATA",
                            "PRIVILEGED_PROCESS", "SYSTEM_WIDE", "UNKNOWN",
                        ],
                    },
                    "rationale": {"type": "string"},
                    "impact_rationale": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        },
    },
}


class LargeFeatureAgent:
    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore | None = None,
        *,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.trace = trace

    async def run(
        self,
        small_features: list[SmallFeatureSpec],
        *,
        priority_context: list[LargeFeatureSpec] | None = None,
    ) -> list[LargeFeatureSpec]:
        if not small_features:
            return []
        session_key = "large_feature:" + stable_id(
            "grouping-session",
            sorted(item.small_feature_id for item in small_features),
        )
        groups: dict[str, list[SmallFeatureSpec]] = defaultdict(list)
        compatibility_by_feature: dict[str, dict[str, Any]] = {}
        for feature in small_features:
            first_entry = (
                feature.entry_call_order[0]
                if feature.entry_call_order
                else feature.root_entries[0] if feature.root_entries else ""
            )
            compatibility = {
                # This is the Large Feature definition: the first Entry and
                # prerequisite state identify the family.  Prerequisite text is
                # semantically partitioned by the strong model below; hashing
                # raw prose here made equivalent states form one-feature groups.
                "first_entry": first_entry,
                "prerequisites": _normalized_state(
                    _large_feature_prerequisite_state(feature)
                ),
            }
            key = hashlib.sha256(first_entry.encode()).hexdigest()[:20]
            groups[key].append(feature)
            compatibility_by_feature[feature.small_feature_id] = {
                "fingerprint": key,
                "compatibility": compatibility,
            }

        emit_trace(
            self.trace,
            "large_feature",
            "compatibility_partitioned",
            f"partitioned {len(small_features)} small features into {len(groups)} deterministic groups",
            assignments=compatibility_by_feature,
            groups={key: [item.small_feature_id for item in value] for key, value in groups.items()},
        )

        result: list[LargeFeatureSpec] = []
        for fingerprint, group in groups.items():
            emit_trace(
                self.trace,
                "large_feature",
                "group_started",
                f"validate compatibility group {fingerprint} with {len(group)} small features",
                fingerprint=fingerprint,
                small_features=[as_json(item) for item in group],
            )
            response = await self.llm.complete_json(
                role="large_feature",
                instructions=(
                    "All supplied features have the same first Entry. Partition them so each output group has the same "
                    "program state that must exist before the first Entry, by meaning, even when equivalent state is "
                    "worded differently. This is the Large Feature definition. Request bytes, command/opcode, framing, "
                    "length constraints, expected result, and per-operation cleanup are not prerequisite state and must "
                    "not split otherwise compatible operations. Never group features whose actual required session, "
                    "authentication, configuration, connection, object, or mode state differs. Hard execution "
                    "incompatibilities (anchor, build target, isolation backend, and input channel) are enforced by code "
                    "after this semantic partition. Multiple features in one group use explicit selector dispatch and "
                    "each must retain a reachable seed. Use every supplied ID exactly once and use only supplied IDs."
                ),
                payload={"compatibility_fingerprint": fingerprint, "small_features": [_small_payload(x) for x in group]},
                output_schema=LARGE_FEATURE_SCHEMA,
                session_key=session_key,
            )
            emit_trace(
                self.trace,
                "large_feature",
                "model_proposal",
                f"group {fingerprint}: model proposed {len(object_list(response.get('large_features')))} large groups",
                fingerprint=fingerprint,
                response=response,
            )
            by_id = {feature.small_feature_id: feature for feature in group}
            assigned: set[str] = set()
            for raw in object_list(response.get("large_features")):
                members = unique_strings(
                    item for item in string_list(raw.get("small_feature_ids"))
                    if item in by_id and item not in assigned
                )
                if not members:
                    emit_trace(
                        self.trace,
                        "large_feature",
                        "proposal_rejected",
                        f"group {fingerprint}: rejected proposal with no valid member IDs",
                        fingerprint=fingerprint,
                        proposal=raw,
                    )
                    continue
                assigned.update(members)
                selected = [by_id[item] for item in members]
                for hard_key, partition in _hard_large_partitions(selected).items():
                    # A selector byte can encode at most 256 deterministic
                    # variants. Larger semantic groups become multiple harness
                    # execution groups instead of wrapping selector values.
                    for offset in range(0, len(partition), 256):
                        execution_partition = partition[offset:offset + 256]
                        large_feature = self._make_large(raw, execution_partition, fingerprint)
                        result.append(large_feature)
                        emit_trace(
                            self.trace,
                            "large_feature",
                            "feature_created",
                            f"created {large_feature.large_feature_id} '{large_feature.name}' from {len(execution_partition)} small features",
                            fingerprint=fingerprint,
                            hard_compatibility={
                                "anchor": hard_key[0],
                                "build_target": hard_key[1],
                                "isolation_mode": hard_key[2],
                                "channel": hard_key[3],
                            },
                            selector_partition_offset=offset,
                            fallback=False,
                            feature=as_json(large_feature),
                            proposal=raw,
                        )
            for feature in group:
                if feature.small_feature_id not in assigned:
                    fallback = self._make_large({}, [feature], fingerprint)
                    result.append(fallback)
                    emit_trace(
                        self.trace,
                        "large_feature",
                        "feature_created",
                        f"created fallback {fallback.large_feature_id} for unassigned {feature.small_feature_id}",
                        fingerprint=fingerprint,
                        fallback=True,
                        fallback_reason="model did not assign this small feature to a valid group",
                        feature=as_json(fallback),
                    )
        result = await self._assign_security_priorities(
            result,
            small_features,
            priority_context or [],
            session_key=session_key,
        )
        # Harness generation consumes this order.  Attacker accessibility is
        # the primary scheduling tier, so an unauthenticated remote surface is
        # never delayed behind a local-only surface just because the latter has
        # a larger impact label.  The access/impact score orders candidates
        # within the same access tier. Discarded subjects remain in the
        # artifact set for auditability but sort after every retained feature.
        result.sort(key=large_feature_schedule_key)
        emit_trace(
            self.trace,
            "large_feature",
            "completed",
            (
                f"created {len(result)} large features; "
                f"discarded={sum(item.security_priority.disposition is HarnessDisposition.DISCARD for item in result)}"
            ),
            feature_ids=[item.large_feature_id for item in result],
            priorities={
                item.large_feature_id: as_json(item.security_priority)
                for item in result
            },
        )
        await close_llm_session(self.llm, session_key)
        return result

    async def _assign_security_priorities(
        self,
        features: list[LargeFeatureSpec],
        small_features: list[SmallFeatureSpec],
        priority_context: list[LargeFeatureSpec],
        *,
        session_key: str,
    ) -> list[LargeFeatureSpec]:
        if not features:
            return []
        by_small_id = {item.small_feature_id: item for item in small_features}
        response = await self.llm.complete_json(
            role="large_feature",
            instructions=(
                "Assess the security priority of every candidate Large Feature by the real deployment subject that "
                "controls its fuzzed input. A subject is the external actor or peer supplying the input, not the "
                "harness process or application component merely receiving it. List only intended application "
                "capabilities: do not count vulnerabilities, crashes, helper functions, allocations, parser stages, "
                "or implementation details as capabilities. Compare the subject with all other relevant input "
                "subjects visible in the supplied candidate and comparison features. Use exactly the same short "
                "capability label for semantically equivalent capabilities across subjects. attack_access classifies "
                "the minimum realistic access needed to occupy or control the subject: unauthenticated remote, "
                "authenticated ordinary user, local ordinary user, privileged user, trusted component control, or "
                "structurally implausible. Use IMPLAUSIBLE only when the role is structurally very difficult to occupy "
                "(for example, requiring control of the trusted server in an ordinary client/server trust model), not "
                "merely because authentication or local access is required. For every Feature mapping, classify the "
                "maximum credible security impact if that Feature is compromised: ordinary user process, sensitive "
                "data, privileged process, or system-wide. Base impact on the Feature's reachable authority and assets, "
                "not on hypothetical privileges absent from the supplied evidence. Do not output a priority "
                "number or discard decision; deterministic code calculates both. Return a non-duplicated subject "
                "inventory plus exactly one feature-to-subject mapping for every candidate large_feature_id. Reuse "
                "one subject_id when multiple features receive input from the same deployment actor, and never invent "
                "large_feature_ids."
            ),
            payload={
                "candidate_large_features": [
                    _priority_payload(item, by_small_id) for item in features
                ],
                "comparison_large_features": [
                    _priority_context_payload(item) for item in priority_context
                ],
                "priority_definition": {
                    "higher_priority": (
                        "the attacker can control the input subject more easily and successful exploitation has a "
                        "larger credible impact; intended capability count does not change the priority score"
                    ),
                    "discard": (
                        "the subject can perform every capability of every other subject and is IMPLAUSIBLE for an "
                        "attacker to occupy"
                    ),
                },
            },
            output_schema=LARGE_FEATURE_PRIORITY_SCHEMA,
            session_key=session_key,
        )
        subjects = {
            str(raw.get("subject_id", "")): raw
            for raw in object_list(response.get("subjects"))
            if str(raw.get("subject_id", ""))
        }
        feature_subjects = {
            str(raw.get("large_feature_id", "")): raw
            for raw in object_list(response.get("feature_subjects"))
            if str(raw.get("large_feature_id", ""))
        }
        prioritized: list[LargeFeatureSpec] = []
        for feature in features:
            mapping = feature_subjects.get(feature.large_feature_id)
            profile = (
                subjects.get(str(mapping.get("subject_id", "")))
                if mapping is not None else None
            )
            raw = _inline_priority_assessment(profile, mapping, subjects)
            priority = _security_priority_from_assessment(
                raw,
                fallback_capabilities=feature.small_feature_names,
            )
            prioritized_feature = replace(feature, security_priority=priority)
            prioritized.append(prioritized_feature)
            emit_trace(
                self.trace,
                "large_feature",
                "priority_assessed",
                (
                    f"{feature.large_feature_id}: score={priority.priority_score}, "
                    f"subject={priority.input_subject}, disposition={priority.disposition}"
                ),
                large_feature_id=feature.large_feature_id,
                priority=as_json(priority),
                raw_subject_profile=profile,
                raw_feature_mapping=mapping,
            )
            if priority.disposition is HarnessDisposition.DISCARD:
                emit_trace(
                    self.trace,
                    "large_feature",
                    "feature_discarded",
                    f"{feature.large_feature_id}: {priority.discard_reason}",
                    large_feature_id=feature.large_feature_id,
                    priority=as_json(priority),
                )
        return prioritized

    def _make_large(
        self, raw: dict[str, Any], members: list[SmallFeatureSpec], fingerprint: str
    ) -> LargeFeatureSpec:
        ids = [member.small_feature_id for member in members]
        # The deterministic partition already proved these fields equal. The
        # model may split a partition, but it must not rewrite the proven
        # lifecycle or introduce new functions/state.
        anchor = members[0].harness_anchor
        variants = [
            {"selector": str(index), "small_feature_id": member.small_feature_id}
            for index, member in enumerate(members)
        ]
        evidence = [evidence for member in members for evidence in member.evidence]
        prerequisite_state = unique_strings(
            state
            for member in members
            for state in _large_feature_prerequisite_state(member)
        )
        fixture_fingerprint = hashlib.sha256(json.dumps({
            "first_entry": (
                members[0].entry_call_order[0]
                if members[0].entry_call_order
                else members[0].root_entries[0] if members[0].root_entries else ""
            ),
            "prerequisites": _normalized_state(prerequisite_state),
            "anchor": anchor,
            "build_target": members[0].build_target,
            "isolation_mode": members[0].isolation_mode,
            "channel": _channel_family(members[0].channel_kind),
        }, sort_keys=True).encode()).hexdigest()[:20]
        known_functions = unique_strings(
            function for member in members for function in member.required_functions
        )
        node_ids = unique_strings([anchor, *known_functions])
        function_nodes = []
        for function_id in node_ids:
            if self.graph is not None and function_id in self.graph.bundle.functions:
                function = self.graph.get(function_id)
                function_nodes.append({
                    "id": function_id,
                    "name": function.name,
                    "file": function.file,
                    "start_line": function.start_line,
                })
            else:
                function_nodes.append({"id": function_id})
        function_edges = self.graph.induced_edges(node_ids) if self.graph is not None else []
        entry_nodes: list[dict[str, Any]] = []
        entry_edges: list[dict[str, Any]] = []
        for member in members:
            order = member.entry_call_order or unique_strings([
                *member.root_entries, *member.supporting_entries
            ])
            invocation_ids: list[str] = []
            for position, entry_id in enumerate(order):
                invocation_id = stable_id(
                    "entry-invocation", member.small_feature_id, position, entry_id
                )
                invocation_ids.append(invocation_id)
                entry_nodes.append({
                    "id": invocation_id,
                    "entry_id": entry_id,
                    "small_feature_id": member.small_feature_id,
                    "position": position,
                    "role": (
                        "root" if entry_id in member.root_entries else "supporting"
                    ),
                })
            for position, (source_id, target_id) in enumerate(
                zip(invocation_ids, invocation_ids[1:])
            ):
                entry_edges.append({
                    "source_id": source_id,
                    "target_id": target_id,
                    "from_entry_id": order[position],
                    "to_entry_id": order[position + 1],
                    "small_feature_id": member.small_feature_id,
                    "kind": "runtime_order",
                })
        dispatch_strategy = str(raw.get("dispatch_strategy", "selector_byte"))
        if dispatch_strategy not in {
            "selector_byte", "shared_selector_byte", "one_job_per_feature"
        }:
            dispatch_strategy = "selector_byte" if len(members) > 1 else "one_job_per_feature"
        if len(members) > 1 and dispatch_strategy == "one_job_per_feature":
            dispatch_strategy = "selector_byte"
        return LargeFeatureSpec(
            large_feature_id=stable_id("lf", *sorted(ids), fixture_fingerprint),
            name=str(raw.get("name", members[0].name)),
            description=str(raw.get("description", "; ".join(member.description for member in members))),
            small_feature_ids=ids,
            small_feature_names=[member.name for member in members],
            common_anchor=anchor,
            common_initialization=_ordered_intersection(
                [member.initialization for member in members]
            ),
            common_cleanup=_ordered_intersection(
                [member.cleanup_success for member in members]
            ),
            common_cleanup_failure=_ordered_intersection(
                [member.cleanup_failure for member in members]
            ),
            prerequisite_state=prerequisite_state,
            fixture_fingerprint=fixture_fingerprint,
            isolation_mode=members[0].isolation_mode,
            isolation_rationale=str(raw.get("isolation_rationale", "derived from small-feature lifecycle")),
            dispatch_strategy=dispatch_strategy,
            variants=variants,
            entry_call_graph={
                "nodes": entry_nodes,
                "edges": entry_edges,
                "function_nodes": function_nodes,
                "function_edges": function_edges,
            },
            required_functions=known_functions,
            evidence=evidence,
        )


def _small_payload(feature: SmallFeatureSpec) -> dict[str, Any]:
    prerequisite_state = _large_feature_prerequisite_state(feature)
    prerequisite_keys = {
        " ".join(value.casefold().split()) for value in prerequisite_state
    }
    return {
        "small_feature_id": feature.small_feature_id,
        "name": feature.name,
        "description": feature.description,
        "root_entries": feature.root_entries,
        "supporting_entries": feature.supporting_entries,
        "entry_call_order": feature.entry_call_order,
        "harness_anchor": feature.harness_anchor,
        "prerequisite_state": prerequisite_state,
        "request_constraints": [
            value for value in feature.preconditions
            if " ".join(value.casefold().split()) not in prerequisite_keys
        ],
        "initialization": feature.initialization,
        "cleanup_success": feature.cleanup_success,
        "cleanup_failure": feature.cleanup_failure,
        "required_functions": feature.required_functions,
        "channel_kind": feature.channel_kind,
        "build_target": feature.build_target,
        "isolation_mode": feature.isolation_mode,
        "planning_complete": feature.planning_complete,
        "function_references_complete": feature.function_references_complete,
        "planning_blockers": feature.planning_blockers,
    }


def _priority_payload(
    feature: LargeFeatureSpec,
    small_features: dict[str, SmallFeatureSpec],
) -> dict[str, Any]:
    members = [
        small_features[identifier]
        for identifier in feature.small_feature_ids
        if identifier in small_features
    ]
    return {
        "large_feature_id": feature.large_feature_id,
        "name": feature.name,
        "description": feature.description,
        "common_anchor": feature.common_anchor,
        "prerequisite_state": feature.prerequisite_state,
        "isolation_mode": feature.isolation_mode,
        "member_features": [
            {
                "small_feature_id": member.small_feature_id,
                "name": member.name,
                "description": member.description,
                "channel_kind": member.channel_kind,
                "root_entries": member.root_entries,
                "supporting_entries": member.supporting_entries,
                "preconditions": member.preconditions,
                "actions": member.actions,
                "completion_oracle": member.completion_oracle,
                "evidence": [as_json(item) for item in member.evidence],
            }
            for member in members
        ],
    }


def _priority_context_payload(feature: LargeFeatureSpec) -> dict[str, Any]:
    return {
        "large_feature_id": feature.large_feature_id,
        "name": feature.name,
        "description": feature.description,
        "small_feature_names": feature.small_feature_names,
        "prerequisite_state": feature.prerequisite_state,
        "security_priority": as_json(feature.security_priority),
    }


def _inline_priority_assessment(
    profile: dict[str, Any] | None,
    mapping: dict[str, Any] | None,
    all_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if profile is None or mapping is None:
        return None
    subject_id = str(profile.get("subject_id", ""))
    profile_rationale = str(profile.get("rationale", "")).strip()
    mapping_rationale = str(mapping.get("rationale", "")).strip()
    impact_rationale = str(mapping.get("impact_rationale", "")).strip()
    try:
        profile_confidence = float(profile.get("confidence", 0.0))
    except (TypeError, ValueError):
        profile_confidence = 0.0
    try:
        mapping_confidence = float(mapping.get("confidence", 0.0))
    except (TypeError, ValueError):
        mapping_confidence = 0.0
    return {
        "input_subject": profile.get("name", "unknown"),
        "subject_capabilities": profile.get("capabilities", []),
        "other_subjects": [
            {
                "subject": other.get("name", other_id),
                "capabilities": other.get("capabilities", []),
            }
            for other_id, other in all_profiles.items()
            if other_id != subject_id
        ],
        "attack_access": profile.get("attack_access", "UNKNOWN"),
        "impact_scope": mapping.get("impact_scope", "UNKNOWN"),
        "rationale": "; ".join(
            item for item in (
                mapping_rationale, profile_rationale, impact_rationale,
            ) if item
        ),
        "confidence": min(profile_confidence, mapping_confidence),
    }


def _security_priority_from_assessment(
    raw: dict[str, Any] | None,
    *,
    fallback_capabilities: list[str],
) -> LargeFeaturePriority:
    """Normalize a model comparison and derive score/disposition in code.

    The model identifies semantic subjects and capabilities.  It never controls
    the numeric score or the hard discard decision.
    """

    if not isinstance(raw, dict):
        return LargeFeaturePriority(
            subject_capabilities=_canonical_capabilities(fallback_capabilities),
        )

    subject = " ".join(str(raw.get("input_subject", "unknown")).split()) or "unknown"
    subject_capabilities = _canonical_capabilities(
        string_list(raw.get("subject_capabilities"))
    )
    if not subject_capabilities:
        subject_capabilities = _canonical_capabilities(fallback_capabilities)

    comparison_subjects: list[dict[str, Any]] = []
    for comparison in object_list(raw.get("other_subjects")):
        comparison_name = " ".join(str(comparison.get("subject", "")).split())
        capabilities = _canonical_capabilities(
            string_list(comparison.get("capabilities"))
        )
        # An empty capability list cannot support a relative privilege claim.
        if not comparison_name or not capabilities:
            continue
        comparison_subjects.append({
            "subject": comparison_name,
            "capabilities": capabilities,
        })

    try:
        attack_access = AttackAccess(
            str(raw.get("attack_access", "UNKNOWN")).upper()
        )
    except ValueError:
        attack_access = AttackAccess.UNKNOWN
    try:
        impact_scope = ImpactScope(
            str(raw.get("impact_scope", "UNKNOWN")).upper()
        )
    except ValueError:
        impact_scope = ImpactScope.UNKNOWN
    access_score = _attack_access_score(attack_access)
    impact_score = _impact_scope_score(impact_scope)
    attacker_feasibility = _attacker_feasibility(attack_access)
    try:
        confidence = min(1.0, max(0.0, float(raw.get("confidence", 0.0))))
    except (TypeError, ValueError):
        confidence = 0.0

    subject_keys = {_capability_key(item) for item in subject_capabilities}
    other_key_sets = [
        {_capability_key(item) for item in item["capabilities"]}
        for item in comparison_subjects
    ]
    capability_ratio: float | None = None
    capability_scarcity_score = 50
    capability_superset = False
    if subject_keys and other_key_sets:
        capability_universe = set(subject_keys)
        for other_capabilities in other_key_sets:
            capability_universe.update(other_capabilities)
        capability_ratio = round(len(subject_keys) / len(capability_universe), 4)
        capability_scarcity_score = round(100 * (1.0 - capability_ratio))
        capability_superset = all(
            other_capabilities.issubset(subject_keys)
            for other_capabilities in other_key_sets
        )

    base_risk_score = (
        round(100 * (access_score / 5.0) * (impact_score / 4.0))
        if access_score is not None and impact_score is not None
        else 50
    )
    # Priority is defined only by attacker accessibility and credible impact.
    # Capability comparison remains diagnostic and supports the explicit
    # all-capability/implausible-subject discard rule, but does not change rank.
    priority_score = base_risk_score

    discard = (
        capability_superset
        and attack_access is AttackAccess.IMPLAUSIBLE
        and confidence >= 0.8
    )
    discard_reason = ""
    if discard:
        discard_reason = (
            "the input subject contains every compared subject capability and is "
            "not a realistic attacker-controlled role"
        )
    rationale = str(raw.get("rationale", "")).strip()
    if not comparison_subjects:
        rationale = (
            f"{rationale}; " if rationale else ""
        ) + "no evidenced comparison subject was available; retained with neutral priority"

    return LargeFeaturePriority(
        input_subject=subject,
        subject_capabilities=subject_capabilities,
        comparison_subjects=comparison_subjects,
        capability_ratio=capability_ratio,
        capability_scarcity_score=capability_scarcity_score,
        attack_access=attack_access,
        access_score=access_score,
        impact_scope=impact_scope,
        impact_score=impact_score,
        base_risk_score=base_risk_score,
        priority_score=priority_score,
        attacker_feasibility=attacker_feasibility,
        capability_superset_of_all_others=capability_superset,
        disposition=(HarnessDisposition.DISCARD if discard else HarnessDisposition.KEEP),
        rationale=rationale,
        discard_reason=discard_reason,
        confidence=confidence,
    )


def _canonical_capabilities(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = " ".join(value.split())
        key = _capability_key(normalized)
        if not normalized or key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


def _capability_key(value: str) -> str:
    return " ".join(value.casefold().split())


def _attack_access_score(value: AttackAccess) -> int | None:
    return {
        AttackAccess.UNAUTHENTICATED_REMOTE: 5,
        AttackAccess.AUTHENTICATED_ORDINARY_USER: 4,
        AttackAccess.LOCAL_ORDINARY_USER: 3,
        AttackAccess.PRIVILEGED_USER: 2,
        AttackAccess.TRUSTED_COMPONENT_CONTROL: 1,
        AttackAccess.IMPLAUSIBLE: 0,
        AttackAccess.UNKNOWN: None,
    }[value]


def _impact_scope_score(value: ImpactScope) -> int | None:
    return {
        ImpactScope.ORDINARY_USER_PROCESS: 1,
        ImpactScope.SENSITIVE_DATA: 2,
        ImpactScope.PRIVILEGED_PROCESS: 3,
        ImpactScope.SYSTEM_WIDE: 4,
        ImpactScope.UNKNOWN: None,
    }[value]


def _attacker_feasibility(value: AttackAccess) -> AttackerFeasibility:
    return {
        AttackAccess.UNAUTHENTICATED_REMOTE: AttackerFeasibility.HIGH,
        AttackAccess.AUTHENTICATED_ORDINARY_USER: AttackerFeasibility.HIGH,
        AttackAccess.LOCAL_ORDINARY_USER: AttackerFeasibility.MEDIUM,
        AttackAccess.PRIVILEGED_USER: AttackerFeasibility.LOW,
        AttackAccess.TRUSTED_COMPONENT_CONTROL: AttackerFeasibility.LOW,
        AttackAccess.IMPLAUSIBLE: AttackerFeasibility.IMPLAUSIBLE,
        AttackAccess.UNKNOWN: AttackerFeasibility.UNKNOWN,
    }[value]


def _hard_large_partitions(
    features: list[SmallFeatureSpec],
) -> dict[tuple[str, str, str, str], list[SmallFeatureSpec]]:
    partitions: dict[tuple[str, str, str, str], list[SmallFeatureSpec]] = {}
    for feature in features:
        key = (
            feature.harness_anchor,
            feature.build_target,
            feature.isolation_mode,
            _channel_family(feature.channel_kind),
        )
        partitions.setdefault(key, []).append(feature)
    return partitions


def _ordered_intersection(groups: list[list[str]]) -> list[str]:
    if not groups:
        return []
    common = {
        " ".join(item.casefold().split())
        for item in groups[0]
        if item.strip()
    }
    for group in groups[1:]:
        common &= {
            " ".join(item.casefold().split())
            for item in group
            if item.strip()
        }
    return [
        item for item in groups[0]
        if " ".join(item.casefold().split()) in common
    ]


def _channel_family(channel: str) -> str:
    """Normalize free-form verifier labels only for feature compatibility.

    Entry evidence retains the detailed label.  Feature grouping needs a stable
    transport family so wording such as "backend network socket" and "network"
    does not create different deterministic partitions.
    """

    value = channel.casefold().replace("-", "_")
    if any(token in value for token in ("tls", "network", "socket", "recv", "accept")):
        return "network"
    if any(token in value for token in ("file", "filesystem", "path", "directory")):
        return "file"
    if "stdin" in value or "terminal" in value:
        return "stdin"
    if "argv" in value or "command_line" in value:
        return "argv"
    if "environment" in value or "getenv" in value:
        return "environment"
    if any(token in value for token in ("ipc", "rpc", "message_queue", "pipe")):
        return "ipc"
    if any(token in value for token in ("device", "ioctl")):
        return "device"
    if "callback" in value:
        return "callback"
    return value or "unknown"


def _normalized_state(values: list[str]) -> list[str]:
    return sorted({" ".join(value.casefold().split()) for value in values if value.strip()})


def _large_feature_prerequisite_state(feature: SmallFeatureSpec) -> list[str]:
    """Keep pre-Entry program state separate from per-request input shape.

    Small Feature discovery records both kinds of facts in ``preconditions`` so
    that a harness can build a valid request.  Large Feature identity, however,
    is defined only by the first Entry and the state that exists before it.
    Treating an opcode or packet-length constraint as state makes every command
    a one-member Large Feature, which is the opposite of that definition.
    """

    return [
        value for value in feature.preconditions
        if not _is_request_constraint(value)
    ]


def _is_request_constraint(value: str) -> bool:
    text = " ".join(value.casefold().split())
    if not text:
        return False
    explicit_input_shape = re.search(
        r"\b(?:opcode|extlen|keylen|bodylen|magic|nkey|vlen|cas|"
        r"request bytes?|header bytes?|buf\s*\[|first byte|selector byte)\b",
        text,
    )
    input_object = re.search(
        r"\b(?:input|request|payload|packet|datagram|frame|message|command|"
        r"key|value|buffer)\b",
        text,
    )
    shape_constraint = re.search(
        r"\b(?:format|framing|encoded|contains?|begins?|starts?|complete|"
        r"single[- ]packet|non[- ]empty|length|size|bytes?|greater than|"
        r"less than|equal(?:s| to)?|valid shape)\b",
        text,
    )
    command_selection = re.search(
        r"\b(?:set|setq|add|addq|replace|replaceq|delete|deleteq|get|getq|"
        r"getk|getkq|gat|gatq|gatk|gatkq|touch|flush|flushq|version|noop|"
        r"quit|append|prepend|increment|decrement)\b",
        text,
    )
    return bool(
        explicit_input_shape
        or (input_object and shape_constraint)
        or (input_object and command_selection)
    )
