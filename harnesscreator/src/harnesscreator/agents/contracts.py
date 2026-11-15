from __future__ import annotations

import re
from dataclasses import replace
from typing import Iterable

from ..models import (
    Evidence,
    LargeFeatureDependency,
    ObligationOwner,
    ProofObligation,
    ProofStatus,
    SmallFeatureSpec,
    stable_id,
    unique_strings,
)


_SEMANTIC_BLOCKER_PATTERNS = (
    "concrete requested operation boundary is unresolved",
)


def assess_small_feature(feature: SmallFeatureSpec) -> SmallFeatureSpec:
    """Separate operation validity from executable-harness proof.

    Small Feature discovery is responsible for identifying a concrete
    application operation and its intra-operation ordering.  Transport setup,
    a build target, an exact completion citation, and other P2 facts are kept
    as proof obligations for later stages; they no longer erase a semantic
    operation before Large Feature composition can see it.
    """

    semantic_blockers: list[str] = []
    if not feature.root_entries:
        semantic_blockers.append("Small Feature has no VERIFIED root Entry")
    if not feature.actions:
        semantic_blockers.append("Small Feature has no concrete application action")
    action_ids: list[str] = []
    action_by_id: dict[str, dict[str, object]] = {}
    for index, action in enumerate(feature.actions):
        action_id = str(action.get("action_id", "")).strip()
        function_id = str(action.get("function_id", "")).strip()
        if not action_id:
            semantic_blockers.append(f"action {index} has no stable action_id")
            continue
        if action_id in action_by_id:
            semantic_blockers.append(f"duplicate action_id: {action_id}")
            continue
        if not function_id:
            semantic_blockers.append(f"action {action_id} has no application function")
        action_ids.append(action_id)
        action_by_id[action_id] = action

    action_id_set = set(action_ids)
    for action_id, action in action_by_id.items():
        for predecessor in _string_values(action.get("allowed_after")):
            if predecessor not in action_id_set:
                semantic_blockers.append(
                    f"action {action_id} references missing predecessor {predecessor}"
                )
    if _has_action_cycle(action_by_id):
        semantic_blockers.append("action ordering contains a dependency cycle")

    for dependency in feature.dependencies:
        if dependency.producer_action_id not in action_id_set:
            semantic_blockers.append(
                f"dependency {dependency.dependency_id} has missing producer action "
                f"{dependency.producer_action_id}"
            )
        if dependency.consumer_action_id not in action_id_set:
            semantic_blockers.append(
                f"dependency {dependency.dependency_id} has missing consumer action "
                f"{dependency.consumer_action_id}"
            )

    for blocker in feature.planning_blockers:
        lowered = blocker.casefold()
        if any(pattern in lowered for pattern in _SEMANTIC_BLOCKER_PATTERNS):
            semantic_blockers.append(blocker)

    semantic_blockers = unique_strings(semantic_blockers)
    obligations = obligations_from_small_feature(feature, semantic_blockers)
    return replace(
        feature,
        semantic_complete=not semantic_blockers,
        semantic_blockers=semantic_blockers,
        proof_obligations=obligations,
    )


def obligations_from_small_feature(
    feature: SmallFeatureSpec,
    semantic_blockers: Iterable[str] | None = None,
) -> list[ProofObligation]:
    semantic_keys = {
        _normalise_text(item) for item in (semantic_blockers or [])
    }
    obligations: list[ProofObligation] = []
    existing = {item.description: item for item in feature.proof_obligations}
    for blocker in unique_strings(feature.planning_blockers):
        if _normalise_text(blocker) in semantic_keys:
            owner = ObligationOwner.SMALL_FEATURE
            kind = "OPERATION_CONTRACT"
        else:
            owner, kind = _obligation_route(blocker)
        previous = existing.get(blocker)
        obligations.append(ProofObligation(
            obligation_id=(
                previous.obligation_id
                if previous is not None else
                stable_id("proof", feature.small_feature_id, owner, kind, blocker)
            ),
            owner=owner,
            kind=kind,
            description=blocker,
            required_for=(
                "semantic operation contract"
                if owner is ObligationOwner.SMALL_FEATURE else
                "Large Feature dependency plan"
                if owner is ObligationOwner.LARGE_FEATURE else
                "executable harness protocol"
                if owner is ObligationOwner.HARNESS_GENERATOR else
                "selected build backend"
                if owner is ObligationOwner.BUILD else
                "runtime reachability and completion"
            ),
            status=(
                previous.status
                if previous is not None else
                ProofStatus.POSSIBLE
                if "indirect" in blocker.casefold() or "callback" in blocker.casefold()
                else ProofStatus.OPEN
            ),
            source_feature_ids=[feature.small_feature_id],
            evidence=list(previous.evidence) if previous is not None else [],
            attempts=previous.attempts if previous is not None else 0,
        ))
    return obligations


def infer_large_feature_dependencies(
    members: list[SmallFeatureSpec],
) -> list[LargeFeatureDependency]:
    """Infer only explicit producer/consumer matches across operations.

    The relation is a planning hypothesis until source or runtime evidence is
    attached.  It is never promoted merely because two free-form descriptions
    sound related.
    """

    result: list[LargeFeatureDependency] = []
    seen: set[tuple[str, str, str]] = set()
    for producer in members:
        produced = _action_resources(producer.actions, "produces")
        if not produced:
            continue
        for consumer in members:
            if producer.small_feature_id == consumer.small_feature_id:
                continue
            consumed = _action_resources(consumer.actions, "consumes")
            shared = sorted(set(produced) & set(consumed))
            for resource in shared:
                key = (
                    producer.small_feature_id,
                    consumer.small_feature_id,
                    resource,
                )
                if key in seen:
                    continue
                seen.add(key)
                evidence = _resource_evidence(producer, consumer)
                result.append(LargeFeatureDependency(
                    dependency_id=stable_id("lfdep", *key),
                    producer_small_feature_id=producer.small_feature_id,
                    consumer_small_feature_id=consumer.small_feature_id,
                    relation="STATE",
                    condition=f"producer establishes '{resource}' before consumer",
                    status=(
                        ProofStatus.PROVEN_STATIC if evidence else ProofStatus.POSSIBLE
                    ),
                    evidence=evidence,
                ))
    return result


def unresolved_obligations(
    obligations: Iterable[ProofObligation],
) -> list[ProofObligation]:
    return [
        item for item in obligations
        if item.status not in {ProofStatus.PROVEN_STATIC, ProofStatus.PROVEN_RUNTIME}
    ]


def _obligation_route(blocker: str) -> tuple[ObligationOwner, str]:
    value = blocker.casefold()
    if blocker.startswith((
        "SOURCE_DEPENDENCY_", "UPSTREAM_DEPENDENCY_",
        "UPSTREAM_CONTEXT_", "UPSTREAM_SEQUENCE_",
    )) or any(token in value for token in (
        "producer action", "consumer action", "prerequisite state",
        "dependency endpoint", "operation sequence",
    )):
        return ObligationOwner.LARGE_FEATURE, "CROSS_OPERATION_DEPENDENCY"
    if any(token in value for token in (
        "build-target", "build target", "fork/subprocess", "engine_unsupported",
        "selected oss-fuzz", "backend",
    )):
        return ObligationOwner.BUILD, "BUILD_BACKEND"
    if any(token in value for token in (
        "runtime reach", "coverage", "breakpoint", "dynamic",
    )):
        return ObligationOwner.RUNTIME, "RUNTIME_PROOF"
    if "completion" in value:
        return ObligationOwner.HARNESS_GENERATOR, "COMPLETION_PROTOCOL"
    if "input" in value or "entry" in value:
        return ObligationOwner.HARNESS_GENERATOR, "INPUT_DELIVERY"
    if "function reference" in value:
        return ObligationOwner.HARNESS_GENERATOR, "FUNCTION_RESOLUTION"
    if "anchor" in value or "call path" in value:
        return ObligationOwner.HARNESS_GENERATOR, "CALL_PATH"
    return ObligationOwner.HARNESS_GENERATOR, "LIFECYCLE_PROTOCOL"


def _has_action_cycle(actions: dict[str, dict[str, object]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(action_id: str) -> bool:
        if action_id in visiting:
            return True
        if action_id in visited:
            return False
        visiting.add(action_id)
        for predecessor in _string_values(actions[action_id].get("allowed_after")):
            if predecessor in actions and visit(predecessor):
                return True
        visiting.remove(action_id)
        visited.add(action_id)
        return False

    return any(visit(action_id) for action_id in actions)


def _action_resources(actions: list[dict[str, object]], field: str) -> dict[str, str]:
    resources: dict[str, str] = {}
    for action in actions:
        for value in _string_values(action.get(field)):
            key = _resource_key(value)
            if key:
                resources.setdefault(key, value)
    return resources


def _resource_evidence(
    producer: SmallFeatureSpec,
    consumer: SmallFeatureSpec,
) -> list[Evidence]:
    producer_functions = {
        str(action.get("function_id", "")) for action in producer.actions
    }
    consumer_functions = {
        str(action.get("function_id", "")) for action in consumer.actions
    }
    producer_evidence = [
        item for item in producer.evidence
        if item.function_id in producer_functions and item.line is not None
    ]
    consumer_evidence = [
        item for item in consumer.evidence
        if item.function_id in consumer_functions and item.line is not None
    ]
    return [*producer_evidence[:1], *consumer_evidence[:1]]


def _resource_key(value: str) -> str:
    words = re.findall(r"[a-z0-9_]+", value.casefold())
    ignored = {
        "a", "an", "the", "one", "current", "request", "response",
        "result", "status", "bytes", "data", "input", "output",
    }
    return " ".join(word for word in words if word not in ignored)


def _normalise_text(value: str) -> str:
    return " ".join(value.casefold().split())


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
