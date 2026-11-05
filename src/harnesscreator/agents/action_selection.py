"""Source-backed Action selection before scenario planning and harness generation.

This stage makes an explicit usefulness decision immediately after Action
reconstruction. Uncertain Actions remain in the worklist; missing examples,
failed runtime trials, and low coverage are not evidence of uselessness.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..analysis.graph import GraphStore
from ..llm.base import (
    LLMProvider, close_llm_session, is_terminal_llm_infrastructure_error,
)
from ..models import (
    ActionStateContract, ExternalActionSchema, ProofStatus,
    ScenarioStatus, ScenarioWitness, StateDependencyGraph,
    as_json, stable_id,
)
from .common import concurrent_map, function_payload, resolve_source_linked_function
from .scenario import INPUT_ACTION_SCHEMA, _validated_evidence


ACTION_SELECTION_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["decision", "reason", "source_evidence"],
    "properties": {
        "decision": {"type": "string", "enum": ["KEEP", "DROP", "UNRESOLVED"]},
        "reason": {"type": "string"},
        "source_evidence": INPUT_ACTION_SCHEMA["properties"]["actions"]["items"]["properties"]["evidence"],
    },
}


ACTION_GROUP_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["relation", "decision", "reason", "source_evidence",
                 "individual_decisions", "requested_function_id"],
    "properties": {
        "relation": {"type": "string", "enum": [
            "SAME_SOURCE_EFFECT", "DIFFERENT", "UNRESOLVED",
        ]},
        "decision": {"type": "string", "enum": ["KEEP", "DROP", "UNRESOLVED"]},
        "reason": {"type": "string"},
        "source_evidence": INPUT_ACTION_SCHEMA["properties"]["actions"]["items"]["properties"]["evidence"],
        "requested_function_id": {"type": "string"},
        "individual_decisions": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["action_id", "decision", "reason", "source_evidence"],
                "properties": {
                    "action_id": {"type": "string"},
                    "decision": {"type": "string", "enum": ["KEEP", "DROP", "UNRESOLVED"]},
                    "reason": {"type": "string"},
                    "source_evidence": INPUT_ACTION_SCHEMA["properties"]["actions"]["items"]["properties"]["evidence"],
                },
            },
        },
    },
}


@dataclass(slots=True)
class ActionSelectionDecision:
    action_id: str
    disposition: str
    reason: str
    source_evidence: list[dict[str, Any]]


@dataclass(slots=True)
class ActionGroupDecision:
    group_id: str
    action_ids: list[str]
    relation: str
    disposition: str
    reason: str
    source_evidence: list[dict[str, Any]]


@dataclass(slots=True)
class ActionGroupValidation:
    group_id: str
    action_ids: list[str]
    status: str
    reason: str


@dataclass(slots=True)
class ActionEffectFamily:
    """One source-supported effect with independently executable input routes."""

    effect_id: str
    action_ids: list[str]
    route_ids: list[str]
    relation: str
    source_evidence: list[dict[str, Any]]


@dataclass(slots=True)
class ActionInputRoute:
    route_id: str
    effect_id: str
    action_id: str
    entry_id: str
    channel_kind: str
    source_api: str
    discriminator: str


def build_action_effect_families(
    groups: list[ActionGroupDecision],
    retained_actions: list[ExternalActionSchema],
) -> tuple[list[ActionEffectFamily], list[ActionInputRoute]]:
    """Merge only proven source effects; preserve every acquisition route.

    DIFFERENT and UNRESOLVED review groups become singleton effects.  This
    function deliberately makes no claim about runtime or fuzz equivalence.
    """
    by_id = {action.action_id: action for action in retained_actions}
    if len(by_id) != len(retained_actions):
        raise ValueError("duplicate Action ID in retained inventory")
    families: list[ActionEffectFamily] = []
    routes: list[ActionInputRoute] = []
    assigned: set[str] = set()
    for group in groups:
        retained_ids = [action_id for action_id in group.action_ids
                        if action_id in by_id]
        if not retained_ids:
            continue
        subsets = ([retained_ids] if group.relation == "SAME_SOURCE_EFFECT"
                   and len(retained_ids) > 1 else [[item] for item in retained_ids])
        for ids in subsets:
            if any(action_id in assigned for action_id in ids):
                raise ValueError("Action appears in more than one source group")
            assigned.update(ids)
            effect_id = stable_id("action-effect", *sorted(ids))
            route_ids: list[str] = []
            for action_id in ids:
                action = by_id[action_id]
                # The Action ID distinguishes even identical-looking route
                # candidates until original execution can validate them.
                route_id = stable_id("action-route", action_id)
                route_ids.append(route_id)
                routes.append(ActionInputRoute(
                    route_id, effect_id, action_id, action.entry_id,
                    action.channel_kind, action.source_api,
                    action.discriminator,
                ))
            families.append(ActionEffectFamily(
                effect_id, ids, route_ids,
                group.relation if len(ids) > 1 else "SINGLETON",
                group.source_evidence if len(ids) > 1 else [],
            ))
    if assigned != set(by_id):
        raise ValueError("source groups did not account for every retained Action")
    return families, routes


def _state_signature(contract: ActionStateContract) -> tuple[object, ...]:
    """Compare structured state facts, not model-written descriptions."""
    def requirements(values: list[Any]) -> tuple[tuple[object, ...], ...]:
        return tuple(sorted((
            item.resource, item.binding, item.predicate,
            item.binding_value_hex is not None,
            item.binding_value_hex or "", item.scope, item.owner_binding,
        ) for item in values))
    return (
        requirements(contract.consumes),
        requirements(contract.produces),
        requirements(contract.invalidates),
    )


def validate_action_groups(
    groups: list[ActionGroupDecision],
    retained_actions: list[ExternalActionSchema],
    dependencies: StateDependencyGraph,
    witnesses: list[ScenarioWitness],
) -> list[ActionGroupValidation]:
    """Audit shared source effects after state and original-runtime stages.

    This never deletes a route or treats one route's witness as proof of
    another. A source grouping alone is not a runtime equivalence proof.
    """
    retained = {action.action_id for action in retained_actions}
    contracts = {item.action_id: item for item in dependencies.contracts}
    proven = {item.target_action_id for item in witnesses
              if item.status is ScenarioStatus.PROVEN_RUNTIME}
    results: list[ActionGroupValidation] = []
    for group in groups:
        ids = group.action_ids
        if group.relation != "SAME_SOURCE_EFFECT":
            status, reason = (
                "NOT_GROUPED", "Source review did not establish a shared effect"
            )
        elif any(action_id not in retained for action_id in ids):
            status, reason = (
                "NOT_RETAINED", "At least one route left the selected Action inventory"
            )
        elif any(action_id not in contracts
                 or contracts[action_id].status is not ProofStatus.PROVEN_STATIC
                 for action_id in ids):
            status, reason = (
                "STATE_UNRESOLVED", "Not every route has a proven state contract"
            )
        elif len({_state_signature(contracts[action_id])
                  for action_id in ids}) != 1:
            status, reason = (
                "STATE_MISMATCH", "Source-proven state contracts differ across routes"
            )
        elif any(action_id not in proven for action_id in ids):
            status, reason = (
                "RUNTIME_UNRESOLVED", "Not every route has its own proven original-program witness"
            )
        else:
            status, reason = (
                "ROUTES_SUPPORTED", "Every route has the same proven state contract "
                "and an independent proven original-program witness; route-specific "
                "fuzz coverage still requires separate measurement"
            )
        results.append(ActionGroupValidation(group.group_id, ids, status, reason))
    return results


class ActionSelectionAgent:
    """Keep substantive input processing; drop only source-supported trivia."""

    def __init__(self, llm: LLMProvider, graph: GraphStore):
        self.llm = llm
        self.graph = graph
        self.last_groups: list[ActionGroupDecision] = []
        self._terminal_failure = ""

    @staticmethod
    def _candidate_groups(
        actions: list[ExternalActionSchema],
    ) -> list[list[ExternalActionSchema]]:
        """Find review peers; matching names are hints, never merge proof."""
        groups: list[list[ExternalActionSchema]] = []
        positions: dict[tuple[str, str, str], int] = {}
        for action in actions:
            actor = str(action.actor)
            name = action.name.strip().casefold()
            handler = action.handler_function_id
            if (action.status is ProofStatus.REFUTED or actor == "UNKNOWN"
                or not name or not handler):
                groups.append([action])
                continue
            key = (actor, handler, name)
            index = positions.get(key)
            if index is None:
                positions[key] = len(groups)
                groups.append([action])
            else:
                groups[index].append(action)
        return groups

    async def run(self, actions: list[ExternalActionSchema]) -> list[ActionSelectionDecision]:
        self._terminal_failure = ""
        groups = self._candidate_groups(actions)
        reviewed = await concurrent_map(
            groups, self._review_candidate_group,
            max(1, int(getattr(self.llm, "max_concurrency", 1))),
        )
        self.last_groups = [group for _decisions, group in reviewed]
        decisions = {decision.action_id: decision
                     for group_decisions, _group in reviewed
                     for decision in group_decisions}
        if len(decisions) != len(actions) or set(decisions) != {
            action.action_id for action in actions
        }:
            raise RuntimeError("Action source grouping lost or duplicated a candidate")
        return [decisions[action.action_id] for action in actions]

    async def _review_candidate_group(
        self, actions: list[ExternalActionSchema],
    ) -> tuple[list[ActionSelectionDecision], ActionGroupDecision]:
        group_id = stable_id("action-group", *sorted(
            action.action_id for action in actions
        ))
        if self._terminal_failure:
            decisions = [ActionSelectionDecision(
                action.action_id, "UNRESOLVED", self._terminal_failure, [],
            ) for action in actions]
            return decisions, ActionGroupDecision(
                group_id, [action.action_id for action in actions],
                "UNRESOLVED", "UNRESOLVED", self._terminal_failure, [],
            )
        if len(actions) == 1:
            decision = await self._review(actions[0])
            return [decision], ActionGroupDecision(
                group_id, [actions[0].action_id], "SINGLETON",
                decision.disposition, decision.reason, decision.source_evidence,
            )
        anchors = {
            function_id for action in actions for function_id in (
                action.entry_function_id,
                action.dispatcher_function_id,
                action.handler_function_id,
            )
        }
        functions = self.graph.bundle.functions
        if not anchors.issubset(functions):
            reason = "A candidate's acquisition, selector, or effect source is not indexed"
            decisions = [ActionSelectionDecision(
                action.action_id, "UNRESOLVED", reason, [],
            ) for action in actions]
            return decisions, ActionGroupDecision(
                group_id, [action.action_id for action in actions],
                "UNRESOLVED", "UNRESOLVED", reason, [],
            )
        opened = sorted(anchors)
        payloads = []
        for action in actions:
            payload = as_json(action)
            payload.pop("inspected_function_ids", None)
            payloads.append(payload)
        session = f"action_group:{group_id}"
        try:
            while True:
                source = [function_payload(
                    functions[function_id],
                    source_limit=max(1, len(functions[function_id].source) + 1),
                ) for function_id in opened]
                response = await self.llm.complete_json(
                role="input_action",
                instructions=(
                    "Review these candidate Actions together using the supplied exact source. "
                    "A matching name or handler only proposes a comparison; it is never proof. "
                    "SAME_SOURCE_EFFECT means the externally selected handler effect, its "
                    "source-visible preconditions and state changes, and its success/failure "
                    "response semantics agree for every candidate. Different framing or Entry "
                    "can be retained as separate input routes. If any effect, precondition, "
                    "or response semantics differ, return DIFFERENT. If the source cannot "
                    "establish equivalence, return UNRESOLVED. Cite exact lines in every "
                    "acquisition, selection, and effect function for SAME_SOURCE_EFFECT. "
                    "For SAME_SOURCE_EFFECT only, also decide whether the shared effect is "
                    "worth fuzzing: KEEP substantive input-driven behavior; use "
                    "UNRESOLVED when usefulness differs or is unclear. A grouped DROP "
                    "will not remove multiple routes; those need individual proof. "
                    "Never use absent request examples or unobserved runtime behavior as a "
                    "reason to DROP. This is source-level grouping only: every route remains "
                    "a distinct candidate for request construction and runtime verification. "
                    "If relation is DIFFERENT or UNRESOLVED, return one individual_decisions "
                    "record for EVERY action_id, using the same KEEP/DROP/UNRESOLVED rules "
                    "and citing its own selection and handler lines for DROP. "
                    "For SAME_SOURCE_EFFECT, individual_decisions must be empty."
                    " If a parser, completion, or response function is needed to decide "
                    "the relation, set requested_function_id to one exact indexed "
                    "function ID or unambiguous name and continue in this session. "
                    "Only conclude UNRESOLVED when no further available source can "
                    "settle the missing fact. Do not infer equality from a shared name."
                ),
                payload={"actions": payloads, "source_functions": source,
                         "opened_function_ids": opened},
                output_schema=ACTION_GROUP_SCHEMA,
                session_key=session,
                )
                requested = str(response.get("requested_function_id") or "")
                if not requested:
                    break
                selected = resolve_source_linked_function(
                    requested, opened, [], self.graph,
                )
                if not selected:
                    response = {**response, "relation": "UNRESOLVED",
                                "reason": ("Requested comparison source is unavailable "
                                           f"or already opened: {requested}")}
                    break
                opened.append(selected)
            relation = str(response.get("relation") or "UNRESOLVED")
            disposition = str(response.get("decision") or "UNRESOLVED")
            reason = str(response.get("reason") or "").strip()
            citations = [item for item in _validated_evidence(
                response.get("source_evidence"), set(opened), self.graph,
            ) if item.line is not None]
            citation_ids = {item.function_id for item in citations}
            if (relation == "SAME_SOURCE_EFFECT"
                and (not reason or not anchors.issubset(citation_ids))):
                relation = "UNRESOLVED"
                reason = "Shared effect lacked source-line evidence for every route anchor"
            if relation not in {"SAME_SOURCE_EFFECT", "DIFFERENT", "UNRESOLVED"}:
                relation = "UNRESOLVED"
                reason = "Invalid source-equivalence verdict"
            if disposition not in {"KEEP", "DROP", "UNRESOLVED"}:
                disposition = "UNRESOLVED"
            if relation == "SAME_SOURCE_EFFECT":
                if disposition == "DROP":
                    disposition = "UNRESOLVED"
                    reason = (
                        "A shared-effect decision cannot drop multiple input "
                        "routes without individual source review"
                    )
                evidence = [as_json(item) for item in citations]
                decisions = [ActionSelectionDecision(
                    action.action_id, disposition, reason, evidence,
                ) for action in actions]
            else:
                # One grouped source read can still assess each candidate's
                # usefulness. Missing or invalid per-action claims stay open.
                raw_individual = response.get("individual_decisions")
                if not isinstance(raw_individual, list):
                    raw_individual = []
                by_id: dict[str, dict[str, Any]] = {}
                duplicates: set[str] = set()
                valid_ids = {action.action_id for action in actions}
                for item in raw_individual:
                    if not isinstance(item, dict):
                        continue
                    action_id = str(item.get("action_id") or "")
                    if action_id not in valid_ids:
                        continue
                    if action_id in by_id:
                        duplicates.add(action_id)
                    else:
                        by_id[action_id] = item
                decisions = []
                for action in actions:
                    item = by_id.get(action.action_id)
                    if item is None or action.action_id in duplicates:
                        decisions.append(ActionSelectionDecision(
                            action.action_id, "UNRESOLVED",
                            "Grouped review omitted or duplicated this Action", [],
                        ))
                        continue
                    individual_verdict = str(item.get("decision") or "UNRESOLVED")
                    individual_reason = str(item.get("reason") or "").strip()
                    individual_anchors = {
                        action.dispatcher_function_id,
                        action.handler_function_id,
                    }
                    individual_evidence = [evidence for evidence in
                        _validated_evidence(
                            item.get("source_evidence"), anchors, self.graph,
                        ) if evidence.line is not None]
                    cited_ids = {evidence.function_id for evidence in individual_evidence}
                    if individual_verdict not in {"KEEP", "DROP", "UNRESOLVED"}:
                        individual_verdict = "UNRESOLVED"
                    if individual_verdict == "DROP" and (
                        not individual_reason
                        or not individual_anchors.issubset(cited_ids)
                    ):
                        individual_verdict = "UNRESOLVED"
                        individual_reason = (
                            "DROP lacked source-line evidence for this Action's "
                            "selection and handler"
                        )
                    decisions.append(ActionSelectionDecision(
                        action.action_id, individual_verdict,
                        individual_reason,
                        [as_json(evidence) for evidence in individual_evidence],
                    ))
                disposition = "INDIVIDUAL"
            return decisions, ActionGroupDecision(
                group_id, [action.action_id for action in actions],
                relation, disposition, reason,
                [as_json(item) for item in citations],
            )
        except Exception as exc:
            reason = f"Action grouping unavailable: {type(exc).__name__}: {exc}"
            if is_terminal_llm_infrastructure_error(exc):
                self._terminal_failure = reason
            decisions = [ActionSelectionDecision(
                action.action_id, "UNRESOLVED", reason, [],
            ) for action in actions]
            return decisions, ActionGroupDecision(
                group_id, [action.action_id for action in actions],
                "UNRESOLVED", "UNRESOLVED", reason, [],
            )
        finally:
            await close_llm_session(self.llm, session)

    async def _review(self, action: ExternalActionSchema) -> ActionSelectionDecision:
        if self._terminal_failure:
            return ActionSelectionDecision(
                action.action_id, "UNRESOLVED", self._terminal_failure, [],
            )
        if action.status is ProofStatus.REFUTED:
            return ActionSelectionDecision(
                action.action_id, "DROP", "Action was already refuted by source analysis", [],
            )
        anchors = {
            action.entry_function_id,
            action.dispatcher_function_id,
            action.handler_function_id,
        }
        functions = self.graph.bundle.functions
        if not anchors.issubset(functions):
            return ActionSelectionDecision(
                action.action_id, "UNRESOLVED",
                "An acquisition, selection, or handler source is not indexed", [],
            )
        opened = set(anchors)
        source = [function_payload(
            functions[function_id],
            source_limit=max(1, len(functions[function_id].source) + 1),
        ) for function_id in sorted(opened)]
        action_payload = as_json(action)
        action_payload.pop("inspected_function_ids", None)
        session = f"action_selection:{action.action_id}"
        try:
            response = await self.llm.complete_json(
                role="input_action",
                instructions=(
                    "Decide whether this newly reconstructed Action deserves a fuzzing harness. "
                    "Judge its actual externally controlled effect from the supplied acquisition, "
                    "selection, and handler source. KEEP protocol parsing, storage, state changes, "
                    "error handling, and any other substantive input-driven behavior, including "
                    "startup arguments when their values reach such behavior. "
                    "DROP only when the cited selection and handler source show that this Action "
                    "is solely incidental setup, bookkeeping, or a redundant wrapper with no "
                    "distinct input-driven target behavior. A function name, missing request "
                    "example, unsupported runtime adapter, or short fuzz budget is never a DROP "
                    "reason. If usefulness cannot be decided from these sources, UNRESOLVED. "
                    "Cite exact source lines for DROP; do not infer non-reachability from absent "
                    "evidence. Do not treat a syntax branch as an Action by itself."
                ),
                payload={"action": action_payload, "source_functions": source},
                output_schema=ACTION_SELECTION_SCHEMA,
                session_key=session,
            )
            verdict = str(response.get("decision") or "UNRESOLVED")
            reason = str(response.get("reason") or "").strip()
            citations = [item for item in _validated_evidence(
                response.get("source_evidence"), opened, self.graph,
            ) if item.line is not None]
            citation_ids = {item.function_id for item in citations}
            if verdict == "DROP" and (
                not reason
                or action.dispatcher_function_id not in citation_ids
                or action.handler_function_id not in citation_ids
            ):
                verdict = "UNRESOLVED"
                reason = "DROP lacked source-line evidence for both selection and handler"
            if verdict not in {"KEEP", "DROP", "UNRESOLVED"}:
                verdict = "UNRESOLVED"
                reason = "Model returned an invalid selection verdict"
            return ActionSelectionDecision(
                action.action_id, verdict, reason,
                [as_json(item) for item in citations],
            )
        except Exception as exc:
            if is_terminal_llm_infrastructure_error(exc):
                self._terminal_failure = (
                    f"Action selection unavailable: {type(exc).__name__}: {exc}"
                )
            return ActionSelectionDecision(
                action.action_id, "UNRESOLVED",
                f"Action selection unavailable: {type(exc).__name__}: {exc}", [],
            )
        finally:
            await close_llm_session(self.llm, session)
