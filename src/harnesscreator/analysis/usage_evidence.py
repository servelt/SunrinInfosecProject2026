from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..models import AnalysisBundle, FunctionMetadata, stable_id, unique_strings


@dataclass(slots=True)
class UsageConstraint:
    """A source-backed ordering constraint emitted by an upstream tool.

    ``producer_function_ids`` and ``consumer_function_ids`` are populated only
    by exact, unique matches against the project's static-analysis database.
    Ambiguous names are deliberately retained as unresolved evidence instead of
    being guessed by an LLM or by fuzzy string matching.
    """

    constraint_id: str
    provider: str
    relation: str
    strength: str
    producer: str
    consumer: str
    producer_function_ids: list[str] = field(default_factory=list)
    consumer_function_ids: list[str] = field(default_factory=list)
    source: str = ""
    detail: str = ""


@dataclass(slots=True)
class UsageSequence:
    sequence_id: str
    provider: str
    calls: list[str]
    function_ids: list[str]
    source: str
    authoritative: bool = False


@dataclass(slots=True)
class UsageProviderStatus:
    provider: str
    state: str
    source: str = ""
    reason: str = ""
    constraints: int = 0
    sequences: int = 0
    upstream_revision: str = ""
    source_sha256: str = ""


@dataclass(slots=True)
class UsageActionCheck:
    actions: list[dict[str, Any]]
    blockers: list[str] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)
    applied_constraints: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UsageEvidenceBundle:
    constraints: list[UsageConstraint] = field(default_factory=list)
    sequences: list[UsageSequence] = field(default_factory=list)
    providers: list[UsageProviderStatus] = field(default_factory=list)

    def relevant_payload(self, function_ids: Iterable[str]) -> dict[str, Any]:
        selected = set(function_ids)
        relevant_constraints = [
            constraint
            for constraint in self.constraints
            if selected.intersection(constraint.producer_function_ids)
            or selected.intersection(constraint.consumer_function_ids)
        ]
        relevant_sequences = [
            sequence
            for sequence in self.sequences
            if selected.intersection(sequence.function_ids)
        ]
        # Deterministic validation below uses the complete bundle.  Prompt data
        # is a bounded explanation window so a highly branching RUBICK NFA
        # cannot recreate the context-window problem this workflow is meant to
        # avoid.
        constraints = relevant_constraints[:128]
        sequences = relevant_sequences[:32]
        return {
            "constraints": [_constraint_payload(item) for item in constraints],
            "sequences": [_sequence_payload(item) for item in sequences],
            "omitted_constraint_count": len(relevant_constraints) - len(constraints),
            "omitted_sequence_count": len(relevant_sequences) - len(sequences),
            "policy": (
                "REQUIRED and FORBIDDEN constraints are upstream evidence, not "
                "suggestions. OBSERVED/PREFERRED order is advisory. Unresolved "
                "symbol matches must not be guessed."
            ),
        }

    def constrain_actions(
        self,
        actions: list[dict[str, Any]],
    ) -> UsageActionCheck:
        """Apply only constraints that the upstream tools actually established.

        Required predecessor edges are copied into ``allowed_after`` when the
        proposed list already has the correct order.  The list is never
        reordered: a missing or reversed required call remains an explicit
        planning blocker so state/sequence analysis can retain the unresolved
        obligation instead of silently inventing a lifecycle.
        """

        normalized: list[dict[str, Any]] = []
        for action in actions:
            raw_predecessors = action.get("allowed_after", [])
            if not isinstance(raw_predecessors, list):
                raw_predecessors = [raw_predecessors]
            normalized.append({
                **action,
                "allowed_after": unique_strings(
                    str(value)
                    for value in raw_predecessors
                    if str(value).strip()
                ),
            })
        positions: dict[str, list[int]] = {}
        for index, action in enumerate(normalized):
            function_id = str(action.get("function_id", ""))
            positions.setdefault(function_id, []).append(index)

        blockers: list[str] = []
        advisories: list[str] = []
        applied: list[str] = []
        for constraint in self.constraints:
            consumer_positions = sorted({
                index
                for function_id in constraint.consumer_function_ids
                for index in positions.get(function_id, [])
            })
            if not consumer_positions:
                continue
            producer_positions = sorted({
                index
                for function_id in constraint.producer_function_ids
                for index in positions.get(function_id, [])
            })
            label = (
                f"{constraint.provider} {constraint.strength} "
                f"{constraint.producer} -> {constraint.consumer}"
            )
            if constraint.strength == "REQUIRED":
                if not constraint.producer_function_ids:
                    blockers.append(
                        f"UPSTREAM_DEPENDENCY_UNRESOLVED: {label}; producer symbol was not uniquely resolved"
                    )
                    continue
                if not producer_positions:
                    blockers.append(
                        f"UPSTREAM_DEPENDENCY_MISSING: {label}; required producer action is absent"
                    )
                    continue
                for consumer_index in consumer_positions:
                    prior = [index for index in producer_positions if index < consumer_index]
                    if not prior:
                        blockers.append(
                            f"UPSTREAM_DEPENDENCY_REVERSED: {label}; producer must precede consumer"
                        )
                        continue
                    producer_index = prior[-1]
                    producer_action_id = str(
                        normalized[producer_index].get("action_id", "")
                    ).strip()
                    if not producer_action_id:
                        blockers.append(
                            f"UPSTREAM_DEPENDENCY_UNRESOLVED: {label}; producer action has no action_id"
                        )
                        continue
                    predecessors = normalized[consumer_index]["allowed_after"]
                    if producer_action_id not in predecessors:
                        predecessors.append(producer_action_id)
                    applied.append(constraint.constraint_id)
            elif constraint.strength == "FORBIDDEN":
                if any(
                    producer_index < consumer_index
                    for producer_index in producer_positions
                    for consumer_index in consumer_positions
                ):
                    blockers.append(
                        f"UPSTREAM_CONTEXT_FORBIDDEN: {label}; forbidden context is present"
                    )
            elif not producer_positions:
                advisories.append(
                    f"UPSTREAM_ORDER_ADVISORY: {label}; observed/preferred producer is absent"
                )

        authoritative_by_provider: dict[str, list[UsageSequence]] = {}
        for sequence in self.sequences:
            if sequence.authoritative:
                authoritative_by_provider.setdefault(sequence.provider, []).append(sequence)
        action_function_order = [
            str(action.get("function_id", "")) for action in normalized
        ]
        for provider, sequences in authoritative_by_provider.items():
            vocabulary = {
                function_id
                for sequence in sequences
                for function_id in sequence.function_ids
            }
            projected = [
                function_id
                for function_id in action_function_order
                if function_id in vocabulary
            ]
            if len(projected) < 2:
                continue
            if any(
                _is_subsequence(projected, sequence.function_ids)
                for sequence in sequences
            ):
                continue
            blockers.append(
                f"UPSTREAM_SEQUENCE_INVALID: {provider} has no emitted sequence "
                f"that permits the proposed action order {projected}"
            )

        return UsageActionCheck(
            actions=normalized,
            blockers=unique_strings(blockers),
            advisories=unique_strings(advisories),
            applied_constraints=unique_strings(applied),
        )


class _FunctionResolver:
    def __init__(self, analysis: AnalysisBundle):
        aliases: dict[str, set[str]] = {}
        for function in analysis.functions.values():
            for alias in _function_aliases(function):
                aliases.setdefault(alias, set()).add(function.function_id)
        self.aliases = aliases

    def resolve(self, symbol: str) -> list[str]:
        direct = self.aliases.get(symbol.strip(), set())
        if len(direct) == 1:
            return sorted(direct)
        normalized = _symbol_name(symbol)
        matches = self.aliases.get(normalized, set())
        return sorted(matches) if len(matches) == 1 else []


def load_usage_evidence(
    analysis: AnalysisBundle,
    *,
    fuzzgen_reports: Iterable[Path] = (),
    hopper_constraints: Iterable[Path] = (),
    winnie_reports: Iterable[Path] = (),
    rubick_nfas: Iterable[Path] = (),
    upstream_revisions: dict[str, str] | None = None,
) -> UsageEvidenceBundle:
    """Load output produced by the original research implementations.

    This module is intentionally an adapter.  It does not recreate FuzzGen,
    Hopper, WINNIE, or RUBICK's analyses.  A provider is marked ``USED`` only
    after one of its real output files has been parsed successfully.
    """

    resolver = _FunctionResolver(analysis)
    bundle = UsageEvidenceBundle()
    revisions = upstream_revisions or {}
    configured = {
        "FuzzGen": list(fuzzgen_reports),
        "Hopper": list(hopper_constraints),
        "WINNIE": list(winnie_reports),
        "RUBICK": list(rubick_nfas),
    }
    loaders = {
        "FuzzGen": _load_fuzzgen_report,
        "Hopper": _load_hopper_constraints,
        "WINNIE": _load_winnie_report,
        "RUBICK": _load_rubick_nfa,
    }
    for provider, paths in configured.items():
        if not paths:
            bundle.providers.append(UsageProviderStatus(
                provider=provider,
                state="NOT_CONFIGURED",
                reason="no upstream output was supplied; provider evidence was not used",
                upstream_revision=revisions.get(provider, ""),
            ))
            continue
        for path in paths:
            resolved = path.expanduser().resolve()
            try:
                constraints, sequences = loaders[provider](resolved, resolver)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                bundle.providers.append(UsageProviderStatus(
                    provider=provider,
                    state="ERROR",
                    source=str(resolved),
                    reason=str(exc),
                    upstream_revision=revisions.get(provider, ""),
                    source_sha256=_file_sha256(resolved),
                ))
                continue
            bundle.constraints.extend(constraints)
            bundle.sequences.extend(sequences)
            bundle.providers.append(UsageProviderStatus(
                provider=provider,
                state="USED",
                source=str(resolved),
                constraints=len(constraints),
                sequences=len(sequences),
                upstream_revision=revisions.get(provider, ""),
                source_sha256=_file_sha256(resolved),
            ))
    bundle.constraints = list({
        constraint.constraint_id: constraint for constraint in bundle.constraints
    }.values())
    bundle.sequences = list({
        sequence.sequence_id: sequence for sequence in bundle.sequences
    }.values())
    return bundle


def load_upstream_revisions(root: Path | None) -> dict[str, str]:
    """Read locked provider revisions without probing or mutating a clone."""

    if root is None:
        return {}
    lock = root / "LOCK.json"
    try:
        payload = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    aliases = {
        "fuzzgen": "FuzzGen",
        "hopper": "Hopper",
        "rubick": "RUBICK",
        "winnie": "WINNIE",
    }
    return {
        aliases.get(str(item.get("name", "")).casefold(), str(item.get("name", ""))):
            str(item.get("commit", ""))
        for item in payload.get("repositories", [])
        if isinstance(item, dict) and item.get("name") and item.get("commit")
    }


def _load_hopper_constraints(
    path: Path,
    resolver: _FunctionResolver,
) -> tuple[list[UsageConstraint], list[UsageSequence]]:
    # Mirrors CallContext::from_rule in Hopper's
    # hopper-core/src/fuzz/constraints/context.rs.  This parses its output/rule
    # syntax; it does not infer a context relation of our own.
    pattern = re.compile(
        r"^\s*ctx\s+([^\[\s]+)\[(?:\$\d+|\*|-)\]\s*<-\s*"
        r"(!\s*)?([^\s;?]+)\s*(\?)?\s*;?\s*$"
    )
    constraints: list[UsageConstraint] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.split("//", 1)[0].strip()
        if not line or not line.startswith("ctx "):
            continue
        match = pattern.match(line)
        if not match:
            raise ValueError(f"invalid Hopper ctx rule at {path}:{line_number}: {raw_line}")
        consumer, forbidden, producer, preferred = match.groups()
        strength = "FORBIDDEN" if forbidden else "PREFERRED" if preferred else "REQUIRED"
        constraints.append(_constraint(
            provider="Hopper",
            relation="CALL_CONTEXT",
            strength=strength,
            producer=producer,
            consumer=consumer,
            resolver=resolver,
            source=f"{path}:{line_number}",
            detail=raw_line.strip(),
        ))
    return constraints, []


def _load_fuzzgen_report(
    path: Path,
    resolver: _FunctionResolver,
) -> tuple[list[UsageConstraint], list[UsageSequence]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "harnesscreator.fuzzgen.aadg.v1":
        raise ValueError(
            "FuzzGen report must use schema harnesscreator.fuzzgen.aadg.v1; "
            "raw DOT is not silently reinterpreted"
        )
    constraints: list[UsageConstraint] = []
    sequences: list[UsageSequence] = []
    for graph_index, graph in enumerate(payload.get("graphs", [])):
        if not isinstance(graph, dict):
            raise ValueError("FuzzGen graphs must be JSON objects")
        nodes = {
            str(node.get("id")): node
            for node in graph.get("nodes", [])
            if isinstance(node, dict) and node.get("id") is not None
        }
        dependency_occurrences: dict[str, dict[str, list[str]]] = {}
        for node_id, node in nodes.items():
            for dep_id, kinds in _fuzzgen_dependencies(node):
                occurrence = dependency_occurrences.setdefault(
                    dep_id, {"DEF": [], "USE": [], "INIT": []}
                )
                for kind in kinds:
                    occurrence.setdefault(kind, []).append(node_id)
        for dep_id, occurrence in dependency_occurrences.items():
            for producer_id in occurrence.get("DEF", []):
                producer = _fuzzgen_node_symbol(nodes[producer_id])
                for consumer_id in unique_strings([
                    *occurrence.get("USE", []),
                    *occurrence.get("INIT", []),
                ]):
                    if producer_id == consumer_id:
                        continue
                    consumer = _fuzzgen_node_symbol(nodes[consumer_id])
                    constraints.append(_constraint(
                        provider="FuzzGen",
                        relation="DATA_DEPENDENCY",
                        strength="REQUIRED",
                        producer=producer,
                        consumer=consumer,
                        resolver=resolver,
                        source=str(path),
                        detail=f"graph={graph.get('name', graph_index)} dependency_id={dep_id}",
                    ))
        for edge_index, edge in enumerate(graph.get("control_edges", [])):
            if not isinstance(edge, dict) or bool(edge.get("back_edge", False)):
                continue
            producer_node = nodes.get(str(edge.get("from")))
            consumer_node = nodes.get(str(edge.get("to")))
            if producer_node is None or consumer_node is None:
                continue
            producer = _fuzzgen_node_symbol(producer_node)
            consumer = _fuzzgen_node_symbol(consumer_node)
            if producer and consumer:
                constraints.append(_constraint(
                    provider="FuzzGen",
                    relation="CONTROL_EDGE",
                    strength="OBSERVED",
                    producer=producer,
                    consumer=consumer,
                    resolver=resolver,
                    source=str(path),
                    detail=(
                        f"graph={graph.get('name', graph_index)} "
                        f"control_edge={edge_index}"
                    ),
                ))
        calls: list[str] = []
        for node in graph.get("nodes", []):
            if isinstance(node, dict):
                symbol = _fuzzgen_node_symbol(node)
                if symbol:
                    calls.append(symbol)
        function_ids = [
            resolved[0]
            for symbol in calls
            if (resolved := resolver.resolve(symbol))
        ]
        if calls:
            sequences.append(UsageSequence(
                sequence_id=stable_id("useq", "FuzzGen", str(path), graph_index, *calls),
                provider="FuzzGen",
                calls=calls,
                function_ids=function_ids,
                source=str(path),
                authoritative=False,
            ))
    return constraints, sequences


def _load_winnie_report(
    path: Path,
    resolver: _FunctionResolver,
) -> tuple[list[UsageConstraint], list[UsageSequence]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "harnesscreator.winnie.trace-sequence.v1":
        raise ValueError(
            "WINNIE report must use schema harnesscreator.winnie.trace-sequence.v1"
        )
    sequences: list[UsageSequence] = []
    for index, item in enumerate(payload.get("sequences", [])):
        raw_calls = item.get("calls", []) if isinstance(item, dict) else []
        calls = [
            str(call.get("function", "")) if isinstance(call, dict) else str(call)
            for call in raw_calls
        ]
        calls = [call for call in calls if call]
        function_ids = [
            resolved[0]
            for call in calls
            if (resolved := resolver.resolve(call))
        ]
        if calls:
            sequences.append(UsageSequence(
                sequence_id=stable_id("useq", "WINNIE", str(path), index, *calls),
                provider="WINNIE",
                calls=calls,
                function_ids=function_ids,
                source=str(path),
                authoritative=True,
            ))
    return [], sequences


def _load_rubick_nfa(
    path: Path,
    resolver: _FunctionResolver,
) -> tuple[list[UsageConstraint], list[UsageSequence]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") == "harnesscreator.rubick.nfa-set.v1":
        nfas = payload.get("nfas", [])
        if not isinstance(nfas, list):
            raise ValueError("RUBICK NFA set must contain a list named nfas")
    else:
        nfas = [payload]
    sequences: list[UsageSequence] = []
    for nfa_index, nfa in enumerate(nfas):
        if not isinstance(nfa, dict):
            raise ValueError("RUBICK NFA entry must be an object")
        sequences.extend(_rubick_nfa_sequences(path, nfa, resolver, nfa_index))
    return [], sequences


def _rubick_nfa_sequences(
    path: Path,
    payload: dict[str, Any],
    resolver: _FunctionResolver,
    nfa_index: int,
) -> list[UsageSequence]:
    required = {"name", "initial", "states", "map"}
    if not required <= set(payload):
        raise ValueError("RUBICK NFA is missing one of name/initial/states/map")
    transitions: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for source, targets in payload.get("map", {}).items():
        if not isinstance(targets, dict):
            continue
        transitions[str(source)] = [
            (str(target), event)
            for target, event in targets.items()
            if isinstance(event, dict)
        ]
    sequences: list[UsageSequence] = []
    stack: list[tuple[str, list[str], set[str]]] = [
        (str(initial), [], {str(initial)})
        for initial in payload.get("initial", [])
    ]
    # RUBICK's NFA can branch.  Preserve a bounded set of source-produced call
    # paths for prompt evidence without turning the adapter into a new automata
    # inference engine.
    while stack and len(sequences) < 256:
        state, calls, visited = stack.pop()
        outgoing = transitions.get(state, [])
        if not outgoing:
            if calls:
                function_ids = [
                    resolved[0]
                    for call in calls
                    if (resolved := resolver.resolve(call))
                ]
                sequences.append(UsageSequence(
                    sequence_id=stable_id(
                        "useq", "RUBICK", str(path), nfa_index, *calls
                    ),
                    provider="RUBICK",
                    calls=calls,
                    function_ids=function_ids,
                    source=str(path),
                    authoritative=True,
                ))
            continue
        for target, event in outgoing:
            if target in visited:
                continue
            next_calls = list(calls)
            if event.get("type") == "call" and event.get("func"):
                next_calls.append(str(event["func"]))
            stack.append((target, next_calls, {*visited, target}))
    return sequences


def _constraint(
    *,
    provider: str,
    relation: str,
    strength: str,
    producer: str,
    consumer: str,
    resolver: _FunctionResolver,
    source: str,
    detail: str,
) -> UsageConstraint:
    return UsageConstraint(
        constraint_id=stable_id(
            "udep", provider, relation, strength, producer, consumer, source, detail
        ),
        provider=provider,
        relation=relation,
        strength=strength,
        producer=producer,
        consumer=consumer,
        producer_function_ids=resolver.resolve(producer),
        consumer_function_ids=resolver.resolve(consumer),
        source=source,
        detail=detail,
    )


def _function_aliases(function: FunctionMetadata) -> set[str]:
    values = {
        function.function_id,
        function.name,
        function.qualified_name,
        function.signature,
        _symbol_name(function.name),
        _symbol_name(function.qualified_name),
        _symbol_name(function.signature),
    }
    return {value.strip() for value in values if value and value.strip()}


def _symbol_name(value: str) -> str:
    text = value.strip()
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    # A report may contain a return type while FI stores only the callee name.
    return text.rsplit(None, 1)[-1] if text else ""


def _fuzzgen_node_symbol(node: dict[str, Any]) -> str:
    for key in ("callee", "function", "name", "signature"):
        value = str(node.get(key, "")).strip()
        if value:
            return value
    return ""


def _fuzzgen_dependencies(node: dict[str, Any]) -> list[tuple[str, set[str]]]:
    records: list[Any] = list(node.get("dependencies", []))
    records.extend(node.get("arguments", []))
    if node.get("return_dependency") is not None:
        value = node["return_dependency"]
        records.append(value if isinstance(value, dict) else {
            "dependency_id": value,
            "dependency_type": "DEF",
        })
    result: list[tuple[str, set[str]]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        dep_id = record.get(
            "dependency_id", record.get("dep_id", record.get("depID"))
        )
        if dep_id in (None, "", -1, 0xFFFF, "0xffff", "0x0000ffff"):
            continue
        kinds = _dependency_kinds(
            record.get("dependency_type", record.get("dep_type", record.get("depTy")))
        )
        if kinds:
            result.append((str(dep_id), kinds))
    return result


def _dependency_kinds(value: Any) -> set[str]:
    if isinstance(value, int):
        return {
            kind
            for flag, kind in ((1, "DEF"), (2, "USE"), (4, "INIT"))
            if value & flag
        }
    if isinstance(value, list):
        return {
            str(item).upper()
            for item in value
            if str(item).upper() in {"DEF", "USE", "INIT"}
        }
    text = str(value or "").upper()
    return {
        kind for kind in ("DEF", "USE", "INIT") if kind in text
    }


def _constraint_payload(item: UsageConstraint) -> dict[str, Any]:
    return {
        "constraint_id": item.constraint_id,
        "provider": item.provider,
        "relation": item.relation,
        "strength": item.strength,
        "producer": item.producer,
        "consumer": item.consumer,
        "producer_function_ids": item.producer_function_ids,
        "consumer_function_ids": item.consumer_function_ids,
        "source": item.source,
        "detail": item.detail,
    }


def _sequence_payload(item: UsageSequence) -> dict[str, Any]:
    return {
        "sequence_id": item.sequence_id,
        "provider": item.provider,
        "calls": item.calls,
        "function_ids": item.function_ids,
        "source": item.source,
        "authoritative": item.authoritative,
    }


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
    if not needle:
        return True
    index = 0
    for item in haystack:
        if item == needle[index]:
            index += 1
            if index == len(needle):
                return True
    return False


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()
