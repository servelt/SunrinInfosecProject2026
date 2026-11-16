"""Durable, evidence-scoped work units after Entry verification.

The source acquisition verdict, configured activation, and runtime reachability
are deliberately separate. A budget or an unavailable backend is never a
negative claim about the program's behavior.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import EntryRecord, Evidence, stable_id, unique_strings
from ..input_transport import source_transport
from ..storage import ArtifactStore

if TYPE_CHECKING:
    from ..agents.behavior import BehaviorCandidate


@dataclass(slots=True)
class EntryDecision:
    entry_id: str
    source_verdict: str
    transport: str
    activation: str
    runtime_reachability: str
    external_input: str
    disposition: str
    reason: str
    priority: int


def plan_entries(
    entries: list[EntryRecord], *, scenario_channel: str,
    scenario_command: list[str], scenario_port: int | None,
    scenario_input_env: str = "",
) -> list[EntryDecision]:
    """Prioritize configured external inputs without changing Entry verdicts.

    Unknown activation is preserved. Only a runtime acquisition trace can
    change runtime_reachability from UNRESOLVED to REACHED.
    """
    result: list[EntryDecision] = []
    for entry in entries:
        transport = source_transport(entry)
        activation = "UNRESOLVED"
        disposition = "SELECTED"
        reason = "source-only investigation; original input delivery is not configured"
        priority = 50
        compatible = bool(scenario_command) and scenario_channel in {"auto", transport}
        if transport in {"tcp", "udp"} and scenario_port is None:
            compatible = False
        if transport == "file" and not any("{input}" in token for token in scenario_command):
            compatible = False
            reason = "file input requires an explicit trusted {input} argument"
            if scenario_command:
                activation, disposition, priority = "NOT_CONFIGURED", "DEFERRED", 80
        if transport == "env" and not scenario_input_env:
            compatible = False
            reason = "environment input requires a trusted scenario_input_env name"
            if scenario_command:
                activation, disposition, priority = "NOT_CONFIGURED", "DEFERRED", 80
        if transport == "argv" and scenario_channel != "argv" and not any(
            "{input}" in token for token in scenario_command
        ):
            compatible = False
            activation, disposition, priority = "NOT_CONFIGURED", "DEFERRED", 80
            reason = "argv input requires an explicit argv channel or trusted {input} placeholder"
        if transport == "unknown":
            compatible = False
            activation, disposition, priority = "UNRESOLVED", "DEFERRED", 80
            reason = "transport unresolved; source analysis may establish delivery"
        if compatible:
            activation = "CONFIGURED_CANDIDATE"
            disposition = "SELECTED"
            reason = "source transport matches a configured original-program trial"
            priority = 10 if transport in {"tcp", "udp"} else 30
        result.append(EntryDecision(
            entry.entry_id, str(entry.status.value), transport, activation,
            "UNRESOLVED", transport if compatible else "UNRESOLVED",
            disposition, reason, priority,
        ))
    return sorted(result, key=lambda item: (item.priority, item.entry_id))


@dataclass(slots=True)
class WorkUnit:
    work_id: str
    entry_id: str
    input_flow: str
    effect: str
    prior_state: str
    execution_mode: str
    behavior_ids: list[str] = field(default_factory=list)
    path_variants: list[list[str]] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    disposition: str = "POSSIBLE"
    reason: str = "source hypothesis; runtime path not yet attributed"


def _identity(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _usable_identity(value: str) -> bool:
    """Reject explanations that cannot serve as a stable work-unit key.

    Short domain labels such as ``request bytes`` remain usable. A paragraph
    about the flow is evidence to inspect, not a claim of semantic identity.
    """
    return bool(
        value and not value.startswith(("unknown", "unresolved"))
        and len(value) <= 96 and len(value.split()) <= 5
        and not any(mark in value for mark in (".", ";", "?", "!", "\n"))
    )


def canonicalize_behaviors(rows: list[BehaviorCandidate]) -> list[WorkUnit]:
    """Merge path evidence only when the same declared effect is identifiable.

    A missing structured effect is not equated with another candidate just
    because both have the same target function or prose-like summary.
    """
    by_key: dict[tuple[str, ...], WorkUnit] = {}
    for row in rows:
        effect = _identity(row.effect)
        flow = _identity(row.input_flow)
        prior = _identity(row.prior_state)
        mode = _identity(row.execution_mode)
        known = all(_usable_identity(value) for value in (effect, flow, prior, mode))
        if known:
            key = (row.entry_id, flow, effect, prior, mode, row.kind)
            unknowns = list(row.unknowns)
        else:
            key = (row.entry_id, "unresolved-effect-identity", row.behavior_id)
            unknowns = unique_strings([
                *row.unknowns,
                "input flow, effect, prior state or execution mode identity unresolved",
            ])
        unit = by_key.get(key)
        if unit is None:
            unit = WorkUnit(
                work_id=stable_id("boundary-work", *key), entry_id=row.entry_id,
                input_flow=row.input_flow or "UNRESOLVED",
                effect=row.effect or "UNRESOLVED",
                prior_state=row.prior_state or "UNRESOLVED",
                execution_mode=row.execution_mode or "UNRESOLVED",
                disposition="POSSIBLE" if known else "UNRESOLVED",
                reason=("source hypothesis; runtime path not yet attributed" if known
                        else "structured identity is missing or prose; do not merge by wording"),
            )
            by_key[key] = unit
        unit.behavior_ids.append(row.behavior_id)
        for path in row.path_variants or [row.path_function_ids]:
            if path not in unit.path_variants:
                unit.path_variants.append(list(path))
        seen = {(item.kind, item.function_id, item.file, item.line, item.detail)
                for item in unit.evidence}
        for item in row.evidence:
            identity = (item.kind, item.function_id, item.file, item.line, item.detail)
            if identity not in seen:
                unit.evidence.append(item)
                seen.add(identity)
        unit.unknowns = unique_strings([*unit.unknowns, *unknowns])
    return list(by_key.values())


def prioritize_work_units(
    units: list[WorkUnit], rows: list[BehaviorCandidate],
    runtime_hint_function_ids: list[str],
) -> list[tuple[WorkUnit, dict[str, bool | int]]]:
    """Order source candidates by inspectable evidence, never model position.

    A temporal debugger hit is a navigation hint only. It cannot turn a
    possible source effect into an attributed runtime observation.
    """
    by_behavior = {row.behavior_id: row for row in rows}
    hints = set(runtime_hint_function_ids)
    ranked: list[tuple[tuple[object, ...], WorkUnit, dict[str, bool | int]]] = []
    for unit in units:
        members = [by_behavior[bid] for bid in unit.behavior_ids if bid in by_behavior]
        targets = {member.target_function_id for member in members}
        downstream = any(
            member.target_function_id != member.entry_function_id for member in members
        )
        cited_target = any(
            item.kind == "source" and item.function_id in targets
            for item in unit.evidence
        )
        linked_path = any(
            path and any(
                path[0] == member.entry_function_id
                and path[-1] == member.target_function_id
                for member in members
            ) for path in unit.path_variants
        )
        signals: dict[str, bool | int] = {
            "structured_identity": unit.disposition == "POSSIBLE",
            "named_effect": _usable_identity(_identity(unit.effect)),
            "downstream_effect": downstream,
            "temporal_target_hint": bool(targets & hints),
            "target_source_cited": cited_target,
            "entry_to_target_path_declared": linked_path,
            "unresolved_obligations": len(unit.unknowns),
        }
        key: tuple[object, ...] = (
            not signals["structured_identity"],
            not signals["named_effect"],
            not signals["downstream_effect"],
            not signals["target_source_cited"],
            not signals["entry_to_target_path_declared"],
            not signals["temporal_target_hint"],
            signals["unresolved_obligations"],
            unit.work_id,
        )
        ranked.append((key, unit, signals))
    return [(unit, signals) for _key, unit, signals in sorted(ranked, key=lambda row: row[0])]


class WorkLedger:
    """Append-only stage transitions; completed stages survive interruption."""

    _FINAL = {
        "COMPLETED", "BLOCKED_UNSUPPORTED_BACKEND", "BLOCKED_EVIDENCE",
        "FAILED_IMPLEMENTATION", "FAILED_DESIGN_ASSUMPTION",
    }

    def __init__(self, store: ArtifactStore):
        self.store = store
        self.path = store.root / "workflow" / "work-events.jsonl"
        self._latest: dict[tuple[str, str], dict] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue  # ignore only an interrupted final append
                self._latest[(event["work_id"], event["stage"])] = event

    def mark(self, work_id: str, stage: str, status: str, reason: str, **details: object) -> None:
        event = {
            "work_id": work_id, "stage": stage, "status": status,
            "reason": reason, "time_unix": time.time(), **details,
        }
        self.store.append_jsonl("workflow/work-events.jsonl", event)
        self._latest[(work_id, stage)] = event

    def latest(self, work_id: str, stage: str) -> dict | None:
        return self._latest.get((work_id, stage))

    def finished(self, work_id: str, stage: str) -> bool:
        event = self.latest(work_id, stage)
        return bool(event and event["status"] in self._FINAL)

    def latest_events(self) -> list[dict]:
        return list(self._latest.values())


def snapshot_path(store: ArtifactStore, work_id: str, stage: str) -> Path:
    return store.root / "workflow" / "work-items" / work_id / f"{stage}.json"
