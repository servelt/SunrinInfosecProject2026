from __future__ import annotations

import time
from typing import Any, Callable, Protocol

from .storage import ArtifactStore


class TraceCallback(Protocol):
    def __call__(self, agent: str, event: str, details: dict[str, Any]) -> None: ...


class AgentTraceLogger:
    """Crash-durable decisions plus a deliberately small human trace.

    ``agent-events.jsonl`` remains the lossless debugging record.  The console
    and ``agent-trace.log`` are a navigation view: where an Entry analysis
    started, which function-to-function moves were newly explored, and how
    an external action was split, which state facts were established, and how
    a runtime witness became a harness plan.
    """

    def __init__(
        self,
        store: ArtifactStore,
        *,
        console: Callable[[str], None] | None = None,
    ):
        self.store = store
        self.console = console
        self.sequence = 0
        self._seen_moves: set[tuple[str, str, str, str]] = set()
        self._entry_labels: dict[str, str] = {}
        self._candidate_labels: dict[str, str] = {}
        self._small_labels: dict[str, str] = {}
        self._large_labels: dict[str, str] = {}

    def emit(self, agent: str, event: str, details: dict[str, Any]) -> None:
        self.sequence += 1
        timestamp = time.time()
        record = {
            "sequence": self.sequence,
            "timestamp": timestamp,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
            "agent": agent,
            "event": event,
            **details,
        }
        self.store.append_jsonl("debug/agent-events.jsonl", record)
        messages = self._human_messages(agent, event, details)
        for message in messages:
            self.store.append_text(
                "debug/agent-trace.log",
                f"[{record['time']}] {message}\n",
            )
            if self.console:
                self.console(message)

    def _human_messages(
        self,
        agent: str,
        event: str,
        details: dict[str, Any],
    ) -> list[str]:
        if agent == "entry_verifier" and event == "candidate_started":
            candidate = _dict(details.get("candidate"))
            function = _dict(details.get("function"))
            candidate_id = str(candidate.get("candidate_id", "entry-candidate"))
            label = _entry_label(function, str(candidate.get("source_api", "input")))
            self._candidate_labels[candidate_id] = label
            return [f"[ENTRY START] {candidate_id} | {label}"]

        if agent == "entry_verifier" and event == "context_expanded":
            candidate_id = str(details.get("candidate_id", "entry-candidate"))
            label = self._candidate_labels.get(candidate_id, candidate_id)
            return self._walk_messages(
                stage="ENTRY",
                origin_id=candidate_id,
                origin_label=label,
                details=details,
            )

        if agent == "entry_verifier" and event == "final_verdict":
            candidate_id = str(details.get("candidate_id", "entry-candidate"))
            entry_id = str(details.get("entry_id", ""))
            function = _dict(details.get("function"))
            record = _dict(details.get("record"))
            label = self._candidate_labels.get(candidate_id) or _entry_label(
                function, str(record.get("source_api", "input"))
            )
            if entry_id:
                self._entry_labels[entry_id] = label
            verdict = str(details.get("final_status", "UNRESOLVED"))
            rationale = _short(str(record.get("rationale", "")))
            suffix = f" | {rationale}" if rationale else ""
            return [f"[ENTRY DONE] {candidate_id} | {label} -> {verdict}{suffix}"]

        if agent == "input_action" and event == "entry_started":
            entry_id = str(details.get("entry_id", "entry"))
            function = _dict(details.get("root_function"))
            label = str(function.get("name", entry_id))
            self._entry_labels[entry_id] = label
            return [f"[ACTION START] {entry_id} | {label}"]

        if agent == "input_action" and event == "function_opened":
            entry_id = str(details.get("entry_id", "entry"))
            function = _dict(details.get("function"))
            return [
                f"[ACTION OPEN] {entry_id} | "
                f"{function.get('name', function.get('function_id', 'function'))}"
            ]

        if agent == "input_action" and event == "return_path_navigation":
            return [f"[ACTION WALK] {_short(str(details.get('message', '')))}"]

        if agent == "input_action" and event == "callback_slot_navigation":
            return [f"[ACTION WALK] {_short(str(details.get('message', '')))}"]

        if agent == "input_action" and event == "branch_function_opened":
            entry_id = str(details.get("entry_id", "entry"))
            seed = str(details.get("operation_seed_id", "branch"))
            discriminator = _short(str(details.get("discriminator", "")), 60)
            function = _dict(details.get("function"))
            suffix = f" [{discriminator}]" if discriminator else ""
            return [
                f"[ACTION BRANCH] {entry_id} | {seed}{suffix} -> "
                f"{function.get('name', function.get('function_id', 'function'))}"
            ]

        if agent == "input_action" and event == "branch_completed":
            actions = _list(details.get("actions"))
            failure = _short(str(details.get("infrastructure_failure", "")))
            outcome = f"FAILED | {failure}" if failure else f"actions={len(actions)}"
            return [
                f"[ACTION DONE] {details.get('operation_seed_id', 'branch')} | {outcome}"
            ]

        if agent == "input_action" and event == "entry_completed":
            entry_id = str(details.get("entry_id", "entry"))
            actions = _list(details.get("actions"))
            return [f"[ACTION DONE] {entry_id} | actions={len(actions)}"]

        if agent == "state_dependency" and event == "function_opened":
            action_id = str(details.get("action_id", "action"))
            function = _dict(details.get("function"))
            return [
                f"[STATE OPEN] {action_id} | "
                f"{function.get('name', function.get('function_id', 'function'))}"
            ]

        if agent == "state_dependency" and event == "action_completed":
            contract = _dict(details.get("contract"))
            return [
                f"[STATE DONE] {details.get('action_id', 'action')} -> "
                f"{contract.get('status', 'POSSIBLE')}"
            ]

        if agent == "scenario_planner" and event == "completed":
            return [
                f"[SCENARIO PLAN] candidates={details.get('candidate_count', 0)} | "
                f"executable={details.get('executable_count', 0)}"
            ]

        if agent == "scenario_runtime" and event == "witness":
            return [
                f"[SCENARIO RUN] {details.get('scenario_id', 'scenario')} -> "
                f"{details.get('status', 'UNPROVEN')} | "
                f"steps={details.get('step_count', 0)}"
            ]

        if agent == "small_feature" and event == "entry_started":
            entry = _dict(details.get("entry"))
            function = _dict(details.get("root_function"))
            entry_id = str(entry.get("entry_id", "entry"))
            label = _entry_label(function, str(entry.get("source_api", "input")))
            self._entry_labels[entry_id] = label
            return [f"[SMALL START] {entry_id} | {label}"]

        if agent == "small_feature" and event == "context_walk":
            entry_id = str(details.get("entry_id", "entry"))
            label = self._entry_labels.get(entry_id, entry_id)
            return self._walk_messages(
                stage="SMALL",
                origin_id=entry_id,
                origin_label=label,
                details=details,
            )

        if agent == "small_feature" and event == "entry_resolution":
            entry_id = str(details.get("entry_id", "entry"))
            status = str(details.get("final_status", "UNRESOLVED"))
            resolution = _dict(details.get("resolution"))
            rationale = _short(str(resolution.get("rationale", "")))
            suffix = f" | {rationale}" if rationale else ""
            return [f"[ENTRY RECHECK] {entry_id} -> {status}{suffix}"]

        if agent == "orchestrator" and event == "small_feature_entry_resolution_completed":
            promoted = len(_list(details.get("promoted_entry_ids")))
            dropped = len(_list(details.get("dropped_entries")))
            return [
                f"[ENTRY FINALIZE] promoted={promoted}, dropped={dropped}"
            ]

        if agent == "orchestrator" and event == "backend_readiness_blocked":
            feature_id = str(details.get("small_feature_id", "small-feature"))
            name = str(details.get("name", feature_id))
            blockers = "; ".join(_strings(_list(details.get("blockers"))))
            suffix = f" | {_short(blockers)}" if blockers else ""
            return [f"[SMALL BLOCK] {feature_id} ({name}){suffix}"]

        if agent == "small_feature" and event == "feature_created":
            feature = _dict(details.get("feature"))
            feature_id = str(feature.get("small_feature_id", "small-feature"))
            name = str(feature.get("name", "unnamed feature"))
            description = _short(str(feature.get("description", "")))
            self._small_labels[feature_id] = name
            members = _strings([
                *_list(feature.get("root_entries")),
                *_list(feature.get("supporting_entries")),
            ])
            messages = [
                f"[SMALL MAP] {entry_id} ({self._entry_labels.get(entry_id, entry_id)}) -> "
                f"{feature_id} ({name})"
                for entry_id in members
            ]
            readiness = "READY" if bool(feature.get("planning_complete", False)) else "BLOCKED"
            suffix = f" | {description}" if description else ""
            messages.append(f"[SMALL DONE] {feature_id} ({name}) | {readiness}{suffix}")
            return messages

        if agent == "large_feature" and event == "feature_created":
            feature = _dict(details.get("feature"))
            feature_id = str(feature.get("large_feature_id", "large-feature"))
            name = str(feature.get("name", "unnamed feature"))
            description = _short(str(feature.get("description", "")))
            self._large_labels[feature_id] = name
            members = _strings(_list(feature.get("small_feature_ids")))
            messages = [
                f"[LARGE MAP] {small_id} ({self._small_labels.get(small_id, small_id)}) -> "
                f"{feature_id} ({name})"
                for small_id in members
            ]
            suffix = f" | {description}" if description else ""
            messages.append(f"[LARGE DONE] {feature_id} ({name}){suffix}")
            return messages

        if agent == "harness_generator" and event == "attempt_started":
            if details.get("scenario_id"):
                return [
                    f"[HARNESS START] scenario={details.get('scenario_id')} | "
                    f"attempt {details.get('attempt', '?')}"
                ]
            large = _dict(details.get("large_feature"))
            large_id = str(large.get("large_feature_id", "large-feature"))
            attempt = details.get("attempt", "?")
            return [
                f"[HARNESS START] {large_id} ({self._large_labels.get(large_id, large_id)}) "
                f"| attempt {attempt}"
            ]

        if agent == "harness_generator" and event == "context_function_opened":
            function = _dict(details.get("function"))
            name = str(function.get("name", function.get("function_id", "function")))
            large_id = str(
                details.get("scenario_id")
                or details.get("large_feature_id", "scenario")
            )
            parent = str(details.get("discovered_from_name", "") or "")
            if not parent:
                return [f"[HARNESS OPEN] {large_id} | {name}"]
            return [f"[HARNESS WALK] {large_id} | {parent} -> {name}"]

        if agent == "harness_generator" and event == "context_decision":
            blockers = _list(details.get("blockers"))
            if blockers:
                reason = str(blockers[0])
                return [
                    f"[HARNESS BLOCK] {details.get('scenario_id', 'scenario')} | "
                    f"{reason[:180]}"
                ]
            return [
                f"[HARNESS READY] {details.get('scenario_id', 'scenario')} | "
                "source generation can start"
            ]

        if agent == "harness_generator" and event == "draft_created":
            manifest = _dict(details.get("manifest"))
            if details.get("scenario_id"):
                return [
                    f"[HARNESS DONE] {manifest.get('harness_id', 'harness')} | "
                    f"scenario={details.get('scenario_id')}"
                ]
            return [
                f"[HARNESS DONE] {manifest.get('harness_id', 'harness')} | "
                f"large={details.get('large_feature_id', 'unknown')}"
            ]

        if agent == "static_harness_gate" and event == "decision":
            report = _dict(details.get("report"))
            failed = sum(
                str(_dict(item).get("status", "")) == "FAIL"
                for item in _list(report.get("checks"))
            )
            verdict = "PASS" if failed == 0 else f"FAIL({failed})"
            return [f"[STATIC GATE] {details.get('harness_id', 'harness')} -> {verdict}"]

        if agent == "harness_verifier" and event == "decision":
            verification = _dict(details.get("verification"))
            verdict = "QUALIFIED" if bool(verification.get("qualified", False)) else "FAILED"
            reason = _short(str(verification.get("reason", "")))
            suffix = f" | {reason}" if reason else ""
            return [f"[VERIFY] {details.get('harness_id', 'harness')} -> {verdict}{suffix}"]

        if agent == "harness_verifier" and event == "retry_routed":
            failure = _dict(details.get("failure"))
            return [
                f"[VERIFY ROUTE] {details.get('harness_id', 'harness')} | "
                f"{failure.get('kind', 'UNKNOWN')} -> "
                f"{failure.get('disposition', 'STOP')} | "
                f"repeat={details.get('repeat_count', 1)}"
            ]

        if agent == "entry_generator" and event == "completed":
            return [f"[ENTRY GENERATOR] {details.get('deduplicated_count', 0)} candidates"]

        if agent == "orchestrator" and event in {
            "verified_entries_selected", "run_completed"
        }:
            message = _short(str(details.get("message", "")))
            return [f"[WORKFLOW] {message}"] if message else []

        return []

    def _walk_messages(
        self,
        *,
        stage: str,
        origin_id: str,
        origin_label: str,
        details: dict[str, Any],
    ) -> list[str]:
        names = {
            str(item.get("function_id", "")): str(item.get("name", ""))
            for raw in _list(details.get("functions"))
            if (item := _dict(raw))
        }
        result: list[str] = []
        for raw in _list(details.get("walk")):
            item = _dict(raw)
            if str(item.get("relation", "")) in {"root", "retained_context"}:
                continue
            source_id = str(item.get("discovered_from", ""))
            target_id = str(item.get("function_id", ""))
            source = names.get(source_id, source_id or "?")
            target = str(item.get("name", "")) or names.get(target_id, target_id or "?")
            key = (stage, origin_id, source_id or source, target_id or target)
            if key in self._seen_moves:
                continue
            self._seen_moves.add(key)
            result.append(f"[{stage} WALK] {origin_id} ({origin_label}) | {source} -> {target}")
        return result


def emit_trace(
    callback: TraceCallback | None,
    agent: str,
    event: str,
    message: str,
    **details: Any,
) -> None:
    if callback:
        callback(agent, event, {"message": message, **details})


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value)
        if text and text not in result:
            result.append(text)
    return result


def _entry_label(function: dict[str, Any], source_api: str) -> str:
    name = str(function.get("name", "unknown_function"))
    return f"{name}::{source_api}"


def _short(value: str, limit: int = 180) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."
