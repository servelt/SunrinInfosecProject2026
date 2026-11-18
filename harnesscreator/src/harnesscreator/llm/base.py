from __future__ import annotations

import asyncio
from collections import deque
import hashlib
import json
import re
import time
from typing import Any, Callable, Protocol
from pathlib import Path


class InvalidOutputSchemaError(RuntimeError):
    """The requested structured-output schema cannot be sent to Codex.

    Codex structured outputs use the strict JSON-Schema subset: object fields
    must be closed and every declared property must be required. Free-form
    object maps must be encoded as fixed-shape key/value records instead.
    """


def _exception_text(exc: BaseException) -> str:
    """Return the complete, cycle-safe exception chain as normalized text."""

    parts: list[str] = []
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        parts.append(f"{type(current).__name__}: {current}".casefold())
        current = current.__cause__ or current.__context__
    return "\n".join(parts)


def is_terminal_llm_infrastructure_error(exc: BaseException) -> bool:
    """Return whether retrying another work item cannot repair the failure.

    Schema rejection and account/billing limits apply to every Entry, Action,
    or Harness that shares the provider.  Treating either as item-local caused
    historical runs to spend one failed model call per queued branch/plan.
    """

    if isinstance(exc, InvalidOutputSchemaError):
        return True
    message = _exception_text(exc)
    return any(marker in message for marker in (
        "invalid_json_schema",
        "invalid_request_error",
        "authentication_error",
        "http 400",
        "status 400",
        "status': 400",
        'status": 400',
        "usage limit",
        "purchase more credits",
        "insufficient_quota",
        "billing_hard_limit_reached",
        "exceeded your current quota",
    ))


def is_transient_llm_transport_error(exc: BaseException) -> bool:
    """Return whether an exception represents a shared transient transport loss."""

    message = _exception_text(exc)
    return any(marker in message for marker in (
        "reconnecting",
        "connection reset",
        "connection refused",
        "broken pipe",
        "server disconnected",
    ))


def validate_strict_output_schema(schema: dict[str, Any]) -> None:
    """Reject unsupported structured-output schemas before an LLM turn starts."""

    if not isinstance(schema, dict):
        raise InvalidOutputSchemaError("output schema root must be an object")

    def visit(node: Any, path: str) -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]")
            return
        if not isinstance(node, dict):
            return

        declared_type = node.get("type")
        is_object = declared_type == "object" or (
            isinstance(declared_type, list) and "object" in declared_type
        )
        if is_object:
            additional = node.get("additionalProperties")
            if isinstance(additional, dict):
                raise InvalidOutputSchemaError(
                    f"{path}: schema-valued additionalProperties is unsupported; "
                    "use an array of fixed-shape key/value objects"
                )
            properties = node.get("properties")
            if properties is not None and not isinstance(properties, dict):
                raise InvalidOutputSchemaError(f"{path}.properties must be an object")
            if properties:
                if additional is not False:
                    raise InvalidOutputSchemaError(
                        f"{path}: object schemas with properties must set "
                        "additionalProperties=false"
                    )
                required = node.get("required")
                if not isinstance(required, list):
                    raise InvalidOutputSchemaError(
                        f"{path}: required must list every declared property"
                    )
                property_names = set(properties)
                required_names = {
                    value for value in required if isinstance(value, str)
                }
                missing = sorted(property_names - required_names)
                extra = sorted(required_names - property_names)
                if missing or extra or len(required_names) != len(required):
                    raise InvalidOutputSchemaError(
                        f"{path}: required/properties mismatch "
                        f"(missing={missing}, extra={extra})"
                    )

        for key, value in node.items():
            if key in {"properties", "$defs", "definitions"} and isinstance(value, dict):
                for name, child in value.items():
                    visit(child, f"{path}.{key}.{name}")
            elif key in {
                "items", "additionalProperties", "anyOf", "oneOf", "allOf", "not",
            }:
                visit(value, f"{path}.{key}")

    visit(schema, "$")


class LLMProvider(Protocol):
    async def complete_json(
        self,
        *,
        role: str,
        instructions: str,
        payload: dict[str, Any],
        output_schema: dict[str, Any],
        session_key: str | None = None,
    ) -> dict[str, Any]: ...

    async def close_session(self, session_key: str) -> None: ...

    async def close(self) -> None: ...


class ScriptedLLM:
    """Deterministic provider used by unit and integration tests."""

    def __init__(self, responses: list[dict[str, Any]]):
        self.max_concurrency = 1
        self.responses = deque(responses)
        self.calls: list[dict[str, Any]] = []

    async def complete_json(
        self,
        *,
        role: str,
        instructions: str,
        payload: dict[str, Any],
        output_schema: dict[str, Any],
        session_key: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append({
            "role": role,
            "instructions": instructions,
            "payload": payload,
            "session_key": session_key,
        })
        if not self.responses:
            raise RuntimeError(f"no scripted response left for {role}")
        return self.responses.popleft()

    async def close_session(self, session_key: str) -> None:
        return None

    async def close(self) -> None:
        return None


_REPLAY_ROLES = frozenset({"entry_generator", "entry_verifier"})


def _replay_key(role: str, model: Any, instructions: str, input_sha256: str) -> str:
    return hashlib.sha256(json.dumps([role, model, instructions, input_sha256]).encode()).hexdigest()


def _entry_replay_hash(payload: dict[str, Any]) -> str:
    """Hash source evidence without Clang's process-local declaration addresses."""
    canonical = json.dumps(
        _canonical_call_value(payload), ensure_ascii=False, sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _load_replay() -> tuple[dict[str, dict[str, Any]], dict[str, list[tuple[str, dict[str, Any]]]]]:
    """Completed Entry answers of earlier runs (HARNESSCREATOR_LLM_REPLAY: llm.jsonl paths, ':'-separated).

    A run that stopped (time cap, usage limit, a crash) loses every Entry answer it paid for.  The
    same question - same role, model, instructions and byte-identical payload, i.e. the same source -
    gets the same answer here instead of a new model call.  Only the stateless Entry roles are
    replayed; conversational roles depend on their session and are always asked again.
    """
    import os
    table: dict[str, dict[str, Any]] = {}
    # Conversational (session) calls: replayed only for a session that reached its close marker, turn
    # by turn in the recorded order, so a replayed turn never answers a question asked in a different
    # conversation state.
    sessions: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for path in filter(None, os.environ.get("HARNESSCREATOR_LLM_REPLAY", "").split(":")):
        try:
            handle = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            turns: dict[str, list[tuple[str, dict[str, Any]]]] = {}
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                key_s = row.get("session_key")
                if row.get("status") == "session_closed" and key_s in turns:
                    if key_s not in sessions:
                        sessions[key_s] = turns.pop(key_s)
                    continue
                if row.get("role") not in _REPLAY_ROLES:
                    continue
                if row.get("status") != "completed" or not isinstance(row.get("response"), dict):
                    if key_s:
                        turns[key_s] = [("", {})]    # a failed turn: this conversation is not replayable
                    continue
                payload = row.get("payload")
                input_hash = (
                    _entry_replay_hash(payload) if isinstance(payload, dict)
                    else row.get("input_sha256", "")
                )
                key = _replay_key(row["role"], row.get("model"), row.get("instructions", ""),
                                  input_hash)
                if key_s:
                    turns.setdefault(key_s, []).append((key, row["response"]))
                else:
                    table[key] = row["response"]
    return table, sessions


class RecordingLLM:
    """Emit completed audit records without retaining large prompts in memory."""

    def __init__(
        self,
        delegate: LLMProvider,
        on_record: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.delegate = delegate
        self.max_concurrency = getattr(delegate, "max_concurrency", 1)
        self.on_record = on_record
        self.completed_count = 0
        self.replay, self.replay_sessions = _load_replay()
        self.replay_turn: dict[str, int] = {}      # session -> next recorded turn; -1 = went live
        self.replayed = 0

    async def complete_json(
        self,
        *,
        role: str,
        instructions: str,
        payload: dict[str, Any],
        output_schema: dict[str, Any],
        session_key: str | None = None,
    ) -> dict[str, Any]:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        started = time.time()
        record: dict[str, Any] = {
            "role": role,
            "started_at": started,
            "input_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "instructions": instructions,
            "payload": payload,
            "output_schema": output_schema,
            "session_key": session_key,
        }
        resolver = getattr(self.delegate, "model_for_role", None)
        if callable(resolver):
            record["model"] = resolver(role)
        effort_resolver = getattr(self.delegate, "effort_for_role", None)
        effort = effort_resolver(role) if callable(effort_resolver) else getattr(self.delegate, "effort", None)
        record["reasoning_effort"] = effort
        replay_hash = (
            _entry_replay_hash(payload) if role in _REPLAY_ROLES
            else record["input_sha256"]
        )
        key = _replay_key(role, record.get("model"), instructions, replay_hash)
        # Only stateless questions are replayed.  A conversational call (session_key) depends on the
        # turns before it; replaying some turns and asking the rest live left the model without the
        # replayed context, so conversations are always asked again.
        response = self.replay.get(key) if role in _REPLAY_ROLES and not session_key else None
        if response is not None:
            record.update(response=response, status="completed", replayed=True,
                          duration_seconds=0.0)
            self.replayed += 1
            if self.on_record:
                self.on_record(record)
            return response
        try:
            response = await self.delegate.complete_json(
                role=role,
                instructions=instructions,
                payload=payload,
                output_schema=output_schema,
                session_key=session_key,
            )
            record["response"] = response
            record["status"] = "completed"
            return response
        except asyncio.CancelledError as exc:
            record["status"] = "cancelled"
            record["error"] = f"{type(exc).__name__}: concurrent workflow cancelled this call"
            raise
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            record["duration_seconds"] = time.time() - started
            self.completed_count += 1
            if self.on_record:
                self.on_record(record)

    async def close_session(self, session_key: str) -> None:
        closer = getattr(self.delegate, "close_session", None)
        if callable(closer):
            await closer(session_key)
        if self.on_record:
            # A completed response prefix is unsafe to resume unless the
            # logical agent session itself reached its close boundary. This
            # marker lets future runs distinguish a finished context walk from
            # a VM/process crash that left only a replayable-looking prefix.
            now = time.time()
            self.on_record({
                "record_type": "session_closed",
                "session_key": session_key,
                "status": "session_closed",
                "started_at": now,
                "duration_seconds": 0.0,
            })

    async def close(self) -> None:
        await self.delegate.close()


class CachingLLM:
    """Replays exact completed calls from an earlier trajectory before delegating.

    Stateful calls are reusable only as an exact, ordered whole-session
    prefix.  If the first call differs, that session is delegated live from
    the beginning.  If a later call differs after replay has begun, the
    already-replayed requests are submitted to a live thread to restore its
    source history, then the divergent current turn continues live.  This
    keeps resume safe when deterministic filtering changes between runs.
    """

    def __init__(
        self,
        delegate: LLMProvider,
        trajectory: Path,
        on_event: Callable[[str], None] | None = None,
    ):
        self.delegate = delegate
        self.on_event = on_event
        self.max_concurrency = getattr(delegate, "max_concurrency", 1)
        self.model = getattr(delegate, "model", None)
        self.role_models = dict(getattr(delegate, "role_models", {}))
        self.role_efforts = dict(getattr(delegate, "role_efforts", {}))
        self.supports_context_compaction = getattr(delegate, "supports_context_compaction", True)
        self.effort = getattr(delegate, "effort", None)
        self.trajectory = trajectory
        self._responses: dict[str, dict[str, Any]] = {}
        loaded_stateful_responses: dict[
            str, deque[tuple[str, dict[str, Any]]]
        ] = {}
        closed_stateful_sessions: set[str] = set()
        checkpointed_stateful_sessions: set[str] = set()
        has_session_close_markers = False
        self._stateful_modes: dict[str, str] = {}
        self._replayed_calls: dict[str, list[dict[str, Any]]] = {}
        with trajectory.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # A machine/VM crash can interrupt the final append. Earlier
                    # complete records remain safe and are still reusable.
                    if not line.endswith("\n"):
                        break
                    raise ValueError(
                        f"invalid JSONL record at {trajectory}:{line_number}"
                    )
                if record.get("record_type") == "session_closed":
                    has_session_close_markers = True
                    marker_session = record.get("session_key")
                    if marker_session is not None:
                        closed_stateful_sessions.add(str(marker_session))
                    continue
                if record.get("status") != "completed" or not isinstance(record.get("response"), dict):
                    continue
                record_role = str(record.get("role", ""))
                expected_model = self.model_for_role(record_role)
                if expected_model is not None and record.get("model") != expected_model:
                    # A resume must not silently replay an answer produced by a
                    # different model than the one fixed for this role.
                    continue
                effort_resolver = getattr(self.delegate, "effort_for_role", None)
                expected_effort = effort_resolver(record_role) if callable(effort_resolver) else self.effort
                if record.get("reasoning_effort") != expected_effort:
                    continue
                key = _call_key(
                    role=record_role,
                    instructions=str(record.get("instructions", "")),
                    payload=record.get("payload", {}),
                    output_schema=record.get("output_schema", {}),
                    session_key=record.get("session_key"),
                )
                session_key = record.get("session_key")
                if session_key is None:
                    self._responses[key] = record["response"]
                else:
                    loaded_stateful_responses.setdefault(
                        str(session_key), deque()
                    ).append((key, record["response"]))
                    if _is_self_contained_stateful_checkpoint(
                        record_role,
                        record.get("payload", {}),
                    ):
                        # A completed Harness generation checkpoint contains
                        # the cumulative opened sources. Its exact discovery
                        # prefix can be replayed safely after interruption; a
                        # later mismatch resumes from that self-contained turn.
                        checkpointed_stateful_sessions.add(str(session_key))
        if not has_session_close_markers:
            # Trajectories written before explicit close markers still have a
            # durable agent trace.  Recover only sessions whose terminal event
            # was flushed.  This is especially important after WSL/VM loss: a
            # completed Entry/Small walk remains reusable, while the prefix of
            # an in-flight walk must start live instead of replaying into a
            # thread that never saw its earlier source.
            inferred_closed = _infer_legacy_closed_sessions(
                trajectory,
                set(loaded_stateful_responses),
            )
            if inferred_closed:
                has_session_close_markers = True
                closed_stateful_sessions.update(inferred_closed)
        self._stateful_responses = (
            {
                session_key: responses
                for session_key, responses in loaded_stateful_responses.items()
                if session_key in closed_stateful_sessions
                or session_key in checkpointed_stateful_sessions
            }
            if has_session_close_markers
            else loaded_stateful_responses
        )
        self.hits = 0
        self.misses = 0
        self.rehydrations = 0
        self.rehydrated_calls = 0
        self.checkpoint_resumes = 0
        self.cached_calls = len(self._responses) + sum(
            len(items) for items in self._stateful_responses.values()
        )

    def model_for_role(self, role: str) -> str | None:
        resolver = getattr(self.delegate, "model_for_role", None)
        if callable(resolver):
            return resolver(role)
        return self.role_models.get(role, self.model)

    def effort_for_role(self, role: str) -> str | None:
        resolver = getattr(self.delegate, "effort_for_role", None)
        return resolver(role) if callable(resolver) else self.effort

    async def complete_json(
        self,
        *,
        role: str,
        instructions: str,
        payload: dict[str, Any],
        output_schema: dict[str, Any],
        session_key: str | None = None,
    ) -> dict[str, Any]:
        if session_key is not None:
            key = _call_key(
                role, instructions, payload, output_schema, session_key
            )
            mode = self._stateful_modes.get(session_key)
            queued = self._stateful_responses.get(session_key)
            if mode is None:
                if queued and queued[0][0] == key:
                    mode = "replay"
                else:
                    mode = "live"
                self._stateful_modes[session_key] = mode
            if mode == "replay":
                if not queued or queued[0][0] != key:
                    # Cached answers have already advanced the deterministic
                    # agent state, but the delegate has no thread history.
                    # Re-submit the exact earlier requests first. Their fresh
                    # answers are intentionally ignored: the current payload
                    # already carries the cached agent state, while the live
                    # thread needs the prior source turns for reasoning.
                    history = self._replayed_calls.pop(session_key, [])
                    self._stateful_modes[session_key] = "live"
                    self._stateful_responses.pop(session_key, None)
                    delegated_payload = payload
                    checkpoint = _is_self_contained_stateful_checkpoint(
                        role, delegated_payload
                    )
                    synthesized_checkpoint = False
                    if role == "input_action" and not checkpoint:
                        delegated_payload = _synthesize_input_action_checkpoint(
                            history, payload,
                        )
                        checkpoint = _is_self_contained_stateful_checkpoint(
                            role, delegated_payload,
                        )
                        synthesized_checkpoint = checkpoint
                    if role == "small_feature" and not checkpoint:
                        # Small Feature walks may contain dozens of large source
                        # turns. Replaying those turns into a new app-server
                        # thread is both unnecessary and catastrophically slow:
                        # the server can compact repeatedly before it ever
                        # reaches the divergent turn. Build one self-contained
                        # continuation from the exact cached requests/responses
                        # instead. This is semantically equivalent to the
                        # explicit checkpoints emitted by SmallFeatureAgent:
                        # current client state remains authoritative, while the
                        # model receives every active source body and a compact
                        # inventory of prior operation proposals.
                        delegated_payload = _synthesize_small_feature_checkpoint(
                            history,
                            payload,
                        )
                        checkpoint = _is_self_contained_stateful_checkpoint(
                            role, delegated_payload
                        )
                        synthesized_checkpoint = checkpoint
                    if self.on_event:
                        small_checkpoint = delegated_payload.get(
                            "stateful_resume_checkpoint"
                        )
                        checkpoint_functions = (
                            small_checkpoint.get("functions", [])
                            if isinstance(small_checkpoint, dict)
                            else []
                        )
                        self.on_event(
                            "stateful resume divergence: "
                            f"session={session_key}, role={role}, "
                            f"round={payload.get('context_round', 'n/a')}, "
                            f"replayed_prefix={len(history)}, "
                            f"checkpoint_present={isinstance(small_checkpoint, dict)}, "
                            f"checkpoint_functions={len(checkpoint_functions)}, "
                            f"checkpoint_accepted={checkpoint}, "
                            f"checkpoint_synthesized={synthesized_checkpoint}"
                        )
                    # Harness generation is a deliberate self-contained
                    # checkpoint: after sequential discovery completes, its
                    # payload carries every opened source body plus the final
                    # lifecycle/build facts.  On resume, starting this turn on
                    # a fresh thread is equivalent to replaying dozens of
                    # discovery turns and avoids paying that model cost again.
                    # Earlier discovery turns are not self-contained and still
                    # take the conservative live-rehydration path below.
                    if checkpoint:
                        self.checkpoint_resumes += 1
                        self.misses += 1
                        live_instructions = instructions
                        if role == "input_action":
                            live_instructions += (
                                "\nThis is a resumed model thread. Read the full "
                                "source bodies in stateful_resume_checkpoint.functions "
                                "as the previously opened context. "
                                "prior_action_drafts are unverified earlier claims; "
                                "recheck them against the opened source."
                            )
                        return await self.delegate.complete_json(
                            role=role,
                            instructions=live_instructions,
                            payload=delegated_payload,
                            output_schema=output_schema,
                            session_key=session_key,
                        )
                    if role in {"small_feature", "input_action"}:
                        raise RuntimeError(
                            f"cannot safely resume {role} session after a "
                            "late cache divergence: no complete source checkpoint "
                            f"could be constructed for {session_key}. Refusing to "
                            "silently replay the entire model history."
                        )
                    self.rehydrations += 1
                    for previous in history:
                        await self.delegate.complete_json(**{
                            key: value for key, value in previous.items()
                            if key != "cached_response"
                        })
                    self.rehydrated_calls += len(history)
                    self.misses += len(history) + 1
                    return await self.delegate.complete_json(
                        role=role,
                        instructions=instructions,
                        payload=payload,
                        output_schema=output_schema,
                        session_key=session_key,
                    )
                _, cached = queued.popleft()
                self.hits += 1
                self._replayed_calls.setdefault(session_key, []).append({
                    "role": role,
                    "instructions": instructions,
                    "payload": json.loads(json.dumps(payload)),
                    "output_schema": json.loads(json.dumps(output_schema)),
                    "session_key": session_key,
                    "cached_response": json.loads(json.dumps(cached)),
                })
                return json.loads(json.dumps(cached))
            self.misses += 1
            return await self.delegate.complete_json(
                role=role,
                instructions=instructions,
                payload=payload,
                output_schema=output_schema,
                session_key=session_key,
            )
        key = _call_key(role, instructions, payload, output_schema, session_key)
        one_shot_cached = self._responses.get(key)
        if one_shot_cached is not None:
            self.hits += 1
            # Round-trip copy prevents a caller from mutating the cache.
            return json.loads(json.dumps(one_shot_cached))
        self.misses += 1
        return await self.delegate.complete_json(
            role=role,
            instructions=instructions,
            payload=payload,
            output_schema=output_schema,
            session_key=session_key,
        )
    async def close_session(self, session_key: str) -> None:
        mode = self._stateful_modes.pop(session_key, None)
        self._stateful_responses.pop(session_key, None)
        self._replayed_calls.pop(session_key, None)
        if mode == "replay":
            return
        closer = getattr(self.delegate, "close_session", None)
        if callable(closer):
            await closer(session_key)

    async def close(self) -> None:
        await self.delegate.close()


def _is_self_contained_stateful_checkpoint(
    role: str,
    payload: dict[str, Any],
) -> bool:
    """Return whether a divergent turn contains the full prior source state."""

    if role == "harness_generator":
        discovery = payload.get("sequential_context_discovery")
        functions = payload.get("functions")
        legacy_checkpoint = bool(
            isinstance(discovery, dict)
            and discovery.get("context_complete") is True
            and discovery.get("generation_blocked") is not True
            and _complete_source_checkpoint(functions)
        )
        scenario_discovery = payload.get("context_discovery")
        scenario_functions = payload.get("opened_functions")
        return legacy_checkpoint or bool(
            isinstance(scenario_discovery, dict)
            and scenario_discovery.get("context_complete") is True
            and not scenario_discovery.get("blocking_dependencies")
            and _complete_source_checkpoint(scenario_functions)
        )
    if role == "small_feature":
        checkpoint = payload.get("stateful_resume_checkpoint")
        return bool(
            isinstance(checkpoint, dict)
            and checkpoint.get("complete") is True
            and _complete_source_checkpoint(checkpoint.get("functions"))
        )
    if role == "input_action":
        checkpoint = payload.get("stateful_resume_checkpoint")
        return bool(
            isinstance(checkpoint, dict)
            and checkpoint.get("complete") is True
            and _complete_source_checkpoint(checkpoint.get("functions"))
        )
    return False


def _complete_source_checkpoint(functions: Any) -> bool:
    return bool(
        isinstance(functions, list)
        and functions
        and all(
            isinstance(item, dict)
            and str(item.get("function_id", "")).strip()
            and str(item.get("source", "")).strip()
            # A bounded excerpt is useful during an uninterrupted stateful
            # walk, but it is not a self-contained replacement for that
            # history.  Treating it as complete allowed a resumed generator
            # to forget omitted initialization/callback code silently.
            and item.get("source_truncated", False) is not True
            for item in functions
        )
    )


def _synthesize_input_action_checkpoint(
    history: list[dict[str, Any]],
    current_payload: dict[str, Any],
) -> dict[str, Any]:
    """Restore all opened Action source bodies in one live model turn.

    The cache replays only an exact prefix. At its first new source read the
    delegate has no thread history, so source references alone are unsafe.
    The checkpoint is rejected unless every opened ID has a complete body.
    """
    resumed = json.loads(json.dumps(current_payload))
    by_id: dict[str, dict[str, Any]] = {}
    latest_actions: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for previous in history:
        previous_payload = previous.get("payload", {})
        function = previous_payload.get("current_function")
        if isinstance(function, dict) and function.get("function_id"):
            by_id[str(function["function_id"])] = function
        response = previous.get("cached_response", {})
        if isinstance(response, dict):
            actions = response.get("actions", [])
            if isinstance(actions, list):
                for item in actions:
                    if not isinstance(item, dict):
                        continue
                    identity = tuple(
                        str(item.get(field) or "").strip().casefold()
                        for field in (
                            "name", "dispatcher_function_id",
                            "handler_function_id", "discriminator",
                        )
                    )
                    latest_actions[identity] = item
    current_function = current_payload.get("current_function")
    if isinstance(current_function, dict) and current_function.get("function_id"):
        by_id[str(current_function["function_id"])] = current_function
    opened_ids = [
        str(item.get("function_id", ""))
        for item in current_payload.get("opened_functions", [])
        if isinstance(item, dict) and item.get("function_id")
    ]
    functions = [by_id[function_id] for function_id in opened_ids
                 if function_id in by_id]
    resumed["stateful_resume_checkpoint"] = {
        "complete": bool(opened_ids) and len(functions) == len(opened_ids),
        "resume_mode": "synthesized_from_exact_cached_prefix",
        "functions": functions,
        "prior_action_drafts": list(latest_actions.values()),
        "warning": (
            "Source bodies and prior drafts are context, not proof of the "
            "Entry-to-handler path or runtime execution."
        ),
    }
    return resumed


def _synthesize_small_feature_checkpoint(
    history: list[dict[str, Any]],
    current_payload: dict[str, Any],
) -> dict[str, Any]:
    """Collapse an exact cached Small Feature prefix into one live turn.

    The deterministic agent, rather than the model thread, owns the canonical
    proposal inventory and context selection.  A resumed model therefore needs
    only the source bodies in the current active window plus a compact reminder
    of operations returned by the cached prefix.  Keeping this conversion in
    the cache layer avoids changing cache keys for normal uninterrupted runs.
    """

    resumed = json.loads(json.dumps(current_payload))
    source_by_id: dict[str, dict[str, Any]] = {}
    retained_by_key: dict[str, dict[str, Any]] = {}

    def retain_source(item: Any) -> None:
        if not isinstance(item, dict):
            return
        function_id = str(item.get("function_id", "")).strip()
        source = str(item.get("source", "")).strip()
        if function_id and source:
            source_by_id[function_id] = json.loads(json.dumps(item))

    def retain_operation(item: Any) -> None:
        if not isinstance(item, dict):
            return
        name = str(item.get("name", "")).strip()
        if not name:
            return
        actions = item.get("actions", [])
        action_functions = item.get("action_functions", [])
        if isinstance(actions, list):
            action_functions = [
                str(action.get("function_id", ""))
                for action in actions
                if isinstance(action, dict)
                and str(action.get("function_id", "")).strip()
            ]
        compact = {
            "name": name,
            "root_entries": item.get("root_entries", []),
            "supporting_entries": item.get("supporting_entries", []),
            "harness_anchor": item.get("harness_anchor", ""),
            "action_functions": action_functions,
            "completion_oracle": item.get("completion_oracle", ""),
            "stable_post_state": item.get("stable_post_state", ""),
            "planning_complete": item.get("planning_complete", False),
            "planning_blockers": item.get("planning_blockers", []),
        }
        operation_key = json.dumps(
            {
                "name": " ".join(name.casefold().split()),
                "roots": compact["root_entries"],
                "supporting": compact["supporting_entries"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        retained_by_key[operation_key] = compact

    def absorb_payload(item: Any) -> None:
        if not isinstance(item, dict):
            return
        for function in item.get("context", []):
            retain_source(function)
        checkpoint = item.get("stateful_resume_checkpoint")
        if isinstance(checkpoint, dict):
            for function in checkpoint.get("functions", []):
                retain_source(function)
            for operation in checkpoint.get("retained_operations", []):
                retain_operation(operation)

    for previous in history:
        absorb_payload(previous.get("payload"))
        response = previous.get("cached_response")
        if isinstance(response, dict):
            for operation in response.get("small_features", []):
                retain_operation(operation)
    absorb_payload(current_payload)

    active_ids = [
        str(item.get("function_id", ""))
        for item in current_payload.get("opened_context_functions", [])
        if isinstance(item, dict) and str(item.get("function_id", "")).strip()
    ]
    for function in current_payload.get("context", []):
        if isinstance(function, dict):
            function_id = str(function.get("function_id", "")).strip()
            if function_id and function_id not in active_ids:
                active_ids.append(function_id)
    functions = [
        source_by_id[function_id]
        for function_id in active_ids
        if function_id in source_by_id
    ]
    if not functions:
        functions = list(source_by_id.values())

    existing_checkpoint = resumed.get("stateful_resume_checkpoint")
    metadata_only = (
        existing_checkpoint.get("metadata_only_functions", [])
        if isinstance(existing_checkpoint, dict)
        else []
    )
    resumed["stateful_resume_checkpoint"] = {
        "complete": bool(functions),
        "resume_mode": "synthesized_from_exact_cached_prefix",
        "functions": functions,
        "retained_operations": list(retained_by_key.values()),
        **(
            {"metadata_only_functions": metadata_only}
            if metadata_only else {}
        ),
    }
    return resumed


async def close_llm_session(llm: LLMProvider, session_key: str) -> None:
    """Release a logical agent thread without requiring every test double to implement it."""

    closer = getattr(llm, "close_session", None)
    if callable(closer):
        await closer(session_key)


def _call_key(
    role: str,
    instructions: str,
    payload: dict[str, Any],
    output_schema: dict[str, Any],
    session_key: str | None = None,
) -> str:
    canonical = json.dumps(
        {
            "role": role,
            "instructions": instructions,
            # These metadata lists are mathematical sets and can be emitted in
            # a different order by hash-backed analysis merges in another
            # process. Canonicalize only known set-valued fields. Ordered
            # semantic fields such as actions and entry_call_order are kept.
            "payload": _canonical_call_value(payload),
            "output_schema": output_schema,
            "session_key": session_key,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _infer_legacy_closed_sessions(
    trajectory: Path,
    known_sessions: set[str],
) -> set[str]:
    """Infer safe legacy session boundaries from sibling run artifacts."""

    try:
        run_root = trajectory.parent.parent
    except IndexError:
        return set()
    if (run_root / "summary.json").is_file():
        # A summary is written only after the orchestrator has crossed every
        # agent lifetime boundary in that run.
        return set(known_sessions)
    trace = run_root / "debug" / "agent-events.jsonl"
    if not trace.is_file():
        return set()
    inferred: set[str] = set()
    large_completed = False
    try:
        with trace.open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # A crash may cut the final trace append. Terminal events
                    # before that line are still authoritative.
                    continue
                agent = str(event.get("agent", ""))
                kind = str(event.get("event", ""))
                if agent == "entry_verifier" and kind == "final_verdict":
                    candidate_id = str(event.get("candidate_id", ""))
                    if candidate_id:
                        inferred.add(f"entry_verifier:{candidate_id}")
                elif agent == "small_feature" and kind == "entry_enumerated":
                    entry_id = str(event.get("entry_id", ""))
                    if entry_id:
                        inferred.add(f"small_feature:{entry_id}")
                elif agent == "input_action" and kind == "entry_completed":
                    entry_id = str(event.get("entry_id", ""))
                    if entry_id:
                        inferred.add(f"input_action:{entry_id}")
                elif agent == "state_dependency" and kind == "action_completed":
                    action_id = str(event.get("action_id", ""))
                    if action_id:
                        inferred.add(f"state_dependency:{action_id}")
                elif agent == "large_feature" and kind == "completed":
                    large_completed = True
    except OSError:
        return set()
    if large_completed:
        inferred.update(
            session for session in known_sessions
            if session.startswith("large_feature:")
        )
    return inferred & known_sessions


_ORDER_INSENSITIVE_CALL_FIELDS = {
    "build_targets",
    "callees",
    "callers",
    "external_calls",
    "headers",
    "inspected_function_ids",
    "providers",
}

_VOLATILE_CLANG_ID_FIELDS = {
    "direct_argument_declaration_ids",
    "direct_argument_addressed_scalar_declaration_ids",
    "field_declaration_id",
    "receiver_declaration_id",
}


def _canonical_call_value(
    value: Any, parent_key: str | None = None,
    ast_ids: dict[str, int] | None = None,
) -> Any:
    if ast_ids is None:
        ast_ids = {}
    if isinstance(value, dict):
        return {
            key: _canonical_call_value(value[key], str(key), ast_ids)
            for key in sorted(value)
        }
    if isinstance(value, list):
        normalized = [_canonical_call_value(child, parent_key, ast_ids) for child in value]
        if parent_key in _ORDER_INSENSITIVE_CALL_FIELDS:
            return sorted(
                normalized,
                key=lambda child: json.dumps(
                    child,
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        return normalized
    if (parent_key in _VOLATILE_CLANG_ID_FIELDS and isinstance(value, str)
            and re.fullmatch(r"0x[0-9a-fA-F]+", value)):
        return f"@clang_decl:{ast_ids.setdefault(value, len(ast_ids))}"
    return value
