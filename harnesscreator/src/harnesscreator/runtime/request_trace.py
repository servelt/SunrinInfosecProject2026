"""Request-correlated observations from a *cooperatively instrumented* binary.

This is a small data contract, not a binary instrumentation engine. The original
program (or a compiler-instrumented build) must emit acquisition and target
processing events from the real source locations. A GDB breakpoint order alone
cannot establish request attribution. Data in the journal is trusted only as
runtime evidence from the configured local test build, not as protection against
an adversarial program deliberately forging diagnostic output.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RequestTraceObservation:
    entry_reached: bool
    target_reached: bool
    trace: tuple[str, ...]
    problem: str = ""
    # An append-only trace may still receive events after the network reply.
    # Only a missing event (or an unfinished final JSONL row) is retryable;
    # malformed or contradictory completed evidence is terminal.
    pending: bool = False


def response_attested(trace: list[str] | tuple[str, ...], response: bytes) -> bool:
    """Whether the same request's result event matches the captured response."""
    return f"semantic-response:{hashlib.sha256(response).hexdigest()}" in trace


def response_hex_attested(trace: list[str] | tuple[str, ...], response_hex: str) -> bool:
    """Reject malformed stored observations without crashing an audit."""
    try:
        return response_attested(trace, bytes.fromhex(response_hex))
    except (TypeError, ValueError):
        return False


def exact_acquisitions(
    events: list[dict], request: bytes, entry_function_id: str,
) -> list[tuple[str, dict, int]]:
    """Identify complete one-shot or fragment-backed acquisitions of ``request``.

    The caller decides whether one match (one original request window) or
    several matches (separate libFuzzer invocations) are expected.
    """
    expected_digest = hashlib.sha256(request).hexdigest()
    acquisitions_by_id: dict[str, list[tuple[int, dict]]] = {}
    for index, event in enumerate(events):
        if event.get("event") not in ("acquire", "acquire_fragment"):
            continue
        request_id = event.get("request_id")
        if isinstance(request_id, str) and request_id:
            acquisitions_by_id.setdefault(request_id, []).append((index, event))
    matching: list[tuple[str, dict, int]] = []
    for request_id, acquisitions in acquisitions_by_id.items():
        if any(event.get("entry_function_id") != entry_function_id
               for _, event in acquisitions):
            continue
        kinds = {event["event"] for _, event in acquisitions}
        if kinds == {"acquire"}:
            if len(acquisitions) != 1:
                continue
            final_index, entry = acquisitions[0]
            if entry.get("request_sha256") == expected_digest:
                matching.append((request_id, entry, final_index))
            continue
        if kinds != {"acquire_fragment"}:
            # A complete acquisition and fragment stream with the same ID
            # cannot independently identify one logical request.
            continue
        expected_offset = 0
        chunks: list[bytes] = []
        valid = True
        for _, fragment in acquisitions:
            offset_value = fragment.get("offset")
            raw_hex = fragment.get("data_hex")
            supplied_digest = fragment.get("request_sha256")
            if (type(offset_value) is not int or offset_value != expected_offset
                or not isinstance(raw_hex, str)
                or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", raw_hex)
                or (supplied_digest is not None
                    and supplied_digest != expected_digest)):
                valid = False
                break
            chunk = bytes.fromhex(raw_hex)
            chunks.append(chunk)
            expected_offset += len(chunk)
            if expected_offset > len(request):
                valid = False
                break
        if valid and b"".join(chunks) == request:
            matching.append((request_id, acquisitions[0][1], acquisitions[-1][0]))
    return matching


class RequestTraceJournal:
    """Bounded, monotonic consumption of a JSONL event file.

    Each event must identify a single request with a unique ``request_id``.
    A one-shot ``acquire`` event carries the SHA-256 of all request bytes.
    A request assembled by several reads may instead emit ordered
    ``acquire_fragment`` events with exact ``data_hex`` and contiguous byte
    offsets. Every fragment must name the same request, connection and Entry.
    The product instrumentation must know the *logical request* boundaries;
    syscall read boundaries alone do not supply them. A ``handler`` event must
    reuse that request ID and name the canonical handler function ID. This asserts
    *data-flow causality*, rather than mere temporal proximity.
    A result event is optional for handler-reach observation but required for
    PROVEN_RUNTIME. If it claims semantic success, it must also identify a
    source-evidenced completion function and line. Its response digest must
    match the output captured for the request. A state digest is optional:
    read-only or stateless operations have no required post-state oracle.
    Differential state comparison remains a separate, stricter gate. The event comes from a trusted instrumented
    original build; the journal does not infer success from a state digest
    or silence.

    Typical examples use the environment variable HARNESSCREATOR_TRACE_JSONL
    to discover where to write events. The verifier creates an isolated trace
    file and sets this variable on the spawned original process.
    """

    def __init__(self, path: Path, *, maximum_bytes: int = 2_000_000):
        self.path = path
        self.maximum_bytes = maximum_bytes
        self.mechanism = "request-correlated-jsonl-v1"
        # One journal belongs to one original-process run. Repeating an ID in
        # a later request window makes delayed handler events ambiguous even
        # when both requests used the same connection.
        self._request_offsets: dict[str, int] = {}

    def offset(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def observe(
        self, offset: int, request: bytes, entry_function_id: str,
        handler_function_id: str, dispatcher_function_id: str = "",
        require_dispatch: bool = False,
        response: bytes | None = None,
        success_sites: tuple[tuple[str, int], ...] = (),
    ) -> RequestTraceObservation:
        try:
            length = self.path.stat().st_size
            if length < offset or length - offset > self.maximum_bytes:
                return RequestTraceObservation(False, False, (), "trace truncated or exceeds size limit")
            with self.path.open("rb") as stream:
                stream.seek(offset)
                raw = stream.read(self.maximum_bytes + 1)
        except OSError as exc:
            return RequestTraceObservation(False, False, (), f"trace cannot be read: {exc}")
        if len(raw) > self.maximum_bytes:
            return RequestTraceObservation(False, False, (), "trace exceeds size limit")
        if raw and not raw.endswith(b"\n"):
            return RequestTraceObservation(False, False, (), "trace final event is incomplete", True)
        events: list[dict] = []
        for row in raw.splitlines():
            try:
                event = json.loads(row)
            except (ValueError, UnicodeError):
                return RequestTraceObservation(False, False, (), "malformed JSONL event")
            if not isinstance(event, dict):
                return RequestTraceObservation(False, False, (), "trace event is not an object")
            events.append(event)
        expected_digest = hashlib.sha256(request).hexdigest()
        matching = exact_acquisitions(events, request, entry_function_id)
        # Ambiguous same-content acquisition is not request attribution.
        if len(matching) != 1:
            return RequestTraceObservation(
                False, False, (),
                f"expected one exact-byte acquisition event, got {len(matching)}",
                len(matching) == 0,
            )
        request_id, entry, entry_index = matching[0]
        events_for_id = [
            (index, event) for index, event in enumerate(events)
            if event.get("request_id") == request_id
        ]
        # Reusing one ID for a different request/connection means the journal
        # cannot distinguish which operation produced the target event.
        connection = entry.get("connection_id")
        if not isinstance(connection, str) or not connection:
            return RequestTraceObservation(False, False, (), "missing connection identity")
        if any(
            event.get("connection_id") != connection
            for _, event in events_for_id
        ):
            return RequestTraceObservation(
                False, False, (), "request ID spans multiple connections",
            )
        previous_offset = self._request_offsets.get(request_id)
        if previous_offset is not None and previous_offset != offset:
            return RequestTraceObservation(
                False, False, (), "request ID was reused in a later step",
            )
        self._request_offsets[request_id] = offset
        trace = [f"acquire:{entry_function_id}:{request_id}:{connection}"]
        dispatch_index = entry_index
        if require_dispatch:
            dispatches = [
                (index, event) for index, event in events_for_id
                if index > entry_index and event.get("event") == "dispatch"
                and event.get("dispatcher_function_id") == dispatcher_function_id
                and event.get("connection_id") == connection
            ]
            if len(dispatches) != 1:
                return RequestTraceObservation(
                    True, False, tuple(trace),
                    "matching dispatcher event missing or ambiguous",
                    len(dispatches) == 0,
                )
            dispatch_index = dispatches[0][0]
            trace.append(f"dispatch:{dispatcher_function_id}:{request_id}")
        handlers = [
            (index, event) for index, event in events_for_id
            if index > dispatch_index and event.get("event") == "handler"
            and event.get("handler_function_id") == handler_function_id
            and event.get("connection_id") == connection
        ]
        if len(handlers) != 1:
            return RequestTraceObservation(
                True, False, tuple(trace),
                "matching handler event missing or ambiguous",
                len(handlers) == 0,
            )
        # Events cannot reference an unrelated input digest with the same ID.
        if any(
            event.get("request_sha256") is not None
            and event.get("request_sha256") != expected_digest
            for _, event in events_for_id
        ):
            return RequestTraceObservation(True, False, tuple(trace), "conflicting request digest")
        trace.append(f"handler:{handler_function_id}:{request_id}")
        results = [
            (index, event) for index, event in events_for_id
            if event.get("event") == "result" and index > handlers[0][0]
            and event.get("connection_id") == connection
        ]
        if results:
            if len(results) != 1:
                return RequestTraceObservation(True, False, tuple(trace), "ambiguous result events")
            result = results[0][1]
            result_response = result.get("response_sha256")
            state_digest = result.get("state_digest")
            if not isinstance(result_response, str) or not re.fullmatch(r"[0-9a-f]{64}", result_response):
                return RequestTraceObservation(True, False, tuple(trace), "invalid response digest")
            if state_digest is not None and (
                not isinstance(state_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", state_digest)
            ):
                return RequestTraceObservation(True, False, tuple(trace), "invalid state digest")
            if response is not None and result_response != hashlib.sha256(response).hexdigest():
                return RequestTraceObservation(True, False, tuple(trace), "response differs from the target trace")
            outcome = result.get("outcome")
            if outcome is not None and outcome not in ("success", "failure"):
                return RequestTraceObservation(True, False, tuple(trace), "invalid result outcome")
            if outcome == "success":
                site = (result.get("success_function_id"), result.get("success_line"))
                if site not in success_sites:
                    return RequestTraceObservation(
                        True, False, tuple(trace),
                        "success outcome has no matching source-evidenced completion site",
                    )
                trace.append(f"semantic-success-site:{site[0]}@{site[1]}")
            trace.append(f"semantic-response:{result_response}")
            if state_digest is not None:
                trace.append(f"semantic-state:{state_digest}")
            if outcome is not None:
                # An explicit completion event may serve as a success oracle
                # for operations without a response. The runtime verifier
                # still requires source evidence and exact request identity.
                trace.append(f"semantic-outcome:{outcome}")
        return RequestTraceObservation(True, True, tuple(trace), pending=not results)
