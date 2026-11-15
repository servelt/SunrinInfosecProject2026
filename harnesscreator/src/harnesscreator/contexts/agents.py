from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from typing import Any

from ..agents.common import function_payload, function_ref
from ..analysis.graph import GraphStore
from ..llm.base import close_llm_session
from .builder import CallGraph
from .model import Seed

ROLES = ("context_classifier", "context_locator", "seed_generator", "seed_frontier")

_EVIDENCE = {
    "type": "object",
    "properties": {"file": {"type": "string"}, "line": {"type": "integer"}, "detail": {"type": "string"}},
    "required": ["file", "line", "detail"], "additionalProperties": False,
}
_SEED_ITEM = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "messages": {"type": "array", "items": {
            "type": "object",
            "properties": {"encoding": {"type": "string", "enum": ["text", "hex"]}, "data": {"type": "string"}},
            "required": ["encoding", "data"], "additionalProperties": False}},
        "rationale": {"type": "string"},
        "evidence": {"type": "array", "items": _EVIDENCE},
    },
    "required": ["name", "messages", "rationale", "evidence"], "additionalProperties": False,
}
SEED_GENERATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "seeds": {"type": "array", "items": _SEED_ITEM},
        "open_function_id": {"type": "string"},
        "open_artifact_path": {"type": "string"},
        "done": {"type": "boolean"},
        "notes": {"type": "string"},
    },
    "required": ["seeds", "open_function_id", "open_artifact_path", "done", "notes"], "additionalProperties": False,
}
BLOCKED_REASONS = ["NONE", "NEEDS_STARTUP_OPTION", "NEEDS_SERVER_ISSUED_VALUE", "NEEDS_OTHER_CHANNEL",
                   "NOT_REACHABLE_FROM_THIS_INPUT", "UNKNOWN"]
SEED_FRONTIER_SCHEMA = {
    "type": "object",
    "properties": {
        "seeds": {"type": "array", "items": _SEED_ITEM},
        "open_function_id": {"type": "string"},
        "give_up": {"type": "boolean"},
        "blocked_reason": {"type": "string", "enum": BLOCKED_REASONS},
        "explanation": {"type": "string"},
    },
    "required": ["seeds", "open_function_id", "give_up", "blocked_reason", "explanation"], "additionalProperties": False,
}
CONTEXT_LOCATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "interpreter_function_ids": {"type": "array", "items": {"type": "string"}},
        "open_function_id": {"type": "string"},
        "bytes_remain_after_return": {"type": "boolean"},
        "done": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
    "required": ["interpreter_function_ids", "open_function_id", "bytes_remain_after_return", "done", "rationale"],
    "additionalProperties": False,
}

_DELIVERY_RULES = {
    "stream": "The seed is sent on one connection. Each message is written in order and the server's reply is read "
              "before the next message. Give every message exactly as the bytes on the wire, including line "
              "terminators.",
    "datagram": "Each message is sent as one datagram, including any datagram header the program expects.",
    "stdin": "All messages are concatenated and written to the program's standard input, then input is closed.",
    "file": "All messages are concatenated into one file that the program reads.",
}

_ESCAPES = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, '"': 34, "'": 39}


def decode_text(text: str) -> bytes:
    """Decode a text message with C-style escapes (\\r \\n \\t \\0 \\\\ \\xNN)."""

    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            if nxt == "x" and index + 3 < len(text) and _is_hex(text[index + 2:index + 4]):
                out.append(int(text[index + 2:index + 4], 16))
                index += 4
                continue
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                index += 2
                continue
        out.extend(char.encode("utf-8"))
        index += 1
    return bytes(out)


def _is_hex(chunk: str) -> bool:
    return len(chunk) == 2 and all(c in "0123456789abcdefABCDEF" for c in chunk)


def seeds_from_items(items: list[dict[str, Any]], *, context_id: str, delivery: str, origin: str,
                     parent_seed_id: str | None = None, target_function_id: str | None = None) -> list[Seed]:
    seeds = []
    for item in items:
        messages: list[bytes] = []
        try:
            for message in item.get("messages", []):
                data = message.get("data", "")
                messages.append(bytes.fromhex("".join(data.split())) if message.get("encoding") == "hex"
                                else decode_text(data))
        except ValueError:
            continue  # malformed hex: the candidate is dropped, not repaired by guessing
        if not messages or not any(messages):
            continue
        messages_hex = [message.hex() for message in messages]
        digest = hashlib.sha256(json.dumps([context_id, delivery, messages_hex]).encode()).hexdigest()[:16]
        seeds.append(Seed(
            seed_id=f"seed-{digest}", context_id=context_id, delivery=delivery, messages_hex=messages_hex,
            origin=origin, rationale=item.get("rationale", ""), evidence=list(item.get("evidence", [])),
            parent_seed_id=parent_seed_id, target_function_id=target_function_id))
    return seeds


def _printable(data: bytes, limit: int = 600) -> str:
    text = data[:limit].decode("latin-1")
    return "".join(c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" if c not in "\r\n\t" else
                   {"\r": "\\r", "\n": "\\n", "\t": "\\t"}[c] for c in text) + ("…" if len(data) > limit else "")


def describe_seed(seed: Seed, responses: list[bytes] | None = None) -> dict[str, Any]:
    described: dict[str, Any] = {"seed_id": seed.seed_id, "messages": [_printable(m) for m in seed.messages]}
    if responses is not None:
        described["responses"] = [_printable(r) for r in responses]
    return described


def _context_payload(context: dict[str, Any], delivery: str) -> dict[str, Any]:
    return {
        "context_id": context["context_id"], "resource_kind": context["resource_kind"], "delivery": delivery,
        "delivery_rule": _DELIVERY_RULES.get(delivery, ""),
        "driver_function": context.get("driver_function", ""),
        "interpreter_functions": context.get("interpreter_functions", []),
        "entries": [{k: entry.get(k) for k in ("entry_function", "entry_file", "entry_line", "source_api",
                                                "channel_kind", "delivery")}
                    for entry in context.get("entries", []) if entry.get("delivery") == delivery],
    }


class SeedGeneratorAgent:
    """Proposes candidate seeds for one input context and delivery.

    It reads the interpreting functions and the project's own tests, clients
    and documents, one item per turn.  Its output is only a set of candidates:
    acceptance is decided by running them against the original program.
    """

    def __init__(self, llm: Any, graph: GraphStore, source_root: Path, *, max_turns: int = 40,
                 artifact_char_limit: int = 60_000):
        self.llm, self.graph, self.source_root = llm, graph, Path(source_root)
        self.max_turns, self.artifact_char_limit = max_turns, artifact_char_limit

    async def run(self, context: dict[str, Any], delivery: str, artifact_paths: list[str]) -> tuple[list[Seed], dict[str, Any]]:
        session = f"seed_generator:{context['context_id']}:{delivery}"
        functions = self.graph.bundle.functions
        opened: list[str] = []
        # Read in the order the bytes travel: the function that acquires them for
        # this delivery (it shows framing such as a datagram header), the driver
        # that joins acquisition and interpretation, then the interpreters.
        queue = []
        for function_id in ([entry.get("entry_function_id") for entry in context.get("entries", [])
                             if entry.get("delivery") == delivery]
                            + [context.get("driver_function_id")]
                            + list(context.get("interpreter_function_ids", []))):
            if function_id in functions and function_id not in queue:
                queue.append(function_id)
        current_function = queue.pop(0) if queue else None
        current_artifact: dict[str, Any] | None = None
        collected: dict[str, Seed] = {}
        trace = {"turns": 0, "opened_functions": [], "opened_artifacts": [], "ended": "turn_budget"}
        try:
            # max_turns 0 means no turn limit: the session ends when the model is done
            # or nothing is left to open (each function and artifact is opened once).
            for _ in (range(self.max_turns) if self.max_turns else itertools.count()):
                trace["turns"] += 1
                payload: dict[str, Any] = {
                    "context": _context_payload(context, delivery),
                    "opened_functions": [function_ref(functions[fid]) for fid in opened],
                    "unopened_interpreter_functions": [function_ref(functions[fid]) for fid in queue],
                    "available_project_artifacts": artifact_paths,
                    "seeds_collected": len(collected),
                }
                if current_function:
                    function = functions[current_function]
                    payload["current_function"] = function_payload(function)
                    payload["callees_you_may_open"] = [function_ref(f) for f in self.graph.callees(current_function)]
                    opened.append(current_function)
                    trace["opened_functions"].append(function.name)
                if current_artifact:
                    payload["opened_artifact"] = current_artifact
                try:
                    response = await self._ask(session, payload)
                except Exception as exc:  # keep the seeds collected so far
                    trace["ended"] = f"model_error: {type(exc).__name__}: {exc}"
                    break
                for seed in seeds_from_items(response.get("seeds", []), context_id=context["context_id"],
                                             delivery=delivery, origin="generator"):
                    collected.setdefault(seed.seed_id, seed)
                current_function, current_artifact = None, None
                wanted_function = response.get("open_function_id", "")
                wanted_artifact = response.get("open_artifact_path", "")
                if wanted_function in functions and wanted_function not in opened:
                    current_function = wanted_function
                    if wanted_function in queue:
                        queue.remove(wanted_function)
                elif wanted_artifact in artifact_paths and wanted_artifact not in trace["opened_artifacts"]:
                    current_artifact = self._read_artifact(wanted_artifact)
                    trace["opened_artifacts"].append(wanted_artifact)
                elif response.get("done"):
                    trace["ended"] = "model_done"
                    break
                elif queue:
                    current_function = queue.pop(0)
                else:
                    trace["ended"] = "nothing_left_to_open"
                    break
        finally:
            await close_llm_session(self.llm, session)
        return list(collected.values()), trace

    async def _ask(self, session: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.llm.complete_json(
            role="seed_generator", session_key=session, output_schema=SEED_GENERATOR_SCHEMA, payload=payload,
            instructions=(
                        "Produce candidate SEEDS for this input context. A seed is one complete input that the "
                        "original program would accept through the stated delivery; it may contain one request or "
                        "a sequence of requests, including requests that first create the state a later request "
                        "needs. Derive every seed from what you can read: the interpreting functions and the "
                        "project's own tests, clients, examples and documents. Prefer real exchanges found in "
                        "project artifacts. Aim to exercise as many different handlers reachable from the "
                        "interpreting functions as the opened material supports; do not invent keywords or "
                        "formats that the opened material does not show. Each seed needs evidence (file and line) "
                        "for its format. Use encoding 'text' with C escapes (\\r\\n, \\xNN) for textual data and "
                        "'hex' for binary data. To read more, set open_function_id to one listed function id or "
                        "open_artifact_path to one listed path (one item per turn, leave the other empty). Set "
                        "done=true when the opened material supports no further seeds."))

    def _read_artifact(self, relative: str) -> dict[str, Any]:
        path = (self.source_root / relative).resolve()
        try:
            path.relative_to(self.source_root.resolve())
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            return {"path": relative, "error": str(exc)}
        return {"path": relative, "text": text[: self.artifact_char_limit],
                "truncated": len(text) > self.artifact_char_limit}


class SeedFrontierAgent:
    """Finds an input that reaches one not-yet-executed function.

    The question is local and checkable: the caller was executed by an
    accepted seed, the callee was not.  Every proposal is run against the
    original program and the outcome is returned to the same session.
    """

    def __init__(self, llm: Any, graph: GraphStore):
        self.llm, self.graph = llm, graph

    def session_key(self, context_id: str, delivery: str, target_function_id: str) -> str:
        return f"seed_frontier:{context_id}:{delivery}:{target_function_id}"

    async def turn(self, *, context: dict[str, Any], delivery: str, target_function_id: str, caller_function_id: str,
                   base_seed: dict[str, Any] | None, attempts: list[dict[str, Any]],
                   opened_function_id: str | None) -> dict[str, Any]:
        functions = self.graph.bundle.functions
        payload: dict[str, Any] = {
            "context": _context_payload(context, delivery),
            "target_function": function_ref(functions[target_function_id]),
            "executed_caller": function_ref(functions[caller_function_id]),
            "seed_that_executed_the_caller": base_seed,
            "previous_attempts": attempts,
        }
        if not attempts and opened_function_id is None:
            payload["executed_caller_source"] = function_payload(functions[caller_function_id])
            payload["target_function_source"] = function_payload(functions[target_function_id])
        if opened_function_id and opened_function_id in functions:
            payload["opened_function"] = function_payload(functions[opened_function_id])
        return await self.llm.complete_json(
            role="seed_frontier", output_schema=SEED_FRONTIER_SCHEMA, payload=payload,
            session_key=self.session_key(context["context_id"], delivery, target_function_id),
            instructions=(
                "An accepted seed executed the caller function but the target function has not been executed by any "
                "seed. Read the caller to find the condition under which it calls the target, and propose seeds "
                "(complete inputs for the stated delivery) that satisfy it. If the condition depends on state, "
                "include the earlier requests that create that state in the same seed. previous_attempts lists "
                "seeds already run against the original program with the program's replies and whether the target "
                "was executed; do not repeat them. To read another function first, set open_function_id and leave "
                "seeds empty. If the target cannot be reached through this input, set give_up=true and choose "
                "blocked_reason: NEEDS_STARTUP_OPTION (code is enabled by a launch option or build setting), "
                "NEEDS_SERVER_ISSUED_VALUE (the request must contain a value from an earlier reply), "
                "NEEDS_OTHER_CHANNEL, NOT_REACHABLE_FROM_THIS_INPUT, or UNKNOWN; explain with file and line."))

    async def turn_lines(self, *, context: dict[str, Any], delivery: str, function_id: str,
                         unexecuted_lines: list[int], base_seed: dict[str, Any] | None,
                         attempts: list[dict[str, Any]], opened_function_id: str | None) -> dict[str, Any]:
        """Same question one level down: lines of an executed function that no seed has executed."""

        functions = self.graph.bundle.functions
        payload: dict[str, Any] = {
            "context": _context_payload(context, delivery),
            "function": function_ref(functions[function_id]),
            "unexecuted_lines": unexecuted_lines,
            "seed_that_executed_the_function": base_seed,
            "previous_attempts": attempts,
        }
        if not attempts and opened_function_id is None:
            payload["function_source"] = function_payload(functions[function_id])
        if opened_function_id and opened_function_id in functions:
            payload["opened_function"] = function_payload(functions[opened_function_id])
        return await self.llm.complete_json(
            role="seed_frontier", output_schema=SEED_FRONTIER_SCHEMA, payload=payload,
            session_key=self.session_key(context["context_id"], delivery, "lines:" + function_id),
            instructions=(
                "Accepted seeds executed this function, but the listed source lines of it have not been executed by "
                "any seed. Read the function to find the conditions that lead to those lines and propose seeds "
                "(complete inputs for the stated delivery) that execute them. A branch often depends on state "
                "created by an earlier request (an item that must already exist, a mode that must be set): put "
                "those earlier requests in the same seed. previous_attempts lists seeds already run against the "
                "original program with its replies and which of the lines they executed; do not repeat them. To "
                "read another function first, set open_function_id and leave seeds empty. If the lines cannot be "
                "executed through this input (allocation failure, a launch option, a value the server must issue "
                "first), set give_up=true with the matching blocked_reason and explain with file and line."))

    async def close(self, context_id: str, delivery: str, target_function_id: str) -> None:
        await close_llm_session(self.llm, self.session_key(context_id, delivery, target_function_id))


RESOURCE_KINDS = ("network", "local_ipc", "file", "stdin", "argv", "env", "internal", "unknown")
DELIVERY_KINDS = ("stream", "datagram", "not_applicable", "unknown")
CONTEXT_CLASSIFIER_SCHEMA = {
    "type": "object",
    "properties": {
        "resource_kind": {"type": "string", "enum": list(RESOURCE_KINDS)},
        "delivery": {"type": "string", "enum": list(DELIVERY_KINDS)},
        "rationale": {"type": "string"},
    },
    "required": ["resource_kind", "delivery", "rationale"], "additionalProperties": False,
}


class EntryChannelClassifier:
    """Places one Entry in a fixed list of resource kinds and deliveries.

    The Entry Verifier describes the channel in free text.  Searching that
    text for words fails on sentences such as "not network input" or "TCP or
    UDP is not established" (measured 2026-11-15: 3 of 10 Entries misplaced),
    so the kind is chosen from an enumeration instead.
    """

    def __init__(self, llm: Any, graph: GraphStore):
        self.llm, self.graph = llm, graph

    async def classify(self, entry: dict[str, Any]) -> dict[str, Any]:
        function = self.graph.bundle.functions[entry["entry_function_id"]]
        response = await self.llm.complete_json(
            role="context_classifier", output_schema=CONTEXT_CLASSIFIER_SCHEMA,
            payload={
                "entry": {k: entry.get(k) for k in ("entry_id", "source_api", "channel_kind", "entry_line",
                                                    "boundary_subject", "attacker_control")},
                "entry_function": function_payload(function),
            },
            instructions=(
                "The Entry acquires external bytes at the stated line of entry_function. Choose who supplies "
                "those bytes (resource_kind) and how they arrive (delivery).\n"
                "resource_kind: network = a socket whose peer is another host or process reached through an "
                "internet-family transport (TCP, UDP, TLS over such a socket); local_ipc = an AF_UNIX socket, "
                "named pipe or FIFO written by another local process; file = the content of a path the program "
                "opens (regular file, configuration, pid file, /proc, storage backing file); stdin = the "
                "standard input or console of the process; argv = command-line arguments; env = environment "
                "variables; internal = a descriptor the program itself creates and writes (eventfd, timerfd, "
                "self-pipe, wakeup notification), so no outside party supplies the bytes; unknown = the source "
                "and the description do not establish it.\n"
                "delivery: stream = an ordered byte stream without message boundaries (TCP, TLS, AF_UNIX stream "
                "socket, pipe); datagram = one message per read with boundaries kept (UDP, SOCK_DGRAM, "
                "recvfrom on a datagram socket); not_applicable = file, stdin, argv, env and internal; unknown "
                "= a socket whose type is not established.\n"
                "When the bytes come from a socket, including a TLS session on one, and nothing shows the "
                "socket is AF_UNIX, choose network. "
                "Decide from what the source and the Entry description state positively. A sentence saying "
                "the input is NOT some kind, or that a kind is not established, is not evidence for that kind."))
        return {"entry_id": entry["entry_id"], "resource_kind": response["resource_kind"],
                "delivery": response["delivery"], "rationale": response.get("rationale", "")}


class ContextLocatorAgent:
    """Names the functions that read the content of the bytes an Entry acquires.

    Used when no earlier artifact identifies them.  An answer is accepted only
    if the call graph joins it to the Entry function (a common ancestor exists).

    The acquiring function often reads only part of the bytes and leaves them
    in storage that outlives the call; the code that interprets the rest then
    lies in a caller.  The model therefore states, per level, whether the bytes
    remain readable after that function returns, and while they do the walk
    moves up to a caller instead of ending at the acquiring function.  The walk
    stops at the first caller that adds no new reader once some reader other
    than the Entry function is known.
    """

    def __init__(self, llm: Any, graph: GraphStore, callgraph: CallGraph, *, max_turns: int = 24):
        self.llm, self.graph, self.callgraph, self.max_turns = llm, graph, callgraph, max_turns

    async def locate(self, entry: dict[str, Any]) -> dict[str, Any]:
        functions = self.graph.bundle.functions
        entry_function = entry["entry_function_id"]
        session = f"context_locator:{entry['entry_id']}"
        opened: list[str] = []
        named: list[str] = []
        climbed: list[str] = []
        current = level = entry_function
        named_before_level = 0
        result = {"entry_id": entry["entry_id"], "interpreter_function_ids": [], "rejected_function_ids": [],
                  "opened_function_ids": opened, "climbed_function_ids": climbed, "ended": "turn_budget",
                  "rationale": ""}
        try:
            for _ in range(self.max_turns):
                opened.append(current)
                response = await self.llm.complete_json(
                    role="context_locator", session_key=session, output_schema=CONTEXT_LOCATOR_SCHEMA,
                    payload={
                        "entry": {k: entry.get(k) for k in ("entry_id", "source_api", "channel_kind", "entry_line",
                                                            "boundary_subject")},
                        "current_function": function_payload(functions[current]),
                        "connections": self.graph.frontier([current]),
                        "opened_functions": [function_ref(functions[fid]) for fid in opened],
                        "return_question_function": function_ref(functions[level]),
                        "confirmed_interpreters": [function_ref(functions[fid]) for fid in named],
                    },
                    instructions=(
                        "The Entry acquires external bytes at the stated line. On each path the bytes take, "
                        "find the first function that reads their content: one that parses them or chooses "
                        "what to do based on them. Stop there on that path: do not open or list the functions "
                        "such a reader calls, the call graph already supplies them. "
                        "Follow the bytes, not only the call that acquires them. A function that acquires or "
                        "partly reads the bytes often leaves them in storage that outlives the call (a field of "
                        "a connection or session object, a global, a buffer owned by the caller); other code "
                        "then reads them from there after it returns, usually in a caller or in a function the "
                        "caller invokes next, possibly through a function pointer. Those functions count. Open "
                        "one connected function per turn with open_function_id. interpreter_function_ids lists "
                        "the functions confirmed so far, from source you have read, to read the content. "
                        "bytes_remain_after_return answers one question about return_question_function only: "
                        "after it returns, are the acquired bytes, or the part not yet read, still in storage "
                        "that its caller or later code can read? Set done=true when nothing more needs opening "
                        "from here."))
                result["rationale"] = response.get("rationale", "")
                for function_id in response.get("interpreter_function_ids", []):
                    if function_id not in named:
                        named.append(function_id)
                wanted = response.get("open_function_id", "")
                if not response.get("done") and wanted in functions and wanted not in opened:
                    current = wanted
                    continue
                # Nothing more to open below this level: decide whether to move up to a caller.
                callers = [f.function_id for f in self.graph.callers(level) if f.function_id not in opened]
                reader_beyond_entry = any(fid != entry_function and fid in functions for fid in named)
                found_at_level = len(named) > named_before_level
                if (response.get("bytes_remain_after_return") and callers
                        and (found_at_level or not reader_beyond_entry)):
                    level = current = wanted if wanted in callers else callers[0]
                    climbed.append(level)
                    named_before_level = len(named)
                    continue
                result["ended"] = "model_done" if response.get("done") else "nothing_left_to_open"
                break
        finally:
            await close_llm_session(self.llm, session)
        for function_id in named:
            joined = function_id in functions and self.callgraph.driver(entry_function, [function_id])
            (result["interpreter_function_ids"] if joined else result["rejected_function_ids"]).append(function_id)
        return result
