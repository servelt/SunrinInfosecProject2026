"""Harness generation for an input context, judged by measurement.

The generator inherited from the Action workflow refuses to write code unless
every fact is established from source (for memcached it stopped because the
connection functions are ``static`` and the startup state has no "evidenced"
initializer).  For an input context the facts are measured instead:

* the verified seeds were run on the original program, and the functions each
  seed executed are recorded;
* the built harness is run on the same seeds and must execute the same functions
  without a sanitizer report.

So this generator always attempts a harness, in one of the delivery shapes found
in hand-written daemon harnesses, and the result is decided by build, seed
replay, seed equivalence and an independent review of the sixteen QuartetFuzz
P1/P2-derived checks.  Nothing here reports QUALIFIED.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..agents.common import function_payload, function_ref
from ..llm.base import close_llm_session
from ..runtime.runner import SANITIZER_MARKERS
from ..storage import ArtifactStore
from . import harness as bridge
from .builder import CallGraph, entry_supports_delivery

STATUS_EQUIVALENT = "BUILT_SEED_EQUIVALENT_NOT_QUALIFIED"
STATUS_EQUIVALENT_REVIEW_FAILED = "BUILT_SEED_EQUIVALENT_REVIEW_FAILED"
STATUS_MISMATCH = "BUILT_SEED_MISMATCH"
STATUS_REPLAYED = "BUILT_REPLAYED_NOT_QUALIFIED"
STATUS_REPLAY_FAILED = "BUILT_REPLAY_FAILED"
STATUS_BUILD_FAILED = "BUILD_FAILED"
STATUS_NO_CODE = "GENERATION_BLOCKED"
_PROGRESS = {STATUS_NO_CODE: 0, STATUS_BUILD_FAILED: 1, STATUS_REPLAY_FAILED: 2, STATUS_MISMATCH: 3,
             STATUS_REPLAYED: 4, STATUS_EQUIVALENT_REVIEW_FAILED: 5, STATUS_EQUIVALENT: 6}

CHECKS = {
    "HC01": "Everything the harness creates for one input (descriptors, memory, threads) is released before it returns.",
    "HC02": "The harness never uses or hands to the program memory it has already released.",
    "HC03": "The harness leaves no state of its own that changes how a later input is processed; program state that "
            "persists between inputs is named in the explanation.",
    "HC04": "The fuzz bytes (Data, Size) reach the program through this context's delivery so that the Entry acquires "
            "exactly those bytes; nothing else is injected into that channel. Every byte is offered: sending stops "
            "before Size only when the program itself closed or reset the connection (its decision about the input, "
            "as for any external peer), never because of a harness deadline or a send error the harness caused.",
    "HC05": "Harness code reads and writes only inside its own buffers.",
    "HC06": "Size 0 and large Size are handled; every length passed to a call is the real length.",
    "HC07": "Harness code has no undefined behaviour (uninitialized values, bad casts, data races it introduces).",
    "HC08": "The original program code does the acquisition, parsing and dispatch; the harness re-implements none of it.",
    "HC09": "The program is initialized the way it initializes itself (its real startup with a realistic configuration), once.",
    "HC10": "The harness fabricates no protocol content: bytes not taken from Data are limited to transport setup "
            "and, for the peer_stream delivery, the context's fixed trigger (with {PEER_HOST}/{PEER_PORT} filled in), "
            "which the contract requires.",
    "HC11": "Order matches a real peer: connect, deliver, let the program finish processing, close; the harness waits "
            "for processing to finish before it returns. For a stream that means waiting for the program to close "
            "the connection after the write side is shut down; returning after a silence window FAILS this check "
            "unless the program is known to keep the connection open.",
    "HC12": "Replies and return values are consumed so the program is never blocked on the harness; delivery errors are handled.",
    "HC13": "Each input's connection and descriptors are closed; nothing accumulates across inputs.",
    "HC14": "Every function or symbol the harness uses exists with the declared signature and is linkable "
            "(non-static, or hc_native_original_main).",
    "HC15": "Calls the environment must make for the program to run normally are present (for example ignoring SIGPIPE).",
    "HC16": "The harness never puts the program in a state an external peer of this channel could not produce.",
}

_READ_SCHEMA = {
    "type": "object",
    "properties": {"open_function_id": {"type": "string"}, "enough": {"type": "boolean"}, "notes": {"type": "string"}},
    "required": ["open_function_id", "enough", "notes"], "additionalProperties": False,
}
_AUDIT = {
    "type": "array", "items": {
        "type": "object",
        "properties": {"check_id": {"type": "string"}, "status": {"type": "string", "enum": ["PASS", "WARN", "FAIL"]},
                       "evidence": {"type": "string"}},
        "required": ["check_id", "status", "evidence"], "additionalProperties": False}}
_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "code": {"type": "string"},
        "shape": {"type": "string", "enum": ["in_process_server", "wrapped_io", "direct_call", "none"]},
        "explanation": {"type": "string"},
        "persisting_program_state": {"type": "string"},
        "self_audit": _AUDIT,
        "blockers": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["code", "shape", "explanation", "persisting_program_state", "self_audit", "blockers"],
    "additionalProperties": False,
}
def review_problems(review: dict[str, Any]) -> list[str]:
    """Why a review does not cover HC01..HC16 exactly once each ([] when it does)."""
    ids = [str(check.get("check_id", "")) for check in review.get("checks") or []]
    expected = set(CHECKS)
    problems = []
    missing = sorted(expected - set(ids))
    repeated = sorted({i for i in ids if ids.count(i) > 1})
    unknown = sorted(set(ids) - expected)
    if missing:
        problems.append("missing " + ", ".join(missing))
    if repeated:
        problems.append("repeated " + ", ".join(repeated))
    if unknown:
        problems.append("unknown " + ", ".join(unknown))
    return problems


_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {"checks": _AUDIT, "summary": {"type": "string"}},
    "required": ["checks", "summary"], "additionalProperties": False,
}

_CONTRACT = (
    "BUILD CONTRACT. The harness is one separate source file. It is compiled with clang and linked with every "
    "translation unit of the original program, all built with AddressSanitizer, UndefinedBehaviorSanitizer and "
    "libFuzzer instrumentation. The original program's main is renamed to hc_native_original_main with the same "
    "signature; the harness may declare it (int hc_native_original_main(int argc, char **argv);) and call it. "
    "Functions that are static in the original cannot be called, and the harness must not #include a .c file of "
    "the original. Project headers are on the include path. The harness defines "
    "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) and may define LLVMFuzzerInitialize. libFuzzer "
    "calls LLVMFuzzerTestOneInput many times in one process."
)
_SHAPES = (
    "DELIVERY SHAPES used in hand-written daemon harnesses; choose the one this program allows:\n"
    "(in_process_server) Start the original program once inside the fuzzing process by calling "
    "hc_native_original_main on a background thread with the given command-line arguments, wait until it accepts "
    "input, then for every fuzz input act as one external peer on the real channel: for a stream, connect, send "
    "all Size bytes of Data (keep writing until every byte is sent; stop early only when the program itself "
    "closes or resets the connection, which is its own decision about the input) while also reading whatever "
    "the program sends in the meantime (wait for writable and readable together, e.g. one poll on both), so a "
    "program that answers a request before it reads the next one is never blocked on a full reply buffer; then "
    "shut down the sending side, "
    "read replies until the program closes the connection, close. Do not put a wall-clock deadline or a silence "
    "window on sending or on waiting for the close: a program that never finishes is a hang that the fuzzer's own "
    "per-input timeout reports, while a harness that gives up first would truncate inputs or return before the "
    "program processed them. For datagrams, send Data as one datagram and read replies for a short bounded "
    "time. Use this when the acquisition and processing functions are static or need the program's full startup.\n"
    "(wrapped_io) Create the program's own connection object through its real non-static constructor on a "
    "socketpair or pipe, write Data to the other end, and run the program's own processing loop until the input "
    "is consumed.\n"
    "(direct_call) Only when the function that acquires the bytes is itself callable and nothing else is needed.\n"
    "(in_process_server, peer side) For the peer_stream delivery the fuzz bytes are what a server the program "
    "connects to sends back. Start the program as above and, once, open a listening TCP socket on the loopback "
    "address with an ephemeral port. For every input: connect to the program's endpoint, send the fixed trigger "
    "with {PEER_HOST} and {PEER_PORT} replaced by that listener's address and port (send nothing when the trigger "
    "is empty), accept the connection the program opens to the listener (bounded wait), write Data on it, shut "
    "down its sending side, read on it until the program closes it, then shut down the sending side of the "
    "trigger connection too (the client has nothing more to say; a program that reads further client input on "
    "an error path otherwise waits for its own timeout, which the fuzzer records as a hang), read the trigger "
    "connection until the program closes it, and close both."
)

_PEER_FRAMING = (
    "INPUT FRAMING for peer_stream delivery: Data is the whole byte stream the peer (a server the program "
    "connects to) sends on the connection the program opens; deliver it unchanged. The trigger is fixed, not "
    "fuzzed: it is given in peer_trigger with the placeholders {PEER_HOST} and {PEER_PORT}."
)


_DATAGRAM_FRAMING = (
    "INPUT FRAMING for datagram delivery: the fuzz input is a sequence of records. Each record is a 2-byte "
    "big-endian length followed by that many bytes; send each record's bytes as one datagram, in order, and read "
    "replies for a short bounded time after each. If a length exceeds the bytes that remain, send the remaining "
    "bytes as the last datagram. The framing only marks datagram boundaries; the datagram contents come from Data."
)


class _DatagramSeed:
    """A verified seed whose harness input keeps the datagram boundaries (2-byte length before each datagram)."""

    def __init__(self, seed: Any):
        self._seed = seed

    def __getattr__(self, name: str) -> Any:
        return getattr(self._seed, name)

    @property
    def data(self) -> bytes:
        return b"".join(len(message).to_bytes(2, "big") + message for message in self._seed.messages
                        if len(message) < 65536)


class _PeerSeed:
    """A verified peer_stream seed: the harness receives only the peer's bytes (message 1 is the trigger)."""

    def __init__(self, seed: Any):
        self._seed = seed

    def __getattr__(self, name: str) -> Any:
        return getattr(self._seed, name)

    @property
    def data(self) -> bytes:
        return b"".join(self._seed.messages[1:])


def _ask(llm: Any, role: str, session: str, schema: dict[str, Any], instructions: str, payload: dict[str, Any]):
    return llm.complete_json(role=role, session_key=session, output_schema=schema,
                             instructions=instructions, payload=payload)


def _main_function(graph: Any, callgraph: CallGraph, entry_function_id: str) -> str | None:
    ancestors = callgraph.ancestors(entry_function_id)
    mains = sorted((fid for fid, fn in graph.bundle.functions.items() if fn.name == "main"),
                   key=lambda fid: (fid not in ancestors, ancestors.get(fid, 0), graph.bundle.functions[fid].file))
    return mains[0] if mains else None


class MeasuredHarnessGenerator:
    def __init__(self, llm: Any, graph: Any, callgraph: CallGraph, *, reading_turns: int = 30):
        self.llm, self.graph, self.callgraph, self.reading_turns = llm, graph, callgraph, reading_turns

    def _brief(self, context: dict[str, Any], delivery: str, seeds: list[Any], server_args: list[str],
               host: str, port: int) -> dict[str, Any]:
        first = seeds[0]
        executed = sorted({name for seed in seeds for name in seed.functions_beyond_baseline})
        return {
            "context_id": context["context_id"], "resource_kind": context.get("resource_kind"), "delivery": delivery,
            "entries": [{k: e.get(k) for k in ("entry_function", "entry_file", "entry_line", "source_api",
                                                "channel_kind", "delivery_candidates", "delivery_basis")}
                        for e in context.get("entries", []) if entry_supports_delivery(context, e, delivery)],
            "driver_function": context.get("driver_function"),
            "interpreter_functions": context.get("interpreter_functions"),
            "original_program_arguments": server_args,
            "channel_endpoint": {"host": host, "port": port} if port else None,
            "input_framing": _DATAGRAM_FRAMING if delivery == "datagram" else _PEER_FRAMING
                             if delivery == "peer_stream" else
                             "The fuzz input is the byte stream itself, delivered unchanged.",
            **({"peer_trigger": first.messages[0].decode("latin-1") if first.messages else "",
                "peer": [e.get("channel_kind") for e in context.get("entries", [])
                         if entry_supports_delivery(context, e, delivery)]}
               if delivery == "peer_stream" else {}),
            "verified_seed_count": len(seeds),
            "example_seed": {"messages": [m[:400].decode("latin-1") for m in first.messages][:8],
                             "replies": [r[:300].decode("latin-1") for r in first.responses][:8]},
            "functions_the_original_executed_for_the_seeds": executed[:300],
            "measurement": "Each verified seed was sent to the original program started with these arguments, and the "
                           "functions it executed (beyond a run with no input) were recorded. After the harness is "
                           "built, every seed is replayed in it; it must finish without a sanitizer report and "
                           "execute the same functions.",
        }

    async def read(self, session: str, brief: dict[str, Any], queue: list[str]) -> list[str]:
        functions = self.graph.bundle.functions
        opened: list[str] = []
        current = queue.pop(0) if queue else None
        for _ in range(self.reading_turns):
            if current is None:
                break
            opened.append(current)
            near = {f.function_id: f for f in self.graph.callers(current) + self.graph.callees(current)}
            response = await _ask(
                self.llm, "harness_generator", session, _READ_SCHEMA,
                "You will write a libFuzzer harness for this input context. First read the original source, one "
                "function per turn, to learn: how the program starts and what its command-line arguments set up, how "
                "it begins accepting input on this channel, where the bytes are acquired, and when processing of one "
                "input is finished. " + _CONTRACT + " " + _SHAPES + " Ask for the next function with "
                "open_function_id (one of the listed ids), or set enough=true when you can choose a shape and write "
                "the harness. Reading every handler is not needed: the program's own dispatcher handles the bytes.",
                {"context": brief, "current_function": function_payload(functions[current]),
                 "connected_functions": [function_ref(f) for f in near.values()][:120],
                 "still_queued": [function_ref(functions[f]) for f in queue],
                 "opened_functions": [functions[f].name for f in opened]})
            wanted = response.get("open_function_id", "")
            if wanted in functions and wanted not in opened:
                current = wanted
                if wanted in queue:
                    queue.remove(wanted)
            elif response.get("enough") or not queue:
                break
            else:
                current = queue.pop(0)
        return opened

    async def write(self, session: str, brief: dict[str, Any], language: str, feedback: list[str]) -> dict[str, Any]:
        return await _ask(
            self.llm, "harness_generator", session, _WRITE_SCHEMA,
            f"Write the complete {language} source of the harness now. " + _CONTRACT + " " + _SHAPES + " "
            "Requirements: the fuzz input is the whole input one external peer sends on this channel (it may hold "
            "several requests); deliver it unchanged and add no protocol content of your own. Initialize once. For "
            "in_process_server use the given original_program_arguments and endpoint, ignore SIGPIPE, bound the "
            "startup and connection waits, and return only after the program has finished processing the input; "
            "a program that never finishes an input is reported by the fuzzer's own per-input timeout. "
            "Do not add a fixed pause after an input to let background threads or timers of the program do work: "
            "a harness is executed many thousands of times, and only the processing of the delivered bytes has to "
            "be reproduced. Wait on an observable condition, never on a long constant. For a stream connection the "
            "condition is the program closing it: shut down the write side once the input is sent, then read "
            "until recv() returns 0, with no deadline of the harness's own. A program that reads until the peer's "
            "end of input closes its side only after it has handled every request, so that is the one sign "
            "processing is finished. A silence window is NOT a completion condition: a program that writes a "
            "log line or a file per request can pause longer than any short window, the harness then returns "
            "while the program is still working, and a fault it hits afterwards is charged to the next input. "
            "Measured on one daemon: a 100 ms silence window let 598 inputs that fault the program into the "
            "corpus as non-crashing, and the fuzzer died on them at every restart (285 restarts in 2.5 h). Use "
            "silence only for a program that keeps the connection open after the peer's end of input, and say "
            "so in persisting_program_state. This waiting rule is for delivering an input only. A readiness "
            "check at startup needs nothing but an accepted connection (and the greeting, if the program sends "
            "one): close it at once. A server that greets and then waits for a command never closes that probe "
            "connection, so waiting there for the close costs the whole deadline on every start -- measured on "
            "one daemon: 10.0 s per start instead of 0.006 s, paid again by every fuzzer restart and every "
            "single-input replay. "
            "Name in persisting_program_state any program state that survives from one input to the next. Fill "
            "self_audit with one entry for each of HC01..HC16 as described in checks. Return code even when you "
            "are unsure of a detail: the build, the replay of the verified seeds and the comparison of executed "
            "functions will show whether it is right, and their results come back to you. Use blockers and an empty "
            "code only if no shape can exist for this program, and say exactly why.",
            {"context": brief, "checks": CHECKS, "feedback_from_previous_attempt": feedback})

    async def review(self, session: str, brief: dict[str, Any], code: str, generator_notes: dict[str, Any]) -> dict[str, Any]:
        try:
            return await _ask(
                self.llm, "harness_verifier", session, _REVIEW_SCHEMA,
                "Review this generated libFuzzer harness independently of its author. " + _CONTRACT + " Judge each "
                "of HC01..HC16 from the code: PASS when the code shows it holds, FAIL when the code violates it "
                "(quote the line), WARN when it cannot be decided from the code alone. The purpose is that a crash "
                "found with this harness is a crash of the original program on input an external peer can send, "
                "not a fault of the harness.",
                {"context": brief, "checks": CHECKS, "harness_source": code,
                 "author_shape": generator_notes.get("shape"),
                 "author_persisting_program_state": generator_notes.get("persisting_program_state")})
        finally:
            await close_llm_session(self.llm, session)


def _run(argv: list[str], *, timeout: float, env: dict[str, str]) -> tuple[int | None, str, bool]:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, env=env, check=False)
        return done.returncode, done.stdout + done.stderr, False
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"") + (exc.stderr or b"")
        return None, output.decode("utf-8", "replace") if isinstance(output, bytes) else str(output), True


def _environment() -> dict[str, str]:
    # The program keeps running in the fuzzing process, so memory it still
    # owns at exit is not a leak of one input.
    return dict(os.environ, ASAN_OPTIONS="detect_leaks=0:handle_abort=1",
                UBSAN_OPTIONS="print_stacktrace=1", ASAN_SYMBOLIZER_PATH=bridge._symbolizer() or "")


_UBSAN_LINE = re.compile(r"^(\S+?):(\d+):\d+: runtime error: (.*)$", re.MULTILINE)
_ASAN_ERROR = re.compile(r"ERROR: (\w+Sanitizer): ([^\n]*)")
_FRAME = re.compile(r"^\s*#(\d+) \S+ in (\S+) (\S+?):(\d+)", re.MULTILINE)


def classify_reports(output: str, harness_name: str) -> tuple[list[dict[str, Any]], bool]:
    """Split sanitizer reports into reports located in the original program and harness faults.

    A report whose location (UBSan) or innermost frames (ASan) are in the
    harness source is a fault of the harness.  A report located in the original
    program, triggered by a seed the original accepted, is a finding about the
    program, not a reason to rewrite the harness.
    """

    program: list[dict[str, Any]] = []
    harness_fault = False
    for match in _UBSAN_LINE.finditer(output):
        file, line, text = match.group(1), int(match.group(2)), match.group(3)
        if Path(file).name == harness_name:
            harness_fault = True
        else:
            program.append({"sanitizer": "UndefinedBehaviorSanitizer", "file": file, "line": line,
                            "message": re.sub(r"0x[0-9a-fA-F]+", "ADDR", text)[:200]})
    for match in _ASAN_ERROR.finditer(output):
        if match.group(1) == "UndefinedBehaviorSanitizer":
            continue
        frames = [(f.group(2), f.group(3), int(f.group(4))) for f in _FRAME.finditer(output[match.end():match.end() + 6000])]
        project = [frame for frame in frames if not frame[1].startswith(("/usr/", "/build/"))][:3]
        # The innermost frame outside system libraries decides whose code faulted.
        if not project or Path(project[0][1]).name == harness_name:
            harness_fault = True
        else:
            program.append({"sanitizer": match.group(1), "file": project[0][1], "line": project[0][2],
                            "function": project[0][0], "message": match.group(2)[:200]})
    if not program and not harness_fault and any(marker in output for marker in SANITIZER_MARKERS):
        harness_fault = True  # a report that could not be located is not assumed to be the program's
    return program, harness_fault


def replay(binary: Path, seeds: list[Any], directory: Path, harness_name: str = "fuzz_target.c") -> list[dict[str, Any]]:
    directory.mkdir(parents=True, exist_ok=True)
    results = []
    for index, seed in enumerate(seeds):
        path = directory / f"{index:04d}-{seed.seed_id}"
        path.write_bytes(seed.data)
        code, output, timed_out = _run([str(binary), str(path), "-runs=1", "-timeout=30"], timeout=120, env=_environment())
        program_reports, harness_fault = classify_reports(output, harness_name)
        results.append({"seed_id": seed.seed_id, "bytes": len(seed.data), "returncode": code, "timed_out": timed_out,
                        "sanitizer_report": bool(program_reports) or harness_fault,
                        "program_reports": program_reports, "harness_fault": harness_fault,
                        "ok": not timed_out and not harness_fault and (code == 0 or bool(program_reports)),
                        "output_tail": output[-1500:]})
    return results


def program_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int, str], list[str]] = {}
    for item in results:
        for report in item.get("program_reports", []):
            key = (report["sanitizer"], report["file"], report["line"], report["message"])
            grouped.setdefault(key, [])
            if item["seed_id"] not in grouped[key]:
                grouped[key].append(item["seed_id"])
    return [{"sanitizer": k[0], "file": k[1], "line": k[2], "message": k[3], "seeds": len(v), "seed_ids": v[:10],
             "confirmed_on_original_program": False}
            for k, v in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0]))]


def executions_per_second(binary: Path, seed: Any, directory: Path, runs: int = 50) -> float | None:
    """Speed of the built harness on one verified seed (libFuzzer -runs=N on a fixed input)."""

    import time
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "speed-seed"
    path.write_bytes(seed.data)
    started = time.monotonic()
    code, _output, timed_out = _run([str(binary), str(path), f"-runs={runs}"], timeout=300, env=_environment())
    elapsed = time.monotonic() - started
    if timed_out or elapsed <= 0:
        return None
    return round(runs / elapsed, 1)


def covering_seeds(seeds: list[Any]) -> list[Any]:
    """Fewest seeds (greedy) that together cover every function any seed executed on the original."""

    remaining = {name for seed in seeds for name in seed.functions_beyond_baseline}
    chosen, pool = [], list(seeds)
    while remaining and pool:
        best = max(pool, key=lambda seed: (len(remaining & set(seed.functions_beyond_baseline)), -len(seed.data)))
        gain = remaining & set(best.functions_beyond_baseline)
        if not gain:
            break
        chosen.append(best)
        pool.remove(best)
        remaining -= gain
    return chosen


EQUIVALENCE_SEED_LIMIT = 40


def equivalence_seeds(seeds: list[Any], limit: int = EQUIVALENCE_SEED_LIMIT) -> list[Any]:
    """The seeds whose function equivalence is measured: every verified seed, up to `limit`.

    The covering seeds come first.  Covering function names alone kept one seed of several that
    executed the same functions along different lines (LightFTP: 1 of 4), and the others were
    never compared with the original; seeds left out by the limit are counted, not hidden."""
    chosen = covering_seeds(seeds)
    chosen += [seed for seed in seeds if seed not in chosen][:max(0, limit - len(chosen))]
    return chosen


def equivalence(binary: Path, seeds: list[Any]) -> list[dict[str, Any]]:
    previous = os.environ.get("ASAN_OPTIONS")
    os.environ["ASAN_OPTIONS"] = "detect_leaks=0"
    try:
        return bridge._seed_equivalence(binary, seeds)
    finally:
        if previous is None:
            os.environ.pop("ASAN_OPTIONS", None)
        else:
            os.environ["ASAN_OPTIONS"] = previous


async def _unit(context: dict[str, Any], delivery: str, *, settings: Any, store: ArtifactStore, graph: Any,
                callgraph: CallGraph, llm: Any, server_args: list[str], host: str, port: int,
                reading_turns: int) -> dict[str, Any]:
    context_id = context["context_id"]
    name = bridge._safe_name(f"{context_id}-{delivery}")
    unit_dir = Path(bridge.OUTPUT_DIR) / name
    seeds, skipped = bridge.load_seeds(settings.run_dir, context_id, delivery)
    if delivery == "datagram":
        seeds = [_DatagramSeed(seed) for seed in seeds]
    elif delivery == "peer_stream":
        seeds = [_PeerSeed(seed) for seed in seeds]
    row: dict[str, Any] = {
        "context_id": context_id, "delivery": delivery, "directory": str(unit_dir), "generator": "measured",
        "resource_kind": context.get("resource_kind"), "generated": False, "review_passed": False, "built": False,
        "seeds_available": len(seeds), "seeds_replayed": 0, "seeds_replay_ok": 0, "status": STATUS_NO_CODE,
        "reason": "", "qualified": False, "attempt": None, "attempts": [], "notes": list(skipped)}
    entries = [e for e in context.get("entries", []) if entry_supports_delivery(context, e, delivery)]
    # A delivery taken from an Entry's open candidates is a measured trial, not
    # an established fact about the Entry; the row says which one it was.
    row["entry_deliveries"] = [
        {"entry_function": e.get("entry_function"), "recorded_delivery": e.get("delivery"),
         "delivery_candidates": e.get("delivery_candidates") or [e.get("delivery")],
         "delivery_basis": e.get("delivery_basis", ""),
         "established": e.get("delivery") == delivery and len(e.get("delivery_candidates") or [1]) <= 1}
        for e in entries]
    if not seeds or not entries:
        row["reason"] = ("no verified seed exists for this context and delivery" if not seeds
                         else "the context has no Entry with this delivery")
        store.write_json(unit_dir / "status.json", row)
        return row
    functions = graph.bundle.functions
    entry_function = entries[0]["entry_function_id"]
    queue = []
    for function_id in [entry_function, context.get("driver_function_id"),
                        _main_function(graph, callgraph, entry_function),
                        *list(context.get("interpreter_function_ids", []))[:2]]:
        if function_id in functions and function_id not in queue:
            queue.append(function_id)
    cpp = Path(functions[entry_function].file).suffix.lower() in (".cc", ".cpp", ".cxx", ".c++")
    source_name, language = ("fuzz_target.cc", "C++") if cpp else ("fuzz_target.c", "C")
    generator = MeasuredHarnessGenerator(llm, graph, callgraph, reading_turns=reading_turns)
    brief = generator._brief(context, delivery, seeds, server_args, host, port)
    store.write_json(unit_dir / "brief.json", brief)
    session = f"harness_generator:measured:{name}"
    measured = equivalence_seeds(seeds)
    feedback: list[str] = []
    previous_missing: list[str] | None = None
    try:
        try:
            opened = await generator.read(session, brief, queue)
        except Exception as exc:
            # A refused or lost source-reading session (measured on 3proxy: a provider
            # content filter on the first turn) must leave a status row like any other
            # blocked unit, not abort every later context of the stage.
            row["reason"] = f"harness generator source reading raised {type(exc).__name__}: {exc}"
            store.write_json(unit_dir / "status.json", row)
            return row
        store.write_json(unit_dir / "opened-functions.json", [functions[f].name for f in opened])
        for number in range(1, settings.attempts + 1):
            attempt = unit_dir / f"attempt-{number}"
            record: dict[str, Any] = {"attempt": number, "directory": str(attempt), "generated": False,
                                      "review_passed": False, "built": False, "seeds_replayed": 0,
                                      "seeds_replay_ok": 0, "status": STATUS_NO_CODE, "reason": ""}
            row["attempts"].append(record)
            try:
                draft = await generator.write(session, brief, language, feedback)
            except Exception as exc:
                record["reason"] = f"harness generator raised {type(exc).__name__}: {exc}"
                break
            code = str(draft.get("code") or "")
            harness = store.write_text(attempt / source_name, code)
            store.write_json(attempt / "generator.json", {k: v for k, v in draft.items() if k != "code"})
            record["harness_source"] = str(attempt / source_name)
            if not code.strip():
                record["reason"] = "generator returned no source: " + "; ".join(draft.get("blockers") or ["no reason given"])
                feedback = ["You returned no code. " + _SHAPES + " Write the harness; measurement will judge it."]
                continue
            record["generated"] = True
            record["shape"] = draft.get("shape")

            review, incomplete = {}, ["no review"]
            for turn in ("", ":retry"):           # an incomplete review is asked once more
                try:
                    review = await generator.review(f"harness_verifier:measured:{name}:{number}{turn}", brief, code,
                                                    draft)
                except Exception as exc:
                    review = {"checks": [], "summary": f"review raised {type(exc).__name__}: {exc}"}
                incomplete = review_problems(review)
                if not incomplete:
                    break
            store.write_json(attempt / "independent-review.json", review)
            failed_checks = [c for c in review.get("checks", []) if c.get("status") == "FAIL"]
            review_feedback = [f"Independent review {c.get('check_id')} FAIL: {c.get('evidence')}" for c in failed_checks]
            if incomplete:
                # Not a pass: a review that skipped, repeated or invented checks did not examine the draft.
                record["review_incomplete"] = incomplete
                failed_checks = failed_checks + [{"check_id": "REVIEW_INCOMPLETE", "status": "FAIL",
                                                  "evidence": "; ".join(incomplete)}]
            record["review_passed"] = not failed_checks
            record["review_failed_checks"] = [c.get("check_id") for c in failed_checks]

            if not settings.build:
                record["status"] = bridge.STATUS_GENERATED_NOT_BUILT
                record["reason"] = "build disabled"
                break
            # Inlined functions would look unexecuted in the per-function report.
            # The caller's flags must survive: a program may need one to build at all
            # (e.g. -fcommon for pre-C99 tentative definitions in a header).
            previous_flags = os.environ.get("HARNESSCREATOR_NATIVE_EXTRA_CFLAGS")
            os.environ["HARNESSCREATOR_NATIVE_EXTRA_CFLAGS"] = ((previous_flags or "") + " -fno-inline").strip()
            try:
                binary, diagnostics, repairable = await bridge._build(settings, store, attempt, harness)
            finally:
                if previous_flags is None:
                    os.environ.pop("HARNESSCREATOR_NATIVE_EXTRA_CFLAGS", None)
                else:
                    os.environ["HARNESSCREATOR_NATIVE_EXTRA_CFLAGS"] = previous_flags
            if binary is None:
                record["status"] = STATUS_BUILD_FAILED
                record["reason"] = "native build: " + diagnostics[-3000:]
                if not repairable:
                    break
                feedback = ["Build failed:\n" + diagnostics[-6000:], *review_feedback]
                continue
            record["built"] = True
            record["binary"] = str(binary)

            results = await asyncio.to_thread(replay, binary, seeds, settings.run_dir / attempt / "replay", source_name)
            store.write_json(attempt / "replay.json", {"seeds": results})
            findings = program_findings(results)
            store.write_json(attempt / "program-findings.json", {
                "note": "sanitizer reports located in the original program's code while replaying seeds the original "
                        "accepted; not yet reproduced on a sanitizer build of the original program itself",
                "findings": findings})
            record["program_findings"] = len(findings)
            bad = [item for item in results if not item["ok"]]
            record["seeds_replayed"], record["seeds_replay_ok"] = len(results), len(results) - len(bad)
            if bad:
                record["status"] = STATUS_REPLAY_FAILED
                record["reason"] = (f"{len(bad)} of {len(results)} verified seeds did not replay cleanly: "
                                    + ", ".join(item["seed_id"] for item in bad[:6]))
                feedback = [
                    "The built harness did not replay seeds that the original program accepted. "
                    f"{len(bad)} of {len(results)} failed. Example {item['seed_id']} ({item['bytes']} bytes): "
                    f"exit {item['returncode']}" + (", timed out" if item["timed_out"] else "")
                    + (", sanitizer report" if item["sanitizer_report"] else "") + "\n" + item["output_tail"]
                    for item in bad[:2]] + review_feedback
                continue

            record["executions_per_second"] = await asyncio.to_thread(
                executions_per_second, binary, min(seeds, key=lambda seed: len(seed.data)),
                settings.run_dir / attempt / "replay")
            measured_results = await asyncio.to_thread(equivalence, binary, measured) if bridge._symbolizer() else []
            usable = [item for item in measured_results if item["measured"]]
            missing = sorted({name for item in usable for name in item["missing"]})
            expected = {name for seed in measured for name in seed.functions_beyond_baseline}
            with_functions = [seed for seed in seeds if seed.functions_beyond_baseline]
            store.write_json(attempt / "seed-equivalence.json", {
                "seeds_verified": len(seeds), "seeds_with_functions_beyond_baseline": len(with_functions),
                "seeds_measured": len(usable), "seeds_selected": len(measured),
                "seeds_not_measured": len(with_functions) - len(usable),
                "original_functions": len(expected), "missing_in_harness": missing, "results": measured_results,
                "note": (f"every verified seed up to {EQUIVALENCE_SEED_LIMIT}, the covering seeds first; each result "
                         "compares that seed's own functions beyond the run with no input. Function names are "
                         "compared, so two static functions of one name in different files are not told apart.")})
            record["seed_equivalence"] = {"seeds_measured": len(usable), "original_functions": len(expected),
                                          "seeds_not_measured": len(with_functions) - len(usable),
                                          "missing_in_harness": len(missing)}
            if not usable:
                record["status"] = STATUS_REPLAYED
                record["reason"] = f"built; {len(results)} seeds replayed cleanly; seed equivalence was not measurable"
                break
            if missing:
                record["status"] = STATUS_MISMATCH
                record["reason"] = (f"{len(expected) - len(missing)} of {len(expected)} functions the original executed "
                                    f"for the seeds were also executed in the harness; not executed: "
                                    + ", ".join(missing[:25])
                                    + ". Functions run by background threads or during shutdown of the original can "
                                      "appear here without a harness defect; see seed-equivalence.json.")
                if missing == previous_missing:
                    break  # another draft left the same functions out: rewriting again will not change it
                previous_missing = missing
                feedback = [
                    "The harness replayed every verified seed without error, but it did not execute these functions "
                    "that the original program executed for the same seeds: " + ", ".join(missing[:80])
                    + ". Typical causes: the harness returns before the program has processed the whole input, it "
                    "delivers the bytes through a different path, or the program was started with other arguments.",
                    *review_feedback]
                continue
            if failed_checks:
                record["status"] = STATUS_EQUIVALENT_REVIEW_FAILED
                record["reason"] = (f"built, {len(results)} seeds replayed cleanly and executed the same functions as the "
                                    "original, but the independent review failed: "
                                    + "; ".join(f"{c.get('check_id')}: {str(c.get('evidence'))[:200]}" for c in failed_checks))
                feedback = review_feedback
                continue
            record["status"] = STATUS_EQUIVALENT
            record["reason"] = (f"built ({record.get('executions_per_second')} executions/s on a small seed); "
                                f"{len(results)} verified seeds replayed without a harness fault; "
                                f"{len(usable)} seeds covering {len(expected)} functions executed the same functions "
                                "as the original; independent review has no FAIL. "
                                + (f"{len(findings)} sanitizer finding(s) located in the original program are listed in "
                                   "program-findings.json. " if findings else "")
                                + "Not QUALIFIED: no fuzzing run and no crash attribution yet.")
            break
    finally:
        await close_llm_session(llm, session)
    best = max(row["attempts"], key=lambda item: (_PROGRESS.get(item["status"], 0), item["attempt"]),
               default={"status": STATUS_NO_CODE, "reason": row["reason"], "attempt": None})
    for key in ("generated", "review_passed", "built", "seeds_replayed", "seeds_replay_ok", "status", "reason",
                "attempt", "harness_source", "binary", "seed_equivalence", "shape", "review_failed_checks",
                "program_findings", "executions_per_second"):
        if key in best:
            row[key] = best[key]
    store.write_json(unit_dir / "status.json", row)
    return row


def add_measured_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--legacy-generator", action="store_true",
                        help="use the Action workflow's generator and static gate instead of the measured generator")
    parser.add_argument("--server-args", default=None,
                        help="command-line arguments of the original program used when the seeds were verified "
                             "(without the program path); default: recorded by the seeds stage")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="port of the channel used when the seeds were verified")
    parser.add_argument("--reading-turns", type=int, default=30, help="resource limit for source reading")


async def run_measured_harness(args: argparse.Namespace, llm: Any) -> int:
    run_dir = Path(args.run_dir)
    try:
        settings = bridge._settings(args, run_dir)
        graph = bridge.load_graph(run_dir)
        selected = bridge._select(bridge.load_contexts(run_dir), list(args.context or []) or None, args.delivery)
    except (OSError, ValueError) as exc:
        bridge._emit(str(exc))
        return 2
    callgraph = CallGraph.from_run(run_dir)
    store = ArtifactStore(run_dir)
    rows: list[dict[str, Any]] = []
    for context, delivery in selected:
        spec_file = run_dir / "seeds" / f"run-spec-{context['context_id']}-{delivery}.json"
        spec = json.loads(spec_file.read_text(encoding="utf-8")) if spec_file.is_file() else {}
        server_args = shlex.split(args.server_args) if args.server_args is not None else list(spec.get("command", [])[1:])
        port = args.port or int(spec.get("port") or 0)
        bridge._emit(f"{context['context_id']} {delivery}: started (measured generator)")
        row = await _unit(context, delivery, settings=settings, store=store, graph=graph, callgraph=callgraph,
                          llm=llm, server_args=server_args, host=spec.get("host") or args.host, port=port,
                          reading_turns=args.reading_turns)
        rows.append(row)
        bridge._write_summary(store, settings, rows)
        bridge._emit(f"{row['context_id']} {row['delivery']}: {row['status']} - {row['reason']}")
    if not selected:
        bridge._emit("no input context selected (use --context)")
        return 1
    return 0 if all(row["status"] in (STATUS_EQUIVALENT, STATUS_REPLAYED) for row in rows) else 1
