"""Read a HarnessCreator run: functions, call graph, input context, harnesses and seeds.

FuzzingBrain V2 obtains function metadata, call edges and per-fuzzer reachability
from Fuzz Introspector (paper §3.3.1).  HarnessCreator already produced the same
facts for the original program, plus a measured harness per input channel, so
they are reused here instead of an OSS-Fuzz build.
"""

from __future__ import annotations

import collections
import dataclasses
import json
import re
import subprocess
from pathlib import Path
from typing import Any


@dataclasses.dataclass
class FunctionInfo:
    function_id: str
    name: str
    file: str
    start_line: int
    end_line: int
    source: str
    signature: str


@dataclasses.dataclass
class Harness:
    harness_id: str
    context_id: str
    delivery: str            # "stream" | "datagram" | "peer_stream" (the harness plays a server the program contacts)
    attempt_dir: Path
    source_path: Path
    binary: Path
    build_plan: Path | None
    command: list[str]       # original program command used when the seeds were verified
    host: str
    port: int
    seeds: list[tuple[str, bytes]]
    trigger: bytes = b""     # peer_stream: sent to the program's endpoint; names the peer as {PEER_HOST}:{PEER_PORT}

    @property
    def name(self) -> str:
        return f"{self.context_id}-{self.delivery}"


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def frame_messages(messages: list[bytes], delivery: str) -> bytes:
    """Whole-harness input from protocol messages (HarnessCreator measured_harness._DatagramSeed)."""
    if delivery == "datagram":
        return b"".join(len(m).to_bytes(2, "big") + m for m in messages if len(m) < 65536)
    if delivery == "peer_stream":
        return b"".join(messages[1:])          # message 1 is the fixed trigger
    return b"".join(messages)


_NM_LINE = re.compile(r"^\S+\s+[tTwW]\s+(?P<name>\S+)(?:\t(?P<file>.+):(?P<line>\d+))?\s*$")


def parse_nm_sites(text: str) -> dict[str, list[tuple[str, int]]]:
    """`nm -l --defined-only` output -> {function name: [(file, line), ...]} (locations only)."""
    sites: dict[str, list[tuple[str, int]]] = collections.defaultdict(list)
    for line in text.splitlines():
        match = _NM_LINE.match(line)
        if match and match.group("file"):
            sites[match.group("name")].append((match.group("file"), int(match.group("line"))))
    return dict(sites)


def defined_function_sites(binary: Path) -> dict[str, list[tuple[str, int]]]:
    out = subprocess.run(["nm", "-l", "--defined-only", str(binary)], capture_output=True, text=True,
                         check=False)
    return parse_nm_sites(out.stdout)


def _same_file(recorded: str, located: str) -> bool:
    a, b = Path(recorded).as_posix().lstrip("./"), Path(located).as_posix()
    return bool(a) and (b == a or b.endswith("/" + a))


def resolve_active_targets(functions: dict[str, "FunctionInfo"], target_ids: list[str], compiled: set[str],
                           sites: dict[str, list[tuple[str, int]]]) -> tuple[list[str], dict[str, str]]:
    """Which target definitions the harness binary actually contains.

    A function is identified by its id (file and line range), never by its name alone: one name can
    name several definitions (opposite #ifdef branches, file-static helpers, other programs).  The
    binary's debug locations decide; a definition none of them falls inside is not compiled.  When
    the binary gives no location for a name that several definitions share, which one is compiled
    is unknown: those definitions are kept and marked ambiguous, never resolved by name.
    Returns (active ids, {id: why it is ambiguous}).
    """
    by_name: dict[str, list[FunctionInfo]] = collections.defaultdict(list)
    for fn in functions.values():
        by_name[fn.name].append(fn)
    active: list[str] = []
    ambiguous: dict[str, str] = {}
    for fid in target_ids:
        fn = functions.get(fid)
        if fn is None or fn.name not in compiled:
            continue
        located = sites.get(fn.name) or []
        if located:
            if any(_same_file(fn.file, file) and fn.start_line <= line <= max(fn.end_line, fn.start_line)
                   for file, line in located):
                active.append(fid)
            continue
        active.append(fid)
        if len(by_name[fn.name]) > 1:
            ambiguous[fid] = (f"the binary has no debug location for `{fn.name}`, which names "
                              f"{len(by_name[fn.name])} definitions")
    return active, ambiguous


def defined_functions(binary: Path) -> set[str]:
    out = subprocess.run(["nm", "--defined-only", str(binary)], capture_output=True, text=True, check=False)
    names = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("t", "T"):
            names.add(parts[2])
    return names


# HarnessCreator's attempt statuses (contexts/measured_harness.py), best first.  None is
# QUALIFIED: stage 1 never claims that, so stage 2 must not wait for it.
_ATTEMPT_RANK = ("BUILT_SEED_EQUIVALENT_NOT_QUALIFIED", "BUILT_SEED_EQUIVALENT_REVIEW_FAILED",
                 "BUILT_REPLAYED_NOT_QUALIFIED", "BUILT_SEED_MISMATCH")
# A harness whose verified seeds did not replay cleanly changes or loses the input before the
# program sees it (or faults by itself): fuzzing it measures the harness, not the program.
_NOT_ANALYSED = frozenset({"BUILT_REPLAY_FAILED", "BUILD_FAILED", "GENERATION_BLOCKED"})


def _admissible(row: dict[str, Any]) -> bool:
    """The attempt's own receipt says it was built and every verified seed replayed cleanly."""
    replayed, ok = int(row.get("seeds_replayed") or 0), int(row.get("seeds_replay_ok") or 0)
    return (str(row.get("status") or "") in _ATTEMPT_RANK and row.get("built") is True
            and replayed > 0 and ok == replayed)


def pick_attempt(hc_run: Path, context_id: str, delivery: str) -> Path:
    base = hc_run / "context-harnesses" / f"{context_id}-{delivery}"
    attempts = sorted((p for p in base.glob("attempt-*") if (p / "build" / "hc-native-fuzzer").is_file()),
                      key=lambda p: int(p.name.split("-")[1]))
    if not attempts:
        raise FileNotFoundError(f"no built harness under {base}")
    status_path = base / "status.json"
    if status_path.is_file():
        receipts = {f"attempt-{row.get('attempt')}": row
                    for row in json.loads(status_path.read_text(encoding="utf-8")).get("attempts") or []}
        # A binary on disk is not a receipt: stage 1 may have stopped between the build and the
        # replay, or written a status without these fields.  Only what it recorded counts.
        usable = [a for a in attempts if _admissible(receipts.get(a.name) or {})]
        if not usable:
            raise FileNotFoundError(f"no built harness under {base} has a receipt of a clean seed replay: "
                                    + ", ".join(f"{a.name}={(receipts.get(a.name) or {}).get('status') or 'none'}"
                                                for a in attempts))
        rank = {status: index for index, status in enumerate(_ATTEMPT_RANK)}
        # Best recorded status, then the latest attempt among equals.
        return min(usable, key=lambda a: (rank[str(receipts[a.name]["status"])], -int(a.name.split("-")[1])))
    # Runs without status.json (older stage 1 output): the latest attempt whose seed-equivalence check
    # found nothing missing.  It is analysed as UNVERIFIED (see attempt_status).
    for attempt in reversed(attempts):
        eq = attempt / "seed-equivalence.json"
        if eq.is_file() and not json.loads(eq.read_text(encoding="utf-8")).get("missing_in_harness"):
            return attempt
    return attempts[-1]


def attempt_status(attempt: Path) -> str:
    """The status stage 1 recorded for this attempt, or why it is unverified."""
    path = attempt.parent / "status.json"
    if not path.is_file():
        return ("UNVERIFIED: no status.json, so the build, the seed replay and the equivalence check are "
                "not on record for this attempt")
    for row in json.loads(path.read_text(encoding="utf-8")).get("attempts") or []:
        if f"attempt-{row.get('attempt')}" == attempt.name:
            return str(row.get("status") or "")
    return ""


class Project:
    def __init__(self, hc_run: Path, context_id: str, deliveries: list[str]):
        self.hc_run = Path(hc_run).resolve()
        project = json.loads((self.hc_run / "project.json").read_text(encoding="utf-8"))
        self.source_root = Path(project["source_root"]).resolve()
        self.name = project.get("name") or self.source_root.name
        database = project.get("analysis_compile_database")
        self.compile_database = Path(database) if database and Path(database).is_file() else None
        self.functions: dict[str, FunctionInfo] = {}
        for row in _rows(self.hc_run / "analysis" / "functions.jsonl"):
            self.functions[row["function_id"]] = FunctionInfo(
                row["function_id"], row["name"], row.get("file", ""), int(row.get("start_line") or 0),
                int(row.get("end_line") or 0), row.get("source") or "", row.get("signature") or "")
        self.by_name: dict[str, list[FunctionInfo]] = collections.defaultdict(list)
        for fn in self.functions.values():
            self.by_name[fn.name].append(fn)
        self.callees: dict[str, set[str]] = collections.defaultdict(set)
        self.callers: dict[str, set[str]] = collections.defaultdict(set)
        for edge in _rows(self.hc_run / "analysis" / "edges.jsonl"):
            a, b = self.functions.get(edge.get("caller_id")), self.functions.get(edge.get("callee_id"))
            if a and b:
                self.callees[a.name].add(b.name)
                self.callers[b.name].add(a.name)
        contexts = {row["context_id"]: row for row in _rows(self.hc_run / "contexts" / "contexts.jsonl")}
        if context_id not in contexts:
            raise KeyError(f"context {context_id} not in {self.hc_run}/contexts/contexts.jsonl")
        self.context = contexts[context_id]
        self.context_id = context_id
        self.harnesses: dict[str, Harness] = {}
        compiled: set[str] = set()
        sites: dict[str, list[tuple[str, int]]] = {}
        for delivery in deliveries:
            attempt = pick_attempt(self.hc_run, context_id, delivery)
            spec_path = self.hc_run / "seeds" / f"run-spec-{context_id}-{delivery}.json"
            spec = json.loads(spec_path.read_text(encoding="utf-8")) if spec_path.is_file() else {}
            harness = Harness(
                harness_id=f"h-{delivery}", context_id=context_id, delivery=delivery, attempt_dir=attempt,
                source_path=attempt / "fuzz_target.c", binary=attempt / "build" / "hc-native-fuzzer",
                build_plan=(attempt / "build" / ".native-build" / "build-plan.json"),
                command=list(spec.get("command") or []), host=spec.get("host") or "127.0.0.1",
                port=int(spec.get("port") or 0), seeds=self._seeds(delivery),
                trigger=self._trigger(context_id, delivery))
            self.harnesses[harness.harness_id] = harness
            compiled |= defined_functions(harness.binary)
            for name, located in defined_function_sites(harness.binary).items():
                sites.setdefault(name, []).extend(located)
        self.compiled = compiled
        # FBv2 restricts a worker to functions its fuzzer reaches; here: reached from the
        # context's interpreters AND present in the harness binary -- by definition, not by name.
        self.target_ids, self.ambiguous_ids = resolve_active_targets(
            self.functions, list(self.context.get("target_function_ids", [])), compiled, sites)
        self.target_names = {self.functions[f].name for f in self.target_ids}
        self.interpreter_names = [self.functions[f].name for f in self.context.get("interpreter_function_ids", [])
                                  if f in self.functions]
        self.entries = self.context.get("entries", [])
        self.frontier = _rows(self.hc_run / "seeds" / "frontier.jsonl")
        # Runtime evidence HarnessCreator already measured on this program.
        # executed_names: functions a verified normal input actually ran.
        # blocked_names: functions its frontier judged to need another startup option or channel,
        #   i.e. facts about this harness configuration, not guesses.
        self.executed_names: set[str] = set()
        for path in sorted((self.hc_run / "seeds" / "corpus" / context_id).glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            self.executed_names |= set(raw.get("target_functions_beyond_baseline_whole_input")
                                       or raw.get("target_functions_beyond_baseline") or [])
            # Everything the verified input executed, startup included: a function every run
            # executes is executed by this input too.  "Beyond baseline" alone made files whose
            # functions run only at startup look never executed (closed_files).
            self.executed_names |= {self.functions[fid].name for fid in raw.get("covered_target_function_ids") or []
                                    if fid in self.functions}
        self.blocked_names: set[str] = {
            row["target_function"] for row in self.frontier
            if row.get("target_function") and row.get("blocked_reason") in
            ("NEEDS_STARTUP_OPTION", "NEEDS_OTHER_CHANNEL")}
        self.reached_names: set[str] = {
            row["target_function"] for row in self.frontier
            if row.get("target_function") and row.get("outcome") == "REACHED"}
        self.executed_names |= self.reached_names
        # A file in which no function was ever executed is a feature this configuration does not
        # open (memcached: the proxy needs a startup option). Used to rank, and to warn the
        # invariant recorder, never to claim unreachability.
        by_file: dict[str, set[str]] = collections.defaultdict(set)
        for fid in self.target_ids:
            fn = self.functions[fid]
            by_file[fn.file].add(fn.name)
        self.closed_files: set[str] = {file for file, names in by_file.items()
                                       if names and not (names & self.executed_names)}

    def site_evidence(self, function_name: str, file: str = "") -> dict[str, Any]:
        """What was measured about reaching this function with this harness."""
        return {
            "executed_by_a_verified_normal_input": function_name in self.executed_names,
            "needs_another_startup_option_or_channel": function_name in self.blocked_names,
            "no_function_of_this_file_was_ever_executed": bool(file) and file in self.closed_files,
        }

    def _trigger(self, context_id: str, delivery: str) -> bytes:
        path = self.hc_run / "seeds" / f"peer-trigger-{context_id}-{delivery}.json"
        if delivery != "peer_stream" or not path.is_file():
            return b""
        return bytes.fromhex(json.loads(path.read_text(encoding="utf-8")).get("trigger_hex", ""))

    def _seeds(self, delivery: str) -> list[tuple[str, bytes]]:
        out = []
        for path in sorted((self.hc_run / "seeds" / "corpus" / self.context_id).glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw.get("delivery") != delivery:
                continue
            messages = [bytes.fromhex(m) for m in raw.get("messages_hex") or []]
            out.append((raw.get("seed_id") or path.stem, frame_messages(messages, delivery)))
        return out

    # -- lookups ---------------------------------------------------------------
    def function(self, name: str, function_id: str = "") -> FunctionInfo | None:
        """The definition meant: by id when known, else the one active target definition of the name."""
        if function_id and function_id in self.functions:
            return self.functions[function_id]
        candidates = self.by_name.get(name) or []
        if not candidates:
            return None
        active = [fn for fn in candidates if fn.function_id in self.target_ids]
        return (active or candidates)[0]

    def active_ids(self, name: str) -> list[str]:
        """Ids of this name's target definitions the harness binary contains (several for file-static twins)."""
        return sorted(fid for fid in self.target_ids if self.functions[fid].name == name)

    def reachable_from(self, names: list[str], limit: int | None = None) -> list[str]:
        seen: list[str] = []
        queue = collections.deque(n for n in names if n in self.target_names)
        visited = set(queue)
        while queue:
            name = queue.popleft()
            seen.append(name)
            for callee in sorted(self.callees.get(name, ())):
                if callee in self.target_names and callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
            if limit and len(seen) >= limit:
                break
        return seen

    def facts(self) -> dict[str, Any]:
        """HarnessCreator-measured facts given to the threat model and direction agents."""
        blocked = collections.Counter(row.get("blocked_reason") for row in self.frontier if row.get("blocked_reason"))
        needs_option = sorted({row.get("target_function") for row in self.frontier
                               if row.get("blocked_reason") == "NEEDS_STARTUP_OPTION" and row.get("target_function")})
        other_channel = sorted({row.get("target_function") for row in self.frontier
                                if row.get("blocked_reason") == "NEEDS_OTHER_CHANNEL" and row.get("target_function")})
        return {
            "program": self.name,
            "input_entries": [{k: e.get(k) for k in ("entry_function", "source_api", "channel_kind",
                                                      "attacker_control", "delivery")} for e in self.entries],
            "interpreter_functions": self.interpreter_names,
            "driver_function": self.context.get("driver_function"),
            "harnesses": {h.harness_id: {"delivery": h.delivery, "program_command": h.command, "port": h.port,
                                         "verified_normal_inputs": len(h.seeds)} for h in self.harnesses.values()},
            "reachable_compiled_functions": len(self.target_names),
            "functions_needing_a_different_startup_option": needs_option[:60],
            "functions_needing_another_channel": other_channel[:60],
            "frontier_blocked_reason_counts": dict(blocked),
            "functions_executed_by_a_verified_normal_input": len(self.executed_names),
            "source_files_whose_functions_were_never_executed": sorted(self.closed_files)[:40],
        }


_LINE_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+)$")


def parse_location(text: str) -> tuple[str, int] | None:
    match = _LINE_RE.match((text or "").strip())
    return (match.group("file"), int(match.group("line"))) if match else None
