from __future__ import annotations

import collections
import dataclasses
import json
import time
from pathlib import Path
from typing import Any, Callable

from ..analysis.graph import GraphStore
from ..llm.base import is_terminal_llm_infrastructure_error
from .agents import SeedFrontierAgent, SeedGeneratorAgent, describe_seed, seeds_from_items
from .builder import CallGraph
from .coverage import CoverageUnavailable, GcovCoverage, TargetMap
from .execution import ProgramRunner
from .model import Seed, SeedResult


def _append(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class SeedWorkflow:
    """Seed generation, verification on the original program, and frontier exploration
    for one input context and one delivery.

    Acceptance is measured, not asserted by the model: a seed is accepted when
    running it on the coverage-instrumented original executes target functions
    or lines that a run with no input does not.
    """

    def __init__(self, *, run_dir: Path, context: dict[str, Any], delivery: str, graph: GraphStore,
                 callgraph: CallGraph, llm: Any, runner: ProgramRunner, coverage: GcovCoverage,
                 source_root: Path, artifact_paths: list[str], generator_turns: int = 40,
                 frontier_turns: int = 6, max_frontier_targets: int = 0, time_budget_seconds: float = 0.0,
                 skip_generator: bool = False, explore_lines: bool = False, skip_frontier: bool = False,
                 thread_trace: Any = None,
                 emit: Callable[[str], None] | None = None):
        self.run_dir, self.context, self.delivery = Path(run_dir), context, delivery
        self.graph, self.callgraph, self.llm = graph, callgraph, llm
        self.runner, self.coverage = runner, coverage
        self.source_root, self.artifact_paths = Path(source_root), artifact_paths
        self.generator_turns, self.frontier_turns = generator_turns, frontier_turns
        self.max_frontier_targets, self.time_budget_seconds = max_frontier_targets, time_budget_seconds
        self.skip_generator = skip_generator
        self.explore_lines = explore_lines
        self.skip_frontier = skip_frontier
        self.thread_trace = thread_trace  # (ProgramRunner, trace file, SymbolTable) or None
        self.instrumented_lines: dict[str, set[int]] = collections.defaultdict(set)
        self.emit = emit or (lambda message: None)
        self.context_id = context["context_id"]
        self.out = self.run_dir / "seeds"
        self.key = f"{self.context_id}-{delivery}"
        self.targets = set(context.get("target_function_ids", []))
        self.target_map = TargetMap(
            (dataclasses.asdict(function) for function in graph.bundle.functions.values()), self.targets)
        self.baseline_functions: set[str] = set()
        self.baseline_lines: set[tuple[str, int]] = set()
        self.covered_functions: set[str] = set()
        self.covered_lines: set[tuple[str, int]] = set()
        self.accepted: dict[str, tuple[Seed, list[bytes], set[str]]] = {}
        self.results: dict[str, SeedResult] = {}
        self.counts: collections.Counter[str] = collections.Counter()
        self.started = time.monotonic()
        self.all_targets = set(self.targets)
        self.snapshot: Any = None
        self.infrastructure_error = ""
        # peer_stream: the trigger of the first accepted seed is the one a harness will use, so later
        # seeds must use it too (only the peer's bytes are fuzzed).
        self.peer_trigger: bytes | None = None

    # ---- execution -------------------------------------------------------

    def _name(self, function_id: str) -> str:
        return self.graph.bundle.functions[function_id].name

    def _out_of_time(self) -> bool:
        return bool(self.time_budget_seconds) and time.monotonic() - self.started >= self.time_budget_seconds

    async def _execute(self, messages: list[bytes], *, paced: bool = True) -> tuple[Any, set[str], set[tuple[str, int]], str]:
        self.coverage.reset()
        observation = await self.runner.run(messages, paced=paced)
        try:
            snapshot = self.coverage.collect()
        except CoverageUnavailable as exc:
            return observation, set(), set(), str(exc)
        self.snapshot = snapshot
        return observation, self.target_map.covered_functions(snapshot), self.target_map.covered_lines(snapshot), ""

    async def baseline(self) -> None:
        observation, functions, lines, problem = await self._execute([])
        if problem:
            raise CoverageUnavailable(
                f"baseline run produced no coverage ({problem}); program exit: {observation.exit_status}; "
                f"delivery error: {observation.error or 'none'}")
        if observation.error:
            raise RuntimeError(f"baseline run failed: {observation.error} (exit {observation.exit_status})")
        # Target functions that are not compiled into this build (code behind a
        # configure option, for example) cannot be executed by any input, so
        # they are reported separately and are not explored.
        self.targets = self.all_targets & self.target_map.compiled_functions(self.snapshot)
        for function_id, line in self.target_map.instrumented_lines(self.snapshot):
            if function_id in self.targets:
                self.instrumented_lines[function_id].add(line)
        self.baseline_functions, self.baseline_lines = functions, lines
        self.covered_functions, self.covered_lines = set(functions), set(lines)
        self.emit(f"[SEED] {self.key} baseline: {len(functions)}/{len(self.targets)} target functions run without input "
                  f"({len(self.all_targets) - len(self.targets)} of {len(self.all_targets)} targets are not in this build)")

    async def verify(self, seed: Seed) -> SeedResult:
        if seed.seed_id in self.results:
            return self.results[seed.seed_id]
        if (self.delivery == "peer_stream" and self.peer_trigger is not None
                and (seed.messages[:1] or [b""])[0] != self.peer_trigger):
            result = SeedResult(
                seed_id=seed.seed_id, context_id=self.context_id, delivery=self.delivery,
                status="REJECTED_OTHER_TRIGGER",
                reason="message 1 differs from the fixed trigger of this context; a harness fuzzes only the peer bytes",
                responses_hex=[], covered_target_function_ids=[], new_target_function_ids=[], new_target_lines=0,
                process_exit="not_started")
            self.results[seed.seed_id] = result
            self.counts[result.status] += 1
            _append(self.out / "candidates.jsonl", dataclasses.asdict(seed))
            _append(self.out / "results.jsonl", dataclasses.asdict(result))
            self.emit(f"[SEED] {self.key} {seed.seed_id} {result.status}")
            return result
        observation, functions, lines, problem = await self._execute(seed.messages)
        new_functions = functions - self.covered_functions
        new_lines = lines - self.covered_lines
        beyond_baseline = (functions - self.baseline_functions) or (lines - self.baseline_lines)
        if problem:
            status, reason = "COVERAGE_UNAVAILABLE", problem
        elif observation.error and not beyond_baseline:
            status, reason = "RUN_FAILED", observation.error
        elif not beyond_baseline:
            status, reason = "REJECTED_NO_TARGET", "executed no target function or line beyond the run with no input"
        elif new_lines or new_functions:
            status, reason = "ACCEPTED_NEW", f"{len(new_functions)} new target functions, {len(new_lines)} new target lines"
        else:
            status, reason = "ACCEPTED_REDUNDANT", "reached target code already covered by earlier seeds"
        result = SeedResult(
            seed_id=seed.seed_id, context_id=self.context_id, delivery=self.delivery, status=status, reason=reason,
            responses_hex=[response.hex() for response in observation.responses],
            covered_target_function_ids=sorted(functions), new_target_function_ids=sorted(new_functions),
            new_target_lines=len(new_lines), process_exit=observation.exit_status)
        self.results[seed.seed_id] = result
        self.counts[status] += 1
        _append(self.out / "candidates.jsonl", dataclasses.asdict(seed))
        _append(self.out / "results.jsonl", dataclasses.asdict(result))
        if status == "ACCEPTED_NEW":
            if self.delivery == "peer_stream" and self.peer_trigger is None:
                self.peer_trigger = (seed.messages[:1] or [b""])[0]
                self.context["peer_trigger"] = self.peer_trigger.decode("latin-1")
                (self.out / f"peer-trigger-{self.key}.json").write_text(json.dumps({
                    "context_id": self.context_id, "trigger_hex": self.peer_trigger.hex(),
                    "trigger_text": self.peer_trigger.decode("latin-1"), "seed_id": seed.seed_id,
                    "placeholders": ["{PEER_HOST}", "{PEER_PORT}"]}, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
            self.covered_functions |= functions
            self.covered_lines |= lines
            self.accepted[seed.seed_id] = (seed, observation.responses, functions)
            corpus = self.out / "corpus" / self.context_id
            corpus.mkdir(parents=True, exist_ok=True)
            (corpus / f"{seed.seed_id}.json").write_text(json.dumps({
                "seed_id": seed.seed_id, "context_id": self.context_id, "delivery": self.delivery,
                "messages_hex": seed.messages_hex, "responses_hex": result.responses_hex,
                "covered_target_function_ids": result.covered_target_function_ids,
                "target_functions_beyond_baseline": sorted(
                    self._name(fid) for fid in functions - self.baseline_functions),
                "origin": seed.origin, "rationale": seed.rationale}, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
            (corpus / f"{seed.seed_id}.bin").write_bytes(seed.harness_bytes)
        self.emit(f"[SEED] {self.key} {seed.seed_id} {status}: {reason}")
        return result

    async def measure_whole_input_delivery(self) -> dict[str, int]:
        """Run every accepted seed once more the way a fuzz harness delivers it.

        Seeds are verified like an interactive client (a reply is read between
        messages), so time passes between requests.  A harness writes the whole
        input at once.  Code that runs only because time passed (item ageing,
        background maintenance) therefore differs between the two, and the
        harness must be compared with the delivery it actually performs.
        """

        measured = differing = 0
        for seed_id, (seed, _responses, paced_functions) in self.accepted.items():
            _observation, functions, _lines, problem = await self._execute(seed.messages, paced=False)
            path = self.out / "corpus" / self.context_id / f"{seed_id}.json"
            if problem or not path.is_file():
                continue
            record = json.loads(path.read_text(encoding="utf-8"))
            record["target_functions_beyond_baseline_whole_input"] = sorted(
                self._name(fid) for fid in functions - self.baseline_functions)
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            measured += 1
            differing += bool((paced_functions - self.baseline_functions) - functions)
        self.emit(f"[SEED] {self.key} whole-input delivery measured for {measured} seeds; "
                  f"{differing} executed fewer functions than with paced delivery")
        return {"seeds_measured": measured, "seeds_executing_fewer_functions": differing}

    async def measure_request_threads(self) -> dict[str, int]:
        """Record, per accepted seed, the functions run by the thread that ran the Entry function.

        Coverage alone cannot tell request processing from periodic maintenance
        or shutdown work done by other threads.  A build with every function
        instrumented reports the executing thread, and the functions executed by
        the thread(s) that executed this context's Entry function are the
        request path of that seed.
        """

        from .thread_trace import read_trace, request_functions
        runner, trace_file, symbols = self.thread_trace
        entry_names = {entry["entry_function"] for entry in self.context.get("entries", [])
                       if entry.get("delivery") == self.delivery}
        measured = without_entry = 0
        for seed_id, (seed, _responses, _functions) in self.accepted.items():
            path = self.out / "corpus" / self.context_id / f"{seed_id}.json"
            if not path.is_file():
                continue
            trace_file.unlink(missing_ok=True)
            await runner.run(seed.messages, paced=False)
            functions = request_functions(read_trace(trace_file, symbols), entry_names)
            record = json.loads(path.read_text(encoding="utf-8"))
            record["request_thread_functions"] = sorted(functions)
            record["request_thread_trace"] = "measured" if functions else "entry_thread_not_found"
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            measured += bool(functions)
            without_entry += not functions
        self.emit(f"[SEED] {self.key} request-thread functions measured for {measured} seeds "
                  f"({without_entry} without an Entry-executing thread)")
        return {"seeds_measured": measured, "seeds_without_entry_thread": without_entry}

    # ---- frontier --------------------------------------------------------

    def frontier(self) -> list[tuple[str, str, int]]:
        """Target functions not executed yet whose caller was executed, largest unexplored region first."""

        items = []
        for function_id in self.targets - self.covered_functions:
            callers = sorted(self.callgraph.callers.get(function_id, set()) & self.covered_functions,
                             key=lambda fid: (self._name(fid), fid))
            if callers:
                gain = len((self.callgraph.reachable([function_id]) & self.targets) - self.covered_functions)
                items.append((function_id, callers[0], gain))
        items.sort(key=lambda item: (-item[2], self._name(item[0]), item[0]))
        return items

    def _base_seed(self, caller: str) -> dict[str, Any] | None:
        for seed, responses, functions in self.accepted.values():
            if caller in functions and caller not in self.baseline_functions:
                return describe_seed(seed, responses)
        return None

    async def explore(self, agent: SeedFrontierAgent, target: str, caller: str) -> dict[str, Any]:
        attempts: list[dict[str, Any]] = []
        record = {"context_id": self.context_id, "delivery": self.delivery, "target_function_id": target,
                  "target_function": self._name(target), "caller_function": self._name(caller),
                  "turns": 0, "seeds_tried": 0, "outcome": "TURN_BUDGET_EXHAUSTED", "blocked_reason": "",
                  "explanation": ""}
        opened: str | None = None
        try:
            for _ in range(self.frontier_turns):
                record["turns"] += 1
                try:
                    response = await agent.turn(
                        context=self.context, delivery=self.delivery, target_function_id=target,
                        caller_function_id=caller, base_seed=self._base_seed(caller), attempts=attempts,
                        opened_function_id=opened)
                except Exception as exc:  # one failed model session must not end the whole stage
                    record["outcome"] = "MODEL_ERROR"
                    record["explanation"] = f"{type(exc).__name__}: {exc}"
                    if is_terminal_llm_infrastructure_error(exc):
                        self.infrastructure_error = record["explanation"]
                    break
                opened = None
                record["explanation"] = response.get("explanation", "")
                seeds = seeds_from_items(response.get("seeds", []), context_id=self.context_id,
                                         delivery=self.delivery, origin="frontier", target_function_id=target)
                for seed in seeds:
                    result = await self.verify(seed)
                    record["seeds_tried"] += 1
                    attempts.append({**describe_seed(seed, [bytes.fromhex(r) for r in result.responses_hex]),
                                     "status": result.status,
                                     "target_executed": target in result.covered_target_function_ids,
                                     "newly_executed": [self._name(fid) for fid in result.new_target_function_ids][:20]})
                if target in self.covered_functions:
                    record["outcome"] = "REACHED"
                    break
                if response.get("give_up"):
                    record["outcome"] = "GAVE_UP"
                    record["blocked_reason"] = response.get("blocked_reason", "UNKNOWN")
                    break
                wanted = response.get("open_function_id", "")
                if wanted in self.graph.bundle.functions:
                    opened = wanted
                elif not seeds:
                    record["outcome"] = "NO_PROPOSAL"
                    break
        finally:
            await agent.close(self.context_id, self.delivery, target)
        _append(self.out / "frontier.jsonl", record)
        self.emit(f"[FRONTIER] {self.key} {record['target_function']}: {record['outcome']} "
                  f"{record['blocked_reason']}".rstrip())
        return record

    def line_frontier(self) -> list[tuple[str, list[int]]]:
        """Executed target functions that still have lines no seed executed, most unexecuted lines first.

        A success path that calls no new function (it only runs other lines of
        the same handler) never shows up in the function frontier; this does.
        """

        executed = collections.defaultdict(set)
        for function_id, line in self.covered_lines:
            executed[function_id].add(line)
        items = []
        for function_id in self.covered_functions & self.targets:
            missing = sorted(self.instrumented_lines.get(function_id, set()) - executed[function_id])
            if missing:
                items.append((function_id, missing))
        items.sort(key=lambda item: (-len(item[1]), self._name(item[0]), item[0]))
        return items

    async def explore_function_lines(self, agent: SeedFrontierAgent, function_id: str,
                                     missing: list[int]) -> dict[str, Any]:
        attempts: list[dict[str, Any]] = []
        key = "lines:" + function_id
        record = {"context_id": self.context_id, "delivery": self.delivery, "target_function_id": key,
                  "target_function": self._name(function_id), "caller_function": "", "kind": "lines",
                  "unexecuted_lines_before": len(missing), "unexecuted_lines_after": len(missing),
                  "turns": 0, "seeds_tried": 0, "outcome": "TURN_BUDGET_EXHAUSTED", "blocked_reason": "",
                  "explanation": ""}
        opened: str | None = None
        wanted_lines = set(missing)
        try:
            for _ in range(self.frontier_turns):
                record["turns"] += 1
                try:
                    response = await agent.turn_lines(
                        context=self.context, delivery=self.delivery, function_id=function_id,
                        unexecuted_lines=sorted(wanted_lines), base_seed=self._base_seed(function_id),
                        attempts=attempts, opened_function_id=opened)
                except Exception as exc:
                    record["outcome"] = "MODEL_ERROR"
                    record["explanation"] = f"{type(exc).__name__}: {exc}"
                    if is_terminal_llm_infrastructure_error(exc):
                        self.infrastructure_error = record["explanation"]
                    break
                opened = None
                record["explanation"] = response.get("explanation", "")
                seeds = seeds_from_items(response.get("seeds", []), context_id=self.context_id,
                                         delivery=self.delivery, origin="frontier", target_function_id=function_id)
                reached: set[int] = set()
                for seed in seeds:
                    result = await self.verify(seed)
                    record["seeds_tried"] += 1
                    now = {line for fid, line in self.covered_lines if fid == function_id}
                    hit = sorted(wanted_lines & now)
                    reached |= set(hit)
                    attempts.append({**describe_seed(seed, [bytes.fromhex(r) for r in result.responses_hex]),
                                     "status": result.status, "listed_lines_executed": hit})
                wanted_lines -= reached
                record["unexecuted_lines_after"] = len(wanted_lines)
                if reached:
                    record["outcome"] = "REACHED_ALL" if not wanted_lines else "REACHED_SOME"
                    if not wanted_lines:
                        break
                    continue
                if response.get("give_up"):
                    record["outcome"] = "GAVE_UP" if record["outcome"] == "TURN_BUDGET_EXHAUSTED" else record["outcome"]
                    record["blocked_reason"] = response.get("blocked_reason", "UNKNOWN")
                    break
                wanted = response.get("open_function_id", "")
                if wanted in self.graph.bundle.functions:
                    opened = wanted
                elif not seeds:
                    if record["outcome"] == "TURN_BUDGET_EXHAUSTED":
                        record["outcome"] = "NO_PROPOSAL"
                    break
        finally:
            await agent.close(self.context_id, self.delivery, key)
        _append(self.out / "frontier.jsonl", record)
        self.emit(f"[FRONTIER] {self.key} lines of {record['target_function']}: {record['outcome']} "
                  f"({record['unexecuted_lines_before']} -> {record['unexecuted_lines_after']} unexecuted) "
                  f"{record['blocked_reason']}".rstrip())
        return record

    # ---- whole stage -----------------------------------------------------

    async def run(self) -> dict[str, Any]:
        await self.baseline()
        # Candidates from an earlier run of this context are measured again
        # rather than trusted; their old rows are replaced by the new ones.
        mine = lambda row: row.get("context_id") == self.context_id and row.get("delivery") == self.delivery
        earlier = {row["seed_id"]: row for row in _rows(self.out / "candidates.jsonl") if mine(row)}
        for name in ("candidates.jsonl", "results.jsonl"):
            kept = [row for row in _rows(self.out / name) if not mine(row)]
            if (self.out / name).is_file():
                (self.out / name).write_text(
                    "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in kept),
                    encoding="utf-8")
        for row in earlier.values():
            await self.verify(Seed(**row))
        if self.skip_generator:
            candidates, trace = [], {"turns": 0, "opened_functions": [], "opened_artifacts": [], "ended": "skipped"}
        else:
            generator = SeedGeneratorAgent(self.llm, self.graph, self.source_root, max_turns=self.generator_turns)
            candidates, trace = await generator.run(self.context, self.delivery, self.artifact_paths)
        self.emit(f"[SEED] {self.key} generator proposed {len(candidates)} candidates in {trace['turns']} turns "
                  f"({trace['ended']})")
        for seed in candidates:
            await self.verify(seed)

        agent = SeedFrontierAgent(self.llm, self.graph)
        attempted = {row["target_function_id"] for row in _rows(self.out / "frontier.jsonl")
                     if row.get("context_id") == self.context_id and row.get("delivery") == self.delivery
                     and row.get("outcome") != "REACHED"}
        frontier_records = []
        stopped = "frontier_empty"
        while True:
            pending = [item for item in self.frontier() if item[0] not in attempted]
            if not pending:
                break
            if self.skip_frontier:
                stopped = "frontier_skipped"
                break
            if self.infrastructure_error:
                stopped = "model_infrastructure_error"
                break
            if self._out_of_time():
                stopped = "time_budget_exhausted"
                break
            if self.max_frontier_targets and len(frontier_records) >= self.max_frontier_targets:
                stopped = "frontier_target_budget_exhausted"
                break
            target, caller, _ = pending[0]
            attempted.add(target)
            frontier_records.append(await self.explore(agent, target, caller))

        line_records = []
        if self.explore_lines and stopped == "frontier_empty":
            while True:
                pending_lines = [item for item in self.line_frontier() if "lines:" + item[0] not in attempted]
                if not pending_lines:
                    break
                if self.infrastructure_error:
                    stopped = "model_infrastructure_error"
                    break
                if self._out_of_time():
                    stopped = "time_budget_exhausted"
                    break
                if self.max_frontier_targets and len(frontier_records) + len(line_records) >= self.max_frontier_targets:
                    stopped = "frontier_target_budget_exhausted"
                    break
                function_id, missing = pending_lines[0]
                attempted.add("lines:" + function_id)
                line_records.append(await self.explore_function_lines(agent, function_id, missing))
                # A newly executed function may have opened the function frontier again.
                for target, caller, _ in [item for item in self.frontier() if item[0] not in attempted]:
                    attempted.add(target)
                    frontier_records.append(await self.explore(agent, target, caller))

        whole_input = await self.measure_whole_input_delivery()
        request_threads = await self.measure_request_threads() if self.thread_trace else None
        remaining = self.frontier()
        summary = {
            "context_id": self.context_id, "delivery": self.delivery,
            "target_functions": len(self.all_targets),
            "target_functions_in_this_build": len(self.targets),
            "target_functions_not_in_this_build": len(self.all_targets - self.targets),
            "executed_without_input": len(self.baseline_functions),
            "executed_with_seeds": len(self.covered_functions),
            "executed_only_with_seeds": len(self.covered_functions - self.baseline_functions),
            "target_lines_executed_only_with_seeds": len(self.covered_lines - self.baseline_lines),
            "seed_results": dict(self.counts), "corpus_seeds": len(self.accepted),
            "generator": trace,
            "frontier_attempts": dict(collections.Counter(r["outcome"] for r in frontier_records)),
            "frontier_blocked_reasons": dict(collections.Counter(
                r["blocked_reason"] for r in frontier_records if r["blocked_reason"])),
            "line_frontier_attempts": dict(collections.Counter(r["outcome"] for r in line_records)),
            "executed_functions_with_unexecuted_lines": len(self.line_frontier()),
            "frontier_remaining": len(remaining),
            "frontier_remaining_unattempted": len([item for item in remaining if item[0] not in attempted]),
            "stopped": stopped, "model_infrastructure_error": self.infrastructure_error,
            "whole_input_delivery": whole_input, "request_thread_trace": request_threads,
            **({"peer_trigger_hex": self.peer_trigger.hex()} if self.peer_trigger is not None else {}),
            "note": "A budget stop means not examined, not unreachable.",
        }
        (self.out / f"summary-{self.key}.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (self.out / f"coverage-{self.key}.json").write_text(json.dumps({
            "executed_without_input": sorted(self._name(f) for f in self.baseline_functions),
            "executed_only_with_seeds": sorted(self._name(f) for f in self.covered_functions - self.baseline_functions),
            "frontier_remaining": [{"function": self._name(t), "executed_caller": self._name(c), "unexplored_behind": g}
                                   for t, c, g in remaining]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return summary
