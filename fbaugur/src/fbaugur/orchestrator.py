"""The run: linear preparation, three concurrent lanes, then crash confirmation.

    preparation   1 workers -> 2 threat model -> 3 directions
    concurrent    candidate lane | invariant lane | fuzzing lane
    on each crash 4 confirm and report

The candidate lane is FuzzingBrain V2's pipeline (§3.4): per-function SP generation
over the priority pools, verification, PoV generation, with claim-based assignment.
The invariant lane is Code Augur's reason-falsify-refine loop (§4.2-4.3) fed by the
verifier's safety judgments.  The fuzzing lane is FBv2 §3.6 plus Code Augur's
instrumented build.

Error policy is upstream FBv2's: a failed agent, build or replay is recorded and the
lane moves to the next item.  The run stops only on a terminal model condition, the
wall clock, or a harness that cannot start.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import sqlite3
import time
import traceback
from pathlib import Path
from typing import Any

from .agent import (AgentRunner, TerminalLLMError, harness_context, load_prompt, sanitizer_guidance,
                    sanitizer_vuln_types)
from .config import RunConfig
from .fuzzing import GlobalFuzzer, fuzz_candidate
from .index import build_index
from .instrument import Invariant
from .project import Project, parse_location
from .runner import (crash_signature, daemon_replay, fault_key, find_duplicate, finding_type, gdb_violation_state,
                     in_harness, is_finding, load_ub_baseline, program_frames, run_input)
from .store import Store, new_id

POOL_PHASES = [("core", 1), ("core", 2), ("general", 3), ("general", 4)]   # FBv2 Table 2
IDLE = 2.0


FINAL_STATUSES = ("confirmed", "validated", "reported", "not_vulnerability", "needs_review")


def prior_findings(scan_dirs: list[str]) -> list[dict[str, Any]]:
    """Final findings of contexts already analysed in this pipeline run, read-only.

    Each context has its own state.db, so de-duplication used to stop at the context boundary:
    on tinyproxy the second harness context re-found the same use-after-free, over-read and
    one-byte overflow and filed three more advisories for three bugs already reported.  The rows
    keep their crash ids, prefixed with the context directory so a duplicate points at the
    original.
    """
    found: list[dict[str, Any]] = []
    marks = ",".join("?" for _ in FINAL_STATUSES)
    for directory in scan_dirs:
        db = Path(directory) / "state.db"
        if not db.is_file():
            continue
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(f"SELECT crash_id, signature, status, details FROM crashes WHERE status IN ({marks})",
                                FINAL_STATUSES).fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            conn.close()
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item["details"]) if item["details"] else {}
            except ValueError:
                item["details"] = {}
            item["crash_id"] = f"{Path(directory).name}/{item['crash_id']}"
            found.append(item)
    return found


@dataclasses.dataclass
class Worker:
    """FBv2's Worker is one fuzzer x one sanitizer.  The analysis lanes (candidates, verification,
    PoV, invariants) run on the AddressSanitizer worker of each harness; a MemorySanitizer worker
    of the same harness runs its own fuzzer on its own build, because MSan and ASan cannot share
    a binary and only MSan sees reads of uninitialized memory (measured on LightFTP: `PASS` before
    any `USER` reads an uninitialized buffer; the ASan build reports nothing)."""
    worker_id: str
    harness_id: str
    delivery: str
    sanitizer: str = "address+undefined"
    binary: Path | None = None


class Run:
    def __init__(self, run_dir: Path, cfg: RunConfig, *, harnesscreator_src: Path, emit=None):
        self.run_dir = Path(run_dir)
        self.cfg = cfg
        self.emit = emit or (lambda message: None)
        self.store = Store(self.run_dir / "state.db")
        self.project = Project(Path(cfg.hc_run), cfg.context_id, cfg.deliveries)
        self.index = build_index(self.run_dir, self.project, harnesscreator_src=harnesscreator_src,
                                 sanitizer=cfg.sanitizer)
        self.agents = AgentRunner(self.run_dir, cfg, self.store, emit=self.emit)
        self.workers = [Worker(f"w-{h.delivery}", h.harness_id, h.delivery)
                        for h in self.project.harnesses.values()]
        self.fuzzers: dict[str, GlobalFuzzer] = {}
        self.builders: dict[str, Any] = {}
        self.builds: dict[str, int] = {}
        self.deadline = time.time() + cfg.max_hours * 3600
        self.stop = asyncio.Event()
        self.terminal: str = ""
        self.sp_done = asyncio.Event()
        self.draining = False             # final drain after the deadline: confirmation still allowed
        self.prior = prior_findings(cfg.prior_scans)
        # Delta scan (FBv2 POVDeltaStrategy): analyse the functions a diff changes, not the program.
        self.delta = bool(cfg.diff_path)
        if self.delta:
            source = Path(cfg.diff_path)
            if not source.is_file():
                raise FileNotFoundError(f"diff not found: {source}")
            (self.run_dir / "delta.diff").write_text(source.read_text(encoding="utf-8", errors="replace"),
                                                     encoding="utf-8")
        self.delta_changes: list[dict[str, Any]] = []
        self._delta_running: set[str] = set()
        self._build_lock = asyncio.Lock()
        self._last_build = 0.0
        for directory in ("logs", "agents", "reports", "inputs", "povs", "work"):
            (self.run_dir / directory).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ helpers
    def out_of_time(self) -> bool:
        return self.stop.is_set() or time.time() >= self.deadline

    def validation_closed(self) -> bool:
        """Too late to validate -- except during the final drain, which has its own time limit."""
        return self.out_of_time() and not self.draining

    def harness(self, worker: Worker):
        return self.project.harnesses[worker.harness_id]

    def binary_for(self, worker: Worker) -> Path:
        return worker.binary or self.harness(worker).binary

    @property
    def analysis_workers(self) -> list[Worker]:
        return [w for w in self.workers if w.sanitizer != "memory"]

    async def _add_msan_workers(self) -> None:
        """Build each harness once more with MemorySanitizer and add a fuzzing worker for it.

        Skipped with a reason when it cannot work: no clang new enough (the builder refuses clang
        older than 18, which on this kernel fails to start 4 runs in 10), or a build whose runtime
        does not start on a verified normal input.
        """
        for worker in list(self.analysis_workers):
            harness = self.harness(worker)
            from .instrument import InvariantBuilder
            builder = InvariantBuilder(
                source_root=self.project.source_root, harness_source=harness.source_path,
                build_plan=harness.build_plan, work_dir=self.run_dir / "work" / f"{worker.harness_id}-msan-build",
                harnesscreator_src=Path(self.index["harnesscreator_src"]), python=self.cfg.python,
                extra_cflags=self.cfg.native_extra_cflags, sanitizer="memory",
                compile_database=self.project.compile_database)
            try:
                result = await asyncio.to_thread(builder.build, 1, [], self.emit)
            except Exception as exc:                             # MSan is an addition; never fatal
                self.emit(f"[msan] {worker.harness_id}: build did not start ({type(exc).__name__}: {exc})")
                continue
            if not result.ok:
                self.emit(f"[msan] {worker.harness_id}: no MemorySanitizer build -- {result.error.strip()[-300:]}")
                continue
            probe = await asyncio.to_thread(run_input, result.binary, harness.seeds[0][1], timeout=30)
            if "can not mmap the shadow memory" in probe.stderr_tail or probe.timed_out:
                self.emit(f"[msan] {worker.harness_id}: MemorySanitizer runtime does not start; worker skipped")
                continue
            msan = Worker(f"{worker.worker_id}-msan", worker.harness_id, worker.delivery, "memory", result.binary)
            self.workers.append(msan)
            note = f"; the first verified normal input already reports {probe.crash_type}" if probe.crashed else ""
            self.emit(f"[msan] {msan.worker_id}: MemorySanitizer worker on {result.binary}{note}")
            entry = self.index["harnesses"].get(worker.harness_id)
            if entry is not None:                               # the PoV tool replays on it too
                entry["msan_binary"] = str(result.binary)
                (self.run_dir / "index.json").write_text(json.dumps(self.index, ensure_ascii=False),
                                                         encoding="utf-8")

    def _system(self, role: str, harness_id: str, *, extra: str = "", sanitizer: str | None = None) -> str:
        sanitizer = sanitizer or self.cfg.sanitizer
        name = {"sp_generator": "function_analysis_prompt", "sp_verifier": "verify_suspicious_points_prompt",
                "pov": "pov_agent_prompt", "direction": "direction_planning_prompt",
                "report": "pov_report_prompt", "seed": "seed_agent_system_prompt",
                "invariant_recorder": "invariant_record", "threat_model": "threat_model",
                "invariant_repair": "invariant_repair", "triage": "triage", "refine": "refine",
                "delta_sp_generator": "find_suspicious_points_prompt", "vuln_validator": "vuln_validator"}[role]
        if role == "sp_verifier" and getattr(self, "delta", False):
            name = "verify_suspicious_points_delta_prompt"     # FBv2: confirm the bug, skip reachability
        body = load_prompt(name)
        if role == "delta_sp_generator":
            # FBv2 DeltaSPGenerator.system_prompt, verbatim wording.
            body += (f"\n\n## Sanitizer-Specific Patterns: {sanitizer}\n\nFocus ONLY on these bug types "
                     "(other bugs won't be detected by this sanitizer):\n" + sanitizer_guidance(sanitizer))
        if role in ("sp_generator", "sp_verifier", "direction"):
            # Upstream prompts carry {fuzzer}/{sanitizer}/{sanitizer_patterns} placeholders.
            body = body.replace("{fuzzer}", harness_id).replace("{sanitizer}", sanitizer)
            body = body.replace("{sanitizer_patterns}", sanitizer_guidance(sanitizer))
        if role == "sp_verifier":
            body += load_prompt("verify_safety_addendum")
        if role == "report":
            body += load_prompt("advisory_addendum")
        if "{project}" in body:
            body = body.replace("{project}", self.index["program"])
        return body + "\n" + harness_context(self.index, harness_id, sanitizer) + extra

    async def lane(self, name: str, coroutine) -> None:
        """Run one lane; an unexpected error is logged and the lane ends, never the run.

        Upstream FBv2 does the same per work item (worker/pipeline.py:377): the failure is
        recorded and the pipeline keeps going.
        """
        try:
            await coroutine
        except asyncio.CancelledError:
            raise
        except TerminalLLMError as exc:
            self.terminal = str(exc)
            self.emit(f"TERMINAL in {name}: {exc}")
            self.stop.set()
        except Exception as exc:
            detail = traceback.format_exc()[-3000:]
            self.store.event("lane_error", f"{name}: {type(exc).__name__}: {exc}")
            (self.run_dir / "logs" / "lane-errors.log").open("a", encoding="utf-8").write(
                f"\n=== {time.strftime('%H:%M:%S')} {name}\n{detail}\n")
            self.emit(f"LANE ERROR {name}: {type(exc).__name__}: {exc} (see logs/lane-errors.log)")

    async def _agent(self, role: str, harness_id: str, message: str, *, subject: str = "",
                     extra_system: str = "", **binding: Any):
        try:
            owner = next((w for w in self.workers if w.worker_id == binding.get("worker")), None)
            system = self._system(role, harness_id, extra=extra_system,
                                  sanitizer=owner.sanitizer if owner else None)
            return await self.agents.run(role=role, system=system,
                                         message=message, subject=subject, harness=harness_id, **binding)
        except TerminalLLMError as exc:
            self.terminal = str(exc)
            self.emit(f"TERMINAL: {exc}")
            self.stop.set()
            return None

    # ------------------------------------------------------------------ 1-3 preparation
    async def prepare(self) -> bool:
        self.emit(f"workers: {[(w.worker_id, w.delivery) for w in self.workers]}")
        for worker in self.analysis_workers:
            harness = self.harness(worker)
            result = await asyncio.to_thread(run_input, harness.binary, harness.seeds[0][1], timeout=20)
            if result.crashed or result.timed_out:
                self.emit(f"harness {harness.harness_id} does not run a verified normal input: {result.summary()}")
                return False
        # Undefined behaviour the verified normal inputs already trigger is the program's background
        # noise, not a finding.  Measured once here and shared through a file, because the tool
        # servers that replay PoVs run in their own processes.
        baseline: set[str] = set()
        for worker in self.analysis_workers:
            harness = self.harness(worker)
            for _, blob in harness.seeds:
                result = await asyncio.to_thread(run_input, harness.binary, blob, timeout=20)
                baseline.update(result.ub_sites())
        self.ub_baseline = baseline
        (self.run_dir / "ub-baseline.json").write_text(json.dumps(sorted(baseline)), encoding="utf-8")
        self.emit(f"undefined-behaviour baseline: {len(baseline)} site(s) reached by normal inputs"
                  + (f" {sorted(baseline)[:5]}" if baseline else ""))
        if self.cfg.msan:
            await self._add_msan_workers()
        if not self.cfg.skip_threat_model and not self.store.row(
                "SELECT 1 FROM threat_model WHERE harness_scope='project'"):
            facts = json.dumps(self.index["facts"], ensure_ascii=False, indent=2)
            await self._agent("threat_model", self.workers[0].harness_id,
                              f"Write the threat model for `{self.index['program']}`.\n\n"
                              f"## Facts measured by the harness generator\n```json\n{facts}\n```\n",
                              subject=self.index["program"], worker=self.workers[0].worker_id)
        if self.store.row("SELECT 1 FROM threat_model WHERE harness_scope='project'"):
            self.emit("threat model recorded")
        if self.delta:
            return self._prepare_delta()
        for worker in self.workers:
            if self.out_of_time():
                break
            if self.store.scalar("SELECT COUNT(*) FROM directions WHERE harness_id=?", worker.harness_id):
                continue
            await self._agent("direction", worker.harness_id,
                              f"Divide the code this harness reaches into at most {self.cfg.max_directions} "
                              "directions. Read the harness source first, then the program's command dispatch.",
                              subject=worker.harness_id, worker=worker.worker_id)
        self._fill_pools()
        total = self.store.scalar("SELECT COUNT(*) FROM pool WHERE status='pending'")
        self.emit(f"directions: {self.store.scalar('SELECT COUNT(*) FROM directions')}, "
                  f"functions queued: {total}")
        return total > 0 or bool(self.store.scalar("SELECT COUNT(*) FROM sps"))

    def _prepare_delta(self) -> bool:
        """FBv2 POVDeltaStrategy step 1: every changed function, reachable or not, with its distance."""
        from .delta import changed_functions
        roots = [self.index.get("driver")] + list(self.index.get("interpreters") or [])
        diff = (self.run_dir / "delta.diff").read_text(encoding="utf-8", errors="replace")
        source_root = Path(self.project.source_root)

        def read_source(rel: str) -> list[str] | None:
            path = source_root / rel
            return path.read_text(encoding="utf-8", errors="replace").splitlines() if path.is_file() else None

        changes, report = changed_functions(diff, self.index["functions"], self.index["callees"], roots, read_source)
        for entry in report["files"]:
            shifted = sorted({o for o in entry.get("line_offsets", []) if o})
            if shifted:
                self.emit(f"[delta] {entry['diff_file']}: the diff was made against another revision; its hunks "
                          f"were found {', '.join(f'{o:+d}' for o in shifted)} line(s) away in the analysed source "
                          f"and their line numbers moved there")
            if entry.get("unmatched_hunks"):
                self.emit(f"[delta] {entry['diff_file']}: {entry['unmatched_hunks']} hunk(s) do not match the analysed "
                          f"source at all; their line numbers are the diff's own and may point at other code")
        self.delta_changes = [c.as_dict() for c in changes]
        (self.run_dir / "delta-changes.json").write_text(
            json.dumps({"report": report, "changes": self.delta_changes}, ensure_ascii=False, indent=2),
            encoding="utf-8")
        reachable = sum(1 for c in changes if c.static_reachable)
        self.emit(f"[delta] {len(changes)} changed function(s), {reachable} statically reachable from "
                  f"{roots[0]}: " + ", ".join(f"{c.function}{'' if c.static_reachable else '(static-unreachable)'}"
                                              for c in changes))
        if report["unmatched_files"]:
            self.emit(f"[delta] changed files with no function definitions in this program: {report['unmatched_files']}")
        if not changes:
            self.emit("[delta] the diff changes no function of this program; nothing to analyse")
        return bool(changes)

    async def delta_sp_agent(self, worker: Worker) -> None:
        """FBv2 DeltaSPGenerator: one agent reads the diff and analyses every changed function."""
        try:
            if not self.delta_changes or self.out_of_time():
                return
            harness = self.harness(worker)
            fuzzer_code = harness.source_path.read_text(encoding="utf-8", errors="replace")
            reachable = [c for c in self.delta_changes if c["static_reachable"]]
            unreachable = [c for c in self.delta_changes if not c["static_reachable"]]
            listing = ""
            if reachable:
                listing += "### Static-Reachable Functions:\n" + "".join(
                    f"- {c['function']} ({c['file']})\n  Distance: {c['distance']}\n" for c in reachable) + "\n"
            if unreachable:
                listing += ("### Static-Unreachable Functions (MAY BE REACHABLE VIA FUNCTION POINTERS!):\n"
                            + "".join(f"- {c['function']} ({c['file']})\n  Warning: Check for function pointer "
                                      "patterns!\n" for c in unreachable) + "\n")
            fuzzer = worker.harness_id
            # FBv2 DeltaSPGenerator.get_initial_message, same structure and wording.
            message = (f"Analyze the code changes for potential vulnerabilities.\n\n"
                       f"## Your Target Configuration (FIXED - cannot change)\n\n"
                       f"**Fuzzer**: `{fuzzer}`\n**Sanitizer**: `{worker.sanitizer}`\n\n"
                       f"Only find vulnerabilities that are:\n1. REACHABLE from `{fuzzer}` (verify call path exists)\n"
                       f"2. DETECTABLE by `{worker.sanitizer}` sanitizer (bug type must match)\n\n"
                       f"## Fuzzer Source Code (CRITICAL - READ THIS FIRST!)\n\nThis code shows EXACTLY how input "
                       f"enters the target library.\nVulnerabilities must be reachable through this entry point.\n\n"
                       f"```c\n{fuzzer_code}\n```\n\n"
                       f"## Changed Functions (ALL - including static-unreachable)\n\n**IMPORTANT**: Analyze ALL "
                       f"functions below, even those marked as static-unreachable!\nStatic analysis cannot track "
                       f"function pointer calls.\n\n{listing}"
                       f"## Your Task\n\nFollow these steps IN ORDER:\n\n1. **READ THE DIFF**: Call get_diff to see "
                       f"what code was changed\n\n2. **ANALYZE ALL CHANGED FUNCTIONS** (including static-unreachable!):"
                       f"\n   - Read each function's source code with get_function_source\n   - Look for "
                       f"{worker.sanitizer}-detectable vulnerabilities:\n     - {sanitizer_vuln_types(worker.sanitizer)}"
                       f"\n\n3. **CREATE SUSPICIOUS POINTS**: For each potential vulnerability:\n   - One SP per unique "
                       f"root cause (not per symptom)\n   - Use control flow description, not line numbers\n   - Set "
                       f"confidence score based on vulnerability clarity\n   - Include static_reachable info if known"
                       f"\n\n**IMPORTANT**: Do NOT skip static-unreachable functions! They may be reachable via "
                       f"function pointers.\nThe Verify agent will judge actual reachability later.\n")
            await self._agent("delta_sp_generator", worker.harness_id, message, subject="delta",
                              worker=worker.worker_id, direction="delta", function="")
        finally:
            self._delta_running.discard(worker.worker_id)
            if not self._delta_running:
                self.sp_done.set()

    def _fill_pools(self) -> None:
        """FBv2 priority pools: core/general x not-yet-analysed/analysed (Table 2).

        Two measured facts from HarnessCreator are applied on top:
        a function its frontier judged to need another startup option or channel cannot be
        reached with this harness, so it is left out; and within each phase, functions a
        verified normal input actually executed come first.  Everything else stays in the
        pool: not having been executed yet is what fuzzing is for.
        """
        now = time.time()
        skipped = 0
        for worker in self.workers:
            # Per worker: FBv2 pools belong to one {fuzzer, sanitizer} worker, and a function the
            # ASan worker has analysed is still unanalysed for MemorySanitizer bugs.
            analysed: set[str] = set()
            directions = self.store.rows("SELECT * FROM directions WHERE harness_id=?", worker.harness_id)
            for direction in directions:
                core = [f for f in (direction["entry_functions"] or []) + (direction["core_functions"] or [])
                        if f in self.project.by_name]
                general = [f for f in self.project.reachable_from(core) if f not in core]
                limit = self.cfg.max_function_analyses or 10 ** 6
                for pool, names in (("core", core), ("general", general)):
                    for name in dict.fromkeys(names):
                        if name in self.project.blocked_names:
                            skipped += 1
                            continue
                        phase = (1 if pool == "core" and name not in analysed else
                                 2 if pool == "core" else
                                 3 if name not in analysed else 4)
                        if name not in self.project.executed_names:
                            phase += 4            # no runtime evidence yet: analyse after the rest
                        existing = self.store.row(
                            "SELECT 1 FROM pool WHERE worker_id=? AND direction_id=? AND function_name=?",
                            worker.worker_id, direction["direction_id"], name)
                        if existing:
                            continue
                        if self.store.scalar("SELECT COUNT(*) FROM pool WHERE worker_id=?",
                                             worker.worker_id) >= limit:
                            break
                        self.store.insert("pool", {
                            "worker_id": worker.worker_id, "direction_id": direction["direction_id"],
                            "function_name": name, "pool": pool, "phase": phase, "status": "pending",
                            "updated_at": now})
                        analysed.add(name)
        if skipped:
            self.emit(f"pool: left out {skipped} function(s) measured to need another startup option "
                      f"or channel")

    # ------------------------------------------------------------------ candidate lane
    async def sp_generator_agent(self, worker: Worker, slot: int) -> None:
        while not self.out_of_time():
            item = self.store.claim("pool", "rowid",
                                    where="status='pending' AND worker_id=?", args=(worker.worker_id,),
                                    set_status="analysing", order="phase ASC, rowid ASC")
            if item is None:
                busy = self.store.scalar("SELECT COUNT(*) FROM pool WHERE status IN ('pending','analysing')")
                if not busy:
                    self.sp_done.set()
                    return
                await asyncio.sleep(IDLE)
                continue
            name = item["function_name"]
            function = self.project.function(name)
            if function is None or not function.source:
                self.store.update("pool", "rowid", item["rowid"], {"status": "skipped",
                                                                   "error": "no source", "updated_at": time.time()})
                continue
            callers = sorted(self.project.callers.get(name, ()))[:12]
            callees = sorted(self.project.callees.get(name, ()))[:20]
            numbered = "\n".join(f"{function.start_line + i:6d}  {line}"
                                 for i, line in enumerate(function.source.splitlines()))
            message = (f"Analyze this function for {worker.sanitizer}-detectable vulnerabilities "
                       f"({sanitizer_vuln_types(worker.sanitizer)}).\n\n"
                       f"## Target function `{name}`\nFile: `{function.file}`  "
                       f"Lines: {function.start_line}-{function.end_line}\n```c\n{numbered}\n```\n\n"
                       f"## Callers\n{callers or '(none recorded)'}\n\n## Callees\n{callees or '(none recorded)'}\n\n"
                       "If you find issues, call create_suspicious_point for each. If the function is safe, "
                       "say briefly why. Be concise.")
            try:
                result = await self._agent("sp_generator", worker.harness_id, message, subject=name,
                                           worker=worker.worker_id, direction=item["direction_id"],
                                           function=name)
                status = "analysed" if result and result.ok else "failed"
                error = result.error[:500] if result and result.error else None
            except asyncio.CancelledError:
                self.store.update("pool", "rowid", item["rowid"],
                                  {"status": "pending", "updated_at": time.time()})
                raise
            except Exception as exc:
                status, error = "failed", f"{type(exc).__name__}: {exc}"
                self.emit(f"[sp_generator] {name}: {error}")
            self.store.update("pool", "rowid", item["rowid"],
                              {"status": status, "error": error, "updated_at": time.time()})

    async def verifier_agent(self, worker: Worker, slot: int) -> None:
        while not self.out_of_time():
            sp = self.store.claim_sp(from_status="pending_verify", to_status="verifying",
                                     worker_id=worker.worker_id, agent=f"verify-{slot}")
            if sp is None:
                if self.sp_done.is_set() and not self.store.scalar(
                        "SELECT COUNT(*) FROM sps WHERE status='pending_verify' AND worker_id=?",
                        worker.worker_id):
                    return
                await asyncio.sleep(IDLE)
                continue
            fields = {k: sp.get(k) for k in ("sp_id", "function_name", "vuln_type", "description",
                                              "score", "important_controlflow")}
            message = (f"Verify this suspicious point.\n\n```json\n"
                       f"{json.dumps(fields, ensure_ascii=False, indent=2)}\n```\n\n"
                       f"Its id for update_suspicious_point is `{sp['sp_id']}`. Read the function and its "
                       "callers before judging. When your verdict rests on a protection that keeps the "
                       "operation safe, record safety_reason and safety_location as the addendum requires.")
            result = await self._agent("sp_verifier", worker.harness_id, message, subject=sp["sp_id"],
                                       worker=worker.worker_id, sp=sp["sp_id"])
            row = self.store.row("SELECT * FROM sps WHERE sp_id=?", sp["sp_id"]) or sp
            score = row.get("score") or 0.0
            important = bool(row.get("is_important"))
            if result is None or not result.ok:
                # An unverified candidate is kept: FBv2 only drops a candidate on a 100% certain FP.
                self.store.update("sps", "sp_id", sp["sp_id"],
                                  {"status": "pending_pov" if score >= self.cfg.pov_min_score else "verified",
                                   "claimed_by": None, "updated_at": time.time()})
                continue
            if score >= self.cfg.pov_min_score and important:
                status = "pending_pov"
            else:
                status = "rejected"
                await self._fp_seed(worker, row)
            self.store.update("sps", "sp_id", sp["sp_id"],
                              {"status": status, "claimed_by": None, "updated_at": time.time()})
            if row.get("safety_reason") and row.get("safety_location"):
                self.store.event("safety", f"{sp['sp_id']} -> invariant candidate")

    async def _fp_seed(self, worker: Worker, sp: dict[str, Any]) -> None:
        """FBv2 §3.6: a false positive is a near miss, so seed the fuzzer around it."""
        if self.out_of_time():
            return
        await self._agent("seed", worker.harness_id,
                          load_prompt("fp_seed_prompt").format(
                              sp_id=sp["sp_id"], function_name=sp["function_name"],
                              vuln_type=sp.get("vuln_type") or "", description=sp.get("description") or "",
                              fuzzer=worker.harness_id, fuzzer_source="(call get_fuzzer_info)"),
                          subject=f"fp:{sp['sp_id']}", worker=worker.worker_id)

    async def pov_agent(self, worker: Worker, slot: int) -> None:
        while not self.out_of_time():
            sp = self.store.claim_sp(from_status="pending_pov", to_status="generating_pov",
                                     worker_id=worker.worker_id, agent=f"pov-{slot}",
                                     min_score=self.cfg.pov_min_score)
            if sp is None:
                if self.sp_done.is_set() and not self.store.scalar(
                        "SELECT COUNT(*) FROM sps WHERE status IN ('pending_verify','verifying','pending_pov') "
                        "AND worker_id=?", worker.worker_id):
                    return
                await asyncio.sleep(IDLE)
                continue
            witness = ""
            if sp.get("witness_path") and Path(sp["witness_path"]).is_file():
                data = Path(sp["witness_path"]).read_bytes()[:2048]
                witness = ("\n## A fuzzer input that already reached the inconsistent state\n"
                           f"{len(data)} bytes, hex:\n```\n{data.hex()}\n```\n"
                           "Start from these bytes and extend them so the state reaches the consumer.\n")
            message = (f"Generate a PoV for this suspicious point.\n\n```json\n"
                       f"{json.dumps({k: sp.get(k) for k in ('sp_id','function_name','vuln_type','description','pov_guidance','verification_notes')}, ensure_ascii=False, indent=2)}\n```\n"
                       + witness + "\nRead the harness source first, then iterate with create_pov.")
            result = await self._agent("pov", worker.harness_id, message, subject=sp["sp_id"],
                                       worker=worker.worker_id, sp=sp["sp_id"])
            crashed = self.store.scalar("SELECT COUNT(*) FROM povs WHERE sp_id=? AND crashed=1", sp["sp_id"])
            if crashed:
                self.store.update("sps", "sp_id", sp["sp_id"],
                                  {"status": "pov_generated", "is_real": 1, "updated_at": time.time()})
                continue
            self.store.update("sps", "sp_id", sp["sp_id"],
                              {"status": "pov_failed", "claimed_by": None, "updated_at": time.time()})
            if not self.out_of_time() and self.cfg.sp_fuzz_seconds:
                fuzzer = self.fuzzers.get(worker.harness_id)
                await fuzz_candidate(self.store, run_dir=self.run_dir, worker=worker.worker_id,
                                     harness=worker.harness_id, binary=self.harness(worker).binary,
                                     sp_id=sp["sp_id"], seconds=self.cfg.sp_fuzz_seconds,
                                     global_corpus=fuzzer.corpus if fuzzer else self.run_dir / "work",
                                     emit=self.emit)

    # ------------------------------------------------------------------ invariant lane
    def _builder(self, harness_id: str):
        from .instrument import InvariantBuilder

        if harness_id not in self.builders:
            harness = self.project.harnesses[harness_id]
            self.builders[harness_id] = InvariantBuilder(
                source_root=self.project.source_root, harness_source=harness.source_path,
                build_plan=harness.build_plan, work_dir=self.run_dir / "work" / harness_id / "invariants",
                harnesscreator_src=Path(self.index["harnesscreator_src"]),
                python=self.cfg.python, extra_cflags=self.cfg.native_extra_cflags,
                compile_database=self.project.compile_database)
        return self.builders[harness_id]

    async def invariant_recorder(self, worker: Worker) -> None:
        seen: set[str] = set()
        while not self.out_of_time():
            rows = self.store.rows(
                "SELECT * FROM sps WHERE worker_id=? AND safety_reason IS NOT NULL AND safety_reason!='' "
                "AND safety_location IS NOT NULL AND status IN ('rejected','verified','pov_failed') "
                "ORDER BY updated_at ASC", worker.worker_id)
            pending = [r for r in rows if r["sp_id"] not in seen
                       and not self.store.scalar("SELECT COUNT(*) FROM invariants WHERE sp_id=?", r["sp_id"])]
            if not pending:
                if self.sp_done.is_set() and not self.store.scalar(
                        "SELECT COUNT(*) FROM sps WHERE status IN ('pending_verify','verifying') AND worker_id=?",
                        worker.worker_id):
                    return
                await asyncio.sleep(IDLE * 2)
                continue
            sp = pending[0]
            seen.add(sp["sp_id"])
            location = parse_location(sp["safety_location"] or "")
            message = ("The verifier judged this suspicious point safe. Commit the invariant(s) behind that "
                       f"judgment.\n\n## Suspicious point\n- function: {sp['function_name']}\n"
                       f"- type: {sp['vuln_type']}\n- description: {sp['description']}\n\n"
                       f"## Why the verifier thinks it is safe\n{sp['safety_reason']}\n\n"
                       f"## Where that relation must hold\n{sp['safety_location']}\n")
            if location:
                message += f"\n## Source around that line\n```c\n{self._window(location)}\n```\n"
            await self._agent("invariant_recorder", worker.harness_id, message, subject=sp["sp_id"],
                              worker=worker.worker_id, sp=sp["sp_id"])

    def _window(self, location: tuple[str, int], before: int = 20, after: int = 8) -> str:
        path = self.project.source_root / location[0]
        if not path.is_file():
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start, end = max(1, location[1] - before), min(len(lines), location[1] + after)
        return "\n".join(f"{i:6d} {'>' if i == location[1] else ' '} {lines[i - 1]}"
                         for i in range(start, end + 1))

    async def build_coordinator(self, worker: Worker) -> None:
        """Rebuild P' when invariants are waiting, batching them (one build is ~30 s)."""
        while not self.out_of_time():
            pending = self.store.rows("SELECT * FROM invariants WHERE status='pending_build'")
            if not pending or time.time() - self._last_build < self.cfg.rebuild_min_interval_seconds:
                if not pending and self.sp_done.is_set() and not self.store.scalar(
                        "SELECT COUNT(*) FROM sps WHERE status IN ('pending_verify','verifying') "
                        "AND worker_id=?", worker.worker_id):
                    return
                await asyncio.sleep(IDLE * 2)
                continue
            async with self._build_lock:
                await self._rebuild(worker)

    async def _rebuild(self, worker: Worker) -> None:
        harness_id = worker.harness_id
        version = self.builds.get(harness_id, 0) + 1
        # Code Augur commits invariants to the project, not to one harness: both harnesses build
        # the same program, so each one tests every surviving invariant. An invariant no normal
        # input ever reached in a previous build is left out (status built_unreached).
        active = self.store.rows(
            "SELECT * FROM invariants WHERE status IN ('pending_build','built','lead') ORDER BY phi_num")
        if not active:
            return
        invariants = [Invariant(num=r["phi_num"], file=r["file"], line=r["line"], expression=r["expression"],
                                distance=bool(r.get("distance"))) for r in active]
        started = time.time()
        self.store.insert("builds", {"harness_id": harness_id, "version": version, "status": "building",
                                     "phis": [i.num for i in invariants], "started_at": started})
        self.emit(f"[build] {harness_id} v{version}: {len(invariants)} invariants")
        builder = self._builder(harness_id)
        try:
            result = await asyncio.to_thread(builder.build, version, invariants, self.emit)
        except Exception as exc:                                  # a broken build must not end the run
            result = None
            self.emit(f"[build] v{version} failed to start: {type(exc).__name__}: {exc}")
        self._last_build = time.time()
        self.builds[harness_id] = version
        if result is None or not result.ok:
            error = (result.error if result else "builder raised")[-4000:]
            blamed = result.failing if result else []
            self.store.conn.execute("UPDATE builds SET status=?, error=?, ended_at=? WHERE harness_id=? AND version=?",
                                    ("failed", error, time.time(), harness_id, version))
            if blamed:
                for phi in blamed:
                    row = self.store.row("SELECT * FROM invariants WHERE phi_num=?", phi)
                    repairs = (row.get("repairs") or 0) if row else 0
                    status = "needs_repair" if repairs < self.cfg.max_repairs else "withdrawn"
                    self.store.update("invariants", "phi_num", phi,
                                      {"status": status, "last_error": error[-2000:], "updated_at": time.time()})
                self.emit(f"[build] v{version} failed; invariants {blamed} sent to repair")
            else:
                # No invariant could be blamed: keep them but do not retry immediately.
                for row in active:
                    if row["status"] == "pending_build":
                        self.store.update("invariants", "phi_num", row["phi_num"],
                                          {"status": "build_blocked", "last_error": error[-2000:],
                                           "updated_at": time.time()})
                self.emit(f"[build] v{version} failed with no attributable invariant")
            return
        self.store.conn.execute("UPDATE builds SET status=?, binary=?, ended_at=? WHERE harness_id=? AND version=?",
                                ("ok", str(result.binary), time.time(), harness_id, version))
        for row in active:
            self.store.update("invariants", "phi_num", row["phi_num"],
                              {"status": "lead" if row["status"] == "lead" else "built",
                               "build_version": version, "updated_at": time.time()})
        await self._measure_reach(worker, result.binary, invariants, result.line_map)
        triaged = [r["phi_num"] for r in active if r["status"] == "lead"]
        fuzzer = self.fuzzers.get(harness_id)
        if fuzzer is not None:
            await fuzzer.swap(result.binary, triaged)
        self.emit(f"[build] {harness_id} v{version} ok in {time.time() - started:.0f}s; fuzzing it now")

    @staticmethod
    def _blame_instrumentation(result, line_map: dict[str, dict[int, int]] | None,
                               *, last_evaluated: bool = False) -> list[int]:
        """Which invariants a sanitizer report from P' points at.

        First by source line: a report from P' names lines of the instrumented copy, and the
        builder recorded which of those lines hold an assertion.  This is how LightFTP's unsafe
        `phi 16` was identified -- UBSan printed `ftpserv.c:1684: applying non-zero offset 8191
        to null pointer`, and line 1684 of the instrumented copy was the assertion.

        A bare SEGV carries no such line, and a build whose DWARF `addr2line` cannot read has
        no file or line in its frames either.  With `last_evaluated` the final reach marker is
        used instead: `fba_phi_reach(N)` runs immediately before the expression of assertion N,
        so under trace the last marker is the assertion that was executing.  That is a guess
        about which assertion, never about whether the instrumentation is at fault, so the
        caller must establish the latter first -- see `_measure_reach`.

        A fault that maps to no assertion blames nothing: this must never silence a real bug.
        """
        if not line_map:
            return []
        blamed: list[int] = []
        sites = [(frame.get("file"), frame.get("line")) for frame in result.frames]
        sites += [(item.get("file"), item.get("line")) for item in result.ubsan]
        for path, line in sites:
            if not path or not line:
                continue
            mapping = line_map.get(str(path))
            if mapping is None:                      # the report may print a relative path
                mapping = next((m for key, m in line_map.items() if key.endswith(str(path))), None)
            if mapping is None:
                continue
            num = mapping.get(int(line)) or mapping.get(str(int(line)))
            if num is not None and num not in blamed:
                blamed.append(int(num))
        # The last-marker guess is only for a fault with no location.  When the faulting program
        # frame (or a UBSan report) names a source line that is not an assertion, the fault
        # happened in program code:
        # blaming the last assertion evaluated there accused two innocent ones on tinyproxy.
        top = program_frames(result.frames)[:1]
        located = bool(top and top[0].get("file") and top[0].get("line")) or \
            any(item.get("file") and item.get("line") for item in result.ubsan)
        if not blamed and last_evaluated and result.reach_order and not located:
            blamed.append(int(result.reach_order[-1]))
        return blamed

    def _record_probe_violation(self, worker: Worker, phi: int, blob: bytes) -> None:
        """File an assertion that fired on a verified normal input for triage.

        Same shape as the row the fuzzing lane writes, so the existing triage and refine
        agents pick it up with no special case.  One row per invariant per build: a seed set
        would otherwise file the same question a dozen times and spend the triage budget on it.
        """
        existing = self.store.row(
            "SELECT violation_id FROM violations WHERE phi_num=? AND harness_id=?",
            phi, worker.harness_id)
        if existing is not None:
            return
        fuzzer = self.fuzzers.get(worker.harness_id)
        stored = fuzzer._store_input(blob, "violation") if fuzzer is not None else None
        if stored is None:
            directory = self.run_dir / "inputs" / "violation"
            directory.mkdir(parents=True, exist_ok=True)
            stored = directory / f"probe-{hashlib.sha1(blob).hexdigest()[:16]}.bin"
            stored.write_bytes(blob)
        now = time.time()
        self.store.insert("violations", {
            "violation_id": new_id("vio"), "phi_num": phi, "harness_id": worker.harness_id,
            "worker_id": worker.worker_id, "input_path": str(stored), "status": "pending",
            "created_at": now, "updated_at": now})
        self.emit(f"[build] invariant phi {phi} fires on a verified normal input; sent to triage")

    async def _drop_unsafe(self, unsafe: dict[int, str], probe_inputs: int) -> None:
        """Withdraw invariants that are unsafe on normal input, and say so in the log."""
        now = time.time()
        for num, reason in sorted(unsafe.items()):
            row = self.store.row("SELECT * FROM invariants WHERE phi_num=?", num)
            if row is None:
                continue
            history = list(row.get("history") or [])
            history.append({"event": "unsafe", "reason": reason, "probe_inputs": probe_inputs, "at": now})
            self.store.update("invariants", "phi_num", num,
                              {"status": "withdrawn_unsafe", "history": history,
                               "last_error": reason, "updated_at": now})
            self.emit(f"[build] invariant phi {num} withdrawn: {reason}")

    async def _measure_reach(self, worker: Worker, binary: Path, invariants: list[Invariant],
                             line_map: dict[str, dict[int, int]] | None = None) -> None:
        """Run verified normal inputs against P' and record which assertions execute.

        Code Augur's feedback rewards getting closer to an invariant, which is useless for an
        assertion no input of this harness can reach (memcached: the proxy and the background
        movers need startup options the harness does not pass).  An assertion that no verified
        normal input reaches is recorded as `built_unreached` and left out of the next build.
        This is a measurement of this harness, not a claim that the site is unreachable.

        The same probe also measures whether each assertion is SAFE on normal input, which is
        a separate question from reachability and is why the probe exists at all.  An invariant
        is a measurement, so on an input the program accepts it must neither fire nor fault.
        Measured on LightFTP: the recorder wrote `params[PATH_MAX*2-1] == 0 || ...` for ftpMLSD,
        and `params` is NULL for every parameterless FTP command, so the assertion itself read
        address 0x1fff and killed the process before libFuzzer executed a single unit.  One such
        invariant disables the whole fuzzing lane, so it is dropped here rather than repaired.
        Probing runs with FBA_PHI_CONTINUE for every invariant so that one firing assertion
        cannot abort the probe and hide the state of all the others.
        """
        probes = [blob for _, blob in self.harness(worker).seeds[:self.cfg.reach_probe_seeds]]
        # The fuzzer's own corpus reaches further than the verified normal inputs do, so a
        # sample of it is probed too: a single thin probe must not condemn a reachable site.
        fuzzer = self.fuzzers.get(worker.harness_id)
        if fuzzer is not None and fuzzer.corpus.is_dir():
            corpus = sorted(fuzzer.corpus.iterdir())
            step = max(1, len(corpus) // max(1, self.cfg.reach_probe_corpus))
            for path in corpus[::step][:self.cfg.reach_probe_corpus]:
                try:
                    probes.append(path.read_bytes())
                except OSError:
                    pass
        if not probes or not invariants:
            return
        numbers = [i.num for i in invariants]
        probe_env = {"FBA_PHI_TRACE": "1", "FBA_PHI_CONTINUE": ",".join(str(n) for n in numbers)}
        reached: set[int] = set()
        unsafe: dict[int, str] = {}
        fired: dict[int, bytes] = {}
        for blob in probes:
            if self.out_of_time():
                return
            result = await asyncio.to_thread(run_input, binary, blob,
                                              timeout=self.cfg.harness_timeout_seconds,
                                              env_extra=probe_env)
            reached.update(result.reached)
            for num in result.violations:
                # An assertion that FIRES is not withdrawn here.  Firing on an input the
                # program accepts is exactly the signal Code Augur's triage is for, and only
                # triage can tell "the assertion was too strong" from "the program really does
                # reach this state".  Measured on LightFTP: `context->RestPoint >= 0` fired on
                # a normal session, and withdrawing it threw away the question of whether REST
                # accepts a negative offset.  So it goes to triage with the input that fired
                # it, and stays in the build.  A FAULTING assertion is different -- it stops
                # the fuzzer from running at all -- and is still withdrawn below.
                fired.setdefault(num, blob)
            if result.crashed:
                # Whether the instrumentation is at fault is settled by the uninstrumented
                # harness, not by guessing: only if the clean build accepts the same input is
                # the fault the assertion's.  If the clean build crashes too, this is the
                # program's own bug and the fuzzing lane reports it as a crash, untouched.
                clean = await asyncio.to_thread(run_input, self.harness(worker).binary, blob,
                                                timeout=self.cfg.harness_timeout_seconds)
                if not clean.crashed:
                    for num in self._blame_instrumentation(result, line_map, last_evaluated=True):
                        unsafe[num] = f"faults on an input the program accepts ({result.crash_type})"
            if len(reached) == len(invariants) and not unsafe:
                break
        if unsafe:
            await self._drop_unsafe(unsafe, len(probes))
            invariants = [i for i in invariants if i.num not in unsafe]
            if not invariants:
                return
        for num, blob in sorted(fired.items()):
            if num not in unsafe:
                self._record_probe_violation(worker, num, blob)
        now = time.time()
        dropped = []
        for invariant in invariants:
            row = self.store.row("SELECT * FROM invariants WHERE phi_num=?", invariant.num)
            if row is None or row["status"] == "lead":
                continue
            history = list(row.get("history") or [])
            if invariant.num in reached:
                if row.get("reached"):
                    continue
                history.append({"event": "reached", "harness": worker.harness_id, "at": now})
                self.store.update("invariants", "phi_num", invariant.num,
                                  {"reached": 1, "history": history, "updated_at": now})
            elif not row.get("reached"):
                probed = {name for name in (row.get("probed_by") or "").split(",") if name}
                probed.add(worker.harness_id)
                values = {"probed_by": ",".join(sorted(probed)), "updated_at": now}
                # Dropping needs two independent measurements to agree: this probe did not reach
                # it, AND no function of its source file was ever executed by a verified normal
                # input (for memcached: the proxy and the automovers need startup options this
                # harness does not pass). A probe miss alone keeps the invariant in the build.
                closed = invariant.file in self.project.closed_files
                if closed and len(probed) >= len(self.workers):
                    history.append({"event": "unreached", "probed_by": sorted(probed),
                                    "probe_inputs": len(probes),
                                    "reason": "no function of this file is executed by a normal input",
                                    "at": now})
                    values.update({"status": "built_unreached", "history": history})
                    dropped.append(invariant.num)
                self.store.update("invariants", "phi_num", invariant.num, values)
        kept = [i.num for i in invariants if i.num not in reached and i.num not in dropped]
        if dropped:
            self.emit(f"[build] invariants {dropped} sit in source files no normal input executes and "
                      "were not reached; left out of the next build")
        if kept:
            self.emit(f"[build] invariants {kept} were not reached by {len(probes)} probe inputs but "
                      "stay in the build (their file is exercised)")

    async def triage_agent(self, worker: Worker) -> None:
        while not self.out_of_time():
            violation = self.store.claim("violations", "violation_id",
                                         where="status='pending' AND harness_id=?", args=(worker.harness_id,),
                                         set_status="triaging")
            if violation is None:
                await asyncio.sleep(IDLE * 2)
                if self.sp_done.is_set() and not self.store.scalar(
                        "SELECT COUNT(*) FROM invariants WHERE harness_id=? AND status IN "
                        "('pending_build','needs_repair','needs_refinement')", worker.harness_id):
                    if not self.store.scalar("SELECT COUNT(*) FROM pool WHERE status IN ('pending','analysing')"):
                        return
                continue
            await self._triage_one(worker, violation)

    async def _triage_one(self, worker: Worker, violation: dict[str, Any]) -> None:
        invariant = self.store.row("SELECT * FROM invariants WHERE phi_num=?", violation["phi_num"])
        if invariant is None:
            return
        build = self.store.row("SELECT binary FROM builds WHERE harness_id=? AND status='ok' "
                               "ORDER BY version DESC LIMIT 1", worker.harness_id)
        data = Path(violation["input_path"]).read_bytes()
        state = ""
        original = ""
        if build and Path(build["binary"]).is_file():
            from .instrument import split_comparison
            operands = [o for o in (split_comparison(invariant["expression"]) or ()) if o not in ("<", "<=", ">", ">=", "==", "!=")]
            state = await asyncio.to_thread(gdb_violation_state, Path(build["binary"]), data,
                                            invariant["phi_num"], list(operands) or [invariant["expression"]])
        plain = await asyncio.to_thread(run_input, self.harness(worker).binary, data, timeout=20)
        original = plain.summary()
        message = (f"Triage this invariant violation.\n\n## Invariant phi {invariant['phi_num']}\n"
                   f"- location: {invariant['file']}:{invariant['line']}\n"
                   f"- expression: `{invariant['expression']}`\n"
                   f"- security property: {invariant['security_property']}\n"
                   f"- why it was believed to hold: {invariant['rationale']}\n\n"
                   f"## Source around the assertion\n```c\n{self._window((invariant['file'], invariant['line']))}\n```\n\n"
                   f"## The violating input\n{len(data)} bytes, hex:\n```\n{data[:1024].hex()}\n```\n\n"
                   f"## Program state at the assertion (debugger)\n```\n{state[:5000]}\n```\n\n"
                   f"## The same input on the program WITHOUT assertions\n{original}\n\n"
                   "Decide REAL_ISSUE, TOO_STRONG or UNDECIDED and call triage_verdict once.")
        result = await self._agent("triage", worker.harness_id, message,
                                   subject=f"phi{invariant['phi_num']}", worker=worker.worker_id,
                                   phi=invariant["phi_num"], violation=violation["violation_id"])
        row = self.store.row("SELECT verdict FROM violations WHERE violation_id=?", violation["violation_id"])
        if not row or not row.get("verdict"):
            self.store.update("violations", "violation_id", violation["violation_id"],
                              {"status": "undecided", "verdict": "UNDECIDED",
                               "notes": (result.error if result else "no verdict"), "updated_at": time.time()})
            self.store.update("invariants", "phi_num", invariant["phi_num"],
                              {"status": "built", "updated_at": time.time()})

    async def refine_agent(self, worker: Worker) -> None:
        while not self.out_of_time():
            invariant = self.store.claim("invariants", "phi_num",
                                         where="status='needs_refinement' AND harness_id=?",
                                         args=(worker.harness_id,), set_status="refining",
                                         order="updated_at ASC")
            repair = None if invariant else self.store.claim(
                "invariants", "phi_num", where="status='needs_repair' AND harness_id=?",
                args=(worker.harness_id,), set_status="repairing", order="updated_at ASC")
            target = invariant or repair
            if target is None:
                await asyncio.sleep(IDLE * 2)
                if self.sp_done.is_set() and not self.store.scalar(
                        "SELECT COUNT(*) FROM pool WHERE status IN ('pending','analysing')"):
                    return
                continue
            if invariant is not None:
                if (target.get("refinements") or 0) >= self.cfg.max_refinements:
                    self.store.update("invariants", "phi_num", target["phi_num"],
                                      {"status": "withdrawn", "updated_at": time.time()})
                    continue
                violation = self.store.row("SELECT * FROM violations WHERE phi_num=? AND verdict='TOO_STRONG' "
                                           "ORDER BY updated_at DESC LIMIT 1", target["phi_num"])
                message = (f"Refine invariant phi {target['phi_num']}.\n\n"
                           f"- location: {target['file']}:{target['line']}\n"
                           f"- falsified expression: `{target['expression']}`\n"
                           f"- security property: {target['security_property']}\n\n"
                           f"## Why triage called it too strong\n{(violation or {}).get('notes', '')}\n\n"
                           f"## Source around the assertion\n```c\n"
                           f"{self._window((target['file'], target['line']))}\n```\n")
                await self._agent("refine", worker.harness_id, message, subject=f"phi{target['phi_num']}",
                                  worker=worker.worker_id, phi=target["phi_num"],
                                  violation=(violation or {}).get("violation_id", ""))
            else:
                message = (f"Invariant phi {target['phi_num']} does not compile.\n\n"
                           f"- location: {target['file']}:{target['line']}\n"
                           f"- expression: `{target['expression']}`\n\n"
                           f"## Compiler output\n```\n{(target.get('last_error') or '')[-3000:]}\n```\n\n"
                           f"## Source around the line\n```c\n"
                           f"{self._window((target['file'], target['line']))}\n```\n")
                await self._agent("invariant_repair", worker.harness_id, message,
                                  subject=f"phi{target['phi_num']}", worker=worker.worker_id,
                                  phi=target["phi_num"])
            still = self.store.scalar("SELECT status FROM invariants WHERE phi_num=?", target["phi_num"])
            if still in ("refining", "repairing"):
                self.store.update("invariants", "phi_num", target["phi_num"],
                                  {"status": "withdrawn", "updated_at": time.time()})

    # ------------------------------------------------------------------ fuzzing lane
    async def fuzzing_lane(self, worker: Worker) -> None:
        harness = self.harness(worker)
        msan = worker.sanitizer == "memory"
        # A separate label keeps the MSan fuzzer's corpus, artifacts and log apart from the ASan one.
        fuzzer = GlobalFuzzer(self.store, run_dir=self.run_dir, worker=worker.worker_id,
                              harness=f"{worker.harness_id}-msan" if msan else worker.harness_id,
                              binary=self.binary_for(worker), seeds=harness.seeds, emit=self.emit)
        self.fuzzers[worker.worker_id if msan else worker.harness_id] = fuzzer
        if msan:
            fuzzer.share_from = self.run_dir / "work" / worker.harness_id / "corpus"
        else:
            await self._direction_seeds(worker)
        await fuzzer.start()
        try:
            while not self.out_of_time():
                phis = {r["phi_num"]: r["phi_num"] for r in self.store.rows(
                    "SELECT phi_num FROM invariants WHERE harness_id=? AND build_version IS NOT NULL",
                    worker.harness_id)}
                await fuzzer.poll(phis=phis or None)
                await asyncio.sleep(5)
        finally:
            # Cancellation lands here: record the statistics first, they are the lane's result.
            self.store.set_meta(f"fuzz_stats_{worker.harness_id}", fuzzer.stats())
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.shield(asyncio.create_task(fuzzer.poll()))
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.shield(asyncio.create_task(fuzzer.stop()))
            self.store.set_meta(f"fuzz_stats_{worker.harness_id}", fuzzer.stats())

    async def _direction_seeds(self, worker: Worker) -> None:
        """FBv2 §3.6: a Seed agent per direction, highest risk first."""
        order = {"high": 0, "medium": 1, "low": 2}
        directions = sorted(self.store.rows("SELECT * FROM directions WHERE harness_id=?", worker.harness_id),
                            key=lambda d: order.get(d["risk_level"], 3))
        for direction in directions[:self.cfg.max_directions]:
            if self.out_of_time():
                return
            await self._agent("seed", worker.harness_id,
                              load_prompt("direction_seed_prompt").format(
                                  direction_id=direction["direction_id"],
                                  target_functions=", ".join(direction["core_functions"][:20]),
                                  risk_level=direction["risk_level"], risk_reason=direction["risk_reason"],
                                  fuzzer=worker.harness_id, fuzzer_source="(call get_fuzzer_info)"),
                              subject=direction["name"], worker=worker.worker_id,
                              direction=direction["direction_id"])

    # ------------------------------------------------------------------ 4 crash confirmation
    async def confirmation_lane(self) -> None:
        while True:
            crash = self.store.claim("crashes", "crash_id", where="status='pending'", args=(),
                                     set_status="confirming")
            if crash is None:
                if self.out_of_time():
                    return
                await asyncio.sleep(IDLE * 2)
                continue
            await self._confirm(crash)

    async def _confirm(self, crash: dict[str, Any]) -> None:
        worker = next((w for w in self.workers if w.worker_id == crash["worker_id"]), self.workers[0])
        harness = self.harness(worker)
        data = Path(crash["input_path"]).read_bytes()
        # 1. reproduce on the build without assertions, in a fresh process
        replay = await asyncio.to_thread(run_input, self.binary_for(worker), data, timeout=30)
        details = dict(crash.get("details") or {})
        details["replay"] = replay.summary()
        baseline = getattr(self, "ub_baseline", None)
        if baseline is None:
            baseline = self.ub_baseline = load_ub_baseline(self.run_dir)
        if not is_finding(replay, baseline):
            self.store.update("crashes", "crash_id", crash["crash_id"],
                              {"status": "not_reproduced", "details": details, "updated_at": time.time()})
            self.emit(f"[crash] {crash['crash_id']} did not reproduce without assertions")
            return
        # 2. a fault inside the harness is a harness defect, not a program finding
        if in_harness(replay.frames, harness.source_path):
            self.store.update("crashes", "crash_id", crash["crash_id"],
                              {"status": "harness_fault", "details": details, "updated_at": time.time()})
            self.emit(f"[crash] {crash['crash_id']} is a harness fault")
            return
        # 3. de-duplicate by the top three program frames.  A replay can end before the sanitizer
        # has printed its stack (seen once on LightFTP: "stack-buffer-overflow" with no frames,
        # while three replays of the same input all gave writelogentry / ftp_client_thread).  A
        # signature made of the crash type alone would file the same bug as a new one, so the
        # input is replayed again, and a finding that never shows a program frame is not counted.
        attempts = 1
        while replay.crashed and not program_frames(replay.frames) and attempts < 3:
            again = await asyncio.to_thread(run_input, self.binary_for(worker), data, timeout=30)
            attempts += 1
            if again.crashed:
                replay = again
        if replay.crashed and not program_frames(replay.frames):
            details["replay"] = replay.summary()
            details["replays"] = attempts
            self.store.update("crashes", "crash_id", crash["crash_id"],
                              {"status": "unattributed", "details": details, "updated_at": time.time()})
            self.emit(f"[crash] {crash['crash_id']}: {replay.crash_type} with no program frame in "
                      f"{attempts} replays; not counted as a distinct finding")
            return
        signature = crash_signature(replay, baseline)
        if self.delta:
            from .delta import delta_relation
            details["delta_relation"] = delta_relation(program_frames(replay.frames), self.delta_changes)
        key = fault_key(replay, baseline)
        details["fault_key"] = key
        finals = self.store.rows("SELECT crash_id, signature, details FROM crashes WHERE crash_id!=? AND status IN "
                                 "('confirmed','validated','reported','not_vulnerability','needs_review')",
                                 crash["crash_id"])
        earlier, how = find_duplicate(signature, key, finals)
        if not earlier and self.prior:
            earlier, how = find_duplicate(signature, key, self.prior)
            if earlier:
                details["duplicate_kind"] = how + ", in an earlier context"
                self.store.update("crashes", "crash_id", crash["crash_id"],
                                  {"status": "duplicate", "duplicate_of": earlier["crash_id"],
                                   "signature": signature, "details": details, "updated_at": time.time()})
                self.emit(f"[crash] {crash['crash_id']}: already found in an earlier context as "
                          f"{earlier['crash_id']} ({how}: {signature})")
                return
        if earlier:
            details["duplicate_kind"] = how
            self.store.update("crashes", "crash_id", crash["crash_id"],
                              {"status": "duplicate", "duplicate_of": earlier["crash_id"],
                               "signature": signature, "details": details, "updated_at": time.time()})
            if how == "same fault site":
                # Not a new bug, but a new way in: kept on the original for the advisory and a human.
                original = dict(earlier.get("details") or {})
                paths = list(original.get("other_paths") or [])
                if signature not in paths:
                    paths.append(signature)
                    original["other_paths"] = paths
                    self.store.update("crashes", "crash_id", earlier["crash_id"],
                                      {"details": original, "updated_at": time.time()})
                self.emit(f"[crash] {crash['crash_id']}: same fault site as {earlier['crash_id']} "
                          f"({key}) by another path: {signature}")
            return
        values = {"status": "confirmed", "signature": signature, "crash_type": finding_type(replay, baseline),
                  "frames": replay.frames, "details": details, "updated_at": time.time()}
        self.store.update("crashes", "crash_id", crash["crash_id"], values)
        scope = ""
        if self.delta:
            scope = {"line": " [delta: the stack passes a changed line]",
                     "fault": " [delta: faults inside a changed function]",
                     "stack": " [delta: only a caller further down the stack was changed]",
                     "none": " [outside the changed code]"}[details["delta_relation"]]
        self.emit(f"[crash] CONFIRMED {crash['crash_id']}: {finding_type(replay, baseline)} at {signature}{scope}")
        if self.validation_closed():
            return
        await self._validate_and_report(crash["crash_id"], worker, data, replay, signature, baseline)

    async def _measure_plain_build(self, worker: Worker, data: bytes) -> dict[str, Any]:
        """The finding's effect in the program built without sanitizers, for the validator to score.

        Two runs.  The normal build gets the input `plain_replays` times on new connections: does
        it die, does glibc report heap damage, what does it answer?  Then glibc's debugging
        allocator (MALLOC_CHECK_=3) gets it a few times: it checks the bytes right after each
        allocation, so it catches a small overflow that the normal allocator's slack hides -- proof
        that the access happens, not that it does harm in a production configuration.
        """
        from .runner import debug_allocator_library, plain_replay
        command = self.cfg.daemon_plain_command
        if not command:
            return {"plain_build": {"configured": False, "summary": "not run: no --daemon-plain-command, so what the "
                                    "finding does in a normal build is not measured; impact can only come from the code"}}
        port = self.cfg.daemon_port or self.harness(worker).port
        cwd = self.cfg.daemon_cwd or None
        out: dict[str, Any] = {}
        pr = await asyncio.to_thread(plain_replay, command, data, port=port, delivery=worker.delivery, trigger=self.harness(worker).trigger, cwd=cwd,
                                     repeat=max(1, self.cfg.plain_replays))
        if not pr.started:
            out["plain_build"] = {"configured": True, "started": False, "summary": f"could not be started: {pr.note}"}
        else:
            if pr.died:
                what = (f"the program died after {pr.runs_sent} of {pr.requested} request(s) (exit status "
                        f"{pr.returncode})")
            else:
                what = f"the program served {pr.runs_sent} of {pr.requested} requests and kept running"
            what += ("; glibc reported: " + "; ".join(pr.allocator_errors)) if pr.allocator_errors \
                else "; glibc reported no heap error"
            out["plain_build"] = {
                "configured": True, "started": True, "requested": pr.requested, "runs_sent": pr.runs_sent,
                "died": pr.died, "returncode": pr.returncode, "allocator_errors": pr.allocator_errors,
                "effect": pr.effect, "first_response": pr.response[:1500].decode("latin-1"),
                "summary": "normal build (no sanitizer): " + what}
        import shlex
        library = debug_allocator_library(shlex.split(command)[0])
        if library and pr.started:
            dbg = await asyncio.to_thread(plain_replay, command, data, port=port, delivery=worker.delivery, trigger=self.harness(worker).trigger, cwd=cwd,
                                          repeat=5, env={"LD_PRELOAD": library, "MALLOC_CHECK_": "3"})
            if dbg.started:
                found = dbg.died or bool(dbg.allocator_errors)
                out["debug_allocator"] = {
                    "detected": found, "runs_sent": dbg.runs_sent, "allocator_errors": dbg.allocator_errors,
                    "summary": ("glibc's debugging allocator (MALLOC_CHECK_=3, not a production setting) "
                                + (f"stopped the program after {dbg.runs_sent} request(s): "
                                   + ("; ".join(dbg.allocator_errors) or f"exit status {dbg.returncode}")
                                   if found else f"saw nothing in {dbg.runs_sent} request(s)"))}
        return out

    async def _validate_and_report(self, crash_id: str, worker: Worker, data: bytes, replay, signature: str,
                                   baseline: set[str]) -> None:
        """Is this confirmed finding a vulnerability?  If so, write it as a GitHub advisory.

        Not part of FuzzingBrain V2, which reports every reproduced crash.  Measured checks come
        first -- repeated replays, then the real program started as a server and sent the same
        bytes over its own socket -- and a validator agent judges what they cannot: who controls
        the input, the preconditions, the consequence.  A verdict of VULNERABILITY is accepted
        only if something reproduces it -- a harness replay or the real program -- and, when a
        real-program replay is configured, the real program does; otherwise it is lowered to
        NEEDS_REVIEW with the reason.
        """
        from .advisory import write_rejection
        harness = self.harness(worker)
        checks: dict[str, Any] = {}
        runs, crashed, others = max(1, self.cfg.validation_replays), 0, set()
        for _ in range(runs):
            again = await asyncio.to_thread(run_input, self.binary_for(worker), data, timeout=30)
            if is_finding(again, baseline):
                crashed += 1
                others.add(crash_signature(again, baseline))
        checks["reproducibility"] = {"runs": runs, "crashed": crashed, "signature": signature,
                                     "other_signatures": sorted(others - {signature})}
        command = self.cfg.daemon_msan_command if worker.sanitizer == "memory" else self.cfg.daemon_command
        if command:
            port = self.cfg.daemon_port or harness.port
            # Repeated, and the count recorded separately from the harness replays: the advisory
            # writer once reported "5 of 5 runs against the real daemon" after one daemon replay
            # and five harness replays.  Each number now says which program produced it.
            daemon_runs, daemon_hits, started, first = 3, 0, 0, None
            for _ in range(daemon_runs):
                dr = await asyncio.to_thread(daemon_replay, command, data, port=port, delivery=worker.delivery, trigger=harness.trigger,
                                             cwd=self.cfg.daemon_cwd or None)
                if not dr.started:
                    continue
                started += 1
                if is_finding(dr.result, baseline):
                    daemon_hits += 1
                    first = first or dr
            if not started:
                checks["daemon"] = {"configured": True, "started": False, "reproduced": None,
                                    "summary": f"could not be started: {dr.note}"}
            else:
                found = first is not None
                theirs = crash_signature(first.result, baseline) if found else ""
                same = found and [f["function"] for f in program_frames(first.result.frames)[:2]] == \
                    [f["function"] for f in program_frames(replay.frames)[:2]]
                kind = finding_type(first.result, baseline) if found else None
                checks["daemon"] = {
                    "configured": True, "started": started, "runs": daemon_runs, "reproduced_runs": daemon_hits,
                    "reproduced": found, "same_fault": same, "type": kind, "signature": theirs,
                    "summary": (f"reproduced in {daemon_hits} of {started} runs of the real program: {kind} at "
                                f"`{theirs}`" + ("" if same else " (a different fault than the harness showed)")
                                if found else f"not reproduced in {started} runs of the real program")}
        else:
            checks["daemon"] = {"configured": False, "reproduced": None,
                                "summary": "not run: no real-program command was given (--daemon-command)"}
        checks.update(await self._measure_plain_build(worker, data))
        row = self.store.row("SELECT * FROM crashes WHERE crash_id=?", crash_id) or {}
        details = dict(row.get("details") or {})
        if details.get("delta_relation"):
            checks["delta_relation"] = details["delta_relation"]
        details["checks"] = checks
        self.store.update("crashes", "crash_id", crash_id, {"details": details, "updated_at": time.time()})
        self.emit(f"[validate] {crash_id}: harness {crashed}/{runs}; real program: {checks['daemon']['summary']}")
        if self.validation_closed():
            return
        shown = data if len(data) <= 2048 else data[:2048]
        message = (f"Decide whether this confirmed finding is a security vulnerability.\n\n"
                   f"- program: {self.index['program']}\n- sanitizer: {worker.sanitizer}\n"
                   f"- finding: {finding_type(replay, baseline)} at {signature}\n"
                   f"- input: {len(data)} bytes, delivered as: {worker.delivery}\n```python\n{shown!r}\n```\n\n"
                   f"## Measured checks\n```json\n{json.dumps(checks, ensure_ascii=False, indent=2)}\n```\n\n"
                   f"## Sanitizer output\n```\n{replay.stderr_tail[-5000:]}\n```\n")
        await self._agent("vuln_validator", worker.harness_id, message, subject=crash_id,
                          worker=worker.worker_id, crash=crash_id)
        row = self.store.row("SELECT * FROM crashes WHERE crash_id=?", crash_id) or {}
        details = dict(row.get("details") or {})
        validation = details.get("validation")
        if not validation:
            validation = {"verdict": "NEEDS_REVIEW", "reasons": "the validator gave no verdict",
                          "cvss_vector": "", "cvss_score": None, "checks": checks}
        validation["checks"] = checks
        if validation["verdict"] == "VULNERABILITY":
            lowered = []
            daemon = checks["daemon"]
            # One independent reproduction is required.  The real program counts on its own: a
            # harness that returns before the program finishes can miss a fault on a single replay
            # (measured: an older LightFTP harness missed the CVE 5 times in 5), the server cannot.
            if crashed == 0 and not daemon.get("reproduced"):
                lowered.append(f"0 of {runs} harness replays reproduced it and the real program did not either")
            if daemon.get("configured") and daemon.get("started") and not daemon.get("reproduced"):
                lowered.append("the real program, started as a server, did not reproduce it")
            if daemon.get("configured") and not daemon.get("started"):
                lowered.append("the real program could not be started to confirm it")
            if validation.get("cvss_score") == 0:
                lowered.append("no impact is measured in a normal build or proven from the code; what remains "
                               "depends on another environment (" + (validation.get("conditional_impact") or
                                                                    "not stated") + ")")
            if lowered:
                validation["verdict"] = "NEEDS_REVIEW"
                validation["reasons"] = ("Lowered from VULNERABILITY because " + "; ".join(lowered) + ". "
                                         + validation.get("reasons", ""))
        details["validation"] = validation
        status = {"VULNERABILITY": "validated", "NOT_A_VULNERABILITY": "not_vulnerability",
                  "NEEDS_REVIEW": "needs_review"}[validation["verdict"]]
        self.store.update("crashes", "crash_id", crash_id, {"details": details, "status": status,
                                                            "updated_at": time.time()})
        self.emit(f"[validate] {crash_id}: {validation['verdict']}"
                  + (f", {validation.get('severity')} {validation.get('cvss_score')}" if validation.get("cvss_score")
                     is not None else ""))
        if validation["verdict"] != "VULNERABILITY":
            path = write_rejection(self.run_dir, crash=row, validation=validation)
            self.store.update("crashes", "crash_id", crash_id, {"report_path": str(path)})
            return
        if self.validation_closed():
            return
        daemon_hint = (f"- real program command: `{command}` (cwd `{self.cfg.daemon_cwd}`), port "
                       f"{self.cfg.daemon_port or harness.port}\n" if command else "")
        message = (f"Write the GitHub security advisory for this validated vulnerability.\n\n"
                   f"- program: {self.index['program']} (tested version: {self.cfg.product_version or 'unknown'})\n"
                   f"- finding: {finding_type(replay, baseline)} at {signature}\n{daemon_hint}"
                   f"- input: {len(data)} bytes over {worker.delivery}\n```python\n{shown!r}\n```\n\n"
                   f"## Validation\n```json\n{json.dumps(validation, ensure_ascii=False, indent=2)}\n```\n\n"
                   f"## Sanitizer output\n```\n{replay.stderr_tail[-5000:]}\n```\n\n"
                   "Read the functions on the stack before writing, then call submit_advisory once.")
        await self._agent("report", worker.harness_id, message, subject=crash_id,
                          worker=worker.worker_id, crash=crash_id)
        row = self.store.row("SELECT status, report_path FROM crashes WHERE crash_id=?", crash_id) or {}
        self.emit(f"[advisory] {crash_id}: " + (row.get("report_path") or "the writer did not submit an advisory"))

    # ------------------------------------------------------------------ run
    async def execute(self) -> dict[str, Any]:
        started = time.time()
        self.cfg.save()
        if not await self.prepare():
            self.emit("preparation produced no work; stopping")
            return self.summary(started)
        tasks: list[asyncio.Task] = []

        def spawn(name: str, coroutine) -> None:
            tasks.append(asyncio.create_task(self.lane(name, coroutine), name=name))

        for worker in self.workers:
            spawn(f"fuzz:{worker.worker_id}", self.fuzzing_lane(worker))
            if self.delta:
                self._delta_running.add(worker.worker_id)
                spawn(f"delta-spgen:{worker.worker_id}", self.delta_sp_agent(worker))
            else:
                for slot in range(self.cfg.sp_generator_agents):
                    spawn(f"spgen{slot}:{worker.worker_id}", self.sp_generator_agent(worker, slot))
            for slot in range(self.cfg.verifier_agents):
                spawn(f"verify{slot}:{worker.worker_id}", self.verifier_agent(worker, slot))
            for slot in range(self.cfg.pov_agents):
                spawn(f"pov{slot}:{worker.worker_id}", self.pov_agent(worker, slot))
            if worker.sanitizer == "memory":
                continue        # invariants are compiled into the ASan build; MSan has its own fuzzer only
            spawn(f"phi-record:{worker.worker_id}", self.invariant_recorder(worker))
            spawn(f"phi-build:{worker.worker_id}", self.build_coordinator(worker))
            spawn(f"phi-triage:{worker.worker_id}", self.triage_agent(worker))
            spawn(f"phi-refine:{worker.worker_id}", self.refine_agent(worker))
        spawn("confirm", self.confirmation_lane())
        analysis = [t for t in tasks if not t.get_name().startswith(("fuzz:", "confirm"))]
        try:
            await asyncio.wait(analysis, timeout=max(1.0, self.deadline - time.time()))
        except asyncio.CancelledError:
            raise
        # Code Augur keeps falsifying after the agents are done, so the remaining budget is
        # spent fuzzing.  0 (the default) means "until the deadline": a caller who asked for
        # two hours gets two hours.  Measured on LightFTP: the lanes drained after 19 of the
        # 105 available minutes and a 20-minute cap ended the run with 66 minutes unused,
        # while 19 built invariants had never been exercised by the fuzzer.  A positive value
        # is an explicit cap for a caller who wants the run to end once the agents are done.
        remaining = max(0.0, self.deadline - time.time())
        extra = min(self.cfg.fuzz_after_drain_minutes * 60, remaining) \
            if self.cfg.fuzz_after_drain_minutes > 0 else remaining
        self.emit(f"analysis lanes drained; fuzzing on for {extra / 60:.0f} min "
                  f"({remaining / 60:.0f} min of budget left)")
        if extra > 0 and not self.stop.is_set():
            await asyncio.sleep(extra)
        self.stop.set()
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        await self.final_drain()
        return self.summary(started)

    async def final_drain(self) -> None:
        """Confirm and validate the crashes left when the lanes stopped.

        The confirmation lane ends as soon as it finds no pending crash after the deadline, but the
        fuzzers are stopped at that same moment and their crash watchers still record what they
        caught on the way down.  On tinyproxy a heap-buffer-overflow recorded at 13:08:07, three
        seconds after the deadline, stayed "pending" and was never looked at.  Cancelling the lanes
        can also cut a confirmation or a validation in half.  Both are picked up here, with the
        fuzzers already stopped, inside final_drain_minutes.
        """
        unvalidated = [row["crash_id"] for row in self.store.rows(
            "SELECT crash_id, details FROM crashes WHERE status='confirmed'")
            if not (row.get("details") or {}).get("validation")]
        for crash_id in unvalidated:
            self.store.update("crashes", "crash_id", crash_id, {"status": "pending", "updated_at": time.time()})
        self.store.conn.execute("UPDATE crashes SET status='pending' WHERE status='confirming'")
        waiting = self.store.scalar("SELECT COUNT(*) FROM crashes WHERE status='pending'") or 0
        if not waiting:
            return
        limit = max(0.0, self.cfg.final_drain_minutes) * 60
        self.emit(f"final drain: {waiting} crash(es) left when the lanes stopped; up to {limit / 60:.0f} min to "
                  f"confirm and validate them")
        self.draining = True
        end = time.time() + limit
        try:
            while time.time() < end:
                crash = self.store.claim("crashes", "crash_id", where="status='pending'", args=(),
                                         set_status="confirming")
                if crash is None:
                    break
                try:
                    await asyncio.wait_for(self._confirm(crash), timeout=max(1.0, end - time.time()))
                except asyncio.TimeoutError:
                    self.store.update("crashes", "crash_id", crash["crash_id"],
                                      {"status": "pending", "updated_at": time.time()})
                    break
        finally:
            self.draining = False
        left = self.store.scalar("SELECT COUNT(*) FROM crashes WHERE status='pending'") or 0
        if left:
            self.emit(f"final drain: {left} crash(es) still unconfirmed after {limit / 60:.0f} min; "
                      f"they stay 'pending' in state.db")

    def summary(self, started: float) -> dict[str, Any]:
        counts = lambda sql: {row["k"]: row["n"] for row in self.store.rows(sql)}
        data = {
            "run_dir": str(self.run_dir),
            "program": self.index["program"],
            "elapsed_seconds": round(time.time() - started, 1),
            "terminal_error": self.terminal,
            "workers": [w.worker_id for w in self.workers],
            "directions": self.store.scalar("SELECT COUNT(*) FROM directions"),
            "functions": counts("SELECT status AS k, COUNT(*) AS n FROM pool GROUP BY status"),
            "suspicious_points": counts("SELECT status AS k, COUNT(*) AS n FROM sps GROUP BY status"),
            "sp_origins": counts("SELECT origin AS k, COUNT(*) AS n FROM sps GROUP BY origin"),
            "invariants": counts("SELECT status AS k, COUNT(*) AS n FROM invariants GROUP BY status"),
            "invariants_reached_by_a_normal_input": self.store.scalar(
                "SELECT COUNT(*) FROM invariants WHERE reached=1"),
            "invariants_never_reached": self.store.scalar(
                "SELECT COUNT(*) FROM invariants WHERE reached=0 AND probed_by IS NOT NULL"),
            "violations": counts("SELECT verdict AS k, COUNT(*) AS n FROM violations GROUP BY verdict"),
            "crashes": counts("SELECT status AS k, COUNT(*) AS n FROM crashes GROUP BY status"),
            "builds": counts("SELECT status AS k, COUNT(*) AS n FROM builds GROUP BY status"),
            "povs": self.store.scalar("SELECT COUNT(*) FROM povs"),
            "agent_runs": counts("SELECT status AS k, COUNT(*) AS n FROM agent_runs GROUP BY status"),
            "agent_runs_by_role": counts("SELECT role AS k, COUNT(*) AS n FROM agent_runs GROUP BY role"),
            "model_usage": self.agents.usage,
            "fuzzers": {h: self.store.get_meta(f"fuzz_stats_{h}") for h in self.project.harnesses},
            "reports": [str(p) for p in sorted((self.run_dir / "reports").glob("*.md"))],
            "qualification": ("A finding counts only as a crash reproduced on the program without assertions. "
                              "Invariant violations are leads, not findings."),
        }
        (self.run_dir / "summary.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                                                    encoding="utf-8")
        return data
