"""Tests for the implemented fbaugur modules.

The tests marked `real_run` need the HarnessCreator run in FBA_HC_RUN (a run that
produced a built harness and verified seeds); they are skipped otherwise.
Set FBA_SLOW=1 to also run the build/execute tests (one full harness build, ~30 s).
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from fbaugur.instrument import (Invariant, instrument_text, lexical_problems, location_problems,
                                split_comparison)
from fbaugur.runner import in_harness, parse_report
from fbaugur.store import Store

from fbaugur.cli import HC_SRC_DEFAULT

# The tests that build and execute a harness need an existing HarnessCreator run to borrow
# its harness source, seeds and build plan from; there is no such run in a fresh checkout, so
# point FBA_HC_RUN at one (and FBA_CONTEXT at a context it built).  Without it those tests skip.
HC_RUN = os.environ.get("FBA_HC_RUN", "")
CONTEXT = os.environ.get("FBA_CONTEXT", "ctx-803ca65377ec")
HC_SRC = Path(os.environ.get("FBA_HARNESSCREATOR_SRC", str(HC_SRC_DEFAULT)))
PYTHON = os.environ.get("FBA_PYTHON", sys.executable)
real_run = unittest.skipUnless(bool(HC_RUN) and Path(HC_RUN, "project.json").is_file(),
                               "set FBA_HC_RUN to a HarnessCreator run directory")
slow = unittest.skipUnless(os.environ.get("FBA_SLOW"), "set FBA_SLOW=1 to build and execute harnesses")

ASAN_REPORT = """==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x4 bp 0x7 sp 0x7
READ of size 4 at 0x602 thread T0
    #0 0x4a1b2c in process_get_command /src/proto_text.c:1234:9
    #1 0x4a2000 in drive_machine /src/memcached.c:3000:5
    #2 0x7f0000 in start_thread /nptl/pthread_create.c:442
0x602 is located 0 bytes to the right of 2-byte region
allocated by thread T0 here:
    #0 0x49 in malloc
"""


class ExpressionTests(unittest.TestCase):
    def test_split_comparison_finds_one_top_level_comparison(self):
        self.assertEqual(split_comparison("c->rbytes <= c->rsize"), ("c->rbytes", "<=", "c->rsize"))
        self.assertEqual(split_comparison("x < sizeof(buf)"), ("x", "<", "sizeof(buf)"))
        self.assertEqual(split_comparison("a << 2 <= b"), ("a << 2", "<=", "b"))
        for expression in ("a <= b && c <= d", "a ? b : c", "x <= y <= z", "nokey", "a <= b || c"):
            self.assertIsNone(split_comparison(expression), expression)

    def test_side_effects_are_rejected(self):
        macros = {"hashsize"}
        self.assertEqual(lexical_problems("c->rbytes <= c->rsize", macros), [])
        self.assertEqual(lexical_problems("x < hashsize(hashpower)", macros), [])
        self.assertEqual(lexical_problems("x < sizeof(out)", macros), [])
        self.assertIn("assignment", lexical_problems("n = 5", macros)[0])
        self.assertIn("increment", lexical_problems("i++ < n", macros)[0])
        self.assertIn("strlen", lexical_problems("strlen(s) < n", macros)[0])
        self.assertIn("empty", lexical_problems("", macros)[0])

    def test_insertion_line_must_start_a_statement(self):
        lines = ["int f(void) {\n", "    int x = 1;\n", "\n", "    } else {\n", "        case 3:\n",
                 "#define Z 1\n", "    memcpy(a,b,n);\n", "label:\n", "}\n"]
        self.assertEqual(location_problems(lines, 2), [])
        self.assertEqual(location_problems(lines, 7), [])
        for line in (3, 4, 5, 6, 8, 9, 99):
            self.assertTrue(location_problems(lines, line), line)

    def test_snippet_and_insertion(self):
        source = "void f(int n, char *b) {\n    int x = n;\n    memcpy(b, &x, n);\n}\n"
        text, line_map = instrument_text(source, [Invariant(4, "x.c", 3, "n <= 4")], cxx=False)
        self.assertIn("fba_phi_reach(4);", text)
        self.assertIn("fba_phi_dist(4,", text)
        self.assertIn("if (!(n <= 4)) fba_phi_violate(4);", text)
        self.assertEqual(list(line_map.values()), [4])
        # the check is inserted before the guarded statement, and the original text is preserved
        body = text.splitlines()
        self.assertIn("memcpy(b, &x, n);", body[line_map and max(line_map) or 0])
        self.assertTrue(all(line in text for line in source.splitlines()))
        # no distance probe for a non-comparison (the runtime prototype still mentions the name)
        other, _ = instrument_text(source, [Invariant(5, "x.c", 3, "b != NULL && n > 0")], cxx=False)
        self.assertNotIn("fba_phi_dist(5,", other)
        self.assertIn("fba_phi_reach(5);", other)


class ReportParsingTests(unittest.TestCase):
    def test_sanitizer_crash(self):
        result = parse_report(ASAN_REPORT, 1, False)
        self.assertTrue(result.crashed)
        self.assertEqual(result.crash_type, "heap-buffer-overflow")
        self.assertEqual([f["function"] for f in result.frames],
                         ["process_get_command", "drive_machine", "start_thread"])
        self.assertEqual(result.frames[0]["line"], 1234)

    def test_invariant_abort_is_not_a_crash(self):
        text = "FBA_PHI_VIOLATION:7\n==1==ERROR: AddressSanitizer: ABRT on unknown address\n    #0 0x1 in abort\n"
        result = parse_report(text, 0, False)
        self.assertFalse(result.crashed)
        self.assertEqual(result.violations, [7])

    def test_a_real_fault_after_a_violation_is_still_a_crash(self):
        result = parse_report("FBA_PHI_VIOLATION:7\n" + ASAN_REPORT, 1, False)
        self.assertTrue(result.crashed)
        self.assertEqual(result.violations, [7])

    def test_ubsan_alone_is_not_a_crash(self):
        text = "/src/proto_bin.c:298:17: runtime error: member access within misaligned address 0x6\n"
        result = parse_report(text, 0, False)
        self.assertFalse(result.crashed)
        self.assertEqual(result.ubsan[0]["line"], 298)

    def test_harness_frames_are_told_apart_from_program_frames(self):
        program = parse_report(ASAN_REPORT, 1, False)
        harness = parse_report(ASAN_REPORT.replace("/src/proto_text.c", "/run/fuzz_target.c"), 1, False)
        self.assertFalse(in_harness(program.frames, Path("/run/fuzz_target.c")))
        self.assertTrue(in_harness(harness.frames, Path("/run/fuzz_target.c")))

    def test_unsymbolized_frames_are_kept_so_signatures_can_tell_bugs_apart(self):
        # Without llvm-symbolizer the program's own frames arrive as binary+offset.  Dropping
        # them left the LightFTP run with one signature (`start_thread:442 | __clone3:81`) for
        # every crash, so 21 crashes from four different suspicious points were all filed as
        # duplicates of one another.  The offsets must survive even when nothing resolves them.
        text = ("==7==ERROR: AddressSanitizer: SEGV on unknown address 0x1fff\n"
                "    #0 0x52bbce  (/nonexistent/hc-native-fuzzer+0x52bbce) (BuildId: abc)\n"
                "    #1 0x52dde9  (/nonexistent/hc-native-fuzzer+0x52dde9) (BuildId: abc)\n"
                "    #2 0x7f0 in start_thread nptl/pthread_create.c:442\n")
        result = parse_report(text, 1, False)
        self.assertTrue(result.crashed)
        self.assertEqual(len(result.frames), 3)
        self.assertEqual([f["index"] for f in result.frames], [0, 1, 2])
        self.assertEqual(result.frames[0]["function"], "hc-native-fuzzer+0x52bbce")
        self.assertEqual(result.frames[2]["function"], "start_thread")
        # Two crashes at different offsets must not collapse into one signature.
        other = parse_report(text.replace("0x52bbce", "0x41aaaa"), 1, False)
        self.assertNotEqual([f["function"] for f in result.frames],
                            [f["function"] for f in other.frames])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.addCleanup(self.tmp.cleanup)

    def sp(self, sp_id: str, score: float, important: int, created: float) -> None:
        self.store.insert("sps", {"sp_id": sp_id, "worker_id": "w1", "function_name": "f", "vuln_type": "t",
                                  "description": "d", "score": score, "status": "verified",
                                  "is_important": important, "important_controlflow": [{"name": "x"}],
                                  "created_at": created, "updated_at": created})

    def test_claim_order_follows_importance_then_score_then_age(self):
        now = time.time()
        for index, (score, important) in enumerate([(0.9, 1), (0.4, 0), (0.6, 1), (0.7, 0)]):
            self.sp(f"sp-{index}", score, important, now + index)
        order = []
        while True:
            claimed = self.store.claim_sp(from_status="verified", to_status="generating_pov",
                                          worker_id="w1", agent="pov-1", min_score=0.5)
            if claimed is None:
                break
            order.append(claimed["sp_id"])
        self.assertEqual(order, ["sp-0", "sp-2", "sp-3"])
        # a low score is skipped, never deleted (FBv2 keeps rejected candidates)
        self.assertEqual(self.store.scalar("SELECT status FROM sps WHERE sp_id='sp-1'"), "verified")

    def test_one_claimer_per_row(self):
        self.store.insert("violations", {"violation_id": "vio-1", "phi_num": 1, "status": "pending",
                                         "created_at": time.time(), "updated_at": time.time()})
        first = self.store.claim("violations", "violation_id", where="status='pending'", args=(),
                                 set_status="triaging")
        self.assertEqual(first["violation_id"], "vio-1")
        self.assertIsNone(self.store.claim("violations", "violation_id", where="status='pending'", args=(),
                                           set_status="triaging"))

    def test_claim_returns_a_rowid_key_and_respects_a_custom_order(self):
        """Regression: `SELECT *` leaves rowid out, so the pool row came back without its key."""
        for phase in (3, 1, 2):
            self.store.insert("pool", {"worker_id": "w", "direction_id": "d",
                                       "function_name": f"f{phase}", "pool": "core", "phase": phase,
                                       "status": "pending", "updated_at": time.time()})
        order = []
        while True:
            claimed = self.store.claim("pool", "rowid", where="status='pending' AND worker_id=?",
                                       args=("w",), set_status="analysing", order="phase ASC, rowid ASC")
            if claimed is None:
                break
            self.assertIn("rowid", claimed)
            order.append(claimed["phase"])
            self.store.update("pool", "rowid", claimed["rowid"], {"status": "analysed"})
        self.assertEqual(order, [1, 2, 3])
        self.assertEqual(self.store.scalar("SELECT COUNT(*) FROM pool WHERE status='analysed'"), 3)

    def test_json_fields_and_meta_round_trip(self):
        self.sp("sp-x", 0.5, 0, time.time())
        self.assertEqual(self.store.row("SELECT * FROM sps WHERE sp_id='sp-x'")["important_controlflow"],
                         [{"name": "x"}])
        self.store.set_meta("build_version", 3)
        self.assertEqual(self.store.get_meta("build_version"), 3)
        self.assertEqual(self.store.get_meta("absent", "default"), "default")


@real_run
class ProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fbaugur.project import Project
        cls.project = Project(Path(HC_RUN), CONTEXT, ["stream", "datagram"])

    def test_reads_functions_call_graph_and_harnesses(self):
        project = self.project
        self.assertGreater(len(project.functions), 100)
        self.assertIn("drive_machine", project.by_name)
        self.assertTrue(project.callees["drive_machine"])
        self.assertTrue(project.callers["drive_machine"])
        for harness in project.harnesses.values():
            self.assertTrue(harness.binary.is_file())
            self.assertTrue(harness.source_path.is_file())
            self.assertTrue(harness.seeds, harness.harness_id)

    def test_targets_are_reachable_and_present_in_the_binary(self):
        project = self.project
        self.assertTrue(project.target_names <= project.compiled)
        self.assertTrue(set(project.interpreter_names) & project.target_names)
        reachable = project.reachable_from(project.interpreter_names)
        self.assertTrue(set(reachable) <= project.target_names)
        self.assertGreater(len(reachable), 10)

    def test_datagram_seeds_carry_length_prefixed_records(self):
        from fbaugur.project import frame_messages
        self.assertEqual(frame_messages([b"ab", b"c"], "datagram"), b"\x00\x02ab\x00\x01c")
        self.assertEqual(frame_messages([b"ab", b"c"], "stream"), b"abc")
        _, blob = self.project.harnesses["h-datagram"].seeds[0]
        self.assertEqual(int.from_bytes(blob[:2], "big") + 2 <= len(blob), True)

    def test_facts_report_measured_limits(self):
        facts = self.project.facts()
        self.assertEqual(facts["program"], self.project.name)
        self.assertTrue(facts["input_entries"])
        self.assertEqual(facts["reachable_compiled_functions"], len(self.project.target_names))
        self.assertIsInstance(facts["functions_needing_a_different_startup_option"], list)


@real_run
@slow
class InvariantBuildTests(unittest.TestCase):
    """One real build of P' with a true and a deliberately false invariant."""

    SITE = ("memcached.c", 2410)          # memmove(c->rbuf, c->rbuf + 8, res) in try_read_udp
    HOLDS = "res <= c->rsize"
    FAILS = "res <= 0"

    @classmethod
    def setUpClass(cls):
        from fbaugur.instrument import InvariantBuilder
        from fbaugur.project import Project
        cls.tmp = tempfile.TemporaryDirectory()
        cls.project = Project(Path(HC_RUN), CONTEXT, ["datagram"])
        cls.harness = cls.project.harnesses["h-datagram"]
        cls.builder = InvariantBuilder(
            source_root=cls.project.source_root, harness_source=cls.harness.source_path,
            build_plan=cls.harness.build_plan, work_dir=Path(cls.tmp.name),
            harnesscreator_src=HC_SRC, python=PYTHON)
        cls.invariants = [Invariant(1, cls.SITE[0], cls.SITE[1], cls.HOLDS),
                          Invariant(2, cls.SITE[0], cls.SITE[1], cls.FAILS)]
        cls.build = cls.builder.build(1, cls.invariants, lambda *_: None)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_precheck_and_syntax_check_use_the_real_compile_command(self):
        builder = self.builder
        self.assertEqual(builder.precheck(*self.SITE, self.HOLDS), [])
        self.assertTrue(builder.precheck("nosuch.c", 1, self.HOLDS))
        self.assertTrue(builder.precheck(*self.SITE, "res = 5"))
        scratch = Path(self.tmp.name) / "syntax"
        error, _ = builder.syntax_check(Invariant(90, *self.SITE, self.HOLDS), scratch)
        self.assertIsNone(error)
        error, _ = builder.syntax_check(Invariant(91, *self.SITE, "res <= c->nosuchfield"), scratch)
        self.assertIn("nosuchfield", error)
        # a comparison that the operand types already decide cannot be falsified
        error, _ = builder.syntax_check(Invariant(92, self.SITE[0], 2402, "buf[0] <= 255"), scratch)
        self.assertIn("operand types", error or "")

    def test_build_succeeds(self):
        self.assertTrue(self.build.ok, self.build.error[-2000:])
        self.assertTrue(self.build.binary.is_file())

    def test_false_invariant_is_falsified_by_a_normal_input_and_the_true_one_holds(self):
        from fbaugur.runner import run_input
        _, blob = self.harness.seeds[0]
        result = run_input(self.build.binary, blob, timeout=10, env_extra={"FBA_PHI_TRACE": "1"})
        self.assertEqual(result.violations, [2])
        self.assertEqual(result.reached, [1, 2])
        self.assertFalse(result.crashed)          # the abort is the invariant signal
        # the same input on the uninstrumented harness stays clean
        original = run_input(self.harness.binary, blob, timeout=10)
        self.assertFalse(original.crashed)
        self.assertEqual(original.violations, [])

    def test_continue_mode_keeps_running_past_a_triaged_violation(self):
        from fbaugur.runner import run_input
        _, blob = self.harness.seeds[0]
        result = run_input(self.build.binary, blob, timeout=10, env_extra={"FBA_PHI_CONTINUE": "2"})
        self.assertEqual(result.violations, [2])
        self.assertEqual(result.returncode, 0)

    def test_debugger_captures_the_state_at_the_violation(self):
        from fbaugur.runner import gdb_violation_state
        _, blob = self.harness.seeds[0]
        state = gdb_violation_state(self.build.binary, blob, 2, ["res", "c->rsize"], timeout=180)
        self.assertIn("try_read_udp", state)
        self.assertIn("fba_phi_violate", state)
        self.assertIn("res = ", state)

    def test_the_build_records_which_line_holds_which_invariant(self):
        # The line map is what turns a sanitizer report from P' into a named invariant.
        self.assertTrue(self.build.line_map)
        numbers = {num for mapping in self.build.line_map.values() for num in mapping.values()}
        self.assertEqual(numbers, {1, 2})
        self.assertTrue(any(key.endswith("memcached.c") for key in self.build.line_map))

    def test_an_invariant_that_faults_on_normal_input_is_blamed_by_its_line(self):
        """An assertion that crashes the process, the LightFTP `phi 16` failure, reproduced.

        There the recorder wrote `params[PATH_MAX*2-1] == 0 || ...` and `params` is NULL for
        every parameterless FTP command, so the assertion read address 0x1fff and killed the
        process before libFuzzer executed one unit.  An unsafe assertion must be attributable
        to its own phi number, otherwise the only option is to blame the program.
        """
        from fbaugur.orchestrator import Run
        from fbaugur.runner import run_input
        unsafe = Invariant(3, self.SITE[0], self.SITE[1], "*(volatile char *)0 == 0")
        build = self.builder.build(2, [Invariant(1, *self.SITE, self.HOLDS), unsafe], lambda *_: None)
        self.assertTrue(build.ok, build.error[-2000:])
        _, blob = self.harness.seeds[0]
        result = run_input(build.binary, blob, timeout=10,
                           env_extra={"FBA_PHI_TRACE": "1", "FBA_PHI_CONTINUE": "1,3"})
        self.assertTrue(result.crashed)
        # A bare SEGV carries no UBSan line and this build's DWARF gives addr2line no line
        # either, so attribution falls back to the last assertion that began evaluating.
        self.assertEqual(result.reach_order[-1], 3)
        self.assertEqual(Run._blame_instrumentation(result, build.line_map, last_evaluated=True), [3])
        # Without that fallback nothing is blamed, which is the safe default for a crash
        # that may well be the program's own.
        self.assertEqual(Run._blame_instrumentation(result, build.line_map), [])
        # The same seed on the uninstrumented harness is clean, which is what makes the
        # fault the assertion's and not the program's.
        self.assertFalse(run_input(self.harness.binary, blob, timeout=10).crashed)

    def test_a_fault_outside_any_assertion_blames_no_invariant(self):
        # A real bug must never be written off as bad instrumentation.
        from fbaugur.orchestrator import Run
        result = parse_report(ASAN_REPORT, 1, False)
        self.assertEqual(Run._blame_instrumentation(result, self.build.line_map), [])



class LaneGuardTests(unittest.IsolatedAsyncioTestCase):
    """A lane that raises is recorded and ends; it must not take the run down."""

    async def test_unexpected_error_is_recorded_and_contained(self):
        from fbaugur.orchestrator import Run

        with tempfile.TemporaryDirectory() as tmp:
            run = Run.__new__(Run)                      # no HarnessCreator run needed for the guard
            run.run_dir = Path(tmp)
            (run.run_dir / "logs").mkdir(parents=True)
            run.store = Store(run.run_dir / "state.db")
            run.stop = __import__("asyncio").Event()
            run.terminal = ""
            messages: list[str] = []
            run.emit = messages.append

            async def broken():
                raise KeyError("rowid")

            await run.lane("spgen0", broken())
            self.assertFalse(run.stop.is_set())
            self.assertTrue(any("LANE ERROR spgen0" in m for m in messages), messages)
            self.assertTrue(run.store.rows("SELECT * FROM events WHERE kind='lane_error'"))
            self.assertIn("KeyError", (run.run_dir / "logs" / "lane-errors.log").read_text())

    async def test_terminal_model_error_stops_the_run(self):
        from fbaugur.agent import TerminalLLMError
        from fbaugur.orchestrator import Run

        with tempfile.TemporaryDirectory() as tmp:
            run = Run.__new__(Run)
            run.run_dir = Path(tmp)
            (run.run_dir / "logs").mkdir(parents=True)
            run.store = Store(run.run_dir / "state.db")
            run.stop = __import__("asyncio").Event()
            run.terminal = ""
            run.emit = lambda _message: None

            async def limit():
                raise TerminalLLMError("usage limit reached")

            await run.lane("verify0", limit())
            self.assertTrue(run.stop.is_set())
            self.assertIn("usage limit", run.terminal)


@real_run
class PromptTests(unittest.TestCase):
    """Every role must render a system prompt: a missing file or placeholder kills a lane."""

    @classmethod
    def setUpClass(cls):
        import json
        from fbaugur.config import RunConfig
        from fbaugur.index import build_index
        from fbaugur.orchestrator import Run
        from fbaugur.project import Project
        cls.tmp = tempfile.TemporaryDirectory()
        run_dir = Path(cls.tmp.name)
        cfg = RunConfig(run_dir=str(run_dir), hc_run=HC_RUN, context_id=CONTEXT, deliveries=["datagram"])
        cfg.save()
        project = Project(Path(HC_RUN), CONTEXT, ["datagram"])
        index = build_index(run_dir, project, harnesscreator_src=HC_SRC, sanitizer=cfg.sanitizer)
        cls.orchestrator = Run.__new__(Run)
        cls.orchestrator.cfg, cls.orchestrator.index = cfg, index

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_role_renders_without_leftover_placeholders(self):
        import re
        from fbaugur.config import ROLE_TIER
        for role in ROLE_TIER:
            with self.subTest(role=role):
                text = self.orchestrator._system(role, "h-datagram")
                self.assertGreater(len(text), 500)
                self.assertEqual(sorted(set(re.findall(r"\{[a-z_]+\}", text))), [])
                self.assertIn("libFuzzer harness", text)        # the harness context is appended

    def test_sanitizer_guidance_and_safety_addendum_are_included(self):
        self.assertIn("AddressSanitizer Detectable", self.orchestrator._system("sp_generator", "h-datagram"))
        self.assertIn("UndefinedBehaviorSanitizer", self.orchestrator._system("sp_generator", "h-datagram"))
        verifier = self.orchestrator._system("sp_verifier", "h-datagram")
        self.assertIn("safety_reason", verifier)
        self.assertIn("safety_location", verifier)

    def test_fbv2_seed_prompts_accept_their_fields(self):
        from fbaugur.agent import load_prompt
        self.assertIn("high", load_prompt("direction_seed_prompt").format(
            direction_id="d", target_functions="a", risk_level="high", risk_reason="r",
            fuzzer="h", fuzzer_source="s"))
        self.assertIn("sp-1", load_prompt("fp_seed_prompt").format(
            sp_id="sp-1", function_name="f", vuln_type="t", description="d", fuzzer="h", fuzzer_source="s"))


@real_run
class ReachabilityEvidenceTests(unittest.TestCase):
    """HarnessCreator already measured which functions a normal input runs; use it, don't guess."""

    @classmethod
    def setUpClass(cls):
        from fbaugur.project import Project
        cls.project = Project(Path(HC_RUN), CONTEXT, ["stream", "datagram"])

    def test_executed_and_blocked_sets_come_from_measurements(self):
        project = self.project
        self.assertTrue(project.executed_names)
        self.assertTrue(project.executed_names & project.target_names)
        # the frontier judged these to need another startup option or channel
        self.assertTrue(project.blocked_names)
        self.assertFalse(project.blocked_names & project.reached_names)

    def test_a_file_with_no_executed_function_is_reported_closed(self):
        project = self.project
        # memcached's proxy needs a startup option the harness does not pass
        self.assertIn("proto_proxy.c", project.closed_files)
        for file in project.closed_files:
            names = {fn.name for fn in project.functions.values()
                     if fn.file == file and fn.name in project.target_names}
            self.assertFalse(names & project.executed_names, file)
        # a file the input path does exercise is not closed
        self.assertNotIn("memcached.c", project.closed_files)
        self.assertNotIn("proto_text.c", project.closed_files)

    def test_site_evidence_separates_the_three_measurements(self):
        evidence = self.project.site_evidence("drive_machine", "memcached.c")
        self.assertTrue(evidence["executed_by_a_verified_normal_input"])
        self.assertFalse(evidence["no_function_of_this_file_was_ever_executed"])
        closed = sorted(self.project.closed_files)[0]
        name = next(fn.name for fn in self.project.functions.values()
                    if fn.file == closed and fn.name in self.project.target_names)
        shut = self.project.site_evidence(name, closed)
        self.assertFalse(shut["executed_by_a_verified_normal_input"])
        self.assertTrue(shut["no_function_of_this_file_was_ever_executed"])

    def test_blocked_functions_are_left_out_of_the_pool(self):
        """A function measured to need another startup option cannot be reached here."""
        import asyncio, json, time
        from fbaugur.config import RunConfig
        from fbaugur.index import build_index
        from fbaugur.orchestrator import Run, Worker
        from fbaugur.store import Store

        blocked = sorted(self.project.blocked_names & self.project.target_names)
        self.assertTrue(blocked, "this run recorded no blocked function")
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            cfg = RunConfig(run_dir=str(run_dir), hc_run=HC_RUN, context_id=CONTEXT, deliveries=["datagram"])
            cfg.save()
            run = Run.__new__(Run)
            run.cfg, run.project, run.store = cfg, self.project, Store(run_dir / "state.db")
            run.index = build_index(run_dir, self.project, harnesscreator_src=HC_SRC, sanitizer=cfg.sanitizer)
            run.emit = lambda _m: None
            run.workers = [Worker("w-datagram", "h-datagram", "datagram")]
            # one direction whose core functions include a blocked one
            run.store.insert("directions", {
                "direction_id": "dir-1", "harness_id": "h-datagram", "name": "t", "risk_level": "high",
                "risk_reason": "r", "core_functions": [blocked[0], "drive_machine"],
                "entry_functions": ["drive_machine"], "code_summary": "", "created_at": time.time()})
            run._fill_pools()
            pooled = {r["function_name"]: r for r in run.store.rows("SELECT * FROM pool")}
            self.assertNotIn(blocked[0], pooled)
            self.assertIn("drive_machine", pooled)
            # a function with runtime evidence is analysed before one without
            evidenced = pooled["drive_machine"]["phase"]
            others = [r["phase"] for n, r in pooled.items() if n not in self.project.executed_names]
            self.assertTrue(all(evidenced < phase for phase in others) or not others)


if __name__ == "__main__":
    unittest.main()
