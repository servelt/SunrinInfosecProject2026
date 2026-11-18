"""Tests for the implemented fbaugur modules.

The tests marked `real_run` need the HarnessCreator run in FBA_HC_RUN (a run that
produced a built harness and verified seeds); they are skipped otherwise.
Set FBA_SLOW=1 to also run the build/execute tests (one full harness build, ~30 s).
"""

from __future__ import annotations

import os
import sys
import json
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


def run_until_crash(binary, blob, env_extra, attempts=5):
    """Replay until the process faults.  The memcached test harness is an older one that returns
    after a short silence, so a fault in a worker thread can land after the process has exited;
    these tests are about attributing a fault, not about that race, so they retry it."""
    from fbaugur.runner import run_input
    result = None
    for _ in range(attempts):
        result = run_input(binary, blob, timeout=20, env_extra=env_extra)
        if result.crashed:
            break
    return result


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
        result = run_until_crash(build.binary, blob, {"FBA_PHI_TRACE": "1", "FBA_PHI_CONTINUE": "1,3"})
        self.assertTrue(result.crashed)
        # A bare SEGV carries no UBSan line and this build's DWARF gives addr2line no line
        # either, so attribution falls back to the last assertion that began evaluating.
        self.assertEqual(result.reach_order[-1], 3)
        self.assertEqual(Run._blame_instrumentation(result, build.line_map, last_evaluated=True), [3])
        # Without that fallback, attribution needs a line: with llvm-symbolizer the SEGV frame
        # carries one and names the assertion directly; without it nothing is blamed, which is
        # the safe default for a crash that may well be the program's own.
        from fbaugur.runner import find_symbolizer
        self.assertEqual(Run._blame_instrumentation(result, build.line_map), [3] if find_symbolizer() else [])
        # The same seed on the uninstrumented harness is clean, which is what makes the
        # fault the assertion's and not the program's.
        self.assertFalse(run_input(self.harness.binary, blob, timeout=10).crashed)

    def test_a_fault_outside_any_assertion_blames_no_invariant(self):
        # A real bug must never be written off as bad instrumentation.
        from fbaugur.orchestrator import Run
        result = parse_report(ASAN_REPORT, 1, False)
        self.assertEqual(Run._blame_instrumentation(result, self.build.line_map), [])

    def test_firing_on_a_normal_input_goes_to_triage_but_faulting_is_withdrawn(self):
        """The two outcomes of probing are not the same thing and must not share a verdict.

        An assertion that FIRES on an input the program accepts is the question triage exists
        to answer: too strong, or does the program really reach that state?  On LightFTP
        `context->RestPoint >= 0` fired on a normal session and withdrawing it discarded the
        question of whether REST accepts a negative offset.  An assertion that FAULTS stops
        libFuzzer from executing anything at all, so it has to go.
        """
        from fbaugur.runner import run_input
        _, blob = self.harness.seeds[0]
        # phi 2 (`res <= 0`) is false on a normal input, so it fires without faulting.
        fires = run_input(self.build.binary, blob, timeout=10,
                           env_extra={"FBA_PHI_TRACE": "1", "FBA_PHI_CONTINUE": "1,2"})
        self.assertEqual(fires.violations, [2])
        self.assertFalse(fires.crashed)      # firing alone never costs the fuzzing lane a run
        # Faulting is the other case, and that one is attributable and withdrawn.
        build = self.builder.build(3, [Invariant(4, *self.SITE, "*(volatile char *)0 == 0")],
                                   lambda *_: None)
        self.assertTrue(build.ok, build.error[-2000:])
        faults = run_until_crash(build.binary, blob, {"FBA_PHI_TRACE": "1", "FBA_PHI_CONTINUE": "4"})
        self.assertTrue(faults.crashed)
        self.assertEqual(faults.violations, [])   # it never reached the report, it died first



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


LIGHTFTP_FRAMES = [   # the ASan stack of CVE-2017-1000218 as an unsymbolized build reports it
    {"index": 0, "function": "__interceptor_strcat", "file": None, "line": None},
    {"index": 1, "function": "writelogentry", "file": None, "line": None},
    {"index": 2, "function": "ftp_client_thread", "file": None, "line": None},
    {"index": 3, "function": "start_thread", "file": "nptl/pthread_create.c", "line": 442},
    {"index": 4, "function": "__clone3", "file": "misc/../sysdeps/unix/sysv/linux/x86_64/clone3.S", "line": 81},
]
PORT_UB = "/src/ftpserv.c:551:51: runtime error: left shift of 200 by 24 places cannot be represented in type 'int'\n"


class FindingTests(unittest.TestCase):
    """What counts as a finding, and how findings are told apart (all measured on LightFTP)."""

    def test_undefined_behaviour_outside_the_baseline_is_a_finding(self):
        from fbaugur.runner import finding_type, is_finding
        result = parse_report(PORT_UB, 0, False)
        self.assertFalse(result.crashed)                    # UBSan never aborts in this build
        self.assertTrue(is_finding(result, set()))
        self.assertIn("left shift of 200", finding_type(result, set()))

    def test_undefined_behaviour_normal_inputs_already_trigger_is_not(self):
        from fbaugur.runner import is_finding
        # The baseline is what ub_sites() gives for the normal inputs (paths are kept, not file names).
        normal = set(parse_report(PORT_UB, 0, False).ub_sites())
        self.assertFalse(is_finding(parse_report(PORT_UB, 0, False), normal))

    def test_signature_uses_program_frames_even_without_files(self):
        from fbaugur.runner import RunResult, crash_signature
        result = RunResult(1, False, True, "AddressSanitizer", "stack-buffer-overflow",
                           LIGHTFTP_FRAMES, [], [], [], "")
        # Program frames are used without files; the bug class leads and `@?` marks the unknown place
        # (such a signature is kept, but never used to merge two findings).
        self.assertEqual(crash_signature(result),
                         "stack-buffer-overflow | writelogentry@? | ftp_client_thread@?")

    def test_two_different_bugs_get_different_signatures(self):
        from fbaugur.runner import RunResult, crash_signature
        other = [dict(f) for f in LIGHTFTP_FRAMES]
        other[1]["function"] = "finalpath"
        a = RunResult(1, False, True, "AddressSanitizer", "x", LIGHTFTP_FRAMES, [], [], [], "")
        b = RunResult(1, False, True, "AddressSanitizer", "x", other, [], [], [], "")
        self.assertNotEqual(crash_signature(a), crash_signature(b))

    def test_ub_only_signature_is_its_site(self):
        from fbaugur.runner import crash_signature
        # The site keeps its path (no source root is set here, so the reported path is kept whole).
        self.assertEqual(crash_signature(parse_report(PORT_UB, 0, False), set()), "UB /src/ftpserv.c:551")

    def test_harness_fault_is_recognised_by_function_name(self):
        from fbaugur.runner import in_harness
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "fuzz_target.c")
            source.write_text("static size_t hc_send_all(int fd, const char *d, size_t n)\n{\n  return 0;\n}\n"
                              "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)\n{\n  return 0;\n}\n")
            harness = [{"index": 0, "function": "__interceptor_memcpy", "file": None, "line": None},
                       {"index": 1, "function": "hc_send_all", "file": None, "line": None}]
            self.assertTrue(in_harness(harness, source))
            self.assertFalse(in_harness(LIGHTFTP_FRAMES, source))


class QuarantineTests(unittest.TestCase):
    """A corpus input that faults while the corpus loads is moved out, matched by content."""

    def _fuzzer(self, tmp: Path):
        from fbaugur.fuzzing import GlobalFuzzer
        return GlobalFuzzer(Store(tmp / "state.db"), run_dir=tmp, worker="w", harness="h",
                            binary=tmp / "bin", seeds=[])

    def test_seed_crash_before_inited_is_quarantined(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            fuzzer = self._fuzzer(tmp)
            bad, good = b"USER " + b"A" * 600 + b"\r\n", b"NOOP\r\n"
            (fuzzer.corpus / "4f2b").write_bytes(bad)
            (fuzzer.corpus / "pov-17aa").write_bytes(bad)          # same bytes under another name
            (fuzzer.corpus / "c0de").write_bytes(good)
            artifact = fuzzer.artifacts / "crash-1"
            fuzzer.artifacts.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(bad)
            fuzzer.log.parent.mkdir(parents=True, exist_ok=True)
            fuzzer.log.write_text("\n=== 05:20:01 run\nINFO: seed corpus: files: 3\n==1==ERROR: AddressSanitizer\n"
                                  f"MS: 0 ; base unit: 0000\nartifact_prefix='x'; Test unit written to {artifact}\n")
            self.assertEqual(fuzzer.quarantine_seed_crash(), 2)
            self.assertEqual(sorted(p.name for p in fuzzer.corpus.iterdir()), ["c0de"])
            self.assertEqual(len(list((fuzzer.work / "corpus-quarantine").iterdir())), 2)

    def test_crash_after_inited_is_a_mutation_and_leaves_the_corpus_alone(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            fuzzer = self._fuzzer(tmp)
            (fuzzer.corpus / "a").write_bytes(b"x")
            fuzzer.artifacts.mkdir(parents=True, exist_ok=True)
            (fuzzer.artifacts / "crash-2").write_bytes(b"x")
            fuzzer.log.parent.mkdir(parents=True, exist_ok=True)
            fuzzer.log.write_text("\n=== 05:20:01 run\n#3\tINITED cov: 10 ft: 10\n==1==ERROR: AddressSanitizer\n"
                                  f"Test unit written to {fuzzer.artifacts / 'crash-2'}\n")
            self.assertEqual(fuzzer.quarantine_seed_crash(), 0)
            self.assertTrue((fuzzer.corpus / "a").exists())


class ContextOrderTests(unittest.TestCase):
    def test_built_harnesses_follow_context_priority_not_directory_order(self):
        from fbaugur.pipeline import built_harnesses
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary)
            for ctx in ("ctx-033f", "ctx-cc74"):                      # 033f sorts first by name
                build = run / "context-harnesses" / f"{ctx}-stream" / "attempt-1" / "build"
                build.mkdir(parents=True)
                (build / "hc-native-fuzzer").write_bytes(b"")
            (run / "contexts").mkdir()
            (run / "contexts" / "contexts.jsonl").write_text(
                json.dumps({"context_id": "ctx-cc74"}) + "\n" + json.dumps({"context_id": "ctx-033f"}) + "\n")
            self.assertEqual(built_harnesses(run), [("ctx-cc74", "stream"), ("ctx-033f", "stream")])


class MemorySanitizerTests(unittest.TestCase):
    """MSan reports, symbolizer discovery and compiler choice (measured on LightFTP)."""

    MSAN_REPORT = ("==7==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
                   "    #0 0x1 in ParseConfig /src/cfgparse.c:76:9\n"
                   "    #1 0x2 in ftpPASS /src/ftpserv.c:1060:7\n"
                   "    #2 0x3 in ftp_client_thread /src/ftpserv.c:1816:6\n"
                   "  Uninitialized value was created by a heap allocation\n"
                   "    #0 0x9 in malloc\n")

    def test_msan_warning_is_a_finding_with_its_own_type(self):
        from fbaugur.runner import crash_signature
        result = parse_report(self.MSAN_REPORT, 1, False)
        self.assertTrue(result.crashed)
        self.assertEqual((result.kind, result.crash_type), ("MemorySanitizer", "use-of-uninitialized-value"))
        # the origin stack after it (malloc) is not part of the signature
        self.assertEqual(crash_signature(result), "use-of-uninitialized-value | ParseConfig@/src/cfgparse.c:76 | "
                                                  "ftpPASS@/src/ftpserv.c:1060 | ftp_client_thread@/src/ftpserv.c:1816")

    def test_sanitizer_env_sets_msan_options_and_a_symbolizer_when_one_exists(self):
        from fbaugur.runner import find_symbolizer, sanitizer_env
        env = sanitizer_env()
        self.assertIn("halt_on_error=1", env["MSAN_OPTIONS"])
        if find_symbolizer():
            self.assertEqual(env["MSAN_SYMBOLIZER_PATH"], env["ASAN_SYMBOLIZER_PATH"])

    def test_msan_never_uses_a_clang_older_than_18(self):
        import importlib, re, sys
        sys.path.insert(0, str(HC_SRC))
        try:
            native = importlib.import_module("harnesscreator.runtime.native_build")
        finally:
            sys.path.remove(str(HC_SRC))
        cc, _ = native._compilers("memory")
        if cc is not None:
            version = re.search(r"clang-(\d+)", cc)
            self.assertTrue(version and int(version.group(1)) >= 18, cc)
        self.assertIn("memory", native._SANITIZERS["memory"][1])


class PerSanitizerAnalysisTests(unittest.TestCase):
    """FBv2: each {fuzzer, sanitizer} worker runs its own analysis in its sanitizer's scope."""

    def test_guidance_follows_fbv2_per_sanitizer(self):
        from fbaugur.agent import sanitizer_guidance, sanitizer_vuln_types
        memory = sanitizer_guidance("memory")
        self.assertIn("MemorySanitizer Detectable Bugs", memory)
        self.assertIn("Uninitialized", memory)
        self.assertNotIn("AddressSanitizer", memory)
        self.assertEqual(sanitizer_vuln_types("memory"), "Uninitialized memory reads")
        self.assertNotIn("Uninitialized", sanitizer_vuln_types("address+undefined"))

    def test_msan_tool_proves_on_its_own_build_and_files_under_the_right_worker(self):
        # The worker name must never become `w-stream-msan-msan`.
        import inspect
        from fbaugur import tools
        source = inspect.getsource(tools.Toolbox.create_pov)
        self.assertIn('asan_worker = self.worker[:-len("-msan")] if on_msan else self.worker', source)
        self.assertIn("builds.reverse()", source)

    def test_msan_guidance_adds_cross_request_state_without_naming_any_target(self):
        # The addition must stay generic: a prompt that names the measured bug would make any
        # evaluation on that target meaningless.
        from fbaugur.agent import sanitizer_guidance
        memory = sanitizer_guidance("memory")
        self.assertIn("state one request leaves for another", memory)
        for name in ("LightFTP", "ftpPASS", "GPBuffer", "ParseConfig"):
            self.assertNotIn(name, memory)
        self.assertNotIn("state one request leaves", sanitizer_guidance("address+undefined"))


CVE_INJECT_DIFF = """diff --git a/Source/Other/ftpserv.c b/Source/Other/ftpserv.c
index 1111111..2222222 100644
--- a/Source/Other/ftpserv.c
+++ b/Source/Other/ftpserv.c
@@ -380,7 +380,7 @@ ssize_t writeconsolestr(const char *Buffer)
 
 int writelogentry(PFTPCONTEXT context, const char *logtext1, const char *logtext2)
 {
-	char		cvbuf[32], _text[PATH_MAX*4];
+	char		cvbuf[32], _text[512];
 	time_t		itm = time(NULL);
 	struct tm	ltm;
 
"""


class DeltaTests(unittest.TestCase):
    """FBv2 delta scan input: diff -> changed functions with reachability (LightFTP shapes)."""

    FUNCTIONS = {"writelogentry": [{"file": "ftpserv.c", "start": 381, "end": 440}],
                 "ftp_client_thread": [{"file": "ftpserv.c", "start": 1726, "end": 1836}],
                 "stor_thread": [{"file": "ftpserv.c", "start": 1192, "end": 1271}]}
    CALLEES = {"ftp_client_thread": ["writelogentry", "recvcmd"]}

    def test_reversed_cve_fix_maps_to_the_sink_line(self):
        from fbaugur.delta import changed_functions
        changes, report = changed_functions(CVE_INJECT_DIFF, self.FUNCTIONS, self.CALLEES, ["ftp_client_thread"])
        self.assertEqual([(c.function, c.changed_lines, c.static_reachable, c.distance) for c in changes],
                         [("writelogentry", [383], True, 1)])
        # repository path Source/Other/ftpserv.c matched to the analysed file ftpserv.c
        self.assertEqual(report["files"], [{"diff_file": "Source/Other/ftpserv.c", "source_file": "ftpserv.c",
                                            "changed_lines": 1}])

    def test_unreachable_changes_are_kept_and_marked(self):
        # FBv2: thread entry points started through pthread_create are invisible to a static call
        # graph; they are analysed anyway and the PoV decides.
        from fbaugur.delta import changed_functions
        diff = ("--- a/ftpserv.c\n+++ b/ftpserv.c\n@@ -1200,2 +1200,3 @@\n x\n+y\n z\n")
        changes, _ = changed_functions(diff, self.FUNCTIONS, self.CALLEES, ["ftp_client_thread"])
        self.assertEqual([(c.function, c.static_reachable, c.distance) for c in changes], [("stor_thread", False, None)])

    def test_a_removed_line_starting_with_dashes_is_not_a_file_header(self):
        from fbaugur.delta import parse_diff
        diff = "--- a/x.c\n+++ b/x.c\n@@ -1,3 +1,3 @@\n int a;\n--- old comment\n+++ new comment\n int b;\n"
        files = parse_diff(diff)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].hunks[0].changed_new_lines(), [2])

    def test_a_pure_deletion_marks_where_it_happened(self):
        from fbaugur.delta import parse_diff
        diff = "--- a/x.c\n+++ b/x.c\n@@ -10,4 +10,3 @@\n a\n-b\n c\n d\n"
        self.assertEqual(parse_diff(diff)[0].hunks[0].changed_new_lines(), [11])

    def test_delta_generator_prompt_is_fbv2_with_the_workers_sanitizer(self):
        from fbaugur.agent import load_prompt
        body = load_prompt("find_suspicious_points_prompt")
        self.assertTrue(body.strip())
        delta_verify = load_prompt("verify_suspicious_points_delta_prompt")
        self.assertIn("DO NOT** analyze reachability", delta_verify)

    def test_relation_to_the_diff_is_decided_by_the_fault_frame(self):
        # Measured on LightFTP with the injected CVE (T1) and the real 7ea0a8f diff (T2).
        from fbaugur.delta import delta_relation
        t1 = [{"function": "writelogentry", "file": "ftpserv.c", "changed_lines": [383]}]
        t2 = [{"function": "ftp_client_thread", "file": "ftpserv.c", "changed_lines": [1798, 1803]}]
        cve = [{"function": "writelogentry", "file": "/b/ftpserv.c", "line": 435},
               {"function": "ftp_client_thread", "file": "/b/ftpserv.c", "line": 1790}]
        umr = [{"function": "ParseConfig", "file": "/b/cfgparse.c", "line": 76},
               {"function": "ftpPASS", "file": "/b/ftpserv.c", "line": 1060},
               {"function": "ftp_client_thread", "file": "/b/ftpserv.c", "line": 1816}]
        self.assertEqual(delta_relation(cve, t1), "fault")   # the diff's bug, though not on line 383
        self.assertEqual(delta_relation(umr, t1), "none")
        self.assertEqual(delta_relation(cve, t2), "stack")   # older bug under a changed dispatcher
        self.assertEqual(delta_relation(umr, t2), "stack")
        self.assertEqual(delta_relation([{"function": "ftp_client_thread", "file": "/b/ftpserv.c",
                                          "line": 1798}], t2), "line")


class AdvisoryTests(unittest.TestCase):
    """CVSS is computed here, and the advisory follows GitHub's form and the OSV schema."""

    def test_cvss_31_base_scores_match_reference_values(self):
        from fbaugur.cvss import base_score, rating
        for vector, score, level in (
                ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
                ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "High"),
                ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
                ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
                ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
                ("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7, "Low"),
                ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
                ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None")):
            self.assertEqual(base_score("CVSS:3.1/" + vector), score, vector)
            self.assertEqual(rating(score), level, vector)

    def test_an_invalid_vector_is_refused_rather_than_guessed(self):
        from fbaugur.cvss import base_score
        for bad in ("CVSS:3.1/AV:N/AC:L", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
            with self.assertRaises(ValueError):
                base_score(bad)

    def _validation(self, verdict="VULNERABILITY"):
        return {"verdict": verdict, "reasons": "pre-auth overflow", "attacker_input": "one long line",
                "preconditions": "none", "consequence": "stack overwrite", "severity": "Critical",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 9.8,
                "cwe_ids": ["CWE-121"], "vulnerable_functions": ["writelogentry"],
                "checks": {"reproducibility": {"runs": 5, "crashed": 5, "signature": "writelogentry:435"},
                           "daemon": {"summary": "reproduced: stack-buffer-overflow"}}}

    def test_advisory_has_githubs_fields_in_order_and_a_valid_osv_record(self):
        from fbaugur.advisory import write_advisory
        with tempfile.TemporaryDirectory() as tmp:
            poc = Path(tmp, "poc.bin")
            poc.write_bytes(b"USER " + b"A" * 600 + b"\r\n")
            paths = write_advisory(Path(tmp), crash={"crash_id": "crash-1", "input_path": str(poc),
                                                     "crash_type": "stack-buffer-overflow",
                                                     "signature": "writelogentry:435"},
                                   validation=self._validation(), program="lightftp", version="7ea0a8f",
                                   title="Stack overflow in writelogentry", summary="S", details="D", poc="P",
                                   impact="I", vulnerable_functions=["writelogentry"], patched_versions="",
                                   workarounds="")
            md = paths["markdown"].read_text()
            order = [md.index(h) for h in ("### Summary", "### Details", "### PoC", "### Impact")]
            self.assertEqual(order, sorted(order))
            for field in ("| Affected versions | = 7ea0a8f |", "| Severity | Critical (9.8) |", "CWE-121",
                          "AI assistance used"):
                self.assertIn(field, md)
            osv = json.loads(paths["osv"].read_text())
            for key in ("schema_version", "id", "modified", "summary", "details", "affected", "severity"):
                self.assertIn(key, osv)
            self.assertEqual(osv["severity"][0]["type"], "CVSS_V3")
            self.assertEqual(osv["affected"][0]["versions"], ["7ea0a8f"])
            self.assertTrue(osv["database_specific"]["ai_assisted"])

    def test_a_rejected_finding_keeps_its_reasons(self):
        from fbaugur.advisory import write_rejection
        with tempfile.TemporaryDirectory() as tmp:
            path = write_rejection(Path(tmp), crash={"crash_id": "crash-2", "crash_type": "ub",
                                                     "signature": "UB ftpserv.c:551"},
                                   validation=self._validation("NOT_A_VULNERABILITY"))
            self.assertTrue(path.name.endswith("not-a-vulnerability.md"))
            self.assertIn("pre-auth overflow", path.read_text())

    def test_poc_bytes_fold_long_runs_and_round_trip(self):
        from fbaugur.advisory import bytes_expression
        for data in (b"A" * 2000 + b"\r\n", b"USER " + b"A" * 600 + b"\r\n", b"PASS x\r\n", b"", b"\x00" * 40):
            self.assertEqual(eval(bytes_expression(data)), data)
        self.assertEqual(bytes_expression(b"A" * 2000 + b"\r\n"), "b'A' * 2000 + b'\\r\\n'")


class DuplicateTests(unittest.TestCase):
    """A finding repeats an earlier one by the same stack, or by the same fault site."""

    def _result(self, frames, kind="stack-buffer-overflow"):
        from fbaugur.runner import RunResult
        return RunResult(1, False, True, "AddressSanitizer", kind,
                         [{"index": i, "function": f, "file": "/b/ftpserv.c", "line": l} for i, (f, l) in enumerate(frames)],
                         [], [], [], "")

    def test_same_strcat_from_another_caller_is_the_same_root_cause(self):
        from fbaugur.runner import crash_signature, fault_key, find_duplicate
        logged = self._result([("writelogentry", 435), ("ftp_client_thread", 1790)])
        via_user = self._result([("writelogentry", 435), ("ftpUSER", 489), ("ftp_client_thread", 1820)])
        earlier = [{"crash_id": "c1", "signature": crash_signature(logged), "details": {"fault_key": fault_key(logged)}}]
        self.assertNotEqual(crash_signature(via_user), crash_signature(logged))
        row, how = find_duplicate(crash_signature(via_user), fault_key(via_user), earlier)
        self.assertEqual((row["crash_id"], how), ("c1", "same fault site"))

    def test_identical_stack_is_found_first(self):
        from fbaugur.runner import crash_signature, fault_key, find_duplicate
        logged = self._result([("writelogentry", 435), ("ftp_client_thread", 1790)])
        earlier = [{"crash_id": "c1", "signature": crash_signature(logged), "details": {"fault_key": fault_key(logged)}}]
        self.assertEqual(find_duplicate(crash_signature(logged), fault_key(logged), earlier)[1], "same stack")

    def test_another_line_or_another_bug_class_is_a_new_finding(self):
        from fbaugur.runner import crash_signature, fault_key, find_duplicate
        logged = self._result([("writelogentry", 435), ("ftp_client_thread", 1790)])
        earlier = [{"crash_id": "c1", "signature": crash_signature(logged), "details": {"fault_key": fault_key(logged)}}]
        other_line = self._result([("writelogentry", 432), ("ftp_client_thread", 1790)])
        other_kind = self._result([("writelogentry", 435), ("ftp_client_thread", 1790)], "heap-use-after-free")
        for result in (other_line, other_kind):
            self.assertEqual(find_duplicate(crash_signature(result) + "x", fault_key(result), earlier), (None, ""))

    def test_ub_findings_are_keyed_by_their_site(self):
        from fbaugur.runner import fault_key
        self.assertEqual(fault_key(parse_report(PORT_UB, 0, False), set()), "undefined-behavior@/src/ftpserv.c:551")


class RebuildFlagsTests(unittest.TestCase):
    def test_project_compile_database_is_moved_onto_the_instrumented_copy(self):
        # tinyproxy needs -DHAVE_CONFIG_H to read config.h; without the project's flags every
        # rebuild failed ("use of undeclared identifier 'PACKAGE'") and no invariant ever ran.
        from fbaugur.instrument import InvariantBuilder
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            (source / "src").mkdir(parents=True)
            (source / "src" / "reqs.c").write_text("int x;\n")
            db = root / "compile_commands.json"
            db.write_text(json.dumps([{"directory": str(source / "src"), "file": str(source / "src" / "reqs.c"),
                                       "arguments": ["clang", "-DHAVE_CONFIG_H", "-I.", f"-I{source}",
                                                     "-c", "reqs.c", "-o", "reqs.o"]}]))
            builder = InvariantBuilder.__new__(InvariantBuilder)
            builder.source_root, builder.compile_database = source, db
            copy = root / "v1" / "src"
            copy.mkdir(parents=True)
            moved = json.loads(builder._relocated_database(copy, root / "v1").read_text())[0]
            self.assertEqual(moved["directory"], str(copy / "src"))
            self.assertEqual(moved["file"], str(copy / "src" / "reqs.c"))
            self.assertIn("-DHAVE_CONFIG_H", moved["arguments"])
            self.assertIn(f"-I{copy}", moved["arguments"])
            self.assertNotIn(f"-I{source}", moved["arguments"])


class PipelineDedupAndDrainTests(unittest.TestCase):
    def _crash(self, store, crash_id, status, signature="", details=None):
        store.insert("crashes", {"crash_id": crash_id, "worker_id": "w-stream", "source": "global_fuzzer",
                                 "input_path": "", "status": status, "signature": signature,
                                 "details": details or {}, "created_at": time.time(), "updated_at": time.time()})

    def test_finding_of_an_earlier_context_is_found_by_stack_and_by_fault_site(self):
        # tinyproxy: the second harness context re-found three bugs the first had reported.
        from fbaugur.orchestrator import prior_findings
        from fbaugur.runner import find_duplicate
        from fbaugur.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan-ctx-451fc82eb0d1"
            scan.mkdir()
            store = Store(scan / "state.db")
            self._crash(store, "crash-931436df7a18", "reported", "keyhash:74 | htab_find_elem:144 | htab_delete:170",
                        {"fault_key": "heap-use-after-free@keyhash:74"})
            self._crash(store, "crash-dup", "duplicate", "keyhash:74 | x:1 | y:2", {"fault_key": "other@x:1"})
            store.conn.close()
            prior = prior_findings([str(scan), str(Path(tmp) / "missing")])
            self.assertEqual([p["crash_id"] for p in prior], ["scan-ctx-451fc82eb0d1/crash-931436df7a18"])
            same, how = find_duplicate("keyhash:74 | htab_find_elem:144 | htab_delete:170", "", prior)
            self.assertEqual((same["crash_id"], how), ("scan-ctx-451fc82eb0d1/crash-931436df7a18", "same stack"))
            other, how = find_duplicate("keyhash:74 | htab_find_elem:144 | lookup:99",
                                        "heap-use-after-free@keyhash:74", prior)
            self.assertEqual(how, "same fault site")

    def test_final_drain_confirms_and_validates_what_the_stopped_lanes_left(self):
        # tinyproxy: a crash recorded 3 s after the deadline stayed "pending" forever.
        import asyncio
        from fbaugur.config import RunConfig
        from fbaugur.orchestrator import Run
        from fbaugur.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            run = Run.__new__(Run)
            run.store = Store(Path(tmp) / "state.db")
            run.cfg = RunConfig(run_dir=tmp, hc_run=tmp, context_id="c", deliveries=["stream"])
            run.emitted = []
            run.emit = run.emitted.append
            run.draining = False
            # deadline is a property over these (it can be extended at run time)
            run.started_at, run._fixed_deadline = time.time() - 10, time.time() - 5
            run.workers = []
            run.stop = asyncio.Event()
            run.stop.set()
            self._crash(run.store, "late", "pending")
            self._crash(run.store, "cut", "confirming")
            self._crash(run.store, "half", "confirmed", details={"replay": "x"})
            self._crash(run.store, "done", "confirmed", details={"validation": {"verdict": "VULNERABILITY"}})
            seen = []

            async def confirm(crash):
                seen.append((crash["crash_id"], run.validation_closed()))
                run.store.update("crashes", "crash_id", crash["crash_id"], {"status": "reported"})

            run._confirm = confirm
            asyncio.run(run.final_drain())
            self.assertEqual(sorted(seen), [("cut", False), ("half", False), ("late", False)])
            self.assertFalse(run.draining)
            self.assertTrue(run.validation_closed())
            self.assertEqual(run.store.scalar("SELECT status FROM crashes WHERE crash_id='done'"), "confirmed")
            self.assertTrue(any("final drain:" in m and "'crashes': 3" in m for m in run.emitted))


class InsertionPlacementTests(unittest.TestCase):
    def test_an_assertion_cannot_become_the_body_of_a_braceless_if(self):
        # tinyproxy hsearch.c: an assertion inserted before `break;` made the break unconditional.
        lines = ["\tfor (i=hash,j=1; ; i+=j++) {", "\t\te = htab->elems + (i & htab->mask);",
                 "\t\tif ((!e->item.key && (!e->hash || e->hash == dead)) ||",
                 "\t\t    (e->hash==hash && STRCMP(e->item.key, key)==0))", "\t\t\tbreak;", "\t}"]
        self.assertTrue(location_problems(lines, 5))
        self.assertIn("line 3", location_problems(lines, 5)[0])
        self.assertEqual(location_problems(lines, 3), [])
        self.assertEqual(location_problems(lines, 2), [])
        self.assertTrue(location_problems(["} else", "  y();"], 2))
        self.assertTrue(location_problems(["if (a)", "{", "  x = 1;"], 2))
        self.assertEqual(location_problems(["if (a) {", "  x = 1;"], 2), [])
        self.assertEqual(location_problems(["foo(a);", "bar();"], 2), [])

    def test_a_located_fault_in_program_code_is_not_put_on_the_last_assertion(self):
        # tinyproxy: the broken lookup faulted in keyhash, and phi 4 -- evaluated last, innocent --
        # was withdrawn as unsafe.
        from fbaugur.orchestrator import Run
        from fbaugur.runner import RunResult as _RunResult

        def RunResult(**kw):
            base = dict(returncode=1, timed_out=False, kind="AddressSanitizer", ubsan=[], violations=[],
                        reached=[], stderr_tail="")
            base.update(kw)
            return _RunResult(**base)

        line_map = {"/w/v3/src/src/hsearch.c": {142: 4}}
        located = RunResult(crashed=True, crash_type="heap-use-after-free", reach_order=[2, 3, 4],
                            frames=[{"function": "keyhash", "file": "/w/v3/src/src/hsearch.c", "line": 74}])
        self.assertEqual(Run._blame_instrumentation(located, line_map, last_evaluated=True), [])
        bare = RunResult(crashed=True, crash_type="SEGV", reach_order=[2, 3, 4], frames=[{"function": "lookup"}])
        self.assertEqual(Run._blame_instrumentation(bare, line_map, last_evaluated=True), [4])
        on_line = RunResult(crashed=True, crash_type="SEGV", reach_order=[4],
                            frames=[{"function": "htab_destroy", "file": "/w/v3/src/src/hsearch.c", "line": 142}])
        self.assertEqual(Run._blame_instrumentation(on_line, line_map, last_evaluated=True), [4])


class DeltaAnchorTests(unittest.TestCase):
    def test_hunks_from_another_revision_are_moved_to_the_analysed_lines(self):
        from fbaugur.delta import changed_functions
        source = ["int a;", "int b;", "", "", "", "", "static int f(void)", "{", "    int i;", "    g(i);",
                  "    return 0;", "}"]
        diff = ("--- a/src/x.c\n+++ b/src/x.c\n@@ -3,4 +3,4 @@ static int f(void)\n"
                " {\n-    int i, j;\n+    int i;\n     g(i);\n     return 0;\n")
        functions = {"f": [{"file": "src/x.c", "start": 7, "end": 12}]}
        changes, report = changed_functions(diff, functions, {}, ["f"], lambda rel: source)
        self.assertEqual(changes[0].changed_lines, [9])            # the diff said 4
        self.assertEqual(report["files"][0]["line_offsets"], [5])
        moved, _ = changed_functions(diff.replace("     g(i);", "     h(i);"), functions, {}, ["f"], lambda rel: source)
        self.assertEqual(moved, [])                                  # text not in the file: diff's own line 4


class ImpactBasisTests(unittest.TestCase):
    """Impact is scored only where it is measured in a normal build or proven from the code."""

    def _toolbox(self, tmp, plain):
        from fbaugur.config import RunConfig
        from fbaugur.store import Store
        from fbaugur.tools import Toolbox
        RunConfig(run_dir=tmp, hc_run=tmp, context_id="c", deliveries=["stream"]).save()
        (Path(tmp) / "index.json").write_text(json.dumps({"source_root": tmp, "harnesses": {}, "targets": [],
                                                           "program": "p"}))
        store = Store(Path(tmp) / "state.db")
        store.insert("crashes", {"crash_id": "c1", "status": "confirming", "details": {"checks": {"plain_build": plain}},
                                 "created_at": time.time(), "updated_at": time.time()})
        return Toolbox(Path(tmp), role="vuln_validator", crash="c1")

    def _submit(self, box, vector, basis, conditional=""):
        return box.submit_validation("VULNERABILITY", "r", "a", "p", "c", vector, ["CWE-122"],
                                     impact_basis=basis, conditional_impact=conditional)

    def test_conditional_impact_is_recorded_but_not_scored(self):
        # The one-byte overflow: harmless in glibc (200/200), claimed I:L/A:L "with hardened allocators".
        from fbaugur.tools import ToolError
        with tempfile.TemporaryDirectory() as tmp:
            box = self._toolbox(tmp, {"configured": True, "started": True, "effect": False,
                                      "summary": "normal build: served 200 of 200 requests"})
            with self.assertRaises(ToolError):          # "measured" contradicts the measurement
                self._submit(box, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L", {"I": "measured", "A": "measured"})
            with self.assertRaises(ToolError):          # conditional needs the condition written down
                self._submit(box, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L", {"I": "conditional", "A": "conditional"})
            out = self._submit(box, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",
                               {"C": "none", "I": "conditional", "A": "conditional"}, "an allocator that checks exact sizes")
            self.assertIn("adjusted", out)
            v = box.store.row("SELECT details FROM crashes WHERE crash_id='c1'")["details"]["validation"]
            self.assertEqual(v["cvss_score"], 0.0)
            self.assertEqual(v["cvss_vector"], "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N")
            self.assertEqual(v["cvss_vector_submitted"], "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L")
            self.assertEqual(len(v["score_adjustments"]), 2)

    def test_measured_impact_keeps_its_score(self):
        # The use-after-free: the normal build aborted ("double free detected in tcache 2").
        from fbaugur.tools import ToolError
        with tempfile.TemporaryDirectory() as tmp:
            box = self._toolbox(tmp, {"configured": True, "started": True, "effect": True, "summary": "died"})
            with self.assertRaises(ToolError):          # an impact with no basis
                self._submit(box, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", {"A": "measured"})
            self._submit(box, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", {"C": "code", "A": "measured"})
            v = box.store.row("SELECT details FROM crashes WHERE crash_id='c1'")["details"]["validation"]
            self.assertEqual(v["cvss_score"], 8.2)
            self.assertEqual(v["score_adjustments"], [])


class PlainReplayTests(unittest.TestCase):
    def test_repeated_requests_stop_when_the_program_dies(self):
        import socket, subprocess, sys as _sys
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp) / "srv.py"
            server.write_text(
                "import socket, os\n"
                f"s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', {port})); s.listen(5)\n"
                "n = 0\nwhile True:\n    c, _ = s.accept()\n    d = c.recv(100)\n    if not d: c.close(); continue\n"
                "    n += 1\n    c.sendall(b'OK ' + d)\n    c.close()\n    if n == 3: os.abort()\n")
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps({"command": f"{_sys.executable} {server}", "port": port, "delivery": "stream",
                                        "input_hex": b"hello".hex(), "repeat": 10, "settle": 1, "io_timeout": 3}))
            root = str(Path(__file__).resolve().parent.parent / "src")
            proc = subprocess.run([_sys.executable, "-m", "fbaugur.daemon_replay", str(spec)], capture_output=True,
                                  text=True, timeout=60, env=dict(os.environ, PYTHONPATH=root))
            out = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(out["runs_sent"], 3)
        self.assertTrue(out["crashed_on_its_own"])
        self.assertEqual(bytes.fromhex(out["response_hex"]), b"OK hello")

    def test_the_debug_allocator_matches_the_program_word_size(self):
        import sys as _sys
        from fbaugur.runner import _elf_kind, debug_allocator_library
        library = debug_allocator_library(_sys.executable)
        if library is None:
            self.skipTest("glibc has no libc_malloc_debug here")
        self.assertEqual(_elf_kind(os.path.realpath(library)), _elf_kind(_sys.executable))


class SpDedupTests(unittest.TestCase):
    """FBv2 core/sp_dedup.py: a model decides; only an exact same bug is merged."""

    def _toolbox(self, tmp):
        from fbaugur.config import RunConfig
        from fbaugur.tools import Toolbox
        RunConfig(run_dir=tmp, hc_run=tmp, context_id="c", deliveries=["stream"]).save()
        (Path(tmp) / "index.json").write_text(json.dumps({"source_root": tmp, "harnesses": {}, "targets": [],
                                                           "program": "p", "functions": {"sblist_new": {}}}))
        return Toolbox(Path(tmp), role="sp_generator", worker="w", harness="h")

    def test_parse_follows_fbv2(self):
        from fbaugur.tools import parse_sp_dedup
        sps = [{"sp_id": "sp-a"}, {"sp_id": "sp-b"}]
        self.assertEqual(parse_sp_dedup('{"duplicate": true, "duplicate_of": "SP-2"}', sps), "sp-b")
        self.assertEqual(parse_sp_dedup('```json\n{"duplicate": true, "duplicate_of": "1"}\n```', sps), "sp-a")
        self.assertEqual(parse_sp_dedup('{"duplicate": true, "duplicate_of": "sp-a"}', sps), "sp-a")
        self.assertIsNone(parse_sp_dedup('{"duplicate": false, "duplicate_of": null}', sps))
        self.assertIsNone(parse_sp_dedup('{"duplicate": true, "duplicate_of": "SP-9"}', sps))
        self.assertIsNone(parse_sp_dedup("no duplicate", sps))

    def test_differently_worded_same_bug_is_merged_and_kept_on_record(self):
        # tinyproxy full scan: "Division by zero" and "null deref / div-by-zero (conditional)" for one
        # sblist_new divisor were never merged, because the first words of the types differ.
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            box = self._toolbox(tmp)
            first = json.loads(box.create_suspicious_point("sblist_new", "Division by zero", "itemsize divides 4096"))
            with mock.patch("fbaugur.tools.sp_duplicate_of", return_value=first["suspicious_point_id"]) as ask:
                out = json.loads(box.create_suspicious_point("sblist_new", "null deref / div-by-zero (conditional)",
                                                             "4096/itemsize with itemsize 0"))
            self.assertTrue(out["merged"])
            self.assertEqual(ask.call_args[0][1][0]["sp_id"], first["suspicious_point_id"])
            rows = box.store.rows("SELECT status, merged_into FROM sps ORDER BY created_at")
            self.assertEqual([r["status"] for r in rows], ["pending_verify", "duplicate"])
            self.assertEqual(rows[1]["merged_into"], first["suspicious_point_id"])

    def test_failed_check_keeps_the_sp(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            box = self._toolbox(tmp)
            box.create_suspicious_point("sblist_new", "Division by zero", "a")
            with mock.patch("fbaugur.tools.subprocess.run", side_effect=OSError("no claude")):
                out = json.loads(box.create_suspicious_point("sblist_new", "Division by zero", "a"))
            self.assertTrue(out["created"])


class StopAndFailureTests(unittest.TestCase):
    """Review 2026-11-17: deleting a preparing session left its processes running; a Codex run that
    completed a turn and then exited 7 counted as completed; a silent preparation agent outlived its limit."""

    def test_deleting_a_preparing_session_ends_its_processes(self):
        from fbaugur import proctrack
        from fbaugur.web.sessions import Sessions
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            sessions = Sessions(home, None, Path(tmp), Path(tmp) / "targets", sys.executable)
            sid = "20990101-000000-test"
            sessions.save({"id": sid, "state": "preparing", "pid": None, "created": time.time()})
            child = proctrack.spawn(sid, ["sleep", "60"])
            self.assertEqual(sessions.delete(sid), "deleted")
            child.wait(timeout=10)
            self.assertIsNotNone(child.returncode)
            with self.assertRaises(proctrack.Cancelled):
                proctrack.spawn(sid, ["sleep", "1"])

    def test_codex_failure_after_a_completed_turn_is_an_error(self):
        from fbaugur.agent import parse_codex
        out = '{"type":"turn.completed","usage":{"input_tokens":1}}\n'
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "tools.jsonl"
            self.assertEqual(parse_codex("r", "role", out, "", log, returncode=0).status, "completed")
            failed = parse_codex("r", "role", out, "boom", log, returncode=7)
            self.assertEqual(failed.status, "error")
            self.assertIn("status 7", failed.error)

    def test_silent_preparation_agent_is_stopped_at_its_limit(self):
        from fbaugur.autoprep import AutoPrep
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "agent"
            fake.write_text("#!/bin/sh\nsleep 30\n")
            fake.chmod(0o755)
            prep = AutoPrep(Path(tmp) / "work", repo="x/y", name="y", provider="claude", model="m",
                            python=sys.executable, hc=Path(tmp), claude=str(fake), agent_timeout=0.5, emit=lambda m: None)
            (Path(tmp) / "work").mkdir()
            started = time.time()
            ok, problems, _ = prep.run()
            self.assertLess(time.time() - started, 10)
            self.assertFalse(ok)
            self.assertIn("did not finish", problems[0])
