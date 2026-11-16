import asyncio
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from harnesscreator.contexts.agents import decode_text, seeds_from_items
from harnesscreator.contexts.builder import (CallGraph, build_contexts, classify_delivery, classify_resource,
                                             write_contexts)
from harnesscreator.contexts.cli import load_graph
from harnesscreator.contexts.coverage import GcovCoverage
from harnesscreator.contexts.execution import ProgramRunner, ProgramSpec
from harnesscreator.contexts.workflow import SeedWorkflow
from harnesscreator.llm.base import ScriptedLLM

PROGRAM = textwrap.dedent('''\
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    static int stored;
    static void handle_set(const char *arg) { (void)arg; stored = 1; puts("STORED"); }
    static void handle_hit(void) { puts("VALUE"); }
    static void handle_get(const char *arg) { (void)arg; if (stored) handle_hit(); else puts("END"); }
    static void handle_admin(void) { puts("ADMIN"); }
    static void dispatch(char *line) {
        if (!strncmp(line, "set ", 4)) handle_set(line + 4);
        else if (!strncmp(line, "get ", 4)) handle_get(line + 4);
        else if (!strcmp(line, "admin\\n") && getenv("ALLOW_ADMIN")) handle_admin();
        else puts("ERROR");
    }
    int main(void) {
        char line[128];
        while (fgets(line, sizeof line, stdin)) dispatch(line);
        return 0;
    }
''')
FUNCTIONS = ["main", "dispatch", "handle_set", "handle_get", "handle_hit", "handle_admin"]
EDGES = [("main", "dispatch"), ("dispatch", "handle_set"), ("dispatch", "handle_get"),
         ("dispatch", "handle_admin"), ("handle_get", "handle_hit")]


def write_run(run: Path, *, entries=None, extra_functions=(), extra_edges=(), actions=()):
    (run / "analysis").mkdir(parents=True)
    (run / "entries").mkdir()
    names = FUNCTIONS + list(extra_functions)
    with (run / "analysis" / "functions.jsonl").open("w") as handle:
        for index, name in enumerate(names):
            handle.write(json.dumps({
                "function_id": f"fn-{name}", "name": name, "qualified_name": name, "signature": f"void {name}()",
                "language": "c_cpp", "file": "prog.c", "start_line": index + 1, "end_line": index + 1,
                "source": f"void {name}() {{}}"}) + "\n")
    with (run / "analysis" / "edges.jsonl").open("w") as handle:
        for index, (caller, callee, *kind) in enumerate(list(EDGES) + list(extra_edges)):
            handle.write(json.dumps({"edge_id": f"e{index}", "caller_id": f"fn-{caller}", "callee_id": f"fn-{callee}",
                                     "kind": kind[0] if kind else "direct"}) + "\n")
    entries = entries or [{"entry_id": "entry-stdin", "entry_function_id": "fn-main", "source_api": "fgets",
                           "channel_kind": "process standard input stream", "status": "VERIFIED", "entry_line": 17,
                           "attacker_control": "full", "consumer_hints": ["fn-dispatch"]}]
    with (run / "entries" / "verified.jsonl").open("w") as handle:
        for entry in entries:
            handle.write(json.dumps(entry) + "\n")
    if actions:
        (run / "actions").mkdir()
        with (run / "actions" / "discovered-semantic.jsonl").open("w") as handle:
            for action in actions:
                handle.write(json.dumps(action) + "\n")


class BuilderTests(unittest.TestCase):
    def test_resource_and_delivery_classification(self):
        self.assertEqual(classify_resource("recvfrom", "UDP datagram socket input"), "network")
        self.assertEqual(classify_delivery("network", "recvfrom", "UDP datagram socket input"), "datagram")
        self.assertEqual(classify_delivery("network", "read", "AF_INET TCP stream socket input"), "stream")
        self.assertEqual(classify_resource("read", "eventfd backend-notification wakeup counter"), "internal")
        self.assertEqual(classify_resource("argv", "process-launch command-line arguments (argc/argv)"), "argv")
        self.assertEqual(classify_resource("fgets", "standard input interactive debug-command line"), "stdin")
        self.assertEqual(classify_resource("getenv", "process environment variable input"), "env")
        self.assertEqual(classify_resource("fgets", "filesystem PID-file input"), "file")
        self.assertEqual(classify_resource("ioctl", "something else"), "unknown")

    def test_entries_sharing_a_driver_form_one_context_and_internal_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            entries = [
                {"entry_id": "e-tcp", "entry_function_id": "fn-tcp_read", "source_api": "read", "status": "VERIFIED",
                 "channel_kind": "AF_INET TCP stream socket input", "consumer_hints": []},
                {"entry_id": "e-udp", "entry_function_id": "fn-udp_read", "source_api": "recvfrom", "status": "VERIFIED",
                 "channel_kind": "UDP datagram socket input", "consumer_hints": []},
                {"entry_id": "e-evt", "entry_function_id": "fn-notify", "source_api": "read", "status": "VERIFIED",
                 "channel_kind": "eventfd worker-thread I/O notification", "consumer_hints": []},
                {"entry_id": "e-pid", "entry_function_id": "fn-save_pid", "source_api": "fgets", "status": "VERIFIED",
                 "channel_kind": "filesystem PID-file input", "consumer_hints": []},
            ]
            # Run-to-run noise: the two Entries name different dispatchers, plus one unrelated to the acquisition.
            actions = [{"entry_id": "e-tcp", "dispatcher_function_id": "fn-dispatch"},
                       {"entry_id": "e-udp", "dispatcher_function_id": "fn-handle_get"},
                       {"entry_id": "e-pid", "dispatcher_function_id": "fn-dispatch"}]
            write_run(run, entries=entries, actions=actions,
                      extra_functions=["drive", "tcp_read", "udp_read", "notify", "save_pid"],
                      extra_edges=[("drive", "tcp_read", "indirect_possible"), ("drive", "udp_read", "indirect_possible"),
                                   ("drive", "dispatch"), ("main", "save_pid"), ("drive", "notify")])
            result = build_contexts(run)
            by_kind = {ctx.resource_kind: ctx for ctx in result["contexts"]}
            network = by_kind["network"]
            self.assertEqual(network.driver_function, "drive")
            self.assertEqual({m.entry_id for m in network.entries}, {"e-tcp", "e-udp"})
            self.assertEqual(network.deliveries, ["datagram", "stream"])
            self.assertIn("fn-handle_hit", network.target_function_ids)
            # save_pid's only recorded dispatcher has no call path from it other than through main.
            self.assertEqual(by_kind["file"].entries[0].entry_id, "e-pid")
            self.assertEqual([row["entry_id"] for row in result["excluded"]], ["e-evt"])
            self.assertEqual(result["contexts"][0].resource_kind, "network")
            first = [ctx.context_id for ctx in result["contexts"]]
            self.assertEqual(first, [ctx.context_id for ctx in build_contexts(run)["contexts"]])
            write_contexts(run, result)
            self.assertTrue((run / "contexts" / "contexts.jsonl").is_file())

    def test_driver_is_nearest_common_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            write_run(run)
            graph = CallGraph.from_run(run)
            self.assertEqual(graph.driver("fn-handle_set", ["fn-handle_hit"]), "fn-dispatch")
            self.assertEqual(graph.driver("fn-main", ["fn-dispatch"]), "fn-main")
            self.assertEqual(graph.reachable(["fn-handle_get"]), {"fn-handle_get", "fn-handle_hit"})


class CliTests(unittest.TestCase):
    def test_program_command_option_does_not_replace_the_subcommand(self):
        from harnesscreator.cli import build_parser
        args = build_parser().parse_args([
            "seeds", "/tmp/run", "--source", "/tmp/src", "--coverage-root", "/tmp/cov",
            "--command", "/tmp/cov/server -p 1", "--channel", "tcp", "--port", "1"])
        self.assertEqual(args.command, "seeds")
        self.assertEqual(args.program_command, "/tmp/cov/server -p 1")
        for argv in (["contexts", "/tmp/run"], ["context-harness", "/tmp/run"]):
            self.assertEqual(build_parser().parse_args(argv).command, argv[0])


class SeedDecodingTests(unittest.TestCase):
    def test_text_escapes_and_hex(self):
        self.assertEqual(decode_text("get k\\r\\n\\x00\\\\"), b"get k\r\n\x00\\")
        seeds = seeds_from_items(
            [{"name": "a", "messages": [{"encoding": "text", "data": "x\\n"}, {"encoding": "hex", "data": "00 ff"}],
              "rationale": "", "evidence": []},
             {"name": "bad", "messages": [{"encoding": "hex", "data": "zz"}], "rationale": "", "evidence": []}],
            context_id="c", delivery="stream", origin="generator")
        self.assertEqual([s.messages for s in seeds], [[b"x\n", b"\x00\xff"]])


SERVER = textwrap.dedent('''\
    import socket, sys
    kind, port = sys.argv[1], int(sys.argv[2])
    if kind == "tcp":
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(1)
        while True:
            c, _ = s.accept(); c.sendall(b"HELLO\\n")
            while True:
                d = c.recv(4096)
                if not d: break
                c.sendall(b"echo:" + d)
            c.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
        while True:
            d, a = s.recvfrom(4096); s.sendto(b"echo:" + d, a)
''')


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_stream_and_datagram_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "server.py"
            script.write_text(SERVER)
            port = free_port()
            observation = await ProgramRunner(ProgramSpec(
                command=[sys.executable, str(script), "tcp", str(port)], cwd=Path(tmp), delivery="stream",
                port=port, step_timeout=0.3)).run([b"one\n", b"two\n"])
            self.assertEqual(observation.responses, [b"HELLO\n", b"echo:one\n", b"echo:two\n"])
            port = free_port()
            observation = await ProgramRunner(ProgramSpec(
                command=[sys.executable, str(script), "tcp", str(port)], cwd=Path(tmp), delivery="stream",
                port=port, step_timeout=0.3)).run([b"one\n", b"two\n"], paced=False)
            self.assertEqual(observation.responses[0], b"")
            self.assertEqual(observation.responses[1].replace(b"echo:", b""), b"HELLO\none\ntwo\n")
            self.assertEqual(observation.error, "")
            self.assertTrue(observation.exit_status.startswith("signalled"))
            port = free_port(socket.SOCK_DGRAM)
            observation = await ProgramRunner(ProgramSpec(
                command=[sys.executable, str(script), "udp", str(port)], cwd=Path(tmp), delivery="datagram",
                port=port, step_timeout=0.5)).run([b"ping"])
            self.assertEqual(observation.responses, [b"", b"echo:ping"])

    async def test_missing_listener_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            observation = await ProgramRunner(ProgramSpec(
                command=[sys.executable, "-c", "import time; time.sleep(30)"], cwd=Path(tmp), delivery="stream",
                port=free_port(), startup_timeout=0.3)).run([b"x"])
            self.assertIn("no listener", observation.error)


def seed_item(name, *lines):
    return {"name": name, "messages": [{"encoding": "text", "data": "".join(lines)}], "rationale": name,
            "evidence": [{"file": "prog.c", "line": 10, "detail": "dispatch keyword"}]}


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gcov"), "gcc and gcov are required")
class SeedWorkflowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.build = root / "build"
        self.build.mkdir()
        (self.build / "prog.c").write_text(PROGRAM)
        subprocess.run(["gcc", "--coverage", "-O0", "-o", "prog", "prog.c"], cwd=self.build, check=True)
        self.run_dir = root / "run"
        write_run(self.run_dir)
        write_contexts(self.run_dir, build_contexts(self.run_dir))
        self.context = json.loads((self.run_dir / "contexts" / "contexts.jsonl").read_text().splitlines()[0])

    def tearDown(self):
        self.tmp.cleanup()

    def workflow(self, llm):
        return SeedWorkflow(
            run_dir=self.run_dir, context=self.context, delivery="stdin", graph=load_graph(self.run_dir),
            callgraph=CallGraph.from_run(self.run_dir), llm=llm, coverage=GcovCoverage(self.build),
            runner=ProgramRunner(ProgramSpec(command=[str(self.build / "prog")], cwd=self.build, delivery="stdin")),
            source_root=self.build, artifact_paths=[])

    async def test_seeds_are_measured_and_state_dependent_code_is_reached_through_the_frontier(self):
        self.assertEqual(self.context["resource_kind"], "stdin")
        self.assertEqual(self.context["driver_function"], "main")
        llm = ScriptedLLM([
            {"seeds": [seed_item("set", "set k\\n"), seed_item("get miss", "get k\\n")],
             "open_function_id": "", "open_artifact_path": "", "done": True, "notes": ""},
            # frontier: handle_admin (needs an environment variable the run does not set)
            {"seeds": [seed_item("admin", "admin\\n")], "open_function_id": "", "give_up": False,
             "blocked_reason": "NONE", "explanation": "try the keyword"},
            {"seeds": [], "open_function_id": "", "give_up": True, "blocked_reason": "NEEDS_STARTUP_OPTION",
             "explanation": "prog.c:12 requires ALLOW_ADMIN in the environment"},
            # frontier: handle_hit (needs the state a set request creates)
            {"seeds": [seed_item("set then get", "set k\\n", "get k\\n")], "open_function_id": "", "give_up": False,
             "blocked_reason": "NONE", "explanation": "handle_get calls handle_hit only when stored is set"},
        ])
        summary = await self.workflow(llm).run()
        self.assertEqual(summary["executed_without_input"], 0)
        self.assertEqual(summary["executed_only_with_seeds"], 4)   # dispatch, handle_set, handle_get, handle_hit
        self.assertEqual(summary["frontier_attempts"], {"GAVE_UP": 1, "REACHED": 1})
        self.assertEqual(summary["frontier_blocked_reasons"], {"NEEDS_STARTUP_OPTION": 1})
        self.assertEqual(summary["frontier_remaining"], 1)
        self.assertEqual(summary["stopped"], "frontier_empty")
        results = {row["seed_id"]: row for row in map(json.loads, (self.run_dir / "seeds" / "results.jsonl").read_text().splitlines())}
        statuses = sorted(row["status"] for row in results.values())
        # "admin\n" only reaches the error branch of dispatch: new line, so it is kept as a seed.
        self.assertEqual(statuses, ["ACCEPTED_NEW"] * 4)
        corpus = list((self.run_dir / "seeds" / "corpus" / self.context["context_id"]).glob("*.json"))
        self.assertEqual(len(corpus), 4)
        sequence = [json.loads(p.read_text()) for p in corpus if b"set k\nget k\n" == bytes.fromhex("".join(json.loads(p.read_text())["messages_hex"]))]
        self.assertEqual(len(sequence), 1)
        self.assertIn("fn-handle_hit", sequence[0]["covered_target_function_ids"])
        self.assertIn(b"VALUE", bytes.fromhex(sequence[0]["responses_hex"][-1]))
        roles = [call["role"] for call in llm.calls]
        self.assertEqual(roles, ["seed_generator", "seed_frontier", "seed_frontier", "seed_frontier"])
        self.assertTrue(llm.calls[2]["payload"]["previous_attempts"][0]["target_executed"] is False)

        # Second run: earlier candidates are measured again and the given-up function is not asked again.
        llm = ScriptedLLM([{"seeds": [], "open_function_id": "", "open_artifact_path": "", "done": True, "notes": ""}])
        summary = await self.workflow(llm).run()
        self.assertEqual(summary["executed_only_with_seeds"], 4)
        self.assertEqual(summary["frontier_attempts"], {})
        self.assertEqual(len((self.run_dir / "seeds" / "results.jsonl").read_text().splitlines()), 4)

    async def test_seed_that_reaches_nothing_is_rejected_and_missing_coverage_is_an_error(self):
        llm = ScriptedLLM([{"seeds": [{"name": "empty line", "messages": [{"encoding": "hex", "data": ""}],
                                       "rationale": "", "evidence": []}, seed_item("set", "set k\\n")],
                            "open_function_id": "", "open_artifact_path": "", "done": True, "notes": ""}])
        workflow = self.workflow(llm)
        workflow.frontier_turns = 0
        summary = await workflow.run()
        self.assertEqual(summary["seed_results"], {"ACCEPTED_NEW": 1})
        for path in self.build.glob("*.gcno"):
            path.unlink()
        from harnesscreator.contexts.coverage import CoverageUnavailable
        with self.assertRaises(CoverageUnavailable):
            await self.workflow(ScriptedLLM([])).baseline()


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gcov"), "gcc and gcov are required")
class SeedWorkflowRobustnessTests(SeedWorkflowTests):
    def setUp(self):
        super().setUp()
        # A function that exists in the analysis graph but is not compiled into the program.
        shutil.rmtree(self.run_dir)
        write_run(self.run_dir, extra_functions=["handle_optional"], extra_edges=[("dispatch", "handle_optional")])
        write_contexts(self.run_dir, build_contexts(self.run_dir))
        self.context = json.loads((self.run_dir / "contexts" / "contexts.jsonl").read_text().splitlines()[0])

    async def test_seeds_are_measured_and_state_dependent_code_is_reached_through_the_frontier(self):
        self.skipTest("covered by the parent class")

    async def test_seed_that_reaches_nothing_is_rejected_and_missing_coverage_is_an_error(self):
        self.skipTest("covered by the parent class")

    async def test_uncompiled_targets_are_not_explored_and_a_failed_model_turn_does_not_end_the_stage(self):
        self.assertIn("fn-handle_optional", self.context["target_function_ids"])
        llm = ScriptedLLM([
            {"seeds": [seed_item("set", "set k\\n"), seed_item("get miss", "get k\\n")],
             "open_function_id": "", "open_artifact_path": "", "done": True, "notes": ""},
            # The scripted model has no answer for the first frontier function: that turn raises.
        ])
        summary = await self.workflow(llm).run()
        self.assertEqual(summary["target_functions"], 6)
        self.assertEqual(summary["target_functions_not_in_this_build"], 1)
        self.assertEqual(summary["frontier_attempts"], {"MODEL_ERROR": 2})   # handle_admin, handle_hit
        self.assertEqual(summary["executed_only_with_seeds"], 3)
        frontier = [json.loads(line) for line in (self.run_dir / "seeds" / "frontier.jsonl").read_text().splitlines()]
        self.assertNotIn("handle_optional", [row["target_function"] for row in frontier])
        self.assertTrue((self.run_dir / "seeds" / f"summary-{self.context['context_id']}-stdin.json").is_file())


COUNT_PROGRAM = PROGRAM.replace(
    "static void dispatch(char *line) {",
    "static void handle_count(void) {\n"
    "    if (stored)\n"
    "        puts(\"ONE\");\n"
    "    else\n"
    "        puts(\"ZERO\");\n"
    "}\n"
    "static void dispatch(char *line) {").replace(
    "    else if (!strcmp(line, \"admin\\n\")",
    "    else if (!strcmp(line, \"count\\n\")) handle_count();\n    else if (!strcmp(line, \"admin\\n\")")


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gcov"), "gcc and gcov are required")
class LineFrontierTests(unittest.IsolatedAsyncioTestCase):
    """A state-dependent branch that calls no new function is found through unexecuted lines."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.build = root / "build"
        self.build.mkdir()
        self.assertIn("handle_count", COUNT_PROGRAM)
        (self.build / "prog.c").write_text(COUNT_PROGRAM)
        subprocess.run(["gcc", "--coverage", "-O0", "-o", "prog", "prog.c"], cwd=self.build, check=True)
        self.run_dir = root / "run"
        write_run(self.run_dir, extra_functions=["handle_count"], extra_edges=[("dispatch", "handle_count")])
        write_contexts(self.run_dir, build_contexts(self.run_dir))
        self.context = json.loads((self.run_dir / "contexts" / "contexts.jsonl").read_text().splitlines()[0])

    def tearDown(self):
        self.tmp.cleanup()

    async def test_branch_needing_earlier_state_is_reached_without_any_new_function(self):
        give_up = {"seeds": [], "open_function_id": "", "give_up": True, "blocked_reason": "NEEDS_STARTUP_OPTION",
                   "explanation": "needs ALLOW_ADMIN"}
        frontier = lambda *lines: {"seeds": [seed_item("frontier", *lines)], "open_function_id": "",
                                   "give_up": False, "blocked_reason": "NONE", "explanation": ""}
        llm = ScriptedLLM([
            {"seeds": [seed_item("set", "set k\\n"), seed_item("get", "get k\\n"), seed_item("count", "count\\n")],
             "open_function_id": "", "open_artifact_path": "", "done": True, "notes": ""},
            give_up,                            # function frontier: handle_admin
            frontier("set k\\n", "get k\\n"),   # function frontier: handle_hit
            frontier("bogus\\n"),               # lines of dispatch: the admin test and the error branch
            frontier("set k\\n", "count\\n"),   # lines of handle_count: the branch taken only after a set
        ])
        workflow = SeedWorkflow(
            run_dir=self.run_dir, context=self.context, delivery="stdin", graph=load_graph(self.run_dir),
            callgraph=CallGraph.from_run(self.run_dir), llm=llm, coverage=GcovCoverage(self.build),
            runner=ProgramRunner(ProgramSpec(command=[str(self.build / "prog")], cwd=self.build, delivery="stdin")),
            source_root=self.build, artifact_paths=[], explore_lines=True)
        summary = await workflow.run()
        self.assertEqual(summary["frontier_attempts"], {"GAVE_UP": 1, "REACHED": 1})
        self.assertEqual(summary["line_frontier_attempts"], {"REACHED_ALL": 2})
        self.assertEqual(summary["executed_functions_with_unexecuted_lines"], 0)
        line_calls = [call for call in llm.calls if "unexecuted_lines" in call["payload"]]
        self.assertEqual([call["payload"]["function"]["name"] for call in line_calls], ["dispatch", "handle_count"])
        corpus = [json.loads(p.read_text()) for p in (self.run_dir / "seeds" / "corpus" / self.context["context_id"]).glob("*.json")]
        after_set = [seed for seed in corpus if bytes.fromhex("".join(seed["messages_hex"])) == b"set k\ncount\n"]
        self.assertEqual(len(after_set), 1)
        self.assertIn(b"ONE", bytes.fromhex(after_set[0]["responses_hex"][-1]))


THREADED = textwrap.dedent('''\
    #include <pthread.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    static volatile int stop;
    static void bg_work(void) { usleep(1000); }
    static void *bg(void *a) { (void)a; while (!stop) bg_work(); return NULL; }
    static void handle_set(void) { puts("STORED"); }
    static void dispatch(char *l) { if (!strncmp(l, "set", 3)) handle_set(); }
    int main(void) {
        pthread_t t; char l[64];
        pthread_create(&t, NULL, bg, NULL);
        while (fgets(l, sizeof l, stdin)) dispatch(l);
        usleep(20000); stop = 1; pthread_join(t, NULL);
        return 0;
    }
''')


@unittest.skipUnless(shutil.which("gcc") and shutil.which("nm"), "gcc and nm are required")
class ThreadTraceTests(unittest.TestCase):
    def test_functions_are_attributed_to_the_thread_that_ran_the_entry_function(self):
        from harnesscreator.contexts.thread_trace import SymbolTable, build_hook_object, read_trace, request_functions
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "p.c").write_text(THREADED)
            hook = build_hook_object(root / "hook.o")
            subprocess.run(["gcc", "-O0", "-g", "-finstrument-functions", "-o", "p", "p.c", str(hook), "-lpthread"],
                           cwd=root, check=True)
            trace = root / "trace.txt"
            subprocess.run([str(root / "p")], input=b"set k\n", cwd=root, check=True, capture_output=True,
                           env={"HC_THREAD_TRACE": str(trace), "PATH": "/usr/bin:/bin"})
            threads = read_trace(trace, SymbolTable(root / "p"))
            self.assertEqual(len(threads), 2)
            request = request_functions(threads, {"main"})
            self.assertEqual(request, {"main", "dispatch", "handle_set"})
            self.assertEqual(request_functions(threads, {"bg"}), {"bg", "bg_work"})
            self.assertEqual(request_functions(threads, {"not_there"}), set())
