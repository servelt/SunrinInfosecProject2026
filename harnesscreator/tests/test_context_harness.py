"""Input-context harness stage: context + verified seeds -> existing generator -> build -> replay."""
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from harnesscreator.agents.harness import CHECKLIST_NAMES
from harnesscreator.contexts.harness import ContextSeed
from harnesscreator.contexts.harness import (
    NOT_PROVEN_CHECK_IDS,
    add_harness_arguments,
    run_context_harness,
)
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import stable_id

CONTEXT_ID = "ctx-stdin0001"

PRELUDE = "#include <stddef.h>\n#include <sys/types.h>\n#include <unistd.h>\n\n"
HANDLE_LINE = (
    "int handle_line(const char *buf, size_t n) {\n"
    "    size_t i;\n"
    "    int lines = 0;\n"
    "    for (i = 0; i < n; i++) {\n"
    "        if (buf[i] == '\\n') lines++;\n"
    "    }\n"
    "    return lines;\n"
    "}\n"
)
MAIN = (
    "int main(void) {\n"
    "    char buf[4096];\n"
    "    ssize_t n = read(0, buf, sizeof(buf));\n"
    "    if (n <= 0) return 1;\n"
    "    return handle_line(buf, (size_t)n) > 0 ? 0 : 1;\n"
    "}\n"
)
SERVICE = PRELUDE + HANDLE_LINE + "\n" + MAIN

# Delivers Data/Size through the program's own stdin read: the bytes are
# written to a pipe that replaces fd 0, then the original main runs.
HARNESS = (
    "#include <stddef.h>\n#include <stdint.h>\n#include <sys/types.h>\n#include <unistd.h>\n\n"
    "int hc_native_original_main(void);\n\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
    "    const uint8_t *hc_fuzz_request = Data;\n"
    "    size_t hc_fuzz_request_size = Size;\n"
    "    int hc_pipe[2];\n"
    "    int hc_saved_stdin;\n"
    "    ssize_t hc_written;\n"
    "    if (Size > 4096) return 0;\n"
    "    if (pipe(hc_pipe) != 0) return 0;\n"
    "    hc_saved_stdin = dup(0);\n"
    "    hc_written = write(hc_pipe[1], hc_fuzz_request, hc_fuzz_request_size);\n"
    "    close(hc_pipe[1]);\n"
    "    if (hc_saved_stdin >= 0 && hc_written == (ssize_t)hc_fuzz_request_size\n"
    "        && dup2(hc_pipe[0], 0) >= 0) {\n"
    "        (void)hc_native_original_main();\n"
    "    }\n"
    "    if (hc_saved_stdin >= 0) {\n"
    "        dup2(hc_saved_stdin, 0);\n"
    "        close(hc_saved_stdin);\n"
    "    }\n"
    "    close(hc_pipe[0]);\n"
    "/*EXTRA*/\n"
    "    return 0;\n"
    "}\n"
)
ABORTING_HARNESS = HARNESS.replace(
    "/*EXTRA*/", "    if (hc_fuzz_request_size > 0) __builtin_trap();")
# Calls the interpreting function directly, skipping the Entry.
BYPASS_HARNESS = (
    "#include <stddef.h>\n#include <stdint.h>\n\n"
    "int handle_line(const char *buf, size_t n);\n\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
    "    const uint8_t *hc_fuzz_request = Data;\n"
    "    size_t hc_fuzz_request_size = Size;\n"
    "    (void)handle_line((const char *)hc_fuzz_request, hc_fuzz_request_size);\n"
    "    return 0;\n"
    "}\n"
)

SEEDS = {
    "seed-a": [b"PING hello\n"],
    "seed-b": [b"PING one\n", b"PING two\n"],
}


def _lines(part: str) -> tuple[int, int]:
    start = SERVICE[:SERVICE.index(part)].count("\n") + 1
    return start, start + part.count("\n") - 1


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _fixture(tmp: Path, *, seeds: bool = True) -> tuple[Path, Path, dict[str, str]]:
    source = tmp / "src"
    source.mkdir()
    (source / "service.c").write_text(SERVICE, encoding="utf-8")
    run = tmp / "run"
    ids = {name: stable_id("fn", "c_cpp", name, "service.c") for name in ("handle_line", "main")}
    functions = []
    for name, text, signature in (
        ("handle_line", HANDLE_LINE, "int handle_line(const char *buf, size_t n)"),
        ("main", MAIN, "int main(void)"),
    ):
        start, end = _lines(text)
        functions.append({
            "function_id": ids[name], "name": name, "qualified_name": name,
            "signature": signature, "language": "c_cpp", "file": "service.c",
            "start_line": start, "end_line": end, "source": text,
            "field_added_by_a_later_version": True,
        })
    _write_jsonl(run / "analysis" / "functions.jsonl", functions)
    call_line = _lines(MAIN)[0] + 4
    _write_jsonl(run / "analysis" / "edges.jsonl", [{
        "edge_id": "edge-main-handle", "caller_id": ids["main"], "callee_id": ids["handle_line"],
        "line": call_line, "kind": "direct", "confidence": 1.0, "providers": ["fixture"],
        "field_added_by_a_later_version": True,
    }])
    entry_line = _lines(MAIN)[0] + 2
    entry_id = "entry-stdin-read"
    _write_jsonl(run / "entries" / "verified.jsonl", [{
        "entry_id": entry_id, "candidate_id": "entry-candidate-1", "status": "VERIFIED",
        "entry_function_id": ids["main"], "source_api": "read",
        "channel_kind": "standard input", "attacker_control": "full",
        "provenance_path": [], "consumer_hints": [ids["handle_line"]],
        "evidence": [{"kind": "first_data_acquisition", "function_id": ids["main"],
                      "file": "service.c", "line": entry_line,
                      "detail": "read(0, buf, sizeof(buf)) fills the local buffer"}],
        "unknowns": [], "verifier_confidence": 0.9, "entry_line": entry_line,
        "first_acquisition_confirmed": True, "field_added_by_a_later_version": True,
    }])
    _write_jsonl(run / "contexts" / "contexts.jsonl", [{
        "context_id": CONTEXT_ID, "resource_kind": "stdin", "priority": 2,
        "deliveries": ["stdin"], "driver_function_id": ids["main"], "driver_function": "main",
        "interpreter_function_ids": [ids["handle_line"]],
        "interpreter_functions": ["handle_line"],
        "target_function_ids": [ids["handle_line"]], "target_function_count": 1, "notes": [],
        "entries": [{
            "entry_id": entry_id, "entry_function_id": ids["main"], "entry_function": "main",
            "entry_file": "service.c", "entry_line": entry_line, "source_api": "read",
            "channel_kind": "standard input", "attacker_control": "full",
            "entry_status": "VERIFIED", "resource_kind": "stdin", "delivery": "stdin",
            "interpreter_function_ids": [ids["handle_line"]],
            "interpreter_source": "consumer_hint", "driver_function_id": ids["main"],
        }],
    }])
    if seeds:
        corpus = run / "seeds" / "corpus" / CONTEXT_ID
        corpus.mkdir(parents=True)
        for seed_id, messages in SEEDS.items():
            (corpus / f"{seed_id}.json").write_text(json.dumps({
                "seed_id": seed_id, "context_id": CONTEXT_ID, "delivery": "stdin",
                "messages_hex": [item.hex() for item in messages], "responses_hex": [],
                "covered_target_function_ids": [ids["handle_line"]],
                "origin": "source_reading", "rationale": "newline-terminated request",
            }), encoding="utf-8")
    return run, source, ids


def _context_turn(complete: bool) -> dict:
    return {
        "context_complete": complete, "requested_function_ids": [],
        "established_facts": ["main reads fd 0 once and passes the buffer to handle_line"],
        "blocking_dependencies": [], "resolved_blocking_dependencies": [],
        "verification_obligations": ["deliver Data/Size through fd 0 and restore it"],
        "terminal_backend_blocker": False, "rationale": "fixture",
    }


def _generation(code: str) -> list[dict]:
    """Responses of the generator: one turn per plan function, then the source."""
    return [
        _context_turn(False),
        _context_turn(True),
        {
            "code": code,
            "manifest": {
                "build_target": "", "headers": [], "libraries": [], "min_size": 0,
                "max_size": 4096, "execution_model": "in_process_reset",
            },
            "checklist": [
                {"check_id": check_id, "status": "PASS", "evidence": "fixture harness"}
                for check_id in CHECKLIST_NAMES
            ],
            "implemented_step_indexes": [0],
            "generation_blockers": [],
        },
    ]


def _review() -> list[dict]:
    """Responses of the independent reviewer; it cannot prove HC11/HC16 from a seed."""
    return [
        {"context_complete": False, "requested_function_ids": [], "rationale": "fixture"},
        {"context_complete": True, "requested_function_ids": [], "rationale": "fixture"},
        {
            "checks": [
                {"check_id": check_id,
                 "status": "WARN" if check_id in NOT_PROVEN_CHECK_IDS else "PASS",
                 "evidence": "reviewed against the opened source", "remediation": ""}
                for check_id in CHECKLIST_NAMES
            ],
            "summary": "seed replay is not an attributed trace",
        },
    ]


def _args(run: Path, *argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_harness_arguments(parser)
    args = parser.parse_args(list(argv))
    args.run_dir = run
    return args


def _summary(run: Path) -> dict:
    return json.loads((run / "context-harnesses" / "summary.json").read_text(encoding="utf-8"))


class ContextHarnessWithoutBuild(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_argument_defaults(self) -> None:
        args = _args(self.root)
        self.assertIsNone(args.context)
        self.assertIsNone(args.delivery)
        self.assertEqual(args.attempts, 2)
        self.assertFalse(args.no_build)

    async def test_generates_audits_and_reviews_a_whole_stream_harness(self) -> None:
        run, source, ids = _fixture(self.root)
        llm = ScriptedLLM([*_generation(HARNESS), *_review()])
        code = await run_context_harness(
            _args(run, "--context", CONTEXT_ID, "--source", str(source), "--no-build"), llm)
        self.assertEqual(code, 0)
        self.assertEqual(
            [call["role"] for call in llm.calls],
            ["harness_generator"] * 3 + ["harness_verifier"] * 3)

        attempt = run / "context-harnesses" / f"{CONTEXT_ID}-stdin" / "attempt-1"
        self.assertEqual((attempt / "fuzz_target.c").read_text(encoding="utf-8"), HARNESS)
        for name in ("harness-plan.json", "manifest.json", "generator-audit.json",
                     "static-audit.json", "independent-audit.json"):
            self.assertTrue((attempt / name).is_file(), name)

        # The fuzz input is the whole first seed; nothing is a fixed setup request.
        payload = llm.calls[2]["payload"]
        first = b"".join(SEEDS["seed-a"]).hex()
        self.assertEqual(payload["harness_plan"]["setup_steps"], [])
        self.assertEqual(payload["harness_plan"]["fuzz_step"]["request_hex"], first)
        self.assertEqual(payload["harness_plan"]["fuzz_entry_function_id"], ids["main"])
        self.assertEqual(payload["harness_plan"]["required_function_ids"], [ids["handle_line"]])
        self.assertEqual(str(payload["scenario_witness"]["status"]), "REPLAYED_RUNTIME")
        self.assertIn("native_builder_main_contract", payload["trusted_build_configuration"])

        static = json.loads((attempt / "static-audit.json").read_text(encoding="utf-8"))
        self.assertEqual(static["blocking_check_ids"], [])
        self.assertFalse(static["strict_passed"])
        failed = {item["check_id"] for item in static["checks"] if item["status"] != "PASS"}
        self.assertEqual(failed, set(NOT_PROVEN_CHECK_IDS))

        summary = _summary(run)
        self.assertEqual(len(summary["harnesses"]), 1)
        row = summary["harnesses"][0]
        self.assertEqual((row["context_id"], row["delivery"]), (CONTEXT_ID, "stdin"))
        self.assertTrue(row["generated"])
        self.assertTrue(row["static_passed"])
        self.assertFalse(row["built"])
        self.assertEqual(row["seeds_replayed"], 0)
        self.assertEqual(row["status"], "GENERATED_NOT_BUILT")
        self.assertNotEqual(row["status"], "QUALIFIED")
        self.assertFalse(row["qualified"])
        self.assertTrue(row["reason"])

    async def test_context_without_seeds_is_blocked_before_any_model_call(self) -> None:
        run, source, _ = _fixture(self.root, seeds=False)
        llm = ScriptedLLM([])
        code = await run_context_harness(
            _args(run, "--context", CONTEXT_ID, "--source", str(source)), llm)
        self.assertEqual(code, 1)
        self.assertEqual(llm.calls, [])
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "GENERATION_BLOCKED")
        self.assertIn("seed", row["reason"])
        self.assertFalse(row["generated"])
        self.assertFalse(row["static_passed"])
        self.assertFalse(row["built"])
        self.assertEqual(row["attempts"], [])

    async def test_harness_that_skips_the_entry_fails_the_static_audit(self) -> None:
        run, source, _ = _fixture(self.root)
        llm = ScriptedLLM(_generation(BYPASS_HARNESS))
        code = await run_context_harness(
            _args(run, "--context", CONTEXT_ID, "--source", str(source),
                  "--attempts", "1", "--no-build"), llm)
        self.assertEqual(code, 1)
        self.assertEqual(len(llm.calls), 3)  # the reviewer is never asked
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "STATIC_FAILED")
        self.assertTrue(row["generated"])
        self.assertFalse(row["static_passed"])
        self.assertIn("HC08", row["reason"])

    async def test_default_selection_is_network_contexts_only(self) -> None:
        run, source, _ = _fixture(self.root)
        llm = ScriptedLLM([])
        code = await run_context_harness(_args(run, "--source", str(source)), llm)
        self.assertEqual(code, 1)
        self.assertEqual(llm.calls, [])
        self.assertEqual(_summary(run)["harnesses"], [])

    async def test_unknown_context_is_a_usage_error(self) -> None:
        run, source, _ = _fixture(self.root)
        code = await run_context_harness(
            _args(run, "--context", "ctx-missing", "--source", str(source)), ScriptedLLM([]))
        self.assertEqual(code, 2)


@unittest.skipUnless(shutil.which("clang") and shutil.which("clang++"), "Clang needed")
class ContextHarnessBuildAndReplay(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    async def test_builds_and_replays_every_seed(self) -> None:
        run, source, _ = _fixture(self.root)
        llm = ScriptedLLM([*_generation(HARNESS), *_review()])
        code = await run_context_harness(
            _args(run, "--context", CONTEXT_ID, "--source", str(source)), llm)
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "BUILT_REPLAYED_NOT_QUALIFIED", row["reason"])
        self.assertEqual(code, 0)
        self.assertTrue(row["built"])
        self.assertEqual(row["seeds_replayed"], len(SEEDS))
        self.assertEqual(row["seeds_replay_ok"], len(SEEDS))
        self.assertFalse(row["qualified"])
        self.assertTrue(Path(row["binary"]).is_file())

        attempt = run / "context-harnesses" / f"{CONTEXT_ID}-stdin" / "attempt-1"
        self.assertTrue(json.loads((attempt / "build.json").read_text())["ok"])
        self.assertIn("NATIVE_BUILD_OK", (attempt / "build.log").read_text())
        replay = json.loads((attempt / "replay.json").read_text(encoding="utf-8"))
        self.assertEqual([item["seed_id"] for item in replay["seeds"]], sorted(SEEDS))
        for item in replay["seeds"]:
            self.assertEqual(item["returncode"], 0, item["output_tail"])
            self.assertFalse(item["sanitizer_report"])
            # Each seed file is the concatenation of the seed's messages.
            self.assertEqual(Path(item["file"]).read_bytes(), b"".join(SEEDS[item["seed_id"]]))

    async def test_seed_that_crashes_the_harness_is_not_counted_as_replayed(self) -> None:
        run, source, _ = _fixture(self.root)
        llm = ScriptedLLM([*_generation(ABORTING_HARNESS), *_review()])
        code = await run_context_harness(
            _args(run, "--context", CONTEXT_ID, "--source", str(source), "--attempts", "1"), llm)
        self.assertEqual(code, 1)
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "BUILT_REPLAY_FAILED", row["reason"])
        self.assertTrue(row["built"])
        self.assertEqual(row["seeds_replayed"], len(SEEDS))
        self.assertEqual(row["seeds_replay_ok"], 0)


if __name__ == "__main__":
    unittest.main()


def _add_original_functions(run: Path, names: list[str]) -> None:
    """Record, for every seed, the functions the original executed beyond a run with no input."""

    for path in (run / "seeds" / "corpus" / CONTEXT_ID).glob("*.json"):
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["target_functions_beyond_baseline"] = names
        path.write_text(json.dumps(raw), encoding="utf-8")


@unittest.skipUnless(shutil.which("clang") and shutil.which("clang++")
                     and (shutil.which("llvm-symbolizer") or shutil.which("addr2line")),
                     "clang and a symbolizer are required")
class ContextHarnessSeedEquivalence(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    async def test_harness_executing_the_same_functions_as_the_original_is_equivalent(self) -> None:
        run, source, _ = _fixture(self.root)
        _add_original_functions(run, ["handle_line"])
        llm = ScriptedLLM([*_generation(HARNESS), *_review()])
        code = await run_context_harness(_args(run, "--context", CONTEXT_ID, "--source", str(source)), llm)
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "BUILT_SEED_EQUIVALENT_NOT_QUALIFIED", row["reason"])
        self.assertEqual(code, 0)
        self.assertEqual(row["seed_equivalence"], {"seeds_measured": len(SEEDS), "seeds_equivalent": len(SEEDS)})
        self.assertFalse(row["qualified"])

    async def test_harness_missing_a_function_the_original_executed_is_a_mismatch(self) -> None:
        run, source, _ = _fixture(self.root)
        _add_original_functions(run, ["handle_line", "function_the_harness_never_runs"])
        llm = ScriptedLLM([*_generation(HARNESS), *_review()])
        code = await run_context_harness(
            _args(run, "--context", CONTEXT_ID, "--source", str(source), "--attempts", "1"), llm)
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "BUILT_SEED_MISMATCH", row["reason"])
        self.assertEqual(code, 1)
        self.assertIn("function_the_harness_never_runs", row["reason"])
        attempt = run / "context-harnesses" / f"{CONTEXT_ID}-stdin" / "attempt-1"
        equivalence = json.loads((attempt / "seed-equivalence.json").read_text(encoding="utf-8"))
        self.assertTrue(all(item["missing"] == ["function_the_harness_never_runs"] for item in equivalence["results"]))


def _measured_args(run: Path, source: Path, *extra: str) -> argparse.Namespace:
    args = _args(run, "--context", CONTEXT_ID, "--source", str(source), *extra)
    args.server_args, args.host, args.port, args.reading_turns, args.legacy_generator = None, "127.0.0.1", 0, 5, False
    return args


def _written(code: str) -> dict:
    return {"code": code, "shape": "wrapped_io", "explanation": "stdin is replaced by a pipe holding Data",
            "persisting_program_state": "none",
            "self_audit": [{"check_id": f"HC{i:02d}", "status": "PASS", "evidence": "see code"} for i in range(1, 17)],
            "blockers": []}


def _reviewed(*failed: str) -> dict:
    return {"summary": "", "checks": [
        {"check_id": f"HC{i:02d}", "status": "FAIL" if f"HC{i:02d}" in failed else "PASS", "evidence": "line"}
        for i in range(1, 17)]}


_READ_DONE = {"open_function_id": "", "enough": True, "notes": ""}


@unittest.skipUnless(shutil.which("clang") and shutil.which("clang++")
                     and (shutil.which("llvm-symbolizer") or shutil.which("addr2line")),
                     "clang and a symbolizer are required")
class MeasuredHarnessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    async def test_harness_is_written_built_replayed_and_compared_with_the_original(self) -> None:
        from harnesscreator.contexts.measured_harness import run_measured_harness
        run, source, _ = _fixture(self.root)
        _add_original_functions(run, ["handle_line"])
        llm = ScriptedLLM([_READ_DONE, _written(HARNESS), _reviewed()])
        code = await run_measured_harness(_measured_args(run, source), llm)
        row = _summary(run)["harnesses"][0]
        self.assertEqual(row["status"], "BUILT_SEED_EQUIVALENT_NOT_QUALIFIED", row["reason"])
        self.assertEqual(code, 0)
        self.assertEqual(row["seeds_replay_ok"], len(SEEDS))
        self.assertEqual(row["seed_equivalence"]["missing_in_harness"], 0)
        self.assertFalse(row["qualified"])
        self.assertEqual([call["role"] for call in llm.calls], ["harness_generator", "harness_generator", "harness_verifier"])
        self.assertIn("functions_the_original_executed_for_the_seeds", llm.calls[1]["payload"]["context"])

    async def test_empty_code_and_a_function_mismatch_are_fed_back_instead_of_ending_the_stage(self) -> None:
        from harnesscreator.contexts.measured_harness import run_measured_harness
        run, source, _ = _fixture(self.root)
        _add_original_functions(run, ["handle_line"])
        empty = dict(_written(""), shape="none", blockers=["cannot call static function"])
        llm = ScriptedLLM([
            _READ_DONE,
            empty,                                        # attempt 1: no code
            _written(BYPASS_HARNESS.replace("handle_line((const char *)hc_fuzz_request, hc_fuzz_request_size)", "0")),
            _reviewed(),                                  # attempt 2: builds and replays, but never runs handle_line
            _written(HARNESS), _reviewed("HC13"),         # attempt 3: equivalent, review objects
        ])
        code = await run_measured_harness(_measured_args(run, source, "--attempts", "3"), llm)
        row = _summary(run)["harnesses"][0]
        statuses = [item["status"] for item in row["attempts"]]
        self.assertEqual(statuses, ["GENERATION_BLOCKED", "BUILT_SEED_MISMATCH", "BUILT_SEED_EQUIVALENT_REVIEW_FAILED"])
        self.assertEqual(row["status"], "BUILT_SEED_EQUIVALENT_REVIEW_FAILED")
        self.assertEqual(code, 1)
        self.assertIn("handle_line", llm.calls[4]["payload"]["feedback_from_previous_attempt"][0])


class ReportClassificationTests(unittest.TestCase):
    def test_reports_in_the_program_are_findings_and_reports_in_the_harness_are_faults(self) -> None:
        from harnesscreator.contexts.measured_harness import classify_reports, program_findings
        ubsan = ("/src/app/proto_bin.c:152:5: runtime error: store to misaligned address 0x6290000052d4 for type "
                 "'uint64_t', which requires 8 byte alignment\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\n")
        program, fault = classify_reports(ubsan, "fuzz_target.c")
        self.assertFalse(fault)
        self.assertEqual((program[0]["file"], program[0]["line"]), ("/src/app/proto_bin.c", 152))
        self.assertIn("ADDR", program[0]["message"])
        program, fault = classify_reports("/run/attempt-1/fuzz_target.c:40:9: runtime error: index 9 out of bounds\n",
                                          "fuzz_target.c")
        self.assertTrue(fault)
        self.assertEqual(program, [])
        asan = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2\n"
                "    #0 0x4f in memcpy /usr/lib/llvm/asan_interceptors.cpp:10\n"
                "    #1 0x50 in process_get /src/app/proto_text.c:77:3\n"
                "    #2 0x51 in LLVMFuzzerTestOneInput /run/attempt-1/fuzz_target.c:200:5\n")
        program, fault = classify_reports(asan, "fuzz_target.c")
        self.assertFalse(fault)
        self.assertEqual((program[0]["function"], program[0]["line"]), ("process_get", 77))
        program, fault = classify_reports(asan.replace("process_get /src/app/proto_text.c:77", "hc_deliver /run/attempt-1/fuzz_target.c:90"),
                                          "fuzz_target.c")
        self.assertTrue(fault)
        grouped = program_findings([{"seed_id": "a", "program_reports": classify_reports(ubsan, "fuzz_target.c")[0]},
                                    {"seed_id": "b", "program_reports": classify_reports(ubsan, "fuzz_target.c")[0]}])
        self.assertEqual((len(grouped), grouped[0]["seeds"]), (1, 2))


class ExpectedFunctionTests(unittest.TestCase):
    def test_whole_input_and_request_thread_measurements_narrow_what_the_harness_must_execute(self) -> None:
        from harnesscreator.contexts.harness import _expected_functions
        paced = {"target_functions_beyond_baseline": ["handle", "aged_path", "maintainer"]}
        self.assertEqual(_expected_functions(paced), ("handle", "aged_path", "maintainer"))
        whole = dict(paced, target_functions_beyond_baseline_whole_input=["handle", "maintainer"])
        self.assertEqual(_expected_functions(whole), ("handle", "maintainer"))
        traced = dict(whole, request_thread_trace="measured", request_thread_functions=["entry", "handle"])
        self.assertEqual(_expected_functions(traced), ("handle",))
        untraced = dict(whole, request_thread_trace="entry_thread_not_found", request_thread_functions=[])
        self.assertEqual(_expected_functions(untraced), ("handle", "maintainer"))


class DatagramFramingTests(unittest.TestCase):
    def test_datagram_seed_keeps_message_boundaries_in_the_harness_input(self) -> None:
        from harnesscreator.contexts.measured_harness import _DatagramSeed
        seed = ContextSeed(seed_id="s", messages=(b"ab", b"xyz"), responses=(), covered_target_function_ids=(),
                           origin="", rationale="", functions_beyond_baseline=("f",))
        framed = _DatagramSeed(seed)
        self.assertEqual(framed.data, b"\x00\x02ab\x00\x03xyz")
        self.assertEqual((framed.seed_id, framed.functions_beyond_baseline), ("s", ("f",)))
