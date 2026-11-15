import shutil
import subprocess
import tempfile
import unittest
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.assertions import (execute_assertion, guided_fuzz_assertion,
    instrument_copy,
    parse_violation, triage_assertion_violation, triage_violation,
    validate_expression_source)
from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.runtime import RuntimeExecutor
from vulnerabilityanalysis.scan import run_assertions_for_scan, scan_selected
from vulnerabilityanalysis.models import Assertion, FunctionAnalysis, RuntimeResult
from vulnerabilityanalysis.workflow import run_phase1


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "harnessgenerator/harnesscreator/tests/fixtures/c_project/target.c"


class AssertionFlowTest(unittest.TestCase):
    def test_only_source_defined_pure_function_macros_are_proposed(self):
        expression = "FORMAT_KIND(format) == 0 || FORMAT_COUNT(format) == expected"
        macros = ["#define FORMAT_KIND(x) (((x)>>16)&31)\n"
                  "#define FORMAT_COUNT(x) (((x)>>3)&15)\n"]
        validate_expression_source(expression, "", macro_sources=macros)
        with self.assertRaisesRegex(ValueError, "function calls are forbidden"):
            validate_expression_source(expression, "")
        for definition in ("#define FORMAT_KIND(x) ((x)++)",
                           "#define FORMAT_KIND(x) ((x) <<= 1)",
                           "#define FORMAT_KIND(x) helper(x)"):
            with self.subTest(definition=definition), self.assertRaises(ValueError):
                validate_expression_source("FORMAT_KIND(format) == 0", "",
                                           macro_sources=[definition])
        with self.assertRaisesRegex(ValueError, "function calls are forbidden"):
            validate_expression_source("helper(format) == 0", "", macro_sources=macros)

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_target_preprocessing_guards_normal_and_guided_macro_instrumentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "format.h").write_text(
                "#define FORMAT_KIND(x) (((x)>>16)&31)\n"
                "#define FORMAT_COUNT(x) (((x)>>3)&15)\n"
                "#define BAD(x) ((x)++)\n")
            source = root / "target.c"
            source.write_text('#include "format.h"\n'
                              'int check(unsigned format, unsigned expected) {\n'
                              '  return 1;\n'
                              '}\n'
                              'int main(int argc, char **argv) {\n'
                              '  return check(24u, argc > 1 ? 4u : 3u) - 1;\n'
                              '}\n')
            build = ["clang", "-I", str(root), "{source}", "-o", "{binary}"]
            expression = "FORMAT_KIND(format) != 0 || FORMAT_COUNT(format) == expected"
            for guided in (False, True):
                with self.subTest(guided=guided):
                    copy = root / ("guided.c" if guided else "instrumented.c")
                    binary = root / ("guided" if guided else "instrumented")
                    instrument_copy(source, 3, expression, copy, "a-macro",
                                    guided=guided, build_command=build)
                    compiled = subprocess.run(["clang", "-I", str(root), str(copy),
                                               "-o", str(binary)], capture_output=True, text=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    self.assertEqual(subprocess.run([str(binary)], capture_output=True).returncode, 0)
                    violation = subprocess.run([str(binary), "violate"], capture_output=True)
                    self.assertIn(b"VA_ASSERTION_VIOLATION:a-macro", violation.stderr)
            # Both parser rejection and explicit side-effect rejection keep
            # the macro expansion out of executable Assertion code.
            with self.assertRaisesRegex(
                    ValueError, "side effects|invalid parenthesized operand"):
                instrument_copy(source, 3, "BAD(format) == 0", root / "bad.c", "a-bad",
                                build_command=build)
            with self.assertRaisesRegex(ValueError, "function calls are forbidden"):
                instrument_copy(source, 3, "unknown(format) == 0", root / "unknown.c",
                                "a-unknown", build_command=build)
            with self.assertRaisesRegex(ValueError, "function calls are forbidden"):
                instrument_copy(source, 3, expression, root / "unverified.c", "a-unverified")
            (root / "format.h").write_text((root / "format.h").read_text() +
                                           "#define ADVANCE(x) ((x)+1)\n")
            pointer_source = root / "pointer.c"
            pointer_source.write_text('#include <stddef.h>\n#include "format.h"\n'
                                      'int check(const char *base, size_t n) {\n'
                                      '  const char *cursor = base;\n'
                                      '  return 0;\n}\n')
            with self.assertRaisesRegex(ValueError, "out-of-bounds pointer addition"):
                instrument_copy(pointer_source, 5, "ADVANCE(cursor) <= base + n",
                                root / "pointer-instrumented.c", "a-pointer-macro",
                                build_command=build)

    def test_pointer_name_in_struct_member_does_not_match_local_variable(self):
        # The narrow syntactic check must not confuse a member named
        # offset_table with an unrelated local pointer of that name.
        validate_expression_source(
            "state->offset_table + count > state->offset_table",
            "const char *offset_table = 0;\n")

    def test_instrumentation_rejects_unbounded_pointer_addition(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "target.c"
            source.write_text("#include <stddef.h>\n"
                              "int parse(const char *base, size_t n) {\n"
                              "  const char *cursor = base;\n"
                              "  return cursor[0];\n}\n")
            with self.assertRaisesRegex(ValueError, "out-of-bounds pointer addition"):
                instrument_copy(source, 4, "cursor + n <= base + n",
                                Path(tmp) / "instrumented.c", "a-pointer")
            self.assertFalse((Path(tmp) / "instrumented.c").exists())

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_scan_executes_proposed_assertion_with_supplied_build_and_seed(self):
        test_case = self
        class Pipeline:
            def __init__(self, *_args, **_kwargs):
                self.verifications = {}

            async def analyze_function(self, _id, name, source_file, _source, _context=None,
                                       **_kwargs):
                return FunctionAnalysis(_id, name, source_file, "short inputs safe-return",
                                        "harness bytes", [], [], ["size >= 2 at entry"], [])

            async def generate_sp(self, *_args, **_kwargs):
                return []

            async def generate_assertions(self, analysis, worker_id, direction_id,
                                          _source, **_kwargs):
                test_case.assertIn("LLVMFuzzerTestOneInput", _kwargs["harness_source"])
                test_case.assertTrue(Path(_kwargs["harness_source_path"]).is_file())
                return [Assertion("a-scan", worker_id, direction_id, analysis.function_name,
                                  f"{analysis.source_file}:9", "size >= 2 at entry",
                                  "size >= 2", [])]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            shutil.copy2(TARGET, target / "target.c")
            (root / "project.json").write_text(json.dumps({"source_root": str(target)}))
            (root / "analysis").mkdir()
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "name": "parse_frame", "file": "target.c", "start_line": 8}) + "\n")
            fixture = root / "fixture"
            fixture.mkdir()
            harness = fixture / "harness.c"
            harness.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                               "extern int parse_frame(const uint8_t *, size_t);\n"
                               "int LLVMFuzzerTestOneInput(const uint8_t *p, size_t n)"
                               " {parse_frame(p,n); return 0;}\n")
            (fixture / "manifest.json").write_text(json.dumps({
                "harness_id": "fixture", "artifact_kind": "REGRESSION_FIXTURE",
                "project_harness": False, "source_file": str(harness),
                "expected_anchors": ["parse_frame"],
                "expected_consumers": ["parse_frame"], "sanitizers": ["ASAN"]}))
            (fixture / "validation.json").write_text('{"build_ok":true}')
            run = run_phase1(fixture, root / "runs", target_repository=target)
            seed = root / "seed.bin"
            seed.write_bytes(b"A")
            build = ["clang", "-fsanitize=fuzzer,address", "-g", "{source}",
                     str(harness), "-o", "{binary}"]
            with patch("vulnerabilityanalysis.scan.AgentPipeline", Pipeline):
                asyncio.run(scan_selected(run, object(), target_repository=target,
                    assertion_build_command=build,
                    assertion_run_command=["{binary}", "{input}"], assertion_seed=seed))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(scan["assertion_execution"]["status"], "EXECUTED")
            self.assertEqual(scan["assertion_execution"]["results"]["a-scan"], "VIOLATED")
            self.assertEqual(json.loads((run / "assertions/history.json").read_text())[0]
                             ["next_action"], "REANALYZE")
            blocked_run = run_phase1(fixture, root / "runs", target_repository=target)
            with patch("vulnerabilityanalysis.scan.AgentPipeline", Pipeline):
                asyncio.run(scan_selected(blocked_run, object(), target_repository=target))
            blocked = json.loads((blocked_run / "scan.json").read_text())
            self.assertEqual(blocked["assertion_execution"]["status"], "BLOCKED")
            self.assertEqual(blocked["assertion_execution"]["results"]["a-scan"], "BLOCKED")

    def test_scan_blocks_missing_function_analysis_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "assertions").mkdir()
            (run / "run.json").write_text('{"run_id":"test"}')
            (run / "assertions/proposed.json").write_text(json.dumps([{
                "assertion_id": "a-missing", "worker_id": "w", "direction_id": "d",
                "function": "parse_frame", "source_location": "target.c:9",
                "safe_assumption": "size >= 2", "runtime_expression": "size >= 2",
                "required_context": []}]))
            seed = run / "seed"
            seed.write_bytes(b"A")
            outcomes = run_assertions_for_scan(run, TARGET, seed,
                ["clang", "{source}", "-o", "{binary}"], ["{binary}", "{input}"])
            self.assertEqual(outcomes[0].status, "BLOCKED")
            self.assertFalse((run / "assertions/a-missing/executions").exists())

    def test_scan_rejects_source_path_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "assertions").mkdir()
            (run / "run.json").write_text('{"run_id":"test"}')
            analysis = run / "analysis.json"
            analysis.write_text(json.dumps({"function_name": "parse_frame",
                                            "safe_assumptions": ["size >= 2"]}))
            (run / "assertions/proposed.json").write_text(json.dumps([{
                "assertion_id": "a-wrong", "worker_id": "w", "direction_id": "d",
                "function": "parse_frame", "source_location": "other.c:9",
                "safe_assumption": "size >= 2", "runtime_expression": "size >= 2",
                "required_context": [], "source_function_analysis": str(analysis)}]))
            seed = run / "seed"
            seed.write_bytes(b"A")
            outcomes = run_assertions_for_scan(run, TARGET, seed,
                ["clang", "{source}", "-o", "{binary}"], ["{binary}", "{input}"])
            self.assertEqual(outcomes[0].status, "INVALID_ASSERTION")

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_held_and_not_reached_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text("#include <stddef.h>\nint target(const char *p, size_t n) {\n"
                              "  if (n == 0) return 0;\n  return p[0];\n}\n")
            harness = root / "harness.c"
            harness.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                               "extern int target(const char *, size_t);\n"
                               "int LLVMFuzzerTestOneInput(const uint8_t *p, size_t n) {"
                               "if (n && p[0] == 'Z') target((const char *)p,n); return 0;}\n")
            build = ["clang", "-fsanitize=fuzzer,address", "{source}", str(harness), "-o", "{binary}"]
            for content, expected in ((b"ZA", "HELD_FOR_EXECUTION"), (b"AA", "NOT_REACHED")):
                seed = root / (expected + ".bin")
                seed.write_bytes(content)
                assertion = Assertion("a-held", "w", "d", "target", "target.c:3",
                                      "n is positive", "n > 0", [])
                result, evidence = execute_assertion(assertion, source, 3, seed,
                    root / expected, build, ["{binary}", "{input}"])
                self.assertEqual(result.status, expected)
                self.assertIsNotNone(evidence)
                triage = json.loads((root / expected / "triage.json").read_text())
                self.assertEqual(triage["classification"], "NOT_A_VIOLATION")

    def test_source_review_can_distinguish_overstrong_assumption(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "target.c"
            source.write_text("if (n < 2) return 0; /* safe short input */\n")
            assertion = Assertion("a-strong", "w", "d", "target", "target.c:1",
                                  "n is always at least two", "n >= 2", [])
            violated = RuntimeResult(-6, "", "VA_ASSERTION_HIT:a-strong\n"
                                     "VA_ASSERTION_VIOLATION:a-strong\n", 6, False,
                                     None, None, "UNKNOWN")
            original = RuntimeResult(0, "", "", None, False, None, None, "UNKNOWN")
            unknown = triage_assertion_violation(assertion, violated, original,
                                                   original_source=source)
            self.assertEqual(unknown["classification"], "INSUFFICIENT_EVIDENCE")
            reviewed = triage_assertion_violation(assertion, violated, original,
                source_review={"review_status": "CONFIRMED_BENIGN",
                               "source_quote": "if (n < 2) return 0;",
                               "reason": "short input has an explicit safe return"},
                original_source=source)
            self.assertEqual(reviewed["classification"], "OVERSTRONG_ASSUMPTION")

    def test_sanitizer_crash_without_violation_tag_is_not_assertion_violation(self):
        assertion = Assertion("a-sanitizer", "w", "d", "target", "target.c:1",
                              "pointer is valid", "p != 0", [])
        result = RuntimeResult(1, "", "ERROR: AddressSanitizer: heap-use-after-free",
                               None, False, "ASAN", None, "UNKNOWN")
        self.assertNotEqual(triage_violation(assertion.assertion_id, result), "VIOLATED")
        self.assertEqual(triage_assertion_violation(assertion, result, None)["classification"],
                         "NOT_A_VIOLATION")

    def test_original_sanitizer_failure_is_only_a_security_candidate(self):
        assertion = Assertion("a-bug", "w", "d", "target", "target.c:1",
                              "pointer remains live", "p != 0", [])
        instrumented = RuntimeResult(-6, "", "VA_ASSERTION_HIT:a-bug\n"
                                     "VA_ASSERTION_VIOLATION:a-bug\n", 6, False,
                                     None, None, "UNKNOWN")
        original = RuntimeResult(1, "", "ERROR: AddressSanitizer: heap-use-after-free",
                                 None, False, "AddressSanitizer: heap-use-after-free",
                                 None, "SANITIZER_CRASH")
        result = triage_assertion_violation(assertion, instrumented, original)
        self.assertEqual(result["classification"], "SECURITY_DEFECT_POSSIBLE")
        self.assertIn("root cause", result["unknowns"][0])

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_llm_expression_with_out_of_scope_symbol_is_invalid_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "fuzz.c"
            harness.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                               "extern int parse_frame(const uint8_t*, size_t);\n"
                               "int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){parse_frame(d,n);return 0;}\n")
            seed = root / "seed.bin"
            seed.write_bytes(b"AB")
            assertion = Assertion("a-invalid", "w", "d", "parse_frame", "target.c:9",
                "size is safe", "missing_symbol > 0", [], generation_method="LLM")
            original = TARGET.read_bytes()
            result, evidence = execute_assertion(assertion, TARGET, 9, seed, root / "assertion",
                ["clang", "-fsanitize=fuzzer,address", "-g", "{source}", str(harness), "-o", "{binary}"],
                ["{binary}", "{input}"])
            self.assertEqual(result.status, "INVALID_ASSERTION")
            self.assertIn("missing_symbol", result.execution_result)
            self.assertIsNone(evidence)
            self.assertFalse((root / "assertion/runtime.json").exists())
            self.assertEqual(TARGET.read_bytes(), original)

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_multiple_inputs_preserve_separate_assertion_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            (run / "assertions").mkdir(parents=True)
            (run / "run.json").write_text('{"run_id":"test-run"}')
            proposal = {"assertion_id": "a-size", "worker_id": "w", "direction_id": "d",
                        "function": "parse_frame", "source_location": "target.c:9",
                        "safe_assumption": "size >= 2 at entry", "runtime_expression": "size >= 2",
                        "required_context": [], "source_function_analysis": "analysis/parse_frame.json",
                        "safe_judgment": "size >= 2 at entry", "safe_reason": "caller is assumed to validate size"}
            (run / "analysis").mkdir()
            analysis_path = run / "analysis/parse_frame.json"
            analysis_path.write_text(json.dumps({"function_name": "parse_frame",
                "safe_assumptions": ["size >= 2 at entry"], "input_flow": "fuzzer bytes",
                "input_sources": ["harness"], "security_sensitive_operations": []}))
            proposal["source_function_analysis"] = str(analysis_path)
            (run / "assertions/proposed.json").write_text(json.dumps([proposal]))
            harness = root / "fuzz.c"
            harness.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                               "extern int parse_frame(const uint8_t*, size_t);\n"
                               "int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){parse_frame(d,n);return 0;}\n")
            short, long = root / "short.bin", root / "long.bin"
            short.write_bytes(b"A")
            long.write_bytes(b"AB")
            build = ["clang", "-fsanitize=fuzzer,address", "-g", "{source}", str(harness), "-o", "{binary}"]
            for seed in (short, long):
                run_assertions_for_scan(run, TARGET, seed, build, ["{binary}", "{input}"])
            history = json.loads((run / "assertions/history.json").read_text())
            self.assertEqual([item["status"] for item in history], ["VIOLATED", "HELD_FOR_EXECUTION"])
            self.assertEqual(len({item["execution_result"] for item in history}), 2)
            self.assertEqual(len(json.loads((run / "evidence.json").read_text())), 2)

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_function_analysis_assumption_flows_to_instrumented_execution(self):
        class Provider:
            def __init__(self):
                self.responses = [
                    {"summary": "guarded frame", "input_flow": "size from harness", "state_dependencies": [],
                     "context_requests": [], "safe_assumptions": ["size >= 2 at entry"], "unknowns": [],
                     "input_sources": [], "security_sensitive_operations": [], "validations": [],
                     "memory_operations": [], "evidence": [], "hypothesis_evaluations": [{
                         "source_location": "target.c:9", "security_property": "bounded read",
                         "hypothesis": "entry size is too small", "judgment": "EXPLICIT_SAFE_JUDGMENT",
                         "reason": "caller supplies at least two bytes", "safe_assumption": "size >= 2 at entry",
                         "source_file": str(TARGET), "source_line": 9,
                         "source_quote": "if (size < 2) {", "input_influence": "INPUT_DEPENDENT"}]},
                    {"assertions": [{"safe_id": 0, "safe_assumption": "size >= 2 at entry",
                      "runtime_expression": "size >= 2", "source_line": 9,
                      "required_context": [], "rationale": "entry size"}],
                     "dispositions": [{"safe_id": 0, "safe_assumption": "size >= 2 at entry",
                                       "status": "PROPOSED", "reason": "input size predicate"}]},
                ]

            async def generate(self, request):
                return self.responses.pop(0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pipeline = AgentPipeline(Provider())
            source = TARGET.read_text()
            analysis = asyncio.run(pipeline.analyze_function("fn", "parse_frame", str(TARGET), source))
            assertions = asyncio.run(pipeline.generate_assertions(analysis, "w", "d", source))
            self.assertEqual(len(assertions), 1)
            harness = root / "fuzz.c"
            harness.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                               "extern int parse_frame(const uint8_t*, size_t);\n"
                               "int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){parse_frame(d,n);return 0;}\n")
            seed = root / "short.bin"
            seed.write_bytes(b"A")
            assertion, evidence = execute_assertion(
                assertions[0], TARGET, 9, seed, root / "assertion",
                ["clang", "-fsanitize=fuzzer,address", "-g", "{source}", str(harness), "-o", "{binary}"],
                ["{binary}", "{input}"])
            self.assertEqual(assertion.status, "VIOLATED")
            self.assertEqual(assertion.next_action, "REANALYZE")
            self.assertEqual(assertion.safe_judgment, "size >= 2 at entry")
            self.assertTrue(evidence.contradicts)
            self.assertEqual(TARGET.read_text(), source)
            triage = json.loads((root / "assertion/triage.json").read_text())
            self.assertEqual(triage["assertion_status"], "VIOLATED")
            self.assertEqual(triage["classification"], "INSUFFICIENT_EVIDENCE")
            self.assertIsNotNone(triage["original_runtime"])
            self.assertEqual(len(triage["input_sha256"]), 64)
            guided = guided_fuzz_assertion(
                assertions[0], TARGET, 9, seed, root / "guided",
                ["clang", "-fsanitize=fuzzer,address", "-g", "{source}", str(harness),
                 "-o", "{binary}"], ["{binary}", "{input}"], seconds=2)
            self.assertEqual(guided["status"], "ASSERTION_WITNESS_OBSERVED")
            self.assertGreater(guided["fuzzer_run_count"], 0)
            self.assertGreater(guided["fuzz_seconds_actual"], 0)
            self.assertTrue(guided["violation_witnesses"])
            self.assertEqual(guided["violation_triage"]["assertion_status"], "VIOLATED")

    def test_rejects_side_effect_expression(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                instrument_copy(TARGET, 9, "size++ < 2", Path(tmp) / "target.c", "a-1")

    @unittest.skipUnless(shutil.which("clang"), "clang required")
    def test_tagged_assertion_violation_reproduces_and_requests_reanalysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instrumented = instrument_copy(TARGET, 9, "size >= 2", root / "target.c", "a-size")
            harness = root / "fuzz.c"
            harness.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                               "extern int parse_frame(const uint8_t*, size_t);\n"
                               "int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){parse_frame(d,n);return 0;}\n")
            binary = root / "fuzz"
            build = subprocess.run(["clang", "-fsanitize=fuzzer,address", "-g", str(instrumented),
                                    str(harness), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            seed = root / "short.bin"
            seed.write_bytes(b"A")
            result = RuntimeExecutor(timeout_seconds=5).run([str(binary), "{input}"], seed)
            self.assertEqual(parse_violation(result.stderr), "a-size")
            self.assertEqual(triage_violation("a-size", result), "VIOLATED")


if __name__ == "__main__":
    unittest.main()
