"""Public C toy checks for development-only cumulative HP instrumentation."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vulnerabilityanalysis.assertions import guided_fuzz_assertion, instrument_copy
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.hp_project_state import (finalize_hp_project_state,
    load_hp_project_state, prior_phi_assertions_for_source)
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1
import test_phase1


SOURCE = ("#include <stdlib.h>\n"
          "int parse(int x) {\n"
          "  int a = x;\n"
          "  return a;\n"
          "}\n"
          "int entry(int x) {\n"
          "  int b = x;\n"
          "  return parse(b);\n"
          "}\n"
          "int main(int argc, char **argv) {\n"
          "  if (argc < 2) return 3;\n"
          "  (void)entry(atoi(argv[1]));\n"
          "  return 0;\n"
          "}\n")


class CumulativePhiToyTest(unittest.TestCase):
    def test_two_functions_keep_both_tags_and_distinguish_prior_violation(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, copy, binary = root / "toy.c", root / "instrumented.c", root / "toy"
            source.write_text(SOURCE)
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            instrument_copy(source, 8, "b < 2", copy, "new-phi", guided=True,
                            prior_assertions=[("old-phi", 4, "a < 1")])
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_sha)
            code = copy.read_text()
            self.assertIn("VA_ASSERTION_VIOLATION:old-phi", code)
            self.assertIn("VA_ASSERTION_VIOLATION:new-phi", code)
            build = subprocess.run([compiler, "-O0", str(copy), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(build.returncode, 0, build.stderr)
            good = subprocess.run([str(binary), "0"], capture_output=True, text=True, timeout=5)
            prior = subprocess.run([str(binary), "1"], capture_output=True, text=True, timeout=5)
            current = subprocess.run([str(binary), "2"], capture_output=True, text=True, timeout=5)
            self.assertEqual(good.returncode, 0)
            self.assertNotEqual(prior.returncode, 0)
            self.assertIn("VA_ASSERTION_VIOLATION:old-phi", prior.stderr)
            self.assertNotIn("VA_ASSERTION_VIOLATION:new-phi", prior.stderr)
            self.assertNotEqual(current.returncode, 0)
            self.assertIn("VA_ASSERTION_VIOLATION:new-phi", current.stderr)

    def test_colliding_assertion_sites_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "toy.c"
            source.write_text(SOURCE)
            with self.assertRaisesRegex(ValueError, "collid|same source line"):
                instrument_copy(source, 8, "b < 2", root / "instrumented.c", "new-phi",
                                guided=True, prior_assertions=[("old-phi", 8, "b < 1")])

    def test_real_guided_prior_witness_does_not_mark_new_phi_ran(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if compiler is None:
            self.skipTest("clang unavailable")
        source_text = ("#include <stdint.h>\n#include <stddef.h>\n"
                       "void parse(unsigned char x) {\n"
                       "  unsigned a = x;\n"
                       "  if (a > 0) return;\n"
                       "}\n"
                       "void entry(unsigned char x) {\n"
                       "  unsigned b = x;\n"
                       "  parse(b);\n"
                       "}\n"
                       "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
                       "  if (size) entry(data[0]);\n"
                       "  return 0;\n"
                       "}\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, seed = root / "toy.c", root / "seed"
            source.write_text(source_text)
            seed.write_bytes(b"\x01")
            prior = Assertion("old-phi", "worker", "direction", "parse", "toy.c:5",
                              "a <= 0", "a <= 0", [])
            current = Assertion("new-phi", "worker", "direction", "entry", "toy.c:9",
                                "b <= 2", "b <= 2", [])
            report = guided_fuzz_assertion(current, source, 9, seed, root / "guided",
                [compiler, "-fsanitize=fuzzer,address", "-O0", "-g", "{source}",
                 "-o", "{binary}"], ["{binary}", "{input}"], seconds=1,
                prior_phi_assertions=[prior])
            self.assertEqual(report["status"], "PRIOR_PHI_WITNESS_OBSERVED", report)
            self.assertEqual(report["prior_phi_witnesses"][0]["assertion_id"], "old-phi")
            self.assertEqual(report["prior_phi_triage"][0]["classification"],
                             "OVERSTRONG_ASSUMPTION")
            self.assertGreaterEqual(report["prior_phi_replay"]["old-phi"]["violated"], 1)
            self.assertEqual(report["new_phi_opportunity"],
                             "BLOCKED_BY_PRIOR_PHI_WITNESS")
            self.assertNotEqual(report.get("status"), "RAN")

    def test_actual_two_function_state_and_guided_binary_contain_both_phi(self):
        compiler = os.environ.get("VA_TEST_CLANG") or shutil.which("clang")
        if compiler is None:
            self.skipTest("clang unavailable")
        source_text = ("#include <stdint.h>\n#include <stddef.h>\n"
                       "void parse_input(const uint8_t *data, size_t size) {\n"
                       "  if (!size) return;\n"
                       "  size_t value = data[0];\n"
                       "  (void)value;\n"
                       "}\n"
                       "void entry_input(const uint8_t *data, size_t size) {\n"
                       "  if (!size) return;\n"
                       "  size_t value = data[0];\n"
                       "  parse_input(data, size);\n"
                       "  (void)value;\n"
                       "}\n")
        harness_text = ("#include <stdint.h>\n#include <stddef.h>\n"
                        "void entry_input(const uint8_t *, size_t);\n"
                        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
                        "  entry_input(data, size); return 0;\n"
                        "}\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, repo = test_phase1.HarnessCreatorArtifactTest()._id_artifact(root)
            source = repo / "target.c"
            source.write_text(source_text)
            harness = artifact / "fuzz.c"
            harness.write_text(harness_text)
            functions = root / "analysis" / "functions.jsonl"
            rows = [json.loads(line) for line in functions.read_text().splitlines()]
            for row in rows:
                row["start_line"] = 8 if row["name"] == "entry_input" else 3
            functions.write_text("".join(json.dumps(row) + "\n" for row in rows))
            build = [compiler, "-fsanitize=fuzzer,address", "-O0", "-g",
                     "{source}", str(harness), "-o", "{binary}"]
            first = run_phase1(artifact, root / "runs", target_repository=repo,
                               hp_project_state_dev=True)
            selection = json.loads((first / "selection.json").read_text())
            self.assertEqual(selection["function_name"], "parse_input")
            seed = first / "seed"
            seed.write_bytes(b"\x01")
            prior = Assertion("old-phi", "worker", selection["direction_id"],
                              "parse_input", "target.c:6", "value <= 255",
                              "value <= 255", [])
            execution = first / "assertions" / "old-phi" / "executions" / "one"
            guided = guided_fuzz_assertion(prior, source, 6, seed,
                execution / "guided_fuzz", build, ["{binary}", "{input}"], seconds=1)
            self.assertEqual(guided["status"], "RAN", guided)
            analysis = first / "analysis" / "selected.json"
            analysis.parent.mkdir(exist_ok=True)
            analysis.write_text(json.dumps({"function_id": selection["function_id"],
                "function_name": "parse_input", "safe_assumptions": [prior.safe_assumption],
                "hypothesis_evaluations": [{"judgment": "EXPLICIT_SAFE_JUDGMENT",
                                           "safe_assumption": prior.safe_assumption}]}))
            assertions = first / "assertions"
            (assertions / "dispositions.json").write_text(json.dumps([{
                "safe_id": 0, "safe_assumption": prior.safe_assumption,
                "status": "PROPOSED"}]))
            runtime_path = execution / "runtime.json"
            runtime_path.write_text("{}")
            prior.status = "HELD_FOR_EXECUTION"
            prior.execution_result = str(runtime_path)
            prior.source_function_analysis = str(analysis)
            (assertions / "results.json").write_text(json.dumps([prior.__dict__]))
            (first / "scan.json").write_text(json.dumps({
                "selected_function": "parse_input", "target_repository": str(repo)}))
            first_state = finalize_hp_project_state(first, repo)
            self.assertEqual(len(first_state["Phi"]), 1)
            self.assertTrue(first_state["C"])
            second = continue_phase1(first)
            second_state = load_hp_project_state(second, repo)
            checks = prior_phi_assertions_for_source(second, repo, source)
            selected = json.loads((second / "selection.json").read_text())
            self.assertEqual(selected["function_name"], "entry_input")
            current = Assertion("new-phi", "worker", selected["direction_id"],
                                "entry_input", "target.c:12", "value <= 255",
                                "value <= 255", [])
            seed2 = second / "seed"
            seed2.write_bytes(b"\x01")
            result = guided_fuzz_assertion(current, source, 12, seed2,
                second / "guided_second", build, ["{binary}", "{input}"], seconds=1,
                prior_corpus=second / "hp_guided_corpus",
                prior_corpus_allowlist=second_state["C"], prior_phi_assertions=checks)
            self.assertEqual(result["status"], "RAN", result)
            self.assertGreaterEqual(result["replayed_reached"], 1)
            copy = Path(result["instrumented_source"]).read_text()
            self.assertIn("VA_ASSERTION_VIOLATION:old-phi", copy)
            self.assertIn("VA_ASSERTION_VIOLATION:new-phi", copy)
            self.assertEqual(len(result["carried_corpus"]), len(second_state["C"]))
            self.assertGreaterEqual(result["prior_phi_replay"]["old-phi"]["reached"], 1)
            self.assertEqual(result["prior_phi_replay"]["old-phi"]["violated"], 0)


if __name__ == "__main__":
    unittest.main()
