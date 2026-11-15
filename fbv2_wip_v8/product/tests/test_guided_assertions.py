"""Real libFuzzer checks for assertion feedback, with no LLM or network calls."""
import json
import asyncio
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.assertions import (execute_assertion, guided_fuzz_assertion,
                                              instrument_copy, parse_hit, parse_violation,
                                              assess_safe_assumption,
                                              refinement_rejection_reasons)
from vulnerabilityanalysis.models import (Assertion, FunctionAnalysis, SuspiciousPoint,
                                          VerificationResult)
from vulnerabilityanalysis.runtime import fuzz_locally
from vulnerabilityanalysis.scan import (run_assertions_for_scan,
                                        refine_overstrong_assertions,
                                        apply_assertion_sp_feedback)


@unittest.skipUnless(shutil.which("clang"), "clang/libFuzzer required")
class GuidedAssertionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "target.c"
        self.source.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "void target(const uint8_t *data, size_t size) {\n"
            "  if (!size) return;\n"
            "  size_t value = data[0];\n"
            "  (void)value;\n"
            "}\n", encoding="utf-8")
        self.harness = self.root / "harness.c"
        self.harness.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "void target(const uint8_t *, size_t);\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) "
            "{ target(data,size); return 0; }\n", encoding="utf-8")
        self.seed = self.root / "seed"
        self.seed.write_bytes(b"\x00")
        self.build = ["clang", "-fsanitize=fuzzer,address", "-g", "-O0", "{source}",
                      str(self.harness), "-o", "{binary}"]

    def assertion(self, assertion_id, expression):
        return Assertion(assertion_id, "w", "d", "target", "target.c:6",
                         expression, expression, [])

    def test_extra_counters_retain_distance_mutations(self):
        baseline = self.root / "baseline"
        subprocess.run([part.replace("{source}", str(self.source)).replace("{binary}",
                        str(baseline)) for part in self.build], check=True, capture_output=True)
        baseline_corpus = self.root / "baseline-corpus"
        baseline_corpus.mkdir()
        (baseline_corpus / "initial-seed").write_bytes(self.seed.read_bytes())
        plain = fuzz_locally(baseline, baseline_corpus, seconds=1)
        guided = guided_fuzz_assertion(self.assertion("a-distance", "value <= 255"),
            self.source, 6, self.seed, self.root / "guided", self.build,
            ["{binary}", "{input}"], seconds=1)
        self.assertEqual(guided["status"], "RAN")
        self.assertEqual(guided["distance_feedback"], "SUPPORTED")
        self.assertTrue(guided["extra_counters_loaded"])
        self.assertGreater(guided["retained_mutations"], 0)
        self.assertFalse(guided["violation_witnesses"])
        self.assertEqual(plain.coverage["final_edges"], plain.coverage["initial_edges"])
        self.assertTrue((self.root / "guided/guided_fuzz.json").is_file())
        self.assertEqual(guided["fuzzer_run_count"], len(guided["fuzz_segments"]))
        self.assertEqual(guided["executions"], sum(row["executions"] for row in
                         guided["fuzz_segments"]))
        self.assertGreaterEqual(guided["build_seconds"], 0)
        self.assertGreater(guided["fuzz_seconds_actual"], 0)
        self.assertEqual(self.source.read_text().count("VA_ASSERT"), 0)

    def test_no_violation_uses_one_uninterrupted_fuzz_run(self):
        report = guided_fuzz_assertion(self.assertion("a-no-violation", "value <= 255"),
            self.source, 6, self.seed, self.root / "no-violation", self.build,
            ["{binary}", "{input}"], seconds=2)
        self.assertEqual(report["status"], "RAN")
        self.assertFalse(report["violation_witnesses"])
        self.assertEqual(report["fuzzer_run_count"], 1)
        self.assertEqual([row["segment"] for row in report["fuzz_segments"]], ["initial"])
        self.assertNotIn("continuation", report)

    def test_extra_counter_feature_is_not_ordinary_edge_coverage(self):
        probe = self.root / "extra-probe.c"
        probe.write_text(
            "#include <stddef.h>\n#include <stdint.h>\n"
            "#ifdef WITH_EXTRA\n"
            "__attribute__((used,section(\"__libfuzzer_extra_counters\"))) "
            "static volatile uint8_t extra[16];\n#endif\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n"
            "  if (n) {\n#ifdef WITH_EXTRA\n    extra[d[0] & 3] = 1;\n#endif\n  }\n"
            "  return 0;\n}\n", encoding="utf-8")
        outcomes = []
        for label, flags in (("plain", []), ("extra", ["-DWITH_EXTRA"])):
            binary = self.root / label
            subprocess.run(["clang", "-fsanitize=fuzzer,address", "-O1", *flags,
                            str(probe), "-o", str(binary)], check=True, capture_output=True)
            corpus = self.root / f"{label}-corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"A")
            result = subprocess.run([str(binary), str(corpus), "-runs=128", "-seed=1"],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            outcomes.append((result.stderr, len(list(corpus.iterdir()))))
        self.assertIn("16 Extra Counters", outcomes[1][0])
        self.assertGreater(outcomes[1][1], outcomes[0][1])
        self.assertIn("cov: 2", outcomes[1][0])
        self.assertIn("MS:", outcomes[1][0])

    def test_reach_hold_violate_and_existing_triage(self):
        assertion = self.assertion("a-violate", "value <= 200")
        report = guided_fuzz_assertion(assertion, self.source, 6, self.seed,
            self.root / "violate", self.build, ["{binary}", "{input}"], seconds=2)
        self.assertEqual(report["status"], "ASSERTION_WITNESS_OBSERVED")
        self.assertTrue(report["violation_witnesses"])
        self.assertEqual(report["violation_triage"]["assertion_status"], "VIOLATED")
        triage = json.loads(Path(report["violation_triage"]["triage_artifact"]).read_text())
        self.assertNotEqual(triage["security_verdict"], "VERIFIED")
        self.assertEqual(triage["original_source_sha256"], report["source_sha256"])
        binary = report["binary"]
        empty = self.root / "empty"
        empty.write_bytes(b"")
        held = self.root / "held"
        held.write_bytes(b"\x01")
        bad = self.root / "bad"
        bad.write_bytes(b"\xff")
        for path, hit, violation in ((empty, False, False), (held, True, False),
                                     (bad, True, True)):
            completed = subprocess.run([binary, str(path)], capture_output=True,
                                       text=True, env={"VA_ASSERT_TRACE": "1"}, timeout=10)
            self.assertEqual(parse_hit(completed.stderr) == "a-violate", hit)
            self.assertEqual(parse_violation(completed.stderr) == "a-violate", violation)

    def test_multiple_assertions_have_separate_ids_and_corpora(self):
        results = []
        for number, expression in enumerate(("value <= 255", "value >= 0")):
            report = guided_fuzz_assertion(self.assertion(f"a-{number}", expression),
                self.source, 6, self.seed, self.root / f"assertion-{number}",
                self.build, ["{binary}", "{input}"], seconds=1)
            results.append(report)
        self.assertTrue(all(row["extra_counters_loaded"] for row in results))
        self.assertNotEqual(results[0]["instrumented_source"],
                            results[1]["instrumented_source"])
        self.assertEqual({row["assertion_id"] for row in results}, {"a-0", "a-1"})

    def test_refined_guided_run_carries_verified_prior_corpus(self):
        prior = self.root / "prior-corpus"
        prior.mkdir()
        (prior / "initial-seed").write_bytes(b"\x01")
        (prior / "not-a-corpus-entry.log").write_bytes(b"ignore")
        report = guided_fuzz_assertion(self.assertion("a-carried", "value <= 255"),
            self.source, 6, self.seed, self.root / "carried", self.build,
            ["{binary}", "{input}"], seconds=1, prior_corpus=prior)
        self.assertEqual(report["status"], "RAN")
        self.assertEqual(len(report["carried_corpus"]), 1)
        self.assertTrue(Path(report["carried_corpus"][0]["destination"]).is_file())

    def test_signed_distance_rejected_without_losing_reach_feedback(self):
        self.source.write_text(self.source.read_text().replace(
            "size_t value = data[0];",
            "typedef int VA_SIGNED; VA_SIGNED value = (int)data[0];"))
        report = guided_fuzz_assertion(self.assertion("a-signed", "value <= 255"),
            self.source, 6, self.seed, self.root / "signed", self.build,
            ["{binary}", "{input}"], seconds=1)
        self.assertEqual(report["status"], "RAN")
        self.assertEqual(report["distance_feedback"], "UNSUPPORTED")
        self.assertIn("unsigned numeric subset", report["distance_reason"])
        self.assertTrue(report["extra_counters_loaded"])

    def test_unsigned_typedef_uses_compiler_verified_distance(self):
        self.source.write_text(self.source.read_text().replace(
            "size_t value = data[0];",
            "typedef unsigned VA_SIZE; VA_SIZE value = data[0];"))
        report = guided_fuzz_assertion(self.assertion("a-alias", "value <= 255"),
            self.source, 6, self.seed, self.root / "alias", self.build,
            ["{binary}", "{input}"], seconds=1)
        self.assertEqual(report["status"], "RAN")
        self.assertEqual(report["distance_feedback"], "SUPPORTED")
        self.assertTrue(report["extra_counters_loaded"])

    def test_process_harness_is_reported_unsupported(self):
        report = guided_fuzz_assertion(self.assertion("a-process", "value <= 255"),
            self.source, 6, self.seed, self.root / "process", self.build,
            ["{binary}", "--file", "{input}"], seconds=1)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("process harness unsupported", report["reason"])

    def test_scan_records_fuzz_witness_separately_from_initial_seed(self):
        run = self.root / "run"
        (run / "assertions").mkdir(parents=True)
        (run / "run.json").write_text('{"run_id":"guided-test"}')
        analysis = run / "analysis.json"
        analysis.write_text(json.dumps({"function_name": "target",
                                        "safe_assumptions": ["value <= 200"]}))
        assertion = self.assertion("a-scan-guided", "value <= 200")
        assertion.source_function_analysis = str(analysis)
        (run / "assertions/proposed.json").write_text(json.dumps([assertion.__dict__]))
        outcomes = run_assertions_for_scan(run, self.source, self.seed, self.build,
                                           ["{binary}", "{input}"], fuzz_seconds=2)
        self.assertEqual([item.status for item in outcomes],
                         ["HELD_FOR_EXECUTION", "VIOLATED"])
        self.assertEqual(outcomes[1].next_action, "REANALYZE")
        self.assertEqual(len(json.loads((run / "evidence.json").read_text())), 2)
        self.assertEqual(len(json.loads((run / "assertions/history.json").read_text())), 2)

    def test_real_sanitizer_crash_is_not_assertion_violation(self):
        self.source.write_text(self.source.read_text().replace(
            "(void)value;", "if (value >= 200) { volatile int *p = 0; *p = 1; }"))
        self.seed.write_bytes(b"\xff")
        report = guided_fuzz_assertion(self.assertion("a-crash", "value <= 255"),
            self.source, 6, self.seed, self.root / "sanitizer", self.build,
            ["{binary}", "{input}"], seconds=1)
        self.assertEqual(report["status"], "CRASH_OBSERVED_INCOMPLETE")
        self.assertFalse(report["violation_witnesses"])
        self.assertTrue(report["other_crash_artifacts"])
        self.assertNotIn("violation_triage", report)

    def test_first_violation_is_triaged_then_fuzzing_continues(self):
        self.source.write_text(self.source.read_text().replace(
            "(void)value;", 'if (value > 200) { extern int puts(const char*); puts("AFTER_VIOLATION"); }'))
        self.seed.write_bytes(b"\xff")
        report = guided_fuzz_assertion(self.assertion("a-continue", "value <= 200"),
            self.source, 6, self.seed, self.root / "continue", self.build,
            ["{binary}", "{input}"], seconds=2)
        self.assertEqual(report["violation_triage"]["assertion_status"], "VIOLATED")
        self.assertIn("continuation", report, report)
        self.assertEqual(report["continuation"]["status"], "RAN")
        self.assertEqual([row["segment"] for row in report["fuzz_segments"]],
                         ["initial", "continuation"])
        self.assertEqual(report["fuzzer_run_count"], 2)
        self.assertEqual(report["executions"], sum(row["executions"] for row in
                         report["fuzz_segments"]))
        self.assertGreaterEqual(report["corpus_reused_count"], 1)
        self.assertIn("initial segment only", report["coverage_feedback_scope"])
        self.assertGreaterEqual(report["continuation"]["final_corpus_count"], 1)
        replay = subprocess.run([report["continuation"]["binary"], str(self.seed)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(replay.returncode, 0)
        self.assertIn("AFTER_VIOLATION", replay.stdout)

    def test_three_violation_triage_outcomes_use_original_program(self):
        self.seed.write_bytes(b"\xff")
        cases = [
            ("unknown", "(void)value;", "INSUFFICIENT_EVIDENCE"),
            ("overstrong", "if (value > 200) return;", "OVERSTRONG_ASSUMPTION"),
            ("defect", "if (value > 200) { volatile int *p = 0; *p = 1; }",
             "SECURITY_DEFECT_POSSIBLE"),
        ]
        for label, statement, expected in cases:
            with self.subTest(label=label):
                source = self.root / label / "target.c"
                source.parent.mkdir()
                source.write_text(self.source.read_text().replace("(void)value;", statement))
                outcome, _ = execute_assertion(self.assertion(f"a-{label}", "value <= 200"),
                    source, 6, self.seed, self.root / label / "execution", self.build,
                    ["{binary}", "{input}"])
                self.assertEqual(outcome.status, "VIOLATED")
                triage = json.loads((self.root / label / "execution/triage.json").read_text())
                self.assertEqual(triage["classification"], expected)
                self.assertEqual(triage["security_verdict"], "UNKNOWN")

    def test_only_exact_negated_sp_condition_receives_assertion_evidence(self):
        run = self.root / "link-run"
        (run / "assertions").mkdir(parents=True)
        (run / "sp").mkdir()
        (run / "run.json").write_text('{"run_id":"link-test"}')
        analysis = run / "analysis.json"
        analysis.write_text(json.dumps({"function_name": "target",
                                        "safe_assumptions": ["value <= 200"]}))
        assertion = self.assertion("a-link", "value <= 200")
        assertion.source_function_analysis = str(analysis)
        (run / "assertions/proposed.json").write_text(json.dumps([assertion.__dict__]))
        def point(identifier, location, condition):
            return SuspiciousPoint(identifier, "w", "d", "target", "target.c", location,
                                   "operation", "hypothesis", [condition], "input", [],
                                   [], [], [], sp_condition=condition).__dict__
        (run / "sp/candidates.json").write_text(json.dumps([
            point("sp-related", "target.c:6", "value > 200"),
            point("sp-same-function", "target.c:7", "value > 200")]))
        self.seed.write_bytes(b"\xff")
        run_assertions_for_scan(run, self.source, self.seed, self.build,
                                ["{binary}", "{input}"])
        linkage = json.loads((run / "assertions/sp_linkage.json").read_text())
        self.assertEqual(linkage[0]["related_sp_ids"], ["sp-related"])
        related = [row["related_candidate"] for row in
                   json.loads((run / "evidence.json").read_text())]
        self.assertIn("sp-related", related)
        self.assertNotIn("sp-same-function", related)
        before = json.loads((run / "sp/candidates.json").read_text())
        class ExistingVerifier:
            def __init__(self):
                self.calls = 0
                self.last_request_count = 1
                self.verifications = {}
            async def verify_sp(self, candidate, source, context, **kwargs):
                self.calls += 1
                self.assertion_context = [row for row in context
                                          if row.get("request_type") == "ASSERTION_VIOLATION"]
                self.verifications[candidate.sp_id] = VerificationResult(
                    candidate.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
                    "UNKNOWN", "RUNTIME_TRACE", "new assertion evidence; security still unknown")
                return candidate
        verifier = ExistingVerifier()
        kwargs = dict(function_name="target", source=self.source.read_text(),
                      source_path=self.source, source_start_line=3, context=[],
                      harness_source=self.harness.read_text(), harness_source_path=self.harness,
                      target_repository=self.root, max_llm_calls=1)
        feedback = asyncio.run(apply_assertion_sp_feedback(run, verifier, **kwargs))
        self.assertEqual(feedback["feedback"][0]["status"],
                         "REVERIFIED_WITH_NEW_EVIDENCE")
        self.assertEqual(verifier.calls, 1)
        self.assertEqual(len(verifier.assertion_context), 1)
        self.assertEqual(json.loads((run / "sp/candidates.json").read_text()), before)
        again = asyncio.run(apply_assertion_sp_feedback(run, verifier, **kwargs))
        self.assertEqual(again["status"], "NO_NEW_EVIDENCE")
        self.assertEqual(verifier.calls, 1)

    @unittest.skipUnless(shutil.which("gdb"), "GDB required for expression measurement")
    def test_refinement_reuses_function_analyzer_and_preserves_original(self):
        self.source.write_text(self.source.read_text().replace(
            "(void)value;", "if (value > 200) return;"))
        self.seed.write_bytes(b"\xff")
        run = self.root / "refine-run"
        (run / "assertions").mkdir(parents=True)
        (run / "run.json").write_text('{"run_id":"refine-test"}')
        analysis_path = run / "analysis.json"
        analysis_path.write_text(json.dumps({"function_name": "target",
                                             "safe_assumptions": ["value <= 200"]}))
        original = self.assertion("a-old", "value <= 200")
        original.source_function_analysis = str(analysis_path)
        (run / "assertions/proposed.json").write_text(json.dumps([original.__dict__]))
        run_assertions_for_scan(run, self.source, self.seed, self.build,
                                ["{binary}", "{input}"], fuzz_seconds=1)
        old = json.loads((run / "assertions/a-old.json").read_text())
        class ExistingRoles:
            def __init__(self):
                self.calls = []
            async def analyze_function(self, *args, **kwargs):
                self.calls.append("function_analysis")
                self.analysis_scope = kwargs.get("analysis_scope")
                self.harness_context = (kwargs.get("harness_source"),
                                        kwargs.get("harness_source_path"))
                feedback = json.loads(args[-1][-1]["source"])
                self.assertion_feedback = feedback
                return FunctionAnalysis("target", "target", "target.c", "guard reviewed",
                                        "fuzzer bytes", [], [], ["value <= 255"], [])
            async def generate_assertions(self, *args, **kwargs):
                self.calls.append("assertion_generator")
                return [Assertion("a-refined", "w", "d", "target", "target.c:6",
                                  "value <= 255", "value <= 255", [])]
        roles = ExistingRoles()
        scope = {"selected_function": {"role": "CORE", "source_risk": "HIGH"}}
        report = asyncio.run(refine_overstrong_assertions(
            run, roles, function_id="target", function_name="target", source_file="target.c",
            source=self.source.read_text(), original_source=self.source,
            source_start_line=3, context=[], build_command=self.build,
            run_command=["{binary}", "{input}"], fuzz_seconds=1, max_llm_calls=2,
            harness_source=self.harness.read_text(), harness_source_path=self.harness,
            analysis_scope=scope))
        self.assertEqual(roles.calls, ["function_analysis", "assertion_generator"])
        self.assertEqual(roles.analysis_scope, scope)
        self.assertEqual(roles.harness_context,
                         (self.harness.read_text(), self.harness))
        self.assertEqual(roles.assertion_feedback["runtime_expression"], "value <= 200")
        self.assertIs(roles.assertion_feedback["runtime_expression_result"], False)
        self.assertNotIn("state_trace_excerpt", roles.assertion_feedback)
        self.assertIn("predicate's boolean", roles.assertion_feedback["gdb_interpretation_note"])
        self.assertEqual(report["refinements"][0]["status"], "NO_VALID_REFINED_ASSERTION")
        self.assertIn("TYPE_RANGE_TAUTOLOGY", report["refinements"][0][
            "proposal_checks"][0]["rejection_reasons"])
        self.assertEqual(report["refinements"][0]["revisions"], [])
        self.assertEqual(json.loads((run / "assertions/a-old.json").read_text()), old)

    def test_second_benign_violation_refines_again_within_budget(self):
        self.source.write_text(self.source.read_text().replace(
            "(void)value;", "if (value > 200) return;"))
        self.seed.write_bytes(b"\xff")
        run = self.root / "iterative-refine"
        (run / "assertions").mkdir(parents=True)
        (run / "run.json").write_text('{"run_id":"iterative-refine"}')
        analysis_path = run / "analysis.json"
        analysis_path.write_text(json.dumps({"function_name": "target",
                                             "safe_assumptions": ["value <= 200"]}))
        original = self.assertion("a-iter-old", "value <= 200")
        original.source_function_analysis = str(analysis_path)
        (run / "assertions/proposed.json").write_text(json.dumps([original.__dict__]))
        run_assertions_for_scan(run, self.source, self.seed, self.build,
                                ["{binary}", "{input}"])
        class ExistingRoles:
            def __init__(self):
                self.round = 0
            async def analyze_function(self, *args, **kwargs):
                self.round += 1
                value = 210 if self.round == 1 else 255
                return FunctionAnalysis("target", "target", "target.c", "guard reviewed",
                                        "fuzzer bytes", [], [], [f"value <= {value}"], [])
            async def generate_assertions(self, analysis, *args, **kwargs):
                expression = analysis.safe_assumptions[0]
                return [Assertion(f"a-iter-{self.round}", "w", "d", "target",
                                  "target.c:6", expression, expression, [])]
        roles = ExistingRoles()
        report = asyncio.run(refine_overstrong_assertions(
            run, roles, function_id="target", function_name="target", source_file="target.c",
            source=self.source.read_text(), original_source=self.source,
            source_start_line=3, context=[], build_command=self.build,
            run_command=["{binary}", "{input}"], fuzz_seconds=0,
            max_llm_calls=4))
        self.assertEqual(report["llm_calls"], 2)
        self.assertEqual(roles.round, 1)
        self.assertEqual(len(report["refinements"]), 1)
        self.assertEqual(report["refinements"][0]["status"], "NO_VALID_REFINED_ASSERTION")
        self.assertIn("WEAKENED_BOUND_WITHOUT_INDEPENDENT_SECURITY_PROPERTY_EVIDENCE",
                      report["refinements"][0]["proposal_checks"][0]["rejection_reasons"])

    def test_safe_assumption_quality_preserves_redundant_and_tautological_assumptions(self):
        redundant = self.root / "redundant.c"
        redundant.write_text("#include <assert.h>\nvoid f(int *token) {\n"
                             "  assert(token);\n  (void)token;\n}\n")
        pointer = Assertion("a-pointer", "w", "d", "f", "redundant.c:4",
                            "token is non-null", "token != NULL", [])
        quality = assess_safe_assumption(pointer, redundant, {"input_flow": "token"},
                                         self.build)
        self.assertEqual(quality["quality"], "LOW_VALUE")
        self.assertTrue(quality["already_enforced"])
        self.assertEqual(pointer.safe_assumption, "token is non-null")
        byte = self.assertion("a-byte", "value <= 255")
        quality = assess_safe_assumption(byte, self.source, {"input_flow": "data[0]"})
        self.assertEqual(quality["runtime_falsifiability"], "NO")
        self.assertIn("TYPE_RANGE_TAUTOLOGY", quality["reasons"][0])
        wider = self.root / "wider.c"
        wider.write_text(self.source.read_text().replace("const uint8_t *data",
                                                         "const uint16_t *data"))
        self.assertNotEqual(assess_safe_assumption(byte, wider)["runtime_falsifiability"],
                            "NO")

    def test_safe_assumption_quality_detects_negated_early_return_guard(self):
        source = self.root / "guarded.c"
        source.write_text("void f(char *start, char *end, char *p) {\n"
                          "  if (p < start ||\n"
                          "      p >= end) {\n"
                          "    return;\n"
                          "  }\n"
                          "  (void)*p;\n"
                          "}\n")
        duplicate = Assertion("a-guard", "w", "d", "f", "guarded.c:6",
                              "range is safe", "p >= start && p < end", [])
        quality = assess_safe_assumption(duplicate, source)
        self.assertEqual(quality["quality"], "LOW_VALUE")
        self.assertTrue(quality["already_enforced"])
        self.assertIn("DUPLICATES_EARLY_RETURN_GUARD", quality["reasons"][0])
        different = Assertion("a-other", "w", "d", "f", "guarded.c:6",
                              "a different claim", "p > start && p < end", [])
        self.assertNotEqual(assess_safe_assumption(different, source)["quality"], "LOW_VALUE")

    def test_combined_nonnull_claim_redundant_only_on_straight_line(self):
        source = self.root / "nonnull.c"
        source.write_text("#include <assert.h>\nvoid f(char *parser, char *token) {\n"
                          "  assert(parser);\n  assert(token);\n\n  (void)*token;\n}\n")
        claim = Assertion("a-pair", "w", "d", "f", "nonnull.c:6",
                          "both pointers are non-null", "parser != NULL && token != NULL", [])
        quality = assess_safe_assumption(claim, source, build_command=self.build)
        self.assertEqual(quality["quality"], "LOW_VALUE")
        self.assertIn("DUPLICATES_EXISTING_ASSERT", quality["reasons"][0])
        self.assertNotEqual(assess_safe_assumption(
            claim, source, build_command=["clang", "-DNDEBUG", "{source}",
                                         "-o", "{binary}"])["quality"], "LOW_VALUE")
        same_line = Assertion("a-same", "w", "d", "f", "nonnull.c:3",
                              "parser is non-null", "parser != NULL", [])
        self.assertEqual(assess_safe_assumption(same_line, source,
                         build_command=self.build)["quality"], "LOW_VALUE")
        source.write_text(source.read_text().replace(
            "  assert(token);\n", "  assert(token);\n  token = 0;\n"))
        moved = Assertion("a-after-change", "w", "d", "f", "nonnull.c:7",
                          claim.safe_assumption, claim.runtime_expression, [])
        self.assertNotEqual(assess_safe_assumption(moved, source)["quality"], "LOW_VALUE")

    def test_existing_assert_quality_uses_actual_preprocessor_configuration(self):
        source = self.root / "ndebug.c"
        source.write_text("#include <assert.h>\nint f(char *ptr) {\n"
                          "  assert(ptr);\n  return ptr == 0;\n}\n"
                          "int main(void) { return f(0); }\n")
        claim = Assertion("a-ndebug", "w", "d", "f", "ndebug.c:4",
                          "ptr is non-null", "ptr != NULL", [])
        active = ["clang", "{source}", "-o", "{binary}"]
        inactive = ["clang", "-DNDEBUG", "{source}", "-o", "{binary}"]
        for flags, expected_quality, expected_exit in (
                (active, "LOW_VALUE", -6),
                (inactive, "UNDETERMINED", 1)):
            binary = self.root / ("ndebug-binary" if flags is inactive else "active-binary")
            build = [arg.replace("{source}", str(source)).replace("{binary}", str(binary))
                     for arg in flags]
            subprocess.run(build, check=True, capture_output=True)
            # The active build aborts on a null pointer; NDEBUG removes the check.
            import resource
            def disable_core():
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            replay = subprocess.run([str(binary)], capture_output=True, preexec_fn=disable_core)
            self.assertEqual(replay.returncode, expected_exit)
            self.assertEqual(assess_safe_assumption(claim, source,
                             build_command=flags)["quality"], expected_quality)
        self.assertEqual(assess_safe_assumption(claim, source)["quality"], "UNDETERMINED")
        original = Assertion("a-original", "w", "d", "f", "ndebug.c:4",
                             "ptr may be null", "ptr == NULL", [])
        self.assertIn("ALREADY_ENFORCED_BY_SOURCE", refinement_rejection_reasons(
            original, claim, source, build_command=active))
        self.assertNotIn("ALREADY_ENFORCED_BY_SOURCE", refinement_rejection_reasons(
            original, claim, source, build_command=inactive))

        config = self.root / "config.h"
        config.write_text("#define NDEBUG 1\n")
        configured = ["clang", "-include", str(config), "{source}", "-o", "{binary}"]
        self.assertEqual(assess_safe_assumption(claim, source,
                         build_command=configured)["quality"], "UNDETERMINED")

    def test_scan_keeps_low_value_assertion_but_skips_guided_campaign(self):
        self.source.write_text(self.source.read_text().replace(
            "  (void)value;", "  if (value > 200) { return; }\n  (void)value;"))
        run = self.root / "low-value-run"
        (run / "assertions").mkdir(parents=True)
        (run / "run.json").write_text('{"run_id":"low-value-test"}')
        analysis = run / "analysis.json"
        analysis.write_text(json.dumps({"function_name": "target",
                                        "safe_assumptions": ["value <= 200"]}))
        assertion = Assertion("a-low-value", "w", "d", "target", "target.c:7",
                              "value <= 200", "value <= 200", [])
        assertion.source_function_analysis = str(analysis)
        (run / "assertions/proposed.json").write_text(json.dumps([assertion.__dict__]))
        outcomes = run_assertions_for_scan(run, self.source, self.seed, self.build,
                                           ["{binary}", "{input}"], fuzz_seconds=1)
        self.assertEqual([item.status for item in outcomes], ["HELD_FOR_EXECUTION"])
        self.assertFalse(list((run / "assertions").glob("**/guided_fuzz/guided_fuzz.json")))
        skipped = list((run / "assertions").glob("**/guided_fuzz_skipped.json"))
        self.assertEqual(len(skipped), 1)
        self.assertEqual(json.loads(skipped[0].read_text())["status"], "SKIPPED_LOW_VALUE")

    def test_refinement_rejects_predicate_contradicting_visible_guard(self):
        guarded = self.root / "guarded.c"
        guarded.write_text("#include <stdint.h>\nvoid f(unsigned value) {\n"
                           "  if (value > 200) return;\n  (void)value;\n}\n")
        old = Assertion("old", "w", "d", "f", "guarded.c:4",
                        "value <= 200", "value <= 200", [])
        proposed = Assertion("new", "w", "d", "f", "guarded.c:4",
                             "value > 200", "value > 200", [])
        self.assertIn("CONTRADICTS_SOURCE_GUARD",
                      refinement_rejection_reasons(old, proposed, guarded))

    def test_noncrashing_violation_reanalyzes_without_verifying_assertion_as_bug(self):
        run = self.root / "feedback-no-crash"
        for name in ("assertions", "analysis", "sp", "verification"):
            (run / name).mkdir(parents=True)
        (run / "run.json").write_text('{"run_id":"feedback-no-crash"}')
        initial = FunctionAnalysis("target", "target", "target.c", "unknown",
                                   "data[0]", [], [], ["value <= 200"], [])
        analysis_path = run / "analysis/target.json"
        analysis_path.write_text(json.dumps(initial.__dict__))
        assertion = self.assertion("a-feedback", "value <= 200")
        assertion.source_function_analysis = str(analysis_path)
        (run / "assertions/proposed.json").write_text(json.dumps([assertion.__dict__]))
        (run / "sp/candidates.json").write_text("[]")
        self.seed.write_bytes(b"\xff")
        outcomes = run_assertions_for_scan(run, self.source, self.seed, self.build,
                                           ["{binary}", "{input}"])
        self.assertEqual(outcomes[0].status, "VIOLATED")
        triage = json.loads(Path(outcomes[0].execution_result).parent.joinpath(
            "triage.json").read_text())
        self.assertEqual(triage["classification"], "INSUFFICIENT_EVIDENCE")

        class ExistingRoles:
            last_request_count = 1
            def __init__(self):
                self.calls = []
                self.verifications = {}
            async def analyze_function(self, *args, **kwargs):
                self.calls.append("analyze")
                return FunctionAnalysis("target", "target", "target.c", "possible input-linked access",
                    "data[0]", [], [], ["value <= 200"], [],
                    security_sensitive_operations=["array access with input-derived value"])
            async def generate_sp(self, *args, **kwargs):
                self.calls.append("generate_sp")
                return [SuspiciousPoint("sp-new", "w", "d", "target", "target.c",
                    "target.c:6", "input-related access", "possible bad access", ["value > 200"],
                    "data[0]", [], [], [], [])]
            async def verify_sp(self, point, *args, **kwargs):
                self.calls.append("verify_sp")
                self.verifications[point.sp_id] = VerificationResult(
                    point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
                    "UNKNOWN", "RUNTIME_TRACE", "security impact unresolved")
        roles = ExistingRoles()
        kwargs = dict(function_name="target", source=self.source.read_text(),
                      source_path=self.source, source_start_line=3, context=[],
                      harness_source=self.harness.read_text(), harness_source_path=self.harness,
                      target_repository=self.root, max_llm_calls=3)
        feedback = asyncio.run(apply_assertion_sp_feedback(run, roles, **kwargs))
        self.assertEqual(roles.calls, ["analyze", "generate_sp", "verify_sp"])
        self.assertEqual(feedback["feedback"][0]["status"],
                         "SP_GENERATED_FROM_NEW_RUNTIME_EVIDENCE")
        self.assertEqual(feedback["feedback"][0]["verified_sp_ids"], ["sp-new"])
        self.assertNotEqual(json.loads((run / "sp/sp-new.json").read_text())["status"], "VERIFIED")
        again = asyncio.run(apply_assertion_sp_feedback(run, roles, **kwargs))
        self.assertEqual(again["status"], "NO_NEW_EVIDENCE")

    def test_development_queue_keeps_assertion_feedback_verification_available(self):
        self.seed.write_bytes(b"\xff")

        class FeedbackRoles:
            last_request_count = 1

            def __init__(self):
                self.calls = []
                self.verifications = {}

            async def analyze_function(self, *args, **kwargs):
                self.calls.append("analyze")
                return FunctionAnalysis("target", "target", "target.c", "input-related access",
                    "data[0]", [], [], ["value <= 200"], [],
                    security_sensitive_operations=["array access with input-derived value"])

            async def generate_sp(self, *args, **kwargs):
                self.calls.append("generate_sp")
                return [SuspiciousPoint("sp-feedback", "w", "d", "target", "target.c",
                    "target.c:6", "input-related access", "possible bad access",
                    ["value > 200"], "data[0]", [], [], [], [])]

            async def verify_sp(self, point, *args, **kwargs):
                self.calls.append("verify_sp")
                self.verifications[point.sp_id] = VerificationResult(
                    point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
                    "UNKNOWN", "RUNTIME_TRACE", "impact unresolved")

        for policy, expected in (("PAIR_RESERVED", ["analyze", "generate_sp"]),
                                 ("DRAIN_RANKED_DEV", ["analyze", "generate_sp", "verify_sp"])):
            with self.subTest(policy=policy):
                run = self.root / policy
                for name in ("assertions", "analysis", "sp", "verification"):
                    (run / name).mkdir(parents=True)
                (run / "run.json").write_text('{"run_id":"assertion-feedback"}')
                analysis_path = run / "analysis/target.json"
                analysis_path.write_text(json.dumps(FunctionAnalysis(
                    "target", "target", "target.c", "unknown", "data[0]", [], [],
                    ["value <= 200"], []).__dict__))
                assertion = self.assertion("a-feedback", "value <= 200")
                assertion.source_function_analysis = str(analysis_path)
                (run / "assertions/proposed.json").write_text(json.dumps(
                    [assertion.__dict__]))
                (run / "sp/candidates.json").write_text("[]")
                (run / "scan.json").write_text(json.dumps({
                    "selected_sp_ids": ["sp-old-1", "sp-old-2", "sp-old-3"]}))
                outcomes = run_assertions_for_scan(
                    run, self.source, self.seed, self.build, ["{binary}", "{input}"])
                self.assertEqual(outcomes[0].status, "VIOLATED")
                roles = FeedbackRoles()
                feedback = asyncio.run(apply_assertion_sp_feedback(
                    run, roles, function_name="target", source=self.source.read_text(),
                    source_path=self.source, source_start_line=3, context=[],
                    harness_source=self.harness.read_text(),
                    harness_source_path=self.harness, target_repository=self.root,
                    max_llm_calls=4, max_sp_calls=3, max_hp_calls=1,
                    max_candidates=2, candidate_budget_policy=policy))
                self.assertEqual(roles.calls, expected)
                self.assertLessEqual(feedback["sp_llm_calls"], 3)
                self.assertLessEqual(feedback["llm_calls"], 4)
                self.assertEqual(feedback["feedback"][0]["verified_sp_ids"],
                                 ["sp-feedback"] if policy == "DRAIN_RANKED_DEV" else [])


class AssertionSlotContractTest(unittest.TestCase):
    def test_valid_rows_beyond_budget_are_explicitly_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text("int target(void) { return 0; }\n")
            seed = root / "seed"
            seed.write_bytes(b"A")
            run = root / "run"
            (run / "assertions").mkdir(parents=True)
            (run / "run.json").write_text('{"run_id":"pending-test"}')
            analysis = run / "analysis.json"
            analysis.write_text(json.dumps({"function_name": "target",
                                            "safe_assumptions": ["value <= 255"]}))
            rows = [Assertion(f"a-{index}", "w", "d", "target", "target.c:1",
                              "value <= 255", "value <= 255", [],
                              source_function_analysis=str(analysis))
                    for index in range(1, 6)]
            (run / "assertions/proposed.json").write_text(json.dumps(
                [item.__dict__ for item in rows]))

            def execute(item, *args, **kwargs):
                item.status = "HELD_FOR_EXECUTION"
                return item, None

            with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                       return_value={"quality": "HIGH_VALUE", "reasons": []}), \
                 patch("vulnerabilityanalysis.scan.execute_assertion", side_effect=execute):
                outcomes = run_assertions_for_scan(run, source, seed, ["build"],
                                                   ["{binary}", "{input}"], max_assertions=2)
            self.assertEqual([row.assertion_id for row in outcomes], ["a-1", "a-2"])
            pending = json.loads((run / "assertions/pending.json").read_text())
            self.assertEqual(pending["pending_assertion_ids"], ["a-3", "a-4", "a-5"])
            self.assertEqual(pending["reason"], "EXECUTION_BUDGET")

    def test_invalid_rows_do_not_displace_two_executable_assertions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text("int target(void) { return 0; }\n")
            seed = root / "seed"
            seed.write_bytes(b"A")
            run = root / "run"
            (run / "assertions").mkdir(parents=True)
            (run / "run.json").write_text('{"run_id":"slot-test"}')
            analysis = run / "analysis.json"
            analysis.write_text(json.dumps({"function_name": "target",
                                            "safe_assumptions": ["value <= 255"]}))
            rows = []
            for assertion_id in ("a-pre-invalid", "a-runtime-invalid", "a-valid-one", "a-valid-two"):
                item = Assertion(assertion_id, "w", "d", "target", "target.c:1",
                                 "value <= 255", "value <= 255", [],
                                 source_function_analysis=str(analysis))
                if assertion_id == "a-pre-invalid":
                    item.status = "INVALID_ASSERTION"
                rows.append(item)
            (run / "assertions/proposed.json").write_text(json.dumps(
                [item.__dict__ for item in rows]))

            def execute(item, *args, **kwargs):
                item.status = ("INVALID_ASSERTION" if item.assertion_id == "a-runtime-invalid"
                               else "HELD_FOR_EXECUTION")
                return item, None

            with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                       return_value={"quality": "HIGH_VALUE", "reasons": []}), \
                 patch("vulnerabilityanalysis.scan.execute_assertion", side_effect=execute) as executed:
                outcomes = run_assertions_for_scan(run, source, seed, ["build"],
                                                   ["{binary}", "{input}"], max_assertions=2)
            self.assertEqual([item.assertion_id for item in outcomes],
                             [item.assertion_id for item in rows])
            self.assertEqual(executed.call_count, 3)
            self.assertEqual([item.status for item in outcomes],
                             ["INVALID_ASSERTION", "INVALID_ASSERTION",
                              "HELD_FOR_EXECUTION", "HELD_FOR_EXECUTION"])
