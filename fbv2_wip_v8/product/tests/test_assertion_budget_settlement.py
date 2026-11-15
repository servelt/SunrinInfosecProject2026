"""Assertion proposals and later SP feedback keep their own turn accounts."""
import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.assertions import assess_safe_assumption
from vulnerabilityanalysis.models import Assertion, FunctionAnalysis
from vulnerabilityanalysis.scan import (count_checkable_assertions,
    reallocate_unused_hp_turns, run_assertions_for_scan, scan_selected)
from vulnerabilityanalysis.workflow import run_phase1, write_json


class AssertionBudgetSettlementTests(unittest.TestCase):
    def test_quality_metrics_count_actual_preprocessing_attempts(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "target.c"
            source.write_text("#include <assert.h>\nint target(char *p) {\n"
                              "  assert(p);\n  return p[0];\n}\n")
            proposal = Assertion("a", "w", "d", "target", "target.c:4",
                                 "p != NULL", "p != NULL", [])
            metrics: dict[str, int] = {}
            with patch("vulnerabilityanalysis.assertions._run_assertion_command",
                       return_value=SimpleNamespace(returncode=1, stdout="")) as preprocess:
                assess_safe_assumption(proposal, source, build_command=["cc"],
                                       metrics=metrics)
            self.assertEqual(preprocess.call_count, 1)
            self.assertEqual(metrics["preprocess_count"], preprocess.call_count)

    def test_only_invalid_proposals_release_unused_hp_turns(self):
        invalid = [SimpleNamespace(status="INVALID_ASSERTION")]
        checkable = count_checkable_assertions(invalid)
        self.assertEqual(checkable, 0)
        decision = reallocate_unused_hp_turns(
            sp_cap=4, hp_cap=4, hp_used=2, product_sp_cap=8,
            safe_count=1, assertion_count=checkable,
            hp_complete=True, assertion_called=True, resumed=False)
        self.assertEqual(decision["effective_sp_limit"], 6)

    def test_checkable_proposal_reserves_hp_path(self):
        rows = [SimpleNamespace(status="INVALID_ASSERTION"),
                SimpleNamespace(status="PROPOSED")]
        self.assertEqual(count_checkable_assertions(rows), 1)

    def test_violation_feedback_accounts_hp_analysis_and_sp_generation_separately(self):
        class Pipeline:
            instance = None

            def __init__(self, *args, **kwargs):
                type(self).instance = self
                self.roles = []
                self.last_request_count = 1
                self.last_context_request_omitted = []
                self.last_request_artifacts = None
                self.last_assertion_dispositions = []
                self.last_assertion_disposition_errors = []
                self.verifications = {}

            async def generate_sp(self, *args, **kwargs):
                self.roles.append("sp_generation")
                return []

            async def analyze_function(self, *args, **kwargs):
                self.roles.append("function_analysis")
                return FunctionAnalysis("fn", "parse", "target.c", "source-backed SAFE",
                    "fuzzer input size reaches data read", [], [], ["size > 0"], [],
                    input_sources=["fuzzer size"],
                    security_sensitive_operations=["data read at index size"])

            async def generate_assertions(self, *args, **kwargs):
                self.roles.append("assertion_generator")
                return [Assertion("a", "worker", "direction", "parse", "target.c:2",
                                  "size > 0", "size > 0", [])]

        def fake_assertion_run(run_dir, *args, **kwargs):
            execution = run_dir / "assertions" / "a" / "executions" / "e"
            execution.mkdir(parents=True)
            runtime = execution / "runtime.json"
            runtime.write_text('{}')
            original = execution / "original_runtime.json"
            original.write_text('{"exit_code":0,"failure_classification":"NO_CRASH"}')
            write_json(execution / "triage.json", {
                "classification": "INSUFFICIENT_EVIDENCE",
                "original_runtime": str(original), "input_sha256": "synthetic",
                "input_path": str(args[1]), "safe_judgment": "size > 0",
                "source_review": "synthetic", "unknowns": []})
            violated = Assertion("a", "worker", "direction", "parse", "target.c:2",
                "size > 0", "size > 0", [], status="VIOLATED",
                execution_result=str(runtime))
            write_json(run_dir / "assertions" / "results.json", [asdict(violated)])
            write_json(run_dir / "assertions" / "sp_linkage.json", [{
                "assertion_id": "a", "worker_id": "worker", "direction_id": "direction",
                "input_runtime": str(runtime), "related_sp_ids": [], "relation": "UNKNOWN"}])
            return [violated]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            (repo / "target.c").write_text(
                "int parse(const unsigned char *data, unsigned long size) {\n"
                "  return size ? data[size] : 0;\n}\n")
            artifact = root / "harness"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) "
                "{ return parse(data, size); }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
                "sanitizers": ["ASAN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            (root / "analysis").mkdir()
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
            seed = root / "normal.bin"
            seed.write_bytes(b"A")
            run = run_phase1(artifact, root / "runs", target_repository=repo)
            with patch("vulnerabilityanalysis.scan.AgentPipeline", Pipeline), patch(
                    "vulnerabilityanalysis.scan.run_assertions_for_scan", fake_assertion_run):
                asyncio.run(scan_selected(run, SimpleNamespace(), target_repository=repo,
                    sp_llm_call_limit=4, hp_llm_call_limit=4,
                    hallucination_prevent="on", assertion_build_command=["true"],
                    assertion_run_command=["{binary}", "{input}"],
                    assertion_seed=seed))
            roles = Pipeline.instance.roles
            self.assertEqual(roles, ["sp_generation", "function_analysis",
                                     "assertion_generator", "function_analysis",
                                     "sp_generation"])
            scan = json.loads((run / "scan.json").read_text())
            turn_budget = json.loads((run / "sp/turn_budget.json").read_text())
            self.assertEqual((scan["sp_llm_calls"], scan["hp_llm_calls"]), (2, 3))
            self.assertEqual(scan["llm_calls"], 5)
            self.assertEqual((turn_budget["sp_calls_final"],
                              turn_budget["hp_calls_final"]), (2, 3))
            self.assertEqual(turn_budget["hp_calls_before_transfer"], 2)
            self.assertEqual(scan["assertion_execution"]["sp_feedback"]["sp_llm_calls"], 1)
            self.assertEqual(scan["assertion_execution"]["sp_feedback"]["hp_llm_calls"], 1)

    def test_executable_assertion_slots_prioritize_non_low_value_proposals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text("#include <stdint.h>\n"
                "int target(uint8_t x, unsigned idx, unsigned len) {\n"
                "  return (int)x + (int)idx;\n}\n")
            input_path = root / "normal.bin"
            input_path.write_bytes(b"A")
            run = root / "run"
            (run / "assertions").mkdir(parents=True)
            write_json(run / "run.json", {"run_id": "test-run"})
            analysis = run / "analysis.json"
            analysis.write_text(json.dumps({"function_name": "target",
                "safe_assumptions": ["x <= 255", "x >= 0", "idx < len"]}))
            expressions = ["x <= 255", "x >= 0", "idx < len"]
            proposals = [Assertion(f"a{index}", "w", "d", "target", "target.c:3",
                expression, expression, [], source_function_analysis=str(analysis))
                for index, expression in enumerate(expressions)]
            write_json(run / "assertions/proposed.json", [asdict(row) for row in proposals])

            def successful_execution(assertion, *args, **kwargs):
                assertion.status = "HELD_FOR_EXECUTION"
                return assertion, None

            with patch("vulnerabilityanalysis.scan.execute_assertion",
                       side_effect=successful_execution):
                outcomes = run_assertions_for_scan(run, source, input_path,
                    ["true"], ["{binary}", "{input}"], max_assertions=2)
            self.assertEqual([row.assertion_id for row in outcomes], ["a2", "a0"])
            self.assertEqual(json.loads((run / "assertions/pending.json").read_text())[
                "pending_assertion_ids"], ["a1"])
            quality = json.loads((run / "assertions/quality.json").read_text())
            self.assertEqual([row["assertion_id"] for row in quality],
                             ["a0", "a1", "a2"])
            self.assertEqual([row["quality"] for row in quality],
                             ["LOW_VALUE", "LOW_VALUE", "UNDETERMINED"])

    def test_scan_reuses_initial_quality_without_reassessing_every_proposal(self):
        class Pipeline:
            def __init__(self, *args, **kwargs):
                self.last_request_count = 1
                self.last_context_request_omitted = []
                self.last_request_artifacts = None
                self.last_assertion_dispositions = []
                self.last_assertion_disposition_errors = []
                self.verifications = {}

            async def generate_sp(self, *args, **kwargs):
                return []

            async def analyze_function(self, *args, **kwargs):
                return FunctionAnalysis("fn", "parse", "target.c", "source-backed SAFE",
                    "fuzzer input", [], [], ["x > 0", "x > 1", "x > 2"], [])

            async def generate_assertions(self, *args, **kwargs):
                return [Assertion(f"a{i}", "w", "d", "parse", "target.c:2",
                    f"x > {i}", f"x > {i}", []) for i in range(3)]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            (repo / "target.c").write_text("int parse(int x) {\n return x;\n}\n")
            artifact = root / "harness"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned n) "
                "{ return parse(n); }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c",
                "expected_consumers": ["parse"], "sanitizers": ["ASAN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            (root / "analysis").mkdir()
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
            seed = root / "normal.bin"
            seed.write_bytes(b"A")
            run = run_phase1(artifact, root / "runs", target_repository=repo)
            assessments = []
            executed = []

            def quality(assertion, *args, **kwargs):
                assessments.append(assertion.assertion_id)
                return {"assertion_id": assertion.assertion_id,
                    "quality": "LOW_VALUE" if assertion.assertion_id == "a0" else "UNDETERMINED",
                    "reasons": []}

            def execute(assertion, *args, **kwargs):
                executed.append(assertion.assertion_id)
                assertion.status = "HELD_FOR_EXECUTION"
                return assertion, None

            with patch("vulnerabilityanalysis.scan.AgentPipeline", Pipeline), patch(
                    "vulnerabilityanalysis.scan.assess_safe_assumption", side_effect=quality), patch(
                    "vulnerabilityanalysis.scan.execute_assertion", side_effect=execute):
                asyncio.run(scan_selected(run, SimpleNamespace(), target_repository=repo,
                    sp_llm_call_limit=4, hp_llm_call_limit=4, hallucination_prevent="on",
                    assertion_build_command=["true"],
                    assertion_run_command=["{binary}", "{input}"], assertion_seed=seed))
            self.assertEqual(assessments, ["a0", "a1", "a2"])
            self.assertEqual(executed, ["a1", "a2"])
            metrics = json.loads((run / "assertions/quality_metrics.json").read_text())
            self.assertEqual(metrics["initial"]["proposal_count"], 3)
            self.assertEqual(metrics["initial"]["quality_evaluated_count"], 3)
            self.assertEqual(metrics["execution_runs"][0]["quality_evaluated_count"], 0)
            self.assertEqual(metrics["total"]["preprocess_count"], 0)
            self.assertGreaterEqual(metrics["total"]["wall_ms"], 0)
            self.assertEqual([row["assertion_id"] for row in
                json.loads((run / "assertions/quality.json").read_text())],
                ["a0", "a1", "a2"])
            self.assertEqual(json.loads((run / "assertions/pending.json").read_text())[
                "pending_assertion_ids"], ["a0"])

            quality_path = run / "assertions/quality.json"
            inputs_path = run / "assertions/quality_inputs.json"
            analysis_path = run / "analysis/parse.json"
            source_path = repo / "target.c"
            baseline_quality = quality_path.read_bytes()
            baseline_inputs = inputs_path.read_bytes()
            baseline_analysis = analysis_path.read_bytes()
            baseline_source = source_path.read_bytes()
            for changed in ("source", "analysis", "build_command", "quality_row"):
                quality_path.write_bytes(baseline_quality)
                inputs_path.write_bytes(baseline_inputs)
                analysis_path.write_bytes(baseline_analysis)
                source_path.write_bytes(baseline_source)
                command = ["true"]
                if changed == "source":
                    source_path.write_bytes(baseline_source + b"/* changed source */\n")
                elif changed == "analysis":
                    analysis_row = json.loads(baseline_analysis)
                    analysis_row["summary"] = "changed analysis"
                    write_json(analysis_path, analysis_row)
                elif changed == "build_command":
                    command = ["another-compiler"]
                else:
                    rows = json.loads(baseline_quality)
                    rows[0]["quality"] = "UNDETERMINED"
                    write_json(quality_path, rows)
                assessments.clear()
                with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                           side_effect=quality), patch(
                           "vulnerabilityanalysis.scan.execute_assertion", side_effect=execute):
                    run_assertions_for_scan(run, source_path, seed, command,
                        ["{binary}", "{input}"], max_assertions=2)
                self.assertEqual(assessments, ["a0"] if changed == "quality_row" else
                                 ["a0", "a1", "a2"], changed)

            # An assert call depends on preprocessing state outside target.c
            # (for example an included header or NDEBUG). The source hash and
            # command may stay unchanged while the quality verdict changes.
            source_path.write_text("#include <assert.h>\nint parse(int x) {\n"
                " assert(x);\n return x;\n}\n")
            proposals_path = run / "assertions/proposed.json"
            proposals = json.loads(proposals_path.read_text())
            for proposal in proposals:
                proposal["source_location"] = "target.c:4"
            write_json(proposals_path, proposals)
            analysis_path.write_bytes(baseline_analysis)
            assessments.clear()
            with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                       side_effect=quality), patch(
                       "vulnerabilityanalysis.scan.execute_assertion", side_effect=execute):
                run_assertions_for_scan(run, source_path, seed, ["true"],
                    ["{binary}", "{input}"], max_assertions=2)
                assessments.clear()
                run_assertions_for_scan(run, source_path, seed, ["true"],
                    ["{binary}", "{input}"], max_assertions=2)
            self.assertEqual(assessments, ["a0", "a1", "a2"])


if __name__ == "__main__":
    unittest.main()
