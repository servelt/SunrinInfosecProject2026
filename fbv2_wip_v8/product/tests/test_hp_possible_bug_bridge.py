"""A model's bug suspicion can enter SP without becoming trusted evidence."""

import asyncio
from dataclasses import asdict
import json
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.models import FunctionAnalysis
from vulnerabilityanalysis.scan import (_queue_hp_possible_bugs,
                                        hp_possible_bug_candidates, scan_selected)
from vulnerabilityanalysis.workflow import prepare_sp_resume, run_phase1


def _analysis(judgment="POSSIBLE_BUG"):
    return FunctionAnalysis(
        function_id="fn", function_name="parse", source_file="target.c",
        summary="possible bounds error", input_flow="harness bytes may reach parse",
        state_dependencies=[], context_requests=[], safe_assumptions=[], unknowns=[],
        hypothesis_evaluations=[{
            "source_location": "target.c:parse, data[size]",
            "source_file": "", "source_line": 0, "source_quote": "",
            "input_influence": "UNKNOWN",
            "security_property": "read bounds", "hypothesis": "data[size] is readable",
            "judgment": judgment, "reason": "the guard permits size equal to the allocation",
            "safe_assumption": "",
        }],
    )


def _fixture(root):
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
    return artifact, repo


class _Provider:
    def __init__(self):
        self.roles = []

    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "sp_generation":
            return {"suspicious_points": []}
        if request.role == "function_analysis":
            row = _analysis().hypothesis_evaluations[0]
            return {
                "summary": "possible bounds error", "input_flow": "harness bytes may reach parse",
                "state_dependencies": [], "context_requests": [], "safe_assumptions": [],
                "unknowns": [], "input_sources": [], "security_sensitive_operations": [],
                "validations": [], "memory_operations": [], "evidence": [],
                "safe_assumption_lifecycle": [],
                "hypothesis_evaluations": [row],
            }
        if request.role == "sp_verifier":
            assert request.payload["suspicious_point"]["code_location"] == "UNKNOWN"
            return {
                "status": "PLAUSIBLE", "supporting_evidence": [],
                "contradicting_evidence": [], "unknowns": ["runtime state unknown"],
                "rationale": "needs execution", "reachability": "UNKNOWN",
                "controllability": "UNKNOWN", "guards": [], "required_state": [],
                "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                "context_requests": [], "recommended_next_action": "GENERATE_POC",
            }
        if request.role == "poc_generator":
            return {"generator_script": "def build():\n    return b'A'\n",
                    "expected_behavior": "exercise target", "trigger_rationale": "try input"}
        raise AssertionError(request.role)


class BridgeTest(unittest.TestCase):
    def test_hp_request_absolute_lines_feed_verified_candidate_without_relative_rewrite(self):
        class NumberedProvider(_Provider):
            async def generate(self, request):
                if request.role != "function_analysis":
                    return await super().generate(request)
                self.assert_source = request.payload["source"]
                self.assert_start = request.payload["source_start_line"]
                response = await super().generate(request)
                row = response["hypothesis_evaluations"][0]
                row.update(source_location="", source_file="target.c",
                           source_line=206,
                           source_quote="  return size ? data[size] : 0;")
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            function_source = ("int parse(const unsigned char *data, unsigned long size) {\n"
                               "  return size ? data[size] : 0;\n}\n")
            source.write_text("/* pad */\n" * 204 + function_source)
            provider = NumberedProvider()
            analysis = asyncio.run(AgentPipeline(provider).analyze_function(
                "fn", "parse", "target.c", function_source,
                source_start_line=205))
            self.assertEqual(provider.assert_start, 205)
            self.assertIn("206:   return size ? data[size] : 0;",
                          provider.assert_source)
            context = {"source_path": source, "target_root": root,
                       "function_source": function_source,
                       "function_start_line": 205}
            decisions: list[dict] = []
            points = hp_possible_bug_candidates(analysis, "w", "d", decisions,
                                                context)
            self.assertEqual(len(points), 1)
            self.assertEqual(decisions[0]["location_status"],
                             "VERIFIED_SINGLE_LINE")
            self.assertEqual(points[0].source_line, 206)
            analysis.hypothesis_evaluations[0]["source_line"] = 2
            decisions = []
            self.assertEqual(hp_possible_bug_candidates(
                analysis, "w", "d", decisions, context), [])
            self.assertEqual(decisions[0]["status"],
                             "REJECTED_LINE_OUTSIDE_FUNCTION")

    def test_structured_line_outside_analyzed_function_is_rejected_and_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'sp').mkdir()
            repo = root / 'repo'
            repo.mkdir()
            source = repo / 'target.c'
            function_source = 'int parse(void) {\n  return 1;\n}\n'
            source.write_text(function_source + 'int other(void) {\n  return 2;\n}\n')
            analysis = _analysis()
            row = analysis.hypothesis_evaluations[0]
            for quote in ('  return 2;', ''):
                with self.subTest(quote=quote):
                    row.update(source_location='' if quote else 'target.c:parse operation',
                               source_file='target.c', source_line=5,
                               source_quote=quote)
                    (root / 'function_analysis.json').write_text(json.dumps(asdict(analysis)))
                    ids = _queue_hp_possible_bugs(root, analysis, 'w', 'd', {
                        'function_id': 'fn', 'function_name': 'parse', 'source_file': 'target.c'},
                        location_context={'source_path': source, 'target_root': repo,
                                          'function_source': function_source,
                                          'function_start_line': 1})
                    self.assertEqual(ids, [])
                    decisions = json.loads((root / 'sp' / 'hp_possible_bug_dispositions.json').read_text())
                    self.assertEqual(decisions[0]['status'], 'REJECTED_LINE_OUTSIDE_FUNCTION')
                    self.assertFalse((root / 'sp' / 'candidates.json').exists())

    def test_structured_quote_supplies_operation_when_free_text_location_empty(self):
        analysis = _analysis()
        row = analysis.hypothesis_evaluations[0]
        row['source_location'] = ''
        row['source_file'] = 'target.c'
        row['source_line'] = 2
        row['source_quote'] = 'return size ? data[size] : 0;'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'target.c'
            source.write_text('int parse(const unsigned char *data, unsigned long size) {\n'
                              '  return size ? data[size] : 0;\n}\n')
            points = hp_possible_bug_candidates(analysis, 'w', 'd',
                location_context={'source_path': source, 'target_root': root,
                    'function_source': source.read_text(), 'function_start_line': 1})
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].code_location, 'target.c:2')
        self.assertEqual(points[0].suspicious_operation, row['source_quote'])

    def test_unused_hp_budget_allows_sp_and_hp_candidates_in_same_scan(self):
        class TwoCandidateProvider(_Provider):
            async def generate(self, request):
                if request.role == "sp_generation":
                    self.roles.append(request.role)
                    return {"suspicious_points": [{
                        "source_file": "target.c", "source_line": 2,
                        "source_excerpt": "return size ? data[size] : 0;",
                        "sp_condition": "size > 0", "suspicious_operation": "indexed read",
                        "vulnerability_hypothesis": "index may exceed buffer",
                        "trigger_conditions": ["large size"],
                        "external_input_relation": "input bytes", "required_state": [],
                        "security_property": "read bounds",
                        "supporting_evidence": ["indexed read in source"],
                        "contradicting_evidence": [], "unknowns": []}]}
                if request.role == "sp_verifier":
                    self.roles.append(request.role)
                    return {"status": "REFUTED", "supporting_evidence": [],
                            "contradicting_evidence": ["synthetic guard"], "unknowns": [],
                            "rationale": "synthetic refutation", "reachability": "UNKNOWN",
                            "controllability": "UNKNOWN", "guards": [], "required_state": [],
                            "contradiction_snippet": "", "contradiction_scope": "WHOLE_HYPOTHESIS",
                            "context_requests": [], "recommended_next_action": "REFUTE"}
                return await super().generate(request)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, repo = _fixture(root)
            run = run_phase1(artifact, root / "runs", target_repository=repo)
            provider = TwoCandidateProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      sp_llm_call_limit=4, hp_llm_call_limit=4,
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            turn_budget = json.loads((run / "sp" / "turn_budget.json").read_text())
            self.assertEqual(turn_budget["function_id"], scan["selected_function_id"])
            self.assertEqual(turn_budget["effective_sp_limit"],
                             scan["effective_sp_llm_call_limit"])
            self.assertEqual(turn_budget["combined_limit"],
                             scan["combined_llm_call_limit"])
            self.assertEqual(provider.roles.count("sp_verifier"), 2)
            self.assertEqual(len(scan["selected_sp_ids"]), 2)
            self.assertEqual(set(scan["hp_possible_bug_sp_ids"]) &
                             set(scan["selected_sp_ids"]),
                             set(scan["hp_possible_bug_sp_ids"]))
            self.assertEqual(scan["sp_llm_call_limit"], 4)
            self.assertGreater(scan["effective_sp_llm_call_limit"], 4)
            self.assertEqual(scan["transferred_hp_llm_calls"],
                             scan["hp_llm_call_limit"] - scan["hp_calls_before_transfer"])
            self.assertLessEqual(scan["sp_llm_calls"] + scan["hp_llm_calls"],
                                 scan["combined_llm_call_limit"])

    def test_possible_bug_is_untrusted_candidate_with_stable_origin(self):
        analysis = _analysis()
        first, second = [hp_possible_bug_candidates(analysis, "w", "d") for _ in range(2)]
        self.assertEqual([x.sp_id for x in first], [x.sp_id for x in second])
        self.assertEqual(len(first), 1)
        point = first[0]
        self.assertEqual(point.code_location, "UNKNOWN")
        self.assertIsNone(point.source_line)
        self.assertIsNone(point.sp_condition)
        self.assertEqual(point.external_input_relation, "UNKNOWN")
        self.assertIn("HP_ANALYSIS_POSSIBLE_BUG", point.status_history)
        self.assertIn("Potential violation", point.vulnerability_hypothesis)
        self.assertIn("data[size] is readable", point.vulnerability_hypothesis)
        self.assertFalse(point.supporting_evidence)

    def test_safe_unknown_and_missing_claim_do_not_enter_sp(self):
        for judgment in ("UNKNOWN", "EXPLICIT_SAFE_JUDGMENT"):
            self.assertEqual(hp_possible_bug_candidates(_analysis(judgment), "w", "d"), [])
        analysis = _analysis()
        analysis.hypothesis_evaluations[0]["reason"] = ""
        self.assertEqual(hp_possible_bug_candidates(analysis, "w", "d"), [])
        analysis = _analysis()
        analysis.hypothesis_evaluations[0]["source_location"] = "elsewhere.c:other_function"
        self.assertEqual(hp_possible_bug_candidates(analysis, "w", "d"), [])

    def test_rejected_hp_location_has_explicit_disposition(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sp").mkdir()
            analysis = _analysis()
            analysis.hypothesis_evaluations[0]["source_location"] = "elsewhere.c:other_function"
            (root / "function_analysis.json").write_text(json.dumps(asdict(analysis)))
            ids = _queue_hp_possible_bugs(root, analysis, "w", "d", {
                "function_id": "fn", "function_name": "parse", "source_file": "target.c"})
            self.assertEqual(ids, [])
            decisions = json.loads((root / "sp" / "hp_possible_bug_dispositions.json").read_text())
            self.assertEqual(decisions[0]["status"], "REJECTED_UNLINKED_SOURCE_LOCATION")
            self.assertFalse((root / "sp" / "candidates.json").exists())

    def test_hp_candidate_uses_only_pre_runtime_exact_single_line_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, repo = _fixture(root)
            source_path = repo / "target.c"
            analysis = _analysis()
            analysis.hypothesis_evaluations[0]["source_location"] = (
                "target.c:2: return size ? data[size] : 0;")
            context = {"source_path": source_path, "target_root": repo,
                       "function_source": source_path.read_text(),
                       "function_start_line": 1}
            points = hp_possible_bug_candidates(analysis, "w", "d",
                                                 location_context=context)
            self.assertEqual(points[0].code_location, "target.c:2")
            self.assertEqual(points[0].source_line, 2)
            self.assertEqual(points[0].source_excerpt,
                             "return size ? data[size] : 0;")
            analysis.hypothesis_evaluations[0]["source_location"] = (
                "target.c:2-3: return size ? data[size] : 0;")
            rejected_location = hp_possible_bug_candidates(
                analysis, "w", "d", location_context=context)
            self.assertEqual(rejected_location[0].code_location, "UNKNOWN")

    def test_mismatched_analysis_identity_is_rejected_before_queueing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sp").mkdir()
            analysis = _analysis()
            analysis.function_name = "another_function"
            with self.assertRaisesRegex(ValueError, "identity differs"):
                _queue_hp_possible_bugs(root, analysis, "w", "d", {
                    "function_id": "fn", "function_name": "parse", "source_file": "target.c"})
            self.assertFalse((root / "sp" / "candidates.json").exists())

    def test_fetched_hp_source_is_separate_from_original_sp_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sp").mkdir()
            (root / "sp" / "candidates.json").write_text("[]")
            (root / "scan.json").write_text('{"pending_sp_ids": [], "sp_verification_status": {}}')
            (root / "context.json").write_text("[]")
            (root / "function_analysis.json").write_text(json.dumps(asdict(_analysis())))
            hp_source = {"target": "callee", "source": "int callee(void) { return 1; }"}
            ids = _queue_hp_possible_bugs(root, _analysis(), "w", "d", {
                "function_id": "fn", "function_name": "parse", "source_file": "target.c",
            }, [hp_source, hp_source])
            self.assertEqual(len(ids), 1)
            self.assertEqual(json.loads((root / "context.json").read_text()), [])
            self.assertEqual(json.loads((root / "hp_context.json").read_text()), [hp_source])

    def test_live_hp_only_candidate_is_verified_in_same_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, repo = _fixture(root)
            run = run_phase1(artifact, root / "runs", target_repository=repo)
            first = _Provider()
            asyncio.run(scan_selected(run, first, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      sp_llm_call_limit=4, hp_llm_call_limit=4,
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(first.roles,
                             ["sp_generation", "function_analysis", "sp_verifier",
                              "poc_generator"])
            self.assertEqual(scan["poc_count"], 1)
            self.assertEqual(scan["pending_sp_ids"], [])
            self.assertEqual((scan["sp_llm_calls"], scan["hp_llm_calls"]), (3, 1))
            point = json.loads((run / "sp" / "candidates.json").read_text())[0]
            self.assertEqual(point["code_location"], "UNKNOWN")
            self.assertEqual(scan["sp_verification_status"][point["sp_id"]],
                             "VERIFIER_EXECUTED")
            self.assertNotEqual(point["status"], "VERIFIED")

    def test_hp_candidate_pending_budget_can_resume_without_new_hp_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, repo = _fixture(root)
            run = run_phase1(artifact, root / "runs", target_repository=repo)
            first = _Provider()
            asyncio.run(scan_selected(run, first, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      sp_llm_call_limit=1, hp_llm_call_limit=1,
                                      hallucination_prevent="on"))
            initial = json.loads((run / "scan.json").read_text())
            self.assertEqual(first.roles, ["sp_generation", "function_analysis"])
            self.assertEqual(initial["sp_verification_status"][
                initial["hp_possible_bug_sp_ids"][0]], "PENDING_CANDIDATE_BUDGET")
            self.assertEqual(initial["pending_sp_ids"], initial["hp_possible_bug_sp_ids"])
            resumed = prepare_sp_resume(run, root / "runs" / "resume")
            second = _Provider()
            asyncio.run(scan_selected(resumed, second, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      resume_from=run, hallucination_prevent="on",
                                      sp_llm_call_limit=4, hp_llm_call_limit=4))
            result = json.loads((resumed / "scan.json").read_text())
            self.assertEqual(second.roles, ["sp_verifier", "poc_generator"])
            self.assertEqual(result["pending_sp_ids"], [])
            self.assertEqual(result["poc_count"], 1)

    def test_evaluation_fuzz_override_is_explicit_and_capped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, repo = _fixture(root)
            run = run_phase1(artifact, root / "runs", target_repository=repo)
            asyncio.run(scan_selected(run, _Provider(), target_repository=repo,
                                      hallucination_prevent="off",
                                      fuzz_budget_seconds=7200,
                                      evaluation_fuzz_limit_seconds=7200))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(scan["fuzz_time_limit_seconds"], 7200)
            self.assertEqual(scan["evaluation_fuzz_limit_seconds"], 7200)
            with self.assertRaisesRegex(ValueError, "evaluation fuzz limit"):
                asyncio.run(scan_selected(run, _Provider(), target_repository=repo,
                                          hallucination_prevent="off",
                                          evaluation_fuzz_limit_seconds=7201))


if __name__ == "__main__":
    unittest.main()
