"""Target independent failures exposed by the official Harness workflow."""
import asyncio
from dataclasses import asdict
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.models import Assertion, FunctionAnalysis, FunctionPoolItem, SuspiciousPoint
from vulnerabilityanalysis.scan import (candidate_verification_slots,
    assertion_turn_decision, hp_possible_bug_candidates, reallocate_unused_hp_turns,
    refine_overstrong_assertions)
from vulnerabilityanalysis.scheduler import CandidateScheduler, Scheduler


class Provider:
    def __init__(self, response):
        self.response = response
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        return self.response


class WorkflowConnectionTests(unittest.TestCase):
    def test_depth_does_not_raise_priority_for_equally_reachable_functions(self):
        near = FunctionPoolItem("near", "near", "x.c", "d", "RELATED", None,
                                static_reachable=True, call_depth=0)
        far = FunctionPoolItem("far", "far", "x.c", "d", "RELATED", None,
                               static_reachable=True, call_depth=5)
        scheduler = Scheduler.default()
        self.assertEqual(scheduler.score(near), scheduler.score(far))
        self.assertFalse(any("depth" in reason for reason in near.priority_reasons))

    def test_zero_signal_core_does_not_outrank_source_risk_by_role_alone(self):
        core = FunctionPoolItem("core", "getter", "x.c", "d", "CORE", None,
                                static_reachable=True, call_depth=0)
        related = FunctionPoolItem("related", "decode", "x.c", "d", "RELATED", None,
                                   static_reachable=True, call_depth=1)
        selected = Scheduler.default().select(
            [core, related], sources={"core": "int getter(void) { return 0; }",
                                      "related": "void decode(char *p) { p[0] = 1; }"})
        self.assertIs(selected, related)
        self.assertEqual(core.risk_level, "UNKNOWN")

    def test_hp_candidate_and_sp_candidate_share_unverified_hint_score(self):
        def point(identifier, hp):
            return SuspiciousPoint(identifier, "w", "d", "parse", "x.c", "UNKNOWN",
                "indexed access", "index may exceed bounds", ["large index"],
                "UNKNOWN" if hp else "input may affect index", [], [], [], [],
                security_property="memory safety",
                status_history=["HP_ANALYSIS_POSSIBLE_BUG"] if hp else [])
        hp, sp = point("hp", True), point("sp", False)
        scheduler = CandidateScheduler.default()
        scheduler.score(hp)
        scheduler.score(sp)
        self.assertEqual(hp.priority_score, sp.priority_score)

    def test_legacy_empty_assertion_reply_has_explicit_disposition(self):
        analysis = FunctionAnalysis("fn", "target", "x.c", "summary", "flow", [], [],
                                    ["owned once"], [])
        pipeline = AgentPipeline(Provider({"assertions": []}), legacy_offline_replay=True)
        asyncio.run(pipeline.generate_assertions(analysis, "w", "d", "void target(void) {}"))
        self.assertEqual(pipeline.last_assertion_dispositions[0]["status"], "OTHER")
        self.assertEqual(pipeline.last_assertion_dispositions[0]["safe_assumption"], "owned once")

    def test_structured_hp_location_requires_exact_pre_runtime_line(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text("int parse(int n) {\n  return n + 1;\n}\n")
            row = {"source_location": "parse operation", "source_file": "target.c",
                   "source_line": 2, "source_quote": "return n + 1;",
                   "security_property": "integer bounds", "hypothesis": "n may wrap",
                   "judgment": "POSSIBLE_BUG", "reason": "n is unbounded",
                   "safe_assumption": "", "input_influence": "UNKNOWN"}
            analysis = FunctionAnalysis("fn", "parse", "target.c", "summary", "flow", [],
                                        [], [], [], hypothesis_evaluations=[row])
            context = {"source_path": source, "target_root": root,
                       "function_source": source.read_text(), "function_start_line": 1}
            accepted = hp_possible_bug_candidates(analysis, "w", "d", location_context=context)
            self.assertEqual(accepted[0].code_location, "target.c:2")
            row["source_quote"] = "return n + 2;"
            rejected = hp_possible_bug_candidates(analysis, "w", "d", location_context=context)
            self.assertEqual(rejected[0].code_location, "UNKNOWN")

    def test_new_assertion_dispositions_cover_each_safe(self):
        analysis = FunctionAnalysis("fn", "target", "x.c", "summary", "flow", [], [],
                                    ["owned once", "input bound"], [])
        response = {"assertions": [], "dispositions": [
            {"safe_id": 0, "safe_assumption": "owned once", "status": "NOT_EXPRESSIBLE",
             "reason": "requires a before and after relation"},
            {"safe_id": 1, "safe_assumption": "input bound", "status": "NOT_INPUT_DEPENDENT",
             "reason": "fixed by the harness"}]}
        pipeline = AgentPipeline(Provider(response))
        asyncio.run(pipeline.generate_assertions(analysis, "w", "d", "void target(void) {}"))
        self.assertEqual(len(pipeline.last_assertion_dispositions), 2)

    def test_incomplete_new_assertion_dispositions_are_recorded(self):
        analysis = FunctionAnalysis("fn", "target", "x.c", "summary", "flow", [], [],
                                    ["first", "second"], [])
        response = {"assertions": [], "dispositions": [
            {"safe_id": 0, "safe_assumption": "first", "status": "OTHER",
             "reason": "unsupported"}]}
        pipeline = AgentPipeline(Provider(response))
        asyncio.run(pipeline.generate_assertions(
            analysis, "w", "d", "void target(void) {}"))
        self.assertEqual(pipeline.last_assertion_dispositions[1]["status"],
                         "MISSING_DISPOSITION")

    def test_function_analysis_preserves_input_influence_claim_without_trusting_it(self):
        row = {"source_location": "x.c:2", "source_file": "x.c", "source_line": 2,
               "source_quote": "return n;", "security_property": "bounds",
               "hypothesis": "n is bounded", "judgment": "EXPLICIT_SAFE_JUDGMENT",
               "reason": "caller limits n", "safe_assumption": "n is bounded",
               "input_influence": "INPUT_DEPENDENT"}
        response = {"summary": "reviewed", "input_flow": "n from bytes",
                    "state_dependencies": [], "context_requests": [],
                    "safe_assumptions": ["n is bounded"], "unknowns": [],
                    "input_sources": [], "security_sensitive_operations": [],
                    "validations": [], "memory_operations": [], "evidence": [],
                    "safe_assumption_lifecycle": [],
                    "hypothesis_evaluations": [row]}
        analysis = asyncio.run(AgentPipeline(Provider(response)).analyze_function(
            "fn", "target", "x.c", "int target(int n) { return n; }"))
        self.assertEqual(analysis.hypothesis_evaluations[0]["input_influence"], "INPUT_DEPENDENT")

    def test_candidate_selection_reserves_verifier_and_pov_for_each_slot(self):
        self.assertEqual(candidate_verification_slots(3, 2), 1)
        self.assertEqual(candidate_verification_slots(4, 2), 2)
        self.assertEqual(candidate_verification_slots(1, 2), 0)

    def test_unused_hp_turns_increase_candidate_slots_without_exceeding_total(self):
        transfer = reallocate_unused_hp_turns(
            sp_cap=4, hp_cap=4, hp_used=3, product_sp_cap=8,
            safe_count=0, assertion_count=0, hp_complete=True, assertion_called=False,
            resumed=False)
        self.assertEqual(transfer["transferred_hp_calls"], 1)
        self.assertEqual(transfer["effective_sp_limit"], 5)
        self.assertLessEqual(transfer["effective_sp_limit"] + 3,
                             transfer["total_limit"])
        self.assertEqual(candidate_verification_slots(transfer["effective_sp_limit"] - 1, 2), 2)

    def test_hp_turns_are_not_transferred_when_claim_or_run_is_unfinished(self):
        scenarios = [
            dict(safe_count=1, assertion_count=1, hp_complete=True, assertion_called=True, resumed=False),
            dict(safe_count=0, assertion_count=0, hp_complete=False, assertion_called=False, resumed=False),
            dict(safe_count=0, assertion_count=0, hp_complete=True, assertion_called=False, resumed=True),
        ]
        for flags in scenarios:
            with self.subTest(flags=flags):
                decision = reallocate_unused_hp_turns(
                    sp_cap=4, hp_cap=4, hp_used=3, product_sp_cap=8, **flags)
                self.assertEqual(decision["transferred_hp_calls"], 0)
                self.assertEqual(decision["effective_sp_limit"], 4)

    def test_safe_without_any_assertion_reuses_only_unspent_hp_turns(self):
        transfer = reallocate_unused_hp_turns(
            sp_cap=4, hp_cap=4, hp_used=2, product_sp_cap=8,
            safe_count=3, assertion_count=0, hp_complete=True,
            assertion_called=True, resumed=False)
        self.assertEqual(transfer["effective_sp_limit"], 6)
        self.assertEqual(transfer["transferred_hp_calls"], 2)
        self.assertLessEqual(transfer["effective_sp_limit"] + 2, transfer["total_limit"])

    def test_hp_assertion_call_respects_its_own_limit(self):
        self.assertEqual(assertion_turn_decision(safe_count=1, hp_used=1, hp_cap=1),
                         "PENDING_HP_BUDGET")
        self.assertEqual(assertion_turn_decision(safe_count=1, hp_used=1, hp_cap=2), "CALL")
        self.assertEqual(assertion_turn_decision(safe_count=0, hp_used=1, hp_cap=1), "NO_SAFE")

    def test_refinement_preserves_reason_when_no_assertion_is_proposed(self):
        class RefinementPipeline:
            last_assertion_dispositions = []

            async def analyze_function(self, *args, **kwargs):
                return FunctionAnalysis("fn", "target", "target.c", "reviewed", "input", [],
                                        [], ["new safe"], [])

            async def generate_assertions(self, *args, **kwargs):
                self.last_assertion_dispositions = [{"safe_assumption": "new safe",
                    "status": "NOT_EXPRESSIBLE", "reason": "needs two observation points"}]
                return []

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            (run / "assertions").mkdir(parents=True)
            source = root / "target.c"
            source.write_text("int target(void) { return 0; }\n")
            input_path = root / "input.bin"
            input_path.write_bytes(b"x")
            execution = root / "execution" / "runtime.json"
            execution.parent.mkdir()
            (execution.parent / "triage.json").write_text(json.dumps({
                "classification": "OVERSTRONG_ASSUMPTION", "input_path": str(input_path)}))
            original = Assertion("old", "w", "d", "target", "target.c:1", "old safe",
                                 "1 == 1", [], status="VIOLATED", execution_result=str(execution))
            (run / "assertions" / "results.json").write_text(json.dumps([asdict(original)]))
            result = asyncio.run(refine_overstrong_assertions(
                run, RefinementPipeline(), function_id="fn", function_name="target",
                source_file="target.c", source=source.read_text(), original_source=source,
                source_start_line=1, context=[], build_command=[], run_command=[],
                fuzz_seconds=0))
            self.assertEqual(result["refinements"][0]["status"], "NO_VALID_REFINED_ASSERTION")
            disposition_path = run / "assertions" / "refinements" / "old" / "dispositions.json"
            self.assertEqual(json.loads(disposition_path.read_text())[0]["status"],
                             "NOT_EXPRESSIBLE")


if __name__ == "__main__":
    unittest.main()
