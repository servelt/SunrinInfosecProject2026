"""HP Context expansion must not silently erase an earlier bug lead."""

import unittest
import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnerabilityanalysis.scan import retain_hp_possible_bug_history, scan_selected
from vulnerabilityanalysis.workflow import run_phase1


class HPRoundHistoryTests(unittest.TestCase):
    def test_scan_queues_first_round_lead_after_context_round_omits_it(self):
        class Provider:
            def __init__(self):
                self.analysis_calls = 0

            async def generate(self, request):
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                if request.role != "function_analysis":
                    raise AssertionError(request.role)
                self.analysis_calls += 1
                first = self.analysis_calls == 1
                return {"summary": "reviewed", "input_flow": "bytes", "state_dependencies": [],
                        "context_requests": ([{"target": "helper", "request_type": "FUNCTION",
                                              "reason": "check bound", "expected_information": "bound",
                                              "hypothesis_index": 0}]
                                             if first else []),
                        "safe_assumptions": [], "unknowns": [], "input_sources": [],
                        "security_sensitive_operations": [], "validations": [],
                        "memory_operations": [], "evidence": [],
                        "safe_assumption_lifecycle": [],
                        "hypothesis_evaluations": ([{"judgment": "POSSIBLE_BUG",
                            "hypothesis": "index may be invalid", "source_location": "target.c:2",
                            "source_file": "target.c", "source_line": 2,
                            "source_quote": "  return size ? data[0] : 0;",
                            "security_property": "memory safety", "reason": "review needed",
                            "safe_assumption": "", "input_influence": "UNKNOWN"}]
                            if first else [])}

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "target.c").write_text(
                "int parse(const unsigned char *data, unsigned long size) {\n"
                "  return size ? data[0] : 0;\n}\n"
                "int helper(void) { return 1; }\n")
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *p, unsigned long n) "
                "{ return parse(p, n); }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
                "sanitizers": ["ASAN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            (root / "analysis").mkdir()
            (root / "analysis/functions.jsonl").write_text("\n".join(json.dumps({
                "function_id": name, "name": name, "file": "target.c"})
                for name in ("parse", "helper")) + "\n")
            run = run_phase1(artifact, root / "result", target_repository=repo)
            provider = Provider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="on", sp_llm_call_limit=1,
                                      hp_llm_call_limit=3))
            self.assertEqual(provider.analysis_calls, 2)
            candidate = json.loads((run / "hp_candidate_analysis.json").read_text())
            self.assertEqual(len(candidate["hypothesis_evaluations"]), 1)
            history = json.loads((run / "hp_analysis_rounds.json").read_text())
            self.assertEqual(history["possible_bug_history"][0]["status"],
                             "NOT_RESTATED_IN_FINAL_ROUND")
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(len(scan["hp_possible_bug_sp_ids"]), 1)

    def test_omitted_prior_bug_is_retained_for_verification(self):
        lead = {"judgment": "POSSIBLE_BUG", "hypothesis": "length may exceed buffer",
                "source_location": "target.c:7", "source_file": "target.c",
                "source_line": 7, "source_quote": "buf[n] = 0;",
                "security_property": "memory safety", "reason": "bound not established"}
        rows, audit = retain_hp_possible_bug_history([[lead], []])
        self.assertEqual(rows, [lead])
        self.assertEqual(audit[0]["status"], "NOT_RESTATED_IN_FINAL_ROUND")

    def test_same_lead_is_deduplicated_and_latest_rationale_kept(self):
        first = {"judgment": "POSSIBLE_BUG", "hypothesis": "length may exceed buffer",
                 "source_location": "target.c:7", "reason": "needs context"}
        second = dict(first, reason="caller does not bound length")
        rows, audit = retain_hp_possible_bug_history([[first], [second]])
        self.assertEqual(rows, [second])
        self.assertEqual(len(audit), 2)

    def test_model_safe_without_verified_refutation_does_not_erase_lead(self):
        lead = {"judgment": "POSSIBLE_BUG", "hypothesis": "length may exceed buffer",
                "source_location": "target.c:7", "reason": "unbounded"}
        later = dict(lead, judgment="SAFE", reason="probably checked")
        rows, audit = retain_hp_possible_bug_history([[lead], [later]])
        self.assertEqual(rows, [lead])
        self.assertEqual(audit[0]["status"], "LATER_MODEL_REASSESSMENT_UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
