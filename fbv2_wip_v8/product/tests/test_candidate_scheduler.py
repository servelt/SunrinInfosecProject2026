import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.models import SuspiciousPoint
from vulnerabilityanalysis.scan import (_corpus_inputs, candidate_verification_slots,
                                        scan_selected)
from vulnerabilityanalysis.scheduler import CandidateScheduler
from vulnerabilityanalysis.workflow import run_phase1


def candidate(number: int, important: bool = True) -> SuspiciousPoint:
    return SuspiciousPoint(
        f"sp-{number}", "w", "d", "parse", "target.c", f"target.c:{number + 10}",
        "indexed read", "index may exceed allocation", ["large index"] if important else [],
        "input byte controls index" if important else "UNKNOWN", [],
        ["source line shows indexed read"] if important else [], [], [],
        security_property="memory safety" if important else None,
    )


class CandidateSchedulerTest(unittest.TestCase):
    def test_corpus_index_tolerates_libfuzzer_removing_a_seed_during_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp)
            disappearing = corpus / "a-seed"
            disappearing.write_bytes(b"duplicate")
            stable = corpus / "b-seed"
            stable.write_bytes(b"stable")
            original_read = Path.read_bytes

            def read_while_fuzzer_mutates(path):
                if path == disappearing:
                    path.unlink()
                    raise FileNotFoundError(path)
                return original_read(path)

            with patch.object(Path, "read_bytes", read_while_fuzzer_mutates):
                indexed = _corpus_inputs(corpus)
            self.assertEqual(list(indexed.values()), [stable])

    def test_source_confirmed_lifetime_operation_prioritizes_sp_without_refuting_others(self):
        source = "void process(char *ptr) { orderedmap_remove (map, ptr); ptr += strlen (ptr) + 1; }"
        lifetime = candidate(1)
        lifetime.sp_id = "sp-a"
        lifetime.code_location = "`orderedmap_remove(map, ptr);` followed by `ptr += strlen(ptr) + 1;`"
        lifetime.suspicious_operation = "read after removal"
        lifetime.vulnerability_hypothesis = "removal may invalidate ptr before strlen"
        other = candidate(2)
        other.sp_id = "sp-z"
        other.code_location = "`orderedmap_remove(map, ptr);`"
        other.suspicious_operation = "case mismatch"
        selected = CandidateScheduler.default().select_many([other, lifetime], 1, source=source)
        self.assertEqual(selected[0].sp_id, "sp-a")
        self.assertEqual(other.status, "OPEN")
        self.assertTrue(any("source" in reason for reason in lifetime.priority_reasons))

    def test_verified_file_line_location_receives_source_bonus(self):
        source = ("void process(char *ptr) {\n"
                  "    orderedmap_remove(map, ptr);\n"
                  "    /* advance to next token */\n"
                  "    ptr += strlen(ptr) + 1;\n"
                  "}\n")
        point = candidate(1)
        point.source_line = 11
        point.code_location = "target.c:11"
        point.source_excerpt = "orderedmap_remove(map, ptr);"
        scheduler = CandidateScheduler.default()
        scheduler.score(point, source, source_start_line=10)
        self.assertTrue(any("source-confirmed mutation" in reason
                            for reason in point.priority_reasons))

        # A model-supplied location or excerpt cannot independently earn a
        # source-confirmation score when it disagrees with the analyzed source.
        for location, line, excerpt in (
                ("target.c:12", 11, "orderedmap_remove(map, ptr);"),
                ("target.c:11", 11, "free(ptr);"),
                ("target.c:11", 12, "orderedmap_remove(map, ptr);")):
            point.code_location, point.source_line, point.source_excerpt = location, line, excerpt
            scheduler.score(point, source, source_start_line=10)
            self.assertFalse(any("source-confirmed mutation" in reason
                                 for reason in point.priority_reasons))
        point.code_location = "target.c:11"
        point.source_line = 11
        point.source_excerpt = "orderedmap_remove(map, ptr);"
        scheduler.score(point, source)
        self.assertFalse(any("source-confirmed mutation" in reason
                             for reason in point.priority_reasons))
        separated = source.replace("    /* advance to next token */",
                                   "}\n    /* separate block */")
        scheduler.score(point, separated, source_start_line=10)
        self.assertFalse(any("source-confirmed mutation" in reason
                             for reason in point.priority_reasons))

    def test_fifth_slot_keeps_evidence_priority_when_all_candidates_wait_equally(self):
        items = [candidate(i) for i in range(5)] + [candidate(5, important=False)]
        scheduler = CandidateScheduler.default()
        selected = scheduler.select_many(items, 5)
        self.assertNotIn(items[-1], selected)
        self.assertEqual(len({item.sp_id for item in selected}), 5)
        self.assertEqual(items[-1].status, "OPEN")
        self.assertIn("equal wait age; evidence priority retained",
                      selected[-1].priority_reasons)

    def test_two_slot_budget_does_not_prefer_low_evidence_on_equal_wait(self):
        high = [candidate(i) for i in range(3)]
        waiting = candidate(3, important=False)
        selected = CandidateScheduler.default().select_many(high + [waiting], 2)
        self.assertNotIn(waiting, selected)
        self.assertEqual(selected[0].status, "OPEN")
        self.assertEqual(waiting.status, "OPEN")
        self.assertIn("equal wait age; evidence priority retained",
                      selected[1].priority_reasons)

    def test_two_slot_budget_serves_candidate_waiting_from_prior_run(self):
        high = [candidate(i) for i in range(3)]
        waiting = candidate(3, important=False)
        waiting.wait_age = 6
        selected = CandidateScheduler.default().select_many(high + [waiting], 2)
        self.assertIs(selected[1], waiting)
        self.assertIn("aging deep-verification slot", waiting.priority_reasons)

    def test_runtime_reachability_outweighs_unproven_input_hint(self):
        reached = candidate(1, important=False)
        reached.runtime_reachable = True
        hinted = candidate(2, important=True)
        selected = CandidateScheduler.default().select_many([reached, hinted], 1)
        self.assertEqual(selected[0].sp_id, "sp-1")
        self.assertIn("runtime", " ".join(selected[0].priority_reasons))

    def test_verifier_first_uses_same_six_turns_to_check_third_candidate(self):
        self.assertEqual(candidate_verification_slots(5, 3), 2)
        self.assertEqual(candidate_verification_slots(5, 3, "VERIFIER_FIRST"), 3)
        with self.assertRaisesRegex(ValueError, "candidate budget policy"):
            candidate_verification_slots(5, 3, "UNKNOWN")

        class Provider:
            def __init__(self, responses):
                self.responses = list(responses)

            async def generate(self, request):
                return self.responses.pop(0)

        candidates = [{
            "source_file": "target.c", "source_line": 2,
            "source_excerpt": "if (size > 0) return data[0];", "sp_condition": "",
            "suspicious_operation": "data[index]",
            "vulnerability_hypothesis": f"candidate {number} may exceed bounds",
            "trigger_conditions": ["large input"],
            "external_input_relation": "input byte controls index",
            "required_state": [], "security_property": "memory safety",
            "supporting_evidence": ["indexed read"],
            "contradicting_evidence": [], "unknowns": ["caller guard"]
        } for number in (1, 2, 3)]
        verdict = {"status": "PLAUSIBLE", "supporting_evidence": [],
                   "contradicting_evidence": [], "unknowns": ["caller guard"],
                   "rationale": "needs runtime", "reachability": "UNKNOWN",
                   "controllability": "UNKNOWN", "guards": [], "required_state": [],
                   "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                   "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        provider = Provider([
            {"suspicious_points": candidates},
            verdict, {"generator_script": "def build():\n    return b'A'\n",
                      "expected_behavior": "probe", "trigger_rationale": "input"},
            verdict, {"generator_script": "def build():\n    return b'B'\n",
                      "expected_behavior": "probe", "trigger_rationale": "input"},
            verdict,
        ])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"; repo.mkdir()
            (repo / "target.c").write_text(
                "int parse(const unsigned char *data, unsigned long size) {\n"
                "  if (size > 0) return data[0];\n  return 0;\n}\n")
            artifact = root / "hg"; artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(const char *p, unsigned long n) { return 0; }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
                "sanitizers": ["UNKNOWN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"; analysis.mkdir()
            (analysis / "functions.jsonl").write_text(json.dumps({
                "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
            run = run_phase1(artifact, root / "results", target_repository=repo)
            asyncio.run(scan_selected(
                run, provider, target_repository=repo,
                run_command=["/usr/bin/true", "{input}"],
                max_candidates=3, candidate_budget_policy="VERIFIER_FIRST",
                sp_llm_call_limit=6, hallucination_prevent="off"))
            summary = json.loads((run / "scan.json").read_text())
            self.assertEqual(summary["sp_llm_calls"], 6)
            self.assertEqual(summary["candidate_budget_policy"], "VERIFIER_FIRST")
            self.assertEqual(sum(value == "VERIFIER_EXECUTED" for value in
                                 summary["sp_verification_status"].values()), 3)
            self.assertEqual(summary["poc_count"], 2)
            self.assertEqual(provider.responses, [])

    def test_scan_executes_two_bounded_candidates_from_same_function(self):
        class Provider:
            def __init__(self, responses):
                self.responses = list(responses)

            async def generate(self, request):
                return self.responses.pop(0)

        rows = []
        for number in (1, 2, 3):
            rows.append({"source_file": "target.c", "source_line": 2,
                         "source_excerpt": "if (size > 0) return data[0];", "sp_condition": "",
                         "suspicious_operation": "data[index]",
                         "vulnerability_hypothesis": f"index {number} may exceed bounds",
                         "trigger_conditions": ["large input"],
                         "external_input_relation": "input byte controls index",
                         "required_state": [], "security_property": "memory safety",
                         "supporting_evidence": ["indexed read"],
                         "contradicting_evidence": [], "unknowns": ["caller guard"]})
        verdict = {"status": "PLAUSIBLE", "supporting_evidence": [],
                   "contradicting_evidence": [], "unknowns": ["caller guard"],
                   "rationale": "needs runtime", "reachability": "UNKNOWN",
                   "controllability": "UNKNOWN", "guards": [], "required_state": [],
                   "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                   "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        provider = Provider([
            {"suspicious_points": rows},
            verdict, {"generator_script": "def build():\n    return b'A'\n",
                      "expected_behavior": "probe", "trigger_rationale": "input"},
            verdict, {"generator_script": "def build():\n    return b'B'\n",
                      "expected_behavior": "probe", "trigger_rationale": "input"},
        ])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"; repo.mkdir()
            (repo / "target.c").write_text("int parse(const unsigned char *data, unsigned long size) {\n"
                                           "  if (size > 0) return data[0];\n  return 0;\n}\n")
            artifact = root / "hg"; artifact.mkdir()
            (artifact / "fuzz.c").write_text("int LLVMFuzzerTestOneInput(const char *p, unsigned long n) { return 0; }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
                "sanitizers": ["UNKNOWN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"; analysis.mkdir()
            (analysis / "functions.jsonl").write_text(json.dumps({
                "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
            run = run_phase1(artifact, root / "results", target_repository=repo)
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"], max_candidates=2,
                                      global_fuzz_enabled=True, global_fuzz_seconds=1,
                                      hallucination_prevent="off"))
            self.assertEqual(len(json.loads((run / "poc/pocs.json").read_text())), 2)
            self.assertEqual(json.loads((run / "scan.json").read_text())["poc_count"], 2)
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(len(scan["pending_sp_ids"]), 1)
            self.assertEqual(scan["sp_verification_status"][scan["pending_sp_ids"][0]],
                             "PENDING_CANDIDATE_BUDGET")
            self.assertEqual(json.loads((run / "runtime/global_fuzz.json").read_text())["status"],
                             "BLOCKED")
            candidates = json.loads((run / "sp/candidates.json").read_text())
            pending = next(row for row in candidates if row["sp_id"] == scan["pending_sp_ids"][0])
            self.assertEqual(pending["status"], "OPEN")
            # Candidate disposition and Verifier execution are separate axes:
            # an unresolved PoV leaves the hypothesis OPEN after verification.
            selected_rows = [row for row in candidates if row["sp_id"] in scan["selected_sp_ids"]]
            self.assertEqual(len(selected_rows), 2)
            self.assertTrue(all(row["status"] == "OPEN" for row in selected_rows))
            self.assertTrue(all(scan["sp_verification_status"][row["sp_id"]] ==
                                "VERIFIER_EXECUTED" for row in selected_rows))
            self.assertEqual({row["sp_id"] for row in
                              json.loads((run / "poc/pocs.json").read_text())},
                             {row["sp_id"] for row in selected_rows})
            self.assertIn(pending["sp_id"], [point.sp_id for point in
                CandidateScheduler.default().select_many([SuspiciousPoint(**pending)], 1)])
            self.assertTrue(all(row["priority_reasons"] for row in
                                json.loads((run / "sp/candidates.json").read_text())))

            original_scan = (run / "scan.json").read_bytes()
            resumed = run_phase1(artifact, root / "results", target_repository=repo)
            resumed_provider = Provider([verdict, {"generator_script": "def build():\n    return b'C'\n",
                                                   "expected_behavior": "probe", "trigger_rationale": "input"}])
            asyncio.run(scan_selected(resumed, resumed_provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      max_candidates=1, resume_from=run,
                                      hallucination_prevent="off"))
            self.assertEqual(resumed_provider.responses, [])
            self.assertTrue((resumed / "verification" / f"{pending['sp_id']}.json").is_file())
            resumed_scan = json.loads((resumed / "scan.json").read_text())
            self.assertNotIn(pending["sp_id"], resumed_scan["pending_sp_ids"])
            self.assertEqual(resumed_scan["sp_verification_status"][scan["selected_sp_ids"][0]],
                             "PROCESSED_PREVIOUS_RUN")
            self.assertEqual((run / "scan.json").read_bytes(), original_scan)
            # An orphan verification file is not evidence that the prior run
            # actually verified this pending candidate.
            verified_prior = root / "results" / "verified-prior"
            shutil.copytree(run, verified_prior)
            prior_verification = json.loads((run / "verification" /
                f"{scan['selected_sp_ids'][0]}.json").read_text())
            prior_verification["sp_id"] = pending["sp_id"]
            (verified_prior / "verification" / f"{pending['sp_id']}.json").write_text(
                json.dumps(prior_verification))
            verified_resume = run_phase1(artifact, root / "results", target_repository=repo)
            pov_only = Provider([{"generator_script": "def build():\n    return b'D'\n",
                                  "expected_behavior": "probe", "trigger_rationale": "input"}])
            with self.assertRaisesRegex(ValueError, "verification lineage mismatch"):
                asyncio.run(scan_selected(verified_resume, pov_only, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          max_candidates=1, resume_from=verified_prior,
                                          hallucination_prevent="off"))
            self.assertEqual(len(pov_only.responses), 1)
            repeated = run_phase1(artifact, root / "results", target_repository=repo)
            with self.assertRaisesRegex(ValueError, "same evidence"):
                asyncio.run(scan_selected(repeated, Provider([]), target_repository=repo,
                                          max_candidates=1, resume_from=run))

    def test_invalid_pov_syntax_does_not_abort_next_candidate(self):
        class Provider:
            def __init__(self, responses):
                self.responses = list(responses)

            async def generate(self, request):
                return self.responses.pop(0)

        candidates = [{
            "source_file": "target.c", "source_line": 2,
            "source_excerpt": "if (size > 0) return data[0];", "sp_condition": "",
            "suspicious_operation": "data[index]",
            "vulnerability_hypothesis": f"candidate {number} index may exceed bounds",
            "trigger_conditions": ["large input"],
            "external_input_relation": "input byte controls index",
            "required_state": [], "security_property": "memory safety",
            "supporting_evidence": ["indexed read"],
            "contradicting_evidence": [], "unknowns": ["caller guard"]
        } for number in (1, 2)]
        verdict = {"status": "PLAUSIBLE", "supporting_evidence": [],
                   "contradicting_evidence": [], "unknowns": ["caller guard"],
                   "rationale": "needs runtime", "reachability": "UNKNOWN",
                   "controllability": "UNKNOWN", "guards": [], "required_state": [],
                   "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                   "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        provider = Provider([
            {"suspicious_points": candidates},
            verdict, {"generator_script": "def build(:\n    pass\n",
                      "expected_behavior": "invalid syntax", "trigger_rationale": "input"},
            verdict, {"generator_script": "def build():\n    return b'B'\n",
                      "expected_behavior": "probe", "trigger_rationale": "input"},
        ])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"; repo.mkdir()
            (repo / "target.c").write_text(
                "int parse(const unsigned char *data, unsigned long size) {\n"
                "  if (size > 0) return data[0];\n  return 0;\n}\n")
            artifact = root / "hg"; artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(const char *p, unsigned long n) { return 0; }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
                "sanitizers": ["UNKNOWN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"; analysis.mkdir()
            (analysis / "functions.jsonl").write_text(json.dumps({
                "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
            run = run_phase1(artifact, root / "results", target_repository=repo)
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      max_candidates=2, hallucination_prevent="off"))
            rows = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(sorted(row["status"] for row in rows),
                             ["EXECUTED_UNRESOLVED", "INPUT_GENERATION_ERROR"])
            self.assertEqual(json.loads((run / "scan.json").read_text())["poc_count"], 2)
            self.assertEqual(provider.responses, [])

    def test_scan_keeps_unknown_open_when_verifier_requests_unavailable_context(self):
        class Provider:
            def __init__(self):
                self.responses = [
                    {"suspicious_points": [{"source_file": "target.c", "source_line": 2,
                     "source_excerpt": "  return data[i];", "sp_condition": "", "suspicious_operation": "data[i]",
                     "vulnerability_hypothesis": "i may be out of bounds", "trigger_conditions": ["large i"],
                     "external_input_relation": "input", "required_state": [], "security_property": "bounds",
                     "supporting_evidence": [], "contradicting_evidence": [], "unknowns": []}]},
                    {"status": "UNKNOWN", "supporting_evidence": [], "contradicting_evidence": [],
                     "unknowns": ["caller guard unknown"], "rationale": "need caller", "reachability": "UNKNOWN",
                     "controllability": "UNKNOWN", "guards": [], "required_state": [],
                     "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                     "context_requests": [{"target": "missing_caller", "request_type": "CALLER",
                      "reason": "check index guard", "expected_information": "bound"}],
                     "recommended_next_action": "REQUEST_CONTEXT"},
                    {"generator_script": "def build():\n    return b'A'\n",
                     "expected_behavior": "probe", "trigger_rationale": "input"},
                ]

            async def generate(self, request):
                return self.responses.pop(0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"; repo.mkdir()
            (repo / "target.c").write_text("int parse(int i, char *data) {\n  return data[i];\n}\n")
            artifact = root / "hg"; artifact.mkdir()
            (artifact / "fuzz.c").write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
                "sanitizers": ["UNKNOWN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"; analysis.mkdir()
            (analysis / "functions.jsonl").write_text(json.dumps({
                "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
            run = run_phase1(artifact, root / "results", target_repository=repo)
            asyncio.run(scan_selected(run, Provider(), target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="off"))
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(len(pocs), 1)
            self.assertEqual(pocs[0]["status"], "EXECUTED_UNRESOLVED")
            verification = next((run / "verification").glob("*.json"))
            self.assertEqual(json.loads(verification.read_text())["recommended_next_action"],
                             "REQUEST_CONTEXT")
            point = json.loads((run / "sp/candidates.json").read_text())[0]
            self.assertEqual(point["status"], "OPEN")
            self.assertEqual(json.loads((run / "scan.json").read_text())["poc_decisions"][0]["decision"],
                             "DYNAMIC_PROBE_WITH_UNKNOWN_VERDICT")


if __name__ == "__main__":
    unittest.main()
