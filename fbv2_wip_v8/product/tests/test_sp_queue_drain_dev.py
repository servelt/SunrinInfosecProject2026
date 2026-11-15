"""Bounded development comparison of preselection and ranked queue draining."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.models import VerificationResult
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import run_phase1

from test_direction_plan import fixture


class _ScriptedProvider:
    def __init__(self, candidate_count: int = 2) -> None:
        self.calls: list[str] = []
        self.candidate_count = candidate_count

    async def generate(self, request):
        self.calls.append(request.role)
        if request.role == "sp_generation":
            source = "int A(void) { return 0; }"
            rows = [{
                "source_file": "target.c", "source_line": 1,
                "source_excerpt": source, "sp_condition": "",
                "suspicious_operation": operation,
                "vulnerability_hypothesis": hypothesis,
                "trigger_conditions": triggers,
                "external_input_relation": "harness input may affect result",
                "required_state": [], "security_property": "memory safety",
                "supporting_evidence": supports, "contradicting_evidence": [],
                "unknowns": [],
            } for operation, hypothesis, triggers, supports in (
                ("first guard", "first hypothesis is refuted", ["guard path"],
                 ["source guard"]),
                ("second result", "second hypothesis needs runtime", [], []),
            )]
            for number in range(3, self.candidate_count + 1):
                rows.append({**rows[1],
                             "suspicious_operation": f"result operation {number}",
                             "vulnerability_hypothesis": f"hypothesis {number} needs runtime"})
            return {"suspicious_points": rows[:self.candidate_count]}
        if request.role == "poc_generator":
            return {"generator_script": "def build():\n    return b'A'\n",
                    "expected_behavior": "non-crashing probe",
                    "trigger_rationale": "development queue comparison"}
        raise AssertionError(f"unexpected model role: {request.role}")


class _DuplicateProvider(_ScriptedProvider):
    async def generate(self, request):
        if request.role != "sp_generation":
            return await super().generate(request)
        source = "int A(void) { return 0; }"
        common = {
            "source_file": "target.c", "source_line": 1,
            "source_excerpt": source, "sp_condition": "",
            "suspicious_operation": "read after free",
            "trigger_conditions": ["ptr freed before read"],
            "external_input_relation": "input may reach read",
            "required_state": ["ptr freed before read"],
            "security_property": "memory safety",
            "contradicting_evidence": [], "unknowns": [],
        }
        return {"suspicious_points": [
            {**common, "vulnerability_hypothesis": "use after free at result read",
             "supporting_evidence": []},
            {**common, "vulnerability_hypothesis": "released ptr read after free",
             "supporting_evidence": ["source hint one", "source hint two", "source hint three"]},
        ]}


async def _one_call_verifier(self, point, *_args, **_kwargs):
    self.last_request_count = 1
    refuted = point.vulnerability_hypothesis.startswith("first")
    point.status = "REFUTED" if refuted else "POC_PENDING"
    point.status_history.append(point.status)
    self.verifications[point.sp_id] = VerificationResult(
        point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
        "REFUTED" if refuted else "PLAUSIBLE",
        "REFUTE" if refuted else "GENERATE_POC",
        "scripted queue opportunity test")
    return point


async def _two_call_verifier_pending_pov(self, point, *_args, **_kwargs):
    # The verifier consumed an initial request and a context request.
    self.last_request_count = 2
    point.status = "POC_PENDING"
    point.status_history.append(point.status)
    self.verifications[point.sp_id] = VerificationResult(
        point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
        "PLAUSIBLE", "GENERATE_POC", "verified but PoV call exhausted")
    return point


class RankedQueueDrainDevTest(unittest.TestCase):
    def test_resume_rejects_duplicate_candidate_ids_before_any_new_artifact(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(artifact, repo / "runs", target_repository=repo)
            asyncio.run(scan_selected(
                first, _ScriptedProvider(candidate_count=1),
                target_repository=repo, max_candidates=0,
                sp_llm_call_limit=1, hallucination_prevent="off"))
            candidates_path = first / "sp/candidates.json"
            rows = json.loads(candidates_path.read_text())
            self.assertEqual(len(rows), 1)
            candidates_path.write_text(json.dumps([rows[0], rows[0]]))
            resumed = run_phase1(artifact, repo / "runs", target_repository=repo)
            provider = _ScriptedProvider()
            with self.assertRaisesRegex(ValueError, "duplicate SP ID in resume candidates"):
                asyncio.run(scan_selected(
                    resumed, provider, target_repository=repo,
                    resume_from=first, max_candidates=1,
                    sp_llm_call_limit=2, hallucination_prevent="off"))
            self.assertEqual(provider.calls, [])
            self.assertFalse((resumed / "sp/candidates.json").exists())

    def test_resume_keeps_pending_duplicate_when_prior_representative_is_not_pending(self):
        # A prior run may predate ranked deduplication. Its highest-scored SP
        # was handled; the lower-scored equivalent remains an explicit pending
        # opportunity. A resume must rank only its pending worklist.
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(artifact, repo / "runs", target_repository=repo)
            with (patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations", return_value=[]),
                  patch.object(AgentPipeline, "verify_sp", _one_call_verifier)):
                asyncio.run(scan_selected(
                    first, _DuplicateProvider(), target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=1, sp_llm_call_limit=3,
                    hallucination_prevent="off"))
            prior = json.loads((first / "scan.json").read_text())
            self.assertEqual(len(prior["pending_sp_ids"]), 1)
            self.assertEqual(len(prior["selected_sp_ids"]), 1)
            self.assertNotEqual(prior["pending_sp_ids"][0], prior["selected_sp_ids"][0])
            resumed = run_phase1(artifact, repo / "runs", target_repository=repo)
            with patch.object(AgentPipeline, "verify_sp", _one_call_verifier):
                asyncio.run(scan_selected(
                    resumed, _ScriptedProvider(), target_repository=repo,
                    resume_from=first,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=1, sp_llm_call_limit=2,
                    hallucination_prevent="off"))
            scan = json.loads((resumed / "scan.json").read_text())
            self.assertEqual(scan["selected_sp_ids"], prior["pending_sp_ids"])
            self.assertEqual(scan["deduplicated_sp_ids"], [])

    def test_default_resume_reuses_only_recorded_verification(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(artifact, repo / "runs", target_repository=repo)
            with patch.object(AgentPipeline, "verify_sp", _two_call_verifier_pending_pov):
                asyncio.run(scan_selected(
                    first, _ScriptedProvider(candidate_count=1),
                    target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=3,
                    hallucination_prevent="off"))
            prior_scan = json.loads((first / "scan.json").read_text())
            verified_id = prior_scan["selected_sp_ids"][0]
            self.assertIn(verified_id, prior_scan["pending_sp_ids"])
            self.assertIn(verified_id, prior_scan["verification_artifact_sha256"])
            resumed = run_phase1(artifact, repo / "runs", target_repository=repo)
            asyncio.run(scan_selected(
                resumed, _ScriptedProvider(), target_repository=repo,
                resume_from=first, run_command=["/usr/bin/true", "{input}"],
                max_candidates=2, sp_llm_call_limit=2,
                hallucination_prevent="off"))
            scan = json.loads((resumed / "scan.json").read_text())
            self.assertEqual(scan["sp_verification_status"][verified_id],
                             "VERIFIER_REUSED")
            self.assertEqual(scan["sp_llm_calls"], 1)
            self.assertEqual(scan["poc_count"], 1)

    def test_resume_reuses_prior_verification_with_one_sp_call_left(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with patch.object(AgentPipeline, "verify_sp", _two_call_verifier_pending_pov):
                asyncio.run(scan_selected(
                    first, _ScriptedProvider(), target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=3,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))
            prior_scan = json.loads((first / "scan.json").read_text())
            self.assertEqual(len(prior_scan["selected_sp_ids"]), 1)
            verified_id = prior_scan["selected_sp_ids"][0]
            self.assertIn(verified_id, prior_scan["pending_sp_ids"])
            self.assertEqual(prior_scan["sp_verification_status"][verified_id],
                             "VERIFIER_EXECUTED")
            self.assertIn(verified_id, prior_scan["verification_artifact_sha256"])
            resumed = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            asyncio.run(scan_selected(
                resumed, _ScriptedProvider(), target_repository=repo,
                resume_from=first, run_command=["/usr/bin/true", "{input}"],
                max_candidates=2, sp_llm_call_limit=1,
                candidate_budget_policy="DRAIN_RANKED_DEV",
                hallucination_prevent="off"))
            scan = json.loads((resumed / "scan.json").read_text())
            budget = json.loads((resumed / "sp/turn_budget.json").read_text())
            self.assertEqual(budget["reused_verification_count"], 1)
            self.assertEqual(budget["possible_pov_pairs"], 1)
            self.assertGreaterEqual(scan["effective_candidate_limit"], 1)
            self.assertEqual(scan["poc_count"], 1)
            self.assertEqual(scan["sp_llm_calls"], 1)

    def test_resume_rejects_verification_added_after_prior_scan(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            asyncio.run(scan_selected(
                first, _ScriptedProvider(candidate_count=3),
                target_repository=repo, run_command=["/usr/bin/true", "{input}"],
                max_candidates=2, sp_llm_call_limit=1,
                candidate_budget_policy="DRAIN_RANKED_DEV",
                hallucination_prevent="off"))
            points = json.loads((first / "sp/candidates.json").read_text())
            reusable_id = points[-1]["sp_id"]
            (first / "verification").mkdir(exist_ok=True)
            verification = VerificationResult(
                reusable_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
                "PLAUSIBLE", "GENERATE_POC", "prior run verified this candidate")
            (first / "verification" / f"{reusable_id}.json").write_text(
                json.dumps(verification.__dict__))
            resumed = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")

            with self.assertRaisesRegex(ValueError, "verification lineage mismatch"):
                asyncio.run(scan_selected(
                    resumed, _ScriptedProvider(), target_repository=repo,
                    resume_from=first,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=2,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))

    def test_resume_rejects_changed_prior_verification_bytes(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with patch.object(AgentPipeline, "verify_sp", _two_call_verifier_pending_pov):
                asyncio.run(scan_selected(
                    first, _ScriptedProvider(), target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=3,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))
            prior_scan = json.loads((first / "scan.json").read_text())
            verified_id = prior_scan["selected_sp_ids"][0]
            verification_path = first / "verification" / f"{verified_id}.json"
            verification_path.write_bytes(verification_path.read_bytes() + b"\n")
            resumed = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with self.assertRaisesRegex(ValueError, "verification lineage mismatch"):
                asyncio.run(scan_selected(
                    resumed, _ScriptedProvider(), target_repository=repo,
                    resume_from=first,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=1,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))

    def test_targeted_fuzz_reservations_follow_queue_pair_bound(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            requested_seconds: list[int] = []

            def fake_targeted_fuzz(*_args, **kwargs):
                requested_seconds.append(kwargs["seconds"])
                return None

            with (patch.object(AgentPipeline, "verify_sp", _one_call_verifier),
                  patch("vulnerabilityanalysis.scan.run_targeted_fuzz",
                        side_effect=fake_targeted_fuzz)):
                asyncio.run(scan_selected(
                    run, _ScriptedProvider(candidate_count=4),
                    target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=8,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    targeted_fuzzer_binary=Path("/usr/bin/true"),
                    targeted_fuzz_seconds=5, fuzz_budget_seconds=5,
                    hallucination_prevent="off"))
            budget = json.loads((run / "sp" / "turn_budget.json").read_text())
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(budget["targeted_fuzz_slice_seconds"], 1)
            self.assertEqual(scan["poc_count"], 3)
            self.assertEqual(requested_seconds, [1, 1, 1])
            self.assertLessEqual(scan["fuzz_seconds_allocated"], 5)

    def test_queue_worklist_is_call_bounded_and_zero_disables_it(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            for enabled in (0, 2):
                provider = _ScriptedProvider(candidate_count=20)
                run = run_phase1(
                    artifact, repo / "runs", target_repository=repo,
                    direction_plan=plan,
                    selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
                with patch.object(AgentPipeline, "verify_sp", _one_call_verifier):
                    asyncio.run(scan_selected(
                        run, provider, target_repository=repo,
                        run_command=["/usr/bin/true", "{input}"],
                        max_candidates=enabled, sp_llm_call_limit=4,
                        candidate_budget_policy="DRAIN_RANKED_DEV",
                        hallucination_prevent="off"))
                scan = json.loads((run / "scan.json").read_text())
                self.assertEqual(scan["sp_count"], 20)
                self.assertEqual(scan["effective_candidate_limit"],
                                 0 if enabled == 0 else 2)
                self.assertEqual(len(scan["queued_sp_ids"]),
                                 scan["effective_candidate_limit"])
                self.assertLessEqual(scan["sp_llm_calls"], 4)
                self.assertEqual(len(scan["pending_sp_ids"]),
                                 20 if enabled == 0 else 18)
                if enabled:
                    candidates = json.loads((run / "sp/candidates.json").read_text())
                    self.assertLessEqual(max(row["wait_age"] for row in candidates), 2)

    def test_resume_cannot_change_ranked_queue_budget_identity(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            first = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan,
                selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with patch.object(AgentPipeline, "verify_sp", _one_call_verifier):
                asyncio.run(scan_selected(
                    first, _ScriptedProvider(candidate_count=3),
                    target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    max_candidates=2, sp_llm_call_limit=4,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))
            self.assertTrue(json.loads((first / "scan.json").read_text())["pending_sp_ids"])
            for policy, maximum in (("PAIR_RESERVED", 2), ("DRAIN_RANKED_DEV", 3)):
                resumed = run_phase1(
                    artifact, repo / "runs", target_repository=repo,
                    direction_plan=plan,
                    selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
                with self.assertRaisesRegex(ValueError, "queue resume budget policy changed"):
                    asyncio.run(scan_selected(
                        resumed, _ScriptedProvider(), target_repository=repo,
                        resume_from=first, max_candidates=maximum,
                        candidate_budget_policy=policy,
                        hallucination_prevent="off"))

    @unittest.skipUnless(shutil.which("clang"), "clang/libFuzzer required")
    def test_drain_reaches_real_c_binary_after_first_refutation(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            binary = repo / "compiled-fuzzer"
            subprocess.run(["clang", "-fsanitize=fuzzer,address", "-g",
                            str(repo / "target.c"), str(repo / "fuzz.c"),
                            "-o", str(binary)], check=True, capture_output=True)
            run = run_phase1(
                artifact, repo / "runs", target_repository=repo,
                direction_plan=plan, selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with patch.object(AgentPipeline, "verify_sp", _one_call_verifier):
                asyncio.run(scan_selected(
                    run, _ScriptedProvider(), target_repository=repo,
                    run_command=[str(binary), "{input}"],
                    max_candidates=2, sp_llm_call_limit=4,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))
            scan = json.loads((run / "scan.json").read_text())
            pocs = json.loads((run / "poc" / "pocs.json").read_text())
            self.assertEqual(scan["sp_llm_calls"], 4)
            self.assertEqual(len(pocs), 1)
            runtime = json.loads(Path(pocs[0]["execution_log"]).read_text())
            self.assertEqual(runtime["exit_code"], 0)
            self.assertFalse(runtime["sanitizer"])

    def test_refuted_candidate_releases_call_for_next_verifier_and_pov(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            results = {}
            with patch.object(AgentPipeline, "verify_sp", _one_call_verifier):
                for policy in ("PAIR_RESERVED", "DRAIN_RANKED_DEV"):
                    provider = _ScriptedProvider()
                    run = run_phase1(
                        artifact, repo / "runs", target_repository=repo,
                        direction_plan=plan,
                        selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
                    asyncio.run(scan_selected(
                        run, provider, target_repository=repo,
                        run_command=["/usr/bin/true", "{input}"],
                        max_candidates=2, sp_llm_call_limit=4,
                        candidate_budget_policy=policy,
                        hallucination_prevent="off"))
                    scan = json.loads((run / "scan.json").read_text())
                    results[policy] = (scan, provider.calls)
            pair, pair_calls = results["PAIR_RESERVED"]
            drained, drained_calls = results["DRAIN_RANKED_DEV"]
            self.assertEqual(pair["sp_llm_calls"], 2)
            self.assertEqual(pair["poc_count"], 0)
            self.assertEqual(drained["sp_llm_calls"], 4)
            self.assertEqual(drained["poc_count"], 1)
            self.assertEqual(pair_calls, ["sp_generation"])
            self.assertEqual(drained_calls, ["sp_generation", "poc_generator"])
            self.assertEqual(sum(value == "VERIFIER_EXECUTED" for value in
                                 drained["sp_verification_status"].values()), 2)

    def test_queue_drain_rejects_old_score_selection(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan)
            with self.assertRaisesRegex(ValueError, "development-only"):
                asyncio.run(scan_selected(
                    run, _ScriptedProvider(), target_repository=repo,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    hallucination_prevent="off"))
