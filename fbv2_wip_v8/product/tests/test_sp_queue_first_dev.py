"""Provider-free queue-first development regressions."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.models import ContextRequest, VerificationResult
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.scheduler import CandidateScheduler
from vulnerabilityanalysis.workflow import run_phase1

from test_direction_plan import fixture


class _Provider:
    def __init__(self, count=3):
        self.count = count
        self.calls = []

    async def generate(self, request):
        self.calls.append(request.role)
        if request.role == "sp_verifier":
            return {}
        if request.role == "function_analysis":
            return {
                "summary": "possible input-dependent bounds issue", "input_flow": "input",
                "state_dependencies": [], "context_requests": [], "safe_assumptions": [],
                "unknowns": [], "input_sources": [],
                "security_sensitive_operations": [], "validations": [],
                "memory_operations": [], "evidence": [],
                "safe_assumption_lifecycle": [],
                "hypothesis_evaluations": [{
                    "source_location": "target.c:A, return statement",
                    "source_file": "target.c", "source_line": 1,
                    "source_quote": "int A(void) { return 0; }",
                    "input_influence": "UNKNOWN", "security_property": "memory safety",
                    "hypothesis": "return value may violate an input-dependent bound",
                    "judgment": "POSSIBLE_BUG", "reason": "requires runtime validation",
                    "safe_assumption": "",
                }],
            }
        if request.role == "sp_generation":
            return {"suspicious_points": [{
                "source_file": "target.c", "source_line": 1,
                "source_excerpt": "int A(void) { return 0; }",
                "sp_condition": "input reaches A", "suspicious_operation": f"operation {i}",
                "vulnerability_hypothesis": f"hypothesis {i}",
                "trigger_conditions": [f"trigger {i}"],
                "external_input_relation": "harness input may affect result",
                "required_state": [], "security_property": "memory safety",
                "supporting_evidence": [], "contradicting_evidence": [], "unknowns": [],
            } for i in range(self.count)]}
        if request.role == "poc_generator":
            return {"generator_script": "def build():\n    return b'A'\n",
                    "expected_behavior": "non-crashing probe",
                    "trigger_rationale": "development queue comparison"}
        raise AssertionError(request.role)


class _Ledger:
    def __init__(self, function_id: str, maximum: int):
        self.budget = SimpleNamespace(profile="GLOBAL_ONLY_DEV", logical_max=maximum,
                                      physical_max=maximum, wall_seconds=60)
        self.logical = 0
        self.physical = 0
        self.started_at = time.time()
        self.selected_functions = [function_id]
        self.active_turn = None
        self.tainted = False

    def debit(self):
        if self.logical >= self.budget.logical_max or self.physical >= self.budget.physical_max:
            raise AssertionError("physical request after external budget exhaustion")
        self.logical += 1
        self.physical += 1


class _GuardedProvider(_Provider):
    def __init__(self, ledger: _Ledger, function_id: str, count=3,
                 fail_verifier=False, expire_after_generation=False):
        super().__init__(count)
        self.ledger = ledger
        self.scope_id = function_id
        self.fail_verifier = fail_verifier
        self.expire_after_generation = expire_after_generation
        self.backend = SimpleNamespace(ledger=ledger, scope_id=function_id,
                                       _request=lambda *_a, **_k: None)

    async def generate(self, request):
        self.ledger.debit()
        if self.fail_verifier and request.role == "sp_verifier":
            self.calls.append(request.role)
            raise RuntimeError("partial verifier transport after physical start")
        result = await super().generate(request)
        if self.expire_after_generation and request.role == "sp_generation":
            self.ledger.started_at -= 61
        return result


class _Qualification:
    product_issued = True

    def __init__(self, source_root: Path, harness: Path, binary: Path):
        self.source_root = source_root.resolve()
        self.harness = harness.resolve()
        self.binary = binary.resolve()


def _fixed_order(self, points, limit, **_kwargs):
    # select_many's requested limit changes its aging slots. Hold rank fixed.
    return points[:max(0, limit)]


def _verifier(refuted: set[int], *, context_round_for: int | None = None,
              reanalyze_for: int | None = None):
    attempts = {}

    async def verify(self, point, *_args, **_kwargs):
        await self.provider.generate(SimpleNamespace(role="sp_verifier"))
        self.last_request_count = 1
        try:
            index = int(point.vulnerability_hypothesis.rsplit(" ", 1)[-1])
        except ValueError:
            index = -1
        attempts[point.sp_id] = attempts.get(point.sp_id, 0) + 1
        requesting = index == context_round_for and attempts[point.sp_id] == 1
        verdict = "REFUTED" if index in refuted else "PLAUSIBLE"
        action = ("REQUEST_CONTEXT" if requesting else
                  "REANALYZE" if index == reanalyze_for else
                  "REFUTE" if verdict == "REFUTED" else "GENERATE_POC")
        point.status = ("REFUTED" if verdict == "REFUTED" and not requesting else
                        "OPEN" if index == reanalyze_for else "POC_PENDING")
        point.status_history.append(point.status)
        self.verifications[point.sp_id] = VerificationResult(
            point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
            verdict if not requesting else "UNKNOWN", action, "scripted verifier",
            [ContextRequest("A", "A", "FUNCTION", "inspect A", "source body")]
            if requesting else [])
        return point

    return verify


class QueueFirstDevTest(unittest.TestCase):
    def _run(self, root: Path, *, count=3, sp_limit=4, hp_limit=1,
             verifier=None, hp=False, policy="QUEUE_FIRST_DEV", targeted=0):
        root.mkdir(parents=True, exist_ok=True)
        artifact, repo, plan = fixture(root)
        run = run_phase1(artifact, repo / "runs", target_repository=repo,
                         direction_plan=plan,
                         selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
        provider = _Provider(count)
        with (patch.object(CandidateScheduler, "select_many", _fixed_order),
              patch.object(AgentPipeline, "verify_sp", verifier or _verifier({0, 1})),
              patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations", return_value=[]),
              patch("vulnerabilityanalysis.scan.run_targeted_fuzz", return_value=None)):
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                run_command=["/usr/bin/true", "{input}"],
                candidate_budget_policy=policy, max_candidates=2,
                sp_llm_call_limit=sp_limit, hp_llm_call_limit=hp_limit,
                targeted_fuzzer_binary=Path("/usr/bin/true") if targeted else None,
                targeted_fuzz_seconds=targeted, fuzz_budget_seconds=targeted,
                hallucination_prevent="on" if hp else "off"))
        return json.loads((run / "scan.json").read_text()), provider, run

    def _external_run(self, root: Path, *, maximum=3, verifier=None,
                      fail_verifier=False, expire_after_generation=False):
        artifact, repo, plan = fixture(root)
        run = run_phase1(artifact, repo / "runs", target_repository=repo,
                         direction_plan=plan,
                         selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
        function_id = json.loads((run / "selection.json").read_text())["function_id"]
        binary = repo / "target.bin"
        binary.write_bytes(b"fixture only")
        qualification = _Qualification(repo, repo / "fuzz.c", binary)
        ledger = _Ledger(function_id, maximum)
        provider = _GuardedProvider(ledger, function_id, fail_verifier=fail_verifier,
                                    expire_after_generation=expire_after_generation)
        with (patch.object(CandidateScheduler, "select_many", _fixed_order),
              patch.object(AgentPipeline, "verify_sp", verifier or _verifier(set())),
              patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations", return_value=[]),
              patch("vulnerabilityanalysis.scan.OfficialPinnedQualification", _Qualification),
              patch("vulnerabilityanalysis.scan._official_pin_matches_qualification",
                    return_value=True),
              patch("vulnerabilityanalysis.scan.execute_poc", return_value=[])):
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                target_binary=binary, official_qualification=qualification,
                external_turn_budget=ledger, candidate_budget_policy="QUEUE_FIRST_DEV",
                max_candidates=2, targeted_fuzz_seconds=0, global_fuzz_enabled=False,
                hallucination_prevent="off"))
        return json.loads((run / "scan.json").read_text()), provider, ledger, run

    def test_refuted_a_b_release_last_credit_for_c_verifier(self):
        with TemporaryDirectory() as temp:
            scan, provider, _run = self._run(Path(temp))
            ids = scan["queued_sp_ids"]
            self.assertEqual(len(ids), 3)
            self.assertEqual(provider.calls, ["sp_generation", "sp_verifier",
                                              "sp_verifier", "sp_verifier"])
            self.assertEqual(scan["selected_sp_ids"], ids)
            self.assertEqual(scan["sp_verification_status"][ids[-1]], "VERIFIER_EXECUTED")
            self.assertEqual(scan["sp_queue_status"][ids[-1]], "PENDING_POV_BUDGET")
            self.assertEqual(scan["pending_sp_ids"], [ids[-1]])
            self.assertEqual(scan["poc_count"], 0)
            self.assertEqual(scan["verified_crash_ids"], [])

    def test_ready_pov_takes_last_credit_before_next_verifier(self):
        with TemporaryDirectory() as temp:
            scan, provider, _run = self._run(
                Path(temp), count=2, sp_limit=3, verifier=_verifier(set()))
            ids = scan["queued_sp_ids"]
            self.assertEqual(provider.calls,
                             ["sp_generation", "sp_verifier", "poc_generator"])
            self.assertEqual(scan["selected_sp_ids"], [ids[0]])
            self.assertEqual(scan["sp_queue_status"][ids[1]], "PENDING_VERIFY_BUDGET")
            self.assertEqual(scan["poc_count"], 1)

    def test_context_request_spends_physical_credit_and_keeps_pending(self):
        with TemporaryDirectory() as temp:
            with patch("vulnerabilityanalysis.scan._resolve_verifier_context",
                       return_value=([{"source_file": "target.c",
                                       "source": "int A(void) { return 0; }"}], [])):
                scan, provider, _run = self._run(
                    Path(temp), count=2, sp_limit=3,
                    verifier=_verifier({0}, context_round_for=0))
            ids = scan["queued_sp_ids"]
            self.assertEqual(provider.calls,
                             ["sp_generation", "sp_verifier", "sp_verifier"])
            self.assertEqual(scan["sp_llm_calls"], len(provider.calls))
            self.assertEqual(scan["sp_queue_status"][ids[1]], "PENDING_VERIFY_BUDGET")

    def test_hp_possible_bug_keeps_origin_and_sp_candidates(self):
        with TemporaryDirectory() as temp:
            scan, provider, run = self._run(Path(temp), count=2, sp_limit=2,
                                            hp_limit=1, hp=True,
                                            verifier=_verifier({0, 1}))
            ids = scan["queued_sp_ids"]
            hp_ids = scan["hp_possible_bug_sp_ids"]
            self.assertEqual(len(ids), 3)
            self.assertEqual(len(hp_ids), 1)
            self.assertIn(hp_ids[0], ids)
            self.assertEqual(scan["sp_queue_origin_counts"]["SP"]["queued"], 2)
            self.assertEqual(scan["sp_queue_origin_counts"]["HP"]["queued"], 1)
            queue = json.loads((run / "sp/queue_first_dev.json").read_text())
            self.assertEqual(queue["status"], scan["sp_queue_status"])
            self.assertEqual(queue["pending_reason"], scan["sp_queue_pending_reason"])
            self.assertEqual(queue["scope"], "SP_QUEUE_ONLY")
            self.assertEqual(queue["candidate_origin"][hp_ids[0]],
                             "HP_ANALYSIS_POSSIBLE_BUG")
            self.assertEqual(queue["run_state"], "COMPLETED")
            self.assertEqual(set(queue["pending_verify_ids"]), set(scan["pending_sp_ids"]))
            self.assertIn("function_analysis", provider.calls)

    def test_equal_order_and_budget_show_only_queue_consumption(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            old, old_provider, _ = self._run(root / "old", policy="DRAIN_RANKED_DEV")
            new, new_provider, _ = self._run(root / "new")
            self.assertEqual(old["sp_llm_call_limit"], new["sp_llm_call_limit"])
            self.assertEqual(old["sp_count"], new["sp_count"])
            self.assertEqual(old_provider.calls,
                             ["sp_generation", "sp_verifier", "sp_verifier"])
            self.assertEqual(new_provider.calls,
                             ["sp_generation", "sp_verifier", "sp_verifier", "sp_verifier"])
            self.assertEqual(len(old["deduplicated_sp_ids"]), 0)
            self.assertEqual(len(new["duplicate_relation_ids"]), 0)

    def test_fresh_full_rank_prefix_matches_bounded_rank(self):
        from vulnerabilityanalysis.models import SuspiciousPoint

        points = [SuspiciousPoint(f"sp-{i}", "w", "d", "A", "target.c", "target.c:1",
                                  f"op {i}", f"hypothesis {i}", [], "input", [], [], [], [])
                  for i in range(5)]
        limited = CandidateScheduler.default().select_many(
            [SuspiciousPoint(**vars(point)) for point in points], 2)
        full = CandidateScheduler.default().select_many(
            [SuspiciousPoint(**vars(point)) for point in points], len(points))
        self.assertEqual([point.sp_id for point in limited],
                         [point.sp_id for point in full[:2]])

    def test_reanalyze_does_not_spin_or_claim_verified(self):
        with TemporaryDirectory() as temp:
            scan, provider, _run = self._run(
                Path(temp), count=2, sp_limit=3,
                verifier=_verifier({1}, reanalyze_for=0))
            ids = scan["queued_sp_ids"]
            self.assertEqual(provider.calls,
                             ["sp_generation", "sp_verifier", "sp_verifier"])
            self.assertEqual(scan["sp_queue_status"][ids[0]], "PENDING_NEW_EVIDENCE")
            self.assertEqual(scan["sp_queue_status"][ids[1]], "REFUTED")
            self.assertIn(ids[0], scan["pending_sp_ids"])
            self.assertEqual(scan["verified_crash_ids"], [])

    def test_duplicate_relation_is_recorded_without_deleting_candidate(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo, plan = fixture(root)
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = _Provider(2)
            def relation(points, **_kwargs):
                return [{"sp_id": points[1].sp_id,
                         "duplicate_of": points[0].sp_id,
                         "reason": "synthetic relation only"}]
            with (patch.object(CandidateScheduler, "select_many", _fixed_order),
                  patch.object(AgentPipeline, "verify_sp", _verifier({0, 1})),
                  patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations",
                        side_effect=relation)):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    candidate_budget_policy="QUEUE_FIRST_DEV", max_candidates=2,
                    sp_llm_call_limit=3, hp_llm_call_limit=1,
                    hallucination_prevent="off"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(len(scan["queued_sp_ids"]), 2)
            self.assertEqual(len(scan["selected_sp_ids"]), 2)
            self.assertEqual(scan["deduplicated_sp_ids"], [])
            self.assertEqual(scan["duplicate_relation_ids"], [scan["queued_sp_ids"][1]])

    def test_colliding_generator_ids_fail_closed_before_verifier(self):
        class CollisionProvider(_Provider):
            async def generate(self, request):
                result = await super().generate(request)
                if request.role == "sp_generation":
                    result["suspicious_points"][1]["vulnerability_hypothesis"] = (
                        result["suspicious_points"][0]["vulnerability_hypothesis"])
                return result

        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = CollisionProvider(2)
            with self.assertRaisesRegex(ValueError, "duplicate SP ID"):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    candidate_budget_policy="QUEUE_FIRST_DEV", max_candidates=2,
                    sp_llm_call_limit=4, hp_llm_call_limit=1,
                    hallucination_prevent="off"))
            self.assertEqual(provider.calls, ["sp_generation"])
            raw = json.loads((run / "sp/candidates.json").read_text())
            self.assertEqual(len(raw), 2)
            self.assertEqual(raw[0]["sp_id"], raw[1]["sp_id"])
            diagnostic = json.loads((run / "sp/queue_first_dev_id_collision.json").read_text())
            self.assertEqual(diagnostic["duplicate_sp_ids"], [raw[0]["sp_id"]])

    def test_default_policy_preserves_id_collision_before_per_id_file(self):
        class CollisionProvider(_Provider):
            async def generate(self, request):
                result = await super().generate(request)
                if request.role == "sp_generation":
                    result["suspicious_points"][1]["vulnerability_hypothesis"] = (
                        result["suspicious_points"][0]["vulnerability_hypothesis"])
                return result

        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = CollisionProvider(2)
            with self.assertRaisesRegex(ValueError, "duplicate SP ID"):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    candidate_budget_policy="PAIR_RESERVED", max_candidates=2,
                    sp_llm_call_limit=4, hp_llm_call_limit=1,
                    hallucination_prevent="off"))
            self.assertEqual(provider.calls, ["sp_generation"])
            raw = json.loads((run / "sp/candidates.json").read_text())
            self.assertEqual(len(raw), 2)
            self.assertEqual(raw[0]["sp_id"], raw[1]["sp_id"])
            diagnostic = json.loads((run / "sp/id_collision.json").read_text())
            self.assertEqual(diagnostic["duplicate_sp_ids"], [raw[0]["sp_id"]])
            self.assertFalse((run / "sp" / f"{raw[0]['sp_id']}.json").exists())

    def test_expired_local_deadline_starts_no_model_call(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = _Provider()
            with self.assertRaisesRegex(TimeoutError, "SCAN_WALL_TIME_EXCEEDED"):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    candidate_budget_policy="QUEUE_FIRST_DEV", max_candidates=2,
                    sp_llm_call_limit=4, hp_llm_call_limit=1,
                    scan_deadline_monotonic=time.monotonic() - 1,
                    hallucination_prevent="off"))
            self.assertEqual(provider.calls, [])

    def test_deadline_expiring_during_generation_starts_no_verifier(self):
        clock = [100.0]

        class ExpiringProvider(_Provider):
            async def generate(self, request):
                result = await super().generate(request)
                if request.role == "sp_generation":
                    clock[0] = 102.0
                return result

        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = ExpiringProvider(2)
            fake_time = SimpleNamespace(monotonic=lambda: clock[0],
                                        time=time.time, time_ns=time.time_ns)
            with (patch("vulnerabilityanalysis.scan.time", fake_time),
                  patch.object(CandidateScheduler, "select_many", _fixed_order),
                  patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations",
                        return_value=[])):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    candidate_budget_policy="QUEUE_FIRST_DEV", max_candidates=2,
                    sp_llm_call_limit=4, hp_llm_call_limit=1,
                    scan_deadline_monotonic=101.0,
                    hallucination_prevent="off"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(provider.calls, ["sp_generation"])
            self.assertEqual(set(scan["sp_queue_status"].values()),
                             {"PENDING_VERIFY_BUDGET"})
            self.assertEqual(set(scan["sp_queue_pending_reason"].values()),
                             {"SCAN_WALL_LIMIT"})

    def test_external_ledger_debits_physical_and_logical_before_next_work(self):
        with TemporaryDirectory() as temp:
            scan, provider, ledger, _run = self._external_run(Path(temp))
            ids = scan["queued_sp_ids"]
            self.assertEqual((ledger.logical, ledger.physical), (3, 3))
            self.assertEqual(provider.calls,
                             ["sp_generation", "sp_verifier", "poc_generator"])
            self.assertEqual(scan["sp_queue_status"][ids[1]], "PENDING_VERIFY_BUDGET")
            self.assertEqual(scan["global_physical_used"], 3)
            self.assertEqual(scan["verified_crash_ids"], [])

    def test_external_context_request_debits_two_physical_verifier_starts(self):
        with TemporaryDirectory() as temp:
            with patch("vulnerabilityanalysis.scan._resolve_verifier_context",
                       return_value=([{"source_file": "target.c",
                                       "source": "int A(void) { return 0; }"}], [])):
                scan, provider, ledger, _run = self._external_run(
                    Path(temp), verifier=_verifier({0}, context_round_for=0))
            self.assertEqual(provider.calls,
                             ["sp_generation", "sp_verifier", "sp_verifier"])
            self.assertEqual((ledger.logical, ledger.physical), (3, 3))
            self.assertEqual(scan["sp_llm_calls"], 3)
            self.assertEqual(len(scan["pending_sp_ids"]), 2)

    def test_fuzz_slice_uses_possible_pairs_not_full_pending_queue(self):
        with TemporaryDirectory() as temp:
            scan, _provider, run = self._run(
                Path(temp), count=20, sp_limit=3, targeted=5,
                verifier=_verifier(set()))
            budget = json.loads((run / "sp/turn_budget.json").read_text())
            self.assertEqual(budget["possible_pov_pairs"], 1)
            self.assertEqual(budget["targeted_fuzz_slice_seconds"], 5)
            self.assertEqual(scan["poc_count"], 1)
            self.assertLessEqual(scan["fuzz_seconds_allocated"], 5)

    def test_external_wall_exhaustion_keeps_every_candidate_pending(self):
        with TemporaryDirectory() as temp:
            scan, provider, ledger, run = self._external_run(
                Path(temp), expire_after_generation=True)
            self.assertEqual(provider.calls, ["sp_generation"])
            self.assertEqual(ledger.physical, 1)
            self.assertEqual(set(scan["pending_sp_ids"]), set(scan["queued_sp_ids"]))
            self.assertEqual(set(scan["sp_queue_status"].values()),
                             {"PENDING_VERIFY_BUDGET"})
            queue = json.loads((run / "sp/queue_first_dev.json").read_text())
            self.assertEqual(queue["status"], scan["sp_queue_status"])

    def test_partial_transport_marks_in_flight_and_never_autoresumes(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo, plan = fixture(root)
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            function_id = json.loads((run / "selection.json").read_text())["function_id"]
            binary = repo / "target.bin"
            binary.write_bytes(b"fixture only")
            qualification = _Qualification(repo, repo / "fuzz.c", binary)
            ledger = _Ledger(function_id, 3)
            provider = _GuardedProvider(ledger, function_id, fail_verifier=True)
            with (patch.object(CandidateScheduler, "select_many", _fixed_order),
                  patch.object(AgentPipeline, "verify_sp", _verifier(set())),
                  patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations",
                        return_value=[]),
                  patch("vulnerabilityanalysis.scan.OfficialPinnedQualification",
                        _Qualification),
                  patch("vulnerabilityanalysis.scan._official_pin_matches_qualification",
                        return_value=True)):
                with self.assertRaisesRegex(RuntimeError, "partial verifier transport"):
                    asyncio.run(scan_selected(
                        run, provider, target_repository=repo, target_binary=binary,
                        official_qualification=qualification, external_turn_budget=ledger,
                        candidate_budget_policy="QUEUE_FIRST_DEV", max_candidates=2,
                        hallucination_prevent="off"))
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))
            self.assertFalse((run / "scan.json").exists())
            queue = json.loads((run / "sp/queue_first_dev.json").read_text())
            self.assertEqual(queue["run_state"], "INCOMPLETE")
            self.assertIn("IN_FLIGHT_VERIFY", queue["status"].values())
            self.assertFalse(queue["auto_resume"])

    def test_queue_resume_rejected_before_any_model_call(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = _Provider()
            with self.assertRaisesRegex(ValueError, "cannot resume"):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                    candidate_budget_policy="QUEUE_FIRST_DEV", resume_from=repo,
                    hallucination_prevent="off"))
            self.assertEqual(provider.calls, [])
