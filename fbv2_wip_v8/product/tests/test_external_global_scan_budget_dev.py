"""The one-function development Scan may use a guarded global request ledger."""
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
from vulnerabilityanalysis.direction_plan import DEV_FIRST_PASS_POLICY
from vulnerabilityanalysis.models import FunctionAnalysis, VerificationResult
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import run_phase1

from test_direction_plan import fixture
from test_sp_queue_drain_dev import _ScriptedProvider


class _GlobalLedger:
    """Provider-free stand-in that debits each logical and physical send."""

    def __init__(self, function_id: str, maximum: int):
        self.budget = SimpleNamespace(profile="GLOBAL_ONLY_DEV", logical_max=maximum,
                                      physical_max=maximum, wall_seconds=60)
        self.logical = 0
        self.physical = 0
        self.started_at = time.time()
        self.selected_functions = [function_id]
        self.active_turn = None
        self.tainted = False
        self.roles: list[str] = []

    def debit(self, role: str) -> None:
        if self.logical >= self.budget.logical_max or self.physical >= self.budget.physical_max:
            raise AssertionError("product sent after the global ledger was exhausted")
        self.logical += 1
        self.physical += 1
        self.roles.append(role)


class _GuardedProvider(_ScriptedProvider):
    def __init__(self, ledger: _GlobalLedger, function_id: str, *, candidates: int = 5):
        super().__init__(candidate_count=candidates)
        self.ledger = ledger
        self.scope_id = function_id
        class Backend:
            def __init__(self):
                self.ledger, self.scope_id = ledger, function_id

            async def _request(self, *_args, **_kwargs):
                raise AssertionError("provider-free test must not use App Server")

        self.backend = Backend()

    async def generate(self, request):
        self.ledger.debit(request.role)
        if request.role in {"function_analysis", "sp_verifier"}:
            return {}
        if request.role == "assertion_generator":
            return {}
        return await super().generate(request)


class _Qualification:
    product_issued = True

    def __init__(self, source_root: Path, harness: Path, binary: Path):
        self.source_root = source_root.resolve()
        self.harness = harness.resolve()
        self.binary = binary.resolve()


async def _refute_with_guarded_call(self, point, *_args, **_kwargs):
    await self.provider.generate(SimpleNamespace(role="sp_verifier"))
    self.last_request_count = 1
    point.status = "REFUTED"
    point.status_history.append("REFUTED")
    self.verifications[point.sp_id] = VerificationResult(
        point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
        "REFUTED", "REFUTE", "provider-free budget test")
    return point


async def _refute_without_call(self, point, *_args, **_kwargs):
    self.last_request_count = 1
    point.status = "REFUTED"
    point.status_history.append("REFUTED")
    self.verifications[point.sp_id] = VerificationResult(
        point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
        "REFUTED", "REFUTE", "default policy parity test")
    return point


async def _safe_with_guarded_call(self, function_id, function_name, source_file,
                                  *_args, **_kwargs):
    await self.provider.generate(SimpleNamespace(role="function_analysis"))
    self.last_request_count = 1
    return FunctionAnalysis(function_id, function_name, source_file,
                            "safe assumption for budget test", "input", [], [],
                            ["value <= 10"], [])


async def _no_safe_with_guarded_call(self, function_id, function_name, source_file,
                                     *_args, **_kwargs):
    await self.provider.generate(SimpleNamespace(role="function_analysis"))
    self.last_request_count = 1
    return FunctionAnalysis(function_id, function_name, source_file,
                            "no supported safe assumption", "input", [], [], [], [])


async def _assertion_with_guarded_call(self, *_args, **_kwargs):
    await self.provider.generate(SimpleNamespace(role="assertion_generator"))
    self.last_request_count = 1
    return []


class ExternalGlobalScanBudgetDevTests(unittest.TestCase):
    def test_default_and_explicit_none_keep_frozen_local_policy(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _plan = fixture(Path(temp))
            scans = []
            with patch.object(AgentPipeline, "verify_sp", _refute_without_call):
                for explicit_none in (False, True):
                    run = run_phase1(artifact, repo / "runs", target_repository=repo)
                    kwargs = ({"external_turn_budget": None} if explicit_none else {})
                    asyncio.run(scan_selected(
                        run, _ScriptedProvider(), target_repository=repo,
                        hallucination_prevent="off", sp_llm_call_limit=4,
                        hp_llm_call_limit=4, max_candidates=2, **kwargs))
                    scans.append(json.loads((run / "scan.json").read_text()))
            stable = ("sp_llm_call_limit", "hp_llm_call_limit",
                      "combined_llm_call_limit", "candidate_budget_policy",
                      "selected_sp_ids", "pending_sp_ids", "sp_verification_status")
            self.assertEqual({key: scans[0][key] for key in stable},
                             {key: scans[1][key] for key in stable})
            self.assertEqual((scans[0]["sp_llm_call_limit"],
                              scans[0]["hp_llm_call_limit"],
                              scans[0]["combined_llm_call_limit"]), (4, 4, 8))

    def _run(self, root: Path):
        artifact, repo, plan = fixture(root)
        run = run_phase1(artifact, repo / "runs", target_repository=repo,
                         direction_plan=plan, selection_policy=DEV_FIRST_PASS_POLICY)
        function_id = json.loads((run / "selection.json").read_text())["function_id"]
        binary = repo / "target.bin"
        binary.write_bytes(b"fixture")
        qualification = _Qualification(repo, repo / "fuzz.c", binary)
        return run, repo, function_id, binary, qualification

    def _scan(self, run, repo, binary, qualification, provider, ledger, **kwargs):
        with (patch("vulnerabilityanalysis.scan.OfficialPinnedQualification", _Qualification),
              patch("vulnerabilityanalysis.scan._official_pin_matches_qualification",
                    return_value=True),
              patch("vulnerabilityanalysis.scan.ranked_sp_dedup_relations", return_value=[])):
            return asyncio.run(scan_selected(
                run, provider, target_repository=repo, target_binary=binary,
                official_qualification=qualification, external_turn_budget=ledger,
                candidate_budget_policy="DRAIN_RANKED_DEV", max_candidates=1,
                targeted_fuzz_seconds=0, global_fuzz_enabled=False, **kwargs))

    def test_fifth_sp_call_uses_global_credit_without_local_eight_call_cap(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 12)
            provider = _GuardedProvider(ledger, function_id)
            with patch.object(AgentPipeline, "verify_sp", _refute_with_guarded_call):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="off")
            result = json.loads((run / "scan.json").read_text())
            self.assertGreaterEqual(result["sp_llm_calls"], 5)
            self.assertEqual(ledger.physical, result["sp_llm_calls"])
            self.assertEqual(result["hp_llm_calls"], 0)

    def test_safe_gets_assertion_call_then_sp_queue_waits_at_global_cap(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 3)
            provider = _GuardedProvider(ledger, function_id, candidates=2)
            with (patch.object(AgentPipeline, "analyze_function", _safe_with_guarded_call),
                  patch.object(AgentPipeline, "generate_assertions", _assertion_with_guarded_call)):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="on", hp_context_round_limit=0)
            result = json.loads((run / "scan.json").read_text())
            self.assertEqual(ledger.roles, ["sp_generation", "function_analysis",
                                            "assertion_generator"])
            self.assertEqual(result["assertion_generation_status"], "COMPLETED")
            self.assertTrue(result["pending_sp_ids"])
            self.assertIsNone(result["hp_error"])

    def test_no_safe_releases_last_credit_to_sp_verifier(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 3)
            provider = _GuardedProvider(ledger, function_id, candidates=2)
            with (patch.object(AgentPipeline, "analyze_function", _no_safe_with_guarded_call),
                  patch.object(AgentPipeline, "verify_sp", _refute_with_guarded_call)):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="on", hp_context_round_limit=0)
            result = json.loads((run / "scan.json").read_text())
            self.assertEqual(ledger.roles, ["sp_generation", "function_analysis",
                                            "sp_verifier"])
            self.assertEqual(result["assertion_generation_status"], "NO_SAFE")
            self.assertEqual(len(result["selected_sp_ids"]), 1)
            self.assertEqual(result["global_logical_used"], 3)

    def test_exhausted_credit_is_pending_not_hp_error(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 1)
            provider = _GuardedProvider(ledger, function_id, candidates=2)
            self._scan(run, repo, binary, qualification, provider, ledger,
                       hallucination_prevent="on", hp_context_round_limit=0)
            result = json.loads((run / "scan.json").read_text())
            self.assertEqual(ledger.roles, ["sp_generation"])
            self.assertEqual(result["assertion_generation_status"], "PENDING_HP_BUDGET")
            self.assertIsNone(result["hp_error"])
            self.assertTrue(result["pending_sp_ids"])

    def test_last_credit_verifies_candidate_when_hp_needs_two(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 2)
            provider = _GuardedProvider(ledger, function_id, candidates=2)
            with patch.object(AgentPipeline, "verify_sp", _refute_with_guarded_call):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="on", hp_context_round_limit=0)
            result = json.loads((run / "scan.json").read_text())
            self.assertEqual(ledger.roles, ["sp_generation", "sp_verifier"])
            self.assertEqual(result["assertion_generation_status"], "PENDING_HP_BUDGET")
            self.assertEqual(len(result["selected_sp_ids"]), 1)
            self.assertEqual(result["global_logical_used"], 2)

    def test_refuted_candidates_reuse_unspent_pov_credit_for_verification(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 4)
            provider = _GuardedProvider(ledger, function_id, candidates=5)
            with patch.object(AgentPipeline, "verify_sp", _refute_with_guarded_call):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="off")
            result = json.loads((run / "scan.json").read_text())
            self.assertEqual(ledger.roles, ["sp_generation", "sp_verifier",
                                            "sp_verifier", "sp_verifier"])
            self.assertEqual(len(result["selected_sp_ids"]), 3)
            self.assertEqual(len(result["queued_sp_ids"]), 5)
            self.assertEqual(len(result["pending_sp_ids"]), 2)
            self.assertEqual(result["global_logical_used"], 4)

    def test_physical_retry_exhaustion_keeps_verified_point_pending_pov(self):
        async def plausible_after_retry(self, point, *_args, **_kwargs):
            await self.provider.generate(SimpleNamespace(role="sp_verifier"))
            self.provider.ledger.physical += 1  # One physical retry of that logical turn.
            self.last_request_count = 1
            point.status = "POC_PENDING"
            point.status_history.append("POC_PENDING")
            self.verifications[point.sp_id] = VerificationResult(
                point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
                "PLAUSIBLE", "GENERATE_POC", "retry used the last physical credit")
            return point

        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 3)
            provider = _GuardedProvider(ledger, function_id, candidates=2)
            with patch.object(AgentPipeline, "verify_sp", plausible_after_retry):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="off")
            result = json.loads((run / "scan.json").read_text())
            self.assertEqual((ledger.logical, ledger.physical), (2, 3))
            self.assertEqual(result["poc_count"], 0)
            self.assertEqual(len(result["selected_sp_ids"]), 1)
            self.assertIn(result["selected_sp_ids"][0], result["pending_sp_ids"])
            self.assertIn("BLOCKED_LLM_BUDGET",
                          [row["decision"] for row in result["poc_decisions"]])

    def test_typed_provider_budget_stop_is_not_normalized_as_hp_error(self):
        class BudgetStop(BaseException):
            pass

        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 3)
            provider = _GuardedProvider(ledger, function_id, candidates=2)
            original_generate = provider.generate

            async def stop_at_hp(request):
                if request.role == "function_analysis":
                    raise BudgetStop("global budget rejected before wire")
                return await original_generate(request)

            provider.generate = stop_at_hp
            with self.assertRaises(BudgetStop):
                self._scan(run, repo, binary, qualification, provider, ledger,
                           hallucination_prevent="on", hp_context_round_limit=0)
            self.assertTrue((run / "sp" / "candidates.json").is_file())
            self.assertFalse((run / "hp_error.json").exists())
            self.assertFalse((run / "scan.json").exists())

    def test_unqualified_or_unguarded_provider_rejected_before_send(self):
        with TemporaryDirectory() as temp:
            run, repo, function_id, binary, qualification = self._run(Path(temp))
            ledger = _GlobalLedger(function_id, 12)
            provider = _GuardedProvider(ledger, function_id)
            with self.assertRaises(ValueError):
                self._scan(run, repo, binary, qualification, _ScriptedProvider(), ledger,
                           hallucination_prevent="off")
            self.assertEqual(ledger.physical, 0)
            with self.assertRaises(ValueError):
                self._scan(run, repo, binary, None, provider, ledger,
                           hallucination_prevent="off")
            self.assertEqual(ledger.physical, 0)


if __name__ == "__main__":
    unittest.main()
