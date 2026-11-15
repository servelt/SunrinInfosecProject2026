"""Provider-free checks for the opt-in HP Context budget experiment."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from test_direction_plan import fixture
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import run_phase1


SAFE_SENTINEL = "synthetic safe judgment for budget control only"


class RoundProvider:
    """Return a fourth-round SAFE claim without claiming it is source-proven."""

    def __init__(self, *, safe_on_fourth: bool = True):
        self.safe_on_fourth = safe_on_fourth
        self.roles: list[str] = []
        self.analysis_payloads: list[dict] = []

    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "sp_generation":
            return {"suspicious_points": []}
        if request.role == "function_analysis":
            self.analysis_payloads.append(request.payload)
            number = len(self.analysis_payloads)
            names = {1: ["B", "C", "E"], 2: ["D"], 3: ["E"]}.get(number, [])
            safe = number == 4 and self.safe_on_fourth
            return {
                "summary": "synthetic context budget test", "input_flow": "UNKNOWN",
                "state_dependencies": [], "context_requests": [{
                    "target": name, "request_type": "FUNCTION",
                    "reason": "inspect a named helper", "expected_information": "body",
                    "hypothesis_index": 0,
                } for name in names],
                "safe_assumptions": [SAFE_SENTINEL] if safe else [],
                "unknowns": [] if safe else ["synthetic uncertainty"],
                "input_sources": [], "security_sensitive_operations": [],
                "validations": [], "memory_operations": [], "evidence": [],
                "safe_assumption_lifecycle": [],
                "hypothesis_evaluations": ([{
                    "source_location": "", "security_property": "synthetic control",
                    "hypothesis": "synthetic budget branch", "judgment": "EXPLICIT_SAFE_JUDGMENT",
                    "reason": "mock control flow, not a safety finding",
                    "safe_assumption": SAFE_SENTINEL, "source_file": "",
                    "source_line": 0, "source_quote": "", "input_influence": "UNKNOWN",
                }] if safe else [{
                    "source_location": "target.c:1", "source_file": "target.c",
                    "source_line": 1, "source_quote": "fixture source",
                    "security_property": "synthetic context budget",
                    "hypothesis": "the requested helper may affect this round",
                    "judgment": "UNKNOWN", "reason": "context is required",
                    "safe_assumption": "", "input_influence": "UNKNOWN",
                }]),
            }
        if request.role == "assertion_generator":
            return {"assertions": [], "dispositions": [{
                "safe_id": 0, "safe_assumption": SAFE_SENTINEL,
                "status": "OTHER", "reason": "synthetic claim is not instrumentable",
            }]}
        raise AssertionError(request.role)


def dev_run(root: Path) -> tuple[Path, Path]:
    artifact, repo, plan = fixture(root)
    with (repo / "target.c").open("a", encoding="utf-8") as stream:
        for name in "BCDE":
            stream.write(f"int {name}(void) {{ return {ord(name)}; }}\n")
    run = run_phase1(artifact, repo / "runs", target_repository=repo,
                     direction_plan=plan,
                     selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
    return run, repo


class HPContextRoundLimitDevTests(unittest.TestCase):
    def _scan(self, run: Path, repo: Path, provider: RoundProvider, **options) -> dict:
        asyncio.run(scan_selected(run, provider, target_repository=repo,
                                  hallucination_prevent="on", **options))
        return json.loads((run / "scan.json").read_text(encoding="utf-8"))

    def test_default_retains_two_rounds_and_two_requests_per_turn(self):
        with TemporaryDirectory() as temp:
            run, repo = dev_run(Path(temp))
            provider = RoundProvider()
            scan = self._scan(run, repo, provider, hp_llm_call_limit=4,
                              sp_llm_call_limit=4)
            records = json.loads((run / "hp_context_requests.json").read_text())
            self.assertEqual(len(provider.analysis_payloads), 3)
            self.assertEqual(scan["hp_llm_calls"], 3)
            self.assertEqual(scan["safe_assumption_count"], 0)
            self.assertEqual(scan["assertion_generation_status"], "NO_SAFE")
            self.assertNotIn("hp_context_round_limit", scan)
            self.assertTrue(any(row["target"] == "E" and
                                row["status"] == "SKIPPED_PER_TURN_LIMIT"
                                for row in records))
            self.assertTrue(any(row["target"] == "E" and
                                row["status"] == "SKIPPED_CONTEXT_ROUND_LIMIT"
                                for row in records))

    def test_hp5_sp3_uses_third_context_then_reserved_assertion_call(self):
        with TemporaryDirectory() as temp:
            run, repo = dev_run(Path(temp))
            provider = RoundProvider()
            scan = self._scan(run, repo, provider, hp_context_round_limit=3,
                              hp_llm_call_limit=5, sp_llm_call_limit=3)
            records = json.loads((run / "hp_context_requests.json").read_text())
            self.assertEqual(len(provider.analysis_payloads), 4)
            self.assertTrue(any(row["round"] == 3 and row["target"] == "E" and
                                row["status"] == "FETCHED" and
                                row["delivered_to_analysis"] for row in records))
            self.assertIn("int E(void)", json.dumps(
                provider.analysis_payloads[-1]["context"]))
            self.assertEqual(provider.roles.count("assertion_generator"), 1)
            self.assertEqual(scan["hp_llm_calls"], 5)
            self.assertEqual(scan["hp_llm_call_limit"], 5)
            self.assertEqual(scan["sp_llm_call_limit"], 3)
            self.assertEqual(scan["combined_llm_call_limit"], 8)
            self.assertEqual(scan["hp_context_requests_per_turn_limit"], 2)
            self.assertEqual(scan["assertion_count"], 0)

    def test_hp4_sp4_records_pending_if_safe_arrives_in_final_context_round(self):
        with TemporaryDirectory() as temp:
            run, repo = dev_run(Path(temp))
            provider = RoundProvider()
            scan = self._scan(run, repo, provider, hp_context_round_limit=3,
                              hp_llm_call_limit=4, sp_llm_call_limit=4)
            self.assertEqual(len(provider.analysis_payloads), 4)
            self.assertNotIn("assertion_generator", provider.roles)
            self.assertEqual(scan["hp_llm_calls"], 4)
            self.assertEqual(scan["combined_llm_call_limit"], 8)
            self.assertEqual(scan["assertion_generation_status"], "PENDING_HP_BUDGET")
            self.assertEqual(scan["assertion_execution"]["status"], "PENDING_HP_BUDGET")
            self.assertEqual(json.loads((run / "assertions/pending_generation.json").read_text())
                             ["reason"], "HP_CALL_LIMIT")

    def test_no_safe_keeps_unknown_and_reallocates_only_unused_call(self):
        with TemporaryDirectory() as temp:
            run, repo = dev_run(Path(temp))
            provider = RoundProvider(safe_on_fourth=False)
            scan = self._scan(run, repo, provider, hp_context_round_limit=3,
                              hp_llm_call_limit=5, sp_llm_call_limit=3)
            self.assertEqual(len(provider.analysis_payloads), 4)
            self.assertNotIn("assertion_generator", provider.roles)
            self.assertEqual(scan["safe_assumption_count"], 0)
            self.assertEqual(scan["assertion_generation_status"], "NO_SAFE")
            self.assertEqual(scan["hp_llm_calls"], 4)
            self.assertEqual(scan["effective_sp_llm_call_limit"], 4)
            self.assertEqual(scan["transferred_hp_llm_calls"], 1)

    def test_override_rejects_non_dev_run_and_invalid_numbers_before_provider(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo, plan = fixture(root)
            score_run = run_phase1(artifact, repo / "runs", target_repository=repo,
                                   direction_plan=plan)
            provider = RoundProvider()
            with self.assertRaisesRegex(ValueError, "development"):
                self._scan(score_run, repo, provider, hp_context_round_limit=3)
            self.assertEqual(provider.roles, [])
        for bad in (True, "3", -1, 8):
            with self.subTest(bad=bad), TemporaryDirectory() as temp:
                run, repo = dev_run(Path(temp))
                provider = RoundProvider()
                with self.assertRaisesRegex(ValueError, "HP Context round limit"):
                    self._scan(run, repo, provider, hp_context_round_limit=bad)
                self.assertEqual(provider.roles, [])
        for limits in ({"hp_llm_call_limit": 5},
                       {"hp_llm_call_limit": 5, "sp_llm_call_limit": 4}):
            with self.subTest(limits=limits), TemporaryDirectory() as temp:
                run, repo = dev_run(Path(temp))
                provider = RoundProvider()
                with self.assertRaisesRegex(ValueError, "explicit SP/HP limits"):
                    self._scan(run, repo, provider, hp_context_round_limit=3, **limits)
                self.assertEqual(provider.roles, [])


if __name__ == "__main__":
    unittest.main()
