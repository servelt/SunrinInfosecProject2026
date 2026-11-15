"""Provider-free Stage 14 HP Context and Assertion role-chain checks.

The official md4c V2 Phase 1 fixture is development data. Scripted replies
exercise accounting and evidence lineage only; they are not model findings.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / "src"), str(Path(__file__).resolve().parent)]

from dev_global_appserver_bridge import DevelopmentGlobalAppServer  # noqa: E402
import test_dev_blind3_official_interleaved_adapter as stage13_fixture  # noqa: E402
from test_dev_global_appserver_bridge import FakeWireServer  # noqa: E402
from test_dev_interleaved_crossrole_stage import (  # noqa: E402
    _RoleWire, _wire_sp_response,
)
import vulnerabilityanalysis.interleaved_dev as base  # noqa: E402
from vulnerabilityanalysis.source import SourceRepository  # noqa: E402
from vulnerabilityanalysis.interleaved_roles_dev import (  # noqa: E402
    _dir, _stage14_assertion_rows, run_assertion_generation_stage,
    run_hp_context_stage, run_hp_first_stage, run_hp_followup_stage,
)
from vulnerabilityanalysis.models import Assertion  # noqa: E402
import test_dev_interleaved_sp_stage as sp_fixture  # noqa: E402
import test_dev_interleaved_crossrole_stage as stage12_fixture  # noqa: E402


def _analysis(item: dict, span, *, request: bool, safe: bool) -> dict:
    claim = "Scripted input relation for provider-free role wiring"
    return {
        "summary": "scripted development response",
        "input_flow": "synthetic response only",
        "state_dependencies": [],
        "context_requests": ([{
            "target": "MD_HTML", "request_type": "TYPE",
            "reason": "inspect type in official source",
            "expected_information": "struct body"}] if request else []),
        "safe_assumptions": [claim] if safe else [],
        "unknowns": [], "input_sources": [],
        "security_sensitive_operations": [], "validations": [],
        "memory_operations": [], "evidence": [],
        "hypothesis_evaluations": ([{
            "source_location": f"{item['source_file']}:{span.start_line}",
            "security_property": "synthetic provider-free wiring",
            "source_file": item["source_file"],
            "source_line": span.start_line,
            "source_quote": span.source.splitlines()[0],
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": claim,
            "judgment": "EXPLICIT_SAFE_JUDGMENT",
            "reason": "scripted role-chain test only",
            "safe_assumption": claim}] if safe else []),
    }


class OfficialHPVerticalStage14Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = stage13_fixture.OfficialInterleavedAdapterTests(
            "test_product_issued_v2_prepare_read_no_model_or_target")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.adapter = fixture._adapter_after_prepare()
        self.state = self.adapter.read()
        self.item = self.state["work_items"][0]
        harness = base._pinned_harness(
            self.state, Path(self.state["source_run"]),
            self.adapter.qualification.source_root)
        self.repository = SourceRepository(
            self.adapter.qualification.source_root, harness.function_catalog)
        self.span = self.repository.open_function_span(self.item["function_id"])
        self.adapter.backend.sent = []

    def _wire(self, collect=None) -> ExitStack:
        stack = ExitStack()
        for name, method in (
            ("start", FakeWireServer.start),
            ("_thread_for", FakeWireServer._thread_for),
            ("_delete_ephemeral_thread", FakeWireServer._delete_ephemeral_thread),
            ("_transport_request", FakeWireServer._transport_request),
            ("_collect", collect or _RoleWire._collect),
        ):
            stack.enter_context(patch.object(DevelopmentGlobalAppServer,
                                             name, method))
        return stack

    def test_official_context_followup_assertion_one_ledger_no_target(self) -> None:
        siblings = [row for row in self.state["work_items"]
                    if row["function_id"] == self.item["function_id"] and
                    row["direction_id"] != self.item["direction_id"]]
        if siblings:
            self.assertNotEqual(_dir(self.adapter.state_path, self.item),
                                _dir(self.adapter.state_path, siblings[0]))
        claim = "Scripted input relation for provider-free role wiring"
        self.adapter.backend.responses = [
            _wire_sp_response(self.repository, self.item, 1),
            _analysis(self.item, self.span, request=True, safe=False),
            _analysis(self.item, self.span, request=False, safe=True),
            {"assertions": [{"safe_id": 0, "safe_assumption": claim,
                "runtime_expression": "size > 0", "source_line": self.span.start_line + 4,
                "required_context": [], "rationale": "scripted provider-free test"}],
             "dispositions": [{"safe_id": 0, "safe_assumption": claim,
                "status": "PROPOSED", "reason": "scripted provider-free test"}]},
        ]

        async def sequence() -> None:
            await self.adapter.sp(0)
            await self.adapter.hp(0)
            resolved = await self.adapter.hp_context(0)
            self.assertGreater(json.loads(resolved.read_text())["fresh_count"], 0)
            await self.adapter.hp_followup(0)
            await self.adapter.assertions(0)

        with self._wire():
            asyncio.run(sequence())
        saved = self.adapter.read()
        self.assertEqual(saved["work_items"][0]["hp_state"],
                         "PENDING_ASSERTION_EXECUTION")
        self.assertEqual([row["role"] for row in saved["role_turns"]],
                         ["function_analysis", "function_analysis",
                          "assertion_generator"])
        self.assertEqual((self.adapter.ledger.logical,
                          self.adapter.ledger.physical), (4, 4))
        self.assertEqual([row["physical"] for row in self.adapter.backend.sent],
                         [1, 2, 3, 4])
        self.assertEqual(saved["scan_count"], 0)
        self.assertFalse((self.adapter.state_path.parent / "scan.json").exists())
        assertion_receipt = saved["role_turns"][-1]
        artifact = Path(assertion_receipt["artifact_path"])
        changed = json.loads(artifact.read_text())
        changed["dispositions"][0]["status"] = "NOT_INPUT_DEPENDENT"
        artifact.write_text(json.dumps(changed, sort_keys=True) + "\n")
        raw_state = json.loads(self.adapter.state_path.read_text())
        raw_state["role_turns"][-1]["artifact_sha256"] = hashlib.sha256(
            artifact.read_bytes()).hexdigest()
        self.adapter.state_path.write_text(json.dumps(raw_state, sort_keys=True) + "\n")
        with self.assertRaises(ValueError):
            base.read_interleaved_dev(self.adapter.state_path)

    def test_no_safe_is_local_disposition_without_assertion_turn(self) -> None:
        self.adapter.backend.responses = [
            _wire_sp_response(self.repository, self.item, 1),
            _analysis(self.item, self.span, request=False, safe=False),
        ]

        async def sequence() -> None:
            await self.adapter.sp(0)
            await self.adapter.hp(0)
            await self.adapter.assertions(0)

        with self._wire():
            asyncio.run(sequence())
        saved = self.adapter.read()
        self.assertEqual(saved["work_items"][0]["hp_state"], "NO_SAFE")
        self.assertEqual((self.adapter.ledger.logical,
                          self.adapter.ledger.physical), (2, 2))
        self.assertEqual(len(self.adapter.backend.sent), 2)
        self.assertEqual(len(saved["role_turns"]), 1)

    def test_cancelled_hp_followup_keeps_debit_and_blocks_next_role(self) -> None:
        self.adapter.backend.responses = [
            _wire_sp_response(self.repository, self.item, 1),
            _analysis(self.item, self.span, request=True, safe=False),
        ]

        async def cancel_followup(backend, thread_id, turn_id):
            if len(backend.sent) == 3:
                raise asyncio.CancelledError("scripted HP followup interruption")
            return await _RoleWire._collect(backend, thread_id, turn_id)

        async def sequence() -> None:
            await self.adapter.sp(0)
            await self.adapter.hp(0)
            await self.adapter.hp_context(0)
            with self.assertRaises(asyncio.CancelledError):
                await self.adapter.hp_followup(0)

        with self._wire(cancel_followup):
            asyncio.run(sequence())
        saved = self.adapter.read()
        self.assertEqual(saved["role_active"]["state"],
                         "INCOMPLETE_ROLE_TURN")
        self.assertEqual(saved["role_active"]["hp_round"], 1)
        self.assertEqual((self.adapter.ledger.logical,
                          self.adapter.ledger.physical), (3, 3))
        with self.assertRaises(ValueError):
            asyncio.run(self.adapter.assertions(0))
        self.assertEqual(len(self.adapter.backend.sent), 3)

    def test_completed_malformed_hp_response_keeps_debit(self) -> None:
        self.adapter.backend.responses = [
            _wire_sp_response(self.repository, self.item, 1),
        ]

        async def malformed_hp(backend, thread_id, turn_id):
            if len(backend.sent) == 2:
                backend._record_server_event({"method": "turn/completed",
                    "params": {"threadId": thread_id,
                               "turn": {"id": turn_id, "status": "completed",
                                        "items": []}}})
                backend._server_terminal_status = "completed"
                return '{"summary":'
            return await _RoleWire._collect(backend, thread_id, turn_id)

        async def sequence() -> None:
            await self.adapter.sp(0)
            with self.assertRaises(json.JSONDecodeError):
                await self.adapter.hp(0)

        with self._wire(malformed_hp):
            asyncio.run(sequence())
        saved = self.adapter.read()
        self.assertEqual(saved["role_active"]["state"],
                         "INCOMPLETE_ROLE_TURN")
        self.assertEqual((self.adapter.ledger.logical,
                          self.adapter.ledger.physical), (2, 2))
        self.assertEqual(len(self.adapter.backend.sent), 2)
        with self.assertRaises(ValueError):
            asyncio.run(self.adapter.assertions(0))


class AssertionDispositionStage14Tests(unittest.TestCase):
    def _row(self, *, safe: str = "canonical SAFE", identifier: str = "a") -> Assertion:
        return Assertion(identifier, "worker", "direction", "F", "x.c:3",
                         safe, "size > 0", [], status="PROPOSED")

    def test_valid_safe_id_accepts_model_rephrasing(self) -> None:
        response = {"assertions": [{"safe_id": 0,
                     "safe_assumption": "model rephrased text",
                     "runtime_expression": "size > 0", "source_line": 3}]}
        dispositions = [{"safe_id": 0, "safe_assumption": "canonical SAFE",
                         "status": "PROPOSED"}]
        rows = _stage14_assertion_rows(
            [self._row()], dispositions, [], response, ["canonical SAFE"],
            Path("/tmp/provider-free-analysis.json"))
        self.assertEqual(rows[0]["status"], "PROPOSED")

    def test_missing_disposition_blocks_proposal(self) -> None:
        response = {"assertions": [{"safe_id": 0,
                     "safe_assumption": "canonical SAFE",
                     "runtime_expression": "size > 0", "source_line": 3}]}
        rows = _stage14_assertion_rows(
            [self._row()], [], [], response, ["canonical SAFE"],
            Path("/tmp/provider-free-analysis.json"))
        self.assertEqual(rows[0]["status"], "INVALID_ASSERTION")

    def test_non_input_dependent_safe_cannot_reach_execution(self) -> None:
        response = {"assertions": [{"safe_id": 0,
                     "safe_assumption": "canonical SAFE",
                     "runtime_expression": "size > 0", "source_line": 3}]}
        dispositions = [{"safe_id": 0, "safe_assumption": "canonical SAFE",
                         "status": "PROPOSED"}]
        rows = _stage14_assertion_rows(
            [self._row()], dispositions, [], response, ["canonical SAFE"],
            Path("/tmp/provider-free-analysis.json"), set())
        self.assertEqual(rows[0]["status"], "INVALID_ASSERTION")

    def test_duplicate_assertion_id_blocks_both_proposals(self) -> None:
        response = {"assertions": [{"safe_id": index,
                     "safe_assumption": "canonical SAFE",
                     "runtime_expression": "size > 0", "source_line": 3}
                     for index in range(2)]}
        dispositions = [{"safe_id": index,
                         "safe_assumption": "canonical SAFE", "status": "PROPOSED"}
                        for index in range(2)]
        rows = _stage14_assertion_rows(
            [self._row(), self._row()], dispositions, [], response,
            ["canonical SAFE", "canonical SAFE"],
            Path("/tmp/provider-free-analysis.json"))
        self.assertEqual([row["status"] for row in rows],
                         ["INVALID_ASSERTION", "INVALID_ASSERTION"])


class HPBudgetStage14Tests(unittest.TestCase):
    def test_safe_with_no_model_credit_stays_pending_without_send(self) -> None:
        with TemporaryDirectory(prefix="stage14-budget-") as temp:
            repository, path, ledger = sp_fixture.InterleavedSPStageTests().fixture(
                Path(temp), credits=3)
            item = base.read_interleaved_dev(path)["work_items"][0]
            asyncio.run(base.generate_sp_stage(
                path, 0, sp_fixture._Provider(ledger, item["work_item_id"], 1),
                ledger, target_repository=repository))
            harness = base._pinned_harness(
                base.read_interleaved_dev(path),
                Path(base.read_interleaved_dev(path)["source_run"]), repository)
            span = SourceRepository(repository,
                                    harness.function_catalog).open_function_span(
                                        item["function_id"])
            hp = stage12_fixture._RoleProvider(
                ledger, item["work_item_id"], "function_analysis",
                _analysis(item, span, request=False, safe=True))
            asyncio.run(run_hp_first_stage(
                path, 0, hp, ledger, target_repository=repository))
            assertion_provider = stage12_fixture._RoleProvider(
                ledger, item["work_item_id"], "assertion_generator", {})
            artifact = asyncio.run(run_assertion_generation_stage(
                path, 0, assertion_provider, ledger,
                target_repository=repository))
            saved = base.read_interleaved_dev(path)
            self.assertEqual(saved["work_items"][0]["hp_state"],
                             "PENDING_HP_BUDGET")
            self.assertEqual(json.loads(artifact.read_text())["status"],
                             "PENDING_HP_BUDGET")
            self.assertEqual(assertion_provider.calls, [])
            self.assertEqual((ledger.logical, ledger.physical), (3, 3))

    def test_followup_budget_receipt_is_round_scoped(self) -> None:
        with TemporaryDirectory(prefix="stage14-round-budget-") as temp:
            repository, path, ledger = sp_fixture.InterleavedSPStageTests().fixture(
                Path(temp), credits=3)
            item = base.read_interleaved_dev(path)["work_items"][0]
            asyncio.run(base.generate_sp_stage(
                path, 0, sp_fixture._Provider(ledger, item["work_item_id"], 1),
                ledger, target_repository=repository))
            response = _analysis(item, SourceRepository(
                repository, base._pinned_harness(
                    base.read_interleaved_dev(path),
                    Path(base.read_interleaved_dev(path)["source_run"]),
                    repository).function_catalog).open_function_span(
                        item["function_id"]), request=False, safe=False)
            response["context_requests"] = [{
                "target": "B", "request_type": "FUNCTION",
                "reason": "scripted provider-free Context test",
                "expected_information": "body"}]
            hp = stage12_fixture._RoleProvider(
                ledger, item["work_item_id"], "function_analysis", response)
            asyncio.run(run_hp_first_stage(
                path, 0, hp, ledger, target_repository=repository))
            local = stage12_fixture._RoleProvider(
                ledger, item["work_item_id"], "function_analysis", {})
            resolved = run_hp_context_stage(
                path, 0, local, ledger, target_repository=repository)
            self.assertGreater(json.loads(resolved.read_text())["fresh_count"], 0)
            with self.assertRaises(Exception) as captured:
                asyncio.run(run_hp_followup_stage(
                    path, 0, local, ledger, target_repository=repository))
            self.assertEqual(type(captured.exception).__name__,
                             "DevelopmentBudgetExhausted")
            saved = base.read_interleaved_dev(path)
            self.assertEqual(saved["role_active"]["state"],
                             "NO_OPPORTUNITY_BUDGET")
            self.assertEqual(saved["role_active"]["hp_round"], 1)
            self.assertEqual(local.calls, [])
            self.assertEqual((ledger.logical, ledger.physical), (3, 3))
            pending_ids = [row["id"] for row in ledger.pending_work]
            self.assertIn("role-budget:" + item["work_item_id"] +
                          ":function_analysis:round-1", pending_ids)
            graph = Path(json.loads(resolved.read_text())["graph_path"])
            prior_graph = graph.read_bytes()
            graph.write_bytes(prior_graph + b"\n")
            with self.assertRaises(ValueError):
                base.read_interleaved_dev(path)
            graph.write_bytes(prior_graph)
            self.assertEqual(base.read_interleaved_dev(path)["role_active"]
                             ["state"], "NO_OPPORTUNITY_BUDGET")
            changed = json.loads(resolved.read_text())
            changed["requests"][0]["status"] = "NOT_FOUND"
            resolved.write_text(json.dumps(changed, sort_keys=True) + "\n")
            raw = json.loads(path.read_text())
            raw["work_items"][0]["hp_context_receipts"][0]["sha256"] = \
                hashlib.sha256(resolved.read_bytes()).hexdigest()
            path.write_text(json.dumps(raw, sort_keys=True) + "\n")
            with self.assertRaises(ValueError):
                base.read_interleaved_dev(path)


if __name__ == "__main__":
    unittest.main()
