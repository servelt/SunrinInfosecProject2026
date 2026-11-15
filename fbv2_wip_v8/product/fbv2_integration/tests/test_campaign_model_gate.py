"""Provider-free checks for one durable, concurrent development model cap."""

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from devtools.campaign_model_gate import (
    CampaignGateError, CampaignLedgeredProvider, CampaignModelGate,
    CampaignPendingBudget, CampaignUncertain, _turn_from_events,
    wrap_campaign_client_factory,
)
from devtools.ledgered_provider import LedgeredProvider


def request(role):
    return SimpleNamespace(role=role, instructions="fixture", payload={"source": "pin"},
                           output_schema={}, session_key=None, model="fixture",
                           effort="low")


@dataclass(frozen=True)
class ReceiptRequest:
    role: str
    instructions: str = "fixture"
    payload: dict | None = None
    output_schema: dict | None = None
    session_key: str | None = None
    model: str = "fixture"
    effort: str = "low"
    raw_response_path: Path | None = None

    def __post_init__(self):
        object.__setattr__(self, "payload", self.payload or {"source": "pin"})
        object.__setattr__(self, "output_schema", self.output_schema or {})


class ReceiptTransport:
    """Provider-free App Server event/output shape, with no external call."""

    def __init__(self, root: Path, *, mismatched_turn=False,
                 missing_completion=False, changed_response=False,
                 duplicate_completion=False, long_response=False,
                 tool_calls=None):
        root.mkdir(mode=0o700, exist_ok=True)
        events = root / "model_events"
        events.mkdir(mode=0o700, exist_ok=True)
        self.event_log_path = events / "fixture.jsonl"
        self.calls = 0
        self.mismatched_turn = mismatched_turn
        self.missing_completion = missing_completion
        self.changed_response = changed_response
        self.duplicate_completion = duplicate_completion
        self.long_response = long_response
        self.tool_calls = [] if tool_calls is None else tool_calls

    async def generate(self, req):
        self.calls += 1
        assert req.raw_response_path is not None
        result = {"content": "fixture" + ("x" * 5000 if self.long_response else ""),
                  "tool_calls": self.tool_calls}
        raw = json.dumps(result, sort_keys=True)
        descriptor = os.open(req.raw_response_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(raw if not self.changed_response else '{}')
        turn_id = f"turn-{self.calls}"
        thread_id = f"thread-{self.calls}"
        rows = [
            {"method": "turn/started", "thread_id": thread_id,
             "turn_id": "", "server_request": False,
             "params": {"threadId": thread_id, "turn": {"id": turn_id}}},
            {"method": "item/completed", "thread_id": "",
             "turn_id": turn_id, "item_type": "agentMessage",
             "server_request": False,
             "agent_message_sha256": hashlib.sha256(raw.encode()).hexdigest()},
        ]
        if not self.missing_completion:
            rows.append({"method": "turn/completed", "thread_id": thread_id,
                         "turn_id": ("other-turn" if self.mismatched_turn else turn_id),
                         "turn_status": "completed", "server_request": False})
            if self.duplicate_completion:
                rows.append(dict(rows[-1]))
        descriptor = os.open(self.event_log_path,
                             os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                             0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            for row in rows:
                output.write(json.dumps(row, sort_keys=True) + "\n")
        return result

    async def close(self):
        pass


class InspectingTransport:
    def __init__(self, gate, *, failure=None):
        self.gate = gate
        self.failure = failure
        self.calls = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def generate(self, _request):
        self.calls += 1
        # Predebit and fsync must complete before the transport is entered.
        snapshot = self.gate.snapshot()
        assert snapshot["physical"] >= self.calls
        assert snapshot["records"][-1]["status"] == "STARTED"
        self.started.set()
        await self.release.wait()
        if self.failure:
            raise self.failure
        return {"content": "fixture", "tool_calls": []}

    async def close(self):
        pass


class CampaignModelGateTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "campaign.json"
        self.gate = CampaignModelGate(self.path, "public-md4c-dev", 2, 60,
                                      create=True)

    async def test_concurrent_roles_share_one_durable_cap(self):
        direction = InspectingTransport(self.gate)
        sp = InspectingTransport(self.gate)
        a = CampaignLedgeredProvider(direction, self.gate,
                                     role="direction", owner_id="worker-0")
        b = CampaignLedgeredProvider(sp, self.gate,
                                     role="sp", owner_id="direction-0:func-1")
        first = asyncio.create_task(a.generate(request("direction")))
        await direction.started.wait()
        second = asyncio.create_task(b.generate(request("sp")))
        await sp.started.wait()
        snapshot = self.gate.snapshot()
        self.assertEqual(snapshot["physical"], 2)
        self.assertEqual([row["status"] for row in snapshot["records"]],
                         ["STARTED", "STARTED"])
        with self.assertRaises(CampaignPendingBudget):
            await CampaignLedgeredProvider(InspectingTransport(self.gate), self.gate,
                                           role="seed", owner_id="direction-0").generate(
                                               request("seed"))
        self.assertEqual(self.gate.snapshot()["physical"], 2)
        self.assertEqual(self.gate.snapshot()["records"][-1]["status"],
                         "PENDING_BUDGET")
        direction.release.set()
        sp.release.set()
        await asyncio.gather(first, second)
        self.assertEqual([row["status"] for row in self.gate.snapshot()["records"]],
                         ["COMPLETED", "COMPLETED", "PENDING_BUDGET"])

    async def test_completed_appserver_turn_has_independently_checked_response(self):
        transport = ReceiptTransport(self.path.parent)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp", owner_id="func-0")
        result = await wrapped.generate(ReceiptRequest("sp"))
        self.assertEqual(result, {"content": "fixture", "tool_calls": []})
        evidence = wrapped.last_response_evidence
        self.assertEqual(evidence["status"], "VERIFIED")
        self.assertEqual(evidence["request_id"], wrapped.last_request_id)
        self.assertEqual(evidence["turn_id"], "turn-1")
        self.assertEqual(self.gate.verify_response_evidence(wrapped.last_request_id),
                         evidence)
        self.assertEqual(self.gate.snapshot()["physical"], 1)
        self.assertEqual(self.gate.snapshot()["records"][0]["response_evidence"],
                         evidence)
        restored = CampaignModelGate(self.path, "public-md4c-dev", 2, 60)
        self.assertEqual(restored.verify_response_evidence(wrapped.last_request_id),
                         evidence)

    async def test_turn_completion_before_final_message_cannot_prove_response(self):
        rows = [
            {"method": "turn/started", "thread_id": "t", "turn_id": "v"},
            {"method": "turn/completed", "thread_id": "t", "turn_id": "v",
             "turn_status": "completed"},
            {"method": "item/completed", "item_type": "agentMessage",
             "thread_id": "t", "turn_id": "v",
             "agent_message_sha256": hashlib.sha256(b'{}').hexdigest()},
        ]
        segment = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
        with self.assertRaises(ValueError):
            _turn_from_events(segment, hashlib.sha256(b'{}').hexdigest())

    async def test_raw_or_event_mutation_revokes_proof_without_redebit(self):
        transport = ReceiptTransport(self.path.parent)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp", owner_id="func-0")
        await wrapped.generate(ReceiptRequest("sp"))
        request_id = wrapped.last_request_id
        raw = Path(wrapped.last_response_evidence["response_path"])
        raw.write_text('{"content":"changed","tool_calls":[]}')
        self.assertEqual(self.gate.verify_response_evidence(request_id)["status"],
                         "UNPROVEN")
        self.assertEqual(self.gate.snapshot()["physical"], 1)

    async def test_incomplete_or_mismatched_event_is_unproven(self):
        for label, kwargs in (("mismatch", {"mismatched_turn": True}),
                              ("missing", {"missing_completion": True}),
                              ("content", {"changed_response": True}),
                              ("duplicate", {"duplicate_completion": True})):
            path = self.path.with_name(label + ".json")
            gate = CampaignModelGate(path, label, 1, 60, create=True)
            transport = ReceiptTransport(path.parent / label, **kwargs)
            wrapped = CampaignLedgeredProvider(transport, gate,
                                               role="sp", owner_id="func-0")
            await wrapped.generate(ReceiptRequest("sp"))
            self.assertEqual(wrapped.last_response_evidence["status"], "UNPROVEN")
            self.assertEqual(gate.verify_response_evidence(wrapped.last_request_id)["status"],
                             "UNPROVEN")
            self.assertEqual(gate.snapshot()["physical"], 1)

    async def test_long_response_has_hash_commitment_without_inline_event_body(self):
        transport = ReceiptTransport(self.path.parent, long_response=True)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp", owner_id="func-0")
        await wrapped.generate(ReceiptRequest("sp"))
        self.assertEqual(wrapped.last_response_evidence["status"], "VERIFIED")
        self.assertEqual(self.gate.verify_response_evidence(wrapped.last_request_id)
                         ["status"], "VERIFIED")

    async def test_host_tool_receipt_binds_proposal_and_retained_result(self):
        proposals = [{"name": "create_suspicious_point",
                      "arguments": '{"function_name":"parse_input"}'}]
        transport = ReceiptTransport(self.path.parent, tool_calls=proposals)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp", owner_id="func-0")
        await wrapped.generate(ReceiptRequest("sp"))
        request_id = wrapped.last_request_id
        call = {"id": f"bridge_{request_id}_0", "type": "function",
                "function": {"name": "create_suspicious_point",
                             "arguments": '{"function_name": "parse_input"}'}}
        result = '{"success":true,"created":true,"id":"0123456789abcdef01234567"}'
        event = wrapped.record_tool_result(request_id, call, result)
        self.assertEqual(event["call_id"], call["id"])
        self.assertEqual(self.gate.verify_tool_event(request_id, call["id"])["status"],
                         "VERIFIED")
        self.assertEqual(self.gate.snapshot()["physical"], 1)

        Path(event["result_path"]).write_text(result + " ")
        self.assertEqual(self.gate.verify_tool_event(request_id, call["id"])["status"],
                         "UNPROVEN")

    async def test_host_tool_receipt_rejects_cross_request_or_changed_proposal(self):
        proposals = [{"name": "create_suspicious_point",
                      "arguments": '{"function_name":"parse_input"}'}]
        transport = ReceiptTransport(self.path.parent, tool_calls=proposals)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp", owner_id="func-0")
        await wrapped.generate(ReceiptRequest("sp"))
        request_id = wrapped.last_request_id
        call = {"id": f"bridge_{request_id}_0", "type": "function",
                "function": {"name": "create_suspicious_point",
                             "arguments": '{"function_name":"other"}'}}
        with self.assertRaises(CampaignGateError):
            wrapped.record_tool_result(request_id, call, '{"success":true}')
        call["function"]["arguments"] = '{"function_name":"parse_input"}'
        call["id"] = "bridge_other-request_0"
        with self.assertRaises(CampaignGateError):
            wrapped.record_tool_result(request_id, call, '{"success":true}')
        self.assertEqual(self.gate.snapshot()["physical"], 1)
        self.assertEqual(self.gate.snapshot()["records"][0].get("tool_events", []), [])

    async def test_started_host_tool_blocks_replay_and_new_model_after_restart(self):
        proposals = [{"name": "create_pov", "arguments": '{"generator_code":"x"}'}]
        transport = ReceiptTransport(self.path.parent, tool_calls=proposals)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="pov", owner_id="pov_1:sp")
        await wrapped.generate(ReceiptRequest("pov"))
        request_id = wrapped.last_request_id
        call = {"id": f"bridge_{request_id}_0", "function": {
            "name": "create_pov", "arguments": '{"generator_code":"x"}'}}
        wrapped.begin_tool_result(request_id, call)
        self.assertEqual(self.gate.snapshot()["records"][0]["tool_events"][0]
                         ["status"], "STARTED")
        self.assertEqual(self.gate.verify_tool_event(request_id, call["id"])["status"],
                         "UNPROVEN")
        with self.assertRaises(CampaignGateError):
            wrapped.begin_tool_result(request_id, call)
        restored = CampaignModelGate(self.path, "public-md4c-dev", 2, 60)
        with self.assertRaises(CampaignUncertain):
            restored.reserve(request_id="next", role="sp", owner_id="func",
                             request_sha256="a" * 64)
        self.assertEqual(restored.snapshot()["physical"], 1)

    async def test_failed_host_tool_stays_incomplete_and_blocks_new_model(self):
        proposals = [{"name": "create_pov", "arguments": '{"generator_code":"x"}'}]
        wrapped = CampaignLedgeredProvider(
            ReceiptTransport(self.path.parent, tool_calls=proposals), self.gate,
            role="pov", owner_id="pov_1:sp")
        await wrapped.generate(ReceiptRequest("pov"))
        request_id = wrapped.last_request_id
        call = {"id": f"bridge_{request_id}_0", "function": {
            "name": "create_pov", "arguments": '{"generator_code":"x"}'}}
        wrapped.begin_tool_result(request_id, call)
        wrapped.fail_tool_result(request_id, call["id"], "RuntimeError")

        event = self.gate.snapshot()["records"][0]["tool_events"][0]
        self.assertEqual((event["status"], event["error"]),
                         ("INCOMPLETE", "RuntimeError"))
        with self.assertRaises(CampaignUncertain):
            self.gate.reserve(request_id="next", role="sp", owner_id="func",
                              request_sha256="a" * 64)

    async def test_codex_bridge_issues_request_bound_host_tool_receipt(self):
        from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge

        proposals = [{"name": "read_source",
                      "arguments": '{"path":"parser.c"}'}]
        transport = ReceiptTransport(self.path.parent, tool_calls=proposals)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp", owner_id="func-0")
        bridge = CodexToolBridge(wrapped, ReceiptRequest,
                                 codex_model="fixture", role="sp", max_calls=1)
        tool = {"type": "function", "function": {
            "name": "read_source", "parameters": {"type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"], "additionalProperties": False}}}

        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "read"}], [tool])
        bridge.audit_tool_start(response, response.tool_calls[0])
        bridge.audit_tool_result(response, response.tool_calls[0], "source bytes")

        self.assertEqual(response.model_request_id, wrapped.last_request_id)
        self.assertEqual(response.model_turn_id, "turn-1")
        self.assertEqual(self.gate.verify_tool_event(
            wrapped.last_request_id, response.tool_calls[0]["id"])["status"],
            "VERIFIED")

    async def test_later_budget_refusal_clears_last_success_without_debit(self):
        transport = ReceiptTransport(self.path.parent)
        single = CampaignModelGate(self.path.with_name("single.json"),
                                   "one-call", 1, 60, create=True)
        wrapped = CampaignLedgeredProvider(transport, single,
                                           role="sp", owner_id="func-0")
        await wrapped.generate(ReceiptRequest("sp"))
        self.assertEqual(wrapped.last_response_evidence["status"], "VERIFIED")
        with self.assertRaises(CampaignPendingBudget):
            await wrapped.generate(ReceiptRequest("sp"))
        self.assertIsNone(wrapped.last_request_id)
        self.assertIsNone(wrapped.last_response_evidence)
        self.assertEqual(single.snapshot()["physical"], 1)

    async def test_same_appserver_turn_cannot_prove_two_model_requests(self):
        first = CampaignLedgeredProvider(ReceiptTransport(self.path.parent),
                                         self.gate, role="sp", owner_id="func-0")
        await first.generate(ReceiptRequest("sp"))
        second = CampaignLedgeredProvider(ReceiptTransport(self.path.parent),
                                          self.gate, role="sp", owner_id="func-1")
        with self.assertRaises(CampaignGateError):
            await second.generate(ReceiptRequest("sp"))
        self.assertIsNone(second.last_request_id)
        self.assertIsNone(second.last_response_evidence)
        # The second physical start is still durably charged. A restart seals
        # its unfinished reservation as uncertain; it must not be retransmitted.
        restored = CampaignModelGate(self.path, "public-md4c-dev", 2, 60)
        self.assertEqual(restored.snapshot()["physical"], 2)
        self.assertEqual([row["status"] for row in restored.snapshot()["records"]],
                         ["COMPLETED", "UNCERTAIN"])

    async def test_legacy_completed_turn_and_uncertain_turn_stay_unproven(self):
        self.gate.reserve(request_id="old", role="sp", owner_id="func-0",
                          request_sha256="a" * 64)
        self.gate.finish("old", completed=True)
        self.assertEqual(self.gate.verify_response_evidence("old")["status"],
                         "UNPROVEN")
        self.gate.reserve(request_id="interrupted", role="seed", owner_id="dir-0",
                          request_sha256="b" * 64)
        self.gate.finish("interrupted", completed=False, error="stream")
        self.assertEqual(self.gate.verify_response_evidence("interrupted")["status"],
                         "UNPROVEN")
        self.assertEqual(self.gate.snapshot()["physical"], 2)

    async def test_restart_marks_started_turn_uncertain_and_blocks_resend(self):
        self.gate.reserve(request_id="first", role="direction", owner_id="worker-0",
                          request_sha256="a" * 64)
        restored = CampaignModelGate(self.path, "public-md4c-dev", 2, 60)
        record = restored.snapshot()["records"][0]
        self.assertEqual(record["status"], "UNCERTAIN")
        self.assertEqual(restored.snapshot()["physical"], 1)
        with self.assertRaises(CampaignUncertain):
            restored.reserve(request_id="second", role="sp", owner_id="func-1",
                             request_sha256="b" * 64)
        self.assertEqual(restored.snapshot()["physical"], 1)

    async def test_restart_after_completed_turn_keeps_remaining_credit(self):
        self.gate.reserve(request_id="first", role="direction", owner_id="worker-0",
                          request_sha256="a" * 64)
        self.gate.finish("first", completed=True)
        restored = CampaignModelGate(self.path, "public-md4c-dev", 2, 60)
        restored.reserve(request_id="second", role="pov", owner_id="sp-0",
                         request_sha256="b" * 64)
        restored.finish("second", completed=True)
        self.assertEqual(restored.snapshot()["physical"], 2)
        self.assertEqual([row["status"] for row in restored.snapshot()["records"]],
                         ["COMPLETED", "COMPLETED"])

    async def test_transport_failure_is_one_uncertain_debit_without_retry(self):
        transport = InspectingTransport(self.gate,
                                        failure=RuntimeError("stream interrupted"))
        transport.release.set()
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="verifier", owner_id="sp-0")
        with self.assertRaisesRegex(CampaignUncertain, "did not complete") as caught:
            await wrapped.generate(request("verifier"))
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        self.assertEqual(str(caught.exception.__cause__), "stream interrupted")
        self.assertEqual(transport.calls, 1)
        self.assertEqual(self.gate.snapshot()["physical"], 1)
        self.assertEqual(self.gate.snapshot()["records"][0]["status"],
                         "UNCERTAIN")
        with self.assertRaises(CampaignUncertain):
            await wrapped.generate(request("verifier"))
        self.assertEqual(transport.calls, 1)

    async def test_explicit_safety_refusal_without_turn_completion_blocks_sp(self):
        class ProviderSafetyRefusedError(RuntimeError):
            pass

        seed_transport = InspectingTransport(
            self.gate, failure=ProviderSafetyRefusedError("explicit refusal"))
        seed_transport.release.set()
        seed = CampaignLedgeredProvider(seed_transport, self.gate,
                                        role="seed", owner_id="direction-0")
        sp_transport = InspectingTransport(self.gate)
        sp = CampaignLedgeredProvider(sp_transport, self.gate,
                                      role="sp", owner_id="direction-0:func-0")
        with self.assertRaises(CampaignUncertain):
            await seed.generate(request("seed"))
        with self.assertRaises(CampaignUncertain):
            await sp.generate(request("sp"))
        snapshot = self.gate.snapshot()
        self.assertEqual(snapshot["physical"], 1)
        self.assertEqual(snapshot["records"][0]["status"], "UNCERTAIN")
        self.assertEqual(snapshot["records"][0]["error"],
                         "ProviderSafetyRefusedError")
        self.assertEqual(seed_transport.calls, 1)
        self.assertEqual(sp_transport.calls, 0)

    async def test_duplicate_request_id_does_not_double_debit(self):
        self.gate.reserve(request_id="fixed", role="pov", owner_id="sp-0",
                          request_sha256="c" * 64)
        self.gate.finish("fixed", completed=True)
        with self.assertRaises(CampaignGateError):
            self.gate.reserve(request_id="fixed", role="pov", owner_id="sp-0",
                              request_sha256="c" * 64)
        self.assertEqual(self.gate.snapshot()["physical"], 1)

    async def test_mutated_checkpoint_and_stacked_ledger_fail_closed(self):
        with self.path.open("ab") as stream:
            stream.write(b" ")
        with self.assertRaises(CampaignGateError):
            self.gate.snapshot()
        with self.assertRaises(CampaignGateError):
            CampaignModelGate(self.path, "public-md4c-dev", 2, 60)
        dummy = SimpleNamespace(generate=None, close=None)
        stacked = LedgeredProvider(dummy, None, scope_id="x", role="direction")
        with self.assertRaisesRegex(ValueError, "already ledgered"):
            CampaignLedgeredProvider(stacked, self.gate,
                                     role="direction", owner_id="worker-0")

    async def test_role_mismatch_is_rejected_before_debit(self):
        transport = InspectingTransport(self.gate)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="sp_large", owner_id="func-2")
        with self.assertRaisesRegex(ValueError, "role differs"):
            await wrapped.generate(request("sp"))
        self.assertEqual(self.gate.snapshot()["physical"], 0)
        self.assertEqual(transport.calls, 0)

    async def test_original_role_factory_uses_one_gate_for_all_roles(self):
        transports = []

        def builder(role, owner):
            transport = InspectingTransport(self.gate)
            transport.release.set()
            transports.append(transport)
            return SimpleNamespace(role=role, owner=owner, provider=transport)

        factory = wrap_campaign_client_factory(self.gate, builder)
        direction = factory("direction", "worker-0")
        seed = factory("seed", "direction-0")
        self.assertIsNot(direction, seed)
        await direction.provider.generate(request("direction"))
        await seed.provider.generate(request("seed"))
        self.assertEqual(self.gate.snapshot()["physical"], 2)
        self.assertEqual([row["role"] for row in self.gate.snapshot()["records"]],
                         ["direction", "seed"])
        self.assertEqual([row["owner_id"] for row in self.gate.snapshot()["records"]],
                         ["worker-0", "direction-0"])
        self.assertEqual([row.calls for row in transports], [1, 1])

    async def test_late_response_after_suppressed_cancellation_is_uncertain(self):
        short = CampaignModelGate(self.path.with_name("short.json"),
                                  "public-md4c-short", 2, 0.03, create=True)

        class CancellationSuppressingTransport:
            calls = 0

            async def generate(self, _request):
                self.calls += 1
                try:
                    await asyncio.sleep(1)
                except asyncio.CancelledError:
                    await asyncio.sleep(0.04)
                    return {"content": "late response", "tool_calls": []}

            async def close(self):
                pass

        transport = CancellationSuppressingTransport()
        wrapped = CampaignLedgeredProvider(transport, short,
                                           role="sp", owner_id="func-0")
        with self.assertRaises(CampaignUncertain):
            await wrapped.generate(request("sp"))
        self.assertEqual(transport.calls, 1)
        self.assertEqual(short.snapshot()["physical"], 1)
        self.assertEqual(short.snapshot()["records"][0]["status"], "UNCERTAIN")

    async def test_wall_clock_rollback_cannot_extend_monotonic_budget(self):
        payload = self.gate.snapshot()
        with patch("devtools.campaign_model_gate.time.time",
                   return_value=payload["started_at"] - 3600), patch(
                   "devtools.campaign_model_gate.time.monotonic",
                   return_value=payload["started_monotonic"] + 120):
            with self.assertRaises(CampaignPendingBudget):
                self.gate.reserve(request_id="clock-rollback", role="seed",
                                  owner_id="direction-0", request_sha256="d" * 64)
        self.assertEqual(self.gate.snapshot()["physical"], 0)
