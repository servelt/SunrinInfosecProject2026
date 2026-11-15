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
    CampaignPendingBudget, CampaignStopping, CampaignUncertain,
    _private_bytes, _turn_from_events,
    product_campaign_client_factory, wrap_campaign_client_factory,
)
from devtools.ledgered_provider import LedgeredProvider


def test_private_receipt_reader_rejects_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "receipt.fifo"
    os.mkfifo(fifo, 0o600)
    with unittest.TestCase().assertRaises(CampaignGateError):
        _private_bytes(fifo)


def test_model_gate_without_count_cap_still_records_every_physical_reservation():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, 60,
                                 create=True)
        for index, role in enumerate(("direction", "seed", "sp")):
            gate.reserve(request_id=f"request-{index}", role=role,
                         owner_id=f"owner-{index}",
                         request_sha256=hashlib.sha256(
                             f"request-{index}".encode()).hexdigest())
        snapshot = gate.snapshot()
        assert snapshot["physical_max"] is None
        assert snapshot["physical"] == 3
        assert len(snapshot["records"]) == 3


def test_model_gate_without_count_cap_still_rejects_after_wall_deadline():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, 60,
                                 create=True)
        start = gate.snapshot()["started_monotonic"]
        with patch("devtools.campaign_model_gate.time.monotonic",
                   return_value=start + 61):
            with unittest.TestCase().assertRaises(CampaignPendingBudget):
                gate.reserve(request_id="late", role="sp", owner_id="function",
                             request_sha256=hashlib.sha256(b"late").hexdigest())
        assert gate.snapshot()["physical"] == 0


def test_remaining_envelope_is_settled_atomic_and_does_not_spend_budget():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "serial-envelope", 4, 60, create=True)
        first = gate.check_remaining_envelope(
            minimum_calls=4, minimum_wall_seconds=30)
        assert first["admitted"] is True
        assert first["remaining_calls"] == 4
        assert gate.snapshot()["physical"] == 0

        gate.reserve(request_id="used", role="sp", owner_id="function-A",
                     request_sha256=hashlib.sha256(b"used").hexdigest())
        with unittest.TestCase().assertRaises(CampaignGateError):
            gate.check_remaining_envelope(
                minimum_calls=3, minimum_wall_seconds=30)
        gate.finish("used", completed=True)
        second = gate.check_remaining_envelope(
            minimum_calls=4, minimum_wall_seconds=30)
        assert second["admitted"] is False
        assert second["remaining_calls"] == 3


def test_fullscan_gate_without_campaign_model_deadline_keeps_receipts():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        start = gate.snapshot()["started_monotonic"]
        with patch("devtools.campaign_model_gate.time.monotonic",
                   return_value=start + 1801):
            gate.reserve(request_id="later", role="sp", owner_id="function",
                         request_sha256=hashlib.sha256(b"later").hexdigest())
        assert gate.snapshot()["physical"] == 1
        assert gate.snapshot()["wall_seconds"] is None


def test_graceful_stop_closes_new_reservations_without_rewriting_ledger():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        gate.reserve(request_id="already-started", role="sp",
                     owner_id="function-A",
                     request_sha256=hashlib.sha256(b"started").hexdigest())
        gate.close_admission("SIGINT")
        with unittest.TestCase().assertRaises(CampaignStopping):
            gate.reserve(request_id="must-not-start", role="pov",
                         owner_id="candidate-B",
                         request_sha256=hashlib.sha256(b"stopped").hexdigest())
        gate.finish("already-started", completed=True)
        snapshot = gate.snapshot()
        assert [row["request_id"] for row in snapshot["records"]] == [
            "already-started"
        ]
        assert snapshot["records"][0]["status"] == "COMPLETED"
        assert gate.stop_snapshot() == {
            "admission_open": False,
            "reason": "SIGINT",
            "active_request_ids": [],
            "transport_started_request_ids": [],
        }


def test_stop_after_predebit_is_retained_as_pretransport_refusal():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        gate.reserve(request_id="raced", role="sp", owner_id="function-A",
                     request_sha256=hashlib.sha256(b"raced").hexdigest())
        gate.close_admission("SIGINT")
        with unittest.TestCase().assertRaises(CampaignStopping):
            gate.confirm_transport_admission("raced")
        snapshot = gate.snapshot()
        assert snapshot["physical"] == 0
        assert snapshot["records"][0]["status"] == "PENDING_STOP"
        assert snapshot["records"][0]["error"] == "USER_STOP_BEFORE_TRANSPORT"
        assert gate.stop_snapshot()["active_request_ids"] == []
        restored = CampaignModelGate(Path(directory) / "campaign.json",
                                     "public-md4c-full-sp", None, None)
        assert restored.snapshot()["records"][0]["status"] == "PENDING_STOP"


def test_stop_injected_during_dispatch_lease_rolls_back_before_transport():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        gate.reserve(request_id="raced", role="sp", owner_id="function-A",
                     request_sha256=hashlib.sha256(b"raced").hexdigest())
        actual = gate._admission_closed
        original_is_set = actual.is_set
        calls = 0

        def injected_stop():
            nonlocal calls
            calls += 1
            if calls == 1:
                actual.set()
                return False
            return original_is_set()

        with patch.object(actual, "is_set", side_effect=injected_stop):
            with unittest.TestCase().assertRaises(CampaignStopping):
                gate.confirm_transport_admission("raced")
        row = gate.snapshot()["records"][0]
        assert row["status"] == "PENDING_STOP"
        assert "transport_started_at" not in row
        assert gate.snapshot()["physical"] == 0


def test_durable_dispatch_lease_defines_an_already_inflight_request():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        gate.reserve(request_id="inflight", role="sp", owner_id="function-A",
                     request_sha256=hashlib.sha256(b"inflight").hexdigest())
        gate.confirm_transport_admission("inflight")
        gate.close_admission("SIGINT")
        gate.finish("inflight", completed=True)
        row = gate.snapshot()["records"][0]
        assert row["status"] == "COMPLETED"
        assert isinstance(row["transport_started_at"], float)
        assert gate.snapshot()["physical"] == 1


def test_transport_admission_rejects_non_main_signal_thread():
    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        gate.reserve(request_id="threaded", role="sp", owner_id="function-A",
                     request_sha256=hashlib.sha256(b"threaded").hexdigest())
        with unittest.TestCase().assertRaises(CampaignGateError):
            asyncio.run(asyncio.to_thread(
                gate.confirm_transport_admission, "threaded"))
        gate.close_admission("SIGINT")
        with unittest.TestCase().assertRaises(CampaignStopping):
            gate.confirm_transport_admission("threaded")
        row = gate.snapshot()["records"][0]
        assert row["status"] == "PENDING_STOP"
        assert "transport_started_at" not in row


def test_provider_rejects_non_main_thread_before_reservation():
    class Provider:
        entered = False

        async def generate(self, _request):
            self.entered = True
            return SimpleNamespace()

    with tempfile.TemporaryDirectory() as directory:
        gate = CampaignModelGate(Path(directory) / "campaign.json",
                                 "public-md4c-full-sp", None, None,
                                 create=True)
        provider = Provider()
        wrapped = CampaignLedgeredProvider(
            provider, gate, role="sp", owner_id="function-A")

        def threaded_generate():
            return asyncio.run(wrapped.generate(request("sp")))

        with unittest.TestCase().assertRaises(CampaignGateError):
            asyncio.run(asyncio.to_thread(threaded_generate))
        assert provider.entered is False
        assert gate.snapshot()["records"] == []
        assert gate.snapshot()["physical"] == 0


def test_fullscan_factory_keeps_per_request_timeout_without_shared_wall():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gate = CampaignModelGate(root / "campaign.json", "full-sp", None, None,
                                 create=True)
        seen = []

        def fake_bridge(**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(role=kwargs["role"], provider=object())

        with patch("fuzzingbrain.llms.codex_tool_bridge.product_codex_bridge",
                   side_effect=fake_bridge):
            factory = product_campaign_client_factory(
                gate, cwd=root, codex_model="fixture", max_calls_per_agent=None,
                executable="fixture", executable_sha256="a" * 64,
                event_log_dir=root, response_stream_limit_bytes=2_000_000,
                parallel_agents=True)
            factory("sp", "function-A")
        assert seen[0]["timeout_seconds"] == 300.0
        assert factory._fbv2_campaign_invocation_lock is None


def test_fullscan_factory_routes_each_role_through_the_pinned_product_profile():
    role_models = {
        "direction": {"model": "gpt-5.6-luna", "reasoning": "high"},
        "seed": {"model": "gpt-5.6-luna", "reasoning": "high"},
        "sp": {"model": "gpt-5.6-luna", "reasoning": "high"},
        "sp_large": {"model": "gpt-5.6-luna", "reasoning": "high"},
        "verifier": {"model": "gpt-5.6-sol", "reasoning": "low"},
        "pov": {"model": "gpt-5.6-sol", "reasoning": "max"},
        "function_analysis": {"model": "gpt-5.6-sol", "reasoning": "max"},
        "assertion_generator": {"model": "gpt-5.6-sol", "reasoning": "max"},
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gate = CampaignModelGate(root / "campaign.json", "full-sp", None, None,
                                 create=True)
        seen = []

        def fake_bridge(**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(role=kwargs["role"], provider=object())

        with patch("fuzzingbrain.llms.codex_tool_bridge.product_codex_bridge",
                   side_effect=fake_bridge):
            factory = product_campaign_client_factory(
                gate, cwd=root, codex_model="fallback-must-not-be-used",
                effort="medium", max_calls_per_agent=None,
                executable="fixture", executable_sha256="a" * 64,
                event_log_dir=root, response_stream_limit_bytes=2_000_000,
                parallel_agents=True,
                role_models=role_models)
            for role in role_models:
                factory(role, f"owner-{role}")

        observed = {
            row["role"]: (row["codex_model"], row["effort"])
            for row in seen
        }
        assert observed == {
            role: (route["model"], route["reasoning"])
            for role, route in role_models.items()
        }


def test_fullscan_factory_rejects_an_incomplete_role_profile():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gate = CampaignModelGate(root / "campaign.json", "full-sp", None, None,
                                 create=True)
        with unittest.TestCase().assertRaisesRegex(
                ValueError, "invalid campaign role model profile"):
            product_campaign_client_factory(
                gate, cwd=root, codex_model="fixture",
                max_calls_per_agent=None, executable="fixture",
                executable_sha256="a" * 64, event_log_dir=root,
                response_stream_limit_bytes=2_000_000,
                role_models={
                    "sp": {"model": "gpt-5.6-luna", "reasoning": "high"}
                })


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
                 tool_calls=None, turn_prefix=""):
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
        self.turn_prefix = turn_prefix

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
        turn_id = f"{self.turn_prefix}turn-{self.calls}"
        thread_id = f"{self.turn_prefix}thread-{self.calls}"
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

    async def test_seed_direct_transport_binds_canonical_args_end_to_end(self):
        from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge

        source = "def generate(n):\n    return b'<x a=\"b\">' + b'\\x00'\n"
        proposals = [{
            "name": "create_seed",
            "arguments": "{}",
            "seed_generator_code": source,
            "seed_num_seeds": 3,
        }]
        transport = ReceiptTransport(self.path.parent, tool_calls=proposals)
        wrapped = CampaignLedgeredProvider(
            transport, self.gate, role="seed", owner_id="direction-0")
        bridge = CodexToolBridge(
            wrapped, ReceiptRequest, codex_model="fixture", role="seed",
            max_calls=1)
        tool = {"type": "function", "function": {
            "name": "create_seed", "parameters": {"type": "object",
                "properties": {"generator_code": {"type": "string"},
                               "num_seeds": {"type": "integer"}},
                "required": ["generator_code", "num_seeds"],
                "additionalProperties": False}}}
        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "generate"}], [tool])
        call = response.tool_calls[0]
        self.assertEqual(json.loads(call["function"]["arguments"]), {
            "generator_code": source, "num_seeds": 3,
        })
        bridge.audit_tool_start(response, call)
        bridge.audit_tool_result(
            response, call, '{"success":true,"created":3}')
        request_id = wrapped.last_request_id
        self.assertEqual(
            self.gate.verify_tool_event(request_id, call["id"])["status"],
            "VERIFIED")

    async def test_seed_gate_rejects_missing_or_typed_wrong_sentinels(self):
        cases = [
            {"name": "read_source", "arguments": '{"path":"x"}'},
            {"name": "read_source", "arguments": '{"path":"x"}',
             "seed_generator_code": "", "seed_num_seeds": False},
            {"name": "read_source", "arguments": '{"path":"x"}',
             "seed_generator_code": "", "seed_num_seeds": 0.0},
        ]
        for index, proposal in enumerate(cases):
            path = self.path.with_name(f"seed-sentinel-{index}.json")
            gate = CampaignModelGate(path, f"sentinel-{index}", 1, 60,
                                     create=True)
            wrapped = CampaignLedgeredProvider(
                ReceiptTransport(path.parent / f"raw-{index}",
                                 tool_calls=[proposal]),
                gate, role="seed", owner_id="direction-0")
            await wrapped.generate(ReceiptRequest("seed"))
            request_id = wrapped.last_request_id
            call = {"id": f"bridge_{request_id}_0", "function": {
                "name": "read_source", "arguments": '{"path":"x"}'}}
            with self.assertRaises(CampaignGateError):
                wrapped.begin_tool_result(request_id, call)

    async def test_seed_gate_rejects_changed_canonical_execution_args(self):
        proposals = [{
            "name": "create_seed", "arguments": "{}",
            "seed_generator_code": "def generate(n): return b'x'",
            "seed_num_seeds": 2,
        }]
        wrapped = CampaignLedgeredProvider(
            ReceiptTransport(self.path.parent, tool_calls=proposals), self.gate,
            role="seed", owner_id="direction-0")
        await wrapped.generate(ReceiptRequest("seed"))
        request_id = wrapped.last_request_id
        changed = {"id": f"bridge_{request_id}_0", "function": {
            "name": "create_seed", "arguments": json.dumps({
                "generator_code": "def generate(n): return b'y'",
                "num_seeds": 2,
            }, sort_keys=True)}}
        with self.assertRaises(CampaignGateError):
            wrapped.begin_tool_result(request_id, changed)

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

    async def test_uncertain_parallel_request_blocks_later_host_side_effect(self):
        proposal = [{"name": "read_source",
                     "arguments": '{"path":"parser.c"}'}]
        wrapped = CampaignLedgeredProvider(
            ReceiptTransport(self.path.parent, tool_calls=proposal), self.gate,
            role="sp", owner_id="function-A")
        await wrapped.generate(ReceiptRequest("sp"))
        request_id = wrapped.last_request_id
        call = {"id": f"bridge_{request_id}_0", "function": {
            "name": "read_source", "arguments": '{"path":"parser.c"}'}}
        self.gate.reserve(request_id="other", role="verifier",
                          owner_id="candidate-B", request_sha256="b" * 64)
        self.gate.finish("other", completed=False, error="CancelledError")
        with self.assertRaises(CampaignUncertain):
            wrapped.begin_tool_result(request_id, call)
        self.assertEqual(self.gate.snapshot()["records"][0]
                         .get("tool_events", []), [])

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

    async def test_fullscan_requests_overlap_and_keep_distinct_owners(self):
        from fuzzingbrain.worker.pipeline import injected_agent_client

        entered = asyncio.Event()
        release = {"sp": asyncio.Event(), "pov": asyncio.Event()}
        active = 0
        peak = 0

        class ConcurrentTransport:
            def __init__(self, role):
                self.role = role

            async def generate(self, _request):
                nonlocal active, peak
                active += 1
                peak = max(peak, active)
                if active == 2:
                    entered.set()
                try:
                    await release[self.role].wait()
                    return {"content": "fixture", "tool_calls": []}
                finally:
                    active -= 1

            async def close(self):
                pass

        class Bridge:
            def __init__(self, role):
                self.role = role
                self.provider = ConcurrentTransport(role)

            async def close(self):
                await self.provider.close()

        factory = wrap_campaign_client_factory(
            self.gate, lambda role, owner: Bridge(role), parallel_agents=True)

        async def run(role, owner):
            async with injected_agent_client(factory, role, owner) as client:
                await client.provider.generate(request(role))

        tasks = [asyncio.create_task(run("sp", "function-A")),
                 asyncio.create_task(run("pov", "candidate-B"))]
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            self.assertEqual(peak, 2)
            release["pov"].set()
            for _ in range(20):
                await asyncio.sleep(0)
                if self.gate.snapshot()["records"][1]["status"] == "COMPLETED":
                    break
            self.assertEqual([row["status"] for row in
                              self.gate.snapshot()["records"]],
                             ["STARTED", "COMPLETED"])
        finally:
            release["sp"].set()
            release["pov"].set()
            await asyncio.gather(*tasks)
        records = self.gate.snapshot()["records"]
        self.assertEqual({row["owner_id"] for row in records},
                         {"function-A", "candidate-B"})
        self.assertEqual([row["status"] for row in records],
                         ["COMPLETED", "COMPLETED"])
        self.assertEqual(self.gate.snapshot()["physical"], 2)

    async def test_parallel_receipts_and_tools_keep_owner_on_reverse_completion(self):
        entered = asyncio.Event()
        active = 0
        release = {"sp": asyncio.Event(), "pov": asyncio.Event()}

        class SlowReceipt(ReceiptTransport):
            def __init__(self, role, owner):
                super().__init__(self_root / owner, turn_prefix=owner + "-",
                                 tool_calls=[{"name": "read_source",
                                              "arguments": json.dumps({
                                                  "owner": owner})}])
                self.role = role

            async def generate(self, req):
                nonlocal active
                active += 1
                if active == 2:
                    entered.set()
                try:
                    await release[self.role].wait()
                    return await super().generate(req)
                finally:
                    active -= 1

        self_root = self.path.parent
        first = CampaignLedgeredProvider(
            SlowReceipt("sp", "function-A"), self.gate,
            role="sp", owner_id="function-A")
        second = CampaignLedgeredProvider(
            SlowReceipt("pov", "candidate-B"), self.gate,
            role="pov", owner_id="candidate-B")
        first_task = asyncio.create_task(first.generate(ReceiptRequest("sp")))
        second_task = asyncio.create_task(second.generate(ReceiptRequest("pov")))
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            release["pov"].set()
            await asyncio.wait_for(second_task, timeout=2)
            self.assertEqual([row["status"] for row in
                              self.gate.snapshot()["records"]],
                             ["STARTED", "COMPLETED"])
        finally:
            release["sp"].set()
            release["pov"].set()
            await asyncio.wait_for(first_task, timeout=2)

        for wrapped, owner, agent_id in ((first, "function-A", "a" * 24),
                                         (second, "candidate-B", "b" * 24)):
            request_id = wrapped.last_request_id
            evidence = self.gate.verify_response_evidence(request_id)
            self.assertEqual(evidence["status"], "VERIFIED")
            self.assertTrue(evidence["thread_id"].startswith(owner + "-"))
            call = {"id": f"bridge_{request_id}_0", "function": {
                "name": "read_source",
                "arguments": json.dumps({"owner": owner})}}
            wrapped.begin_tool_result(request_id, call, agent_id=agent_id)
            wrapped.complete_tool_result(request_id, call["id"], owner)
            tool = self.gate.verify_tool_event(request_id, call["id"])
            self.assertEqual((tool["status"], tool["agent_id"]),
                             ("VERIFIED", agent_id))
        self.assertNotEqual(first.last_request_id, second.last_request_id)
        self.assertEqual(self.gate.snapshot()["physical"], 2)

    async def test_parallel_reservation_waits_for_audited_host_tool(self):
        from fuzzingbrain.agents.base import BaseAgent
        from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge

        entered = asyncio.Event()
        release = asyncio.Event()
        proposal = [{"name": "read_source",
                     "arguments": '{"path":"parser.c"}'}]

        class SlowAgent(BaseAgent):
            enable_context_compression = False

            @property
            def system_prompt(self):
                return "fixture"

            def get_initial_message(self, **kwargs):
                return "fixture"

            async def _execute_tool(self, client, name, args):
                entered.set()
                await release.wait()
                return "source bytes"

        def builder(role, owner):
            if role == "verifier":
                transport = InspectingTransport(self.gate)
                transport.release.set()
                return SimpleNamespace(role=role, provider=transport)
            transport = ReceiptTransport(self.path.parent / owner,
                                         tool_calls=proposal)
            return CodexToolBridge(transport, ReceiptRequest,
                                   codex_model="fixture", role=role,
                                   max_calls=2)

        factory = wrap_campaign_client_factory(self.gate, builder,
                                               parallel_agents=True)
        sp = factory("sp", "function-A")
        verifier = factory("verifier", "candidate-B")
        self.assertIs(sp._fbv2_campaign_boundary_lock,
                      factory._fbv2_campaign_boundary_lock)
        self.assertIs(verifier._fbv2_campaign_boundary_lock,
                      factory._fbv2_campaign_boundary_lock)
        tool = {"type": "function", "function": {
            "name": "read_source", "parameters": {"type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"], "additionalProperties": False}}}
        response = await sp.acall_with_tools(
            [{"role": "user", "content": "read"}], [tool])
        agent = SlowAgent(llm_client=sp, verbose=False)
        tool_task = asyncio.create_task(agent._execute_audited_tool(
            None, response, response.tool_calls[0], "read_source",
            {"path": "parser.c"}))
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            model_task = asyncio.create_task(
                verifier.provider.generate(ReceiptRequest("verifier")))
            await asyncio.sleep(0)
            self.assertEqual(self.gate.snapshot()["physical"], 1)
            self.assertFalse(model_task.done())
        finally:
            release.set()
            self.assertEqual(await tool_task, "source bytes")
        await asyncio.wait_for(model_task, timeout=2)
        records = self.gate.snapshot()["records"]
        self.assertEqual(records[0]["tool_events"][0]["status"], "COMPLETED")
        self.assertEqual([row["owner_id"] for row in records],
                         ["function-A", "candidate-B"])

    async def test_verifier_local_limit_needs_owned_verified_tool_receipts(self):
        from fuzzingbrain.worker.pipeline import AgentPipeline

        owner = "verify_1:candidate-A"
        agent_id = "a" * 24
        proposals = [{"name": "get_function_source",
                      "arguments": '{"function_name":"parse_input"}'}]
        transport = ReceiptTransport(self.path.parent / "verifier-local",
                                     tool_calls=proposals)
        wrapped = CampaignLedgeredProvider(transport, self.gate,
                                           role="verifier", owner_id=owner)
        await wrapped.generate(ReceiptRequest("verifier"))
        request_id = wrapped.last_request_id
        call = {"id": f"bridge_{request_id}_0", "function": {
            "name": "get_function_source",
            "arguments": '{"function_name":"parse_input"}'}}
        wrapped.begin_tool_result(request_id, call, agent_id=agent_id)
        wrapped.complete_tool_result(request_id, call["id"], "source bytes")
        client = SimpleNamespace(provider=wrapped,
                                 last_agent_response_was_final=False,
                                 agent_id=agent_id)
        agent = SimpleNamespace(stop_reason="max_iterations")
        factory = SimpleNamespace(_fbv2_campaign_gate=self.gate)
        pipeline = AgentPipeline("task", SimpleNamespace(),
                                 llm_client_factory=factory)
        self.assertEqual(pipeline._settled_local_verifier_limit(
            client, agent, owner), 0)
        self.gate.reserve(request_id="unrelated-stopped", role="pov",
                          owner_id="pov_2:candidate-B",
                          request_sha256="b" * 64)
        self.gate.close_admission("SIGINT")
        with self.assertRaises(CampaignStopping):
            self.gate.confirm_transport_admission("unrelated-stopped")
        self.assertEqual(pipeline._settled_local_verifier_limit(
            client, agent, owner), 0)
        client.agent_id = "b" * 24
        self.assertIsNone(pipeline._settled_local_verifier_limit(
            client, agent, owner))
        client.agent_id = agent_id
        agent.stop_reason = "uncertain_remote"
        self.assertIsNone(pipeline._settled_local_verifier_limit(
            client, agent, owner))

    async def test_verifier_local_limit_accepts_only_successful_update_receipt(self):
        from fuzzingbrain.worker.pipeline import AgentPipeline

        owner = "verify_1:candidate-A"
        agent_id = "a" * 24
        arguments = '{"suspicious_point_id":"candidate-A","is_checked":true}'
        for successful in (True, False):
            gate = CampaignModelGate(
                self.path.with_name(f"verifier-{successful}.json"),
                f"verifier-{successful}", 2, 60, create=True)
            transport = ReceiptTransport(
                self.path.parent / f"verifier-{successful}",
                tool_calls=[{"name": "update_suspicious_point",
                             "arguments": arguments}])
            wrapped = CampaignLedgeredProvider(
                transport, gate, role="verifier", owner_id=owner)
            await wrapped.generate(ReceiptRequest("verifier"))
            request_id = wrapped.last_request_id
            call = {"id": f"bridge_{request_id}_0", "function": {
                "name": "update_suspicious_point", "arguments": arguments}}
            wrapped.begin_tool_result(request_id, call, agent_id=agent_id)
            wrapped.complete_tool_result(
                request_id, call["id"],
                json.dumps({"success": successful, "updated": successful,
                            "server_result": {"updated": successful}}))
            client = SimpleNamespace(provider=wrapped,
                                     last_agent_response_was_final=False,
                                     agent_id=agent_id)
            pipeline = AgentPipeline(
                "task", SimpleNamespace(), llm_client_factory=SimpleNamespace(
                    _fbv2_campaign_gate=gate))
            result = pipeline._settled_local_verifier_limit(
                client, SimpleNamespace(stop_reason="max_iterations"), owner)
            self.assertEqual(result, 1 if successful else None)

    async def test_parallel_cancelled_transport_blocks_later_work(self):
        entered = asyncio.Event()

        class PendingTransport:
            async def generate(self, request):
                entered.set()
                await asyncio.Future()

            async def close(self):
                pass

        wrapped = CampaignLedgeredProvider(PendingTransport(), self.gate,
                                           role="sp", owner_id="function-A")
        task = asyncio.create_task(wrapped.generate(request("sp")))
        await asyncio.wait_for(entered.wait(), timeout=2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.gate.snapshot()["records"][0]["status"],
                         "UNCERTAIN")
        with self.assertRaises(CampaignUncertain):
            self.gate.reserve(request_id="later", role="pov",
                              owner_id="candidate-B", request_sha256="a" * 64)

    async def test_campaign_factory_serializes_entire_injected_agent_invocation(self):
        from fuzzingbrain.worker.pipeline import injected_agent_client

        first_entered = asyncio.Event()
        finish_first = asyncio.Event()
        first_closing = asyncio.Event()
        finish_close = asyncio.Event()
        second_entered = asyncio.Event()

        class Bridge:
            def __init__(self, role, owner):
                self.role = role
                self.owner = owner
                self.provider = InspectingTransport(self_gate)

            async def close(self):
                if self.owner == "first":
                    first_closing.set()
                    await finish_close.wait()

        self_gate = self.gate
        factory = wrap_campaign_client_factory(
            self.gate, lambda role, owner: Bridge(role, owner))

        async def first():
            async with injected_agent_client(factory, "sp", "first"):
                first_entered.set()
                await finish_first.wait()

        async def second():
            async with injected_agent_client(factory, "verifier", "second"):
                second_entered.set()

        first_task = asyncio.create_task(first())
        await asyncio.wait_for(first_entered.wait(), timeout=1)
        second_task = asyncio.create_task(second())
        await asyncio.sleep(0)
        self.assertFalse(second_entered.is_set())

        finish_first.set()
        await asyncio.wait_for(first_closing.wait(), timeout=1)
        await asyncio.sleep(0)
        self.assertFalse(second_entered.is_set())

        finish_close.set()
        await asyncio.wait_for(asyncio.gather(first_task, second_task), timeout=1)
        self.assertTrue(second_entered.is_set())

    async def test_late_response_after_suppressed_cancellation_is_uncertain(self):
        short = CampaignModelGate(self.path.with_name("short.json"),
                                  "public-md4c-short", 2, 0.2, create=True)

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
