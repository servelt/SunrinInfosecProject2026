"""Product HP roles use the existing FBv2 campaign debit and response proof."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from devtools.campaign_model_gate import (
    CampaignLedgeredProvider, CampaignModelGate, CampaignPendingBudget,
    CampaignUncertain, product_campaign_client_factory,
)
import devtools.campaign_model_gate as campaign_model_gate


def test_signed_campaign_timeout_reaches_transport_and_keeps_default(tmp_path,
                                                                     monkeypatch):
    gate = CampaignModelGate(tmp_path / "campaign-timeout.json", "timeout", 2,
                             900, create=True)
    events = tmp_path / "events"
    events.mkdir()
    observed = []

    def bridge_factory(**kwargs):
        observed.append(kwargs)
        return SimpleNamespace(role=kwargs["role"], provider=SimpleNamespace())

    monkeypatch.setattr("fuzzingbrain.llms.codex_tool_bridge.product_codex_bridge",
                        bridge_factory)
    common = dict(cwd=tmp_path, codex_model="fixture", max_calls_per_agent=1,
                  executable="codex", executable_sha256="a" * 64,
                  event_log_dir=events, response_stream_limit_bytes=2_000_000)
    signed = product_campaign_client_factory(
        gate, **common, turn_timeout_seconds=900)
    signed("direction", "owner")
    assert observed[-1]["timeout_seconds"] == 900
    assert observed[-1]["response_stream_limit_bytes"] == 2_000_000
    ordinary = product_campaign_client_factory(gate, **common)
    ordinary("direction", "owner-2")
    assert observed[-1]["timeout_seconds"] == 300
    for invalid in (901, float("nan"), 0):
        with pytest.raises(ValueError, match="invalid campaign"):
            product_campaign_client_factory(
                gate, **common, turn_timeout_seconds=invalid)


PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))
from vulnerabilityanalysis.llm import LLMRequest


class ProductHPTransportFixture:
    """Produce product App Server artifacts locally, without model traffic."""

    def __init__(self, event_log_path: Path, *, fail_after_start: bool = False):
        self.event_log_path = event_log_path
        self.fail_after_start = fail_after_start
        self.calls = 0

    async def generate(self, request: LLMRequest) -> dict:
        assert type(request) is LLMRequest
        self.calls += 1
        if self.fail_after_start:
            raise RuntimeError("fixture transport lost its response")
        assert request.raw_response_path is not None
        result = {"role": request.role, "fixture": "provider-free"}
        raw = json.dumps(result, sort_keys=True).encode()
        descriptor = os.open(request.raw_response_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
        thread = f"thread-{request.role}"
        turn = f"turn-{request.role}"
        events = [
            {"method": "turn/started", "thread_id": thread,
             "turn_id": turn},
            {"method": "item/completed", "item_type": "agentMessage",
             "thread_id": thread, "turn_id": turn,
             "agent_message_sha256": hashlib.sha256(raw).hexdigest()},
            {"method": "turn/completed", "thread_id": thread,
             "turn_id": turn, "turn_status": "completed"},
        ]
        descriptor = os.open(self.event_log_path,
                             os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            for event in events:
                output.write(json.dumps(event, sort_keys=True).encode() + b"\n")
        return result

    async def close(self):
        pass


def _request(role: str) -> LLMRequest:
    return LLMRequest(role=role, instructions="fixture", payload={"x": 1},
                      output_schema={"type": "object"},
                      model="fixture", effort="low")


def test_product_hp_roles_share_model_budget_and_verified_event_evidence(tmp_path):
    gate = CampaignModelGate(tmp_path / "campaign.json", "hp-fixture", 2, 60,
                             create=True)
    function_transport = ProductHPTransportFixture(tmp_path / "function.jsonl")
    assertion_transport = ProductHPTransportFixture(tmp_path / "assertion.jsonl")
    function = CampaignLedgeredProvider(function_transport, gate,
                                         role="function_analysis", owner_id="func:direction")
    assertion = CampaignLedgeredProvider(assertion_transport, gate,
                                          role="assertion_generator", owner_id="func:direction")

    async def run():
        assert (await function.generate(_request("function_analysis")))["fixture"] == "provider-free"
        assert (await assertion.generate(_request("assertion_generator")))["fixture"] == "provider-free"
        with pytest.raises(CampaignPendingBudget):
            await function.generate(_request("function_analysis"))

    asyncio.run(run())
    assert function_transport.calls == assertion_transport.calls == 1
    assert gate.snapshot()["physical"] == 2
    assert gate.verify_response_evidence(assertion.last_request_id)["status"] == "VERIFIED"
    # Budget refusal clears the function wrapper's last-success pointer.
    assert function.last_request_id is None
    first = gate.snapshot()["records"][0]
    assert first["role"] == "function_analysis"
    assert gate.verify_response_evidence(first["request_id"])["status"] == "VERIFIED"


def test_uncertain_product_hp_turn_blocks_other_role_before_transport(tmp_path):
    gate = CampaignModelGate(tmp_path / "campaign.json", "hp-uncertain", 2, 60,
                             create=True)
    function_transport = ProductHPTransportFixture(
        tmp_path / "function.jsonl", fail_after_start=True)
    assertion_transport = ProductHPTransportFixture(tmp_path / "assertion.jsonl")
    function = CampaignLedgeredProvider(function_transport, gate,
                                         role="function_analysis", owner_id="func:direction")
    assertion = CampaignLedgeredProvider(assertion_transport, gate,
                                          role="assertion_generator", owner_id="func:direction")

    async def run():
        with pytest.raises(CampaignUncertain):
            await function.generate(_request("function_analysis"))
        with pytest.raises(CampaignUncertain):
            await assertion.generate(_request("assertion_generator"))

    asyncio.run(run())
    assert function_transport.calls == 1
    assert assertion_transport.calls == 0
    assert gate.snapshot()["physical"] == 1


def test_sp_and_hp_model_turns_overlap_on_one_main_thread_gate(tmp_path):
    """The shared gate supports independent tracks in one asyncio loop."""
    gate = CampaignModelGate(tmp_path / "campaign.json", "sp-hp-overlap", 2, 60,
                             create=True)

    async def run():
        both_entered = asyncio.Event()
        releases = {"sp": asyncio.Event(), "function_analysis": asyncio.Event()}
        entered = []

        class HeldTransport(ProductHPTransportFixture):
            def __init__(self, role):
                super().__init__(tmp_path / f"{role}.jsonl")
                self.role = role

            async def generate(self, request):
                entered.append(self.role)
                if len(entered) == 2:
                    both_entered.set()
                await releases[self.role].wait()
                return await super().generate(request)

        sp_transport = HeldTransport("sp")
        hp_transport = HeldTransport("function_analysis")
        sp = CampaignLedgeredProvider(sp_transport, gate, role="sp",
                                      owner_id="sp:function-A")
        hp = CampaignLedgeredProvider(hp_transport, gate,
                                      role="function_analysis",
                                      owner_id="hp:function-B")
        tasks = [asyncio.create_task(sp.generate(_request("sp"))),
                 asyncio.create_task(hp.generate(_request("function_analysis")))]
        try:
            await asyncio.wait_for(both_entered.wait(), timeout=2)
            rows = gate.snapshot()["records"]
            assert [row["status"] for row in rows] == ["STARTED", "STARTED"]
            assert {row["role"] for row in rows} == {"sp", "function_analysis"}
            assert gate.snapshot()["physical"] == 2
        finally:
            releases["function_analysis"].set()
            releases["sp"].set()
        await asyncio.gather(*tasks)
        assert sp_transport.calls == hp_transport.calls == 1
        assert gate.verify_response_evidence(sp.last_request_id)["status"] == "VERIFIED"
        assert gate.verify_response_evidence(hp.last_request_id)["status"] == "VERIFIED"
        with pytest.raises(CampaignPendingBudget):
            await hp.generate(_request("function_analysis"))

    asyncio.run(run())


def test_parallel_hp_uncertain_blocks_new_admission_without_losing_sp_result(tmp_path):
    """A failed HP transport cannot erase an already admitted SP turn."""
    gate = CampaignModelGate(tmp_path / "campaign.json", "sp-hp-uncertain", 3,
                             60, create=True)

    async def run():
        sp_entered = asyncio.Event()
        release_sp = asyncio.Event()

        class HeldSP(ProductHPTransportFixture):
            async def generate(self, request):
                sp_entered.set()
                await release_sp.wait()
                return await super().generate(request)

        sp_transport = HeldSP(tmp_path / "sp.jsonl")
        hp_transport = ProductHPTransportFixture(
            tmp_path / "hp.jsonl", fail_after_start=True)
        later_transport = ProductHPTransportFixture(tmp_path / "later.jsonl")
        sp = CampaignLedgeredProvider(sp_transport, gate, role="sp",
                                      owner_id="sp:function-A")
        hp = CampaignLedgeredProvider(hp_transport, gate,
                                      role="function_analysis",
                                      owner_id="hp:function-B")
        later = CampaignLedgeredProvider(later_transport, gate,
                                         role="assertion_generator",
                                         owner_id="hp:function-B")

        sp_task = asyncio.create_task(sp.generate(_request("sp")))
        try:
            await asyncio.wait_for(sp_entered.wait(), timeout=2)
            with pytest.raises(CampaignUncertain):
                await hp.generate(_request("function_analysis"))
            with pytest.raises(CampaignUncertain):
                await later.generate(_request("assertion_generator"))
        finally:
            release_sp.set()
        assert (await sp_task)["fixture"] == "provider-free"

        rows = gate.snapshot()["records"]
        assert len(rows) == 2
        assert {row["role"]: row["status"] for row in rows} == {
            "sp": "COMPLETED", "function_analysis": "UNCERTAIN"}
        assert gate.snapshot()["physical"] == 2
        assert gate.verify_response_evidence(sp.last_request_id)["status"] == "VERIFIED"
        assert sp_transport.calls == hp_transport.calls == 1
        assert later_transport.calls == 0

    asyncio.run(run())


def test_transport_admission_survives_backward_wall_clock_step(tmp_path,
                                                               monkeypatch):
    gate = CampaignModelGate(tmp_path / "campaign.json", "clock-step", 1, 60,
                             create=True)
    gate.reserve(request_id="request-clock", role="sp", owner_id="sp:one",
                 request_sha256="a" * 64)
    started = gate.snapshot()["records"][0]["started_at"]
    with monkeypatch.context() as patch:
        patch.setattr(campaign_model_gate.time, "time", lambda: started - 1)
        gate.confirm_transport_admission("request-clock")
    row = gate.snapshot()["records"][0]
    assert row["status"] == "STARTED"
    assert row["transport_started_at"] == started


def test_cancelled_hp_with_saved_response_stays_uncertain_and_preserves_sp(tmp_path):
    """Saved response bytes alone cannot settle a cancelled model transport."""
    gate = CampaignModelGate(tmp_path / "cancelled.json", "cancelled-hp", 3,
                             60, create=True)

    async def run():
        hp_artifacts_saved = asyncio.Event()
        release_sp = asyncio.Event()

        class HeldSP(ProductHPTransportFixture):
            async def generate(self, request):
                await release_sp.wait()
                return await super().generate(request)

        class CancelledAfterArtifacts(ProductHPTransportFixture):
            async def generate(self, request):
                await super().generate(request)
                hp_artifacts_saved.set()
                await asyncio.Future()

        sp = CampaignLedgeredProvider(
            HeldSP(tmp_path / "sp-events.jsonl"), gate,
            role="sp", owner_id="sp:one")
        hp = CampaignLedgeredProvider(
            CancelledAfterArtifacts(tmp_path / "hp-events.jsonl"), gate,
            role="function_analysis", owner_id="hp:one")
        later_transport = ProductHPTransportFixture(tmp_path / "later.jsonl")
        later = CampaignLedgeredProvider(
            later_transport, gate, role="assertion_generator", owner_id="hp:one")
        sp_task = asyncio.create_task(sp.generate(_request("sp")))
        hp_task = asyncio.create_task(hp.generate(_request("function_analysis")))
        try:
            await asyncio.wait_for(hp_artifacts_saved.wait(), timeout=2)
            hp_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await hp_task
            with pytest.raises(CampaignUncertain):
                await later.generate(_request("assertion_generator"))
        finally:
            release_sp.set()
            if not hp_task.done():
                hp_task.cancel()
            await asyncio.gather(hp_task, return_exceptions=True)
            await sp_task
        rows = gate.snapshot()["records"]
        assert {row["role"]: row["status"] for row in rows} == {
            "sp": "COMPLETED", "function_analysis": "UNCERTAIN"}
        assert gate.snapshot()["physical"] == 2
        assert hp.last_response_evidence is None
        assert hp.last_request_id is None
        assert later_transport.calls == 0
        assert gate.verify_response_evidence(sp.last_request_id)["status"] == "VERIFIED"
        hp_request_id = hp.issued_request_ids[0]
        assert gate.verify_response_evidence(hp_request_id)["status"] != "VERIFIED"

    asyncio.run(run())
