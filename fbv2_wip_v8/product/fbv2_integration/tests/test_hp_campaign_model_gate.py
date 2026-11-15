"""Product HP roles use the existing FBv2 campaign debit and response proof."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from devtools.campaign_model_gate import (
    CampaignLedgeredProvider, CampaignModelGate, CampaignPendingBudget,
    CampaignUncertain,
)


PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
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
