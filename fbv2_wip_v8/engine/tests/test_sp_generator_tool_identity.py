"""The original SP agent must retain the ID returned by its create tool."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from bson import ObjectId

from fuzzingbrain.agents.base import BaseAgent
from fuzzingbrain.agents.sp_generators import FullSPGenerator


def test_created_sp_identity_matches_tool_result(monkeypatch):
    sp_id = str(ObjectId())

    async def created(_self, _client, _name, _args):
        return json.dumps({"success": True, "created": True, "id": sp_id})

    monkeypatch.setattr(BaseAgent, "_execute_tool", created)
    agent = FullSPGenerator(function_name="parse_input",
                            function_source="int parse_input(void) {return 0;}",
                            llm_client=object())
    asyncio.run(agent._execute_tool(
        None, "create_suspicious_point",
        {"function_name": "parse_input", "vuln_type": "out-of-bounds-read"}))

    assert agent.sp_created is True
    assert agent.sp_details["sp_id"] == sp_id


@pytest.mark.parametrize("payload", [
    [],
    7,
    {"success": False, "error": "suspicious point was not saved"},
    {"success": True},
    {"success": True, "created": True, "id": ""},
    {"success": True, "created": True, "merged": True,
     "id": str(ObjectId())},
])
def test_failed_or_ambiguous_create_receipt_is_terminal_after_audit(
        monkeypatch, payload):
    events = []

    class GateClient:
        def audit_tool_start(self, _response, _call):
            events.append("start")

        def audit_tool_result(self, _response, _call, result):
            events.append(("result", json.loads(result)))

        def audit_tool_error(self, _response, _call, _exc):
            events.append("error")

    async def returned(_self, _client, _name, _args):
        return json.dumps(payload)

    monkeypatch.setattr(BaseAgent, "_execute_tool", returned)
    agent = FullSPGenerator(
        function_name="parse_input",
        function_source="int parse_input(void) {return 0;}",
        llm_client=GateClient())
    call = {"id": "call-1", "function": {
        "name": "create_suspicious_point", "arguments": "{}"}}

    with pytest.raises(RuntimeError) as failed:
        asyncio.run(agent._execute_audited_tool(
            None, SimpleNamespace(), call, "create_suspicious_point",
            {"function_name": "parse_input"}))

    assert getattr(failed.value, "fbv2_stop_reason", None) == (
        "sp_persistence_failure")
    assert agent.stop_reason == "sp_persistence_failure"
    assert events == ["start", ("result", payload)]
    assert agent.sp_created is False


@pytest.mark.parametrize("kind", ["created", "merged"])
def test_persisted_create_or_merge_receipt_remains_successful(monkeypatch, kind):
    sp_id = str(ObjectId())
    payload = {"success": True, kind: True, "id": sp_id}

    async def returned(_self, _client, _name, _args):
        return json.dumps(payload)

    monkeypatch.setattr(BaseAgent, "_execute_tool", returned)
    agent = FullSPGenerator(
        function_name="parse_input",
        function_source="int parse_input(void) {return 0;}",
        llm_client=object())
    asyncio.run(agent._execute_tool(
        None, "create_suspicious_point", {"function_name": "parse_input"}))

    assert agent.sp_created is True
    assert agent.sp_persistence_failed is False
    assert agent.created_sp_ids == {sp_id}
