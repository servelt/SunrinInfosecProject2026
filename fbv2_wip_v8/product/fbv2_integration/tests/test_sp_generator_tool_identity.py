"""The original SP agent must retain the ID returned by its create tool."""

import asyncio
import json

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
