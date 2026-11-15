"""An isolated PoV MCP tool must see its own AgentContext, not Worker context."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastmcp import Client

from fuzzingbrain.agents.pov_agent import POVAgent
from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server
from fuzzingbrain.tools.pov import clear_pov_context, get_pov_context


def _agent(agent_id: str, fuzzer: str, *, qualified: bool = False):
    agent = POVAgent(
        llm_client=MagicMock(), model="fixture", task_id="task",
        worker_id="shared-worker", fuzzer=fuzzer, sanitizer="address",
        repos=object(), fuzzer_code=f"source for {fuzzer}",
        qualified_runtime_required=qualified,
    )
    agent.suspicious_point = {"suspicious_point_id": f"sp-{agent_id}"}
    context = SimpleNamespace(agent_id=agent_id, sp_id=None)
    agent._context = context
    agent._configure_context(context)
    return agent


def test_pov_context_is_registered_under_isolated_agent_id():
    first = _agent("agent-first", "fuzz-first")
    second = _agent("agent-second", "fuzz-second", qualified=True)
    try:
        assert get_pov_context("shared-worker") == {}
        assert (get_pov_context("agent-first")["suspicious_point_id"] ==
                "sp-agent-first")
        assert (get_pov_context("agent-second")["suspicious_point_id"] ==
                "sp-agent-second")
        assert get_pov_context("agent-second")["qualified_runtime_required"] is True

        async def read_bound_tools():
            rows = []
            for agent in (first, second):
                server = create_isolated_mcp_server(
                    agent_id=agent.mcp_context_id,
                    worker_id=agent.mcp_context_id,
                    include_pov_tools=True,
                )
                async with Client(server) as client:
                    result = await client.call_tool("get_fuzzer_info", {})
                    rows.append(result.structured_content)
            return rows

        rows = asyncio.run(read_bound_tools())
        assert [row["success"] for row in rows] == [True, True]
        assert [row["fuzzer"] for row in rows] == ["fuzz-first", "fuzz-second"]
        assert [row["fuzzer_source"] for row in rows] == [
            "source for fuzz-first", "source for fuzz-second"]
    finally:
        clear_pov_context("agent-first")
        clear_pov_context("agent-second")


def test_pov_agent_clears_context_after_local_failure(monkeypatch):
    agent = POVAgent(
        llm_client=MagicMock(), model="fixture", task_id="task",
        worker_id="worker", fuzzer="fuzz", sanitizer="address",
        repos=object(), fuzzer_code="source")

    async def fail_after_context(**_kwargs):
        context = SimpleNamespace(agent_id="agent-failure", sp_id=None)
        agent._context = context
        agent._configure_context(context)
        raise RuntimeError("local fixture failure")

    monkeypatch.setattr(agent, "run_async", fail_after_context)
    result = asyncio.run(agent.generate_pov_async({
        "suspicious_point_id": "sp-failure"}))
    assert result.success is False
    assert get_pov_context("agent-failure") == {}
