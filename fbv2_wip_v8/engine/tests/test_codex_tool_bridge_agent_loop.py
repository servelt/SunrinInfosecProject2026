"""Exercise the FuzzingBrain MCP loop with the Codex bridge."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fuzzingbrain.agents.base import BaseAgent
from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge
from fuzzingbrain.llms.codex_tool_bridge import CodexBridgeProtocolError
from devtools.campaign_model_gate import CampaignPendingBudget, CampaignUncertain


READ_SOURCE = {"type": "function", "function": {
    "name": "read_source", "description": "Read pinned source",
    "parameters": {"type": "object", "properties": {
        "path": {"type": "string"}}, "required": ["path"],
        "additionalProperties": False}}}


class FakeProvider:
    def __init__(self):
        self.requests = []
        self.responses = [
            {"content": "", "tool_calls": [
                {"name": "read_source", "arguments": '{"path":"parser.c"}'}]},
            {"content": "Direction complete", "tool_calls": []},
        ]

    async def generate(self, request):
        self.requests.append(request)
        return self.responses.pop(0)

    async def close(self):
        pass


class IsolatedAgent(BaseAgent):
    enable_context_compression = False

    @property
    def system_prompt(self):
        return "Plan a direction from the source evidence"

    def get_initial_message(self, **kwargs):
        return "Read the pinned source"

    async def _get_tools(self, client):
        return [READ_SOURCE]

    async def _execute_tool(self, client, tool_name, tool_args):
        self.executed.append((tool_name, tool_args))
        return "int parse(void) { return 0; }"


def test_original_agent_loop_executes_only_validated_proposal():
    provider = FakeProvider()
    bridge = CodexToolBridge(provider, lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=2)
    agent = IsolatedAgent(llm_client=bridge, max_iterations=3, verbose=False)
    agent.executed = []
    logged = []
    agent._log = lambda message, **_kwargs: logged.append(message)

    answer = asyncio.run(agent._run_agent_loop(None, "Read the pinned source"))

    assert answer == "Direction complete"
    assert agent.executed == [("read_source", {"path": "parser.c"})]
    assert agent.total_tool_calls == 1
    assert bridge.calls_attempted == 2
    assert "Using model: test-codex" in logged
    assert agent.messages[-1] == {
        "role": "assistant", "content": "Direction complete"}
    assert provider.requests[1].payload["history"][-1] == {
        "role": "tool", "tool_call_id": "bridge_1_0",
        "content": "int parse(void) { return 0; }"}


def test_run_async_persists_terminal_conversation_snapshot():
    provider = FakeProvider()
    bridge = CodexToolBridge(provider, lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=2)
    agent = IsolatedAgent(llm_client=bridge, max_iterations=3, verbose=False)
    terminal_seen = []

    def capture_terminal():
        terminal_seen.append((agent.end_time, agent.total_iterations))

    context = SimpleNamespace(
        agent_id="0123456789abcdef01234567",
        agent=None,
        iterations=0,
        tool_calls=0,
        result_summary=None,
        log_path=None,
    )
    context_manager = MagicMock()
    context_manager.__enter__.return_value = context
    context_manager.__exit__.return_value = False

    class NullClient:
        def __init__(self, _server):
            pass

        async def __aenter__(self):
            return None

        async def __aexit__(self, *_args):
            return False

    with patch.object(agent, "_setup_logging"), \
            patch.object(agent, "_run_agent_loop",
                         new=AsyncMock(return_value="done")), \
            patch.object(agent, "_log_conversation",
                         side_effect=capture_terminal), \
            patch("fuzzingbrain.agents.base.AgentContext",
                  return_value=context_manager), \
            patch("fuzzingbrain.agents.base.create_isolated_mcp_server",
                  return_value=object()), \
            patch("fuzzingbrain.agents.base.Client", NullClient):
        assert asyncio.run(agent.run_async()) == "done"

    assert len(terminal_seen) == 1
    assert terminal_seen[0][0] is not None


def test_campaign_turn_handoff_occurs_only_between_settled_agent_turns():
    provider = FakeProvider()
    bridge = CodexToolBridge(provider, lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=2)
    handoffs = []

    async def handoff():
        handoffs.append(len(provider.requests))

    bridge._fbv2_yield_campaign_turn = handoff
    agent = IsolatedAgent(llm_client=bridge, max_iterations=3, verbose=False)
    agent.executed = []

    assert asyncio.run(agent._run_agent_loop(None, "Read the pinned source")) == (
        "Direction complete")
    assert handoffs == [1]
    assert agent.executed == [("read_source", {"path": "parser.c"})]


def test_campaign_mcp_reply_loss_after_side_effect_is_not_completed():
    class LostReply:
        def __init__(self):
            self.side_effect_happened = False

        async def call_tool(self, _name, _args):
            self.side_effect_happened = True
            raise RuntimeError("MCP reply lost after side effect")

    bridge = CodexToolBridge(FakeProvider(),
                             lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_sp",
                             max_calls=2)
    bridge.provider.requires_response_lineage = True
    agent = IsolatedAgent(llm_client=bridge, max_iterations=2, verbose=False)
    client = LostReply()
    with pytest.raises(RuntimeError, match="reply lost"):
        asyncio.run(BaseAgent._execute_tool(
            agent, client, "create_suspicious_point", {"x": 1}))
    assert client.side_effect_happened is True


def test_original_loop_seals_lost_mcp_reply_before_next_model_turn():
    class ToolAgent(IsolatedAgent):
        _execute_tool = BaseAgent._execute_tool

    class LostReply:
        async def call_tool(self, _name, _args):
            raise RuntimeError("MCP reply lost")

    provider = FakeProvider()
    provider.requires_response_lineage = True
    provider.last_request_id = "request-a"
    provider.last_response_evidence = {
        "status": "VERIFIED", "turn_id": "turn-a"}
    events = []
    provider.begin_tool_result = lambda *_args, **_kwargs: events.append("STARTED")
    provider.fail_tool_result = lambda *_args: events.append("INCOMPLETE")
    provider.complete_tool_result = lambda *_args: events.append("COMPLETED")
    bridge = CodexToolBridge(provider, lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_sp",
                             max_calls=2)
    bridge.agent_id = "0123456789abcdef01234567"
    agent = ToolAgent(llm_client=bridge, max_iterations=2, verbose=False)
    with pytest.raises(RuntimeError, match="reply lost"):
        asyncio.run(agent._run_agent_loop(LostReply(), "source"))
    assert events == ["STARTED", "INCOMPLETE"]
    assert len(provider.requests) == 1


def test_original_agent_loop_audits_executed_tool_result_before_next_turn():
    provider = FakeProvider()
    bridge = CodexToolBridge(provider, lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=2)
    observed = []
    bridge.audit_tool_result = lambda response, call, result: observed.append(
        (response, call, result, len(provider.requests)))
    agent = IsolatedAgent(llm_client=bridge, max_iterations=3, verbose=False)
    agent.executed = []

    asyncio.run(agent._run_agent_loop(None, "Read the pinned source"))

    assert len(observed) == 1
    assert observed[0][1]["id"] == "bridge_1_0"
    assert observed[0][2] == "int parse(void) { return 0; }"
    assert observed[0][3] == 1


def test_verified_response_stops_when_tool_result_cannot_be_audited():
    provider = FakeProvider()
    provider.last_request_id = "request-a"
    provider.last_response_evidence = {"status": "VERIFIED", "turn_id": "turn-a"}
    bridge = CodexToolBridge(provider, lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=2)
    agent = IsolatedAgent(llm_client=bridge, max_iterations=3, verbose=False)
    agent.executed = []

    with pytest.raises(CodexBridgeProtocolError, match="audit sink"):
        asyncio.run(agent._run_agent_loop(None, "Read the pinned source"))

    assert len(provider.requests) == 1
    assert len(agent.executed) == 0


def test_model_error_is_not_a_completed_agent_loop():
    class ErrorProvider:
        async def generate(self, request):
            raise RuntimeError("budget exhausted")

        async def close(self):
            pass

    bridge = CodexToolBridge(ErrorProvider(),
                             lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=1)
    agent = IsolatedAgent(llm_client=bridge, max_iterations=2, verbose=False)
    agent.executed = []
    assert asyncio.run(agent._run_agent_loop(None, "source")) == ""
    assert agent.stop_reason == "llm_error"


def test_original_agent_loop_preserves_pretransport_and_uncertain_markers():
    for raised, expected in [
        (CampaignPendingBudget("cap reached"), "budget_before_transport"),
        (CampaignUncertain("remote state unknown"), "uncertain_remote"),
    ]:
        class RefusingProvider:
            async def generate(self, _request):
                raise raised

            async def close(self):
                pass

        bridge = CodexToolBridge(RefusingProvider(),
                                 lambda **kw: SimpleNamespace(**kw),
                                 codex_model="test-codex", role="fbv2_direction",
                                 max_calls=1)
        agent = IsolatedAgent(llm_client=bridge, max_iterations=2, verbose=False)
        agent.executed = []
        assert asyncio.run(agent._run_agent_loop(None, "source")) == ""
        assert agent.stop_reason == expected


def test_tool_only_last_iteration_is_not_a_completed_agent_loop():
    bridge = CodexToolBridge(FakeProvider(),
                             lambda **kw: SimpleNamespace(**kw),
                             codex_model="test-codex", role="fbv2_direction",
                             max_calls=1)
    agent = IsolatedAgent(llm_client=bridge, max_iterations=1, verbose=False)
    agent.executed = []
    asyncio.run(agent._run_agent_loop(None, "source"))
    assert agent.stop_reason == "max_iterations"
