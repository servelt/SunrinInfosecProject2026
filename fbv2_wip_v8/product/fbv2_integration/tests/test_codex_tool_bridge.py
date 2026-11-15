"""Provider-free contract tests for the opt-in Codex/FuzzingBrain bridge."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


# Import this small module directly: the original llms package eagerly imports
# live provider SDKs, which are intentionally absent from this isolated test.
MODULE_PATH = (Path(__file__).resolve().parents[1] / "fuzzingbrain" / "llms" /
               "codex_tool_bridge.py")
spec = importlib.util.spec_from_file_location("fbv2_codex_tool_bridge", MODULE_PATH)
assert spec is not None and spec.loader is not None
bridge_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bridge_module
spec.loader.exec_module(bridge_module)

CodexToolBridge = bridge_module.CodexToolBridge
CodexBridgeProtocolError = bridge_module.CodexBridgeProtocolError
CodexBridgeBudgetExceeded = bridge_module.CodexBridgeBudgetExceeded


class FakeProvider:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.closed = False

    async def generate(self, request):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def close(self):
        self.closed = True


def request(**kwargs):
    return SimpleNamespace(**kwargs)


READ_SOURCE = {"type": "function", "function": {
    "name": "read_source", "description": "Read a pinned source span",
    "parameters": {"type": "object", "properties": {
        "path": {"type": "string"}}, "required": ["path"],
        "additionalProperties": False}}}


class CodexToolBridgeTests(unittest.IsolatedAsyncioTestCase):
    def make_bridge(self, provider, **kwargs):
        return CodexToolBridge(provider, request, codex_model="test-codex",
                               role="fbv2_direction", max_calls=2, **kwargs)

    async def test_tool_proposal_has_original_agent_response_shape(self):
        provider = FakeProvider({"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"parser.c"}'}]})
        bridge = self.make_bridge(provider)
        history = [{"role": "system", "content": "Plan directions"},
                   {"role": "user", "content": "Analyze this function"}]
        response = await bridge.acall_with_tools(history, [READ_SOURCE],
                                                  model="claude-sonnet-4-5",
                                                  temperature=0.2)
        self.assertEqual(response.model, "test-codex")
        self.assertEqual(response.tool_calls[0]["function"]["name"], "read_source")
        self.assertEqual(json.loads(response.tool_calls[0]["function"]["arguments"]),
                         {"path": "parser.c"})
        sent = provider.requests[0]
        self.assertEqual(sent.model, "test-codex")
        self.assertIsNone(sent.session_key)
        self.assertEqual(sent.payload["history"], history[1:])
        self.assertIn("Plan directions", sent.instructions)
        self.assertEqual(sent.payload["tools"][0]["name"], "read_source")
        self.assertEqual(sent.output_schema["properties"]["tool_calls"]["items"]
                         ["properties"]["arguments"], {"type": "string"})
        self.assertEqual(bridge.calls_attempted, 1)
        self.assertIs(bridge.last_agent_response_was_final, False)

    async def test_campaign_request_makes_host_tool_id_unique_across_agents(self):
        outcome = {"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"parser.c"}'}]}
        first_provider = FakeProvider(outcome)
        first_provider.last_request_id = "request-a"
        first_provider.last_response_evidence = {
            "status": "VERIFIED", "turn_id": "turn-a"}
        second_provider = FakeProvider(outcome)
        second_provider.last_request_id = "request-b"
        second_provider.last_response_evidence = {
            "status": "VERIFIED", "turn_id": "turn-b"}

        first = await self.make_bridge(first_provider).acall_with_tools(
            [{"role": "user", "content": "read"}], [READ_SOURCE])
        second = await self.make_bridge(second_provider).acall_with_tools(
            [{"role": "user", "content": "read"}], [READ_SOURCE])

        self.assertEqual(first.tool_calls[0]["id"], "bridge_request-a_0")
        self.assertEqual(second.tool_calls[0]["id"], "bridge_request-b_0")
        self.assertNotEqual(first.tool_calls[0]["id"], second.tool_calls[0]["id"])
        self.assertEqual(first.model_turn_id, "turn-a")
        self.assertEqual(second.lineage_status, "VERIFIED")

    async def test_verified_model_tool_result_requires_durable_audit_sink(self):
        outcome = {"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"parser.c"}'}]}
        provider = FakeProvider(outcome)
        provider.last_request_id = "request-a"
        provider.last_response_evidence = {
            "status": "VERIFIED", "turn_id": "turn-a"}
        bridge = self.make_bridge(provider)
        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "read"}], [READ_SOURCE])
        with self.assertRaisesRegex(CodexBridgeProtocolError, "audit sink"):
            bridge.audit_tool_start(response, response.tool_calls[0])

        recorded = []
        bridge.agent_id = "0123456789abcdef01234567"
        provider.begin_tool_result = lambda *args, **kwargs: recorded.append(
            ("STARTED", args, kwargs))
        provider.complete_tool_result = lambda *args: recorded.append(("COMPLETED", args))
        bridge.audit_tool_start(response, response.tool_calls[0])
        bridge.audit_tool_result(response, response.tool_calls[0], "source")
        self.assertEqual(recorded, [
            ("STARTED", ("request-a", response.tool_calls[0]),
             {"agent_id": bridge.agent_id}),
            ("COMPLETED", ("request-a", response.tool_calls[0]["id"], "source"))])

    async def test_campaign_unproven_response_cannot_issue_host_tool_call(self):
        provider = FakeProvider({"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"parser.c"}'}]})
        provider.requires_response_lineage = True
        provider.last_request_id = "request-a"
        provider.last_response_evidence = {
            "status": "UNPROVEN", "reason": "MISSING_EVENT"}
        bridge = self.make_bridge(provider)

        with self.assertRaisesRegex(CodexBridgeProtocolError,
                                    "no verified App Server lineage"):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "read"}], [READ_SOURCE])
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(bridge.calls_attempted, 1)

    async def test_invalid_arguments_never_become_executable_tool_calls(self):
        provider = FakeProvider({"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"unexpected":"x"}'}]})
        bridge = self.make_bridge(provider)
        with self.assertRaises(CodexBridgeProtocolError):
            await bridge.acall_with_tools([{"role": "user", "content": "read"}],
                                          [READ_SOURCE])
        self.assertEqual(bridge.calls_attempted, 1)

    async def test_unadvertised_tool_is_rejected(self):
        provider = FakeProvider({"content": "", "tool_calls": [
            {"name": "write_file", "arguments": '{"path":"parser.c"}'}]})
        bridge = self.make_bridge(provider)
        with self.assertRaises(CodexBridgeProtocolError):
            await bridge.acall_with_tools([{"role": "user", "content": "read"}],
                                          [READ_SOURCE])

    async def test_failed_physical_turn_consumes_cap_and_is_not_retried(self):
        provider = FakeProvider(RuntimeError("uncertain remote turn"),
                                {"content": "done", "tool_calls": []})
        bridge = CodexToolBridge(provider, request, codex_model="test-codex",
                                 role="fbv2_sp", max_calls=1)
        with self.assertRaisesRegex(RuntimeError, "uncertain remote turn"):
            await bridge.acall([{"role": "user", "content": "analyze"}])
        with self.assertRaises(CodexBridgeBudgetExceeded):
            await bridge.acall([{"role": "user", "content": "analyze"}])
        self.assertEqual(len(provider.requests), 1)

    async def test_compression_call_uses_no_tools_and_result_is_plain_text(self):
        provider = FakeProvider({"content": "summary", "tool_calls": []})
        bridge = self.make_bridge(provider)
        response = await bridge.acall([{"role": "user", "content": "compress"}],
                                      max_tokens=2000)
        self.assertEqual(response.content, "summary")
        self.assertEqual(response.tool_calls, [])
        self.assertIsNone(bridge.last_agent_response_was_final)
        self.assertEqual(provider.requests[0].output_schema["properties"]
                         ["tool_calls"]["maxItems"], 0)
        self.assertNotIn("enum", provider.requests[0].output_schema
                         ["properties"]["tool_calls"]["items"]
                         ["properties"]["name"])

    async def test_tool_choice_none_rejects_proposed_call(self):
        provider = FakeProvider({"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"parser.c"}'}]})
        bridge = self.make_bridge(provider)
        with self.assertRaises(CodexBridgeProtocolError):
            await bridge.acall_with_tools([{"role": "user", "content": "read"}],
                                          [READ_SOURCE], tool_choice="none")

    async def test_tool_arguments_must_be_json_object(self):
        for raw in ("not json", "[]", "null"):
            provider = FakeProvider({"content": "", "tool_calls": [
                {"name": "read_source", "arguments": raw}]})
            bridge = self.make_bridge(provider)
            with self.assertRaises(CodexBridgeProtocolError):
                await bridge.acall_with_tools(
                    [{"role": "user", "content": "read"}], [READ_SOURCE])

    async def test_direction_completion_contract_is_only_added_when_tool_advertised(self):
        provider = FakeProvider({"content": "no plan", "tool_calls": []})
        bridge = CodexToolBridge(provider, request, codex_model="test-codex",
                                 role="direction", max_calls=1)
        create_tool = {"type": "function", "function": {
            "name": "create_direction", "parameters": {
                "type": "object", "properties": {},
                "additionalProperties": False}}}
        await bridge.acall_with_tools([{"role": "user", "content": "plan"}],
                                      [READ_SOURCE, create_tool])
        self.assertIn("create_direction tool result confirming persistence",
                      provider.requests[0].instructions)
        self.assertIn("get_call_graph first when that tool is advertised",
                      provider.requests[0].instructions)

        no_create = FakeProvider({"content": "no plan", "tool_calls": []})
        bridge = CodexToolBridge(no_create, request, codex_model="test-codex",
                                 role="direction", max_calls=1)
        await bridge.acall_with_tools([{"role": "user", "content": "plan"}],
                                      [READ_SOURCE])
        self.assertNotIn("create_direction tool result confirming persistence",
                         no_create.requests[0].instructions)


if __name__ == "__main__":
    unittest.main()
