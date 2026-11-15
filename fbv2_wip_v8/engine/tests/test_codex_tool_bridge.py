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
CodexBridgeInvalidToolJSON = bridge_module.CodexBridgeInvalidToolJSON
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

CREATE_SEED = {"type": "function", "function": {
    "name": "create_seed", "description": "Create corpus seeds",
    "parameters": {"type": "object", "properties": {
        "generator_code": {"type": "string"},
        "num_seeds": {"type": "integer"}},
        "required": ["generator_code"], "additionalProperties": False}}}


class CodexToolBridgeTests(unittest.IsolatedAsyncioTestCase):
    def make_bridge(self, provider, **kwargs):
        return CodexToolBridge(provider, request, codex_model="test-codex",
                               role="fbv2_direction", max_calls=2, **kwargs)

    async def test_no_call_count_cap_still_counts_every_model_turn(self):
        provider = FakeProvider({"content": "first", "tool_calls": []},
                                {"content": "second", "tool_calls": []})
        bridge = CodexToolBridge(provider, request, codex_model="test-codex",
                                 role="fbv2_direction", max_calls=None)
        history = [{"role": "system", "content": "Plan directions"},
                   {"role": "user", "content": "Analyze the target"}]
        await bridge.acall_with_tools(history, [], model="test-codex")
        await bridge.acall_with_tools(history, [], model="test-codex")
        self.assertEqual(bridge.calls_attempted, 2)
        self.assertEqual(len(provider.requests), 2)

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

    async def test_seed_source_uses_direct_structured_fields_not_nested_json(self):
        source = (
            "def generate(seed_num: int) -> bytes:\n"
            "    return b'<div class=\"x\">' + b'\\x00'\n"
        )
        provider = FakeProvider({"content": "", "tool_calls": [{
            "name": "create_seed",
            "arguments": "{}",
            "seed_generator_code": source,
            "seed_num_seeds": 5,
        }]})
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="seed", max_calls=1)

        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "generate"}], [CREATE_SEED])

        arguments = json.loads(response.tool_calls[0]["function"]["arguments"])
        self.assertEqual(arguments, {
            "generator_code": source,
            "num_seeds": 5,
        })
        schema = provider.requests[0].output_schema["properties"][
            "tool_calls"]["items"]
        self.assertIn("seed_generator_code", schema["properties"])
        self.assertIn("seed_num_seeds", schema["required"])
        self.assertIn("nested JSON encoding", provider.requests[0].instructions)

    async def test_seed_read_only_tool_requires_empty_direct_seed_sentinels(self):
        provider = FakeProvider({"content": "", "tool_calls": [{
            "name": "read_source",
            "arguments": '{"path":"parser.c"}',
            "seed_generator_code": "",
            "seed_num_seeds": 0,
        }]})
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="seed", max_calls=1)

        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "read"}],
            [READ_SOURCE, CREATE_SEED])

        self.assertEqual(
            json.loads(response.tool_calls[0]["function"]["arguments"]),
            {"path": "parser.c"})

    async def test_seed_direct_fields_cannot_ambiguously_override_other_tool(self):
        provider = FakeProvider({"content": "", "tool_calls": [{
            "name": "read_source",
            "arguments": '{"path":"parser.c"}',
            "seed_generator_code": "def generate(n): return b'x'",
            "seed_num_seeds": 1,
        }]})
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="seed", max_calls=1)

        with self.assertRaises(CodexBridgeInvalidToolJSON):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "read"}],
                [READ_SOURCE, CREATE_SEED])

    async def test_direct_seed_requires_empty_legacy_argument_placeholder(self):
        provider = FakeProvider({"content": "", "tool_calls": [{
            "name": "create_seed",
            "arguments": '{"generator_code":"shadow"}',
            "seed_generator_code": "def generate(n): return b'x'",
            "seed_num_seeds": 1,
        }]})
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="seed", max_calls=1)

        with self.assertRaises(CodexBridgeInvalidToolJSON):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "generate"}], [CREATE_SEED])

    async def test_direct_seed_envelope_rejects_oversize_and_excess_count(self):
        outcomes = (
            {"content": "", "tool_calls": [{
                "name": "create_seed", "arguments": "{}",
                "seed_generator_code": "x" * (32 * 1024 + 1),
                "seed_num_seeds": 1,
            }]},
            {"content": "", "tool_calls": [{
                "name": "create_seed", "arguments": "{}",
                "seed_generator_code": "def generate(n): return b'x'",
                "seed_num_seeds": 17,
            }]},
        )
        for outcome in outcomes:
            provider = FakeProvider(outcome)
            bridge = CodexToolBridge(
                provider, request, codex_model="test-codex",
                role="seed", max_calls=1)
            with self.assertRaises(CodexBridgeProtocolError):
                await bridge.acall_with_tools(
                    [{"role": "user", "content": "generate"}], [CREATE_SEED])
            self.assertEqual(bridge.calls_attempted, 1)

    async def test_direct_seed_requires_exact_placeholder_and_valid_utf8(self):
        for arguments, source in (
            ("{ }", "def generate(n): return b'x'"),
            ("{}", "def generate(n): return 'bad\ud800'"),
        ):
            provider = FakeProvider({"content": "", "tool_calls": [{
                "name": "create_seed", "arguments": arguments,
                "seed_generator_code": source, "seed_num_seeds": 1,
            }]})
            bridge = CodexToolBridge(
                provider, request, codex_model="test-codex",
                role="seed", max_calls=1)
            with self.assertRaises(CodexBridgeInvalidToolJSON):
                await bridge.acall_with_tools(
                    [{"role": "user", "content": "generate"}], [CREATE_SEED])

    async def test_direct_seed_byte_cap_counts_utf8_bytes(self):
        provider = FakeProvider({"content": "", "tool_calls": [{
            "name": "create_seed", "arguments": "{}",
            "seed_generator_code": "가" * 10923,
            "seed_num_seeds": 1,
        }]})
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="seed", max_calls=1)
        with self.assertRaises(CodexBridgeInvalidToolJSON):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "generate"}], [CREATE_SEED])

    async def test_non_seed_role_cannot_advertise_create_seed(self):
        bridge = self.make_bridge(FakeProvider())
        with self.assertRaisesRegex(CodexBridgeProtocolError, "non-Seed role"):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "generate"}], [CREATE_SEED])

    async def test_malformed_second_seed_tool_keeps_valid_prefix_non_executable(self):
        provider = FakeProvider({"content": "", "tool_calls": [
            {"name": "create_seed", "arguments": "{}",
             "seed_generator_code": "def generate(n): return b'x'",
             "seed_num_seeds": 1},
            {"name": "read_source", "arguments": "not-json",
             "seed_generator_code": "", "seed_num_seeds": 0},
        ]})
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="seed", max_calls=1)

        with self.assertRaises(CodexBridgeProtocolError):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "generate"}],
                [CREATE_SEED, READ_SOURCE])
        # No response is returned, so BaseAgent cannot start the valid prefix.
        self.assertEqual(bridge.calls_attempted, 1)

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
            invalid = {"content": "", "tool_calls": [
                {"name": "read_source", "arguments": raw}]}
            provider = FakeProvider(*([invalid] * (2 if raw == "not json" else 1)))
            bridge = self.make_bridge(provider)
            with self.assertRaises(CodexBridgeProtocolError):
                await bridge.acall_with_tools(
                    [{"role": "user", "content": "read"}], [READ_SOURCE])
            self.assertEqual(len(provider.requests), 2 if raw == "not json" else 1)

    async def test_completed_invalid_json_gets_one_charged_correction_turn(self):
        provider = FakeProvider(
            {"content": "", "tool_calls": [
                {"name": "read_source", "arguments": r'{"path":"\s"}'}]},
            {"content": "", "tool_calls": [
                {"name": "read_source", "arguments": r'{"path":"\\s"}'}]},
        )
        bridge = self.make_bridge(provider)

        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "read"}], [READ_SOURCE])

        self.assertEqual(bridge.calls_attempted, 2)
        self.assertEqual(len(response.tool_calls), 1)
        self.assertEqual(json.loads(response.tool_calls[0]["function"]
                                    ["arguments"]), {"path": r"\s"})
        retry_history = provider.requests[1].payload["history"]
        self.assertEqual(retry_history[-1]["role"], "user")
        self.assertIn("before any host tool ran", retry_history[-1]["content"])
        self.assertFalse(any(item["role"] == "tool" for item in retry_history))

    async def test_repeated_extra_data_gets_second_bounded_correction_turn(self):
        malformed = {"content": "reasoning", "tool_calls": [
            {"name": "read_source",
             "arguments": '{"path":"parser.c"} trailing commentary'}]}
        provider = FakeProvider(
            malformed,
            malformed,
            {"content": "", "tool_calls": [
                {"name": "read_source",
                 "arguments": '{"path":"parser.c"}'}]},
        )
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="fbv2_direction", max_calls=3)

        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "read"}], [READ_SOURCE])

        self.assertEqual(bridge.calls_attempted, 3)
        self.assertEqual(len(provider.requests), 3)
        self.assertEqual(json.loads(response.tool_calls[0]["function"]
                                    ["arguments"]), {"path": "parser.c"})
        for correction_request in provider.requests[1:]:
            history = correction_request.payload["history"]
            sanitized = history[-2]["content"]
            correction = history[-1]
            self.assertEqual(correction["role"], "user")
            self.assertIn("Extra data", correction["content"])
            self.assertIn("complete intended tool_calls", correction["content"])
            self.assertIn("<INVALID_JSON_OMITTED>", sanitized)
            self.assertNotIn("trailing commentary", sanitized)

    async def test_persistently_invalid_extra_data_stops_without_tool_call(self):
        malformed = {"content": "", "tool_calls": [
            {"name": "read_source",
             "arguments": '{"path":"parser.c"} trailing'}]}
        provider = FakeProvider(malformed, malformed, malformed)
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="fbv2_direction", max_calls=3)

        with self.assertRaises(CodexBridgeProtocolError):
            await bridge.acall_with_tools(
                [{"role": "user", "content": "read"}], [READ_SOURCE])

        self.assertEqual(bridge.calls_attempted, 3)
        self.assertEqual(len(provider.requests), 3)

    async def test_correction_sanitizes_failed_member_but_preserves_valid_calls(self):
        malformed = {"content": "do not reflect this narrative", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"first.c"}'},
            {"name": "read_source",
             "arguments": '{"path":"second.c"} trailing meta-loop'},
        ]}
        corrected = {"content": "", "tool_calls": [
            {"name": "read_source", "arguments": '{"path":"first.c"}'},
            {"name": "read_source", "arguments": '{"path":"second.c"}'},
        ]}
        provider = FakeProvider(malformed, corrected)
        bridge = CodexToolBridge(
            provider, request, codex_model="test-codex",
            role="fbv2_direction", max_calls=2)

        response = await bridge.acall_with_tools(
            [{"role": "user", "content": "read both"}], [READ_SOURCE])

        self.assertEqual(len(response.tool_calls), 2)
        history = provider.requests[1].payload["history"]
        sanitized = json.loads(history[-2]["content"])
        self.assertEqual(
            json.loads(sanitized["tool_calls"][0]["arguments"]),
            {"path": "first.c"})
        self.assertEqual(sanitized["tool_calls"][1]["arguments"],
                         "<INVALID_JSON_OMITTED>")
        self.assertNotIn("trailing meta-loop", history[-2]["content"])
        self.assertNotIn("do not reflect this narrative", history[-2]["content"])
        self.assertIn("tool_calls[1]", history[-1]["content"])

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
