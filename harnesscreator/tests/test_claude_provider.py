import asyncio
import types
import unittest

import anthropic
import httpx2 as httpx

from harnesscreator.cli import _resolve_claude_models, build_parser
from harnesscreator.llm import is_terminal_llm_infrastructure_error
from harnesscreator.llm.claude import ClaudeProvider
from harnesscreator.llm.codex_app_server import CodexAppServerError

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}},
          "required": ["ok"], "additionalProperties": False}


def message(text, stop_reason="end_turn", thinking=True):
    blocks = []
    if thinking:
        blocks.append(types.SimpleNamespace(type="thinking", thinking="", signature="sig"))
    blocks.append(types.SimpleNamespace(type="text", text=text))
    usage = types.SimpleNamespace(input_tokens=10, output_tokens=5,
                                  cache_read_input_tokens=3, cache_creation_input_tokens=0)
    return types.SimpleNamespace(content=blocks, stop_reason=stop_reason, usage=usage,
                                 stop_details=types.SimpleNamespace(category="cyber"))


def status_error(cls, status):
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls("boom", response=httpx.Response(status, request=request), body=None)


class ClaudeTests(unittest.IsolatedAsyncioTestCase):
    def provider(self):
        return ClaudeProvider(role_models={"a": "claude-haiku-5-5"}, role_efforts={"a": "high"})

    async def call(self, p, role="a", session="one"):
        return await p.complete_json(role=role, instructions="test", payload={},
                                     output_schema=SCHEMA, session_key=session)

    async def test_request_shape_retry_and_sessions(self):
        p = self.provider()
        seen = []
        answers = iter(['{"ok":"wrong"}', '{"ok":true}', '{"ok":false}'])

        async def request(body):
            seen.append({**body, "messages": list(body["messages"])})
            return message(next(answers))
        p._request = request
        self.assertEqual(await self.call(p), {"ok": True})
        self.assertEqual(await self.call(p), {"ok": False})
        first = seen[0]
        self.assertEqual(first["model"], "claude-haiku-5-5")
        self.assertEqual(first["output_config"]["effort"], "high")
        self.assertEqual(first["output_config"]["format"], {"type": "json_schema", "schema": SCHEMA})
        self.assertEqual(first["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("thinking", first)
        self.assertNotIn("temperature", first)
        # The repair turn replays the assistant content unchanged, thinking block first.
        self.assertEqual(seen[1]["messages"][1]["content"][0].type, "thinking")
        self.assertIn("did not match", seen[1]["messages"][2]["content"])
        # The second call continues the same session append-only.
        self.assertEqual(seen[2]["messages"][:4], seen[1]["messages"] + [
            {"role": "assistant", "content": seen[2]["messages"][3]["content"]}])
        self.assertEqual(p.usage["calls"], 3)
        self.assertEqual(p.usage["cache_read_input_tokens"], 9)
        with self.assertRaises(CodexAppServerError):
            await self.call(p, role="b")
        await p.close_session("one")
        self.assertNotIn("one", p._sessions)

    async def test_invalid_twice_is_rejected(self):
        p = self.provider()

        async def request(body):
            return message('{"ok":"bad"}')
        p._request = request
        with self.assertRaisesRegex(CodexAppServerError, "schema validation"):
            await self.call(p)
        self.assertNotIn("one", p._sessions)

    async def test_refusal_and_truncation_are_errors(self):
        p = self.provider()

        async def refused(body):
            return message("", stop_reason="refusal")
        p._request = refused
        with self.assertRaisesRegex(CodexAppServerError, "refusal, category=cyber"):
            await self.call(p)

        async def truncated(body):
            return message('{"ok":', stop_reason="max_tokens")
        p._request = truncated
        with self.assertRaisesRegex(CodexAppServerError, "max_tokens"):
            await self.call(p)

    async def test_unsupported_schema_falls_back_to_prompt(self):
        p = self.provider()
        seen = []

        async def request(body):
            seen.append({**body, "messages": list(body["messages"])})
            if "format" in body.get("output_config", {}):
                raise status_error(anthropic.BadRequestError, 400)
            return message('{"ok":true}')
        p._request = request
        self.assertEqual(await self.call(p, session=None), {"ok": True})
        self.assertEqual(await self.call(p, session=None), {"ok": True})
        # One rejected structured attempt, then prompt-only for this schema.
        self.assertEqual(["format" in b["output_config"] for b in seen], [True, False, False])
        self.assertIn("conforming to this schema", seen[1]["messages"][-1]["content"])

    async def test_api_errors_are_wrapped(self):
        p = self.provider()

        async def unauthenticated(body):
            raise status_error(anthropic.AuthenticationError, 401)
        p._request = unauthenticated
        with self.assertRaises(CodexAppServerError) as caught:
            await self.call(p)
        self.assertTrue(is_terminal_llm_infrastructure_error(caught.exception))

        async def limited(body):
            raise status_error(anthropic.RateLimitError, 429)
        p._request = limited
        with self.assertRaises(CodexAppServerError) as caught:
            await self.call(p)
        self.assertFalse(is_terminal_llm_infrastructure_error(caught.exception))


class ClaudeCliTests(unittest.TestCase):
    def test_default_routes_every_role_to_haiku(self):
        args = build_parser().parse_args(["run", "/tmp/project", "--provider", "claude"])
        models = _resolve_claude_models(args)
        self.assertTrue(models)
        self.assertEqual(set(models.values()), {"claude-haiku-5-5"})

    def test_overrides(self):
        args = build_parser().parse_args([
            "run", "/tmp/project", "--provider", "claude",
            "--coding-model", "claude-sonnet-5-5"])
        models = _resolve_claude_models(args)
        self.assertEqual(models["harness_generator"], "claude-sonnet-5-5")
        self.assertEqual(models["entry_generator"], "claude-haiku-5-5")


if __name__ == "__main__":
    unittest.main()
