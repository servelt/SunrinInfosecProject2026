import json
import unittest

from harnesscreator.llm import is_terminal_llm_infrastructure_error
from harnesscreator.llm.claude_code import ClaudeCodeProvider
from harnesscreator.llm.codex_app_server import CodexAppServerError

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}},
          "required": ["ok"], "additionalProperties": False}


class FakeProcess:
    def __init__(self, role, results):
        self.role = role
        self.results = results
        self.prompts = []
        self.closed = False

    async def turn(self, prompt):
        self.prompts.append(prompt)
        return next(self.results)

    async def close(self):
        self.closed = True


def ok(text):
    return {"type": "result", "subtype": "success", "is_error": False, "result": text,
            "usage": {"input_tokens": 2, "output_tokens": 3, "cache_read_input_tokens": 5},
            "_rate_limit": {"status": "allowed"}}


class ClaudeCodeTests(unittest.IsolatedAsyncioTestCase):
    def provider(self, results):
        p = ClaudeCodeProvider(role_models={"a": "claude-haiku-5-5"}, role_efforts={"a": "high"})
        self.spawned = []
        shared = iter(results)

        async def spawn(role):
            worker = FakeProcess(role, shared)
            self.spawned.append(worker)
            return worker
        p._spawn = spawn
        return p

    async def call(self, p, role="a", session="one"):
        return await p.complete_json(role=role, instructions="test", payload={},
                                     output_schema=SCHEMA, session_key=session)

    async def test_command_isolates_the_cli(self):
        p = ClaudeCodeProvider(role_models={"a": "claude-haiku-5-5"}, role_efforts={"a": "high"})
        command = p._command("claude-haiku-5-5", "high")
        self.assertEqual(command[command.index("--model") + 1], "claude-haiku-5-5")
        self.assertEqual(command[command.index("--tools") + 1], "")
        self.assertEqual(command[command.index("--setting-sources") + 1], "")
        self.assertEqual(command[command.index("--effort") + 1], "high")
        self.assertIn("--strict-mcp-config", command)
        await p.close()

    async def test_session_reuses_one_process_and_repairs(self):
        p = self.provider([ok('{"ok":"wrong"}'), ok('{"ok":true}'), ok('```json\n{"ok":false}\n```')])
        self.assertEqual(await self.call(p), {"ok": True})
        self.assertEqual(await self.call(p), {"ok": False})
        self.assertEqual(len(self.spawned), 1)
        worker = self.spawned[0]
        self.assertIn("JSON_SCHEMA:", worker.prompts[0])
        self.assertIn("could not be used", worker.prompts[1])
        self.assertEqual(p.usage["calls"], 3)
        self.assertEqual(p.usage["cache_read_input_tokens"], 15)
        with self.assertRaises(CodexAppServerError):
            await self.call(p, role="b")
        await p.close_session("one")
        self.assertTrue(worker.closed)
        await p.close()

    async def test_sessionless_call_closes_its_process(self):
        p = self.provider([ok('{"ok":true}')])
        self.assertEqual(await self.call(p, session=None), {"ok": True})
        self.assertTrue(self.spawned[0].closed)
        await p.close()

    async def test_invalid_twice_drops_the_session(self):
        p = self.provider([ok('{"ok":"bad"}'), ok('{"ok":"bad"}')])
        with self.assertRaisesRegex(CodexAppServerError, "schema validation"):
            await self.call(p)
        self.assertNotIn("one", p._sessions)
        self.assertTrue(self.spawned[0].closed)
        await p.close()

    async def test_usage_limit_is_terminal(self):
        limited = {"type": "result", "subtype": "error_during_execution", "is_error": True,
                   "result": "limit reached",
                   "_rate_limit": {"status": "rejected", "rateLimitType": "five_hour", "resetsAt": 1}}
        p = self.provider([limited])
        with self.assertRaises(CodexAppServerError) as caught:
            await self.call(p)
        self.assertTrue(is_terminal_llm_infrastructure_error(caught.exception))
        await p.close()


class SelectAnswerTests(unittest.TestCase):
    SCHEMA = {"type": "object", "properties": {"ids": {"type": "array", "items": {"type": "string"}},
                                               "done": {"type": "boolean"}},
              "required": ["ids", "done"], "additionalProperties": False}

    def select(self, text):
        from jsonschema import Draft202012Validator
        from harnesscreator.llm.claude_code import _select_answer
        return _select_answer(text, Draft202012Validator(self.SCHEMA), self.SCHEMA)

    def test_answer_after_a_copy_of_the_schema_is_used(self):
        # Reply shape recorded from Claude Haiku 5.5 on 2026-11-15 (context_locator).
        copy = dict(self.SCHEMA)
        del copy["type"]
        text = json.dumps(copy) + "\n\n" + json.dumps({"ids": ["fn-a"], "done": True})
        self.assertEqual(self.select(text), {"ids": ["fn-a"], "done": True})

    def test_copy_of_the_schema_alone_is_not_an_answer(self):
        with self.assertRaisesRegex(ValueError, "no answer object"):
            self.select(json.dumps(self.SCHEMA))
        partial = dict(self.SCHEMA)
        del partial["type"]
        with self.assertRaisesRegex(ValueError, "required property"):
            self.select(json.dumps(partial))

    def test_two_different_answers_are_rejected_and_a_repeated_one_is_not(self):
        first, second = {"ids": [], "done": False}, {"ids": ["fn-a"], "done": True}
        with self.assertRaisesRegex(ValueError, "2 different answer objects"):
            self.select(json.dumps(first) + "\n" + json.dumps(second))
        self.assertEqual(self.select(json.dumps(second) + "\n" + json.dumps(second)), second)

    def test_fenced_answer_and_broken_json(self):
        self.assertEqual(self.select("```json\n" + json.dumps({"ids": [], "done": True}) + "\n```"),
                         {"ids": [], "done": True})
        with self.assertRaises(ValueError):
            self.select('{"ids": [], "done": tru')


if __name__ == "__main__":
    unittest.main()
