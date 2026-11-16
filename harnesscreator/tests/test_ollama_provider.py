import asyncio
import unittest
from harnesscreator.llm.ollama import OllamaProvider
from harnesscreator.llm.codex_app_server import CodexAppServerError

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}},
          "required": ["ok"], "additionalProperties": False}

class OllamaTests(unittest.IsolatedAsyncioTestCase):
    def provider(self):
        return OllamaProvider(role_models={"a": "glm", "b": "kimi"}, role_efforts={"a": "high", "b": None})

    async def call(self, p, role="a", session="one"):
        return await p.complete_json(role=role, instructions="test", payload={}, output_schema=SCHEMA, session_key=session)

    async def test_retry_and_sessions(self):
        p = self.provider()
        seen = []
        answers = iter(['{"ok":"wrong"}', '{"ok":true}', '{"ok":false}'])
        def request(body):
            seen.append((body['model'], body.get('think'), list(body['messages'])))
            return {"done": True, "message": {"content": next(answers)}}
        p._request = request
        self.assertEqual(await self.call(p), {"ok": True})
        self.assertEqual(await self.call(p), {"ok": False})
        self.assertEqual(seen[0][0:2], ("glm", "high"))
        self.assertIn('wrong', seen[1][2][-2]['content'])
        self.assertGreater(len(seen[2][2]), 2)
        with self.assertRaises(CodexAppServerError):
            await self.call(p, role="b")
        await p.close_session('one')
        self.assertNotIn('one', p._sessions)

    async def test_fenced_json_is_schema_validated(self):
        p = self.provider()
        requests = []
        def request(body):
            requests.append(body)
            return {"done": True, "message": {"content": "```json\n{\"ok\":true}\n```"}}
        p._request = request
        self.assertEqual(await self.call(p), {"ok": True})
        self.assertEqual(len(requests), 1)

    async def test_invalid_rejected(self):
        p = self.provider()
        p._request = lambda body: {"done": True, "message": {"content": '{"ok":"bad"}'}}
        with self.assertRaisesRegex(CodexAppServerError, 'schema validation'):
            await self.call(p)
        self.assertNotIn('one', p._sessions)

    async def test_roles_and_ephemeral(self):
        p = self.provider()
        requests = []
        def request(body):
            requests.append(body)
            return {"done": True, "message": {"content": '{"ok":true}'}}
        p._request = request
        await self.call(p, role="b", session=None)
        self.assertEqual(requests[0]['model'], 'kimi')
        self.assertIs(requests[0]['truncate'], False)
        self.assertIs(requests[0]['shift'], False)
        self.assertNotIn('think', requests[0])
        self.assertEqual(p._sessions, {})

if __name__ == '__main__':
    unittest.main()
