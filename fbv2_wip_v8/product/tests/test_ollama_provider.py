import asyncio
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from vulnerabilityanalysis.__main__ import configured_client
from vulnerabilityanalysis.llm import CodexAppServerClient, LLMRequest, OllamaCloudClient, OllamaCloudError


SCHEMA = {"type": "object", "properties": {"value": {"type": "integer"}},
          "required": ["value"], "additionalProperties": False}


class OllamaCloudClientTest(unittest.TestCase):
    def test_explicit_ollama_selection_keeps_existing_role_profile(self):
        config = yaml.safe_load((Path(__file__).resolve().parents[1] /
                                 "config/default.yaml").read_text(encoding="utf-8"))
        client, roles = configured_client(config, cwd=Path.cwd(), model=None, effort=None,
                                          provider_override="ollama-cloud")
        self.assertIsInstance(client, OllamaCloudClient)
        expected = {
            "direction_generator": ("glm-5.3-flash", "high"),
            "function_analysis": ("glm-5.3-flash", "high"),
            "sp_generation": ("glm-5.3-flash", "high"),
            "sp_verifier": ("glm-5.3", "low"),
            "poc_generator": ("glm-5.3", "max"),
            "assertion_generator": ("glm-5.3", "max"),
            "runtime_analysis": ("glm-5.3", "max"),
            "gdb_analysis": ("glm-5.3", "max"),
            "root_cause_verifier": ("glm-5.3", "max"),
        }
        self.assertEqual({role: (row["model"], row["reasoning"])
                          for role, row in roles.items()}, expected)

    def test_codex_provider_uses_role_equivalent_profile(self):
        config = yaml.safe_load((Path(__file__).resolve().parents[1] /
                                 "config/default.yaml").read_text(encoding="utf-8"))
        client, roles = configured_client(config, cwd=Path.cwd(), model=None, effort=None,
                                          provider_override="codex")
        self.assertIsInstance(client, CodexAppServerClient)
        expected = {
            "direction_generator": ("gpt-5.6-luna", "high"),
            "function_analysis": ("gpt-5.6-sol", "max"),
            "sp_generation": ("gpt-5.6-luna", "high"),
            "assertion_generator": ("gpt-5.6-sol", "max"),
            "sp_verifier": ("gpt-5.6-sol", "low"),
            "poc_generator": ("gpt-5.6-sol", "max"),
            "runtime_analysis": ("gpt-5.6-sol", "max"),
            "gdb_analysis": ("gpt-5.6-sol", "max"),
            "root_cause_verifier": ("gpt-5.6-sol", "max"),
        }
        self.assertEqual({role: (row["model"], row["reasoning"])
                          for role, row in roles.items()}, expected)
        self.assertEqual(client.effort, "medium")

    def test_default_provider_uses_codex_without_ollama_fallback(self):
        config = yaml.safe_load((Path(__file__).resolve().parents[1] /
                                 "config/default.yaml").read_text(encoding="utf-8"))
        client, roles = configured_client(config, cwd=Path.cwd(), model=None, effort=None,
                                          provider_override=None)
        self.assertIsInstance(client, CodexAppServerClient)
        self.assertEqual(roles, config["models"])

    def test_explicit_model_override_disables_role_profile(self):
        config = yaml.safe_load((Path(__file__).resolve().parents[1] /
                                 "config/default.yaml").read_text(encoding="utf-8"))
        client, roles = configured_client(config, cwd=Path.cwd(), model="glm-5.3",
                                          effort="low", provider_override="ollama-cloud")
        self.assertIsInstance(client, OllamaCloudClient)
        self.assertIsNone(roles)
        self.assertEqual((client.model, client.effort), ("glm-5.3", "low"))

    def test_cloud_chat_uses_verified_thinking_level_and_validates_json_locally(self):
        calls = []

        def urlopen(request, timeout):
            calls.append((request, timeout))
            if request.full_url.endswith("/show"):
                return io.BytesIO(json.dumps({"thinking": {
                    "values": ["low", "high", "max"], "default": "max"}}).encode())
            return io.BytesIO(json.dumps({"done": True, "message": {
                "role": "assistant", "content": '{"value":1}', "thinking": "reasoning"}}).encode())

        client = OllamaCloudClient(api_key="test-secret", model="glm-5.3", effort="low")
        request = LLMRequest("sp_verifier", "Verify source facts.", {"source": "x"}, SCHEMA,
                             model="glm-5.3-flash", effort="high")
        with patch("vulnerabilityanalysis.llm.urlopen", side_effect=urlopen):
            result = asyncio.run(client.generate(request))
        self.assertEqual(result, {"value": 1})
        self.assertEqual([row[0].full_url for row in calls],
                         ["https://ollama.com/api/show", "https://ollama.com/api/chat"])
        chat = json.loads(calls[1][0].data)
        self.assertEqual(chat["model"], "glm-5.3-flash")
        self.assertEqual(chat["think"], "high")
        self.assertFalse(chat["stream"])
        self.assertNotIn("format", chat)  # Cloud does not support schema-enforced output.
        self.assertIn('"required": ["value"]', chat["messages"][0]["content"])
        self.assertEqual(calls[1][0].get_header("Authorization"), "Bearer test-secret")

    def test_request_log_keeps_timing_and_usage_without_key_or_prompt(self):
        def urlopen(request, timeout):
            if request.full_url.endswith("/show"):
                return io.BytesIO(b'{"thinking":{"values":["low","high","max"]}}')
            return io.BytesIO(b'{"done":true,"message":{"content":"{\\"value\\":1}"},'
                              b'"prompt_eval_count":20,"eval_count":5}')

        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "llm_requests.jsonl"
            client = OllamaCloudClient(api_key="test-secret", model="glm-5.3-flash",
                                       effort="high", request_log_path=log_path)
            with patch("vulnerabilityanalysis.llm.urlopen", side_effect=urlopen):
                self.assertEqual(asyncio.run(client.generate(
                    LLMRequest("sp_generation", "private prompt", {}, SCHEMA))), {"value": 1})
            text = log_path.read_text(encoding="utf-8")
            events = [json.loads(line) for line in text.splitlines()]
            self.assertEqual([event["event"] for event in events], ["started", "completed"])
            self.assertEqual(events[-1]["prompt_eval_count"], 20)
            self.assertEqual(events[-1]["eval_count"], 5)
            self.assertNotIn("test-secret", text)
            self.assertNotIn("private prompt", text)

    def test_missing_key_fails_before_network(self):
        client = OllamaCloudClient(api_key="", model="glm-5.3-flash", effort="high")
        with patch("vulnerabilityanalysis.llm.urlopen") as urlopen:
            with self.assertRaisesRegex(OllamaCloudError, "OLLAMA_API_KEY"):
                asyncio.run(client.generate(LLMRequest("sp_generation", "", {}, SCHEMA)))
        urlopen.assert_not_called()

    def test_private_home_key_file_is_available_to_existing_process(self):
        with tempfile.TemporaryDirectory() as home:
            key_file = Path(home) / ".config/vulnerabilityanalysis/ollama_api_key"
            key_file.parent.mkdir(parents=True)
            key_file.write_text("private-test-key\n", encoding="utf-8")
            key_file.chmod(0o600)
            with patch.dict(os.environ, {"HOME": home, "OLLAMA_API_KEY": ""}):
                client = OllamaCloudClient(model="glm-5.3", effort="low")
            self.assertEqual(client.api_key, "private-test-key")

    def test_readable_by_other_users_key_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as home:
            key_file = Path(home) / ".config/vulnerabilityanalysis/ollama_api_key"
            key_file.parent.mkdir(parents=True)
            key_file.write_text("private-test-key\n", encoding="utf-8")
            key_file.chmod(0o644)
            with patch.dict(os.environ, {"HOME": home, "OLLAMA_API_KEY": ""}):
                with self.assertRaisesRegex(OllamaCloudError, "permissions"):
                    OllamaCloudClient(model="glm-5.3", effort="low")

    def test_unsupported_thinking_level_is_rejected_instead_of_silent_default(self):
        def urlopen(request, timeout):
            return io.BytesIO(b'{"thinking":{"values":["low","high","max"],"default":"max"}}')

        client = OllamaCloudClient(api_key="test-secret", model="glm-5.3", effort="medium")
        with patch("vulnerabilityanalysis.llm.urlopen", side_effect=urlopen) as mocked:
            with self.assertRaisesRegex(OllamaCloudError, "medium"):
                asyncio.run(client.generate(LLMRequest("sp_verifier", "", {}, SCHEMA)))
        self.assertEqual(mocked.call_count, 1)

    def test_schema_mismatch_is_not_accepted_as_agent_evidence(self):
        def urlopen(request, timeout):
            if request.full_url.endswith("/show"):
                return io.BytesIO(b'{"thinking":{"values":["low","high","max"],"default":"max"}}')
            return io.BytesIO(b'{"done":true,"message":{"content":"{\\"value\\":\\"wrong\\"}"}}')

        client = OllamaCloudClient(api_key="test-secret", model="glm-5.3", effort="low")
        with patch("vulnerabilityanalysis.llm.urlopen", side_effect=urlopen):
            with self.assertRaisesRegex(OllamaCloudError, "schema"):
                asyncio.run(client.generate(LLMRequest("sp_verifier", "", {}, SCHEMA)))

    def test_fenced_json_object_is_accepted_and_validated(self):
        def urlopen(request, timeout):
            if request.full_url.endswith("/show"):
                return io.BytesIO(b'{"thinking":{"values":["high"]}}')
            return io.BytesIO(json.dumps({"done": True, "message": {
                "content": '```json\n{"value":1}\n```'}}).encode())

        client = OllamaCloudClient(api_key="test-secret", model="glm-5.3-flash",
                                   effort="high")
        with tempfile.TemporaryDirectory() as temp:
            raw_path = Path(temp) / "response.raw.txt"
            with patch("vulnerabilityanalysis.llm.urlopen", side_effect=urlopen):
                self.assertEqual(asyncio.run(client.generate(
                    LLMRequest("poc_generator", "", {}, SCHEMA,
                               raw_response_path=raw_path))), {"value": 1})
            self.assertEqual(raw_path.read_text(), '```json\n{"value":1}\n```')
            self.assertEqual(raw_path.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
