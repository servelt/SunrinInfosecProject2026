import asyncio
import hashlib
import json
import os
import signal
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.llm import (AppServerError, CodexAppServerClient,
                                       LLMRequest, ModelAuditError,
                                       ProviderSafetyRefusedError,
                                       _TurnResponseEnvelope)


class AppServerNotificationTest(unittest.TestCase):
    @staticmethod
    def _observed_safety_params(thread_id="t", turn_id="v", model="gpt-5.6-sol"):
        return {"threadId": thread_id, "turnId": turn_id, "model": model,
                "fasterModel": "gpt-5.6-luna", "reasons": ["user_risk"],
                "useCases": ["bio"], "showBufferingUi": True}

    def test_safety_buffering_is_bound_to_requested_turn_and_audited(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "events.jsonl"
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._active_model_effort = ("gpt-5.6-sol", "max")
            client._active_role = "FUNCTION_ANALYSIS"
            client._notifications.extend([
                {"method": "model/safetyBuffering/updated",
                 "params": self._observed_safety_params()},
                {"method": "item/completed", "params": {"threadId": "t", "turnId": "v",
                    "item": {"type": "agentMessage", "text": '{"answer":"4"}'}}},
                {"method": "turn/completed", "params": {"threadId": "t",
                    "turn": {"id": "v", "status": "completed"}}},
            ])
            self.assertEqual(asyncio.run(client._collect("t", "v")), '{"answer":"4"}')
            self.assertFalse(client.forbidden_tool_event)
            rows = [json.loads(line) for line in audit.read_text().splitlines()]
            summary = next(row for row in rows
                           if row.get("classification") == "PROVIDER_SAFETY_BUFFERING")
            self.assertEqual(summary["requested_model"], "gpt-5.6-sol")
            self.assertEqual(summary["faster_models"], ["gpt-5.6-luna"])
            self.assertEqual(summary["reasons"], ["user_risk"])
            self.assertEqual(summary["use_cases"], ["bio"])
            self.assertEqual(summary["turn_status"], "completed")
            self.assertGreaterEqual(summary["buffer_to_turn_end_seconds"], 0)
            self.assertIsNone(summary["buffer_to_stop_seconds"])
            self.assertEqual(rows[0]["params"], self._observed_safety_params())

        client = CodexAppServerClient(cwd=Path.cwd())
        client._active_model_effort = ("gpt-5.6-sol", "max")
        client._notifications.extend([
            {"method": "model/safetyBuffering/updated",
             "params": self._observed_safety_params()},
            {"method": "turn/moderationMetadata", "params": {"threadId": "t", "turnId": "v",
                "metadata": {"generation": {"is_blocked": True}, "prompt": {},
                             "tool_call": {}, "tool_response": {}}}},
            {"method": "turn/completed", "params": {"threadId": "t",
                "turn": {"id": "v", "status": "failed",
                         "error": {"codexErrorInfo": "cyberPolicy"}}}},
        ])
        with self.assertRaises(ProviderSafetyRefusedError):
            asyncio.run(client._collect("t", "v"))
        summary = client.safety_buffering_summaries[0]
        self.assertEqual(summary["turn_status"], "provider_safety_refused_terminal")
        self.assertIsNone(summary["buffer_to_turn_end_seconds"])
        self.assertGreaterEqual(summary["buffer_to_stop_seconds"], 0)

        client = CodexAppServerClient(cwd=Path.cwd())
        client._active_model_effort = ("gpt-5.6-sol", "max")
        client._notifications.extend([
            {"method": "model/safetyBuffering/updated",
             "params": {**self._observed_safety_params(), "showBufferingUi": False}},
            {"method": "turn/completed", "params": {"threadId": "t",
                "turn": {"id": "v", "status": "completed"}}},
        ])
        self.assertEqual(asyncio.run(client._collect("t", "v")), "")
        summary = client.safety_buffering_summaries[0]
        self.assertFalse(summary["buffered"])
        self.assertIsNone(summary["buffer_to_turn_end_seconds"])
        self.assertIsNone(summary["buffer_to_stop_seconds"])

    def test_safety_buffering_mismatch_or_tool_shape_stays_forbidden(self):
        for changes in ({"threadId": "other"}, {"turnId": "other"},
                        {"model": "gpt-5.6-luna"},
                        {"item": {"type": "webSearch"}},
                        {"reasons": ["x" * 4096]}):
            with self.subTest(changes=changes):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._active_model_effort = ("gpt-5.6-sol", "max")
                client._notifications.append({"method": "model/safetyBuffering/updated",
                    "params": {**self._observed_safety_params(), **changes}})
                with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.forbidden_tool_event)

        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append({"method": "model/rerouted", "params": {
            "threadId": "t", "turnId": "v", "fromModel": "gpt-5.6-sol",
            "toModel": "gpt-5.6-luna", "reason": "synthetic"}})
        with self.assertRaisesRegex(AppServerError, "MODEL_REROUTED"):
            asyncio.run(client._collect("t", "v"))

    def test_explicit_safety_block_is_refusal_not_tool_or_safe_result(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "events.jsonl"
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._active_role = "FUNCTION_ANALYSIS"
            client._notifications.append({"method": "turn/moderationMetadata", "params": {
                "threadId": "t", "turnId": "v", "metadata": {
                    "generation": {"omnimod": {"is_blocked": True}},
                    "prompt": {"omnimod": {"is_blocked": False}},
                    "tool_call": {}, "tool_response": {}}}})
            client._notifications.append({"method": "turn/completed", "params": {
                "threadId": "t", "turn": {"id": "v", "status": "failed",
                    "error": {"codexErrorInfo": "cyberPolicy"}}}})
            with self.assertRaisesRegex(ProviderSafetyRefusedError,
                                        "PROVIDER_SAFETY_REFUSED: role=FUNCTION_ANALYSIS"):
                asyncio.run(client._collect("t", "v"))
            self.assertFalse(client.forbidden_tool_event)
            rows = [json.loads(line) for line in audit.read_text().splitlines()]
            self.assertIn("PROVIDER_SAFETY_REFUSED",
                          [row.get("classification") for row in rows])
            self.assertIn("PROVIDER_SAFETY_REFUSAL_TERMINAL",
                          [row.get("classification") for row in rows])
            self.assertTrue(client.provider_safety_refused)
            self.assertEqual(len(client.provider_safety_terminal_records), 1)

        for safety_code in ("cyberPolicy", "misalignmentPolicyViolation"):
            with self.subTest(safety_code=safety_code):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.append({"method": "turn/completed", "params": {
                    "threadId": "t", "turn": {"id": "v", "status": "failed",
                        "error": {"codexErrorInfo": safety_code}}}})
                with self.assertRaisesRegex(ProviderSafetyRefusedError,
                                            "PROVIDER_SAFETY_REFUSED"):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.provider_safety_refused)

    def test_blocked_turn_waits_for_only_matching_policy_terminal(self):
        block = {"method": "turn/moderationMetadata", "params": {
            "threadId": "t", "turnId": "v", "metadata": {
                "generation": {"is_blocked": True}, "prompt": {},
                "tool_call": {}, "tool_response": {}}}}
        for terminal in (
            {"threadId": "t", "turn": {"id": "v", "status": "completed"}},
            {"threadId": "t", "turn": {"id": "v", "status": "failed",
                "error": {"codexErrorInfo": "other"}}},
        ):
            with self.subTest(terminal=terminal):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.extend([block.copy(),
                    {"method": "turn/completed", "params": terminal}])
                with self.assertRaises(ProviderSafetyRefusedError):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.provider_safety_refused)
                self.assertEqual(client.provider_safety_terminal_records, [])

        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([block.copy(),
            {"method": "turn/completed", "params": {"threadId": "other",
                "turn": {"id": "v", "status": "failed",
                    "error": {"codexErrorInfo": "cyberPolicy"}}}},
            {"method": "turn/completed", "params": {"threadId": "t",
                "turn": {"id": "v", "status": "failed",
                    "error": {"codexErrorInfo": "cyberPolicy"}}}}])
        with self.assertRaises(ProviderSafetyRefusedError):
            asyncio.run(client._collect("t", "v"))
        self.assertEqual(len(client.provider_safety_terminal_records), 1)
        self.assertTrue(client.provider_safety_refused)

    def test_blocked_turn_does_not_settle_after_provider_retry_notice(self):
        block = {"method": "turn/moderationMetadata", "params": {
            "threadId": "t", "turnId": "v", "metadata": {
                "generation": {"is_blocked": True}, "prompt": {},
                "tool_call": {}, "tool_response": {}}}}
        retry = {"method": "error", "params": {
            "threadId": "t", "turnId": "v", "willRetry": True}}
        terminal = {"method": "turn/completed", "params": {"threadId": "t",
            "turn": {"id": "v", "status": "failed",
                "error": {"codexErrorInfo": "cyberPolicy"}}}}
        for sequence, expected in (((block, retry, terminal), "after block"),
                                   ((retry, block, terminal), "before block")):
            with self.subTest(sequence=expected):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.extend(dict(event) for event in sequence)
                with self.assertRaisesRegex(ProviderSafetyRefusedError,
                                            "remote retry " + expected):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.provider_safety_refused)
                self.assertEqual(client.provider_safety_terminal_records, [])

    def test_blocked_turn_timeout_eof_and_cancellation_stay_unconfirmed(self):
        block = {"method": "turn/moderationMetadata", "params": {
            "threadId": "t", "turnId": "v", "metadata": {
                "generation": {"is_blocked": True}, "prompt": {},
                "tool_call": {}, "tool_response": {}}}}

        async def never_read():
            await asyncio.sleep(60)

        client = CodexAppServerClient(cwd=Path.cwd())
        client.SAFETY_REFUSAL_TERMINAL_WAIT_SECONDS = 0.01
        client._notifications.append(block.copy())
        client._read = never_read
        started = time.monotonic()
        with self.assertRaisesRegex(ProviderSafetyRefusedError, "completion unconfirmed"):
            asyncio.run(client._collect("t", "v"))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(client.provider_safety_refused)
        self.assertEqual(client.provider_safety_terminal_records, [])

        client = CodexAppServerClient(cwd=Path.cwd())
        client.SAFETY_REFUSAL_TERMINAL_WAIT_SECONDS = 0.005
        client._notifications.append(block.copy())
        async def late_terminal():
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                await asyncio.sleep(0.01)
                return {"method": "turn/completed", "params": {"threadId": "t",
                    "turn": {"id": "v", "status": "failed",
                        "error": {"codexErrorInfo": "cyberPolicy"}}}}
        client._read = late_terminal
        with self.assertRaisesRegex(ProviderSafetyRefusedError, "completion unconfirmed"):
            asyncio.run(client._collect("t", "v"))
        self.assertEqual(client.provider_safety_terminal_records, [])

        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append(block.copy())
        with self.assertRaises(AppServerError):
            asyncio.run(client._collect("t", "v"))
        self.assertTrue(client.provider_safety_refused)
        self.assertEqual(client.provider_safety_terminal_records, [])

        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append(block.copy())
        client._read = never_read
        async def cancel_wait():
            task = asyncio.create_task(client._collect("t", "v"))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        asyncio.run(cancel_wait())
        self.assertTrue(client.provider_safety_refused)
        self.assertEqual(client.provider_safety_terminal_records, [])

    def test_unblocked_moderation_commentary_metadata_is_non_executable(self):
        """Accept the current App Server envelope without weakening tool checks."""
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([
            {"method": "turn/moderationMetadata", "params": {
                "threadId": "t", "turnId": "v", "metadata": {
                    "commentary": {}, "generation": {},
                    "prompt": {"omnimod": {"outputs": [{
                        "is_blocked": False,
                        "results": [{"category_flags": {"V4+": False}}],
                    }]}},
                    "tool_call": {}, "tool_response": {},
                }}},
            {"method": "turn/completed", "params": {
                "threadId": "t", "turn": {"id": "v", "status": "completed"}}},
        ])
        self.assertEqual(asyncio.run(client._collect("t", "v")), "")
        self.assertFalse(client.forbidden_tool_event)

        for commentary in ({"item": {"type": "commandExecution"}}, [], "text"):
            with self.subTest(commentary=commentary):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.append({
                    "method": "turn/moderationMetadata", "params": {
                        "threadId": "t", "turnId": "v", "metadata": {
                            "commentary": commentary, "generation": {}, "prompt": {},
                            "tool_call": {}, "tool_response": {},
                        }}})
                with self.assertRaisesRegex(
                        AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))

    def test_blocked_commentary_moderation_is_provider_refusal(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._active_role = "SP"
        client._notifications.extend([
            {"method": "turn/moderationMetadata", "params": {
                "threadId": "t", "turnId": "v", "metadata": {
                    "commentary": {"omnimod": {"is_blocked": True}},
                    "generation": {}, "prompt": {},
                    "tool_call": {}, "tool_response": {},
                }}},
            {"method": "turn/completed", "params": {
                "threadId": "t", "turn": {"id": "v", "status": "failed",
                    "error": {"codexErrorInfo": "cyberPolicy"}}}},
        ])
        with self.assertRaisesRegex(ProviderSafetyRefusedError,
                                    "PROVIDER_SAFETY_REFUSED: role=SP"):
            asyncio.run(client._collect("t", "v"))
        self.assertFalse(client.forbidden_tool_event)
        self.assertTrue(client.provider_safety_refused)
        self.assertEqual(len(client.provider_safety_terminal_records), 1)

    def test_blocked_turn_terminal_audit_failure_does_not_confirm_it(self):
        client = CodexAppServerClient(cwd=Path.cwd(), event_log_path=Path('/unused'))
        client._notifications.extend([
            {"method": "turn/moderationMetadata", "params": {
                "threadId": "t", "turnId": "v", "metadata": {
                    "generation": {"is_blocked": True}, "prompt": {},
                    "tool_call": {}, "tool_response": {}}}},
            {"method": "turn/completed", "params": {"threadId": "t",
                "turn": {"id": "v", "status": "failed",
                    "error": {"codexErrorInfo": "cyberPolicy"}}}},
        ])
        with patch('vulnerabilityanalysis.llm._append_private_jsonl',
                   side_effect=[None, None, None, AppServerError('disk full')]):
            with self.assertRaisesRegex(ModelAuditError, 'refusal terminal'):
                asyncio.run(client._collect('t', 'v'))
        self.assertTrue(client.provider_safety_refused)
        self.assertTrue(client.audit_log_failed)
        self.assertEqual(client.provider_safety_terminal_records, [])

        client = CodexAppServerClient(cwd=Path.cwd(), event_log_path=Path('/unused'))
        client._active_model_effort = ('gpt-5.6-sol', 'max')
        client._notifications.extend([
            {'method': 'model/safetyBuffering/updated',
             'params': self._observed_safety_params()},
            {'method': 'turn/moderationMetadata', 'params': {'threadId': 't',
                'turnId': 'v', 'metadata': {'generation': {'is_blocked': True},
                    'prompt': {}, 'tool_call': {}, 'tool_response': {}}}},
            {'method': 'turn/completed', 'params': {'threadId': 't', 'turn': {
                'id': 'v', 'status': 'failed',
                'error': {'codexErrorInfo': 'cyberPolicy'}}}},
        ])
        with patch('vulnerabilityanalysis.llm._append_private_jsonl',
                   side_effect=[None] * 5 + [AppServerError('disk full')]):
            with self.assertRaises(ProviderSafetyRefusedError):
                asyncio.run(client._collect('t', 'v'))
        self.assertTrue(client.audit_log_failed)
        self.assertEqual(client.provider_safety_terminal_records, [])
        self.assertEqual(client.safety_buffering_summaries[0]['turn_status'],
                         'provider_safety_refused_audit_failed')

    def test_blocked_turn_before_start_response_does_not_retry_or_return_json(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        sent = []
        closed = []
        responses = iter([
            {"method": "turn/moderationMetadata", "params": {
                "threadId": "t", "turnId": "v", "metadata": {
                    "generation": {"is_blocked": True}, "prompt": {},
                    "tool_call": {}, "tool_response": {}}}},
            {"id": 1, "result": {"turn": {"id": "v"}}},
            {"method": "turn/completed", "params": {"threadId": "t",
                "turn": {"id": "v", "status": "failed",
                    "error": {"codexErrorInfo": "cyberPolicy"}}}},
        ])
        async def start():
            return None
        async def thread_for(*_args):
            return "t"
        async def send(message):
            sent.append(message)
        async def read():
            return next(responses)
        async def close():
            closed.append(True)
        client.start, client._thread_for = start, thread_for
        client._send, client._read, client.close = send, read, close
        schema = {"type": "object", "properties": {}, "additionalProperties": False}
        request = LLMRequest("seed", "", {}, schema)
        with self.assertRaises(ProviderSafetyRefusedError):
            asyncio.run(client.generate(request))
        with self.assertRaises(ProviderSafetyRefusedError):
            asyncio.run(client.generate(request))
        self.assertEqual([row["method"] for row in sent], ["turn/start"])
        self.assertEqual(client.model_request_counts, {"DEFAULT": 1})
        self.assertEqual(closed, [True, True])
        self.assertEqual(len(client.provider_safety_terminal_records), 1)

    def test_blocked_turn_still_rejects_tool_event(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([
            {"method": "turn/moderationMetadata", "params": {
                "threadId": "t", "turnId": "v", "metadata": {
                    "generation": {"is_blocked": True}, "prompt": {},
                    "tool_call": {}, "tool_response": {}}}},
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "v",
                "item": {"type": "commandExecution"}}},
        ])
        with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
            asyncio.run(client._collect("t", "v"))
        self.assertTrue(client.provider_safety_refused)
        self.assertTrue(client.forbidden_tool_event)
        self.assertEqual(client.provider_safety_terminal_records, [])

    def test_large_structured_block_leaves_small_audit_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / 'events.jsonl'
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._record_server_event({
                'method': 'turn/moderationMetadata',
                'params': {'threadId': 't', 'turnId': 'v', 'metadata': {
                    'generation': {'omnimod': {'is_blocked': True,
                                                'details': 'x' * 5000}},
                    'prompt': {}, 'tool_call': {}, 'tool_response': {},
                }},
            })
            self.assertIn(('t', 'v'), client.structured_safety_block_observations)
            row = json.loads(audit.read_text().splitlines()[0])
            self.assertTrue(row['structured_safety_block_observed'])
            self.assertNotIn('params', row)
            self.assertGreater(row['params_omitted_bytes'], 4096)

    def test_large_agent_message_and_terminal_status_keep_lineage_commitments(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / 'events.jsonl'
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            text = '{"content":"' + 'x' * 5000 + '","tool_calls":[]}'
            client._record_server_event({
                'method': 'item/completed',
                'params': {'threadId': 't', 'turnId': 'v',
                           'item': {'type': 'agentMessage', 'text': text}},
            })
            client._record_server_event({
                'method': 'turn/completed',
                'params': {'threadId': 't',
                           'turn': {'id': 'v', 'status': 'completed'}},
            })
            message, terminal = [json.loads(line) for line in audit.read_text().splitlines()]
            self.assertNotIn('params', message)
            self.assertEqual(message['agent_message_sha256'],
                             hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(terminal['turn_status'], 'completed')

    def test_terminal_policy_refusal_leaves_marker_with_turn_id(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / 'events.jsonl'
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._record_server_event({
                'method': 'turn/completed',
                'params': {'threadId': 't', 'turn': {
                    'id': 'v', 'status': 'failed',
                    'error': {'codexErrorInfo': 'cyberPolicy'},
                    'reason': 'x' * 5000,
                }},
            })
            row = json.loads(audit.read_text().splitlines()[0])
            self.assertEqual(row['turn_id'], 'v')
            self.assertTrue(row['structured_safety_refusal_observed'])
            self.assertNotIn('params', row)
            self.assertIn(('t', 'v'), client.structured_safety_block_observations)

    def test_safety_summary_write_failure_keeps_original_forbidden_event(self):
        for audit_failure in (OSError('disk full'),
                              AppServerError('private audit path invalid')):
            with self.subTest(audit_failure=type(audit_failure).__name__):
                client = CodexAppServerClient(cwd=Path.cwd(), event_log_path=Path('/unused'))
                client._active_model_effort = ('gpt-5.6-sol', 'max')
                client._notifications.extend([
                    {'method': 'model/safetyBuffering/updated',
                     'params': self._observed_safety_params()},
                    {'method': 'model/rerouted', 'params': {'threadId': 't', 'turnId': 'v',
                        'fromModel': 'gpt-5.6-sol', 'toModel': 'gpt-5.6-luna'}},
                ])
                with patch('vulnerabilityanalysis.llm._append_private_jsonl',
                           side_effect=[None, None, audit_failure]):
                    with self.assertRaisesRegex(AppServerError, 'MODEL_REROUTED'):
                        asyncio.run(client._collect('t', 'v'))
                self.assertTrue(client.forbidden_tool_event)
                self.assertTrue(client.audit_log_failed)

    def test_safety_refusal_audit_write_failure_remains_refusal(self):
        client = CodexAppServerClient(cwd=Path.cwd(), event_log_path=Path('/unused'))
        client._notifications.append({'method': 'turn/moderationMetadata',
            'params': {'threadId': 't', 'turnId': 'v', 'metadata': {
                'generation': {'is_blocked': True}, 'prompt': {},
                'tool_call': {}, 'tool_response': {}}}})
        with patch('vulnerabilityanalysis.llm._append_private_jsonl',
                   side_effect=[None, AppServerError('private audit path invalid')]):
            with self.assertRaises(ProviderSafetyRefusedError):
                asyncio.run(client._collect('t', 'v'))
        self.assertTrue(client.provider_safety_refused)
        self.assertTrue(client.audit_log_failed)

    def test_safety_event_queued_before_turn_response_keeps_turn_binding_check(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._active_model_effort = ("gpt-5.6-sol", "max")
        client._active_thread_id = "t"
        responses = iter([
            {"method": "model/safetyBuffering/updated",
             "params": self._observed_safety_params()},
            {"id": 1, "result": {"turn": {"id": "v"}}},
        ])
        async def read():
            return next(responses)
        async def send(_message):
            return None
        client._read, client._send = read, send
        self.assertEqual(asyncio.run(client._request("turn/start", {})),
                         {"turn": {"id": "v"}})
        self.assertIn(("t", "v"), client._safety_buffering_received_at)
        client._safety_buffering_received_at[("t", "v")] = time.monotonic() - 5
        client._notifications.append({"method": "turn/completed", "params": {
            "threadId": "t", "turn": {"id": "v", "status": "completed"}}})
        self.assertEqual(asyncio.run(client._collect("t", "v")), "")
        self.assertEqual(len(client.safety_buffering_summaries), 1)
        self.assertGreaterEqual(client.safety_buffering_summaries[0][
            "buffer_to_turn_end_seconds"], 4.9)

    def test_pre_response_wrong_model_is_rejected_before_timeout(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._active_thread_id = "t"
        client._active_model_effort = ("gpt-5.6-sol", "max")
        responses = iter([{"method": "model/safetyBuffering/updated",
                           "params": self._observed_safety_params(model="wrong-model")}])
        async def read():
            try:
                return next(responses)
            except StopIteration:
                raise AppServerError("app-server response timed out") from None
        async def send(_message):
            return None
        async def close():
            return None
        client._read, client._send, client.close = read, send, close
        with self.assertRaisesRegex(AppServerError, "SAFETY_BUFFERING_OUTSIDE_ACTIVE_TURN"):
            asyncio.run(client._request("turn/start", {}))
        self.assertTrue(client.forbidden_tool_event)

    def test_pre_response_timeout_keeps_raw_safety_observation_censored(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._active_thread_id = "t"
        client._active_model_effort = ("gpt-5.6-sol", "max")
        responses = iter([{"method": "model/safetyBuffering/updated",
                           "params": self._observed_safety_params()}])
        async def read():
            try:
                return next(responses)
            except StopIteration:
                raise AppServerError("app-server response timed out") from None
        async def send(_message):
            return None
        client._read, client._send = read, send
        with self.assertRaisesRegex(AppServerError, "response timed out"):
            asyncio.run(client._request("turn/start", {}))
        self.assertEqual(client.safety_notification_observations, {("t", "v"): True})
        self.assertEqual(client.safety_buffering_summaries, [])

    def test_turn_start_notification_burst_cannot_starve_shared_deadline(self):
        client = CodexAppServerClient(cwd=Path.cwd(), timeout_seconds=1)
        notifications = [
            {"method": "thread/status/changed", "params": {
                "threadId": "t", "status": "active", "sequence": index}}
            for index in range(100_000)
        ]
        responses = iter([
            *notifications,
            {"id": 1, "result": {"turn": {"id": "v"}}},
        ])

        async def read():
            return next(responses)

        async def send(_message):
            return None

        client._read, client._send = read, send
        envelope = _TurnResponseEnvelope(
            deadline=time.monotonic() + 0.001, limit_bytes=20_000_000)
        with self.assertRaisesRegex(AppServerError, "wall deadline"):
            asyncio.run(client._request(
                "turn/start", {}, response_envelope=envelope))
        self.assertLess(len(client._notifications), len(notifications))

    def test_turn_start_and_collect_share_one_response_byte_budget(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        first = {"method": "thread/status/changed", "params": {
            "threadId": "t", "status": "active", "detail": "X" * 300}}
        responses = iter([first, {"id": 1, "result": {"turn": {"id": "v"}}}])

        async def read():
            return next(responses)

        async def send(_message):
            return None

        client._read, client._send = read, send
        envelope = _TurnResponseEnvelope(
            deadline=time.monotonic() + 1, limit_bytes=1024)

        async def run():
            result = await client._request(
                "turn/start", {}, response_envelope=envelope)
            self.assertEqual(result, {"turn": {"id": "v"}})
            client._notifications.append({
                "method": "item/agentMessage/delta", "params": {
                    "turnId": "v", "itemId": "answer", "delta": "Y" * 900}})
            await client._collect("t", "v", response_envelope=envelope)

        with self.assertRaisesRegex(AppServerError, "response stream limit"):
            asyncio.run(run())

    def test_control_rpc_read_is_bounded_by_aggregate_deadline(self):
        client = CodexAppServerClient(cwd=Path.cwd(), timeout_seconds=0.002)

        async def read():
            await asyncio.sleep(0.03)
            return {"id": 1, "result": {"thread": {"id": "late"}}}

        async def send(_message):
            return None

        client._read, client._send = read, send
        started = time.monotonic()
        with self.assertRaisesRegex(AppServerError, "wall deadline"):
            asyncio.run(client._request("thread/start", {}))
        self.assertLess(time.monotonic() - started, 0.02)

    def test_safety_notification_after_turn_does_not_escape_request_validation(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        responses = iter([{"method": "model/safetyBuffering/updated",
                           "params": self._observed_safety_params()}])
        async def read():
            return next(responses)
        async def send(_message):
            return None
        async def close():
            return None
        client._read, client._send, client.close = read, send, close
        with self.assertRaisesRegex(AppServerError, "SAFETY_BUFFERING_OUTSIDE_ACTIVE_TURN"):
            asyncio.run(client._request("thread/delete", {}))

    def test_pure_startup_notifications_queue_before_turn_and_log_full_params(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "events.jsonl"
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            notifications = [
                {"method": "configWarning", "params": {"details": None,
                    "summary": client.APPROVED_CONFIG_WARNING}},
                {"method": "remoteControl/status/changed", "params": {"status": "disabled"}},
                {"method": "account/updated", "params": {"reason": "startup"}},
                {"method": "warning", "params": {"message": client.APPROVED_CODE_MODE_WARNING,
                    "threadId": "t"}},
            ]
            responses = iter([
                *notifications,
                {"id": 1, "result": {"turn": {"id": "v"}}},
                {"method": "item/completed", "params": {"turnId": "v",
                    "item": {"type": "agentMessage", "text": '{"answer":"4"}'}}},
                {"method": "turn/completed", "params": {"threadId": "t",
                    "turn": {"id": "v", "status": "completed"}}},
            ])
            sent = []
            async def read():
                return next(responses)
            async def send(message):
                sent.append(message)
            client._read, client._send = read, send
            async def run():
                self.assertEqual(await client._request("turn/start", {}),
                                 {"turn": {"id": "v"}})
                self.assertEqual(await client._collect("t", "v"), '{"answer":"4"}')
            asyncio.run(run())
            self.assertFalse(client.forbidden_tool_event)
            self.assertEqual(len(sent), 1)
            rows = [json.loads(line) for line in audit.read_text().splitlines()]
            for message in notifications:
                matching = [row for row in rows if row["method"] == message["method"]]
                self.assertEqual(len(matching), 1)
                self.assertEqual(matching[0]["params"], message["params"])
            self.assertEqual(audit.stat().st_mode & 0o077, 0)

    def test_startup_notification_with_tool_item_or_server_request_stays_forbidden(self):
        for method in CodexAppServerClient.PURE_STARTUP_NOTIFICATIONS:
            for extra in ({"item": {"type": "commandExecution"}},
                          {"items": [{"type": "webSearch"}]},
                          {"details": {"item": {"type": "fileChange"}}}):
                with self.subTest(method=method, extra=extra):
                    client = CodexAppServerClient(cwd=Path.cwd())
                    client._notifications.append({"method": method, "params": extra})
                    with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                        asyncio.run(client._collect("t", "v"))
                    self.assertTrue(client.forbidden_tool_event)

            with self.subTest(method=method, server_request=True):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.append({"id": 42, "method": method,
                                              "params": {"summary": "startup"}})
                rejected = []
                async def reject(message):
                    rejected.append(message["id"])
                client._reject_request = reject
                with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))
                self.assertEqual(rejected, [42])
                self.assertTrue(client.forbidden_tool_event)

        client = CodexAppServerClient(cwd=Path.cwd())
        responses = iter([
            {"method": "warning", "params": {"item": {"type": "mcpToolCall"}}},
            {"id": 1, "result": {"turn": {"id": "v"}}},
        ])
        async def read():
            return next(responses)
        async def send(_message):
            return None
        async def close():
            return None
        client._read, client._send, client.close = read, send, close
        with self.assertRaisesRegex(AppServerError, "EMBEDDED_ITEM"):
            asyncio.run(client._request("turn/start", {}))
        self.assertTrue(client.forbidden_tool_event)

    def test_oversize_startup_notification_fails_closed_without_truncating_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "events.jsonl"
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._notifications.append({"method": "warning",
                                          "params": {"summary": "x" * 4096}})
            with self.assertRaisesRegex(AppServerError, "PARAMS_TOO_LARGE"):
                asyncio.run(client._collect("t", "v"))
            row = json.loads(audit.read_text().splitlines()[0])
            self.assertGreater(row["params_omitted_bytes"], 4096)
            self.assertEqual(len(row["params_sha256"]), 64)
            self.assertNotIn("params", row)
            self.assertTrue(client.forbidden_tool_event)

        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append({"method": "warning",
                                      "params": {"summary": "한" * 2000}})
        with self.assertRaisesRegex(AppServerError, "PARAMS_TOO_LARGE"):
            asyncio.run(client._collect("t", "v"))

    def test_existing_tool_notification_families_remain_forbidden(self):
        for method in ("command/output", "fs/changed", "mcpServer/startupStatus/updated",
                       "process/started", "hook/started"):
            with self.subTest(method=method):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.append({"method": method, "params": {}})
                with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.forbidden_tool_event)

    def test_observed_full_turn_notification_order_replays_without_tool_allowance(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        rows = [
            ("configWarning", {"details": None, "summary": client.APPROVED_CONFIG_WARNING}),
            ("remoteControl/status/changed", {"status": "disabled"}),
            ("account/updated", {"authMode": "chatgpt", "planType": "pro"}),
            ("thread/started", {"threadId": "t"}),
            ("warning", {"message": client.APPROVED_CODE_MODE_WARNING, "threadId": "t"}),
            ("thread/status/changed", {"threadId": "t"}),
            ("turn/started", {"threadId": "t", "turnId": "v"}),
            ("item/started", {"threadId": "t", "turnId": "v",
                              "item": {"type": "userMessage", "content": []}}),
            ("item/completed", {"threadId": "t", "turnId": "v",
                                "item": {"type": "userMessage", "content": []}}),
            ("item/started", {"threadId": "t", "turnId": "v",
                              "item": {"type": "agentMessage"}}),
            *(('item/agentMessage/delta', {"threadId": "t", "turnId": "v",
                                            "itemId": "a", "delta": part})
              for part in ('{', '"answer"', ':', '"4"', '}')),
            ("turn/moderationMetadata", {"threadId": "t", "turnId": "v",
                "metadata": {"generation": {"omnimod": {"is_blocked": False}},
                             "prompt": {"omnimod": {"is_blocked": False}},
                             "tool_call": {}, "tool_response": {}}}),
            ("item/completed", {"threadId": "t", "turnId": "v",
                                "item": {"type": "agentMessage", "text": '{"answer":"4"}'}}),
            ("thread/tokenUsage/updated", {"threadId": "t"}),
            ("account/rateLimits/updated", {}),
            ("thread/status/changed", {"threadId": "t"}),
            ("turn/completed", {"threadId": "t",
                                "turn": {"id": "v", "status": "completed",
                                         "items": [{"type": "agentMessage"}]}}),
        ]
        self.assertEqual(len(rows), 21)
        client._notifications.extend({"method": method, "params": params}
                                     for method, params in rows)
        self.assertEqual(asyncio.run(client._collect("t", "v")), '{"answer":"4"}')
        self.assertFalse(client.forbidden_tool_event)

    @staticmethod
    def _observed_thread_settings(model, effort, thread_id="t"):
        return {"threadId": thread_id, "threadSettings": {
            "activePermissionProfile": None,
            "approvalPolicy": "never", "approvalsReviewer": "user",
            "collaborationMode": {"mode": "default", "settings": {
                "developer_instructions": None, "model": model,
                "reasoning_effort": effort}},
            "cwd": "/work", "disabledPluginIds": [],
            "effort": effort, "model": model,
            "modelProvider": "hp_openai_zero_retry",
            "multiAgentMode": "explicitRequestOnly",
            "personality": None,
            "sandboxPolicy": {"networkAccess": False, "type": "readOnly"},
            "serviceTier": None, "summary": None,
        }}

    def test_three_observed_role_event_orders_replay_with_exact_settings(self):
        # Recorded source-free 2+2 turns: luna/high=24 notifications,
        # sol/low=22, sol/max=21. Only the first two changed thread settings.
        for model, effort, with_settings, with_reasoning, expected_count in (
                ("gpt-5.6-luna", "high", True, True, 24),
                ("gpt-5.6-sol", "low", True, False, 22),
                ("gpt-5.6-sol", "max", False, False, 21)):
            with self.subTest(model=model, effort=effort), tempfile.TemporaryDirectory() as temp:
                audit = Path(temp) / "events.jsonl"
                client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
                client._active_model_effort = (model, effort)
                rows = [
                    ("configWarning", {"details": None,
                        "summary": client.APPROVED_CONFIG_WARNING}),
                    ("remoteControl/status/changed", {"status": "disabled"}),
                    ("account/updated", {"authMode": "chatgpt", "planType": "pro"}),
                    ("thread/started", {"threadId": "t"}),
                ]
                if with_settings:
                    rows.append(("thread/settings/updated",
                                 self._observed_thread_settings(model, effort)))
                rows.extend([
                    ("warning", {"message": client.APPROVED_CODE_MODE_WARNING,
                                 "threadId": "t"}),
                    ("thread/status/changed", {"threadId": "t"}),
                    ("turn/started", {"threadId": "t", "turnId": "v"}),
                    ("item/started", {"threadId": "t", "turnId": "v",
                                      "item": {"type": "userMessage"}}),
                    ("item/completed", {"threadId": "t", "turnId": "v",
                                        "item": {"type": "userMessage"}}),
                ])
                if with_reasoning:
                    rows.extend([
                        ("item/started", {"threadId": "t", "turnId": "v",
                                          "item": {"type": "reasoning"}}),
                        ("item/completed", {"threadId": "t", "turnId": "v",
                                            "item": {"type": "reasoning"}}),
                    ])
                rows.append(("item/started", {"threadId": "t", "turnId": "v",
                                               "item": {"type": "agentMessage"}}))
                rows.extend(("item/agentMessage/delta", {"threadId": "t", "turnId": "v",
                         "itemId": "a", "delta": part}) for part in ('{', '"answer"', ':', '"4"', '}'))
                rows.extend([
                    ("turn/moderationMetadata", {"threadId": "t", "turnId": "v",
                        "metadata": {"generation": {"is_blocked": False},
                                     "prompt": {"is_blocked": False},
                                     "tool_call": {}, "tool_response": {}}}),
                    ("item/completed", {"threadId": "t", "turnId": "v",
                                        "item": {"type": "agentMessage",
                                                 "text": '{"answer":"4"}'}}),
                    ("thread/tokenUsage/updated", {"threadId": "t"}),
                    ("account/rateLimits/updated", {}),
                    ("thread/status/changed", {"threadId": "t"}),
                    ("turn/completed", {"threadId": "t", "turn": {
                        "id": "v", "status": "completed",
                        "items": [{"type": "agentMessage"}]}}),
                ])
                self.assertEqual(len(rows), expected_count)
                client._notifications.extend({"method": method, "params": params}
                                             for method, params in rows)
                self.assertEqual(asyncio.run(client._collect("t", "v")), '{"answer":"4"}')
                self.assertFalse(client.forbidden_tool_event)
                logged = [json.loads(line) for line in audit.read_text().splitlines()]
                self.assertEqual([row["method"] for row in logged],
                                 [method for method, _ in rows])
                if with_settings:
                    setting = next(row for row in logged
                                   if row["method"] == "thread/settings/updated")
                    self.assertEqual(setting["params"],
                                     self._observed_thread_settings(model, effort))
                self.assertNotIn("params", next(row for row in logged
                    if row["method"] == "item/agentMessage/delta"))

    def test_thread_settings_must_match_requested_role_and_keep_tool_policy(self):
        correct = self._observed_thread_settings("gpt-5.6-luna", "high")
        bad = []
        for changed_model, changed_effort in (("gpt-5.6-sol", "high"),
                                              ("gpt-5.6-luna", "low")):
            bad.append(self._observed_thread_settings(changed_model, changed_effort))
        wrong_thread = json.loads(json.dumps(correct))
        wrong_thread["threadId"] = "other"
        bad.append(wrong_thread)
        for path, value in (("approvalPolicy", "on-request"),
                            ("cwd", "/host"),
                            ("sandboxPolicy", {"networkAccess": True, "type": "readOnly"}),
                            ("disabledPluginIds", ["unexpected"]),
                            ("newToolPolicy", {"enabled": True})):
            changed = json.loads(json.dumps(correct))
            changed["threadSettings"][path] = value
            bad.append(changed)
        embedded = json.loads(json.dumps(correct))
        embedded["threadSettings"]["item"] = {"type": "commandExecution"}
        bad.append(embedded)
        for params in bad:
            with self.subTest(params=params):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._active_model_effort = ("gpt-5.6-luna", "high")
                client._notifications.append({"method": "thread/settings/updated",
                                              "params": params})
                with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.forbidden_tool_event)

    def test_non_delta_notifications_log_params_up_to_four_kib(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "events.jsonl"
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._notifications.extend([
                {"method": "thread/status/changed", "params": {"threadId": "t",
                    "status": "active"}},
                {"method": "item/agentMessage/delta", "params": {"turnId": "v",
                    "delta": "private model text"}},
                {"method": "thread/tokenUsage/updated", "params": {"blob": "x" * 5000}},
                {"method": "item/completed", "params": {"turnId": "v",
                    "item": {"type": "agentMessage", "text": '{"answer":"4"}'}}},
                {"method": "turn/completed", "params": {"threadId": "t",
                    "turn": {"id": "v", "status": "completed"}}},
            ])
            self.assertEqual(asyncio.run(client._collect("t", "v")), '{"answer":"4"}')
            rows = [json.loads(line) for line in audit.read_text().splitlines()]
            self.assertEqual(rows[0]["params"], {"threadId": "t", "status": "active"})
            self.assertNotIn("params", rows[1])
            self.assertNotIn("private model text", audit.read_text())
            self.assertNotIn("params", rows[2])
            self.assertEqual(len(rows[2]["params_sha256"]), 64)
            self.assertEqual(len(rows[2]["params_prefix_utf8"].encode()), 4096)
            self.assertEqual(rows[3]["params"]["item"]["type"], "agentMessage")
            self.assertEqual(audit.stat().st_mode & 0o077, 0)

    def test_new_turn_events_reject_wrong_turn_tool_metadata_and_unknown_warning(self):
        bad = [
            {"method": "item/started", "params": {"threadId": "t", "turnId": "other",
                "item": {"type": "userMessage"}}},
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "v",
                "item": {"type": "commandExecution"}}},
            {"method": "warning", "params": {"threadId": "t",
                "message": "model downgraded; outputSchema ignored"}},
            {"method": "remoteControl/status/changed", "params": {"status": "enabled"}},
            {"method": "turn/moderationMetadata", "params": {"threadId": "t", "turnId": "v",
                "metadata": {"generation": {}, "prompt": {},
                             "tool_call": {"executed": True}, "tool_response": {}}}},
            {"method": "turn/moderationMetadata", "params": {"threadId": "t", "turnId": "other",
                "metadata": {"generation": {}, "prompt": {},
                             "tool_call": {}, "tool_response": {}}}},
            {"method": "turn/completed", "params": {"threadId": "t",
                "turn": {"id": "v", "status": "completed",
                         "items": [{"type": "commandExecution"}]}}},
        ]
        for message in bad:
            with self.subTest(message=message['method'], params=message['params']):
                client = CodexAppServerClient(cwd=Path.cwd())
                client._notifications.append(message)
                with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))
                self.assertTrue(client.forbidden_tool_event)

    def test_codex_executable_bytes_rechecked_without_a_model_call(self):
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / 'codex'
            executable.write_bytes(b'first binary')
            expected = hashlib.sha256(executable.read_bytes()).hexdigest()
            client = CodexAppServerClient(cwd=Path(temp), executable=str(executable),
                                          executable_sha256=expected)
            client._verify_executable_identity(str(executable))
            executable.write_bytes(b'changed binary')
            with self.assertRaisesRegex(AppServerError, 'identity changed'):
                client._verify_executable_identity(str(executable))

    def test_tool_items_stop_turn_and_leave_private_event_type_audit(self):
        for item_type in ("commandExecution", "fileChange", "mcpToolCall", "webSearch"):
            with self.subTest(item_type=item_type), tempfile.TemporaryDirectory() as temp:
                audit = Path(temp) / "events.jsonl"
                client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
                client._notifications.extend([
                    {"method": "item/started", "params": {"turnId": "v", "item": {"type": "reasoning"}}},
                    {"method": "item/completed", "params": {"turnId": "v", "item": {"type": item_type}}},
                    {"method": "turn/completed", "params": {"threadId": "t", "turn": {"id": "v", "status": "completed"}}},
                ])
                with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
                    asyncio.run(client._collect("t", "v"))
                rows = [json.loads(row) for row in audit.read_text().splitlines()]
                self.assertIn(("item/completed", item_type),
                              [(row["method"], row.get("item_type")) for row in rows])
                self.assertEqual(audit.stat().st_mode & 0o077, 0)

    def test_tool_delta_and_server_request_stop_turn(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append({"method": "item/commandExecution/outputDelta",
                                      "params": {"turnId": "v", "delta": "secret"}})
        with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
            asyncio.run(client._collect("t", "v"))

        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append({"id": 42, "method": "item/commandExecution/requestApproval",
                                      "params": {"threadId": "t", "turnId": "v"}})
        rejected = []
        async def reject(message):
            rejected.append(message["id"])
        client._reject_request = reject
        with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
            asyncio.run(client._collect("t", "v"))
        self.assertEqual(rejected, [42])

    def test_tool_event_queued_before_turn_response_stops_request(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        responses = iter([
            {"method": "item/commandExecution/outputDelta",
             "params": {"turnId": "v", "delta": "untrusted"}},
            {"id": 1, "result": {"turn": {"id": "v"}}},
        ])
        closed = []
        async def read():
            return next(responses)
        async def send(_message):
            return None
        async def close():
            closed.append(True)
        client._read, client._send, client.close = read, send, close
        with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
            asyncio.run(client._request("turn/start", {}))
        self.assertEqual(closed, [True])
        self.assertTrue(client.forbidden_tool_event)

    def test_rejected_server_request_stays_tool_error_if_reply_pipe_breaks(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append({"id": 3, "method": "item/commandExecution/requestApproval",
                                      "params": {"threadId": "t", "turnId": "v"}})
        async def broken(_message):
            raise BrokenPipeError("synthetic closed pipe")
        client._reject_request = broken
        with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
            asyncio.run(client._collect("t", "v"))
        self.assertTrue(client.forbidden_tool_event)

    def test_reasoning_and_agent_message_are_only_allowed_items(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([
            {"method": "item/started", "params": {"turnId": "v", "item": {"type": "reasoning"}}},
            {"method": "item/reasoning/textDelta", "params": {"turnId": "v", "delta": "thought"}},
            {"method": "item/completed", "params": {"turnId": "v", "item": {"type": "reasoning"}}},
            {"method": "item/completed", "params": {"turnId": "v", "item": {"type": "agentMessage", "text": '{"value":1}'}}},
            {"method": "turn/completed", "params": {"threadId": "t", "turn": {"id": "v", "status": "completed"}}},
        ])
        self.assertEqual(asyncio.run(client._collect("t", "v")), '{"value":1}')

    def test_stale_turn_completion_is_logged_without_tainting_current_turn(self):
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "events.jsonl"
            client = CodexAppServerClient(cwd=Path(temp), event_log_path=audit)
            client._notifications.extend([
                {"method": "turn/completed", "params": {"threadId": "old-thread",
                    "turn": {"id": "old-turn", "status": "completed"}}},
                {"method": "item/completed", "params": {"turnId": "current-turn",
                    "item": {"type": "agentMessage", "text": '{"value":1}'}}},
                {"method": "turn/completed", "params": {"threadId": "current-thread",
                    "turn": {"id": "current-turn", "status": "completed"}}},
            ])
            self.assertEqual(asyncio.run(client._collect("current-thread", "current-turn")),
                             '{"value":1}')
            self.assertFalse(client.forbidden_tool_event)
            rows = [json.loads(row) for row in audit.read_text().splitlines()]
            self.assertIn("STALE_OR_UNRELATED_TURN_EVENT",
                          [row.get("classification") for row in rows])

    def test_stale_turn_completion_does_not_waive_real_tool_event(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([
            {"method": "turn/completed", "params": {"threadId": "old",
                "turn": {"id": "old", "status": "completed"}}},
            {"method": "item/completed", "params": {"turnId": "v",
                "item": {"type": "webSearch"}}},
        ])
        with self.assertRaisesRegex(AppServerError, "FORBIDDEN_MODEL_TOOL_EVENT"):
            asyncio.run(client._collect("t", "v"))
        self.assertTrue(client.forbidden_tool_event)

    def test_function_analysis_audit_preserves_request_and_original_judgment(self):
        response = {"hypothesis_evaluations": [{"hypothesis": "input changes state",
                                                   "judgment": "EXPLICIT_SAFE_JUDGMENT",
                                                   "reason": "model claimed a guard applies",
                                                   "safe_assumption": "state is valid"}]}

        class Recorder:
            async def generate(self, _request):
                return response

        schema = {"type": "object", "properties": {"hypothesis_evaluations": {
            "type": "array", "items": {"type": "object"}}},
            "required": ["hypothesis_evaluations"], "additionalProperties": False}
        with tempfile.TemporaryDirectory() as temp:
            pipeline = AgentPipeline(Recorder(), schema_error_dir=Path(temp))
            self.assertEqual(asyncio.run(pipeline._ask(
                "function_analysis", {"source": "int target(void) { return 0; }"}, schema)), response)
            row = json.loads((Path(temp) / "agent_requests.jsonl").read_text())
            request = json.loads(Path(row["request_artifact"]).read_text())
            original = json.loads(Path(row["response_artifact"]).read_text())
            self.assertEqual(request["payload"]["source"], "int target(void) { return 0; }")
            self.assertEqual(original, response)
            self.assertEqual(original["hypothesis_evaluations"], response["hypothesis_evaluations"])
            self.assertEqual(pipeline.last_request_artifacts["response_artifact"],
                             row["response_artifact"])
            self.assertEqual(Path(row["request_artifact"]).stat().st_mode & 0o077, 0)
            self.assertEqual(Path(row["response_artifact"]).stat().st_mode & 0o077, 0)

    def test_codex_raw_assistant_text_is_saved_before_json_parsing(self):
        client = CodexAppServerClient(cwd=Path.cwd())

        async def start():
            return None

        async def request(method, _params, **_kwargs):
            return {"thread": {"id": "thread-1"}} if method == "thread/start" else {"turn": {"id": "turn-1"}}

        raw = '{"value": 1}\n'

        async def collect(_thread, _turn, **_kwargs):
            return raw

        async def delete(_thread):
            return None

        client.start, client._request = start, request
        client._collect, client._delete_ephemeral_thread = collect, delete
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        with tempfile.TemporaryDirectory() as temp:
            raw_path = Path(temp) / "response.raw.txt"
            result = asyncio.run(client.generate(LLMRequest("function_analysis", "", {}, schema,
                                                              raw_response_path=raw_path)))
            self.assertEqual(result, {"value": 1})
            self.assertEqual(raw_path.read_text(), raw)
            self.assertEqual(raw_path.stat().st_mode & 0o077, 0)

    def test_codex_invalid_json_still_preserves_raw_assistant_text(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        cleanup = []

        async def start():
            return None

        async def request(method, _params, **_kwargs):
            return {"thread": {"id": "thread-1"}} if method == "thread/start" else {"turn": {"id": "turn-1"}}

        async def collect(_thread, _turn, **_kwargs):
            return '{"value": invalid}\n'

        async def close():
            cleanup.append("closed")

        client.start, client._request, client._collect, client.close = start, request, collect, close
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        with tempfile.TemporaryDirectory() as temp:
            raw_path = Path(temp) / "invalid.raw.txt"
            with self.assertRaises(json.JSONDecodeError):
                asyncio.run(client.generate(LLMRequest("function_analysis", "", {}, schema,
                                                       raw_response_path=raw_path)))
            self.assertEqual(raw_path.read_text(), '{"value": invalid}\n')
            self.assertEqual(cleanup, ["closed"])

    def test_pipeline_log_links_codex_original_text_to_hypothesis_response(self):
        client = CodexAppServerClient(cwd=Path.cwd())

        async def start():
            return None

        async def request(method, _params, **_kwargs):
            return {"thread": {"id": "thread-1"}} if method == "thread/start" else {"turn": {"id": "turn-1"}}

        raw = '{"hypothesis_evaluations":[{"hypothesis":"state relation","judgment":"UNKNOWN"}]}\n'

        async def collect(_thread, _turn, **_kwargs):
            return raw

        async def delete(_thread):
            return None

        client.start, client._request = start, request
        client._collect, client._delete_ephemeral_thread = collect, delete
        schema = {"type": "object", "properties": {"hypothesis_evaluations": {
            "type": "array", "items": {"type": "object"}}},
            "required": ["hypothesis_evaluations"], "additionalProperties": False}
        with tempfile.TemporaryDirectory() as temp:
            pipeline = AgentPipeline(client, schema_error_dir=Path(temp))
            result = asyncio.run(pipeline._ask("function_analysis", {"source": "int f(void);"}, schema))
            row = json.loads((Path(temp) / "agent_requests.jsonl").read_text())
            self.assertEqual(Path(row["raw_response_artifact"]).read_text(), raw)
            self.assertEqual(json.loads(Path(row["response_artifact"]).read_text()), result)
            self.assertEqual(pipeline.last_request_artifacts["raw_response_artifact"],
                             row["raw_response_artifact"])

    def test_role_model_settings_reach_provider_without_agent_hardcoding(self):
        class Recorder:
            requests = []

            async def generate(self, request):
                self.requests.append(request)
                return {"value": 1}

        provider = Recorder()
        pipeline = AgentPipeline(provider, role_models={
            "function_analysis": {"model": "gpt-5.6-luna", "reasoning": "medium"},
            "sp_verifier": {"model": "gpt-5.6-luna", "reasoning": "medium"},
        })
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        asyncio.run(pipeline._ask("function_analysis", {}, schema))
        asyncio.run(pipeline._ask("sp_verifier", {}, schema))
        self.assertEqual([(row.model, row.effort) for row in provider.requests],
                         [("gpt-5.6-luna", "medium"), ("gpt-5.6-luna", "medium")])

    def test_request_model_and_effort_override_provider_defaults(self):
        client = CodexAppServerClient(cwd=Path.cwd(), model="gpt-6-sol", effort="medium")
        sent = []
        async def start():
            return None
        async def request(method, params, **_kwargs):
            sent.append((method, params))
            return {"thread": {"id": "thread-1"}} if method == "thread/start" else {"turn": {"id": "turn-1"}}
        async def collect(thread, turn, **_kwargs):
            return '{"value":1}'
        async def delete(thread):
            return None
        client.start, client._request, client._collect, client._delete_ephemeral_thread = start, request, collect, delete
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        result = asyncio.run(client.generate(LLMRequest("analysis", "Return one", {}, schema,
                                                       model="gpt-5.6-luna", effort="low")))
        self.assertEqual(result, {"value": 1})
        self.assertEqual(sent[0][1]["model"], "gpt-5.6-luna")
        self.assertEqual(sent[1][1]["model"], "gpt-5.6-luna")
        self.assertEqual(sent[1][1]["effort"], "low")
        self.assertEqual(client.model_request_counts, {"gpt-5.6-luna": 1})

    def test_timed_out_turn_closes_stale_process_without_thread_delete(self):
        client = CodexAppServerClient(cwd=Path.cwd(), timeout_seconds=1)
        events = []
        async def start():
            events.append("start")
        async def request(method, params, **_kwargs):
            return {"thread": {"id": "thread-1"}} if method == "thread/start" else {"turn": {"id": "turn-1"}}
        async def collect(thread, turn, **_kwargs):
            raise AppServerError("app-server response timed out")
        async def delete(thread):
            events.append("delete")
        async def close():
            events.append("close")
        client.start, client._request, client._collect = start, request, collect
        client._delete_ephemeral_thread, client.close = delete, close
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        with self.assertRaises(AppServerError):
            asyncio.run(client.generate(LLMRequest("analysis", "Return one", {}, schema)))
        self.assertEqual(events, ["start", "close"])

    def test_outer_wait_for_cancellation_finishes_cleanup(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        events = []
        async def start():
            events.append("start")
        async def request(method, _params, **_kwargs):
            return {"thread": {"id": "t"}} if method == "thread/start" else {"turn": {"id": "v"}}
        async def collect(_thread, _turn, **_kwargs):
            await asyncio.sleep(60)
            return '{"value":1}'
        async def close():
            await asyncio.sleep(0.02)
            events.append("closed")
        client.start, client._request, client._collect, client.close = start, request, collect, close
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        async def run():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(client.generate(LLMRequest("analysis", "", {}, schema)), 0.01)
            self.assertEqual(events, ["start", "closed"])
        asyncio.run(run())

    def test_cancellation_during_start_also_finishes_cleanup(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        events = []
        async def start():
            await asyncio.sleep(60)
        async def close():
            await asyncio.sleep(0.01)
            events.append("closed")
        client.start, client.close = start, close
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        async def run():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(client.generate(LLMRequest("analysis", "", {}, schema)), 0.01)
            self.assertEqual(events, ["closed"])
        asyncio.run(run())

    def test_cancelled_login_status_reaps_auth_child(self):
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / "codex"
            executable.write_text("synthetic")
            executable.chmod(0o700)
            client = CodexAppServerClient(cwd=Path(temp), executable=str(executable),
                                          launch_prefix=["/isolated-launcher"],
                                          wire_cwd="/work")
            async def run():
                done = asyncio.Event()
                class AuthProcess:
                    stdin = None
                    returncode = None
                    stopped = False
                    async def communicate(self):
                        await asyncio.sleep(60)
                    async def wait(self):
                        await done.wait()
                        return self.returncode
                    def terminate(self):
                        self.stopped = True
                        self.returncode = -signal.SIGTERM
                        done.set()
                    def kill(self):
                        self.stopped = True
                        self.returncode = -signal.SIGKILL
                        done.set()
                auth = AuthProcess()
                async def create(*_argv, **_kwargs):
                    return auth
                schema = {"type": "object", "properties": {}, "additionalProperties": False}
                with patch("vulnerabilityanalysis.llm.asyncio.create_subprocess_exec", create):
                    with self.assertRaises(TimeoutError):
                        await asyncio.wait_for(
                            client.generate(LLMRequest("analysis", "", {}, schema)), 0.01)
                self.assertTrue(auth.stopped)
                self.assertIsNone(client.process_id)
            asyncio.run(run())

    def test_direct_outer_timeout_error_finishes_cleanup(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        events = []
        async def start():
            raise TimeoutError("outer synthetic deadline")
        async def close():
            events.append("closed")
        client.start, client.close = start, close
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        with self.assertRaises(TimeoutError):
            asyncio.run(client.generate(LLMRequest("analysis", "", {}, schema)))
        self.assertEqual(events, ["closed"])

    def test_broken_stream_during_thread_start_finishes_cleanup(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        events = []
        async def start():
            return None
        async def request(_method, _params, **_kwargs):
            raise BrokenPipeError("synthetic stream closed")
        async def close():
            events.append("closed")
        client.start, client._request, client.close = start, request, close
        schema = {"type": "object", "properties": {}, "additionalProperties": False}
        with self.assertRaises(BrokenPipeError):
            asyncio.run(client.generate(LLMRequest("analysis", "", {}, schema)))
        self.assertEqual(events, ["closed"])

    def test_turn_has_wall_deadline_even_when_notifications_keep_arriving(self):
        client = CodexAppServerClient(cwd=Path.cwd(), timeout_seconds=0.01)
        events = []
        async def start():
            return None
        async def request(method, params, **_kwargs):
            return {"thread": {"id": "t"}} if method == "thread/start" else {"turn": {"id": "v"}}
        async def collect(_thread, _turn, **_kwargs):
            await asyncio.sleep(0.1)
            return '{"value":1}'
        async def close():
            events.append("close")
        client.start, client._request, client._collect, client.close = start, request, collect, close
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        with self.assertRaisesRegex(AppServerError, "wall deadline"):
            asyncio.run(client.generate(LLMRequest("analysis", "Return one", {}, schema)))
        self.assertEqual(events, ["close"])

    def test_prefilled_notification_burst_cannot_starve_monotonic_deadline(self):
        client = CodexAppServerClient(cwd=Path.cwd(), timeout_seconds=1)
        for index in range(20_000):
            client._notifications.append({
                "method": "item/agentMessage/delta",
                "params": {"turnId": "v", "itemId": "answer",
                           "delta": str(index % 10)},
            })
        client._notifications.extend([
            {"method": "item/completed", "params": {"turnId": "v", "item": {
                "type": "agentMessage", "text": '{"value":1}'}}},
            {"method": "turn/completed", "params": {"threadId": "t", "turn": {
                "id": "v", "status": "completed"}}},
        ])
        with self.assertRaisesRegex(AppServerError, "wall deadline"):
            asyncio.run(client._collect(
                "t", "v", deadline=time.monotonic() + 0.001,
                response_limit_bytes=10_000_000))

    def test_response_stream_byte_contract_rejects_delta_flood(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([
            {"method": "item/agentMessage/delta", "params": {
                "turnId": "v", "itemId": "answer", "delta": "X" * 256}}
            for _ in range(16)
        ])
        client._notifications.append({
            "method": "turn/completed", "params": {"threadId": "t", "turn": {
                "id": "v", "status": "completed"}}})
        with self.assertRaisesRegex(AppServerError, "response stream limit"):
            asyncio.run(client._collect(
                "t", "v", deadline=time.monotonic() + 1,
                response_limit_bytes=1024))

    def test_response_stream_limit_configuration_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "response stream limit"):
            CodexAppServerClient(cwd=Path.cwd(), response_stream_limit_bytes=4095)
        client = CodexAppServerClient(
            cwd=Path.cwd(), response_stream_limit_bytes=4096)
        self.assertEqual(client.response_stream_limit_bytes, 4096)

    def test_close_escalates_term_ignoring_process_with_bounded_wait(self):
        async def run():
            script = ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      "print('READY',flush=True); time.sleep(60)")
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", script, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                assert process.stdout is not None
                self.assertEqual(await asyncio.wait_for(process.stdout.readline(), 2), b"READY\n")
                client = CodexAppServerClient(cwd=Path.cwd())
                client._process = process
                client.CLOSE_STDIN_GRACE_SECONDS = 0.03
                client.CLOSE_TERM_GRACE_SECONDS = 0.03
                client.CLOSE_KILL_GRACE_SECONDS = 0.5
                began = time.monotonic()
                await client.close()
                self.assertLess(time.monotonic() - began, 1)
                self.assertIsNotNone(process.returncode)
                self.assertIsNone(client.process_id)
            finally:
                if process.returncode is None:
                    process.kill()
                    await asyncio.wait_for(process.wait(), 2)
        asyncio.run(run())

    def test_cancelled_close_still_escalates_and_reaps(self):
        async def run():
            script = ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      "print('READY',flush=True); time.sleep(60)")
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", script, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                assert process.stdout is not None
                self.assertEqual(await asyncio.wait_for(process.stdout.readline(), 2), b"READY\n")
                client = CodexAppServerClient(cwd=Path.cwd())
                client._process = process
                client.CLOSE_STDIN_GRACE_SECONDS = 0.04
                client.CLOSE_TERM_GRACE_SECONDS = 0.04
                client.CLOSE_KILL_GRACE_SECONDS = 0.5
                closing = asyncio.create_task(client.close())
                await asyncio.sleep(0.01)
                closing.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await closing
                self.assertIsNotNone(process.returncode)
            finally:
                if process.returncode is None:
                    process.kill()
                    await asyncio.wait_for(process.wait(), 2)
        asyncio.run(run())

    def test_login_status_uses_same_launch_prefix_as_app_server(self):
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / "codex"
            executable.write_text("synthetic")
            executable.chmod(0o700)
            client = CodexAppServerClient(cwd=Path(temp), executable=str(executable),
                                          launch_prefix=["/isolated-launcher"],
                                          wire_cwd="/work")
            commands = []
            host_cwds = []
            class AuthProcess:
                returncode = 0
                async def communicate(self):
                    return b"Logged in using ChatGPT", b""
            async def create(*argv, **kwargs):
                commands.append(argv)
                host_cwds.append(kwargs["cwd"])
                if len(commands) == 1:
                    return AuthProcess()
                raise RuntimeError("stop before App Server start")
            with patch("vulnerabilityanalysis.llm.asyncio.create_subprocess_exec", create):
                with self.assertRaisesRegex(RuntimeError, "stop before"):
                    asyncio.run(client.start())
            self.assertEqual(commands[0][:4],
                             ("/isolated-launcher", str(executable), "login", "status"))
            self.assertEqual(commands[1][:4],
                             ("/isolated-launcher", str(executable), "app-server", "--stdio"))
            self.assertEqual(host_cwds, [str(Path(temp).resolve())] * 2)

    def test_sandboxed_thread_uses_chroot_work_path_not_host_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            client = CodexAppServerClient(cwd=Path(temp),
                launch_prefix=["/isolated-launcher"], wire_cwd="/work")
            requests = []

            async def request(method, params, **_kwargs):
                requests.append((method, params))
                return {"thread": {"id": "thread-1"}}

            client._request = request
            self.assertEqual(asyncio.run(client._thread_for("analysis", None, None)), "thread-1")
            self.assertEqual(requests[0][0], "thread/start")
            self.assertEqual(requests[0][1]["cwd"], "/work")
            self.assertEqual(client.cwd, Path(temp).resolve())
            self.assertNotEqual(requests[0][1]["cwd"], str(client.cwd))

    def test_sandboxed_wire_path_must_be_explicit_known_chroot_path(self):
        with tempfile.TemporaryDirectory() as temp:
            for wire_cwd in (None, "/tmp", str(Path(temp)), "/work/../tmp", "work"):
                with self.subTest(wire_cwd=wire_cwd):
                    with self.assertRaises(ValueError):
                        CodexAppServerClient(cwd=Path(temp),
                            launch_prefix=["/isolated-launcher"], wire_cwd=wire_cwd)
            ordinary = CodexAppServerClient(cwd=Path(temp))
            self.assertEqual(ordinary.wire_cwd, str(Path(temp).resolve()))

    def test_retryable_reconnect_does_not_abort_turn(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.extend([
            {"method": "error", "params": {"threadId": "t", "turnId": "v", "willRetry": True,
                                           "error": {"message": "Reconnecting... 2/5"}}},
            {"method": "item/completed", "params": {"turnId": "v", "item": {"type": "agentMessage", "text": '{"value":1}'}}},
            {"method": "turn/completed", "params": {"threadId": "t", "turn": {"id": "v", "status": "completed"}}},
        ])
        self.assertEqual(asyncio.run(client._collect("t", "v")), '{"value":1}')

    def test_terminal_error_still_aborts_turn(self):
        client = CodexAppServerClient(cwd=Path.cwd())
        client._notifications.append({"method": "error", "params": {"threadId": "t", "turnId": "v",
                                                                "willRetry": False, "error": {"message": "failed"}}})
        with self.assertRaises(AppServerError):
            asyncio.run(client._collect("t", "v"))


@unittest.skipUnless(os.environ.get("VA_LIVE_CODEX") == "1" and shutil.which("codex"), "live Codex opt-in")
class LiveCodexTest(unittest.TestCase):
    def test_json_turn_and_process_reuse(self):
        async def run():
            async with CodexAppServerClient(cwd=Path.cwd(), timeout_seconds=90) as client:
                request = LLMRequest(role="smoke", instructions="Return the integer one.", payload={},
                                     output_schema={"type": "object", "properties": {"value": {"type": "integer"}},
                                                    "required": ["value"], "additionalProperties": False})
                first = await client.generate(request)
                pid = client.process_id
                second = await client.generate(request)
                self.assertEqual(first, {"value": 1})
                self.assertEqual(second, {"value": 1})
                self.assertEqual(client.process_id, pid)
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
