import asyncio
import unittest
from pathlib import Path

from harnesscreator.llm.codex_app_server import (
    CodexAppServer,
    CodexAppServerError,
    CodexAppServerPool,
    CodexContextWindowError,
    _model_ids,
    _daybreak_program_for_model,
    _parse_json_object,
    _turn_failure,
)
from harnesscreator.llm.base import (
    InvalidOutputSchemaError,
    is_terminal_llm_infrastructure_error,
    is_transient_llm_transport_error,
    validate_strict_output_schema,
)


class AppServerParsingTest(unittest.TestCase):
    def test_cli_daybreak_feature_is_enabled_for_app_server(self) -> None:
        self.assertEqual(
            CodexAppServer(cwd=Path("."), daybreak=True)._command("/bin/codex"),
            ["/bin/codex", "--enable", "cli_daybreak", "app-server", "-c", "mcp_servers={}"],
        )
        self.assertEqual(
            CodexAppServer(cwd=Path("."))._command("/bin/codex"),
            ["/bin/codex", "app-server", "-c", "mcp_servers={}"],
        )

    def test_explicit_daybreak_model_compatibility(self) -> None:
        self.assertEqual(_daybreak_program_for_model("gpt-6-sol"), "daybreakBlue")
        self.assertEqual(_daybreak_program_for_model("gpt-5.6-cyber"), "daybreakRed")
        self.assertIsNone(_daybreak_program_for_model("gpt-5.6-sol"))
        self.assertIsNone(_daybreak_program_for_model("gpt-6.1-sol"))
        self.assertIsNone(_daybreak_program_for_model("gpt-6-astra"))

    def test_classifies_provider_wide_failures_across_exception_chain(self) -> None:
        try:
            try:
                raise CodexAppServerError(
                    "You've hit your usage limit. Purchase more credits."
                )
            except CodexAppServerError as cause:
                raise RuntimeError("harness generation failed") from cause
        except RuntimeError as wrapped:
            self.assertTrue(is_terminal_llm_infrastructure_error(wrapped))
            self.assertFalse(is_transient_llm_transport_error(wrapped))

        reconnect = CodexAppServerError("Reconnecting... 2/5")
        self.assertFalse(is_terminal_llm_infrastructure_error(reconnect))
        self.assertTrue(is_transient_llm_transport_error(reconnect))

    def test_parses_direct_and_fenced_json(self) -> None:
        self.assertEqual(_parse_json_object('{"ok":true}'), {"ok": True})
        self.assertEqual(_parse_json_object('```json\n{"ok": true}\n```'), {"ok": True})

    def test_rejects_non_object(self) -> None:
        with self.assertRaises(CodexAppServerError):
            _parse_json_object("[1, 2]")

    def test_extracts_model_ids_from_model_list(self) -> None:
        payload = {"data": [{"id": "gpt-5.5"}, {"model": {"id": "gpt-5.4"}}]}
        self.assertEqual(_model_ids(payload), {"gpt-5.4", "gpt-5.5"})

    def test_rejects_dynamic_object_map_before_server_request(self) -> None:
        with self.assertRaisesRegex(
            InvalidOutputSchemaError, "schema-valued additionalProperties"
        ):
            validate_strict_output_schema({
                "type": "object",
                "additionalProperties": False,
                "required": ["bindings"],
                "properties": {
                    "bindings": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                },
            })

    def test_all_agent_output_schemas_use_strict_subset(self) -> None:
        from harnesscreator.agents import (
            entry, features, harness, scenario, scenario_harness, small_feature,
        )

        for module in (
            entry, features, harness, scenario, scenario_harness, small_feature,
        ):
            for name, schema in vars(module).items():
                if name.endswith("SCHEMA") and isinstance(schema, dict):
                    with self.subTest(module=module.__name__, schema=name):
                        validate_strict_output_schema(schema)


class AppServerSessionTest(unittest.IsolatedAsyncioTestCase):
    async def test_reconnect_notice_waits_for_turn_completion(self) -> None:
        server = CodexAppServer(cwd=Path("."))
        server._notification_backlog.extend([
            {"method": "error", "params": {"message": "Reconnecting... 2/5", "turnId": "turn-1"}},
            {"method": "item/completed", "params": {
                "turnId": "turn-1", "item": {"type": "agentMessage", "text": '{"ok":true}'},
            }},
            {"method": "turn/completed", "params": {
                "threadId": "thread-1", "turn": {"id": "turn-1", "status": "completed"},
            }},
        ])
        self.assertEqual(await server._collect_turn("thread-1", "turn-1"), '{"ok":true}')

    async def test_reconnect_notice_does_not_hide_terminal_failure(self) -> None:
        server = CodexAppServer(cwd=Path("."))
        server._notification_backlog.extend([
            {"method": "error", "params": {"message": "Reconnecting... 2/5"}},
            {"method": "turn/completed", "params": {
                "threadId": "thread-1", "turn": {
                    "id": "turn-1", "status": "failed",
                    "error": {"message": "provider unavailable"},
                },
            }},
        ])
        with self.assertRaisesRegex(CodexAppServerError, "provider unavailable"):
            await server._collect_turn("thread-1", "turn-1")

    async def test_non_reconnect_error_remains_failure(self) -> None:
        server = CodexAppServer(cwd=Path("."))
        server._notification_backlog.append(
            {"method": "error", "params": {"message": "permission denied", "turnId": "turn-1"}}
        )
        with self.assertRaisesRegex(CodexAppServerError, "permission denied"):
            await server._collect_turn("thread-1", "turn-1")

    async def test_failed_daybreak_turn_start_deletes_persistent_thread(self) -> None:
        class FailingServer(CodexAppServer):
            def __init__(self):
                super().__init__(cwd=Path("."), model="gpt-6-sol", daybreak=True)
                self.requests = []
                self._process = object()  # type: ignore[assignment]

            async def start(self):
                return {}

            async def _request(self, method, params):
                self.requests.append((method, params))
                if method == "thread/start":
                    return {"thread": {"id": "daybreak-thread"}}
                if method == "turn/start":
                    raise CodexAppServerError("access_program_not_enabled")
                return {}

        server = FailingServer()
        with self.assertRaisesRegex(CodexAppServerError, "access_program_not_enabled"):
            await server._complete_json_once(
                role="harness_generator", instructions="test", payload={},
                output_schema={"type": "object"}, session_key=None,
            )
        self.assertIn(
            ("thread/delete", {"threadId": "daybreak-thread"}), server.requests
        )

    async def test_chatgpt_login_is_required_to_avoid_api_billing(self) -> None:
        class AccountServer(CodexAppServer):
            def __init__(self, kind):
                super().__init__(cwd=Path("."))
                self.kind = kind

            async def _request(self, method, params):
                self.asserted_request = (method, params)
                return {"account": {"type": self.kind}} if self.kind else {"account": None}

        chatgpt = AccountServer("chatgpt")
        await chatgpt._verify_chatgpt_auth()
        self.assertEqual(chatgpt.auth_mode, "chatgpt")
        self.assertEqual(
            chatgpt.asserted_request, ("account/read", {"refreshToken": False})
        )
        for kind in ("apiKey", None):
            with self.subTest(kind=kind):
                server = AccountServer(kind)
                with self.assertRaisesRegex(CodexAppServerError, "separate API-key billing"):
                    await server._verify_chatgpt_auth()

    async def test_daybreak_routes_only_supported_models(self) -> None:
        class RecordingServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(
                    cwd=Path("."), daybreak=True,
                    role_models={
                        "entry_generator": "gpt-5.6-sol",
                        "harness_generator": "gpt-6-sol",
                    },
                )
                self.sent = []
                self._process = object()  # type: ignore[assignment]

            async def start(self):
                return {"started": True}

            async def _request(self, method, params):
                self.sent.append((method, params))
                if method == "thread/start":
                    return {"thread": {"id": f"thread-{len(self.sent)}"}}
                if method == "turn/start":
                    return {"turn": {"id": f"turn-{len(self.sent)}"}}
                return {}

            async def _collect_turn(self, thread_id, turn_id):
                return '{"ok": true}'

        server = RecordingServer()
        for role in ("entry_generator", "harness_generator"):
            self.assertEqual(
                await server.complete_json(
                    role=role, instructions="emit JSON", payload={},
                    output_schema={"type": "object"},
                ), {"ok": True},
            )
        starts = [params for method, params in server.sent if method == "thread/start"]
        turns = [params for method, params in server.sent if method == "turn/start"]
        self.assertNotIn("daybreakEnabled", starts[0])
        self.assertTrue(starts[0]["ephemeral"])
        self.assertTrue(starts[1]["daybreakEnabled"])
        self.assertFalse(starts[1]["ephemeral"])
        self.assertEqual(turns[0]["cyberAccessProgram"], "standard")
        self.assertEqual(turns[1]["cyberAccessProgram"], "daybreakBlue")

    async def test_context_window_error_compacts_same_session_and_retries(self) -> None:
        class RecoveryServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."))
                self.calls = 0
                self.compactions = 0
                self.closed = 0
                self._threads["small_feature:e1"] = (
                    "thread-live", "small_feature"
                )

            async def _complete_json_once(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise CodexContextWindowError("context full")
                return {"ok": True}

            async def compact_session(self, session_key):
                self.asserted_session = session_key
                self.compactions += 1

            async def close(self):
                self.closed += 1

        server = RecoveryServer()
        result = await server.complete_json(
            role="small_feature",
            instructions="continue",
            payload={},
            output_schema={"type": "object"},
            session_key="small_feature:e1",
        )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(server.calls, 2)
        self.assertEqual(server.compactions, 1)
        self.assertEqual(server.asserted_session, "small_feature:e1")
        self.assertEqual(server.closed, 0)
        self.assertIn("small_feature:e1", server._threads)

    async def test_context_capacity_compacts_before_next_turn(self) -> None:
        class CapacityServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."), context_compact_ratio=0.70)
                self.compacted = []

            async def _compact_thread(self, thread_id):
                self.compacted.append(thread_id)

        server = CapacityServer()
        server._thread_usage["thread-1"] = (190_000, 258_400)
        await server._ensure_context_capacity("thread-1", "small next prompt")
        self.assertEqual(server.compacted, ["thread-1"])

    async def test_compaction_retries_transient_reconnect_on_same_thread(self) -> None:
        class ReconnectingServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."))
                self.attempts = []

            async def _compact_thread_once(self, thread_id):
                self.attempts.append(thread_id)
                if len(self.attempts) == 1:
                    raise CodexAppServerError("Reconnecting... 2/2")

        server = ReconnectingServer()
        await server._compact_thread("thread-live")
        self.assertEqual(server.attempts, ["thread-live", "thread-live"])

    async def test_stateful_turn_retries_transient_reconnect_on_same_thread(self) -> None:
        class ReconnectingServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."))
                self.calls = 0
                self.closed = 0
                self.events = []
                self.on_event = self.events.append
                self._threads["input_action:e1:o1"] = (
                    "thread-live", "input_action"
                )

            async def _complete_json_once(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise CodexAppServerError("Reconnecting... 2/2")
                return {"ok": True}

            async def close_session(self, session_key):
                self.closed += 1

        server = ReconnectingServer()
        result = await server.complete_json(
            role="input_action",
            instructions="continue",
            payload={},
            output_schema={"type": "object"},
            session_key="input_action:e1:o1",
        )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(server.calls, 2)
        self.assertEqual(server.closed, 0)
        self.assertIn("input_action:e1:o1", server._threads)
        self.assertTrue(any("retrying once" in event for event in server.events))

    async def test_failed_session_preserves_other_live_session(self) -> None:
        class SharedWorker(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."))
                self._process = object()  # type: ignore[assignment]
                self._threads = {
                    "small_feature:failed": ("thread-failed", "small_feature"),
                    "small_feature:other": ("thread-other", "small_feature"),
                }
                self.deleted = []
                self.closed = False
                self.calls = 0

            async def _complete_json_once(self, **kwargs):
                self.calls += 1
                raise CodexAppServerError("Reconnecting... 2/2")

            async def _request(self, method, params):
                if method == "thread/delete":
                    self.deleted.append(params["threadId"])
                return {}

            async def close(self):
                self.closed = True

        server = SharedWorker()
        with self.assertRaisesRegex(CodexAppServerError, "was lost"):
            await server.complete_json(
                role="small_feature", instructions="continue", payload={},
                output_schema={"type": "object"},
                session_key="small_feature:failed",
            )
        self.assertEqual(server.deleted, ["thread-failed"])
        self.assertEqual(server.calls, 2)
        self.assertIn("small_feature:other", server._threads)
        self.assertFalse(server.closed)

    async def test_compaction_consumes_turn_and_keeps_thread_state(self) -> None:
        class CompactServer(CodexAppServer):
            async def _request(self, method, params):
                self.request = (method, params)
                return {}

        server = CompactServer(cwd=Path("."))
        server._threads["small_feature:e1"] = ("thread-1", "small_feature")
        server._notification_backlog.extend(
            [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "compact-turn"},
                    },
                },
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "compact-turn",
                        "tokenUsage": {
                            "last": {"totalTokens": 200_000},
                            "total": {"totalTokens": 900_000},
                            "modelContextWindow": 258_400,
                        },
                    },
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "compact-turn", "status": "completed"},
                    },
                },
            ]
        )

        await server.compact_session("small_feature:e1")

        self.assertEqual(
            server.request,
            ("thread/compact/start", {"threadId": "thread-1"}),
        )
        self.assertEqual(server._thread_compactions["thread-1"], 1)
        self.assertEqual(server._thread_usage["thread-1"], (32_300, 258_400))
        self.assertEqual(server._threads["small_feature:e1"][0], "thread-1")

    async def test_compaction_reconnect_notice_waits_for_completion(self) -> None:
        class CompactServer(CodexAppServer):
            async def _request(self, method, params):
                return {}

        server = CompactServer(cwd=Path("."))
        server._notification_backlog.extend([
            {"method": "turn/started", "params": {
                "threadId": "thread-1", "turn": {"id": "compact-turn"},
            }},
            {"method": "error", "params": {
                "turnId": "compact-turn", "message": "Reconnecting... 2/5",
            }},
            {"method": "turn/completed", "params": {
                "threadId": "thread-1", "turn": {
                    "id": "compact-turn", "status": "completed",
                },
            }},
        ])
        await server._compact_thread_once("thread-1")
        self.assertEqual(server._thread_compactions["thread-1"], 1)

    async def test_token_usage_uses_last_turn_not_cumulative_total(self) -> None:
        server = CodexAppServer(cwd=Path("."))
        server._record_token_usage(
            "thread/tokenUsage/updated",
            {
                "threadId": "thread-1",
                "tokenUsage": {
                    "last": {"totalTokens": 123_456},
                    "total": {"totalTokens": 999_999},
                    "modelContextWindow": 258_400,
                },
            },
        )
        self.assertEqual(server._thread_usage["thread-1"], (123_456, 258_400))

    async def test_context_window_notification_has_distinct_error_type(self) -> None:
        error = _turn_failure(
            "turn failed",
            {
                "message": "context is full",
                "codexErrorInfo": "contextWindowExceeded",
            },
        )
        self.assertIsInstance(error, CodexContextWindowError)

    async def test_same_session_reuses_one_thread_and_defers_recycle(self) -> None:
        class FakeServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."), max_turns_per_process=1)
                self.requests = []
                self.thread_starts = 0
                self.closed = 0

            async def start(self):
                if self._process is None:
                    self._process = object()  # type: ignore[assignment]
                return {"started": True}

            async def _request(self, method, params):
                self.requests.append((method, params))
                if method == "thread/start":
                    self.thread_starts += 1
                    return {"thread": {"id": f"thread-{self.thread_starts}"}}
                if method == "turn/start":
                    return {"turn": {"id": f"turn-{len(self.requests)}"}}
                return {}

            async def _collect_turn(self, thread_id, turn_id):
                return '{"ok": true}'

            async def close(self):
                self.closed += 1
                self._process = None
                self._threads.clear()
                self._notification_backlog.clear()
                self._turns_since_start = 0
                self._recycle_pending = False

        server = FakeServer()
        for value in (1, 2):
            result = await server.complete_json(
                role="harness_generator",
                instructions="continue",
                payload={"value": value},
                output_schema={"type": "object"},
                session_key="harness_generator:lf-1",
            )
            self.assertEqual(result, {"ok": True})

        self.assertEqual(server.thread_starts, 1)
        self.assertEqual(server.closed, 0)
        turn_threads = [
            params["threadId"] for method, params in server.requests
            if method == "turn/start"
        ]
        self.assertEqual(turn_threads, ["thread-1", "thread-1"])

        await server.close_session("harness_generator:lf-1")
        self.assertEqual(server.closed, 1)

    async def test_pool_keeps_a_session_on_its_original_worker(self) -> None:
        class FakeClient:
            def __init__(self, name):
                self.name = name
                self.calls = []
                self.closed_sessions = []

            async def start(self):
                return None

            async def complete_json(self, **kwargs):
                await asyncio.sleep(0)
                self.calls.append(kwargs["session_key"])
                return {"worker": self.name}

            async def close_session(self, session_key):
                self.closed_sessions.append(session_key)

            async def close(self):
                return None

        pool = CodexAppServerPool(cwd=Path("."), workers=2)
        clients = [FakeClient("zero"), FakeClient("one")]
        pool._clients = clients  # type: ignore[assignment]
        pool._client_locks = [asyncio.Lock(), asyncio.Lock()]
        pool._session_counts = [0, 0]

        first = await pool.complete_json(
            role="entry_verifier", instructions="a", payload={},
            output_schema={"type": "object"}, session_key="entry_verifier:c1",
        )
        await pool.complete_json(
            role="entry_verifier", instructions="b", payload={},
            output_schema={"type": "object"}, session_key="entry_verifier:c2",
        )
        again = await pool.complete_json(
            role="entry_verifier", instructions="c", payload={},
            output_schema={"type": "object"}, session_key="entry_verifier:c1",
        )

        self.assertEqual(first, again)
        self.assertEqual(clients[0].calls, ["entry_verifier:c1", "entry_verifier:c1"])
        self.assertEqual(clients[1].calls, ["entry_verifier:c2"])
        await pool.close_session("entry_verifier:c1")
        self.assertEqual(clients[0].closed_sessions, ["entry_verifier:c1"])

    async def test_failed_thread_delete_forces_recycle_after_last_session(self) -> None:
        class DeleteFailureServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."))
                self.closed = 0
                self._process = object()  # type: ignore[assignment]
                self._threads["small_feature:e1"] = (
                    "thread-orphan", "small_feature"
                )

            async def _request(self, method, params):
                raise CodexAppServerError("delete failed")

            async def close(self):
                self.closed += 1
                self._process = None
                self._threads.clear()
                self._recycle_pending = False

        server = DeleteFailureServer()
        await server.close_session("small_feature:e1")
        self.assertEqual(server.closed, 1)

    async def test_one_shot_failure_does_not_restart_a_live_stateful_worker(self) -> None:
        class MixedServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."))
                self.closed = 0
                self._threads["harness_generator:lf-1"] = (
                    "thread-live", "harness_generator"
                )

            async def _complete_json_once(self, **kwargs):
                raise CodexAppServerError("ephemeral turn failed")

            async def close(self):
                self.closed += 1

        server = MixedServer()
        with self.assertRaisesRegex(
            CodexAppServerError, "refusing a process restart"
        ):
            await server.complete_json(
                role="small_feature",
                instructions="reconcile",
                payload={},
                output_schema={"type": "object"},
            )
        self.assertEqual(server.closed, 0)
        self.assertIn("harness_generator:lf-1", server._threads)

    async def test_failed_ephemeral_delete_recycles_without_losing_result(self) -> None:
        class EphemeralDeleteFailureServer(CodexAppServer):
            def __init__(self) -> None:
                super().__init__(cwd=Path("."), max_turns_per_process=16)
                self.closed = 0

            async def start(self):
                if self._process is None:
                    self._process = object()  # type: ignore[assignment]
                return {"started": True}

            async def _request(self, method, params):
                if method == "thread/start":
                    return {"thread": {"id": "ephemeral-thread"}}
                if method == "turn/start":
                    return {"turn": {"id": "ephemeral-turn"}}
                if method == "thread/delete":
                    raise CodexAppServerError("delete failed")
                return {}

            async def _collect_turn(self, thread_id, turn_id):
                return '{"ok": true}'

            async def close(self):
                self.closed += 1
                self._process = None
                self._threads.clear()
                self._recycle_pending = False

        server = EphemeralDeleteFailureServer()
        result = await server.complete_json(
            role="entry_generator",
            instructions="scan",
            payload={},
            output_schema={"type": "object"},
        )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(server.closed, 1)


if __name__ == "__main__":
    unittest.main()
