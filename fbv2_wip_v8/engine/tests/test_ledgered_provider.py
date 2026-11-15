"""Provider-free durability checks using the existing development ledger."""

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from devtools.ledgered_provider import (
    LedgeredProvider, appserver_event_summary, create_smoke_ledger,
    ledger_summary, load_ledger_module,
)


def request():
    return SimpleNamespace(role="direction", instructions="fixture",
                           payload={"source": "pinned"}, output_schema={},
                           session_key=None, model="fixture", effort="low")


class InspectingProvider:
    def __init__(self, checkpoint_path, error=None):
        self.checkpoint_path = checkpoint_path
        self.error = error
        self.calls = 0

    async def generate(self, model_request):
        self.calls += 1
        # The physical debit must already be durable when transport starts.
        checkpoint = json.loads(self.checkpoint_path.read_text())
        assert checkpoint["physical"] == 1
        assert checkpoint["attempts"][-1]["status"] == "STARTED"
        if self.error:
            raise self.error
        return {"content": "fixture", "tool_calls": []}

    async def close(self):
        pass


class LedgeredProviderTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.checkpoint = Path(self.temp.name) / "requests.json"
        self.module = load_ledger_module()
        self.ledger = create_smoke_ledger(
            self.module, checkpoint_path=self.checkpoint,
            scope_id="fixture-direction", role=self.module.DIRECTION_ROLE,
            physical_max=2, wall_seconds=60)

    async def test_physical_start_is_persisted_before_provider_and_completed_once(self):
        delegate = InspectingProvider(self.checkpoint)
        provider = LedgeredProvider(delegate, self.ledger,
                                    scope_id="fixture-direction",
                                    role=self.module.DIRECTION_ROLE)

        self.assertEqual((await provider.generate(request()))["content"], "fixture")
        self.assertEqual(delegate.calls, 1)
        self.assertEqual((self.ledger.logical, self.ledger.physical), (1, 1))
        self.assertEqual(self.ledger.attempts[-1]["status"], "COMPLETED")

    async def test_interrupted_started_attempt_restores_as_terminal_uncertain(self):
        # Simulate process death after durable start and before any response.
        digest = "a" * 64
        self.ledger.begin_turn("fixture-direction", self.module.DIRECTION_ROLE, digest)
        self.ledger.start_attempt(digest)

        restored = self.module.DevelopmentRequestLedger.restore(
            self.checkpoint, self.ledger.budget)

        self.assertEqual(restored.physical, 1)
        self.assertEqual(restored.attempts[-1]["status"],
                         "INTERRUPTED_UNCERTAIN_REMOTE_STATE")
        self.assertEqual(restored.pending_work[-1]["state"],
                         "INCOMPLETE_UNCERTAIN_REMOTE_STATE")
        with self.assertRaisesRegex(ValueError, "terminal model turn"):
            restored.begin_turn("fixture-direction", self.module.DIRECTION_ROLE,
                                "b" * 64)

    async def test_provider_error_is_not_retried(self):
        delegate = InspectingProvider(self.checkpoint, RuntimeError("remote uncertain"))
        provider = LedgeredProvider(delegate, self.ledger,
                                    scope_id="fixture-direction",
                                    role=self.module.DIRECTION_ROLE)

        with self.assertRaisesRegex(RuntimeError, "remote uncertain"):
            await provider.generate(request())

        self.assertEqual(delegate.calls, 1)
        self.assertEqual(self.ledger.physical, 1)
        self.assertEqual(self.ledger.pending_work[-1]["state"],
                         "INCOMPLETE_UNCERTAIN_REMOTE_STATE")

    async def test_semantically_identical_checkpoint_byte_change_is_rejected(self):
        delegate = InspectingProvider(self.checkpoint)
        provider = LedgeredProvider(delegate, self.ledger,
                                    scope_id="fixture-direction",
                                    role=self.module.DIRECTION_ROLE)
        await provider.generate(request())
        self.assertIsNone(ledger_summary(self.ledger)["ledger_checkpoint_error"])

        # A JSON reader would accept this file, but it is no longer the
        # exact checkpoint whose bytes the ledger last made durable.
        with self.checkpoint.open("ab") as file:
            file.write(b" ")
        summary = ledger_summary(self.ledger)
        self.assertEqual(summary["ledger_checkpoint_error"],
                         "CHECKPOINT_BYTE_MISMATCH")
        self.assertNotEqual(summary["ledger_checkpoint_sha256"],
                            self.ledger._checkpoint_sha256)

    async def test_appserver_turn_events_are_distinct_from_predebit(self):
        event_log = Path(self.temp.name) / "events.jsonl"
        events = [
            {"method": "turn/started", "turn_id": "",
             "params": {"turn": {"id": "turn-a"}}},
            {"method": "thread/tokenUsage/updated", "turn_id": "turn-a",
             "params": {"tokenUsage": {"last": {"inputTokens": 100,
                                                 "outputTokens": 10}}}},
            {"method": "turn/completed", "turn_id": "turn-a"},
        ]
        event_log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
        summary = appserver_event_summary(event_log)
        self.assertIsNone(summary["event_log_error"])
        self.assertEqual(summary["appserver_turns_started"], 1)
        self.assertEqual(summary["appserver_turns_completed"], 1)
        self.assertEqual(summary["appserver_input_tokens_reported"], 100)
        self.assertEqual(summary["appserver_output_tokens_reported"], 10)

        # A durable predebit with no App Server turn is a reservation, not a
        # measured remote model call.
        event_log.write_text("", encoding="utf-8")
        summary = appserver_event_summary(event_log)
        self.assertEqual(summary["appserver_turns_started"], 0)
        self.assertEqual(summary["appserver_turns_completed"], 0)
