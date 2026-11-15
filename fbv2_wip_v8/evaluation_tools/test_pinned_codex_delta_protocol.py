"""Provider-free regressions for pinned Codex 0.164 delta notifications."""

from __future__ import annotations

import asyncio
import copy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import blind2_runner_draft as runner  # noqa: E402
from dev_global_appserver_bridge import DevelopmentGlobalAppServer  # noqa: E402
from pinned_codex_delta_protocol import pinned_delta_violation  # noqa: E402
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger,
)
from vulnerabilityanalysis.llm import (  # noqa: E402
    CodexAppServerClient, ModelToolEventError,
)


def _client(kind: str, root: Path):
    if kind == 'development':
        budget = DevelopmentBudget(physical_max=1, logical_max=1,
                                   retries_max=0, wall_seconds=60,
                                   initial_starts_required=1)
        ledger = DevelopmentRequestLedger.create(budget, root / 'ledger.json')
        return DevelopmentGlobalAppServer(
            ledger=ledger, role_models={}, cwd=root,
            event_log_path=root / 'events.jsonl')
    return runner.GuardedAppServer(
        ledger=runner.Ledger(started_at=time.time()),
        checkpoint=root / 'ledger.json', route_sha256='a' * 64,
        role_models={}, codex_executable_path=root / 'unused',
        codex_executable_sha256='a' * 64, cwd=root,
        event_log_path=root / 'events.jsonl')


def _message(method: str = 'item/agentMessage/delta', **extra):
    params = {'threadId': 'thread-1', 'turnId': 'turn-1',
              'itemId': 'item-1', 'delta': 'PRIVATE_DELTA_CONTENT'}
    params.update(extra)
    return {'method': method, 'params': params}


class PinnedDeltaProtocolTests(unittest.IsolatedAsyncioTestCase):
    def test_exact_pinned_shapes_types_and_signed_index_bounds(self):
        for method, index in (
                ('item/reasoning/textDelta', 'contentIndex'),
                ('item/reasoning/summaryTextDelta', 'summaryIndex')):
            with self.subTest(method=method):
                self.assertIsNone(pinned_delta_violation(
                    _message(method, **{index: -(1 << 63)})))
                self.assertEqual(pinned_delta_violation(
                    _message(method, **{index: True})),
                    'UNAPPROVED_DELTA_SHAPE')
                self.assertEqual(pinned_delta_violation(
                    _message(method, **{index: 1 << 63})),
                    'UNAPPROVED_DELTA_SHAPE')
                self.assertEqual(pinned_delta_violation(_message(method)),
                                 'UNAPPROVED_DELTA_SHAPE')
        for key, value in (('delta', 1), ('itemId', ''), ('threadId', None)):
            with self.subTest(key=key):
                self.assertEqual(pinned_delta_violation(_message(**{key: value})),
                                 'UNAPPROVED_DELTA_SHAPE')
        self.assertIsNone(pinned_delta_violation(_message(delta='')))
        self.assertIsNone(pinned_delta_violation({'method': 'turn/completed',
                                                 'params': {'turn': {}}}))

    async def test_queued_hidden_nested_field_is_rejected_before_product_collect(self):
        for kind in ('development', 'formal'):
            with self.subTest(kind=kind), TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                client = _client(kind, root)
                client._notifications.append(_message(
                    extra={'nested': {'type': 'commandExecution'}}))
                with patch.object(CodexAppServerClient, '_collect',
                                  new_callable=AsyncMock,
                                  return_value='{"answer":"4"}') as base:
                    with self.assertRaises(ModelToolEventError):
                        await client._collect('thread-1', 'turn-1')
                    base.assert_not_awaited()
                self.assertTrue(client.forbidden_tool_event)
                if client.event_log_path.is_file():
                    content = client.event_log_path.read_text()
                    self.assertNotIn('PRIVATE_DELTA_CONTENT', content)
                    self.assertIn('UNAPPROVED_DELTA_SHAPE', content)

    async def test_new_wire_delta_wrong_shape_is_rejected(self):
        for kind in ('development', 'formal'):
            with self.subTest(kind=kind), TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                client = _client(kind, root)
                client._active_thread_id = 'thread-1'
                client._active_turn_id = 'turn-1'
                bad = _message(item={'type': 'commandExecution'})
                with patch.object(CodexAppServerClient, '_read',
                                  new_callable=AsyncMock, return_value=bad):
                    with self.assertRaises(ModelToolEventError):
                        await client._read()
                self.assertTrue(client.forbidden_tool_event)

    async def test_malformed_summary_part_is_not_logged_with_extra_delta_text(self):
        for kind in ('development', 'formal'):
            with self.subTest(kind=kind), TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                client = _client(kind, root)
                message = {'method': 'item/reasoning/summaryPartAdded',
                           'params': {'threadId': 'thread-1',
                                      'turnId': 'turn-1', 'itemId': 'item-1',
                                      'summaryIndex': 0,
                                      'delta': 'PRIVATE_DELTA_CONTENT'}}
                with self.assertRaises(ModelToolEventError):
                    client._record_server_event(message)
                content = client.event_log_path.read_text()
                self.assertNotIn('PRIVATE_DELTA_CONTENT', content)
                self.assertIn('UNAPPROVED_DELTA_SHAPE', content)
                self.assertTrue(client.forbidden_tool_event)

    async def test_wrong_turn_delta_is_rejected_before_collection(self):
        for kind in ('development', 'formal'):
            with self.subTest(kind=kind), TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                client = _client(kind, root)
                client._notifications.append(_message(turnId='other-turn'))
                with patch.object(CodexAppServerClient, '_collect',
                                  new_callable=AsyncMock,
                                  return_value='{"answer":"4"}'):
                    with self.assertRaises(ModelToolEventError):
                        await client._collect('thread-1', 'turn-1')

    async def test_pinned_official_delta_shapes_are_accepted(self):
        cases = (
            _message(),
            _message('item/reasoning/textDelta', contentIndex=0),
            _message('item/reasoning/summaryTextDelta', summaryIndex=0),
            {'method': 'item/reasoning/summaryPartAdded', 'params': {
                'threadId': 'thread-1', 'turnId': 'turn-1',
                'itemId': 'item-1', 'summaryIndex': 0}},
        )
        for kind in ('development', 'formal'):
            with self.subTest(kind=kind), TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                client = _client(kind, root)
                client._active_thread_id = 'thread-1'
                client._active_turn_id = 'turn-1'
                for message in cases:
                    with patch.object(CodexAppServerClient, '_read',
                                      new_callable=AsyncMock,
                                      return_value=message):
                        self.assertEqual(await client._read(), message)
                self.assertFalse(client.forbidden_tool_event)
                client._record_server_event(copy.deepcopy(cases[0]))
                self.assertNotIn('PRIVATE_DELTA_CONTENT',
                                 client.event_log_path.read_text())


if __name__ == '__main__':
    unittest.main()
