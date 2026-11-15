"""Provider-free wire-boundary regressions for the development request guard."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev_global_appserver_bridge import (  # noqa: E402
    DevelopmentGlobalAppServer, verify_model_event_order,
    verify_product_request_order,
)
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentBudgetExhausted, DevelopmentRequestLedger,
)
from dev_persistent_physical_fuzz_ledger import (  # noqa: E402
    PersistentPhysicalFuzzLedger, PhysicalModelStartBlocked,
)
from vulnerabilityanalysis.llm import (  # noqa: E402
    AppServerError, CodexAppServerClient, LLMRequest, ModelAuditError,
    ModelToolEventError,
)


ROUTES = {
    'direction_generator': {'model': 'test-model', 'reasoning': 'high'},
    'sp_generation': {'model': 'test-model', 'reasoning': 'high'},
    'function_analysis': {'model': 'test-model', 'reasoning': 'high'},
}
SCHEMA = {'type': 'object', 'properties': {'answer': {'type': 'string'}},
          'required': ['answer'], 'additionalProperties': False}


def request(role: str, *, value: int = 4) -> LLMRequest:
    return LLMRequest(role=role, instructions='Answer the supplied arithmetic.',
                      payload={'value': value}, output_schema=SCHEMA,
                      model='test-model', effort='high')


def budget(*, physical: int = 4, logical: int = 4,
           retries: int = 1) -> DevelopmentBudget:
    return DevelopmentBudget(physical_max=physical, logical_max=logical,
                             retries_max=retries, wall_seconds=60,
                             initial_starts_required=1)


class FakeWireServer(DevelopmentGlobalAppServer):
    def __init__(self, ledger: DevelopmentRequestLedger, root: Path,
                 outcomes: list[str], *,
                 physical_ledger: PersistentPhysicalFuzzLedger | None = None):
        self.sent: list[dict] = []
        self.outcomes = outcomes
        self.retry_route_checks = 0
        self.closed_count = 0

        async def route() -> None:
            self.retry_route_checks += 1

        physical_option = ({'physical_ledger': physical_ledger}
                           if physical_ledger is not None else {})
        super().__init__(ledger=ledger, role_models=ROUTES,
                         retry_route_check=route, cwd=root,
                         **physical_option,
                         model='test-model', effort='high', timeout_seconds=1)

    async def start(self) -> None:
        pass

    async def _thread_for(self, role, session_key, model) -> str:
        return 'test-thread'

    async def _delete_ephemeral_thread(self, thread_id: str) -> None:
        pass

    async def _transport_request(self, method: str, params: dict, *, response_envelope=None) -> dict:
        if method != 'turn/start':
            return {}
        # _request must have durably persisted this attempt before transport.
        snapshot = json.loads(self.ledger.checkpoint_path.read_text())
        self.sent.append({'method': method, 'params': params,
                          'physical': snapshot['physical'],
                          'attempt_status': snapshot['attempts'][-1]['status']})
        return {'turn': {'id': f'test-turn-{len(self.sent)}'}}

    async def _collect(self, thread_id: str, turn_id: str, *, response_envelope=None) -> str:
        outcome = self.outcomes.pop(0)
        if outcome == 'stream':
            raise AppServerError('stream disconnected before completion')
        if outcome == 'visible_stream':
            self._visible_output = True
            raise AppServerError('stream disconnected before completion')
        if outcome == 'tool':
            self.forbidden_tool_event = True
            raise ModelToolEventError('FORBIDDEN_MODEL_TOOL_EVENT: commandExecution')
        if outcome == 'cancel':
            raise asyncio.CancelledError()
        if outcome == 'malformed':
            # Server completed, but product-side JSON parsing will fail.
            self._server_terminal_status = 'completed'
            return '{"answer":'
        if outcome == 'nonbudget_limit':
            raise ValueError('schema limit mismatch')
        return '{"answer":"4"}'

    async def close(self) -> None:
        self.closed_count += 1


class DevelopmentWireBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_wire_model_start_obeys_physical_stop(self):
        for mode in ('active', 'cleanup_incomplete'):
            with self.subTest(mode=mode), TemporaryDirectory() as temp:
                root = Path(temp)
                model = DevelopmentRequestLedger.create(
                    budget(physical=1, logical=1, retries=0), root / 'model.json')
                model.select_function('fn')
                physical = PersistentPhysicalFuzzLedger.create(
                    root / 'physical.json', total_seconds=20)
                physical.reserve('SP:one', 'SP', 10)
                if mode == 'cleanup_incomplete':
                    physical.finish('SP:one', physical_seconds=1,
                                    cleanup_complete=False)
                wire = FakeWireServer(model, root, ['ok'], physical_ledger=physical)
                wire.bind_scope('fn')
                with self.assertRaises(PhysicalModelStartBlocked):
                    await wire.generate(request('sp_generation'))
                self.assertEqual(wire.sent, [])
                self.assertEqual(model.physical, 0)
                self.assertIsNone(model.active_turn)
                self.assertEqual(wire.closed_count, 1)
                if mode == 'active':
                    physical.finish('SP:one', physical_seconds=1)

    async def test_real_wire_model_start_with_settled_physical_ledger(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            model = DevelopmentRequestLedger.create(
                budget(physical=1, logical=1, retries=0), root / 'model.json')
            model.select_function('fn')
            physical = PersistentPhysicalFuzzLedger.create(
                root / 'physical.json', total_seconds=20)
            wire = FakeWireServer(model, root, ['ok'], physical_ledger=physical)
            wire.bind_scope('fn')
            self.assertEqual((await wire.generate(request('sp_generation')))['answer'], '4')
            self.assertEqual(model.physical, 1)
            self.assertEqual(len(wire.sent), 1)

    async def test_physical_stop_after_durable_start_blocks_following_wire(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            model = DevelopmentRequestLedger.create(
                budget(physical=2, logical=2, retries=0), root / 'model.json')
            model.select_function('fn')
            physical = PersistentPhysicalFuzzLedger.create(
                root / 'physical.json', total_seconds=20)
            wire = FakeWireServer(model, root, ['ok'], physical_ledger=physical)
            wire.bind_scope('fn')
            transport = wire._transport_request

            async def stop_after_start(method: str, params: dict, *, response_envelope=None) -> dict:
                self.assertEqual(model.physical, 1)
                physical.reserve('HP:late-stop', 'HP', 10)
                physical.finish('HP:late-stop', physical_seconds=1,
                                cleanup_complete=False)
                return await transport(method, params, response_envelope=response_envelope)

            wire._transport_request = stop_after_start
            self.assertEqual((await wire.generate(request('sp_generation')))['answer'], '4')
            self.assertEqual(len(wire.sent), 1)
            with self.assertRaises(PhysicalModelStartBlocked):
                await wire.generate(request('function_analysis'))
            self.assertEqual(len(wire.sent), 1)
            self.assertEqual(model.physical, 1)
            self.assertEqual(wire.closed_count, 1)

    async def test_cleanup_stop_between_stream_failure_and_retry_blocks_wire(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            model = DevelopmentRequestLedger.create(
                budget(physical=2, logical=1, retries=1), root / 'model.json')
            model.select_function('fn')
            physical = PersistentPhysicalFuzzLedger.create(
                root / 'physical.json', total_seconds=20)
            wire = FakeWireServer(model, root, ['stream', 'ok'],
                                  physical_ledger=physical)
            wire.bind_scope('fn')
            collect = wire._collect

            async def stop_then_stream(thread_id: str, turn_id: str, *, response_envelope=None) -> str:
                physical.reserve('SP:retry-stop', 'SP', 10)
                physical.finish('SP:retry-stop', physical_seconds=1,
                                cleanup_complete=False)
                wire._collect = collect
                return await collect(thread_id, turn_id, response_envelope=response_envelope)

            wire._collect = stop_then_stream
            with self.assertRaises(PhysicalModelStartBlocked):
                await wire.generate(request('sp_generation'))
            self.assertEqual(len(wire.sent), 1)
            self.assertEqual(model.physical, 1)
            self.assertIsNone(model.active_turn)
            self.assertGreaterEqual(wire.closed_count, 1)

    async def _completed_attempt(self, root: Path) -> tuple[DevelopmentRequestLedger, str]:
        ledger = DevelopmentRequestLedger.create(
            budget(physical=1, logical=1, retries=0), root / 'ledger.json')
        ledger.select_function('fn')
        wire = FakeWireServer(ledger, root, ['ok'])
        wire.bind_scope('fn')
        await wire.generate(request('sp_generation'))
        return ledger, ledger.attempts[0]['app_server_turn_id']

    async def test_private_full_event_log_preserves_large_harmless_items(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger, turn_id = await self._completed_attempt(root)
            log = root / 'model-events.jsonl'
            client = DevelopmentGlobalAppServer(
                ledger=ledger, role_models=ROUTES, cwd=root,
                model='test-model', effort='high', event_log_path=log)
            # An official V2 Direction turn has emitted harmless item params
            # above 113 KiB. The private development log must keep the whole
            # item so the offline audit can verify its type and turn ID.
            item = {'type': 'userMessage', 'text': 'public toy ' * 25000}
            for method in ('item/started', 'item/completed'):
                client._record_server_event({'method': method, 'params': {
                    'threadId': 'test-thread', 'turnId': turn_id, 'item': item}})
            client._record_server_event({'method': 'turn/completed', 'params': {
                'threadId': 'test-thread',
                'turn': {'id': turn_id, 'status': 'completed', 'items': [item]}}})
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(isinstance(row.get('params'), dict) for row in rows))
            self.assertTrue(all('params_omitted_bytes' not in row for row in rows))
            self.assertGreater(len(json.dumps(rows[-1]['params']).encode()), 4096)
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            verify_model_event_order(ledger, log)
            self.assertEqual(CodexAppServerClient.STARTUP_NOTIFICATION_AUDIT_MAX_BYTES,
                             4096)
            warning = {'method': 'warning', 'params': {
                'threadId': 'test-thread', 'message': 'w' * 5000}}
            self.assertEqual(client._unapproved_event_label(warning),
                             'warning:PARAMS_TOO_LARGE')
            product_client = CodexAppServerClient(cwd=root)
            self.assertEqual(product_client._unapproved_event_label(warning),
                             'warning:PARAMS_TOO_LARGE')

    async def test_safety_buffering_summary_binds_to_raw_completed_turn(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger, turn_id = await self._completed_attempt(root)
            log = root / 'model-events.jsonl'
            client = DevelopmentGlobalAppServer(
                ledger=ledger, role_models=ROUTES, cwd=root,
                model='test-model', effort='high', event_log_path=log)
            client._record_server_event({'method': 'turn/started', 'params': {
                'threadId': 'test-thread', 'turn': {'id': turn_id}}})
            client._record_server_event({
                'method': 'model/safetyBuffering/updated', 'params': {
                    'threadId': 'test-thread', 'turnId': turn_id,
                    'model': 'test-model', 'fasterModel': None,
                    'reasons': ['user_risk'], 'useCases': ['bio'],
                    'showBufferingUi': True}})
            client._record_server_event({'method': 'turn/completed', 'params': {
                'threadId': 'test-thread',
                'turn': {'id': turn_id, 'status': 'completed', 'items': []}}})
            summary = {
                'classification': 'PROVIDER_SAFETY_BUFFERING',
                'buffered': True, 'thread_id': 'test-thread',
                'turn_id': turn_id, 'role': 'sp_generation',
                'requested_model': 'test-model', 'faster_models': [],
                'reasons': ['user_risk'], 'use_cases': ['bio'],
                'buffer_to_turn_end_seconds': 0.1,
                'buffer_to_stop_seconds': None, 'turn_status': 'completed',
            }
            with log.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(summary) + '\n')
            verify_model_event_order(ledger, log)
            raw_lines = log.read_text(encoding='utf-8').splitlines()[:-1]
            for change in ({'requested_model': 'other-model'},
                           {'role': 'function_analysis'},
                           {'buffer_to_turn_end_seconds': -1},
                           {'unexpected': 'ignored?'}):
                with self.subTest(change=change):
                    forged = {**summary, **change}
                    log.write_text('\n'.join([*raw_lines, json.dumps(forged)])
                                   + '\n', encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, 'safety'):
                        verify_model_event_order(ledger, log)
            log.write_text('\n'.join(raw_lines) + '\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'ledger'):
                verify_model_event_order(ledger, log)
            log.write_text('\n'.join([raw_lines[0], raw_lines[2],
                                      json.dumps(summary)]) + '\n',
                           encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'safety'):
                verify_model_event_order(ledger, log)

    async def test_private_full_turn_summary_still_rejects_hidden_tool(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger, turn_id = await self._completed_attempt(root)
            log = root / 'model-events.jsonl'
            client = DevelopmentGlobalAppServer(
                ledger=ledger, role_models=ROUTES, cwd=root,
                model='test-model', effort='high', event_log_path=log)
            message = {'method': 'turn/completed', 'params': {
                'threadId': 'test-thread', 'turn': {
                    'id': turn_id, 'status': 'completed', 'items': [
                        {'type': 'userMessage', 'text': 'p' * 5000},
                        {'type': 'commandExecution'}]}}}
            client._notifications.append(message)
            with self.assertRaisesRegex(ModelToolEventError, 'TURN_SUMMARY_CONTAINS_TOOL_ITEM'):
                await client._collect('test-thread', turn_id)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue('params' in rows[0])
            with self.assertRaisesRegex(ValueError, 'tool or server'):
                verify_model_event_order(ledger, log)

    async def test_private_event_over_1m_stays_incomplete_for_offline_audit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger, turn_id = await self._completed_attempt(root)
            log = root / 'model-events.jsonl'
            client = DevelopmentGlobalAppServer(
                ledger=ledger, role_models=ROUTES, cwd=root,
                model='test-model', effort='high', event_log_path=log)
            client._record_server_event({'method': 'item/started', 'params': {
                'threadId': 'test-thread', 'turnId': turn_id,
                'item': {'type': 'userMessage', 'text': 'p' * 1100000}}})
            row = json.loads(log.read_text().splitlines()[0])
            self.assertGreater(row['params_omitted_bytes'], 1048576)
            self.assertNotIn('params', row)
            with self.assertRaisesRegex(ValueError, 'params unavailable'):
                verify_model_event_order(ledger, log)

    async def test_private_event_log_wrong_mode_stops_the_client(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger, turn_id = await self._completed_attempt(root)
            log = root / 'model-events.jsonl'
            log.write_text('')
            log.chmod(0o644)
            client = DevelopmentGlobalAppServer(
                ledger=ledger, role_models=ROUTES, cwd=root,
                model='test-model', effort='high', event_log_path=log)
            with self.assertRaisesRegex(ModelAuditError, 'MODEL_AUDIT_WRITE_FAILED'):
                client._record_server_event({'method': 'item/started', 'params': {
                    'threadId': 'test-thread', 'turnId': turn_id,
                    'item': {'type': 'userMessage', 'text': 'public toy'}}})
            self.assertTrue(client.audit_log_failed)

    async def test_buffered_internal_retry_stops_before_base_collector(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=1), root / 'ledger.json')
            client = DevelopmentGlobalAppServer(
                ledger=ledger, role_models=ROUTES, cwd=root,
                model='test-model', effort='high')
            client._notifications.append({'method': 'error', 'params': {
                'threadId': 't', 'turnId': 'turn', 'willRetry': True}})
            with self.assertRaisesRegex(AppServerError, 'internal retry'):
                await client._collect('t', 'turn')
            self.assertTrue(client._internal_retry)

    async def test_direction_and_functions_share_physical_chain_and_cap_prevents_wire(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=3), root / 'ledger.json')
            ledger.register_direction('plan')
            client = FakeWireServer(ledger, root, ['ok', 'ok'])
            client.bind_scope('plan')
            self.assertEqual((await client.generate(request('direction_generator')))
                             ['answer'], '4')
            client.unbind_scope()
            self.assertTrue(ledger.select_function('fn'))
            client.bind_scope('fn')
            await client.generate(request('sp_generation'))
            with self.assertRaisesRegex(ValueError, 'not eligible'):
                await client.generate(request('function_analysis'))
            self.assertEqual([row['physical'] for row in client.sent], [1, 2])
            self.assertEqual([row['attempt_status'] for row in client.sent],
                             ['STARTED', 'STARTED'])
            self.assertEqual((ledger.physical, ledger.logical), (2, 2))

    async def test_eligible_stream_retry_uses_same_logical_turn_and_hash(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=1), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['stream', 'ok'])
            client.bind_scope('fn')
            self.assertEqual((await client.generate(request('sp_generation')))
                             ['answer'], '4')
            self.assertEqual((ledger.logical, ledger.physical, ledger.retries),
                             (1, 2, 1))
            self.assertEqual(client.retry_route_checks, 1)
            self.assertEqual([row['retry'] for row in ledger.attempts],
                             [False, True])
            self.assertEqual(ledger.attempts[0]['request_hash'],
                             ledger.attempts[1]['request_hash'])

    async def test_visible_output_tool_event_and_cancel_never_retry(self):
        for outcome, error_type in [('visible_stream', AppServerError),
                                    ('tool', ModelToolEventError),
                                    ('cancel', asyncio.CancelledError)]:
            with self.subTest(outcome=outcome), TemporaryDirectory() as temp:
                root = Path(temp)
                ledger = DevelopmentRequestLedger.create(
                    budget(physical=2, logical=1), root / 'ledger.json')
                ledger.select_function('fn')
                client = FakeWireServer(ledger, root, [outcome])
                client.bind_scope('fn')
                with self.assertRaises(error_type):
                    await client.generate(request('sp_generation'))
                self.assertEqual(len(client.sent), 1)
                self.assertEqual(ledger.retries, 0)
                self.assertEqual(ledger.function_states['fn'],
                                 'INCOMPLETE_INTERRUPTED')
                self.assertEqual(ledger.attempts[0]['status'], 'ERROR')

    async def test_wall_budget_failure_during_start_is_pending_budget(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=2), root / 'ledger.json')
            ledger.select_function('fn')
            start = ledger.start_attempt

            def expire_before_start(digest: str, *, retry: bool = False) -> int:
                ledger.started_at = time.time() - ledger.budget.wall_seconds - 1
                ledger.checkpoint()
                return start(digest, retry=retry)

            ledger.start_attempt = expire_before_start  # type: ignore[method-assign]
            client = FakeWireServer(ledger, root, [])
            client.bind_scope('fn')
            with self.assertRaisesRegex(DevelopmentBudgetExhausted, 'wall limit'):
                await client.generate(request('sp_generation'))
            self.assertEqual(client.sent, [])
            self.assertEqual(ledger.function_states['fn'], 'INCOMPLETE_BUDGET')
            self.assertEqual(ledger.physical, 0)
            self.assertEqual(ledger.pending_work[0]['state'],
                             'INCOMPLETE_PRE_SEND_MODEL_TURN')
            self.assertEqual(ledger.turns[0]['status'], 'INCOMPLETE_BUDGET')

    async def test_nonbudget_value_error_with_limit_word_stays_interrupted(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=2), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['nonbudget_limit'])
            client.bind_scope('fn')
            with self.assertRaisesRegex(ValueError, 'schema limit mismatch'):
                await client.generate(request('sp_generation'))
            self.assertEqual(len(client.sent), 1)
            self.assertEqual(ledger.physical, 1)
            self.assertEqual(ledger.function_states['fn'], 'INCOMPLETE_INTERRUPTED')
            self.assertEqual(ledger.pending_work[0]['state'],
                             'INCOMPLETE_UNCERTAIN_REMOTE_STATE')

    async def test_restore_after_unsettled_start_never_resends(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'ledger.json'
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=1), path)
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, [])
            client.bind_scope('fn')
            value = request('sp_generation')
            from dev_global_appserver_bridge import request_hash
            digest = request_hash(value)
            ledger.begin_turn('fn', 'sp_generation', digest)
            client._request_hash = digest
            await client._request('turn/start', {'model': 'test-model',
                                                 'effort': 'high'})
            self.assertEqual(len(client.sent), 1)
            restored = DevelopmentRequestLedger.restore(path, ledger.budget)
            self.assertEqual(restored.physical, 1)
            self.assertEqual(restored.attempts[0]['status'],
                             'INTERRUPTED_UNCERTAIN_REMOTE_STATE')
            self.assertEqual(restored.pending_work[0]['state'],
                             'INCOMPLETE_UNCERTAIN_REMOTE_STATE')
            self.assertEqual(restored.function_states['fn'],
                             'INCOMPLETE_INTERRUPTED')
            with self.assertRaises(ValueError):
                restored.begin_turn('fn', 'sp_generation', digest)

    async def test_product_artifact_order_is_bound_to_logical_turn_hash(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=2), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['ok', 'ok'])
            client.bind_scope('fn')
            values = [request('sp_generation', value=4),
                      request('sp_generation', value=5)]
            artifacts = []
            for index, value in enumerate(values):
                await client.generate(value)
                path = root / f'request-{index}.json'
                path.write_text(json.dumps({
                    'role': value.role, 'instructions': value.instructions,
                    'payload': value.payload, 'output_schema': value.output_schema,
                    'model': value.model, 'reasoning': value.effort}))
                artifacts.append(path)
            verify_product_request_order(ledger, artifacts, scope_id='fn')
            with self.assertRaisesRegex(ValueError, 'order or content'):
                verify_product_request_order(ledger, artifacts[::-1], scope_id='fn')

            events = root / 'model-events.jsonl'
            rows = [{'method': 'turn/completed',
                     'turn_id': row['app_server_turn_id'],
                     'thread_id': 'test-thread', 'item_type': None,
                     'server_request': False,
                     'params': {'threadId': 'test-thread',
                                'turn': {'id': row['app_server_turn_id'],
                                         'status': 'completed'}}}
                    for row in ledger.attempts]
            events.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
            verify_model_event_order(ledger, events)
            events.write_text('\n'.join(json.dumps(row) for row in rows[::-1]) + '\n')
            with self.assertRaisesRegex(ValueError, 'order differs'):
                verify_model_event_order(ledger, events)
            events.write_text(json.dumps({
                'method': 'item/completed', 'turn_id': rows[0]['turn_id'],
                'server_request': False, 'item_type': 'commandExecution'}) + '\n')
            with self.assertRaisesRegex(ValueError, 'tool or server'):
                verify_model_event_order(ledger, events)
            # Red-team counterexample: item_type alone misses a command method
            # if the event row has no embedded item and is a notification.
            command = {'method': 'commandExecution/started', 'turn_id': '',
                       'thread_id': '', 'item_type': None,
                       'server_request': False, 'params': {}}
            events.write_text('\n'.join(json.dumps(row) for row in
                                        [command, *rows]) + '\n')
            with self.assertRaisesRegex(ValueError, 'tool or server'):
                verify_model_event_order(ledger, events)
            hidden_tool = json.loads(json.dumps(rows))
            hidden_tool[0]['params']['turn']['items'] = [
                {'type': 'commandExecution'}]
            events.write_text('\n'.join(json.dumps(row) for row in
                                        hidden_tool) + '\n')
            with self.assertRaisesRegex(ValueError, 'tool or server'):
                verify_model_event_order(ledger, events)

    async def test_late_duplicate_completion_is_bound_to_original_turn(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=2, logical=2, retries=0), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['ok', 'ok'])
            client.bind_scope('fn')
            await client.generate(request('sp_generation', value=4))
            await client.generate(request('sp_generation', value=5))
            turn_ids = [row['app_server_turn_id'] for row in ledger.attempts]
            completions = [{
                'method': 'turn/completed', 'thread_id': 'test-thread',
                'turn_id': turn_id, 'item_type': None,
                'server_request': False,
                'params': {'threadId': 'test-thread', 'turn': {
                    'id': turn_id, 'status': 'completed', 'items': []}},
            } for turn_id in turn_ids]
            summary = {'method': 'turn/completed',
                       'classification': 'STALE_OR_UNRELATED_TURN_EVENT',
                       'thread_id': 'test-thread', 'turn_id': turn_ids[0]}
            log = root / 'model-events.jsonl'

            def write_rows(rows):
                log.write_text(''.join(json.dumps(row) + '\n' for row in rows),
                               encoding='utf-8')

            write_rows([*completions, completions[0], summary])
            verify_model_event_order(ledger, log)
            for rows in (
                    [*completions, completions[0]],
                    [*completions, summary],
                    [*completions, {**completions[0], 'params': {
                        'threadId': 'test-thread', 'turn': {
                            'id': turn_ids[0], 'status': 'failed',
                            'items': []}}}, summary],
                    [*completions, {**completions[0], 'params': {
                        'threadId': 'test-thread', 'turn': {
                            'id': turn_ids[0], 'status': 'completed',
                            'items': [{'type': 'commandExecution'}]}}}, summary],
            ):
                with self.subTest(rows=rows):
                    write_rows(rows)
                    with self.assertRaises(ValueError):
                        verify_model_event_order(ledger, log)
    async def test_failed_terminal_event_matches_error_attempt(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=1, logical=1, retries=0), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['stream'])
            client.bind_scope('fn')
            with self.assertRaises(AppServerError):
                await client.generate(request('sp_generation'))
            turn_id = ledger.attempts[0]['app_server_turn_id']
            events = root / 'model-events.jsonl'
            events.write_text(json.dumps({
                'method': 'turn/completed', 'turn_id': turn_id,
                'thread_id': 'test-thread', 'item_type': None,
                'server_request': False,
                'params': {'threadId': 'test-thread',
                           'turn': {'id': turn_id, 'status': 'failed',
                                    'error': {'message': 'stream broken'}}}}) + '\n')
            verify_model_event_order(ledger, events)
            events.write_text(json.dumps({
                'method': 'error', 'turn_id': turn_id,
                'thread_id': 'test-thread', 'item_type': None,
                'server_request': False,
                'params': {'threadId': 'test-thread', 'turnId': turn_id,
                           'willRetry': False, 'message': 'stream broken'}}) + '\n')
            verify_model_event_order(ledger, events)

    async def test_server_success_with_product_parse_error_is_not_success(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=1, logical=1, retries=0), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['malformed'])
            client.bind_scope('fn')
            malformed = replace(request('sp_generation'),
                                raw_response_path=root / 'raw-response.txt')
            with self.assertRaises(json.JSONDecodeError):
                await client.generate(malformed)
            self.assertEqual(ledger.attempts[0]['status'], 'ERROR')
            self.assertEqual(ledger.attempts[0]['server_terminal_status'],
                             'completed')
            self.assertEqual(ledger.attempts[0]['product_response_error_type'],
                             'JSONDecodeError')
            self.assertEqual(ledger.attempts[0]['product_response_error_sha256'],
                             hashlib.sha256(
                                 malformed.raw_response_path.read_bytes()).hexdigest())
            self.assertEqual(ledger.turns[0]['status'],
                             'INCOMPLETE_PRODUCT_RESPONSE')
            self.assertEqual(ledger.function_states['fn'],
                             'INCOMPLETE_PRODUCT_RESPONSE')
            self.assertEqual(ledger.pending_work[-1]['state'],
                             'INCOMPLETE_PRODUCT_RESPONSE')
            with self.assertRaisesRegex(ValueError, 'terminal model turn'):
                ledger.begin_turn('fn', 'function_analysis',
                                  ledger.turns[0]['hash'])
            turn_id = ledger.attempts[0]['app_server_turn_id']
            events = root / 'model-events.jsonl'
            events.write_text(json.dumps({
                'method': 'turn/completed', 'turn_id': turn_id,
                'thread_id': 'test-thread', 'item_type': None,
                'server_request': False,
                'params': {'threadId': 'test-thread',
                           'turn': {'id': turn_id, 'status': 'completed'}}}) + '\n')
            verify_model_event_order(ledger, events)
            events.write_text('')
            with self.assertRaisesRegex(ValueError, 'completed App Server turns'):
                verify_model_event_order(ledger, events)

    async def test_secondary_finish_failure_preserves_stream_error(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=1, logical=1, retries=0), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['stream'])
            client.bind_scope('fn')
            with patch.object(ledger, 'finish_attempt',
                              side_effect=OSError('secondary checkpoint failure')):
                with self.assertRaisesRegex(
                        AppServerError, 'stream disconnected') as caught:
                    await client.generate(request('sp_generation'))
            self.assertTrue(any('finish_attempt' in note for note in
                                getattr(caught.exception, '__notes__', [])))
            self.assertEqual(len(client.sent), 1)
            self.assertEqual(ledger.physical, 1)

    async def test_secondary_close_failure_preserves_settlement_error(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=1, logical=1, retries=0), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['ok'])
            client.bind_scope('fn')

            async def fail_close():
                raise RuntimeError('secondary close error')

            client.close = fail_close
            with patch.object(ledger, 'finish_attempt',
                              side_effect=ValueError('primary settlement error')):
                with self.assertRaisesRegex(
                        ValueError, 'primary settlement error') as caught:
                    await client.generate(request('sp_generation'))
            self.assertTrue(any('close failed' in note for note in
                                getattr(caught.exception, '__notes__', [])))
            self.assertEqual(ledger.physical, 1)

    async def test_product_parse_error_survives_base_client_close_failure(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = DevelopmentRequestLedger.create(
                budget(physical=1, logical=1, retries=0), root / 'ledger.json')
            ledger.select_function('fn')
            client = FakeWireServer(ledger, root, ['malformed'])
            client.bind_scope('fn')
            malformed = replace(request('sp_generation'),
                                raw_response_path=root / 'raw-response.txt')

            async def fail_close():
                raise RuntimeError('secondary close error')

            client.close = fail_close
            with self.assertRaises(json.JSONDecodeError) as caught:
                await client.generate(malformed)
            self.assertTrue(any('close' in note for note in
                                getattr(caught.exception, '__notes__', [])))
            self.assertEqual(ledger.attempts[-1]['product_response_error_type'],
                             'JSONDecodeError')


if __name__ == '__main__':
    unittest.main()
