"""Provider-free Stage11 checks using the real durable App Server bridge."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools')]

from dev_global_appserver_bridge import (  # noqa: E402
    artifact_hash, verify_model_event_order, verify_product_request_order)
from dev_global_request_ledger import (DevelopmentBudget,  # noqa: E402
    DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE)
from dev_fbv2_four_phase_worklist import build_from_pinned_run  # noqa: E402
from dev_no_k_three_function_gate import make_public_fixture  # noqa: E402
from test_dev_global_appserver_bridge import FakeWireServer  # noqa: E402
from vulnerabilityanalysis.interleaved_dev import (  # noqa: E402
    create_interleaved_dev, generate_sp_stage, read_interleaved_dev)
from vulnerabilityanalysis.workflow import run_phase1  # noqa: E402


BRIDGE = PREP / 'evaluation_tools' / 'dev_global_appserver_bridge.py'
ROUTE = {'sp_generation': {'model': 'test-model', 'reasoning': 'high'}}


class StageWire(FakeWireServer):
    def __init__(self, ledger, root, outcomes):
        super().__init__(ledger, root, outcomes)
        self.event_log_path = root / 'model-events.jsonl'

    async def _collect(self, thread_id: str, turn_id: str) -> str:
        outcome = self.outcomes.pop(0)
        if outcome == 'stream':
            from vulnerabilityanalysis.llm import AppServerError
            raise AppServerError('stream disconnected before completion')
        if outcome == 'cancel':
            raise asyncio.CancelledError('synthetic cancellation')
        if outcome == 'pre_ack':
            raise AssertionError('pre-ack failure must be raised before collect')
        self._record_server_event({'method': 'turn/completed', 'params': {
            'threadId': thread_id,
            'turn': {'id': turn_id, 'status': 'completed', 'items': []}}})
        self._server_terminal_status = 'completed'
        if outcome == 'malformed':
            return '{"suspicious_points":'
        return '{"suspicious_points":[]}'


class WrongEventWire(StageWire):
    async def _collect(self, thread_id: str, turn_id: str) -> str:
        self._record_server_event({'method': 'turn/completed', 'params': {
            'threadId': thread_id,
            'turn': {'id': 'forged-other-turn', 'status': 'completed',
                     'items': []}}})
        self._server_terminal_status = 'completed'
        return '{"suspicious_points":[]}'


class InterleavedAppServerStageTests(unittest.TestCase):
    def fixture(self, root: Path, outcomes: list[str], *, retries: int = 0):
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        source_run = run_phase1(
            artifact, repo / 'runs', target_repository=repo,
            direction_plan=plan, selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        worklist = build_from_pinned_run(source_run)
        worklist_path = root / 'WORKLIST.json'
        worklist_path.write_text(json.dumps(worklist, sort_keys=True) + '\n')
        state_path = create_interleaved_dev(
            source_run, worklist_path,
            hashlib.sha256(worklist_path.read_bytes()).hexdigest(),
            root / 'interleaved', target_repository=repo)
        ledger = DevelopmentRequestLedger.create(DevelopmentBudget(
            physical_max=5, logical_max=4, retries_max=retries,
            wall_seconds=60, initial_starts_required=2,
            profile=GLOBAL_ONLY_DEV_PROFILE), root / 'MODEL_LEDGER.json')
        ledger.register_direction('public-direction')
        digest = 'a' * 64
        ledger.begin_turn('public-direction', 'direction_generator', digest)
        ledger.start_attempt(digest)
        ledger.finish_attempt(completed=True)
        item = read_interleaved_dev(state_path)['work_items'][0]
        wire = StageWire(ledger, root, outcomes)
        wire.bind_scope(item['work_item_id'])
        return repo, state_path, ledger, wire

    def run_stage(self, repo, state_path, ledger, wire, ordinal=0, **kwargs):
        return asyncio.run(generate_sp_stage(
            state_path, ordinal, wire, ledger, target_repository=repo,
            role_models=ROUTE, accounting_owner='APP_SERVER_TURN_START_V1',
            bridge_source_sha256=hashlib.sha256(BRIDGE.read_bytes()).hexdigest(),
            allow_synthetic_wire=True, **kwargs))

    def test_one_bridge_debit_and_bound_request_event_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['ok'])
            before = ledger.physical
            artifact = self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(ledger.physical, before + 1)
            self.assertEqual(len(wire.sent), 1)
            self.assertEqual(wire.sent[0]['attempt_status'], 'STARTED')
            self.assertEqual(json.loads(artifact.read_text()), [])
            item = read_interleaved_dev(state_path)['work_items'][0]
            evidence = item['appserver_evidence']
            self.assertEqual(evidence['accepted_turn_ids'], ['test-turn-1'])
            request = Path(evidence['request_artifact_path'])
            self.assertEqual(artifact_hash(json.loads(request.read_text())),
                             ledger.turns[-1]['hash'])
            verify_product_request_order(ledger, [request],
                                         scope_id=item['work_item_id'])
            verify_model_event_order(ledger, wire.event_log_path)
            self.assertEqual(ledger.turns[-1]['status'], 'COMPLETED')

    def test_second_function_appends_events_without_invalidating_first(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['ok', 'ok'])
            rows = read_interleaved_dev(state_path)['work_items']
            self.run_stage(repo, state_path, ledger, wire)
            first = read_interleaved_dev(state_path)['work_items'][0]
            original_event_size = first['appserver_evidence']['event_log_prefix_bytes']
            wire.unbind_scope()
            wire.bind_scope(rows[1]['work_item_id'])
            self.run_stage(repo, state_path, ledger, wire, ordinal=1)
            result = read_interleaved_dev(state_path)
            self.assertEqual(result['next_sp_ordinal'], 2)
            self.assertEqual(result['work_items'][0]['appserver_evidence']
                             ['event_log_prefix_bytes'], original_event_size)
            self.assertGreater(wire.event_log_path.stat().st_size,
                               original_event_size)
            self.assertEqual([row['state'] for row in result['work_items'][:2]],
                             ['SP_GENERATED_HP_PENDING'] * 2)
            self.assertEqual(len(wire.sent), 2)

    def test_completed_server_malformed_json_is_incomplete_and_no_resend(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['malformed'])
            with self.assertRaises(json.JSONDecodeError):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(ledger.attempts[-1]['status'], 'ERROR')
            self.assertEqual(ledger.turns[-1]['status'],
                             'INCOMPLETE_PRODUCT_RESPONSE')
            self.assertEqual(read_interleaved_dev(state_path)['work_items'][0]
                             ['state'], 'INCOMPLETE_PRODUCT_RESPONSE')
            self.assertEqual(len(wire.sent), 1)
            requests = list((state_path.parent / 'work_items').glob(
                '*/logs/sp_generation_*_request.json'))
            self.assertEqual(len(requests), 1)
            self.assertEqual(artifact_hash(json.loads(requests[0].read_text())),
                             ledger.turns[-1]['hash'])
            with self.assertRaises(ValueError):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(len(wire.sent), 1)

    def test_stream_interruption_stops_without_replay(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['stream'])
            wire.retry_route_check = None
            with self.assertRaisesRegex(Exception, 'stream disconnected'):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(ledger.physical, 2)  # Direction plus first SP.
            self.assertEqual(read_interleaved_dev(state_path)['work_items'][0]
                             ['state'], 'INCOMPLETE_UNCERTAIN_MODEL_TURN')
            with self.assertRaises(ValueError):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(len(wire.sent), 1)

    def test_cancel_after_physical_start_is_terminal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['cancel'])
            with self.assertRaises(asyncio.CancelledError):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(ledger.physical, 2)
            self.assertEqual(read_interleaved_dev(state_path)['work_items'][0]
                             ['state'], 'INCOMPLETE_UNCERTAIN_MODEL_TURN')
            with self.assertRaises(ValueError):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(len(wire.sent), 1)

    def test_retry_has_one_logical_two_physical_and_one_request_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(
                root, ['stream', 'ok'], retries=1)
            self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual((ledger.logical, ledger.physical, ledger.retries),
                             (2, 3, 1))
            self.assertEqual([row['status'] for row in ledger.attempts[-2:]],
                             ['ERROR', 'COMPLETED'])
            self.assertTrue(ledger.attempts[-2]['retry_eligible'])
            self.assertEqual(read_interleaved_dev(state_path)['work_items'][0]
                             ['appserver_evidence']['accepted_turn_ids'],
                             ['test-turn-1', 'test-turn-2'])
            self.assertEqual(len(wire.sent), 2)

    def test_completed_response_wrong_event_is_local_incomplete(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, _ = self.fixture(root, ['ok'])
            item = read_interleaved_dev(state_path)['work_items'][0]
            wire = WrongEventWire(ledger, root, ['ok'])
            wire.bind_scope(item['work_item_id'])
            with self.assertRaisesRegex(ValueError, 'event turn order'):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(ledger.turns[-1]['status'], 'COMPLETED')
            self.assertEqual(read_interleaved_dev(state_path)['work_items'][0]
                             ['state'], 'INCOMPLETE_LOCAL_POSTPROCESS')
            self.assertEqual(len(wire.sent), 1)

    def test_wrong_bridge_pin_stops_before_selection_and_wire(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['ok'])
            # A stale externally supplied bridge SHA fails before selection.
            with self.assertRaisesRegex(ValueError, 'bridge identity'):
                asyncio.run(generate_sp_stage(
                    state_path, 0, wire, ledger, target_repository=repo,
                    role_models=ROUTE,
                    accounting_owner='APP_SERVER_TURN_START_V1',
                    bridge_source_sha256='0' * 64,
                    allow_synthetic_wire=True))
            self.assertEqual(ledger.selected_functions, [])
            self.assertEqual(wire.sent, [])

    def test_pre_ack_failure_has_no_phantom_physical_start(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, state_path, ledger, wire = self.fixture(root, ['pre_ack'])
            before = ledger.physical

            async def fail_thread(*args):
                raise RuntimeError('synthetic thread/start failure')

            wire._thread_for = fail_thread
            with self.assertRaisesRegex(RuntimeError, 'thread/start failure'):
                self.run_stage(repo, state_path, ledger, wire)
            self.assertEqual(ledger.physical, before)
            self.assertEqual(wire.sent, [])
            self.assertEqual(read_interleaved_dev(state_path)['work_items'][0]
                             ['state'], 'INCOMPLETE_UNCERTAIN_MODEL_TURN')


if __name__ == '__main__':
    unittest.main()
