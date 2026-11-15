"""Public, provider-free two-function first slice of interleaved Scan work."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools')]

from dev_fbv2_four_phase_worklist import build_from_pinned_run  # noqa: E402
from dev_global_appserver_bridge import request_hash  # noqa: E402
from dev_global_request_ledger import (DevelopmentBudget,  # noqa: E402
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)
from dev_no_k_three_function_gate import make_public_fixture  # noqa: E402
from vulnerabilityanalysis.interleaved_dev import (create_interleaved_dev,  # noqa: E402
                                                  generate_sp_stage,
                                                  read_interleaved_dev)
from vulnerabilityanalysis.workflow import (continue_four_phase_dev,  # noqa: E402
                                            run_phase1, start_four_phase_dev,
                                            write_four_phase_terminal_marker)
import vulnerabilityanalysis.interleaved_dev as stage_module  # noqa: E402


class _Provider:
    """The same fsynced ledger debit as the evaluator bridge; no transport."""

    def __init__(self, ledger, scope_id, count, *, cancel=False):
        self.ledger = ledger
        self.scope_id = scope_id
        self.transport_only = True
        self.count = count
        self.cancel = cancel
        self.calls = []

    async def generate(self, request):
        if (request.role != 'sp_generation' or
                not request.instructions or
                request.output_schema.get('required') != ['suspicious_points'] or
                not request.payload['analysis']['function_id'].startswith('fn-') or
                not isinstance(request.payload['context'], list) or
                not isinstance(request.payload['source_start_line'], int) or
                'LLVMFuzzerTestOneInput' not in request.payload['harness_source']):
            raise AssertionError('product SP payload contract changed')
        digest = request_hash(request)
        if (self.ledger.active_turn is None or
                self.ledger.active_turn['hash'] != digest or
                self.ledger.active_turn['scope_id'] != self.scope_id or
                self.ledger.attempts[-1]['status'] != 'STARTED'):
            raise AssertionError('transport called before durable physical debit')
        checkpoint = json.loads(self.ledger.checkpoint_path.read_text())
        if (checkpoint['active_turn']['hash'] != digest or
                checkpoint['attempts'][-1]['status'] != 'STARTED' or
                checkpoint['attempts'][-1]['physical'] != checkpoint['physical']):
            raise AssertionError('transport called before fsynced ledger checkpoint')
        self.calls.append(request.role)
        if self.cancel:
            raise asyncio.CancelledError('simulated interruption after physical start')
        source = request.payload['source']
        line = next(row for row in source.splitlines() if 'int ' in row)
        number, excerpt = line.split(': ', 1)
        source_file = request.payload['analysis']['source_file']
        response = {'suspicious_points': [{
            'source_file': source_file, 'source_line': int(number),
            'source_excerpt': excerpt, 'sp_condition': '',
            'suspicious_operation': f'operation {index}',
            'vulnerability_hypothesis': f'hypothesis {index}',
            'trigger_conditions': [f'trigger {index}'],
            'external_input_relation': 'input may reach source',
            'required_state': [], 'security_property': 'memory safety',
            'supporting_evidence': [], 'contradicting_evidence': [],
            'unknowns': [],
        } for index in range(self.count)]}
        return response


class _NoDebitProvider(_Provider):
    async def generate(self, request):
        if self.ledger.attempts[-1]['status'] != 'STARTED':
            raise AssertionError('physical debit was not persisted before transport')
        self.calls.append(request.role)
        return {'suspicious_points': []}


class _MalformedProvider(_Provider):
    async def generate(self, request):
        self.calls.append(request.role)
        return {'suspicious_points': 'invalid list'}


class _InvalidLocationProvider(_Provider):
    async def generate(self, request):
        response = await super().generate(request)
        response['suspicious_points'][0]['source_excerpt'] = 'not source text'
        response['suspicious_points'][0]['sp_condition'] = 'length > 0'
        return response


class _MutatingProvider(_Provider):
    def __init__(self, ledger, scope_id, count, *, source_path=None,
                 mutate_harness=False):
        super().__init__(ledger, scope_id, count)
        self.source_path = source_path
        self.mutate_harness = mutate_harness

    async def generate(self, request):
        response = await super().generate(request)
        path = (Path(request.payload['harness_source_file'])
                if self.mutate_harness else self.source_path)
        path.write_bytes(path.read_bytes() + b'\n/* changed during model turn */\n')
        return response


class _MutatingCallerProvider(_Provider):
    def __init__(self, ledger, scope_id, caller_path):
        super().__init__(ledger, scope_id, 1)
        self.caller_path = caller_path

    async def generate(self, request):
        if not any(row.get('source_file') == str(self.caller_path)
                   for row in request.payload['context']):
            raise AssertionError('caller source was not delivered to SP')
        response = await super().generate(request)
        self.caller_path.write_bytes(
            self.caller_path.read_bytes() + b'\n/* changed during turn */\n')
        return response


class InterleavedSPStageTests(unittest.TestCase):
    def fixture(self, root: Path, *, credits=8):
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
            physical_max=credits, logical_max=credits, retries_max=0,
            wall_seconds=60, initial_starts_required=2,
            profile=GLOBAL_ONLY_DEV_PROFILE), root / 'MODEL_LEDGER.json')
        ledger.register_direction('public-direction')
        digest = 'a' * 64
        ledger.begin_turn('public-direction', 'direction_generator', digest)
        ledger.start_attempt(digest)
        ledger.finish_attempt(completed=True)
        return repo, state_path, ledger

    def caller_fixture(self, root: Path):
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        caller = repo / 'other.c'
        caller.write_text('int D(void) { return A(); }\n', encoding='utf-8')
        analysis = repo / 'analysis'
        with (analysis / 'functions.jsonl').open('a') as stream:
            stream.write(json.dumps({'function_id': 'fn-d', 'name': 'D',
                                     'file': 'other.c'}) + '\n')
        with (analysis / 'edges.jsonl').open('a') as stream:
            stream.write(json.dumps({'caller_id': 'fn-d', 'callee_id': 'fn-a',
                                     'kind': 'SOURCE_DIRECT_COMPILED'}) + '\n')
        proposal = json.loads(plan.read_text())
        proposal['functions_sha256'] = hashlib.sha256(
            (analysis / 'functions.jsonl').read_bytes()).hexdigest()
        proposal['edges_sha256'] = hashlib.sha256(
            (analysis / 'edges.jsonl').read_bytes()).hexdigest()
        plan.write_text(json.dumps(proposal, sort_keys=True) + '\n')
        source_run = run_phase1(
            artifact, repo / 'runs', target_repository=repo,
            direction_plan=plan, selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        worklist = build_from_pinned_run(source_run)
        worklist_path = root / 'WORKLIST.json'
        worklist_path.write_text(json.dumps(worklist, sort_keys=True) + '\n')
        path = create_interleaved_dev(
            source_run, worklist_path,
            hashlib.sha256(worklist_path.read_bytes()).hexdigest(),
            root / 'interleaved', target_repository=repo)
        ledger = DevelopmentRequestLedger.create(DevelopmentBudget(
            physical_max=8, logical_max=8, retries_max=0,
            wall_seconds=60, initial_starts_required=2,
            profile=GLOBAL_ONLY_DEV_PROFILE), root / 'MODEL_LEDGER.json')
        ledger.register_direction('public-direction')
        digest = 'a' * 64
        ledger.begin_turn('public-direction', 'direction_generator', digest)
        ledger.start_attempt(digest)
        ledger.finish_attempt(completed=True)
        return repo, path, ledger, caller

    def test_existing_serial_continuation_rejects_pending_sp_even_with_marker(self):
        with TemporaryDirectory() as tmp:
            repo, path, _ledger = self.fixture(Path(tmp))
            state = read_interleaved_dev(path)
            source_run = Path(state['source_run'])
            worklist_path = Path(state['worklist_path'])
            serial = start_four_phase_dev(source_run, worklist_path,
                                          state['worklist_sha256'],
                                          repo / 'runs' / 'serial-old-contract')
            run = json.loads((serial / 'run.json').read_text())
            item = json.loads((serial / 'work_item.json').read_text())
            (serial / 'scan.json').write_text(json.dumps({
                'pending_sp_ids': ['sp-pending'],
                'hp_error': None,
                'assertion_generation_status': 'NOT_SCHEDULED_NO_SAFE_ASSUMPTION',
                'assertion_execution': {'status': 'DISABLED'},
            }) + '\n')
            write_four_phase_terminal_marker(serial, run, item)
            with self.assertRaisesRegex(ValueError, 'pending or incomplete'):
                continue_four_phase_dev(serial)

    def test_second_function_gets_sp_opportunity_before_first_queue_drains(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            rows = read_interleaved_dev(path)['work_items']
            self.assertNotEqual(rows[0]['function_id'], rows[1]['function_id'])
            a = _Provider(ledger, rows[0]['work_item_id'], 3)
            b = _Provider(ledger, rows[1]['work_item_id'], 1)
            asyncio.run(generate_sp_stage(path, 0, a, ledger,
                                          target_repository=repo))
            state_after_a = read_interleaved_dev(path)
            self.assertEqual(len(state_after_a['work_items'][0]['candidate_ids']), 3)
            self.assertEqual(state_after_a['work_items'][0]['hp_state'],
                             'PENDING_HP_FIRST_OPPORTUNITY')
            self.assertFalse((path.parent / 'scan.json').exists())
            self.assertFalse((path.parent / 'four_phase_scan_complete.json').exists())
            asyncio.run(generate_sp_stage(path, 1, b, ledger,
                                          target_repository=repo))
            state = read_interleaved_dev(path)
            self.assertEqual([a.calls, b.calls], [['sp_generation'], ['sp_generation']])
            self.assertEqual(len(state['work_items'][0]['candidate_ids']), 3)
            self.assertEqual(len(state['work_items'][1]['candidate_ids']), 1)
            self.assertEqual(state['work_items'][2]['hp_state'], 'NOT_ADMITTED')
            self.assertNotIn('safe_assumption_count', state['work_items'][2])
            self.assertTrue(all(row['state'] == 'PENDING_VERIFY' for row in
                                state['work_items'][0]['sp_queue']))
            self.assertEqual(state['work_items'][1]['hp_state'],
                             'PENDING_HP_FIRST_OPPORTUNITY')
            self.assertEqual(ledger.function_states[rows[0]['work_item_id']],
                             'SELECTED_NOT_STARTED')
            self.assertEqual(ledger.function_states[rows[1]['work_item_id']],
                             'SELECTED_NOT_STARTED')
            self.assertFalse((path.parent / 'scan.json').exists())
            self.assertFalse((path.parent / 'four_phase_scan_complete.json').exists())

    def test_caller_context_source_change_during_sp_rejects_candidate_commit(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger, caller = self.caller_fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            self.assertEqual(row['function_id'], 'fn-a')
            provider = _MutatingCallerProvider(
                ledger, row['work_item_id'], caller)
            with self.assertRaisesRegex(ValueError, 'Context source changed'):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            self.assertEqual(ledger.physical, 2)
            self.assertNotEqual(read_interleaved_dev(path)['work_items'][0]
                                ['state'], 'SP_GENERATED_HP_PENDING')

    def test_caller_context_source_change_after_success_rejects_recovery(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger, caller = self.caller_fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            self.assertEqual(read_interleaved_dev(path)['work_items'][0]
                             ['state'], 'SP_GENERATED_HP_PENDING')
            caller.write_bytes(caller.read_bytes() + b'\n/* changed after success */\n')
            with self.assertRaisesRegex(ValueError, 'Context source changed'):
                read_interleaved_dev(path)

    def test_scripted_sp_request_change_rejected_even_if_state_sha_updated(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            state = json.loads(path.read_text())
            item = state['work_items'][0]
            request = Path(item['sp_request_path'])
            payload = json.loads(request.read_text())
            payload['payload']['source'] += '\n9999: injected_line();'
            request.write_text(json.dumps(payload) + '\n')
            item['sp_request_sha256'] = hashlib.sha256(request.read_bytes()).hexdigest()
            path.write_text(json.dumps(state) + '\n')
            with self.assertRaisesRegex(ValueError, 'request differs from ledger'):
                read_interleaved_dev(path)

    def test_scripted_sp_route_change_rejected_even_if_state_sha_updated(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            state = json.loads(path.read_text())
            item = state['work_items'][0]
            request = Path(item['sp_request_path'])
            payload = json.loads(request.read_text())
            payload['model'] = 'different-model'
            request.write_text(json.dumps(payload) + '\n')
            item['sp_request_sha256'] = hashlib.sha256(request.read_bytes()).hexdigest()
            path.write_text(json.dumps(state) + '\n')
            with self.assertRaisesRegex(ValueError, 'route changed'):
                read_interleaved_dev(path)

    def test_sp_candidate_change_rejected_with_original_response_unchanged(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            candidate_path = asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            state = json.loads(path.read_text())
            candidates = json.loads(candidate_path.read_text())
            candidates[0]['vulnerability_hypothesis'] = 'forged hypothesis'
            candidate_path.write_text(json.dumps(candidates) + '\n')
            state['work_items'][0]['candidates_sha256'] = hashlib.sha256(
                candidate_path.read_bytes()).hexdigest()
            path.write_text(json.dumps(state) + '\n')
            with self.assertRaisesRegex(ValueError,
                                         'candidate differs from model response'):
                read_interleaved_dev(path)

    def test_sp_candidate_other_field_change_rejected_with_state_sha_updated(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            candidate_path = asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            state = json.loads(path.read_text())
            candidates = json.loads(candidate_path.read_text())
            candidates[0]['suspicious_operation'] = 'forged operation'
            candidate_path.write_text(json.dumps(candidates) + '\n')
            state['work_items'][0]['candidates_sha256'] = hashlib.sha256(
                candidate_path.read_bytes()).hexdigest()
            path.write_text(json.dumps(state) + '\n')
            with self.assertRaisesRegex(ValueError,
                                         'candidate differs from model response'):
                read_interleaved_dev(path)

    def test_sp_invalid_location_lineage_replays_without_target(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(
                path, 0, _InvalidLocationProvider(
                    ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            saved = read_interleaved_dev(path)['work_items'][0]
            self.assertEqual(saved['candidate_ids'][0],
                             saved['sp_queue'][0]['sp_id'])

    def test_scripted_provider_default_route_rejected_before_physical_debit(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _Provider(ledger, row['work_item_id'], 1)
            provider.model = 'implicit-model'
            with self.assertRaisesRegex(ValueError, 'not eligible'):
                asyncio.run(generate_sp_stage(
                    path, 0, provider, ledger, target_repository=repo))
            self.assertEqual(ledger.physical, 1)
            self.assertEqual(provider.calls, [])

    def test_explicit_scripted_role_route_is_bound_to_ledger(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo,
                role_models={'sp_generation': {
                    'model': 'scripted-model', 'reasoning': 'high'}}))
            item = read_interleaved_dev(path)['work_items'][0]
            request = json.loads(Path(item['sp_request_path']).read_text())
            self.assertEqual(request['model'], 'scripted-model')
            self.assertEqual(request['reasoning'], 'high')
            self.assertEqual(item['sp_request_model'], 'scripted-model')
            self.assertEqual(item['sp_request_effort'], 'high')

    def test_official_graph_outside_target_root_is_pinned_separately(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            stage = root / 'official-stage'
            target.mkdir()
            stage.mkdir()
            source = target / 'target.c'
            graph = stage / 'edges.jsonl'
            source.write_text('int A(void) { return 0; }\n')
            graph.write_text('{"caller_id":"a","callee_id":"b"}\n')
            audit = {'graph_artifact': str(graph),
                     'graph_sha256': hashlib.sha256(graph.read_bytes()).hexdigest()}
            context = [{'source_file': str(source), 'source': source.read_text()}]
            pins = stage_module._context_file_pins(context, audit, target)
            self.assertEqual(set(pins), {str(source), str(graph)})
            stage_module._check_context_file_pins(pins)
            graph.write_text(graph.read_text() + '{}\n')
            with self.assertRaisesRegex(ValueError, 'Context source changed'):
                stage_module._check_context_file_pins(pins)

    def test_interrupted_physical_start_is_not_resent_to_next_function(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            rows = read_interleaved_dev(path)['work_items']
            a = _Provider(ledger, rows[0]['work_item_id'], 3, cancel=True)
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(generate_sp_stage(path, 0, a, ledger,
                                              target_repository=repo))
            self.assertEqual(read_interleaved_dev(path)['work_items'][0]['state'],
                             'INCOMPLETE_UNCERTAIN_MODEL_TURN')
            self.assertEqual(read_interleaved_dev(path)['work_items'][0]['hp_state'],
                             'NO_OPPORTUNITY_INTERRUPTED')
            self.assertEqual(ledger.physical, 2)  # Direction plus interrupted SP.
            with self.assertRaises(ValueError):
                asyncio.run(generate_sp_stage(path, 1,
                    _Provider(ledger, rows[1]['work_item_id'], 1), ledger,
                    target_repository=repo))
            self.assertEqual(ledger.physical, 2)

    def test_budget_adapter_with_own_backend_cannot_double_debit(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _Provider(ledger, row['work_item_id'], 1)
            provider.backend = object()  # Existing ProductBudgetAdapter shape.
            with self.assertRaisesRegex(ValueError, 'not eligible'):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            self.assertEqual(provider.calls, [])
            self.assertEqual(ledger.physical, 1)

    def test_state_write_failure_after_selection_stops_before_transport(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _Provider(ledger, row['work_item_id'], 1)
            actual_write = stage_module._private_json

            def fail_armed_write(destination, value, *, replace):
                if destination == path and replace:
                    raise OSError('simulated checkpoint storage failure')
                return actual_write(destination, value, replace=replace)

            with patch.object(stage_module, '_private_json', fail_armed_write):
                with self.assertRaisesRegex(OSError, 'checkpoint storage'):
                    asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                                  target_repository=repo))
            self.assertEqual(provider.calls, [])
            self.assertEqual(ledger.physical, 1)
            self.assertEqual(ledger.selected_functions, [row['work_item_id']])
            with self.assertRaisesRegex(ValueError, 'not eligible'):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            self.assertEqual(provider.calls, [])

    def test_stage_predebits_even_for_transport_without_ledger_calls(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _NoDebitProvider(ledger, row['work_item_id'], 0)
            asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                          target_repository=repo))
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual(ledger.physical, 2)
            self.assertEqual(read_interleaved_dev(path)['work_items'][0]['state'],
                             'SP_GENERATED_HP_PENDING')
            self.assertTrue(list(path.parent.glob('work_items/*/sp/candidates.json')))

    def test_completed_transport_with_invalid_response_is_not_uncertain(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _MalformedProvider(ledger, row['work_item_id'], 0)
            with self.assertRaises(Exception):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            state = read_interleaved_dev(path)['work_items'][0]
            self.assertEqual(state['state'], 'INCOMPLETE_PRODUCT_RESPONSE')
            self.assertEqual(state['hp_state'], 'NO_OPPORTUNITY_PRODUCT_RESPONSE')
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual(ledger.physical, 2)
            self.assertEqual(ledger.attempts[-1]['status'], 'COMPLETED')
            self.assertFalse(list(path.parent.glob('work_items/*/sp/candidates.json')))
            self.assertFalse((path.parent / 'scan.json').exists())

    def test_source_changed_during_response_never_becomes_generated(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _MutatingProvider(ledger, row['work_item_id'], 1,
                                         source_path=repo / 'target.c')
            with self.assertRaisesRegex(ValueError, 'source changed'):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            saved = json.loads(path.read_text())
            self.assertNotEqual(saved['work_items'][0]['state'],
                                'SP_GENERATED_HP_PENDING')
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual(ledger.physical, 2)
            self.assertEqual(ledger.attempts[-1]['status'], 'COMPLETED')
            self.assertFalse(list(path.parent.glob('work_items/*/sp/candidates.json')))
            with self.assertRaisesRegex(ValueError, 'source changed'):
                read_interleaved_dev(path)

    def test_harness_changed_during_response_never_becomes_generated(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _MutatingProvider(ledger, row['work_item_id'], 1,
                                         mutate_harness=True)
            with self.assertRaises(ValueError):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            saved = json.loads(path.read_text())
            self.assertNotEqual(saved['work_items'][0]['state'],
                                'SP_GENERATED_HP_PENDING')
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual(ledger.physical, 2)
            self.assertEqual(ledger.attempts[-1]['status'], 'COMPLETED')
            self.assertFalse(list(path.parent.glob('work_items/*/sp/candidates.json')))

    def test_source_changed_after_generated_is_rejected_on_read(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            target = repo / 'target.c'
            target.write_bytes(target.read_bytes() + b'\n/* later drift */\n')
            with self.assertRaisesRegex(ValueError, 'source changed'):
                read_interleaved_dev(path)

    def test_harness_changed_after_generated_is_rejected_on_read(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            state = json.loads(path.read_text())
            harness = json.loads((Path(state['source_run']) /
                                  'harness.json').read_text())
            harness_path = Path(harness['harness_path'])
            harness_path.write_bytes(harness_path.read_bytes() + b'\n/* drift */\n')
            with self.assertRaises(ValueError):
                read_interleaved_dev(path)

    def test_abandon_failure_preserves_original_cancellation(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _Provider(ledger, row['work_item_id'], 1, cancel=True)
            with patch.object(ledger, 'abandon_turn',
                              side_effect=RuntimeError('cleanup failed')):
                with self.assertRaises(asyncio.CancelledError) as caught:
                    asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                                  target_repository=repo))
            self.assertEqual(str(caught.exception),
                             'simulated interruption after physical start')
            self.assertTrue(any('abandon_turn' in note for note in
                                getattr(caught.exception, '__notes__', [])))
            saved = json.loads(path.read_text())
            self.assertEqual(saved['work_items'][0]['state'],
                             'INCOMPLETE_UNCERTAIN_MODEL_TURN')
            self.assertEqual(ledger.physical, 2)

    def test_state_cleanup_failure_preserves_original_schema_error(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _MalformedProvider(ledger, row['work_item_id'], 0)
            real_write = stage_module._private_json

            def fail_terminal_write(destination, value, *, replace):
                if (destination == path and replace and
                        value['work_items'][0]['state'] ==
                        'INCOMPLETE_PRODUCT_RESPONSE'):
                    raise OSError('simulated terminal state write failure')
                return real_write(destination, value, replace=replace)

            with patch.object(stage_module, '_private_json',
                              fail_terminal_write):
                with self.assertRaisesRegex(Exception, 'not of type') as caught:
                    asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                                  target_repository=repo))
            self.assertTrue(any('state_write' in note for note in
                                getattr(caught.exception, '__notes__', [])))
            self.assertEqual(json.loads(path.read_text())['work_items'][0]['state'],
                             'SP_REQUEST_ARMED')
            self.assertEqual(len(list(path.parent.glob('CLEANUP_FAILURE_*.json'))), 1)
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual(ledger.attempts[-1]['status'], 'COMPLETED')
            with self.assertRaisesRegex(ValueError, 'cleanup failure receipt'):
                read_interleaved_dev(path)
            with self.assertRaises(ValueError):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))

    def test_generated_state_write_failure_keeps_cursor_and_original_error(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _Provider(ledger, row['work_item_id'], 1)
            real_write = stage_module._private_json

            def fail_generated_write(destination, value, *, replace):
                if (destination == path and replace and
                        value['work_items'][0]['state'] ==
                        'SP_GENERATED_HP_PENDING'):
                    raise OSError('simulated generated state write failure')
                return real_write(destination, value, replace=replace)

            with patch.object(stage_module, '_private_json',
                              fail_generated_write):
                with self.assertRaisesRegex(OSError, 'generated state write'):
                    asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                                  target_repository=repo))
            saved = read_interleaved_dev(path)
            self.assertEqual(saved['next_sp_ordinal'], 0)
            self.assertEqual(saved['work_items'][0]['state'],
                             'INCOMPLETE_PRODUCT_RESPONSE')
            self.assertEqual(saved['work_items'][0]['candidate_ids'], [])
            self.assertEqual(saved['work_items'][0]['sp_queue'], [])
            self.assertIsNone(saved['work_items'][0]['candidates_sha256'])
            self.assertEqual(len(saved['work_items'][0]
                                 ['uncommitted_candidate_artifact_sha256']), 64)
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual(ledger.physical, 2)
            with self.assertRaises(ValueError):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            self.assertEqual(provider.calls, ['sp_generation'])

    def test_incomplete_item_cannot_claim_consumable_candidates(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            provider = _MalformedProvider(ledger, row['work_item_id'], 0)
            with self.assertRaises(Exception):
                asyncio.run(generate_sp_stage(path, 0, provider, ledger,
                                              target_repository=repo))
            saved = json.loads(path.read_text())
            saved['work_items'][0]['sp_queue'] = [
                {'sp_id': 'sp-forged', 'state': 'PENDING_VERIFY'}]
            path.write_text(json.dumps(saved) + '\n')
            with self.assertRaisesRegex(ValueError, 'candidate.*queue'):
                read_interleaved_dev(path)

    def test_candidate_tamper_prevents_next_function_request(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            rows = read_interleaved_dev(path)['work_items']
            artifact = asyncio.run(generate_sp_stage(
                path, 0, _Provider(ledger, rows[0]['work_item_id'], 3), ledger,
                target_repository=repo))
            artifact.write_bytes(artifact.read_bytes() + b' ')
            b = _Provider(ledger, rows[1]['work_item_id'], 1)
            with self.assertRaisesRegex(ValueError, 'candidate artifact changed'):
                asyncio.run(generate_sp_stage(path, 1, b, ledger,
                                              target_repository=repo))
            self.assertEqual(b.calls, [])
            self.assertEqual(ledger.physical, 2)

    def test_generated_state_rejects_ledger_byte_drift_on_read(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp))
            row = read_interleaved_dev(path)['work_items'][0]
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, row['work_item_id'], 1), ledger,
                target_repository=repo))
            self.assertEqual(read_interleaved_dev(path)['work_items'][0]['state'],
                             'SP_GENERATED_HP_PENDING')
            ledger.checkpoint_path.write_bytes(
                ledger.checkpoint_path.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'ledger.*(SHA|changed)'):
                read_interleaved_dev(path)

    def test_global_budget_blocks_second_sp_without_losing_first_queue(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp), credits=3)
            rows = read_interleaved_dev(path)['work_items']
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, rows[0]['work_item_id'], 3), ledger,
                target_repository=repo))
            b = _Provider(ledger, rows[1]['work_item_id'], 1)
            with self.assertRaisesRegex(ValueError, 'initial global credits'):
                asyncio.run(generate_sp_stage(path, 1, b, ledger,
                                              target_repository=repo))
            self.assertEqual(b.calls, [])
            self.assertEqual(ledger.physical, 2)
            self.assertEqual(ledger.no_opportunity[rows[1]['work_item_id']],
                             'NO_OPPORTUNITY_BUDGET')
            blocked = read_interleaved_dev(path)['work_items'][1]
            self.assertEqual(blocked['state'], 'NO_OPPORTUNITY_BUDGET')
            self.assertEqual(blocked['hp_state'], 'NO_OPPORTUNITY_BUDGET')
            future = read_interleaved_dev(path)['work_items'][2]
            self.assertEqual(future['state'],
                             'NOT_ADMITTED_BUDGET_EXHAUSTED')
            self.assertEqual(future['hp_state'],
                             'NOT_ADMITTED_BUDGET_EXHAUSTED')
            self.assertNotIn(rows[2]['work_item_id'], ledger.no_opportunity)
            with self.assertRaises(ValueError):
                asyncio.run(generate_sp_stage(path, 1, b, ledger,
                                              target_repository=repo))
            c = _Provider(ledger, rows[2]['work_item_id'], 1)
            with self.assertRaises(ValueError):
                asyncio.run(generate_sp_stage(path, 2, c, ledger,
                                              target_repository=repo))
            self.assertEqual(c.calls, [])
            self.assertEqual(b.calls, [])
            self.assertEqual(len(read_interleaved_dev(path)['work_items'][0]
                                 ['candidate_ids']), 3)

    def test_budget_denial_state_write_failure_recovers_without_model_send(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp), credits=3)
            rows = read_interleaved_dev(path)['work_items']
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, rows[0]['work_item_id'], 2), ledger,
                target_repository=repo))
            provider = _Provider(ledger, rows[1]['work_item_id'], 1)
            real_write = stage_module._private_json

            def fail_budget_write(destination, value, *, replace):
                if (destination == path and replace and
                        value['work_items'][1]['state'] == 'NO_OPPORTUNITY_BUDGET'):
                    raise OSError('simulated budget state write failure')
                return real_write(destination, value, replace=replace)

            with patch.object(stage_module, '_private_json', fail_budget_write):
                with self.assertRaisesRegex(OSError, 'budget state write'):
                    asyncio.run(generate_sp_stage(path, 1, provider, ledger,
                                                  target_repository=repo))
            self.assertEqual(json.loads(path.read_text())['work_items'][1]['state'],
                             'PENDING_SP_GENERATION')
            self.assertEqual(ledger.no_opportunity[rows[1]['work_item_id']],
                             'NO_OPPORTUNITY_BUDGET')
            self.assertEqual(provider.calls, [])
            with self.assertRaisesRegex(ValueError, 'initial global credits'):
                asyncio.run(generate_sp_stage(path, 1, provider, ledger,
                                              target_repository=repo))
            recovered = read_interleaved_dev(path)
            self.assertEqual(recovered['work_items'][1]['state'],
                             'NO_OPPORTUNITY_BUDGET')
            self.assertEqual(recovered['budget_exhausted_from_ordinal'], 1)
            self.assertEqual(provider.calls, [])
            self.assertEqual(ledger.physical, 2)

    def test_budget_denial_durable_receipt_tamper_is_rejected_on_read(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp), credits=3)
            rows = read_interleaved_dev(path)['work_items']
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, rows[0]['work_item_id'], 1), ledger,
                target_repository=repo))
            with self.assertRaisesRegex(ValueError, 'initial global credits'):
                asyncio.run(generate_sp_stage(path, 1,
                    _Provider(ledger, rows[1]['work_item_id'], 1), ledger,
                    target_repository=repo))
            receipt = json.loads(ledger.checkpoint_path.read_text())
            receipt['no_opportunity'][rows[1]['work_item_id']] = 'WRONG_REASON'
            ledger.checkpoint_path.write_text(json.dumps(receipt) + '\n')
            with self.assertRaisesRegex(ValueError, 'budget.*receipt'):
                read_interleaved_dev(path)

    def test_budget_reconcile_rejects_unsaved_ledger_object_claim(self):
        with TemporaryDirectory() as tmp:
            repo, path, ledger = self.fixture(Path(tmp), credits=3)
            rows = read_interleaved_dev(path)['work_items']
            asyncio.run(generate_sp_stage(path, 0,
                _Provider(ledger, rows[0]['work_item_id'], 1), ledger,
                target_repository=repo))
            provider = _Provider(ledger, rows[1]['work_item_id'], 1)
            real_write = stage_module._private_json

            def fail_budget_write(destination, value, *, replace):
                if (destination == path and replace and
                        value['work_items'][1]['state'] == 'NO_OPPORTUNITY_BUDGET'):
                    raise OSError('state write failed after ledger denial')
                return real_write(destination, value, replace=replace)

            with patch.object(stage_module, '_private_json', fail_budget_write):
                with self.assertRaises(OSError):
                    asyncio.run(generate_sp_stage(path, 1, provider, ledger,
                                                  target_repository=repo))
            receipt = json.loads(ledger.checkpoint_path.read_text())
            receipt['no_opportunity'][rows[1]['work_item_id']] = 'WRONG_REASON'
            ledger.checkpoint_path.write_text(json.dumps(receipt) + '\n')
            with self.assertRaisesRegex(ValueError, 'budget receipt'):
                asyncio.run(generate_sp_stage(path, 1, provider, ledger,
                                              target_repository=repo))
            self.assertEqual(json.loads(path.read_text())['work_items'][1]['state'],
                             'PENDING_SP_GENERATION')
            self.assertEqual(provider.calls, [])

    def test_future_item_cannot_be_marked_generated_by_state_edit(self):
        with TemporaryDirectory() as tmp:
            _repo, path, _ledger = self.fixture(Path(tmp))
            state = read_interleaved_dev(path)
            state['work_items'][1]['state'] = 'SP_GENERATED_HP_PENDING'
            state['work_items'][1]['hp_state'] = 'PENDING_HP_FIRST_OPPORTUNITY'
            path.write_text(json.dumps(state) + '\n')
            with self.assertRaisesRegex(ValueError, 'future work item'):
                read_interleaved_dev(path)


if __name__ == '__main__':
    unittest.main()
