"""Provider-free cross-function role continuation against one work state."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
import json

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools')]

from test_dev_interleaved_sp_stage import _Provider  # noqa: E402
from test_dev_interleaved_appserver_stage import StageWire, BRIDGE  # noqa: E402
import vulnerabilityanalysis.interleaved_dev as stage  # noqa: E402
from vulnerabilityanalysis.source import SourceRepository  # noqa: E402


class _HPProvider(_Provider):
    async def generate(self, request):
        self.calls.append(request.role)
        if request.role != 'function_analysis':
            raise AssertionError('expected HP first FunctionAnalysis')
        return {
            'summary': 'reviewed', 'input_flow': 'seed bytes reach function',
            'state_dependencies': [], 'context_requests': [],
            'safe_assumptions': [], 'unknowns': [], 'input_sources': [],
            'security_sensitive_operations': [], 'validations': [],
            'memory_operations': [], 'evidence': [],
            'hypothesis_evaluations': [],
        }


class _RoleProvider(_Provider):
    def __init__(self, ledger, scope_id, role, response):
        super().__init__(ledger, scope_id, 0)
        self.role = role
        self.response = response

    async def generate(self, request):
        from dev_global_appserver_bridge import request_hash
        if request.role != self.role or self.ledger.active_turn is None or \
                self.ledger.active_turn['hash'] != request_hash(request) or \
                self.ledger.attempts[-1]['status'] != 'STARTED':
            raise AssertionError('role transport preceded durable model debit')
        self.calls.append(request.role)
        return self.response


class _CancelledRoleProvider(_RoleProvider):
    async def generate(self, request):
        await super().generate(request)
        raise asyncio.CancelledError('role stream interrupted after debit')


class _MutatingRoleProvider(_RoleProvider):
    async def generate(self, request):
        result = await super().generate(request)
        harness = Path(request.payload['harness_source_file'])
        harness.write_bytes(harness.read_bytes() + b'\n/* changed in HP turn */\n')
        return result


def _verdict(status='PLAUSIBLE', action='GENERATE_POC'):
    return {'status': status, 'supporting_evidence': [],
            'contradicting_evidence': [], 'unknowns': [],
            'rationale': 'public candidate requires testing',
            'reachability': 'UNKNOWN', 'controllability': 'UNKNOWN',
            'guards': [], 'required_state': [], 'contradiction_snippet': '',
            'contradiction_scope': 'UNKNOWN', 'context_requests': [],
            'recommended_next_action': action}


class _RoleWire(StageWire):
    def __init__(self, ledger, root, responses):
        super().__init__(ledger, root, [])
        self.responses = list(responses)

    async def _collect(self, thread_id, turn_id):
        self._record_server_event({'method': 'turn/completed', 'params': {
            'threadId': thread_id,
            'turn': {'id': turn_id, 'status': 'completed', 'items': []}}})
        self._server_terminal_status = 'completed'
        return json.dumps(self.responses.pop(0))


def _wire_sp_response(repository, item, count):
    span = repository.open_function_span(item['function_id'])
    line = next(row for row in span.source.splitlines() if 'int ' in row)
    number = span.start_line + span.source.splitlines().index(line)
    return {'suspicious_points': [{
        'source_file': item['source_file'], 'source_line': number,
        'source_excerpt': line, 'sp_condition': '',
        'suspicious_operation': f'operation {i}',
        'vulnerability_hypothesis': f'hypothesis {i}',
        'trigger_conditions': [f'trigger {i}'],
        'external_input_relation': 'input may reach source',
        'required_state': [], 'security_property': 'memory safety',
        'supporting_evidence': [], 'contradicting_evidence': [],
        'unknowns': []} for i in range(count)]}


class InterleavedCrossRoleTests(unittest.TestCase):
    def test_b_hp_starts_while_a_candidates_remain_pending(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=12)
            rows = stage.read_interleaved_dev(path)['work_items']
            a = _Provider(ledger, rows[0]['work_item_id'], 3)
            b = _Provider(ledger, rows[1]['work_item_id'], 1)
            asyncio.run(stage.generate_sp_stage(path, 0, a, ledger,
                                                target_repository=repo))
            asyncio.run(stage.generate_sp_stage(path, 1, b, ledger,
                                                target_repository=repo))
            hp = _HPProvider(ledger, rows[1]['work_item_id'], 0)
            artifact = asyncio.run(stage.run_hp_first_stage(
                path, 1, hp, ledger, target_repository=repo))
            saved = stage.read_interleaved_dev(path)
            self.assertTrue(artifact.is_file())
            self.assertEqual(saved['work_items'][0]['sp_queue'][0]['state'],
                             'PENDING_VERIFY')
            self.assertEqual(saved['work_items'][1]['hp_state'],
                             'HP_ANALYSIS_RECORDED')
            self.assertEqual(hp.calls, ['function_analysis'])

    def test_hp_string_list_and_note_normalization_survives_read(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=8)
            item = stage.read_interleaved_dev(path)['work_items'][0]
            asyncio.run(stage.generate_sp_stage(
                path, 0, _Provider(ledger, item['work_item_id'], 1),
                ledger, target_repository=repo))
            hp = _RoleProvider(ledger, item['work_item_id'],
                               'function_analysis', {
                'summary': 'reviewed', 'input_flow': 'input may reach source',
                'state_dependencies': 'a state dependency',
                'context_requests': [], 'safe_assumptions': '', 'unknowns': [],
                'input_sources': [], 'security_sensitive_operations': [],
                'validations': [], 'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': [],
                'state_note': 'additional qualification'})
            artifact = asyncio.run(stage.run_hp_first_stage(
                path, 0, hp, ledger, target_repository=repo))
            analysis = json.loads(artifact.read_text())
            self.assertEqual(analysis['state_dependencies'],
                             ['a state dependency'])
            self.assertIn('Model state_note: additional qualification',
                          analysis['unknowns'])
            self.assertEqual(stage.read_interleaved_dev(path)['work_items'][0]
                             ['hp_state'], 'HP_ANALYSIS_RECORDED')

    def test_hp_context_request_stays_pending_not_assertion_success(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=8)
            item = stage.read_interleaved_dev(path)['work_items'][0]
            asyncio.run(stage.generate_sp_stage(
                path, 0, _Provider(ledger, item['work_item_id'], 1),
                ledger, target_repository=repo))
            hp = _RoleProvider(ledger, item['work_item_id'],
                               'function_analysis', {
                'summary': 'needs another definition',
                'input_flow': 'not yet established',
                'state_dependencies': [], 'context_requests': [{
                    'target': 'S', 'request_type': 'TYPE',
                    'reason': 'definition needed',
                    'expected_information': 'complete type'}],
                'safe_assumptions': [], 'unknowns': ['type unknown'],
                'input_sources': [], 'security_sensitive_operations': [],
                'validations': [], 'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': []})
            artifact = asyncio.run(stage.run_hp_first_stage(
                path, 0, hp, ledger, target_repository=repo))
            self.assertEqual(len(json.loads(artifact.read_text())
                                 ['context_requests']), 1)
            saved = stage.read_interleaved_dev(path)
            self.assertEqual(saved['work_items'][0]['hp_state'],
                             'PENDING_HP_CONTEXT')
            self.assertEqual(len(saved['role_turns']), 1)
            self.assertEqual(saved['scan_count'], 0)

    def test_a_sp_b_sp_b_hp_a_verifier_a_pov_share_one_ledger(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=12)
            rows = stage.read_interleaved_dev(path)['work_items']
            a_id, b_id = rows[0]['work_item_id'], rows[1]['work_item_id']
            a_artifact = asyncio.run(stage.generate_sp_stage(
                path, 0, _Provider(ledger, a_id, 3), ledger,
                target_repository=repo))
            a_sha = stage._sha(a_artifact)
            asyncio.run(stage.generate_sp_stage(
                path, 1, _Provider(ledger, b_id, 1), ledger,
                target_repository=repo))
            hp = _RoleProvider(ledger, b_id, 'function_analysis', {
                'summary': 'reviewed', 'input_flow': 'input may reach source',
                'state_dependencies': [], 'context_requests': [],
                'safe_assumptions': ['unlinked claim'], 'unknowns': [],
                'input_sources': [], 'security_sensitive_operations': [],
                'validations': [], 'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': []})
            role_models = {
                'function_analysis': {'model': 'public-hp-model',
                                      'reasoning': 'high'},
                'sp_verifier': {'model': 'public-verifier-model',
                                'reasoning': 'high'},
                'poc_generator': {'model': 'public-pov-model',
                                  'reasoning': 'low'}}
            hp_artifact = asyncio.run(stage.run_hp_first_stage(
                path, 1, hp, ledger, target_repository=repo,
                role_models=role_models))
            self.assertEqual(json.loads(hp_artifact.read_text())['safe_assumptions'], [])
            a_sp = stage.read_interleaved_dev(path)['work_items'][0]['candidate_ids'][0]
            verifier = _RoleProvider(ledger, a_id, 'sp_verifier', _verdict())
            verification = asyncio.run(stage.run_sp_verifier_stage(
                path, 0, a_sp, verifier, ledger, target_repository=repo,
                role_models=role_models))
            self.assertEqual(json.loads(verification.read_text())['verification']
                             ['verdict'], 'PLAUSIBLE')
            pov = _RoleProvider(ledger, a_id, 'poc_generator', {
                'generator_script': 'def build():\n    return b"seed"\n',
                'expected_behavior': 'could exercise the public candidate',
                'trigger_rationale': 'public seed'})
            poc = asyncio.run(stage.run_pov_stage(
                path, 0, a_sp, pov, ledger, target_repository=repo,
                role_models=role_models))
            saved = stage.read_interleaved_dev(path)
            self.assertTrue(poc.is_file())
            self.assertEqual(stage._sha(a_artifact), a_sha)
            self.assertEqual(saved['work_items'][0]['sp_queue'], [
                {'sp_id': a_sp, 'state': 'POV_GENERATED_UNVALIDATED'},
                *[{'sp_id': identifier, 'state': 'PENDING_VERIFY'}
                  for identifier in saved['work_items'][0]['candidate_ids'][1:]]])
            self.assertEqual(saved['work_items'][1]['hp_state'],
                             'HP_ANALYSIS_RECORDED')
            self.assertEqual((ledger.logical, ledger.physical), (6, 6))
            self.assertEqual(saved['scan_count'], 0)

    def test_hp_budget_denial_is_durable_and_never_transmitted(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=4)
            rows = stage.read_interleaved_dev(path)['work_items']
            for ordinal in (0, 1):
                asyncio.run(stage.generate_sp_stage(
                    path, ordinal,
                    _Provider(ledger, rows[ordinal]['work_item_id'], 1),
                    ledger, target_repository=repo))
            asyncio.run(stage.run_hp_first_stage(
                path, 0, _HPProvider(ledger, rows[0]['work_item_id'], 0),
                ledger, target_repository=repo))
            hp = _RoleProvider(ledger, rows[1]['work_item_id'],
                               'function_analysis', {})
            with self.assertRaisesRegex(ValueError, 'model turn not eligible'):
                asyncio.run(stage.run_hp_first_stage(
                    path, 1, hp, ledger, target_repository=repo))
            saved = stage.read_interleaved_dev(path)
            self.assertEqual(hp.calls, [])
            self.assertEqual(saved['role_active']['state'],
                             'NO_OPPORTUNITY_BUDGET')
            self.assertEqual((ledger.logical, ledger.physical), (4, 4))
            self.assertEqual(ledger.pending_work[-1]['state'], 'PENDING_BUDGET')

    def test_cancelled_hp_turn_cannot_be_resent_or_counted_complete(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=8)
            rows = stage.read_interleaved_dev(path)['work_items']
            for ordinal in (0, 1):
                asyncio.run(stage.generate_sp_stage(
                    path, ordinal,
                    _Provider(ledger, rows[ordinal]['work_item_id'], 1),
                    ledger, target_repository=repo))
            hp = _CancelledRoleProvider(ledger, rows[1]['work_item_id'],
                                        'function_analysis', {})
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(stage.run_hp_first_stage(
                    path, 1, hp, ledger, target_repository=repo))
            saved = stage.read_interleaved_dev(path)
            self.assertEqual(saved['role_active']['state'],
                             'INCOMPLETE_ROLE_TURN')
            self.assertEqual(saved['work_items'][1]['hp_state'],
                             'PENDING_HP_FIRST_OPPORTUNITY')
            before = (ledger.logical, ledger.physical)
            with self.assertRaisesRegex(ValueError, 'not eligible'):
                asyncio.run(stage.run_hp_first_stage(
                    path, 1, hp, ledger, target_repository=repo))
            self.assertEqual((ledger.logical, ledger.physical), before)

    def test_hp_harness_drift_after_model_response_is_incomplete(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=8)
            item = stage.read_interleaved_dev(path)['work_items'][0]
            asyncio.run(stage.generate_sp_stage(
                path, 0, _Provider(ledger, item['work_item_id'], 1),
                ledger, target_repository=repo))
            hp = _MutatingRoleProvider(
                ledger, item['work_item_id'], 'function_analysis', {
                    'summary': 'reviewed', 'input_flow': 'input may reach source',
                    'state_dependencies': [], 'context_requests': [],
                    'safe_assumptions': [], 'unknowns': [],
                    'input_sources': [], 'security_sensitive_operations': [],
                    'validations': [], 'memory_operations': [], 'evidence': [],
                    'hypothesis_evaluations': []})
            with self.assertRaisesRegex(ValueError, 'Harness|source'):
                asyncio.run(stage.run_hp_first_stage(
                    path, 0, hp, ledger, target_repository=repo))
            raw = json.loads(path.read_text())
            self.assertEqual(raw['role_active']['state'],
                             'INCOMPLETE_ROLE_TURN')
            self.assertEqual(raw['role_turns'], [])
            self.assertEqual((ledger.logical, ledger.physical), (3, 3))
            with self.assertRaises(ValueError):
                stage.read_interleaved_dev(path)

    def test_response_artifact_and_ledger_tampering_are_rejected(self):
        with TemporaryDirectory() as temp:
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                Path(temp), credits=12)
            rows = stage.read_interleaved_dev(path)['work_items']
            for ordinal, count in ((0, 3), (1, 1)):
                asyncio.run(stage.generate_sp_stage(
                    path, ordinal,
                    _Provider(ledger, rows[ordinal]['work_item_id'], count),
                    ledger, target_repository=repo))
            asyncio.run(stage.run_hp_first_stage(
                path, 1, _HPProvider(ledger, rows[1]['work_item_id'], 0),
                ledger, target_repository=repo))
            sp_id = stage.read_interleaved_dev(path)['work_items'][0]['candidate_ids'][0]
            asyncio.run(stage.run_sp_verifier_stage(
                path, 0, sp_id, _RoleProvider(
                    ledger, rows[0]['work_item_id'], 'sp_verifier', _verdict()),
                ledger, target_repository=repo))
            asyncio.run(stage.run_pov_stage(
                path, 0, sp_id, _RoleProvider(
                    ledger, rows[0]['work_item_id'], 'poc_generator', {
                        'generator_script': 'def build():\n    return b"seed"\n',
                        'expected_behavior': 'exercise public candidate',
                        'trigger_rationale': 'public seed'}),
                ledger, target_repository=repo))
            pristine = path.read_bytes()
            for role in ('function_analysis', 'sp_verifier', 'poc_generator'):
                with self.subTest(role=role):
                    saved = json.loads(pristine)
                    receipt = next(row for row in saved['role_turns']
                                   if row['role'] == role)
                    artifact = Path(receipt['artifact_path'])
                    original = artifact.read_bytes()
                    body = json.loads(original)
                    if role == 'function_analysis':
                        body['summary'] = 'forged HP conclusion'
                    elif role == 'sp_verifier':
                        body['verification']['verdict'] = 'REFUTED'
                        body['verification']['recommended_next_action'] = 'REFUTE'
                        body['candidate']['status'] = 'REFUTED'
                        saved['work_items'][0]['sp_queue'][0]['state'] = 'REFUTED'
                        receipt['after_state'] = 'REFUTED'
                    else:
                        body['generator_script'] = 'def build():\n    return b"forged"\n'
                    artifact.write_text(json.dumps(body, sort_keys=True) + '\n')
                    receipt['artifact_sha256'] = hashlib.sha256(
                        artifact.read_bytes()).hexdigest()
                    path.write_text(json.dumps(saved, sort_keys=True) + '\n')
                    with self.assertRaises(ValueError):
                        stage.read_interleaved_dev(path)
                    artifact.write_bytes(original)
                    path.write_bytes(pristine)
            ledger.begin_turn(rows[0]['work_item_id'], 'sp_verifier', 'b' * 64)
            ledger.start_attempt('b' * 64)
            ledger.finish_attempt(completed=True)
            saved = json.loads(pristine)
            saved['ledger_logical'] = ledger.logical
            saved['ledger_physical'] = ledger.physical
            saved['role_ledger_checkpoint_sha256'] = stage._sha(
                ledger.checkpoint_path)
            path.write_text(json.dumps(saved, sort_keys=True) + '\n')
            with self.assertRaisesRegex(ValueError, 'unreceipted function turn'):
                stage.read_interleaved_dev(path)

    def test_same_fake_wire_bridge_switches_a_b_hp_verifier_pov(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            from test_dev_interleaved_sp_stage import InterleavedSPStageTests
            repo, path, ledger = InterleavedSPStageTests().fixture(
                root, credits=12)
            state = stage.read_interleaved_dev(path)
            rows = state['work_items']
            harness = stage._pinned_harness(state, Path(state['source_run']), repo)
            repository = SourceRepository(repo, harness.function_catalog)
            hp_response = {
                'summary': 'reviewed', 'input_flow': 'input may reach source',
                'state_dependencies': [], 'context_requests': [],
                'safe_assumptions': [], 'unknowns': [], 'input_sources': [],
                'security_sensitive_operations': [], 'validations': [],
                'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': []}
            wire = _RoleWire(ledger, root, [
                _wire_sp_response(repository, rows[0], 3),
                _wire_sp_response(repository, rows[1], 1),
                hp_response, _verdict(), {
                    'generator_script': 'def build():\n    return b"seed"\n',
                    'expected_behavior': 'public candidate',
                    'trigger_rationale': 'public seed'}])
            routes = {name: {'model': 'test-model', 'reasoning': 'high'}
                      for name in ('sp_generation', 'function_analysis',
                                   'sp_verifier', 'poc_generator')}
            wire.role_models = routes
            bridge_sha = hashlib.sha256(BRIDGE.read_bytes()).hexdigest()
            common = {'target_repository': repo, 'role_models': routes,
                      'accounting_owner': 'APP_SERVER_TURN_START_V1',
                      'bridge_source_sha256': bridge_sha,
                      'allow_synthetic_wire': True}
            wire.bind_scope(rows[0]['work_item_id'])
            asyncio.run(stage.generate_sp_stage(path, 0, wire, ledger, **common))
            wire.unbind_scope()
            wire.bind_scope(rows[1]['work_item_id'])
            asyncio.run(stage.generate_sp_stage(path, 1, wire, ledger, **common))
            asyncio.run(stage.run_hp_first_stage(path, 1, wire, ledger, **common))
            sp_id = stage.read_interleaved_dev(path)['work_items'][0]['candidate_ids'][0]
            wire.unbind_scope()
            wire.bind_scope(rows[0]['work_item_id'])
            asyncio.run(stage.run_sp_verifier_stage(
                path, 0, sp_id, wire, ledger, **common))
            asyncio.run(stage.run_pov_stage(
                path, 0, sp_id, wire, ledger, **common))
            saved = stage.read_interleaved_dev(path)
            self.assertEqual(len(wire.sent), 5)
            self.assertEqual((ledger.logical, ledger.physical), (6, 6))
            self.assertEqual(saved['work_items'][0]['sp_queue'][0]['state'],
                             'POV_GENERATED_UNVALIDATED')
            self.assertEqual(saved['scan_count'], 0)


if __name__ == '__main__':
    unittest.main()
