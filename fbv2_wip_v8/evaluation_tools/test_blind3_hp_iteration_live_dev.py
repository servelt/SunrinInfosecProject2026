"""No-network tests for the HP live-development transport boundary."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import AsyncMock, patch

import blind2_runner_draft as old_runner
import blind3_hp_iteration_live_dev as live_mod
from blind3_hp_iteration_live_dev import (
    LiveHPPolicy, LiveHPLedger, LiveHPAppServer, LiveHPProvider,
    _tree_digest, _scan_options_digest, load_live_contract, refined_guided_observation,
    perform_live_preflight, run_sequence_live_dev, verify_execution_inputs,
)
from vulnerabilityanalysis.llm import AppServerError, LLMRequest, ModelToolEventError
from vulnerabilityanalysis.runtime import RuntimeCleanupError


ROUTES = {
    'function_analysis': {'model': 'test-model', 'reasoning': 'high'},
    'assertion_generator': {'model': 'test-model', 'reasoning': 'high'},
}


def approved_scan_options():
    return {'role_models': {role: dict(route) for role, route in ROUTES.items()}}


def pinned_contract(root: Path):
    policy = LiveHPPolicy()
    binary = root / 'codex'
    binary.write_text('test executable')
    launcher = Path(__file__).with_name('blind2_model_sandbox.py').resolve()
    config = root / 'config.toml'
    config.write_text(
        'model = "test-model"\n'
        'model_provider = "test_zero_retry"\n'
        'model_reasoning_effort = "high"\n'
        '[model_providers.test_zero_retry]\n'
        'name = "OpenAI"\nwire_api = "responses"\n'
        'requires_openai_auth = true\nsupports_websockets = false\n'
        'request_max_retries = 0\nstream_max_retries = 0\n'
        '[features]\napps = false\n')
    auth = root / 'auth.json'
    auth.write_text('{}')
    auth.chmod(0o600)
    toy = root / 'toy'
    toy.mkdir()
    (toy / 'target.c').write_text('int fn(void) { return 0; }\n')
    artifact = toy / 'harness.json'
    artifact.write_text('{}')
    run = root / 'run'
    run.mkdir()
    phase1 = {
        'run.json': {'artifact': str(artifact), 'harness_id': 'h1'},
        'harness.json': {'harness_id': 'h1'},
        'workers.json': [{'worker_id': 'w1', 'harness_id': 'h1'}],
        'directions.json': [{'direction_id': 'd1', 'worker_id': 'w1'}],
        'function_pool.json': [{'function_id': 'fn', 'function_name': 'fn',
                                'source_file': 'target.c'}],
        'selection.json': {'function_id': 'fn', 'function_name': 'fn',
                           'source_file': 'target.c'},
    }
    for name, content in phase1.items():
        (run / name).write_text(json.dumps(content))
    python = Path(sys.executable).resolve()
    row = {'kind': 'BLIND3_HP_LIVE_DEV_V1', 'limits': asdict(policy),
           'role_models': ROUTES,
           'route_sha256': '0' * 64,
           'public_toy': {'target_repository': str(toy),
                          'source_tree_sha256': _tree_digest(toy),
                          'selected_function_id': 'fn',
                          'phase1_run': str(run),
                          'phase1_files_sha256': {name: hashlib.sha256(
                              (run / name).read_bytes()).hexdigest()
                              for name in phase1},
                          'artifact_path': str(artifact),
                          'artifact_sha256': hashlib.sha256(
                              artifact.read_bytes()).hexdigest(),
                          'scan_options_sha256': _scan_options_digest(
                              approved_scan_options()),
                          'scan_input_files_sha256': {}},
           'pins': {'codex_executable': str(binary),
                    'codex_executable_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'sandbox_launcher': str(launcher),
                    'sandbox_launcher_sha256': hashlib.sha256(launcher.read_bytes()).hexdigest(),
                    'python_executable': str(python),
                    'python_executable_sha256': hashlib.sha256(python.read_bytes()).hexdigest(),
                    'config_file': str(config),
                    'config_file_sha256': hashlib.sha256(config.read_bytes()).hexdigest()}}
    path = root / 'contract.json'
    path.write_text(json.dumps(row, sort_keys=True))
    return path, hashlib.sha256(path.read_bytes()).hexdigest(), policy


def request(role: str = 'function_analysis', *, model='test-model', effort='high'):
    return LLMRequest(role=role, instructions='Public arithmetic toy.',
                      payload={'n': 2}, output_schema={'type': 'object'},
                      model=model, effort=effort)


class FakeWire(LiveHPAppServer):
    def __init__(self, ledger, contract, root, *, outcome='ok',
                 preflight_verified=True):
        self.sent = []
        self.closed = False
        self.outcome = outcome
        super().__init__(ledger=ledger, contract=contract, cwd=root,
                         event_log_path=root / 'events.jsonl',
                         timeout_seconds=2)
        # Direct transport unit tests explicitly simulate a completed
        # preflight. Formal run tests still execute the mandatory preflight.
        self._preflight_verified = preflight_verified
        if preflight_verified:
            self._input_guard = lambda: None
            self._request_artifact_root = root / 'live_model_requests'

    async def start(self):
        return None

    async def _thread_for(self, role, session_key, model):
        return 'toy-thread'

    async def _delete_ephemeral_thread(self, thread_id):
        return None

    async def _transport_request(self, method, params, *, response_envelope=None):
        if method != 'turn/start':
            return {}
        snapshot = json.loads(Path(self.ledger.checkpoint_path).read_text())
        self.sent.append(snapshot)
        if self.outcome == 'transport':
            raise AppServerError('wire lost after physical start')
        return {'turn': {'id': f'toy-turn-{snapshot["physical"]}'}}

    async def _collect(self, thread_id, turn_id, *, response_envelope=None):
        if self.outcome == 'tool':
            self._notifications.append({'method': 'item/started', 'params': {
                'threadId': thread_id, 'turnId': turn_id,
                'item': {'type': 'commandExecution'}}})
            return await super()._collect(thread_id, turn_id, response_envelope=response_envelope)
        if self.outcome == 'internal_retry':
            self._notifications.append({'method': 'error', 'params': {
                'threadId': thread_id, 'turnId': turn_id,
                'willRetry': True}})
            return await super()._collect(thread_id, turn_id, response_envelope=response_envelope)
        if self.outcome == 'timeout':
            raise AppServerError('app-server turn wall deadline exceeded')
        if self.outcome == 'cancel':
            raise asyncio.CancelledError()
        self._record_server_event({'method': 'turn/completed', 'params': {
            'threadId': thread_id,
            'turn': {'id': turn_id, 'status': 'completed', 'items': []}}})
        return '{}'

    async def close(self):
        self.closed = True
        return None


class LiveHPBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_role_routes_must_match_contract_before_model(self):
        cases = {
            'missing': {},
            'wrong_model': {**approved_scan_options(), 'role_models': {
                **approved_scan_options()['role_models'],
                'function_analysis': {'model': 'other-model', 'reasoning': 'high'}}},
            'wrong_effort': {**approved_scan_options(), 'role_models': {
                **approved_scan_options()['role_models'],
                'assertion_generator': {'model': 'test-model', 'reasoning': 'low'}}},
            'extra_role': {**approved_scan_options(), 'role_models': {
                **approved_scan_options()['role_models'],
                'sp_generation': {'model': 'test-model', 'reasoning': 'high'}}},
        }
        for label, options in cases.items():
            with self.subTest(label=label), TemporaryDirectory() as temp:
                root = Path(temp)
                path, _, _ = pinned_contract(root)
                # Even a newly pinned, self-consistent options digest cannot
                # authorize a route differing from the live role contract.
                row = json.loads(path.read_text())
                row['public_toy']['scan_options_sha256'] = _scan_options_digest(options)
                path.write_text(json.dumps(row, sort_keys=True))
                contract, _ = load_live_contract(
                    path, hashlib.sha256(path.read_bytes()).hexdigest())
                with self.assertRaisesRegex(ValueError, 'role_models'):
                    verify_execution_inputs(contract, root / 'run', root / 'toy', options)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, _ = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            self.assertEqual(verify_execution_inputs(
                contract, root / 'run', root / 'toy', approved_scan_options())
                ['scan_options_sha256'], contract.scan_options_sha256)

    async def test_synthetic_reports_only_get_reported_label(self):
        with TemporaryDirectory() as temp:
            run = Path(temp)
            guided = run / 'assertions/a2/guided_fuzz/guided_fuzz.json'
            guided.parent.mkdir(parents=True)
            guided.write_text(json.dumps({'status': 'RAN',
                                          'fuzz_seconds_actual': 1.0}))
            (run / 'assertions/refinement_history.json').write_text(json.dumps({
                'refinements': [{'status': 'REFINED_AND_TESTED',
                                 'revisions': [{
                                     'assertion': {'assertion_id': 'a2',
                                                   'status': 'HELD_FOR_EXECUTION'},
                                     'guided_fuzz': str(guided)}]}]}))
            (run / 'runtime').mkdir()
            (run / 'runtime/runner_fuzz_jobs.json').write_text(json.dumps([
                {'id': 'a1', 'kind': 'ASSERTION', 'result_status': 'RAN',
                 'physical_actual': 1.0},
                {'id': 'a2', 'kind': 'ASSERTION', 'result_status': 'RAN',
                 'physical_actual': 1.0}]))
            row = refined_guided_observation(run)
            self.assertEqual(row['status'], 'REPORTED_SECOND_GUIDED_RAN')
            self.assertEqual(row['evidence_scope'], 'MUTABLE_REPORTS_ONLY')

    async def test_phase1_and_scan_option_tampering_blocks_preflight(self):
        changes = {
            'artifact': ('run.json', 'artifact', '/private/other_harness.json'),
            'function_name': ('selection.json', 'function_name', 'not_toy_fn'),
            'source_file': ('selection.json', 'source_file', '/private/other.c'),
            'worker': ('workers.json', None, []),
            'pool': ('function_pool.json', None, []),
            'harness': ('harness.json', 'harness_id', 'not_h1'),
        }
        for label, (name, field_name, value) in changes.items():
            with self.subTest(label=label), TemporaryDirectory() as temp:
                root = Path(temp)
                path, digest, policy = pinned_contract(root)
                contract, _ = load_live_contract(path, digest)
                target = root / 'run' / name
                row = json.loads(target.read_text())
                if field_name is None:
                    row = value
                else:
                    row[field_name] = value
                target.write_text(json.dumps(row))
                ledger = LiveHPLedger(started_at=time.time(),
                                      policy=asdict(policy), contract_sha256=digest,
                                      checkpoint_path=str(root / 'ledger.json'))
                app = FakeWire(ledger, contract, root)
                with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                     patch.object(old_runner, 'verify_model_namespace_sandbox') as sandbox, \
                     patch.object(old_runner, 'check_live_route', new_callable=AsyncMock) as route:
                    with self.assertRaises(ValueError):
                        await perform_live_preflight(
                            contract, app, root / 'run', root / 'toy',
                            approved_scan_options())
                    sandbox.assert_not_called()
                    route.assert_not_awaited()
                self.assertEqual((ledger.logical, ledger.physical,
                                  len(app.sent)), (0, 0, 0))
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            ledger = LiveHPLedger(started_at=time.time(),
                                  policy=asdict(policy), contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root)
            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox') as sandbox:
                with self.assertRaisesRegex(ValueError, 'scan options'):
                    await perform_live_preflight(
                        contract, app, root / 'run', root / 'toy',
                        {**approved_scan_options(),
                         'target_binary': root / 'toy/target.c'})
                sandbox.assert_not_called()

    async def test_phase1_change_after_preflight_blocks_first_physical_send(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def fake_scan(folder, _provider, **_options):
                run_file = folder / 'run.json'
                row = json.loads(run_file.read_text())
                row['artifact'] = '/private/other_harness.json'
                run_file.write_text(json.dumps(row))
                await provider.generate(request('function_analysis'))

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                with self.assertRaisesRegex(ValueError, 'Phase 1 execution inputs'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest, scan_options=approved_scan_options())
            self.assertEqual(ledger.physical, 0)
            self.assertEqual(app.sent, [])

    async def test_model_request_artifact_tamper_stops_after_scan(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def fake_scan(folder, _provider, **_options):
                await provider.generate(request('sp_generation'))
                await provider.generate(request('function_analysis'))
                Path(ledger.attempts[0]['request_artifact']).write_text('{}')
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 1,
                    'original_hp_limit': 5, 'combined_limit': 6,
                    'hp_calls_before_transfer': 1,
                    'checkable_assertion_count': 0,
                    'effective_sp_limit': 1, 'transferred_hp_calls': 0,
                    'reason': 'HP_NO_ASSERTION'}))
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 1, 'effective_sp_llm_call_limit': 1,
                    'combined_llm_call_limit': 6}))

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                with self.assertRaisesRegex(Exception,
                                            'LIVE_EVIDENCE_AUDIT_INCOMPLETE'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest, scan_options=approved_scan_options())
            self.assertEqual(ledger.physical, 1)
            self.assertEqual(json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                             ['status'], 'STOPPED_FAIL_CLOSED')

    async def test_scan_options_change_after_preflight_blocks_model_send(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, _, policy = pinned_contract(root)
            options = {**approved_scan_options(), 'hallucination_prevent': 'off'}
            contract_row = json.loads(path.read_text())
            contract_row['public_toy']['scan_options_sha256'] = _scan_options_digest(
                options)
            path.write_text(json.dumps(contract_row, sort_keys=True))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def fake_scan(_folder, _provider, **_scan_options):
                options['hallucination_prevent'] = 'on'
                await provider.generate(request('function_analysis'))

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                with self.assertRaisesRegex(ValueError, 'scan options'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest,
                        scan_options=options)
            self.assertEqual(ledger.physical, 0)
            self.assertEqual(app.sent, [])

    async def test_pinned_seed_change_after_preflight_blocks_model_send(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, _, policy = pinned_contract(root)
            seed = root / 'normal_seed.bin'
            seed.write_bytes(b'public-toy-seed')
            options = {**approved_scan_options(), 'assertion_seed': seed}
            contract_row = json.loads(path.read_text())
            contract_row['public_toy']['scan_options_sha256'] = _scan_options_digest(
                options)
            contract_row['public_toy']['scan_input_files_sha256'] = {
                str(seed): hashlib.sha256(seed.read_bytes()).hexdigest()}
            path.write_text(json.dumps(contract_row, sort_keys=True))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def fake_scan(_folder, _provider, **_scan_options):
                seed.write_bytes(b'changed-after-preflight')
                await provider.generate(request('function_analysis'))

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                with self.assertRaisesRegex(ValueError, 'file pin changed'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest,
                        scan_options=options)
            self.assertEqual(ledger.physical, 0)
            self.assertEqual(app.sent, [])

    async def test_json_pinned_file_options_reach_scan_as_paths(self):
        # The reviewed live Spec is JSON, whereas scan_selected expects Path
        # objects for these file inputs. Check the actual run_sequence bridge.
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, _, policy = pinned_contract(root)
            seed = root / 'normal_seed.bin'
            binary = root / 'toy-binary'
            initial = root / 'initial.bin'
            for item in (seed, binary, initial):
                item.write_bytes(b'public-toy-input')
            options = {**approved_scan_options(),
                       'assertion_seed': str(seed),
                       'target_binary': str(binary),
                       'initial_inputs': [str(initial)]}
            row = json.loads(path.read_text())
            row['public_toy']['scan_options_sha256'] = _scan_options_digest(options)
            row['public_toy']['scan_input_files_sha256'] = {
                str(item): hashlib.sha256(item.read_bytes()).hexdigest()
                for item in (seed, binary, initial)}
            path.write_text(json.dumps(row, sort_keys=True))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            contract, _ = load_live_contract(path, digest)
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def fake_scan(_folder, _provider, **scan_options):
                self.assertEqual(scan_options['assertion_seed'], seed)
                self.assertIsInstance(scan_options['assertion_seed'], Path)
                self.assertEqual(scan_options['target_binary'], binary)
                self.assertIsInstance(scan_options['target_binary'], Path)
                self.assertEqual(scan_options['initial_inputs'], [initial])
                self.assertIsInstance(scan_options['initial_inputs'][0], Path)
                raise RuntimeError('STOP_AFTER_TYPE_CHECK')

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                with self.assertRaisesRegex(RuntimeError, 'STOP_AFTER_TYPE_CHECK'):
                    await run_sequence_live_dev(
                        root / 'run', provider, ledger, root / 'toy',
                        root / 'ledger.json', contract_path=path,
                        contract_sha256=digest, scan_options=options)
            self.assertEqual(ledger.physical, 0)
            self.assertEqual(app.sent, [])

    async def test_direct_model_send_without_preflight_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            app.bind_scope('fn')
            with self.assertRaisesRegex(ValueError, 'provider no longer eligible'):
                await app.generate(request())
            self.assertEqual((ledger.logical, ledger.physical, len(app.sent)),
                             (0, 0, 0))

    async def test_direct_thread_and_turn_start_without_preflight_are_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            app.bind_scope('fn')
            for method in ('thread/start', 'turn/start'):
                with self.subTest(method=method):
                    with self.assertRaisesRegex(ValueError, 'preflight'):
                        await app._request(method, {})
            self.assertEqual((ledger.logical, ledger.physical, len(app.sent)),
                             (0, 0, 0))

    async def test_sandbox_or_route_preflight_failure_prevents_scan_and_send(self):
        for stage in ('sandbox', 'route'):
            with self.subTest(stage=stage), TemporaryDirectory() as temp:
                root = Path(temp)
                path, digest, policy = pinned_contract(root)
                contract, _ = load_live_contract(path, digest)
                run = root / 'run'
                run.mkdir(exist_ok=True)
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': 'fn', 'function_name': 'fn',
                    'source_file': 'target.c'}))
                ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                      contract_sha256=digest,
                                      checkpoint_path=str(root / 'ledger.json'))
                app = FakeWire(ledger, contract, root, preflight_verified=False)
                provider = LiveHPProvider(ledger, app)
                sandbox_effect = (ValueError('sandbox failed') if stage == 'sandbox'
                                  else {'isolation': True})
                with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                     patch.object(old_runner, 'verify_model_namespace_sandbox',
                                  side_effect=sandbox_effect if stage == 'sandbox'
                                  else None,
                                  return_value=sandbox_effect if stage == 'route'
                                  else None), \
                     patch.object(old_runner, 'check_live_route',
                                  new_callable=AsyncMock) as route, \
                     patch.object(live_mod, '_run_sequence_core',
                                  new_callable=AsyncMock) as core:
                    if stage == 'route':
                        route.side_effect = ValueError('route failed')
                    with self.assertRaisesRegex(ValueError,
                                                'sandbox failed|route failed'):
                        await run_sequence_live_dev(
                            run, provider, ledger, root / 'toy',
                            root / 'ledger.json', contract_path=path,
                            contract_sha256=digest, scan_options=approved_scan_options())
                    core.assert_not_awaited()
                    self.assertEqual(route.await_count,
                                     0 if stage == 'sandbox' else 1)
                self.assertFalse(app._preflight_verified)
                self.assertTrue(app.closed)
                self.assertEqual((ledger.logical, ledger.physical,
                                  len(app.sent)), (0, 0, 0))

    async def test_whole_function_wall_timeout_closes_provider_and_keeps_original(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn',
                'source_file': 'target.c'}))
            ledger = LiveHPLedger(
                started_at=time.time() - policy.wall_seconds + 0.15,
                policy=asdict(policy), contract_sha256=digest,
                checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def slow_core(*_args, **_kwargs):
                await asyncio.sleep(0.5)

            async def failed_close():
                app.closed = True
                raise OSError('secondary close failed')

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(live_mod, '_run_sequence_core', side_effect=slow_core), \
                 patch.object(app, 'close', failed_close):
                with self.assertRaises(TimeoutError):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy',
                        root / 'ledger.json', contract_path=path,
                        contract_sha256=digest, scan_options=approved_scan_options())
            self.assertTrue(app.closed)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))
            self.assertEqual(json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                             ['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(json.loads((run / 'runtime/live_provider_cleanup_error.json')
                                        .read_text())['error_type'], 'OSError')

    async def test_external_cancel_closes_provider_and_checkpoints(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn',
                'source_file': 'target.c'}))
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)
            entered = asyncio.Event()

            async def slow_core(*_args, **_kwargs):
                entered.set()
                await asyncio.sleep(1)

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(live_mod, '_run_sequence_core', side_effect=slow_core):
                task = asyncio.create_task(run_sequence_live_dev(
                    run, provider, ledger, root / 'toy', root / 'ledger.json',
                    contract_path=path, contract_sha256=digest, scan_options=approved_scan_options()))
                await asyncio.wait_for(entered.wait(), timeout=1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertTrue(app.closed)
            self.assertEqual(json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                             ['status'], 'STOPPED_CANCELLED')

    async def test_late_provider_close_cannot_return_success(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn',
                'source_file': 'target.c'}))
            ledger = LiveHPLedger(
                started_at=time.time() - policy.wall_seconds + 0.15,
                policy=asdict(policy), contract_sha256=digest,
                checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root, preflight_verified=False)
            provider = LiveHPProvider(ledger, app)

            async def fake_core(*_args, **_kwargs):
                return [{'function_id': 'fn',
                         'status': 'INCONCLUSIVE_NO_REFINED_ASSERTION'}]

            async def slow_close():
                await asyncio.sleep(0.25)
                app.closed = True

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(live_mod, '_run_sequence_core', side_effect=fake_core), \
                 patch.object(live_mod, 'verify_model_event_order'), \
                 patch.object(live_mod, 'refined_guided_observation',
                              return_value={'status': 'NO_REFINED_ASSERTION'}), \
                 patch.object(app, 'close', slow_close):
                with self.assertRaises(TimeoutError):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy',
                        root / 'ledger.json', contract_path=path,
                        contract_sha256=digest, scan_options=approved_scan_options())
            self.assertTrue(app.closed)
            self.assertEqual(json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                             ['status'], 'STOPPED_WALL_LIMIT')

    async def test_missing_pinned_app_state_blocks_before_scan(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root)
            provider = LiveHPProvider(ledger, app)
            with patch.dict(os.environ, {}, clear=True), \
                 patch.object(old_runner.scan_mod, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'CODEX_HOME missing'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest, scan_options=approved_scan_options())
                scan.assert_not_called()
            self.assertEqual(ledger.logical, 0)
            self.assertEqual(ledger.physical, 0)

    async def test_second_guided_pending_is_not_counted_as_ran(self):
        with TemporaryDirectory() as temp:
            run = Path(temp)
            guided = run / 'assertions/a2/guided_fuzz/guided_fuzz.json'
            guided.parent.mkdir(parents=True)
            guided.write_text(json.dumps({'status': 'PENDING_FUZZ_BUDGET',
                                          'fuzz_seconds_actual': 0}))
            (run / 'assertions/refinement_history.json').write_text(json.dumps({
                'refinements': [{'status': 'REFINED_AND_TESTED',
                                 'revisions': [{
                                     'assertion': {'assertion_id': 'a2',
                                                   'status': 'HELD_FOR_EXECUTION'},
                                     'guided_fuzz': str(guided)}]}]}))
            (run / 'runtime').mkdir()
            (run / 'runtime/runner_fuzz_jobs.json').write_text(json.dumps([
                {'id': 'a1', 'kind': 'ASSERTION', 'result_status': 'RAN',
                 'physical_actual': 0.01},
                {'id': 'a2', 'kind': 'ASSERTION',
                 'result_status': 'PENDING_FUZZ_BUDGET',
                 'physical_actual': 0}]))
            self.assertEqual(refined_guided_observation(run)['status'],
                             'REFINED_ASSERTION_TESTED_GUIDED_NOT_RAN')

    async def test_contract_requires_development_wall_above_observed_toy(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            loaded, _ = load_live_contract(path, digest)
            self.assertEqual(loaded.policy, policy)
            self.assertEqual(policy.wall_seconds, 3300)
            row = json.loads(path.read_text())
            row['limits']['wall_seconds'] = 300
            path.write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, 'SHA'):
                load_live_contract(path, digest)

    async def test_repinned_config_with_provider_retry_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, _, _ = pinned_contract(root)
            config = root / 'config.toml'
            config.write_text(config.read_text().replace(
                'request_max_retries = 0', 'request_max_retries = 1'))
            row = json.loads(path.read_text())
            row['pins']['config_file_sha256'] = hashlib.sha256(
                config.read_bytes()).hexdigest()
            path.write_text(json.dumps(row, sort_keys=True))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'zero-retry'):
                load_live_contract(path, digest)

    async def test_physical_checkpoint_precedes_wire_and_scripted_sp_is_not_physical(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            ledger.select('fn')
            ledger.bind_run('fn', root)
            ledger.checkpoint()
            app = FakeWire(ledger, contract, root)
            provider = LiveHPProvider(ledger, app)
            provider.begin_function('fn')
            self.assertEqual((await provider.generate(request('sp_generation')))
                             ['suspicious_points'], [])
            self.assertEqual((ledger.logical, ledger.physical), (1, 0))
            await provider.generate(request())
            self.assertEqual((ledger.logical, ledger.physical), (2, 1))
            self.assertEqual(len(app.sent), 1)
            sent = app.sent[0]
            self.assertEqual(sent['physical'], 1)
            self.assertEqual(sent['attempts'][-1]['status'], 'STARTED')
            self.assertEqual(sent['attempts'][-1]['role'], 'function_analysis')
            self.assertEqual(sent['attempts'][-1]['model'], 'test-model')
            self.assertEqual(sent['attempts'][-1]['effort'], 'high')
            self.assertEqual(Path(ledger.checkpoint_path).stat().st_mode & 0o777, 0o600)

    async def test_checkpoint_failure_rejects_wire_before_transport(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            ledger.select('fn')
            ledger.bind_run('fn', root)
            ledger.checkpoint()
            app = FakeWire(ledger, contract, root)
            app.bind_scope('fn')
            with patch.object(ledger, 'checkpoint', side_effect=OSError('disk full')):
                with self.assertRaisesRegex(OSError, 'disk full'):
                    await app.generate(request())
            self.assertEqual(app.sent, [])

    async def test_tool_timeout_and_transport_errors_never_retry(self):
        for outcome in ('tool', 'timeout', 'transport', 'cancel', 'internal_retry'):
            with self.subTest(outcome=outcome), TemporaryDirectory() as temp:
                root = Path(temp)
                path, digest, policy = pinned_contract(root)
                contract, _ = load_live_contract(path, digest)
                ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                      contract_sha256=digest,
                                      checkpoint_path=str(root / 'ledger.json'))
                ledger.select('fn')
                ledger.bind_run('fn', root)
                ledger.checkpoint()
                app = FakeWire(ledger, contract, root, outcome=outcome)
                app.bind_scope('fn')
                with self.assertRaises((AppServerError, ModelToolEventError,
                                        asyncio.CancelledError)):
                    await app.generate(request())
                self.assertLessEqual(len(app.sent), 1)
                self.assertEqual(ledger.physical, 1)
                self.assertEqual(ledger.retries, 0)
                self.assertEqual(ledger.attempts[0]['status'], 'ERROR')
                if outcome == 'internal_retry':
                    self.assertTrue(ledger.attempts[0]['internal_retry'])
                if outcome == 'tool':
                    events = (root / 'events.jsonl').read_text()
                    self.assertIn('commandExecution', events)
                with self.assertRaises((ValueError, ModelToolEventError)):
                    await app.generate(request())

    async def test_real_runner_boundary_counts_two_assertions_and_two_guided_jobs(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn',
                'source_file': 'target.c'}))
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root)
            provider = LiveHPProvider(ledger, app)

            def fake_guided(*_args, **_kwargs):
                return {'status': 'RAN', 'fuzz_seconds_actual': 0.01,
                        'violation_witnesses': []}

            async def fake_refine(folder, *_args, **_kwargs):
                await provider.generate(request('function_analysis'))
                await provider.generate(request('assertion_generator'))
                guided = folder / 'assertions/a2/guided_fuzz/guided_fuzz.json'
                guided.parent.mkdir(parents=True, exist_ok=True)
                guided.write_text(json.dumps({'status': 'RAN',
                                              'fuzz_seconds_actual': 0.01}))
                return {'status': 'PROCESSED', 'llm_calls': 2,
                        'refinements': [{'status': 'REFINED_AND_TESTED',
                                         'revisions': [{
                                            'assertion': {'assertion_id': 'a2',
                                                          'status': 'HELD_FOR_EXECUTION'},
                                            'guided_fuzz': str(guided)}]}]}

            async def fake_scan(folder, _provider, **options):
                self.assertEqual((options['sp_llm_call_limit'],
                                  options['hp_llm_call_limit'],
                                  options['combined_llm_call_limit'] if
                                  'combined_llm_call_limit' in options else 6),
                                 (1, 5, 6))
                await provider.generate(request('sp_generation'))
                for role in ('function_analysis', 'function_analysis',
                             'assertion_generator'):
                    await provider.generate(request(role))
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 1,
                    'original_hp_limit': 5, 'combined_limit': 6,
                    'hp_calls_before_transfer': 3,
                    'checkable_assertion_count': 1,
                    'effective_sp_limit': 1, 'transferred_hp_calls': 0,
                    'reason': 'HP_ASSERTION_PATH'}))
                old_runner.scan_mod.guided_fuzz_assertion(
                    type('Assertion', (), {'assertion_id': 'a1'})(), seconds=2)
                triage = folder / 'assertions/a1/executions/e1/triage.json'
                triage.parent.mkdir(parents=True)
                triage.write_text(json.dumps({'classification':
                                              'OVERSTRONG_ASSUMPTION'}))
                (folder / 'assertions/results.json').write_text(json.dumps([{
                    'assertion_id': 'a1', 'status': 'VIOLATED',
                    'execution_result': str(triage.parent / 'runtime.json')}]))
                await old_runner.scan_mod.refine_overstrong_assertions(
                    folder, function_id='fn', max_llm_calls=2)
                old_runner.scan_mod.guided_fuzz_assertion(
                    type('Assertion', (), {'assertion_id': 'a2'})(), seconds=2)
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 5, 'effective_sp_llm_call_limit': 1,
                    'combined_llm_call_limit': 6}))

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(old_runner.scan_mod, 'refine_overstrong_assertions', fake_refine), \
                 patch.object(old_runner.scan_mod, 'guided_fuzz_assertion', fake_guided):
                rows = await run_sequence_live_dev(
                    run, provider, ledger, root / 'toy', root / 'ledger.json',
                    contract_path=path, contract_sha256=digest, scan_options=approved_scan_options())
            self.assertEqual(rows[0]['status'], 'INCONCLUSIVE_REPORTED_GUIDED_RAN')
            self.assertEqual(rows[0]['refined_guided_observation'],
                             'REPORTED_SECOND_GUIDED_RAN')
            self.assertTrue(app.closed)
            self.assertTrue(app._dev_tainted)
            self.assertFalse(app._preflight_verified)
            self.assertEqual(json.loads((run / 'runtime/live_preflight.json').read_text())
                             ['status'], 'PASS')
            self.assertEqual((ledger.logical, ledger.physical, ledger.retries),
                             (6, 5, 0))
            self.assertEqual(len(ledger.attempts), 5)
            for attempt in ledger.attempts:
                artifact = Path(attempt['request_artifact'])
                self.assertTrue(artifact.is_relative_to(
                    run / 'runtime/live_model_requests'))
                self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                 attempt['request_artifact_sha256'])
                self.assertEqual(json.loads(artifact.read_text())
                                 ['request_sha256'], attempt['request_hash'])
            self.assertEqual(ledger.counts['fn'], {
                'sp_generation': 1, 'function_analysis': 3,
                'assertion_generator': 2})
            jobs = json.loads((run / 'runtime/runner_fuzz_jobs.json').read_text())
            self.assertEqual(len(jobs), 2)
            self.assertEqual([job['id'] for job in jobs], ['a1', 'a2'])
            self.assertTrue(all(job['result_status'] == 'RAN' for job in jobs))

    async def test_cleanup_error_does_not_replace_original_runtime_error(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn',
                'source_file': 'target.c'}))
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root)
            provider = LiveHPProvider(ledger, app)

            async def failed_scan(*_args, **_kwargs):
                raise RuntimeCleanupError('primary cleanup failure', '', '')

            async def failed_close():
                raise OSError('secondary provider close failure')

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', failed_scan), \
                 patch.object(app, 'close', failed_close):
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'primary cleanup failure'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest, scan_options=approved_scan_options())
            self.assertTrue((run / 'FUNCTION_CHECKPOINT.json').is_file())
            secondary = json.loads((run / 'runtime/live_provider_cleanup_error.json').read_text())
            self.assertEqual(secondary['error_type'], 'OSError')

    async def test_cleanup_failure_after_success_is_stopped_and_checkpointed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest, policy = pinned_contract(root)
            contract, _ = load_live_contract(path, digest)
            run = root / 'run'
            run.mkdir(exist_ok=True)
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn',
                'source_file': 'target.c'}))
            ledger = LiveHPLedger(started_at=time.time(), policy=asdict(policy),
                                  contract_sha256=digest,
                                  checkpoint_path=str(root / 'ledger.json'))
            app = FakeWire(ledger, contract, root)
            provider = LiveHPProvider(ledger, app)

            async def one_turn_scan(folder, _provider, **_options):
                await provider.generate(request('sp_generation'))
                await provider.generate(request('function_analysis'))
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 1,
                    'original_hp_limit': 5, 'combined_limit': 6,
                    'hp_calls_before_transfer': 1,
                    'checkable_assertion_count': 0,
                    'effective_sp_limit': 1, 'transferred_hp_calls': 0,
                    'reason': 'HP_NO_ASSERTION'}))
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 1, 'effective_sp_llm_call_limit': 1,
                    'combined_llm_call_limit': 6}))

            async def failed_close():
                raise OSError('provider close failed after scan')

            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, 'verify_model_namespace_sandbox',
                              return_value={'isolation': True}), \
                 patch.object(old_runner, 'check_live_route', new_callable=AsyncMock), \
                 patch.object(old_runner.scan_mod, 'scan_selected', one_turn_scan), \
                 patch.object(app, 'close', failed_close):
                with self.assertRaisesRegex(OSError, 'provider close failed'):
                    await run_sequence_live_dev(
                        run, provider, ledger, root / 'toy', root / 'ledger.json',
                        contract_path=path, contract_sha256=digest, scan_options=approved_scan_options())
            self.assertEqual(json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                             ['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(json.loads((run / 'runtime/live_provider_cleanup_error.json')
                                        .read_text())['error_type'], 'OSError')


if __name__ == '__main__':
    unittest.main()
