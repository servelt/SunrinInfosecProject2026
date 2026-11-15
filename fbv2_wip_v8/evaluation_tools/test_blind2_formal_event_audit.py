"""Provider-free checks for the formal runner's private App Server audit."""

from __future__ import annotations

import json
import asyncio
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from unittest import TestCase
from unittest.mock import patch

import blind2_runner_draft as runner


def _ledger_with_completed_turn(root: Path) -> runner.Ledger:
    ledger = runner.Ledger(started_at=time.time())
    ledger.select('synthetic-fn')
    ledger.bind_run('synthetic-fn', root / 'run')
    request_hash = 'a' * 64
    ledger.begin_turn('synthetic-fn', 'sp_generation', request_hash)
    ledger.start_attempt(request_hash)
    ledger.attempts[-1].update(app_server_turn_id='turn-1',
                               role='sp_generation', model='synthetic-model')
    ledger.finish_attempt(completed=True, accepted=True)
    return ledger


def _messages(*, text: str = 'four', tool_summary: bool = False) -> list[dict]:
    items = [{'type': 'userMessage'}, {'type': 'agentMessage'}]
    if tool_summary:
        items.append({'type': 'commandExecution'})
    return [
        {'method': 'thread/started', 'params': {
            'threadId': 'thread-1', 'thread': {'id': 'thread-1'}}},
        {'method': 'turn/started', 'params': {
            'threadId': 'thread-1', 'turn': {'id': 'turn-1', 'status': 'inProgress'}}},
        {'method': 'item/completed', 'params': {
            'threadId': 'thread-1', 'turnId': 'turn-1',
            'item': {'type': 'agentMessage', 'id': 'item-1', 'text': text}}},
        {'method': 'turn/completed', 'params': {
            'threadId': 'thread-1',
            'turn': {'id': 'turn-1', 'status': 'completed', 'items': items}}},
    ]


class FormalEventAuditTests(TestCase):
    def _backend(self, root: Path) -> runner.GuardedAppServer:
        root.chmod(0o700)
        backend = runner.GuardedAppServer(
            ledger=runner.Ledger(started_at=time.time()),
            checkpoint=root / 'ledger.json', route_sha256='b' * 64,
            role_models={}, codex_executable_path=root / 'unused',
            codex_executable_sha256='b' * 64, cwd=root)
        backend.event_log_path = root / 'MODEL_EVENT_TYPES.jsonl'
        return backend

    def test_large_harmless_event_is_fully_private_and_bound_to_formal_ledger(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            for message in _messages(text='x' * 5000):
                backend._record_server_event(message)
            log = backend.event_log_path
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(rows[2]['params']['item']['text'], 'x' * 5000)
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            runner.verify_formal_model_event_order(_ledger_with_completed_turn(root), log)

    def test_hidden_tool_in_completed_summary_is_rejected_offline(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            for message in _messages(tool_summary=True):
                backend._record_server_event(message)
            with self.assertRaisesRegex(ValueError, 'tool'):
                runner.verify_formal_model_event_order(
                    _ledger_with_completed_turn(root), backend.event_log_path)

    def test_oversized_event_cannot_get_formal_audit_pass(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            for message in _messages(text='x' * 70000):
                backend._record_server_event(message)
            with self.assertRaisesRegex(ValueError, 'params unavailable'):
                runner.verify_formal_model_event_order(
                    _ledger_with_completed_turn(root), backend.event_log_path)

    def test_private_write_failure_taints_session(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            backend.event_log_path.mkdir()
            with self.assertRaises(runner.ModelAuditError):
                backend._record_server_event(_messages()[0])
            self.assertTrue(backend.audit_log_failed)

    def test_private_recording_limit_does_not_expand_online_startup_acceptance(self):
        with TemporaryDirectory() as tmp:
            backend = self._backend(Path(tmp))
            label = backend._unapproved_event_label({
                'method': 'configWarning',
                'params': {'summary': 'x' * 5000, 'details': None}})
            self.assertEqual(label, 'configWarning:PARAMS_TOO_LARGE')

    def test_missing_completion_or_nonprivate_directory_blocks_audit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            for message in _messages()[:-1]:
                backend._record_server_event(message)
            with self.assertRaisesRegex(ValueError, 'completed App Server turns'):
                runner.verify_formal_model_event_order(
                    _ledger_with_completed_turn(root), backend.event_log_path)
            backend._record_server_event(_messages()[-1])
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'not private'):
                runner.verify_formal_model_event_order(
                    _ledger_with_completed_turn(root), backend.event_log_path)

    def test_retry_error_and_later_completion_match_two_physical_starts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            ledger = runner.Ledger(started_at=time.time())
            ledger.select('synthetic-fn')
            ledger.bind_run('synthetic-fn', root / 'run')
            request_hash = 'a' * 64
            ledger.begin_turn('synthetic-fn', 'sp_generation', request_hash)
            ledger.start_attempt(request_hash)
            ledger.attempts[-1]['app_server_turn_id'] = 'turn-failed'
            self.assertTrue(ledger.finish_attempt(
                completed=False, error='stream disconnected before completion',
                accepted=True, visible=False, response_saved=False))
            ledger.start_attempt(request_hash, retry=True)
            ledger.attempts[-1]['app_server_turn_id'] = 'turn-1'
            ledger.finish_attempt(completed=True, accepted=True)
            messages = [
                {'method': 'turn/started', 'params': {
                    'threadId': 'thread-1',
                    'turn': {'id': 'turn-failed', 'status': 'inProgress'}}},
                {'method': 'error', 'params': {
                    'threadId': 'thread-1', 'turnId': 'turn-failed',
                    'willRetry': False, 'message': 'synthetic stream break'}},
                *_messages(),
            ]
            for message in messages:
                backend._record_server_event(message)
            report = runner.verify_formal_model_event_order(
                ledger, backend.event_log_path)
            self.assertEqual(report['physical_attempts'], 2)
            self.assertEqual(report['completed_turns'], 1)

    def test_server_completion_with_later_schema_error_is_not_ledger_success(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            ledger = runner.Ledger(started_at=time.time())
            ledger.select('synthetic-fn')
            ledger.bind_run('synthetic-fn', root / 'run')
            request_hash = 'a' * 64
            ledger.begin_turn('synthetic-fn', 'sp_generation', request_hash)
            ledger.start_attempt(request_hash)
            ledger.attempts[-1].update(
                app_server_turn_id='turn-1', server_terminal_status='completed')
            ledger.finish_attempt(completed=False, error='synthetic schema error',
                                  accepted=True, visible=True)
            ledger.abandon_turn('synthetic-fn', 'SchemaError')
            for message in _messages():
                backend._record_server_event(message)
            report = runner.verify_formal_model_event_order(
                ledger, backend.event_log_path)
            self.assertEqual(report['accepted_turns'], 1)
            self.assertEqual(report['completed_turns'], 0)

    def test_normal_buffered_turn_summary_is_bound_without_false_hold(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            messages = _messages()
            messages.insert(2, {'method': 'model/safetyBuffering/updated',
                                'params': {'threadId': 'thread-1',
                                           'turnId': 'turn-1',
                                           'model': 'synthetic-model',
                                           'fasterModel': None,
                                           'reasons': ['user_risk'],
                                           'useCases': ['bio'],
                                           'showBufferingUi': True}})
            for message in messages:
                backend._record_server_event(message)
            summary = {
                'classification': 'PROVIDER_SAFETY_BUFFERING',
                'buffered': True, 'thread_id': 'thread-1',
                'turn_id': 'turn-1', 'role': 'sp_generation',
                'requested_model': 'synthetic-model',
                'faster_models': [], 'reasons': ['user_risk'],
                'use_cases': ['bio'], 'buffer_to_turn_end_seconds': 0.1,
                'buffer_to_stop_seconds': None, 'turn_status': 'completed',
            }
            with backend.event_log_path.open('a') as stream:
                stream.write(json.dumps(summary) + '\n')
            report = runner.verify_formal_model_event_order(
                _ledger_with_completed_turn(root), backend.event_log_path)
            self.assertEqual(report['safety_summary_rows'], 1)

    def test_safety_summary_wrong_model_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            messages = _messages()
            messages.insert(2, {'method': 'model/safetyBuffering/updated',
                                'params': {'threadId': 'thread-1',
                                           'turnId': 'turn-1',
                                           'model': 'synthetic-model',
                                           'fasterModel': None,
                                           'reasons': [], 'useCases': [],
                                           'showBufferingUi': False}})
            for message in messages:
                backend._record_server_event(message)
            summary = {
                'classification': 'PROVIDER_SAFETY_BUFFERING',
                'buffered': False, 'thread_id': 'thread-1',
                'turn_id': 'turn-1', 'role': 'sp_generation',
                'requested_model': 'other-model',
                'faster_models': [], 'reasons': [], 'use_cases': [],
                'buffer_to_turn_end_seconds': None,
                'buffer_to_stop_seconds': None, 'turn_status': 'completed',
            }
            with backend.event_log_path.open('a') as stream:
                stream.write(json.dumps(summary) + '\n')
            with self.assertRaisesRegex(ValueError, 'safety summary'):
                runner.verify_formal_model_event_order(
                    _ledger_with_completed_turn(root), backend.event_log_path)

    def test_stale_duplicate_completion_needs_matching_summary(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = self._backend(root)
            for message in _messages():
                backend._record_server_event(message)
            backend._record_server_event(_messages()[-1])
            stale = {'method': 'turn/completed',
                     'classification': 'STALE_OR_UNRELATED_TURN_EVENT',
                     'thread_id': 'thread-1', 'turn_id': 'turn-1'}
            with self.assertRaisesRegex(ValueError, 'summary lineage'):
                runner.verify_formal_model_event_order(
                    _ledger_with_completed_turn(root), backend.event_log_path)
            with backend.event_log_path.open('a') as stream:
                stream.write(json.dumps(stale) + '\n')
            report = runner.verify_formal_model_event_order(
                _ledger_with_completed_turn(root), backend.event_log_path)
            self.assertEqual(report['stale_summary_rows'], 1)

    def test_model_audit_is_set_before_route_and_gates_final_result(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'evaluation_tools').mkdir()
            (root / 'manifest').write_text('{}')
            contract = {
                'artifact': 'artifact', 'target_repository': 'target',
                'assertion_build_manifest': 'manifest',
                'codex_executable_sha256': 'a' * 64,
                'route_sha256': 'b' * 64, 'role_models': {},
                'default_model': 'synthetic-model', 'default_effort': 'high',
                'asan_symbolizer_sha256': 'c' * 64,
                'asan_symbolizer_libllvm_sha256': 'd' * 64,
                'normal_seeds': [], 'asan_binary': 'asan',
                'coverage_fuzzer': 'fuzzer',
                'run_command': ['asan', '{input}'],
                'assertion_run_command': ['{binary}', '{input}'],
                'assertion_build_command': ['build'],
                'assertion_seed': 'seed', 'runtime_sanitizers': ['address'],
                'sp_followup_crash_consumer_wall': {
                    'per_item_wall_seconds': 30,
                    'combined_wall_seconds': 60},
            }

            class ScriptedBackend:
                audit_method = 'thread/started'

                def __init__(self, **_kwargs):
                    self.event_log_path = None

                async def __aenter__(self):
                    log = self.event_log_path
                    assert log is not None and log.parent.is_dir()
                    assert log.parent.stat().st_mode & 0o777 == 0o700
                    row = {'method': self.audit_method, 'item_type': None,
                           'thread_id': 'thread-1', 'turn_id': '',
                           'server_request': False,
                           'params': {'threadId': 'thread-1',
                                      'thread': {'id': 'thread-1'}}}
                    log.write_text(json.dumps(row) + '\n')
                    log.chmod(0o600)
                    return self

                async def __aexit__(self, *_args):
                    return None

                async def verify_route(self):
                    return None

            async def fake_sequence(*_args, **_kwargs):
                return [{'status': 'COMPLETE'}]

            def run_case(method: str):
                ScriptedBackend.audit_method = method
                output = root / method.replace('/', '_')
                with patch.object(runner, 'HERE', root / 'evaluation_tools'), \
                     patch.object(runner, 'GuardedAppServer', ScriptedBackend), \
                     patch.object(runner, 'require_official_qualification',
                                  return_value={'status': 'QUALIFIED'}), \
                     patch.object(runner, 'enforce_asan_environment', return_value=''), \
                     patch.object(runner, 'verify_pinned_codex_executable',
                                  return_value=Path('/usr/bin/true')), \
                     patch.object(runner, 'verify_model_namespace_sandbox',
                                  return_value={}), \
                     patch.object(runner, '_protected_model_paths', return_value={}), \
                     patch.object(runner, 'resolve_reference_file',
                                  side_effect=lambda path: root / path), \
                     patch.object(runner, 'prepare_prior_corpus',
                                  return_value=root / 'prior'), \
                     patch.object(runner, 'run_phase1', return_value=root / 'run'), \
                     patch.object(runner, 'run_sequence', fake_sequence), \
                     patch.object(runner, 'build_provider_safety_report',
                                  return_value={}), \
                     patch.dict(os.environ, {'ASAN_SYMBOLIZER_PATH': '/synthetic'}):
                    return output, asyncio.run(runner._execute_live_with_cwd(
                        contract, output, root / 'empty-model-cwd'))

            output, result = run_case('thread/started')
            self.assertEqual(result, [{'status': 'COMPLETE'}])
            self.assertEqual(json.loads((output / 'MODEL_EVENT_AUDIT.json').read_text())[
                'status'], 'PASS_EVENT_LINEAGE')
            self.assertTrue((output / 'RUNNER_RESULT.json').is_file())

            with self.assertRaises(runner.FatalModelAuditFailure):
                run_case('command/exec')
            output = root / 'command_exec'
            self.assertEqual(json.loads((output / 'MODEL_EVENT_AUDIT.json').read_text())[
                'status'], 'HOLD_EVENT_AUDIT')
            self.assertFalse((output / 'RUNNER_RESULT.json').exists())
