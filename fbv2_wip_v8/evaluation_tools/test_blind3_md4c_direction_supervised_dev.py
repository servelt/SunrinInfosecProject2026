"""Provider-free checks for the one-turn official V2 Direction boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import blind3_md4c_direction_supervised_dev as boundary  # noqa: E402
from dev_global_appserver_bridge import artifact_hash  # noqa: E402


class OfficialDirectionBoundaryTests(unittest.TestCase):
    def test_official_sandbox_paths_include_target_once(self):
        paths = (Path('/reference'), Path('/product'), boundary.TARGET,
                 boundary.TARGET / '.git', Path('/evaluator'))

        class FakeRunner:
            @staticmethod
            def _protected_model_paths(_contract):
                return paths

        self.assertEqual(boundary._official_protected_paths(FakeRunner, {}),
                         paths)

        class DuplicateRunner:
            @staticmethod
            def _protected_model_paths(_contract):
                return (*paths, boundary.TARGET)

        with self.assertRaisesRegex(ValueError, 'duplicated'):
            boundary._official_protected_paths(DuplicateRunner, {})

    def test_direct_api_cannot_start_live_or_child(self):
        with patch.object(boundary, 'load_spec',
                          side_effect=AssertionError('spec reached')):
            with self.assertRaisesRegex(ValueError, 'external source pin'):
                boundary.run_supervised(Path('/missing'), '0' * 64)
            with self.assertRaisesRegex(ValueError, 'external source pin'):
                asyncio.run(boundary._run_child({}, '0' * 64))

    def test_parent_accepts_matching_receipt_then_rejects_phase1_mutation(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            spec_sha, context_sha = 'a' * 64, 'b' * 64
            pins = {'harness_sha256': 'c' * 64}
            pins_sha = boundary.digest(pins)
            policy = 'FBV2_FIRST_PASS_UNIQUE_DEV'

            def put(name, data):
                path = output / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = (json.dumps(data, sort_keys=True) + '\n').encode()
                path.write_bytes(raw)
                return hashlib.sha256(raw).hexdigest()

            plan_sha = put('direction/DIRECTION_PLAN.json', {'response': {}})
            request_body = {'role': 'direction_generator',
                            'instructions': 'synthetic', 'payload': {},
                            'output_schema': {}, 'model': 'synthetic',
                            'reasoning': 'high'}
            request_hash = artifact_hash(request_body)
            raw_body = {'directions': [], 'unknowns': []}
            request_file_sha = put('direction/DIRECTION_REQUEST.json',
                                   request_body)
            raw_file_sha = put('direction/DIRECTION_RAW.txt', raw_body)
            result_sha = put('direction/DIRECTION_PHASE1_RESULT.json', {
                'direction_plan_sha256': plan_sha,
                'direction_request_sha256': request_file_sha,
                'direction_raw_sha256': raw_file_sha,
                'selection_policy': policy, 'pool_count': 1})
            run_relative = 'direction/product_runs/synthetic-run'
            run_sha = put(run_relative + '/run.json', {
                'direction_plan_sha256': plan_sha,
                'selection_policy': policy})
            phase1_sha = {'run.json': run_sha, **{
                name: put(run_relative + '/' + name, {'synthetic': name})
                for name in ('function_pool.json', 'directions.json',
                             'selection.json', 'workers.json', 'harness.json',
                             'call_graph_audit.json')}}
            copied_plan_sha = put(
                run_relative + '/direction_plan.json', {'response': {}})
            self.assertEqual(copied_plan_sha, plan_sha)
            phase1_sha['direction_plan.json'] = copied_plan_sha
            pins_file_sha = put('direction/DIRECTION_INPUT_PINS.json', {
                'context_sha256': context_sha, 'pins': pins})
            ledger_sha = put(boundary.LEDGER_NAME, {
                'physical': 1, 'logical': 1, 'retries': 0,
                'active_turn': None,
                'turns': [{'role': 'direction_generator',
                           'status': 'COMPLETED', 'hash': request_hash}],
                'attempts': [{'status': 'COMPLETED', 'accepted': True,
                              'response_saved': True,
                              'request_hash': request_hash,
                              'app_server_turn_id': 'synthetic-turn'}]})
            event_path = output / 'MODEL_EVENTS.jsonl'
            event_path.write_bytes(b'{}\n')
            event_sha = hashlib.sha256(event_path.read_bytes()).hexdigest()
            receipt = {
                'spec_sha256': spec_sha, 'context_sha256': context_sha,
                'input_pins_sha256': pins_sha,
                'selection_policy': policy, 'hp_project_state_dev': False,
                'actual_provider_calls': 1, 'pool_count': 1,
                'physical': 1, 'logical': 1, 'retries': 0,
                'ledger_sha256': ledger_sha,
                'direction_request_hash': request_hash,
                'direction_request_file_sha256': request_file_sha,
                'direction_raw_file_sha256': raw_file_sha,
                'phase1_result_sha256': result_sha,
                'direction_plan_sha256': plan_sha,
                'phase1_run_relative': run_relative,
                'run_sha256': run_sha,
                'phase1_artifact_sha256': phase1_sha,
                'direction_input_file_sha256': pins_file_sha,
                'model_event_log_sha256': event_sha}
            receipt_sha = put(boundary.RECEIPT_NAME, receipt)
            child = {'status': 'OFFICIAL_V2_DIRECTION_PHASE1_COMPLETE',
                     'spec_sha256': spec_sha, 'context_sha256': context_sha,
                     'input_pins_sha256': pins_sha,
                     'receipt_sha256': receipt_sha,
                     'phase1_result_sha256': result_sha,
                     'direction_plan_sha256': plan_sha,
                     'direction_request_file_sha256': request_file_sha,
                     'direction_raw_file_sha256': raw_file_sha,
                     'phase1_artifact_sha256': phase1_sha,
                     'physical': 1, 'logical': 1, 'retries': 0}
            fd = boundary._open_output_dir(output)
            try:
                kwargs = {'expected_spec_sha256': spec_sha,
                          'expected_context_sha256': context_sha,
                          'expected_pins_sha256': pins_sha,
                          'expected_catalog_count': 1}
                self.assertTrue(boundary._completion_predicate(
                    child, fd, output, **kwargs))
                for name, original in (
                        ('DIRECTION_REQUEST.json', request_body),
                        ('DIRECTION_RAW.txt', raw_body)):
                    artifact = output / 'direction' / name
                    artifact.unlink()
                    self.assertFalse(boundary._completion_predicate(
                        child, fd, output, **kwargs), name + ' missing')
                    put('direction/' + name, original)
                    put('direction/' + name, {'changed': True})
                    self.assertFalse(boundary._completion_predicate(
                        child, fd, output, **kwargs), name + ' changed')
                    put('direction/' + name, original)
                # Even if all file-level hashes are rewritten consistently,
                # a different request body must not inherit the old ledger turn.
                modified_request = {**request_body, 'model': 'changed-model'}
                changed_request_sha = put('direction/DIRECTION_REQUEST.json',
                                          modified_request)
                changed_result_sha = put(
                    'direction/DIRECTION_PHASE1_RESULT.json', {
                        'direction_plan_sha256': plan_sha,
                        'direction_request_sha256': changed_request_sha,
                        'direction_raw_sha256': raw_file_sha,
                        'selection_policy': policy, 'pool_count': 1})
                changed_receipt = {**receipt,
                    'direction_request_file_sha256': changed_request_sha,
                    'phase1_result_sha256': changed_result_sha}
                changed_receipt_sha = put(boundary.RECEIPT_NAME,
                                          changed_receipt)
                changed_child = {**child,
                    'direction_request_file_sha256': changed_request_sha,
                    'phase1_result_sha256': changed_result_sha,
                    'receipt_sha256': changed_receipt_sha}
                self.assertFalse(boundary._completion_predicate(
                    changed_child, fd, output, **kwargs),
                    'changed request is not the completed ledger request')
                put('direction/DIRECTION_REQUEST.json', request_body)
                put('direction/DIRECTION_PHASE1_RESULT.json', {
                    'direction_plan_sha256': plan_sha,
                    'direction_request_sha256': request_file_sha,
                    'direction_raw_sha256': raw_file_sha,
                    'selection_policy': policy, 'pool_count': 1})
                put(boundary.RECEIPT_NAME, receipt)
                for name in ('direction_plan.json', 'harness.json',
                             'call_graph_audit.json'):
                    artifact = output / run_relative / name
                    artifact.unlink()
                    self.assertFalse(boundary._completion_predicate(
                        child, fd, output, **kwargs), name + ' missing')
                    original = ({'response': {}} if name == 'direction_plan.json'
                                else {'synthetic': name})
                    put(run_relative + '/' + name, original)
                    put(run_relative + '/' + name, {'synthetic': 'changed'})
                    self.assertFalse(boundary._completion_predicate(
                        child, fd, output, **kwargs), name + ' changed')
                    put(run_relative + '/' + name, original)
                for name in ('function_pool.json', 'directions.json',
                             'selection.json', 'workers.json'):
                    artifact = output / run_relative / name
                    artifact.unlink()
                    self.assertFalse(boundary._completion_predicate(
                        child, fd, output, **kwargs), name + ' missing')
                    put(run_relative + '/' + name, {'synthetic': name})
                    put(run_relative + '/' + name, {'synthetic': 'changed'})
                    self.assertFalse(boundary._completion_predicate(
                        child, fd, output, **kwargs), name + ' changed')
                    put(run_relative + '/' + name, {'synthetic': name})
                altered_plan_sha = put(run_relative + '/direction_plan.json',
                                       {'response': {'altered': True}})
                altered_manifest = {**phase1_sha,
                                    'direction_plan.json': altered_plan_sha}
                altered_receipt = {**receipt,
                                   'phase1_artifact_sha256': altered_manifest}
                altered_receipt_sha = put(boundary.RECEIPT_NAME, altered_receipt)
                altered_child = {**child,
                                 'phase1_artifact_sha256': altered_manifest,
                                 'receipt_sha256': altered_receipt_sha}
                self.assertFalse(boundary._completion_predicate(
                    altered_child, fd, output, **kwargs),
                    'run plan copy differs from pinned Direction plan')
                put(run_relative + '/direction_plan.json', {'response': {}})
                put(boundary.RECEIPT_NAME, receipt)
                (output / run_relative / 'extra.json').write_text('{}')
                self.assertFalse(boundary._completion_predicate(
                    child, fd, output, **kwargs), 'unregistered output file')
                (output / run_relative / 'extra.json').unlink()
                put(run_relative + '/run.json', {'selection_policy': 'SCORE'})
                self.assertFalse(boundary._completion_predicate(
                    child, fd, output, **kwargs))
            finally:
                import os
                os.close(fd)

    def test_direct_live_cannot_bypass_external_source_pin(self):
        started = subprocess.run(
            ['/usr/bin/python3.12', '-I', '-B', str(Path(boundary.__file__)),
             '--run-live', '/missing/spec.json', '0' * 64],
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(started.returncode, 0)
        self.assertIn('external source pin', started.stderr)

    def test_real_official_v2_preflight_has_zero_model_or_ledger_files(self):
        with TemporaryDirectory() as temporary:
            review = Path(temporary)
            with patch.object(boundary, 'REVIEW', review):
                output = review / 'new-private-output'
                spec, digest = boundary.prepare(output,
                    source_mode='all_catalog_prefix')
                row = boundary.load_spec(spec, digest)
                check = boundary.offline_preflight(row)
            self.assertEqual(check['status'], 'PREFLIGHT_PASS_NO_MODEL_CALL')
            self.assertEqual(check['actual_provider_calls'], 0)
            self.assertEqual(check['source_mode'], 'all_catalog_prefix')
            self.assertGreater(check['catalog_count'], 0)
            self.assertFalse((output / boundary.LEDGER_NAME).exists())
            self.assertFalse((output / 'MODEL_EVENTS.jsonl').exists())
            self.assertFalse((output / boundary.CHILD_NAME).exists())

    def test_changed_source_context_pin_rejected_before_model(self):
        with TemporaryDirectory() as temporary:
            review = Path(temporary)
            with patch.object(boundary, 'REVIEW', review):
                spec, digest = boundary.prepare(
                    review / 'new-private-output',
                    source_mode='all_catalog_prefix')
                real_context = boundary._source_context

                def changed(mode):
                    context, pins = real_context(mode)
                    pins['harness_sha256'] = '0' * 64
                    return context, pins

                with patch.object(boundary, '_source_context',
                                  side_effect=changed):
                    with self.assertRaisesRegex(ValueError, 'V2 input pin'):
                        boundary.load_spec(spec, digest)
            self.assertFalse((review / 'new-private-output' /
                              boundary.LEDGER_NAME).exists())

    def test_receipt_without_matching_ledger_cannot_pass_supervisor(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            receipt = {'status': 'OFFICIAL_V2_DIRECTION_PHASE1_COMPLETE',
                       'spec_sha256': 'a' * 64,
                       'phase1_result_sha256': 'b' * 64,
                       'direction_plan_sha256': 'c' * 64,
                       'physical': 1, 'logical': 1, 'retries': 0}
            (output / boundary.CHILD_NAME).write_text(json.dumps(receipt))
            fd = boundary._open_output_dir(output)
            try:
                self.assertFalse(boundary._completion_predicate(
                    receipt, fd, output, expected_spec_sha256='a' * 64,
                    expected_context_sha256='d' * 64,
                    expected_pins_sha256='e' * 64,
                    expected_catalog_count=1))
            finally:
                import os
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
