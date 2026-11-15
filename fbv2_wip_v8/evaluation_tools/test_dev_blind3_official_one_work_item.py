"""Provider-free checks for the official one-job supervised bridge."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import dev_blind3_official_one_work_item as bridge  # noqa: E402

BUDGET = {'physical_max': 4, 'logical_max': 4, 'retries_max': 0,
          'wall_seconds': 1200, 'initial_starts_required': 2}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class OfficialOneWorkItemProviderFreeTests(unittest.TestCase):
    def setUp(self):
        self.output = ROOT / 'review' / f'REVIEW_ONE_JOB_{uuid4().hex}'
        self.addCleanup(shutil.rmtree, self.output, ignore_errors=True)

    def prepared(self):
        # These preparation tests ran before the one-time Stage 7 live arm.
        # Its immutable first_run now exists. Do not move that evidence or
        # weaken production load_spec pins just to replay a pre-start test.
        source = json.loads(bridge.FRESH_RECEIPT.read_text())['source_run']
        if (Path(source).parent / 'stage7-one-work-item').exists():
            self.skipTest('Stage 7 historical one-time first_run already exists; '
                          'fresh Stage 8 preparation covers this boundary')
        return bridge.prepare(self.output, BUDGET)

    def test_preflight_uses_official_v2_without_model_or_target(self):
        spec, digest = self.prepared()
        result = subprocess.run(
            ['/usr/bin/python3.12', '-I', '-B', str(TOOLS /
                'dev_blind3_official_one_work_item.py'), '--preflight-only',
             str(spec), digest], text=True, capture_output=True,
            timeout=30, check=True)
        row = json.loads(result.stdout)
        self.assertEqual(row['status'], 'OFFICIAL_PREFLIGHT_PASS_NO_MODEL_CALL')
        self.assertTrue(row['official_v2_qualified'])
        self.assertEqual((row['actual_model_calls'], row['target_runs'],
                          row['fuzz_seconds']), (0, 0, 0))
        saved = json.loads(spec.read_text(encoding='utf-8'))
        self.assertIn('NO_TARGET_BINARY_OR_FUZZER',
                      saved['execution_boundary'])
        self.assertIn('compiler helpers may execute',
                      saved['execution_boundary'])
        self.assertEqual(row['worklist_sha256'], bridge.sha(
            bridge.FRESH_RECEIPT.parent / 'md4c_development_worklist.json'))
        self.assertFalse(Path(bridge.load_spec(spec, digest)['first_run']).exists())
        self.assertFalse((self.output / bridge.MODEL_NAME).exists())
        self.assertFalse((self.output / bridge.PHYSICAL_NAME).exists())

    def test_source_pin_drift_rejected_before_helper_import(self):
        spec, digest = self.prepared()
        real = bridge._file_pins
        def changed(source, worklist):
            rows = real(source, worklist)
            name = next(k for k in rows if k.endswith('/workers.json'))
            rows[name] = '0' * 64
            return rows
        with patch.object(bridge, '_file_pins', side_effect=changed), patch.object(
                bridge, '_base', side_effect=AssertionError('helper imported')):
            with self.assertRaisesRegex(ValueError, 'source, code or worklist'):
                bridge.load_spec(spec, digest)

    def test_code_pin_drift_rejected_before_helper_import(self):
        spec, digest = self.prepared()
        real = bridge._code_pins
        def changed():
            rows = real()
            rows['product_src'] = '0' * 64
            return rows
        with patch.object(bridge, '_code_pins', side_effect=changed), patch.object(
                bridge, '_full', side_effect=AssertionError('helper imported')):
            with self.assertRaisesRegex(ValueError, 'code changed before'):
                bridge.load_spec(spec, digest)

    def test_external_sha_bootstrap_required_before_live_launch(self):
        spec, digest = self.prepared()
        with self.assertRaisesRegex(ValueError, 'externally pinned'):
            bridge.run_supervised(spec, digest)
        self.assertFalse((self.output / 'supervisor.log').exists())

    def test_missing_or_partial_event_log_preserves_physical_stop(self):
        events = self.output / 'MODEL_EVENTS.jsonl'
        state, digest = bridge._model_event_evidence(
            events, 'STOPPED_CLEANUP_INCOMPLETE')
        self.assertEqual((state, digest), ('MISSING_INCOMPLETE', None))
        with self.assertRaisesRegex(ValueError, 'no model event log'):
            bridge._model_event_evidence(events, 'SCAN_RECORDED')
        self.output.mkdir(mode=0o700)
        raw = b'{"method":"turn/started"}\n'
        events.write_bytes(raw)
        self.assertEqual(bridge._model_event_evidence(
            events, 'STOPPED_CLEANUP_INCOMPLETE'),
            ('PRESENT_INCOMPLETE', _sha(raw)))

    def test_fifo_receipt_cannot_block_parent_completion(self):
        self.output.mkdir(mode=0o700)
        os.mkfifo(self.output / bridge.RECEIPT_NAME)
        script = (
            'import os,pathlib,sys; sys.path.insert(0,sys.argv[1]); '
            'import dev_blind3_official_one_work_item as b; '
            'out=pathlib.Path(sys.argv[2]); '
            'fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY); '
            'child={"kind":b.KIND,"status":"ONE_WORK_ITEM_MODEL_TRACE_RECORDED",'
            '"spec_sha256":"a"*64,"model_events_state":"VERIFIED_COMPLETE",'
            '"target_runs":0,"fuzz_seconds":0,"model_physical_starts":2}; '
            'row={"worklist_sha256":"b"*64}; '
            'exec("try:\\n b._completion(child,fd,out,\\\"a\\\"*64,row)\\n'
            'except ValueError:\\n print(\\\"REJECTED_NONREGULAR\\\")")')
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', script, str(TOOLS),
             str(self.output)], text=True, capture_output=True,
            timeout=3, check=True)
        self.assertIn('REJECTED_NONREGULAR', result.stdout)

    def test_supervisor_completion_checks_separate_ledgers_and_stop(self):
        from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
        self.output.mkdir(mode=0o700)
        os.chmod(self.output, 0o700)
        event = b'{"method":"turn/completed"}\n'
        model_row = {'physical': 2, 'direction_counts': {},
                     'selected_functions': ['work-item-1'],
                     'function_states': {'work-item-1': 'SCAN_RECORDED'},
                     'tainted': False, 'active_turn': None,
                     'turns': [
                         {'id': 'L000001', 'scope_id': 'work-item-1',
                          'status': 'COMPLETED', 'role': 'sp_generation'},
                         {'id': 'L000002', 'scope_id': 'work-item-1',
                          'status': 'COMPLETED', 'role': 'function_analysis'}],
                     'attempts': [
                         {'turn_id': 'L000001', 'role': 'sp_generation',
                          'status': 'COMPLETED', 'app_server_turn_id': 't1'},
                         {'turn_id': 'L000002', 'role': 'function_analysis',
                          'status': 'COMPLETED', 'app_server_turn_id': 't2'}]}
        model = json.dumps(model_row).encode()
        (self.output / 'MODEL_EVENTS.jsonl').write_bytes(event)
        (self.output / bridge.MODEL_NAME).write_bytes(model)
        physical_ledger = PersistentPhysicalFuzzLedger.create(
            self.output / bridge.PHYSICAL_NAME, total_seconds=1200)

        def receipt_and_child():
            digests = {'model_ledger_sha256': _sha((self.output /
                            bridge.MODEL_NAME).read_bytes()),
                       'physical_ledger_sha256': _sha((self.output /
                            bridge.PHYSICAL_NAME).read_bytes()),
                       'model_events_sha256': _sha(event)}
            receipt = {'status': 'SCAN_RECORDED', 'analysis_complete': True,
                       'official_v2_qualified': True, 'spec_sha256': 'a' * 64,
                       'model_physical_starts': 2, 'target_runs': 0,
                       'fuzz_seconds': 0,
                       'work_item_id': 'work-item-1',
                       'worklist_sha256': 'b' * 64,
                       'execution_boundary': ('NO_TARGET_BINARY_OR_FUZZER; '
                           'protected input-generator/compiler helpers may execute'),
                       'model_events_state': 'VERIFIED_COMPLETE',
                       'model_audit_failed': False,
                       'direction_source':
                           'SAVED_MODEL_PLAN_NOT_NEW_MODEL_START', **digests}
            raw = (json.dumps(receipt) + '\n').encode()
            (self.output / bridge.RECEIPT_NAME).write_bytes(raw)
            return {'kind': bridge.KIND,
                    'status': 'ONE_WORK_ITEM_MODEL_TRACE_RECORDED',
                    'spec_sha256': 'a' * 64,
                    'target_runs': 0, 'fuzz_seconds': 0,
                    'model_physical_starts': 2,
                    'model_events_state': 'VERIFIED_COMPLETE',
                    'receipt_sha256': _sha(raw), **digests}

        fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        child = receipt_and_child()
        row = {'worklist_sha256': 'b' * 64,
               'execution_boundary': ('NO_TARGET_BINARY_OR_FUZZER; '
                   'protected input-generator/compiler helpers may execute'),
               'output_dir': str(self.output), 'physical_resource_seconds': 1200}
        with patch.object(bridge, '_verified_parent_trace', return_value=True):
            self.assertTrue(bridge._completion(child, fd, self.output,
                                               'a' * 64, row))
        model_row['attempts'][1]['status'] = 'ERROR'
        (self.output / bridge.MODEL_NAME).write_text(json.dumps(model_row))
        child = receipt_and_child()
        with patch.object(bridge, '_verified_parent_trace', return_value=True):
            self.assertFalse(bridge._completion(child, fd, self.output,
                                                'a' * 64, row))
        model_row['attempts'][1]['status'] = 'COMPLETED'
        (self.output / bridge.MODEL_NAME).write_text(json.dumps(model_row))
        physical_ledger.reserve('test-stop', 'SP', 1)
        physical_ledger.finish('test-stop', physical_seconds=0,
                               cleanup_complete=False)
        child = receipt_and_child()
        with patch.object(bridge, '_verified_parent_trace', return_value=True):
            self.assertFalse(bridge._completion(child, fd, self.output,
                                                'a' * 64, row))

    def test_parent_trace_rejects_late_scan_change_and_hp_error(self):
        from dev_no_k_three_function_gate import make_public_fixture
        from dev_fbv2_four_phase_worklist import build_from_pinned_run
        from vulnerabilityanalysis.workflow import (run_phase1,
            start_four_phase_dev, validate_four_phase_dev_selection,
            write_four_phase_terminal_marker)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, repo, plan = make_public_fixture(root / 'fixture')
            source = run_phase1(artifact, repo / 'runs',
                target_repository=repo, direction_plan=plan,
                selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            work = root / 'WORKLIST.json'
            work.write_text(json.dumps(build_from_pinned_run(source),
                                       sort_keys=True) + '\n')
            run = start_four_phase_dev(source, work, bridge.sha(work),
                                       repo / 'runs/first')
            run_row, selection, item = validate_four_phase_dev_selection(run)
            scan = {'four_phase_work_item_id': item['work_item_id'],
                    'selected_function_id': selection['function_id'],
                    'pending_sp_ids': [],
                    'assertion_execution': {'status': 'DISABLED'},
                    'assertion_generation_status': 'NOT_SCHEDULED_NO_SAFE_ASSUMPTION'}
            scan_path = run / 'scan.json'
            scan_path.write_text(json.dumps(scan, sort_keys=True) + '\n')
            write_four_phase_terminal_marker(run, run_row, item)
            row = {'first_run': str(run), 'output_dir': str(root),
                   'global_budget': BUDGET}
            receipt = {'scan_sha256': bridge.sha(scan_path),
                       'terminal_sha256': bridge.sha(run /
                           'four_phase_scan_complete.json'),
                       'work_item_id': item['work_item_id'],
                       'selected_function_id': selection['function_id']}
            scan['late_change'] = True
            scan_path.write_text(json.dumps(scan, sort_keys=True) + '\n')
            self.assertFalse(bridge._verified_parent_trace(row, receipt))
            (run / 'four_phase_scan_complete.json').unlink()
            scan.pop('late_change')
            scan['hp_error'] = {'type': 'TimeoutError'}
            scan_path.write_text(json.dumps(scan, sort_keys=True) + '\n')
            write_four_phase_terminal_marker(run, run_row, item)
            receipt['scan_sha256'] = bridge.sha(scan_path)
            receipt['terminal_sha256'] = bridge.sha(run /
                'four_phase_scan_complete.json')
            with self.assertRaisesRegex(ValueError, 'pending or incomplete'):
                bridge._verified_parent_trace(row, receipt)
if __name__ == '__main__':
    unittest.main()
