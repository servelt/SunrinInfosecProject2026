"""Provider-free checks for the separate official V2 PoV budget probe."""

import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, '/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
import dev_blind3_official_pov_probe as probe  # noqa: E402
import dev_blind3_official_one_work_item as stage7  # noqa: E402


class OfficialPovProbeProviderFreeTests(unittest.TestCase):
    def setUp(self):
        self.output = ROOT / 'review' / f'REVIEW_STAGE8_POV_{uuid4().hex}'
        self.addCleanup(shutil.rmtree, self.output, ignore_errors=True)

    def prepared(self):
        if (probe.FRESH_RECEIPT.parent / 'product_runs' /
                'stage8-pov-budget-probe').exists():
            # The real one-time run is historical evidence. Exercise fresh
            # preparation against an independent, provider-free Phase 1.
            from dev_fbv2_four_phase_worklist import build_from_pinned_run
            from vulnerabilityanalysis.workflow import run_phase1
            fixture = ROOT / 'review' / f'REVIEW_STAGE8_PHASE1_{uuid4().hex}'
            fixture.mkdir(mode=0o700)
            self.addCleanup(shutil.rmtree, fixture, ignore_errors=True)
            source = run_phase1(
                probe.ARTIFACT, fixture / 'product_runs',
                target_repository=probe.TARGET,
                direction_plan=probe.SAVED_DIRECTION / 'DIRECTION_PLAN.json',
                selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            worklist = fixture / 'md4c_development_worklist.json'
            worklist.write_text(json.dumps(build_from_pinned_run(source),
                                           sort_keys=True, indent=2) + '\n')
            receipt = json.loads(probe.FRESH_RECEIPT.read_text())
            receipt.update(source_run=str(source), worklist_path=str(worklist),
                           worklist_sha256=probe.sha(worklist),
                           direction_plan_sha256=probe.sha(
                               source / 'direction_plan.json'))
            fresh = fixture / 'STAGE8_PROVIDER_FREE_RECEIPT.json'
            fresh.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
            self.fixture_receipt = fresh
            for name, value in (('FRESH_RECEIPT', fresh),
                                ('FRESH_RECEIPT_SHA', probe.sha(fresh))):
                patcher = patch.object(probe, name, value)
                patcher.start()
                self.addCleanup(patcher.stop)
        return probe.prepare(self.output, dict(probe.PROBE_BUDGET))

    def test_fresh_phase1_preserves_stage7_and_pins_separate_job(self):
        stage7_bytes = stage7.sha(Path(stage7.__file__))
        spec, digest = self.prepared()
        row = probe.load_spec(spec, digest)
        self.assertEqual(row['kind'], probe.KIND)
        self.assertEqual(row['global_budget'], probe.PROBE_BUDGET)
        self.assertEqual(row['source_run'], json.loads(
            probe.FRESH_RECEIPT.read_text())['source_run'])
        self.assertEqual(row['worklist_sha256'], probe.sha(
            probe.FRESH_RECEIPT.parent / 'md4c_development_worklist.json'))
        self.assertIn('/stage8-pov-budget-probe', row['first_run'])
        self.assertFalse(Path(row['first_run']).exists())
        self.assertEqual(stage7.sha(Path(stage7.__file__)), stage7_bytes)
        self.assertNotEqual(row['source_run'], json.loads(
            stage7.FRESH_RECEIPT.read_text())['source_run'])
        for name in (probe.MODEL_NAME, probe.PHYSICAL_NAME,
                     'MODEL_EVENTS.jsonl'):
            self.assertFalse((self.output / name).exists())

    def test_exact_predeclared_budget_and_external_bootstrap(self):
        wrong = dict(probe.PROBE_BUDGET, physical_max=8)
        with self.assertRaisesRegex(ValueError, 'predeclared exact budget'):
            probe.prepare(self.output, wrong)
        spec, digest = self.prepared()
        with self.assertRaisesRegex(ValueError, 'externally pinned'):
            probe.run_supervised(spec, digest)
        self.assertFalse((self.output / 'supervisor.log').exists())

    def test_official_preflight_uses_no_model_or_target(self):
        spec, digest = self.prepared()
        if hasattr(self, 'fixture_receipt'):
            script = (
                'import json,sys; from pathlib import Path; '
                'sys.path.insert(0,sys.argv[1]); '
                'import dev_blind3_official_pov_probe as p; '
                'p.FRESH_RECEIPT=Path(sys.argv[2]); '
                'p.FRESH_RECEIPT_SHA=sys.argv[3]; '
                'row=p.load_spec(Path(sys.argv[4]),sys.argv[5]); '
                'print(json.dumps(p.offline_preflight(row)))')
            command = ['/usr/bin/python3.12', '-I', '-B', '-c', script,
                       str(TOOLS), str(self.fixture_receipt),
                       probe.sha(self.fixture_receipt), str(spec), digest]
        else:
            command = ['/usr/bin/python3.12', '-I', '-B', str(TOOLS /
                'dev_blind3_official_pov_probe.py'), '--preflight-only',
                str(spec), digest]
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=30, check=True)
        row = json.loads(result.stdout)
        self.assertEqual(row['status'], 'OFFICIAL_PREFLIGHT_PASS_NO_MODEL_CALL')
        self.assertTrue(row['official_v2_qualified'])
        self.assertEqual((row['actual_model_calls'], row['target_runs'],
                          row['fuzz_seconds']), (0, 0, 0))

    def test_source_pin_drift_rejected_before_helper_import(self):
        spec, digest = self.prepared()
        actual = probe._file_pins
        def changed(source, worklist):
            files = actual(source, worklist)
            key = next(name for name in files if name.endswith('/workers.json'))
            files[key] = '0' * 64
            return files
        with patch.object(probe, '_file_pins', side_effect=changed), patch.object(
                probe, '_base', side_effect=AssertionError('helper imported')):
            with self.assertRaisesRegex(ValueError, 'source, code or worklist'):
                probe.load_spec(spec, digest)

    @staticmethod
    def model_row(*, pov=True):
        roles = ['sp_generation', 'function_analysis', 'sp_verifier']
        if pov:
            roles.append('poc_generator')
        turns = [{'id': f'L{i:06d}', 'scope_id': 'work-1', 'role': role,
                  'status': 'COMPLETED'} for i, role in enumerate(roles, 1)]
        attempts = [{'turn_id': turn['id'], 'role': turn['role'],
                     'scope_id': 'work-1', 'status': 'COMPLETED',
                     'accepted': True, 'response_saved': True,
                     'retry': False, 'internal_retry': False,
                     'app_server_turn_id': f'T{i}'}
                    for i, turn in enumerate(turns, 1)]
        return {'physical': len(roles), 'logical': len(roles),
                'direction_counts': {}, 'selected_functions': ['work-1'],
                'function_states': {'work-1': 'SELECTED_NOT_STARTED'},
                'tainted': False, 'active_turn': None,
                'turns': turns, 'attempts': attempts}

    @classmethod
    def model_row_seven(cls):
        # Frozen Stage 8 shape: one generator, three HP analysis turns,
        # two verifiers and the seventh accepted/saved PoV turn.
        model = cls.model_row()
        roles = ['sp_generation', 'function_analysis', 'function_analysis',
                 'function_analysis', 'sp_verifier', 'sp_verifier',
                 'poc_generator']
        model['turns'] = [
            {'id': f'L{i:06d}', 'scope_id': 'work-1', 'role': role,
             'status': 'COMPLETED'} for i, role in enumerate(roles, 1)]
        model['attempts'] = [
            {'turn_id': turn['id'], 'role': turn['role'],
             'scope_id': 'work-1', 'status': 'COMPLETED',
             'accepted': True, 'response_saved': True, 'retry': False,
             'internal_retry': False, 'app_server_turn_id': f'T{i}'}
            for i, turn in enumerate(model['turns'], 1)]
        model['physical'] = model['logical'] = 7
        return model

    def test_no_pov_cannot_claim_component_completion(self):
        self.assertFalse(probe._completed_pov_chain(self.model_row(pov=False),
                                                     'work-1'))
        self.assertTrue(probe._completed_pov_chain(self.model_row(), 'work-1'))
        unsaved = self.model_row()
        unsaved['attempts'][-1]['response_saved'] = False
        self.assertFalse(probe._completed_pov_chain(unsaved, 'work-1'))
        retried = self.model_row()
        retried['attempts'][-1]['retry'] = True
        self.assertFalse(probe._completed_pov_chain(retried, 'work-1'))

    def test_frozen_seven_turn_shape_has_saved_pov_and_no_tainted_key(self):
        model = self.model_row_seven()
        model.pop('tainted')  # The durable checkpoint has no such field.
        self.assertTrue(probe._completed_pov_chain(model, 'work-1'))
        model['attempts'][-1]['response_saved'] = False
        self.assertFalse(probe._completed_pov_chain(model, 'work-1'))

    def test_target_blocked_after_pov_is_component_only_success(self):
        from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
        self.output.mkdir(mode=0o700)
        physical = PersistentPhysicalFuzzLedger.create(
            self.output / probe.PHYSICAL_NAME, total_seconds=1200)
        events = b'{"method":"turn/completed"}\n'
        (self.output / 'MODEL_EVENTS.jsonl').write_bytes(events)
        model = self.model_row_seven()
        (self.output / probe.MODEL_NAME).write_text(json.dumps(model))

        def child(status='INCOMPLETE_TARGET_EXECUTION_FORBIDDEN'):
            blocked = status == 'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN'
            digests = {
                'model_ledger_sha256': probe.sha(self.output / probe.MODEL_NAME),
                'physical_ledger_sha256': probe.sha(self.output / probe.PHYSICAL_NAME),
                'model_events_sha256': hashlib.sha256(events).hexdigest(),
            }
            receipt = {'kind': probe.KIND,
                       'status': status,
                       'component_status': 'POV_MODEL_REACHED_NO_TARGET',
                       'stopped_before_target': blocked,
                       'analysis_complete': False,
                       'official_v2_qualified': True,
                       'spec_sha256': 'a' * 64,
                       'execution_boundary': ('NO_TARGET_BINARY_OR_FUZZER; '
                           'protected input-generator/compiler helpers may execute'),
                       'model_events_state': 'PRESENT_INCOMPLETE',
                       'model_audit_failed': False,
                       'worklist_sha256': 'b' * 64,
                       'work_item_id': 'work-1',
                       'model_physical_starts': model['physical'],
                       'target_runs': 0, 'fuzz_seconds': 0,
                       'direction_source': 'SAVED_MODEL_PLAN_NOT_NEW_MODEL_START',
                       **digests}
            raw = (json.dumps(receipt) + '\n').encode()
            (self.output / probe.RECEIPT_NAME).write_bytes(raw)
            return {'kind': probe.KIND,
                    'status': 'POV_MODEL_REACHED_NO_TARGET',
                    'stopped_before_target': blocked,
                    'spec_sha256': 'a' * 64,
                    'model_events_state': 'PRESENT_INCOMPLETE',
                    'model_physical_starts': model['physical'],
                    'target_runs': 0, 'fuzz_seconds': 0,
                    'receipt_sha256': hashlib.sha256(raw).hexdigest(),
                    **digests}

        fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        row = {'worklist_sha256': 'b' * 64,
               'execution_boundary': ('NO_TARGET_BINARY_OR_FUZZER; '
                   'protected input-generator/compiler helpers may execute'),
               'output_dir': str(self.output), 'physical_resource_seconds': 1200}
        with patch.object(probe, '_verified_parent_trace', return_value=True):
            self.assertTrue(probe._completion(child(), fd, self.output,
                                               'a' * 64, row))
        model = self.model_row(pov=False)
        # Keep four accepted physical turns, replacing PoV with another HP
        # turn so this tests the PoV predicate rather than the count floor.
        model['turns'].append({'id': 'L000004', 'scope_id': 'work-1',
                               'role': 'function_analysis',
                               'status': 'COMPLETED'})
        model['attempts'].append({
            'turn_id': 'L000004', 'role': 'function_analysis',
            'scope_id': 'work-1', 'status': 'COMPLETED', 'accepted': True,
            'response_saved': True, 'retry': False,
            'internal_retry': False, 'app_server_turn_id': 'T4'})
        model['physical'] = model['logical'] = 4
        (self.output / probe.MODEL_NAME).write_text(json.dumps(model))
        with patch.object(probe, '_verified_parent_trace', return_value=True):
            self.assertFalse(probe._completion(child(), fd, self.output,
                                                'a' * 64, row))
        model = self.model_row_seven()
        model.pop('tainted')
        (self.output / probe.MODEL_NAME).write_text(json.dumps(model))
        with patch.object(probe, '_verified_parent_trace', return_value=True):
            self.assertTrue(probe._completion(
                child('INCOMPLETE_PENDING_WORK'), fd, self.output,
                'a' * 64, row))
        model['attempts'][-1]['response_saved'] = False
        (self.output / probe.MODEL_NAME).write_text(json.dumps(model))
        with patch.object(probe, '_verified_parent_trace', return_value=True):
            self.assertFalse(probe._completion(
                child('INCOMPLETE_PENDING_WORK'), fd, self.output,
                'a' * 64, row))

    def test_partial_parent_trace_rechecks_requests_and_rejects_tool_event(self):
        from dev_global_appserver_bridge import artifact_hash
        self.output.mkdir(mode=0o700)
        run = self.output / 'run'
        (run / 'logs').mkdir(parents=True)
        model = self.model_row_seven()
        artifacts = []
        for index, turn in enumerate(model['turns'], 1):
            artifact = {'role': turn['role'], 'instructions': 'toy arithmetic',
                        'payload': {'value': index}, 'output_schema': {},
                        'model': 'toy-model', 'reasoning': 'high'}
            turn['hash'] = artifact_hash(artifact)
            path = run / 'logs' / f'request-{index}.json'
            path.write_text(json.dumps(artifact))
            artifacts.append(path)
        (self.output / probe.MODEL_NAME).write_text(json.dumps(model))
        (run / 'logs/agent_requests.jsonl').write_text(''.join(
            json.dumps({'request_artifact': str(path)}) + '\n'
            for path in artifacts))
        rows = [{'method': 'turn/completed',
                 'turn_id': attempt['app_server_turn_id'],
                 'thread_id': 'toy-thread', 'item_type': None,
                 'server_request': False,
                 'params': {'threadId': 'toy-thread',
                            'turn': {'id': attempt['app_server_turn_id'],
                                     'status': 'completed'}}}
                for attempt in model['attempts']]
        events = self.output / 'MODEL_EVENTS.jsonl'
        events.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        ledger = SimpleNamespace(checkpoint_path=self.output / probe.MODEL_NAME,
                                 turns=model['turns'], attempts=model['attempts'],
                                 tainted=False, active_turn=None)
        receipt = {'status': 'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN',
                   'analysis_complete': False, 'stopped_before_target': True,
                   'model_events_state': 'PRESENT_INCOMPLETE',
                   'work_item_id': 'work-1', 'selected_function_id': 'fn',
                   'scan_sha256': None, 'terminal_sha256': None}
        row = {'first_run': str(run), 'output_dir': str(self.output),
               'global_budget': probe.PROBE_BUDGET}
        with patch('vulnerabilityanalysis.workflow.validate_four_phase_dev_selection',
                   return_value=({'run_id': 'run'}, {'function_id': 'fn'},
                                 {'work_item_id': 'work-1'})), patch(
                     'dev_global_request_ledger.DevelopmentRequestLedger.restore',
                     return_value=ledger):
            self.assertTrue(probe._verified_parent_trace(row, receipt))
            scan_path = run / 'scan.json'
            marker_path = run / 'four_phase_scan_complete.json'
            scan = {'four_phase_work_item_id': 'work-1',
                    'selected_function_id': 'fn', 'poc_count': 1,
                    'pending_sp_ids': [f'sp-{i}' for i in range(5)]}
            scan_path.write_text(json.dumps(scan))
            marker_path.write_text('{}')
            receipt.update(status='INCOMPLETE_PENDING_WORK',
                           stopped_before_target=False,
                           scan_sha256=probe.sha(scan_path),
                           terminal_sha256=probe.sha(marker_path))
            with patch('vulnerabilityanalysis.workflow.verify_four_phase_terminal_marker',
                       return_value={'status': 'partial'}):
                self.assertTrue(probe._verified_parent_trace(row, receipt))
                scan_path.unlink()
                self.assertFalse(probe._verified_parent_trace(row, receipt))
                scan_path.write_text(json.dumps(scan))
                scan['pending_sp_ids'] = []
                scan_path.write_text(json.dumps(scan))
                receipt['scan_sha256'] = probe.sha(scan_path)
                self.assertFalse(probe._verified_parent_trace(row, receipt))
            scan_path.unlink()
            marker_path.unlink()
            receipt.update(status='INCOMPLETE_TARGET_EXECUTION_FORBIDDEN',
                           stopped_before_target=True,
                           scan_sha256=None, terminal_sha256=None)
            forbidden = {'method': 'commandExecution/started',
                         'thread_id': '', 'turn_id': '', 'item_type': None,
                         'server_request': False, 'params': {}}
            events.write_text(json.dumps(forbidden) + '\n' + ''.join(
                json.dumps(item) + '\n' for item in rows))
            with self.assertRaisesRegex(ValueError, 'tool or server'):
                probe._verified_parent_trace(row, receipt)
            events.write_text('{bad json\n')
            with self.assertRaises(json.JSONDecodeError):
                probe._verified_parent_trace(row, receipt)


if __name__ == '__main__':
    unittest.main()
