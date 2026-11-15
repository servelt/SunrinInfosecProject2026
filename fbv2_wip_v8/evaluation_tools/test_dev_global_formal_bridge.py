"""Provider-free public-toy calls through the actual run_sequence loop."""

from __future__ import annotations

import asyncio
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import blind2_runner_draft as runner
import dev_global_campaign as global_dev
import dev_global_formal_bridge as formal_dev
from vulnerabilityanalysis.runtime import RuntimeCleanupError

sys.path.insert(0, str(runner.PRODUCT / 'tests'))
import test_fuzzer_crash_consumer as product_crash_tests
import test_official_v2_contract as product_v2_tests


class Provider:
    def __init__(self, ledger):
        self.ledger = ledger
        self.function_id = None

    def begin_function(self, function_id):
        self.function_id = function_id

    def end_function(self):
        self.function_id = None


class SyntheticCampaign:
    def __init__(self, root: Path):
        self.output = root / 'dev-output'
        self.budget = global_dev.SharedPhysicalFuzzBudget(10)
        self.final_result = None
        self.function_windows = []
        self.global_seconds = 1
        self.global_wall_reservation_seconds = 3
        self.aborted = 0

    def start(self):
        return 'ACTIVE'

    def abort(self):
        self.aborted += 1
        return {'status': 'STOPPED_ABORTED', 'cleanup_complete': True}

    def finish(self):
        return {'status': 'RAN', 'cleanup_complete': True}


def safe_campaign(root: Path, *, total: float = 50,
                  reservation: float = 18) -> tuple[global_dev.DevGlobalCampaign, object]:
    target = 'int target_operation(int marker) { (void)marker; return 0; }\n'
    with patch.object(product_crash_tests, 'OFFICIAL_TARGET', target):
        fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
    plan = root / 'DIRECTION_PLAN.json'
    plan.write_text(json.dumps({'status': 'COMPLETED',
                                'direction_ids': ['direction-one']}))
    seed = root / 'direction-seed'
    seed.write_bytes(b'Y')
    campaign = global_dev.DevGlobalCampaign(
        root / 'dev-output', q, total_fuzz_seconds=total,
        global_seconds=3, global_wall_reservation_seconds=reservation,
        replay_limit=1)
    campaign.stage_direction_seeds(
        plan, global_dev.digest(plan), [global_dev.DirectionSeed(
            'direction-one', seed, sha256(seed.read_bytes()).hexdigest())])
    return campaign, fixture


def two_runs(root: Path) -> tuple[Path, Path]:
    first, second = root / 'first', root / 'second'
    for run, function_id in ((first, 'function-one'),
                             (second, 'function-two')):
        run.mkdir()
        (run / 'selection.json').write_text(json.dumps({
            'function_id': function_id}))
    return first, second


class GlobalFormalDevBridgeTests(unittest.TestCase):
    def test_sequence_accepts_pinned_synthetic_consumer_result(self):
        """Acceptance of the child receipt is distinct from target execution."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            qualification = fixture.issue()
            self.assertIsNotNone(qualification)
            campaign = global_dev.DevGlobalCampaign(
                root / 'dev-output', qualification, total_fuzz_seconds=20,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            campaign.run_dir.mkdir(parents=True)
            report = {'binary_sha256': qualification.binary_sha256,
                      'requested_seconds': 1}
            global_dev.write_json(campaign.run_dir / 'runtime' / 'global_fuzz.json',
                                  report)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=14,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            code = (
                'import hashlib,json,pathlib,sys;'
                's=pathlib.Path(sys.argv[1]);v=json.loads(s.read_text());'
                'r=pathlib.Path(v["run_dir"])/"runtime"/'
                '"dev_global_consumer_result.json";'
                'r.write_text(json.dumps({' 
                '"kind":"DEV_GLOBAL_CONSUMER_RESULT_V1",'
                '"status":"COMPLETED","rows":[],'
                '"spec_sha256":hashlib.sha256(s.read_bytes()).hexdigest(),'
                '"report_sha256":v["report_sha256"],'
                '"contract_sha256":v["contract_sha256"],'
                '"binary_sha256":v["binary_sha256"]}))'
            )
            async def completed(*_args, **_kwargs):
                return []
            def consume_in_finish():
                rows = global_dev.consume_global_fuzzer_observations(
                    campaign.run_dir, report,
                    deadline_monotonic=time.monotonic() + 20)
                self.assertEqual(rows, [])
                return {'status': 'RAN', 'cleanup_complete': True}
            def command(spec_path, _spec_sha, _pycache_prefix):
                return [sys.executable, '-I', '-c', code, str(spec_path)]
            with patch.object(campaign, 'start', return_value='ACTIVE'), \
                 patch.object(campaign, 'finish', side_effect=consume_in_finish), \
                 patch.object(bridge, '_wait_for_guard_child', return_value=True), \
                 patch.object(runner, 'run_sequence', completed), \
                 patch.object(global_dev, '_consumer_worker_command',
                              side_effect=command):
                result = asyncio.run(bridge.run_sequence(
                    root / 'first', Provider(ledger), ledger, root,
                    root / 'checkpoint'))
            authority = json.loads((campaign.run_dir /
                                    'DEV_GLOBAL_CONSUMER_AUTHORITY.json').read_text())
            self.assertEqual(result['status'], 'DEV_SEQUENCE_COMPLETE')
            self.assertEqual(result['consumer_guard_status'],
                             'GLOBAL_CONSUMER_COMPLETE')
            self.assertEqual(authority['status'], 'COMPLETED')
            self.assertTrue(authority['gate_eligible'])
            self.assertEqual(authority['result_sha256'],
                             result['consumer_result_sha256'])

    def test_sequence_consumer_timeout_is_physical_and_preserves_checkpoint(self):
        """Exercise the bridge's real callback with a synthetic blocked child."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            qualification = fixture.issue()
            self.assertIsNotNone(qualification)
            campaign = global_dev.DevGlobalCampaign(
                root / 'dev-output', qualification, total_fuzz_seconds=20,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            campaign.run_dir.mkdir(parents=True)
            report = {'binary_sha256': qualification.binary_sha256,
                      'requested_seconds': 1}
            report_path = campaign.run_dir / 'runtime' / 'global_fuzz.json'
            global_dev.write_json(report_path, report)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=14,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            marker = root / 'detached.pid'
            code = (
                'import pathlib,subprocess,sys,time;'
                'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],'
                'start_new_session=True);'
                f'pathlib.Path({str(marker)!r}).write_text(str(p.pid));'
                'time.sleep(30)'
            )
            async def completed(*_args, **_kwargs):
                return []
            def consume_in_finish():
                global_dev.consume_global_fuzzer_observations(
                    campaign.run_dir, report,
                    deadline_monotonic=time.monotonic() + 20)
                return {'status': 'RAN', 'cleanup_complete': True}
            with patch.object(campaign, 'start', return_value='ACTIVE'), \
                 patch.object(campaign, 'finish', side_effect=consume_in_finish), \
                 patch.object(campaign, 'abort', return_value={
                     'status': 'STOPPED_ABORTED', 'cleanup_complete': True}), \
                 patch.object(bridge, '_wait_for_guard_child', return_value=True), \
                 patch.object(runner, 'run_sequence', completed), \
                 patch.object(global_dev, '_consumer_worker_command',
                              return_value=[sys.executable, '-I', '-c', code]):
                with self.assertRaises(TimeoutError):
                    asyncio.run(bridge.run_sequence(
                        root / 'first', Provider(ledger), ledger, root,
                        root / 'checkpoint'))
            result = json.loads(bridge.result_path.read_text())
            authority = json.loads((campaign.run_dir /
                                    'DEV_GLOBAL_CONSUMER_AUTHORITY.json').read_text())
            self.assertEqual(result['status'], 'INCOMPLETE_GLOBAL_FINISH_ERROR')
            self.assertEqual(result['consumer_guard_status'],
                             'STOPPED_GLOBAL_CONSUMER_WALL')
            self.assertTrue(result['consumer_hard_wall_enforced'])
            self.assertEqual(authority['status'], 'INCOMPLETE')
            self.assertFalse(authority['gate_eligible'])
            self.assertTrue(marker.is_file())
            self.assertFalse(Path(f'/proc/{int(marker.read_text())}').exists())

    def test_sync_consumer_guard_stops_blocked_call_and_detached_descendant(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / 'detached.pid'
            code = (
                'import pathlib,subprocess,sys,time;'
                'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],'
                'start_new_session=True);'
                f'pathlib.Path({str(marker)!r}).write_text(str(p.pid));'
                'time.sleep(30)'
            )
            started = time.monotonic()
            result = formal_dev._run_guarded_consumer_command(
                [sys.executable, '-I', '-c', code], root / 'consumer.log',
                wall_seconds=1)
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(result['status'], 'STOPPED_GLOBAL_CONSUMER_WALL')
            self.assertTrue(result['cleanup_complete'])
            self.assertTrue(marker.is_file())
            self.assertFalse(Path(f'/proc/{int(marker.read_text())}').exists())

    def test_nominal_sp_job_does_not_launch_without_physical_grace_reservation(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            campaign.budget.reserve('GLOBAL', 9)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            ledger.fuzz_overrun_policy = 'PHYSICAL_DEBIT_V1'
            meter = formal_dev.BridgeMeter(
                ledger, root / 'checkpoint', bridge=bridge)
            launched = []

            def slow_job(*, seconds):
                launched.append(seconds)
                time.sleep(0.1)
                return {'status': 'RAN', 'fuzz_seconds_actual': 2}

            with self.assertRaisesRegex(formal_dev.SharedPhysicalBudgetExceeded,
                                        'reservation refused'):
                meter.invoke('candidate', 'ASSERTION', 1, slow_job)
            self.assertEqual(launched, [])
            self.assertEqual(campaign.budget.spent_seconds, 0)

    def test_cancel_during_guard_readiness_aborts_and_records_original(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            with patch.object(bridge, '_wait_for_guard_child',
                              side_effect=asyncio.CancelledError('original cancel')):
                with self.assertRaisesRegex(asyncio.CancelledError, 'original cancel'):
                    asyncio.run(bridge.run_sequence(
                        root / 'first', Provider(ledger), ledger, root,
                        root / 'checkpoint'))
            self.assertEqual(campaign.aborted, 1)
            result = json.loads(bridge.result_path.read_text())
            self.assertEqual(result['error_type'], 'CancelledError')

    def test_result_write_failure_does_not_replace_original_cancel(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            with patch.object(bridge, '_wait_for_guard_child',
                              side_effect=asyncio.CancelledError('original cancel')), \
                 patch.object(bridge, '_write_result',
                              side_effect=OSError('audit output failed')):
                with self.assertRaisesRegex(asyncio.CancelledError, 'original cancel'):
                    asyncio.run(bridge.run_sequence(
                        root / 'first', Provider(ledger), ledger, root,
                        root / 'checkpoint'))
            self.assertEqual(campaign.aborted, 1)
            self.assertEqual(bridge.result_write_error_type, 'OSError')

    def test_abort_error_does_not_replace_original_cleanup_error(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            async def bad_sequence(*_args, **_kwargs):
                raise RuntimeCleanupError('original cleanup failed', '', '')
            with patch.object(bridge, '_wait_for_guard_child', return_value=True), \
                 patch.object(runner, 'run_sequence', bad_sequence), \
                 patch.object(campaign, 'abort',
                              side_effect=RuntimeError('abort failed')):
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'original cleanup failed'):
                    asyncio.run(bridge.run_sequence(
                        root / 'first', Provider(ledger), ledger, root,
                        root / 'checkpoint'))
            result = json.loads(bridge.result_path.read_text())
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['error_type'], 'RuntimeCleanupError')

    def test_accounting_error_does_not_replace_original_runtime_cleanup_error(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            ledger.fuzz_overrun_policy = 'PHYSICAL_DEBIT_V1'
            meter = formal_dev.BridgeMeter(
                ledger, root / 'checkpoint', bridge=bridge)
            def original_error(*, seconds):
                raise RuntimeCleanupError('original runtime cleanup', '', '')
            with patch.object(campaign.budget, 'finish',
                              side_effect=ValueError('accounting failed')):
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'original runtime cleanup'):
                    meter.invoke('hp-one', 'ASSERTION', 1, original_error)
            self.assertTrue(bridge.shared_budget_failed)

    def test_physical_debit_overrun_uses_remaining_shared_budget(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            ledger.fuzz_overrun_policy = 'PHYSICAL_DEBIT_V1'
            meter = formal_dev.BridgeMeter(
                ledger, root / 'checkpoint', bridge=bridge)
            def first(*, seconds):
                return {'status': 'RAN', 'fuzz_seconds_actual': 2}
            def second(*, seconds):
                return {'status': 'RAN', 'fuzz_seconds_actual': 1}
            meter.invoke('first', 'ASSERTION', 1, first)
            self.assertEqual(campaign.budget.available, 8)
            self.assertFalse(bridge.shared_budget_failed)
            meter.invoke('second', 'ASSERTION', 1, second)
            self.assertEqual(campaign.budget.available, 7)
            self.assertEqual(ledger.fuzz_physical_actual, 3)
            self.assertEqual(len(campaign.budget.records), 2)

    def test_physical_debit_fails_when_total_plus_active_global_exceeds_cap(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            campaign.budget.reserve('GLOBAL', 9)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            ledger.fuzz_overrun_policy = 'PHYSICAL_DEBIT_V1'
            meter = formal_dev.BridgeMeter(
                ledger, root / 'checkpoint', bridge=bridge)
            with self.assertRaisesRegex(formal_dev.SharedPhysicalBudgetExceeded,
                                        'reservation refused'):
                meter.invoke('first', 'ASSERTION', 1,
                             lambda *, seconds: {
                                 'status': 'RAN', 'fuzz_seconds_actual': 2})
            self.assertTrue(bridge.shared_budget_failed)
            self.assertEqual(campaign.budget.available, 1)

    def test_budget_write_failure_releases_new_reservation_before_run(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = SyntheticCampaign(root)
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=1,
                termination_grace_seconds=2)
            ledger = runner.Ledger(started_at=time.time())
            ledger.fuzz_overrun_policy = 'PHYSICAL_DEBIT_V1'
            meter = formal_dev.BridgeMeter(
                ledger, root / 'checkpoint', bridge=bridge)
            with patch.object(bridge, 'write_budget',
                              side_effect=OSError('ENOSPC')):
                with self.assertRaises(formal_dev.SharedPhysicalBudgetExceeded):
                    meter.invoke('x', 'ASSERTION', 1,
                                 lambda *, seconds: self.fail('must not start'))
            self.assertEqual(campaign.budget.reservations, {})
            self.assertIsNone(ledger.active_fuzz)
            self.assertTrue(bridge.shared_budget_failed)

    def test_start_and_finish_errors_are_recorded_without_success(self):
        for stage in ('start', 'finish'):
            with self.subTest(stage=stage), TemporaryDirectory() as tmp:
                root = Path(tmp)
                campaign = SyntheticCampaign(root)
                bridge = formal_dev.GlobalFormalDevBridge(
                    campaign, consumer_wall_seconds=1,
                    termination_grace_seconds=2)
                ledger = runner.Ledger(started_at=time.time())
                async def completed(*_args, **_kwargs):
                    return []
                with patch.object(bridge, '_wait_for_guard_child', return_value=True), \
                     patch.object(runner, 'run_sequence', completed), \
                     patch.object(campaign, stage,
                                  side_effect=RuntimeError(stage + ' exploded')):
                    with self.assertRaisesRegex(RuntimeError, stage + ' exploded'):
                        asyncio.run(bridge.run_sequence(
                            root / 'first', Provider(ledger), ledger, root,
                            root / 'checkpoint'))
                result = json.loads(bridge.result_path.read_text())
                self.assertNotEqual(result['status'], 'DEV_SEQUENCE_COMPLETE')
                self.assertEqual(result['error_type'], 'RuntimeError')

    def _run_scripted(self, root: Path, campaign: global_dev.DevGlobalCampaign,
                      *, guided: bool, followup: bool,
                      consumer_wall: float = 30) -> tuple[dict, runner.Ledger, list]:
        first, second = two_runs(root)
        ledger = runner.Ledger(started_at=time.time())
        provider = Provider(ledger)
        bridge = formal_dev.GlobalFormalDevBridge(
            campaign, consumer_wall_seconds=consumer_wall,
            termination_grace_seconds=2)
        scan_options_seen = []

        def toy_guided(_assertion, *, seconds, **_kwargs):
            time.sleep(0.03)
            return {'status': 'RAN', 'fuzz_seconds_actual': 0.03,
                    'violation_witnesses': []}

        def toy_followup(run, _fuzzer, meter, **_kwargs):
            def fuzz(*, seconds):
                time.sleep(0.03)
                return {'status': 'RAN'}
            meter.invoke('sp-' + run.name, 'FAILED_POV_SEED', 2, fuzz)
            return []

        async def fake_scan(run, _provider, **kwargs):
            scan_options_seen.append(kwargs)
            if guided:
                runner.scan_mod.guided_fuzz_assertion(
                    SimpleNamespace(assertion_id='hp-' + run.name), seconds=2)
            (run / 'scan.json').write_text(json.dumps({
                'selected_function_id': json.loads(
                    (run / 'selection.json').read_text())['function_id'],
                'sp_llm_calls': 0, 'hp_llm_calls': 0,
                'effective_sp_llm_call_limit': 4,
                'combined_llm_call_limit': 8}))

        with patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
             patch.object(runner.scan_mod, 'guided_fuzz_assertion', toy_guided), \
             patch.object(runner, 'run_failed_pov_followups', toy_followup), \
             patch.object(runner, 'consume_reproduced_sp_followups',
                          return_value=[]), \
             patch.object(runner, 'continue_phase1', return_value=second), \
             patch.object(runner, 'checkpoint_run',
                          return_value=root / 'FUNCTION_CHECKPOINT.json'), \
             patch.object(runner, 'summarize_resource_exhaustion',
                          return_value={
                              'resource_exhaustion_artifact_count': 0,
                              'environment_error_artifact_count': 0}):
            options = {
                'max_functions': 2,
                'scan_options': {
                    'run_command': [str(campaign.q.binary), '{input}'],
                    'target_binary': campaign.q.binary,
                    'official_qualification': campaign.q},
                'followup_fuzzer': campaign.q.binary if followup else None,
                'consumer_budget': {
                    'per_item_wall_seconds': 10,
                    'combined_wall_seconds': 20} if followup else None,
            }
            result = asyncio.run(bridge.run_sequence(
                first, provider, ledger, campaign.q.source_root,
                root / 'BUDGET_CHECKPOINT.json', **options))
        return result, ledger, scan_options_seen

    def test_two_real_runner_functions_share_global_guided_followup_ledger(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign, _fixture = safe_campaign(root)
            result, ledger, scan_options = self._run_scripted(
                root, campaign, guided=True, followup=True)
            self.assertEqual(result['status'], 'DEV_SEQUENCE_COMPLETE', result)
            self.assertEqual(len(result['function_rows']), 2)
            self.assertEqual([r['status'] for r in result['function_rows']],
                             ['COMPLETE', 'COMPLETE'])
            self.assertEqual([r['function_id'] for r in
                              result['global_function_windows']],
                             ['function-one', 'function-two'])
            self.assertTrue(all(r['global_guard_alive'] for r in
                                result['global_function_windows']))
            self.assertEqual(len({r['global_guard_pid'] for r in
                                  result['global_function_windows']}), 1)
            self.assertTrue(all(o['global_fuzz_enabled'] is False and
                                o['global_fuzz_seconds'] == 0
                                for o in scan_options))
            budget = json.loads((campaign.output /
                                 'DEV_SHARED_FUZZ_BUDGET.json').read_text())
            keys = [r['key'] for r in budget['records']]
            self.assertEqual(keys.count('GLOBAL'), 1)
            self.assertEqual(len([k for k in keys if k.startswith('ASSERTION:')]), 2)
            self.assertEqual(len([k for k in keys if k.startswith('FAILED_POV_SEED:')]), 2)
            self.assertEqual(budget['reserved_seconds'], 0)
            self.assertLessEqual(budget['spent_seconds'], budget['total_seconds'])
            self.assertAlmostEqual(
                sum(r['physical_seconds'] for r in budget['records'] if r['key'] != 'GLOBAL'),
                ledger.fuzz_physical_actual, delta=0.01)

    def test_global_reservation_blocks_guided_before_shared_cap(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign, _fixture = safe_campaign(root, total=18, reservation=18)
            first, _second = two_runs(root)
            ledger = runner.Ledger(started_at=time.time())
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=30,
                termination_grace_seconds=2)
            def toy_guided(_assertion, *, seconds, **_kwargs):
                self.fail('guided process must not start after refused reservation')
            async def fake_scan(run, _provider, **_kwargs):
                runner.scan_mod.guided_fuzz_assertion(
                    SimpleNamespace(assertion_id='hp-one'), seconds=2)
            with patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner.scan_mod, 'guided_fuzz_assertion', toy_guided), \
                 patch.object(runner, 'checkpoint_run',
                              return_value=root / 'FUNCTION_CHECKPOINT.json'), \
                 patch.object(runner, 'summarize_resource_exhaustion',
                              return_value={
                                  'resource_exhaustion_artifact_count': 0,
                                  'environment_error_artifact_count': 0}):
                with self.assertRaises(formal_dev.SharedPhysicalBudgetExceeded):
                    asyncio.run(bridge.run_sequence(
                        first, Provider(ledger), ledger, campaign.q.source_root,
                        root / 'BUDGET_CHECKPOINT.json', max_functions=1))
            recorded = json.loads(bridge.result_path.read_text())
            self.assertEqual(recorded['status'], 'STOPPED_SHARED_FUZZ_BUDGET')
            self.assertTrue(recorded['global_cleanup_complete'])
            self.assertLessEqual(recorded['shared_physical_budget']['spent_seconds'], 18)

    def test_global_crash_consumer_uses_separate_wall_deadline_and_overrun_stops(self):
        """Known seed only; consumer wall is neither fuzz time nor discovery."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
            plan = root / 'DIRECTION_PLAN.json'
            plan.write_text(json.dumps({'status': 'COMPLETED',
                                        'direction_ids': ['direction-one']}))
            seed = root / 'direction-seed'
            seed.write_bytes(b'X')
            campaign = global_dev.DevGlobalCampaign(
                root / 'dev-output', q, total_fuzz_seconds=30,
                global_seconds=3, global_wall_reservation_seconds=18,
                replay_limit=1)
            campaign.stage_direction_seeds(
                plan, global_dev.digest(plan), [global_dev.DirectionSeed(
                    'direction-one', seed, sha256(seed.read_bytes()).hexdigest())])
            first, _second = two_runs(root)
            ledger = runner.Ledger(started_at=time.time())
            bridge = formal_dev.GlobalFormalDevBridge(
                campaign, consumer_wall_seconds=0.05,
                termination_grace_seconds=2)
            deadlines = []

            async def fake_scan(run, _provider, **_kwargs):
                (run / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'function-one',
                    'sp_llm_calls': 0, 'hp_llm_calls': 0,
                    'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8}))

            def slow_consumer(*_args, **kwargs):
                deadlines.append(kwargs['deadline_monotonic'] - time.monotonic())
                time.sleep(0.25)
                return []

            with patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(global_dev, 'consume_global_fuzzer_observations',
                              slow_consumer), \
                 patch.object(runner, 'checkpoint_run',
                              return_value=root / 'FUNCTION_CHECKPOINT.json'), \
                 patch.object(runner, 'summarize_resource_exhaustion',
                              return_value={
                                  'resource_exhaustion_artifact_count': 0,
                                  'environment_error_artifact_count': 0}):
                with self.assertRaisesRegex(
                        formal_dev.SharedPhysicalBudgetExceeded,
                        'INCOMPLETE_GLOBAL_CONSUMER_WALL_OVERRUN'):
                    asyncio.run(bridge.run_sequence(
                        first, Provider(ledger), ledger, q.source_root,
                        root / 'BUDGET_CHECKPOINT.json', max_functions=1))
            # The consumer cannot start when the reservation cannot also
            # cover bounded descendant cleanup.
            self.assertEqual(deadlines, [])
            result = json.loads(bridge.result_path.read_text())
            self.assertEqual(result['status'],
                             'INCOMPLETE_GLOBAL_CONSUMER_WALL_OVERRUN')
            self.assertTrue(result['global_cleanup_complete'])
            self.assertEqual(result['consumer_wall_seconds'], 0)
            self.assertFalse(result['consumer_hard_wall_enforced'])
            self.assertEqual(result['consumer_wall_scope'],
                             'GUARDED_CHILD_WITH_CLEANUP_ENVELOPE')
            self.assertFalse(result['parallel_physical_hard_cap_enforced'])
            self.assertLess(result['shared_physical_budget']['spent_seconds'], 30)


if __name__ == '__main__':
    unittest.main()
