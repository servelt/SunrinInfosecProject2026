"""Model-free checks for the second runner's accounting boundary."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from unittest import TestCase
from unittest.mock import patch
from types import SimpleNamespace

import blind2_runner_draft as runner
from vulnerabilityanalysis.models import RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.runtime import (RuntimeCleanupError, PhysicalFuzzStop,
                                           PhysicalFuzzBudgetPending)


class FakeMeter:
    def __init__(self, *_args, **_kwargs):
        self.records = []
        self.zero_budget_assertion_runs = set()

    @contextmanager
    def patch_guided(self):
        yield


class FakeProvider:
    def __init__(self, ledger):
        self.ledger = ledger
        self.selected = None

    def begin_function(self, function_id):
        self.selected = function_id

    def end_function(self):
        self.selected = None


class Blind2RunnerDraftTests(TestCase):
    def test_fuzz_settlement_failure_does_not_replace_runtime_cleanup_error(self):
        with TemporaryDirectory() as tmp:
            ledger = runner.Ledger(started_at=time.time())
            meter = runner.SharedFuzzMeter(ledger, Path(tmp) / 'ledger.json')

            def cleanup_failure(*, seconds):
                raise RuntimeCleanupError('original detached process', '', '')

            with patch.object(type(ledger), 'finish_fuzz',
                              side_effect=OSError('settlement failed')):
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'original detached process') as raised:
                    meter.invoke('SP_FOLLOWUP:one', 'FAILED_POV_SEED', 1,
                                 cleanup_failure)
            self.assertTrue(any('settlement failed' in note
                                for note in getattr(raised.exception, '__notes__', [])))

    def test_fuzz_settlement_failure_without_primary_is_fatal(self):
        with TemporaryDirectory() as tmp:
            ledger = runner.Ledger(started_at=time.time())
            meter = runner.SharedFuzzMeter(ledger, Path(tmp) / 'ledger.json')
            with patch.object(type(ledger), 'finish_fuzz',
                              side_effect=OSError('settlement failed')):
                with self.assertRaisesRegex(runner.FuzzMeterAccountingError,
                                            'settlement'):
                    meter.invoke('SP_FOLLOWUP:one', 'FAILED_POV_SEED', 1,
                                 lambda *, seconds: {'status': 'RAN'})

    def test_nonfatal_primary_with_settlement_failure_keeps_primary_and_stops(self):
        with TemporaryDirectory() as tmp:
            ledger = runner.Ledger(started_at=time.time())
            meter = runner.SharedFuzzMeter(ledger, Path(tmp) / 'ledger.json')

            def original_failure(*, seconds):
                raise OSError('original fuzzer error')

            with patch.object(type(ledger), 'finish_fuzz',
                              side_effect=OSError('settlement failed')):
                with self.assertRaisesRegex(OSError, 'original fuzzer error') as raised:
                    meter.invoke('SP_FOLLOWUP:one', 'FAILED_POV_SEED', 1,
                                 original_failure)
            self.assertTrue(meter.settlement_failed)
            self.assertTrue(getattr(raised.exception, 'fuzz_accounting_failed', False))

    def test_physical_fuzz_stop_is_fatal_before_next_function(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'first', root / 'second'
            for run, function_id in ((first, 'fn1'), (second, 'fn2')):
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': function_id, 'function_name': function_id}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)

            async def physical_stop(_run, _provider, **_kwargs):
                raise PhysicalFuzzStop('STOPPED_PHYSICAL_LEDGER_ERROR',
                                       'synthetic physical ledger stop')

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', physical_stop), \
                 patch.object(runner, 'continue_phase1', return_value=second) as next_function:
                with self.assertRaises(PhysicalFuzzStop):
                    asyncio.run(runner.run_sequence(
                        first, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            next_function.assert_not_called()
            checkpoint = json.loads((first / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'], 'STOPPED_PHYSICAL_LEDGER_ERROR')

    def test_physical_fuzz_budget_pending_is_not_complete(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / 'first'; first.mkdir()
            (first / 'selection.json').write_text(json.dumps({
                'function_id': 'fn1', 'function_name': 'fn1'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)

            async def pending_before_launch(_run, _provider, **_kwargs):
                raise PhysicalFuzzBudgetPending('no physical reservation')

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', pending_before_launch), \
                 patch.object(runner, 'continue_phase1') as next_function:
                with self.assertRaises(PhysicalFuzzBudgetPending):
                    asyncio.run(runner.run_sequence(
                        first, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            next_function.assert_not_called()
            checkpoint = json.loads((first / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'], 'PENDING_SHARED_PHYSICAL_BUDGET')

    def test_hp_refinement_noop_report_has_zero_reserved_fuzz_seconds(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'assertions').mkdir(parents=True)
            ledger = runner.Ledger(started_at=time.time())
            ledger.counts['function'] = {'assertion_generator': 1}
            meter = runner.SharedFuzzMeter(ledger, root / 'ledger.json')
            with meter.patch_guided():
                report = asyncio.run(runner.scan_mod.refine_overstrong_assertions(
                    run, function_id='function'))
            self.assertEqual(report['status'], 'NO_ELIGIBLE_VIOLATION')
            self.assertEqual(report['guided_fuzz_reserved_seconds'], 0)

    def test_frozen_runner_rejects_development_candidate_budget_policy(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            with self.assertRaisesRegex(ValueError, 'runner owns all fixed budget'):
                asyncio.run(runner.run_sequence(
                    root / 'run', provider, ledger, root, root / 'checkpoint.json',
                    scan_options={'candidate_budget_policy': 'VERIFIER_FIRST'}))

    def test_formal_sequence_keeps_global_fuzzer_off_and_uncharged(self):
        """The scoped SP/HP run never enables Global through run_sequence."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            seen_scan_options = []
            meters = []

            async def fake_scan(folder, _provider, **kwargs):
                seen_scan_options.append(kwargs)
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8}))

            def make_meter(*args, **kwargs):
                meter = FakeMeter(*args, **kwargs)
                meters.append(meter)
                return meter

            with patch.object(runner, 'SharedFuzzMeter', make_meter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'checkpoint_run', return_value=root / 'checkpoint'), \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                rows = asyncio.run(runner.run_sequence(
                    run, provider, ledger, root, root / 'ledger.json', max_functions=1))

            self.assertEqual(rows[0]['status'], 'COMPLETE')
            self.assertEqual(len(seen_scan_options), 1)
            self.assertIs(seen_scan_options[0]['global_fuzz_enabled'], False)
            self.assertEqual(seen_scan_options[0]['global_fuzz_seconds'], 0)
            self.assertEqual(ledger.fuzz_budget_used(), 0)
            self.assertEqual(meters[0].records, [])
            self.assertFalse((run / 'runtime' / 'global_fuzz.json').exists())

    def test_formal_sequence_rejects_global_fuzzer_override(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for options in ({'global_fuzz_enabled': True},
                            {'global_fuzz_enabled': False},
                            {'global_fuzz_seconds': 1},
                            {'global_fuzz_seconds': 0}):
                ledger = runner.Ledger(started_at=time.time())
                provider = FakeProvider(ledger)
                with self.subTest(options=options), self.assertRaisesRegex(
                        ValueError, 'runner owns all fixed budget'):
                    asyncio.run(runner.run_sequence(
                        root / 'run', provider, ledger, root,
                        root / 'checkpoint.json', scan_options=options))
                self.assertEqual(ledger.physical, 0)
                self.assertEqual(ledger.fuzz_budget_used(), 0)

    def _assert_supervisor_sigkill_reaps_family(self, *, route: bool,
                                                post_wait_gap: bool = False,
                                                detached: bool = False) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_file = root / 'family.json'
            cleanup_marker = root / 'post_wait_cleanup'
            separate_session = ',start_new_session=True' if detached else ''
            child_script = ('import json,os,pathlib,subprocess,sys,time;'
                            'grandchild=subprocess.Popen([sys.executable,"-c",'
                            '"import time;time.sleep(30)"]'+separate_session+');'
                            f'pathlib.Path({str(pid_file)!r}).write_text('
                            'json.dumps({"child":os.getpid(),'
                            '"grandchild":grandchild.pid}));')
            child_script += 'sys.exit(0)' if post_wait_gap else 'time.sleep(30)'
            runner_dir = str(Path(runner.__file__).resolve().parent)
            if route:
                call = (f'r._bounded_preapproval_process('
                        f'[sys.executable,"-c",{child_script!r}],timeout_seconds=30)')
            else:
                call = (f'r.supervise_child([sys.executable,"-c",{child_script!r}],'
                        f'pathlib.Path({str(root / "run")!r}),timeout_seconds=30)')
            supervisor_script = (f'import pathlib,sys;sys.path.insert(0,{runner_dir!r});'
                                 'import blind2_runner_draft as r;')
            if post_wait_gap:
                supervisor_script += (
                    'r._kill_process_group=lambda _pgid:('
                    f'pathlib.Path({str(cleanup_marker)!r}).write_text("cleanup"),'
                    '__import__("time").sleep(30));')
            supervisor_script += call
            supervisor = subprocess.Popen([sys.executable, '-c', supervisor_script],
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            family: dict[str, int] | None = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not pid_file.is_file():
                    if supervisor.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertTrue(pid_file.is_file(), 'synthetic child never started')
                family = json.loads(pid_file.read_text())
                if post_wait_gap:
                    while time.monotonic() < deadline + 5 and not cleanup_marker.is_file():
                        if supervisor.poll() is not None:
                            break
                        time.sleep(0.02)
                    self.assertTrue(cleanup_marker.is_file(), 'post-wait gap not reached')
                os.kill(supervisor.pid, signal.SIGKILL)
                supervisor.wait(timeout=5)
                self._assert_descendant_stopped(family['child'])
                self._assert_descendant_stopped(family['grandchild'])
            finally:
                if supervisor.poll() is None:
                    supervisor.kill()
                    supervisor.wait(timeout=5)
                if family is not None:
                    for member in ('child', 'grandchild'):
                        try:
                            os.killpg(os.getpgid(family[member]), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_supervisor_sigkill_reaps_runner_and_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(route=False)

    def test_preapproval_supervisor_sigkill_reaps_route_and_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(route=True)

    def test_supervisor_post_wait_sigkill_still_reaps_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(route=False, post_wait_gap=True)

    def test_preapproval_post_wait_sigkill_still_reaps_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(route=True, post_wait_gap=True)

    def test_supervisor_sigkill_reaps_detached_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(route=False, detached=True)

    def test_preapproval_sigkill_reaps_detached_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(route=True, detached=True)

    def test_supervisor_post_wait_sigkill_reaps_detached_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(
            route=False, post_wait_gap=True, detached=True)

    def test_preapproval_post_wait_sigkill_reaps_detached_grandchild(self):
        self._assert_supervisor_sigkill_reaps_family(
            route=True, post_wait_gap=True, detached=True)

    def test_subreaper_unavailable_blocks_before_child_launch(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'executed'
            script = f'import pathlib;pathlib.Path({str(marker)!r}).write_text("yes")'
            unavailable = runner._PROCESS_GROUP_GUARD.replace(
                'if libc.prctl(36, 1, 0, 0, 0) != 0:', 'if True:')
            with patch.object(runner, '_PROCESS_GROUP_GUARD', unavailable):
                with self.assertRaisesRegex(ValueError, 'failed before approval'):
                    runner._bounded_preapproval_process(
                        [sys.executable, '-c', script], timeout_seconds=5)
            self.assertFalse(marker.exists())

    def test_incomplete_subreaper_cleanup_is_reported(self):
        incomplete = runner._PROCESS_GROUP_GUARD.replace(
            'cleaned = stop_descendants()', 'cleaned = False')
        with TemporaryDirectory() as tmp:
            with patch.object(runner, '_PROCESS_GROUP_GUARD', incomplete):
                with self.assertRaisesRegex(ValueError, 'cleanup incomplete'):
                    runner._bounded_preapproval_process(
                        [sys.executable, '-c', 'pass'], timeout_seconds=5)
                result = runner.supervise_child(
                    [sys.executable, '-c', 'pass'], Path(tmp) / 'run', timeout_seconds=5)
            self.assertEqual(result, 'STOPPED_CLEANUP_INCOMPLETE')
            row = json.loads((Path(tmp) / 'run' / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(row['original_stop_reason'], 'CHILD_ERROR')
            self.assertTrue(row['cleanup_incomplete'])
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 24)

    def test_cleanup_failure_outweighs_child_tool_event_marker(self):
        incomplete = runner._PROCESS_GROUP_GUARD.replace(
            'cleaned = stop_descendants()', 'cleaned = False')
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import pathlib;'
                      f'p=pathlib.Path({str(output)!r});p.mkdir();'
                      '(p/"RUNNER_RESULT.json").write_text('
                      '"{\\"status\\":\\"INCOMPLETE_TOOL_EVENT\\"}")')
            with patch.object(runner, '_PROCESS_GROUP_GUARD', incomplete):
                status = runner.supervise_child(
                    [sys.executable, '-c', script], output, timeout_seconds=5)
            self.assertEqual(status, 'STOPPED_CLEANUP_INCOMPLETE')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(row['original_stop_reason'], 'CHILD_ERROR')
            self.assertTrue(row['cleanup_incomplete'])
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 24)

    def test_wall_timeout_cleanup_failure_has_distinct_top_level_status(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            prior = output / 'runs' / 'function_0' / 'FUNCTION_CHECKPOINT.json'
            prior.parent.mkdir(parents=True)
            prior.write_text(json.dumps({'status': 'COMPLETE'}))
            real_cleanup = runner._request_guard_cleanup

            def cleanup_but_report_failure(child, status_read):
                real_cleanup(child, status_read)
                return False

            with patch.object(runner, '_request_guard_cleanup',
                              side_effect=cleanup_but_report_failure):
                status = runner.supervise_child(
                    [sys.executable, '-c', 'import time;time.sleep(30)'],
                    output, timeout_seconds=.1)
            self.assertEqual(status, 'STOPPED_CLEANUP_INCOMPLETE')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(row['original_stop_reason'], 'STOPPED_WALL_LIMIT')
            self.assertTrue(row['cleanup_incomplete'])
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 23)
            self.assertEqual(row['function_checkpoints'][0]['sha256'], runner.digest(prior))

    def test_wall_timeout_preserves_partial_function_checkpoint(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            prior = output / 'runs' / 'function_0' / 'FUNCTION_CHECKPOINT.json'
            prior.parent.mkdir(parents=True)
            prior.write_text('{partial')
            status = runner.supervise_child(
                [sys.executable, '-c', 'import time;time.sleep(30)'],
                output, timeout_seconds=.1)
            self.assertEqual(status, 'STOPPED_WALL_LIMIT')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 23)
            checkpoint = row['function_checkpoints'][0]
            self.assertEqual(checkpoint['sha256'], runner.digest(prior))
            self.assertEqual(checkpoint['status'], 'INCOMPLETE_CHECKPOINT_UNREADABLE')
            self.assertIn('checkpoint_read_error', checkpoint)

    def test_wall_timeout_preserves_partial_budget_checkpoint(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            output.mkdir()
            budget = output / 'BUDGET_CHECKPOINT.json'
            budget.write_text('{partial')
            status = runner.supervise_child(
                [sys.executable, '-c', 'import time;time.sleep(30)'],
                output, timeout_seconds=.1)
            self.assertEqual(status, 'STOPPED_WALL_LIMIT')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['budget_checkpoint_sha256'], runner.digest(budget))
            self.assertIn('budget_checkpoint_read_error', row)

    def test_terminal_stop_over_k_records_overflow_and_still_writes_result(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            for index in range(2):
                checkpoint = output / 'runs' / str(index) / 'FUNCTION_CHECKPOINT.json'
                checkpoint.parent.mkdir(parents=True)
                checkpoint.write_text(json.dumps({'status': 'COMPLETE'}))
            runner.record_cleanup_incomplete_stop(output, max_functions=1)
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['processed_function_count'], 2)
            self.assertEqual(row['remaining_selection_slots'], 0)
            self.assertEqual(row['checkpoint_overflow_count'], 1)
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')

    def test_child_partial_result_is_preserved_before_cleanup_stop(self):
        incomplete = runner._PROCESS_GROUP_GUARD.replace(
            'cleaned = stop_descendants()', 'cleaned = False')
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import pathlib;'
                      f'p=pathlib.Path({str(output)!r});p.mkdir();'
                      '(p/"RUNNER_RESULT.json").write_text("{partial")')
            with patch.object(runner, '_PROCESS_GROUP_GUARD', incomplete):
                status = runner.supervise_child(
                    [sys.executable, '-c', script], output, timeout_seconds=5)
            self.assertEqual(status, 'STOPPED_CLEANUP_INCOMPLETE')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            partial = output / row['child_result_partial_path']
            self.assertEqual(partial.read_text(), '{partial')
            self.assertEqual(row['child_result_partial_sha256'], runner.digest(partial))
            self.assertIn('child_result_read_error', row)

    def test_wall_timeout_preserves_partial_child_result(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            output.mkdir()
            (output / 'RUNNER_RESULT.json').write_text('{partial')
            status = runner.supervise_child(
                [sys.executable, '-c', 'import time;time.sleep(30)'],
                output, timeout_seconds=.1)
            self.assertEqual(status, 'STOPPED_WALL_LIMIT')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            partial = output / row['child_result_partial_path']
            self.assertEqual(partial.read_text(), '{partial')
            self.assertEqual(row['child_result_partial_sha256'], runner.digest(partial))

    def test_wall_timeout_preserves_valid_child_result_before_override(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            output.mkdir()
            original = '{"status":"COMPLETE","functions":[]}'
            (output / 'RUNNER_RESULT.json').write_text(original)
            status = runner.supervise_child(
                [sys.executable, '-c', 'import time;time.sleep(30)'],
                output, timeout_seconds=.1)
            self.assertEqual(status, 'STOPPED_WALL_LIMIT')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            prior = output / row['child_result_prior_path']
            self.assertEqual(prior.read_text(), original)
            self.assertEqual(row['child_result_prior_sha256'], runner.digest(prior))
            self.assertEqual(row['child_result_prior_status'], 'COMPLETE')

    def test_abnormal_exit_preserves_partial_budget_and_function_checkpoints(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            function = output / 'runs' / 'function_0' / 'FUNCTION_CHECKPOINT.json'
            function.parent.mkdir(parents=True)
            function.write_text('{partial')
            budget = output / 'BUDGET_CHECKPOINT.json'
            budget.write_text('{partial')
            status = runner.supervise_child(
                [sys.executable, '-c', 'import sys;sys.exit(7)'],
                output, timeout_seconds=5)
            self.assertEqual(status, 'CHILD_ERROR')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['budget_checkpoint_sha256'], runner.digest(budget))
            self.assertIn('budget_checkpoint_read_error', row)
            self.assertEqual(row['function_checkpoints'][0]['sha256'], runner.digest(function))
            self.assertEqual(row['function_checkpoints'][0]['status'],
                             'INCOMPLETE_CHECKPOINT_UNREADABLE')

    def test_success_exit_partial_result_fails_closed_with_preserved_bytes(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import pathlib;'
                      f'p=pathlib.Path({str(output)!r});p.mkdir();'
                      '(p/"RUNNER_RESULT.json").write_text("{partial")')
            status = runner.supervise_child(
                [sys.executable, '-c', script], output, timeout_seconds=5)
            self.assertEqual(status, 'CHILD_ERROR')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['original_stop_reason'], 'CHILD_RESULT_UNREADABLE')
            prior = output / row['child_result_partial_path']
            self.assertEqual(prior.read_text(), '{partial')
            self.assertEqual(row['child_result_partial_sha256'], runner.digest(prior))

    def test_success_exit_missing_result_still_writes_terminal_artifact(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            status = runner.supervise_child(
                [sys.executable, '-c', 'pass'], output, timeout_seconds=5)
            self.assertEqual(status, 'CHILD_ERROR')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['status'], 'CHILD_ERROR')
            self.assertEqual(row['original_stop_reason'], 'CHILD_RESULT_MISSING')
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 24)

    def test_abnormal_exit_partial_result_preserves_no_opportunity(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import pathlib,sys;'
                      f'p=pathlib.Path({str(output)!r});p.mkdir();'
                      '(p/"RUNNER_RESULT.json").write_text("{partial");'
                      'sys.exit(7)')
            status = runner.supervise_child(
                [sys.executable, '-c', script], output, timeout_seconds=5)
            self.assertEqual(status, 'CHILD_ERROR')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 24)
            prior = output / row['child_result_partial_path']
            self.assertEqual(row['child_result_partial_sha256'], runner.digest(prior))

    def test_success_exit_cannot_hide_cleanup_stop_marker(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import pathlib;'
                      f'p=pathlib.Path({str(output)!r});p.mkdir();'
                      '(p/"RUNNER_RESULT.json").write_text('
                      '"{\\"status\\":\\"STOPPED_CLEANUP_INCOMPLETE\\"}")')
            status = runner.supervise_child(
                [sys.executable, '-c', script], output, timeout_seconds=5)
            self.assertEqual(status, 'STOPPED_CLEANUP_INCOMPLETE')

    def test_child_cleanup_flag_takes_precedence_over_success_exit(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import pathlib;'
                      f'p=pathlib.Path({str(output)!r});p.mkdir();'
                      '(p/"RUNNER_RESULT.json").write_text('
                      '"{\\"status\\":\\"COMPLETE\\",'
                      '\\"cleanup_incomplete\\":true}")')
            status = runner.supervise_child(
                [sys.executable, '-c', script], output, timeout_seconds=5)
            self.assertEqual(status, 'STOPPED_CLEANUP_INCOMPLETE')
            row = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(row['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(row['original_stop_reason'], 'COMPLETE')
            self.assertEqual(row['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(row['remaining_selection_slots'], 24)

    def test_preapproval_normal_exit_reaps_detached_grandchild(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'detached.pid'
            script = ('import pathlib,subprocess,sys;'
                      'grandchild=subprocess.Popen([sys.executable,"-c",'
                      '"import time;time.sleep(30)"],start_new_session=True);'
                      f'pathlib.Path({str(marker)!r}).write_text(str(grandchild.pid))')
            pid = None
            try:
                runner._bounded_preapproval_process([sys.executable, '-c', script],
                                                    timeout_seconds=5)
                pid = int(marker.read_text())
                self._assert_descendant_stopped(pid)
            finally:
                if pid is None and marker.is_file():
                    pid = int(marker.read_text())
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_supervisor_normal_exit_reaps_detached_grandchild(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker, output = root / 'detached.pid', root / 'run'
            script = ('import pathlib,subprocess,sys;'
                      'grandchild=subprocess.Popen([sys.executable,"-c",'
                      '"import time;time.sleep(30)"],start_new_session=True);'
                      f'pathlib.Path({str(marker)!r}).write_text(str(grandchild.pid));'
                      f'pathlib.Path({str(output)!r}).mkdir();'
                      f'pathlib.Path({str(output / "RUNNER_RESULT.json")!r}).write_text("{{}}")')
            pid = None
            try:
                self.assertEqual(runner.supervise_child(
                    [sys.executable, '-c', script], output, timeout_seconds=5),
                    'COMPLETE_OR_INCONCLUSIVE')
                pid = int(marker.read_text())
                self._assert_descendant_stopped(pid)
            finally:
                if pid is None and marker.is_file():
                    pid = int(marker.read_text())
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_guard_closes_pipe_held_by_detached_grandchild(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'detached.pid'
            script = ('import pathlib,subprocess,sys;'
                      'grandchild=subprocess.Popen([sys.executable,"-c",'
                      '"import time;time.sleep(30)"],start_new_session=True);'
                      f'pathlib.Path({str(marker)!r}).write_text(str(grandchild.pid))')
            child, status_read = runner._launch_guarded(
                [sys.executable, '-c', script], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            pid = None
            try:
                try:
                    child.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    if marker.is_file():
                        os.kill(int(marker.read_text()), signal.SIGKILL)
                    raise
                pid = int(marker.read_text())
                self._assert_descendant_stopped(pid)
            finally:
                os.close(status_read)
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if pid is None and marker.is_file():
                    pid = int(marker.read_text())
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def _assert_timeout_reaps_detached_grandchild(self, *, route: bool) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / 'detached.pid'
            script = ('import pathlib,subprocess,sys,time;'
                      'grandchild=subprocess.Popen([sys.executable,"-c",'
                      '"import time;time.sleep(30)"],start_new_session=True);'
                      f'pathlib.Path({str(marker)!r}).write_text(str(grandchild.pid));'
                      'time.sleep(30)')
            pid = None
            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    if route:
                        future = executor.submit(runner._bounded_preapproval_process,
                            [sys.executable, '-c', script], timeout_seconds=3)
                    else:
                        future = executor.submit(runner.supervise_child,
                            [sys.executable, '-c', script], root / 'run',
                            timeout_seconds=3)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not marker.is_file():
                        if future.done():
                            break
                        time.sleep(.02)
                    self.assertTrue(marker.is_file(), 'detached test child did not start')
                    if route:
                        with self.assertRaisesRegex(TimeoutError, 'physical wall deadline'):
                            future.result(timeout=10)
                    else:
                        self.assertEqual(future.result(timeout=10), 'STOPPED_WALL_LIMIT')
                        result = json.loads((root / 'run' / 'RUNNER_RESULT.json').read_text())
                        self.assertFalse(result['cleanup_incomplete'])
                pid = int(marker.read_text())
                self._assert_descendant_stopped(pid)
            finally:
                if pid is None and marker.is_file():
                    pid = int(marker.read_text())
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_preapproval_timeout_reaps_detached_grandchild(self):
        self._assert_timeout_reaps_detached_grandchild(route=True)

    def test_supervisor_timeout_reaps_detached_grandchild(self):
        self._assert_timeout_reaps_detached_grandchild(route=False)

    @staticmethod
    def _assert_descendant_stopped(pid: int) -> None:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            proc = Path(f'/proc/{pid}/stat')
            try:
                state = proc.read_text().split()[2]
            except (FileNotFoundError, ProcessLookupError):
                return
            if state == 'Z':
                return
            time.sleep(0.02)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        raise AssertionError(f'supervised descendant {pid} is still running')

    @staticmethod
    def _exiting_parent_with_descendant(pid_file: Path, output: Path | None = None,
                                        exit_code: int = 7) -> str:
        result = ''
        if output is not None:
            result = (f'p=pathlib.Path({str(output)!r});p.mkdir(parents=True);'
                      '(p/"RUNNER_RESULT.json").write_text('
                      'json.dumps({"status":"INCOMPLETE_TOOL_EVENT"}));')
        return ('import json,pathlib,subprocess,sys;'
                'child=subprocess.Popen([sys.executable,"-c",'
                '"import time;time.sleep(30)"]);'
                f'pathlib.Path({str(pid_file)!r}).write_text(str(child.pid));'
                f'{result}'
                f'sys.exit({exit_code})')

    def test_preselection_rejects_artifact_from_other_official_contract(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness_file = root / 'fuzzer.c'; harness_file.write_text('int main(void) { return 0; }')
            token = SimpleNamespace(product_issued=True, harness=harness_file.resolve(),
                source_root=root.resolve(),
                contract_kind='OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2',
                contract_sha256='a' * 64, harness_sha256='b' * 64,
                oss_fuzz_revision='c' * 40, upstream_revision='d' * 40,
                upstream_harness_path='fuzzer.c')
            artifact = SimpleNamespace(source_kind='official_oss_fuzz',
                harness_path=str(harness_file), metadata={'official_pin': {
                    'contract_kind': token.contract_kind,
                    'contract_sha256': 'e' * 64,
                    'local_harness_sha256': token.harness_sha256,
                    'oss_fuzz': {'revision': token.oss_fuzz_revision},
                    'upstream_harness': {'revision': token.upstream_revision,
                                         'path': token.upstream_harness_path}}})
            with self.assertRaisesRegex(ValueError, 'Artifact/qualification mismatch'):
                runner.verify_preselection_official_binding(artifact, token, root)
            artifact.metadata['official_pin']['contract_sha256'] = token.contract_sha256
            runner.verify_preselection_official_binding(artifact, token, root)

    def test_catalog_build_preflight_blocks_missing_or_unproven_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir = root / 'evaluation_tools'; tools_dir.mkdir()
            catalog_root = root / 'artifact'
            (catalog_root / 'analysis').mkdir(parents=True)
            source = root / 'source'; source.mkdir()
            receipt = root / 'receipt.json'; receipt.write_text('{}')
            harness = SimpleNamespace(metadata={'run_root': str(catalog_root)})
            with patch.object(runner, 'HERE', tools_dir):
                with self.assertRaisesRegex(ValueError, 'provenance is unavailable'):
                    runner.require_catalog_build_integrity({}, harness, source)
                contract = {'catalog_build_receipt': 'receipt.json',
                            'catalog_build_receipt_sha256': 'a' * 64}
                with patch.object(runner, 'audit_catalog_build', return_value={
                        'status': 'BLOCKED', 'reasons': ['asan: CATALOG_SOURCE_MISMATCH']}):
                    with self.assertRaisesRegex(ValueError, 'Catalog build provenance blocked'):
                        runner.require_catalog_build_integrity(contract, harness, source)

    def test_v2_catalog_preflight_requires_bound_artifact_indirect_sidecar(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir = root / 'evaluation_tools'; tools_dir.mkdir()
            artifact = root / 'artifact'
            (artifact / 'analysis').mkdir(parents=True)
            source = root / 'source'; source.mkdir()
            sidecar = artifact / 'analysis/indirect_edges.jsonl'
            original = root / 'derived_indirect.jsonl'
            original.write_text('{"kind":"function_reference"}\n')
            asan = root / 'asan.bin'; asan.write_bytes(b'asan build')
            coverage = root / 'coverage.bin'; coverage.write_bytes(b'coverage build')
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({
                'schema': 'EVALUATOR_CATALOG_BUILD_RECEIPT_V2',
                'indirect_edges': {'path': str(original.relative_to(root)),
                                   'sha256': runner.digest(original)},
                'roles': {'asan': {'binary': {'sha256': runner.digest(asan)}},
                          'coverage': {'binary': {'sha256': runner.digest(coverage)}}}}))
            contract = {'catalog_build_receipt': 'receipt.json',
                        'catalog_build_receipt_sha256': runner.digest(receipt),
                        'asan_binary': 'asan.bin', 'coverage_fuzzer': 'coverage.bin'}
            harness = SimpleNamespace(metadata={'run_root': str(artifact)})
            with patch.object(runner, 'HERE', tools_dir), \
                 patch.object(runner, 'audit_catalog_build', return_value={
                     'status': 'ATTESTED_RECEIPT_CONSISTENT'}):
                with self.assertRaisesRegex(ValueError, 'indirect'):
                    runner.require_catalog_build_integrity(contract, harness, source)
                sidecar.write_text('{"kind":"wrong"}\n')
                with self.assertRaisesRegex(ValueError, 'indirect'):
                    runner.require_catalog_build_integrity(contract, harness, source)
                sidecar.write_bytes(original.read_bytes())
                self.assertEqual(runner.require_catalog_build_integrity(
                    contract, harness, source)['status'],
                    'ATTESTED_RECEIPT_CONSISTENT')
                coverage.write_bytes(b'different build')
                with self.assertRaisesRegex(ValueError, 'binary'):
                    runner.require_catalog_build_integrity(contract, harness, source)

    def test_blind2_catalog_preflight_rejects_v1_receipt_even_if_internally_consistent(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir = root / 'evaluation_tools'; tools_dir.mkdir()
            artifact = root / 'artifact'; (artifact / 'analysis').mkdir(parents=True)
            source = root / 'source'; source.mkdir()
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'schema': 'EVALUATOR_CATALOG_BUILD_RECEIPT_V1'}))
            contract = {'catalog_build_receipt': 'receipt.json',
                        'catalog_build_receipt_sha256': runner.digest(receipt)}
            harness = SimpleNamespace(metadata={'run_root': str(artifact)})
            with patch.object(runner, 'HERE', tools_dir), \
                 patch.object(runner, 'audit_catalog_build', return_value={
                     'status': 'ATTESTED_RECEIPT_CONSISTENT'}):
                with self.assertRaisesRegex(ValueError, 'V2 Catalog receipt'):
                    runner.require_catalog_build_integrity(contract, harness, source)

    def test_failed_pov_fuzzer_error_is_not_counted_as_success(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = runner.Ledger(started_at=time.time())
            meter = runner.SharedFuzzMeter(ledger, root / 'ledger.json')
            outcome = meter.invoke('SP_FOLLOWUP:test', 'FAILED_POV_SEED', 5,
                                   lambda **_kwargs: {'status': 'ERROR',
                                                      'reason': 'synthetic execution failure'})
            self.assertEqual(outcome['status'], 'ERROR')
            self.assertEqual(meter.records[-1]['result_status'], 'ERROR')
            self.assertEqual(meter.records[-1]['reason'], 'ERROR')

    def test_fuzz_overrun_preserves_crash_and_blocks_later_fuzz_after_restore(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint = root / 'ledger.json'
            ledger = runner.Ledger(started_at=time.time())
            ticks = iter([0.0, 2.5])
            meter = runner.SharedFuzzMeter(ledger, checkpoint, clock=lambda: next(ticks))
            crash = {'status': 'CRASH_OBSERVED_INCOMPLETE',
                     'observed_crash_id': 'synthetic-crash'}
            self.assertEqual(meter.invoke('first', 'FAILED_POV_SEED', 1,
                                          lambda *, seconds: crash), crash)
            self.assertEqual(ledger.fuzz_actual, 1)
            self.assertEqual(ledger.fuzz_physical_actual, 2.5)
            self.assertEqual(ledger.fuzz_overrun_seconds, 1.5)
            self.assertTrue(ledger.fuzz_overrun_blocked)
            self.assertEqual(meter.records[-1]['physical_actual'], 2.5)
            calls = []
            result = meter.invoke('later', 'FAILED_POV_SEED', 1,
                lambda *, seconds: calls.append(seconds))
            self.assertEqual(result['status'], 'PENDING_FUZZ_OVERRUN_LOCKOUT')
            self.assertEqual(calls, [])
            restored = runner.Ledger.restore(checkpoint)
            later = runner.SharedFuzzMeter(restored, checkpoint)
            result = later.invoke('after-restore', 'FAILED_POV_SEED', 1,
                lambda *, seconds: calls.append(seconds))
            self.assertEqual(result['status'], 'PENDING_FUZZ_OVERRUN_LOCKOUT')
            self.assertEqual(calls, [])

    def test_future_physical_debit_preserves_crash_and_allows_remaining_budget(self):
        with TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / 'ledger.json'
            ledger = runner.Ledger(started_at=time.time(),
                                   fuzz_overrun_policy='PHYSICAL_DEBIT_V1')
            ticks = iter([0.0, 301.4, 302.0, 303.0])
            meter = runner.SharedFuzzMeter(ledger, checkpoint, clock=lambda: next(ticks))
            crash = {'status': 'CRASH_OBSERVED_INCOMPLETE',
                     'observed_crash_id': 'synthetic-crash'}
            self.assertEqual(meter.invoke('first', 'FAILED_POV_SEED', 300,
                                          lambda *, seconds: crash), crash)
            self.assertEqual(ledger.fuzz_actual, 300)
            self.assertAlmostEqual(ledger.fuzz_physical_actual, 301.4)
            self.assertAlmostEqual(ledger.fuzz_overrun_seconds, 1.4)
            self.assertFalse(ledger.fuzz_overrun_blocked)
            calls = []
            self.assertEqual(meter.invoke('second', 'FAILED_POV_SEED', 300,
                                          lambda *, seconds: calls.append(seconds)), None)
            self.assertEqual(calls, [300])
            restored = runner.Ledger.restore(checkpoint)
            self.assertEqual(restored.fuzz_overrun_policy, 'PHYSICAL_DEBIT_V1')
            self.assertFalse(restored.fuzz_overrun_blocked)
            self.assertAlmostEqual(restored.fuzz_budget_used(), 302.4)
            self.assertEqual(restored.begin_fuzz('third', 'FAILED_POV_SEED', 300), 300)

    def test_future_physical_debit_stops_only_when_budget_or_measurement_is_unknown(self):
        with TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / 'ledger.json'
            ledger = runner.Ledger(started_at=time.time(),
                                   fuzz_overrun_policy='PHYSICAL_DEBIT_V1')
            ledger.fuzz_physical_actual = 7199.5
            self.assertEqual(ledger.begin_fuzz('no-budget', 'FAILED_POV_SEED', 300), 0)
            self.assertEqual(ledger.pending[-1]['reason'], 'PENDING_FUZZ_BUDGET')
            ledger.fuzz_physical_actual = 0
            self.assertEqual(ledger.begin_fuzz('interrupted', 'FAILED_POV_SEED', 10), 10)
            ledger.checkpoint(checkpoint)
            restored = runner.Ledger.restore(checkpoint)
            self.assertTrue(restored.fuzz_overrun_blocked)
            self.assertEqual(restored.fuzz_physical_actual, 10)
            self.assertEqual(restored.begin_fuzz('next', 'FAILED_POV_SEED', 10), 0)
            self.assertEqual(restored.pending[-1]['reason'], 'PENDING_FUZZ_OVERRUN_LOCKOUT')

    def test_failed_pov_followup_receipt_preserves_fuzzer_error(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            (run / 'corpus/candidate/SP1').mkdir(parents=True)
            point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse', 'target.c',
                                    'target.c:1', 'read', 'bounds', [], 'bytes',
                                    [], [], [], [])
            (run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
            ledger = runner.Ledger(started_at=time.time())
            meter = runner.SharedFuzzMeter(ledger, root / 'ledger.json')
            pov = {'sp_id': 'SP1', 'poc_id': 'POV1'}
            with patch.object(runner, 'crash_free_pov_rows', return_value=[pov]), \
                 patch.object(runner, 'ensure_clean_pov_seed',
                              return_value={'status': 'BOUND_CLEAN_POV'}):
                receipts = runner.run_failed_pov_followups(
                    run, root / 'binary', meter,
                    fuzzer_call=lambda *_args, **_kwargs: {'status': 'ERROR'},
                    replay_command=None)
            self.assertEqual(receipts[0]['status'], 'FUZZ_ERROR')
            self.assertEqual(receipts[0]['termination_reason'], 'ERROR')

    def test_failed_pov_followup_marks_overrun_lockout_as_pending(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            (run / 'corpus/candidate/SP1').mkdir(parents=True)
            point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse', 'target.c',
                                    'target.c:1', 'read', 'bounds', [], 'bytes',
                                    [], [], [], [])
            (run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
            ledger = runner.Ledger(started_at=time.time())
            ledger.fuzz_overrun_blocked = True
            meter = runner.SharedFuzzMeter(ledger, root / 'ledger.json')
            calls = []
            with patch.object(runner, 'crash_free_pov_rows', return_value=[
                    {'sp_id': 'SP1', 'poc_id': 'POV1'}]), \
                 patch.object(runner, 'ensure_clean_pov_seed', return_value={
                     'status': 'BOUND_CLEAN_POV'}):
                receipts = runner.run_failed_pov_followups(
                    run, root / 'binary', meter,
                    fuzzer_call=lambda *_args, **_kwargs: calls.append(1))
            self.assertEqual(receipts[0]['status'], 'PENDING_FUZZ_OVERRUN_LOCKOUT')
            self.assertEqual(receipts[0]['termination_reason'],
                             'PENDING_FUZZ_OVERRUN_LOCKOUT')
            self.assertEqual(calls, [])

    def test_blocked_first_pov_does_not_consume_next_seed_for_same_sp(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            (run / 'corpus/candidate/SP1').mkdir(parents=True)
            point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse', 'target.c',
                                    'target.c:1', 'read', 'bounds', [], 'bytes',
                                    [], [], [], [])
            (run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
            meter = runner.SharedFuzzMeter(runner.Ledger(started_at=time.time()),
                                           root / 'ledger.json')
            fuzzer_calls = []
            def fake_fuzzer(*_args, **_kwargs):
                fuzzer_calls.append(1)
                return {'status': 'ERROR'}
            with patch.object(runner, 'crash_free_pov_rows', return_value=[
                    {'sp_id': 'SP1', 'poc_id': 'POV1'},
                    {'sp_id': 'SP1', 'poc_id': 'POV2'}]), \
                 patch.object(runner, 'ensure_clean_pov_seed', side_effect=[
                     {'status': 'BLOCKED_NO_GENERATED_POV'},
                     {'status': 'BOUND_CLEAN_POV'}]):
                receipts = runner.run_failed_pov_followups(
                    run, root / 'binary', meter, fuzzer_call=fake_fuzzer)
            self.assertEqual(receipts[0]['status'], 'BLOCKED_NO_GENERATED_POV')
            self.assertEqual(receipts[1]['status'], 'FUZZ_ERROR')
            self.assertEqual(len(fuzzer_calls), 1)

    def test_followup_crash_keeps_observed_reproduced_and_verified_separate(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            corpus = run / 'corpus/candidate/SP1'
            corpus.mkdir(parents=True)
            point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse', 'target.c',
                                    'target.c:1', 'read', 'bounds', [], 'bytes',
                                    [], [], [], [])
            (run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
            (run / 'scan.json').write_text(json.dumps({
                'fuzzer_observed_crash_ids': [], 'observed_crash_ids': [],
                'runtime_reproduced_crash_ids': [], 'verified_crash_ids': []}))
            binary = root / 'coverage-fuzzer'
            binary.write_bytes(b'synthetic binary')
            meter = runner.SharedFuzzMeter(runner.Ledger(started_at=time.time()),
                                           root / 'ledger.json')
            def fake_fuzzer(*_args, **_kwargs):
                (corpus / 'crash-a').write_bytes(b'synthetic crash input')
                return {'status': 'CRASH_OBSERVED_INCOMPLETE'}
            observed = RuntimeResult(1, '', 'AddressSanitizer: heap-buffer-overflow',
                                     None, False, 'heap-buffer-overflow',
                                     '#0 in parse', 'SANITIZER_CRASH')
            with patch.object(runner, 'crash_free_pov_rows', return_value=[
                    {'sp_id': 'SP1', 'poc_id': 'POV1'}]), \
                 patch.object(runner, 'ensure_clean_pov_seed', return_value={
                     'status': 'BOUND_CLEAN_POV'}), \
                 patch('vulnerabilityanalysis.runtime.RuntimeExecutor.run',
                       return_value=observed):
                receipts = runner.run_failed_pov_followups(
                    run, binary, meter, fuzzer_call=fake_fuzzer,
                    replay_command=[str(binary), '{input}'])
            self.assertEqual(receipts[0]['new_fuzzer_crash_count'], 1)
            self.assertEqual(receipts[0]['original_replays'][0]['sanitizer'],
                             'heap-buffer-overflow')
            records = list((run / 'runtime/fuzzer_crashes').glob('*.json'))
            self.assertEqual(len(records), 1)
            summary = json.loads((run / 'scan.json').read_text())
            self.assertEqual(summary['fuzzer_observed_crash_ids'], [records[0].stem])
            self.assertEqual(summary['sp_followup_reproduced_crash_ids'],
                             [records[0].stem])
            self.assertEqual(summary['verified_crash_ids'], [])
            central = json.loads(records[0].read_text())
            self.assertEqual(central['status'],
                             'REPRODUCED_ORIGINAL_BINARY_PENDING_ROOT_CAUSE')
            self.assertEqual(central['verification_scope'],
                             'ORIGINAL_BINARY_SANITIZER_ONLY')
            tasks = json.loads((run / 'runtime/reanalysis_requests.json').read_text())
            self.assertEqual(tasks[0]['crash_id'], records[0].stem)
            self.assertEqual(tasks[0]['status'], 'PENDING_SOURCE_CAUSAL_EVIDENCE')
            self.assertEqual(summary['reanalysis_requests'], tasks)

    def test_followup_crash_is_indexed_before_replay_can_fail(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            corpus = run / 'corpus/candidate/SP1'
            corpus.mkdir(parents=True)
            point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse', 'target.c',
                                    'target.c:1', 'read', 'bounds', [], 'bytes',
                                    [], [], [], [])
            (run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
            (run / 'scan.json').write_text(json.dumps({'observed_crash_ids': [],
                                                     'verified_crash_ids': []}))
            binary = root / 'coverage-fuzzer'
            binary.write_bytes(b'synthetic binary')
            meter = runner.SharedFuzzMeter(runner.Ledger(started_at=time.time()),
                                           root / 'ledger.json')
            def fake_fuzzer(*_args, **_kwargs):
                (corpus / 'crash-a').write_bytes(b'synthetic crash input')
                return {'status': 'CRASH_OBSERVED_INCOMPLETE'}
            with patch.object(runner, 'crash_free_pov_rows', return_value=[
                    {'sp_id': 'SP1', 'poc_id': 'POV1'}]), \
                 patch.object(runner, 'ensure_clean_pov_seed', return_value={
                     'status': 'BOUND_CLEAN_POV'}), \
                 patch('vulnerabilityanalysis.runtime.RuntimeExecutor.run',
                       side_effect=TimeoutError('synthetic replay error')):
                with self.assertRaisesRegex(TimeoutError, 'replay error'):
                    runner.run_failed_pov_followups(
                        run, binary, meter, fuzzer_call=fake_fuzzer,
                        replay_command=[str(binary), '{input}'])
            records = list((run / 'runtime/fuzzer_crashes').glob('*.json'))
            self.assertEqual(len(records), 1)
            summary = json.loads((run / 'scan.json').read_text())
            self.assertEqual(summary['fuzzer_observed_crash_ids'], [records[0].stem])
            self.assertEqual(summary['verified_crash_ids'], [])

    def test_followup_replay_without_sanitizer_is_not_reproduced_or_verified(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            corpus = run / 'corpus/candidate/SP1'
            corpus.mkdir(parents=True)
            point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse', 'target.c',
                                    'target.c:1', 'read', 'bounds', [], 'bytes',
                                    [], [], [], [])
            (run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
            (run / 'scan.json').write_text(json.dumps({'verified_crash_ids': []}))
            binary = root / 'coverage-fuzzer'
            binary.write_bytes(b'synthetic binary')
            meter = runner.SharedFuzzMeter(runner.Ledger(started_at=time.time()),
                                           root / 'ledger.json')

            def fake_fuzzer(*_args, **_kwargs):
                (corpus / 'crash-a').write_bytes(b'synthetic crash input')
                return {'status': 'CRASH_OBSERVED_INCOMPLETE'}

            clean = RuntimeResult(0, '', '', None, False, None, None, 'NO_CRASH')
            with patch.object(runner, 'crash_free_pov_rows', return_value=[
                    {'sp_id': 'SP1', 'poc_id': 'POV1'}]), \
                 patch.object(runner, 'ensure_clean_pov_seed', return_value={
                     'status': 'BOUND_CLEAN_POV'}), \
                 patch('vulnerabilityanalysis.runtime.RuntimeExecutor.run',
                       return_value=clean):
                runner.run_failed_pov_followups(
                    run, binary, meter, fuzzer_call=fake_fuzzer,
                    replay_command=[str(binary), '{input}'])
            record = json.loads(next((run / 'runtime/fuzzer_crashes').glob('*.json')).read_text())
            summary = json.loads((run / 'scan.json').read_text())
            self.assertEqual(record['status'], 'ORIGINAL_REPLAY_NOT_REPRODUCED')
            self.assertFalse(summary.get('sp_followup_reproduced_crash_ids'))
            self.assertEqual(summary['verified_crash_ids'], [])
            self.assertFalse((run / 'runtime/reanalysis_requests.json').exists())

    def test_early_bootstrap_requires_pinned_freeze_helpers(self):
        with TemporaryDirectory() as tmp:
            reference = Path(tmp)
            tools = reference / 'tools'
            tools.mkdir()
            names = ('blind2_runner_draft.py', 'blind2_freeze_contract.py',
                     'create_freeze_manifest.py', 'blind2_model_sandbox.py')
            for name in names:
                (tools / name).write_text(f'# {name}\n')
            spec = tools / 'freeze_spec.json'
            spec.write_text('{}')
            manifest = reference / 'public/FREEZE_MANIFEST.json'
            manifest.parent.mkdir()
            entries = [{'root': 'reference', 'group': 'evaluation_tools',
                        'path': f'tools/{name}', 'sha256': runner.digest(tools / name)}
                       for name in names]
            manifest.write_text(json.dumps({'entries': entries}))
            contract = {'freeze_spec': 'tools/freeze_spec.json',
                        'freeze_manifest': 'public/FREEZE_MANIFEST.json',
                        'freeze_spec_sha256': runner.digest(spec),
                        'freeze_manifest_sha256': runner.digest(manifest)}
            runner.verify_preimport_helper_pins(contract, reference, tools,
                                                tools / names[0])
            entries.pop()
            manifest.write_text(json.dumps({'entries': entries}))
            contract['freeze_manifest_sha256'] = runner.digest(manifest)
            with self.assertRaisesRegex(ValueError, 'helper'):
                runner.verify_preimport_helper_pins(contract, reference, tools,
                                                    tools / names[0])

    def test_import_origin_rejects_product_shadowing_evaluation_helper(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / 'tools'
            tools.mkdir()
            product_src = root / 'vulnerabilityanalysis/src'
            (product_src / 'vulnerabilityanalysis').mkdir(parents=True)
            wrong = product_src / 'blind2_budget_guard.py'
            wrong.write_text('')
            with self.assertRaisesRegex(ValueError, 'loaded module'):
                runner.verify_loaded_module_origins({
                    'blind2_budget_guard': SimpleNamespace(__file__=str(wrong))},
                    tools, product_src)

    def test_import_origin_rejects_product_shadowing_yaml(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / 'tools'
            tools.mkdir()
            product_src = root / 'vulnerabilityanalysis/src'
            (product_src / 'vulnerabilityanalysis').mkdir(parents=True)
            wrong = product_src / 'yaml.py'
            wrong.write_text('')
            modules = {name: SimpleNamespace(__file__=str(tools / f'{name}.py'))
                       for name in ('blind_runner_guards', 'blind2_budget_guard',
                                    'blind2_freeze_contract', 'create_freeze_manifest',
                                    'catalog_build_integrity',
                                    'pinned_codex_delta_protocol')}
            modules['yaml'] = SimpleNamespace(__file__=str(wrong))
            with self.assertRaisesRegex(ValueError, 'loaded module origin changed: yaml'):
                runner.verify_loaded_module_origins(modules, tools, product_src)

    def test_execute_bootstrap_reexecs_with_new_empty_bytecode_cache(self):
        with TemporaryDirectory() as tmp:
            cache = Path(tmp) / 'new-cache'
            cache.mkdir()
            with patch.dict(os.environ, {
                    'PYTHONPYCACHEPREFIX': str(Path(tmp) / 'old-cache'),
                    'VA_BLIND2_PYCACHE_PID': 'another-process'}), \
                 patch.object(runner.tempfile, 'mkdtemp', return_value=str(cache)), \
                 patch.object(runner.os, 'execve', side_effect=RuntimeError('reexec')) as launch:
                with self.assertRaisesRegex(RuntimeError, 'reexec'):
                    runner._fresh_execution_pycache()
            executable, argv, environment = launch.call_args.args
            self.assertEqual(executable, runner.sys.executable)
            self.assertEqual(argv[1], '-I')
            self.assertEqual(argv[2:4], ['-X', f'pycache_prefix={cache}'])
            self.assertEqual(argv[4], str(Path(runner.__file__).resolve()))
            self.assertEqual(environment['PYTHONPYCACHEPREFIX'], str(cache))
            self.assertEqual(environment['VA_BLIND2_PYCACHE_PID'], str(os.getpid()))
            self.assertEqual(list(cache.iterdir()), [])

    def test_execute_bootstrap_rejects_prefilled_project_bytecode_cache(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / 'tools'
            product = root / 'product'
            tools.mkdir()
            product.mkdir()
            cache = root / 'cache'
            project_cache = cache / tools.relative_to(tools.anchor)
            project_cache.mkdir(parents=True)
            (project_cache / 'blind2_runner_draft.cpython-312.pyc').write_bytes(b'old')
            with patch.object(runner, 'HERE', tools), \
                 patch.object(runner, 'PRODUCT', product), \
                 patch.object(runner.sys, 'pycache_prefix', str(cache)), \
                 patch.dict(os.environ, {'PYTHONPYCACHEPREFIX': str(cache),
                                         'VA_BLIND2_PYCACHE_PID': str(os.getpid())}):
                with self.assertRaisesRegex(ValueError, 'project bytecode'):
                    runner._fresh_execution_pycache()

    def test_preimport_helper_pins_require_exact_approval_first(self):
        with TemporaryDirectory() as tmp:
            reference = Path(tmp)
            contract = reference / 'contract.json'
            contract.write_text('{}')
            runner_file = reference / 'runner.py'
            runner_file.write_text('# runner\n')
            approval = (reference / 'approval_runs' / runner.digest(contract) /
                        'APPROVAL.json')
            approval.parent.mkdir(parents=True)
            approval.write_text(json.dumps({
                'approved': True, 'contract_sha256': runner.digest(contract),
                'runner_sha256': '0' * 64}))
            with self.assertRaisesRegex(ValueError, 'bootstrap approval'):
                runner.verify_preimport_execution_authority(
                    contract, runner_file, reference, child=False)
            approval.write_text(json.dumps({
                'approved': True, 'contract_sha256': runner.digest(contract),
                'runner_sha256': runner.digest(runner_file)}))
            runner.verify_preimport_execution_authority(
                contract, runner_file, reference, child=False)

    def test_normal_corpus_accepts_contract_selected_count(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = [root / "a", root / "b"]
            for path, data in zip(seeds, [b"one", b"two"]):
                path.write_bytes(data)
            corpus = runner.prepare_prior_corpus(seeds, root / "normal")
            self.assertEqual(len(list(corpus.iterdir())), 2)
            self.assertEqual(len(json.loads((root / "NORMAL_CORPUS_MANIFEST.json").read_text())), 2)
            run = root / "run"; run.mkdir()
            pov = run / "pov.bin"; pov.write_bytes(b"candidate")
            bound = runner.ensure_clean_pov_seed(
                run, {"sp_id": "SP1", "generated_input": str(pov)}, corpus)
            self.assertEqual(bound["status"], "BOUND_CLEAN_POV")
            self.assertEqual(bound["normal_seed_count"], 2)

    def test_official_harness_name_comes_from_contract(self):
        contract = {
            "artifact": "model_target/attempt",
            "official_harness_contract": "public/OFFICIAL_HARNESS_CONTRACT.json",
            "official_harness_contract_sha256": "a" * 64,
            "official_harness_path": "model_target/attempt/new_fuzzer.cc",
            "target_repository": "model_target/source",
            "asan_binary": "model_target/attempt/asan_binary",
            "assertion_seed": "model_target/attempt/seed",
        }
        token = SimpleNamespace(product_issued=True)
        with TemporaryDirectory() as tmp:
            pinned_contract = Path(tmp) / 'official.json'
            pinned_contract.write_text('{"kind":"OFFICIAL_OSS_FUZZ_HARNESS_V1"}')
            with patch.object(runner, "resolve_reference_file",
                              side_effect=lambda value: pinned_contract if value ==
                              'public/OFFICIAL_HARNESS_CONTRACT.json' else Path('/tmp/pinned')), \
                 patch.object(runner, "issue_official_pinned_qualification",
                              return_value=token):
                self.assertIs(runner.require_official_qualification(contract), token)

    def test_v2_official_harness_passes_both_checkouts_to_product_issuer(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir = root / 'evaluation_tools'; tools_dir.mkdir()
            oss = root / 'oss-fuzz'; oss.mkdir()
            upstream = root / 'upstream'; upstream.mkdir()
            pinned_contract = root / 'official.json'
            pinned_contract.write_text('{"kind":"OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"}')
            contract = {
                'artifact': 'staged/attempt',
                'official_harness_contract': 'public/OFFICIAL_HARNESS_CONTRACT.json',
                'official_harness_contract_sha256': 'a' * 64,
                'official_harness_path': 'staged/attempt/upstream_fuzzer.c',
                'target_repository': 'model_target/source',
                'asan_binary': 'model_target/attempt/asan_binary',
                'assertion_seed': 'model_target/attempt/seed',
                'oss_fuzz_checkout': 'oss-fuzz',
                'upstream_checkout': 'upstream',
            }
            token = SimpleNamespace(product_issued=True)
            with patch.object(runner, 'HERE', tools_dir), \
                 patch.object(runner, 'resolve_reference_file',
                              side_effect=lambda value: pinned_contract if value ==
                              'public/OFFICIAL_HARNESS_CONTRACT.json' else root / 'pinned'), \
                 patch.object(runner, 'issue_official_pinned_qualification',
                              return_value=token) as issuer:
                self.assertIs(runner.require_official_qualification(contract), token)
            self.assertEqual(issuer.call_args.kwargs['oss_fuzz_checkout'], oss)
            self.assertEqual(issuer.call_args.kwargs['upstream_checkout'], upstream)

    def test_prequeued_model_text_is_visible_to_retry_guard(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = runner.Ledger(started_at=time.time())
            client = runner.GuardedAppServer(
                ledger=ledger, checkpoint=root / "ledger.json",
                route_sha256="a" * 64, role_models={}, cwd=root,
                codex_executable_path=root / 'unused-codex',
                codex_executable_sha256='a' * 64)
            client._notifications.extend([
                {"method": "item/agentMessage/delta", "params": {
                    "threadId": "t", "turnId": "v", "itemId": "i",
                    "delta": "visible text"}},
                {"method": "turn/completed", "params": {
                    "threadId": "t", "turn": {"id": "v", "status": "completed"}}},
            ])
            self.assertEqual(asyncio.run(client._collect("t", "v")), "visible text")
            self.assertTrue(client.visible_output)

    def test_timeout_is_reported_as_incomplete(self):
        self.assertEqual(runner.classify_scan_interruption(TimeoutError("expired")),
                         "INCOMPLETE_TIMEOUT")
        self.assertEqual(runner.classify_scan_interruption(
            runner.AppServerError("app-server turn wall deadline exceeded")),
            "INCOMPLETE_TIMEOUT")
        self.assertEqual(runner.classify_scan_interruption(
            runner.ModelToolEventError("FORBIDDEN_MODEL_TOOL_EVENT: commandExecution")),
            "INCOMPLETE_TOOL_EVENT")
        self.assertEqual(runner.classify_scan_interruption(
            runner.ProviderSafetyRefusedError("PROVIDER_SAFETY_REFUSED: role=function_analysis")),
            "PROVIDER_SAFETY_REFUSED")
        self.assertEqual(runner.classify_scan_interruption(
            runner.ModelAuditError("MODEL_AUDIT_WRITE_FAILED: synthetic")),
            "INCOMPLETE_AUDIT_ERROR")

    def test_provider_safety_report_counts_explicit_metadata_only(self):
        backend = runner.CodexAppServerClient(cwd=Path.cwd())
        backend.safety_buffering_summaries = [
            {'thread_id': 't1', 'turn_id': 'v1',
             'buffered': True, 'buffer_to_turn_end_seconds': 270.25,
             'buffer_to_stop_seconds': None,
             'role': 'function_analysis',
             'reasons': ['user_risk'], 'use_cases': ['bio'],
             'turn_status': 'completed'},
            {'thread_id': 't2', 'turn_id': 'v2',
             'buffered': True, 'buffer_to_turn_end_seconds': None,
             'buffer_to_stop_seconds': 1.5,
             'role': 'sp_generation',
             'reasons': ['user_risk'], 'use_cases': [],
             'turn_status': 'provider_safety_refused'},
        ]
        backend.provider_safety_refusal_records = [
            {'classification': 'PROVIDER_SAFETY_REFUSED', 'role': 'sp_generation',
             'thread_id': 't2', 'turn_id': 'v2'}]
        report = runner.build_provider_safety_report(backend)
        self.assertEqual(report['safety_event_turn_count'], 2)
        self.assertEqual(report['buffered_turn_count'], 2)
        self.assertEqual(report['buffered_incomplete_turn_count'], 1)
        self.assertEqual(report['buffer_to_turn_end_seconds_total'], 270.25)
        self.assertEqual(report['buffer_to_stop_seconds_total'], 1.5)
        self.assertEqual(report['provider_safety_refused_count'], 1)

    def test_pre_response_safety_event_is_censored_not_reported_as_zero(self):
        backend = runner.CodexAppServerClient(cwd=Path.cwd())
        backend.safety_notification_observations = {('t', 'v'): True}
        backend.structured_safety_block_observations = {('t2', 'v2')}
        report = runner.build_provider_safety_report(backend)
        self.assertFalse(report['aggregate_complete'])
        self.assertEqual(report['status'], 'CHILD_CENSORED_BEFORE_COLLECT')
        self.assertEqual(report['safety_event_turn_count'], 1)
        self.assertEqual(report['buffered_turn_count'], 0)
        self.assertEqual(report['buffered_turn_count_lower_bound'], 1)
        self.assertEqual(report['duration_censored_turn_count'], 1)
        self.assertEqual(report['provider_safety_refused_count'], 0)
        self.assertEqual(report['provider_safety_refused_count_lower_bound'], 1)
        self.assertEqual(report['unclassified_block_observation_count'], 1)

    def test_parent_fallback_marks_hard_stopped_buffer_duration_censored(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            rows = [
                {'item_type': None, 'method': 'model/safetyBuffering/updated',
                 'thread_id': 't', 'turn_id': 'v',
                 'params': {'showBufferingUi': True}},
                {'item_type': 'agentMessage', 'method': 'item/completed',
                 'params': {'text': 'model/safetyBuffering/updated'}},
                {'classification': 'PROVIDER_SAFETY_REFUSED',
                 'thread_id': 't2', 'turn_id': 'v2'},
            ]
            (output / 'MODEL_EVENT_TYPES.jsonl').write_text(''.join(
                json.dumps(row, sort_keys=True) + '\n' for row in rows))
            runner.ensure_model_safety_summary(output)
            summary = json.loads((output / 'MODEL_SAFETY_SUMMARY.json').read_text())
            self.assertFalse(summary['aggregate_complete'])
            self.assertEqual(summary['safety_event_turn_count_lower_bound'], 1)
            self.assertEqual(summary['buffered_turn_count_lower_bound'], 1)
            self.assertEqual(summary['provider_safety_refused_count_lower_bound'], 1)
            self.assertEqual(summary['duration_censored_turn_count'], 1)
            self.assertEqual(summary['buffer_to_turn_end_seconds_total_observed'], 0)

    def test_parent_fallback_preserves_raw_block_before_child_classification(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            blocked = {
                'threadId': 't', 'turnId': 'v',
                'metadata': {
                    'generation': {'result': {'is_blocked': True}},
                    'prompt': {}, 'tool_call': {}, 'tool_response': {},
                },
            }
            rows = [
                {'item_type': None, 'method': 'turn/moderationMetadata',
                 'thread_id': 't', 'turn_id': 'v', 'params': blocked},
                {'item_type': None, 'method': 'turn/moderationMetadata',
                 'thread_id': 'other', 'turn_id': 'v', 'params': blocked},
            ]
            (output / 'MODEL_EVENT_TYPES.jsonl').write_text(''.join(
                json.dumps(row, sort_keys=True) + '\n' for row in rows))
            runner.ensure_model_safety_summary(output)
            summary = json.loads((output / 'MODEL_SAFETY_SUMMARY.json').read_text())
            self.assertFalse(summary['aggregate_complete'])
            self.assertEqual(summary['provider_safety_refused_count_lower_bound'], 1)
            self.assertEqual(summary['raw_structured_block_turn_count'], 1)

    def test_parent_fallback_keeps_large_block_marker_without_full_params(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            row = {'item_type': None, 'method': 'turn/moderationMetadata',
                   'thread_id': 't', 'turn_id': 'v',
                   'structured_safety_block_observed': True,
                   'params_sha256': 'a' * 64, 'params_omitted_bytes': 5000}
            (output / 'MODEL_EVENT_TYPES.jsonl').write_text(
                json.dumps(row, sort_keys=True) + '\n')
            (output / 'MODEL_SAFETY_SUMMARY.json').write_text(
                '{"status":"PARENT_FALLBACK_AFTER_CHILD_STOP"}')
            runner.ensure_model_safety_summary(output)
            summary = json.loads((output / 'MODEL_SAFETY_SUMMARY.json').read_text())
            self.assertEqual(summary['provider_safety_refused_count_lower_bound'], 1)
            self.assertEqual(summary['raw_structured_block_turn_count'], 1)
            self.assertIsNotNone(summary.get('prior_partial_summary_sha256'))

    def test_parent_fallback_keeps_structured_failed_turn_refusal(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            row = {'item_type': None, 'method': 'turn/completed',
                   'thread_id': 't', 'turn_id': 'v',
                   'structured_safety_refusal_observed': True,
                   'params_sha256': 'b' * 64, 'params_omitted_bytes': 5000}
            (output / 'MODEL_EVENT_TYPES.jsonl').write_text(
                json.dumps(row, sort_keys=True) + '\n')
            runner.ensure_model_safety_summary(output)
            summary = json.loads((output / 'MODEL_SAFETY_SUMMARY.json').read_text())
            self.assertEqual(summary['provider_safety_refused_count_lower_bound'], 1)
            self.assertEqual(summary['raw_structured_block_turn_count'], 1)

    def test_model_audit_failure_escapes_hp_handler_and_stops_selection(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'; run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'synthetic_fn'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = runner.GuardedAppServer(
                ledger=ledger, checkpoint=root / 'ledger.json',
                route_sha256='a' * 64,
                role_models={'function_analysis': {
                    'model': 'gpt-5.6-sol', 'reasoning': 'max'}},
                cwd=root, model='gpt-5.6-sol', effort='max',
                codex_executable_path=root / 'unused-codex',
                codex_executable_sha256='a' * 64)
            statuses = []
            continued = []

            async def fake_model_generate(client, _request):
                client.ledger.start_attempt(client.request_hash)
                client.accepted_turn_id = 'synthetic-turn'
                client.audit_log_failed = True
                raise runner.ModelAuditError('MODEL_AUDIT_WRITE_FAILED: synthetic')

            async def fake_scan(_folder, active_provider, **_kwargs):
                request = SimpleNamespace(
                    role='function_analysis', instructions='source-free synthetic',
                    payload={}, output_schema={'type': 'object'},
                    session_key=None, model='gpt-5.6-sol', effort='max',
                    raw_response_path=None)
                try:
                    await active_provider.generate(request)
                except Exception:
                    continued.append(True)

            def checkpoint(_run, status, _ledger):
                statuses.append(status)
                return root / 'checkpoint'

            with patch.object(runner.CodexAppServerClient, 'generate', fake_model_generate), \
                 patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'continue_phase1') as next_function, \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaises(runner.FatalModelAuditFailure):
                    asyncio.run(runner.run_sequence(
                        run, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            self.assertEqual(continued, [])
            self.assertEqual(statuses, ['INCOMPLETE_AUDIT_ERROR'])
            self.assertEqual(ledger.physical, 1)
            next_function.assert_not_called()

    def test_parent_fallback_preserves_partial_safety_summary_before_rebuilding(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            original = b'{"aggregate_complete": true'
            (output / 'MODEL_SAFETY_SUMMARY.json').write_bytes(original)
            (output / 'MODEL_EVENT_TYPES.jsonl').write_text('')
            runner.ensure_model_safety_summary(output)
            rebuilt = json.loads((output / 'MODEL_SAFETY_SUMMARY.json').read_text())
            self.assertFalse(rebuilt['aggregate_complete'])
            self.assertEqual(rebuilt['prior_partial_summary_sha256'],
                             hashlib.sha256(original).hexdigest())
            partial = Path(rebuilt['prior_partial_summary_path'])
            self.assertEqual(partial.read_bytes(), original)
            self.assertEqual(rebuilt['prior_partial_summary_error_type'],
                             'JSONDecodeError')

    def test_parent_route_uses_empty_temporary_model_cwd(self):
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            root = workspace / 'prep'
            root.mkdir()
            source = root / 'model_target' / 'source'
            source.mkdir(parents=True)
            (source / '.git').mkdir()
            (workspace / 'blind2_candidate_20261027' / 'evaluator_only').mkdir(parents=True)
            (workspace / 'product').mkdir()
            config = root / 'private' / 'config.toml'
            config.parent.mkdir()
            config.write_text('model="test"')
            tools_dir = root / 'evaluation_tools'
            tools_dir.mkdir()
            seen = []

            class RouteClient:
                def __init__(self, **kwargs):
                    seen.append(kwargs)
                    self.cwd = kwargs['cwd']

                async def __aenter__(self):
                    assert self.cwd.is_dir() and not any(self.cwd.iterdir())
                    return self

                async def __aexit__(self, *_args):
                    return None

            async def route(_client, _digest, _models):
                return None

            @contextmanager
            def state(_config):
                yield root / 'private-state'

            with patch.object(runner, 'HERE', tools_dir), \
                 patch.object(runner, 'PRODUCT', workspace / 'product'), \
                 patch.object(runner, 'private_codex_state', state), \
                 patch.object(runner, 'verify_pinned_codex_executable',
                              return_value=Path('/usr/bin/true')), \
                 patch.object(runner, 'verify_model_namespace_sandbox',
                              return_value={'cwd_is_empty_work': True}), \
                 patch.object(runner, 'CodexAppServerClient', RouteClient), \
                 patch.object(runner, 'check_live_route', route):
                runner.verify_parent_route({
                    'target_repository': 'model_target/source',
                    'codex_config': 'private/config.toml',
                    'default_model': 'test', 'default_effort': 'low',
                    'codex_executable_sha256': 'a' * 64,
                    'route_sha256': 'a' * 64, 'role_models': {}})
            self.assertEqual(len(seen), 1)
            self.assertNotEqual(seen[0]['cwd'], source)
            self.assertFalse(seen[0]['cwd'].exists())
            self.assertEqual(seen[0]['launch_prefix'][1],
                             str(tools_dir / 'blind2_model_sandbox.py'))
            self.assertEqual(seen[0]['executable'], '/usr/bin/true')
            self.assertEqual(seen[0]['executable_sha256'], 'a' * 64)

    def test_child_model_cwd_is_removed_after_execution(self):
        captured = []

        @contextmanager
        def state(_config):
            yield None

        async def inside(_contract, _output, model_cwd):
            self.assertTrue(model_cwd.is_dir())
            self.assertEqual(list(model_cwd.iterdir()), [])
            captured.append(model_cwd)
            return [{'status': 'DRY_TEST'}]

        with TemporaryDirectory() as tmp, \
             patch.object(runner, 'private_codex_state', state), \
             patch.object(runner, '_execute_live_with_cwd', inside):
            rows = asyncio.run(runner.execute_live({'codex_config': 'config'}, Path(tmp) / 'out'))
        self.assertEqual(rows, [{'status': 'DRY_TEST'}])
        self.assertFalse(captured[0].exists())

    def test_namespace_self_test_blocks_missing_or_unverified_launcher(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            launcher = root / 'blind2_model_sandbox.py'
            launcher.write_text('# synthetic launcher, never executed')
            denied = tuple(root / name for name in ('reference', 'product', 'target',
                                                    'git', 'evaluator_only'))
            for path in denied:
                path.mkdir()
            expected = {'cwd_is_empty_work': True, 'host_home_hidden': True,
                        'host_mnt_hidden': True, 'model_state_copied': True,
                        'private_proc': True, 'capabilities_dropped': True,
                        'contract_paths_hidden': True}
            response = SimpleNamespace(returncode=0, stdout=json.dumps({
                'status': 'PASS', 'checks': expected, 'deny_path_count': len(denied)}))
            with patch.object(runner, 'HERE', root), \
                 patch.object(runner.subprocess, 'run', return_value=response) as call:
                self.assertEqual(runner.verify_model_namespace_sandbox(
                    Path('/usr/bin/true'), denied), expected)
            self.assertIn('--self-test', call.call_args.args[0])
            self.assertEqual(call.call_args.args[0].count('--deny-path'), len(denied))
            response = SimpleNamespace(returncode=0, stdout=json.dumps({
                'status': 'PASS', 'checks': {**expected, 'host_home_hidden': False},
                'deny_path_count': len(denied)}))
            with patch.object(runner, 'HERE', root), \
                 patch.object(runner.subprocess, 'run', return_value=response):
                with self.assertRaisesRegex(ValueError, 'isolation self-test failed'):
                    runner.verify_model_namespace_sandbox(Path('/usr/bin/true'), denied)
            launcher.unlink()
            with patch.object(runner, 'HERE', root):
                with self.assertRaisesRegex(ValueError, 'launcher unavailable'):
                    runner.verify_model_namespace_sandbox(Path('/usr/bin/true'), denied)

    def test_namespace_self_test_requires_actual_contract_paths(self):
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            root = workspace / 'prep'; root.mkdir()
            tools = root / 'evaluation_tools'; tools.mkdir()
            product = workspace / 'product'; product.mkdir()
            target = root / 'model_target'; target.mkdir()
            (target / '.git').mkdir()
            evaluator = workspace / 'blind2_candidate_20261027' / 'evaluator_only'
            evaluator.mkdir(parents=True)
            with patch.object(runner, 'HERE', tools), patch.object(runner, 'PRODUCT', product):
                paths = runner._protected_model_paths({'target_repository': 'model_target'})
            self.assertEqual(paths, (root, product, target, target / '.git', evaluator))
            evaluator.rmdir()
            with patch.object(runner, 'HERE', tools), patch.object(runner, 'PRODUCT', product):
                with self.assertRaises(FileNotFoundError):
                    runner._protected_model_paths({'target_repository': 'model_target'})

    def test_preapproval_route_has_physical_deadline_and_group_cleanup(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'pid'
            script = ('import os,signal,time;'
                      'signal.signal(signal.SIGTERM, signal.SIG_IGN);'
                      f'open({str(marker)!r}, "w").write(str(os.getpid()));'
                      'time.sleep(30)')
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(runner._bounded_preapproval_process,
                    [sys.executable, '-c', script], timeout_seconds=3)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not marker.is_file():
                    if future.done():
                        break
                    time.sleep(.02)
                self.assertTrue(marker.is_file(), 'route child did not start')
                with self.assertRaisesRegex(TimeoutError, 'physical wall deadline'):
                    future.result(timeout=10)
            self.assertLess(time.monotonic() - started, 10)
            self._assert_descendant_stopped(int(marker.read_text()))

    def test_preapproval_route_error_kills_descendant_after_leader_exits(self):
        with TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / 'descendant.pid'
            script = self._exiting_parent_with_descendant(pid_file)
            with self.assertRaisesRegex(ValueError, 'failed before approval'):
                runner._bounded_preapproval_process([sys.executable, '-c', script],
                                                    timeout_seconds=5)
            self._assert_descendant_stopped(int(pid_file.read_text()))

    def test_preapproval_route_success_kills_descendant_after_leader_exits(self):
        with TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / 'descendant.pid'
            script = self._exiting_parent_with_descendant(pid_file, exit_code=0)
            runner._bounded_preapproval_process([sys.executable, '-c', script],
                                                timeout_seconds=5)
            self._assert_descendant_stopped(int(pid_file.read_text()))

    def test_preapproval_route_child_reuses_early_freeze_checks(self):
        with TemporaryDirectory() as tmp:
            contract = Path(tmp) / 'contract.json'
            contract.write_text('{}')
            with patch.object(runner, '_bounded_preapproval_process') as bounded:
                runner.supervise_preapproval_route(contract)
            command = bounded.call_args.args[0]
            self.assertEqual(command[:2], [sys.executable, '-I'])
            self.assertIn('--execute', command)
            self.assertIn('--route-probe', command)
            self.assertEqual(command[-2:], ['--contract', str(contract.resolve())])

    def test_tool_event_stop_records_prior_checkpoints_and_unselected_slots(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            prior = output / 'runs' / 'function_0' / 'FUNCTION_CHECKPOINT.json'
            prior.parent.mkdir(parents=True)
            prior.write_text(json.dumps({'status': 'COMPLETE'}))
            budget = output / 'BUDGET_CHECKPOINT.json'
            budget.write_text('{}')
            runner.record_tool_event_stop(output, max_functions=3)
            result = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(result['status'], 'INCOMPLETE_TOOL_EVENT')
            self.assertEqual(result['processed_function_count'], 1)
            self.assertEqual(result['remaining_selection_slots'], 2)
            self.assertEqual(result['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(result['function_checkpoints'][0]['sha256'], runner.digest(prior))
            self.assertEqual(result['budget_checkpoint_sha256'], runner.digest(budget))

    def test_provider_safety_stop_keeps_prior_checkpoints_and_no_opportunity(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            prior = output / 'runs' / 'function_0' / 'FUNCTION_CHECKPOINT.json'
            prior.parent.mkdir(parents=True)
            prior.write_text(json.dumps({'status': 'COMPLETE'}))
            runner.record_provider_safety_stop(output, max_functions=3)
            result = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(result['status'], 'PROVIDER_SAFETY_REFUSED')
            self.assertEqual(result['processed_function_count'], 1)
            self.assertEqual(result['remaining_selection_slots'], 2)
            self.assertEqual(result['remaining_selection_status'], 'NO_OPPORTUNITY')

    def test_supervisor_preserves_tool_event_stop_marker_on_child_error(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            script = ('import json,pathlib,sys;'
                      f'p=pathlib.Path({str(output)!r});'
                      'p.mkdir(parents=True);'
                      '(p/"RUNNER_RESULT.json").write_text('
                      'json.dumps({"status":"INCOMPLETE_TOOL_EVENT"}));'
                      'sys.exit(7)')
            status = runner.supervise_child([sys.executable, '-c', script], output,
                                            timeout_seconds=5)
            self.assertEqual(status, 'INCOMPLETE_TOOL_EVENT')
            self.assertEqual(json.loads((output / 'RUNNER_RESULT.json').read_text()),
                             {'status': 'INCOMPLETE_TOOL_EVENT'})

    def test_supervisor_preserves_cancelled_stop_and_prior_checkpoint(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            checkpoint = output / 'runs' / 'fn' / 'FUNCTION_CHECKPOINT.json'
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text(json.dumps({'status': 'INCOMPLETE_CANCELLED'}))
            runner_dir = str(Path(runner.__file__).resolve().parent)
            script = (f'import pathlib,sys;sys.path.insert(0,{runner_dir!r});'
                      'import blind2_runner_draft as r;'
                      f'r.record_cancelled_stop(pathlib.Path({str(output)!r}),'
                      'max_functions=3);sys.exit(7)')
            status = runner.supervise_child([sys.executable, '-c', script], output,
                                            timeout_seconds=5)
            self.assertEqual(status, 'INCOMPLETE_CANCELLED')
            result = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(result['status'], 'INCOMPLETE_CANCELLED')
            self.assertEqual(result['remaining_selection_slots'], 2)
            self.assertEqual(result['function_checkpoints'][0]['sha256'], runner.digest(checkpoint))

    def test_supervisor_preserves_runtime_cleanup_failure_stop(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            checkpoint = output / 'fn1' / 'FUNCTION_CHECKPOINT.json'
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text(json.dumps({'status': 'STOPPED_CLEANUP_INCOMPLETE'}))
            runner_dir = str(Path(runner.__file__).resolve().parent)
            script = (f'import pathlib,sys;sys.path.insert(0,{runner_dir!r});'
                      'import blind2_runner_draft as r;'
                      f'r.record_cleanup_incomplete_stop(pathlib.Path({str(output)!r}),'
                      'max_functions=3);sys.exit(7)')
            status = runner.supervise_child([sys.executable, '-c', script], output,
                                            timeout_seconds=5)
            self.assertEqual(status, 'STOPPED_CLEANUP_INCOMPLETE')
            result = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(result['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(result['remaining_selection_slots'], 2)
            self.assertEqual(result['function_checkpoints'][0]['sha256'], runner.digest(checkpoint))

    def test_supervisor_preserves_physical_ledger_stop(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            checkpoint = output / 'fn1' / 'FUNCTION_CHECKPOINT.json'
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text(json.dumps({'status': 'STOPPED_PHYSICAL_LEDGER_ERROR'}))
            runner_dir = str(Path(runner.__file__).resolve().parent)
            script = (f'import pathlib,sys;sys.path.insert(0,{runner_dir!r});'
                      'import blind2_runner_draft as r;'
                      f'r.record_physical_fuzz_stop(pathlib.Path({str(output)!r}),'
                      '"STOPPED_PHYSICAL_LEDGER_ERROR",max_functions=3);sys.exit(7)')
            status = runner.supervise_child([sys.executable, '-c', script], output,
                                            timeout_seconds=5)
            self.assertEqual(status, 'STOPPED_PHYSICAL_LEDGER_ERROR')
            result = json.loads((output / 'RUNNER_RESULT.json').read_text())
            self.assertEqual(result['status'], 'STOPPED_PHYSICAL_LEDGER_ERROR')
            self.assertEqual(result['remaining_selection_status'], 'NO_OPPORTUNITY')
            self.assertEqual(result['function_checkpoints'][0]['sha256'], runner.digest(checkpoint))

    def test_child_records_cancel_or_fuzz_accounting_marker_before_exit(self):
        for error, expected in (
            (asyncio.CancelledError('ordinary cancellation'), 'INCOMPLETE_CANCELLED'),
            (asyncio.CancelledError('cancel with failed settlement'),
             'INCOMPLETE_CANCELLED'),
            (TimeoutError('timeout with failed settlement'),
             'INCOMPLETE_TIMEOUT'),
            (OSError('tool failed with unsettled fuzz'),
             'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE'),
        ):
            with self.subTest(error=repr(error)), \
                 TemporaryDirectory(dir=runner.HERE.parent / 'runs') as tmp:
                if 'failed settlement' in str(error) or \
                        expected == 'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE':
                    error.fuzz_accounting_failed = True
                root = Path(tmp)
                contract = root / 'contract.json'; contract.write_text('{}')
                consumed = root / 'consumed.json'
                consumed.write_text(json.dumps({
                    'contract_sha256': runner.digest(contract),
                    'runner_sha256': runner.digest(Path(runner.__file__))}))
                output = root / 'output'

                async def fail_live(*_args):
                    raise error

                argv = ['runner', '--execute', '--child', '--contract',
                        str(contract), '--output', str(output)]
                with patch.object(sys, 'argv', argv), \
                     patch.object(runner, 'preflight_live', return_value={}), \
                     patch.object(runner, 'approval_record_paths',
                                  return_value=(root / 'approval', consumed,
                                                root / 'launch')), \
                     patch.object(runner, 'claim_child_launch'), \
                     patch.object(runner, 'execute_live', fail_live):
                    with self.assertRaises(type(error)):
                        runner.main()
                result = json.loads((output / 'RUNNER_RESULT.json').read_text())
                self.assertEqual(result['status'], expected)

    def test_supervisor_error_kills_descendant_and_preserves_tool_marker(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'run'
            pid_file = Path(tmp) / 'descendant.pid'
            script = self._exiting_parent_with_descendant(pid_file, output)
            status = runner.supervise_child([sys.executable, '-c', script], output,
                                            timeout_seconds=5)
            self.assertEqual(status, 'INCOMPLETE_TOOL_EVENT')
            self.assertEqual(json.loads((output / 'RUNNER_RESULT.json').read_text()),
                             {'status': 'INCOMPLETE_TOOL_EVENT'})
            self._assert_descendant_stopped(int(pid_file.read_text()))

    def test_codex_cli_path_and_sha_are_pinned_before_launch(self):
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'codex-static'
            binary.write_bytes(b'first synthetic executable')
            binary.chmod(0o700)
            contract = {'codex_executable_path': str(binary),
                        'codex_executable_sha256': runner.digest(binary)}
            with patch.object(runner.shutil, 'which', return_value=str(binary)):
                self.assertEqual(runner.verify_pinned_codex_executable(contract), binary)
                binary.write_bytes(b'changed synthetic executable')
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    runner.verify_pinned_codex_executable(contract)
            binary.write_bytes(b'first synthetic executable')
            alternate = Path(tmp) / 'alternate-codex'
            alternate.write_bytes(binary.read_bytes())
            alternate.chmod(0o700)
            with patch.object(runner.shutil, 'which', return_value=str(alternate)):
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    runner.verify_pinned_codex_executable(contract)
            with self.assertRaisesRegex(ValueError, 'must be frozen'):
                runner.verify_pinned_codex_executable({})

    def test_zero_retry_config_rejects_declared_model_tools(self):
        minimal = ('model="synthetic"\nmodel_provider="p"\n'
                   'model_reasoning_effort="low"\n'
                   '[model_providers.p]\nname="OpenAI"\nwire_api="responses"\n'
                   'requires_openai_auth=true\nsupports_websockets=false\n'
                   'request_max_retries=0\nstream_max_retries=0\n'
                   '[features]\napps=false\n')
        with TemporaryDirectory() as tmp:
            config = Path(tmp) / 'codex.toml'
            config.write_text(minimal)
            runner.check_zero_retry_config(config, 'synthetic', 'low')
            invalid = (
                minimal + '[mcp_servers.local]\ncommand="tool"\n',
                minimal + '[mcp_servers.codex_apps]\nenabled=false\n',
                minimal.replace('apps=false', 'apps=true'),
                minimal.replace('apps=false', 'apps=0'),
                minimal.replace('apps=false', 'apps=false\nshell_tool=true'),
                minimal.replace('[features]\napps=false\n',
                                '[apps._default]\nenabled=false\n'),
            )
            for candidate in invalid:
                with self.subTest(candidate=candidate):
                    config.write_text(candidate)
                    with self.assertRaisesRegex(ValueError, 'configuration changed'):
                        runner.check_zero_retry_config(config, 'synthetic', 'low')

    def test_pinned_asan_symbolizer_sets_only_matching_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            symbolizer = root / 'llvm-symbolizer'
            symbolizer.write_bytes(b'synthetic symbolizer')
            symbolizer.chmod(0o700)
            library = root / 'libLLVM.so.18.1'
            library.write_bytes(b'synthetic libLLVM')
            library_alias = root / 'libLLVM-loader-alias'
            library_alias.symlink_to(library)
            contract = {
                'asan_symbolizer_path': str(symbolizer),
                'asan_symbolizer_sha256': runner.digest(symbolizer),
                'asan_symbolizer_libllvm_path': str(library),
                'asan_symbolizer_libllvm_sha256': runner.digest(library),
                'asan_symbolizer_libllvm_alias': str(library_alias),
            }
            with patch.dict(os.environ, {'ASAN_SYMBOLIZER_PATH': '',
                                         'LLVM_SYMBOLIZER_PATH': ''}):
                self.assertEqual(runner.verify_pinned_asan_symbolizer(contract), symbolizer)
                self.assertEqual(os.environ['ASAN_SYMBOLIZER_PATH'], str(symbolizer))
                self.assertEqual(os.environ['LLVM_SYMBOLIZER_PATH'], str(symbolizer))
                with patch.dict(os.environ, {'ASAN_SYMBOLIZER_PATH': '/wrong'}):
                    with self.assertRaisesRegex(ValueError, 'conflicts'):
                        runner.verify_pinned_asan_symbolizer(contract)
            with self.assertRaisesRegex(ValueError, 'missing'):
                runner.verify_pinned_asan_symbolizer({})
            symbolizer.write_bytes(b'changed synthetic symbolizer')
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                runner.verify_pinned_asan_symbolizer(contract)
            symbolizer.write_bytes(b'synthetic symbolizer')
            library.write_bytes(b'changed synthetic libLLVM')
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                runner.verify_pinned_asan_symbolizer(contract)
            library.write_bytes(b'synthetic libLLVM')
            library_alias.unlink()
            library_alias.symlink_to(symbolizer)
            with self.assertRaisesRegex(ValueError, 'loader alias changed'):
                runner.verify_pinned_asan_symbolizer(contract)
            library_alias.unlink()
            library_alias.symlink_to(library)
            link = root / 'symbolizer-link'
            link.symlink_to(symbolizer)
            contract['asan_symbolizer_path'] = str(link)
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                runner.verify_pinned_asan_symbolizer(contract)

    def test_guarded_provider_rechecks_cli_on_every_physical_start(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'codex-static'
            binary.write_bytes(b'original synthetic executable')
            binary.chmod(0o700)
            client = runner.GuardedAppServer(
                ledger=runner.Ledger(started_at=time.time()),
                checkpoint=root / 'ledger.json', route_sha256='a' * 64,
                role_models={}, cwd=root, executable=str(binary),
                codex_executable_path=binary,
                codex_executable_sha256=runner.digest(binary))
            starts = []

            async def fake_start(_client):
                starts.append(True)

            with patch.object(runner.shutil, 'which', return_value=str(binary)), \
                 patch.object(runner.CodexAppServerClient, 'start', fake_start):
                asyncio.run(client.start())
                binary.write_bytes(b'changed synthetic executable')
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    asyncio.run(client.start())
            self.assertEqual(starts, [True])

    def test_private_codex_state_copies_and_removes_credentials(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            auth = root / '.codex' / 'auth.json'
            auth.parent.mkdir()
            auth.write_text('{"synthetic":"credential"}')
            config = root / 'config.toml'
            config.write_text('model="synthetic"')
            before = os.environ.get('CODEX_HOME')
            with patch.object(Path, 'home', return_value=root):
                with runner.private_codex_state(config) as state:
                    self.assertEqual(os.environ['CODEX_HOME'], str(state))
                    self.assertEqual((state / 'auth.json').read_bytes(), auth.read_bytes())
                    self.assertEqual((state / 'config.toml').read_bytes(), config.read_bytes())
                    self.assertFalse((state / 'auth.json').is_symlink())
                    self.assertEqual((state / 'auth.json').stat().st_mode & 0o077, 0)
                self.assertFalse(state.exists())
            self.assertEqual(os.environ.get('CODEX_HOME'), before)

    def test_selected_run_is_bound_before_any_scan_request(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"; run.mkdir()
            (run / "selection.json").write_text(json.dumps({"function_id": "fn"}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)

            async def fake_scan(folder, _provider, **_kwargs):
                self.assertEqual(ledger.run_paths["fn"], str(folder.resolve()))
                (folder / "scan.json").write_text(json.dumps({
                    "selected_function_id": "fn", "sp_llm_calls": 0,
                    "hp_llm_calls": 0, "effective_sp_llm_call_limit": 4,
                    "combined_llm_call_limit": 8}))

            with patch.object(runner, "SharedFuzzMeter", FakeMeter), \
                 patch.object(runner.scan_mod, "scan_selected", fake_scan), \
                 patch.object(runner, "checkpoint_run", return_value=root / "checkpoint"), \
                 patch.object(runner, "summarize_resource_exhaustion", return_value={
                     "resource_exhaustion_artifact_count": 0,
                     "environment_error_artifact_count": 0}):
                rows = asyncio.run(runner.run_sequence(
                    run, provider, ledger, root, root / "ledger.json", max_functions=1))
            self.assertEqual(rows[0]["status"], "COMPLETE")
            self.assertEqual(provider.selected, None)

    def test_hp_swallowed_tool_event_still_stops_scan_as_incomplete(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'; run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'synthetic_fn'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            statuses = []

            async def fake_scan(_folder, active_provider, **_kwargs):
                # Mimic an HP layer that catches AppServerError and records
                # hp_error internally, then returns as if SP may continue.
                active_provider.forbidden_tool_event = True

            def checkpoint(_run, status, _ledger):
                statuses.append(status)
                return root / 'checkpoint'

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaises(runner.ModelToolEventError):
                    asyncio.run(runner.run_sequence(
                        run, provider, ledger, root, root / 'ledger.json',
                        max_functions=1))
            self.assertEqual(statuses, ['INCOMPLETE_TOOL_EVENT'])

    def test_hp_swallowed_provider_safety_refusal_stops_before_next_function(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'; run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'synthetic_fn'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            statuses = []

            async def fake_scan(_folder, active_provider, **_kwargs):
                # HP caught an explicit provider block and returned to SP.
                active_provider.provider_safety_refused = True

            def checkpoint(_run, status, _ledger):
                statuses.append(status)
                return root / 'checkpoint'

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'continue_phase1') as next_function, \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaises(runner.ProviderSafetyRefusedError):
                    asyncio.run(runner.run_sequence(
                        run, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            self.assertEqual(statuses, ['PROVIDER_SAFETY_REFUSED'])
            next_function.assert_not_called()

    def test_provider_safety_refusal_escapes_hp_exception_handler_immediately(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'; run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'synthetic_fn'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = runner.GuardedAppServer(
                ledger=ledger, checkpoint=root / 'ledger.json',
                route_sha256='a' * 64,
                role_models={'function_analysis': {
                    'model': 'gpt-5.6-sol', 'reasoning': 'max'}},
                cwd=root, model='gpt-5.6-sol', effort='max',
                codex_executable_path=root / 'unused-codex',
                codex_executable_sha256='a' * 64)
            statuses = []
            continued_after_refusal = []

            async def fake_model_generate(client, _request):
                client.ledger.start_attempt(client.request_hash)
                client.accepted_turn_id = 'synthetic-turn'
                raise runner.ProviderSafetyRefusedError(
                    'PROVIDER_SAFETY_REFUSED: role=function_analysis')

            async def fake_scan(_folder, active_provider, **_kwargs):
                request = SimpleNamespace(
                    role='function_analysis', instructions='source-free synthetic',
                    payload={}, output_schema={'type': 'object'},
                    session_key=None, model='gpt-5.6-sol', effort='max',
                    raw_response_path=None)
                try:
                    await active_provider.generate(request)
                except Exception:
                    continued_after_refusal.append(True)

            def checkpoint(_run, status, _ledger):
                statuses.append(status)
                return root / 'checkpoint'

            with patch.object(runner.CodexAppServerClient, 'generate', fake_model_generate), \
                 patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'continue_phase1') as next_function, \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaises(runner.FatalProviderSafetyRefusal):
                    asyncio.run(runner.run_sequence(
                        run, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            self.assertEqual(continued_after_refusal, [])
            self.assertEqual(statuses, ['PROVIDER_SAFETY_REFUSED'])
            self.assertEqual(ledger.physical, 1)
            self.assertEqual(ledger.retries, 0)
            self.assertEqual(ledger.attempts[0]['status'], 'ERROR')
            next_function.assert_not_called()

    def test_cancelled_scan_checkpoints_and_never_selects_next_function(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'; run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'synthetic_fn'}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)

            async def cancelled_scan(_folder, _provider, **_kwargs):
                raise asyncio.CancelledError('synthetic stop')

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', cancelled_scan), \
                 patch.object(runner, 'continue_phase1') as next_function, \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaises(asyncio.CancelledError):
                    asyncio.run(runner.run_sequence(
                        run, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            next_function.assert_not_called()
            self.assertIsNone(provider.selected)
            checkpoint = json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'], 'INCOMPLETE_CANCELLED')

    def test_runtime_cleanup_failure_stops_before_next_function(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'first', root / 'second'
            for run, function_id in ((first, 'fn1'), (second, 'fn2')):
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': function_id, 'function_name': function_id}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            visited = []

            async def fake_scan(run, _provider, **_kwargs):
                visited.append(run.name)
                if run == first:
                    raise RuntimeCleanupError(
                        'synthetic detached process survived', 'partial stdout',
                        '==ERROR: AddressSanitizer: heap-use-after-free\n'
                        '    #0 0x123 in md_parse md4c.c:45\n')
                (run / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn2', 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8}))

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'continue_phase1', return_value=second) as next_function, \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaises(RuntimeCleanupError):
                    asyncio.run(runner.run_sequence(
                        first, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            next_function.assert_not_called()
            self.assertEqual(visited, ['first'])
            self.assertEqual(ledger.functions, ['fn1'])
            checkpoint = json.loads((first / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            emergency = first / 'runtime' / 'cleanup_incomplete.json'
            record = json.loads(emergency.read_text())
            self.assertEqual(record['function_id'], 'fn1')
            self.assertEqual(record['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(record['partial_stdout'], 'partial stdout')
            self.assertIn('#0 0x123 in md_parse md4c.c:45', record['partial_stderr'])
            self.assertFalse(record['verified'])
            self.assertEqual(checkpoint['file_sha256']['runtime/cleanup_incomplete.json'],
                             runner.digest(emergency))

    def test_runtime_cleanup_with_malformed_runtime_json_keeps_original_error(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'; run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'synthetic_fn'}))
            malformed = run / 'runtime' / 'partial.json'
            malformed.parent.mkdir()
            malformed.write_bytes(b'{"stderr":')
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)

            async def cleanup_failure(_run, _provider, **_kwargs):
                raise RuntimeCleanupError('original cleanup failure', '', '')

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', cleanup_failure), \
                 patch.object(runner, 'continue_phase1') as next_function:
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'original cleanup failure'):
                    asyncio.run(runner.run_sequence(
                        run, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))

            next_function.assert_not_called()
            self.assertTrue((root / 'ledger.json').is_file())
            checkpoint = json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(checkpoint['file_sha256']['runtime/partial.json'],
                             runner.digest(malformed))
            report = json.loads((run / 'runtime' /
                                 'runner_resource_exhaustion.json').read_text())
            self.assertEqual(report['malformed_json_artifacts'], [{
                'artifact': 'runtime/partial.json',
                'artifact_sha256': runner.digest(malformed),
                'error_type': 'JSONDecodeError'}])

    def test_runtime_cleanup_with_fuzz_settlement_error_stops_sequence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'first', root / 'second'
            for run, function_id in ((first, 'fn1'), (second, 'fn2')):
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': function_id, 'function_name': function_id}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            meters = []
            original_meter = runner.SharedFuzzMeter

            def make_meter(*args, **kwargs):
                meter = original_meter(*args, **kwargs)
                meters.append(meter)
                return meter

            async def broken_scan(_run, _provider, **_kwargs):
                def cleanup_failure(*, seconds):
                    raise RuntimeCleanupError('original cleanup failed', '', 'partial ASan')
                meters[0].invoke('SP_FOLLOWUP:one', 'FAILED_POV_SEED', 1,
                                 cleanup_failure)

            with patch.object(runner, 'SharedFuzzMeter', make_meter), \
                 patch.object(runner.scan_mod, 'scan_selected', broken_scan), \
                 patch.object(type(ledger), 'finish_fuzz',
                              side_effect=OSError('settlement failed')), \
                 patch.object(runner, 'continue_phase1', return_value=second) as next_function:
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'original cleanup failed'):
                    asyncio.run(runner.run_sequence(
                        first, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            next_function.assert_not_called()
            checkpoint = json.loads((first / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(json.loads((root / 'ledger.json').read_text())
                             ['active_fuzz']['id'], 'SP_FOLLOWUP:one')

    def test_nonfatal_fuzzer_error_with_settlement_failure_stops_sequence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'first', root / 'second'
            for run, function_id in ((first, 'fn1'), (second, 'fn2')):
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': function_id, 'function_name': function_id}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            meters = []
            original_meter = runner.SharedFuzzMeter

            def make_meter(*args, **kwargs):
                meter = original_meter(*args, **kwargs)
                meters.append(meter)
                return meter

            async def broken_scan(_run, _provider, **_kwargs):
                def original_failure(*, seconds):
                    raise OSError('original fuzzer error')
                meters[0].invoke('SP_FOLLOWUP:one', 'FAILED_POV_SEED', 1,
                                 original_failure)

            with patch.object(runner, 'SharedFuzzMeter', make_meter), \
                 patch.object(runner.scan_mod, 'scan_selected', broken_scan), \
                 patch.object(type(ledger), 'finish_fuzz',
                              side_effect=OSError('settlement failed')), \
                 patch.object(runner, 'continue_phase1', return_value=second) as next_function:
                with self.assertRaisesRegex(OSError, 'original fuzzer error'):
                    asyncio.run(runner.run_sequence(
                        first, provider, ledger, root, root / 'ledger.json',
                        max_functions=2))
            next_function.assert_not_called()
            checkpoint = json.loads((first / 'FUNCTION_CHECKPOINT.json').read_text())
            self.assertEqual(checkpoint['status'],
                             'STOPPED_FUZZ_ACCOUNTING_INCOMPLETE')

    def test_primary_terminal_reason_survives_simultaneous_fuzz_settlement_failure(self):
        for error, expected in (
            (runner.ModelToolEventError('forbidden model tool'),
             'INCOMPLETE_TOOL_EVENT'),
            (TimeoutError('original fuzzer timeout'), 'INCOMPLETE_TIMEOUT'),
        ):
            with self.subTest(error=type(error).__name__), TemporaryDirectory() as tmp:
                root = Path(tmp)
                run = root / 'first'
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': 'fn1', 'function_name': 'fn1'}))
                ledger = runner.Ledger(started_at=time.time())
                provider = FakeProvider(ledger)
                meters = []
                original_meter = runner.SharedFuzzMeter

                def make_meter(*args, **kwargs):
                    meter = original_meter(*args, **kwargs)
                    meters.append(meter)
                    return meter

                async def broken_scan(_run, _provider, **_kwargs):
                    def primary_failure(*, seconds):
                        raise error
                    meters[0].invoke('SP_FOLLOWUP:one', 'FAILED_POV_SEED', 1,
                                     primary_failure)

                with patch.object(runner, 'SharedFuzzMeter', make_meter), \
                     patch.object(runner.scan_mod, 'scan_selected', broken_scan), \
                     patch.object(type(ledger), 'finish_fuzz',
                                  side_effect=OSError('settlement failed')):
                    with self.assertRaises(type(error)) as raised:
                        asyncio.run(runner.run_sequence(
                            run, provider, ledger, root, root / 'ledger.json',
                            max_functions=1))
                self.assertIs(raised.exception, error)
                self.assertTrue(getattr(error, 'fuzz_accounting_failed', False))
                checkpoint = json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                self.assertEqual(checkpoint['status'], expected)

    def test_hp_error_keeps_sp_artifact_and_continues_next_function(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'first', root / 'second'
            for run, function_id in ((first, 'fn1'), (second, 'fn2')):
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({'function_id': function_id}))
            ledger = runner.Ledger(started_at=time.time())
            provider = FakeProvider(ledger)
            statuses = []

            async def fake_scan(run, _provider, **_kwargs):
                function_id = json.loads((run / 'selection.json').read_text())['function_id']
                (run / 'sp').mkdir()
                (run / 'sp' / 'candidates.json').write_text('[{"sp_id":"SP1"}]')
                (run / 'scan.json').write_text(json.dumps({
                    'selected_function_id': function_id,
                    'sp_llm_calls': 0, 'hp_llm_calls': 0,
                    'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8,
                    'safe_assumption_count': None if function_id == 'fn1' else 0,
                    'hp_error': ({'stage': 'function_analysis', 'type': 'AppServerError'}
                                 if function_id == 'fn1' else None)}))

            def checkpoint(_run, status, _ledger):
                statuses.append(status)
                return root / 'checkpoint'

            with patch.object(runner, 'SharedFuzzMeter', FakeMeter), \
                 patch.object(runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(runner, 'continue_phase1', return_value=second), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                rows = asyncio.run(runner.run_sequence(
                    first, provider, ledger, root, root / 'ledger.json',
                    max_functions=2))
            self.assertEqual([row['status'] for row in rows],
                             ['INCOMPLETE_HP_ERROR', 'COMPLETE'])
            self.assertEqual(statuses, ['INCOMPLETE_HP_ERROR', 'COMPLETE'])
            self.assertEqual(json.loads((first / 'scan.json').read_text())['safe_assumption_count'], None)
            self.assertTrue((first / 'sp' / 'candidates.json').is_file())
