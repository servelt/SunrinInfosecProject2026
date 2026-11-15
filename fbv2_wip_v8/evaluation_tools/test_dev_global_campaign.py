"""Provider-free, public-toy acceptance checks for the development Global bridge."""

from __future__ import annotations

from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import blind2_runner_draft as runner
import dev_global_campaign as dev
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2

sys.path.insert(0, str(runner.PRODUCT / 'tests'))
import test_fuzzer_crash_consumer as product_crash_tests
import test_official_v2_contract as product_v2_tests

LIVE_PYTHON = Path('/home/dawne/.venvs/fbv2-live-v11/bin/python')


def make_plan(root: Path, *, direction_id: str = 'direction-one') -> tuple[Path, str]:
    plan = root / 'DIRECTION_PLAN.json'
    plan.write_text(json.dumps({'status': 'COMPLETED',
                                'direction_ids': [direction_id]}))
    return plan, dev.digest(plan)


def make_seed(root: Path, data: bytes = b'X') -> dev.DirectionSeed:
    path = root / 'direction-seed'
    path.write_bytes(data)
    return dev.DirectionSeed('direction-one', path, sha256(data).hexdigest())


def campaign(root: Path, q, *, seconds: int = 5) -> dev.DevGlobalCampaign:
    return dev.DevGlobalCampaign(root / 'output', q, total_fuzz_seconds=40,
                                 global_seconds=seconds,
                                 global_wall_reservation_seconds=25,
                                 replay_limit=1)


def process_gone(pid: int) -> bool:
    status = Path(f'/proc/{pid}/status')
    return not status.exists()


def slow_detached_command(marker: Path) -> list[str]:
    code = (
        'import pathlib, subprocess, sys, time\n'
        'child=subprocess.Popen([sys.executable,"-c",'
        '"import time;time.sleep(60)"], start_new_session=True)\n'
        'pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n'
        'time.sleep(60)\n'
    )
    return [sys.executable, '-I', '-B', '-c', code, str(marker)]


def await_marker(marker: Path, log: Path) -> int:
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not marker.exists():
        raise AssertionError(log.read_text())
    return int(marker.read_text())


class DevGlobalCampaignTests(unittest.TestCase):
    def test_worker_uses_fresh_private_pycache_and_signed_source_loaders(self):
        if not LIVE_PYTHON.is_file():
            self.skipTest('pinned live Python is unavailable')
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / 'worker_pycache'
            cache.mkdir(mode=0o700)
            missing = root / 'missing-worker-spec.json'
            isolated_product = (Path(dev.__file__).resolve().parent.parent /
                                'product' / 'src')
            command = dev._worker_command(missing, '0' * 64, cache)
            self.assertEqual(command[1:6], [
                '-I', '-S', '-B', '-X', f'pycache_prefix={cache}'])
            command[0] = str(LIVE_PYTHON)
            # Verbose import evidence proves adjacent timestamp-compatible
            # project caches are ignored in favour of signed .py sources.
            command.insert(4, '-v')
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=15,
                env={**os.environ,
                     dev._PRODUCT_SRC_ENV: str(isolated_product),
                     dev._WORKER_PYCACHE_ENV: str(cache)})
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(list(cache.iterdir()), [])
            self.assertIn('vulnerabilityanalysis/official_harness.py',
                          completed.stderr)
            self.assertIn('evaluation_tools/blind2_runner_draft.py',
                          completed.stderr)
            project_cache = re.compile(
                re.escape(str(Path(dev.__file__).resolve().parent.parent)) +
                r'/(?:evaluation_tools|product/src)/.*__pycache__')
            self.assertIsNone(project_cache.search(completed.stderr))

    def test_worker_rejects_sourceless_and_native_project_importables(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('shadow.pyc', 'shadow.cpython-313-x86_64-linux-gnu.so'):
                artifact = root / name
                artifact.write_bytes(b'not executable')
                with self.subTest(name=name), self.assertRaisesRegex(
                        RuntimeError, 'unsigned importable project artifact'):
                    dev._reject_unpinned_importables(root)
                artifact.unlink()
            cache = root / '__pycache__'
            cache.mkdir()
            (cache / 'signed.cpython-313.pyc').write_bytes(b'adjacent ignored cache')
            dev._reject_unpinned_importables(root)
            hidden = root / 'shadow_package'
            hidden.mkdir()
            (hidden / '__init__.pyc').write_bytes(b'untrusted package')
            hidden.chmod(0o111)
            try:
                with self.assertRaisesRegex(
                        RuntimeError, 'not completely readable'):
                    dev._reject_unpinned_importables(root)
            finally:
                hidden.chmod(0o700)

    def test_worker_wait_limit_preserves_signed_report_settlement_envelope(self):
        run = object.__new__(dev.DevGlobalCampaign)
        run.global_seconds = 30
        run.global_wall_reservation_seconds = 67.5
        # 67.5 includes the outer 12.5-second guard cleanup.  The worker keeps
        # all remaining 55 seconds for probe, fuzz supervision, and report
        # settlement instead of silently shrinking back to fuzz+20 seconds.
        self.assertEqual(run._worker_wait_limit(), 55.0)

    def test_accounted_consumer_blocks_unmetered_replay_and_forwards_account(self):
        """A retained Global crash is not an excuse for unmetered Gate processes."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            report = {
                'binary_sha256': q.binary_sha256, 'requested_seconds': 1,
                'status': 'CRASH_OBSERVED_INCOMPLETE',
                'observed_crashes': [{
                    'observed_crash_id': 'one', 'sha256': 'a' * 64}],
            }

            def prepared_run(account, report_value=report, suffix=None):
                run = dev.DevGlobalCampaign(
                    root / (suffix or ('with-account' if account else 'without-account')), q,
                    total_fuzz_seconds=30, global_seconds=1,
                    global_wall_reservation_seconds=14, replay_limit=1,
                    process_envelope=account, require_accounted_consumer=True)
                run.run_dir.mkdir(parents=True)
                dev.write_json(run.run_dir / 'runtime' / 'global_fuzz.json', report_value)
                run.process = SimpleNamespace(poll=lambda: 0, pid=424242)
                run.status_read = 123
                run.started_at = time.monotonic() - 1
                run.guard_exited_at_monotonic = time.monotonic()
                run.absolute_deadline_monotonic = time.monotonic() + 10
                run._guard_exit_event.set()
                run.budget.reserve('GLOBAL', 2)
                return run

            common_patches = lambda run: (
                patch.object(run, '_await_guard_exit', return_value='WATCHER_WAIT'),
                patch.object(run, '_guard_status', return_value=0),
                patch.object(run, '_close_guard'),
                patch.object(run, '_physical_elapsed',
                             return_value=(1, True, 'TEST_GUARD_EXIT')),
                patch.object(run, '_authority_ok', return_value=True),
                patch.object(dev, 'record_global_fuzzer_observations',
                             return_value={'one'}),
            )

            legacy_report = {key: value for key, value in report.items()
                             if key != 'observed_crashes'}
            legacy_report['observed_crash_id'] = 'one'
            no_account = prepared_run(None, legacy_report)
            from contextlib import ExitStack
            with ExitStack() as stack:
                for item in common_patches(no_account):
                    stack.enter_context(item)
                consume = stack.enter_context(patch.object(
                    dev, 'consume_global_fuzzer_observations'))
                blocked = no_account.finish()
            consume.assert_not_called()
            self.assertEqual(blocked['status'], 'CRASH_OBSERVED_INCOMPLETE')
            self.assertEqual(blocked['consumer_rows'][0]['status'],
                             'PENDING_PROCESS_ACCOUNT')
            self.assertEqual(blocked['consumer_rows'][0]['crash_id'], 'one')
            self.assertIsNone(blocked['consumer_rows'][0]['input_sha256'])
            self.assertFalse(blocked['consumer_process_account_installed'])

            fake_account = SimpleNamespace(
                output_limit_bytes=4096, deadline_monotonic=time.monotonic() + 30,
                before_process=lambda *_args, **_kwargs: None,
                after_process=lambda *_args, **_kwargs: None)
            with self.assertRaisesRegex(ValueError, 'durable V2 process ledger'):
                prepared_run(fake_account)
            ledger = PersistentProcessLedgerV2.create(
                root / 'process-ledger.json', wall_total_seconds=40,
                fuzz_total_seconds=0)
            account = DevelopmentProcessEnvelopeV2(
                ledger, work_item_id='global', assertion_id='consumer',
                attempt_id='one', output_limit_bytes=4096,
                total_wall_seconds=30,
                pin_hook=lambda _phase, _command: None)
            ran_report = {**report, 'status': 'RAN'}
            with_account = prepared_run(account, ran_report)
            with ExitStack() as stack:
                for item in common_patches(with_account):
                    stack.enter_context(item)
                consume = stack.enter_context(patch.object(
                    dev, 'consume_global_fuzzer_observations', return_value=[
                        {'crash_id': 'one',
                         'status': 'PENDING_SCAN_DEADLINE'}]))
                pending = with_account.finish()
            self.assertEqual(consume.call_count, 1)
            self.assertIs(consume.call_args.kwargs['process_envelope'], account)
            self.assertEqual(pending['status'], 'CRASH_OBSERVED_INCOMPLETE')
            self.assertTrue(pending['consumer_process_account_installed'])

            pending_cause = prepared_run(account, ran_report, suffix='pending-cause')
            with ExitStack() as stack:
                for item in common_patches(pending_cause):
                    stack.enter_context(item)
                stack.enter_context(patch.object(
                    dev, 'consume_global_fuzzer_observations', return_value=[
                        {'crash_id': 'one', 'status': 'PENDING_CAUSAL_EVIDENCE'}]))
                unresolved = pending_cause.finish()
            self.assertEqual(unresolved['status'], 'CRASH_OBSERVED_INCOMPLETE')

            completed = prepared_run(account, ran_report, suffix='completed-account')
            with ExitStack() as stack:
                for item in common_patches(completed):
                    stack.enter_context(item)
                stack.enter_context(patch.object(
                    dev, 'consume_global_fuzzer_observations', return_value=[
                        {'crash_id': 'one', 'status': 'GATE_CHECKED_NOT_VERIFIED'}]))
                terminal = completed.finish()
            self.assertEqual(terminal['status'], 'CRASH_OBSERVED_INCOMPLETE')

    def test_deadline_and_finish_send_only_one_guard_term(self):
        run = object.__new__(dev.DevGlobalCampaign)
        run.absolute_deadline_monotonic = time.monotonic() - 1
        run._guard_exit_event = threading.Event()
        run._guard_stop_lock = threading.Lock()
        run._guard_stop_requested = False
        run._deadline_signalled = False
        observed = []

        class FakeProcess:
            pid = 424242

            @staticmethod
            def poll():
                return None

            @staticmethod
            def wait(*, timeout):
                run._guard_exit_event.set()
                return 0

        status_read, status_write = os.pipe()
        os.write(status_write, b'0\n')
        os.close(status_write)
        try:
            with patch.object(dev.os, 'kill', side_effect=lambda pid, signum:
                              observed.append((pid, signum))):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    watcher = pool.submit(run._stop_guard_at_deadline,
                                          FakeProcess())
                    finisher = pool.submit(run._request_cleanup_once,
                                           FakeProcess(), status_read)
                    watcher.result(timeout=2)
                    self.assertTrue(finisher.result(timeout=2))
            self.assertEqual(observed, [(FakeProcess.pid, signal.SIGTERM)])
        finally:
            os.close(status_read)

    def test_deadline_watcher_stops_detached_descendant_during_analysis(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            qualification = fixture.issue()
            self.assertIsNotNone(qualification)
            plan, plan_hash = make_plan(root)
            run = dev.DevGlobalCampaign(
                root / 'output', qualification, total_fuzz_seconds=20,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            marker = root / 'detached.pid'
            with patch.object(dev, '_worker_command',
                              return_value=slow_detached_command(marker)):
                self.assertEqual(run.start(), 'ACTIVE')
                detached = await_marker(marker, run.run_dir / 'worker.log')
                # No call to finish yet: the background deadline owns this
                # physical limit while the main analysis could be busy.
                deadline = time.monotonic() + 4
                while run.process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertIsNotNone(run.process.poll())
                result = run.finish()
            self.assertEqual(result['status'], 'STOPPED_GLOBAL_WALL_LIMIT')
            self.assertFalse(Path(f'/proc/{detached}').exists())
            self.assertLessEqual(result['physical_seconds'],
                                 run.global_wall_reservation_seconds)

    def test_global_reservation_must_cover_guard_and_cleanup_before_launch(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            qualification = fixture.issue()
            self.assertIsNotNone(qualification)
            plan, plan_hash = make_plan(root)
            seed = make_seed(root)
            run = dev.DevGlobalCampaign(
                root / 'output', qualification, total_fuzz_seconds=20,
                global_seconds=3, global_wall_reservation_seconds=6,
                replay_limit=0)
            run.stage_direction_seeds(plan, plan_hash, [seed])
            with patch.object(dev, '_launch_guarded') as launch:
                with self.assertRaisesRegex(ValueError, 'reservation'):
                    run.start()
                launch.assert_not_called()

    def test_without_direction_seed_global_never_starts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [])
            self.assertEqual(run.start(), 'NOT_STARTED_NO_DIRECTION_SEED')
            self.assertIsNone(run.process)
            self.assertEqual(run.budget.snapshot()['spent_seconds'], 0)

    def test_authority_plan_seed_and_worker_spec_fail_closed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            plan, plan_hash = make_plan(root)
            seed = make_seed(root)
            with self.assertRaisesRegex(ValueError, 'Direction seed bytes changed'):
                campaign(root, q).stage_direction_seeds(
                    plan, plan_hash,
                    [dev.DirectionSeed(seed.direction_id, seed.path, '0' * 64)])
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [seed])
            stored = Path(run.seeds[0]['stored'])
            self.assertEqual(stored.read_bytes(), b'X')
            self.assertEqual(run.seeds[0]['source_sha256'], seed.sha256)
            plan.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'Direction seed or plan changed'):
                run.start()
            self.assertIsNone(run.process)
            self.assertEqual(run.budget.snapshot()['spent_seconds'], 0)

            worker_spec = run.run_dir / 'worker_spec.json'
            worker_spec.write_text('{}')
            old_sha = dev.digest(worker_spec)
            worker_spec.write_text('{"changed":true}')
            self.assertEqual(dev._worker(worker_spec, old_sha), 2)
            self.assertEqual(dev._worker(run.run_dir / 'missing.json', old_sha), 2)
            wrong_run = root / 'wrong-run'
            wrong_run.mkdir()
            worker_spec.write_text(json.dumps({
                'run_dir': str(wrong_run), 'binary': str(fixture.binary),
                'binary_sha256': dev.digest(fixture.binary),
                'run_command': [str(fixture.binary), '{input}'],
                'seconds': 1, 'product_src': str(dev.PRODUCT_SRC),
                'direction_plan_path': str(plan),
                'direction_plan_sha256': dev.digest(plan),
                'seed_files': [{'path': str(stored), 'sha256': dev.digest(stored)}]}))
            self.assertEqual(dev._worker(worker_spec, dev.digest(worker_spec)), 2)

    def test_stored_seed_or_official_binary_change_prevents_start(self):
        for change in ('stored-seed', 'official-binary'):
            with self.subTest(change=change), TemporaryDirectory() as tmp:
                root = Path(tmp)
                fixture = product_v2_tests.Fixture(root / 'authority')
                q = fixture.issue()
                self.assertIsNotNone(q)
                plan, plan_hash = make_plan(root)
                run = campaign(root, q)
                run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
                if change == 'stored-seed':
                    Path(run.seeds[0]['stored']).write_bytes(b'changed')
                    reason = 'Direction seed or plan changed'
                else:
                    fixture.binary.write_bytes(b'changed')
                    reason = 'official V2 authority changed'
                with self.assertRaisesRegex(ValueError, reason):
                    run.start()
                self.assertIsNone(run.process)
                self.assertEqual(run.budget.snapshot()['spent_seconds'], 0)

    def test_shared_physical_ledger_reserves_overlapping_work_and_flags_overrun(self):
        ledger = dev.SharedPhysicalFuzzBudget(10)
        ledger.reserve('GLOBAL', 5)
        ledger.reserve('SP-A', 3)
        ledger.reserve('HP-B', 2)
        with self.assertRaises(ValueError):
            ledger.reserve('SP-C', 0.1)
        ledger.finish('SP-A', 1)
        ledger.finish('HP-B', 2)
        row = ledger.finish('GLOBAL', 6)
        self.assertTrue(row['overrun'])
        self.assertEqual(ledger.snapshot()['spent_seconds'], 9)
        self.assertEqual(ledger.snapshot()['reserved_seconds'], 0)
        self.assertEqual({r['key'] for r in ledger.records},
                         {'GLOBAL', 'SP-A', 'HP-B'})

    def test_parallel_hard_cap_is_only_detected_after_charge(self):
        ledger = dev.SharedPhysicalFuzzBudget(10)
        ledger.reserve('GLOBAL', 3)
        ledger.reserve('SP-A', 7)
        ledger.finish('SP-A', 7)
        row = ledger.finish('GLOBAL', 5)
        self.assertTrue(row['overrun'])
        self.assertEqual(ledger.spent_seconds, 12)
        self.assertEqual(ledger.available, -2)

    def test_real_official_toy_global_seed_reaches_existing_gate(self):
        """A crashing toy seed tests the Gate; it is not a discovery test."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
            plan, plan_hash = make_plan(root)
            seed = make_seed(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [seed])
            self.assertEqual(run.start(), 'ACTIVE')
            guard_pid = run.process.pid
            run.mark_function('function-one')
            run.mark_function('function-two')
            result = run.finish()
            self.assertEqual(result['status'], 'CRASH_OBSERVED_INCOMPLETE', result)
            self.assertTrue(result['cleanup_complete'])
            self.assertTrue(process_gone(guard_pid))
            self.assertEqual(result['seed_count'], 1)
            self.assertEqual(result['observed_crash_count'], 1)
            self.assertEqual(result['consumer_rows'][0]['status'], 'VERIFIED')
            seed_sha = sha256(b'X').hexdigest()
            self.assertEqual(result['staged_seed_sha256s'], [seed_sha])
            self.assertEqual(result['observed_crash_rows'], [{
                'crash_id': result['consumer_rows'][0]['crash_id'],
                'input_sha256': seed_sha}])
            self.assertFalse(result['global_crash_mutation_observed'])
            self.assertEqual(result['observed_mutated_crash_rows'], [])
            # A crash from the starting seed cannot earn mutation credit.
            self.assertIn(result['observed_crash_rows'][0]['input_sha256'],
                          result['staged_seed_sha256s'])
            self.assertEqual([r['function_id'] for r in result['function_windows']],
                             ['function-one', 'function-two'])
            self.assertEqual({r['global_guard_pid'] for r in result['function_windows']},
                             {guard_pid})
            self.assertEqual(fixture.seed.read_bytes(), b'Y')

    def test_real_official_toy_global_mutates_safe_seed_before_gate(self):
        """A new toy input exercises mutation provenance, not OSS discovery."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q, seconds=5)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root, b'Y')])
            self.assertEqual(run.start(), 'ACTIVE')
            result = run.finish()
            self.assertEqual(result['status'], 'CRASH_OBSERVED_INCOMPLETE', result)
            self.assertTrue(result['cleanup_complete'])
            self.assertEqual(result['observed_crash_count'], 1)
            self.assertEqual(result['consumer_rows'][0]['status'], 'VERIFIED')
            self.assertTrue(result['global_crash_mutation_observed'])
            self.assertEqual(result['observed_mutated_crash_rows'], [{
                'crash_id': result['observed_crash_rows'][0]['crash_id'],
                'input_sha256': result['observed_crash_rows'][0]['input_sha256'],
                'base_sha256': result['staged_seed_sha256s'][0],
            }])
            self.assertNotIn(result['observed_crash_rows'][0]['input_sha256'],
                             result['staged_seed_sha256s'])

    def test_mutation_log_tamper_blocks_consumer(self):
        """A changed raw libFuzzer log cannot support a crash mutation claim."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q, seconds=5)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root, b'Y')])
            self.assertEqual(run.start(), 'ACTIVE')
            run.process.wait(timeout=15)
            report = json.loads((run.run_dir / 'runtime' / 'global_fuzz.json').read_text())
            self.assertTrue(report['crash_mutation_observations'])
            runtime_path = Path(report['runtime_artifact'])
            runtime = json.loads(runtime_path.read_text())
            runtime['stderr'] = runtime['stderr'].replace('base unit:', 'base changed:')
            runtime_path.write_text(json.dumps(runtime))
            result = run.finish()
            self.assertEqual(result['status'], 'INCOMPLETE_GLOBAL_REPORT_OR_CONSUMER')
            self.assertEqual(result['consumer_rows'], [])

    def test_real_safe_toy_global_stays_active_across_two_function_windows(self):
        """No known crash: prove one real Global worker persists across markers."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe_target = 'int target_operation(int marker) { (void)marker; return 0; }\n'
            with patch.object(product_crash_tests, 'OFFICIAL_TARGET', safe_target):
                _fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q, seconds=3)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root, b'Y')])
            self.assertEqual(run.start(), 'ACTIVE')
            run.mark_function('function-one')
            time.sleep(0.25)
            run.mark_function('function-two')
            self.assertTrue(all(row['global_guard_alive']
                                for row in run.function_windows))
            self.assertEqual({row['global_guard_pid']
                              for row in run.function_windows}, {run.process.pid})
            result = run.finish()
            self.assertEqual(result['status'], 'RAN', result)
            self.assertEqual(result['observed_crash_count'], 0)
            self.assertEqual(result['consumer_rows'], [])
            self.assertTrue(result['cleanup_complete'])
            self.assertTrue(process_gone(run.process.pid))
            self.assertEqual(result['physical_time_basis'],
                             'PARENT_MONOTONIC_GUARD_EXIT_OBSERVATION')
            self.assertTrue(result['guard_end_observed'])
            self.assertGreater(result['worker_execution_seconds'], 0)
            self.assertGreaterEqual(result['guard_minus_worker_seconds'], 0)

    def test_abort_reaps_detached_grandchild(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            marker = root / 'detached.pid'
            with patch.object(dev, '_worker_command',
                              return_value=slow_detached_command(marker)):
                self.assertEqual(run.start(), 'ACTIVE')
                detached_pid = await_marker(marker, run.run_dir / 'worker.log')
                guard_pid = run.process.pid
                try:
                    result = run.abort()
                    self.assertEqual(result['status'], 'STOPPED_ABORTED', result)
                    self.assertTrue(result['cleanup_complete'])
                    self.assertTrue(process_gone(guard_pid))
                    self.assertTrue(process_gone(detached_pid))
                finally:
                    if not process_gone(detached_pid):
                        os.kill(detached_pid, 9)

    def test_timeout_reaps_detached_grandchild_and_records_reason(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            marker = root / 'detached.pid'
            with patch.object(dev, '_worker_command',
                              return_value=slow_detached_command(marker)), \
                 patch.object(run, '_worker_wait_limit', return_value=2.0):
                self.assertEqual(run.start(), 'ACTIVE')
                self.assertAlmostEqual(run.absolute_deadline_monotonic -
                                       run.started_at, 2.0, delta=0.001)
                detached_pid = await_marker(marker, run.run_dir / 'worker.log')
                guard_pid = run.process.pid
                try:
                    result = run.finish()
                    self.assertEqual(result['status'], 'STOPPED_GLOBAL_WALL_LIMIT', result)
                    self.assertEqual(result['original_stop_reason'], 'GLOBAL_WALL_LIMIT')
                    self.assertTrue(result['cleanup_complete'])
                    self.assertTrue(process_gone(guard_pid))
                    self.assertTrue(process_gone(detached_pid))
                finally:
                    if not process_gone(detached_pid):
                        os.kill(detached_pid, 9)

    def test_worker_error_is_incomplete_and_guard_is_reaped(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            command = [sys.executable, '-I', '-B', '-c', 'raise RuntimeError("toy")']
            with patch.object(dev, '_worker_command', return_value=command):
                self.assertEqual(run.start(), 'ACTIVE')
                guard_pid = run.process.pid
                result = run.finish()
            self.assertEqual(result['status'], 'STOPPED_GLOBAL_WORKER_ERROR', result)
            self.assertEqual(result['observed_crash_count'], 0)
            self.assertTrue(result['cleanup_complete'])
            self.assertTrue(process_gone(guard_pid))

    def test_delayed_finish_charges_observed_guard_lifetime_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            command = [sys.executable, '-I', '-B', '-c',
                       'import time;time.sleep(.05)']
            with patch.object(dev, '_worker_command', return_value=command):
                run.start()
                run.process.wait(timeout=5)
                end_observed = time.monotonic()
                time.sleep(0.45)
                result = run.finish()
            self.assertLessEqual(result['physical_seconds'],
                                 end_observed - run.started_at + 0.10)
            self.assertTrue(result['cleanup_complete'])

    def test_delayed_abort_charges_observed_guard_lifetime_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            command = [sys.executable, '-I', '-B', '-c',
                       'import time;time.sleep(.05)']
            with patch.object(dev, '_worker_command', return_value=command):
                run.start()
                run.process.wait(timeout=5)
                end_observed = time.monotonic()
                time.sleep(0.45)
                result = run.abort()
            self.assertLessEqual(result['physical_seconds'],
                                 end_observed - run.started_at + 0.10)
            self.assertTrue(result['cleanup_complete'])

    def test_silent_watcher_failure_is_prompt_and_never_exact_or_ran(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            q = product_v2_tests.Fixture(root / 'authority').issue()
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            command = [sys.executable, '-I', '-B', '-c',
                       'import time;time.sleep(.05)']
            with patch.object(dev, '_worker_command', return_value=command), \
                 patch.object(run, '_worker_wait_limit', return_value=0.5), \
                 patch.object(run, '_watch_guard', return_value=None):
                run.start()
                run.process.wait(timeout=5)
                ended_before_finish = time.monotonic()
                result = run.finish()
            self.assertLess(time.monotonic() - ended_before_finish, 0.3)
            self.assertEqual(result['status'], 'INCOMPLETE_GUARD_EXIT_TIMESTAMP')
            self.assertFalse(result['guard_end_observed'])
            self.assertFalse(result['guard_exit_time_trusted'])
            self.assertEqual(result['guard_watcher_health'], 'EXIT_TIMESTAMP_MISSING')
            self.assertEqual(result['physical_time_basis'],
                             'PARENT_LATE_POLL_UPPER_BOUND_UNCERTAIN')

    def test_guard_exit_after_absolute_deadline_is_not_ran(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            q = product_v2_tests.Fixture(root / 'authority').issue()
            plan, plan_hash = make_plan(root)
            run = campaign(root, q)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root)])
            command = [sys.executable, '-I', '-B', '-c',
                       'import time;time.sleep(5)']
            with patch.object(dev, '_worker_command', return_value=command), \
                 patch.object(run, '_worker_wait_limit', return_value=1.0):
                run.start()
                run.process.wait(timeout=5)
                result = run.finish()
            self.assertEqual(result['status'], 'STOPPED_GLOBAL_WALL_LIMIT')
            self.assertEqual(result['original_stop_reason'], 'GLOBAL_WALL_LIMIT')
            self.assertTrue(result['guard_exit_time_trusted'])
            self.assertGreater(result['guard_exited_monotonic'],
                               run.absolute_deadline_monotonic)

    def test_worker_receipt_tamper_is_untrusted_advisory(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe_target = 'int target_operation(int marker) { (void)marker; return 0; }\n'
            with patch.object(product_crash_tests, 'OFFICIAL_TARGET', safe_target):
                _fixture, q = product_crash_tests.FuzzerCrashConsumerTest()._real_official_uaf(root)
            plan, plan_hash = make_plan(root)
            run = campaign(root, q, seconds=1)
            run.stage_direction_seeds(plan, plan_hash, [make_seed(root, b'Y')])
            run.start()
            run.process.wait(timeout=15)
            receipt = run.run_dir / 'runtime' / 'dev_global_worker_result.json'
            worker = json.loads(receipt.read_text())
            worker['worker_execution_seconds'] = 1_000_000_000
            receipt.write_text(json.dumps(worker))
            result = run.finish()
            self.assertEqual(result['status'], 'RAN', result)
            self.assertEqual(result['worker_receipt_trust'], 'UNTRUSTED_ADVISORY')
            self.assertEqual(result['worker_receipt_status'], 'INVALID_INCONSISTENT_TIME')
            self.assertNotIn('guard_minus_worker_seconds', result)


if __name__ == '__main__':
    unittest.main()
