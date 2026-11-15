"""Provider-free physical command probes for the durable development bridge."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

import blind2_runner_draft as runner
from dev_persistent_guarded_fuzz_bridge import PersistentGuardedFuzzBridge


def pinned_command(corpus: Path, *, body: str = 'pass') -> list[str]:
    return [str(Path(sys.executable).resolve()), '-I', '-c', body,
            str(corpus)]


def pinned_kwargs(corpus: Path, *, job_id: str = 'function-1:SP-1',
                  body: str = 'pass') -> tuple[list[str], dict]:
    command = pinned_command(corpus, body=body)
    with Path(command[0]).open('rb') as stream:
        binary_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    argv_sha256 = hashlib.sha256(json.dumps(
        command, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    return command, {'job_id': job_id, 'binary': Path(command[0]),
                     'expected_binary_sha256': binary_sha256,
                     'corpus': corpus, 'expected_argv_sha256': argv_sha256}


def pinned_receipt(root: Path, job_id: str) -> Path:
    name = hashlib.sha256(job_id.encode()).hexdigest() + '.json'
    return root / 'PINNED_FUZZ_RECEIPTS' / name


def detached_sleeper(marker: Path) -> list[str]:
    code = (
        'import pathlib,subprocess,sys,time;'
        'child=subprocess.Popen([sys.executable,"-I","-c",'
        '"import time;time.sleep(30)"],start_new_session=True);'
        'pathlib.Path(sys.argv[1]).write_text(str(child.pid));'
        'time.sleep(30)'
    )
    return [sys.executable, '-I', '-c', code, str(marker)]


def wait_for_marker(marker: Path) -> int:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            value = marker.read_text().strip()
        except FileNotFoundError:
            value = ''
        if value.isascii() and value.isdecimal() and int(value) > 0:
            return int(value)
        time.sleep(0.02)
    raise AssertionError(f'guarded job did not publish a numeric PID: {marker}')


class PersistentGuardedFuzzBridgeTests(unittest.TestCase):
    def test_pinned_receipt_exists_before_child_and_links_finished_charge(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal seed')
            command, pins = pinned_kwargs(
                corpus, body='import pathlib,sys;'
                'pathlib.Path(sys.argv[1],"new-seed").write_bytes(b"new")')
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            real_run = bridge.command_group.run
            receipt_path = pinned_receipt(root, pins['job_id'])

            def inspect_before_child(*args, **kwargs):
                receipt = json.loads(receipt_path.read_text())
                self.assertEqual(receipt['status'], 'RESERVED_PRELAUNCH')
                self.assertEqual(receipt['role'], 'SP')
                self.assertEqual(receipt['logical_job_id'], pins['job_id'])
                self.assertEqual(receipt['binary_sha256'],
                                 pins['expected_binary_sha256'])
                self.assertEqual(receipt['argv_sha256'],
                                 pins['expected_argv_sha256'])
                self.assertEqual(receipt['pre_corpus_files'][0]['path'], 'seed')
                self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
                self.assertIn(receipt['persistent_key'], bridge.snapshot()['active'])
                return real_run(*args, **kwargs)

            with patch.object(bridge.command_group, 'run',
                              side_effect=inspect_before_child):
                result = bridge.run_pinned('SP', command,
                                           requested_seconds=1, **pins)
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(result['status'], 'COMPLETED')
            self.assertEqual(receipt['status'], 'FINISHED')
            self.assertEqual(receipt['persistent_key'], result['persistent_key'])
            self.assertEqual(receipt['ledger_finished_row'],
                             bridge.snapshot()['finished'][0])
            self.assertEqual(receipt['post_corpus_files'][0]['path'], 'new-seed')
            self.assertEqual(receipt['post_corpus_files'][1]['path'], 'seed')
            self.assertTrue(receipt['cleanup_complete'])
            self.assertEqual(result['pinned_receipt'], str(receipt_path))

    def test_pinned_preflight_rejects_symlink_and_wrong_pins_without_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            seed = corpus / 'seed'
            seed.write_bytes(b'seed')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            with patch.object(bridge.command_group, 'run') as launch:
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', command, requested_seconds=1,
                                      **{**pins, 'expected_binary_sha256': '0' * 64})
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', command, requested_seconds=1,
                                      **{**pins, 'expected_argv_sha256': '0' * 64})
                seed.unlink()
                seed.symlink_to(root / 'outside')
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', command, requested_seconds=1, **pins)
                seed.unlink()
                seed.write_bytes(b'seed')
                linked_corpus = root / 'linked-corpus'
                linked_corpus.symlink_to(corpus, target_is_directory=True)
                linked_command, linked_pins = pinned_kwargs(linked_corpus)
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', linked_command,
                                      requested_seconds=1, **linked_pins)
                linked_binary = root / 'linked-binary'
                linked_binary.symlink_to(command[0])
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', [str(linked_binary), *command[1:]],
                                      requested_seconds=1,
                                      **{**pins, 'binary': linked_binary})
                launch.assert_not_called()
            self.assertEqual(bridge.snapshot()['finished'], [])

    def test_pinned_recheck_detects_prechild_corpus_change(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            seed = corpus / 'seed'
            seed.write_bytes(b'original')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            real_reserve = bridge.ledger.reserve

            def change_after_reserve(*args, **kwargs):
                real_reserve(*args, **kwargs)
                seed.write_bytes(b'changed')

            with patch.object(bridge.ledger, 'reserve',
                              side_effect=change_after_reserve), \
                 patch.object(bridge.command_group, 'run') as launch:
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', command, requested_seconds=1, **pins)
                launch.assert_not_called()
            self.assertEqual(bridge.snapshot()['active'], {})
            self.assertEqual(len(bridge.snapshot()['finished']), 1)
            self.assertEqual(bridge.snapshot()['finished'][0]['physical_seconds'], 0)

    def test_pinned_receipt_write_failure_before_reserve_never_starts_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'original')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            with patch.object(bridge, '_new_receipt',
                              side_effect=OSError('receipt write failed')), \
                 patch.object(bridge.command_group, 'run') as launch:
                with self.assertRaisesRegex(OSError, 'receipt write failed'):
                    bridge.run_pinned('SP', command, requested_seconds=1, **pins)
                launch.assert_not_called()
            self.assertEqual(bridge.snapshot()['active'], {})
            self.assertEqual(bridge.snapshot()['finished'], [])

    def test_pinned_receipt_update_failure_after_reserve_releases_without_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'original')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            with patch.object(bridge, '_update_receipt',
                              side_effect=OSError('receipt update failed')), \
                 patch.object(bridge.command_group, 'run') as launch:
                with self.assertRaisesRegex(OSError, 'receipt update failed'):
                    bridge.run_pinned('SP', command, requested_seconds=1, **pins)
                launch.assert_not_called()
            state = bridge.snapshot()
            self.assertEqual(state['active'], {})
            self.assertEqual(len(state['finished']), 1)
            self.assertEqual(state['finished'][0]['physical_seconds'], 0)
            with patch.object(bridge.command_group, 'run') as launch:
                with self.assertRaisesRegex(ValueError, 'tainted'):
                    bridge.run('HP', [sys.executable, '-I', '-c', 'pass'],
                               requested_seconds=1)
                launch.assert_not_called()

    def test_pinned_concurrent_second_job_is_rejected_before_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=30)
            entered = threading.Event()
            release = threading.Event()
            real_run = bridge.command_group.run

            def hold_first(*args, **kwargs):
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError('first pinned job was not released')
                return real_run(*args, **kwargs)

            with patch.object(bridge.command_group, 'run',
                              side_effect=hold_first) as launch:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(bridge.run_pinned, 'SP', command,
                                        requested_seconds=1, **pins)
                    self.assertTrue(entered.wait(timeout=3))
                    with self.assertRaisesRegex(ValueError, 'concurrent pinned'):
                        bridge.run_pinned('HP', command, requested_seconds=1,
                                          **{**pins, 'job_id': 'second:HP'})
                    self.assertEqual(launch.call_count, 1)
                    self.assertFalse(pinned_receipt(root, 'second:HP').exists())
                    release.set()
                    self.assertEqual(first.result(timeout=5)['status'], 'COMPLETED')

    def test_pinned_active_rejects_legacy_before_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=30)
            entered, release = threading.Event(), threading.Event()
            real_run = bridge.command_group.run

            def hold_first(*args, **kwargs):
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError('pinned job was not released')
                return real_run(*args, **kwargs)

            with patch.object(bridge.command_group, 'run',
                              side_effect=hold_first) as launch:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(bridge.run_pinned, 'SP', command,
                                        requested_seconds=1, **pins)
                    self.assertTrue(entered.wait(timeout=3))
                    with self.assertRaisesRegex(ValueError, 'may not overlap'):
                        bridge.run('HP', [sys.executable, '-I', '-c', 'pass'],
                                   requested_seconds=1)
                    self.assertEqual(launch.call_count, 1)
                    release.set()
                    self.assertEqual(first.result(timeout=5)['status'], 'COMPLETED')

    def test_legacy_active_rejects_pinned_before_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=30)
            entered, release = threading.Event(), threading.Event()
            real_run = bridge.command_group.run

            def hold_first(*args, **kwargs):
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError('legacy job was not released')
                return real_run(*args, **kwargs)

            with patch.object(bridge.command_group, 'run',
                              side_effect=hold_first) as launch:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(bridge.run, 'GLOBAL',
                                        [sys.executable, '-I', '-c', 'pass'],
                                        requested_seconds=1)
                    self.assertTrue(entered.wait(timeout=3))
                    with self.assertRaisesRegex(ValueError, 'may not overlap'):
                        bridge.run_pinned('SP', command,
                                          requested_seconds=1, **pins)
                    self.assertEqual(launch.call_count, 1)
                    self.assertFalse(pinned_receipt(root, pins['job_id']).exists())
                    release.set()
                    self.assertEqual(first.result(timeout=5)['status'], 'COMPLETED')

    def test_legacy_admission_blocks_pinned_receipt_failure_race(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=30)
            entered, release = threading.Event(), threading.Event()
            real_legacy = bridge._run_legacy

            def wait_after_admission(*args, **kwargs):
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError('legacy admission was not released')
                return real_legacy(*args, **kwargs)

            with patch.object(bridge, '_run_legacy',
                              side_effect=wait_after_admission), \
                 patch.object(bridge, '_new_receipt',
                              side_effect=OSError('would taint')) as receipt:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(bridge.run, 'GLOBAL',
                                        [sys.executable, '-I', '-c', 'pass'],
                                        requested_seconds=1)
                    self.assertTrue(entered.wait(timeout=3))
                    with self.assertRaisesRegex(ValueError, 'may not overlap'):
                        bridge.run_pinned('SP', command,
                                          requested_seconds=1, **pins)
                    receipt.assert_not_called()
                    release.set()
                    self.assertEqual(first.result(timeout=5)['status'], 'COMPLETED')

    def test_pinned_receipt_failure_blocks_legacy_before_and_after_taint(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=30)
            entered, release = threading.Event(), threading.Event()

            def fail_receipt(*_args, **_kwargs):
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError('receipt failure was not released')
                raise OSError('receipt write failed')

            with patch.object(bridge, '_new_receipt', side_effect=fail_receipt), \
                 patch.object(bridge.command_group, 'run') as launch:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    pinned = pool.submit(bridge.run_pinned, 'SP', command,
                                         requested_seconds=1, **pins)
                    self.assertTrue(entered.wait(timeout=3))
                    with self.assertRaisesRegex(ValueError, 'may not overlap'):
                        bridge.run('HP', [sys.executable, '-I', '-c', 'pass'],
                                   requested_seconds=1)
                    release.set()
                    with self.assertRaisesRegex(OSError, 'receipt write failed'):
                        pinned.result(timeout=5)
                    with self.assertRaisesRegex(ValueError, 'tainted'):
                        bridge.run('HP', [sys.executable, '-I', '-c', 'pass'],
                                   requested_seconds=1)
                    launch.assert_not_called()

    def test_restored_finished_receipt_checks_key_and_role(self):
        for field, value in [('persistent_key', 'SP:incorrect'), ('role', 'HP')]:
            with self.subTest(field=field), TemporaryDirectory() as tmp:
                root = Path(tmp)
                corpus = root / 'corpus'
                corpus.mkdir()
                (corpus / 'seed').write_bytes(b'normal')
                command, pins = pinned_kwargs(corpus)
                bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
                self.assertEqual(bridge.run_pinned(
                    'SP', command, requested_seconds=1, **pins)['status'],
                    'COMPLETED')
                path = pinned_receipt(root, pins['job_id'])
                row = json.loads(path.read_text())
                row[field] = value
                path.write_text(json.dumps(row))
                restored = PersistentGuardedFuzzBridge.restore(
                    root, total_seconds=20)
                with patch.object(restored.command_group, 'run') as launch:
                    with self.assertRaisesRegex(ValueError, 'tainted'):
                        restored.run_pinned('SP', command, requested_seconds=1,
                                            **{**pins, 'job_id': 'next:SP'})
                    launch.assert_not_called()

    def test_restored_receipt_rejects_internal_hash_and_filename_damage(self):
        for field, value in [
                ('argv_sha256', '0' * 64),
                ('pre_corpus_sha256', '0' * 64),
                ('post_corpus_sha256', '0' * 64),
                ('post_binary_sha256', '0' * 64),
                ('logical_job_id', 'other:SP')]:
            with self.subTest(field=field), TemporaryDirectory() as tmp:
                root = Path(tmp)
                corpus = root / 'corpus'
                corpus.mkdir()
                (corpus / 'seed').write_bytes(b'normal')
                command, pins = pinned_kwargs(corpus)
                bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
                self.assertEqual(bridge.run_pinned(
                    'SP', command, requested_seconds=1, **pins)['status'],
                    'COMPLETED')
                path = pinned_receipt(root, pins['job_id'])
                row = json.loads(path.read_text())
                row[field] = value
                path.write_text(json.dumps(row))
                restored = PersistentGuardedFuzzBridge.restore(
                    root, total_seconds=20)
                with patch.object(restored.command_group, 'run') as launch:
                    with self.assertRaisesRegex(ValueError, 'tainted'):
                        restored.run_pinned('SP', command, requested_seconds=1,
                                            **{**pins, 'job_id': 'next:SP'})
                    launch.assert_not_called()

    def test_pinned_budget_pending_is_final_for_that_logical_id(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=2)
            with patch.object(bridge.command_group, 'run') as launch:
                first = bridge.run_pinned('SP', command,
                                          requested_seconds=1, **pins)
                self.assertEqual(first['status'], 'PENDING_SHARED_PHYSICAL_BUDGET')
                with self.assertRaises(FileExistsError):
                    bridge.run_pinned('SP', command,
                                      requested_seconds=1, **pins)
                launch.assert_not_called()

    def test_pinned_finished_means_accounted_even_when_child_errors(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(
                corpus, body='import sys;sys.exit(7)')
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            result = bridge.run_pinned('SP', command,
                                       requested_seconds=1, **pins)
            receipt = json.loads(pinned_receipt(root, pins['job_id']).read_text())
            self.assertEqual(result['status'], 'CHILD_ERROR')
            self.assertEqual(receipt['status'], 'FINISHED')
            self.assertEqual(receipt['result_status'], 'CHILD_ERROR')
            self.assertTrue(receipt['cleanup_complete'])

    def test_pinned_budget_pending_never_launches_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=2)
            with patch.object(bridge.command_group, 'run') as launch:
                result = bridge.run_pinned('HP', command,
                                           requested_seconds=1, **pins)
                launch.assert_not_called()
            self.assertEqual(result['status'], 'PENDING_SHARED_PHYSICAL_BUDGET')
            self.assertEqual(bridge.snapshot()['active'], {})
            self.assertEqual(bridge.snapshot()['finished'], [])

    def test_pinned_cleanup_failure_stops_and_records_finished_row(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(
                corpus, body='import subprocess,sys,time;'
                'subprocess.Popen([sys.executable,"-I","-c",'
                '"import time;time.sleep(30)"],start_new_session=True);'
                'time.sleep(30)')
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            real_cleanup = runner._request_guard_cleanup

            def reported_failure(child, status):
                real_cleanup(child, status)
                return False

            with patch.object(runner, '_request_guard_cleanup',
                              side_effect=reported_failure):
                result = bridge.run_pinned('HP', command,
                                           requested_seconds=0.2, **pins)
            receipt = json.loads(pinned_receipt(root, pins['job_id']).read_text())
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(receipt['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertFalse(receipt['cleanup_complete'])
            self.assertEqual(receipt['ledger_finished_row'],
                             bridge.snapshot()['finished'][0])

    def test_pinned_receipt_tamper_after_launch_is_not_success(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(corpus)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            receipt = pinned_receipt(root, pins['job_id'])
            real_run = bridge.command_group.run

            def tamper_then_run(*args, **kwargs):
                receipt.write_text('tampered')
                return real_run(*args, **kwargs)

            with patch.object(bridge.command_group, 'run',
                              side_effect=tamper_then_run):
                with self.assertRaises(ValueError):
                    bridge.run_pinned('SP', command,
                                      requested_seconds=1, **pins)
            self.assertEqual(bridge.snapshot()['active'], {})
            with self.assertRaises(ValueError):
                bridge.run_pinned('SP', command, requested_seconds=1,
                                  **{**pins, 'job_id': 'next-job'})

    def test_pinned_post_corpus_symlink_is_not_reported_complete(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'
            corpus.mkdir()
            (corpus / 'seed').write_bytes(b'normal')
            command, pins = pinned_kwargs(
                corpus, body='import pathlib,sys;'
                'pathlib.Path(sys.argv[1],"linked").symlink_to("/etc/hosts")')
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=20)
            with self.assertRaises(ValueError):
                bridge.run_pinned('SP', command, requested_seconds=1, **pins)
            receipt = json.loads(pinned_receipt(root, pins['job_id']).read_text())
            self.assertEqual(receipt['status'], 'STOPPED_POST_CORPUS_UNTRUSTED')
            self.assertEqual(receipt['ledger_finished_row'],
                             bridge.snapshot()['finished'][0])
            self.assertEqual(bridge.snapshot()['active'], {})
            with self.assertRaises(ValueError):
                bridge.run_pinned('SP', command, requested_seconds=1,
                                  **{**pins, 'job_id': 'next-job'})

    def test_invalid_cleanup_envelope_creates_no_ledger(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'cleanup envelope'):
                PersistentGuardedFuzzBridge.create(
                    root, total_seconds=30, cleanup_envelope_seconds=2)
            self.assertFalse((root / 'DEV_PERSISTENT_PHYSICAL_FUZZ_LEDGER.json').exists())

    def test_prelaunch_persistent_reservation_and_completed_measurement(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=15)
            real_run = bridge.command_group.run
            observed = []

            def check_then_run(*args, **kwargs):
                state = bridge.snapshot()
                observed.append(state)
                checkpoint = json.loads(bridge.ledger.path.read_text())
                self.assertEqual(len(checkpoint['active']), 1)
                self.assertEqual(state['reserved_seconds'], 13.5)
                return real_run(*args, **kwargs)

            with patch.object(bridge.command_group, 'run', side_effect=check_then_run):
                result = bridge.run('SP', [sys.executable, '-I', '-c', 'pass'],
                                    requested_seconds=1)
            self.assertEqual(len(observed), 1)
            self.assertEqual(result['status'], 'COMPLETED')
            self.assertTrue(result['cleanup_complete'])
            self.assertEqual(result['persistent_charge']['kind'], 'SP')
            state = bridge.snapshot()
            self.assertEqual(len(state['active']), 0)
            self.assertEqual(len(state['finished']), 1)
            self.assertGreater(state['spent_seconds'], 0)
            self.assertIsNone(state['stop_status'])
            restored = PersistentGuardedFuzzBridge.restore(root, total_seconds=15)
            self.assertEqual(restored.snapshot()['spent_seconds'],
                             state['spent_seconds'])

    def test_parallel_global_and_hp_share_durable_prelaunch_cap(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=30)
            global_marker, hp_marker = root / 'global.pid', root / 'hp.pid'
            with ThreadPoolExecutor(max_workers=2) as pool:
                global_future = pool.submit(
                    bridge.run, 'GLOBAL', detached_sleeper(global_marker),
                    requested_seconds=2)
                hp_future = pool.submit(
                    bridge.run, 'HP', detached_sleeper(hp_marker),
                    requested_seconds=2)
                global_pid = wait_for_marker(global_marker)
                hp_pid = wait_for_marker(hp_marker)
                pending = bridge.run('SP',
                                     [sys.executable, '-I', '-c', 'pass'],
                                     requested_seconds=2)
                global_result, hp_result = global_future.result(), hp_future.result()
            self.assertEqual(pending['status'], 'PENDING_SHARED_PHYSICAL_BUDGET')
            self.assertEqual(global_result['status'], 'STOPPED_JOB_WALL')
            self.assertEqual(hp_result['status'], 'STOPPED_JOB_WALL')
            self.assertTrue(global_result['cleanup_complete'])
            self.assertTrue(hp_result['cleanup_complete'])
            self.assertFalse(Path(f'/proc/{global_pid}').exists())
            self.assertFalse(Path(f'/proc/{hp_pid}').exists())
            state = bridge.snapshot()
            self.assertEqual(len(state['finished']), 2)
            self.assertEqual({row['kind'] for row in state['finished']},
                             {'GLOBAL', 'HP'})
            self.assertEqual(state['reserved_seconds'], 0)
            self.assertLessEqual(state['spent_seconds'], 30)

    def test_restart_preserves_measured_spend_for_next_kind(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=15)
            first = bridge.run('GLOBAL', detached_sleeper(root / 'first.pid'),
                               requested_seconds=2)
            self.assertEqual(first['status'], 'STOPPED_JOB_WALL')
            self.assertGreaterEqual(first['physical_seconds'], 2)
            restarted = PersistentGuardedFuzzBridge.restore(root,
                                                             total_seconds=15)
            second = restarted.run('HP', [sys.executable, '-I', '-c', 'pass'],
                                   requested_seconds=1)
            self.assertEqual(second['status'], 'PENDING_SHARED_PHYSICAL_BUDGET')
            self.assertEqual(len(restarted.snapshot()['finished']), 1)

    def test_checkpoint_integrity_failure_is_not_budget_pending(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=15)
            bridge.ledger.path.chmod(0o644)
            with patch.object(bridge.command_group, 'run') as launch:
                with self.assertRaisesRegex(ValueError, 'single-link owned mode 0600'):
                    bridge.run('SP', [sys.executable, '-I', '-c', 'pass'],
                               requested_seconds=1)
                # A failed integrity check taints the owner. The next request
                # must still fail before launch, independent of error wording.
                with self.assertRaises(RuntimeError):
                    bridge.run('HP', [sys.executable, '-I', '-c', 'pass'],
                               requested_seconds=1)
                launch.assert_not_called()

    def test_cleanup_failure_stops_persistent_admission(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=15)
            marker = root / 'child.pid'
            real_cleanup = runner._request_guard_cleanup

            def reported_failure(child, status):
                real_cleanup(child, status)
                return False

            with patch.object(runner, '_request_guard_cleanup',
                              side_effect=reported_failure):
                result = bridge.run('GLOBAL', detached_sleeper(marker),
                                    requested_seconds=0.2)
            pid = wait_for_marker(marker)
            self.assertFalse(Path(f'/proc/{pid}').exists())
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(bridge.snapshot()['stop_status'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                bridge.run('SP', [sys.executable, '-I', '-c', 'pass'],
                           requested_seconds=0.2)

    def test_parallel_completed_job_settles_after_other_job_cleanup_stop(self):
        with TemporaryDirectory() as tmp:
            bridge = PersistentGuardedFuzzBridge.create(Path(tmp),
                                                       total_seconds=30)
            both_started = threading.Barrier(2)
            failed_done = threading.Event()

            def guarded(kind, _command, *, requested_seconds):
                both_started.wait(timeout=3)
                if kind == 'GLOBAL':
                    return {'status': 'STOPPED_CLEANUP_INCOMPLETE',
                            'physical_seconds': 1.0,
                            'cleanup_complete': False}
                if not failed_done.wait(timeout=3):
                    raise AssertionError('first job did not finish')
                return {'status': 'COMPLETED', 'physical_seconds': 2.0,
                        'cleanup_complete': True}

            def global_run():
                result = bridge.run('GLOBAL', [sys.executable],
                                    requested_seconds=1)
                failed_done.set()
                return result

            with patch.object(bridge.command_group, 'run', side_effect=guarded):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    global_future = pool.submit(global_run)
                    hp_future = pool.submit(bridge.run, 'HP',
                                            [sys.executable], requested_seconds=1)
                    global_result = global_future.result(timeout=5)
                    hp_result = hp_future.result(timeout=5)
            self.assertEqual(global_result['status'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(hp_result['status'], 'COMPLETED')
            self.assertEqual(hp_result['persistent_stop_status'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(bridge.snapshot()['spent_seconds'], 3.0)
            self.assertEqual(bridge.snapshot()['active'], {})
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                bridge.run('SP', [sys.executable], requested_seconds=1)

    def test_reported_physical_overrun_stops_admission(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=15)
            fake = {'status': 'COMPLETED', 'physical_seconds': 14.0,
                    'cleanup_complete': True}
            with patch.object(bridge.command_group, 'run', return_value=fake):
                result = bridge.run('HP', [sys.executable, '-I', '-c', 'pass'],
                                    requested_seconds=1)
            self.assertEqual(result['status'], 'STOPPED_PHYSICAL_CAP_UNPROVEN')
            self.assertEqual(bridge.snapshot()['spent_seconds'], 14.0)
            self.assertEqual(bridge.snapshot()['stop_status'],
                             'STOPPED_PHYSICAL_CAP_UNPROVEN')
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                bridge.run('GLOBAL', [sys.executable, '-I', '-c', 'pass'],
                           requested_seconds=0.1)

    def test_guard_error_wins_over_accounting_error_and_restore_stops(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = PersistentGuardedFuzzBridge.create(root, total_seconds=15)
            with patch.object(bridge.command_group, 'run',
                              side_effect=RuntimeError('original guard error')), \
                 patch.object(bridge.ledger, 'finish',
                              side_effect=RuntimeError('ledger write failed')):
                with self.assertRaisesRegex(RuntimeError, 'original guard error'):
                    bridge.run('SP', [sys.executable, '-I', '-c', 'pass'],
                               requested_seconds=1)
            restored = PersistentGuardedFuzzBridge.restore(root, total_seconds=15)
            self.assertEqual(restored.snapshot()['stop_status'],
                             'STOPPED_UNCERTAIN_PROCESS')


if __name__ == '__main__':
    unittest.main()
