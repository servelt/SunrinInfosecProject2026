"""Provider-free checks for concurrent development fuzz command guards."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

import blind2_runner_draft as runner
import dev_global_physical_cap as cap


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
    while time.monotonic() < deadline and not marker.is_file():
        time.sleep(0.02)
    if not marker.is_file():
        raise AssertionError(f'guarded job did not start: {marker}')
    return int(marker.read_text())


class SharedPhysicalCapTests(unittest.TestCase):
    def test_missing_guard_receipt_is_cleanup_incomplete(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        try:
            self.assertEqual(cap._strict_guard_status(read_fd), -32768)
        finally:
            os.close(read_fd)

    def test_two_concurrent_detached_jobs_share_one_hard_cap(self):
        for second_kind, refused_kind in (('SP', 'HP'), ('HP', 'SP')):
            with self.subTest(second_kind=second_kind), TemporaryDirectory() as tmp:
                root = Path(tmp)
                group = cap.DevGuardedPhysicalFuzzGroup(
                    root, total_seconds=30, cleanup_envelope_seconds=12.5)
                first_marker, second_marker = root / 'global.pid', root / 'second.pid'
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(group.run, 'GLOBAL',
                                        detached_sleeper(first_marker),
                                        requested_seconds=2)
                    second = pool.submit(group.run, second_kind,
                                         detached_sleeper(second_marker),
                                         requested_seconds=2)
                    first_pid = wait_for_marker(first_marker)
                    second_pid = wait_for_marker(second_marker)
                    self.assertEqual(Path(f'/proc/{first_pid}').stat().st_uid,
                                     os.getuid())
                    self.assertEqual(Path(f'/proc/{second_pid}').stat().st_uid,
                                     os.getuid())
                    refused = group.run(refused_kind,
                                        [sys.executable, '-I', '-c', 'pass'],
                                        requested_seconds=2)
                    first_result, second_result = first.result(), second.result()
                self.assertEqual(refused['status'], 'PENDING_SHARED_PHYSICAL_BUDGET')
                self.assertEqual(first_result['status'], 'STOPPED_JOB_WALL')
                self.assertEqual(second_result['status'], 'STOPPED_JOB_WALL')
                self.assertTrue(first_result['cleanup_complete'])
                self.assertTrue(second_result['cleanup_complete'])
                self.assertFalse(Path(f'/proc/{first_pid}').exists())
                self.assertFalse(Path(f'/proc/{second_pid}').exists())
                snapshot = group.snapshot()
                self.assertLessEqual(snapshot['spent_seconds'], 30)
                self.assertEqual(snapshot['reserved_seconds'], 0)
                self.assertEqual(len(snapshot['records']), 2)
                self.assertEqual(
                    sum(row['physical_seconds'] for row in snapshot['records']),
                    snapshot['spent_seconds'])

    def test_cleanup_failure_is_not_reported_as_completed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            group = cap.DevGuardedPhysicalFuzzGroup(root, total_seconds=15,
                                                     cleanup_envelope_seconds=12.5)
            marker = root / 'detached.pid'
            real_cleanup = runner._request_guard_cleanup
            def reported_cleanup_failure(child, status):
                real_cleanup(child, status)
                return False
            with patch.object(cap.runner, '_request_guard_cleanup',
                              side_effect=reported_cleanup_failure):
                result = group.run('GLOBAL', detached_sleeper(marker),
                                   requested_seconds=1)
            detached = wait_for_marker(marker)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertFalse(result['cleanup_complete'])
            self.assertFalse(Path(f'/proc/{detached}').exists())
            self.assertLessEqual(group.snapshot()['spent_seconds'], 15)
            self.assertEqual(group.snapshot()['status'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            refused = group.run('SP', [sys.executable, '-I', '-c', 'pass'],
                                requested_seconds=1)
            self.assertEqual(refused['status'], 'STOPPED_CLEANUP_INCOMPLETE')


if __name__ == '__main__':
    unittest.main()
