"""Provider-free failure controls for a development physical fuzz ledger."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev_persistent_physical_fuzz_ledger import (PersistentPhysicalFuzzLedger,
                                                 PhysicalModelStartBlocked)


class PersistentPhysicalFuzzLedgerTests(unittest.TestCase):
    def test_model_start_guard_serializes_cleanup_stop_commit(self):
        with TemporaryDirectory() as temp:
            ledger = PersistentPhysicalFuzzLedger.create(
                Path(temp) / 'physical.json', total_seconds=10)
            entered, stopped = threading.Event(), threading.Event()

            def stop_physical():
                entered.set()
                ledger.reserve('sp:guard-test', 'SP', 2)
                ledger.finish('sp:guard-test', physical_seconds=1,
                              cleanup_complete=False)
                stopped.set()

            with ThreadPoolExecutor(max_workers=1) as pool:
                with ledger.model_start_guard():
                    pending = pool.submit(stop_physical)
                    self.assertTrue(entered.wait(timeout=2))
                    self.assertFalse(stopped.wait(timeout=.1))
                    self.assertIsNone(ledger.snapshot()['stop_status'])
                pending.result(timeout=2)
            self.assertTrue(stopped.is_set())
            self.assertEqual(ledger.snapshot()['stop_status'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            with self.assertRaises(PhysicalModelStartBlocked) as captured:
                with ledger.model_start_guard():
                    self.fail('a stopped physical ledger admitted a model start')
            self.assertEqual(captured.exception.status,
                             'STOPPED_CLEANUP_INCOMPLETE')

    def test_model_start_guard_rejects_active_job_without_taint(self):
        with TemporaryDirectory() as temp:
            ledger = PersistentPhysicalFuzzLedger.create(
                Path(temp) / 'physical.json', total_seconds=10)
            ledger.reserve('hp:active', 'HP', 3)
            with self.assertRaises(PhysicalModelStartBlocked) as captured:
                with ledger.model_start_guard():
                    self.fail('active physical job admitted a model start')
            self.assertEqual(captured.exception.status,
                             'STOPPED_UNCERTAIN_PROCESS')
            self.assertFalse(ledger._tainted)
            ledger.finish('hp:active', physical_seconds=1)
            with ledger.model_start_guard():
                pass

    def test_early_finish_releases_only_unused_reserved_time(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            ledger.reserve('sp:1', 'SP', 8)
            with self.assertRaises(ValueError):
                ledger.reserve('hp:1', 'HP', 3)
            row = ledger.finish('sp:1', physical_seconds=2)
            self.assertEqual((row['reserved_seconds'], row['physical_seconds']),
                             (8, 2))
            ledger.reserve('hp:1', 'HP', 7)
            restored = PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)
            self.assertEqual(restored.snapshot()['stop_status'],
                             'STOPPED_UNCERTAIN_PROCESS')
            with self.assertRaises(RuntimeError):
                restored.reserve('global:1', 'GLOBAL', 1)

    def test_completed_checkpoint_restores_and_reuses_remaining_time(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            ledger.reserve('sp:1', 'SP', 8)
            ledger.finish('sp:1', physical_seconds=2)
            resumed = PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)
            self.assertIsNone(resumed.snapshot()['stop_status'])
            resumed.reserve('hp:1', 'HP', 7)
            resumed.finish('hp:1', physical_seconds=1)
            self.assertEqual(resumed.snapshot()['spent_seconds'], 3)

    def test_overrun_blocks_next_job_and_persists(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=4)
            ledger.reserve('sp:1', 'SP', 3)
            row = ledger.finish('sp:1', physical_seconds=3.25)
            self.assertTrue(row['overrun'])
            self.assertEqual(ledger.snapshot()['stop_status'],
                             'STOPPED_PHYSICAL_CAP_UNPROVEN')
            restored = PersistentPhysicalFuzzLedger.restore(path, total_seconds=4)
            with self.assertRaises(RuntimeError):
                restored.reserve('hp:1', 'HP', .5)
            with self.assertRaises(RuntimeError):
                restored.finish('sp:1', physical_seconds=1)

    def test_active_reservation_restore_is_never_replayed(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=20)
            ledger.reserve('global:1', 'GLOBAL', 9)
            restored = PersistentPhysicalFuzzLedger.restore(path, total_seconds=20)
            snapshot = restored.snapshot()
            self.assertEqual(snapshot['active']['global:1']['reserved_seconds'], 9)
            self.assertEqual(snapshot['stop_status'], 'STOPPED_UNCERTAIN_PROCESS')
            self.assertEqual(snapshot['spent_seconds'], 0)
            with self.assertRaises(RuntimeError):
                restored.reserve('sp:1', 'SP', 1)
            self.assertEqual(PersistentPhysicalFuzzLedger.restore(
                path, total_seconds=20).snapshot(), snapshot)

    def test_parallel_reservations_cannot_oversubscribe(self):
        with TemporaryDirectory() as temp:
            ledger = PersistentPhysicalFuzzLedger.create(
                Path(temp) / 'physical.json', total_seconds=10)
            gate = threading.Barrier(2)
            def reserve(key: str) -> bool:
                gate.wait(timeout=2)
                try:
                    ledger.reserve(key, 'SP', 7)
                    return True
                except ValueError:
                    return False
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(reserve, ('a', 'b')))
            self.assertEqual(sorted(results), [False, True])
            self.assertEqual(ledger.snapshot()['reserved_seconds'], 7)

    def test_two_restored_owners_cannot_overwrite_each_other(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            owners = [PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)
                      for _ in range(2)]
            gate = threading.Barrier(2)
            def reserve(index: int) -> bool:
                gate.wait(timeout=2)
                try:
                    owners[index].reserve(f'sp:{index}', 'SP', 7)
                    return True
                except (RuntimeError, ValueError):
                    return False
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(reserve, (0, 1)))
            self.assertEqual(sorted(results), [False, True])
            state = PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)
            self.assertEqual(state.snapshot()['stop_status'],
                             'STOPPED_UNCERTAIN_PROCESS')
            self.assertEqual(state.snapshot()['reserved_seconds'], 7)

    def test_cleanup_failure_stops_even_without_overrun(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            ledger.reserve('sp:1', 'SP', 4)
            row = ledger.finish('sp:1', physical_seconds=1,
                                cleanup_complete=False)
            self.assertFalse(row['cleanup_complete'])
            self.assertFalse(row['overrun'])
            self.assertEqual(PersistentPhysicalFuzzLedger.restore(
                path, total_seconds=10).snapshot()['stop_status'],
                'STOPPED_CLEANUP_INCOMPLETE')

    def test_started_parallel_job_can_settle_after_cleanup_stop(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            ledger.reserve('global:1', 'GLOBAL', 4)
            ledger.reserve('hp:1', 'HP', 4)
            ledger.finish('global:1', physical_seconds=1,
                          cleanup_complete=False)
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                ledger.reserve('sp:1', 'SP', 1)
            hp = ledger.finish('hp:1', physical_seconds=2)
            self.assertTrue(hp['cleanup_complete'])
            state = ledger.snapshot()
            self.assertEqual(state['stop_status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(state['spent_seconds'], 3)
            self.assertEqual(state['active'], {})
            self.assertEqual(len(state['finished']), 2)
            restored = PersistentPhysicalFuzzLedger.restore(path,
                                                             total_seconds=10)
            self.assertEqual(restored.snapshot()['finished'], state['finished'])
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                restored.reserve('sp:2', 'SP', 1)

    def test_restored_owner_cannot_settle_previous_owners_active_job(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            ledger.reserve('global:1', 'GLOBAL', 4)
            ledger.reserve('hp:1', 'HP', 4)
            ledger.finish('global:1', physical_seconds=1,
                          cleanup_complete=False)
            restored = PersistentPhysicalFuzzLedger.restore(path,
                                                             total_seconds=10)
            with self.assertRaisesRegex(RuntimeError, 'active job owner'):
                restored.finish('hp:1', physical_seconds=2)
            self.assertIn('hp:1', restored.snapshot()['active'])

    def test_external_checkpoint_change_taints_current_owner(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            path.write_bytes(path.read_bytes() + b' \n')
            with self.assertRaises(RuntimeError):
                ledger.reserve('sp:1', 'SP', 1)
            with self.assertRaises(RuntimeError):
                ledger.reserve('hp:1', 'HP', 1)

    def test_spent_counter_cannot_disagree_with_measured_records(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            ledger = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            ledger.reserve('sp:1', 'SP', 2)
            ledger.finish('sp:1', physical_seconds=1)
            state = json.loads(path.read_text())
            state['spent_seconds'] = 0.0
            path.write_text(json.dumps(state, sort_keys=True, separators=(',', ':')) + '\n')
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)

    def test_duplicate_key_and_finish_are_rejected(self):
        with TemporaryDirectory() as temp:
            ledger = PersistentPhysicalFuzzLedger.create(
                Path(temp) / 'physical.json', total_seconds=10)
            ledger.reserve('sp:1', 'SP', 2)
            with self.assertRaises(ValueError):
                ledger.reserve('sp:1', 'SP', 2)
            ledger.finish('sp:1', physical_seconds=1)
            with self.assertRaises(ValueError):
                ledger.reserve('sp:1', 'SP', 2)
            with self.assertRaises(ValueError):
                ledger.finish('sp:1', physical_seconds=1)

    def test_link_and_permission_tamper_fail_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'physical.json'
            PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            alias = root / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(alias, total_seconds=10)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)
            os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(path, total_seconds=9)
            lock = root / 'physical.json.lock'
            os.chmod(lock, 0o644)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(path, total_seconds=10)

    def test_hardlink_alias_cannot_split_one_checkpoint_into_two_ledgers(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, alias = root / 'physical.json', root / 'alias.json'
            owner = PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            os.link(path, alias)
            alias_lock = root / 'alias.json.lock'
            descriptor = os.open(alias_lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(alias, total_seconds=10)
            with self.assertRaises(ValueError):
                owner.reserve('sp:1', 'SP', 7)

    def test_relative_or_traversal_checkpoint_paths_are_rejected(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'physical.json'
            PersistentPhysicalFuzzLedger.create(path, total_seconds=10)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.create(Path('physical.json'),
                                                    total_seconds=10)
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(Path('physical.json'),
                                                     total_seconds=10)
            traversal = Path(temp) / '..' / Path(temp).name / 'physical.json'
            with self.assertRaises(ValueError):
                PersistentPhysicalFuzzLedger.restore(traversal, total_seconds=10)


if __name__ == '__main__':
    unittest.main()
