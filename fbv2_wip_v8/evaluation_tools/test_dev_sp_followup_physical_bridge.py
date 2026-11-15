"""Provider-free failed-PoV handoff tests for the development physical ledger."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(HERE), str(PRODUCT / 'src')]

import blind2_runner_draft as formal  # noqa: E402
from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger  # noqa: E402
from dev_product_fuzz_physical_adapter import (  # noqa: E402
    PhysicalFuzzLedgerStop, ProductFuzzPhysicalRunner)
from dev_sp_followup_physical_bridge import DevSpFollowupPhysicalCall  # noqa: E402
from vulnerabilityanalysis import runtime, scan  # noqa: E402
from vulnerabilityanalysis.models import SuspiciousPoint  # noqa: E402


class DevSpFollowupPhysicalBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.run = self.root / 'run'
        self.corpus = self.run / 'corpus/candidate/SP1'
        self.corpus.mkdir(parents=True)
        (self.corpus / 'seed').write_bytes(b'Y')
        (self.run / 'sp').mkdir()
        point = SuspiciousPoint('SP1', 'worker', 'direction', 'parse',
                                'target.c', 'target.c:1', 'read', 'bounds',
                                [], 'bytes', [], [], [], [])
        (self.run / 'sp/candidates.json').write_text(json.dumps([asdict(point)]))
        self.binary = self.root / 'fuzzer'
        self.binary.write_bytes(b'provider-free synthetic fuzzer')
        self.ledger_path = self.root / 'physical.json'

    def _make_call(self, *, total: int = 30,
                   kind: str = 'SP') -> DevSpFollowupPhysicalCall:
        ledger = PersistentPhysicalFuzzLedger.create(
            self.ledger_path, total_seconds=total)
        self.physical = ProductFuzzPhysicalRunner(ledger, kind=kind)
        return DevSpFollowupPhysicalCall(
            physical_runner=self.physical,
            contract_ledger_path=self.ledger_path,
            contract_total_seconds=total,
            expected_run=self.run, expected_binary=self.binary,
            expected_binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            expected_sp_id='SP1', fuzz_seconds=2)

    def _run_followup(self, call: DevSpFollowupPhysicalCall):
        meter = formal.SharedFuzzMeter(
            formal.Ledger(started_at=time.time()), self.root / 'logical.json')
        with patch.object(formal, 'crash_free_pov_rows', return_value=[
                {'sp_id': 'SP1', 'poc_id': 'POV1'}]), \
             patch.object(formal, 'ensure_clean_pov_seed', return_value={
                 'status': 'BOUND_CLEAN_POV'}):
            return formal.run_failed_pov_followups(
                self.run, self.binary, meter, fuzzer_call=call)

    def test_formal_followup_injects_exact_two_second_sp_command(self):
        call = self._make_call()
        actual = []

        def fake_targeted(_point, _binary, _run, _retry, _evidence_ids,
                          *, seconds, guarded_runner):
            self.assertEqual(seconds, 2)
            return_value = guarded_runner(
                [str(self.binary), str(self.corpus), '-max_total_time=2',
                 '-max_len=8388608', '-print_final_stats=1'],
                cwd=self.corpus, timeout=17)
            self.assertEqual(return_value.returncode, 0)
            return {'status': 'RAN'}

        def fake_process(argv, *, cwd, timeout):
            actual.append((argv, cwd, timeout))
            return subprocess.CompletedProcess(argv, 0, '', '')

        with patch.object(scan, 'run_targeted_fuzz', side_effect=fake_targeted), \
             patch.object(runtime, '_guarded_run', side_effect=fake_process):
            receipts = self._run_followup(call)
        self.assertEqual(receipts[0]['status'], 'FUZZ_RETURNED')
        self.assertEqual(len(actual), 1)
        self.assertEqual(actual[0][2], 17)
        finished = call.physical_runner.ledger.snapshot()['finished']
        self.assertEqual(len(finished), 1)
        self.assertEqual(finished[0]['kind'], 'SP')
        self.assertEqual(finished[0]['reserved_seconds'], 26.5)

    def test_insufficient_physical_budget_is_pending_without_start(self):
        call = self._make_call(total=20)
        with patch.object(scan, 'run_targeted_fuzz') as targeted, \
             patch.object(runtime, '_guarded_run') as process:
            receipts = self._run_followup(call)
        self.assertEqual(receipts[0]['status'],
                         'FUZZ_PENDING_PHYSICAL_FUZZ_BUDGET')
        targeted.assert_not_called()
        process.assert_not_called()
        self.assertEqual(call.physical_runner.ledger.snapshot()['finished'], [])

    def test_binary_pin_change_is_fatal_before_product_call(self):
        call = self._make_call()
        self.binary.write_bytes(b'changed after pin')
        with patch.object(scan, 'run_targeted_fuzz') as targeted:
            with self.assertRaises(PhysicalFuzzLedgerStop):
                self._run_followup(call)
        targeted.assert_not_called()
        self.assertEqual(call.physical_runner.ledger.snapshot()['finished'], [])

    def test_corpus_retarget_is_fatal_before_product_call(self):
        call = self._make_call()
        self.corpus.rename(self.corpus.with_name('moved'))
        self.corpus.symlink_to(self.corpus.with_name('moved'),
                               target_is_directory=True)
        with patch.object(scan, 'run_targeted_fuzz') as targeted:
            with self.assertRaises(PhysicalFuzzLedgerStop):
                self._run_followup(call)
        targeted.assert_not_called()
        self.assertEqual(call.physical_runner.ledger.snapshot()['finished'], [])

    def test_short_logical_grant_is_pending_without_product_call(self):
        call = self._make_call()
        with patch.object(scan, 'run_targeted_fuzz') as targeted:
            result = call(SimpleNamespace(sp_id='SP1'), self.binary,
                          self.run, object(), [], seconds=1)
        # The target identity must still be valid before budget is classified.
        self.assertEqual(result['status'], 'PENDING_PHYSICAL_FUZZ_BUDGET')
        targeted.assert_not_called()

    def test_unpinned_argv_is_fatal_before_physical_start(self):
        call = self._make_call()

        def fake_targeted(_point, _binary, _run, _retry, _evidence_ids,
                          *, seconds, guarded_runner):
            return guarded_runner(
                [str(self.binary), str(self.corpus), '-max_total_time=300',
                 '-max_len=8388608', '-print_final_stats=1'],
                cwd=self.corpus, timeout=17)

        with patch.object(scan, 'run_targeted_fuzz', side_effect=fake_targeted), \
             patch.object(runtime, '_guarded_run') as process:
            with self.assertRaises(PhysicalFuzzLedgerStop):
                self._run_followup(call)
        process.assert_not_called()
        self.assertEqual(call.physical_runner.ledger.snapshot()['finished'], [])

    def test_missing_formal_max_len_is_fatal_before_physical_start(self):
        call = self._make_call()

        def fake_targeted(_point, _binary, _run, _retry, _evidence_ids,
                          *, seconds, guarded_runner):
            return guarded_runner(
                [str(self.binary), str(self.corpus), '-max_total_time=2',
                 '-print_final_stats=1'], cwd=self.corpus, timeout=17)

        with patch.object(scan, 'run_targeted_fuzz', side_effect=fake_targeted), \
             patch.object(runtime, '_guarded_run') as process:
            with self.assertRaises(PhysicalFuzzLedgerStop):
                self._run_followup(call)
        process.assert_not_called()

    def test_corrupted_checkpoint_is_fatal_not_budget_pending(self):
        call = self._make_call(total=20)
        self.ledger_path.write_text('{}\n')
        with patch.object(scan, 'run_targeted_fuzz') as targeted:
            with self.assertRaises(PhysicalFuzzLedgerStop):
                self._run_followup(call)
        targeted.assert_not_called()

    def test_wrong_role_or_total_rejected_before_start(self):
        with self.assertRaises(PhysicalFuzzLedgerStop):
            self._make_call(kind='HP')
        other = self.root / 'other'
        other.mkdir(mode=0o700)
        physical = ProductFuzzPhysicalRunner(
            PersistentPhysicalFuzzLedger.create(other / 'physical.json',
                                                total_seconds=30), kind='SP')
        with self.assertRaises(PhysicalFuzzLedgerStop):
            DevSpFollowupPhysicalCall(
                physical_runner=physical,
                contract_ledger_path=other / 'physical.json',
                contract_total_seconds=31,
                expected_run=self.run, expected_binary=self.binary,
                expected_binary_sha256=hashlib.sha256(
                    self.binary.read_bytes()).hexdigest(),
                expected_sp_id='SP1', fuzz_seconds=2)

    def test_wrong_ledger_path_rejected_before_start(self):
        call = self._make_call()
        with self.assertRaises(PhysicalFuzzLedgerStop):
            DevSpFollowupPhysicalCall(
                physical_runner=call.physical_runner,
                contract_ledger_path=self.root / 'different.json',
                contract_total_seconds=30,
                expected_run=self.run, expected_binary=self.binary,
                expected_binary_sha256=hashlib.sha256(
                    self.binary.read_bytes()).hexdigest(),
                expected_sp_id='SP1', fuzz_seconds=2)


if __name__ == '__main__':
    unittest.main()
