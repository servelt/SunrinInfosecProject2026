"""Provider-free and public toy checks for the opt-in product fuzz runner."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREP = HERE.parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(HERE), str(PRODUCT / 'src')]

from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger  # noqa: E402
from dev_product_fuzz_physical_adapter import (  # noqa: E402
    PhysicalFuzzLedgerStop, ProductFuzzPhysicalRunner)
from vulnerabilityanalysis import runtime  # noqa: E402
from vulnerabilityanalysis.analysis import RetryLedger  # noqa: E402
from vulnerabilityanalysis.assertions import guided_fuzz_assertion  # noqa: E402
from vulnerabilityanalysis.models import Assertion, SuspiciousPoint  # noqa: E402
from vulnerabilityanalysis.scan import run_targeted_fuzz  # noqa: E402


CLANG = PREP / 'review_tools/local_clang/clang'


class ProductFuzzPhysicalAdapterTests(unittest.TestCase):
    def setUp(self):
        evidence_dir = os.environ.get('VA_STAGE2B_TOY_EVIDENCE_DIR')
        if evidence_dir:
            self.root = Path(evidence_dir).resolve()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            self.temp = tempfile.TemporaryDirectory()
            self.addCleanup(self.temp.cleanup)
            self.root = Path(self.temp.name)
        self.ledger = PersistentPhysicalFuzzLedger.create(
            self.root / 'physical.json', total_seconds=35)
        self.binary = self.root / 'target'
        self.binary.write_bytes(b'test binary')

    def fuzz(self, kind='SP', *, corpus='corpus', seconds=1):
        return runtime.fuzz_locally(
            self.binary, self.root / corpus, seconds=seconds,
            single_process=True,
            guarded_runner=ProductFuzzPhysicalRunner(self.ledger, kind=kind))

    def test_prelaunch_reservation_shared_by_sp_hp_global(self):
        launched = threading.Event()
        release = threading.Event()
        observed = []

        def guarded(command, **kwargs):
            observed.append(self.ledger.snapshot())
            launched.set()
            self.assertTrue(release.wait(timeout=3))
            return subprocess.CompletedProcess(command, 0, '', '')

        with patch.object(runtime, '_guarded_run', side_effect=guarded):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.fuzz, 'SP', corpus='sp-corpus')
                self.assertTrue(launched.wait(timeout=3))
                with self.assertRaises(runtime.PhysicalFuzzBudgetPending):
                    self.fuzz('HP', corpus='hp-corpus')
                release.set()
                first.result(timeout=5)
                self.assertEqual(self.fuzz('GLOBAL', corpus='global-corpus').exit_code, 0)
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0]['reserved_seconds'], 25.5)
        state = self.ledger.snapshot()
        self.assertEqual(state['active'], {})
        self.assertEqual([row['kind'] for row in state['finished']], ['SP', 'GLOBAL'])
        self.assertIsNone(state['stop_status'])

    def test_timeout_keeps_original_product_classification_and_settles(self):
        def timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs['timeout'],
                                            output=b'progress', stderr=b'')
        with patch.object(runtime, '_guarded_run', side_effect=timeout):
            result = self.fuzz('SP')
        self.assertTrue(result.timed_out)
        self.assertEqual(result.failure_classification, 'ENVIRONMENT_ERROR')
        state = self.ledger.snapshot()
        self.assertEqual(state['active'], {})
        self.assertTrue(state['finished'][0]['cleanup_complete'])
        self.assertIsNone(state['stop_status'])

    def test_timeout_does_not_hide_other_active_jobs_cleanup_stop(self):
        self.ledger = PersistentPhysicalFuzzLedger.create(
            self.root / 'parallel.json', total_seconds=60)
        both_started = threading.Barrier(2)
        failed_done = threading.Event()

        def guarded(command, **kwargs):
            both_started.wait(timeout=3)
            if kwargs['cwd'].name == 'global-corpus':
                raise runtime.RuntimeCleanupError('global cleanup incomplete', '', '')
            if not failed_done.wait(timeout=3):
                raise AssertionError('global failure did not settle')
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])

        def global_run():
            try:
                self.fuzz('GLOBAL', corpus='global-corpus')
            except runtime.RuntimeCleanupError:
                pass
            finally:
                failed_done.set()

        with patch.object(runtime, '_guarded_run', side_effect=guarded):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(global_run)
                second = pool.submit(self.fuzz, 'HP', corpus='hp-corpus')
                first.result(timeout=5)
                with self.assertRaises(PhysicalFuzzLedgerStop) as caught:
                    second.result(timeout=5)
        self.assertIsInstance(caught.exception.__cause__,
                              subprocess.TimeoutExpired)
        state = self.ledger.snapshot()
        self.assertEqual(state['stop_status'], 'STOPPED_CLEANUP_INCOMPLETE')
        self.assertEqual(state['active'], {})
        self.assertEqual(len(state['finished']), 2)

    def test_cleanup_failure_preserves_original_error_and_stops_next_start(self):
        original = runtime.RuntimeCleanupError('cleanup incomplete', '', 'partial')
        with patch.object(runtime, '_guarded_run', side_effect=original) as launch:
            with self.assertRaises(runtime.RuntimeCleanupError) as caught:
                self.fuzz('HP')
            self.assertIs(caught.exception, original)
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                self.fuzz('GLOBAL', corpus='later')
            self.assertEqual(launch.call_count, 1)
        state = self.ledger.snapshot()
        self.assertEqual(state['stop_status'], 'STOPPED_CLEANUP_INCOMPLETE')
        self.assertFalse(state['finished'][0]['cleanup_complete'])

    def test_integrity_error_is_not_budget_pending_or_a_launch(self):
        self.ledger.path.chmod(0o644)
        with patch.object(runtime, '_guarded_run') as launch:
            with self.assertRaises(PhysicalFuzzLedgerStop) as stopped:
                self.fuzz('SP')
            launch.assert_not_called()
        self.assertEqual(stopped.exception.status,
                         'STOPPED_PHYSICAL_LEDGER_ERROR')

    def test_insufficient_budget_still_checks_disk_integrity_before_pending(self):
        for name, corrupt in (
                ('permissions', lambda ledger: ledger.path.chmod(0o644)),
                ('bytes', lambda ledger: ledger.path.write_bytes(b'{}')),
                ('lock_permissions', lambda ledger: ledger.lock_path.chmod(0o644))):
            with self.subTest(name=name):
                self.ledger = PersistentPhysicalFuzzLedger.create(
                    self.root / f'{name}.json', total_seconds=1)
                corrupt(self.ledger)
                with patch.object(runtime, '_guarded_run') as launch:
                    with self.assertRaises(PhysicalFuzzLedgerStop) as stopped:
                        self.fuzz('SP', corpus=f'{name}-corpus')
                    launch.assert_not_called()
                self.assertEqual(stopped.exception.status,
                                 'STOPPED_PHYSICAL_LEDGER_ERROR')

    def test_physical_overrun_does_not_return_success(self):
        with patch.object(runtime, '_guarded_run',
                          return_value=subprocess.CompletedProcess([], 0, '', '')), \
             patch('dev_product_fuzz_physical_adapter.time.monotonic',
                   side_effect=[0.0, 30.0]):
            with self.assertRaises(PhysicalFuzzLedgerStop):
                self.fuzz('SP')
        self.assertEqual(self.ledger.snapshot()['stop_status'],
                         'STOPPED_PHYSICAL_CAP_UNPROVEN')

    def test_successful_guard_cannot_return_if_settlement_is_corrupted(self):
        def tamper(command, **kwargs):
            self.ledger.path.chmod(0o644)
            return subprocess.CompletedProcess(command, 0, '', '')
        with patch.object(runtime, '_guarded_run', side_effect=tamper):
            with self.assertRaises(PhysicalFuzzLedgerStop) as stopped:
                self.fuzz('SP')
        self.assertEqual(stopped.exception.status,
                         'STOPPED_PHYSICAL_LEDGER_ERROR')
        self.assertIn('SP:', next(iter(self.ledger.snapshot()['active'])))

    @unittest.skipUnless(CLANG.is_file(), 'local Clang wrapper unavailable')
    def test_real_public_libfuzzer_uses_product_guard_and_persistent_ledger(self):
        source = self.root / 'toy.c'
        source.write_text(
            '#include <stddef.h>\n#include <stdint.h>\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {'
            ' if (n && d[0] == 0x7f) return 0; return 0; }\n',
            encoding='utf-8')
        built = subprocess.run(
            [str(CLANG), '-fsanitize=fuzzer,address', '-O1', str(source),
             '-o', str(self.binary)], capture_output=True, text=True,
            timeout=30, check=False)
        self.assertEqual(built.returncode, 0, built.stderr)
        corpus = self.root / 'real-corpus'
        corpus.mkdir()
        (corpus / 'seed').write_bytes(b'A')
        result = self.fuzz('SP', corpus='real-corpus')
        self.assertEqual(result.exit_code, 0, result.stderr[-1000:])
        self.assertFalse(result.timed_out)
        state = self.ledger.snapshot()
        self.assertEqual(len(state['finished']), 1)
        self.assertGreater(state['spent_seconds'], 0)
        self.assertLess(state['spent_seconds'], 25.5)
        self.assertEqual(state['active'], {})
        self.assertIsNone(state['stop_status'])

    @unittest.skipUnless(CLANG.is_file(), 'local Clang wrapper unavailable')
    def test_real_public_targeted_sp_fuzz_uses_same_physical_ledger(self):
        source = self.root / 'targeted-toy.c'
        source.write_text(
            '#include <stddef.h>\n#include <stdint.h>\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {'
            ' (void)d; (void)n; return 0; }\n', encoding='utf-8')
        built = subprocess.run(
            [str(CLANG), '-fsanitize=fuzzer,address', '-O1', str(source),
             '-o', str(self.binary)], capture_output=True, text=True,
            timeout=30, check=False)
        self.assertEqual(built.returncode, 0, built.stderr)
        point = SuspiciousPoint('sp', 'worker', 'direction', 'parse', 'target.c',
                                'target.c:1', 'read', 'bounds', [], 'bytes',
                                [], [], [], [])
        corpus = self.root / 'corpus/candidate/sp'
        corpus.mkdir(parents=True)
        (corpus / 'seed').write_bytes(b'A')
        result = run_targeted_fuzz(
            point, self.binary, self.root, RetryLedger(2), [], seconds=1,
            guarded_runner=ProductFuzzPhysicalRunner(self.ledger, kind='SP'))
        self.assertIsNotNone(result)
        state = self.ledger.snapshot()
        self.assertEqual([row['kind'] for row in state['finished']], ['SP'])
        self.assertGreater(state['spent_seconds'], 0)
        self.assertEqual(state['active'], {})
        self.assertIsNone(state['stop_status'])

    @unittest.skipUnless(CLANG.is_file(), 'local Clang wrapper unavailable')
    def test_public_sp_and_hp_guided_continuation_share_one_physical_ledger(self):
        source = self.root / 'target.c'
        source.write_text(
            '#include <stdint.h>\n#include <stddef.h>\n'
            'void target(const uint8_t *data, size_t size) {\n'
            '  if (!size) return;\n'
            '  size_t value = data[0];\n'
            '  (void)value;\n'
            '}\n', encoding='utf-8')
        harness = self.root / 'harness.c'
        harness.write_text(
            '#include <stdint.h>\n#include <stddef.h>\n'
            'void target(const uint8_t *, size_t);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) '
            '{ target(data,size); return 0; }\n', encoding='utf-8')
        build = [str(CLANG), '-fsanitize=fuzzer,address', '-g', '-O0',
                 '{source}', str(harness), '-o', '{binary}']
        built = subprocess.run(
            [part.replace('{source}', str(source)).replace('{binary}', str(self.binary))
             for part in build], capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        corpus = self.root / 'sp-corpus'
        corpus.mkdir()
        (corpus / 'seed').write_bytes(b'A')
        sp_runner = ProductFuzzPhysicalRunner(self.ledger, kind='SP')
        hp_runner = ProductFuzzPhysicalRunner(self.ledger, kind='HP')
        self.assertIs(sp_runner.ledger, hp_runner.ledger)
        sp_result = runtime.fuzz_locally(
            self.binary, corpus, seconds=1, single_process=True,
            guarded_runner=sp_runner)
        self.assertEqual(sp_result.exit_code, 0, sp_result.stderr[-1000:])
        seed = self.root / 'hp-seed'
        seed.write_bytes(b'\xff')
        assertion = Assertion('hp-toy', 'worker', 'direction', 'target',
                              'target.c:6', 'value <= 200', 'value <= 200', [])
        guided = guided_fuzz_assertion(
            assertion, source, 6, seed, self.root / 'hp-guided',
            build, ['{binary}', '{input}'], seconds=2,
            guarded_runner=hp_runner)
        self.assertEqual(guided['fuzzer_run_count'], 2, guided)
        self.assertEqual(guided['continuation']['status'], 'RAN', guided)
        self.assertEqual(guided['violation_triage']['assertion_status'], 'VIOLATED')
        state = self.ledger.snapshot()
        self.assertEqual([row['kind'] for row in state['finished']],
                         ['SP', 'HP', 'HP'])
        self.assertEqual(state['active'], {})
        self.assertIsNone(state['stop_status'])

    def test_targeted_sp_budget_pending_never_launches_fuzz_child(self):
        self.ledger = PersistentPhysicalFuzzLedger.create(
            self.root / 'tiny-physical.json', total_seconds=1)
        self.binary.write_text('#!/bin/sh\necho max_total_time\n')
        self.binary.chmod(0o755)
        point = SuspiciousPoint('sp', 'worker', 'direction', 'parse', 'target.c',
                                'target.c:1', 'read', 'bounds', [], 'bytes',
                                [], [], [], [])
        corpus = self.root / 'corpus/candidate/sp'
        corpus.mkdir(parents=True)
        (corpus / 'seed').write_bytes(b'A')
        with patch.object(runtime, '_guarded_run') as launched:
            with self.assertRaises(runtime.PhysicalFuzzBudgetPending):
                run_targeted_fuzz(
                    point, self.binary, self.root, RetryLedger(2), [], seconds=1,
                    guarded_runner=ProductFuzzPhysicalRunner(self.ledger, kind='SP'))
            launched.assert_not_called()
        self.assertEqual(self.ledger.snapshot()['active'], {})
        self.assertEqual(self.ledger.snapshot()['finished'], [])


if __name__ == '__main__':
    unittest.main()
