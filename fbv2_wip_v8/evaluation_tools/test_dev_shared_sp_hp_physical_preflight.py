"""Provider-free admission checks for the development SP/HP Scan handoff."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
CLANG = HERE.parent / 'review_tools/local_clang/clang'
sys.path[:0] = [str(HERE), str(PRODUCT / 'src')]

from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger  # noqa: E402
from dev_product_fuzz_physical_adapter import ProductFuzzPhysicalRunner  # noqa: E402
from dev_shared_sp_hp_physical_preflight import (  # noqa: E402
    SharedPhysicalPreflightError, make_shared_sp_hp_runners,
    scan_selected_with_shared_sp_hp_physical)
from vulnerabilityanalysis import runtime, scan  # noqa: E402


class SharedSpHpPhysicalPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'physical.json'
        self.ledger = PersistentPhysicalFuzzLedger.create(
            self.path, total_seconds=60)
        self.sp = ProductFuzzPhysicalRunner(self.ledger, kind='SP')
        self.hp = ProductFuzzPhysicalRunner(self.ledger, kind='HP')
        self.options = {
            'max_candidates': 1,
            'candidate_budget_policy': 'QUEUE_FIRST_DEV',
            'official_qualification': object(),
            'targeted_fuzzer_binary': self.root / 'toy-fuzzer',
            'targeted_fuzz_seconds': 1,
            'assertion_fuzz_seconds': 1,
            'global_fuzz_enabled': False,
            'global_fuzz_seconds': 0,
        }

    def dispatch(self, *, sp=None, hp=None, path=None, total=60, options=None):
        return asyncio.run(scan_selected_with_shared_sp_hp_physical(
            self.root / 'run', object(),
            contract_ledger_path=self.path if path is None else path,
            contract_total_seconds=total,
            sp_runner=self.sp if sp is None else sp,
            hp_runner=self.hp if hp is None else hp,
            scan_options=self.options if options is None else options))

    def test_invalid_callbacks_are_rejected_before_provider_or_fuzzer(self):
        other_path = self.root / 'other.json'
        other = PersistentPhysicalFuzzLedger.create(other_path, total_seconds=60)
        restored = PersistentPhysicalFuzzLedger.restore(self.path, total_seconds=60)
        cases = (
            {'hp': ProductFuzzPhysicalRunner(other, kind='HP')},
            {'hp': ProductFuzzPhysicalRunner(restored, kind='HP')},
            {'sp': lambda *_args, **_kwargs: None},
            {'sp': ProductFuzzPhysicalRunner(self.ledger, kind='HP')},
            {'hp': ProductFuzzPhysicalRunner(self.ledger, kind='GLOBAL')},
            {'path': other_path},
            {'total': 61},
        )
        provider_calls: list[int] = []

        async def fake_scan(*_args, **_kwargs):
            provider_calls.append(1)

        with patch.object(scan, 'scan_selected', fake_scan), \
                patch.object(runtime, '_guarded_run') as child:
            for case in cases:
                with self.subTest(case=case), \
                        self.assertRaises(SharedPhysicalPreflightError):
                    self.dispatch(**case)
        self.assertEqual(provider_calls, [])
        child.assert_not_called()

    def test_tampered_checkpoint_and_lock_are_fatal_before_dispatch(self):
        provider_calls: list[int] = []

        async def fake_scan(*_args, **_kwargs):
            provider_calls.append(1)

        with patch.object(scan, 'scan_selected', fake_scan), \
                patch.object(runtime, '_guarded_run') as child:
            state = json.loads(self.path.read_text())
            state['revision'] += 1
            self.path.write_text(json.dumps(state))
            with self.assertRaises(SharedPhysicalPreflightError):
                self.dispatch()
            lock_path = self.root / 'lock-test.json'
            lock_ledger = PersistentPhysicalFuzzLedger.create(
                lock_path, total_seconds=60)
            lock_sp = ProductFuzzPhysicalRunner(lock_ledger, kind='SP')
            lock_hp = ProductFuzzPhysicalRunner(lock_ledger, kind='HP')
            lock_path.with_name(lock_path.name + '.lock').chmod(0o644)
            with self.assertRaises(SharedPhysicalPreflightError):
                self.dispatch(sp=lock_sp, hp=lock_hp, path=lock_path)
        self.assertEqual(provider_calls, [])
        child.assert_not_called()

    def test_global_on_and_callback_override_are_rejected(self):
        provider_calls: list[int] = []

        async def fake_scan(*_args, **_kwargs):
            provider_calls.append(1)

        with patch.object(scan, 'scan_selected', fake_scan):
            for change in ({'global_fuzz_enabled': True},
                           {'global_fuzz_seconds': 1},
                           {'global_fuzzer_binary': self.root / 'global'},
                           {'hp_guided_guarded_runner': lambda: None}):
                with self.subTest(change=change), \
                        self.assertRaises(SharedPhysicalPreflightError):
                    self.dispatch(options={**self.options, **change})
        self.assertEqual(provider_calls, [])

    def test_factory_forwards_two_callbacks_with_one_ledger(self):
        sp, hp = make_shared_sp_hp_runners(
            self.ledger, contract_ledger_path=self.path,
            contract_total_seconds=60)
        received = []

        async def fake_scan(_run, _provider, **kwargs):
            received.append(kwargs)
            return 'forwarded'

        with patch.object(scan, 'scan_selected', fake_scan):
            result = self.dispatch(sp=sp, hp=hp)
        self.assertEqual(result, 'forwarded')
        self.assertEqual(len(received), 1)
        self.assertIs(received[0]['targeted_fuzz_guarded_runner'], sp)
        self.assertIs(received[0]['hp_guided_guarded_runner'], hp)
        self.assertIs(sp.ledger, hp.ledger)
        self.assertIs(sp.ledger, self.ledger)

    def test_same_ledger_callbacks_reserve_before_each_low_level_start(self):
        binary = self.root / 'toy-fuzzer'
        binary.write_bytes(b'provider-free toy')
        starts: list[list[str]] = []

        def fake_child(command, **_kwargs):
            snapshot = self.ledger.snapshot()
            self.assertEqual(len(snapshot['active']), 1)
            starts.append(command)
            return subprocess.CompletedProcess(command, 0, '', '')

        async def fake_scan(_run, _provider, **kwargs):
            for key, corpus in (('targeted_fuzz_guarded_runner', 'sp-corpus'),
                                ('hp_guided_guarded_runner', 'hp-corpus')):
                runtime.fuzz_locally(binary, self.root / corpus, seconds=1,
                                     single_process=True,
                                     guarded_runner=kwargs[key])
            return 'ran'

        with patch.object(scan, 'scan_selected', fake_scan), \
                patch.object(runtime, '_guarded_run', side_effect=fake_child):
            self.assertEqual(self.dispatch(), 'ran')
        self.assertEqual(len(starts), 2)
        snapshot = self.ledger.snapshot()
        self.assertEqual([row['kind'] for row in snapshot['finished']], ['SP', 'HP'])
        self.assertEqual(snapshot['active'], {})
        self.assertIsNone(snapshot['stop_status'])

    @unittest.skipUnless(CLANG.is_file(), 'local Clang wrapper unavailable')
    def test_public_toy_runs_sp_and_hp_through_forwarded_callbacks(self):
        source = self.root / 'toy.c'
        source.write_text(
            '#include <stddef.h>\n#include <stdint.h>\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {'
            ' (void)d; (void)n; return 0; }\n', encoding='utf-8')
        binary = self.options['targeted_fuzzer_binary']
        built = subprocess.run(
            [str(CLANG), '-fsanitize=fuzzer,address', '-O1', str(source),
             '-o', str(binary)], capture_output=True, text=True,
            timeout=30, check=False)
        self.assertEqual(built.returncode, 0, built.stderr)

        async def fake_scan(_run, _provider, **kwargs):
            for key, label in (('targeted_fuzz_guarded_runner', 'sp'),
                               ('hp_guided_guarded_runner', 'hp')):
                corpus = self.root / label
                corpus.mkdir()
                (corpus / 'seed').write_bytes(b'A')
                result = runtime.fuzz_locally(
                    binary, corpus, seconds=1, single_process=True,
                    guarded_runner=kwargs[key])
                self.assertEqual(result.exit_code, 0, result.stderr[-1000:])
            return 'toy-complete'

        with patch.object(scan, 'scan_selected', fake_scan):
            self.assertEqual(self.dispatch(), 'toy-complete')
        state = self.ledger.snapshot()
        self.assertEqual([row['kind'] for row in state['finished']], ['SP', 'HP'])
        self.assertTrue(all(row['physical_seconds'] > 0 for row in state['finished']))
        self.assertEqual(state['active'], {})
        self.assertIsNone(state['stop_status'])


if __name__ == '__main__':
    unittest.main()
