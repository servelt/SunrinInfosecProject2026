"""Provider-free checks for the development HP iteration accounting boundary."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import blind2_runner_draft as old_runner
from blind3_hp_iteration_dev import (DevHPLedger, DevHPPolicy, load_dev_contract,
                                     run_sequence_dev)
from vulnerabilityanalysis.runtime import RuntimeCleanupError


class AccountedProvider:
    provider_free = True

    def __init__(self, ledger, checkpoint):
        self.ledger = ledger
        self.checkpoint = checkpoint
        self.function_id = None

    def begin_function(self, function_id):
        if not self.checkpoint.is_file():
            raise AssertionError('selection checkpoint missing before provider began')
        self.function_id = function_id

    def end_function(self):
        self.function_id = None

    async def generate(self, request):
        digest = hashlib.sha256(request.role.encode()).hexdigest()
        self.ledger.begin_turn(self.function_id, request.role, digest)
        self.ledger.checkpoint(self.checkpoint)
        self.ledger.start_attempt(digest)
        self.ledger.checkpoint(self.checkpoint)
        self.ledger.finish_attempt(completed=True)
        self.ledger.checkpoint(self.checkpoint)
        return {}


def contract(root: Path):
    policy = DevHPPolicy()
    path = root / 'dev-contract.json'
    path.write_text(json.dumps({'kind': 'BLIND3_HP_ITERATION_DEV',
                                'limits': asdict(policy)}, sort_keys=True))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, digest


class HPFormalDevBoundaryTests(unittest.TestCase):
    def test_0_run_rechecks_contract_before_provider_begins(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')
            path.write_text(path.read_text() + '\n')
            with patch.object(provider, 'begin_function') as begin:
                with self.assertRaisesRegex(ValueError, 'contract SHA'):
                    asyncio.run(run_sequence_dev(
                        run, provider, ledger, root, root / 'ledger.json',
                        policy=policy, contract_path=path))
                begin.assert_not_called()

    def test_0_contract_tamper_rejected_before_any_turn(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            loaded, _ = load_dev_contract(path, digest)
            self.assertEqual(loaded, DevHPPolicy())
            row = json.loads(path.read_text())
            row['limits']['assertion_generator_max'] = 1
            path.write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, 'contract SHA'):
                load_dev_contract(path, digest)

    def test_1_formal_runner_counts_one_refinement_and_two_guided_jobs(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            def fake_guided(*_args, **_kwargs):
                return {'status': 'RAN', 'fuzz_seconds_actual': 0.01,
                        'violation_witnesses': []}

            async def fake_refine(folder, *_args, **_kwargs):
                await provider.generate(SimpleNamespace(role='function_analysis'))
                await provider.generate(SimpleNamespace(role='assertion_generator'))
                return {'status': 'PROCESSED', 'llm_calls': 2,
                        'refinements': [{'status': 'REFINED_AND_TESTED'}]}

            async def fake_scan(folder, _provider, **options):
                self.assertEqual((options['sp_llm_call_limit'],
                                  options['hp_llm_call_limit'],
                                  options['hp_context_round_limit']), (3, 5, 1))
                await provider.generate(SimpleNamespace(role='sp_generation'))
                for role in ('function_analysis', 'function_analysis',
                             'assertion_generator'):
                    await provider.generate(SimpleNamespace(role=role))
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 3,
                    'original_hp_limit': 5, 'combined_limit': 8,
                    'hp_calls_before_transfer': 3, 'safe_assumption_count': 1,
                    'assertion_proposal_count': 1, 'checkable_assertion_count': 1,
                    'assertion_generation_status': 'COMPLETED',
                    'effective_sp_limit': 3, 'transferred_hp_calls': 0,
                    'reason': 'HP_ASSERTION_PATH'}))
                assertion = SimpleNamespace(assertion_id='a1')
                old_runner.scan_mod.guided_fuzz_assertion(assertion, seconds=1)
                triage = folder / 'assertions/a1/executions/e1/triage.json'
                triage.parent.mkdir(parents=True)
                triage.write_text(json.dumps({'classification': 'OVERSTRONG_ASSUMPTION'}))
                (folder / 'assertions/results.json').write_text(json.dumps([{
                    'assertion_id': 'a1', 'status': 'VIOLATED',
                    'execution_result': str(triage.parent / 'runtime.json')}]))
                outcome = await old_runner.scan_mod.refine_overstrong_assertions(
                    folder, function_id='fn', max_llm_calls=2)
                self.assertEqual(outcome['status'], 'PROCESSED')
                old_runner.scan_mod.guided_fuzz_assertion(assertion, seconds=1)
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 5, 'effective_sp_llm_call_limit': 3,
                    'combined_llm_call_limit': 8}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(old_runner.scan_mod, 'refine_overstrong_assertions', fake_refine), \
                 patch.object(old_runner.scan_mod, 'guided_fuzz_assertion', fake_guided):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))

            self.assertEqual(rows[0]['status'], 'BOUNDARY_ACCOUNTED')
            self.assertEqual((ledger.logical, ledger.physical), (6, 6))
            self.assertEqual(ledger.counts['fn']['function_analysis'], 3)
            self.assertEqual(ledger.counts['fn']['assertion_generator'], 2)
            jobs = json.loads((run / 'runtime/runner_fuzz_jobs.json').read_text())
            self.assertEqual(len([row for row in jobs if row['kind'] == 'ASSERTION']), 2)
            self.assertTrue((run / 'FUNCTION_CHECKPOINT.json').is_file())

    def test_2_budget_shortage_keeps_violation_pending_without_call(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')
            called = []

            async def forbidden_refine(*_args, **_kwargs):
                called.append(True)
                raise AssertionError('refinement called without two HP slots')

            async def fake_scan(folder, _provider, **_options):
                await provider.generate(SimpleNamespace(role='sp_generation'))
                for role in ('function_analysis', 'function_analysis',
                             'function_analysis', 'assertion_generator'):
                    await provider.generate(SimpleNamespace(role=role))
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 3,
                    'original_hp_limit': 5, 'combined_limit': 8,
                    'hp_calls_before_transfer': 4, 'safe_assumption_count': 1,
                    'assertion_proposal_count': 1, 'checkable_assertion_count': 1,
                    'assertion_generation_status': 'COMPLETED',
                    'effective_sp_limit': 3, 'transferred_hp_calls': 0,
                    'reason': 'HP_ASSERTION_PATH'}))
                triage = folder / 'assertions/a1/executions/e1/triage.json'
                triage.parent.mkdir(parents=True)
                triage.write_text(json.dumps({'classification': 'OVERSTRONG_ASSUMPTION'}))
                (folder / 'assertions/results.json').write_text(json.dumps([{
                    'assertion_id': 'a1', 'status': 'VIOLATED',
                    'execution_result': str(triage.parent / 'runtime.json')}]))
                result = await old_runner.scan_mod.refine_overstrong_assertions(
                    folder, function_id='fn', max_llm_calls=1)
                self.assertEqual(result['status'], 'PENDING_ROLE_BUDGET')
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 4, 'effective_sp_llm_call_limit': 3,
                    'combined_llm_call_limit': 8}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(old_runner.scan_mod, 'refine_overstrong_assertions', forbidden_refine):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))
            self.assertFalse(called)
            self.assertEqual(rows[0]['status'], 'INCOMPLETE_HP_ITERATION_BUDGET')
            self.assertEqual(ledger.logical, 5)
            self.assertTrue(ledger.pending)

    def test_3_original_asan_defect_is_inconclusive_without_refinement(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')
            called = []

            async def forbidden_refine(*_args, **_kwargs):
                called.append(True)
                raise AssertionError('security defect must not become SAFE refinement')

            async def fake_scan(folder, _provider, **_options):
                for role in ('sp_generation', 'function_analysis',
                             'function_analysis', 'assertion_generator'):
                    await provider.generate(SimpleNamespace(role=role))
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 3,
                    'original_hp_limit': 5, 'combined_limit': 8,
                    'hp_calls_before_transfer': 3, 'safe_assumption_count': 1,
                    'assertion_proposal_count': 1, 'checkable_assertion_count': 1,
                    'assertion_generation_status': 'COMPLETED',
                    'effective_sp_limit': 3, 'transferred_hp_calls': 0,
                    'reason': 'HP_ASSERTION_PATH'}))
                triage = folder / 'assertions/a1/executions/e1/triage.json'
                triage.parent.mkdir(parents=True)
                triage.write_text(json.dumps({'classification': 'SECURITY_DEFECT_POSSIBLE',
                                              'security_verdict': 'UNKNOWN'}))
                (folder / 'assertions/results.json').write_text(json.dumps([{
                    'assertion_id': 'a1', 'status': 'VIOLATED',
                    'execution_result': str(triage.parent / 'runtime.json')}]))
                result = await old_runner.scan_mod.refine_overstrong_assertions(
                    folder, function_id='fn', max_llm_calls=2)
                self.assertEqual(result['status'], 'NO_ELIGIBLE_VIOLATION')
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 3, 'effective_sp_llm_call_limit': 3,
                    'combined_llm_call_limit': 8}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(old_runner.scan_mod, 'refine_overstrong_assertions', forbidden_refine):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))
            self.assertFalse(called)
            self.assertEqual(rows[0]['status'], 'INCONCLUSIVE_NO_REFINED_ASSERTION')
            self.assertEqual(ledger.logical, 4)
            self.assertFalse(any(row['reason'] == 'PENDING_ROLE_BUDGET'
                                 for row in ledger.pending))

    def test_4_cleanup_failure_checkpoint_precedes_resource_scan(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            async def fake_scan(*_args, **_kwargs):
                raise RuntimeCleanupError('detached child not reaped', 'partial out',
                                          'partial err')

            def check_resource(folder):
                self.assertEqual(json.loads((folder / 'FUNCTION_CHECKPOINT.json').read_text())
                                 ['status'], 'STOPPED_CLEANUP_INCOMPLETE')
                self.assertTrue((folder / 'runtime/cleanup_incomplete.json').is_file())
                return {'resource_exhaustion_artifact_count': 0}

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan), \
                 patch.object(old_runner, 'summarize_resource_exhaustion', check_resource):
                with self.assertRaises(RuntimeCleanupError):
                    asyncio.run(run_sequence_dev(
                        run, provider, ledger, root, root / 'ledger.json',
                        policy=policy, contract_path=path))
            self.assertTrue((root / 'ledger.json').is_file())

    def test_5_original_runtime_cleanup_error_wins_over_provider_and_summary(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            def failing_end():
                raise RuntimeError('provider close failed')

            async def failing_scan(*_args, **_kwargs):
                raise RuntimeCleanupError('original detached process error',
                                          'original out', 'original err')

            def failing_summary(_run):
                self.assertTrue((run / 'FUNCTION_CHECKPOINT.json').is_file())
                raise RuntimeError('resource summary failed')

            with patch.object(provider, 'end_function', failing_end), \
                 patch.object(old_runner.scan_mod, 'scan_selected', failing_scan), \
                 patch.object(old_runner, 'summarize_resource_exhaustion', failing_summary):
                with self.assertRaisesRegex(RuntimeCleanupError,
                                            'original detached process error'):
                    asyncio.run(run_sequence_dev(
                        run, provider, ledger, root, root / 'ledger.json',
                        policy=policy, contract_path=path))
            self.assertTrue((run / 'FUNCTION_CHECKPOINT.json').is_file())
            self.assertTrue((run / 'runtime/cleanup_incomplete.json').is_file())
            self.assertTrue((root / 'ledger.json').is_file())

    def test_6_tampered_turn_budget_and_checkpoint_are_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            (run / 'sp').mkdir(parents=True)
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            ledger.select('fn')
            ledger.bind_run('fn', run)
            (run / 'sp/turn_budget.json').write_text(json.dumps({
                'function_id': 'fn', 'original_sp_limit': 3,
                'original_hp_limit': 4, 'combined_limit': 8,
                'hp_calls_before_transfer': 0, 'checkable_assertion_count': 1,
                'effective_sp_limit': 3, 'transferred_hp_calls': 0}))
            with self.assertRaisesRegex(ValueError, 'turn-budget'):
                ledger.begin_turn('fn', 'function_analysis', 'a' * 64)
            self.assertEqual(ledger.logical, 0)
            (run / 'sp/turn_budget.json').unlink()
            checkpoint = root / 'ledger.json'
            ledger.checkpoint(checkpoint)
            restored = DevHPLedger.restore_for_contract(checkpoint, digest)
            self.assertEqual(restored.logical, 0)
            saved = json.loads(checkpoint.read_text())
            saved['policy']['assertion_generator_max'] = 99
            checkpoint.write_text(json.dumps(saved))
            with self.assertRaisesRegex(ValueError, 'policy is not pinned'):
                DevHPLedger.restore_for_contract(checkpoint, digest)

    def test_7_no_safe_is_inconclusive_even_if_scan_completed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            async def fake_scan(folder, _provider, **_options):
                await provider.generate(SimpleNamespace(role='sp_generation'))
                await provider.generate(SimpleNamespace(role='function_analysis'))
                (folder / 'sp').mkdir()
                (folder / 'sp/turn_budget.json').write_text(json.dumps({
                    'function_id': 'fn', 'original_sp_limit': 3,
                    'original_hp_limit': 5, 'combined_limit': 8,
                    'hp_calls_before_transfer': 1, 'safe_assumption_count': 0,
                    'assertion_proposal_count': 0, 'checkable_assertion_count': 0,
                    'assertion_generation_status': 'NO_SAFE',
                    'effective_sp_limit': 7, 'transferred_hp_calls': 4,
                    'reason': 'HP_NO_ASSERTION_UNUSED_CALLS'}))
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 1,
                    'hp_llm_calls': 1, 'effective_sp_llm_call_limit': 7,
                    'combined_llm_call_limit': 8,
                    'assertion_execution': {'status': 'NOT_SCHEDULED_NO_SAFE_ASSUMPTION'}}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))
            self.assertEqual(rows[0]['status'], 'INCONCLUSIVE_NO_REFINED_ASSERTION')
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))

    def test_8_provider_begin_failure_keeps_selection_checkpoint(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')
            with patch.object(provider, 'begin_function',
                              side_effect=RuntimeError('provider begin failed')):
                with self.assertRaisesRegex(RuntimeError, 'provider begin failed'):
                    asyncio.run(run_sequence_dev(
                        run, provider, ledger, root, root / 'ledger.json',
                        policy=policy, contract_path=path))
            self.assertTrue((root / 'ledger.json').is_file())
            self.assertEqual(json.loads((run / 'FUNCTION_CHECKPOINT.json').read_text())
                             ['status'], 'STOPPED_FAIL_CLOSED')

    def test_9_hp_error_cannot_be_overwritten_by_refinement_history(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            async def fake_scan(folder, _provider, **_options):
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 3,
                    'combined_llm_call_limit': 8, 'hp_error': 'stream disconnected',
                    'assertion_execution': {'status': 'INCOMPLETE_HP_ERROR'}}))
                (folder / 'assertions').mkdir()
                (folder / 'assertions/refinement_history.json').write_text(json.dumps({
                    'refinements': [{'status': 'REFINED_AND_TESTED'}]}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))
            self.assertEqual(rows[0]['status'], 'INCOMPLETE_HP_ERROR')

    def test_10_hp_error_without_history_remains_incomplete(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            async def fake_scan(folder, _provider, **_options):
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 3,
                    'combined_llm_call_limit': 8, 'hp_error': 'stream disconnected',
                    'assertion_execution': {'status': 'PENDING'}}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))
            self.assertEqual(rows[0]['status'], 'INCOMPLETE_HP_ERROR')

    def test_11_pretransport_hp_error_precedes_turn_count_discrepancy(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({
                'function_id': 'fn', 'function_name': 'fn'}))
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            provider = AccountedProvider(ledger, root / 'ledger.json')

            async def fake_scan(folder, _provider, **_options):
                # The product counted a logical HP request that failed before
                # the evaluator observed a physical App Server start.
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 1, 'effective_sp_llm_call_limit': 3,
                    'combined_llm_call_limit': 8,
                    'hp_error': {'stage': 'FUNCTION_ANALYSIS',
                                 'type': 'AppServerError'},
                    'assertion_execution': {'status': 'INCOMPLETE_HP_ERROR'}}))

            with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                rows = asyncio.run(run_sequence_dev(
                    run, provider, ledger, root, root / 'ledger.json',
                    policy=policy, contract_path=path))
            self.assertEqual(rows[0]['status'], 'INCOMPLETE_HP_ERROR')
            self.assertEqual(json.loads(
                (run / 'FUNCTION_CHECKPOINT.json').read_text())['status'],
                'INCOMPLETE_HP_ERROR')
            discrepancy = json.loads((run / 'runtime' /
                                      'hp_accounting_discrepancy.json').read_text())
            self.assertEqual(discrepancy['error_type'], 'ValueError')
            self.assertEqual(discrepancy['hp_error_present'], True)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_12_hp_error_does_not_excuse_other_accounting_changes(self):
        valid_error = {'stage': 'FUNCTION_ANALYSIS', 'type': 'AppServerError'}
        cases = ((0, 2, 'fn', valid_error), (1, 0, 'fn', valid_error),
                 (0, 1, 'other', valid_error), (0, 1.0, 'fn', valid_error),
                 (False, 1, 'fn', valid_error), (0, True, 'fn', valid_error),
                 (0, 1, 'fn', {}),
                 (0, 1, 'fn', {'stage': 'FUNCTION_ANALYSIS', 'type': ''}),
                 (0, 1, 'fn', {'stage': 'UNKNOWN', 'type': 'AppServerError'}))
        for product_sp, product_hp, selected, hp_error in cases:
            with self.subTest(sp=product_sp, hp=product_hp,
                              selected=selected, hp_error=hp_error), \
                    TemporaryDirectory() as temp:
                root = Path(temp)
                path, digest = contract(root)
                policy, _ = load_dev_contract(path, digest)
                run = root / 'run'
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': 'fn', 'function_name': 'fn'}))
                ledger = DevHPLedger(started_at=time.time(),
                                     policy=asdict(policy), contract_sha256=digest)
                provider = AccountedProvider(ledger, root / 'ledger.json')

                async def fake_scan(folder, _provider, **_options):
                    (folder / 'scan.json').write_text(json.dumps({
                        'selected_function_id': selected,
                        'sp_llm_calls': product_sp,
                        'hp_llm_calls': product_hp,
                        'effective_sp_llm_call_limit': 3,
                        'combined_llm_call_limit': 8,
                        'hp_error': hp_error}))

                with patch.object(old_runner.scan_mod, 'scan_selected', fake_scan):
                    with self.assertRaisesRegex(ValueError,
                                                'turn accounting differ'):
                        asyncio.run(run_sequence_dev(
                            run, provider, ledger, root, root / 'ledger.json',
                            policy=policy, contract_path=path))
                self.assertFalse((run / 'runtime' /
                                  'hp_accounting_discrepancy.json').exists())
                self.assertEqual(json.loads(
                    (run / 'FUNCTION_CHECKPOINT.json').read_text())['status'],
                    'STOPPED_FAIL_CLOSED')

    def test_13_hp_error_cannot_hide_transfer_or_exhausted_role(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path, digest = contract(root)
            policy, _ = load_dev_contract(path, digest)
            run = root / 'run'
            run.mkdir()
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=digest)
            ledger.select('fn')
            ledger.bind_run('fn', run)
            error = {'stage': 'FUNCTION_ANALYSIS', 'type': 'AppServerError'}
            scan = {'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 1,
                    'effective_sp_llm_call_limit': policy.sp_per_function,
                    'combined_llm_call_limit': policy.combined_per_function,
                    'hp_error': error}
            (run / 'sp').mkdir()
            (run / 'sp' / 'turn_budget.json').write_text(json.dumps({
                'function_id': 'fn',
                'original_sp_limit': policy.sp_per_function,
                'original_hp_limit': policy.hp_per_function,
                'combined_limit': policy.combined_per_function,
                'hp_calls_before_transfer': 0,
                'transferred_hp_calls': 1,
                'effective_sp_limit': policy.sp_per_function + 1,
                'checkable_assertion_count': 0,
                'reason': 'HP_NO_ASSERTION_UNUSED_CALLS'}))
            scan['effective_sp_llm_call_limit'] = policy.sp_per_function + 1
            with self.assertRaisesRegex(ValueError, 'turn accounting differ'):
                ledger.validate_scan('fn', scan)
            (run / 'sp' / 'turn_budget.json').unlink()

            ledger.counts['fn']['function_analysis'] = policy.function_analysis_max
            scan['hp_llm_calls'] = policy.function_analysis_max + 1
            scan['effective_sp_llm_call_limit'] = policy.sp_per_function
            with self.assertRaisesRegex(ValueError, 'turn accounting differ'):
                ledger.validate_scan('fn', scan)

            ledger.counts['fn'].clear()
            scan['hp_llm_calls'] = 1
            scan['effective_sp_llm_call_limit'] = float(policy.sp_per_function)
            with self.assertRaisesRegex(ValueError, 'turn accounting differ'):
                ledger.validate_scan('fn', scan)
            scan['effective_sp_llm_call_limit'] = policy.sp_per_function
            scan['combined_llm_call_limit'] = float(policy.combined_per_function)
            with self.assertRaisesRegex(ValueError, 'turn accounting differ'):
                ledger.validate_scan('fn', scan)
            scan['combined_llm_call_limit'] = policy.combined_per_function
            ledger.started_at = time.time() - policy.wall_seconds - 1
            with self.assertRaisesRegex(ValueError, 'turn accounting differ'):
                ledger.validate_scan('fn', scan)


if __name__ == '__main__':
    unittest.main()
