"""Scripted official V2 candidate handoff; no provider, target, or Fuzzer."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import blind2_runner_draft as official_runner
import blind3_md4c_full_candidate_provider_free_dev as full_driver
from blind3_md4c_live_direction_sp_hp_dev import _read
from blind3_md4c_full_candidate_provider_free_dev import (
    FixedCandidateScriptedAppServer, execute_provider_free_full_candidate)
from dev_global_request_ledger import (
    DevelopmentBudget, DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE)
from dev_global_appserver_product_flow import DevelopmentBudgetStop
from test_blind3_md4c_live_direction_sp_hp_dev import (
    ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, CONTRACT, scripted_direction)
from vulnerabilityanalysis.llm import AppServerError


ROLE_MODELS = {role: {'model': 'test-model', 'reasoning': 'high'}
               for role in ('direction_generator', 'sp_generation',
                            'function_analysis', 'assertion_generator',
                            'sp_verifier', 'poc_generator')}


class FullCandidateProviderFreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qualification = official_runner.require_official_qualification(
            json.loads(CONTRACT.read_text(encoding='utf-8')))

    def make(self, root: Path, credits: int, *, tool_event=False,
             timeout_role=None, initial_starts_required=2,
             fault_mode=None):
        root.mkdir()
        budget = DevelopmentBudget(
            physical_max=credits, logical_max=credits, retries_max=0,
            wall_seconds=180,
            initial_starts_required=initial_starts_required,
            profile=GLOBAL_ONLY_DEV_PROFILE)
        ledger = DevelopmentRequestLedger.create(budget,
                                                 root / 'GLOBAL_LEDGER.json')
        fault_mode = (fault_mode or
                      ('tool_event_at_verifier' if tool_event else
                       'timeout_at_verifier' if timeout_role == 'sp_verifier'
                       else 'none'))
        backend = FixedCandidateScriptedAppServer(
            ledger, root, scripted_direction(), ROLE_MODELS,
            fault_mode=fault_mode)
        return ledger, backend

    def invoke(self, root, ledger, backend):
        return asyncio.run(execute_provider_free_full_candidate(
            output=root / 'flow', artifact=ARTIFACT,
            target_repository=TARGET, oss_fuzz_checkout=OSS_FUZZ,
            upstream_checkout=UPSTREAM, qualification=self.qualification,
            backend=backend, ledger=ledger, role_models=ROLE_MODELS,
            scope_id='md4c-official-v2-full-candidate-dev'))

    def test_sp_verifier_pov_and_hp_assertion_share_global_ledger(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            result = self.invoke(root, ledger, backend)
            self.assertEqual(result['status'], 'PENDING_UNVERIFIED_DEV')
            self.assertEqual(result['roles'], [
                'direction_generator', 'sp_generation', 'function_analysis',
                'assertion_generator', 'sp_verifier', 'poc_generator'])
            self.assertEqual(backend.wire_starts, list(range(1, 7)))
            self.assertEqual((ledger.logical, ledger.physical), (6, 6))
            self.assertEqual(result['sp_verified'], 1)
            self.assertEqual(result['pov_model_calls'], 1)
            self.assertEqual(result['assertion_model_calls'], 1)
            self.assertEqual(result['runtime_status'], 'NOT_EXECUTED_DEV')
            self.assertEqual(result['vulnerability_verdict'], 'NOT_EVALUATED')
            scan = _read(Path(result['phase1_run']) / 'scan.json')
            self.assertEqual(scan['poc_count'], 1)
            self.assertEqual(scan['global_logical_used'], 6)

    def test_exhausted_budget_keeps_verified_candidate_pending_pov(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 5)
            result = self.invoke(root, ledger, backend)
            self.assertEqual(result['roles'][-1], 'sp_verifier')
            self.assertEqual(result['pov_model_calls'], 0)
            self.assertGreaterEqual(result['sp_pending'], 1)
            self.assertEqual(result['physical'], 5)

    def test_caller_pinned_one_start_after_direction_keeps_sp_pending(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 2, initial_starts_required=1)
            result = self.invoke(root, ledger, backend)
            self.assertEqual(result['roles'], [
                'direction_generator', 'sp_generation'])
            self.assertEqual(result['budget_initial_starts_required'], 1)
            self.assertEqual(result['sp_verified'], 0)
            self.assertGreaterEqual(result['sp_pending'], 1)
            self.assertEqual((result['logical'], result['physical']), (2, 2))

    def test_tool_event_in_scripted_verifier_cannot_write_success_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6, tool_event=True)
            with self.assertRaisesRegex(ValueError, 'tool or server request'):
                self.invoke(root, ledger, backend)
            self.assertFalse((root / 'flow/DEV_FULL_CANDIDATE_RESULT.json').exists())
            self.assertEqual(_read(root / 'flow/DEV_FULL_CANDIDATE_STOP.json')
                             ['status'], 'INCOMPLETE')

    def test_timeout_leaves_incomplete_record_and_no_success_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6, timeout_role='sp_verifier')
            with self.assertRaisesRegex(AppServerError, 'wall deadline'):
                self.invoke(root, ledger, backend)
            self.assertFalse((root / 'flow/DEV_FULL_CANDIDATE_RESULT.json').exists())
            stop = _read(root / 'flow/DEV_FULL_CANDIDATE_STOP.json')
            self.assertEqual(stop['status'], 'INCOMPLETE_TIMEOUT')
            self.assertEqual(stop['error_type'], 'AppServerError')
            self.assertEqual(stop['cause_type'], 'TimeoutError')

    def test_live_backend_rejected_before_direction_send(self):
        self.assertNotIn('provider', inspect.signature(
            execute_provider_free_full_candidate).parameters)
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, _ = self.make(root, 6)
            class LiveTransportOverride(FixedCandidateScriptedAppServer):
                async def _transport_request(self, method, params):
                    raise AssertionError('live transport must never be called')
            backend = LiveTransportOverride(
                ledger, root, scripted_direction(), ROLE_MODELS)
            with self.assertRaisesRegex(ValueError, 'provider-free'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_instance_transport_override_rejected_before_direction_send(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            async def live_transport(_method, _params):
                raise AssertionError('live transport must never be called')
            backend._transport_request = live_transport
            with self.assertRaisesRegex(ValueError, 'provider-free'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_instance_generate_override_rejected_before_direction_send(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            async def unguarded_generate(_request):
                raise AssertionError('unguarded generate must never be called')
            backend.generate = unguarded_generate
            with self.assertRaisesRegex(ValueError, 'provider-free'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_instance_collect_override_rejected_before_direction_send(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            async def live_collect(_thread, _turn):
                raise AssertionError('unguarded collect must never be called')
            backend._collect = live_collect
            with self.assertRaisesRegex(ValueError, 'provider-free'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_later_role_route_mismatch_rejected_before_direction_send(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            backend.role_models['sp_verifier'] = {
                'model': 'different-scripted-model', 'reasoning': 'high'}
            with self.assertRaisesRegex(ValueError, 'provider-free'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (0, 0))

    def test_route_mutation_after_last_pov_has_stop_not_success(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6,
                fault_mode='mutate_route_after_pov')
            with self.assertRaisesRegex(ValueError, 'routes changed'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (6, 6))
            self.assertFalse((root / 'flow/DEV_FULL_CANDIDATE_RESULT.json').exists())
            self.assertEqual(_read(root / 'flow/DEV_FULL_CANDIDATE_STOP.json')
                             ['status'], 'INCOMPLETE')

    def test_second_official_pin_failure_after_direction_has_stop_receipt(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            original = full_driver._official_preflight
            calls = 0
            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise ValueError('synthetic second pin failure')
                return original(*args, **kwargs)
            with patch.object(full_driver, '_official_preflight', fail_second):
                with self.assertRaisesRegex(ValueError, 'second pin failure'):
                    self.invoke(root, ledger, backend)
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))
            self.assertFalse((root / 'flow/DEV_FULL_CANDIDATE_RESULT.json').exists())
            stop = _read(root / 'flow/DEV_FULL_CANDIDATE_STOP.json')
            self.assertEqual(stop['status'], 'INCOMPLETE')
            self.assertEqual(stop['error_type'], 'ValueError')
            self.assertIsNotNone(stop['ledger_checkpoint_sha256'])

    def test_one_credit_after_direction_has_no_opportunity_receipt(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 1, initial_starts_required=1)
            result = self.invoke(root, ledger, backend)
            self.assertEqual(result['status'], 'NO_OPPORTUNITY_BUDGET')
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))
            self.assertEqual(result, _read(root / 'flow/DEV_FULL_CANDIDATE_RESULT.json'))
            self.assertEqual(len(result['direction_plan_sha256']), 64)
            self.assertEqual(len(result['phase1_sha256']), 64)
            self.assertEqual(len(result['ledger_checkpoint_sha256']), 64)
            self.assertFalse((root / 'flow/DEV_FULL_CANDIDATE_STOP.json').exists())

    def test_budget_stop_followed_by_failed_postcheck_is_incomplete(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 6)
            async def synthetic_budget_stop(*_args, **_kwargs):
                raise DevelopmentBudgetStop('synthetic budget stop')
            with (patch.object(full_driver, 'scan_selected', synthetic_budget_stop),
                  patch.object(full_driver, '_postcheck',
                               side_effect=ValueError('synthetic pin changed'))):
                with self.assertRaisesRegex(ValueError, 'pin changed'):
                    self.invoke(root, ledger, backend)
            stop = _read(root / 'flow/DEV_FULL_CANDIDATE_STOP.json')
            self.assertEqual(stop['status'], 'INCOMPLETE')
            self.assertEqual(stop['error_type'], 'ValueError')
            self.assertFalse((root / 'flow/DEV_FULL_CANDIDATE_RESULT.json').exists())
