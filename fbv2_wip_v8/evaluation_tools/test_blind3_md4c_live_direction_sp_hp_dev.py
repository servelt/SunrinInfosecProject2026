"""Provider-free official V2 Direction -> Phase 1 -> SP/HP development checks.

The scripted App Server never connects to a provider. No target or Fuzzer runs.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREP = HERE.parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(HERE), str(PREP / 'review_tools'), str(PRODUCT / 'src')]

import blind3_md4c_live_direction_sp_hp_dev as flow  # noqa: E402
import blind2_runner_draft as official_runner  # noqa: E402
from dev_global_appserver_product_flow import (  # noqa: E402
    ROLE_MODELS, ScriptedAppServer)
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE)
from development_direction_study import build_context_from_artifact  # noqa: E402
from vulnerabilityanalysis.direction_plan import DEV_FIRST_PASS_POLICY  # noqa: E402
from vulnerabilityanalysis.llm import LLMRequest  # noqa: E402


ARTIFACT = PREP / 'v2_artifact_stage/attempt'
TARGET = PREP / 'model_target'
OSS_FUZZ = PREP / 'oss_fuzz_checkout'
UPSTREAM = PREP / 'upstream_asan_final'
CONTRACT = PREP / 'tools/FROZEN_CONTRACT_ATTEMPT3.json'


def budget(physical: int) -> DevelopmentBudget:
    return DevelopmentBudget(
        physical_max=physical, logical_max=physical, retries_max=0,
        wall_seconds=180, initial_starts_required=2,
        sp_per_function=1, hp_per_function=1, combined_per_function=2,
        hp_analysis_per_function=1, hp_assertion_per_function=1)


def scripted_direction() -> dict:
    context, _ = build_context_from_artifact(
        ARTIFACT, TARGET, oss_fuzz_checkout=OSS_FUZZ,
        upstream_checkout=UPSTREAM, source_mode='all_catalog_prefix')
    anchors = context['harness_anchor_ids']
    return {'directions': [{
        'name': 'Parsing feature', 'risk_level': 'NORMAL',
        'entry_function_ids': anchors, 'core_function_ids': anchors[:1],
        'rationale': 'Provider-free feature grouping for ledger integration.',
    }], 'unknowns': []}


class BadRawBackend(ScriptedAppServer):
    async def generate(self, request):
        response = await super().generate(request)
        request.raw_response_path.unlink()
        return response


class NoPhysicalBackend(ScriptedAppServer):
    async def generate(self, request):
        return self.direction_answer


class OfficialV2LiveDevelopmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
        cls.qualification = official_runner.require_official_qualification(contract)
        cls.answer = scripted_direction()

    def make(self, root: Path, physical: int, *, backend_type=ScriptedAppServer,
             global_only: bool = False):
        root.mkdir()
        configured_budget = budget(physical)
        if global_only:
            configured_budget = replace(configured_budget,
                                        profile=GLOBAL_ONLY_DEV_PROFILE)
        ledger = DevelopmentRequestLedger.create(
            configured_budget, root / 'GLOBAL_LEDGER.json')
        backend = backend_type(ledger, root, self.answer)
        return ledger, backend

    def invoke(self, root: Path, ledger, backend, qualification=None,
               *, global_only: bool = False):
        return asyncio.run(flow.execute_official_v2_direction_sp_hp(
            output=root / 'flow', artifact=ARTIFACT,
            target_repository=TARGET, oss_fuzz_checkout=OSS_FUZZ,
            upstream_checkout=UPSTREAM,
            qualification=qualification or self.qualification,
            backend=backend, ledger=ledger, role_models=ROLE_MODELS,
            scope_id='md4c-official-v2-dev',
            external_global_dev=global_only))

    def test_global_only_profile_reaches_real_product_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            # Direction and SP spend two credits. Product reserves two more
            # before HP analysis so a resulting SAFE can reach Assertion.
            ledger, backend = self.make(root, 4, global_only=True)
            with patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                       side_effect=AssertionError('target was run')), \
                 patch('vulnerabilityanalysis.scan.fuzz_locally',
                       side_effect=AssertionError('fuzzer was run')), \
                 patch('vulnerabilityanalysis.scan.execute_poc',
                       side_effect=AssertionError('PoV was run')), \
                 patch('vulnerabilityanalysis.scan.execute_assertion',
                       side_effect=AssertionError('Assertion was run')):
                result = self.invoke(root, ledger, backend, global_only=True)
            scan = json.loads((Path(result['phase1_run']) / 'scan.json').read_text())
            self.assertEqual(result['status'], 'PENDING_UNVERIFIED_DEV')
            self.assertEqual(result['budget_profile'], GLOBAL_ONLY_DEV_PROFILE)
            self.assertEqual(scan['budget_authority'], 'EXTERNAL_GLOBAL_DEV')
            self.assertEqual(scan['candidate_budget_policy'], 'DRAIN_RANKED_DEV')
            self.assertIsNone(scan['sp_llm_call_limit'])
            self.assertIsNone(scan['hp_llm_call_limit'])
            self.assertEqual([row['role'] for row in ledger.turns], [
                'direction_generator', 'sp_generation', 'function_analysis'])
            self.assertEqual(backend.wire_starts, [1, 2, 3])

    def test_global_profile_and_adapter_optin_must_agree_before_direction(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3, global_only=True)
            with patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'profile or adapter'):
                    self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertEqual((ledger.physical, ledger.logical), (0, 0))

    def test_smoke_adapter_blocks_verifier_before_any_wire_send(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 5, global_only=True)
            backend.bind_scope('unselected-test-function')
            adapter = flow._SmokeProductBudgetAdapter(
                backend, ledger, 'unselected-test-function', root / 'unused_pin.json')
            request = LLMRequest(
                role='sp_verifier', instructions='never send', payload={},
                output_schema={'type': 'object'}, model='test-model',
                effort='high')
            with self.assertRaises(flow.SmokeBoundaryStop):
                asyncio.run(adapter.generate(request))
            self.assertEqual((ledger.physical, ledger.logical), (0, 0))
            self.assertEqual(backend.wire_starts, [])

    def test_full_live_chain_uses_one_physical_ledger_and_pinned_phase1(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            with patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                       side_effect=AssertionError('target was run')), \
                 patch('vulnerabilityanalysis.scan.fuzz_locally',
                       side_effect=AssertionError('fuzzer was run')), \
                 patch('vulnerabilityanalysis.scan.execute_poc',
                       side_effect=AssertionError('PoV was run')), \
                 patch('vulnerabilityanalysis.scan.execute_assertion',
                       side_effect=AssertionError('Assertion was run')):
                result = self.invoke(root, ledger, backend)
            self.assertEqual(result['status'], 'PENDING_UNVERIFIED_DEV')
            self.assertEqual((ledger.physical, ledger.logical, ledger.retries),
                             (3, 3, 0))
            self.assertEqual([row['role'] for row in ledger.turns], [
                'direction_generator', 'sp_generation', 'function_analysis'])
            self.assertEqual(backend.wire_starts, [1, 2, 3])
            run = Path(result['phase1_run'])
            phase1 = json.loads((run / 'run.json').read_text())
            scan = json.loads((run / 'scan.json').read_text())
            self.assertEqual(phase1['selection_policy'], DEV_FIRST_PASS_POLICY)
            self.assertEqual(phase1['direction_plan_sha256'],
                             result['direction_plan_sha256'])
            self.assertEqual(scan['poc_count'], 0)
            self.assertEqual(scan['assertion_count'], 0)
            self.assertEqual(scan['fuzz_seconds_allocated'], 0)
            self.assertEqual(result['pool_count'], 166)
            self.assertEqual(result['target_runs'], 0)
            self.assertEqual(result['fuzz_seconds'], 0)
            pin_path = flow._phase1_pin_path(root / 'flow')
            self.assertEqual(result['phase1_pin_sha256'], flow.sha(pin_path))
            self.assertEqual(pin_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(pin_path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(flow.verify_pin_after_model(pin_path)['run_dir'],
                             str(run))
            restored = DevelopmentRequestLedger.restore(
                ledger.checkpoint_path, ledger.budget)
            self.assertEqual(restored.summary([
                row['function_id'] for row in json.loads(
                    (run / 'function_pool.json').read_text())]),
                ledger.summary([row['function_id'] for row in json.loads(
                    (run / 'function_pool.json').read_text())]))
            self.assertEqual(list(restored.function_states.values()),
                             ['SCAN_RECORDED'])

    def test_phase1_pool_changed_after_pin_blocks_sp_hp_request(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            real_issue = flow.issue_pin

            def issue_then_change_pool(run, pin_path):
                record = real_issue(run, pin_path)
                path = Path(run) / 'function_pool.json'
                pool = json.loads(path.read_text())
                pool[0]['pin_test_marker'] = 'changed after evaluator pin'
                path.write_text(json.dumps(pool) + '\n')
                return record

            with patch.object(flow, 'issue_pin', side_effect=issue_then_change_pool), \
                 patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'pin values'):
                    self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertEqual((ledger.physical, ledger.logical), (1, 1))
            self.assertFalse(ledger.selected_functions)

    def test_phase1_selection_changed_after_scan_blocks_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            real_scan = flow.scan_selected

            async def scan_then_change_selection(run, *args, **kwargs):
                result = await real_scan(run, *args, **kwargs)
                path = Path(run) / 'selection.json'
                selection = json.loads(path.read_text())
                selection['pin_test_marker'] = 'changed after Scan'
                path.write_text(json.dumps(selection) + '\n')
                return result

            with patch.object(flow, 'scan_selected',
                              side_effect=scan_then_change_selection):
                with self.assertRaisesRegex(ValueError, 'pin values'):
                    self.invoke(root, ledger, backend)
            self.assertEqual((ledger.physical, ledger.logical), (3, 3))
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())

    def test_phase1_pin_rechecked_at_each_model_request(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            original_bind = backend.bind_scope

            def bind_then_change_selection(fid):
                original_bind(fid)
                if not (root / 'flow/product_runs').is_dir():
                    return
                run_dir = next((root / 'flow/product_runs').iterdir())
                selection_path = run_dir / 'selection.json'
                pool_path = run_dir / 'function_pool.json'
                selection = json.loads(selection_path.read_text())
                pool = json.loads(pool_path.read_text())
                selection['priority_reasons'] = ['forged after evaluator pin']
                for row in pool:
                    if row['function_id'] == fid:
                        row['priority_reasons'] = selection['priority_reasons']
                selection_path.write_text(json.dumps(selection) + '\n')
                pool_path.write_text(json.dumps(pool) + '\n')

            backend.bind_scope = bind_then_change_selection
            with self.assertRaisesRegex(flow.SmokeBoundaryStop,
                                        'before model request'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.physical, ledger.logical), (1, 1))
            self.assertEqual(backend.wire_starts, [1])
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())

    def test_phase1_pin_rechecked_before_second_function_request(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            original_generate = backend.generate

            async def generate_then_change_pool(request):
                response = await original_generate(request)
                if request.role == 'sp_generation':
                    run_dir = next((root / 'flow/product_runs').iterdir())
                    pool_path = run_dir / 'function_pool.json'
                    pool = json.loads(pool_path.read_text())
                    pool[0]['pin_test_marker'] = 'changed after first SP request'
                    pool_path.write_text(json.dumps(pool) + '\n')
                return response

            backend.generate = generate_then_change_pool
            with self.assertRaisesRegex(flow.SmokeBoundaryStop,
                                        'before model request'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.physical, ledger.logical), (2, 2))
            self.assertEqual(backend.wire_starts, [1, 2])
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())

    def test_missing_raw_direction_response_never_starts_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3, backend_type=BadRawBackend)
            with patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'raw response missing'):
                    self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertEqual(ledger.physical, 1)

    def test_unaccounted_direction_response_never_starts_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3, backend_type=NoPhysicalBackend)
            with patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'physical ledger record'):
                    self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertEqual((ledger.physical, ledger.logical), (0, 0))

    def test_wrong_official_source_pin_rejected_before_direction_and_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            forged = replace(self.qualification, source_tree_sha256='0' * 64)
            with patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'official V2 qualification'):
                    self.invoke(root, ledger, backend, forged)
                scan.assert_not_called()
            self.assertEqual((ledger.physical, ledger.logical), (0, 0))

    def test_pin_check_failing_after_direction_never_starts_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            # Simulate a checkout or binary change without touching pinned bytes.
            with patch.object(flow, '_qualification_pins_ok',
                              side_effect=[True, False]), \
                 patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'official V2 qualification'):
                    self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertEqual((ledger.physical, ledger.logical), (1, 1))

    def test_insufficient_post_direction_credit_is_no_opportunity(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 2)
            with patch.object(flow, 'scan_selected') as scan:
                result = self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertEqual(result['status'], 'NO_OPPORTUNITY_BUDGET')
            self.assertEqual((ledger.physical, ledger.logical), (1, 1))
            self.assertFalse(ledger.selected_functions)
            self.assertNotIn('SAFE', json.dumps(result))

    def test_budget_no_opportunity_rechecks_pins_before_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 2)
            with patch.object(flow, '_direction_pins_unchanged',
                              return_value=False), \
                 patch.object(flow, 'scan_selected') as scan:
                with self.assertRaisesRegex(ValueError, 'input pins changed'):
                    self.invoke(root, ledger, backend)
                scan.assert_not_called()
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())
            self.assertEqual((ledger.physical, ledger.logical), (1, 1))

    def test_pending_budget_rechecks_pins_before_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            real_begin = ledger.begin_turn

            def expire_before_hp(scope_id, role, request_digest):
                if role == 'function_analysis':
                    ledger.started_at = time.time() - ledger.budget.wall_seconds - 1
                    ledger.checkpoint()
                return real_begin(scope_id, role, request_digest)

            ledger.begin_turn = expire_before_hp
            with patch.object(flow, '_direction_pins_unchanged',
                              return_value=False):
                with self.assertRaisesRegex(ValueError, 'input pins changed'):
                    self.invoke(root, ledger, backend)
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())
            self.assertEqual((ledger.physical, ledger.logical), (2, 2))
            self.assertIn('INCOMPLETE_BUDGET', ledger.function_states.values())

    def test_pending_budget_without_pin_change_is_not_a_negative_finding(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            real_begin = ledger.begin_turn

            def expire_before_hp(scope_id, role, request_digest):
                if role == 'function_analysis':
                    ledger.started_at = time.time() - ledger.budget.wall_seconds - 1
                    ledger.checkpoint()
                return real_begin(scope_id, role, request_digest)

            ledger.begin_turn = expire_before_hp
            result = self.invoke(root, ledger, backend)
            self.assertEqual(result['status'], 'PENDING_BUDGET')
            self.assertEqual(result['vulnerability_verdict'], 'NOT_EVALUATED')
            self.assertEqual((ledger.physical, ledger.logical), (2, 2))
            restored = DevelopmentRequestLedger.restore(
                ledger.checkpoint_path, ledger.budget)
            self.assertEqual(restored.pending_work, ledger.pending_work)

    def test_scan_mutating_direction_raw_blocks_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            real_scan = flow.scan_selected

            async def mutate_after_scan(*args, **kwargs):
                result = await real_scan(*args, **kwargs)
                (root / 'flow/DIRECTION_RAW.txt').write_text('{}\n')
                return result

            with patch.object(flow, 'scan_selected',
                              side_effect=mutate_after_scan):
                with self.assertRaisesRegex(ValueError, 'stored request, raw or plan'):
                    self.invoke(root, ledger, backend)
            self.assertEqual((ledger.physical, ledger.logical), (3, 3))
            self.assertEqual(list(ledger.function_states.values()),
                             ['SELECTED_NOT_STARTED'])
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())

    def test_consistent_checkpoint_hash_tamper_after_scan_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / 'case'
            ledger, backend = self.make(root, 3)
            real_mark = ledger.mark_scan_recorded

            def mark_then_tamper(fid):
                real_mark(fid)
                path = ledger.checkpoint_path
                saved = json.loads(path.read_text())
                saved['turns'][1]['hash'] = 'f' * 64
                saved['attempts'][1]['request_hash'] = 'f' * 64
                path.write_text(json.dumps(saved, sort_keys=True) + '\n')
                path.chmod(0o600)

            ledger.mark_scan_recorded = mark_then_tamper
            with self.assertRaisesRegex(ValueError, 'restored development opportunity'):
                self.invoke(root, ledger, backend)
            self.assertEqual((ledger.physical, ledger.logical), (3, 3))
            self.assertFalse((root / 'flow/DEV_DIRECTION_SP_HP_RESULT.json').exists())


if __name__ == '__main__':
    unittest.main()
