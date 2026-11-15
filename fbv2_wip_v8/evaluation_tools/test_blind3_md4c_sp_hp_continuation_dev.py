"""Provider-free checks for the separate official V2 SP/HP continuation."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'review_tools'),
                '/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src']
import blind3_md4c_sp_hp_continuation_dev as boundary  # noqa: E402
from dev_budgeted_product_flow import create_public_fixture  # noqa: E402
from dev_global_appserver_product_flow import (  # noqa: E402
    ProductBudgetAdapter, ScriptedAppServer, ROLE_MODELS)
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger)
from vulnerabilityanalysis.scan import scan_selected  # noqa: E402
from vulnerabilityanalysis.workflow import run_phase1  # noqa: E402
import blind2_runner_draft as official_runner  # noqa: E402


class ContinuationBoundaryTests(unittest.TestCase):
    def test_historical_replay_is_not_a_successful_live_ledger(self):
        receipt, run, context = boundary._historical()
        self.assertEqual(receipt['historical_live_status'], 'CHILD_ERROR')
        self.assertEqual(receipt['historical_model_physical'], 1)
        self.assertEqual(receipt['replay_model_calls'], 0)
        self.assertEqual(len(context['pool_ids']), 166)
        self.assertEqual(run, Path(receipt['phase1_run']))

    def test_direct_live_api_is_rejected_before_spec(self):
        with patch.object(boundary, 'load_spec',
                          side_effect=AssertionError('spec reached')):
            with self.assertRaisesRegex(ValueError, 'external source pin'):
                boundary.run_supervised(Path('/missing'), '0' * 64)
            with self.assertRaisesRegex(ValueError, 'external source pin'):
                asyncio.run(boundary._run_child({}, '0' * 64))

    def test_two_scripted_product_turns_leave_downstream_unexecuted(self):
        async def case(root: Path) -> None:
            artifact, repo, plan = create_public_fixture(root)
            run = run_phase1(artifact, root / 'runs',
                             target_repository=repo, direction_plan=plan)
            selection = json.loads((run / 'selection.json').read_text())
            scope = selection['function_id']
            ledger = DevelopmentRequestLedger.create(DevelopmentBudget(
                physical_max=2, logical_max=2, retries_max=0,
                wall_seconds=60, initial_starts_required=2,
                sp_per_function=1, hp_per_function=1,
                combined_per_function=2, hp_analysis_per_function=1,
                hp_assertion_per_function=1), root / 'GLOBAL_LEDGER.json')
            self.assertTrue(ledger.select_function(scope))
            backend = ScriptedAppServer(ledger, root, {})
            backend.bind_scope(scope)
            provider = ProductBudgetAdapter(backend, ledger, scope)
            await scan_selected(run, provider, target_repository=repo,
                role_models=ROLE_MODELS, hallucination_prevent='on',
                sp_llm_call_limit=1, hp_llm_call_limit=1,
                max_candidates=2, targeted_fuzz_seconds=0,
                assertion_fuzz_seconds=0, global_fuzz_enabled=False,
                run_command=None, initial_inputs=None)
            backend.unbind_scope()
            scan = json.loads((run / 'scan.json').read_text())
            self.assertEqual([turn['role'] for turn in ledger.turns],
                             ['sp_generation', 'function_analysis'])
            self.assertEqual((ledger.physical, ledger.logical, ledger.retries),
                             (2, 2, 0))
            self.assertEqual(scan['effective_candidate_limit'], 0)
            self.assertEqual(scan['poc_count'], 0)
            self.assertEqual(scan['assertion_count'], 0)
            self.assertEqual(scan['fuzz_seconds_allocated'], 0)
            self.assertFalse(scan['verification_artifact_sha256'])
            self.assertEqual(provider.rejected_prewire, None)

        with TemporaryDirectory() as directory:
            asyncio.run(case(Path(directory) / 'fixture'))

    def test_official_phase1_scan_uses_only_sp_then_hp(self):
        """Real V2 qualification and selected Phase1, scripted provider only."""
        async def case(root: Path) -> None:
            _receipt, source_run, _context = boundary._historical()
            run = root / 'run'
            shutil.copytree(source_run, run)
            contract = json.loads(boundary.CONTRACT.read_text())
            qualification = official_runner.require_official_qualification(contract)
            selected = json.loads((run / 'selection.json').read_text())
            scope = selected['function_id']
            ledger = DevelopmentRequestLedger.create(DevelopmentBudget(
                physical_max=2, logical_max=2, retries_max=0,
                wall_seconds=60, initial_starts_required=2,
                sp_per_function=1, hp_per_function=1,
                combined_per_function=2, hp_analysis_per_function=1,
                hp_assertion_per_function=1), root / 'GLOBAL_LEDGER.json')
            self.assertTrue(ledger.select_function(scope))
            backend = ScriptedAppServer(ledger, root, {})
            backend.bind_scope(scope)
            provider = ProductBudgetAdapter(backend, ledger, scope)
            await scan_selected(run, provider,
                target_repository=boundary.TARGET,
                target_binary=qualification.binary,
                official_qualification=qualification,
                role_models=ROLE_MODELS, hallucination_prevent='on',
                sp_llm_call_limit=1, hp_llm_call_limit=1,
                hp_context_round_limit=0, max_candidates=2,
                targeted_fuzz_seconds=0, assertion_fuzz_seconds=0,
                global_fuzz_enabled=False, run_command=None,
                initial_inputs=None)
            backend.unbind_scope()
            scan = json.loads((run / 'scan.json').read_text())
            self.assertEqual([row['role'] for row in ledger.turns],
                             ['sp_generation', 'function_analysis'])
            self.assertEqual((ledger.physical, ledger.logical, ledger.retries),
                             (2, 2, 0))
            self.assertEqual(scan['effective_candidate_limit'], 0)
            self.assertEqual(scan['poc_count'], 0)
            self.assertEqual(scan['assertion_count'], 0)
            self.assertEqual(scan['fuzz_seconds_allocated'], 0)
            self.assertFalse(scan['verification_artifact_sha256'])
            self.assertIsNone(scan['hp_error'])

        with TemporaryDirectory() as directory:
            asyncio.run(case(Path(directory)))

    def test_parent_rejects_missing_non_delta_event_params(self):
        with TemporaryDirectory() as directory:
            output = Path(directory)

            def put(name: str, value) -> str:
                path = output / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = ((json.dumps(value, sort_keys=True) + '\n').encode()
                       if not isinstance(value, bytes) else value)
                path.write_bytes(raw)
                return hashlib.sha256(raw).hexdigest()

            spec_sha = 'a' * 64
            ledger = {
                'physical': 2, 'logical': 2, 'retries': 0,
                'active_turn': None, 'direction_scopes': [],
                'selected_functions': ['private-id'],
                'turns': [
                    {'role': role, 'status': 'COMPLETED', 'hash': c * 64}
                    for role, c in [('sp_generation', 'b'),
                                    ('function_analysis', 'c')]],
                'attempts': [
                    {'status': 'COMPLETED', 'accepted': True,
                     'response_saved': True,
                     'app_server_turn_id': 'turn-' + str(index),
                     'request_hash': c * 64}
                    for index, c in [(1, 'b'), (2, 'c')]],
            }
            ledger_sha = put(boundary.LEDGER_NAME, ledger)
            event_sha = put('MODEL_EVENTS.jsonl', b'{"method":"account/updated","params":{},"server_request":false,"item_type":null}\n')
            scan = {'selected_function_id': 'private-id',
                    'pending_sp_ids': [], 'sp_llm_calls': 1,
                    'hp_llm_calls': 1, 'effective_candidate_limit': 0,
                    'poc_count': 0, 'assertion_count': 0,
                    'fuzz_seconds_allocated': 0,
                    'verification_artifact_sha256': {},
                    'observed_crash_ids': [],
                    'fuzzer_observed_crash_ids': [],
                    'verified_crash_ids': []}
            scan_sha = put('product_run/scan.json', scan)
            points_sha = put('product_run/sp/candidates.json', [])
            analysis_sha = put('product_run/function_analysis.json',
                               {'safe_assumptions': [], 'unknowns': []})
            receipt = {'spec_sha256': spec_sha,
                       'historical_live_status': 'CHILD_ERROR',
                       'historical_direction_physical': 1,
                       'combined_physical_ledger_claim': False,
                       'official_v2_qualified': True,
                       'selected_count': 1,
                       'continuation_physical': 2,
                       'continuation_logical': 2,
                       'continuation_retries': 0,
                       'verifier_calls': 0, 'pov_calls': 0,
                       'fuzz_seconds': 0,
                       'event_audit_status': 'PASS_FULL_NON_DELTA_PARAMS',
                       'sp_candidate_count': 0,
                       'pending_verifier_count': 0,
                       'hp_safe_count': 0, 'hp_unknown_count': 0,
                       'pending_assertion_count': 0,
                       'ledger_sha256': ledger_sha,
                       'model_event_log_sha256': event_sha,
                       'scan_sha256': scan_sha,
                       'sp_candidates_sha256': points_sha,
                       'hp_analysis_sha256': analysis_sha}
            receipt_sha = put(boundary.RECEIPT_NAME, receipt)
            child = {'status': 'BOUNDED_SP_HP_OBSERVED_PENDING_DOWNSTREAM',
                     'spec_sha256': spec_sha,
                     'historical_receipt_sha256':
                         boundary.HISTORICAL_RECEIPT_SHA256,
                     'receipt_sha256': receipt_sha,
                     **{key: receipt[key] for key in (
                         'ledger_sha256', 'model_event_log_sha256',
                         'scan_sha256', 'sp_candidates_sha256',
                         'hp_analysis_sha256')}}
            fd = boundary._direction()._open_output_dir(output)
            try:
                check = lambda: boundary._completion_predicate(
                    child, fd, output, expected_spec_sha256=spec_sha)
                self.assertTrue(check())
                put('MODEL_EVENTS.jsonl', b'{"method":"account/updated","params":null,"server_request":false,"item_type":null}\n')
                new_sha = hashlib.sha256(
                    (output / 'MODEL_EVENTS.jsonl').read_bytes()).hexdigest()
                receipt['model_event_log_sha256'] = new_sha
                child['model_event_log_sha256'] = new_sha
                child['receipt_sha256'] = put(boundary.RECEIPT_NAME, receipt)
                self.assertFalse(check())
            finally:
                import os
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
