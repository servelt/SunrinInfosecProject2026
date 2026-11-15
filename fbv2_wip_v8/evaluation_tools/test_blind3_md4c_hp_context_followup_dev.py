"""Provider-free contract checks for isolated md4c HP Context follow-up."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'review_tools'),
                '/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src']
import blind3_md4c_hp_context_followup_dev as hp  # noqa: E402
from dev_global_appserver_product_flow import ScriptedAppServer, ROLE_MODELS  # noqa: E402
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger)
from vulnerabilityanalysis.adapter import HarnessAdapter  # noqa: E402
from vulnerabilityanalysis.agents import AgentPipeline  # noqa: E402
from vulnerabilityanalysis.source import SourceRepository  # noqa: E402


class HPContextFollowupTests(unittest.TestCase):
    def test_posthoc_source_and_official_context_resolve(self):
        receipt, original_request, selection, analysis, span, _request_path = hp._original()
        context = hp._resolved_input()
        self.assertEqual(receipt['original_supervisor_status'], 'CHILD_ERROR')
        self.assertEqual(receipt['continuation_physical'], 2)
        self.assertEqual(len(analysis['context_requests']), 2)
        self.assertEqual([row['record_count'] for row in context['records']], [2, 1])
        self.assertEqual(len(context['context']), 3)
        self.assertEqual(context['source_start_line'], span['start_line'])
        self.assertEqual(original_request['payload']['context'], [])
        self.assertEqual(context['selected_function_id'], selection['function_id'])

    def test_posthoc_pin_changed_is_rejected(self):
        with patch.object(hp, 'POSTHOC_SHA', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'post-hoc audit receipt changed'):
                hp._original()

    def test_original_request_is_bound_to_completed_ledger_hash(self):
        with patch('dev_global_appserver_bridge.artifact_hash',
                   return_value='0' * 64):
            with self.assertRaisesRegex(ValueError,
                                        'physical ledger'):
                hp._original()

    def test_parent_requires_all_and_only_three_model_artifacts(self):
        stem = 'logs/function_analysis_123_nonce_1'
        paths = {'request_artifact': stem + '_request.json',
                 'response_artifact': stem + '_parsed.json',
                 'raw_response_artifact': stem + '_raw.txt'}
        expected = set(hp._FIXED_HASHED_FILES) | set(paths.values())
        row = {'artifact_paths': paths, 'file_hashes': {
            name: 'a' * 64 for name in expected}}
        self.assertEqual(hp._required_hashed_files(row), expected)
        for excluded in expected:
            changed = {**row, 'file_hashes': {
                name: 'a' * 64 for name in expected - {excluded}}}
            self.assertIsNone(hp._required_hashed_files(changed))
        changed = {**row, 'file_hashes': {
            **row['file_hashes'], 'logs/extra.json': 'a' * 64}}
        self.assertIsNone(hp._required_hashed_files(changed))
        changed = {**row, 'artifact_paths': {**paths,
            'raw_response_artifact': '../outside_raw.txt'}}
        self.assertIsNone(hp._required_hashed_files(changed))

    def test_direct_live_entry_rejected_before_spec(self):
        with patch.object(hp, 'load_spec',
                          side_effect=AssertionError('spec reached')):
            with self.assertRaisesRegex(ValueError, 'external source pin'):
                hp.run_supervised(Path('/missing'), '0' * 64)
            with self.assertRaisesRegex(ValueError, 'external source pin'):
                asyncio.run(hp._run_child({}, '0' * 64))

    def test_real_product_analyzer_uses_recorded_context_with_one_scripted_turn(self):
        async def case(root: Path) -> None:
            _receipt, prior_request, selection, _prior_analysis, _span, _path = hp._original()
            context = hp._resolved_input()
            harness = HarnessAdapter().load(hp.ARTIFACT, target_repository=hp.TARGET)
            source_repo = SourceRepository(hp.TARGET, harness.function_catalog)
            source_span = source_repo.open_function_span(selection['function_id'])
            budget = DevelopmentBudget(
                physical_max=1, logical_max=1, retries_max=0,
                wall_seconds=60, initial_starts_required=1,
                sp_per_function=1, hp_per_function=1,
                combined_per_function=2, hp_analysis_per_function=1,
                hp_assertion_per_function=1)
            ledger = DevelopmentRequestLedger.create(budget, root / 'GLOBAL_LEDGER.json')
            self.assertTrue(ledger.select_function(selection['function_id']))
            backend = ScriptedAppServer(ledger, root, {})
            backend.bind_scope(selection['function_id'])
            pipeline = AgentPipeline(backend, max_context_requests=0,
                role_models=ROLE_MODELS, schema_error_dir=root / 'logs')
            result = await pipeline.analyze_function(
                selection['function_id'], selection['function_name'],
                selection['source_file'], source_span.source,
                context['context'],
                harness_source=Path(harness.harness_path).read_text(),
                harness_source_path=Path(harness.harness_path),
                analysis_scope=prior_request['payload']['analysis_scope'],
                source_start_line=source_span.start_line)
            backend.unbind_scope()
            self.assertEqual(result.function_id, selection['function_id'])
            self.assertEqual((ledger.physical, ledger.logical, ledger.retries),
                             (1, 1, 0))
            self.assertEqual([x['role'] for x in ledger.turns], ['function_analysis'])
            request_path = Path(pipeline.last_request_artifacts['request_artifact'])
            product_request = json.loads(request_path.read_text())
            self.assertEqual(product_request['payload']['context'], context['context'])
            self.assertEqual(product_request['payload']['source_start_line'],
                             source_span.start_line)
            self.assertTrue(product_request['payload']['source'].startswith(
                f'{source_span.start_line}: '))
            self.assertEqual(product_request['payload']['analysis_scope'],
                             prior_request['payload']['analysis_scope'])

        with TemporaryDirectory() as directory:
            asyncio.run(case(Path(directory)))


if __name__ == '__main__':
    unittest.main()
