"""Provider-free contract checks for the Blind 3 development Direction bridge."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREP = HERE.parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(HERE), str(PREP / 'review_tools'), str(PRODUCT / 'src'),
                str(PRODUCT / 'tests')]

from test_direction_plan import fixture  # noqa: E402
from development_direction_study import build_context  # noqa: E402
from dev_global_request_ledger import DevelopmentBudget, DevelopmentRequestLedger  # noqa: E402
from dev_global_appserver_bridge import request_hash  # noqa: E402
import blind3_direction_phase1_dev as bridge  # noqa: E402
from blind3_direction_context_windows_dev import window_excerpt  # noqa: E402


def prepared_context(repo: Path) -> tuple[dict, dict]:
    files = {
        'harness/source': (repo / 'fuzz.c').read_bytes(),
        'catalog/functions.jsonl': (repo / 'analysis/functions.jsonl').read_bytes(),
        'catalog/edges.jsonl': (repo / 'analysis/edges.jsonl').read_bytes(),
        'catalog/indirect_edges.jsonl': (repo / 'analysis/indirect_edges.jsonl').read_bytes(),
    }
    context = build_context(files, None, source_mode='all_catalog_prefix',
                            harness_member='harness/source', anchor_ids=['fn-a'])
    pins = {name: hashlib.sha256(files[member]).hexdigest() for name, member in (
        ('harness_sha256', 'harness/source'),
        ('functions_sha256', 'catalog/functions.jsonl'),
        ('edges_sha256', 'catalog/edges.jsonl'),
        ('indirect_edges_sha256', 'catalog/indirect_edges.jsonl'))}
    pins['source_files_sha256'] = {
        'target.c': hashlib.sha256((repo / 'target.c').read_bytes()).hexdigest()}
    return context, pins


def ledger(root: Path, *, physical_max: int = 2, logical_max: int = 2,
           direction_turns_per_scope: int = 1) -> DevelopmentRequestLedger:
    return DevelopmentRequestLedger.create(
        DevelopmentBudget(physical_max=physical_max, logical_max=logical_max,
                          retries_max=0,
                          wall_seconds=60, initial_starts_required=1,
                          sp_per_function=1, hp_per_function=1,
                          combined_per_function=2, hp_analysis_per_function=1,
                          hp_assertion_per_function=1,
                          direction_turns_per_scope=direction_turns_per_scope),
        root / 'GLOBAL_LEDGER.json')


class ScriptedDirectionBackend:
    def __init__(self, request_ledger: DevelopmentRequestLedger, response: dict | list[dict],
                 on_generate=None, *, account=True, write_raw=True):
        self.ledger = request_ledger
        self.responses = response if isinstance(response, list) else [response]
        self.on_generate = on_generate
        self.account = account
        self.write_raw = write_raw
        self.scope_id = None
        self.requests = []

    def bind_scope(self, scope_id: str) -> None:
        if self.scope_id is not None:
            raise ValueError('scope already bound')
        self.scope_id = scope_id

    def unbind_scope(self) -> None:
        self.scope_id = None

    async def generate(self, request):
        self.requests.append(request)
        response = self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]
        if not self.account:
            return copy.deepcopy(response)
        digest = request_hash(request)
        self.ledger.begin_turn(self.scope_id, request.role, digest)
        self.ledger.start_attempt(digest)
        if self.on_generate:
            self.on_generate()
        if self.write_raw:
            request.raw_response_path.write_text(json.dumps(response))
            request.raw_response_path.chmod(0o600)
        self.ledger.finish_attempt(completed=True, accepted=True,
                                   response_saved=True)
        return copy.deepcopy(response)


class DirectionBridgeTests(unittest.TestCase):
    @staticmethod
    def graph_gap(response: dict) -> dict:
        broken = copy.deepcopy(response)
        broken['directions'].append({
            'name': 'Reverse feature', 'risk_level': 'NORMAL',
            'entry_function_ids': ['fn-c'], 'core_function_ids': ['fn-b'],
            'rationale': 'This claim deliberately reverses the recorded B to C edge.'})
        return broken

    def test_repair_opt_in_valid_first_answer_spends_one_turn(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            result, request_ledger, backend, output = self.invoke(
                root, artifact, repo, response,
                direction_graph_repair_max_turns=2)
            self.assertEqual(request_ledger.physical, 1)
            self.assertEqual(result['direction_turn_count'], 1)
            self.assertFalse((output / 'DIRECTION_REPAIR_REQUEST.json').exists())
            self.assertIn('same Direction', backend.requests[0].instructions)
            self.assertIn('multiple Directions', backend.requests[0].instructions)

    def test_graph_gap_gets_one_accounted_repair_with_both_raw_records(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            valid = json.loads(proposal.read_text())['response']
            broken = self.graph_gap(valid)
            result, request_ledger, backend, output = self.invoke(
                root, artifact, repo, [broken, valid],
                direction_graph_repair_max_turns=2)
            self.assertEqual(result['direction_turn_count'], 2)
            self.assertEqual(request_ledger.physical, 2)
            self.assertEqual(request_ledger.logical, 2)
            self.assertEqual([row['status'] for row in request_ledger.turns],
                             ['COMPLETED', 'COMPLETED'])
            self.assertEqual(json.loads((output / 'DIRECTION_RAW.txt').read_text()), broken)
            self.assertEqual(json.loads((output / 'DIRECTION_REPAIR_RAW.txt').read_text()), valid)
            self.assertEqual(result['direction_repair_request_sha256'],
                             bridge.sha(output / 'DIRECTION_REPAIR_REQUEST.json'))
            self.assertEqual(result['direction_repair_raw_sha256'],
                             bridge.sha(output / 'DIRECTION_REPAIR_RAW.txt'))
            self.assertEqual(backend.requests[1].payload['graph_gaps'][0][
                'core_ids_without_path'], ['fn-b'])

    def test_invalid_repair_fails_without_phase1(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            valid = json.loads(proposal.read_text())['response']
            broken = self.graph_gap(valid)
            with self.assertRaisesRegex(ValueError, 'graph path'):
                self.invoke(root, artifact, repo, [broken, broken],
                            direction_graph_repair_max_turns=2)
            output = root / 'development-output'
            self.assertTrue((output / 'DIRECTION_REPAIR_RAW.txt').is_file())
            self.assertFalse((output / 'DIRECTION_PLAN.json').exists())
            self.assertFalse((output / 'product_runs').exists())

    def test_repair_physical_budget_exhaustion_fails_before_second_wire(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            valid = json.loads(proposal.read_text())['response']
            broken = self.graph_gap(valid)
            with self.assertRaisesRegex(ValueError, 'physical|budget|credit|not eligible'):
                self.invoke(root, artifact, repo, [broken, valid],
                            direction_graph_repair_max_turns=2,
                            physical_max=1, logical_max=2)
            output = root / 'development-output'
            self.assertFalse((output / 'DIRECTION_REPAIR_RAW.txt').exists())
            self.assertFalse((output / 'DIRECTION_PLAN.json').exists())

    def test_source_pin_change_during_repair_fails_closed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            valid = json.loads(proposal.read_text())['response']
            broken = self.graph_gap(valid)
            calls = 0
            def change_on_second():
                nonlocal calls
                calls += 1
                if calls == 2:
                    (repo / 'target.c').write_text('int A(void) { return 99; }\n')
            with self.assertRaisesRegex(ValueError, 'Direction input changed'):
                self.invoke(root, artifact, repo, [broken, valid],
                            on_generate=change_on_second,
                            direction_graph_repair_max_turns=2)
            self.assertFalse((root / 'development-output/product_runs').exists())

    def test_repair_status_io_failure_preserves_original_model_error(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            valid = json.loads(proposal.read_text())['response']
            broken = self.graph_gap(valid)
            calls = 0
            def stop_second():
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError('original model event error')
            write = bridge.private_json
            def fail_status(path, value):
                if path.name == 'DIRECTION_REPAIR_STATUS.json':
                    raise OSError('scripted status I/O failure')
                return write(path, value)
            with patch.object(bridge, 'private_json', side_effect=fail_status):
                with self.assertRaisesRegex(RuntimeError,
                                            'original model event error'):
                    self.invoke(root, artifact, repo, [broken, valid],
                                on_generate=stop_second,
                                direction_graph_repair_max_turns=2)
            self.assertFalse((root / 'development-output/product_runs').exists())

    def test_non_graph_validation_failure_never_requests_repair(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            valid = json.loads(proposal.read_text())['response']
            invalid = copy.deepcopy(valid)
            invalid['directions'][0]['core_function_ids'] = ['not-in-catalog']
            request_ledger = ledger(root, direction_turns_per_scope=2)
            backend = ScriptedDirectionBackend(request_ledger, [invalid, valid])
            with patch.object(bridge, 'build_context_from_artifact',
                              side_effect=lambda *_args, **_kwargs:
                                  prepared_context(repo)):
                with self.assertRaisesRegex(ValueError, 'unknown Catalog ID'):
                    asyncio.run(bridge.execute_direction_phase1(
                        output=root / 'development-output', artifact=artifact,
                        target_repository=repo, oss_fuzz_checkout=repo,
                        upstream_checkout=repo, backend=backend,
                        ledger=request_ledger,
                        role_models={'direction_generator': {
                            'model': 'test-model', 'reasoning': 'high'}},
                        scope_id='development-direction',
                        direction_graph_repair_max_turns=2))
            self.assertEqual(len(backend.requests), 1)

    def test_output_ancestor_symlink_is_rejected_before_model(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            request_ledger = ledger(root)
            backend = ScriptedDirectionBackend(request_ledger, response)
            real_parent = root / 'real'
            (real_parent / 'sub').mkdir(parents=True)
            (root / 'alias').symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'Direction output'):
                asyncio.run(bridge.execute_direction_phase1(
                    output=root / 'alias' / 'sub' / 'new',
                    artifact=artifact, target_repository=repo,
                    oss_fuzz_checkout=repo, upstream_checkout=repo,
                    backend=backend, ledger=request_ledger,
                    role_models={'direction_generator': {
                        'model': 'test-model', 'reasoning': 'high'}},
                    scope_id='development-direction'))
            self.assertEqual(backend.requests, [])

    def invoke(self, root: Path, artifact: Path, repo: Path,
               response: dict | list[dict],
               *, on_generate=None, source_mode='all_catalog_prefix',
               prepared=None, direction_graph_repair_max_turns=1,
               physical_max=2, logical_max=2):
        request_ledger = ledger(
            root, physical_max=physical_max, logical_max=logical_max,
            direction_turns_per_scope=direction_graph_repair_max_turns)
        backend = ScriptedDirectionBackend(request_ledger, response, on_generate)
        output = root / 'development-output'
        real_phase1 = bridge.run_phase1
        def checked_phase1(*args, **kwargs):
            self.assertTrue(1 <= len(backend.requests) <=
                            direction_graph_repair_max_turns)
            self.assertEqual([request.role for request in backend.requests],
                             ['direction_generator'] * len(backend.requests))
            self.assertEqual(request_ledger.physical, len(backend.requests))
            self.assertEqual(request_ledger.turns[-1]['status'], 'COMPLETED')
            return real_phase1(*args, **kwargs)
        context_builder = prepared or (lambda: prepared_context(repo))
        with patch.object(bridge, 'build_context_from_artifact',
                          side_effect=lambda *_args, **_kwargs: context_builder()), \
             patch.object(bridge, 'build_windowed_context_from_artifact',
                          side_effect=lambda *_args, **_kwargs: context_builder()), \
             patch.object(bridge, 'run_phase1', side_effect=checked_phase1):
            result = asyncio.run(bridge.execute_direction_phase1(
                output=output, artifact=artifact, target_repository=repo,
                oss_fuzz_checkout=repo, upstream_checkout=repo,
                backend=backend, ledger=request_ledger,
                role_models={'direction_generator': {
                    'model': 'test-model', 'reasoning': 'high'}},
                scope_id='development-direction', source_mode=source_mode,
                direction_graph_repair_max_turns=
                    direction_graph_repair_max_turns))
        return result, request_ledger, backend, output

    def test_window_option_changes_only_bounded_source_view(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            source = ('int A(const unsigned char *data, unsigned long size) {\n' +
                      '  unsigned filler = 0;\n' * 35 +
                      '  return size ? B(data[0]) : 0;\n' +
                      '  filler += 1;\n' * 25 + '}\n')
            call_line = source[:source.index('B(data[0])')].count('\n') + 1
            old, pins = prepared_context(repo)
            old['source_excerpts_by_graph_rule'] = [{
                'id': 'fn-a', 'source_prefix': source[:800],
                'source_truncated': True}]
            new = copy.deepcopy(old)
            new['source_excerpts_by_graph_rule'][0].pop('source_prefix')
            new['source_excerpts_by_graph_rule'][0].update(
                window_excerpt(source, 1, [call_line]))
            new['source_window_columns'] = [
                'start_char', 'end_char', 'start_line', 'text']
            new['omitted_range_columns'] = ['start_char', 'end_char']
            self.assertNotIn('B(data[0])', json.dumps(old))
            self.assertIn('B(data[0])', json.dumps(new))
            self.assertEqual(old['functions'], new['functions'])
            self.assertEqual(old['direct_edges'], new['direct_edges'])
            prefix_root, windows_root = root / 'prefix', root / 'windows'
            prefix_root.mkdir()
            windows_root.mkdir()
            old_result, old_ledger, old_backend, _ = self.invoke(
                prefix_root, artifact, repo, response,
                prepared=lambda: (copy.deepcopy(old), copy.deepcopy(pins)))
            new_result, new_ledger, new_backend, _ = self.invoke(
                windows_root, artifact, repo, response,
                source_mode='stratified_callsite_800',
                prepared=lambda: (copy.deepcopy(new), copy.deepcopy(pins)))
            self.assertEqual(old_ledger.physical, new_ledger.physical)
            self.assertEqual(old_ledger.physical, 1)
            self.assertEqual(old_result['direction_plan_sha256'],
                             new_result['direction_plan_sha256'])
            self.assertEqual(old_result['selection_policy'],
                             new_result['selection_policy'])
            self.assertEqual(old_backend.requests[0].payload['functions'],
                             new_backend.requests[0].payload['functions'])
            self.assertEqual(old_backend.requests[0].payload['direct_edges'],
                             new_backend.requests[0].payload['direct_edges'])
            self.assertEqual(
                json.loads((Path(old_result['phase1_run']) /
                            'function_pool.json').read_text()),
                json.loads((Path(new_result['phase1_run']) /
                            'function_pool.json').read_text()))

    def test_model_direction_precedes_real_phase1_and_is_charged(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            # The fixture writes directly into its existing directory.
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            result, request_ledger, backend, output = self.invoke(
                root, artifact, repo, response)
            run = Path(result['phase1_run'])
            self.assertEqual(result['status'], 'DIRECTION_PHASE1_PREPARED_DEV')
            self.assertEqual(request_ledger.physical, 1)
            self.assertEqual([row['role'] for row in request_ledger.turns],
                             ['direction_generator'])
            self.assertEqual([row['status'] for row in request_ledger.turns],
                             ['COMPLETED'])
            self.assertEqual(backend.requests[0].role, 'direction_generator')
            self.assertEqual((backend.requests[0].model,
                              backend.requests[0].effort), ('test-model', 'high'))
            self.assertIn('harness_source', backend.requests[0].payload)
            self.assertIn('direct_edges', backend.requests[0].payload)
            self.assertIn('functions', backend.requests[0].payload)
            self.assertEqual(json.loads((run / 'run.json').read_text())[
                'selection_policy'], 'FBV2_FIRST_PASS_UNIQUE_DEV')
            self.assertEqual(result['selection_policy'],
                             'FBV2_FIRST_PASS_UNIQUE_DEV')
            self.assertEqual(json.loads((run / 'run.json').read_text())[
                'direction_plan_sha256'], result['direction_plan_sha256'])
            self.assertEqual((run / 'direction_plan.json').read_bytes(),
                             (output / 'DIRECTION_PLAN.json').read_bytes())
            pool = json.loads((run / 'function_pool.json').read_text())
            self.assertEqual(len({row['function_id'] for row in pool}), len(pool))
            self.assertEqual(len(pool), 5)

    def test_invalid_response_cannot_start_phase1(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            response['directions'][0]['core_function_ids'] = ['not-a-catalog-id']
            with self.assertRaises(ValueError):
                self.invoke(root, artifact, repo, response)
            self.assertFalse((root / 'development-output/product_runs').exists())
            self.assertFalse((root / 'development-output/DIRECTION_PLAN.json').exists())

    def test_source_changed_during_turn_cannot_start_phase1(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            def change_source():
                (repo / 'target.c').write_text('int A(void) { return 99; }\n')
            with self.assertRaisesRegex(ValueError, 'Direction input changed'):
                self.invoke(root, artifact, repo, response, on_generate=change_source)
            self.assertFalse((root / 'development-output/product_runs').exists())

    def test_overlapping_claims_preserve_plan_but_select_unique_pool(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            response['directions'][0]['core_function_ids'] = ['fn-a', 'fn-b']
            response['directions'].append({
                'name': 'Shared input feature', 'risk_level': 'NORMAL',
                'entry_function_ids': ['fn-a'], 'core_function_ids': ['fn-b'],
                'rationale': 'The same recorded A to B path belongs to this feature.'})
            result, _, _, output = self.invoke(root, artifact, repo, response)
            run = Path(result['phase1_run'])
            self.assertEqual(json.loads((output / 'DIRECTION_PLAN.json').read_text())[
                'response']['directions'][0]['core_function_ids'], ['fn-a', 'fn-b'])
            directions = json.loads((run / 'directions.json').read_text())
            self.assertEqual(directions[0]['entry_functions'], ['A'])
            self.assertEqual(directions[0]['core_functions'], ['B'])
            pool = json.loads((run / 'function_pool.json').read_text())
            self.assertEqual(len(pool), len({row['function_id'] for row in pool}))

    def test_unaccounted_direction_response_cannot_start_phase1(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            request_ledger = ledger(root)
            backend = ScriptedDirectionBackend(request_ledger, response, account=False)
            with patch.object(bridge, 'build_context_from_artifact',
                              side_effect=lambda *_args, **_kwargs: prepared_context(repo)):
                with self.assertRaisesRegex(ValueError, 'physical ledger'):
                    asyncio.run(bridge.execute_direction_phase1(
                        output=root / 'development-output', artifact=artifact,
                        target_repository=repo, oss_fuzz_checkout=repo,
                        upstream_checkout=repo, backend=backend,
                        ledger=request_ledger,
                        role_models={'direction_generator': {
                            'model': 'test-model', 'reasoning': 'high'}},
                        scope_id='development-direction'))
            self.assertFalse((root / 'development-output/product_runs').exists())

    def test_missing_raw_model_response_cannot_start_phase1(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / 'fixture'
            fixture_root.mkdir()
            artifact, repo, proposal = fixture(fixture_root)
            response = json.loads(proposal.read_text())['response']
            request_ledger = ledger(root)
            backend = ScriptedDirectionBackend(request_ledger, response, write_raw=False)
            with patch.object(bridge, 'build_context_from_artifact',
                              side_effect=lambda *_args, **_kwargs: prepared_context(repo)):
                with self.assertRaisesRegex(ValueError, 'raw response'):
                    asyncio.run(bridge.execute_direction_phase1(
                        output=root / 'development-output', artifact=artifact,
                        target_repository=repo, oss_fuzz_checkout=repo,
                        upstream_checkout=repo, backend=backend,
                        ledger=request_ledger,
                        role_models={'direction_generator': {
                            'model': 'test-model', 'reasoning': 'high'}},
                        scope_id='development-direction'))
            self.assertFalse((root / 'development-output/product_runs').exists())


if __name__ == '__main__':
    unittest.main()
