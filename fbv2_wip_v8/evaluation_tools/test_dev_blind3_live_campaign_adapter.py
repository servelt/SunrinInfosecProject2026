"""Provider-free boundary tests for one official four-phase live-model job."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(TOOLS), str(PRODUCT / 'src'), str(PRODUCT / 'tests')]

from dev_blind3_live_campaign_adapter import run_one_development_work_item  # noqa: E402
from dev_fbv2_four_phase_worklist import build_from_pinned_run  # noqa: E402
from dev_global_appserver_bridge import DevelopmentGlobalAppServer  # noqa: E402
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE,
)
from dev_no_k_three_function_gate import make_public_fixture  # noqa: E402
from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger  # noqa: E402
from vulnerabilityanalysis.llm import LLMRequest  # noqa: E402
from vulnerabilityanalysis.scan import scan_selected as product_scan_selected  # noqa: E402
from vulnerabilityanalysis.workflow import run_phase1  # noqa: E402


ROUTES = {role: {'model': 'test-model', 'reasoning': 'high'}
          for role in ('sp_generation', 'sp_verifier', 'poc_generator',
                       'function_analysis', 'assertion_generator')}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ToyQualification:
    """Only a test stand-in. The actual adapter delegates authority to Scan."""

    product_issued = True

    def __init__(self, repo: Path):
        self.source_root = repo.resolve()
        self.harness = (repo / 'fuzz.c').resolve()
        self.binary = (repo / 'target.bin').resolve()


class NoCandidateWire(DevelopmentGlobalAppServer):
    def __init__(self, ledger: DevelopmentRequestLedger,
                 physical: PersistentPhysicalFuzzLedger, root: Path):
        super().__init__(ledger=ledger, physical_ledger=physical,
                         role_models=ROUTES, cwd=root, model='test-model',
                         effort='high', timeout_seconds=2,
                         event_log_path=root / 'MODEL_EVENTS.jsonl')
        self.wire_starts: list[int] = []

    async def start(self) -> None:
        pass

    async def _thread_for(self, role, session_key, model) -> str:
        return 'test-thread'

    async def _delete_ephemeral_thread(self, thread_id: str) -> None:
        pass

    async def _transport_request(self, method: str, params: dict) -> dict:
        if method != 'turn/start':
            return {}
        saved = json.loads(self.ledger.checkpoint_path.read_text())
        self.wire_starts.append(saved['physical'])
        return {'turn': {'id': f'test-turn-{len(self.wire_starts)}'}}

    async def _collect(self, thread_id: str, turn_id: str) -> str:
        self._record_server_event({'method': 'turn/completed', 'params': {
            'threadId': thread_id,
            'turn': {'id': turn_id, 'status': 'completed', 'items': []}}})
        role = self.ledger.active_turn['role']
        if role == 'sp_generation':
            return '{"suspicious_points":[]}'
        if role == 'function_analysis':
            return json.dumps({
                'summary': 'public toy no-safe analysis',
                'input_flow': 'none', 'state_dependencies': [],
                'context_requests': [], 'safe_assumptions': [],
                'unknowns': [], 'input_sources': [],
                'security_sensitive_operations': [], 'validations': [],
                'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': [],
            })
        raise AssertionError('unexpected model role in public toy fixture')

    async def close(self) -> None:
        pass


class LiveOneWorkItemTests(unittest.IsolatedAsyncioTestCase):
    def fixture(self, root: Path, *, physical_max: int = 1):
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        run = run_phase1(artifact, repo / 'runs', target_repository=repo,
                         direction_plan=plan,
                         selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        worklist = root / 'WORKLIST.json'
        worklist.write_text(json.dumps(build_from_pinned_run(run), sort_keys=True)
                            + '\n')
        (repo / 'target.bin').write_bytes(b'public toy binary never executed\n')
        budget = DevelopmentBudget(
            physical_max=physical_max, logical_max=physical_max,
            retries_max=0, wall_seconds=60, initial_starts_required=1,
            profile=GLOBAL_ONLY_DEV_PROFILE)
        ledger = DevelopmentRequestLedger.create(budget, root / 'MODEL_LEDGER.json')
        physical = PersistentPhysicalFuzzLedger.create(
            root / 'PHYSICAL_LEDGER.json', total_seconds=30)
        backend = NoCandidateWire(ledger, physical, root)
        return run, worklist, repo, ledger, physical, backend

    async def test_one_work_item_counts_guarded_sp_and_hp_wire_starts(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run, worklist, repo, ledger, physical, backend = self.fixture(
                root, physical_max=3)
            with (patch('vulnerabilityanalysis.official_harness.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True)):
                result = await run_one_development_work_item(
                    source_run=run, worklist_path=worklist,
                    expected_worklist_sha256=sha(worklist),
                    first_run=repo / 'runs' / 'first-live',
                    target_repository=repo,
                    target_binary=repo / 'target.bin',
                    official_qualification=ToyQualification(repo),
                    backend=backend, model_ledger=ledger,
                    physical_ledger=physical, role_models=ROUTES)
            self.assertEqual(result['status'], 'SCAN_RECORDED')
            self.assertEqual(result['model_physical_starts'], 2)
            self.assertEqual(backend.wire_starts, [1, 2])
            self.assertEqual([row['role'] for row in ledger.turns],
                             ['sp_generation', 'function_analysis'])
            self.assertEqual(ledger.direction_counts, {})
            self.assertEqual(result['target_runs'], 0)
            self.assertEqual(result['fuzz_seconds'], 0)
            self.assertEqual(ledger.function_states[result['work_item_id']],
                             'SCAN_RECORDED')

    async def test_stop_after_sp_before_hp_is_terminal_not_scan_recorded(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run, worklist, repo, ledger, physical, backend = self.fixture(
                root, physical_max=3)
            collect = backend._collect

            async def stop_after_sp(thread_id: str, turn_id: str) -> str:
                response = await collect(thread_id, turn_id)
                physical.reserve('HP:cleanup', 'HP', 10)
                physical.finish('HP:cleanup', physical_seconds=1,
                                cleanup_complete=False)
                return response

            backend._collect = stop_after_sp
            with (patch('vulnerabilityanalysis.official_harness.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True)):
                result = await run_one_development_work_item(
                    source_run=run, worklist_path=worklist,
                    expected_worklist_sha256=sha(worklist),
                    first_run=repo / 'runs' / 'first-live',
                    target_repository=repo,
                    target_binary=repo / 'target.bin',
                    official_qualification=ToyQualification(repo),
                    backend=backend, model_ledger=ledger,
                    physical_ledger=physical, role_models=ROUTES)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertFalse(result['analysis_complete'])
            self.assertEqual(result['model_physical_starts'], 1)
            self.assertEqual(backend.wire_starts, [1])
            self.assertEqual(ledger.function_states[result['work_item_id']],
                             'INCOMPLETE_INTERRUPTED')
            self.assertTrue(any(row['scope_id'] == result['work_item_id'] and
                                row['state'] == 'INCOMPLETE_PRE_SEND_MODEL_TURN'
                                for row in ledger.pending_work))
            self.assertFalse((repo / 'runs' / 'first-live' / 'scan.json').exists())

    async def test_changed_final_scan_cannot_pass_stale_terminal_marker(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run, worklist, repo, ledger, physical, backend = self.fixture(
                root, physical_max=3)

            async def change_scan(selected_run: Path, *args, **kwargs):
                await product_scan_selected(selected_run, *args, **kwargs)
                scan_path = selected_run / 'scan.json'
                scan = json.loads(scan_path.read_text())
                scan['late_edit'] = True
                scan_path.write_text(json.dumps(scan, sort_keys=True) + '\n')

            with (patch('vulnerabilityanalysis.official_harness.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True),
                  patch('vulnerabilityanalysis.scan.scan_selected',
                        side_effect=change_scan)):
                with self.assertRaisesRegex(ValueError, 'terminal Scan marker'):
                    await run_one_development_work_item(
                        source_run=run, worklist_path=worklist,
                        expected_worklist_sha256=sha(worklist),
                        first_run=repo / 'runs' / 'first-live',
                        target_repository=repo,
                        target_binary=repo / 'target.bin',
                        official_qualification=ToyQualification(repo),
                        backend=backend, model_ledger=ledger,
                        physical_ledger=physical, role_models=ROUTES)
            self.assertNotIn('SCAN_RECORDED', ledger.function_states.values())

    async def test_cleanup_stop_after_scan_write_blocks_evaluator_settlement(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run, worklist, repo, ledger, physical, backend = self.fixture(
                root, physical_max=3)

            async def scan_then_stop(selected_run: Path, *args, **kwargs):
                await product_scan_selected(selected_run, *args, **kwargs)
                self.assertTrue((selected_run / 'scan.json').is_file())
                self.assertTrue((selected_run / 'four_phase_scan_complete.json').is_file())
                physical.reserve('HP:post-scan-stop', 'HP', 10)
                physical.finish('HP:post-scan-stop', physical_seconds=1,
                                cleanup_complete=False)

            with (patch('vulnerabilityanalysis.official_harness.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True),
                  patch('vulnerabilityanalysis.scan.scan_selected',
                        side_effect=scan_then_stop)):
                result = await run_one_development_work_item(
                    source_run=run, worklist_path=worklist,
                    expected_worklist_sha256=sha(worklist),
                    first_run=repo / 'runs' / 'first-live',
                    target_repository=repo,
                    target_binary=repo / 'target.bin',
                    official_qualification=ToyQualification(repo),
                    backend=backend, model_ledger=ledger,
                    physical_ledger=physical, role_models=ROUTES)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertFalse(result['analysis_complete'])
            self.assertEqual(backend.wire_starts, [1, 2])
            self.assertIsNotNone(result['scan_sha256'])
            self.assertEqual(ledger.function_states[result['work_item_id']],
                             'INCOMPLETE_PHYSICAL_STOP')

    async def test_hp_start_after_stop_preserves_interrupted_turn(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run, worklist, repo, ledger, physical, backend = self.fixture(
                root, physical_max=2)

            async def sp_then_stopped_hp(_run, provider, **_options):
                await provider.generate(LLMRequest(
                    role='sp_generation', instructions='toy', payload={},
                    output_schema={'type': 'object', 'properties': {
                        'suspicious_points': {'type': 'array'}},
                        'required': ['suspicious_points']},
                    model='test-model', effort='high'))
                physical.reserve('HP:before-start', 'HP', 10)
                physical.finish('HP:before-start', physical_seconds=1,
                                cleanup_complete=False)
                await provider.generate(LLMRequest(
                    role='function_analysis', instructions='toy', payload={},
                    output_schema={'type': 'object'},
                    model='test-model', effort='high'))

            with (patch('vulnerabilityanalysis.official_harness.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True),
                  patch('vulnerabilityanalysis.scan.scan_selected',
                        side_effect=sp_then_stopped_hp)):
                result = await run_one_development_work_item(
                    source_run=run, worklist_path=worklist,
                    expected_worklist_sha256=sha(worklist),
                    first_run=repo / 'runs' / 'first-live',
                    target_repository=repo,
                    target_binary=repo / 'target.bin',
                    official_qualification=ToyQualification(repo),
                    backend=backend, model_ledger=ledger,
                    physical_ledger=physical, role_models=ROUTES)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertFalse(result['analysis_complete'])
            self.assertEqual(result['model_physical_starts'], 1)
            self.assertEqual(backend.wire_starts, [1])
            self.assertEqual(ledger.function_states[result['work_item_id']],
                             'INCOMPLETE_INTERRUPTED')
            self.assertTrue(any(row['scope_id'] == result['work_item_id'] and
                                row['state'] == 'INCOMPLETE_PRE_SEND_MODEL_TURN'
                                for row in ledger.pending_work))
            self.assertFalse((repo / 'runs' / 'first-live' / 'scan.json').exists())

    async def test_preexisting_physical_stop_has_no_model_or_target_start(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            run, worklist, repo, ledger, physical, backend = self.fixture(root)
            physical.reserve('SP:prior', 'SP', 10)
            physical.finish('SP:prior', physical_seconds=1,
                            cleanup_complete=False)
            with (patch('vulnerabilityanalysis.official_harness.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        ToyQualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True)):
                result = await run_one_development_work_item(
                    source_run=run, worklist_path=worklist,
                    expected_worklist_sha256=sha(worklist),
                    first_run=repo / 'runs' / 'first-live',
                    target_repository=repo,
                    target_binary=repo / 'target.bin',
                    official_qualification=ToyQualification(repo),
                    backend=backend, model_ledger=ledger,
                    physical_ledger=physical, role_models=ROUTES)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['model_physical_starts'], 0)
            self.assertEqual(backend.wire_starts, [])
            self.assertEqual(result['target_runs'], 0)
            self.assertEqual(result['analysis_complete'], False)


if __name__ == '__main__':
    unittest.main()
