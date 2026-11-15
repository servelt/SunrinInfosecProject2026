"""Provider-free campaign shell over two Directions sharing one function."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools')]

import dev_blind3_campaign_shell as shell  # noqa: E402
from dev_fbv2_four_phase_worklist import build_from_pinned_run  # noqa: E402
from dev_global_request_ledger import (DevelopmentBudget,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)  # noqa: E402
from dev_no_k_three_function_gate import make_public_fixture  # noqa: E402
from dev_persistent_physical_fuzz_ledger import (PersistentPhysicalFuzzLedger,
                                                 PhysicalModelStartBlocked)  # noqa: E402
from test_dev_multifunction_global_scan import _Qualification  # noqa: E402
from vulnerabilityanalysis.workflow import run_phase1  # noqa: E402


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


class Blind3CampaignShellTests(unittest.TestCase):
    def fixture(self, root: Path, *, physical_max: int):
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        proposal = _read(plan)
        first = proposal['response']['directions'][0]
        first['core_function_ids'] = ['fn-a']
        proposal['response']['directions'].append(
            dict(first, name='Second public Direction'))
        plan.write_text(json.dumps(proposal, sort_keys=True) + '\n')
        source = run_phase1(artifact, repo / 'runs', target_repository=repo,
                            direction_plan=plan,
                            selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        worklist = build_from_pinned_run(source)
        self.assertEqual(worklist['counts']['phases']['small/new'], 2)
        worklist_path = root / 'WORKLIST.json'
        worklist_path.write_text(json.dumps(worklist, sort_keys=True) + '\n')
        binary = repo / 'target.bin'
        binary.write_bytes(b'public synthetic binary; never executed\n')
        qualification = _Qualification(repo, repo / 'fuzz.c', binary)
        model = DevelopmentRequestLedger.create(DevelopmentBudget(
            physical_max=physical_max, logical_max=physical_max,
            retries_max=0, wall_seconds=60, initial_starts_required=1,
            profile=GLOBAL_ONLY_DEV_PROFILE), root / 'MODEL_LEDGER.json')
        model.register_direction('public-direction')
        model.begin_turn('public-direction', 'direction_generator', 'a' * 64)
        model.start_attempt('a' * 64)
        model.finish_attempt(completed=True)
        physical = PersistentPhysicalFuzzLedger.create(
            root / 'PHYSICAL_LEDGER.json', total_seconds=120)
        return {
            'source_run': source, 'worklist_path': worklist_path,
            'expected_worklist_sha256': hashlib.sha256(
                worklist_path.read_bytes()).hexdigest(),
            'first_run': repo / 'runs' / 'campaign-first',
            'campaign_output': root / 'campaign',
            'target_repository': repo, 'target_binary': binary,
            'official_qualification': qualification,
            'model_ledger': model, 'physical_ledger': physical,
        }

    @staticmethod
    def run_shell(args: dict):
        with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                    _Qualification),
              patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                    return_value=True),
              patch('vulnerabilityanalysis.scan.execute_poc',
                    side_effect=AssertionError('Target execution forbidden')),
              patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                    side_effect=AssertionError('Fuzzing forbidden')),
              patch('vulnerabilityanalysis.scan.run_global_fuzz',
                    side_effect=AssertionError('Global Fuzzing forbidden')),
              patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                    side_effect=AssertionError('Target execution forbidden'))):
            return asyncio.run(shell.run_scripted_four_phase_campaign(**args))

    def test_two_direction_jobs_make_two_scans_with_one_global_ledger(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            result = self.run_shell(args)
            self.assertEqual(result['status'], 'BUDGET_EXHAUSTED_PENDING_WORK')
            self.assertEqual(len(result['completed']), 2)
            first, second = result['completed']
            self.assertEqual(first['function_id'], second['function_id'])
            self.assertNotEqual(first['direction_id'], second['direction_id'])
            self.assertNotEqual(first['work_item_id'], second['work_item_id'])
            self.assertEqual(result['physical_model_starts'], 3)
            self.assertEqual(result['logical_model_turns'], 3)
            self.assertEqual(result['target_runs'], 0)
            self.assertEqual(result['fuzz_seconds'], 0)
            ledger = args['model_ledger']
            self.assertEqual(ledger.selected_functions,
                             [first['work_item_id'], second['work_item_id']])
            self.assertTrue(all(ledger.function_states[item['work_item_id']] ==
                                'SCAN_RECORDED' for item in result['completed']))
            for item in result['completed']:
                run = next(path for path in args['first_run'].parent.iterdir()
                           if path.is_dir() and (path / 'work_item.json').is_file()
                           and _read(path / 'work_item.json')['work_item_id'] ==
                           item['work_item_id'])
                self.assertEqual(_read(run / 'scan.json')['selected_direction_id'],
                                 item['direction_id'])
            self.assertTrue((args['campaign_output'] / 'PENDING_WORKLIST.json').is_file())

    def test_budget_stop_before_second_request_preserves_pending(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=2)
            result = self.run_shell(args)
            self.assertEqual(result['status'], 'BUDGET_EXHAUSTED_PENDING_WORK')
            self.assertEqual(len(result['completed']), 1)
            self.assertEqual(result['physical_model_starts'], 2)
            self.assertGreater(result['pending_count'], 0)
            current = Path(result['current_run'])
            self.assertFalse((current / 'scan.json').exists())
            self.assertEqual(args['model_ledger'].no_opportunity[
                _read(current / 'work_item.json')['work_item_id']],
                'NO_OPPORTUNITY_BUDGET')
            pending = _read(args['campaign_output'] / 'PENDING_WORKLIST.json')
            self.assertTrue(all(row['state'] == 'PENDING_BUDGET'
                                for row in pending['pending']))

    def test_cancel_after_physical_model_start_is_incomplete_without_next_job(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            args['cancel_on_ordinal'] = 0
            with self.assertRaises(asyncio.CancelledError):
                self.run_shell(args)
            result = _read(args['campaign_output'] / 'CAMPAIGN_PROGRESS.json')
            self.assertEqual(result['status'], 'INCOMPLETE_INTERRUPTED')
            self.assertEqual(result['completed'], [])
            self.assertEqual(result['physical_model_starts'], 2)
            ledger = args['model_ledger']
            self.assertEqual(len(ledger.selected_functions), 1)
            self.assertEqual(ledger.pending_work[0]['state'],
                             'INCOMPLETE_UNCERTAIN_REMOTE_STATE')
            self.assertEqual(ledger.function_states[ledger.selected_functions[0]],
                             'INCOMPLETE_INTERRUPTED')
            self.assertEqual(len(list(args['first_run'].parent.glob('*/scan.json'))), 0)

    def test_prior_guided_cleanup_failure_stops_next_job_before_model(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            real_continue = shell.continue_four_phase_dev
            physical = args['physical_ledger']

            def stop_after_first(run):
                next_run = real_continue(run)
                physical.reserve('HP:scripted-guided', 'HP', 10)
                physical.finish('HP:scripted-guided', physical_seconds=1,
                                cleanup_complete=False)
                return next_run

            with patch.object(shell, 'continue_four_phase_dev',
                              side_effect=stop_after_first):
                result = self.run_shell(args)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(len(result['completed']), 1)
            self.assertEqual(result['physical_model_starts'], 2)
            self.assertFalse((Path(result['current_run']) / 'scan.json').exists())
            self.assertEqual(args['model_ledger'].no_opportunity[
                _read(Path(result['current_run']) / 'work_item.json')['work_item_id']],
                'NO_OPPORTUNITY_PHYSICAL_STOP')

    def test_cleanup_stop_between_precheck_and_model_start_blocks_start(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            physical = args['physical_ledger']
            real_hash = shell.request_hash
            injected = []

            def stop_after_precheck(request):
                digest = real_hash(request)
                physical.reserve('SP:race-after-precheck', 'SP', 10)
                physical.finish('SP:race-after-precheck', physical_seconds=1,
                                cleanup_complete=False)
                injected.append(physical.snapshot()['revision'])
                return digest

            with patch.object(shell, 'request_hash', side_effect=stop_after_precheck):
                result = self.run_shell(args)
            self.assertEqual(len(injected), 1)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['physical_model_starts'], 1)  # Direction only
            self.assertEqual(result['attempts'][-1]['status'],
                             'INCOMPLETE_PHYSICAL_STOP')
            self.assertEqual(args['model_ledger'].active_turn, None)
            self.assertEqual(len(args['model_ledger'].selected_functions), 1)
            self.assertEqual(args['model_ledger'].function_states[
                args['model_ledger'].selected_functions[0]], 'INCOMPLETE_PHYSICAL_STOP')
            scope = args['model_ledger'].selected_functions[0]
            self.assertEqual(args['model_ledger'].summary([scope])['status'], 'INCOMPLETE')
            self.assertEqual(args['model_ledger'].pending_work[-1]['reason'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            restored = DevelopmentRequestLedger.restore(
                args['model_ledger'].checkpoint_path, args['model_ledger'].budget)
            self.assertEqual(restored.function_states[scope], 'INCOMPLETE_PHYSICAL_STOP')
            with self.assertRaises(ValueError):
                restored.select_function('another-public-function')
            with self.assertRaises(ValueError):
                restored.begin_turn(scope, 'sp_generation', 'b' * 64)
            self.assertEqual(len(list(args['first_run'].parent.glob('*/scan.json'))), 0)

    def test_cleanup_stop_at_selection_return_starts_zero_sp_turns(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            model, physical = args['model_ledger'], args['physical_ledger']
            real_select = model.select_function

            def select_then_stop(scope_id):
                selected = real_select(scope_id)
                if selected:
                    physical.reserve('GLOBAL:selection-race', 'GLOBAL', 10)
                    physical.finish('GLOBAL:selection-race', physical_seconds=1,
                                    cleanup_complete=False)
                return selected

            with patch.object(model, 'select_function', side_effect=select_then_stop):
                result = self.run_shell(args)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['physical_model_starts'], 1)
            self.assertEqual(result['logical_model_turns'], 1)
            self.assertEqual(model.summary(model.selected_functions)['status'],
                             'INCOMPLETE')
            self.assertEqual(sum(model.function_counts[scope].get('sp_generation', 0)
                                 for scope in model.selected_functions), 0)
            self.assertEqual(result['attempts'][-1]['model_roles'], [])
            self.assertFalse((Path(result['current_run']) / 'scan.json').exists())

    def test_physical_stop_checkpoint_failure_keeps_stop_as_primary_error(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            physical, model = args['physical_ledger'], args['model_ledger']
            real_hash = shell.request_hash

            def stop_after_precheck(request):
                digest = real_hash(request)
                physical.reserve('HP:audit-failure', 'HP', 10)
                physical.finish('HP:audit-failure', physical_seconds=1,
                                cleanup_complete=False)
                return digest

            with (patch.object(shell, 'request_hash', side_effect=stop_after_precheck),
                  patch.object(model, 'mark_selected_physical_stop',
                               side_effect=OSError('synthetic checkpoint failure'))):
                with self.assertRaises(PhysicalModelStartBlocked) as captured:
                    self.run_shell(args)
            self.assertEqual(captured.exception.status,
                             'STOPPED_CLEANUP_INCOMPLETE')
            self.assertTrue(any('OSError' in note for note in
                                getattr(captured.exception, '__notes__', [])))
            progress = _read(args['campaign_output'] / 'CAMPAIGN_PROGRESS.json')
            self.assertEqual(progress['status'], 'STOPPED_AUDIT_INCOMPLETE')
            self.assertEqual(progress['audit_error_type'], 'OSError')
            self.assertEqual(progress['physical_model_starts'], 1)
            self.assertEqual(len(model.selected_functions), 1)
            self.assertEqual(model.function_states[model.selected_functions[0]],
                             'SELECTED_NOT_STARTED')
            self.assertEqual(len(list(args['first_run'].parent.glob('*/scan.json'))), 0)

    def test_stop_after_scan_before_settlement_is_terminal_incomplete(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            physical, model = args['physical_ledger'], args['model_ledger']
            real_read = shell._read

            def read_scan_then_stop(path):
                row = real_read(path)
                if path.name == 'scan.json':
                    physical.reserve('SP:post-scan-stop', 'SP', 10)
                    physical.finish('SP:post-scan-stop', physical_seconds=1,
                                    cleanup_complete=False)
                return row

            with patch.object(shell, '_read', side_effect=read_scan_then_stop):
                result = self.run_shell(args)
            scope = model.selected_functions[0]
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['physical_model_starts'], 2)
            self.assertEqual(result['completed'], [])
            self.assertEqual(model.function_states[scope], 'INCOMPLETE_PHYSICAL_STOP')
            self.assertEqual(model.summary([scope])['status'], 'INCOMPLETE')
            self.assertEqual(model.pending_work[-1]['reason'],
                             'STOPPED_CLEANUP_INCOMPLETE')
            self.assertTrue((Path(result['current_run']) / 'scan.json').is_file())
            self.assertEqual(len(model.selected_functions), 1)
            with self.assertRaises(ValueError):
                model.select_function('next-function')

    def test_scan_recorded_before_concurrent_stop_stays_complete(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            physical, model = args['physical_ledger'], args['model_ledger']
            real_mark = model.mark_scan_recorded
            real_continue = shell.continue_four_phase_dev
            entered, stopped = threading.Event(), threading.Event()
            stop_errors: list[BaseException] = []
            stop_thread: threading.Thread | None = None

            def stop_after_recorded():
                entered.set()
                try:
                    physical.reserve('HP:after-scan-recorded', 'HP', 10)
                    physical.finish('HP:after-scan-recorded', physical_seconds=1,
                                    cleanup_complete=False)
                except BaseException as exc:
                    stop_errors.append(exc)
                finally:
                    stopped.set()

            def mark_then_race(scope_id):
                nonlocal stop_thread
                real_mark(scope_id)
                stop_thread = threading.Thread(target=stop_after_recorded,
                                               daemon=True)
                stop_thread.start()
                self.assertTrue(entered.wait(timeout=2))
                self.assertFalse(stopped.wait(timeout=.05))

            def continue_after_stop(run):
                self.assertIsNotNone(stop_thread)
                stop_thread.join(timeout=2)
                self.assertFalse(stop_thread.is_alive())
                self.assertEqual(stop_errors, [])
                return real_continue(run)

            with (patch.object(model, 'mark_scan_recorded',
                               side_effect=mark_then_race),
                  patch.object(shell, 'continue_four_phase_dev',
                               side_effect=continue_after_stop)):
                result = self.run_shell(args)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['physical_model_starts'], 2)
            self.assertEqual(len(result['completed']), 1)
            first_scope = result['completed'][0]['work_item_id']
            self.assertEqual(model.function_states[first_scope], 'SCAN_RECORDED')
            self.assertEqual(len(model.selected_functions), 1)
            self.assertTrue(stopped.is_set())
            self.assertEqual(model.no_opportunity[
                _read(Path(result['current_run']) / 'work_item.json')['work_item_id']],
                'NO_OPPORTUNITY_PHYSICAL_STOP')

    def test_cancel_and_abandon_write_failure_preserves_original_error(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            args['cancel_on_ordinal'] = 0
            model = args['model_ledger']
            with patch.object(model, 'abandon_turn',
                              side_effect=OSError('synthetic audit write failure')):
                with self.assertRaises(asyncio.CancelledError) as captured:
                    self.run_shell(args)
            self.assertTrue(any('OSError' in note for note in
                                getattr(captured.exception, '__notes__', [])))
            progress = _read(args['campaign_output'] / 'CAMPAIGN_PROGRESS.json')
            self.assertEqual(progress['status'], 'STOPPED_AUDIT_INCOMPLETE')
            self.assertEqual(progress['error_type'], 'CancelledError')
            self.assertEqual(progress['audit_error_type'], 'OSError')
            self.assertEqual(progress['physical_model_starts'], 2)
            self.assertEqual(progress['completed'], [])
            self.assertIsNotNone(model.active_turn)
            self.assertEqual(model.attempts[-1]['status'], 'STARTED')
            self.assertEqual(len(model.selected_functions), 1)
            self.assertEqual(len(list(args['first_run'].parent.glob('*/scan.json'))), 0)

    def test_continuation_error_is_terminal_and_does_not_start_next_job(self):
        with TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), physical_max=3)
            with patch.object(shell, 'continue_four_phase_dev',
                              side_effect=ValueError('synthetic continuity mismatch')):
                with self.assertRaisesRegex(ValueError, 'continuity mismatch'):
                    self.run_shell(args)
            result = _read(args['campaign_output'] / 'CAMPAIGN_PROGRESS.json')
            self.assertEqual(result['status'], 'STOPPED_CONTINUATION_ERROR')
            self.assertEqual(len(result['completed']), 1)
            self.assertEqual(result['physical_model_starts'], 2)
            self.assertEqual(len(args['model_ledger'].selected_functions), 1)
            self.assertEqual(result['global_budget']['profile'],
                             GLOBAL_ONLY_DEV_PROFILE)
            self.assertEqual((args['campaign_output'] /
                              'CAMPAIGN_PROGRESS.json').stat().st_mode & 0o777,
                             0o600)


if __name__ == '__main__':
    unittest.main()
