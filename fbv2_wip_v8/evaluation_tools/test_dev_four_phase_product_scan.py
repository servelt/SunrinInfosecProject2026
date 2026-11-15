"""Provider-free toy: one function scanned under two distinct Directions."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools')]

from dev_fbv2_four_phase_worklist import build_from_pinned_run  # noqa: E402
from dev_four_phase_budget_progress import freeze_pending_budget  # noqa: E402
from dev_global_request_ledger import (DevelopmentBudget,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)  # noqa: E402
from dev_no_k_three_function_gate import make_public_fixture  # noqa: E402
from test_dev_multifunction_global_scan import _Provider, _Qualification  # noqa: E402
from vulnerabilityanalysis.scan import scan_selected  # noqa: E402
import vulnerabilityanalysis.scan as scan_module  # noqa: E402
from vulnerabilityanalysis.workflow import (continue_four_phase_dev,
                                             run_phase1, start_four_phase_dev,
                                             validate_four_phase_dev_selection)  # noqa: E402


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def replace_final_scan(run: Path, changes: dict) -> None:
    """Synthetic finished Scan with a matching marker, not a stale SHA stop."""
    scan_path = run / 'scan.json'
    scan_path.write_text(json.dumps({**read(scan_path), **changes}, sort_keys=True) + '\n')
    marker_path = run / 'four_phase_scan_complete.json'
    marker = read(marker_path)
    marker['scan_sha256'] = hashlib.sha256(scan_path.read_bytes()).hexdigest()
    marker_path.write_text(json.dumps(marker, sort_keys=True) + '\n')


class FourPhaseProductScanTests(unittest.TestCase):
    def fixture(self, root: Path, physical_max: int):
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        proposal = read(plan)
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
        first_run = start_four_phase_dev(
            source, worklist_path,
            hashlib.sha256(worklist_path.read_bytes()).hexdigest(),
            repo / 'runs' / 'four-phase-first')
        binary = repo / 'target.bin'
        binary.write_bytes(b'public synthetic binary; never executed\n')
        qualification = _Qualification(repo, repo / 'fuzz.c', binary)
        ledger = DevelopmentRequestLedger.create(DevelopmentBudget(
            physical_max=physical_max, logical_max=physical_max,
            retries_max=0, wall_seconds=60, initial_starts_required=1,
            profile=GLOBAL_ONLY_DEV_PROFILE), root / 'MODEL_LEDGER.json')
        ledger.register_direction('public-direction')
        digest = 'a' * 64
        ledger.begin_turn('public-direction', 'direction_generator', digest)
        ledger.start_attempt(digest)
        ledger.finish_attempt(completed=True)
        return first_run, repo, binary, qualification, ledger

    def scan(self, run, repo, binary, qualification, ledger):
        item = read(run / 'work_item.json')
        provider = _Provider(ledger, item['work_item_id'])
        with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                    _Qualification),
              patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                    return_value=True),
              patch('vulnerabilityanalysis.scan.execute_poc',
                    side_effect=AssertionError('Target execution is forbidden'))):
            asyncio.run(scan_selected(
                run, provider, target_repository=repo, target_binary=binary,
                official_qualification=qualification,
                external_turn_budget=ledger, external_multifunction_dev=True,
                candidate_budget_policy='QUEUE_FIRST_DEV', max_candidates=1,
                targeted_fuzz_seconds=0, global_fuzz_enabled=False,
                hallucination_prevent='off'))
        return provider

    def test_two_direction_jobs_make_distinct_scan_evidence(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=3)
            first = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(first['work_item_id']))
            self.assertEqual(self.scan(run, repo, binary, qualification,
                                       ledger).calls, ['sp_generation'])
            ledger.mark_scan_recorded(first['work_item_id'])
            second_run = continue_four_phase_dev(run,
                                                 run.parent / 'four-phase-second')
            second = read(second_run / 'work_item.json')
            self.assertEqual(first['function_id'], second['function_id'])
            self.assertNotEqual(first['direction_id'], second['direction_id'])
            self.assertNotEqual(first['work_item_id'], second['work_item_id'])
            pool = read(second_run / 'function_pool.json')
            self.assertTrue(next(row for row in pool if row['direction_id'] ==
                                 first['direction_id'] and row['function_id'] ==
                                 first['function_id'])['analyzed'])
            self.assertFalse(read(second_run / 'selection.json')['analyzed'])
            self.assertTrue(ledger.select_function(second['work_item_id']))
            self.assertEqual(self.scan(second_run, repo, binary, qualification,
                                       ledger).calls, ['sp_generation'])
            for folder, item in ((run, first), (second_run, second)):
                scan = read(folder / 'scan.json')
                self.assertEqual(scan['four_phase_work_item_id'], item['work_item_id'])
                self.assertEqual(scan['selected_direction_id'], item['direction_id'])
                self.assertEqual(scan['four_phase'], 'small/new')
            self.assertEqual((ledger.logical, ledger.physical), (3, 3))

    def test_work_item_tamper_and_budget_stop_before_request(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=2)
            first = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(first['work_item_id']))
            self.scan(run, repo, binary, qualification, ledger)
            ledger.mark_scan_recorded(first['work_item_id'])
            second_run = continue_four_phase_dev(run,
                                                 run.parent / 'four-phase-second')
            second = read(second_run / 'work_item.json')
            self.assertFalse(ledger.select_function(second['work_item_id']))
            progress = freeze_pending_budget(
                second_run, ledger, Path(tmp) / 'PENDING_WORKLIST.json')
            self.assertEqual(progress['phase_counts']['small/new'],
                             {'completed': 1, 'pending': 1})
            self.assertEqual(progress['phase_counts']['big/new']['completed'], 0)
            self.assertEqual(progress['phase_semantics_status'],
                             'SCHEDULED_PHASES_RECOMPUTED_CALLER_SOURCE_PIN')
            self.assertIn('big/new', progress['starved_phases'])
            self.assertEqual(len(progress['pending']), 5)
            self.assertTrue(all(row['state'] == 'PENDING_BUDGET'
                                for row in progress['pending']))
            with self.assertRaises(ValueError):
                self.scan(second_run, repo, binary, qualification, ledger)
            self.assertFalse((second_run / 'scan.json').exists())
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))
            (second_run / 'work_item.json').write_text(json.dumps(
                {**second, 'direction_id': 'tampered'}) + '\n')
            with self.assertRaises(ValueError):
                validate_four_phase_dev_selection(second_run)

    def test_worklist_tamper_stops_before_first_model_request(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=2)
            item = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(item['work_item_id']))
            worklist = run / 'four_phase_worklist.json'
            worklist.write_bytes(worklist.read_bytes() + b' ')
            with self.assertRaises(ValueError):
                self.scan(run, repo, binary, qualification, ledger)
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))
            self.assertFalse((run / 'scan.json').exists())

    def test_omitted_work_item_with_new_sha_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, _, _, _, _ = self.fixture(root, physical_max=2)
            source = Path(read(run / 'run.json')['source_phase1_run'])
            worklist = read(run / 'four_phase_worklist.json')
            removed = worklist['worklist'].pop()
            worklist['counts']['direction_function_jobs'] -= 1
            worklist['counts']['phases'][removed['phase']] -= 1
            replacement = root / 'OMITTED_WORKLIST.json'
            replacement.write_text(json.dumps(worklist, sort_keys=True) + '\n')
            with self.assertRaisesRegex(ValueError, 'omitted a Pool pair'):
                start_four_phase_dev(source, replacement,
                                     hashlib.sha256(replacement.read_bytes()).hexdigest(),
                                     source.parent / 'omitted-work-item')

    def test_phase_flip_with_new_sha_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, _, _, _, _ = self.fixture(root, physical_max=2)
            source = Path(read(run / 'run.json')['source_phase1_run'])
            worklist = read(run / 'four_phase_worklist.json')
            big = next(row for row in worklist['worklist'] if row['phase'] == 'big/new')
            big['phase'] = 'big/re'
            worklist['worklist'].sort(key=lambda row: worklist['phase_order'].index(
                row['phase']))
            worklist['counts']['phases']['big/new'] -= 1
            worklist['counts']['phases']['big/re'] += 1
            replacement = root / 'FLIPPED_PHASE.json'
            replacement.write_text(json.dumps(worklist, sort_keys=True) + '\n')
            with self.assertRaisesRegex(ValueError, 'scheduled phase'):
                start_four_phase_dev(source, replacement,
                                     hashlib.sha256(replacement.read_bytes()).hexdigest(),
                                     source.parent / 'flipped-phase')

    def test_source_workers_changed_after_worklist_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, _, _, _, _ = self.fixture(root, physical_max=2)
            source = Path(read(run / 'run.json')['source_phase1_run'])
            workers = source / 'workers.json'
            workers.write_bytes(workers.read_bytes() + b' ')
            worklist = run / 'four_phase_worklist.json'
            with self.assertRaisesRegex(ValueError, 'not bound'):
                start_four_phase_dev(source, worklist,
                                     hashlib.sha256(worklist.read_bytes()).hexdigest(),
                                     source.parent / 'changed-workers')

    def test_invented_unassigned_pair_and_count_tamper_are_rejected(self):
        for changed in ('invented_pair', 'wrong_count'):
            with self.subTest(changed=changed), TemporaryDirectory() as tmp:
                root = Path(tmp)
                run, _, _, _, _ = self.fixture(root, physical_max=2)
                source = Path(read(run / 'run.json')['source_phase1_run'])
                worklist = read(run / 'four_phase_worklist.json')
                if changed == 'invented_pair':
                    removed = worklist['worklist'].pop()
                    worklist['unassigned'].append({**removed, 'direction_id':
                                                   'invented-direction',
                                                   'reason': 'NO_DIRECT_ENTRY_PATH'})
                    worklist['counts']['direction_function_jobs'] -= 1
                    worklist['counts']['phases'][removed['phase']] -= 1
                    worklist['counts']['unassigned_records'] += 1
                    worklist['counts']['unassigned_reasons'] = {
                        'NO_DIRECT_ENTRY_PATH': 1}
                else:
                    worklist['counts']['direction_function_jobs'] += 1
                replacement = root / 'BAD_WORKLIST.json'
                replacement.write_text(json.dumps(worklist, sort_keys=True) + '\n')
                with self.assertRaises(ValueError):
                    start_four_phase_dev(source, replacement,
                                         hashlib.sha256(replacement.read_bytes()).hexdigest(),
                                         source.parent / 'bad-worklist')

    def test_pool_and_selection_correlated_tamper_stops_before_model(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=2)
            item = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(item['work_item_id']))
            pool_path = run / 'function_pool.json'
            selection_path = run / 'selection.json'
            pool = read(pool_path)
            selected = read(selection_path)
            selected['priority_reasons'].append('SYNTHETIC_UNTRUSTED_REASON')
            for row in pool:
                if ((row['direction_id'], row['function_id']) ==
                        (selected['direction_id'], selected['function_id'])):
                    row['priority_reasons'] = selected['priority_reasons']
            pool_path.write_text(json.dumps(pool, sort_keys=True, indent=2) + '\n')
            selection_path.write_text(json.dumps(selected, sort_keys=True, indent=2) + '\n')
            with self.assertRaisesRegex(ValueError, 'canonical pair transition'):
                self.scan(run, repo, binary, qualification, ledger)
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))
            self.assertFalse((run / 'scan.json').exists())

    def test_parent_scan_tamper_stops_second_work_item(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=3)
            first = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(first['work_item_id']))
            self.scan(run, repo, binary, qualification, ledger)
            ledger.mark_scan_recorded(first['work_item_id'])
            second_run = continue_four_phase_dev(run,
                                                 run.parent / 'four-phase-second')
            second = read(second_run / 'work_item.json')
            self.assertTrue(ledger.select_function(second['work_item_id']))
            scan = run / 'scan.json'
            scan.write_bytes(scan.read_bytes() + b' ')
            with self.assertRaises(ValueError):
                self.scan(second_run, repo, binary, qualification, ledger)
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))
            self.assertFalse((second_run / 'scan.json').exists())

    def test_pending_sp_or_hp_error_blocks_next_work_item(self):
        for changed in ({'pending_sp_ids': ['public-pending']},
                        {'hp_error': {'type': 'public-error'}}):
            with self.subTest(changed=changed), TemporaryDirectory() as tmp:
                run, repo, binary, qualification, ledger = self.fixture(
                    Path(tmp), physical_max=3)
                first = read(run / 'work_item.json')
                self.assertTrue(ledger.select_function(first['work_item_id']))
                self.scan(run, repo, binary, qualification, ledger)
                replace_final_scan(run, changed)
                with self.assertRaises(ValueError):
                    continue_four_phase_dev(run,
                                             run.parent / 'four-phase-second')
                self.assertEqual((ledger.logical, ledger.physical), (2, 2))

    def test_guided_physical_budget_stop_blocks_continuation_and_next_model(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=3)
            first = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(first['work_item_id']))
            self.scan(run, repo, binary, qualification, ledger)
            ledger.mark_scan_recorded(first['work_item_id'])
            second = continue_four_phase_dev(run, run.parent / 'second')
            replace_final_scan(run, {'assertion_execution': {
                'status': 'INCOMPLETE_HP_GUIDED_PHYSICAL_BUDGET',
                'guided_fuzz_statuses': {'synthetic-a':
                                         'PENDING_SHARED_PHYSICAL_BUDGET'}}})
            with self.assertRaisesRegex(ValueError, 'pending or incomplete'):
                continue_four_phase_dev(run, run.parent / 'must-not-exist')
            self.assertFalse((run.parent / 'must-not-exist').exists())
            second_record = read(second / 'run.json')
            second_record['parent_scan_sha256'] = hashlib.sha256(
                (run / 'scan.json').read_bytes()).hexdigest()
            second_record['parent_scan_terminal_sha256'] = hashlib.sha256(
                (run / 'four_phase_scan_complete.json').read_bytes()).hexdigest()
            (second / 'run.json').write_text(json.dumps(
                second_record, sort_keys=True, indent=2) + '\n')
            next_item = read(second / 'work_item.json')
            self.assertTrue(ledger.select_function(next_item['work_item_id']))
            with self.assertRaisesRegex(ValueError, 'pending or incomplete'):
                self.scan(second, repo, binary, qualification, ledger)
            self.assertFalse((second / 'scan.json').exists())
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))

    def test_provisional_scan_cannot_start_next_work_item(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=3)
            item = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(item['work_item_id']))
            actual_write = scan_module.write_json
            midflight_attempts = []

            def observed_write(path, value):
                actual_write(path, value)
                if path == run / 'scan.json' and not midflight_attempts:
                    try:
                        continue_four_phase_dev(run, run.parent / 'too-early')
                    except ValueError:
                        midflight_attempts.append('BLOCKED_BEFORE_TERMINAL_MARKER')

            with patch('vulnerabilityanalysis.scan.write_json', side_effect=observed_write):
                self.scan(run, repo, binary, qualification, ledger)
            self.assertEqual(midflight_attempts, ['BLOCKED_BEFORE_TERMINAL_MARKER'])
            self.assertFalse((run.parent / 'too-early').exists())
            self.assertTrue((run / 'four_phase_scan_complete.json').is_file())

    def test_budget_report_rejects_missing_completed_scan_marker(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self.fixture(
                Path(tmp), physical_max=2)
            first = read(run / 'work_item.json')
            self.assertTrue(ledger.select_function(first['work_item_id']))
            self.scan(run, repo, binary, qualification, ledger)
            ledger.mark_scan_recorded(first['work_item_id'])
            second = continue_four_phase_dev(run, run.parent / 'second')
            self.assertFalse(ledger.select_function(read(second / 'work_item.json')
                                                    ['work_item_id']))
            (run / 'four_phase_scan_complete.json').unlink()
            output = Path(tmp) / 'SHOULD_NOT_EXIST.json'
            with self.assertRaises(ValueError):
                freeze_pending_budget(second, ledger, output)
            self.assertFalse(output.exists())
