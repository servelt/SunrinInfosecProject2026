"""Provider-free opt-in physical accounting at both SP targeted call sites."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.runtime import PhysicalFuzzBudgetPending, PhysicalFuzzStop
from vulnerabilityanalysis.scan import scan_selected
import vulnerabilityanalysis.scan as scan_module
from vulnerabilityanalysis.workflow import run_phase1

from test_direction_plan import fixture
from test_poc_feedback_scan_dev import SOURCE, _Provider, _verifier
from test_sp_queue_first_dev import _Qualification


class _TwoSpProvider(_Provider):
    async def generate(self, request):
        result = await super().generate(request)
        if request.role == 'sp_generation':
            another = dict(result['suspicious_points'][0])
            another['vulnerability_hypothesis'] = 'second independent input path'
            result['suspicious_points'].append(another)
        return result


class TargetedPhysicalFuzzDevTest(unittest.TestCase):
    def _scan(self, root: Path, *, revisions: int, fuzz_result,
              two_candidates: bool = False,
              fail_window_receipt: bool = False,
              fail_allocation_receipt: bool = False):
        artifact, repo, plan = fixture(root)
        (repo / 'target.c').write_text(SOURCE)
        run = run_phase1(
            artifact, repo / 'runs', target_repository=repo,
            direction_plan=plan,
            selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        binary = repo / 'target.bin'
        binary.write_bytes(b'fixture only')
        qualification = _Qualification(repo, repo / 'fuzz.c', binary)
        provider = _TwoSpProvider() if two_candidates else _Provider()
        runner = lambda _command, **_kwargs: None
        observed = []
        fail_next_window = [False]
        original_open = Path.open
        original_write_json = scan_module.write_json

        def checked_open(path, *args, **kwargs):
            if (fail_window_receipt and fail_next_window[0] and
                    path.name == 'stage_windows.jsonl' and
                    args and args[0] == 'a'):
                raise OSError('synthetic fuzz receipt write failure')
            return original_open(path, *args, **kwargs)

        def checked_write_json(path, value):
            if (fail_allocation_receipt and Path(path).name == 'fuzz_allocation.json'
                    and value.get('allocated_seconds', 0) > 0):
                raise OSError('synthetic fuzz allocation receipt write failure')
            return original_write_json(path, value)

        def targeted(*_args, **kwargs):
            observed.append(kwargs.get('guarded_runner'))
            if isinstance(fuzz_result, BaseException):
                fail_next_window[0] = True
                raise fuzz_result
            if callable(fuzz_result):
                return fuzz_result(len(observed))
            return fuzz_result

        with (patch.object(AgentPipeline, 'verify_sp', _verifier),
              patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                    _Qualification),
              patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                    return_value=True),
              patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                    side_effect=targeted),
              patch('vulnerabilityanalysis.scan.write_json',
                    side_effect=checked_write_json),
              patch.object(Path, 'open', checked_open)):
            error = None
            try:
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    target_binary=binary,
                    official_qualification=qualification,
                    run_command=['/usr/bin/true', '{input}'],
                    candidate_budget_policy=('QUEUE_FIRST_DEV' if two_candidates
                                             else 'DRAIN_RANKED_DEV'),
                    max_candidates=1,
                    sp_llm_call_limit=6 if two_candidates else 4,
                    targeted_fuzzer_binary=binary,
                    targeted_fuzz_seconds=1,
                    fuzz_budget_seconds=2 if two_candidates else 1,
                    pov_feedback_revisions=revisions,
                    hallucination_prevent='off',
                    targeted_fuzz_guarded_runner=runner))
            except BaseException as exc:
                error = exc
        return run, observed, runner, error

    def test_pre_revision_sp_path_forwards_runner_and_marks_budget_pending(self):
        with TemporaryDirectory() as temp:
            run, observed, runner, error = self._scan(
                Path(temp), revisions=0,
                fuzz_result=PhysicalFuzzBudgetPending('insufficient reservation'))
            self.assertIsNone(error)
            self.assertEqual(observed, [runner])
            rows = [json.loads(line) for line in
                    (run / 'logs/stage_windows.jsonl').read_text().splitlines()]
            self.assertEqual([row['status'] for row in rows if row['kind'] == 'FUZZ'],
                             ['PENDING_SHARED_PHYSICAL_BUDGET'])

    def test_post_revision_sp_path_forwards_runner_and_propagates_stop(self):
        with TemporaryDirectory() as temp:
            stopped = PhysicalFuzzStop('STOPPED_PHYSICAL_CAP_UNPROVEN',
                                       'measured overrun')
            run, observed, runner, error = self._scan(
                Path(temp), revisions=1, fuzz_result=stopped)
            self.assertIs(error, stopped)
            self.assertEqual(observed, [runner])
            rows = [json.loads(line) for line in
                    (run / 'logs/stage_windows.jsonl').read_text().splitlines()]
            self.assertEqual([row['status'] for row in rows if row['kind'] == 'FUZZ'],
                             ['STOPPED_PHYSICAL_CAP_UNPROVEN'])

    def test_opt_in_rejects_unmetered_global_path_before_model_call(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(
                artifact, repo / 'runs', target_repository=repo,
                direction_plan=plan,
                selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            binary = repo / 'target.bin'
            binary.write_bytes(b'fixture only')
            provider = _Provider()
            with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        _Qualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True)):
                with self.assertRaisesRegex(ValueError, 'serial official development'):
                    asyncio.run(scan_selected(
                        run, provider, target_repository=repo,
                        target_binary=binary,
                        official_qualification=_Qualification(
                            repo, repo / 'fuzz.c', binary),
                        candidate_budget_policy='DRAIN_RANKED_DEV',
                        max_candidates=1,
                        targeted_fuzzer_binary=binary,
                        targeted_fuzz_seconds=1, fuzz_budget_seconds=1,
                        global_fuzz_enabled=True,
                        hallucination_prevent='off',
                        targeted_fuzz_guarded_runner=lambda *_a, **_k: None))
            self.assertEqual(provider.requests, [])

    def test_combined_sp_hp_opt_in_rejects_either_unmetered_path(self):
        for missing in ('SP', 'HP'):
            with self.subTest(missing=missing), TemporaryDirectory() as temp:
                artifact, repo, plan = fixture(Path(temp))
                run = run_phase1(
                    artifact, repo / 'runs', target_repository=repo,
                    direction_plan=plan,
                    selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
                binary = repo / 'target.bin'
                binary.write_bytes(b'fixture only')
                provider = _Provider()
                with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                            _Qualification),
                      patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                            return_value=True)):
                    with self.assertRaisesRegex(ValueError, 'guarded .* requires'):
                        asyncio.run(scan_selected(
                            run, provider, target_repository=repo,
                            target_binary=binary,
                            official_qualification=_Qualification(
                                repo, repo / 'fuzz.c', binary),
                            candidate_budget_policy='DRAIN_RANKED_DEV',
                            max_candidates=1,
                            targeted_fuzzer_binary=binary,
                            targeted_fuzz_seconds=1, assertion_fuzz_seconds=1,
                            fuzz_budget_seconds=2, global_fuzz_enabled=False,
                            targeted_fuzz_guarded_runner=(
                                None if missing == 'SP' else lambda *_a, **_k: None),
                            hp_guided_guarded_runner=(
                                None if missing == 'HP' else lambda *_a, **_k: None)))
                self.assertEqual(provider.requests, [])

    def test_combined_sp_hp_opt_in_accepts_both_runners(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            (repo / 'target.c').write_text(SOURCE)
            run = run_phase1(
                artifact, repo / 'runs', target_repository=repo,
                direction_plan=plan,
                selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            binary = repo / 'target.bin'
            binary.write_bytes(b'fixture only')
            provider = _Provider()
            sp_runner = lambda _command, **_kwargs: None
            hp_runner = lambda _command, **_kwargs: None
            observed = []

            def fake_targeted(*_args, **kwargs):
                observed.append(kwargs.get('guarded_runner'))
                return None

            with (patch.object(AgentPipeline, 'verify_sp', _verifier),
                  patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                        _Qualification),
                  patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                        return_value=True),
                  patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                        side_effect=fake_targeted)):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    target_binary=binary,
                    official_qualification=_Qualification(
                        repo, repo / 'fuzz.c', binary),
                    run_command=['/usr/bin/true', '{input}'],
                    candidate_budget_policy='DRAIN_RANKED_DEV',
                    max_candidates=1, sp_llm_call_limit=4,
                    targeted_fuzzer_binary=binary,
                    targeted_fuzz_seconds=1, assertion_fuzz_seconds=1,
                    fuzz_budget_seconds=2, global_fuzz_enabled=False,
                    hallucination_prevent='off',
                    targeted_fuzz_guarded_runner=sp_runner,
                    hp_guided_guarded_runner=hp_runner))
            self.assertTrue(provider.requests)
            self.assertEqual(observed, [sp_runner])
            self.assertTrue((run / 'scan.json').is_file())

    def test_two_selected_sp_jobs_run_serially_and_stop_before_second_launch(self):
        with TemporaryDirectory() as temp:
            stopped = PhysicalFuzzStop('STOPPED_CLEANUP_INCOMPLETE',
                                       'first child cleanup failed')

            def first_fatal(index):
                if index == 1:
                    time.sleep(1.0)
                    raise stopped
                return None

            run, observed, runner, error = self._scan(
                Path(temp), revisions=0, fuzz_result=first_fatal,
                two_candidates=True)
            self.assertIs(error, stopped)
            self.assertEqual(observed, [runner])
            rows = [json.loads(line) for line in
                    (run / 'logs/stage_windows.jsonl').read_text().splitlines()]
            self.assertEqual([row['status'] for row in rows if row['kind'] == 'FUZZ'],
                             ['STOPPED_CLEANUP_INCOMPLETE'])

    def test_two_selected_sp_jobs_both_complete_serially(self):
        with TemporaryDirectory() as temp:
            active = 0
            maximum_active = 0

            def succeed(_index):
                nonlocal active, maximum_active
                active += 1
                maximum_active = max(maximum_active, active)
                time.sleep(0.05)
                active -= 1
                return None

            _run, observed, runner, error = self._scan(
                Path(temp), revisions=0, fuzz_result=succeed,
                two_candidates=True)
            self.assertIsNone(error)
            self.assertEqual(observed, [runner, runner])
            self.assertEqual(maximum_active, 1)

    def test_fatal_physical_stop_wins_over_fuzz_window_write_error(self):
        with TemporaryDirectory() as temp:
            stopped = PhysicalFuzzStop('STOPPED_PHYSICAL_CAP_UNPROVEN',
                                       'measured overrun')
            _run, observed, runner, error = self._scan(
                Path(temp), revisions=0, fuzz_result=stopped,
                fail_window_receipt=True)
            self.assertEqual(observed, [runner])
            self.assertIs(error, stopped)
            self.assertIn('fuzz window receipt failed: OSError',
                          error.__notes__)

    def test_allocation_receipt_failure_never_starts_either_sp_path(self):
        for revisions in (0, 1):
            with self.subTest(revisions=revisions), TemporaryDirectory() as temp:
                _run, observed, _runner, error = self._scan(
                    Path(temp), revisions=revisions, fuzz_result=None,
                    fail_allocation_receipt=True)
                self.assertIsInstance(error, OSError)
                self.assertIn('synthetic fuzz allocation receipt', str(error))
                self.assertEqual(observed, [])


if __name__ == '__main__':
    unittest.main()
