"""Check the original four-phase work-item shape without running a Scan."""

from __future__ import annotations

import unittest
from pathlib import Path
import tempfile

from dev_fbv2_four_phase_worklist import (build_from_pinned_run,
                                           build_phase_worklist)


def catalog(*names: str) -> dict:
    return {name: {'function_id': f'fn-{name.lower()}', 'name': name,
                   'file': 'toy.c'} for name in names}


def direction(did: str, *, entries=(), cores=(), related=(), risk='NORMAL') -> dict:
    return {'direction_id': did, 'worker_id': 'worker', 'name': did,
            'entry_functions': list(entries), 'core_functions': list(cores),
            'related_functions': list(related), 'risk_level': risk}


class FourPhaseWorklistTests(unittest.TestCase):
    def test_public_phase1_fixture_has_two_small_and_one_big(self):
        from dev_no_k_three_function_gate import make_public_fixture
        from vulnerabilityanalysis.workflow import run_phase1
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, repo, plan = make_public_fixture(root / 'fixture')
            run = run_phase1(artifact, root / 'runs', target_repository=repo,
                             direction_plan=plan,
                             selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            result = build_from_pinned_run(run)
        self.assertEqual(result['counts']['phases'], {
            'small/new': 2, 'small/re': 0, 'big/new': 1, 'big/re': 0})
        self.assertEqual(result['cost'], {
            'model_calls': 0, 'target_runs': 0, 'fuzz_seconds': 0})

    def test_overlap_is_two_direction_jobs_in_same_snapshot_phase(self):
        result = build_phase_worklist(
            catalog('A', 'B'),
            [direction('high', entries=('A',), cores=('B',), risk='HIGH'),
             direction('low', entries=('A',), cores=('B',), risk='LOW')],
            {'A': {'B'}, 'B': set()}, history={})
        jobs = [(row['phase'], row['direction_id'], row['function_id'])
                for row in result['worklist']]
        self.assertEqual(jobs, [
            ('small/new', 'high', 'fn-a'), ('small/new', 'high', 'fn-b'),
            ('small/new', 'low', 'fn-a'), ('small/new', 'low', 'fn-b')])
        self.assertEqual(result['counts']['distinct_functions_scanned_if_executed'], 2)
        self.assertEqual(result['counts']['direction_function_jobs'], 4)

    def test_prior_analysis_snapshot_enters_re_phase_even_for_same_direction(self):
        result = build_phase_worklist(
            catalog('A', 'B'),
            [direction('d1', entries=('A',), related=('B',), risk='HIGH'),
             direction('d2', entries=('A',), related=('B',), risk='LOW')],
            {'A': {'B'}, 'B': set()},
            history={'fn-a': ['d1'], 'fn-b': ['prior-other-direction']})
        self.assertEqual([(row['phase'], row['direction_id'])
                          for row in result['worklist']],
                         [('small/re', 'd1'), ('small/re', 'd2'),
                          ('big/re', 'd1'), ('big/re', 'd2')])
        self.assertEqual([(row['function_id'], row['reason'])
                          for row in result['warnings']],
                         [('fn-b', 'HISTORICAL_DIRECTION_NOT_IN_CURRENT_PLAN')])

    def test_no_entry_core_is_small_and_indirect_only_is_unassigned(self):
        result = build_phase_worklist(
            catalog('A', 'B', 'C', 'D'),
            [direction('connected', entries=('A',), related=('B', 'C')),
             direction('empty', cores=('D',), related=('C',))],
            {'A': {'B'}, 'B': set(), 'C': set(), 'D': set()},
            history={}, indirect_candidates={'connected': {'C'}})
        self.assertEqual([(row['phase'], row['function_id'])
                          for row in result['worklist']],
                         [('small/new', 'fn-a'), ('small/new', 'fn-d'),
                          ('big/new', 'fn-b')])
        self.assertEqual({(row['direction_id'], row['function_id'], row['reason'])
                          for row in result['unassigned']},
                         {('connected', 'fn-c', 'UNVERIFIED_INDIRECT_PATH'),
                          ('empty', 'fn-c', 'NO_ENTRY_FOR_BIG_POOL')})
        self.assertEqual([(row['function_id'], row['reason'])
                          for row in result['warnings']],
                         [('fn-d', 'CORE_WITHOUT_ENTRY_BFS')])
        self.assertEqual(result['counts']['distinct_catalog_functions_accounted'], 4)

    def test_indirect_candidate_omitted_from_related_keeps_direction_provenance_once(self):
        for related in ((), ('B',)):
            with self.subTest(related=related):
                result = build_phase_worklist(
                    catalog('A', 'B'),
                    [direction('d', entries=('A',), related=related)],
                    {'A': set(), 'B': set()}, history={},
                    indirect_candidates={'d': {'B'}})
                self.assertEqual([(row['phase'], row['function_id'])
                                  for row in result['worklist']],
                                 [('small/new', 'fn-a')])
                self.assertEqual(result['unassigned'], [
                    {'direction_id': 'd', 'function_id': 'fn-b',
                     'function_name': 'B',
                     'reason': 'UNVERIFIED_INDIRECT_PATH'}])
                self.assertEqual(result['counts']['distinct_catalog_functions_accounted'], 2)

    def test_core_is_small_without_direct_path_and_unlisted_reachable_is_big(self):
        result = build_phase_worklist(
            catalog('A', 'B', 'C'),
            [direction('d', entries=('A',), cores=('C',))],
            {'A': {'B'}, 'B': set(), 'C': set()}, history={})
        self.assertEqual([(row['function_id'], row['phase'])
                          for row in result['worklist']],
                         [('fn-a', 'small/new'), ('fn-c', 'small/new'),
                          ('fn-b', 'big/new')])
        self.assertEqual(result['unassigned'], [])
        self.assertEqual([(row['function_id'], row['reason'])
                          for row in result['warnings']],
                         [('fn-c', 'CORE_NOT_DIRECT_REACHABLE')])

    def test_duplicate_catalog_identity_is_rejected(self):
        duplicate = catalog('A', 'B')
        duplicate['B']['function_id'] = duplicate['A']['function_id']
        with self.assertRaisesRegex(ValueError, 'unique Catalog'):
            build_phase_worklist(duplicate, [direction('d', entries=('A',))],
                                 {}, history={})

    def test_duplicate_history_direction_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'malformed direction IDs'):
            build_phase_worklist(catalog('A'),
                                 [direction('d', entries=('A',))], {},
                                 history={'fn-a': ['d', 'd']})

    def test_same_phase_order_is_deterministic_and_unlisted_is_accounted(self):
        directions = [direction('z', entries=('B',), risk='NORMAL'),
                      direction('a', entries=('A',), risk='NORMAL')]
        first = build_phase_worklist(catalog('A', 'B', 'C'), directions,
                                     {'A': set(), 'B': set()}, history={})
        second = build_phase_worklist(catalog('A', 'B', 'C'),
                                      list(reversed(directions)),
                                      {'B': set(), 'A': set()}, history={})
        self.assertEqual(first, second)
        self.assertEqual([(row['direction_id'], row['function_id'])
                          for row in first['worklist']],
                         [('a', 'fn-a'), ('z', 'fn-b')])
        self.assertEqual([(row['function_id'], row['reason'])
                          for row in first['unassigned']],
                         [('fn-c', 'NO_DIRECTION_MEMBERSHIP')])


if __name__ == '__main__':
    unittest.main()
