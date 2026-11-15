"""Provider-free comparison of two existing first-pass product selectors."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools')]

from dev_no_k_three_function_gate import make_public_fixture
from vulnerabilityanalysis.workflow import run_phase1
from dev_selection_order_ab import compare_run


class SelectionOrderABTests(unittest.TestCase):
    def _run(self, root: Path) -> Path:
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        return run_phase1(artifact, root / 'runs', target_repository=repo,
                          direction_plan=plan,
                          selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')

    def test_same_pinned_pool_and_plan_drive_two_complete_orders(self):
        with TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            report = compare_run(run)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['input_validation']['pool_unique_functions'], 3)
            self.assertEqual(report['input_validation']['direction_count'], 1)
            self.assertEqual(report['arms']['SCORE']['unique_functions'], 3)
            self.assertEqual(report['arms']['FBV2_FIRST_PASS_UNIQUE_DEV']['unique_functions'], 3)
            self.assertEqual(set(report['arms']['SCORE']['order']),
                             {'fn-a', 'fn-b', 'fn-c'})
            self.assertEqual(set(report['arms']['FBV2_FIRST_PASS_UNIQUE_DEV']['order']),
                             {'fn-a', 'fn-b', 'fn-c'})
            self.assertEqual(report['arms']['FBV2_FIRST_PASS_UNIQUE_DEV']['order'][0],
                             json.loads((run / 'selection.json').read_text())['function_id'])
            self.assertEqual(report['cost']['model_calls'], 0)
            self.assertEqual(report['cost']['target_runs'], 0)
            self.assertEqual(report['cost']['fuzz_seconds'], 0)
            self.assertEqual(report['input_validation']['source_identity_scope'],
                             'CURRENT_CHECKOUT_ONLY_PHASE1_BYTES_UNPROVEN')
            self.assertEqual(report['comparison']['legacy_k_reference'], 24)
            repeated = compare_run(run)
            self.assertEqual(
                {key: arm['order_sha256'] for key, arm in report['arms'].items()},
                {key: arm['order_sha256'] for key, arm in repeated['arms'].items()})

    def test_changed_pinned_plan_is_rejected(self):
        with TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            with (run / 'direction_plan.json').open('ab') as stream:
                stream.write(b' ')
            with self.assertRaisesRegex(ValueError, 'Direction plan'):
                compare_run(run)

    def test_pool_id_duplicate_is_rejected(self):
        with TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            pool_path = run / 'function_pool.json'
            pool = json.loads(pool_path.read_text())
            pool.append(pool[0])
            pool_path.write_text(json.dumps(pool) + '\n')
            with self.assertRaisesRegex(ValueError, 'Pool'):
                compare_run(run)


if __name__ == '__main__':
    unittest.main()
