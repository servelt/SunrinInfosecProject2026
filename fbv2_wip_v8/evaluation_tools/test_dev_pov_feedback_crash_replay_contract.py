"""Provider-free counterexample for PoV revision versus SP Crash replay budget.

The expected-failure test is an explicit HOLD. It becomes an unexpected
success when a separately bounded Crash validation opportunity is provided.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path.insert(0, str(PRODUCT / 'src'))

from vulnerabilityanalysis.scan import (  # noqa: E402
    record_targeted_fuzzer_observations, targeted_fuzzer_replay_plan)


SP_ID = 'sp-development-control'
CRASH_ID = 'crash-development-control'


def synthetic_observation(root: Path) -> tuple[dict, dict]:
    """Record a synthetic Crash file identity without executing a target."""
    corpus = root / 'corpus' / 'candidate' / SP_ID
    corpus.mkdir(parents=True)
    sample = corpus / 'synthetic-input.bin'
    sample.write_bytes(b'development-only-crash-marker')
    witness = {
        'observed_crash_id': CRASH_ID,
        'sha256': sha256(sample.read_bytes()).hexdigest(),
        'candidate_path': str(sample),
    }
    seed_report = {'crash_inputs': [witness], 'new_seeds': []}
    observed = record_targeted_fuzzer_observations(root, SP_ID, seed_report)
    assert observed == {CRASH_ID}
    indexed = json.loads((root / 'runtime' / 'fuzzer_crashes' /
                          f'{CRASH_ID}.json').read_text())
    return seed_report, indexed


def replay_after_povs(seed_report: dict, runtime_pov_count: int):
    """Apply scan.py's counted execution-log rule to first/revised PoVs."""
    rows = [{'sp_id': SP_ID, 'execution_log': f'runtime-{n}.json'}
            for n in range(runtime_pov_count)]
    prior_attempts = sum(row['sp_id'] == SP_ID and
                         bool(row.get('execution_log')) for row in rows)
    return targeted_fuzzer_replay_plan(
        seed_report, prior_attempts=prior_attempts, max_attempts=2)


class PoVFeedbackCrashReplayContractTests(unittest.TestCase):
    def test_two_pov_runtimes_keep_crash_observed_but_pending(self):
        with TemporaryDirectory() as tmp:
            seed_report, indexed = synthetic_observation(Path(tmp))
            selected, pending = replay_after_povs(seed_report, 2)
            self.assertEqual(indexed['status'],
                             'PENDING_RUNTIME_REPLAY_AND_TRIAGE')
            self.assertEqual(indexed['observations'][0]['source'], 'SP_FUZZER')
            self.assertIsNone(indexed['independent_runtime_crash_artifact'])
            self.assertEqual(selected, [])
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['observed_crash_id'], CRASH_ID)
            self.assertEqual(pending[0]['reason'], 'RUNTIME_ATTEMPT_LIMIT')

    def test_one_pov_runtime_control_still_has_replay_opportunity(self):
        with TemporaryDirectory() as tmp:
            seed_report, _ = synthetic_observation(Path(tmp))
            selected, pending = replay_after_povs(seed_report, 1)
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]['observed_crash_id'], CRASH_ID)
            self.assertEqual(pending, [])

    @unittest.expectedFailure
    def test_hold_independent_crash_replay_after_revision(self):
        """Desired contract: two PoV runtimes cannot erase Crash validation."""
        with TemporaryDirectory() as tmp:
            seed_report, _ = synthetic_observation(Path(tmp))
            selected, _pending = replay_after_povs(seed_report, 2)
            self.assertEqual([row['observed_crash_id'] for row in selected],
                             [CRASH_ID])


if __name__ == '__main__':
    unittest.main()
