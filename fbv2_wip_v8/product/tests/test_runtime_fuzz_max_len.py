"""The evaluation may pin libFuzzer input length without changing defaults."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.runtime import fuzz_locally


class FuzzMaxLenTests(unittest.TestCase):
    def test_explicit_eight_mib_is_forwarded_and_default_is_unchanged(self):
        observed = []
        def fake_run(argv, **kwargs):
            observed.append(argv)
            return subprocess.CompletedProcess(argv, 0, '', '')
        with tempfile.TemporaryDirectory() as directory, patch(
                'vulnerabilityanalysis.runtime._guarded_run', fake_run):
            root = Path(directory)
            fuzz_locally(root / 'binary', root / 'corpus1', seconds=1,
                         max_len=8 * 1024 * 1024)
            fuzz_locally(root / 'binary', root / 'corpus2', seconds=1)
        self.assertIn('-max_len=8388608', observed[0])
        self.assertFalse(any(part.startswith('-max_len=') for part in observed[1]))

    def test_invalid_max_len_is_rejected_without_launch(self):
        with tempfile.TemporaryDirectory() as directory, patch(
                'vulnerabilityanalysis.runtime._guarded_run') as run:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'max_len'):
                fuzz_locally(root / 'binary', root / 'corpus', seconds=1,
                             max_len=0)
            run.assert_not_called()

    def test_opt_in_guarded_runner_uses_same_fuzz_command_and_default_is_unchanged(self):
        observed = []
        def injected(argv, **kwargs):
            observed.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, '', 'cov: 1 ft: 1\n')
        with tempfile.TemporaryDirectory() as directory, patch(
                'vulnerabilityanalysis.runtime._guarded_run') as default:
            root = Path(directory)
            result = fuzz_locally(root / 'binary', root / 'corpus', seconds=2,
                                  single_process=True, guarded_runner=injected)
            default.assert_not_called()
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(observed[0][1]['timeout'], 17)
        self.assertEqual(observed[0][1]['cwd'].name, 'corpus')
        self.assertIn('-max_total_time=2', observed[0][0])
        self.assertIn('-print_final_stats=1', observed[0][0])
