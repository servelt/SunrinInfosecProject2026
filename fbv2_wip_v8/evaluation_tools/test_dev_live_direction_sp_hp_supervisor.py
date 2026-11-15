"""Provider-free fail-first checks for the public-toy live boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dev_live_direction_sp_hp_supervisor as boundary  # noqa: E402


class LiveToyBoundaryTests(unittest.TestCase):
    def test_explicit_completion_predicate_can_accept_one_turn_receipt(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            child = {'status': 'SYNTHETIC_ONE_TURN',
                     'physical': 1, 'logical': 1, 'retries': 0}
            script = ('import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                      '(p/sys.argv[2]).write_text(json.dumps(json.loads(sys.argv[3])))')
            command = [sys.executable, '-I', '-B', '-c', script,
                       str(output), boundary.CHILD_NAME, json.dumps(child)]
            identity = output.stat()
            result = boundary.supervise_command(
                command, output, wall_seconds=3,
                expected_output_identity=(identity.st_dev, identity.st_ino),
                completion_predicate=lambda row, _fd, _out: row == child)
            self.assertEqual(result['status'], 'CHILD_EXITED_COMPLETE')

    def test_expected_output_inode_blocks_launch_before_child(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            marker = output / 'launched.txt'
            command = [sys.executable, '-I', '-B', '-c',
                       'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("yes")',
                       str(marker)]
            with self.assertRaisesRegex(ValueError, 'inode changed before launch'):
                boundary.supervise_command(command, output, wall_seconds=3,
                    expected_output_identity=(0, 0))
            self.assertFalse(marker.exists())

    def test_read_only_preflight_can_repeat_with_fresh_cache(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            previous_prefix = sys.pycache_prefix
            previous_env = os.environ.get('PYTHONPYCACHEPREFIX')
            seen = []

            def inspect_cache(_row):
                cache = Path(sys.pycache_prefix)
                self.assertTrue(cache.is_dir())
                self.assertFalse(any(cache.iterdir()))
                self.assertEqual(os.environ['PYTHONPYCACHEPREFIX'], str(cache))
                seen.append(cache)
                return {'status': 'PREFLIGHT_PASS_NO_MODEL_CALL'}

            with patch.object(boundary, '_offline_preflight_body',
                              side_effect=inspect_cache):
                for _ in range(2):
                    self.assertEqual(
                        boundary.offline_preflight({'output_dir': str(output)})['status'],
                        'PREFLIGHT_PASS_NO_MODEL_CALL')
            self.assertEqual(len(set(seen)), 2)
            self.assertTrue(all(not cache.exists() for cache in seen))
            self.assertEqual(sys.pycache_prefix, previous_prefix)
            self.assertEqual(os.environ.get('PYTHONPYCACHEPREFIX'), previous_env)

    def test_byte_change_breaks_source_pin(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'one.py').write_text('x = 1\n')
            expected = boundary.tree_digest(root, {'.py'})
            boundary.require_tree_digest(root, {'.py'}, expected)
            (root / 'one.py').write_text('x = 2\n')
            with self.assertRaisesRegex(ValueError, 'source tree changed'):
                boundary.require_tree_digest(root, {'.py'}, expected)

    def test_symlink_and_unreviewed_executable_are_rejected(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'one.py').write_text('x = 1\n')
            (root / 'alias.py').symlink_to(root / 'one.py')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                boundary.tree_digest(root, {'.py'})
            (root / 'alias.py').unlink()
            (root / 'legacy.pyc').write_bytes(b'bytes')
            with self.assertRaisesRegex(ValueError, 'bytecode'):
                boundary.tree_digest(root, {'.py'})

    def test_spec_hash_fails_before_any_source_import(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'spec.json'
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'spec pin'):
                boundary.load_spec(path, '0' * 64)

    def test_physical_wall_stops_hung_child_without_model(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            started = time.monotonic()
            result = boundary.supervise_command(
                [sys.executable, '-I', '-B', '-c', 'import time; time.sleep(20)'],
                output, wall_seconds=0.2)
            self.assertEqual(result['status'], 'STOPPED_WALL_LIMIT')
            self.assertLess(time.monotonic() - started, 10)
            self.assertTrue((output / boundary.RESULT_NAME).is_file())

    def test_cleanup_exception_still_records_incomplete_boundary(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            sys.path.insert(0, str(boundary.ROOT / 'evaluation_tools'))
            import blind2_runner_draft as runner
            with patch.object(runner, '_request_guard_cleanup',
                              side_effect=RuntimeError('synthetic cleanup failure')):
                result = boundary.supervise_command(
                    [sys.executable, '-I', '-B', '-c', 'import time; time.sleep(20)'],
                    output, wall_seconds=0.2, runner=runner)
            self.assertEqual(result['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(result['cleanup_error_type'], 'RuntimeError')

    def test_zero_exit_without_child_evidence_is_inconclusive(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            result = boundary.supervise_command(
                [sys.executable, '-I', '-B', '-c', 'pass'],
                output, wall_seconds=3)
            self.assertEqual(result['status'], 'CHILD_EXITED_INCONCLUSIVE')

    def test_fifo_evidence_is_rejected_without_blocking(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            os.mkfifo(output / boundary.LEDGER_NAME)
            script = (
                'import json,os,sys; sys.path.insert(0,sys.argv[1]); '
                'import dev_live_direction_sp_hp_supervisor as b; '
                'fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY); '
                'print(json.dumps(b._evidence_at(fd,__import__("pathlib").Path(sys.argv[2]),b.LEDGER_NAME)))')
            result = subprocess.run(
                [sys.executable, '-I', '-B', '-c', script,
                 str(Path(boundary.__file__).parent), str(output)],
                text=True, capture_output=True, timeout=3, check=True)
            self.assertIsNone(json.loads(result.stdout)['sha256'])

    def test_fifo_child_result_is_inconclusive_without_blocking(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'private'
            output.mkdir(mode=0o700)
            script = (
                'import json,pathlib,sys; sys.path.insert(0,sys.argv[1]); '
                'import dev_live_direction_sp_hp_supervisor as b; '
                'out=pathlib.Path(sys.argv[2]); '
                'cmd=[sys.executable,"-I","-B","-c",'
                '"import os,sys;os.mkfifo(sys.argv[1])",str(out/b.CHILD_NAME)]; '
                'print(json.dumps(b.supervise_command(cmd,out,wall_seconds=3)))')
            result = subprocess.run(
                [sys.executable, '-I', '-B', '-c', script,
                 str(Path(boundary.__file__).parent), str(output)],
                text=True, capture_output=True, timeout=8, check=True)
            self.assertEqual(json.loads(result.stdout)['status'],
                             'CHILD_EXITED_INCONCLUSIVE')

    def test_fresh_prefix_ignores_stale_source_bytecode_even_under_B(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'sample.py'
            source.write_text('VALUE = 1\n')
            old_prefix = sys.pycache_prefix
            old_env = os.environ.get('PYTHONPYCACHEPREFIX')
            try:
                sys.pycache_prefix = None
                os.environ.pop('PYTHONPYCACHEPREFIX', None)
                py_compile.compile(str(source), doraise=True)
                mtime = source.stat().st_mtime_ns
                source.write_text('VALUE = 2\n')
                os.utime(source, ns=(mtime, mtime))

                def loaded_value() -> int:
                    spec = importlib.util.spec_from_file_location('sample', source)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    return module.VALUE

                self.assertEqual(loaded_value(), 1, '-B can still read old pyc')
                output = root / 'private'
                output.mkdir(mode=0o700)
                boundary._fresh_cache(output, 'new_cache')
                self.assertEqual(loaded_value(), 2)
            finally:
                sys.pycache_prefix = old_prefix
                if old_env is None:
                    os.environ.pop('PYTHONPYCACHEPREFIX', None)
                else:
                    os.environ['PYTHONPYCACHEPREFIX'] = old_env

    def test_live_launch_requires_external_source_pin(self):
        driver = Path(boundary.__file__)
        direct = subprocess.run(
            [sys.executable, '-I', '-B', str(driver), '--run-live',
             '/missing/spec.json', '0' * 64], capture_output=True,
            text=True, timeout=5)
        self.assertNotEqual(direct.returncode, 0)
        self.assertIn('external source pin', direct.stderr)
        wrong = subprocess.run(
            [sys.executable, '-I', '-B', '-c', boundary.INLINE_BOOTSTRAP,
             str(driver), '0' * 64, '--preflight-only',
             '/missing/spec.json', '0' * 64], capture_output=True,
            text=True, timeout=5)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn('bootstrap source changed', wrong.stderr)

    def test_supervisor_evidence_stays_on_original_directory_inode(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, moved, decoy = root / 'private', root / 'moved', root / 'decoy'
            output.mkdir(mode=0o700)
            decoy.mkdir(mode=0o700)
            command = [sys.executable, '-I', '-B', '-c',
                       ('import os,sys; os.rename(sys.argv[1],sys.argv[2]); '
                        'os.symlink(sys.argv[3],sys.argv[1])'),
                       str(output), str(moved), str(decoy)]
            result = boundary.supervise_command(command, output, wall_seconds=3)
            self.assertEqual(result['status'], 'STOPPED_OUTPUT_IDENTITY_CHANGED')
            self.assertTrue((moved / boundary.RESULT_NAME).is_file())
            self.assertFalse((decoy / boundary.RESULT_NAME).exists())


if __name__ == '__main__':
    unittest.main()
