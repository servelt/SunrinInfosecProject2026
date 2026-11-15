"""No-model physical-boundary tests for the public-toy HP development CLI."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import blind2_runner_draft as old_runner
import blind3_hp_supervised_live_dev as mod
from blind3_hp_iteration_live_dev import LiveHPPolicy, _scan_options_digest
from test_blind3_hp_iteration_live_dev import approved_scan_options, pinned_contract


PRODUCT = (Path(__file__).resolve().parents[1] / "product")


def spec_fixture(root: Path) -> tuple[Path, str, Path]:
    contract, contract_sha, _ = pinned_contract(root)
    output = root / 'supervised'
    output.mkdir(mode=0o700)
    row = {
        'kind': 'BLIND3_HP_SUPERVISED_DEV_V1',
        'contract_path': str(contract), 'contract_sha256': contract_sha,
        'output_dir': str(output), 'product_root': str(PRODUCT),
        'product_source_sha256': mod._source_digest(PRODUCT),
        'evaluation_sha256': {name: mod.sha(mod.HERE / name)
                              for name in (*mod.CODE_FILES, Path(mod.__file__).name)},
        'scan_options': approved_scan_options(),
    }
    path = root / 'supervised_spec.json'
    path.write_text(json.dumps(row, sort_keys=True))
    return path, mod.sha(path), output


def pid_running(pid: int) -> bool:
    path = Path(f'/proc/{pid}/stat')
    if not path.exists():
        return False
    return path.read_text().split(') ', 1)[1][0] != 'Z'


class PhysicalSupervisorTests(unittest.TestCase):
    def test_physical_wall_matches_frozen_child_policy(self):
        self.assertEqual(mod.SUPERVISED_WALL_SECONDS,
                         LiveHPPolicy().wall_seconds)

    def test_direct_api_without_external_bootstrap_is_rejected(self):
        with patch.object(mod, 'load_spec') as load:
            with self.assertRaisesRegex(ValueError, 'external bootstrap'):
                mod.run_supervised(Path('/unused'), '0' * 64)
            load.assert_not_called()

    def test_external_bootstrap_rejects_changed_entry_bytes_before_execution(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / 'changed_entry.py'
            source = Path(mod.__file__).read_text()
            script.write_text(source.replace(
                'from __future__ import annotations\n',
                'from __future__ import annotations\nprint("UNPINNED_ENTRY_RAN")\n', 1))
            completed = subprocess.run(
                [sys.executable, '-I', '-B', '-c', mod.BOOTSTRAP_CODE,
                 str(script), mod.sha(Path(mod.__file__)), '--preflight-only',
                 str(root / 'missing.json'), '0' * 64],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn('UNPINNED_ENTRY_RAN', completed.stdout)

    def test_external_bootstrap_literal_and_direct_cli_rejection(self):
        literal = (Path(mod.__file__).resolve().parent.parent / 'review' /
                   'HP_SUPERVISOR_BOOTSTRAP_LITERAL_20261030.txt')
        self.assertEqual(literal.read_text(), mod.BOOTSTRAP_CODE)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, _ = spec_fixture(root)
            result = subprocess.run(
                [sys.executable, '-I', '-B', str(Path(mod.__file__)),
                 '--preflight-only', str(spec), digest],
                capture_output=True, text=True, timeout=10,
                env={**os.environ, 'CODEX_HOME': str(root)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('external bootstrap', result.stderr)

    def test_unpinned_evaluation_importable_binaries_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'approved.py').write_text('VALUE = 1\n')
            for name in ('ghost.pyc', 'approved.cpython-312-x86_64-linux-gnu.so'):
                binary = root / name
                binary.write_bytes(b'unregistered executable')
                with self.subTest(name=name), patch.object(mod, 'HERE', root):
                    with self.assertRaisesRegex(ValueError, 'unregistered executable'):
                        mod._runtime_code_files()
                binary.unlink()

    def test_unpinned_product_importable_binaries_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / 'product'
            for folder in ('src', 'prompts', 'config'):
                (root / folder).mkdir(parents=True)
            (root / 'src' / 'approved.py').write_text('VALUE = 1\n')
            for name in ('rogue.pyc', 'rogue.cpython-312-x86_64-linux-gnu.so'):
                binary = root / 'src' / name
                binary.write_bytes(b'not actually executable')
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, 'unregistered executable'):
                        mod._source_digest(root)
                binary.unlink()

    def test_cli_creates_private_empty_cache_before_evaluation_import(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, _ = spec_fixture(root)
            command = [sys.executable, '-I', '-B', '-c', mod.BOOTSTRAP_CODE,
                       str(Path(mod.__file__)), mod.sha(Path(mod.__file__)),
                       '--preflight-only', str(spec), digest]
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=20,
                                    env={**os.environ, 'CODEX_HOME': str(root)})
            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row['status'], 'PREFLIGHT_PASS')
            self.assertTrue(row['private_fresh_pycache'])

    def test_bootstrapped_parent_and_child_fail_before_model_on_bad_toy_route(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, output = spec_fixture(root)
            command = [sys.executable, '-I', '-B', '-c', mod.BOOTSTRAP_CODE,
                       str(Path(mod.__file__)), mod.sha(Path(mod.__file__)),
                       '--supervise', str(spec), digest]
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=25,
                                    env={**os.environ, 'CODEX_HOME': str(root)})
            self.assertNotEqual(result.returncode, 0)
            saved = json.loads((output / mod.RESULT_NAME).read_text())
            self.assertEqual(saved['status'], 'CHILD_ERROR')
            self.assertEqual(saved['spec_sha256'], digest)
            self.assertEqual(saved['contract_sha256'],
                             json.loads(spec.read_text())['contract_sha256'])
            self.assertIsNone(saved['model_event_log']['sha256'])

    def test_transitive_evaluation_runtime_helpers_are_pinned(self):
        # These modules are imported below the live entrypoint. A spec that
        # authenticates only the entrypoint could execute changed helper code.
        required = {
            'dev_global_request_ledger.py', 'pinned_codex_delta_protocol.py',
            'blind2_budget_guard.py', 'blind2_freeze_contract.py',
            'catalog_build_integrity.py',
        }
        self.assertTrue(required <= set(mod.CODE_FILES))

    def test_changed_transitive_helper_digest_rejected_before_import(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, _, _ = spec_fixture(root)
            row = json.loads(spec.read_text())
            row['evaluation_sha256']['dev_global_request_ledger.py'] = '0' * 64
            spec.write_text(json.dumps(row, sort_keys=True))
            with patch.object(mod, '_import_live') as loaded:
                with self.assertRaisesRegex(ValueError, 'pin changed'):
                    mod.load_spec(spec, mod.sha(spec))
                loaded.assert_not_called()

    def test_new_evaluation_helper_after_spec_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, _ = spec_fixture(root)
            with patch.object(mod, '_runtime_code_files',
                              return_value=(*mod.CODE_FILES, 'unexpected_helper.py')):
                with self.assertRaisesRegex(ValueError, 'spec shape changed'):
                    mod.load_spec(spec, digest)

    def test_parent_rechecks_pins_before_any_launch(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, _ = spec_fixture(root)
            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, '_launch_guarded') as launch, \
                 patch.object(mod, '_require_external_bootstrap'):
                with self.assertRaisesRegex(ValueError, 'pin changed'):
                    mod.run_supervised(spec, '0' * 64)
                launch.assert_not_called()
                # The toy source check now runs in the bounded child, before
                # that child starts a model; parent only pins the spec/code.
                launch.assert_not_called()

    def test_parent_preflight_runs_only_inside_supervised_child(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, _ = spec_fixture(root)
            with patch.object(mod, '_require_external_bootstrap'), \
                 patch.object(mod, 'preflight', side_effect=AssertionError(
                     'unbounded parent preflight executed')) as parent_preflight, \
                 patch.object(mod, 'supervise_command', return_value={
                     'status': 'CHILD_EXITED_INCONCLUSIVE'}) as supervise:
                mod.run_supervised(spec, digest)
            parent_preflight.assert_not_called()
            command = supervise.call_args.args[0]
            self.assertEqual(command[:4], [sys.executable, '-I', '-B', '-c'])
            self.assertEqual(command[4], mod.BOOTSTRAP_CODE)
            self.assertEqual(command[5], str(Path(mod.__file__).resolve()))
            self.assertEqual(command[6], mod.sha(Path(mod.__file__)))

    def test_parent_rejects_contract_wall_mismatch_before_child(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, _, _ = spec_fixture(root)
            spec_row = json.loads(spec.read_text())
            contract = Path(spec_row['contract_path'])
            row = json.loads(contract.read_text())
            row['limits']['wall_seconds'] += 1
            contract.write_text(json.dumps(row, sort_keys=True))
            spec_row['contract_sha256'] = mod.sha(contract)
            spec.write_text(json.dumps(spec_row, sort_keys=True))
            with patch.object(mod, '_require_external_bootstrap'), \
                 patch.object(mod, 'supervise_command') as supervise:
                with self.assertRaisesRegex(ValueError, 'wall differs'):
                    mod.run_supervised(spec, mod.sha(spec))
            supervise.assert_not_called()

    def test_output_parent_symlink_swap_is_fail_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            output = root / 'output'
            moved = root / 'moved'
            output.mkdir(mode=0o700)
            code = (f'import os;os.rename({str(output)!r},{str(moved)!r});'
                    f'os.symlink({str(moved)!r},{str(output)!r})')
            result = mod.supervise_command(
                [sys.executable, '-I', '-c', code], output,
                wall_seconds=3, runner=old_runner)
            self.assertEqual(result['status'], 'STOPPED_OUTPUT_PATH_CHANGED')
            self.assertTrue(result['output_path_changed'])
            self.assertEqual(json.loads((moved / mod.RESULT_NAME).read_text())['status'],
                             'STOPPED_OUTPUT_PATH_CHANGED')

    def test_output_inode_swap_before_launch_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            output = root / 'output'
            output.mkdir(mode=0o700)
            before = output.stat()
            output.rename(root / 'old-output')
            output.mkdir(mode=0o700)
            with patch.object(old_runner, '_launch_guarded') as launch:
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    mod.supervise_command(
                        [sys.executable, '-I', '-c', 'pass'], output,
                        wall_seconds=3, runner=old_runner,
                        expected_output_identity=(before.st_dev, before.st_ino))
            launch.assert_not_called()

    def test_durable_supervisor_result_contains_frozen_identity(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            output.chmod(0o700)
            provenance = {'spec_sha256': 'a' * 64,
                          'contract_sha256': 'b' * 64,
                          'product_source_sha256': 'c' * 64,
                          'evaluation_source_sha256': 'd' * 64}
            result = mod.supervise_command(
                [sys.executable, '-I', '-c', 'pass'], output,
                wall_seconds=3, runner=old_runner, provenance=provenance)
            saved = json.loads((output / mod.RESULT_NAME).read_text())
            self.assertEqual({key: saved[key] for key in provenance}, provenance)
            self.assertEqual(result, saved)

    def test_valid_spec_preflight_is_no_model(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, digest, _ = spec_fixture(root)
            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, '_launch_guarded') as launch:
                loaded = mod.load_spec(spec, digest)
                _, contract = mod.preflight(loaded)
                self.assertEqual(contract.selected_function_id, 'fn')
                launch.assert_not_called()

    def test_missing_role_route_is_rejected_by_child_preflight(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            spec, _, _ = spec_fixture(root)
            spec_row = json.loads(spec.read_text())
            contract = Path(spec_row['contract_path'])
            contract_row = json.loads(contract.read_text())
            # Re-pin both files to show that hash consistency alone cannot
            # approve an omitted Function Analyzer route.
            contract_row['public_toy']['scan_options_sha256'] = (
                _scan_options_digest({}))
            contract.write_text(json.dumps(contract_row, sort_keys=True))
            spec_row['contract_sha256'] = mod.sha(contract)
            spec_row['scan_options'] = {}
            spec.write_text(json.dumps(spec_row, sort_keys=True))
            with patch.dict(os.environ, {'CODEX_HOME': str(root)}), \
                 patch.object(old_runner, '_launch_guarded') as launch:
                loaded = mod.load_spec(spec, mod.sha(spec))
                with self.assertRaisesRegex(ValueError, 'role_models'):
                    mod.preflight(loaded)
                launch.assert_not_called()

    def test_sync_block_sets_id_descendant_is_reaped(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            output.chmod(0o700)
            marker = output / 'grandchild.pid'
            code = (
                'import pathlib,subprocess,sys,time;'
                'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],'
                'start_new_session=True);'
                f'pathlib.Path({str(marker)!r}).write_text(str(p.pid));'
                'time.sleep(30)'
            )
            result = mod.supervise_command(
                [sys.executable, '-I', '-c', code], output,
                wall_seconds=1.5, runner=old_runner)
            self.assertEqual(result['status'], 'STOPPED_WALL_LIMIT')
            self.assertFalse(result['cleanup_incomplete'])
            self.assertTrue(marker.is_file())
            self.assertFalse(pid_running(int(marker.read_text())))
            self.assertEqual(json.loads((output / mod.RESULT_NAME).read_text())[
                'original_stop_reason'], 'STOPPED_WALL_LIMIT')

    def test_normal_exit_also_reaps_sets_id_descendant(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            output.chmod(0o700)
            marker = output / 'grandchild.pid'
            code = (
                'import pathlib,subprocess,sys;'
                'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],'
                'start_new_session=True);'
                f'pathlib.Path({str(marker)!r}).write_text(str(p.pid))'
            )
            result = mod.supervise_command(
                [sys.executable, '-I', '-c', code], output,
                wall_seconds=3, runner=old_runner)
            self.assertEqual(result['status'], 'CHILD_EXITED_INCONCLUSIVE')
            self.assertFalse(pid_running(int(marker.read_text())))

    def test_child_error_retains_attempt_ledger_without_claiming_success(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            output.chmod(0o700)
            ledger = output / mod.LEDGER_NAME
            code = (
                'import pathlib,sys;'
                f'pathlib.Path({str(ledger)!r}).write_text("physical=1");'
                'sys.exit(17)'
            )
            result = mod.supervise_command(
                [sys.executable, '-I', '-c', code], output,
                wall_seconds=3, runner=old_runner)
            self.assertEqual(result['status'], 'CHILD_ERROR')
            self.assertEqual(result['return_code'], 17)
            self.assertEqual(result['physical_attempt_ledger']['sha256'],
                             hashlib.sha256(b'physical=1').hexdigest())
            self.assertEqual(ledger.read_text(), 'physical=1')

    def test_cancel_primary_survives_cleanup_error(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            output.chmod(0o700)
            read_fd, write_fd = os.pipe()
            os.close(write_fd)

            class Child:
                pid = 999999999
                returncode = None

                def wait(self, timeout=None):
                    raise asyncio.CancelledError('cancelled')

                def poll(self):
                    return None

            class Runner:
                def _launch_guarded(self, *_args, **_kwargs):
                    return Child(), read_fd

                def _request_guard_cleanup(self, *_args):
                    raise RuntimeError('cleanup broke')

                def _kill_process_group(self, _pid):
                    return None

            with self.assertRaises(asyncio.CancelledError):
                mod.supervise_command(['unused'], output,
                                      wall_seconds=1, runner=Runner())
            row = json.loads((output / mod.RESULT_NAME).read_text())
            self.assertEqual(row['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(row['primary_error_type'], 'CancelledError')
            self.assertEqual(row['cleanup_error_type'], 'RuntimeError')

    def test_timeout_cleanup_failure_keeps_wall_reason(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            output.chmod(0o700)
            read_fd, write_fd = os.pipe()
            os.close(write_fd)

            class Child:
                pid = 999999999
                returncode = None

                def wait(self, timeout=None):
                    raise subprocess.TimeoutExpired('synthetic', timeout)

                def poll(self):
                    return None

            class Runner:
                def _launch_guarded(self, *_args, **_kwargs):
                    return Child(), read_fd

                def _request_guard_cleanup(self, *_args):
                    return False

                def _kill_process_group(self, _pid):
                    return None

            row = mod.supervise_command(['unused'], output,
                                        wall_seconds=1, runner=Runner())
            self.assertEqual(row['status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(row['original_stop_reason'], 'STOPPED_WALL_LIMIT')


if __name__ == '__main__':
    unittest.main()
