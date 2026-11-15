"""Isolated, provider-free Stage 5 public-toy preflight regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import types
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent
PREP = TOOLS.parent
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(TOOLS), str(PRODUCT / 'src'), str(PRODUCT / 'tests')]

import dev_blind3_supervised_campaign_preflight as preflight  # noqa: E402
import dev_live_direction_sp_hp_supervisor as supervisor  # noqa: E402
from dev_fbv2_four_phase_worklist import build_from_pinned_run  # noqa: E402
from dev_no_k_three_function_gate import make_public_fixture  # noqa: E402
from vulnerabilityanalysis.workflow import run_phase1  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PublicToyCampaignPreflightTests(unittest.TestCase):
    def fixture(self, root: Path, *, mode: str = 'normal') -> tuple[Path, str, Path]:
        output = root / 'stage5'
        output.mkdir(mode=0o700)
        artifact, repo, plan = make_public_fixture(output / 'fixture')
        proposal = json.loads(plan.read_text())
        first = proposal['response']['directions'][0]
        first['core_function_ids'] = ['fn-a']
        proposal['response']['directions'].append(
            dict(first, name='Second public Direction'))
        plan.write_text(json.dumps(proposal, sort_keys=True) + '\n')
        run = run_phase1(artifact, repo / 'runs', target_repository=repo,
                         direction_plan=plan,
                         selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        worklist = build_from_pinned_run(run)
        self.assertEqual(worklist['counts']['phases']['small/new'], 2)
        worklist_path = output / 'WORKLIST.json'
        worklist_path.write_text(json.dumps(worklist, sort_keys=True) + '\n')
        (repo / 'target.bin').write_bytes(b'public synthetic binary; never executed\n')
        contract, digest = preflight.prepare(
            output, run, worklist_path, repo, mode=mode)
        return contract, digest, output

    def invoke(self, contract: Path, digest: str, action: str = '--run'):
        command = [str(preflight.PYTHON), '-I', '-B', '-c',
                   supervisor.INLINE_BOOTSTRAP,
                   str(Path(preflight.__file__)), sha(Path(preflight.__file__)),
                   action, str(contract), digest]
        return subprocess.run(command, text=True, capture_output=True,
                              timeout=110, check=False)

    def test_two_direction_same_function_scans_under_bounded_supervisor(self):
        with TemporaryDirectory() as temp:
            contract, digest, output = self.fixture(Path(temp))
            row = json.loads(contract.read_text())
            for name in ('workers.json', 'directions.json', 'run.json'):
                self.assertIn((Path(row['source_run']) / name).relative_to(
                    output).as_posix(), row['input_pins'])
            self.assertIn(Path(row['worklist_path']).relative_to(output).as_posix(),
                          row['input_pins'])
            for name in ('target.c', 'fuzz.c', 'target.bin'):
                self.assertIn((Path(row['target_repository']) / name).relative_to(
                    output).as_posix(), row['input_pins'])
            prechecked = self.invoke(contract, digest, '--preflight')
            self.assertEqual(prechecked.returncode, 0, prechecked.stderr)
            self.assertEqual(json.loads(prechecked.stdout)['status'],
                             'PREIMPORT_PIN_CHECKED_DEV')
            self.assertFalse((output / preflight.MODEL_NAME).exists())
            result = self.invoke(contract, digest)
            self.assertEqual(result.returncode, 0, result.stderr)
            supervised = json.loads(result.stdout)
            self.assertEqual(supervised['status'], 'CHILD_EXITED_COMPLETE')
            child = json.loads((output / preflight.CHILD_NAME).read_text())
            self.assertEqual(child['status'], 'EXPECTED_TOY_TRACE')
            self.assertEqual(child['campaign_status'],
                             'BUDGET_EXHAUSTED_PENDING_WORK')
            self.assertEqual(child['physical_model_starts'], 3)
            self.assertEqual((child['target_runs'], child['fuzz_seconds']), (0, 0))
            first, second = child['completed_work_items']
            self.assertEqual(first['function_id'], second['function_id'])
            self.assertNotEqual(first['direction_id'], second['direction_id'])
            self.assertNotEqual(first['work_item_id'], second['work_item_id'])
            for item in (first, second):
                self.assertEqual(len(item['scan_sha256']), 64)
                self.assertEqual(len(item['terminal_sha256']), 64)
            self.assertTrue(preflight.supervised_outcome_valid(
                contract, digest, supervised))
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, {**supervised,
                                   'status': 'CHILD_EXITED_INCONCLUSIVE'}))
            first_run = Path(row['first_run'])
            scan = first_run / 'scan.json'
            scan_bytes = scan.read_bytes()
            scan.write_bytes(scan_bytes + b'changed\n')
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, supervised))
            scan.write_bytes(scan_bytes)
            terminal = first_run / 'four_phase_scan_complete.json'
            terminal_bytes = terminal.read_bytes()
            terminal.unlink()
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, supervised))
            terminal.write_bytes(terminal_bytes)
            alias = first_run.with_name('linked-run')
            alias.symlink_to(first_run, target_is_directory=True)
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, supervised))
            alias.unlink()
            copy = first_run.with_name('duplicate-run')
            shutil.copytree(first_run, copy)
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, supervised))
            shutil.rmtree(copy)
            for evidence in (output / preflight.MODEL_NAME,
                             output / preflight.PHYSICAL_NAME,
                             output / 'campaign' / 'CAMPAIGN_PROGRESS.json'):
                original = evidence.read_bytes()
                evidence.write_bytes(original + b'changed\n')
                self.assertFalse(preflight.supervised_outcome_valid(
                    contract, digest, supervised), evidence.name)
                evidence.write_bytes(original)
            target_source = Path(row['target_repository']) / 'target.c'
            source_bytes = target_source.read_bytes()
            target_source.write_bytes(source_bytes + b'changed after run\n')
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, supervised))
            target_source.write_bytes(source_bytes)
            with patch.object(supervisor, '_code_pins', return_value={}):
                self.assertFalse(preflight.supervised_outcome_valid(
                    contract, digest, supervised))
            child_path = output / preflight.CHILD_NAME
            child_path.write_bytes(child_path.read_bytes() + b'changed\n')
            self.assertFalse(preflight.supervised_outcome_valid(
                contract, digest, supervised))

    def test_missing_and_changed_source_pins_fail_before_model_or_target(self):
        for target, action in (('workers.json', 'unlink'),
                               ('directions.json', 'change'),
                               ('target.c', 'change'),
                               ('target.bin', 'change')):
            with self.subTest(target=target), TemporaryDirectory() as temp:
                contract, digest, output = self.fixture(Path(temp))
                row = json.loads(contract.read_text())
                path = (Path(row['source_run']) / target if target.endswith('.json')
                        else Path(row['target_repository']) / target)
                if action == 'unlink':
                    path.unlink()
                else:
                    path.write_bytes(path.read_bytes() + b'changed\n')
                result = self.invoke(contract, digest, '--preflight')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output / preflight.MODEL_NAME).exists())
                self.assertFalse((output / preflight.CHILD_NAME).exists())
                self.assertFalse((output / 'campaign').exists())

    def test_source_scan_added_after_pin_fails_before_scripted_direction(self):
        for action in ('--preflight', '--run'):
            with self.subTest(action=action), TemporaryDirectory() as temp:
                contract, digest, output = self.fixture(Path(temp))
                source = Path(json.loads(contract.read_text())['source_run'])
                (source / 'scan.json').write_text('{"unexpected":true}\n')
                result = self.invoke(contract, digest, action)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output / preflight.MODEL_NAME).exists())
                self.assertFalse((output / preflight.CHILD_NAME).exists())
                self.assertFalse((output / 'campaign').exists())

    def test_symlinked_source_ancestor_and_old_cache_fail_closed(self):
        for failure in ('source_symlink', 'old_cache'):
            with self.subTest(failure=failure), TemporaryDirectory() as temp:
                contract, digest, output = self.fixture(Path(temp))
                if failure == 'source_symlink':
                    source = Path(json.loads(contract.read_text())['source_run'])
                    moved = source.with_name('moved-source-run')
                    source.rename(moved)
                    source.symlink_to(moved, target_is_directory=True)
                else:
                    cache = output / 'parent_pycache'
                    cache.mkdir(mode=0o700)
                    (cache / 'stale.pyc').write_bytes(b'old bytecode')
                result = self.invoke(contract, digest)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output / preflight.MODEL_NAME).exists())
                self.assertFalse((output / preflight.CHILD_NAME).exists())

    def test_input_change_after_initial_pin_check_stops_before_child(self):
        with TemporaryDirectory() as temp:
            contract, digest, output = self.fixture(Path(temp))
            script = (
                'import pathlib,sys\n'
                f'sys.path.insert(0,{str(TOOLS)!r})\n'
                'import dev_blind3_supervised_campaign_preflight as p\n'
                'original=p.load_contract\n'
                'def tamper(path,digest):\n'
                '  row=original(path,digest)\n'
                '  source=pathlib.Path(row["target_repository"])/"target.c"\n'
                '  source.write_bytes(source.read_bytes()+b"changed\\n")\n'
                '  return row\n'
                'p.load_contract=tamper\n'
                'try:\n'
                f'  p.run_supervised(pathlib.Path({str(contract)!r}),{digest!r})\n'
                'except ValueError as error:\n'
                '  assert "input changed during supervisor import" in str(error)\n'
                'else:\n'
                '  raise AssertionError("mutated input was accepted")\n')
            result = subprocess.run([str(preflight.PYTHON), '-I', '-B', '-c', script],
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((output / preflight.MODEL_NAME).exists())
            self.assertFalse((output / preflight.CHILD_NAME).exists())

    def test_child_dev_helper_origin_mismatch_blocks_before_ledger(self):
        with TemporaryDirectory() as temp:
            contract, digest, output = self.fixture(Path(temp))
            expected = str(TOOLS / 'dev_global_request_ledger.py')
            script = (
                'import pathlib,sys,types\n'
                f'sys.path.insert(0,{str(TOOLS)!r})\n'
                'import dev_blind3_supervised_campaign_preflight as p\n'
                'fake=types.ModuleType("dev_global_request_ledger")\n'
                f'fake.__file__={expected!r}\n'
                f'fake.__spec__=types.SimpleNamespace(origin={expected!r})\n'
                'sys.modules[fake.__name__]=fake\n'
                'try:\n'
                f'  p.load_contract(pathlib.Path({str(contract)!r}),{digest!r})\n'
                'except ValueError as error:\n'
                '  assert "imported before public-toy pins" in str(error)\n'
                'else:\n'
                '  raise AssertionError("preloaded helper was accepted")\n')
            result = subprocess.run([str(preflight.PYTHON), '-I', '-B', '-c', script],
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((output / preflight.MODEL_NAME).exists())

    def test_same_name_supervisor_helper_shadow_is_rejected(self):
        with TemporaryDirectory() as temp:
            contract, digest, output = self.fixture(Path(temp))
            script = (
                'import pathlib,sys,types\n'
                f'sys.path.insert(0,{str(TOOLS)!r})\n'
                'import dev_blind3_supervised_campaign_preflight as p\n'
                'fake=types.ModuleType("dev_live_direction_sp_hp_supervisor")\n'
                f'fake.__file__={str(preflight.HELPER)!r}\n'
                f'fake.__spec__=types.SimpleNamespace(origin={str(preflight.HELPER)!r})\n'
                'sys.modules[fake.__name__]=fake\n'
                'try:\n'
                f'  p.load_contract(pathlib.Path({str(contract)!r}),{digest!r})\n'
                'except ValueError as error:\n'
                '  assert "imported before public-toy pins" in str(error)\n'
                'else:\n'
                '  raise AssertionError("shadow helper was accepted")\n')
            result = subprocess.run([str(preflight.PYTHON), '-I', '-B', '-c', script],
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((output / preflight.MODEL_NAME).exists())

    def test_fake_blind2_runner_cannot_supply_its_own_origin_verifier(self):
        with TemporaryDirectory() as temp:
            contract, _digest, output = self.fixture(Path(temp))
            fake = types.ModuleType('blind2_runner_draft')
            fake.__file__ = str(preflight.BLIND2_RUNNER)
            fake.__spec__ = types.SimpleNamespace(
                origin=str(preflight.BLIND2_RUNNER))
            fake.verify_loaded_module_origins = lambda *_args: None
            with patch.dict(sys.modules, {'blind2_runner_draft': fake}):
                with self.assertRaisesRegex(ValueError,
                                            'preloaded before checked import'):
                    preflight._checked_blind2_runner()
            self.assertFalse((output / preflight.MODEL_NAME).exists())

    def test_dangling_output_symlink_blocks_before_direction_debit(self):
        for name in ('campaign', preflight.MODEL_NAME, preflight.PHYSICAL_NAME,
                     preflight.CHILD_NAME, 'parent_pycache', 'child_pycache'):
            with self.subTest(name=name), TemporaryDirectory() as temp:
                contract, digest, output = self.fixture(Path(temp))
                (output / name).symlink_to(output / 'absent-target')
                result = self.invoke(contract, digest)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output / preflight.CHILD_NAME).is_file())
                self.assertFalse((output / 'campaign').is_dir())

    def test_physical_stop_after_first_records_no_opportunity(self):
        with TemporaryDirectory() as temp:
            contract, digest, output = self.fixture(
                Path(temp), mode='stop_after_first')
            result = self.invoke(contract, digest)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'],
                             'CHILD_EXITED_COMPLETE')
            child = json.loads((output / preflight.CHILD_NAME).read_text())
            self.assertEqual(child['status'], 'EXPECTED_TOY_TRACE')
            self.assertEqual(child['campaign_status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(len(child['completed_work_items']), 1)
            self.assertEqual(child['current_no_opportunity'],
                             'NO_OPPORTUNITY_PHYSICAL_STOP')
            self.assertEqual(child['physical_model_starts'], 2)

    def test_stop_between_precheck_and_model_start_blocks_request(self):
        with TemporaryDirectory() as temp:
            contract, digest, output = self.fixture(
                Path(temp), mode='stop_before_first_model')
            result = self.invoke(contract, digest)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'],
                             'CHILD_EXITED_COMPLETE')
            child = json.loads((output / preflight.CHILD_NAME).read_text())
            self.assertEqual(child['status'], 'EXPECTED_TOY_TRACE')
            self.assertEqual(child['campaign_status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(child['completed_work_items'], [])
            self.assertEqual(child['current_model_state'], 'INCOMPLETE_PHYSICAL_STOP')
            self.assertEqual(child['remaining_status'],
                             'NO_OPPORTUNITY_PHYSICAL_STOP')
            self.assertEqual(child['physical_model_starts'], 1)  # Direction only.
            self.assertEqual((child['target_runs'], child['fuzz_seconds']), (0, 0))


if __name__ == '__main__':
    unittest.main()
