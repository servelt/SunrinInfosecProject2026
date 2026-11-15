"""Pinned provider-free public-toy preflight. No official qualification.

Reuse existing dev supervisor INLINE_BOOTSTRAP and supervise_command, which
call Blind 2's subreaper. No Blind 2 bootstrap or supervisor code is copied.
"""

from __future__ import annotations

import argparse
import atexit
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Any
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
PYTHON = Path('/usr/bin/python3.12')
HELPER = TOOLS / 'dev_live_direction_sp_hp_supervisor.py'
BLIND2_RUNNER = TOOLS / 'blind2_runner_draft.py'
CONTRACT_NAME = 'PUBLIC_TOY_CAMPAIGN_CONTRACT.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
MODEL_NAME = 'MODEL_LEDGER.json'
PHYSICAL_NAME = 'GLOBAL_LEDGER.json'  # Existing supervisor evidence slot.
SOURCE_FILES = ('run.json', 'harness.json', 'workers.json', 'directions.json',
                'function_pool.json', 'direction_plan.json', 'selection.json',
                'call_graph_audit.json')
TOY_FILES = ('fuzz.c', 'target.c', 'project.json', 'direction_plan.json',
             'analysis/functions.jsonl', 'analysis/edges.jsonl',
             'analysis/indirect_edges.jsonl', 'attempt/manifest.json',
             'attempt/validation.json', 'target.bin')
MODES = frozenset({'normal', 'stop_after_first', 'stop_before_first_model'})
PREIMPORT_MODULES = frozenset({
    'blind2_runner_draft', 'dev_live_direction_sp_hp_supervisor',
    'dev_blind3_campaign_shell', 'dev_four_phase_budget_progress',
    'dev_global_appserver_bridge', 'dev_global_request_ledger',
    'dev_persistent_physical_fuzz_ledger',
})
HEX = re.compile(r'[0-9a-f]{64}\Z')


def _sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _plain(path: Path, *, directory: bool = False) -> None:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or
            not (path.is_dir() if directory else path.is_file())):
        raise ValueError(f'public-toy pin missing or linked: {path}')


def _private_dir(path: Path) -> None:
    _plain(path, directory=True)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('public-toy output is not private')


def _absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def _loaded_source(module: Any, expected: Path) -> None:
    source = Path(str(getattr(module, '__file__', '')))
    spec = getattr(module, '__spec__', None)
    origin = Path(str(getattr(spec, 'origin', '')))
    if (source != expected or origin != expected or source.suffix != '.py' or
            source.is_symlink()):
        raise ValueError(f'public-toy loaded module origin changed: {expected.name}')


def _pin_files(output: Path, source: Path, worklist: Path,
               repo: Path) -> dict[str, str]:
    paths = [*(source / name for name in SOURCE_FILES), worklist,
             *(repo / name for name in TOY_FILES)]
    result: dict[str, str] = {}
    for path in paths:
        _plain(path)
        relative = path.relative_to(output).as_posix()
        if relative in result:
            raise ValueError('duplicate public-toy input pin')
        result[relative] = _sha(path)
    return result


def _helper() -> Any:
    sys.path.insert(0, str(TOOLS))
    import dev_live_direction_sp_hp_supervisor as helper
    _loaded_source(helper, HELPER)
    return helper


def _checked_blind2_runner() -> Any:
    if 'blind2_runner_draft' in sys.modules:
        raise ValueError('supervisor was preloaded before checked import')
    import blind2_runner_draft as runner
    _loaded_source(runner, BLIND2_RUNNER)
    return runner


def prepare(output: Path, source_run: Path, worklist_path: Path,
            target_repository: Path, *, mode: str = 'normal') -> tuple[Path, str]:
    """Pin an existing public Phase 1 run without a model or campaign start."""
    output, source_run, worklist_path, target_repository = map(
        Path, (output, source_run, worklist_path, target_repository))
    _private_dir(output)
    for path in (source_run, target_repository):
        _plain(path, directory=True)
    if (mode not in MODES or not source_run.is_relative_to(output) or
            not target_repository.is_relative_to(output) or
            not worklist_path.is_relative_to(output) or
            source_run.parent != target_repository / 'runs' or
            not _absent(source_run / 'scan.json') or
            not _absent(source_run.parent / 'campaign-first') or
            not _absent(output / CONTRACT_NAME)):
        raise ValueError('public-toy preparation paths or mode changed')
    for path in (HELPER, BLIND2_RUNNER, PYTHON):
        _plain(path)
    pins = _pin_files(output, source_run, worklist_path, target_repository)
    helper = _helper()
    row = {
        'kind': 'BLIND3_PUBLIC_TOY_SCRIPTED_PREFLIGHT_DEV_V1',
        'scope': 'PUBLIC_TOY_SCRIPTED_DEVELOPMENT_ONLY_NO_OFFICIAL_QUALIFICATION',
        'not_claimed': ['Blind 3 approval', 'official target qualification',
                        'real model', 'Target execution', 'Fuzzing', 'Oracle',
                        'atomic identity against same-UID concurrent edits',
                        'descendant cleanup after missing guard status pipe'],
        'output_dir': str(output), 'source_run': str(source_run),
        'worklist_path': str(worklist_path),
        'target_repository': str(target_repository),
        'target_binary': str(target_repository / 'target.bin'),
        'first_run': str(source_run.parent / 'campaign-first'),
        'campaign_output': str(output / 'campaign'),
        'mode': mode, 'input_pins': pins,
        'driver_sha256': _sha(Path(__file__)),
        'helper_sha256': _sha(HELPER),
        'blind2_supervisor_source_sha256': _sha(BLIND2_RUNNER),
        'code_pins': helper._code_pins(),
        'python_path': str(PYTHON), 'python_sha256': _sha(PYTHON),
        'model_budget': {'physical_max': 3, 'logical_max': 3,
                         'retries_max': 0, 'wall_seconds': 60,
                         'initial_starts_required': 1,
                         'profile': 'GLOBAL_ONLY_DEV'},
        'supervisor_wall_seconds': 90,
        'physical_fuzz_budget_seconds': 120,
    }
    contract = output / CONTRACT_NAME
    helper._write_once(contract, row)
    return contract, _sha(contract)


def load_contract(contract: Path, expected_sha256: str) -> dict[str, Any]:
    """Verify code and inputs before importing a product module."""
    if any(name == 'vulnerabilityanalysis' or
           name.startswith('vulnerabilityanalysis.') for name in sys.modules):
        raise ValueError('product was imported before public-toy pins')
    if PREIMPORT_MODULES & sys.modules.keys():
        raise ValueError('development helper was imported before public-toy pins')
    contract = Path(contract)
    _plain(contract)
    if not HEX.fullmatch(expected_sha256) or _sha(contract) != expected_sha256:
        raise ValueError('public-toy contract SHA-256 changed')
    row = json.loads(contract.read_text(encoding='utf-8'))
    expected_budget = {'physical_max': 3, 'logical_max': 3, 'retries_max': 0,
                       'wall_seconds': 60, 'initial_starts_required': 1,
                       'profile': 'GLOBAL_ONLY_DEV'}
    if (not isinstance(row, dict) or
            row.get('kind') != 'BLIND3_PUBLIC_TOY_SCRIPTED_PREFLIGHT_DEV_V1' or
            row.get('scope') !=
                'PUBLIC_TOY_SCRIPTED_DEVELOPMENT_ONLY_NO_OFFICIAL_QUALIFICATION' or
            row.get('mode') not in MODES or
            row.get('model_budget') != expected_budget or
            row.get('supervisor_wall_seconds') != 90 or
            row.get('physical_fuzz_budget_seconds') != 120 or
            row.get('python_path') != str(PYTHON)):
        raise ValueError('public-toy development contract changed')
    output = Path(row['output_dir'])
    _private_dir(output)
    if contract != output / CONTRACT_NAME:
        raise ValueError('public-toy contract route changed')
    source, worklist, repo = (Path(row[key]) for key in
                              ('source_run', 'worklist_path', 'target_repository'))
    for path in (source, repo):
        _plain(path, directory=True)
    if (not source.is_relative_to(output) or
            not worklist.is_relative_to(output) or
            not repo.is_relative_to(output) or
            source.parent != repo / 'runs' or
            not _absent(source / 'scan.json') or
            Path(row['target_binary']) != repo / 'target.bin' or
            Path(row['first_run']) != source.parent / 'campaign-first' or
            Path(row['campaign_output']) != output / 'campaign' or
            not _absent(Path(row['first_run'])) or
            not _absent(Path(row['campaign_output'])) or
            any(not _absent(output / name) for name in
                (MODEL_NAME, PHYSICAL_NAME, CHILD_NAME,
                 'DEV_LIVE_SUPERVISOR_RESULT.json')) or
            '--child' not in sys.argv and
                not _absent(output / 'supervisor.log')):
        raise ValueError('public-toy execution path changed or already started')
    if '--child' in sys.argv:
        _plain(output / 'supervisor.log')
    for path, expected in ((Path(__file__), row['driver_sha256']),
                           (HELPER, row['helper_sha256']),
                           (BLIND2_RUNNER, row['blind2_supervisor_source_sha256']),
                           (PYTHON, row['python_sha256'])):
        _plain(path)
        if not isinstance(expected, str) or _sha(path) != expected:
            raise ValueError(f'public-toy code pin changed: {path}')
    if row.get('input_pins') != _pin_files(output, source, worklist, repo):
        raise ValueError('public-toy source, worklist, Direction, or Worker pin changed')
    cache = output / ('child_pycache' if '--child' in sys.argv else 'parent_pycache')
    if '--child' in sys.argv:
        _private_dir(cache)
        if sys.pycache_prefix != str(cache):
            raise ValueError('public-toy child cache prefix changed')
    else:
        if '--preflight' in sys.argv:
            cache = Path(tempfile.mkdtemp(prefix='preflight_pycache_', dir=output))
            atexit.register(shutil.rmtree, cache, ignore_errors=True)
        else:
            if cache.exists() or cache.is_symlink():
                raise ValueError('public-toy parent cache already used')
            cache.mkdir(mode=0o700)
        sys.pycache_prefix = str(cache)
        os.environ['PYTHONPYCACHEPREFIX'] = str(cache)
    for project in (TOOLS, PRODUCT):
        if (cache / project.relative_to(project.anchor)).exists():
            raise ValueError('public-toy import cache contains project bytecode')
    helper = _helper()
    if row.get('code_pins') != helper._code_pins():
        raise ValueError('public-toy evaluation or product code tree changed')
    return row


class _ToyQualification:
    """Scripted Scan binding; no official build provenance."""
    product_issued = True

    def __init__(self, repo: Path, harness: Path, binary: Path):
        self.source_root = repo.resolve()
        self.harness = harness.resolve()
        self.binary = binary.resolve()


def _stop_after_first(shell: Any, physical: Any):
    real_continue = shell.continue_four_phase_dev

    def stop(run: Path) -> Path:
        next_run = real_continue(run)
        physical.reserve('HP:toy-cleanup-stop', 'HP', 10)
        physical.finish('HP:toy-cleanup-stop', physical_seconds=1,
                        cleanup_complete=False)
        return next_run

    return stop


def _stop_before_first_model(shell: Any, physical: Any):
    real_hash = shell.request_hash

    def stop(request: Any) -> str:
        hashed = real_hash(request)
        physical.reserve('SP:toy-start-race', 'SP', 10)
        physical.finish('SP:toy-start-race', physical_seconds=1,
                        cleanup_complete=False)
        return hashed

    return stop


def _run_child(row: dict[str, Any], contract_sha256: str) -> int:
    dev_modules = PREIMPORT_MODULES - {
        'blind2_runner_draft', 'dev_live_direction_sp_hp_supervisor'}
    if dev_modules & sys.modules.keys():
        raise ValueError('development helper was preloaded before checked import')
    from dev_global_request_ledger import (DevelopmentBudget,
                                           DevelopmentRequestLedger,
                                           GLOBAL_ONLY_DEV_PROFILE)
    from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
    import dev_blind3_campaign_shell as shell
    runner = _checked_blind2_runner()
    runner.verify_loaded_module_origins(sys.modules, TOOLS, PRODUCT / 'src')
    if row['code_pins'] != _helper()._code_pins():
        raise ValueError('public-toy product or helper changed during child import')
    if row['input_pins'] != _pin_files(
            Path(row['output_dir']), Path(row['source_run']),
            Path(row['worklist_path']), Path(row['target_repository'])):
        raise ValueError('public-toy input changed during child import')
    for name in ('dev_four_phase_budget_progress',
                 'dev_global_appserver_bridge',
                 'dev_global_request_ledger',
                 'dev_persistent_physical_fuzz_ledger',
                 'dev_blind3_campaign_shell'):
        _loaded_source(sys.modules[name], TOOLS / f'{name}.py')

    output, repo = Path(row['output_dir']), Path(row['target_repository'])
    model = DevelopmentRequestLedger.create(DevelopmentBudget(
        physical_max=3, logical_max=3, retries_max=0, wall_seconds=60,
        initial_starts_required=1, profile=GLOBAL_ONLY_DEV_PROFILE),
        output / MODEL_NAME)
    model.register_direction('public-direction')
    digest = hashlib.sha256(b'PUBLIC_TOY_SCRIPTED_DIRECTION').hexdigest()
    model.begin_turn('public-direction', 'direction_generator', digest)
    model.start_attempt(digest)
    model.finish_attempt(completed=True)
    physical = PersistentPhysicalFuzzLedger.create(
        output / PHYSICAL_NAME, total_seconds=120)
    mode = row['mode']
    qualification = _ToyQualification(repo, repo / 'fuzz.c',
                                      Path(row['target_binary']))
    with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                _ToyQualification),
          patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                return_value=True),
          patch('vulnerabilityanalysis.scan.execute_poc',
                side_effect=AssertionError('toy Target execution forbidden')),
          patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                side_effect=AssertionError('toy Fuzzing forbidden')),
          patch('vulnerabilityanalysis.scan.run_global_fuzz',
                side_effect=AssertionError('toy Global Fuzzing forbidden')),
          patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                side_effect=AssertionError('toy Target execution forbidden')),
          patch.object(shell, 'continue_four_phase_dev',
                       side_effect=_stop_after_first(shell, physical)
                       if mode == 'stop_after_first' else
                       shell.continue_four_phase_dev),
          patch.object(shell, 'request_hash',
                       side_effect=_stop_before_first_model(shell, physical)
                       if mode == 'stop_before_first_model' else
                       shell.request_hash)):
        result = asyncio.run(shell.run_scripted_four_phase_campaign(
            source_run=Path(row['source_run']),
            worklist_path=Path(row['worklist_path']),
            expected_worklist_sha256=_sha(Path(row['worklist_path'])),
            first_run=Path(row['first_run']),
            campaign_output=Path(row['campaign_output']),
            target_repository=repo,
            target_binary=Path(row['target_binary']),
            official_qualification=qualification,
            model_ledger=model, physical_ledger=physical))
    return _write_child_receipt(row, contract_sha256, result, model, physical)


def _write_child_receipt(row: dict, contract_sha256: str, result: dict,
                         model: Any, physical: Any) -> int:
    output, mode = Path(row['output_dir']), row['mode']
    completed = result['completed']
    current = Path(result['current_run']) if result.get('current_run') else None
    item = (json.loads((current / 'work_item.json').read_text())
            if current and (current / 'work_item.json').is_file() else None)
    stopped = mode != 'normal'
    expected = ('STOPPED_CLEANUP_INCOMPLETE' if stopped else
                'BUDGET_EXHAUSTED_PENDING_WORK')
    ok = (result['status'] == expected and
          len(completed) == (0 if mode == 'stop_before_first_model' else
                             1 if stopped else 2) and
          result['physical_model_starts'] ==
              (1 if mode == 'stop_before_first_model' else
               2 if stopped else 3) and
          result['target_runs'] == result['fuzz_seconds'] == 0 and
          (not stopped or result.get('remaining_status') ==
           'NO_OPPORTUNITY_PHYSICAL_STOP'))
    if mode == 'stop_after_first':
        ok = ok and bool(item) and model.no_opportunity.get(
            item['work_item_id']) == 'NO_OPPORTUNITY_PHYSICAL_STOP'
    if mode == 'stop_before_first_model':
        ok = ok and bool(item) and model.function_states.get(
            item['work_item_id']) == 'INCOMPLETE_PHYSICAL_STOP'
    if len(completed) == 2:
        ok = ok and (completed[0]['function_id'] == completed[1]['function_id'] and
                     completed[0]['direction_id'] != completed[1]['direction_id'] and
                     completed[0]['work_item_id'] != completed[1]['work_item_id'])
    receipt = {
        'kind': 'BLIND3_PUBLIC_TOY_SCRIPTED_PREFLIGHT_RECEIPT_V1',
        'scope': row['scope'], 'contract_sha256': contract_sha256,
        'status': 'EXPECTED_TOY_TRACE' if ok else 'UNEXPECTED_TOY_TRACE',
        'campaign_status': result['status'], 'mode': mode,
        'completed_work_items': completed,
        'current_work_item_id': (item or {}).get('work_item_id'),
        'current_model_state': model.function_states.get(
            (item or {}).get('work_item_id')),
        'current_no_opportunity': model.no_opportunity.get(
            (item or {}).get('work_item_id')),
        'remaining_status': result.get('remaining_status'),
        'model_ledger_sha256': _sha(model.checkpoint_path),
        'physical_ledger_sha256': _sha(physical.path),
        'campaign_progress_sha256': _sha(
            Path(row['campaign_output']) / 'CAMPAIGN_PROGRESS.json'),
        'physical_model_starts': model.physical,
        'actual_model_transports': 0, 'target_runs': 0, 'fuzz_seconds': 0,
        'assurance_limit': 'PREIMPORT_PIN_CHECKED_DEV_SCRIPTED_TOY_ONLY',
    }
    _helper()._write_once(output / CHILD_NAME, receipt)
    return 0 if ok else 1


def run_supervised(contract: Path, expected_sha256: str) -> dict[str, Any]:
    """Validate before importing Blind 2's guarded process launcher."""
    row = load_contract(contract, expected_sha256)
    helper = _helper()
    runner = _checked_blind2_runner()  # Imports product after pins.
    if row['code_pins'] != helper._code_pins():
        raise ValueError('public-toy code changed during supervisor import')
    if row['input_pins'] != _pin_files(
            Path(row['output_dir']), Path(row['source_run']),
            Path(row['worklist_path']), Path(row['target_repository'])):
        raise ValueError('public-toy input changed during supervisor import')
    runner.verify_loaded_module_origins(sys.modules, TOOLS, PRODUCT / 'src')
    output = Path(row['output_dir'])
    identity = output.stat()
    child_cache = output / 'child_pycache'
    if child_cache.exists() or child_cache.is_symlink():
        raise ValueError('public-toy child cache already exists')
    child_cache.mkdir(mode=0o700)
    command = [str(PYTHON), '-I', '-B', '-X',
               f'pycache_prefix={child_cache}', '-c', helper.INLINE_BOOTSTRAP,
               str(Path(__file__)), row['driver_sha256'], '--child',
               str(contract), expected_sha256]

    def completed_trace(child: dict, _fd: int, _output: Path) -> bool:
        return (child.get('kind') ==
                'BLIND3_PUBLIC_TOY_SCRIPTED_PREFLIGHT_RECEIPT_V1' and
                child.get('status') == 'EXPECTED_TOY_TRACE' and
                child.get('contract_sha256') == expected_sha256 and
                child.get('mode') == row['mode'] and
                (child.get('campaign_status') ==
                 ('BUDGET_EXHAUSTED_PENDING_WORK' if row['mode'] == 'normal'
                  else 'STOPPED_CLEANUP_INCOMPLETE')) and
                len(child.get('completed_work_items', [])) ==
                    (2 if row['mode'] == 'normal' else
                     1 if row['mode'] == 'stop_after_first' else 0))

    return helper.supervise_command(
        command, output, wall_seconds=row['supervisor_wall_seconds'],
        runner=runner, spec_sha256=expected_sha256,
        completion_predicate=completed_trace,
        expected_output_identity=(identity.st_dev, identity.st_ino))


def _work_item_checkpoints_valid(row: dict, child: dict) -> bool:
    """Bind every claimed completed work item to one saved toy run."""
    completed = child.get('completed_work_items')
    if not isinstance(completed, list):
        return False
    expected_count = (2 if row['mode'] == 'normal' else
                      1 if row['mode'] == 'stop_after_first' else 0)
    if len(completed) != expected_count:
        return False
    ids = [item.get('work_item_id') for item in completed
           if isinstance(item, dict)]
    if len(ids) != len(completed) or len(ids) != len(set(ids)):
        return False
    try:
        root = Path(row['source_run']).parent
        _plain(root, directory=True)
        matches: dict[str, Path] = {}
        for candidate in root.iterdir():
            if candidate.is_symlink():
                return False
            if not candidate.is_dir():
                continue
            item_path = candidate / 'work_item.json'
            if not item_path.exists() and not item_path.is_symlink():
                continue
            _plain(item_path)
            saved = json.loads(item_path.read_text(encoding='utf-8'))
            item_id = saved.get('work_item_id')
            if item_id in ids:
                if item_id in matches:
                    return False
                matches[item_id] = candidate
                claimed = next(item for item in completed
                               if item['work_item_id'] == item_id)
                if any(saved.get(key) != claimed.get(key) for key in
                       ('ordinal', 'direction_id', 'function_id')):
                    return False
        if set(matches) != set(ids):
            return False
        for claimed in completed:
            path = matches[claimed['work_item_id']]
            for filename, field in (('scan.json', 'scan_sha256'),
                                    ('four_phase_scan_complete.json',
                                     'terminal_sha256')):
                evidence = path / filename
                _plain(evidence)
                if (_sha(evidence) != claimed.get(field) or
                        not HEX.fullmatch(str(claimed.get(field)))):
                    return False
    except (OSError, ValueError, TypeError, KeyError):
        return False
    return True


def supervised_outcome_valid(contract: Path, expected_sha256: str,
                             result: dict[str, Any]) -> bool:
    """Never treat a generic inconclusive child exit as a successful toy run."""
    if (_sha(contract) != expected_sha256 or
            result.get('cleanup_incomplete') or
            result.get('output_identity_ok') is not True or
            result.get('return_code') != 0):
        return False
    row = json.loads(contract.read_text(encoding='utf-8'))
    try:
        output = Path(row['output_dir'])
        final_pins = _pin_files(
            output, Path(row['source_run']), Path(row['worklist_path']),
            Path(row['target_repository']))
    except (OSError, ValueError, TypeError, KeyError):
        return False
    if final_pins != row.get('input_pins'):
        return False
    try:
        if (row.get('driver_sha256') != _sha(Path(__file__)) or
                row.get('helper_sha256') != _sha(HELPER) or
                row.get('blind2_supervisor_source_sha256') !=
                    _sha(BLIND2_RUNNER) or
                row.get('python_sha256') != _sha(PYTHON) or
                row.get('code_pins') != _helper()._code_pins()):
            return False
    except (OSError, ValueError, TypeError):
        return False
    child_path = Path(row['output_dir']) / CHILD_NAME
    if (child_path.is_symlink() or not child_path.is_file() or
            result.get('child_result', {}).get('path') != str(child_path) or
            _sha(child_path) != result.get('child_result', {}).get('sha256')):
        return False
    child = json.loads(child_path.read_text(encoding='utf-8'))
    if (child.get('status') != 'EXPECTED_TOY_TRACE' or
            child.get('contract_sha256') != expected_sha256 or
            child.get('mode') != row['mode'] or
            not _work_item_checkpoints_valid(row, child)):
        return False
    for path, field in (
            (Path(row['output_dir']) / MODEL_NAME, 'model_ledger_sha256'),
            (Path(row['output_dir']) / PHYSICAL_NAME, 'physical_ledger_sha256'),
            (Path(row['campaign_output']) / 'CAMPAIGN_PROGRESS.json',
             'campaign_progress_sha256')):
        try:
            _plain(path)
        except (OSError, ValueError):
            return False
        if (_sha(path) != child.get(field) or
                stat.S_IMODE(path.stat().st_mode) != 0o600):
            return False
    if (result.get('physical_ledger', {}).get('path') !=
            str(Path(row['output_dir']) / PHYSICAL_NAME) or
            result.get('physical_ledger', {}).get('sha256') !=
            child['physical_ledger_sha256']):
        return False
    return (result['status'] == 'CHILD_EXITED_COMPLETE' and
            child.get('campaign_status') ==
            ('BUDGET_EXHAUSTED_PENDING_WORK' if row['mode'] == 'normal'
             else 'STOPPED_CLEANUP_INCOMPLETE'))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--preflight', action='store_true')
    group.add_argument('--run', action='store_true')
    group.add_argument('--child', action='store_true')
    parser.add_argument('contract', type=Path)
    parser.add_argument('sha256')
    args = parser.parse_args(argv)
    if (sys.executable != str(PYTHON) or not sys.flags.isolated or
            not sys.dont_write_bytecode or
            globals().get('__VA_SOURCE_BOOTSTRAP_SHA__') != _sha(Path(__file__))):
        raise ValueError('public-toy execution requires pinned /usr/bin/python3.12 -I -B')
    if args.preflight:
        row = load_contract(args.contract, args.sha256)
        print(json.dumps({'status': 'PREIMPORT_PIN_CHECKED_DEV',
                          'contract_sha256': args.sha256,
                          'input_count': len(row['input_pins'])}, sort_keys=True))
        return 0
    if args.child:
        row = load_contract(args.contract, args.sha256)
        return _run_child(row, args.sha256)
    result = run_supervised(args.contract, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if supervised_outcome_valid(args.contract, args.sha256, result) else 1


if __name__ == '__main__':
    raise SystemExit(main())
