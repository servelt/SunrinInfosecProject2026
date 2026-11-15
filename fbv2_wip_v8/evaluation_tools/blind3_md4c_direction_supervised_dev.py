"""One supervised official V2 Direction turn, development only.

The model result feeds product Phase 1. This never runs Scan, HP, fuzzing,
Oracle grading, or Blind 3. Live use requires an externally pinned entrypoint.
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
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

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'review'
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
CONTRACT = ROOT / 'tools/FROZEN_CONTRACT_ATTEMPT3.json'
ARTIFACT = ROOT / 'v2_artifact_stage/attempt'
TARGET = ROOT / 'model_target'
OSS_FUZZ = ROOT / 'oss_fuzz_checkout'
UPSTREAM = ROOT / 'upstream_asan_final'
SUPERVISOR = ROOT / 'evaluation_tools/dev_live_direction_sp_hp_supervisor.py'
SPEC_NAME = 'OFFICIAL_V2_DIRECTION_DEV_SPEC.json'
RECEIPT_NAME = 'OFFICIAL_V2_DIRECTION_DEV_RECEIPT.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
LEDGER_NAME = 'GLOBAL_LEDGER.json'
PHASE1_FILES = ('run.json', 'function_pool.json', 'directions.json',
                'selection.json', 'workers.json', 'direction_plan.json',
                'harness.json', 'call_graph_audit.json')
WALL_SECONDS = 900
HEX = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_MODES = frozenset({'all_catalog_prefix', 'stratified_callsite_800'})
_BASE: Any = None


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def _require_external_source_pin() -> None:
    if (globals().get('__VA_SOURCE_BOOTSTRAP_SHA__') != sha(Path(__file__)) or
            sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('live execution requires external source pin and isolated Python')


def _fresh_private_pycache() -> None:
    if getattr(sys, '_va_official_direction_cache', None):
        return
    path = Path(tempfile.mkdtemp(prefix='va-direction-dev-pycache-'))
    path.chmod(0o700)
    if any(path.iterdir()):
        raise ValueError('dedicated Python cache is not empty')
    sys.pycache_prefix = str(path)
    os.environ['PYTHONPYCACHEPREFIX'] = str(path)
    sys._va_official_direction_cache = str(path)
    atexit.register(shutil.rmtree, path, ignore_errors=True)


def _base() -> Any:
    global _BASE
    _fresh_private_pycache()
    if _BASE is None:
        sys.path.insert(0, str(ROOT / 'evaluation_tools'))
        import dev_live_direction_sp_hp_supervisor as supervisor
        _BASE = supervisor
    return _BASE


def _source_context(source_mode: str) -> tuple[dict, dict]:
    if source_mode not in SOURCE_MODES:
        raise ValueError('Direction source mode is not reviewed')
    _base()
    sys.path[:0] = [str(ROOT / 'review_tools'), str(PRODUCT / 'src')]
    if source_mode == 'stratified_callsite_800':
        from blind3_direction_context_windows_dev import (
            build_windowed_context_from_artifact)
        return build_windowed_context_from_artifact(
            ARTIFACT, TARGET, oss_fuzz_checkout=OSS_FUZZ,
            upstream_checkout=UPSTREAM)
    from development_direction_study import build_context_from_artifact
    return build_context_from_artifact(
        ARTIFACT, TARGET, oss_fuzz_checkout=OSS_FUZZ,
        upstream_checkout=UPSTREAM, source_mode=source_mode)


def _pinned_contract(base: Any) -> tuple[dict, Path, Path]:
    base._plain_path(CONTRACT, directory=False)
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    config = ROOT / contract['codex_config']
    executable = Path(contract['codex_executable_path'])
    for item in (config, executable, Path('/usr/bin/python3.12')):
        base._plain_path(item, directory=False)
    if sha(executable) != contract['codex_executable_sha256']:
        raise ValueError('Codex executable differs from contract')
    return contract, config, executable


def _official_paths() -> dict[str, str]:
    return {key: str(path) for key, path in (
        ('artifact', ARTIFACT), ('target_repository', TARGET),
        ('oss_fuzz_checkout', OSS_FUZZ), ('upstream_checkout', UPSTREAM))}


def _official_protected_paths(runner: Any, contract: dict) -> tuple[Path, ...]:
    paths = runner._protected_model_paths(contract)
    if TARGET not in paths or len(paths) != len(set(paths)):
        raise ValueError('official Target missing or duplicated in sandbox paths')
    return paths


def prepare(output: Path, *, source_mode: str) -> tuple[Path, str]:
    """Create a private pinned spec; no provider connection or model call."""
    base = _base()
    output = Path(output)
    if (source_mode not in SOURCE_MODES or not output.is_absolute() or
            output.exists() or output.is_symlink() or
            output.parent != REVIEW or
            any(parent.is_symlink() for parent in output.parents)):
        raise ValueError('new Direction output must be inside Linux review root')
    base._plain_path(REVIEW, directory=True)
    code_pins = base._code_pins()
    _contract, config, executable = _pinned_contract(base)
    context, pins = _source_context(source_mode)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    identity = os.stat(output, follow_symlinks=False)
    row = {
        'kind': 'BLIND3_MD4C_OFFICIAL_V2_DIRECTION_DEV_V1',
        'scope': 'md4c development Direction once; Phase1 only; no Scan or HP',
        'output_dir': str(output),
        'output_identity': {'dev': identity.st_dev, 'ino': identity.st_ino},
        'source_mode': source_mode,
        'official_v2_paths': _official_paths(),
        'artifact_tree_sha256': base.tree_digest(ARTIFACT, None),
        'context_sha256': digest(context), 'input_pins': pins,
        'input_pins_sha256': digest(pins),
        'catalog_count': len(context['functions']),
        'driver_sha256': sha(Path(__file__)),
        'base_supervisor_sha256': sha(SUPERVISOR),
        'code_pins': code_pins,
        'dependency_versions': base._dependency_pins(),
        'contract_sha256': sha(CONTRACT),
        'codex_config_sha256': sha(config),
        'codex_executable_sha256': sha(executable),
        'python_path': '/usr/bin/python3.12',
        'python_sha256': sha(Path('/usr/bin/python3.12')),
        'global_budget': {'physical': 1, 'logical': 1, 'retries': 0,
                          'wall_seconds': WALL_SECONDS},
        'selection_policy': 'FBV2_FIRST_PASS_UNIQUE_DEV',
        'hp_project_state_dev': False,
    }
    spec = output / SPEC_NAME
    base._write_once(spec, row)
    return spec, sha(spec)


def load_spec(path: Path, expected_sha256: str) -> dict:
    """Pin entrypoint and supervisor before other evaluation/product imports."""
    path = Path(path)
    if (not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)
            or path.is_symlink() or not path.is_file() or
            sha(path) != expected_sha256):
        raise ValueError('official Direction spec pin changed')
    row = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(row, dict) or row.get('driver_sha256') != sha(Path(__file__))
            or row.get('base_supervisor_sha256') != sha(SUPERVISOR)):
        raise ValueError('official Direction executable source pin changed')
    base = _base()
    required = {'kind', 'scope', 'output_dir', 'output_identity', 'source_mode',
        'official_v2_paths', 'artifact_tree_sha256', 'context_sha256',
        'input_pins', 'input_pins_sha256', 'catalog_count', 'driver_sha256',
        'base_supervisor_sha256', 'code_pins', 'dependency_versions',
        'contract_sha256', 'codex_config_sha256', 'codex_executable_sha256',
        'python_path', 'python_sha256', 'global_budget', 'selection_policy',
        'hp_project_state_dev'}
    if (set(row) != required or
            row['kind'] != 'BLIND3_MD4C_OFFICIAL_V2_DIRECTION_DEV_V1' or
            row['scope'] != 'md4c development Direction once; Phase1 only; no Scan or HP' or
            row['source_mode'] not in SOURCE_MODES or
            row['official_v2_paths'] != _official_paths() or
            row['global_budget'] != {'physical': 1, 'logical': 1,
                                     'retries': 0, 'wall_seconds': WALL_SECONDS} or
            row['selection_policy'] != 'FBV2_FIRST_PASS_UNIQUE_DEV' or
            row['hp_project_state_dev'] is not False or
            row['python_path'] != '/usr/bin/python3.12' or
            row['code_pins'] != base._code_pins() or
            row['dependency_versions'] != base._dependency_pins()):
        raise ValueError('official Direction spec shape or code pin changed')
    output = Path(row['output_dir'])
    base._private_dir(output)
    identity = os.stat(output, follow_symlinks=False)
    if (row['output_identity'] != {'dev': identity.st_dev,
                                   'ino': identity.st_ino} or
            path != output / SPEC_NAME or output.parent != REVIEW or
            digest(row['input_pins']) != row['input_pins_sha256']):
        raise ValueError('official Direction output or V2 input pin changed')
    _contract, config, executable = _pinned_contract(base)
    for item, expected in ((CONTRACT, row['contract_sha256']),
                           (config, row['codex_config_sha256']),
                           (executable, row['codex_executable_sha256']),
                           (Path(row['python_path']), row['python_sha256'])):
        if sha(item) != expected:
            raise ValueError('official Direction route pin changed')
    if base.tree_digest(ARTIFACT, None) != row['artifact_tree_sha256']:
        raise ValueError('official V2 input pin changed: artifact tree')
    context, pins = _source_context(row['source_mode'])
    if (pins != row['input_pins'] or digest(context) != row['context_sha256'] or
            len(context['functions']) != row['catalog_count']):
        raise ValueError('official V2 input pin changed: context or Catalog')
    return row


def offline_preflight(row: dict) -> dict:
    """Repeat V2 qualification and local route checks without provider use."""
    base = _base()
    contract, config, _ = _pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, toy, _app, _budget, _ledger = base._imports()
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    runner.verify_pinned_codex_executable(contract)
    roles = toy.live_role_models(contract)
    context, pins = _source_context(row['source_mode'])
    if (pins != row['input_pins'] or digest(context) != row['context_sha256']):
        raise ValueError('official V2 input pin changed during preflight')
    return {'status': 'PREFLIGHT_PASS_NO_MODEL_CALL',
            'actual_provider_calls': 0, 'source_mode': row['source_mode'],
            'catalog_count': len(context['functions']),
            'context_chars': len(json.dumps(context, sort_keys=True,
                                            ensure_ascii=False)),
            'context_sha256': row['context_sha256'],
            'input_pins_sha256': row['input_pins_sha256'],
            'selection_policy': row['selection_policy'],
            'hp_project_state_dev': False,
            'direction_route': roles['direction_generator'],
            'contract_sha256': row['contract_sha256']}


def _open_output_dir(path: Path) -> int:
    """Hold the original output inode and reject links at each component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_beneath(directory_fd: int, relative: str, *, limit: int = 1_000_000
                  ) -> bytes:
    parts = Path(relative).parts
    if (not parts or any(part in {'', '.', '..'} for part in parts) or
            Path(relative).is_absolute()):
        raise ValueError('receipt path escapes output')
    fd = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            if (not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or
                    os.fstat(stream.fileno()).st_size > limit):
                raise ValueError('receipt evidence size or type invalid')
            return stream.read()
    finally:
        os.close(fd)


def _open_dir_beneath(directory_fd: int, relative: str) -> int:
    parts = Path(relative).parts
    if (not parts or any(part in {'', '.', '..'} for part in parts) or
            Path(relative).is_absolute()):
        raise ValueError('receipt directory escapes output')
    fd = os.dup(directory_fd)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _completion_predicate(child: dict, directory_fd: int, output: Path, *,
                          expected_spec_sha256: str,
                          expected_context_sha256: str,
                          expected_pins_sha256: str,
                          expected_catalog_count: int) -> bool:
    """Parent checks V2 input, Phase 1 receipt, and one physical ledger row."""
    try:
        if (child.get('status') != 'OFFICIAL_V2_DIRECTION_PHASE1_COMPLETE' or
                child.get('physical') != 1 or child.get('logical') != 1 or
                child.get('retries') != 0 or
                child.get('spec_sha256') != expected_spec_sha256 or
                child.get('context_sha256') != expected_context_sha256 or
                child.get('input_pins_sha256') != expected_pins_sha256):
            return False
        receipt_bytes = _read_beneath(directory_fd, RECEIPT_NAME)
        if hashlib.sha256(receipt_bytes).hexdigest() != child.get('receipt_sha256'):
            return False
        receipt = json.loads(receipt_bytes)
        if (receipt.get('spec_sha256') != expected_spec_sha256 or
                receipt.get('context_sha256') != expected_context_sha256 or
                receipt.get('input_pins_sha256') != expected_pins_sha256 or
                receipt.get('selection_policy') != 'FBV2_FIRST_PASS_UNIQUE_DEV' or
                receipt.get('hp_project_state_dev') is not False or
                receipt.get('actual_provider_calls') != 1 or
                receipt.get('pool_count') != expected_catalog_count or
                child.get('phase1_result_sha256') !=
                    receipt.get('phase1_result_sha256') or
                child.get('direction_plan_sha256') !=
                    receipt.get('direction_plan_sha256') or
                child.get('direction_request_file_sha256') !=
                    receipt.get('direction_request_file_sha256') or
                child.get('direction_raw_file_sha256') !=
                    receipt.get('direction_raw_file_sha256') or
                child.get('phase1_artifact_sha256') !=
                    receipt.get('phase1_artifact_sha256') or
                receipt.get('physical') != 1 or receipt.get('logical') != 1 or
                receipt.get('retries') != 0):
            return False
        ledger_bytes = _read_beneath(directory_fd, LEDGER_NAME)
        ledger = json.loads(ledger_bytes)
        turns, attempts = ledger.get('turns', []), ledger.get('attempts', [])
        if (hashlib.sha256(ledger_bytes).hexdigest() != receipt.get('ledger_sha256') or
                ledger.get('physical') != 1 or ledger.get('logical') != 1 or
                ledger.get('retries') != 0 or ledger.get('active_turn') is not None or
                len(turns) != 1 or len(attempts) != 1 or
                turns[0].get('role') != 'direction_generator' or
                turns[0].get('status') != 'COMPLETED' or
                attempts[0].get('status') != 'COMPLETED' or
                attempts[0].get('accepted') is not True or
                attempts[0].get('response_saved') is not True or
                attempts[0].get('request_hash') != turns[0].get('hash') or
                not isinstance(attempts[0].get('app_server_turn_id'), str) or
                turns[0].get('hash') != receipt.get('direction_request_hash')):
            return False
        result_bytes = _read_beneath(directory_fd,
            'direction/DIRECTION_PHASE1_RESULT.json')
        result = json.loads(result_bytes)
        if (hashlib.sha256(result_bytes).hexdigest() !=
                receipt.get('phase1_result_sha256') or
                result.get('direction_plan_sha256') !=
                    receipt.get('direction_plan_sha256') or
                result.get('selection_policy') != receipt.get('selection_policy') or
                result.get('pool_count') != receipt.get('pool_count')):
            return False
        request_bytes = _read_beneath(directory_fd,
            'direction/DIRECTION_REQUEST.json')
        raw_bytes = _read_beneath(directory_fd,
            'direction/DIRECTION_RAW.txt')
        request_sha = hashlib.sha256(request_bytes).hexdigest()
        raw_sha = hashlib.sha256(raw_bytes).hexdigest()
        if (request_sha != result.get('direction_request_sha256') or
                request_sha != receipt.get('direction_request_file_sha256') or
                raw_sha != result.get('direction_raw_sha256') or
                raw_sha != receipt.get('direction_raw_file_sha256')):
            return False
        from dev_global_appserver_bridge import artifact_hash
        if artifact_hash(json.loads(request_bytes)) != receipt.get(
                'direction_request_hash'):
            return False
        run_relative = receipt.get('phase1_run_relative')
        if (not isinstance(run_relative, str) or
                Path(run_relative).parts[:2] != ('direction', 'product_runs') or
                len(Path(run_relative).parts) != 3):
            return False
        run_fd = _open_dir_beneath(directory_fd, run_relative)
        try:
            if set(os.listdir(run_fd)) != set(PHASE1_FILES):
                return False
        finally:
            os.close(run_fd)
        phase1_sha = receipt.get('phase1_artifact_sha256')
        if (not isinstance(phase1_sha, dict) or
                set(phase1_sha) != set(PHASE1_FILES)):
            return False
        for name in PHASE1_FILES:
            expected = phase1_sha[name]
            if (not isinstance(expected, str) or not HEX.fullmatch(expected) or
                    hashlib.sha256(_read_beneath(
                        directory_fd, run_relative + '/' + name)).hexdigest() !=
                    expected):
                return False
        run_bytes = _read_beneath(directory_fd, run_relative + '/run.json')
        run = json.loads(run_bytes)
        if (hashlib.sha256(run_bytes).hexdigest() != receipt.get('run_sha256') or
                phase1_sha['run.json'] != receipt.get('run_sha256') or
                phase1_sha['direction_plan.json'] !=
                    receipt.get('direction_plan_sha256') or
                run.get('direction_plan_sha256') != receipt.get('direction_plan_sha256') or
                run.get('selection_policy') != receipt.get('selection_policy')):
            return False
        plan_bytes = _read_beneath(directory_fd,
            'direction/DIRECTION_PLAN.json')
        if (hashlib.sha256(plan_bytes).hexdigest() !=
                receipt.get('direction_plan_sha256') or
                hashlib.sha256(_read_beneath(directory_fd,
                    'MODEL_EVENTS.jsonl', limit=64_000_000)).hexdigest() !=
                    receipt.get('model_event_log_sha256')):
            return False
        pins_bytes = _read_beneath(directory_fd,
            'direction/DIRECTION_INPUT_PINS.json')
        pins = json.loads(pins_bytes)
        return (hashlib.sha256(pins_bytes).hexdigest() ==
                    receipt.get('direction_input_file_sha256') and
                pins.get('context_sha256') == expected_context_sha256 and
                digest(pins.get('pins')) == expected_pins_sha256)
    except Exception:
        return False


async def _run_child(row: dict, spec_sha256: str) -> dict:
    _require_external_source_pin()
    base = _base()
    contract, config, executable = _pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, toy, AppServer, Budget, Ledger = base._imports()
    from blind3_direction_phase1_dev import execute_direction_phase1
    from dev_global_appserver_bridge import (artifact_hash,
        verify_model_event_order)
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    roles = toy.live_role_models(contract)
    output = Path(row['output_dir'])
    model_cwd = output / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    base._private_dir(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('model cwd must be empty')
    base._write_once(output / 'OFFICIAL_V2_PRECHECK.json', {
        'spec_sha256': spec_sha256, 'source_mode': row['source_mode'],
        'input_pins_sha256': row['input_pins_sha256'],
        'context_sha256': row['context_sha256'],
        'code_pins': row['code_pins'],
        'codex_executable_sha256': row['codex_executable_sha256'],
        'direction_route': roles['direction_generator']})
    ledger = Ledger.create(Budget(
        physical_max=1, logical_max=1, retries_max=0,
        wall_seconds=WALL_SECONDS, initial_starts_required=1,
        sp_per_function=1, hp_per_function=1, combined_per_function=2,
        hp_analysis_per_function=1, hp_assertion_per_function=1),
        output / LEDGER_NAME)
    with runner.private_codex_state(config):
        sandbox = runner.verify_model_namespace_sandbox(
            executable, _official_protected_paths(runner, contract))
        base._write_once(output / 'SANDBOX_SELF_TEST.json', sandbox)
        backend = AppServer(
            ledger=ledger, role_models=roles, cwd=model_cwd,
            wire_cwd='/work', launch_prefix=[sys.executable,
                str(ROOT / 'evaluation_tools/blind2_model_sandbox.py')],
            executable=str(executable),
            executable_sha256=contract['codex_executable_sha256'],
            model=contract['default_model'], effort=contract['default_effort'],
            timeout_seconds=300, event_log_path=output / 'MODEL_EVENTS.jsonl')
        async with backend:
            await asyncio.wait_for(runner.check_live_route(
                backend, contract['route_sha256'], roles), timeout=120)
            result = await asyncio.wait_for(execute_direction_phase1(
                output=output / 'direction', artifact=ARTIFACT,
                target_repository=TARGET, oss_fuzz_checkout=OSS_FUZZ,
                upstream_checkout=UPSTREAM, backend=backend, ledger=ledger,
                role_models=roles, scope_id='official-v2-md4c-development',
                source_mode=row['source_mode']), timeout=600)
    verify_model_event_order(ledger, output / 'MODEL_EVENTS.jsonl')
    if (ledger.physical != 1 or ledger.logical != 1 or ledger.retries != 0 or
            ledger.tainted or ledger.active_turn is not None or
            result['status'] != 'DIRECTION_PHASE1_PREPARED_DEV' or
            result['pool_count'] != row['catalog_count'] or
            result['selection_policy'] != row['selection_policy']):
        raise ValueError('official Direction physical trace incomplete')
    if load_spec(output / SPEC_NAME, spec_sha256) != row:
        raise ValueError('official Direction pins changed after Phase 1')
    direction = output / 'direction'
    phase1_run = Path(result['phase1_run'])
    if not phase1_run.is_relative_to(output):
        raise ValueError('Phase 1 output escaped private directory')
    request = json.loads((direction / 'DIRECTION_REQUEST.json').read_text())
    receipt = {
        'kind': 'BLIND3_MD4C_OFFICIAL_V2_DIRECTION_DEV_RECEIPT_V1',
        'status': 'OFFICIAL_V2_DIRECTION_PHASE1_COMPLETE',
        'spec_sha256': spec_sha256,
        'context_sha256': row['context_sha256'],
        'input_pins_sha256': row['input_pins_sha256'],
        'direction_input_file_sha256': sha(direction / 'DIRECTION_INPUT_PINS.json'),
        'direction_request_hash': artifact_hash(request),
        'direction_request_file_sha256': sha(direction / 'DIRECTION_REQUEST.json'),
        'direction_raw_file_sha256': sha(direction / 'DIRECTION_RAW.txt'),
        'direction_plan_sha256': result['direction_plan_sha256'],
        'phase1_result_sha256': sha(direction / 'DIRECTION_PHASE1_RESULT.json'),
        'phase1_run_relative': phase1_run.relative_to(output).as_posix(),
        'run_sha256': sha(phase1_run / 'run.json'),
        'phase1_artifact_sha256': {
            name: sha(phase1_run / name) for name in PHASE1_FILES},
        'ledger_sha256': sha(output / LEDGER_NAME),
        'model_event_log_sha256': sha(output / 'MODEL_EVENTS.jsonl'),
        'selection_policy': row['selection_policy'],
        'hp_project_state_dev': False,
        'pool_count': result['pool_count'],
        'physical': ledger.physical, 'logical': ledger.logical,
        'retries': ledger.retries, 'actual_provider_calls': ledger.physical,
    }
    base._write_once(output / RECEIPT_NAME, receipt)
    child = {'status': 'OFFICIAL_V2_DIRECTION_PHASE1_COMPLETE',
             'spec_sha256': spec_sha256,
             'context_sha256': row['context_sha256'],
             'input_pins_sha256': row['input_pins_sha256'],
             'receipt_sha256': sha(output / RECEIPT_NAME),
             'phase1_result_sha256': receipt['phase1_result_sha256'],
             'direction_plan_sha256': receipt['direction_plan_sha256'],
             'direction_request_file_sha256': receipt['direction_request_file_sha256'],
             'direction_raw_file_sha256': receipt['direction_raw_file_sha256'],
             'phase1_artifact_sha256': receipt['phase1_artifact_sha256'],
             'physical': 1, 'logical': 1, 'retries': 0}
    base._write_once(output / CHILD_NAME, child)
    return child


def run_supervised(spec: Path, expected_sha256: str) -> dict:
    _require_external_source_pin()
    row = load_spec(spec, expected_sha256)
    output = Path(row['output_dir'])
    if any((output / name).exists() for name in (
            LEDGER_NAME, CHILD_NAME, RECEIPT_NAME)):
        raise ValueError('official Direction attempt already started')
    base = _base()
    contract, _, _ = _pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, _toy, _app, _budget, _ledger = base._imports()
    os.umask(0o077)
    parent_cache = output / 'parent_pycache'
    if parent_cache.exists() or parent_cache.is_symlink():
        raise ValueError('parent cache must be fresh')
    parent_cache.mkdir(mode=0o700)
    base._private_dir(parent_cache)
    sys.pycache_prefix = str(parent_cache)
    os.environ['PYTHONPYCACHEPREFIX'] = str(parent_cache)
    child_cache = output / 'child_pycache'
    if child_cache.exists() or child_cache.is_symlink():
        raise ValueError('child cache must be fresh')
    child_cache.mkdir(mode=0o700)
    base._private_dir(child_cache)
    command = [row['python_path'], '-I', '-B', '-X',
               f'pycache_prefix={child_cache}', '-c', base.INLINE_BOOTSTRAP,
               str(Path(__file__).resolve()), row['driver_sha256'],
               '--child', str(spec), expected_sha256]
    predicate = lambda child, fd, held: _completion_predicate(
        child, fd, held, expected_spec_sha256=expected_sha256,
        expected_context_sha256=row['context_sha256'],
        expected_pins_sha256=row['input_pins_sha256'],
        expected_catalog_count=row['catalog_count'])
    if load_spec(spec, expected_sha256) != row:
        raise ValueError('official Direction pins changed before child launch')
    return base.supervise_command(
        command, output, wall_seconds=WALL_SECONDS, runner=runner,
        spec_sha256=expected_sha256, completion_predicate=predicate,
        expected_output_identity=(row['output_identity']['dev'],
                                  row['output_identity']['ino']))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--preflight-only', action='store_true')
    group.add_argument('--run-live', action='store_true')
    group.add_argument('--child', action='store_true')
    parser.add_argument('--source-mode', choices=sorted(SOURCE_MODES),
                        default='all_catalog_prefix')
    parser.add_argument('path', type=Path)
    parser.add_argument('sha256', nargs='?')
    args = parser.parse_args(argv)
    if (sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('use /usr/bin/python3.12 -I -B')
    if args.prepare:
        spec, expected = prepare(args.path, source_mode=args.source_mode)
        print(json.dumps({'status': 'PREPARED_NO_MODEL_CALL',
                          'spec': str(spec), 'sha256': expected}))
        return 0
    if not args.sha256:
        parser.error('reviewed spec SHA-256 required')
    if args.run_live or args.child:
        _require_external_source_pin()
    row = load_spec(args.path, args.sha256)
    if args.preflight_only:
        print(json.dumps(offline_preflight(row), sort_keys=True))
        return 0
    if args.child:
        asyncio.run(_run_child(row, args.sha256))
        return 0
    result = run_supervised(args.path, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
