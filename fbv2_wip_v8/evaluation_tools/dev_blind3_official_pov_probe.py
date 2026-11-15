"""Official V2, supervised, separate PoV-budget *development* model component.

Prepare and preflight never contact a provider. A live run needs an externally
SHA-pinned bootstrap, reissues V2 qualification in the supervised child, and
uses the four-phase adapter for one SP/HP work item. Target binary, Fuzzer,
Oracle and Blind 3 execution are outside this component. Protected PoV input
generator and compiler helper processes may still execute.
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


ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'review'
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
EVALUATION = ROOT / 'evaluation_tools'
CONTRACT = ROOT / 'tools/FROZEN_CONTRACT_ATTEMPT3.json'
ARTIFACT = ROOT / 'v2_artifact_stage/attempt'
TARGET = ROOT / 'model_target'
OSS_FUZZ = ROOT / 'oss_fuzz_checkout'
UPSTREAM = ROOT / 'upstream_asan_final'
FRESH_RECEIPT = REVIEW / 'STAGE8_OFFICIAL_PHASE1_20261031/STAGE8_PROVIDER_FREE_RECEIPT.json'
FRESH_RECEIPT_SHA = '47e07a1bde11889fa60bbb78d132c880b3e0308dfacd974d38e1bf2f47ab7a5b'
SAVED_DIRECTION = REVIEW / 'DEV_LIVE_FULL_CANDIDATE_PREP_20261031_v8/direction'
SAVED_ATTEMPT = SAVED_DIRECTION.parent
SOURCE_FILES = ('run.json', 'harness.json', 'workers.json', 'directions.json',
                'function_pool.json', 'direction_plan.json', 'selection.json',
                'call_graph_audit.json')
DIRECTION_FILES = ('DIRECTION_INPUT_PINS.json', 'DIRECTION_REQUEST.json',
                   'DIRECTION_PLAN.json', 'DIRECTION_PHASE1_RESULT.json',
                   'DIRECTION_RAW.txt')
ROLES = frozenset({'sp_generation', 'sp_verifier', 'poc_generator',
                   'function_analysis', 'assertion_generator'})
SPEC_NAME = 'OFFICIAL_ONE_WORK_ITEM_SPEC.json'
RECEIPT_NAME = 'OFFICIAL_ONE_WORK_ITEM_RECEIPT.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
MODEL_NAME = 'MODEL_LEDGER.json'
PHYSICAL_NAME = 'GLOBAL_LEDGER.json'  # Existing supervisor evidence slot.
SUPERVISION_NAME = 'OFFICIAL_ONE_WORK_ITEM_SUPERVISION.json'
KIND = 'OFFICIAL_V2_ONE_WORK_ITEM_POV_BUDGET_PROBE_DEV_V1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
PROBE_BUDGET = {'physical_max': 7, 'logical_max': 7,
                'retries_max': 0, 'wall_seconds': 1200.0,
                'initial_starts_required': 2}


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _model_event_evidence(path: Path, scan_status: str) -> tuple[str, str | None]:
    """A physical STOP may precede the first event; retain that stop cause."""
    if path.is_symlink():
        raise ValueError('model event log is linked')
    if not path.exists():
        if scan_status == 'SCAN_RECORDED':
            raise ValueError('completed Scan has no model event log')
        return 'MISSING_INCOMPLETE', None
    if not path.is_file():
        raise ValueError('model event log is not regular')
    return ('VERIFIED_COMPLETE' if scan_status == 'SCAN_RECORDED'
            else 'PRESENT_INCOMPLETE'), sha(path)


def _plain(path: Path, *, directory: bool = False) -> None:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or
            not (path.is_dir() if directory else path.is_file())):
        raise ValueError(f'official component path missing or linked: {path}')


def _private(path: Path) -> None:
    _plain(path, directory=True)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('official component output is not private')


def _tree_digest(root: Path, suffixes: set[str] | None) -> str:
    """Match the supervisor's tree digest before any product import."""
    _plain(root, directory=True)
    entries: list[tuple[str, str]] = []
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in names:
            if (base / name).is_symlink():
                raise ValueError('linked code/source directory')
        for name in files:
            path = base / name
            if path.is_symlink() or path.suffix in {'.so', '.pyd', '.dll', '.dylib'}:
                raise ValueError('linked or native code/source file')
            if path.suffix == '.pyc':
                if path.parent.name != '__pycache__' or '.cpython-' not in name:
                    raise ValueError('loose bytecode')
                source = path.parent.parent / (name.split('.cpython-', 1)[0] + '.py')
                if not source.is_file() or source.is_symlink():
                    raise ValueError('sourceless bytecode')
                continue
            if suffixes is None or path.suffix in suffixes:
                entries.append((path.relative_to(root).as_posix(), sha(path)))
    if not entries:
        raise ValueError('empty code/source tree')
    return hashlib.sha256(json.dumps(sorted(entries), separators=(',', ':'),
        ensure_ascii=False).encode()).hexdigest()


def _code_pins() -> dict[str, str]:
    _plain(PRODUCT / 'pyproject.toml')
    return {
        'product_pyproject': sha(PRODUCT / 'pyproject.toml'),
        'product_src': _tree_digest(PRODUCT / 'src', {'.py'}),
        'product_prompts': _tree_digest(PRODUCT / 'prompts', {'.md'}),
        'product_config': _tree_digest(PRODUCT / 'config', {'.yaml', '.yml'}),
        'product_tests': _tree_digest(PRODUCT / 'tests', {'.py'}),
        'evaluation_tools': _tree_digest(EVALUATION, {'.py'}),
        'review_tools': _tree_digest(ROOT / 'review_tools', {'.py'}),
    }


def _saved_files() -> tuple[Path, ...]:
    return (*(SAVED_DIRECTION / name for name in DIRECTION_FILES),
            SAVED_ATTEMPT / 'GLOBAL_LEDGER.json',
            SAVED_ATTEMPT / 'MODEL_EVENTS.jsonl')


def _fresh_inputs() -> tuple[Path, Path, dict]:
    _plain(FRESH_RECEIPT)
    if sha(FRESH_RECEIPT) != FRESH_RECEIPT_SHA:
        raise ValueError('fresh Phase 1 receipt SHA changed')
    row = json.loads(FRESH_RECEIPT.read_text(encoding='utf-8'))
    source, worklist = Path(row['source_run']), Path(row['worklist_path'])
    _plain(source, directory=True)
    _plain(worklist)
    if (row.get('status') != 'FRESH_UNSCANNED_PHASE1' or
            source.parent != FRESH_RECEIPT.parent / 'product_runs' or
            worklist != FRESH_RECEIPT.parent / 'md4c_development_worklist.json' or
            sha(worklist) != row.get('worklist_sha256') or
            (source / 'scan.json').exists() or
            (source / 'scan.json').is_symlink()):
        raise ValueError('fresh Phase 1 or Worker-pinned worklist changed')
    source_row = json.loads((source / 'run.json').read_text(encoding='utf-8'))
    work = json.loads(worklist.read_text(encoding='utf-8'))
    required_work_pins = ('run.json', 'harness.json', 'workers.json',
                          'directions.json', 'function_pool.json',
                          'direction_plan.json')
    if (source_row.get('direction_plan_sha256') != row['direction_plan_sha256'] or
            source_row.get('selection_policy') != 'FBV2_FIRST_PASS_UNIQUE_DEV' or
            source_row.get('source_kind') != 'official_oss_fuzz' or
            source_row.get('direction_source_kind') != 'PINNED_MODEL_PROPOSAL' or
            work.get('kind') != 'FBV2_FOUR_PHASE_DEVELOPMENT_WORKLIST_V1' or
            work.get('history_status') != 'NO_PRIOR_ANALYSIS_RECORDED' or
            any(work.get('input_hashes', {}).get(name) != sha(source / name)
                for name in required_work_pins)):
        raise ValueError('fresh Phase 1 provenance changed')
    return source, worklist, row


def _file_pins(source: Path, worklist: Path) -> dict[str, str]:
    paths = (FRESH_RECEIPT, worklist,
             *(source / name for name in SOURCE_FILES), *_saved_files())
    result: dict[str, str] = {}
    for path in paths:
        _plain(path)
        rel = path.relative_to(ROOT).as_posix()
        if rel in result:
            raise ValueError('duplicate one-work-item input pin')
        result[rel] = sha(path)
    direction = json.loads((SAVED_DIRECTION / 'DIRECTION_PHASE1_RESULT.json').read_text())
    if (direction.get('direction_plan_sha256') != sha(source / 'direction_plan.json') or
            direction.get('direction_raw_sha256') != sha(SAVED_DIRECTION / 'DIRECTION_RAW.txt') or
            direction.get('direction_request_sha256') != sha(SAVED_DIRECTION / 'DIRECTION_REQUEST.json') or
            direction.get('direction_physical_starts', 0) < 1):
        raise ValueError('saved Direction model provenance differs')
    return result


def _full() -> Any:
    sys.path.insert(0, str(EVALUATION))
    import blind3_md4c_live_full_candidate_supervised_dev as full
    return full


def _base() -> Any:
    sys.path.insert(0, str(EVALUATION))
    import dev_live_direction_sp_hp_supervisor as base
    return base


def _source_bootstrap() -> None:
    if (globals().get('__VA_SOURCE_BOOTSTRAP_SHA__') != sha(Path(__file__)) or
            sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('official component requires externally pinned isolated Python')


def _budget(value: dict) -> Any:
    return _full()._budget(value)


def prepare(output: Path, budget: dict) -> tuple[Path, str]:
    """Pin one fresh job and official inputs without a model request."""
    output = Path(output)
    if (not output.is_absolute() or output.parent != REVIEW or output.exists() or
            output.is_symlink() or any(p.is_symlink() for p in output.parents)):
        raise ValueError('official output must be a fresh Linux review directory')
    if budget != PROBE_BUDGET:
        raise ValueError('separate PoV probe requires the predeclared exact budget')
    _budget(budget)
    source, worklist, fresh = _fresh_inputs()
    first_run = source.parent / 'stage8-pov-budget-probe'
    if first_run.exists() or first_run.is_symlink():
        raise ValueError('four-phase first work item was already started')
    code = _code_pins()
    files = _file_pins(source, worklist)
    base = _base()
    full = _full()
    contract, config, executable, routes = full._contract_routes(base)
    routes = {key: routes[key] for key in ROLES}
    os.umask(0o077)
    output.mkdir(mode=0o700)
    identity = output.stat()
    row = {
        'kind': KIND, 'scope': 'OFFICIAL_V2_ONE_WORK_ITEM_MODEL_ONLY_DEV',
        'execution_boundary': ('NO_TARGET_BINARY_OR_FUZZER; '
            'protected input-generator/compiler helpers may execute'),
        'output_dir': str(output),
        'output_identity': {'dev': identity.st_dev, 'ino': identity.st_ino},
        'source_run': str(source), 'worklist_path': str(worklist),
        'worklist_sha256': fresh['worklist_sha256'],
        'first_run': str(first_run), 'saved_direction_source': str(SAVED_DIRECTION),
        'direction_source': 'SAVED_MODEL_PLAN_NOT_NEW_MODEL_START',
        'file_pins': files, 'source_pins': {
            key: _tree_digest(path, None) for key, path in (
                ('artifact', ARTIFACT), ('target', TARGET),
                ('oss_fuzz', OSS_FUZZ), ('upstream', UPSTREAM))},
        'code_pins': code, 'driver_sha256': sha(Path(__file__)),
        'full_candidate_source_sha256': sha(Path(full.__file__)),
        'supervisor_source_sha256': sha(Path(base.__file__)),
        'contract_sha256': sha(CONTRACT), 'codex_config_sha256': sha(config),
        'codex_executable_sha256': sha(executable),
        'python_path': '/usr/bin/python3.12',
        'python_sha256': sha(Path('/usr/bin/python3.12')),
        'role_models': routes, 'route_sha256': contract['route_sha256'],
        'global_budget': budget,
        'physical_resource_seconds': budget['wall_seconds'],
    }
    path = output / SPEC_NAME
    base._write_once(path, row)
    return path, sha(path)


def load_spec(path: Path, expected_sha256: str, *, started: bool = False) -> dict:
    """Check all relevant bytes before any product/evaluation helper import."""
    path = Path(path)
    _plain(path)
    if (not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)
            or sha(path) != expected_sha256):
        raise ValueError('one-work-item spec SHA changed')
    row = json.loads(path.read_text(encoding='utf-8'))
    required = {'kind', 'scope', 'output_dir', 'output_identity',
                'execution_boundary',
                'source_run', 'worklist_path', 'worklist_sha256', 'first_run',
                'saved_direction_source', 'direction_source', 'file_pins',
                'source_pins', 'code_pins', 'driver_sha256',
                'full_candidate_source_sha256', 'supervisor_source_sha256',
                'contract_sha256', 'codex_config_sha256',
                'codex_executable_sha256', 'python_path', 'python_sha256',
                'role_models', 'route_sha256', 'global_budget',
                'physical_resource_seconds'}
    if (not isinstance(row, dict) or set(row) != required or
            row['kind'] != KIND or
            row['scope'] != 'OFFICIAL_V2_ONE_WORK_ITEM_MODEL_ONLY_DEV' or
            row['execution_boundary'] != ('NO_TARGET_BINARY_OR_FUZZER; '
                'protected input-generator/compiler helpers may execute') or
            row['direction_source'] != 'SAVED_MODEL_PLAN_NOT_NEW_MODEL_START' or
            row['saved_direction_source'] != str(SAVED_DIRECTION) or
            row['driver_sha256'] != sha(Path(__file__)) or
            row['full_candidate_source_sha256'] !=
                sha(EVALUATION / 'blind3_md4c_live_full_candidate_supervised_dev.py') or
            row['supervisor_source_sha256'] !=
                sha(EVALUATION / 'dev_live_direction_sp_hp_supervisor.py') or
            row['python_path'] != '/usr/bin/python3.12' or
            row['python_sha256'] != sha(Path('/usr/bin/python3.12')) or
            row['global_budget'] != PROBE_BUDGET or
            row['physical_resource_seconds'] != row['global_budget']['wall_seconds']):
        raise ValueError('one-work-item spec shape or executable changed')
    current_code_pins = _code_pins()
    if row['code_pins'] != current_code_pins:
        raise ValueError('one-work-item code changed before helper imports')
    _budget(row['global_budget'])
    output = Path(row['output_dir'])
    _private(output)
    identity = output.stat()
    source, worklist, fresh = _fresh_inputs()
    if (path != output / SPEC_NAME or output.parent != REVIEW or
            row['output_identity'] != {'dev': identity.st_dev, 'ino': identity.st_ino} or
            row['source_run'] != str(source) or
            row['worklist_path'] != str(worklist) or
            row['worklist_sha256'] != fresh['worklist_sha256'] or
            row['first_run'] != str(source.parent / 'stage8-pov-budget-probe') or
            row['file_pins'] != _file_pins(source, worklist) or
            row['source_pins'] != {key: _tree_digest(value, None)
                for key, value in (('artifact', ARTIFACT), ('target', TARGET),
                                   ('oss_fuzz', OSS_FUZZ), ('upstream', UPSTREAM))}):
        raise ValueError('one-work-item source, code or worklist changed')
    first = Path(row['first_run'])
    if not started and (first.exists() or first.is_symlink() or any(
            (output / name).exists() or (output / name).is_symlink()
            for name in (MODEL_NAME, PHYSICAL_NAME, CHILD_NAME,
                         'DEV_LIVE_SUPERVISOR_RESULT.json'))):
        raise ValueError('one-work-item attempt already started')
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    config = ROOT / contract['codex_config']
    executable = Path(contract['codex_executable_path'])
    for file, digest in ((CONTRACT, row['contract_sha256']),
                         (config, row['codex_config_sha256']),
                         (executable, row['codex_executable_sha256'])):
        _plain(file)
        if sha(file) != digest:
            raise ValueError('one-work-item contract or route changed')
    base, full = _base(), _full()
    pinned_contract, _config, _executable, routes = full._contract_routes(base)
    if (pinned_contract['route_sha256'] != row['route_sha256'] or
            {key: routes[key] for key in ROLES} != row['role_models'] or
            row['code_pins'] != base._code_pins()):
        raise ValueError('one-work-item loaded helper or model route changed')
    return row


def offline_preflight(row: dict) -> dict:
    """Exercise the real official V2 route with zero model/Target calls."""
    base, full = _base(), _full()
    output = Path(row['output_dir'])
    with base._preflight_cache(output):
        contract, config, executable, routes = full._contract_routes(base)
        base._route_pinned_codex(contract)
        runner, *_ = base._imports()
        runner.verify_loaded_module_origins(sys.modules, EVALUATION, PRODUCT / 'src')
        runner.check_zero_retry_config(config, contract['default_model'],
                                       contract['default_effort'])
        runner.verify_pinned_codex_executable(contract)
        qualified = runner.require_official_qualification(contract)
        from blind3_md4c_live_direction_sp_hp_dev import _official_preflight
        _official_preflight(ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, qualified)
        return {'status': 'OFFICIAL_PREFLIGHT_PASS_NO_MODEL_CALL',
                'spec_sha256': sha(output / SPEC_NAME),
                'official_v2_qualified': True, 'actual_model_calls': 0,
                'target_runs': 0, 'fuzz_seconds': 0,
                'source_run': row['source_run'],
                'worklist_sha256': row['worklist_sha256'],
                'role_models': row['role_models']}


async def _run_child(row: dict, spec_sha256: str) -> dict:
    """Real-model-capable only after external SHA bootstrap and supervisor."""
    _source_bootstrap()
    if load_spec(Path(row['output_dir']) / SPEC_NAME, spec_sha256) != row:
        raise ValueError('official one-work-item pins changed before imports')
    base, full = _base(), _full()
    contract, config, executable, routes = full._contract_routes(base)
    base._route_pinned_codex(contract)
    runner, _, AppServer, _, Ledger = base._imports()
    from dev_blind3_live_campaign_adapter import run_one_development_work_item
    from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
    from blind3_md4c_live_direction_sp_hp_dev import _official_preflight
    runner.verify_loaded_module_origins(sys.modules, EVALUATION, PRODUCT / 'src')
    runner.check_zero_retry_config(config, contract['default_model'],
                                   contract['default_effort'])
    runner.verify_pinned_codex_executable(contract)
    official = runner.require_official_qualification(contract)
    _official_preflight(ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, official)
    output = Path(row['output_dir'])
    model_cwd = output / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    _private(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('model cwd was not empty')
    base._write_once(output / 'OFFICIAL_V2_PRECHECK.json', {
        'spec_sha256': spec_sha256,
        'official_v2_qualified': True,
        'saved_direction_sha256': row['file_pins'][
            (SAVED_DIRECTION / 'DIRECTION_PHASE1_RESULT.json').relative_to(ROOT).as_posix()],
        'direction_source': row['direction_source'],
        'worklist_sha256': row['worklist_sha256']})
    budget = _budget(row['global_budget'])
    model = Ledger.create(budget, output / MODEL_NAME)
    physical = PersistentPhysicalFuzzLedger.create(
        output / PHYSICAL_NAME, total_seconds=row['physical_resource_seconds'])
    with runner.private_codex_state(config):
        direction = full._direction()
        sandbox = runner.verify_model_namespace_sandbox(
            executable, direction._official_protected_paths(runner, contract))
        base._write_once(output / 'SANDBOX_SELF_TEST.json', sandbox)
        backend = AppServer(
            ledger=model, physical_ledger=physical,
            role_models=row['role_models'], cwd=model_cwd, wire_cwd='/work',
            launch_prefix=[sys.executable,
                str(EVALUATION / 'blind2_model_sandbox.py')],
            executable=str(executable),
            executable_sha256=contract['codex_executable_sha256'],
            model=contract['default_model'], effort=contract['default_effort'],
            timeout_seconds=300, event_log_path=output / 'MODEL_EVENTS.jsonl')
        backend.retry_route_check = lambda: runner.check_live_route(
            backend, row['route_sha256'], routes)
        async with backend:
            await asyncio.wait_for(runner.check_live_route(
                backend, row['route_sha256'], routes), timeout=120)
            result = await run_one_development_work_item(
                source_run=Path(row['source_run']),
                worklist_path=Path(row['worklist_path']),
                expected_worklist_sha256=row['worklist_sha256'],
                first_run=Path(row['first_run']),
                target_repository=TARGET, target_binary=official.binary,
                official_qualification=official, backend=backend,
                model_ledger=model, physical_ledger=physical,
                role_models=row['role_models'])
    _official_preflight(ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, official)
    if load_spec(output / SPEC_NAME, spec_sha256, started=True) != row:
        raise ValueError('official component sources changed after model turns')
    restored = Ledger.restore(model.checkpoint_path, budget)
    if (restored.physical != model.physical or
            restored.logical != model.logical or
            restored.retries != model.retries or restored.tainted or
            restored.active_turn is not None or
            backend.forbidden_tool_event or
            (backend.audit_log_failed and result.get('status') == 'SCAN_RECORDED') or
            backend.provider_safety_refused or
            result.get('target_runs') != 0 or result.get('fuzz_seconds') != 0 or
            result.get('direction_source') !=
                'PINNED_PLAN_INPUT_UNACCOUNTED_IN_THIS_LEDGER'):
        raise ValueError('official component model ledger or no-Target scope changed')
    model_events_state, model_events_sha = _model_event_evidence(
        backend.event_log_path, result['status'])
    stopped_before_target = result['status'] == 'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN'
    reached_pov = (
        result['status'] in {'SCAN_RECORDED', 'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN',
                             'INCOMPLETE_PENDING_WORK'}
        and _completed_pov_chain(json.loads(model.checkpoint_path.read_text()),
                                 result['work_item_id'])
        and model_events_sha is not None and not backend.audit_log_failed
    )
    component_status = ('POV_MODEL_REACHED_NO_TARGET' if reached_pov else
                        'MODEL_TRACE_INCOMPLETE')
    receipt = {'kind': KIND, 'status': result['status'],
               'component_status': component_status,
               'stopped_before_target': stopped_before_target,
               'scope': row['scope'], 'spec_sha256': spec_sha256,
               'execution_boundary': row['execution_boundary'],
               'official_v2_qualified': True,
               'analysis_complete': result['analysis_complete'],
               'direction_source': row['direction_source'],
               'worklist_sha256': row['worklist_sha256'],
               'work_item_id': result['work_item_id'],
               'selected_function_id': result['selected_function_id'],
               'model_physical_starts': model.physical,
               'model_logical_turns': model.logical,
               'model_retries': model.retries,
               'model_ledger_sha256': sha(model.checkpoint_path),
               'physical_ledger_sha256': sha(physical.path),
               'model_events_sha256': model_events_sha,
               'model_events_state': model_events_state,
               'model_audit_failed': backend.audit_log_failed,
               'scan_sha256': result.get('scan_sha256'),
               'terminal_sha256': result.get('terminal_sha256'),
               'target_runs': 0, 'fuzz_seconds': 0,
               'vulnerability_verdict': 'NOT_EVALUATED'}
    base._write_once(output / RECEIPT_NAME, receipt)
    child = {'kind': KIND, 'status': component_status,
             'spec_sha256': spec_sha256,
             'stopped_before_target': stopped_before_target,
             'receipt_sha256': sha(output / RECEIPT_NAME),
             'model_ledger_sha256': receipt['model_ledger_sha256'],
             'physical_ledger_sha256': receipt['physical_ledger_sha256'],
             'model_events_sha256': receipt['model_events_sha256'],
             'model_events_state': model_events_state,
             'model_physical_starts': model.physical,
             'model_logical_turns': model.logical,
             'target_runs': 0, 'fuzz_seconds': 0}
    base._write_once(output / CHILD_NAME, child)
    return child


def _completed_pov_chain(model: dict, work_item_id: str) -> bool:
    """A PoV claim needs a saved turn; callers must restore/validate the ledger."""
    if (model.get('direction_counts') != {} or
            model.get('selected_functions') != [work_item_id] or
            model.get('function_states', {}).get(work_item_id) not in
                {'SELECTED_NOT_STARTED', 'SCAN_RECORDED'} or
            model.get('active_turn') is not None or
            model.get('retries', 0) != 0):
        return False
    turns, attempts = model.get('turns'), model.get('attempts')
    if (not isinstance(turns, list) or not isinstance(attempts, list) or
            len(turns) != len(attempts) or len(turns) < 4):
        return False
    roles = []
    for turn, attempt in zip(turns, attempts, strict=True):
        if (not isinstance(turn, dict) or turn.get('scope_id') != work_item_id or
                turn.get('status') != 'COMPLETED' or
                turn.get('role') not in ROLES or
                not isinstance(attempt, dict) or
                attempt.get('turn_id') != turn.get('id') or
                attempt.get('scope_id') != work_item_id or
                attempt.get('role') != turn.get('role') or
                attempt.get('status') != 'COMPLETED' or
                attempt.get('accepted') is not True or
                attempt.get('response_saved') is not True or
                attempt.get('retry') is not False or
                attempt.get('internal_retry') is not False or
                not isinstance(attempt.get('app_server_turn_id'), str) or
                not attempt['app_server_turn_id']):
            return False
        roles.append(turn['role'])
    return ({'sp_generation', 'function_analysis', 'sp_verifier',
             'poc_generator'} <= set(roles) and
            roles.index('sp_generation') < roles.index('sp_verifier') <
            roles.index('poc_generator'))


def _verified_parent_trace(row: dict, receipt: dict) -> bool:
    """Recheck PoV, events and requests even when Target guard stopped Scan."""
    run = Path(row['first_run'])
    _plain(run, directory=True)
    sys.path[:0] = [str(EVALUATION), str(PRODUCT / 'src')]
    from vulnerabilityanalysis.workflow import (validate_four_phase_dev_selection,
        verify_four_phase_terminal_marker, require_four_phase_continuable_scan)
    from dev_global_request_ledger import DevelopmentRequestLedger
    from dev_global_appserver_bridge import (verify_model_event_order,
                                             verify_product_request_order)
    run_row, selection, item = validate_four_phase_dev_selection(run)
    if (item['work_item_id'] != receipt.get('work_item_id') or
            selection['function_id'] != receipt.get('selected_function_id')):
        return False
    complete = receipt.get('status') == 'SCAN_RECORDED'
    target_blocked = (receipt.get('status') ==
                      'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN' and
                      receipt.get('stopped_before_target') is True)
    pending = (receipt.get('status') == 'INCOMPLETE_PENDING_WORK' and
               receipt.get('stopped_before_target') is False)
    if not (complete or target_blocked or pending):
        return False
    if (receipt.get('analysis_complete') is not complete or
            receipt.get('model_events_state') !=
                ('VERIFIED_COMPLETE' if complete else 'PRESENT_INCOMPLETE')):
        return False
    scan_path = run / 'scan.json'
    marker_path = run / 'four_phase_scan_complete.json'
    if scan_path.exists() or scan_path.is_symlink():
        _plain(scan_path)
        if sha(scan_path) != receipt.get('scan_sha256'):
            return False
        scan = json.loads(scan_path.read_text(encoding='utf-8'))
        if (scan.get('four_phase_work_item_id') != item['work_item_id'] or
                scan.get('selected_function_id') != selection['function_id']):
            return False
        if complete:
            require_four_phase_continuable_scan(scan)
        if pending and (scan.get('poc_count', 0) < 1 or
                        not isinstance(scan.get('pending_sp_ids'), list) or
                        not scan['pending_sp_ids']):
            return False
    elif complete or pending or receipt.get('scan_sha256') is not None:
        return False
    if marker_path.exists() or marker_path.is_symlink():
        if not scan_path.is_file():
            return False
        _plain(marker_path)
        if (sha(marker_path) != receipt.get('terminal_sha256') or
                verify_four_phase_terminal_marker(run, run_row, item) is None):
            return False
    elif complete or pending or receipt.get('terminal_sha256') is not None:
        return False
    if complete and receipt.get('stopped_before_target') is not False:
        return False
    model = DevelopmentRequestLedger.restore(
        Path(row['output_dir']) / MODEL_NAME, _budget(row['global_budget']))
    if model.tainted or model.active_turn is not None:
        return False
    if not _completed_pov_chain(json.loads(model.checkpoint_path.read_text()),
                                item['work_item_id']):
        return False
    verify_model_event_order(model, Path(row['output_dir']) / 'MODEL_EVENTS.jsonl')
    request_rows = run / 'logs/agent_requests.jsonl'
    _plain(request_rows)
    artifacts = []
    for line in request_rows.read_text(encoding='utf-8').splitlines():
        request = Path(json.loads(line)['request_artifact'])
        if not request.is_relative_to(run):
            return False
        _plain(request)
        artifacts.append(request)
    verify_product_request_order(model, artifacts, scope_id=item['work_item_id'])
    return True


def _completion(child: dict, fd: int, output: Path, expected: str,
                row: dict) -> bool:
    """Confirm one PoV model turn, never promote partial Scan to completion."""
    if (not isinstance(child, dict) or child.get('kind') != KIND or
            child.get('status') != 'POV_MODEL_REACHED_NO_TARGET' or
            child.get('spec_sha256') != expected or
            child.get('model_events_state') not in
                {'VERIFIED_COMPLETE', 'PRESENT_INCOMPLETE'} or
            type(child.get('stopped_before_target')) is not bool or
            child.get('target_runs') != 0 or child.get('fuzz_seconds') != 0 or
            type(child.get('model_physical_starts')) is not int or
            child['model_physical_starts'] < 4):
        return False
    def read(name: str) -> bytes:
        file_fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                          dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('one-work-item evidence is not regular')
            if metadata.st_size > 2_000_000:
                raise ValueError('one-work-item evidence too large')
            return stream.read()
    receipt_bytes = read(RECEIPT_NAME)
    if hashlib.sha256(receipt_bytes).hexdigest() != child.get('receipt_sha256'):
        return False
    receipt = json.loads(receipt_bytes)
    complete = receipt.get('status') == 'SCAN_RECORDED'
    guarded = receipt.get('status') == 'INCOMPLETE_TARGET_EXECUTION_FORBIDDEN'
    pending = receipt.get('status') == 'INCOMPLETE_PENDING_WORK'
    if (not (complete or guarded or pending) or
            receipt.get('component_status') != 'POV_MODEL_REACHED_NO_TARGET' or
            receipt.get('stopped_before_target') is not guarded or
            child.get('stopped_before_target') is not guarded or
            receipt.get('analysis_complete') is not complete or
            receipt.get('official_v2_qualified') is not True or
            receipt.get('spec_sha256') != expected or
            receipt.get('execution_boundary') != row['execution_boundary'] or
            receipt.get('model_events_state') !=
                ('VERIFIED_COMPLETE' if complete else 'PRESENT_INCOMPLETE') or
            child.get('model_events_state') != receipt.get('model_events_state') or
            receipt.get('model_audit_failed') is not False or
            receipt.get('worklist_sha256') != row['worklist_sha256'] or
            receipt.get('model_physical_starts') != child['model_physical_starts'] or
            receipt.get('target_runs') != 0 or receipt.get('fuzz_seconds') != 0):
        return False
    def digest_file(name: str) -> str:
        file_fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                          dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('one-work-item evidence is not regular')
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    for name, key in ((MODEL_NAME, 'model_ledger_sha256'),
                      (PHYSICAL_NAME, 'physical_ledger_sha256'),
                      ('MODEL_EVENTS.jsonl', 'model_events_sha256')):
        digest = digest_file(name)
        if child.get(key) != digest or receipt.get(key) != digest:
            return False
    physical = json.loads(read(PHYSICAL_NAME))
    model = json.loads(read(MODEL_NAME))
    if (physical.get('active') != {} or
            physical.get('stop_status') is not None):
        return False
    from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
    restored_physical = PersistentPhysicalFuzzLedger.restore(
        Path(row['output_dir']) / PHYSICAL_NAME,
        total_seconds=row['physical_resource_seconds']).snapshot()
    return (physical.get('active') == {} and
            physical.get('stop_status') is None and
            restored_physical['spent_seconds'] == 0 and
            restored_physical['finished'] == [] and
            model.get('physical') == child['model_physical_starts'] and
            _completed_pov_chain(model, receipt.get('work_item_id')) and
            _verified_parent_trace(row, receipt) and
            receipt.get('direction_source') ==
                'SAVED_MODEL_PLAN_NOT_NEW_MODEL_START')


def run_supervised(spec: Path, expected_sha256: str) -> dict:
    """Explicit externally SHA-bootstrapped entry; never automatic."""
    _source_bootstrap()
    row = load_spec(spec, expected_sha256)
    output = Path(row['output_dir'])
    base, full = _base(), _full()
    contract, _config, _executable, _routes = full._contract_routes(base)
    base._route_pinned_codex(contract)
    runner, *_ = base._imports()
    base._fresh_cache(output, 'parent_pycache')
    child_cache = output / 'child_pycache'
    child_cache.mkdir(mode=0o700)
    _private(child_cache)
    command = [row['python_path'], '-I', '-B', '-X',
               f'pycache_prefix={child_cache}', '-c', base.INLINE_BOOTSTRAP,
               str(Path(__file__).resolve()), row['driver_sha256'],
               '--child', str(spec), expected_sha256]
    if load_spec(spec, expected_sha256) != row:
        raise ValueError('one-work-item pins changed before child launch')
    validation_error: str | None = None
    def completion_fail_closed(child: dict, fd: int, held: Path) -> bool:
        nonlocal validation_error
        try:
            return _completion(child, fd, held, expected_sha256, row)
        except Exception as exc:
            validation_error = type(exc).__name__
            return False
    supervised = base.supervise_command(
        command, output, wall_seconds=row['global_budget']['wall_seconds'],
        runner=runner, spec_sha256=expected_sha256,
        completion_predicate=completion_fail_closed,
        expected_output_identity=(row['output_identity']['dev'],
                                  row['output_identity']['ino']))
    if load_spec(spec, expected_sha256, started=True) != row:
        raise ValueError('one-work-item pins changed after supervision')
    base._write_once(output / SUPERVISION_NAME, {
        'kind': KIND, 'spec_sha256': expected_sha256,
        'supervisor_result_sha256': sha(output / base.RESULT_NAME),
        'supervisor_status': supervised['status'],
        'completion_validation_error_type': validation_error,
        'child_result': supervised['child_result'],
        'physical_ledger': supervised['physical_ledger'],
        'vulnerability_verdict': 'NOT_EVALUATED'})
    return supervised


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--preflight-only', action='store_true')
    group.add_argument('--run-live', action='store_true')
    group.add_argument('--child', action='store_true')
    parser.add_argument('--physical-max', type=int)
    parser.add_argument('--logical-max', type=int)
    parser.add_argument('--retries-max', type=int)
    parser.add_argument('--wall-seconds', type=float)
    parser.add_argument('--initial-starts-required', type=int)
    parser.add_argument('path', type=Path)
    parser.add_argument('sha256', nargs='?')
    args = parser.parse_args(argv)
    if (sys.executable != '/usr/bin/python3.12' or not sys.flags.isolated or
            not sys.dont_write_bytecode):
        raise ValueError('use /usr/bin/python3.12 -I -B')
    if args.child:
        cache = args.path.parent / 'child_pycache'
        _private(cache)
        if sys.pycache_prefix != str(cache) or any(cache.iterdir()):
            raise ValueError('one-work-item child import cache changed')
    else:
        cache = Path(tempfile.mkdtemp(prefix='va-official-one-job-cache-'))
        cache.chmod(0o700)
        if any(cache.iterdir()):
            raise ValueError('one-work-item fresh import cache not empty')
        sys.pycache_prefix = str(cache)
        os.environ['PYTHONPYCACHEPREFIX'] = str(cache)
        atexit.register(shutil.rmtree, cache, ignore_errors=True)
    if args.prepare:
        if any(value is None for value in (args.physical_max, args.logical_max,
                args.retries_max, args.wall_seconds,
                args.initial_starts_required)):
            raise ValueError('explicit development budget required')
        budget = {'physical_max': args.physical_max,
                  'logical_max': args.logical_max,
                  'retries_max': args.retries_max,
                  'wall_seconds': args.wall_seconds,
                  'initial_starts_required': args.initial_starts_required}
        spec, digest = prepare(args.path, budget)
        print(json.dumps({'status': 'PREPARED_NO_MODEL_CALL',
                          'spec': str(spec), 'sha256': digest}))
        return 0
    if not args.sha256:
        parser.error('externally reviewed spec SHA-256 is required')
    if args.run_live or args.child:
        _source_bootstrap()
    row = load_spec(args.path, args.sha256, started=args.child)
    if args.preflight_only:
        print(json.dumps(offline_preflight(row), sort_keys=True))
        return 0
    if args.child:
        try:
            asyncio.run(_run_child(row, args.sha256))
        except BaseException as exc:
            base = _base()
            output = Path(row['output_dir'])
            try:
                base._write_once(output / 'OFFICIAL_ONE_WORK_ITEM_STOP.json', {
                    'kind': KIND, 'status': 'STOPPED',
                    'error_type': type(exc).__name__,
                    'spec_sha256': args.sha256,
                    'model_ledger': base._evidence(output / MODEL_NAME),
                    'physical_ledger': base._evidence(output / PHYSICAL_NAME),
                    'model_events': base._evidence(output / 'MODEL_EVENTS.jsonl')})
            except BaseException:
                pass
            raise
        return 0
    result = run_supervised(args.path, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
