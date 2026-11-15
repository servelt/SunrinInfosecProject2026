"""Pinned official V2 one-function live-model *development* component route.

Prepare and preflight do not contact a provider. Live use requires an external
SHA-pinned bootstrap and the existing subreaper supervisor. A completed receipt
means that model-stage evidence was recorded, not that a bug was found or that
Blind 3 is authorized. Target, Assertion, Runtime, Fuzzer and Gate execution
are blocked in this route; a PoV model may still propose an input.
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'review'
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
CONTRACT = ROOT / 'tools/FROZEN_CONTRACT_ATTEMPT3.json'
ARTIFACT = ROOT / 'v2_artifact_stage/attempt'
TARGET = ROOT / 'model_target'
OSS_FUZZ = ROOT / 'oss_fuzz_checkout'
UPSTREAM = ROOT / 'upstream_asan_final'
SUPERVISOR = ROOT / 'evaluation_tools/dev_live_direction_sp_hp_supervisor.py'
DIRECTION = ROOT / 'evaluation_tools/blind3_md4c_direction_supervised_dev.py'
SPEC_NAME = 'OFFICIAL_V2_LIVE_CANDIDATE_SPEC.json'
RECEIPT_NAME = 'OFFICIAL_V2_LIVE_CANDIDATE_RECEIPT.json'
STOP_NAME = 'OFFICIAL_V2_LIVE_CANDIDATE_STOP.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
LEDGER_NAME = 'GLOBAL_LEDGER.json'
SUPERVISION_NAME = 'OFFICIAL_V2_LIVE_CANDIDATE_SUPERVISION.json'
HEX = re.compile(r'[0-9a-f]{64}\Z')
ROLES = frozenset({'direction_generator', 'sp_generation',
    'function_analysis', 'assertion_generator', 'sp_verifier', 'poc_generator'})
SOURCE_MODES = frozenset({'all_catalog_prefix', 'stratified_callsite_800'})
KIND = 'BLIND3_MD4C_LIVE_FULL_CANDIDATE_DEV_V1'
SCOPE = ('official V2 one-function model stages only; no target, fuzzing, '
         'Gate, or Blind 3 authorization')


def _direction_evidence(direction: dict) -> dict:
    fields = ('direction_turn_count', 'direction_request_sha256',
              'direction_raw_sha256', 'direction_repair_request_sha256',
              'direction_repair_raw_sha256', 'direction_repair_status_sha256',
              'direction_logical_turn_id', 'direction_physical_starts')
    return {key: direction.get(key) for key in fields}


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _tree_digest_before_import(root: Path, suffixes: set[str] | None) -> str:
    """Match the supervisor's byte digest using stdlib before importing it."""
    if (not root.is_absolute() or root.is_symlink() or
            any(parent.is_symlink() for parent in root.parents) or
            root.resolve(strict=True) != root or not root.is_dir()):
        raise ValueError('pre-import code root missing or linked')
    entries = []
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        if any((base / name).is_symlink() for name in names):
            raise ValueError('pre-import linked code directory')
        for name in files:
            path = base / name
            if path.is_symlink():
                raise ValueError('pre-import linked code file')
            if path.suffix in {'.so', '.pyd', '.dll', '.dylib'}:
                raise ValueError('pre-import native code extension')
            if path.suffix == '.pyc':
                if path.parent.name != '__pycache__' or '.cpython-' not in name:
                    raise ValueError('pre-import loose bytecode')
                source = path.parent.parent / (name.split('.cpython-', 1)[0] + '.py')
                if not source.is_file() or source.is_symlink():
                    raise ValueError('pre-import sourceless bytecode')
                continue
            if suffixes is None or path.suffix in suffixes:
                entries.append((path.relative_to(root).as_posix(), sha(path)))
    if not entries:
        raise ValueError('pre-import code tree empty')
    return hashlib.sha256(json.dumps(sorted(entries), separators=(',', ':'),
        ensure_ascii=False).encode()).hexdigest()


def _check_code_before_import(pins: Any) -> None:
    if not isinstance(pins, dict):
        raise ValueError('pre-import code pin map missing')
    trees = {
        'product_src': (PRODUCT / 'src', {'.py'}),
        'product_prompts': (PRODUCT / 'prompts', {'.md'}),
        'product_config': (PRODUCT / 'config', {'.yaml', '.yml'}),
        'product_tests': (PRODUCT / 'tests', {'.py'}),
        'evaluation_tools': (ROOT / 'evaluation_tools', {'.py'}),
        'review_tools': (ROOT / 'review_tools', {'.py'}),
    }
    if (set(pins) != {*trees, 'product_pyproject'} or
            pins['product_pyproject'] != sha(PRODUCT / 'pyproject.toml')):
        raise ValueError('pre-import product pin changed')
    for name, (path, suffixes) in trees.items():
        if pins[name] != _tree_digest_before_import(path, suffixes):
            raise ValueError(f'pre-import code tree changed: {name}')


def _base() -> Any:
    sys.path.insert(0, str(ROOT / 'evaluation_tools'))
    import dev_live_direction_sp_hp_supervisor as base
    return base


def _direction() -> Any:
    sys.path.insert(0, str(ROOT / 'evaluation_tools'))
    import blind3_md4c_direction_supervised_dev as direction
    return direction


def _require_external_source_pin() -> None:
    if (globals().get('__VA_SOURCE_BOOTSTRAP_SHA__') != sha(Path(__file__)) or
            sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('live component requires external source pin and isolated Python')


def _fresh_import_cache(*, child_output: Path | None = None) -> None:
    """Set an empty Python bytecode lookup root before non-stdlib imports."""
    if child_output is not None:
        cache = child_output / 'child_pycache'
        if (sys.pycache_prefix != str(cache) or cache.is_symlink() or
                not cache.is_dir() or
                stat.S_IMODE(cache.stat().st_mode) != 0o700 or
                any(cache.iterdir())):
            raise ValueError('child dedicated Python cache changed before imports')
        return
    cache = Path(tempfile.mkdtemp(prefix='va-live-component-pycache-'))
    cache.chmod(0o700)
    if any(cache.iterdir()):
        raise ValueError('fresh Python import cache not empty')
    sys.pycache_prefix = str(cache)
    os.environ['PYTHONPYCACHEPREFIX'] = str(cache)
    atexit.register(shutil.rmtree, cache, ignore_errors=True)


def _contract_routes(base: Any) -> tuple[dict, Path, Path, dict]:
    direction = _direction()
    contract, config, executable = direction._pinned_contract(base)
    if (contract.get('artifact') != ARTIFACT.relative_to(ROOT).as_posix() or
            contract.get('target_repository') != TARGET.relative_to(ROOT).as_posix() or
            contract.get('oss_fuzz_checkout') != OSS_FUZZ.relative_to(ROOT).as_posix() or
            contract.get('upstream_checkout') != UPSTREAM.relative_to(ROOT).as_posix()):
        raise ValueError('official V2 source routes changed')
    sys.path.insert(0, str(PRODUCT / 'src'))
    import yaml
    config_row = yaml.safe_load((PRODUCT / 'config/default.yaml').read_text())
    configured = config_row.get('models') if isinstance(config_row, dict) else None
    frozen = contract.get('role_models')
    if not isinstance(configured, dict) or not isinstance(frozen, dict):
        raise ValueError('model role map unavailable')
    routes = {role: configured.get(role) for role in ROLES}
    if (any(not isinstance(route, dict) or set(route) != {'model', 'reasoning'} or
            any(not isinstance(value, str) or not value for value in route.values())
            for route in routes.values()) or
            any(routes[role] != frozen.get(role) for role in ROLES
                if role != 'direction_generator')):
        raise ValueError('development role routes differ from product or frozen contract')
    return contract, config, executable, routes


def _sources(base: Any, source_mode: str) -> tuple[dict, dict]:
    if source_mode not in SOURCE_MODES:
        raise ValueError('unreviewed Direction source mode')
    context, pins = _direction()._source_context(source_mode)
    return context, pins


def _budget(value: dict, *, direction_turn_cap: int = 1) -> Any:
    sys.path.insert(0, str(ROOT / 'evaluation_tools'))
    from dev_global_request_ledger import DevelopmentBudget, GLOBAL_ONLY_DEV_PROFILE
    if (direction_turn_cap not in (1, 2) or type(direction_turn_cap) is not int or
            not isinstance(value, dict) or
            set(value) != {'physical_max', 'logical_max', 'retries_max',
                           'wall_seconds', 'initial_starts_required'} or
            type(value['initial_starts_required']) is not int or
            type(value['physical_max']) is not int or
            type(value['logical_max']) is not int or
            type(value['retries_max']) is not int or
            not 1 <= value['physical_max'] <= 64 or
            not 1 <= value['logical_max'] <= 64 or
            not 0 <= value['retries_max'] <= 4 or
            not 1 <= value['initial_starts_required'] <= min(
                value['physical_max'], value['logical_max']) or
            type(value['wall_seconds']) not in (int, float) or
            not 60 <= value['wall_seconds'] <= 1200 or
            value['physical_max'] > value['logical_max'] + value['retries_max']):
        raise ValueError('explicit global development budget invalid')
    # The upper limits are a caller-reviewed development cost contract, not
    # constants from FuzzingBrain V2. Per-function fields are inert under
    # GLOBAL_ONLY_DEV. They are kept
    # at 1 solely to avoid silently inheriting the old SP4/HP4 defaults.
    return DevelopmentBudget(profile=GLOBAL_ONLY_DEV_PROFILE, **value,
        sp_per_function=1, hp_per_function=1, combined_per_function=2,
        hp_analysis_per_function=1, hp_assertion_per_function=1,
        direction_turns_per_scope=direction_turn_cap)


def prepare(output: Path, *, source_mode: str, budget: dict,
            direction_graph_repair_max_turns: int = 1) -> tuple[Path, str]:
    """Pin all inputs before any provider connection; caller chooses global caps."""
    base = _base()
    if (not output.is_absolute() or output.exists() or output.is_symlink() or
            output.parent != REVIEW or any(p.is_symlink() for p in output.parents)):
        raise ValueError('new live component output must be in Linux review root')
    base._plain_path(REVIEW, directory=True)
    _budget(budget, direction_turn_cap=direction_graph_repair_max_turns)
    code_pins = base._code_pins()
    contract, config, executable, routes = _contract_routes(base)
    context, pins = _sources(base, source_mode)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    identity = output.stat()
    row = {
        'kind': KIND, 'scope': SCOPE, 'output_dir': str(output),
        'output_identity': {'dev': identity.st_dev, 'ino': identity.st_ino},
        'source_mode': source_mode,
        'official_v2_paths': _direction()._official_paths(),
        'source_pins': {key: base.tree_digest(path, None) for key, path in (
            ('artifact', ARTIFACT), ('target', TARGET),
            ('oss_fuzz', OSS_FUZZ), ('upstream', UPSTREAM))},
        'context_sha256': _direction().digest(context),
        'input_pins': pins, 'input_pins_sha256': _direction().digest(pins),
        'catalog_count': len(context['functions']),
        'driver_sha256': sha(Path(__file__)),
        'base_supervisor_sha256': sha(SUPERVISOR),
        'direction_boundary_sha256': sha(DIRECTION),
        'code_pins': code_pins,
        'dependency_versions': base._dependency_pins(),
        'contract_sha256': sha(CONTRACT),
        'codex_config_sha256': sha(config),
        'codex_executable_sha256': sha(executable),
        'python_path': '/usr/bin/python3.12',
        'python_sha256': sha(Path('/usr/bin/python3.12')),
        'role_models': routes,
        'route_sha256': contract['route_sha256'],
        'global_budget': budget,
        'selection_policy': 'FBV2_FIRST_PASS_UNIQUE_DEV',
        'candidate_budget_policy': 'DRAIN_RANKED_DEV',
    }
    if direction_graph_repair_max_turns == 2:
        row['direction_graph_repair_max_turns'] = 2
    spec = output / SPEC_NAME
    base._write_once(spec, row)
    return spec, sha(spec)


def load_spec(path: Path, expected_sha256: str) -> dict:
    """Authenticate code/contract/source bytes before importing product code."""
    if (not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)
            or path.is_symlink() or not path.is_file() or
            sha(path) != expected_sha256):
        raise ValueError('live component spec SHA changed')
    row = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(row, dict) or row.get('driver_sha256') != sha(Path(__file__))
            or row.get('base_supervisor_sha256') != sha(SUPERVISOR) or
            row.get('direction_boundary_sha256') != sha(DIRECTION)):
        raise ValueError('live component executable code pin changed')
    _check_code_before_import(row.get('code_pins'))
    base = _base()
    required = {'kind', 'scope', 'output_dir', 'output_identity',
        'source_mode', 'official_v2_paths', 'source_pins', 'context_sha256',
        'input_pins', 'input_pins_sha256', 'catalog_count', 'driver_sha256',
        'base_supervisor_sha256', 'direction_boundary_sha256', 'code_pins',
        'dependency_versions', 'contract_sha256', 'codex_config_sha256',
        'codex_executable_sha256', 'python_path', 'python_sha256',
        'role_models', 'route_sha256', 'global_budget',
        'selection_policy', 'candidate_budget_policy'}
    optional_repair = row.get('direction_graph_repair_max_turns', 1)
    if (set(row) not in (required, required | {'direction_graph_repair_max_turns'}) or
            optional_repair not in (1, 2) or type(optional_repair) is not int or
            row['kind'] != KIND or row['scope'] != SCOPE or
            row['selection_policy'] != 'FBV2_FIRST_PASS_UNIQUE_DEV' or
            row['candidate_budget_policy'] != 'DRAIN_RANKED_DEV' or
            row['source_mode'] not in SOURCE_MODES or
            row['official_v2_paths'] != _direction()._official_paths() or
            row['python_path'] != '/usr/bin/python3.12' or
            row['code_pins'] != base._code_pins() or
            row['dependency_versions'] != base._dependency_pins()):
        raise ValueError('live component spec shape or source code changed')
    _budget(row['global_budget'], direction_turn_cap=optional_repair)
    output = Path(row['output_dir'])
    base._private_dir(output)
    stat_row = output.stat()
    if (path != output / SPEC_NAME or output.parent != REVIEW or
            row['output_identity'] != {'dev': stat_row.st_dev,
                                       'ino': stat_row.st_ino}):
        raise ValueError('live component output inode changed')
    for key, path in (('artifact', ARTIFACT), ('target', TARGET),
                      ('oss_fuzz', OSS_FUZZ), ('upstream', UPSTREAM)):
        if base.tree_digest(path, None) != row['source_pins'].get(key):
            raise ValueError(f'official V2 input changed: {key}')
    contract, config, executable, routes = _contract_routes(base)
    for item, expected in ((CONTRACT, row['contract_sha256']),
                           (config, row['codex_config_sha256']),
                           (executable, row['codex_executable_sha256']),
                           (Path(row['python_path']), row['python_sha256'])):
        if sha(item) != expected:
            raise ValueError('live component route pin changed')
    if (routes != row['role_models'] or
            contract['route_sha256'] != row['route_sha256']):
        raise ValueError('live component role or workspace route changed')
    context, pins = _sources(base, row['source_mode'])
    if (pins != row['input_pins'] or
            _direction().digest(pins) != row['input_pins_sha256'] or
            _direction().digest(context) != row['context_sha256'] or
            len(context['functions']) != row['catalog_count']):
        raise ValueError('official V2 Direction context changed')
    return row


def offline_preflight(row: dict) -> dict:
    """No thread/start and no turn/start; qualification is read-only."""
    base = _base()
    with base._preflight_cache(Path(row['output_dir'])):
        contract, config, _executable, routes = _contract_routes(base)
        base._route_pinned_codex(contract)
        runner, _toy, _app, _budget_class, _ledger_class = base._imports()
        runner.verify_loaded_module_origins(sys.modules,
            ROOT / 'evaluation_tools', PRODUCT / 'src')
        runner.check_zero_retry_config(
            config, contract['default_model'], contract['default_effort'])
        runner.verify_pinned_codex_executable(contract)
        qualified = runner.require_official_qualification(contract)
        from blind3_md4c_live_direction_sp_hp_dev import _official_preflight
        _official_preflight(ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, qualified)
        return {'status': 'PREFLIGHT_PASS_NO_MODEL_CALL',
                'official_v2_qualified': True, 'actual_provider_calls': 0,
                'spec_sha256': sha(Path(row['output_dir']) / SPEC_NAME),
                'role_models': routes, 'global_budget': row['global_budget'],
                'code_pins': row['code_pins']}


class ExecutionBoundary(BaseException):
    """A development model-stage run attempted target or Fuzzer execution."""


def _forbid_execution(*_args: Any, **_kwargs: Any) -> Any:
    raise ExecutionBoundary('live component route cannot execute target or Fuzzer')


def _defer_pov_runtime(poc: Any, *_args: Any, **_kwargs: Any) -> list:
    poc.status = 'PENDING_RUNTIME_DEV'
    poc.actual_behavior = 'Target was not executed in development component run'
    return []


def _candidate_evidence(run: Path) -> dict:
    """Preserve generated candidates even when the next turn has no credit."""
    path = run / 'sp/candidates.json'
    if not path.exists():
        return {'path': None, 'sha256': None, 'sp_ids': []}
    if path.is_symlink() or not path.is_file():
        raise ValueError('candidate artifact missing or linked')
    rows = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(rows, list) or
            any(not isinstance(row, dict) or
                not isinstance(row.get('sp_id'), str) or not row['sp_id']
                for row in rows)):
        raise ValueError('candidate artifact shape changed')
    ids = [row['sp_id'] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError('candidate artifact duplicate identity')
    return {'path': 'sp/candidates.json', 'sha256': sha(path), 'sp_ids': ids}


def _stop(output: Path, ledger: Any, exc: BaseException) -> None:
    """Write an evidence pointer without replacing the primary exception."""
    try:
        base = _base()
        base._write_once(output / STOP_NAME, {
            'kind': KIND, 'status': 'STOPPED', 'error_type': type(exc).__name__,
            'cause_type': (type(exc.__cause__).__name__
                           if exc.__cause__ is not None else None),
            'physical': ledger.physical if ledger is not None else 0,
            'logical': ledger.logical if ledger is not None else 0,
            'ledger': base._evidence(output / LEDGER_NAME),
            'model_events': base._evidence(output / 'MODEL_EVENTS.jsonl'),
            'runtime_executed': False, 'fuzz_seconds': 0,
            'vulnerability_verdict': 'NOT_EVALUATED'})
    except BaseException:
        pass


async def _run_child(row: dict, spec_sha256: str) -> dict:
    """Real-model capable path; never invoked by prepare/preflight/tests."""
    _require_external_source_pin()
    if load_spec(Path(row['output_dir']) / SPEC_NAME, spec_sha256) != row:
        raise ValueError('live component pins changed before helper imports')
    base = _base()
    contract, config, executable, routes = _contract_routes(base)
    base._route_pinned_codex(contract)
    runner, _toy, AppServer, Budget, Ledger = base._imports()
    from blind3_direction_phase1_dev import execute_direction_phase1
    from blind3_md4c_live_direction_sp_hp_dev import _official_preflight, _postcheck
    from dev_global_appserver_bridge import verify_model_event_order
    from dev_global_appserver_product_flow import DevelopmentBudgetStop, ProductBudgetAdapter
    from vulnerabilityanalysis.scan import scan_selected
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    runner.verify_pinned_codex_executable(contract)
    official = runner.require_official_qualification(contract)
    _official_preflight(ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, official)
    output = Path(row['output_dir'])
    model_cwd = output / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    base._private_dir(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('model cwd not empty')
    base._write_once(output / 'OFFICIAL_V2_PRECHECK.json', {
        'spec_sha256': spec_sha256, 'code_pins': row['code_pins'],
        'source_pins': row['source_pins'], 'role_models': routes,
        'route_sha256': row['route_sha256'],
        'official_v2_qualified': True, 'global_budget': row['global_budget']})
    direction_cap = row.get('direction_graph_repair_max_turns', 1)
    budget = _budget(row['global_budget'], direction_turn_cap=direction_cap)
    ledger = Ledger.create(budget, output / LEDGER_NAME)
    direction = None
    run = None
    scan = None
    try:
        with runner.private_codex_state(config):
            sandbox = runner.verify_model_namespace_sandbox(
                executable, _direction()._official_protected_paths(runner, contract))
            base._write_once(output / 'SANDBOX_SELF_TEST.json', sandbox)
            backend = AppServer(
                ledger=ledger, role_models=routes, cwd=model_cwd,
                wire_cwd='/work', launch_prefix=[sys.executable,
                    str(ROOT / 'evaluation_tools/blind2_model_sandbox.py')],
                executable=str(executable),
                executable_sha256=contract['codex_executable_sha256'],
                model=contract['default_model'], effort=contract['default_effort'],
                timeout_seconds=300, event_log_path=output / 'MODEL_EVENTS.jsonl')
            backend.retry_route_check = lambda: runner.check_live_route(
                backend, row['route_sha256'], routes)
            async with backend:
                await asyncio.wait_for(runner.check_live_route(
                    backend, row['route_sha256'], routes), timeout=120)
                direction = await execute_direction_phase1(
                    output=output / 'direction', artifact=ARTIFACT,
                    target_repository=TARGET, oss_fuzz_checkout=OSS_FUZZ,
                    upstream_checkout=UPSTREAM, backend=backend, ledger=ledger,
                    role_models=routes, scope_id='official-v2-md4c-component-dev',
                    source_mode=row['source_mode'],
                    direction_graph_repair_max_turns=direction_cap)
                direction_count = direction.get('direction_turn_count', 1)
                if (direction['status'] != 'DIRECTION_PHASE1_PREPARED_DEV' or
                        direction_count not in (1, 2) or
                        direction_count > direction_cap or
                        ledger.logical != direction_count or
                        ledger.direction_counts.get(
                            'official-v2-md4c-component-dev') != direction_count or
                        any(turn['role'] != 'direction_generator' or
                            turn['status'] != 'COMPLETED'
                            for turn in ledger.turns[:direction_count])):
                    raise ValueError('Direction lacks completed physical turn')
                run = Path(direction['phase1_run'])
                selected = json.loads((run / 'selection.json').read_text())
                pool = json.loads((run / 'function_pool.json').read_text())
                phase1 = json.loads((run / 'run.json').read_text())
                pool_ids = [item['function_id'] for item in pool]
                fid = selected.get('function_id')
                if (not isinstance(fid, str) or fid not in pool_ids or
                        len(pool_ids) != len(set(pool_ids)) or
                        phase1.get('selected_function_id') != fid or
                        phase1.get('direction_source_kind') !=
                        'PINNED_MODEL_PROPOSAL' or
                        phase1.get('selection_policy') !=
                        'FBV2_FIRST_PASS_UNIQUE_DEV' or
                        phase1.get('direction_plan_sha256') !=
                        direction['direction_plan_sha256']):
                    raise ValueError('Phase 1 selection or Direction identity changed')
                if not ledger.select_function(fid):
                    # A one-turn cap can complete Direction but leave no
                    # function opportunity. Preserve it as a first-class
                    # no-opportunity receipt, never as a negative finding.
                    _postcheck(output / 'direction', ARTIFACT, TARGET,
                        OSS_FUZZ, UPSTREAM, official, row['source_mode'],
                        direction, ledger, backend, pool_ids)
                    if load_spec(output / SPEC_NAME, spec_sha256) != row:
                        raise ValueError('source changed at no-opportunity boundary')
                    boundary = {'kind': KIND, 'status': 'NO_OPPORTUNITY_BUDGET',
                        'spec_sha256': spec_sha256,
                        'selected_function_id': fid,
                        'ledger_sha256': sha(output / LEDGER_NAME),
                        'model_events_sha256': sha(output / 'MODEL_EVENTS.jsonl'),
                        'physical': ledger.physical, 'logical': ledger.logical,
                        'retries': ledger.retries, 'target_runs': 0,
                        'fuzz_seconds': 0,
                        'vulnerability_verdict': 'NOT_EVALUATED'}
                    if direction_cap == 2:
                        boundary['direction_evidence'] = _direction_evidence(direction)
                        boundary['direction_plan_sha256'] = direction[
                            'direction_plan_sha256']
                        boundary['roles'] = [turn['role'] for turn in ledger.turns]
                        boundary['global_budget'] = row['global_budget']
                    base._write_once(output / RECEIPT_NAME, boundary)
                    child = {'status': 'NO_OPPORTUNITY_BUDGET',
                        'spec_sha256': spec_sha256,
                        'receipt_sha256': sha(output / RECEIPT_NAME),
                        'physical': ledger.physical, 'logical': ledger.logical,
                        'retries': ledger.retries}
                    base._write_once(output / CHILD_NAME, child)
                    return child
                backend.bind_scope(fid)
                provider = ProductBudgetAdapter(backend, ledger, fid)
                budget_stopped = False
                try:
                    with (patch('vulnerabilityanalysis.scan.execute_poc',
                                _defer_pov_runtime),
                          patch('vulnerabilityanalysis.scan.run_assertions_for_scan',
                                _forbid_execution),
                          patch('vulnerabilityanalysis.scan.run_targeted_fuzz',
                                _forbid_execution),
                          patch('vulnerabilityanalysis.scan.fuzz_locally',
                                _forbid_execution),
                          patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                                _forbid_execution)):
                        try:
                            await scan_selected(
                                run, provider, target_repository=TARGET,
                                target_binary=official.binary,
                                official_qualification=official,
                                role_models=routes, hallucination_prevent='on',
                                external_turn_budget=ledger,
                                candidate_budget_policy='DRAIN_RANKED_DEV',
                                max_candidates=1, targeted_fuzz_seconds=0,
                                global_fuzz_enabled=False,
                                assertion_fuzz_seconds=0, run_command=None,
                                initial_inputs=None, pov_feedback_revisions=0)
                        except DevelopmentBudgetStop:
                            if (run / 'scan.json').exists():
                                raise ValueError('budget-stopped Scan saved as complete')
                            if provider.rejected_prewire is None:
                                raise ValueError('budget stop lacks proven prewire denial')
                            budget_stopped = True
                finally:
                    backend.unbind_scope()
        if (provider.rejected_prewire is not None) != budget_stopped:
            raise ValueError('product attempted unbudgeted request')
        if routes != row['role_models'] or backend.role_models != row['role_models']:
            raise ValueError('role route changed after model turns')
        _official_preflight(ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM, official)
        _postcheck(output / 'direction', ARTIFACT, TARGET, OSS_FUZZ, UPSTREAM,
                   official, row['source_mode'], direction, ledger, backend,
                   pool_ids)
        if (run / 'scan.json').is_file():
            scan = json.loads((run / 'scan.json').read_text())
            if (scan.get('budget_authority') != 'EXTERNAL_GLOBAL_DEV' or
                    scan.get('global_budget_profile') != 'GLOBAL_ONLY_DEV' or
                    scan.get('candidate_budget_policy') != 'DRAIN_RANKED_DEV' or
                    scan.get('selected_function_id') != fid or
                    scan.get('sp_llm_call_limit', 'missing') is not None or
                    scan.get('hp_llm_call_limit', 'missing') is not None or
                    scan.get('fuzz_seconds_allocated') != 0 or
                    scan.get('observed_crash_ids') or
                    scan.get('verified_crash_ids')):
                raise ValueError('Scan escaped development model-stage scope')
            ledger.mark_scan_recorded(fid)
        verify_model_event_order(ledger, backend.event_log_path)
        restored = Ledger.restore(ledger.checkpoint_path, ledger.budget)
        if (restored.summary(pool_ids) != ledger.summary(pool_ids) or
                restored.physical != ledger.physical or
                restored.logical != ledger.logical or
                restored.retries != ledger.retries or
                ledger.tainted or ledger.active_turn is not None):
            raise ValueError('live component ledger restore or event audit failed')
        if load_spec(output / SPEC_NAME, spec_sha256) != row:
            raise ValueError('live component sources changed after model turns')
        receipt_status = ('PENDING_BUDGET' if scan is None else
            'INCOMPLETE_HP_ERROR' if scan.get('hp_error') else
            'PENDING_UNVERIFIED_DEV')
        receipt = {'kind': KIND, 'status': receipt_status,
                   'spec_sha256': spec_sha256,
                   'official_v2_qualified': True,
                   'budget_profile': 'GLOBAL_ONLY_DEV',
                   'global_budget': row['global_budget'],
                   'selection_policy': row['selection_policy'],
                   'candidate_budget_policy': row['candidate_budget_policy'],
                   'direction_plan_sha256': direction['direction_plan_sha256'],
                   'phase1_run_relative': run.relative_to(output).as_posix(),
                   'selected_function_id': fid,
                   'pool_count': len(pool_ids),
                   'scan_sha256': sha(run / 'scan.json') if scan else None,
                   'candidate_evidence': _candidate_evidence(run),
                   'budget_stopped': budget_stopped,
                   'rejected_prewire': provider.rejected_prewire,
                   'ledger_sha256': sha(output / LEDGER_NAME),
                   'model_events_sha256': sha(output / 'MODEL_EVENTS.jsonl'),
                   'physical': ledger.physical, 'logical': ledger.logical,
                   'retries': ledger.retries,
                   'roles': [turn['role'] for turn in ledger.turns],
                   'sp_candidate_count': scan.get('sp_count') if scan else None,
                   'sp_verified_count': len(scan.get('selected_sp_ids', []))
                       if scan else None,
                   'pending_candidate_count': len(scan.get('pending_sp_ids', []))
                       if scan else None,
                   'pov_model_calls': sum(turn['role'] == 'poc_generator'
                       for turn in ledger.turns),
                   'target_runs': 0, 'fuzz_seconds': 0,
                   'runtime_status': 'NOT_EXECUTED_DEV',
                   'vulnerability_verdict': 'NOT_EVALUATED'}
        if direction_cap == 2:
            receipt['direction_evidence'] = _direction_evidence(direction)
        base._write_once(output / RECEIPT_NAME, receipt)
        child = {'status': 'BOUNDED_LIVE_COMPONENT_TRACE_RECORDED',
                 'spec_sha256': spec_sha256,
                 'receipt_sha256': sha(output / RECEIPT_NAME),
                 'ledger_sha256': receipt['ledger_sha256'],
                 'model_events_sha256': receipt['model_events_sha256'],
                 'physical': ledger.physical, 'logical': ledger.logical,
                 'retries': ledger.retries}
        base._write_once(output / CHILD_NAME, child)
        return child
    except BaseException as exc:
        _stop(output, ledger, exc)
        raise


def _completion_predicate(child: dict, directory_fd: int, output: Path,
                          *, spec_sha256: str, budget: dict,
                          direction_turn_cap: int = 1) -> bool:
    """The parent authenticates receipt and ledger before COMPLETE."""
    try:
        direction = _direction()
        if (child.get('status') != 'BOUNDED_LIVE_COMPONENT_TRACE_RECORDED' or
                child.get('spec_sha256') != spec_sha256):
            return False
        receipt_bytes = direction._read_beneath(directory_fd, RECEIPT_NAME)
        ledger_bytes = direction._read_beneath(directory_fd, LEDGER_NAME)
        events = direction._read_beneath(directory_fd, 'MODEL_EVENTS.jsonl',
                                        limit=128_000_000)
        receipt = json.loads(receipt_bytes)
        ledger = json.loads(ledger_bytes)
        if not isinstance(receipt, dict) or not isinstance(ledger, dict):
            return False
        if (sha_bytes(receipt_bytes) != child.get('receipt_sha256') or
                sha_bytes(ledger_bytes) != child.get('ledger_sha256') or
                sha_bytes(events) != child.get('model_events_sha256') or
                receipt.get('spec_sha256') != spec_sha256 or
                receipt.get('global_budget') != budget or
                receipt.get('status') != 'PENDING_UNVERIFIED_DEV' or
                receipt.get('vulnerability_verdict') != 'NOT_EVALUATED' or
                receipt.get('target_runs') != 0 or
                receipt.get('fuzz_seconds') != 0 or
                receipt.get('ledger_sha256') != child.get('ledger_sha256') or
                receipt.get('model_events_sha256') !=
                    child.get('model_events_sha256') or
                receipt.get('physical') != child.get('physical') or
                receipt.get('logical') != child.get('logical') or
                receipt.get('retries') != child.get('retries') or
                ledger.get('physical') != child.get('physical') or
                ledger.get('logical') != child.get('logical') or
                ledger.get('retries') != child.get('retries') or
                ledger.get('active_turn') is not None or
                'tainted' in ledger or
                child['physical'] > budget['physical_max'] or
                child['logical'] > budget['logical_max'] or
                child['retries'] > budget['retries_max'] or
                child['logical'] < 3 or
                ledger.get('budget', {}).get('profile') != 'GLOBAL_ONLY_DEV' or
                any(ledger.get('budget', {}).get(name) != value
                    for name, value in budget.items()) or
                ledger.get('kind') !=
                    'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1'):
            return False
        turns, attempts = ledger.get('turns'), ledger.get('attempts')
        direction_evidence = receipt.get('direction_evidence')
        direction_count = (direction_evidence.get('direction_turn_count', 1)
            if isinstance(direction_evidence, dict) else 1)
        if (not isinstance(turns, list) or not isinstance(attempts, list) or
                len(turns) != child['logical'] or
                len(attempts) != child['physical'] or
                direction_count not in (1, 2) or
                direction_count > direction_turn_cap or
                len(turns) < direction_count + 2 or
                [turn.get('role') for turn in turns[:direction_count + 2]] !=
                    ['direction_generator'] * direction_count +
                    ['sp_generation', 'function_analysis'] or
                any(turn.get('role') not in ROLES for turn in turns) or
                any(turn.get('status') != 'COMPLETED' for turn in turns) or
                any(attempt.get('status') not in {'COMPLETED', 'ERROR'}
                    for attempt in attempts) or
                receipt.get('roles', [turn.get('role') for turn in turns]) !=
                    [turn.get('role') for turn in turns] or
                direction_turn_cap == 2 and receipt.get('roles') !=
                    [turn.get('role') for turn in turns] or
                not _direction_trace_ok(directory_fd, ledger, receipt,
                                        direction_turn_cap)):
            return False
        relative = receipt.get('phase1_run_relative')
        if (not isinstance(relative, str) or
                Path(relative).parts[:2] != ('direction', 'product_runs') or
                len(Path(relative).parts) != 3 or
                not isinstance(receipt.get('scan_sha256'), str) or
                sha_bytes(direction._read_beneath(
                    directory_fd, relative + '/scan.json',
                    limit=16_000_000)) != receipt['scan_sha256']):
            return False
        candidates = receipt.get('candidate_evidence')
        if (not isinstance(candidates, dict) or
                candidates.get('path') != 'sp/candidates.json' or
                not isinstance(candidates.get('sp_ids'), list) or
                not isinstance(candidates.get('sha256'), str) or
                sha_bytes(direction._read_beneath(directory_fd,
                    relative + '/sp/candidates.json', limit=16_000_000)) !=
                    candidates['sha256']):
            return False
        return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return False


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _request_artifact_hash(raw: bytes) -> str:
    row = json.loads(raw)
    if set(row) != {'role', 'instructions', 'payload', 'output_schema',
                    'model', 'reasoning'}:
        raise ValueError('Direction request artifact shape changed')
    value = {'role': row['role'], 'instructions': row['instructions'],
             'payload': row['payload'], 'schema': row['output_schema'],
             'session_key': None, 'model': row['model'],
             'effort': row['reasoning']}
    return sha_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                 separators=(',', ':')).encode())


def _direction_trace_ok(fd: int, ledger: dict, receipt: dict,
                        expected_cap: int) -> bool:
    """Bind optional second Direction wire evidence to receipt and ledger."""
    if (not isinstance(ledger, dict) or not isinstance(receipt, dict) or
            not isinstance(ledger.get('budget', {}), dict)):
        return False
    turns, attempts = ledger.get('turns'), ledger.get('attempts')
    if not isinstance(turns, list) or not isinstance(attempts, list):
        return False
    checkpoint_cap = ledger.get('budget', {}).get('direction_turns_per_scope', 1)
    if checkpoint_cap != expected_cap:
        return False
    evidence = receipt.get('direction_evidence')
    if expected_cap == 1 and evidence is None:
        return bool(turns and turns[0].get('role') == 'direction_generator' and
                    all(turn.get('role') != 'direction_generator'
                        for turn in turns[1:]))
    if not isinstance(evidence, dict) or set(evidence) != {
            'direction_turn_count', 'direction_request_sha256',
            'direction_raw_sha256', 'direction_repair_request_sha256',
            'direction_repair_raw_sha256', 'direction_repair_status_sha256',
            'direction_logical_turn_id', 'direction_physical_starts'}:
        return False
    count = evidence['direction_turn_count']
    if (type(count) is not int or not 1 <= count <= expected_cap or
            len(turns) < count or
            any(turn.get('role') != 'direction_generator' or
                turn.get('status') != 'COMPLETED' for turn in turns[:count]) or
            any(turn.get('role') == 'direction_generator' for turn in turns[count:]) or
            turns[count - 1].get('id') != evidence['direction_logical_turn_id']):
        return False
    counts = ledger.get('direction_counts')
    if (not isinstance(counts, dict) or len(counts) != 1 or
            next(iter(counts.values())) != count):
        return False
    scope = next(iter(counts))
    if (any(turn.get('scope_id') != scope for turn in turns[:count]) or
            sum(attempt.get('scope_id') == scope for attempt in attempts) !=
                evidence['direction_physical_starts']):
        return False
    reader = _direction()._read_beneath
    paths = [('DIRECTION_REQUEST.json', 'direction_request_sha256'),
             ('DIRECTION_RAW.txt', 'direction_raw_sha256')]
    if count == 2:
        paths += [('DIRECTION_REPAIR_REQUEST.json',
                   'direction_repair_request_sha256'),
                  ('DIRECTION_REPAIR_RAW.txt', 'direction_repair_raw_sha256'),
                  ('DIRECTION_REPAIR_STATUS.json',
                   'direction_repair_status_sha256')]
    elif any(evidence.get(name) is not None for name in (
            'direction_repair_request_sha256', 'direction_repair_raw_sha256',
            'direction_repair_status_sha256')):
        return False
    raw = {}
    for name, field in paths:
        if (not isinstance(evidence.get(field), str) or
                not HEX.fullmatch(evidence[field])):
            return False
        raw[name] = reader(fd, f'direction/{name}', limit=2_000_000)
        if sha_bytes(raw[name]) != evidence[field]:
            return False
    request_names = ['DIRECTION_REQUEST.json']
    if count == 2:
        request_names.append('DIRECTION_REPAIR_REQUEST.json')
    if any(_request_artifact_hash(raw[name]) != turn.get('hash')
           for name, turn in zip(request_names, turns[:count])):
        return False
    if count == 2:
        status = json.loads(raw['DIRECTION_REPAIR_STATUS.json'])
        if (status.get('kind') != 'DIRECTION_GRAPH_REPAIR_DEV_V1' or
                status.get('status') != 'VALIDATED' or
                status.get('direction_turn_count') != 2 or
                status.get('first_request_sha256') !=
                    evidence['direction_request_sha256'] or
                status.get('first_raw_sha256') != evidence['direction_raw_sha256'] or
                status.get('repair_request_sha256') !=
                    evidence['direction_repair_request_sha256'] or
                status.get('repair_raw_sha256') !=
                    evidence['direction_repair_raw_sha256']):
            return False
    plan_raw = reader(fd, 'direction/DIRECTION_PLAN.json', limit=2_000_000)
    if sha_bytes(plan_raw) != receipt.get('direction_plan_sha256'):
        return False
    plan = json.loads(plan_raw)
    last_raw = raw['DIRECTION_REPAIR_RAW.txt'] if count == 2 else raw['DIRECTION_RAW.txt']
    response = json.loads(last_raw)
    if (not isinstance(plan, dict) or
            not isinstance(plan.get('response'), dict) or
            not isinstance(response, dict)):
        return False
    if (set(response) != {'directions', 'unknowns'} or
            set(plan['response']) != {
                'directions', 'unknowns', 'pool_preservation_rule',
                'indirect_runtime_status'} or
            plan['response']['pool_preservation_rule'] !=
                'all Catalog functions remain candidates; Direction output only changes priority evidence' or
            plan['response']['indirect_runtime_status'] != 'UNVERIFIED'):
        return False
    if any(plan.get('response', {}).get(key) != response.get(key)
           for key in ('directions', 'unknowns')):
        return False
    return True


def _verified_component_status(output: Path, spec_sha256: str,
                               supervised: dict) -> tuple[str, str | None]:
    """Classify an incomplete child only after checking its evidence bytes."""
    if supervised['status'] == 'CHILD_EXITED_COMPLETE':
        return 'PENDING_UNVERIFIED_DEV', None
    if supervised['status'] not in {'CHILD_EXITED_INCONCLUSIVE', 'CHILD_ERROR'}:
        return 'NOT_INSPECTED_AFTER_STOP', supervised['status']
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        reader = _direction()._read_beneath
        child_raw = reader(fd, CHILD_NAME)
        if sha_bytes(child_raw) != supervised['child_result']['sha256']:
            return 'UNVERIFIED_CHILD_RESULT', 'CHILD_HASH_MISMATCH'
        child = json.loads(child_raw)
        if child.get('spec_sha256') != spec_sha256:
            return 'UNVERIFIED_CHILD_RESULT', 'SPEC_MISMATCH'
        if child.get('status') == 'STOPPED':
            stop_raw = reader(fd, STOP_NAME)
            stop = json.loads(stop_raw)
            if (sha_bytes(stop_raw) != child.get('stop_sha256') or
                    stop.get('kind') != KIND):
                return 'UNVERIFIED_CHILD_RESULT', 'STOP_MISMATCH'
            return 'STOPPED', stop.get('error_type')
        return _verified_boundary(fd, child, spec_sha256)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return 'UNVERIFIED_CHILD_RESULT', 'UNREADABLE_BOUNDARY_EVIDENCE'
    finally:
        os.close(fd)


def _verified_boundary(fd: int, child: dict,
                       spec_sha256: str) -> tuple[str, str | None]:
    reader = _direction()._read_beneath
    spec_raw = reader(fd, SPEC_NAME, limit=1_000_000)
    spec_row = json.loads(spec_raw)
    if (sha_bytes(spec_raw) != spec_sha256 or
            not isinstance(spec_row, dict) or
            type(spec_row.get('direction_graph_repair_max_turns', 1)) is not int or
            spec_row.get('direction_graph_repair_max_turns', 1) not in (1, 2)):
        return 'UNVERIFIED_CHILD_RESULT', 'DIRECTION_SPEC_MISMATCH'
    receipt_raw = reader(fd, RECEIPT_NAME)
    receipt = json.loads(receipt_raw)
    if (sha_bytes(receipt_raw) != child.get('receipt_sha256') or
            receipt.get('kind') != KIND or
            receipt.get('spec_sha256') != spec_sha256 or
            receipt.get('status') not in
                {'NO_OPPORTUNITY_BUDGET', 'PENDING_BUDGET',
                 'INCOMPLETE_HP_ERROR'} or
            receipt.get('target_runs') != 0 or
            receipt.get('fuzz_seconds') != 0 or
            receipt.get('vulnerability_verdict') != 'NOT_EVALUATED'):
        return 'UNVERIFIED_CHILD_RESULT', 'RECEIPT_MISMATCH'
    ledger_raw = reader(fd, LEDGER_NAME)
    events_raw = reader(fd, 'MODEL_EVENTS.jsonl', limit=128_000_000)
    ledger = json.loads(ledger_raw)
    if not isinstance(receipt, dict) or not isinstance(ledger, dict):
        return 'UNVERIFIED_CHILD_RESULT', 'LEDGER_OR_EVENTS_MISMATCH'
    if not isinstance(ledger.get('budget', {}), dict):
        return 'UNVERIFIED_CHILD_RESULT', 'LEDGER_OR_EVENTS_MISMATCH'
    if (sha_bytes(ledger_raw) != receipt.get('ledger_sha256') or
            sha_bytes(events_raw) != receipt.get('model_events_sha256') or
            any(ledger.get(name) != receipt.get(name) or
                child.get(name) != receipt.get(name)
                for name in ('physical', 'logical', 'retries')) or
            ledger.get('active_turn') is not None or
            'tainted' in ledger or
            ledger.get('kind') !=
                'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1'):
        return 'UNVERIFIED_CHILD_RESULT', 'LEDGER_OR_EVENTS_MISMATCH'
    turns, attempts = ledger.get('turns'), ledger.get('attempts')
    direction_cap = spec_row.get('direction_graph_repair_max_turns', 1)
    if direction_cap == 2:
        spec_budget = spec_row.get('global_budget')
        if (not isinstance(spec_budget, dict) or
                receipt.get('global_budget') != spec_budget or
                any(ledger['budget'].get(name) != value
                    for name, value in spec_budget.items()) or
                any(ledger.get(name, -1) > spec_budget[limit]
                    for name, limit in (('physical', 'physical_max'),
                                        ('logical', 'logical_max'),
                                        ('retries', 'retries_max')))):
            return 'UNVERIFIED_CHILD_RESULT', 'DIRECTION_SPEC_MISMATCH'
    evidence = receipt.get('direction_evidence')
    direction_count = (evidence.get('direction_turn_count', 1)
        if isinstance(evidence, dict) else 1)
    if (not isinstance(turns, list) or not isinstance(attempts, list) or
            len(turns) != child['logical'] or
            len(attempts) != child['physical'] or
            not turns or turns[0].get('role') != 'direction_generator' or
            turns[0].get('status') != 'COMPLETED' or
            any(turn.get('role') not in ROLES for turn in turns) or
            direction_cap not in (1, 2) or
            direction_count not in (1, 2) or
            direction_count > direction_cap or
            receipt.get('roles', [turn.get('role') for turn in turns]) !=
                [turn.get('role') for turn in turns] or
            direction_cap == 2 and receipt.get('roles') !=
                [turn.get('role') for turn in turns] or
            (len(turns) > direction_count and
                turns[direction_count].get('role') != 'sp_generation') or
            (len(turns) > direction_count + 1 and
                turns[direction_count + 1].get('role') != 'function_analysis') or
            not _direction_trace_ok(fd, ledger, receipt, direction_cap)):
        return 'UNVERIFIED_CHILD_RESULT', 'BOUNDARY_TURNS_MISMATCH'
    status = receipt['status']
    if status == 'NO_OPPORTUNITY_BUDGET':
        if (child.get('status') != status or
                child['logical'] != direction_count or
                child['physical'] < direction_count or
                any(turn.get('role') != 'direction_generator'
                    for turn in turns) or
                ledger.get('selected_functions') != [] or
                ledger.get('no_opportunity', {}).get(
                    receipt.get('selected_function_id')) != status):
            return 'UNVERIFIED_CHILD_RESULT', 'NO_OPPORTUNITY_MISMATCH'
        return status, 'FUNCTION_START_CREDIT_UNAVAILABLE'
    if (child.get('status') != 'BOUNDED_LIVE_COMPONENT_TRACE_RECORDED' or
            status == 'PENDING_BUDGET' and
                (receipt.get('budget_stopped') is not True or
                 not isinstance(receipt.get('rejected_prewire'), dict) or
                 not ledger.get('pending_work')) or
            status == 'INCOMPLETE_HP_ERROR' and
                receipt.get('budget_stopped') is True):
        return 'UNVERIFIED_CHILD_RESULT', 'PENDING_BOUNDARY_MISMATCH'
    candidates = receipt.get('candidate_evidence')
    if not isinstance(candidates, dict):
        return 'UNVERIFIED_CHILD_RESULT', 'CANDIDATE_EVIDENCE_MISSING'
    if candidates.get('path') is None:
        if (status != 'PENDING_BUDGET' or
                candidates != {'path': None, 'sha256': None, 'sp_ids': []}):
            return 'UNVERIFIED_CHILD_RESULT', 'CANDIDATE_EVIDENCE_MISMATCH'
    else:
        relative = receipt.get('phase1_run_relative')
        if (candidates.get('path') != 'sp/candidates.json' or
                not isinstance(relative, str) or
                Path(relative).parts[:2] != ('direction', 'product_runs') or
                len(Path(relative).parts) != 3 or
                not isinstance(candidates.get('sp_ids'), list) or
                sha_bytes(reader(fd, relative + '/sp/candidates.json',
                    limit=16_000_000)) != candidates.get('sha256')):
            return 'UNVERIFIED_CHILD_RESULT', 'CANDIDATE_EVIDENCE_MISMATCH'
    return status, ('GLOBAL_MODEL_REQUEST_CREDIT_EXHAUSTED'
                    if status == 'PENDING_BUDGET' else 'HP_ERROR')


def run_supervised(spec: Path, expected_sha256: str) -> dict:
    """An externally pinned caller must invoke this; no automatic model call."""
    _require_external_source_pin()
    row = load_spec(spec, expected_sha256)
    output = Path(row['output_dir'])
    if any((output / name).exists() for name in
           (LEDGER_NAME, CHILD_NAME, RECEIPT_NAME, STOP_NAME)):
        raise ValueError('live component attempt already started')
    base = _base()
    contract, _config, _executable, _routes = _contract_routes(base)
    base._route_pinned_codex(contract)
    runner, _toy, _app, _budget_class, _ledger_class = base._imports()
    os.umask(0o077)
    parent_cache = base._fresh_cache(output, 'parent_pycache')
    child_cache = output / 'child_pycache'
    child_cache.mkdir(mode=0o700)
    base._private_dir(child_cache)
    command = [row['python_path'], '-I', '-B', '-X',
               f'pycache_prefix={child_cache}', '-c', base.INLINE_BOOTSTRAP,
               str(Path(__file__).resolve()), row['driver_sha256'],
               '--child', str(spec), expected_sha256]
    if load_spec(spec, expected_sha256) != row:
        raise ValueError('live component pin changed before child launch')
    supervised = base.supervise_command(
        command, output, wall_seconds=row['global_budget']['wall_seconds'],
        runner=runner, spec_sha256=expected_sha256,
        completion_predicate=lambda child, fd, held: _completion_predicate(
            child, fd, held, spec_sha256=expected_sha256,
            budget=row['global_budget'], direction_turn_cap=
                row.get('direction_graph_repair_max_turns', 1)),
        expected_output_identity=(row['output_identity']['dev'],
                                  row['output_identity']['ino']))
    component, stop_reason = _verified_component_status(
        output, expected_sha256, supervised)
    supplemental = {
        'kind': KIND, 'spec_sha256': expected_sha256,
        'supervisor_result_sha256': sha(output / base.RESULT_NAME),
        'supervisor_status': supervised['status'],
        'component_status': component, 'stop_reason': stop_reason,
        'child_result': supervised['child_result'],
        'physical_ledger': supervised['physical_ledger'],
        'model_events': base._evidence(output / 'MODEL_EVENTS.jsonl'),
        'vulnerability_verdict': 'NOT_EVALUATED'}
    base._write_once(output / SUPERVISION_NAME, supplemental)
    return {**supervised, 'component_status': component,
            'component_stop_reason': stop_reason,
            'component_supervision_sha256': sha(output / SUPERVISION_NAME)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--preflight-only', action='store_true')
    group.add_argument('--run-live', action='store_true')
    group.add_argument('--child', action='store_true')
    parser.add_argument('--source-mode', choices=sorted(SOURCE_MODES),
                        default='stratified_callsite_800')
    parser.add_argument('--direction-graph-repair-max-turns', type=int,
                        choices=(1, 2), default=1)
    parser.add_argument('--physical-max', type=int)
    parser.add_argument('--logical-max', type=int)
    parser.add_argument('--retries-max', type=int)
    parser.add_argument('--wall-seconds', type=float)
    parser.add_argument('--initial-starts-required', type=int)
    parser.add_argument('path', type=Path)
    parser.add_argument('sha256', nargs='?')
    args = parser.parse_args(argv)
    if (sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('use /usr/bin/python3.12 -I -B')
    _fresh_import_cache(child_output=args.path.parent if args.child else None)
    if args.prepare:
        if any(x is None for x in (args.physical_max, args.logical_max,
                 args.retries_max, args.wall_seconds, args.initial_starts_required)):
            raise ValueError('all global budget limits must be explicit')
        budget = {'physical_max': args.physical_max,
                  'logical_max': args.logical_max,
                  'retries_max': args.retries_max,
                  'wall_seconds': args.wall_seconds,
                  'initial_starts_required': args.initial_starts_required}
        spec, digest = prepare(args.path, source_mode=args.source_mode,
                               budget=budget,
                               direction_graph_repair_max_turns=
                                   args.direction_graph_repair_max_turns)
        print(json.dumps({'status': 'PREPARED_NO_MODEL_CALL',
                          'spec': str(spec), 'sha256': digest}))
        return 0
    if not args.sha256:
        parser.error('externally reviewed spec SHA-256 required')
    if args.run_live or args.child:
        _require_external_source_pin()
    row = load_spec(args.path, args.sha256)
    if args.preflight_only:
        print(json.dumps(offline_preflight(row), sort_keys=True))
        return 0
    if args.child:
        try:
            asyncio.run(_run_child(row, args.sha256))
        except BaseException as exc:
            output = Path(row['output_dir'])
            _stop(output, None, exc)
            try:
                _base()._write_once(output / CHILD_NAME, {
                    'status': 'STOPPED', 'error_type': type(exc).__name__,
                    'spec_sha256': args.sha256,
                    'stop_sha256': sha(output / STOP_NAME)
                        if (output / STOP_NAME).is_file() else None,
                    'ledger': _base()._evidence(output / LEDGER_NAME),
                    'model_events': _base()._evidence(
                        output / 'MODEL_EVENTS.jsonl')})
            except BaseException:
                pass
            raise
        return 0
    result = run_supervised(args.path, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
