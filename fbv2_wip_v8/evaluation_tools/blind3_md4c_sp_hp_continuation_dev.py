"""Bounded official V2 md4c SP/HP continuation, development only.

The input Direction is a *post-hoc offline replay* of an earlier failed live
attempt. Its historical physical call is never inserted into this ledger.
Prepare and preflight make no model request. Live use needs an externally
SHA-pinned entrypoint and the existing process supervisor.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
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
DIRECTION_BOUNDARY = ROOT / 'evaluation_tools/blind3_md4c_direction_supervised_dev.py'
HISTORICAL_RECEIPT = (REVIEW /
    'BLIND3_MD4C_DIRECTION_OFFLINE_REPLAY_V2_20261030' /
    'DIRECTION_OFFLINE_REPLAY_RECEIPT.json')
HISTORICAL_RECEIPT_SHA256 = '57545a021b3025fa68a41f3bceeee2a71c1ad101a6d4cc971a02ce446e1e42bf'
SPEC_NAME = 'OFFICIAL_V2_SP_HP_CONTINUATION_SPEC.json'
RECEIPT_NAME = 'OFFICIAL_V2_SP_HP_CONTINUATION_RECEIPT.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
LEDGER_NAME = 'GLOBAL_LEDGER.json'
PHASE1_FILES = ('run.json', 'function_pool.json', 'directions.json',
                'selection.json', 'workers.json', 'direction_plan.json',
                'harness.json', 'call_graph_audit.json')
WALL_SECONDS = 900
HEX = re.compile(r'[0-9a-f]{64}\Z')
_BASE: Any = None


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def _base() -> Any:
    global _BASE
    if _BASE is None:
        sys.path.insert(0, str(ROOT / 'evaluation_tools'))
        import dev_live_direction_sp_hp_supervisor as base
        _BASE = base
    return _BASE


def _direction() -> Any:
    sys.path.insert(0, str(ROOT / 'evaluation_tools'))
    import blind3_md4c_direction_supervised_dev as direction
    return direction


def _require_external_source_pin() -> None:
    if (globals().get('__VA_SOURCE_BOOTSTRAP_SHA__') != sha(Path(__file__)) or
            sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('live continuation requires external source pin and isolated Python')


def _historical() -> tuple[dict, Path, dict]:
    """Verify the immutable replay receipt and its eight Phase 1 files."""
    base = _base()
    base._plain_path(HISTORICAL_RECEIPT, directory=False)
    if sha(HISTORICAL_RECEIPT) != HISTORICAL_RECEIPT_SHA256:
        raise ValueError('post-hoc Direction receipt changed')
    receipt = json.loads(HISTORICAL_RECEIPT.read_text(encoding='utf-8'))
    if (receipt.get('kind') != 'DIRECTION_POSTHOC_OFFLINE_REPLAY_DEV_V1' or
            receipt.get('status') != 'OFFLINE_PHASE1_COMPLETE_DEV_ONLY' or
            receipt.get('historical_live_status') != 'CHILD_ERROR' or
            receipt.get('historical_model_physical') != 1 or
            receipt.get('historical_model_logical') != 1 or
            receipt.get('historical_model_retries') != 0 or
            receipt.get('replay_model_calls') != 0 or
            receipt.get('replay_scan_calls') != 0):
        raise ValueError('historical Direction identity or limits changed')
    run = Path(receipt['phase1_run'])
    base._plain_path(run, directory=True)
    if (run.parent.parent != HISTORICAL_RECEIPT.parent or
            run.parent.name != 'product_runs' or
            set(receipt.get('phase1_files_sha256', {})) != set(PHASE1_FILES) or
            set(path.name for path in run.iterdir()) != set(PHASE1_FILES)):
        raise ValueError('post-hoc Phase 1 run layout changed')
    for name in PHASE1_FILES:
        path = run / name
        base._plain_path(path, directory=False)
        if sha(path) != receipt['phase1_files_sha256'][name]:
            raise ValueError('post-hoc Phase 1 file changed')
    selection = json.loads((run / 'selection.json').read_text(encoding='utf-8'))
    pool = json.loads((run / 'function_pool.json').read_text(encoding='utf-8'))
    run_row = json.loads((run / 'run.json').read_text(encoding='utf-8'))
    ids = [row['function_id'] for row in pool]
    if (not isinstance(selection, dict) or len(ids) != len(set(ids)) or
            len(ids) != receipt['pool_count'] or
            selection.get('function_id') not in ids or
            selection.get('function_id') != run_row.get('selected_function_id') or
            run_row.get('selection_policy') != 'FBV2_FIRST_PASS_UNIQUE_DEV' or
            run_row.get('hp_project_state_dev') is True):
        raise ValueError('post-hoc Phase 1 selection identity changed')
    return receipt, run, {'selection': selection, 'pool_ids': ids}


def _source_pins() -> dict[str, str]:
    base = _base()
    return {'artifact': base.tree_digest(ARTIFACT, None),
            'target': base.tree_digest(TARGET, None),
            'oss_fuzz': base.tree_digest(OSS_FUZZ, None),
            'upstream': base.tree_digest(UPSTREAM, None)}


def prepare(output: Path) -> tuple[Path, str]:
    """Create a fresh private spec; no provider connection or model request."""
    base = _base()
    output = Path(output)
    if (not output.is_absolute() or output.exists() or output.is_symlink() or
            output.parent != REVIEW or
            any(parent.is_symlink() for parent in output.parents)):
        raise ValueError('continuation output must be fresh under Linux review root')
    base._plain_path(REVIEW, directory=True)
    historical, _run, selection = _historical()
    contract, config, executable = _direction()._pinned_contract(base)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    identity = os.stat(output, follow_symlinks=False)
    row = {
        'kind': 'BLIND3_MD4C_POSTHOC_SP_HP_CONTINUATION_DEV_V1',
        'scope': 'one current Phase1 function; SP1 HP1; no verifier PoV fuzz; not Blind3',
        'output_dir': str(output),
        'output_identity': {'dev': identity.st_dev, 'ino': identity.st_ino},
        'historical_receipt_path': str(HISTORICAL_RECEIPT),
        'historical_receipt_sha256': HISTORICAL_RECEIPT_SHA256,
        'historical_live_status': historical['historical_live_status'],
        'historical_direction_physical': historical['historical_model_physical'],
        'phase1_run': historical['phase1_run'],
        'phase1_files_sha256': historical['phase1_files_sha256'],
        'phase1_selection_sha256': historical['phase1_files_sha256']['selection.json'],
        'pool_count': len(selection['pool_ids']),
        'source_pins': _source_pins(),
        'code_pins': base._code_pins(),
        'dependency_versions': base._dependency_pins(),
        'driver_sha256': sha(Path(__file__)),
        'base_supervisor_sha256': sha(SUPERVISOR),
        'direction_boundary_sha256': sha(DIRECTION_BOUNDARY),
        'contract_sha256': sha(CONTRACT),
        'codex_config_sha256': sha(config),
        'codex_executable_sha256': sha(executable),
        'python_path': '/usr/bin/python3.12',
        'python_sha256': sha(Path('/usr/bin/python3.12')),
        'continuation_budget': {'physical': 2, 'logical': 2,
                                'retries': 0, 'wall_seconds': WALL_SECONDS,
                                'sp_generation': 1, 'function_analysis': 1,
                                'sp_verifier': 0, 'poc_generator': 0,
                                'assertion_generator': 0, 'fuzz_seconds': 0},
    }
    spec = output / SPEC_NAME
    base._write_once(spec, row)
    return spec, sha(spec)


def load_spec(path: Path, expected_sha256: str) -> dict:
    path = Path(path)
    if (not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)
            or path.is_symlink() or not path.is_file() or
            sha(path) != expected_sha256):
        raise ValueError('continuation spec pin changed')
    row = json.loads(path.read_text(encoding='utf-8'))
    base = _base()
    expected_keys = {'kind', 'scope', 'output_dir', 'output_identity',
        'historical_receipt_path', 'historical_receipt_sha256',
        'historical_live_status', 'historical_direction_physical',
        'phase1_run', 'phase1_files_sha256', 'phase1_selection_sha256',
        'pool_count', 'source_pins', 'code_pins', 'dependency_versions',
        'driver_sha256', 'base_supervisor_sha256',
        'direction_boundary_sha256', 'contract_sha256',
        'codex_config_sha256', 'codex_executable_sha256',
        'python_path', 'python_sha256', 'continuation_budget'}
    if (not isinstance(row, dict) or set(row) != expected_keys or
            row['kind'] != 'BLIND3_MD4C_POSTHOC_SP_HP_CONTINUATION_DEV_V1' or
            row['scope'] != 'one current Phase1 function; SP1 HP1; no verifier PoV fuzz; not Blind3' or
            row['historical_receipt_path'] != str(HISTORICAL_RECEIPT) or
            row['historical_receipt_sha256'] != HISTORICAL_RECEIPT_SHA256 or
            row['historical_live_status'] != 'CHILD_ERROR' or
            row['historical_direction_physical'] != 1 or
            row['continuation_budget'] != {'physical': 2, 'logical': 2,
                'retries': 0, 'wall_seconds': WALL_SECONDS,
                'sp_generation': 1, 'function_analysis': 1,
                'sp_verifier': 0, 'poc_generator': 0,
                'assertion_generator': 0, 'fuzz_seconds': 0} or
            row['driver_sha256'] != sha(Path(__file__)) or
            row['base_supervisor_sha256'] != sha(SUPERVISOR) or
            row['direction_boundary_sha256'] != sha(DIRECTION_BOUNDARY) or
            row['code_pins'] != base._code_pins() or
            row['dependency_versions'] != base._dependency_pins() or
            row['python_path'] != '/usr/bin/python3.12'):
        raise ValueError('continuation code, budget or ledger identity changed')
    output = Path(row['output_dir'])
    base._private_dir(output)
    identity = os.stat(output, follow_symlinks=False)
    if (path != output / SPEC_NAME or output.parent != REVIEW or
            row['output_identity'] != {'dev': identity.st_dev, 'ino': identity.st_ino}):
        raise ValueError('continuation output identity changed')
    historical, run, selection = _historical()
    if (row['phase1_run'] != str(run) or
            row['phase1_files_sha256'] != historical['phase1_files_sha256'] or
            row['phase1_selection_sha256'] != sha(run / 'selection.json') or
            row['pool_count'] != len(selection['pool_ids']) or
            row['source_pins'] != _source_pins()):
        raise ValueError('continuation source or Phase1 pin changed')
    _contract, config, executable = _direction()._pinned_contract(base)
    for item, expected in ((CONTRACT, row['contract_sha256']),
                           (config, row['codex_config_sha256']),
                           (executable, row['codex_executable_sha256']),
                           (Path(row['python_path']), row['python_sha256'])):
        if sha(item) != expected:
            raise ValueError('continuation route pin changed')
    return row


def offline_preflight(row: dict) -> dict:
    """Issue a same-process official V2 qualification without calling a model."""
    base = _base()
    contract, config, _ = _direction()._pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, toy, _app, _budget, _ledger = base._imports()
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    runner.verify_pinned_codex_executable(contract)
    roles = toy.live_role_models(contract)
    qualified = runner.require_official_qualification(contract)
    if not qualified.product_issued:
        raise ValueError('official V2 qualification not issued')
    _historical()
    return {'status': 'PREFLIGHT_PASS_NO_MODEL_CALL',
            'actual_provider_calls': 0,
            'official_v2_qualified': True,
            'historical_live_status': row['historical_live_status'],
            'historical_direction_physical': 1,
            'continuation_physical_before_live': 0,
            'pool_count': row['pool_count'],
            'selection_count': 1,
            'role_routes': {role: roles[role]
                for role in ('sp_generation', 'function_analysis')},
            'historical_receipt_sha256': HISTORICAL_RECEIPT_SHA256}


async def _run_child(row: dict, spec_sha256: str) -> dict:
    _require_external_source_pin()
    base = _base()
    contract, config, executable = _direction()._pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, toy, AppServer, Budget, Ledger = base._imports()
    from dev_global_appserver_bridge import verify_model_event_order
    from dev_global_appserver_product_flow import ProductBudgetAdapter
    from vulnerabilityanalysis.scan import scan_selected
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    roles = toy.live_role_models(contract)
    official = runner.require_official_qualification(contract)
    historical, source_run, context = _historical()
    output = Path(row['output_dir'])
    run = output / 'product_run'
    shutil.copytree(source_run, run, symlinks=False)
    for name in PHASE1_FILES:
        if sha(run / name) != row['phase1_files_sha256'][name]:
            raise ValueError('copied Phase1 file changed')
    model_cwd = output / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    base._private_dir(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('model cwd must be empty')
    base._write_once(output / 'OFFICIAL_V2_PRECHECK.json', {
        'spec_sha256': spec_sha256,
        'historical_receipt_sha256': HISTORICAL_RECEIPT_SHA256,
        'historical_live_status': 'CHILD_ERROR',
        'historical_direction_physical': 1,
        'continuation_physical_before_live': 0,
        'source_pins': row['source_pins'],
        'code_pins': row['code_pins'],
        'role_routes': {role: roles[role]
            for role in ('sp_generation', 'function_analysis')},
        'official_v2_qualified': bool(official.product_issued)})
    ledger = Ledger.create(Budget(
        physical_max=2, logical_max=2, retries_max=0,
        wall_seconds=WALL_SECONDS, initial_starts_required=2,
        sp_per_function=1, hp_per_function=1,
        combined_per_function=2, hp_analysis_per_function=1,
        hp_assertion_per_function=1), output / LEDGER_NAME)
    selected_id = context['selection']['function_id']
    if not ledger.select_function(selected_id):
        raise ValueError('one current Phase1 selection not eligible')
    with runner.private_codex_state(config):
        sandbox = runner.verify_model_namespace_sandbox(
            executable, _direction()._official_protected_paths(runner, contract))
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
            backend.bind_scope(selected_id)
            try:
                provider = ProductBudgetAdapter(backend, ledger, selected_id)
                await asyncio.wait_for(scan_selected(
                    run, provider, target_repository=TARGET,
                    target_binary=official.binary,
                    official_qualification=official,
                    role_models=roles, hallucination_prevent='on',
                    sp_llm_call_limit=1, hp_llm_call_limit=1,
                    hp_context_round_limit=0,
                    max_candidates=2, targeted_fuzz_seconds=0,
                    assertion_fuzz_seconds=0, global_fuzz_enabled=False,
                    run_command=None, initial_inputs=None), timeout=600)
            finally:
                backend.unbind_scope()
    if provider.rejected_prewire is not None:
        raise ValueError('product attempted an unbudgeted request')
    toy._verify_product_requests(ledger, run, selected_id, None)
    verify_model_event_order(ledger, output / 'MODEL_EVENTS.jsonl')
    roles_seen = [turn['role'] for turn in ledger.turns]
    if (roles_seen != ['sp_generation', 'function_analysis'] or
            ledger.physical != 2 or ledger.logical != 2 or ledger.retries != 0 or
            ledger.tainted or ledger.active_turn is not None or
            any(turn['status'] != 'COMPLETED' for turn in ledger.turns) or
            any(attempt['status'] != 'COMPLETED' for attempt in ledger.attempts)):
        raise ValueError('SP/HP continuation physical trace incomplete')
    scan = json.loads((run / 'scan.json').read_text(encoding='utf-8'))
    points = json.loads((run / 'sp/candidates.json').read_text(encoding='utf-8'))
    pending_ids = scan.get('pending_sp_ids')
    if (scan.get('selected_function_id') != selected_id or
            scan.get('hp_error') is not None or not isinstance(points, list) or
            not isinstance(pending_ids, list) or
            scan.get('sp_llm_calls') != 1 or scan.get('hp_llm_calls') != 1 or
            scan.get('llm_calls') != 2 or
            scan.get('effective_candidate_limit') != 0 or
            scan.get('poc_count') != 0 or
            scan.get('assertion_count') != 0 or
            scan.get('fuzz_seconds_allocated') != 0 or
            scan.get('selected_sp_ids') != [] or
            scan.get('verification_artifact_sha256') != {} or
            scan.get('observed_crash_ids') != [] or
            scan.get('fuzzer_observed_crash_ids') != [] or
            scan.get('verified_crash_ids') != []):
        raise ValueError('SP/HP continuation Scan incomplete')
    analysis_path = run / 'function_analysis.json'
    if not analysis_path.is_file() or analysis_path.is_symlink():
        raise ValueError('HP analysis artifact missing')
    analysis = json.loads(analysis_path.read_text(encoding='utf-8'))
    if (len(list((run / 'povs').glob('*.json'))) if (run / 'povs').exists()
            else 0):
        raise ValueError('PoV materialized despite zero downstream budget')
    for sp_id in pending_ids:
        ledger.mark_pending('verifier-' + sp_id, selected_id,
            'SP_VERIFIER', 'ONE_SP_GENERATION_CREDIT_ONLY')
    if analysis.get('safe_assumptions'):
        ledger.mark_pending('assertion-' + selected_id, selected_id,
            'ASSERTION', 'ONE_HP_ANALYSIS_CREDIT_ONLY')
    ledger.mark_scan_recorded(selected_id)
    for item in context['pool_ids']:
        if item != selected_id:
            ledger.mark_no_opportunity(item, 'ONE_FUNCTION_DEVELOPMENT_BOUND')
    restored = Ledger.restore(ledger.checkpoint_path, ledger.budget)
    if (restored.physical != ledger.physical or
            restored.function_counts != ledger.function_counts or
            restored.pending_work != ledger.pending_work):
        raise ValueError('continuation ledger restore changed accounting')
    if load_spec(output / SPEC_NAME, spec_sha256) != row:
        raise ValueError('continuation code or source changed during Scan')
    receipt = {
        'kind': 'BLIND3_MD4C_POSTHOC_SP_HP_CONTINUATION_RECEIPT_V1',
        'status': 'BOUNDED_SP_HP_OBSERVED_PENDING_DOWNSTREAM',
        'scope': 'development one-function continuation only; no Blind3',
        'spec_sha256': spec_sha256,
        'historical_receipt_sha256': HISTORICAL_RECEIPT_SHA256,
        'historical_live_status': historical['historical_live_status'],
        'historical_direction_physical': 1,
        'continuation_physical': ledger.physical,
        'continuation_logical': ledger.logical,
        'continuation_retries': ledger.retries,
        'combined_physical_ledger_claim': False,
        'official_v2_qualified': True,
        'pool_count': len(context['pool_ids']),
        'selected_count': 1,
        'sp_candidate_count': len(points),
        'hp_safe_count': len(analysis.get('safe_assumptions', [])),
        'hp_unknown_count': len(analysis.get('unknowns', [])),
        'verifier_calls': 0, 'pov_calls': 0, 'fuzz_seconds': 0,
        'pending_verifier_count': len(pending_ids),
        'pending_assertion_count': int(bool(analysis.get('safe_assumptions'))),
        'event_audit_status': 'PASS_FULL_NON_DELTA_PARAMS',
        'scan_sha256': sha(run / 'scan.json'),
        'sp_candidates_sha256': sha(run / 'sp/candidates.json'),
        'hp_analysis_sha256': sha(analysis_path),
        'ledger_sha256': sha(output / LEDGER_NAME),
        'model_event_log_sha256': sha(output / 'MODEL_EVENTS.jsonl'),
    }
    base._write_once(output / RECEIPT_NAME, receipt)
    child = {
        'status': receipt['status'], 'spec_sha256': spec_sha256,
        'historical_receipt_sha256': HISTORICAL_RECEIPT_SHA256,
        'receipt_sha256': sha(output / RECEIPT_NAME),
        'ledger_sha256': receipt['ledger_sha256'],
        'model_event_log_sha256': receipt['model_event_log_sha256'],
        'scan_sha256': receipt['scan_sha256'],
        'sp_candidates_sha256': receipt['sp_candidates_sha256'],
        'hp_analysis_sha256': receipt['hp_analysis_sha256'],
        'continuation_physical': 2, 'continuation_logical': 2,
        'continuation_retries': 0,
    }
    base._write_once(output / CHILD_NAME, child)
    return child


def _completion_predicate(child: dict, fd: int, _output: Path, *,
                          expected_spec_sha256: str) -> bool:
    """Parent validates the held output inode, ledger, event and Scan hashes."""
    try:
        direction = _direction()
        read = direction._read_beneath
        receipt_bytes = read(fd, RECEIPT_NAME)
        receipt = json.loads(receipt_bytes)
        if (child.get('status') != 'BOUNDED_SP_HP_OBSERVED_PENDING_DOWNSTREAM' or
                child.get('spec_sha256') != expected_spec_sha256 or
                child.get('historical_receipt_sha256') != HISTORICAL_RECEIPT_SHA256 or
                child.get('receipt_sha256') != hashlib.sha256(receipt_bytes).hexdigest() or
                receipt.get('spec_sha256') != expected_spec_sha256 or
                receipt.get('historical_live_status') != 'CHILD_ERROR' or
                receipt.get('historical_direction_physical') != 1 or
                receipt.get('combined_physical_ledger_claim') is not False or
                receipt.get('official_v2_qualified') is not True or
                receipt.get('selected_count') != 1 or
                receipt.get('continuation_physical') != 2 or
                receipt.get('continuation_logical') != 2 or
                receipt.get('continuation_retries') != 0 or
                receipt.get('verifier_calls') != 0 or
                receipt.get('pov_calls') != 0 or receipt.get('fuzz_seconds') != 0 or
                receipt.get('event_audit_status') !=
                    'PASS_FULL_NON_DELTA_PARAMS'):
            return False
        checks = ((LEDGER_NAME, 'ledger_sha256'),
                  ('MODEL_EVENTS.jsonl', 'model_event_log_sha256'),
                  ('product_run/scan.json', 'scan_sha256'),
                  ('product_run/sp/candidates.json', 'sp_candidates_sha256'),
                  ('product_run/function_analysis.json', 'hp_analysis_sha256'))
        for name, key in checks:
            actual = hashlib.sha256(read(fd, name, limit=64_000_000)).hexdigest()
            if actual != receipt.get(key) or actual != child.get(key):
                return False
        ledger = json.loads(read(fd, LEDGER_NAME))
        turns = ledger.get('turns', [])
        attempts = ledger.get('attempts', [])
        if (ledger.get('physical') != 2 or ledger.get('logical') != 2 or
                ledger.get('retries') != 0 or ledger.get('active_turn') is not None or
                [row.get('role') for row in turns] !=
                    ['sp_generation', 'function_analysis'] or
                [row.get('status') for row in turns] !=
                    ['COMPLETED', 'COMPLETED'] or
                [row.get('status') for row in attempts] !=
                    ['COMPLETED', 'COMPLETED'] or
                any(row.get('accepted') is not True or
                    row.get('response_saved') is not True or
                    not isinstance(row.get('app_server_turn_id'), str) or
                    row.get('request_hash') != turn.get('hash')
                    for row, turn in zip(attempts, turns, strict=True)) or
                len(ledger.get('selected_functions', [])) != 1 or
                ledger.get('direction_scopes') != []):
            return False
        points = json.loads(read(fd, 'product_run/sp/candidates.json'))
        analysis = json.loads(read(fd, 'product_run/function_analysis.json'))
        scan = json.loads(read(fd, 'product_run/scan.json'))
        events = read(fd, 'MODEL_EVENTS.jsonl', limit=64_000_000)
        delta = {'item/agentMessage/delta', 'item/reasoning/textDelta',
                 'item/reasoning/summaryTextDelta'}
        for line in events.splitlines():
            event = json.loads(line)
            if (not isinstance(event, dict) or
                    event.get('server_request') is not False or
                    event.get('item_type') not in
                        (None, 'userMessage', 'agentMessage', 'reasoning') or
                    (event.get('method') not in delta | {'<response>'} and
                     not isinstance(event.get('params'), dict))):
                return False
        return (isinstance(points, list) and
                receipt.get('sp_candidate_count') == len(points) and
                receipt.get('pending_verifier_count') ==
                    len(scan.get('pending_sp_ids', [])) and
                receipt.get('hp_safe_count') == len(analysis.get('safe_assumptions', [])) and
                receipt.get('hp_unknown_count') == len(analysis.get('unknowns', [])) and
                receipt.get('pending_assertion_count') ==
                    int(bool(analysis.get('safe_assumptions'))) and
                scan.get('selected_function_id') ==
                    ledger['selected_functions'][0] and
                scan.get('sp_llm_calls') == 1 and
                scan.get('hp_llm_calls') == 1 and
                scan.get('effective_candidate_limit') == 0 and
                scan.get('poc_count') == 0 and
                scan.get('assertion_count') == 0 and
                scan.get('fuzz_seconds_allocated') == 0 and
                scan.get('verification_artifact_sha256') == {} and
                scan.get('observed_crash_ids') == [] and
                scan.get('fuzzer_observed_crash_ids') == [] and
                scan.get('verified_crash_ids') == [])
    except Exception:
        return False


def run_supervised(spec: Path, expected_sha256: str) -> dict:
    _require_external_source_pin()
    row = load_spec(spec, expected_sha256)
    output = Path(row['output_dir'])
    if any((output / name).exists() for name in
           (LEDGER_NAME, CHILD_NAME, RECEIPT_NAME)):
        raise ValueError('continuation attempt already started')
    base = _base()
    contract, _, _ = _direction()._pinned_contract(base)
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
        child, fd, held, expected_spec_sha256=expected_sha256)
    if load_spec(spec, expected_sha256) != row:
        raise ValueError('continuation pins changed before child launch')
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
    parser.add_argument('path', type=Path)
    parser.add_argument('sha256', nargs='?')
    args = parser.parse_args(argv)
    if (sys.executable != '/usr/bin/python3.12' or
            not sys.flags.isolated or not sys.dont_write_bytecode):
        raise ValueError('use /usr/bin/python3.12 -I -B')
    if args.prepare:
        spec, expected = prepare(args.path)
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
        try:
            asyncio.run(_run_child(row, args.sha256))
        except BaseException as exc:
            # A failed or cancelled model turn never becomes a negative
            # vulnerability result. The durable ledger remains separate from
            # the historical Direction trace and wins over this summary.
            output = Path(row['output_dir'])
            if not (output / CHILD_NAME).exists():
                base = _base()
                base._write_once(output / CHILD_NAME, {
                    'status': 'INCOMPLETE_CONTINUATION',
                    'error_type': type(exc).__name__,
                    'historical_live_status': 'CHILD_ERROR',
                    'historical_direction_physical': 1,
                    'combined_physical_ledger_claim': False,
                    'ledger': base._evidence(output / LEDGER_NAME),
                    'model_events': base._evidence(
                        output / 'MODEL_EVENTS.jsonl')})
            raise
        return 0
    result = run_supervised(args.path, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
