"""One bounded HP Context follow-up from pinned md4c development evidence.

This evaluation tool does not resume Scan or change the historical failed
SP/HP supervisor result. It fetches the two recorded HP ContextRequests from
the official V2 source/graph and asks Function Analyzer once on a separate
physical ledger. Prepare and preflight never call a model.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'review'
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
PRIOR = REVIEW / 'BLIND3_MD4C_SP_HP_CONTINUATION_PREFLIGHT_V1_20261030'
POSTHOC = (REVIEW / 'BLIND3_MD4C_SP_HP_POSTHOC_AUDIT_20261030' /
           'SP_HP_POSTHOC_AUDIT_RECEIPT.json')
POSTHOC_SHA = 'aa0d171e69633dda87a67c562d85611ea26e0bc31230a6fc9a0eb4c9eddc13d4'
CONTRACT = ROOT / 'tools/FROZEN_CONTRACT_ATTEMPT3.json'
ARTIFACT = ROOT / 'v2_artifact_stage/attempt'
TARGET = ROOT / 'model_target'
OSS_FUZZ = ROOT / 'oss_fuzz_checkout'
UPSTREAM = ROOT / 'upstream_asan_final'
SUPERVISOR = ROOT / 'evaluation_tools/dev_live_direction_sp_hp_supervisor.py'
DIRECTION = ROOT / 'evaluation_tools/blind3_md4c_direction_supervised_dev.py'
SPEC_NAME = 'HP_CONTEXT_FOLLOWUP_SPEC.json'
CONTEXT_NAME = 'HP_CONTEXT_INPUT.json'
RECEIPT_NAME = 'HP_CONTEXT_FOLLOWUP_RECEIPT.json'
CHILD_NAME = 'DEV_LIVE_CHILD_RESULT.json'
LEDGER_NAME = 'GLOBAL_LEDGER.json'
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
        sys.path[:0] = [str(ROOT / 'evaluation_tools'),
                        str(ROOT / 'review_tools'), str(PRODUCT / 'src')]
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
        raise ValueError('live HP follow-up requires external source pin and isolated Python')


def _original() -> tuple[dict, dict, dict, dict, dict, Path]:
    """Verify immutable failed-parent files and the separate post-hoc audit."""
    base = _base()
    base._plain_path(POSTHOC, directory=False)
    if sha(POSTHOC) != POSTHOC_SHA:
        raise ValueError('SP/HP post-hoc audit receipt changed')
    receipt = json.loads(POSTHOC.read_text(encoding='utf-8'))
    if (receipt.get('kind') != 'BLIND3_MD4C_SP_HP_POSTHOC_AUDIT_DEV_V1' or
            receipt.get('posthoc_status') !=
                'PRODUCT_SP_HP_AND_EVENT_LINEAGE_CONFIRMED_DEV_ONLY' or
            receipt.get('original_supervisor_status') != 'CHILD_ERROR' or
            receipt.get('original_child_status') != 'INCOMPLETE_CONTINUATION' or
            receipt.get('continuation_physical') != 2 or
            receipt.get('continuation_logical') != 2 or
            receipt.get('continuation_retries') != 0 or
            receipt.get('combined_ledger_claim') is not False or
            receipt.get('event_audit', {}).get('status') != 'PASS_EVENT_LINEAGE'):
        raise ValueError('historical SP/HP outcome or event audit changed')
    for name, expected in receipt.get('source_pins', {}).items():
        relative = Path(name)
        if (relative.is_absolute() or '..' in relative.parts or not relative.parts or
                not isinstance(expected, str) or not HEX.fullmatch(expected)):
            raise ValueError('post-hoc source pin invalid')
        path = PRIOR / relative
        base._plain_path(path, directory=False)
        if sha(path) != expected:
            raise ValueError('historical SP/HP source changed')
    if len(receipt.get('source_pins', {})) != 9:
        raise ValueError('historical SP/HP source set incomplete')
    run = PRIOR / 'product_run'
    base._plain_path(run, directory=True)
    for relative in ('selection.json', 'source_span.json',
                     'sp/initial_call_context.json'):
        base._plain_path(run / relative, directory=False)
    request_paths = list((run / 'logs').glob('function_analysis_*_request.json'))
    if len(request_paths) != 1:
        raise ValueError('historical HP request is not unique')
    request_path = request_paths[0]
    base._plain_path(request_path, directory=False)
    request = json.loads(request_path.read_text(encoding='utf-8'))
    selection = json.loads((run / 'selection.json').read_text(encoding='utf-8'))
    analysis = json.loads((run / 'function_analysis.json').read_text(encoding='utf-8'))
    span = json.loads((run / 'source_span.json').read_text(encoding='utf-8'))
    ledger = json.loads((PRIOR / LEDGER_NAME).read_text(encoding='utf-8'))
    from dev_global_appserver_bridge import artifact_hash
    turns, attempts = ledger.get('turns', []), ledger.get('attempts', [])
    if (len(turns) != 2 or len(attempts) != 2 or
            turns[1].get('role') != 'function_analysis' or
            turns[1].get('scope_id') != selection.get('function_id') or
            turns[1].get('status') != 'COMPLETED' or
            attempts[1].get('status') != 'COMPLETED' or
            attempts[1].get('request_hash') != turns[1].get('hash') or
            artifact_hash(request) != turns[1].get('hash')):
        raise ValueError('historical HP request differs from physical ledger')
    if (request.get('role') != 'function_analysis' or
            request.get('model') != 'gpt-5.6-sol' or
            request.get('reasoning') != 'max' or
            not isinstance(request.get('payload'), dict) or
            request['payload'].get('function_name') != selection.get('function_name') or
            request['payload'].get('source_file') != selection.get('source_file') or
            request['payload'].get('source_start_line') is not None or
            request['payload'].get('context') != [] or
            analysis.get('function_id') != selection.get('function_id') or
            span.get('function_id') != selection.get('function_id') or
            len(analysis.get('context_requests', [])) != 2 or
            not isinstance(request['payload'].get('analysis_scope'), dict)):
        raise ValueError('historical HP request or Context identity changed')
    return receipt, request, selection, analysis, span, request_path


def _resolved_input() -> dict:
    """Recompute precisely the recorded ContextRequests from official source."""
    _base()
    from vulnerabilityanalysis.adapter import HarnessAdapter
    from vulnerabilityanalysis.context import ContextResolver
    from vulnerabilityanalysis.models import ContextRequest
    from vulnerabilityanalysis.scan import _fresh_analysis_context
    from vulnerabilityanalysis.source import SourceRepository

    receipt, request, selection, analysis, prior_span, request_path = _original()
    harness = HarnessAdapter().load(ARTIFACT, target_repository=TARGET)
    source_repo = SourceRepository(TARGET, harness.function_catalog)
    source_span = source_repo.open_function_span(selection['function_id'])
    source_path = source_repo.source_path(selection['function_id'])
    if (source_span.start_line != prior_span.get('start_line') or
            source_span.end_line != prior_span.get('end_line') or
            source_span.source_sha256 != prior_span.get('source_sha256') or
            source_span.source_file_sha256 != prior_span.get('source_file_sha256') or
            str(source_path.resolve()) != prior_span.get('source_file') or
            source_span.source != request['payload']['source'] or
            Path(request['payload']['harness_source_file']) !=
                Path(harness.harness_path) or
            request['payload']['harness_source'] !=
                Path(harness.harness_path).read_text(encoding='utf-8', errors='replace')):
        raise ValueError('official source differs from historical HP request')
    root = harness.metadata.get('run_root')
    if not isinstance(root, str):
        raise ValueError('official call graph root unavailable')
    graph = Path(root) / 'analysis/edges.jsonl'
    _base()._plain_path(graph, directory=False)
    prior_initial = json.loads((PRIOR / 'product_run/sp/initial_call_context.json').read_text())
    if sha(graph) != prior_initial.get('audit', {}).get('graph_sha256'):
        raise ValueError('official graph differs from historical SP Context')
    resolver = ContextResolver(source_repo, call_graph_path=graph,
        harness_path=Path(harness.harness_path), build_command=None)
    held: list[dict[str, str]] = []
    records: list[dict] = []
    for row in analysis['context_requests']:
        req = ContextRequest(**row)
        if req.requesting_function != selection['function_id']:
            raise ValueError('HP Context request changed selected function')
        resolved = resolver.resolve(req)
        fresh = _fresh_analysis_context(resolved, held)
        if not fresh or resolver.last_limit_events:
            raise ValueError('HP Context request unresolved or truncated')
        for item in fresh:
            path = Path(item.get('source_file', ''))
            if (not path.is_absolute() or path.is_symlink() or
                    not path.is_relative_to(TARGET)):
                raise ValueError('HP Context source escaped official Target')
        held.extend(fresh)
        records.append({'request_type': req.request_type, 'target': req.target,
                        'status': 'FETCHED', 'record_count': len(fresh),
                        'source_sha256': digest(fresh)})
    return {'kind': 'PINNED_OFFICIAL_HP_CONTEXT_INPUT_DEV_V1',
            'prior_request_sha256': sha(request_path),
            'prior_analysis_sha256': sha(PRIOR / 'product_run/function_analysis.json'),
            'prior_source_span_sha256': sha(PRIOR / 'product_run/source_span.json'),
            'prior_initial_context_sha256': sha(
                PRIOR / 'product_run/sp/initial_call_context.json'),
            'official_graph_sha256': sha(graph),
            'source_sha256': source_span.source_sha256,
            'source_start_line': source_span.start_line,
            'selected_function_id': selection['function_id'],
            'records': records, 'context': held,
            'context_sha256': digest(held),
            'historical_posthoc_sha256': POSTHOC_SHA,
            'historical_original_status': receipt['original_supervisor_status']}


def _source_pins() -> dict[str, str]:
    base = _base()
    return {'artifact': base.tree_digest(ARTIFACT, None),
            'target': base.tree_digest(TARGET, None),
            'oss_fuzz': base.tree_digest(OSS_FUZZ, None),
            'upstream': base.tree_digest(UPSTREAM, None)}


def prepare(output: Path) -> tuple[Path, str]:
    base = _base()
    output = Path(output)
    if (not output.is_absolute() or output.exists() or output.is_symlink() or
            output.parent != REVIEW or any(parent.is_symlink() for parent in output.parents)):
        raise ValueError('HP output must be fresh under Linux review root')
    base._plain_path(REVIEW, directory=True)
    context = _resolved_input()
    contract, config, executable = _direction()._pinned_contract(base)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    base._write_once(output / CONTEXT_NAME, context)
    identity = os.stat(output, follow_symlinks=False)
    row = {'kind': 'BLIND3_MD4C_HP_CONTEXT_FOLLOWUP_DEV_V1',
           'scope': 'one isolated HP Context re-analysis; no Scan/Assertion/fuzz/Blind3',
           'output_dir': str(output),
           'output_identity': {'dev': identity.st_dev, 'ino': identity.st_ino},
           'original_dir': str(PRIOR), 'original_posthoc_sha256': POSTHOC_SHA,
           'original_sp_hp_status': 'CHILD_ERROR',
           'original_sp_hp_physical_separate': 2,
           'historical_direction_physical_separate': 1,
           'context_input_sha256': sha(output / CONTEXT_NAME),
           'context_sha256': context['context_sha256'],
           'prior_request_sha256': context['prior_request_sha256'],
           'prior_analysis_sha256': context['prior_analysis_sha256'],
           'prior_source_span_sha256': context['prior_source_span_sha256'],
           'prior_initial_context_sha256': context['prior_initial_context_sha256'],
           'official_graph_sha256': context['official_graph_sha256'],
           'source_pins': _source_pins(), 'code_pins': base._code_pins(),
           'dependency_versions': base._dependency_pins(),
           'driver_sha256': sha(Path(__file__)),
           'base_supervisor_sha256': sha(SUPERVISOR),
           'direction_boundary_sha256': sha(DIRECTION),
           'contract_sha256': sha(CONTRACT),
           'codex_config_sha256': sha(config),
           'codex_executable_sha256': sha(executable),
           'python_path': '/usr/bin/python3.12',
           'python_sha256': sha(Path('/usr/bin/python3.12')),
           'budget': {'physical': 1, 'logical': 1, 'retries': 0,
                      'wall_seconds': WALL_SECONDS, 'function_analysis': 1,
                      'sp': 0, 'verifier': 0, 'pov': 0, 'assertion': 0,
                      'fuzz_seconds': 0}}
    spec = output / SPEC_NAME
    base._write_once(spec, row)
    return spec, sha(spec)


def load_spec(spec: Path, expected_sha256: str) -> dict:
    base = _base()
    spec = Path(spec)
    if (not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256) or
            spec.is_symlink() or not spec.is_file() or sha(spec) != expected_sha256):
        raise ValueError('HP spec pin changed')
    row = json.loads(spec.read_text(encoding='utf-8'))
    output = Path(row['output_dir'])
    base._private_dir(output)
    stat = os.stat(output, follow_symlinks=False)
    if (row.get('kind') != 'BLIND3_MD4C_HP_CONTEXT_FOLLOWUP_DEV_V1' or
            row.get('scope') !=
                'one isolated HP Context re-analysis; no Scan/Assertion/fuzz/Blind3' or
            row.get('output_identity') != {'dev': stat.st_dev, 'ino': stat.st_ino} or
            output.parent != REVIEW or spec != output / SPEC_NAME or
            row.get('original_dir') != str(PRIOR) or
            row.get('original_posthoc_sha256') != POSTHOC_SHA or
            row.get('original_sp_hp_status') != 'CHILD_ERROR' or
            row.get('original_sp_hp_physical_separate') != 2 or
            row.get('historical_direction_physical_separate') != 1 or
            row.get('budget') != {'physical': 1, 'logical': 1, 'retries': 0,
                'wall_seconds': WALL_SECONDS, 'function_analysis': 1,
                'sp': 0, 'verifier': 0, 'pov': 0, 'assertion': 0,
                'fuzz_seconds': 0} or
            row.get('driver_sha256') != sha(Path(__file__)) or
            row.get('base_supervisor_sha256') != sha(SUPERVISOR) or
            row.get('direction_boundary_sha256') != sha(DIRECTION) or
            row.get('code_pins') != base._code_pins() or
            row.get('dependency_versions') != base._dependency_pins() or
            row.get('source_pins') != _source_pins()):
        raise ValueError('HP spec shape, source or code pin changed')
    context = _resolved_input()
    path = output / CONTEXT_NAME
    base._plain_path(path, directory=False)
    if (sha(path) != row.get('context_input_sha256') or
            json.loads(path.read_text(encoding='utf-8')) != context or
            context['context_sha256'] != row.get('context_sha256') or
            any(context[key] != row.get(key) for key in (
                'prior_request_sha256', 'prior_analysis_sha256',
                'prior_source_span_sha256', 'prior_initial_context_sha256',
                'official_graph_sha256'))):
        raise ValueError('HP resolved Context pin changed')
    _contract, config, executable = _direction()._pinned_contract(base)
    for item, expected in ((CONTRACT, row['contract_sha256']),
                           (config, row['codex_config_sha256']),
                           (executable, row['codex_executable_sha256']),
                           (Path(row['python_path']), row['python_sha256'])):
        if sha(item) != expected:
            raise ValueError('HP route pin changed')
    return row


def offline_preflight(row: dict) -> dict:
    base = _base()
    contract, config, executable = _direction()._pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, toy, _app, _budget, _ledger = base._imports()
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    runner.verify_pinned_codex_executable(contract)
    official = runner.require_official_qualification(contract)
    roles = toy.live_role_models(contract)
    if (not official.product_issued or
            roles['function_analysis'] != {'model': 'gpt-5.6-sol',
                                          'reasoning': 'max'}):
        raise ValueError('official V2 or HP model route unavailable')
    context = _resolved_input()
    return {'status': 'PREFLIGHT_PASS_NO_MODEL_CALL',
            'provider_calls': 0, 'official_v2_qualified': True,
            'original_status': 'CHILD_ERROR',
            'original_physical_separate': 2,
            'resolved_requests': len(context['records']),
            'context_records': len(context['context']),
            'context_sha256': context['context_sha256'],
            'hp_route': roles['function_analysis']}


async def _run_child(row: dict, spec_sha256: str) -> dict:
    _require_external_source_pin()
    base = _base()
    contract, config, executable = _direction()._pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, toy, AppServer, Budget, Ledger = base._imports()
    from dev_global_appserver_bridge import artifact_hash, verify_model_event_order
    from vulnerabilityanalysis.adapter import HarnessAdapter
    from vulnerabilityanalysis.agents import AgentPipeline
    from vulnerabilityanalysis.source import SourceRepository
    runner.verify_loaded_module_origins(sys.modules,
        ROOT / 'evaluation_tools', PRODUCT / 'src')
    runner.check_zero_retry_config(
        config, contract['default_model'], contract['default_effort'])
    official = runner.require_official_qualification(contract)
    if not official.product_issued:
        raise ValueError('official V2 qualification missing')
    roles = toy.live_role_models(contract)
    context = _resolved_input()
    original, request, selection, _analysis, _span, _request_path = _original()
    output = Path(row['output_dir'])
    base._write_once(output / 'OFFICIAL_V2_PRECHECK.json', {
        'spec_sha256': spec_sha256, 'official_v2_qualified': True,
        'original_posthoc_sha256': POSTHOC_SHA,
        'original_supervisor_status': original['original_supervisor_status'],
        'original_sp_hp_physical_separate': 2,
        'new_physical_before_live': 0,
        'code_pins': row['code_pins'], 'source_pins': row['source_pins'],
        'hp_route': roles['function_analysis']})
    harness = HarnessAdapter().load(ARTIFACT, target_repository=TARGET)
    source_repo = SourceRepository(TARGET, harness.function_catalog)
    source_span = source_repo.open_function_span(selection['function_id'])
    source_path = source_repo.source_path(selection['function_id'])
    model_cwd = output / 'model_cwd'
    model_cwd.mkdir(mode=0o700)
    base._private_dir(model_cwd)
    if any(model_cwd.iterdir()):
        raise ValueError('HP model cwd not empty')
    ledger = Ledger.create(Budget(
        physical_max=1, logical_max=1, retries_max=0,
        wall_seconds=WALL_SECONDS, initial_starts_required=1,
        sp_per_function=1, hp_per_function=1,
        combined_per_function=2, hp_analysis_per_function=1,
        hp_assertion_per_function=1), output / LEDGER_NAME)
    if not ledger.select_function(selection['function_id']):
        raise ValueError('HP selected function unavailable')
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
            backend.bind_scope(selection['function_id'])
            try:
                pipeline = AgentPipeline(backend,
                    max_context_requests=2, role_models=roles,
                    schema_error_dir=output / 'logs')
                analysis = await asyncio.wait_for(pipeline.analyze_function(
                    selection['function_id'], selection['function_name'],
                    selection['source_file'], source_span.source,
                    context['context'],
                    harness_source=Path(harness.harness_path).read_text(
                        encoding='utf-8', errors='replace'),
                    harness_source_path=Path(harness.harness_path),
                    analysis_scope=request['payload']['analysis_scope'],
                    source_start_line=source_span.start_line), timeout=600)
            finally:
                backend.unbind_scope()
    artifacts = pipeline.last_request_artifacts
    if (not isinstance(artifacts, dict) or
            set(artifacts) != {'request_artifact', 'response_artifact',
                              'raw_response_artifact'}):
        raise ValueError('HP request artifacts incomplete')
    names: dict[str, str] = {}
    for key, value in artifacts.items():
        if not isinstance(value, str):
            raise ValueError('HP request artifact missing')
        path = Path(value)
        if path.parent != output / 'logs' or path.is_symlink() or not path.is_file():
            raise ValueError('HP request artifact escaped private output')
        names[key] = path.relative_to(output).as_posix()
    request_row = json.loads((output / names['request_artifact']).read_text())
    if (request_row['role'] != 'function_analysis' or
            request_row['model'] != roles['function_analysis']['model'] or
            request_row['reasoning'] != roles['function_analysis']['reasoning'] or
            request_row['payload'].get('context') != context['context'] or
            request_row['payload'].get('source_start_line') != source_span.start_line or
            request_row['payload'].get('source') != '\n'.join(
                f'{source_span.start_line + i}: {line}'
                for i, line in enumerate(source_span.source.splitlines())) or
            request_row['payload'].get('analysis_scope') !=
                request['payload']['analysis_scope'] or
            artifact_hash(request_row) != ledger.turns[0]['hash'] or
            ledger.physical != 1 or ledger.logical != 1 or ledger.retries != 0 or
            ledger.active_turn is not None or
            ledger.turns[0]['role'] != 'function_analysis' or
            ledger.turns[0]['status'] != 'COMPLETED' or
            ledger.attempts[0]['status'] != 'COMPLETED' or
            ledger.attempts[0].get('response_saved') is not True):
        raise ValueError('HP follow-up physical/request trace incomplete')
    verify_model_event_order(ledger, output / 'MODEL_EVENTS.jsonl')
    audited = runner.verify_formal_model_event_order(SimpleNamespace(
        attempts=[{**ledger.attempts[0],
                   'model': roles['function_analysis']['model']}],
        physical=ledger.physical), output / 'MODEL_EVENTS.jsonl')
    if audited.get('status') != 'PASS_EVENT_LINEAGE':
        raise ValueError('HP formal model event audit failed')
    base._write_once(output / 'HP_FOLLOWUP_ANALYSIS.json', asdict(analysis))
    base._write_once(output / 'HP_PENDING_CONTEXT_REQUESTS.json', {
        'status': 'PENDING_UNFULFILLED',
        'retained': [asdict(item) for item in analysis.context_requests],
        'omitted_per_turn_limit': pipeline.last_context_request_omitted,
        'additional_model_calls': 0})
    restored = Ledger.restore(ledger.checkpoint_path, ledger.budget)
    if (restored.physical, restored.logical, restored.retries) != (1, 1, 0):
        raise ValueError('HP ledger restore changed accounting')
    if load_spec(output / SPEC_NAME, spec_sha256) != row:
        raise ValueError('HP source or spec changed during live turn')
    file_hashes = {name: sha(output / name) for name in (
        CONTEXT_NAME, LEDGER_NAME, 'MODEL_EVENTS.jsonl',
        'HP_FOLLOWUP_ANALYSIS.json', 'HP_PENDING_CONTEXT_REQUESTS.json',
        'OFFICIAL_V2_PRECHECK.json', 'SANDBOX_SELF_TEST.json',
        *names.values())}
    receipt = {'kind': 'BLIND3_MD4C_HP_CONTEXT_FOLLOWUP_RECEIPT_DEV_V1',
               'status': 'ISOLATED_HP_ANALYSIS_COMPLETE_DEV_ONLY',
               'spec_sha256': spec_sha256,
               'original_posthoc_sha256': POSTHOC_SHA,
               'original_supervisor_status': 'CHILD_ERROR',
               'original_sp_hp_physical_separate': 2,
               'historical_direction_physical_separate': 1,
               'new_physical': 1, 'new_logical': 1, 'new_retries': 0,
               'combined_ledger_claim': False,
               'official_v2_qualified': True,
               'context_sha256': context['context_sha256'],
               'context_record_count': len(context['context']),
               'safe_count': len(analysis.safe_assumptions),
               'unknown_count': len(analysis.unknowns),
               'pending_context_request_count': (len(analysis.context_requests) +
                                                 len(pipeline.last_context_request_omitted)),
               'omitted_context_request_count':
                   len(pipeline.last_context_request_omitted),
               'assertion_calls': 0, 'verifier_calls': 0,
               'pov_calls': 0, 'fuzz_seconds': 0,
               'event_audit': audited, 'artifact_paths': names,
               'file_hashes': file_hashes}
    base._write_once(output / RECEIPT_NAME, receipt)
    child = {'status': receipt['status'], 'spec_sha256': spec_sha256,
             'receipt_sha256': sha(output / RECEIPT_NAME),
             'ledger_sha256': file_hashes[LEDGER_NAME],
             'event_log_sha256': file_hashes['MODEL_EVENTS.jsonl'],
             'analysis_sha256': file_hashes['HP_FOLLOWUP_ANALYSIS.json'],
             'physical': 1, 'logical': 1, 'retries': 0}
    base._write_once(output / CHILD_NAME, child)
    return child


_FIXED_HASHED_FILES = frozenset({
    CONTEXT_NAME, LEDGER_NAME, 'MODEL_EVENTS.jsonl',
    'HP_FOLLOWUP_ANALYSIS.json', 'HP_PENDING_CONTEXT_REQUESTS.json',
    'OFFICIAL_V2_PRECHECK.json', 'SANDBOX_SELF_TEST.json',
})


def _required_hashed_files(receipt: dict) -> set[str] | None:
    """No child-supplied path can reduce or expand the parent's evidence set."""
    paths = receipt.get('artifact_paths')
    files = receipt.get('file_hashes')
    if (not isinstance(paths, dict) or
            set(paths) != {'request_artifact', 'response_artifact',
                           'raw_response_artifact'} or
            not isinstance(files, dict)):
        return None
    names = [paths[key] for key in ('request_artifact', 'response_artifact',
                                   'raw_response_artifact')]
    if (any(not isinstance(name, str) or Path(name).parent != Path('logs')
            for name in names) or len(set(names)) != 3 or
            not names[0].endswith('_request.json') or
            not names[1].endswith('_parsed.json') or
            not names[2].endswith('_raw.txt')):
        return None
    stems = (names[0].removesuffix('_request.json'),
             names[1].removesuffix('_parsed.json'),
             names[2].removesuffix('_raw.txt'))
    if len(set(stems)) != 1 or not stems[0].startswith('logs/function_analysis_'):
        return None
    required = set(_FIXED_HASHED_FILES) | set(names)
    return required if set(files) == required else None


def _completion_predicate(child: dict, directory_fd: int, _output: Path,
                          *, spec_sha256: str, output: Path) -> bool:
    try:
        read = _direction()._read_beneath
        receipt_bytes = read(directory_fd, RECEIPT_NAME)
        receipt = json.loads(receipt_bytes)
        spec_bytes = read(directory_fd, SPEC_NAME)
        spec_row = json.loads(spec_bytes)
        if (child.get('status') != 'ISOLATED_HP_ANALYSIS_COMPLETE_DEV_ONLY' or
                child.get('spec_sha256') != spec_sha256 or
                child.get('receipt_sha256') !=
                    hashlib.sha256(receipt_bytes).hexdigest() or
                child.get('physical') != 1 or child.get('logical') != 1 or
                child.get('retries') != 0 or
                receipt.get('spec_sha256') != spec_sha256 or
                hashlib.sha256(spec_bytes).hexdigest() != spec_sha256 or
                receipt.get('original_supervisor_status') != 'CHILD_ERROR' or
                receipt.get('combined_ledger_claim') is not False or
                receipt.get('official_v2_qualified') is not True or
                receipt.get('event_audit', {}).get('status') !=
                    'PASS_EVENT_LINEAGE'):
            return False
        files = receipt.get('file_hashes')
        if _required_hashed_files(receipt) is None:
            return False
        for name, expected in files.items():
            if (not isinstance(name, str) or Path(name).is_absolute() or
                    '..' in Path(name).parts or not isinstance(expected, str) or
                    not HEX.fullmatch(expected) or
                    hashlib.sha256(read(directory_fd, name, limit=64_000_000)).hexdigest()
                    != expected):
                return False
        if (files.get(LEDGER_NAME) != child.get('ledger_sha256') or
                files.get(CONTEXT_NAME) is None or
                files.get('MODEL_EVENTS.jsonl') != child.get('event_log_sha256') or
                files.get('HP_FOLLOWUP_ANALYSIS.json') != child.get('analysis_sha256') or
                receipt.get('event_audit', {}).get('event_log_sha256') !=
                    child.get('event_log_sha256')):
            return False
        ledger = json.loads(read(directory_fd, LEDGER_NAME))
        attempts, turns = ledger.get('attempts', []), ledger.get('turns', [])
        if (ledger.get('physical') != 1 or ledger.get('logical') != 1 or
                ledger.get('retries') != 0 or ledger.get('active_turn') is not None or
                len(attempts) != 1 or len(turns) != 1 or
                attempts[0].get('status') != 'COMPLETED' or
                attempts[0].get('response_saved') is not True or
                attempts[0].get('accepted') is not True or
                turns[0].get('status') != 'COMPLETED' or
                turns[0].get('role') != 'function_analysis' or
                attempts[0].get('request_hash') != turns[0].get('hash')):
            return False
        request_name = receipt['artifact_paths']['request_artifact']
        from dev_global_appserver_bridge import artifact_hash
        request = json.loads(read(directory_fd, request_name))
        context_input = json.loads(read(directory_fd, CONTEXT_NAME))
        if (artifact_hash(request) != turns[0]['hash'] or
                files[CONTEXT_NAME] != spec_row.get('context_input_sha256') or
                not isinstance(context_input.get('context'), list) or
                digest(context_input['context']) !=
                    context_input.get('context_sha256') or
                request['payload'].get('context') != context_input['context'] or
                request['payload'].get('source_start_line') !=
                    context_input.get('source_start_line')):
            return False
        analysis = json.loads(read(directory_fd, 'HP_FOLLOWUP_ANALYSIS.json'))
        pending = json.loads(read(directory_fd, 'HP_PENDING_CONTEXT_REQUESTS.json'))
        if (receipt.get('safe_count') != len(analysis.get('safe_assumptions', [])) or
                receipt.get('unknown_count') != len(analysis.get('unknowns', [])) or
                pending.get('status') != 'PENDING_UNFULFILLED' or
                pending.get('additional_model_calls') != 0 or
                pending.get('retained') != analysis.get('context_requests') or
                receipt.get('omitted_context_request_count') !=
                    len(pending.get('omitted_per_turn_limit', [])) or
                receipt.get('pending_context_request_count') !=
                    len(pending['retained']) +
                    len(pending['omitted_per_turn_limit']) or
                receipt.get('context_sha256') !=
                    context_input['context_sha256']):
            return False
        # The event audit is recomputed from pinned bytes; model identity comes
        # from the separately pinned role route, not the dev ledger's attempt.
        import blind2_runner_draft as runner
        route = json.loads(read(directory_fd, 'OFFICIAL_V2_PRECHECK.json'))['hp_route']
        if route != {'model': 'gpt-5.6-sol', 'reasoning': 'max'}:
            return False
        event_bytes = read(directory_fd, 'MODEL_EVENTS.jsonl', limit=64_000_000)
        with tempfile.NamedTemporaryFile(mode='w+b', prefix='.hp-parent-audit-',
                                         dir=output) as held:
            held.write(event_bytes)
            held.flush()
            os.fsync(held.fileno())
            before = os.fstat(held.fileno())
            audit = runner.verify_formal_model_event_order(SimpleNamespace(
                attempts=[{**attempts[0], 'model': route['model']}], physical=1),
                Path(held.name))
            after = os.stat(held.name, follow_symlinks=False)
            if (not stat.S_ISREG(after.st_mode) or
                    (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or
                    hashlib.sha256(event_bytes).hexdigest() !=
                        audit.get('event_log_sha256')):
                return False
        return audit == receipt['event_audit']
    except Exception:
        return False


def run_supervised(spec: Path, expected_sha256: str) -> dict:
    _require_external_source_pin()
    row = load_spec(spec, expected_sha256)
    output = Path(row['output_dir'])
    if any((output / name).exists() for name in
           (LEDGER_NAME, CHILD_NAME, RECEIPT_NAME)):
        raise ValueError('HP follow-up already attempted')
    base = _base()
    contract, _config, _executable = _direction()._pinned_contract(base)
    base._route_pinned_codex(contract)
    runner, _toy, _app, _budget, _ledger = base._imports()
    os.umask(0o077)
    parent_cache = output / 'parent_pycache'
    if parent_cache.exists() or parent_cache.is_symlink():
        raise ValueError('HP parent cache not fresh')
    parent_cache.mkdir(mode=0o700)
    base._private_dir(parent_cache)
    sys.pycache_prefix = str(parent_cache)
    os.environ['PYTHONPYCACHEPREFIX'] = str(parent_cache)
    child_cache = output / 'child_pycache'
    if child_cache.exists() or child_cache.is_symlink():
        raise ValueError('HP child cache not fresh')
    child_cache.mkdir(mode=0o700)
    base._private_dir(child_cache)
    command = [row['python_path'], '-I', '-B', '-X',
               f'pycache_prefix={child_cache}', '-c', base.INLINE_BOOTSTRAP,
               str(Path(__file__).resolve()), row['driver_sha256'],
               '--child', str(spec), expected_sha256]
    predicate = lambda child, fd, held: _completion_predicate(
        child, fd, held, spec_sha256=expected_sha256, output=output)
    if load_spec(spec, expected_sha256) != row:
        raise ValueError('HP source changed before child launch')
    return base.supervise_command(command, output, wall_seconds=WALL_SECONDS,
        runner=runner, spec_sha256=expected_sha256,
        completion_predicate=predicate,
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
            output = Path(row['output_dir'])
            if not (output / CHILD_NAME).exists():
                base = _base()
                base._write_once(output / CHILD_NAME, {
                    'status': 'INCOMPLETE_HP_CONTEXT_FOLLOWUP',
                    'error_type': type(exc).__name__,
                    'historical_status': 'CHILD_ERROR',
                    'combined_ledger_claim': False,
                    'ledger': base._evidence(output / LEDGER_NAME),
                    'model_events': base._evidence(output / 'MODEL_EVENTS.jsonl')})
            raise
        return 0
    result = run_supervised(args.path, args.sha256)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'CHILD_EXITED_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
