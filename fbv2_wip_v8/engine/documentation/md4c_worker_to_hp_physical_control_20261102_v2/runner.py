"""Provider-free original FBv2 queue through the real md4c product Gate.

All Direction/Seed/SP/Verifier/PoV agent decisions are scripted fixtures.
Global campaign is either a protected no-process fake or a bounded qualified
physical run; the qualified PoV Runtime executes the public pinned md4c ASan
binary. A non-crashing PoV can also exercise completed Worker HP handoff.
This does not demonstrate automatic vulnerability discovery.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from functools import partial
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

ENGINE = Path('/home/dawne/work/SunrinInfosecProject2026/fbv2_hp_integration')
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
EVAL = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/evaluation_tools')
for source in (ENGINE, PRODUCT, EVAL):
    sys.path.insert(0, str(source))

import mongomock
from bson import ObjectId
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_accounted_global_campaign import AccountedGlobalCampaign
from dev_global_campaign import DevGlobalCampaign
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from devtools.original_global_bridge import OriginalGlobalBridge
from devtools.original_hp_post_worker import run_post_worker_hp
from devtools.original_hp_preparation import (
    PreparedHPFunction, run_prepared_hp_assertion_handoff)
from devtools import original_public_live as live
from devtools.product_qualified_runtime import (
    ProductQualifiedPoVAdapter, consume_qualified_pov_observation)
from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.suspicious_point import SPStatus, SuspiciousPoint
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.tools.pov import clear_pov_context, create_pov_impl, set_pov_context
from fuzzingbrain.worker.executor import WorkerExecutor
from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent, PipelineConfig
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy
from vulnerabilityanalysis.official_harness import (
    _qualification_pins_ok, issue_official_pinned_qualification)
from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.assertions import execute_assertion, guided_fuzz_assertion
from vulnerabilityanalysis.source import SourceRepository


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-seed', action='store_true',
                        help='exercise the durable zero-Seed Global skip')
    parser.add_argument('--real-global', action='store_true',
                        help='run the qualified Global Fuzzer for 15 seconds')
    parser.add_argument('--official-consumer', action='store_true',
                        help='use WorkerExecutor and public-dev consumer boundary')
    parser.add_argument('--normal-pov', action='store_true',
                        help='use the qualified normal seed for a completed Worker')
    parser.add_argument('--hp-provider-free', action='store_true',
                        help='exercise product HP after the completed original Worker')
    parser.add_argument('--hp-physical-control', action='store_true',
                        help='run scripted HP SAFE through the existing physical callbacks')
    parser.add_argument('--zero-sp', action='store_true',
                        help='run qualified Global Fuzzing with zero SP candidates')
    args = parser.parse_args()
    if args.no_seed and args.real_global:
        parser.error('--no-seed and --real-global are exclusive')
    if args.official_consumer and not (args.no_seed or args.real_global):
        parser.error('--official-consumer requires --no-seed or --real-global')
    if args.normal_pov and not (args.no_seed and args.official_consumer):
        parser.error('--normal-pov requires --no-seed --official-consumer')
    if args.hp_provider_free and not args.normal_pov:
        parser.error('--hp-provider-free requires --normal-pov')
    if args.hp_physical_control and not args.hp_provider_free:
        parser.error('--hp-physical-control requires --hp-provider-free')
    if args.zero_sp and (not args.real_global or not args.official_consumer or
                         args.normal_pov or args.hp_provider_free):
        parser.error('--zero-sp requires --real-global --official-consumer only')
    spec = json.loads(Path('/tmp/fbv2-public-md4c-v3.json').read_text())
    contract_path = Path(spec['admission']['contract_path'])
    contract = json.loads(contract_path.read_text())
    local, target = contract['local'], contract['target']
    q = issue_official_pinned_qualification(
        contract_path=contract_path,
        approved_contract_sha256=spec['admission']['contract_sha256'],
        source_root=Path(target['source_root']),
        harness=Path(local['harness_file']), binary=Path(local['binary']),
        normal_seed=Path(local['normal_seed']),
        oss_fuzz_checkout=Path(spec['admission']['oss_fuzz_checkout']),
        upstream_checkout=Path(spec['admission']['upstream_checkout']))
    assert q is not None and _qualification_pins_ok(q)
    input_bytes = (ENGINE / 'documentation/md4c_oob_retained_input_20261101.bin').read_bytes()
    assert hashlib.sha256(input_bytes).hexdigest() == (
        '9de288250d625a75471a2da8f876d22472f871190eec592664fcd201130d5613')
    pov_input_bytes = q.normal_seed.read_bytes() if args.normal_pov else input_bytes
    input_sha = hashlib.sha256(pov_input_bytes).hexdigest()

    root = Path(tempfile.mkdtemp(prefix='fbv2-queue-gate-controlled-'))
    if args.real_global:
        print(json.dumps({'phase': 'STARTED', 'run_dir': str(root),
                          'global_fuzz_seconds_cap': 15,
                          'global_physical_reservation_seconds': 35}), flush=True)
    run_id = 'controlledqueue' + uuid4().hex
    task_id, direction_id, candidate_id, direction_agent_id = (
        str(ObjectId()) for _ in range(4))
    repos = RepositoryManager(mongomock.MongoClient().controlled_queue_gate)
    normal_function_source = ''
    if args.normal_pov:
        repository = SourceRepository(q.source_root, {'md_collect_marks': {
            'function_id': 'md_collect_marks', 'name': 'md_collect_marks',
            'file': 'src/md4c.c'}})
        normal_function_source = repository.open_function_span(
            'md_collect_marks').source
    assert repos.functions.save(Function(
        task_id=task_id, name='md_collect_marks', file_path='src/md4c.c',
        content=normal_function_source if args.normal_pov else
                '/* provider-free function fixture, no model analysis */'))
    ledger = PersistentProcessLedgerV2.create(
        root / 'process-ledger.json', wall_total_seconds=300,
        fuzz_total_seconds=60 if args.real_global else
                           30 if args.hp_physical_control else 0)
    adapter = ProductQualifiedPoVAdapter(
        qualification=q, repos=repos, task_id=task_id, work_item_id=task_id,
        run_id=run_id, fuzzer='fuzz-mdhtml', sanitizer='address', ledger=ledger,
        output_dir=root / 'pov-runtime', timeout_seconds=3, wall_seconds=180,
        output_limit_bytes=4_000_000)
    events: list[str] = []
    clients: list[str] = []
    generated_ids: list[str] = []

    class ScriptedClient:
        last_agent_response_was_final = True

        def __init__(self, role: str):
            self.role = role
            clients.append(role)

        async def close(self):
            pass

    class ProtectedGlobalCampaign:
        def __init__(self):
            self.q = q
            self.global_seconds = 2
            self.global_wall_reservation_seconds = 4
            self.require_accounted_consumer = True
            self.staged = None

        def _authority_ok(self):
            return _qualification_pins_ok(q)

        def stage_direction_seeds(self, plan, sha, seeds):
            assert hashlib.sha256(plan.read_bytes()).hexdigest() == sha
            assert [(seed.direction_id, seed.path.read_bytes()) for seed in seeds] == [
                (direction_id, b'provider-free-global-seed')]
            self.staged = (plan, sha, seeds)
            events.append('global_stage_fake')

        def start(self):
            assert self.staged is not None
            events.append('global_start_fake')
            return 'ACTIVE'

        def finish(self):
            events.append('global_finish_fake')
            return {'status': 'RAN', 'cleanup_complete': True,
                    'consumer_rows': [], 'observed_crash_count': 0}

        def abort(self):
            events.append('global_abort_fake')
            return {'status': 'STOPPED_ABORTED', 'cleanup_complete': True}

    model_gate = None
    if args.no_seed or args.real_global:
        model_gate = SimpleNamespace(
            campaign_id=run_id,
            snapshot=lambda: {
                'campaign_id': run_id, 'physical': 0,
                'records': [
                    {'request_id': 'fixture-direction', 'role': 'direction',
                     'owner_id': task_id, 'status': 'COMPLETED',
                     'response_evidence': {'status': 'VERIFIED'},
                     'tool_events': []},
                    {'request_id': 'fixture-seed', 'role': 'seed',
                     'owner_id': direction_id, 'status': 'COMPLETED',
                     'response_evidence': {'status': 'VERIFIED'},
                     'tool_events': []}]},
            verify_response_evidence=lambda _request_id: {'status': 'VERIFIED'},
            verify_tool_event=lambda *_args: {'status': 'VERIFIED'})
        envelope = DevelopmentProcessEnvelopeV2(
            ledger, work_item_id=task_id, assertion_id='global_consumer',
            attempt_id=run_id, output_limit_bytes=4_000_000,
            total_wall_seconds=300, pin_hook=lambda *_args: None)
        base = DevGlobalCampaign(
            root / 'global', q, total_fuzz_seconds=60 if args.real_global else 20,
            global_seconds=15 if args.real_global else 2,
            global_wall_reservation_seconds=35 if args.real_global else 4,
            replay_limit=1, process_envelope=envelope,
            require_accounted_consumer=True)
        campaign = AccountedGlobalCampaign(
            base, ledger, reservation_key=f'GLOBAL_FUZZ:{task_id}:{run_id}')
    else:
        campaign = ProtectedGlobalCampaign()

    def global_factory(plan_path: Path, plan_sha256: str) -> OriginalGlobalBridge:
        return OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=plan_path,
            direction_plan_sha256=plan_sha256, seed_spool=root / 'seed-spool',
            expected_binary_sha256=q.binary_sha256, model_gate=model_gate)

    executor = WorkerExecutor(
        workspace_path=str(root / 'worker'), project_name='md4c-controlled',
        fuzzer='fuzz-mdhtml', sanitizer='address', task_type='pov',
        repos=repos, task_id=task_id, fuzzer_binary_path=str(q.binary),
        llm_client_factory=lambda role, owner: ScriptedClient(role),
        qualified_pov_runtime_binding=adapter.binding,
        require_original_global_bridge=True,
        original_global_bridge_factory=global_factory)
    strategy = POVFullscanStrategy(executor,
                                  llm_client_factory=executor.llm_client_factory)

    class DirectionRole:
        stop_reason = None
        mcp_context_id = direction_agent_id

        def __init__(self, **_kwargs):
            pass

        async def plan_directions_async(self, **_kwargs):
            events.append('direction_fixture')
            assert repos.directions.save(Direction(
                direction_id=direction_id, task_id=task_id,
                fuzzer='fuzz-mdhtml', created_by_agent_id=direction_agent_id,
                name='controlled md4c function', risk_level='high',
                core_functions=['md_collect_marks'], entry_functions=[]))
            return {'success': True, 'directions_created': 1,
                    'direction_ids': [direction_id]}

    class SeedRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.manager = kwargs['fuzzer_manager']

        async def generate_direction_seeds(self, *, direction_id, **_kwargs):
            events.append('seed_fixture')
            if args.no_seed:
                return {'success': True, 'direction_id': direction_id,
                        'seeds_generated': 0, 'seed_tool_failures': 0,
                        'fatal_seed_cleanup': False}
            self.manager.add_direction_seed(
                q.normal_seed.read_bytes() if args.real_global else
                b'provider-free-global-seed', direction_id)
            return {'success': True, 'seeds_generated': 1}

    class SPRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.direction_id = kwargs['direction_id']

        async def analyze_async(self):
            events.append('sp_fixture')
            if args.zero_sp:
                return {'success': True, 'sp_created': False}
            assert repos.suspicious_points.save(SuspiciousPoint(
                suspicious_point_id=candidate_id, task_id=task_id,
                function_name='md_collect_marks', direction_id=self.direction_id,
                description='scripted queue candidate', vuln_type='buffer-overflow',
                score=0.9, sources=[{'harness_name': 'fuzz-mdhtml',
                                     'sanitizer': 'address'}]))
            return {'success': True, 'sp_created': True}

    class VerifierRole:
        stop_reason = None

        def __init__(self, **_kwargs):
            self.sp_id = None

        def set_context(self, *, suspicious_point):
            self.sp_id = suspicious_point['suspicious_point_id']

        async def run_async(self, **_kwargs):
            events.append('verifier_fixture')
            assert self.sp_id == candidate_id
            assert repos.suspicious_points.update(self.sp_id, {
                'is_checked': True, 'is_real': False, 'is_important': True,
                'score': 0.9, 'verification_notes': 'scripted queue only',
                'pov_guidance': 'controlled input'})
            return 'scripted verifier verdict'

    class PoVRole:
        stop_reason = None

        def __init__(self, **kwargs):
            self.ctx_id = kwargs['worker_id']
            self.agent_id = str(ObjectId())
            self.kwargs = kwargs

        async def generate_pov_async(self, suspicious_point):
            events.append('pov_fixture')
            assert suspicious_point['suspicious_point_id'] == candidate_id
            set_pov_context(
                task_id=task_id, worker_id=self.ctx_id,
                output_dir=self.kwargs['output_dir'], repos=repos,
                fuzzer='fuzz-mdhtml', sanitizer='address',
                suspicious_point_id=candidate_id, fuzzer_path=q.binary,
                agent_id=self.agent_id, qualified_runtime_required=True,
                qualified_runtime_binding=self.kwargs['qualified_runtime_binding'])
            try:
                generated = create_pov_impl(
                    'def generate(variant): return b"controlled existing input"',
                    worker_id=self.ctx_id)
            finally:
                clear_pov_context(self.ctx_id)
            assert generated['success'] is True
            if args.normal_pov:
                assert generated['runtime_status'] != 'PENDING_INDEPENDENT_VALIDATION'
            else:
                assert generated['runtime_status'] == 'PENDING_INDEPENDENT_VALIDATION'
            generated_ids.extend(generated['pov_ids'])
            events.append('qualified_runtime_real')
            return SimpleNamespace(
                success=False, crashed=False, pending_runtime=False,
                pending_validation=not args.normal_pov, pov_id=None,
                generated_pov_ids=generated['pov_ids'])

    original_config = PipelineConfig

    def quick_config(**kwargs):
        kwargs.update(num_verify_agents=1, num_pov_agents=1,
                      poll_interval=0.005, max_idle_cycles=6)
        return original_config(**kwargs)

    with patch('fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent',
               return_value=DirectionRole()), \
         patch('fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent', SeedRole), \
         patch('fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator', SPRole), \
         patch('fuzzingbrain.worker.pipeline.SPVerifier', VerifierRole), \
         patch('fuzzingbrain.worker.pipeline.POVAgent', PoVRole), \
         patch('fuzzingbrain.tools.pov._execute_generator_code',
               return_value=([pov_input_bytes], None)), \
         patch('fuzzingbrain.worker.pipeline.PipelineConfig',
               side_effect=quick_config):
        pending_reason = None
        official_result = None
        if args.official_consumer:
            # The real Worker raises validation_pending. Exercise the public
            # entry's post-Worker consumer rather than catching it here.
            spec_path = root / 'controlled-spec.json'
            spec_path.write_text('{}\n')
            token = object()
            entry = Path(live.__file__).resolve().parent / 'original_public_live_entry.py'
            marker = {
                'pid': os.getpid(), 'spec_path': str(spec_path),
                'spec_sha256': hashlib.sha256(spec_path.read_bytes()).hexdigest(),
                'token': token, 'used': False,
                'engine_py_sha256': 'a' * 64,
                'product_py_sha256': 'b' * 64,
                'evaluation_py_sha256': 'c' * 64,
                'hp_mode': False}
            identity = SimpleNamespace(
                task_id=task_id, run_id=run_id, task_path=q.source_root,
                run_dir=root, engine_py_sha256='a' * 64,
                product_py_sha256='b' * 64,
                evaluation_py_sha256='c' * 64)
            bound = SimpleNamespace(
                identity=identity, bootstrap_token=token,
                recheck=lambda: _qualification_pins_ok(q),
                executor=executor, strategy=strategy,
                server=SimpleNamespace(
                    repos=repos, socket_path=root / 'unused.sock'),
                admission=SimpleNamespace(
                    summary={'project_name': 'md4c'}, qualification=q,
                    prepared={'fuzzer_name': 'fuzz-mdhtml'}),
                process_ledger=ledger, model_gate=model_gate,
                global_campaign=campaign, pov_adapter=adapter,
                caps=SimpleNamespace(pov_timeout_seconds=3))
            with patch('fuzzingbrain.db.get_database', return_value=repos.db), \
                 patch('fuzzingbrain.llms.buffer.WorkerLLMBuffer'), \
                 patch('fuzzingbrain.llms.buffer.set_worker_buffer'), \
                 patch.object(executor, '_get_strategy', return_value=strategy), \
                 patch.object(live, '_isolated_runtime', return_value=True), \
                 patch.object(live, 'require_journaled_mongo'), \
                 patch.dict(sys.modules, {'__main__': SimpleNamespace(
                     __file__=str(entry), _PINNED_PUBLIC_BOOTSTRAP=marker)}), \
                 patch.object(sys, 'argv', [str(entry), '--authorize-public-dev']):
                official_result = live.run_original_public_dev(
                    bound, explicit_public_dev_authorization=True)
            assert official_result['original_worker_status'] == (
                'COMPLETED' if args.normal_pov or args.zero_sp else
                'PENDING_INDEPENDENT_VALIDATION')
            assert official_result['verification_status'] == (
                'NO_PENDING_OBSERVATION' if args.normal_pov or args.zero_sp else
                'PENDING_INDEPENDENT_VALIDATION')
            assert official_result['execution_status'] == 'EXECUTED'
            pending_reason = None if args.normal_pov or args.zero_sp else 'validation_pending'
            stats = None
        else:
            try:
                stats = asyncio.run(strategy._run_full_pipeline())
            except IncompleteInjectedAgent as error:
                # The original pipeline intentionally stops at a crashed PoV until
                # the independent product verifier consumes its retained input.
                assert error.reason == 'validation_pending', error
                pending_reason = error.reason
                stats = None

    assert len(generated_ids) == (0 if args.zero_sp else 1)
    pov_id = None if args.zero_sp else generated_ids[0]
    assert pending_reason == (None if args.normal_pov or args.zero_sp else
                              'validation_pending')
    expected_events = ['direction_fixture', 'seed_fixture']
    if not args.no_seed and not args.real_global:
        expected_events += ['global_stage_fake', 'global_start_fake']
    expected_events += ['sp_fixture']
    if not args.zero_sp:
        expected_events += ['verifier_fixture', 'pov_fixture',
                            'qualified_runtime_real']
    if not args.no_seed and not args.real_global:
        expected_events += ['global_finish_fake']
    assert events == expected_events
    if not args.real_global:
        assert campaign.final_result['status'] == (
            'SKIPPED_NO_SEED' if args.no_seed else 'RAN')
    if args.no_seed:
        assert campaign.final_result['physical_seconds'] == 0.0
        assert campaign.final_result['global_charge_relation'] == (
            'NO_PHYSICAL_GLOBAL_RUN')
        assert base.process is None
        assert not any(row['key'].startswith('GLOBAL_FUZZ:')
                       for row in ledger.snapshot()['finished'])
    if args.real_global:
        assert campaign.final_result['physical_seconds'] > 0
        assert len([row for row in ledger.snapshot()['finished']
                    if row['key'].startswith('GLOBAL_FUZZ:')]) == 1
    if not args.normal_pov and not args.zero_sp:
        assert repos.suspicious_points.find_by_id(candidate_id).status == (
            SPStatus.PENDING_INDEPENDENT_VALIDATION.value)

    def recheck():
        if not _qualification_pins_ok(q):
            raise ValueError('official md4c qualification changed')

    gate_row = (None if args.normal_pov or args.zero_sp else
                official_result['pov_product_gate_rows'][0]
                if official_result is not None else
                consume_qualified_pov_observation(
                    adapter, pov_id, recheck=recheck, timeout_seconds=3))
    if args.zero_sp:
        assert official_result['pov_product_gate_rows'] == []
        assert official_result['pov_lineage_rows'] == []
        assert repos.suspicious_points.find_by_id(candidate_id) is None
    elif args.normal_pov:
        assert official_result['pov_product_gate_rows'] == []
        assert official_result['pov_lineage_rows'][0]['pov_id'] == pov_id
        normal_runtime = json.loads((adapter.root / pov_id / 'runtime.json').read_text())
        assert normal_runtime['status'] == 'NO_CRASH'
        assert normal_runtime['input_sha256'] == input_sha
        assert normal_runtime['binary_sha256'] == q.binary_sha256
    else:
        assert gate_row['product_gate_status'] == (
            'TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE')
        assert gate_row['security_gate_invoked'] is False
        assert gate_row['discovery_credit'] == 'NOT_CREDITED'
    hp_result = None
    hp_prepared = None
    hp_physical_result = None
    if args.hp_provider_free:
        function = repos.functions.find_by_name(task_id, 'md_collect_marks')
        assert function.analyzed_by_directions == [direction_id]

        class HPProvider:
            def __init__(self, role: str, response: dict):
                self.role = role
                self.response = response
                self.closed = False

            async def generate(self, _request):
                events.append('hp_' + self.role)
                return self.response

            async def close(self):
                self.closed = True

        safe = 'The parser context and line array are non-null while scanning marks'
        analysis_response = {
            'summary': 'Provider-free source handoff only',
            'input_flow': 'Harness bytes reach the markdown parser',
            'state_dependencies': [], 'context_requests': [],
            'safe_assumptions': [safe] if args.hp_physical_control else [],
            'unknowns': [],
            'input_sources': ['Harness bytes'],
            'security_sensitive_operations': [], 'validations': [],
            'memory_operations': [], 'evidence': [],
            'hypothesis_evaluations': ([{
                'source_location': 'src/md4c.c:3264',
                'source_file': 'src/md4c.c', 'source_line': 3264,
                'source_quote': 'for(line_index = 0; line_index < n_lines; line_index++) {',
                'security_property': 'valid mark scan pointers',
                'input_influence': 'INPUT_DEPENDENT',
                'hypothesis': 'null pointer would invalidate the scan',
                'judgment': 'EXPLICIT_SAFE_JUDGMENT',
                'reason': 'the loop reads lines through the parser context',
                'safe_assumption': safe,
            }] if args.hp_physical_control else []),
        }
        analysis = HPProvider('function_analysis', analysis_response)
        assertion = HPProvider('assertion_generator', ({
            'assertions': [{'safe_id': 0, 'safe_assumption': safe,
                            'runtime_expression': 'ctx != NULL && lines != NULL',
                            'source_line': 3264, 'required_context': [],
                            'rationale': 'check pointers before the mark scan'}],
            'dispositions': [{'safe_id': 0, 'safe_assumption': safe,
                              'status': 'PROPOSED', 'reason': 'expressible'}],
        } if args.hp_physical_control else {}))
        prepared_rows = []
        prepared_work = []

        def analysis_factory(work):
            assert work.function_name == 'md_collect_marks'
            assert work.source_start_line == 3255
            assert work.source_end_line == 3725
            assert 'md_collect_marks(MD_CTX* ctx' in work.source
            assert work.source_file_sha256 == hashlib.sha256(
                Path(work.source_file).read_bytes()).hexdigest()
            assert work.analysis_scope['selected_function'][
                'fbv2_source_match'] == 'EXACT_DEFINITION'
            prepared_rows.append(work.receipt())
            prepared_work.append(work)
            return AgentPipeline(analysis)

        hp_result = asyncio.run(run_post_worker_hp(
            bound=bound, worker_receipt=official_result,
            analysis_pipeline_factory=analysis_factory,
            assertion_pipeline_factory=lambda _work: AgentPipeline(assertion),
            max_items=1, provider_free_fixture=True))
        assert hp_result['status'] == 'HP_POST_WORKER_COMPLETE', hp_result
        assert hp_result['selected_count'] == 1
        assert hp_result['rows'][0]['status'] == (
            'ASSERTIONS_PROPOSED_UNVERIFIED' if args.hp_physical_control
            else 'NO_SAFE_ASSUMPTION')
        assert hp_result['original_result'] == official_result['original_result']
        assert hp_result['sp_global_effect'] == 'UNCHANGED'
        assert hp_result['security_gate_credit'] == 'NOT_CREDITED'
        assert analysis.closed and assertion.closed
        assert events[-1] == ('hp_assertion_generator' if args.hp_physical_control
                              else 'hp_function_analysis')
        assert len(prepared_rows) == 1
        hp_prepared = prepared_rows[0]
        if args.hp_physical_control:
            work = prepared_work[0]
            assert type(work) is PreparedHPFunction
            proposal = hp_result['rows'][0]['assertion_proposals'][0]
            builder = Path('/home/dawne/SunrinInfosecProject2026/reference/'
                           'blind2_v2_preparation_20261027/tools/'
                           'multi_tu_assertion_build.py')
            manifest = builder.with_name('multi_tu_assertion_build_manifest.json')
            builder_sha = hashlib.sha256(builder.read_bytes()).hexdigest()
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

            def hp_pins(phase, _command):
                if (not _qualification_pins_ok(q) or
                        hashlib.sha256(builder.read_bytes()).hexdigest() != builder_sha or
                        hashlib.sha256(manifest.read_bytes()).hexdigest() != manifest_sha):
                    raise RuntimeError(f'HP fixture pin changed at {phase}')

            hp_envelope = DevelopmentProcessEnvelopeV2(
                ledger, work_item_id=task_id,
                assertion_id=proposal['assertion_id'], attempt_id=run_id,
                output_limit_bytes=4_000_000, total_wall_seconds=120,
                pin_hook=hp_pins)
            hp_physical_result = run_prepared_hp_assertion_handoff(
                work=work, qualification=q, analysis_result=hp_result['rows'][0],
                worker_id=official_result['original_result']['worker_id'],
                assertion_id=proposal['assertion_id'], output_dir=root / 'hp-physical',
                build_command=[str(builder), '{source}', '-o', '{binary}'],
                run_command=['{binary}', '{input}'], guided_seconds=1,
                timeout_seconds=30, provider_free_fixture=True,
                execute_callback=partial(execute_assertion,
                                         process_envelope=hp_envelope),
                guided_callback=partial(guided_fuzz_assertion,
                                        process_envelope=hp_envelope),
                builder_manifest_path=manifest,
                builder_manifest_sha256=manifest_sha)
            assert hp_physical_result['status'] == 'HP_ASSERTION_HANDOFF_COMPLETE', hp_physical_result
            assert hp_physical_result['security_gate_credit'] == 'NOT_CREDITED'
    state, receipt_sha = ledger.receipt_snapshot()
    assert len(state['finished']) >= (1 if args.normal_pov or args.zero_sp else
                                     6 if args.real_global else 5)
    assert not state['active']
    if not args.real_global or campaign.final_result['status'] == 'RAN':
        assert state['stop_status'] is None
    assert _qualification_pins_ok(q)
    report = {
        'kind': ('FBV2_ORIGINAL_QUEUE_NO_SEED_CONTROLLED_MD4C_GATE_V1'
                 if args.no_seed else 'FBV2_ORIGINAL_QUEUE_CONTROLLED_MD4C_GATE_V1'),
        'run_id': run_id, 'task_id': task_id, 'direction_id': direction_id,
        'sp_id': None if args.zero_sp else candidate_id, 'pov_id': pov_id,
        'source_tree_sha256': q.source_tree_sha256,
        'harness_sha256': q.harness_sha256,
        'binary_sha256': q.binary_sha256,
        'contract_sha256': q.contract_sha256,
        'input_sha256': None if args.zero_sp else input_sha,
        'role_events': events, 'role_clients': clients,
        'original_stats': stats.to_dict() if stats is not None else None,
        'original_pipeline_stop_reason': pending_reason,
        'global_status': campaign.final_result['status'],
        'global_charge_relation': campaign.final_result.get(
            'global_charge_relation'),
        'no_seed_mode': args.no_seed,
        'normal_pov_mode': args.normal_pov,
        'zero_sp_mode': args.zero_sp,
        'hp_provider_free_mode': args.hp_provider_free,
        'hp_prepared': hp_prepared,
        'hp_result': hp_result,
        'hp_physical_control_mode': args.hp_physical_control,
        'hp_physical_result': hp_physical_result,
        'real_global_mode': args.real_global,
        'seed_source_kind': ('SCRIPTED_HARNESS_NORMAL_BYTES_NOT_MODEL'
                             if args.real_global else
                             'SCRIPTED_ZERO_SEED' if args.no_seed else
                             'SCRIPTED_DIRECTION_BYTES_NOT_MODEL'),
        'official_consumer_mode': args.official_consumer,
        'official_result': official_result,
        'global_fuzzer_physical': args.real_global,
        'model_calls': 0, 'automatic_discovery': False,
        'physical_finished': len(state['finished']),
        'physical_active': len(state['active']),
        'physical_wall_seconds': state['wall_spent_seconds'],
        'process_ledger_receipt_sha256': receipt_sha,
        'process_stop_status': state['stop_status'],
        'gate_outcome': gate_row,
    }
    result_path = root / 'CONTROLLED_RESULT.json'
    result_path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({
        'run_dir': str(root), 'role_events': events,
        'pov_id': pov_id,
        'gate_status': (gate_row['product_gate_status'] if gate_row else
                        'NOT_APPLICABLE_NO_CRASH'),
        'global_status': campaign.final_result['status'],
        'physical_finished': len(state['finished']),
        'physical_wall_seconds': state['wall_spent_seconds'],
    }))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        import traceback
        traceback.print_exc(file=sys.__stderr__)
        raise
