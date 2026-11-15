"""Real multi-step C process/trace regression; action discovery is not mocked as AI."""
from __future__ import annotations
import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path
import pytest

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.agents.scenario import ScenarioPlanner
from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.models import (
    ActionExample, ActionStateContract, Evidence, ExternalActionSchema,
    InputFieldConstraint, ProjectSpec, ProofStatus, ScenarioStatus,
    StateDependencyGraph, StateRequirement,
)
from harnesscreator.runtime.contracts import audit_harness_plan
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier


def test_source_instrumented_stdin_set_get_both_mutation_positions():
    asyncio.run(_source_instrumented_stdin_set_get_both_mutation_positions())


async def _source_instrumented_stdin_set_get_both_mutation_positions():
    cc = shutil.which('cc')
    if not cc or not Path('/usr/include/openssl/sha.h').is_file():
        pytest.skip('C compiler and libcrypto headers are needed')
    fixture = Path(__file__).parent / 'fixtures' / 'stateful_stdin.c'
    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        source = root / 'server.c'
        source.write_bytes(fixture.read_bytes())
        bundle = StaticAnalyzer(root).index()
        graph = GraphStore(bundle)
        functions = {item.name: item for item in bundle.functions.values()}
        entry, put, get = [functions[key] for key in ('input_read', 'handle_set', 'handle_get')]
        source.write_text(source.read_text().replace('__ENTRY__', entry.function_id)
                          .replace('__SET__', put.function_id).replace('__GET__', get.function_id))
        exe = root / 'server'
        build = subprocess.run([cc, str(source), '-O0', '-g', '-lcrypto', '-o', str(exe)],
                               capture_output=True, text=True)
        if build.returncode:
            pytest.skip('fixture cannot link libcrypto: ' + build.stderr[:300])
        evidence = [Evidence('source', entry.function_id, entry.file, entry.start_line, 'first stdin read')]
        def action(name, data, handler):
            return ExternalActionSchema(
                action_id=name, entry_id='stdin', name=name, description=name,
                dispatcher_function_id=handler.function_id, handler_function_id=handler.function_id,
                discriminator=name, channel_kind='stdin',
                fields=[InputFieldConstraint('key', 4, 1, 'bytes', 'key', 'same key', evidence)],
                examples=[ActionExample(data.hex(), {'key': b'k'.hex()})],
                success_markers_hex=[(b'OK\n' if name == 'set' else b'VALUE:yes\n').hex()],
                failure_markers_hex=[b'ERR\n'.hex()],
                evidence=evidence, inspected_function_ids=[entry.function_id, handler.function_id],
                status=ProofStatus.PROVEN_STATIC, source_api='fgets',
                success_evidence=evidence, failure_evidence=evidence,
                entry_function_id=entry.function_id, entry_probe_evidence=evidence,
            )
        actions = [action('set', b'SET k\n', put), action('get', b'GET k\n', get)]
        resource = StateRequirement('item', 'key', 'exists', evidence, ProofStatus.PROVEN_STATIC)
        dependencies = StateDependencyGraph([
            ActionStateContract('set', [], [resource], [], 'stored', evidence, ['set'], ProofStatus.PROVEN_STATIC),
            ActionStateContract('get', [resource], [], [], 'found', evidence, ['get'], ProofStatus.PROVEN_STATIC),
        ], [], [])
        planner = ScenarioPlanner(max_steps=3)
        normal = planner.plan(actions, dependencies)
        post = planner.post_fuzz_candidates(actions, dependencies, normal)
        assert len(post) >= 1
        project = ProjectSpec(
            source_root=root, output_root=root/'out',
            scenario_command=[str(exe)], scenario_channel='stdin',
            scenario_attribution='trace', scenario_step_timeout=2,
        ).normalized()
        runner = ScenarioRuntimeVerifier(project, actions, graph)
        candidate = next(item for item in post if item.target_action_id == 'set')
        witness = await runner.verify(candidate)
        assert witness.status is ScenarioStatus.PROVEN_RUNTIME, witness.rationale
        assert witness.fuzz_step_index == 0
        assert [o.target_reached for o in witness.observations] == [True, True]
        plan = build_harness_plan(witness, action_function_ids={
            'set': (entry.function_id, put.function_id),
            'get': (entry.function_id, get.function_id),
        })
        assert [s.action_id for s in plan.post_steps] == ['get']
        assert audit_harness_plan(witness, plan).passed
