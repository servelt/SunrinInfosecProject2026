from __future__ import annotations

import hashlib
from dataclasses import replace

from harnesscreator.agents.scenario import ScenarioPlanner
from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.models import (
    ActionExample, ActionOrderingConstraint, ActionStateContract, Evidence, ExternalActionSchema,
    InputFieldConstraint, ProofStatus, RuntimeStepObservation, ScenarioStatus,
    ScenarioWitness, StateDependencyGraph, StateRequirement,
)
from harnesscreator.runtime.contracts import audit_harness_plan


def _action(name: str, data: bytes, evidence: list[Evidence], *, field=True):
    fields = ([InputFieldConstraint('key', 4, 1, 'bytes', 'key', 'same key', evidence)]
              if field else [])
    return ExternalActionSchema(
        action_id=name, entry_id='entry', name=name, description=name,
        dispatcher_function_id=name, handler_function_id=name,
        discriminator=name, channel_kind='tcp', fields=fields,
        examples=[ActionExample(data.hex(), {'key': b'k'.hex()} if field else {})],
        success_markers_hex=[b'OK\n'.hex()], failure_markers_hex=[], evidence=evidence,
        inspected_function_ids=[name], status=ProofStatus.PROVEN_STATIC,
        confidence=1.0, source_api='recv', entry_function_id='tcp_read',
    )


def _fixture():
    ev = [Evidence('source', 'handler', 'test.c', 10, 'source backed')]
    put = _action('put', b'PUT k\n', ev)
    read = _action('read', b'GET k\n', ev)
    resource = StateRequirement('item', 'key', 'exists', ev, ProofStatus.PROVEN_STATIC)
    graph = StateDependencyGraph([
        ActionStateContract('put', [], [resource], [], 'saved', ev, ['put'], ProofStatus.PROVEN_STATIC),
        ActionStateContract('read', [resource], [], [], 'found', ev, ['read'], ProofStatus.PROVEN_STATIC),
    ], [], [])
    return [put, read], graph


def test_initial_trial_budget_cannot_erase_later_actions():
    evidence = [Evidence('source', 'handler', 'test.c', 10, 'source backed')]
    actions = [_action(f'action-{index}', bytes([65 + index]), evidence, field=False)
               for index in range(3)]
    planner = ScenarioPlanner(max_candidates=1, max_variants_per_action=1)
    candidates = planner.exploratory_candidates(actions, [], limit=None)
    assert {item.target_action_id for item in candidates} == {
        item.action_id for item in actions
    }
    assert len(candidates) == len(actions)
    assert any('reserving one trial slot per target' in item
               for item in planner.obligations)


def test_prerequisite_search_does_not_expand_unrelated_actions():
    evidence = [Evidence('source', 'handler', 'test.c', 10, 'source backed')]
    target = _action('lookup', b'GET\n', evidence, field=False)
    setup = _action('z-create', b'SET\n', evidence, field=False)
    unrelated = [
        _action(f'a-unrelated-{index}', f'STAT {index}\n'.encode(),
                evidence, field=False)
        for index in range(12)
    ]
    needed = StateRequirement('item', '', 'exists', evidence,
                              ProofStatus.PROVEN_STATIC)
    other = StateRequirement('statistics', '', 'observed', evidence,
                             ProofStatus.PROVEN_STATIC)
    contracts = [
        ActionStateContract(target.action_id, [needed], [], [], 'found',
                            evidence, [target.action_id], ProofStatus.PROVEN_STATIC),
        ActionStateContract(setup.action_id, [], [needed], [], 'stored',
                            evidence, [setup.action_id], ProofStatus.PROVEN_STATIC),
        *[
            ActionStateContract(item.action_id, [], [other], [], 'reported',
                                evidence, [item.action_id], ProofStatus.PROVEN_STATIC)
            for item in unrelated
        ],
    ]
    planner = ScenarioPlanner(max_candidates=1, max_search_states=2)
    scenarios = planner.plan([target, setup, *unrelated],
                             StateDependencyGraph(contracts, [], []))
    lookup = next(item for item in scenarios
                  if item.target_action_id == target.action_id)
    assert [step.action_id for step in lookup.steps] == ['z-create', 'lookup']


def test_prerequisite_slice_preserves_required_predecessor_without_state_output():
    evidence = [Evidence('source', 'handler', 'test.c', 10, 'source backed')]
    target = _action('target', b'RUN\n', evidence, field=False)
    prerequisite = _action('prepare', b'PREPARE\n', evidence, field=False)
    contracts = [
        ActionStateContract(item.action_id, [], [], [], 'completed', evidence,
                            [item.action_id], ProofStatus.PROVEN_STATIC)
        for item in (target, prerequisite)
    ]
    order = [ActionOrderingConstraint(
        'prepare-first', 'prepare', 'target', 'REQUIRED',
        'source_fixture', 'target requires an earlier prepare call',
    )]
    scenarios = ScenarioPlanner(max_candidates=1).plan(
        [target, prerequisite], StateDependencyGraph(contracts, [], [],
                                                    ordering_constraints=order),
    )
    selected = next(item for item in scenarios
                    if item.target_action_id == 'target')
    assert [step.action_id for step in selected.steps] == ['prepare', 'target']


def test_post_fuzz_budget_does_not_erase_later_state_producers():
    evidence = [Evidence('source', 'handler', 'test.c', 10, 'source backed')]
    producers = [
        _action(f'put-{index}', f'PUT {index}\n'.encode(), evidence, field=False)
        for index in range(40)
    ]
    observer = _action('get', b'GET\n', evidence, field=False)
    resource = StateRequirement('item', '', 'exists', evidence, ProofStatus.PROVEN_STATIC)
    dependencies = StateDependencyGraph([
        *[
            ActionStateContract(item.action_id, [], [resource], [], 'saved',
                                evidence, [item.action_id], ProofStatus.PROVEN_STATIC)
            for item in producers
        ],
        ActionStateContract('get', [resource], [], [], 'found',
                            evidence, ['get'], ProofStatus.PROVEN_STATIC),
    ], [], [])
    planner = ScenarioPlanner(max_steps=4, max_candidates=1)
    base = planner.plan([*producers, observer], dependencies)
    post = planner.post_fuzz_candidates([*producers, observer], dependencies, base)
    assert {item.target_action_id for item in post} == {
        item.action_id for item in producers
    }


def test_post_fuzz_planner_and_execution_boundary_do_not_change_legacy():
    actions, dependencies = _fixture()
    planner = ScenarioPlanner(max_steps=4)
    normal = planner.plan(actions, dependencies)
    post = planner.post_fuzz_candidates(actions, dependencies, normal)
    assert post
    scenario = post[0]
    assert [step.action_id for step in scenario.steps] == ['put', 'read']
    assert scenario.target_action_id == 'put'
    assert scenario.fuzz_step_index == 0
    witness = ScenarioWitness(
        witness_id='w', scenario_id=scenario.scenario_id,
        target_action_id=scenario.target_action_id, steps=scenario.steps,
        observations=[RuntimeStepObservation(
            index=step.index, action_id=step.action_id,
            request_hex=step.request_hex, response_hex=b'OK\n'.hex(),
            success=True, detail='runtime', duration_seconds=0.1,
            response_success=True, entry_reached=True, target_reached=True,
            target_probe='request-correlated-jsonl-v1',
            probe_trace=['semantic-response:' + hashlib.sha256(b'OK\n').hexdigest()],
        ) for step in scenario.steps],
        command=['./server'], channel='tcp', process_returncode=None,
        status=ScenarioStatus.PROVEN_RUNTIME, rationale='instrumented trace',
        fuzz_step_index=scenario.fuzz_step_index,
    )
    plan = build_harness_plan(witness,
        action_function_ids={'put': ('tcp_read', 'put'), 'read': ('tcp_read', 'read')})
    assert not plan.setup_steps
    assert plan.fuzz_step.action_id == 'put'
    assert [item.action_id for item in plan.post_steps] == ['read']
    assert plan.boundary_contract['selected_function_id'] == 'tcp_read'
    assert plan.boundary_contract['internal_boundary_is_approved'] is False
    assert audit_harness_plan(witness, plan).passed
    assert not audit_harness_plan(witness, replace(plan, post_steps=[])).passed
    # The legacy no-post plan still maps the last request as fuzz.
    legacy = next(item for item in normal if item.target_action_id == 'read')
    legacy_witness = replace(witness, scenario_id=legacy.scenario_id,
                             target_action_id='read', steps=legacy.steps,
                             observations=[], fuzz_step_index=-1,
                             status=ScenarioStatus.REPLAYED_RUNTIME)
    legacy_plan = build_harness_plan(legacy_witness,
        action_function_ids={'put': ('tcp_read', 'put'), 'read': ('tcp_read', 'read')},
        allow_observed=True)
    assert legacy_plan.setup_steps and not legacy_plan.post_steps
    assert legacy_plan.fuzz_step.action_id == 'read'
