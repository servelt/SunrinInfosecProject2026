"""Stage-boundary tests: never silently erase a verified input Action."""
from __future__ import annotations

from harnesscreator.models import ScenarioStatus, ScenarioWitness, ScenarioStep
from harnesscreator.runtime.workflow_evidence import schedule_generation


def witness(action: str, status: ScenarioStatus, suffix: str = '') -> ScenarioWitness:
    return ScenarioWitness(
        witness_id=f'w-{action}-{suffix}', scenario_id=f's-{action}-{suffix}',
        target_action_id=action,
        steps=[ScenarioStep(0, action, 'external', b'GET x\n'.hex(), {}, [])],
        observations=[], command=[], channel='tcp', process_returncode=None,
        status=status, rationale='test',
    )


def test_source_only_opt_in_preserves_unattributed_observation():
    observed = witness('read', ScenarioStatus.REPLAYED_RUNTIME)
    result = schedule_generation([observed], source_supported_actions={'read'},
                                 exploratory_enabled=False, source_drafts_enabled=True,
                                 max_source_drafts=1)
    assert result.selected == [observed]
    assert result.source_only == [observed]
    assert result.proven == []


def test_proven_is_never_lost_due_to_draft_budget():
    already_proven = witness('set', ScenarioStatus.PROVEN_RUNTIME)
    blocked = witness('get', ScenarioStatus.UNPROVEN)
    result = schedule_generation([blocked, already_proven],
                                 source_supported_actions={'get', 'set'},
                                 exploratory_enabled=False, source_drafts_enabled=True,
                                 max_source_drafts=0)
    assert result.selected == [already_proven]
    assert result.excluded[blocked.scenario_id].startswith('SOURCE_DRAFT_BUDGET')


def test_draft_budget_prefers_distinct_actions_before_variants():
    w = [witness('set', ScenarioStatus.UNPROVEN, str(i)) for i in range(9)]
    w.append(witness('get', ScenarioStatus.INFRASTRUCTURE_FAILED))
    result = schedule_generation(w, source_supported_actions={'set', 'get'},
                                 exploratory_enabled=False, source_drafts_enabled=True,
                                 max_source_drafts=2)
    assert {x.target_action_id for x in result.source_only} == {'set', 'get'}
    assert len(result.excluded) == 8


def test_rejected_and_no_source_evidence_remain_explained():
    incomplete = witness('unsupported', ScenarioStatus.UNPROVEN)
    result = schedule_generation([incomplete], source_supported_actions=set(),
                                 exploratory_enabled=False, source_drafts_enabled=True,
                                 max_source_drafts=5)
    assert result.selected == []
    assert result.excluded[incomplete.scenario_id] == 'SOURCE_CONTRACT_INCOMPLETE'


def test_exploratory_observed_is_not_double_scheduled():
    obs = witness('set', ScenarioStatus.OBSERVED_RUNTIME)
    unproven = witness('get', ScenarioStatus.UNPROVEN)
    result = schedule_generation([obs, unproven],
                                 source_supported_actions={'set','get'},
                                 exploratory_enabled=True, source_drafts_enabled=True,
                                 max_source_drafts=2)
    assert result.selected == [obs, unproven]
    assert result.observed == [obs]
    assert result.source_only == [unproven]
