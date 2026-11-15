"""Every discovered external Action retains a planning outcome."""
from unittest.mock import patch

from harnesscreator.agents.scenario import ScenarioPlanner
from harnesscreator.models import (
    ActionExample, Evidence, ExternalActionSchema, InputFieldConstraint,
    ProofStatus, ActionStateContract, StateDependencyGraph,
)


def _action(name: str) -> ExternalActionSchema:
    evidence = [Evidence("source", "fn", "fixture.c", 1, "input action")]
    return ExternalActionSchema(
        action_id=name, entry_id="entry", name=name, description=name,
        dispatcher_function_id="fn", handler_function_id="fn",
        discriminator=name, channel_kind="stdin", fields=[],
        examples=[ActionExample(name.encode().hex())],
        success_markers_hex=[], failure_markers_hex=[], evidence=evidence,
        inspected_function_ids=["fn"], status=ProofStatus.POSSIBLE,
        confidence=0.5, source_api="read", success_evidence=evidence,
        entry_function_id="fn",
    )


def test_default_variant_budget_cannot_erase_a_later_action() -> None:
    planner = ScenarioPlanner(max_candidates=1)
    candidates = planner.exploratory_candidates([_action("first"), _action("second")], [])

    assert {item.target_action_id for item in candidates} == {"first", "second"}
    assert any("reserving one trial slot per target" in item for item in planner.obligations)


def test_explicit_diagnostic_limit_records_omitted_action() -> None:
    planner = ScenarioPlanner(max_candidates=1)
    candidates = planner.exploratory_candidates(
        [_action("first"), _action("second")], [], limit=1,
    )

    assert [item.target_action_id for item in candidates] == ["first"]
    assert any("omitted target action(s)" in item and "second" in item
               for item in planner.obligations)


def test_unrenderable_source_example_is_reported_separately_from_budget() -> None:
    broken = _action("broken")
    broken.fields = [InputFieldConstraint("missing", 30, 1)]
    planner = ScenarioPlanner(max_candidates=2)

    candidates = planner.exploratory_candidates([broken, _action("valid")], [])

    assert [item.target_action_id for item in candidates] == ["valid"]
    assert any("broken: no concrete standalone request" in item
               for item in planner.obligations)
    assert not any("budget omitted" in item and "broken" in item
                   for item in planner.obligations)


def test_exhausted_prerequisite_search_is_not_reported_as_complete() -> None:
    action = _action("lookup")
    contract = ActionStateContract(
        action.action_id, [], [], [], "possible prerequisite",
        action.evidence, [action.handler_function_id], ProofStatus.POSSIBLE,
    )
    planner = ScenarioPlanner(max_candidates=1, max_search_states=1)
    with patch.object(planner, "_search_many", return_value=([], True)):
        candidates = planner.exploratory_candidates(
            [action], [], dependencies=StateDependencyGraph([contract], [], []),
        )

    assert [item.target_action_id for item in candidates] == ["lookup"]
    assert any("additional prerequisite sequences remain unresolved" in item
               for item in planner.obligations)
