from __future__ import annotations

import json
from pathlib import Path

import pytest

from harnesscreator.analysis import (
    fuzzgen_reports_to_rubick_a2dg,
    load_usage_evidence,
    run_rubick_a2dg,
)
from harnesscreator.models import AnalysisBundle, FunctionMetadata


def _analysis() -> AnalysisBundle:
    init = FunctionMetadata.create(
        name="item_init",
        signature="void item_init(void)",
        file="item.c",
        start_line=1,
        end_line=3,
        source="void item_init(void) {}",
    )
    use = FunctionMetadata.create(
        name="item_get",
        signature="item *item_get(const char *key)",
        file="item.c",
        start_line=5,
        end_line=8,
        source="item *item_get(const char *key) { return 0; }",
    )
    return AnalysisBundle(
        functions={init.function_id: init, use.function_id: use},
        edges=[],
        completeness={"authoritative": True},
    )


def test_hopper_required_context_overrides_action_guess(tmp_path: Path) -> None:
    constraints = tmp_path / "constraint.config"
    constraints.write_text(
        "ctx item_get[$0] <- item_init\n",
        encoding="utf-8",
    )
    evidence = load_usage_evidence(
        _analysis(), hopper_constraints=[constraints]
    )
    init_id = next(
        function_id
        for function_id, function in _analysis().functions.items()
        if function.name == "item_init"
    )
    get_id = next(
        function_id
        for function_id, function in _analysis().functions.items()
        if function.name == "item_get"
    )

    missing = evidence.constrain_actions([
        {"action_id": "get", "function_id": get_id, "allowed_after": []}
    ])
    assert any("UPSTREAM_DEPENDENCY_MISSING" in item for item in missing.blockers)

    ordered = evidence.constrain_actions([
        {"action_id": "init", "function_id": init_id, "allowed_after": []},
        {"action_id": "get", "function_id": get_id, "allowed_after": []},
    ])
    assert not ordered.blockers
    assert ordered.actions[1]["allowed_after"] == ["init"]
    assert ordered.applied_constraints

    reversed_actions = evidence.constrain_actions([
        {"action_id": "get", "function_id": get_id, "allowed_after": []},
        {"action_id": "init", "function_id": init_id, "allowed_after": []},
    ])
    assert any(
        "UPSTREAM_DEPENDENCY_REVERSED" in item
        for item in reversed_actions.blockers
    )


def test_fuzzgen_dependency_report_is_not_reinferred(tmp_path: Path) -> None:
    report = tmp_path / "fuzzgen.json"
    report.write_text(json.dumps({
        "schema": "harnesscreator.fuzzgen.aadg.v1",
        "graphs": [{
            "name": "consumer",
            "nodes": [
                {
                    "id": "0",
                    "callee": "item_init",
                    "dependencies": [{
                        "slot": "return",
                        "dependency_id": 65536,
                        "dependency_type": 1,
                    }],
                },
                {
                    "id": "1",
                    "callee": "item_get",
                    "dependencies": [{
                        "slot": "arg0",
                        "dependency_id": 65536,
                        "dependency_type": 2,
                    }],
                },
            ],
            "control_edges": [
                {"from": "0", "to": "1", "back_edge": False}
            ],
        }],
    }), encoding="utf-8")

    evidence = load_usage_evidence(_analysis(), fuzzgen_reports=[report])
    dependencies = [
        item for item in evidence.constraints
        if item.relation == "DATA_DEPENDENCY"
    ]
    assert len(dependencies) == 1
    assert dependencies[0].producer == "item_init"
    assert dependencies[0].consumer == "item_get"
    assert dependencies[0].strength == "REQUIRED"
    assert evidence.providers[0].state == "USED"


def test_locked_rubick_source_runs_out_of_process(tmp_path: Path) -> None:
    research_root = Path(__file__).resolve().parents[2] / "research-repos"
    if not (research_root / "Rubick").is_dir():
        pytest.skip("locked RUBICK checkout is not present")
    report = tmp_path / "fuzzgen.json"
    report.write_text(json.dumps({
        "schema": "harnesscreator.fuzzgen.aadg.v1",
        "graphs": [{
            "name": "consumer",
            "nodes": [
                {"id": "0", "callee": "item_init", "dependencies": []},
                {"id": "1", "callee": "item_get", "dependencies": []},
            ],
            "control_edges": [
                {"from": "0", "to": "1", "back_edge": False}
            ],
        }],
    }), encoding="utf-8")
    a2dgs = fuzzgen_reports_to_rubick_a2dg(
        [report], tmp_path / "a2dg"
    )
    rubick_run = run_rubick_a2dg(
        research_root, a2dgs, tmp_path / "rubick-nfa.json"
    )
    evidence = load_usage_evidence(
        _analysis(), rubick_nfas=[rubick_run.output]
    )
    assert rubick_run.returncode == 0
    assert "harnesscreator_bridge.py" in rubick_run.command[1]
    rubick_status = next(
        item for item in evidence.providers if item.provider == "RUBICK"
    )
    assert rubick_status.state == "USED"
    assert evidence.sequences
    assert evidence.sequences[0].calls == ["item_init", "item_get"]
    ids = {
        function.name: function_id
        for function_id, function in _analysis().functions.items()
    }
    invalid = evidence.constrain_actions([
        {"action_id": "get", "function_id": ids["item_get"], "allowed_after": []},
        {"action_id": "init", "function_id": ids["item_init"], "allowed_after": []},
    ])
    assert any("UPSTREAM_SEQUENCE_INVALID" in item for item in invalid.blockers)
