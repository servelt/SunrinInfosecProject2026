from __future__ import annotations

import asyncio
from pathlib import Path

from harnesscreator.agents.harness import CHECKLIST_NAMES
from harnesscreator.agents.scenario_harness import (
    ScenarioHarnessGeneratorAgent,
    build_harness_plan,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.indexer import StaticAnalyzer
from harnesscreator.llm.base import ScriptedLLM, validate_strict_output_schema
from harnesscreator.models import (
    CheckStatus,
    GateReport,
    HarnessDraft,
    HarnessManifest,
    ProjectSpec,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
)
from harnesscreator.agents.scenario_harness import SCENARIO_REVIEW_CONTEXT_SCHEMA


def _case(tmp_path: Path):
    (tmp_path / "server.c").write_text(
        "void startup(void) {}\n"
        "int receive_one(const char *p) { return p[0]; }\n"
        "int handle_one(const char *p) { return receive_one(p); }\n",
        encoding="utf-8",
    )
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    ids = {function.name: function.function_id for function in graph.bundle.functions.values()}
    witness = ScenarioWitness(
        "witness", "scenario", "action",
        [ScenarioStep(0, "action", "entry", "58", {}, [])],
        [], ["handle_one"], "stdin", 0, ScenarioStatus.PROVEN_RUNTIME,
        "request-correlated fixture",
    )
    plan = build_harness_plan(
        witness,
        action_function_ids={"action": (ids["receive_one"], ids["handle_one"])},
    )
    manifest = HarnessManifest(
        harness_id="harness", scenario_id="scenario", source_file="fuzz_target.c",
        build_target="fixture", engine="libfuzzer", sanitizers=["address"],
        execution_model="in_process_reset", headers=[], libraries=[],
        min_size=0, max_size=4096, dispatch_strategy="one_scenario_per_harness",
        expected_anchors=[ids["handle_one"]], expected_consumers=[ids["receive_one"]],
    )
    draft = HarnessDraft(
        manifest,
        "int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return 0; }",
        context_function_ids=[ids["startup"]],
    )
    project = ProjectSpec(name="fixture", source_root=tmp_path, output_root=tmp_path / "out")
    return graph, ids, plan, witness, draft, project


def test_independent_reviewer_opens_source_one_function_per_turn(tmp_path: Path) -> None:
    validate_strict_output_schema(SCENARIO_REVIEW_CONTEXT_SCHEMA)
    graph, ids, plan, witness, draft, project = _case(tmp_path)
    llm = ScriptedLLM([
        {"context_complete": False, "requested_function_ids": [ids["startup"]],
         "rationale": "inspect startup"},
        {"context_complete": False, "requested_function_ids": [], "rationale": "inspect requested source"},
        {"context_complete": True, "requested_function_ids": [], "rationale": "source inspected"},
        {"checks": [
            {"check_id": check_id, "status": "PASS", "evidence": "inspected source",
             "remediation": ""}
            for check_id in CHECKLIST_NAMES
        ], "summary": "reviewed"},
    ])
    agent = ScenarioHarnessGeneratorAgent(llm, graph, project)
    report = asyncio.run(agent.review(draft, plan, witness, GateReport([])))
    assert report.passed
    assert len(llm.calls) == 4
    opened = [call["payload"]["current_function"] for call in llm.calls[:3]]
    assert {item["function_id"] for item in opened} == (
        set(plan.entry_function_ids) | set(plan.required_function_ids) | {ids["startup"]}
    )
    assert all("source" in item for item in opened)
    assert "current_function" not in llm.calls[3]["payload"]
    assert "harness_code" in llm.calls[0]["payload"]
    assert "harness_code" not in llm.calls[1]["payload"]
    assert len({call["session_key"] for call in llm.calls}) == 1


def test_independent_review_stops_when_source_context_incomplete(tmp_path: Path) -> None:
    graph, _, plan, witness, draft, project = _case(tmp_path)
    llm = ScriptedLLM([
        {"context_complete": False, "requested_function_ids": [],
         "rationale": "needs additional source"},
        {"context_complete": False, "requested_function_ids": [],
         "rationale": "still incomplete"},
    ])
    agent = ScenarioHarnessGeneratorAgent(llm, graph, project)
    report = asyncio.run(agent.review(draft, plan, witness, GateReport([])))
    assert not report.passed
    assert len(llm.calls) == 2
    assert any(check.check_id == "HC14" and check.status is CheckStatus.FAIL
               for check in report.checks)


def test_independent_review_rejects_unlinked_source_request(tmp_path: Path) -> None:
    graph, _, plan, witness, draft, project = _case(tmp_path)
    llm = ScriptedLLM([
        {"context_complete": False, "requested_function_ids": ["not_in_the_index"],
         "rationale": "request another body"},
    ])
    report = asyncio.run(
        ScenarioHarnessGeneratorAgent(llm, graph, project).review(
            draft, plan, witness, GateReport([])
        )
    )
    assert len(llm.calls) == 1
    assert any(
        check.check_id == "HC14" and check.status is CheckStatus.FAIL
        and "not_in_the_index" in check.evidence
        for check in report.checks
    )
