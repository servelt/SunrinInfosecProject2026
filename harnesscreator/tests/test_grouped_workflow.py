"""Source-path batching must save turns without erasing unresolved work."""

from __future__ import annotations

import unittest
from dataclasses import replace

from harnesscreator.agents.scenario import InputActionAgent, StateDependencyAgent
from harnesscreator.analysis import GraphStore
from harnesscreator.analysis.usage_evidence import UsageEvidenceBundle
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    ActionExample, AnalysisBundle, EntryRecord, EntrySiteKind, Evidence,
    ExternalActionSchema, FunctionMetadata, OperationSeed, ProofStatus, Verdict,
)


def _fixture():
    source = (
        "int dispatch(const unsigned char *buf) {\n"
        "  switch (buf[0]) {\n"
        "    case 1: return buf[1];\n"
        "    case 2: return buf[2];\n"
        "    case 3: return buf[3];\n"
        "    default: return -1;\n"
        "  }\n"
        "}\n"
    )
    function = FunctionMetadata.create(
        name="dispatch", signature="int dispatch(const unsigned char *buf)",
        file="target.c", start_line=1, end_line=8, source=source,
    )
    graph = GraphStore(AnalysisBundle(functions={function.function_id: function}, edges=[]))
    entry = EntryRecord(
        entry_id="entry-1", candidate_id="candidate-1", status=Verdict.VERIFIED,
        entry_function_id=function.function_id, source_api="read",
        channel_kind="network tcp socket", attacker_control="full",
        provenance_path=[], consumer_hints=[function.function_id],
        evidence=[Evidence("source", function.function_id, function.file, 1,
                           "read gets external input")],
        unknowns=[], verifier_confidence=1,
        first_acquisition_confirmed=True,
        site_kind=EntrySiteKind.DIRECT_ACQUISITION, entry_line=1,
    )
    seeds = [
        OperationSeed(
            operation_seed_id=f"seed-{number}",
            dispatcher_function_id=function.function_id,
            discriminator=str(number), line=number + 2,
            handler_function_ids=[function.function_id],
            entry_path_function_ids=[function.function_id],
            evidence_kind="switch_case",
        )
        for number in (1, 2, 3)
    ]
    return graph, entry, seeds


def _action_response(function, number):
    evidence = [{
        "kind": "source", "function_id": function.function_id,
        "line": number + 2, "detail": f"case {number} dispatches input",
    }]
    return {
        "name": f"opcode {number}", "description": "external operation",
        "dispatcher_function_id": function.function_id,
        "handler_function_id": function.function_id,
        "discriminator": str(number), "fields": [],
        "examples": [{"data_hex": f"0{number}000000", "bindings": [],
                      "rationale": "opcode request", "origin": "product_source",
                      "evidence": evidence}],
        "success_markers_hex": ["4f4b"], "failure_markers_hex": [],
        "success_evidence": evidence, "failure_evidence": [],
        "response_bindings": [], "evidence": evidence,
        "unknowns": [], "confidence": 0.99,
    }


def _state_action(function, name):
    evidence = [Evidence("source", function.function_id, function.file, 3,
                         "handler parses the selected command")]
    return ExternalActionSchema(
        action_id=f"action-{name}", entry_id="entry-1", name=name,
        description="request", dispatcher_function_id=function.function_id,
        handler_function_id=function.function_id, discriminator=name,
        channel_kind="network tcp socket", fields=[],
        examples=[ActionExample("01020304")], success_markers_hex=["4f4b"],
        failure_markers_hex=[], evidence=evidence,
        inspected_function_ids=[function.function_id],
        status=ProofStatus.PROVEN_STATIC, confidence=0.99,
    )


def _state_contract(action_id, function, *, complete=True):
    return {
        "action_id": action_id,
        "action_context_complete": complete,
        "consumes": [], "produces": [], "invalidates": [],
        "initial_resources": [], "success_condition": "valid request parsed",
        "evidence": [{
            "kind": "source", "function_id": function.function_id,
            "line": 3, "detail": "handler returns after input parsing",
        }],
        "unknowns": [],
    }


class GroupedWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_distant_cases_in_truncated_function_are_not_grouped(self):
        function = FunctionMetadata.create(
            name="large_dispatch", signature="int large_dispatch(int op)",
            file="target.c", start_line=1, end_line=203,
            source=("int large_dispatch(int op) {\n"
                    + "  volatile int x = 0; // " + "A" * 180 + "\n"
                    + ("  x += op; // " + "B" * 180 + "\n") * 200
                    + "  return x;\n}\n"),
        )
        graph = GraphStore(AnalysisBundle(
            functions={function.function_id: function}, edges=[],
        ))
        entry = EntryRecord(
            entry_id="entry-long", candidate_id="candidate-long",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="read", channel_kind="stdin", attacker_control="full",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=1,
        )
        seeds = [
            OperationSeed(
                operation_seed_id=f"long-{line}",
                dispatcher_function_id=function.function_id,
                discriminator=str(line), line=line,
                handler_function_ids=[function.function_id],
                evidence_kind="switch_case",
            ) for line in (3, 190)
        ]
        agent = InputActionAgent(ScriptedLLM([]), graph, budget=4)
        groups = agent._group_branch_items([
            (entry, seed, function.function_id) for seed in seeds
        ])
        # Complete source is now delivered. Distant cases are no longer
        # hidden solely because an excerpt ended before their case label.
        self.assertEqual([len(group) for group in groups], [2])

    async def test_multiple_labels_one_source_walk_keeps_each_action(self):
        graph, entry, seeds = _fixture()
        with self.assertRaisesRegex(ValueError, "syntax-branch Action discovery is retired"):
            InputActionAgent(
                ScriptedLLM([]), graph, budget=4,
                semantic_action_mode=False,
            )

    async def test_missing_group_case_falls_back_to_individual_worker(self):
        graph, entry, seeds = _fixture()
        function = graph.get(entry.entry_function_id)
        llm = ScriptedLLM([
            {
                "actions": [_action_response(function, i) for i in (1, 2)],
                "context_complete": True, "requested_function_ids": [],
                "rationale": "third case omitted",
                "branch_dispositions": [
                    {"operation_seed_id": seed.operation_seed_id,
                     "disposition": "ACTION", "evidence": []}
                    for seed in seeds[:2]
                ],
            },
            {
                "actions": [_action_response(function, 3)],
                "context_complete": True, "requested_function_ids": [],
                "rationale": "third case independently recovered",
                "branch_disposition": "ACTION",
                "branch_disposition_evidence": [],
            },
        ])
        agent = InputActionAgent(llm, graph, budget=4)
        results = await agent._run_seed_group([
            (entry, seed, function.function_id) for seed in seeds
        ])

        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(len(results), 3)
        self.assertEqual([len(row[0]) for row in results], [1, 1, 1])
        self.assertIn("group unresolved", results[2][3])

    async def test_state_group_replays_each_contract_with_no_extra_llm_turns(self):
        graph, entry, _ = _fixture()
        function = graph.get(entry.entry_function_id)
        actions = [_state_action(function, "1"), _state_action(function, "2")]
        llm = ScriptedLLM([{
            "contracts": [_state_contract(action.action_id, function)
                          for action in actions],
            "context_complete": True, "requested_function_ids": [],
            "rationale": "both contracts analyzed from the same handler",
        }])
        agent = StateDependencyAgent(llm, graph, UsageEvidenceBundle(), budget=4)

        dependencies = await agent.run(actions)

        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(agent.planned_state_groups, 1)
        self.assertEqual(len(dependencies.contracts), 2)
        self.assertTrue(all(
            contract.status is ProofStatus.PROVEN_STATIC
            for contract in dependencies.contracts
        ))

    async def test_source_reviewed_effect_shares_state_walk_across_entries(self):
        graph, entry, _ = _fixture()
        function = graph.get(entry.entry_function_id)
        first = _state_action(function, "1")
        second = replace(_state_action(function, "2"), entry_id="entry-udp")
        llm = ScriptedLLM([{
            "contracts": [_state_contract(item.action_id, function)
                          for item in (first, second)],
            "context_complete": True, "requested_function_ids": [],
            "rationale": "shared handler source, separate contracts",
        }])
        agent = StateDependencyAgent(llm, graph, UsageEvidenceBundle(), budget=4)
        dependencies = await agent.run(
            [first, second], source_group_ids={
                first.action_id: "source-reviewed-group",
                second.action_id: "source-reviewed-group",
            },
        )
        self.assertEqual(agent.planned_state_groups, 1)
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual({item.action_id for item in dependencies.contracts},
                         {first.action_id, second.action_id})

    async def test_unfinished_state_in_group_gets_its_own_source_walk(self):
        graph, entry, _ = _fixture()
        function = graph.get(entry.entry_function_id)
        actions = [_state_action(function, "1"), _state_action(function, "2")]
        independent = _state_contract(actions[1].action_id, function)
        independent.pop("action_id")
        independent.pop("action_context_complete")
        llm = ScriptedLLM([
            {
                "contracts": [
                    _state_contract(actions[0].action_id, function),
                    _state_contract(actions[1].action_id, function, complete=False),
                ],
                "context_complete": True, "requested_function_ids": [],
                "rationale": "second branch needs independent study",
            },
            {
                **independent, "context_complete": True,
                "requested_function_ids": [], "rationale": "independent study",
            },
        ])
        agent = StateDependencyAgent(llm, graph, UsageEvidenceBundle(), budget=4)

        dependencies = await agent.run(actions)

        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(len(dependencies.contracts), 2)
        self.assertTrue(all(
            contract.status is ProofStatus.PROVEN_STATIC
            for contract in dependencies.contracts
        ))


if __name__ == "__main__":
    unittest.main()
