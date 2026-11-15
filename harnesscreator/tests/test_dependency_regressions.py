from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path

from harnesscreator.agents.scenario import ScenarioPlanner, StateDependencyAgent
from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.analysis.usage_evidence import UsageConstraint, UsageEvidenceBundle
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    ActionExample, ActionStateContract, AnalysisBundle, Evidence, ExternalActionSchema,
    InputFieldConstraint, ProofStatus, ScenarioStatus, StateDependencyGraph,
    StateRequirement,
)


def action(name: str, examples: list[ActionExample], field_offset: int) -> ExternalActionSchema:
    evidence = [Evidence("source", "fn", "target.c", 1, "fixture")]
    return ExternalActionSchema(
        action_id=name, entry_id="entry", name=name, description=name,
        dispatcher_function_id="fn", handler_function_id="fn", discriminator=name,
        channel_kind="stdin", fields=[InputFieldConstraint(
            name="key", offset=field_offset, width=1, encoding="bytes",
            binding="key", relation="request key", evidence=evidence,
        )], examples=examples, success_markers_hex=["4f4b"], failure_markers_hex=[],
        evidence=evidence, inspected_function_ids=["fn"],
        status=ProofStatus.PROVEN_STATIC, confidence=0.99,
        source_api="read", success_evidence=evidence,
    )


class PlannerBindingRegressionTest(unittest.TestCase):
    def test_unlisted_example_binding_uses_its_actual_field_bytes(self) -> None:
        producer = action("set", [ActionExample(b"SET a\n".hex(), {})], 4)
        consumer = action("get", [
            ActionExample(b"GET b\n".hex(), {"key": b"b".hex()}),
            ActionExample(b"GET a\n".hex(), {"key": b"a".hex()}),
        ], 4)
        resource = StateRequirement(
            "item", "key", "exists", producer.evidence, ProofStatus.PROVEN_STATIC,
        )
        graph = StateDependencyGraph([
            ActionStateContract("set", [], [resource], [], "stored",
                                producer.evidence, ["fn"], ProofStatus.PROVEN_STATIC),
            ActionStateContract("get", [resource], [], [], "value",
                                consumer.evidence, ["fn"], ProofStatus.PROVEN_STATIC),
        ], [], [])
        candidates = ScenarioPlanner(max_steps=4).plan([producer, consumer], graph)
        get_candidates = [c for c in candidates if c.target_action_id == "get"]
        self.assertTrue(get_candidates)
        self.assertTrue(all(c.status is ScenarioStatus.CANDIDATE for c in get_candidates))
        self.assertEqual(
            [[bytes.fromhex(s.request_hex) for s in c.steps] for c in get_candidates],
            [[b"SET a\n", b"GET a\n"]],
        )

    def test_bound_field_cannot_extend_a_short_example(self) -> None:
        target = action("query", [
            ActionExample(b"A".hex(), {"key": b"k".hex()}),
            ActionExample(b"ABk".hex(), {"key": b"k".hex()}),
        ], 2)
        graph = StateDependencyGraph([
            ActionStateContract("query", [], [], [], "ok", target.evidence,
                                ["fn"], ProofStatus.PROVEN_STATIC),
        ], [], [])
        candidates = ScenarioPlanner(max_steps=2).plan([target], graph)
        self.assertEqual(
            [bytes.fromhex(c.steps[0].request_hex) for c in candidates],
            [b"ABk"],
        )


class StateDependencyRegressionTest(unittest.IsolatedAsyncioTestCase):
    async def test_long_handler_tail_is_visible_to_state_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int query(const unsigned char *p) {\n"
                + "".join(
                    f"  /* state analysis context {index:04d} */\n"
                    for index in range(520)
                )
                + "  /* REQUIRED_TAIL: success depends on item state */\n"
                + "  return p[0] == 'Q';\n}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            handler = next(iter(graph.bundle.functions.values()))
            self.assertGreater(len(handler.source), 16_000)
            target = action("query", [ActionExample(b"Q".hex(), {})], 0)
            target.handler_function_id = handler.function_id
            target.dispatcher_function_id = handler.function_id
            llm = ScriptedLLM([{
                "consumes": [], "produces": [], "invalidates": [],
                "initial_resources": [], "success_condition": "",
                "evidence": [], "unknowns": [], "context_complete": True,
                "requested_function_ids": [],
            }])
            await StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(),
            ).run([target])
            current = llm.calls[0]["payload"]["current_function"]
            self.assertIn("REQUIRED_TAIL", current["source"])
            self.assertFalse(current["source_truncated"])

    async def test_demoted_contract_cannot_supply_initial_state(self) -> None:
        action_ref = types.SimpleNamespace(
            action_id="query", handler_function_id="query_fn",
            dispatcher_function_id="query_fn",
        )
        upstream = UsageEvidenceBundle(constraints=[UsageConstraint(
            constraint_id="missing-producer", provider="test", relation="before",
            strength="REQUIRED", producer="make", consumer="query",
            producer_function_ids=[], consumer_function_ids=["query_fn"],
        )])
        agent = StateDependencyAgent(
            types.SimpleNamespace(max_concurrency=1),
            GraphStore(AnalysisBundle(functions={}, edges=[])), upstream,
        )

        async def scripted_run(_):
            return ActionStateContract(
                "query", [], [], [], "success", [], [], ProofStatus.PROVEN_STATIC,
            ), [StateRequirement(
                "cached_item", "", "exists", [], ProofStatus.PROVEN_STATIC,
            )]

        agent._run_action = scripted_run
        result = await agent.run([action_ref])
        self.assertIs(result.contracts[0].status, ProofStatus.POSSIBLE)
        self.assertEqual(result.initial_resources, [])

    async def test_earlier_invalid_claim_cannot_disappear_at_final_turn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int item_exists(const unsigned char *p) { return p[0] != 0; }\n"
                "int query(const unsigned char *p) { return item_exists(p); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            funcs = {item.name: item for item in graph.bundle.functions.values()}
            query, item_exists = funcs["query"], funcs["item_exists"]
            evidence = Evidence("source", query.function_id, query.file,
                                query.start_line, "handler")
            target = ExternalActionSchema(
                action_id="query", entry_id="entry", name="query",
                description="query", dispatcher_function_id=query.function_id,
                handler_function_id=query.function_id, discriminator="Q",
                channel_kind="stdin", fields=[], examples=[ActionExample("51", {})],
                success_markers_hex=["31"], failure_markers_hex=[],
                evidence=[evidence], inspected_function_ids=[query.function_id],
                status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                source_api="read", success_evidence=[evidence],
            )
            source_evidence = [{"kind": "source", "function_id": query.function_id,
                                "line": query.start_line, "detail": "handler"}]
            llm = ScriptedLLM([
                {"consumes": [{"resource": "item", "binding": "",
                               "predicate": "exists", "evidence": []}],
                 "produces": [], "invalidates": [], "initial_resources": [],
                 "success_condition": "", "evidence": source_evidence,
                 "unknowns": ["lookup unopened"], "context_complete": False,
                 "requested_function_ids": [item_exists.function_id]},
                {"consumes": [], "produces": [], "invalidates": [],
                 "initial_resources": [], "success_condition": "returns true",
                 "evidence": source_evidence, "unknowns": [],
                 "context_complete": True, "requested_function_ids": []},
            ])
            result = await StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(), budget=2,
            ).run([target])
        self.assertIs(result.contracts[0].status, ProofStatus.POSSIBLE)
        self.assertTrue(any(
            "lacked valid opened-source evidence" in item
            for item in result.contracts[0].unknowns
        ))
