from __future__ import annotations

import unittest

from harnesscreator.agents.contracts import assess_small_feature
from harnesscreator.agents.features import LargeFeatureAgent
from harnesscreator.agents.harness import _validated_operation_protocols
from harnesscreator.agents.small_feature import (
    SmallFeatureAgent,
    _DiscoveryResult,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.operation_seeds import extract_operation_seeds
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle,
    CallEdge,
    Evidence,
    FunctionMetadata,
    EntryRecord,
    ObligationOwner,
    OperationSeed,
    ProofStatus,
    SmallFeatureSpec,
    Verdict,
)


def _function(name: str, source: str, start: int = 1) -> FunctionMetadata:
    return FunctionMetadata.create(
        name=name,
        qualified_name=name,
        signature=f"int {name}(void)",
        file="server.c",
        start_line=start,
        end_line=start + max(0, len(source.splitlines()) - 1),
        source=source,
    )


def _feature(
    identifier: str,
    entry: str,
    function: FunctionMetadata,
    *,
    consumes: list[str] | None = None,
    produces: list[str] | None = None,
) -> SmallFeatureSpec:
    return SmallFeatureSpec(
        small_feature_id=identifier,
        name=identifier,
        description=identifier,
        root_entries=[entry],
        supporting_entries=[],
        harness_anchor=function.function_id,
        anchor_rationale="normal operation",
        boundary_preserved=True,
        preconditions=[],
        initialization=[],
        required_functions=[function.function_id],
        actions=[{
            "action_id": "operate",
            "function_id": function.function_id,
            "consumes": consumes or [],
            "produces": produces or [],
            "allowed_after": [],
            "success_condition": "operation succeeds",
        }],
        input_bindings=[],
        cleanup_success=[],
        cleanup_failure=[],
        stable_post_state="done",
        completion_oracle="operation succeeds",
        evidence=[Evidence(
            "operation", function.function_id, function.file,
            function.start_line, "operation source",
        )],
        unknowns=[],
        confidence=0.9,
        completion_action_id="",
        channel_kind="network",
        build_target="server",
        isolation_mode="in_process_reset",
        planning_complete=False,
        planning_blockers=[
            "completion_action_id does not identify an evidenced operation action"
        ],
    )


class EvidenceWorkflowTest(unittest.IsolatedAsyncioTestCase):
    def test_protocol_gap_does_not_erase_semantic_feature(self) -> None:
        operation = _function("operate", "int operate(void) { return 0; }")
        feature = _feature("sf-operation", "entry-a", operation)
        feature.boundary_preserved = False
        feature.planning_blockers.append(
            "normal lifecycle/security boundary preservation is unresolved"
        )

        assessed = assess_small_feature(feature)

        self.assertTrue(assessed.semantic_complete)
        self.assertFalse(assessed.planning_complete)
        self.assertTrue(assessed.proof_obligations)
        self.assertTrue(all(
            item.owner is ObligationOwner.HARNESS_GENERATOR
            for item in assessed.proof_obligations
        ))

    def test_invalid_intra_operation_order_is_semantic_blocker(self) -> None:
        operation = _function("operate", "int operate(void) { return 0; }")
        feature = _feature("sf-operation", "entry-a", operation)
        feature.actions[0]["allowed_after"] = ["missing-action"]

        assessed = assess_small_feature(feature)

        self.assertFalse(assessed.semantic_complete)
        self.assertTrue(any(
            "missing predecessor" in item for item in assessed.semantic_blockers
        ))

    def test_operation_seed_extraction_is_project_generic(self) -> None:
        store = _function("store_item", "int store_item(void) { return 1; }", 30)
        lookup = _function("lookup_item", "int lookup_item(void) { return 1; }", 40)
        dispatcher = _function(
            "dispatch_request",
            """int dispatch_request(int opcode) {
  switch (opcode) {
    case OP_STORE:
      return store_item();
    case OP_LOOKUP:
      return lookup_item();
    default:
      return -1;
  }
}""",
            1,
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                item.function_id: item for item in (dispatcher, store, lookup)
            },
            edges=[],
        ))

        seeds = extract_operation_seeds([dispatcher], graph)

        by_discriminator = {item.discriminator: item for item in seeds}
        self.assertIn("OP_STORE", by_discriminator)
        self.assertIn("OP_LOOKUP", by_discriminator)
        self.assertEqual(
            by_discriminator["OP_STORE"].handler_function_ids,
            [store.function_id],
        )
        self.assertEqual(
            by_discriminator["OP_LOOKUP"].handler_function_ids,
            [lookup.function_id],
        )

    def test_guard_does_not_claim_a_later_call_as_its_handler(self) -> None:
        parse = _function("parse_frame", "int parse_frame(void) { return 1; }", 30)
        reader = _function(
            "read_frame",
            """int read_frame(int received) {
  if (received <= 0) {
    return -1;
  }
  return parse_frame();
}""",
            1,
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parse)},
            edges=[],
        ))

        self.assertEqual(extract_operation_seeds([reader], graph), [])

    def test_inline_conditional_effect_is_a_possible_work_item(self) -> None:
        dispatcher = _function(
            "dispatch_inline",
            """int dispatch_inline(const unsigned char *input) {
  int state = 0;
  if (input[0] == 1) {
    state = 7;
  }
  return state;
}""",
            1,
        )
        graph = GraphStore(AnalysisBundle(
            functions={dispatcher.function_id: dispatcher}, edges=[],
        ))
        seeds = extract_operation_seeds(
            [dispatcher], graph, input_symbols={"input"},
        )
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0].handler_function_ids, [])
        self.assertEqual(seeds[0].status, ProofStatus.POSSIBLE)
        self.assertEqual(seeds[0].evidence_kind, "conditional_branch")
        self.assertEqual(extract_operation_seeds([dispatcher], graph), [])

    def test_call_bearing_internal_if_does_not_expand_entry_work(self) -> None:
        internal = _function("internal_tick", "int internal_tick(void) { return 1; }", 30)
        external = _function("handle_input", "int handle_input(void) { return 1; }", 40)
        dispatcher = _function(
            "dispatch",
            """int dispatch(unsigned char *input, int phase) {
  if (phase == 2) {
    internal_tick();
  }
  if (input[0] == 1) {
    handle_input();
  }
  return 0;
}""",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (dispatcher, internal, external)},
            edges=[],
        ))

        syntax = extract_operation_seeds([dispatcher], graph)
        linked = extract_operation_seeds([dispatcher], graph, input_symbols={"input"})

        self.assertEqual(len(syntax), 2)
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0].handler_function_ids, [external.function_id])
        self.assertEqual(
            extract_operation_seeds([dispatcher], graph, input_symbols=set()),
            [],
        )

    def test_same_line_internal_if_does_not_absorb_input_branch(self) -> None:
        internal = _function("internal_tick", "int internal_tick(void) { return 1; }", 30)
        external = _function("handle_input", "int handle_input(void) { return 1; }", 40)
        dispatcher = _function(
            "dispatch",
            "int dispatch(unsigned char *input, int phase) { "
            "if (phase == 2) { internal_tick(); } "
            "if (input[0] == 1) { handle_input(); } return 0; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (dispatcher, internal, external)},
            edges=[],
        ))

        seeds = extract_operation_seeds([dispatcher], graph, input_symbols={"input"})

        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0].handler_function_ids, [external.function_id])

    def test_line_less_points_to_targets_are_not_attached_to_every_branch(self) -> None:
        handler = _function(
            "callback_handler", "int callback_handler(void) { return 1; }", 30
        )
        dispatcher = _function(
            "dispatch",
            """int dispatch(int opcode, int (*callback)(void)) {
  switch (opcode) {
    case 1: return callback();
    default: return 0;
  }
}""",
            1,
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                dispatcher.function_id: dispatcher,
                handler.function_id: handler,
            },
            edges=[CallEdge(
                edge_id="svf-whole-function", caller_id=dispatcher.function_id,
                callee_id=handler.function_id, line=None,
                kind="indirect_possible", confidence=0.5,
            )],
        ))

        seed = next(
            item for item in extract_operation_seeds([dispatcher], graph)
            if item.discriminator == "1"
        )

        self.assertEqual(seed.handler_function_ids, [])
        self.assertIn("callback", seed.unresolved_call_names)

    async def test_unresolved_operation_seeds_become_parallel_work_items(self) -> None:
        entry_function = _function("read_request", "int read_request(void) { return 0; }")
        dispatcher = _function("dispatch", "int dispatch(void) { return 0; }", 10)
        first = _function("first_handler", "int first_handler(void) { return 0; }", 20)
        second = _function("second_handler", "int second_handler(void) { return 0; }", 30)
        graph = GraphStore(AnalysisBundle(
            functions={
                item.function_id: item
                for item in (entry_function, dispatcher, first, second)
            },
            edges=[],
        ))
        entry = EntryRecord(
            entry_id="entry-a",
            candidate_id="candidate-a",
            status=Verdict.VERIFIED,
            entry_function_id=entry_function.function_id,
            source_api="read",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{
                "function_id": entry_function.function_id,
                "relation": "external bytes",
            }],
            consumer_hints=[],
            evidence=[Evidence(
                "source", entry_function.function_id, entry_function.file,
                entry_function.start_line, "external bytes",
            )],
            unknowns=[],
            verifier_confidence=0.95,
            first_acquisition_confirmed=True,
        )
        seeds = [
            OperationSeed(
                "op-a", dispatcher.function_id, "A", 11,
                [first.function_id],
            ),
            # An alias of A must share the same focused handler work item.
            OperationSeed(
                "op-a-alias", dispatcher.function_id, "A_ALIAS", 12,
                [first.function_id],
            ),
            OperationSeed(
                "op-b", dispatcher.function_id, "B", 13,
                [second.function_id],
            ),
        ]

        class RecordingAgent(SmallFeatureAgent):
            def __init__(self) -> None:
                super().__init__(ScriptedLLM([]), graph)
                self.focused: list[list[str]] = []

            async def _discover_from_entry(  # type: ignore[override]
                self, seed_entry, all_entries, *, harness_feedback,
                excluded_anchors, focused_operation_seeds=None,
            ):
                focused = list(focused_operation_seeds or [])
                if not focused:
                    return _DiscoveryResult(
                        seed_entry.entry_id, [], {}, list(seeds)
                    )
                self.focused.append([
                    item.operation_seed_id for item in focused
                ])
                return _DiscoveryResult(
                    seed_entry.entry_id,
                    [],
                    {},
                    [
                        OperationSeed(
                            item.operation_seed_id,
                            item.dispatcher_function_id,
                            item.discriminator,
                            item.line,
                            item.handler_function_ids,
                            status=ProofStatus.REFUTED,
                        )
                        for item in focused
                    ],
                )

        agent = RecordingAgent()
        await agent.run([entry])

        self.assertEqual(len(agent.focused), 2)
        self.assertIn(["op-a", "op-a-alias"], agent.focused)
        self.assertIn(["op-b"], agent.focused)
        self.assertTrue(all(
            item.status is ProofStatus.REFUTED
            for item in agent.last_operation_seeds
        ))

    async def test_nested_dispatcher_seeds_are_scheduled_in_later_waves(self) -> None:
        entry_function = _function(
            "read_request", "int read_request(void) { return 0; }"
        )
        outer = _function("outer_dispatch", "int outer_dispatch(void) { return 0; }", 10)
        inner = _function("inner_dispatch", "int inner_dispatch(void) { return 0; }", 20)
        leaf = _function("leaf_handler", "int leaf_handler(void) { return 0; }", 30)
        graph = GraphStore(AnalysisBundle(
            functions={
                item.function_id: item
                for item in (entry_function, outer, inner, leaf)
            },
            edges=[],
        ))
        entry = EntryRecord(
            entry_id="entry-nested",
            candidate_id="candidate-nested",
            status=Verdict.VERIFIED,
            entry_function_id=entry_function.function_id,
            source_api="read",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{
                "function_id": entry_function.function_id,
                "relation": "external bytes",
            }],
            consumer_hints=[],
            evidence=[Evidence(
                "source", entry_function.function_id, entry_function.file,
                entry_function.start_line, "external bytes",
            )],
            unknowns=[],
            verifier_confidence=0.95,
            first_acquisition_confirmed=True,
        )
        outer_seed = OperationSeed(
            "outer-seed", outer.function_id, "OUTER", 11,
            [inner.function_id],
        )
        inner_seed = OperationSeed(
            "inner-seed", inner.function_id, "INNER", 21,
            [leaf.function_id],
        )

        class NestedRecordingAgent(SmallFeatureAgent):
            def __init__(self) -> None:
                super().__init__(ScriptedLLM([]), graph)
                self.focused: list[list[str]] = []

            async def _discover_from_entry(  # type: ignore[override]
                self, seed_entry, all_entries, *, harness_feedback,
                excluded_anchors, focused_operation_seeds=None,
            ):
                focused = list(focused_operation_seeds or [])
                if not focused:
                    return _DiscoveryResult(
                        seed_entry.entry_id, [], {}, [outer_seed]
                    )
                ids = [item.operation_seed_id for item in focused]
                self.focused.append(ids)
                if ids == ["outer-seed"]:
                    return _DiscoveryResult(
                        seed_entry.entry_id,
                        [],
                        {},
                        [
                            OperationSeed(
                                outer_seed.operation_seed_id,
                                outer_seed.dispatcher_function_id,
                                outer_seed.discriminator,
                                outer_seed.line,
                                outer_seed.handler_function_ids,
                                status=ProofStatus.PROVEN_STATIC,
                            ),
                            inner_seed,
                        ],
                    )
                return _DiscoveryResult(
                    seed_entry.entry_id,
                    [],
                    {},
                    [OperationSeed(
                        inner_seed.operation_seed_id,
                        inner_seed.dispatcher_function_id,
                        inner_seed.discriminator,
                        inner_seed.line,
                        inner_seed.handler_function_ids,
                        status=ProofStatus.PROVEN_STATIC,
                    )],
                )

        agent = NestedRecordingAgent()
        await agent.run([entry])

        self.assertEqual(agent.focused, [["outer-seed"], ["inner-seed"]])
        self.assertEqual(
            {item.operation_seed_id: item.status for item in agent.last_operation_seeds},
            {
                "outer-seed": ProofStatus.PROVEN_STATIC,
                "inner-seed": ProofStatus.PROVEN_STATIC,
            },
        )

    async def test_large_feature_can_link_operations_from_different_entries(self) -> None:
        store = _function("store_item", "int store_item(void) { return 1; }", 30)
        lookup = _function("lookup_item", "int lookup_item(void) { return 1; }", 40)
        producer = assess_small_feature(_feature(
            "sf-store", "entry-write", store, produces=["stored item exists"]
        ))
        consumer = assess_small_feature(_feature(
            "sf-get-hit", "entry-read", lookup, consumes=["stored item exists"]
        ))
        provider = ScriptedLLM([
            {"large_features": [{
                "name": "store then lookup",
                "description": "exercise the successful lookup state",
                "small_feature_ids": [
                    producer.small_feature_id, consumer.small_feature_id,
                ],
                "common_anchor": producer.harness_anchor,
                "common_initialization": [],
                "common_cleanup": [],
                "prerequisite_state": [],
                "isolation_mode": "in_process_reset",
                "isolation_rationale": "same fixture",
                "dispatch_strategy": "selector_byte",
                "variants": [],
                "required_functions": [
                    producer.harness_anchor, consumer.harness_anchor,
                ],
                "dependencies": [{
                    "producer_small_feature_id": producer.small_feature_id,
                    "consumer_small_feature_id": consumer.small_feature_id,
                    "relation": "STATE",
                    "condition": "stored item must exist before successful lookup",
                    "evidence": [
                        {
                            "kind": "operation",
                            "function_id": store.function_id,
                            "file": store.file,
                            "line": store.start_line,
                            "detail": "store creates the item",
                        },
                        {
                            "kind": "operation",
                            "function_id": lookup.function_id,
                            "file": lookup.file,
                            "line": lookup.start_line,
                            "detail": "lookup consumes existing item state",
                        },
                    ],
                }],
            }]},
            {"subjects": [], "feature_subjects": []},
        ])

        result = await LargeFeatureAgent(provider).run([producer, consumer])

        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(len(result), 1)
        self.assertEqual(
            set(result[0].small_feature_ids), {"sf-store", "sf-get-hit"}
        )
        self.assertTrue(result[0].dependencies)

    def test_p2_protocol_rejects_unopened_function(self) -> None:
        operation = _function("operate", "int operate(void) { return 0; }", 10)
        unopened = _function("unopened", "int unopened(void) { return 0; }", 20)
        feature = _feature("sf-operation", "entry-a", operation)

        accepted, errors = _validated_operation_protocols([{
            "small_feature_id": feature.small_feature_id,
            "ordered_function_ids": [operation.function_id, unopened.function_id],
            "input_delivery_function_id": operation.function_id,
            "completion_function_id": unopened.function_id,
            "evidence": [{
                "function_id": operation.function_id,
                "line": operation.start_line,
                "detail": "input delivery",
            }],
            "rationale": "invalid unopened target",
        }], [feature], [operation])

        self.assertEqual(accepted, [])
        self.assertTrue(any("unopened function" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
