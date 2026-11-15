"""Source-supported Action selection happens before planning or fuzzing."""
import unittest
import tempfile
from dataclasses import replace
from pathlib import Path

from harnesscreator.agents.action_selection import (
    ACTION_GROUP_SCHEMA, ACTION_SELECTION_SCHEMA, ActionGroupDecision,
    ActionSelectionDecision,
    ActionSelectionAgent, build_action_effect_families,
    validate_action_groups,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.llm.base import (
    InvalidOutputSchemaError, ScriptedLLM, validate_strict_output_schema,
)
from harnesscreator.models import (
    ActionActor, ActionStateContract, AnalysisBundle, ExternalActionSchema,
    FunctionMetadata, ProofStatus, ScenarioStatus, ScenarioWitness,
    StateDependencyGraph, StateRequirement, Evidence,
)
from harnesscreator.storage import ArtifactStore


def fixture():
    functions = [FunctionMetadata.create(
        name=name, signature=f"int {name}(void)", file="server.c",
        start_line=line, end_line=line,
        source=f"int {name}(void) {{ return {line}; }}",
    ) for name, line in (("receive", 1), ("dispatch", 2), ("handle", 3))]
    graph = GraphStore(AnalysisBundle(
        functions={item.function_id: item for item in functions}, edges=[],
    ))
    action = ExternalActionSchema(
        action_id="action-test", entry_id="entry-test", name="write value",
        description="request writes a value",
        dispatcher_function_id=functions[1].function_id,
        handler_function_id=functions[2].function_id, discriminator="write",
        channel_kind="tcp", fields=[], examples=[], success_markers_hex=[],
        failure_markers_hex=[], evidence=[], inspected_function_ids=[],
        entry_function_id=functions[0].function_id,
    )
    return graph, functions, action


def citation(function):
    return {"kind": "source", "function_id": function.function_id,
            "line": function.start_line, "detail": "exact source line"}


class ActionSelectionTests(unittest.IsolatedAsyncioTestCase):
    def test_effect_location_groups_different_names_for_review_without_merging(self):
        graph, functions, action = fixture()
        site = Evidence("source", functions[2].function_id, functions[2].file,
                        functions[2].start_line, "same handler effect")
        first = replace(action, actor=ActionActor.INBOUND_CLIENT,
                        effect_evidence=[site])
        second = replace(first, action_id="action-alias", entry_id="entry-other",
                         name="different model name")
        agent = ActionSelectionAgent(ScriptedLLM([]), graph)
        decisions = agent.run_fast([first, second])
        self.assertEqual(len(agent.last_groups), 1)
        self.assertEqual(agent.last_groups[0].relation, "UNRESOLVED")
        self.assertEqual([item.disposition for item in decisions], ["KEEP", "KEEP"])

    def test_schema_is_strict(self):
        validate_strict_output_schema(ACTION_SELECTION_SCHEMA)
        validate_strict_output_schema(ACTION_GROUP_SCHEMA)

    def test_fast_selection_preserves_unreviewed_peers_without_model_calls(self):
        graph, _functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp",
                         channel_kind="udp")
        llm = ScriptedLLM([])
        agent = ActionSelectionAgent(llm, graph)
        decisions = agent.run_fast([first, second])
        self.assertEqual([item.disposition for item in decisions], ["KEEP", "KEEP"])
        self.assertEqual(agent.last_groups[0].relation, "UNRESOLVED")
        self.assertEqual(llm.calls, [])

    def test_fast_selection_reuses_only_matching_prior_effect_group(self):
        graph, _functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp")
        previous = ActionGroupDecision(
            "old", [first.action_id, second.action_id],
            "SAME_SOURCE_EFFECT", "KEEP", "source reviewed", [],
        )
        old_decisions = [
            ActionSelectionDecision(item.action_id, "KEEP", "source reviewed", [])
            for item in (first, second)
        ]
        agent = ActionSelectionAgent(ScriptedLLM([]), graph)
        agent.run_fast([first, second], prior_groups=[previous],
                       prior_decisions=old_decisions)
        self.assertEqual(agent.last_groups[0].relation, "SAME_SOURCE_EFFECT")
        agent.run_fast([first, replace(second, action_id="new")],
                       prior_groups=[previous], prior_decisions=old_decisions)
        self.assertEqual(agent.last_groups[0].relation, "UNRESOLVED")

    async def test_shared_effect_reviews_two_routes_once_and_keeps_both(self):
        graph, functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(
            first, action_id="action-udp", entry_id="entry-udp",
            channel_kind="udp",
            discriminator="UDP write request reaches the same handler",
        )
        llm = ScriptedLLM([{
            "relation": "SAME_SOURCE_EFFECT", "decision": "KEEP",
            "requested_function_id": "",
            "reason": "Both routes select the same write effect and response semantics",
            "source_evidence": [citation(item) for item in functions],
            "individual_decisions": [],
        }])
        agent = ActionSelectionAgent(llm, graph)
        decisions = await agent.run([first, second])
        self.assertEqual([item.action_id for item in decisions],
                         [first.action_id, second.action_id])
        self.assertEqual([item.disposition for item in decisions],
                         ["KEEP", "KEEP"])
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(agent.last_groups[0].relation, "SAME_SOURCE_EFFECT")
        self.assertEqual(agent.last_groups[0].action_ids,
                         [first.action_id, second.action_id])

    async def test_group_opens_missing_parser_before_deciding(self):
        graph, functions, action = fixture()
        parser = FunctionMetadata.create(
            name="parse_request", signature="int parse_request(void)",
            file="server.c", start_line=4, end_line=4,
            source="int parse_request(void) { return 4; }",
        )
        graph.bundle.functions[parser.function_id] = parser
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp")
        llm = ScriptedLLM([{
            "relation": "UNRESOLVED", "decision": "UNRESOLVED",
            "reason": "need parser", "source_evidence": [],
            "individual_decisions": [],
            "requested_function_id": parser.function_id,
        }, {
            "relation": "SAME_SOURCE_EFFECT", "decision": "KEEP",
            "reason": "parser confirms equal effect",
            "source_evidence": [citation(item) for item in [*functions, parser]],
            "individual_decisions": [], "requested_function_id": "",
        }])
        agent = ActionSelectionAgent(llm, graph)
        await agent.run([first, second])
        self.assertEqual(agent.last_groups[0].relation, "SAME_SOURCE_EFFECT")
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(len(llm.calls[1]["payload"]["source_functions"]), 4)

    async def test_unproven_equivalence_preserves_individual_decisions(self):
        graph, functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp",
                         channel_kind="udp")
        llm = ScriptedLLM([{
            "relation": "UNRESOLVED", "decision": "UNRESOLVED",
            "requested_function_id": "",
            "reason": "The two input paths are not proven equivalent",
            "source_evidence": [citation(functions[2])],
            "individual_decisions": [
                {"action_id": first.action_id, "decision": "KEEP",
                 "reason": "writes data", "source_evidence": [
                     citation(item) for item in functions]},
                {"action_id": second.action_id, "decision": "DROP",
                 "reason": "looks redundant", "source_evidence": [citation(functions[2])]},
            ],
        }])
        agent = ActionSelectionAgent(llm, graph)
        decisions = await agent.run([first, second])
        self.assertEqual([item.disposition for item in decisions],
                         ["KEEP", "UNRESOLVED"])
        self.assertEqual(agent.last_groups[0].relation, "UNRESOLVED")
        self.assertEqual(len(llm.calls), 1)

    async def test_shared_effect_requires_every_route_anchor(self):
        graph, functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp",
                         channel_kind="udp")
        llm = ScriptedLLM([{
            "relation": "SAME_SOURCE_EFFECT", "decision": "DROP",
            "requested_function_id": "",
            "reason": "model claims same effect",
            "source_evidence": [citation(functions[2])],
            "individual_decisions": [],
        }])
        agent = ActionSelectionAgent(llm, graph)
        decisions = await agent.run([first, second])
        self.assertEqual([item.disposition for item in decisions],
                         ["UNRESOLVED", "UNRESOLVED"])
        self.assertEqual(agent.last_groups[0].relation, "UNRESOLVED")

    async def test_group_wide_drop_never_discards_both_routes(self):
        graph, functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp")
        llm = ScriptedLLM([{
            "relation": "SAME_SOURCE_EFFECT", "decision": "DROP",
            "requested_function_id": "",
            "reason": "model judges the shared effect uninteresting",
            "source_evidence": [citation(item) for item in functions],
            "individual_decisions": [],
        }])
        decisions = await ActionSelectionAgent(llm, graph).run([first, second])
        self.assertEqual([item.disposition for item in decisions],
                         ["UNRESOLVED", "UNRESOLVED"])

    async def test_same_name_with_different_handler_is_not_grouped(self):
        graph, functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-other",
                         handler_function_id=functions[1].function_id)
        llm = ScriptedLLM([{
            "decision": "KEEP", "reason": "input affects behavior",
            "source_evidence": [citation(item) for item in functions],
        }] * 2)
        agent = ActionSelectionAgent(llm, graph)
        decisions = await agent.run([first, second])
        self.assertEqual(len(agent.last_groups), 2)
        self.assertEqual([item.disposition for item in decisions],
                         ["KEEP", "KEEP"])

    async def test_backend_peer_and_client_do_not_share_a_group(self):
        graph, _functions, action = fixture()
        client = replace(action, actor=ActionActor.INBOUND_CLIENT)
        backend = replace(action, action_id="action-backend",
                          entry_id="entry-backend",
                          actor=ActionActor.OUTBOUND_PEER)
        llm = ScriptedLLM([{
            "decision": "KEEP", "reason": "input-driven behavior",
            "source_evidence": [],
        }] * 2)
        agent = ActionSelectionAgent(llm, graph)
        await agent.run([client, backend])
        self.assertEqual(len(agent.last_groups), 2)

    async def test_group_provider_failure_preserves_all_routes(self):
        graph, _functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-udp", entry_id="entry-udp")
        agent = ActionSelectionAgent(ScriptedLLM([]), graph)
        decisions = await agent.run([first, second])
        self.assertEqual([item.disposition for item in decisions],
                         ["UNRESOLVED", "UNRESOLVED"])
        self.assertEqual(agent.last_groups[0].relation, "UNRESOLVED")

    async def test_terminal_provider_failure_does_not_fan_out(self):
        graph, _functions, action = fixture()
        first = replace(action, actor=ActionActor.INBOUND_CLIENT)
        second = replace(first, action_id="action-other", name="other operation")

        class TerminalLLM:
            max_concurrency = 1
            calls = 0

            async def complete_json(self, **_kwargs):
                self.calls += 1
                raise InvalidOutputSchemaError("invalid_json_schema")

            async def close_session(self, _key):
                return None

        llm = TerminalLLM()
        decisions = await ActionSelectionAgent(llm, graph).run([first, second])
        self.assertEqual(llm.calls, 1)
        self.assertEqual([item.disposition for item in decisions],
                         ["UNRESOLVED", "UNRESOLVED"])

    def test_group_validation_requires_matching_state_and_each_runtime_route(self):
        _graph, _functions, action = fixture()
        other = replace(action, action_id="action-udp", entry_id="entry-udp")
        group = ActionGroupDecision(
            "group-1", [action.action_id, other.action_id],
            "SAME_SOURCE_EFFECT", "KEEP", "shared source effect", [],
        )
        contracts = [ActionStateContract(
            item.action_id, [], [StateRequirement("stored-key")], [],
            "request succeeded", [], [], status=ProofStatus.PROVEN_STATIC,
        ) for item in (action, other)]
        witnesses = [ScenarioWitness(
            f"w-{item.action_id}", f"s-{item.action_id}", item.action_id,
            [], [], [], "tcp", None, ScenarioStatus.PROVEN_RUNTIME, "ok",
        ) for item in (action, other)]
        graph = StateDependencyGraph(contracts, [], [])
        checked = validate_action_groups([group], [action, other], graph,
                                         witnesses)
        self.assertEqual(checked[0].status, "ROUTES_SUPPORTED")
        self.assertEqual(validate_action_groups(
            [group], [action, other], graph, witnesses[:1],
        )[0].status, "RUNTIME_UNRESOLVED")
        contracts[1].produces = [StateRequirement("different-key")]
        self.assertEqual(validate_action_groups(
            [group], [action, other], graph, witnesses,
        )[0].status, "STATE_MISMATCH")

    def test_effect_families_share_proven_effect_but_keep_each_route(self):
        _graph, _functions, action = fixture()
        tcp = replace(action, actor=ActionActor.INBOUND_CLIENT)
        udp = replace(tcp, action_id="action-udp", entry_id="entry-udp",
                      channel_kind="udp")
        other = replace(tcp, action_id="action-other", name="other")
        groups = [
            ActionGroupDecision("shared", [tcp.action_id, udp.action_id],
                                "SAME_SOURCE_EFFECT", "KEEP", "same", []),
            ActionGroupDecision("unresolved", [other.action_id],
                                "UNRESOLVED", "UNRESOLVED", "unknown", []),
        ]
        families, routes = build_action_effect_families(
            groups, [tcp, udp, other],
        )
        self.assertEqual(len(families), 2)
        self.assertEqual(families[0].action_ids,
                         [tcp.action_id, udp.action_id])
        self.assertEqual(len(routes), 3)
        self.assertEqual(routes[0].effect_id, routes[1].effect_id)
        self.assertNotEqual(routes[0].route_id, routes[1].route_id)
        self.assertNotEqual(routes[0].effect_id, routes[2].effect_id)

    def test_unresolved_pair_never_becomes_one_effect(self):
        _graph, _functions, action = fixture()
        other = replace(action, action_id="action-other", entry_id="other")
        group = ActionGroupDecision("maybe", [action.action_id, other.action_id],
                                    "UNRESOLVED", "UNRESOLVED", "unknown", [])
        families, routes = build_action_effect_families([group], [action, other])
        self.assertEqual(len(families), 2)
        self.assertEqual(len(routes), 2)

    async def test_exampleless_action_is_reviewed_and_can_be_kept(self):
        graph, functions, action = fixture()
        llm = ScriptedLLM([{
            "decision": "KEEP", "reason": "input affects stored data",
            "source_evidence": [citation(item) for item in functions],
        }])
        decision = (await ActionSelectionAgent(llm, graph).run([action]))[0]
        self.assertEqual(decision.disposition, "KEEP")
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(llm.calls[0]["role"], "input_action")
        self.assertNotIn("fuzz_observations", llm.calls[0]["payload"])

    async def test_drop_requires_both_dispatcher_and_handler_source(self):
        graph, functions, action = fixture()
        llm = ScriptedLLM([{
            "decision": "DROP", "reason": "no distinct input-driven target behavior",
            "source_evidence": [citation(item) for item in functions],
        }])
        decision = (await ActionSelectionAgent(llm, graph).run([action]))[0]
        self.assertEqual(decision.disposition, "DROP")
        self.assertEqual(len(decision.source_evidence), 3)

    async def test_keep_without_input_path_evidence_is_deferred(self):
        graph, functions, action = fixture()
        llm = ScriptedLLM([{
            "decision": "KEEP", "reason": "handler appears interesting",
            "source_evidence": [citation(functions[2])],
        }])
        decision = (await ActionSelectionAgent(llm, graph).run([action]))[0]
        self.assertEqual(decision.disposition, "UNRESOLVED")

    async def test_source_review_checkpoint_reuses_completed_decision(self):
        graph, functions, action = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary))
            first = ActionSelectionAgent(ScriptedLLM([{
                "decision": "KEEP", "reason": "external byte changes stored data",
                "source_evidence": [citation(item) for item in functions],
            }]), graph, checkpoint_store=store)
            self.assertEqual((await first.run([action]))[0].disposition, "KEEP")
            cached_llm = ScriptedLLM([])
            second = ActionSelectionAgent(
                cached_llm, graph, resume_checkpoint_dir=store.root,
            )
            self.assertEqual((await second.run([action]))[0].disposition, "KEEP")
            self.assertEqual(cached_llm.calls, [])

    async def test_unsupported_drop_keeps_action_unresolved(self):
        graph, functions, action = fixture()
        llm = ScriptedLLM([{
            "decision": "DROP", "reason": "looks trivial",
            "source_evidence": [citation(functions[1])],
        }])
        decision = (await ActionSelectionAgent(llm, graph).run([action]))[0]
        self.assertEqual(decision.disposition, "UNRESOLVED")

    async def test_already_refuted_action_does_not_call_model(self):
        graph, _, action = fixture()
        llm = ScriptedLLM([])
        decision = (await ActionSelectionAgent(llm, graph).run([
            replace(action, status=ProofStatus.REFUTED),
        ]))[0]
        self.assertEqual(decision.disposition, "DROP")
        self.assertEqual(llm.calls, [])

    async def test_model_failure_retains_action_as_unresolved(self):
        graph, _, action = fixture()
        decision = (await ActionSelectionAgent(ScriptedLLM([]), graph).run([action]))[0]
        self.assertEqual(decision.disposition, "UNRESOLVED")
