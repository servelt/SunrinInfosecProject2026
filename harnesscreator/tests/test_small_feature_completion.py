"""Regression coverage for completion and bounded empty responses."""
import unittest

from harnesscreator.agents.small_feature import SmallFeatureAgent
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle, CallEdge, EntryRecord, FunctionMetadata, Verdict,
)


class SmallFeatureCompletionTest(unittest.IsolatedAsyncioTestCase):
    def fixture(self):
        function = FunctionMetadata.create(
            name="main", signature="int main(int argc, char **argv)",
            file="main.c", start_line=1, end_line=1,
            source="int main(int argc, char **argv) { return argc; }",
        )
        graph = GraphStore(AnalysisBundle({function.function_id: function}, []))
        entry = EntryRecord(
            entry_id="entry-argv", candidate_id="candidate-argv",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="argv", channel_kind="argv", attacker_control="unknown",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=1.0, first_acquisition_confirmed=True,
        )
        return graph, entry

    async def test_empty_completion_finishes_without_secondary_audit(self):
        graph, entry = self.fixture()
        provider = ScriptedLLM([{
            "small_features": [], "unrelated_entries": [],
            "context_complete": True, "requested_function_ids": [],
            "entry_resolutions": [],
        }])
        events = []
        agent = SmallFeatureAgent(provider, graph, trace=lambda *event: events.append(event))
        self.assertEqual(await agent.run([entry]), [])
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(agent.last_final_entries, [entry])
        self.assertTrue(any(event[1] == "entry_enumerated" for event in events))

    async def test_empty_unresolved_responses_stop_instead_of_consuming_all_turns(self):
        graph, entry = self.fixture()
        provider = ScriptedLLM([{
            "small_features": [], "unrelated_entries": [],
            "context_complete": False, "requested_function_ids": [],
            "entry_resolutions": [],
        } for _ in range(4)])
        agent = SmallFeatureAgent(provider, graph, max_turns=64)
        self.assertEqual(await agent.run([entry]), [])
        self.assertEqual(len(provider.calls), 4)
        self.assertEqual(len({call["session_key"] for call in provider.calls}), 1)

    async def test_feature_draft_does_not_implicitly_open_every_named_function(self):
        graph, entry = self.fixture()
        helper = FunctionMetadata.create(
            name="helper", signature="void helper(void)", file="main.c",
            start_line=3, end_line=3, source="void helper(void) {}",
        )
        root = graph.bundle.functions[entry.entry_function_id]
        graph = GraphStore(AnalysisBundle(
            {root.function_id: root, helper.function_id: helper},
            [CallEdge("edge-main-helper", root.function_id, helper.function_id)],
        ))
        provider = ScriptedLLM([{
            "small_features": [{
                "harness_anchor": helper.function_id,
                "required_functions": [helper.function_id],
                "actions": [{"function_id": helper.function_id}],
            }],
            "unrelated_entries": [], "context_complete": True,
            "requested_function_ids": [], "entry_resolutions": [],
        }])
        agent = SmallFeatureAgent(provider, graph)
        self.assertEqual(await agent.run([entry]), [])
        self.assertEqual(len(provider.calls), 1)

    async def test_small_feature_starts_with_only_the_entry_source(self):
        graph, entry = self.fixture()
        helper = FunctionMetadata.create(
            name="old_verifier_context", signature="void old_verifier_context(void)",
            file="main.c", start_line=3, end_line=3,
            source="void old_verifier_context(void) {}",
        )
        root = graph.bundle.functions[entry.entry_function_id]
        entry.inspected_function_ids = [root.function_id, helper.function_id]
        graph = GraphStore(AnalysisBundle(
            {root.function_id: root, helper.function_id: helper},
            [CallEdge("edge-main-old", root.function_id, helper.function_id)],
        ))
        provider = ScriptedLLM([{
            "small_features": [], "unrelated_entries": [],
            "context_complete": True, "requested_function_ids": [],
            "entry_resolutions": [],
        }])

        await SmallFeatureAgent(provider, graph).run([entry])

        payload = provider.calls[0]["payload"]
        self.assertEqual(
            [item["function_id"] for item in payload["context"]],
            [root.function_id],
        )
        self.assertIn(
            helper.function_id,
            [item["function_id"] for item in payload["previously_inspected_entry_functions"]],
        )
