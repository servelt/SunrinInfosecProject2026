"""Action source navigation can browse the graph and resume long walks."""

import unittest

from harnesscreator.agents.scenario import InputActionAgent, SEMANTIC_INPUT_ACTION_SCHEMA
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.declarations import SourceDeclaration
from harnesscreator.llm.base import ScriptedLLM, validate_strict_output_schema
from harnesscreator.models import AnalysisBundle, CallEdge, EntryRecord, FunctionMetadata, Verdict


def function(name: str, line: int) -> FunctionMetadata:
    return FunctionMetadata.create(
        name=name, signature=f"int {name}(void)", file="target.c",
        start_line=line, end_line=line,
        source=f"int {name}(void) {{ return 0; }}",
    )


def answer(*, focus: str = "", jump: str = "", request: str = "") -> dict:
    return {
        "actions": [], "context_complete": not (focus or jump or request),
        "requested_function_ids": [request] if request else [],
        "tree_focus_function_id": focus,
        "jump_target_function_id": jump,
        "rationale": "inspect graph navigation",
    }


def entry(root: FunctionMetadata) -> EntryRecord:
    return EntryRecord(
        entry_id="entry-tree", candidate_id="candidate-tree",
        status=Verdict.VERIFIED, entry_function_id=root.function_id,
        source_api="read", channel_kind="stdin", attacker_control="full",
        provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
        verifier_confidence=0.9, entry_line=root.start_line,
        first_acquisition_confirmed=True,
    )


class ActionTreeNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_action_agent_lists_and_opens_declaration_without_tree_edge(self) -> None:
        root = function("receive", 1)
        graph = GraphStore(AnalysisBundle(
            functions={root.function_id: root}, edges=[],
            declarations=[SourceDeclaration(
                "WIRE_MAGIC", "macro", "wire.h", 7, 7,
                "#define WIRE_MAGIC 0x80")],
        ))
        llm = ScriptedLLM([
            {**answer(), "context_complete": False,
             "list_declarations": True, "declaration_name_filter": "WIRE"},
            {**answer(), "context_complete": False,
             "requested_declaration_name": "WIRE_MAGIC"},
            answer(),
        ])

        await InputActionAgent(llm, graph).run([entry(root)])

        self.assertEqual(len(llm.calls), 3)
        catalog = llm.calls[1]["payload"]["current_source_artifact"]
        self.assertEqual([item["name"] for item in catalog["names"]], ["WIRE_MAGIC"])
        definition = llm.calls[2]["payload"]["current_source_artifact"]
        self.assertEqual(definition["source_excerpt"], "#define WIRE_MAGIC 0x80")
        self.assertEqual(definition["file"], "wire.h")

    async def test_action_without_request_bytes_survives_discovery(self) -> None:
        root, handler = function("receive", 1), function("store", 2)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (root, handler)},
            edges=[CallEdge(edge_id="store", caller_id=root.function_id,
                            callee_id=handler.function_id, line=1, kind="direct")],
        ))
        citations = [{
            "kind": "source", "function_id": item.function_id,
            "line": item.start_line, "detail": "source selection/effect",
        } for item in (root, handler)]
        action = {
            "name": "symbolic store", "description": "store selected by CMD_STORE",
            "dispatcher_function_id": root.function_id,
            "handler_function_id": handler.function_id,
            "discriminator": "CMD_STORE", "fields": [], "examples": [],
            "success_markers_hex": [], "failure_markers_hex": [],
            "success_evidence": [citations[1]], "failure_evidence": [],
            "response_bindings": [], "evidence": citations,
            "unknowns": ["numeric opcode unresolved"], "confidence": 0.7,
            "action_context_complete": True,
        }
        llm = ScriptedLLM([
            answer(jump=handler.function_id),
            {**answer(), "actions": [action]},
        ])

        actions = await InputActionAgent(llm, graph).run([entry(root)])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].name, "symbolic store")
        self.assertEqual(actions[0].examples, [])
        self.assertIn("leave examples empty when unknown", llm.calls[0]["instructions"])

    async def test_browse_previously_opened_dispatcher_after_leaving_its_branch(self) -> None:
        root, dispatcher, get_handler, suffix, set_handler = (
            function("receive", 1), function("dispatch", 2),
            function("get_handler", 3), function("get_suffix", 4),
            function("set_handler", 5),
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (
                root, dispatcher, get_handler, suffix, set_handler,
            )},
            edges=[
                CallEdge(edge_id="a", caller_id=root.function_id,
                         callee_id=dispatcher.function_id, line=1, kind="direct"),
                CallEdge(edge_id="b", caller_id=dispatcher.function_id,
                         callee_id=get_handler.function_id, line=2, kind="direct"),
                CallEdge(edge_id="c", caller_id=get_handler.function_id,
                         callee_id=suffix.function_id, line=3, kind="direct"),
                CallEdge(edge_id="d", caller_id=dispatcher.function_id,
                         callee_id=set_handler.function_id, line=2, kind="direct"),
            ],
        ))
        llm = ScriptedLLM([
            answer(jump=dispatcher.function_id),
            answer(jump=get_handler.function_id),
            answer(jump=suffix.function_id),
            answer(focus=dispatcher.function_id),
            answer(jump=set_handler.function_id),
            answer(),
        ])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(root)])

        self.assertEqual(len(llm.calls), 6)
        tree = llm.calls[4]["payload"]["navigation_tree"]
        self.assertEqual(tree["focus"]["function_id"], dispatcher.function_id)
        self.assertIn(set_handler.function_id,
                      {item["function_id"] for item in tree["children"]})
        self.assertFalse(any("not a visible or previously opened" in item
                             for item in agent.inventory_obligations))

    async def test_navigation_does_not_revoke_an_omitted_prior_action(self) -> None:
        root, touch, delete = (
            function("receive", 1), function("touch", 2), function("delete", 3),
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (root, touch, delete)},
            edges=[
                CallEdge(edge_id="touch", caller_id=root.function_id,
                         callee_id=touch.function_id, line=1, kind="direct"),
                CallEdge(edge_id="delete", caller_id=root.function_id,
                         callee_id=delete.function_id, line=1, kind="direct"),
            ],
        ))
        citation = {
            "kind": "source", "function_id": touch.function_id,
            "line": touch.start_line, "detail": "selected handler",
        }
        touch_action = {
            "name": "touch", "description": "touch selected by input",
            "dispatcher_function_id": root.function_id,
            "handler_function_id": touch.function_id,
            "discriminator": "touch", "fields": [], "examples": [],
            "success_markers_hex": [], "failure_markers_hex": [],
            "success_evidence": [citation], "failure_evidence": [],
            "response_bindings": [], "evidence": [citation],
            "unknowns": [], "confidence": 0.7,
            "action_context_complete": True,
        }
        llm = ScriptedLLM([
            answer(jump=touch.function_id),
            {**answer(focus=root.function_id), "actions": [touch_action]},
            answer(jump=delete.function_id),
            answer(),
        ])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(root)])

        self.assertEqual(
            [call["payload"]["current_function"]["name"] for call in llm.calls],
            ["receive", "touch", "touch", "delete"],
        )
        self.assertFalse(any(call["payload"].get("review_only")
                             for call in llm.calls))

    async def test_incomplete_context_without_next_target_is_recorded(self) -> None:
        root = function("receive", 1)
        graph = GraphStore(AnalysisBundle(
            functions={root.function_id: root}, edges=[],
        ))
        llm = ScriptedLLM([{**answer(), "context_complete": False}])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(root)])

        self.assertTrue(any(
            "Action source walk is incomplete" in item
            and "no next function was requested" in item
            for item in agent.inventory_obligations
        ))
        self.assertEqual(len(llm.calls), 1)

    async def test_expand_tree_then_jump_and_continue_at_target(self) -> None:
        root, middle, target = (function("receive", 1), function("parse", 2),
                                function("effect", 3))
        edges = [
            CallEdge(edge_id="a", caller_id=root.function_id,
                     callee_id=middle.function_id, line=1, kind="direct"),
            CallEdge(edge_id="b", caller_id=middle.function_id,
                     callee_id=target.function_id, line=2, kind="direct"),
        ]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (root, middle, target)},
            edges=edges,
        ))
        llm = ScriptedLLM([
            answer(focus=middle.function_id),
            answer(jump=target.function_id),
            answer(),
        ])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(root)])

        self.assertEqual(
            [call["payload"]["current_function"]["name"] for call in llm.calls],
            ["receive", "receive", "effect"],
        )
        self.assertEqual(
            llm.calls[1]["payload"]["navigation_tree"]["focus"]["function_id"],
            middle.function_id,
        )
        self.assertIn(target.function_id, {
            child["function_id"] for child in
            llm.calls[1]["payload"]["navigation_tree"]["children"]
        })
        self.assertEqual(llm.calls[2]["payload"]["navigation_tree"]["jumps_used"], 1)
        self.assertEqual(agent.continuations[0]["jump_history"], [{
            "from_function_id": root.function_id,
            "to_function_id": target.function_id,
        }])

    async def test_fifth_jump_reaches_target(self) -> None:
        functions = [function(f"step_{i}", i + 1) for i in range(6)]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in functions}, edges=[],
        ))
        llm = ScriptedLLM([
            *(answer(jump=functions[i + 1].function_id) for i in range(5)),
            answer(),
        ])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(functions[0])])

        self.assertEqual(len(llm.calls), 6)
        self.assertEqual(llm.calls[-1]["payload"]["current_function"]["name"],
                         functions[5].name)
        self.assertEqual(len(agent.continuations[0]["jump_history"]), 5)
        self.assertFalse(any("jump limit" in item
                             for item in agent.inventory_obligations))

    async def test_direct_caller_is_a_normal_step(self) -> None:
        root, caller = function("read_one", 1), function("serve", 2)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (root, caller)},
            edges=[CallEdge(edge_id="caller", caller_id=caller.function_id,
                            callee_id=root.function_id, line=2, kind="direct")],
        ))
        llm = ScriptedLLM([answer(request=caller.function_id), answer()])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(root)])

        self.assertEqual([call["payload"]["current_function"]["name"]
                          for call in llm.calls], ["read_one", "serve"])
        self.assertEqual(agent.continuations[0]["jump_history"], [])

    async def test_unrelated_normal_request_is_recorded_as_jump(self) -> None:
        root, target = function("read_one", 1), function("other", 2)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (root, target)},
            edges=[],
        ))
        llm = ScriptedLLM([answer(request=target.function_id), answer()])
        agent = InputActionAgent(llm, graph)

        await agent.run([entry(root)])

        self.assertEqual(llm.calls[1]["payload"]["navigation_tree"]["jumps_used"], 1)
        self.assertEqual(len(agent.continuations[0]["jump_history"]), 1)

    async def test_resume_can_continue_after_four_jumps(self) -> None:
        functions = [function(f"resume_{i}", i + 1) for i in range(6)]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in functions}, edges=[],
        ))
        first_llm = ScriptedLLM([
            answer(jump=functions[i + 1].function_id) for i in range(5)
        ])
        first = InputActionAgent(first_llm, graph, budget=5)
        await first.run([entry(functions[0])])
        second_llm = ScriptedLLM([answer(), answer()])
        resumed = InputActionAgent(
            second_llm, graph, resume_continuations=first.continuations,
        )

        await resumed.run([entry(functions[0])])

        self.assertEqual(len(first.continuations[0]["jump_history"]), 4)
        self.assertEqual(first.continuations[0]["next_function_ids"],
                         [functions[5].function_id])
        self.assertEqual(len(resumed.continuations[0]["jump_history"]), 5)
        self.assertIn(functions[5].function_id,
                      resumed.continuations[0]["opened_function_ids"])
        self.assertFalse(any("jump limit" in item
                             for item in resumed.inventory_obligations))

    def test_schema_accepts_tree_navigation_fields(self) -> None:
        validate_strict_output_schema(SEMANTIC_INPUT_ACTION_SCHEMA)


if __name__ == "__main__":
    unittest.main()
