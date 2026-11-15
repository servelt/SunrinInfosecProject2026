"""Selected Actions receive request synthesis before original execution."""
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from harnesscreator.agents.action_requests import ACTION_REQUEST_SCHEMA, ActionRequestAgent
from harnesscreator.analysis.declarations import extract_declarations
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.llm.base import ScriptedLLM, validate_strict_output_schema
from harnesscreator.models import AnalysisBundle, ExternalActionSchema, FunctionMetadata, ProofStatus
from harnesscreator.storage import ArtifactStore


def fixture():
    functions = [FunctionMetadata.create(
        name=name, signature=f"int {name}(void)", file="server.c",
        start_line=line, end_line=line,
        source=f"int {name}(void) {{ return {line}; }}",
    ) for name, line in (("receive", 1), ("dispatch", 2),
                         ("handle", 3), ("parse_field", 4))]
    graph = GraphStore(AnalysisBundle(
        functions={item.function_id: item for item in functions}, edges=[],
    ))
    action = ExternalActionSchema(
        action_id="selected-action", entry_id="entry", name="write value",
        description="input-driven storage", dispatcher_function_id=functions[1].function_id,
        handler_function_id=functions[2].function_id, discriminator="write",
        channel_kind="tcp", fields=[], examples=[], success_markers_hex=[],
        failure_markers_hex=[], evidence=[], inspected_function_ids=[],
        entry_function_id=functions[0].function_id,
    )
    return graph, functions, action


def response(decision, *, request="", declaration="", list_declarations=False,
             declaration_filter="", examples=None, evidence=None):
    return {"decision": decision, "examples": examples or [], "fields": [],
            "requested_function_id": request, "reason": "inspect complete request",
            "requested_declaration_name": declaration,
            "list_declarations": list_declarations,
            "declaration_name_filter": declaration_filter,
            "drop_evidence": evidence or []}


def citation(function):
    return {"kind": "source", "function_id": function.function_id,
            "line": function.start_line, "detail": "request format line"}


class ActionRequestTests(unittest.IsolatedAsyncioTestCase):
    def test_schema_is_strict(self):
        validate_strict_output_schema(ACTION_REQUEST_SCHEMA)

    async def test_lists_and_opens_macro_and_struct_by_name_without_function_edge(self):
        graph, funcs, action = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "wire.h"
            header.write_text(
                '#define NOREPLYSTR "noreply"\n'
                'typedef union { struct { unsigned char opcode; } request; '
                'unsigned char bytes[1]; } packet_header;\n', encoding="utf-8")
            graph.bundle.declarations = extract_declarations(root, [header]).all()
            example = {
                "data_hex": "01", "bindings": [], "rationale": "framed request",
                "origin": "model_input_hypothesis", "evidence": [
                    citation(funcs[0]),
                    {"kind": "source_declaration", "function_id": "wire.h",
                     "line": 2, "detail": "packet header layout"},
                ],
            }
            ready_reply = response("READY", examples=[example])
            ready_reply["fields"] = [{
                "name": "opcode", "offset": 0, "width": 1,
                "encoding": "byte", "binding": "", "relation": "opaque",
                "evidence": [{"kind": "source_declaration",
                              "function_id": "wire.h", "line": 2,
                              "detail": "one-byte opcode field"}],
            }]
            llm = ScriptedLLM([
                response("CONTINUE", list_declarations=True,
                         declaration_filter="packet"),
                response("CONTINUE", declaration="packet_header"),
                response("CONTINUE", declaration="NOREPLYSTR"),
                response("CONTINUE"), response("CONTINUE"),
                ready_reply,
            ])
            resolved, decisions = await ActionRequestAgent(
                llm, graph, source_root=root,
            ).run([action])
            self.assertEqual(decisions[0].disposition, "READY")
            self.assertEqual(len(llm.calls), 6)
            self.assertEqual([item["name"] for item in
                              llm.calls[1]["payload"]["declaration_catalog"]],
                             ["packet_header"])
            self.assertIn("typedef union", llm.calls[2]["payload"]
                          ["opened_declaration"]["source"])
            self.assertIn("#define NOREPLYSTR", llm.calls[3]["payload"]
                          ["opened_declaration"]["source"])
            self.assertTrue(any(item.file == "wire.h"
                                for item in resolved[0].examples[0].evidence))
            self.assertEqual(resolved[0].fields[0].evidence[0].file, "wire.h")

    async def test_completed_request_is_checkpointed_and_reused_only_for_same_source(self):
        graph, funcs, action = fixture()
        example = {
            "data_hex": "41", "bindings": [], "rationale": "complete request",
            "origin": "model_input_hypothesis", "evidence": [citation(funcs[2])],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            progress = []
            first = ScriptedLLM([
                response("CONTINUE"), response("CONTINUE"),
                response("READY", examples=[example]),
            ])
            resolved, decisions = await ActionRequestAgent(
                first, graph, checkpoint_store=ArtifactStore(root),
                progress=lambda decision, done, total, cached: progress.append(
                    (decision.disposition, done, total, cached)),
            ).run([action])
            self.assertEqual(decisions[0].disposition, "READY")
            checkpoints = list((root / "actions/request-checkpoints").glob("*.json"))
            self.assertEqual(len(checkpoints), 1)
            self.assertEqual(progress, [("READY", 1, 1, False)])

            saved = json.loads(checkpoints[0].read_text(encoding="utf-8"))
            saved["schema_version"] = 1
            checkpoints[0].write_text(json.dumps(saved), encoding="utf-8")

            replay = ScriptedLLM([])
            reused, cached_decisions = await ActionRequestAgent(
                replay, graph, resume_checkpoint_dir=root,
                progress=lambda decision, done, total, cached: progress.append(
                    (decision.disposition, done, total, cached)),
            ).run([action])
            self.assertEqual(reused[0].examples, resolved[0].examples)
            self.assertEqual(cached_decisions[0], decisions[0])
            self.assertEqual(replay.calls, [])
            self.assertEqual(progress[-1], ("READY", 1, 1, True))

            different_group = ScriptedLLM([
                response("CONTINUE"), response("CONTINUE"),
                response("UNRESOLVED"),
            ])
            _, group_decisions = await ActionRequestAgent(
                different_group, graph, resume_checkpoint_dir=root,
            ).run([action], shared_effects={action.action_id: {"group_id": "new"}})
            self.assertEqual(group_decisions[0].disposition, "UNRESOLVED")
            self.assertEqual(len(different_group.calls), 3)

            changed = replace(funcs[2], source=funcs[2].source + "\n/* changed */")
            graph.bundle.functions[changed.function_id] = changed
            fresh = ScriptedLLM([
                response("CONTINUE"), response("CONTINUE"),
                response("UNRESOLVED"),
            ])
            _, changed_decisions = await ActionRequestAgent(
                fresh, graph, resume_checkpoint_dir=root,
            ).run([action])
            self.assertEqual(changed_decisions[0].disposition, "UNRESOLVED")
            self.assertEqual(len(fresh.calls), 3)

    async def test_old_request_checkpoint_is_reanalyzed_after_validation_change(self):
        graph, funcs, action = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = ScriptedLLM([
                response("CONTINUE"), response("CONTINUE"),
                response("UNRESOLVED"),
            ])
            await ActionRequestAgent(
                first, graph, checkpoint_store=ArtifactStore(root),
            ).run([action])
            checkpoint = next((root / "actions/request-checkpoints").glob("*.json"))
            saved = json.loads(checkpoint.read_text(encoding="utf-8"))
            saved["schema_version"] = 1
            checkpoint.write_text(json.dumps(saved), encoding="utf-8")

            example = {
                "data_hex": "41", "bindings": [], "rationale": "complete request",
                "origin": "model_input_hypothesis", "evidence": [citation(funcs[2])],
            }
            resumed = ScriptedLLM([
                response("CONTINUE"), response("CONTINUE"),
                response("READY", examples=[example]),
            ])
            resolved, decisions = await ActionRequestAgent(
                resumed, graph, resume_checkpoint_dir=root,
            ).run([action])
            self.assertEqual(decisions[0].disposition, "READY")
            self.assertEqual(resolved[0].examples[0].data_hex, "41")
            self.assertEqual(len(resumed.calls), 3)

    async def test_shared_effect_still_builds_each_route_request_separately(self):
        graph, _funcs, action = fixture()
        other = replace(action, action_id="udp-action", entry_id="udp-entry",
                        channel_kind="udp")
        llm = ScriptedLLM([response("CONTINUE"), response("CONTINUE"),
                           response("UNRESOLVED")] * 2)
        effects = {
            item.action_id: {
                "group_id": "source-group", "action_ids": [action.action_id,
                other.action_id], "source_summary": "same handler effect",
                "source_evidence": [],
            } for item in (action, other)
        }
        resolved, decisions = await ActionRequestAgent(llm, graph).run(
            [action, other], shared_effects=effects,
        )
        self.assertEqual([item.action_id for item in resolved],
                         [action.action_id, other.action_id])
        self.assertEqual([item.action_id for item in decisions],
                         [action.action_id, other.action_id])
        self.assertEqual(len({call["session_key"] for call in llm.calls}), 2)
        self.assertTrue(all(call["payload"]["shared_source_effect"]
                            ["group_id"] == "source-group" for call in llm.calls))

    async def test_opens_anchors_then_parser_in_one_session_and_keeps_variants(self):
        graph, funcs, action = fixture()
        examples = [{
            "data_hex": value, "bindings": [], "rationale": "complete request",
            "origin": "model_input_hypothesis", "evidence": [citation(funcs[3])],
        } for value in ("41", "42")]
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("CONTINUE", request=funcs[3].function_id),
            response("READY", examples=examples),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual([item.data_hex for item in resolved[0].examples], ["41", "42"])
        self.assertEqual(decisions[0].disposition, "READY")
        self.assertEqual(len(llm.calls), 4)
        self.assertEqual(len({call["session_key"] for call in llm.calls}), 1)

    async def test_ready_with_bytes_only_in_fields_gets_same_session_correction(self):
        graph, funcs, action = fixture()
        misplaced = response("READY")
        misplaced["fields"] = [{
            "name": "request", "offset": 0, "width": 1,
            "encoding": "hex", "binding": "41", "relation": "opaque",
            "evidence": [citation(funcs[2])],
        }]
        example = {
            "data_hex": "41", "bindings": [], "rationale": "complete request",
            "origin": "model_input_hypothesis", "evidence": [citation(funcs[2])],
        }
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"), misplaced,
            response("READY", examples=[example]),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(decisions[0].disposition, "READY")
        self.assertEqual(resolved[0].examples[0].data_hex, "41")
        self.assertEqual(len(llm.calls), 4)
        self.assertEqual(len({call["session_key"] for call in llm.calls}), 1)
        self.assertNotIn("validation_feedback", llm.calls[2]["payload"])
        self.assertIn("examples[].data_hex",
                      llm.calls[3]["payload"]["validation_feedback"])
        self.assertEqual(llm.calls[3]["payload"]["current_function"]["function_id"],
                         funcs[2].function_id)

    async def test_repeated_empty_ready_without_new_source_stays_unresolved(self):
        graph, _funcs, action = fixture()
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("READY"), response("READY"),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(len(llm.calls), 4)
        self.assertEqual(decisions[0].disposition, "UNRESOLVED")
        self.assertIn("repeated after validation feedback", decisions[0].reason)
        self.assertEqual(resolved[0].examples, [])

    async def test_empty_ready_can_decline_when_source_does_not_support_bytes(self):
        graph, _funcs, action = fixture()
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("READY"), response("UNRESOLVED"),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(decisions[0].disposition, "UNRESOLVED")
        self.assertEqual(resolved[0].examples, [])
        self.assertEqual(len(llm.calls), 4)

    async def test_uncited_ready_example_can_be_repaired_without_inventing_bytes(self):
        graph, funcs, action = fixture()
        uncited = {
            "data_hex": "41", "bindings": [], "rationale": "request",
            "origin": "model_input_hypothesis", "evidence": [],
        }
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("READY", examples=[uncited]),
            response("READY", examples=[{**uncited,
                                         "evidence": [citation(funcs[2])]}]),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(decisions[0].disposition, "READY")
        self.assertEqual(resolved[0].examples[0].data_hex, "41")
        self.assertIn("source-line citation",
                      llm.calls[3]["payload"]["validation_feedback"])

    async def test_continue_without_function_request_gets_structured_feedback(self):
        graph, funcs, action = fixture()
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("CONTINUE"),
            response("CONTINUE", request=funcs[3].function_id),
            response("UNRESOLVED"),
        ])
        _, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(decisions[0].disposition, "UNRESOLVED")
        self.assertEqual(len(llm.calls), 5)
        self.assertIn("requested_function_id",
                      llm.calls[3]["payload"]["validation_feedback"])
        self.assertEqual(llm.calls[4]["payload"]["current_function"]["function_id"],
                         funcs[3].function_id)

    async def test_request_stage_reads_numeric_opcode_from_local_include_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "server.c").write_text(
                '#include "api.h"\nint receive(void) { unsigned char b; return read(0, &b, 1); }\n'
                'int dispatch(int opcode) { return opcode == CMD_SET; }\n'
                'int handle(void) { return 1; }\n'
            )
            (root / "api.h").write_text('#include "wire.h"\n')
            (root / "wire.h").write_text(
                'enum command { CMD_GET = 0x00, CMD_SET = 0x01 };\n'
            )
            functions = [FunctionMetadata.create(
                name=name, signature=f"int {name}(void)", file="server.c",
                start_line=line, end_line=line, source=source,
            ) for name, line, source in (
                ("receive", 2, "int receive(void) { unsigned char b; return read(0, &b, 1); }"),
                ("dispatch", 3, "int dispatch(int opcode) { return opcode == CMD_SET; }"),
                ("handle", 4, "int handle(void) { return 1; }"),
            )]
            graph = GraphStore(AnalysisBundle(
                functions={item.function_id: item for item in functions}, edges=[],
            ))
            action = ExternalActionSchema(
                action_id="binary-set", entry_id="entry", name="binary SET",
                description="storage", dispatcher_function_id=functions[1].function_id,
                handler_function_id=functions[2].function_id,
                discriminator="CMD_SET", channel_kind="tcp", fields=[], examples=[],
                success_markers_hex=[], failure_markers_hex=[], evidence=[],
                inspected_function_ids=[], entry_function_id=functions[0].function_id,
            )
            example = {
                "data_hex": "01", "bindings": [], "rationale": "SET opcode",
                "origin": "model_input_hypothesis",
                "evidence": [{
                    "kind": "source_declaration", "function_id": "wire.h",
                    "line": 1, "detail": "CMD_SET = 0x01",
                }, {
                    "kind": "source", "function_id": functions[0].function_id,
                    "line": 2, "detail": "read acquires one request byte",
                }],
            }
            llm = ScriptedLLM([
                response("CONTINUE"), response("CONTINUE"),
                response("READY", examples=[example]),
            ])

            resolved, decisions = await ActionRequestAgent(
                llm, graph, source_root=root,
            ).run([action])

            definitions = llm.calls[1]["payload"]["source_linked_numeric_definitions"]
            self.assertIn(("CMD_SET", "0x01", "wire.h"), {
                (item["name"], item["value"], item["file"])
                for item in definitions
            })
            self.assertEqual(decisions[0].disposition, "READY")
            self.assertEqual(resolved[0].examples[0].data_hex, "01")
            self.assertIn("wire.h", {
                item.file for item in resolved[0].examples[0].evidence
            })

            header_only = {**example, "evidence": example["evidence"][:1]}
            unresolved, rejected = await ActionRequestAgent(
                ScriptedLLM([
                    response("CONTINUE"), response("CONTINUE"),
                    response("READY", examples=[header_only]),
                ]),
                graph, source_root=root,
            ).run([action])
            self.assertEqual(rejected[0].disposition, "UNRESOLVED")
            self.assertEqual(unresolved[0].examples, [])

    async def test_unresolved_clears_provisional_example_before_planning(self):
        graph, funcs, action = fixture()
        action.examples = []
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("UNRESOLVED"),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(resolved[0].examples, [])
        self.assertEqual(decisions[0].disposition, "UNRESOLVED")

    async def test_drop_requires_source_evidence_for_selector_and_handler(self):
        graph, funcs, action = fixture()
        llm = ScriptedLLM([
            response("CONTINUE"), response("CONTINUE"),
            response("DROP", evidence=[citation(funcs[1])]),
        ])
        resolved, decisions = await ActionRequestAgent(llm, graph).run([action])
        self.assertEqual(decisions[0].disposition, "UNRESOLVED")
        self.assertNotEqual(resolved[0].status, ProofStatus.REFUTED)
