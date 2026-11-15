"""Active Action discovery treats source branches as evidence, not jobs."""

import tempfile
import json
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from harnesscreator.agents.scenario import (
    InputActionAgent, SEMANTIC_INPUT_ACTION_SCHEMA,
    _examples,
    _input_controlled_call_candidates,
    _producer_output_guard_candidates,
    _source_output_parameter_field_callers,
    _callback_registration_leads,
    _consolidate_same_request_actions, _entry_destination_names,
    _entry_receiver_field_names,
    _entry_shared_field_paths, _shared_field_handoff_candidates,
    _shared_field_return_callers, source_receiver_field_navigation_candidates,
    source_dataflow_consumers, _tainted_call_positions,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis import StaticAnalyzer
from harnesscreator.llm.base import (
    CachingLLM, RecordingLLM, ScriptedLLM, validate_strict_output_schema,
)
from harnesscreator.models import (
    AnalysisBundle, CallEdge, EntryRecord, Evidence, FunctionMetadata,
    ProofStatus, Verdict,
)


class SchemaRecordingLLM(ScriptedLLM):
    def __init__(self, responses: list[dict]):
        super().__init__(responses)
        self.schemas: list[dict] = []

    async def complete_json(self, **kwargs):
        self.schemas.append(kwargs["output_schema"])
        return await super().complete_json(**kwargs)


class DirectHandoffIdentityTests(unittest.TestCase):
    def test_callback_registration_lead_matches_target_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct ctx { int (*reader)(int); };\n"
                "int receive_one(int fd) { char data[1]; "
                "read(fd, data, 1); return data[0]; }\n"
                "int unrelated(int fd) { return fd; }\n"
                "void setup_good(struct ctx *c) { c->reader = receive_one; }\n"
                "void setup_other(struct ctx *c) { c->reader = unrelated; }\n"
                "int drive(struct ctx *c, int fd) { return c->reader(fd); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            self.assertEqual(
                _callback_registration_leads(
                    graph, [by_name["receive_one"].function_id],
                    {by_name["receive_one"].function_id},
                ),
                [by_name["setup_good"].function_id],
            )

    def test_guard_identity_from_different_translation_unit_is_not_input(self):
        reader = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd)",
            file="daemon.h", start_line=1, end_line=4,
            source="int receive_one(int fd) { char input[1]; read(fd, input, 1); return effect(); }",
        )
        effect = FunctionMetadata.create(
            name="effect", signature="int effect(void)", file="daemon.c",
            start_line=10, end_line=10, source="int effect(void) { return 1; }",
        )
        reader.external_call_sites = [{
            "api": "read", "line": 1, "offset": 20,
            "provider": "clang-ast-c", "analysis_unit": "unit-a.c",
            "direct_argument_identifiers": ["fd", "input", ""],
            "direct_argument_declaration_ids": ["fd", "reused-id", "size"],
        }]
        reader.guarded_call_sites = [{
            "analysis_unit": "unit-b.c", "guard_offset": 50,
            "guard_line": 1, "call_line": 1, "callee_name": "effect",
            "callee_function_id": effect.function_id,
            "condition_declaration_ids": ["reused-id"],
            "condition_content_declaration_ids": ["reused-id"],
        }]
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader, effect.function_id: effect},
            edges=[],
        ))
        entry = EntryRecord(
            entry_id="guard-unit", candidate_id="guard-unit",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=1,
            first_acquisition_confirmed=True,
        )
        self.assertEqual(_input_controlled_call_candidates(
            graph, reader, {"input"}, entry=entry,
        )[0], [])

    def test_declaration_ids_from_different_translation_units_do_not_match(self):
        caller = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd)",
            file="daemon.h", start_line=1, end_line=4,
            source="int receive_one(int fd) { char input[1]; read(fd, input, 1); return sink(input); }",
        )
        caller.external_call_sites = [{
            "api": "read", "line": 1, "analysis_unit": "unit-a.c",
            "direct_argument_declaration_ids": ["fd", "reused-id", "size"],
        }]
        caller.direct_call_sites = [{
            "callee_function_id": "sink-id", "line": 1,
            "provider": "clang-ast-c", "analysis_unit": "unit-b.c",
            "direct_argument_declaration_ids": ["reused-id"],
        }]
        entry = EntryRecord(
            entry_id="translation-unit", candidate_id="translation-unit",
            status=Verdict.VERIFIED, entry_function_id=caller.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=1,
            first_acquisition_confirmed=True,
        )
        self.assertEqual(_tainted_call_positions(
            caller, "sink", 1, {"input"}, callee_function_id="sink-id",
            entry=entry,
        ), set())

    def test_compiler_call_target_is_remapped_after_analysis_merge(self):
        with tempfile.TemporaryDirectory() as temporary:
            fallback_reader = FunctionMetadata.create(
                name="receive_one", signature="int receive_one(void)",
                file="daemon.c", start_line=3, end_line=4,
                source="int receive_one(void) { return sink(0); }",
            )
            fallback_sink = FunctionMetadata.create(
                name="sink", signature="int sink(int)", file="daemon.c",
                start_line=1, end_line=1, source="int sink(int x) { return x; }",
            )
            fallback_reader.direct_call_sites = [{
                "callee_function_id": fallback_sink.function_id,
                "line": 3, "provider": "clang-ast-c",
                "direct_argument_declaration_ids": ["decl-1"],
            }]
            primary_reader = replace(fallback_reader, function_id="fi-reader",
                                     direct_call_sites=[])
            primary_sink = replace(fallback_sink, function_id="fi-sink")
            merged = StaticAnalyzer(Path(temporary))._merge(
                AnalysisBundle(functions={primary_reader.function_id: primary_reader,
                                          primary_sink.function_id: primary_sink},
                               edges=[]),
                AnalysisBundle(functions={fallback_reader.function_id: fallback_reader,
                                          fallback_sink.function_id: fallback_sink},
                               edges=[]),
            )
            reader = next(item for item in merged.functions.values()
                          if item.name == "receive_one")
            sink = next(item for item in merged.functions.values()
                        if item.name == "sink")
            self.assertEqual(reader.direct_call_sites[0]["callee_function_id"],
                             sink.function_id)

    def test_shadowed_same_name_is_not_input_handoff(self):
        for suffix in ("c", "cpp"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    "extern \"C\" long read(int, void *, unsigned long);\n"
                    if suffix == "cpp" else
                    "extern long read(int, void *, unsigned long);\n",
                    encoding="utf-8",
                )
                with source.open("a", encoding="utf-8") as handle:
                    handle.write(
                        "int sink(char *p) { return p[0]; }\n"
                        "int receive_one(int fd) {\n"
                        "  char input[2]; read(fd, input, 2);\n"
                        "  { char input[2] = {'X', 0}; sink(input); }\n"
                        "  return 0;\n"
                        "}\n"
                    )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                reader = next(item for item in graph.bundle.functions.values()
                              if item.name == "receive_one")
                sink = next(item for item in graph.bundle.functions.values()
                            if item.name == "sink")
                entry = EntryRecord(
                    entry_id="shadowed", candidate_id="shadowed",
                    status=Verdict.VERIFIED,
                    entry_function_id=reader.function_id, source_api="read",
                    channel_kind="stdin", attacker_control="local",
                    provenance_path=[], consumer_hints=[], evidence=[],
                    unknowns=[], verifier_confidence=0.99,
                    entry_line=reader.start_line + 1,
                    first_acquisition_confirmed=True,
                )
                self.assertTrue(reader.direct_call_sites)
                consumers, _ = source_dataflow_consumers(
                    graph, entry, function_limit=len(graph.bundle.functions),
                    include_all_consumers=True, include_candidate_edges=True,
                )
                self.assertNotIn(sink.function_id, {item[0] for item in consumers})

    def test_acquired_declaration_still_reaches_direct_callee(self):
        for suffix in ("c", "cpp"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                declaration = (
                    "extern \"C\" long read(int, void *, unsigned long);\n"
                    if suffix == "cpp" else
                    "extern long read(int, void *, unsigned long);\n"
                )
                source.write_text(
                    declaration +
                    "int sink(char *p) { return p[0]; }\n"
                    "int receive_one(int fd) {\n"
                    "  char input[2]; read(fd, input, 2);\n"
                    "  return sink(input);\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                reader = next(item for item in graph.bundle.functions.values()
                              if item.name == "receive_one")
                sink = next(item for item in graph.bundle.functions.values()
                            if item.name == "sink")
                entry = EntryRecord(
                    entry_id="direct", candidate_id="direct",
                    status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                    source_api="read", channel_kind="stdin",
                    attacker_control="local", provenance_path=[], consumer_hints=[],
                    evidence=[], unknowns=[], verifier_confidence=0.99,
                    entry_line=reader.start_line + 1,
                    first_acquisition_confirmed=True,
                )
                consumers, _ = source_dataflow_consumers(
                    graph, entry, function_limit=len(graph.bundle.functions),
                    include_all_consumers=True, include_candidate_edges=True,
                )
                self.assertIn(sink.function_id, {item[0] for item in consumers})


class SemanticActionWorkflowTest(unittest.IsolatedAsyncioTestCase):
    async def test_c_output_parameter_identifies_struct_field_caller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct Context { char bytes[8]; };\n"
                "int acquire(char *buffer) { return read(0, buffer, 8); }\n"
                "void receive(struct Context *ctx) { acquire(ctx->bytes); }\n"
                "void local_receive(void) { char bytes[8]; acquire(bytes); }\n"
                "void mixed_receive(struct Context *ctx) { "
                "char local[8]; acquire(ctx->bytes); acquire(local); }\n",
                encoding="utf-8",
            )
            database = root / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang", "-c", str(source)],
            }]), encoding="utf-8")
            graph = GraphStore(StaticAnalyzer(root, compile_database=database).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["acquire"]
            entry = EntryRecord(
                entry_id="c-field", candidate_id="c-field-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                entry_line=3, source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[], consumer_hints=[],
                evidence=[], unknowns=[], verifier_confidence=1.0,
            )
            leads = _source_output_parameter_field_callers(graph, entry)
            self.assertEqual(
                set(leads),
                {by_name["receive"].function_id,
                 by_name["mixed_receive"].function_id},
            )
            self.assertEqual(
                leads[by_name["receive"].function_id][0]["field_name"], "bytes",
            )
            self.assertEqual(
                leads[by_name["receive"].function_id][0]["receiver_kind"],
                "declaration",
            )
            storage_leads = _source_output_parameter_field_callers(
                graph, entry, include_local=True,
            )
            self.assertEqual(
                set(storage_leads),
                {by_name["receive"].function_id,
                 by_name["local_receive"].function_id,
                 by_name["mixed_receive"].function_id},
            )
            self.assertEqual(
                storage_leads[by_name["local_receive"].function_id][0]["storage_name"],
                "bytes",
            )
            self.assertEqual(
                {record["storage_kind"] for record in
                 storage_leads[by_name["mixed_receive"].function_id]},
                {"field", "local_or_parameter"},
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": False,
                "requested_function_ids": [], "rationale": "inspect caller",
            }])
            await InputActionAgent(llm, graph, budget=1).run([entry])
            mixed_choice = next(
                item for item in llm.calls[0]["payload"]["frontier"]
                if item["function_id"] == by_name["mixed_receive"].function_id
            )
            self.assertTrue(any(
                connection.get("relation")
                == "source_output_parameter_storage_handoff_candidate"
                and len(connection.get("storage_handoffs", [])) == 2
                for connection in mixed_choice["connections"]
            ))

    async def test_recvfrom_transport_comes_from_socket_provenance(self) -> None:
        reader = FunctionMetadata.create(
            name="receive_bytes", signature="int receive_bytes(int fd, char *buffer)",
            file="transport.c", start_line=1, end_line=3,
            source=(
                "int receive_bytes(int fd, char *buffer) {\n"
                "  return recvfrom(fd, buffer, 8, 0, 0, 0);\n"
                "}\n"
            ),
        )
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        entry = EntryRecord(
            entry_id="entry-recvfrom", candidate_id="candidate-recvfrom",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="recvfrom", channel_kind="network socket bytes",
            attacker_control="peer", provenance_path=[], consumer_hints=[],
            evidence=[], unknowns=[], verifier_confidence=0.99,
            entry_line=2, first_acquisition_confirmed=True,
        )
        tcp_agent = InputActionAgent(ScriptedLLM([]), graph, scenario_channel="tcp")
        udp_agent = InputActionAgent(ScriptedLLM([]), graph, scenario_channel="udp")
        # The API alone does not identify TCP or UDP. Both remain candidates
        # until the configured original-runtime trial attributes the bytes.
        self.assertEqual(tcp_agent.scenario_incompatibility(entry), "")
        self.assertEqual(udp_agent.scenario_incompatibility(entry), "")

        entry.channel_kind = "Internet TCP stream socket bytes"
        self.assertEqual(tcp_agent.scenario_incompatibility(entry), "")
        self.assertIn("UDP", udp_agent.scenario_incompatibility(entry))

        entry.channel_kind = "Internet UDP datagram socket bytes"
        self.assertIn("TCP", tcp_agent.scenario_incompatibility(entry))
        self.assertEqual(udp_agent.scenario_incompatibility(entry), "")

    async def test_action_walk_opens_source_linked_table_before_handler(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "extern long read(int, void *, unsigned long);\n"
                "int handle_one(void) { return 1; }\n"
                "int handle_two(void) { return 2; }\n"
                "int handle_three(void) { return 3; }\n"
                "int unrelated(void) { return 3; }\n"
                "static int (*unused_handlers[1])(void) = {unrelated};\n"
                "static int (*handlers[3])(void) = {handle_one, handle_two, handle_three};\n"
                "static const char *commands[3] = {\"ONE\", \"TWO\", \"THREE\"};\n"
                "int recv_line(int fd, char *buf) { return read(fd, buf, 8); }\n"
                "int serve(int fd) { char buf[8] = {0}; recv_line(fd, buf);\n"
                "  for (int i = 0; i < 2; ++i)\n"
                "    if (buf[0] == commands[i][0]) return handlers[i]();\n"
                "  return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["recv_line"]
            entry = EntryRecord(
                entry_id="table-entry", candidate_id="table-entry",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line,
                first_acquisition_confirmed=True,
            )
            model = ScriptedLLM([
                {"actions": [], "context_complete": False,
                 "requested_function_ids": ["serve"], "rationale": "follow caller"},
                {"actions": [], "context_complete": False,
                 "requested_function_ids": ["commands"], "rationale": "read table"},
                {"actions": [], "context_complete": False,
                 "requested_function_ids": ["handle_one"], "rationale": "read selected effect"},
                {"actions": [], "context_complete": False,
                 "requested_function_ids": ["handle_two"], "rationale": "read sibling effect"},
                {"actions": [], "context_complete": False,
                 "requested_function_ids": [], "rationale": "other effects remain"},
            ])
            hypotheses = {"table-entry": [{
                "case_id": "case-one", "data_hex": "4f4e450d0a",
                "sample_basis": [{"source_item_id": reader.function_id,
                                  "line": reader.start_line,
                                  "detail": "the receive call reads the line"}],
            }]}
            agent = InputActionAgent(
                model, graph, source_root=Path(temporary),
                input_case_hypotheses=hypotheses,
            )
            await agent.run([entry])
            self.assertEqual(len(model.calls), 5)
            self.assertEqual(
                model.calls[0]["payload"]["source_backed_input_cases"],
                hypotheses["table-entry"],
            )
            self.assertEqual(
                model.calls[1]["payload"]["source_backed_input_cases"], [],
            )
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in model.calls],
                ["recv_line", "serve", "serve", "handle_one", "handle_two"],
            )
            declaration_turn = model.calls[2]["payload"]
            self.assertEqual(
                declaration_turn["current_source_artifact"]["path"],
                "daemon.c",
            )
            self.assertIn("handle_one", {
                item["name"] for item in declaration_turn["frontier"]
            })
            self.assertNotIn("unrelated", {
                item["name"] for item in declaration_turn["frontier"]
            })
            self.assertIn(
                by_name["handle_three"].function_id,
                agent.continuations[0]["next_function_ids"],
            )
            cited = _examples([{
                "data_hex": "4f4e450d0a", "bindings": [],
                "rationale": "table and receive line", "origin": "input_surface_case",
                "evidence": [{
                    "kind": "source_declaration", "function_id": "daemon.c",
                    "line": 8, "detail": "the command table contains ONE",
                }],
            }], {reader.function_id}, graph, {"daemon.c": [(1, 10)]})
            self.assertEqual(len(cited), 1)
            self.assertEqual(cited[0].evidence[0].kind,
                             "source_declaration_lexical")

    async def test_consumer_parameter_guard_uses_declaration_identity(self):
        for suffix in ("c", "cpp"):
            with self.subTest(language=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    "int selected(void) { return 1; }\n"
                    "int unrelated(void) { return 2; }\n"
                    "int parse(char *payload, char opcode) {\n"
                    "  if (payload[0] == 'A') selected();\n"
                    "  if (opcode == 'B') selected();\n"
                    "  { char *payload = 0; if (payload) unrelated(); }\n"
                    "  return 0;\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                by_name = {item.name: item for item in graph.bundle.functions.values()}
                parser = by_name["parse"]
                self.assertEqual(
                    {item["name"] for item in parser.ast_parameter_declarations},
                    {"payload", "opcode"},
                )
                candidates, unresolved = _input_controlled_call_candidates(
                    graph, parser, {"payload", "opcode"},
                )
                self.assertEqual(candidates, [by_name["selected"].function_id])
                self.assertFalse(any("unrelated" in item for item in unresolved))

    async def test_derived_local_guard_stops_after_literal_overwrite(self):
        for suffix in ("c", "cpp"):
            with self.subTest(language=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    "int decode(char *payload) { return payload[0]; }\n"
                    "int selected(void) { return 1; }\n"
                    "int overwritten(void) { return 2; }\n"
                    "int config_only(void) { return 3; }\n"
                    "int parse(char *payload, int config) {\n"
                    "  int cmd = decode(payload);\n"
                    "  if (cmd == 'A') selected();\n"
                    "  cmd = 0;\n"
                    "  if (cmd == 'B') overwritten();\n"
                    "  if (config) config_only();\n"
                    "  return 0;\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                by_name = {item.name: item for item in graph.bundle.functions.values()}
                candidates, unresolved = _input_controlled_call_candidates(
                    graph, by_name["parse"], {"payload"},
                )
                self.assertEqual(candidates, [by_name["selected"].function_id])
                self.assertTrue(any("overwritten" in item for item in unresolved))
                self.assertFalse(any("config_only" in item for item in unresolved))

    async def test_parser_output_parameter_links_later_handler_guard(self):
        for suffix in ("c", "cpp"):
            with self.subTest(language=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    "void parse(char *input, char *output) { output[0] = input[0]; }\n"
                    "void inspect(char *input, char *output) { (void)input[0]; (void)output[0]; }\n"
                    "void index_only(char *output, int selector) { output[selector] = 1; }\n"
                    "int selected(void) { return 1; }\n"
                    "int config_only(void) { return 2; }\n"
                    "int dispatch(char *input, int config) {\n"
                    "  char command[2] = {0, 0};\n"
                    "  inspect(input, command);\n"
                    "  parse(input, command);\n"
                    "  if (command[0] == 'A') selected();\n"
                    "  if (config) config_only();\n"
                    "  return 0;\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                by_name = {item.name: item for item in graph.bundle.functions.values()}
                self.assertEqual(by_name["parse"].parameter_output_positions, [1])
                self.assertEqual(by_name["inspect"].parameter_output_positions, [])
                self.assertEqual(by_name["index_only"].parameter_output_positions, [0])
                candidates = _producer_output_guard_candidates(
                    graph, by_name["dispatch"],
                    {by_name["parse"].function_id,
                     by_name["inspect"].function_id},
                )
                self.assertEqual(candidates, [by_name["selected"].function_id])

    async def test_action_frontier_keeps_parser_output_handler(self):
        for suffix in ("c", "cpp"):
            with self.subTest(language=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    "#include <unistd.h>\n"
                    "void parse(char *input, char *output) { output[0] = input[0]; }\n"
                    "int selected(void) { return 1; }\n"
                    "int config_only(void) { return 2; }\n"
                    "int dispatch(char *input, int config) {\n"
                    "  char command[2] = {0, 0};\n"
                    "  parse(input, command);\n"
                    "  if (command[0] == 'A') selected();\n"
                    "  if (config) config_only();\n"
                    "  return 0;\n"
                    "}\n"
                    "void receive_one(int fd) {\n"
                    "  char input[2]; read(fd, input, 2); dispatch(input, 0);\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                by_name = {item.name: item for item in graph.bundle.functions.values()}
                entry = EntryRecord(
                    entry_id="parser-output", candidate_id="parser-output",
                    status=Verdict.VERIFIED,
                    entry_function_id=by_name["receive_one"].function_id,
                    source_api="read", channel_kind="stdin", attacker_control="local",
                    provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.99, entry_line=13,
                    first_acquisition_confirmed=True,
                )
                llm = ScriptedLLM([
                    {"actions": [], "context_complete": False,
                     "requested_function_ids": [by_name["dispatch"].function_id],
                     "rationale": "inspect consumer"},
                    {"actions": [], "context_complete": True,
                     "requested_function_ids": [], "rationale": "inspect leads"},
                ])
                agent = InputActionAgent(llm, graph, budget=2)
                self.assertEqual(await agent.run([entry]), [])
                self.assertEqual(len(llm.calls), 2)
                names = {item["name"] for item in llm.calls[1]["payload"]["frontier"]}
                self.assertIn("selected", names)
                self.assertNotIn("config_only", names)

    async def test_entry_walk_opens_handler_guarded_in_called_parser(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int selected(void) { return 1; }\n"
                "int parse(char *payload) {\n"
                "  if (payload[0] == 'A') return selected();\n"
                "  return 0;\n"
                "}\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  return parse(input);\n"
                "}\n", encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="parser-guard", candidate_id="parser-guard",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                {"actions": [], "context_complete": True,
                 "requested_function_ids": [], "rationale": "inspect source"}
                for _ in range(3)
            ])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"]
                      for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "parse", "selected"])
            self.assertEqual(agent.planned_branch_validations, 0)

    async def test_missing_consumer_ast_is_open_obligation(self):
        function = FunctionMetadata.create(
            name="parse", signature="parse: void(char *)", file="daemon.c",
            start_line=4, end_line=8, source="void parse(char *input) {}",
        )
        graph = GraphStore(AnalysisBundle(functions={function.function_id: function}, edges=[]))
        candidates, unresolved = _input_controlled_call_candidates(
            graph, function, {"input"},
        )
        self.assertEqual(candidates, [])
        self.assertTrue(any("unavailable" in item for item in unresolved))

    async def test_pointer_guard_is_not_treated_as_acquired_byte_guard(self):
        for suffix, declaration in (
            ("c", "extern long read(int, void *, unsigned long);"),
            ("cpp", 'extern "C" long read(int, void *, unsigned long);'),
        ):
            with self.subTest(language=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    declaration + "\n"
                    "int pointer_handler(void) { return 1; }\n"
                    "int byte_handler(void) { return 2; }\n"
                    "int scalar_handler(void) { return 3; }\n"
                    "int receive_one(int fd) {\n"
                    "  char buf[8]; char ch;\n"
                    "  read(fd, buf, 8);\n"
                    "  if (buf) pointer_handler();\n"
                    "  if (buf[0]) byte_handler();\n"
                    "  read(fd, &ch, 1);\n"
                    "  if (ch) scalar_handler();\n"
                    "  return 0;\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                by_name = {item.name: item for item in graph.bundle.functions.values()}
                reader = by_name["receive_one"]
                for line, expected, rejected in (
                    (7, "byte_handler", "pointer_handler"),
                    (10, "scalar_handler", "pointer_handler"),
                ):
                    entry = EntryRecord(
                        entry_id=f"guard-{line}", candidate_id=f"guard-{line}",
                        status=Verdict.VERIFIED,
                        entry_function_id=reader.function_id,
                        source_api="read", channel_kind="stdin",
                        attacker_control="local", provenance_path=[],
                        consumer_hints=[], evidence=[], unknowns=[],
                        verifier_confidence=0.99, entry_line=line,
                        first_acquisition_confirmed=True,
                    )
                    candidates, unresolved = _input_controlled_call_candidates(
                        graph, reader, _entry_destination_names(reader, entry),
                        entry=entry,
                    )
                    self.assertIn(by_name[expected].function_id, candidates)
                    self.assertNotIn(by_name[rejected].function_id, candidates)
                    if line == 7:
                        self.assertTrue(any("pointer_handler" in item for item in unresolved))

    async def test_literal_overwrite_does_not_auto_follow_guarded_call(self):
        for suffix, declaration in (
            ("c", "extern long read(int, void *, unsigned long);"),
            ("cpp", 'extern "C" long read(int, void *, unsigned long);'),
        ):
            with self.subTest(language=suffix), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / f"daemon.{suffix}"
                source.write_text(
                    declaration + "\n"
                    "int handle(void) { return 1; }\n"
                    "int receive_one(int fd) {\n"
                    "  char ch; read(fd, &ch, 1);\n"
                    "  ch = 'X';\n"
                    "  if (ch) return handle();\n"
                    "  return 0;\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                reader = next(item for item in graph.bundle.functions.values()
                              if item.name == "receive_one")
                entry = EntryRecord(
                    entry_id="literal-overwrite", candidate_id="literal-overwrite",
                    status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                    source_api="read", channel_kind="stdin", attacker_control="local",
                    provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.99, entry_line=reader.start_line + 1,
                    first_acquisition_confirmed=True,
                )
                model = ScriptedLLM([{
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "inspect source",
                }])
                agent = InputActionAgent(model, graph)
                self.assertEqual(await agent.run([entry]), [])
                self.assertEqual(
                    [call["payload"]["current_function"]["name"]
                     for call in model.calls],
                    ["receive_one"],
                )
                self.assertTrue(any(
                    "acquired scalar was overwritten" in reason
                    for reason in agent.inventory_obligations
                ))

    async def test_nondefinite_writes_keep_guarded_call_available(self):
        statements = (
            "ch = ch + 1;",
            "if (fd < 0) ch = 'X';",
            "goto check; ch = 'X'; check: ;",
        )
        for statement in statements:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "daemon.c"
                source.write_text(
                    "extern long read(int, void *, unsigned long);\n"
                    "int handle(void) { return 1; }\n"
                    "int receive_one(int fd) {\n"
                    "  char ch; read(fd, &ch, 1);\n"
                    f"  {statement}\n"
                    "  if (ch) return handle();\n"
                    "  return 0;\n"
                    "}\n", encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                reader = next(item for item in graph.bundle.functions.values()
                              if item.name == "receive_one")
                entry = EntryRecord(
                    entry_id="nondefinite-write", candidate_id="nondefinite-write",
                    status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                    source_api="read", channel_kind="stdin", attacker_control="local",
                    provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.99, entry_line=reader.start_line + 1,
                    first_acquisition_confirmed=True,
                )
                model = ScriptedLLM([{
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "inspect source",
                } for _ in range(2)])
                agent = InputActionAgent(model, graph)
                self.assertEqual(await agent.run([entry]), [])
                self.assertEqual(
                    [call["payload"]["current_function"]["name"]
                     for call in model.calls],
                    ["receive_one", "handle"],
                )

    async def test_guard_declaration_identity_after_overwrite_is_not_input_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int handler(void) { return 1; }\n"
                "int receive_one(int fd) {\n"
                "  char data[1];\n"
                "  read(fd, data, 1);\n"
                "  data[0] = 1;\n"
                "  if (data[0]) return handler();\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            functions = {item.name: item for item in graph.bundle.functions.values()}
            reader, handler = functions["receive_one"], functions["handler"]
            self.assertTrue(reader.guarded_call_sites)
            entry = EntryRecord(
                entry_id="overwritten", candidate_id="overwritten",
                status=Verdict.VERIFIED,
                entry_function_id=reader.function_id, source_api="read",
                channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=5,
                first_acquisition_confirmed=True,
            )
            citation = lambda function, line: dict(
                kind="source", function_id=function.function_id,
                line=line, detail="opened source",
            )
            action = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                entry, [dict(
                    name="claimed input action", description="claimed effect",
                    dispatcher_function_id=reader.function_id,
                    handler_function_id=handler.function_id,
                    discriminator="", fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="guess",
                                   origin="source_candidate",
                                   evidence=[citation(reader, 7)])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation(handler, 2)],
                    failure_evidence=[], response_bindings=[],
                    evidence=[citation(reader, 7), citation(handler, 2)],
                    unknowns=[], confidence=0.99,
                    action_context_complete=True,
                )], [reader.function_id, handler.function_id], [],
                context_complete=True,
            )[0]
            self.assertEqual(action.status, ProofStatus.POSSIBLE)

    async def test_lost_action_session_retains_unfinished_source_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "extern long read(int, void *, unsigned long);\n"
                "int helper(char *p) { return p[0]; }\n"
                "int receive_one(int fd) { char input[2]; read(fd, input, 2); "
                "return helper(input); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="session-interrupted", candidate_id="session-interrupted",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line,
                first_acquisition_confirmed=True,
            )
            citation = [{"kind": "source", "function_id": reader.function_id,
                         "line": reader.start_line,
                         "detail": "input is passed to a consumer"}]
            first = {
                "actions": [{
                    "name": "consume input", "description": "consume one input byte",
                    "dispatcher_function_id": None, "discriminator": None,
                    "handler_function_id": reader.function_id, "fields": [],
                    "examples": [{"data_hex": "41", "bindings": [],
                                  "rationale": "candidate byte", "origin": "source_candidate",
                                  "evidence": citation}],
                    "success_markers_hex": [], "failure_markers_hex": [],
                    "success_evidence": citation, "failure_evidence": [],
                    "response_bindings": [], "evidence": citation,
                    "unknowns": ["helper result not inspected"],
                    "confidence": 0.5, "action_context_complete": False,
                }],
                "context_complete": False,
                "requested_function_ids": ["helper"],
                "rationale": "inspect the input consumer",
            }
            # The second call fails like a lost stateful app-server session.
            model = ScriptedLLM([first])
            agent = InputActionAgent(model, graph)
            actions = await agent.run([entry])
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].status, ProofStatus.POSSIBLE)
            self.assertTrue(any("interrupted" in reason
                                for reason in actions[0].unknowns))
            self.assertTrue(agent.infrastructure_failures)
            self.assertEqual(
                agent.continuations[0]["partial_action_drafts"][0]["name"],
                "consume input",
            )

    async def test_guarded_input_handoffs_are_opened_without_sweeping_other_guards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int handle_a(char *p) { return p[0] == 'A'; }\n"
                "int handle_b(char *p) { return p[0] == 'B'; }\n"
                "int tick(int config) { return config; }\n"
                "int receive_one(int fd, int config) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0] == 'A') handle_a(input);\n"
                "  if (input[0] == 'B') handle_b(input);\n"
                "  if (config) tick(config);\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="guarded-input", candidate_id="guarded-input-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[Evidence(
                    "source", reader.function_id, reader.file,
                    reader.start_line + 1, "read acquires input",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "input uses are ambiguous",
            }])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one"])
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name["handle_a"].function_id, by_name["handle_b"].function_id},
            )
            first_frontier = {
                item["function_id"]: item["connections"]
                for item in llm.calls[0]["payload"]["frontier"]
            }
            for name in ("handle_a", "handle_b"):
                handoffs = [
                    item for item in first_frontier[by_name[name].function_id]
                    if item["relation"] == "source_linked_value_handoff_candidate"
                ]
                self.assertEqual(len(handoffs), 1)
                self.assertEqual(handoffs[0]["source_function_id"], reader.function_id)
                self.assertEqual(handoffs[0]["source_line"], 7 if name == "handle_a" else 8)
            self.assertNotIn(
                by_name["tick"].function_id,
                {item["function_id"] for item in llm.calls[0]["payload"]["frontier"]},
            )
            self.assertEqual(agent.planned_branch_validations, 0)

    async def test_input_guarded_effect_call_without_byte_argument_is_inspected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int state;\n"
                "int handle_a(void) { state = 1; return state; }\n"
                "int handle_b(void) { state = 2; return state; }\n"
                "int tick(void) { state++; return state; }\n"
                "int receive_one(int fd, int config) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0] == 'A') handle_a();\n"
                "  if (input[0] == 'B') handle_b();\n"
                "  if (config) tick();\n"
                "  return state;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="guarded-effect", candidate_id="guarded-effect-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[Evidence(
                    "source", reader.function_id, reader.file,
                    reader.start_line + 1, "read acquires input",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                {"actions": [], "context_complete": False,
                 "requested_function_ids": [by_name["handle_a"].function_id],
                 "rationale": "inspect the first source-linked effect"},
                *[{"actions": [], "context_complete": True,
                   "requested_function_ids": [], "rationale": "inspect remaining input use"}
                  for _ in range(2)],
            ])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "handle_a", "handle_b"])
            first_frontier = {
                item["function_id"]: item["connections"]
                for item in llm.calls[0]["payload"]["frontier"]
            }
            for name in ("handle_a", "handle_b"):
                connections = first_frontier[by_name[name].function_id]
                relations = {item["relation"] for item in connections}
                self.assertIn("source_guarded_call_candidate", relations)
                self.assertNotIn("source_linked_value_handoff_candidate", relations)
                guarded = next(
                    item for item in connections
                    if item["relation"] == "source_guarded_call_candidate"
                )
                self.assertEqual(guarded["source_function_id"], reader.function_id)
                self.assertEqual(guarded["source_line"], 8 if name == "handle_a" else 9)
                self.assertEqual(guarded["guard_line"], guarded["source_line"])
            self.assertNotIn(by_name["tick"].function_id, first_frontier)
            self.assertEqual(agent.planned_branch_validations, 0)


    async def test_shadowed_input_name_does_not_open_unrelated_guarded_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "extern long read(int, void *, unsigned long);\n"
                "int real_handler(void) { return 1; }\n"
                "int unrelated(void) { return 2; }\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0]) real_handler();\n"
                "  { char input[2] = {1, 0}; if (input[0]) unrelated(); }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="shadowed-input", candidate_id="shadowed-input-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[Evidence(
                    "source", reader.function_id, reader.file,
                    reader.start_line + 1, "read acquires input",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            self.assertTrue(reader.guarded_call_sites)
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "inspect input-controlled calls",
            } for _ in range(2)])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "real_handler"])
            self.assertNotIn("unrelated", opened)

    async def test_cpp_shadowed_input_name_uses_the_acquired_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.cpp"
            source.write_text(
                'extern "C" long read(int, void *, unsigned long);\n'
                "int real_handler() { return 1; }\n"
                "int unrelated() { return 2; }\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; ::read(fd, input, 2);\n"
                "  if (input[0]) real_handler();\n"
                "  { char input[2] = {1, 0}; if (input[0]) unrelated(); }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="cpp-shadowed-input", candidate_id="cpp-shadowed-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[Evidence(
                    "source", reader.function_id, reader.file,
                    reader.start_line + 1, "read acquires input",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "inspect input-controlled calls",
            } for _ in range(2)])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "real_handler"])

    async def test_cross_unit_guarded_call_opens_unique_symbol_definition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "reader.c").write_text(
                "extern long read(int, void *, unsigned long);\n"
                "extern int external_handler(void);\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0]) external_handler();\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "handler.c").write_text(
                "int external_handler(void) { return 1; }\n", encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="cross-unit", candidate_id="cross-unit-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "no more source",
            } for _ in range(2)])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"] for call in llm.calls],
                ["receive_one", "external_handler"],
            )

    async def test_ambiguous_cross_unit_symbol_stays_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "reader.c").write_text(
                "extern long read(int, void *, unsigned long);\n"
                "extern int external_handler(void);\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0]) external_handler();\n"
                "  return 0;\n"
                "}\n", encoding="utf-8",
            )
            for filename in ("server_handler.c", "test_handler.c"):
                (root / filename).write_text(
                    "int external_handler(void) { return 1; }\n",
                    encoding="utf-8",
                )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="ambiguous-cross-unit", candidate_id="ambiguous-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "no more source",
            }])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(llm.calls), 1)
            self.assertTrue(agent.continuations)
            self.assertTrue(any(
                "external_handler() has ambiguous cross-unit source definitions" in item
                for item in agent.inventory_obligations
            ))

    async def test_cpp_cross_unit_symbol_selects_correct_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "reader.cpp").write_text(
                'extern "C" long read(int, void *, unsigned long);\n'
                "namespace A { int handle(int); }\n"
                "namespace B { int handle(int); }\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; ::read(fd, input, 2);\n"
                "  if (input[0]) A::handle(1);\n"
                "  return 0;\n"
                "}\n", encoding="utf-8",
            )
            (root / "handler.cpp").write_text(
                "namespace A { int handle(int value) { return value; } }\n"
                "namespace B { int handle(int value) { return value + 1; } }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            target = next(item for item in graph.bundle.functions.values()
                          if item.file == "handler.cpp" and item.start_line == 1
                          and item.name == "handle")
            self.assertTrue(target.linkage_symbol)
            entry = EntryRecord(
                entry_id="cpp-cross-unit", candidate_id="cpp-cross-unit-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "inspect source",
            } for _ in range(2)])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                llm.calls[1]["payload"]["current_function"]["function_id"],
                target.function_id,
            )

    async def test_internal_linkage_definition_is_not_cross_unit_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "reader.c").write_text(
                "extern long read(int, void *, unsigned long);\n"
                "extern int hidden(void);\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0]) hidden();\n"
                "  return 0;\n"
                "}\n", encoding="utf-8",
            )
            (root / "other.c").write_text(
                "static int hidden(void) { return 1; }\n"
                "int unrelated(void) { return hidden(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            hidden = next(item for item in graph.bundle.functions.values()
                          if item.name == "hidden")
            self.assertFalse(hidden.linkage_external)
            entry = EntryRecord(
                entry_id="internal-target", candidate_id="internal-target-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "no more source",
            }])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(llm.calls), 1)
            self.assertTrue(any(
                "hidden() has no resolved source definition" in item
                for item in agent.inventory_obligations
            ))

    async def test_cpp_input_guard_can_navigate_to_member_method(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.cpp"
            source.write_text(
                'extern "C" long read(int, void *, unsigned long);\n'
                "struct State { int handle() { return 1; } };\n"
                "int receive_one(int fd) {\n"
                "  State state; char input[2]; ::read(fd, input, 2);\n"
                "  if (input[0]) state.handle();\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="cpp-method", candidate_id="cpp-method-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "inspect call",
            } for _ in range(2)])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "handle"])

    async def test_missing_ast_keeps_input_control_question_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "extern long read(int, void *, unsigned long);\n"
                "int handle(void) { return 1; }\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  if (input[0]) handle();\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            reader.external_call_sites.clear()
            reader.guarded_call_sites.clear()
            entry = EntryRecord(
                entry_id="no-ast", candidate_id="no-ast-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "done",
            }])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(llm.calls), 1)
            self.assertTrue(agent.continuations)
            self.assertTrue(any(
                "Clang declaration identity is unavailable" in item
                for item in agent.inventory_obligations
            ))

    async def test_missing_ast_does_not_treat_non_if_control_as_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "extern long read(int, void *, unsigned long);\n"
                "int handle(void) { return 1; }\n"
                "int receive_one(int fd) {\n"
                "  char input[2]; read(fd, input, 2);\n"
                "  while (input[0]) { handle(); break; }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            reader.external_call_sites.clear()
            reader.guarded_call_sites.clear()
            entry = EntryRecord(
                entry_id="no-ast-loop", candidate_id="no-ast-loop-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "done",
            }])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertTrue(agent.continuations)
            self.assertTrue(any(
                "Clang declaration identity is unavailable" in item
                for item in agent.inventory_obligations
            ))

    async def test_input_controlled_non_if_calls_are_navigation_candidates(self) -> None:
        statements = (
            "while (input[0]) { handle(); break; }",
            "for (int i = 0; input[0] && i < 1; ++i) handle();",
            "input[0] ? handle() : 0;",
            "input[0] && handle();",
        )
        for statement in statements:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "daemon.c"
                source.write_text(
                    "#include <unistd.h>\n"
                    "int handle(void) { return 1; }\n"
                    "int unrelated(void) { return 0; }\n"
                    "int receive_one(int fd, int config) {\n"
                    "  char input[2]; read(fd, input, 2);\n"
                    f"  {statement}\n"
                    "  if (config) unrelated();\n"
                    "  return 0;\n"
                    "}\n",
                    encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
                reader = next(item for item in graph.bundle.functions.values()
                              if item.name == "receive_one")
                entry = EntryRecord(
                    entry_id="non-if", candidate_id="non-if-candidate",
                    status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                    source_api="read", channel_kind="stdin", attacker_control="local",
                    provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.99, entry_line=reader.start_line + 1,
                    first_acquisition_confirmed=True,
                )
                llm = ScriptedLLM([{
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "inspect source",
                } for _ in range(2)])
                agent = InputActionAgent(llm, graph)
                self.assertEqual(await agent.run([entry]), [])
                opened = [call["payload"]["current_function"]["name"]
                          for call in llm.calls]
                self.assertEqual(opened, ["receive_one", "handle"])
                self.assertNotIn("unrelated", opened)

    async def test_input_controlled_else_call_is_inspected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int first(void) { return 1; }\n"
                "int second(void) { return 2; }\n"
                "int receive_one(int fd) {\n"
                "  char input[1]; read(fd, input, 1);\n"
                "  if (input[0] == 'A') { first(); }\n"
                "  else { second(); }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="input-else", candidate_id="input-else-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                {"actions": [], "context_complete": False,
                 "requested_function_ids": [next(item.function_id for item in graph.bundle.functions.values()
                                            if item.name == "first")],
                 "rationale": "inspect first controlled call"},
                *[{"actions": [], "context_complete": True,
                   "requested_function_ids": [], "rationale": "inspect remaining controlled source"}
                  for _ in range(2)],
            ])
            self.assertEqual(await InputActionAgent(llm, graph).run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "first", "second"])

    async def test_input_controlled_switch_calls_are_not_case_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int first(void) { return 1; }\n"
                "int second(void) { return 2; }\n"
                "int unrelated(void) { return 3; }\n"
                "int receive_one(int fd, int config) {\n"
                "  char input[1]; read(fd, input, 1);\n"
                "  switch (input[0]) {\n"
                "    case 'A': first(); break;\n"
                "    case 'B': second(); break;\n"
                "  }\n"
                "  if (config) unrelated();\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            reader = next(item for item in graph.bundle.functions.values()
                          if item.name == "receive_one")
            entry = EntryRecord(
                entry_id="switch-input", candidate_id="switch-input-candidate",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                {"actions": [], "context_complete": False,
                 "requested_function_ids": [next(item.function_id for item in graph.bundle.functions.values()
                                            if item.name == "first")],
                 "rationale": "inspect first controlled call"},
                *[{"actions": [], "context_complete": True,
                   "requested_function_ids": [], "rationale": "inspect remaining controlled source"}
                  for _ in range(2)],
            ])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"] for call in llm.calls]
            self.assertEqual(opened, ["receive_one", "first", "second"])
            self.assertEqual(agent.planned_branch_validations, 0)

    async def test_direct_parameter_handoff_is_not_action_dependence_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int handle(char *data, int config) {\n"
                "  if (data[0]) (void)data[0];\n"
                "  if (config) return 1;\n"
                "  return 0;\n"
                "}\n"
                "int receive_one(int fd, int config) {\n"
                "  char data[1]; read(fd, data, 1);\n"
                "  return handle(data, config);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root, handler = by_name["receive_one"], by_name["handle"]
            entry = EntryRecord(
                entry_id="direct-unrelated", candidate_id="candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line + 1,
                first_acquisition_confirmed=True,
            )
            citation = [{
                "kind": "source", "function_id": handler.function_id,
                "line": handler.start_line + 1,
                "detail": "input parameter appears before a separate config result",
            }]
            action = {
                "name": "handle configured request", "description": "config result",
                "dispatcher_function_id": handler.function_id,
                "handler_function_id": handler.function_id,
                "discriminator": "byte", "fields": [],
                "examples": [{
                    "data_hex": "41", "bindings": [], "rationale": "trial",
                    "origin": "source_candidate", "evidence": citation,
                }],
                "success_markers_hex": [], "failure_markers_hex": [],
                "success_evidence": citation, "failure_evidence": [],
                "response_bindings": [], "evidence": citation,
                "unknowns": [], "confidence": 1.0,
                "action_context_complete": True,
            }
            consumers, _ = source_dataflow_consumers(
                graph, entry, function_limit=len(graph.bundle.functions),
                include_all_consumers=True,
            )
            result = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                entry, [action], [root.function_id, handler.function_id], [],
                context_complete=True,
                direct_consumer_ids={item[0] for item in consumers},
                direct_consumer_taint_names={
                    item[0]: item[2] for item in consumers
                },
            )
            self.assertEqual(result[0].status, ProofStatus.POSSIBLE)

    async def test_inline_input_mention_is_not_result_dependence_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int receive_one(int fd, int config) {\n"
                "  char data[1]; read(fd, data, 1);\n"
                "  if (data[0]) (void)data[0];\n"
                "  if (config) return 1;\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            root = next(iter(graph.bundle.functions.values()))
            entry = EntryRecord(
                entry_id="inline-unrelated", candidate_id="candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line + 1,
                first_acquisition_confirmed=True,
            )
            citation = [{
                "kind": "source", "function_id": root.function_id,
                "line": root.start_line + 2,
                "detail": "input occurs in an unrelated condition",
            }]
            action = {
                "name": "configured return", "description": "config result",
                "dispatcher_function_id": root.function_id,
                "handler_function_id": root.function_id,
                "discriminator": "byte", "fields": [],
                "examples": [{
                    "data_hex": "41", "bindings": [], "rationale": "trial",
                    "origin": "source_candidate", "evidence": citation,
                }],
                "success_markers_hex": [], "failure_markers_hex": [],
                "success_evidence": citation, "failure_evidence": [],
                "response_bindings": [], "evidence": citation,
                "unknowns": [], "confidence": 1.0,
                "action_context_complete": True,
            }
            result = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                entry, [action], [root.function_id], [], context_complete=True,
            )
            self.assertEqual(result[0].status, ProofStatus.POSSIBLE)

    async def test_source_only_preprocessor_branch_is_navigation_not_proof(self):
        reader_source = (
            "int receive_one(int fd) {\n"
            "  char data[1];\n"
            "  read(fd, data, 1);\n"
            "#if OPTIONAL_PARSER\n"
            "  parse(data);\n"
            "#endif\n"
            "  return 0;\n}"
        )
        reader = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd)",
            file="daemon.c", start_line=1, end_line=8,
            source=reader_source,
        )
        parser = FunctionMetadata.create(
            name="parse", signature="int parse(char *data)",
            file="daemon.c", start_line=20, end_line=20,
            source="int parse(char *data) { return data[0]; }",
        )
        entry = EntryRecord(
            entry_id="conditional-parser", candidate_id="conditional-parser",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[Evidence(
                "source", reader.function_id, reader.file, 3, "read input",
            )], unknowns=[], verifier_confidence=0.99, entry_line=3,
            first_acquisition_confirmed=True,
        )

        def consumers(provider: str, *, candidate: bool):
            graph = GraphStore(AnalysisBundle(
                functions={item.function_id: item for item in (reader, parser)},
                edges=[CallEdge(
                    "conditional-call", reader.function_id,
                    parser.function_id, 5, "direct", providers=[provider],
                )],
            ))
            return source_dataflow_consumers(
                graph, entry, function_limit=2,
                include_all_consumers=True,
                include_candidate_edges=candidate,
            )[0]

        self.assertEqual(consumers("bootstrap-source", candidate=False), [])
        self.assertEqual(
            [item[0] for item in consumers("bootstrap-source", candidate=True)],
            [parser.function_id],
        )
        self.assertEqual(
            [item[0] for item in consumers("fuzz-introspector", candidate=False)],
            [parser.function_id],
        )
        source_graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)},
            edges=[CallEdge(
                "source-only-call", reader.function_id, parser.function_id,
                5, "direct", providers=["bootstrap-source"],
            )],
        ))
        llm = ScriptedLLM([{
            "actions": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "no proved operation",
        }])
        agent = InputActionAgent(llm, source_graph)
        self.assertEqual(await agent.run([entry]), [])
        self.assertEqual(len(llm.calls), 1)
        self.assertIn(parser.function_id,
                      agent.continuations[0]["next_function_ids"])
        self.assertTrue(any(
            "source-linked input-consumer candidate(s)" in obligation
            and parser.function_id in obligation
            for obligation in agent.inventory_obligations
        ))

    async def test_unrelated_parameter_calls_do_not_enter_input_worklist(self):
        call_lines = "".join(
            f"  if (cfg == {index}) inspect_{index}(cfg);\n"
            for index in range(30)
        )
        reader_source = (
            "int receive_one(int fd, int cfg) {\n"
            "  char data[1];\n"
            "  read(fd, data, 1);\n"
            + call_lines + "  return data[0];\n}"
        )
        reader = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd, int cfg)",
            file="daemon.c", start_line=1,
            end_line=len(reader_source.splitlines()), source=reader_source,
        )
        helpers = [FunctionMetadata.create(
            name=f"inspect_{index}", signature=f"int inspect_{index}(int cfg)",
            file="daemon.c", start_line=100 + index,
            end_line=100 + index,
            source=f"int inspect_{index}(int cfg) {{ return cfg; }}",
        ) for index in range(30)]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in [reader, *helpers]},
            edges=[CallEdge(
                f"guard-{index}", reader.function_id, helper.function_id,
                4 + index, "direct",
            ) for index, helper in enumerate(helpers)],
        ))
        entry = EntryRecord(
            entry_id="cfg-guard-entry", candidate_id="cfg-guard-candidate",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[Evidence(
                "source", reader.function_id, reader.file, 3, "read input",
            )], unknowns=[], verifier_confidence=0.99, entry_line=3,
            first_acquisition_confirmed=True,
        )
        llm = ScriptedLLM([{
            "actions": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "no action yet",
        }])
        agent = InputActionAgent(llm, graph)
        actions = await agent.run([entry])
        self.assertEqual(actions, [])
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(agent.continuations[0]["next_function_ids"], [])
        self.assertTrue(any("did not complete" in item
                            for item in agent.inventory_obligations))

    async def test_internal_if_in_entry_is_not_proven_external_action(self) -> None:
        handler = FunctionMetadata.create(
            name="handler", signature="int handler(void)", file="daemon.c",
            start_line=7, end_line=7,
            source="int handler(void) { return 1; }",
        )
        for condition, expected in (
            ("config", ProofStatus.POSSIBLE),
            ("data[0] == 'A'", ProofStatus.POSSIBLE),
        ):
            with self.subTest(condition=condition):
                receive = FunctionMetadata.create(
                    name="receive_one", signature="int receive_one(int fd)",
                    file="daemon.c", start_line=1, end_line=6,
                    source=(
                        "int receive_one(int fd) {\n"
                        "  char data[1];\n"
                        "  read(fd, data, 1);\n"
                        f"  if ({condition}) return handler();\n"
                        "  return 0;\n}"
                    ),
                )
                graph = GraphStore(AnalysisBundle(
                    functions={item.function_id: item for item in (receive, handler)},
                    edges=[CallEdge(
                        "receive-handler", receive.function_id,
                        handler.function_id, 4, "direct",
                    )],
                ))
                entry = EntryRecord(
                    entry_id="entry-guard", candidate_id="entry-guard",
                    status=Verdict.VERIFIED,
                    entry_function_id=receive.function_id,
                    source_api="read", channel_kind="stdin",
                    attacker_control="local", provenance_path=[],
                    consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.99, entry_line=3,
                    first_acquisition_confirmed=True,
                )
                root_citation = dict(
                    kind="source", function_id=receive.function_id,
                    line=4, detail="guard before handler",
                )
                handler_citation = dict(
                    kind="source", function_id=handler.function_id,
                    line=7, detail="handler effect",
                )
                raw = dict(
                    name="claimed request", description="claimed external effect",
                    dispatcher_function_id=receive.function_id,
                    handler_function_id=handler.function_id,
                    discriminator="", fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="A",
                                   origin="source_candidate", evidence=[root_citation])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[handler_citation], failure_evidence=[],
                    response_bindings=[], evidence=[root_citation, handler_citation],
                    unknowns=[], confidence=0.9, action_context_complete=True,
                )
                action = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                    entry, [raw], [receive.function_id, handler.function_id], [],
                    context_complete=True,
                )[0]
                self.assertEqual(action.status, expected)
                if expected is ProofStatus.POSSIBLE:
                    self.assertTrue(any("internal guard" in value
                                        for value in action.unknowns))

    async def test_unrelated_input_guard_cannot_prove_handler_selection(self) -> None:
        receive = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd, int config)",
            file="daemon.c", start_line=1, end_line=7,
            source=(
                "int receive_one(int fd, int config) {\n"
                "  char data[1];\n"
                "  read(fd, data, 1);\n"
                "  if (data[0]) log_input();\n"
                "  if (config) return handler();\n"
                "  return 0;\n}"
            ),
        )
        handler = FunctionMetadata.create(
            name="handler", signature="int handler(void)",
            file="daemon.c", start_line=10, end_line=10,
            source="int handler(void) { return 1; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (receive, handler)},
            edges=[CallEdge("handler-call", receive.function_id,
                            handler.function_id, 5, "direct")],
        ))
        entry = EntryRecord(
            entry_id="entry-unrelated-guard", candidate_id="candidate-unrelated-guard",
            status=Verdict.VERIFIED, entry_function_id=receive.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=3,
            first_acquisition_confirmed=True,
        )
        source_evidence = [
            dict(kind="source", function_id=receive.function_id, line=4,
                 detail="input checked in a separate branch"),
            dict(kind="source", function_id=handler.function_id, line=10,
                 detail="handler result"),
        ]
        raw = dict(
            name="claimed operation", description="claimed effect",
            dispatcher_function_id=receive.function_id,
            handler_function_id=handler.function_id, discriminator="",
            fields=[], examples=[dict(data_hex="41", bindings=[], rationale="A",
                                     origin="source_candidate", evidence=source_evidence[:1])],
            success_markers_hex=[], failure_markers_hex=[],
            success_evidence=source_evidence[1:], failure_evidence=[],
            response_bindings=[], evidence=source_evidence,
            unknowns=[], confidence=0.9, action_context_complete=True,
        )
        action = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
            entry, [raw], [receive.function_id, handler.function_id], [],
            context_complete=True,
        )[0]
        self.assertEqual(action.status, ProofStatus.POSSIBLE)
        self.assertTrue(any("control" in value or "input" in value
                            for value in action.unknowns))

    async def test_forwarded_input_can_be_unrelated_to_later_handler(self) -> None:
        receive = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd, int config)",
            file="daemon.c", start_line=1, end_line=5,
            source=(
                "int receive_one(int fd, int config) {\n"
                "  char data[1];\n"
                "  read(fd, data, 1);\n"
                "  return dispatch(data, config);\n}"
            ),
        )
        dispatch = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(char *data, int config)",
            file="daemon.c", start_line=10, end_line=15,
            source=(
                "int dispatch(char *data, int config) {\n"
                "  if (data[0]) log_input();\n"
                "  if (config) return handler();\n"
                "  return 0;\n}"
            ),
        )
        handler = FunctionMetadata.create(
            name="handler", signature="int handler(void)",
            file="daemon.c", start_line=20, end_line=20,
            source="int handler(void) { return 1; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (receive, dispatch, handler)},
            edges=[
                CallEdge("dispatch-call", receive.function_id,
                         dispatch.function_id, 4, "direct"),
                CallEdge("handler-call", dispatch.function_id,
                         handler.function_id, 12, "direct"),
            ],
        ))
        entry = EntryRecord(
            entry_id="entry-forwarded-guard", candidate_id="candidate-forwarded-guard",
            status=Verdict.VERIFIED, entry_function_id=receive.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=3,
            first_acquisition_confirmed=True,
        )
        source_evidence = [
            dict(kind="source", function_id=dispatch.function_id, line=11,
                 detail="input checked in a separate branch"),
            dict(kind="source", function_id=handler.function_id, line=20,
                 detail="handler result"),
        ]
        raw = dict(
            name="claimed operation", description="claimed effect",
            dispatcher_function_id=dispatch.function_id,
            handler_function_id=handler.function_id, discriminator="",
            fields=[], examples=[dict(data_hex="41", bindings=[], rationale="A",
                                     origin="source_candidate", evidence=source_evidence[:1])],
            success_markers_hex=[], failure_markers_hex=[],
            success_evidence=source_evidence[1:], failure_evidence=[],
            response_bindings=[], evidence=source_evidence,
            unknowns=[], confidence=0.9, action_context_complete=True,
        )
        action = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
            entry, [raw],
            [receive.function_id, dispatch.function_id, handler.function_id], [],
            context_complete=True,
            direct_consumer_ids={dispatch.function_id},
            direct_consumer_taint_names={dispatch.function_id: {"data"}},
        )[0]
        self.assertEqual(action.status, ProofStatus.POSSIBLE)
        self.assertTrue(any("control" in value or "data" in value
                            for value in action.unknowns))

    async def test_reported_call_can_guide_inspection_but_not_prove_input_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int consume(char *data) { return data[0]; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "return consume(data); }\n",
                encoding="utf-8",
            )
            indexed = StaticAnalyzer(root).index()
            functions = {item.name: item for item in indexed.functions.values()}
            receive = functions["receive_one"]
            consume = functions["consume"]
            reported = GraphStore(AnalysisBundle(
                functions=indexed.functions,
                edges=[CallEdge(
                    "introspector-only", receive.function_id,
                    consume.function_id, receive.start_line, "reported",
                )],
            ))
            entry = EntryRecord(
                entry_id="reported-input", candidate_id="reported-input",
                status=Verdict.VERIFIED, entry_function_id=receive.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=receive.start_line,
                first_acquisition_confirmed=True,
            )
            proved, _ = source_dataflow_consumers(
                reported, entry, function_limit=len(indexed.functions),
                include_all_consumers=True,
            )
            leads, _ = source_dataflow_consumers(
                reported, entry, function_limit=len(indexed.functions),
                include_all_consumers=True, include_candidate_edges=True,
            )
            self.assertEqual(proved, [])
            self.assertEqual([item[0] for item in leads], [consume.function_id])

    async def test_comment_is_not_a_post_read_field_copy(self) -> None:
        function = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(struct ctx *c, int fd)",
            file="daemon.c", start_line=1, end_line=5,
            source=(
                "int receive_one(struct ctx *c, int fd) {\n"
                "/* c->cursor = c->buf; */\n"
                "read(fd, c->buf, 8);\n"
                "return 1;\n}"
            ),
        )
        entry = EntryRecord(
            entry_id="comment-copy", candidate_id="comment-copy",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=3,
            first_acquisition_confirmed=True,
        )
        self.assertEqual(_entry_receiver_field_names(function, entry), {"buf"})

    async def test_pre_read_alias_stays_with_acquisition_receiver(self) -> None:
        function = FunctionMetadata.create(
            name="receive_one",
            signature="int receive_one(struct ctx *c, struct ctx *other, int fd)",
            file="daemon.c", start_line=1, end_line=5,
            source=(
                "int receive_one(struct ctx *c, struct ctx *other, int fd) {\n"
                "other->cursor = other->buf;\n"
                "c->next = c->buf;\n"
                "read(fd, c->buf, 8);\n"
                "return 1; }"
            ),
        )
        entry = EntryRecord(
            entry_id="owner-alias", candidate_id="owner-alias",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=4,
            first_acquisition_confirmed=True,
        )
        self.assertEqual(
            _entry_receiver_field_names(function, entry, owner_filter="c"),
            {"buf", "next"},
        )
        self.assertNotIn(
            "cursor", _entry_receiver_field_names(
                function, entry, owner_filter="c",
            ),
        )

    async def test_many_if_guards_do_not_create_action_workers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            guards = "\n".join(
                f"if (data[0] == {number}) return {number};"
                for number in range(128)
            )
            source.write_text(
                "#include <unistd.h>\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1);\n"
                + guards + "\nreturn 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            function = next(iter(graph.bundle.functions.values()))
            entry = EntryRecord(
                entry_id="many-guards", candidate_id="many-guards",
                status=Verdict.VERIFIED,
                entry_function_id=function.function_id, source_api="read",
                channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", function.function_id,
                                   function.file, function.start_line,
                                   "read acquires input")],
                unknowns=[], verifier_confidence=0.99,
                entry_line=function.start_line,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([dict(
                actions=[], context_complete=True,
                requested_function_ids=[], rationale="no action established",
            )])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(llm.calls), 1)
            self.assertEqual(agent.planned_branch_validations, 0)
            self.assertEqual(agent.operation_seeds, [])
            self.assertTrue(any(
                "no external Action reconstructed" in item
                for item in agent.inventory_obligations
            ))

    async def test_input_consumer_must_follow_acquisition_in_same_function(self) -> None:
        for call_order, expected_consumer, expected_unresolved in (
            ("consume(data); read(fd, data, 2);", False, False),
            ("read(fd, data, 2); consume(data);", True, False),
            ("read(fd, data, consume(data));", False, False),
            ("sink(read(fd, data, 2), consume(data));", False, True),
        ):
            with self.subTest(call_order=call_order), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "daemon.c").write_text(
                    "#include <unistd.h>\n"
                    "int consume(char *data) { return data[0]; }\n"
                    "int sink(int a, int b) { return a + b; }\n"
                    "int receive_one(int fd) { char data[2] = {0}; "
                    + call_order + " return 0; }\n",
                    encoding="utf-8",
                )
                graph = GraphStore(StaticAnalyzer(root).index())
                receiver = next(item for item in graph.bundle.functions.values()
                                if item.name == "receive_one")
                consumer = next(item for item in graph.bundle.functions.values()
                                if item.name == "consume")
                entry = EntryRecord(
                    entry_id="ordered", candidate_id="ordered-candidate",
                    status=Verdict.VERIFIED,
                    entry_function_id=receiver.function_id,
                    source_api="read", channel_kind="stdin",
                    attacker_control="local", provenance_path=[],
                    consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.99, entry_line=receiver.start_line,
                    first_acquisition_confirmed=True,
                )
                consumers, unresolved = source_dataflow_consumers(
                    graph, entry, function_limit=len(graph.bundle.functions),
                    include_all_consumers=True,
                )
                self.assertEqual(
                    [item[0] for item in consumers],
                    [consumer.function_id] if expected_consumer else [],
                )
                self.assertEqual(unresolved, expected_unresolved)
                if expected_unresolved:
                    navigation, navigation_unresolved = source_dataflow_consumers(
                        graph, entry, function_limit=len(graph.bundle.functions),
                        include_all_consumers=True,
                        include_candidate_edges=True,
                    )
                    self.assertIn(consumer.function_id,
                                  [item[0] for item in navigation])
                    self.assertTrue(navigation_unresolved)

    async def test_post_read_field_handoff_crosses_caller_without_unrelated_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct session { char buf[8]; char *payload; int other; };\n"
                "struct session ses;\n"
                "int process_packet(void) { return ses.payload[0]; }\n"
                "int read_first(int fd) { return read(fd, ses.buf, 8); }\n"
                "int read_packet(int fd) { int n = read_first(fd); "
                "ses.payload = ses.buf; return n; }\n"
                "int session_loop(int fd) { read_packet(fd); "
                "if (ses.payload) return process_packet(); return 0; }\n"
                "int unrelated(int fd) { read_packet(fd); "
                "ses.other = 1; return ses.other; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            acquisition = by_name["read_first"]
            entry = EntryRecord(
                entry_id="return-field", candidate_id="return-field-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=acquisition.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[],
                consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99,
                entry_line=acquisition.start_line,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["read_packet"].function_id],
                     rationale="inspect the return caller"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["session_loop"].function_id],
                     rationale="inspect the session use"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["process_packet"].function_id],
                     rationale="inspect the selected consumer"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="source inspected"),
            ])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in llm.calls],
                ["read_first", "read_packet", "session_loop", "process_packet"],
            )
            self.assertNotIn(
                by_name["unrelated"].function_id,
                [call["payload"]["current_function"]["function_id"]
                 for call in llm.calls],
            )
            self.assertEqual(
                _shared_field_return_callers(
                    graph,
                    [acquisition.function_id, by_name["read_packet"].function_id],
                    _entry_shared_field_paths(acquisition, entry),
                    acquisition.function_id,
                ),
                [(by_name["session_loop"].function_id,
                  by_name["read_packet"].function_id)],
            )

    async def test_field_backed_request_handler_is_opened_as_navigation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; };\n"
                "int handle(struct ctx *c) { return c->buf[0]; }\n"
                "int parse(struct ctx *c) { return handle(c); }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return parse(c); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver, parser, handler = (
                by_name["receive_one"], by_name["parse"], by_name["handle"]
            )
            entry = EntryRecord(
                entry_id="field-backed", candidate_id="field-backed-candidate",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[parser.function_id],
                evidence=[], unknowns=[], verifier_confidence=0.99,
                entry_line=receiver.start_line, first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[parser.function_id],
                     rationale="inspect receiver handoff"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[handler.function_id],
                     rationale="inspect field consumer"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="source inspected"),
            ])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in llm.calls],
                ["receive_one", "parse", "handle"],
            )
            self.assertNotIn(
                handler.function_id,
                [item for continuation in agent.continuations
                 for item in continuation["next_function_ids"]],
            )

    async def test_receiver_handoff_ignores_unrelated_guards_and_wrong_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; int ready; };\n"
                "int use_input(struct ctx *x) { return x->buf[0]; }\n"
                "int forward(struct ctx *x) { return use_input(x); }\n"
                "int guard(struct ctx *x) { if (x->ready) return 1; return 0; }\n"
                "int receive_one(struct ctx *c, struct ctx *other, int fd) { "
                "forward(c); read(fd, c->buf, 8); "
                "guard(c); forward(other); return forward(c); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="receiver-guard", candidate_id="receiver-guard-candidate",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            self.assertEqual(
                source_receiver_field_navigation_candidates(graph, entry),
                [by_name["forward"].function_id,
                 by_name["use_input"].function_id],
            )

    async def test_pre_read_pointer_copy_leads_to_direct_field_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; char *cursor; };\n"
                "int parse(struct ctx *c) { return c->cursor[0]; }\n"
                "int receive_one(struct ctx *c, int fd) {\n"
                "  c->cursor = c->buf;\n"
                "  read(fd, c->buf, 8);\n"
                "  return parse(c);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="pre-read-alias", candidate_id="pre-read-alias",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=6,
                first_acquisition_confirmed=True,
            )
            self.assertEqual(
                source_receiver_field_navigation_candidates(graph, entry),
                [by_name["parse"].function_id],
            )

    async def test_post_read_callback_follows_copied_field_to_dispatcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; char *cursor; int ready; "
                "int (*next)(struct ctx *); };\n"
                "int store(struct ctx *c) { return ++c->ready; }\n"
                "int dispatch(struct ctx *c) { "
                "if (c->cursor[0] == 'S') return store(c); return 0; }\n"
                "int binary(struct ctx *c) { "
                "if (c->cursor[0]) return dispatch(c); return 0; }\n"
                "int ascii(struct ctx *c) { return c->buf[0]; }\n"
                "int parse(struct ctx *c) { "
                "if (c->buf[0] == 'B') return binary(c); return ascii(c); }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "c->cursor = c->buf; read(fd, c->buf, 8); return 1; }\n"
                "int drive(struct ctx *c, int fd) {\n"
                "if (receive_one(c, fd))\n"
                "    return c->next(c);\n"
                "return 0; }\n"
                "void setup(struct ctx *c) { c->next = parse; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            acquisition = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="callback-field", candidate_id="callback-field-candidate",
                status=Verdict.VERIFIED, entry_function_id=acquisition.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=acquisition.start_line,
                first_acquisition_confirmed=True,
            )
            self.assertEqual(
                _entry_receiver_field_names(acquisition, entry),
                {"buf", "cursor"},
            )
            model = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["drive"].function_id],
                     rationale="inspect return caller"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["parse"].function_id],
                     rationale="inspect callback target"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["binary"].function_id],
                     rationale="inspect input-selected path"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["dispatch"].function_id],
                     rationale="inspect semantic operation"),
                dict(actions=[], context_complete=True, requested_function_ids=[],
                     rationale="source inspected"),
            ])
            agent = InputActionAgent(model, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened_names = [
                call["payload"]["current_function"]["name"]
                for call in model.calls
            ]
            self.assertIn("dispatch", opened_names)
            self.assertNotIn("store", opened_names)
            self.assertLess(opened_names.index("receive_one"),
                            opened_names.index("parse"))
            self.assertLess(opened_names.index("parse"),
                            opened_names.index("binary"))
            self.assertLess(opened_names.index("binary"),
                            opened_names.index("dispatch"))

    async def test_requested_path_is_opened_before_unrequested_field_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; int (*next)(struct ctx *); };\n"
                "int binary(struct ctx *c) { return c->buf[1]; }\n"
                "int ascii_detail(struct ctx *c) { return c->buf[2]; }\n"
                "int ascii(struct ctx *c) { if (c->buf[0]) return ascii_detail(c); return 0; }\n"
                "int parse(struct ctx *c) { "
                "if (c->buf[0] == 'B') return binary(c); return ascii(c); }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return 1; }\n"
                "int drive(struct ctx *c, int fd) {\n"
                "if (receive_one(c, fd))\n"
                "    return c->next(c);\n"
                "return 0; }\n"
                "void setup(struct ctx *c) { c->next = parse; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="sibling-first", candidate_id="sibling-first",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )

            class DeepPathLLM(ScriptedLLM):
                def __init__(self):
                    super().__init__([])

                async def complete_json(self, **kwargs):
                    self.calls.append(kwargs)
                    name = kwargs["payload"]["current_function"]["name"]
                    requested = {
                        "parse": [by_name["ascii"].function_id],
                        "ascii": [by_name["ascii_detail"].function_id],
                    }.get(name, [])
                    return dict(
                        actions=[], context_complete=True,
                        requested_function_ids=requested,
                        rationale="follow ASCII path" if requested else "done",
                    )

            llm = DeepPathLLM()
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [
                call["payload"]["current_function"]["name"]
                for call in llm.calls
            ]
            self.assertLess(opened.index("parse"), opened.index("binary"))
            self.assertLess(opened.index("parse"), opened.index("ascii"))
            self.assertLess(opened.index("ascii"), opened.index("ascii_detail"))
            self.assertLess(opened.index("ascii_detail"), opened.index("binary"))
            self.assertIn("ascii", opened)
            self.assertEqual(agent.planned_branch_validations, 0)

    async def test_action_draft_rechecks_source_opened_after_initial_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int consume(char *data) { return data[0]; }\n"
                "int receive_one(int fd) { char data[1]; "
                "read(fd, data, 1); return consume(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver, consumer = by_name["receive_one"], by_name["consume"]
            entry = EntryRecord(
                entry_id="late-source", candidate_id="late-source",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=consumer.function_id,
                line=consumer.start_line, detail="consumer reads the byte",
            )
            raw = dict(
                name="consume byte", description="return one input byte",
                dispatcher_function_id=consumer.function_id,
                handler_function_id=consumer.function_id,
                discriminator="byte", fields=[],
                examples=[dict(data_hex="41", bindings=[], rationale="A",
                               origin="source_candidate", evidence=[citation])],
                success_markers_hex=[], failure_markers_hex=[],
                success_evidence=[citation], failure_evidence=[],
                response_bindings=[], evidence=[citation], confidence=0.9,
                action_context_complete=False,
            )
            llm = ScriptedLLM([
                dict(actions=[{
                    **raw, "unknowns": ["consume has not been opened"],
                }], context_complete=False,
                     requested_function_ids=[consumer.function_id],
                     rationale="need consumer source"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="consumer opened"),
                dict(actions=[
                    {**raw, "unknowns": [
                        "observable effect remains unproven",
                    ]},
                    {**raw, "name": "new review-only claim", "unknowns": []},
                ], context_complete=False,
                     requested_function_ids=[], rationale="reviewed source"),
            ])
            agent = InputActionAgent(llm, graph)
            actions = await agent.run([entry])

            self.assertEqual(len(llm.calls), 3)
            self.assertTrue(llm.calls[2]["payload"]["review_only"])
            self.assertEqual(
                [item["name"] for item in llm.calls[2]["payload"]["already_opened_source_bodies"]],
                ["consume"],
            )
            self.assertIn("consume byte", [
                item["name"] for item in llm.calls[2]["payload"]["stale_action_drafts"]
            ])
            self.assertEqual(len(actions), 1)
            self.assertIn("observable effect remains unproven", actions[0].unknowns)
            self.assertFalse(any(
                "not been opened" in unknown for unknown in actions[0].unknowns
            ))

    async def test_later_action_revision_replaces_earlier_evidence_rich_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int consume(char *data) { return data[0]; }\n"
                "int receive_one(int fd) { char data[1]; "
                "read(fd, data, 1); return consume(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {item.name: item for item in graph.bundle.functions.values()}
            receiver, consumer = functions["receive_one"], functions["consume"]
            entry = EntryRecord(
                entry_id="revised-action", candidate_id="revised-action",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=consumer.function_id,
                line=consumer.start_line, detail="consumer body inspected",
            )
            draft = dict(
                name="consume byte", description="read input byte",
                dispatcher_function_id=consumer.function_id,
                handler_function_id=consumer.function_id,
                discriminator="byte", fields=[],
                examples=[dict(data_hex="41", bindings=[], rationale="A",
                               origin="source_candidate", evidence=[citation])],
                success_markers_hex=[], failure_markers_hex=[],
                success_evidence=[citation], failure_evidence=[],
                response_bindings=[], evidence=[citation], confidence=0.9,
                action_context_complete=False,
                unknowns=["old claim from earlier source turn"],
            )
            revision = {
                **draft,
                "evidence": [], "success_evidence": [], "examples": [],
                "unknowns": ["input effect still needs independent evidence"],
            }
            llm = ScriptedLLM([
                dict(actions=[draft], context_complete=False,
                     requested_function_ids=[consumer.function_id],
                     rationale="inspect consumer"),
                dict(actions=[revision], context_complete=True,
                     requested_function_ids=[], rationale="revised claim"),
            ])
            actions = await InputActionAgent(llm, graph).run([entry])
            self.assertEqual(len(actions), 1)
            self.assertIn(
                "input effect still needs independent evidence", actions[0].unknowns,
            )
            self.assertNotIn("old claim from earlier source turn", actions[0].unknowns)
            self.assertEqual(actions[0].status, ProofStatus.POSSIBLE)

    async def test_next_frontier_does_not_repeat_unrelated_old_callers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int consume(char *data) { return data[0]; }\n"
                "int unrelated(void) { return 7; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "return consume(data) + unrelated(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            consumer = by_name["consume"]
            unrelated = by_name["unrelated"]
            entry = EntryRecord(
                entry_id="focused-frontier", candidate_id="focused-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[consumer.function_id], rationale="inspect input"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="input consumer inspected"),
            ])
            agent = InputActionAgent(llm, graph)
            await agent.run([entry])

            self.assertEqual(len(llm.calls), 2)
            first_frontier = {
                item["function_id"] for item in llm.calls[0]["payload"]["frontier"]
            }
            second_frontier = {
                item["function_id"] for item in llm.calls[1]["payload"]["frontier"]
            }
            self.assertNotIn(unrelated.function_id, first_frontier)
            self.assertNotIn(unrelated.function_id, second_frontier)
            self.assertEqual(
                llm.calls[1]["payload"]["current_function"]["function_id"],
                consumer.function_id,
            )

    async def test_model_can_request_named_effect_helper_outside_input_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int report_result(void) { return 7; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "return report_result(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root, helper = by_name["receive_one"], by_name["report_result"]
            entry = EntryRecord(
                entry_id="effect-helper", candidate_id="effect-helper",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[helper.function_id],
                     rationale="inspect the named result helper"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[], rationale="inspected"),
            ])
            await InputActionAgent(llm, graph).run([entry])
            self.assertNotIn(
                helper.function_id,
                {item["function_id"] for item in llm.calls[0]["payload"]["frontier"]},
            )
            self.assertEqual(
                llm.calls[1]["payload"]["current_function"]["function_id"],
                helper.function_id,
            )

    async def test_unused_input_parameter_does_not_create_action_lead(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int state;\n"
                "int internal(char *request) {\n"
                "  /* request is not read here */\n"
                "  if (state) return 1;\n"
                "  return 0;\n"
                "}\n"
                "int external(char *request) {\n"
                "  if (request[0] == 'A') return 1;\n"
                "  return 0;\n"
                "}\n"
                "int receive_one(int fd) {\n"
                "  char request[2];\n"
                "  read(fd, request, sizeof(request));\n"
                "  return internal(request) + external(request);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="unused-param", candidate_id="unused-param-candidate",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[Evidence(
                    "source", receiver.function_id, receiver.file,
                    receiver.start_line + 2, "read acquires request bytes",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=receiver.start_line + 2,
                first_acquisition_confirmed=True,
            )

            consumers, truncated = source_dataflow_consumers(
                graph, entry, function_limit=len(graph.bundle.functions),
                include_all_consumers=True,
            )
            self.assertFalse(truncated)
            self.assertEqual(
                {item[0] for item in consumers},
                {by_name["internal"].function_id,
                 by_name["external"].function_id},
            )
            internal = by_name["internal"]
            internal_evidence = [{
                "kind": "source", "function_id": internal.function_id,
                "line": internal.start_line + 2,
                "detail": "internal state selects a return value",
            }]
            fabricated = {
                "name": "internal state branch",
                "description": "returns the current internal state",
                "dispatcher_function_id": internal.function_id,
                "handler_function_id": internal.function_id,
                "discriminator": "state", "fields": [],
                "examples": [{
                    "data_hex": "41", "bindings": [],
                    "rationale": "request guess", "origin": "source_candidate",
                    "evidence": internal_evidence,
                }],
                "success_markers_hex": [], "failure_markers_hex": [],
                "success_evidence": internal_evidence,
                "failure_evidence": [], "response_bindings": [],
                "evidence": internal_evidence,
                "unknowns": [], "confidence": 1.0,
                "action_context_complete": True,
            }
            candidate = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                entry, [fabricated],
                [receiver.function_id, internal.function_id], [],
                context_complete=True,
                direct_consumer_ids={item[0] for item in consumers},
                direct_consumer_taint_names={
                    item[0]: item[2] for item in consumers
                },
            )[0]
            self.assertEqual(candidate.status, ProofStatus.POSSIBLE)
            self.assertTrue(any(
                "not visible" in reason for reason in candidate.unknowns
            ))

    async def test_action_proof_is_independent_of_other_unopened_entry_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int request(int fd) { char c; read(fd, &c, 1); "
                "if (c == 'A') return 1; return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            root = next(iter(graph.bundle.functions.values()))
            entry = EntryRecord(
                entry_id="entry", candidate_id="candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            citation = [{
                "kind": "source", "function_id": root.function_id,
                "line": root.start_line, "detail": "request byte selects the result",
            }]
            raw = {
                "name": "request A", "description": "returns success for A",
                "dispatcher_function_id": root.function_id,
                "handler_function_id": root.function_id,
                "discriminator": "A", "fields": [],
                "examples": [{
                    "data_hex": "41", "bindings": [], "rationale": "source byte A",
                    "origin": "source_candidate", "evidence": citation,
                }],
                "success_markers_hex": [], "failure_markers_hex": [],
                "success_evidence": citation, "failure_evidence": [],
                "response_bindings": [], "evidence": citation,
                "unknowns": [], "confidence": 0.9,
                "action_context_complete": True,
            }
            agent = InputActionAgent(ScriptedLLM([]), graph)
            examined = agent._validate_actions(
                entry, [raw], [root.function_id], [], context_complete=False,
            )
            self.assertEqual(examined[0].status, ProofStatus.POSSIBLE)
            self.assertIn(
                "input-to-effect data or control dependence is not established by the current source locator",
                examined[0].unknowns,
            )
            self.assertFalse(any(
                "context walk did not complete" in unknown
                for unknown in examined[0].unknowns
            ))
            incomplete = agent._validate_actions(
                entry, [{**raw, "action_context_complete": False}],
                [root.function_id], [], context_complete=True,
            )
            self.assertEqual(incomplete[0].status, ProofStatus.POSSIBLE)
            self.assertIn(
                "this Action's source context is incomplete",
                incomplete[0].unknowns,
            )

    async def test_branchless_action_does_not_require_fabricated_dispatcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int consume(int fd) { char c; read(fd, &c, 1); return c; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            handler = next(iter(graph.bundle.functions.values()))
            entry = EntryRecord(
                entry_id="plain-input", candidate_id="plain-candidate",
                status=Verdict.VERIFIED, entry_function_id=handler.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=handler.start_line,
                first_acquisition_confirmed=True,
            )
            citation = [{
                "kind": "source", "function_id": handler.function_id,
                "line": handler.start_line, "detail": "read byte affects result",
            }]
            raw = {
                "name": "consume byte", "description": "return input byte",
                "dispatcher_function_id": None, "discriminator": None,
                "handler_function_id": handler.function_id, "fields": [],
                "examples": [{
                    "data_hex": "41", "bindings": [], "rationale": "input example",
                    "origin": "source_candidate", "evidence": citation,
                }],
                "success_markers_hex": [], "failure_markers_hex": [],
                "success_evidence": citation, "failure_evidence": [],
                "response_bindings": [], "evidence": citation,
                "unknowns": [], "confidence": 0.9,
                "action_context_complete": True,
            }
            required = SEMANTIC_INPUT_ACTION_SCHEMA["properties"]["actions"]["items"]["required"]
            self.assertIn("dispatcher_function_id", required)
            self.assertIn("discriminator", required)
            validate_strict_output_schema(SEMANTIC_INPUT_ACTION_SCHEMA)
            actions = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                entry, [raw], [handler.function_id], [], context_complete=True,
            )
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].status, ProofStatus.POSSIBLE, actions[0].unknowns)
            self.assertEqual(actions[0].discriminator, "")
            self.assertEqual(actions[0].dispatcher_function_id, handler.function_id)
            self.assertEqual(actions[0].operation_seed_ids, [])
            ambiguous = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
                entry, [raw, {**raw, "name": "another invented operation"}],
                [handler.function_id], [], context_complete=True,
            )
            self.assertEqual(len(ambiguous), 1)
            self.assertTrue(all(
                item.status is ProofStatus.POSSIBLE for item in ambiguous
            ))
            self.assertTrue(all(
                any("same complete external request bytes" in reason
                    for reason in item.unknowns)
                for item in ambiguous
            ))
            alternate_handler = replace(
                actions[0], action_id="same-bytes-other-handler",
                handler_function_id="other-handler",
            )
            alternatives = _consolidate_same_request_actions([
                actions[0], alternate_handler,
            ])
            self.assertEqual(len(alternatives), 2)
            self.assertTrue(all(
                item.status is ProofStatus.POSSIBLE for item in alternatives
            ))
            different_effect = replace(
                actions[0], action_id="same-bytes-other-effect",
                description="state dependent alternative effect",
            )
            effect_variants = _consolidate_same_request_actions([
                actions[0], different_effect,
            ])
            self.assertEqual(len(effect_variants), 2)
            self.assertTrue(all(
                item.status is ProofStatus.POSSIBLE for item in effect_variants
            ))

    async def test_source_linked_model_request_takes_priority_before_remaining_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int first(char *data) { return data[0]; }\n"
                "int second(char *data) { return data[0] + 1; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "first(data); return second(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root, first, second = (
                by_name["receive_one"], by_name["first"], by_name["second"]
            )
            entry = EntryRecord(
                entry_id="request-priority", candidate_id="candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[second.function_id], rationale="inspect second"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="second inspected"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="first inspected"),
            ])
            agent = InputActionAgent(llm, graph)
            agent._direct_entry_path = lambda _entry: [
                root.function_id, first.function_id,
            ]
            await agent.run([entry])
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in llm.calls],
                ["receive_one", "second", "first"],
            )
            self.assertFalse(any(
                "direct input-fed function(s) remained" in item
                for item in agent.inventory_obligations
            ))

    async def test_shared_field_transfer_opens_post_read_consumer_as_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct state { char *readbuf; char *payload; };\n"
                "struct state ses;\n"
                "char *buffer_writeptr(char *p) { return p; }\n"
                "int acquire(int fd) { return read(fd, buffer_writeptr(ses.readbuf), 1); }\n"
                "void decrypt(void) { ses.payload = ses.readbuf; }\n"
                "int parse(void) { return ses.payload[0]; }\n"
                "void read_packet(int fd) { acquire(fd); decrypt(); }\n"
                "int session_loop(int fd) { read_packet(fd); "
                "if (ses.payload) return parse(); return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            root = by_name["acquire"]
            entry = EntryRecord(
                entry_id="shared-field", candidate_id="shared-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[],
                consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            fields = _entry_shared_field_paths(root, entry)
            self.assertEqual(fields, {"ses.readbuf"})
            initial_opened = [
                by_name[name].function_id for name in (
                    "acquire", "buffer_writeptr", "read_packet", "session_loop",
                )
            ]
            leads = _shared_field_handoff_candidates(
                graph, entry, initial_opened, fields,
            )
            self.assertEqual(leads[0][0], by_name["decrypt"].function_id)
            self.assertNotIn(
                by_name["parse"].function_id,
                {item[0] for item in leads},
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": False,
                "requested_function_ids": [by_name[name].function_id],
                "rationale": f"inspect {name}",
            } for name in ("buffer_writeptr", "read_packet", "session_loop",
                           "decrypt", "parse")] + [{
                "actions": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "done",
            }])
            agent = InputActionAgent(llm, graph)
            actions, _seeds = await agent._run_entry(entry)
            opened = [
                call["payload"]["current_function"]["name"]
                for call in llm.calls
            ]
            self.assertEqual(opened, [
                "acquire", "buffer_writeptr", "read_packet",
                "session_loop", "decrypt", "parse",
            ])
            self.assertEqual(actions, [])

    async def test_unrelated_field_assignment_does_not_create_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct state { char *readbuf; char *payload; };\n"
                "struct state ses, other;\n"
                "int acquire(int fd) { return read(fd, ses.readbuf, 1); }\n"
                "void transform(void) { /* ses.payload = ses.readbuf; */ "
                "ses.payload = other.readbuf; }\n"
                "int parse(void) { return ses.payload[0]; }\n"
                "void run(int fd) { acquire(fd); transform(); parse(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            root = by_name["acquire"]
            entry = EntryRecord(
                entry_id="unrelated-field", candidate_id="unrelated-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[],
                consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            fields = _entry_shared_field_paths(root, entry)
            leads = _shared_field_handoff_candidates(
                graph, entry,
                [root.function_id, by_name["run"].function_id,
                 by_name["transform"].function_id],
                fields,
            )
            self.assertNotIn(
                by_name["parse"].function_id,
                {item[0] for item in leads},
            )

    async def test_member_argument_with_same_name_is_not_direct_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct session { char *data; };\n"
                "int parse(char *value) { return value[0]; }\n"
                "int receive_one(int fd, struct session *other) {\n"
                "  char data[4];\n"
                "  read(fd, data, 4);\n"
                "  return parse(other->data);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            receiver = next(
                item for item in graph.bundle.functions.values()
                if item.name == "receive_one"
            )
            entry = EntryRecord(
                entry_id="member-argument", candidate_id="member-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[],
                consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=6,
                first_acquisition_confirmed=True,
            )
            consumers, truncated = source_dataflow_consumers(
                graph, entry, function_limit=len(graph.bundle.functions),
                include_all_consumers=True,
            )
            self.assertFalse(truncated)
            self.assertEqual(consumers, [])

    async def test_entry_taint_never_falls_back_to_other_read_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int receive_two(int fd) {\n"
                "  char first[8], second[8];\n"
                "  read(fd, first, 8);\n"
                "  read(fd, second, 8);\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            function = next(iter(graph.bundle.functions.values()))
            entry = EntryRecord(
                entry_id="second-read", candidate_id="second-candidate",
                status=Verdict.VERIFIED, entry_function_id=function.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=5,
                first_acquisition_confirmed=True,
            )
            self.assertEqual(_entry_destination_names(function, entry), {"second"})
            entry.entry_line = 9
            self.assertEqual(_entry_destination_names(function, entry), set())

    async def test_same_field_name_on_different_objects_is_not_input_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct session { char buf[4]; };\n"
                "int parse(char *data) { return data[0]; }\n"
                "int receive_one(int fd, struct session *a, struct session *b) {\n"
                "  read(fd, a->buf, 4);\n"
                "  return parse(b->buf);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            receiver = next(
                item for item in graph.bundle.functions.values()
                if item.name == "receive_one"
            )
            entry = EntryRecord(
                entry_id="field-read", candidate_id="field-candidate",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=5,
                first_acquisition_confirmed=True,
            )
            agent = InputActionAgent(ScriptedLLM([]), graph)
            self.assertEqual(_entry_destination_names(receiver, entry), set())
            self.assertEqual(
                agent._source_dataflow_dispatchers(
                    entry, function_limit=len(graph.bundle.functions),
                    include_all_consumers=True,
                ),
                ([], False),
            )

    async def test_nested_pointer_destination_opens_helper_without_claiming_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct session { unsigned char data[8]; };\n"
                "unsigned char* buffer_ptr(struct session *s) { return s->data; }\n"
                "int receive_one(int fd, struct session *s) { "
                "return read(fd, buffer_ptr(s), 8); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="nested-destination", candidate_id="nested-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", root.function_id, root.file,
                                   root.start_line, "read acquires bytes")],
                unknowns=[], verifier_confidence=0.99,
                entry_line=root.start_line, first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[by_name["buffer_ptr"].function_id],
                     rationale="inspect destination helper"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="helper seen"),
            ])
            events: list[str] = []
            agent = InputActionAgent(
                llm, graph,
                trace=lambda _agent, event_name, _details: events.append(event_name),
            )

            actions = await agent.run([entry])

            self.assertEqual(actions, [])
            self.assertEqual(len(llm.calls), 2)
            self.assertEqual(
                llm.calls[1]["payload"]["current_function"]["function_id"],
                by_name["buffer_ptr"].function_id,
            )
            self.assertIn("function_opened", events)
            self.assertTrue(any(
                "acquisition destination was not resolved" in item
                for item in agent.inventory_obligations
            ))

    async def test_empty_completion_cannot_hide_a_direct_input_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int parse(char *data) { return data[0]; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "return parse(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver, parser = by_name["receive_one"], by_name["parse"]
            entry = EntryRecord(
                entry_id="branchless-read", candidate_id="branchless-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[],
                consumer_hints=[], evidence=[Evidence(
                    "source", receiver.function_id, receiver.file,
                    receiver.start_line, "read acquires external bytes",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=parser.function_id,
                line=parser.start_line,
                detail="parse consumes the acquired byte",
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=True,
                     requested_function_ids=[], rationale="no Action"),
                dict(actions=[dict(
                    name="parse byte", description="process input byte",
                    dispatcher_function_id=parser.function_id,
                    handler_function_id=parser.function_id,
                    discriminator="byte", fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="A",
                                   origin="source_candidate", evidence=[citation])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9,
                )], context_complete=True, requested_function_ids=[],
                     rationale="input consumer found"),
            ])
            agent = InputActionAgent(llm, graph)

            actions = await agent.run([entry])

            self.assertEqual(len(llm.calls), 2)
            self.assertEqual([item.name for item in actions], ["parse byte"])
            self.assertFalse(any(
                "direct input-fed function(s) remained" in item
                for item in agent.inventory_obligations
            ))

    async def test_empty_completion_opens_unique_source_return_caller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct session { char buf[1]; };\n"
                "int receive_one(int fd, struct session *s) { "
                "return read(fd, s->buf, 1); }\n"
                "int parse(char *data) { return data[0]; }\n"
                "int serve(int fd) { struct session s; "
                "receive_one(fd, &s); return parse(s.buf); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver, caller, parser = (
                by_name["receive_one"], by_name["serve"], by_name["parse"]
            )
            entry = EntryRecord(
                entry_id="field-read", candidate_id="field-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="local", provenance_path=[],
                consumer_hints=[], evidence=[Evidence(
                    "source", receiver.function_id, receiver.file,
                    receiver.start_line, "read writes the session buffer",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=parser.function_id,
                line=parser.start_line, detail="parse consumes session bytes",
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=True,
                     requested_function_ids=[],
                     rationale="prematurely stop at field-backed read"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[parser.function_id],
                     rationale="caller forwards the field to parse"),
                dict(actions=[dict(
                    name="parse byte", description="process session input",
                    dispatcher_function_id=parser.function_id,
                    handler_function_id=parser.function_id,
                    discriminator="byte", fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="A",
                                   origin="source_candidate", evidence=[citation])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9,
                )], context_complete=True, requested_function_ids=[],
                     rationale="parser inspected"),
            ])
            events: list[tuple[str, str, dict]] = []
            agent = InputActionAgent(
                llm, graph,
                trace=lambda agent_name, event_name, details: events.append(
                    (agent_name, event_name, details)
                ),
            )

            actions = await agent.run([entry])

            self.assertEqual(len(llm.calls), 3)
            self.assertEqual(actions[0].name, "parse byte")
            self.assertEqual(actions[0].status, ProofStatus.POSSIBLE)
            self.assertTrue(any(
                "input-value flow" in item for item in actions[0].unknowns
            ))
            self.assertTrue(any(
                agent_name == "input_action" and event_name == "function_opened"
                and details.get("function", {}).get("function_id") == caller.function_id
                for agent_name, event_name, details in events
            ))

    async def test_first_action_does_not_hide_another_input_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int first(char *data) { return data[0]; }\n"
                "int second(char *data) { return data[0] + 1; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "first(data); return second(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            consumers = [by_name["first"], by_name["second"]]
            entry = EntryRecord(
                entry_id="two-consumers", candidate_id="two-consumer-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", root.function_id, root.file,
                                   root.start_line, "read acquires bytes")],
                unknowns=[], verifier_confidence=0.99,
                entry_line=root.start_line, first_acquisition_confirmed=True,
            )

            def action(function):
                citation = dict(
                    kind="source", function_id=function.function_id,
                    line=function.start_line, detail="consumes acquired bytes",
                )
                return dict(
                    name=function.name, description="process input",
                    dispatcher_function_id=function.function_id,
                    handler_function_id=function.function_id,
                    discriminator="byte", fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="trial",
                                   origin="source_candidate", evidence=[citation])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9,
                )

            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[consumers[0].function_id],
                     rationale="inspect first"),
                dict(actions=[action(consumers[0])], context_complete=False,
                     requested_function_ids=[consumers[1].function_id],
                     rationale="inspect second"),
                dict(actions=[action(consumers[1])], context_complete=True,
                     requested_function_ids=[], rationale="second complete"),
            ])
            agent = InputActionAgent(llm, graph)
            actions = await agent.run([entry])

            self.assertEqual(len(llm.calls), 3)
            self.assertEqual({item.name for item in actions}, {"first", "second"})
            self.assertFalse(any(
                "direct input-fed function(s) remained" in item
                for item in agent.inventory_obligations
            ))

    async def test_empty_model_request_preserves_ambiguous_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int first(char *data) { return data[0]; }\n"
                "int second(char *data) { return data[0] + 1; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "first(data); return second(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="source-linked-consumers", candidate_id="source-linked",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", root.function_id, root.file,
                                   root.start_line, "read acquires bytes")],
                unknowns=[], verifier_confidence=0.99,
                entry_line=root.start_line, first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([dict(
                actions=[], context_complete=True,
                requested_function_ids=[], rationale="stop at read",
            )])
            agent = InputActionAgent(llm, graph)
            await agent.run([entry])

            self.assertEqual(
                [call["payload"]["current_function"]["name"] for call in llm.calls],
                ["receive_one"],
            )
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name["first"].function_id, by_name["second"].function_id},
            )
            self.assertTrue(any(
                "direct input-fed function(s) remained" in item
                for item in agent.inventory_obligations
            ))
            resumed_llm = ScriptedLLM([dict(
                actions=[], context_complete=True,
                requested_function_ids=[], rationale="continue recorded input use",
            ) for _ in range(2)])
            resumed = InputActionAgent(
                resumed_llm, graph,
                resume_continuations=agent.continuations,
            )
            self.assertEqual(await resumed.run([entry]), [])
            self.assertEqual(len(resumed_llm.calls), 2)
            resumed_names = [
                call["payload"]["current_function"]["name"]
                for call in resumed_llm.calls
            ]
            self.assertEqual(resumed_names[0], "receive_one")
            self.assertIn(resumed_names[1], {"first", "second"})
            self.assertEqual(
                len(set(resumed.continuations[0]["next_function_ids"]) &
                    {by_name["first"].function_id,
                     by_name["second"].function_id}),
                1,
            )

    async def test_completed_action_does_not_sweep_unproved_field_neighbor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; int (*next)(struct ctx *); };\n"
                "int parse(struct ctx *c) { return c->buf[1]; }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); if (c->buf[0] == 'A') return 1; "
                "return 0; }\n"
                "int drive(struct ctx *c, int fd) { "
                "if (receive_one(c, fd)) return c->next(c); return 0; }\n"
                "void setup(struct ctx *c) { c->next = parse; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            neighbor = by_name["drive"]
            entry = EntryRecord(
                entry_id="field-neighbor", candidate_id="field-neighbor-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=root.function_id,
                line=root.start_line, detail="input byte selects the return",
            )
            llm = ScriptedLLM([dict(
                actions=[dict(
                    name="A request", description="return selected result",
                    dispatcher_function_id=root.function_id,
                    handler_function_id=root.function_id,
                    discriminator="A", fields=[], examples=[],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9, action_context_complete=True,
                )], context_complete=True, requested_function_ids=[],
                rationale="all externally selected operations are inventoried",
            )])
            agent = InputActionAgent(llm, graph)
            await agent.run([entry])
            self.assertEqual(len(llm.calls), 1)
            self.assertIn(
                neighbor.function_id,
                [item["function_id"]
                 for item in llm.calls[0]["payload"]["frontier"]],
            )
            self.assertIn(
                neighbor.function_id,
                agent.continuations[0]["next_function_ids"],
            )

    async def test_field_backed_read_preserves_ambiguous_callback_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "struct ctx { char buf[8]; int (*next)(struct ctx *); };\n"
                "int parse_a(struct ctx *c) { return c->buf[0]; }\n"
                "int parse_b(struct ctx *c) { return c->buf[1]; }\n"
                "int receive_one(struct ctx *c, int fd) { "
                "read(fd, c->buf, 8); return 1; }\n"
                "int drive(struct ctx *c, int fd) {\n"
                "if (receive_one(c, fd))\n"
                "  return c->next(c);\n"
                "return 0; }\n"
                "void setup(struct ctx *c, int mode) { "
                "if (mode) c->next = parse_a; else c->next = parse_b; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="two-callbacks", candidate_id="two-callbacks-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[], rationale="follow return"),
                dict(actions=[], context_complete=False,
                     requested_function_ids=[], rationale="callbacks unresolved"),
            ])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            opened = [call["payload"]["current_function"]["name"]
                      for call in llm.calls]
            self.assertEqual(opened[:2], ["receive_one", "drive"])
            self.assertEqual(opened, ["receive_one", "drive"])
            self.assertTrue(agent.continuations)
            self.assertTrue({
                by_name["parse_a"].function_id,
                by_name["parse_b"].function_id,
            }.issubset(set(agent.continuations[0]["next_function_ids"])))
            self.assertEqual(agent.planned_branch_validations, 0)


    async def test_many_guarded_input_consumers_wait_for_evidenced_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            count = 30
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                + "\n".join(
                    f"int sink_{index}(char *data) {{ return data[0]; }}"
                    for index in range(count)
                )
                + "\nint receive_one(int fd) { char data[1]; read(fd, data, 1); "
                + " ".join(
                    f"if (data[0] == {index}) sink_{index}(data);"
                    for index in range(count)
                )
                + " return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="many-consumers", candidate_id="many-consumers-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", root.function_id, root.file,
                                   root.start_line, "read acquires bytes")],
                unknowns=[], verifier_confidence=0.99,
                entry_line=root.start_line, first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([dict(
                actions=[], context_complete=True,
                requested_function_ids=[], rationale="inspect the remaining input uses",
            )])
            agent = InputActionAgent(llm, graph)
            actions = await agent.run([entry])
            self.assertEqual(actions, [])
            self.assertEqual(len(llm.calls), 1)
            self.assertEqual(agent.planned_branch_validations, 0)
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name[f"sink_{index}"].function_id for index in range(count)},
            )

    async def test_many_controlled_calls_are_preserved_without_serial_sweep(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            count = 30
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                + "\n".join(
                    f"int effect_{index}(void) {{ return {index}; }}"
                    for index in range(count)
                )
                + "\nint receive_one(int fd) {\n"
                + "  char input[1]; read(fd, input, 1);\n"
                + "\n".join(
                    f"  if (input[0] == {index}) effect_{index}();"
                    for index in range(count)
                )
                + "\n  return 0;\n}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="many-controlled", candidate_id="many-controlled",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99,
                entry_line=reader.start_line + 1,
                first_acquisition_confirmed=True,
            )
            llm = ScriptedLLM([{
                "actions": [], "context_complete": True,
                "requested_function_ids": [],
                "rationale": "guard alternatives are not yet distinguished",
            }])
            agent = InputActionAgent(llm, graph)
            self.assertEqual(await agent.run([entry]), [])
            self.assertEqual(len(llm.calls), 1)
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]),
                {by_name[f"effect_{index}"].function_id
                 for index in range(count)},
            )

    async def test_recorded_action_frontier_resumes_one_source_lead(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int effect_a(void) { return 1; }\n"
                "int effect_b(void) { return 2; }\n"
                "int receive_one(int fd) { char input[1]; "
                "read(fd, input, 1); "
                "if (input[0] == 'A') effect_a(); "
                "if (input[0] == 'B') effect_b(); return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="resume-controlled", candidate_id="resume-controlled",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line,
                first_acquisition_confirmed=True,
            )
            first = dict(actions=[], context_complete=False,
                         requested_function_ids=[], rationale="two possible calls")
            trajectory = root / "llm.jsonl"
            with trajectory.open("w", encoding="utf-8") as stream:
                def persist(record):
                    stream.write(json.dumps(record) + "\n")
                    stream.flush()
                recorded = RecordingLLM(ScriptedLLM([first]), on_record=persist)
                initial = InputActionAgent(recorded, graph)
                self.assertEqual(await initial.run([entry]), [])
            prior = initial.continuations[0]
            self.assertEqual(len(prior["next_function_ids"]), 2)
            live = ScriptedLLM([dict(
                actions=[], context_complete=False,
                requested_function_ids=[], rationale="one effect inspected",
            )])
            cache = CachingLLM(live, trajectory)
            resumed = InputActionAgent(
                cache, graph, resume_continuations=[prior],
            )
            self.assertEqual(await resumed.run([entry]), [])
            self.assertEqual(cache.hits, 1)
            self.assertEqual(cache.checkpoint_resumes, 1)
            self.assertEqual(len(live.calls), 1)
            opened = live.calls[0]["payload"]["current_function"]["function_id"]
            self.assertEqual(opened, prior["next_function_ids"][0])
            checkpoint = live.calls[0]["payload"]["stateful_resume_checkpoint"]
            self.assertIn(
                "Read the full source bodies",
                live.calls[0]["instructions"],
            )
            self.assertEqual(
                {item["function_id"] for item in checkpoint["functions"]},
                {reader.function_id, opened},
            )
            self.assertEqual(
                resumed.continuations[0]["next_function_ids"],
                [prior["next_function_ids"][1]],
            )

    async def test_changed_action_source_disables_recorded_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "daemon.c").write_text(
                "#include <unistd.h>\n"
                "int effect_a(void) { return 1; }\n"
                "int effect_b(void) { return 2; }\n"
                "int receive_one(int fd) { char input[1]; "
                "read(fd, input, 1); "
                "if (input[0] == 'A') effect_a(); "
                "if (input[0] == 'B') effect_b(); return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="changed-controlled", candidate_id="changed-controlled",
                status=Verdict.VERIFIED, entry_function_id=reader.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=reader.start_line,
                first_acquisition_confirmed=True,
            )
            first = dict(actions=[], context_complete=False,
                         requested_function_ids=[], rationale="two calls")
            initial = InputActionAgent(ScriptedLLM([first]), graph)
            await initial.run([entry])
            prior = dict(initial.continuations[0])
            prior["source_fingerprints"] = dict(prior["source_fingerprints"])
            prior["source_fingerprints"][prior["next_function_ids"][0]] = "stale"
            live = ScriptedLLM([first])
            resumed = InputActionAgent(
                live, graph, resume_continuations=[prior],
            )
            await resumed.run([entry])
            self.assertEqual(len(live.calls), 1)
            self.assertTrue(any(
                "does not match" in item for item in resumed.inventory_obligations
            ))

    async def test_unopened_matching_callback_registrations_are_continuations(self) -> None:
        root = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd)",
            file="daemon.c", start_line=1, end_line=1,
            source="int receive_one(int fd) { char data[1]; read(fd, data, 1); return 0; }",
        )
        registrations = [FunctionMetadata.create(
            name=f"setup_{index}", signature=f"void setup_{index}(void)",
            file="daemon.c", start_line=index + 2, end_line=index + 2,
            source=f"void setup_{index}(void) {{}}",
        ) for index in range(3)]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in [root, *registrations]},
            edges=[],
        ))
        graph.callback_registration_candidates = lambda _selected: [
            {
                "function_id": item.function_id,
                "connections": [{
                    "callback_target_function_id": (
                        root.function_id if index < 2 else "unrelated-target"
                    ),
                }],
            }
            for index, item in enumerate(registrations)
        ]
        entry = EntryRecord(
            entry_id="callback-registration", candidate_id="callback-registration",
            status=Verdict.VERIFIED, entry_function_id=root.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.99, entry_line=root.start_line,
            first_acquisition_confirmed=True,
        )
        llm = ScriptedLLM([dict(
            actions=[], context_complete=True, requested_function_ids=[],
            rationale="registration path remains uninspected",
        )])
        agent = InputActionAgent(llm, graph)
        self.assertEqual(await agent.run([entry]), [])
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(
            set(agent.continuations[0]["next_function_ids"]),
            {item.function_id for item in registrations[:2]},
        )

    async def test_completed_action_cannot_close_uninspected_callback_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int receive_one(int fd) { char data[1]; "
                "return read(fd, data, 1); }\n"
                "int callback_a(void) { return 1; }\n"
                "int callback_b(void) { return 2; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="uninspected-callbacks", candidate_id="callback-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            callback_ids = {
                by_name["callback_a"].function_id,
                by_name["callback_b"].function_id,
            }
            graph.callback_slot_candidates = lambda _selected: [
                {
                    "function_id": function_id,
                    "connections": [{
                        "relation": "callback_candidate_caller",
                        "build_target_relation": "overlap",
                    }],
                }
                for function_id in sorted(callback_ids)
            ]
            llm = ScriptedLLM([dict(
                actions=[{"action_context_complete": True}],
                context_complete=True, requested_function_ids=[],
                rationale="first Action appears complete",
            )])
            agent = InputActionAgent(llm, graph)
            agent._validate_actions = lambda *_args, **_kwargs: [
                SimpleNamespace(status=ProofStatus.PROVEN_STATIC)
            ]

            await agent._run_entry(entry)

            self.assertEqual(len(llm.calls), 1)
            self.assertEqual(
                set(agent.continuations[0]["next_function_ids"]), callback_ids,
            )

    async def test_completed_action_does_not_hide_sibling_input_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int first(char *data) { return data[0]; }\n"
                "int second(char *data) { return data[0] + 1; }\n"
                "int receive_one(int fd) { char data[1]; read(fd, data, 1); "
                "first(data); return second(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root, first, second = (
                by_name["receive_one"], by_name["first"], by_name["second"]
            )
            entry = EntryRecord(
                entry_id="completed-first", candidate_id="completed-first-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
                verifier_confidence=0.99, entry_line=root.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=first.function_id,
                line=first.start_line, detail="first input consumer",
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[first.function_id],
                     rationale="inspect first consumer"),
                dict(actions=[dict(
                    name="first operation", description="process first byte",
                    dispatcher_function_id=first.function_id,
                    handler_function_id=first.function_id,
                    discriminator=None, fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="trial",
                                   origin="source_candidate", evidence=[citation])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9, action_context_complete=True,
                )], context_complete=True, requested_function_ids=[],
                     rationale="first operation source complete"),
                dict(actions=[], context_complete=True,
                     requested_function_ids=[],
                     rationale="second direct consumer inspected"),
            ])
            agent = InputActionAgent(llm, graph)
            actions = await agent.run([entry])
            self.assertEqual(len(llm.calls), 3)
            self.assertEqual(len(actions), 1)
            self.assertEqual(
                llm.calls[-1]["payload"]["current_function"]["function_id"],
                second.function_id,
            )
            self.assertFalse(any(
                "direct input-fed function(s) remained" in item
                for item in agent.inventory_obligations
            ))

    async def test_call_edge_without_value_flow_is_not_static_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "char request_byte;\n"
                "int parse_global(void) { return request_byte; }\n"
                "int receive_one(int fd) { read(fd, &request_byte, 1); "
                "return parse_global(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            root, parser = by_name["receive_one"], by_name["parse_global"]
            entry = EntryRecord(
                entry_id="global-read", candidate_id="global-candidate",
                status=Verdict.VERIFIED, entry_function_id=root.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", root.function_id, root.file,
                                   root.start_line, "read acquires bytes")],
                unknowns=[], verifier_confidence=0.99,
                entry_line=root.start_line, first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=parser.function_id,
                line=parser.start_line, detail="reads global field",
            )
            llm = ScriptedLLM([
                dict(actions=[], context_complete=False,
                     requested_function_ids=[parser.function_id],
                     rationale="inspect parser"),
                dict(actions=[dict(
                    name="parse global", description="use acquired byte",
                    dispatcher_function_id=parser.function_id,
                    handler_function_id=parser.function_id,
                    discriminator="byte", fields=[],
                    examples=[dict(data_hex="41", bindings=[], rationale="trial",
                                   origin="source_candidate", evidence=[citation])],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9,
                )], context_complete=True, requested_function_ids=[],
                     rationale="parser inspected"),
            ])
            actions = await InputActionAgent(llm, graph).run([entry])

            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].status, ProofStatus.POSSIBLE)
            self.assertTrue(any(
                "call/callback path alone" in item
                for item in actions[0].unknowns
            ))

    async def test_entry_handoff_is_not_cut_at_six_or_sixty_four_functions(self) -> None:
        functions = [
            FunctionMetadata.create(
                name=f"stage_{index}", signature=f"void stage_{index}(void)",
                file="daemon.c", start_line=index + 1, end_line=index + 1,
                source=f"void stage_{index}(void) {{}}",
            )
            for index in range(72)
        ]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in functions},
            edges=[
                CallEdge(
                    f"edge-{index}", functions[index].function_id,
                    functions[index + 1].function_id, index + 1, "direct",
                )
                for index in range(len(functions) - 1)
            ],
        ))
        entry = EntryRecord(
            entry_id="long-path", candidate_id="long-path-candidate",
            status=Verdict.VERIFIED,
            entry_function_id=functions[0].function_id,
            source_api="read", channel_kind="stdin",
            attacker_control="local", provenance_path=[],
            consumer_hints=[functions[-1].function_id],
            evidence=[], unknowns=[], verifier_confidence=0.9,
            inspected_function_ids=[item.function_id for item in functions],
        )
        agent = InputActionAgent(ScriptedLLM([]), graph)
        self.assertEqual(
            agent._direct_entry_path(entry),
            [item.function_id for item in functions],
        )

    async def test_field_navigation_keeps_candidates_past_the_old_twelve_limit(self) -> None:
        reader = FunctionMetadata.create(
            name="consume", signature="void consume(Node *n, int fd)",
            file="target.c", start_line=1, end_line=1,
            source=("void consume(Node *n, int fd) { read(fd, n->payload, 8); "
                    "if (n->state) log_state(); use(n->payload); }"),
        )
        writers = [
            FunctionMetadata.create(
                name=f"write_{index}", signature=f"void write_{index}(Node *n)",
                file="target.c", start_line=index + 2, end_line=index + 2,
                source=f"void write_{index}(Node *n) {{ n->payload = {index}; }}",
            )
            for index in range(20)
        ]
        unrelated_writers = [
            FunctionMetadata.create(
                name=f"set_state_{index}",
                signature=f"void set_state_{index}(Node *n)",
                file="target.c", start_line=index + 30, end_line=index + 30,
                source=f"void set_state_{index}(Node *n) {{ n->state = {index}; }}",
            )
            for index in range(20)
        ]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in [
                reader, *writers, *unrelated_writers,
            ]},
            edges=[],
        ))
        entry = EntryRecord(
            entry_id="field-entry", candidate_id="field-candidate",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="network tcp socket",
            attacker_control="remote", provenance_path=[], consumer_hints=[],
            evidence=[], unknowns=[], verifier_confidence=0.9,
            entry_line=1, first_acquisition_confirmed=True,
        )
        agent = InputActionAgent(ScriptedLLM([]), graph)

        choices = agent._choices([reader.function_id], [], entry)

        self.assertEqual(
            {item["function_id"] for item in choices},
            {item.function_id for item in writers},
        )
        self.assertTrue(all(
            any(connection["relation"] == "shared_typed_field_candidate"
                for connection in item["connections"])
            for item in choices
        ))

    async def test_forced_handoff_does_not_erase_a_model_requested_function(self) -> None:
        reader = FunctionMetadata.create(
            name="receive_one", signature="int receive_one(int fd)",
            file="daemon.c", start_line=1, end_line=6,
            source=("int receive_one(int fd) {\n"
                    " char data[4];\n read(fd, data, 4);\n"
                    " hint(data);\n return parser(data);\n}"),
        )
        hint = FunctionMetadata.create(
            name="hint", signature="int hint(char *data)", file="daemon.c",
            start_line=10, end_line=10,
            source="int hint(char *data) { return data[0]; }",
        )
        parser = FunctionMetadata.create(
            name="parser", signature="int parser(char *data)", file="daemon.c",
            start_line=20, end_line=20,
            source="int parser(char *data) { return data[0] == 'A'; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={f.function_id: f for f in (reader, hint, parser)},
            edges=[
                CallEdge("reader-hint", reader.function_id, hint.function_id, 4, "direct"),
                CallEdge("reader-parser", reader.function_id, parser.function_id, 5, "direct"),
            ],
        ))
        entry = EntryRecord(
            entry_id="divergent-handoff", candidate_id="divergent-candidate",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[hint.function_id],
            evidence=[Evidence("source", reader.function_id, reader.file, 3,
                               "read acquires external bytes")],
            unknowns=[], verifier_confidence=0.99, entry_line=3,
            first_acquisition_confirmed=True,
        )
        citation = dict(kind="source", function_id=parser.function_id,
                        line=parser.start_line, detail="parser processes A")
        llm = ScriptedLLM([
            dict(actions=[], context_complete=False,
                 requested_function_ids=[parser.function_id],
                 rationale="open parser"),
            dict(actions=[], context_complete=False,
                 requested_function_ids=[hint.function_id],
                 rationale="inspect hint"),
            dict(actions=[dict(
                name="parse A", description="accept A", discriminator="A",
                dispatcher_function_id=parser.function_id,
                handler_function_id=parser.function_id, fields=[],
                examples=[dict(data_hex="41", bindings=[], rationale="A",
                               origin="source_candidate", evidence=[citation])],
                success_markers_hex=[], failure_markers_hex=[],
                success_evidence=[citation], failure_evidence=[],
                response_bindings=[], evidence=[citation], unknowns=[],
                confidence=0.9,
            )], context_complete=True, requested_function_ids=[],
                 rationale="parser inspected"),
        ])
        actions = await InputActionAgent(llm, graph).run([entry])
        self.assertEqual(len(llm.calls), 3)
        self.assertEqual([item.name for item in actions], ["parse A"])

    async def test_input_flow_continues_past_an_earlier_if_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.c"
            source.write_text(
                "#include <unistd.h>\n"
                "int state;\n"
                "int leaf(unsigned char *p) { if (p[0] == 'G') state = 1; return state; }\n"
                "int guard(unsigned char *p) { if (p[0] != 0) return leaf(p); return 0; }\n"
                "int receive_one(int fd) { unsigned char p[2]; read(fd,p,2); return guard(p); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="guarded-read", candidate_id="guarded-candidate",
                status=Verdict.VERIFIED, entry_function_id=receiver.function_id,
                source_api="read", channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[], evidence=[Evidence(
                    "source", receiver.function_id, receiver.file,
                    receiver.start_line, "read acquires input",
                )], unknowns=[], verifier_confidence=0.99,
                entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            agent = InputActionAgent(ScriptedLLM([]), graph)
            seeds, truncated = agent._inventory_entry(entry)

            self.assertFalse(truncated)
            self.assertEqual(
                {seed.dispatcher_function_id for seed in seeds},
                {by_name["guard"].function_id, by_name["leaf"].function_id},
            )

    async def test_cpp_branchless_input_action_is_not_lost(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "daemon.cpp"
            source.write_text(
                "#include <unistd.h>\n"
                "int parse(const char *data) { return data[0]; }\n"
                "int receive_one(int fd) { char data[1]; read(fd,data,1); "
                "return parse(data); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(Path(temporary)).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receiver, parser = by_name["receive_one"], by_name["parse"]
            entry = EntryRecord(
                entry_id="cpp-read", candidate_id="cpp-read-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=receiver.function_id,
                source_api="read", channel_kind="network tcp socket",
                attacker_control="remote", provenance_path=[],
                consumer_hints=[parser.function_id], evidence=[Evidence(
                    "source", receiver.function_id, receiver.file,
                    receiver.start_line, "read receives one external byte",
                )],
                unknowns=[], verifier_confidence=0.99,
                entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            citation = dict(
                kind="source", function_id=parser.function_id,
                line=parser.start_line,
                detail="parse returns the supplied input byte",
            )
            ordinary = dict(
                actions=[], context_complete=False,
                requested_function_ids=[parser.function_id],
                rationale="open the parser", branch_disposition="UNRESOLVED",
                branch_disposition_evidence=[],
            )
            final = dict(
                actions=[dict(
                    name="parse byte", description="process one external byte",
                    dispatcher_function_id=parser.function_id,
                    handler_function_id=parser.function_id,
                    discriminator="byte", fields=[],
                    examples=[dict(
                        data_hex="41", bindings=[], rationale="one-byte input",
                        origin="source_candidate", evidence=[citation],
                    )],
                    success_markers_hex=[], failure_markers_hex=[],
                    success_evidence=[citation], failure_evidence=[],
                    response_bindings=[], evidence=[citation], unknowns=[],
                    confidence=0.9,
                )],
                context_complete=True, requested_function_ids=[],
                rationale="branchless operation", branch_disposition="NOT_ACTION",
                branch_disposition_evidence=[citation],
            )
            llm = SchemaRecordingLLM([ordinary, final])
            agent = InputActionAgent(llm, graph)

            actions = await agent.run([entry])

            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].name, "parse byte")
            self.assertEqual(agent.planned_branch_validations, 0)
            self.assertEqual(len(llm.calls), 2)
            self.assertTrue(all(
                "branch_disposition" not in schema["properties"]
                and "branch_disposition" not in schema["required"]
                for schema in llm.schemas
            ))

            # A completion claim cannot override an explicit request to read
            # the handler. Losing that next turn silently drops this Action.
            contradictory_llm = ScriptedLLM([
                {**ordinary, "context_complete": True}, final,
            ])
            contradictory_agent = InputActionAgent(contradictory_llm, graph)
            from dataclasses import replace
            unforced_entry = replace(entry, consumer_hints=[])
            continued = await contradictory_agent.run([unforced_entry])
            self.assertEqual(len(continued), 1)
            self.assertEqual(len(contradictory_llm.calls), 2)
            self.assertTrue(any(
                "claimed Action context complete" in obligation
                for obligation in contradictory_agent.inventory_obligations
            ))

    async def test_many_internal_ifs_do_not_create_branch_workers(self) -> None:
        reader_source = (
            "int read_one(int fd) {\n"
            "  char buf[16];\n"
            "  read(fd, buf, sizeof(buf));\n"
            "  return dispatch(buf);\n"
            "}"
        )
        dispatcher_source = (
            "int dispatch(char *buf) {\n"
            + "".join(
                f"  if (state == {index}) tick();\n"
                for index in range(30)
            )
            + "  if (buf[0] == 'A') return 1;\n"
            + "  if (buf[0] == 'B') return 2;\n"
            + "  return 0;\n}"
        )
        reader = FunctionMetadata.create(
            name="read_one", signature="int read_one(int fd)",
            file="target.c", start_line=1,
            end_line=len(reader_source.splitlines()), source=reader_source,
        )
        dispatcher = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(char *buf)",
            file="target.c", start_line=20,
            end_line=19 + len(dispatcher_source.splitlines()),
            source=dispatcher_source,
        )
        tick = FunctionMetadata.create(
            name="tick", signature="int tick(void)", file="target.c",
            start_line=100, end_line=100,
            source="int tick(void) { return 0; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, dispatcher, tick)},
            edges=[CallEdge(
                edge_id="read-dispatch", caller_id=reader.function_id,
                callee_id=dispatcher.function_id, line=reader.start_line + 3,
                kind="direct",
            )],
        ))
        entry = EntryRecord(
            entry_id="external-read", candidate_id="external-read-candidate",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="network tcp socket",
            attacker_control="remote", provenance_path=[],
            consumer_hints=[dispatcher.function_id],
            evidence=[Evidence(
                "source", reader.function_id, reader.file,
                reader.start_line + 2, "read receives external bytes",
            )],
            unknowns=[], verifier_confidence=0.99,
            entry_line=reader.start_line + 2,
            first_acquisition_confirmed=True,
        )

        def action(letter: str, line: int) -> dict:
            source_evidence = [dict(
                kind="source", function_id=dispatcher.function_id,
                line=line, detail=f"{letter} selects this operation",
            )]
            return {
                "name": f"request {letter}", "description": f"respond to {letter}",
                "dispatcher_function_id": dispatcher.function_id,
                "handler_function_id": dispatcher.function_id,
                "discriminator": letter, "fields": [],
                "examples": [dict(
                    data_hex=letter.encode().hex(), bindings=[],
                    rationale="source request form", origin="source_candidate",
                    evidence=source_evidence,
                )],
                "success_markers_hex": ["4f4b"],
                "failure_markers_hex": [],
                "success_evidence": source_evidence,
                "failure_evidence": [], "response_bindings": [],
                "evidence": source_evidence,
                "unknowns": [], "confidence": 0.95,
            }

        first_action_line = dispatcher.start_line + 31
        ordinary = {
            "actions": [], "context_complete": False,
            "requested_function_ids": [dispatcher.function_id],
            "rationale": "open the consumer", "branch_disposition": "UNRESOLVED",
            "branch_disposition_evidence": [],
        }
        final = {
            "actions": [
                action("A", first_action_line),
                action("B", first_action_line + 1),
            ],
            "context_complete": True, "requested_function_ids": [],
            "rationale": "two distinct external request effects",
            "branch_disposition": "ACTION",
            "branch_disposition_evidence": [dict(
                kind="source", function_id=dispatcher.function_id,
                line=first_action_line, detail="request byte controls the result",
            )],
        }
        # Self-reported confidence is not independent source evidence.
        final["actions"][1]["confidence"] = 0.01
        llm = ScriptedLLM([ordinary, final])
        agent = InputActionAgent(llm, graph)

        actions = await agent.run([entry])

        self.assertEqual(len(actions), 2)
        self.assertEqual({item.name for item in actions}, {"request A", "request B"})
        self.assertTrue(all(item.status is ProofStatus.POSSIBLE for item in actions))
        self.assertFalse(any(
            "produced no source-backed external Action candidate" in obligation
            for obligation in agent.inventory_obligations
        ))
        self.assertEqual(agent.planned_branch_validations, 0)
        # Even an ACTION disposition does not license an inventory of every
        # internal guard or switch label as a separate external operation.
        self.assertEqual(agent.operation_seeds, [])
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(agent.budget, len(graph.bundle.functions))

        # A syntactic branch alone never becomes a guessed Action.
        empty_llm = ScriptedLLM([ordinary, {**final, "actions": []}])
        empty_agent = InputActionAgent(empty_llm, graph)
        self.assertEqual(await empty_agent.run([entry]), [])
        self.assertFalse(empty_agent.operation_seeds)
        self.assertTrue(any(
            "produced no source-backed external Action candidate" in obligation
            for obligation in empty_agent.inventory_obligations
        ))
        self.assertEqual(empty_agent.planned_branch_validations, 0)

        unsupported = action("A", first_action_line)
        unsupported["examples"][0]["evidence"] = []
        unsupported_llm = ScriptedLLM([
            ordinary, {**final, "actions": [unsupported]},
        ])
        unsupported_actions = await InputActionAgent(
            unsupported_llm, graph
        ).run([entry])
        self.assertEqual(len(unsupported_actions), 1)
        self.assertEqual(unsupported_actions[0].status, ProofStatus.POSSIBLE)

        # Thirty internal guards can be described with thirty different
        # names, but identical complete request bytes do not establish thirty
        # externally selectable operations.
        guard_claims = []
        for index in range(30):
            claim = action("A", first_action_line)
            claim["name"] = f"internal guard {index}"
            claim["discriminator"] = f"state == {index}"
            guard_claims.append(claim)
        collapsed = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
            entry, guard_claims,
            [reader.function_id, dispatcher.function_id], [],
            context_complete=True,
            direct_consumer_ids={dispatcher.function_id},
        )
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0].status, ProofStatus.POSSIBLE)
        self.assertTrue(any(
            "same complete external request bytes" in reason
            for reason in collapsed[0].unknowns
        ))
        repeated = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
            entry, [action("A", first_action_line)] * 2,
            [reader.function_id, dispatcher.function_id], [],
            context_complete=True,
            direct_consumer_ids={dispatcher.function_id},
        )
        self.assertEqual(len(repeated), 1)
        self.assertEqual(repeated[0].status, ProofStatus.POSSIBLE)

    async def test_possible_callback_edge_is_navigation_not_static_action_proof(self) -> None:
        receive = FunctionMetadata.create(
            name="receive", signature="int receive(int fd)", file="server.c",
            start_line=1, end_line=1,
            source="int receive(int fd) { char b[1]; read(fd,b,1); return dispatch(b); }",
        )
        dispatch = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(char *b)", file="server.c",
            start_line=2, end_line=2,
            source="int dispatch(char *b) { return callback(b); }",
        )
        handle = FunctionMetadata.create(
            name="handle", signature="int handle(char *b)", file="server.c",
            start_line=3, end_line=3,
            source="int handle(char *b) { return b[0] == 'A'; }",
        )
        functions = {item.function_id: item for item in (receive, dispatch, handle)}
        edges = [
            CallEdge("receive-dispatch", receive.function_id,
                     dispatch.function_id, 1, "direct", 1.0),
            CallEdge("possible-callback", dispatch.function_id,
                     handle.function_id, 2, "indirect_possible", 0.5),
        ]
        graph = GraphStore(AnalysisBundle(functions=functions, edges=edges))
        entry = EntryRecord(
            entry_id="callback-entry", candidate_id="callback-candidate",
            status=Verdict.VERIFIED, entry_function_id=receive.function_id,
            source_api="read", channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[dispatch.function_id],
            evidence=[], unknowns=[], verifier_confidence=0.99,
            entry_line=1, first_acquisition_confirmed=True,
        )
        citation_dispatch = dict(kind="source", function_id=dispatch.function_id,
                                 line=2, detail="callback consumes the request")
        citation_handle = dict(kind="source", function_id=handle.function_id,
                               line=3, detail="possible target returns a result")
        raw = dict(
            name="callback result", description="possible callback result",
            dispatcher_function_id=dispatch.function_id,
            handler_function_id=handle.function_id, discriminator="A",
            fields=[], examples=[dict(data_hex="41", bindings=[],
                                     rationale="one byte", origin="source_candidate",
                                     evidence=[citation_dispatch])],
            success_markers_hex=[], failure_markers_hex=[],
            success_evidence=[citation_handle], failure_evidence=[],
            response_bindings=[], evidence=[citation_dispatch, citation_handle],
            unknowns=[], confidence=0.9, action_context_complete=True,
        )
        opened = list(functions)
        self.assertEqual(
            graph.causal_path_from_entry(
                dispatch.function_id, handle.function_id,
                opened_function_ids=opened,
            ),
            [dispatch.function_id, handle.function_id],
        )
        self.assertEqual(
            graph.causal_path_from_entry(
                dispatch.function_id, handle.function_id,
                opened_function_ids=opened, proven_direct_only=True,
            ),
            [],
        )
        candidate = InputActionAgent(ScriptedLLM([]), graph)._validate_actions(
            entry, [raw], opened, [], context_complete=True,
            direct_consumer_ids={dispatch.function_id},
        )[0]
        self.assertEqual(candidate.status, ProofStatus.POSSIBLE)
        self.assertTrue(any("possible indirect" in item for item in candidate.unknowns))

        direct = GraphStore(AnalysisBundle(functions=functions, edges=[
            edges[0], CallEdge("direct-handler", dispatch.function_id,
                               handle.function_id, 2, "direct", 1.0),
        ]))
        proven = InputActionAgent(ScriptedLLM([]), direct)._validate_actions(
            entry, [raw], opened, [], context_complete=True,
            direct_consumer_ids={dispatch.function_id},
        )[0]
        # The graph edge alone does not show that the request value controls
        # or reaches the callback target; the source only says callback(b).
        self.assertEqual(proven.status, ProofStatus.POSSIBLE)
        self.assertTrue(any("dependence" in item for item in proven.unknowns))
        # An opened function name with an unsited citation does not prove
        # that the claimed request bytes or success condition occur in it.
        unsited = {
            **raw,
            "examples": [{
                **raw["examples"][0],
                "evidence": [{**citation_dispatch, "line": None}],
            }],
            "success_evidence": [{**citation_handle, "line": None}],
            "evidence": [
                {**citation_dispatch, "line": None}, citation_handle,
            ],
        }
        candidate = InputActionAgent(ScriptedLLM([]), direct)._validate_actions(
            entry, [unsited], opened, [], context_complete=True,
            direct_consumer_ids={dispatch.function_id},
        )[0]
        self.assertEqual(candidate.status, ProofStatus.POSSIBLE)
        self.assertTrue(any("source-located example" in value
                            for value in candidate.unknowns))
