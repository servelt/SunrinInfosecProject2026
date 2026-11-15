"""Source-path screening must retain uncertainty without inventing Actions."""

from __future__ import annotations

import unittest

from harnesscreator.agents.entry_action_screen import EntryActionScreenAgent
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import AnalysisBundle, CallEdge, EntryRecord, FunctionMetadata, Verdict


def function(name: str, line: int, source: str) -> FunctionMetadata:
    return FunctionMetadata.create(
        name=name, signature=f"int {name}(void)", file="server.c",
        start_line=line, end_line=line + source.count("\n"), source=source,
    )


def entry(reader: FunctionMetadata) -> EntryRecord:
    return EntryRecord(
        entry_id="tcp-entry", candidate_id="tcp-candidate", status=Verdict.VERIFIED,
        entry_function_id=reader.function_id, source_api="recv", channel_kind="tcp",
        attacker_control="full", provenance_path=[], consumer_hints=[], evidence=[],
        unknowns=[], verifier_confidence=0.9, entry_line=reader.start_line,
        first_acquisition_confirmed=True,
    )


def source_line(function_id: str, line: int, text: str) -> dict:
    return {
        "function_id": function_id, "line": line,
        "source_text": text, "data_relation": "input value is passed to parser",
    }


class EntryActionScreenTests(unittest.IsolatedAsyncioTestCase):
    async def test_multiline_acquisition_quote_is_accepted(self):
        reader = function(
            "udp_read", 10,
            "res = recvfrom(fd, buf, size,\n"
            "               0, &addr, &addrlen);\n"
            "if (res > 0) request_id = buf[0];\n",
        )
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "disposition": "SELECTED", "path_function_ids": [reader.function_id],
            "evidence": [
                source_line(reader.function_id, 10,
                            "res = recvfrom(fd, buf, size,\n"
                            "               0, &addr, &addrlen);"),
                source_line(reader.function_id, 12, "request_id = buf[0]"),
            ],
            "requested_function_ids": [], "rationale": "request ID parsed from input",
        }])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "SELECTED")

    async def test_acquisition_line_inside_multiline_quote_is_accepted(self):
        reader = function(
            "udp_read", 10,
            "res = recvfrom(fd, buf, size,\n"
            "               0, &addr, &addrlen);\n"
            "if (res > 0) request_id = buf[0];\n",
        )
        acquired = entry(reader)
        acquired.entry_line = 11
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "disposition": "SELECTED", "path_function_ids": [reader.function_id],
            "evidence": [
                source_line(reader.function_id, 10,
                            "res = recvfrom(fd, buf, size,\n"
                            "               0, &addr, &addrlen);"),
                source_line(reader.function_id, 12, "request_id = buf[0]"),
            ],
            "requested_function_ids": [], "rationale": "request ID parsed from input",
        }])
        result = (await EntryActionScreenAgent(model, graph).run([acquired]))[0]
        self.assertEqual(result.disposition, "SELECTED")

    async def test_unrelated_bad_quote_does_not_erase_supported_route(self):
        reader = function(
            "udp_read", 10,
            "res = recvfrom(fd, buf, size, 0, &addr, &len);\n"
            "if (res > 0) request_id = buf[0];\n",
        )
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "disposition": "SELECTED", "path_function_ids": [reader.function_id],
            "evidence": [
                source_line(reader.function_id, 10,
                            "res = recvfrom(fd, buf, size, 0, &addr, &len);"),
                source_line(reader.function_id, 11, "request_id = buf[0]"),
                source_line(reader.function_id, 11, "not present in the source"),
            ],
            "requested_function_ids": [], "rationale": "request ID parsed from input",
        }])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "SELECTED")
        self.assertEqual(len(result.evidence), 2)

    async def test_single_statement_can_acquire_and_process_input(self):
        reader = function("recv_and_parse", 10, "return parse(recv(fd, buf, size));\n")
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "disposition": "SELECTED", "path_function_ids": [reader.function_id],
            "evidence": [source_line(reader.function_id, 10,
                                     "return parse(recv(fd, buf, size));")],
            "requested_function_ids": [], "rationale": "the same statement parses received bytes",
        }])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "SELECTED")

    async def test_screen_provider_error_remains_incomplete(self):
        reader = function("tcp_read", 10, "return read(fd, buf, size);\n")
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))

        class FailingModel:
            max_concurrency = 1

            async def complete_json(self, **_kwargs):
                raise RuntimeError("provider disconnected")

        result = (await EntryActionScreenAgent(FailingModel(), graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "INCOMPLETE")
        self.assertIn("provider disconnected", result.rationale)

    async def test_registration_quote_may_precede_acquisition_quote(self):
        reader = function("tcp_read", 10, "return read(fd, buf, size);\n")
        caller = function(
            "process_client", 20,
            "res = connection.read(fd, buf, size);\n"
            "return parse(buf);\n",
        )
        registrar = function("init_connection", 30, "connection.read = tcp_read;\n")
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, caller, registrar)},
            edges=[
                CallEdge("caller-to-reader", caller.function_id, reader.function_id),
                CallEdge("registrar-to-caller", registrar.function_id, caller.function_id),
            ],
        ))
        model = ScriptedLLM([
            {"disposition": "INCOMPLETE", "path_function_ids": [], "evidence": [],
             "requested_function_ids": [caller.function_id], "rationale": "inspect caller"},
            {"disposition": "INCOMPLETE", "path_function_ids": [], "evidence": [],
             "requested_function_ids": [registrar.function_id],
             "rationale": "inspect callback registration"},
            {"disposition": "SELECTED",
             "path_function_ids": [reader.function_id, caller.function_id,
                                   registrar.function_id],
             "evidence": [
                 source_line(registrar.function_id, 30, "connection.read = tcp_read"),
                 source_line(reader.function_id, 10, "return read(fd, buf, size)"),
                 source_line(caller.function_id, 20,
                             "res = connection.read(fd, buf, size)"),
                 source_line(caller.function_id, 21, "return parse(buf)"),
             ],
             "requested_function_ids": [], "rationale": "buffer reaches parser"},
        ])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "SELECTED")

    async def test_callback_assignment_links_unconnected_reader_to_invoker(self):
        reader = function("tcp_read", 10, "return read(fd, buf, size);\n")
        caller = function("process_client", 20,
                          "res = connection.read(fd, buf, size);\n")
        registrar = function("init_connection", 30, "connection.read = tcp_read;\n")
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, caller, registrar)},
            edges=[],
        ))
        screen = EntryActionScreenAgent(ScriptedLLM([]), graph)
        evidence = [
            source_line(reader.function_id, 10, "return read(fd, buf, size)"),
            source_line(caller.function_id, 20,
                        "res = connection.read(fd, buf, size)"),
            source_line(registrar.function_id, 30, "connection.read = tcp_read"),
        ]
        self.assertEqual(
            screen._supported_path(
                [reader.function_id, caller.function_id], reader.function_id,
                [reader.function_id, caller.function_id, registrar.function_id], evidence,
            ),
            [reader.function_id, caller.function_id],
        )

    async def test_tcp_input_to_parser_is_selected_without_enumerating_actions(self):
        reader = function("tcp_read", 10, "int tcp_read(void) { recv(fd, buf, n, 0); return parse(buf); }\n")
        parser = function("parse", 20, "int parse(char *buf) { return dispatch(buf); }\n")
        graph = GraphStore(AnalysisBundle(
            functions={f.function_id: f for f in (reader, parser)},
            edges=[CallEdge("read-to-parse", reader.function_id, parser.function_id)],
        ))
        model = ScriptedLLM([
            {
                "disposition": "INCOMPLETE", "path_function_ids": [], "evidence": [],
                "requested_function_ids": [parser.function_id], "rationale": "inspect parser",
            },
            {
                "disposition": "SELECTED",
                "path_function_ids": [reader.function_id, parser.function_id],
                "evidence": [
                    source_line(reader.function_id, 10, "return parse(buf)"),
                    source_line(parser.function_id, 20, "dispatch(buf)"),
                ],
                "requested_function_ids": [], "rationale": "buffer reaches dispatcher",
            },
        ])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "SELECTED")
        self.assertEqual(len(model.calls), 2)
        self.assertTrue(all(call["role"] == "entry_action_screen" for call in model.calls))

    async def test_unconnected_claim_is_incomplete_not_negative_entry_verdict(self):
        reader = function("tcp_read", 10, "int tcp_read(void) { recv(fd, buf, n, 0); }\n")
        unrelated = function("unrelated", 20, "int unrelated(void) { return dispatch(buf); }\n")
        graph = GraphStore(AnalysisBundle(
            functions={f.function_id: f for f in (reader, unrelated)}, edges=[],
        ))
        model = ScriptedLLM([{
            "disposition": "SELECTED",
            "path_function_ids": [reader.function_id, unrelated.function_id],
            "evidence": [
                source_line(reader.function_id, 10, "recv(fd, buf, n, 0)"),
                source_line(unrelated.function_id, 20, "dispatch(buf)"),
            ],
            "requested_function_ids": [], "rationale": "claimed edge",
        }])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "INCOMPLETE")
        self.assertIn("lacks source-linked evidence", result.rationale)

    async def test_read_helper_can_reach_processing_in_its_caller(self):
        reader = function("tcp_read", 10, "int tcp_read(void *buf) { return read(fd, buf, n); }\n")
        caller = function(
            "process_client", 20,
            "int process_client(void) { char buf[64]; tcp_read(buf); return parse(buf); }\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={f.function_id: f for f in (reader, caller)},
            edges=[CallEdge("caller-to-reader", caller.function_id, reader.function_id)],
        ))
        model = ScriptedLLM([
            {"disposition": "INCOMPLETE", "path_function_ids": [], "evidence": [],
             "requested_function_ids": [caller.function_id], "rationale": "inspect caller"},
            {"disposition": "SELECTED",
             "path_function_ids": [reader.function_id, caller.function_id],
             "evidence": [
                 source_line(reader.function_id, 10, "read(fd, buf, n)"),
                 source_line(caller.function_id, 20, "tcp_read(buf); return parse(buf)"),
             ],
             "requested_function_ids": [], "rationale": "caller processes returned buffer"},
        ])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "SELECTED")
        self.assertEqual(result.path_function_ids[-1], caller.function_id)

    async def test_missing_source_leaves_obligation(self):
        reader = function("tcp_read", 10, "int tcp_read(void) { return recv(fd, buf, n, 0); }\n")
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        model = ScriptedLLM([{
            "disposition": "INCOMPLETE", "path_function_ids": [], "evidence": [],
            "requested_function_ids": ["missing_parser"], "rationale": "parser source absent",
        }])
        result = (await EntryActionScreenAgent(model, graph).run([entry(reader)]))[0]
        self.assertEqual(result.disposition, "INCOMPLETE")
        self.assertEqual(result.inspected_function_ids, [reader.function_id])
        self.assertEqual(result.pending_function_ids, ["missing_parser"])
        self.assertIn("unavailable", result.rationale)
