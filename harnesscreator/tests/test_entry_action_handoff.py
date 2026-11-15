"""Regression tests for cross-stage Entry provenance and Action navigation."""

from __future__ import annotations

import asyncio
import unittest
import json
from dataclasses import replace
from pathlib import Path
import socket
import sys
import tempfile

from harnesscreator.agents.entry import EntryVerifierAgent
from harnesscreator.agents.entry_action_screen import EntryActionScreenResult
from harnesscreator.agents.scenario import InputActionAgent, _entry_actor
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.declarations import SourceDeclaration
from harnesscreator.llm.base import CachingLLM, RecordingLLM, ScriptedLLM
from harnesscreator.models import (
    ActionActor, ActionExample, AnalysisBundle, AnalysisDisposition, CallEdge, EntryCandidate, EntryRecord,
    EntrySiteKind, ExternalActionSchema, FunctionMetadata, OperationSeed,
    ProofStatus, ProjectSpec, ScenarioCandidate, ScenarioStatus, ScenarioStep, Verdict,
)
from harnesscreator.analysis.request_hypotheses import source_literal_request_trials
from harnesscreator.analysis.operation_seeds import extract_operation_seeds
from harnesscreator.orchestrator import (
    _is_source_literal_runtime_trial, _source_draft_action_is_supported,
    _preflight_round_robin,
)
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier, _action_transport


def _function(name: str, source: str, line: int) -> FunctionMetadata:
    return FunctionMetadata.create(
        name=name, signature=f"int {name}(void)", file="network.c",
        start_line=line, end_line=line + source.count("\n"), source=source,
    )


class EntryActionHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_entry_verifier_opens_indexed_macro_named_in_its_unknown(self):
        reader = _function(
            "tcp_read", "int tcp_read(void) { return read(fd, buf, n); }\n", 10,
        )
        declaration = SourceDeclaration(
            "ssl_accept", "macro", "tls.h", 5, 5,
            "#define ssl_accept(c, sfd, fail) NULL",
        )
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
            declarations=[declaration],
        ))
        answer = {
            "status": "UNRESOLVED", "channel_kind": "network_tcp",
            "attacker_control": "full", "provenance_path": [],
            "consumer_hints": [], "evidence": [],
            "unknowns": ["The return value of ssl_accept is unknown."],
            "confidence": 0.4, "rationale": "need build-specific ssl_accept value",
            "first_acquisition_confirmed": False, "context_complete": True,
            "requested_function_ids": [], "requested_declaration_name": "",
            "list_declarations": False, "declaration_name_filter": "",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tls.h").write_text(
                "#ifdef TLS\nvoid *ssl_accept(void);\n#else\n"
                "/* fallback */\n#define ssl_accept(c, sfd, fail) NULL\n#endif\n",
                encoding="utf-8",
            )
            (root / "config.h").write_text("/* #undef TLS */\n", encoding="utf-8")
            model = ScriptedLLM([answer, answer])
            candidate = EntryCandidate(
                candidate_id="tcp", function_id=reader.function_id,
                source_api="read", line=10, channel_hint="network_tcp",
                rationale="socket input", confidence=0.8,
            )
            await EntryVerifierAgent(
                model, graph, budget=1, source_root=root,
            ).run(candidate)
        self.assertEqual(len(model.calls), 2)
        artifact = model.calls[1]["payload"]["declaration_result"]
        self.assertEqual(artifact["name"], "ssl_accept")
        self.assertIn("#define ssl_accept(c, sfd, fail) NULL", artifact["source_excerpt"])
        self.assertEqual(
            artifact["selected_config_guard_states"]["TLS"]["state"], "UNDEFINED"
        )

    async def test_screened_route_starts_action_walk_at_its_consumer(self):
        reader = _function(
            "receive", "int receive(void) { recv(fd, buf, n, 0); return parse(buf); }\n", 1,
        )
        parser = _function("parse", "int parse(char *buf) { return buf[0]; }\n", 5)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)},
            edges=[CallEdge("read-parse", reader.function_id, parser.function_id)],
        ))
        acquired = EntryRecord(
            entry_id="screened-entry", candidate_id="screened-candidate",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="recv", channel_kind="tcp", attacker_control="full",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.9, entry_line=1,
            first_acquisition_confirmed=True,
        )
        route = EntryActionScreenResult(
            acquired.entry_id, "SELECTED", [reader.function_id, parser.function_id],
            [{"function_id": reader.function_id, "line": 1,
              "source_text": "parse(buf)", "data_relation": "passes buffer"}],
            [reader.function_id, parser.function_id], [], "input reaches parser",
        )
        model = ScriptedLLM([{
            "actions": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "parser inspected",
        }])
        agent = InputActionAgent(model, graph, entry_routes={acquired.entry_id: route})
        await agent._run_entry(acquired)
        self.assertEqual(model.calls[0]["payload"]["current_function"]["name"], "parse")
        handed_off = model.calls[0]["payload"]["screened_input_route"]
        self.assertEqual(handed_off["path_function_ids"], route.path_function_ids)
        self.assertEqual([item["name"] for item in handed_off["source_bodies"]], ["receive"])

    async def test_action_walk_opens_named_handlers_before_finishing(self):
        reader = _function(
            "receive", "int receive(void) { recv(fd, buf, n, 0); return dispatch(buf); }\n", 1,
        )
        dispatcher = _function(
            "dispatch", "int dispatch(char *buf) { if (buf[0] == 'g') return get_item(); return set_item(); }\n", 5,
        )
        get_item = _function("get_item", "int get_item(void) { return 1; }\n", 9)
        set_item = _function("set_item", "int set_item(void) { return 2; }\n", 13)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in
                       (reader, dispatcher, get_item, set_item)},
            edges=[
                CallEdge("receive-dispatch", reader.function_id, dispatcher.function_id),
                CallEdge("dispatch-get", dispatcher.function_id, get_item.function_id),
                CallEdge("dispatch-set", dispatcher.function_id, set_item.function_id),
            ],
        ))
        entry = EntryRecord(
            entry_id="entry", candidate_id="candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="recv",
            channel_kind="tcp", attacker_control="full", provenance_path=[],
            consumer_hints=[], evidence=[], unknowns=[], verifier_confidence=0.9,
            entry_line=1, first_acquisition_confirmed=True,
        )
        route = EntryActionScreenResult(
            entry.entry_id, "SELECTED", [reader.function_id, dispatcher.function_id],
            [], [reader.function_id, dispatcher.function_id], [], "input reaches dispatch",
        )
        get_action = {
            "name": "get", "dispatcher_function_id": dispatcher.function_id,
            "handler_function_id": get_item.function_id, "discriminator": "g",
        }
        set_action = {
            "name": "set", "dispatcher_function_id": dispatcher.function_id,
            "handler_function_id": set_item.function_id, "discriminator": "s",
        }
        model = ScriptedLLM([
            {"actions": [get_action, set_action], "context_complete": True},
            {"actions": [get_action], "context_complete": True},
            {"actions": [set_action], "context_complete": True},
        ])
        agent = InputActionAgent(model, graph, entry_routes={entry.entry_id: route})
        actions, _ = await agent._run_entry(entry)

        self.assertEqual(
            [call["payload"]["current_function"]["name"] for call in model.calls],
            ["dispatch", "get_item", "set_item"],
        )
        self.assertEqual({action.name for action in actions}, {"get", "set"})
        self.assertEqual(model.calls[1]["payload"]["handler_source_review"][0]["name"], "get")
        self.assertEqual(model.calls[2]["payload"]["handler_source_review"][0]["name"], "set")
        self.assertFalse(any("Action source bodies were not inspected" in item
                             for item in agent.inventory_obligations))

    async def test_action_keeps_missing_selection_and_effect_as_unknowns(self):
        reader = _function("receive", "int receive(void) { return buf[0]; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[],
        ))
        acquired = EntryRecord(
            entry_id="entry", candidate_id="candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="read",
            channel_kind="stdin", attacker_control="full", provenance_path=[],
            consumer_hints=[], evidence=[], unknowns=[], verifier_confidence=0.9,
            entry_line=1, first_acquisition_confirmed=True,
        )
        agent = InputActionAgent(ScriptedLLM([]), graph)
        actions = agent._validate_actions(
            acquired, [{"name": "read byte", "handler_function_id": reader.function_id,
                        "dispatcher_function_id": reader.function_id,
                        "evidence": [{"function_id": reader.function_id,
                                      "line": 1, "detail": "reads a byte"}]}],
            [reader.function_id], [], context_complete=True,
        )
        self.assertEqual(len(actions), 1)
        self.assertTrue(any("selection is unresolved" in item for item in actions[0].unknowns))
        self.assertTrue(any("effect is unresolved" in item for item in actions[0].unknowns))

    async def test_uninspected_input_consumers_remain_audited_without_fanout(self):
        reader = _function("receive", "int receive(void) { return read(fd, buf, n); }\n", 1)
        first = _function("first", "int first(char *buf) { return buf[0]; }\n", 5)
        second = _function("second", "int second(char *buf) { return buf[0]; }\n", 9)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, first, second)},
            edges=[],
        ))
        acquired = EntryRecord(
            entry_id="entry", candidate_id="candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="read",
            channel_kind="stdin", attacker_control="full", provenance_path=[],
            consumer_hints=[], evidence=[], unknowns=[], verifier_confidence=0.9,
            entry_line=1, first_acquisition_confirmed=True,
        )
        model = ScriptedLLM([{
            "actions": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "no more source requested",
        }])
        agent = InputActionAgent(model, graph)
        consumers = [
            (item.function_id, [reader.function_id, item.function_id], {"buf"})
            for item in (first, second)
        ]
        agent._source_consumers = lambda _entry, *, include_candidate_edges: (consumers, False)
        await agent._run_entry(acquired)
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(
            {item["function_id"] for item in agent.source_coverage
             if item["disposition"] == "UNRESOLVED"},
            {first.function_id, second.function_id},
        )
        self.assertTrue(any("input-consumer" in item for item in agent.inventory_obligations))

    async def test_opened_dispatcher_records_unreviewed_cases_as_hints_only(self):
        reader = _function(
            "receive",
            "int receive(void) {\n"
            "  int opcode = read(fd, buf, n);\n"
            "  switch (opcode) {\n"
            "  case 1: handle_one(buf); break;\n"
            "  case 2: handle_two(buf); break;\n"
            "  }\n"
            "  return 0;\n"
            "}\n",
            1,
        )
        graph = GraphStore(AnalysisBundle(functions={reader.function_id: reader}, edges=[]))
        acquired = EntryRecord(
            entry_id="entry", candidate_id="candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="read",
            channel_kind="stdin", attacker_control="full", provenance_path=[],
            consumer_hints=[], evidence=[], unknowns=[], verifier_confidence=0.9,
            entry_line=2, first_acquisition_confirmed=True,
        )
        model = ScriptedLLM([{
            "actions": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "no Action claimed",
        }])
        agent = InputActionAgent(model, graph)
        actions, _ = await agent._run_entry(acquired)
        self.assertEqual(actions, [])
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(
            {item["discriminator"] for item in agent.selector_hints
             if item["disposition"] == "UNREVIEWED_SYNTAX_HINT"},
            {"1", "2"},
        )

    async def test_action_trial_starts_before_same_entry_finishes_other_functions(self):
        reader = _function("receive", "int receive(void) { return parse(); }\n", 1)
        parser = _function("parse", "int parse(void) { return inspect_peer(); }\n", 5)
        peer = _function("inspect_peer", "int inspect_peer(void) { return 0; }\n", 9)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser, peer)},
            edges=[
                CallEdge("read-parse", reader.function_id, parser.function_id),
                CallEdge("parse-peer", parser.function_id, peer.function_id),
            ],
        ))
        entry = EntryRecord(
            entry_id="receive-entry", candidate_id="receive-candidate",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="network tcp",
            attacker_control="remote", provenance_path=[],
            consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.9, first_acquisition_confirmed=True,
            entry_line=reader.start_line,
        )
        response = lambda requested: {
            "actions": [{"name": "hypothesis"}],
            "requested_function_ids": requested,
            "context_complete": False,
            "rationale": "keep inspecting",
        }
        model = ScriptedLLM([
            response([parser.function_id]),
            response([peer.function_id]),
            response([]),
        ])
        observed: list[int] = []

        async def trial(actions):
            self.assertEqual([action.action_id for action in actions], ["ready-action"])
            observed.append(len(model.calls))

        agent = InputActionAgent(model, graph, early_runtime_hook=trial)
        ready_action = ExternalActionSchema(
            action_id="ready-action", entry_id=entry.entry_id, name="hypothesis",
            description="source backed trial", dispatcher_function_id=parser.function_id,
            handler_function_id=parser.function_id, discriminator="request",
            channel_kind="network tcp", fields=[], examples=[],
            success_markers_hex=[], failure_markers_hex=[], evidence=[],
            inspected_function_ids=[reader.function_id, parser.function_id],
            status=ProofStatus.POSSIBLE,
        )
        agent._validate_actions = lambda _entry, _raw, opened, *_args, **_kwargs: (
            [ready_action] if parser.function_id in opened else []
        )
        await agent._run_entry(entry)
        self.assertEqual(len(model.calls), 3)
        self.assertIn(2, observed)

        # The trial callback is shared by every Entry. A deterministic code
        # error must stop at its first occurrence instead of becoming an
        # unresolved Action on every later function or Entry.
        failed_model = ScriptedLLM([
            response([parser.function_id]),
            response([peer.function_id]),
        ])

        async def broken_trial(_actions):
            raise NameError("runtime callback has an unbound local")

        failed_agent = InputActionAgent(
            failed_model, graph, early_runtime_hook=broken_trial,
        )
        failed_agent._validate_actions = agent._validate_actions
        with self.assertRaisesRegex(NameError, "unbound local"):
            await failed_agent._run_entry(entry)
        self.assertEqual(len(failed_model.calls), 2)

    async def test_completed_entry_reaches_original_trial_while_peer_walk_waits(self):
        fast = _function("receive_fast", "int receive_fast(void) { return 0; }\n", 1)
        slow = _function("receive_slow", "int receive_slow(void) { return 0; }\n", 5)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (fast, slow)},
            edges=[],
        ))
        entries = [EntryRecord(
            entry_id=name, candidate_id=name, status=Verdict.VERIFIED,
            entry_function_id=function.function_id, source_api="read",
            channel_kind="stdin", attacker_control="local",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.9, first_acquisition_confirmed=True,
            entry_line=function.start_line,
        ) for name, function in (("fast", fast), ("slow", slow))]
        trial_started = asyncio.Event()
        events = []

        async def walk(entry):
            if entry.entry_id == "slow":
                await asyncio.wait_for(trial_started.wait(), timeout=1.0)
            events.append(f"walk:{entry.entry_id}")
            return [], []

        async def original_trial(actions):
            self.assertEqual(actions, [])
            events.append("trial")
            trial_started.set()

        llm = ScriptedLLM([])
        llm.max_concurrency = 2
        agent = InputActionAgent(llm, graph, early_runtime_hook=original_trial)
        agent._run_entry = walk
        self.assertEqual(await agent.run(entries), [])
        self.assertEqual(events[:3], ["walk:fast", "trial", "walk:slow"])

    async def test_budgeted_entry_walk_replays_and_opens_next_function(self):
        reader = _function("read_record", "int read_record(void) { return parse_record(); }\n", 1)
        parser = _function("parse_record", "int parse_record(void) { return 0; }\n", 5)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, parser)},
            edges=[CallEdge("reader-parser", reader.function_id, parser.function_id)],
        ))
        candidate = EntryCandidate(
            candidate_id="reader-candidate", function_id=reader.function_id,
            source_api="fread", line=reader.start_line, channel_hint="file",
            rationale="file data", confidence=0.8,
        )
        base = {
            "channel_kind": "file", "attacker_control": "file owner",
            "provenance_path": [{"function_id": reader.function_id, "relation": "external file"}],
            "consumer_hints": [], "evidence": [{
                "kind": "source", "function_id": reader.function_id,
                "file": reader.file, "line": reader.start_line,
                "detail": "input acquisition",
            }],
            "unknowns": [], "confidence": 0.99,
            "rationale": "source inspection", "first_acquisition_confirmed": True,
        }
        first = {**base, "status": "UNRESOLVED", "context_complete": False,
                 "requested_function_ids": [parser.function_id]}
        second = {**base, "status": "VERIFIED", "context_complete": True,
                  "requested_function_ids": []}
        with tempfile.TemporaryDirectory() as td:
            trajectory = Path(td) / "llm.jsonl"
            def persist(record):
                with trajectory.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record) + "\n")
            recorded = RecordingLLM(ScriptedLLM([first]), on_record=persist)
            deferred = await EntryVerifierAgent(recorded, graph, budget=1).run(candidate)
            self.assertEqual(deferred.status, Verdict.UNRESOLVED)
            self.assertEqual(deferred.analysis_disposition, AnalysisDisposition.DEFERRED)
            self.assertEqual(deferred.pending_function_ids, [parser.function_id])

            cached = CachingLLM(ScriptedLLM([first, second]), trajectory)
            resumed = await EntryVerifierAgent(cached, graph, budget=2).run(candidate)
            self.assertEqual(resumed.status, Verdict.VERIFIED)
            self.assertEqual(resumed.pending_function_ids, [])
            self.assertIn(parser.function_id, resumed.inspected_function_ids)
            self.assertEqual(cached.hits, 1)
            self.assertEqual(cached.rehydrated_calls, 1)

    async def test_entry_verifier_may_request_one_direct_callee_at_depth_four(self):
        names = ["tcp_read", "worker_enqueue", "thread_libevent_process",
                 "setup_thread", "setup_thread_notify"]
        functions = [
            _function(name, f"int {name}(void) {{ return {names[index + 1]}(); }}\n"
                      if index + 1 < len(names) else
                      f"int {name}(void) {{ return 0; }}\n", 10 + index * 10)
            for index, name in enumerate(names)
        ]
        edges = [
            CallEdge(edge_id=f"edge-{i}", caller_id=functions[i].function_id,
                     callee_id=functions[i + 1].function_id,
                     line=functions[i].start_line)
            for i in range(4)
        ]
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in functions}, edges=edges,
        ))
        answer = {
            "status": "UNRESOLVED", "channel_kind": "network_tcp",
            "attacker_control": "remote", "provenance_path": [],
            "consumer_hints": [], "evidence": [], "unknowns": ["callback identity"],
            "confidence": 0.3, "rationale": "need next function",
            "first_acquisition_confirmed": False, "context_complete": False,
        }
        provider = ScriptedLLM([
            {**answer, "requested_function_ids": [functions[i + 1].function_id]}
            for i in range(4)
        ] + [{**answer, "requested_function_ids": [], "context_complete": True}])
        candidate = EntryCandidate(
            candidate_id="tcp-entry", function_id=functions[0].function_id,
            source_api="read", line=functions[0].start_line,
            channel_hint="network_tcp", rationale="socket input", confidence=0.8,
        )
        record = await EntryVerifierAgent(
            provider, graph, depth=3, budget=6,
        ).run(candidate)
        self.assertEqual(record.status, Verdict.UNRESOLVED)
        self.assertEqual(len(provider.calls), 5)
        self.assertIn(functions[4].function_id, record.inspected_function_ids)
        boundary_frontier = provider.calls[3]["payload"]["available_context_functions"]
        extension = next(item for item in boundary_frontier
                         if item["function_id"] == functions[4].function_id)
        self.assertEqual(extension["function_id"], functions[4].function_id)
        self.assertIsNone(provider.calls[3]["payload"]["context_limits"]["max_graph_depth"])

    async def test_action_can_open_verified_context_and_typed_callback_writer(self):
        reader = _function("try_read_udp", "int try_read_udp(void) { return 0; }\n", 10)
        drive = _function(
            "drive_machine", "int drive_machine(conn *c) { return c->try_read_command(c); }\n", 20,
        )
        initialize = _function(
            "conn_new", "void conn_new(conn *c) { c->try_read_command = parse_ascii; }\n", 30,
        )
        parse = _function("parse_ascii", "int parse_ascii(conn *c) { return 0; }\n", 40)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, drive, initialize, parse)},
            edges=[CallEdge("reader-drive", reader.function_id, drive.function_id)],
        ))
        entry = EntryRecord(
            entry_id="udp", candidate_id="udp-candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="recvfrom",
            channel_kind="network_udp", attacker_control="remote",
            provenance_path=[], consumer_hints=[drive.function_id],
            evidence=[], unknowns=[], verifier_confidence=0.98,
            inspected_function_ids=[initialize.function_id],
            first_acquisition_confirmed=True,
        )
        agent = InputActionAgent(ScriptedLLM([]), graph)
        choices = agent._choices([reader.function_id, drive.function_id], [], entry)
        selected = next(item for item in choices
                        if item["function_id"] == initialize.function_id)
        self.assertEqual(selected["connections"][0]["relation"],
                         "entry_verifier_opened_navigation")
        without_prior = EntryRecord(
            entry_id="udp2", candidate_id="udp-candidate2", status=Verdict.UNRESOLVED,
            entry_function_id=reader.function_id, source_api="recvfrom",
            channel_kind="network_udp", attacker_control="remote",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.5,
        )
        choices = agent._choices([drive.function_id], [], without_prior)
        writer = next(item for item in choices
                      if item["function_id"] == initialize.function_id)
        self.assertEqual(writer["connections"][0]["relation"],
                         "callback_registration_candidate")
        self.assertIn(
            "navigation only", writer["connections"][0]["proof_policy"],
        )
        self.assertFalse(graph.causal_path_from_entry(
            drive.function_id, initialize.function_id,
            opened_function_ids=graph.bundle.functions,
        ))

    async def test_argv_actor_and_transport_not_inferred_from_socket_setup(self):
        main = _function("main", "int main(int argc, char **argv) { bind(0, 0, 0); return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(
            functions={main.function_id: main}, edges=[],
        ))
        entry = EntryRecord(
            entry_id="argv-entry", candidate_id="argv-candidate", status=Verdict.VERIFIED,
            entry_function_id=main.function_id, source_api="argv",
            channel_kind="network tcp socket", attacker_control="process launcher",
            provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
            verifier_confidence=0.9, site_kind=EntrySiteKind.PROCESS_START,
            first_acquisition_confirmed=True,
        )
        self.assertEqual(_entry_actor(entry, graph), ActionActor.LOCAL_PROCESS_INPUT)
        action = ExternalActionSchema(
            action_id="argv-action", entry_id=entry.entry_id, name="--port",
            description="port flag", dispatcher_function_id=main.function_id,
            handler_function_id=main.function_id, discriminator="-p",
            channel_kind=entry.channel_kind, fields=[], examples=[],
            success_markers_hex=[], failure_markers_hex=[], evidence=[],
            inspected_function_ids=[main.function_id], status=ProofStatus.POSSIBLE,
            source_api="argv", actor=_entry_actor(entry, graph),
        )
        self.assertEqual(_action_transport(action), "argv")

    async def test_source_literal_trial_stays_unproved_and_is_not_a_source_draft(self):
        reader = _function("tcp_read", "int tcp_read(void) { return 0; }\n", 10)
        handler = _function("handle_set", "int handle_set(void) { return 1; }\n", 30)
        dispatch = _function(
            "process_command_ascii",
            'int process_command_ascii(char *cmd) { if (strcmp(cmd, "set") == 0) return handle_set(); return 0; }\n',
            20,
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, dispatch, handler)},
            edges=[
                CallEdge("read-dispatch", reader.function_id, dispatch.function_id),
                CallEdge("dispatch-handler", dispatch.function_id, handler.function_id),
            ],
        ))
        entry = EntryRecord(
            entry_id="tcp-entry", candidate_id="tcp-candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="recv",
            channel_kind="network tcp socket", attacker_control="remote",
            provenance_path=[], consumer_hints=[dispatch.function_id],
            evidence=[], unknowns=[], verifier_confidence=0.9,
            entry_line=reader.start_line, first_acquisition_confirmed=True,
        )
        seed = OperationSeed(
            operation_seed_id="literal-set", dispatcher_function_id=dispatch.function_id,
            discriminator='strcmp(cmd, "set") == 0', line=dispatch.start_line,
            handler_function_ids=[handler.function_id],
            evidence_kind="conditional_branch", status=ProofStatus.POSSIBLE,
            entry_path_function_ids=[reader.function_id, dispatch.function_id],
        )
        agent = InputActionAgent(
            ScriptedLLM([]), graph, scenario_response_protocol="memcached_ascii",
        )
        agent._seeds_by_entry = {entry.entry_id: [seed]}
        agent.operation_seeds = [seed]
        actions = agent._add_source_literal_runtime_trials([entry], [])
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action.status, ProofStatus.POSSIBLE)
        self.assertEqual(bytes.fromhex(action.examples[0].data_hex),
                         b"set hc_probe_key 0 0 1\r\nX\r\n")
        self.assertEqual(action.actor, ActionActor.UNKNOWN)
        self.assertEqual(_action_transport(action), "tcp")
        self.assertTrue(_is_source_literal_runtime_trial(action))
        self.assertFalse(_source_draft_action_is_supported(action))

        # A fixed first-N cutoff hid later source-located candidates. These
        # are hypotheses only; keeping them does not promote static proof.
        many_seeds = [
            replace(seed, operation_seed_id=f"literal-{index}",
                    discriminator=f'strcmp(cmd, "cmd{index}") == 0')
            for index in range(13)
        ]
        many_agent = InputActionAgent(
            ScriptedLLM([]), graph, scenario_response_protocol="markers",
        )
        many_agent._seeds_by_entry = {entry.entry_id: many_seeds}
        many_agent.operation_seeds = many_seeds
        many_actions = many_agent._add_source_literal_runtime_trials([entry], [])
        self.assertEqual(len(many_actions), 13)
        self.assertTrue(all(item.status is ProofStatus.POSSIBLE
                            for item in many_actions))
        self.assertIn(b"cmd12\r\n", [
            bytes.fromhex(example.data_hex)
            for item in many_actions for example in item.examples
        ])

    async def test_udp_trial_framing_and_refuted_or_argv_seeds_are_excluded(self):
        self.assertEqual(
            source_literal_request_trials(
                'strcmp(cmd, "get") == 0', channel="udp socket",
                response_protocol="memcached_ascii",
            ),
            [b"\x00\x01\x00\x00\x00\x01\x00\x00get hc_probe_key\r\n"],
        )
        self.assertEqual(source_literal_request_trials(
            'strcmp(cmd, "get") == 0', channel="argv",
            response_protocol="memcached_ascii",
        ), [])
        self.assertEqual(source_literal_request_trials(
            'if (state == ST_CONN_READ)', channel="network tcp",
        ), [])
        self.assertEqual(source_literal_request_trials(
            "CMD_SET", channel="network tcp",
            response_protocol="memcached_ascii",
        ), [b"set hc_probe_key 0 0 1\r\nX\r\n"])
        self.assertEqual(source_literal_request_trials(
            "CMD_SET", channel="network tcp",
            response_protocol="markers",
        ), [])

    async def test_memcached_parser_enum_switch_yields_runtime_trial(self):
        reader = _function("tcp_read", "int tcp_read(void) { return 0; }\n", 10)
        handler = _function("handle_set", "int handle_set(void) { return 1; }\n", 45)
        dispatcher = _function("process_command_ascii", (
            "int process_command_ascii(void) {\n"
            "    switch (parser.cmd) {\n"
            "    case CMD_GET:\n"
            "        return handle_get();\n"
            "    case CMD_SET:\n"
            "        return handle_set();\n"
            "    default:\n"
            "        return 0;\n"
            "    }\n"
            "}\n"
        ), 20)
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, dispatcher, handler)},
            edges=[CallEdge("read-dispatch", reader.function_id, dispatcher.function_id)],
        ))
        entry = EntryRecord(
            entry_id="tcp", candidate_id="tcp-candidate", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="read",
            channel_kind="network tcp", attacker_control="remote",
            provenance_path=[], consumer_hints=[dispatcher.function_id],
            evidence=[], unknowns=[], verifier_confidence=0.9,
            first_acquisition_confirmed=True, entry_line=reader.start_line,
        )
        seed = next(seed for seed in extract_operation_seeds([dispatcher], graph)
                    if seed.discriminator == "CMD_SET")
        self.assertEqual(seed.evidence_kind, "switch_case")
        seed = replace(seed, entry_path_function_ids=[reader.function_id, dispatcher.function_id])
        agent = InputActionAgent(
            ScriptedLLM([]), graph, scenario_response_protocol="memcached_ascii",
        )
        agent._seeds_by_entry = {entry.entry_id: [seed]}
        agent.operation_seeds = [seed]
        trials = agent._add_source_literal_runtime_trials([entry], [])
        self.assertEqual(len(trials), 1)
        self.assertEqual(trials[0].discriminator, "CMD_SET")
        self.assertEqual(bytes.fromhex(trials[0].examples[0].data_hex),
                         b"set hc_probe_key 0 0 1\r\nX\r\n")

    async def test_preflight_interleaves_entries_instead_of_spending_on_one(self):
        main = _function("dispatch", "int dispatch(void) { return 0; }\n", 1)
        graph = GraphStore(AnalysisBundle(functions={main.function_id: main}, edges=[]))
        actions = [ExternalActionSchema(
            action_id=f"{entry}-{index}", entry_id=entry, name="request",
            description="request", dispatcher_function_id=main.function_id,
            handler_function_id=main.function_id, discriminator="get",
            channel_kind="network tcp", fields=[], examples=[],
            success_markers_hex=[], failure_markers_hex=[], evidence=[],
            inspected_function_ids=[main.function_id], status=ProofStatus.POSSIBLE,
        ) for entry, index in (("tcp", 1), ("tcp", 2), ("tcp", 3), ("udp", 1), ("udp", 2))]
        self.assertEqual(
            [action.action_id for action in _preflight_round_robin(actions)],
            ["tcp-1", "udp-1", "tcp-2", "udp-2", "tcp-3"],
        )

    async def test_original_trial_callback_does_not_schedule_branch_workers(self):
        reader = _function("tcp_read", "int tcp_read(void) { return 0; }\n", 10)
        dispatch = _function(
            "parser", 'int parser(char *cmd) { if (strcmp(cmd, "get") == 0) return 1; return 0; }\n', 20,
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (reader, dispatch)},
            edges=[CallEdge("reader-to-parser", reader.function_id, dispatch.function_id)],
        ))
        entry = EntryRecord(
            entry_id="tcp", candidate_id="c", status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="recv",
            channel_kind="network tcp", attacker_control="remote",
            provenance_path=[], consumer_hints=[dispatch.function_id],
            evidence=[], unknowns=[], verifier_confidence=0.9,
            first_acquisition_confirmed=True, entry_line=reader.start_line,
        )
        seed = OperationSeed(
            operation_seed_id="get", dispatcher_function_id=dispatch.function_id,
            discriminator='strcmp(cmd, "get") == 0', line=dispatch.start_line,
            handler_function_ids=[dispatch.function_id],
            evidence_kind="conditional_branch", status=ProofStatus.POSSIBLE,
            entry_path_function_ids=[reader.function_id, dispatch.function_id],
        )
        events: list[str] = []

        async def early_runtime(actions):
            events.append("original_runtime_trial")
            self.assertEqual(actions, [])

        async def direct_entry(_entry):
            events.append("source_entry_walk")
            # This mocked walk stands in for the acquisition-to-parser flow.
            agent._input_symbols_by_entry[_entry.entry_id] = {
                dispatch.function_id: {"cmd"},
            }
            return [], [seed]

        async def branch(group):
            events.append("llm_branch_validation")
            return [([], [], ProofStatus.POSSIBLE, "unproved") for _ in group]

        agent = InputActionAgent(
            ScriptedLLM([]), graph,
            scenario_response_protocol="memcached_ascii",
            early_runtime_hook=early_runtime,
            max_branch_validations=1,
        )
        agent._run_entry = direct_entry
        agent._run_seed_group = branch
        await agent.run([entry])
        self.assertEqual(
            events,
            ["source_entry_walk", "original_runtime_trial"],
        )

    async def test_memcached_accepted_trial_creates_draft_witness_not_static_proof(self):
        try:
            port_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port_probe.bind(("127.0.0.1", 0))
            port = int(port_probe.getsockname()[1])
            port_probe.close()
        except PermissionError as exc:
            raise unittest.SkipTest("test sandbox forbids local sockets") from exc
        script = (
            "import socket,sys\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen(1)\n"
            "c,_=s.accept(); received=c.recv(4096)\n"
            "c.sendall(b'STORED\\r\\n' if received == b'set hc_probe_key 0 0 1\\r\\nX\\r\\n' else b'ERROR\\r\\n')\n"
            "c.close(); s.close()\n"
        )
        request = b"set hc_probe_key 0 0 1\r\nX\r\n"
        action = ExternalActionSchema(
            action_id="source-trial", entry_id="tcp", name="CMD_SET",
            description="not yet proven", dispatcher_function_id="dispatcher",
            handler_function_id="handler", discriminator="CMD_SET",
            channel_kind="network tcp", fields=[],
            examples=[ActionExample(
                data_hex=request.hex(), origin="source_literal_runtime_hypothesis",
            )],
            success_markers_hex=[], failure_markers_hex=[], evidence=[],
            inspected_function_ids=["dispatcher", "handler"],
            status=ProofStatus.POSSIBLE, source_api="read",
            entry_function_id="entry",
        )
        candidate = ScenarioCandidate(
            scenario_id="trial", target_action_id=action.action_id,
            steps=[ScenarioStep(0, action.action_id, "tcp", request.hex(), {}, [])],
            required_entries=["tcp"], satisfied_resources=[], planning_evidence=[],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs", require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script, str(port)],
                scenario_channel="tcp", scenario_host="127.0.0.1", scenario_port=port,
                scenario_response_protocol="memcached_ascii",
                scenario_exploratory_drafts=True, scenario_startup_timeout=2.0,
                scenario_step_timeout=1.0,
            ).normalized()
            witness = await ScenarioRuntimeVerifier(
                project, [action], target_observer=lambda *args: True,
            ).verify(candidate)
        self.assertEqual(witness.status, ScenarioStatus.OBSERVED_RUNTIME)
        self.assertNotEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
        self.assertEqual(bytes.fromhex(witness.observations[0].response_hex), b"STORED\r\n")
        self.assertIn("protocol-level acceptance observed", witness.observations[0].detail)

