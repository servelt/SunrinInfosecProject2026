"""Regression tests for optional exploration without invented proof.

These tests deliberately simulate GDB observations. They do not assert that
request-to-handler causality has been proven by real dynamic instrumentation.
"""
from __future__ import annotations

import socket
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harnesscreator.agents.scenario import ScenarioPlanner
from harnesscreator.agents.scenario import (
    _merge_raw_action_turn,
    _replace_raw_action_drafts,
)
from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.models import (
    ActionActor,
    ActionExample,
    EntryRecord,
    Evidence,
    ExternalActionSchema,
    ProjectSpec,
    ProofStatus,
    ScenarioCandidate,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
    StateDependencyGraph,
    Verdict,
    stable_id,
)
from harnesscreator.runtime.scenario import (
    ScenarioRuntimeVerifier,
    _ordered_thread_trace_sequence,
    _response_marker_matches,
)
from harnesscreator.orchestrator import _entry_walk_draft_witness_allowed


class EntryWalkDraftEvidenceTest(unittest.TestCase):
    def test_source_case_trial_survives_later_action_revision(self) -> None:
        matched = {
            "name": "NOOP", "dispatcher_function_id": "fn-dispatch",
            "handler_function_id": "fn-noop", "discriminator": "",
            "description": "earlier draft",
            "examples": [{
                "data_hex": b"NOOP\r\n".hex(),
                "origin": "matched_source_case_hypothesis",
                "evidence": [{"function_id": "fn-dispatch", "line": 7}],
            }, {
                "data_hex": b"GUESS\r\n".hex(),
                "origin": "model_generated",
            }],
        }
        revision = {
            **matched, "description": "later source review", "examples": [],
        }
        for merge in (_merge_raw_action_turn, _replace_raw_action_drafts):
            with self.subTest(merge=merge.__name__):
                result = merge([matched], [revision])
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["description"], "later source review")
                self.assertEqual(result[0]["examples"], [matched["examples"][0]])
                self.assertEqual(matched["examples"][1]["data_hex"],
                                 b"GUESS\r\n".hex())
        different_handler = {
            **revision, "handler_function_id": "fn-other",
        }
        result = _merge_raw_action_turn([matched], [different_handler])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1]["examples"], [])

    def test_exploration_requires_ordered_handler_observation(self) -> None:
        replayed = SimpleNamespace(status=ScenarioStatus.REPLAYED_RUNTIME)
        observed = SimpleNamespace(status=ScenarioStatus.OBSERVED_RUNTIME)
        proven = SimpleNamespace(status=ScenarioStatus.PROVEN_RUNTIME)
        self.assertFalse(_entry_walk_draft_witness_allowed(
            replayed, exploratory=True, source_only=False,
        ))
        self.assertTrue(_entry_walk_draft_witness_allowed(
            observed, exploratory=True, source_only=False,
        ))
        self.assertTrue(_entry_walk_draft_witness_allowed(
            replayed, exploratory=False, source_only=True,
        ))
        self.assertTrue(_entry_walk_draft_witness_allowed(
            proven, exploratory=False, source_only=False,
        ))


def make_action(
    *, source_function: str = "fn-entry", handler_function: str = "fn-handler"
) -> ExternalActionSchema:
    evidence = [Evidence(
        "source", source_function, "daemon.c", 1, "source-derived request/response"
    )]
    return ExternalActionSchema(
        action_id="GET",
        entry_id="entry-tcp",
        name="GET",
        description="GET request",
        dispatcher_function_id="fn-dispatch",
        handler_function_id=handler_function,
        discriminator="GET",
        channel_kind="tcp",
        fields=[],
        examples=[ActionExample(b"GET key\r\n".hex(), {}, evidence=evidence)],
        success_markers_hex=[b"OK\n".hex()],
        failure_markers_hex=[b"ERR\n".hex()],
        evidence=evidence,
        inspected_function_ids=[source_function, handler_function],
        status=ProofStatus.POSSIBLE,
        source_api="recv",
        success_evidence=evidence,
        entry_function_id=source_function,
        actor=ActionActor.INBOUND_CLIENT,
    )


class ExploratoryPlannerTest(unittest.TestCase):
    def test_background_handler_cannot_complete_another_threads_entry(self):
        markers = [
            "__HARNESSCREATOR_TARGET__:entry:GET",
            "__HARNESSCREATOR_TARGET__:handler:GET",
        ]
        unrelated_background_hit = (
            f"{markers[0]}:T1\n{markers[1]}:T2\n"
        ).encode()
        self.assertEqual(
            _ordered_thread_trace_sequence(unrelated_background_hit, markers),
            (True, False),
        )
        same_thread_hit = (
            f"{markers[0]}:T1\n{markers[1]}:T1\n"
        ).encode()
        self.assertEqual(
            _ordered_thread_trace_sequence(same_thread_hit, markers),
            (True, True),
        )

    def test_candidate_variant_budget_preserves_every_action(self):
        first = make_action()
        second = make_action()
        second.action_id = "DELETE"
        second.name = "DELETE"
        planner = ScenarioPlanner(max_candidates=1)
        candidates = planner.exploratory_candidates([first, second], [])
        self.assertEqual([item.target_action_id for item in candidates], ["GET", "DELETE"])
        self.assertTrue(any(
            "reserving one trial slot per target" in obligation
            for obligation in planner.obligations
        ))

    def test_unproven_action_gets_direct_probe_without_inventing_contract(self):
        action = make_action()
        planner = ScenarioPlanner(max_candidates=4)
        strict = planner.plan([action], StateDependencyGraph([], [], []))
        self.assertEqual(strict, [])
        candidates = planner.exploratory_candidates([action], strict)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, ScenarioStatus.CANDIDATE)
        self.assertEqual(candidates[0].steps[0].request_hex, b"GET key\r\n".hex())
        self.assertEqual(candidates[0].satisfied_resources, [])
        self.assertIn("not proven", candidates[0].planning_evidence[1])

    def test_exploration_does_not_replace_strict_proven_sequence(self):
        action = make_action()
        strict = [ScenarioCandidate(
            "already-planned", "GET", [ScenarioStep(0, "GET", "entry-tcp", "00", {}, [])],
            ["entry-tcp"], [], [],
        )]
        self.assertEqual(ScenarioPlanner().exploratory_candidates([action], strict), [])

    def test_no_fake_example_without_evidence(self):
        action = make_action()
        action.evidence = []
        self.assertEqual(ScenarioPlanner().exploratory_candidates([action], []), [])

    def test_observed_not_accepted_for_plan_without_opt_in(self):
        witness = ScenarioWitness(
            "wid", "sid", "GET",
            [ScenarioStep(0, "GET", "entry-tcp", b"GET key\r\n".hex(), {}, [b"OK\n".hex()])],
            [], ["daemon"], "tcp", None, ScenarioStatus.OBSERVED_RUNTIME,
            "request attribution unavailable",
        )
        with self.assertRaises(ValueError):
            build_harness_plan(
                witness, action_function_ids={"GET": ("fn-entry", "fn-handler")}
            )
        plan = build_harness_plan(
            witness,
            action_function_ids={"GET": ("fn-entry", "fn-handler")},
            allow_observed=True,
        )
        self.assertEqual(plan.fuzz_step.request_hex, b"GET key\r\n".hex())

    def test_markers_are_not_embedded_substrings(self):
        self.assertFalse(_response_marker_matches(b"NOT_STORED\r\n", b"STORED\r\n"))
        self.assertTrue(_response_marker_matches(b"STORED\r\n", b"STORED\r\n"))
        self.assertTrue(_response_marker_matches(b"OK:ABCD\n", b"OK:"))
        self.assertFalse(_response_marker_matches(b"NOT_OK:ABCD\n", b"OK:"))


class ExploratoryRuntimeTest(unittest.IsolatedAsyncioTestCase):
    async def test_unattributed_trace_becomes_observed_not_proven(self):
        class FakeProbe:
            mechanism = "SYNTHETIC GDB marker trace"
            stdin_fd = None
            stdout_fd = None

            def __init__(self, *_args, **_kwargs):
                pass

            def launch_argv(self, argv):
                return argv

            def offset(self):
                return 0

            def ordered_chain_observation(self, _action, _offset):
                return True, True, ["entry", "dispatch", "handler"]

            def ordered_chain_reached(self, _action, _offset):
                return True, True

            def close(self):
                pass

        server_script = (
            "import socket,sys\n"
            "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "s.bind(('127.0.0.1',int(sys.argv[1])));s.listen(1)\n"
            "c,_=s.accept();data=c.recv(128)\n"
            "c.sendall(b'OK\\n' if data==b'GET key\\r\\n' else b'ERR\\n')\n"
            "c.close();s.close()\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int read_site(void) { return 0; }\n"
                "int dispatch_site(void) { return 0; }\n"
                "int handler_site(void) { return 0; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            names = {item.name: item for item in graph.bundle.functions.values()}
            entry = names["read_site"]
            dispatch = names["dispatch_site"]
            handler = names["handler_site"]
            action = make_action(
                source_function=entry.function_id, handler_function=handler.function_id
            )
            action.dispatcher_function_id = dispatch.function_id
            action.entry_probe_evidence = [Evidence(
                "source", entry.function_id, entry.file, entry.start_line,
                "source-acquisition callsite",
            )]
            action.success_evidence = [Evidence(
                "source", handler.function_id, handler.file, handler.start_line,
                "source success response",
            )]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            step = ScenarioStep(
                0, action.action_id, action.entry_id,
                b"GET key\r\n".hex(), {}, [b"OK\n".hex()],
            )
            candidate = ScenarioCandidate("sid", action.action_id, [step],
                                          [action.entry_id], [], ["synthetic fixture"])
            base_kwargs = dict(
                source_root=root, output_root=root / "runs", require_fuzz_introspector=False,
                svf_enabled=False,
                scenario_command=[sys.executable, "-u", "-c", server_script, str(port)],
                scenario_channel="tcp", scenario_host="127.0.0.1", scenario_port=port,
                scenario_step_timeout=2.0, scenario_startup_timeout=2.0,
            )
            with patch("harnesscreator.runtime.scenario._GdbTargetProbe", FakeProbe), \
                 patch("harnesscreator.runtime.scenario.shutil.which", return_value="/fake/gdb"):
                strict = await ScenarioRuntimeVerifier(
                    ProjectSpec(**base_kwargs).normalized(), [action], graph
                ).verify(candidate)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as second_socket:
                    second_socket.bind(("127.0.0.1", 0))
                    second_port = second_socket.getsockname()[1]
                explore_kwargs = dict(base_kwargs)
                explore_kwargs["scenario_port"] = second_port
                explore_kwargs["scenario_command"] = [
                    sys.executable, "-u", "-c", server_script, str(second_port)
                ]
                explored = await ScenarioRuntimeVerifier(
                    ProjectSpec(**explore_kwargs, scenario_exploratory_drafts=True).normalized(),
                    [action], graph,
                ).verify(candidate)
        self.assertEqual(strict.status, ScenarioStatus.UNPROVEN, msg=strict.rationale)
        self.assertEqual(explored.status, ScenarioStatus.OBSERVED_RUNTIME, msg=explored.rationale)
        self.assertFalse(explored.observations[0].target_reached)
        self.assertTrue(explored.observations[0].target_observed)
        self.assertTrue(explored.observations[0].response_success)
        self.assertIn("NOT a PROVEN_RUNTIME", explored.rationale)


if __name__ == "__main__":
    unittest.main()


class SourceCaseActionMatchTest(unittest.IsolatedAsyncioTestCase):
    def test_incomplete_action_can_be_trialed_only_with_cited_case_and_result(self):
        from harnesscreator.orchestrator import _is_matched_source_case_runtime_trial

        action = make_action()
        action.unknowns.append("this Action's source context is incomplete")
        action.examples[0].origin = "matched_source_case_hypothesis"
        self.assertTrue(_is_matched_source_case_runtime_trial(action))
        self.assertEqual(action.status, ProofStatus.POSSIBLE)
        action.examples[0].evidence = []
        self.assertFalse(_is_matched_source_case_runtime_trial(action))
        action.examples[0].evidence = action.success_evidence
        action.success_evidence = []
        self.assertFalse(_is_matched_source_case_runtime_trial(action))

    async def test_opened_incomplete_action_recovers_exact_source_case_for_trial(self):
        from harnesscreator.agents.scenario import InputActionAgent
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int recv_cmd(void) { return dispatch_cmd(); }\n"
                "int dispatch_cmd(void) { return handle_noop(); }\n"
                "int handle_noop(void) { return 200; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {fn.name: fn for fn in graph.bundle.functions.values()}
            entry_fn = functions["recv_cmd"]
            dispatcher = functions["dispatch_cmd"]
            handler = functions["handle_noop"]
            entry = EntryRecord(
                "entry-noop", "candidate-noop", Verdict.VERIFIED,
                entry_fn.function_id, "recv", "tcp", "peer", [], [],
                [Evidence("source", entry_fn.function_id, entry_fn.file,
                          entry_fn.start_line, "external request receiver")],
                [], 0.9, entry_line=entry_fn.start_line,
                first_acquisition_confirmed=True,
            )
            source_case = {
                "case_id": "case-noop", "data_hex": b"NOOP\r\n".hex(),
                "origin": "model_input_hypothesis", "sample_basis": [],
            }
            raw = [{
                "name": "NOOP", "handler_function_id": handler.function_id,
                "dispatcher_function_id": dispatcher.function_id,
                "action_context_complete": False, "examples": [],
            }]
            llm = ScriptedLLM([{
                "matches": [{
                    "action_name": "NOOP", "handler_function_id": handler.function_id,
                    "case_id": "case-noop", "rationale": "dispatcher selects NOOP",
                    "evidence": [{
                        "kind": "source", "function_id": dispatcher.function_id,
                        "line": dispatcher.start_line,
                        "detail": "dispatches the received command",
                    }],
                }],
                "rationale": "one source-backed trial candidate",
            }])
            agent = InputActionAgent(
                llm, graph,
                input_case_hypotheses={entry.entry_id: [source_case]},
            )
            attempted: set[tuple[str, str]] = set()
            opened = [entry_fn.function_id, dispatcher.function_id,
                      handler.function_id]
            await agent._match_source_cases_for_ready_actions(
                entry, raw, opened, {}, attempted,
            )
            self.assertEqual(raw[0]["examples"][0]["data_hex"], b"NOOP\r\n".hex())
            self.assertEqual(raw[0]["examples"][0]["origin"],
                             "matched_source_case_hypothesis")
            self.assertFalse(raw[0]["action_context_complete"])
            self.assertEqual(len(llm.calls), 1)
            await agent._match_source_cases_for_ready_actions(
                entry, raw, opened, {}, attempted,
            )
            self.assertEqual(len(llm.calls), 1)

    async def test_unopened_or_mismatched_case_evidence_is_rejected(self):
        from harnesscreator.agents.scenario import InputActionAgent
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int receive_one(void) { return handle_one(); }\n"
                "int handle_one(void) { return 1; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {fn.name: fn for fn in graph.bundle.functions.values()}
            receiver = functions["receive_one"]
            handler = functions["handle_one"]
            entry = EntryRecord(
                "entry-one", "candidate-one", Verdict.VERIFIED,
                receiver.function_id, "recv", "tcp", "peer", [], [],
                [Evidence("source", receiver.function_id, receiver.file,
                          receiver.start_line, "receiver")], [], 0.9,
                entry_line=receiver.start_line,
                first_acquisition_confirmed=True,
            )
            raw = [{"name": "ONE", "handler_function_id": handler.function_id,
                    "dispatcher_function_id": receiver.function_id,
                    "action_context_complete": True, "examples": []}]
            llm = ScriptedLLM([{
                "matches": [{
                    "action_name": "ONE", "handler_function_id": handler.function_id,
                    "case_id": "case-one", "rationale": "unsupported",
                    "evidence": [{
                        "kind": "source", "function_id": handler.function_id,
                        "line": handler.end_line + 1, "detail": "outside opened source",
                    }],
                }], "rationale": "no valid source location",
            }])
            agent = InputActionAgent(
                llm, graph,
                input_case_hypotheses={entry.entry_id: [
                    {"case_id": "case-one", "data_hex": b"X".hex()}
                ]},
            )
            await agent._match_source_cases_for_ready_actions(
                entry, raw, [receiver.function_id, handler.function_id], {}, set(),
            )
            self.assertEqual(raw[0]["examples"], [])


class ExploratoryGeneratorTest(unittest.IsolatedAsyncioTestCase):
    async def test_harness_source_payload_distinguishes_recorded_and_unrecorded_units(self):
        from harnesscreator.agents.scenario_harness import ScenarioHarnessGeneratorAgent
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.c").write_text("int server_input(void) { return 1; }\n", encoding="utf-8")
            (root / "fuzz").mkdir()
            (root / "fuzz" / "helper.c").write_text(
                "int optional_fuzz_helper(void) { return 2; }\n", encoding="utf-8",
            )
            compile_db = root / "compile_commands.json"
            compile_db.write_text(json.dumps([{
                "directory": str(root), "file": "server.c",
                "command": "clang -c server.c -o server.o",
            }]), encoding="utf-8")
            graph = GraphStore(StaticAnalyzer(root, compile_database=compile_db).index())
            functions = {function.name: function for function in graph.bundle.functions.values()}
            agent = ScenarioHarnessGeneratorAgent(
                ScriptedLLM([]), graph,
                ProjectSpec(source_root=root, output_root=root / "runs",
                            require_fuzz_introspector=False).normalized(),
            )
            server = agent._opened_function_payload(functions["server_input"])
            helper = agent._opened_function_payload(functions["optional_fuzz_helper"])
            self.assertEqual(server["recorded_compilation"], "RECORDED")
            self.assertEqual(helper["recorded_compilation"], "NOT_RECORDED")
            self.assertIn("not proof", helper["recorded_compilation_meaning"])

    async def test_harness_obligations_survive_source_walk_without_becoming_source_blockers(self):
        from harnesscreator.agents.scenario_harness import ScenarioHarnessGeneratorAgent
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int receive_one(void) { return handle_one(); }\n"
                "int handle_one(void) { return 1; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {fn.name: fn for fn in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                "observed-wid", "observed-sid", "REQUEST",
                [ScenarioStep(0, "REQUEST", "entry-tcp", b"X\r\n".hex(), {}, [])],
                [], ["original-daemon"], "tcp", None,
                ScenarioStatus.REPLAYED_RUNTIME, "response observed without request trace",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"REQUEST": (
                    functions["receive_one"].function_id,
                    functions["handle_one"].function_id,
                )},
                allow_observed=True,
            )
            obligation = "generated code must deliver one request and wait for completion"
            llm = ScriptedLLM([{
                "context_complete": False, "requested_function_ids": [],
                "established_facts": [], "blocking_dependencies": [],
                "verification_obligations": [obligation],
                "terminal_backend_blocker": False,
                "rationale": "required handler source remains unopened",
            }, {
                "context_complete": True, "requested_function_ids": [],
                "established_facts": ["handler source inspected"],
                "blocking_dependencies": [],
                "verification_obligations": [obligation],
                "terminal_backend_blocker": False,
                "rationale": "source context complete, harness behavior unverified",
            }, {
                "code": "", "manifest": {}, "checklist": [],
                "implemented_step_indexes": [0],
                "generation_blockers": ["per-input completion cannot be implemented safely"],
            }])
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                require_fuzz_introspector=False,
                scenario_source_drafts=True,
            ).normalized()
            draft = await ScenarioHarnessGeneratorAgent(llm, graph, project).run(plan, witness)
            self.assertEqual(len(llm.calls), 3)
            self.assertEqual(
                llm.calls[1]["payload"]["verification_obligations"],
                [obligation],
            )
            self.assertEqual(
                llm.calls[2]["payload"]["context_discovery"]["verification_obligations"],
                [obligation],
            )
            self.assertEqual(draft.code, "")
            self.assertIn("per-input completion cannot be implemented safely",
                          draft.generation_blockers)

    async def test_long_harness_function_is_not_silently_truncated(self):
        from harnesscreator.agents.scenario_harness import ScenarioHarnessGeneratorAgent
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int process_input(const char *data, unsigned long size) {\n"
                + "".join(
                    f"  /* source section {index:04d}: input processing context */\n"
                    for index in range(500)
                )
                + "  /* REQUIRED_TAIL: final input guard */\n"
                + "  return size > 0 && data[0] == 'X';\n}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            function = next(iter(graph.bundle.functions.values()))
            self.assertGreater(len(function.source), 16_000)
            witness = ScenarioWitness(
                "observed-wid", "observed-sid", "REQUEST",
                [ScenarioStep(0, "REQUEST", "entry-stdin", b"X".hex(), {}, [])],
                [], ["original-daemon"], "stdin", None,
                ScenarioStatus.OBSERVED_RUNTIME, "original input observed",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"REQUEST": (function.function_id, function.function_id)},
                allow_observed=True,
            )
            llm = ScriptedLLM([{
                "context_complete": True, "requested_function_ids": [],
                "established_facts": [], "blocking_dependencies": [],
                "terminal_backend_blocker": False, "rationale": "source inspected",
            }, {
                "code": "", "manifest": {}, "checklist": [],
                "implemented_step_indexes": [0], "generation_blockers": [],
            }])
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                require_fuzz_introspector=False,
                scenario_exploratory_drafts=True,
            ).normalized()
            await ScenarioHarnessGeneratorAgent(llm, graph, project).run(plan, witness)
            self.assertEqual(len(llm.calls), 2)
            for current in (
                llm.calls[0]["payload"]["current_function"],
                llm.calls[1]["payload"]["opened_functions"][0],
            ):
                self.assertIn("REQUIRED_TAIL", current["source"])
                self.assertFalse(current["source_truncated"])

    async def test_server_loop_claim_does_not_skip_required_handler_source(self):
        from harnesscreator.agents.scenario_harness import ScenarioHarnessGeneratorAgent
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "void server(void) { for (;;) { accept_one(); } }\n"
                "void handler(void) { parse_one(); wait_for_completion(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {fn.name: fn for fn in graph.bundle.functions.values()}
            server = functions["server"]
            handler = functions["handler"]
            witness = ScenarioWitness(
                "observed-wid", "observed-sid", "REQUEST",
                [ScenarioStep(0, "REQUEST", "entry-tcp", b"X\r\n".hex(), {}, [])],
                [], ["original-daemon"], "tcp", None,
                ScenarioStatus.REPLAYED_RUNTIME, "response-only experiment",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"REQUEST": (server.function_id, handler.function_id)},
                allow_observed=True,
            )
            llm = ScriptedLLM([{
                "context_complete": False, "requested_function_ids": [],
                "established_facts": [],
                "blocking_dependencies": [{
                    "description": "server loop has no per-input termination",
                    "required_for": "selected execution model",
                    "function_id": server.function_id,
                    "line": server.start_line,
                }],
                "terminal_backend_blocker": True,
                "rationale": "the selected repeat-call model cannot reset this root",
            }, {
                "context_complete": True, "requested_function_ids": [],
                "established_facts": ["handler inspected"],
                "blocking_dependencies": [],
                "terminal_backend_blocker": False,
                "rationale": "required handler is now inspected",
            }])
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                require_fuzz_introspector=False,
                scenario_exploratory_drafts=True,
            ).normalized()
            opened, discovery = await ScenarioHarnessGeneratorAgent(
                llm, graph, project,
            )._discover_context(plan, witness, [])
            self.assertEqual(len(llm.calls), 2)
            self.assertEqual([fn.function_id for fn in opened],
                             [server.function_id, handler.function_id])
            self.assertFalse(discovery["context_complete"])
            self.assertEqual(len(discovery["blocking_dependencies"]), 1)
            blocker_id = stable_id(
                "harness-context-blocker", "selected execution model",
                server.function_id, str(server.start_line),
                "server loop has no per-input termination",
            )
            self.assertEqual(
                discovery["blocking_dependencies"][0]["blocker_id"],
                blocker_id,
            )
            resolved_llm = ScriptedLLM([{
                "context_complete": False, "requested_function_ids": [],
                "established_facts": [],
                "blocking_dependencies": [{
                    "description": "server loop has no per-input termination",
                    "required_for": "selected execution model",
                    "function_id": server.function_id,
                    "line": server.start_line,
                }],
                "terminal_backend_blocker": True,
                "rationale": "inspect the handler before deciding",
            }, {
                "context_complete": True, "requested_function_ids": [],
                "established_facts": [], "blocking_dependencies": [],
                "resolved_blocking_dependencies": [{
                    "blocker_id": blocker_id,
                    "function_id": handler.function_id,
                    "line": handler.start_line,
                    "explanation": "handler calls wait_for_completion",
                }],
                "terminal_backend_blocker": False,
                "rationale": "opened handler source supplies completion evidence",
            }])
            _opened, resolved_discovery = await ScenarioHarnessGeneratorAgent(
                resolved_llm, graph, project,
            )._discover_context(plan, witness, [])
            self.assertTrue(resolved_discovery["context_complete"])
            self.assertEqual(resolved_discovery["blocking_dependencies"], [])
            unresolved = ScriptedLLM([{
                "context_complete": False, "requested_function_ids": [],
                "established_facts": [],
                "blocking_dependencies": [{
                    "description": "worker completion is not evidenced",
                    "required_for": "selected execution model",
                    "function_id": server.function_id,
                    "line": server.start_line,
                }],
                "terminal_backend_blocker": True,
                "rationale": "server loop remains unresolved",
            }, {
                "context_complete": False, "requested_function_ids": [],
                "established_facts": [],
                "blocking_dependencies": [{
                    "description": "no source-backed per-input completion or reset",
                    "required_for": "selected execution model",
                    "function_id": handler.function_id,
                    "line": handler.start_line,
                }],
                "terminal_backend_blocker": True,
                "rationale": "still unresolved after required inspection",
            }])
            blocked = await ScenarioHarnessGeneratorAgent(
                unresolved, graph, project,
            ).run(plan, witness)
            self.assertEqual(len(unresolved.calls), 2)
            self.assertEqual(blocked.code, "")
            self.assertTrue(any("no source-backed per-input completion"
                                in reason for reason in blocked.generation_blockers))
            invalid_citation = ScriptedLLM([{
                "context_complete": False, "requested_function_ids": [],
                "established_facts": [],
                "blocking_dependencies": [{
                    "description": "unsupported backend asserted without a real source line",
                    "required_for": "selected execution model",
                    "function_id": server.function_id,
                    "line": server.end_line + 100,
                }],
                "terminal_backend_blocker": True,
                "rationale": "invalid citation",
            }, {
                "context_complete": True, "requested_function_ids": [],
                "established_facts": [], "blocking_dependencies": [],
                "terminal_backend_blocker": False,
                "rationale": "the handler was opened after rejecting the citation",
            }])
            opened, discovery = await ScenarioHarnessGeneratorAgent(
                invalid_citation, graph, project,
            )._discover_context(plan, witness, [])
            self.assertEqual(len(invalid_citation.calls), 2)
            self.assertEqual([fn.function_id for fn in opened],
                             [server.function_id, handler.function_id])
            self.assertTrue(discovery["context_complete"])

    async def test_exploratory_witness_produces_source_draft_not_proof(self):
        from unittest.mock import AsyncMock
        from harnesscreator.agents.scenario_harness import (
            ScenarioHarnessGeneratorAgent,
            ScenarioStaticHarnessGate,
        )
        from harnesscreator.agents.harness import CHECKLIST_NAMES
        from harnesscreator.llm.base import ScriptedLLM
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int process_input(const unsigned char *p, unsigned long n) {\n"
                "  return n > 0 && p[0] == 'G';\n}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            process = next(iter(graph.bundle.functions.values()))
            witness = ScenarioWitness(
                "observed-wid", "observed-sid", "GET",
                [ScenarioStep(0, "GET", "entry-tcp", b"GET key\r\n".hex(), {}, [b"OK\n".hex()])],
                [], ["original-daemon"], "tcp", None,
                ScenarioStatus.OBSERVED_RUNTIME,
                "GDB marker chain observed but unattributed",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"GET": (process.function_id, process.function_id)},
                allow_observed=True,
            )
            code = (
                "#include <stddef.h>\n#include <stdint.h>\n"
                "extern \"C\" int process_input(const unsigned char*, unsigned long);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data,size_t Size){\n"
                " if(Size<1) return 0;\n"
                " const uint8_t *hc_fuzz_request=Data;\n"
                " size_t hc_fuzz_request_size=Size;\n"
                " return process_input(hc_fuzz_request,hc_fuzz_request_size);\n}\n"
            )
            llm = ScriptedLLM([{
                "code": code,
                "manifest": {"build_target": "daemon", "headers": [], "libraries": [],
                             "min_size": 0, "max_size": 4096, "execution_model": "in_process_reset"},
                "checklist": [
                    {"check_id": identifier, "status": "PASS", "evidence": "fixture"}
                    for identifier in CHECKLIST_NAMES
                ],
                "implemented_step_indexes": [0],
                "generation_blockers": [],
            }])
            project = ProjectSpec(
                source_root=root, output_root=root / "runs", require_fuzz_introspector=False,
                scenario_exploratory_drafts=True,
                scenario_channel="disabled",
            ).normalized()
            generator = ScenarioHarnessGeneratorAgent(llm, graph, project)
            generator._discover_context = AsyncMock(return_value=(
                [process], {"context_complete": True, "blocking_dependencies": [],
                            "established_facts": ["process_input receives bytes"]}
            ))
            draft = await generator.run(plan, witness)
            self.assertIn("LLVMFuzzerTestOneInput", draft.code)
            self.assertEqual(draft.generation_blockers, [])
            # The static gate must not certify an unattributed original trace.
            report = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
            self.assertFalse(report.passed)
            self.assertEqual(next(c.status for c in report.checks if c.check_id == "HC11").value, "FAIL")

class RequestRefinementTest(unittest.IsolatedAsyncioTestCase):
    async def test_repair_uses_rejection_and_real_source_line(self):
        from harnesscreator.agents.scenario_refine import ScenarioRequestRefiner
        from harnesscreator.llm.base import ScriptedLLM
        from harnesscreator.models import RuntimeStepObservation
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int handler(const char *p) {\n"
                "  if (p[0] == 'S' && p[1] == 'E') return 1;\n"
                "  puts(\"ERR\");\n"
                "  return 0;\n}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            function = next(iter(graph.bundle.functions.values()))
            action = make_action(
                source_function=function.function_id, handler_function=function.function_id
            )
            action.examples = [ActionExample(b"GET key\r\n".hex(), {},
                                             evidence=action.evidence)]
            action.failure_markers_hex = [b"ERR".hex()]
            action.failure_evidence = [Evidence(
                "source", function.function_id, function.file,
                function.start_line + 2, "failure response marker",
            )]
            observation = RuntimeStepObservation(
                index=0, action_id=action.action_id,
                request_hex=b"GET key\r\n".hex(), response_hex=b"ERR\n".hex(),
                success=False, detail=f"matched failure marker {b'ERR'.hex()}",
                duration_seconds=0.1,
                response_success=False,
            )
            witness = ScenarioWitness(
                "w", "s", action.action_id,
                [ScenarioStep(0, action.action_id, action.entry_id,
                              observation.request_hex, {}, action.success_markers_hex)],
                [observation], ["daemon"], "tcp", None, ScenarioStatus.UNPROVEN,
                "source-derived input was rejected",
            )
            llm = ScriptedLLM([{
                "requests": [
                    {"data_hex": b"SET key\r\n".hex(), "rationale": "switch selects SET",
                     "evidence": [{"function_id": function.function_id,
                                   "line": function.start_line + 1,
                                   "detail": "branch requires S and E"}]},
                    {"data_hex": b"BOGUS\n".hex(), "rationale": "invented",
                     "evidence": [{"function_id": function.function_id,
                                   "line": function.end_line + 15,
                                   "detail": "nonexistent line"}]},
                ],
                "requested_function_ids": [],
                "context_complete": True,
                "rationale": "one source-cited proposal",
            }])
            examples = await ScenarioRequestRefiner(llm, graph).repair(action, witness)
            self.assertEqual(len(examples), 1)
            self.assertEqual(examples[0].data_hex, b"SET key\r\n".hex())
            self.assertEqual(examples[0].origin, "runtime_feedback_source_candidate")
            action.failure_evidence = []
            no_oracle_llm = ScriptedLLM([])
            no_oracle_refiner = ScenarioRequestRefiner(no_oracle_llm, graph)
            self.assertEqual(await no_oracle_refiner.repair(action, witness), [])
            self.assertEqual(no_oracle_llm.calls, [])
            self.assertIn("source-backed failure marker",
                          no_oracle_refiner.unresolved_reasons[0])

    async def test_repair_opens_requested_source_beyond_old_four_body_cutoff(self):
        from harnesscreator.agents.scenario_refine import ScenarioRequestRefiner
        from harnesscreator.llm.base import ScriptedLLM
        from harnesscreator.models import RuntimeStepObservation
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "daemon.c").write_text(
                "int receive(void) { return 0; }\n"
                "int parse(void) { puts(\"ERR\"); return 0; }\n"
                "int helper_one(void) { return 0; }\n"
                "int helper_two(void) { return 0; }\n"
                "int helper_three(void) { return 0; }\n"
                "int check_request(const char *p) { return p[0] == 'S'; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            names = {item.name: item for item in graph.bundle.functions.values()}
            action = make_action(
                source_function=names["receive"].function_id,
                handler_function=names["parse"].function_id,
            )
            action.inspected_function_ids = [
                names[name].function_id for name in (
                    "helper_one", "helper_two", "helper_three", "check_request",
                )
            ]
            action.examples = [ActionExample(
                b"GET key\r\n".hex(), {}, evidence=action.evidence,
            )]
            action.failure_markers_hex = [b"ERR".hex()]
            action.failure_evidence = [Evidence(
                "source", names["parse"].function_id, names["parse"].file,
                names["parse"].start_line, "failure response marker",
            )]
            observation = RuntimeStepObservation(
                index=0, action_id=action.action_id,
                request_hex=b"GET key\r\n".hex(), response_hex=b"ERR\n".hex(),
                success=False, detail=f"matched failure marker {b'ERR'.hex()}",
                duration_seconds=0.1,
                response_success=False,
            )
            witness = ScenarioWitness(
                "w", "s", action.action_id,
                [ScenarioStep(0, action.action_id, action.entry_id,
                              observation.request_hex, {}, action.success_markers_hex)],
                [observation], ["daemon"], "tcp", None, ScenarioStatus.UNPROVEN,
                "source-derived input was rejected",
            )
            target = names["check_request"]
            llm = ScriptedLLM([
                {
                    "requests": [{
                        "data_hex": b"BAD key\r\n".hex(),
                        "rationale": "provisional guess before the request check",
                        "evidence": [{
                            "function_id": names["parse"].function_id,
                            "line": names["parse"].start_line,
                            "detail": "incomplete parser evidence",
                        }],
                    }],
                    "requested_function_ids": [target.function_id],
                    "context_complete": False,
                    "rationale": "request check is in another source body",
                },
                {
                    "requests": [{
                        "data_hex": b"SET key\r\n".hex(),
                        "rationale": "the request check uses S",
                        "evidence": [{
                            "function_id": target.function_id,
                            "line": target.start_line,
                            "detail": "request check",
                        }],
                    }],
                    "requested_function_ids": [],
                    "context_complete": True,
                    "rationale": "source question answered",
                },
            ])
            examples = await ScenarioRequestRefiner(llm, graph).repair(action, witness)
            self.assertEqual(len(examples), 1)
            self.assertEqual(len(llm.calls), 2)
            self.assertEqual(llm.calls[0]["session_key"], llm.calls[1]["session_key"])
            self.assertEqual(
                llm.calls[1]["payload"]["current_function"]["function_id"],
                target.function_id,
            )

class TentativeStateSequenceTest(unittest.TestCase):
    def test_possible_contracts_produce_set_then_get_trial(self):
        from harnesscreator.models import ActionStateContract, StateRequirement
        set_action = make_action()
        set_action.action_id = "SET"
        set_action.examples = [ActionExample(b"SET k\n".hex(), {"key": b"k".hex()},
                                            evidence=set_action.evidence)]
        get_action = make_action()
        get_action.examples = [ActionExample(b"GET k\n".hex(), {"key": b"k".hex()},
                                            evidence=get_action.evidence)]
        required = StateRequirement(resource="item", binding="key", predicate="exists")
        graph = StateDependencyGraph(
            contracts=[
                ActionStateContract(
                    "SET", [], [required], [], "stored", set_action.evidence,
                    [set_action.handler_function_id], status=ProofStatus.POSSIBLE,
                ),
                ActionStateContract(
                    "GET", [required], [], [], "value", get_action.evidence,
                    [get_action.handler_function_id], status=ProofStatus.POSSIBLE,
                ),
            ],
            initial_resources=[], open_obligations=[],
        )
        planner = ScenarioPlanner(max_steps=4, max_candidates=8)
        strict = planner.plan([set_action, get_action], graph)
        self.assertEqual(strict, [])
        trials = planner.exploratory_candidates(
            [set_action, get_action], strict, dependencies=graph
        )
        get_trial = next(c for c in trials if c.target_action_id == "GET")
        self.assertEqual([s.action_id for s in get_trial.steps], ["SET", "GET"])
        self.assertEqual(get_trial.status, ScenarioStatus.CANDIDATE)
        self.assertIn("not proven", get_trial.planning_evidence[1])
