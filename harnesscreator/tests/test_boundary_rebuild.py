"""Regression tests for the evidence-led pipeline without Action assumptions."""

from __future__ import annotations

import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from harnesscreator.agents.behavior import BehaviorRecoveryAgent
from harnesscreator.agents.boundary_harness import BoundaryStaticGate
from harnesscreator.agents.execution_contract import ExecutionContractAgent
from harnesscreator.agents.input_surfaces import InputSurfaceCase
from harnesscreator.analysis import GraphStore
from harnesscreator.llm import ScriptedLLM
from harnesscreator.orchestrator import HarnessCreator
from harnesscreator.models import (
    AnalysisBundle, CheckStatus, EntryRecord, EntrySiteKind,
    Evidence, FunctionMetadata, ProjectSpec, Verdict,
)
from harnesscreator.runtime.boundary import (
    BoundaryTrialRunner, _endpoint_is_active, _socket_trial, select_backend,
)
from harnesscreator.storage import ArtifactStore
from harnesscreator.workflow_boundary import run_boundary_workflow


def source_graph() -> tuple[GraphStore, FunctionMetadata, EntryRecord]:
    source = (
        "int consume_stream(void) {\n"
        "  char buf[32];\n"
        "  if (!fgets(buf, sizeof(buf), stdin)) return 0;\n"
        "  return buf[0] == 'A';\n"
        "}\n"
    )
    fn = FunctionMetadata.create(
        name="consume_stream", signature="int consume_stream(void)",
        file="input.c", start_line=1, end_line=5, source=source,
    )
    entry = EntryRecord(
        entry_id="stdin-entry", candidate_id="candidate", status=Verdict.VERIFIED,
        entry_function_id=fn.function_id, source_api="fgets",
        channel_kind="stdin", attacker_control="caller stdin bytes",
        provenance_path=[], consumer_hints=[fn.function_id],
        evidence=[Evidence("source", fn.function_id, fn.file, 3, "fgets from stdin")],
        unknowns=[], verifier_confidence=1, entry_line=3,
        site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        first_acquisition_confirmed=True,
        inspected_function_ids=[fn.function_id],
    )
    graph = GraphStore(AnalysisBundle(
        functions={fn.function_id: fn}, edges=[],
        completeness={"provider": "fixture", "authoritative": False},
    ))
    return graph, fn, entry


class BoundaryUdpStartupTest(unittest.TestCase):
    def test_delayed_udp_only_listener_receives_exactly_one_request(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        received: list[bytes] = []
        ready = threading.Event()

        def serve() -> None:
            time.sleep(0.12)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
                listener.bind(("127.0.0.1", port))
                listener.settimeout(1)
                ready.set()
                data, peer = listener.recvfrom(1024)
                received.append(data)
                listener.sendto(b"PONG", peer)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            response = _socket_trial(
                "127.0.0.1", port, "udp", b"PING", 2, 0.3, 1024,
            )
        finally:
            worker.join(timeout=2)
        self.assertTrue(ready.is_set())
        self.assertFalse(worker.is_alive())
        self.assertEqual(response, b"PONG")
        self.assertEqual(received, [b"PING"])

    def test_udp_port_probe_refuses_an_existing_listener(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            self.assertTrue(_endpoint_is_active(
                "127.0.0.1", listener.getsockname()[1], "udp",
            ))

    def test_silent_udp_listener_does_not_receive_a_duplicate_trial(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.settimeout(0.5)
            received: list[bytes] = []

            def serve() -> None:
                try:
                    while True:
                        received.append(listener.recvfrom(1024)[0])
                except socket.timeout:
                    pass

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                response = _socket_trial(
                    "127.0.0.1", port, "udp", b"PING", 1, 0.2, 1024,
                )
            finally:
                worker.join(timeout=2)
            self.assertEqual(response, b"")
            self.assertEqual(received, [b"PING"])

    def test_ipv6_udp_loopback_uses_the_matching_socket_family(self) -> None:
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            listener.bind(("::1", 0))
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {exc}")
        with listener:
            port = listener.getsockname()[1]
            self.assertTrue(_endpoint_is_active("::1", port, "udp"))
            listener.settimeout(1)

            def serve() -> None:
                data, peer = listener.recvfrom(1024)
                listener.sendto(data + b"!", peer)

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                response = _socket_trial("::1", port, "udp", b"PING", 1, 1, 1024)
            finally:
                worker.join(timeout=2)
            self.assertEqual(response, b"PING!")


def behavior_response(fn: FunctionMetadata) -> dict:
    return {
        "behaviors": [{
            "target_function_id": fn.function_id,
            "kind": "computation", "summary": "test the first stdin byte",
            "input_flow": "stdin buffer", "effect": "compare first byte",
            "prior_state": "none", "execution_mode": "in_process_reset",
            "path_function_ids": [fn.function_id],
            "evidence": [{
                "function_id": fn.function_id, "line": 4,
                "detail": "checks the byte acquired by fgets",
            }],
        }],
        "requested_function_ids": [], "context_complete": True,
        "rationale": "byte effect with no branch action taxonomy",
    }


def contract_response(fn: FunctionMetadata, *, reset: str = "in_process_reset") -> dict:
    return {
        "input_binding": "real fgets reads caller-owned stdin",
        "calls": [], "prerequisite_bytes_hex": [],
        "isolation": reset,
        "repeatability_evidence": [{
            "function_id": fn.function_id, "line": 2,
            "detail": "stack-local temporary buffer recreated at each invocation",
        }] if reset == "in_process_reset" else [],
        "result_condition": "return value represents first byte comparison",
        "requested_function_ids": [], "context_complete": True,
        "unknowns": [], "rationale": "local buffer and no stored state in this source",
    }


class EvidenceLedAgentTest(unittest.IsolatedAsyncioTestCase):
    async def test_default_repair_budget_allows_third_attempt_and_stops_repeated_failure(self) -> None:
        graph, fn, entry = source_graph()
        checks = [
            {"check_id": f"HC{i:02d}", "status": "PASS", "evidence": "fixture"}
            for i in range(1, 17)
        ]

        def blocked_draft(reason: str) -> dict:
            return {
                "code": "",
                "manifest": {"build_target": "application", "headers": [],
                             "libraries": [], "min_size": 0, "max_size": 4096},
                "checklist": checks,
                "generation_blockers": [reason],
                "input_delivery_evidence": [],
            }

        llm = ScriptedLLM([
            behavior_response(fn),
            {"samples": [{"data_hex": "410a", "rationale": "stdin sample"}],
             "requested_function_ids": [], "context_complete": True, "rationale": "stdin"},
            contract_response(fn),
            {"requested_function_ids": [], "context_complete": True,
             "blocking_unknowns": [], "rationale": "whole function inspected"},
            blocked_draft("missing declaration A"),
            blocked_draft("missing declaration B"),
            blocked_draft("missing declaration A"),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                verification_backend="command", scenario_source_drafts=True,
                max_source_drafts=1,
            ).normalized()
            store = ArtifactStore(root / "runs" / "third-attempt")
            summary = await run_boundary_workflow(
                project=project, run_id="third-attempt", store=store,
                analysis=graph.bundle, graph=graph, llm=llm, trace=None,
                candidates=[], verified=[entry], unresolved=[],
                uninspected_functions=0, max_generation_attempts=0,
                dynamic_verification=False,
            )
            self.assertEqual(summary.generation_attempts, 3)
            self.assertEqual(len(llm.responses), 0)
            self.assertTrue(list((store.root / "harnesses").glob("*/attempt-3/draft.json")))

    async def test_protocol_name_does_not_inject_product_regression_vectors(self) -> None:
        graph, _fn, entry = source_graph()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "memcached-copy"
            root.mkdir()
            store = ArtifactStore(root / "runs" / "generic")
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                scenario_channel="tcp", scenario_port=12345,
                scenario_command=["/bin/true"],
                scenario_response_protocol="memcached_ascii",
            ).normalized()
            await run_boundary_workflow(
                project=project, run_id="generic", store=store,
                analysis=graph.bundle, graph=graph, llm=ScriptedLLM([]),
                trace=None, candidates=[], verified=[entry], unresolved=[],
                uninspected_functions=0, max_generation_attempts=1,
                dynamic_verification=False,
            )
            events = (store.root / "workflow" / "work-events.jsonl").read_text()
            self.assertNotIn("protocol-regression", events)
            self.assertFalse((store.root / "workflow" / "memcached-source-runtime-paths.json").exists())

    async def test_retired_resume_option_preserves_existing_artifacts(self) -> None:
        graph, _fn, _entry = source_graph()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "runs" / "saved"
            (existing / "workflow").mkdir(parents=True)
            (existing / "workflow" / "resume-fingerprint.json").write_text(
                '{"sha256":"wrong"}\n', encoding="utf-8",
            )
            sentinel = existing / "project.json"
            sentinel.write_text("old project evidence\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Action workflow does not support"):
                HarnessCreator(
                    ProjectSpec(
                        source_root=root, output_root=root / "runs",
                        resume_run_id="saved", svf_enabled=False,
                    ),
                    ScriptedLLM([]), precomputed_analysis=graph.bundle,
                )
            self.assertEqual(sentinel.read_text(encoding="utf-8"),
                             "old project evidence\n")
            self.assertFalse((existing / "workflow" / "capability-preflight.json").exists())

    async def test_second_entry_is_scheduled_before_first_entry_extra_effect(self) -> None:
        graph, fn, first = source_graph()
        second = replace(first, entry_id="second-entry", candidate_id="second")
        two = behavior_response(fn)
        two["behaviors"].append({**two["behaviors"][0],
                                 "summary": "other computation", "effect": "other effect"})
        sample = {"samples": [{"data_hex": "410a", "rationale": "bytes"}],
                  "requested_function_ids": [], "context_complete": True, "rationale": "input"}
        unknown = contract_response(fn, reset="unknown")
        llm = ScriptedLLM([
            two, sample, unknown,
            behavior_response(fn), sample, unknown,
            unknown,
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(source_root=root, output_root=root / "runs").normalized()
            await run_boundary_workflow(
                project=project, run_id="fair", store=ArtifactStore(root / "runs" / "fair"),
                analysis=graph.bundle, graph=graph, llm=llm, trace=None,
                candidates=[], verified=[first, second], unresolved=[],
                uninspected_functions=0, max_generation_attempts=1,
                dynamic_verification=False,
            )
        roles = [call["role"] for call in llm.calls]
        self.assertEqual(roles, [
            "behavior_recovery", "input_surface", "execution_contract",
            "behavior_recovery", "input_surface", "execution_contract",
            "execution_contract",
        ])

    async def test_unsupported_backend_blocks_before_generation_and_resumes_without_model(self) -> None:
        graph, fn, entry = source_graph()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs", max_source_drafts=8,
            ).normalized()
            store = ArtifactStore(root / "runs" / "blocked")
            llm = ScriptedLLM([
                behavior_response(fn),
                {"samples": [{"data_hex": "410a", "rationale": "stdin bytes"}],
                 "requested_function_ids": [], "context_complete": True, "rationale": "sample"},
                contract_response(fn, reset="process_isolation_required"),
            ])
            kwargs = dict(
                project=project, run_id="blocked", store=store, analysis=graph.bundle,
                graph=graph, trace=None, candidates=[], verified=[entry], unresolved=[],
                uninspected_functions=0, max_generation_attempts=1,
                dynamic_verification=False,
            )
            first = await run_boundary_workflow(llm=llm, **kwargs)
            self.assertEqual(first.harnesses_generated, 0)
            self.assertEqual(first.execution_contracts, 1)
            self.assertFalse(any(call["role"] == "harness_generator" for call in llm.calls))
            events = (store.root / "workflow" / "work-events.jsonl").read_text()
            self.assertIn("BLOCKED_UNSUPPORTED_BACKEND", events)
            replay_llm = ScriptedLLM([])
            await run_boundary_workflow(llm=replay_llm, **kwargs)
            self.assertEqual(replay_llm.calls, [])

    async def test_behavior_receives_exact_complete_function_without_splitting(self) -> None:
        graph, fn, entry = source_graph()
        llm = ScriptedLLM([behavior_response(fn)])
        agent = BehaviorRecoveryAgent(llm, graph)
        behaviors = await agent.run([entry])
        self.assertEqual(len(behaviors), 1)
        self.assertEqual(behaviors[0].kind, "computation")
        self.assertEqual(llm.calls[0]["payload"]["current_function"]["source"], fn.source)
        self.assertNotIn("action", llm.calls[0]["payload"])

    async def test_unknown_reset_is_not_complete_even_when_model_says_complete(self) -> None:
        graph, fn, entry = source_graph()
        behavior = (await BehaviorRecoveryAgent(
            ScriptedLLM([behavior_response(fn)]), graph,
        ).run([entry]))[0]
        contract = (await ExecutionContractAgent(
            ScriptedLLM([contract_response(fn, reset="unknown")]), graph,
        ).run([behavior], {entry.entry_id: "stdin"}))[0]
        self.assertFalse(contract.evidence_complete)
        self.assertTrue(any("reset" in issue for issue in contract.unknowns))

    async def test_no_prerequisite_is_valid_when_source_is_stateless(self) -> None:
        graph, fn, entry = source_graph()
        behavior = (await BehaviorRecoveryAgent(
            ScriptedLLM([behavior_response(fn)]), graph,
        ).run([entry]))[0]
        contract = (await ExecutionContractAgent(
            ScriptedLLM([contract_response(fn)]), graph,
        ).run([behavior], {entry.entry_id: "stdin"}))[0]
        self.assertTrue(contract.evidence_complete)
        self.assertFalse(contract.calls)
        self.assertTrue(select_backend(contract).backend_implemented)

    async def test_process_required_does_not_silently_use_libfuzzer(self) -> None:
        graph, fn, entry = source_graph()
        behavior = (await BehaviorRecoveryAgent(
            ScriptedLLM([behavior_response(fn)]), graph,
        ).run([entry]))[0]
        contract = (await ExecutionContractAgent(
            ScriptedLLM([contract_response(fn, reset="process_isolation_required")]), graph,
        ).run([behavior], {entry.entry_id: "stdin"}))[0]
        selected = select_backend(contract)
        self.assertFalse(selected.backend_implemented)
        self.assertEqual(selected.required_execution, "fresh_process_per_input")

    async def test_unknown_reset_requires_external_backend_for_known_transport(self) -> None:
        graph, fn, entry = source_graph()
        behavior = (await BehaviorRecoveryAgent(
            ScriptedLLM([behavior_response(fn)]), graph,
        ).run([entry]))[0]
        contract = (await ExecutionContractAgent(
            ScriptedLLM([contract_response(fn, reset="unknown")]), graph,
        ).run([behavior], {entry.entry_id: "tcp"}))[0]
        self.assertFalse(contract.evidence_complete)
        selected = select_backend(contract)
        self.assertFalse(selected.backend_implemented)
        self.assertEqual(selected.selected_backend, "external_stateful_fuzzer")
        self.assertEqual(selected.required_execution, "stateful_network_sequence")

    async def test_local_original_execution_accepts_unclassified_stdin_bytes(self) -> None:
        _graph, fn, entry = source_graph()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                scenario_command=[sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                scenario_channel="stdin",
            ).normalized()
            case = InputSurfaceCase(
                case_id="case-1", entry_id=entry.entry_id,
                entry_function_id=fn.function_id, source_api="fgets",
                channel_kind="stdin", data_hex=b"A\x00B\n".hex(),
                origin="test", rationale="raw byte source",
            )
            trial = await BoundaryTrialRunner(project).run(case, entry)
            self.assertEqual(trial.status, "OBSERVED_EXIT")
            self.assertEqual(bytes.fromhex(trial.response_hex), b"A\x00B\n")
            self.assertFalse(trial.handler_attributed)

    async def test_original_trial_size_uses_only_operator_selected_limit(self) -> None:
        _graph, fn, entry = source_graph()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"A" * 70_000
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                scenario_command=[
                    sys.executable, "-c",
                    "import sys; raw=sys.stdin.buffer.read(); "
                    "sys.stdout.write(str(len(raw)))",
                ],
                scenario_channel="stdin", scenario_step_timeout=2,
                max_input_trial_bytes=0,
            ).normalized()
            case = InputSurfaceCase(
                case_id="large-stdin", entry_id=entry.entry_id,
                entry_function_id=fn.function_id, source_api="fgets",
                channel_kind="stdin", data_hex=payload.hex(),
                origin="test", rationale="large source-backed input",
            )
            observed = await BoundaryTrialRunner(project).run(case, entry)
            self.assertEqual(observed.status, "OBSERVED_EXIT", observed.failure_reason)
            self.assertEqual(bytes.fromhex(observed.response_hex), b"70000")
            limited = await BoundaryTrialRunner(replace(
                project, max_input_trial_bytes=65_536,
            )).run(case, entry)
            self.assertEqual(limited.status, "INCOMPATIBLE_INPUT")
            self.assertIn("operator-selected", limited.failure_reason)


    async def test_exact_request_trace_attributes_handler_but_response_alone_does_not(self) -> None:
        _graph, fn, entry = source_graph()
        script = (
            "import os,sys,json,hashlib;"
            "raw=sys.stdin.buffer.read();"
            "path=os.environ['HARNESSCREATOR_TRACE_JSONL'];"
            "digest=hashlib.sha256(raw).hexdigest();"
            "base={'request_id':'req-1','connection_id':'stdin-1'};"
            "events=[dict(base,event='acquire',entry_function_id=" + repr(fn.function_id) +
            ",request_sha256=digest),dict(base,event='handler',handler_function_id=" +
            repr(fn.function_id) + ")];"
            "open(path,'a').write(''.join(json.dumps(e)+'\\n' for e in events));"
            "sys.stdout.buffer.write(raw)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs", scenario_attribution="trace",
                scenario_command=[sys.executable, "-c", script], scenario_channel="stdin",
            ).normalized()
            case = InputSurfaceCase(
                case_id="case-trace", entry_id=entry.entry_id,
                entry_function_id=fn.function_id, source_api="fgets",
                channel_kind="stdin", data_hex=b"A\n".hex(),
                origin="test", rationale="instrumented bytes",
            )
            trial = await BoundaryTrialRunner(project).run_attributed(
                case, entry, fn.function_id, root / "trace.jsonl",
            )
            self.assertEqual(trial.status, "OBSERVED_EXIT")
            self.assertTrue(trial.handler_attributed, trial.failure_reason)
            self.assertTrue(trial.target_reached)

    async def test_new_pipeline_runs_without_a_single_action_or_large_feature(self) -> None:
        graph, fn, entry = source_graph()
        checks = [
            {"check_id": f"HC{i:02d}", "status": "PASS", "evidence": "independent test evidence"}
            for i in range(1, 17)
        ]
        review_checks = [
            {**item, "remediation": ""} for item in checks
        ]
        src = (
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int consume_stream(void);\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
            "  if (Size < 1) return 0;\n"
            "  (void)Data[0];\n"
            "  return consume_stream();\n}\n"
        )
        llm = ScriptedLLM([
            behavior_response(fn),
            {"samples": [{"data_hex": "410a", "rationale": "A followed by newline"}],
             "requested_function_ids": [], "context_complete": True, "rationale": "stdin"},
            contract_response(fn),
            {"requested_function_ids": [], "context_complete": True,
             "blocking_unknowns": [], "rationale": "inspected one whole function"},
            {"code": src,
             "manifest": {"build_target": "application", "headers": [],
                          "libraries": [], "min_size": 1, "max_size": 4096},
             "checklist": checks, "generation_blockers": [],
             "input_delivery_evidence": [{
                 "function_id": fn.function_id, "line": 3,
                 "detail": "app consumes stdin via fgets",
             }]},
            {"requested_function_ids": [], "context_complete": True,
             "blocking_unknowns": [], "rationale": "independent source review"},
            {"checks": review_checks, "summary": "auditor's syntactic pass"},
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                verification_backend="command", scenario_source_drafts=True,
                max_source_drafts=1,
            ).normalized()
            store = ArtifactStore(root / "runs" / "one")
            summary = await run_boundary_workflow(
                project=project, run_id="one", store=store,
                analysis=graph.bundle, graph=graph, llm=llm, trace=None,
                candidates=[], verified=[entry], unresolved=[],
                uninspected_functions=0, max_generation_attempts=1,
                dynamic_verification=False,
            )
            self.assertEqual(summary.action_schemas, 0)
            self.assertEqual(summary.scenario_candidates, 0)
            self.assertEqual(summary.behavior_candidates, 1)
            self.assertEqual(summary.execution_contracts, 1)
            self.assertEqual(summary.harnesses_generated, 1)
            self.assertEqual(summary.harnesses_static_passed, 0)
            self.assertEqual(summary.harnesses_build_passed, 0)
            self.assertEqual(summary.harnesses_qualified, 0)
            self.assertIn("UNQUALIFIED", summary.status)
            self.assertEqual(llm.responses.__len__(), 0)
            opened_turns = [call for call in llm.calls
                            if "current_function" in call["payload"]]
            self.assertTrue(opened_turns)
            self.assertTrue(all(call["payload"]["current_function"]["source"] == fn.source
                                for call in opened_turns))

    async def test_real_c_executable_builds_input_driven_unqualified_harness(self) -> None:
        compiler = shutil.which("g++")
        if not compiler:
            self.skipTest("g++ and its sanitizer runtime are required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_text = (
                "#include <stdio.h>\n#include <stddef.h>\n"
                "#ifdef __cplusplus\nextern \"C\" {\n#endif\n"
                "int parse_bytes(const unsigned char *data, size_t size) {\n"
                "  if (size == 0) return 0;\n"
                "  return data[0] == 'A';\n}\n"
                "#ifdef __cplusplus\n}\n#endif\n"
                "#ifndef HARNESS_BUILD\n"
                "int main(void) {\n"
                "  unsigned char bytes[64];\n"
                "  size_t count = fread(bytes, 1, sizeof(bytes), stdin);\n"
                "  return parse_bytes(bytes, count);\n}\n"
                "#endif\n"
            )
            (root / "target.c").write_text(target_text, encoding="utf-8")
            parser = FunctionMetadata.create(
                name="parse_bytes", signature="int parse_bytes(const unsigned char*, size_t)",
                file="target.c", start_line=6, end_line=9,
                source="\n".join(target_text.splitlines()[5:9]),
            )
            main = FunctionMetadata.create(
                name="main", signature="int main(void)", file="target.c",
                start_line=14, end_line=18,
                source="\n".join(target_text.splitlines()[13:18]),
            )
            from harnesscreator.models import CallEdge
            self.assertIn("fread", main.source)
            # Graph edges are only navigation, not proof of byte dependence.
            edge = CallEdge(
                edge_id="main-to-parser", caller_id=main.function_id,
                callee_id=parser.function_id, line=17,
            )
            graph = GraphStore(AnalysisBundle(
                functions={main.function_id: main, parser.function_id: parser},
                edges=[edge], completeness={"provider": "test"},
            ))
            entry = EntryRecord(
                entry_id="stdin-main", candidate_id="c", status=Verdict.VERIFIED,
                entry_function_id=main.function_id, source_api="fread",
                channel_kind="stdin", attacker_control="stdin",
                provenance_path=[], consumer_hints=[parser.function_id],
                evidence=[Evidence("source", main.function_id, "target.c", 16, "fread")],
                unknowns=[], verifier_confidence=1.0, entry_line=16,
                first_acquisition_confirmed=True,
            )
            audit = [
                {"check_id": f"HC{i:02d}", "status": "PASS", "evidence": "source-backed fixture"}
                for i in range(1, 17)
            ]
            response = lambda fid: {
                "requested_function_ids": [], "context_complete": True,
                "blocking_unknowns": [], "rationale": f"opened {fid}",
            }
            generator_code = (
                "#include <cstdint>\n#include <cstddef>\n"
                "extern \"C\" int parse_bytes(const unsigned char*, size_t);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                "  (void)parse_bytes(Data, Size);\n  return 0;\n}\n"
            )
            behavior = {
                "behaviors": [{
                    "target_function_id": parser.function_id, "kind": "computation",
                    "summary": "byte value parsing", "path_function_ids": [main.function_id, parser.function_id],
                    "input_flow": "fread buffer to parse_bytes", "effect": "parse first byte",
                    "prior_state": "none", "execution_mode": "in_process_reset",
                    "evidence": [{"function_id": main.function_id, "line": 17, "detail": "fread feeds parser"},
                                 {"function_id": parser.function_id, "line": 8, "detail": "byte accessed"}],
                }], "requested_function_ids": [], "context_complete": True, "rationale": "direct byte path",
            }
            contract = {
                "input_binding": "Data/Size substitute fread byte buffer before parse_bytes",
                "calls": [], "prerequisite_bytes_hex": [], "isolation": "in_process_reset",
                "repeatability_evidence": [{"function_id": parser.function_id, "line": 7,
                                            "detail": "function owns no persistent state"}],
                "result_condition": "parser return", "requested_function_ids": [],
                "context_complete": True, "unknowns": [], "rationale": "pure parser",
            }
            llm = ScriptedLLM([
                {"behaviors": [], "requested_function_ids": [parser.function_id],
                 "context_complete": False, "rationale": "open callee"},
                behavior,
                {"samples": [{"data_hex": "41", "rationale": "valid byte"}],
                 "requested_function_ids": [], "context_complete": True, "rationale": "raw stdin"},
                {**contract, "context_complete": False}, contract,
                {**response(main.function_id),
                 "blocking_unknowns": ["parse_bytes body must be opened"]},
                response(parser.function_id),
                {"code": generator_code,
                 "manifest": {"build_target": "target", "headers": [], "libraries": [],
                              "min_size": 0, "max_size": 4096},
                 "checklist": audit, "generation_blockers": [],
                 "input_delivery_evidence": [
                     {"function_id": main.function_id, "line": 17, "detail": "fread to parser"},
                     {"function_id": parser.function_id, "line": 6, "detail": "parser receives buffer"},
                 ]},
                response(main.function_id), response(parser.function_id),
                {"checks": [{**item, "remediation": ""} for item in audit],
                 "summary": "source-level audit"},
            ])
            driver = Path(__file__).parent / "fixtures" / "fuzz_driver.cc"
            project = ProjectSpec(
                source_root=root, output_root=root / "runs", max_source_drafts=1,
                verification_backend="command", scenario_source_drafts=True,
                harness_source_filename="fuzz_target.cc",
                build_command=[compiler, "-std=c++17", "-DHARNESS_BUILD",
                               "-fsanitize=address,undefined", "{harness}",
                               "{source_root}/target.c", str(driver),
                               "-o", "{output}/fuzz_target"],
                harness_binary="{output}/fuzz_target",
            ).normalized()
            store = ArtifactStore(root / "runs" / "native")
            summary = await run_boundary_workflow(
                project=project, run_id="native", store=store,
                analysis=graph.bundle, graph=graph, llm=llm, trace=None,
                candidates=[], verified=[entry], unresolved=[],
                uninspected_functions=0, max_generation_attempts=1,
                dynamic_verification=False,
            )
            self.assertEqual(summary.harnesses_generated, 1)
            self.assertEqual(summary.harnesses_build_passed, 1)
            self.assertEqual(summary.status, "BUILD_VERIFIED_UNQUALIFIED")
            self.assertEqual(summary.harnesses_qualified, 0)
            self.assertEqual(len(llm.responses), 0)


if __name__ == "__main__":
    unittest.main()
