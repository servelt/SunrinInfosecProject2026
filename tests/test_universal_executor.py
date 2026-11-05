"""Source-wide discovery must be independent from original execution adapters.

These cases compile REAL C with file/argv/environment data acquisition, not
scripted-model output or fabricated runtime response logs. Exact target proof
still requires a source-instrumented trace; a test-only injected observer is
diagnostic and cannot create a proven witness.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.cli import build_parser, _run
from harnesscreator.input_transport import source_transport
from harnesscreator.models import (
    ActionExample, EntryRecord, Evidence, ExternalActionSchema, ProjectSpec,
    ProofStatus, ScenarioCandidate, ScenarioStatus, ScenarioStep, Verdict,
)
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier, _action_transport
from unittest.mock import patch

FIXTURE = Path(__file__).parent / "fixtures" / "multi_input.c"


def _candidate(action):
    return ScenarioCandidate(
        "scenario-" + action.action_id, action.action_id,
        [ScenarioStep(0, action.action_id, "entry-" + action.action_id,
                      b"HELLO".hex(), {}, [b"OK\n".hex()])],
        ["entry-" + action.action_id], [], [],
    )


def _action(name, source, handler, mode):
    evidence = [Evidence("source", source.function_id, source.file, source.start_line,
                         "first external input acquisition")]
    return ExternalActionSchema(
        action_id=name, entry_id="entry-" + name,
        name=name, description=name, dispatcher_function_id=handler.function_id,
        handler_function_id=handler.function_id, discriminator=name,
        channel_kind={"file":"file contents", "argv":"argv command line argument",
                      "env":"environment variable"}[mode],
        fields=[], examples=[ActionExample(b"HELLO".hex())],
        success_markers_hex=[b"OK\n".hex()], failure_markers_hex=[b"ERR\n".hex()],
        evidence=evidence, inspected_function_ids=[source.function_id, handler.function_id],
        status=ProofStatus.PROVEN_STATIC,
        source_api={"file":"fread", "argv":"argv", "env":"getenv"}[mode],
        success_evidence=evidence,
        entry_function_id=source.function_id, entry_probe_evidence=evidence,
    )


def _entry_for_transport(action):
    return EntryRecord(
        entry_id=action.entry_id, candidate_id=action.entry_id,
        status=Verdict.VERIFIED, entry_function_id=action.entry_function_id,
        source_api=action.source_api, channel_kind=action.channel_kind,
        attacker_control="external client", provenance_path=[],
        consumer_hints=[], evidence=[], unknowns=[], verifier_confidence=1.0,
    )


class MultipleInputSurfaces(unittest.IsolatedAsyncioTestCase):
    async def test_file_argv_environment_replay_but_no_false_proof(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("C compiler required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "multi_input.c").write_bytes(FIXTURE.read_bytes())
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {f.name: f for f in graph.bundle.functions.values()}
            output = root / "target"
            subprocess.run([cc, "-O0", "-g", str(root/"multi_input.c"), "-o", str(output)], check=True)
            for mode, fn, command in [
                ("file", "load_file", [str(output), "file", "{input_file}"]),
                ("argv", "load_argv", [str(output), "argv", "{input_arg}"]),
                ("env", "load_environment", [str(output), "env"]),
            ]:
                with self.subTest(mode=mode):
                    action = _action(mode, functions[fn], functions["accept_request"], mode)
                    self.assertEqual(_action_transport(action), mode)
                    project = ProjectSpec(
                        source_root=root, output_root=root / "out",
                        scenario_channel="auto", scenario_command=command,
                        scenario_attribution="gdb", scenario_exploratory_drafts=True,
                    ).normalized()
                    # No instrumented trace: original process returns OK, but
                    # cannot prove which handler was executed from that alone.
                    witness = await ScenarioRuntimeVerifier(project, [action], graph).verify(
                        _candidate(action)
                    )
                    self.assertEqual(witness.status, ScenarioStatus.REPLAYED_RUNTIME, witness.rationale)
                    self.assertTrue(witness.observations[0].response_success)
                    self.assertFalse(witness.observations[0].target_reached)
                    self.assertEqual(witness.channel, mode)
                    # A test observer can exercise the adapter but cannot
                    # establish request-to-handler causality or response
                    # attribution for a real original program.
                    witnessed = await ScenarioRuntimeVerifier(
                        project, [action], graph, target_observer=lambda *_: True,
                    ).verify(_candidate(action))
                    self.assertEqual(witnessed.status, ScenarioStatus.UNPROVEN, witnessed.rationale)
                    self.assertEqual(
                        witnessed.observations[0].target_probe,
                        "injected runtime target observer",
                    )

    async def test_unconfigured_or_unsafe_materialization_remains_unproven(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "multi_input.c").write_bytes(FIXTURE.read_bytes())
            graph = GraphStore(StaticAnalyzer(root).index())
            f = {f.name: f for f in graph.bundle.functions.values()}
            action = _action("file", f["load_file"], f["accept_request"], "file")
            project = ProjectSpec(source_root=root, output_root=root/"out",
                                  scenario_command=["/bin/true"],
                                  scenario_channel="auto", scenario_exploratory_drafts=True).normalized()
            w = await ScenarioRuntimeVerifier(project, [action], graph).verify(_candidate(action))
            self.assertEqual(w.status, ScenarioStatus.UNPROVEN)
            self.assertIn("{input_file}", w.rationale)
            # Without a command there is no original runtime proof, even
            # though the source-derived action remains in the inventory.
            no_command = ProjectSpec(source_root=root, output_root=root/"out").normalized()
            w = await ScenarioRuntimeVerifier(no_command, [action], graph).verify(_candidate(action))
            self.assertEqual(w.status, ScenarioStatus.UNPROVEN)

    async def test_ambiguous_fd_does_not_become_stdin_or_tcp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"multi_input.c").write_bytes(FIXTURE.read_bytes())
            graph = GraphStore(StaticAnalyzer(root).index())
            f = {f.name: f for f in graph.bundle.functions.values()}
            action = _action("read", f["load_file"], f["accept_request"], "file")
            action.channel_kind = "fd_or_stream"
            action.source_api = "read"
            self.assertEqual(_action_transport(action), "")
            project = ProjectSpec(source_root=root, output_root=root/"out",
                                  scenario_command=["/bin/true"], scenario_channel="auto").normalized()
            w = await ScenarioRuntimeVerifier(project, [action], graph).verify(_candidate(action))
            self.assertEqual(w.status, ScenarioStatus.UNPROVEN)
            self.assertIn("ambiguous", w.rationale)

    async def test_socket_api_does_not_choose_internet_transport_without_family_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "multi_input.c").write_bytes(FIXTURE.read_bytes())
            graph = GraphStore(StaticAnalyzer(root).index())
            functions = {f.name: f for f in graph.bundle.functions.values()}
            action = _action("file", functions["load_file"], functions["accept_request"], "file")
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_command=["/bin/true"], scenario_channel="auto",
                scenario_exploratory_drafts=True,
            ).normalized()
            for api, channel, expected in [
                ("recv", "network socket", ""),
                ("recvfrom", "network datagram", ""),
                ("recv", "AF_UNIX SOCK_STREAM local socket", "unix_stream"),
                ("recvfrom", "AF_UNIX SOCK_DGRAM local socket", ""),
                ("recv", "TCP or UDP socket", ""),
            ]:
                with self.subTest(api=api, channel=channel):
                    candidate = replace(action, source_api=api, channel_kind=channel)
                    self.assertEqual(_action_transport(candidate), expected)
                    self.assertEqual(
                        source_transport(_entry_for_transport(candidate)),
                        expected or "unknown",
                    )
                    witness = await ScenarioRuntimeVerifier(project, [candidate], graph).verify(
                        _candidate(candidate)
                    )
                    self.assertEqual(witness.status, ScenarioStatus.UNPROVEN)
            for api, channel, expected in [
                ("recv", "Internet TCP socket", "tcp"),
                ("recvfrom", "Internet UDP datagram", "udp"),
            ]:
                with self.subTest(api=api, channel=channel):
                    self.assertEqual(
                        _action_transport(replace(action, source_api=api, channel_kind=channel)),
                        expected,
                    )
                    self.assertEqual(
                        source_transport(_entry_for_transport(
                            replace(action, source_api=api, channel_kind=channel)
                        )), expected,
                    )
            explicit_tcp = replace(project, scenario_channel="tcp", scenario_port=11211)
            unix_action = replace(action, source_api="recv", channel_kind="AF_UNIX SOCK_STREAM local socket")
            unix_witness = await ScenarioRuntimeVerifier(
                explicit_tcp, [unix_action], graph,
            ).verify(_candidate(unix_action))
            self.assertEqual(unix_witness.status, ScenarioStatus.UNPROVEN)
            self.assertIn("uses unix_stream", unix_witness.rationale)

            occupied = root / "existing.sock"
            occupied.write_text("do not unlink")
            unix_project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_command=["/bin/true"], scenario_channel="unix_stream",
                scenario_socket_path=str(occupied),
                scenario_exploratory_drafts=True,
            ).normalized()
            occupied_witness = await ScenarioRuntimeVerifier(
                unix_project, [unix_action], graph,
            ).verify(_candidate(unix_action))
            self.assertEqual(occupied_witness.status, ScenarioStatus.UNPROVEN)
            self.assertIn("already exists", occupied_witness.rationale)
            self.assertEqual(occupied.read_text(), "do not unlink")

    async def test_canonical_upstream_build_does_not_block_pre_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oss = root / "oss-fuzz"
            (oss / "infra").mkdir(parents=True)
            (oss / "infra" / "helper.py").write_text("# fake helper")
            args = build_parser().parse_args([
                "run", str(root), "--allow-source-analysis",
                "--verification-backend", "oss-fuzz", "--oss-fuzz-dir", str(oss),
                "--oss-fuzz-project", "sample", "--oss-fuzz-fuzzer", "sample_fuzzer",
                "--harness-source-filename", "sample_fuzzer.c",
                "--oss-fuzz-source-path", "/src/sample",
            ])
            class StopBeforeLLM(Exception): pass
            with patch("harnesscreator.cli._resolve_oss_fuzz_recipe", return_value=(
                "sample_fuzzer", "sample_fuzzer.c", "/src/sample",
            )), patch(
                "harnesscreator.cli._prepare_fuzz_introspector", side_effect=StopBeforeLLM,
            ), patch(
                "harnesscreator.cli.preflight_oss_fuzz_backend", side_effect=AssertionError("premature preflight")
            ), patch(
                "harnesscreator.cli.NativeOssFuzzVerifierAgent.probe_canonical_build",
                side_effect=AssertionError("premature canonical build"),
            ):
                with self.assertRaises(StopBeforeLLM):
                    await _run(args)

    async def test_cli_reaches_static_preparation_without_original_or_oss_fuzz(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = build_parser().parse_args(["run", str(root), "--allow-source-analysis"])
            self.assertEqual(args.scenario_channel, "auto")
            class StopBeforeLLM(Exception): pass
            with patch("harnesscreator.cli._prepare_fuzz_introspector", side_effect=StopBeforeLLM):
                with self.assertRaises(StopBeforeLLM):
                    await _run(args)


class SourceOnlyDraftContracts(unittest.TestCase):
    def test_silent_file_action_can_be_planned_without_runtime_oracle(self):
        from harnesscreator.agents.scenario import ScenarioPlanner
        from harnesscreator.agents.scenario_harness import build_harness_plan
        from harnesscreator.models import (
            ActionStateContract, StateDependencyGraph, ScenarioWitness,
        )
        from harnesscreator.runtime.contracts import audit_harness_plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "multi_input.c").write_bytes(FIXTURE.read_bytes())
            graph = GraphStore(StaticAnalyzer(root).index())
            funcs = {f.name: f for f in graph.bundle.functions.values()}
            action = _action("file", funcs["load_file"], funcs["accept_request"], "file")
            # File tools and parsers frequently produce NO response frame.
            action.success_markers_hex = []
            deps = StateDependencyGraph(
                contracts=[ActionStateContract("file", [], [], [], "exit 0",
                                               action.evidence, [funcs["accept_request"].function_id],
                                               ProofStatus.PROVEN_STATIC)],
                initial_resources=[], open_obligations=[],
            )
            scenarios = ScenarioPlanner(max_steps=2).plan([action], deps)
            candidate = next(x for x in scenarios if x.status is ScenarioStatus.CANDIDATE)
            witness = ScenarioWitness(
                witness_id="source-only", scenario_id=candidate.scenario_id,
                target_action_id=candidate.target_action_id, steps=candidate.steps,
                observations=[], command=[], channel="file", process_returncode=None,
                status=ScenarioStatus.UNPROVEN, rationale="no executor",
            )
            paths = {"file": (funcs["load_file"].function_id, funcs["accept_request"].function_id)}
            with self.assertRaises(ValueError):
                build_harness_plan(witness, action_function_ids=paths)
            plan = build_harness_plan(witness, action_function_ids=paths, allow_unproven=True)
            self.assertEqual(plan.boundary_contract["status"], "SOURCE_ONLY_UNVERIFIED")
            self.assertFalse(audit_harness_plan(witness, plan).passed)
            self.assertTrue(audit_harness_plan(witness, plan, allow_unproven=True).passed)

    def test_unknown_inputs_never_fabricate_environment_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"v.c").write_text('char *read_env(char *name) {return getenv(name);}', encoding="utf-8")
            graph = GraphStore(StaticAnalyzer(root).index())
            src = list(graph.bundle.functions.values())[0]
            action = _action("env", src, src, "env")
            proj = ProjectSpec(source_root=root, output_root=root/"out",
                               scenario_channel="env", scenario_command=["/bin/true"]).normalized()
            runner = ScenarioRuntimeVerifier(proj, [action], graph)
            self.assertEqual(runner._environment_variable_name("env"), "")
