"""Real C TCP, UDP and AF_UNIX stream execution, not scripted model output."""
from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.models import (
    ActionActor, ActionExample, Evidence, ExternalActionSchema, ProjectSpec,
    ProofStatus, ScenarioCandidate, ScenarioStatus, ScenarioStep,
)
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier

SOURCE = Path(__file__).parent / "fixtures" / "daemon_matrix.c"


def free_port(protocol: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RealDaemonMatrix(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_udp_and_unix_stream_use_same_request_contract(self):
        cc = shutil.which("cc")
        if not cc or not Path("/usr/include/openssl/sha.h").exists():
            self.skipTest("a C compiler and OpenSSL development headers are needed")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon_matrix.c").write_bytes(SOURCE.read_bytes())
            graph = GraphStore(StaticAnalyzer(root).index())
            names = {f.name: f for f in graph.bundle.functions.values()}
            entry = names["input_read"]
            handler = names["target_handler"]
            c_file = root / "daemon_matrix.c"
            c_file.write_text(c_file.read_text().replace("__ENTRY__", entry.function_id).replace("__HANDLER__", handler.function_id))
            executable = root / "daemon"
            proc = subprocess.run([cc, "-O0", "-g", str(c_file), "-pthread", "-lcrypto", "-o", str(executable)],
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest("fixture build could not link OpenSSL: " + proc.stderr)
            for protocol in ("tcp", "udp", "unix_stream"):
                with self.subTest(protocol=protocol):
                    evidence = [Evidence("source", entry.function_id, entry.file,
                                         entry.start_line, "read original external bytes")]
                    action = ExternalActionSchema(
                        action_id="HELLO", entry_id="entry", name="HELLO",
                        description="HELLO request", dispatcher_function_id=handler.function_id,
                        handler_function_id=handler.function_id, discriminator="HELLO",
                        channel_kind=("AF_UNIX SOCK_STREAM" if protocol == "unix_stream"
                                      else "AF_INET SOCK_STREAM or AF_UNIX SOCK_STREAM peer payload"
                                      if protocol == "tcp" else "network"), fields=[],
                        examples=[ActionExample(b"HELLO\n".hex(), {}, evidence=evidence)],
                        success_markers_hex=[b"OK\n".hex()],
                        failure_markers_hex=[b"ERR\n".hex()],
                        evidence=evidence, inspected_function_ids=[entry.function_id, handler.function_id],
                        status=ProofStatus.PROVEN_STATIC,
                        source_api="recvfrom" if protocol == "udp" else "recv",
                        success_evidence=evidence, entry_function_id=entry.function_id,
                        entry_probe_evidence=evidence,
                        actor=ActionActor.INBOUND_CLIENT,
                    )
                    port = free_port(protocol) if protocol != "unix_stream" else None
                    project = ProjectSpec(
                        source_root=root, output_root=root / "out",
                        scenario_command=[str(executable), protocol,
                                          "{scenario_socket_path}" if protocol == "unix_stream" else str(port)],
                        scenario_channel="auto" if protocol == "unix_stream" else protocol,
                        scenario_host="127.0.0.1", scenario_port=port,
                        scenario_attribution="trace", scenario_step_timeout=2,
                        scenario_startup_timeout=4,
                    ).normalized()
                    candidate = ScenarioCandidate(
                        f"{protocol}-hello", "HELLO",
                        [ScenarioStep(0, "HELLO", "entry", b"HELLO\n".hex(), {}, [b"OK\n".hex()])],
                        ["entry"], [], [],
                    )
                    result = await ScenarioRuntimeVerifier(project, [action], graph).verify(candidate)
                    self.assertEqual(result.status, ScenarioStatus.PROVEN_RUNTIME, result.rationale)
                    self.assertTrue(result.observations[0].target_reached)
                    self.assertTrue(result.observations[0].response_success)
                    self.assertTrue(result.observations[0].request_write_completed)
                    if protocol == "unix_stream":
                        self.assertEqual(result.channel, "unix_stream")
                        self.assertFalse(Path(result.command[-1]).exists())
                        plan = build_harness_plan(result, action_function_ids={
                            "HELLO": (entry.function_id, handler.function_id),
                        })
                        self.assertEqual(plan.reset_strategy, "loopback_network")
                        self.assertEqual(
                            plan.boundary_contract["mode"], "original_input_transport",
                        )
