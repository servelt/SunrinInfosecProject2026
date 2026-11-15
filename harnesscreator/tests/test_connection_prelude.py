"""Server-first lines are separate from responses to client requests."""

from __future__ import annotations

import socket
import sys
import tempfile
import unittest
from pathlib import Path

from harnesscreator.models import (
    ActionExample, ExternalActionSchema, ProjectSpec, ProofStatus,
    ScenarioCandidate, ScenarioStep,
)
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ConnectionPreludeTests(unittest.IsolatedAsyncioTestCase):
    async def _replay(self, marker: bytes):
        port = _free_port()
        script = (
            "import socket,sys\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen(1)\n"
            "c,_=s.accept(); c.sendall(b'120 Starting\\r\\n220 Ready\\r\\n')\n"
            "c.settimeout(0.5)\n"
            "try: data=c.recv(4096)\n"
            "except socket.timeout: data=b''\n"
            "if data==b'USER test\\r\\n': c.sendall(b'331 Password required\\r\\n')\n"
            "c.close(); s.close()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script, str(port)],
                scenario_channel="tcp", scenario_host="127.0.0.1",
                scenario_port=port, scenario_startup_timeout=1,
                scenario_step_timeout=1, scenario_require_target_reach=False,
            ).normalized()
            action = ExternalActionSchema(
                action_id="user", entry_id="entry-user", name="USER",
                description="login name", dispatcher_function_id="handler",
                handler_function_id="handler", discriminator="",
                channel_kind="network socket", fields=[],
                examples=[ActionExample(b"USER test\r\n".hex(), {})],
                success_markers_hex=[b"331 Password required\r\n".hex()], failure_markers_hex=[],
                evidence=[], inspected_function_ids=[],
                status=ProofStatus.POSSIBLE, source_api="recv",
                entry_function_id="entry-function",
                connection_prelude_marker_hex=marker.hex(),
            )
            candidate = ScenarioCandidate(
                "session", action.action_id,
                [ScenarioStep(
                    0, action.action_id, action.entry_id,
                    b"USER test\r\n".hex(), {}, [b"331 Password required\r\n".hex()],
                    connection_prelude_marker_hex=marker.hex(),
                )], [action.entry_id], [], [],
            )
            return await ScenarioRuntimeVerifier(project, [action]).verify(candidate)

    async def test_greeting_is_consumed_before_request_and_not_used_as_reply(self):
        witness = await self._replay(b"220")
        self.assertEqual(
            bytes.fromhex(witness.connection_prelude_hex),
            b"120 Starting\r\n220 Ready\r\n",
        )
        self.assertEqual(
            bytes.fromhex(witness.observations[0].response_hex),
            b"331 Password required\r\n",
        )
        self.assertTrue(witness.observations[0].request_write_completed)
        self.assertTrue(witness.observations[0].response_success)

    async def test_wrong_greeting_blocks_request_write(self):
        witness = await self._replay(b"999")
        self.assertFalse(witness.observations[0].request_write_completed)
        self.assertFalse(witness.observations[0].response_success)
        self.assertIn("not observed", witness.observations[0].detail)
