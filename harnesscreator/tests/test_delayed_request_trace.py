"""A response can arrive before the original process finishes writing its trace."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

from harnesscreator.models import ExternalActionSchema, ProjectSpec, ScenarioStep
from harnesscreator.runtime.request_trace import RequestTraceJournal, response_attested
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier


class DelayedRequestTraceTests(unittest.IsolatedAsyncioTestCase):
    async def test_result_written_after_response_is_observed_within_step_timeout(self) -> None:
        request = b"HELLO\n"
        response = b"OK\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace_file = root / "trace.jsonl"
            def append(event: dict) -> None:
                with trace_file.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(event) + "\n")

            append({
                "event": "acquire", "request_id": "r1", "connection_id": "c1",
                "entry_function_id": "entry", "request_sha256": hashlib.sha256(request).hexdigest(),
            })
            append({
                "event": "handler", "request_id": "r1", "connection_id": "c1",
                "handler_function_id": "handler",
            })
            action = ExternalActionSchema(
                action_id="hello", entry_id="entry", name="hello",
                description="test", dispatcher_function_id="handler",
                handler_function_id="handler", discriminator="",
                channel_kind="tcp", fields=[], examples=[],
                success_markers_hex=[], failure_markers_hex=[], evidence=[],
                inspected_function_ids=[], entry_function_id="entry",
            )
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_attribution="trace", scenario_step_timeout=0.5,
            )
            verifier = ScenarioRuntimeVerifier(project, [action])

            async def write_later() -> None:
                await asyncio.sleep(0.08)
                append({
                    "event": "result", "request_id": "r1", "connection_id": "c1",
                    "response_sha256": hashlib.sha256(response).hexdigest(),
                    "state_digest": hashlib.sha256(b"state").hexdigest(),
                })

            writer = asyncio.create_task(write_later())
            try:
                entry_reached, target_reached, _mechanism, trace = await verifier._target_reached(
                    ScenarioStep(0, "hello", "entry", request.hex(), {}, []),
                    action, request, response, RequestTraceJournal(trace_file), 0,
                )
            finally:
                await writer
            self.assertTrue(entry_reached)
            self.assertTrue(target_reached)
            self.assertTrue(response_attested(trace, response))

    async def test_missing_result_remains_unattested_after_timeout(self) -> None:
        request, response = b"X", b"OK\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace_file = root / "trace.jsonl"
            events = [
                {"event": "acquire", "request_id": "r1", "connection_id": "c1",
                 "entry_function_id": "entry", "request_sha256": hashlib.sha256(request).hexdigest()},
                {"event": "handler", "request_id": "r1", "connection_id": "c1",
                 "handler_function_id": "handler"},
            ]
            trace_file.write_text("".join(json.dumps(event) + "\n" for event in events))
            action = ExternalActionSchema(
                action_id="x", entry_id="entry", name="x", description="test",
                dispatcher_function_id="handler", handler_function_id="handler",
                discriminator="", channel_kind="stdin", fields=[], examples=[],
                success_markers_hex=[], failure_markers_hex=[], evidence=[],
                inspected_function_ids=[], entry_function_id="entry",
            )
            verifier = ScenarioRuntimeVerifier(ProjectSpec(
                source_root=root, output_root=root / "out", scenario_attribution="trace",
                scenario_step_timeout=0.03,
            ), [action])
            started = time.monotonic()
            entry_reached, target_reached, _mechanism, trace = await verifier._target_reached(
                ScenarioStep(0, "x", "entry", request.hex(), {}, []),
                action, request, response, RequestTraceJournal(trace_file), 0,
            )
            self.assertGreaterEqual(time.monotonic() - started, 0.025)
            self.assertTrue(entry_reached)
            self.assertTrue(target_reached)
            self.assertFalse(response_attested(trace, response))

    async def test_contradictory_completed_result_is_not_retried(self) -> None:
        request, response = b"X", b"OK\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace_file = root / "trace.jsonl"
            events = [
                {"event": "acquire", "request_id": "r1", "connection_id": "c1",
                 "entry_function_id": "entry", "request_sha256": hashlib.sha256(request).hexdigest()},
                {"event": "handler", "request_id": "r1", "connection_id": "c1",
                 "handler_function_id": "handler"},
                {"event": "result", "request_id": "r1", "connection_id": "c1",
                 "response_sha256": hashlib.sha256(b"WRONG\n").hexdigest(),
                 "state_digest": hashlib.sha256(b"state").hexdigest()},
            ]
            trace_file.write_text("".join(json.dumps(event) + "\n" for event in events))
            action = ExternalActionSchema(
                action_id="x", entry_id="entry", name="x", description="test",
                dispatcher_function_id="handler", handler_function_id="handler",
                discriminator="", channel_kind="stdin", fields=[], examples=[],
                success_markers_hex=[], failure_markers_hex=[], evidence=[],
                inspected_function_ids=[], entry_function_id="entry",
            )
            verifier = ScenarioRuntimeVerifier(ProjectSpec(
                source_root=root, output_root=root / "out", scenario_attribution="trace",
                scenario_step_timeout=0.5,
            ), [action])
            entry_reached, target_reached, mechanism, trace = await asyncio.wait_for(
                verifier._target_reached(
                    ScenarioStep(0, "x", "entry", request.hex(), {}, []),
                    action, request, response, RequestTraceJournal(trace_file), 0,
                ), timeout=0.15,
            )
            self.assertTrue(entry_reached)
            self.assertFalse(target_reached)
            self.assertIn("response differs", mechanism)
            self.assertFalse(response_attested(trace, response))


if __name__ == "__main__":
    unittest.main()
