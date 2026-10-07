from pathlib import Path
import json
import asyncio
import tempfile
import unittest

from harnesscreator.llm import CachingLLM, RecordingLLM, ScriptedLLM
from harnesscreator.storage import ArtifactStore


class ArtifactStoreTest(unittest.TestCase):
    def test_writes_exact_binary_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary))
            path = store.write_bytes("findings/f-1/input", b"\x00\xff\x80seed")

            self.assertEqual(path.read_bytes(), b"\x00\xff\x80seed")

    def test_streams_and_appends_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary))
            path = store.write_jsonl("events.jsonl", ({"value": value} for value in range(2)))
            store.append_jsonl("events.jsonl", {"value": 2})

            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(records, [{"value": 0}, {"value": 1}, {"value": 2}])


class CrashRecoveryTest(unittest.TestCase):
    def test_cache_ignores_only_an_interrupted_final_record(self) -> None:
        complete = {
            "role": "probe",
            "instructions": "test",
            "payload": {"value": 1},
            "output_schema": {"type": "object"},
            "status": "completed",
            "response": {"ok": True},
        }
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(complete) + "\n" + '{"role": "part', encoding="utf-8")
            cache = CachingLLM(ScriptedLLM([]), trajectory)

        self.assertEqual(cache.cached_calls, 1)

    def test_cache_rejects_corrupt_complete_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text("not-json\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                CachingLLM(ScriptedLLM([]), trajectory)

    def test_cache_counts_an_ordered_stateful_session(self) -> None:
        complete = {
            "role": "entry_verifier", "instructions": "open the next function",
            "payload": {"round": 1}, "output_schema": {"type": "object"},
            "session_key": "entry_verifier:candidate-1", "status": "completed",
            "response": {"requested_function_ids": ["fn-2"]},
        }
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(complete) + "\n", encoding="utf-8")
            cache = CachingLLM(ScriptedLLM([]), trajectory)

        self.assertEqual(cache.cached_calls, 1)


class StatefulCacheTest(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_trace_replays_only_completed_sessions_after_crash(self) -> None:
        records = [
            {
                "role": "small_feature", "instructions": "walk",
                "payload": {"entry": entry_id},
                "output_schema": {"type": "object"},
                "session_key": f"small_feature:{entry_id}",
                "status": "completed", "response": {"entry": entry_id},
            }
            for entry_id in ("done", "interrupted")
        ]
        delegate = ScriptedLLM([{"fresh": True}])
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            trajectory = run_root / "trajectories" / "llm.jsonl"
            trajectory.parent.mkdir(parents=True)
            trajectory.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            trace = run_root / "debug" / "agent-events.jsonl"
            trace.parent.mkdir(parents=True)
            trace.write_text(json.dumps({
                "agent": "small_feature", "event": "entry_enumerated",
                "entry_id": "done",
            }) + "\n", encoding="utf-8")
            cache = CachingLLM(delegate, trajectory)
            done = await cache.complete_json(
                role="small_feature", instructions="walk",
                payload={"entry": "done"}, output_schema={"type": "object"},
                session_key="small_feature:done",
            )
            interrupted = await cache.complete_json(
                role="small_feature", instructions="walk",
                payload={"entry": "interrupted"}, output_schema={"type": "object"},
                session_key="small_feature:interrupted",
            )

        self.assertEqual(done, {"entry": "done"})
        self.assertEqual(interrupted, {"fresh": True})
        self.assertEqual(cache.hits, 1)
        self.assertEqual(cache.misses, 1)

    async def test_incomplete_marked_trajectory_session_restarts_live(self) -> None:
        records = [
            {
                "role": "entry_verifier", "instructions": "walk",
                "payload": {"candidate": "closed"},
                "output_schema": {"type": "object"},
                "session_key": "entry_verifier:closed",
                "status": "completed", "response": {"cached": True},
            },
            {
                "record_type": "session_closed",
                "session_key": "entry_verifier:closed",
                "status": "session_closed",
            },
            {
                "role": "entry_verifier", "instructions": "walk",
                "payload": {"candidate": "interrupted"},
                "output_schema": {"type": "object"},
                "session_key": "entry_verifier:interrupted",
                "status": "completed", "response": {"stale_prefix": True},
            },
        ]
        delegate = ScriptedLLM([{"fresh": True}])
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            cache = CachingLLM(delegate, trajectory)
            cached = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={"candidate": "closed"}, output_schema={"type": "object"},
                session_key="entry_verifier:closed",
            )
            fresh = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={"candidate": "interrupted"}, output_schema={"type": "object"},
                session_key="entry_verifier:interrupted",
            )

        self.assertEqual(cached, {"cached": True})
        self.assertEqual(fresh, {"fresh": True})
        self.assertEqual(cache.hits, 1)
        self.assertEqual(cache.misses, 1)

    async def test_stateful_replay_ignores_set_metadata_order(self) -> None:
        record = {
            "role": "entry_verifier", "instructions": "walk",
            "payload": {
                "round": 2,
                "context": [{
                    "function_id": "fn-1",
                    "callers": ["fn-b", "fn-a"],
                    "callees": ["fn-d", "fn-c"],
                    "actions": ["second", "first"],
                }],
            },
            "output_schema": {"type": "object"},
            "session_key": "entry_verifier:candidate-order",
            "status": "completed", "response": {"status": "VERIFIED"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(record) + "\n", encoding="utf-8")
            cache = CachingLLM(ScriptedLLM([]), trajectory)
            response = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={
                    "round": 2,
                    "context": [{
                        "function_id": "fn-1",
                        "callers": ["fn-a", "fn-b"],
                        "callees": ["fn-c", "fn-d"],
                        "actions": ["second", "first"],
                    }],
                },
                output_schema={"type": "object"},
                session_key="entry_verifier:candidate-order",
            )

        self.assertEqual(response, {"status": "VERIFIED"})
        self.assertEqual(cache.hits, 1)

    async def test_replays_an_exact_stateful_sequence_without_a_live_thread(self) -> None:
        records = [
            {
                "role": "entry_verifier", "instructions": "walk",
                "payload": {"round": round_number},
                "output_schema": {"type": "object"},
                "session_key": "entry_verifier:candidate-1",
                "status": "completed", "response": {"round": round_number},
            }
            for round_number in (1, 2)
        ]
        delegate = ScriptedLLM([])
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            cache = CachingLLM(delegate, trajectory)
            first = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={"round": 1}, output_schema={"type": "object"},
                session_key="entry_verifier:candidate-1",
            )
            second = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={"round": 2}, output_schema={"type": "object"},
                session_key="entry_verifier:candidate-1",
            )
            await cache.close_session("entry_verifier:candidate-1")

        self.assertEqual(first, {"round": 1})
        self.assertEqual(second, {"round": 2})
        self.assertEqual(cache.hits, 2)
        self.assertEqual(delegate.calls, [])

    async def test_first_stateful_mismatch_uses_a_fresh_live_session(self) -> None:
        record = {
            "role": "small_feature", "instructions": "old prompt",
            "payload": {"round": 1}, "output_schema": {"type": "object"},
            "session_key": "small_feature:entry-1", "status": "completed",
            "response": {"stale": True},
        }
        delegate = ScriptedLLM([{"fresh": 1}, {"fresh": 2}])
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(record) + "\n", encoding="utf-8")
            cache = CachingLLM(delegate, trajectory)
            first = await cache.complete_json(
                role="small_feature", instructions="new prompt",
                payload={"round": 1}, output_schema={"type": "object"},
                session_key="small_feature:entry-1",
            )
            second = await cache.complete_json(
                role="small_feature", instructions="old prompt",
                payload={"round": 1}, output_schema={"type": "object"},
                session_key="small_feature:entry-1",
            )

        self.assertEqual(first, {"fresh": 1})
        self.assertEqual(second, {"fresh": 2})
        self.assertEqual(cache.hits, 0)
        self.assertEqual(cache.misses, 2)

    async def test_late_stateful_divergence_rehydrates_live_context(self) -> None:
        record = {
            "role": "entry_verifier", "instructions": "walk",
            "payload": {"round": 1}, "output_schema": {"type": "object"},
            "session_key": "entry_verifier:candidate-1", "status": "completed",
            "response": {"round": 1},
        }
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(record) + "\n", encoding="utf-8")
            delegate = ScriptedLLM([
                {"fresh_rehydrated_round": 1},
                {"fresh_current_round": 2},
            ])
            cache = CachingLLM(delegate, trajectory)
            first = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={"round": 1}, output_schema={"type": "object"},
                session_key="entry_verifier:candidate-1",
            )
            second = await cache.complete_json(
                role="entry_verifier", instructions="walk",
                payload={"round": 2}, output_schema={"type": "object"},
                session_key="entry_verifier:candidate-1",
            )

        self.assertEqual(first, {"round": 1})
        self.assertEqual(second, {"fresh_current_round": 2})
        self.assertEqual(
            [call["payload"] for call in delegate.calls],
            [{"round": 1}, {"round": 2}],
        )
        self.assertEqual(cache.rehydrations, 1)
        self.assertEqual(cache.rehydrated_calls, 1)

    async def test_harness_generation_checkpoint_skips_discovery_rehydration(self) -> None:
        discovery_record = {
            "role": "harness_generator", "instructions": "discover",
            "payload": {"round": 1}, "output_schema": {"type": "object"},
            "session_key": "harness_generator:lf-1", "status": "completed",
            "response": {"context_complete": True},
        }
        checkpoint = {
            "sequential_context_discovery": {
                "context_complete": True,
                "generation_blocked": False,
            },
            "functions": [{
                "function_id": "fn-1",
                "source": "int target(const unsigned char *p, unsigned long n);",
            }],
        }
        old_generation_record = {
            "role": "harness_generator", "instructions": "generate-v1",
            "payload": checkpoint, "output_schema": {"type": "object"},
            "session_key": "harness_generator:lf-1", "status": "completed",
            "response": {"code": "old"},
        }
        unrelated_close_marker = {
            "record_type": "session_closed", "session_key": "other:closed",
            "status": "session_closed",
        }
        delegate = ScriptedLLM([{"code": "generated"}])
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(
                "".join(
                    json.dumps(record) + "\n"
                    for record in (
                        discovery_record,
                        old_generation_record,
                        unrelated_close_marker,
                    )
                ),
                encoding="utf-8",
            )
            cache = CachingLLM(delegate, trajectory)
            cached = await cache.complete_json(
                role="harness_generator", instructions="discover",
                payload={"round": 1}, output_schema={"type": "object"},
                session_key="harness_generator:lf-1",
            )
            generated = await cache.complete_json(
                role="harness_generator", instructions="generate-v2",
                payload=checkpoint, output_schema={"type": "object"},
                session_key="harness_generator:lf-1",
            )

        self.assertEqual(cached, {"context_complete": True})
        self.assertEqual(generated, {"code": "generated"})
        self.assertEqual([call["payload"] for call in delegate.calls], [checkpoint])
        self.assertEqual(cache.checkpoint_resumes, 1)
        self.assertEqual(cache.rehydrations, 0)
        self.assertEqual(cache.rehydrated_calls, 0)

    async def test_small_feature_partition_checkpoint_skips_walk_rehydration(self) -> None:
        walk_record = {
            "role": "small_feature", "instructions": "walk",
            "payload": {"round": 1}, "output_schema": {"type": "object"},
            "session_key": "small_feature:entry-1", "status": "completed",
            "response": {"context_complete": False},
        }
        checkpoint = {
            "round": 2,
            "stateful_resume_checkpoint": {
                "complete": True,
                "functions": [{
                    "function_id": "fn-1",
                    "source": "int dispatch(const unsigned char *p, unsigned long n);",
                }],
            },
        }
        closed = {
            "record_type": "session_closed", "session_key": "small_feature:entry-1",
            "status": "session_closed",
        }
        delegate = ScriptedLLM([{"small_features": []}])
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(
                json.dumps(walk_record) + "\n" + json.dumps(closed) + "\n",
                encoding="utf-8",
            )
            cache = CachingLLM(delegate, trajectory)
            cached = await cache.complete_json(
                role="small_feature", instructions="walk",
                payload={"round": 1}, output_schema={"type": "object"},
                session_key="small_feature:entry-1",
            )
            partitioned = await cache.complete_json(
                role="small_feature", instructions="partition",
                payload=checkpoint, output_schema={"type": "object"},
                session_key="small_feature:entry-1",
            )

        self.assertEqual(cached, {"context_complete": False})
        self.assertEqual(partitioned, {"small_features": []})
        self.assertEqual([call["payload"] for call in delegate.calls], [checkpoint])
        self.assertEqual(cache.checkpoint_resumes, 1)
        self.assertEqual(cache.rehydrations, 0)
        self.assertEqual(cache.rehydrated_calls, 0)

    async def test_small_feature_late_divergence_synthesizes_one_checkpoint_turn(self) -> None:
        first_payload = {
            "context_round": 1,
            "context": [{
                "function_id": "fn-entry",
                "name": "recv_request",
                "source": "int recv_request(int fd) { return recv(fd, 0, 0, 0); }",
            }],
            "opened_context_functions": [{"function_id": "fn-entry"}],
        }
        record = {
            "role": "small_feature", "instructions": "walk",
            "payload": first_payload, "output_schema": {"type": "object"},
            "session_key": "small_feature:entry-1", "status": "completed",
            "response": {
                "context_complete": False,
                "small_features": [{
                    "name": "GET request",
                    "root_entries": ["entry-1"],
                    "supporting_entries": [],
                    "harness_anchor": "fn-entry",
                    "actions": [{"function_id": "fn-entry"}],
                    "completion_oracle": "response status",
                    "stable_post_state": "connection reusable",
                }],
            },
        }
        delegate = ScriptedLLM([{"context_complete": True, "small_features": []}])
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(record) + "\n", encoding="utf-8")
            cache = CachingLLM(delegate, trajectory)
            cached = await cache.complete_json(
                role="small_feature", instructions="walk",
                payload=first_payload, output_schema={"type": "object"},
                session_key="small_feature:entry-1",
            )
            resumed = await cache.complete_json(
                role="small_feature", instructions="walk",
                payload={
                    "context_round": 2,
                    "context": [],
                    "opened_context_functions": [{"function_id": "fn-entry"}],
                },
                output_schema={"type": "object"},
                session_key="small_feature:entry-1",
            )

        self.assertFalse(cached["context_complete"])
        self.assertTrue(resumed["context_complete"])
        self.assertEqual(len(delegate.calls), 1)
        checkpoint = delegate.calls[0]["payload"]["stateful_resume_checkpoint"]
        self.assertEqual(checkpoint["resume_mode"], "synthesized_from_exact_cached_prefix")
        self.assertEqual(
            [item["function_id"] for item in checkpoint["functions"]],
            ["fn-entry"],
        )
        self.assertEqual(checkpoint["retained_operations"][0]["name"], "GET request")
        self.assertEqual(cache.checkpoint_resumes, 1)
        self.assertEqual(cache.rehydrations, 0)
        self.assertEqual(cache.rehydrated_calls, 0)


class RecordingMetadataTest(unittest.IsolatedAsyncioTestCase):
    async def test_records_a_completed_session_boundary(self) -> None:
        records = []
        provider = RecordingLLM(ScriptedLLM([]), on_record=records.append)

        await provider.close_session("small_feature:entry-1")

        self.assertEqual(records, [{
            "record_type": "session_closed",
            "session_key": "small_feature:entry-1",
            "status": "session_closed",
            "started_at": records[0]["started_at"],
            "duration_seconds": 0.0,
        }])

    async def test_records_concurrent_cancellation_explicitly(self) -> None:
        class BlockingProvider:
            max_concurrency = 1

            async def complete_json(self, **kwargs):
                await asyncio.Event().wait()

            async def close(self):
                return None

        records = []
        provider = RecordingLLM(BlockingProvider(), on_record=records.append)
        task = asyncio.create_task(provider.complete_json(
            role="entry_verifier",
            instructions="wait",
            payload={},
            output_schema={"type": "object"},
            session_key="entry_verifier:cancelled",
        ))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(records[0]["status"], "cancelled")
        self.assertIn("CancelledError", records[0]["error"])

    async def test_records_selected_model_and_effort(self) -> None:
        class Provider:
            max_concurrency = 1
            effort = "high"

            def model_for_role(self, role):
                return {"entry_generator": "gpt-5.4"}.get(role, "gpt-5.5")

            async def complete_json(self, **kwargs):
                return {"ok": True}

            async def close(self):
                return None

        records = []
        provider = RecordingLLM(Provider(), on_record=records.append)

        await provider.complete_json(
            role="entry_generator",
            instructions="probe",
            payload={},
            output_schema={"type": "object"},
        )

        self.assertEqual(records[0]["model"], "gpt-5.4")
        self.assertEqual(records[0]["reasoning_effort"], "high")


class ModelAwareCacheTest(unittest.TestCase):
    def test_does_not_reuse_a_call_from_a_different_model(self) -> None:
        class Provider:
            max_concurrency = 1
            model = None
            role_models = {"entry_generator": "gpt-5.4"}
            effort = "high"

            def model_for_role(self, role):
                return self.role_models.get(role)

            async def complete_json(self, **kwargs):
                return {"fresh": True}

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(
                json.dumps(
                    {
                        "role": "entry_generator",
                        "instructions": "scan",
                        "payload": {"function": "read_input"},
                        "output_schema": {"type": "object"},
                        "model": "gpt-5.6-luna",
                        "reasoning_effort": "high",
                        "status": "completed",
                        "response": {"stale": True},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            cache = CachingLLM(Provider(), trajectory)

        self.assertEqual(cache.cached_calls, 0)


if __name__ == "__main__":
    unittest.main()
