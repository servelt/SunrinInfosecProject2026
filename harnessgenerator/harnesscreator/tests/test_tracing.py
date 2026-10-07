import json
from pathlib import Path
import tempfile
import unittest

from harnesscreator.storage import ArtifactStore
from harnesscreator.tracing import AgentTraceLogger


class HumanTraceTest(unittest.TestCase):
    def test_human_trace_shows_entry_walk_and_feature_membership_only(self) -> None:
        console: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary))
            trace = AgentTraceLogger(store, console=console.append)
            function = {
                "function_id": "fn-read",
                "name": "read_request",
                "qualified_name": "read_request",
                "file": "server.c",
                "start_line": 10,
                "end_line": 20,
            }
            candidate = {
                "candidate_id": "candidate-1",
                "source_api": "recv",
            }
            trace.emit("entry_verifier", "candidate_started", {
                "candidate": candidate,
                "function": function,
                "message": "verbose message that must not be copied",
            })
            walk = [{
                "function_id": "fn-caller",
                "name": "serve_client",
                "relation": "caller_of",
                "discovered_from": "fn-read",
            }]
            context = [
                function,
                {**function, "function_id": "fn-caller", "name": "serve_client"},
            ]
            for _ in range(2):
                trace.emit("entry_verifier", "context_expanded", {
                    "candidate_id": "candidate-1",
                    "functions": context,
                    "walk": walk,
                })
            trace.emit("entry_verifier", "round_decision", {
                "message": "this detailed decision belongs only in JSONL",
            })
            trace.emit("entry_verifier", "final_verdict", {
                "candidate_id": "candidate-1",
                "entry_id": "entry-1",
                "function": function,
                "final_status": "VERIFIED",
                "record": {"source_api": "recv", "rationale": "peer bytes enter the buffer"},
            })
            trace.emit("small_feature", "feature_created", {
                "feature": {
                    "small_feature_id": "sf-1",
                    "name": "process request",
                    "description": "Receive and process one request.",
                    "root_entries": ["entry-1"],
                    "supporting_entries": [],
                    "planning_complete": True,
                }
            })
            trace.emit("large_feature", "feature_created", {
                "feature": {
                    "large_feature_id": "lf-1",
                    "name": "request processing",
                    "description": "Process compatible request operations.",
                    "small_feature_ids": ["sf-1"],
                }
            })

            human = (store.root / "debug" / "agent-trace.log").read_text(encoding="utf-8")
            records = [
                json.loads(line)
                for line in (store.root / "debug" / "agent-events.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]

        self.assertIn("[ENTRY START] candidate-1 | read_request::recv", human)
        self.assertEqual(human.count("read_request -> serve_client"), 1)
        self.assertIn("[ENTRY DONE] candidate-1 | read_request::recv -> VERIFIED", human)
        self.assertIn("[SMALL MAP] entry-1 (read_request::recv) -> sf-1 (process request)", human)
        self.assertIn("[SMALL DONE] sf-1 (process request) | READY", human)
        self.assertIn("[LARGE MAP] sf-1 (process request) -> lf-1 (request processing)", human)
        self.assertIn("[LARGE DONE] lf-1 (request processing)", human)
        self.assertNotIn("detailed decision", human)
        self.assertEqual(len(records), 7)
        self.assertEqual(len(console), 7)


if __name__ == "__main__":
    unittest.main()
