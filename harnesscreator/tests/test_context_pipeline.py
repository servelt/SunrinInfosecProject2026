"""`run --workflow context`: Entry stage, then contexts -> seeds -> harness in one run."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.cli import build_parser
from harnesscreator.contexts import pipeline
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle, EntryRecord, Evidence, FunctionMetadata, ProjectSpec, Verdict,
)
from harnesscreator.orchestrator import EntryStageCompleted, HarnessCreator
from harnesscreator.storage import ArtifactStore

CONTEXTS = [
    {"context_id": "ctx-client", "resource_kind": "network", "deliveries": ["datagram", "stream"]},
    {"context_id": "ctx-backend", "resource_kind": "network", "deliveries": ["stream"]},
    {"context_id": "ctx-stdin", "resource_kind": "stdin", "deliveries": ["stdin"]},
]


def run_args(root: Path, *extra: str) -> argparse.Namespace:
    return build_parser().parse_args([
        "run", str(root / "source"), "--provider", "claude", "--coverage-root", str(root / "cov"),
        "--coverage-command", f"{root / 'cov' / 'server'} -p 11311", "--port", "11311", *extra])


class SelectUnitsTests(unittest.TestCase):
    def test_default_takes_every_context_of_each_channel(self):
        # Both network contexts deliver a stream and each is a separate input path, so each
        # one gets its own harness.  LightFTP showed what "the first context wins" cost: the
        # STOR/APPE data-connection readers were dropped and no harness ever fuzzed them.
        units = pipeline.select_units(CONTEXTS, [])
        self.assertEqual([(ctx["context_id"], channel) for ctx, channel in units],
                         [("ctx-client", "tcp"), ("ctx-backend", "tcp"), ("ctx-client", "udp")])

    def test_explicit_channel_takes_every_context_with_that_delivery(self):
        units = pipeline.select_units(CONTEXTS, ["stdin", "udp"])
        self.assertEqual([(ctx["context_id"], channel) for ctx, channel in units],
                         [("ctx-client", "udp"), ("ctx-stdin", "stdin")])

    def test_per_channel_cap_keeps_the_highest_priority_contexts(self):
        units = pipeline.select_units(CONTEXTS, ["tcp"], per_channel=1)
        self.assertEqual([(ctx["context_id"], channel) for ctx, channel in units],
                         [("ctx-client", "tcp")])

    def test_no_network_context_selects_nothing(self):
        self.assertEqual(pipeline.select_units(CONTEXTS[2:], []), [])


class ValidateTests(unittest.TestCase):
    def test_default_workflow_is_context_and_names_what_is_missing(self):
        args = build_parser().parse_args(["run", "/tmp/project"])
        self.assertEqual(args.workflow, "context")
        with self.assertRaisesRegex(ValueError, "--coverage-root and --coverage-command"):
            pipeline.validate(args)

    def test_network_channel_needs_a_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cov").mkdir()
            (root / "cov" / "server.gcno").write_bytes(b"")
            (root / "cov" / "server").write_text("")
            args = build_parser().parse_args([
                "run", str(root), "--coverage-root", str(root / "cov"),
                "--coverage-command", str(root / "cov" / "server")])
            with self.assertRaisesRegex(ValueError, "needs --port"):
                pipeline.validate(args)
            args.scenario_port = 11311
            pipeline.validate(args)


class PipelineOrderTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, root: Path, seeds_per_channel: dict[str, int], harness_exit: int = 0):
        run_dir = root / "run"
        (run_dir / "contexts").mkdir(parents=True)
        calls: list[tuple[str, argparse.Namespace]] = []

        async def contexts(ns):
            calls.append(("contexts", ns))
            (run_dir / "contexts" / "contexts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in CONTEXTS), encoding="utf-8")
            return 0

        async def seeds(ns):
            calls.append(("seeds", ns))
            delivery = pipeline._CHANNEL_DELIVERY[ns.channel]
            (run_dir / "seeds").mkdir(exist_ok=True)
            (run_dir / "seeds" / f"summary-{ns.context[0]}-{delivery}.json").write_text(
                json.dumps({"corpus_seeds": seeds_per_channel[ns.channel]}), encoding="utf-8")
            return 0

        async def harness(ns):
            calls.append(("harness", ns))
            return harness_exit

        with patch.object(pipeline.stages, "_contexts", contexts), \
                patch.object(pipeline.stages, "_seeds", seeds), \
                patch.object(pipeline.stages, "_harness", harness), \
                patch("builtins.print"):
            code = await pipeline.run_after_entries(run_args(root), run_dir, {"verified_entries": 2})
        return code, calls, json.loads((run_dir / "context-workflow" / "summary.json").read_text())

    async def test_every_context_of_a_channel_gets_seeds_before_its_harness(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, calls, summary = await self._run(Path(temporary), {"tcp": 5, "udp": 3})
        self.assertEqual(code, 0)
        # Both tcp contexts run, each with its own seeds stage, then the udp one.
        self.assertEqual([name for name, _ in calls],
                         ["contexts", "seeds", "harness", "seeds", "harness", "seeds", "harness"])
        located = calls[0][1]
        self.assertTrue(located.locate)
        self.assertEqual(located.locate_resource, ["network"])
        seeds = [ns for name, ns in calls if name == "seeds"]
        harnesses = [ns for name, ns in calls if name == "harness"]
        self.assertEqual([(ns.channel, ns.context) for ns in seeds],
                         [("tcp", ["ctx-client"]), ("tcp", ["ctx-backend"]), ("udp", ["ctx-client"])])
        self.assertEqual([ns.delivery for ns in harnesses], ["stream", "stream", "datagram"])
        self.assertEqual(seeds[0].port, 11311)
        self.assertEqual(seeds[0].generator_turns, 0)
        self.assertEqual(seeds[0].max_frontier_targets, 0)
        self.assertEqual(seeds[0].provider, "claude")
        self.assertEqual([row["channel"] for row in summary["channels"]], ["tcp", "tcp", "udp"])
        self.assertEqual([row["context_id"] for row in summary["contexts"]["not_run"]], ["ctx-stdin"])

    async def test_channel_without_verified_input_gets_no_harness(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, calls, summary = await self._run(Path(temporary), {"tcp": 5, "udp": 0})
        self.assertEqual(code, 3)
        # The udp unit comes last and produced no verified input, so it stops before a harness.
        self.assertEqual([name for name, _ in calls],
                         ["contexts", "seeds", "harness", "seeds", "harness", "seeds"])
        self.assertIn("skipped", summary["channels"][2]["harness"]["error"])

    async def test_failed_harness_is_reported_in_the_exit_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, _, summary = await self._run(Path(temporary), {"tcp": 5, "udp": 3}, harness_exit=1)
        self.assertEqual(code, 3)
        self.assertEqual(summary["channels"][0]["harness"]["exit"], 1)


class OrchestratorStopTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_ends_at_the_entry_files_without_entering_action_stages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            text = "int receive(void) { char b[8]; return read(0, b, sizeof(b)); }\n"
            (source / "input.c").write_text(text, encoding="utf-8")
            function = FunctionMetadata.create(
                name="receive", signature="int receive(void)", file="input.c",
                start_line=1, end_line=1, source=text)
            entry = EntryRecord(
                entry_id="saved-entry", candidate_id="saved-candidate", status=Verdict.VERIFIED,
                entry_function_id=function.function_id, source_api="read", channel_kind="stdin",
                attacker_control="full", provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", function.function_id, "input.c", 1, "reads caller input")],
                unknowns=[], verifier_confidence=1.0, entry_line=1, first_acquisition_confirmed=True)
            saved = ArtifactStore(root / "previous")
            saved.write_jsonl("analysis/product-functions.jsonl", [function])
            saved.write_jsonl("entries/candidates.jsonl", [{"candidate_id": "saved-candidate"}])
            saved.write_jsonl("entries/verified.jsonl", [entry])
            saved.write_jsonl("entries/unresolved.jsonl", [])
            project = ProjectSpec(
                source_root=source, output_root=root / "runs", name="fixture",
                require_fuzz_introspector=False, svf_enabled=False, scenario_channel="disabled",
                entry_artifacts_from=saved.root)

            async def forbidden(_self, **_kwargs):
                raise AssertionError("Action stages must not start")

            with patch.object(HarnessCreator, "_run_scenario_pipeline", forbidden):
                with self.assertRaises(EntryStageCompleted) as raised:
                    await HarnessCreator(
                        project, ScriptedLLM([]), stop_after_entries=True,
                        precomputed_analysis=AnalysisBundle(functions={function.function_id: function}, edges=[]),
                    ).run()
            done = raised.exception
            self.assertEqual(done.as_dict()["verified_entries"], 1)
            self.assertEqual(done.as_dict()["status"], "ENTRY_STAGE_COMPLETED")
            # Everything the contexts stage reads is on disk.
            for name in ("project.json", "analysis/functions.jsonl", "analysis/edges.jsonl", "entries/verified.jsonl"):
                self.assertTrue((done.run_dir / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
