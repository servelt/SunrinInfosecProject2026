"""Paired-scan controls: disabling HP, initial inputs, and wall budget."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis import __main__ as cli
from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.llm import AppServerError
from vulnerabilityanalysis.models import FunctionAnalysis
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import prepare_function_retry, run_phase1


def fixture(root: Path) -> tuple[Path, Path]:
    source = root / "source"
    source.mkdir()
    (source / "target.c").write_text("int parse(void) { return 0; }\n")
    artifact = root / "harness"
    artifact.mkdir()
    (artifact / "fuzz.c").write_text("int LLVMFuzzerTestOneInput(void) { return parse(); }\n")
    (artifact / "manifest.json").write_text(json.dumps({
        "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"]}))
    (artifact / "validation.json").write_text('{"build_ok": true}')
    (root / "project.json").write_text(json.dumps({"source_root": str(source)}))
    (root / "analysis").mkdir()
    (root / "analysis/functions.jsonl").write_text(json.dumps({
        "function_id": "f", "name": "parse", "file": "target.c"}) + "\n")
    return artifact, source


class EvaluationInfrastructureTest(unittest.TestCase):
    def test_cli_provider_failure_records_retryable_incomplete_function(self):
        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        async def failed_scan(*_args, **_kwargs):
            raise AppServerError("workspace routing discovery failed")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, source = fixture(root)
            run = run_phase1(artifact, root / "results", target_repository=source)
            argv = ["vulnerabilityanalysis", "scan", str(run), "--target-repository",
                    str(source), "--max-functions", "1", "--hallucination-prevent", "off"]
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                return_value=(Client(), {})), patch.object(cli, "scan_selected", failed_scan):
                with self.assertRaises(AppServerError):
                    cli.main()
            error = json.loads((run / "scan_error.json").read_text())
            self.assertEqual(error["type"], "AppServerError")
            self.assertEqual(error["stage"], "SCAN_INCOMPLETE")
            self.assertFalse((run / "scan.json").exists())
            retry = prepare_function_retry(run, root / "results" / "retry")
            self.assertEqual(json.loads((retry / "selection.json").read_text())["function_id"],
                             json.loads((run / "selection.json").read_text())["function_id"])

    def test_off_skips_assertion_generator_and_both_modes_receive_initial_seed(self):
        class Pipeline:
            generated_assertions = 0

            def __init__(self, *_args, **_kwargs):
                self.verifications = {}

            async def analyze_function(self, function_id, name, source_file, *_args, **_kwargs):
                return FunctionAnalysis(function_id, name, source_file, "safe claim", "input",
                                        [], [], ["safe claim"], [])

            async def generate_sp(self, *_args, **_kwargs):
                return []

            async def generate_assertions(self, *_args, **_kwargs):
                Pipeline.generated_assertions += 1
                return []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, source = fixture(root)
            seed = root / "seed"
            seed.write_bytes(b"abc")
            with patch("vulnerabilityanalysis.scan.AgentPipeline", Pipeline):
                results = []
                for mode in ("off", "on"):
                    run = run_phase1(artifact, root / "results", target_repository=source)
                    asyncio.run(scan_selected(run, object(), target_repository=source,
                        run_command=["/usr/bin/true", "{input}"], initial_inputs=[seed],
                        hallucination_prevent=mode))
                    results.append(json.loads((run / "scan.json").read_text()))
                    inputs = json.loads((run / "corpus/initial_inputs.json").read_text())
                    self.assertEqual(len(inputs), 1)
                    self.assertEqual(inputs[0]["exit_code"], 0)
                    self.assertEqual(Path(inputs[0]["stored"]).read_bytes(), b"abc")
                    timing = json.loads((run / "timing.json").read_text())
                    self.assertGreaterEqual(timing["initial_corpus_runtime_seconds"], 0)
                    self.assertTrue({"FUNCTION_ANALYSIS", "VERIFY", "POV", "RUNTIME",
                                     "GLOBAL_FUZZ", "SP_FUZZ", "ASSERTION_BUILD",
                                     "ASSERTION_FUZZ"}.issubset(timing["stage_seconds"]))
                    self.assertTrue((run / "logs/stage_windows.jsonl").is_file())
                self.assertEqual(Pipeline.generated_assertions, 1)
                self.assertEqual(results[0]["assertion_execution"]["status"], "DISABLED")
                self.assertEqual(results[1]["assertion_execution"]["status"],
                                 "NOT_SCHEDULED_NO_VALID_ASSERTION")

    def test_cli_wall_limit_records_timeout(self):
        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        async def slow_scan(*_args, **_kwargs):
            await asyncio.sleep(1)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, source = fixture(root)
            run = run_phase1(artifact, root / "results", target_repository=source)
            argv = ["vulnerabilityanalysis", "scan", str(run), "--target-repository",
                    str(source), "--max-functions", "1", "--max-scan-seconds", "0.02",
                    "--hallucination-prevent", "off"]
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                return_value=(Client(), {})), patch.object(cli, "scan_selected", slow_scan):
                with self.assertRaises(TimeoutError):
                    cli.main()
            summary = json.loads((run / "function_scan.json").read_text())
            self.assertEqual(summary["error"], "SCAN_WALL_TIME_EXCEEDED")
            self.assertEqual(json.loads((run / "scan_timeout.json").read_text())
                             ["status"], "SCAN_WALL_TIME_EXCEEDED")
            self.assertEqual(json.loads((run / "experiment_setup.json").read_text())
                             ["hallucination_prevent"], "off")
            self.assertEqual(json.loads((run / "experiment_setup.json").read_text())
                             ["baseline_kind"], "FBV2_SP_INDEPENDENT_HP_OFF")

    def test_cancelled_llm_request_has_separate_cost_record(self):
        class SlowProvider:
            async def generate(self, _request):
                await asyncio.sleep(1)

        with tempfile.TemporaryDirectory() as tmp:
            async def run_request():
                pipeline = AgentPipeline(SlowProvider(), schema_error_dir=Path(tmp))
                await asyncio.wait_for(pipeline._ask("function_analysis", {}, {
                    "type": "object", "properties": {}, "additionalProperties": False}),
                    timeout=0.02)

            with self.assertRaises(TimeoutError):
                asyncio.run(run_request())
            row = json.loads((Path(tmp) / "agent_requests.jsonl").read_text())
            self.assertEqual(row["status"], "CANCELLED")
            self.assertIsNone(row["cost"])

    def test_on_requires_runnable_assertion_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, source = fixture(root)
            run = run_phase1(artifact, root / "results", target_repository=source)
            argv = ["vulnerabilityanalysis", "scan", str(run), "--target-repository",
                    str(source), "--hallucination-prevent", "on"]
            with patch("sys.argv", argv):
                with self.assertRaisesRegex(ValueError, "HP on requires"):
                    cli.main()

    def test_cli_on_passes_same_initial_inputs_into_real_scan_boundary(self):
        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class Captured(Exception):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, source = fixture(root)
            seed = root / "seed"
            seed.write_bytes(b"abc")
            run = run_phase1(artifact, root / "results", target_repository=source)

            async def capture(_run_dir, _client, **kwargs):
                self.assertEqual(kwargs["hallucination_prevent"], "on")
                self.assertEqual(kwargs["initial_inputs"], [seed])
                self.assertEqual(kwargs["assertion_fuzz_seconds"], 1)
                self.assertEqual(kwargs["max_candidates"], 1)
                self.assertEqual(kwargs["run_command"], ["/tmp/eval-binary", "{input}"])
                raise Captured

            argv = ["vulnerabilityanalysis", "scan", str(run), "--target-repository",
                    str(source), "--binary", "/tmp/eval-binary", "--max-functions", "1",
                    "--max-scan-seconds", "9", "--hallucination-prevent", "on",
                    "--max-candidates", "1",
                    "--initial-seed", str(seed), "--assertion-fuzz-seconds", "1",
                    "--assertion-build-command", '["cc", "{source}", "-o", "{binary}"]',
                    "--assertion-run-command", '["{binary}", "{input}"]']
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                return_value=(Client(), {})), patch.object(cli, "scan_selected", capture):
                with self.assertRaises(Captured):
                    cli.main()
            setup = json.loads((run / "experiment_setup.json").read_text())
            self.assertEqual(setup["initial_inputs"][0]["sha256"],
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            self.assertEqual(setup["max_candidates"], 1)
            self.assertEqual(setup["baseline_kind"], "FBV2_PLUS_HP_ENABLED")
