"""A Reference contract is verified and frozen before a normal Scan."""
import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.workflow import prepare_reference_qualification, run_phase1
from vulnerabilityanalysis.scan import scan_selected


def sha(path: Path, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, path.read_bytes()).hexdigest()


class ReferenceQualificationScanStartTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        (self.repo / "target.c").write_text("int target(void) { return 0; }\n")
        self.archive = self.root / "source.tar.gz"
        self.archive.write_bytes(b"frozen source archive")
        self.binary = self.root / "target"
        self.binary.write_bytes(b"asan binary")
        self.runner = self.root / "runner.py"
        self.runner.write_text("# reviewed runner\n")
        self.normal = self.root / "normal.http"
        self.normal.write_bytes(b"GET / HTTP/1.1\r\n\r\n")
        self.malformed = self.root / "malformed.http"
        self.malformed.write_bytes(b"bad request\r\n")
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        harness_source = self.root / "harness.py"
        harness_source.write_text("# fixture metadata source\n")
        (self.root / "project.json").write_text(json.dumps({
            "source_root": str(self.repo),
        }))
        (self.root / "analysis").mkdir()
        (self.root / "analysis/functions.jsonl").write_text(json.dumps({
            "function_id": "fn-target", "name": "target",
            "file": "target.c", "start_line": 1,
        }) + "\n")
        (self.artifact / "manifest.json").write_text(json.dumps({
            "harness_id": "reference-test", "artifact_kind": "REGRESSION_FIXTURE",
            "project_harness": False, "source_file": str(harness_source),
            "expected_anchors": ["fn-target"], "sanitizers": ["ASAN"],
        }))
        (self.artifact / "validation.json").write_text(json.dumps({
            "build_ok": True, "qualified": False,
        }))
        self.run = run_phase1(self.artifact, self.root / "runs",
                              target_repository=self.repo)
        self.contract_path = self.root / "reference_contract.json"
        self.contract = {
            "kind": "REFERENCE_HTTP_CONTRACT_V1", "harness_id": "reference-test",
            "source_file": "target.c", "source_sha256": sha(self.repo / "target.c"),
            "source_archive": str(self.archive),
            "source_archive_sha512": sha(self.archive, "sha512"),
            "binary": str(self.binary), "binary_sha256": sha(self.binary),
            "runner": str(self.runner), "runner_sha256": sha(self.runner),
            "normal_input": str(self.normal), "normal_input_sha256": sha(self.normal),
            "malformed_input": str(self.malformed),
            "malformed_input_sha256": sha(self.malformed),
            "artifact_manifest_sha256": sha(self.artifact / "manifest.json"),
            "harness_source_sha256": sha(harness_source),
        }
        self.contract_path.write_text(json.dumps(self.contract))

    def prepare(self):
        return prepare_reference_qualification(
            self.run, self.contract_path, target_repository=self.repo,
            binary=self.binary, runner=self.runner)

    def test_unqualified_artifact_needs_explicit_contract_and_runtime_checks(self):
        run = json.loads((self.run / "run.json").read_text())
        self.assertNotIn("harness_qualification_request_sha256", run)
        request_path = self.prepare()
        request = json.loads(request_path.read_text())
        run = json.loads((self.run / "run.json").read_text())
        self.assertEqual(run["harness_qualification_request_sha256"], sha(request_path))
        self.assertEqual(request["provisioned_by"], "SCAN_START")
        self.assertEqual(request["harness_id"], "reference-test")
        self.assertFalse(json.loads((self.artifact / "validation.json").read_text())["qualified"])
        self.assertEqual(self.prepare(), request_path)

    def test_wrong_hashes_or_missing_inputs_fail_before_request_is_written(self):
        for field in ("source_sha256", "binary_sha256", "runner_sha256",
                      "normal_input_sha256", "malformed_input_sha256",
                      "artifact_manifest_sha256", "harness_source_sha256"):
            with self.subTest(field=field):
                wrong = {**self.contract, field: "0" * 64}
                self.contract_path.write_text(json.dumps(wrong))
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    self.prepare()
                self.assertFalse((self.run / "harness_qualification_request.json").exists())
        self.contract_path.write_text(json.dumps(self.contract))
        self.normal.unlink()
        with self.assertRaisesRegex(ValueError, "paths do not match"):
            self.prepare()
        self.assertFalse((self.run / "harness_qualification_request.json").exists())

    def test_artifact_cannot_self_supply_contract(self):
        inside = self.artifact / "reference_contract.json"
        inside.write_text(json.dumps(self.contract))
        with self.assertRaisesRegex(ValueError, "outside the Harness artifact"):
            prepare_reference_qualification(
                self.run, inside, target_repository=self.repo,
                binary=self.binary, runner=self.runner)
        self.assertFalse((self.run / "harness_qualification_request.json").exists())

    def test_general_scan_cli_passes_process_command_and_pins_request(self):
        from vulnerabilityanalysis import __main__ as cli

        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class Captured(Exception):
            pass

        async def capture(run_dir, _client, **kwargs):
            self.assertEqual(run_dir, self.run)
            self.assertEqual(kwargs["run_command"][1:], [
                str(self.runner), str(self.binary), "{input}"])
            self.assertEqual(kwargs["target_binary"], self.binary)
            request = json.loads((self.run / "harness_qualification_request.json").read_text())
            self.assertEqual(request["provisioned_by"], "SCAN_START")
            raise Captured

        argv = ["vulnerabilityanalysis", "scan", str(self.run),
                "--target-repository", str(self.repo), "--binary", str(self.binary),
                "--process-runner", str(self.runner),
                "--reference-qualification", str(self.contract_path),
                "--max-functions", "1"]
        with patch("sys.argv", argv), patch.object(cli, "configured_client",
                return_value=(Client(), {})), patch.object(cli, "scan_selected", capture):
            with self.assertRaises(Captured):
                cli.main()

    def test_scan_selected_routes_pov_to_the_same_qualification_contract(self):
        source = self.repo / "target.c"
        source.write_text("int target(const char *data, int size) {\n"
                          "  if (size > 0) return data[0];\n"
                          "  return 0;\n}\n")
        self.contract["source_sha256"] = sha(source)
        self.contract_path.write_text(json.dumps(self.contract))
        self.prepare()

        class Provider:
            def __init__(self, responses):
                self.responses = list(responses)

            async def generate(self, _request):
                return self.responses.pop(0)

        verdict = {"status": "PLAUSIBLE", "supporting_evidence": [],
                   "contradicting_evidence": [], "unknowns": ["caller bounds"],
                   "rationale": "runtime check", "reachability": "UNKNOWN",
                   "controllability": "UNKNOWN", "guards": [], "required_state": [],
                   "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                   "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        provider = Provider([
            {"suspicious_points": [{
                "source_file": "target.c", "source_line": 2,
                "source_excerpt": "if (size > 0) return data[0];",
                "sp_condition": "", "suspicious_operation": "data[0]",
                "vulnerability_hypothesis": "index may be outside the object",
                "trigger_conditions": ["bad input"],
                "external_input_relation": "input controls data",
                "required_state": [], "security_property": "memory safety",
                "supporting_evidence": ["indexed read"],
                "contradicting_evidence": [], "unknowns": ["caller bounds"],
            }]},
            verdict,
            {"generator_script": "def build():\n    return b'A'\n",
             "expected_behavior": "probe", "trigger_rationale": "input"},
        ])
        command = ["/usr/bin/python3", str(self.runner), str(self.binary), "{input}"]
        with patch("vulnerabilityanalysis.scan.execute_poc", return_value=[]) as execute:
            asyncio.run(scan_selected(self.run, provider, target_repository=self.repo,
                                      run_command=command, target_binary=self.binary,
                                      max_candidates=1, hallucination_prevent="off"))
        self.assertEqual(execute.call_count, 1)
        args, kwargs = execute.call_args
        self.assertEqual(args[2], command)
        self.assertEqual(args[3], self.run)
        self.assertEqual(kwargs["target_binary"], self.binary)
        self.assertTrue(kwargs["auto_input_receipt"])
        self.assertTrue((self.run / "harness_qualification_request.json").is_file())


if __name__ == "__main__":
    unittest.main()
