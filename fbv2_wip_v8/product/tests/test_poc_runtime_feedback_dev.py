"""Development PoV feedback accepts only completed, bounded runtime facts."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.analysis import generate_input
from vulnerabilityanalysis.models import SuspiciousPoint, stable_id
from vulnerabilityanalysis.scan import execute_poc

from test_fuzzer_crash_consumer import SOURCE


PRIOR_SCRIPT = "def build():\n    return b'A'\n"


class _Provider:
    def __init__(self):
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        return {"generator_script": "def build():\n    return b'A'\n",
                "expected_behavior": "complete without a crash",
                "trigger_rationale": "development feedback control"}


def _point() -> SuspiciousPoint:
    return SuspiciousPoint("sp-1", "worker", "direction", "parse", "target.c",
                           "target.c:2", "data[0]", "possible invalid read",
                           ["input reaches parser"], "input bytes", [], [], [], [])


def _feedback() -> dict:
    return {"prior_poc_id": stable_id("poc", "sp-1", PRIOR_SCRIPT),
            "prior_poc_script_sha256": hashlib.sha256(PRIOR_SCRIPT.encode()).hexdigest(),
            "prior_input_sha256": "b" * 64,
            "prior_runtime_sha256": "c" * 64,
            "exit_code": 0, "timed_out": False, "sanitizer": "NONE",
            "crash_triage": "NONE", "failure_classification": "TARGET_NOT_REACHED",
            "reachability": {"function_reached": None,
                             "sp_location_reached": None,
                             "sp_condition_reached": None}}


class PoCRuntimeFeedbackDevTest(unittest.TestCase):
    def test_real_c_runtime_result_drives_a_second_pov_input(self):
        """A scripted model chooses inputs; the C binary and Gate really run."""
        compiler = shutil.which("gcc-13") or shutil.which("gcc")
        if not compiler:
            self.skipTest("GCC unavailable")

        class _RevisionProvider:
            def __init__(self):
                self.requests = []

            async def generate(self, request):
                self.requests.append(request)
                marker = "Y" if len(self.requests) == 1 else "X"
                return {"generator_script": f"def build():\n    return b'{marker}'\n",
                        "expected_behavior": "bounded development control",
                        "trigger_rationale": "revise after a completed non-crash"}

        with TemporaryDirectory() as temp:
            root = Path(temp)
            checkout, run = root / "checkout", root / "run"
            checkout.mkdir()
            run.mkdir()
            source, harness, binary = (checkout / "target.c",
                                       checkout / "harness.c", root / "asan-target")
            source.write_text(SOURCE)
            harness.write_text("/* Synthetic development Harness. */\n")
            build = subprocess.run(
                [compiler, "-g", "-O0", "-fno-omit-frame-pointer",
                 "-fsanitize=address", "-static-libasan", str(source),
                 "-o", str(binary)], capture_output=True, text=True)
            if build.returncode:
                self.skipTest("static ASan build unavailable: " + build.stderr[:160])
            point = SuspiciousPoint("sp-revision", "worker", "direction",
                                    "target_operation", "target.c", "target.c:9",
                                    "buffer[0]", "possible use after free",
                                    ["input reaches target_operation"], "input byte",
                                    [], [], [], [])
            provider = _RevisionProvider()
            pipeline = AgentPipeline(provider)
            command = [str(binary), "{input}"]
            first = asyncio.run(pipeline.generate_poc(point, SOURCE, harness.read_text()))
            first_dir = run / "poc" / first.poc_id
            first_input = first_dir / "input.bin"
            generate_input(first.generator_script, first_dir / "generate.py", first_input)
            first.generated_input = str(first_input)
            execute_poc(first, point, command, run, target_repository=checkout,
                        harness_path=harness, target_binary=binary)
            runtime_path = run / "runtime" / f"{first.poc_id}.json"
            runtime = json.loads(runtime_path.read_text())
            self.assertEqual(runtime["exit_code"], 0)
            self.assertIsNone(runtime["sanitizer"])
            feedback = {
                "prior_poc_id": first.poc_id,
                "prior_poc_script_sha256": hashlib.sha256(
                    first.generator_script.encode()).hexdigest(),
                "prior_input_sha256": hashlib.sha256(first_input.read_bytes()).hexdigest(),
                "prior_runtime_sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
                "exit_code": runtime["exit_code"], "timed_out": runtime["timed_out"],
                "sanitizer": "NONE", "crash_triage": "NONE",
                "failure_classification": runtime["failure_classification"],
                "reachability": {name: runtime[name] for name in
                    ("function_reached", "sp_location_reached", "sp_condition_reached")},
            }
            second = asyncio.run(pipeline.generate_poc(
                point, SOURCE, harness.read_text(), runtime_feedback=feedback,
                prior_generator_script=first.generator_script))
            self.assertNotEqual(first.poc_id, second.poc_id)
            self.assertEqual(provider.requests[1].payload["runtime_feedback"], feedback)
            second_dir = run / "poc" / second.poc_id
            second_input = second_dir / "input.bin"
            generate_input(second.generator_script, second_dir / "generate.py", second_input)
            self.assertNotEqual(first_input.read_bytes(), second_input.read_bytes())
            second.generated_input = str(second_input)
            execute_poc(second, point, command, run, target_repository=checkout,
                        harness_path=harness, target_binary=binary)
            second_runtime = json.loads((run / "runtime" /
                                        f"{second.poc_id}.json").read_text())
            self.assertIsNotNone(second_runtime["sanitizer"])
            self.assertNotEqual(second_runtime["exit_code"], 0)

    def test_first_pov_payload_is_byte_contract_compatible(self):
        provider = _Provider()
        poc = asyncio.run(AgentPipeline(provider).generate_poc(
            _point(), "int parse(void) { return 0; }", "int LLVMFuzzerTestOneInput(void) {}"))
        self.assertEqual(poc.sp_id, "sp-1")
        self.assertEqual(set(provider.requests[0].payload),
                         {"suspicious_point", "source", "harness_source"})

    def test_second_pov_receives_only_structured_noncrash_feedback(self):
        provider = _Provider()
        feedback = _feedback()
        asyncio.run(AgentPipeline(provider).generate_poc(
            _point(), "int parse(void) { return 0; }",
            "int LLVMFuzzerTestOneInput(void) {}", runtime_feedback=feedback,
            prior_generator_script=PRIOR_SCRIPT))
        payload = provider.requests[0].payload
        self.assertEqual(set(payload), {"suspicious_point", "source",
                                        "harness_source", "runtime_feedback",
                                        "prior_generator_script"})
        self.assertEqual(payload["runtime_feedback"], feedback)
        self.assertEqual(payload["prior_generator_script"], PRIOR_SCRIPT)
        feedback["reachability"]["function_reached"] = False
        self.assertIsNone(payload["runtime_feedback"]["reachability"]["function_reached"])

    def test_unknown_raw_output_paths_and_oversized_identity_are_rejected(self):
        invalid = []
        for key, value in (("stderr", "attacker-controlled output"),
                           ("runtime_path", "/tmp/target.log"),
                           ("model_note", "arbitrary narrative")):
            row = _feedback()
            row[key] = value
            invalid.append(row)
        row = _feedback()
        row["prior_poc_id"] = "poc-" + "1" * 4096
        invalid.append(row)
        row = _feedback()
        row["prior_input_sha256"] = "not-a-digest"
        invalid.append(row)
        row = _feedback()
        row["failure_classification"] = "RAW_TARGET_OUTPUT"
        invalid.append(row)
        for row in invalid:
            with self.subTest(row=row):
                provider = _Provider()
                with self.assertRaises(ValueError):
                    asyncio.run(AgentPipeline(provider).generate_poc(
                        _point(), "source", "harness", runtime_feedback=row,
                        prior_generator_script=PRIOR_SCRIPT))
                self.assertEqual(provider.requests, [])

    def test_incomplete_crash_and_contradictory_reachability_are_rejected(self):
        variants = []
        for key, value in (("timed_out", True), ("exit_code", 1),
                           ("exit_code", False), ("sanitizer", "ADDRESS_SANITIZER"),
                           ("crash_triage", "TARGET_CRASH")):
            row = _feedback()
            row[key] = value
            variants.append(row)
        row = _feedback()
        row["reachability"]["function_reached"] = False
        row["reachability"]["sp_location_reached"] = True
        variants.append(row)
        row = _feedback()
        row["reachability"]["sp_location_reached"] = "YES"
        variants.append(row)
        for row in variants:
            with self.subTest(row=row):
                provider = _Provider()
                with self.assertRaises(ValueError):
                    asyncio.run(AgentPipeline(provider).generate_poc(
                        _point(), "source", "harness", runtime_feedback=deepcopy(row),
                        prior_generator_script=PRIOR_SCRIPT))
                self.assertEqual(provider.requests, [])

    def test_prior_script_hash_identity_ast_and_size_are_bound(self):
        variants = []
        row = _feedback()
        row["prior_poc_id"] = "poc-" + "1" * 16
        variants.append((row, PRIOR_SCRIPT))
        row = _feedback()
        row["prior_poc_script_sha256"] = "a" * 64
        variants.append((row, PRIOR_SCRIPT))
        disallowed = "import os\ndef build():\n    return b'A'\n"
        row = _feedback()
        row["prior_poc_script_sha256"] = hashlib.sha256(disallowed.encode()).hexdigest()
        row["prior_poc_id"] = stable_id("poc", "sp-1", disallowed)
        variants.append((row, disallowed))
        huge = "def build():\n    return b'" + "A" * 8192 + "'\n"
        row = _feedback()
        row["prior_poc_script_sha256"] = hashlib.sha256(huge.encode()).hexdigest()
        row["prior_poc_id"] = stable_id("poc", "sp-1", huge)
        variants.append((row, huge))
        variants.append((_feedback(), None))
        for feedback, script in variants:
            with self.subTest(script_length=len(script or "")):
                provider = _Provider()
                with self.assertRaises(ValueError):
                    asyncio.run(AgentPipeline(provider).generate_poc(
                        _point(), "source", "harness", runtime_feedback=feedback,
                        prior_generator_script=script))
                self.assertEqual(provider.requests, [])
        provider = _Provider()
        with self.assertRaises(ValueError):
            asyncio.run(AgentPipeline(provider).generate_poc(
                _point(), "source", "harness", prior_generator_script=PRIOR_SCRIPT))
        self.assertEqual(provider.requests, [])


if __name__ == "__main__":
    unittest.main()
