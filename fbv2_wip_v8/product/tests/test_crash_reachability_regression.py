import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.models import PoC, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.scan import execute_poc


class CrashReachabilityRegression(unittest.TestCase):
    def test_incomplete_replay_keeps_environment_error_after_direct_reachability(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            sample = run_dir / "input.bin"
            sample.write_bytes(b"input")
            point = SuspiciousPoint("sp-1", "w", "d", "target", "target.c", "target.c:9",
                                    "write", "hypothesis", [], "input", [], [], [], [])
            poc = PoC("poc-1", "sp-1", "", str(sample), None, "observation")
            incomplete = RuntimeResult(None, "", "ERROR: AddressSanitizer: heap-use-after-free",
                                       None, False, "heap-use-after-free", "#0 in target",
                                       "ENVIRONMENT_ERROR")
            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run", return_value=incomplete), \
                 patch("vulnerabilityanalysis.scan.trace_function_reached",
                       return_value=(True, "function hit")), \
                 patch("vulnerabilityanalysis.scan.triage_crash",
                       return_value={"category": "ENVIRONMENT_ERROR", "sp_linked": False}):
                execute_poc(poc, point, ["/usr/bin/cat", "{input}"], run_dir,
                            trace_reachability=True)
            result = json.loads((run_dir / "runtime/poc-1.json").read_text())
            self.assertEqual(result["failure_classification"], "ENVIRONMENT_ERROR")
            self.assertEqual(result["sanitizer"], "heap-use-after-free")

    def test_incomplete_replay_keeps_environment_error_after_process_trace(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            sample = run_dir / "input.bin"
            sample.write_bytes(b"input")
            binary = run_dir / "target-bin"
            binary.write_bytes(b"synthetic")
            point = SuspiciousPoint("sp-1", "w", "d", "target", "target.c", "target.c:9",
                                    "write", "hypothesis", [], "input", [], [], [], [])
            poc = PoC("poc-1", "sp-1", "", str(sample), None, "observation")
            incomplete = RuntimeResult(None, "", "ERROR: AddressSanitizer: heap-use-after-free",
                                       None, False, "heap-use-after-free", "#0 in target",
                                       "ENVIRONMENT_ERROR")
            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run", return_value=incomplete), \
                 patch("vulnerabilityanalysis.scan.trace_process_harness",
                       return_value=(True, True, None, "trace")), \
                 patch("vulnerabilityanalysis.scan.triage_crash",
                       return_value={"category": "ENVIRONMENT_ERROR", "sp_linked": False}):
                execute_poc(poc, point, [str(binary), "--", "{input}"], run_dir,
                            trace_reachability=True, target_binary=binary)
            result = json.loads((run_dir / "runtime/poc-1.json").read_text())
            self.assertEqual(result["failure_classification"], "ENVIRONMENT_ERROR")
            self.assertEqual(result["sanitizer"], "heap-use-after-free")

    def test_direct_crashing_poc_is_traced_without_becoming_a_fuzz_seed(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            sample = run_dir / "input.bin"
            sample.write_bytes(b"crash")
            point = SuspiciousPoint(
                "sp-1", "w", "d", "target", "target.c", "target.c:9",
                "write", "hypothesis", [], "input", [], [], [], [],
                sp_condition="i >= size",
            )
            poc = PoC("poc-1", "sp-1", "", str(sample), None, "observation")
            crash = RuntimeResult(
                1, "", "ERROR: AddressSanitizer: heap-buffer-overflow", None,
                False, "heap-buffer-overflow", "stack", "SANITIZER_CRASH",
            )
            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run", return_value=crash), \
                 patch("vulnerabilityanalysis.scan.trace_function_reached",
                       return_value=(True, "function hit")) as function_trace, \
                 patch("vulnerabilityanalysis.scan.trace_sp_location",
                       return_value=(True, True, "condition hit")) as sp_trace, \
                 patch("vulnerabilityanalysis.scan.triage_crash",
                       return_value={"category": "HARNESS_CRASH", "sp_linked": False}):
                evidence = execute_poc(
                    poc, point, ["/usr/bin/cat", "{input}"], run_dir,
                    trace_reachability=True, sp_location="target.c:9",
                    sp_condition="i >= size",
                )

            function_trace.assert_called_once_with(Path("/usr/bin/cat"), sample, "target")
            sp_trace.assert_called_once_with(
                Path("/usr/bin/cat"), sample, "target.c:9", "i >= size")
            result = json.loads((run_dir / "runtime/poc-1.json").read_text())
            self.assertTrue(result["function_reached"])
            self.assertTrue(result["sp_location_reached"])
            self.assertTrue(result["sp_condition_reached"])
            self.assertEqual(result["failure_classification"], "SANITIZER_CRASH")
            self.assertFalse(any(item.type == "CORPUS_SEED" for item in evidence))
            self.assertFalse((run_dir / "corpus").exists())


if __name__ == "__main__":
    unittest.main()
