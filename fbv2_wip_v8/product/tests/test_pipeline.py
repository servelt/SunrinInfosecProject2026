import tempfile
import unittest
from pathlib import Path
import sys

from vulnerabilityanalysis.runtime import classify_runtime, parse_sanitizer, RuntimeExecutor
from vulnerabilityanalysis.analysis import RetryLedger, review_verdict, validate_generator_script


class RetryAndStateTest(unittest.TestCase):
    def test_same_strategy_without_new_evidence_stops(self):
        ledger = RetryLedger(max_attempts=2)
        self.assertTrue(ledger.allow("sp-1", "seed", []))
        ledger.record("sp-1", "seed", [], "INPUT_INVALID")
        self.assertFalse(ledger.allow("sp-1", "seed", []))
        self.assertTrue(ledger.allow("sp-1", "seed", ["new-trace"]))

    def test_unverified_attempt_never_refutes_candidate(self):
        self.assertEqual(review_verdict("REFUTED", [], ["no crash in one run"]), "UNKNOWN")
        self.assertEqual(review_verdict("REFUTED", ["caller has unconditional size guard at line 40"], []), "REFUTED")


class RuntimeTest(unittest.TestCase):
    def test_sanitizer_report_is_parsed_and_not_confused_with_exit_code(self):
        stderr = "==123==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 bad at target.c:22\n"
        self.assertEqual(parse_sanitizer(stderr), "AddressSanitizer: heap-buffer-overflow")
        self.assertEqual(classify_runtime(1, stderr, target_reached=None, sp_reached=None), "SANITIZER_CRASH")
        self.assertEqual(classify_runtime(0, "", target_reached=None, sp_reached=None), "UNKNOWN")

    def test_local_command_substitutes_input_without_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "seed"
            p.write_bytes(b"hello")
            result = RuntimeExecutor(timeout_seconds=2).run(["/usr/bin/wc", "-c", "{input}"], p)
            self.assertEqual(result.exit_code, 0)
            self.assertIn("5", result.stdout)
            self.assertEqual(result.failure_classification, "UNKNOWN")


class GeneratorTest(unittest.TestCase):
    def test_structured_text_input_builder_is_accepted(self):
        from vulnerabilityanalysis.analysis import generate_input
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generate_input("def build():\n    lines = ['---', 'key: value']\n"
                           "    return ('\\n'.join(lines) + '\\n').encode('utf-8')\n",
                           root / "generate.py", root / "input.bin")
            self.assertEqual((root / "input.bin").read_bytes(), b"---\nkey: value\n")

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX resource limits required")
    def test_generator_memory_limit_retries_once_within_fixed_cap(self):
        from vulnerabilityanalysis.analysis import generate_input
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generate_input("def build():\n    scratch = bytearray(80 * 1024 * 1024)\n"
                           "    return b'A'\n", root / "generate.py", root / "input.bin",
                           initial_memory_mib=64, max_memory_mib=128)
            self.assertEqual((root / "input.bin").read_bytes(), b"A")
            receipt = json.loads((root / "generate.py.resources.json").read_text())
            self.assertEqual(receipt["attempts"], [
                {"memory_mib": 64, "status": "MEMORY_LIMIT"},
                {"memory_mib": 128, "status": "COMPLETED"}])

    def test_generator_script_size_is_bounded_before_parsing(self):
        from vulnerabilityanalysis.analysis import generate_input
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "generator script exceeds 2 MiB"):
                generate_input("x" * (2_097_152 + 1), root / "generate.py",
                               root / "input.bin")
            self.assertFalse((root / "generate.py").exists())

    def test_invalid_generator_syntax_is_a_pov_validation_error(self):
        from vulnerabilityanalysis.analysis import generate_input
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "generate.py"
            output = Path(temp) / "input.bin"
            with self.assertRaisesRegex(ValueError, "generator syntax"):
                generate_input("def build(:\n    pass\n", script, output)
            self.assertFalse(script.exists())
            self.assertFalse(output.exists())

    def test_rejects_external_process_or_network_imports(self):
        with self.assertRaises(ValueError):
            validate_generator_script("import socket\nopen('x','wb').write(b'x')")
        with self.assertRaises(ValueError):
            validate_generator_script("import subprocess\nsubprocess.run(['curl','x'])")


if __name__ == "__main__":
    unittest.main()
