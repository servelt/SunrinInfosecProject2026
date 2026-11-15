"""HP Assertion replay must not inherit a parent ASan abort policy."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.assertions import (
    HP_ASSERTION_ASAN_OPTIONS, _run_assertion_command,
    _run_hp_assertion_input)
from vulnerabilityanalysis.runtime import (
    CLEAN_RUNTIME_ENVIRONMENT, ProcessEnvelopeStop, RuntimeStartError,
    _guarded_run, fuzz_locally, trace_sp_location)


class HPAssertionEnvironmentReceiptTest(unittest.TestCase):
    def test_parent_abort_and_loader_options_do_not_reach_assertion_replay(self):
        observed = []

        def fake_guarded_run(argv, **kwargs):
            observed.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_bytes(b"fixture")
            with patch.dict(os.environ, {
                    "ASAN_OPTIONS": "handle_abort=1",
                    "LD_PRELOAD": "/tmp/parent-injection.so",
                    "PATH": "/tmp/parent-tools",
            }, clear=True), patch(
                    "vulnerabilityanalysis.runtime.shutil.which", return_value=None
            ), patch(
                    "vulnerabilityanalysis.runtime._guarded_run", fake_guarded_run
            ):
                result = _run_hp_assertion_input(
                    ["/synthetic-binary", "{input}"], input_path,
                    timeout_seconds=3, process_envelope=None,
                    process_segment="assertion.instrumented_seed_replay")

        self.assertEqual(len(observed), 1)
        environment = observed[0][1]["env"]
        self.assertEqual(environment, {
            **CLEAN_RUNTIME_ENVIRONMENT,
            "ASAN_OPTIONS": HP_ASSERTION_ASAN_OPTIONS,
        })
        self.assertEqual(result.runtime_profile["launch_environment"], environment)
        self.assertEqual(result.runtime_profile["launch_asan_options"],
                         HP_ASSERTION_ASAN_OPTIONS)
        self.assertTrue(result.runtime_profile["target_started"])
        self.assertEqual(result.runtime_profile["environment_policy"],
                         "CLEAN_HP_ASSERTION_ENV_V1")
        self.assertEqual(observed[0][1]["process_segment"],
                         "assertion.instrumented_seed_replay")

    def test_failed_start_records_attempted_environment_without_claiming_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_bytes(b"fixture")
            with patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None), \
                 patch("vulnerabilityanalysis.runtime._guarded_run",
                       side_effect=RuntimeStartError("launch failed")):
                result = _run_hp_assertion_input(
                    ["/synthetic-binary", "{input}"], input_path,
                    timeout_seconds=3, process_envelope=None,
                    process_segment="assertion.instrumented_seed_replay")
        self.assertEqual(result.failure_classification, "HARNESS_NOT_STARTED")
        self.assertFalse(result.runtime_profile["target_started"])
        self.assertEqual(result.runtime_profile["launch_asan_options"],
                         HP_ASSERTION_ASAN_OPTIONS)

    def test_post_process_ledger_error_stops_instead_of_claiming_no_target(self):
        class FailingEnvelope:
            output_limit_bytes = 4096
            deadline_monotonic = float("inf")

            def before_process(self, *args, **kwargs):
                return "lease"

            def after_process(self, *args, **kwargs):
                raise OSError("synthetic ledger failure after completion")

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_bytes(b"fixture")
            with patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None), \
                 patch("vulnerabilityanalysis.runtime._guarded_run_once",
                       return_value=subprocess.CompletedProcess(
                           ["/synthetic-binary", str(input_path)], 0, "", "")):
                with self.assertRaises(ProcessEnvelopeStop) as caught:
                    _run_hp_assertion_input(
                        ["/synthetic-binary", "{input}"], input_path,
                        timeout_seconds=3, process_envelope=FailingEnvelope(),
                        process_segment="assertion.instrumented_seed_replay")
        self.assertEqual(caught.exception.status, "STOPPED_PROCESS_LEDGER_ERROR")

    def test_reservation_oserror_stops_without_launching_target(self):
        class FailingEnvelope:
            output_limit_bytes = 4096
            deadline_monotonic = float("inf")

            def before_process(self, *args, **kwargs):
                raise OSError("synthetic reservation I/O")

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_bytes(b"fixture")
            with patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None), \
                 patch("vulnerabilityanalysis.runtime._guarded_run_once") as launch:
                with self.assertRaises(ProcessEnvelopeStop) as caught:
                    _run_hp_assertion_input(
                        ["/synthetic-binary", "{input}"], input_path,
                        timeout_seconds=3, process_envelope=FailingEnvelope(),
                        process_segment="assertion.test_original_replay")
                launch.assert_not_called()
        self.assertEqual(caught.exception.status, "STOPPED_PROCESS_LEDGER_ERROR")

    def test_signed_prelaunch_cwd_error_is_not_a_completed_original_build(self):
        class UnusedEnvelope:
            output_limit_bytes = 4096
            deadline_monotonic = float("inf")

            def before_process(self, *args, **kwargs):
                raise AssertionError("reservation should not be attempted")

        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-cwd"
            with patch("vulnerabilityanalysis.runtime._guarded_run_once") as launch:
                with self.assertRaises(ProcessEnvelopeStop) as caught:
                    _guarded_run(
                        ["/synthetic-builder"], cwd=missing, timeout=3,
                        process_envelope=UnusedEnvelope(),
                        process_segment="assertion.test_original_build")
                launch.assert_not_called()
        self.assertEqual(caught.exception.status, "STOPPED_PROCESS_PRELAUNCH_ERROR")

    def test_untyped_runtime_oserror_does_not_prove_start_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_bytes(b"fixture")
            with patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None), \
                 patch("vulnerabilityanalysis.runtime._guarded_run",
                       side_effect=OSError("uncertain runtime I/O")):
                with self.assertRaisesRegex(OSError, "uncertain runtime I/O"):
                    _run_hp_assertion_input(
                        ["/synthetic-binary", "{input}"], input_path,
                        timeout_seconds=3, process_envelope=None,
                        process_segment="assertion.instrumented_seed_replay")

    def test_signed_guided_fuzz_receives_pinned_environment(self):
        observed = []

        def fake_guarded_run(argv, **kwargs):
            observed.append(kwargs)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                "ASAN_OPTIONS": "handle_abort=1",
                "LD_PRELOAD": "/tmp/parent-injection.so",
        }, clear=True), patch("vulnerabilityanalysis.runtime._guarded_run", fake_guarded_run):
            root = Path(directory)
            fuzz_locally(root / "binary", root / "corpus", seconds=1,
                         process_envelope=object(),
                         env={**CLEAN_RUNTIME_ENVIRONMENT,
                              "ASAN_OPTIONS": HP_ASSERTION_ASAN_OPTIONS})
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["env"], {
            **CLEAN_RUNTIME_ENVIRONMENT,
            "ASAN_OPTIONS": HP_ASSERTION_ASAN_OPTIONS,
        })

    def test_signed_build_and_gdb_trace_use_clean_parent_environment(self):
        observed = []
        scripts = []

        def fake_guarded_run(argv, **kwargs):
            observed.append(kwargs)
            if "-x" in argv:
                scripts.append(Path(argv[argv.index("-x") + 1]).read_text())
            return subprocess.CompletedProcess(argv, 0,
                'Source files for which symbols have been read in:\n' + str(source), "")

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "target.c"
            binary = Path(directory) / "binary"
            input_path = Path(directory) / "input"
            source.write_text("int target(void) { return 0; }\n")
            binary.write_bytes(b"fixture")
            input_path.write_bytes(b"fixture")
            with patch.dict(os.environ, {
                    "ASAN_OPTIONS": "handle_abort=1",
                    "LD_PRELOAD": "/tmp/parent-injection.so",
            }, clear=True), patch(
                    "vulnerabilityanalysis.runtime._guarded_run", fake_guarded_run
            ), patch("vulnerabilityanalysis.assertions._guarded_run", fake_guarded_run):
                _run_assertion_command(["cc", "-v"], timeout=2,
                                       process_envelope=object())
                trace_sp_location(binary, input_path, f"{source}:1",
                                  process_envelope=object(),
                                  env={**CLEAN_RUNTIME_ENVIRONMENT,
                                       "ASAN_OPTIONS": HP_ASSERTION_ASAN_OPTIONS})

        self.assertGreaterEqual(len(observed), 3)
        expected = {**CLEAN_RUNTIME_ENVIRONMENT,
                    "ASAN_OPTIONS": HP_ASSERTION_ASAN_OPTIONS}
        self.assertTrue(all(row["env"] == expected for row in observed))
        self.assertEqual(len(scripts), 1)
        self.assertIn("set environment ASAN_OPTIONS detect_leaks=0:handle_abort=0",
                      scripts[0])

    def test_signed_build_rejects_unpinned_explicit_environment(self):
        with patch("vulnerabilityanalysis.assertions._guarded_run") as runner:
            with self.assertRaisesRegex(ValueError, "environment is not pinned"):
                _run_assertion_command(["cc", "-v"], timeout=2,
                    process_envelope=object(),
                    env={"LD_PRELOAD": "/tmp/parent-injection.so"})
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
