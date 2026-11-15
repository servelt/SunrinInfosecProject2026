import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.analysis import RetryLedger
from vulnerabilityanalysis.models import RuntimeResult
from vulnerabilityanalysis.runtime import fuzz_locally, fuzz_process_harness
from vulnerabilityanalysis.scan import (run_global_fuzz,
                                        _corpus_inputs,
                                        _observed_libfuzzer_crash_mutation,
                                        _observed_libfuzzer_crash_mutations,
                                        record_global_fuzzer_observations,
                                        settle_failed_fuzz_reservations)


class GlobalFuzzConnectionTest(unittest.TestCase):
    def test_corpus_index_rejects_symlinked_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / 'corpus'; corpus.mkdir()
            outside = root / 'outside'; outside.write_bytes(b'external')
            (corpus / 'linked').symlink_to(outside)
            seed = corpus / 'seed'; seed.write_bytes(b'Y')
            self.assertEqual(_corpus_inputs(corpus), {
                hashlib.sha256(b'Y').hexdigest(): seed})

    def test_crash_mutation_can_descend_from_new_corpus_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / 'initial'; seed.write_bytes(b'Y')
            intermediate = root / 'generated'; intermediate.write_bytes(b'YZ')
            crash = root / 'crash-generated'; crash.write_bytes(b'YZX')
            initial_sha = hashlib.sha256(seed.read_bytes()).hexdigest()
            generated_sha = hashlib.sha256(intermediate.read_bytes()).hexdigest()
            crash_sha = hashlib.sha256(crash.read_bytes()).hexdigest()
            stderr = (
                'MS: 1 InsertByte-; base unit: ' +
                hashlib.sha1(intermediate.read_bytes()).hexdigest() + '\n' +
                "artifact_prefix='./'; Test unit written to ./crash-generated\n")
            observation = [{'observed_crash_id': 'crash-one',
                            'candidate_path': str(crash), 'sha256': crash_sha}]
            corpus = {initial_sha: seed, generated_sha: intermediate}
            self.assertTrue(_observed_libfuzzer_crash_mutation(
                stderr, observation, {initial_sha}, corpus))
            self.assertEqual(_observed_libfuzzer_crash_mutations(
                stderr, observation, {initial_sha}, corpus), [{
                    'observed_crash_id': 'crash-one',
                    'input_sha256': crash_sha,
                    'base_sha256': generated_sha}])
            other = root / 'crash-other'; other.write_bytes(b'YZZ')
            other_sha = hashlib.sha256(other.read_bytes()).hexdigest()
            rows = [*observation, {'observed_crash_id': 'crash-two',
                                  'candidate_path': str(other), 'sha256': other_sha}]
            self.assertEqual(_observed_libfuzzer_crash_mutations(
                stderr, rows, {initial_sha}, corpus), [{
                    'observed_crash_id': 'crash-one',
                    'input_sha256': crash_sha,
                    'base_sha256': generated_sha}])
            self.assertFalse(_observed_libfuzzer_crash_mutation(
                stderr, observation, {initial_sha}, {initial_sha: seed}))
            self.assertFalse(_observed_libfuzzer_crash_mutation(
                stderr, observation, {initial_sha, crash_sha}, corpus))
            self.assertFalse(_observed_libfuzzer_crash_mutation(
                stderr.replace('crash-generated', 'crash-other'), observation,
                {initial_sha}, corpus))

    def test_coverage_timeout_preserves_earlier_sanitizer_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed"; seed.write_bytes(b"A")
            binary = root / "target"; binary.write_bytes(b"target")
            calls = 0

            def execute(argv, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    Path(kwargs["env"]["LLVM_PROFILE_FILE"]).write_bytes(b"profile")
                    return subprocess.CompletedProcess(argv, 1, "",
                        "ERROR: AddressSanitizer: heap-buffer-overflow\n")
                raise subprocess.TimeoutExpired(argv, 5)

            with patch("vulnerabilityanalysis.runtime.shutil.which", return_value="tool"), \
                 patch("vulnerabilityanalysis.runtime._guarded_run", side_effect=execute):
                report = fuzz_process_harness(binary, [str(binary), "{input}"],
                                              [seed], root / "fuzz", seconds=1)
            self.assertIn("heap-buffer-overflow", report["observations"][0]["sanitizer"])
            self.assertTrue(Path(report["observations"][0]["stderr_path"]).is_file())
            self.assertIsNone(report["coverage_feedback"])
            self.assertEqual(report["coverage_error"], "TimeoutExpired")

    def test_coverage_postprocessing_uses_remaining_fuzz_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed"; seed.write_bytes(b"A")
            binary = root / "target"; binary.write_bytes(b"target")
            calls = []

            def execute(argv, **kwargs):
                calls.append((argv[0], kwargs["timeout"]))
                if len(calls) == 1:
                    Path(kwargs["env"]["LLVM_PROFILE_FILE"]).write_bytes(b"profile")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                time.sleep(0.12)  # Simulate a tool that consumes the remaining deadline.
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch("vulnerabilityanalysis.runtime.shutil.which", return_value="tool"), \
                 patch("vulnerabilityanalysis.runtime._guarded_run", side_effect=execute):
                report = fuzz_process_harness(binary, [str(binary), "{input}"],
                                              [seed], root / "fuzz", seconds=0.1)
            self.assertEqual([name for name, _ in calls], [str(binary), "llvm-profdata"])
            self.assertLessEqual(calls[1][1], 0.1)
            self.assertEqual(report["coverage_error"], "FUZZ_DEADLINE_EXPIRED")
            self.assertEqual(len(report["observations"]), 1)

    def test_larger_explicit_global_budget_reexecutes_same_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            result = RuntimeResult(0, "", "#2 INITED cov: 1 ft: 1 corp: 1/1b\n"
                                   "#10 NEW cov: 2 ft: 2 corp: 2/2b\n",
                                   None, False, None, None, "UNKNOWN")
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=result) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(3),
                                        run_command=[str(binary), "{input}"],
                                        seconds=1, enabled=True)
                second = run_global_fuzz(binary, root, RetryLedger(3),
                                         run_command=[str(binary), "{input}"],
                                         seconds=30, enabled=True)
            self.assertEqual((first["status"], second["status"]), ("RAN", "RAN"))
            self.assertEqual(fuzz.call_count, 2)
            self.assertNotEqual(first["runtime_artifact"], second["runtime_artifact"])

    def test_direct_libfuzzer_probes_once_then_writes_final_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fuzzer"
            binary.write_bytes(b"binary")
            binary.chmod(0o755)
            interface = subprocess.CompletedProcess(
                [str(binary), "-help=1"], 0, "max_total_time", "")
            result = RuntimeResult(
                0, "", "#2 INITED cov: 1 ft: 1 corp: 1/1b\n"
                "#10 NEW cov: 2 ft: 2 corp: 2/2b\n",
                None, False, None, None, "UNKNOWN")
            with patch("vulnerabilityanalysis.scan._guarded_run",
                       return_value=interface) as probe, \
                 patch("vulnerabilityanalysis.scan.fuzz_locally",
                       return_value=result) as fuzz:
                report = run_global_fuzz(
                    binary, root, RetryLedger(3),
                    run_command=[str(binary), "{input}"],
                    seconds=30, enabled=True)
            probe.assert_called_once_with([str(binary.resolve()), "-help=1"], timeout=5)
            fuzz.assert_called_once_with(binary, corpus, seconds=30, single_process=True)
            self.assertEqual(report["status"], "RAN")
            self.assertTrue((root / "runtime/global_fuzz.json").is_file())
            self.assertEqual(
                json.loads((root / "runtime/global_fuzz.json").read_text())["status"],
                "RAN")

    def test_larger_process_budget_reexecutes_without_overwriting_prior_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "target"; binary.write_bytes(b"target")
            binary.chmod(0o755)
            command = [sys.executable, "wrapper.py", str(binary), "{input}"]
            completed = {"status": "RAN", "observations": [], "mutation_count": 1,
                         "coverage_feedback": None}
            with patch("vulnerabilityanalysis.scan.fuzz_process_harness",
                       return_value=completed) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(3),
                                        run_command=command, seconds=1, enabled=True)
                old_artifact = Path(first["runtime_artifact"])
                old_content = old_artifact.read_bytes()
                second = run_global_fuzz(binary, root, RetryLedger(3),
                                         run_command=command, seconds=30, enabled=True)
            self.assertEqual(fuzz.call_count, 2)
            self.assertEqual(second["status"], "RAN")
            self.assertNotEqual(first["runtime_artifact"], second["runtime_artifact"])
            self.assertEqual(old_artifact.read_bytes(), old_content)

    def test_failed_fuzz_reservation_returns_only_unused_time_after_join(self):
        windows = [
            {"reservation_preallocated": True, "reserved_seconds": 600,
             "actual_seconds": 0.2, "status": "ERROR"},
            {"reservation_preallocated": True, "reserved_seconds": 200,
             "actual_seconds": 12.0, "status": "RAN"},
        ]
        self.assertEqual(settle_failed_fuzz_reservations(800, windows), 201)

    def test_failed_process_mutation_is_not_reported_as_completed_fuzzing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"A")
            binary = root / "target"
            binary.write_bytes(b"binary")
            success = subprocess.CompletedProcess([str(binary)], 0, "", "")
            with patch("vulnerabilityanalysis.runtime._guarded_run",
                       side_effect=[success, OSError("synthetic launch failure")]), \
                 patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None):
                result = fuzz_process_harness(binary, [str(binary), "{input}"],
                                              [seed], root / "fuzz", seconds=1)
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["mutation_count"], 0)
            self.assertEqual(result["mutation_attempted_count"], 1)
            self.assertEqual(result["mutation_executed_count"], 0)

    def test_two_argument_process_harness_uses_process_mutation_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "process-target"
            binary.write_text("#!/bin/sh\nexit 0\n"); binary.chmod(0o755)
            outcome = {"status": "RAN", "observations": [], "mutation_count": 1,
                       "coverage_feedback": None}
            with patch("vulnerabilityanalysis.scan.fuzz_process_harness",
                       return_value=outcome) as process:
                report = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=[str(binary), "{input}"],
                                         seconds=1, enabled=True)
            process.assert_called_once()
            self.assertEqual(report["status"], "RAN")

    def test_libfuzzer_reports_all_new_crash_input_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n"); binary.chmod(0o755)
            def fake_fuzz(_binary, folder, **_kwargs):
                (folder / "crash-1").write_bytes(b"X")
                (folder / "crash-2").write_bytes(b"Y")
                return RuntimeResult(1, "", "ERROR: AddressSanitizer: heap-buffer-overflow",
                                     "heap-buffer-overflow", False, None, None, "TARGET_BUG")
            with patch("vulnerabilityanalysis.scan.fuzz_locally", side_effect=fake_fuzz):
                report = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=[str(binary), "{input}"],
                                         seconds=1, enabled=True)
            self.assertEqual({Path(row["candidate_path"]).read_bytes()
                              for row in report["observed_crashes"]}, {b"X", b"Y"})

    def test_help_text_without_runtime_fuzz_evidence_is_not_cached_as_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "claiming-fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            no_fuzz_evidence = RuntimeResult(0, "", "", None, False,
                                             None, None, "UNKNOWN")
            with patch("vulnerabilityanalysis.scan.fuzz_locally",
                       return_value=no_fuzz_evidence) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(2),
                                        run_command=[str(binary), "{input}"],
                                        seconds=1, enabled=True)
                second = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=[str(binary), "{input}"],
                                         seconds=1, enabled=True)
            self.assertEqual(first["status"], "INCOMPLETE_NO_FUZZ_EVIDENCE")
            self.assertEqual(second["status"], "INCOMPLETE_NO_FUZZ_EVIDENCE")
            self.assertEqual(fuzz.call_count, 2)

    def test_process_sanitizer_observation_has_crash_identity_and_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "target"; binary.write_bytes(b"binary"); binary.chmod(0o755)
            command = [sys.executable, "wrapper.py", str(binary), "{input}"]

            def fake_fuzz(_binary, _command, _seeds, output, *, seconds):
                output.mkdir(parents=True)
                sample = output / "input-000.bin"; sample.write_bytes(b"X")
                return {"status": "RAN", "coverage_feedback": None, "mutation_count": 1,
                        "observations": [{"input_path": str(sample), "sha256":
                            __import__("hashlib").sha256(b"X").hexdigest(),
                            "sanitizer": "heap-buffer-overflow", "status": "EXECUTED"}]}

            with patch("vulnerabilityanalysis.scan.fuzz_process_harness", side_effect=fake_fuzz):
                report = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=command, seconds=1, enabled=True)
            self.assertEqual(len(report["observed_crashes"]), 1)
            self.assertEqual(Path(report["observed_crashes"][0]["candidate_path"]).read_bytes(), b"X")
            self.assertTrue(report["observed_crashes"][0]["observed_crash_id"])
            ids = record_global_fuzzer_observations(root, report)
            self.assertEqual(ids, {report["observed_crashes"][0]["observed_crash_id"]})
            queued = json.loads((root / "runtime/fuzzer_crashes" /
                                 f"{next(iter(ids))}.json").read_text())
            self.assertEqual(queued["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
            self.assertEqual(queued["observations"][0]["crash_input"]["sha256"],
                             report["observed_crashes"][0]["sha256"])

    def test_process_harness_identity_includes_binary_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "target"; binary.write_bytes(b"first"); binary.chmod(0o755)
            command = [sys.executable, "wrapper.py", str(binary), "{input}"]
            completed = {"status": "RAN", "coverage_feedback": None,
                         "observations": [], "mutation_count": 1}
            with patch("vulnerabilityanalysis.scan.fuzz_process_harness",
                       return_value=completed) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(2),
                                        run_command=command, seconds=1, enabled=True)
                binary.write_bytes(b"second")
                second = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=command, seconds=1, enabled=True)
            self.assertEqual(fuzz.call_count, 2)
            self.assertEqual(second["status"], "RAN")
            self.assertNotEqual(first["seed_fingerprint"], second["seed_fingerprint"])

    def test_blocked_process_harness_attempt_is_not_cached_as_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "target"; binary.write_bytes(b"same"); binary.chmod(0o755)
            command = [sys.executable, "wrapper.py", str(binary), "{input}"]
            blocked = {"status": "BLOCKED", "coverage_feedback": None,
                       "observations": [], "mutation_count": 0}
            completed = {"status": "RAN", "coverage_feedback": None,
                         "observations": [], "mutation_count": 1}
            with patch("vulnerabilityanalysis.scan.fuzz_process_harness",
                       side_effect=[blocked, completed]) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(2),
                                        run_command=command, seconds=1, enabled=True)
                second = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=command, seconds=1, enabled=True)
            self.assertEqual(first["status"], "BLOCKED")
            self.assertEqual(second["status"], "RAN")
            self.assertEqual(fuzz.call_count, 2)

    def test_timeout_is_not_reported_or_cached_as_completed_global_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho 'max_total_time'\n")
            binary.chmod(0o755)
            timed_out = RuntimeResult(None, "", "deadline exceeded", None, True,
                                      None, None, "ENVIRONMENT_ERROR")
            completed = RuntimeResult(0, "", "#2 INITED cov: 1 ft: 1\n#100 DONE cov: 1 ft: 1\n", None,
                                      False, None, None, "UNKNOWN",
                                      coverage={"initial_edges": 1, "final_edges": 1,
                                                "initial_features": 1, "final_features": 1,
                                                "status": "UNCHANGED"})
            with patch("vulnerabilityanalysis.scan.fuzz_locally",
                       side_effect=[timed_out, completed]) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(2),
                                        run_command=[str(binary), "{input}"],
                                        seconds=1, enabled=True)
                self.assertEqual(first["status"], "TIMED_OUT")
                second = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=[str(binary), "{input}"],
                                         seconds=1, enabled=True)
                self.assertEqual(second["status"], "RAN")
                self.assertEqual(fuzz.call_count, 2)

    def test_nonzero_libfuzzer_exit_with_progress_is_not_completed_or_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            abnormal = RuntimeResult(1, "", "#2 INITED cov: 1 ft: 1\n#10 DONE cov: 2 ft: 2\n",
                                     None, False, None, None, "UNKNOWN")
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=abnormal) as fuzz:
                first = run_global_fuzz(binary, root, RetryLedger(2),
                                        run_command=[str(binary), "{input}"],
                                        seconds=1, enabled=True)
                second = run_global_fuzz(binary, root, RetryLedger(2),
                                         run_command=[str(binary), "{input}"],
                                         seconds=1, enabled=True)
            self.assertEqual(first["status"], "ERROR")
            self.assertEqual(second["status"], "ERROR")
            self.assertIn("failed", first["reason"])
            self.assertEqual(fuzz.call_count, 2)

    def test_incompatible_fuzzer_is_blocked_without_consuming_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "useful.bin").write_bytes(b"A")
            binary = root / "fuzzer"; binary.write_text("#!/bin/sh\nexit 0\n"); binary.chmod(0o755)
            result = run_global_fuzz(binary, root, RetryLedger(2),
                                     run_command=["/different/target", "{input}"],
                                     seconds=1, enabled=True)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse((root / "runtime/global_fuzz.runtime.json").exists())

    def test_global_fuzzer_consumes_seed_and_records_coverage_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "useful.bin").write_bytes(b"A")
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\n"
                              "if [ \"$1\" = '-help=1' ]; then echo 'libFuzzer max_total_time runs'; exit 0; fi\n"
                              "test -f \"$1/useful.bin\" || exit 4\n"
                              "echo '#2 INITED cov: 5 ft: 5 corp: 1/1b' >&2\n"
                              "echo '#100 NEW cov: 7 ft: 8 corp: 2/2b' >&2\n")
            binary.chmod(0o755)
            ledger = RetryLedger(2)
            first = run_global_fuzz(binary, root, ledger,
                                    run_command=[str(binary), "{input}"], seconds=1,
                                    enabled=True)
            self.assertEqual(first["status"], "RAN")
            self.assertEqual(first["seed_count"], 1)
            self.assertEqual(first["coverage_feedback"]["initial_edges"], 5)
            self.assertEqual(first["coverage_feedback"]["final_edges"], 7)
            self.assertEqual(first["coverage_feedback"]["status"], "INCREASED")
            self.assertEqual(json.loads(Path(first["runtime_artifact"]).read_text())
                             ["coverage"]["final_edges"], 7)
            second = run_global_fuzz(binary, root, RetryLedger(2),
                                     run_command=[str(binary), "{input}"], seconds=1,
                                     enabled=True)
            self.assertEqual(second["status"], "SKIPPED_NO_NEW_EVIDENCE")
            old_artifact = Path(first["runtime_artifact"])
            old_content = old_artifact.read_bytes()
            (corpus / "new.bin").write_bytes(b"B")
            third = run_global_fuzz(binary, root, RetryLedger(2),
                                    run_command=[str(binary), "{input}"], seconds=1,
                                    enabled=True)
            self.assertEqual(third["status"], "RAN")
            self.assertNotEqual(third["runtime_artifact"], first["runtime_artifact"])
            self.assertEqual(old_artifact.read_bytes(), old_content)

    def test_coverage_not_claimed_without_libfuzzer_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "quiet"; binary.write_text("#!/bin/sh\nexit 0\n"); binary.chmod(0o755)
            result = fuzz_locally(binary, root / "corpus", seconds=1)
            self.assertIsNone(result.coverage)

    def test_timeout_preserves_partial_libfuzzer_output_without_completed_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"; binary.write_bytes(b"binary")
            partial = b"INFO: seed corpus: files: 1\n#2 INITED cov: 7 ft: 9 corp: 1/1b\n"
            error = subprocess.TimeoutExpired([str(binary)], 16, stderr=partial)
            with patch("vulnerabilityanalysis.runtime._guarded_run", side_effect=error):
                result = fuzz_locally(binary, root / "corpus", seconds=1)
            self.assertTrue(result.timed_out)
            self.assertIn("INITED cov: 7", result.stderr)
            self.assertIsNone(result.coverage)

    def test_timeout_retains_partial_sanitizer_report_as_unverified_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"; binary.write_bytes(b"binary")
            partial = (b"ERROR: AddressSanitizer: heap-buffer-overflow\n"
                       b"#0 0x1 in parse /tmp/source.c:9\n")
            error = subprocess.TimeoutExpired([str(binary)], 16, stderr=partial)
            with patch("vulnerabilityanalysis.runtime._guarded_run", side_effect=error):
                result = fuzz_locally(binary, root / "corpus", seconds=1)
            self.assertTrue(result.timed_out)
            self.assertIn("heap-buffer-overflow", result.sanitizer)
            self.assertIn("/tmp/source.c:9", result.stderr)
            self.assertIsNone(result.coverage)

    def test_process_harness_mutates_with_separate_line_coverage(self):
        if not all(shutil.which(name) for name in ("clang", "llvm-profdata", "llvm-cov")):
            self.skipTest("LLVM coverage tools required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text("#include <stdio.h>\nint main(int argc,char**argv) { "
                              "FILE*f=fopen(argv[1],\"rb\"); int c=fgetc(f); fclose(f); "
                              "if(c=='A') puts(\"a\"); else puts(\"other\"); return 0; }\n")
            binary = root / "target"
            subprocess.run(["clang", "-g", "-O0", "-fprofile-instr-generate",
                            "-fcoverage-mapping", str(source), "-o", str(binary)], check=True)
            runner = root / "runner.py"
            runner.write_text("import subprocess,sys\n"
                              "raise SystemExit(subprocess.call([sys.argv[1],sys.argv[2]]))\n")
            corpus = root / "corpus/global"; corpus.mkdir(parents=True)
            (corpus / "seed.bin").write_bytes(b"A")
            command = [sys.executable, str(runner), str(binary), "{input}"]
            first = run_global_fuzz(binary, root, RetryLedger(2),
                                    run_command=command, seconds=3, enabled=True)
            self.assertEqual(first["status"], "RAN", first)
            self.assertGreater(first["mutation_count"], 0)
            self.assertEqual(first["coverage_feedback"]["kind"], "LLVM_SOURCE_LINES")
            self.assertGreaterEqual(first["coverage_feedback"]["final_lines"],
                                    first["coverage_feedback"]["initial_lines"])
            second = run_global_fuzz(binary, root, RetryLedger(2),
                                     run_command=command, seconds=3, enabled=True)
            self.assertEqual(second["status"], "SKIPPED_NO_NEW_EVIDENCE")
