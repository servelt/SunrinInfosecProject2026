"""Provider-free physical fuzz boundary checks for HP Guided campaigns."""

from __future__ import annotations

import json
import hashlib
from dataclasses import asdict
from pathlib import Path
import subprocess
import time
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.assertions import guided_fuzz_assertion
from vulnerabilityanalysis.models import Assertion, RuntimeResult
from vulnerabilityanalysis.scan import run_assertions_for_scan
from vulnerabilityanalysis.runtime import (PhysicalFuzzBudgetPending,
                                           PhysicalFuzzStop, RuntimeCleanupError)


class GuidedPhysicalBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "target.c"
        self.source.write_text("int target(int n) { return n; }\n")
        self.seed = self.root / "seed"
        self.seed.write_bytes(b"A")
        self.output = self.root / "guided"
        self.assertion = Assertion("hp-a", "worker", "direction", "target",
                                   "target.c:1", "n >= 0", "n >= 0", [])
        self.initial_violation = False

    def _instrument(self, source, _line, _expression, destination, *_args, **_kwargs):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())

    def _command(self, argv, **_kwargs):
        if "-E" in argv:
            self.assertIn("-P", argv)
            probe = Path(argv[-1])
            self.assertTrue(probe.name.startswith("va-macro-probe-"))
            return subprocess.CompletedProcess(argv, 0, probe.read_text(), "")
        if "-o" in argv:
            binary = Path(argv[argv.index("-o") + 1])
            binary.write_bytes(b"toy binary")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "-runs=1" in argv:
            marker = ("VA_ASSERTION_VIOLATION:hp-a\n"
                      if self.initial_violation else "")
            return subprocess.CompletedProcess(argv, 0, "",
                                               "16 Extra Counters\n" + marker)
        if any(Path(part).name.startswith("crash-") for part in argv):
            return subprocess.CompletedProcess(
                argv, 1, "", "VA_ASSERTION_VIOLATION:hp-a\n")
        return subprocess.CompletedProcess(argv, 0, "", "VA_ASSERTION_HIT:hp-a\n")

    def _execute(self, assertion, *_args, **_kwargs):
        assertion.status = "VIOLATED"
        return assertion, None

    def _run(self, runner, *, seconds=1, prior_corpus=None,
             prior_corpus_allowlist=None):
        with (patch("vulnerabilityanalysis.assertions.instrument_copy",
                    side_effect=self._instrument),
              patch("vulnerabilityanalysis.assertions._run_assertion_command",
                    side_effect=self._command),
              patch("vulnerabilityanalysis.assertions.execute_assertion",
                    side_effect=self._execute)):
            return guided_fuzz_assertion(
                self.assertion, self.source, 1, self.seed, self.output,
                ["cc", "{source}", "-o", "{binary}"],
                ["{binary}", "{input}"], seconds=seconds,
                guarded_runner=runner, prior_corpus=prior_corpus,
                prior_corpus_allowlist=prior_corpus_allowlist)

    def _receipt(self):
        return json.loads((self.output / "guided_fuzz.json").read_text())

    def test_enveloped_optional_corpus_replay_respects_wall_reservation(self):
        calls = []

        def command(argv, **kwargs):
            calls.append(kwargs.get("process_segment"))
            return self._command(argv, **kwargs)

        def fuzz(_binary, corpus, **_kwargs):
            for index in range(20):
                data = bytes([index + 1])
                (corpus / hashlib.sha1(data).hexdigest()).write_bytes(data)
            return RuntimeResult(0, "", "stat::number_of_executed_units: 20\n",
                                 None, False, None, None, "NONE", coverage={})

        for label, wall_seconds, expected_replays in (
                ("ample", 300, 8), ("short", 15, 0)):
            with self.subTest(label=label):
                calls.clear()
                output = self.root / label
                envelope = SimpleNamespace(
                    deadline_monotonic=time.monotonic() + wall_seconds,
                    cleanup_envelope_seconds=9.5)
                with (patch("vulnerabilityanalysis.assertions.instrument_copy",
                            side_effect=self._instrument),
                      patch("vulnerabilityanalysis.assertions._run_assertion_command",
                            side_effect=command),
                      patch("vulnerabilityanalysis.assertions.fuzz_locally",
                            side_effect=fuzz)):
                    report = guided_fuzz_assertion(
                        self.assertion, self.source, 1, self.seed, output,
                        ["cc", "{source}", "-o", "{binary}"],
                        ["{binary}", "{input}"], seconds=1,
                        process_envelope=envelope)
                self.assertEqual(report["status"], "RAN")
                self.assertEqual(report["replay_sampling_limit"], 8)
                self.assertEqual(report["replayed_inputs"], expected_replays)
                self.assertEqual(calls.count("guided.corpus_replay"), expected_replays)
                self.assertEqual(report["replay_skipped_wall_reservation"],
                                 8 - expected_replays)
                manifest = json.loads((output / "corpus-manifest.json").read_text())
                self.assertEqual(len(manifest), 21)
                if label == "short":
                    self.assertTrue(all(row["assertion_reached"] is None
                                        for row in manifest))

    def test_guided_corpus_retention_stops_before_unbounded_hashing(self):
        def fuzz(_binary, corpus, **_kwargs):
            for index in range(8193):
                data = index.to_bytes(2, "big")
                (corpus / hashlib.sha1(data).hexdigest()).write_bytes(data)
            return RuntimeResult(0, "", "stat::number_of_executed_units: 8193\n",
                                 None, False, None, None, "NONE", coverage={})

        with (patch("vulnerabilityanalysis.assertions.instrument_copy",
                    side_effect=self._instrument),
              patch("vulnerabilityanalysis.assertions._run_assertion_command",
                    side_effect=self._command),
              patch("vulnerabilityanalysis.assertions.fuzz_locally",
                    side_effect=fuzz)):
            report = guided_fuzz_assertion(
                self.assertion, self.source, 1, self.seed, self.output,
                ["cc", "{source}", "-o", "{binary}"],
                ["{binary}", "{input}"], seconds=1)
        self.assertEqual(report["status"], "INCOMPLETE_CORPUS_RETENTION")
        self.assertIn("entry count", report["corpus_retention_reason"])
        self.assertEqual(self._receipt()["status"], report["status"])
        self.assertFalse((self.output / "corpus-manifest.json").exists())

    def test_initial_uses_explicit_runner_and_clean_exit_is_ran(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(
                argv, 0, "", "stat::number_of_executed_units: 1\n")

        report = self._run(runner)
        self.assertEqual(report["status"], "RAN")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["timeout"], 16)
        self.assertEqual(self._receipt()["status"], "RAN")

    def test_continuation_uses_same_runner_after_assertion_witness(self):
        self.initial_violation = True
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(
                argv, 0, "", "stat::number_of_executed_units: 1\n")

        report = self._run(runner, seconds=2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["continuation"]["status"], "RAN")
        self.assertEqual([row["segment"] for row in report["fuzz_segments"]],
                         ["initial", "continuation"])

    def test_initial_prelaunch_pending_is_not_ran_or_launched(self):
        def pending(_argv, **_kwargs):
            raise PhysicalFuzzBudgetPending("no reservation")

        report = self._run(pending)
        self.assertEqual(report["status"], "PENDING_SHARED_PHYSICAL_BUDGET")
        self.assertEqual(report["fuzzer_run_count"], 0)
        self.assertEqual(self._receipt()["status"], report["status"])
        self.assertFalse((self.output / "fuzzer-runtime.json").exists())

    def test_continuation_prelaunch_pending_keeps_initial_artifacts(self):
        self.initial_violation = True
        calls = 0

        def runner(argv, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PhysicalFuzzBudgetPending("second reservation denied")
            return subprocess.CompletedProcess(
                argv, 0, "", "stat::number_of_executed_units: 1\n")

        report = self._run(runner, seconds=2)
        self.assertEqual(calls, 2)
        self.assertNotEqual(report["status"], "RAN")
        self.assertEqual(report["continuation"]["status"],
                         "PENDING_SHARED_PHYSICAL_BUDGET")
        self.assertTrue((self.output / "fuzzer-runtime.json").is_file())
        self.assertTrue((self.output / "corpus-manifest.json").is_file())
        self.assertEqual(self._receipt()["continuation"]["status"],
                         "PENDING_SHARED_PHYSICAL_BUDGET")

    def test_continuation_timeout_is_partial_even_after_real_witness(self):
        self.initial_violation = True
        calls = 0

        def runner(argv, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(
                argv, 0, "", "stat::number_of_executed_units: 1\n")

        report = self._run(runner, seconds=2)
        self.assertEqual(calls, 2)
        self.assertEqual(report["status"], "INCOMPLETE_CONTINUATION")
        self.assertEqual(report["initial_segment_status"], "RAN")
        self.assertEqual(report["continuation"]["status"], "TIMED_OUT")
        self.assertEqual(report["violation_triage"]["assertion_status"], "VIOLATED")

    def test_fatal_initial_stop_keeps_original_exception_and_partial_report(self):
        stop = PhysicalFuzzStop("STOPPED_PHYSICAL_CAP_UNPROVEN", "overrun")

        def stopped(_argv, **_kwargs):
            raise stop

        with self.assertRaises(PhysicalFuzzStop) as caught:
            self._run(stopped)
        self.assertIs(caught.exception, stop)
        self.assertEqual(self._receipt()["status"], stop.status)

    def test_fatal_continuation_cleanup_keeps_original_exception(self):
        self.initial_violation = True
        stop = RuntimeCleanupError("cleanup incomplete", "", "partial")
        calls = 0

        def runner(argv, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise stop
            return subprocess.CompletedProcess(
                argv, 0, "", "stat::number_of_executed_units: 1\n")

        with self.assertRaises(RuntimeCleanupError) as caught:
            self._run(runner, seconds=2)
        self.assertIs(caught.exception, stop)
        self.assertEqual(self._receipt()["status"], "STOPPED_CLEANUP_INCOMPLETE")
        self.assertTrue((self.output / "fuzzer-runtime.json").is_file())

    def test_timeout_or_nonzero_exit_is_not_ran(self):
        for outcome in ("timeout", "exit", "sanitizer_zero_exit"):
            with self.subTest(outcome=outcome):
                self.output = self.root / outcome

                def runner(argv, **kwargs):
                    if outcome == "timeout":
                        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                    if outcome == "sanitizer_zero_exit":
                        return subprocess.CompletedProcess(
                            argv, 0, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n")
                    return subprocess.CompletedProcess(argv, 1, "", "bad exit")

                report = self._run(runner)
                self.assertNotEqual(report["status"], "RAN")
                self.assertNotEqual(self._receipt()["status"], "RAN")
                if outcome == "sanitizer_zero_exit":
                    self.assertEqual(report["status"], "CRASH_OBSERVED_INCOMPLETE")

    def test_guarded_prior_corpus_requires_strict_allowlist(self):
        prior = self.root / "prior"
        prior.mkdir()
        (prior / "initial-seed").write_bytes(b"B")
        with self.assertRaisesRegex(ValueError, "allowlist"):
            self._run(lambda *_args, **_kwargs: self.fail("fuzzer launched"),
                      prior_corpus=prior)

    def test_pending_first_assertion_does_not_unmeter_next_assertion(self):
        run = self.root / "run"
        folder = run / "assertions"
        folder.mkdir(parents=True)
        (run / "run.json").write_text('{"run_id":"hp-physical-pending"}')
        analysis = run / "analysis.json"
        safes = ["n is nonnegative", "n is below ten"]
        analysis.write_text(json.dumps({"function_name": "target",
                                        "safe_assumptions": safes}))
        proposed = [Assertion(f"hp-{index}", "worker", "direction", "target",
                              "target.c:1", safe, "n >= 0", [],
                              source_function_analysis=str(analysis))
                    for index, safe in enumerate(safes)]
        (folder / "proposed.json").write_text(json.dumps(
            [asdict(item) for item in proposed]))
        physical_runner = lambda _argv, **_kwargs: None
        observed = []

        def fake_execute(item, _source, _line, _seed, output, *_args, **_kwargs):
            output.mkdir(parents=True)
            artifact = output / "runtime.json"
            artifact.write_text("{}")
            item.status = "HELD_FOR_EXECUTION"
            item.execution_result = str(artifact)
            return item, None

        def fake_guided(item, _source, _line, _seed, output, *_args, **kwargs):
            observed.append(kwargs.get("guarded_runner"))
            output.mkdir()
            report = {"assertion_id": item.assertion_id,
                      "status": "PENDING_SHARED_PHYSICAL_BUDGET",
                      "fuzzer_run_count": 0}
            (output / "guided_fuzz.json").write_text(json.dumps(report))
            return report

        with (patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                    return_value={"quality": "POSSIBLE", "reasons": []}),
              patch("vulnerabilityanalysis.scan.execute_assertion",
                    side_effect=fake_execute),
              patch("vulnerabilityanalysis.scan.guided_fuzz_assertion",
                    side_effect=fake_guided)):
            outcomes = run_assertions_for_scan(
                run, self.source, self.seed, ["cc", "{source}", "-o", "{binary}"],
                ["{binary}", "{input}"], fuzz_seconds=1,
                guarded_runner=physical_runner)
        self.assertEqual(observed, [physical_runner, physical_runner])
        self.assertEqual([item.status for item in outcomes],
                         ["HELD_FOR_EXECUTION", "HELD_FOR_EXECUTION"])
        self.assertEqual(len(json.loads((folder / "results.json").read_text())), 2)


if __name__ == "__main__":
    unittest.main()
