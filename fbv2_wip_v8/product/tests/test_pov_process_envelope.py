"""Opt-in PoV process accounting at the product Runtime boundary."""

import hashlib
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.final_verification import independent_replay
from vulnerabilityanalysis.models import FixedPoC, PoC, SuspiciousPoint
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop
from vulnerabilityanalysis.scan import execute_poc


class RecordingEnvelope:
    output_limit_bytes = 4096

    def __init__(self, limit: int):
        self.limit = limit
        self.deadline_monotonic = time.monotonic() + 60
        self.reservations = []
        self.settlements = []

    def before_process(self, command, *, cwd, env, timeout, kind, segment):
        if len(self.reservations) >= self.limit:
            raise ProcessEnvelopeStop("PENDING_PROCESS_BUDGET", "physical process budget exhausted")
        lease = len(self.reservations)
        self.reservations.append((lease, tuple(command), kind, segment))
        return lease

    def after_process(self, lease, *, elapsed_seconds, cleanup_complete,
                      output_limited, error):
        self.settlements.append((lease, cleanup_complete, output_limited, error))


def _point() -> SuspiciousPoint:
    return SuspiciousPoint(
        "sp-1", "worker", "direction", "parse", "src/parser.c", "src/parser.c:42",
        "indexed read", "heap buffer overflow", ["input index too large"],
        "input controls index", [], [], [], [], security_property="memory safety")


def _fixed(input_path: Path) -> FixedPoC:
    binary = Path(sys.executable)
    return FixedPoC(
        "p-1", "sp-1", str(input_path), "", str(binary),
        [str(binary), "{input}"], "AddressSanitizer: heap-buffer-overflow",
        "heap-buffer-overflow", "parse:src/parser.c:42", "indexed read",
        hashlib.sha256(input_path.read_bytes()).hexdigest(),
        hashlib.sha256(binary.read_bytes()).hexdigest())


class PoVEnvelopeTest(unittest.TestCase):
    def test_primary_execution_reserves_then_settles_one_physical_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"normal")
            poc = PoC("p-1", "sp-1", "", str(seed),
                      [sys.executable, "{input}"], "crash")
            envelope = RecordingEnvelope(1)
            events = []

            def launch(command, **kwargs):
                events.append((len(envelope.reservations), kwargs["output_limit_bytes"]))
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("vulnerabilityanalysis.runtime._guarded_run_once", side_effect=launch):
                execute_poc(poc, _point(), poc.run_command, root / "run",
                            process_envelope=envelope)
            self.assertEqual(events, [(1, 4096)])
            self.assertEqual([row[3] for row in envelope.reservations],
                             ["pov.primary_execution"])
            self.assertEqual([row[0] for row in envelope.settlements], [0])
            self.assertTrue(envelope.settlements[0][1])

    def test_independent_replay_cannot_launch_after_budget_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"normal")
            fixed = _fixed(seed)
            envelope = RecordingEnvelope(1)
            launches = []

            def launch(command, **kwargs):
                launches.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("vulnerabilityanalysis.runtime._guarded_run_once", side_effect=launch):
                result = independent_replay(fixed, root / "replay-1",
                                            process_envelope=envelope)
                self.assertEqual(result.status, "NOT_REPRODUCED")
                with self.assertRaises(ProcessEnvelopeStop) as rejected:
                    independent_replay(fixed, root / "replay-2",
                                       process_envelope=envelope)
            self.assertEqual(rejected.exception.status, "PENDING_PROCESS_BUDGET")
            self.assertEqual(len(launches), 1)
            self.assertEqual([row[3] for row in envelope.reservations],
                             ["pov.independent_replay"])
            self.assertEqual(len(envelope.settlements), 1)
            self.assertFalse((root / "replay-2" / "validation.json").exists())

    def test_primary_charge_exhausts_shared_budget_before_independent_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"normal")
            poc = PoC("p-1", "sp-1", "", str(seed),
                      [sys.executable, "{input}"], "crash")
            fixed = _fixed(seed)
            envelope = RecordingEnvelope(1)
            with patch("vulnerabilityanalysis.runtime._guarded_run_once") as launch:
                launch.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(
                    command, 0, "", "")
                execute_poc(poc, _point(), poc.run_command, root / "primary",
                            process_envelope=envelope)
                with self.assertRaises(ProcessEnvelopeStop):
                    independent_replay(fixed, root / "replay",
                                       process_envelope=envelope)
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(len(envelope.reservations), 1)
            self.assertEqual(len(envelope.settlements), 1)
            self.assertFalse((root / "replay" / "validation.json").exists())

    def test_unmetered_probe_and_direct_qualification_are_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"normal")
            for option, value in (
                ("trace_reachability", True),
                ("auto_input_receipt", True),
                ("direct_qualification", object()),
            ):
                with self.subTest(option=option):
                    poc = PoC("p-1", "sp-1", "", str(seed),
                              [sys.executable, "{input}"], "crash")
                    envelope = RecordingEnvelope(1)
                    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as launch:
                        with self.assertRaisesRegex(ValueError, "unmetered"):
                            execute_poc(poc, _point(), poc.run_command, root / option,
                                        process_envelope=envelope, **{option: value})
                    launch.assert_not_called()
                    self.assertEqual(envelope.reservations, [])

    def test_official_qualification_is_admissible_with_bounded_primary_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"normal")
            poc = PoC("p-1", "sp-1", "", str(seed),
                      [sys.executable, "{input}"], "crash")
            envelope = RecordingEnvelope(1)
            with patch("vulnerabilityanalysis.runtime._guarded_run_once") as launch:
                launch.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(
                    command, 0, "", "")
                execute_poc(poc, _point(), poc.run_command, root / "run",
                            official_qualification=object(), process_envelope=envelope)
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(len(envelope.settlements), 1)

    def test_unbounded_replay_uses_clean_environment_without_envelope_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.bin"
            seed.write_bytes(b"normal")
            fixed = _fixed(seed)
            with patch("vulnerabilityanalysis.final_verification.RuntimeExecutor.run") as run:
                from vulnerabilityanalysis.models import RuntimeResult
                run.return_value = RuntimeResult(0, "", "", None, False, None, None,
                                                 "CLEAN_EXIT")
                independent_replay(fixed, root / "replay")
            self.assertEqual(len(run.call_args.args), 2)
            # Goal A.1.1 (F9): the replay always pins its sanitizer environment;
            # the unbounded call still carries no process-envelope arguments.
            from vulnerabilityanalysis.final_verification import REPLAY_ASAN_OPTIONS
            self.assertEqual(run.call_args.kwargs,
                             {"extra_env": {"ASAN_OPTIONS": REPLAY_ASAN_OPTIONS},
                              "inherit_environment": False})


if __name__ == "__main__":
    unittest.main()
