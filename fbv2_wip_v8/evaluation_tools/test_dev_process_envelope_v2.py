"""Provider-free Stage17a tests for product process-envelope seams."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis import assertions, runtime
from vulnerabilityanalysis.models import Assertion

from dev_persistent_physical_fuzz_ledger import PhysicalBudgetExhausted
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
import dev_blind3_official_assertion_execution as stage16
import dev_blind3_official_assertion_handoff as stage15
import test_dev_blind3_official_assertion_execution as stage16_fixture
from dev_blind3_official_interleaved_adapter import sha256


class ProcessEnvelopeV2Tests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ledger = PersistentProcessLedgerV2.create(
            self.root / "process-v2.json", wall_total_seconds=100,
            fuzz_total_seconds=50)

    def envelope(self, *, limit: int = 1024, hook=None, attempt: str = "a1",
                 wall: float = 100) -> DevelopmentProcessEnvelopeV2:
        return DevelopmentProcessEnvelopeV2(
            self.ledger, work_item_id="work-1", assertion_id="assert-1",
            attempt_id=attempt, output_limit_bytes=limit,
            total_wall_seconds=wall, pin_hook=hook or (lambda phase, argv: None))

    @staticmethod
    def command(source: str, *args: str) -> list[str]:
        return [sys.executable, "-I", "-c", source, *args]

    def synthetic_assertion_inputs(self, *, prior_tag: str | None = None):
        source = self.root / "synthetic.c"
        source.write_text("int synthetic(int n) {\n  int x = n;\n  return x;\n}\n")
        seed = self.root / "seed"
        seed.write_bytes(b"harmless")
        binary_body = (f"#!{sys.executable}\nimport sys\n"
                       "print('16 Extra Counters',file=sys.stderr)\n")
        if prior_tag is not None:
            binary_body += f"print('VA_ASSERTION_VIOLATION:{prior_tag}',file=sys.stderr)\n"
        compiler = self.root / "synthetic-compiler"
        compiler.write_text(
            f"#!{sys.executable}\nimport pathlib,sys\n"
            "if '-fsyntax-only' in sys.argv: sys.exit(0)\n"
            "out=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
            f"out.write_text({binary_body!r});out.chmod(0o700)\n")
        compiler.chmod(0o700)
        assertion = Assertion("synthetic-a", "worker", "direction", "synthetic",
                              f"{source}:2", "n >= 0", "n >= 0", [])
        return (source, seed, compiler, assertion)

    def test_product_assertion_alias_and_fuzz_share_one_v2_ledger(self):
        envelope = self.envelope()
        done = assertions._run_assertion_command(
            self.command("print('built')"), timeout=1,
            process_envelope=envelope, process_segment="build")
        self.assertEqual(done.stdout.strip(), "built")
        # This is the runtime path used by fuzz_locally when V2 is selected;
        # the synthetic command itself has no target or fuzzer capability.
        runtime._guarded_run(self.command("print('campaign')"), timeout=1,
                             process_envelope=envelope, process_kind="HP_FUZZ",
                             process_segment="guided.initial")
        snapshot = self.ledger.snapshot()
        self.assertEqual([row["kind"] for row in snapshot["finished"]],
                         ["AUX_PROCESS", "HP_FUZZ"])
        self.assertEqual(len({row["key"] for row in snapshot["finished"]}), 2)
        self.assertGreater(snapshot["wall_spent_seconds"],
                           snapshot["fuzz_spent_seconds"])
        self.assertEqual(snapshot["fuzz_spent_seconds"],
                         snapshot["finished"][1]["physical_seconds"])

    def test_execute_assertion_synthetic_build_and_replay_are_all_accounted(self):
        source, seed, compiler, assertion = self.synthetic_assertion_inputs()
        envelope = self.envelope()
        result, _ = assertions.execute_assertion(
            assertion, source, 2, seed, self.root / "assertion-out",
            [str(compiler), "{source}", "-o", "{binary}"],
            ["{binary}", "{input}"], timeout_seconds=1,
            process_envelope=envelope)
        self.assertNotEqual(result.status, "ERROR")
        rows = self.ledger.snapshot()["finished"]
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["key"].rsplit(":", 1)[-1] for row in rows],
                         ["assertion.instrumented_syntax",
                          "assertion.instrumented_build",
                          "assertion.instrumented_seed_replay"])
        self.assertTrue(all(row["kind"] == "AUX_PROCESS" for row in rows))

    def test_guided_synthetic_build_probe_campaign_replay_share_envelope(self):
        source, seed, compiler, assertion = self.synthetic_assertion_inputs()
        envelope = self.envelope()
        report = assertions.guided_fuzz_assertion(
            assertion, source, 2, seed, self.root / "guided-out",
            [str(compiler), "{source}", "-o", "{binary}"],
            ["{binary}", "{input}"], seconds=1,
            process_envelope=envelope)
        self.assertEqual(report["status"], "RAN")
        rows = self.ledger.snapshot()["finished"]
        self.assertEqual(sum(row["kind"] == "HP_FUZZ" for row in rows), 1)
        self.assertIn("guided.initial_campaign", [
            row["key"].rsplit(":", 1)[-1] for row in rows])
        self.assertGreaterEqual(len(rows), 4)
        self.assertEqual(self.ledger.snapshot()["stop_status"], None)

    def test_guided_prior_phi_reentry_reuses_the_same_envelope(self):
        source, seed, compiler, assertion = self.synthetic_assertion_inputs(
            prior_tag="prior-a")
        prior = Assertion("prior-a", "worker", "direction", "synthetic",
                          f"{source}:3", "n >= 0", "n >= 0", [])
        envelope = self.envelope()
        seen = []

        def fake_nested(*args, **kwargs):
            seen.append(kwargs.get("process_envelope"))
            return prior, None

        with patch.object(assertions, "execute_assertion", side_effect=fake_nested):
            assertions.guided_fuzz_assertion(
                assertion, source, 2, seed, self.root / "guided-prior",
                [str(compiler), "{source}", "-o", "{binary}"],
                ["{binary}", "{input}"], seconds=1,
                prior_phi_assertions=[prior], process_envelope=envelope)
        self.assertEqual(seen, [envelope])

    def test_gdb_dwarf_and_trace_both_receive_same_envelope(self):
        source, seed, _compiler, _assertion = self.synthetic_assertion_inputs()
        binary = self.root / "dummy-elf"
        binary.write_bytes(b"not executed")
        sentinel = object()
        observed = []

        def fake_gdb(argv, **kwargs):
            observed.append((argv, kwargs))
            output = str(source) if "info sources" in argv else ""
            return subprocess.CompletedProcess(argv, 0, output, "")

        with patch.object(runtime, "_guarded_run", side_effect=fake_gdb):
            runtime.trace_sp_location(binary, seed, f"{source}:2",
                                      process_envelope=sentinel)
        self.assertEqual(len(observed), 2)
        self.assertEqual([row[1]["process_segment"] for row in observed],
                         ["assertion.gdb_source_inventory",
                          "assertion.gdb_state_trace"])
        self.assertTrue(all(row[1]["process_envelope"] is sentinel
                            for row in observed))

    def test_v1_guarded_runner_and_v2_envelope_cannot_double_reserve(self):
        with self.assertRaisesRegex(ValueError, "cannot both reserve"):
            runtime.fuzz_locally(self.root / "unused", self.root / "corpus",
                                 guarded_runner=lambda *args, **kwargs: None,
                                 process_envelope=self.envelope())
        self.assertEqual(self.ledger.snapshot()["finished"], [])

    def test_stdout_stderr_combined_cap_and_cap_plus_one(self):
        good = self.envelope(limit=100)
        runtime._guarded_run(self.command(
            "import sys;sys.stderr.write('E'*40);sys.stdout.write('O'*60)"),
            timeout=1, process_envelope=good, process_segment="exact_cap")
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(self.command(
                "import sys;sys.stderr.write('E'*40);sys.stdout.write('O'*61)"),
                timeout=1, process_envelope=good, process_segment="over_cap")
        self.assertEqual(captured.exception.status, "STOPPED_OUTPUT_LIMIT")
        partial = captured.exception.__cause__
        self.assertIsInstance(partial, runtime.RuntimeOutputLimitError)
        self.assertEqual(len(partial.stderr.encode()) +
                         len(partial.stdout.encode()), 100)
        self.assertEqual(partial.stderr_total_bytes, 40)
        self.assertEqual(partial.stdout_total_bytes, 61)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_OUTPUT_LIMIT")
        with self.assertRaises(RuntimeError):
            runtime._guarded_run(self.command("pass"), timeout=1,
                                 process_envelope=good, process_segment="blocked")

    def test_stderr_cap_plus_one_keeps_early_sanitizer_only_as_partial(self):
        envelope = self.envelope(limit=100)
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(self.command(
                "import sys;sys.stderr.write('ERROR: AddressSanitizer: synthetic\\n'+'Z'*200)"),
                timeout=1, process_envelope=envelope,
                process_segment="large_stderr")
        partial = captured.exception.__cause__
        self.assertIsInstance(partial, runtime.RuntimeOutputLimitError)
        self.assertIn("AddressSanitizer: synthetic", partial.stderr)
        self.assertEqual(len(partial.stderr.encode()), 100)
        self.assertEqual(partial.stdout_total_bytes, -1)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_OUTPUT_LIMIT")

    def test_output_leaf_symlink_is_rejected_without_reading_other_file(self):
        secret = self.root / "secret"
        secret.write_text("DO_NOT_READ_ME")
        source = (
            "import os,pathlib,sys;"
            "parts=pathlib.Path('/proc/'+str(os.getppid())+'/cmdline').read_bytes().split(b'\\0');"
            "path=pathlib.Path(parts[7].decode());"
            "path.unlink();path.symlink_to(sys.argv[1])"
        )
        envelope = self.envelope()
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(self.command(source, str(secret)), timeout=1,
                                 process_envelope=envelope,
                                 process_segment="output_symlink")
        self.assertIsInstance(captured.exception.__cause__,
                              runtime.RuntimeOutputIntegrityError)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_CLEANUP_INCOMPLETE")
        self.assertEqual(secret.read_text(), "DO_NOT_READ_ME")

    def test_regular_output_inode_replacement_is_rejected(self):
        source = (
            "import os,pathlib;"
            "parts=pathlib.Path('/proc/'+str(os.getppid())+'/cmdline').read_bytes().split(b'\\0');"
            "path=pathlib.Path(parts[7].decode());"
            "path.unlink();path.write_text('replacement');path.chmod(0o600)"
        )
        envelope = self.envelope()
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(self.command(source), timeout=1,
                                 process_envelope=envelope,
                                 process_segment="output_inode_swap")
        self.assertIsInstance(captured.exception.__cause__,
                              runtime.RuntimeOutputIntegrityError)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_CLEANUP_INCOMPLETE")

    def test_private_output_does_not_change_target_umask(self):
        marker = self.root / "target-file"
        source = (
            "import os,sys;"
            "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o666);"
            "os.write(fd,b'ok');os.close(fd)"
        )
        previous = os.umask(0o022)
        try:
            runtime._guarded_run(self.command(source, str(marker)), timeout=1,
                                 process_envelope=self.envelope(),
                                 process_segment="umask_boundary")
        finally:
            os.umask(previous)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o644)

    def test_missing_helper_output_identity_is_rejected_before_read(self):
        without_ids = runtime._RUNTIME_SUBREAPER.replace(
            "if output_ids is not None:", "if False and output_ids is not None:")
        self.assertNotEqual(without_ids, runtime._RUNTIME_SUBREAPER)
        envelope = self.envelope()
        with patch.object(runtime, "_RUNTIME_SUBREAPER", without_ids):
            with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
                runtime._guarded_run(self.command("print('private')"), timeout=1,
                                     process_envelope=envelope,
                                     process_segment="missing_ids")
        self.assertIsInstance(captured.exception.__cause__,
                              runtime.RuntimeOutputIntegrityError)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_CLEANUP_INCOMPLETE")

    def test_timeout_is_charged_once_and_after_pin_stop_is_fatal(self):
        calls = []
        def hook(phase, argv):
            calls.append(phase)
            if phase == "after_process":
                raise ValueError("post pin changed")
        envelope = self.envelope(hook=hook)
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(self.command("import time;time.sleep(2)"),
                                 timeout=.05, process_envelope=envelope,
                                 process_segment="timeout")
        self.assertEqual(captured.exception.status, "STOPPED_PIN_DRIFT")
        self.assertIsInstance(captured.exception.__cause__, subprocess.TimeoutExpired)
        self.assertEqual(len(self.ledger.snapshot()["finished"]), 1)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_PIN_DRIFT")
        self.assertEqual(calls.count("after_process"), 1)

    def test_unproven_cleanup_is_fatal_with_partial_cause(self):
        envelope = self.envelope()
        original = runtime.RuntimeCleanupError("synthetic cleanup", "", "partial")
        with patch.object(runtime, "_guarded_run_once", side_effect=original):
            with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
                runtime._guarded_run(self.command("pass"), timeout=1,
                                     process_envelope=envelope,
                                     process_segment="cleanup_failure")
        self.assertEqual(captured.exception.status,
                         "STOPPED_CLEANUP_INCOMPLETE")
        self.assertIs(captured.exception.__cause__, original)
        self.assertEqual(self.ledger.snapshot()["finished"][0]
                         ["cleanup_complete"], False)

    def test_helper_all_three_waits_timeout_stops_and_closes_status_fd(self):
        class NeverReaped:
            def __init__(self):
                self.terminated = self.killed = False
            def wait(self, timeout):
                raise subprocess.TimeoutExpired(["synthetic-helper"], timeout)
            def terminate(self):
                self.terminated = True
            def kill(self):
                self.killed = True
        helper = NeverReaped()
        opened = []
        original_pipe = os.pipe
        def tracked_pipe():
            pair = original_pipe()
            opened.append(pair)
            return pair
        with (patch.object(runtime.os, "pipe", side_effect=tracked_pipe),
              patch.object(runtime.subprocess, "Popen", return_value=helper)):
            with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
                runtime._guarded_run(self.command("pass"), timeout=.1,
                                     process_envelope=self.envelope(),
                                     process_segment="unreaped_helper")
        self.assertEqual(captured.exception.status,
                         "STOPPED_CLEANUP_INCOMPLETE")
        self.assertIsInstance(captured.exception.__cause__,
                              runtime.RuntimeCleanupError)
        self.assertTrue(helper.terminated and helper.killed)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0][0])
        self.assertEqual(self.ledger.snapshot()["finished"][0]
                         ["cleanup_complete"], False)

    def test_uncertain_helper_launch_exception_is_not_a_clean_start_error(self):
        with patch.object(runtime.subprocess, "Popen", side_effect=KeyboardInterrupt):
            with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
                runtime._guarded_run(self.command("pass"), timeout=1,
                                     process_envelope=self.envelope(),
                                     process_segment="uncertain_launch")
        self.assertEqual(captured.exception.status,
                         "STOPPED_CLEANUP_INCOMPLETE")
        self.assertIsInstance(captured.exception.__cause__,
                              runtime.RuntimeCleanupError)
        self.assertIsInstance(captured.exception.__cause__.__cause__, KeyboardInterrupt)

    def test_setsid_descendant_is_reaped_and_charged_once(self):
        marker = self.root / "descendant.pid"
        source = (
            "import pathlib,subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid))"
        )
        runtime._guarded_run(self.command(source, str(marker)), timeout=1,
                             process_envelope=self.envelope(),
                             process_segment="detached_descendant")
        pid = int(marker.read_text())
        self.assertFalse(Path(f"/proc/{pid}").exists())
        self.assertEqual(len(self.ledger.snapshot()["finished"]), 1)
        self.assertEqual(self.ledger.snapshot()["stop_status"], None)

    def test_global_diagnostic_uses_same_fuzz_budget(self):
        done = runtime._guarded_run(
            self.command("print('bounded')"), timeout=1,
            process_envelope=self.envelope(), process_kind="GLOBAL_FUZZ",
            process_segment="global_diagnostic")
        self.assertEqual(done.stdout.strip(), "bounded")
        snapshot = self.ledger.snapshot()
        self.assertEqual(len(snapshot["finished"]), 1)
        self.assertEqual(snapshot["finished"][0]["kind"], "GLOBAL_FUZZ")
        self.assertGreater(snapshot["fuzz_spent_seconds"], 0)
        self.assertEqual(snapshot["active"], {})

    def test_overrun_cannot_return_success(self):
        envelope = self.envelope()
        lease = envelope.before_process(self.command("pass"), cwd=None, env=None,
                                        timeout=.1, kind="AUX_PROCESS",
                                        segment="overrun")
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            envelope.after_process(lease, elapsed_seconds=10, cleanup_complete=True,
                                   output_limited=False, error=None)
        self.assertEqual(captured.exception.status,
                         "STOPPED_PHYSICAL_CAP_UNPROVEN")
        self.assertEqual(self.ledger.snapshot()["finished"][0]["overrun"], True)

    def test_timeout_with_ledger_overrun_remains_fatal_stop(self):
        envelope = self.envelope()
        lease = envelope.before_process(self.command("pass"), cwd=None, env=None,
                                        timeout=.1, kind="AUX_PROCESS",
                                        segment="timeout_overrun")
        original = subprocess.TimeoutExpired([sys.executable], .1)
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            envelope.after_process(lease, elapsed_seconds=10,
                                   cleanup_complete=True, output_limited=False,
                                   error=original)
        self.assertEqual(captured.exception.status,
                         "STOPPED_PHYSICAL_CAP_UNPROVEN")

    def test_start_error_with_post_pin_stop_is_not_normalized(self):
        def hook(phase, argv):
            if phase == "after_process":
                raise ValueError("binary changed")
        envelope = self.envelope(hook=hook)
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run([str(self.root / "missing-program")], timeout=1,
                                 process_envelope=envelope,
                                 process_segment="missing_start")
        self.assertEqual(captured.exception.status, "STOPPED_PIN_DRIFT")
        self.assertIsInstance(captured.exception.__cause__, runtime.RuntimeStartError)

    def test_active_restore_blocks_automatic_resend(self):
        envelope = self.envelope()
        envelope.before_process(self.command("pass"), cwd=None, env=None,
                                timeout=1, kind="AUX_PROCESS", segment="armed")
        restored = PersistentProcessLedgerV2.restore(
            self.ledger.path, wall_total_seconds=100, fuzz_total_seconds=50)
        self.assertEqual(restored.snapshot()["stop_status"],
                         "STOPPED_UNCERTAIN_PROCESS")
        with self.assertRaises(RuntimeError):
            DevelopmentProcessEnvelopeV2(
                restored, work_item_id="work-1", assertion_id="assert-1",
                attempt_id="a1", output_limit_bytes=1024,
                total_wall_seconds=100, pin_hook=lambda phase, argv: None)

    def test_prelaunch_pin_drift_has_no_process_and_stops_ledger(self):
        def hook(phase, argv):
            if phase == "before_reserve":
                raise ValueError("builder changed")
        envelope = self.envelope(hook=hook)
        marker = self.root / "started"
        with self.assertRaises(runtime.ProcessEnvelopeStop):
            runtime._guarded_run(self.command(
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('yes')",
                str(marker)), timeout=1, process_envelope=envelope,
                process_segment="pin_drift")
        self.assertFalse(marker.exists())
        self.assertEqual(self.ledger.snapshot()["finished"], [])
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_PIN_DRIFT")

    def test_mutating_original_argv_env_and_cwd_alias_after_pin_changes_nothing(self):
        first = self.root / "first"
        second = self.root / "second"
        first.mkdir()
        second.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(first, target_is_directory=True)
        argv = self.command(
            "import os,sys;print(sys.argv[1]);print(os.getenv('STAGE17_PIN'));print(os.getcwd())",
            "original")
        environment = dict(os.environ)
        environment["STAGE17_PIN"] = "original"
        seen = []

        def hook(phase, pinned_argv):
            seen.append((phase, tuple(pinned_argv)))
            if phase == "after_reserve_before_launch":
                argv[-1] = "changed"
                argv[3] = "print('changed script')"
                environment["STAGE17_PIN"] = "changed"
                alias.unlink()
                alias.symlink_to(second, target_is_directory=True)
                pinned_argv[3] = "print('hook changed script')"

        done = runtime._guarded_run(
            argv, cwd=alias, env=environment, timeout=1,
            process_envelope=self.envelope(hook=hook),
            process_segment="snapshot_explicit")
        self.assertEqual(done.stdout.splitlines(),
                         ["original", "original", str(first)])
        self.assertEqual(seen[0][1], seen[-1][1])

    def test_implicit_env_and_cwd_are_snapshotted_before_pin(self):
        first = self.root / "implicit-first"
        second = self.root / "implicit-second"
        first.mkdir()
        second.mkdir()
        previous_cwd = Path.cwd()
        previous_value = os.environ.get("STAGE17_IMPLICIT_PIN")
        os.chdir(first)
        os.environ["STAGE17_IMPLICIT_PIN"] = "original"
        try:
            def hook(phase, argv):
                if phase == "after_reserve_before_launch":
                    os.chdir(second)
                    os.environ["STAGE17_IMPLICIT_PIN"] = "changed"
            done = runtime._guarded_run(self.command(
                "import os;print(os.getenv('STAGE17_IMPLICIT_PIN'));print(os.getcwd())"),
                timeout=1, process_envelope=self.envelope(hook=hook),
                process_segment="snapshot_implicit")
            self.assertEqual(done.stdout.splitlines(), ["original", str(first)])
        finally:
            os.chdir(previous_cwd)
            if previous_value is None:
                os.environ.pop("STAGE17_IMPLICIT_PIN", None)
            else:
                os.environ["STAGE17_IMPLICIT_PIN"] = previous_value

    def test_cwd_directory_inode_swap_after_reservation_never_starts_child(self):
        safe = self.root / "work"
        evil = self.root / "evil"
        safe.mkdir()
        evil.mkdir()
        (safe / "identity").write_text("SAFE")
        (evil / "identity").write_text("EVIL")
        marker = self.root / "child-started"

        def hook(phase, _argv):
            if phase == "after_reserve_before_launch":
                safe.rename(self.root / "safe-old")
                evil.rename(safe)

        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(
                self.command(
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("
                    "pathlib.Path('identity').read_text())", str(marker)),
                cwd=safe, timeout=1, process_envelope=self.envelope(hook=hook),
                process_segment="cwd_inode_swap")
        self.assertEqual(captured.exception.status,
                         "STOPPED_CLEANUP_INCOMPLETE")
        self.assertIsInstance(captured.exception.__cause__,
                              runtime.RuntimeCleanupError)
        self.assertFalse(marker.exists())
        snapshot = self.ledger.snapshot()
        self.assertEqual(len(snapshot["finished"]), 1)
        self.assertFalse(snapshot["finished"][0]["cleanup_complete"])
        self.assertEqual(snapshot["stop_status"], "STOPPED_CLEANUP_INCOMPLETE")

    def test_wall_deadline_rejects_before_process(self):
        envelope = self.envelope(wall=.01)
        marker = self.root / "started"
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            runtime._guarded_run(self.command(
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('yes')",
                str(marker)), timeout=1, process_envelope=envelope,
                process_segment="no_wall")
        self.assertEqual(captured.exception.status, "STOPPED_WALL_LIMIT")
        self.assertFalse(marker.exists())
        self.assertEqual(self.ledger.snapshot()["finished"], [])

    def test_post_process_wall_expiry_is_charged_and_fatal(self):
        envelope = self.envelope()
        lease = envelope.before_process(self.command("pass"), cwd=None, env=None,
                                        timeout=1, kind="AUX_PROCESS",
                                        segment="late_finish")
        envelope.deadline_monotonic = time.monotonic() - 1
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            envelope.after_process(lease, elapsed_seconds=.1,
                                   cleanup_complete=True, output_limited=False,
                                   error=None)
        self.assertEqual(captured.exception.status, "STOPPED_WALL_LIMIT")
        self.assertEqual(len(self.ledger.snapshot()["finished"]), 1)
        self.assertEqual(self.ledger.snapshot()["stop_status"],
                         "STOPPED_WALL_LIMIT")

    def test_local_wall_deadline_is_charged_without_global_stop(self):
        envelope = DevelopmentProcessEnvelopeV2(
            self.ledger, work_item_id="local-work",
            assertion_id="local-assertion", attempt_id="local-attempt",
            output_limit_bytes=1024, total_wall_seconds=100,
            pin_hook=lambda _phase, _command: None,
            wall_limit_scope="LOCAL")
        lease = envelope.before_process(
            self.command("pass"), cwd=None, env=None, timeout=1,
            kind="AUX_PROCESS", segment="local_gate")
        envelope.deadline_monotonic = time.monotonic() - 1
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            envelope.after_process(
                lease, elapsed_seconds=.1, cleanup_complete=True,
                output_limited=False, error=None)
        self.assertEqual(captured.exception.status,
                         "STOPPED_LOCAL_WALL_LIMIT")
        snapshot = self.ledger.snapshot()
        self.assertEqual(len(snapshot["finished"]), 1)
        self.assertIsNone(snapshot["stop_status"])

    def test_local_wall_prelaunch_rejection_does_not_stop_shared_ledger(self):
        envelope = DevelopmentProcessEnvelopeV2(
            self.ledger, work_item_id="local-prelaunch",
            assertion_id="local-assertion", attempt_id="local-attempt",
            output_limit_bytes=1024, total_wall_seconds=.01,
            pin_hook=lambda _phase, _command: None,
            wall_limit_scope="LOCAL")
        with self.assertRaises(runtime.ProcessEnvelopeStop) as captured:
            envelope.before_process(
                self.command("pass"), cwd=None, env=None, timeout=1,
                kind="AUX_PROCESS", segment="local_gate_prelaunch")
        self.assertEqual(captured.exception.status,
                         "STOPPED_LOCAL_WALL_LIMIT")
        self.assertEqual(self.ledger.snapshot()["finished"], [])
        self.assertIsNone(self.ledger.snapshot()["stop_status"])

    def test_fuzz_cap_exhaustion_does_not_consume_aux_account(self):
        limited = PersistentProcessLedgerV2.create(
            self.root / "small-fuzz.json", wall_total_seconds=50,
            fuzz_total_seconds=1)
        limited.reserve("aux:1", "AUX_PROCESS", 2)
        limited.finish("aux:1", physical_seconds=.1,
                       cleanup_complete=True)
        with self.assertRaises(PhysicalBudgetExhausted):
            limited.reserve("fuzz:1", "HP_FUZZ", 2)
        self.assertEqual(limited.snapshot()["fuzz_spent_seconds"], 0)

    def test_official_v2_pins_guard_only_a_synthetic_process(self):
        legacy_receipt = (Path(__file__).resolve().parents[1] / "review" /
                          "STAGE7_OFFICIAL_PHASE1_20261031" /
                          "STAGE7_PROVIDER_FREE_RECEIPT.json")
        if not legacy_receipt.is_file():
            self.skipTest("legacy Blind3 Stage7 fixture receipt is not present")
        fixture = stage16_fixture.OfficialAssertionExecutionStage16Tests(
            "test_synthetic_signatures_share_hp_ledger_without_target")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        handoff_sha = sha256(fixture.handoff_path)
        model_sha = sha256(fixture.adapter.ledger.checkpoint_path)
        v1_physical_sha = sha256(fixture.adapter.physical_ledger.path)
        state = fixture.adapter.read()
        work_item_id = state["work_items"][0]["work_item_id"]
        proposal = Path(state["role_turns"][-1]["artifact_path"])
        assertion_id = __import__("json").loads(proposal.read_text())[
            "assertions"][0]["assertion_id"]
        v2 = PersistentProcessLedgerV2.create(
            fixture.fixture.fixture.fixture.root / "stage17-process-v2.json",
            wall_total_seconds=50, fuzz_total_seconds=20)
        checks = []

        def pinned(phase: str, command: list[str]) -> None:
            stage16.load_wiring_contract(
                fixture.path, fixture.contract_sha, fixture.adapter)
            stage15.load_execution_contract(
                fixture.fixture.contract_path,
                fixture.fixture.contract_sha, fixture.adapter)
            current = fixture.adapter.read()
            if (current["work_items"][0]["work_item_id"] != work_item_id or
                    current["work_items"][0]["hp_state"] !=
                    "PENDING_ASSERTION_EXECUTION" or
                    sha256(fixture.handoff_path) != handoff_sha):
                raise ValueError("official V2 Work Item pin changed")
            checks.append(phase)

        envelope = DevelopmentProcessEnvelopeV2(
            v2, work_item_id=work_item_id, assertion_id=assertion_id,
            attempt_id="stage17a-synthetic", output_limit_bytes=128,
            total_wall_seconds=50, pin_hook=pinned)
        result = assertions._run_assertion_command(
            self.command("print('provider-free')"), timeout=1,
            process_envelope=envelope,
            process_segment="official_v2.synthetic_probe")
        self.assertEqual(result.stdout.strip(), "provider-free")
        self.assertEqual(checks,
                         ["before_reserve", "after_reserve_before_launch",
                          "after_process"])
        self.assertEqual(len(v2.snapshot()["finished"]), 1)
        self.assertEqual(sha256(fixture.handoff_path), handoff_sha)
        self.assertEqual(sha256(fixture.adapter.ledger.checkpoint_path), model_sha)
        self.assertEqual(sha256(fixture.adapter.physical_ledger.path),
                         v1_physical_sha)
        self.assertEqual(fixture.adapter.read()["scan_count"], 0)


if __name__ == "__main__":
    unittest.main()
