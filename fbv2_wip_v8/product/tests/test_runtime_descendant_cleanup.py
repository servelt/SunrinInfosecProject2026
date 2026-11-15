"""Process lifecycle regressions for local replay, without a real target."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.runtime import (RuntimeCleanupError, RuntimeExecutor,
                                          _guarded_run, fuzz_locally, fuzz_process_harness)


def state(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0]
    except OSError:
        return None


def stopped(pid: int, seconds: float = 3) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if state(pid) in (None, "Z", "X"):
            return True
        time.sleep(0.025)
    return state(pid) in (None, "Z", "X")


class RuntimeDescendantCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed = self.root / "seed.bin"
        self.seed.write_bytes(b"normal")
        self.pids: list[int] = []
        self.addCleanup(self.cleanup_pids)

    def cleanup_pids(self):
        for pid in self.pids:
            if state(pid) not in (None, "Z", "X"):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def command(self, marker: Path, *, wait: bool, inherit: bool) -> list[str]:
        script = (
            "import subprocess,sys,time,pathlib\n"
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
            "start_new_session=True,"
            f"stdout={'None' if inherit else 'subprocess.DEVNULL'},"
            f"stderr={'None' if inherit else 'subprocess.DEVNULL'})\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(p.pid))\n"
            "print('ERROR: AddressSanitizer: heap-use-after-free\\n'"
            "+'#0 0x1 in parse /tmp/source.c:9',file=sys.stderr,flush=True)\n"
            + ("time.sleep(30)\n" if wait else "")
        )
        return [sys.executable, "-c", script, "{input}"]

    def pid(self, marker: Path) -> int:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if marker.is_file():
                pid = int(marker.read_text())
                self.pids.append(pid)
                return pid
            time.sleep(0.025)
        self.fail("detached child marker never appeared")

    def test_normal_exit_reaps_detached_child(self):
        marker = self.root / "normal.pid"
        result = RuntimeExecutor(timeout_seconds=2).run(
            self.command(marker, wait=False, inherit=False), self.seed)
        pid = self.pid(marker)
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertTrue(stopped(pid), f"detached child still alive: {pid}")

    def test_timeout_preserves_partial_asan_and_reaps_detached_child(self):
        marker = self.root / "timeout.pid"
        result = RuntimeExecutor(timeout_seconds=0.4).run(
            self.command(marker, wait=True, inherit=False), self.seed)
        pid = self.pid(marker)
        self.assertTrue(result.timed_out)
        self.assertIn("heap-use-after-free", result.sanitizer or "")
        self.assertIn("/tmp/source.c:9", result.stack_trace or "")
        self.assertTrue(stopped(pid), f"detached child still alive: {pid}")

    def test_inherited_output_pipe_cannot_hold_replay_open(self):
        marker = self.root / "pipe.pid"
        started = time.monotonic()
        result = RuntimeExecutor(timeout_seconds=2).run(
            self.command(marker, wait=False, inherit=True), self.seed)
        pid = self.pid(marker)
        self.assertLess(time.monotonic() - started, 4)
        self.assertFalse(result.timed_out)
        self.assertTrue(stopped(pid), f"pipe holder still alive: {pid}")

    def test_caller_sigkill_reaps_detached_child(self):
        marker = self.root / "caller.pid"
        command = self.command(marker, wait=True, inherit=False)
        caller = (
            "from pathlib import Path\n"
            "from vulnerabilityanalysis.runtime import RuntimeExecutor\n"
            f"RuntimeExecutor(timeout_seconds=20).run({command!r},Path({str(self.seed)!r}))\n"
        )
        environment = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        process = subprocess.Popen([sys.executable, "-c", caller], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        pid = self.pid(marker)
        process.kill()
        process.wait(timeout=3)
        self.assertTrue(stopped(pid), f"caller SIGKILL left detached child: {pid}")

    def test_unproven_replay_cleanup_propagates_partial_asan(self):
        partial = "ERROR: AddressSanitizer: heap-use-after-free\n#0 0x1 in parse /tmp/a.c:7\n"
        with patch("vulnerabilityanalysis.runtime._guarded_run",
                   side_effect=RuntimeCleanupError("cleanup incomplete", "", partial)):
            with self.assertRaises(RuntimeCleanupError) as caught:
                RuntimeExecutor(timeout_seconds=1).run([sys.executable, "{input}"], self.seed)
        self.assertIn("heap-use-after-free", caught.exception.stderr)
        self.assertEqual(caught.exception.stdout, "")

    def test_missing_binary_remains_harness_not_started(self):
        result = RuntimeExecutor(timeout_seconds=1).run(
            [str(self.root / "missing-binary"), "{input}"], self.seed)
        self.assertEqual(result.failure_classification, "HARNESS_NOT_STARTED")
        self.assertIsNone(result.exit_code)

    def test_unsupported_subreaper_fails_closed(self):
        with patch("vulnerabilityanalysis.runtime.sys.platform", "darwin"):
            with self.assertRaises(RuntimeCleanupError):
                RuntimeExecutor(timeout_seconds=1).run([sys.executable, "{input}"], self.seed)

    def test_fuzzer_cleanup_error_propagates_partial_asan(self):
        partial = "ERROR: AddressSanitizer: heap-use-after-free\n#0 0x1 in parse /tmp/a.c:7\n"
        binary = self.root / "fuzzer"; binary.write_bytes(b"fixture")
        with patch("vulnerabilityanalysis.runtime._guarded_run",
                   side_effect=RuntimeCleanupError("cleanup incomplete", "", partial)):
            with self.assertRaises(RuntimeCleanupError) as caught:
                fuzz_locally(binary, self.root / "corpus", seconds=1)
        self.assertIn("heap-use-after-free", caught.exception.stderr)

    def test_process_harness_cleanup_error_propagates_partial_asan(self):
        partial = "ERROR: AddressSanitizer: heap-use-after-free\n#0 0x1 in parse /tmp/a.c:7\n"
        binary = self.root / "harness"; binary.write_bytes(b"fixture")
        with patch("vulnerabilityanalysis.runtime._guarded_run",
                   side_effect=RuntimeCleanupError("cleanup incomplete", "", partial)), \
             patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None):
            with self.assertRaises(RuntimeCleanupError) as caught:
                fuzz_process_harness(binary, [str(binary), "{input}"],
                                     [self.seed], self.root / "process", seconds=1)
        self.assertIn("heap-use-after-free", caught.exception.stderr)

    def test_process_harness_timeout_keeps_partial_asan_file(self):
        partial = b"ERROR: AddressSanitizer: heap-use-after-free\n#0 0x1 in parse /tmp/a.c:7\n"
        binary = self.root / "harness"; binary.write_bytes(b"fixture")
        with patch("vulnerabilityanalysis.runtime._guarded_run",
                   side_effect=subprocess.TimeoutExpired([str(binary)], 1, stderr=partial)), \
             patch("vulnerabilityanalysis.runtime.shutil.which", return_value=None):
            report = fuzz_process_harness(binary, [str(binary), "{input}"],
                                          [self.seed], self.root / "process", seconds=1)
        self.assertEqual(report["observations"][0]["status"], "TIMEOUT")
        self.assertIn("heap-use-after-free", report["observations"][0]["sanitizer"])
        self.assertTrue(Path(report["observations"][0]["stderr_path"]).is_file())

    def test_binary_guard_preserves_arbitrary_git_output_bytes(self):
        output = b"blob\x00\xff\xfe\n"
        command = [sys.executable, "-c", f"import os;os.write(1,{output!r})"]
        done = _guarded_run(command, timeout=2, text=False)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, output)
        self.assertEqual(done.stderr, b"")

    def test_binary_guard_timeout_preserves_arbitrary_partial_bytes(self):
        output = b"blob\x00\xff\xfe\n"
        command = [sys.executable, "-c",
                   f"import os,time;os.write(1,{output!r});time.sleep(30)"]
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            _guarded_run(command, timeout=0.25, text=False)
        self.assertEqual(caught.exception.output, output)


if __name__ == "__main__":
    unittest.main()
