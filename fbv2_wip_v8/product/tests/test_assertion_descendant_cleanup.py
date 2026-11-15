"""Assertion build and replay must reap synthetic detached descendants."""
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

from vulnerabilityanalysis.assertions import (_run_assertion_command,
                                              execute_assertion, guided_fuzz_assertion)
from vulnerabilityanalysis.models import Assertion, RuntimeResult
from vulnerabilityanalysis.runtime import RuntimeCleanupError


def _state(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0]
    except OSError:
        return None


def _stopped(pid: int, seconds: float = 3) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _state(pid) in (None, "Z", "X"):
            return True
        time.sleep(.025)
    return _state(pid) in (None, "Z", "X")


class AssertionDescendantCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "target.c"
        self.source.write_text("int target(int n) {\n  return n;\n}\n")
        self.seed = self.root / "seed"
        self.seed.write_bytes(b"normal")
        self.pids: list[int] = []
        self.addCleanup(self._kill_remaining)

    def _kill_remaining(self):
        for pid in self.pids:
            if _state(pid) not in (None, "Z", "X"):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _pid(self, marker: Path) -> int:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if marker.is_file():
                pid = int(marker.read_text())
                self.pids.append(pid)
                return pid
            time.sleep(.025)
        self.fail(f"detached child marker never appeared: {marker}")

    def _compiler(self, marker: Path, *, wait: bool = False,
                  child_on_replay: bool = False) -> Path:
        compiler = self.root / "fake-compiler"
        fake_binary = (
            f"#!{sys.executable}\n"
            "import pathlib, subprocess, sys\n"
            "p=subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'], "
            "start_new_session=True, stdin=subprocess.DEVNULL, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(p.pid))\n"
            "print('16 Extra Counters', file=sys.stderr)\n"
        ) if child_on_replay else f"#!{sys.executable}\nimport sys\nsys.exit(0)\n"
        script = (
            f"#!{sys.executable}\n"
            "import pathlib, subprocess, sys, time\n"
            "if '-fsyntax-only' in sys.argv:\n"
            "    sys.exit(0)\n"
            + ("p=subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'], "
               "start_new_session=True, stdin=subprocess.DEVNULL, "
               "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
               f"pathlib.Path({str(marker)!r}).write_text(str(p.pid))\n"
               if not child_on_replay else "")
            + "destination=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
            f"destination.write_text({fake_binary!r})\n"
            "destination.chmod(0o700)\n"
            + ("time.sleep(30)\n" if wait else "")
        )
        compiler.write_text(script)
        compiler.chmod(0o700)
        return compiler

    def _assertion(self) -> Assertion:
        return Assertion("a-l02", "worker", "direction", "target",
                         f"{self.source}:2", "n >= 0", "n >= 0", [])

    def test_normal_build_reaps_detached_compiler_descendant(self):
        marker = self.root / "build.pid"
        compiler = self._compiler(marker)
        assertion, _ = execute_assertion(self._assertion(), self.source, 2, self.seed,
            self.root / "normal", [str(compiler), "{source}", "-o", "{binary}"],
            ["{binary}", "{input}"], timeout_seconds=2)
        self.assertNotEqual(assertion.status, "ERROR")
        self.assertTrue(_stopped(self._pid(marker)), "compiler descendant survived")

    def test_timed_out_build_reaps_detached_compiler_descendant(self):
        marker = self.root / "timeout.pid"
        compiler = self._compiler(marker, wait=True)
        assertion, _ = execute_assertion(self._assertion(), self.source, 2, self.seed,
            self.root / "timeout", [str(compiler), "{source}", "-o", "{binary}"],
            ["{binary}", "{input}"], timeout_seconds=.4)
        self.assertEqual(assertion.status, "ERROR")
        self.assertTrue(_stopped(self._pid(marker)), "timed-out compiler descendant survived")

    def test_guided_probe_reaps_detached_instrumented_binary_descendant(self):
        marker = self.root / "replay.pid"
        compiler = self._compiler(marker, child_on_replay=True)
        runtime = RuntimeResult(0, "", "", None, False, None, None, "UNKNOWN")
        with patch("vulnerabilityanalysis.assertions.fuzz_locally", return_value=runtime):
            report = guided_fuzz_assertion(self._assertion(), self.source, 2, self.seed,
                self.root / "guided", [str(compiler), "{source}", "-o", "{binary}"],
                ["{binary}", "{input}"], seconds=1)
        self.assertEqual(report["status"], "RAN")
        self.assertTrue(_stopped(self._pid(marker)), "instrumented binary descendant survived")

    def test_unproven_build_cleanup_propagates_partial_output(self):
        partial = "ERROR: AddressSanitizer: heap-use-after-free\n#0 in build /tmp/a.c:7\n"
        with patch("vulnerabilityanalysis.assertions._guarded_run",
                   side_effect=RuntimeCleanupError("cleanup incomplete", "", partial)):
            with self.assertRaises(RuntimeCleanupError) as caught:
                execute_assertion(self._assertion(), self.source, 2, self.seed,
                    self.root / "incomplete", ["compiler", "{source}", "-o", "{binary}"],
                    ["{binary}", "{input}"], timeout_seconds=1)
        self.assertEqual(caught.exception.stderr, partial)

    def test_zero_timeout_keeps_timeout_classification(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            _run_assertion_command([sys.executable, "-c", "pass"], timeout=0)


if __name__ == "__main__":
    unittest.main()
