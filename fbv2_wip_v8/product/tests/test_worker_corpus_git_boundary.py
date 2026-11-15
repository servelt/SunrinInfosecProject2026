"""Worker corpus Git checks must not leave detached hook descendants."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.runtime import RuntimeCleanupError
from vulnerabilityanalysis.scan import worker_corpus_identity
from vulnerabilityanalysis.workflow import write_json


def _state(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0]
    except OSError:
        return None


class WorkerCorpusGitBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        if sys.platform != "linux" or shutil.which("git") is None:
            self.skipTest("Linux Git fixture unavailable")
        temporary = tempfile.TemporaryDirectory(prefix="va-worker-git-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        (self.repo / "source.c").write_text("int f(void) { return 0; }\n")
        self._git("init", "-q", str(self.repo), cwd=self.root)
        self._git("add", "source.c")
        self._git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                  "commit", "-qm", "fixture")
        self.harness = self.root / "harness.c"
        self.harness.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
        self.binary = self.root / "fuzzer"
        self.binary.write_bytes(b"synthetic executable identity")
        self.run = self.root / "run"
        write_json(self.run / "run.json", {"harness_id": "h"})
        write_json(self.run / "harness.json", {"harness_path": str(self.harness)})
        write_json(self.run / "workers.json", [
            {"harness_id": "h", "worker_id": "w", "sanitizer": "ASAN"}])
        self.pids: list[int] = []
        self.addCleanup(self._kill_remaining)

    def _git(self, *args: str, cwd: Path | None = None) -> None:
        subprocess.run(["git", *(args if cwd else ("-C", str(self.repo), *args))],
                       cwd=cwd, check=True, capture_output=True)

    def _kill_remaining(self) -> None:
        for pid in self.pids:
            if _state(pid) not in (None, "Z", "X"):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _install_hook(self, *, wait: bool) -> Path:
        marker = self.root / "detached.pid"
        hook = self.root / "fsmonitor.py"
        hook.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
            "start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(child.pid))\n"
            "print('1', flush=True)\n"
            + ("time.sleep(30)\n" if wait else ""))
        hook.chmod(0o700)
        self._git("config", "core.fsmonitor", str(hook))
        return marker

    def _pid(self, marker: Path) -> int:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not marker.is_file():
            time.sleep(.02)
        self.assertTrue(marker.is_file(), "Git fsmonitor was not invoked")
        pid = int(marker.read_text())
        self.pids.append(pid)
        return pid

    def _assert_reaped(self, pid: int) -> None:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and _state(pid) is not None:
            time.sleep(.02)
        self.assertIsNone(_state(pid), f"detached Git hook child remains: {pid}")

    def test_clean_identity_reaps_detached_git_hook_child(self) -> None:
        marker = self._install_hook(wait=False)
        identity = worker_corpus_identity(self.run, self.repo, self.binary, ["ASAN"])
        self.assertEqual(identity["worker_id"], "w")
        self._assert_reaped(self._pid(marker))

    def test_hung_git_check_has_short_deadline_and_reaps_hook_child(self) -> None:
        marker = self._install_hook(wait=True)
        with patch("vulnerabilityanalysis.scan._WORKER_GIT_STATUS_TIMEOUT_SECONDS", .25):
            with self.assertRaisesRegex(ValueError, "Git clean check timed out"):
                worker_corpus_identity(self.run, self.repo, self.binary, ["ASAN"])
        self._assert_reaped(self._pid(marker))

    def test_cleanup_failure_propagates_without_marking_corpus_clean(self) -> None:
        partial = "Git hook cleanup was not proven"
        with patch("vulnerabilityanalysis.scan._guarded_run",
                   side_effect=RuntimeCleanupError("cleanup incomplete", "", partial)):
            with self.assertRaises(RuntimeCleanupError) as caught:
                worker_corpus_identity(self.run, self.repo, self.binary, ["ASAN"])
        self.assertEqual(caught.exception.stderr, partial)


if __name__ == "__main__":
    unittest.main()
