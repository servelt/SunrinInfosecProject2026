"""Provider-free regressions for official V2 Git provenance subprocesses."""
from __future__ import annotations

import hashlib
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

from vulnerabilityanalysis.official_harness import (
    _committed_file_matches, _git_clean, _git_tree_matches_worktree,
)
from vulnerabilityanalysis.runtime import RuntimeCleanupError


def _state(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0]
    except OSError:
        return None


class OfficialGitDescendantTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None or sys.platform != "linux":
            self.skipTest("Linux Git fixture unavailable")
        temporary = tempfile.TemporaryDirectory(prefix="va-official-git-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        self._git("init", "-q", str(self.repo), cwd=self.root)
        self.source = self.repo / "binary.dat"
        self.data = b"header\x00\xff\xfe\n"
        self.source.write_bytes(self.data)
        self._git("add", "binary.dat")
        self._git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                  "commit", "-qm", "fixture")
        self.revision = self._git("rev-parse", "HEAD").stdout.strip()
        self.pids: list[int] = []
        self.addCleanup(self._kill_remaining)

    def _git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *(args if cwd else ("-C", str(self.repo), *args))],
                              cwd=cwd, capture_output=True, text=True, check=True)

    def _kill_remaining(self) -> None:
        for pid in self.pids:
            if _state(pid) not in (None, "Z", "X"):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _install_fsmonitor(self, *, sleep_after_spawn: bool) -> Path:
        marker = self.root / "detached.pid"
        hook = self.root / "fsmonitor.py"
        hook.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
            "start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(child.pid))\n"
            "print('1', flush=True)\n"
            + ("time.sleep(30)\n" if sleep_after_spawn else "")
        )
        hook.chmod(0o700)
        self._git("config", "core.fsmonitor", str(hook))
        return marker

    def _detached_pid(self, marker: Path) -> int:
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

    def test_status_reaps_detached_fsmonitor_child(self) -> None:
        marker = self._install_fsmonitor(sleep_after_spawn=False)
        _git_clean(self.repo)
        self._assert_reaped(self._detached_pid(marker))

    def test_status_timeout_reaps_detached_fsmonitor_child(self) -> None:
        marker = self._install_fsmonitor(sleep_after_spawn=True)
        self.assertFalse(_git_clean(self.repo))
        self._assert_reaped(self._detached_pid(marker))

    def test_show_and_tree_keep_binary_git_output(self) -> None:
        expected = hashlib.sha256(self.data).hexdigest()
        self.assertTrue(_committed_file_matches(self.repo, self.revision,
                                                "binary.dat", expected))
        self.assertTrue(_git_tree_matches_worktree(self.repo, self.revision))

    def test_unproven_git_cleanup_cannot_become_clean_provenance(self) -> None:
        partial = "core.fsmonitor left an uncollected descendant"
        with patch("vulnerabilityanalysis.official_harness._guarded_run",
                   side_effect=RuntimeCleanupError("cleanup incomplete", "", partial)):
            with self.assertRaises(RuntimeCleanupError) as caught:
                _git_clean(self.repo)
        self.assertEqual(caught.exception.stderr, partial)


if __name__ == "__main__":
    unittest.main()
