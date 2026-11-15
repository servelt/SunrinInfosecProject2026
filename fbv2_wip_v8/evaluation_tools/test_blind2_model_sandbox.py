"""Provider-free checks of the Blind 2 model filesystem boundary."""

from __future__ import annotations

import json
import os
import pathlib
import select
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from evaluation_tools import blind2_model_sandbox as sandbox


HERE = pathlib.Path(__file__).resolve().parent
LAUNCHER = HERE / "blind2_model_sandbox.py"

PROBE_SOURCE = r"""
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--sleep") == 0) {
        puts("READY");
        fflush(stdout);
        for (;;) pause();
    }
    char cwd[PATH_MAX];
    if (getpid() != 1 || !getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/work")) return 11;
    if (access("/home/dawne", F_OK) == 0 || access("/mnt", F_OK) == 0) return 12;
    if (access("/bin/sh", F_OK) == 0 || access("/usr/bin/git", F_OK) == 0) return 13;
    if (getenv("LEAK_MARKER") || getenv("PYTHONPATH")) return 14;
    if (strcmp(getenv("HOME"), "/home/model") || strcmp(getenv("CODEX_HOME"), "/home/model/.codex")) return 15;
    if (strcmp(getenv("PATH"), "/bin")) return 16;
    struct stat st;
    if (lstat("/home/model/.codex/auth.json", &st) || S_ISLNK(st.st_mode)) return 17;
    for (int i = 1; i < argc; i++) {
        char through_proc[PATH_MAX];
        if (access(argv[i], F_OK) == 0) return 18;
        if (snprintf(through_proc, sizeof(through_proc), "/proc/1/root%s", argv[i]) >= sizeof(through_proc)) return 19;
        if (access(through_proc, F_OK) == 0) return 20;
    }
    DIR *dir = opendir("/work");
    if (!dir) return 21;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) return 22;
    }
    closedir(dir);
    puts("ISOLATED");
    return 0;
}
"""


@unittest.skipUnless(shutil.which("gcc"), "static GCC fixture unavailable")
class SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="blind2-sandbox-test-")
        cls.base = pathlib.Path(cls.temporary.name)
        source = cls.base / "probe.c"
        source.write_text(PROBE_SOURCE)
        cls.static_probe = cls.base / "probe-static"
        cls.dynamic_probe = cls.base / "probe-dynamic"
        subprocess.run(["gcc", "-static", "-O0", str(source), "-o", str(cls.static_probe)], check=True)
        subprocess.run(["gcc", "-O0", str(source), "-o", str(cls.dynamic_probe)], check=True)
        cls.state = cls.base / "private-codex-state"
        cls.state.mkdir()
        # The host auth file is intentionally symlinked. Its *content* may be
        # copied; the host path and symlink must not enter the chroot.
        cls.host_auth = cls.base / "host-auth.json"
        cls.host_auth.write_text("{}\n")
        (cls.state / "auth.json").symlink_to(cls.host_auth)
        (cls.state / "config.toml").write_text('model = "synthetic"\n')

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _run(self, *args: str, state: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, CODEX_HOME=str(state or self.state), LEAK_MARKER="host-secret-marker")
        env["PYTHONPATH"] = "/tmp/host-python-path"
        return subprocess.run([sys.executable, str(LAUNCHER), *args], env=env,
                              text=True, capture_output=True, timeout=20)

    def test_self_test_requires_private_paths_and_pid_namespace(self) -> None:
        result = self._run("--self-test", str(self.static_probe),
                           "--deny-path", str(self.base),
                           "--deny-path", str(self.host_auth))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(all(report["checks"].values()), report)
        self.assertEqual(report["deny_path_count"], 2)

    def test_self_test_rejects_vacuous_or_untrusted_denied_paths(self) -> None:
        empty = self._run("--self-test", str(self.static_probe))
        self.assertEqual(empty.returncode, 126)
        missing = self._run("--self-test", str(self.static_probe),
                            "--deny-path", str(self.base / "missing"))
        self.assertEqual(missing.returncode, 126)
        relative = self._run("--self-test", str(self.static_probe),
                             "--deny-path", "relative/path")
        self.assertEqual(relative.returncode, 126)

    def test_static_child_cannot_read_target_or_evaluator_files(self) -> None:
        target = self.base / "target" / ".git" / "HEAD"
        evaluator = self.base / "evaluator_only" / "sealed-input"
        target.parent.mkdir(parents=True)
        evaluator.parent.mkdir(parents=True)
        target.write_text("hidden target history\n")
        evaluator.write_text("hidden evaluator answer\n")
        result = self._run(str(self.static_probe), str(target), str(evaluator),
                           str(self.host_auth))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ISOLATED")

    def test_dynamic_executable_is_rejected_before_namespace_launch(self) -> None:
        result = self._run(str(self.dynamic_probe))
        self.assertEqual(result.returncode, 126)
        self.assertIn("static ELF64", result.stderr)

    def test_missing_auth_stops_before_model_launch(self) -> None:
        empty_state = self.base / "empty-state"
        empty_state.mkdir(exist_ok=True)
        result = self._run(str(self.static_probe), state=empty_state)
        self.assertEqual(result.returncode, 126)
        self.assertIn("auth.json", result.stderr)

    def test_inner_setup_uses_running_interpreter_path(self) -> None:
        """The namespace setup must not depend on /usr/bin/python3.12."""
        alternate = self.base / "alternate-python"
        shutil.copy2(sys.executable, alternate)

        class CompletedChild:
            pid = -1

            @staticmethod
            def wait() -> int:
                return 0

        with mock.patch.dict(os.environ, {"CODEX_HOME": str(self.state)}), \
                mock.patch.object(sandbox.sys, "executable", str(alternate)), \
                mock.patch.object(sandbox.subprocess, "Popen", return_value=CompletedChild()) as spawn:
            self.assertEqual(sandbox._outside(str(self.static_probe), []), 0)
        self.assertEqual(spawn.call_args.args[0][4], str(alternate.resolve()))

    def test_supervisor_group_kill_leaves_no_model_process(self) -> None:
        """The 24-hour supervisor's PGID SIGKILL must reach namespace PID 1."""
        env = dict(os.environ, CODEX_HOME=str(self.state))
        process = subprocess.Popen(
            [sys.executable, str(LAUNCHER), str(self.static_probe), "--sleep"],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        fixture_pids: list[int] = []
        try:
            assert process.stdout is not None
            readable, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(readable, "static sleep fixture did not start")
            self.assertEqual(process.stdout.readline().strip(), "READY")
            fixture_pids = self._running_fixture_pids()
            self.assertTrue(fixture_pids, "could not identify running static fixture")
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(self._pid_running(pid) for pid in fixture_pids):
                time.sleep(0.05)
            self.assertFalse([pid for pid in fixture_pids if self._pid_running(pid)],
                             "sandbox child survived supervisor process-group kill")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            for pid in fixture_pids:
                if self._pid_running(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_direct_launcher_kill_leaves_no_model_process(self) -> None:
        """The bounded close() SIGKILL fallback must not orphan unshare/PID 1."""
        env = dict(os.environ, CODEX_HOME=str(self.state))
        process = subprocess.Popen(
            [sys.executable, str(LAUNCHER), str(self.static_probe), "--sleep"],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        fixture_pids: list[int] = []
        try:
            assert process.stdout is not None
            readable, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(readable, "static sleep fixture did not start")
            self.assertEqual(process.stdout.readline().strip(), "READY")
            fixture_pids = self._running_fixture_pids()
            self.assertTrue(fixture_pids, "could not identify running static fixture")
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(self._pid_running(pid) for pid in fixture_pids):
                time.sleep(0.05)
            self.assertFalse([pid for pid in fixture_pids if self._pid_running(pid)],
                             "sandbox child survived direct launcher kill")
        finally:
            # This group kill is cleanup only; the assertion above checks
            # that direct PID kill already terminated the namespace child.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                process.wait(timeout=5)
            for pid in fixture_pids:
                if self._pid_running(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def _running_fixture_pids(self) -> list[int]:
        expected = self.static_probe.stat()
        result: list[int] = []
        for entry in pathlib.Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                actual = (entry / "exe").stat()
                if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
                    result.append(int(entry.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        return result

    @staticmethod
    def _pid_running(pid: int) -> bool:
        try:
            status = pathlib.Path(f"/proc/{pid}/stat").read_text()
            return status.rsplit(") ", 1)[1][0] != "Z"
        except (FileNotFoundError, ProcessLookupError, IndexError):
            return False


if __name__ == "__main__":
    unittest.main()
