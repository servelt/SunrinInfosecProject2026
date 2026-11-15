"""Provider-free checks for short target probes and compiler subprocesses."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis import agents, analysis, context, direct_input, scan
from vulnerabilityanalysis.runtime import RuntimeCleanupError, _guarded_run
from vulnerabilityanalysis.source import SourceRepository


class AuxiliaryProcessBoundaryTest(unittest.TestCase):
    @staticmethod
    def _launcher(path: Path, marker: Path, *, output: str = "",
                  hang: bool = False) -> Path:
        path.write_text(
            f"#!{sys.executable}\n"
            "import os, subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(30)'], start_new_session=True, "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL)\n"
            f"with open({str(marker)!r}, 'a') as stream: "
            "stream.write(str(child.pid) + '\\n')\n"
            f"print({output!r}, flush=True)\n"
            + ("time.sleep(30)\n" if hang else ""),
            encoding="utf-8",
        )
        path.chmod(0o700)
        return path

    def _assert_all_reaped(self, marker: Path) -> None:
        self.assertTrue(marker.is_file(), "synthetic detached child was not started")
        pids = [int(row) for row in marker.read_text().splitlines()]
        self.assertTrue(pids)
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if all(not Path(f"/proc/{pid}").exists() for pid in pids):
                    return
                time.sleep(.02)
            self.fail(f"detached descendants survived: {pids}")
        finally:
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_libfuzzer_help_probe_reaps_detached_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pids"
            binary = self._launcher(root / "fake-fuzzer", marker,
                                    output="max_total_time supported")
            self.assertTrue(scan._supports_libfuzzer_interface(binary))
            self._assert_all_reaped(marker)

    def test_libfuzzer_help_timeout_reaps_detached_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pids"
            binary = self._launcher(root / "hanging-fuzzer", marker,
                                    output="max_total_time supported", hang=True)
            self.assertFalse(scan._supports_libfuzzer_interface(binary))
            self._assert_all_reaped(marker)

    def test_condition_compiler_reaps_detached_children(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pids"
            compiler = self._launcher(root / "fake-compiler", marker)
            source = root / "source.c"
            source.write_text("int sample(int count) {\n    return count;\n}\n")
            with patch.object(agents.shutil, "which", return_value=str(compiler)):
                self.assertIsNone(agents._source_condition_check(source, 2, "count > 0"))
            self._assert_all_reaped(marker)

    def test_condition_compiler_timeout_reaps_detached_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pids"
            compiler = self._launcher(root / "hanging-compiler", marker, hang=True)
            source = root / "source.c"
            source.write_text("int sample(int count) {\n    return count;\n}\n")
            with patch.object(agents.shutil, "which", return_value=str(compiler)), \
                 patch.object(agents, "_guarded_run",
                              side_effect=lambda command, timeout: _guarded_run(
                                  command, timeout=.25)):
                result = agents._source_condition_check(source, 2, "count > 0")
            self.assertIn("TimeoutExpired", result)
            self._assert_all_reaped(marker)

    def test_context_preprocessor_reaps_detached_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pids"
            source = root / "source.c"
            source.write_text("int sample(void) { return 0; }\n")
            compiler = self._launcher(root / "fake-preprocessor", marker,
                                      output=f'# 1 "{source}"\nint sample(void) {{ return 0; }}')
            resolver = context.ContextResolver(SourceRepository(root, {}),
                                               build_command=[str(compiler), "{source}"])
            active = resolver._active_build_lines(source)
            self.assertIn(source, active)
            self._assert_all_reaped(marker)

    def test_direct_callback_probe_reaps_detached_gdb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "pids"
            gdb = self._launcher(root / "fake-gdb", marker)
            binary = root / "binary"
            binary.write_bytes(b"synthetic executable")
            seed = root / "seed"
            seed.write_bytes(b"abc")
            with patch.object(direct_input.platform, "machine", return_value="x86_64"), \
                 patch.object(direct_input.shutil, "which", return_value=str(gdb)):
                result = direct_input.probe_libfuzzer_callback(binary, seed)
            self.assertFalse(result.measured)
            self._assert_all_reaped(marker)

    def test_cleanup_failure_is_not_downgraded_by_probe_or_context(self) -> None:
        error = RuntimeCleanupError("incomplete", "", "partial stderr")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.c"
            source.write_text("int sample(void) { return 0; }\n")
            compiler = root / "compiler"
            compiler.write_text("#!/bin/sh\nexit 0\n")
            compiler.chmod(0o700)
            with patch.object(scan, "_guarded_run", side_effect=error):
                with self.assertRaises(RuntimeCleanupError):
                    scan._supports_libfuzzer_interface(compiler)
            resolver = context.ContextResolver(SourceRepository(root, {}),
                                               build_command=[str(compiler), "{source}"])
            with patch.object(context, "_guarded_run", side_effect=error):
                with self.assertRaises(RuntimeCleanupError):
                    resolver._active_build_lines(source)
            with patch.object(agents.shutil, "which", return_value=str(compiler)), \
                 patch.object(agents, "_guarded_run", side_effect=error):
                with self.assertRaises(RuntimeCleanupError):
                    agents._source_condition_check(source, 1, "1")

    def test_generator_records_cleanup_failure_and_preserves_partial_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "pov.py"
            output = root / "pov.bin"
            partial = "ERROR: AddressSanitizer: synthetic\n#0 in synthetic source.c:1\n"
            with patch.object(analysis, "_guarded_run", side_effect=RuntimeCleanupError(
                    "incomplete", "", partial)):
                with self.assertRaises(RuntimeCleanupError) as raised:
                    analysis.generate_input("def build():\n    return bytes(4)\n", script, output)
            self.assertEqual(raised.exception.stderr, partial)
            receipt = json.loads((root / "pov.py.resources.json").read_text())
            self.assertEqual(receipt["attempts"][0]["status"], "CLEANUP_INCOMPLETE")
            self.assertEqual(receipt["attempts"][0]["partial_stderr_sha256"],
                             hashlib.sha256(partial.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
