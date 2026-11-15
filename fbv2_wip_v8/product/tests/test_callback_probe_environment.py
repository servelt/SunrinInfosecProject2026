"""HP may pin the GDB callback probe environment without changing legacy callers."""

import subprocess

from vulnerabilityanalysis import direct_input
from vulnerabilityanalysis.runtime import CLEAN_RUNTIME_ENVIRONMENT


def test_callback_probe_uses_explicit_clean_environment(tmp_path, monkeypatch):
    binary = tmp_path / "binary"
    binary.write_bytes(b"fixture binary")
    seed = tmp_path / "input"
    seed.write_bytes(b"candidate input")
    monkeypatch.setattr(direct_input.platform, "machine", lambda: "x86_64")
    chosen = []
    monkeypatch.setattr(
        direct_input.shutil, "which",
        lambda command, *, path=None: chosen.append((command, path)) or
        "/usr/bin/gdb")
    launches = []

    def scripted_gdb(command, **kwargs):
        launches.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, "", "GDB fixture failure")

    monkeypatch.setattr(direct_input, "_guarded_run", scripted_gdb)
    result = direct_input.probe_libfuzzer_callback(
        binary, seed, env=dict(CLEAN_RUNTIME_ENVIRONMENT))

    assert result.measured is False
    assert chosen == [("gdb", CLEAN_RUNTIME_ENVIRONMENT["PATH"])]
    assert len(launches) == 1
    assert launches[0][1]["env"] == CLEAN_RUNTIME_ENVIRONMENT
    assert launches[0][1]["timeout"] == 20.0


def test_callback_probe_legacy_lookup_keeps_one_argument(tmp_path, monkeypatch):
    binary = tmp_path / "binary"
    binary.write_bytes(b"fixture binary")
    seed = tmp_path / "input"
    seed.write_bytes(b"candidate input")
    monkeypatch.setattr(direct_input.platform, "machine", lambda: "x86_64")
    chosen = []
    monkeypatch.setattr(
        direct_input.shutil, "which",
        lambda command: chosen.append(command) or "/usr/bin/gdb")
    monkeypatch.setattr(
        direct_input, "_guarded_run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, "", "GDB fixture failure"))

    result = direct_input.probe_libfuzzer_callback(binary, seed)

    assert result.measured is False
    assert chosen == ["gdb"]
