#!/usr/bin/env python3
"""Pinned supervisor for one future md4c UAF causal measurement.

This program is only an issuer component.  The outer V2 process envelope must
pin this file, the instrumented binary and the input.  It launches the binary
exactly once, preserves the target's ASan stderr, authenticates the durable
trace emitted by the instrumented target, and mirrors the target termination.
It grants no Gate or discovery credit by itself.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys


MAX_TRACE_BYTES = 1_000_000


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _regular(path: Path, *, must_exist: bool = True) -> Path:
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents)):
        raise ValueError("instrumentation path is not canonical")
    path = path.resolve(strict=must_exist)
    if must_exist:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("instrumentation input is not a regular file")
    return path


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        raise ValueError("expected: EMITTER BINARY INPUT TRACE_PATH")
    binary = _regular(Path(argv[1]))
    input_path = _regular(Path(argv[2]))
    trace_path = _regular(Path(argv[3]), must_exist=False)
    if trace_path.exists() or trace_path.parent != Path.cwd().resolve():
        raise ValueError("trace staging path must be new in evaluation directory")
    expected = {
        "binary": os.environ.get("FBV2_BINARY_SHA256"),
        "input": os.environ.get("FBV2_INPUT_SHA256"),
        "evaluation": os.environ.get("FBV2_EVALUATION_ID"),
    }
    if (_sha(binary) != expected["binary"] or
            _sha(input_path) != expected["input"] or
            not expected["evaluation"] or
            os.environ.get("FBV2_TRACE_PATH") != str(trace_path)):
        raise ValueError("instrumentation environment differs from pinned inputs")
    target_command = [str(binary), "-runs=1", str(input_path)]
    target_env = dict(os.environ)
    done = subprocess.run(
        target_command, cwd=Path.cwd(), env=target_env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    if done.stdout:
        raise ValueError("instrumented md4c target unexpectedly wrote stdout")
    fd = os.open(trace_path, os.O_RDONLY | os.O_CLOEXEC |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.getuid() or info.st_size > MAX_TRACE_BYTES):
            raise ValueError("instrumented md4c trace file is unsafe")
        trace_bytes = os.read(fd, MAX_TRACE_BYTES + 1)
        if len(trace_bytes) != info.st_size:
            raise ValueError("instrumented md4c trace changed while reading")
    finally:
        os.close(fd)
    trace = json.loads(trace_bytes)
    if (trace.get("kind") != "FBV2_UAF_RAW_TRACE_V1" or
            trace.get("evaluation_id") != expected["evaluation"] or
            trace.get("input_sha256") != expected["input"]):
        raise ValueError("instrumented md4c trace identity differs")
    trace["target_execution"] = {
        "binary_path": str(binary), "binary_sha256": expected["binary"],
        "input_path": str(input_path), "input_sha256": expected["input"],
        "command": target_command, "returncode": done.returncode,
        "signal": -done.returncode if done.returncode < 0 else None,
        "stdout_sha256": hashlib.sha256(done.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(done.stderr).hexdigest(),
    }
    rendered = (json.dumps(trace, sort_keys=True, separators=(",", ":")) +
                "\n").encode()
    os.write(sys.stdout.fileno(), rendered)
    os.write(sys.stderr.fileno(), done.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    if done.returncode < 0:
        caught = -done.returncode
        signal.signal(caught, signal.SIG_DFL)
        os.kill(os.getpid(), caught)
        raise RuntimeError("mirrored signal did not terminate emitter")
    return done.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
