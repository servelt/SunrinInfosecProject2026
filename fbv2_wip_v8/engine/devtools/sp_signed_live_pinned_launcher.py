#!/usr/bin/env python3
"""Execute the signed SP live entry from one authenticated open-file image."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BOOTSTRAP_PYTHON = Path("/usr/bin/python3.12")
_FORBIDDEN_ENVIRONMENT = frozenset({
    "BASH_ENV", "ENV", "GCONV_PATH", "LD_AUDIT", "LD_LIBRARY_PATH",
    "LD_PRELOAD", "PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH",
    "PYTHONPLATLIBDIR", "PYTHONSTARTUP", "PYTHONUSERBASE",
})
_RUNTIME_HANDOFF_NAMES = frozenset({
    "FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256",
    "FBV2_RUNTIME_CLOSURE_MANIFEST_PATH",
    "FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256",
    "FBV2_RUNTIME_CLOSURE_SPEC_PATH", "FBV2_RUNTIME_CLOSURE_SPEC_SHA256",
    "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH",
    "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256",
    "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID",
})


def pinned_bytes(path: Path, wanted: str) -> bytes:
    if (not _SHA.fullmatch(wanted or "") or not path.is_absolute() or
            path.is_symlink() or path != path.resolve() or not path.is_file()):
        raise ValueError("SP live entry path is not a canonical pinned file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("SP live entry is not regular")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    current = path.stat(follow_symlinks=False)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                            row.st_mtime_ns, row.st_ctime_ns)
    if (identity(before) != identity(after) or
            (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino) or
            hashlib.sha256(raw).hexdigest() != wanted):
        raise ValueError("SP live entry changed while being loaded")
    return raw


def _runtime_handoff() -> dict[str, str]:
    values = {name: os.environ.get(name) for name in _RUNTIME_HANDOFF_NAMES}
    if (any(type(value) is not str or not value for value in values.values()) or
            not values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID"].isdigit() or
            any(name in os.environ for name in _FORBIDDEN_ENVIRONMENT)):
        raise ValueError("SP runtime closure supervisor handoff is absent")
    parent = int(values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID"])
    supervisor = Path(values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH"])
    if os.getppid() != parent:
        raise ValueError("SP runtime closure supervisor parent changed")
    try:
        parent_exe = Path(f"/proc/{parent}/exe").resolve()
        parent_argv = Path(f"/proc/{parent}/cmdline").read_bytes().split(b"\0")
    except OSError as exc:
        raise ValueError("SP runtime closure supervisor is unavailable") from exc
    bootstrap_source = parent_argv[5] if len(parent_argv) > 5 else b""
    if (parent_exe != _BOOTSTRAP_PYTHON or len(parent_argv) < 9 or
            parent_argv[0] != str(_BOOTSTRAP_PYTHON).encode() or
            parent_argv[1:4] != [b"-I", b"-S", b"-B"] or
            parent_argv[4] != b"-c" or
            hashlib.sha256(bootstrap_source).hexdigest() !=
                values["FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256"] or
            parent_argv[6] != str(supervisor).encode() or
            parent_argv[7] != values[
                "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256"].encode() or
            parent_argv[8] != b"exec"):
        raise ValueError("SP runtime closure supervisor identity changed")
    pinned_bytes(supervisor,
                 values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256"])
    manifest_path = Path(values["FBV2_RUNTIME_CLOSURE_MANIFEST_PATH"])
    try:
        manifest = json.loads(pinned_bytes(
            manifest_path,
            values["FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256"]))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("SP runtime closure manifest is invalid") from exc
    if (type(manifest) is not dict or
            manifest.get("kind") != "FBV2_SP_RUNTIME_CLOSURE_V1" or
            manifest.get("supervisor_path") != str(supervisor) or
            manifest.get("supervisor_sha256") !=
                values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256"] or
            manifest.get("bootstrap_source_sha256") !=
                values["FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256"] or
            manifest.get("runtime_python_path") != sys.executable or
            list(sys.path) != manifest.get("initial_sys_path") or
            type(manifest.get("sanitized_sys_path")) is not list):
        raise ValueError("SP runtime closure process identity changed")
    sys.path[:] = list(manifest["sanitized_sys_path"])
    return values


def main(argv: list[str] | None = None) -> int:
    if sys.flags.isolated != 1 or sys.flags.no_site != 1:
        raise ValueError("SP live launcher requires python -I -S isolation")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entry", type=Path, required=True)
    parser.add_argument("--entry-sha256", required=True)
    parser.add_argument("entry_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    forwarded = list(args.entry_args)
    if forwarded[:1] == ["--"]:
        forwarded.pop(0)
    if not forwarded:
        raise ValueError("SP live entry arguments are absent")
    signed_sp = "--sp-live-approval" in forwarded
    runtime_handoff = _runtime_handoff() if signed_sp else {}
    if not signed_sp and any(name in os.environ
                             for name in _RUNTIME_HANDOFF_NAMES):
        raise ValueError("runtime closure handoff is only valid for signed SP")
    raw = pinned_bytes(args.entry, args.entry_sha256)
    if not hasattr(os, "memfd_create"):
        raise ValueError("sealed SP live entry requires Linux memfd")
    fd = os.memfd_create("fbv2-sp-live-entry", os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise ValueError("sealed SP live entry write failed")
            offset += written
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                 fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
            raise ValueError("sealed SP live entry is not immutable")
        os.set_inheritable(fd, True)
        launcher_path = Path(__file__).resolve()
        environment = {
            **os.environ,
            "FBV2_PINNED_ENTRY_FD": str(fd),
            "FBV2_PINNED_ENTRY_PATH": str(args.entry),
            "FBV2_PINNED_ENTRY_SHA256": args.entry_sha256,
            "FBV2_PINNED_LAUNCHER_PATH": str(launcher_path),
            "FBV2_PINNED_LAUNCHER_SHA256": hashlib.sha256(
                launcher_path.read_bytes()).hexdigest(),
        }
        environment.update(runtime_handoff)
        os.execve(sys.executable, [sys.executable, "-I", "-S", "-B",
                  f"/proc/self/fd/{fd}", *forwarded], environment)
    finally:
        os.close(fd)
    raise RuntimeError("sealed SP live entry exec did not replace launcher")


if __name__ == "__main__":
    raise SystemExit(main())
