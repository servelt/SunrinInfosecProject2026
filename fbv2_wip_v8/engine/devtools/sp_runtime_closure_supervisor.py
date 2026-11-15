#!/usr/bin/python3.12
"""Verify the complete signed-SP Python closure before starting that Python."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BOOTSTRAP_PYTHON = Path("/usr/bin/python3.12")
_BOOTSTRAP_PYTHON_SHA256 = (
    "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
_BOOTSTRAP_SOURCE = '''import hashlib,os,stat,sys
p=sys.argv[1]; wanted=sys.argv[2]
if not os.path.isabs(p) or os.path.islink(p) or os.path.realpath(p)!=p: raise SystemExit("unsafe supervisor path")
fd=os.open(p,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); before=os.fstat(fd); raw=os.read(fd,before.st_size+1); after=os.fstat(fd); os.close(fd)
if not stat.S_ISREG(before.st_mode) or len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or hashlib.sha256(raw).hexdigest()!=wanted: raise SystemExit("supervisor image changed")
sys.argv=[p,*sys.argv[3:]]
exec(compile(raw,p,"exec"),{"__name__":"__main__","__file__":p,"__package__":None,"__cached__":None})'''
_BOOTSTRAP_SOURCE_SHA256 = hashlib.sha256(
    _BOOTSTRAP_SOURCE.encode()).hexdigest()
_RUNTIME_PYTHON = Path("/home/dawne/tools/miniconda3/bin/python3.13")
_RUNTIME_STDLIB = Path("/home/dawne/tools/miniconda3/lib/python3.13")
_RUNTIME_LIBRARY_ROOT = Path("/home/dawne/tools/miniconda3/lib")
_TRUSTED_SITE_PACKAGES = Path(
    "/home/dawne/.venvs/fbv2-live-v11/lib/python3.13/site-packages")
_ABSENT_ZIP = Path("/home/dawne/tools/miniconda3/lib/python313.zip")
_EXPECTED_ENVIRONMENT = {
    "CODEX_HOME": "/home/dawne/.codex",
    "FBV2_SEED_DOCKER_CLI_SHA256":
        "84a8553077099a6a56b5ec36651dc17f5a1b89c26e33971e02906818c2f2626d",
    "FBV2_SEED_DOCKER_IMAGE_ID":
        "sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1",
    "HOME": "/home/dawne", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    "LOGNAME": "dawne", "NO_COLOR": "1", "PATH": "/usr/bin:/bin",
    "TERM": "dumb", "USER": "dawne",
}
_FORBIDDEN_ENVIRONMENT = frozenset({
    "BASH_ENV", "ENV", "GCONV_PATH", "LD_AUDIT", "LD_LIBRARY_PATH",
    "LD_PRELOAD", "PYTHONBREAKPOINT", "PYTHONHOME", "PYTHONINSPECT",
    "PYTHONPATH", "PYTHONPLATLIBDIR", "PYTHONSTARTUP", "PYTHONUSERBASE",
})


def _stable_file(path: Path, wanted: str | None = None) -> bytes:
    if (not path.is_absolute() or path.is_symlink() or
            path != path.resolve() or not path.is_file()):
        raise ValueError(f"unsafe closure file: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("closure member is not regular")
        chunks: list[bytes] = []
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
            (current.st_dev, current.st_ino) !=
                (after.st_dev, after.st_ino) or
            wanted is not None and hashlib.sha256(raw).hexdigest() != wanted):
        raise ValueError(f"closure file changed: {path}")
    return raw


def _walk_error(error: OSError) -> None:
    raise error


def tree_sha256(root: Path, excluded_top_level: tuple[str, ...] = ()) -> str:
    """Hash a complete plain tree, including names, kinds, modes and bytes."""
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve() or not root.is_dir()):
        raise ValueError(f"unsafe closure root: {root}")
    excluded = set(excluded_top_level)
    digest = hashlib.sha256()
    digest.update(b"FBV2_RUNTIME_CLOSURE_TREE_V1\0")
    for current, directories, files in os.walk(
            root, topdown=True, followlinks=False, onerror=_walk_error):
        parent = Path(current)
        relative_parent = parent.relative_to(root)
        if relative_parent == Path("."):
            directories[:] = [name for name in directories
                              if name not in excluded]
            files = [name for name in files if name not in excluded]
        linked_directories = [name for name in directories
                              if (parent / name).is_symlink()]
        directories[:] = [name for name in directories
                          if name not in linked_directories]
        directories.sort()
        linked_directories.sort()
        files.sort()
        for name, proposed_kind in [
                *((name, b"D") for name in directories),
                *((name, b"L") for name in linked_directories),
                *((name, b"F") for name in files)]:
            path = parent / name
            info = path.lstat()
            kind = proposed_kind
            if stat.S_ISLNK(info.st_mode):
                kind = b"L"
                target_text = os.readlink(path)
                target = (path.parent / target_text).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    raise ValueError(
                        f"closure tree link escapes root: {path}") from None
                if not target.exists():
                    raise ValueError(f"closure tree link is broken: {path}")
                content = target_text.encode("utf-8")
            elif kind == b"D":
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError(f"closure tree has linked directory: {path}")
                content = b""
            else:
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f"closure tree has special file: {path}")
                content = hashlib.sha256(_stable_file(path)).digest()
            relative = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(kind)
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
            digest.update(content)
    return digest.hexdigest()


def _manifest_value(supervisor_path: Path) -> dict:
    return {
        "bootstrap_python_path": str(_BOOTSTRAP_PYTHON),
        "bootstrap_python_sha256": _BOOTSTRAP_PYTHON_SHA256,
        "bootstrap_source_sha256": _BOOTSTRAP_SOURCE_SHA256,
        "forbidden_absent_paths": [str(_ABSENT_ZIP)],
        "initial_sys_path": [
            str(_ABSENT_ZIP), str(_RUNTIME_STDLIB),
            str(_RUNTIME_STDLIB / "lib-dynload"),
        ],
        "kind": "FBV2_SP_RUNTIME_CLOSURE_V1",
        "runtime_python_path": str(_RUNTIME_PYTHON),
        "runtime_python_sha256": hashlib.sha256(
            _stable_file(_RUNTIME_PYTHON)).hexdigest(),
        "sanitized_sys_path": [
            str(_RUNTIME_STDLIB), str(_RUNTIME_STDLIB / "lib-dynload")],
        "supervisor_path": str(supervisor_path),
        "supervisor_sha256": hashlib.sha256(
            _stable_file(supervisor_path)).hexdigest(),
        "trees": [
            {
                "excluded_top_level": ["site-packages"],
                "label": "RUNTIME_STDLIB_AND_DYNLOAD",
                "root": str(_RUNTIME_STDLIB),
                "sha256": tree_sha256(
                    _RUNTIME_STDLIB, ("site-packages",)),
            },
            {
                "excluded_top_level": ["python3.13", "terminfo"],
                "label": "RUNTIME_NATIVE_LIBRARY_ROOT",
                "root": str(_RUNTIME_LIBRARY_ROOT),
                "sha256": tree_sha256(
                    _RUNTIME_LIBRARY_ROOT, ("python3.13", "terminfo")),
            },
            {
                "excluded_top_level": [],
                "label": "TRUSTED_SITE_PACKAGES",
                "root": str(_TRUSTED_SITE_PACKAGES),
                "sha256": tree_sha256(_TRUSTED_SITE_PACKAGES),
            },
        ],
        "trusted_site_packages": str(_TRUSTED_SITE_PACKAGES),
    }


def _verify_manifest(path: Path, wanted: str) -> dict:
    raw = _stable_file(path, wanted)
    try:
        manifest = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("runtime closure manifest is malformed") from exc
    if type(manifest) is not dict or type(manifest.get("supervisor_path")) is not str:
        raise ValueError("runtime closure manifest contract changed")
    supervisor = Path(manifest["supervisor_path"])
    if supervisor != Path(__file__).resolve():
        raise ValueError("runtime closure supervisor path changed")
    expected = _manifest_value(supervisor)
    if type(manifest) is not dict or manifest != expected:
        raise ValueError("runtime closure manifest contract changed")
    bootstrap_info = _BOOTSTRAP_PYTHON.stat(follow_symlinks=False)
    if (bootstrap_info.st_uid != 0 or bootstrap_info.st_gid != 0 or
            stat.S_IMODE(bootstrap_info.st_mode) & 0o022):
        raise ValueError("runtime closure bootstrap Python is not root-owned")
    for absent in expected["forbidden_absent_paths"]:
        if Path(absent).exists() or Path(absent).is_symlink():
            raise ValueError("forbidden runtime import path appeared")
    return manifest


def _pin(path: Path, wanted: str, label: str) -> None:
    if not _SHA.fullmatch(wanted or ""):
        raise ValueError(f"{label} SHA is malformed")
    _stable_file(path, wanted)


def _clean_environment() -> dict[str, str]:
    if any(name in os.environ for name in _FORBIDDEN_ENVIRONMENT):
        raise ValueError("runtime closure supervisor received loader environment")
    if dict(os.environ) != _EXPECTED_ENVIRONMENT:
        raise ValueError("runtime closure supervisor environment is not exact")
    return dict(_EXPECTED_ENVIRONMENT)


def _verify_bootstrapped_exec(supervisor: Path, supervisor_sha256: str) -> None:
    argv = Path(f"/proc/{os.getpid()}/cmdline").read_bytes().split(b"\0")
    expected_prefix = [
        str(_BOOTSTRAP_PYTHON).encode(), b"-I", b"-S", b"-B", b"-c",
        _BOOTSTRAP_SOURCE.encode(), str(supervisor).encode(),
        supervisor_sha256.encode(), b"exec",
    ]
    if argv[:len(expected_prefix)] != expected_prefix:
        raise ValueError("runtime closure supervisor was not sealed by bootstrap")


def _write_manifest(path: Path) -> int:
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("runtime closure manifest output is not fresh")
    value = _manifest_value(Path(__file__).resolve())
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"manifest": str(path),
                      "sha256": hashlib.sha256(data).hexdigest()},
                     sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    if (sys.flags.isolated != 1 or sys.flags.no_site != 1 or
            Path(sys.executable) != _BOOTSTRAP_PYTHON):
        raise ValueError("runtime closure supervisor needs root-owned Python")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    measure = sub.add_parser("measure")
    measure.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--manifest-sha256", required=True)
    execute = sub.add_parser("exec")
    execute.add_argument("--manifest", type=Path, required=True)
    execute.add_argument("--manifest-sha256", required=True)
    execute.add_argument("--spec", type=Path, required=True)
    execute.add_argument("--spec-sha256", required=True)
    execute.add_argument("--launcher", type=Path, required=True)
    execute.add_argument("--launcher-sha256", required=True)
    execute.add_argument("--entry", type=Path, required=True)
    execute.add_argument("--entry-sha256", required=True)
    execute.add_argument("entry_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    _stable_file(_BOOTSTRAP_PYTHON, _BOOTSTRAP_PYTHON_SHA256)
    if args.command == "measure":
        return _write_manifest(args.output)
    manifest = _verify_manifest(args.manifest, args.manifest_sha256)
    if args.command == "verify":
        print(json.dumps({"manifest_sha256": args.manifest_sha256,
                          "status": "RUNTIME_CLOSURE_VERIFIED"},
                         sort_keys=True))
        return 0
    spec_raw = _stable_file(args.spec, args.spec_sha256)
    spec = json.loads(spec_raw)
    optin = spec.get("sp_live_admission") if type(spec) is dict else None
    supervisor = Path(__file__).resolve()
    _verify_bootstrapped_exec(supervisor, manifest["supervisor_sha256"])
    if (type(optin) is not dict or
            optin.get("runtime_python_path") !=
                manifest["runtime_python_path"] or
            optin.get("runtime_python_sha256") !=
                manifest["runtime_python_sha256"] or
            optin.get("runtime_closure_manifest_path") != str(args.manifest) or
            optin.get("runtime_closure_manifest_sha256") !=
                args.manifest_sha256 or
            optin.get("runtime_closure_supervisor_path") != str(supervisor) or
            optin.get("runtime_closure_supervisor_sha256") !=
                manifest["supervisor_sha256"] or
            optin.get("pinned_launcher_path") != str(args.launcher) or
            optin.get("pinned_launcher_sha256") != args.launcher_sha256 or
            optin.get("live_entry_sha256") != args.entry_sha256):
        raise ValueError("signed spec runtime closure binding changed")
    _pin(args.launcher, args.launcher_sha256, "pinned launcher")
    _pin(args.entry, args.entry_sha256, "pinned entry")
    forwarded = list(args.entry_args)
    if forwarded[:1] == ["--"]:
        forwarded.pop(0)
    if not forwarded:
        raise ValueError("signed entry arguments are absent")
    environment = _clean_environment()
    environment.update({
        "FBV2_RUNTIME_CLOSURE_MANIFEST_PATH": str(args.manifest),
        "FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256": args.manifest_sha256,
        "FBV2_RUNTIME_CLOSURE_SPEC_PATH": str(args.spec),
        "FBV2_RUNTIME_CLOSURE_SPEC_SHA256": args.spec_sha256,
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH": str(supervisor),
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256":
            manifest["supervisor_sha256"],
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID": str(os.getpid()),
        "FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256":
            manifest["bootstrap_source_sha256"],
    })
    process = subprocess.Popen([
        manifest["runtime_python_path"], "-I", "-S", "-B",
        str(args.launcher), "--entry", str(args.entry),
        "--entry-sha256", args.entry_sha256, "--", *forwarded,
    ], env=environment, close_fds=True)
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
