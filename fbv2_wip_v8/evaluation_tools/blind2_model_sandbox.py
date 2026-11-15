"""Run a static Codex App Server in a minimal filesystem namespace.

Usage: python blind2_model_sandbox.py /absolute/path/to/codex app-server --stdio
The caller must separately enforce model-turn budgets and reject tool-use events.
"""

from __future__ import annotations

import json
import ctypes
import os
import signal
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


class SandboxError(RuntimeError):
    pass


def _die_with_parent(expected_parent: int) -> None:
    """Kill unshare if its launcher dies, including a direct SIGKILL.

    This runs in the single-threaded launcher's forked child before exec.
    unshare's --kill-child then terminates namespace PID 1.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent:
        os._exit(126)


def _self_test_paths(args: list[str], *, check_host: bool) -> list[str]:
    if not args or args[0] != "--self-test" or len(args) < 3 or len(args[1:]) % 2:
        raise SandboxError("self-test requires one or more --deny-path absolute paths")
    paths: list[str] = []
    for index in range(1, len(args), 2):
        name = args[index + 1]
        if args[index] != "--deny-path" or not name.startswith("/") or "\x00" in name:
            raise SandboxError("self-test deny paths must be absolute")
        path = Path(name)
        if path.as_posix() != name or ".." in path.parts or name in paths:
            raise SandboxError("self-test deny paths must be canonical and unique")
        if check_host and (not path.exists() or path.is_symlink()):
            raise SandboxError("self-test deny path missing or linked on host")
        paths.append(name)
    return paths


def _static_elf(path: Path) -> bool:
    """A PT_INTERP binary would need a host dynamic loader, so reject it."""
    try:
        with path.open("rb") as handle:
            header = handle.read(64)
            if len(header) != 64 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01":
                return False
            phoff = struct.unpack_from("<Q", header, 32)[0]
            phentsize = struct.unpack_from("<H", header, 54)[0]
            phnum = struct.unpack_from("<H", header, 56)[0]
            if phentsize < 56 or not 0 < phnum <= 4096:
                return False
            handle.seek(phoff)
            for _ in range(phnum):
                row = handle.read(phentsize)
                if len(row) != phentsize or struct.unpack_from("<I", row)[0] == 3:
                    return False
            return True
    except (OSError, OverflowError, struct.error):
        return False


def _mount(*args: str) -> None:
    subprocess.run(("/usr/bin/mount", *args), check=True, stdout=subprocess.DEVNULL)


def _copy(source: Path, destination: Path, *, limit: int = 4 * 1024 * 1024) -> None:
    if not source.is_file():
        raise SandboxError(f"required sandbox input missing: {source.name}")
    with source.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise SandboxError(f"sandbox input too large: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    destination.chmod(0o600)


def _bind(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise SandboxError(f"required host file missing: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.touch(exist_ok=True)
    _mount("--bind", str(source), str(destination))
    _mount("-o", "remount,bind,ro,nosuid,nodev", str(destination))


def _env() -> dict[str, str]:
    result = {
        "HOME": "/home/model", "CODEX_HOME": "/home/model/.codex",
        "PATH": "/bin", "TMPDIR": "/tmp", "XDG_CACHE_HOME": "/tmp/cache",
        "LANG": "C.UTF-8", "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    }
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"):
        if value := os.environ.get(name):
            result[name] = value
    return result


def _drop_capabilities() -> None:
    """The model needs no mount or chroot power after setup."""
    libc = ctypes.CDLL(None, use_errno=True)
    pr_set_no_new_privs = 38
    pr_capbset_drop = 24
    if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
        raise SandboxError("could not enable no_new_privs")
    try:
        cap_last = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    except (OSError, ValueError) as exc:
        raise SandboxError("could not determine Linux capability range") from exc
    for capability in range(cap_last + 1):
        if libc.prctl(pr_capbset_drop, capability, 0, 0, 0) != 0:
            raise SandboxError("could not drop Linux capability bounding set")

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise SandboxError("could not clear Linux capabilities")


def _inside(root: Path, executable: Path, state: Path, args: list[str]) -> int:
    if os.getpid() != 1 or os.geteuid() != 0:
        raise SandboxError("user/PID namespace was not established")
    # unshare is this process's parent. If it dies outside the PID namespace,
    # kill PID 1 so the kernel also terminates any children in this namespace.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise SandboxError("could not tie namespace lifetime to unshare")
    _mount("--make-rprivate", "/")
    _mount("-t", "tmpfs", "-o", "size=256m,mode=0700,nosuid", "tmpfs", str(root))
    for name in ("bin", "dev", "etc", "etc/ssl/certs", "proc", "tmp", "work", "home/model/.codex"):
        (root / name).mkdir(parents=True, exist_ok=True)
    _bind(executable, root / "bin/codex")
    for name in ("null", "urandom", "random", "zero"):
        source, destination = Path("/dev") / name, root / "dev" / name
        destination.touch()
        _mount("--bind", str(source), str(destination))
    for name in ("/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs/ca-certificates.crt"):
        _copy(Path(name), root / name.lstrip("/"), limit=2 * 1024 * 1024)
    for name in ("auth.json", "config.toml"):
        _copy(state / name, root / "home/model/.codex" / name)
    (root / "etc/passwd").write_text("root:x:0:0:model:/home/model:/bin/false\n")
    (root / "etc/group").write_text("root:x:0:\n")
    _mount("-t", "proc", "-o", "nosuid,nodev,noexec,hidepid=2", "proc", str(root / "proc"))
    os.chroot(root)
    os.chdir("/work")
    os.closerange(3, 65536)
    _drop_capabilities()
    if args and args[0] == "--self-test":
        denied_paths = _self_test_paths(args, check_host=False)
        numeric_pids = sorted(name for name in os.listdir("/proc") if name.isdecimal())
        status = Path("/proc/self/status").read_text()
        checks = {
            "cwd_is_empty_work": os.getcwd() == "/work" and not os.listdir("/work"),
            "host_home_hidden": not os.path.exists("/home/dawne"),
            "host_mnt_hidden": not os.path.exists("/mnt"),
            "model_state_copied": all(os.path.isfile(f"/home/model/.codex/{name}")
                                      and not os.path.islink(f"/home/model/.codex/{name}")
                                      for name in ("auth.json", "config.toml")),
            "private_proc": os.getpid() == 1 and numeric_pids == ["1"]
                            and not os.path.exists("/proc/1/root/mnt"),
            "capabilities_dropped": "CapEff:\t0000000000000000" in status
                                    and "CapBnd:\t0000000000000000" in status,
            "contract_paths_hidden": all(not os.path.lexists(path)
                                         and not os.path.lexists("/proc/1/root" + path)
                                         for path in denied_paths),
        }
        print(json.dumps({"status": "PASS" if all(checks.values()) else "FAIL",
                          "checks": checks, "deny_path_count": len(denied_paths)}, sort_keys=True))
        return 0 if all(checks.values()) else 126
    os.execve("/bin/codex", ["/bin/codex", *args], _env())
    return 127


def _outside(executable_name: str, args: list[str]) -> int:
    executable = Path(executable_name)
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise SandboxError("Codex executable must be an absolute executable file")
    executable = executable.resolve(strict=True)
    if not _static_elf(executable):
        raise SandboxError("Codex executable must be a static ELF64 binary")
    state_name = os.environ.get("CODEX_HOME")
    if not state_name:
        raise SandboxError("CODEX_HOME is required")
    state = Path(state_name).resolve(strict=True)
    if not state.is_dir() or any(not (state / n).is_file() for n in ("auth.json", "config.toml")):
        raise SandboxError("CODEX_HOME must contain auth.json and config.toml")
    root = Path(tempfile.mkdtemp(prefix="blind2-model-root-", dir="/tmp"))
    try:
        # The inner setup runs before chroot, so use the exact interpreter that
        # started this frozen launcher instead of assuming a host installation
        # path that may differ across WSL machines.
        interpreter = Path(sys.executable).resolve(strict=True)
        if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
            raise SandboxError("Python interpreter is not an executable file")
        cmd = ["/usr/bin/unshare", "-Urmp", "--fork", "--kill-child=SIGKILL", str(interpreter), str(Path(__file__).resolve()),
               "--inner", str(root), str(executable), str(state), *args]
        # Inherit the runner's process group. The 24-hour supervisor kills that
        # group; making a new session here would let the model outlive the cap.
        parent_pid = os.getpid()
        child = subprocess.Popen(cmd, close_fds=True,
                                 preexec_fn=lambda: _die_with_parent(parent_pid))
        old_handlers: dict[signal.Signals, object] = {}

        def forward(signum: int, _frame: object) -> None:
            if child.poll() is None:
                try:
                    os.kill(child.pid, signum)
                except ProcessLookupError:
                    pass

        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                old_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, forward)
            return child.wait()
        finally:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if len(args) >= 4 and args[0] == "--inner":
            return _inside(Path(args[1]), Path(args[2]), Path(args[3]), args[4:])
        if len(args) >= 4 and args[0] == "--self-test":
            _self_test_paths(["--self-test", *args[2:]], check_host=True)
            return _outside(args[1], ["--self-test", *args[2:]])
        if not args or args[0].startswith("-"):
            raise SandboxError("usage: blind2_model_sandbox.py <static-codex-executable> [arguments...]")
        return _outside(args[0], args[1:])
    except (SandboxError, OSError, subprocess.CalledProcessError) as exc:
        print(f"blind2 model sandbox blocked launch: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
