"""Compare same-thread and worker-thread request attribution in the C++ probe."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent


def run_case(binary: Path, symbol: str, mode: str) -> tuple[bytes, str]:
    environment = os.environ.copy()
    environment["HC_TARGET_FUNCTION"] = symbol
    with subprocess.Popen(
        [str(binary), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=environment,
    ) as process:
        assert process.stdout is not None
        port = int(process.stdout.readline().strip())
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"HELLO")
            reply = client.recv(64)
        _stdout, stderr = process.communicate(timeout=3)
        if process.returncode != 0:
            raise RuntimeError(f"{mode}: server exit {process.returncode}: {stderr}")
        return reply, stderr


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hc-scope-threaded-") as directory:
        root = Path(directory)
        probe = root / "scope.o"
        binary = root / "scope-threaded"
        subprocess.run([
            "clang", "-O0", "-g", "-c",
            str(ROOT / "probe_request_scope.c"), "-o", str(probe),
        ], check=True)
        subprocess.run([
            "clang++", "-O0", "-g", "-finstrument-functions", "-rdynamic",
            "-no-pie", "-pthread", str(ROOT / "probe_scope_threaded.cpp"),
            str(probe), "-ldl", "-o", str(binary),
        ], check=True)
        symbols = subprocess.check_output([
            "nm", "-D", "--defined-only", str(binary),
        ], text=True).splitlines()
        matches = [line.split()[-1] for line in symbols
                   if "handle_request" in line.split()[-1]]
        if len(matches) != 1:
            raise RuntimeError(f"expected one exported C++ handler, found {matches}")
        same_reply, same_trace = run_case(binary, matches[0], "same")
        worker_reply, worker_trace = run_case(binary, matches[0], "worker")
        if same_reply != b"OK\n" or worker_reply != b"OK\n":
            raise AssertionError("both real requests must succeed")
        if "HC_SCOPE RECV" not in same_trace or "HC_SCOPE ENTER" not in same_trace:
            raise AssertionError("same-thread request was not attributed")
        if "HC_SCOPE RECV" not in worker_trace or "HC_SCOPE ENTER" in worker_trace:
            raise AssertionError("worker-thread counterexample did not reproduce")
        print("same-thread: reply=OK, recv=observed, handler=observed")
        print("worker-thread: reply=OK, recv=observed, handler=missing")


if __name__ == "__main__":
    main()
