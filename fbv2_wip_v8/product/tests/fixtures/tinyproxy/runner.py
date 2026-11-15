#!/usr/bin/env python3
"""Local-only process harness for a blind Tinyproxy regression.

This is a regression fixture, not HarnessCreator output. It starts the
unmodified Tinyproxy binary and sends file bytes through its normal TCP
listener to a loopback-only origin server.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


ORIGIN_PORT = 18181


def origin_once(listener: socket.socket) -> None:
    try:
        listener.settimeout(5)
        client, _ = listener.accept()
        with client:
            client.settimeout(3)
            try:
                client.recv(65536)
            except socket.timeout:
                pass
            client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
    except (OSError, socket.timeout):
        pass
    finally:
        listener.close()


def run(binary: Path, input_file: Path) -> int:
    if not binary.is_file() or not input_file.is_file():
        print("target binary or input missing", file=sys.stderr)
        return 2
    payload = input_file.read_bytes()
    if len(payload) > 2_097_152:
        print("input exceeds fixture budget", file=sys.stderr)
        return 2
    with socket.socket() as origin:
        origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        origin.bind(("127.0.0.1", ORIGIN_PORT))
        origin.listen(1)
        threading.Thread(target=origin_once, args=(origin,), daemon=True).start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            proxy_port = reservation.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="va-tinyproxy-") as tmp:
            config = Path(tmp) / "tinyproxy.conf"
            config.write_text(
                f"Port {proxy_port}\nListen 127.0.0.1\nTimeout 3\n"
                "LogLevel Error\nMaxClients 4\nAllow 127.0.0.1\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
            env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
            proc = subprocess.Popen([str(binary), "-d", "-c", str(config)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, env=env)
            transport_failed = False
            try:
                deadline = time.monotonic() + 5
                while True:
                    if proc.poll() is not None:
                        raise RuntimeError("Tinyproxy exited before accepting a client")
                    try:
                        client = socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2)
                        client.close()
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError("Tinyproxy did not accept a loopback client")
                        time.sleep(0.05)
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as client:
                    client.settimeout(4)
                    client.sendall(payload)
                    client.shutdown(socket.SHUT_WR)
                    response = bytearray()
                    while len(response) < 131_072:
                        try:
                            part = client.recv(8192)
                        except (socket.timeout, ConnectionResetError):
                            break
                        if not part:
                            break
                        response.extend(part)
                sys.stdout.buffer.write(response)
                time.sleep(0.2)
            except (OSError, RuntimeError) as exc:
                transport_failed = True
                print(f"fixture transport error: {exc}", file=sys.stderr)
            finally:
                crashed = proc.poll() is not None and proc.returncode != 0
                if proc.poll() is None:
                    proc.terminate()
                try:
                    out, err = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, err = proc.communicate()
                if out:
                    sys.stdout.write(out)
                if err:
                    sys.stderr.write(err)
                if crashed:
                    return proc.returncode or 1
                if transport_failed:
                    return 2
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: runner.py TARGET_BINARY INPUT_FILE")
    raise SystemExit(run(Path(sys.argv[1]), Path(sys.argv[2])))
