"""Replay one input against the real program, started as a server, over its own socket.

This is the strongest of the checks before a finding is called a vulnerability: the bytes go
through the program's actual network interface, with no harness code in the process at all.
A fault the harness alone produces -- a missing initialisation the real startup performs, a
state the harness forces -- does not reproduce here.

Run as `python -m fbaugur.daemon_replay SPEC.json` inside a private network namespace (the
caller wraps it in `unshare -n`), so the program's fixed port cannot collide with anything.
Prints one JSON object: whether the program started, what was sent, and its exit status and
stderr, which the caller parses like any sanitizer report.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time


def _wait_listening(host: str, port: int, kind: int, deadline: float, process) -> bool:
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        if kind == socket.SOCK_DGRAM:
            time.sleep(0.5)               # UDP has no handshake; give the program time to bind
            return process.poll() is None
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True               # this probe connection is closed at once, as a real
        except OSError:                   # peer that gives up would do
            time.sleep(0.1)
    return False


def _send_stream(host: str, port: int, data: bytes, io_timeout: float) -> dict:
    sent = 0
    received = 0
    head = bytearray()
    with socket.create_connection((host, port), timeout=io_timeout) as conn:
        conn.settimeout(io_timeout)
        try:
            conn.sendall(data)
            sent = len(data)
            conn.shutdown(socket.SHUT_WR)
            while True:                   # wait for the program to close: processing is done
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
                if len(head) < 4096:
                    head.extend(chunk[:4096 - len(head)])
        except OSError:
            pass                          # a reset is what a crashing server looks like
    return {"sent": sent, "received": received, "response_hex": bytes(head).hex()}


def _send_peer(host: str, port: int, trigger: bytes, data: bytes, io_timeout: float) -> dict:
    """peer_stream: make the program connect to a listener here, then send `data` as that peer.

    The trigger goes to the program's own endpoint with {PEER_HOST}/{PEER_PORT} naming the
    listener; the program's outbound connection receives the input.  What the program sends back
    on the trigger connection is the response recorded.
    """
    received = 0
    head = bytearray()
    with socket.create_server((host, 0)) as listener, socket.create_connection((host, port), timeout=io_timeout) as client:
        listener.settimeout(io_timeout)
        client.settimeout(io_timeout)
        peer_port = listener.getsockname()[1]
        if trigger:
            client.sendall(trigger.replace(b"{PEER_HOST}", host.encode()).replace(b"{PEER_PORT}", str(peer_port).encode()))
        try:
            peer, _ = listener.accept()
        except OSError:
            return {"sent": 0, "received": 0, "response_hex": "", "peer_error": "the program did not connect"}
        with peer:
            peer.settimeout(io_timeout)
            try:
                peer.sendall(data)
                peer.shutdown(socket.SHUT_WR)
                while peer.recv(65536):
                    pass
            except OSError:
                pass
        try:
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
                if len(head) < 4096:
                    head.extend(chunk[:4096 - len(head)])
        except OSError:
            pass
    return {"sent": len(data), "received": received, "response_hex": bytes(head).hex()}


def _send_datagrams(host: str, port: int, data: bytes) -> dict:
    """Same framing as the datagram harnesses: 2-byte big-endian length, then the payload."""
    packets, offset = [], 0
    while offset + 2 <= len(data):
        size = int.from_bytes(data[offset:offset + 2], "big")
        packets.append(data[offset + 2:offset + 2 + size])
        offset += 2 + size
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for packet in packets:
            sock.sendto(packet, (host, port))
            sent += len(packet)
            time.sleep(0.02)
    return {"sent": sent, "packets": len(packets)}


def _run_once(spec: dict, data: bytes) -> dict:
    """stdin / file delivery: the program reads one input and exits, so each run is a new process.

    The command names the input as {input_file} (file) or reads it on standard input (stdin)."""
    with tempfile.TemporaryDirectory(prefix="replay-") as tmp:
        path = os.path.join(tmp, "input")
        with open(path, "wb") as handle:
            handle.write(data)
        argv = [word.replace("{input_file}", path) for word in shlex.split(spec["command"])]
        try:
            done = subprocess.run(argv, cwd=spec.get("cwd") or None, input=data if spec.get("delivery") == "stdin" else None,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                  env=dict(os.environ, **spec.get("env", {})),
                                  timeout=float(spec.get("io_timeout", 10)) + float(spec.get("startup_timeout", 15)))
            return {"returncode": done.returncode, "stderr": done.stderr.decode("utf-8", "replace")[-60000:],
                    "timed_out": False}
        except subprocess.TimeoutExpired as exc:
            return {"returncode": None, "stderr": (exc.stderr or b"").decode("utf-8", "replace")[-60000:],
                    "timed_out": True}


def _main_once(spec: dict) -> int:
    data = bytes.fromhex(spec["input_hex"])
    result: dict = {"started": True, "sent": len(data), "received": 0, "response_hex": ""}
    runs, stderr, returncode = 0, "", 0
    for _ in range(max(1, int(spec.get("repeat", 1)))):
        once = _run_once(spec, data)
        runs += 1
        stderr, returncode = once["stderr"], once["returncode"]
        # A run that dies of a signal or a sanitizer report is the finding; stop there.
        if returncode is None or returncode < 0 or "Sanitizer" in stderr:
            break
    result.update({"runs_sent": runs, "returncode": returncode, "stderr": stderr,
                   "crashed_on_its_own": returncode is not None and returncode < 0})
    print(json.dumps(result))
    return 0


def main(spec_path: str) -> int:
    spec = json.loads(open(spec_path, encoding="utf-8").read())
    if spec.get("delivery") in ("stdin", "file"):
        return _main_once(spec)
    host, port = spec.get("host", "127.0.0.1"), int(spec["port"])
    kind = socket.SOCK_DGRAM if spec.get("delivery") == "datagram" else socket.SOCK_STREAM
    data = bytes.fromhex(spec["input_hex"])
    err = tempfile.NamedTemporaryFile(prefix="daemon-", suffix=".stderr", delete=False)
    process = subprocess.Popen(shlex.split(spec["command"]), cwd=spec.get("cwd") or None,
                               stdout=subprocess.DEVNULL, stderr=err, stdin=subprocess.DEVNULL,
                               env=dict(os.environ, **spec.get("env", {})), start_new_session=True)
    result: dict = {"started": False}
    try:
        if not _wait_listening(host, port, kind, time.time() + float(spec.get("startup_timeout", 15)), process):
            result["error"] = "the program did not start listening" if process.poll() is None else \
                f"the program exited during startup (status {process.returncode})"
        else:
            result["started"] = True
            # `repeat` sends the same input again on new connections while the program lives:
            # how a normal build is checked for an effect that one request does not show.
            runs = 0
            for _ in range(max(1, int(spec.get("repeat", 1)))):
                if process.poll() is not None:
                    break
                try:
                    if kind == socket.SOCK_DGRAM:
                        sent = _send_datagrams(host, port, data)
                    elif spec.get("delivery") == "peer_stream":
                        sent = _send_peer(host, port, bytes.fromhex(spec.get("trigger_hex", "")), data,
                                          float(spec.get("io_timeout", 10)))
                    else:
                        sent = _send_stream(host, port, data, float(spec.get("io_timeout", 10)))
                except OSError as exc:
                    # Refused: the program is no longer listening (it died after the last
                    # request).  Counting this as a request would say it died later than it did.
                    result["send_error"] = str(exc)
                    break
                runs += 1
                if "sent" not in result:
                    result.update(sent)
                # A program that dies of this request does so a moment after answering; without
                # this wait the next connection lands in the dying program's backlog and the death
                # is put on a later request than the one that caused it.
                watch = time.time() + float(spec.get("between", 0.2))
                while time.time() < watch and process.poll() is None:
                    time.sleep(0.02)
            result["runs_sent"] = runs
            # A fault in a worker thread can land after the reply; give it a moment.
            settle = time.time() + float(spec.get("settle", 3))
            while time.time() < settle and process.poll() is None:
                time.sleep(0.1)
    finally:
        result["crashed_on_its_own"] = process.poll() is not None
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        result["returncode"] = process.returncode
        err.close()
        with open(err.name, encoding="utf-8", errors="replace") as handle:
            result["stderr"] = handle.read()[-60000:]
        os.unlink(err.name)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
