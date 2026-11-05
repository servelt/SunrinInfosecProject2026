#!/bin/sh
set -eu

probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lightftp_copy=/tmp/hc-lightftp-dfsan-20261031
test -x "$lightftp_copy/fftp-dfsan"
docker run --rm --security-opt seccomp=unconfined --platform linux/amd64 \
  -v "$probe_dir:/probe:ro" -v "$lightftp_copy:/app:ro" \
  gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 \
  bash -lc '
    set -eu
    clang -fsanitize=dataflow -fPIC -shared -O0 -g \
      /probe/probe_interpose.c -ldl -o /tmp/recv-label.so
    python3 - <<"PY"
import os
import pathlib
import socket
import subprocess
import time

template = pathlib.Path("/app/fftp-dfsan.conf").read_text()
for index, mode in enumerate(("control", "strict", "loose")):
    port = 22610 + index
    config = pathlib.Path(f"/tmp/fftp-{mode}.conf")
    config.write_text(template.replace("port=22445", f"port={port}"))
    env = os.environ.copy()
    env["LD_PRELOAD"] = "/tmp/recv-label.so"
    env["HC_TRACE_ACQUIRE"] = "1"
    env["HC_TRACE_CONDITIONS"] = "1"
    if mode == "control":
        env["HC_DISABLE_LABEL"] = "1"
    elif mode == "loose":
        env["DFSAN_OPTIONS"] = "strict_data_dependencies=0"
    process = subprocess.Popen(
        ["/app/fftp-dfsan", str(config)], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        for attempt in range(100):
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                break
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError(f"{mode}: server exited before listening")
                time.sleep(0.02)
        else:
            raise RuntimeError(f"{mode}: server did not listen")
        with client:
            client.settimeout(2)
            prelude = client.recv(1024)
            assert b"220" in prelude, (mode, prelude)
            client.sendall(b"NOOP\r\n")
            reply = client.recv(1024)
            assert b"200" in reply, (mode, reply)
    finally:
        process.terminate()
        stdout, trace = process.communicate(timeout=5)
    acquires = trace.count("ACQUIRE recv")
    reaches = trace.count("REACH ")
    conditions = trace.count("CONDITION ")
    print(f"{mode}: acquire={acquires} reaches={reaches} conditions={conditions}")
PY
  '
