#!/bin/sh
set -eu

probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker run --rm --security-opt seccomp=unconfined --platform linux/amd64 \
  -v "$probe_dir:/probe:ro" \
  gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 \
  bash -lc '
    set -eu
    clang++ -stdlib=libc++ -DHC_DFSAN_DIAG -fsanitize=dataflow \
      -mllvm -dfsan-reaches-function-callbacks \
      -mllvm -dfsan-conditional-callbacks -O0 -g \
      -c /probe/probe_scope_threaded.cpp -o /tmp/threaded.o
    # This one-file probe has only C++ runtime symbols among the unresolved
    # DFSan calls. A real multi-object build must resolve project symbols first.
    nm -u /tmp/threaded.o | awk "/[.]dfsan$/ {sub(/[.]dfsan$/, \"\", \$2); print \"fun:\" \$2 \"=uninstrumented\\nfun:\" \$2 \"=discard\"}" \
      > /tmp/cpp-runtime-abi.txt
    for variant in memcmp inline; do
      extra=""
      if [ "$variant" = inline ]; then extra="-DHC_INLINE_COMPARE"; fi
      clang++ -stdlib=libc++ -DHC_DFSAN_DIAG $extra -fsanitize=dataflow \
        -mllvm -dfsan-reaches-function-callbacks \
        -mllvm -dfsan-conditional-callbacks \
        -mllvm -dfsan-abilist=/tmp/cpp-runtime-abi.txt \
        -no-pie -O0 -g /probe/probe_scope_threaded.cpp \
        -pthread -o "/tmp/threaded-cpp-$variant"
    done
    clang -fsanitize=dataflow -fPIC -shared -O0 -g \
      /probe/probe_interpose.c -ldl -o /tmp/recv-label.so
    python3 - <<"PY"
import os
import socket
import subprocess

for variant in ("memcmp", "memcmp_loose", "inline"):
  for mode in ("same", "worker"):
    for labeled in (True, False):
        reaches = 0
        conditions = 0
        for _ in range(20):
            env = os.environ.copy()
            if labeled:
                env["LD_PRELOAD"] = "/tmp/recv-label.so"
                env["HC_TRACE_ACQUIRE"] = "1"
                env["HC_TRACE_CONDITIONS"] = "1"
            if variant == "memcmp_loose":
                env["DFSAN_OPTIONS"] = "strict_data_dependencies=0"
            binary_variant = "memcmp" if variant == "memcmp_loose" else variant
            with subprocess.Popen(
                [f"/tmp/threaded-cpp-{binary_variant}", mode], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) as process:
                port = int(process.stdout.readline().strip())
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.sendall(b"HELLO")
                    reply = client.recv(64)
                _, trace = process.communicate(timeout=5)
                reaches += trace.count("REACH ")
                conditions += trace.count("CONDITION ")
                assert process.returncode == 0, (mode, labeled, trace)
                assert reply == b"OK\n", (mode, labeled, reply, trace)
                if labeled:
                    assert "ACQUIRE recv" in trace, (mode, trace)
                    assert "HANDLER_LABEL=1" in trace, (mode, trace)
                else:
                    assert "HANDLER_LABEL=0" in trace, (mode, trace)
                    assert "REACH " not in trace, (mode, trace)
        label_name = "labeled" if labeled else "control"
        if variant in ("inline", "memcmp_loose") and labeled:
            assert reaches > 0 and conditions > 0, (variant, mode, reaches, conditions)
        if not labeled:
            assert reaches == 0 and conditions == 0, (variant, mode, reaches, conditions)
        print(f"{variant}/{mode}: {label_name} 20/20 reaches={reaches} conditions={conditions}")
PY
  '
