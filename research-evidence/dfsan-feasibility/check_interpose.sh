#!/bin/sh
set -eu

probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker run --rm --security-opt seccomp=unconfined --platform linux/amd64 \
  -v "$probe_dir:/probe:ro" \
  gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 \
  bash -lc '
    set -eu
    clang -fsanitize=dataflow -fPIC -shared -O0 -g \
      /probe/probe_interpose.c -ldl -o /tmp/recv-label.so
    clang -fsanitize=dataflow -mllvm -dfsan-reaches-function-callbacks \
      -no-pie -O0 -g /probe/probe_interpose_main.c -pthread -o /tmp/recv-probe
    for mode in labeled control; do
      success=0
      count=0
      while [ "$count" -lt 20 ]; do
        if [ "$mode" = labeled ]; then
          output=$(LD_PRELOAD=/tmp/recv-label.so /tmp/recv-probe 2>&1)
          printf "%s" "$output" | grep -q "HANDLER_LABEL=1"
          printf "%s" "$output" | grep -q "REACH handle_request"
        else
          output=$(/tmp/recv-probe 2>&1)
          printf "%s" "$output" | grep -q "HANDLER_LABEL=0"
          if printf "%s" "$output" | grep -q "REACH handle_request"; then
            exit 1
          fi
        fi
        success=$((success + 1))
        count=$((count + 1))
      done
      printf "%s: %s/20\n" "$mode" "$success"
    done
  '
