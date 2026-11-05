#!/bin/sh
set -eu

probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker run --rm --security-opt seccomp=unconfined --platform linux/amd64 \
  -v "$probe_dir:/probe:ro" \
  gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 \
  bash -lc '
    set -eu
    clang -fsanitize=dataflow -fPIC -shared -O0 -g \
      /probe/probe_interpose.c -ldl -o /tmp/io-label.so
    clang -fno-sanitize=dataflow -O0 -g -c \
      /probe/probe_wrap_read.c -o /tmp/wrap-read.o
    clang -fsanitize=dataflow -mllvm -dfsan-reaches-function-callbacks \
      -DUSE_READ -no-pie -O0 -g /probe/probe_interpose_main.c \
      /tmp/wrap-read.o -Wl,--wrap=__dfsw_read -pthread -o /tmp/read-wrapped
    clang -fsanitize=dataflow -mllvm -dfsan-reaches-function-callbacks \
      -DUSE_READ -no-pie -O0 -g /probe/probe_interpose_main.c \
      -pthread -o /tmp/read-unwrapped
    for mode in wrapped unwrapped; do
      count=0
      while [ "$count" -lt 20 ]; do
        output=$(LD_PRELOAD=/tmp/io-label.so /tmp/read-$mode 2>&1)
        if [ "$mode" = wrapped ]; then
          printf "%s" "$output" | grep -q "WRAPPED_READ count=1"
          printf "%s" "$output" | grep -q "HANDLER_LABEL=1"
          printf "%s" "$output" | grep -q "REACH handle_request"
        else
          printf "%s" "$output" | grep -q "HANDLER_LABEL=0"
          if printf "%s" "$output" | grep -q "REACH handle_request"; then
            exit 1
          fi
        fi
        count=$((count + 1))
      done
      printf "%s: %s/20\n" "$mode" "$count"
    done
  '
