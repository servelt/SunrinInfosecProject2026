FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake git libncurses5-dev libssl-dev libtinfo6 \
    python3-dev unzip wget xz-utils zip zlib1g-dev libpcre2-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# The Docker build context is the locked, unmodified upstream SVF checkout.
COPY . /opt/SVF
WORKDIR /opt/SVF
RUN SVF_BUILD_JOBS=4 bash ./build.sh

ENV LLVM_DIR=/opt/SVF/llvm-21.1.0.obj
ENV Z3_DIR=/opt/SVF/z3.obj
ENV PATH=/opt/SVF/Release-build/bin:/opt/SVF/llvm-21.1.0.obj/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/SVF/Release-build/lib:/opt/SVF/llvm-21.1.0.obj/lib:/opt/SVF/z3.obj/bin

RUN mkdir -p /opt/harnesscreator && printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'mkdir -p /output/modules' \
    'found=0' \
    'for input in /input/*; do' \
    '  [ -f "$input" ] || continue' \
    '  name=$(basename "$input")' \
    '  case "$input" in' \
    '    *.bc) cp "$input" "/output/modules/$name"; found=1 ;;' \
    '    *.i) clang -x c -O0 -g -emit-llvm -c "$input" -o "/output/modules/$name.bc"; found=1 ;;' \
    '    *.ii) clang++ -x c++ -std=gnu++17 -O0 -g -emit-llvm -c "$input" -o "/output/modules/$name.bc"; found=1 ;;' \
    '  esac' \
    'done' \
    '[ "$found" -eq 1 ] || { echo "no bitcode or preprocessed analysis units mounted" >&2; exit 2; }' \
    'set -- /output/modules/*.bc' \
    'llvm-link "$@" -o /output/linked.bc' \
    'wpa -ander -dump-callgraph /output/linked.bc' \
    > /opt/harnesscreator/run-svf.sh \
    && chmod 0755 /opt/harnesscreator/run-svf.sh
