#!/bin/sh
set -eu

probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

common_flags='-fsanitize=dataflow -mllvm -dfsan-conditional-callbacks=true -O0 -g -fno-pie -no-pie'
# Deliberate word splitting of the fixed compiler flag list above.
# shellcheck disable=SC2086
clang $common_flags "$probe_dir/probe.c" -o "$build_dir/input_condition"
# shellcheck disable=SC2086
clang $common_flags -DUNRELATED_CONDITION_ONLY "$probe_dir/probe.c" -o "$build_dir/unrelated_condition"

positive=$(printf A | "$build_dir/input_condition")
negative=$(printf A | "$build_dir/unrelated_condition")
[ "$positive" = 'result=1 tainted_conditions=1' ]
[ "$negative" = 'result=1 tainted_conditions=0' ]
printf '%s\n' "$positive" "$negative"
