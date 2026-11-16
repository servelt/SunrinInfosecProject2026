#!/bin/bash
# Occulta 대상 준비: WORK/source 에 받아 둔 tinyproxy 를 분석 입력으로 만든다.
#   configure → compile_commands.json → cov/ trace/ daemon-*/ run/  (build.sh)
# "[prep] 이름" 줄이 진행 표시줄의 단계가 된다.
set -eu
cd "$WORK"
echo "[prep] configure"
( cd source && CC=clang ./autogen.sh > "$WORK/configure.log" 2>&1 )
echo "[prep] 컴파일 DB"
mkdir -p analysis
( cd source && bear --output "$WORK/analysis/compile_commands.json" -- make -C src -j"$(nproc)" > "$WORK/make.log" 2>&1 )
echo "[prep] 분석용 빌드"
cp "$PROFILE/build.sh" "$PROFILE/tinyproxy.conf.in" "$WORK/"
bash "$WORK/build.sh" > "$WORK/build.log" 2>&1
echo "[prep] 완료"
