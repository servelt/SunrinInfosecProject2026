#!/bin/bash
# tinyproxy 를 분석에 필요한 형태로 빌드한다. source/ 는 autogen+configure 만 거친 원본이다.
#   cov/          gcc --coverage. 시드가 실제로 실행한 함수 측정 (SIGTERM 처리기가 있어 gcov 가 정상 기록된다)
#   trace/        clang -finstrument-functions. 입력을 읽는 스레드가 도는 함수 기록
#   daemon-asan/  ASan+UBSan 데몬. 발견을 하네스 없이 실제 프로그램에 보내 확인하는 데 쓴다
#   daemon-msan/  MemorySanitizer 데몬 (clang >= 18 필요)
#   daemon-plain/ sanitizer 없는 일반 빌드. 발견이 실제로 무슨 일을 하는지 잰다
set -eu
cd "$(dirname "$0")"; HERE="$PWD"
HC="${HC:-$HERE/../harnesscreator}"; PY="${PY:-python3}"
SRC="$HERE/source/src"
# configure 의 릴리스 플래그 중 동작에 영향을 주는 것: -DNDEBUG (빼면 tinyproxy 의 디버그 할당기가 malloc 마다 출력한다)
DEFS=(-DHAVE_CONFIG_H -DNDEBUG "-I$SRC" "-I$HERE/source" '-DSYSCONFDIR="/usr/local/etc/tinyproxy"' '-DLOCALSTATEDIR="/usr/local/var"')
FILES=$(cd "$SRC" && ls *.c)
build() {   # build DIR CC FLAGS... [-- LINKFLAGS...]
  local dir=$1 cc=$2; shift 2
  rm -rf "$dir" && mkdir -p "$dir"
  ( cd "$dir" && for f in $FILES; do "$cc" "${DEFS[@]}" "$@" -c "$SRC/$f" -o "${f%.c}.o"; done )
}
echo "[1/4] cov/"
# 소스를 cov/ 안에 복사해서 컴파일한다. HarnessCreator 는 gcov 가 알려준 소스 경로가 커버리지 루트 안에
# 있을 때만 그 기록을 읽는다(contexts/coverage.py: relative_to(build_root)). 밖에 두면 "gcov produced no
# readable function or line records" 로 시드 검증이 전부 실패한다.
rm -rf cov && mkdir -p cov && cp "$SRC"/*.c "$SRC"/*.h "$HERE/source/config.h" cov/
( cd cov && for f in $FILES; do gcc -DHAVE_CONFIG_H -DNDEBUG -I. '-DSYSCONFDIR="/usr/local/etc/tinyproxy"' \
    '-DLOCALSTATEDIR="/usr/local/var"' -O0 -g --coverage -c "$f" -o "${f%.c}.o"; done && \
  gcc --coverage -o tinyproxy *.o -lpthread )
echo "[2/4] trace/"
build trace clang -O0 -g -finstrument-functions
PYTHONPATH="$HC/src" "$PY" -m harnesscreator.cli thread-trace-hook trace/hook.o > /dev/null
( cd trace && clang -o tinyproxy *.o -lpthread )
echo "[3/4] daemon-asan/"
build daemon-asan clang -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
( cd daemon-asan && clang -fsanitize=address,undefined -no-pie -o tinyproxy *.o -lpthread )
echo "[4/4] daemon-msan/"
MSAN_CC=$(for v in 30 29 28 27 26 25 24 23 22 21 20 19 18; do command -v clang-$v && break; done || true)
if [ -n "$MSAN_CC" ]; then
  build daemon-msan "$MSAN_CC" -O1 -g -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins=2
  ( cd daemon-msan && "$MSAN_CC" -fsanitize=memory -o tinyproxy *.o -lpthread )
else
  echo "      skipped: no clang >= 18"
fi
echo "[+] daemon-plain/  (no sanitizer, as distributions build it: what a finding does in a normal build)"
build daemon-plain gcc -O2 -g
( cd daemon-plain && gcc -o tinyproxy *.o -lpthread )
echo "[+] run/tinyproxy.conf"
mkdir -p run
sed "s|@HERE@|$HERE|g" tinyproxy.conf.in > run/tinyproxy.conf
echo "done"
