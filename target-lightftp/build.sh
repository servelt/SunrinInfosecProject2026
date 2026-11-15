#!/bin/bash
# LightFTP 7ea0a8f 를 분석에 필요한 세 가지 형태로 빌드한다.
# 원본 source/ 는 수정하지 않는다. 산출물은 cov/, trace/, analysis/ 에 생긴다.
#
#   cov/       gcov 커버리지 빌드. 시드가 실제로 뭘 실행했는지 측정하는 데 쓴다.
#   trace/     함수 진입 추적 빌드. 입력을 읽는 스레드가 어떤 함수를 도는지 기록한다.
#   analysis/  compile_commands.json. 정적 분석과 하네스 빌드가 참고한다.
set -eu
cd "$(dirname "$0")"
HERE="$PWD"
HC="${HC:-$HERE/../harnesscreator}"
PY="${PY:-/root/pwnenv/bin/python}"

echo "[1/3] analysis/compile_commands.json"
mkdir -p analysis
"$PY" - "$HERE" <<'EOF' > analysis/compile_commands.json
import json, sys, pathlib
root = pathlib.Path(sys.argv[1], "source").resolve()
# -fcommon 이 반드시 필요하다. LightFTP 는 헤더에서 g_cfg / g_log 를
# extern 없이 선언하므로(tentative definition) GCC 10 / Clang 11 부터의
# 기본값 -fno-common 으로는 "multiple definition" 으로 링크가 깨진다.
print(json.dumps([
    {"directory": str(root), "file": str(root / name),
     "arguments": ["/usr/bin/clang", "-O1", "-g", "-fcommon", "-I", str(root),
                   "-pthread", "-c", str(root / name), "-o", str(root / name.replace(".c", ".o"))]}
    for name in ("cfgparse.c", "ftpserv.c", "main.c")], indent=2))
EOF
echo "      $(grep -c '"file"' analysis/compile_commands.json) 개 항목"

echo "[2/3] cov/  (gcc + --coverage)"
# gcc 를 쓴다. clang-14 가 내는 gcov 형식(408*)은 시스템 gcov 가 읽지 못한다.
# fba_gcov_flush.c 는 SIGTERM/SIGINT 에 __gcov_dump() 를 불러 카운터를 내린다.
# LightFTP 에는 종료 핸들러가 없어서 이게 없으면 .gcda 가 전혀 생기지 않는다.
rm -rf cov && mkdir -p cov && cp source/*.c source/*.h fba_gcov_flush.c cov/
( cd cov && gcc -O0 -g -fcommon --coverage -I. -pthread \
    -o fftp cfgparse.c ftpserv.c main.c fba_gcov_flush.c -lcrypt )
echo "      cov/fftp"

echo "[3/3] trace/  (clang + -finstrument-functions)"
rm -rf trace && mkdir -p trace && cp source/*.c source/*.h trace/
PYTHONPATH="$HC/src" "$PY" -m harnesscreator.cli thread-trace-hook trace/hook.o > /dev/null
( cd trace && clang -O0 -g -fcommon -finstrument-functions -I. -pthread \
    -o fftp cfgparse.c ftpserv.c main.c hook.o -lcrypt )
echo "      trace/fftp"

echo "[+]   run/fftp.conf"
# 설정 파일의 경로는 절대 경로여야 하고, 이 체크아웃 위치에 맞게 다시 쓴다.
mkdir -p run/share
sed "s|@HERE@|$HERE|g" fftp.conf.in > run/fftp.conf
: > run/fftp.log

echo
echo "완료. 다음으로:  bash ../run-lightftp.sh 3"
