#!/bin/bash
# LightFTP 7ea0a8f (2017-04-20) 를 대상으로 하네스 생성부터 취약점 분석까지 한 번에.
#
# 채점 정답 (도구에는 알려주지 않는다. 직접 측정해 둔 값):
#   싱크    writelogentry()  source/ftpserv.c:383   char _text[512] 에 경계검사 없는 strcat
#   경로    ftp_client_thread()  source/ftpserv.c:1790
#           recvcmd() 직후 받은 명령줄 전체를 조건 없이 그 함수로 넘긴다
#   트리거  473 바이트 + CRLF 이상의 아무 명령줄. 인증 불필요
#   확인법  ASan 스택이 __interceptor_strcat -> writelogentry -> ftp_client_thread
#
# 사용법:  bash run-lightftp.sh [시간]        (기본 3시간)
#   예산 산정 근거 (실측값):
#     1단계  Entry 3.9분 + 문맥 1.3분 + 유닛당 (시드 3.7 + 하네스 6.5)분
#     2단계  분석 레인 소진 약 19분, 그 뒤로는 남은 예산 전부 퍼징
#   tcp/stream 문맥이 3개(제어 연결 + STOR/APPE 데이터 연결)라 유닛도 3개까지 나온다.
#   2시간이면 문맥당 퍼징이 9분뿐이라 불변식이 거의 시험되지 않는다. 3시간 권장.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$HERE/target-lightftp"
F="$HERE/fbaugur"
OUT="${OUT:-$HERE/runs}"
PY="${PY:-/root/pwnenv/bin/python}"
HOURS="${1:-3}"

if [ ! -x "$T/cov/fftp" ]; then
  echo "대상이 아직 빌드되지 않았다. 먼저 이걸 실행해라:"
  echo "  bash $T/build.sh"
  exit 1
fi
if pgrep -f "^$PY -m fbaugur.cli pipeline" > /dev/null; then
  echo "이미 돌고 있는 파이프라인이 있다. 커버리지 디렉터리를 공유해서 양쪽 측정이 깨지니 먼저 내려라:"
  pgrep -af "^$PY -m fbaugur.cli pipeline" | sed 's/^/  /'
  exit 1
fi

mkdir -p "$OUT"
cd "$F" || exit 1
echo "예산 ${HOURS}시간 | 1단계 최대 55분 | 2단계는 문맥별로 남은 예산 균등 분배"
echo "로그: $OUT/lightftp.log"

PYTHONPATH=src "$PY" -m fbaugur.cli pipeline "$T/source" \
  --name lightftp \
  --output "$OUT" \
  --coverage-root "$T/cov" \
  --coverage-command "$T/cov/fftp $T/run/fftp.conf" \
  --coverage-cwd "$T/cov" \
  --thread-trace-command "$T/trace/fftp $T/run/fftp.conf" \
  --analysis-compile-database "$T/analysis/compile_commands.json" \
  --port 2121 --channel tcp \
  --python "$PY" \
  --native-extra-cflags=-fcommon \
  --harnesscreator "$HERE/harnesscreator" \
  --max-hours "$HOURS" --harness-max-minutes 55 \
  2>&1 | tee "$OUT/lightftp.log"
echo "종료 코드: ${PIPESTATUS[0]}"
