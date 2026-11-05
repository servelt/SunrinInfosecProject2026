# memcached와 StateAFL 입력 경로 시험 (2026-10-31)

대상 소스는 `/mnt/c/memcached`의 커밋 `2d51e364799bc9698bd4b11728ea978cea12da6e`를 `git archive`로 `/tmp`에 분리한 복사본이다. 공개 StateAFL 커밋 `d923e22f7b2688db45b08f3fa3a29a566e7ff3a4`의 `afl-clang-fast`로 `./autogen.sh`, `./configure`, `make -j4`를 오프라인 컨테이너에서 실행했다. 원본 작업 디렉터리는 빌드하지 않았다.

계측된 원본 memcached를 시작한 뒤 `hc-replay.py`로 한 TCP 연결에서 `set hc_key 0 0 1\r\nx\r\n` 다음 `get hc_key\r\n`을 보냈다. `hc-replay.json`에는 각각 `STORED\r\n`과 `VALUE hc_key 0 1\r\nx\r\nEND\r\n`이 저장됐다. `hc-export.py`가 이 실제 요청열을 제품의 `export_stateafl_seeds`로 변환했으며, `seed.replay`는 길이 21바이트와 12바이트인 두 요청을 담는다. handler 귀속 근거는 없으므로 manifest의 등급은 `UNPROVEN/diagnostic`이다.

**기존 0비트 판정의 원인 재검토:** 처음 10~25초씩 중단한 시험의 최종 통계에는 bitmap 0비트가 반복됐다 (`hc-stateafl-fuzz.log`, `hc-stateafl-diag.log`). 이를 공유 bitmap 수집 실패로 해석했으나 그 해석은 틀렸다. 임시 진단용 퍼저에서 네트워크 응답 직후의 `trace_bits`는 약 1,200비트, `run_target` 반환 직후에는 1,324비트였다 (`hc-stateafl-map-diag.log`). 그 실행은 시드 보정이 끝나기 전에 `timeout`으로 중단됐으므로 완료된 시드의 `bitmap_size`가 기록되지 않았다. StateAFL 원본 `afl-fuzz.c`는 보정 단계에서 기본 8회, 가변 경로면 40회까지 대상을 반복 실행한다. 이 데몬은 매 실행 약 1초가 걸렸으므로 짧은 시험이 보정 완료를 보장하지 못했다. **따라서 이전의 0비트 최종 통계는 커버리지 미도달 증거로 사용할 수 없다.**

임시 시험 복사본에서 `AFL_FAST_CAL=1`로 보정 반복을 줄인 18초 시험은 시드 보정을 완료했고, bitmap **1,324비트**, 실행 16회, 새 경로 2개를 기록했다 (`hc-stateafl-fastcal.log`, `fuzzer_stats_fastcal`). `AFL_FAST_CAL`은 보정을 덜 정밀하게 만들 수 있으므로 이 시험은 요청열·계측 경로의 **작동 확인**에 한정된다. `-D 500000` 첫 실행도 1,324비트를 기록했지만, 그 밖의 짧은 실행 사이 안정성이나 크래시 진위는 이 결과로 입증되지 않는다. `afl-showmap`은 같은 계측 바이너리의 도움말 경로에서 25개 계측 항목을 기록했다 (`hc-showmap.txt`). 원본 응답도 일부 시도에서는 한 요청 직후 바로 오지 않았으므로, 응답 경계·요청 귀속 검증은 별도로 필요하다.

컨테이너 호스트에서 ASLR이 켜져 있어 공개 StateAFL은 원래 사전 검사에서 종료했다. 퍼징 로그들은 `/tmp`에 분리한 **시험용 복사본에서만 ASLR 사전 검사를 건너뛴** 결과다. 호스트 설정은 변경하지 않았다. 그러므로 상태 추론·크래시 판정의 신뢰성이나 `QUALIFIED` libFuzzer 하네스를 검증한 결과가 아니다.

공개 구현과 `-D` 의미: [StateAFL README](https://github.com/stateafl/stateafl/blob/main/README.md).

## 범용 실행 명령으로 재시험

제품의 `network-fuzz` 명령에 이미 계측한 memcached 실행 파일, 포트 `19099`, 위 `diagnostic` 시드, 실행 대기 `500000`µs와 `-m none`을 **명시적으로** 전달했다. 25초 실행의 [campaign-cli.json](campaign-cli.json)과 [fuzzer_stats_campaign_cli](fuzzer_stats_campaign_cli)에는 대상 실행 23회, 새 경로 2개가 기록됐다. [campaign-cli.log](campaign-cli.log)는 실제 시드 검증·퍼징 로그다. Dropbear에도 **동일 코드 경로**를 사용했으며, 대상별 빌드·실행 인자는 그대로 별개다. 이 재시험 역시 ASLR 사전 검사를 임시 시험 복사본에서만 건너뛰고 `AFL_FAST_CAL=1`을 사용한 연구용 진단이다. 하네스 합격이나 크래시 진위를 주장하지 않는다.
