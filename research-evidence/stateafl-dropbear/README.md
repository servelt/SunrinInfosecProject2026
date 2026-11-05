# Dropbear: StateAFL 전송 시험 (2026-10-31)

대상은 Dropbear 커밋 `59870ad43153fe8d4f1c96f5d5752116c94f31ff`의 별도 `/tmp` 복사본이다. 공개 StateAFL 커밋 `d923e22f7b2688db45b08f3fa3a29a566e7ff3a4`의 `afl-clang-fast`로 `--disable-zlib --disable-harden` 빌드했다. 이는 Dropbear의 다른 빌드 구성과 동일하다는 주장이 아니다. 요청 `SSH-2.0-dbfuzz\r\n`은 대상 소스의 `fuzz/fuzz-sshpacketmutator.c`에서 가져왔다. 제품 원본 실행기에서 로컬 TCP 쓰기 완료, 다음 응답 0바이트, `UNPROVEN`을 관찰했고 [ssh-ident.replay](ssh-ident.replay)를 `diagnostic` 시드로 저장했다. 이는 서버 수신이나 정상 SSH 협상 완료의 증거가 아니다.

새 `network-fuzz` 명령을 사용해 명시한 계측 서버·포트·시드 등급으로 20초 실행했다. [campaign.json](campaign.json)에는 정확한 인자와 `qualified_harness_claim=false`가 있다. [fuzzer_stats](fuzzer_stats)에는 대상 실행 945회, `paths_found=10`, 안정도 100%, 크래시 0건이 기록됐다. [afl-fuzz.log](afl-fuzz.log)는 초기 시드 검증과 종료 로그다. 이 수치는 제한된 **커버리지 경로 확인**이며 요청별 handler 귀속·정상 상태·취약점 여부의 증거가 아니다.

같은 시드에 StateAFL의 상태 인식 `-E`를 넣으면 [state-aware-failure.log](state-aware-failure.log)처럼 시드 dry run은 계측 비트 974개를 보인 뒤 초기 상태 해시 테이블 오류로 종료한다. 따라서 이 옵션은 기본 경로에서 빼고 명시적으로만 선택하도록 했다. 왜 이 시드에서 상태 추론 자료가 없었는지는 별도 분석이 필요하다.

**시험 한계:** 실험용 StateAFL 복사본은 호스트에서 바꿀 수 없는 ASLR 설정 때문에 `check_aslr()` 사전 검사를 임시로 건너뛰었다. 호스트 ASLR은 바꾸지 않았다. `AFL_FAST_CAL=1`로 시드 보정 반복을 줄였고, `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`로 core dump 사전 검사만 건너뛰었다. 따라서 이 결과를 크래시 신뢰도·상태 추론 정확도·제품 `QUALIFIED` 하네스 판정에 사용하지 않는다. 제품 코드나 공개 StateAFL 원본은 수정하지 않았다.

실행 방식의 근거는 [StateAFL 공개 README](https://github.com/stateafl/stateafl/blob/main/README.md)의 계측 컴파일러, `-N` 서버 주소, 길이 접두어 요청열 형식이다. 이 방식이 임의 데몬의 빌드와 정상 흐름을 자동 복구한다는 근거로 사용하지 않는다.
