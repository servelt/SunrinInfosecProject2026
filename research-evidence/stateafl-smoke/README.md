# StateAFL 입력 경로 시험 (2026-10-31)

대상은 이 디렉터리의 작은 `daemon.c`이며, memcached 결과가 아니다. 로컬에 고정한 StateAFL 공개 구현 `d923e22f7b2688db45b08f3fa3a29a566e7ff3a4`를 `/tmp`에 복사해 오프라인 컨테이너에서 빌드했다. `afl-clang-fast`로 `daemon.c`를 계측했고, `replay.py`가 한 TCP 연결에서 `SET a\n`과 `GET a\n`을 실제로 보내 각각 `STORED\n`과 `VALUE\n`을 받았다. `export_seed.py`는 이 관찰을 제품의 `export_stateafl_seeds`에 전달해 `seed.replay`를 만들었다.

`fuzz.log`와 `fuzzer_stats`는 **실험용 StateAFL 복사본**의 25초 실행 결과다. 공개 소스는 이 환경의 ASLR 설정을 감지하고 즉시 종료했으므로, 임시 복사본의 ASLR 사전 검사만 건너뛰었다. 호스트의 ASLR 설정은 변경하지 않았다. 이 실행에서는 627회 실행, 경로 10개 추가, 안정도 87.50%가 기록됐다. 이 수치는 시드 해석과 소켓 실행·커버리지 연결의 스모크 테스트 결과이며, StateAFL 상태 추론의 신뢰성이나 크래시 진위를 검증하지 않는다.

`replay.json`은 원본 데몬의 요청·응답 바이트다. `seed.replay`는 두 요청을 각각 4바이트 길이와 함께 저장한다. 원본 실행에서 응답을 관찰했지만 요청별 handler 귀속은 증명하지 않았으므로 제품 manifest에서는 `diagnostic`으로 분류한다. 여기에는 하네스 생성 또는 `QUALIFIED` 판정 결과가 없다.

공개 구현과 형식 근거: [StateAFL README](https://github.com/stateafl/stateafl/blob/main/README.md).
