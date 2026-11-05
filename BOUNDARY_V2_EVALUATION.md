# Entry 이후 워크플로우 재설계 및 Memcached 평가

작성일: 2026-10-26. 이 문서는 실제 실행 산출물로 확인한 사실과 코드·단위 시험으로만 확인한 사실을 구분한다. **현재 Memcached 하네스 생성, 빌드, 실행, 퍼징은 모두 0건이다.** 따라서 Memcached에 대한 하네스 성공이나 경로 동등성은 주장하지 않는다.

## 1. 평가의 출발점과 결론

기존 실행 `20261025-200350-c7084624`는 사용자 제공 집계상 약 22시간 45분 동안 Entry 후보 31개를 평가하여 VERIFIED 17개, REJECTED 9개, UNRESOLVED 5개를 남겼다. 이후 Behavior 후보 1,093개가 모두 POSSIBLE이었고, ExecutionContract 35개는 모두 `evidence_complete=False`였다. 원본 Trial, 하네스, 빌드, 퍼징은 각각 0개였다. 원본 디렉터리는 보존했다.

새 실행 `20261026-202021-3bb89d91`은 기존 Entry 증거를 가져와 약 10분 실행하고 같은 실행 ID로 약 5분 재개했다. 실행 당시에는 21개 Entry를 계획 대상으로 삼아 6개를 선택하고 15개를 보류했다. 누적 스냅샷에 Behavior 후보 29개, ExecutionContract 3개, 입력 사례 7개, 원본 Trial 7개가 남았다. 작업 단위 기록은 50줄이며 고유 ID는 29개다. 재개 당시 21개 ID가 중복 추가된 기록 결함은 이후 고쳤다. 작업별 Contract와 원본 Trial이 Behavior 전체 완료 전에 진행된 점은 기존 전역 장벽 제거의 실행 증거다. 그러나 하네스 생성 시도는 0개다. 이는 TCP·UDP의 반복 실행 안전성이 증명되지 않아 선택된 외부 상태형 퍼징 백엔드가 구현돼 있지 않기 때문이다. 작업을 성공으로 둔갑시키지 않고 `BLOCKED_UNSUPPORTED_BACKEND`로 기록했다.

실행 후 발견한 두 결함은 수정했으나, 수정된 전체 코드로 긴 Memcached 실행을 다시 완료한 것은 아니다. 첫째, `fgets`를 API 이름만으로 stdin으로 판단하여 파일 입력 세 곳을 선택하고 시험했다. 현재는 `FILE *`의 채널 증거가 파일이면 file, stdin이면 stdin, 불명이면 unknown으로 분류한다. 이 수정 후 저장된 Entry들에 계획 함수를 직접 적용한 결과 선택 대상은 `tcp_read`, `try_read_udp`, `main`의 argv 세 개이고 나머지 14개는 보류된다. 둘째, UDP 원본 Trial은 한 번 `OBSERVED_NO_RESPONSE`였지만, 동일 서버 TCP·UDP 포트가 열릴 때까지 기다린 뒤 송신하도록 Memcached 전용 시험기를 고쳐 실제 서버 통합 시험 5회 연속 통과했다. 이 두 수정은 과거 실행 결과를 소급해서 바꾸지 않는다.

## 2. 작업 단위와 종료 조건

새 작업 단위는 `(외부 Entry, 입력 데이터 흐름, 효과, 선행 상태, 실행 방식, 효과 종류)`이다. 소스 설명문, 증거 줄 번호, 함수 탐색 순서는 키에 넣지 않는다. 같은 구조 키에 연결된 다른 함수 경로와 출처 줄은 `path_variants`와 증거 목록에 누적한다. 서로 다른 효과는 한 작업으로 합치지 않는다. 구조 필드가 비었거나 `unknown`/`unresolved`이거나 설명 문장처럼 길면 그 후보의 작업 식별을 `UNRESOLVED`로 남긴다. 이는 동의어를 자동으로 판별할 수 있다는 주장이 아니다. 실제 Memcached 출력에는 `input_flow`가 문장인 사례가 있었고, 최신 코드에서 이런 문장은 안정적인 병합 키로 사용하지 않는다. 의미상 같은 두 짧은 키가 서로 다른 표현으로 나오면 여전히 중복될 수 있다.

작업은 다음 증거와 종료 상태를 각각 가진다.

1. Entry의 소스 판정은 VERIFIED/UNRESOLVED 그대로 유지한다. 활성화 설정, 전달 가능한 외부 입력, 원본 런타임 도달성은 별도 값이다. 원본 응답만으로 처리 함수 도달을 판정하지 않는다.
2. Behavior는 가능한 효과와 함수 경로를 만든다. 열린 함수의 소스 줄이 없는 주장은 증거로 인정하지 않는다. 탐색 턴 또는 시간 예산이 끝나면 `DEFERRED_BUDGET`과 필요한 함수/증거를 기록한다. 이는 경로 부재 판정이 아니다.
3. Entry 하나에서 시험 가능한 사례가 생기면 다른 Entry의 Behavior 완료를 기다리지 않고 원본 Trial을 실행한다. 발견한 작업 하나에 대해 Contract 분석을 시작하고, 같은 Entry의 나머지 작업은 대기열에 넣는다. 작업 선택에 위치 기반 `[:32]` 절단을 사용하지 않는다.
4. Contract는 함수별 모델 응답과 소스 증거, 아직 열어야 할 함수 ID를 매 턴 저장한다. 실행 백엔드는 하네스 코드를 요청하기 전에 결정한다. 리셋 가능한 반복 호출의 근거가 없으면 프로세스/네트워크 백엔드 필요성을 명시한다.
5. 구현된 백엔드에서만 생성 → 독립 검토 → 정적 검사 → 빌드 → 입력 재생 → sanitizer 퍼징 → 실패 피드백과 수정 순서를 수행한다. 빌드 성공과 실제 처리 경로 동등성은 별도 판정이다. 후자를 확인하기 전에는 `qualified=True`가 될 수 없다.

`workflow/work-events.jsonl`에 단계의 STARTED, COMPLETED, 보류, 차단, 구현 실패를 즉시 추가한다. 함수 탐색 기본 예산은 작업별 12턴, 단계별 900초, 전체 실행 호출별 7200초이며 CLI 옵션으로 바꿀 수 있다. 재개 시 완료 단계의 스냅샷을 불러오며, 일부 모델 탐색은 저장된 턴과 다음 함수부터 재개한다. 전체 예산은 현재 CLI 호출마다 새로 적용되므로 동일 실행 ID의 여러 재개 시간을 합친 총량 상한은 아직 아니다.

## 3. 변경 전후 워크플로우 및 모듈

| 구분 | 변경 전 | 변경 후 |
|---|---|---|
| Entry | 소스 줄로 생성·검증, UNRESOLVED 보존 | 핵심 판정 유지; 활성화/전달/원본 도달성 결정을 추가 기록 |
| Behavior | 전역 후보 누적과 완료 장벽; 1,093개 모두 POSSIBLE | Entry별 탐색·체크포인트 후 작업 단위별 진입; 미확인 경로는 계속 POSSIBLE/UNRESOLVED |
| Contract | 전체 후보의 후속 분석; 35개 모두 증거 불완전 | 작업별 탐색, 턴별 부분 스냅샷, 누적 소스 증거 |
| 입력 시험 | 이전 실행 0건 | 사례별 원본 Trial 즉시 저장; Memcached 회귀 벡터 별도 연결 |
| 백엔드 | 지원 여부가 생성 이전의 명시적 차단 조건이 아니었음 | Contract 뒤 생성 전 선택; 미구현 외부 백엔드는 차단 |
| 생성·검증 | 생성·독립 검토·수정·빌드·sanitizer 단계 존재 | 이 구조 유지; 실제 지원 백엔드에서만 실행 |
| 종료·재개 | 긴 분석 중 중간 결과 손실 가능 | 작업별 이벤트/스냅샷과 실행 설정 지문; 완료 단계 재사용 |

핵심 구현은 `runtime/boundary_work.py`의 Entry 결정·작업 정규화·이벤트 장부, `workflow_boundary_v2.py`의 단계 스케줄러, `agents/behavior.py`와 `agents/execution_contract.py`의 누적 탐색, `runtime/boundary.py`의 원본 시험·백엔드 결정, `runtime/memcached_regression.py`의 Memcached 회귀 시험이다. `workflow_boundary.py`는 v2 호출과 기존 생성 보조 기능을 잇는다. Entry 생성/검증, 하네스 생성기, 독립 검토기, 빌드/sanitizer 검증기는 유지했다. Action/SmallFeature/LargeFeature를 강제로 거치는 경로와 전역 Behavior 완료 장벽은 boundary 모드의 필수 경로에서 제외했다. 다른 모드의 파일은 삭제하지 않았다.

이 설계의 근거는 세 층이다. 첫째, 기존 실행에서 1,093→35→0으로 진행이 멎었다는 실험 결과와 저장된 소스/런타임 로그다. 둘째, [LLVM libFuzzer 문서](https://llvm.org/docs/LibFuzzer.html)는 반복되는 동일 프로세스의 입력 처리 함수를 전제로 하므로 데몬의 리셋 가능성을 근거 없이 가정할 수 없다. 셋째, [AFLNet](https://github.com/aflnet/aflnet)과 [StateAFL 논문](https://arxiv.org/abs/2110.06253)은 상태 있는 네트워크 서버가 여러 메시지와 세션 상태를 포함한다는 별도 실행 문제를 다룬다. 이 자료들은 외부 백엔드 필요성의 근거이지, 현재 HarnessCreator에 해당 백엔드가 구현됐다는 증거는 아니다. [GDB 중단점 문서](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html)는 지정 위치에 실행이 왔음을 보여준다. 따라서 요청 창에 발생한 함수 hit를 정확한 입력 바이트의 인과적 귀속으로 확대 해석하지 않는다.

## 4. Memcached 실행에서 관찰한 것

원본 서버의 한 PID(2497)에서 `version` TCP, 같은 연결의 `set`→`get`, `version` UDP가 예상 응답을 냈다. GDB의 요청 구간 로그에는 TCP `tcp_read`, set의 `process_update_command`, get의 `process_get_command`·`process_get_cmd`, UDP `try_read_udp`가 있었다. UDP 구간에 `tcp_read` hit도 있어, 단순히 구간 내 hit를 그 요청 바이트의 전용 경로라고 말할 수 없다. 실제 회귀 산출물은 세 경로 모두 `OBSERVED_EXPECTED`이지만 `handler_attributed=false`다. 이전 별도 실험에서 `process_command_ascii`도 관찰됐으나 이번 저장된 v2 회귀 결과의 hit 목록에는 없으므로 이번 실행의 확인 결과로 세지 않는다.

원본 사례별 Trial 7개 중 TCP 고정 벡터는 응답을 관찰했다. 첫 UDP 사례별 Trial의 무응답은 원본 회귀 시험의 UDP 정상 응답과 모순되었고, 검사 결과 서버 기동 직후 단일 UDP datagram을 너무 일찍 보낸 경합이었다. 현재 Memcached 시험기는 같은 포트의 TCP co-listener 준비를 확인한 다음 UDP를 송신한다. 이는 Memcached 시험 규칙이며 UDP 전용 일반 프로그램에 TCP 준비 조건을 넣지 않는다. PID 파일, proxy 백엔드, TLS, 파일/환경 입력이 현재 실행 명령에서 활성화되지 않은 사유는 Entry 결정 파일에 남긴다. `-U 0`을 일반 데몬에 적용하지 않고 Memcached 명령 해석에서만 UDP 비활성화 의미로 쓴다.

새 실행 당시 선택된 Entry 6개 중 파일 `fgets` 세 개가 stdin으로 잘못 선택된 것은 구현 오류다. 이들 Trial의 timeout을 대상 경로 실패의 증거로 취급하지 않는다. 수정 후 직접 계획 검사에서는 TCP, UDP와 argv 후보만 선택한다. `main` argv도 소스상 외부 입력 후보일 뿐, 현재 고정 명령에서 임의의 추가 argv가 유효한지는 원본 실행으로 확인되지 않았다.

현재 Memcached TCP/UDP 작업의 Contract는 리셋 가능한 in-process 호출을 입증하지 못했다. 백엔드 결정은 `external_stateful_fuzzer`를 요구했고, 구현 부재로 `BLOCKED_UNSUPPORTED_BACKEND`를 기록했다. 또 하나의 당시 오분류 stdin 작업은 `external_process_fuzzer` 부재로 막혔다. 다른 작업 하나는 Contract/소스 증거 부족으로 `BLOCKED_EVIDENCE`였다. **Memcached의 생성·빌드·실행·퍼징·대응 경로 비교·qualified 결과는 모두 0**이다. 정확한 결과 분류는 이렇다: 원본 요청/일부 함수 hit는 관찰, 정확한 입력→핸들러 귀속은 미증명, 생성 하네스의 대응 경로는 부재, 최종 자격 미달.

## 5. 작업 수와 실행 시간

시간은 `work-events.jsonl`의 완료 및 예산 소진 이벤트에 저장된 단계 실행 초를 합산했다. 첫 호출과 재개 호출을 합친 수치이며, 단계 밖의 정적 분석과 실행 준비는 포함하지 않는다. 새 실행은 약 10분 + 5분의 구성 예산으로 실행했고, 두 호출 모두 정적 분석 사전 단계가 추가로 있었다. 설정 예산과 작업별 실측 시간을 혼동하지 않는다.

| 단계 | 완료 | 예산 소진 | 측정된 실행 시간 |
|---|---:|---:|---:|
| Behavior | 3 | 5 | 441.03초 |
| ExecutionContract | 3 | 1 | 356.97초 |
| InputSurface | 4 | 2 | 87.97초 |
| 원본 Trial | 7 | 0 | 10.34초 |
| Memcached 프로토콜 회귀 | 1 | 0 | 0.96초 |

고유 작업 식별자 29개와 Behavior 29개는 이 제한된 실행에서 우연히 같은 개수다. 작업 목록 파일에는 재개 시 중복 작성된 21줄이 더 있다. 1,093개가 29개로 전부 의미상 정규화됐다는 비교로 사용하면 안 된다. 선택, 보류, 차단의 이유는 `entry-decisions.jsonl`, `work-unit-inventory.jsonl`, `work-events.jsonl`에 각각 남는다. v2 실행 중 요약 파일이 재개 호출에서 일부 카운터를 현재 호출만으로 계산하는 결함도 확인했고, 이후 완료된 작업 스냅샷에서 누적 목록을 복구하도록 수정했다. 따라서 실행 당시 `summary.json`의 일부 수치와 수정 후 코드의 요약 생성 방식은 시점이 다르다.

## 6. 일반 C 규칙과 Memcached 시험 규칙

**일반 C:** 소스 증거 기반 Entry 판정, 전달 수단의 출처 분석, 작업 키, 효과별 누적, 예산 소진의 보류 처리, 작업별 Contract 체크포인트, 생성 전 백엔드 선택, 독립 검토와 sanitizer 재생, 원본/하네스 경로 비교 전 자격 보류를 적용한다. `read`, `fread`, `fgets` 같은 API 이름만으로 FD/`FILE *`의 출처를 결정하지 않는다. 네트워크 포트나 프로토콜을 하드코딩하지 않는다.

**Memcached 전용:** `-p`/`-U`/`-P`/`-Z`와 proxy 역할을 현재 실행 명령과 대조하고, 일반 TCP·UDP를 우선 시험한다. `version`, 동일 서버의 `set`→`get`, UDP 헤더가 있는 `version`을 고정 회귀 벡터로 사용한다. 동일 TCP/UDP 포트의 서버 시작 경합에는 TCP listener 준비를 대기한다. 이 규칙을 일반 C 대상의 기본 가정으로 승격하지 않는다.

## 7. 검증 범위와 남은 실패

코드 수준 회귀는 전체 `pytest` 452개 통과, 5개 건너뜀, 36 subtests 통과(130.23초)였다. 그 뒤 설명문을 작업 식별자로 인정하지 않는 보수적 수정까지 포함한 집중 시험은 31개 통과했다. 실제 Memcached 원본 프로토콜 시험과 GDB 구간 추적을 실행했고, UDP 기동 경합 수정은 실제 서버를 대상으로 5회 반복 확인했다. 별도의 지원 가능한 in-process C fixture에서는 Clang/libFuzzer 및 ASAN·UBSAN 빌드, 재생, 짧은 퍼징을 시험했다. 이 fixture 결과를 Memcached 하네스 결과로 대체하지 않는다. 마지막 코드 전체를 통한 장시간 Memcached 종단 간 실행은 하지 않았으므로 추가 결함 가능성이 남는다.

**구현 결함으로 확인:** `fgets` 출처 오분류, 첫 UDP Trial의 기동 경합, 재개 시 누적 요약 누락, 일부 WSL 환경에서 PIE sanitizer 바이너리의 시작 전 SIGSEGV(해당 WSL 도구 체인에서 `-no-pie`로 30회 비교해 9/30 대 0/30), 오래된 로컬 Codex CLI 모델 호출 실패. 해당 오류는 각각 수정/우회 또는 별도 확인했고 대상 프로그램의 기능 실패로 분류하지 않는다.

**설계 또는 기능 공백:** 외부 상태형/프로세스형 퍼징 백엔드 미구현, 요청 바이트와 원본 내부 처리의 인과적 귀속 미구현, 원본/하네스 대응 처리 경로 비교 미완성, 구조 키의 의미상 동의어 정규화 미증명, 전체 예산의 재개 호출 간 누적 상한 부재. 이 항목은 단위 시험 성공이나 원본 응답만으로 해결되지 않는다. SVF는 이번 새 실행에서 필요한 bitcode가 없어 `UNAVAILABLE`였고 간접 호출 매핑 0이다. Fuzz Introspector 및 소스 부트스트랩 분석은 1,278함수·3,976에지를 제공했지만, 이는 개별 입력의 동적 도달성 증명이 아니다.

다음 실험은 다음 가설을 반증해야 한다.

1. 요청 식별자를 원본의 입력 획득 지점과 실제 처리 함수에 함께 기록하면 TCP·UDP 각각에서 `handler_attributed=true`를 정확한 바이트 단위로 얻을 수 있는가? 동시 요청을 섞어 위양성도 측정한다.
2. Memcached의 프로세스 재시작/세션 순서/상태 유지가 가능한 외부 백엔드를 구현하면 동일 서버의 `set`→`get`을 매 반복에서 재현하고 sanitizer 빌드로 퍼징할 수 있는가? 지원하지 못하는 실행 방식은 계속 차단한다.
3. 동일 원본 입력을 하네스에 재생했을 때 `tcp_read`/`try_read_udp` 이후의 처리 함수와 상태 변화가 대응하는가? 함수명 유사성과 응답 일치만으로는 자격을 주지 않는다.
4. 일반 C 데몬·CLI·파일 처리기 행렬에서 채널 출처와 활성화 판정이 잘못된 stdin/TCP 가정을 만들지 않는가? `fgets`/`read`의 파일·stdin·소켓 변형을 각각 포함한다.
5. 독립적으로 표현한 같은 입력 흐름/효과가 구조 키에서 합쳐지고, 서로 다른 효과가 분리되는가? 실제 소스 경로의 독립 검토와 병합/누락률을 함께 측정한다.

## 8. 원본 자료와 실행 산출물

- 기존 실패 실행: `C:\Users\ok\Documents\Codex\2026-10-20\d\work\memcached-boundary-eval-runs\20261025-200350-c7084624`
- 새 평가 실행: `C:\Users\ok\Documents\Codex\2026-10-20\d\work\memcached-boundary-v2-final-runs\20261026-202021-3bb89d91`
- 최신 전체 시험 로그: `C:\Users\ok\Documents\Codex\2026-10-20\d\work\boundary-v2-full-pytest-latest.log`
- 주요 코드: `src/harnesscreator/workflow_boundary_v2.py`, `src/harnesscreator/runtime/boundary_work.py`, `src/harnesscreator/runtime/boundary.py`, `src/harnesscreator/runtime/memcached_regression.py`, `src/harnesscreator/agents/behavior.py`, `src/harnesscreator/agents/execution_contract.py`
- 회귀 시험: `tests/test_boundary_work_units.py`, `tests/test_boundary_rebuild.py`, `tests/test_memcached_regression.py`, `tests/test_boundary_dynamic_fixture.py`
