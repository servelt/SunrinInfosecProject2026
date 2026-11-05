# C 데몬 하네스 자동생성: 설계 재검토 및 이번 패치의 정확한 범위

## 결론

기존 Entry → Entry Verifier → Input Action → State Dependency → Scenario Planner → Original Runtime Verifier → Harness Generator → Harness Verifier → Crash Reproducer 순서는 **합리적인 분업**이지만, 임의의 데몬에서 성공을 보장하는 알고리즘은 아니다. 특히 기존 Input Action 구현의 'Entry마다 함수별 탐색 × 독립 명령마다 함수별 탐색 × nested 조건별 재탐색'은 프로그램 크기가 커질수록 작업량이 폭증한다. 이를 단순 LLM 재시도/timeout 증가로 해결할 수 없다.

## 로그에서 확인한 증상

- 첨부 로그에서 정적 분석은 약 20초, Entry 단계는 몇 분 만에 종료했으나 Input Action 호출은 수백 회로 증가했다.
- `GET`, `GETS`, `GAT`, `GATS`처럼 같은 함수를 공유하는 서로 다른 명령을 독립 세션에서 다시 열었다.
- `ret == PROCESS_REQUEST_OK`, `!resp_start(c)`, `pr.tok.ntokens > 1` 같은 내부 조건도 독립 분기 분석 대상으로 확대됐다.
- 개별 응답이 수 분까지 늘었고 일부 호출은 600초 timeout 및 JSON 파싱 오류를 반환했다.

## 이번 코드 변경

`src/harnesscreator/agents/scenario.py`의 InputActionAgent를 수정했다.

1. 각 branch worker의 최대 함수 열람 횟수는 기본 4회 (`branch_context_budget`). Entry 전체 탐색 예산과 독립적으로 관리한다.
2. 동일 Entry에서 branch LLM 작업 기본 24개 (`per_entry_branch_budget`). 초과 후보는 제거하지 않고 `operation_seeds` 및 `inventory_obligations`에 남긴다.
3. 하위 함수에서 발견된 일반 내부 `if` guard를 새로운 독립 작업으로 반복 생성하지 않는다. `switch case`, 명령 비교나 명령 필드가 포함된 명확한 후보는 계속 분석 가능하다.
4. 일반 조건보다 구체적인 switch-case 후보를 우선 처리한다. 이 우선순위는 검증 증거를 대신하지 않는다.
5. 상태 계약, 실행 검증 수준, 각 Ollama 모델 역할을 변경하지 않는다.

## 바꾸지 못한 근본 한계

- 현재 코드는 아직 모든 명령의 공통 함수 분석을 구조화된 함수 요약으로 공유하지 않는다. 독립 LLM 세션에서 같은 코드를 재탐색할 수 있다.
- 소스 분석 기반 OperationSeed의 recall과 false positive 모두 정량 평가되지 않았다.
- LLM 세션의 메시지 전체 재전송 문제는 제공자 세션 시스템을 변경해야 해결할 수 있다.
- 시간 예산 초과로 보류한 후보에 대한 **자동 재개/추가 파동 스케줄러는 구현하지 않았다**. 따라서 이번 수정은 폭증을 상한으로 억제하지만 전체 후보를 자동 완주하지 않는다.
- 임의의 C 데몬에서 원본 실행/하네스 재시작/차등 동등성 검증은 여전히 보장되지 않는다.
- 모델 없이 실행하는 소형 회귀 테스트 결과는 실제 Ollama + memcached end-to-end의 증거가 아니다.

## 후속 재설계가 필요한 이유

실질적인 고성능/고재현성 버전에는 `source index -> function summary cache -> dispatcher-local action contracts -> evidence-targeted LLM queries -> prioritized per-action setup/fuzz/post -> build/run/differential feedback`가 필요하다. 함수 요약 캐시는 소스 버전과 컴파일 인자 해시로 무효화하고, **증거가 다른 요청 사이에 무분별하게 공유되지 않도록** 호출 문맥을 포함해야 한다. 각 단계는 proven/possible/unsupported를 보존하고 서로 다른 verdict를 합치지 않아야 한다.

## 연구 대조

- *FuzzingBrain V2*: 전체 파일을 무조건 읽는 대신 의심 위치 중심 계층적 분석 및 도구 사용을 제시. OSS-Fuzz 기반 취약점 검증 결과는 프로그램/데몬 생성기 범용성 보증이 아니다.
- *HarnessAgent* (2025): 소스 조회 도구 정확성, 컴파일 실패 유형 구분, 가짜/무의미한 하네스 검증 문제를 실험적으로 지적. 실험 대상은 OSS-Fuzz 함수 타깃이므로 일반 데몬에 그대로 성공률을 이전할 수 없다.
- *OSS-Fuzz-Gen false-positive lessons* (2026): 생성 코드의 제약 조건 및 원본 실행 문맥 검증이 중요하며, 빌드/크래시 결과만으로 결함을 단정해서는 안 된다.
- *WINNIE*: 실제 실행 흔적에서 하네스 구성 힌트를 복구하는 접근으로, 사용자 제공 실행 흔적이 없는 본 프로젝트의 source-first 경로를 대체하지 않는다.

## 검증 기준

성공 여부는 별도로 집계해야 한다: (a) Entry/Action 발견, (b) 정상 요청 생성, (c) 원본 특정 handler 실행, (d) 생성한 C 하네스 빌드, (e) 반복 fuzzer 실행에서 목표 함수 도달, (f) 가능한 경우 원본과 의미적 동등성. `QUALIFIED`는 독립적 검증 규칙을 충족했을 때만 부여한다.
