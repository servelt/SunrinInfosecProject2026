# HarnessCreator: 요청별 검증과 회귀 테스트 변경 기록

## 적용 범위

이 수정본은 최초 HarnessCreator에 존재하는 9단계 에이전트 워크플로우를 유지한다. `Entry Generator → Entry Verifier → Input Action Agent → State Dependency Agent → Scenario Planner → Original Runtime Verifier → Harness Generator Agent → Harness Verifier Agent → Original Crash Reproducer`를 교체하지 않았다.

외부 QuartetFuzz 프로젝트를 실행하지 않는다. 기존 HarnessCreator의 Harness Generator/Verifier와 OSS-Fuzz 실행 어댑터를 유지했다. 이번 변경은 최신 `HarnessCreator_repaired_original_workflow.zip`에 누적 적용했다.

## 실제로 수정한 문제

| 문제 | 원인 | 수정 | 아직 보장하지 못하는 것 |
|---|---|---|---|
| GDB 부재 때문에 원본 정상 입력도 확인 불가 | 정확한 호출 추적을 필수 사전 조건으로 사용 | 탐색 모드에서는 실제 응답을 재생하고 `REPLAYED_RUNTIME` 기록 | handler 도달과 요청별 귀속 |
| GDB 호출 순서만으로 요청을 증명하려 함 | 이벤트에는 입력/요청 식별자가 없음 | 원본 빌드가 기록하는 `acquire → handler` 요청 ID, 연결 ID, 입력 SHA-256을 함께 확인하는 `trace` 모드 추가 | 임의 프로그램에 대한 자동 계측 생성 |
| 원본 응답 재사용으로 검증 결과 오염 가능 | 이전 실행 결과가 같은 요청 바이트를 이유로 캐시됨 | `ScenarioRuntimeVerifier.verify()` 기본 캐시를 끔 | 모든 환경에서 재실행 결정성 |
| Witness와 HarnessPlan의 참조가 어긋날 수 있음 | 계획 작성 뒤 산출물 간 일치 검사 부재 | `runtime/contracts.py`에서 요청 바이트, 순서, action ID, 관찰 근거를 검사하고 잘못된 계획만 차단 | 정적 분석의 의미적 완전성 |
| 하네스가 빌드되어도 원본과 다른 상태를 만들 가능성 | 빌드/커버리지는 원본과 동작 일치를 검증하지 않음 | 명시적 `--require-differential-validation`에서 입력·handler·응답 해시·상태 해시 비교 추가 | 계측하지 않은 상태, 모든 변이 입력의 동등성 |
| 한 번 정상 응답을 확인했다는 사실을 완전한 증명으로 오인 | 실행 증거 수준이 섞임 | `REPLAYED_RUNTIME`, `OBSERVED_RUNTIME`, `PROVEN_RUNTIME`을 별도 상태로 유지 | 프로그램 밖에서 검증할 수 없는 숨은 상태 |

## 증거 수준

- `REPLAYED_RUNTIME`: 원본 데몬에서 생성 요청을 실행하고 예상 응답을 확인했다. 목표 함수 호출은 확인하지 못했다. 탐색용 **미검증 초안**만 생성할 수 있다.
- `OBSERVED_RUNTIME`: 원본 응답과 GDB 호출 순서를 관찰했다. 그러나 어떤 요청이 handler를 호출했는지 연결하지 못했다. **미검증 초안**이다.
- `PROVEN_RUNTIME`: 명시적으로 제공된 대상 추적기가 실제 요청 ID와 수신 입력을 handler 호출에 연결했다. 이 사실은 해당 실행에만 적용된다.
- `QUALIFIED`: 원본 요청별 실행 증거, 하네스의 빌드·동적 재생·도달·퍼징, 원본과 하네스의 독립 차등 비교를 모두 통과한 결과다. 차등 비교를 실행하려면 `--require-differential-validation`과 두 빌드의 의미 관찰 계측이 필요하다. 백엔드만 통과한 결과는 별도로 집계한다.

## 요청 귀속 JSONL 계약

`--scenario-attribution trace`를 사용하려면 **실제로 디버그 계측한 원본 바이너리**가 아래 이벤트를 기록해야 한다. 실행기는 원본 프로세스의 `HARNESSCREATOR_TRACE_JSONL` 환경 변수에 전용 파일 경로를 제공한다.

```jsonl
{"event":"acquire","request_id":"r-1","connection_id":"conn-1","entry_function_id":"<canonical-entry-id>","request_sha256":"<sha256-of-complete-request-bytes>"}
{"event":"handler","request_id":"r-1","connection_id":"conn-1","handler_function_id":"<canonical-handler-id>"}
```

입력을 받은 이벤트와 handler 이벤트의 요청 ID, 연결 ID가 일치해야 한다. 같은 요청 ID가 여러 입력에 재사용되거나 입력 SHA-256이 다르면 거절한다. 소스의 실제 호출 위치에서 기록해야 한다. GDB 시간 순서나 LLM의 설명만으로 이 이벤트를 만들어서는 안 된다.

스트림 입력이 여러 번 읽혀 **하나의 논리적 요청**을 이루는 경우에는 한 번의 `acquire` 대신 아래처럼 `acquire_fragment` 여러 개를 기록할 수 있다. `offset`은 해당 요청 안에서의 바이트 위치이며 0부터 빈틈 없이 증가해야 한다. 검증기는 조각을 순서대로 결합한 바이트가 실제 전송 요청과 정확히 같은지 확인한다.

```jsonl
{"event":"acquire_fragment","request_id":"r-1","connection_id":"conn-1","entry_function_id":"<canonical-entry-id>","offset":0,"data_hex":"4845"}
{"event":"acquire_fragment","request_id":"r-1","connection_id":"conn-1","entry_function_id":"<canonical-entry-id>","offset":2,"data_hex":"4c4c4f0a"}
{"event":"handler","request_id":"r-1","connection_id":"conn-1","handler_function_id":"<canonical-handler-id>"}
```

이 계약은 원본 계측이 어느 읽기 조각들이 **같은 요청**인지 이미 식별할 수 있을 때만 적용된다. 단순한 `read` 호출 기록만으로 요청 경계나 스레드 간 전달을 자동 복원하지 않는다. [Linux read(2)](https://man7.org/linux/man-pages/man2/read.2.html)와 [recv(2)](https://man7.org/linux/man-pages/man2/recv.2.html)는 짧은 읽기가 정상적임을 명시한다. Dropbear의 `read_packet_init`와 `read_packet`도 패킷 앞부분과 나머지를 나눠 읽는다. 따라서 한 `acquire`에 완전한 요청 해시를 요구하던 계약은 실제 스트림 데몬에 그대로 적용할 수 없었다.

입력 처리가 dispatcher 내부에서 끝나면 `handler` 이벤트의 정확한 함수 ID를 기록한다. 별도의 dispatcher 관찰이 필요한 Action은 다음 이벤트도 요구한다.

```jsonl
{"event":"dispatch","request_id":"r-1","connection_id":"conn-1","dispatcher_function_id":"<canonical-dispatcher-id>"}
```

위 JSONL은 실행 기록이야. 사용자에게 제공해야 하는 요청 예제가 아니며, 런타임 추적기가 실제로 소스에서 기록한 결과만 수용해야 한다. 원본 실행을 수정할 수 없는 환경에서는 `--scenario-exploratory-drafts`를 사용하여 요청 재생과 빌드 초안까지만 진행할 수 있다.

## 선택적인 원본-하네스 차등 검증

아래 플래그를 함께 지정한다.

```text
--verification-backend command
--scenario-attribution trace
--require-differential-validation
```

기존 command verifier의 동적 검사까지 통과한 뒤, 원본과 생성한 하네스가 **동일한 정상 fuzz-step 입력**을 처리하면서 기록한 응답/상태 해시를 비교한다. 이 실험을 수행하려면 **양쪽 빌드에 링크한 계측된 제품 코드**가 handler 실행 뒤 다음 기록을 출력해야 한다. 생성기가 작성한 하네스 코드에서 증명용 JSONL을 직접 출력하는 방식은 허용하지 않는다.

```jsonl
{"event":"result","request_id":"r-1","connection_id":"conn-1","response_sha256":"<sha256-of-response>","state_digest":"<sha256-of-selected-semantic-state>"}
```

상태 해시 대상은 양쪽에서 같은 필드와 정규화 규칙을 사용해야 한다. 계측 기록이 제품 코드에서 실제로 발생했는지를 확인하는 코드 무결성 검사는 별도 운영 환경에서 수행해야 한다. 현재 검사기는 생성 하네스 코드의 직접 기록 시도를 거절하지만, 임의의 빌드 스크립트 전체를 검증하지는 않는다. 포인터 주소, 시각, 임의 포트처럼 의미 없는 차이는 제외해야 한다. 상태를 계측하지 않았으면 `INSUFFICIENT_EVIDENCE`다. 일치하지 않으면 `MISMATCH`다. 이 경우 최종 승인하지 않는다. 이 결과는 비교한 정상 입력과 계측 필드에만 적용한다. 전체 상태의 의미적 동등성을 증명하지 않는다.

libFuzzer는 `-runs=1`에서도 같은 입력을 여러 차례 호출할 수 있다. 하네스는 각 호출에 다른 요청 ID를 기록해야 한다. 차등 검증은 동일 입력의 모든 호출이 같은 결과를 기록했을 때만 통과한다.

## 실행 및 테스트

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python3 -m pytest -q
```

외부 GDB/도커 없이 수행할 수 있는 실제 C 데몬 검사는 다음 명령으로 실행한다. 이 검사는 개발자가 구현한 기초 요청 프로토콜을 대상으로 하며, 임의 제품의 전체 자동 하네스 합성을 증명하지 않는다.

```bash
python3 -m pytest -q tests/test_request_trace.py tests/test_real_daemon_matrix.py tests/test_pipeline_contracts.py tests/test_differential_validation.py
```

전체 테스트 결과 (현재 개발 환경): **308 passed, 6 skipped, 29 subtests passed**. 건너뛴 테스트에는 GDB, Fuzz Introspector, RUBICK 미설치와 교체된 구형 경로가 포함된다. 실제 memcached를 대상으로 한 실제 LLM 생성 및 OSS-Fuzz Docker 퍼징은 이 환경에서 실행하지 않았다.

## 아직 남은 범용성 제약

1. 대부분의 C/C++ 데몬에 자동 삽입할 수 있는 일반적인 요청-ID 계측기는 구현하지 않았다. 특히 멀티스레드와 스레드 간 큐 전달에서는 요청 ID를 실제 연결/요청 객체에 연결해야 한다.
2. 입력 문법이 동적 길이, 암호화, 압축, 서버 발급 토큰 등을 포함하면 `InputActionAgent`의 구체적 요청 생성과 `StateDependencyAgent`의 결속 규칙이 여전히 부족할 수 있다.
3. `Setup → Fuzz → Post`의 임의 위치 변이와 다중 요청 상태 머신 생성은 구현하지 않았다. 기존 기본 전략은 고정 Setup과 마지막 Fuzz 요청을 사용한다.
4. OSS-Fuzz 어댑터는 빌드/재생/퍼징을 지원하지만 여전히 `qualified=False`로 끝난다. 커버리지 결과만으로 요청별 함수 도달과 원본 동작 일치를 확정하지 않기 때문이다.
5. 임의 C/C++ 데몬의 빌드 명령을 자동 복원하거나, 소스가 없는 ELF를 분석하는 기능은 없다. command 백엔드는 신뢰한 빌드 명령과 실행 파일이 필요하다.
6. 단위 테스트 및 계측된 C 프로그램 검사를 통과한 사실은 실제 LLM이 처음 보는 데몬에서 입력 문법과 상태 관계를 정확히 생성한다는 보증이 아니다. 서로 다른 실제 데몬으로 종단 간 성공률을 측정해야 한다.

임의 제품에 대해 100% 정확성을 주장하지 않는다. 결과 상태와 누락 원인을 분리하여 진단할 수 있게 만드는 것이 이번 수정의 목적이다.
