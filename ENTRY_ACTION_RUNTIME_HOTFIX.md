# Entry에서 Action으로 넘어가는 탐색과 조기 실행 수정

## 실패 기록

사용자가 제공한 2026-10-25 memcached 실행 분석에는 다음 결과가 있다.

| 지표 | 당시 결과 |
| --- | ---: |
| 분석 함수 | 1,278개 |
| 호출 간선 | 3,976개 |
| Entry 검증 | 확인 14개, 미해결 8개, 기각 8개 |
| Action | 34개, 모두 `argv` |
| TCP/UDP Action | 0개 |
| 원본 요청 시험 | 0회 |
| LLM 호출 | 647회 |
| 종료 상태 | `FAILED_NO_RUNTIME_WITNESS` |

하네스 빌드가 실패한 것이 아니다. 하네스에 전달할 원본 실행 증거가 없었다. 원본 실행에서 검증된 요청이 없는 상태로 하네스 성공을 표시해서는 안 된다.

## 수정 내용

1. `EntryRecord.inspected_function_ids`를 Action 탐색 후보에 전달한다. `conn_new`처럼 Entry 검증 단계가 조사한 함수 원문을 Action이 다시 열 수 있다. 이 정보는 탐색 근거일 뿐이다. 입력이 실제로 해당 함수에 도달했다는 정적 증거로 승격하지 않는다.
2. 현재 함수가 읽는 구조체 필드의 작성자도 Action 탐색 후보에 넣는다. `c->try_read_command`처럼 함수 포인터를 호출하는 코드에서 초기화 함수를 찾는 데 사용한다. 타입과 필드 이름을 근거로만 후보를 찾는다. 런타임 인과관계는 별도로 확인한다.
3. Entry 검증은 명시적인 요청이 있는 경우에만 깊이 제한을 한 단계 확장할 수 있다. 직접 호출 관계와 실제 함수 ID가 필요하다. 따라서 깊이 3에서 연 `setup_thread`가 직접 호출하는 `setup_thread_notify`를 깊이 4에서 조사할 수 있다.
4. `argv`, `argc`, `envp` 같은 시작 인자를 네트워크 클라이언트로 분류하지 않는다. `main` 안에 `bind` 또는 `accept`가 있어도 실제 입력 API를 먼저 확인한다.
5. Entry 탐색으로 찾은 소스 위치에 명령 문자열 비교가 있으면 원본 요청 시험 후보를 만든다. memcached 모드에서는 `CMD_SET`처럼 명령 ID를 사용하는 분기도 처리한다. 후보는 `POSSIBLE` 상태를 유지한다. 인식할 수 없는 형식은 억지로 합성하지 않는다.
6. `--scenario-exploratory-drafts`가 활성화되면 조기 시험을 Action 분기 전체의 LLM 검증보다 먼저 실행한다. 이후 실행 단계에서는 이미 시험한 동일 시나리오를 다시 실행하지 않는다.
7. 선행 작업을 알 수 없는 요청을 원본에서 시험할 수는 있다. memcached 응답 파서가 실제 성공을 인식하면 `OBSERVED_RUNTIME` 또는 `REPLAYED_RUNTIME` 초안의 근거로 기록한다. 성공 응답을 입증하는 소스 근거가 없으면 `PROVEN_RUNTIME`으로 승격하지 않는다. 이러한 결과를 검증된 하네스의 근거로 취급하지 않는다.

## 원본 요청 시험의 범위

명령 문자열에서 시험 바이트를 만드는 코드는 `src/harnesscreator/analysis/request_hypotheses.py`에 있다.

- 일반 텍스트 프로토콜에서는 소스가 `strcmp`, `strncmp` 등으로 명령 문자열을 비교해야 한다.
- memcached 모드에서는 `case CMD_GET`, `case CMD_SET` 같은 구문도 후보가 된다.
- TCP 또는 UDP Entry에서 발견한 분기여야 한다.
- `--scenario-response-protocol memcached_ascii`에서는 `get`, `gets`, `set`, `add`, `replace`만 시험한다.
- UDP memcached 모드에서는 UDP 헤더를 요청 앞에 붙인다.
- 그 밖의 텍스트 프로토콜은 명령 문자열 뒤에 `\r\n`을 붙인 시험 가설만 만든다.

이는 범용 프로토콜 복원 알고리즘이 아니다. 바이너리 프레이밍이나 복잡한 필수 상태를 임의로 추정하지 않는다. `get`은 미리 저장한 키가 없으면 실패할 수 있다. 따라서 실패한 일회성 `get` 요청만으로 Entry 자체를 기각하지 않는다.

공개 memcached 소스의 `proto_text.c`에서는 `process_command_ascii`가 24개 `CMD_*` 분기로 명령을 처리한다. `proto_parser.c`는 입력 문자를 해석해 이 명령 ID를 만든다. 따라서 문자열 비교만 탐색하면 주요 명령을 놓친다. 이번 수정은 그중 5개 명령에 대한 첫 시험 후보를 만든다. 이는 전체 24개 동작의 복원을 완료했다는 뜻이 아니다. `proto_parser.c`의 문법과 나머지 분기는 이후 분석 대상으로 남는다.

## 조기 시험의 의미

조기 시험은 `InputActionAgent.run()`의 Entry별 소스 탐색 직후 시작한다. 이후에 분기별 모델 검증을 수행한다. 기존처럼 모든 분기 검증을 완료할 때까지 첫 원본 요청을 기다리지 않는다.

조기 시험은 여러 Entry의 요청을 번갈아 선택한다. 한 Entry에 시험 요청이 많아도 다른 Entry를 먼저 한 번씩 시험한다. 처음에는 최대 8개 시나리오를 시험한다. 이 상한은 Action 발견 범위와 전체 분기 검증 범위를 제한하지 않는다. 전체 후보는 다음 검증 단계에 남는다.

memcached 모드에서는 기존 키에 의존하지 않는 `CMD_SET` 후보를 먼저 시험한다. 해당 요청에 대해 원본 프로그램이 `STORED`를 반환하면 후속 하네스 초안 생성을 시도할 수 있다. 정확한 핸들러 도달이 확인되지 않으면 초안은 `QUALIFIED`가 아니다. `get`이 `END`만 반환하면 키 부재와 연결 실패를 구분한 뒤 다음 요청 순서를 분석한다.

원본 시험 결과는 `workflow/entry-walk-runtime-trials.json`과 `scenarios/witnesses/`에 기록한다. `workflow/early-harness-preflight.json`은 이후 전체 Action 검증을 마친 시점의 조기 하네스 경로를 기록한다.

## 기존 실행 명령 변경

기존 memcached 실행 명령과 포트 23877은 유지한다. 다음 인자를 확인한다.

```bash
--provider codex --daybreak
--scenario-channel auto
--scenario-response-protocol memcached_ascii
--scenario-host 127.0.0.1
--scenario-port 23877
--scenario-exploratory-drafts
```

`--scenario-command`에는 실제 사용 중인 memcached 실행 파일과 인자를 그대로 전달한다. `--scenario-channel tcp`를 유지하면 UDP 요청을 실행하지 않는다. TCP와 UDP를 모두 실행하려면 원본 프로그램이 두 프로토콜을 모두 수신하도록 구성해야 한다.

## 검증 범위 및 남은 문제

회귀 테스트는 함수 재탐색, 깊이 확장, 잘못된 `argv` 분류, 요청 바이트 생성, 조기 원본 실행과 분기 LLM 분석의 순서를 확인한다. 모의 memcached TCP 서버에 `set`을 보내 `STORED`를 받은 경우에도 `PROVEN_RUNTIME`으로 승격하지 않는 테스트를 추가했다. 공개 memcached 소스의 명령 분기도 대조했다. 실제 memcached 실행 바이너리는 없어서 원본 TCP/UDP 요청을 재실행하지 않았다.

따라서 이번 변경은 이전 실패의 코드 경로를 수정한 상태다. 실제 Action이 생성되고, 어느 함수가 실행되며, OSS-Fuzz 빌드가 성공하는지는 새 실행 로그로 확인해야 한다. Action 탐색이 여전히 실제 파서를 발견하지 못하면 해당 Entry의 `actions/progress.json`과 함수 열람 기록을 근거로 다음 장애를 분리한다.

## 연구 근거

- AFLNet, *A Greybox Fuzzer for Network Protocols*, ICST 2020: 실제 요청 메시지열과 상태 피드백을 이용한다. 이 작업에서는 원본 메시지 실행을 정적 Action 분석보다 앞당기는 근거로 참고했다. https://github.com/aflnet/aflnet
- StateAFL, *Greybox Fuzzing for Stateful Network Servers*, 2022: 서버 내부의 장기 상태를 관찰한다. 요청 하나의 응답만으로 선행 상태 의존성을 입증하지 않는 근거다. https://github.com/stateafl/stateafl
- Google Research, *Lessons from Mitigating False Positives in Google's OSS-Fuzz-Gen*: 현실적인 엔트리 지점 검증과 잘못된 결과의 감소를 다룬다. 하네스 생성 자격에 독립적인 확인을 유지한다. https://research.google/pubs/lessons-from-mitigating-false-positives-in-googles-oss-fuzz-gen/

논문은 설계 방향의 근거다. 이 변경 코드가 memcached에서 성공했다는 실험 결과는 아니다.
