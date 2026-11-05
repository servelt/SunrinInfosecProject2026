# HarnessCreator

기본 실행 경로는 **Action 기반**이다. 외부 입력을 받는 Entry를 확인하고, 입력이 선택하는 동작과 필요한 선행 상태를 소스에서 추적한다. 원본 프로그램에서 요청 순서를 시험한 뒤 그 순서에 맞는 하네스를 만든다. Behavior 기반 경로는 실행 설정에서 제거했다. Small Feature와 Large Feature 그룹화도 실행 경로에 없다.

```bash
PYTHONPATH=src python3 -m harnesscreator run /path/to/c-project --allow-source-analysis --output /path/to/output
```

원본 프로그램의 특정 입력과 생성 하네스의 실행이 동등하다는 근거가 없으면 `QUALIFIED`로 표시하지 않는다. 반복 호출의 상태 초기화 조건이 없으면 in-process libFuzzer를 강제하지 않는다.

반복 호출이 안전하지 않은 네트워크 데몬에는 별도의 **원본 서버 퍼징 실험 경로**가 있다. `instrument-server`가 호출자가 지정한 빌드 단계를 StateAFL 컴파일러로 실행하고, `network-fuzz --server-build-manifest ... --prepare-only`가 워크플로우에서 관찰한 메시지열과 그 계측 바이너리를 연결한다. `network-fuzz` 실행 결과는 C 하네스의 `QUALIFIED` 판정이 아니다. Clang/LLVM 패스 버전이 맞지 않아 런타임 심볼만 생기는 빌드는 새 객체 파일의 coverage 참조 검사로 구분한다. 실제 LightFTP·memcached 빌드와 실행 근거는 [데몬 실행 방식 검증](docs/데몬_하네스_실행방식_도입검증.md)에 있다.

`run --network-harness-config /absolute/path/network.json`을 지정하면 Action 실행에서 관찰한 TCP/UDP 요청열을 같은 실행 디렉터리의 `research/stateafl/network-harness/`에 자동으로 묶는다. 설정에는 이미 만든 `server_build_manifest`와 계측 서버 명령, 또는 컴파일러·빌드 명령을 담은 `build` 블록을 넣는다. 후자는 실행 중 원본 소스를 복사해 계측 서버를 직접 빌드한다. 두 방식 모두 `afl-fuzz` 경로, 통로·주소·포트·실행 시간·시드 증명 등급을 명시해야 한다. 기본 동작은 **패키지 준비만** 하며, 실제 StateAFL 실행은 설정에서 `"execute": true`를 명시할 때만 시작한다. 결과는 `summary.json`의 `network_harness_status`에 따로 기록하며 C/libFuzzer의 `harnesses_qualified`를 올리지 않는다.

선택적인 `seed_replay_timeout_ms`와 `seed_replay_budget_seconds`는 각각 한 시드와 전체 진단의 시간 한도를 운영자가 지정한다. 저장된 원본 요청을 계측 서버에 다시 보내 원본에서 관찰한 성공 응답 표식을 확인한다. 원본 실행이 연결 직후의 인사말을 기록했다면 재생 시에도 인사말을 먼저 읽어 요청 응답과 분리한다. 이 비교는 요청별 처리 함수 귀속을 증명하지 않는다. 실행 결과와 한계는 [실행 방식 검증](docs/데몬_하네스_실행방식_도입검증.md)을 참고한다.

기존 명령에 들어 있는 `--workflow legacy_scenario`는 Action 경로의 호환 별칭이다. 새 명령에서는 생략하거나 `--workflow action`을 사용한다.

> 이전 Behavior 기반 실험과 결과는 [BOUNDARY_V2_EVALUATION.md](BOUNDARY_V2_EVALUATION.md)에 기록으로 남겼다. 현재 실행 결과로 해석하면 안 된다.

## Action 기반 워크플로우

```text
Entry Generator
  → Entry Verifier
  → Input Action Agent (외부 입력으로 선택하는 명령이 있는 경우)
  → Action Source Grouping / Selection (같은 효과 후보를 소스로 대조)
  → Action Request Agent (보존된 입력 경로마다 요청 바이트 생성)
  → Action Effect Families (증명된 공통 효과 아래 경로별 Action 보존)
  → Input Surface Agent (이름 붙은 Action이 없는 Entry의 원시 입력 후보)
  → Original Runtime Verifier (단일 입력 초기 시험)
  → State Dependency Agent (증명된 상태 생산·소비 관계)
  → Scenario Planner (단일 입력 또는 선행 요청열)
  → Original Runtime Verifier (전체 시나리오)
  → Scenario Harness Generator (16개 계약 검사)
  → Harness Verifier
  → Original Crash Reproducer
```

| 단계 | 하는 일 | 출력 | 확정할 수 없는 것 |
|---|---|---|---|
| Entry Generator | 제품 함수의 전체 소스를 하나씩 독립 요청으로 분석한다. 분석 실패 함수도 기록한다 | `EntryCandidate`, `entries/uninspected-functions.json` | 실제 외부 유입 여부 |
| Entry Verifier | 함수 원문을 하나씩 열어 입력 소유 관계를 따라간다. Caller/Callee 깊이를 정적으로 제한하지 않는다 | `EntryRecord` | 정상 요청 순서 |
| Input Surface Agent | 이름 붙은 Action이 발견되지 않은 Entry에 대해 명령 분기 없이 원본 실행용 바이트 가설을 만든다 | `input-surfaces/inventory.jsonl` | 해당 입력의 실제 처리 성공 |
| 초기 원본 실행 시험 | Action 요청 복원 이후 단일 입력 후보를 원본에서 시험한다. 이 단계는 후보이며 증명이 아니다 | `scenarios/witnesses/` | 입력과 특정 처리 함수의 인과관계 |
| Input Action Agent | Entry에서 시작해 함수 원문을 하나씩 열고, 외부 입력으로 요청 가능한 동작의 선택 조건·효과·handler 근거를 분석한다. `if`·`case`는 탐색 단서로만 쓴다 | `ExternalActionSchema`, `actions/discovered-semantic.jsonl` | 완전한 요청 바이트와 모든 동작을 찾았다는 주장 |
| Action Source Grouping / Selection | 같은 이름·handler·입력 주체는 비교 대상만 제안한다. 열린 Entry·분배·처리 함수의 줄 근거로 같은 효과·선행 상태·응답 의미인지 판정한다. 확실하지 않으면 묶지 않고 Action별 보존·보류·제외를 판정한다 | `actions/source-groups.jsonl`, `actions/selection.jsonl` | 같은 이름만으로 효과·원본 실행을 증명하는 일 |
| Action Request Agent | 공유 효과 근거를 참고하되 보존된 각 Entry·통로·선택 조건마다 요청 형식과 바이트를 독립적으로 복원한다 | `actions/request-decisions.jsonl` | 다른 통로의 요청 바이트를 그대로 재사용하는 일 |
| Action Effect Families | `SAME_SOURCE_EFFECT`로 소스 근거가 확인된 Action만 공통 효과 하나로 기록한다. `DIFFERENT`·`UNRESOLVED`는 개별 효과로 남기고 모든 입력 경로의 Action ID를 유지한다 | `actions/effect-families.jsonl`, `actions/input-routes.jsonl` | 공통 효과만으로 TCP·UDP 실행 또는 fuzz coverage가 같다는 주장 |
| State Dependency Agent | 같은 Entry와 handler를 공유하거나 소스 효과 공유가 확인된 Action을 한 번에 분석한다. 각 Action의 상태 계약은 기존 독립 검사기로 다시 확인한다 | `ActionStateContract` | 실행 가능한 전체 순서 |
| Scenario Planner | 증명된 producer/consumer 및 순서 제약만 사용해 요청 열 생성 | `ScenarioCandidate` | 원본 프로그램에서의 성공 |
| Original Runtime Verifier | 신뢰된 명령으로 원본 프로그램에 요청열을 보낸다. GDB의 시간순 관찰은 `OBSERVED_RUNTIME`까지만 기록한다. 요청·연결·입력 바이트와 실제 처리 함수를 연결하는 원본 계측이 있을 때만 `PROVEN_RUNTIME`을 판정한다. dispatcher는 필수가 아니다 | `ScenarioWitness`와 증거 수준 | 계측되지 않은 일반 데몬의 요청별 함수 귀속, 하네스 코드의 안전성 |
| Harness Generator | witness의 선행 요청과 최종 fuzz 요청을 실제 API 호출 코드로 변환 | `HarnessDraft` | 자신의 코드가 안전하다는 최종 판정 |
| Harness Verifier | 정적 16개 계약, 독립 검토, 실제 빌드·계측·재생·도달·coverage 확인 | `VerificationResult` | 원본에서 재현되지 않는 crash를 취약점으로 인정하는 일 |
| Original Crash Reproducer | crash seed를 원래 외부 요청 열로 되돌려 원본 프로그램에 재생 | `OriginalCrashReplay` | 재현되지 않은 harness-only crash의 취약점 판정 |

Small Feature와 Large Feature 그룹화는 활성 워크플로우에 사용하지 않는다. 실행 단위는 원본 프로그램에서 증명된 `ScenarioWitness`이며, witness 하나가 `HarnessPlan` 하나와 하네스 하나를 만든다. 하나의 witness는 여러 요청과 여러 Entry를 포함할 수 있고, 하나의 Entry에서도 여러 action과 witness가 나올 수 있다.

## 증거 단계

| 상태 | 의미 |
|---|---|
| `POSSIBLE` | 분석 후보이며 아직 증명되지 않음 |
| `PROVEN_STATIC` | 현재 checkout의 함수·line 근거로 정적 관계가 성립 |
| `OBSERVED_RUNTIME` | 원본 응답과 호출 순서는 관찰했지만 해당 요청과 함수 호출의 인과관계를 확정하지 못함 |
| `PROVEN_RUNTIME` | 요청과 목표 함수 호출의 귀속까지 확인한 실행 증거가 존재함. 현재 일반 GDB 경로는 이 상태로 승격하지 않음 |
| `REFUTED` | 반대되는 source 또는 실행 증거가 있음 |

LLM은 `PROVEN_RUNTIME`을 만들 수 없다. 이 상태는 `ScenarioRuntimeVerifier`만 생성한다.

## 일반화된 동작 복원

- `Entry`는 `recv`·`read` 같은 라이브러리 함수 자체가 아니라, 제품 소스에서 외부 데이터를 처음 획득하는 **함수와 위치**다. 직접 입력 호출뿐 아니라 실제 외부 콜백도 후보가 될 수 있다. 입력 형식이 그 함수 하나에 모두 있다고 가정하지 않고 소비 함수·콜백·사용 예시로 문맥을 이어 간다.
- 특정 프로그램의 opcode나 함수 이름을 코드에 고정하지 않는다.
- 기본 Action 경로는 `if`·`switch case` 목록을 만들거나 분기 수로 작업을 예약하지 않는다. 열린 소스의 조건문은 입력이 효과에 도달하는 경로를 설명할 때만 근거로 사용한다. `OperationSeed`는 과거 분기 기반 경로의 호환 자료형이다.
- 같은 Entry 세션에서 함수 원문을 하나씩 열어 외부 입력 형식, 실제 처리 효과, handler 및 응답 근거를 확인한다. 명명된 dispatcher는 필수가 아니다. 하나의 분기가 여러 동작에 관여하거나 여러 분기가 하나의 동작을 구현할 수 있다.
- SVF의 가능한 함수 포인터 대상과 Fuzz Introspector의 보고 간선은 추가 소스 탐색의 단서다. 기본 Action 경로에서 정적 경로 확정에는 소스 위치가 있는 직접 호출만 사용한다. 이 때문에 실제 콜백 동작도 원본 요청별 실행 근거가 없으면 `POSSIBLE`로 남을 수 있다.
- 입력 값이 소비 함수로 이동했다는 정적 판정도 소스 위치가 있는 직접 호출만 사용한다. 보고된 호출·간접 호출은 다음에 열 함수의 후보로 남긴다. Entry 함수 안에서 처리 동작을 주장할 때는 입력 획득 **이후** 그 입력의 사용을 소스 위치로 지목해야 하며, 내부 상태 `if`만으로 Action을 확정하지 않는다. 이 검사는 최소한의 어휘 검사이므로 별칭·실제 분기 실행은 원본 요청별 검증이 필요하다.
- Action별 입력 예시에는 열린 소스 근거가 필요하다. 모르는 동작은 추측하거나 완료 처리하지 않고 미해결로 남긴다. 원본 실행 성공과 하네스 품질은 후속 검증 단계의 책임이다.
- 프로젝트가 제공하는 test/client/example/corpus/spec은 별도 `UsageArtifact` 목록으로 수집한다. 사용자가 명시한 `.bin`, `.raw`, `.seed`, `.input`, `.dat`, `.req` 파일은 원본 실행용 바이트 가설로 읽는다. PCAP과 문서는 직접 외부 요청으로 보내지 않는다. 입력 파일의 존재는 runtime 도달 증거가 아니다.
- NetLifter/Popeye BNF가 제공되면 입력 배치 근거로 사용하지만, source 및 runtime 증명을 대체하지 않는다.
- FuzzGen, Hopper, WINNIE, RUBICK 출력이 제공되면 action 순서 제약으로 사용하며, 매핑이 모호하면 추측하지 않고 obligation으로 남긴다.

### 실제 빌드 문맥 제공

소스의 `#include`, `#ifdef`, 생성 헤더는 제품의 실제 빌드 설정에 따라 달라진다. 분석에는 이미 생성된 Clang compilation database를 전달하는 방법을 우선 사용한다.

```bash
PYTHONPATH=src python3 -m harnesscreator analyze /path/to/source \
  --analysis-compile-database /path/to/build/compile_commands.json
```

Make 등에서 데이터베이스가 없다면 **사용자가 확인한 실제 빌드 명령**을 Bear로 기록할 수 있다. 이 명령은 소스 디렉터리에서 실행되며 일반 빌드 산출물을 쓴다. `bear`가 설치되지 않았거나 컴파일 호출이 기록되지 않으면 분석을 시작하기 전에 오류를 낸다.

```bash
PYTHONPATH=src python3 -m harnesscreator analyze /path/to/source \
  --analysis-build-command 'make -B'
```

`run`에도 같은 두 옵션을 사용할 수 있다. 빌드 명령을 모델이 추측하거나 자동 실행하지 않는다. 이 데이터베이스는 함수 원문과 호출 후보를 정확히 읽는 데 쓰이며, 링크 대상·원본 요청 실행·입력에서 효과까지의 의존 관계를 증명하지 않는다. CMake 빌드에서는 데이터베이스의 컴파일 작업 디렉터리와 실제 `CMakeCache.txt`·`CMakeFiles` 링크 기록을 대조해 **유일한** 타깃만 선택한다. 둘 이상이면 추측하지 않고 미해결로 남긴다. 빌드 문맥을 추가해도 요청별 인과 계측이 없는 일반 데몬의 하네스를 `QUALIFIED`로 자동 승격하지 않는다.

## 호출 수와 초기 결과까지의 시간

기존 memcached 로그에는 `ACTION BRANCH` 소스 열람이 705회 기록됐다. 이를 Entry와 함수 이름으로 묶으면 108개 조합이다. `process_command_ascii`는 98회 열렸다. `STATE OPEN`은 275회였고 첫 번째로 연 handler 이름은 14개였다. 이는 **로그에 기록된 소스 열람 통계**이며 전체 모델 호출 수와 일치하지 않는다.

현재 Action 분석은 Entry별 한 소스 탐색에서 외부 요청 동작을 복원한다. 분기 수로 LLM 작업 수를 정하지 않는다. 같은 handler에서 진행하는 State 분석은 묶을 수 있지만 각 Action의 상태 계약은 독립적으로 확인한다. Entry 전체의 미탐색 경로와 개별 Action의 근거 완료도 따로 판단한다. 다른 경로가 남아 있어도 해당 Action의 입력 형식·경로·handler·결과가 소스로 확인되면 정적 후보로 유지하며, 남은 경로는 미해결 항목으로 기록한다. 다만 모델이 동작을 빠뜨렸는지 완전히 판정하는 검사는 아직 없다. 자세한 근거와 위험은 [의미기반_동작_재설계_근거.md](docs/의미기반_동작_재설계_근거.md)에 적었다.

Action 발견 직후의 `actions/source-groups.jsonl`은 **소스 효과를 함께 검토할 후보**다. 같은 이름·handler·입력 주체라는 조건은 비교 대상을 찾는 데만 쓴다. 비교에 필요한 parser·completion·response 함수가 빠졌으면 모델이 정확한 함수 이름 또는 ID를 요청해 같은 세션에서 추가로 연다. `SAME_SOURCE_EFFECT`만 `actions/effect-families.jsonl`에서 하나의 효과가 되며, 입력 생성과 실행 검증은 `actions/input-routes.jsonl`에 기록된 각 Action 경로에서 따로 수행한다. `DIFFERENT`·`UNRESOLVED`는 합치지 않는다. 입력 생성 이후 각 Action의 상태 계약과 원본 실행 witness를 대조한 결과는 `actions/group-validation.jsonl`에 별도로 기록한다. 이 결과도 경로별 퍼징 coverage를 대신하지 않는다.

선택한 실행 파일 옆의 Makefile이 정확한 소스·오브젝트 링크 폐쇄를 제공할 때만 해당 C/C++ 소스 범위로 Entry 발견을 좁힌다. 근거와 적용 여부는 `analysis/target-source-closure.json`에 기록한다. 링크 폐쇄를 증명할 수 없으면 기존처럼 넓게 탐색하며, 컴파일 데이터베이스에 파일이 없다는 사실만으로 제품 코드를 제외하지 않는다.

`scenario_command`가 구성되어 있으면 Action 요청 복원 후 원본 프로그램에서 단일 입력 후보를 먼저 시험한다. 이름 붙은 Action이 없는 Entry의 원시 입력 가설은 별도 inventory에 남긴다. `input-surfaces/runtime-trials.json`은 현재 원시 후보의 지연 상태를 기록하고, 실제 실행 witness는 `scenarios/witnesses/`에 저장한다. 입력이 특정 handler에 도달했다는 요청별 증거가 없으면 `PROVEN_RUNTIME`으로 승격하지 않는다.

이후 의미상 Action 분석을 완료하면 `--scenario-exploratory-drafts` 또는 `--source-only-drafts`에서 단일 요청 preflight를 다시 수행한다. 이미 시험한 동일 시나리오는 중복 실행하지 않는다. 근거가 확보되면 `harnesses/preflight/`에 소스 초안을 저장한다. 상태 분석은 그 뒤에도 계속한다.

초기 소스는 하네스 통과 결과가 아니다. 이후 정적 검사, 실제 컴파일, sanitizer, 실행 동등성 확인이 필요하다. 전체 memcached 재실행을 아직 수행하지 않았으므로 실제 절감 시간과 최종 하네스 도달률은 미측정이다. 상세 근거는 [EVIDENCE_WORKFLOW.md](EVIDENCE_WORKFLOW.md)를 참고한다.

## 정상 흐름 복원

예를 들어 조회 성공에 특정 객체가 필요하면 상태 분석은 다음 관계를 source로 증명한다.

```text
조회 handler의 성공 분기
  ← 객체 존재 검사가 참이어야 함
  ← 같은 binding을 가진 생성 action이 객체를 만듦
  ← 생성 요청 성공 응답을 먼저 관찰해야 함
```

`ScenarioPlanner`는 이 관계를 사용해 요청 순서를 탐색한다. binding 값도 함께 추적하므로 `SET a → GET b`처럼 상태 종류만 맞고 값이 다른 순서는 채택하지 않는다. 첫 요청 전 상태의 binding도 source가 증명한 구체 값이 없으면 사용하지 않는다. 한 action에 source-derived 요청 예시가 여러 개면 설정된 개수만큼 서로 다른 순서·입력 대안을 보존하고 원본에서 각각 실행한다. 탐색 상태 또는 전체 후보 한도에 도달하면 생략된 target을 성공으로 숨기지 않고 `scenarios/planning-obligations.json`에 기록한다. 최종 승격은 각 요청 이후 응답 표식뿐 아니라 요청 직후의 정확한 acquisition line, 동작을 선택한 소스 위치, handler가 같은 trace slice에서 순서대로 관찰됐을 때만 일어난다.

앞 요청의 응답이 뒤 요청의 입력을 결정하는 경우도 같은 원칙으로 처리한다. Input Action Agent가 응답 직렬화 source에서 고정 길이 값의 정확한 위치와 폭을 증명하면 이를 `ResponseBindingExtractor`로 기록한다. Planner는 값을 미리 지어내지 않고 후속 요청에 `RequestBindingUse`와 요청 template만 남긴다. Original Runtime Verifier가 실제 응답에서 값을 추출해 후속 요청의 해당 field에 넣고, 모든 단계가 성공한 경우에만 구체적인 실행 요청을 witness로 보존한다.

```text
LOGIN 응답의 session_id[4]
  → 실제 응답에서 4바이트 추출
  → 후속 USE 요청 template의 session_id field에 삽입
  → 원본 프로그램에서 USE 성공 확인
```

offset·width·응답 생성 source 중 하나라도 증명되지 않거나 가변 길이 값이면 현재 구현은 이를 추측하지 않고 obligation으로 남긴다.

## 하네스 안전 계약

Harness Generator와 독립 Harness Verifier는 HC01~HC16을 각각 확인한다.

- 자원 수명, 해제 후 사용, 반복 실행 상태 격리
- fuzz `Data/Size`의 실제 target 전달
- 길이 검사, 문자열 경계, 정렬 및 정의되지 않은 동작
- target parser/dispatcher 재구현 금지
- 실제 시작·종료 순서와 결과 처리
- witness의 선행 action, binding, 성공 oracle 보존
- 선행 응답으로 생성된 동적 binding의 실제 수신·길이 검사·추출·후속 요청 patch 순서 보존
- 각 선행 요청과 최종 fuzz 요청을 witness에 기록된 각자의 Entry/transport에 전달
- 호출 함수 존재와 열린 source 근거
- 최종 입력을 `hc_fuzz_request = Data`, `hc_fuzz_request_size = Size`로 묶고 그 두 값을 실제 Entry/transport 전달 지점에서 함께 사용

정적 통과 후에도 실제 compiler/linker와 sanitizer 계측을 확인한다. 동적 검증을 켜면 seed replay, target 도달, coverage 성장까지 검사한다.

하네스 crash는 그대로 취약점으로 인정하지 않는다.

```text
harness crash seed
  → HarnessPlan의 setup 요청 + crash seed로 외부 입력 열 복원
  → 새 원본 프로세스의 setup 응답에서 동적 binding을 다시 추출
  → 원본 프로그램에 동일 순서 재생
  → sanitizer 종류·오류 종류·공통 target frame이 같은 crash 재현: ORIGINAL_REPRODUCED
  → 정상 종료, 무관한 crash 또는 signature 불일치: HARNESS_ARTIFACT
```

## 설치와 테스트

```bash
cd /mnt/c/harness/harnesscreator
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
pytest -q
```

현재 통합 테스트는 작은 실제 C 프로그램을 컴파일한 뒤 다음 전체 경로를 실행한다.

```text
fread Entry 탐지
→ dispatcher action 복원
→ stateless contract 증명
→ 원본 프로그램에서 acquisition → handler 순서와 X / OK 응답 확인
→ ScenarioWitness 생성
→ 하네스 생성
→ HC01~HC16 정적·독립 검토
→ ASan/UBSan 계측 빌드
```

## 실행

Clang 기반 입력 흐름 분석에는 대상 프로그램을 실제로 컴파일할 때 쓴 매크로·헤더 경로가 필요하다. `compile_commands.json`을 먼저 만들고 `--analysis-compile-database`로 전달한다. CMake 프로젝트는 `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, Make 프로젝트는 해당 빌드를 Bear로 기록할 수 있다. 빌드 명령을 모르는 프로젝트에 임의의 `make`를 적용하지 말고 그 프로젝트의 실제 빌드 절차를 기록해야 한다. 근거: [Clang JSON Compilation Database 명세](https://clang.llvm.org/docs/JSONCompilationDatabase.html).

실측 예시: 깨끗한 memcached 소스에서 빌드 명령 기록 없이 분석했을 때 C AST 파일 44개가 실패했고, `bear -- make -B -j4 memcached`로 기록한 46개 컴파일 명령을 전달하자 기록 대상 46개가 모두 파싱됐다. 이 수치는 AST 입력 경로 개선만 증명하며 하네스 생성 성공을 뜻하지 않는다.

SVF가 필요한 실행에서는 같은 컴파일 데이터베이스로 LLVM 비트코드를 별도의 분석 디렉터리에 생성할 수 있다. `--require-svf`는 비트코드 생성이나 SVF 실행이 실패하면 모델 호출 전에 중단한다. 실제 memcached 빌드의 46개 기록에서 비트코드를 생성하고 SVF 호출 관계를 받아오는 경로를 검증했다. SVF 결과에 없는 간접 호출이 없다는 뜻은 아니다. 컴파일 옵션이나 도구 버전이 맞지 않는 다른 프로젝트에서는 실패 원인을 확인해야 한다.

LightFTP의 실제 컴파일 기록 4개에서는 Clang AST가 FTP 처리 함수 테이블의 호출 위치와 후보 32개를 찾았지만, 동일 빌드 최적화 설정의 SVF는 해당 간접 호출 간선을 보고하지 않았다. 이런 경우 `indirect_callgraph=partial`과 `svf_ast_table_sites_without_matching_symbol_edges`를 남기고 경고한다. 테이블 구성원은 다음 소스를 여는 단서이며, 요청이 어느 handler를 선택했는지에 대한 증거가 아니다. 동일 소스·도구·비트코드 내용으로 재분석하면 SVF 결과를 캐시에서 재사용한다.

`analyze`와 `run`은 같은 소스 체크아웃에 대해 동일한 Fuzz Introspector·SVF 캐시를 사용한다. 새 결과 디렉터리로 반복 실행해도 소스와 도구 버전이 같으면 FI 보고서를, 비트코드 내용과 도구 버전이 같으면 SVF 결과를 재사용한다. 캐시는 임시 디렉터리의 `harnesscreator-fi-cache/`와 `harnesscreator-svf-cache/` 아래에 저장된다.

전체 입력 경로 탐색과 **미검증** C 초안 생성 (원본 명령과 OSS-Fuzz 레시피 없이, 명시적 선택):

```bash
harnesscreator run /absolute/source --output /absolute/runs \
  --analysis-compile-database /absolute/build/compile_commands.json \
  --provider codex --daybreak \
  --allow-source-analysis --no-svf --allow-partial-indirect-calls \
  --source-only-drafts
```

원본 프로그램 실행 명령과 입력 채널은 소스 탐색의 필수 조건이 아니다. 기본 `--scenario-channel auto`는 Action별 실행 채널을 선택한다. 원본 실행 근거 없이 C 초안을 만들려면 `--source-only-drafts`를 명시해야 하며 결과는 `QUALIFIED`가 아니다. 자세한 설명은 `UNIVERSAL_INPUT_EXECUTION.md`를 참고한다.

### 원본 요청 실행과 미검증 초안

```bash
harnesscreator run /absolute/source \
  --output /absolute/runs \
  --analysis-compile-database /absolute/build/compile_commands.json \
  --allow-source-analysis \
  --scenario-command '/absolute/source/server --foreground' \
  --scenario-channel tcp \
  --scenario-host 127.0.0.1 \
  --scenario-port 11211 \
  --scenario-evidence /absolute/source/tests \
  --scenario-exploratory-drafts \
  --verification-backend command \
  --build-command 'g++ -fsanitize=address,undefined {harness} project_objects.o -o {output}/fuzz_target' \
  --binary '{output}/fuzz_target' \
  --workers 4 \
  --agent-debug
```

기본 `--scenario-attribution gdb`는 중단점 순서만 관찰하므로 특정 요청이 handler를 실행했다는 근거가 아니다. 따라서 위 명령은 원본 요청 시험과 초안 작성용이며 `QUALIFIED`를 만들지 않는다. 관찰된 요청의 초안이 다른 정적 항목을 통과하면 해당 요청 한 건을 생성 바이너리에 반복 재생하고 `harnesses/*/attempt-*/exploratory-replay.json`에 결과를 저장한다. 이 재생도 원본 요청 귀속 증거가 아니다. 엄격한 판정에는 원본 빌드가 요청 ID, 실제 획득한 바이트, Entry, handler를 연결한 이벤트를 기록하고 `--scenario-attribution trace`로 검증해야 한다. 현재 일반 C/C++ 데몬을 자동으로 그런 빌드로 바꾸는 기능은 없다. 검증 수준과 남은 한계는 [원본 흐름 판정](docs/원본흐름_검증_판정_2026-10-31.md)에 정리했다.

pathname 기반 Unix 도메인 **스트림** 소켓을 쓰는 데몬은 신뢰된 원본 실행 명령에 `{scenario_socket_path}`를 넣고 `--scenario-channel unix_stream`을 지정할 수 있다. 실행마다 새로운 임시 pathname을 만들며 이미 존재하는 경로는 지우지 않는다. 원본 명령에서 경로를 직접 설정한다면 `--scenario-socket-path /absolute/path.sock`을 쓴다. Unix 데이터그램·seqpacket·추상 namespace는 현재 실행 대상이 아니며, 이 모드에서도 요청별 trace가 없으면 `QUALIFIED`가 아니다.

### OSS-Fuzz 검증

```bash
harnesscreator run /absolute/source \
  --output /absolute/runs \
  --analysis-compile-database /absolute/build/compile_commands.json \
  --scenario-command '/absolute/source/server --foreground' \
  --scenario-channel tcp \
  --scenario-host 127.0.0.1 \
  --scenario-port 11211 \
  --scenario-evidence /absolute/source/tests \
  --verification-backend oss-fuzz \
  --oss-fuzz-dir /absolute/oss-fuzz \
  --oss-fuzz-project PROJECT \
  --oss-fuzz-fuzzer FUZZER \
  --oss-fuzz-source-path /src/PROJECT \
  --scenario-exploratory-drafts \
  --no-svf \
  --workers 4 \
  --agent-debug
```

OSS-Fuzz 백엔드는 **공식** `infra/helper.py`를 빌드 및 퍼징 실행 도구로만 사용한다. 기존 `Harness Generator Agent`, 정적 검사, 독립 검토와 `HarnessVerifierAgent`는 그대로 유지한다. **QuartetFuzz 소스 또는 실행 환경은 필요하지 않다.** 공식 OSS-Fuzz 체크아웃과 Docker는 필요하다. `--verification-backend command`에서는 사용자가 제공한 빌드 명령과 바이너리 경로를 이용한다.

TCP와 UDP를 함께 분석하는 memcached 실행에서는 기존 실행 명령의 `--scenario-channel tcp`를 `--scenario-channel auto`로 변경한다. `--scenario-response-protocol memcached_ascii`와 `--scenario-exploratory-drafts`도 지정한다. `auto`는 입력 경로에 맞춰 전송 방식을 선택한다. `tcp`를 유지하면 UDP 요청을 실행하지 않는다. 첫 결과는 `input-surfaces/runtime-trials.json`에서 확인한다. 전체 memcached 재실행은 아직 검증하지 않았다. 재실행 전에는 [WORKFLOW_EVIDENCE_REBUILD.md](WORKFLOW_EVIDENCE_REBUILD.md)의 제한 사항을 확인한다.

현재 OSS-Fuzz 백엔드는 실제 빌드와 제한된 seed replay 및 smoke-test를 수행한다. 그러나 정확한 목표 함수 도달과 원본/하네스의 동등성을 입증하지 못하므로 **`QUALIFIED`를 반환하지 않는다.** `--no-dynamic-verification`을 지정하면 빌드만 수행한다. 이 제한을 숨기고 `COMPLETED`로 집계하지 않는다.

## 주요 산출물

```text
RUN/
├── analysis/
│   ├── functions.jsonl
│   ├── edges.jsonl
│   ├── completeness.json
│   ├── upstream-usage-evidence.json
│   └── project-usage-artifacts.json
├── entries/
│   ├── candidates.jsonl
│   ├── verified.jsonl
│   ├── unresolved.jsonl
│   ├── rejected.jsonl
│   └── uninspected-functions.json
├── input-surfaces/
│   ├── inventory.jsonl
│   ├── obligations.json
│   └── runtime-trials.json
├── actions/
│   ├── inventory.jsonl
│   └── operation-seeds.json
├── scenarios/
│   ├── state-dependency-graph.json
│   ├── candidates.jsonl
│   ├── planning-obligations.json
│   └── witnesses/*.json
├── harness-plans/plans.jsonl
├── harnesses/HARNESS/attempt-N/
│   ├── scenario-witness.json
│   ├── harness-plan.json
│   ├── fuzz_target.cc
│   ├── static-audit.json
│   ├── independent-audit.json
│   └── build-validation.json 또는 validation.json
├── findings/*/original-replay.json
├── debug/agent-events.jsonl
├── debug/agent-trace.log
├── trajectories/llm.jsonl
└── summary.json
```

## 실행 상태

- `COMPLETED`: 모든 계획이 동적 검증까지 통과하고 UNRESOLVED Entry, operation inventory, 상태 관계, 시나리오 탐색, target action에 미해결 의무가 없음
- `PARTIAL`: 일부만 qualification 통과
- `BUILD_VERIFIED_DRAFT_COMPLETE/PARTIAL`: sanitizer 빌드는 통과했으나 runtime qualification을 생략
- `SOURCE_ONLY_DRAFTS_NOT_QUALIFIED`: 원본 실행 증명 없이 소스 기반 C 초안만 생성함
- `FAILED_NO_RUNTIME_WITNESS`: 원본에서 성공한 정상 요청 열이 없음
- `FAILED_NO_VALID_HARNESS`: 정적 또는 독립 하네스 검증을 통과하지 못함
- `FAILED_NO_BUILDABLE_HARNESS`: 실제 빌드·계측을 통과하지 못함
- `FAILED_AGENT_INFRASTRUCTURE`: stateful model session 등 분석 인프라 실패
- `FAILED_VERIFICATION_INFRASTRUCTURE`: compiler, Docker, GDB, coverage runner 등 검증 인프라 실패

## 현재의 명시적 한계

- 내장 원본 실행기는 `stdin`, `tcp`, `udp` 및 단일 실행의 `file`, `argv`, `env`를 지원한다. `file` 입력은 `{input_file}`, `argv`는 `{input_arg}` 실행 인자 형식을 요구하며, 환경변수 키는 고유한 `getenv("NAME")` 소스 근거 또는 `--scenario-input-env`를 필요로 한다. IPC/RPC, device, TLS, 혼합 채널 또는 상태를 유지해야 하는 다단계 파일 실행은 아직 일반적으로 검증하지 못한다.
- 현재 정확한 source-line probe는 TCP/UDP에서만 활성화된다. 임의 binary stdin과 GDB 제어 입력을 안전하게 분리하지 못하므로 stdin은 응답만으로 승격하지 않고 fail-closed 처리한다.
- 원본 실행 binary에는 현재 checkout과 일치하는 debug line 정보가 필요하다. breakpoint를 설치하거나 line을 관찰할 수 없으면 `PROVEN_RUNTIME`이 아니라 infrastructure/unproven 결과가 된다.
- 정적 호출 그래프에는 비동기 큐와 콜백 관계가 누락될 수 있다. 소켓/큐의 어휘적 대응은 다음 분석 후보일 뿐, 실제 호출이나 요청 귀속의 증거가 아니다. SVF 간접 호출 분석은 선택적이며, `indirect_possible`도 실제 실행 증명이 아니다.
- 성공 oracle은 source에 존재하는 응답·상태 표식이어야 한다. 표식이 없으면 성공을 추측하지 않는다.
- 응답에서 후속 요청으로 전달되는 값은 현재 고정 offset·고정 width의 byte binding만 자동 처리한다. 길이 prefix, delimiter 또는 암호화로 길이가 실행 중 달라지는 값은 별도 extractor가 구현되기 전까지 차단한다.
- 원본이 동일한 크래시를 재현하지 못하면 `UNCONFIRMED`로 기록한다. 이것은 하네스 자체 오류를 증명하지 않는다. crash 귀속에는 하네스와 원본 실행의 정규화된 crash signature가 필요하다. 따라서 sanitizer finding의 동일성을 판정하려면 원본 실행 binary도 대응 sanitizer로 빌드해야 한다.
- 원본 재현은 지정된 build, 환경, command에 대한 증명이다. 모든 배포 환경에 대한 형식적 증명은 아니다.
- 여러 스레드나 배경 요청이 있는 서버에서 현재 GDB 표식은 요청 시간 구간의 줄 실행 순서만 기록한다. 같은 요청 또는 같은 스레드의 인과 경로라는 보장은 없으므로, 해당 대상의 `PROVEN_RUNTIME`을 절대적 증명으로 해석하지 않는다.
- 기본 응답 판정은 상태 표식을 응답 줄 단위로 비교한다. 같은 줄의 일부 문자열 충돌은 막지만 임의 프로토콜의 프레임, 다중 응답, 비동기 메시지까지 해석하지 않는다. 프로토콜별 파서 없이는 일반적인 성공 판정이 성립하지 않는다.
- 상태 계약은 마지막 분석 턴에서 앞선 상태 주장을 모두 다시 확인해야 한다. 이전 턴의 근거 없는 주장, 최종 턴에서 사라진 주장, upstream 순서 제약 때문에 강등된 계약의 초기 상태는 계획에 사용하지 않는다.
- 요청 예시의 binding은 근거가 있는 필드 offset/width의 실제 바이트와 맞아야 한다. 필드 밖으로 뻗는 예시 또는 주장한 값과 실제 값이 다른 예시는 계획에서 제외한다.


연구 구현의 고정 revision과 통합 경계는 [`../research-repos/LOCK.json`](../research-repos/LOCK.json)과 [`../research-repos/SOURCE_MAP.md`](../research-repos/SOURCE_MAP.md)에 기록한다.


`--scenario-response-protocol memcached_ascii`를 지정하면 TCP의 memcached ASCII 저장 요청과 단일 키 `get`/`gets`의 완전한 응답을 파싱한다. 저장 성공은 `STORED\r\n` 전체로 확인하고 `NOT_STORED` 등은 실패로 취급한다. 조회는 길이와 `END`를 확인하며 누락 키는 성공으로 취급하지 않는다. 이외 명령이나 다중 키 조회는 미검증 처리한다. 기본 `markers` 모드는 여전히 프레임 인식이 없으므로 그 성공 판정만으로 보장할 수 없다. GDB 표식의 요청별 인과관계 문제는 이 옵션으로 해결되지 않는다.

## Codex app-server (ChatGPT 로그인)

HarnessCreator는 `--provider codex`를 기본값으로 사용한다. `codex app-server`를
로컬 자식 프로세스로 실행하고 JSONL 프로토콜로 통신한다. 기존 Codex CLI에서
ChatGPT 계정으로 로그인한 상태를 사용하므로 이 연결에 별도 `OPENAI_API_KEY`는
필요하지 않다. 실행 전에 `account/read`로 인증 유형을 확인한다. API 키 로그인은
별도 API 요금이 발생할 수 있으므로 실행을 중단한다. 계정의 Codex 사용량과
접근 권한은 그대로 적용된다.

Codex CLI 0.164.0 이상에서 먼저 연결 상태를 확인한다.

```bash
harnesscreator doctor --source /absolute/source --daybreak
```

`doctor`는 기본적으로 모델 호출을 하지 않는다. 실제 Daybreak 접근 권한까지
확인하려면 `--turn`을 추가한다. 이 경우 작은 모델 요청 1회가 사용량에 포함된다.

기본 모델 분배는 다음과 같다.

- `entry_generator`: `gpt-5.6-sol`
- 나머지 주요 분석·검증 역할과 하네스 생성: `gpt-5.6-sol` (임시 기본값)

`gpt-5.6-sol`은 일반 보호 수준으로 실행한다. `--daybreak`를 지정해도
이 모델에는 Daybreak 전용 프로그램을 요청하지 않는다.
이 요청은 Daybreak 사용 권한을 부여하지 않는다. 계정에 권한이 없으면 서버 오류가
발생하며 일반 모드로 조용히 전환하지 않는다. CLI는 Daybreak 기능을 활성화한
뒤 실험적 app-server `daybreakEnabled` 필드도 사용한다.

```bash
harnesscreator run /absolute/source --output /absolute/runs \
  --provider codex --daybreak --workers 1 \
  --candidate-model gpt-5.6-sol --strong-model gpt-5.6-sol \
  --coding-model gpt-5.6-sol
```

Codex CLI가 설치되어 있지 않으면 먼저 설치한다. ChatGPT 계정으로 Codex CLI에
로그인한 뒤 위 명령을 실행한다. `model/list` 결과에 선택한 모델이 없으면
모델 호출 전에 오류를 반환한다. 모델 목록은 계정 사용 권한의 최종 증명이
아니므로 `doctor --turn`으로 확인해야 한다.

모델 교체 자체는 Action/State의 반복 소스 열람을 없애지 않는다.
현재 Action 탐색은 외부 입력을 처음 받는 함수에서 시작해 입력이 전달되거나
입력에 의해 호출이 선택되는 다음 함수 원문을 한 번에 하나씩 연다. 조건문 하나를
기능 하나로 세지 않는다. 직접 전달 후보가 여러 개일 때 모델이 선택하지 않은
함수는 자동으로 모두 열지 않고 `actions/continuations.json`에 남긴다.
입력 형식 단계의 여러 소비 함수도 같은 방식으로
`input-surfaces/continuations.json`에 남긴다.
이전 실행 디렉터리를 `--resume-from /absolute/runs/RUN_ID`로 지정하면 원문과
Entry 지문이 일치하는 미열람 Action 또는 입력 형식 후보 하나를 이어서 연다. 이전 LLM 호출은
정확히 일치할 때만 재사용한다. 오래된 기록에 지문이 없거나 소스가 달라졌으면
자동 후보 선택을 생략하고 이유를 미완료 항목에 남긴다. 이 기능은 원문 탐색
재개이며 원본 실행·하네스 검증의 성공을 뜻하지 않는다.
Action별 요청 입력 복원이 끝나면 `actions/request-checkpoints/`에 결과를 즉시
저장한다. `--resume-from` 재실행에서는 해당 Action 입력과 색인된 함수 원문 및
로컬 헤더 내용의 지문이 모두 같을 때만 이 결과를 재사용한다. 지문이 다르거나
체크포인트가 없으면 요청 입력을 다시 분석한다. 진행 로그의
`[ACTION REQUEST] 완료수/전체수`는 이 단계의 실제 완료 건수다.

## Ollama cloud provider (선택 사항)

Use `harnesscreator run SOURCE --provider ollama` with a running, authenticated
Ollama server. The default endpoint is `http://127.0.0.1:11434`; use
`--ollama-url` to change it. Project source and analysis evidence in model
prompts are sent to the configured provider.

The default roles are `glm-5.3-flash:cloud` (entry generator, high),
`glm-5.3:cloud` (entry verifier and input action, high; state dependency and
harness verifier, max), and `kimi-k2.7-code:cloud` (harness generator, model
default). Legacy small/large feature roles use `glm-5.3:cloud` at high. The
`--effort` option applies to Codex; Ollama uses these role-specific settings.
The existing model override flags also apply to Ollama and must name models
compatible with the selected role's thinking level.

Ollama cloud does not enforce structured output schemas. The adapter validates
JSON locally against the requested schema, retries once on malformed output,
and fails the turn if validation still fails. This validation checks structure,
not factual correctness or harness execution.

## 요청별 검증 및 독립 회귀 테스트

최신 구현과 남은 제약은 [VALIDATION_AND_GENERALIZATION.md](VALIDATION_AND_GENERALIZATION.md)를 참고한다. `--scenario-attribution trace`는 사용자 제공 디버그 빌드의 요청별 JSONL 이벤트를 요구한다. `--require-differential-validation`은 원본과 하네스가 같은 계측 상태를 기록할 때만 통과한다. 두 설정 모두 일반 프로그램에 자동으로 적용되는 계측기가 아니다.
