# Vulnerability Analysis

이 디렉터리는 프로젝트의 **Vulnerability Scanning** 절반을 구현한다. 저장된 하네스 산출물을 읽어 취약점 후보를 분석하며, 하네스를 생성하거나 수정하지 않는다. LLM은 함수별 취약점 가설과 안전하다는 판단의 근거를 제안한다. 실제 판정은 소스코드, 로컬 실행, sanitizer, 필요 시 GDB에서 얻은 Evidence를 따른다.

## 중간발표 기준 상위 Workflow

2026년 10월 3일 중간발표의 Vulnerability Analysis Workflow를 상위 구조로 유지한다.

```text
Harness Artifact → Worker 분리 (Harness × Sanitizer)
                 → Direction Generate Agent (Entry/Core, Risk Level, Function Pool)
                    ├─ SP Generate Agent → SP Verifier Agent → PoV Generate Agent
                    │                                           └─ 실패 시드 전달 ─┐
                    └─ Hallucination Prevent Agent → Global Fuzzer ←──────────────┘
```

Function Scheduling은 Direction의 함수 선정 기능이고 SP Deduplication은 SP 경로의 내부 기능이다. 입력 생성·Runtime·Sanitizer·GDB 검증과 Crash의 Root Cause·고정 입력·독립 재실행·Security Property 확인도 기존 후보 검증의 내부 기능이다. Function Analyzer, Safe Assumption, Assertion Generator, Quality, Instrumentation, Guided Fuzzing, Violation Triage 및 SP Feedback은 Hallucination Prevent Agent 내부 기능이며 새로운 상위 Agent가 아니다. Assertion 위반만으로 취약점을 `VERIFIED`하지 않는다.

이 그림은 발표의 상위 구성요소와 시드 전달을 나타내며 실행 시각을 뜻하지 않는다. 발표 상세도에서는 Entry/Core를 Small Pool, 나머지를 Large Pool에 놓고 Hallucination Prevent가 Harness Entry를 기준으로 Context를 넓힌다고 설명한다. 이 문구만으로 Harness Entry를 Function Analyzer의 고정 분석 대상 함수로 지정했다고 단정할 수는 없다. 현재 코드는 점수·Aging으로 함수를 선정하고, 선택 함수의 Source·Harness로 SP 생성·검증·PoV를 먼저 수행한 뒤 Hallucination Prevent가 켜져 있으면 같은 선택 함수를 분석하면서 Harness Entry Source를 입력 경계로 제공한다. 첫 Function Analyzer 요청에는 별도의 Entry 식별자·호출 그래프·구조화된 입력 전파 경로가 없고, 추가 Context는 모델 요청에 따라 조회한다. 따라서 Pool 우선순위는 발표 상세도와 다르지만 HP의 함수 선택 방식이 발표 의도에 어긋나는지는 상세도만으로 확정할 수 없다. Global Fuzzer는 현재 HP 완료와 무관하게 별도 설정으로 활성화하며 초기 Corpus가 있으면 SP 분석과 중첩될 수 있다. Direction은 저장된 Feature·Call Graph로 `build_directions()`가 구성하며 별도 Direction LLM 호출은 없다. 다중 Sanitizer 입력에서는 Worker별 완료·귀속 처리 오류가 확인돼 단일 Worker Run과 같은 수준의 검증을 주장하지 않는다.

## 구성과 판단 기준

`src/vulnerabilityanalysis/models.py`에는 주요 산출물을 JSON으로 직렬화할 수 있는 dataclass가 있다. `adapter.py`는 현재 HarnessCreator의 `manifest.json`과 성공한 QuartetFuzz Reference 결과 형식을 읽는다. 빌드 명령, Corpus, Sanitizer, Runtime Reachability가 없으면 `null` 또는 `UNKNOWN`으로 남긴다. `scheduler.py`의 가중치와 예산은 `config/default.yaml`에서 조정한다. Entry/Core에 가산점을 주며, 함수 선택 다섯 자리 중 한 자리는 오래 기다린 관련 함수에 배정한다. `Low Priority != Safe`다.

`source.py`는 로컬 C/C++ 함수 하나를 추출한다. `context.py`는 요청 이유를 기록하면서 필요한 함수·Macro·상태 변경만 제한적으로 연다. `agents.py`는 함수 분석, SP 생성, SP 검증, PoC 생성, Assertion 생성을 분리하고, 역할마다 `prompts/`의 Prompt와 JSON Schema를 사용한다. Verifier가 `REFUTED`를 내리려면 정확한 소스 근거가 필요하다.

Direction은 저장된 Small Feature의 서로 다른 Entry/Core 흐름과 실제 Call Graph 연결이 모두 확인될 때 여러 개로 나눈다. 중첩된 Entry/Core 사슬이나 연결이 없는 경우, 그리고 기능이 하나인 경우에는 기존 단일 Direction을 유지한다. `analysis/edges.jsonl` 또는 Reference 정적 Index의 `edges.json`에서 Entry를 시작점으로 탐색한 함수를 Pool에 포함하며, Core의 직접 Caller는 Context용 관련 함수로 남긴다. Call Graph의 연결은 정적 근거이고 Runtime Hit가 아니다. `runtime_reachable=True`는 별도 실행 근거가 있을 때만 사용하고, 나머지는 `null`이다. Direction별 Risk는 Entry/Core의 실제 Source 동작을 기존 함수 점수기로 확인했을 때만 채우며, 근거가 없으면 `UNKNOWN`이다.

`analysis.py`는 Retry Ledger를 적용하고 Python 입력 스크립트를 별도 인터프리터에서 제한적으로 실행한다. `runtime.py`는 Shell 없이 로컬 Binary를 실행해 ASAN/UBSAN을 파싱하고, 필요할 때 Batch GDB로 함수 또는 소스 라인 Breakpoint를 확인한다. `scan.py`는 분석, SP, 검증, PoC, Runtime, Evidence, Assertion을 저장한다. 도달 근거는 `FUNCTION_REACHED`, `SP_LOCATION_REACHED`, `SP_CONDITION_REACHED`로 나눈다. 함수 진입만으로 SP 위치나 조건에 도달했다고 보지 않는다.

SP Generator는 `source_file`, 1부터 시작하는 `source_line`, 원문 한 줄 `source_excerpt`를 구조적으로 반환한다. 실제 Target 파일의 해당 줄이 분석 중인 함수의 같은 줄과 일치할 때만 `code_location=file:line`으로 저장한다. 확인할 수 없으면 `UNKNOWN`이며, 부작용 없는 실행식으로 검증되지 않은 `sp_condition`도 측정 대상으로 보내지 않는다. Verifier는 일부 하위 주장만 반박된 경우 전체 SP를 `REFUTED`하지 않고, 판정이 `UNKNOWN`이면 `REFUTE` 권고를 `REQUEST_CONTEXT` 또는 `RUNTIME_TRACE`로 바로잡는다. Context 요청은 기존 횟수·LLM 호출 예산 안에서만 수행하며 새 소스가 없으면 후보를 `OPEN`으로 둔다. Runtime의 정상 종료 분류는 측정된 수준에 따라 `NO_CRASH_BUT_FUNCTION_REACHED`, `NO_CRASH_BUT_SP_LOCATION_REACHED`, `NO_CRASH_BUT_SP_CONDITION_REACHED`로 구분한다. 측정하지 못한 위치·조건은 `null`이며 정상 종료를 안전성 반증으로 쓰지 않는다.

Crash Triage는 `TARGET_CRASH`, `HARNESS_CRASH`, `ASSERTION_VIOLATION`, `ENVIRONMENT_ERROR`, `UNKNOWN`을 구분한다. `final_verification.py`는 Crash 이후 최종 Gate를 담당한다. Target Source의 Stack Frame 하나만으로 SP를 `VERIFIED`로 만들지 않는다.

후보 상태는 `OPEN → VERIFYING → POC_PENDING → RUNTIME_PENDING → ROOT_CAUSE_PENDING → INDEPENDENT_VALIDATION → SECURITY_CHECK → VERIFIED`를 따른다. Root Cause가 미해결이거나 Verifier가 재분석을 권하면 후보는 `OPEN`으로 남기고 `REANALYZE`를 별도 작업 요청에 기록한다. 별도 Target Crash는 `runtime/crashes/`에서 중복 제거하고 실행별 Root Cause를 보존한다. 독립 재실행 실패도 `OPEN`으로 남으며 어느 경우도 자동 `REFUTED`가 아니다.

Crash와 SP의 관계는 다음처럼 기록한다.

| 관계 | 판정 근거 |
| --- | --- |
| `EXACT` | Invalid Access Stack에 SP의 소스 라인이 있음 |
| `STACK_RELATED` | SP의 함수가 Stack에 있으나 해당 라인 일치는 없음 |
| `LIFETIME_RELATED` | UAF의 Free Stack에 SP 동작이 있음 |
| `DATAFLOW_RELATED` | 해당 후보에 연결된 산출물 기반 Dataflow Evidence가 있음 |
| `UNRELATED` / `UNKNOWN` | 관계가 반증되었거나 판단 근거가 부족함 |

Allocation Stack만으로 Lifetime Root Cause를 확정하지 않는다. Root Cause 검증에는 Target 기원 Crash, 강한 소스·Lifetime·Dataflow 연결, 일치하는 Sanitizer 종류가 필요하다. 단순히 Stack에 함수가 있거나 Integer Overflow 가설에 “overflow”라는 단어가 있다는 것만으로는 부족하다. Trigger State가 미측정이면 `unknowns`에 남기고, 명시적으로 함수·SP 위치·조건에 도달하지 않았다는 추적은 Root Cause 확정과 `VERIFIED` 승격을 막는다. `EXACT`는 무효 접근 위치의 일치이며 앞선 잘못된 경계 검사까지 증명하지 않는다. 외부 입력 관계는 별도 산출물로 확인해야 `VERIFIED`에 이를 수 있다.

Fixed PoC는 생성된 입력과 Python 스크립트를 복사해 경로를 보존하고 입력·대상 Binary Hash를 기록한다. 독립 검증은 새 프로세스에서 그 입력을 다시 실행해 Sanitizer 종류와 상위 Source Signature를 비교한다. 저장된 Replay Runtime 산출물까지 확인하므로 근거 없는 `REPRODUCED` 표시는 통과하지 못한다. Security Property를 확인하려면 외부 입력 통제, 하네스 타당성, Security Impact에 각각 별도 산출물 근거가 있어야 한다. Crash나 Harness Manifest만으로 이 사실들을 추정하지 않는다. 근거가 없으면 `UNKNOWN`이며 `VERIFIED`를 보류한다. 명시적으로 검토한 `security_evidence`를 `execute_poc`에 전달할 수 있지만 LLM의 설명만으로는 통과하지 않는다.

`CandidateScheduler`는 LLM 예산과 `max_candidates` 안에서 여러 SP를 고른다. 측정된 Runtime Reachability를 확인되지 않은 소스·입력 힌트보다 높게 평가하고, 검증 비용과 대기 시간도 반영한다. 대기 슬롯은 실제 대기 나이가 다른 후보가 있을 때 오래 기다린 후보를 우선한다. 새 후보들의 대기 나이가 모두 같으면 근거 점수가 높은 후보를 고른다. 두 후보만 검증하는 예산으로 정확한 80:20 비율을 표현할 수는 없다. 점수는 실험 순서이며 취약점 확률이 아니다. GDB는 구체적인 상태 질문이 있을 때만 사용한다.

개발 실행에서는 `scan --candidate-budget-policy VERIFIER_FIRST --max-candidates 3`으로 같은 함수당 모델 턴 상한 안에서 검증기 호출을 먼저 예약할 수 있다. 기본 `PAIR_RESERVED`는 후보마다 Verifier·PoV 한 호출씩 예약한다. `VERIFIER_FIRST`에서 마지막 후보는 검증만 받고 PoV가 예산 대기로 남을 수 있으며, `scan.json`과 `sp/turn_budget.json`에 선택한 정책을 기록한다. 이 모드는 FuzzingBrain V2의 병렬 대기열을 그대로 복제한 것이 아니라 동일 예산 비교용 적응안이다. 동결된 Blind 2 실행기는 정책 변경을 허용하지 않는다.

검증 예산 밖의 SP는 `sp/candidates.json`에 `OPEN`과 대기 시간을 보존하고 `scan.json.pending_sp_ids` 및 `sp_verification_status`로 구분한다. 동일한 Harness·선택 함수의 **새 Phase 1 Run**을 만든 뒤 `scan <새 Run> --resume-from <기존 Run> --target-repository <소스>`를 실행하면, 기존 SP·Context만 읽어 같은 `CandidateScheduler`로 재선택하고 기존 SP Verifier에 전달한다. 새 Run은 원본 결과를 수정하지 않는다. 같은 후보·Context로 같은 기존 Run을 중복 재개하면 막으며, 새 Context 또는 SP Evidence가 있으면 다시 검토할 수 있다. 재개 Run에서는 FunctionAnalysis·SP 생성·Assertion 제안을 다시 호출하지 않는다.

SP 결과에는 서로 다른 상태축이 있다. `sp/candidates.json`의 `status`는 취약점 가설의 처분 상태 정본이다. `OPEN`은 아직 입증되거나 반증되지 않았다는 뜻이며, Verifier·PoV·Fuzzer가 실행되지 않았다는 뜻은 아니다. Verifier 실행 여부와 후보 예산 상태의 정본은 `scan.json.sp_verification_status`이고, PoV 실행 결과는 `poc/pocs.json`의 `status`, Blind 평가 실행기의 후속 퍼징 결과는 `runtime/runner_sp_followup_fuzz.json`의 `status`를 확인한다. 예를 들어 한 후보가 `OPEN`이면서 `VERIFIER_EXECUTED`이고 PoV 실행 후 퍼징까지 갔을 수 있다. 단일 `status` 필드만으로 탐색 기회를 판정하지 않는다.

`budget.max_llm_calls_per_function: 8`은 SP 경로와 Hallucination Prevent 경로에서 각각 적용하는 함수당 LLM 호출 상한이다. SP 생성·검증·PoV와 FunctionAnalysis·Assertion 생성의 호출 수는 `scan.json`에 `sp_llm_calls`, `hp_llm_calls`로 분리해 기록한다. 두 경로를 모두 실행하면 총 호출 수가 8회를 넘을 수 있다. 정확히 각 8회를 사용한다는 뜻은 아니며, Provider 오류나 검증 결과에 따라 더 일찍 끝날 수 있다.

Crash가 없더라도 함수, SP 위치 또는 SP 조건에 측정된 Hit가 있는 입력은 `corpus/candidate/<sp_id>/`에 보존하고 `corpus/global/`에도 복사한다. 두 Corpus의 복사 기록만으로 Fuzzer 실행을 주장하지 않는다. 후보 Corpus는 별도 지정한 libFuzzer Binary로 제한 시간 Mutation할 수 있다. Global Fuzzer는 `fuzzing.global_enabled: true`인 Config를 명시하고 `--global-fuzzer-binary`를 전달한 경우에만 실행한다. 직접 입력형 Harness는 libFuzzer 인터페이스를 확인하고 Edge·Feature Coverage를 별도로 기록한다. Process Harness는 같은 Runtime 명령으로 제한 시간 Mutation하며, LLVM 프로파일이 실제 생성될 때만 **소스 행 Coverage**를 기록한다. 이 값은 Edge·Feature Coverage나 SP 도달성으로 해석하지 않는다. 미호환·Seed 없음·예산 없음은 `runtime/global_fuzz.json`에 `BLOCKED`로 기록한다. 동일 Harness·Seed 내용의 반복은 Retry Ledger가 막는다. Fuzzing Crash 역시 검토할 Evidence일 뿐 자동 `VERIFIED`가 아니다.

FuzzingBrain V2의 SP 큐 처리 근거는 `fuzzingbrain/db/repository.py:claim_for_verify`와 `fuzzingbrain/worker/pipeline.py:_run_verify_agent`다. Global Seed 보관·실행은 `fuzzingbrain/fuzzer/manager.py:add_direction_seed/start_global_fuzzer`, Coverage 파싱은 `fuzzingbrain/fuzzer/instance.py:_parse_output`을 참고했다. 동일 Worker·Target Revision·Harness·Sanitizer·Binary의 함수별 Run은 해시로 중복 제거한 Worker Corpus를 공유한다. 유효한 초기 Seed와 Fuzzer가 있으면 Function Analysis 전에 Global Fuzzer를 시작하며 실제 중첩 시간과 Seed 이월을 기록한다. `scan <새 Run> --continue-from <완료 Run>`은 다음 함수를 선택하고, `--retry-incomplete-from <중단 Run>`은 중단된 함수를 새 Run에서 재시도한다. Worker의 Fuzzing 예산은 연결된 Run 전체에서 차감한다. 기존 파일 기반 Scheduler를 유지하며 MongoDB 큐나 상시 Fuzzer 프로세스를 복제하지 않는다.

## CodeAugur식 Assertion 경로

CodeAugur 논문에서 가져온 것은 **안전하다고 판단한 이유를 명시적으로 남기고, 실행 가능한 조건으로 검사한 뒤, 조건이 깨지면 판단을 다시 검토하는 개념**이다. Tagged Macro, 엄격한 식 필터, Source Copy 빌드 인터페이스, 상태 이름은 이 프로젝트의 구현이다.

LLM Assertion 출력은 실제 FunctionAnalysis의 Safe Assumption 문자열을 정확히 참조해야 한다. 식 필터는 함수 호출, 대입, 증감 연산을 거부한다. 선택한 Translation Unit의 복사본은 원래 빌드의 Include/Define 옵션으로 Syntax Check한 뒤 Link·실행한다. `DEQUEUE` 뒤에서 제안한 “dequeue 이전” Assertion처럼 삽입 시점이 늦으면 거부한다.

LLM이 Assertion을 만들지 못하면, 실제 `DEQUEUE` Macro 정의를 읽은 경우에만 바로 앞의 Queue Nonempty 조건에 한정된 Static Rule을 쓸 수 있다. 결과에 `generation_method=STATIC_RULE`을 기록한다. 이때 Safe Judgment는 FunctionAnalyzer에서 나왔지만 실행식은 프로젝트 규칙에서 나왔다. LLM 방식과 Static Rule 방식은 식이 같아도 서로 다른 ID를 가진다.

각 Assertion에는 원본 FunctionAnalysis, Safe Judgment와 이유, 실행식, 삽입 위치, 실행 결과를 남긴다. 입력별 상태는 `HELD_FOR_EXECUTION`, `VIOLATED`, `NOT_REACHED`, `INVALID_ASSERTION`, `BLOCKED`, `ERROR`다. `HELD_FOR_EXECUTION`은 그 실행에서만 유지됐다는 뜻이다. 위반은 `REANALYZE`를 요청하며 바로 취약점으로 확정하지 않는다. 여러 실행은 `assertions/history.json`과 `evidence.json`에 별도로 누적한다.

전체 `scan`에서 Assertion 제안이 있으면 빌드·실행 명령과 유효 입력을 사용해 원본이 아닌 소스 복사본에서 실행한다. 필요한 항목이 없으면 `assertions/execution.json`과 `scan.json`에 `BLOCKED` 및 누락 항목을 남긴다. 실행 전 원본 FunctionAnalysis에 해당 Safe Assumption이 실제로 있는지 확인한다. 위반 시 기존 GDB 위치·조건 추적을 시도하고, 같은 입력으로 원본 프로그램을 별도 빌드·실행해 `original-runtime.json`을 보존한다. `triage.json`에는 원본/계측 소스 해시, 입력 해시, 소스 행 대응, GDB 관측 또는 UNKNOWN, 두 Runtime 결과의 경로, 입력 흐름과 보안 관련 분석 정보를 기록한다. 원본에서 Sanitizer 오류가 보이면 `SECURITY_DEFECT_POSSIBLE`, 별도로 검토한 소스 인용이 안전한 처리 경로를 입증하면 `OVERSTRONG_ASSUMPTION`으로 분류할 수 있다. 그 밖에는 `INSUFFICIENT_EVIDENCE`이며 어느 경우에도 Assertion만으로 취약점을 `VERIFIED`하지 않는다. 원본의 단일 정상 실행은 안전성 증거로 일반화하지 않는다.

저장된 유효 입력 실행에 더해, `--assertion-fuzz-seconds`를 명시한 libFuzzer Scan에서는 같은 Assertion 소스 복사본을 제한 시간 동안 Fuzzing한다. Code-Augur §IV-C·§V를 참고해 Assertion당 libFuzzer Extra Counter 16칸을 사용한다. C/C++ Assertion의 도달과 위반에 각 1칸, C에서 검증된 부작용 없는 단순 unsigned 정수 비교식의 절댓값 거리에 14개 로그 구간을 사용한다. 컴파일 또는 타입 검증이 실패하면 거리 계측만 `UNSUPPORTED`로 남기고 도달·위반 계측으로 실행한다. 포인터 NULL 비교에는 수치 거리를 붙이지 않는다. 기존 `fuzz_locally`가 Corpus를 변이·갱신하고, 발견한 Assertion 위반 입력은 기존 `execute_assertion`의 원본/계측본 재실행과 Violation Triage에 전달한다. `guided_fuzz.json`, `corpus-manifest.json`, `fuzzer-runtime.json`에 각각 실행 상태, 저장된 입력과 재생 결과, libFuzzer 로그를 기록한다. 일반 Coverage 수치만으로 Assertion 반증을 주장하지 않는다.

첫 위반 입력은 별도 원본/계측본 실행으로 Triage한다. 남은 Fuzzing 예산이 있으면 같은 소스의 **새 계측 복사본**을 빌드해 해당 Assertion은 위반 Counter만 갱신하고 중단하지 않는다. 최초 Corpus와 위반 입력을 복사해 기존 libFuzzer로 변이를 계속한다. `guided_fuzz.json`의 `continuation`에 별도 빌드·실행·Corpus 결과를 남긴다. 이는 Code-Augur §IV-C의 첫 위반 후 계속 탐색 동작을 프로세스 분리로 적용한 것이며, 이후 Sanitizer Crash도 Assertion 위반과 구분한다.

Violation Triage는 실제 위반 태그, 같은 입력의 원본 Runtime, GDB 상태, 검증 가능한 Caller/Callee 소스 관계를 저장한다. 원본 Sanitizer 오류가 있으면 `SECURITY_DEFECT_POSSIBLE`, 원본이 정상 종료하고 위반 조건에서 **바로 return하는 정확한 소스 행**이 확인된 좁은 경우에만 `OVERSTRONG_ASSUMPTION`, 나머지는 `INSUFFICIENT_EVIDENCE`다. 과도한 가정으로 확인되고 LLM 예산이 남으면 기존 Function Analyzer에 위반 입력·원본 실행·검증된 Guard를 제공하고, 새 가정만 기존 Assertion Generator로 변환해 복사본 실행과 Guided Fuzzing으로 재검증한다. 수정본도 위반하고 같은 좁은 반증 근거가 확인되면 남은 LLM 예산 안에서 반복하며, 1회당 Analyzer·Assertion Generator 최대 2호출을 사용한다. 이전 Assertion의 유효 Corpus가 있으면 최대 64개를 수정본의 시작 Corpus로 넘기고 출처를 기록한다. 원래 Assertion과 재분석 결과·수정 제안·거절 사유·실행 결과는 `assertions/refinement_history.json`에 별도 보존한다. GDB의 조건식 출력값은 변수값으로 해석하지 않는다. 새 가정이나 유효한 삽입 위치가 없으면 중단 사유를 기록한다.

Assertion과 기존 SP는 **같은 소스 위치 및 정확히 반대인 단순 수치 조건**일 때만 관련 Evidence로 연결한다. 같은 함수라는 이유로 연결하지 않는다. 새 Evidence가 있으면 기존 SP Verifier를 다시 사용할 수 있지만 원래 SP Artifact는 바꾸지 않는다. 관련 SP가 없고 원본에서 Sanitizer 오류가 관측됐으며 현재 분석 함수의 Stack 근거가 있을 때만, 남은 LLM 예산 안에서 기존 SP Generator/Verifier를 재사용한다. 같은 피드백은 Fingerprint로 재요청하지 않는다. Assertion 위반만으로 `VERIFIED`하지 않는다. Process Harness의 Extra Counter Fuzzing과 복잡한 조건식 거리 계산은 `UNSUPPORTED`이며, 함수 간 Dataflow 관계의 자동 SP 연결은 아직 검증되지 않았다.

저장된 libyaml Scanner Safe Assumption 2개를 별도 Run `20261009T114020Z-assertion-743ed49f`에서 기존 144바이트 입력으로 검증했다. 실제 `scanner.c` 복사본과 기존 Harness를 ASAN/UBSAN으로 빌드해 두 Assertion 모두 `HELD_FOR_EXECUTION`을 관측했다. 이는 저장된 FunctionAnalysis/Assertion 제안을 재사용한 실행 회귀이며 신규 LLM Scan이나 일반적인 안전성 검증은 아니다.

## LLM Provider와 모델 설정

`llm.py`는 Provider 중립적인 `LLMClient`/`LLMRequest`를 제공한다. 현재 기본 `scan`은 `CodexAppServerClient`를 사용한다. Ollama Cloud 설정과 `OllamaCloudClient`는 보존하며 `--provider ollama-cloud`로 명시적으로 선택할 수 있다. Codex 요청이 실패해도 Ollama로 자동 전환하지 않는다. Ollama 인증은 실행 환경의 `OLLAMA_API_KEY` 또는 `~/.config/vulnerabilityanalysis/ollama_api_key`를 사용한다. 키를 프로젝트 설정이나 결과에 저장하지 않는다. Ollama Cloud에는 서버 측 JSON Schema 강제가 없어 Schema를 Prompt에 포함하고, 받은 JSON을 로컬에서 다시 검증한다.

`CodexAppServerClient`는 설치된 `codex app-server --stdio` 프로세스 하나를 재사용하고 JSONL `initialize`, `thread/start`, `turn/start` 요청과 Streaming Notification으로 응답을 받는다. 역할별 Session을 분리하며, Agent 호출 사이에 긴 대화 기록을 공유하지 않는다. 현재 설치된 Codex CLI 0.161.0의 `model/list`에서 역할별 모델 ID와 Reasoning 지원을 확인했다. 시작 전 ChatGPT 로그인을 확인하고 API Key Mode는 거부한다.

보존된 Tinyproxy 5함수·15함수 Blind Baseline의 모든 Agent 호출은 `gpt-6-sol` / `medium`이었다. 완료된 호출 수는 각각 39회, 115회다. 해당 실패를 약한 모델 탓으로 해석하지 않는다.

보존된 Ollama Cloud 역할별 설정은 `config/default.yaml`의 `models_ollama_cloud`에 있다. 이 설정은 **취약점 분석**에만 적용되며, `harnessgenerator/`의 Entry·Feature·Harness 역할은 변경하지 않는다.

| 역할 | 모델 | Thinking |
| --- | --- | --- |
| Direction, Function Analysis, SP Generation | `glm-5.3-flash` | `high` |
| SP Verification | `glm-5.3` | `low` |
| PoC/PoV, Assertion Generation | `glm-5.3` | `max` |
| Runtime/GDB Analysis, Root Cause Verification | `glm-5.3` | `max` |

마지막 세 역할은 현재 Scan에서 LLM을 호출하지 않으며, 표는 향후 해당 역할이 호출될 때의 설정을 나타낸다. `--model`을 지정하면 활성 역할에 동일 모델을 적용하고, 필요하면 `--effort`로 Thinking Level을 지정한다. Ollama Cloud의 모델 식별자와 Thinking Level은 API의 실제 `/api/tags`, `/api/show` 응답으로 확인했다.

완료된 `scan.json`에는 실제 Provider 이름, 기본 모델·Thinking Level, 역할별 모델 설정을 기록한다. `logs/llm_requests.jsonl`에는 역할별 요청·완료·오류, 경과 시간, API가 반환한 Token 수를 기록하며 키나 Prompt는 기록하지 않는다. Ollama Cloud가 JSON을 코드 펜스로 감싸 반환한 실제 사례가 있어, 전체 응답이 하나의 `json` 코드 블록인 경우에만 펜스를 제거한 뒤 기존 JSON Schema 검증을 수행한다. 그 밖의 형식 오류나 Schema 불일치는 Agent Evidence로 사용하지 않는다.

2026-10-08 인증된 Libyaml Cloud 실험에서는 Reference QuartetFuzz 하네스와 Clean Libyaml Checkout (`90a56d4500aa1a1798514c5cb55c3ad4cb095f94`)을 사용했다. 기본 역할별 모델 Run `20261008T124126Z-ab31c0f4`는 PoC 단계의 `glm-5.3/max` 응답을 600초 안에 받지 못해 미완료다. Flash 진단 Run `20261008T125343Z-f17772c6`은 FunctionAnalysis·SP 생성·Assertion 제안·SP 검증까지 진행했으나 PoC 응답의 코드 펜스 때문에 중단됐다. 수정 뒤 저장된 SP 하나부터 재개한 `diagnostics/poc_resume/`에서는 154바이트 Python 입력을 생성해 로컬 ASAN+UBSAN Binary를 실행했다. 함수 진입은 GDB로 확인했고, SP 위치·조건은 `UNKNOWN`, Sanitizer Finding은 없었다. 후보는 `OPEN`, `VERIFIED`는 0건이다. 이 재개는 비용을 줄이기 위한 `glm-5.3-flash/high` 진단 호출이며 기본 PoC 역할 설정을 변경한 실험이 아니다. 기존 두 Run의 결과는 보존한다.

위 SP의 Evidence 계약 재검증은 별도 Run `20261008T140206Z-sp-evidence-ce0b0c`에 저장했다. 기존 `sp-e1d67bcb87652526`의 자유 형식 위치는 정확한 Breakpoint로 쓸 수 없었으며, 기존 입력의 재실행에서 확인된 것은 함수 진입뿐이다. 수정된 SP Generator는 실제 소스와 대조된 `src/scanner.c:line` 위치의 후보 5개를 반환했다. 두 관련 위치를 같은 입력으로 추적했으나 최적화된 Binary의 GDB Breakpoint가 요청한 행과 다른 행에 설정되어 위치·조건 도달은 `UNKNOWN`으로 유지했다. Verifier는 기존 SP를 `UNKNOWN / REQUEST_CONTEXT`로 남겼고, 추가 Context를 넣은 진단 재검증에서도 같은 판정이었다. 첫 SP 생성 응답은 필수 필드 누락으로 거절됐으며, Prompt를 명확히 한 두 번째 호출이 통과했다. 이 결과는 신규 취약점 검증이 아니며 `VERIFIED`는 0건이다. 추가 Context 재검증은 기본 Context 확장 예산 밖의 진단 실행이므로 일반 Scan 완료로 계산하지 않는다.

현재 기본 Codex app-server 역할별 설정은 같은 파일의 `models`에 있다. 빠른 후보 탐색 역할은 Luna/high, 판정·검증·PoV 및 Hallucination Prevent 역할은 Sol에 배치하고 역할별 추론 수준을 분리한다. HP가 사용하는 `function_analysis`는 안전 판단과 Safe Assumption을 선택하므로 Sol/max를 사용한다. 기본 Provider는 Codex이며 Ollama로 자동 전환하지 않는다.

| 역할 | 모델 | Reasoning |
| --- | --- | --- |
| `direction_generator`, `sp_generation` | `gpt-5.6-sol` | `high` |
| `sp_verifier` | `gpt-5.6-sol` | `low` |
| `function_analysis`, `assertion_generator` | `gpt-5.6-sol` | `max` |
| `poc_generator`, `runtime_analysis`, `gdb_analysis`, `root_cause_verifier` | `gpt-5.6-sol` | `max` |

Direction, Runtime, GDB, Root Cause 역할의 모델도 설정에 있지만, 현재 Tinyproxy Scan에서 호출 수는 0이다. `--provider codex`는 이 역할별 설정을 읽는다. 모델 선택은 공통 Provider 요청 계층에만 둔다.

임시 Backend 전환 진단은 `20261008T171027Z-codex-model-smoke-7dd256d3`과 `20261008T171145Z-codex-verifier-schema-a0f9631c`에 보존했다. 저장된 libyaml 함수 분석을 입력으로 Luna/medium SP 생성 1회가 Strict JSON Schema를 통과해 후보 7개를 생성했다. 첫 Sol/medium Verifier 요청은 `contradiction_scope`와 `context_requests`가 Schema의 필수 목록에 없어 모델 추론 전에 거절됐다. Prompt와 Schema의 필수 필드를 일치시킨 뒤 Sol/medium 검증 1회가 통과했고 결과는 `UNKNOWN / REQUEST_CONTEXT`였다. 이 진단에서 Ollama 호출은 0회다. 모델별 사용량과 계측 한계는 두 번째 Run의 `backend_switch_summary.json`에 기록했다.

`phase1` 명령은 함수 하나를 선택하는 진단 경로로 유지한다. `scan` 명령은 `budget.max_functions_per_scan`(기본 3) 또는 `--max-functions`만큼 같은 Function Pool에서 다음 미분석 함수를 선택해 **각 함수를 순서대로** 분석한다. 각 함수는 별도 Run 디렉터리에 저장되고 첫 Run의 `function_scan.json`에 순서, 함수별 SP·LLM 호출 수, 남은 미분석 함수와 모델별 요청 횟수를 남긴다. 다음 선택은 직전 함수의 `scan.json`이 완료된 후에만 가능하며, 같은 완료 Run에서 중복 후속 선택을 만들지 않는다. 함수별 SP 검증 예산은 기존 설정을 그대로 사용한다.

기존 Function Scheduler는 Entry/Core, 측정된 Reachability, 정적 Call Depth, Aging을 유지하며, 실제 Source에서 확인한 Memory, Pointer/Lifetime, Length/Index, Parser, State Write 동작에 설정 가능한 가중치를 더한다. Comment와 String은 매칭에서 제외한다. Source나 신호가 없으면 `UNKNOWN`이며 함수 이름 또는 알려진 취약점 이름을 점수에 사용하지 않는다. `risk_level`은 관찰된 소스 신호의 개수를 반영하고 `priority_reasons`가 점수 구성요소를 기록한다. Function ID는 점수와 대기 시간이 같을 때만 마지막 Tie-break로 사용하며 `tie_break_reason`을 남긴다.

SP Scheduler는 반증되지 않은 후보를 모두 보존하면서 필요한 상태의 복잡성, 아직 검증되지 않은 반대 근거에 제한된 감점을 준다. 실제 함수 Source에서 순서가 확인된 Mutation/Read 구간에만 가산한다. 두 Scheduler 모두 네 Priority 자리와 한 Aging 자리를 유지한다. 함수당 Deep Verification 예산은 SP 두 개다.

## 실제 하네스 연동과 검증 결과

HarnessCreator는 이미 `project.json`, `analysis/functions.jsonl`, Feature JSON, 시도별 `manifest.json`·`validation.json`, `summary.json`을 저장한다. 추가 Export 변경은 필요하지 않다. 다만 검증 당시 프로젝트의 `harnessgenerator/`와 `result/`에는 **저장된 성공 HarnessCreator Run이 없었다.** 두 디렉터리는 읽기 전용으로 유지했고, 실제 프로젝트 HarnessCreator → Vulnerability Analysis 연동은 성공 산출물이 생길 때까지 미검증이다.

Reference 통합 테스트에는 `reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer/`의 실제 과거 성공 Libyaml Scanner 산출물을 사용했다. `result.json`에 `success=true`, `build_ok=true`가 있고 Harness C 파일도 존재한다. 과거 Binary·Corpus 경로는 다른 컴퓨터를 가리키므로 Adapter가 현재 사용 가능한 것으로 취급하거나 Runtime Reachability를 추정하지 않는다. 별도 현재 Libyaml Checkout에서 Harness를 컴파일·실행했지만, 이 Checkout이 과거 Reference Revision과 같다고 보장할 수는 없다.

이 산출물은 Sanitizer가 `UNKNOWN`인 Worker 하나, `libyaml scanner` Direction 하나, 초기 선택 함수 `yaml_parser_scan`이 있는 Function Pool을 만든다. 선택 점수, 역할, 정적 Depth, 이유를 저장한다. 별도의 로컬 ASAN+UBSAN 빌드와 GDB Breakpoint로 과거 정적 Index와 독립된 실제 도달 근거를 수집할 수 있다.

Direction/Pool 보완 후 별도 Run `20261008T152028Z-40ad2e52`에서 동일 Reference 산출물을 다시 정규화했다. 기능 흐름 하나이므로 Direction은 하나이며 Pool은 12개 함수다. 정적 도달 힌트가 있는 함수는 7개, 이 과거 Artifact만으로 Runtime Hit가 확인된 함수는 0개다. 저장된 13바이트 SP 입력은 별도 회귀 Run `20261008T151927Z-cea47c06/regression_libyaml/`에서 디버그 ASAN+UBSAN Binary로 재실행했다. 함수와 SP 위치 Hit는 확인됐지만 해당 시점의 SP 조건은 거짓, Sanitizer Crash는 없고 후보는 `OPEN`이다. 유용한 입력을 후보/전역 Corpus에 저장한 뒤 후보별 제한된 Mutation을 수행했으나 `VERIFIED` 근거는 나오지 않았다. 이 재실행은 과거 SP·입력을 이용한 연결 회귀이며 신규 LLM Scan이나 신규 SP 발견으로 계산하지 않는다.

### Tinyproxy 1.11.1 Blind Regression Baseline

별도 회귀 실험 `result/vulnerabilityanalysis/20261007T134854Z-5eacaf54/`은 공식 Tag `1.11.1`, Commit `90adf28663874e6d34d3eebeae6279906443aea5`를 사용했다. Source Checkout은 Clean이었고 Build Copy의 C/H 파일 65개가 일치했다. 성공한 프로젝트 HarnessCreator 산출물이 없었으므로 `tests/fixtures/tinyproxy/runner.py`는 `project_harness=false`인 `REGRESSION_FIXTURE`다. 생성된 HTTP Request Byte를 정상 Loopback TCP Listener의 ASAN Tinyproxy 프로세스에 보내며, Loopback Origin Server를 사용한다. 정상 Seed는 ASAN Finding 없이 HTTP 200을 받았고 LLVM Coverage에서 `handle_connection` 실행을 확인했다. 이전 ASAN+UBSAN 빌드의 관련 없는 Baseline UBSAN 진단 때문에 새 ASAN-only Coverage Build를 사용했다.

기존 Worker, 기능별 Direction, Pool Scheduler, 함수 하나씩 분석, 분리된 SP 생성·검증, Python 입력 생성, Runtime Executor로 Blind Scan을 실행했다. 첫 5개 함수 분석에서 Codex app-server 완료 호출 39회, SP 30개, 입력 파일 6개, Candidate Runtime 실험 6회를 기록했다. 세 입력의 Coverage-only 재실행은 선택된 각 함수의 Entry 도달을 확인했으나, 설명식 SP 위치에 대해서는 `SP_LOCATION_REACHED`와 `SP_CONDITION_REACHED`가 `UNKNOWN`이었다. ASAN Crash가 없어 Crash Relation 이후 단계에 진입하지 않았고 `VERIFIED`는 0건이었다. Process Fixture는 libFuzzer Binary가 아니므로 Targeted libFuzzer Mutation을 실행하지 않았다. Assertion 제안 5개는 기록됐지만 이 Regression에서 삽입·실행하지 않았고, 별도 Assertion Integration은 존재한다.

Blind 결과는 `blind_regression_summary.json`으로 먼저 고정했다. 그 뒤에만 `post_blind_comparison.json`에서 알려진 문제와 비교했다. 알려진 `remove_connection_headers`는 Runtime에 도달한 CORE 함수로 Pool에 있었지만 5함수 예산에서 선택되지 않았고, 새 근거 없이 같은 Scheduler 상태를 계속하면 예상 13순위였다. 인접 `process_server_headers` SP는 해당 함수를 언급했으나 알려진 Lifetime 원인을 특정하지 못했다. 이것은 **실험 예산 내 Scheduling Miss**이지 Candidate 반증이 아니다. Fixture의 고정 Upstream Response도 Server Header 실험을 제한한다. Agent Prompt에는 알려진 Crash Input, Advisory, 수동 Stack을 넣지 않았다.

이 실행은 ChatGPT 로그인 기반 app-server와 `gpt-6-sol` / `medium`을 사용했다. 저장된 Agent 산출물에는 Token Usage가 없었다. 재시도 가능한 app-server `error` Notification(`willRetry=true`)은 같은 Turn의 진행 상태로 처리하고, 종료 오류는 실패로 둔다. HTTP 503 재접속 메시지로 중단된 함수 Run 두 개는 Provider 수정 뒤 재실행했으며, 원래 인프라 오류는 `experiment_error.json`에 남아 있다.

5함수 Scheduler 사후 분석은 예산 확장 Run의 `scheduler_diagnosis.json`에 따로 저장했다. 첫 다섯 선택에서 선택된 함수와 알려진 함수는 모두 같은 점수였다: CORE +45, 측정된 함수 도달 +20, 동일한 대기시간 가산 +0~+4. 더 높은 점수를 받은 선택 함수는 없었고 안정적인 Function ID Tie-break가 순서를 결정했다. `Scheduler.select`에 Source Text가 전달되지 않아 Source Memory Operation 가산은 비활성이었고, Call Depth와 정적 Reachability도 없었으며, `risk_level`은 `score`에서 사용되지 않았다. 다섯 번째에는 기다리는 RELATED 함수가 없고 CORE들의 나이도 같아 Aging 자리도 Tie를 바꾸지 못했다. 직접적인 원인은 5함수 Cutoff였지만, 동일한 CORE들의 순서가 ID에 좌우된 이유는 단순한 공식과 누락된 입력이었다.

동일 가중치로 Pool 상태를 15순위까지 연장한 결과는 `result/vulnerabilityanalysis/20261007T142604Z-305db618/budget_extension_summary.json`이다. 앞선 다섯 함수 결과를 이어받아 6~15순위를 `gpt-6-sol` / `medium`으로 분석했다. 전체 15함수에서 SP 82개, 완료 LLM 호출 115회, PoC Record 20개, 실제 Candidate Runtime 19회, ASAN Finding 0건, `VERIFIED` 0건이었다. 추가 열 함수의 첫 실행은 1,331.5초, 중단된 네 함수 재시도는 672.6초였다. 중단된 Provider 호출은 완료 호출 수에서 빠졌고 정확한 총 발행 호출 수와 Token 수는 알 수 없다. 이 시간에는 인프라 복구가 포함되어 모델 비용 측정치는 아니다.

13순위 `remove_connection_headers`에서 `sp-372959689cb39706`이 생성됐다. 가설은 Map 제거가 Value Buffer를 무효화해 이후 `strlen(ptr)` 읽기에 영향을 줄 수 있다는 것이다. 이는 정답을 Prompt에 준 결과가 아니라 Blind Source Analysis의 결과다. 저장된 Candidate Scheduler 기록에서 이 SP는 동일 점수 후보 4개 중 4순위였고 두 자리 Deep Verification 예산 밖에 있었다. 따라서 `OPEN`으로 남아 PoC나 Runtime 검증을 받지 않았다. 별도 생성 입력은 LLVM Coverage상 해당 함수를 실행했지만 정확한 SP 위치·조건 도달은 아직 `UNKNOWN`이다. 함수 예산 확장으로 후보 발견까지는 개선됐고 Candidate 선택은 여전히 병목이다. 추가 함수별 Coverage는 `function_runs/<rank>_<function>/runtime/poc_coverage_summary.json`에 있다.

Scheduler/Model 비교는 별도 Run ID에서 진행 중이며 Baseline을 대체하지 않는다. 수정된 Function 점수는 Source에서 확인한 동작을 사용하고, 수정된 SP Scheduler는 두 Candidate 예산에서도 탐색 자리를 확보한다. 수정 Scheduler의 GPT-6 Sol Run에서 첫 완료 함수는 Lifetime 관련 SP를 만들었고 생성 입력이 Target Code에서 ASAN Heap-Use-After-Free를 일으켰다. 하지만 SP가 나중의 `strlen` 사용을 설명한 반면 실제 Invalid Access는 Map Removal 안에서 발생해 Root Cause 검증은 `UNKNOWN/REANALYZE`에 머물렀다. 이는 실제 Target Crash이지만 해당 가설과 일치한다고 검증된 취약점은 아니다. 이후 함수 아홉 개를 완료한 시점에 app-server 응답 Timeout이 발생했으며, 15함수 비교나 역할별 모델 비교를 주장하려면 미완료 Run을 이어야 한다. 별도 예비 Run은 종전 두 Candidate 예산에서 다섯 번째 SP Aging 자리가 활성화될 수 없음을 발견해 중단했다. 두 Run 모두 보존된 Baseline에 포함하지 않는다.

## 데이터와 상태 규칙

| 산출물 | 저장하는 내용 |
| --- | --- |
| `FunctionAnalysis` | 함수 하나의 입력·상태·검사·Memory 관찰, 제한된 Context 요청, Safe Assumption, Unknown |
| `SuspiciousPoint` | 위치, 동작, 반증 가능한 Trigger, 입력 관계, 필요 상태, 지지·반대 근거 |
| `VerificationResult` | Reachability, Controllability, Guard, 상태, Evidence, Unknown, Verdict, 다음 행동 |
| `PoC` | Python `build()` 스크립트, 생성된 로컬 입력, 명령, 예상·실제 동작 |
| `RuntimeResult` | 종료 코드, Signal, stdout/stderr, Sanitizer, Stack, 실행 시간, 선택적 Reachability/Coverage |
| `Evidence` | 유형, Source·Artifact 경로, 지지·반박 여부, Run ID, Timestamp |
| `Assertion` | FunctionAnalysis 출처, Safe Judgment·이유, 소스 라인·식, 생성 방식, 실행별 상태 |

자연어 반박만으로 `REFUTED`가 될 수 없고, 입력 생성 실패도 SP를 반증하지 않는다. GDB 함수 Hit는 `FUNCTION_REACHED`만 증명하며, 위치·조건 도달은 별도 관찰이 없으면 `UNKNOWN`이다. Source Artifact에 적힌 Sanitizer와 실제 Runtime에 지정한 Sanitizer Profile은 별도 필드다. 정적 가설을 Runtime 증거로 취급하지 않는다.

실패는 입력 생성 오류, Runtime 명령 부재, 환경·하네스 시작 오류, 근거가 있는 Target/SP 미도달, Sanitizer Crash, Crash 없는 경로 도달로 나누고, 확인되지 않은 정보는 `UNKNOWN`으로 둔다. Retry 예산과 Scheduler 가중치는 `config/default.yaml`에 있다. `RetryLedger`는 후보·전략·Evidence 집합이 같은 반복을 막고 횟수를 제한한다. Executor 호환성 문제 수정 뒤에는 이미 생성된 스크립트를 LLM 재호출 없이 재개해 기존 시도를 갱신할 수 있다. Targeted Fuzzing은 명시적으로 켜야 하며 기본 Scan에서는 실행하지 않는다.

## 요구 사항과 실행

프로젝트 루트에서 `pyproject.toml`의 Python 의존성을 설치하거나 `PyYAML`과 `jsonschema`가 있는 환경을 사용한다. 기본 실행에는 로그인된 Codex CLI가 필요하다. Ollama Cloud를 명시적으로 선택할 때만 `OLLAMA_API_KEY` 또는 개인 키 파일이 필요하다. Runtime 실험에는 해당 로컬 Target, 빌드된 Binary, 요청한 Sanitizer/디버그 도구가 필요하다.

이미 `OLLAMA_API_KEY`가 설정된 본인 터미널에서 다음 명령으로 개인 키 파일을 만들 수 있다. 키 값을 화면에 출력하거나 저장소에 넣지 않는다.

```zsh
if [[ -n "$OLLAMA_API_KEY" ]]; then
  install -d -m 700 ~/.config/vulnerabilityanalysis
  (umask 077; printf '%s' "$OLLAMA_API_KEY" > ~/.config/vulnerabilityanalysis/ollama_api_key)
  chmod 600 ~/.config/vulnerabilityanalysis/ollama_api_key
fi
```

```bash
PYTHONPATH=vulnerabilityanalysis/src python3 -m vulnerabilityanalysis phase1 \
  reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer \
  --target-repository /path/to/authorized/libyaml

PYTHONPATH=vulnerabilityanalysis/src python3 -m vulnerabilityanalysis scan \
  result/vulnerabilityanalysis/<run_id> \
  --target-repository /path/to/authorized/libyaml \
  --binary /path/to/local/libfuzzer-binary --trace-reachability \
  --runtime-sanitizer ASAN --runtime-sanitizer UBSAN

# 선택 사항: 보존한 후보 Seed를 로컬 libFuzzer Binary로 Mutation한다.
# 선택된 후보마다 budget.max_fuzz_time이 실행 시간을 제한한다.
PYTHONPATH=vulnerabilityanalysis/src python3 -m vulnerabilityanalysis scan \
  result/vulnerabilityanalysis/<run_id> \
  --target-repository /path/to/authorized/libyaml \
  --binary /path/to/local/libfuzzer-binary \
  --targeted-fuzzer-binary /path/to/local/libfuzzer-binary \
  --targeted-fuzz-seconds 5

PYTHONPATH=vulnerabilityanalysis/src python3 -m unittest discover \
  -s vulnerabilityanalysis/tests -v

# 선택 사항: 기본 Codex app-server Provider를 명시
PYTHONPATH=vulnerabilityanalysis/src python3 -m vulnerabilityanalysis scan \
  result/vulnerabilityanalysis/<run_id> \
  --target-repository /path/to/authorized/libyaml \
  --binary /path/to/local/libfuzzer-binary --provider codex

# 선택 사항: 실제 Codex app-server 연결 테스트
VA_LIVE_CODEX=1 PYTHONPATH=vulnerabilityanalysis/src python3 -m unittest discover \
  -s vulnerabilityanalysis/tests -p test_provider.py -v
```

Assertion Build에는 Target에 맞는 Compiler 인자가 필요하다. `scan.run_assertions_for_scan`에 `{source}`와 `{binary}`가 들어 있는 Build Command 인자 배열, `{binary}`와 `{input}`가 들어 있는 Run Command 인자 배열을 전달한다. 별도 Output Directory에서 선택한 Translation Unit만 교체한다. 원본 Repository는 수정하지 않는다.
전체 Scan CLI에서는 같은 명령을 JSON argv 배열로 `--assertion-build-command`, `--assertion-run-command`에 전달하고, 검증된 입력이 있으면 `--assertion-seed`로 지정할 수 있다. 입력을 생략하면 해당 Scan에서 생성된 첫 PoC 입력을 사용한다. 이 세 조건 중 필요한 것이 빠진 제안은 실행 완료로 기록하지 않는다.
Guided Fuzzing은 libFuzzer용 `--assertion-run-command '["{binary}","{input}"]'`와 `--assertion-fuzz-seconds N`을 함께 지정할 때만 실행한다. 시간은 기존 `budget.max_fuzz_time`을 넘지 않는다. 위반이 있으면 원본 프로그램 비교 및 Triage를 끝내도 `VERIFIED`로 자동 승격하지 않는다.

### OFF/ON 평가 설정

`scan --hallucination-prevent off`는 Function Analyzer를 호출하지 않고 SP Generator/Verifier/PoV 경로를 실행한다. `on`은 SP 경로를 먼저 실행한 뒤 Function Analyzer와 Safe Assumption → Assertion 생성·빌드·실행·Fuzzing·Triage·Refinement·SP Feedback 경로를 허용한다. Assertion 빌드·실행 명령, 초기 입력, 양의 `--assertion-fuzz-seconds`가 없으면 `on`은 시작 전에 오류로 중단한다. 유효한 Safe Assumption 또는 Assertion이 없으면 해당 경로는 `NOT_SCHEDULED`로 기록된다. 기본 `auto`도 SP 경로 이후 HP를 실행한다.

`experiment_setup.json`의 `baseline_kind=FBV2_SP_INDEPENDENT_HP_OFF`는 Function Analyzer를 생략한 SP 경로 비교군을 뜻한다. 이는 FuzzingBrain V2의 원본 구현 전체와 동일하다는 뜻은 아니다. `--max-candidates 1`은 기존 SP Scheduler에서 깊게 검증할 후보 수만 제한한다. 후보는 삭제하거나 안전 판정하지 않고 기존 OPEN/보류 규칙을 따른다. OFF/ON 비교에는 동일한 `--max-candidates`, Seed, 모델 설정, 함수·LLM·시간 예산을 지정한다.

`--initial-seed <파일>`을 반복하거나 `--initial-corpus <디렉터리>`를 지정하면 각 입력을 **Scan 시작 시** 해시 중복 제거 후 `corpus/global/`에 복사하고, 같은 Runtime Command로 기초 실행한 결과를 `runtime/initial_corpus/`에 저장한다. 선택된 SP의 Mutation Corpus에도 같은 초기 입력을 전달한다. 초기 입력의 실행만으로 함수·SP 조건 도달은 인정하지 않는다. Assertion 경로는 복사된 초기 입력을 우선 사용한다. 같은 Campaign에서 `--continue-from` 또는 `--retry-incomplete-from`으로 이어지는 함수 Run은 Worker Corpus를 자동으로 가져온다. 최초 입력 경로를 다시 지정하지 않아도 Corpus는 이월되지만, 독립 비교 실험의 시작 입력은 동일하게 고정해야 한다.

`--max-scan-seconds N`은 한 CLI Scan의 전체 함수 순회에 적용된다. 시간 초과 시 `scan_timeout.json`과 `function_scan.json`에 미완료 상태를 기록하고, 실행 중이던 LLM 호출의 취소는 `logs/agent_requests.jsonl`에서 구분한다. 완료된 Scan의 `timing.json`에는 함수 분석·SP 생성·Verifier·PoV·Runtime·Global/SP Fuzzing·Assertion 빌드/Guided Fuzzing 시간과 역할별 LLM 요청 시간·횟수를 분리한다. Codex app-server에서 제공받지 못한 Token/요금은 `UNKNOWN`으로 남긴다. 동기 Subprocess는 자체 Timeout 내에서 종료되므로 전체 제한 시각을 소폭 넘길 수 있으며, 이 편차는 실제 경과 시간에 기록한다. 두 Run의 `experiment_setup.json`은 입력·Config 해시와 예산을 보존한다.

## 산출물

결과는 `result/vulnerabilityanalysis/<run_id>/`에 저장한다. Phase 1 JSON과 `analysis/`, `context.json`, `sp/`, `verification/`, `poc/`, `runtime/`, `root_cause/`, `fixed_poc/`, `independent/`, `security/`, `assertions/`, `corpus/candidate/`, `evidence.json`, `experiments.json`, `scan.json`을 사용한다. 해당 단계의 결과가 있을 때만 만들어지는 디렉터리도 있다.

실험의 실제 판단과 한계를 읽을 때에는 요약 숫자뿐 아니라 후보별 JSON, Runtime Log, Coverage, Sanitizer Stack, Assertion Provenance를 함께 확인해야 한다. `VERIFIED` 수는 모든 최종 Gate를 통과한 결과만 센다.

## Reference와 설계 근거

`reference/FuzzingBrainV2`는 수정하지 않는 Upstream Reference다. 참고한 동작은 `vulnerabilityanalysis/`에 맞게 구현하며 Reference 디렉터리를 프로젝트 구현 공간으로 사용하지 않는다.

최종 검증 Gate를 위해 실제로 확인한 파일은 `reference/FuzzingBrainV2/FuzzingBrain-V2/fuzzingbrain/tools/pov.py`의 `_verify_pov_core`·`trace_pov_impl`, `.../agents/pov_report_agent.py`, `.../fuzzer/manager.py`, `.../fuzzer/models.py`, `.../tools/coverage.py`다. **DESIGN_NOTE:** Upstream의 `_verify_pov_core`는 저장한 입력을 Sanitizer Target에서 재실행한다. 이 프로젝트의 `VERIFIED`는 현재 Workflow에 따라 SP/Root Cause 연결과 외부 입력·하네스·Security Property Evidence를 추가로 요구한다.

| 출처 | 분류 | 적용 범위 |
| --- | --- | --- |
| `reference/FuzzingBrainV2/FuzzingBrain-V2/fuzzingbrain/core/models/{worker,direction}.py` | ADAPT | Worker × Sanitizer, 기능별 Direction 개념 |
| `.../worker/strategies/pov_fullscan.py::_run_direction_planning`, `.../tools/directions.py::create_direction_impl` | ADAPT | 여러 기능별 Entry/Core Direction. DB·Tool 호출은 복사하지 않고 저장된 Feature와 Call Graph를 사용 |
| `.../worker/strategies/pov_fullscan.py::_find_reachable_from_entries`, `_build_direction_pools` | REIMPLEMENT | Entry 기준 정적 그래프 탐색과 관련 함수 Pool. 실제 실행 Hit와 구분 |
| `.../worker/pipeline.py::_run_verify_agent`, `.../db/repository.py::claim_for_verify` | ADAPT | 예산 밖 후보를 지우지 않고 보류 ID·상태를 저장. Upstream의 자동 영속 큐 Claim은 아직 없음 |
| `.../agents/sp_generators.py`, `.../agents/sp_verifier.py` | ADAPT | 넓은 후보 생성과 분리된 반증 중심 검증 |
| `.../agents/pov_agent.py`, `.../agents/pov_report_agent.py`, `.../tools/pov.py`, `.../fuzzer/seed_tools.py` | ADAPT / REIMPLEMENT | Python Seed와 저장 입력의 재실행. 프로젝트 Root Cause/Security Gate 추가 |
| `.../tools/pov.py::_execute_generator_code`, `_verify_pov_core`, `.../fuzzer/manager.py` | ADAPT | Python Seed 생성·Runtime 확인·유용한 Seed의 후보/전역 Corpus 전달. Global·후보 Corpus 모두 설정된 시간 예산 안에서 Mutation |
| `.../tools/coverage.py` | ADAPT | Breakpoint 설정과 실제 Hit를 구분한 GDB Output Parsing |
| `reference/CodeAugur/CodeAugur.pdf` | 논문 개념 | Tagged Safe Assumption → Runtime 검사 → 위반된 판단 재검토. 해당 디렉터리에는 구현 코드가 아닌 논문이 있음 |
| `reference/QuartetFuzz/QuartetFuzz/` | ADAPT | 과거 성공 Harness 산출물, Harness/Target 오류 구분 |
| `reference/WINNIE/WINNIE.pdf` | 개념 참고 | Harness Entry와 정상 실행 흐름의 의미 |

로컬 발표 자료 `/mnt/c/Users/dawne/Downloads/슬라이드 (5).pptx`의 35~40쪽과 `/mnt/c/Users/dawne/Downloads/중간발표 (15).pptx`의 Workflow/Prototype 부분을 확인했다. 두 자료는 우선순위 Scheduling, 독립 Safe Assumption 경로, Runtime Evidence, Python Seed 생성을 설계 근거로 제시한다. **DESIGN_NOTE:** 발표 자료는 의도된 Workflow를 보여 주지만, 현재 HarnessCreator는 하나의 완전한 Vulnerability Analysis 입력 대신 Manifest와 Validation JSON 등을 저장한다. Adapter는 없는 필드를 `UNKNOWN`으로 남기며 실제 Repository Interface를 과거 그림보다 우선한다.

## libyaml 전체 재실행: SP·Runtime Evidence 점검

`20261008T142433Z-622973b7` Run은 기존 QuartetFuzz libyaml Scanner Harness와 변경 없는 libyaml Checkout을 사용해 Phase 1부터 함수 분석·Context 확장·SP 생성·검증·Python 입력·Runtime까지 다시 실행했다. 실제 Provider는 Ollama Cloud다. 함수 분석과 SP 생성은 `glm-5.3-flash/high`, SP 검증은 `glm-5.3/low`, Assertion·PoC 생성은 `glm-5.3/max`였고 완료된 LLM 호출은 8회다. 이전 FunctionAnalysis나 SP를 입력으로 재사용하지 않았다. 앞선 별도 시도들은 Ollama Cloud의 스키마 밖 필드·잘못된 JSON 때문에 중단됐으며 각 `experiment_error.json`에 남겼다. 전체 새 시도 8회에서 **논리 LLM 호출**은 24회 시작·16회 완료·8회 오류였다. HTTP `/show`·`/chat`별 실제 전송 횟수는 별도로 기록되지 않았다.

새 SP는 6개이고 모두 실제 `src/scanner.c`의 분석 함수 내부 행과 일치했다. 예산상 2개만 검증했다. `sp-f980fa19aba782c1`은 `UNKNOWN/REQUEST_CONTEXT`, `sp-90a62ec73442128d`는 `UNKNOWN/RUNTIME_TRACE`로 남았고, 나머지 4개도 `OPEN`이다. `REQUEST_CONTEXT`는 함수 분석에서 이미 Context 확장 예산 2회를 써서 실제 추가 조회로 이어지지 않았다. `sp-90a62ec73442128d`의 PoC는 13바이트를 생성해 Exit 0, ASAN/UBSAN 오류 없음이었다. 이는 이 입력의 결과일 뿐 안전성 증명이 아니다. Assertion 5개는 제안됐지만 이 Run에서 삽입·실행하지 않았다. `VERIFIED`는 0건이다.

최적화 바이너리에서 함수 진입은 확인됐지만 773행 Hit은 확인되지 않았다. 별도 Source Copy의 `-g -O0` 빌드는 GDB에서 773행 Hit과 `parser->tokens.head == parser->tokens.tail == false`를 확인했다. 최초 Scan은 원본 Source 경로와 Build Copy의 DWARF 경로가 달라 위치·조건을 `UNKNOWN`으로 기록했다. 동일한 소스 해시를 확인하고 Build Copy의 실제 경로를 사용한 추가 GDB 점검, 이어 `-fdebug-prefix-map`으로 원본 경로를 담은 독립 디버그 빌드의 기존 `execute_poc` 재실행에서 위치 `true`·조건 `false`를 측정했다. 각각의 로그와 Source 검증표는 Run의 `runtime/`, 판단 요약은 `e2e_evidence_audit.json`에 있다. 한 입력에서 조건이 false인 사실은 SP 전체의 반증으로 기록하지 않는다.

후속 회귀 실행 `result/vulnerabilityanalysis/evidence-replay-20261008T144522Z/`는 저장된 13바이트 입력과 SP를 사용했고 기존 Run을 덮어쓰지 않았다. Runtime은 GDB의 DWARF 원본 목록에서 동일한 SHA-256의 유일한 소스를 찾아 경로를 연결하며, 실제 Breakpoint Hit가 없으면 위치·조건을 `UNKNOWN`으로 남긴다. 디버그 빌드는 함수/773행 도달 `true`, 해당 순간의 빈 큐 조건 `false`; 최적화 빌드는 함수 도달 `true`, 위치·조건 `UNKNOWN`이었다. Verifier는 연속된 원문 인용의 파일·행을 확인하고 생략 부호가 섞인 인용을 반증 근거로 인정하지 않는다. 자연어 Supporting/Contradicting Evidence는 인용한 파일·행의 존재를 별도로 기록하되, 그 문장의 의미까지 자동 증명했다고 취급하지 않는다. Context 요청은 실제 조회, 기존 Context 재사용, 예산 소진을 구분해 저장한다. 이 회귀에서 두 Context 요청은 예산 소진으로 수행되지 않았고 SP 판정은 `UNKNOWN`으로 유지됐다. 8개 오류는 응답 Schema 위반 5건, JSON 형식 오류 3건으로 분류됐으며 로그에서 네트워크·서버·Timeout 오류는 확인되지 않았다.

## 현재 경계와 남은 작업

- 저장된 성공 HarnessCreator 산출물이 아직 없다. 생성되면 실제 Harness Generator → Vulnerability Analysis 통합 검증을 추가해야 한다.
- QuartetFuzz의 과거 Source/Binary 경로와 현재 Libyaml Checkout이 다르다. 현재 Runtime 결과는 로컬 Checkout에만 적용된다.
- Libyaml 검증에서 GDB는 원본 `-O1` Binary의 `yaml_parser_scan`과 `memset` 라인에 Hit했지만, 원본 `DEQUEUE` 773행 Breakpoint는 멈추지 않았다. 별도 Source Copy의 773행 직전 Assertion은 입력 두 개에서 도달하고 유지됐다. 이는 계측 위치 도달과 해당 두 실행에서 Queue-empty 조건이 없었음을 보일 뿐이다. `memset`의 Owned-token 상태는 `UNKNOWN`이다. 결과: `result/vulnerabilityanalysis/20261007T120848Z-f6cf98e6/runtime/reachability_evidence.json`.
- 실제 `yaml_parser_scan` FunctionAnalysis는 `src/scanner.c:773`의 LLM Assertion 두 개를 만들었다. 둘 다 Source Copy Syntax/Build 검사에 통과했고 로컬 입력 한 개에서 도달·유지됐다. 이전의 774행 제안은 너무 늦은 삽입이라 거부했다. 이는 Assertion 경로 통합 결과이지 취약점 판정이 아니다. Static Fallback Assertion은 별도로 실행하고 출처를 분리했다.
- 보존된 Clean Tinyproxy Baseline은 프로젝트 HarnessCreator 산출물이 아닌 Process-level Regression Fixture를 사용했다. 실제 ASAN Target에서 함수 분석과 Candidate Runtime까지 실행했지만 Crash나 `VERIFIED`는 없었다. 별도 미완료 Scheduler 실험에는 Target ASAN Crash가 있으나 Root Cause 관계가 아직 해결되지 않았다. Clean Tag에 없는 `tinyproxy_fuzz_http_request`를 호출하는 기존 임시 Fuzz Harness는 사용하지 않았다.
- 현재 PoC 입력 방식은 Binary를 지정한 경우 로컬 단일 파일 libFuzzer 인자다. 다른 하네스 Transport에는 명시적인 Runner가 필요하며 이름만 보고 추정하지 않는다.
- 아직 실제 Target이 최종 `VERIFIED` Gate를 통과한 사례는 없다. 컴파일한 로컬 ASAN Test Fixture가 Target Crash → Root Cause → Fixed Input → 새 프로세스 Replay를 시험했지만, 외부 입력·하네스 타당성 Evidence가 없어 `SECURITY_CHECK`에 머문다. 이는 Gate Test이며 발견한 취약점이 아니다. Libyaml Slice도 Target Crash 없이 `VERIFIED` 0건이다.
- Source 근거가 있는 `DATAFLOW_RELATED`를 무인 Scan에서 쓰려면 별도 Producer/Validator가 필요하다. 일반 함수 Trace만으로는 부족하다.
- Side Effect 없는 단순 식과 확인된 `DEQUEUE` 규칙을 넘는 Safe Assumption 계측은 아직 제한적이다. 컴파일 실패는 취약점이 아니라 유효하지 않은 Assertion의 Evidence로 남아야 한다.
- Runtime Evidence가 구체적인 미해결 상태 질문을 보여 줄 때만 Targeted Fuzz Scheduling이나 GDB 변수 수집을 확장할 예정이다.
