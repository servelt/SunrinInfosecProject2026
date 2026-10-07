# HarnessCreator

HarnessCreator는 “하네스가 이미 있다”는 가정 없이 C/C++ 코드에서 외부 입력 경계를 찾고, 실제 상태 수명주기를 복원해 fuzz harness를 생성·검증하는 실행 가능한 MVP다. LLM 연결은 API 키가 아니라 로컬 `codex app-server`의 v2 JSONL 프로토콜을 사용한다.

구현된 흐름은 다음과 같다.

1. 설치된 Fuzz Introspector의 build-free C/C++ frontend를 자동 실행해 프로젝트 전체 함수·caller·callee report를 만들고, bootstrap source indexer로 source·build target·공개 header/declaration을 보완한다. 같은 source digest의 report는 재사용하며 FI 실행 또는 coverage 검증 실패 시 기본적으로 중단한다.
2. Entry Generator가 제품 함수만 크기 제한 batch로 읽으며 외부 데이터의 **최초 유입점** 후보를 만든다. 긴 함수는 line-aware excerpt로 전 구간을 검사하고, 알려진 source API는 결정론적 규칙으로도 보존한다. 이미 획득한 값을 처리하는 parser/getter/dispatcher와 프로그램 내부 input wrapper의 caller는 후보로 만들지 않는다. `accept`, socket 생성 및 readiness event처럼 데이터가 아닌 연결·제어 상태만 만드는 지점도 후보에서 제외한다.
3. Entry Verifier는 Candidate 함수 source 하나에서 시작한다. 인접 caller/callee는 우선 ID·이름·관계만 보여 주고, 모델이 명시적으로 요청한 함수 source만 라운드당 최대 3개씩 누적한다. 이 선택적 context로 외부 데이터 provenance와 `first_acquisition_confirmed`를 함께 검증한 뒤 `VERIFIED / REJECTED / UNRESOLVED`와 evidence 및 이미 검사한 함수 ID를 남긴다.
4. Small Feature Agent는 `VERIFIED`와 `UNRESOLVED`를 함께 받는다. `UNRESOLVED`는 앞 단계에서 검사하지 않은 frontier부터 탐색을 이어가며 기능 복원과 Entry 재판정을 동시에 수행한다. 의존성에서 발견한 다른 `UNRESOLVED`도 외부 데이터 최초 유입점으로 확인되면 `VERIFIED`로 승격해 같은 기능에 포함할 수 있다. `REJECTED`이거나 Small Feature 마지막 round까지 미확정이면 DROP한다. 확정된 Entry만 사용해 초기화, 선행 상태, 함수 action 순서, Entry 호출 순서, 결과 처리, cleanup과 harness anchor를 복원한다.
5. Large Feature Agent가 첫 Entry가 같은 후보 안에서 의미상 동일한 선행 상태를 강한 모델로 묶고, anchor·transport·isolation·build target 충돌을 분리한다. OSS-Fuzz 실행에서는 Common Anchor 자체에 FI build-target 근거가 없는 별도 utility/example과 현재 in-process libFuzzer가 보존할 수 없는 필수 fork/subprocess 기능을 의미 Feature로만 남기고 하네스 생성 대상에서는 차단한다. 이어 전체 Large Feature의 입력 주체와 정상 기능 권한을 비교해 저권한 주체의 하네스부터 우선 처리하고, 모든 다른 주체의 기능을 포함하면서 공격자가 차지하기 어려운 주체의 하네스는 생성 대상에서 제외한다.
6. Harness Generator가 실제 API 호출 코드와 manifest를 만들고 16개 체크리스트를 자체 점검한다. OSS-Fuzz 경로에서는 verifier와 같은 pinned revision의 canonical harness, `build.sh`, Dockerfile, target options를 생성 전부터 읽어 target별 헤더·초기화·링크 방식을 추측하지 않는다. 다만 이는 integration 참고 근거이며, 현재 checkout에서 실제로 연 함수와 Feature가 허용하지 않은 다른 기능을 복사할 수 없다.
7. 독립 Static Gate가 같은 16개 계약을 다시 검사한다.
8. 기본 `auto` 검증은 QuartetFuzz의 실제 `DynamicRunner`를 사용한다. LLM 호출 전 pinned canonical harness를 로컬 checkout overlay와 실제 recipe로 기준선 빌드하고 빈 입력으로 실제 실행하여 프로젝트·Docker·링크·runtime 호환성을 먼저 확정한다. 생성 단계에서는 사용자가 지정한 로컬 checkout을 OSS-Fuzz builder의 application source 위치에 먼저 덮어쓰고, 그 위에 생성 source를 canonical fuzzer 위치에 교체한다. 따라서 Dockerfile이 임의 시점의 원격 source를 다시 clone하더라도 검증 대상은 현재 로컬 checkout이다. 검증 전용 project image에 GDB가 없으면 build context에서 설치한 뒤, 실제 project object와 link하여 adversarial replay → in-container GDB anchor/variant reach → fresh-corpus fuzzing → coverage sanitizer rebuild → llvm-cov 순서로 검증한다. Target의 canonical `.options`에 명시된 leak policy를 replay와 campaign에 동일하게 적용하고, campaign crash artifact를 host에 보존해 GDB로 귀속한다. 고정 빈 입력 실행이 `cov:`를 출력하면 그 값을, 출력하지 않으면 fresh campaign의 첫 `cov:`를 기준점으로 삼아 종료 `cov:` 증가를 요구한다. 동시에 생성 하네스를 제외한 application source 경로의 함수·라인 llvm-cov가 0보다 커야 qualified다. `--no-dynamic-verification`도 기준선 및 생성 하네스의 실제 OSS-Fuzz build를 생략하지 않는다. OSS-Fuzz integration이 없는 프로젝트만 명시적으로 `--verification-backend command`와 trusted build/binary pair를 사용한다.

## 요구 사항

- Python 3.10 이상
- 로그인된 Codex CLI (`codex login`)
- 기본 OSS-Fuzz 검증 시 Docker 접근 권한과 체크아웃된 `../QuartetFuzz/QuartetFuzz` reference implementation. HarnessCreator는 LLM 분석 전에 QuartetFuzz import, Docker daemon, canonical Dockerfile/build.sh/harness source를 모두 검사하고 QuartetFuzz가 고정한 OSS-Fuzz revision을 준비한다. 이후 같은 checkout에서 격리 worker workspace를 만든다. `--oss-fuzz-dir`로 기존 checkout을 지정할 수 있다.
- command backend 동적 검증 시 대상 프로젝트의 compiler, ASan·UBSan, libFuzzer 및 GDB와 source line breakpoint를 위한 debug symbols(`-g`). Binary에 sanitizer instrumentation 표식이 없으면 replay 전에 실패한다.
- 고정된 공식 Fuzz Introspector commit의 C/C++ tree-sitter frontend. `python -m pip install -e .`가 함께 설치한다. PyPI 0.1.10 배포본의 분석에 불필요한 Atheris/clang 의존성을 피하기 위해 공식 저장소의 `src` package를 commit 단위로 고정한다.

OpenAI API 키는 사용하지 않는다. 모델은 읽기 전용 Codex thread에서 분석만 수행한다. 기본 build·debug·fuzz·coverage 실행은 QuartetFuzz의 격리된 OSS-Fuzz runner가, command 호환 경로는 HarnessCreator의 no-shell runner가 소유한다.

## 설치와 확인

```bash
cd /mnt/c/harness/harnesscreator
python -m pip install -e .
harnesscreator doctor --source /path/to/project
harnesscreator doctor --source /path/to/project --turn  # structured-output turn까지 확인
harnesscreator analyze /path/to/project
```

HarnessCreator는 하네스가 생기기 전 단계에서 FI 0.1.10의 build-free C/C++ frontend를 자동 실행한다. 프로젝트 source만 선별해 `fuzzerLogFile-harnesscreator.data.yaml`을 만들며, `runs`, `runs-*`, build/output 및 현재 `--output`은 분석에서 제외한다. 전통적인 LLVM/LTO frontend처럼 기존 fuzz harness나 프로젝트별 build recipe를 요구하지 않는다. 결과는 `--output/.fuzz-introspector/<source-digest>/`에 cache된다. `--fuzz-introspector`는 자동 실행을 대신해 사용자가 준비한 LLVM/LTO 또는 다른 FI report를 명시할 때만 사용한다.

Report 파일이 존재하는지만 확인하지 않는다. FI의 file/function record가 bootstrap source 함수 중 차지하는 비율을 계산하며, 기본 strict 실행은 80% 미만의 부분 report를 거부한다. 여러 target/report가 필요한 프로젝트는 개별 파일 대신 report들을 포함한 output directory를 지정한다. 실제 비율과 threshold는 `analysis/completeness.json`에, provider·권위성·FI 사용 여부는 `summary.json`에 남는다.

FI가 container/build 환경의 다른 절대경로를 기록했더라도 현재 checkout 안의 고유한 최장 path suffix로 source file을 재매핑한다. `run`의 `--output`이 source tree 내부에 있으면 그 디렉터리는 이름과 무관하게 source/build metadata 탐색에서 제외하므로 이전 생성 하네스가 다음 분석에 다시 섞이지 않는다. Source root 자체를 output으로 지정하는 것은 거부한다.

## 실행

Memcached를 기본 논문 호환 backend로 처음부터 끝까지 실행한다. `fuzzer_proxy.c`와 `fuzzer_proxy`는 공식 OSS-Fuzz recipe에 맞춰 자동 선택된다.

```bash
harnesscreator run /mnt/c/memcached \
  --output /mnt/c/memcached/runs-paper \
  --workers 4 \
  --worker-recycle-turns 16 \
  --agent-debug \
  --fuzz-seconds 300
```

Runtime replay/GDB/fuzzing/llvm-cov는 생략하되 실제 OSS-Fuzz build까지만 수행:

```bash
harnesscreator run /mnt/c/memcached \
  --output /mnt/c/memcached/runs-build-only \
  --no-dynamic-verification
```

OSS-Fuzz target을 자동으로 고를 수 없는 프로젝트는 canonical target을 명시한다.

```bash
harnesscreator run /mnt/c/memcached \
  --oss-fuzz-project PROJECT \
  --oss-fuzz-fuzzer FUZZER_BINARY_STEM \
  --harness-source-filename CANONICAL_SOURCE.c \
  --oss-fuzz-source-path /src/PROJECT_CHECKOUT \
  --fuzz-seconds 300
```

OSS-Fuzz integration이 없는 프로젝트에만 command backend를 사용한다. 이 경로는 실제 project object/library를 link해야 하며 논문 benchmark와 동일한 llvm-cov 환경이라고 간주하지 않는다.

```bash
harnesscreator run /path/to/project \
  --verification-backend command \
  --output ./runs \
  --build-command 'PROJECT-SPECIFIC BUILD COMMAND USING {harness} AND {output}' \
  --binary '{output}/fuzz_target' \
  --fuzz-seconds 300
```

빌드 명령과 binary 경로에는 `{harness}`, `{source_root}`, `{output}` placeholder를 쓸 수 있다. 이 문자열은 shell 명령으로 평가되지 않고 argv로 분리되어 실행된다. 모델 출력의 명령은 절대 실행하지 않는다.

일반 C/C++ 프로젝트에서 `{harness}`만 컴파일하면 실제 애플리케이션 심볼이 link되지 않으므로 그런 명령은 허용 가능한 project build 예시가 아니다. Memcached는 command를 수작업으로 만들지 않고 기본 OSS-Fuzz recipe를 사용한다.

FI 자동 실행 자체가 실패해도 regex 기반 bootstrap 결과로 계속할 필요가 있을 때만 불완전성을 명시적으로 수락한다. 이 옵션도 먼저 FI 자동 실행을 시도한다.

```bash
harnesscreator run /path/to/project \
  --allow-source-analysis \
  --no-dynamic-verification
```

FI가 성공하면 이 옵션을 사용했어도 FI report가 그대로 사용된다. FI가 실패해 fallback한 경우에만 `analysis/completeness.json`에 `authoritative: false`와 경고를 기록한다. 전처리기 매크로는 함수 정의에서 제외하고 Makefile.am, CMake, `compile_commands.json`, header declaration을 수집한다. 주소가 전달된 함수와 callback 등록은 낮은 confidence의 `function_reference` edge로 보강하지만 FI call graph로 간주하지 않는다. `auto` backend는 build command가 주어지면 command를, 없으면 OSS-Fuzz를 선택한다. command backend만 `--build-command`와 `--binary`를 모두 요구한다.

Small Feature는 Entry와 1:1이 아니다. 각 `VERIFIED` 또는 `UNRESOLVED` Entry를 독립적인 context seed로 사용해 0개 이상의 operation을 찾고, 하나의 Entry가 여러 기능에 참여하거나 여러 Entry가 하나의 기능을 구성할 수 있다. `UNRESOLVED` seed는 Entry Verifier가 열었던 source를 유지하되 이미 검사한 함수는 새 이동으로 세지 않고 아직 열지 않은 caller/callee frontier부터 이어 간다. 다른 seed의 의존성을 탐색하다 마주친 `UNRESOLVED`도 같은 round에서 재판정할 수 있다. 유효한 provenance·최초 유입·line evidence·0.80 이상 confidence를 만족한 Entry만 기능 구성원이 되며, 반대 근거가 있거나 마지막 round까지 미확정이면 DROP된다. 이 단계의 책임은 요청·동작·성공/실패라는 의미 단위로 기능을 묶는 것이며, 하네스 가능성은 기능의 존재 조건이 아니다. `entry_call_order`는 모든 구성 Entry를 최소 한 번 포함하며, 실제 loop/lifecycle이 같은 Entry Site를 반복 호출하면 같은 ID가 여러 번 나타날 수 있다. Agent는 source 없는 인접 caller/callee 목록에서 필요한 함수 ID만 요청한다. 요청된 source만 라운드당 최대 3개씩 같은 thread context에 누적하고, 이미 보낸 원문은 다음 prompt에 중복 복사하지 않는다. 전체 열린 함수 목록은 source 없는 참조로 함께 전달하며, 요청이 없으면 자동으로 graph depth를 넓히지 않는다. 활성 함수 예산은 다음 탐색 후보를 고르는 작업창만 제한하며, 같은 session에서 이미 원문을 읽은 함수는 작업창에서 밀려나도 유효한 누적 근거로 유지한다. 모델이 반환한 raw 함수 ID, `ID::이름`, 고유 함수 이름과 qualified name은 모두 실제로 열린 단일 함수 ID로 해석하고, 중복 이름처럼 모호한 경우만 거부한다. 각 라운드의 기능 목록은 누적하므로 다음 라운드가 일부 기능만 보완해도 앞서 발견한 다른 기능이 사라지지 않는다. Anchor가 Entry 아래쪽 consumer이거나 정상 lifecycle 근거가 부족해도 의미 Feature 자체는 보존하고, 경계·input binding·Anchor→Entry path·anchor action·action/Entry 순서 또는 required/action 함수 참조 중 하나라도 미확정이면 `planning_complete: false`로 격리한다. OSS-Fuzz backend에서는 여기에 Common Anchor의 FI build-target 귀속과 현재 libFuzzer execution model 적합성도 적용한다. 예를 들어 별도 `timedrun` executable의 `main`이나 vendor example `main`처럼 canonical fuzzer link에 포함된 근거가 없는 Anchor, 필수 fork/exec 기능은 의미 Feature에는 남지만 harness-ready가 아니다. 이 목록은 Large Feature 및 Harness Generator에는 전달하지 않는다. 판정은 `features/small-readiness.json`에서 확인할 수 있다. Large Feature는 첫 Entry가 같은 후보 안에서 선행 상태의 의미적 동등성을 판단하며, raw 문장 표현이 다르다는 이유만으로 별도 그룹을 만들지 않는다. `entry_call_graph.nodes/edges`에는 반복 호출을 구분한 Entry invocation 순서가, `function_nodes/function_edges`에는 실제 분석 call graph가 저장된다. 모델은 확인된 lifecycle이나 함수 집합을 임의로 바꿀 수 없다. 그룹화 후 모델은 중복 없는 입력 주체 목록, 주체별 정상 기능 집합과 공격 접근 조건, Large Feature별 영향 범위 및 Feature→주체 매핑만 판정한다. 코드는 접근 용이도와 영향도를 곱해 `base_risk_score`를 만들고 이를 그대로 최종 `priority_score`로 사용한다. 접근·영향 근거가 없으면 위험 점수 50을 사용한다. Capability 비율은 순위에 반영하지 않고 폐기 정책의 근거로만 보존한다. 현재 주체가 다른 모든 주체의 capability를 포함하고 접근 조건이 `IMPLAUSIBLE`이며 판정 confidence가 0.8 이상인 경우에만 `DISCARD`한다.

Harness Generator의 다음 한 함수 선택은 현재 caller/callee frontier, 현재 source에 이름이 나타난 실제 함수, 또는 Small Feature가 이미 확정한 unopened `required_function` 중 하나여야 한다. 따라서 자동 BFS 없이도 별도의 startup 경로에 있는 확정 초기화·cleanup 함수를 한 번에 하나씩 열 수 있다.

기본 모델 라우팅은 역할별로 고정되어 있다.

| 역할 | 기본 모델 |
|---|---|
| Entry Generator | `gpt-5.6-luna` |
| Entry Verifier | `gpt-5.5` |
| Small Feature Discovery/Reconciliation | `gpt-5.5` |
| Large Feature | `gpt-5.5` |
| Harness Generator | `gpt-5.5` |
| Harness Verifier/Seed Agent | `gpt-5.5` |

필요한 경우 명시적으로 override할 수 있다.

```bash
harnesscreator run /path/to/project \
  --candidate-model MODEL_FAST \
  --strong-model MODEL_REASONING \
  --coding-model MODEL_CODING \
  --no-dynamic-verification
```

`--model`은 모든 역할을 같은 모델로 override한다. 역할별 옵션은 그 위에 다시 적용된다. 아무 모델 옵션도 주지 않으면 위 고정 매핑이 사용된다. 고정 모델을 Codex가 임의로 최신 또는 상위 모델로 대체하지 않는다. 실제 적용된 매핑은 실행 시작 로그와 `workflow.json`에 기록되고, 각 호출의 모델과 reasoning effort는 `trajectories/llm.jsonl`에 기록된다.
정적 분석 preflight 뒤 app-server의 모델 목록을 확인하므로 고정 모델이 없으면 Agent 호출과 run artifact 생성 전에 명확한 오류로 종료한다. 다른 모델을 사용할 때만 역할별 override를 명시한다.

큰 프로젝트는 `--entry-batch-size 32`처럼 Entry Generator 한 번에 처리할 source excerpt 수의 상한을 조절할 수 있다. 전체 prompt에는 별도의 크기 상한도 적용되므로 값이 커도 과대 batch는 자동 분리된다. 16KB를 넘는 단일 함수는 전 구간을 여러 excerpt로 검사한다. `tests/`, `fuzz/`, `benchmarks/`와 non-product build target은 이 LLM 단계 전에 제외된다. 후보는 `DIRECT_ACQUISITION`, `PROCESS_START`, `EXPORTED_API`, `EXTERNAL_CALLBACK` 중 하나여야 하며, 실제 외부 call metadata·공개 declaration·callback 등록 evidence 등 종류별 정적 조건을 통과해야 한다. Harness Generator는 Common Anchor 하나에서 시작해 모델이 매 turn 선택한 함수 source 하나만 추가한다. 모델이 누적 context가 불완전하다고 판정하고 정적 graph/source/Feature로 검증 가능한 다음 후보를 제시하면 hard blocker가 되기 전에도 그 후보 한 개를 계속 연다. 후보 없이 막연히 불완전하다고만 한 경우에는 자동 BFS를 하지 않는다. 최종 생성에는 실제로 연 함수만 전체 약 300KB source 예산 안에서 전달한다.

기본적으로 1개의 독립 `codex app-server` worker를 사용한다. 여러 turn에 걸쳐 함수를 여는 Entry Verifier, Small Feature, Large Feature, Harness Generator, Harness Verifier 작업은 작업 인스턴스별 고정 thread를 소유한다. 따라서 `A`를 읽고 `B`를 선택한 다음 turn은 같은 thread에서 `A`의 원문 context를 유지한 채 `B`를 읽는다. `--workers`가 2 이상이어도 session은 처음 배정된 worker에 고정되며 다른 worker로 이동하지 않는다. 서로 다른 Entry나 Feature는 별도 session을 사용하므로 문맥이 섞이지 않는다.

`--worker-recycle-turns`는 메모리 제한을 위한 재시작 기준이지만, 살아 있는 session이 있으면 재시작을 그 작업 종료 뒤로 미룬다. 동적 검증 직전에도 active thread를 종료하지 않으므로 generation → audit → seed refinement → repair 문맥이 유지된다. 각 stateful thread의 최근 요청 token usage와 model context window를 추적하고, 사용량이 70%에 도달하거나 다음 source prompt와 32K reasoning/output reserve를 합친 예상량이 90%에 도달하면 같은 thread에서 `thread/compact/start`를 먼저 수행한다. 그래도 app-server가 `contextWindowExceeded`를 반환하면 같은 thread를 즉시 한 번 압축하고 실패한 turn을 한 번 재시도한다. 압축 이외의 상태 보존 session 오류나 압축 후 반복된 초과는 빈 thread로 몰래 재시도하지 않고 명시적으로 실패한다. `--resume-from`은 이전 trajectory의 stateful session이 첫 turn부터 저장 순서와 정확히 일치할 때만 session 전체를 재생한다. 정상 종료된 session은 `session_closed` marker로 구분한다. 이 marker를 도입하기 전 run도 sibling agent trace의 `final_verdict`/`entry_enumerated` terminal event가 있는 Entry/Small session만 복구하며, WSL 종료 시 진행 중이던 불완전 prefix는 live session으로 다시 시작한다. 첫 turn이 달라진 session은 처음부터 live thread로 다시 실행하며, 재생 도중 뒤늦게 달라지면 빈 thread로 이어 붙이지 않고 중단한다. 여러 저장소를 동시에 실행할 때는 모든 run의 worker 합계를 기준으로 자원을 계산해야 한다. 안정성을 우선하면 저장소마다 `--workers 1`, 단일 저장소의 속도를 우선할 때만 `--workers 2`를 권장한다.

```bash
harnesscreator run /mnt/c/memcached \
  --workers 1 \
  --resume-from ./runs/<previous-run-id> \
  --no-dynamic-verification
```

## 산출물

각 run은 `analysis/`, `entries/`, `features/`, `harnesses/`, `findings/`, `summary.json`을 가진다. `entries/verified-raw.jsonl`과 `deduplication.json`은 동일 Entry Site 병합 전후를 보존하며, `verified.jsonl`, `rejected.jsonl`, `unresolved.jsonl`은 최초 Verifier 판정을 담는다. Small Feature 재판정 결과는 `promoted-during-small.jsonl`, `dropped-after-small.jsonl`, `verified-final.jsonl`에 분리해 남긴다. `features/small-readiness.json`은 의미상 복원된 Small Feature와 실제 harness-ready Feature를 구분한다. 생성 실패도 덮어쓰지 않고 attempt별 source, manifest, generator audit, static audit, build/replay/reachability/fuzz validation으로 보존한다. 하네스 또는 미귀속 crash를 만든 정확한 bytes는 regression seed로 저장되어 다음 repair attempt의 `validation-seeds.json`에 다시 포함된다.

`summary.json`은 `analysis_provider`, `analysis_authoritative`, `fuzz_introspector_used`를 직접 표시한다. 또한 `small_features`, `harness_ready_small_features`, 생성 대상으로 남은 `large_features`, 주체 정책으로 제외된 `discarded_large_features`, `generation_attempts`, 비어 있지 않은 고유 source 수인 `harnesses_generated`, 모든 정적 계약이 `PASS`인 수 `harnesses_static_passed`, 실제 compiler/linker/instrumentation gate를 통과한 수 `harnesses_build_passed`, `harnesses_blocked`, runtime-qualified 수 `harnesses_qualified`를 구분한다. 의미 Feature는 있으나 계획 증명이 끝난 Feature가 없으면 `FAILED_NO_HARNESSABLE_FEATURES`, 모든 Large Feature가 주체 정책으로 제외되면 `FILTERED_NO_ATTACKER_REALISTIC_HARNESS`, 생성된 유효 하네스가 없으면 `FAILED_NO_VALID_HARNESS`, 빌드 가능한 하네스가 없으면 `FAILED_NO_BUILDABLE_HARNESS`가 된다. Docker·compiler·GDB·coverage runner 자체가 실패한 경우에는 하네스 결함이나 빌드 불가로 덮지 않고 `FAILED_VERIFICATION_INFRASTRUCTURE`로 분리한다. Runtime 검증을 생략해도 build를 통과한 결과만 `BUILD_VERIFIED_DRAFT_COMPLETE` 또는 `BUILD_VERIFIED_DRAFT_PARTIAL`로 표시하며 CLI는 이를 최종 성공으로 취급하지 않는다.

Harness Generator의 16개 self-audit은 모두 정확히 한 번씩 `PASS`와 구체적인 evidence를 가져야 한다. 결정적 Static Gate의 `FAIL`은 즉시 수정하며, 정적 heuristic만으로 확정할 수 없는 `WARN`은 독립 검토에 전달한다. 독립 검토는 HC01~HC16 전부 `PASS`여야 build로 진행한다. 모델이 임의로 만든 build target은 채택하지 않으며 canonical OSS-Fuzz project/fuzzer 또는 trusted command/binary pair가 없으면 HC19 실패다. 실제로 호출한 공개 프로젝트 함수에서 내부 Common Anchor까지 graph 경로가 있으면 HC08의 정적 호출 경계로 인정하되, 최종 도달은 GDB로 확인한다. 현재 runtime은 in-process libFuzzer 전용이므로 콜백 내부의 일반 `fork`/`exec`/`posix_spawn`은 target coverage와 crash 전달을 끊는 HC21 실패이고, 애플리케이션 `.c/.cc/.cpp` 직접 include는 실제 project link 경계를 우회하므로 HC22 실패다.

Large Feature의 selector는 `0..N-1` 연속 정수로 고정된다. 한 selector byte가 표현할 수 있는 256개를 넘으면 여러 실행 그룹으로 분할한다. 결정론적 seed와 qualification fuzzing에는 manifest의 `max_size`를 적용하며, 선언된 상한보다 큰 LLM seed는 실행하지 않는다.

### 에이전트 판단 디버깅

모든 run은 별도 옵션 없이 `debug/agent-events.jsonl`과 `debug/agent-trace.log`를 생성한다. `agent-events.jsonl`은 Entry 후보 거부 근거, 전체 context, model response, verdict, feature reconciliation, priority 및 backtracking을 보존하는 상세 기록이다. 사람용 `agent-trace.log`와 `--agent-debug` 출력은 Entry 시작점, 새로 방문한 `함수 -> 함수`, 최종 Entry 판정, `Entry -> Small Feature`, Small Feature 설명·준비 상태, `Small Feature -> Large Feature`, Large Feature 설명 및 Harness 검증 결과만 표시한다. 같은 Entry에서 같은 함수 이동은 한 번만 출력한다. 원문 전체 LLM 요청/응답은 `trajectories/llm.jsonl`에 남는다.

터미널에서도 판단을 실시간 확인하려면 `--agent-debug`를 사용한다.

```bash
harnesscreator run /mnt/c/memcached \
  --agent-debug \
  --workers 1 \
  --no-dynamic-verification
```

특정 후보나 이벤트만 찾을 수 있다.

```bash
rg '\[ENTRY (START|WALK|DONE)\]' RUN/debug/agent-trace.log
rg '\[SMALL (START|WALK|MAP|DONE)\]' RUN/debug/agent-trace.log
rg '\[LARGE (MAP|DONE)\]' RUN/debug/agent-trace.log
rg '\[(HARNESS|STATIC GATE|VERIFY)' RUN/debug/agent-trace.log
jq 'select(.agent == "entry_verifier" and .event == "final_verdict")' RUN/debug/agent-events.jsonl
jq 'select(.candidate_id == "ENTRY_CANDIDATE_ID")' RUN/debug/agent-events.jsonl
```

## 현재 경계

FI build-free frontend도 source 기반 call graph이므로 indirect function pointer, template 및 virtual dispatch는 근사치일 수 있다. 그래서 provider와 coverage를 기록하고 명시적 FI report override를 허용한다. bootstrap source indexer는 FI 실패를 명시적으로 허용한 경우에만 사용한다. 동적 verification이 빠진 결과는 정적 gate 통과 여부까지만 의미하며 qualified가 아니다. 현재 동적 adapter는 libFuzzer만 지원한다. 일반 qualification은 libFuzzer의 `cov:` counter가 실제로 증가하고 per-file llvm-cov에서 지정한 application checkout 경로의 코드가 실행되어야 통과한다. 전체 report 합계나 생성 하네스 selector의 edge만으로는 통과하지 않는다. Crash stack의 compiler runtime·sanitizer·외부 dependency frame은 target으로 간주하지 않고, 생성 harness 또는 현재 application checkout/분석 파일로 귀속된 경우만 판정한다. Target finding은 하네스 결함과 분리하며 `findings/<id>/input`에 exact binary bytes와 attribution metadata를 함께 보존한다.

상세 설계와 연구 근거, 확장 지점은 [설계.md](./설계.md)에 있다.
