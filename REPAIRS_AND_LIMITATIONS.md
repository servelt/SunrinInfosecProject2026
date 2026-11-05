# HarnessCreator 원본 코드 수정 및 확인 결과

## 수정 기준

사용자가 제공한 최초 `harnesscreator.zip`을 수정했다. 기존 Entry Generator, Entry Verifier, Input Action Agent, State Dependency Agent, Scenario Planner, Original Runtime Verifier, Harness Generator Agent, Harness Verifier Agent, Original Crash Reproducer의 역할을 유지했다. 기능별 정상 요청 흐름의 복원 목표도 유지했다.

QuartetFuzz는 품질 검사 원칙의 연구 근거다. QuartetFuzz의 Python 코드와 `DynamicRunner`는 실행하지 않는다. OSS-Fuzz를 선택하면 공식 `infra/helper.py`만 빌드와 실행 도구로 호출한다. 기존 `HarnessVerifierAgent`가 이 도구를 통해 검증 결과를 반환한다.

## 수정한 오류

1. GDB의 호출 표식에 요청 ID가 없다. 그래서 시간 순서만으로 특정 요청이 handler를 호출했다고 증명할 수 없다. 원본 코드는 이 경우 목표 도달을 무조건 `False`로 반환해 모든 일반 실행의 Witness 승격을 막았다. 새 코드는 `OBSERVED_RUNTIME`을 별도 기록한다. 명시적인 탐색 모드에서 해당 요청열의 하네스 초안을 생성한다. 요청 귀속을 증명하지 않았으므로 `PROVEN_RUNTIME`과 `QUALIFIED`는 반환하지 않는다.
2. 원본의 `PROVEN_STATIC` 선행 관문은 부분 입력 형식과 미확정 상태 계약도 모두 버렸다. 탐색 모드에서는 소스 근거가 있는 Action과 상태 관계를 실험 후보로 남긴다. Planner는 이 후보를 제한된 요청열로 만든다. 원본에서 거절한 요청은 소스와 응답을 바탕으로 수정한 후보를 추가 생성한다. 정적 증명 상태는 그대로 유지한다.
3. 큐를 건너는 비동기 전달은 일반 caller/callee 그래프에서 보이지 않았다. `GraphStore.queue_handoff_candidates()`는 큐의 push/pop과 필드명이 연결되는 함수를 탐색 후보로 추가한다. 이 관계를 실제 함수 호출이나 같은 요청의 실행 증거로 승격하지 않는다. 임의 큐 구현의 완전한 분석기는 아니다.
4. 이전 OSS-Fuzz 경로는 QuartetFuzz의 실행 구현을 가져왔다. 이제 공식 OSS-Fuzz 실행기로 교체했다. 원본 빌드 recipe는 변경하지 않는다. 생성 소스는 임시 복사본에만 기록한다. `--clean` 빌드로 오래된 fuzzer 바이너리의 재사용 위험을 줄인다.
5. 동일한 OSS-Fuzz 프로젝트의 병렬 빌드에서 동기식 파일 잠금이 이벤트 루프를 막을 수 있었다. asyncio 잠금과 비동기 파일 잠금 대기를 결합했다. 병렬 실행 테스트에서 동시에 빌드를 시작하지 않는 것을 확인했다.
6. 원본 CLI는 `oss_fuzz_revision=None`인 상태에서 `oss_fuzz_revision[:12]`을 출력했다. 해당 경로에 진입하면 `TypeError`가 발생한다. 이제 실제 Git HEAD를 확인한다. Git 정보가 없으면 `unversioned`를 출력한다. 임의의 revision을 발명하지 않는다.
7. 이전에는 canonical OSS-Fuzz 빌드만 실행한 결과를 runtime probe까지 완료한 것처럼 표현했다. 새 코드는 빌드 성공과 runtime 검사를 구분한다.
8. 기본 성공 응답 검사는 문자열 포함 여부를 사용했다. 따라서 `NOT_STORED`를 `STORED` 성공으로 오판했다. 새 검사는 줄 단위의 전체 표식을 우선 비교한다. 다만 임의 바이너리 프로토콜을 해석하지는 않는다.
9. 다른 오류 위치가 같은 상위 caller를 공유하면 동일 크래시로 판정했다. 새 코드는 sanitizer 종류, 오류 종류, 정규화한 첫 대상 프레임을 비교한다. 일부 형식에서는 정확한 프레임을 복원하지 못할 수 있다.
10. 원본에서 크래시를 재현하지 못하면 자동으로 `HARNESS_ARTIFACT`로 기록했다. 하지만 미재현은 하네스 오류의 증명이 아니다. 새 코드는 `UNCONFIRMED`로 구분한다. 재현되지 않은 후보를 같은 원인의 취약점으로 승인하지 않는다.
11. 과거 Entry 테스트에는 소켓 출처를 확인할 코드가 없는데도 `VERIFIED`를 기대하는 사례가 있었다. 해당 테스트는 `UNRESOLVED`를 기대하도록 변경했다. 소켓 출처 검증 규칙 자체를 느슨하게 만들지 않았다.

## 기존 에이전트와 실행 백엔드의 경계

`ScenarioHarnessGeneratorAgent`는 기존대로 하네스 코드를 작성한다. `ScenarioStaticHarnessGate`는 기존 품질 검사 항목을 유지한다. 별도의 `generator.review()`가 독립 검토를 수행한다. `HarnessVerifierAgent`가 실제 빌드와 동적 검사 결과를 관리한다. `runtime/oss_fuzz.py`는 HarnessCreator가 관리하는 OSS-Fuzz 실행 어댑터다.

탐색 후보가 `OBSERVED_RUNTIME`이면 빌드만 시도한다. 정적 검사에서 HC11과 HC16은 증명이 부족하므로 통과하지 않는다. 빌드 성공도 `QUALIFIED`가 아니다.

OSS-Fuzz 어댑터는 빌드, 시드 재생과 짧은 퍼징 실행을 호출할 수 있다. 그러나 정확한 handler 도달, 사용자 입력의 전체 전파, 원본과 하네스의 동작 동등성을 아직 입증하지 못한다. 따라서 OSS-Fuzz 어댑터는 성공한 빌드에서도 항상 `qualified=False`를 반환한다. **OSS-Fuzz 백엔드를 통한 최종 자동 승인 기능은 구현되지 않았다.**

## 재현한 테스트

- 최초 원본 패키지: 281 passed, 8 failed, 5 skipped, 24 subtests passed.
- 현재 수정본: 293 passed, 6 skipped, 24 subtests passed.
- 비동기 빌드 직렬화, 오래된 빌드 정리 플래그, 기존 HarnessVerifierAgent 경유를 별도로 검사했다.
- CLI 도움말 표시를 확인했다.
- 현재 실행 환경에는 GDB와 Docker가 없다. 실제 OSS-Fuzz Docker 빌드와 실제 memcached의 종단 간 자동 생성은 수행하지 않았다. 따라서 현재 테스트 결과는 많은 단위 테스트와 합성 TCP 재생 검사를 뜻한다. 임의 데몬의 정상 하네스 생성률은 아직 측정하지 않았다.

## 남아 있는 설계·구현 한계

1. GDB 표식의 요청·연결·스레드 귀속은 해결되지 않았다. 따라서 일반 데몬에서 `PROVEN_RUNTIME` 생성률은 아직 확인되지 않았다.
2. 비동기 큐의 후보 탐색은 데이터 전달 증명이 아니다. 함수 포인터, 여러 큐, 여러 프로세스의 정확한 제어·데이터 의존성을 보장하지 않는다.
3. 현재 `setup_steps`는 고정이며 마지막 요청만 변이한다. `Setup → Fuzz → Post`의 임의 후속 요청 모델은 구현되지 않았다.
4. 하네스 품질 검사에는 LLM 판단과 문자열 검사도 있다. 코드 전체 경로와 소스 주장 의미를 형식적으로 증명하지 않는다.
5. OSS-Fuzz 백엔드의 소스 덮어쓰기와 빌드 동작은 Docker 실험으로 확인해야 한다. 특히 빌드가 실제 로컬 소스를 참조하는지 별도 검사해야 한다.
6. `command` 백엔드는 사용자 지정 빌드 명령과 생성 파일의 링크 구성을 요구한다. 임의 데몬의 빌드 명령을 자동 복원하는 기능은 없다.
7. 응답 프로토콜 판정은 모든 바이너리·스트리밍 프로토콜에 적용되지 않는다. memcached ASCII에 대해서만 일부 응답을 프레임 단위로 판정한다.
8. 실제 원본 재현 실패는 버그 부재의 증명이 아니다. 비결정적 버그는 여러 실행에서만 드러날 수 있다.

## 실행 준비

WSL/Linux에서 최초 ZIP의 수정본 루트로 이동한다. 기존 Python 환경과 같은 가상환경을 준비한다.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
pytest -q
harnesscreator run --help
```

이미 OSS-Fuzz의 독립 체크아웃과 memcached를 위한 Docker 빌드 recipe가 있다면 그 경로를 지정한다. QuartetFuzz는 설치하지 않는다. 실행 모드에는 반드시 `--scenario-exploratory-drafts`를 넣는다.

```text
--verification-backend oss-fuzz
--oss-fuzz-dir /absolute/path/to/oss-fuzz
--oss-fuzz-project memcached
--oss-fuzz-fuzzer fuzzer_proxy
--oss-fuzz-source-path /src/memcached
--scenario-exploratory-drafts
```

해당 OSS-Fuzz 프로젝트의 실제 fuzzer 이름과 빌드 source 파일 이름을 확인해야 한다. 다르면 `--harness-source-filename`을 별도로 지정한다. OSS-Fuzz를 사용하지 않으면 `--verification-backend command`와 유효한 `--build-command`, `--binary`가 필요하다.

## 확인해야 하는 후속 실험

먼저 memcached 한 대상에서 정적 후보, 실행 후보, 관찰 Witness, 빌드한 초안의 개수를 각각 측정한다. 그다음 서로 다른 비동기 구조의 데몬에서 같은 절차를 수행한다. 실제 요청 바이트가 목표 handler에 도달하는지와 상태 초기화가 반복 입력 사이에 올바르게 이루어지는지 별도로 확인한다. 이 결과가 없으면 대부분의 데몬에서 성공한다고 주장할 근거가 없다.
