# HarnessCreator 탐색 실행 모드

이 버전은 정적 분석이 불완전할 때도 정상 입력 경로의 하네스 초안을 생성하도록 확장한다. 원본 프로그램의 요청별 인과관계를 증명하지 못한 초안은 검증된 하네스로 표시하지 않는다.

## 적용한 변경

1. `Entry Verifier`가 직접 입력 획득 위치를 찾았지만 소켓 출처를 확정하지 못하면, 해당 Entry를 `UNRESOLVED`로 유지한다. 소스 위치가 확인된 미확정 Entry도 후속 입력 분석에 참여하지만, 여기서 `VERIFIED`로 승격되지는 않는다. 초기 원본 입력 시험은 기본적으로 개수를 제한하지 않는다. 실행 비용 때문에 명시적으로 제한하려면 `--max-initial-input-trials N`을 지정한다. 이는 Entry 수가 아니라 입력 사례 수의 상한이다.
2. `InputActionAgent`는 원본 소스에서 요청 명령, 필드와 후보 바이트를 만든다. 사용자가 제공한 요청 예제는 필수가 아니다. 미확정 Entry에서 나온 Action은 `POSSIBLE`로 유지한다.
3. `StateDependencyAgent`는 미확정 Action의 상태 생산자와 소비자도 분석할 수 있다. `ScenarioPlanner`는 이를 **실험용 가설**로 사용한다. 예를 들어 SET이 생산한 상태를 GET이 소비하는 후보라면 SET → GET 요청열을 만든다.
4. 상태 관계를 찾지 못해도 입력 형식과 handler의 소스 근거가 있으면 단일 요청 후보를 만든다. 요청 길이와 필드 binding을 검사한다.
5. 원본 데몬에서 각 후보를 실행한다. 정상 응답과 GDB의 Entry → dispatcher → handler 호출 순서가 관찰되더라도 요청 식별자가 없으면 `OBSERVED_RUNTIME`으로 기록한다. `PROVEN_RUNTIME`으로 표시하지 않는다.
6. 원본이 요청을 거절하면 `ScenarioRequestRefiner`가 실패 응답과 parser·handler 소스를 읽고 입력 후보를 최대 두 개 수정한다. 수정한 요청을 새 원본 프로세스에서 한 번 더 시험한다. 입력 바이트를 직접 추측하지 않고, 출처를 기록한 소스 줄이 있어야 후보로 채택한다.
7. `OBSERVED_RUNTIME` 시나리오에서는 `ScenarioHarnessGeneratorAgent`가 C 하네스 초안을 만든다. HC11과 HC16의 런타임 증명 조건은 실패 상태로 유지한다. 나머지 정적 검사에 실패하면 빌드를 실행하지 않는다.
8. 런타임 증명만 부족한 초안은 별도로 컴파일한다. 빌드 성공은 `EXPLORATORY_BUILD_VERIFIED_NOT_QUALIFIED`로 기록한다. 이 상태는 정상 실행의 완전한 동작 동등성이나 퍼징 적격성을 뜻하지 않는다.

## 실행

기존 프로젝트의 정상 실행 명령과 실제 하네스 빌드 명령을 준비한다. 다음 명령으로 필요한 인자들을 확인한다.

```sh
PYTHONPATH=src python -m harnesscreator.cli run --help
```

기존에 사용하던 `harnesscreator run` 명령에 다음 플래그를 추가한다.

```text
--scenario-exploratory-drafts
```

TCP 데몬에서 검증할 때는 `--scenario-channel tcp`와 `--scenario-host`, `--scenario-port`, `--scenario-command`를 지정한다. memcached ASCII 명령만 검증하는 경우 `--scenario-response-protocol memcached_ascii`를 사용한다. 이 프로토콜 판정기는 memcached의 일부 명령만 지원한다. 다른 데몬의 응답 프로토콜까지 일반적으로 해석하지 않는다.

`--verification-backend command`를 사용하면 실제 C/C++ 프로젝트를 링크하는 `--build-command`와 `--binary`를 제공해야 한다. 또는 `--verification-backend oss-fuzz --oss-fuzz-dir /absolute/oss-fuzz`로 공식 OSS-Fuzz 빌드 환경을 사용한다. 어느 경로도 QuartetFuzz를 실행하지 않는다. native OSS-Fuzz 검사는 현재 빌드·스모크 수준이며 `QUALIFIED`를 내지 않는다.

## 산출물

- `actions/inventory.jsonl`: 확인하거나 보류한 외부 요청 행동
- `entries/continuations.jsonl`: 명시한 함수 작업 상한에 닿은 Entry의 다음 함수 ID. `--resume-from`과 더 큰 `--context-functions`로 앞선 모델 호출을 재사용하며 이어서 연다.
- `input-surfaces/continuations.json`: 입력 형식 탐색이 끝나지 않았을 때 열린 함수와 다음 함수 ID
- `input-surfaces/runtime-trials.json`: 실제 시험한 입력과 시험하지 않은 입력 및 그 이유
- `scenarios/state-dependency-graph.json`: 상태 관계의 정적 분석 결과
- `scenarios/exploratory-candidates.json`: 정적 증명이 부족한 시험용 요청
- `scenarios/refined-candidates.jsonl`: 실패 응답을 반영한 추가 요청 후보. 수정 후보가 없으면 생성하지 않는다.
- `scenarios/witnesses/*.json`: 원본 실행의 실제 응답과 관찰 상태
- `harnesses/*/attempt-*/`: C 하네스 초안, 정적 검사, 빌드 검사와 상태 정보
- `summary.json`: `observed_scenarios`, `exploratory_builds`, `harnesses_qualified` 등의 개수

## 아직 해결하지 못한 문제

- GDB의 요청별 인과관계 추적은 구현하지 않았다. 함수 이름과 시간 순서만으로 특정 요청의 실행을 증명할 수 없다.
- 큐를 통한 스레드 간 객체 전달과 비동기 callback을 모든 데몬에서 자동 복원하는 분석기는 구현하지 않았다. 이때 정적 분석이 누락되더라도 직접 획득 후보를 시험할 수 있게 한 상태다.
- 입출력 프로토콜의 형식이 소스만으로 복원되지 않거나, 암호화·압축·동적 인증 상태가 필요하면 요청 생성이 실패한다.
- 현재 하네스 생성기는 마지막 요청을 변이하는 모델이다. 임의 요청 위치를 변이하고 후속 요청을 수행하는 일반 상태 기반 퍼저는 아직 구현하지 않았다.
- `OBSERVED_RUNTIME` 초안은 빌드 검사만 받는다. 실제 타깃 도달, 입력 변이, 상태 격리, sanitizer 퍼징 검사를 통과한 것으로 표시하지 않는다.
- 재현 입력이 원본에서 성공한 것과 모든 퍼징 입력에 대한 동작 동등성은 다른 조건이다.
- 실제 memcached에서 이 수정본 전체를 실행하지 않았다. 현 실행 환경에 GDB와 Docker가 없다. 외부 QuartetFuzz 소스는 실행에 필요하지 않다.

## 테스트

```sh
PYTHONPATH=src pytest -q tests/test_exploratory_drafts.py
PYTHONPATH=src pytest -q
```

탐색 모드는 기본적으로 비활성화한다. 기존 엄격 검증 경로와 비교한 뒤 실제 운영에 사용해야 한다.
