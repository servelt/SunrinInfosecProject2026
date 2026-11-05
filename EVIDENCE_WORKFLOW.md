# HarnessCreator: 비용·누락 근거와 적용한 워크플로우

## 확인한 기존 실행 결과

2026-10-24 memcached 중단 로그와 실행 요약을 기준으로 작성했다. 해당 소스와 원본 데몬을 이 작업 환경에서 다시 실행하지 않았다.

| 구간 | 모델 호출 | 관찰한 문제 |
| --- | ---: | --- |
| Entry 후보 생성 | 34 | 21개 Entry를 최종 승인했다 |
| Entry 확인 | 60 | 승인 Entry 이후의 Action은 아직 실행 검증하지 않았다 |
| Action 분석 | 800 | 약 3시간 57분을 소비했다. Action 266개 중 265개가 `POSSIBLE`이었다 |
| State 분석 | 275 | 약 1시간 26분을 소비했다. 완료한 Action 60개 모두 `POSSIBLE`이었다 |
| 원본 요청 실행 | 0 | Action·State의 전체 완료가 선행 조건이었다 |
| 하네스 생성 | 0 | 원본 요청 단계까지 도달하지 못했다 |

총 1,169회는 해당 실행의 **모델 호출 시도** 수치다. 중단 전 계정의 남은 월간 사용량은 알 수 없다.

`[ACTION BRANCH]` 로그의 소스 열람 705회를 별도로 집계했다.

- 서로 다른 함수 이름은 74개다.
- `Entry ID + 함수 이름` 조합은 108개다.
- `process_command_ascii`는 98회 열었다.
- `process_marithmetic_cmd`는 94회 열었다.
- `_meta_flag_preparse`는 78회 열었다.
- 167개의 서로 다른 `OperationSeed ID`가 등장했다. 같은 ID가 다른 Entry에도 출현하므로 `Entry + OperationSeed` 조합은 202개다.

`[STATE OPEN]`은 275회 기록됐다. 서로 다른 Action ID는 64개다. 첫 번째로 열었던 handler의 이름은 14개였다. 같은 handler를 열어 비슷한 질문을 반복한 것이 확인된다.

위 열람 수치는 모델 호출 수와 다르다. 그룹별 출력 길이와 후속 재분석 횟수도 아직 측정하지 않았으므로, 열람 중복률을 전체 비용 절감률로 바꾸지 않았다.

같은 형식의 실행 로그에서는 다음 명령으로 열람 통계를 다시 계산한다.

```bash
python3 audit_trace.py /absolute/path/to/run.stderr.log
```

## 논문과 설계 연결

1. [SynapseFlow (2026)](https://arxiv.org/pdf/2607.07007)는 데이터 흐름을 따르는 함수 묶음을 사용한다. 논문의 ablation 실험에서 다른 휴리스틱 묶음으로 대체하면 branch coverage가 29.6% 감소했다. 단계별 생성과 해당 단계의 복구를 제거하면 46.7% 감소했다. 따라서 함수 이름이 비슷하다는 이유만으로 묶지 않고, 실제 Entry·dispatcher·handler 관계를 검사한다. 다만 현재 구현은 SynapseFlow의 전체 Structural Flow Graph와 같지 않다.
2. [HarnessAgent 실증 연구 (2026)](https://arxiv.org/pdf/2512.03420)는 29개 OSS-Fuzz 프로젝트를 분석했다. 함수 선언을 지어내거나 컴파일 오류를 잘못 분류하면 겉보기 성공률이 높아질 수 있다고 보고했다. 따라서 하네스 소스 생성은 성공 판정이 아니며, 기존 정적 검사와 빌드·실행·동등성 확인을 유지한다.
3. [AFLNet](https://github.com/aflnet/aflnet)은 실제 요청 시퀀스와 응답 상태를 이용해 상태가 있는 네트워크 서비스를 퍼징한다. HarnessCreator에 요청 시드가 없는 경우, 원본 프로그램에서 단일 요청부터 시험해 실제 응답을 수집해야 한다.
4. [StateAFL](https://link.springer.com/article/10.1007/s10664-022-10233-3)은 네트워크 데몬의 상태를 관찰하고 요청 시퀀스를 재생한다. 따라서 내부 상태 계약을 모델이 주장했다는 이유만으로 정상 요청 순서라고 확정하지 않는다.
5. [OSS-Fuzz-Gen 오류 판정 연구](https://research.google/pubs/lessons-from-mitigating-false-positives-in-googles-oss-fuzz-gen/)는 실행 및 문맥 근거를 이용한 오탐 제거를 다룬다. 생성된 코드의 실패와 원본 프로그램의 실패를 별도로 확인하는 정책을 유지한다.

참고로 SynapseFlow 논문의 25개 프로젝트 평균 전처리 시간은 3.84시간이며, 하네스 한 개의 생성 시간은 0.33시간이다. 이는 본 도구의 성능 예측값이 아니다. 다른 실험 조건에서 측정한 수치다.

## 과거 분기별 작업 단계 (현재 기본 실행 경로에서 사용하지 않음)

아래 3~5번의 분기별 LLM 작업은 과거 설계 기록이다. 현재 기본 실행은 Entry별 소스 탐색에서 의미상 외부 동작을 구성하며 `OperationSeed`를 작업 단위로 예약하지 않는다. 현재 설계의 근거와 검증 범위는 `docs/의미기반_동작_재설계_근거.md`를 따른다.

1. `Entry Generator`가 소스에서 실제 외부 데이터 유입 후보를 수집한다. `Entry Verifier`는 소스 근거로 Entry를 확인한다.
2. `InputActionAgent`가 Entry마다 dispatcher를 찾는다. `OperationSeed`는 거절되거나 처리되지 않아도 목록에 남긴다.
3. Action 작업을 **같은 Entry, 같은 dispatcher, 같은 handler, 같은 Entry 경로**로 묶는다. 한 묶음에는 최대 8개 분기를 넣는다. 이는 모델 출력 크기를 위한 공학적 한도다. 탐색 결과를 삭제하기 위한 한도가 아니다.
4. 묶음으로 열린 dispatcher 소스에 모든 분기의 line이 포함되는지 확인한다. 긴 함수에서 발췌 밖에 있는 분기는 별도 작업으로 분리한다.
5. 모델은 분기마다 Action과 상태를 따로 출력한다. 모델이 분기를 누락했거나 `NOT_ACTION`으로 판단한 경우 개별 Action 분석을 다시 수행한다. 각각의 Action에는 동일한 기존 `PROVEN_STATIC` 조건을 적용한다.
6. 탐색 모드를 활성화한 실행은 상태 분석보다 먼저 최대 16개의 서로 다른 Action으로 원본 데몬을 시험한다. **사용 가능한 witness를 찾으면** 하네스 소스 초안을 즉시 생성한다. 이때 전체 Action 분석은 이미 끝난 상태다.
7. `StateDependencyAgent`는 같은 Entry와 실제 handler를 공유하는 Action을 최대 6개씩 묶는다. 모델 출력은 각 Action ID에 독립적인 상태 계약을 포함해야 한다.
8. 상태 묶음의 결과는 모델을 호출하지 않는 기록 재생기로 되돌린다. 기록 재생기는 모델이 열지 않았던 소스 함수를 제시할 수 없다. 각각의 계약은 기존 State 검사를 통과해야 한다. 누락되거나 문맥 탐색이 미완료인 Action은 개별 분석한다.
9. 전체 상태 계약에 따라 `ScenarioPlanner`가 요청 시퀀스를 구성한다. 초기 단일 요청의 실행 결과는 중복 실행하지 않는다. 앞서 생성한 하네스와 plan·witness가 일치하면 소스를 재사용한다.
10. 기존 하네스 정적 검사, 실제 빌드, sanitizer, 원본과의 의미 비교, crash 재현 기준을 유지한다. 검증되지 않은 source draft를 성공으로 승격하지 않는다.

## 남아 있는 제한

- Action 재구성 자체는 여전히 첫 정상 요청 검증보다 먼저 완료해야 한다. 묶음으로 호출 수를 줄였지만, Action 도중 즉시 하네스를 생성하는 비동기 파이프라인은 구현하지 않았다.
- 실행 예시의 실제 정상 여부는 원본 데몬에서 확인해야 한다. 인증·핸드셰이크·연결 상태가 필요한 경우 단일 요청은 실패할 수 있다.
- 상태 계약을 묶을 때 서로 다른 Action이 공유하는 handler라도 분기별 선행 조건이 다를 수 있다. 각 Action별 계약 출력과 검사를 강제하지만, 모델이 근거가 부족한 계약을 출력하는 위험은 남는다.
- `max_branch_validations`, `per_entry_branch_budget`, `max_scenario_candidates` 등의 기존 한도는 유지한다. 초과 후보는 목록과 obligation에 남긴다. 현재 자동 재개는 없다.
- 일반 GDB 계측만으로 요청과 handler의 인과관계를 항상 확정하지 못한다. 정확한 attribution이 없으면 `PROVEN_RUNTIME`으로 승격하지 않는다.
- 모든 C 데몬에서 성공한다고 주장할 근거는 없다. `memcached`, 상태가 있는 FTP 데몬, 다른 네트워크 데몬으로 별도 재현 실험이 필요하다.

## 다음 실험에서 반드시 기록할 측정값

- `time_to_first_original_request`: 첫 원본 요청까지 걸린 시간
- `time_to_first_draft`: 첫 C 하네스 소스 저장까지 걸린 시간
- `time_to_first_build`: 첫 실제 컴파일 통과까지 걸린 시간
- `total_model_calls`: 단계별 모델 호출 및 오류 수
- `group_fallback_ratio`: 묶음에서 빠져 개별 분석한 후보 비율
- `discovered_operation_seeds`: 모든 Entry와 operation 후보 수
- `verified_actions`: `PROVEN_STATIC` 및 원본 실행 증거를 가진 Action 수
- `reachable_functions`와 fuzzing coverage: 하네스 생성 전후에 원본 함수에 얼마나 도달하는지
- `false_positive_harnesses`: 컴파일만 성공하고 실제 타깃에 도달하지 못한 하네스 수

같은 memcached 소스·실행 명령·도구 설정으로 이전 버전과 현재 버전을 비교해야 실제 개선 비율을 말할 수 있다. 현재 테스트 결과는 **그룹 결과 누락 시 개별 재분석이 작동한다는 기능 확인**이며, 대규모 실행의 비용 개선 결과가 아니다.
