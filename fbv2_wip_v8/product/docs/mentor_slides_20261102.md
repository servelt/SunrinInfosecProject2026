# 11월 5일 멘토 공유용 슬라이드 초안

실제 Google Slides 반영 전 문안이다. 통제 실행과 자동 발견을 같은 연속 실행으로 표현하지 않는다.

## 1. 현재 구현과 검증 수준

| 경로 | 확인된 결과 | 분류 |
| --- | --- | --- |
| 원본 FBv2 Direction·SP | 실제 모델의 Direction 및 UAF 가설 후보 1건 | 함수 지정 모델 분석 |
| md4c Global Fuzzer | 무힌트 121바이트 OOB 입력 생성, 원본 ASan 재생 | 자동 Crash 관측 |
| 제품 Runtime·Gate | 별도 통제 PoV는 OOB 관측 후 인과 증거 대기 | `PENDING_CAUSAL_EVIDENCE` |
| 수동 UAF PoC | 모델 가설을 보고 사람이 입력 제작, Gate 통과 | `MODEL_ASSISTED_MANUAL_VALIDATION` |
| 기존 HP | 수동 SAFE의 Assertion 계측·Guided 물리 실행 | 통제 실행 |

자동 발견으로 `VERIFIED`된 취약점은 현재 0건이다.

## 2. 실패 지점과 원인

| 단계 | 관측 | 현재 처리 |
| --- | --- | --- |
| 실제 모델 Verifier→PoV | `gpt-6.1-sol` 요청에서 `cyberPolicy`, 원격 종료 미확정. 현재 카탈로그에서 6.1 Sol은 standard만, 6 Sol은 Daybreak Blue 사용 가능 | 기존 요청 보존. 새 Blue SP 분석은 별도 범위·예산 확정 후 검토 |
| SP 전용 Fuzzer 라이브 | 모델 주입 모드의 원본 동시 경로 비활성, Worker 후 경로는 정상 모델 PoV 계보 부재 | 11/7 기본 시연은 Global Fuzzer로 진행 |
| 자동 OOB → Gate | 재생 성공, 첫 원인부터 OOB 접근까지의 독립 인과 증거 없음 | `PENDING_CAUSAL_EVIDENCE` 유지 |
| HP 모델 SAFE → Guided | 수동 SAFE 경로는 작동, 실제 모델 SAFE의 연속 물리 실행 미검증 | 기본 시연에서 분리 |
| Git 게시 | 로컬 `main`의 미게시 이력에 Blind 자료·바이너리 포함 | 원격 `main` 기준 안전 브랜치에서 `vulnerabilityanalysis/`만 준비 |
| 깨끗한 체크아웃 재현 | FBv2 원본 수정 패치·md4c 바이너리·평가도구 의존성이 게시 후보에 없음 | 로컬 재현과 Git 게시 가능 범위를 구분 |

## 3. 11월 5일 공유 현황 · 11월 7일 시연 계획

- **11월 2일 완료:** 제품·FBv2 연결·HP 코드, 테스트, 실패 로그, 재현 명령을 팀 GitHub의 `mentor/vulnerabilityanalysis-20261105` 브랜치에 게시했다. `main`은 미변경이다. 원본 FBv2의 게시 권한이 확인되지 않은 변경 패치와 민감한 실행 자료는 별도 보존한다.
- **현재 확인된 통제 실행:** md4c에서 실제 Global Fuzzer 15초, 통제 Worker PoV 입력의 ASan 실행·독립 재생·`PENDING` 판정을 확인했다. 이것은 실제 모델 SP→Verifier→PoV의 완주가 아니다.
- **11월 7일 목표, 아직 미완료:** 같은 환경에서 멘토 시연을 리허설하고 각 단계의 로그·실패 원인을 제시한다. 별도 수동 UAF의 `VERIFIED`와 실제 모델의 정책 차단을 각각 표시한다.
- **그다음:** 기본 FBv2의 남은 실행 연결을 수정하고, 기존 HP의 모델 SAFE 연결을 검증한다. 실제 무힌트 자동 발견 성능은 별도 캠페인으로 평가한다.

실행 명령, 입력·바이너리 SHA, 실패 로그는 [멘토 인계 문서](mentor_handoff_20261102.md)에 정리했다.
