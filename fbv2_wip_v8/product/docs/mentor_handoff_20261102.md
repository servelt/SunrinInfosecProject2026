# 11월 5일 공유용 진행 현황과 11월 7일 md4c 시연

작성일: 2026-11-02. 이 문서는 현재 작업 트리와 보존된 실행 영수증의 상태를 기록한다. `vulnerabilityanalysis/` 이외 팀 저장소 코드는 이번 공유 범위에서 제외한다.

## 확인된 결과

| 경로 | 확인된 결과 | 한계 |
| --- | --- | --- |
| 원본 FBv2 Direction·SP | 실제 모델이 md4c Direction과 UAF 가설 SP 후보 1건을 생성 | SP는 사람이 함수를 지정한 통제 실행. 실제 모델 Verifier→PoV는 미완료 |
| 원본 Worker 대기열 → 제품 Runtime | 역할 응답 fixture로 Direction→Seed→SP→Verifier→PoV를 거쳐 과거 146바이트 OOB 입력을 원본 ASan 바이너리와 제품 독립 재생에서 실행 | 모델 0회, 자동 발견 0건. Gate 승격 함수 미호출, `TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE` |
| 같은 Worker의 물리 Global Fuzzer | 공식 md4c Harness에서 15초 캠페인이 `RAN`; 최신 통제 실행에서 물리 6회 완료·잔류 0회·총 17.715243초 | 해당 캠페인은 새 Crash 0건. 통제 PoV 입력은 퍼저가 만든 입력이 아님 |
| 별도 무힌트 Global Fuzzing | 공개 정상·명세 입력 766개에서 시작해 121바이트 OOB 입력(SHA-256 `0b45653c1f2dde121767938145c4a6e83c0c0bfff33238c6e72ef29940d722e2`)을 생성; 원본 ASan 재생과 제품 소비기 `PENDING_CAUSAL_EVIDENCE` 기록 | 기존 OOB와 같은 canonical Crash ID. 별개 취약점 여부와 인과관계 미확정, 자동 `VERIFIED` 0건 |
| 모델 가설을 보고 만든 UAF 입력 | 사람이 작성한 145바이트 PoC를 독립 재생해 제품 Root Cause·Security Gate `VERIFIED` | `MODEL_ASSISTED_MANUAL_VALIDATION`; 자동 PoV·자동 발견이 아님 |
| 기존 HP | 사람이 준 SAFE의 Assertion 계측과 md4c Guided 물리 실행 확인 | 실제 모델 SAFE→Assertion→Guided 연속 실행은 미검증; 11/7 기본 시연의 필수 조건에서 분리 |

## 현재 차단점과 실패 기록

| 입력·단계 | 관측된 실패·보류 | 원인과 처리 |
| --- | --- | --- |
| 실제 SP Verifier→PoV 모델 연속 실행 | Verifier 진입 뒤 예산 소진 또는 `cyberPolicy`; 원격 종료 미확정 호출은 `UNCERTAIN`. 고정 실행 사양의 모델은 `gpt-6.1-sol` | 기존 요청을 재전송하거나 모델을 내려 우회하지 않음. 실제 모델 PoV 성공으로 보고하지 않음 |
| SP 전용 Fuzzer 라이브 | 원본 동시 실행 경로는 모델 주입 모드에서 비활성. 제품용 Worker 후 경로는 Provider-free 검증됐지만 실제 정상 PoV 계보가 없어 라이브 진입점 `SP_FUZZ_LIVE_MODE_NOT_CONNECTED` | 11/7에는 Global Fuzzer 결과와 구분. 검증된 모델 PoV와 실행 자격이 확보되기 전 차단 유지 |
| 자동 퍼징 OOB → Security Gate | 독립 재생 `REPRODUCED_OBSERVATION_ONLY`, `PENDING_CAUSAL_EVIDENCE`, Gate `NOT_STARTED` | ASan 접근만으로 원인 위치를 확정할 수 없음. Gate 기준은 유지 |
| 11/2 통제 시연 첫 재실행 | `AttributeError: SimpleNamespace has no attribute sp_fuzz_max_items` | 시연용 예산 객체가 최신 공개 실행기의 SP Fuzzer 비활성 계약을 누락. `sp_fuzz_max_items=0, sp_fuzz_seconds=0`을 명시해 동일 명령 재실행 통과 |
| 코드 공유 | 팀 `main`이 `origin/main`보다 3커밋 앞서고 그 이력에 Blind 자료·바이너리가 있음 | `main` Push 금지. 원격 기준 새 게시 브랜치에서 `vulnerabilityanalysis/`만 선별해야 함 |
| 원본 FBv2 코드 공유 | 로컬 통합 체크아웃의 `origin`은 `o2lab/FuzzingBrain-V2`; 해당 체크아웃과 공식 저장소 목록에서 LICENSE 미발견 | upstream Push 금지. `vulnerabilityanalysis/fbv2_integration/`에 우리가 작성한 연결 코드·테스트를 검토 후보로 준비. 원본 문맥을 담은 변경 패치는 Git 게시 후보에서 제외하고 권한 확인 후 별도 처리 |

11월 2일 Codex App Server `model/list`를 **모델 턴 없이** 다시 조회했다. 현재 호출자에게 `gpt-6.1-sol`은 `standard`만, `gpt-6-sol`은 `standard`와 `daybreakBlue`, `gpt-daybreak-blue-latest`는 `daybreakBlue`가 표시됐다. 이 카탈로그는 **현재 사용 가능 옵션**이지 과거 Verifier 요청의 실제 적용 프로그램 영수증이 아니다. 기존 `cyberPolicy`·`UNCERTAIN` 요청은 재전송하지 않는다. Blue 범위에서 새 SP 분석을 수행할 수 있는지는 원본 실행 사양·승인 범위·예산을 별도로 고정한 뒤 판단하고, PoV 자동 검증 완료로 집계하지 않는다.

## 11월 7일 최소 시연 명령

현재 개발 PC의 로컬 경로와 공식 md4c 자격 사양이 있는 경우에만 실행 가능한 명령이다. 모델 호출은 없다. 역할 응답은 fixture이고, 실제 Global Fuzzer와 Target Runtime은 물리 실행된다.

```bash
cd /home/dawne/work/SunrinInfosecProject2026/fbv2_hp_integration
timeout 90s /tmp/va-fbv2-integration-venv313/bin/python -B devtools/md4c_original_queue_controlled_gate_20261102.py --real-global --official-consumer
```

최신 성공 실행: run ID `controlledqueuea67c41abde3c41d0b3f712d62531da06`, 결과 `/tmp/fbv2-queue-gate-controlled-jur9zqca/CONTROLLED_RESULT.json`, 결과 파일 SHA-256 `6b9cb3b090dcca62ef88931b6b2394a223f510c4e3bff9eb56888b1b082f3c1c`. 공식 Harness SHA-256 `55363f6787505ca61b50a028a1a7fdd14cfa71112953cbd02aa8d12e00261815`, 원본 ASan 바이너리 SHA-256 `4b75a6c4e8ace630d9db101592a84d68145448090ba824abc9d597fa8a759196`, 통제 PoV 입력 SHA-256 `9de288250d625a75471a2da8f876d22472f871190eec592664fcd201130d5613`.

스크립트의 자격 사양은 기존 저장소의 `documentation/md4c_public_preflight_spec_20261102_v3.json`을 읽도록 수정했고 같은 명령으로 재실행했다. 다만 개발 PC의 로컬 FBv2·제품·평가도구 경로와 공식 md4c 계약·바이너리가 필요하다. 따라서 **아직 깨끗한 체크아웃에서 명령 하나로 재현되는 배포판은 아니다**. 11/7 전까지 나머지 로컬 경로·사양을 명시하고 리허설한다.

실패 시 출력 원문은 [첫 재실행 오류](md4c_controlled_failure_sp_fuzz_cap_20261102.log), 수정 후 출력은 [물리 Global 통제 실행](md4c_controlled_real_global_20261102.log)에 보존했다. 게시 후보의 제품 코드에 대해 `test_final_verification.py`, `test_fuzzer_crash_consumer.py`, `test_sp_hp_independence.py`를 재실행해 **54 PASS / 3 SKIP / 20 subtests PASS**를 확인했다. 이 집중 시험은 실제 모델 Verifier→PoV 실행이나 자동 OOB 인과 증명의 성공을 뜻하지 않는다.

무힌트 자동 퍼징의 121바이트 OOB는 위 명령의 통제 PoV와 **별개의 캠페인**이다. 보존된 원시 증거는 로컬 `fbv2_hp_integration/documentation/md4c_spec_flags_20261102/`에 있고, 이 문서에는 요약과 SHA만 기록한다. 이 캠페인 결과를 FBv2 모델의 자동 PoV 성과로 합산하지 않는다.

## 멘토 슬라이드용 3장 요약

1. **동작하는 부분:** 원본 FBv2의 실제 Direction·SP 가설, md4c 물리 Global Fuzzing, 통제 PoV의 ASan 실행·독립 재생, 수동 UAF의 Gate `VERIFIED`.
2. **실패한 부분과 원인:** 실제 모델 Verifier→PoV는 제공자 `cyberPolicy`/종료 불확실성으로 중단. 자동 OOB는 원인 증거가 없어 Gate `PENDING`. 실제 모델 SAFE 기반 HP 완주는 미검증.
3. **다음 결정:** 11/7에는 md4c 기본 경로의 실행·판정과 원시 실패 로그를 보여주고, 11/8 이후 기존 HP 연결 및 함수 힌트 없는 비교 실험을 진행. 통제 시험과 자동 발견 실적은 별도로 제시.

원본 47장을 보존한 `슬라이드_멘토공유_진행상태_20261102_v2.pptx` 복사본에 최신 상태·모델 접근·시연 계획 3장을 추가했다. 마지막 장은 **11/5 코드 브랜치 게시 완료, 11/7 시연 미완료**를 구분한다. 로컬 복사본 SHA-256은 `5c8cb13c2c87899b8bf5b3e4c16676df997bb43850f9a02da5225c5e6d45c482`이다. 이 PPTX는 Git 게시 브랜치에 포함하지 않았으므로 멘토 전달 시 별도로 공유해야 한다.

최신 통제 실행의 `/tmp` 원본 3,308개 파일은 로컬 `FBV2_MD4C_DEMO_EVIDENCE_20261102.zip`에 보존했다(SHA-256 `c0be04a41006f8bdd59d86a763dd12eb864bb048cd61aa720d92ecc849b211ae`). ZIP 내부의 파일별 크기·SHA 매니페스트를 독립 대조했다. 이 증거 ZIP도 Git 게시 후보에서 제외했고 원본 md4c 소스·ASan 바이너리는 포함하지 않았다.

## 공유 경계

팀 저장소는 `servelt/SunrinInfosecProject2026`(private)이며, 이번 게시 후보는 `vulnerabilityanalysis/`의 제품 소스·테스트·프롬프트·설정·이 문서와 [FBv2 연결 코드 검토 묶음](../fbv2_integration/README.md)이다. 해당 묶음은 원본 전체·원본 문맥 패치를 담지 않으며, 기존 평가도구의 Blind 프로세스 가드 의존성이 남아 **Git 후보만으로 시연을 독립 재생할 수 없다**. 인증정보, 원시 거부 이벤트, Blind 자료, 바이너리, Corpus, 대용량 실행 산출물은 게시 후보에서 제외한다. 별도 브랜치를 원격 `main` 기준으로 준비하고 기존 미게시 3커밋을 포함하지 않는다. 실제 commit/push 전 게시 파일 목록과 전체 이력을 검토한다.
