# Vulnerability Analysis 제출 Baseline

이 문서는 2026-10-10 현재 코드와 **이미 저장된** 실험의 제출용 색인이다. 아래 JSON·설정·Seed·압축 바이너리는 과거 산출물에서 복사했으며 원본 Run과 SP를 수정하지 않았다. 이 작업에서 새 LLM Scan이나 장시간 Fuzzing은 실행하지 않았다. 사용자가 제공한 `중간발표 (16).pptx`와 `슬라이드 (6).pptx`를 `/mnt/c/Users/dawne/Downloads/`에서 읽기 전용으로 확인했다. 두 PPT는 저장소 밖에 있으므로 아래 대응 관계는 PPT의 실제 도식·문구, 사용자가 제공한 상세 Vulnerability Scanning Workflow, 현재 코드와 저장된 실행 증거를 함께 기준으로 한다.

## 고정 입력과 무결성

| 항목 | 값·출처 |
| --- | --- |
| libyaml 소스 | `https://github.com/yaml/libyaml.git`의 `90a56d4500aa1a1798514c5cb55c3ad4cb095f94` |
| 설계 원본 | `중간발표 (16).pptx` SHA-256 `cf5d11f0e94e5b87cf1b646f547adde74663ab4e30850f9b158c846b16d2265e`; `슬라이드 (6).pptx` SHA-256 `62b7be695838643d8ac2185067443095c5b184bce72fe90e993a885c59a33538`. 두 파일은 읽기 전용이며 제출 Bundle에는 포함하지 않음 |
| libyaml Harness | `reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer/libyaml_scanner_fuzzer.c`, SHA-256 `b370c8209c82c9e94cf95a3ce0cc8eedaaee33df96d1a16e6ba8459ad3a526f4`; **Reference fixture**, 현재 팀의 Harness Generator 성능 평가가 아님 |
| 실제 캠페인 Binary | `libyaml_asan_fuzzer.gz`를 푼 SHA-256 `340fd1d09c35f8622f7b8447e9e6be41a1aea2c0a7b0254fab8d6169a8dba0f1`; Linux x86-64, ASAN/libFuzzer, Debug Symbol 포함 |
| 평가 설정 | `libyaml_evaluation_config.yaml`, SHA-256 `c4fa3ddf5b3594a241505f03a8efb5722ce9316096289e9c1736f5477a840397`; 당시 `global_enabled: true`의 **복사본**. 제품 `config/default.yaml`은 변경하지 않음 |
| 공통 초기 Seed | `libyaml_initial_seed.bin`, 144바이트, SHA-256 `15af1afdc737fda5a7b8529ba41d1d71a05363c7c9e08ef0eb8cbe16211d6951` |
| 판정 근거 복사본 | `evidence/`에 libyaml 전체 Scan 보고서·조건 UNKNOWN 감사·무효 Seed 해시·Safe Assumption 목록, Little CMS 비블라인드 평가·후속 SP, TinyProxy 원래 SP·ASAN Runtime·사후 Replay·142바이트 PoC와 생성 스크립트를 보관. 각 파일의 원본 Run은 아래에 명시하며 복사본은 `SHA256SUMS`로 검증 |
| 런타임·도구 | Ubuntu Linux x86-64, Python 3.12.3, Clang 18.1.3, GDB 15.1, Codex CLI 0.161.0; 실제 LLM 호출에는 로그인된 Codex app-server 필요 |
| 모델 | 설정 복사본의 GPT-5.6 Luna(함수·SP 정적 분석/검증, 주로 medium; Direction·Assertion은 low)와 GPT-5.6 Sol(PoV·깊은 추론, medium). Ollama 설정은 보존하며 자동 fallback 없음 |

압축 바이너리는 **당시 실행한 정확한 파일**을 보존한다. 아래에서 별도로 빌드한 파일은 기능 재현용일 뿐 같은 SHA-256이나 Coverage 계측 수를 보장하지 않는다. 원본 Debug Symbol은 원래 `/tmp/va-ollama-libyaml`의 소스 경로를 사용하므로 GDB 소스 대응에는 같은 Checkout 경로 또는 확인된 경로 매핑이 필요하다.

## 원래 Workflow와 코드·시험 대응

최종 PPT 11쪽은 C/C++ Target → Harness Generator → Vulnerability Analysis를 구분하고, 13쪽은 Harness×Sanitizer Worker에서 SP Generate→Verifier→PoV 경로와 Hallucination Prevent→Global Fuzzer 경로로 갈라지는 도식을 제시한다. 10쪽은 정적 후보 생성·검증과 동적 추론 역할을 구분한다. `슬라이드 (6).pptx` 35~40쪽은 함수 우선순위, 안전 판단 Assertion, 동적 검증·실패 Seed 재사용, Python 입력 생성을 설계 이유로 제시한다. 아래 표의 SP Fuzzer, Corpus, Assertion 세부 단계는 도식만으로 확정한 것이 아니라 사용자의 상세 Workflow와 실제 코드·실험으로 검토했다.

| 설계 경로 | 현재 코드 | 시험·실제 실행 | 판정 |
| --- | --- | --- | --- |
| Harness × Sanitizer Worker, 기능별 Direction, Entry/Core·Risk Pool | `src/vulnerabilityanalysis/adapter.py`, `scheduler.py:build_workers/build_directions/build_pool`, `workflow.py:run_phase1` | `tests/test_phase1.py`, `tests/test_candidate_scheduler.py`; libyaml Pool 12/12 완료 | **IMPLEMENTED** |
| 함수별 분석, 제한적 Caller/Callee/Macro Context | `agents.py:analyze_function`, `context.py:ContextResolver`, `scan.py:scan_selected` | `tests/test_context.py`; 저장된 실제 `yaml_free` Scan에서 Call Graph Caller 3개 조회. 모든 필요한 관계를 자동 찾는다는 보장은 없음 | **PARTIALLY VERIFIED** |
| High-Recall SP 생성, Source 검증, 보수적 Dedup | `agents.py:generate_sp`, `scheduler.py:sp_dedup_relations`, `source.py` | `tests/test_agents.py`, `tests/test_source.py`, `tests/test_sp_feedback_lifecycle.py`; libyaml SP 34개 | **IMPLEMENTED** |
| SP Verifier, 예산 밖 OPEN 유지·재선택 | `agents.py:verify_sp`, `scheduler.py:CandidateScheduler`, `workflow.py:prepare_sp_resume`, `scan.py:scan_selected` | `tests/test_candidate_scheduler.py`, `tests/test_evidence_quality.py`; 29개 검증, 5개 OPEN 보류 | **IMPLEMENTED** |
| Python PoV, Runtime, Crash/Root Cause·독립 Replay·Security Gate | `agents.py:generate_poc`, `scan.py:execute_poc`, `runtime.py`, `final_verification.py` | `tests/test_pipeline.py`, `tests/test_tinyproxy_crash_pipeline_regression.py`, `tests/test_final_verification.py`; libyaml 실제 입력 35건 실행 | **IMPLEMENTED** |
| Global/SP Fuzzer, Corpus 이월·재개 | `scan.py:run_global_fuzz/run_targeted_fuzz/sync_worker_corpus`, `runtime.py:fuzz_locally`, `workflow.py:continue_phase1` | `tests/test_global_fuzz.py`, `tests/test_parallel_fuzz.py`, `tests/test_worker_corpus.py`; 실제 libyaml Seed 공유 및 제한된 Fuzzing | **IMPLEMENTED**, FBv2 원본과 운영 방식 차이 있음 |
| 명시적 안전 판단·기존 Guard/항진식 품질 평가 | `agents.py:analyze_function`, `assertions.py:assess_safe_assumption` | `tests/test_assertions.py`; 저장된 명시적 판단 6건은 모두 현재 Harness에서 적격 Invariant가 아님 | **PARTIALLY VERIFIED**. 독립적인 적격 OSS Invariant 생성은 **BLOCKED** |
| Assertion 생성·검증·Source Copy 삽입·실행 | `agents.py:generate_assertions`, `assertions.py:instrument_copy/execute_assertion`, `scan.py:run_assertions_for_scan` | `tests/test_assertions.py`, `tests/test_guided_assertions.py`; libyaml 저장 가정 2건을 입력 한 건에서 실행해 유지 관측 | **PARTIALLY VERIFIED**. 이 관측은 일반적 안전성의 증거가 아님 |
| Assertion 도달·위반·지원식 거리 Feedback과 Guided Fuzzing | `assertions.py:guided_fuzz_assertion`, `runtime.py:fuzz_locally` | `tests/test_guided_assertions.py`; Little CMS **비블라인드** 진단에서 위반·13,267회 실행. 포인터 비교 거리 Feedback은 지원하지 않음 | **PARTIALLY VERIFIED** |
| 위반 Triage·근거 있는 Refinement | `assertions.py:triage_assertion_violation`, `scan.py:refine_overstrong_assertions` | `tests/test_guided_assertions.py`; Little CMS Triage는 `INSUFFICIENT_EVIDENCE`, 실제 OSS에서 정당한 Refinement 채택·후속 효과는 미확인 | **PARTIALLY VERIFIED** |
| 위반과 기존 SP 상태별 연결·Dedup·새 SP의 기존 PoV 경로 | `scan.py:apply_assertion_sp_feedback`, `scheduler.py:sp_dedup_relations` | `tests/test_sp_feedback_lifecycle.py`; Little CMS **비블라인드** OPEN SP의 Verifier→PoV→Runtime 확인. 독립 생성 Invariant의 위반에서 같은 결과는 미확인 | **PARTIALLY VERIFIED** |

FBv2 [§3.4·§3.6](https://arxiv.org/html/2605.21779)의 역할 분리는 적용했다. 실제 Reference의 `fuzzingbrain/fuzzer/manager.py:start_global_fuzzer`는 Worker의 지속 실행을 관리하고 `worker/pipeline.py:_run_verify_agent/_run_pov_agent`는 별도 작업 루프를 사용한다. 현재 구현은 함수별 시간 slice와 Worker Corpus 이월을 사용한다. Reference의 `core/sp_dedup.py` 및 DB Repository 기반 전역·모델 Dedup과 달리 현재 구현은 소스 위치·취약점 유형·Root Cause가 확인된 경우에만 보수적으로 관계를 기록한다. 두 구현의 탐색량과 중복 제거 효과를 동등하다고 주장하지 않는다.

Code-Augur [§IV-A–C](https://arxiv.org/html/2606.18619)는 프로젝트 Threat Model 아래 보안 가설을 생성·평가하고, **명시적 안전 판단의 근거**를 Invariant로 반증·수정한다. 현재 Function Analyzer는 한 요청에서 여러 가설을 평가하고 필요시 Context를 재조회한다. 논문의 프로젝트 수준 Threat Model 자동 구성 및 가설별 반복 요청과 1:1 구현은 아니다. 앞선 동일 조건 A/B에서는 적격 Invariant 증가가 없어 Analyzer 구조를 변경하지 않았다. 현재 `--hallucination-prevent off`는 Assertion 이후 경로만 끈다. Function Analyzer의 안전 판단 필드 추론 비용이 남으므로 **순수 FBv2 비용 Baseline이 아니라 공유 Analyzer의 HP 실행 경로 OFF**다.

## 동결한 실제 OSS 결과

| 실험 | 관측 결과 | 해석 |
| --- | --- | --- |
| libyaml Full-Scan | `libyaml_baseline.json` 및 `evidence/libyaml_fullscan_report.json`: 함수 12/12, SP 34, Deep Verification 29, OPEN 보류 5, PoC 기록 37·실제 실행 35·입력 생성 오류 2, ASAN Crash 0, VERIFIED 0 | `SP_CONDITION_REACHED`는 참 0·거짓 8·UNKNOWN 27. `evidence/libyaml_poc_condition_audit.json`에서 측정 가능 검증식 없음 19, 정확한 SP 위치 Hit 미확인 8로 구분. 이를 안전 또는 참으로 바꾸지 않음 |
| libyaml Worker Fuzzing | 원본 `result/vulnerabilityanalysis/20261010T1115Z-fullscan-final-review/report.json`의 복사본 `evidence/libyaml_fullscan_report.json`; 보관 Corpus 2,303개, 유효 초기 6함수의 할당 엔진 시간 29초 | 과거 중단된 무효 진단 Run에서 처음 나온 65개는 `evidence/libyaml_invalid_seed_hashes.json`으로 구분. 다음 OFF/ON 초기 Corpus에 넣지 않음 |
| TinyProxy 1.11.1 블라인드 | `tinyproxy_blind_summary.json`, `evidence/tinyproxy_blind_original_sp.json`, `evidence/tinyproxy_blind_runtime_uaf.json`: commit `90adf28663874e6d34d3eebeae6279906443aea5`, `REGRESSION_FIXTURE`, Pool 17, 완료 함수 9, SP 50, Verifier 18, PoC 실행 16, ASAN UAF 1, **VERIFIED 0** | 원본 Run `20261009T051404Z-dd8b6502`. 142바이트 입력과 Python 생성기는 `evidence/tinyproxy_uaf_142b_input.bin`, `evidence/tinyproxy_uaf_input_generator.py`. 함수/SP 원래 가설의 Root Cause 불일치와 시간 제한을 포함한 블라인드 성적. Harness Generator 평가가 아님 |
| TinyProxy 사후 Crash 진단 | `tinyproxy_postblind_gate.json`: 별도 `POST_RUNTIME_SANITIZER` 후보 `crash-0297f01c920dd4f2`가 독립 Replay·로컬 허용 클라이언트 Security Property Gate를 통과해 VERIFIED | 원래 `sp-a4ff121e327e3408`은 OPEN. 사후 1건을 블라인드 VERIFIED에 합산하지 않음 |
| Little CMS Hallucination Prevent | `evidence/lcms_nonblind_evaluation.json`, `evidence/lcms_nonblind_sp_followup.json`; 원본 Run `20261010T054159Z-lcms-codeaugur-diagnostic`, `20261010T060952Z-lcms-pending-sp-followup` | 논문 조건을 제공한 **비블라인드 기능 검증**. Assertion 위반, 13,267회 Guided Fuzzing 실행, Triage는 `INSUFFICIENT_EVIDENCE`; 원본 ASAN 오류 없음, 후속 SP는 OPEN/UNKNOWN. 독립 탐지 성능 증거 아님 |

libyaml `evidence/libyaml_fullscan_report.json`에 저장된 완료 LLM 요청은 최초 6함수 48회, 후속 6함수 41회, 보류 SP 재개 23회로 총 112회다. 후속 6함수 Scan 소요 756.707초와 보류 재개 구간별 소요 합 395.821초는 실행 시간이 겹쳤으므로 합산해 캠페인 Wall Time으로 표시하지 않는다. TinyProxy 블라인드 요약에는 논리적 LLM 호출 74회와 실행 상한 2,700초가 별도로 기록돼 있다.

저장된 명시적 안전 판단 6건은 `evidence/safe_assumption_inventory.json`과 원본 `result/vulnerabilityanalysis/20261010T1140Z-final-integration-audit/report.md`에서 각각 소스·Harness·기존 SP와 대조했다. 모두 현재 Harness에서 입력으로 반증할 적격 Invariant가 아니었다. 합성 Fixture의 Refinement·거리 Feedback·SP 상태별 회귀 테스트를 독립 OSS 탐지 성공으로 합산하지 않는다. **적격 Invariant 0건이므로 Hallucination Prevent 탐지 성능 비교는 현재 `BLOCKED_NO_ELIGIBLE_INVARIANT`**다.

## 재현 명령

프로젝트 루트에서 실행한다. 외부 LLM 호출 없이 개발 상태를 확인하는 명령:

```bash
python3 -m pip install -e ./vulnerabilityanalysis
PYTHONPATH=vulnerabilityanalysis/src python3 -m unittest discover -s vulnerabilityanalysis/tests -q
sha256sum -c vulnerabilityanalysis/baseline/SHA256SUMS
sha256sum vulnerabilityanalysis/baseline/libyaml_initial_seed.bin \
  vulnerabilityanalysis/baseline/libyaml_evaluation_config.yaml
gzip -dc vulnerabilityanalysis/baseline/libyaml_asan_fuzzer.gz | sha256sum
gzip -dc vulnerabilityanalysis/baseline/libyaml_asan_fuzzer.gz > /tmp/va-replay-libyaml-fuzzer
chmod 700 /tmp/va-replay-libyaml-fuzzer
/tmp/va-replay-libyaml-fuzzer -runs=1 vulnerabilityanalysis/baseline/libyaml_initial_seed.bin
```

마지막 명령은 **저장 입력 한 건의 Runtime smoke check**이며 전체 Scan·Fuzzing·취약점 탐지가 아니다. 압축 해제 후 SHA-256이 위 Binary 값과 일치해야 한다. 이 환경에서는 Exit 0, ASAN 오류 없음, 4,924개의 libFuzzer counter 로딩을 확인했다. 다른 OS·런타임 라이브러리에서는 바이너리 자체의 실행 가능 여부를 별도로 확인해야 한다.

소스에서 새 기능 동등 바이너리를 준비할 때에는 libyaml을 별도 Checkout에 고정한다. 아래 빌드는 이 환경에서 정상 입력 1건 실행까지 확인했지만, 원 캠페인 바이너리와 SHA-256 및 counter 수가 **다르다**. 두 파일의 Coverage 총량을 직접 비교하면 안 된다.

```bash
TARGET_REPO=/tmp/va-submission-libyaml
BUILD_DIR=/tmp/va-libyaml-rebuild
HARNESS=reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer/libyaml_scanner_fuzzer.c
if [ ! -d "$TARGET_REPO/.git" ]; then
  git clone https://github.com/yaml/libyaml.git "$TARGET_REPO"
fi
git -C "$TARGET_REPO" checkout --detach 90a56d4500aa1a1798514c5cb55c3ad4cb095f94
git -C "$TARGET_REPO" diff --quiet
cmake -S "$TARGET_REPO" -B "$BUILD_DIR" -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF \
  '-DCMAKE_C_FLAGS=-g -O0 -fsanitize=fuzzer-no-link,address'
cmake --build "$BUILD_DIR" --target yaml -j 4
clang -g -O0 -fsanitize=fuzzer,address -I "$TARGET_REPO/include" \
  "$HARNESS" "$BUILD_DIR/libyaml.a" -o /tmp/va-libyaml-rebuilt-fuzzer
/tmp/va-libyaml-rebuilt-fuzzer -runs=1 vulnerabilityanalysis/baseline/libyaml_initial_seed.bin
```

새 평가 Run을 **시작할 때만** 아래처럼 고정 Seed·Config를 전달한다. `phase1`과 `scan`은 새 `run_id`를 만든다. Codex 로그인이 필요하고 모델 출력·서비스 지연은 고정할 수 없다. `--max-functions 12`는 상한이며 2,400초 안에 항상 12개를 끝낸다는 뜻이 아니다. 미완료 함수는 기존 `--continue-from` 또는 `--retry-incomplete-from`으로 새 Run에서 이어야 한다.

```bash
RUN_DIR=$(PYTHONPATH=vulnerabilityanalysis/src python3 -m vulnerabilityanalysis phase1 \
  reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer \
  --target-repository "$TARGET_REPO")
PYTHONPATH=vulnerabilityanalysis/src python3 -m vulnerabilityanalysis scan "$RUN_DIR" \
  --target-repository "$TARGET_REPO" --binary /tmp/va-replay-libyaml-fuzzer \
  --config vulnerabilityanalysis/baseline/libyaml_evaluation_config.yaml \
  --initial-seed vulnerabilityanalysis/baseline/libyaml_initial_seed.bin \
  --hallucination-prevent off --provider codex --max-functions 12 \
  --max-candidates 2 --max-scan-seconds 2400 --runtime-sanitizer ASAN \
  --global-fuzzer-binary /tmp/va-replay-libyaml-fuzzer \
  --targeted-fuzzer-binary /tmp/va-replay-libyaml-fuzzer --targeted-fuzz-seconds 2
```

ON 비교는 별도의 fresh `phase1` Run·Corpus에서 **같은** Target·Harness·Seed·Config·모델·함수/SP/시간 예산을 사용한다. `--hallucination-prevent on --assertion-fuzz-seconds 1 --assertion-seed vulnerabilityanalysis/baseline/libyaml_initial_seed.bin` 외에 원본 Target을 바꾸지 않고 Source Copy를 빌드할 JSON 배열 `--assertion-build-command`와 `--assertion-run-command '["{binary}","{input}"]'`가 필요하다. 이 환경에서 확인한 빌드 인수는 `clang -g -O0 -fsanitize=fuzzer,address -DHAVE_CONFIG_H -DYAML_DECLARE_STATIC -I "$BUILD_DIR/include" -I "$TARGET_REPO/src" -I "$TARGET_REPO/include" '{source}' "$HARNESS" "$BUILD_DIR/libyaml.a" -o '{binary}'`다. JSON 배열을 구성할 때 각 인수와 실제 절대 경로를 분리해서 전달해야 한다. Source Copy 빌드와 정상 Seed 실행까지만 확인했으며, 적격 Safe Assumption이 없는 현 시점의 새 ON 실험은 실행하지 않았다. 장시간 ON/OFF 반복은 HP 탐지 효과를 측정하지 못한다. 공통 설정안은 원본 `20261010T1125Z-fbv2-hp-baseline-freeze/baseline.json`의 `future_matched_off_on`에 고정했고 **아직 실행하지 않았다**.

## 제출 범위와 남은 한계

이 폴더는 작은 제출 Bundle이다. `evidence/`는 각 결론의 대표 원본을 복사했지만, 원본 Run의 전체 LLM 응답, Runtime·GDB 로그, 나머지 PoC, Corpus 2,303개는 기존 `result/vulnerabilityanalysis/`에 **그대로 보존**했다. 전체 증거 검토가 필요하면 이 원본 Run을 별도 아카이브해야 한다. 대표 JSON만으로 원본의 모든 단계나 입력 재생을 증명한다고 주장하지 않는다. `result/` 경로와 `/tmp` 경로는 이 컴퓨터의 원래 저장 위치이며 다른 환경에서는 매핑해야 한다.

현재 확인된 필수 구현 오류는 Context 재분석 때 동일 Caller 본문을 새 Evidence로 다시 전달하던 1건이며 `scan.py:_fresh_analysis_context`와 `tests/test_context.py`에서 수정·회귀 검증했다. 추가 확정 코드 오류는 이번 저장된 결과·전체 테스트에서 발견되지 않았다. **이는 오류가 없다는 보장이 아니다.** FBv2 취분의 설계 경로는 기능 구현 완료로 정리할 수 있지만, 원본 FBv2와 완전히 동일한 운영 및 Hallucination Prevent의 독립 OSS 탐지 성능은 완료로 표시할 수 없다.

2026-10-10 회귀 실행: `python3 -m unittest discover -s vulnerabilityanalysis/tests -q`에서 **198개, 196 통과, 2 Skip, 0 Fail**. 이때 Git 미추적이었던 8개 테스트 파일(`test_evaluation_infrastructure.py`, `test_global_fuzz.py`, `test_guided_assertions.py`, `test_ollama_provider.py`, `test_parallel_fuzz.py`, `test_sp_feedback_lifecycle.py`, `test_tinyproxy_crash_pipeline_regression.py`, `test_worker_corpus.py`)도 Discovery에 포함됐다. 최종 제출 커밋에 8개 모두 포함됐는지 `git ls-files vulnerabilityanalysis/tests`로 확인한다.
