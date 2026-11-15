# fbaugur — FuzzingBrain V2 기반 취약점 분석 + Code Augur 불변식 반증

HarnessCreator가 만든 하네스를 입력으로 받아 **FuzzingBrain V2**(FBv2) 원본 흐름으로
취약점을 찾고, 여기에 **Code Augur**의 불변식(assert) 반증 경로를 붙인다.

기존 팀 코드(`SunrinInfosecProject2026/fbv2_wip_v8`)를 대체하려고 새로 시작했다.
그 코드의 Live 실행 7회가 모두 `INCOMPLETE`로 끝난 원인은 취약점 분석이 아니라 FBv2 위에
덧붙인 **모델 호출 회계 게이트**였다(정상 상황을 "불확실"로 판정하고 캠페인 전체를 중단).
원본 FBv2는 모델 호출이 실패하면 그 항목만 버리고 계속 간다
(`worker/pipeline.py:377`, `agents/base.py:909`). 이 패키지는 원본 방식을 따른다.

- 참조 원본: `/mnt/c/harness/fuzzingbrainv2/FuzzingBrain-V2` (커밋 `0281e0b`)
- 논문: `reference/FuzzingBrainV2/FuzzingBrainV2.pdf`, `reference/CodeAugur/CodeAugur.pdf`

## 실행

```bash
cd /mnt/c/harness/vulnerabilityanalysis/fbaugur
PYTHONPATH=src python3 -m fbaugur.cli scan <HarnessCreator 실행 디렉터리> \
    --context ctx-803ca65377ec \
    --output fbaugur-runs --python /root/pwnenv/bin/python --max-hours 4

PYTHONPATH=src python3 -m fbaugur.cli report <fbaugur 실행 디렉터리>
```

`--delivery`를 생략하면 그 묶음에서 빌드된 하네스 전부(TCP·UDP)를 Worker로 만든다.
모델은 Claude 구독 사용량으로 돌고(API 키 없음) `--model-t1/t2/t3`으로 등급별로 바꾼다.
짧게 시험하려면 `--max-functions 2 --max-hours 0.2 --max-turns pov=14`처럼 줄인다.

## 워크플로우

```
[준비·선형]  1 Worker 나누기 → 2 위협 모델 → 3 Direction 나누기
                                         │
[동시·병렬]  ┌──────────────────────────┼───────────────────────────┐
  1 후보 줄기 (Worker)        2 불변식 줄기 (하네스)          3 퍼징 줄기 (Worker)
  1-1 후보 생성                                            3-1 시드 ◀─ FP시드·PoV입력·위반입력
  1-2 후보 검증 ──"안전"──▶ 2-1 불변식 기록
       │                2-2 빌드·검사 ──새 assert 빌드──▶ 3-2 전역 퍼저
       ▼                2-3 위반 분류 ◀───── 위반 ─────── 3-3 감시
  1-3 PoV 생성 ◀─버그 단서─┘   │너무 강함                      │크래시
       │크래시             2-4 다듬기 → 2-2                    │
       └──────────────▶ [마무리·선형] 4 크래시 확정·보고 ◀────┘
```

| 단계 | 구현 | 근거 |
|---|---|---|
| 1 Worker | 하네스 × sanitizer. 현재 빌드는 ASan+UBSan이 한 바이너리라 memcached는 Worker 2개 | FBv2 §3.3.2 |
| 2 위협 모델 | 공격자 입력·범위·신뢰 경계·보안상 중요한 상태·범위 밖. HarnessCreator가 측정한 사실을 입력으로 준다 | Code Augur §4.1 |
| 3 Direction | 기능 단위로 최대 5개, 시작·핵심 함수와 위험도 | FBv2 §3.4.1 |
| 1-1 후보 생성 | 함수 하나씩, 우선순위 4단계(핵심/일반 × 미분석/재분석). 저가 모델, 높은 재현율, 중복 병합 | FBv2 §3.4.2~3.4.3, Table 2 |
| 1-2 검증 | 도달성·보호장치·설명 정확성. FP는 100% 확신할 때만. **"안전"이면 그 이유를 불변식 재료로 넘긴다** | FBv2 §3.4.4 + Code Augur 알고리즘 1 |
| 1-3 PoV | 파이썬 생성기로 변형 3개씩, 실패하면 추적 켜기, 모든 입력은 퍼저로 | FBv2 §3.4.5 |
| 2-1 기록 | 안전 근거를 부작용 없는 C 식으로 원본 소스 해당 줄 앞에 삽입 | Code Augur §4.2 |
| 2-2 빌드 | 살아남은 불변식 전부를 한 빌드에 넣고 재빌드. 실패하면 식만 수리 | Code Augur 알고리즘 1 (9~12행) |
| 2-3 분류 | gdb로 위반 지점 값을 뽑아 REAL_ISSUE / TOO_STRONG / UNDECIDED | Code Augur §4.3 |
| 2-4 다듬기 | 항진식으로 넓히는 것 거부 | Code Augur REFINEINVARIANT |
| 3-1 시드 | HarnessCreator 정상 입력 + Direction별 시드 + FP 시드 + PoV 입력 + 위반 입력 | FBv2 §3.6 |
| 3-2 전역 퍼저 | 코퍼스를 유지한 채 새 assert 빌드로 교체. 불변식마다 신호 16칸(도달 1·위반 1·거리 14) | FBv2 §3.6 + Code Augur §4.3, §5 |
| 4 확정 | assert 없는 빌드에서 재현 → 하네스 결함 분리 → 상위 3프레임 중복 제거 → 리포트 | FBv2 §3.4.5, Code Augur §4.4 |

### 설계상 중요한 두 가지

- **불변식은 검증이 "안전"이라고 판정한 곳에서만 생긴다.** Code Augur 알고리즘 1이 그렇고,
  "왜 안전한지"라는 근거가 있어야 식을 쓸 수 있다. 가드가 있어도 그 가드가 지켜준다고 믿는
  관계를 식으로 박는다(논문의 Little CMS 사례 `fmt.channels == cs.channels`).
- **취약점 판정은 재현되는 크래시뿐이다.** 불변식 위반은 단서로만 쓴다. 위반이 REAL_ISSUE로
  분류되면 새 후보가 되어 보통의 PoV 경로를 거친다. 원본이 그 입력에서 안 터져도 버리지 않는다
  (Code Augur의 대표 사례가 "불일치 시점엔 멀쩡하고 나중에 터지는" 경우다).

### 오류 처리

실패한 에이전트·빌드·재생은 기록하고 그 항목만 버린다. 전체를 멈추는 경우는 세 가지뿐이다:
구독 사용량 한도, 로그인 만료, 하네스가 정상 입력조차 못 돌리는 경우.

## 모듈

| 모듈 | 줄 | 역할 |
|---|---|---|
| `store.py` | 168 | SQLite 상태. 한 행을 한 에이전트만 집어가는 claim |
| `config.py` | 82 | 역할별 모델 등급(T1/T2/T3)과 턴 상한 |
| `project.py` | 198 | HarnessCreator 산출물 읽기 |
| `index.py` | 60 | 도구 서버가 읽는 `index.json` 생성 |
| `runner.py` | 175 | 하네스 1회 실행(네임스페이스 격리), sanitizer 파싱, 위반 판별, gdb 상태 |
| `instrument.py` | 315 | 불변식 삽입 + 재빌드, 퍼저 신호 |
| `tools.py` | 761 | 에이전트 도구. FBv2 도구 이름·인자 그대로 + Code Augur 도구 |
| `mcp_server.py` | 115 | 도구를 MCP stdio로 `claude -p`에 노출 (에이전트마다 1프로세스) |
| `agent.py` | 185 | 에이전트 1회 실행, 턴·시간 제한, 실행 기록, 종료 조건 판별 |
| `fuzzing.py` | 265 | 전역 퍼저·후보별 퍼저, 빌드 교체, 산출물 분류 |
| `orchestrator.py` | 480 | 3개 병렬 줄기와 선형 준비·마무리 |
| `cli.py` | 160 | `scan` / `report` |
| `prompts/fbv2/` | — | FBv2 원본 프롬프트 **그대로 복사** (`prompts/fbv2/SOURCE.md` 참조) |
| `prompts/*.md` | — | 새로 쓴 프롬프트: 위협 모델, 불변식 기록·수리, 분류, 다듬기, 하네스 설명, 검증 부록 |

## 검증한 것

```bash
PYTHONPATH=src python3 -m pytest tests -q            # 16 통과, 5 건너뜀 (2초)
PYTHONPATH=src FBA_SLOW=1 python3 -m pytest tests -q # 21 통과 (실제 빌드 포함, 34초)
```

측정값은 memcached 실행 `runs-context-20261115-144424/20261115-144619-ae2c2bcb` 기준이다.

**불변식 메커니즘 (Code Augur 핵심)**
- `try_read_udp`의 `memmove(c->rbuf, c->rbuf + 8, res)` 앞에 불변식 2개 삽입 → 빌드 29초.
- 참인 식(`res <= c->rsize`)은 유지, 거짓 식(`res <= 0`)은 정상 UDP 입력 하나로 깨짐. 둘 다 도달 신호가 나온다.
- 전역 퍼저가 코퍼스(102개)를 유지한 채 assert 빌드로 교체되고, **초 단위로 거짓 불변식을 깼다.**
  위반 입력이 저장되고 퍼저는 재시작된다.
- 이미 분류한 불변식을 계속 모드로 두면 퍼징이 그 지점을 지나 계속된다(코퍼스 102 → 108).
- 위반 abort를 크래시로 세지 않는다. 같은 실행의 진짜 결함(SEGV·오버플로)은 크래시로 센다.
- gdb가 위반 지점의 값과 호출 스택을 뽑는다(`res = 4`, `c->rsize = 65536`,
  `try_read_udp ← drive_machine ← event_handler ← worker_libevent`).
- 식 검사: 대입·증감·부작용 함수 호출 거부, 삽입 위치가 문장 시작인지 확인,
  실제 clang으로 컴파일 검사(없는 필드 거부), **자료형이 결정하는 비교는 거부**(`buf[0] <= 255`).

**도구와 에이전트**
- 역할마다 도구 집합이 다르다(검증자만 `update_suspicious_point`, PoV만 `create_pov` 등).
- 코드 조회 도구가 실제 memcached 데이터를 돌려준다(원본 줄번호, 오타 시 유사 이름 제안,
  이 하네스에서 도달 불가한 호출자 표시).
- 후보 중복 병합이 동작한다(유사도 0.79 → 합치고 높은 점수 유지, FBv2 방식).
- 검증자가 `is_important=True`를 주면 `pov_guidance`를 요구하고, 다른 후보는 수정할 수 없다.
- 불변식 기록·수리·조회, 위반 분류(세 판정), 다듬기(항진식·동일식 거부)가 모두 동작한다.
- REAL_ISSUE 판정이 `pending_pov` 상태의 새 후보를 만들고 위반 입력을 증거로 달아준다.
- **실제 Claude(Haiku 5.5)가 도구를 써서 불변식을 기록했다**: `try_read_udp` 소스를 읽고
  `res + 8 <= c->rsize`를 커밋했다 — 바로 윗줄의 `res -= 8`을 고려한 식이다.

**준비 단계 (실제 Claude, 짧은 스캔)**
- 위협 모델 95초(13턴, 도구 12회), Direction 5개 39초(21턴), Direction별 시드 에이전트 5개.

## 전체 스캔을 실제로 돌린 결과

memcached UDP 하네스, 함수 8개 제한, 모델 전부 Sonnet 5.5, 219초:

```
functions:          analysed 8
suspicious_points:  rejected 2
invariants:         built 1
builds:             ok 1
agent_runs:         sp_generator 8, sp_verifier 2, invariant_recorder 2, seed 7, direction 1
fuzzer:             corpus 93 -> 150, coverage 4418 -> 5518
```

**Code Augur 루프가 실제 코드에서 끝까지 돌았다.**

1. 후보 생성이 `mcmc_tokenize`의 `line[len-2]` 접근에서 size_t 언더플로 후보 2개를 냈다.
2. 검증자가 13·16턴(도구 12·15회) 동안 호출 경로를 따라가 둘 다 FP로 판정하고,
   **왜 안전한지를 구체적으로 기록했다**: "`process_request`가 `cmdlen < 4`면 -1을 반환하므로
   `_mcmc_tokenize_meta`가 실행될 때 항상 `len >= 2`다."
3. FP 시드가 퍼저로 갔다(FBv2 §3.6).
4. 불변식 기록자가 그 관계를 `vendor/mcmc/mcmc.c:71`의 `len >= 2`로 커밋했다.
   두 후보가 같은 지점을 가리켰고 두 번째는 동일 식으로 중복 처리됐다.
5. 하네스를 40초에 재빌드했고(원본 소스는 그대로, 사본의 `line[len-2]` 바로 앞에 삽입),
   전역 퍼저가 코퍼스를 유지한 채 그 빌드로 교체됐다.
6. 정상 입력 25개 중 21개가 그 지점에 도달하고 위반은 0 — 참인 불변식이므로 살아남은 집합에 남고
   퍼저가 계속 깨려고 시도한다.

실행 중 발견해 고친 버그 4개(모두 회귀 테스트로 고정):

- `claim`이 `rowid`를 돌려주지 않아 함수 분석 레인이 조용히 죽었다(`SELECT *`는 rowid를 빼먹는다).
- 레인 하나가 예외로 죽어도 보이지 않았다 → 레인 가드 추가(기록 후 그 레인만 종료).
- `invariant_recorder` 역할이 없는 프롬프트 파일을 찾았다. 가드가 이걸 잡아내 실행은 계속됐다.
- 취소 시 퍼저 통계와 에이전트 기록이 남지 않았다.

관찰: SP 생성을 Haiku로 두면 후보를 거의 내지 않았다(함수 6개에서 1개). FBv2 원본은 이 역할에
중간 등급 모델을 쓰고, Sonnet으로 바꾸니 함수 8개에서 2개가 나왔다. 사용자 요청으로 T3에 두었지만
기본값은 재고할 만하다. 표본이 작아 결론은 아니다.

## LightFTP CVE-2017-1000218 — 알려진 취약점으로 채점한 결과

대상: LightFTP `7ea0a8f`(2017-04-20), 하네스 생성부터 끝까지 한 명령. 2026-11-16.

정답(실행 전에 직접 측정해둔 것): `writelogentry`(`ftpserv.c:383`)가 `char _text[512]`에 경계검사
없이 `strcat`하고, `ftp_client_thread`(`ftpserv.c:1790`)가 받은 명령줄 전체를 조건 없이 그 함수에
넘긴다. 최소 임계는 **473바이트 + CRLF**(하네스에 직접 먹여 이분탐색), 인증 불필요.

```
1단계 14.7분:  문맥 7개 -> ctx-cc74cc20a6b2/tcp, 시드 6개, 타겟 9/9 실행,
               하네스 BUILT_SEED_EQUIVALENT_NOT_QUALIFIED, 112.1 exec/s
2단계 39.5분:  directions 5, functions 56, sps 32(기각 24), invariants 21, crashes 23
확정:          crash-abdfd9d66a6b stack-buffer-overflow
```

**찾았다.** PoV가 `'A'×600 + CRLF`를 만들어 19초에 터뜨렸고, 주소를 `addr2line`으로 풀어
`__interceptor_strcat` → `writelogentry` → `ftp_client_thread`를 확인했다. 정답과 같다.
하네스 생성 시작부터 크래시 확정까지 19분. SP 설명은 임계를 "약 475바이트"로 어림했고
(접두사를 30바이트로 가정, 실제 39바이트) 구조와 경로는 정확했다.

이 실행에서 찾아 고친 것:

- `contexts/measured_harness.py`가 `HARNESSCREATOR_NATIVE_EXTRA_CFLAGS`를 덮어써서
  호출자의 `-fcommon`이 사라졌다. LightFTP는 헤더의 tentative definition(`g_cfg`, `g_log`)
  때문에 그 플래그 없이는 링크되지 않아 1단계가 두 번 빈손으로 끝났다. 같은 환경변수를 다루는
  `contexts/harness.py`는 기존 값을 보존한다 — 한쪽만 틀린 구현 오류였다.
- `select_units()`가 채널당 `next()`로 문맥 하나만 집었다. LightFTP는 `tcp/stream` 문맥이
  3개(제어 연결 `ftp_client_thread`, 데이터 연결 `stor_thread`/`append_thread`)였고,
  STOR/APPE로 업로드되는 바이트가 어떤 하네스에도 들어가지 않았다. 이제 전부 단위가 되고
  `--contexts-per-channel N`으로 상한만 둘 수 있다.
- `fuzz_after_drain_minutes`가 남은 예산을 무시했다. 분석 레인이 105분 중 19분에 비었는데
  20분 상한이 걸려 66분이 쓰이지 않았고, 빌드된 불변식 19개가 퍼저를 거의 못 거쳤다.
  기본값을 0(데드라인까지)으로 바꿨다.
- 심볼 없는 프레임(`binary+0xoffset`)이 버려져 모든 크래시의 서명이 libc 진입점
  `start_thread:442 | __clone3:81`로 같아졌다. 서로 다른 SP 4개의 크래시 21건이 전부 중복으로
  묶였다(이번엔 실제로 같은 버그여서 결론만 맞았다). `symbolize()`로 직접 풀어 서명에 넣는다.
  `ASAN_SYMBOLIZER_PATH`에 `addr2line`을 넘기던 것도 제거했다 — 새니타이저는 그 프로토콜을
  못 써서 "invalid path to external symbolizer"만 났다.
- **불변식 자체가 프로그램을 죽일 수 있었다.** 기록자가 `ftpMLSD`에
  `params[PATH_MAX*2-1] == 0 || ...`를 썼고 `params`는 파라미터 없는 모든 FTP 명령에서 NULL이라,
  단정식이 주소 `0x1fff`를 읽어 libFuzzer가 한 단위도 실행하기 전에 프로세스가 죽었다.
  컴파일·어휘·위치 검사는 전부 통과한 식이다. 이제 도달 측정이 안전성까지 측정한다(아래).

### 불변식 안전성 측정 (`_measure_reach`)

불변식은 관찰이어야 하므로, 프로그램이 받아들이는 입력에서 발화해서도 안 되고 터져서도 안 된다.
도달 측정이 시드와 코퍼스 표본을 흘려보낼 때 불변식 전부를 `FBA_PHI_CONTINUE`로 돌려
하나가 다른 전부를 가리지 않게 하고, 정상 입력에 발화하거나 폴트를 내는 불변식을
`withdrawn_unsafe`로 빼서 다음 빌드에 넣지 않는다.

계측이 원인인지는 추측하지 않는다 — 같은 입력을 **계측 없는 하네스**에 돌려 그쪽이 깨끗할 때만
불변식을 탓한다. 깨끗한 쪽도 터지면 프로그램의 버그이므로 손대지 않는다.

어느 불변식인지는 두 단계로 짚는다. 먼저 소스 줄: 빌더가 `line-map.json`에 어느 줄이 어느
단정식인지 기록하고, P'의 새니타이저 보고가 그 줄을 가리킨다(LightFTP에서 UBSan이
`ftpserv.c:1666: applying non-zero offset 8191 to null pointer`를 찍어 `phi 16`으로 확정됐다).
줄이 없는 맨 SEGV는 마지막 도달 표식으로 짚는다 — `fba_phi_reach(N)`이 식 평가 바로 앞에서
실행되므로 추적 모드의 마지막 표식이 평가 중이던 단정식이다. 둘 다 재현 테스트로 고정했다
(실제 LightFTP `phi 16` 식, 그리고 memcached 빌드에 심은 `*(volatile char *)0 == 0`).

## 아직 근거가 없는 것

- **불변식 경로로 버그를 찾은 사례는 아직 없다.** LightFTP에서 불변식 21개를 넣고 19개가
  도달했지만 위반은 2건(둘 다 `TOO_STRONG`, 즉 불변식이 과했던 것)이고 불변식에서 파생된 SP는
  0건이다. 찾은 버그는 전부 SP→PoV 경로의 성과다. 정답 CVE의 싱크(`writelogentry`)에는
  불변식이 걸리지도 않았다 — 그 SP는 검증 직후 PoV가 터져 불변식을 걸 이유가 없었다.
  Code Augur의 수치(발견의 36~41%가 불변식 경로)는 Sonnet 4.6, 과제당 4시간, $100 조건이다.
- 안전성 측정을 넣은 뒤 전체 실행을 다시 돌리지 않았다. 위 LightFTP 수치는 그 수정 전의 것이다.
- PoV 수락이 지목된 SP의 함수에 실제로 닿았는지 확인하지 않는다. LightFTP에서 `ftpRMD`·`ftpDELE`·
  `ftpLIST` SP의 PoV가 전부 상위 `ftp_client_thread:1790` 로깅에서 먼저 터졌고, 각 핸들러
  고유의 결함은 참인지 거짓인지 확인되지 않은 채 "PoV 성공"으로 기록됐다.
- UDP 하네스는 입력마다 20ms를 기다려 초당 41회뿐이다. 불변식 퍼징이 충분히 도는지 미측정.
- 크래시를 실제 memcached 데몬에 소켓으로 보내 재확인하는 단계(`--daemon-command`)는
  자리만 있고 구현되지 않았다.
- MSan Worker는 의존 라이브러리까지 MSan으로 다시 빌드해야 하므로 제외했다.
