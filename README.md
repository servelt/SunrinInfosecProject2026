# 하네스 자동 생성 + 취약점 분석 파이프라인

소스 트리 하나를 받아서 **퍼징 하네스를 만들고, 그 하네스로 취약점을 찾고, PoV까지 만들어
검증**하는 파이프라인. 명령 하나로 끝까지 돈다.

LightFTP 7ea0a8f 에 걸어 **CVE-2017-1000218 을 19분에 스스로 찾아냈다** (하네스 생성 시작부터
크래시 확정까지). 아래 "검증된 것"에 측정값과 재현 방법이 있다.

## 구성

| 디렉터리 | 역할 |
|---|---|
| `harnesscreator/` | 1단계. 소스에서 외부 입력 지점(Entry)을 찾고, 같은 자원·해석함수를 쓰는 Entry들을 **입력 문맥**으로 묶고, 커버리지 빌드에서 **실제로 실행되는 정상 입력(시드)** 을 만들고, 문맥별로 하네스를 생성·빌드·검증한다 |
| `fbaugur/` | 2단계. FuzzingBrain V2 기반 취약점 분석(위협모델 → 공격방향 → 의심지점 생성·검증 → PoV)에 Code Augur 의 **불변식 반증**을 얹었다 |
| `target-lightftp/` | 채점용 대상. LightFTP 7ea0a8f 원본 소스와 빌드 스크립트 |
| `run-lightftp.sh` | 위 전체를 한 번에 돌리는 명령 |

## 바로 쓰기

```bash
# 1. 대상 빌드 (gcov 빌드, 스레드 추적 빌드, compile_commands.json 생성)
bash target-lightftp/build.sh

# 2. 전체 실행 (기본 3시간)
bash run-lightftp.sh 3
```

필요한 것: `clang`, `gcc`, `gcov`, `gdb`, `unshare`(root), `claude` CLI, 파이썬 3.10+.
파이썬 경로는 `PY=` 로, 출력 위치는 `OUT=` 으로 바꿀 수 있다.

```bash
PY=/usr/bin/python3 OUT=/tmp/runs bash run-lightftp.sh 3
```

### 다른 대상에 걸기

`run-lightftp.sh` 를 복사해서 아래만 바꾸면 된다.

- `--coverage-root` / `--coverage-command` — `--coverage` 로 빌드한 원본과 그걸 띄우는 명령.
  **종료 시 `__gcov_dump()` 를 부르는 핸들러가 필요하다**(`target-lightftp/fba_gcov_flush.c` 참고).
  데몬에 종료 핸들러가 없으면 `.gcda` 가 아예 안 생긴다. gcov 빌드는 **gcc 로** 해라 —
  clang-14 가 내는 형식(`408*`)은 시스템 `gcov` 가 읽지 못한다.
- `--port` / `--channel` — 데몬이 듣는 포트와 채널(`tcp`/`udp`/`stdin`/`file`)
- `--analysis-compile-database` — `compile_commands.json`
- `--native-extra-cflags=...` — 원본 빌드에 필요한 추가 플래그. 오래된 C 코드는
  `-fcommon` 이 필요할 수 있다(헤더의 tentative definition)

2단계만 따로 돌리려면:

```bash
cd fbaugur
PYTHONPATH=src python -m fbaugur.cli scan <하네스_run_디렉터리> \
  --context ctx-xxxxxxxx --delivery stream \
  --harnesscreator-src ../harnesscreator/src
```

`--harnesscreator-src` 를 꼭 넘겨라. 기본값이 개발 당시의 절대 경로로 박혀 있다.

상태를 보려면 `python -m fbaugur.cli report <scan_디렉터리>`.

## 어떻게 도는가

```
1단계 (harnesscreator)
  Entry 발견·검증      외부 입력이 처음 들어오는 함수를 찾고, 공격자 통제 가능성을 검증
  입력 문맥 묶음        같은 자원 종류·해석 함수를 쓰는 Entry 를 하나로 묶는다
                       (해석 함수를 찾을 때 호출자 쪽으로 거슬러 올라간다)
  정상 입력(시드) 생성   커버리지 빌드에 실제로 흘려보내 gcov 로 실행 여부를 확인한 것만 채택
  하네스 생성·검증      문맥×delivery 마다 하나. 시드 재생과 시드 등가성으로 채점

2단계 (fbaugur)
  위협 모델 -> 공격 방향 5개 -> 함수 풀
  의심지점(SP) 생성 -> 검증(FP 기각) -> PoV 생성 -> 크래시 확정·보고
  동시에: 검증된 관계를 불변식으로 소스 사본에 삽입 -> 재빌드 -> 퍼저가 반증 시도
         위반이 나오면 triage 가 판정(진짜 버그 / 불변식이 과함) -> 과하면 정제
```

1단계와 2단계는 각자 독립적으로도 돌아간다. 2단계는 하네스가 있으면 어디서 왔든 쓸 수 있다.

## 검증된 것 (LightFTP CVE-2017-1000218, 2026-11-16)

실행 전에 정답을 직접 측정해 두고 채점했다.

**정답**: `writelogentry()`(`ftpserv.c:383`)가 `char _text[512]` 에 경계검사 없이 `strcat` 하고,
`ftp_client_thread()`(`ftpserv.c:1790`)가 `recvcmd()` 직후 **받은 명령줄 전체를 조건 없이**
그 함수로 넘긴다. 최소 임계는 **473바이트 + CRLF**(하네스에 직접 먹여 이분탐색으로 측정),
인증 불필요.

**결과**
```
1단계 14.7분   문맥 7개 -> 선택 ctx-cc74cc20a6b2/tcp, 시드 6개, 타겟 9/9 실행
               하네스 BUILT_SEED_EQUIVALENT_NOT_QUALIFIED, 112.1 exec/s
2단계 39.5분   방향 5, 함수 56, SP 32(기각 24), 불변식 21, 크래시 23
확정           crash-abdfd9d66a6b stack-buffer-overflow
```

PoV 가 `'A'×600 + CRLF` 를 만들어 **19초**에 터뜨렸다. 주소를 `addr2line` 으로 풀어
`__interceptor_strcat` → `writelogentry` → `ftp_client_thread` 를 확인했고 정답과 같다.
SP 설명은 임계를 "약 475바이트"로 어림했다(접두사를 30바이트로 가정, 실제 39바이트).
구조와 경로는 정확했다.

`NOTQUALIFIED` 는 실패가 아니다. 1단계 생성기 모듈이 낼 수 있는 최고 등급이고
(`QUALIFIED` 는 퍼징과 크래시 귀속이 있어야 붙는다), 그 안에는 빌드 성공, 시드 6개 전부
결함 없이 재생, 시드 등가성 통과(`missing_in_harness: 0`), 독립 리뷰 FAIL 0 이 들어 있다.

## 솔직한 한계

- **불변식 경로로 버그를 찾은 사례는 아직 없다.** 위 실행에서 불변식 21개를 넣고 19개가
  도달했지만 위반은 2건이고 둘 다 `TOO_STRONG`(불변식이 과했던 것)이었다. 불변식에서 파생된
  의심지점은 0건. 찾은 버그는 전부 SP→PoV 경로의 성과다. 정답 CVE 의 싱크에는 불변식이
  걸리지도 않았다 — 그 SP 는 검증 직후 PoV 가 터져서 불변식을 걸 이유가 없었다.
- **크래시 서명이 서로 다른 버그를 구분하지 못한다.** 이 환경에 `llvm-symbolizer` 가 없어
  프로그램 프레임이 `binary+offset` 으로 오고, `addr2line` 은 함수 이름은 주지만 이 빌드의
  DWARF 에서 file:line 을 못 준다. 그런데 서명을 만드는 필터가 `file` 이 있는 프레임만
  남기므로 결국 libc 진입점(`start_thread:442 | __clone3:81`)만 서명이 된다. 결과적으로
  **이 프로그램의 모든 크래시가 같은 서명을 갖고 중복으로 묶인다.** 위 실행에서는 묶인
  21건이 실제로 같은 버그여서 결론만 맞았다. 실제 버그 수를 세려면 저장된 PoV 입력을
  꺼내 직접 심볼화해야 한다. `llvm-symbolizer` 를 설치하면 바로 해결된다.
- **PoV 수락이 지목된 SP 의 함수에 실제로 닿았는지 확인하지 않는다.** LightFTP 에서
  `ftpRMD`/`ftpDELE`/`ftpLIST` SP 의 PoV 가 전부 상위 `ftp_client_thread:1790` 로깅에서
  먼저 터졌고, 각 핸들러 고유의 결함은 참·거짓 미확인 상태로 "PoV 성공" 으로 기록됐다.
- **2단계 문맥 순서가 우선순위가 아니다.** `built_harnesses()` 가 디렉터리 glob 순서로
  돌려주므로, 예산이 부족하면 1순위 문맥이 분석되지 않을 수 있다.
- Worker 에 sanitizer 차원이 없다(ASan+UBSan 한 조합). MSan 은 의존 라이브러리까지 MSan 으로
  다시 빌드해야 해서 제외했다.
- 확정 크래시를 실제 데몬에 소켓으로 보내 재확인하는 단계(`--daemon-command`)는 자리만 있고
  구현되지 않았다.
- `fbaugur scan --resume` 은 한 번도 검증하지 않았다.
- `harnesscreator/tests` 중 `test_scenario_workflow.py` 와 `test_universal_executor.py` 의
  41건이 실패한다. 은퇴한 구 Action/scenario 워크플로우가 의도적으로 예외를 던지는 것이고
  (`"syntax-branch Action discovery is retired"`), 현재 쓰는 문맥 워크플로우와 무관하다.

## 테스트

```bash
# 갓 클론한 상태 (하네스 run 이 아직 없음)
cd fbaugur && PYTHONPATH=src python -m pytest tests/ -q
#   -> 16 passed, 19 skipped

# 하네스 run 이 하나 생긴 뒤 (실제 빌드·실행까지 전부)
cd fbaugur && FBA_SLOW=1 FBA_HC_RUN=<run_디렉터리> PYTHONPATH=src python -m pytest tests/ -q
#   -> 35 passed

cd harnesscreator && PYTHONPATH=src python -m pytest \
    tests/test_context_pipeline.py tests/test_context_grouping.py -q
#   -> 19 passed
```

19개가 건너뛰어지는 건 정상이다. 그 테스트들은 하네스 소스·시드·빌드 계획을 빌려올 **기존
HarnessCreator run 디렉터리**가 있어야 돌아가고, 갓 클론한 트리에는 그게 없다. `run-lightftp.sh`
를 한 번 돌리면 `runs/*/harness/*` 가 생기므로 그걸 `FBA_HC_RUN` 으로 넘기면 된다.

자세한 설계와 측정값은 `fbaugur/README.md`, `harnesscreator/README.md` 에 있다.
