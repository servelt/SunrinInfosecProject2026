# FuzzingBrain V2 연결 코드 검토 묶음

이 디렉터리는 팀 저장소의 `vulnerabilityanalysis/` 범위에서 **우리가 작성한 FBv2 연결 코드와 테스트**를 검토할 수 있게 묶은 것이다. 원본 FBv2 전체 소스 복사본은 아니다. 이 묶음만으로 md4c 시연을 재실행할 수 있다고 주장하지 않는다.

## 원본과 변경 범위

- 원본: `https://github.com/o2lab/FuzzingBrain-V2`의 커밋 `0281e0bc5348dddb6e4cdb4824f79ae5a60d1de3`.
- 원본의 `fuzzingbrain/`, `requirements.txt`, 원본 테스트 2개에 적용한 23개 파일의 로컬 변경 패치는 별도로 보존한다(SHA-256 `0622c766c9b1624a49ce28f43062af97519c09b62d4ff226d9c422e9d3db4992`). 원본 커밋의 깨끗한 index에 `git apply --cached --check`를 통과했지만, 원본 LICENSE가 확인되지 않아 **이 Git 게시 후보에서는 패치 원문을 제외**했다.
- `devtools/`: 추가한 실행·모델 장부·Global·HP·제품 Runtime 연결 스크립트 27개.
- `tests/`: 추가한 Provider-free 연결·중단·증거 회귀 테스트 34개. 원본에서 수정한 테스트 2개는 위 패치에 포함된다.
- `evaluation_tools/`: md4c Global 물리 장부·실행 경로의 개발용 소스 6개와 해당 테스트 4개. 미게시 Blind 실행기를 import하는 테스트와 원시 영수증은 제외했다.

현재 로컬 FBv2 체크아웃의 `origin`은 **o2lab 원본 저장소**이므로 그 원격에는 Push하지 않는다. 체크아웃과 공식 저장소 파일 목록에서 LICENSE 파일을 찾지 못했다. 원본 전체 소스를 팀 저장소에 복사하지 않은 이유 중 하나이며, 패치·연결 코드의 팀 공유 범위도 게시 전에 확인해야 한다.

## 로컬 적용 방법과 남은 의존성

원본 커밋을 별도 디렉터리에 체크아웃한 뒤, 별도로 제공받은 **게시 허가가 확인된 패치**를 적용하고 `devtools/`, `tests/`를 같은 상대 경로에 복사하면 현재 FBv2 연결 소스와 테스트를 재구성할 수 있다. **패치와 평가도구 의존성이 없으면 독립 재구성이 불가능하며, 원본 체크아웃에 이미 있는 변경이나 증거를 덮어쓰지 않는다.**

```bash
git -C <clean-fbv2-checkout> checkout 0281e0bc5348dddb6e4cdb4824f79ae5a60d1de3
git -C <clean-fbv2-checkout> apply --check <authorized-local-patch>
git -C <clean-fbv2-checkout> apply <authorized-local-patch>
cp -a <this-dir>/devtools/. <clean-fbv2-checkout>/devtools/
cp -a <this-dir>/tests/. <clean-fbv2-checkout>/tests/
```

실제 md4c 시연에는 추가로 공식 Harness 계약·소스·원본 ASan 바이너리·정상 Seed, 자격 사양과 보존된 통제 입력이 필요하다. 현재 `devtools/md4c_original_queue_controlled_gate_20261102.py`의 절대 경로와 평가도구 의존성은 개발 PC 기준이다. 함께 제공한 `evaluation_tools/dev_global_campaign.py`는 게시 대상에서 제외한 `blind2_runner_draft.py`의 프로세스 가드 함수 2개를 가져오므로, Blind 자료를 제외한 이 Git 묶음만으로 재현할 수 없다. 이 미해결 의존성을 [멘토 인계 문서](../docs/mentor_handoff_20261102.md)에 명시한다.

과거 146바이트 OOB 통제 입력, 새 121바이트 퍼저 입력, 수동 UAF PoC, 원시 ASan 로그, 모델 원문·원격 요청 이벤트, 바이너리, Corpus는 이 코드 묶음에 포함하지 않았다. 실행 결과의 해시·판정은 인계 문서에 있고, 원시 증거는 별도 접근·민감정보 검토가 필요하다.

## 상태 구분

- 실제 모델 Direction·SP 후보 생성: 확인.
- 실제 모델 Verifier→PoV: `cyberPolicy`/원격 상태 문제로 미완료.
- Provider-free 원본 대기열과 통제 PoV의 제품 Runtime·Gate: 실행 확인. 모델 자동 발견 아님.
- 물리 Global Fuzzing과 별도 무힌트 121바이트 OOB: 실제 공개 md4c에서 관측. 인과 증거 부족으로 `PENDING_CAUSAL_EVIDENCE`.
- HP: 수동 SAFE 물리 실행 확인, 실제 모델 SAFE의 자동 물리 완주는 미확인.

11월 7일에는 이 서로 다른 실행을 한 번의 완전 자동 모델 탐색으로 합쳐 보고하지 않는다.
