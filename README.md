# Occulta

저장소 링크 하나로 퍼징 하네스 생성부터 취약점 확인·보고서까지 자동으로 돌리는 도구.
웹 콘솔(`occulta`)에서 풀스캔과 델타스캔(커밋 하나)을 고르고 진행 상황을 본다.

| 단계 | 디렉토리 | 하는 일 |
|---|---|---|
| Harness Create | `harnesscreator/` | 외부 입력 지점(Entry) 찾기·검증 → 입력 흐름(Context)별로 묶기 → 정상 입력(시드) 생성·측정 → libFuzzer 하네스 생성·검증 |
| Vulnerability Research | `fbaugur/` | 위협 모델 → 기능 영역(Direction) → 의심 지점(SP) 생성·검증 → PoV → 불변식 + 퍼징 → 크래시 확인 → 취약점 판정 → 보고서 |
| 콘솔 | `fbaugur/src/fbaugur/web/` | `occulta` 명령이 띄우는 로컬 웹 (http://localhost:7860) |
| 대상 준비 | `fbaugur/targets/<이름>/` | 저장소별 빌드·실행 방법 (`profile.json`, `prepare.sh`) |

## 설치 (WSL Ubuntu)

저장소가 비공개라 GitHub 로그인이 먼저 필요하다.

```bash
sudo apt-get install -y gh || true   # 없으면 install.sh 가 설치하지만 로그인은 먼저 해야 한다
gh auth login
curl -fsSL -H "Authorization: token $(gh auth token)" \
  https://raw.githubusercontent.com/servelt/SunrinInfosecProject2026/main/install.sh | bash
```

- 설치 위치: `~/.occulta/app` (소스), `~/.occulta/venv` (Python), 명령은 `~/.local/bin/occulta`
- 시스템 패키지(clang, LLVM 20, gcc, bear, autotools, gh)는 `apt` 로 설치한다. sudo 비밀번호를 물을 수 있다.
- LLM 은 Claude Code 를 쓴다: `npm install -g @anthropic-ai/claude-code` 후 `claude` 로 로그인.
- 코드는 `servelt/SunrinInfosecProject2026` 저장소의 `main` 브랜치에 있다. 다른 곳이면 `OCCULTA_REPO=owner/name`, `OCCULTA_BRANCH=이름` 을 붙인다.

## 사용

```bash
occulta            # 웹 콘솔 열기
occulta doctor     # 필요한 도구가 실제로 동작하는지 점검
occulta update     # 최신 릴리스(v* 태그)로 업데이트 (--main 이면 main 브랜치 최신 커밋)
occulta version
```

웹에서도 새 릴리스가 있으면 사이드바 아래에 업데이트 버튼이 뜬다. 진행 중인 스캔이 있으면 업데이트는 거부된다.

## 배포 (관리자)

```bash
echo 0.2.0 > VERSION && git commit -am "release 0.2.0"
git tag v0.2.0 && git push origin main v0.2.0
```

설치된 쪽은 `main` 브랜치에 있는 `v*` 태그만 따라간다. 태그를 찍기 전의 커밋은 배포되지 않는다.

## 지원 범위와 한계

- WSL Ubuntu 만 지원한다.
- 스캔할 수 있는 저장소는 `fbaugur/targets/` 에 준비 프로필이 있는 것뿐이다 (현재 tinyproxy). 빌드 방법을 자동으로 알아내는 기능은 아직 없다.
- 대상 프로그램이 고정 포트를 쓰면(tinyproxy: 8888) 스캔은 한 번에 하나만 돌린다.
