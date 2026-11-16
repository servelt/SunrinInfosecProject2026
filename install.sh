#!/usr/bin/env bash
# Occulta installer (WSL Ubuntu only).
#
#   gh auth login                       # once: the repository is private
#   curl -fsSL -H "Authorization: token $(gh auth token)" \
#     https://raw.githubusercontent.com/${OCCULTA_REPO:-servelt/occulta}/main/install.sh | bash
#
# Installs into ~/.occulta (app/ = git checkout, venv/ = Python packages) and puts the
# `occulta` command in ~/.local/bin.  Run it again to repair an installation.
set -euo pipefail

REPO="${OCCULTA_REPO:-servelt/occulta}"
ROOT="${OCCULTA_HOME:-$HOME/.occulta}"
APP="$ROOT/app"
VENV="$ROOT/venv"
LLVM_VERSION="${OCCULTA_LLVM:-20}"

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[31m[occulta] %s\033[0m\n' "$*" >&2; exit 1; }
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ---------------------------------------------------------------- platform
grep -qi microsoft /proc/version 2>/dev/null || fail "WSL 에서만 설치할 수 있어 (/proc/version 에 Microsoft 가 없음)."
command -v apt-get >/dev/null || fail "Ubuntu(apt) 배포판이 필요해."

# ---------------------------------------------------------------- system packages
say "시스템 패키지 설치"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq git curl wget ca-certificates gnupg lsb-release software-properties-common \
  build-essential clang lld llvm gdb python3 python3-venv python3-pip python3-dev \
  autoconf automake libtool pkg-config bear util-linux iproute2 binutils >/dev/null

if ! command -v "clang-$LLVM_VERSION" >/dev/null; then
  say "LLVM $LLVM_VERSION 설치 (MemorySanitizer 빌드용, apt.llvm.org)"
  tmp=$(mktemp); wget -qO "$tmp" https://apt.llvm.org/llvm.sh
  $SUDO bash "$tmp" "$LLVM_VERSION" >/dev/null; rm -f "$tmp"
fi
$SUDO apt-get install -y -qq "libclang-rt-$LLVM_VERSION-dev" >/dev/null 2>&1 || true

if ! command -v gh >/dev/null; then
  say "GitHub CLI 설치"
  $SUDO mkdir -p -m 755 /etc/apt/keyrings
  wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | $SUDO tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
  $SUDO chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | $SUDO tee /etc/apt/sources.list.d/github-cli.list >/dev/null
  $SUDO apt-get update -qq && $SUDO apt-get install -y -qq gh >/dev/null
fi

# ---------------------------------------------------------------- GitHub access (private repository)
gh auth status >/dev/null 2>&1 || fail "GitHub 로그인이 필요해: 'gh auth login' 실행 후 다시 설치해."
gh auth setup-git >/dev/null     # git fetch/clone use the gh token (also for 'occulta update')

# ---------------------------------------------------------------- source
mkdir -p "$ROOT"
if [ -d "$APP/.git" ]; then
  say "기존 설치 발견: $APP (업데이트는 'occulta update')"
else
  say "소스 받기: $REPO"
  git clone --quiet "https://github.com/$REPO.git" "$APP"
  latest=$(git -C "$APP" tag --list 'v*' --sort=-v:refname | head -1)
  [ -n "$latest" ] && git -C "$APP" checkout --quiet "$latest"
fi

# ---------------------------------------------------------------- Python
say "Python 환경 ($VENV)"
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -e "$APP/harnesscreator" -e "$APP/fbaugur"

# ---------------------------------------------------------------- command
mkdir -p "$HOME/.local/bin"
ln -sf "$APP/bin/occulta" "$HOME/.local/bin/occulta"
chmod +x "$APP/bin/"*
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] && ! grep -q '.local/bin' "$rc" && echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
done

# ---------------------------------------------------------------- Claude Code
if ! command -v claude >/dev/null; then
  echo
  echo "[occulta] Claude Code 가 없어. 설치하고 로그인해:"
  echo "    npm install -g @anthropic-ai/claude-code   # Node.js 18 이상"
  echo "    claude                                     # 처음 실행할 때 로그인"
fi

echo
say "설치 끝. 점검: occulta doctor   실행: occulta   업데이트: occulta update"
"$APP/bin/occulta" doctor || true
