#!/usr/bin/env bash
# Publish a release that installed copies will offer as an update.
#
#   bash release.sh            # next patch version (0.1.5 -> 0.1.6)
#   bash release.sh 0.2.0      # an explicit version
#
# Commits VERSION, tags vX.Y.Z on that commit, pushes main and the tag together (--atomic: both or
# neither), then asks GitHub whether the tag is really there.  A plain `git push` sends no tags,
# which is how earlier releases reached main without their tag.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

[ -z "$(git status --porcelain)" ] || { echo "커밋 안 된 변경이 있어. 먼저 커밋하거나 되돌려:"; git status --short; exit 1; }
current=$(cat VERSION)
if [ $# -ge 1 ]; then next=$1; else IFS=. read -r a b c <<<"$current"; next="$a.$b.$((c + 1))"; fi
tag="v$next"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  if [ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ] || [ "$current" != "$next" ]; then
    echo "$tag 태그가 이미 다른 커밋에 있어 ($(git log --oneline -1 "$tag")). 다른 버전을 쓰거나 'git tag -d $tag' 후 다시 해."
    exit 1
  fi
  echo "$tag 는 이미 지금 커밋에 있어: push 만 다시 함"
else
  if [ "$current" != "$next" ]; then
    echo "$next" > VERSION
    git commit -qm "release $next" VERSION
  fi
  git tag "$tag"
fi

git push --atomic origin main "$tag"
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
  echo "올라감: main 과 $tag ($(git log --oneline -1 "$tag"))"
else
  echo "main 은 push 했지만 GitHub 에서 $tag 가 안 보여. 'git push origin $tag' 로 다시 올려."
  exit 1
fi
