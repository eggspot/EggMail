#!/usr/bin/env bash
# Tests changed-code.sh against throw-away repositories in a temporary directory (nothing else is touched). Run by the ci workflow, by hand:
#   .github/scripts/test-changed-code.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/changed-code.sh
work=$(mktemp -d "${TMPDIR:-/tmp}/changed-code.XXXXXX")
trap 'cd /; rm -rf "$work"' EXIT
failures=0

expect() { # expect <expected> <description> <actual>
  if [ "$1" = "$3" ]; then
    echo "ok   $2 -> $3"
  else
    echo "FAIL $2: expected $1, got $3"
    failures=$((failures + 1))
  fi
}

cd "$work"
git init -q -b main origin
cd origin
git config user.email test@example.invalid
git config user.name test
mkdir docs src
echo a >docs/a.md
echo x >src/x.cs
git add .
git commit -qm base
base=$(git rev-parse HEAD)

cd "$work"
git clone -q --depth=1 "file://$work/origin" pr
cd pr
git config user.email test@example.invalid
git config user.name test

# Only what the old workflow filter ignored: docs/**, *.md anywhere, .github/FUNDING.yml
echo b >>docs/a.md
echo r >README.md
echo y >docs/img.png
mkdir -p .github
echo f >.github/FUNDING.yml
git add .
git commit -qm docs
expect false "documentation only" "$("$script" "$base")"

echo c >>src/x.cs
git commit -qam code
expect true "documentation plus a source file" "$("$script" "$base")"

git reset -q --hard HEAD~1
mkdir -p .github/workflows
echo w >.github/workflows/ci.yml
git add .
git commit -qm workflow
expect true "a workflow file" "$("$script" "$base")"

expect true "no base given" "$("$script")"
expect true "a base that cannot be fetched" "$("$script" 0000000000000000000000000000000000000001)"

[ "$failures" -eq 0 ]
