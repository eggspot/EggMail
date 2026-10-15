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

new_repo() { # new_repo <name>: a repository with docs/a.md, docs/operations.md and src/x.cs on main
  cd "$work"
  git init -q -b main "$1"
  cd "$1"
  git config user.email test@example.invalid
  git config user.name test
  mkdir docs src
  echo a >docs/a.md
  echo o >docs/operations.md
  echo x >src/x.cs
  git add .
  git commit -qm base
}

# ---- single commit on top of a base (no merge commit): the base sha argument is used
new_repo origin
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

echo c >>docs/operations.md
git commit -qam "operations guide"
expect true "docs/operations.md is read by tests, so it counts as code" "$("$script" "$base")"
git reset -q --hard HEAD~1

echo c >>src/x.cs
git commit -qam code
expect true "documentation plus a source file" "$("$script" "$base")"
git reset -q --hard HEAD~1

mkdir -p .github/workflows
echo w >.github/workflows/ci.yml
git add .
git commit -qm workflow
expect true "a workflow file" "$("$script" "$base")"
git reset -q --hard HEAD~1

git mv src/x.cs docs/x.md
git commit -qm "move source into docs"
expect true "a source file renamed into docs/ (the removal of code is seen)" "$("$script" "$base")"
git reset -q --hard HEAD~1

expect true "no base given" "$("$script")"
expect true "a base that cannot be fetched" "$("$script" 0000000000000000000000000000000000000001)"
expect true "a push is never skipped" "$(GITHUB_EVENT_NAME=push "$script" "$base")"

# ---- merge commit (what actions/checkout gives a pull request): the pull request's own changes only
new_repo merged
git switch -q -c feature
echo b >>docs/a.md
git commit -qam "docs only"
git switch -q main
echo changed >>src/x.cs          # somebody else merges code into main after the branch was cut
git commit -qam "code on main"
git switch -q -c merge-ref
git merge -q --no-ff -m "merge of the pull request" feature
expect false "documentation-only pull request whose base moved on with code" "$("$script" 0000000000000000000000000000000000000001)"

git switch -q feature
echo y >src/y.cs
git add src/y.cs
git commit -qm "code in the pull request"
git switch -q main
git switch -q -c merge-ref2
git merge -q --no-ff -m "merge of the pull request" feature
expect true "a pull request with code, merged" "$("$script" 0000000000000000000000000000000000000001)"

[ "$failures" -eq 0 ]
