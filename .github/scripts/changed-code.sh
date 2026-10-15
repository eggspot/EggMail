#!/usr/bin/env bash
# Prints "true" when a pull request changes anything besides documentation, otherwise "false" (used by the ci workflow).
#
#   .github/scripts/changed-code.sh <base commit sha>     run inside a checkout of the pull request's merge commit
#
# Documentation is what the old workflow-level filter ignored: everything under docs/, any *.md file and .github/FUNDING.yml. When anything
# is uncertain (no base given, the base cannot be fetched, the diff fails) the answer is "true": a doubt must run the tests, never skip them.
set -uo pipefail

base=${1:-}
if [ -z "$base" ]; then
  echo true
  exit 0
fi

# The checkout is shallow (depth 1); a tree diff needs only the base commit itself, not its history.
if ! git fetch --no-tags --depth=1 --quiet origin "$base" 2>/dev/null; then
  echo true
  exit 0
fi

if ! files=$(git diff --name-only "$base" HEAD 2>/dev/null); then
  echo true
  exit 0
fi

while IFS= read -r file; do
  [ -z "$file" ] && continue
  case "$file" in
    docs/* | *.md | .github/FUNDING.yml) ;;
    *)
      echo true
      exit 0
      ;;
  esac
done <<<"$files"

echo false
