#!/usr/bin/env bash
# Prints "true" when a pull request changes anything besides documentation, otherwise "false" (used by the ci workflow).
#
#   .github/scripts/changed-code.sh [<base commit sha>]     run inside a checkout of the pull request's merge commit (fetch-depth 2)
#
# Documentation is what the old workflow-level filter ignored: everything under docs/, any *.md file and .github/FUNDING.yml, except
# docs/operations.md, which tests read (ConfigurationDocumentationTests and MetricsDocumentationTests compare it with the code), so a change to it
# runs them. When anything is uncertain (not a pull request event, no usable parent, the diff fails) the answer is "true": a doubt must run the
# tests, never skip them.
#
# What is diffed: the pull request's own changes. The checkout of a pull request is a merge commit whose first parent is the tip of the base
# branch at the time, so `HEAD^1..HEAD` is exactly the pull request and never includes what other people merged into the base since it branched
# (a diff against the base sha from the event payload could, and a documentation-only pull request would then pay for unrelated code changes).
# Without a merge commit (a test, a checkout of a single commit) the base sha argument is fetched and compared instead.
#
# Renames are not detected (`--no-renames`): a file moved from src/ into docs/ lists both paths, so the removal of source code is seen.
set -uo pipefail

if [ "${GITHUB_EVENT_NAME:-pull_request}" != "pull_request" ]; then
  echo true
  exit 0
fi

from=
if [ "$(git rev-list --parents -n 1 HEAD 2>/dev/null | wc -w)" -ge 3 ]; then
  from=HEAD^1
else
  base=${1:-}
  if [ -z "$base" ]; then
    echo true
    exit 0
  fi

  # A tree diff needs only the base commit itself, not its history.
  if ! git fetch --no-tags --depth=1 --quiet origin "$base" 2>/dev/null; then
    echo true
    exit 0
  fi

  from=$base
fi

if ! files=$(git diff --no-renames --name-only "$from" HEAD 2>/dev/null); then
  echo true
  exit 0
fi

while IFS= read -r file; do
  [ -z "$file" ] && continue
  case "$file" in
    docs/operations.md) echo true; exit 0 ;;
    docs/* | *.md | .github/FUNDING.yml) ;;
    *)
      echo true
      exit 0
      ;;
  esac
done <<<"$files"

echo false
