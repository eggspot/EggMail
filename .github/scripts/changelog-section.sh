#!/usr/bin/env bash
# Prints the body of one release section of CHANGELOG.md (Keep a Changelog format) without its heading.
#
#   .github/scripts/changelog-section.sh 1.4.2            the "## [1.4.2] - date" section
#   .github/scripts/changelog-section.sh Unreleased       the "## [Unreleased]" section
#   .github/scripts/changelog-section.sh 1.4.2 other.md   another file
#
# Exits 1 (and prints nothing) when the section does not exist or is empty, so a release cannot go out without curated notes.
set -euo pipefail

version=${1:?usage: changelog-section.sh <version|Unreleased> [file]}
file=${2:-CHANGELOG.md}

body=$(awk -v wanted="$version" '
  /^## \[/ {
    if (inside) { exit }
    name = $0
    sub(/^## \[/, "", name)
    sub(/\].*$/, "", name)
    if (name == wanted) { inside = 1; next }
  }
  inside && /^\[[^]]+\]: / { next }   # link reference definitions at the end of the file belong to no section
  inside {
    lines[++count] = $0
  }
  END {
    first = 1
    while (first <= count && lines[first] ~ /^[[:space:]]*$/) { first++ }
    last = count
    while (last >= first && lines[last] ~ /^[[:space:]]*$/) { last-- }
    for (i = first; i <= last; i++) { print lines[i] }
  }
' "$file")

if [ -z "$body" ]; then
  echo "CHANGELOG section '$version' is missing or empty in $file" >&2
  exit 1
fi
printf '%s\n' "$body"
