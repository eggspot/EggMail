#!/usr/bin/env bash
# Writes the GitHub Release notes to stdout: the curated CHANGELOG.md section of the version (a pre-release without its own section
# falls back to [Unreleased]) followed by how to pull and verify the image.
#
#   .github/scripts/release-notes.sh v1.4.2 ghcr.io/eggspot/eggmail sha256:... eggspot/EggMail release-assets > release-notes.md
# shellcheck disable=SC2016  # the backticks are Markdown, not command substitutions
set -euo pipefail

tag=${1:?usage: release-notes.sh <tag> <image> <index digest> <owner/repo> <assets directory>}
image=${2:?}
digest=${3:?}
repository=${4:?}
assets=${5:?}
here=$(cd "$(dirname "$0")" && pwd)

bash "$here/changelog-section.sh" "${tag#v}" 2>/dev/null || bash "$here/changelog-section.sh" Unreleased
printf '\n## Container image\n\n```sh\ndocker pull %s:%s\n```\n\n' "$image" "$tag"
printf 'Digests of the image index and of each platform (pin one of these in production):\n\n```\n'
cat "$assets/image-digests.txt"
printf '```\n\n'
printf 'Verify the build provenance with `gh attestation verify oci://%s@%s --repo %s`.\n\n' "$image" "$digest" "$repository"
printf 'The SBOMs (SPDX JSON, one per platform) and `checksums.txt` (SHA-256 of every attached file) are attached to this release.\n'
