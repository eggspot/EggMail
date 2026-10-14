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
printf 'Verify the build provenance of the image (it proves that this repository'"'"'s release workflow built the digest from this tag):\n\n'
printf '```sh\ngh attestation verify oci://%s@%s \\\n  --repo %s --source-ref refs/tags/%s \\\n  --signer-workflow %s/.github/workflows/release.yml\n```\n\n' "$image" "$digest" "$repository" "$tag" "$repository"
printf 'The SPDX SBOMs (one per platform) and `checksums.txt` are attached for convenience. They are **not** an independent integrity proof: they were uploaded by the same workflow as the release, so a checksum only detects a corrupted download. The integrity of the image is the registry digest plus the attestation above.\n'
