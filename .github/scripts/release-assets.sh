#!/usr/bin/env bash
# Collects the supply-chain assets of a pushed multi-platform image into a directory (the GitHub Release attaches them):
#
#   .github/scripts/release-assets.sh ghcr.io/eggspot/eggmail@sha256:... release-assets
#
#   image-digests.txt           the index digest and the digest of every platform manifest, as pullable references
#   sbom-<os>-<arch>.spdx.json  the SPDX SBOM that BuildKit attached to each platform (docker/build-push-action `sbom: true`)
#   checksums.txt               SHA-256 of every file above (sha256sum format)
set -euo pipefail

ref=${1:?usage: release-assets.sh <image@digest> <output directory>}
out=${2:?usage: release-assets.sh <image@digest> <output directory>}
image=${ref%@*}
index_digest=${ref#*@}
mkdir -p "$out"

echo "-- platform digests"
docker buildx imagetools inspect "$ref" --raw > "$out/.index.json"
{
  echo "index       ${image}@${index_digest}"
  jq -r --arg image "$image" '.manifests[] | select(.platform.os == "linux") | "\(.platform.os)/\(.platform.architecture)\(if .platform.variant then "/" + .platform.variant else "" end) \($image)@\(.digest)"' "$out/.index.json"
} > "$out/image-digests.txt"
rm "$out/.index.json"
cat "$out/image-digests.txt"
platforms=$(grep -c '^linux/' "$out/image-digests.txt" || true)
[ "$platforms" -ge 2 ] || { echo "::error::expected a linux/amd64 and a linux/arm64 manifest, found $platforms"; exit 1; }

echo "-- SBOMs"
docker buildx imagetools inspect "$ref" --format '{{ json .SBOM }}' > "$out/.sbom.json"
# One entry per platform for an index; a single manifest would have the SPDX document at the top level.
if jq -e 'has("SPDX")' "$out/.sbom.json" >/dev/null; then
  echo "::error::SBOM output is for a single platform, expected one per platform of the index"; exit 1
fi
for platform in $(jq -r 'keys[]' "$out/.sbom.json"); do
  case "$platform" in linux/*) ;; *) continue ;; esac
  file="$out/sbom-${platform//\//-}.spdx.json"
  jq --arg p "$platform" '.[$p].SPDX // empty' "$out/.sbom.json" > "$file"
  [ -s "$file" ] || { echo "::error::no SPDX document for $platform"; exit 1; }
  packages=$(jq '.packages | length' "$file")
  echo "$platform: $(du -h "$file" | cut -f1), $packages packages"
  [ "$packages" -gt 10 ] || { echo "::error::SBOM for $platform lists only $packages packages"; exit 1; }
done
rm "$out/.sbom.json"
[ "$(find "$out" -name 'sbom-*.spdx.json' | wc -l)" -ge 2 ] || { echo "::error::fewer than two SBOM files"; exit 1; }

echo "-- checksums"
(cd "$out" && sha256sum image-digests.txt sbom-*.spdx.json > checksums.txt && cat checksums.txt)
