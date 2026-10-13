#!/usr/bin/env bash
# Smoke test of a PUBLISHED image with plain `docker run` (SQLite backend, the default). Used by .github/workflows/release.yml and
# runnable by hand: deploy/smoke/image.sh ghcr.io/eggspot/eggmail@sha256:... 0.1.0
#
# Checks, in order (the first failure stops the script and prints the container log):
#   1. anonymous pull works (the package is public)
#   2. `--version` prints the expected version, `--healthcheck` fails cleanly when no server runs
#   3. `mta admin create` works against a fresh /data volume owned by the non-root user
#   4. the container becomes healthy by Docker's own HEALTHCHECK, and `docker exec /app/mta --healthcheck` succeeds
#   5. the startup warning for synchronous=OFF is logged
#   6. deploy/smoke/smoke.py: sign-in, domain verification, SMTP submission with AUTH, message in the API and delivered to a sink
set -euo pipefail

ref=${1:?usage: image.sh <image reference> <expected version x.y.z>}
expected=${2:?usage: image.sh <image reference> <expected version x.y.z>}
here=$(cd "$(dirname "$0")" && pwd)
host_ip=${SMOKE_HOST_IP:-$(ip route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')}
password=$(openssl rand -hex 12)Aa1
volume=eggmail-smoke-data
name=eggmail-smoke

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::container state and log"
    docker inspect --format '{{json .State}}' "$name" 2>/dev/null || true
    docker logs "$name" 2>&1 | tail -n 80 || true
    echo "::endgroup::"
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "-- anonymous pull of $ref"
anonymous_config=$(mktemp -d)
DOCKER_CONFIG=$anonymous_config docker pull --quiet "$ref" >/dev/null
rm -rf "$anonymous_config"
docker image inspect --format 'size {{.Size}} bytes, os/arch {{.Os}}/{{.Architecture}}' "$ref"

echo "-- --version"
actual=$(docker run --rm "$ref" --version)
[ "$actual" = "$expected" ] || { echo "::error::--version printed '$actual', expected '$expected'"; exit 1; }

echo "-- --healthcheck without a server must fail cleanly (exit 1), not crash"
set +e
docker run --rm "$ref" --healthcheck
code=$?
set -e
[ "$code" -eq 1 ] || { echo "::error::--healthcheck without a server exited $code, expected 1"; exit 1; }

echo "-- is 'mta' on PATH of the chiseled image? (a compose healthcheck of [\"CMD\", \"mta\", ...] only works if it is)"
docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$ref" | grep '^PATH=' || true
if docker run --rm --entrypoint mta "$ref" --version >/dev/null 2>&1; then
  echo "::notice::'mta' resolves on PATH in this image; the shipped compose files still use /app/mta"
else
  echo "::notice::'mta' is NOT on PATH (as expected for the chiseled image): healthchecks must use the absolute path /app/mta"
fi

echo "-- mta admin create on a fresh volume"
docker volume create "$volume" >/dev/null
docker run --rm -v "$volume:/data" -e MTA_ADMIN_PASSWORD="$password" "$ref" admin create --user smokeadmin

echo "-- start the server"
docker run -d --name "$name" -p 8080:8080 -p 5587:5587 -v "$volume:/data" \
  -e "Dns__Servers__0=${host_ip}:5300" -e Delivery__RemotePort=2500 -e Delivery__AllowPrivateMxAddresses=true \
  "$ref" >/dev/null

echo "-- wait for Docker's health status (HEALTHCHECK of the image)"
for i in $(seq 1 60); do
  health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$name")
  running=$(docker inspect --format '{{.State.Running}}' "$name")
  [ "$running" = "true" ] || { echo "::error::container exited"; exit 1; }
  [ "$health" = "healthy" ] && break
  [ "$health" = "none" ] && { echo "::error::the image has no HEALTHCHECK"; exit 1; }
  sleep 2
done
[ "$health" = "healthy" ] || { echo "::error::container health is '$health' after 120 s"; docker inspect --format '{{json .State.Health}}' "$name"; exit 1; }
echo "healthy after about $((i * 2)) s"

echo "-- docker exec /app/mta --healthcheck, --version"
docker exec "$name" /app/mta --healthcheck
docker exec "$name" /app/mta --version

echo "-- startup warning for synchronous=OFF"
docker logs "$name" 2>&1 | grep -i "synchronous=OFF" >/dev/null || { echo "::error::startup warning for synchronous=OFF missing"; exit 1; }

echo "-- end to end"
python3 "$here/smoke.py" --admin-user smokeadmin --admin-password "$password" --expect-backend sqlite --host-ip "$host_ip" --timeout 90
