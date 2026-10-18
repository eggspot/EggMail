#!/usr/bin/env bash
# Smoke test of the shipped Compose files (deploy/compose) against a published image. Linux with Docker Compose v2 (the host address for the
# DNS stub is found with `ip route`; set SMOKE_HOST_IP to override).
#
#   deploy/smoke/compose.sh postgres <image reference>   compose.postgres.yaml: PostgreSQL 17 + EggMail, full end-to-end smoke test; the administrator
#                                                          password is given in EGGMAIL_ADMIN_PASSWORD (the chosen-password path)
#   deploy/smoke/compose.sh sqlite   <image reference>   compose.yaml: starts, becomes healthy, signs in with the GENERATED administrator password
#                                                          taken from the log (the one-time notice must be there exactly once)
#   deploy/smoke/compose.sh unbound  <image reference>   compose.yaml + compose.unbound.yaml: the resolver validates DNSSEC (AD bit)
#
# Only the postgres variant runs the full end-to-end test (it needs the test-only override that points the instance at the DNS stub
# and the sink); the other two prove that the file starts healthy and that the administrator can sign in.
#
# Safety: every compose command runs with `-p eggmail-smoke-<pid>` (the -p flag beats the `name:` of the files), so `down -v` at the end can
# only remove this run's own containers, network and volumes, never those of a real deployment of the same files. The published ports
# (587, 465, 2525, 8443, and 8080 on the loopback) are fixed by the files, so do not run this on a host where they are in use.
# The files are copied to a temporary directory first, so the test uses them exactly as a user would and leaves the repository clean.
set -euo pipefail

variant=${1:?usage: compose.sh <postgres|sqlite|unbound> <image reference>}
ref=${2:?usage: compose.sh <postgres|sqlite|unbound> <image reference>}
here=$(cd "$(dirname "$0")" && pwd)
project=eggmail-smoke-$$
work=$(mktemp -d)
cp -R "$here/../compose/." "$work/"
cp "$here/compose.smoke.yaml" "$work/"

export EGGMAIL_IMAGE=$ref
export EGGMAIL_HOSTNAME=smoke.eggmail.test
EGGMAIL_DB_PASSWORD=$(openssl rand -hex 12)
export EGGMAIL_DB_PASSWORD
SMOKE_HOST_IP=${SMOKE_HOST_IP:-}
if [ -z "$SMOKE_HOST_IP" ]; then
  command -v ip >/dev/null || { echo "this script needs Linux (the 'ip' command) or SMOKE_HOST_IP=<address of this host>"; exit 2; }
  SMOKE_HOST_IP=$(ip route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
fi
export SMOKE_HOST_IP
admin_password=$(openssl rand -hex 12)Aa1
# Only the postgres variant chooses the administrator password; the other two leave EGGMAIL_ADMIN_PASSWORD empty, so the server generates one.
if [ "$variant" = postgres ]; then export EGGMAIL_ADMIN_PASSWORD=$admin_password; fi

case "$variant" in
  postgres) files=(-f compose.postgres.yaml -f compose.smoke.yaml) ;;
  sqlite)   files=(-f compose.yaml) ;;
  unbound)  files=(-f compose.yaml -f compose.unbound.yaml) ;;
  *) echo "unknown variant $variant"; exit 64 ;;
esac

dc() { docker compose -p "$project" "${files[@]}" "$@"; }

cd "$work"
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::compose state and logs"
    dc ps -a || true
    dc logs --no-color --tail 80 || true
    echo "::endgroup::"
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  cd /
  rm -rf "$work"
}
trap cleanup EXIT

echo "-- docker compose config (${variant})"
dc config --quiet

# Docker Hub rate limits shared runner addresses: retry the pulls instead of failing the run on a transient 429 or network error.
echo "-- pull the images (up to 3 attempts)"
for attempt in 1 2 3; do
  if dc pull --quiet; then break; fi
  [ "$attempt" -lt 3 ] || { echo "::error::could not pull the images"; exit 1; }
  sleep $((attempt * 10))
done

echo "-- docker compose up --wait (every service with a healthcheck must become healthy)"
dc up -d --wait --wait-timeout 150

echo "-- the compose healthcheck uses /app/mta; run it by hand too"
dc exec -T eggmail /app/mta --healthcheck

case "$variant" in
  postgres)
    python3 "$here/smoke.py" --admin-user admin --admin-password "$admin_password" --expect-backend postgres --smtp-port 587 --host-ip "$SMOKE_HOST_IP" --timeout 90
    ;;
  sqlite)
    generated=$(dc logs --no-color eggmail | python3 "$here/smoke.py" --print-generated-password)
    python3 "$here/smoke.py" --admin-user admin --admin-password "$generated" --expect-backend sqlite --stop-after signin
    ;;
  unbound)
    generated=$(dc logs --no-color eggmail | python3 "$here/smoke.py" --print-generated-password)
    python3 "$here/smoke.py" --admin-user admin --admin-password "$generated" --expect-backend sqlite --stop-after signin
    echo "-- EggMail runs with the resolver settings of the override (the environment of the running container)"
    container_env=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$(dc ps -q eggmail)")
    echo "$container_env" | grep -qx 'Dns__TrustAuthenticatedData=true' || { echo "::error::the running container lacks Dns__TrustAuthenticatedData=true"; exit 1; }
    echo "$container_env" | grep -qx 'Dns__Servers__0=172.30.53.53' || { echo "::error::the running container lacks Dns__Servers__0=172.30.53.53"; exit 1; }
    echo "-- Unbound validates DNSSEC: a DNSSEC-signed name (cloudflare.com) answers with the AD flag, sigfail (a broken signature) answers SERVFAIL"
    signed=""
    for _ in $(seq 1 10); do   # the first validations after a start can answer SERVFAIL for a moment
      signed=$(dc exec -T unbound drill -D cloudflare.com @127.0.0.1 A || true)
      if echo "$signed" | grep -qE '^;; flags:.* ad[ ;]'; then break; fi
      sleep 3
    done
    echo "$signed" | grep -E '^;; flags:.* ad[ ;]' >/dev/null || { echo "$signed"; echo "::error::no AD flag for cloudflare.com"; exit 1; }
    broken=""
    for _ in $(seq 1 5); do
      broken=$(dc exec -T unbound drill sigfail.verteiltesysteme.net @127.0.0.1 A || true)
      if echo "$broken" | grep -q 'rcode: SERVFAIL'; then break; fi
      sleep 3
    done
    echo "$broken" | grep -q 'rcode: SERVFAIL' || { echo "$broken"; echo "::error::sigfail.verteiltesysteme.net did not fail validation"; exit 1; }
    ;;
esac
