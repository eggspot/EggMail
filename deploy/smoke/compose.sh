#!/usr/bin/env bash
# Smoke test of the shipped Compose files (deploy/compose) against a published image.
#
#   deploy/smoke/compose.sh postgres <image reference>   compose.postgres.yaml: PostgreSQL 17 + EggMail, full end-to-end smoke test
#   deploy/smoke/compose.sh sqlite   <image reference>   compose.yaml: starts, becomes healthy, bootstrap administrator signs in
#   deploy/smoke/compose.sh unbound  <image reference>   compose.yaml + compose.unbound.yaml: the resolver validates DNSSEC (AD bit)
#
# Only the postgres variant runs the full end-to-end test (it needs the test-only override that points the instance at the DNS stub
# and the sink); the other two prove that the file starts healthy and that the bootstrap administrator can sign in.
# The files are copied to a temporary directory first, so the test uses them exactly as a user would and leaves the repository clean.
set -euo pipefail

variant=${1:?usage: compose.sh <postgres|sqlite|unbound> <image reference>}
ref=${2:?usage: compose.sh <postgres|sqlite|unbound> <image reference>}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cp -R "$here/../compose/." "$work/"
cp "$here/compose.smoke.yaml" "$work/"

export EGGMAIL_IMAGE=$ref
export EGGMAIL_HOSTNAME=smoke.eggmail.test
EGGMAIL_DB_PASSWORD=$(openssl rand -hex 12)
export EGGMAIL_DB_PASSWORD
SMOKE_HOST_IP=${SMOKE_HOST_IP:-$(ip route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')}
export SMOKE_HOST_IP
admin_password=$(openssl rand -hex 12)Aa1
mkdir -p "$work/secrets"
printf '%s' "$admin_password" > "$work/secrets/admin_password.txt"
chmod 644 "$work/secrets/admin_password.txt"

case "$variant" in
  postgres) files=(-f compose.postgres.yaml -f compose.smoke.yaml) ;;
  sqlite)   files=(-f compose.yaml) ;;
  unbound)  files=(-f compose.yaml -f compose.unbound.yaml) ;;
  *) echo "unknown variant $variant"; exit 64 ;;
esac

cd "$work"
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::compose state and logs"
    docker compose "${files[@]}" ps -a || true
    docker compose "${files[@]}" logs --no-color --tail 80 || true
    echo "::endgroup::"
  fi
  docker compose "${files[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  cd /
  rm -rf "$work"
}
trap cleanup EXIT

echo "-- docker compose config (${variant})"
docker compose "${files[@]}" config --quiet

if [ "$variant" = "unbound" ]; then
  # The override must switch TrustAuthenticatedData on for EggMail and point it at the resolver's fixed address.
  config=$(docker compose "${files[@]}" config)
  echo "$config" | grep -q 'Dns__TrustAuthenticatedData: "true"' || { echo "::error::TrustAuthenticatedData not set by the override"; exit 1; }
  echo "$config" | grep -q 'Dns__Servers__0: 172.30.53.53' || { echo "::error::Dns__Servers__0 not set by the override"; exit 1; }
fi

echo "-- docker compose up --wait (every service with a healthcheck must become healthy)"
docker compose "${files[@]}" up -d --wait --wait-timeout 150

echo "-- the compose healthcheck uses /app/mta; run it by hand too"
docker compose "${files[@]}" exec -T eggmail /app/mta --healthcheck

case "$variant" in
  postgres)
    python3 "$here/smoke.py" --admin-user admin --admin-password "$admin_password" --expect-backend postgres --smtp-port 587 --host-ip "$SMOKE_HOST_IP" --timeout 90
    ;;
  sqlite)
    python3 "$here/smoke.py" --admin-user admin --admin-password "$admin_password" --expect-backend sqlite --stop-after signin
    ;;
  unbound)
    python3 "$here/smoke.py" --admin-user admin --admin-password "$admin_password" --expect-backend sqlite --stop-after signin
    echo "-- Unbound validates DNSSEC: sigok answers with the AD flag, sigfail (a broken signature) answers SERVFAIL"
    signed=""
    for _ in $(seq 1 10); do   # the first validations after a start can answer SERVFAIL for a moment
      signed=$(docker compose "${files[@]}" exec -T unbound drill -D sigok.verteiltesysteme.net @127.0.0.1 A || true)
      if echo "$signed" | grep -qE '^;; flags:.* ad[ ;]'; then break; fi
      sleep 3
    done
    echo "$signed" | grep -E '^;; flags:.* ad[ ;]' >/dev/null || { echo "$signed"; echo "::error::no AD flag for sigok.verteiltesysteme.net"; exit 1; }
    broken=$(docker compose "${files[@]}" exec -T unbound drill sigfail.verteiltesysteme.net @127.0.0.1 A || true)
    echo "$broken" | grep -q 'rcode: SERVFAIL' || { echo "$broken"; echo "::error::sigfail.verteiltesysteme.net did not fail validation"; exit 1; }
    ;;
esac
