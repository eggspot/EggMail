#!/usr/bin/env bash
# The throughput matrix of docs/benchmarks.md on one machine: both storage backends, each durable AND non-durable, ingest and end-to-end delivery.
# The bench-throughput workflow runs this same script on a hosted runner; run it on a Mac or Linux box for numbers that are not noisy.
#
#   bench/run-local-matrix.sh                            everything, 3 runs each (about 15 to 40 minutes)
#   bench/run-local-matrix.sh --quick                    one run of 10,000 messages per configuration (a few minutes: checks the setup)
#   bench/run-local-matrix.sh --messages 50000 --runs 5 --out ~/eggmail-bench
#   bench/run-local-matrix.sh --postgres skip            SQLite only
#
# Configurations (name = <backend>-<sync>-<history>-<phase>; every non-durable row has its durable pair, reported side by side):
#   sqlite   sync off | normal | full   x history full;  off | full x statsonly;  phase ingest (delivery off) and delivery (end to end to a counting sink)
#   postgres sync off (synchronous_commit=off) | on (the default, durable)   x history full | statsonly;  phase ingest and delivery
#
# PostgreSQL: --postgres auto (default) starts a throwaway cluster from initdb/pg_ctl/psql on PATH when they exist (brew install postgresql@17;
# the project does not use Docker on developer machines), else a postgres:17 container when docker exists (what the Actions runner does), else it
# skips the PostgreSQL rows and says so. --postgres local | docker | skip force one. The cluster lives inside the results folder and is stopped at
# the end; nothing outside it is touched. The summary prints the server version it measured.
#
# Output (--out, default artifacts/bench/<UTC time>): <name>.run<N>.json for every run, machine.txt, matrix.md (the table), run.log.
# Wrapper-only environment: BENCH_LABEL replaces the first line of matrix.md (the workflow sets "GitHub-hosted ..., noisy, not publishable").
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

messages=30000
runs=3
connections=16
size=2048
out=""
postgres=auto
quick=false
while [ $# -gt 0 ]; do
  case "$1" in
    --messages) messages="$2"; shift ;;
    --runs) runs="$2"; shift ;;
    --connections) connections="$2"; shift ;;
    --size) size="$2"; shift ;;
    --out) out="$2"; shift ;;
    --postgres) postgres="$2"; shift ;;
    --quick) quick=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
if [ "$quick" = true ]; then messages=10000; runs=1; fi
delivery_messages=$(( messages / 3 ))
[ -n "$out" ] || out="artifacts/bench/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
exec > >(tee -a "$out/run.log") 2>&1

echo "== build"
dotnet build bench/Mta.Bench.Pipeline -c Release -v q --nologo 2>&1 | tail -n 3
harness=(dotnet bench/Mta.Bench.Pipeline/bin/Release/net10.0/Mta.Bench.Pipeline.dll)

# ---------------------------------------------------------------------------------------------------------- machine
cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -srm)"
  echo "cores: $cores"
  if [ -r /proc/cpuinfo ]; then grep -m1 'model name' /proc/cpuinfo || true; free -m | head -2 || true
  else sysctl -n machdep.cpu.brand_string 2>/dev/null || true; echo "memory bytes: $(sysctl -n hw.memsize 2>/dev/null || true)"; fi
  echo "dotnet: $(dotnet --version)"
  echo "disk of the results folder: $(df -h "$out" | tail -n 1)"
} | tee "$out/machine.txt"

# ---------------------------------------------------------------------------------------------------------- PostgreSQL
pg_mode=skip
pg_port=0
pg_container="eggmail-bench-pg-$$"
pg_cleanup() {
  case "$pg_mode" in
    docker) docker rm -f "$pg_container" >/dev/null 2>&1 || true ;;
    local) pg_ctl -D "$out/pgdata" -m fast stop >/dev/null 2>&1 || true ;;
  esac
}
trap pg_cleanup EXIT

free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

start_postgres() {
  local want="$1"
  if [ "$want" = skip ]; then return 0; fi
  pg_port="$(free_port)"
  if { [ "$want" = auto ] || [ "$want" = local ]; } && command -v initdb >/dev/null 2>&1 && command -v pg_ctl >/dev/null 2>&1 && command -v psql >/dev/null 2>&1; then
    echo "== PostgreSQL from the binaries on PATH, throwaway cluster in $out/pgdata (default durability)"
    initdb -D "$out/pgdata" -U eggmail --auth=trust -E UTF8 --locale=C >/dev/null
    pg_ctl -D "$out/pgdata" -w -l "$out/postgres.log" -o "-p $pg_port -c listen_addresses=127.0.0.1 -c unix_socket_directories= -c max_connections=200" start >/dev/null
    pg_mode=local
  elif { [ "$want" = auto ] || [ "$want" = docker ]; } && command -v docker >/dev/null 2>&1; then
    echo "== PostgreSQL 17 in a container (default durability: fsync on, synchronous_commit on)"
    docker run -d --name "$pg_container" -p "127.0.0.1:$pg_port:5432" -e POSTGRES_USER=eggmail -e POSTGRES_PASSWORD=eggmail -e POSTGRES_DB=postgres \
      postgres:17 -c max_connections=200 >/dev/null
    pg_mode=docker
  else
    echo "== PostgreSQL: neither docker nor initdb/pg_ctl/psql found (or --postgres $want impossible): the PostgreSQL rows are skipped"
    return 0
  fi
  local i
  for i in $(seq 1 60); do
    if pg_sql postgres 'select 1' >/dev/null 2>&1; then break; fi
    sleep 1
    if [ "$i" = 60 ]; then echo "PostgreSQL did not become ready" >&2; pg_mode=skip_failed; return 1; fi
  done
  echo "PostgreSQL $(pg_sql postgres 'show server_version') on port $pg_port"
}

pg_sql() { # pg_sql <database> <sql>
  if [ "$pg_mode" = docker ]; then
    docker exec -i "$pg_container" psql -U eggmail -d "$1" -v ON_ERROR_STOP=1 -q -At -c "$2"
  else
    PGPASSWORD=eggmail psql -h 127.0.0.1 -p "$pg_port" -U eggmail -d "$1" -v ON_ERROR_STOP=1 -q -At -c "$2"
  fi
}

start_postgres "$postgres"
pg_enabled=false
case "$pg_mode" in docker|local) pg_enabled=true ;; esac

# ---------------------------------------------------------------------------------------------------------- the matrix
run_one() { # run_one <name> <run number> <harness arguments...>
  local name="$1" n="$2"; shift 2
  echo "== $name run $n"
  "${harness[@]}" "$@" --label "$name" --json "$out/${name}.run${n}.json" | tail -n 4
}

run_postgres() { # run_postgres <name> <run number> <synchronous_commit setting or empty> <harness arguments...>
  local name="$1" n="$2" commit="$3"; shift 3
  local db options=""
  db="bench_$(echo "$name" | tr '-' '_')_${n}"
  [ -z "$commit" ] || options=";Options='-c synchronous_commit=${commit}'"
  pg_sql postgres "create database ${db}" >/dev/null
  EGGMAIL_BENCH_POSTGRES="Host=127.0.0.1;Port=${pg_port};Username=eggmail;Password=eggmail;Database=${db};Maximum Pool Size=64${options}" \
    run_one "$name" "$n" --backend postgres "$@"
  pg_sql postgres "drop database ${db} with (force)" >/dev/null
}

common=(--connections "$connections" --size "$size")
# Runs are interleaved (run 1 of every configuration, then run 2 ...), so a slow minute on a shared machine does not land on one side of a pair.
for n in $(seq 1 "$runs"); do
  run_one sqlite-off-full-ingest        "$n" --sync off    --history full      --deliver false --messages "$messages" "${common[@]}"
  run_one sqlite-normal-full-ingest     "$n" --sync normal --history full      --deliver false --messages "$messages" "${common[@]}"
  run_one sqlite-full-full-ingest       "$n" --sync full   --history full      --deliver false --messages "$messages" "${common[@]}"
  run_one sqlite-off-statsonly-ingest   "$n" --sync off    --history statsonly --deliver false --messages "$messages" "${common[@]}"
  run_one sqlite-full-statsonly-ingest  "$n" --sync full   --history statsonly --deliver false --messages "$messages" "${common[@]}"
  run_one sqlite-off-full-delivery      "$n" --sync off    --history full      --deliver true  --messages "$delivery_messages" "${common[@]}"
  run_one sqlite-full-full-delivery     "$n" --sync full   --history full      --deliver true  --messages "$delivery_messages" "${common[@]}"
  if [ "$pg_enabled" = true ]; then
    run_postgres postgres-off-full-ingest       "$n" off --history full      --deliver false --messages "$messages" "${common[@]}"
    run_postgres postgres-on-full-ingest        "$n" ""  --history full      --deliver false --messages "$messages" "${common[@]}"
    run_postgres postgres-off-statsonly-ingest  "$n" off --history statsonly --deliver false --messages "$messages" "${common[@]}"
    run_postgres postgres-on-statsonly-ingest   "$n" ""  --history statsonly --deliver false --messages "$messages" "${common[@]}"
    run_postgres postgres-off-full-delivery     "$n" off --history full      --deliver true  --messages "$delivery_messages" "${common[@]}"
    run_postgres postgres-on-full-delivery      "$n" ""  --history full      --deliver true  --messages "$delivery_messages" "${common[@]}"
  fi
done

# ---------------------------------------------------------------------------------------------------------- the table
label="${BENCH_LABEL:-Local machine ($(uname -sm), $cores logical cores), load generator, server, sink and database on one machine; not a dedicated benchmark host}"
python3 bench/summarize-throughput.py "$out" "$label" > "$out/matrix.md"
[ "$pg_enabled" = true ] || echo "PostgreSQL rows were not measured: no container runtime and no local PostgreSQL binaries." >> "$out/matrix.md"
echo
cat "$out/matrix.md"
echo
echo "results: $out"
