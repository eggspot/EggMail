#!/usr/bin/env bash
# Soak test of the real EggMail host (docs/soak.md): publishes the host and the load tools, then runs bench/soak/soak.py.
#
#   bench/soak/run-soak.sh --hours 2 --backend sqlite
#   bench/soak/run-soak.sh --hours 6 --backend postgres --sync full --crash-interval-min 15
#   bench/soak/run-soak.sh --help                      every option of soak.py
#
# Needs: .NET 10 SDK, python3 (3.9 or newer, standard library only). PostgreSQL runs in a docker container when docker exists, else from the
# binaries on PATH (initdb, pg_ctl, psql, pg_dump, pg_restore). Works on Linux and macOS. Results go to artifacts/soak/results/<time>-<backend>
# unless --out is given; the exit code is 0 for PASS and 1 for FAIL.
#
# Wrapper-only options (not passed on): --skip-build  use the publish output from an earlier run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

skip_build=false
backend=sqlite
has_out=false
passthrough=()
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build) skip_build=true ;;
    --out) has_out=true; passthrough+=("$1" "$2"); shift ;;
    --backend) backend="$2"; passthrough+=("$1" "$2"); shift ;;
    *) passthrough+=("$1") ;;
  esac
  shift
done
if [ "$has_out" = false ]; then
  passthrough+=(--out "artifacts/soak/results/$(date -u +%Y%m%dT%H%M%SZ)-$backend")
fi

# The macOS default of 256 open files is too few for a server with a connection pool, a queue and a dozen sockets under load.
ulimit -n 10240 2>/dev/null || echo "warning: could not raise the open file limit (ulimit -n is $(ulimit -n))" >&2

python3 bench/soak/evaluate.py --self-test >/dev/null || { echo "bench/soak/evaluate.py --self-test failed" >&2; exit 2; }
python3 bench/soak/plan.py --self-test >/dev/null || { echo "bench/soak/plan.py --self-test failed" >&2; exit 2; }

if [ "$skip_build" = false ] || [ ! -e artifacts/soak/publish/mta ] || [ ! -e artifacts/soak/tools/mta-tools.dll ]; then
  # Framework-dependent publish, the layout the Docker image and a systemd unit run: `mta serve` out of one directory.
  dotnet publish src/Mta.Host -c Release -o artifacts/soak/publish -v q --nologo
  dotnet publish src/Mta.Tools -c Release -o artifacts/soak/tools -v q --nologo
fi

exec python3 bench/soak/soak.py "${passthrough[@]}"
