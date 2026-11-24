#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Docker required' >&2; exit 127; }
command -v python3 >/dev/null || exit 127
bounded() { python3 scripts/bounded-command.py "$@"; }
name="gatebeam-f2-$(date +%s)-$$"
cleanup() {
 code=$?
 if [ "$code" -ne 0 ]; then
  # Preserve fixed classifications before removing the owned fixture. Never
  # print server SQL, connection strings, container environment, or raw logs.
  bounded 5 docker inspect --format 'fixture_database status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' "$name" >&2 || :
  bounded 5 docker logs --tail 300 "$name" 2>&1 | python3 scripts/db-fixture-diagnostics.py >&2 || :
 fi
 bounded 15 docker rm -fv "$name" >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM
# DDL-heavy migrations can exhaust a 256MiB tmpfs and PANIC the fixture.
# Use a fresh anonymous disk volume; rm -v removes only this owned container
# and its anonymous volumes. Keep durability and CPU/memory/pid limits intact.
python3 scripts/aggregate-command.py 90 docker run -d --name "$name" --memory 512m --cpus 1 --pids-limit 128 --log-opt max-size=1m --log-opt max-file=1 --mount type=volume,destination=/var/lib/postgresql -e POSTGRES_PASSWORD=test-only -e POSTGRES_DB=gatebeam -p 127.0.0.1::5432 postgres:18.6@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4 -c max_wal_size=64MB -c min_wal_size=32MB -c checkpoint_timeout=30s >/dev/null
# Readiness is owned CI service preparation. Include Docker exec startup in
# that budget; a slow client must not exhaust every3s probe before it runs.
# TCP readiness excludes the entrypoint's temporary Unix-socket-only server.
if ! python3 scripts/aggregate-command.py 80 sh -c '
 for i in $(seq 1 20); do
  if python3 scripts/aggregate-command.py 3 docker exec "$1" pg_isready -h 127.0.0.1 -U postgres -d gatebeam >/dev/null 2>&1; then exit 0; fi
  sleep 1
 done
 exit 1
' -- "$name"; then
 echo 'PostgreSQL readiness deadline' >&2
 exit 1
fi
port=$(python3 scripts/aggregate-command.py 5 docker port "$name" 5432/tcp | sed 's/127.0.0.1://')
export GATEBEAM_TEST_DB_CONTAINER="$name"
export GATEBEAM_TEST_DATABASE_URL="postgres://postgres:test-only@127.0.0.1:$port/gatebeam?sslmode=disable"
export GATEBEAM_CA_TEST_DATABASE_URL="$GATEBEAM_TEST_DATABASE_URL"
python3 scripts/aggregate-command.py 5 docker exec "$name" psql -U postgres -d gatebeam -Atc 'show server_version'
if [ "$#" = 0 ]; then set -- ./internal/platform/jobs/... ./internal/platform/audit/...; fi
# Every call is a real database integration batch. Whole-package time includes
# fresh migrations, durable fixture IO and multiple independently bounded cases.
# Keep one finite batch policy rather than selecting budgets by package names.
package_timeout=300s
command_budget=315
if [ "${GATEBEAM_GO_TRACE:-0}" = 1 ]; then
 python3 scripts/aggregate-command.py "$command_budget" go test -json -tags integration -count=1 -p 2 -timeout "$package_timeout" "$@"
else
 python3 scripts/aggregate-command.py "$command_budget" go test -tags integration -count=1 -p 2 -timeout "$package_timeout" "$@"
fi
