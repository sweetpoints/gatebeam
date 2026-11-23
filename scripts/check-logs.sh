#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
bounded() { python3 scripts/bounded-command.py "$@"; }
case "${1:-query}" in query) ;; *) echo 'usage: check-logs.sh query' >&2;exit 2;; esac
name="gatebeam-o2-$(date +%s)-$$"
cleanup(){ bounded 15 docker rm -f "$name" >/dev/null 2>&1 || :; bounded 10 docker network rm "$name" >/dev/null 2>&1 || :; }
trap cleanup EXIT HUP INT TERM
if [ -z "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
 bounded 120 python3 scripts/install-duckdb.py .work/o2/verified-tools
fi
python3 scripts/aggregate-command.py 120 sh scripts/build-edge.sh
if [ -z "${GATEBEAM_TEST_QUERY_IMAGE:-}" ];then scripts/build-system.sh;export GATEBEAM_TEST_QUERY_IMAGE=gatebeam-query:local;fi
bounded 10 docker image inspect "$GATEBEAM_TEST_QUERY_IMAGE" >/dev/null
bounded 10 docker network create "$name" >/dev/null
export GATEBEAM_TEST_NETWORK="$name"
python3 scripts/aggregate-command.py 60 docker run -d --name "$name" --network "$name" --network-alias history-s3 --memory 512m --cpus 1 --pids-limit 128 --tmpfs /data:size=256m,mode=1777 --tmpfs /logs:size=16m,mode=1777 --log-opt max-size=1m --log-opt max-file=1 -e RUSTFS_ACCESS_KEY=test-access-key -e RUSTFS_SECRET_KEY=test-secret-key -e RUSTFS_CONSOLE_ENABLE=false -p 127.0.0.1::9000 rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2 /data >/dev/null
port=$(bounded 5 docker port "$name" 9000/tcp | sed 's/127.0.0.1://')
export GATEBEAM_TEST_S3="http://127.0.0.1:$port"
export GATEBEAM_TEST_DUCKDB="${GATEBEAM_TEST_DUCKDB:-$PWD/.work/o2/verified-tools/duckdb}"
export GATEBEAM_TEST_HTTPFS="${GATEBEAM_TEST_HTTPFS:-$PWD/.work/o2/verified-tools/httpfs.duckdb_extension}"
ready=0
for i in $(seq 1 20); do
 if bounded 2 curl -s -o /dev/null "$GATEBEAM_TEST_S3/";then ready=1;break;fi
 sleep 1
done
[ "$ready" = 1 ] || { echo 'S3 readiness deadline' >&2; exit 1; }
sh scripts/check-db.sh ./tests/integration/logquery ./internal/modules/observability/...
