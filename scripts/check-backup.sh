#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
bounded(){ python3 scripts/bounded-command.py "$@"; }
python3 scripts/aggregate-command.py 120 go test -count=1 -p 2 -timeout 90s ./internal/modules/backup/...
# The product CLI fixture must always correspond to this checkout.
python3 scripts/aggregate-command.py 120 sh scripts/build-edge.sh
export GATEBEAM_I4_BINARY="$PWD/.work/build/gatebeam"
export GATEBEAM_TEST_OPENSSL="${GATEBEAM_TEST_OPENSSL:-$(command -v openssl)}"
name="gatebeam-o4-$(date +%s)-$$"
export GATEBEAM_TEST_BACKUP_RUN="$name"
cleanup(){
 bounded 15 docker rm -f "$name" >/dev/null 2>&1 || :
 owned=$(bounded 5 docker ps -aq --filter "label=gatebeam.o4.run=$name") || owned=''
 if [ -n "$owned" ];then bounded 15 docker rm -f $owned >/dev/null 2>&1 || :;fi
}
trap cleanup EXIT HUP INT TERM
python3 scripts/aggregate-command.py 60 docker run -d --name "$name" --memory 512m --cpus 1 --pids-limit 128 --tmpfs /data:size=256m,mode=1777 --tmpfs /logs:size=16m,mode=1777 --log-opt max-size=1m --log-opt max-file=1 -e RUSTFS_ACCESS_KEY=test-access-key -e RUSTFS_SECRET_KEY=test-secret-key -e RUSTFS_CONSOLE_ENABLE=false -p 127.0.0.1::9000 rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2 /data >/dev/null
port=$(bounded 5 docker port "$name" 9000/tcp | sed 's/127.0.0.1://')
export GATEBEAM_TEST_S3="http://127.0.0.1:$port"
ready=0
for i in $(seq 1 20);do if bounded 2 curl -s -o /dev/null "$GATEBEAM_TEST_S3/";then ready=1;break;fi;sleep 1;done
[ "$ready" = 1 ] || { echo 'S3 readiness deadline' >&2;exit 1; }
sh scripts/check-db.sh ./tests/integration/backup ./internal/composition -v
