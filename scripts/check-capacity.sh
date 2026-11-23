#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "${1:-all}" in small) rows=100000;objects=100;pattern=16;; million) rows=1000000;objects=1000;pattern=16;; maxobjects) rows=1000000;objects=4096;pattern=16;; near) rows=1000000;objects=128;pattern=2048;; all) "$0" small;"$0" million;"$0" maxobjects;"$0" near;exit;; *) exit 2;; esac
bounded(){ python3 scripts/bounded-command.py "$@"; }
image=${GATEBEAM_TEST_QUERY_IMAGE:?fresh production query image required}
run="gatebeam-o6-capacity-$(date +%s)-$$"
root="$PWD/.work/o6/$run"
mkdir -p "$root"
chmod 777 "$root"
cleanup(){ bounded 15 docker rm -f "$run-s3" "$run-test" >/dev/null 2>&1 || :;bounded 10 docker network rm "$run" >/dev/null 2>&1 || :;bounded 10 docker volume rm "$run-data" >/dev/null 2>&1 || :;rm -rf "$root"; }
trap cleanup EXIT HUP INT TERM
bounded 10 docker network create --internal "$run" >/dev/null
bounded 10 docker volume create "$run-data" >/dev/null
bounded 30 docker run -d --name "$run-s3" --network "$run" --network-alias capacity-s3 --memory 512m --cpus 1 --pids-limit 128 --log-opt max-size=1m --log-opt max-file=1 --mount "type=volume,src=$run-data,dst=/data" --tmpfs /logs:size=16m,mode=1777 -e RUSTFS_ACCESS_KEY=owned-capacity -e RUSTFS_SECRET_KEY=owned-capacity-secret -e RUSTFS_CONSOLE_ENABLE=false rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2 /data >/dev/null
arch=$(bounded 10 docker image inspect "$image" --format '{{.Architecture}}')
python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags capacity -o .work/build/capacity.test ./tests/capacity
run_test(){
 # Dataset generation and owned S3 seeding prepare the measured query. They
 # use the approved emulation preparation budget; actual query scenarios
 # retain their native watchdog and engine deadline on every platform.
 test_seconds=90
 container_seconds=100
 case "$1" in
  TestCapacityPrepare|TestCapacityUpload)
   test_seconds=$(python3 scripts/acceptance_budget.py 90)
   container_seconds=$(python3 scripts/acceptance_budget.py 100)
   ;;
 esac
 echo "capacity step=$1 test_watchdog=${test_seconds}s container_watchdog=${container_seconds}s"
 bounded "$container_seconds" docker run --rm --name "$run-test" --user 101:101 --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 512m --cpus 1 --pids-limit 64 --ulimit nofile=12288:12288 --tmpfs /tmp:size=1g,mode=1777 --network "$run" --log-opt max-size=1m --log-opt max-file=1 --mount "type=bind,src=$root,dst=/dataset" --mount "type=bind,src=$PWD/.work/build/capacity.test,dst=/capacity.test,readonly" -e CAPACITY_ROWS="$rows" -e CAPACITY_OBJECTS="$objects" -e CAPACITY_PATTERN="$pattern" -e CAPACITY_SOURCE="${source:-local}" -e CAPACITY_CACHE="${cache:-cold-process}" -e CAPACITY_SPAN="${span:-wide}" --entrypoint /capacity.test "$image" -test.run "^$1$" -test.v -test.parallel=2 -test.timeout="${test_seconds}s"
}
run_test TestRequiredCapacityMetrics
run_test TestCapacityPrepare
run_test TestCapacityUpload
sources="local archive"
[ "${1:-all}" != maxobjects ] || sources=local
for source in $sources;do
 for cache in cold-process hot-storage;do span=wide;run_test TestLogQueryCapacity;done
 span=narrow;cache=hot-storage;run_test TestLogQueryCapacity
done
