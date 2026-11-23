#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "${1:-auth}" in auth|ingress|pki|operations) ;; *) echo "usage: scripts/check-web.sh auth|ingress|pki|operations" >&2; exit 2;; esac
export GATEBEAM_WEB_SUITE="${1:-auth}"
if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
 python3 scripts/ci-test-inputs.py --arch "${GATEBEAM_TARGET_ARCH:?explicit test target required}" --web
else
python3 scripts/aggregate-command.py 180 env PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS=false pnpm --dir web install --frozen-lockfile --store-dir "$PWD/.work/pnpm-store"
python3 scripts/aggregate-command.py 90 web/node_modules/.bin/vue-tsc --noEmit -p web/tsconfig.json
python3 scripts/aggregate-command.py 90 web/node_modules/.bin/vite build web
fi
if [ "$GATEBEAM_WEB_SUITE" = ingress ] || [ "$GATEBEAM_WEB_SUITE" = pki ] || [ "$GATEBEAM_WEB_SUITE" = operations ]; then
 image='nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606'
 arch=$(python3 scripts/bounded-command.py 10 docker image inspect "$image" --format '{{.Architecture}}')
 GOARCH="$arch" ./scripts/build-edge.sh
 export GATEBEAM_WEB_EDGE_BINARY="$PWD/.work/build/gatebeam"
 python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags integration,native -o .work/build/web-edge.test ./internal/composition
 export GATEBEAM_WEB_FAULT_BINARY="$PWD/.work/build/web-edge.test"
fi
if [ "$GATEBEAM_WEB_SUITE" = operations ]; then
 export GATEBEAM_TEST_OPERATIONS_RUN="gatebeam-o5-$(date +%s)-$$"
 cleanup_operations(){
  owned=$(python3 scripts/bounded-command.py 5 docker ps -aq --filter "label=gatebeam.o5.run=$GATEBEAM_TEST_OPERATIONS_RUN") || owned=''
  if [ -n "$owned" ];then python3 scripts/bounded-command.py 15 docker rm -f $owned >/dev/null 2>&1 || :;fi
  volumes=$(python3 scripts/bounded-command.py 5 docker volume ls -q --filter "label=gatebeam.o5.run=$GATEBEAM_TEST_OPERATIONS_RUN") || volumes=''
  if [ -n "$volumes" ];then python3 scripts/bounded-command.py 10 docker volume rm $volumes >/dev/null 2>&1 || :;fi
  python3 scripts/bounded-command.py 10 docker network rm "$GATEBEAM_TEST_OPERATIONS_RUN-network" >/dev/null 2>&1 || :
 }
 trap cleanup_operations EXIT HUP INT TERM
 if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
  python3 scripts/ci-test-inputs.py --arch "$arch" --program gatebeam --alias gatebeam-web-local
 else
 python3 scripts/aggregate-command.py 90 go build -p 2 -o .work/build/gatebeam-web-local ./cmd/gatebeam
 fi
 export GATEBEAM_WEB_LOCAL_BINARY="$PWD/.work/build/gatebeam-web-local"
 ./scripts/build-edge.sh
 if [ -z "${GATEBEAM_TEST_QUERY_IMAGE:-}" ];then scripts/build-system.sh;export GATEBEAM_TEST_QUERY_IMAGE=gatebeam-query:local;fi
 python3 scripts/bounded-command.py 10 docker image inspect "$GATEBEAM_TEST_QUERY_IMAGE" >/dev/null
 python3 scripts/aggregate-command.py 30 docker network create --internal --label "gatebeam.o5.run=$GATEBEAM_TEST_OPERATIONS_RUN" "$GATEBEAM_TEST_OPERATIONS_RUN-network" >/dev/null
 python3 scripts/aggregate-command.py 60 docker run -d --name "$GATEBEAM_TEST_OPERATIONS_RUN-s3" --label "gatebeam.o5.run=$GATEBEAM_TEST_OPERATIONS_RUN" --network bridge --memory 512m --cpus 1 --pids-limit 128 --tmpfs /data:size=256m,mode=1777 --tmpfs /logs:size=16m,mode=1777 --log-opt max-size=1m --log-opt max-file=1 -e RUSTFS_ACCESS_KEY=test-access-key -e RUSTFS_SECRET_KEY=test-secret-key -e RUSTFS_CONSOLE_ENABLE=false -p 127.0.0.1::9000 rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2 /data >/dev/null
 # Publish the host fixture endpoint from the ordinary bridge. The query
 # worker remains exclusively on the internal network and reaches the same
 # owned S3 via its standard network alias.
 python3 scripts/aggregate-command.py 30 docker network connect --alias history-s3 "$GATEBEAM_TEST_OPERATIONS_RUN-network" "$GATEBEAM_TEST_OPERATIONS_RUN-s3"
 port=$(python3 scripts/bounded-command.py 5 docker port "$GATEBEAM_TEST_OPERATIONS_RUN-s3" 9000/tcp | sed 's/127.0.0.1://')
 export GATEBEAM_TEST_S3="http://127.0.0.1:$port"
 ready=0
 for i in $(seq 1 20);do if python3 scripts/bounded-command.py 2 curl -s -o /dev/null "$GATEBEAM_TEST_S3/";then ready=1;break;fi;sleep 1;done
 [ "$ready" = 1 ] || { echo 'owned S3 readiness deadline' >&2;exit 1; }
fi
export GATEBEAM_WEB_ACCEPTANCE=1
scripts/check-db.sh ./internal/composition -run '^TestWebBrowser$' -v
