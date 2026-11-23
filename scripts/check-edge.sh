#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mode="${1:-compiler}"
case "$mode" in compiler|supervisor|runtime) ;; *) exit 2;; esac
command -v docker >/dev/null
image='nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606'
# The pinned reference is a multi-platform index digest; .Id is the selected
# platform's config digest and is necessarily different. Verify the retained
# repository digest instead, without weakening the immutable reference.
actual=$(python3 scripts/bounded-command.py 10 docker image inspect "$image" --format '{{json .RepoDigests}}')
python3 - "$image" "$actual" <<'PYIMAGE'
import json,sys
expected,actual=sys.argv[1],json.loads(sys.argv[2])
if not isinstance(actual,list) or not any(x in (expected,'docker.io/library/'+expected) for x in actual):
    raise SystemExit('native Nginx immutable repository digest mismatch')
PYIMAGE
if [ "$mode" = runtime ]; then
 python3 scripts/aggregate-command.py 120 go test -count=1 -p 2 -timeout 90s ./internal/modules/deployment/domain ./internal/modules/deployment/application/health ./internal/modules/deployment/application/preflight ./internal/modules/deployment/infrastructure/probe ./internal/modules/deployment/infrastructure/dns
 ./scripts/check-db.sh ./internal/modules/deployment/infrastructure/postgres ./tests/integration/edge -run 'TestRuntime|TestAllUnhealthyReturns503AndRecoveryRestoresWeights|TestPreflightPreservesAOPAndMTLS' -v
 exit
fi
if [ "$mode" = supervisor ]; then
 python3 scripts/aggregate-command.py 120 go test -count=1 -p 2 -timeout 90s ./internal/modules/deployment/domain ./internal/modules/deployment/application/runtime ./internal/modules/deployment/infrastructure/filesystem ./internal/modules/deployment/infrastructure/nginx
 arch=$(python3 scripts/bounded-command.py 10 docker image inspect "$image" --format '{{.Architecture}}')
 case "$arch" in arm64|amd64) ;; *) exit 2;; esac
 mkdir -p .work
 python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags native -o .work/supervisor.test ./internal/modules/deployment/application/runtime
 name="gatebeam-i4-native-$(date +%s)-$$"
 cleanup() { python3 scripts/bounded-command.py 10 docker rm -f "$name" >/dev/null 2>&1 || :; }
 trap cleanup EXIT HUP INT TERM
 python3 scripts/aggregate-command.py --test-package 80 docker run --rm --name "$name" --user 101:101 --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:size=64m,mode=1777 --memory 256m --cpus 1 --pids-limit 64 --log-opt max-size=1m --log-opt max-file=1 --mount "type=bind,src=$PWD/.work/supervisor.test,dst=/supervisor.test,readonly" --entrypoint /supervisor.test "$image" -test.v -test.timeout=60s -test.run "TestNative|TestOfflineOCSPNativeColdRestart|TestOfflineLogRotationPreservesUnarchivedData"
 GOARCH="$arch" ./scripts/build-edge.sh
 export GATEBEAM_I4_BINARY="$PWD/.work/build/gatebeam"
 ./scripts/check-db.sh ./tests/integration/edge -run 'TestI4|TestEdgeStartsWithoutControlServices' -v
 exit
fi
python3 scripts/aggregate-command.py 120 go test -count=1 -p 2 -timeout 90s ./internal/modules/deployment/infrastructure/... ./tests/integration/edge
