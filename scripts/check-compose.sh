#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/target-arch.sh
arch=$(gatebeam_target_arch)
sh scripts/build-edge.sh
export GATEBEAM_COMPOSE_GATEWAY_BINARY="$PWD/.work/build/gatebeam"
export GATEBEAM_COMPOSE_ADMIN_BINARY="$PWD/.work/build/gatebeam-admin"
mkdir -p .work/build
python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags integration -o .work/build/compose-capabilities ./tests/integration/compose
export GATEBEAM_COMPOSE_PROBE_BINARY="$PWD/.work/build/compose-capabilities"
exec sh scripts/check-db.sh ./tests/integration/compose ./tests/fixtures/multinode -v
