#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/target-arch.sh
arch=$(gatebeam_target_arch)
mkdir -p .work/build
python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags integration -o .work/build/dns01-native ./tests/integration/dns01
export GATEBEAM_DNS01_BINARY="$PWD/.work/build/dns01-native"
exec python3 scripts/aggregate-command.py 100 go test -count=1 -p 2 -timeout 90s -tags integration ./tests/integration/dns01 -v
