#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/target-arch.sh
arch=$(gatebeam_target_arch)
mkdir -p .work/build
if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
 python3 scripts/ci-test-inputs.py --arch "$arch"
 exit 0
fi
case "$arch" in arm64|amd64) ;; *) echo 'unsupported edge architecture' >&2; exit 2;; esac
python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -p 2 -trimpath -o .work/build/gatebeam ./cmd/gatebeam

python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -p 2 -trimpath -o .work/build/gatebeam-admin ./cmd/gatebeam-admin
