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
for command in gatebeam-deploy gatebeam-deploy-host; do
 python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o ".work/build/$command" "./cmd/$command"
done
