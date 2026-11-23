#!/bin/sh
# Current-source test driver; dependencies are prepared only inside this guest.
set -eu
mkdir -p /results
modprobe 9pnet_virtio
mount -t 9p -o trans=virtio,version=9p2000.L results /results
export PATH=/opt/pnpm:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export GOCACHE=/opt/gocache GOPATH=/root/go GOPROXY=https://goproxy.cn CGO_ENABLED=0
export PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS=false NPM_CONFIG_REGISTRY=https://registry.npmmirror.com
export PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers GATEBEAM_BROWSER_CHANNEL=chromium GATEBEAM_TEST_OPENSSL=/usr/bin/openssl
export GATEBEAM_TEST_DUCKDB=/opt/ci/duckdb/duckdb GATEBEAM_TEST_HTTPFS=/opt/ci/duckdb/httpfs.duckdb_extension
export GATEBEAM_ACCEPTANCE_EXECUTION=software-emulated-vm GATEBEAM_GO_TRACE=1 GATEBEAM_ACCEPTANCE_KEEP_GOING=1 GATEBEAM_GO_PARALLELISM=4
export COMPOSE_ANSI=never COMPOSE_PROGRESS=plain NO_COLOR=1
cd /workspace
collect() {
 code=$?
 if [ -d .work/system-acceptance ];then mkdir -p /results/system-acceptance;cp -a .work/system-acceptance/. /results/system-acceptance/;fi
 if [ -d ci-output/groups ];then cp -a ci-output/groups /results/;fi
 printf '\nGATEBEAM_COLLECT_EXIT=%s\n' "$code"
}
trap collect EXIT
arch=$(go env GOARCH)
python3 scripts/ci_guest.py --arch "$arch"
