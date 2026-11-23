#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "${1:-full}" in
 contracts)
  python3 scripts/aggregate-command.py 120 go test -count=1 -p 2 -timeout 90s ./tests/e2e
  scripts/check-architecture.sh
  echo 'Contracts only; full-system acceptance NOT performed.'
  ;;
 full)
  : "${GATEBEAM_TEST_OPENSSL:?explicit OpenSSL 3 executable required}"
  export GATEBEAM_BROWSER_CHANNEL="${GATEBEAM_BROWSER_CHANNEL:-chrome}"
  export PNPM_CONFIG_MANAGE_PACKAGE_MANAGER_VERSIONS=false
  exec python3 scripts/check-system.py
  ;;
 *) echo 'usage: check-system.sh full|contracts' >&2; exit 2 ;;
esac
