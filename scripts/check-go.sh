#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
gatebeam_go_parallelism=${GATEBEAM_GO_PARALLELISM:-2}
case "$gatebeam_go_parallelism" in 2|4) ;; *) echo 'Go gate parallelism must be 2 or 4' >&2;exit 2;; esac
# Verification requires Python 3 on macOS/Linux for wall-clock deadlines.
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required for bounded verification" >&2; exit 127; }
python3 tests/architecture/test_bounded_command.py
files=$(find cmd internal db tests/architecture -name '*.go' -type f)
if [ -n "$(gofmt -l $files)" ]; then
  echo 'Go files need gofmt' >&2
  gofmt -d $files >&2
  exit 1
fi
set --
[ "${GATEBEAM_GO_TRACE:-0}" != 1 ] || set -- -x
echo "START go vet $(date -u +%FT%TZ)"
# Type-check integration-tagged fixtures here too, before expensive runtime groups.
# Vet does not execute tests or start their services.
python3 scripts/aggregate-command.py 120 go vet "$@" -tags integration -p 2 ./...
[ "${GATEBEAM_GO_TRACE:-0}" != 1 ] || set -- -x -json
echo "START go test $(date -u +%FT%TZ) parallelism=$gatebeam_go_parallelism"
python3 scripts/aggregate-command.py 120 go test "$@" ./... -count=1 -p "$gatebeam_go_parallelism" -timeout 90s
echo "START architecture checks $(date -u +%FT%TZ)"
scripts/check-architecture.sh
