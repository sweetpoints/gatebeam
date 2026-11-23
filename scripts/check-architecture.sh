#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Verification requires Python 3 on macOS/Linux for wall-clock deadlines.
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required for bounded verification" >&2; exit 127; }
python3 scripts/aggregate-command.py 120 go test ./tests/architecture -count=1 -p 2 -timeout 90s
python3 scripts/aggregate-command.py 120 go run -p 2 ./tests/architecture .
