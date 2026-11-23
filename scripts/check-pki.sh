#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/target-arch.sh
arch=$(gatebeam_target_arch)
case "${1:-acme}" in acme|native-integration)
 mkdir -p .work/build
 if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
  python3 scripts/ci-test-inputs.py --arch "$arch" --program gatebeam --alias gatebeam-host
 else
 python3 scripts/aggregate-command.py 90 go build -p 2 -o .work/build/gatebeam-host ./cmd/gatebeam
 fi
 export GATEBEAM_CA_IMPORT_BINARY="$PWD/.work/build/gatebeam-host"
 if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
  python3 scripts/ci-test-inputs.py --arch "$arch" --program gatebeam
 else
 python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -p 2 -o .work/build/gatebeam ./cmd/gatebeam
 fi
 export GATEBEAM_I4_BINARY="$PWD/.work/build/gatebeam"
 : "${GATEBEAM_TEST_OPENSSL:?explicit OpenSSL3 binary required for offline rotation}"
 ;; esac
case "${1:-acme}" in
 offline-cache)
  go test ./internal/modules/certificates/application/statuscache ./internal/modules/certificates/infrastructure/ocspcache -count=1
  exec ./scripts/check-edge.sh supervisor ;;
 public-client)
  mkdir -p .work/build
  arch=$(gatebeam_target_arch)
  # This suite also exercises offline bootstrap before the supervisor stage.
  python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags native -o .work/supervisor.test ./internal/modules/deployment/application/runtime
  if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
  python3 scripts/ci-test-inputs.py --arch "$arch" --program gatebeam
 else
 python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -p 2 -o .work/build/gatebeam ./cmd/gatebeam
 fi
  export GATEBEAM_I4_BINARY="$PWD/.work/build/gatebeam"
  exec ./scripts/check-db.sh ./internal/modules/certificates/... ./internal/modules/deployment/infrastructure/cloudflare/... ./internal/modules/deployment/infrastructure/nginx/... ./internal/modules/pki/application/acme ./tests/integration/edge ;;
 status)
  export GATEBEAM_TEST_OPENSSL="${GATEBEAM_TEST_OPENSSL:-$(command -v openssl)}"
  exec ./scripts/check-db.sh ./internal/modules/pki/... ./tests/integration/pki -run "Revocation|CertID|Status|CRL|Revoke" ;;
 native-integration)
  mkdir -p .work/build
  arch=$(gatebeam_target_arch)
  python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -tags integration -p 2 -o .work/build/pki-native ./tests/integration/pki
  export GATEBEAM_P3_NATIVE_BINARY="$PWD/.work/build/pki-native"
  exec ./scripts/check-db.sh ./tests/integration/pki -run "DedicatedClientDirectory|ABChallengeRouting|WrongSNI" -v ;;
 acme)
  mkdir -p .work/build
  arch=$(gatebeam_target_arch)
  python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -tags integration -p 2 -o .work/build/pki-native ./tests/integration/pki
  export GATEBEAM_P3_NATIVE_BINARY="$PWD/.work/build/pki-native"
  ./scripts/check-db.sh ./internal/modules/pki/...
  exec ./scripts/check-db.sh ./tests/integration/pki ;;

 *) echo 'usage: check-pki.sh acme|status|public-client|native-integration|offline-cache' >&2; exit 2 ;;
esac
