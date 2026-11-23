# Container/ELF architecture only. Do not export GOARCH into host test commands.
gatebeam_target_arch() {
 arch="${GATEBEAM_TARGET_ARCH:-${GOARCH:-$(go env GOARCH)}}"
 case "$arch" in amd64|arm64) printf '%s\n' "$arch";; *) echo 'unsupported container architecture' >&2;return 2;; esac
}
