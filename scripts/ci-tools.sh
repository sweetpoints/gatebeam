#!/bin/sh
# Install tools in the task container.
set -eu
mode=${1:?build, vm, environment or publish}
case "$(uname -m)" in
 x86_64) arch=amd64; regsum=8e0e62a497fcdb8048d18aa927a139613176ba0531f412bc541044e28f9856bd;;
 aarch64) arch=arm64; regsum=a9b71a3ee79b2d1dbbd7d51fd5e8fa214722c192864235d3d8764463c751a1ff;;
 *) echo '不支持的 Linux 架构' >&2;exit 1;;
esac
curl -fsSL --retry 3 --retry-all-errors --max-time 180 -o /usr/local/bin/regctl "https://github.com/regclient/regclient/releases/download/v0.11.6/regctl-linux-$arch"
echo "$regsum  /usr/local/bin/regctl" | sha256sum -c -
chmod 755 /usr/local/bin/regctl
case "$mode" in
 environment|build) : ;;
 vm) apk add --no-cache qemu-system-x86_64 qemu-system-aarch64 qemu-img e2fsprogs;;
 publish) ;;
 *) exit 1;;
esac
if [ "$mode" = build ];then
 python3 scripts/ci_native_tools.py
 node scripts/install-pnpm.mjs
fi
