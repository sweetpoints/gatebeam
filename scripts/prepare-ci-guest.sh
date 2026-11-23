#!/bin/sh
# 缓存只含固定工具；不包含业务源码、业务镜像或测试结果。
set -eu
mkdir -p .work/ci-environment
builder=gatebeam-guest-$$
cleanup(){ docker buildx rm -f "$builder" >/dev/null 2>&1 || :; }
trap cleanup EXIT HUP INT TERM
if [ ! -s .work/ci-environment/guest.oci.tar ];then
 docker buildx create --name "$builder" --driver remote tcp://buildkitd:1234 >/dev/null
 docker buildx inspect --bootstrap "$builder" >/dev/null
 docker buildx build --builder "$builder" --platform linux/amd64,linux/arm64 --target guest-image --provenance=false --sbom=false --progress plain --output type=oci,dest=.work/ci-environment/guest.oci.tar -f deploy/ci/environment/Dockerfile .
fi
# 无论来自缓存还是新构建，都校验实际平台及 guest 内容。
regctl image import ocidir://.work/ci-environment/checked:guest .work/ci-environment/guest.oci.tar
for arch in amd64 arm64;do
 regctl image get-file --platform "linux/$arch" ocidir://.work/ci-environment/checked:guest /guest.tar ".work/ci-environment/$arch.tar"
 python3 - "$arch" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0,'scripts')
from ci_environment import unpack_guest
root=Path('.work/ci-environment');arch=sys.argv[1]
unpack_guest(root/(arch+'.tar'),root/(arch+'-checked'),arch)
PY
 rm -rf ".work/ci-environment/$arch.tar" ".work/ci-environment/$arch-checked"
done
rm -rf .work/ci-environment/checked
printf 'guest=artifact:sha256:%s\n' "$(sha256sum .work/ci-environment/guest.oci.tar | cut -d ' ' -f 1)" >> "$GITHUB_OUTPUT"
printf 'runner=%s\n' "$CI_PUBLIC_IMAGE" >> "$GITHUB_OUTPUT"
