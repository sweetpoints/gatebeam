#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
version=$(python3 scripts/product_version.py)
. ./scripts/target-arch.sh
arch=$(gatebeam_target_arch)
bounded(){ python3 scripts/bounded-command.py "$@"; }
# Web compilation is CI preparation; ordinary execution retains90/120 seconds.
set -- --label "org.opencontainers.image.version=$version" --build-arg "WEB_CHECK_TIMEOUT=$(python3 scripts/acceptance_budget.py 90)" --build-arg "WEB_INSTALL_TIMEOUT=$(python3 scripts/acceptance_budget.py 120)"
scripts/build-edge.sh
mkdir -p .work/artifacts
builder="gatebeam-build-$(date +%s)-$$"
cleanup(){ bounded 20 docker buildx rm -f "$builder" >/dev/null 2>&1 || :; }
trap cleanup EXIT HUP INT TERM
# BuildKit and its build subprocesses share these cgroup bounds. Passing legacy
# docker-build --memory flags to the default BuildKit driver is not sufficient.
bounded 20 docker buildx create --name "$builder" --driver docker-container --driver-opt 'image=moby/buildkit@sha256:b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c,memory=1536m,memory-swap=1536m,cpu-period=100000,cpu-quota=100000,restart-policy=no' >/dev/null
bounded 90 docker buildx inspect --bootstrap "$builder" >/dev/null
bounded 10 docker update --pids-limit 256 "buildx_buildkit_${builder}0" >/dev/null
# API builds and copies the web stage; Node is never a runtime service/image.
for target in edge api worker ca;do
 python3 scripts/aggregate-command.py 240 docker buildx build "$@" --provenance=false --sbom=false --platform "linux/$arch" --builder "$builder" --load --progress plain --target "$target" --metadata-file ".work/artifacts/$target.build.json" -f deploy/edge/Dockerfile -t "gatebeam-$target:local" .
done
python3 scripts/aggregate-command.py 240 docker buildx build "$@" --provenance=false --sbom=false --platform "linux/$arch" --builder "$builder" --load --progress plain --metadata-file .work/artifacts/query.build.json -f deploy/query/Dockerfile -t gatebeam-query:local .
bounded 10 docker image inspect gatebeam-edge:local gatebeam-api:local gatebeam-worker:local gatebeam-ca:local gatebeam-query:local --format '{{json .}}' > .work/artifacts/images.jsonl
python3 - "$version" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path.cwd()
version=sys.argv[1]
manifest={'product_version':version,'source_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'source_dirty':bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True).strip()),'binary_sha256':hashlib.sha256((root/'.work/build/gatebeam').read_bytes()).hexdigest(),'artifacts':[]}
for line in (root/'.work/artifacts/images.jsonl').read_text().splitlines():
 image=json.loads(line)
 if (image['Config'].get('Labels') or {}).get('org.opencontainers.image.version')!=version:
  raise SystemExit(f'image version differs from VERSION: {image["RepoTags"]}')
 manifest['artifacts'].append({k:image.get(k) for k in ['Id','RepoTags','RepoDigests','Architecture','Os','Size']})
(root/'.work/artifacts/manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Built fixed local artifacts; manifest .work/artifacts/manifest.json; no publication or deployment implied')
PY
