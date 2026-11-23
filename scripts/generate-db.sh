#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Exact release hashes from GitHub sqlc v1.31.1 release asset metadata.
case "$(uname -s)-$(uname -m)" in
 Darwin-arm64) platform=darwin_arm64; hash=21602158c99eb1f2bae197a66abfb1941d1e9e50b23125bb193349c6b1acc71e;;
 Darwin-x86_64) platform=darwin_amd64; hash=c5af76772e3785d21663a62697056b383f07629979b1bd25b93872e73dbd519b;;
 Linux-aarch64) platform=linux_arm64; hash=b7cae247740d0c51a1e657479e5b2d21e6fef428f596682a01bc55bf4ab8a23d;;
 Linux-x86_64) platform=linux_amd64; hash=497ae4fcdfa64c5b0c311ffe4c2bd991e43991e82e5367792ed78bc2dca27354;;
 *) echo 'Unsupported sqlc build platform' >&2; exit 1;;
esac
mkdir -p .work/tools
archive=".work/tools/sqlc-1.31.1-$platform.tar.gz"
if [ ! -f "$archive" ]; then
 python3 scripts/bounded-command.py 65 curl -fsSL --max-time 60 "https://github.com/sqlc-dev/sqlc/releases/download/v1.31.1/sqlc_1.31.1_$platform.tar.gz" -o "$archive.part"
 mv "$archive.part" "$archive"
fi
python3 - "$archive" "$hash" <<'PY'
import hashlib,sys,tarfile
archive,digest=sys.argv[1:]
if hashlib.sha256(open(archive,'rb').read()).hexdigest()!=digest:
 sys.exit('sqlc archive checksum mismatch')
with tarfile.open(archive) as source:
 if source.getnames()!=['sqlc']:sys.exit('unexpected sqlc archive members')
 source.extractall('.work/tools',filter='data')
PY
python3 scripts/bounded-command.py 30 .work/tools/sqlc generate
