#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
fixture="$PWD/tests/fixtures/schema22/source.tar.gz"
source_root="$PWD/.work/schema22-fixture-source"
mkdir -p .work/build .work/artifacts
python3 - "$fixture" "$source_root" <<'PYFIXTURE'
import hashlib
from pathlib import Path
import sys
import tarfile
import tempfile

archive, target = map(Path, sys.argv[1:])
expected = "0577ab837967b615f1a60bc0fe404ad1c95d20e86d9150e2cd33eda4e30971dc"
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("schema 22 fixture checksum mismatch")
if target.exists():
    if (target / ".source-sha256").read_text().strip() != actual or not (target / "db").is_dir():
        raise SystemExit("unexpected existing schema 22 fixture directory")
else:
    with tempfile.TemporaryDirectory(dir=target.parent) as folder:
        extracted = Path(folder) / "source"
        extracted.mkdir()
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(extracted, filter="data")
        (extracted / ".source-sha256").write_text(actual + "\n")
        extracted.replace(target)
PYFIXTURE
python3 scripts/aggregate-command.py 120 env GOMAXPROCS=2 GOMEMLIMIT=512MiB go -C "$source_root" build -p 2 -buildvcs=false -trimpath -o "$PWD/.work/build/gatebeam-schema22" ./cmd/gatebeam
if [ -n "${GATEBEAM_CI_BUILD_INPUT:-}" ]; then
 python3 scripts/ci-test-inputs.py --arch "${GATEBEAM_TARGET_ARCH:?explicit test target required}" --program gatebeam --alias gatebeam-current-host
else
python3 scripts/aggregate-command.py 120 env GOMAXPROCS=2 GOMEMLIMIT=512MiB go build -p 2 -buildvcs=false -trimpath -o .work/build/gatebeam-current-host ./cmd/gatebeam
fi
python3 - <<'PY'
import hashlib,json,pathlib
p=pathlib.Path('.work/build');r={'source_sha256':pathlib.Path('.work/schema22-fixture-source/.source-sha256').read_text().strip(),'historical_sha256':hashlib.sha256((p/'gatebeam-schema22').read_bytes()).hexdigest(),'bridge_sha256':hashlib.sha256((p/'gatebeam-current-host').read_bytes()).hexdigest()}
pathlib.Path('.work/artifacts/schema22-fixture.json').write_text(json.dumps(r,indent=2)+'\n')
print('Built pinned historical API and current native bridge fixtures; no deployment')
PY
