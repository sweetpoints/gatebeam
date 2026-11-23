"""Reuse fixed toolchain files from the guest matching the actual Linux host."""
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from ci_environment import load_guest


def install(image,destination=Path('/')):
 if sys.platform!='linux':raise ValueError('native tools install only in the Linux CI job')
 architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
 if not architecture:raise ValueError('unsupported Linux build host')
 with tempfile.TemporaryDirectory(prefix='native-ci-tools-') as temporary:
  root=Path(temporary);load_guest(image,architecture,root)
  subprocess.run(['tar','-xzf',str(root/'rootfs.tar.gz'),'-C',str(destination),'./usr/local/go','./opt/ci-browser','./opt/ci/install-pnpm.mjs','./opt/ci/install-duckdb.py'],check=True,timeout=300)


if __name__=='__main__':install(os.environ.get('GATEBEAM_CI_GUEST_IMAGE',''))
