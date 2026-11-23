"""Load a digest-pinned, prebuilt guest environment; never install a toolchain."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from ci_registry import pull_environment

FILES={'vmlinuz':128*1024**2,'initrd.img':512*1024**2,'rootfs.tar.gz':16*1024**3,
       'environment.json':65536,'SHA256SUMS':4096}
PAYLOADS=('vmlinuz','initrd.img','rootfs.tar.gz')
REGISTRY_IMAGE=re.compile(r'[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}\Z')

ARTIFACT=re.compile(r'artifact:sha256:[a-f0-9]{64}\Z')
IMAGE=re.compile('(?:'+REGISTRY_IMAGE.pattern.removesuffix(r'\Z')+'|'+ARTIFACT.pattern.removesuffix(r'\Z')+r')\Z')


def unpack_guest(bundle,destination,architecture):
 if architecture not in ('amd64','arm64'):raise ValueError('explicit guest architecture required')
 destination=Path(destination)
 if destination.is_symlink():raise ValueError('regular environment directory required')
 destination.mkdir(parents=True,exist_ok=True)
 if any((destination/name).exists() or (destination/name).is_symlink() for name in PAYLOADS):
  raise ValueError('refusing to replace an existing guest environment')
 with tempfile.TemporaryDirectory(prefix='.environment-',dir=destination) as temporary:
  staged=Path(temporary);seen=set()
  with tarfile.open(bundle,'r:') as archive:
   for member in archive:
    name=member.name
    if name not in FILES or name in seen or not member.isfile() or not 0<member.size<=FILES[name]:
     raise ValueError('unexpected or unbounded environment archive member')
    seen.add(name)
    with archive.extractfile(member) as source,(staged/name).open('wb') as target:
     shutil.copyfileobj(source,target,1024*1024)
   if seen!=set(FILES):raise ValueError('incomplete environment archive')
  metadata=json.loads((staged/'environment.json').read_bytes())
  if metadata.get('schema_version')!=1 or metadata.get('architecture')!=architecture or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',metadata.get('version','')):
   raise ValueError('foreign or invalid guest environment')
  checksums={}
  for line in (staged/'SHA256SUMS').read_text().splitlines():
   fields=line.split()
   if len(fields)!=2 or fields[1] not in PAYLOADS or fields[1] in checksums or not re.fullmatch('[a-f0-9]{64}',fields[0]):
    raise ValueError('invalid environment checksums')
   checksums[fields[1]]=fields[0]
  if set(checksums)!=set(PAYLOADS):raise ValueError('missing environment checksum')
  for name in PAYLOADS:
   with (staged/name).open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
   if digest!=checksums[name]:raise ValueError('guest environment content changed')
  for name in PAYLOADS:(staged/name).replace(destination/name)
 return metadata


def load_guest(image,architecture,destination):
 if not isinstance(image,str) or not IMAGE.fullmatch(image):raise ValueError('digest-pinned CI guest image required')
 if architecture not in ('amd64','arm64'):raise ValueError('explicit guest architecture required')
 destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
 bundle=destination/'guest.tar'
 if bundle.exists() or bundle.is_symlink():raise ValueError('existing guest download refused')
 if ARTIFACT.fullmatch(image):
  archive=Path(os.environ.get('GATEBEAM_CI_GUEST_ARCHIVE','.work/ci-environment/guest.oci.tar'))
  if archive.is_symlink() or not archive.is_file():raise ValueError('fixed guest OCI artifact required')
  with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
  if image!='artifact:sha256:'+digest:raise ValueError('guest OCI artifact changed')
  layout='ocidir://'+str(destination.resolve()/'oci')+':guest'
  subprocess.run(['regctl','image','import',layout,str(archive)],check=True,timeout=300)
  subprocess.run(['regctl','image','get-file','--platform','linux/'+architecture,layout,'/guest.tar',str(bundle)],check=True,timeout=900)
 else:
  with pull_environment() as environment:
   subprocess.run(['regctl','image','get-file','--platform','linux/'+architecture,image,'/guest.tar',str(bundle)],check=True,timeout=900,env=environment)
 try:
  metadata=unpack_guest(bundle,destination,architecture)
  metadata['image']=image
  return metadata
 finally:bundle.unlink(missing_ok=True)
