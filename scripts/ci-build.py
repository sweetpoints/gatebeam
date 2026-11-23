"""Build immutable CI inputs and inspect the exact OCI images later tested."""
from ci_oci import inspect_oci

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from acceptance_phases import ci_context
from ci import ARCHES,ROLES,ROOT,OUT,head,run,sha_file,write
from ci_artifacts import read_build
from ci_environment import IMAGE,ARTIFACT,load_guest
from ci_tools import verify_tools
from ci_registry import pull_environment

PROGRAMS={'gatebeam':'./cmd/gatebeam','gatebeam-admin':'./cmd/gatebeam-admin','gatebeam-deploy':'./cmd/gatebeam-deploy','gatebeam-deploy-host':'./cmd/gatebeam-deploy-host'}


def command(args,*,environment=None,timeout=300):
 subprocess.run(args,cwd=ROOT,env=environment,timeout=timeout,check=True)


def source_epoch(sha):
 value=run(['git','show','-s','--format=%ct',sha])
 if not value.isascii() or not value.isdigit():
  raise ValueError('commit timestamp required for reproducible builds')
 return int(value)


def write_web_archive(tree,destination,epoch):
 def normalize(entry):
  if not (entry.isdir() or entry.isfile()):
   raise ValueError('frontend output contains a non-regular entry')
  entry.uid=entry.gid=0
  entry.uname=entry.gname=''
  entry.mode=0o755 if entry.isdir() else 0o644
  entry.mtime=epoch
  return entry

 # Docker imports the same tree that the acceptance fixture extracts.
 for path in (tree,*sorted(tree.rglob('*'))):
  if path.is_symlink() or not (path.is_dir() or path.is_file()):
   raise ValueError('frontend output contains a non-regular entry')
  path.chmod(0o755 if path.is_dir() else 0o644)
  os.utime(path,(epoch,epoch))
 with tarfile.open(destination,'w') as archive:
  archive.add(tree,arcname='.',filter=normalize)


def build(architecture,environment_image):
 if sys.platform!='linux' or architecture not in ARCHES:raise ValueError('explicit Linux build target required')
 if not IMAGE.fullmatch(environment_image):raise ValueError('pinned native CI environment required')
 os.environ['GOTOOLCHAIN']='local';verify_tools()
 sha=head();epoch=source_epoch(sha);context=ci_context(sha,architecture);started=time.monotonic()
 folder=OUT/'build'/architecture
 if folder.exists():raise ValueError('build destination already exists')
 folder.mkdir(parents=True)
 programs=ROOT/'.work/build';programs.mkdir(parents=True,exist_ok=True)
 env=os.environ.copy();env.update(GOOS='linux',GOARCH=architecture,CGO_ENABLED='0',GOPROXY='https://goproxy.cn',NODE_OPTIONS='--max-old-space-size=1024',NPM_CONFIG_REGISTRY='https://registry.npmmirror.com',SOURCE_DATE_EPOCH=str(epoch),TZ='UTC')
 program_hashes={}
 for name,package in PROGRAMS.items():
  command(['go','build','-p','2','-trimpath','-o',str(programs/name),package],environment=env)
  with (programs/name).open('rb') as stream:header=stream.read(20)
  if header[:6]!=b'\x7fELF\x02\x01' or len(header)<20 or int.from_bytes(header[18:20],'little')!={'amd64':62,'arm64':183}[architecture]:raise ValueError('cross-built program targets a different platform')
  target=folder/'programs'/name;target.parent.mkdir(exist_ok=True);shutil.copy2(programs/name,target)
  program_hashes[name]=sha_file(target)
 command(['pnpm','--dir','web','install','--frozen-lockfile','--store-dir',str(ROOT/'.work/pnpm-store')],environment=env)
 command(['pnpm','--dir','web','exec','vue-tsc','--noEmit'],environment=env,timeout=90)
 command(['pnpm','--dir','web','exec','vite','build','--outDir',str(programs/'web-dist'),'--emptyOutDir'],environment=env,timeout=90)
 write_web_archive(programs/'web-dist',folder/'web.tar',epoch)
 tools=programs/'query-tools';tools.mkdir(exist_ok=True)
 guest_image=os.environ.get('GATEBEAM_CI_GUEST_IMAGE','')
 if ARTIFACT.fullmatch(guest_image):
  with tempfile.TemporaryDirectory(prefix='query-guest-') as temporary:
   guest=Path(temporary);load_guest(guest_image,architecture,guest)
   with tarfile.open(guest/'rootfs.tar.gz','r:gz') as archive:
    for path,name in [('opt/ci/duckdb/duckdb','duckdb'),('opt/ci/duckdb/httpfs.duckdb_extension','httpfs.duckdb_extension'),('etc/ssl/certs/ca-certificates.crt','ca-certificates.crt')]:
     member=archive.getmember('./'+path)
     if not member.isfile():raise ValueError('regular fixed query tool required')
     with archive.extractfile(member) as source,(tools/name).open('wb') as target:shutil.copyfileobj(source,target)
 else:
  with pull_environment() as credentials:
   for path,name in [('/opt/ci/duckdb/duckdb','duckdb'),('/opt/ci/duckdb/httpfs.duckdb_extension','httpfs.duckdb_extension'),('/etc/ssl/certs/ca-certificates.crt','ca-certificates.crt')]:
    command(['regctl','image','get-file','--platform','linux/'+architecture,environment_image,path,str(tools/name)],environment=credentials,timeout=900)
 for path in (tools/'duckdb',tools/'httpfs.duckdb_extension',tools/'ca-certificates.crt'):
  path.chmod(0o755 if path.name=='duckdb' else 0o644)
  os.utime(path,(epoch,epoch))
 for name in PROGRAMS:
  path=programs/name
  path.chmod(0o755)
  os.utime(path,(epoch,epoch))
 builder='gatebeam-build-'+architecture+'-'+str(os.getpid())
 command(['docker','buildx','create','--name',builder,'--driver','remote','tcp://buildkitd:1234'],timeout=30)
 artifacts=[];images=[]
 try:
  command(['docker','buildx','inspect','--bootstrap',builder],timeout=90)
  for role in ROLES:
   archive=folder/(role+'.oci.tar')
   args=['docker','buildx','build','--builder',builder,'--platform','linux/'+architecture,'--provenance=false','--sbom=false','--progress','plain','--label','org.opencontainers.image.revision='+sha,'--build-arg','SOURCE_DATE_EPOCH='+str(epoch),'--output','type=oci,rewrite-timestamp=true,oci-mediatypes=true,compression=gzip,dest='+str(archive)]
   if role=='query':args+=['--build-arg','QUERY_TOOLS_STAGE=tools-prebuilt','-f','deploy/query/Dockerfile']
   else:args+=['--build-arg','WEB_STAGE=web-prebuilt','--target',role,'-f','deploy/edge/Dockerfile']
   command(args+['.'],environment=env,timeout=240)
   metadata=inspect_oci(archive,architecture)
   docker_archive=folder/(role+'.docker.tar')
   with tempfile.TemporaryDirectory(prefix='build-layout-') as temporary:
    layout='ocidir://'+str(Path(temporary)/'image')+':built'
    command(['regctl','image','import',layout,str(archive)])
    command(['regctl','image','export','--name','gatebeam-'+role+':local',layout,str(docker_archive)])
   artifacts.append({**metadata,'role':role,'archive':archive.name,'archive_sha256':sha_file(archive),'docker_archive':docker_archive.name,'docker_archive_sha256':sha_file(docker_archive)})
   images.append({'Id':metadata['config_digest'],'identity_type':'oci-config','RepoTags':['gatebeam-'+role+':local'],'Architecture':architecture,'Os':'linux'})
 finally:
  subprocess.run(['docker','buildx','rm','-f',builder],cwd=ROOT,timeout=30,check=False)
 if head()!=sha:raise ValueError('source changed during image construction')
 write(folder/'build.json',{'source_commit':sha,'source_dirty':False,'ci_context':context,'artifacts':images,'binary_sha256':program_hashes['gatebeam']})
 write(folder/'bundle.json',{'schema_version':1,'kind':'gatebeam-build','ci_context':context,'build_complete':True,'environment_image':environment_image,'build_sha256':sha_file(folder/'build.json'),'programs':program_hashes,'web_archive':'web.tar','web_sha256':sha_file(folder/'web.tar'),'stage':{'name':'fixed-images','exit_code':0,'execution':'linux-cross-build','seconds':round(time.monotonic()-started,3)},'artifacts':artifacts})
 read_build(folder,context)


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('architecture',choices=ARCHES);options=parser.parse_args()
 build(options.architecture,os.environ.get('GATEBEAM_CI_RUNNER_IMAGE',''))
