"""Source-bound build inputs shared by all target test groups, never results."""
import json
from pathlib import Path
import re
import subprocess
import shutil
import tarfile
from ci import ARCHES,ROLES,load,sha_file
from ci_environment import IMAGE
from ci_oci import inspect_oci

PROGRAMS=('gatebeam','gatebeam-admin','gatebeam-deploy','gatebeam-deploy-host')
ALIASES=('gatebeam-host','gatebeam-web-local')


def checked_file(path,digest):
 path=Path(path)
 if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest) or path.is_symlink() or not path.is_file() or sha_file(path)!=digest:
  raise ValueError('build input content changed')
 return path


def read_build(folder,context,*,require_docker=True,require_programs=True):
 folder=Path(folder);bundle=load(folder/'bundle.json')
 if context.get('architecture') not in ARCHES or not re.fullmatch('[a-f0-9]{40}',context.get('source_commit','')):
  raise ValueError('explicit build source and target required')
 if bundle.get('schema_version')!=1 or bundle.get('kind')!='gatebeam-build' or bundle.get('ci_context')!=context or bundle.get('build_complete') is not True:
  raise ValueError('foreign or incomplete build inputs')
 if not isinstance(bundle.get('environment_image'),str) or not IMAGE.fullmatch(bundle['environment_image']):raise ValueError('pinned build environment required')
 stage=bundle.get('stage',{})
 if stage.get('name')!='fixed-images' or type(stage.get('exit_code')) is not int or stage['exit_code']!=0 or stage.get('execution')!='linux-cross-build':
  raise ValueError('real image build did not complete')
 checked_file(folder/'build.json',bundle.get('build_sha256'));build=load(folder/'build.json')
 if build.get('source_commit')!=context['source_commit'] or build.get('source_dirty') is not False or len(build.get('artifacts',[]))!=len(ROLES):
  raise ValueError('foreign build manifest')
 programs=bundle.get('programs',{})
 if set(programs)!=set(PROGRAMS):raise ValueError('all four frozen test programs required')
 for name,digest in programs.items():
  if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('missing program identity')
  if require_programs:
   program=checked_file(folder/'programs'/name,digest)
   with program.open('rb') as stream:header=stream.read(20)
   if len(header)<20 or header[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(header[18:20],'little')!={'amd64':62,'arm64':183}[context['architecture']]:raise ValueError('test program targets a different platform')
 if build.get('binary_sha256')!=programs['gatebeam']:raise ValueError('build and test program identities differ')
 if bundle.get('web_archive')!='web.tar' or not re.fullmatch('[a-f0-9]{64}',bundle.get('web_sha256','')):raise ValueError('frozen frontend required')
 if require_programs:checked_file(folder/'web.tar',bundle['web_sha256'])
 artifacts=bundle.get('artifacts',[])
 if len(artifacts)!=len(ROLES) or sorted(a.get('role','') for a in artifacts)!=sorted(ROLES):raise ValueError('all five unique build roles required')
 for item in artifacts:
  role=item['role']
  if item.get('archive')!=role+'.oci.tar' or item.get('docker_archive')!=role+'.docker.tar':raise ValueError('fixed build archive paths required')
  archive=checked_file(folder/item['archive'],item.get('archive_sha256'))
  if require_docker:checked_file(folder/item['docker_archive'],item.get('docker_archive_sha256'))
  elif not re.fullmatch('[a-f0-9]{64}',item.get('docker_archive_sha256','')):raise ValueError('missing tested Docker archive identity')
  actual=inspect_oci(archive,context['architecture'])
  if any(item.get(k)!=v for k,v in actual.items()):raise ValueError('build OCI differs from frozen metadata')
  entries=[a for a in build['artifacts'] if 'gatebeam-'+role+':local' in a.get('RepoTags',[])]
  if len(entries)!=1 or entries[0].get('Architecture')!=context['architecture'] or entries[0].get('Os')!='linux' or entries[0].get('Id') not in (actual['config_digest'],actual['manifest_digest']):
   raise ValueError('built role identity mismatch')
 return bundle


def validate_live(images,bundle):
 if len(images)!=len(ROLES):raise ValueError('five actual loaded images required')
 result=[]
 for item in bundle['artifacts']:
  role=item['role'];entries=[i for i in images if 'gatebeam-'+role+':local' in i.get('RepoTags',[])]
  if len(entries)!=1:raise ValueError('actual role tag missing or ambiguous')
  image=entries[0]
  if image.get('Id') not in (item['config_digest'],item['manifest_digest']) or image.get('Architecture')!=item['architecture'] or image.get('Os')!='linux':
   raise ValueError('loaded image was not the frozen build input')
  result.append({'role':role,**{k:image.get(k) for k in ('Id','Architecture','Os','RepoTags')}})
 return result


def import_build(folder,context):
 folder=Path(folder);bundle=read_build(folder,context)
 for item in bundle['artifacts']:
  subprocess.run(['docker','image','load','-i',str(folder/item['docker_archive'])],check=True,timeout=300)
 images=json.loads(subprocess.check_output(['docker','image','inspect',*['gatebeam-'+r+':local' for r in ROLES]],timeout=30))
 return validate_live(images,bundle)


def test_inputs(folder,context,expected_digest,destination,*,web=False,names=PROGRAMS,aliases=()):
 folder=Path(folder);checked_file(folder/'bundle.json',expected_digest);bundle=load(folder/'bundle.json')
 if bundle.get('ci_context')!=context or bundle.get('build_complete') is not True:raise ValueError('foreign test program inputs')
 destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
 for name in names:
  if name not in PROGRAMS:raise ValueError('unknown test program')
  source=checked_file(folder/'programs'/name,bundle.get('programs',{}).get(name))
  target=destination/name
  if target.is_symlink():target.unlink()
  if not target.is_file() or sha_file(target)!=bundle['programs'][name]:shutil.copyfile(source,target)
  target.chmod(0o755)
 for alias in aliases:
  if alias not in ALIASES:raise ValueError('unknown test program alias')
  source=checked_file(folder/'programs/gatebeam',bundle.get('programs',{}).get('gatebeam'))
  target=destination/alias
  if target.is_symlink():target.unlink()
  if not target.is_file() or sha_file(target)!=bundle['programs']['gatebeam']:shutil.copyfile(source,target)
  target.chmod(0o755)
 if web:
  archive=checked_file(folder/'web.tar',bundle.get('web_sha256'))
  target=destination/'web-dist'
  if target.exists():shutil.rmtree(target)
  target.mkdir()
  with tarfile.open(archive,'r:') as stream:stream.extractall(target,filter='data')
 return bundle
