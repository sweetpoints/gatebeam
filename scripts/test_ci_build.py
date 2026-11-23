import importlib.util
import json
from pathlib import Path
import tempfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import unittest

ROOT = Path(__file__).resolve().parent.parent

class BuildTests(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('ci_build',ROOT/'scripts/ci-build.py')
  self.build=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.build)
 def test_docker_context_includes_admin_binary(self):
  self.assertIn('!.work/build/gatebeam-admin',(ROOT/'.dockerignore').read_text())
 def test_web_archive_is_identical_across_local_file_metadata(self):
  import os
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   archives=[]
   for index in range(2):
    web=root/f'checkout-{index}';web.mkdir()
    for name in (('a.js','b.css') if index==0 else ('b.css','a.js')):
     file=web/name;file.write_text(name)
     file.chmod(0o600 if index==0 else 0o644)
     os.utime(file,(1700000000+index,1700000000+index))
    archive=root/f'web-{index}.tar';archives.append(archive)
    self.build.write_web_archive(web,archive,1700010000)
   self.assertEqual(archives[0].read_bytes(),archives[1].read_bytes())

 def test_oci_archive_checks_manifest_and_config(self):
  import hashlib,io,tarfile
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'image.tar';blobs={}
   def blob(value):
    raw=json.dumps(value).encode();digest=hashlib.sha256(raw).hexdigest();blobs['blobs/sha256/'+digest]=raw
    return {'digest':'sha256:'+digest,'size':len(raw),'mediaType':'application/vnd.oci.image.manifest.v1+json'}
   config=blob({'os':'linux','architecture':'amd64','config':{}})
   manifest=blob({'schemaVersion':2,'config':config,'layers':[]})
   blobs['index.json']=json.dumps({'manifests':[manifest]}).encode()
   with tarfile.open(path,'w') as tf:
    for name,raw in blobs.items():
     info=tarfile.TarInfo(name);info.size=len(raw);tf.addfile(info,io.BytesIO(raw))
   result=self.build.inspect_oci(path,'amd64');self.assertEqual(result['manifest_digest'],manifest['digest'])
   self.assertEqual(result['config_digest'],config['digest'])
   with self.assertRaises(ValueError):self.build.inspect_oci(path,'arm64')


 def test_native_builder_exports_each_role_once_and_reuses_frozen_web(self):
  import os,shutil
  from unittest.mock import patch
  from ci_test_fixtures import make_build,TOOLS
  from ci_artifacts import read_build
  for arch in ('amd64','arm64'):
   with self.subTest(arch=arch),tempfile.TemporaryDirectory() as td:
    root=Path(td);fixture,context,bundle=make_build(root/'fixture',arch);source=root/'source';source.mkdir();out=root/'out';commands=[]
    def command(args,**kwargs):
     commands.append(args)
     if args[:2]==['go','build']:
      shutil.copy2(fixture/'programs'/Path(args[args.index('-o')+1]).name,args[args.index('-o')+1])
      self.assertEqual(kwargs['environment']['GOARCH'],arch)
     if args[:4]==['pnpm','--dir','web','exec'] and 'vite' in args:
      web=Path(args[args.index('--outDir')+1]);web.mkdir();(web/'index.html').write_text('current web')
     if args[:3]==['regctl','image','get-file']:Path(args[-1]).write_bytes(b'target tool')
     if args[:3]==['docker','buildx','build']:
      path=Path(args[args.index('--output')+1].split('dest=',1)[1]);shutil.copy2(fixture/path.name,path)
     if args[:3]==['regctl','image','export']:Path(args[-1]).write_bytes(b'docker export')
    def guest(image,architecture,destination):
     import io,tarfile
     self.assertEqual(architecture,arch)
     with tarfile.open(Path(destination)/'rootfs.tar.gz','w:gz') as archive:
      for name in ('opt/ci/duckdb/duckdb','opt/ci/duckdb/httpfs.duckdb_extension','etc/ssl/certs/ca-certificates.crt'):
       raw=('target '+arch).encode();member=tarfile.TarInfo('./'+name);member.size=len(raw);archive.addfile(member,io.BytesIO(raw))
    m=self.build
    with patch.dict(os.environ,{'GATEBEAM_CI_RUN_ID':'42','GATEBEAM_CI_RUN_ATTEMPT':'1','GATEBEAM_CI_GUEST_IMAGE':'artifact:sha256:'+'b'*64}),patch.object(m.sys,'platform','linux'),patch.object(m,'ROOT',source),patch.object(m,'OUT',out),patch.object(m,'head',return_value='a'*40),patch.object(m,'verify_tools'),patch.object(m,'source_epoch',return_value=1700010000),patch.object(m,'load_guest',side_effect=guest),patch.object(m,'command',side_effect=command),patch.object(m.subprocess,'run'):
     m.build(arch,TOOLS)
    output=out/'build'/arch;result=read_build(output,context)
    self.assertTrue(result['build_complete']);self.assertEqual(len(result['artifacts']),5)
    self.assertEqual((source/'.work/build/query-tools/duckdb').read_bytes(),('target '+arch).encode())
    builds=[c for c in commands if c[:3]==['docker','buildx','build']]
    self.assertEqual(len(builds),5)
    for c in builds:
     self.assertEqual(c[c.index('--platform')+1],'linux/'+arch)
     self.assertIn('SOURCE_DATE_EPOCH=1700010000',c)
     self.assertIn('rewrite-timestamp=true',c[c.index('--output')+1])
     self.assertTrue('WEB_STAGE=web-prebuilt' in c or 'QUERY_TOOLS_STAGE=tools-prebuilt' in c)
     self.assertNotIn('--push',c);self.assertNotIn('--load',c)
    self.assertEqual(sum(c[:4]==['pnpm','--dir','web','exec'] and 'vite' in c for c in commands),1)


 def test_native_edge_validates_index_reference_instead_of_config_id(self):
  import os,subprocess
  expected='nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606'
  with tempfile.TemporaryDirectory() as td:
   directory=Path(td)
   docker=directory/'docker';docker.write_text("""#!/bin/sh
case "$*" in *RepoDigests*) printf '%s\n' "$TEST_REPO_DIGESTS";; *) echo sha256:3d6cab9c2941df2441024a2f02a65ebe1b8916c3cbe7b9527f62627accea8004;; esac
""");docker.chmod(0o755)
   go=directory/'go';go.write_text('#!/bin/sh\nexit 0\n');go.chmod(0o755)
   env={**os.environ,'PATH':td+':'+os.environ['PATH'],'TEST_REPO_DIGESTS':json.dumps([expected])}
   result=subprocess.run(['sh','scripts/check-edge.sh','compiler'],cwd=ROOT,env=env,capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   env['TEST_REPO_DIGESTS']=json.dumps(['nginx@sha256:'+'f'*64])
   result=subprocess.run(['sh','scripts/check-edge.sh','compiler'],cwd=ROOT,env=env,capture_output=True,text=True)
   self.assertNotEqual(result.returncode,0)

if __name__=='__main__':unittest.main()
