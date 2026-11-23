import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


class EnvironmentTests(unittest.TestCase):
 def module(self):
  import ci_environment
  return ci_environment

 def bundle(self,root,*,arch='arm64',changed=None,extra=None):
  files={'vmlinuz':b'kernel','initrd.img':b'initrd','rootfs.tar.gz':b'rootfs'}
  entries={'environment.json':json.dumps({'schema_version':1,'version':'2026-11-12.1','architecture':arch}).encode(),
           'SHA256SUMS':''.join(hashlib.sha256(v).hexdigest()+'  '+k+'\n' for k,v in files.items()).encode(),**files}
  if changed:entries[changed]=b'changed'
  if extra:entries[extra]=b'unexpected'
  path=root/'guest.tar'
  with tarfile.open(path,'w') as archive:
   for name,data in entries.items():
    info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
  return path

 def test_bootstrap_https_uses_the_copied_public_bundle_explicitly(self):
  recipe=(Path(__file__).resolve().parents[1]/'deploy/ci/environment/Dockerfile').read_text()
  self.assertIn('apt-get -o Acquire::https::CAInfo=/etc/ssl/certs/ca-certificates.crt update',recipe)
  self.assertIn('apt-get -o Acquire::https::CAInfo=/etc/ssl/certs/ca-certificates.crt install',recipe)
  self.assertNotIn('Verify-Peer=false',recipe)
  self.assertNotIn('Verify-Host=false',recipe)

 def test_pinned_environment_is_loaded_once_without_a_toolchain_build(self):
  m=self.module();ref='registry.example/gatebeam-ci-guest@sha256:'+'a'*64
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);bundle=self.bundle(root);commands=[]
   def get(args,**kwargs):
    commands.append(args);Path(args[-1]).write_bytes(bundle.read_bytes())
   with patch.object(m.subprocess,'run',side_effect=get):
    metadata=m.load_guest(ref,'arm64',root/'loaded')
   self.assertEqual(metadata['architecture'],'arm64');self.assertEqual(metadata['image'],ref)
   self.assertEqual(commands,[['regctl','image','get-file','--platform','linux/arm64',ref,'/guest.tar',str(root/'loaded/guest.tar')]])
   self.assertEqual((root/'loaded/vmlinuz').read_bytes(),b'kernel')
   self.assertFalse(any('build' in command or 'apt-get' in command for command in commands))

 def test_local_guest_archive_is_bound_to_its_exact_digest(self):
  m=self.module()
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);oci=root/'guest.oci.tar';oci.write_bytes(b'actual OCI');bundle=self.bundle(root)
   ref='artifact:sha256:'+hashlib.sha256(oci.read_bytes()).hexdigest()
   calls=[]
   def command(args,**kwargs):
    calls.append(args)
    if args[:3]==['regctl','image','get-file']:Path(args[-1]).write_bytes(bundle.read_bytes())
   with patch.dict('os.environ',{'GATEBEAM_CI_GUEST_ARCHIVE':str(oci)}),patch.object(m.subprocess,'run',side_effect=command):
    metadata=m.load_guest(ref,'arm64',root/'loaded')
   self.assertEqual(metadata['image'],ref)
   self.assertEqual(calls[0][:3],['regctl','image','import'])
   self.assertFalse(any('registry.example' in arg for call in calls for arg in call))
   oci.write_bytes(b'changed')
   with patch.dict('os.environ',{'GATEBEAM_CI_GUEST_ARCHIVE':str(oci)}),patch.object(m.subprocess,'run') as run:
    with self.assertRaises(ValueError):m.load_guest(ref,'arm64',root/'changed')
    run.assert_not_called()

 def test_mutable_missing_or_foreign_environment_is_refused(self):
  m=self.module()
  for ref in ('','repo:latest','repo@sha256:bad','https://registry/image@sha256:'+'a'*64):
   with self.subTest(ref=ref),tempfile.TemporaryDirectory() as td,patch.object(m.subprocess,'run') as run:
    with self.assertRaises(ValueError):m.load_guest(ref,'amd64',Path(td)/'out')
    run.assert_not_called()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   with self.assertRaises(ValueError):m.unpack_guest(self.bundle(root,arch='arm64'),root/'out','amd64')

 def test_corruption_and_unexpected_archive_paths_fail_closed(self):
  m=self.module()
  for changed,extra in [('vmlinuz',None),(None,'../escape'),(None,'unexpected')]:
   with self.subTest(changed=changed,extra=extra),tempfile.TemporaryDirectory() as td:
    root=Path(td)
    with self.assertRaises(ValueError):m.unpack_guest(self.bundle(root,changed=changed,extra=extra),root/'out','arm64')
    self.assertFalse((root/'escape').exists())


if __name__=='__main__':unittest.main()
