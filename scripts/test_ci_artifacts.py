import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ci import ROLES,sha_file,write


class BuildArtifactTests(unittest.TestCase):
 def fixture(self,root):
  from ci_test_fixtures import make_build
  return make_build(root)

 def module(self):
  import ci_artifacts
  return ci_artifacts

 def test_all_five_source_bound_archives_are_required(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   folder,context,bundle=self.fixture(Path(td))
   self.assertEqual(m.read_build(folder,context)['build_complete'],True)
   for role in ROLES:self.assertTrue((folder/(role+'.oci.tar')).is_file())

 def test_foreign_inputs_and_changed_archives_fail_before_docker(self):
  m=self.module()
  for kind in ('source','attempt','architecture','missing-role','failed-build','manifest','oci','docker','config','mutable-environment','program','program-platform'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
    folder,context,bundle=self.fixture(Path(td));expected=copy.deepcopy(context)
    if kind in ('source','attempt','architecture'):
     field={'source':'source_commit','attempt':'run_attempt','architecture':'architecture'}[kind]
     expected[field]={'source':'b'*40,'attempt':'2','architecture':'arm64'}[kind]
    if kind=='missing-role':bundle['artifacts'].pop()
    if kind=='failed-build':bundle['stage']['exit_code']=1
    if kind=='manifest':(folder/'build.json').write_text('{}')
    if kind in ('oci','docker'):(folder/bundle['artifacts'][0]['archive' if kind=='oci' else 'docker_archive']).write_bytes(b'changed')
    if kind=='config':bundle['artifacts'][0]['config_digest']='sha256:'+'f'*64
    if kind=='program':(folder/'programs/gatebeam').write_bytes(b'changed')
    if kind=='program-platform':
     file=folder/'programs/gatebeam-admin';data=bytearray(file.read_bytes());data[18:20]=(183).to_bytes(2,'little');file.write_bytes(data);bundle['programs']['gatebeam-admin']=sha_file(file)
    if kind=='mutable-environment':bundle['environment_image']='tools:latest'
    write(folder/'bundle.json',bundle)
    with patch.object(m.subprocess,'run') as run,self.assertRaises((ValueError,OSError)):
     m.import_build(folder,expected)
    run.assert_not_called()

 def test_import_proves_actual_live_image_identity(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   folder,context,bundle=self.fixture(Path(td))
   live=json.loads((folder/'build.json').read_text())['artifacts']
   with patch.object(m.subprocess,'run') as load,patch.object(m.subprocess,'check_output',return_value=json.dumps(live)):
    self.assertEqual(len(m.import_build(folder,context)),5)
    self.assertEqual(load.call_count,5)
   live[0]['Id']='sha256:'+'f'*64
   with patch.object(m.subprocess,'run'),patch.object(m.subprocess,'check_output',return_value=json.dumps(live)),self.assertRaises(ValueError):
    m.import_build(folder,context)

 def test_fixture_aliases_use_the_exact_frozen_program_without_recompilation(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);folder,context,bundle=self.fixture(root);target=root/'programs'
   m.test_inputs(folder,context,sha_file(folder/'bundle.json'),target,names=('gatebeam',),aliases=('gatebeam-host','gatebeam-web-local'))
   for name in ('gatebeam','gatebeam-host','gatebeam-web-local'):
    self.assertEqual(sha_file(target/name),bundle['programs']['gatebeam'])
   with self.assertRaises(ValueError):m.test_inputs(folder,context,sha_file(folder/'bundle.json'),target,names=(),aliases=('../escape',))


if __name__=='__main__':unittest.main()
