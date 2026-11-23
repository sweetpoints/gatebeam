import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from acceptance_phases import GROUPS
from ci import ROLES,sha_file,write
from ci_test_fixtures import GUEST,make_build,make_groups,producer_bindings


class CheckpointTests(unittest.TestCase):
 def module(self):
  spec=importlib.util.spec_from_file_location('checkpoint',Path(__file__).with_name('ci-checkpoint.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

 def fixture(self,root):
  build,context,bundle=make_build(root);groups=make_groups(root,context,build)
  environment=patch.dict(os.environ,producer_bindings(build,groups));environment.start();self.addCleanup(environment.stop)
  return build,context,groups

 def test_direct_groups_assemble_without_any_prepared_artifact(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);build,context,groups=self.fixture(root)
   m.assemble(build,groups,root/'accepted',context,environment_image=GUEST)
   result=json.loads((root/'accepted/results.json').read_text())
   self.assertTrue(result['complete']);self.assertEqual(len(result['stages']),20)
   self.assertEqual(result['environment_image'],GUEST)
   self.assertEqual(result['tls_performance']['functional_verified'],400)
   self.assertFalse((root/'prepared').exists());self.assertFalse((root/'accepted/prepared.json').exists())
   for role in ROLES:self.assertEqual(sha_file(root/'accepted'/(role+'.oci.tar')),sha_file(build/(role+'.oci.tar')))
   self.assertEqual(m.validate_assembled_evidence(root/'accepted',context,environment_image=GUEST),result)

 def test_foreign_or_failed_inputs_never_produce_a_complete_acceptance(self):
  m=self.module()
  for kind in ('build','missing-group','duplicate-group','result-hash','foreign-build','foreign-environment','missing-environment','old-schema','live-image','attempt','failed','missing-tls'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
    root=Path(td);build,context,groups=self.fixture(root)
    proof=json.loads((groups[0]/'group.json').read_text())
    if kind=='build':(build/'bundle.json').write_text('{}')
    if kind=='missing-group':groups.pop()
    if kind=='duplicate-group':groups[-1]=groups[0]
    if kind=='result-hash':(groups[0]/'results.json').write_text('{}')
    if kind=='foreign-build':proof['build_bundle_sha256']='f'*64
    if kind=='foreign-environment':proof['environment_image']=GUEST.replace('d'*64,'f'*64)
    if kind=='missing-environment':proof.pop('environment_image')
    if kind=='old-schema':proof['schema_version']=1
    if kind=='live-image':proof['images_after']=copy.deepcopy(proof['images_after']);proof['images_after'][0]['Id']='sha256:'+'f'*64
    if kind=='attempt':proof['ci_context']['run_attempt']='2'
    if kind=='failed':
     result=json.loads((groups[0]/'results.json').read_text());result['stages'][0]['exit_code']=1;result['group_complete']=False;write(groups[0]/'results.json',result);proof['results_sha256']=sha_file(groups[0]/'results.json')
    if kind=='missing-tls':
     result=json.loads((groups[1]/'results.json').read_text());result.pop('tls_performance');write(groups[1]/'results.json',result)
     other=json.loads((groups[1]/'group.json').read_text());other['results_sha256']=sha_file(groups[1]/'results.json');write(groups[1]/'group.json',other)
    write(groups[0]/'group.json',proof)
    with self.assertRaises((ValueError,OSError)):m.assemble(build,groups,root/'accepted',context,environment_image=GUEST)
    self.assertFalse((root/'accepted/accepted.json').exists())

 def test_self_consistent_replacement_is_rejected_by_the_producer_binding(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);build,context,groups=self.fixture(root)
   bindings=producer_bindings(build,groups)
   result=json.loads((groups[0]/'results.json').read_text());result['annotation']='replaced';write(groups[0]/'results.json',result)
   proof=json.loads((groups[0]/'group.json').read_text());proof['results_sha256']=sha_file(groups[0]/'results.json');write(groups[0]/'group.json',proof)
   with patch.dict(os.environ,bindings),self.assertRaisesRegex(ValueError,'producer'):m.assemble(build,groups,root/'accepted',context,environment_image=GUEST)
   self.assertFalse((root/'accepted').exists())

 def test_authenticated_environment_cannot_be_replaced_by_self_consistent_proofs(self):
  m=self.module()
  for image in ('',None,'guest:latest',GUEST):
   with self.subTest(image=image),tempfile.TemporaryDirectory() as td:
    root=Path(td);build,context,groups=self.fixture(root)
    for folder in groups:
     proof=json.loads((folder/'group.json').read_text());proof['environment_image']=GUEST.replace('d'*64,'f'*64);write(folder/'group.json',proof)
    # Even new group producer bindings cannot authorize a different inputs output.
    bindings=producer_bindings(build,groups)
    with patch.dict(os.environ,bindings),self.assertRaises(ValueError):
     m.assemble(build,groups,root/'accepted',context,environment_image=image)
    self.assertFalse((root/'accepted').exists())


if __name__=='__main__':unittest.main()
