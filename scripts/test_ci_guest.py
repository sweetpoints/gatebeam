import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ci import sha_file,write
from ci_test_fixtures import GUEST,make_build,make_groups


class GuestTests(unittest.TestCase):
 def module(self):
  spec=importlib.util.spec_from_file_location('guest',Path(__file__).with_name('ci_guest.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

 def test_foreign_source_is_rejected_before_preparing_or_loading_anything(self):
  m=self.module();record={'group':'core','ci_context':{'repository':'example/gatebeam','workflow':'acceptance.yml','run_id':'42','run_attempt':'1','source_commit':'a'*40,'architecture':'amd64'}}
  with patch.dict(m.os.environ,{},clear=True),patch.object(m,'head',return_value='b'*40),patch.object(m,'import_build') as images,patch.object(m,'command') as run,self.assertRaises(ValueError):
   m.verify('amd64',record)
  images.assert_not_called();run.assert_not_called()

 def test_each_group_prepares_dependencies_before_testing_without_cache_export(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);build,context,bundle=make_build(root);source=root/'source';source.mkdir()
   calls=[]
   def dependencies(args,**kwargs):calls.append(tuple(args))
   def inputs(*args,**kwargs):
    target=source/'.work/build/web-dist';target.mkdir(parents=True);(target/'index.html').write_text('frozen frontend')
   with patch.object(m,'ROOT',source),patch.object(m,'test_inputs',side_effect=inputs),patch.object(m,'command',side_effect=dependencies):
    m.prepare_dependencies(context,{'build_manifest_sha256':sha_file(build/'bundle.json')})
   self.assertEqual((source/'web/dist/index.html').read_text(),'frozen frontend')
   self.assertIn(('go','mod','download'),calls)
   installs=[c for c in calls if c[0]=='pnpm']
   self.assertEqual(len(installs),1);self.assertIn('--frozen-lockfile',installs[0]);self.assertIn('https://registry.npmmirror.com',installs[0])
   self.assertFalse(any(c[0] in ('tar','zstd') or c[:2] in (('go','test'),('go','build')) for c in calls))
   self.assertFalse((root/'prepared').exists())

 def test_failed_group_preserves_raw_result_and_nonzero_exit(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);build,context,bundle=make_build(root);groups=make_groups(root,context,build)
   images=json.loads((groups[0]/'group.json').read_text())['images_before']
   source=root/'source';source.mkdir();result=json.loads((groups[0]/'results.json').read_text());result['stages'][0]['exit_code']=23;result['group_complete']=False
   write(source/'.work/system-acceptance/results.json',result)
   def digest(path):
    return sha_file(build/'bundle.json') if Path(path)==Path('/results/build/bundle.json') else sha_file(path)
   order=[]
   def setup(*args):order.append('dependencies')
   def execute(*args,**kwargs):order.append('test');return 23
   with patch.dict(m.os.environ,{},clear=True),patch.object(m,'ROOT',source),patch.object(m,'OUT',root/'out'),patch.object(m,'context_for',return_value=context),patch.object(m,'head',return_value=context['source_commit']),patch.object(m,'read_build',return_value=bundle),patch.object(m,'import_build',return_value=images),patch.object(m,'prepare_dependencies',side_effect=setup),patch.object(m,'snapshot_images',return_value=images),patch.object(m.subprocess,'call',side_effect=execute),patch.object(m,'sha_file',side_effect=digest):
    self.assertEqual(m.verify('amd64',{'group':'core','environment_image':GUEST,'runner_environment':bundle['environment_image']}),23)
   self.assertEqual(order,['dependencies','test'])
   saved=json.loads((root/'out/groups/core/amd64/results.json').read_text())
   self.assertFalse(saved['group_complete']);self.assertFalse(saved['complete']);self.assertEqual(saved['stages'][0]['exit_code'],23)
   proof=json.loads((root/'out/groups/core/amd64/group.json').read_text());self.assertEqual(proof['environment_image'],GUEST)
   self.assertNotIn('prepared_sha256',proof)
   manifest=json.loads((source/'.work/artifacts/manifest.json').read_text())
   self.assertEqual(manifest['artifacts'],images);self.assertEqual(manifest['binary_sha256'],bundle['programs']['gatebeam'])


if __name__=='__main__':unittest.main()
