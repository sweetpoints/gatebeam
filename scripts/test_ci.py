import importlib.util
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parent.parent
class ArchitectureTests(unittest.TestCase):
 def resolve(self,**extra):
  env={k:v for k,v in os.environ.items() if k not in ('GOARCH','GATEBEAM_TARGET_ARCH')};env.update(extra)
  return subprocess.run(['sh','-c','. ./scripts/target-arch.sh; gatebeam_target_arch'],cwd=ROOT,env=env,text=True,capture_output=True)
 def test_explicit_target_does_not_require_global_goarch(self):
  p=self.resolve(GATEBEAM_TARGET_ARCH='amd64');self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stdout.strip(),'amd64')
 def test_invalid_target_fails(self):self.assertNotEqual(self.resolve(GATEBEAM_TARGET_ARCH='other').returncode,0)
 def test_native_fixture_is_not_fixed_arm64(self):
  self.assertNotIn('"GOARCH=arm64"',(ROOT/'tests/integration/edge/native_test.go').read_text())
 def test_build_platform_is_explicit(self):
  self.assertIn('--platform "linux/$arch"',(ROOT/'scripts/build-system.sh').read_text())


class ReceiptTests(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('ci',ROOT/'scripts/ci.py');self.ci=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.ci)
 def valid(self):
  sha='a'*40
  receipt={'execution':'native','acceptance_policy':'native-full20','performance_certification':'route-budget-verified','complete':True,'source_commit':sha,'source_dirty':False,'required_stages':list(self.ci.STAGES),'stages':[{'name':n,'exit_code':0} for n in self.ci.STAGES]}
  manifest={'source_commit':sha,'source_dirty':False,'artifacts':[{'Id':'sha256:'+str(i)*64,'Architecture':'arm64','Os':'linux','RepoTags':['gatebeam-'+r+':local']} for i,r in enumerate(self.ci.ROLES,1)]}
  return sha,receipt,manifest
 def test_complete_two_platform_input(self):
  sha,r,m=self.valid();self.ci.validate_receipt(r,m,sha,'arm64')
 def test_missing_dirty_wrong_platform_and_duplicate_rejected(self):
  import copy
  sha,r,m=self.valid()
  for kind in ('dirty','sha','incomplete','duplicate','missing','platform'):
   a,b=copy.deepcopy(r),copy.deepcopy(m)
   if kind=='dirty':a['source_dirty']=True
   if kind=='sha':a['source_commit']='b'*40
   if kind=='incomplete':a['complete']=False
   if kind=='duplicate':a['stages'][-1]=a['stages'][0]
   if kind=='missing':b['artifacts'].pop()
   if kind=='platform':b['artifacts'][0]['Architecture']='amd64'
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.ci.validate_receipt(a,b,sha,'arm64')
 def test_untrusted_ref_never_publishes(self):
  for event,ref in [('pull_request','refs/heads/master'),('push','refs/heads/feature'),('workflow_dispatch','refs/heads/feature')]:
   self.assertIsNone(self.ci.release_tag(event,ref))
  self.assertEqual(self.ci.release_tag('push','refs/heads/master'),'master')
  self.assertIsNone(self.ci.release_tag('push','refs/tags/v1.2.3'))
  self.assertIsNone(self.ci.release_tag('workflow_dispatch','refs/heads/master'))
  self.assertIsNone(self.ci.release_tag('push','refs/tags/bad;value'))
 def test_emulated_receipt_requires_explicit_functional_policy(self):
  sha,r,m=self.valid();r['execution']='software-emulated-vm'
  with self.assertRaises(ValueError):self.ci.validate_receipt(r,m,sha,'arm64')
  r.update(acceptance_policy='software-functional-v1',performance_certification='not-certified',tls_performance={'execution':'software-emulated-vm','policy':'software-functional-v1','performance_certification':'not-certified','routes':400,'verified':72,'elapsed_seconds':5.01,'budget_seconds':5,'target_met':False,'functional_verified':400,'functional_batches':50,'full_business_verified':False,'full_failed':True,'full_routes':[{'site_id':'site-'+str(i//8),'host':'host-'+str(i),'sni':'host-'+str(i),'route':'/','outcome':'verified' if i<72 else 'degraded','reason':'' if i<72 else 'verification_budget_exhausted'} for i in range(400)]})
  self.ci.validate_receipt(r,m,sha,'arm64')
  r['performance_certification']='native-performance-passed'
  with self.assertRaises(ValueError):self.ci.validate_receipt(r,m,sha,'arm64')
 def test_emulated_receipt_requires_measurement_and_complete_functional_coverage(self):
  import copy
  sha,r,m=self.valid()
  r.update(execution='software-emulated-vm',acceptance_policy='software-functional-v1',performance_certification='not-certified')
  with self.assertRaises(ValueError):self.ci.validate_receipt(r,m,sha,'arm64')
  measurement={'execution':'software-emulated-vm','policy':'software-functional-v1','performance_certification':'not-certified','routes':400,'verified':72,'elapsed_seconds':5.01,'budget_seconds':5,'target_met':False,'functional_verified':400,'functional_batches':50,'full_business_verified':False,'full_failed':True,'full_routes':[{'site_id':'site-'+str(i//8),'host':'host-'+str(i),'sni':'host-'+str(i),'route':'/','outcome':'verified' if i<72 else 'degraded','reason':'' if i<72 else 'verification_budget_exhausted'} for i in range(400)]}
  for field,value in [('routes',399),('functional_verified',399),('functional_batches',49),('verified',401),('elapsed_seconds',float('nan')),('target_met',True),('full_business_verified',True),('full_failed',False),('full_routes',[])]:
   bad=copy.deepcopy(measurement);bad[field]=value;r['tls_performance']=bad
   with self.subTest(field=field),self.assertRaises(ValueError):self.ci.validate_receipt(r,m,sha,'arm64')
 def test_execution_policy_combinations_are_not_inferred(self):
  sha,r,m=self.valid()
  for execution in (None,'software-emulated-vm-typo','native'):
   a=dict(r,acceptance_policy='software-functional-v1',performance_certification='not-certified')
   if execution is None:a.pop('execution')
   else:a['execution']=execution
   with self.subTest(execution=execution),self.assertRaises(ValueError):self.ci.validate_receipt(a,m,sha,'arm64')
 def test_index_binds_both_config_distinct_from_manifest(self):
  data=self.ci.make_index('a'*40,[{'architecture':a,'digest':'sha256:'+d*64,'size':123,'mediaType':'application/vnd.oci.image.manifest.v1+json'} for a,d in [('amd64','1'),('arm64','2')]])
  self.assertEqual([x['platform']['architecture'] for x in data['manifests']],['amd64','arm64'])
  self.assertEqual(data['annotations']['org.opencontainers.image.revision'],'a'*40)

if __name__=='__main__':unittest.main()
