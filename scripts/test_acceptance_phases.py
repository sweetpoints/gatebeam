import copy
import unittest
from ci import STAGES


class GroupTests(unittest.TestCase):
 def module(self):
  import acceptance_phases
  return acceptance_phases

 def fixture(self,m):
  context={'repository':'example/gatebeam','workflow':'acceptance.yml','run_id':'42','run_attempt':'2','source_commit':'a'*40,'architecture':'arm64'}
  rows=[]
  for group,names in m.GROUPS.items():
   rows.append({'source_commit':'a'*40,'source_dirty':False,'architecture':'arm64','ci_context':copy.deepcopy(context),**m.MARKERS,'required_stages':list(STAGES),'group':group,'group_stages':list(names),'group_complete':True,'complete':False,'stages':[{'name':n,'exit_code':0} for n in names]})
  return context,rows,{'name':'fixed-images','exit_code':0,'execution':'linux-cross-build'}

 def test_named_groups_and_one_actual_build_cover_each_original_stage_once(self):
  m=self.module();context,rows,build=self.fixture(m)
  names=[n for group in m.GROUPS.values() for n in group]
  self.assertEqual(len(names),19);self.assertEqual(set(names),set(STAGES)-{'fixed-images'})
  rows[list(m.GROUPS).index('security')]['tls_performance']={'measurement':'security-only'}
  result=m.merge_results(rows,build,context)
  self.assertTrue(result['complete']);self.assertEqual([s['name'] for s in result['stages']],list(STAGES))
  self.assertEqual(result['tls_performance'],{'measurement':'security-only'})
  self.assertTrue(all(r['complete'] is False for r in rows))

 def test_distributed_runtime_partitions_count_as_one_original_gate(self):
  m=self.module();context,original,build=self.fixture(m)
  rows=[]
  for group,names in m.SHARDS.items():
   record=copy.deepcopy(original[0])
   record.update(group=group,group_stages=list(names),stages=[{'name':n,'exit_code':0,'seconds':1} for n in names])
   if group in m.MULTINODE_SHARDS:
    record['multinode_suite']=m.MULTINODE_SHARDS[group]
   rows.append(record)
  result=m.merge_shards(rows,build,context)
  self.assertEqual([s['name'] for s in result['stages']],list(STAGES))
  runtime=next(s for s in result['stages'] if s['name']==m.DUAL_NODE_STAGE)
  self.assertEqual(runtime['seconds'],3)
  self.assertEqual(runtime['suites'],list(m.MULTINODE_SHARDS.values()))
  for variant in ('missing','duplicate','wrong-suite','failed'):
   changed=copy.deepcopy(rows)
   index=next(i for i,row in enumerate(changed) if row['group']=='runtime-capacity')
   if variant=='missing':changed.pop(index)
   if variant=='duplicate':changed[index]=copy.deepcopy(changed[index-1])
   if variant=='wrong-suite':changed[index]['multinode_suite']='all'
   if variant=='failed':changed[index]['stages'][0]['exit_code']=1
   with self.subTest(variant=variant),self.assertRaises(ValueError):
    m.merge_shards(changed,build,context)

 def test_missing_foreign_failed_and_duplicate_results_cannot_authorize_publication(self):
  m=self.module();context,original,build=self.fixture(m)
  for kind in ('missing','duplicate','attempt','source','arch','dirty','already-full','failed','wrong-order','wrong-members','not-complete','failed-build','boolean-exit'):
   rows=copy.deepcopy(original);stage=copy.deepcopy(build)
   if kind=='missing':rows.pop()
   if kind=='duplicate':rows[-1]=copy.deepcopy(rows[0])
   if kind=='attempt':rows[1]['ci_context']['run_attempt']='1'
   if kind=='source':rows[1]['source_commit']='b'*40
   if kind=='arch':rows[1]['architecture']='amd64'
   if kind=='dirty':rows[1]['source_dirty']=True
   if kind=='already-full':rows[1]['complete']=True
   if kind=='failed':rows[1]['stages'][0]['exit_code']=1
   if kind=='wrong-order':rows[1]['stages'].reverse()
   if kind=='wrong-members':rows[1]['stages'][0]['name']=rows[0]['stages'][0]['name']
   if kind=='not-complete':rows[1]['group_complete']=False
   if kind=='failed-build':stage['exit_code']=1
   if kind=='boolean-exit':rows[0]['stages'][0]['exit_code']=False
   with self.subTest(kind=kind),self.assertRaises(ValueError):m.merge_results(rows,stage,context)


if __name__=='__main__':unittest.main()
