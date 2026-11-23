"""Same-attempt named acceptance groups; partial results never authorize publication."""
import json
import subprocess
import os
import re
from ci import ARCHES, STAGES, ROLES

GROUPS={
 'core':('go-and-architecture','contracts','core-transactions'),
 'security':('public-client-process-faults','standard-ca-rotation-restart','owned-dns01','native-edge-supervisor','browser-pki'),
 'runtime':('compose-runtime','dual-node-runtime-control-upgrade-migration-capacity'),
 'web':('browser-auth','browser-ingress','browser-operations'),
 'data':('archive-query','backup-recovery','capacity-100k','capacity-1m','capacity-4096','capacity-near2gib'),
}
DUAL_NODE_STAGE = 'dual-node-runtime-control-upgrade-migration-capacity'
MULTINODE_SHARDS = {
 'runtime-control': 'bootstrap',
 'runtime-upgrade': 'maintenance',
 'runtime-capacity': 'capacity',
}
SHARDS = {
 **{group: stages for group, stages in GROUPS.items() if group != 'runtime'},
 'compose': ('compose-runtime',),
 **{group: (DUAL_NODE_STAGE,) for group in MULTINODE_SHARDS},
}
EXECUTION_GROUPS = {**GROUPS, **SHARDS}
MARKERS={'execution':'software-emulated-vm','acceptance_policy':'software-functional-v1','performance_certification':'not-certified'}

def ci_context(sha,arch):
 if not re.fullmatch('[a-f0-9]{40}',sha) or arch not in ARCHES:raise ValueError('invalid CI source/platform')
 run=os.environ.get('GATEBEAM_CI_RUN_ID','');attempt=os.environ.get('GATEBEAM_CI_RUN_ATTEMPT','')
 if not re.fullmatch('[1-9][0-9]*',run) or not re.fullmatch('[1-9][0-9]*',attempt):raise ValueError('explicit CI run and attempt required')
 return {'repository':'example/gatebeam','workflow':'acceptance.yml','run_id':run,'run_attempt':attempt,'source_commit':sha,'architecture':arch}

def validate_group(result,group,context,*,require_success=True):
 if group not in EXECUTION_GROUPS or result.get('group')!=group or result.get('ci_context')!=context:raise ValueError('foreign test group source or attempt')
 if result.get('source_commit')!=context['source_commit'] or result.get('architecture')!=context['architecture'] or result.get('source_dirty') is not False:raise ValueError('unproved group source/platform')
 if any(result.get(k)!=v for k,v in MARKERS.items()) or result.get('complete') is not False:raise ValueError('partial software policy required')
 names=list(EXECUTION_GROUPS[group]);stages=result.get('stages',[])
 if result.get('multinode_suite')!=MULTINODE_SHARDS.get(group):raise ValueError('wrong dual-node suite')
 if result.get('required_stages')!=list(STAGES) or result.get('group_stages')!=names or [x.get('name') for x in stages]!=names:raise ValueError('exact test group and order required')
 if group!='security' and 'tls_performance' in result:raise ValueError('TLS evidence belongs to the security test group')
 success=all(type(x.get('exit_code')) is int and x['exit_code']==0 for x in stages)
 if type(result.get('group_complete')) is not bool or result['group_complete']!=success or require_success and not success:raise ValueError('test group did not pass all required scenarios')
 return result


def merge_results(receipts,build_stage,context):
 if len(receipts)!=len(GROUPS):raise ValueError('all five distinct test groups required')
 if build_stage.get('name')!='fixed-images' or type(build_stage.get('exit_code')) is not int or build_stage['exit_code']!=0 or build_stage.get('execution')!='linux-cross-build':raise ValueError('actual successful image build required')
 for group,result in zip(GROUPS,receipts):validate_group(result,group,context)
 stages=[dict(stage) for receipt in receipts for stage in receipt['stages']]+[dict(build_stage)]
 if len(stages)!=len(STAGES) or {s['name'] for s in stages}!=set(STAGES):raise ValueError('all original twenty scenarios required exactly once')
 result=dict(receipts[0]);result.update(complete=True,stages=[next(s for s in stages if s['name']==name) for name in STAGES])
 for key in ('group','group_stages','group_complete'):result.pop(key,None)
 security=receipts[list(GROUPS).index('security')]
 if 'tls_performance' in security:result['tls_performance']=security['tls_performance']
 return result


def merge_shards(receipts,build_stage,context):
 if len(receipts)!=len(SHARDS):
  raise ValueError('all distributed acceptance jobs required')
 found={}
 for receipt in receipts:
  group=receipt.get('group')
  if group not in SHARDS or group in found:
   raise ValueError('duplicate or unknown distributed job')
  found[group]=validate_group(receipt,group,context)
 parts=[found[group]['stages'][0] for group in MULTINODE_SHARDS]
 seconds=[part.get('seconds') for part in parts]
 if any(type(t) not in (float,int) or not 0<=t<=9900 for t in seconds):
  raise ValueError('invalid dual-node suite timing')
 combined={'name':DUAL_NODE_STAGE,'exit_code':0,'seconds':sum(seconds),
           'suites':list(MULTINODE_SHARDS.values())}
 runtime=dict(found['compose'],group='runtime',group_stages=list(GROUPS['runtime']),
              stages=[*found['compose']['stages'],combined])
 return merge_results([runtime if group=='runtime' else found[group] for group in GROUPS],
                      build_stage,context)


def snapshot_images():
 rows=json.loads(subprocess.check_output(['docker','image','inspect',*['gatebeam-'+r+':local' for r in ROLES]],timeout=30))
 result=[]
 for role in ROLES:
  entries=[x for x in rows if 'gatebeam-'+role+':local' in x.get('RepoTags',[])]
  if len(entries)!=1:raise ValueError('fixed role tag missing or ambiguous')
  result.append({'role':role,**{k:entries[0].get(k) for k in ('Id','Architecture','Os','RepoTags')}})
 return result
