#!/usr/bin/env python3
"""Shared source, acceptance receipt and OCI index validation helpers."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'ci-output'
ROLES=('edge','api','worker','ca','query')
ARCHES=('arm64','amd64')
STAGES=('go-and-architecture','contracts','fixed-images','core-transactions','public-client-process-faults','standard-ca-rotation-restart','owned-dns01','native-edge-supervisor','archive-query','backup-recovery','compose-runtime','dual-node-runtime-control-upgrade-capacity','browser-auth','browser-ingress','browser-pki','browser-operations','capacity-100k','capacity-1m','capacity-4096','capacity-near2gib')
DIGEST=re.compile(r'sha256:[a-f0-9]{64}\Z')

def run(args,*,env=None,timeout=120,raw=False,input=None):
 p=subprocess.run(args,cwd=ROOT,env=env,timeout=timeout,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if p.returncode:raise RuntimeError('command failed: '+str(args[0])+' '+str(args[1] if len(args)>1 else '')+' (see bounded diagnostics)')
 return p.stdout if raw else p.stdout.decode().strip()

def load(p):
 p=Path(p)
 if p.is_symlink() or not p.is_file() or p.stat().st_size>4*1024*1024:raise ValueError('bounded regular JSON required')
 return json.loads(p.read_text())

def write(p,x):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 tmp=p.with_suffix(p.suffix+'.tmp');tmp.write_text(json.dumps(x,indent=2)+'\n');tmp.replace(p)

def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def head():
 sha=run(['git','-C',str(ROOT),'rev-parse','HEAD'])
 if not re.fullmatch('[a-f0-9]{40}',sha) or run(['git','-C',str(ROOT),'status','--porcelain']):raise ValueError('clean exact commit required')
 expected=os.environ.get('CI_COMMIT_SHA',sha)
 if expected!=sha:raise ValueError('checkout differs from event commit')
 return sha

def validate_software_performance(p):
 import math
 expected={'execution':'software-emulated-vm','policy':'software-functional-v1','performance_certification':'not-certified','routes':400,'budget_seconds':5,'functional_verified':400,'functional_batches':50}
 if not isinstance(p,dict) or any(p.get(k)!=v for k,v in expected.items()):raise ValueError('complete software route measurement and functional coverage required')
 count=p.get('verified');elapsed=p.get('elapsed_seconds')
 if type(count) is not int or not 0<=count<=400 or type(elapsed) not in (float,int) or not math.isfinite(elapsed) or elapsed<=0:raise ValueError('invalid TLS measurement')
 routes=p.get('full_routes')
 if not isinstance(routes,list) or len(routes)!=400:raise ValueError('all original full probe outcomes required')
 identities=set();successful=0
 for route in routes:
  if not isinstance(route,dict):raise ValueError('invalid route outcome')
  identity=tuple(route.get(k) for k in ('site_id','host','route'))
  if any(not isinstance(v,str) for v in identity) or not identity[0] or not identity[1] or identity in identities or route.get('sni')!=identity[1]:raise ValueError('duplicate or invalid full route identity')
  identities.add(identity)
  if route.get('outcome')=='verified':successful+=1
  elif route.get('outcome')!='degraded' or route.get('reason')!='verification_budget_exhausted':raise ValueError('non-budget TLS route failure')
 if type(p.get('full_business_verified')) is not bool or p['full_business_verified']!=(count==400) or type(p.get('full_failed')) is not bool or p['full_failed']!=(count!=400):raise ValueError('inconsistent full verification failure state')
 if successful!=count:raise ValueError('TLS count differs from persisted outcomes')
 if type(p.get('target_met')) is not bool or p['target_met']!=(count==400):raise ValueError('inconsistent TLS performance outcome')

def validate_receipt(r,m,sha,arch):
 if arch not in ARCHES or not re.fullmatch('[a-f0-9]{40}',sha):raise ValueError('invalid source/platform')
 if r.get('source_commit')!=sha or r.get('source_dirty') is not False or r.get('complete') is not True:raise ValueError('unproved acceptance source')
 if r.get('required_stages')!=list(STAGES) or [x.get('name') for x in r.get('stages',[])]!=list(STAGES) or any(x.get('exit_code')!=0 for x in r['stages']):raise ValueError('all20 distinct successful gates required')
 execution=r.get('execution')
 if execution not in ('native','software-emulated-vm'):raise ValueError('explicit known acceptance execution required')
 if execution=='native' and (r.get('acceptance_policy')!='native-full20' or r.get('performance_certification')!='route-budget-verified' or 'tls_performance' in r):raise ValueError('native receipt requires its own explicit policy')
 if r.get('execution')=='software-emulated-vm' and (r.get('acceptance_policy')!='software-functional-v1' or r.get('performance_certification')!='not-certified'):raise ValueError('explicit software functional policy required; native performance is not certified')
 if r.get('execution')=='software-emulated-vm':validate_software_performance(r.get('tls_performance'))
 if m.get('source_commit')!=sha or m.get('source_dirty') is not False or len(m.get('artifacts',[]))!=5:raise ValueError('foreign build manifest')
 for role in ROLES:
  found=[x for x in m['artifacts'] if 'gatebeam-'+role+':local' in x.get('RepoTags',[])]
  if len(found)!=1 or found[0].get('Architecture')!=arch or found[0].get('Os')!='linux' or not DIGEST.fullmatch(found[0].get('Id','')):raise ValueError('fixed role platform mismatch')

def release_tag(event,ref):
 if event=='push' and ref=='refs/heads/master':return 'master'
 return None

def make_index(sha,descriptors):
 if sorted(x['architecture'] for x in descriptors)!=['amd64','arm64']:raise ValueError('two unique platforms required')
 return {'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','annotations':{'org.opencontainers.image.source':'https://github.com/sweetpoints/gatebeam','org.opencontainers.image.revision':sha},'manifests':[{'mediaType':x['mediaType'],'digest':x['digest'],'size':x['size'],'platform':{'os':'linux','architecture':x['architecture']}} for x in sorted(descriptors,key=lambda x:x['architecture'])]}
