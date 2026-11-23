"""Producer digests travel through Actions outputs, outside mutable artifacts."""
import argparse
import os
from pathlib import Path
import re
from acceptance_phases import GROUPS
from ci import ARCHES,OUT,load,sha_file


def required_digest(name):
 value=os.environ.get(name,'')
 if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value):raise ValueError('independent producer digest required: '+name)
 return value


def verify_manifest(path,expected):
 if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('independent producer digest required')
 path=Path(path);load(path)  # Bound and reject symlinks before hashing the JSON.
 if sha_file(path)!=expected:raise ValueError('artifact differs from independent producer digest')


def emit(kind,arch,group=None,*,root=OUT,output=None):
 if arch not in ARCHES or kind not in ('build','group','accepted'):raise ValueError('explicit producer kind and architecture required')
 if kind=='group':
  if group not in GROUPS:raise ValueError('explicit test group required')
  path=Path(root)/'groups'/group/arch/'group.json'
 else:
  path=Path(root)/kind/arch/({'build':'bundle.json','accepted':'accepted.json'}[kind])
 record=load(path)
 if record.get('ci_context',{}).get('architecture')!=arch:raise ValueError('producer manifest targets another architecture')
 digest=sha_file(path);target=output or os.environ.get('GITHUB_OUTPUT')
 if not target:raise ValueError('Actions output file required')
 with Path(target).open('a') as stream:
  # The workflow merges nonempty matrix values; every instance emits both keys.
  for name in ('amd64','arm64'):stream.write(name+'_sha256='+ (digest if name==arch else '')+'\n')


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('kind',choices=['build','group','accepted'])
 parser.add_argument('--arch',required=True,choices=ARCHES)
 parser.add_argument('--group',choices=list(GROUPS))
 options=parser.parse_args();emit(options.kind,options.arch,options.group)
