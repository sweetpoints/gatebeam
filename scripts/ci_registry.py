"""Fail closed on Docker Hub origin fallback inside task-owned environments."""
from pathlib import Path
from contextlib import contextmanager
import base64
import json
import os
import re
import tempfile

ORIGINS=('docker.io','registry-1.docker.io','registry.docker.io','index.docker.io')


def block_origins(path):
 path=Path(path)
 if path.is_symlink():raise ValueError('regular owned guest hosts file required')
 lines=[]
 for line in path.read_text().splitlines() if path.exists() else []:
  body,separator,comment=line.partition('#');fields=body.split()
  if len(fields)>1:
   aliases=[name for name in fields[1:] if name.lower().rstrip('.') not in ORIGINS]
   if len(aliases)!=len(fields)-1:
    if aliases:lines.append(fields[0]+' '+' '.join(aliases)+((' #'+comment) if separator else ''))
    elif separator:lines.append('#'+comment)
    continue
  lines.append(line)
 # Standard resolver policy: a mirror failure may try these names, but cannot
 # reach an official registry. auth.docker.io remains available for mirror auth.
 lines.append('127.0.0.1 '+' '.join(ORIGINS))
 path.write_text('\n'.join(lines)+'\n')


@contextmanager
def pull_environment():
 """Use only explicitly configured read credentials for private tool images."""
 env=os.environ.copy();username=env.get('GATEBEAM_CI_PULL_USERNAME','');token=env.get('GATEBEAM_CI_PULL_TOKEN','')
 registry=env.get('GATEBEAM_CI_PULL_REGISTRY','')
 if (username or token or registry) and (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?',registry) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',username) or not token or any(ord(c)<32 for c in token)):raise ValueError('complete private tool-image read credentials required')
 with tempfile.TemporaryDirectory(prefix='gatebeam-ci-pull-') as temporary:
  root=Path(temporary);config=root/'config.json'
  payload={'auths':{}}
  if username:payload['auths'][registry]={'auth':base64.b64encode((username+':'+token).encode()).decode()}
  with open(config,'x',opener=lambda path,flags:os.open(path,flags,0o600)) as output:json.dump(payload,output)
  with open(root/'regctl.json','x',opener=lambda path,flags:os.open(path,flags,0o600)) as output:json.dump({},output)
  yield {**env,'DOCKER_CONFIG':str(root),'REGCTL_CONFIG':str(root/'regctl.json')}
