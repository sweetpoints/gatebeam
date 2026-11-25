#!/usr/bin/env python3
"""Validate explicit prebuilt/owned inputs before starting any fixture resource."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

root=pathlib.Path(__file__).resolve().parent.parent
def load(path):
    p=pathlib.Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>1048576:
        raise SystemExit('regular bounded fixture input required')
    return json.loads(p.read_bytes())
manifest,nodes,budget=map(load,sys.argv[1:])
if nodes!=load(root/'tests/fixtures/multinode/config.json'):
    raise SystemExit('only the explicit isolated multinode fixture is supported; no production hosts')
if budget!=load(root/'tests/fixtures/multinode/budget.json'):
    raise SystemExit('fixture resource budget changed; review the maintained budget separately')
roles=['edge','api','worker','ca','query']
artifacts=manifest.get('artifacts',[])
if len(artifacts)!=len(roles):raise SystemExit('five prebuilt artifacts required')
for role in roles:
    tag=f'gatebeam-{role}:local'
    found=[a for a in artifacts if tag in a.get('RepoTags',[])]
    if len(found)!=1 or not re.fullmatch('sha256:[0-9a-f]{64}',found[0].get('Id','')):
        raise SystemExit('missing fixed role artifact')
    actual=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
    if actual!=found[0]['Id']:raise SystemExit('local image differs from explicit manifest')
    if role == 'ca':
        help_text=subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--user','101:101','--cap-drop','ALL',tag,'--help'],timeout=15,text=True)
        if 'gatebeam-ca <serve|' not in help_text:
            raise SystemExit('CA image must run the independent service')
        continue
    result=subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--user','101:101','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','64m','--pids-limit','32','--entrypoint','/usr/local/bin/gatebeam',tag,'--runtime-contract'],timeout=15,text=True)
    contract=json.loads(result)
    if contract.get('configuration_format')!=2 or contract.get('runtime_protocol')!=1 or contract.get('boot_format')!=1 or not (0<contract.get('schema_min',0)<=27<=contract.get('schema_max',0)) or not (0<contract.get('role_min',0)<=7<=contract.get('role_max',0)):
        raise SystemExit('prebuilt role contract does not support this fixture')
binary=root/'.work/build/gatebeam'
if not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest()!=manifest.get('binary_sha256'):
    raise SystemExit('local binary does not match manifest; build the final images first')
print('Verified five fixed prebuilt images, offline contracts, isolated nodes and unchanged budgets')
