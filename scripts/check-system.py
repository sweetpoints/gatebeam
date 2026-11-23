#!/usr/bin/env python3
"""Run every owned acceptance gate; no stage omission is a passing result."""
import json
import os
import pathlib
import re
import subprocess
import time
from acceptance_budget import aggregate
from ci import validate_software_performance
from acceptance_phases import DUAL_NODE_STAGE, EXECUTION_GROUPS, MULTINODE_SHARDS, ci_context

root = pathlib.Path(__file__).resolve().parent.parent
out = root / '.work' / 'system-acceptance'
out.mkdir(parents=True, exist_ok=True)
(out/'tls-performance.json').unlink(missing_ok=True)
env = os.environ.copy()
env['GATEBEAM_TEST_QUERY_IMAGE'] = 'gatebeam-query:local'
env['GATEBEAM_COMPOSE_EXACT_IMAGES'] = '1'
env['GATEBEAM_ACCEPTANCE_REPORT_DIR'] = str(out)
# Budgets compose existing bounded setup/build commands and per-package90s tests.
# In particular the measured native PKI ~74s package is its own DB stage, rather
# than being appended after all packages inside one global120s watchdog.
stages = [
 ('go-and-architecture', 650, ['scripts/check-go.sh']),
 ('contracts', 300, ['scripts/check-system.sh', 'contracts']),
 ('fixed-images', 1650, ['scripts/build-system.sh']),
 ('core-transactions', 450, ['scripts/check-db.sh', './internal/platform/...', './internal/modules/identity/...', './internal/modules/ingress/...', './internal/integration/...', './internal/modules/deployment/...', './internal/modules/notification/...', './tests/architecture', './tests/integration/publication', './tests/integration/events', './tests/integration/roles', './tests/fixtures/deployment']),
 ('public-client-process-faults', 450, ['scripts/check-pki.sh', 'public-client']),
 ('standard-ca-rotation-restart', 600, ['scripts/check-pki.sh', 'acme']),
 ('owned-dns01', 210, ['scripts/check-dns01.sh']),
 ('native-edge-supervisor', 450, ['scripts/check-edge.sh', 'supervisor']),
 ('archive-query', 420, ['scripts/check-logs.sh']),
 ('backup-recovery', 420, ['scripts/check-backup.sh']),
 ('compose-runtime', 450, ['scripts/check-compose.sh']),
 ('dual-node-runtime-control-upgrade-capacity', 600, ['scripts/check-multinode.sh','--manifest','.work/artifacts/manifest.json','--nodes','tests/fixtures/multinode/config.json','--budget','tests/fixtures/multinode/budget.json']),
 ('browser-auth', 450, ['scripts/check-web.sh', 'auth']),
 ('browser-ingress', 600, ['scripts/check-web.sh', 'ingress']),
 ('browser-pki', 600, ['scripts/check-web.sh', 'pki']),
 ('browser-operations', 750, ['scripts/check-web.sh', 'operations']),
 ('capacity-100k', 910, ['scripts/check-capacity.sh', 'small']),
 ('capacity-1m', 910, ['scripts/check-capacity.sh', 'million']),
 ('capacity-4096', 610, ['scripts/check-capacity.sh', 'maxobjects']),
 ('capacity-near2gib', 910, ['scripts/check-capacity.sh', 'near']),
]
result = {'source_commit': subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'], text=True).strip(), 'source_dirty':bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True).strip()), 'execution':env.get('GATEBEAM_ACCEPTANCE_EXECUTION','native'), 'aggregate_budget_factor':int(aggregate(1)), 'required_stages':[s[0] for s in stages], 'stages':[], 'complete':False}
if result['execution'] == 'native':
    result.update(acceptance_policy='native-full20', performance_certification='route-budget-verified')
if result['execution'] == 'software-emulated-vm':
    result.update(acceptance_policy='software-functional-v1', performance_certification='not-certified')
group = env.get('GATEBEAM_ACCEPTANCE_GROUP','full')
if group != 'full':
    if group not in EXECUTION_GROUPS or result['execution'] != 'software-emulated-vm':
        raise ValueError('only explicit software CI test groups are supported')
    context = ci_context(result['source_commit'],env.get('GATEBEAM_TARGET_ARCH',''))
    result.update(group=group, group_stages=list(EXECUTION_GROUPS[group]), group_complete=False, ci_context=context, architecture=context['architecture'])
    stages = [next(stage for stage in stages if stage[0] == name) for name in EXECUTION_GROUPS[group]]
    if group in MULTINODE_SHARDS:
        suite = MULTINODE_SHARDS[group]
        result['multinode_suite'] = suite
        stages = [(name, budget, command + ['--suite', suite] if name == DUAL_NODE_STAGE else command)
                  for name, budget, command in stages]
receipt = out / 'results.json'
def save():
    receipt.write_text(json.dumps(result, indent=2)+'\n')
save()
keep_going = os.environ.get('GATEBEAM_ACCEPTANCE_KEEP_GOING') == '1'
for name, budget, command in stages:
    base_budget=budget
    budget=aggregate(budget)
    print(f'RUN {name} budget={budget:g}s base_budget={base_budget}s', flush=True)
    start = time.monotonic()
    with (out / (name+'.log')).open('wb') as log:
        code = subprocess.call(['python3', 'scripts/bounded-command.py', str(budget), 'sh', *command], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    if name == 'public-client-process-faults' and code == 0 and result['execution'] == 'software-emulated-vm':
        try:
            measurement = json.loads((out/'tls-performance.json').read_text())
            validate_software_performance(measurement)
            result['tls_performance'] = measurement
        except (OSError, ValueError, TypeError) as error:
            print(f'FAIL software performance evidence: {error}', flush=True)
            code = 1
    elapsed = time.monotonic()-start
    result['stages'].append({'name':name,'base_budget_seconds':base_budget,'budget_seconds':budget,'seconds':round(elapsed,3),'exit_code':code,'log':str(out/(name+'.log'))})
    save()
    print(f'{"PASS" if code == 0 else "FAIL"} {name} elapsed={elapsed:.3f}s log={out/(name+".log")}', flush=True)
    if code and keep_going:
        # Surface a bounded failure excerpt immediately while later gates run;
        # the complete file remains in the guest workspace for this job.
        lines = (out / (name+'.log')).read_text(errors='replace').splitlines()
        print('FAILED STAGE DIAGNOSTICS '+name, flush=True)
        summary = [line for line in lines if line.startswith('START ') or re.search(r'--- FAIL:|_test\.go:\d+:', line)]
        # Large Nginx configuration dumps can otherwise push the actual first
        # assertion out of the tail. Keep the selected assertion summary bounded.
        print('\n'.join(summary[:80])[:32768], flush=True)
        print('\n'.join(lines[-200:])[-65536:], flush=True)
    if code and not keep_going:
        raise SystemExit(code)
success = len(result['stages']) == len(stages) and all(s['exit_code'] == 0 for s in result['stages'])
result['complete'] = group == 'full' and success
if group != 'full':result['group_complete'] = success
save()
if not success:
    raise SystemExit(1)
print(f'Owned {group} tests executed; evidence: {receipt}. This is not CI, publication, production deployment, or real tenant acceptance.', flush=True)
