#!/usr/bin/env python3
"""Prepare only this fresh guest's dependencies, then execute its named group."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import time
from acceptance_phases import EXECUTION_GROUPS,ci_context,snapshot_images,validate_group
from ci import ROOT,OUT,head,load,sha_file,write
from ci_artifacts import import_build,read_build,test_inputs,validate_live
from ci_environment import IMAGE
from ci_tools import verify_tools
from ci_bindings import verify_manifest


def command(args,timeout=3600,*,stage):
 started=time.monotonic();print('START '+stage,flush=True)
 subprocess.run(args,cwd=ROOT,timeout=timeout,check=True)
 print('DONE '+stage+' elapsed='+str(round(time.monotonic()-started,3))+'s',flush=True)


def context_for(architecture,record):
 supplied=record.get('ci_context',{})
 for variable,key in [('GATEBEAM_CI_RUN_ID','run_id'),('GATEBEAM_CI_RUN_ATTEMPT','run_attempt'),('CI_COMMIT_SHA','source_commit')]:
  value=supplied.get(key)
  if not isinstance(value,str):raise ValueError('explicit source preparation context required')
  os.environ[variable]=value
 context=ci_context(head(),architecture)
 if context!=supplied:raise ValueError('guest source differs from current run')
 verify_manifest('/results/build/bundle.json',record.get('build_manifest_sha256'))
 if not isinstance(record.get('environment_image'),str) or not IMAGE.fullmatch(record['environment_image']):raise ValueError('pinned guest environment required')
 os.environ['GOTOOLCHAIN']='local';verify_tools()
 os.environ.update(GATEBEAM_TARGET_ARCH=architecture,GATEBEAM_CI_BUILD_INPUT='/results/build',GATEBEAM_CI_BUILD_BUNDLE_SHA256=record['build_manifest_sha256'])
 return context


def prepare_dependencies(context,record):
 build_folder=Path('/results/build')
 test_inputs(build_folder,context,record['build_manifest_sha256'],ROOT/'.work/build',web=True)
 target=ROOT/'web/dist'
 if target.exists():shutil.rmtree(target)
 shutil.copytree(ROOT/'.work/build/web-dist',target)
 os.environ['GOPROXY']='https://goproxy.cn'
 command(['go','mod','download'],stage='dependencies/go-mod')
 command(['pnpm','--dir','web','install','--frozen-lockfile','--store-dir',str(ROOT/'.work/pnpm-store'),'--registry','https://registry.npmmirror.com'],stage='dependencies/pnpm')
 command(['python3','scripts/ci-pull-images.py'],stage='dependencies/runtime-images')


def verify(architecture,record):
 context=context_for(architecture,record);group=record.get('group')
 if group not in EXECUTION_GROUPS:raise ValueError('explicit named test group required')
 build_folder=Path('/results/build');bundle=read_build(build_folder,context)
 if bundle['environment_image']!=record.get('runner_environment'):raise ValueError('build environment changed after input selection')
 import_build(build_folder,context)
 prepare_dependencies(context,record)
 before=snapshot_images();validate_live(before,bundle)
 # Preserve the original runtime fixture's explicit, actual-image manifest.
 write(ROOT/'.work/artifacts/manifest.json',{'source_commit':context['source_commit'],'source_dirty':False,'binary_sha256':bundle['programs']['gatebeam'],'artifacts':before})
 os.environ.update(GATEBEAM_ACCEPTANCE_GROUP=group,GATEBEAM_TEST_QUERY_IMAGE='gatebeam-query:local')
 code=subprocess.call(['sh','scripts/check-system.sh','full'],cwd=ROOT)
 after=snapshot_images();validate_live(after,bundle)
 if [(i['role'],i['Id']) for i in before]!=[(i['role'],i['Id']) for i in after] or head()!=context['source_commit']:raise ValueError('test group changed frozen images or source')
 result=load(ROOT/'.work/system-acceptance/results.json');validate_group(result,group,context,require_success=False)
 folder=OUT/'groups'/group/architecture;folder.mkdir(parents=True)
 shutil.copy2(ROOT/'.work/system-acceptance/results.json',folder/'results.json')
 write(folder/'group.json',{'schema_version':2,'group':group,'ci_context':context,'build_bundle_sha256':sha_file(build_folder/'bundle.json'),'environment_image':record['environment_image'],'results_sha256':sha_file(folder/'results.json'),'images_before':before,'images_after':after})
 print('GATEBEAM_GROUP_EXIT='+group+':'+str(code),flush=True)
 return code


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--arch',required=True,choices=['amd64','arm64']);options=parser.parse_args()
 record=load('/results/run.json')
 raise SystemExit(verify(options.arch,record))
