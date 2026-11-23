#!/usr/bin/env python3
"""Assemble five independently bound groups covering the same frozen build."""
import argparse
import json
from pathlib import Path
import re
import shutil
from acceptance_phases import GROUPS,MARKERS,ci_context,merge_results,validate_group
from ci import OUT,head,load,sha_file,validate_receipt,write
from ci_artifacts import checked_file,read_build,validate_live
from ci_environment import IMAGE
from ci_bindings import required_digest,verify_manifest


def read_group(folder,group,build_folder,context,bundle,environment_image):
 folder=Path(folder);proof=load(folder/'group.json')
 if not isinstance(environment_image,str) or not IMAGE.fullmatch(environment_image):raise ValueError('independent pinned guest environment required')
 if proof.get('schema_version')!=2 or proof.get('group')!=group or proof.get('ci_context')!=context or proof.get('build_bundle_sha256')!=sha_file(Path(build_folder)/'bundle.json') or proof.get('environment_image')!=environment_image:
  raise ValueError('foreign test group inputs or environment')
 checked_file(folder/'results.json',proof.get('results_sha256'))
 result=load(folder/'results.json');validate_group(result,group,context)
 before=validate_live(proof.get('images_before',[]),bundle);after=validate_live(proof.get('images_after',[]),bundle)
 if [(i['role'],i['Id']) for i in before]!=[(i['role'],i['Id']) for i in after]:raise ValueError('tested image changed within group')
 return result,proof


def combine_evidence(build_folder,group_folders,context,*,environment_image,require_inputs=True):
 build_folder=Path(build_folder)
 bundle=read_build(build_folder,context,require_docker=require_inputs,require_programs=require_inputs)
 if len(group_folders)!=len(GROUPS):raise ValueError('all named test groups required')
 results=[];evidence=[]
 for group,folder in zip(GROUPS,group_folders):
  result,proof=read_group(folder,group,build_folder,context,bundle,environment_image)
  results.append(result);evidence.append({'group':group,'results_sha256':proof['results_sha256'],'proof_sha256':sha_file(Path(folder)/'group.json')})
 merged=merge_results(results,bundle['stage'],context)
 merged.update(build_bundle_sha256=sha_file(build_folder/'bundle.json'),environment_image=environment_image,group_evidence=evidence)
 validate_receipt(merged,load(build_folder/'build.json'),context['source_commit'],context['architecture'])
 return merged


def validate_assembled_evidence(folder,context,*,environment_image):
 folder=Path(folder)
 expected=combine_evidence(folder,[folder/'evidence'/g for g in GROUPS],context,environment_image=environment_image,require_inputs=False)
 if load(folder/'results.json')!=expected:raise ValueError('assembled results differ from complete group evidence')
 return expected


def assemble(build_folder,group_folders,destination,context,*,environment_image):
 build_folder=Path(build_folder);destination=Path(destination)
 verify_manifest(build_folder/'bundle.json',required_digest('GATEBEAM_CI_BUILD_SHA256'))
 if len(group_folders)!=len(GROUPS):raise ValueError('all named test groups required')
 for group,folder in zip(GROUPS,group_folders):verify_manifest(Path(folder)/'group.json',required_digest('GATEBEAM_CI_'+group.upper()+'_SHA256'))
 result=combine_evidence(build_folder,group_folders,context,environment_image=environment_image)
 if destination.exists():raise ValueError('acceptance destination already exists')
 destination.mkdir(parents=True)
 for name in ('build.json','bundle.json'):shutil.copy2(build_folder/name,destination/name)
 for group,folder in zip(GROUPS,group_folders):
  target=destination/'evidence'/group;target.mkdir(parents=True)
  for name in ('results.json','group.json'):shutil.copy2(Path(folder)/name,target/name)
 exports=[]
 for item in load(build_folder/'bundle.json')['artifacts']:
  shutil.copy2(build_folder/item['archive'],destination/item['archive'])
  exports.append({k:v for k,v in item.items() if k not in ('docker_archive','docker_archive_sha256')})
 write(destination/'results.json',result)
 write(destination/'accepted.json',{'source_commit':context['source_commit'],'architecture':context['architecture'],**MARKERS,'ci_context':context,'complete':True,'results_sha256':sha_file(destination/'results.json'),'build_sha256':sha_file(destination/'build.json'),'artifacts':exports})
 try:
  validate_assembled_evidence(destination,context,environment_image=environment_image)
 except Exception:
  (destination/'accepted.json').unlink(missing_ok=True);raise


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['assemble']);parser.add_argument('--arch',required=True,choices=['amd64','arm64']);args=parser.parse_args()
 context=ci_context(head(),args.arch)
 import os
 assemble(OUT/'build'/args.arch,[OUT/'groups'/g/args.arch for g in GROUPS],OUT/'accepted'/args.arch,context,environment_image=os.environ.get('GATEBEAM_CI_GUEST_IMAGE',''))
