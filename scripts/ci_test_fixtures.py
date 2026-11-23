"""Local unit-test data only; never uploaded or used for runtime acceptance."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
from acceptance_phases import GROUPS,MARKERS
from ci import ROLES,STAGES,sha_file,write
from ci_oci import inspect_oci

TOOLS='registry.example/gatebeam-ci-runner@sha256:'+'e'*64
GUEST='registry.example/gatebeam-ci-guest@sha256:'+'d'*64


def make_build(root,arch='amd64'):
 folder=Path(root)/'build'/arch;folder.mkdir(parents=True)
 context={'repository':'example/gatebeam','workflow':'acceptance.yml','run_id':'42','run_attempt':'1','source_commit':'a'*40,'architecture':arch}
 artifacts=[];images=[]
 for role in ROLES:
  blobs={}
  def blob(value,media):
   raw=json.dumps(value,separators=(',',':')).encode();digest='sha256:'+hashlib.sha256(raw).hexdigest();blobs['blobs/sha256/'+digest[7:]]=raw
   return {'mediaType':media,'digest':digest,'size':len(raw)}
  config=blob({'os':'linux','architecture':arch,'config':{'Labels':{'role':role}},'rootfs':{'type':'layers','diff_ids':[]}},'application/vnd.oci.image.config.v1+json')
  manifest=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':config,'layers':[]},'application/vnd.oci.image.manifest.v1+json')
  blobs['index.json']=json.dumps({'schemaVersion':2,'manifests':[manifest]}).encode();blobs['oci-layout']=b'{"imageLayoutVersion":"1.0.0"}'
  archive=folder/(role+'.oci.tar')
  with tarfile.open(archive,'w') as target:
   for name,data in blobs.items():
    member=tarfile.TarInfo(name);member.size=len(data);target.addfile(member,io.BytesIO(data))
  docker=folder/(role+'.docker.tar');docker.write_bytes(('unit-'+role).encode())
  artifacts.append({**inspect_oci(archive,arch),'role':role,'archive':archive.name,'archive_sha256':sha_file(archive),'docker_archive':docker.name,'docker_archive_sha256':sha_file(docker)})
  images.append({'Id':config['digest'],'RepoTags':['gatebeam-'+role+':local'],'Architecture':arch,'Os':'linux'})
 (folder/'programs').mkdir();programs={}
 for name in ('gatebeam','gatebeam-admin','gatebeam-deploy','gatebeam-deploy-host'):
  data=bytearray(64);data[:6]=b'\x7fELF\x02\x01';data[18:20]={'amd64':62,'arm64':183}[arch].to_bytes(2,'little');(folder/'programs'/name).write_bytes(data);programs[name]=sha_file(folder/'programs'/name)
 with tarfile.open(folder/'web.tar','w') as archive:
  data=b'<html>unit fixture</html>';member=tarfile.TarInfo('index.html');member.size=len(data);archive.addfile(member,io.BytesIO(data))
 write(folder/'build.json',{'source_commit':'a'*40,'source_dirty':False,'artifacts':images,'binary_sha256':programs['gatebeam']})
 bundle={'schema_version':1,'kind':'gatebeam-build','ci_context':context,'environment_image':TOOLS,'build_complete':True,'build_sha256':sha_file(folder/'build.json'),'programs':programs,'web_archive':'web.tar','web_sha256':sha_file(folder/'web.tar'),'artifacts':artifacts,'stage':{'name':'fixed-images','exit_code':0,'execution':'linux-cross-build','seconds':1.2}}
 write(folder/'bundle.json',bundle)
 return folder,context,bundle


def measurement():
 return {'execution':'software-emulated-vm','policy':'software-functional-v1','performance_certification':'not-certified','routes':400,'verified':72,'elapsed_seconds':5.01,'budget_seconds':5,'target_met':False,'functional_verified':400,'functional_batches':50,'full_business_verified':False,'full_failed':True,'full_routes':[{'site_id':'site-'+str(i//8),'host':'host-'+str(i),'sni':'host-'+str(i),'route':'/','outcome':'verified' if i<72 else 'degraded','reason':'' if i<72 else 'verification_budget_exhausted'} for i in range(400)]}


def make_groups(root,context,build_folder,*,environment_image=GUEST):
 build=json.loads((build_folder/'build.json').read_text())
 images=[{'role':r,**next(i for i in build['artifacts'] if 'gatebeam-'+r+':local' in i['RepoTags'])} for r in ROLES]
 folders=[]
 for group,names in GROUPS.items():
  folder=Path(root)/'groups'/group/context['architecture'];folder.mkdir(parents=True);folders.append(folder)
  result={**MARKERS,'source_commit':context['source_commit'],'source_dirty':False,'architecture':context['architecture'],'ci_context':copy.deepcopy(context),'required_stages':list(STAGES),'group':group,'group_stages':list(names),'group_complete':True,'complete':False,'stages':[{'name':n,'exit_code':0} for n in names]}
  if group=='security':result['tls_performance']=measurement()
  write(folder/'results.json',result)
  write(folder/'group.json',{'schema_version':2,'group':group,'ci_context':copy.deepcopy(context),'build_bundle_sha256':sha_file(build_folder/'bundle.json'),'environment_image':environment_image,'results_sha256':sha_file(folder/'results.json'),'images_before':images,'images_after':images})
 return folders


def producer_bindings(build_folder,group_folders):
 values={'GATEBEAM_CI_BUILD_SHA256':sha_file(Path(build_folder)/'bundle.json'),'GATEBEAM_CI_GUEST_IMAGE':GUEST}
 values.update({'GATEBEAM_CI_'+group.upper()+'_SHA256':sha_file(Path(folder)/'group.json') for group,folder in zip(GROUPS,group_folders)})
 return values
