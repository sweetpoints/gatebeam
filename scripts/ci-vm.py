#!/usr/bin/env python3
"""Execute a named acceptance group in a fresh target Linux guest."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
from acceptance_phases import EXECUTION_GROUPS,ci_context
from ci import ARCHES,OUT,ROOT,head,write
from ci_artifacts import read_build
from ci_bindings import required_digest,verify_manifest
from ci_environment import IMAGE,load_guest
from ci_registry import block_origins

GUEST_CPUS={'amd64':'Haswell-noTSX','arm64':'neoverse-n1'}


def checkpoint():
 spec=importlib.util.spec_from_file_location('checkpoint',Path(__file__).with_name('ci-checkpoint.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def vm_command(arch,work,results):
 if arch not in ARCHES:raise ValueError('unsupported guest architecture')
 binary,machine,console={'amd64':('qemu-system-x86_64','q35','ttyS0'),'arm64':('qemu-system-aarch64','virt','ttyAMA0')}[arch]
 return [binary,'-machine',machine,'-accel','tcg,thread=multi','-cpu',GUEST_CPUS[arch],'-smp','4','-m','8192','-display','none','-monitor','none','-serial','stdio','-no-reboot','-kernel',str(work/'vmlinuz'),'-initrd',str(work/'initrd.img'),'-append','root=/dev/vda rw console='+console+' init=/gatebeam-init oops=panic panic=-1','-drive','file='+str(work/'rootfs.ext4')+',format=raw,if=virtio','-netdev','user,id=n0','-device','virtio-net-pci,netdev=n0','-object','rng-random,filename=/dev/urandom,id=rng0','-device','virtio-rng-pci,rng=rng0','-virtfs','local,path='+str(results)+',mount_tag=results,security_model=none,id=results']


def check_guest_exit(serial,group):
 lines=serial.replace('\r','').splitlines()
 if any(marker in serial for marker in ('Internal error: Oops:','Kernel panic - not syncing:')):
  raise ValueError('guest kernel failed; acceptance is incomplete')
 if group not in EXECUTION_GROUPS or [l for l in lines if l.startswith('GATEBEAM_GROUP_EXIT=')]!=['GATEBEAM_GROUP_EXIT='+group+':0'] or [l for l in lines if l.startswith('GATEBEAM_VM_EXIT=')]!=['GATEBEAM_VM_EXIT=0']:
  raise ValueError('guest did not complete its actual test group')


def execute(args,timeout):
 subprocess.run(args,cwd=ROOT,timeout=timeout,check=True)


def accept(arch,group):
 if sys.platform!='linux' or arch not in ARCHES:raise ValueError('explicit Linux target required')
 if group not in EXECUTION_GROUPS:raise ValueError('explicit test group required')
 sha=head();context=ci_context(sha,arch);work=ROOT/'.work/vm';work.mkdir(parents=True,exist_ok=True)
 output=OUT/'vm';results=output/'results';results.mkdir(parents=True)
 build_folder=OUT/'build'/arch;build_digest=required_digest('GATEBEAM_CI_BUILD_SHA256');verify_manifest(build_folder/'bundle.json',build_digest)
 bundle=read_build(build_folder,context)
 runner=os.environ.get('GATEBEAM_CI_RUNNER_IMAGE','');image=os.environ.get('GATEBEAM_CI_GUEST_IMAGE','')
 if runner!=bundle['environment_image']:raise ValueError('native environment changed within this run')
 if not IMAGE.fullmatch(image):raise ValueError('independent pinned guest environment required')
 record={'group':group,'ci_context':context,'environment_image':image,'runner_environment':runner,'build_manifest_sha256':build_digest}
 write(results/'run.json',record)
 shutil.copytree(build_folder,results/'build')
 report={'source_commit':sha,'architecture':arch,'ci_context':context,'group':group,'execution':'software-emulated-vm','complete':False,'host_machine':os.uname().machine,'guest_cpu_model':GUEST_CPUS[arch],'runner_environment':runner,'environment_image':image,'group_complete':False}
 write(output/'execution.json',report)
 environment=load_guest(image,arch,work);report['environment_version']=environment['version'];write(output/'execution.json',report)
 source_bundle=work/'source.bundle';execute(['git','-C',str(ROOT),'bundle','create',str(source_bundle),'HEAD'],120)
 rootfs=work/'rootfs';rootfs.mkdir();execute(['tar','-xzf',str(work/'rootfs.tar.gz'),'-C',str(rootfs)],300)
 for name in ('proc','sys','dev','boot'):(rootfs/name).mkdir(exist_ok=True)
 block_origins(rootfs/'etc/hosts')
 execute(['git','clone',str(source_bundle),str(rootfs/'workspace')],120)
 execute(['git','-C',str(rootfs/'workspace'),'checkout','--detach',sha],30)
 for source,target in [('init.sh','gatebeam-init'),('full.sh','gatebeam-run')]:
  shutil.copy2(ROOT/'deploy/ci/vm'/source,rootfs/target);(rootfs/target).chmod(0o755)
 disk=work/'rootfs.ext4'
 with disk.open('wb') as stream:stream.truncate(64*1024**3)
 execute(['mkfs.ext4','-q','-F','-d',str(rootfs),str(disk)],600)
 shutil.rmtree(rootfs);(work/'rootfs.tar.gz').unlink()
 serial=output/'serial.log';serial.touch()
 try:
  with serial.open('wb') as log:
   tail=subprocess.Popen(['tail','-f',str(serial)])
   try:subprocess.run(vm_command(arch,work,results),stdout=log,stderr=subprocess.STDOUT,timeout=8400,check=True)
   finally:tail.terminate();tail.wait(timeout=10)
 finally:
  if (results/'groups').is_dir():shutil.copytree(results/'groups',OUT/'groups',dirs_exist_ok=True)
 check_guest_exit(serial.read_text(errors='replace'),group)
 if head()!=sha:raise ValueError('source changed during acceptance')
 checkpoint().read_group(OUT/'groups'/group/arch,group,build_folder,context,bundle,image)
 report['group_complete']=True
 write(output/'execution.json',report)


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('architecture',choices=ARCHES);parser.add_argument('--group',required=True,choices=list(EXECUTION_GROUPS));options=parser.parse_args()
 accept(options.architecture,options.group)
