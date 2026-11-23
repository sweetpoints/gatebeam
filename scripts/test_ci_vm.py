import importlib.util
from pathlib import Path
import unittest
from acceptance_phases import GROUPS


class VMTests(unittest.TestCase):
 def module(self):
  spec=importlib.util.spec_from_file_location('ci_vm',Path(__file__).with_name('ci-vm.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

 def test_target_architecture_explicitly_selects_the_software_guest(self):
  m=self.module()
  for arch,binary,console in [('amd64','qemu-system-x86_64','ttyS0'),('arm64','qemu-system-aarch64','ttyAMA0')]:
   args=m.vm_command(arch,Path('/owned/work'),Path('/owned/results'))
   self.assertEqual(args[0],binary);self.assertEqual(args[args.index('-accel')+1],'tcg,thread=multi')
   self.assertEqual(args[args.index('-cpu')+1],{'amd64':'Haswell-noTSX','arm64':'neoverse-n1'}[arch])
   self.assertIn('console='+console,args[args.index('-append')+1])
   self.assertIn('oops=panic',args[args.index('-append')+1].split())
   self.assertIn('panic=-1',args[args.index('-append')+1].split())
   self.assertIn('-no-reboot',args)
   self.assertFalse(any('/dev/kvm' in v or 'docker.sock' in v or 'hostfwd' in v for v in args))
   self.assertIn('mount_tag=results',args[args.index('-virtfs')+1])
  with self.assertRaises(ValueError):m.vm_command('unknown',Path('/work'),Path('/results'))

 def test_only_actual_single_group_success_can_complete_a_guest(self):
  m=self.module();prepared='GATEBEAM_PREPARE_EXIT=0\nGATEBEAM_VM_EXIT=0'
  for group in GROUPS:
   with self.assertRaises(ValueError):m.check_guest_exit(prepared,group)
   m.check_guest_exit('GATEBEAM_GROUP_EXIT='+group+':0\nGATEBEAM_VM_EXIT=0',group)
   for text in ('','GATEBEAM_GROUP_EXIT='+group+':1\nGATEBEAM_VM_EXIT=0','GATEBEAM_GROUP_EXIT='+group+':0\nGATEBEAM_VM_EXIT=1','GATEBEAM_GROUP_EXIT='+group+':0\nGATEBEAM_GROUP_EXIT='+group+':0\nGATEBEAM_VM_EXIT=0'):
    with self.assertRaises(ValueError):m.check_guest_exit(text,group)

 def test_guest_kernel_oops_cannot_be_accepted_even_with_success_markers(self):
  m=self.module()
  for failure in ('Internal error: Oops: 0000000096000004 [#1] SMP','Kernel panic - not syncing: Fatal exception'):
   with self.subTest(failure=failure),self.assertRaises(ValueError):
    m.check_guest_exit('[ 1356.65] '+failure+'\nGATEBEAM_GROUP_EXIT=runtime:0\nGATEBEAM_VM_EXIT=0','runtime')


 def test_missing_independent_input_digests_stop_before_loading_the_guest(self):
  import tempfile
  from unittest.mock import patch
  from ci_test_fixtures import make_build,TOOLS,GUEST
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);build,context,_=make_build(root);source=root/'source';source.mkdir()
   environment={'GATEBEAM_CI_RUN_ID':'42','GATEBEAM_CI_RUN_ATTEMPT':'1','GATEBEAM_CI_RUNNER_IMAGE':TOOLS,'GATEBEAM_CI_GUEST_IMAGE':GUEST}
   with patch.object(m.sys,'platform','linux'),patch.object(m,'ROOT',source),patch.object(m,'OUT',root),patch.object(m,'head',return_value=context['source_commit']),patch.dict(m.os.environ,environment,clear=True),patch.object(m,'load_guest',side_effect=RuntimeError('crossed unverified input boundary')) as guest,self.assertRaises(ValueError):
    m.accept('amd64','core')
   guest.assert_not_called()

 def test_missing_guest_identity_is_rejected_before_vm_preparation(self):
  import tempfile
  from unittest.mock import patch
  from ci import sha_file
  from ci_test_fixtures import make_build,TOOLS
  m=self.module()
  for image in ('','guest:latest'):
   with self.subTest(image=image),tempfile.TemporaryDirectory() as td:
    root=Path(td);build,context,_=make_build(root);source=root/'source';source.mkdir()
    environment={'GATEBEAM_CI_RUN_ID':'42','GATEBEAM_CI_RUN_ATTEMPT':'1','GATEBEAM_CI_RUNNER_IMAGE':TOOLS,'GATEBEAM_CI_GUEST_IMAGE':image,'GATEBEAM_CI_BUILD_SHA256':sha_file(build/'bundle.json')}
    with patch.object(m.sys,'platform','linux'),patch.object(m,'ROOT',source),patch.object(m,'OUT',root),patch.object(m,'head',return_value=context['source_commit']),patch.dict(m.os.environ,environment,clear=True),patch.object(m,'load_guest',side_effect=RuntimeError('crossed unverified guest boundary')) as guest:
     try:
      with self.assertRaises(ValueError):m.accept('amd64','core')
     except RuntimeError:self.fail('unbound guest reached VM preparation')
    guest.assert_not_called()


if __name__=='__main__':unittest.main()
