"""Prove emulation only expands explicitly marked aggregate watchdogs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'scripts' / 'aggregate-command.py'
BOUNDED = ROOT / 'scripts' / 'bounded-command.py'

class AggregateBudgetTests(unittest.TestCase):
 def test_emulated_aggregate_can_finish_beyond_native_watchdog(self):
  env={**os.environ,'GATEBEAM_ACCEPTANCE_EXECUTION':'software-emulated-vm'}
  result=subprocess.run([sys.executable,str(HELPER),'0.1',sys.executable,'-c','import time; time.sleep(0.25)'],env=env,capture_output=True,timeout=5)
  self.assertEqual(result.returncode,0,result.stderr.decode())
 def test_native_aggregate_and_unmarked_functional_deadline_still_expire(self):
  for helper,execution in [(HELPER,'native'),(BOUNDED,'software-emulated-vm')]:
   with self.subTest(helper=helper.name):
    result=subprocess.run([sys.executable,str(helper),'0.1',sys.executable,'-c','import time; time.sleep(0.25)'],env={**os.environ,'GATEBEAM_ACCEPTANCE_EXECUTION':execution},capture_output=True,timeout=5)
    self.assertEqual(result.returncode,124,result.stderr.decode())
 def test_only_whole_go_package_timeout_changes_and_arguments_survive(self):
  with tempfile.TemporaryDirectory() as td:
   go=Path(td)/'go';go.write_text('#!'+sys.executable+'\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n');go.chmod(0o755)
   for execution,seconds in [('native','90s'),('software-emulated-vm','1080s')]:
    env={**os.environ,'PATH':td+':'+os.environ['PATH'],'GATEBEAM_ACCEPTANCE_EXECUTION':execution}
    result=subprocess.run([sys.executable,str(HELPER),'120','go','test','-count=1','-timeout','90s','./owned','-args','-request-timeout=5s'],env=env,capture_output=True,text=True,timeout=5)
    self.assertEqual(result.returncode,0,result.stderr)
    self.assertEqual(json.loads(result.stdout),['test','-count=1','-timeout',seconds,'./owned','-args','-request-timeout=5s'])
 def test_container_whole_package_requires_explicit_opt_in(self):
  for opt,expected in [([], '60s'),(['--test-package'],'720s')]:
   result=subprocess.run([sys.executable,str(HELPER),*opt,'5',sys.executable,'-c','import json,sys; print(json.dumps(sys.argv[1:]))','-test.timeout=60s','-request-timeout=5s'],env={**os.environ,'GATEBEAM_ACCEPTANCE_EXECUTION':'software-emulated-vm'},capture_output=True,text=True,timeout=5)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(json.loads(result.stdout),['-test.timeout='+expected,'-request-timeout=5s'])
 def test_unknown_execution_never_silently_expands_deadline(self):
  result=subprocess.run([sys.executable,str(HELPER),'1',sys.executable,'-c','raise SystemExit(0)'],env={**os.environ,'GATEBEAM_ACCEPTANCE_EXECUTION':'typo'},capture_output=True,timeout=5)
  self.assertNotEqual(result.returncode,0)

if __name__=='__main__':unittest.main()
