import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

class PullTests(unittest.TestCase):
 def module(self):
  spec=importlib.util.spec_from_file_location('ci_pull',Path(__file__).with_name('ci-pull-images.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 def test_transient_pull_retries_same_fixed_reference(self):
  m=self.module();image='nginx@sha256:'+'a'*64
  with patch.object(m.subprocess,'run',side_effect=[subprocess.CalledProcessError(1,'docker'),None]) as run,patch.object(m.time,'sleep'):
   m.pull(image)
   self.assertEqual(run.call_count,2)
   self.assertEqual(run.call_args_list[0].args[0],['docker','pull','--quiet',image])
   self.assertEqual(run.call_args_list[0],run.call_args_list[1])
   self.assertEqual(run.call_args.kwargs['timeout'],300)
 def test_persistent_failure_is_bounded_and_still_fails(self):
  m=self.module()
  with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('docker',300)) as run,patch.object(m.time,'sleep'),patch.object(m,'report_failure') as evidence,self.assertRaises(subprocess.TimeoutExpired):m.pull('owned@sha256:'+'b'*64)
  self.assertEqual(run.call_count,3);evidence.assert_called_once_with()

 def test_existing_daemon_errors_report_causes_without_urls_or_credentials(self):
  import contextlib,io,tempfile
  m=self.module()
  self.assertTrue(hasattr(m,'report_failure'),'failed pulls lack bounded daemon evidence')
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'dockerd.log'
   secret='owned-private-marker'
   path.write_text('level=info msg="Attempting next endpoint for pull after error" error="Get http://user:'+secret+'@172.17.0.1:5005/v2/private?token='+secret+': i/o timeout"\n'
    +'level=info msg="Attempting next endpoint for pull after error" error="Get https://registry-1.docker.io/v2/?token='+secret+': connection refused"\n'
    +'level=error msg="registry pull failed" error="unexpected status code 503 '+secret+'"\n')
   output=io.StringIO()
   with contextlib.redirect_stdout(output):m.report_failure(path)
   text=output.getvalue()
   self.assertIn('endpoint=mirror reason=timeout',text)
   self.assertIn('endpoint=origin reason=connection-refused',text)
   self.assertIn('status=503',text)
   self.assertNotIn(secret,text);self.assertNotIn('http://',text);self.assertNotIn('https://',text);self.assertNotIn('private?',text)

 def test_daemon_failure_reporting_handles_missing_and_large_logs(self):
  import contextlib,io,tempfile
  m=self.module()
  self.assertTrue(hasattr(m,'report_failure'),'failed pulls lack bounded daemon evidence')
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'dockerd.log';output=io.StringIO()
   with contextlib.redirect_stdout(output):m.report_failure(path)
   self.assertIn('unavailable',output.getvalue())
   path.write_text('unrelated startup data\n'*100000+''.join('level=error msg="registry pull failed" error="unexpected status code '+str(status)+'"\n' for status in range(400,420)))
   output=io.StringIO()
   with contextlib.redirect_stdout(output):m.report_failure(path)
   self.assertEqual(len(output.getvalue().splitlines()),8)


if __name__=='__main__':unittest.main()
