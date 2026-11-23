import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

spec=importlib.util.spec_from_file_location('duckdb_install',Path(__file__).with_name('install-duckdb.py'))
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class DownloadTests(unittest.TestCase):
 def test_gateway_failures_retry_but_integrity_still_fails_closed(self):
  error=HTTPError('https://example.test/fixed',504,'Gateway timeout',{},None)
  with patch.object(installer.urllib.request,'urlopen',side_effect=error) as request, patch.object(installer.time,'sleep'):
   with self.assertRaises(HTTPError):installer.fetch('https://example.test/fixed')
   self.assertEqual(request.call_count,3)
  with self.assertRaises(ValueError):installer.verified(b'tampered','0'*64)
 def test_cli_uses_provider_supported_client_with_bounded_artifact(self):
  calls=[]
  def execute(args,**kwargs):
   calls.append((args,kwargs));Path(args[args.index('--output')+1]).write_bytes(b'pinned-archive')
  with patch.object(installer.subprocess,'run',side_effect=execute):
   self.assertEqual(installer.fetch_cli('https://install.duckdb.org/fixed'),b'pinned-archive')
  args,options=calls[0]
  self.assertEqual(args[0],'curl');self.assertIn('--fail',args);self.assertIn('--max-filesize',args)
  self.assertTrue(options['check']);self.assertEqual(options['timeout'],100)
 def test_permanent_http_failure_is_not_retried(self):
  error=HTTPError('https://example.test/fixed',404,'Not found',{},None)
  with patch.object(installer.urllib.request,'urlopen',side_effect=error) as request:
   with self.assertRaises(HTTPError):installer.fetch('https://example.test/fixed')
   self.assertEqual(request.call_count,1)

if __name__=='__main__':unittest.main()
