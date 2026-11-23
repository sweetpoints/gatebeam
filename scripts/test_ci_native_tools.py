import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class NativeToolsTests(unittest.TestCase):
 def test_sdk_comes_from_the_verified_guest_for_actual_linux_host(self):
  from ci_native_tools import install
  import ci_native_tools as m
  for host,arch in [('x86_64','amd64'),('aarch64','arm64')]:
   with self.subTest(host=host),tempfile.TemporaryDirectory() as td:
    ref='artifact:sha256:'+'a'*64
    with patch.object(m.sys,'platform','linux'),patch.object(m.platform,'machine',return_value=host),patch.object(m,'load_guest') as guest,patch.object(m.subprocess,'run') as command:
     install(ref,Path(td))
    self.assertEqual(guest.call_args.args[:2],(ref,arch))
    args=command.call_args.args[0]
    self.assertIn('./usr/local/go',args);self.assertNotIn('./opt/pnpm',args)
    self.assertIn('./opt/ci-browser',args)
    self.assertNotIn('curl',args)
