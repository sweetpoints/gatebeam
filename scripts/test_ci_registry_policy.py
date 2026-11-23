"""Pure host-file/service contracts; never contacts a registry or mirror."""
from pathlib import Path
import tempfile
import unittest

ORIGINS=('docker.io','registry-1.docker.io','registry.docker.io','index.docker.io')

class RegistryPolicyTests(unittest.TestCase):
 def test_owned_guest_origins_resolve_only_to_loopback_after_mirror_failure(self):
  from ci_registry import block_origins
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'hosts';path.write_text('127.0.0.1 localhost\n203.0.113.9 registry-1.docker.io unrelated.test # retain\n2001:db8::1 Docker.IO. another.test\n')
   block_origins(path);first=path.read_text();block_origins(path);self.assertEqual(first,path.read_text())
   entries=[line.split('#',1)[0].split() for line in first.splitlines()]
   for origin in ORIGINS:
    self.assertEqual([row[0] for row in entries if len(row)>1 and origin in row[1:]],['127.0.0.1'])
   self.assertIn('203.0.113.9 unrelated.test',first)
   self.assertIn('2001:db8::1 another.test',first)
   self.assertIn('127.0.0.1 localhost',first)
 def test_guest_policy_does_not_follow_symlinks(self):
  from ci_registry import block_origins
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);outside=root/'outside';outside.write_text('untouched');path=root/'hosts';path.symlink_to(outside)
   with self.assertRaises(ValueError):block_origins(path)
   self.assertEqual(outside.read_text(),'untouched')
if __name__=='__main__':unittest.main()
