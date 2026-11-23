import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class PullAuthenticationTests(unittest.TestCase):
 def test_public_and_private_modes_isolate_ambient_authentication(self):
  from ci_registry import pull_environment
  for private in (False,True):
   with self.subTest(private=private),tempfile.TemporaryDirectory() as td:
    ambient=Path(td);(ambient/'config.json').write_text('{"auths":{"other.example":{"auth":"ambient"}}}');(ambient/'regctl.json').write_text('{"hosts":{"other.example":{"user":"ambient"}}}')
    values={'GATEBEAM_CI_PULL_REGISTRY':'registry.example' if private else '', 'GATEBEAM_CI_PULL_USERNAME':'gatebeam_ci_tools' if private else '', 'GATEBEAM_CI_PULL_TOKEN':'unit-read-only-token' if private else '', 'DOCKER_CONFIG':str(ambient),'REGCTL_CONFIG':str(ambient/'regctl.json')}
    with patch.dict(os.environ,values):
     before=dict(os.environ)
     with pull_environment() as env:
      self.assertEqual(dict(os.environ),before)
      directory=Path(env['DOCKER_CONFIG']);config=directory/'config.json'
      self.assertNotEqual(directory,ambient);self.assertNotEqual(env['REGCTL_CONFIG'],str(ambient/'regctl.json'))
      self.assertEqual(json.loads(Path(env['REGCTL_CONFIG']).read_text()),{})
      self.assertEqual(Path(env['REGCTL_CONFIG']).stat().st_mode&0o777,0o600)
      payload=json.loads(config.read_text())
      if private:
       self.assertEqual(set(payload['auths']),{'registry.example'})
       self.assertEqual(base64.b64decode(payload['auths']['registry.example']['auth']).decode(),'gatebeam_ci_tools:unit-read-only-token')
      else:self.assertEqual(payload,{'auths':{}})
      self.assertEqual(config.stat().st_mode&0o777,0o600)
     self.assertFalse(directory.exists());self.assertTrue((ambient/'config.json').exists())

 def test_incomplete_identity_fails_without_attempting_a_pull(self):
  from ci_registry import pull_environment
  for values in ({'GATEBEAM_CI_PULL_USERNAME':'owner','GATEBEAM_CI_PULL_TOKEN':''},{'GATEBEAM_CI_PULL_USERNAME':'','GATEBEAM_CI_PULL_TOKEN':'secret'}):
   with patch.dict(os.environ,values),self.assertRaises(ValueError):
    with pull_environment():self.fail('incomplete credential was accepted')

 def test_private_configuration_is_removed_when_the_pull_raises(self):
  from ci_registry import pull_environment
  for private in (False,True):
   values={'GATEBEAM_CI_PULL_REGISTRY':'registry.example' if private else '', 'GATEBEAM_CI_PULL_USERNAME':'gatebeam_ci_tools' if private else '', 'GATEBEAM_CI_PULL_TOKEN':'unit-read-token' if private else ''}
   with self.subTest(private=private),patch.dict(os.environ,values):
    with self.assertRaises(RuntimeError):
     with pull_environment() as env:
      directory=Path(env['DOCKER_CONFIG']);raise RuntimeError('enclosed operation failed')
    self.assertFalse(directory.exists())

if __name__=='__main__':unittest.main()
