import copy
import unittest

class ToolTests(unittest.TestCase):
 def test_lock_input_change_requires_compatible_frozen_environment(self):
  from ci_tools import validate_tools
  source={'packageManager':'pnpm@12.16.1','engines':{'node':'>=26.13.0 <27'},'devDependencies':{'@playwright/test':'1.65.0'}}
  actual={'go':'go1.27.3','node':'v26.13.0','pnpm':'12.16.1','playwright':'1.65.0'}
  validate_tools('module gatebeam\n\ngo 1.27.0\n',source,actual)
  for key,value in [('go','go1.26.9'),('node','v25.9.0'),('node','v27.0.0'),('pnpm','12.15.0'),('playwright','1.64.0')]:
   with self.subTest(key=key,value=value),self.assertRaises(ValueError):validate_tools('go 1.27.0',source,{**actual,key:value})
  for key,value in [('packageManager','pnpm@12.17.0'),('engines',{'node':'>=27.0.0 <28'}),('devDependencies',{'@playwright/test':'1.66.0'})]:
   with self.subTest(key=key),self.assertRaises(ValueError):validate_tools('go 1.27.0',{**source,key:value},actual)

class GoToolchainTests(unittest.TestCase):
 def test_explicit_toolchain_cannot_silently_use_an_older_fixed_sdk(self):
  from ci_tools import validate_tools
  package={'packageManager':'pnpm@12.16.1','engines':{'node':'>=26.13.0 <27'},'devDependencies':{'@playwright/test':'1.65.0'}}
  actual={'go':'go1.27.3','node':'v26.13.0','pnpm':'12.16.1','playwright':'1.65.0'}
  for directive in ('toolchain go1.27.4','  toolchain go1.27.4 // preferred','toolchain go1.28.0'):
   with self.subTest(directive=directive),self.assertRaisesRegex(ValueError,'rebuild the fixed environment'):
    validate_tools('module gatebeam\n\ngo 1.27.0\n'+directive+'\n',package,actual)
  for directive in ('toolchain go1.27.2','toolchain go1.27.3','toolchain default'):
   validate_tools('module gatebeam\n\ngo 1.27.0\n'+directive+'\n',package,actual)

if __name__=='__main__':unittest.main()

class InstallerContractTests(unittest.TestCase):
 def test_changed_duckdb_version_or_checksum_fails_before_any_tool_execution(self):
  import tempfile
  from pathlib import Path
  from unittest.mock import patch
  import ci_tools
  for change in ('version','checksum','missing','matching'):
   with self.subTest(change=change),tempfile.TemporaryDirectory() as td:
    root=Path(td);source=root/'source';environment=root/'environment';(source/'scripts').mkdir(parents=True);environment.mkdir()
    for name in ('install-duckdb.py','install-pnpm.mjs'):
     data='VERSION=2.0.0\nSHA256=original\n'
     (source/'scripts'/name).write_text(data);(environment/name).write_text(data)
    if change=='version':(source/'scripts/install-duckdb.py').write_text('VERSION=2.1.0\nSHA256=original\n')
    if change=='checksum':(source/'scripts/install-duckdb.py').write_text('VERSION=2.0.0\nSHA256=updated\n')
    if change=='missing':(environment/'install-duckdb.py').unlink()
    if change=='matching':ci_tools.verify_installers(source,environment)
    else:
     with patch.object(ci_tools.subprocess,'check_output') as command,self.assertRaises(ValueError):ci_tools.verify_tools(root=source,environment=environment)
     command.assert_not_called()
