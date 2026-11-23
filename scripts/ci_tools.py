"""Check source tool contracts against the selected immutable CI environment."""
import re
import subprocess
from pathlib import Path
from ci import ROOT,load,sha_file


def version(value,prefix=''):
 match=re.fullmatch(re.escape(prefix)+r'(\d+)\.(\d+)\.(\d+)',value)
 if not match:raise ValueError('explicit stable tool version required')
 return tuple(map(int,match.groups()))


def validate_tools(go_mod,package,actual):
 required=re.search(r'^go (\d+\.\d+\.\d+)$',go_mod,re.M)
 node=re.fullmatch(r'>=(\d+\.\d+\.\d+) <(\d+)',package.get('engines',{}).get('node',''))
 if not required or version(actual['go'],'go')<version(required[1]):raise ValueError('CI Go SDK is older than go.mod; rebuild the fixed environment')
 for preferred in re.findall(r'^[ \t]*toolchain[ \t]+(\S+)',go_mod,re.M):
  if preferred!='default' and version(actual['go'],'go')<version(preferred,'go'):raise ValueError('CI Go SDK is older than the requested toolchain; rebuild the fixed environment')
 if not node or not version(node[1])<=version(actual['node'],'v')<(int(node[2]),0,0):raise ValueError('CI Node does not satisfy package.json; rebuild the fixed environment')
 if package.get('packageManager')!='pnpm@'+actual['pnpm'] or package.get('devDependencies',{}).get('@playwright/test')!=actual['playwright']:
  raise ValueError('CI pnpm/browser version differs from source; rebuild the fixed environment')


def verify_installers(root,environment):
 for name in ('install-duckdb.py','install-pnpm.mjs'):
  source=Path(root)/'scripts'/name;installed=Path(environment)/name
  if source.is_symlink() or installed.is_symlink() or not source.is_file() or not installed.is_file() or sha_file(source)!=sha_file(installed):
   raise ValueError('fixed CI environment installer contract differs from source; rebuild the environment')


def verify_tools(*,root=ROOT,environment=Path('/opt/ci')):
 verify_installers(root,environment)
 def output(args):return subprocess.check_output(args,text=True,timeout=30).strip()
 actual={'go':output(['go','env','GOVERSION']),'node':output(['node','--version']),'pnpm':output(['pnpm','--version']),'playwright':load('/opt/ci-browser/node_modules/@playwright/test/package.json')['version']}
 validate_tools((root/'go.mod').read_text(),load(root/'web/package.json'),actual)
