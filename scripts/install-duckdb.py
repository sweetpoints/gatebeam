#!/usr/bin/env python3
"""Fetch pinned official CLI + signed httpfs; validate release digests and LOAD.
Only a build/test prerequisite. Production query execution never downloads.
"""
import gzip, hashlib, io, os, pathlib, platform, subprocess, sys, tarfile, tempfile, time, urllib.error, urllib.request
VERSION = 'v2.0.0'
PINS = {
 'osx-arm64': ('188a36fe8883ef52e69165a0cbb6031ef679c8e6c448a1ce22951964149b7f96', 'c2d72a98ad081bf4d62c908b8d9f60b70ab1b83faa9141fc7e7d53526658761d'),
 'linux-arm64': ('859e1875d2a9515fbb4bf8871061437a14af82320da68c753f094c4b776348fe', '53f7aea1a0448ea62ef9b63f95da37c5766070084f14f14110e275e76382e7b2'),
 'linux-amd64': ('c6507206baf7793c6013dbd82368469a45f20dc0e17a6f92f204602f652ed2bc', '77e6c429aa04f25da7962572f12b19113e0ce46080fa1365ad66017aadcdb68d'),
}
def fetch(url):
 for attempt in range(3):
  try:
   with urllib.request.urlopen(url,timeout=30) as r:
    data=r.read(100*1024*1024+1)
    if len(data)>100*1024*1024:raise ValueError('artifact too large')
    return data
  except urllib.error.HTTPError as error:
   if error.code not in (429,500,502,503,504) or attempt==2:raise
  except (urllib.error.URLError,TimeoutError,ConnectionError):
   if attempt==2:raise
  time.sleep(2**attempt)
def fetch_cli(url):
 # The official installer uses curl. The distributor rejects Python clients
 # with403 on the observed Linux Runner; curl on the same URL returns206.
 # Keep retries/deadlines bounded and validate the original release digest.
 with tempfile.TemporaryDirectory() as directory:
  target=pathlib.Path(directory)/'cli.tar.gz'
  subprocess.run(['curl','--fail','--location','--silent','--show-error','--retry','2','--retry-delay','1','--retry-max-time','90','--connect-timeout','10','--max-time','60','--max-filesize',str(100*1024*1024),'--output',str(target),url],check=True,timeout=100)
  if target.stat().st_size>100*1024*1024:raise ValueError('artifact too large')
  return target.read_bytes()
def verified(data,digest):
 if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('artifact digest mismatch')
 return data
def main():
 root=pathlib.Path(sys.argv[1]).resolve();root.mkdir(parents=True,exist_ok=True)
 name=('osx' if platform.system()=='Darwin' else 'linux')+'-'+({'aarch64':'arm64','arm64':'arm64','x86_64':'amd64'}[platform.machine()])
 cli_pin,extension_pin=PINS[name]
 archive=verified(fetch_cli(f'https://install.duckdb.org/{VERSION}/duckdb-cli-{name}.tar.gz'),cli_pin)
 with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
  members=[m for m in tf.getmembers() if m.name=='duckdb' and m.isfile()]
  if len(members)!=1:raise ValueError('unexpected CLI archive')
  binary=tf.extractfile(members[0]).read()
 (root/'duckdb').write_bytes(binary);(root/'duckdb').chmod(0o755)
 # Documented DuckDB core backup repository; original site may reject CI clients.
 compressed=fetch(f'https://extensions.duckdb-backup.org/{VERSION}/{name.replace("-","_")}/httpfs.duckdb_extension.gz')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
  extension=stream.read(100*1024*1024+1)
 if len(extension)>100*1024*1024:raise ValueError('extension too large')
 extension=verified(extension,extension_pin)
 (root/'httpfs.duckdb_extension').write_bytes(extension)
 # Default DuckDB rejects unsigned/mismatched extensions. Do not pass -unsigned.
 subprocess.run([str(root/'duckdb'),'-no-agent','-batch','-bail','-c',"LOAD '"+str(root/'httpfs.duckdb_extension').replace("'","''")+"';"],check=True,timeout=10)
 print('Verified DuckDB '+VERSION+' and signed matching httpfs ('+name+')')

if __name__=='__main__':main()
