#!/usr/bin/env python3
"""Prepare immutable guest dependencies; never changes functional gate clocks."""
import subprocess
import time
from pathlib import Path
import re

from ci_dependencies import IMAGES


def report_failure(path=Path('/tmp/dockerd.log')):
 """Classify bounded existing guest logs; never echo URLs, bodies or headers."""
 try:
  with path.open('rb') as log:
   log.seek(0,2);log.seek(max(0,log.tell()-32768))
   lines=log.read(32768).decode(errors='replace').splitlines()
 except OSError:
  print('PREPARE Docker failure evidence unavailable',flush=True)
  return
 seen=set()
 for line in reversed(lines):
  text=line.lower()
  if not any(v in text for v in ('registry','pull','endpoint')) or not any(v in text for v in ('error','failed','timeout')):continue
  endpoint='mirror' if '172.17.0.1:5005' in text else 'origin' if 'registry-1.docker.io' in text else 'other'
  status=re.search(r'status(?: code)?\s*[=:]?\s*([1-5][0-9]{2})',text)
  status=int(status[1]) if status else 0
  reason='unclassified'
  for fragment,label in (('tls handshake timeout','tls-timeout'),('x509:','tls-validation'),('connection refused','connection-refused'),('no such host','dns'),('timeout','timeout'),('deadline exceeded','timeout'),('no matching manifest','platform-missing'),('manifest unknown','manifest-missing'),('eof','connection-closed')):
   if fragment in text:reason=label;break
  if reason=='unclassified' and status:reason='http-status'
  event=(endpoint,reason,status)
  if event in seen:continue
  seen.add(event)
  print('PREPARE Docker pull failure: endpoint='+endpoint+' reason='+reason+' status='+str(status),flush=True)
  if len(seen)==8:break
 if not seen:print('PREPARE Docker failure evidence has no registry error classification',flush=True)


def pull(image):
 for attempt in range(1,4):
  print('PREPARE fixed dependency '+image+' attempt='+str(attempt),flush=True)
  try:
   subprocess.run(['docker','pull','--quiet',image],timeout=300,check=True)
   return
  except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
   if attempt==3:
    report_failure()
    raise
   time.sleep(attempt)

if __name__=='__main__':
 for image in IMAGES:pull(image)
