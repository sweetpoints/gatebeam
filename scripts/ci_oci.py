"""Inspect immutable OCI content without extracting archive paths."""
import hashlib
import json
import re
import tarfile

def inspect_oci(path,arch):
 # Never extract archive paths. Resolve only exact digest-addressed regular blobs.
 with tarfile.open(path,'r:*') as tf:
  members={}
  for m in tf.getmembers():
   name=m.name.removeprefix('./')
   if m.isfile():
    if name in members:raise ValueError('duplicate OCI archive entry')
    members[name]=m
  def data(name,digest=None,size=None):
   m=members.get(name)
   if m is None or m.size>4*1024*1024:raise ValueError('bounded OCI metadata required')
   raw=tf.extractfile(m).read()
   if size is not None and len(raw)!=size:raise ValueError('OCI size mismatch')
   if digest is not None and 'sha256:'+hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('OCI digest mismatch')
   return json.loads(raw)
  def resolve(desc):
   digest=desc.get('digest','')
   if not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):raise ValueError('invalid OCI digest')
   return data('blobs/sha256/'+digest[7:],digest,desc['size'])
  index=data('index.json');descs=index.get('manifests',[])
  if len(descs)!=1:raise ValueError('one platform image required')
  desc=descs[0];manifest=resolve(desc)
  if 'manifests' in manifest:
   if len(manifest['manifests'])!=1:raise ValueError('unexpected OCI index entries')
   desc=manifest['manifests'][0];manifest=resolve(desc)
  config_desc=manifest['config'];config=resolve(config_desc)
  if config.get('os')!='linux' or config.get('architecture')!=arch:raise ValueError('OCI target platform mismatch')
  # Verify every layer as a stream, without retaining image contents in memory.
  for layer in manifest.get('layers',[]):
   digest=layer.get('digest','')
   if not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):raise ValueError('invalid OCI layer digest')
   m=members.get('blobs/sha256/'+digest[7:])
   if m is None or m.size!=layer['size']:raise ValueError('OCI layer size mismatch')
   h=hashlib.sha256()
   with tf.extractfile(m) as stream:
    for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
   if 'sha256:'+h.hexdigest()!=digest:raise ValueError('OCI layer checksum mismatch')
  return {'manifest_digest':desc['digest'],'manifest_size':desc['size'],'mediaType':desc['mediaType'],'config_digest':config_desc['digest'],'os':'linux','architecture':arch}
