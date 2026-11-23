import tempfile
import unittest
from pathlib import Path
from ci import sha_file,write

class BindingTests(unittest.TestCase):
 def test_each_matrix_producer_emits_both_keys_with_only_its_own_digest(self):
  from ci_bindings import emit
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   for arch,other in (('amd64','arm64'),('arm64','amd64')):
    manifest=root/'build'/arch/'bundle.json';write(manifest,{'ci_context':{'architecture':arch}})
    output=root/(arch+'.outputs');emit('build',arch,root=root,output=output)
    values=dict(line.split('=',1) for line in output.read_text().splitlines())
    self.assertEqual(values,{arch+'_sha256':sha_file(manifest),other+'_sha256':''})

 def test_missing_or_changed_independent_digest_is_rejected(self):
  from ci_bindings import verify_manifest
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'bundle.json';write(path,{'content':'original'});trusted=sha_file(path)
   verify_manifest(path,trusted)
   write(path,{'content':'self-consistent replacement'})
   for expected in ('',None,'f'*64,trusted):
    with self.subTest(expected=expected),self.assertRaises(ValueError):verify_manifest(path,expected)
