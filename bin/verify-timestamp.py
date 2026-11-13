#!/usr/bin/python3
"""Verify package RFC3161 evidence with an independently trusted provider root bundle."""
import argparse,hashlib,json,re,tarfile,tempfile
from pathlib import Path
from tsa_core import verify_response,TSAError

def verify(package,proof,roots):
 h=hashlib.sha256()
 with open(package,'rb') as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 sha=h.hexdigest()
 with tempfile.TemporaryDirectory(prefix='fls-ts-proof-') as tmp:
  root=Path(tmp)
  with tarfile.open(proof,'r:gz') as t:
   members=t.getmembers();names=[m.name for m in members];expected={'request.tsq','response.tsr','roots.pem','chain.pem','revocation.crl','verification.json'}
   if set(names)!=expected or len(names)!=len(expected) or any(not m.isfile() or m.size>4*1024*1024 for m in members):raise TSAError('unsafe_proof_package')
   for m in members:(root/m.name).write_bytes(t.extractfile(m).read())
  metadata=json.loads((root/'verification.json').read_text())
  if metadata['package_sha256']!=sha or metadata['package_filename']!=Path(package).name:raise TSAError('package_imprint_mismatch')
  result=verify_response((root/'request.tsq').read_bytes(),(root/'response.tsr').read_bytes(),Path(roots).read_bytes(),root,sha,metadata['provider'],online=False)
  return {'verified':True,**result,'package_filename':Path(package).name,'offline_revocation_at_stamp_time':True}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('package');p.add_argument('proof');p.add_argument('--ca-file',required=True);a=p.parse_args();print(json.dumps(verify(a.package,a.proof,a.ca_file),ensure_ascii=False))
