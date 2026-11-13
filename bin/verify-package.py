#!/usr/bin/python3
"""Verify an FLS package without extraction. Supply a trusted public key from outside it."""
import argparse,base64,hashlib,json,re,tarfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization

def canonical(m):return json.dumps(m,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def verify(path,public_key):
 key=serialization.load_pem_public_key(Path(public_key).read_bytes())
 with tarfile.open(path,'r:gz') as t:
  entries=t.getmembers();names=[m.name for m in entries]
  if len(names)!=len(set(names)) or len(names)!=5:raise ValueError('Unexpected or duplicate package entries')
  if any(not m.isfile() or '/' in m.name or m.size>100*1024**3 for m in entries):raise ValueError('Unsafe package entry')
  def small(name):
   m=t.getmember(name)
   if m.size>32*1024**2:raise ValueError('Metadata too large')
   return t.extractfile(m).read()
  envelope=json.loads(small('manifest.json'));m=envelope['manifest']
  if not re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',m['source_file']):raise ValueError('Invalid source filename')
  expected={m['source_file'],'manifest.json','chain.jsonl','archive-public-key.pem','README.txt'}
  if set(names)!=expected:raise ValueError('Unexpected file set')
  key.verify(base64.b64decode(envelope['signature'],validate=True),canonical(m))
  previous='0'*64;last=None
  for line in small('chain.jsonl').splitlines():
   item=json.loads(line);cm=item['manifest'];key.verify(base64.b64decode(item['signature'],validate=True),canonical(cm))
   if cm['previous_manifest_sha256']!=previous:raise ValueError('Broken manifest chain')
   if last and cm['source_file']<=last['source_file']:raise ValueError('Chain order invalid')
   previous=hashlib.sha256(canonical(cm)).hexdigest();last=cm
  if last!=m:raise ValueError('Chain does not end at this manifest')
  h=hashlib.sha256();size=rows=0
  f=t.extractfile(m['source_file'])
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b);size+=len(b);rows+=b.count(b'\n')
  if (h.hexdigest(),size,rows)!=(m['sha256'],m['bytes'],m['rows']):raise ValueError('Raw log digest, size or record count mismatch')
  return {'verified':True,'source_file':m['source_file'],'rows':rows,'bytes':size,'sha256':h.hexdigest(),'manifest_sha256':hashlib.sha256(canonical(m)).hexdigest(),'signed_at':m['signed_at'],'qualified_timestamp':False,'chain_manifests':len(small('chain.jsonl').splitlines())}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('package');p.add_argument('--public-key',required=True);a=p.parse_args()
 print(json.dumps(verify(a.package,a.public_key),ensure_ascii=False))
