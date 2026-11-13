"""RFC3161 requests, official ESYA transport, independent chain/revocation checks."""
import base64,datetime as dt,hashlib,http.server,io,json,os,re,secrets,ssl,subprocess,tarfile,tempfile,threading,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
from asn1crypto import tsp,cms,pem
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
UTC=dt.timezone.utc
PROVIDERS={'kamusm':{'production':'http://zd.kamusm.gov.tr','test':'http://tzd.kamusm.gov.tr','domains':['kamusm.gov.tr','tubitak.gov.tr']},'turktrust':{'production':'http://zd.turktrust.com.tr','domains':['turktrust.com.tr','turktrust.tr']}}
class TSAError(Exception):pass

def atomic(path,data,mode=0o640):
 path=Path(path);fd,tmp=tempfile.mkstemp(prefix='.tsa-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,mode);os.replace(tmp,path);d=os.open(path.parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:Path(tmp).unlink(missing_ok=True)
def run(cmd,**kwargs):
 r=subprocess.run(cmd,capture_output=True,timeout=45,**kwargs)
 if r.returncode:raise TSAError('cryptographic_verification_failed')
 return r.stdout

def request_for_digest(sha256,nonce=None):
 nonce=nonce or bytes([secrets.randbelow(127)+1])+os.urandom(15)
 req=tsp.TimeStampReq({'version':'v1','message_imprint':{'hash_algorithm':{'algorithm':'sha256'},'hashed_message':bytes.fromhex(sha256)},'nonce':int.from_bytes(nonce,'big'),'cert_req':True})
 return req.dump(),nonce

def allowed_url(url,domains):
 u=urllib.parse.urlsplit(url);host=(u.hostname or '').lower()
 if u.scheme not in ['http','https'] or u.username or u.password or u.fragment or u.port not in [None,80,443]:raise TSAError('certificate_url_rejected')
 if not any(host==d or host.endswith('.'+d) for d in domains):raise TSAError('certificate_url_rejected')
 return url
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a):return None

def fetch(url,domains,limit=4*1024*1024):
 url=allowed_url(url,domains);opener=urllib.request.build_opener(NoRedirect,urllib.request.ProxyHandler({}))
 with opener.open(url,timeout=20) as r:
  b=r.read(limit+1)
  if len(b)>limit:raise TSAError('certificate_response_too_large')
  return b

def pem_certs(data):
 return [x509.load_pem_x509_certificate(b) for b in re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',data,re.S)]

def verify_response(request,response,roots,work,package_sha256,provider,now=None,fetcher=fetch,domains=None,online=True,request_time=None):
 work=Path(work);now=now or dt.datetime.now(UTC);domains=domains or PROVIDERS[provider]['domains'];req=tsp.TimeStampReq.load(request);resp=tsp.TimeStampResp.load(response)
 if req['message_imprint']['hash_algorithm']['algorithm'].native!='sha256' or req['message_imprint']['hashed_message'].native.hex()!=package_sha256:raise TSAError('request_imprint_mismatch')
 if resp['status']['status'].native not in ['granted','granted_with_mods']:raise TSAError('authority_rejected')
 token=resp['time_stamp_token'];sd=token['content'];info=sd['encap_content_info']['content'].parsed
 if info['message_imprint']['hash_algorithm']['algorithm'].native!='sha256' or info['message_imprint']['hashed_message'].native.hex()!=package_sha256:raise TSAError('response_imprint_mismatch')
 if req['nonce'].native is None or info['nonce'].native!=req['nonce'].native:raise TSAError('nonce_mismatch')
 when=info['gen_time'].native
 if online and abs((when-(request_time or now)).total_seconds())>300:raise TSAError('timestamp_clock_out_of_range')
 certs=[x509.load_der_x509_certificate(c.chosen.dump()) for c in sd['certificates'] if c.name=='certificate'];signers=sd['signer_infos']
 if len(signers)!=1 or signers[0]['sid'].name!='issuer_and_serial_number':raise TSAError('signer_identity_invalid')
 serial=signers[0]['sid'].chosen['serial_number'].native;issuer=signers[0]['sid'].chosen['issuer'].dump()
 leaf=next((x509.load_der_x509_certificate(c.chosen.dump()) for c in sd['certificates'] if c.name=='certificate' and c.chosen.serial_number==serial and c.chosen.issuer.dump()==issuer),None)
 if leaf is None:raise TSAError('signer_certificate_missing')
 rootcerts=pem_certs(roots)
 # Include only chain helpers as untrusted material; independently supplied roots
 # are the only trust anchors. Missing issuer certificates may be fetched from
 # provider-owned AIA locations and still must pass OpenSSL verification.
 for _ in range(4):
  last=certs[-1] if certs else leaf
  missing=next((c for c in certs if c.issuer!=c.subject and not any(i.subject==c.issuer for i in certs+rootcerts)),None)
  if missing is None:break
  try:
   aia=missing.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
   urls=[x.access_location.value for x in aia if x.access_method==x509.oid.AuthorityInformationAccessOID.CA_ISSUERS]
   raw=fetcher(urls[0],domains);extra=x509.load_pem_x509_certificate(raw) if raw.startswith(b'-----') else x509.load_der_x509_certificate(raw);certs.append(extra)
  except Exception:raise TSAError('issuer_certificate_missing')
 chain=b''.join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
 atomic(work/'request.tsq',request);atomic(work/'response.tsr',response);atomic(work/'roots.pem',roots);atomic(work/'chain.pem',chain);atomic(work/'signer.pem',leaf.public_bytes(serialization.Encoding.PEM))
 args=['openssl','ts','-verify','-queryfile',str(work/'request.tsq'),'-in',str(work/'response.tsr'),'-CAfile',str(work/'roots.pem'),'-untrusted',str(work/'chain.pem')]
 args+=['-attime',str(int(when.timestamp()))]
 run(args)
 issuer_cert=next((c for c in certs+rootcerts if c.subject==leaf.issuer),None)
 if issuer_cert is None:raise TSAError('issuer_certificate_missing')
 atomic(work/'issuer.pem',issuer_cert.public_bytes(serialization.Encoding.PEM))
 # A CRL is saved with the evidence so the same check can be repeated offline.
 crlfile=work/'revocation.crl';crl_mode=''
 if online:
  try:
   points=leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value;urls=[n.value for p in points for n in (p.full_name or []) if isinstance(n,x509.UniformResourceIdentifier)]
  except x509.ExtensionNotFound:urls=[]
  for url in urls:
   try:
    data=fetcher(url,domains);crl=x509.load_pem_x509_crl(data) if data.startswith(b'-----') else x509.load_der_x509_crl(data);atomic(crlfile,crl.public_bytes(serialization.Encoding.PEM));crl_mode='crl';break
   except Exception:continue
  if not crl_mode:raise TSAError('revocation_status_unavailable')
 elif not crlfile.is_file():raise TSAError('revocation_evidence_missing')
 crl=x509.load_pem_x509_crl(crlfile.read_bytes())
 last=crl.last_update.replace(tzinfo=UTC);nextupdate=crl.next_update.replace(tzinfo=UTC) if crl.next_update else None
 checked_at=now if online else max(when,last)
 if nextupdate is None or nextupdate<checked_at or last>checked_at+dt.timedelta(minutes=5):raise TSAError('revocation_evidence_stale')
 if crl.issuer!=leaf.issuer or not crl.is_signature_valid(issuer_cert.public_key()):raise TSAError('revocation_signature_invalid')
 if crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None:raise TSAError('signer_revoked')
 # Validate certificate purpose, chain and validity at the signed stamp time.
 # The signed CRL may legitimately have been obtained later during recovery;
 # validate its own interval/signature separately instead of backdating it.
 args=['openssl','verify','-purpose','timestampsign','-CAfile',str(work/'roots.pem'),'-untrusted',str(work/'chain.pem'),'-no-CApath','-no-CAstore','-attime',str(int(when.timestamp())),str(work/'signer.pem')]
 run(args)
 return {'provider':provider,'package_sha256':package_sha256,'stamp_at_utc':when.isoformat(),'policy_oid':info['policy'].native,'serial':str(info['serial_number'].native),'signer_subject':leaf.subject.rfc4514_string(),'signer_sha256':leaf.fingerprint(hashes.SHA256()).hex(),'request_sha256':hashlib.sha256(request).hexdigest(),'response_sha256':hashlib.sha256(response).hexdigest(),'trust_roots_sha256':hashlib.sha256(roots).hexdigest(),'revocation':'signer_crl_good','crl_next_update_utc':nextupdate.isoformat(),'cryptographically_verified':True}

class OfficialRelay:
 """One-use authenticated localhost proxy; never persists credential headers."""
 def __init__(self,endpoint,folder,timeout=30):
  self.endpoint=endpoint;self.folder=Path(folder);self.token=secrets.token_urlsafe(32);self.sent=False;self.mode='stamp';self.timeout=timeout;relay=self
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):self.forward('POST')
   def do_GET(self):
    if relay.mode!='balance':self.send_error(405);return
    self.forward('GET')
   def forward(self,method):
    expected='Basic '+base64.b64encode(('fls:'+relay.token).encode()).decode()
    if not secrets.compare_digest(self.headers.get('Proxy-Authorization',''),expected):self.send_response(407);self.send_header('Proxy-Authenticate','Basic realm="FLS-local"');self.end_headers();return
    if self.path.rstrip('/')!=relay.endpoint.rstrip('/'):self.send_error(403);return
    length=int(self.headers.get('Content-Length','0'))
    if (length<1 and relay.mode!='balance') or length>65536:self.send_error(413);return
    body=self.rfile.read(length)
    # HttpURLConnection may retry internally. A relay instance can forward only
    # one paid POST; later requests receive the saved answer or an error.
    if relay.sent:
     cached=relay.folder/'response.tsr'
     if relay.mode=='stamp' and cached.is_file():
      data=cached.read_bytes();self.send_response(200);self.send_header('Content-Type','application/timestamp-reply');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
     else:self.send_response(502);self.send_header('Content-Length','0');self.end_headers()
     return
    if relay.mode=='stamp':atomic(relay.folder/'request.tsq',body,0o600)
    try:
     atomic(relay.folder/'sent.flag',b'may_have_been_sent\n',0o600);relay.sent=True
     allowed_headers={'content-type','identity','user-agent'}
     if relay.mode=='balance':allowed_headers.update({'credit_req','credit_req_time'})
     headers={k:v for k,v in self.headers.items() if k.lower() in allowed_headers}
     opener=urllib.request.build_opener(NoRedirect,urllib.request.ProxyHandler({}));request=urllib.request.Request(relay.endpoint,body if method=='POST' else None,headers=headers,method=method)
     with opener.open(request,timeout=relay.timeout) as response:
      data=response.read(4*1024*1024+1);kind=response.headers.get('Content-Type','')
      if len(data)>4*1024*1024:raise TSAError('response_too_large')
      if relay.mode=='stamp':atomic(relay.folder/'response.tsr',data)
      self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    except Exception:
     self.send_response(502);self.send_header('Content-Length','0');self.end_headers()
  self.server=http.server.HTTPServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
 def __enter__(self):self.thread.start();return self
 def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(2)

def official_request(profile,password,folder,vendor,sha256=None,nonce=None,mode='stamp',endpoint=None):
 endpoint=endpoint or PROVIDERS[profile['provider']][profile['environment']];folder=Path(folder)
 with OfficialRelay(endpoint,folder) as relay:
  relay.mode=mode;port=relay.server.server_port
  payload=[mode,endpoint,str(profile['customer_id']),relay.token,base64.b64encode(password.encode()).decode()]
  if mode=='stamp':payload.extend([sha256,nonce.hex()])
  cmd=['java','-Xmx192m','-Dhttp.proxyHost=127.0.0.1','-Dhttp.proxyPort='+str(port),'-Dhttp.nonProxyHosts=','-cp',str(vendor)+':'+str(Path(vendor)/'client.jar'),'FlsTsaBridge',str(vendor),str(folder/'client-response.tsr')]
  try:result=subprocess.run(cmd,input=('\n'.join(payload)+'\n').encode(),capture_output=True,timeout=75,cwd=folder)
  except subprocess.TimeoutExpired:raise TSAError('request_uncertain' if relay.sent else 'client_unavailable')
  try:reply=json.loads(result.stdout.decode().strip().splitlines()[-1])
  except Exception:raise TSAError('request_uncertain' if relay.sent else 'client_unavailable')
  if result.returncode or 'error' in reply:raise TSAError('request_uncertain' if relay.sent else 'client_unavailable')
  return reply

def make_proof(folder,root,package_name,info):
 folder=Path(folder);root=Path(root);data={'schema':'fls-rfc3161-proof-v1','package_filename':package_name,**info};atomic(folder/'verification.json',json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2).encode()+b'\n')
 filename=package_name+'.timestamp-'+info['response_sha256'][:16]+'.tar.gz';target=root/filename
 if target.exists():
  with tempfile.TemporaryDirectory(prefix='fls-proof-adopt-') as temporary:
   check=Path(temporary)
   with tarfile.open(target,'r:gz') as tar:
    entries=tar.getmembers();expected={'request.tsq','response.tsr','roots.pem','chain.pem','revocation.crl','verification.json'}
    if len(entries)!=6 or {m.name for m in entries}!=expected or any(not m.isfile() or m.size>4*1024*1024 for m in entries):raise TSAError('proof_already_exists')
    for m in entries:(check/m.name).write_bytes(tar.extractfile(m).read())
   previous=json.loads((check/'verification.json').read_text())
   if previous['package_filename']!=package_name or previous['package_sha256']!=info['package_sha256'] or (check/'request.tsq').read_bytes()!=(folder/'request.tsq').read_bytes() or (check/'response.tsr').read_bytes()!=(folder/'response.tsr').read_bytes():raise TSAError('proof_already_exists')
   verify_response((check/'request.tsq').read_bytes(),(check/'response.tsr').read_bytes(),(folder/'roots.pem').read_bytes(),check,info['package_sha256'],info['provider'],online=False)
  return filename,hashlib.sha256(target.read_bytes()).hexdigest(),target.stat().st_size
 fd,tmp=tempfile.mkstemp(prefix='.tsa-proof-',dir=root)
 try:
  with os.fdopen(fd,'wb') as f:
   with tarfile.open(fileobj=f,mode='w:gz',compresslevel=1) as t:
    for name in ['request.tsq','response.tsr','roots.pem','chain.pem','revocation.crl','verification.json']:
     b=(folder/name).read_bytes();m=tarfile.TarInfo(name);m.size=len(b);m.mode=0o640;t.addfile(m,io.BytesIO(b))
   f.flush();os.fsync(f.fileno())
  os.chmod(tmp,0o640)
  if target.exists():
   if hashlib.sha256(Path(tmp).read_bytes()).digest()!=hashlib.sha256(target.read_bytes()).digest():raise TSAError('proof_already_exists')
   Path(tmp).unlink()
  else:os.rename(tmp,target)
  d=os.open(root,os.O_DIRECTORY);os.fsync(d);os.close(d)
  return filename,hashlib.sha256(target.read_bytes()).hexdigest(),target.stat().st_size
 finally:Path(tmp).unlink(missing_ok=True)
