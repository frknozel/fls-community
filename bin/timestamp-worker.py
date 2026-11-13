#!/usr/bin/python3
"""Paid timestamps are explicit, durable, and never blindly repeated after uncertainty."""
import argparse,base64,contextlib,datetime as dt,fcntl,hashlib,importlib.util,json,os,re,sys,time
from pathlib import Path
import pymysql
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tsa_core import TSAError,atomic,request_for_digest,verify_response,official_request,make_proof,PROVIDERS
from archive_transports import connect,deliver,digest,TransferError,archive_remote_directory
UTC=dt.timezone.utc
class Worker:
 def __init__(self,db,key,root,packages,vendor,trust):self.db=db;self.key=key;self.root=Path(root);self.packages=Path(packages);self.vendor=Path(vendor);self.trust=Path(trust)
 def sql(self,q,a=()):
  with self.db.cursor() as c:c.execute(q,a);return c.fetchall()
 def heartbeat(self,status='running',error=''):
  self.sql('INSERT INTO timestamp_worker(id,checked_at,status,error_code) VALUES(1,UTC_TIMESTAMP(6),%s,%s) ON DUPLICATE KEY UPDATE checked_at=VALUES(checked_at),status=VALUES(status),error_code=VALUES(error_code)',(status,error))
 def secret(self,value,context=b'FLS-Timestamp-v1'):
  if not value.startswith('v1:'):raise TSAError('credentials_invalid')
  v=base64.b64decode(value[3:],validate=True);return AESGCM(self.key).decrypt(v[:12],v[12:],context).decode()
 def create_attempt(self,p,kind,sha256,manifest_id=None):
  key=os.urandom(16).hex();folder=self.root/'attempts'/key;folder.mkdir(mode=0o700)
  query,nonce=request_for_digest(sha256);atomic(folder/'request.tsq',query,0o600);atomic(folder/'input.json',json.dumps({'provider':p['provider'],'environment':p['environment'],'profile_revision':p['revision'],'kind':kind,'manifest_id':manifest_id,'package_sha256':sha256,'nonce':nonce.hex(),'prepared_at_utc':dt.datetime.now(UTC).isoformat()}).encode(),0o600)
  self.sql('INSERT INTO timestamp_attempts(attempt_key,provider,profile_revision,kind,manifest_id,request_sha256) VALUES(%s,%s,%s,%s,%s,%s)',(key,p['provider'],p['revision'],kind,manifest_id,hashlib.sha256(query).hexdigest()));return key,folder
 def stamp_request(self,p,folder,sha256,nonce):return official_request(p,self.secret(p['secret_cipher']),folder,self.vendor,sha256,nonce)
 def validate(self,p,folder,sha256):return verify_response((folder/'request.tsq').read_bytes(),(folder/'response.tsr').read_bytes(),(self.trust/(p['provider']+'-roots.pem')).read_bytes(),folder,sha256,p['provider'],request_time=dt.datetime.fromisoformat(json.loads((folder/'input.json').read_text())['prepared_at_utc']))
 def complete_attempt(self,key,p,folder):
  context=json.loads((folder/'input.json').read_text());sha=context['package_sha256']
  # Every response is saved by the localhost relay before being returned to the
  # official client. After a crash, validate that response without a new charge.
  if not (folder/'response.tsr').exists():
   if (folder/'sent.flag').exists():raise TSAError('request_uncertain')
   self.sql("UPDATE timestamp_attempts SET status='sending',updated_at=UTC_TIMESTAMP(6) WHERE attempt_key=%s",(key,))
   try:self.stamp_request(p,folder,sha,bytes.fromhex(context['nonce']))
   except Exception:
    if not(folder/'response.tsr').exists():raise TSAError('request_uncertain' if (folder/'sent.flag').exists() else 'client_unavailable')
  from asn1crypto import tsp
  if tsp.TimeStampReq.load((folder/'request.tsq').read_bytes())['nonce'].native!=int(context['nonce'],16):raise TSAError('nonce_mismatch')
  self.sql("UPDATE timestamp_attempts SET status='response_saved',request_sha256=%s,response_sha256=%s,updated_at=UTC_TIMESTAMP(6) WHERE attempt_key=%s",(hashlib.sha256((folder/'request.tsq').read_bytes()).hexdigest(),hashlib.sha256((folder/'response.tsr').read_bytes()).hexdigest(),key))
  result=self.validate(p,folder,sha)
  self.sql("UPDATE timestamp_attempts SET status='verified',error_code='',request_sha256=%s,response_sha256=%s,updated_at=UTC_TIMESTAMP(6) WHERE attempt_key=%s",(result['request_sha256'],result['response_sha256'],key));return result
 def fail_attempt(self,key,error):
  code=str(error) if isinstance(error,TSAError) else 'verification_failed';status='uncertain' if code=='request_uncertain' else 'error'
  self.sql('UPDATE timestamp_attempts SET status=%s,error_code=%s,updated_at=UTC_TIMESTAMP(6) WHERE attempt_key=%s',(status,code,key));return status,code
 def checks(self):
  for p in self.sql("SELECT * FROM timestamp_profiles WHERE check_status='pending' AND test_requested_at IS NOT NULL ORDER BY provider"):
   self.heartbeat('testing');sha=hashlib.sha256(os.urandom(64)).hexdigest();key,folder=self.create_attempt(p,'test',sha)
   code='';status='ok'
   try:self.complete_attempt(key,p,folder)
   except Exception as e:_,code=self.fail_attempt(key,e);status='error'
   self.sql('UPDATE timestamp_profiles SET check_status=%s,check_code=%s,checked_revision=%s,checked_at=UTC_TIMESTAMP(6),test_requested_at=NULL WHERE provider=%s AND revision=%s AND test_requested_at=%s',(status,code,p['revision'],p['provider'],p['revision'],p['test_requested_at']))
  for p in self.sql("SELECT * FROM timestamp_profiles WHERE balance_requested_at IS NOT NULL AND balance_status='pending'"):self.refresh_balance(p)
 def balance_request(self,p,folder):return official_request(p,self.secret(p['secret_cipher']),folder,self.vendor,mode='balance')
 def refresh_balance(self,p):
  self.heartbeat('balance');folder=self.root/'attempts'/('balance-'+os.urandom(16).hex());folder.mkdir(mode=0o700)
  # Record the last paid attempt represented by this sample. A later request
  # makes a cached balance visibly out of date, never an invented exact debit.
  basis=self.sql('SELECT COALESCE(MAX(id),0) n FROM timestamp_attempts WHERE provider=%s AND profile_revision=%s',(p['provider'],p['revision']))[0]['n']
  try:
   data=self.balance_request(p,folder);balance=int(data['credit'])
   if balance<0:raise TSAError('balance_invalid')
   self.sql("UPDATE timestamp_profiles SET balance=%s,balance_status='ok',balance_at=UTC_TIMESTAMP(6),balance_attempted_at=UTC_TIMESTAMP(6),balance_basis_attempt_id=%s,balance_requested_at=NULL WHERE provider=%s AND revision=%s AND balance_requested_at<=>%s",(balance,basis,p['provider'],p['revision'],p['balance_requested_at']))
  except Exception:
   # Retain the last successful sample with its original time, clearly stale.
   self.sql("UPDATE timestamp_profiles SET balance_status='error',balance_attempted_at=UTC_TIMESTAMP(6),balance_requested_at=NULL WHERE provider=%s AND revision=%s AND balance_requested_at<=>%s",(p['provider'],p['revision'],p['balance_requested_at']))
 def automatic_balance(self):
  s=self.sql('SELECT * FROM timestamp_settings WHERE id=1')[0]
  if not s['enabled'] or s['signing_mode']!='provider':return
  p=self.sql('SELECT * FROM timestamp_profiles WHERE provider=%s',(s['provider'],))[0]
  if p['environment']!='production' or p['check_status']!='ok' or p['checked_revision']!=p['revision'] or not p['secret_cipher'] or p['balance_requested_at'] is not None:return
  now=dt.datetime.now(UTC).replace(tzinfo=None);age=(now-p['balance_attempted_at']).total_seconds() if p['balance_attempted_at'] else 10**9
  later=self.sql("SELECT COUNT(*) n FROM timestamp_attempts WHERE provider=%s AND profile_revision=%s AND id>%s AND status<>'prepared'",(p['provider'],p['revision'],p['balance_basis_attempt_id']))[0]['n']
  # A failed query waits 15 minutes. Successful samples refresh after a paid
  # batch (at most once/minute), otherwise every 15 minutes. No stamp is bought.
  if age>=900 or (p['balance_status']=='ok' and later and age>=60):self.refresh_balance(p)
 def queue(self):
  s=self.sql('SELECT * FROM timestamp_settings WHERE id=1')[0]
  if not s['enabled'] or s['signing_mode']!='provider':return
  p=self.sql('SELECT * FROM timestamp_profiles WHERE provider=%s',(s['provider'],))[0]
  if p['environment']!='production' or p['check_status']!='ok' or p['checked_revision']!=p['revision']:return
  self.sql("INSERT IGNORE INTO timestamp_stamps(manifest_id,provider,profile_revision) SELECT a.manifest_id,%s,%s FROM archive_packages a JOIN archive_manifests m ON m.id=a.manifest_id WHERE a.status='ready' AND m.status='verified' AND a.manifest_id>=%s",(p['provider'],p['revision'],s['start_manifest_id']))
  self.sql("UPDATE timestamp_stamps SET provider=%s,profile_revision=%s,updated_at=UTC_TIMESTAMP(6) WHERE status='pending' AND attempt_key=''",(p['provider'],p['revision']))
 def process(self,job,recover=False):
  p=self.sql('SELECT * FROM timestamp_profiles WHERE provider=%s',(job['provider'],))[0];s=self.sql('SELECT * FROM timestamp_settings WHERE id=1')[0]
  if not recover and (not s['enabled'] or s['signing_mode']!='provider' or s['provider']!=p['provider'] or p['environment']!='production' or p['revision']!=job['profile_revision'] or p['check_status']!='ok' or p['checked_revision']!=p['revision']):return
  a=self.sql('SELECT p.*,m.source_file,m.status manifest_status FROM archive_packages p JOIN archive_manifests m ON m.id=p.manifest_id WHERE p.manifest_id=%s',(job['manifest_id'],))[0]
  key=job['attempt_key'];folder=self.root/'attempts'/key if key else None
  if recover and (not folder or not (folder/'response.tsr').exists()):
   if key:self.fail_attempt(key,TSAError('request_uncertain'))
   self.sql("UPDATE timestamp_stamps SET status='uncertain',error_code='request_uncertain',updated_at=UTC_TIMESTAMP(6) WHERE id=%s",(job['id'],));return
  try:
   if a['status']!='ready' or a['manifest_status']!='verified':raise TSAError('local_package_invalid')
   f=self.packages/a['filename']
   with f.open('rb') as stream:
    if digest(stream)!=a['sha256']:raise TSAError('local_package_invalid')
   if not key:
    key,folder=self.create_attempt(p,'archive',a['sha256'],job['manifest_id']);self.sql("UPDATE timestamp_stamps SET status='processing',attempt_key=%s,error_code='',updated_at=UTC_TIMESTAMP(6) WHERE id=%s",(key,job['id']))
   result=self.complete_attempt(key,p,folder);result['package_bytes']=int(a['bytes']);filename,sha,size=make_proof(folder,self.root/'proofs',a['filename'],result)
   self.sql("UPDATE timestamp_stamps SET status='verified',filename=%s,sha256=%s,bytes=%s,stamp_at=%s,verified_at=UTC_TIMESTAMP(6),info_json=%s,error_code='',updated_at=UTC_TIMESTAMP(6) WHERE id=%s",(filename,sha,size,dt.datetime.fromisoformat(result['stamp_at_utc']).astimezone(UTC).replace(tzinfo=None),json.dumps(result),job['id']))
  except Exception as e:
   status,code=self.fail_attempt(key,e) if key else ('error',str(e) if isinstance(e,TSAError) else 'verification_failed')
   self.sql('UPDATE timestamp_stamps SET status=%s,error_code=%s,updated_at=UTC_TIMESTAMP(6) WHERE id=%s',(status,code,job['id']))
 def recover(self):
  # Never automatically repeat a paid request whose outcome is unknown.
  for job in self.sql("SELECT * FROM timestamp_stamps WHERE status='processing'"):self.process(job,True)
  pending=self.sql("SELECT a.* FROM timestamp_attempts a JOIN timestamp_profiles p ON p.provider=a.provider AND p.revision=a.profile_revision WHERE a.kind='test' AND a.status IN ('prepared','sending','response_saved') AND p.check_status='pending' ORDER BY a.id DESC")
  for a in pending:
   p=self.sql('SELECT * FROM timestamp_profiles WHERE provider=%s',(a['provider'],))[0]
   if p['check_status']!='pending':continue
   folder=self.root/'attempts'/a['attempt_key'];code='';status='ok'
   try:
    if not(folder/'response.tsr').exists():raise TSAError('request_uncertain')
    self.complete_attempt(a['attempt_key'],p,folder)
   except Exception as e:_,code=self.fail_attempt(a['attempt_key'],e);status='error'
   self.sql('UPDATE timestamp_profiles SET check_status=%s,check_code=%s,checked_revision=revision,checked_at=UTC_TIMESTAMP(6),test_requested_at=NULL WHERE provider=%s AND revision=%s',(status,code,p['provider'],p['revision']))
  self.sql("UPDATE timestamp_attempts SET status='uncertain',error_code='request_uncertain',updated_at=UTC_TIMESTAMP(6) WHERE status IN ('prepared','sending','response_saved')")
 def send_evidence(self,limit=2):
  self.sql("INSERT IGNORE INTO timestamp_deliveries(stamp_id,destination_id,destination_revision,remote_subdir,remote_directory) SELECT s.id,d.id,d.revision,a.remote_subdir,a.remote_directory FROM timestamp_stamps s JOIN archive_deliveries a ON a.manifest_id=s.manifest_id AND a.status='verified' JOIN archive_destinations d ON d.id=a.destination_id AND d.revision=a.destination_revision AND d.enabled=1 WHERE s.status='verified'")
  self.sql("UPDATE timestamp_deliveries SET status='retry',next_attempt_at=NULL,error_code='interrupted' WHERE status='uploading'")
  self.sql("UPDATE timestamp_deliveries j JOIN archive_destinations d ON d.id=j.destination_id SET j.status='cancelled',j.error_code='destination_changed' WHERE j.status IN ('pending','retry') AND (d.enabled=0 OR d.revision<>j.destination_revision)")
  jobs=self.sql("SELECT j.*,s.filename,s.sha256,s.bytes FROM timestamp_deliveries j JOIN timestamp_stamps s ON s.id=j.stamp_id JOIN archive_destinations d ON d.id=j.destination_id WHERE j.status IN ('pending','retry') AND (j.next_attempt_at IS NULL OR j.next_attempt_at<=UTC_TIMESTAMP(6)) AND d.enabled=1 AND d.revision=j.destination_revision AND s.status='verified' ORDER BY j.id LIMIT %s",(limit,))
  for j in jobs:
   d=self.sql('SELECT * FROM archive_destinations WHERE id=%s',(j['destination_id'],))[0];remote=None;self.heartbeat('exporting')
   self.sql("UPDATE timestamp_deliveries SET status='uploading',attempts=attempts+1,error_code='' WHERE id=%s",(j['id'],))
   @contextlib.contextmanager
   def guard():
    self.db.begin()
    try:
     fresh=self.sql('SELECT enabled,revision FROM archive_destinations WHERE id=%s FOR UPDATE',(d['id'],))[0]
     if not fresh['enabled'] or fresh['revision']!=j['destination_revision']:raise TransferError('destination_changed')
     yield;self.db.commit()
    except Exception:self.db.rollback();raise
   try:
    f=self.root/'proofs'/j['filename']
    with f.open('rb') as stream:
     if digest(stream)!=j['sha256']:raise TSAError('local_evidence_invalid')
    if j['remote_directory'] and archive_remote_directory(d['remote_path'],j['remote_subdir'])!=j['remote_directory']:raise TransferError('destination_changed')
    secret=json.loads(self.secret(d['secret_cipher'],b'FLS-Archive-v1'));remote=connect(d,secret);remote.enter_directory(j['remote_subdir']);deliver(remote,f,j['filename'],j['sha256'],guard)
    with guard():self.sql("UPDATE timestamp_deliveries SET status='verified',remote_sha256=%s,completed_at=UTC_TIMESTAMP(6),error_code='',next_attempt_at=NULL WHERE id=%s",(j['sha256'],j['id']))
   except Exception as e:
    code=e.code if isinstance(e,TransferError) else 'evidence_transfer_failed';wait=min(3600,60*2**min(int(j['attempts']),6))
    self.sql("UPDATE timestamp_deliveries SET status='retry',error_code=%s,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL %s SECOND) WHERE id=%s",(code,wait,j['id']))
   finally:
    if remote:
     try:remote.close()
     except Exception:pass
 def run(self):
  self.heartbeat();self.recover();self.checks();self.queue()
  for job in self.sql("SELECT * FROM timestamp_stamps WHERE status='pending' ORDER BY manifest_id DESC LIMIT 3"):
   self.heartbeat('stamping');self.process(job)
  self.automatic_balance();self.send_evidence();self.heartbeat('idle')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--credential',required=True);p.add_argument('--key',required=True);a=p.parse_args();root=Path('/srv/fls-server/archive/timestamps')
 with open(root/'.worker.lock','w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:sys.exit(0)
  c=json.loads(Path(a.credential).read_text());db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=c['user'],password=c['password'],database=c.get('database','fls'),autocommit=True,charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor);db.cursor().execute("SET time_zone='+00:00',max_statement_time=30")
  w=Worker(db,Path(a.key).read_bytes(),root,'/srv/fls-server/archive/packages','/opt/fls-tsa','/var/www/fls/deploy/tsa')
  try:w.run()
  except Exception:w.heartbeat('error','worker_failed');print('FLS timestamp worker failed; no credentials logged.',file=sys.stderr);sys.exit(1)
  finally:db.close()
