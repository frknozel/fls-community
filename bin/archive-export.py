#!/usr/bin/python3
"""Create immutable verified hourly bundles, then copy them to configured destinations."""
import argparse,base64,contextlib,datetime as dt,fcntl,hashlib,io,json,os,re,stat,sys,tarfile,tempfile,time
from pathlib import Path
import pymysql
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from archive_transports import TransferError,connect,deliver,digest,archive_subdir,archive_remote_directory,ftps_peer_certificate
UTC=dt.timezone.utc
class ArchiveError(Exception):pass

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def safe_source(value):
 if not re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',value):raise ArchiveError('source_name_invalid')
 return value

def create_package(row,chain,raw_root,package_root,public_path):
 name=safe_source(row['source_file']);key=serialization.load_pem_public_key(public_path.read_bytes());public=public_path.read_bytes()
 previous='0'*64;envelopes=[];last_name=''
 for c in chain:
  m=json.loads(c['manifest_json']);data=canonical(m)
  key.verify(base64.b64decode(c['signature'],validate=True),data)
  if m['previous_manifest_sha256']!=previous or hashlib.sha256(data).hexdigest()!=c['manifest_hash'] or m['source_file']!=c['source_file'] or m['source_file']<=last_name:raise ArchiveError('manifest_chain_invalid')
  previous=c['manifest_hash'];last_name=m['source_file'];envelopes.append({'manifest':m,'signature':c['signature']})
 if not envelopes or envelopes[-1]['manifest']['source_file']!=name:raise ArchiveError('manifest_missing')
 manifest=envelopes[-1];m=manifest['manifest']
 if row['manifest_hash']!=hashlib.sha256(canonical(m)).hexdigest() or m['sha256']!=row['sha256'] or int(m['bytes'])!=int(row['bytes']) or int(m['rows'])!=int(row['rows_count']):raise ArchiveError('manifest_metadata_invalid')
 filename='fls-'+name[:-6]+'-'+row['manifest_hash'][:16]+'.tar.gz';dest=package_root/filename
 readme=('FLS signed hourly archive v1\n\nSource hour is UTC. The raw JSONL is preserved byte-for-byte.\nmanifest.json contains its SHA-256 and Ed25519 signature.\nchain.jsonl contains all prior signed manifests through this hour.\nUse the independently obtained trusted FLS public key to verify; a key\ninside an untrusted archive is not by itself a trust anchor.\n\nVerification tool: bin/verify-package.py from your FLS installation.\npython3 verify-package.py PACKAGE --public-key TRUSTED-KEY.pem\nPython cryptography is required. No extraction is needed.\n\nThis package has a local signature, not a qualified RFC3161 time stamp.\nNo legal compliance certification is implied. No automatic log deletion.\n').encode()
 fd=os.open(raw_root/name,os.O_RDONLY|os.O_NOFOLLOW);tmp=None
 try:
  with os.fdopen(fd,'rb') as raw:
   before=os.fstat(raw.fileno())
   if not stat.S_ISREG(before.st_mode):raise ArchiveError('source_not_regular')
   h=hashlib.sha256();rows=0
   for b in iter(lambda:raw.read(4*1024**2),b''):h.update(b);rows+=b.count(b'\n')
   if (h.hexdigest(),before.st_size,rows)!=(m['sha256'],m['bytes'],m['rows']):raise ArchiveError('raw_integrity_failed')
   raw.seek(0)
   fd,tmp=tempfile.mkstemp(prefix='.fls-package-',dir=package_root);os.chmod(tmp,0o640)
   with os.fdopen(fd,'wb') as output:
    with tarfile.open(fileobj=output,mode='w:gz',compresslevel=1) as tar:
     info=tarfile.TarInfo(name);info.size=before.st_size;info.mode=0o640;tar.addfile(info,raw)
     for n,b in [('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2).encode()+b'\n'),('chain.jsonl',b''.join(canonical(e)+b'\n' for e in envelopes)),('archive-public-key.pem',public),('README.txt',readme)]:
      info=tarfile.TarInfo(n);info.size=len(b);info.mode=0o640;tar.addfile(info,io.BytesIO(b))
    output.flush();os.fsync(output.fileno())
   after=os.fstat(raw.fileno())
   if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):raise ArchiveError('source_changed')
  # Verify the compressed copy itself, not only the source read before packaging.
  import importlib.util
  spec=importlib.util.spec_from_file_location('fls_verify',Path(__file__).with_name('verify-package.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
  def verify_expected(path):
   report=v.verify(path,public_path)
   if (report['source_file'],report['manifest_sha256'],report['sha256'],report['bytes'],report['rows'])!=(name,row['manifest_hash'],m['sha256'],m['bytes'],m['rows']):raise ArchiveError('package_manifest_mismatch')
  verify_expected(tmp)
  if dest.exists():
   # A crash may leave a finalized package without its DB row. Adopt only a fully
   # verified existing package; never overwrite an archived original.
   verify_expected(dest);os.unlink(tmp);tmp=None
  else:os.rename(tmp,dest);tmp=None
  directory=os.open(package_root,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
  with dest.open('rb') as f:sha=digest(f)
  return filename,sha,dest.stat().st_size
 finally:
  if tmp:Path(tmp).unlink(missing_ok=True)

class Worker:
 def __init__(self,db,raw,packages,public,secret_key):self.db=db;self.raw=raw;self.packages=packages;self.public=public;self.key=secret_key
 def sql(self,q,a=()):
  with self.db.cursor() as c:c.execute(q,a);return c.fetchall()
 def heartbeat(self,status='running',code=''):
  self.sql('INSERT INTO archive_export_worker(id,checked_at,status,error_code) VALUES(1,UTC_TIMESTAMP(6),%s,%s) ON DUPLICATE KEY UPDATE checked_at=VALUES(checked_at),status=VALUES(status),error_code=VALUES(error_code)',(status,code))
 def secret(self,d):
  if not d['secret_cipher'].startswith('v1:'):raise ArchiveError('secret_format_invalid')
  value=base64.b64decode(d['secret_cipher'][3:],validate=True);return json.loads(AESGCM(self.key).decrypt(value[:12],value[12:],b'FLS-Archive-v1'))
 def package_batch(self,limit):
  settings=self.sql('SELECT * FROM archive_export_settings WHERE id=1')[0]
  if not settings['packaging_enabled']:return
  rows=self.sql("SELECT m.* FROM archive_manifests m LEFT JOIN archive_packages p ON p.manifest_id=m.id WHERE m.status='verified' AND (p.manifest_id IS NULL OR p.status<>'ready' AND (p.next_attempt_at IS NULL OR p.next_attempt_at<=UTC_TIMESTAMP(6))) ORDER BY m.source_file DESC LIMIT %s",(limit,))
  for r in rows:
   self.heartbeat('packaging')
   self.sql("INSERT IGNORE INTO archive_packages(manifest_id,filename) VALUES(%s,'')",(r['id'],))
   try:
    chain=self.sql('SELECT * FROM archive_manifests WHERE source_file<=%s ORDER BY source_file',(r['source_file'],))
    filename,sha,size=create_package(r,chain,self.raw,self.packages,self.public)
    self.sql("UPDATE archive_packages SET filename=%s,sha256=%s,bytes=%s,status='ready',error_code='',created_at=COALESCE(created_at,UTC_TIMESTAMP(6)),verified_at=UTC_TIMESTAMP(6),attempts=attempts+1,next_attempt_at=NULL WHERE manifest_id=%s",(filename,sha,size,r['id']))
   except Exception as e:
    code=str(e) if isinstance(e,ArchiveError) else 'package_verification_failed'
    self.sql("UPDATE archive_packages SET status='retry',error_code=%s,attempts=attempts+1,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE) WHERE manifest_id=%s",(code,r['id']))
 def queue(self):
  rows=self.sql("SELECT d.id,d.revision,d.remote_path,p.manifest_id,m.source_file FROM archive_destinations d JOIN archive_packages p ON p.manifest_id>=d.start_manifest_id JOIN archive_manifests m ON m.id=p.manifest_id LEFT JOIN archive_deliveries j ON j.destination_id=d.id AND j.destination_revision=d.revision AND j.manifest_id=p.manifest_id WHERE d.enabled=1 AND p.status='ready' AND m.status='verified' AND j.id IS NULL ORDER BY p.manifest_id DESC,d.id LIMIT 500")
  for row in rows:
   subdir=archive_subdir(row['source_file']);directory=archive_remote_directory(row['remote_path'],subdir)
   self.sql('INSERT IGNORE INTO archive_deliveries(destination_id,destination_revision,manifest_id,remote_subdir,remote_directory) VALUES(%s,%s,%s,%s,%s)',(row['id'],row['revision'],row['manifest_id'],subdir,directory))
  # One process owns the flock; an uploading job here survived a previous crash.
  self.sql("UPDATE archive_deliveries SET status='retry',error_code='interrupted',next_attempt_at=NULL WHERE status='uploading'")
  self.sql("UPDATE archive_deliveries j JOIN archive_destinations d ON d.id=j.destination_id SET j.status='cancelled',j.error_code='destination_changed' WHERE j.status IN ('pending','retry') AND (d.enabled=0 OR d.revision<>j.destination_revision)")
 @contextlib.contextmanager
 def publish_guard(self,d,job=None):
  self.db.begin()
  try:
   fresh=self.sql('SELECT revision,enabled FROM archive_destinations WHERE id=%s FOR UPDATE',(d['id'],))
   if not fresh or fresh[0]['revision']!=d['revision'] or job is not None and not fresh[0]['enabled']:raise TransferError('destination_changed')
   yield
   self.db.commit()
  except Exception:self.db.rollback();raise
 def connect(self,d):return connect(d,self.secret(d))
 def tests(self):
  for d in self.sql("SELECT * FROM archive_destinations WHERE check_status='pending' AND test_requested_at IS NOT NULL ORDER BY id LIMIT 2"):
   self.heartbeat('testing');remote=None;code='';pin='';name='fls-test-'+os.urandom(12).hex()+'.bin'
   try:
    remote=self.connect(d);remote.enter_directory(archive_subdir(dt.datetime.now(UTC).strftime('%Y-%m-%d-%H.jsonl')))
    with tempfile.TemporaryDirectory(prefix='fls-export-test-') as folder:
     p=Path(folder)/name;p.write_bytes(os.urandom(1024));sha=hashlib.sha256(p.read_bytes()).hexdigest()
     deliver(remote,p,name,sha,lambda:self.publish_guard(d));remote.remove(name)
   except Exception as e:code=self.error(e);pin=getattr(e,'observed_host_key','')
   finally:
    if remote:
     try:remote.close()
     except Exception:pass
   self.sql("UPDATE archive_destinations SET check_status=%s,check_code=%s,observed_host_key=%s,checked_at=UTC_TIMESTAMP(6),checked_revision=revision,test_requested_at=NULL WHERE id=%s AND revision=%s AND test_requested_at=%s",('error' if code else 'ok',code,pin,d['id'],d['revision'],d['test_requested_at']))
 def error(self,e):
  if isinstance(e,TransferError):return e.code
  if isinstance(e,ssl_error):return 'tls_verification_failed'
  return 'connection_or_transfer_failed'
 def certificate_checks(self):
  # An idle hourly archive queue must not stop certificate monitoring. Bound
  # checks to two targets per run; successes refresh hourly, failures in 5 min.
  targets=self.sql("SELECT * FROM archive_destinations WHERE enabled=1 AND protocol='ftps' AND (tls_peer_revision IS NULL OR tls_peer_revision<>revision OR tls_peer_checked_at IS NULL OR tls_peer_checked_at<=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 HOUR) OR (tls_peer_check_code<>'' AND tls_peer_checked_at<=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 5 MINUTE))) ORDER BY COALESCE(tls_peer_checked_at,'1970-01-01'),id LIMIT 2")
  for d in targets:
   pem='';code=''
   try:pem=ftps_peer_certificate(d)
   except Exception as e:code=self.error(e)
   # Keep the last verified leaf after a network/verification failure, only
   # when it belongs to this same target revision. Failed observations never
   # make an old certificate appear freshly verified.
   self.sql("UPDATE archive_destinations SET tls_peer_pem=IF(%s='',%s,IF(tls_peer_revision=revision,tls_peer_pem,'')),tls_peer_verified_at=IF(%s='',UTC_TIMESTAMP(6),IF(tls_peer_revision=revision,tls_peer_verified_at,NULL)),tls_peer_revision=revision,tls_peer_checked_at=UTC_TIMESTAMP(6),tls_peer_check_code=%s WHERE id=%s AND revision=%s AND enabled=1 AND protocol='ftps'",(code,pem,code,code,d['id'],d['revision']))
 def transfer_batch(self,limit):
  jobs=self.sql("SELECT j.*,p.filename,p.sha256,p.bytes FROM archive_deliveries j JOIN archive_packages p ON p.manifest_id=j.manifest_id JOIN archive_manifests m ON m.id=p.manifest_id JOIN archive_destinations d ON d.id=j.destination_id WHERE j.status IN ('pending','retry') AND (j.next_attempt_at IS NULL OR j.next_attempt_at<=UTC_TIMESTAMP(6)) AND d.enabled=1 AND d.revision=j.destination_revision AND p.status='ready' AND m.status='verified' ORDER BY j.attempts,j.manifest_id DESC LIMIT %s",(limit,))
  for j in jobs:
   self.heartbeat('transferring');d=self.sql('SELECT * FROM archive_destinations WHERE id=%s',(j['destination_id'],))[0];remote=None
   self.sql("UPDATE archive_deliveries SET status='uploading',attempts=attempts+1,started_at=UTC_TIMESTAMP(6),error_code='' WHERE id=%s",(j['id'],))
   try:
    p=self.packages/j['filename'];s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_size!=j['bytes']:raise TransferError('local_package_invalid')
    with p.open('rb') as f:
     if digest(f)!=j['sha256']:raise TransferError('local_package_invalid')
    if j['remote_directory'] and archive_remote_directory(d['remote_path'],j['remote_subdir'])!=j['remote_directory']:raise TransferError('destination_changed')
    remote=self.connect(d);remote.enter_directory(j['remote_subdir']);deliver(remote,p,j['filename'],j['sha256'],lambda:self.publish_guard(d,j))
    with self.publish_guard(d,j):
     self.sql("UPDATE archive_deliveries SET status='verified',completed_at=UTC_TIMESTAMP(6),error_code='',remote_sha256=%s,next_attempt_at=NULL WHERE id=%s",(j['sha256'],j['id']))
   except Exception as e:
    code=self.error(e);wait=min(3600,60*2**min(int(j['attempts']),6))
    self.sql("UPDATE archive_deliveries SET status=%s,error_code=%s,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL %s SECOND) WHERE id=%s AND status='uploading'",('cancelled' if code=='destination_changed' else 'retry',code,wait,j['id']))
    if code=='local_package_invalid':self.sql("UPDATE archive_packages SET status='quarantined',error_code='local_package_invalid',next_attempt_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE) WHERE manifest_id=%s",(j['manifest_id'],))
   finally:
    if remote:
     try:remote.close()
     except Exception:pass
 def run(self,packages=3,deliveries=2):
  for orphan in self.packages.glob('.fls-package-*'):
   if orphan.is_file():orphan.unlink()
  self.heartbeat();self.tests();self.package_batch(packages);self.queue();self.transfer_batch(deliveries);self.certificate_checks();self.heartbeat('idle')

import ssl
ssl_error=ssl.SSLError
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--credential',default='/etc/fls/archive-export.json');p.add_argument('--raw',default='/srv/fls-server/raw');p.add_argument('--packages',default='/srv/fls-server/archive/packages');p.add_argument('--public-key',default='/var/www/fls/public/archive-public-key.pem');p.add_argument('--key',default='/etc/fls/credential-key');p.add_argument('--lock',default='/srv/fls-server/archive/packages/.worker.lock');p.add_argument('--package-limit',type=int,default=3);p.add_argument('--delivery-limit',type=int,default=2);a=p.parse_args()
 with open(a.lock,'w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:sys.exit(0)
  c=json.loads(Path(a.credential).read_text());db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=c['user'],password=c['password'],database=c.get('database','fls'),charset='utf8mb4',autocommit=True,cursorclass=pymysql.cursors.DictCursor)
  db.cursor().execute("SET time_zone='+00:00',max_statement_time=30")
  w=Worker(db,Path(a.raw),Path(a.packages),Path(a.public_key),Path(a.key).read_bytes())
  try:w.run(a.package_limit,a.delivery_limit)
  except Exception:
   w.heartbeat('error','worker_failed');print('FLS archive worker failed; inspect administrative status, no credentials logged.',file=sys.stderr);sys.exit(1)
  finally:db.close()
