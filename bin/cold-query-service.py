#!/usr/bin/python3
"""Peer-authenticated asynchronous cold queries; never reads hot log tables."""
import datetime as dt
import importlib
import json
import os
from pathlib import Path
import pwd
import queue
import re
import secrets
import signal
import socket
import stat
import struct
import threading
import time
import pymysql

REQUEST_MAX=16384
RESPONSE_MAX=4*1024**2
CACHE_BUDGET=2*1024**3
JOB_TTL=15*60
MAX_PENDING=8
MAX_USER_ACTIVE=2
MAX_JOBS=32
MAX_RESULT_MEMORY=24*1024**2
ROOT=Path('/srv/fls-server/archive/detailed')
CACHE=Path('/var/cache/fls-cold-query')
SOCKET='/run/fls-cold-query.sock'
MODULES={'','virus','webfilter','app-ctrl','dns','ips','ssl','forward','local','system','vpn','user','router','ha','connector','anomaly','voip','unknown'}
OUTCOMES={'','security_block','policy_deny','local_deny','other_deny','rating_error','observed','all_blocks'}
LIB_ERRORS={'invalid_scope':422,'invalid_filters':422,'invalid_cursor':422,'cursor_key':422,'query_timeout':503,'result_too_large':413,'event_not_found':404,'snapshot_invalid':409,'catalog_mismatch':409,'cache_unsafe':409,'cache_budget':413,'cache_changed':409,'payload_changed':409}

class RequestError(ValueError):
 def __init__(self,code,status=422):super().__init__(code);self.code=code;self.status=status

def integer(value,minimum=1,maximum=2**32-1):
 if type(value) is not int or not minimum<=value<=maximum:raise RequestError('invalid_request')
 return value

def text(value,maximum):
 if not isinstance(value,str) or len(value)>maximum or any(ord(c)<32 or ord(c)==127 for c in value):raise RequestError('invalid_request')
 try:value.encode('utf-8')
 except UnicodeError:raise RequestError('invalid_request') from None
 return value

def strict_json(raw):
 def pairs(values):
  obj={}
  for k,v in values:
   if k in obj:raise RequestError('invalid_request')
   obj[k]=v
  return obj
 def bad(_):raise RequestError('invalid_request')
 try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_float=bad,parse_constant=bad)
 except (ValueError,UnicodeError,RecursionError):raise RequestError('invalid_request') from None

def validate_request(request):
 if not isinstance(request,dict) or type(request.get('version')) is not int or request['version']!=1 or request.get('op') not in ('start','status'):raise RequestError('invalid_request')
 keys={'version','op','actor','device_id'}|({'snapshot_id','kind','filters','cursor','event_id'} if request['op']=='start' else {'job_id'})
 if set(request)!=keys:raise RequestError('invalid_request')
 actor=request['actor']
 if not isinstance(actor,dict) or set(actor)!={'user_id','session_version'}:raise RequestError('invalid_request')
 integer(actor['user_id']);integer(actor['session_version'],0);integer(request['device_id'])
 if request['op']=='status':
  if not isinstance(request['job_id'],str) or not re.fullmatch(r'[a-f0-9]{32}',request['job_id']):raise RequestError('invalid_request')
  return request
 integer(request['snapshot_id'],1,2**53-1)
 if request['kind'] not in ('list','detail'):raise RequestError('invalid_request')
 filters=request['filters']
 if not isinstance(filters,dict) or set(filters)!={'from','to','source','target','q','module','outcome'}:raise RequestError('invalid_request')
 for key,limit in [('from',32),('to',32),('source',45),('target',45),('q',160),('module',40),('outcome',32)]:text(filters[key],limit)
 if filters['module'] not in MODULES or filters['outcome'] not in OUTCOMES:raise RequestError('invalid_filters')
 if request['cursor'] is not None:text(request['cursor'],4096)
 event_id=request['event_id']
 if request['kind']=='detail':
  if request['cursor'] is not None or not isinstance(event_id,str) or not re.fullmatch(r'[1-9][0-9]{0,19}',event_id) or int(event_id)>2**64-1:raise RequestError('invalid_request')
 elif event_id is not None:raise RequestError('invalid_request')
 return request

def encode(value):
 try:raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
 except (ValueError,UnicodeError,TypeError):raise RequestError('service_unavailable',503) from None
 if len(raw)>RESPONSE_MAX:raise RequestError('result_too_large',413)
 return raw

def error(code,status):return {'ok':False,'code':code,'status':status}

def utc(value):
 if not isinstance(value,str) or len(value)>32:raise RequestError('snapshot_invalid',409)
 try:date=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
 except ValueError:raise RequestError('snapshot_invalid',409) from None
 if date.tzinfo is not None:date=date.astimezone(dt.timezone.utc).replace(tzinfo=None)
 return date

class Broker:
 def __init__(self,db_factory,library,root=ROOT,cache=CACHE,public_key=b'',clock=time.monotonic,maintenance=True):
  self.db_factory=db_factory;self.library=library;self.root=Path(root);self.cache=Path(cache);self.public_key=public_key;self.clock=clock
  self.jobs={};self.lock=threading.RLock();self.pending=queue.Queue(MAX_PENDING);self.stop=threading.Event();self.cursor_key=secrets.token_bytes(32)
  self.maintenance=maintenance;self.last_maintenance=0;self.maintenance_id=0;self.worker=threading.Thread(target=self._work,name='cold-query-worker',daemon=True);self.worker.start()
 def sql(self,query,args=(),write=False):
  db=self.db_factory()
  try:
   with db.cursor() as c:c.execute(query,args);rows=c.fetchall()
   if write:db.commit()
   return rows
  finally:db.close()
 def authorize(self,actor,device_id):
  rows=self.sql('SELECT u.enabled,u.session_version,c.id,c.serial,c.vdom FROM users u JOIN user_fortigate_access a ON a.user_id=u.id JOIN fortigate_connections c ON c.id=a.connection_id WHERE u.id=%s AND c.id=%s',(actor['user_id'],device_id))
  if not rows:raise RequestError('access_denied',403)
  r=rows[0]
  if not int(r['enabled']) or int(r['session_version'])!=actor['session_version']:raise RequestError('unauthenticated',401)
  return {'id':int(r['id']),'serial':r['serial'],'vdom':r['vdom']}
 def snapshot(self,snapshot_id,expected=None):
  rows=self.sql('SELECT * FROM cold_snapshots WHERE id=%s',(snapshot_id,))
  if not rows:raise RequestError('job_not_found',404)
  s=rows[0]
  if s['status']!='verified' or not s['restore_verified_at'] or not re.fullmatch(r'[a-f0-9]{64}',s['manifest_sha256']) or not re.fullmatch(r'[a-f0-9]{64}',s['payload_sha256']):raise RequestError('snapshot_invalid',409)
  if expected and any(s[k]!=expected[k] for k in ('manifest_sha256','payload_sha256','relative_path')):raise RequestError('catalog_mismatch',409)
  return s
 def _cleanup(self):
  now=self.clock()
  for key in list(self.jobs):
   if now-self.jobs[key]['created']>JOB_TTL:del self.jobs[key]
  while len(self.jobs)>=MAX_JOBS:
   finished=[j for j in self.jobs.values() if j['status'] in ('ready','error')]
   if not finished:break
   del self.jobs[min(finished,key=lambda j:j['touched'])['id']]
 def _envelope(self,job):
  return {'ok':True,'job_id':job['id'],'status':job['status'],'device':dict(job['device']),'snapshot_id':job['snapshot_id'],'kind':job['request']['kind'],'event_id':job['request']['event_id'],'result':job['result'] if job['status']=='ready' else None,'error':job['error'] if job['status']=='error' else None}
 def handle(self,request):
  try:
   r=validate_request(request);device=self.authorize(r['actor'],r['device_id'])
   if r['op']=='status':
    with self.lock:
     self._cleanup();j=self.jobs.get(r['job_id'])
     if not j or j['actor']['user_id']!=r['actor']['user_id'] or j['device']['id']!=r['device_id']:raise RequestError('job_not_found',404)
     if j['actor']['session_version']!=r['actor']['session_version'] or j['device']!=device:raise RequestError('access_denied',403)
     ready=j['status']=='ready'
    # Never hold the shared job lock during SQL I/O. Each status call still
    # rechecks both the actor grant and the signed catalog binding.
    if ready:self.snapshot(j['snapshot_id'],j['snapshot'])
    with self.lock:
     if self.jobs.get(r['job_id']) is not j:raise RequestError('job_not_found',404)
     j['touched']=self.clock();return self._envelope(j)
   snapshot=self.snapshot(r['snapshot_id'])
   with self.lock:
    self._cleanup()
    if sum(j['actor']['user_id']==r['actor']['user_id'] and j['status'] in ('queued','preparing') for j in self.jobs.values())>=MAX_USER_ACTIVE or self.pending.full() or len(self.jobs)>=MAX_JOBS:raise RequestError('queue_full',429)
    job={'id':secrets.token_hex(16),'actor':dict(r['actor']),'device':device,'snapshot_id':r['snapshot_id'],'snapshot':snapshot,'request':dict(r),'status':'queued','result':None,'error':None,'created':self.clock(),'touched':self.clock()}
    self.jobs[job['id']]=job
    try:self.pending.put_nowait(job['id'])
    except queue.Full:del self.jobs[job['id']];raise RequestError('queue_full',429) from None
    return self._envelope(job)
  except RequestError as e:return error(e.code,e.status)
  except Exception:return error('service_unavailable',503)
 def _coverage(self,snapshot,prepared):
  if prepared.manifest_sha256!=snapshot['manifest_sha256']:raise RequestError('catalog_mismatch',409)
  rows=self.library.coverage(prepared);seen=set();total=0;values=[]
  for row in rows:
   serial=text(row['serial'],40);vdom=text(row['vdom'],64)
   if not serial or not vdom or (serial,vdom) in seen:raise RequestError('snapshot_invalid',409)
   seen.add((serial,vdom));count=integer(row['records'],1,2**53-1);total+=count
   start=utc(row['first_event_at']);end=utc(row['last_event_at'])
   if start>end:raise RequestError('snapshot_invalid',409)
   values.append((snapshot['id'],serial,vdom,snapshot['manifest_sha256'],count,start,end))
  if total!=int(snapshot['event_count']):raise RequestError('snapshot_invalid',409)
  db=self.db_factory()
  try:
   db.begin()
   with db.cursor() as c:
    c.execute('SELECT manifest_sha256,status FROM cold_snapshots WHERE id=%s',(snapshot['id'],));fresh=c.fetchone()
    if not fresh or fresh['status']!='verified' or fresh['manifest_sha256']!=snapshot['manifest_sha256']:raise RequestError('catalog_mismatch',409)
    if values:c.executemany('INSERT INTO cold_snapshot_devices(snapshot_id,devid,vd,manifest_sha256,event_count,min_event_at,max_event_at,verified_at) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE manifest_sha256=VALUES(manifest_sha256),event_count=VALUES(event_count),min_event_at=VALUES(min_event_at),max_event_at=VALUES(max_event_at),verified_at=VALUES(verified_at)',values)
   db.commit()
  except BaseException:db.rollback();raise
  finally:db.close()
  return seen
 def _prepare(self,snapshot):
  return self.library.prepare(snapshot,root=self.root,trusted_public_key=self.public_key,cache_root=self.cache,budget=CACHE_BUDGET)
 def _valid_result(self,result,job):
  keys={'rows','has_more','next_cursor','page_size','snapshot_id','manifest_sha256','filters'} if job['request']['kind']=='list' else {'event','fields_text','notes','snapshot_id','manifest_sha256'}
  if not isinstance(result,dict) or set(result)!=keys or result['snapshot_id']!=str(job['snapshot_id']) or result['manifest_sha256']!=job['snapshot']['manifest_sha256']:raise RequestError('service_unavailable',502)
  rows=result.get('rows',[result.get('event')])
  if not isinstance(rows,list) or len(rows)>50:raise RequestError('service_unavailable',502)
  if job['request']['kind']=='list' and (type(result['has_more']) is not bool or (type(result['page_size']) is not int or result['page_size']!=50) or result['next_cursor'] is not None and not isinstance(result['next_cursor'],str)):raise RequestError('service_unavailable',502)
  for row in rows:
   if not isinstance(row,dict) or row.get('devid')!=job['device']['serial'] or row.get('vd')!=job['device']['vdom'] or not isinstance(row.get('id'),str) or not re.fullmatch(r'[1-9][0-9]{0,19}',row['id']) or int(row['id'])>2**64-1:raise RequestError('invalid_scope',409)
  if job['request']['kind']=='detail':
   if result['event']['id']!=job['request']['event_id'] or not isinstance(result['fields_text'],str) or not isinstance(result['notes'],list) or len(result['notes'])>100:raise RequestError('invalid_scope',409)
   for note in result['notes']:
    if not isinstance(note,dict) or note.get('event_id')!=job['request']['event_id']:raise RequestError('invalid_scope',409)
  for row in rows:
   if row.get('file_id')!=str(job['snapshot']['file_id']):raise RequestError('invalid_scope',409)
  encode(result);return result
 def _run(self,job_id):
  with self.lock:
   job=self.jobs.get(job_id)
   if not job:return
   job['status']='preparing'
  try:
   if self.authorize(job['actor'],job['device']['id'])!=job['device']:raise RequestError('access_denied',403)
   snapshot=self.snapshot(job['snapshot_id'],job['snapshot']);prepared=self._prepare(snapshot);pairs=self._coverage(snapshot,prepared)
   if (job['device']['serial'],job['device']['vdom']) not in pairs:raise RequestError('event_not_found',404)
   request=job['request'];result=self.library.query(prepared,job['device']['serial'],job['device']['vdom'],request['filters'],cursor=request['cursor'],event_id=request['event_id'],kind=request['kind'],cursor_key=self.cursor_key)
   result=self._valid_result(result,job)
   if self.authorize(job['actor'],job['device']['id'])!=job['device']:raise RequestError('access_denied',403)
   self.snapshot(job['snapshot_id'],job['snapshot'])
   with self.lock:
    if self.jobs.get(job_id) is not job:return
    # Finished responses have a separate memory budget from disk cache.
    while sum(j.get('result_bytes',0) for j in self.jobs.values())+len(encode(result))>MAX_RESULT_MEMORY:
     old=[j for j in self.jobs.values() if j['status'] in ('ready','error') and j['id']!=job_id]
     if not old:raise RequestError('queue_full',429)
     del self.jobs[min(old,key=lambda j:j['touched'])['id']]
    job.update(status='ready',result=result,result_bytes=len(encode(result)),error=None,touched=self.clock())
  except Exception as e:
   code=e.code if isinstance(e,RequestError) else getattr(e,'code','service_unavailable');status=e.status if isinstance(e,RequestError) else LIB_ERRORS.get(code,503)
   if code not in LIB_ERRORS and code not in {'access_denied','unauthenticated','queue_full','job_not_found','service_unavailable'}:code='service_unavailable';status=503
   with self.lock:
    if self.jobs.get(job_id) is job:job.update(status='error',result=None,error={'code':code,'status':status},touched=self.clock())
 def _maintain(self):
  rows=self.sql("SELECT c.* FROM cold_snapshots c WHERE c.status='verified' AND c.restore_verified_at IS NOT NULL AND c.event_count>0 AND c.id>%s AND NOT EXISTS(SELECT 1 FROM cold_snapshot_devices d WHERE d.snapshot_id=c.id AND d.manifest_sha256=c.manifest_sha256) ORDER BY c.id LIMIT 1",(self.maintenance_id,))
  if not rows:self.maintenance_id=0;return
  snapshot=rows[0];self.maintenance_id=int(snapshot['id']);self._coverage(snapshot,self._prepare(snapshot))
 def _work(self):
  while not self.stop.is_set():
   try:job_id=self.pending.get(timeout=.5)
   except queue.Empty:
    if self.maintenance and self.clock()-self.last_maintenance>=60:
     self.last_maintenance=self.clock()
     try:self._maintain()
     except Exception:pass # No data/path/secret exceptions in the journal.
    continue
   try:self._run(job_id)
   finally:self.pending.task_done()
 def close(self):self.stop.set();self.worker.join(timeout=2)

class Server:
 def __init__(self,listener,broker,peer_uid):self.listener=listener;self.broker=broker;self.peer_uid=peer_uid;self.slots=threading.BoundedSemaphore(4);self.stop=threading.Event()
 @staticmethod
 def _read(client,size,deadline=None):
  deadline=time.monotonic()+1 if deadline is None else deadline
  out=bytearray()
  while len(out)<size:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise socket.timeout()
   client.settimeout(remaining)
   part=client.recv(size-len(out))
   if not part:raise RequestError('invalid_request')
   out.extend(part)
  return bytes(out)
 def _client(self,client):
  try:
   client.settimeout(1)
   _,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   if uid!=self.peer_uid:response=error('access_denied',403)
   else:
    deadline=time.monotonic()+1
    size=struct.unpack('!I',self._read(client,4,deadline))[0]
    if not 0<size<=REQUEST_MAX:raise RequestError('invalid_request')
    request=strict_json(self._read(client,size,deadline));response=self.broker.handle(request)
   client.settimeout(1)
   payload=encode(response);client.sendall(struct.pack('!I',len(payload))+payload)
  except RequestError as e:
   try:payload=encode(error(e.code,e.status));client.sendall(struct.pack('!I',len(payload))+payload)
   except OSError:pass
  except (OSError,ValueError):pass
  finally:client.close();self.slots.release()
 def serve(self):
  self.listener.settimeout(.5)
  while not self.stop.is_set():
   try:client,_=self.listener.accept()
   except socket.timeout:continue
   except OSError:break
   if not self.slots.acquire(blocking=False):
    try:raw=encode(error('queue_full',429));client.settimeout(.1);client.sendall(struct.pack('!I',len(raw))+raw)
    except OSError:pass
    finally:client.close()
    continue
   threading.Thread(target=self._client,args=(client,),daemon=True).start()
 def close(self):self.stop.set();self.listener.close();self.broker.close()

def credential(name,limit=16384):
 base=os.environ.get('CREDENTIALS_DIRECTORY','')
 if not base or not Path(base).is_absolute():raise RuntimeError('credentials_unavailable')
 fd=os.open(Path(base)/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  # systemd may expose LoadCredential files as root:root 0440 inside
  # its private credential mount. Permit only root/service group read;
  # group write/execute and every other-user permission remain forbidden.
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid not in (0,os.geteuid()) or info.st_gid not in (0,os.getegid()) or info.st_mode&0o037 or not 0<info.st_size<=limit:raise RuntimeError('credentials_unavailable')
  return stream.read(limit+1)

def main():
 if os.environ.get('LISTEN_PID')!=str(os.getpid()) or os.environ.get('LISTEN_FDS')!='1':raise RuntimeError('socket_activation_required')
 config=strict_json(credential('database'))
 if set(config)!={'user','password'} or config['user']!='fls_cold_query' or not isinstance(config['password'],str) or not 16<=len(config['password'])<=512:raise RuntimeError('credentials_invalid')
 public=credential('trusted-public-key');library=importlib.import_module('cold_query')
 def factory():
  db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',charset='utf8mb4',autocommit=True,cursorclass=pymysql.cursors.DictCursor,connect_timeout=1,read_timeout=1,write_timeout=1)
  with db.cursor() as c:c.execute("SET time_zone='+00:00',max_statement_time=1")
  return db
 listener=socket.socket(fileno=3)
 if listener.family!=socket.AF_UNIX or listener.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM or listener.getsockname()!=SOCKET:raise RuntimeError('socket_activation_invalid')
 broker=Broker(factory,library,public_key=public);server=Server(listener,broker,pwd.getpwnam('fls-web').pw_uid)
 def stop(_signum,_frame):server.close()
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 try:server.serve()
 finally:server.close()

if __name__=='__main__':
 try:main()
 except Exception:print('{"status":"error","code":"cold_query_service_unavailable"}');raise SystemExit(1)
