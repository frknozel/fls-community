#!/usr/bin/python3
"""Public-key-only archive checks and resumable, bounded full-source verification."""
import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import pymysql

UTC=dt.timezone.utc
MAX_JSON=65536
DEFAULTS={'max_bytes':536870912,'max_seconds':45,'read_bytes_per_second':8388608,'target_age_days':30}
RANGES={'max_bytes':(1048576,2147483648),'max_seconds':(1,60),'read_bytes_per_second':(1048576,67108864),'target_age_days':(1,365)}
NAME=re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}\.jsonl$')
HEX=re.compile(r'^[0-9a-f]{64}$')

class IntegrityError(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)

class FileChanged(IntegrityError):pass

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')

def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise IntegrityError('json_duplicate')
        result[key]=value
    return result

def strict_json(data):
    try:
        if len(data)>MAX_JSON:raise IntegrityError('json_size')
        return json.loads(data,object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in ()).throw(IntegrityError('json_number')))
    except (UnicodeError,ValueError,TypeError,RecursionError) as exc:
        if isinstance(exc,IntegrityError):raise
        raise IntegrityError('json_invalid') from exc

def read_file(path,maximum=MAX_JSON,private=False):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>maximum:raise IntegrityError('file_unsafe')
            if private and (info.st_uid not in (0,os.geteuid()) or info.st_gid not in (0,os.getegid()) or info.st_mode&0o037):raise IntegrityError('credential_permissions')
            data=stream.read(maximum+1)
            if len(data)>maximum:raise IntegrityError('file_size')
            return data
    except OSError as exc:raise IntegrityError('file_unavailable') from exc

def source_name(name):
    if not isinstance(name,str) or not NAME.fullmatch(name):raise IntegrityError('source_name')
    try:dt.datetime.strptime(name[:-6],'%Y-%m-%d-%H')
    except ValueError as exc:raise IntegrityError('source_name') from exc
    return name

def fingerprint(info):
    return {'dev':info.st_dev,'ino':info.st_ino,'size':info.st_size,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}

def raw_open(path,expected_size):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except OSError as exc:raise IntegrityError('raw_unavailable') from exc
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise IntegrityError('raw_unsafe')
        if info.st_size!=expected_size:raise IntegrityError('raw_size')
        identity=fingerprint(info)
        raw_unchanged(path,fd,identity)
        return fd,identity
    except BaseException:os.close(fd);raise

def raw_unchanged(path,fd,identity):
    try:
        current=os.fstat(fd);named=os.lstat(path)
        if not stat.S_ISREG(named.st_mode) or named.st_nlink!=1 or fingerprint(current)!=identity or fingerprint(named)!=identity:raise FileChanged('raw_changed')
    except OSError as exc:raise FileChanged('raw_changed') from exc

def load_public(path):
    try:key=serialization.load_pem_public_key(read_file(path,4096))
    except (ValueError,TypeError) as exc:raise IntegrityError('public_key') from exc
    if not isinstance(key,Ed25519PublicKey):raise IntegrityError('public_key')
    return key

def verify_manifest(item,folder,key,previous):
    """Verify small signed bytes, their chain, and every SQL identity binding."""
    name=source_name(item['source_file'])
    disk=strict_json(read_file(Path(folder)/(name+'.manifest.json')))
    try:
        if not isinstance(disk,dict) or set(disk)!={'manifest','signature'} or not isinstance(disk['manifest'],dict) or not isinstance(disk['signature'],str):raise IntegrityError('manifest_shape')
        m=disk['manifest'];encoded=canonical(m)
        signature=base64.b64decode(disk['signature'],validate=True)
        if len(signature)!=64:raise IntegrityError('manifest_signature')
        key.verify(signature,encoded)
        if m.get('schema')!='fls-integrity-v1' or m.get('signature_algorithm')!='Ed25519':raise IntegrityError('manifest_schema')
        for field in ('sha256','previous_manifest_sha256'):
            if not isinstance(m.get(field),str) or not HEX.fullmatch(m[field]):raise IntegrityError('manifest_shape')
        for field in ('bytes','rows'):
            if type(m.get(field)) is not int or not 0<=m[field]<=2**64-1:raise IntegrityError('manifest_shape')
        digest=hashlib.sha256(encoded).hexdigest()
        if m.get('source_file')!=name or m['previous_manifest_sha256']!=previous:raise IntegrityError('manifest_chain')
        bindings={'manifest_hash':digest,'sha256':m['sha256'],'bytes':m['bytes'],'rows_count':m['rows'],'previous_hash':previous,'signature':disk['signature']}
        if any(item.get(field)!=value for field,value in bindings.items()):raise IntegrityError('manifest_catalog')
        if strict_json(item['manifest_json'])!=m:raise IntegrityError('manifest_catalog')
        signed=dt.datetime.fromisoformat(m['signed_at'])
        if signed.tzinfo is None or signed.utcoffset()!=dt.timedelta(0):raise IntegrityError('manifest_time')
        stored=item['signed_at']
        if isinstance(stored,str):stored=dt.datetime.fromisoformat(stored)
        if stored!=signed.replace(tzinfo=None,microsecond=0):raise IntegrityError('manifest_catalog')
        return m,digest
    except InvalidSignature as exc:raise IntegrityError('manifest_signature') from exc
    except (KeyError,TypeError,ValueError,OverflowError) as exc:
        if isinstance(exc,IntegrityError):raise
        raise IntegrityError('manifest_shape') from exc

def verify_fast(item,folder,raw_root,key,previous):
    if item.get('status')=='FAILED' or item.get('check_status')=='FAILED':raise IntegrityError('previous_failure')
    m,digest=verify_manifest(item,folder,key,previous)
    fd,_=raw_open(Path(raw_root)/item['source_file'],m['bytes']);os.close(fd)
    return m,digest

def full_hash(path):
    """One new closed hour is read once; historical fast checks never call this."""
    try:expected=os.lstat(path).st_size
    except OSError as exc:raise IntegrityError('raw_unavailable') from exc
    fd,identity=raw_open(path,expected)
    h=hashlib.sha256();size=rows=0
    try:
        with os.fdopen(fd,'rb',closefd=False) as stream:
            while chunk:=stream.read(4*1024*1024):h.update(chunk);size+=len(chunk);rows+=chunk.count(b'\n')
        raw_unchanged(path,fd,identity)
        if size!=identity['size']:raise FileChanged('raw_changed')
        return h.hexdigest(),size,rows
    finally:os.close(fd)

def validate_limits(config):
    result={}
    for name,(minimum,maximum) in RANGES.items():
        value=config.get(name,DEFAULTS[name])
        if type(value) is not int or not minimum<=value<=maximum:raise IntegrityError('config_limits')
        result[name]=value
    return result

def load_config(path):
    config=strict_json(read_file(path,16384,private=True))
    if not isinstance(config,dict) or not set(config)<={'user','password',*DEFAULTS}:raise IntegrityError('config_shape')
    if config.get('user')!='fls_scrub' or not isinstance(config.get('password'),str) or not 16<=len(config['password'])<=512:raise IntegrityError('config_credentials')
    return {**config,**validate_limits(config)}

def atomic_json(path,value):
    path=Path(path);fd,temp=tempfile.mkstemp(prefix='.checkpoint-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(canonical(value)+b'\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        try:os.unlink(temp)
        except FileNotFoundError:pass

def load_checkpoint(path):
    try:
        value=strict_json(read_file(path,private=True))
        if not isinstance(value,dict) or not isinstance(value.get('checksum'),str):return None
        body={k:v for k,v in value.items() if k!='checksum'}
        if hashlib.sha256(canonical(body)).hexdigest()!=value['checksum']:return None
        if type(value.get('manifest_id')) is not int or not 1<=value['manifest_id']<=2**32-1:return None
        return value
    except (IntegrityError,ValueError,TypeError):return None

def save_checkpoint(path,binding,state):
    value={**binding,**state}
    atomic_json(path,{**value,'checksum':hashlib.sha256(canonical(value)).hexdigest()})


def checkpoint_binding(item,m,identity):
    return {'schema':1,'manifest_id':int(item['id']),'manifest_hash':item['manifest_hash'],'expected_raw_hash':m['sha256'],'expected_size':m['bytes'],'expected_rows':m['rows'],'fingerprint':identity}

def checkpoint_state(value,binding):
    if not isinstance(value,dict) or set(value)!={*binding,'offset','rows','state','checksum'} or any(value.get(k)!=v for k,v in binding.items()):return None
    if value['checksum']!=hashlib.sha256(canonical({k:v for k,v in value.items() if k!='checksum'})).hexdigest():return None
    offset,rows,state=value['offset'],value['rows'],value['state']
    if type(offset) is not int or not 0<=offset<=binding['expected_size'] or type(rows) is not int or not 0<=rows<=binding['expected_rows']:return None
    if offset==0:return {'offset':0,'rows':0,'state':None} if rows==0 and state is None else None
    if not isinstance(state,str) or not 1<=len(state)<=2048:return None
    try:
        if not 1<=len(base64.b64decode(state,validate=True))<=1024:return None
    except ValueError:return None
    return {'offset':offset,'rows':rows,'state':state}

def hash_step(helper,fd,state,byte_limit,seconds,rate):
    request={'schema':1,**state,'limit_bytes':byte_limit,'max_seconds':seconds,'rate_bytes_per_second':rate}
    try:
        process=subprocess.run([str(helper),'--fd='+str(fd)],input=canonical(request),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=seconds+2,check=False)
        if process.returncode!=0:
            failure=strict_json(process.stdout)
            if isinstance(failure,dict) and failure.get('error')=='file_changed':raise FileChanged('raw_changed')
            if isinstance(failure,dict) and failure.get('error')=='invalid_state':raise IntegrityError('hash_state')
            raise IntegrityError('hash_helper')
        result=strict_json(process.stdout)
        if not isinstance(result,dict) or set(result)!={'schema','offset','rows','state','complete','sha256','read_bytes'} or type(result['schema']) is not int or result['schema']!=1:raise IntegrityError('hash_helper_protocol')
        for field in ('offset','rows','read_bytes'):
            if type(result[field]) is not int or result[field]<0:raise IntegrityError('hash_helper_protocol')
        if result['offset']!=state['offset']+result['read_bytes'] or result['read_bytes']>byte_limit or result['rows']<state['rows'] or type(result['complete']) is not bool:raise IntegrityError('hash_helper_protocol')
        if not isinstance(result['state'],str):raise IntegrityError('hash_helper_protocol')
        state_bytes=base64.b64decode(result['state'],validate=True)
        if len(state_bytes)!=108 or base64.b64encode(state_bytes).decode()!=result['state']:raise IntegrityError('hash_helper_protocol')
        if result['complete']:
            if not isinstance(result['sha256'],str) or not HEX.fullmatch(result['sha256']):raise IntegrityError('hash_helper_protocol')
        elif result['sha256'] is not None:raise IntegrityError('hash_helper_protocol')
        return result
    except (subprocess.TimeoutExpired,OSError,ValueError) as exc:
        if isinstance(exc,IntegrityError):raise
        raise IntegrityError('hash_helper') from exc

@contextlib.contextmanager
def integrity_lock(db,wait=0):
    with db.cursor() as c:
        c.execute("SELECT GET_LOCK('fls_archive_integrity_v1',%s)",(wait,));row=c.fetchone()
        acquired=(next(iter(row.values())) if isinstance(row,dict) else row[0] if row else 0)==1
    try:yield acquired
    finally:
        if acquired:
            with db.cursor() as c:c.execute("SELECT RELEASE_LOCK('fls_archive_integrity_v1')")

class Store:
    def __init__(self,db):self.db=db
    def guard(self):return integrity_lock(self.db)
    def failed(self):
        with self.db.cursor() as c:
            c.execute("SELECT manifest_id FROM archive_integrity_checks WHERE status='FAILED' LIMIT 1")
            return c.fetchone() is not None
    def candidates(self,cutoff,active=None):
        columns="m.*,c.last_full_verified_at,c.status check_status,COALESCE((SELECT p.manifest_hash FROM archive_manifests p WHERE p.source_file<m.source_file ORDER BY p.source_file DESC LIMIT 1),REPEAT('0',64)) predecessor_hash"
        join='archive_integrity_checks c JOIN archive_manifests m ON m.id=c.manifest_id'
        rows=[]
        with self.db.cursor(pymysql.cursors.DictCursor) as c:
            if active is not None:
                c.execute('SELECT '+columns+' FROM '+join+' WHERE c.manifest_id=%s',(active,));value=c.fetchone()
                if value:rows.append(value)
            due_join='archive_integrity_checks c FORCE INDEX(oldest_full_check) STRAIGHT_JOIN archive_manifests m ON m.id=c.manifest_id'
            c.execute('SELECT '+columns+' FROM '+due_join+' WHERE (c.last_full_verified_at IS NULL OR c.last_full_verified_at<=%s)'+(' AND c.manifest_id<>%s' if rows else '')+' ORDER BY c.last_full_verified_at,c.manifest_id LIMIT '+str(16-len(rows)),(cutoff,active) if rows else (cutoff,))
            rows.extend(c.fetchall())
        return rows
    def update(self,item,status,progress=0,error='',complete=False,started=False):
        try:
            with self.db.cursor() as c:
                c.execute('SELECT status FROM archive_manifests WHERE id=%s FOR UPDATE',(item['id'],));row=c.fetchone()
                current=row['status'] if isinstance(row,dict) else row[0] if row else None
                if current is None:raise IntegrityError('manifest_missing')
                if current=='FAILED' and status!='FAILED':raise IntegrityError('previous_failure')
                if status=='FAILED':c.execute('UPDATE archive_manifests SET status=%s WHERE id=%s',('FAILED',item['id']))
                elif complete:c.execute("UPDATE archive_manifests SET status='verified',verified_at=UTC_TIMESTAMP(6) WHERE id=%s",(item['id'],))
                c.execute('INSERT INTO archive_integrity_checks(manifest_id,last_full_verified_at,status,error_code,progress_bytes,verification_started_at,updated_at) VALUES(%s,'+('UTC_TIMESTAMP(6)' if complete else 'NULL')+',%s,%s,%s,'+('UTC_TIMESTAMP(6)' if started else 'NULL')+',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE status=VALUES(status),error_code=VALUES(error_code),progress_bytes=VALUES(progress_bytes),verification_started_at='+('VALUES(verification_started_at)' if started else 'verification_started_at')+(',last_full_verified_at=VALUES(last_full_verified_at)' if complete else '')+',updated_at=VALUES(updated_at)',(item['id'],status,error,progress))
            self.db.commit()
        except BaseException:self.db.rollback();raise
    def worker(self,status,limits,bytes_read=0,files=0,current=None,error='',begin=False,finish=False):
        columns='id,version,status,heartbeat_at,bytes_read,files_verified,current_manifest_id,max_bytes,max_seconds,read_bytes_per_second,target_age_days,last_error_code'
        values='1,1,%s,UTC_TIMESTAMP(6),%s,%s,%s,%s,%s,%s,%s,%s'
        args=[status,bytes_read,files,current,limits['max_bytes'],limits['max_seconds'],limits['read_bytes_per_second'],limits['target_age_days'],error]
        if begin:columns+=',last_started_at';values+=',UTC_TIMESTAMP(6)'
        if finish:columns+=',last_finished_at';values+=',UTC_TIMESTAMP(6)'
        updates=','.join(name+'=VALUES('+name+')' for name in columns.split(',') if name not in ('id','version'))
        try:
            with self.db.cursor() as c:c.execute('INSERT INTO archive_integrity_worker('+columns+') VALUES('+values+') ON DUPLICATE KEY UPDATE '+updates,args)
            self.db.commit()
        except BaseException:self.db.rollback();raise

def _run_scrub(store,key,raw_root,manifest_root,state_root,helper,limits,clock=time.monotonic):
    """Run once with bounded native chunks. Caller holds the process flock."""
    checkpoint=Path(state_root)/'checkpoint.json';saved=load_checkpoint(checkpoint)
    total=files=0;active=None;started=clock();store.worker('running',limits,begin=True)
    try:
        if store.failed():raise IntegrityError('previous_failure')
        # Recheck proactively; target_age_days is an overdue limit, not a
        # delay before old files first become eligible.
        eligible_hours=min(24,max(1,limits['target_age_days']*6))
        cutoff=dt.datetime.now(UTC).replace(tzinfo=None)-dt.timedelta(hours=eligible_hours)
        items=store.candidates(cutoff,saved.get('manifest_id') if isinstance(saved,dict) else None)
        if saved and not any(item['id']==saved['manifest_id'] for item in items):
            atomic_json(checkpoint,{});saved=None
        ordered=items
        for item in ordered:
            active=item;is_active=isinstance(saved,dict) and saved.get('manifest_id')==item['id']
            if not is_active and item.get('last_full_verified_at') is not None and item['last_full_verified_at']>cutoff:continue
            remaining=limits['max_seconds']-(clock()-started)
            if total>=limits['max_bytes'] or remaining<1:break
            try:m,_=verify_fast(item,manifest_root,raw_root,key,item['predecessor_hash'])
            except IntegrityError as exc:
                store.update(item,'FAILED',error=exc.code);raise
            path=Path(raw_root)/item['source_file'];fd,identity=raw_open(path,m['bytes'])
            try:
                binding=checkpoint_binding(item,m,identity);state=checkpoint_state(saved,binding) if is_active else None
                state=state or {'offset':0,'rows':0,'state':None}
                store.update(item,'partial',state['offset'],started=state['offset']==0)
                reset_once=False
                while total<limits['max_bytes'] and limits['max_seconds']-(clock()-started)>=1:
                    remaining=limits['max_seconds']-(clock()-started);seconds=max(1,min(5,int(remaining)))
                    limit=min(limits['max_bytes']-total,8*1024*1024)
                    raw_unchanged(path,fd,identity)
                    try:result=hash_step(helper,fd,state,limit,seconds,limits['read_bytes_per_second'])
                    except IntegrityError as exc:
                        if exc.code=='hash_state' and state['offset']>0 and not reset_once:
                            reset_once=True;state={'offset':0,'rows':0,'state':None}
                            atomic_json(checkpoint,{});store.update(item,'partial',0,error='checkpoint_reset',started=True)
                            continue
                        raise
                    raw_unchanged(path,fd,identity)
                    total+=result['read_bytes'];store.worker('running',limits,total,files,item['id'])
                    if result['complete']:
                        if (result['sha256'],result['offset'],result['rows'])!=(m['sha256'],m['bytes'],m['rows']):raise IntegrityError('raw_digest')
                        store.update(item,'verified',result['offset'],complete=True);files+=1
                        # Only this private disposable checkpoint is removed; archives are never removed.
                        try:checkpoint.unlink()
                        except FileNotFoundError:pass
                        saved=None;break
                    if result['read_bytes']==0:raise IntegrityError('hash_no_progress')
                    state={name:result[name] for name in ('offset','rows','state')}
                    save_checkpoint(checkpoint,binding,state);saved={**binding,**state}
                    store.update(item,'partial',state['offset'])
                else:break
            except FileChanged:
                atomic_json(checkpoint,{});saved=None;store.update(item,'partial',0,error='raw_changed')
                store.worker('paused',limits,total,files,item['id'],'raw_changed',finish=True)
                return {'status':'paused','bytes_read':total,'files_verified':files,'error_code':'raw_changed'}
            except IntegrityError as exc:
                # A helper/opaque checkpoint failure is retryable from zero and is
                # never proof that signed raw bytes are corrupt.
                if exc.code in ('hash_helper','hash_helper_protocol','hash_no_progress','hash_state'):
                    atomic_json(checkpoint,{});store.update(item,'partial',0,error=exc.code)
                    store.worker('paused',limits,total,files,item['id'],exc.code,finish=True)
                    return {'status':'paused','bytes_read':total,'files_verified':files,'error_code':exc.code}
                store.update(item,'FAILED',error=exc.code);raise
            finally:os.close(fd)
        status='paused' if saved else 'idle';store.worker(status,limits,total,files,None,finish=True)
        return {'status':status,'bytes_read':total,'files_verified':files,'error_code':''}
    except Exception as exc:
        code=exc.code if isinstance(exc,IntegrityError) else 'worker_failed'
        store.worker('failed',limits,total,files,active['id'] if active else None,code,finish=True)
        raise


def run_scrub(store,key,raw_root,manifest_root,state_root,helper,limits,clock=time.monotonic):
    """Caller holds the state-directory flock; DB lock serializes seal/failure decisions."""
    with store.guard() as acquired:
        if not acquired:
            store.worker('paused',limits,error='signing_active',finish=True)
            return {'status':'paused','bytes_read':0,'files_verified':0,'error_code':'signing_active'}
        return _run_scrub(store,key,raw_root,manifest_root,state_root,helper,limits,clock)
