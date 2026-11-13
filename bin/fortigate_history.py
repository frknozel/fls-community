#!/usr/bin/python3
"""Append-only observed configuration history with a durable, replayable outbox."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

DEVICE='FGT0000000000000'
VDOM='root'
ROOT=Path('/srv/fls-server/metrics/fortigate')
COMPONENTS=('policies','profile_groups','profiles_virus','profiles_webfilter','profiles_app-ctrl','profiles_dns','profiles_ips','profiles_ssl','url_filters')
MISSING=object()

class HistoryError(Exception):
    pass

def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)

def sql_time(value):
    if not isinstance(value,str):raise HistoryError('timestamp')
    try:
        stamp=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if stamp.tzinfo is None:raise ValueError()
        return stamp.astimezone(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')
    except (ValueError,OverflowError):raise HistoryError('timestamp') from None

def mapping(values):
    if not isinstance(values,list) or not values or not all(isinstance(v,dict) for v in values):return None
    for field in ('id','label','match'):
        keys=[str(v.get(field)) for v in values]
        if all(v.get(field) is not None for v in values) and len(set(keys))==len(keys):
            return field,dict(zip(keys,values))
    return None

def differences(before,after,path=()):
    """Preserve ordered rule changes and distinguish absent fields from JSON null."""
    if before is not MISSING and after is not MISSING and canonical(before)==canonical(after):return []
    if (isinstance(before,dict) or before is MISSING) and (isinstance(after,dict) or after is MISSING):
        a={} if before is MISSING else before;b={} if after is MISSING else after;result=[]
        for key in sorted(set(a)|set(b)):result+=differences(a.get(key,MISSING),b.get(key,MISSING),path+(key,))
        return result
    if (isinstance(before,list) or before is MISSING) and (isinstance(after,list) or after is MISSING):
        if before is MISSING:
            keyed=mapping(after)
            if keyed:
                field,items=keyed;return [change for key,item in items.items() for change in differences(MISSING,item,path+(field+'='+key,))]
        if after is MISSING:
            keyed=mapping(before)
            if keyed:
                field,items=keyed;return [change for key,item in items.items() for change in differences(item,MISSING,path+(field+'='+key,))]
    if isinstance(before,list) and isinstance(after,list):
        a=mapping(before);b=mapping(after)
        if a and b and a[0]==b[0]:
            field,a=a;_,b=b;result=[]
            if path and path[-1] in ('rules','entries','filters') and list(a)!=list(b):
                result+=differences(list(a),list(b),path+('_order',))
            for key in sorted(set(a)|set(b)):
                result+=differences(a.get(key,MISSING),b.get(key,MISSING),path+(field+'='+key,))
            return result
    return [{'path':list(path),'before_exists':before is not MISSING,'after_exists':after is not MISSING,
             'before':None if before is MISSING else before,'after':None if after is MISSING else after}]

def objects(component,data,raw=None):
    if not isinstance(data,list) or any(not isinstance(row,dict) for row in data):raise HistoryError('component_schema')
    result={}
    originals={}
    for row in raw or []:
        identity=(str(row.get('policyid'))+':'+str(row.get('uuid','')).lower()) if component=='policies' else str(row.get('id','')) if component=='url_filters' else str(row.get('name',''))
        originals[identity]=row
    def add(identity,kind,name,document,policyid=None,uuid=None,original=None):
        key=hashlib.sha256(identity.encode()).digest()
        if key in result:raise HistoryError('duplicate_identity')
        result[key]={'kind':kind,'name':str(name)[:512],'document':original if original is not None else document,'display':document,'policyid':policyid,'uuid':uuid}
    if component=='policies':
        for policy in data:
            p=dict(policy)
            for key in ('srcintf','dstintf','srcaddr','dstaddr','service'):
                if isinstance(p.get(key),list):p[key]=sorted(p[key])
            pid=p.get('policyid');uuid=p.get('uuid','')
            if not isinstance(pid,int) or not re.fullmatch(r'[a-fA-F0-9-]{36}',uuid):raise HistoryError('policy_identity')
            original=originals.get(str(pid)+':'+uuid.lower())
            if original is not None:
                original=dict(original)
                for key in ('srcintf','dstintf','srcaddr','dstaddr','service'):
                    if isinstance(original.get(key),list):original[key]=sorted(original[key],key=canonical)
            add('policy:'+str(pid)+':'+uuid.lower(),'policy',p.get('name',''),p,pid,uuid.lower(),original)
        add('policy-order','policy_order','Policy sırası',{'policy_order':[{'policyid':p['policyid'],'uuid':p['uuid'].lower()} for p in data]})
    else:
        kind=component[9:] if component.startswith('profiles_') else 'profile_group' if component=='profile_groups' else 'url_filter'
        for row in data:
            identity=str(row.get('id','')) if component=='url_filters' else str(row.get('name',''))
            if not identity:raise HistoryError('object_identity')
            add(component+':'+identity,kind,row.get('name',identity),row,original=originals.get(identity))
    return result

def normalized_collection(component,data,raw=None):
    values=objects(component,data,raw)
    # Object-key order is metadata; the real policy sequence has its own object.
    return [{'key':key.hex(),**value} for key,value in sorted(values.items())]

def atomic(path,value,mode=0o640):
    fd,name=tempfile.mkstemp(prefix='.history-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'w') as stream:stream.write(canonical(value)+'\n');stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)

def enqueue(snapshot,root=ROOT,device=None):
    if snapshot.get('device')!=(device or {'serial':DEVICE,'vdom':VDOM}):raise HistoryError('device_scope')
    outbox=root/'history-outbox';outbox.mkdir(mode=0o700,parents=True,exist_ok=True);outbox.chmod(0o700)
    components={key:snapshot.get('components',{}).get(key,{}) for key in COMPONENTS}
    record={'schema':1,'device':snapshot['device'],'updated_at':snapshot['updated_at'],'components':components}
    value=canonical(record);digest=hashlib.sha256(value.encode()).hexdigest()[:16]
    stamp=sql_time(snapshot['updated_at']).replace('-','').replace(':','').replace(' ','T').replace('.','')
    path=outbox/(stamp+'-'+digest+'.json')
    if not path.exists():atomic(path,record,0o600)
    return path

def connect():
    # The poller account receives this credential only in its config service.
    directory=os.environ.get('CREDENTIALS_DIRECTORY');path=Path(directory)/'fortigate-history.json' if directory else Path('/etc/fls/fortigate-history.json')
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info=os.fstat(stream.fileno());forbidden=0o037 if directory else 0o077
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode&forbidden or info.st_size>16384:raise HistoryError('credential')
            config=json.loads(stream.read(16385))
        if config.get('user')!='fls_history' or not isinstance(config.get('password'),str):raise HistoryError('credential')
        import pymysql
        return pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',
                               charset='utf8mb4',autocommit=False,connect_timeout=2,read_timeout=5,write_timeout=5,cursorclass=pymysql.cursors.DictCursor)
    except Exception:raise HistoryError('history_database') from None

def store(connection,snapshot,device=None):
    identity=device or {'serial':DEVICE,'vdom':VDOM};serial=identity['serial'];vdom=identity['vdom']
    if snapshot.get('schema')!=1 or snapshot.get('device')!=identity:raise HistoryError('device_scope')
    inserted=0
    try:
        connection.begin()
        with connection.cursor() as cursor:
            for component in COMPONENTS:
                sample=snapshot.get('components',{}).get(component)
                if not isinstance(sample,dict) or not sample.get('attempted_at'):raise HistoryError('component_schema')
                attempted=sql_time(sample['attempted_at'])
                cursor.execute('SELECT id FROM fg_config_observations WHERE device=%s AND vd=%s AND component=%s AND attempted_at=%s',(serial,vdom,component,attempted))
                if cursor.fetchone():continue
                cursor.execute('SELECT id,attempted_at,observed_at,version_id FROM fg_config_observations WHERE device=%s AND vd=%s AND component=%s ORDER BY attempted_at DESC LIMIT 1',(serial,vdom,component))
                latest=cursor.fetchone()
                if latest and attempted<=latest['attempted_at'].strftime('%Y-%m-%d %H:%M:%S.%f'):raise HistoryError('out_of_order')
                error=sample.get('error')
                if error:
                    code=error if isinstance(error,str) and re.fullmatch(r'[a-z0-9_]{1,64}',error) else 'poll_failed'
                    cursor.execute('INSERT INTO fg_config_observations(device,vd,component,attempted_at,error_code) VALUES(%s,%s,%s,%s,%s)',(serial,vdom,component,attempted,code));inserted+=1;continue
                observed=sql_time(sample.get('observed_at'))
                if observed<attempted:raise HistoryError('timestamp')
                values=normalized_collection(component,sample.get('data'),sample.get('history_data'));content=canonical(values)
                fingerprint=[{k:v for k,v in obj.items() if k!='display'} for obj in values]
                digest=hashlib.sha256(canonical(fingerprint).encode()).digest()
                cursor.execute('SELECT id,content_json FROM fg_config_versions WHERE device=%s AND vd=%s AND component=%s AND content_sha=%s',(serial,vdom,component,digest));version=cursor.fetchone()
                if version:version_id=version['id']
                else:
                    cursor.execute('INSERT INTO fg_config_versions(device,vd,component,content_sha,content_json,created_at) VALUES(%s,%s,%s,%s,%s,%s)',(serial,vdom,component,digest,content,observed));version_id=cursor.lastrowid
                cursor.execute('SELECT o.id,o.attempted_at,o.observed_at,o.version_id,v.content_json FROM fg_config_observations o JOIN fg_config_versions v ON v.id=o.version_id WHERE o.device=%s AND o.vd=%s AND o.component=%s ORDER BY o.observed_at DESC,o.id DESC LIMIT 1',(serial,vdom,component));previous=cursor.fetchone()
                if previous and observed<=previous['observed_at'].strftime('%Y-%m-%d %H:%M:%S.%f'):raise HistoryError('out_of_order')
                cursor.execute('INSERT INTO fg_config_observations(device,vd,component,attempted_at,observed_at,version_id) VALUES(%s,%s,%s,%s,%s,%s)',(serial,vdom,component,attempted,observed,version_id));observation_id=cursor.lastrowid;inserted+=1
                if previous and previous['version_id']==version_id:continue
                before={v['key']:v for v in json.loads(previous['content_json'])} if previous else {}
                after={v['key']:v for v in values}
                for key in sorted(set(before)|set(after)):
                    a=before.get(key);b=after.get(key)
                    if a and b and canonical(a['document'])==canonical(b['document']):continue
                    obj=b or a;action='baseline' if previous is None else 'added' if a is None else 'removed' if b is None else 'modified'
                    diff=differences(a['document'] if a else MISSING,b['document'] if b else MISSING)
                    cursor.execute('''INSERT INTO fg_config_changes(observation_id,previous_observation_id,device,vd,component,object_key,object_kind,object_name,policyid,poluuid,action,last_confirmed_at,observed_at,before_json,after_json,diff_json)
                                      VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                                   (observation_id,previous['id'] if previous else None,serial,vdom,component,bytes.fromhex(key),obj['kind'],obj['name'],obj['policyid'],obj['uuid'],action,
                                    previous['attempted_at'] if previous else None,observed,canonical(a['document']) if a else None,canonical(b['document']) if b else None,canonical(diff)))
        connection.commit()
        return inserted
    except Exception:
        connection.rollback();raise

def drain(root=ROOT,connector=connect,limit=60,budget=18,device=None):
    outbox=root/'history-outbox';paths=sorted(outbox.glob('*.json'));start=time.monotonic();done=0;error=None;connection=None
    try:
        if paths:connection=connector()
        for path in paths[:limit]:
            if done and time.monotonic()-start>budget:break
            if path.stat().st_size>16777216:raise HistoryError('outbox_size')
            value=json.loads(path.read_text());store(connection,value,device=device);path.unlink();done+=1
        if done:
            directory=os.open(outbox,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
    except Exception as exception:error=str(exception) if isinstance(exception,HistoryError) else 'history_write'
    finally:
        if connection:connection.close()
    result={'checked_at':dt.datetime.now(dt.timezone.utc).isoformat(),'pending':max(0,len(paths)-done),'processed':done,'error':error}
    atomic(root/'history-status.json',result)
    return result

def main():
    parser=argparse.ArgumentParser(description='Replay the durable FortiGate configuration-history outbox.')
    parser.add_argument('command',choices=['drain']);args=parser.parse_args()
    # The same file lock as the config poller protects chronological replay.
    import fcntl
    with (ROOT/'.config.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);print(canonical(drain()))

if __name__=='__main__':main()
