#!/usr/bin/python3
"""Read-only, transactional, resumable indexer for received FortiGate JSONL files."""
import argparse, collections, datetime as dt, hashlib, json, logging, os, re, time
from pathlib import Path
import pymysql

ROOT=Path('/srv/fls-server/raw')
UTC=dt.timezone.utc
PAT=re.compile(r'(?:^|\s)([A-Za-z0-9_.-]+)=(?:"((?:[^"\\]|\\.)*)"|([^\s]*))')
ESC=re.compile(r'\\(["\\])')
BLOCK={'blocked','block','deny','denied','dropped','drop','blocked-quota','block-fail'}
SECURITY_GROUP_MODULES=('webfilter','app-ctrl','dns','ssl','ips')
IPS_BLOCK={'reset','reset_client','reset_server','drop_session'}

def parse(raw):
    return {m[1]:ESC.sub(lambda x:x[1],m[2]) if m[2] is not None else m[3] for m in PAT.finditer(re.sub(r'^<\d+>','',raw,count=1))}

def event_time(f, received):
    value=f.get('eventtime','')
    # A malformed eventtime must not crash the daemon at the same checkpoint forever.
    if re.fullmatch(r'[0-9]{18,21}',value):
        try:
            ns=int(value)
            if ns>10**17:
                result=dt.datetime.fromtimestamp(ns//10**9,UTC).replace(microsecond=(ns%10**9)//1000,tzinfo=None)
                if result.year>=1000:return result
        except (ValueError,OverflowError,OSError):pass
    try:
        result=dt.datetime.strptime(f["date"]+' '+f["time"]+' '+f.get('tz','+0300'),'%Y-%m-%d %H:%M:%S %z').astimezone(UTC).replace(tzinfo=None)
        return result if result.year>=1000 else received
    except (ValueError,KeyError,OverflowError): return received

def classification(f):
    typ,sub,act=f.get('type','unknown'),f.get('subtype','unknown'),f.get('action','')
    rating=typ=='utm' and sub in ('webfilter','dns') and (f.get('eventtype')=='ftgd_err' or 'rating error' in f.get('msg','').lower() or 'no available fortiguard' in (f.get('error','')+' '+f.get('msg','')).lower())
    # A block portal redirect is a DNS denial; ordinary rewrites/safe-search are not.
    dns_block=sub=='dns' and (act=='block-servfail' or act=='redirect' and (rating or f.get('logid','')[-5:] in ('54400','54601','54803') or re.search(r'\bblocked\b',f.get('msg',''),re.I)))
    ips_block=sub=='ips' and act in IPS_BLOCK
    outcome=('security_block' if typ=='utm' else 'local_deny' if typ=='traffic' and sub=='local' else 'policy_deny' if typ=='traffic' and sub=='forward' else 'other_deny') if act in BLOCK or dns_block or ips_block else ('rating_error' if rating else 'observed')
    reason='rating_error' if rating else 'category_block' if sub=='webfilter' and f.get('eventtype')=='ftgd_blk' else 'application_control' if sub=='app-ctrl' else 'ips_signature' if sub=='ips' else 'antivirus' if sub=='virus' else 'certificate_blocklist' if f.get('eventsubtype')=='certificate-blocklisted' else 'ssl_inspection' if sub=='ssl' else 'dns_profile' if sub=='dns' else outcome
    return outcome,int(rating),reason

def integer(s, default=None):
    try: return int(s)
    except (ValueError,TypeError): return default

def bounded_integer(value,minimum,maximum,default=None):
    result=integer(value)
    return result if result is not None and minimum<=result<=maximum else default

def connect():
    c=json.loads(Path('/etc/fls/importer.json').read_text())
    return pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=c['user'],password=c['password'],database='fls',charset='utf8mb4',autocommit=False)

COLS='file_id,byte_offset,byte_length,line_number,raw_sha256,event_at,received_at,type,subtype,action,outcome,rating_error,policyid,poluuid,profile,srcip,srcname,dstip,dstport,hostname,app,category,reason_code,devid,vd,sessionid,fields'
SQL='INSERT INTO events ('+COLS+') VALUES ('+','.join(['%s']*len(COLS.split(',')))+')'

def antivirus_group_key(srcip, fields, event_id):
    """Length-prefixed UTF-8 tuple; missing keys remain isolated per event."""
    value=fields.get('analyticscksum') or fields.get('filehash') or fields.get('checksum') or ''
    values=[str(srcip).strip(' \t\r\n\0\x0b'),str(fields.get('messageid','')).strip(' \t\r\n\0\x0b'),str(value).strip(' \t\r\n\0\x0b')]
    if not all(values): return hashlib.sha256(('event:'+str(event_id)).encode()).digest(),0
    if re.fullmatch('[0-9a-fA-F]+',values[2]): values[2]=values[2].lower()
    parts=[v.encode('utf-8') for v in values]
    payload=b'av1|'+b''.join(str(len(v)).encode()+b':'+v for v in parts)
    return hashlib.sha256(payload).digest(),1

def security_group_key(fields, event_id):
    """Block identity, independent of session/time; incomplete identities stay isolated."""
    clean=lambda value:str(value or '').strip(' \t\r\n\0\x0b')
    module=clean(fields.get('subtype'))
    host_fields=('qname','hostname','sni','servername') if module=='dns' else ('sni','hostname','servername','qname') if module=='ssl' else ('hostname','sni','qname','servername')
    host=next((clean(fields.get(k)) for k in host_fields if clean(fields.get(k))), '')
    reason={k:clean(fields.get(k)) for k in ('action','eventtype','eventsubtype','cat','catdesc','appid','app','appcat','reason','error','msg','filteridx','urlfilteridx','filtertype')}
    reason['code']=classification(fields)[2]
    if module=='dns':
        reason.update({k:clean(fields.get(k)) for k in ('domainfilteridx','domainfilterlist','botnetdomain','botnetip')})
    elif module=='ssl':
        reason.update({k:clean(fields.get(k)) for k in ('certhash','certdesc','tlsver')})
        if re.fullmatch('[0-9a-fA-F]+',reason['certhash']):reason['certhash']=reason['certhash'].lower()
    elif module=='ips':
        # Packet-specific messages/context do not change the attack signature.
        reason={k:clean(fields.get(k)) for k in ('eventtype','eventsubtype','attackid','attack','direction')}
        reason['code']='ips_signature'
        attack_id=integer(reason['attackid'],0)
        reason['attackid']=str(attack_id) if attack_id>0 else ''
    identity={
        'module':clean(fields.get('subtype')), 'devid':clean(fields.get('devid')), 'vd':clean(fields.get('vd')),
        'source':clean(fields.get('srcip')), 'target_kind':'hostname' if host else 'ip',
        'target':host.lower().rstrip('.') if host else clean(fields.get('dstip')),
        'port':clean(fields.get('dstport')), 'protocol':clean(fields.get('proto')),
        'policyid':clean(fields.get('policyid')), 'poluuid':clean(fields.get('poluuid')),
        'profile':clean(fields.get('profile') or fields.get('applist') or fields.get('sensor')),
        'reason':reason,
    }
    if module=='ips':
        identity.update(target=clean(fields.get('dstip')),target_kind='ip',target_hostname=host.lower().rstrip('.'))
    complete=bool(identity['source'] and identity['target'] and integer(identity['policyid'],-1)>=0 and identity['profile'] and any(reason.get(k) for k in ('eventtype','eventsubtype','cat','appid','app','reason','error','msg','attackid','attack')))
    if module=='dns' and not clean(fields.get('qname')):complete=False
    if module=='ips' and not (reason['attackid'] or reason['attack'].lower() not in ('','unknown','n/a','-')):complete=False
    encoded=json.dumps(identity,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    payload=b'security1|'+(encoded.encode('utf-8') if complete else ('event:'+str(event_id)).encode())
    return hashlib.sha256(payload).digest(),int(complete),encoded

def traffic_group_key(fields,event_id):
    """Forward and local denials have separate policy namespaces; profiles are optional."""
    clean=lambda v:str(v or '').strip(' \t\r\n\0\x0b')
    outcome=classification(fields)[0]
    identity={'module':clean(fields.get('subtype')),'outcome':outcome,'devid':clean(fields.get('devid')),'vd':clean(fields.get('vd')),
        'source':clean(fields.get('srcip')),'target':clean(fields.get('dstip')),'target_kind':'ip','port':clean(fields.get('dstport')),'protocol':clean(fields.get('proto')),
        'policyid':clean(fields.get('policyid')),'poluuid':clean(fields.get('poluuid')),'policytype':clean(fields.get('policytype')),
        'source_interface':clean(fields.get('srcintf')),'target_interface':clean(fields.get('dstintf')),
        'reason':{'code':outcome,**{k:clean(fields.get(k)) for k in ('action','reason','error','msg')}}}
    complete=bool(identity['source'] and identity['target'] and integer(identity['policyid'],-1)>=0 and outcome in ('policy_deny','local_deny'))
    encoded=json.dumps(identity,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    payload=b'traffic1|'+(encoded.encode() if complete else ('event:'+str(event_id)).encode())
    return hashlib.sha256(payload).digest(),int(complete),encoded

def insert_traffic_memberships(cursor,events,ignore_existing=False):
    groups={};members=[]
    for event_id,event_at,profile,fields in events:
        key,complete,encoded=traffic_group_key(json.loads(fields),event_id);identity=json.loads(encoded)
        groups[key]=(key,complete,identity['outcome'],identity['module'],bounded_integer(identity['policyid'],0,2**31-1,-1),identity['poluuid'][:40],identity['source'][:45],identity['outcome'],encoded)
        members.append((event_id,key,event_at,profile))
    if groups:cursor.executemany('INSERT IGNORE INTO traffic_groups(group_key,key_complete,outcome,subtype,policyid,poluuid,srcip,reason_code,identity_json) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',[groups[key] for key in sorted(groups)])
    if not members:return 0
    cursor.executemany('INSERT '+('IGNORE ' if ignore_existing else '')+'INTO traffic_event_groups(event_id,group_key,event_at,profile) VALUES(%s,%s,%s,%s)',members)
    return cursor.rowcount

def ingest(db,path,batch_size=1500):
    stat=path.stat()
    with db.cursor() as c:
        c.execute('SELECT id,inode,byte_offset,line_number FROM source_files WHERE name=%s',(path.name,))
        checkpoint=c.fetchone()
        if checkpoint is None:
            c.execute('INSERT IGNORE INTO source_files(name,inode) VALUES(%s,%s)',(path.name,stat.st_ino))
            db.commit()
            c.execute('SELECT id,inode,byte_offset,line_number FROM source_files WHERE name=%s',(path.name,))
            checkpoint=c.fetchone()
        file_id,inode,offset,line_no=checkpoint
    if inode!=stat.st_ino or stat.st_size<offset:
        raise RuntimeError('Source identity/size changed; refusing to skip or overwrite: '+path.name)
    if stat.st_size==offset: return 0
    count=0
    with path.open('rb') as stream:
        stream.seek(offset)
        while True:
            rows=[]; buckets=collections.Counter(); policies={}; devices={}; invalid=[]
            for _ in range(batch_size):
                pos=stream.tell(); line=stream.readline(4*1024*1024+1)
                if not line: break
                if not line.endswith(b'\n'):
                    if len(line)>4*1024*1024: raise RuntimeError('Oversized line: '+path.name)
                    stream.seek(pos); break  # never checkpoint an incomplete line
                line_no+=1
                try:
                    env=json.loads(line);raw=env['raw'];f=parse(raw)
                    if not f.get('type'): raise ValueError('No FortiGate type field')
                    received=dt.datetime.fromisoformat(env['received_at']).astimezone(UTC).replace(tzinfo=None)
                    if received.year<1000:raise ValueError('Receipt time outside SQL date range')
                    event=event_time(f,received);outcome,rating,reason=classification(f)
                    pid=bounded_integer(f.get('policyid'),0,2**31-1,-1); uuid=f.get('poluuid','')[:40]
                    profile=(f.get('profile') or f.get('applist') or f.get('sensor') or '')[:160]
                    row=(file_id,pos,len(line),line_no,hashlib.sha256(raw.encode()).digest(),event,received,f.get('type','unknown')[:24],f.get('subtype','unknown')[:40],f.get('action','')[:48],outcome,rating,pid,uuid,profile,f.get('srcip','')[:45],f.get('srcname','')[:128],f.get('dstip','')[:45],bounded_integer(f.get('dstport'),0,65535),(f.get('hostname') or f.get('sni') or f.get('qname') or f.get('servername') or '')[:512],f.get('app','')[:160],f.get('catdesc','')[:160],reason,f.get('devid','')[:40],f.get('vd','')[:64],bounded_integer(f.get('sessionid'),0,2**64-1),json.dumps(f,ensure_ascii=False,separators=(',',':')))
                    rows.append(row)
                    hour=event.replace(minute=0,second=0,microsecond=0)
                    buckets[(hour,row[7],row[8],outcome,rating,pid,profile,reason)]+=1
                    if f.get('policyname'): policies[(pid,uuid)]=(f['policyname'][:160],event)
                    if f.get('srcip') and f.get('srcname'): devices[f['srcip'][:45]]=(f['srcname'][:128],event)
                except (ValueError,KeyError,TypeError,UnicodeError,OverflowError,OSError) as e:
                    invalid.append({'file':path.name,'offset':pos,'line':line_no,'error':str(e)[:200]})
            end=stream.tell()
            if end==offset: break
            with db.cursor() as c:
                if rows: c.executemany(SQL,rows)
                antivirus={r[1]:r for r in rows if r[8]=='virus'}
                if antivirus:
                    positions=list(antivirus)
                    c.execute('SELECT id,byte_offset FROM events WHERE file_id=%s AND byte_offset IN ('+','.join(['%s']*len(positions))+')',[file_id,*positions])
                    memberships=[]
                    for event_id,position in c.fetchall():
                        r=antivirus[position];key,complete=antivirus_group_key(r[15],json.loads(r[26]),event_id)
                        memberships.append((event_id,key,complete))
                    c.executemany('INSERT INTO av_event_groups(event_id,group_key,key_complete) VALUES(%s,%s,%s)',memberships)
                security={r[1]:r for r in rows if r[8] in SECURITY_GROUP_MODULES and r[10]=='security_block'}
                if security:
                    positions=list(security)
                    c.execute('SELECT id,byte_offset FROM events WHERE file_id=%s AND byte_offset IN ('+','.join(['%s']*len(positions))+')',[file_id,*positions])
                    memberships=[(eid,*security_group_key(json.loads(security[pos][26]),eid)) for eid,pos in c.fetchall()]
                    c.executemany('INSERT INTO security_event_groups(event_id,group_key,key_complete,identity_json) VALUES(%s,%s,%s,%s)',memberships)
                traffic={r[1]:r for r in rows if r[10] in ('policy_deny','local_deny')}
                if traffic:
                    positions=list(traffic)
                    c.execute('SELECT id,byte_offset FROM events WHERE file_id=%s AND byte_offset IN ('+','.join(['%s']*len(positions))+')',[file_id,*positions])
                    insert_traffic_memberships(c,[(eid,traffic[pos][5],traffic[pos][14],traffic[pos][26]) for eid,pos in c.fetchall()])
                if buckets:
                    vals=[]
                    for key,n in buckets.items():
                        digest=hashlib.sha256(json.dumps(key,default=str,ensure_ascii=False).encode()).digest()
                        vals.append((digest,*key,n))
                    c.executemany('INSERT INTO hourly_counts VALUES('+','.join(['%s']*10)+') ON DUPLICATE KEY UPDATE records=records+VALUES(records)',vals)
                if policies:
                    c.executemany('INSERT INTO policies VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE name=IF(VALUES(observed_at)>=observed_at,VALUES(name),name),observed_at=GREATEST(observed_at,VALUES(observed_at))',[(pid,uuid,name,t) for (pid,uuid),(name,t) in policies.items()])
                if devices:
                    c.executemany('INSERT INTO devices VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE name=IF(VALUES(observed_at)>=observed_at,VALUES(name),name),observed_at=GREATEST(observed_at,VALUES(observed_at))',[(ip,name,t) for ip,(name,t) in devices.items()])
                c.execute('UPDATE source_files SET byte_offset=%s,line_number=%s,observed_size=%s,invalid_rows=invalid_rows+%s,updated_at=UTC_TIMESTAMP(6) WHERE id=%s',(end,line_no,path.stat().st_size,len(invalid),file_id))
            db.commit()
            for item in invalid: logging.error('PARSER_REJECT %s',json.dumps(item))
            count+=len(rows);offset=end
            if len(rows)+len(invalid)<batch_size: break
    if count: logging.info('%s: +%d events, checkpoint %d',path.name,count,offset)
    return count

def ingest_pass(db,root=ROOT):
    # Stat every historical file on each pass so replacement, truncation and
    # late appends remain visible, but do not rewrite unchanged checkpoints.
    paths=sorted((path for path in root.glob('*.jsonl') if re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',path.name)),reverse=True)
    with db.cursor() as c:
        c.execute('SELECT name,inode,byte_offset,observed_size FROM source_files')
        checkpoints={name:(inode,offset,size) for name,inode,offset,size in c.fetchall()}
        pending=[]
        for path in paths:
            st=path.stat();old=checkpoints.get(path.name)
            if old is not None and (old[0]!=st.st_ino or st.st_size<old[1]):
                raise RuntimeError('Source identity/size changed; refusing to skip or overwrite: '+path.name)
            if old is None or old[2]!=st.st_size:
                c.execute('INSERT INTO source_files(name,inode,observed_size) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE observed_size=VALUES(observed_size)',(path.name,st.st_ino,st.st_size))
            if old is None or old[1]!=st.st_size:pending.append(path)
    db.commit()
    total=0
    # Discover an hour rollover between pending historical files during a
    # backfill, without rescanning for every closed, idle hour.
    for path in pending:
        total+=ingest(db,path)
        latest=max((candidate for candidate in root.glob('*.jsonl') if re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',candidate.name)),default=None)
        if latest is not None and latest!=path:total+=ingest(db,latest)
    return total

def main():
    p=argparse.ArgumentParser();p.add_argument('--once',action='store_true');args=p.parse_args()
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    db=connect()
    while True:
        total=ingest_pass(db)
        logging.info('Pass complete: %d new events',total)
        if args.once: break
        time.sleep(3)
        db.ping(reconnect=True)

if __name__=='__main__': main()
