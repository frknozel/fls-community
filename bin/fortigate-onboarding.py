#!/usr/bin/python3
"""Bounded receipt verification and sender admission. Never writes log data or calls FortiGate."""
import datetime as dt,fcntl,hashlib,ipaddress,json,os,re,stat,subprocess,tempfile
from pathlib import Path
import pymysql

RSYSLOG='/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd'
ALLOW=Path('/etc/fortigate/fls-senders.json')
PUBLIC=Path('/srv/fortigate/metrics/fortigate-onboarding.json')
RAW=Path('/srv/fortigate/raw')

def ipv4(value):
    ip=ipaddress.ip_address(value)
    if ip.version!=4 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or int(ip)>=0xe0000000 or int(ip)<0x01000000:raise ValueError('ipv4')
    return str(ip)

def atomic(path,value,mode=0o640,gid=None):
    fd,name=tempfile.mkstemp(prefix='.fls-onboarding-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(value,f,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
            if gid is not None:os.fchown(f.fileno(),0,gid)
        os.replace(name,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(name):os.unlink(name)

def private(name):
    directory=Path(os.environ.get('CREDENTIALS_DIRECTORY','/etc/fls'));path=directory/name
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077 or s.st_size>16384:raise ValueError('private_config')
        return json.loads(f.read(16385))

def allowed_ips(pinned,setups):
    return sorted({ipv4(i) for i in pinned}|{ipv4(s['peer_ip']) for s in setups if s['receiver_admitted']})

def lookup_document(ips):
    return {'version':1,'nomatch':'deny','type':'string','table':[{'index':i,'value':'allow'} for i in ips]}

def apply_sources(ips,path=ALLOW,runner=subprocess.run):
    """The web account cannot supply paths, commands, units or networks. Exact IPs only."""
    import grp
    doc=lookup_document(ips);old=json.loads(path.read_text())
    if old==doc:return False
    atomic(path,doc,gid=grp.getgrnam('adm').gr_gid)
    try:
        runner(['systemctl','kill','--kill-whom=main','--signal=HUP','fortigate-collector.service'],check=True,capture_output=True,timeout=5)
    except Exception:
        atomic(path,old,gid=grp.getgrnam('adm').gr_gid)
        # Reassert the last accepted table if the signal's delivery was ambiguous.
        runner(['systemctl','kill','--kill-whom=main','--signal=HUP','fortigate-collector.service'],check=False,capture_output=True,timeout=5)
        raise
    return True

def receipt(row,expected,root=RAW):
    """Read one indexed envelope, using the importer's file offset and original-message hash."""
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',row['name']):return '', 'raw_unavailable'
    size=int(row['byte_length']);offset=int(row['byte_offset'])
    if not 0<size<=4*1024*1024 or offset<0:return '', 'raw_unavailable'
    try:
        fd=os.open(root/row['name'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):return '', 'raw_unavailable'
            f.seek(offset);line=f.read(size)
        if len(line)!=size or not line.endswith(b'\n'):return '', 'raw_unavailable'
        env=json.loads(line);raw=env.get('raw')
        if not isinstance(raw,str) or hashlib.sha256(raw.encode()).digest()!=row['raw_sha256']:return '', 'raw_unavailable'
        peer=ipv4(env.get('sender_ip'));return peer,'ok' if peer==expected else 'source_mismatch'
    except (OSError,ValueError,TypeError,AttributeError):return '', 'raw_unavailable'

def scan(database,setups,root=RAW,limit=5000):
    """Primary-key batches; at most one raw read per configured identity, per batch."""
    with database.cursor() as c:
        c.execute('SELECT event_cursor FROM fortigate_setup_state WHERE id=1');state=c.fetchone()
        if state is None:
            c.execute('SELECT COALESCE(MAX(id),0) n FROM events');cursor=c.fetchone()['n']
            # New installations begin at the current tail; pending setup baselines may be older.
            if setups:cursor=min(cursor,min(s['baseline_event_id'] for s in setups))
            c.execute('INSERT INTO fortigate_setup_state VALUES(1,%s,UTC_TIMESTAMP(6))',(cursor,))
        else:cursor=state['event_cursor']
        c.execute('SELECT id,devid,vd,received_at FROM events WHERE id>%s ORDER BY id LIMIT %s',(cursor,limit));rows=c.fetchall()
        latest={}
        for row in rows:
            for setup in setups:
                if row['id']>setup['baseline_event_id'] and row['received_at']>=setup['test_started_at'] and row['devid']==setup['serial'] and row['vd']==setup['vdom']:latest[setup['connection_id']]=(row,setup)
        for row,setup in latest.values():
            c.execute('SELECT e.id,e.received_at,e.event_at,e.byte_offset,e.byte_length,e.raw_sha256,s.name FROM events e JOIN source_files s ON s.id=e.file_id WHERE e.id=%s',(row['id'],));detail=c.fetchone()
            if not detail:continue
            peer,status=receipt(detail,setup['peer_ip'],root)
            c.execute('INSERT INTO fortigate_setup_receipts(connection_id,setup_revision,event_id,received_at,event_at,peer_ip,status,observed_at) SELECT connection_id,revision,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6) FROM fortigate_setup WHERE connection_id=%s AND revision=%s ON DUPLICATE KEY UPDATE setup_revision=VALUES(setup_revision),event_id=VALUES(event_id),received_at=VALUES(received_at),event_at=VALUES(event_at),peer_ip=VALUES(peer_ip),status=VALUES(status),observed_at=VALUES(observed_at)',(detail['id'],detail['received_at'],detail['event_at'],peer,status,setup['connection_id'],setup['revision']))
        if rows:cursor=rows[-1]['id']
        c.execute('UPDATE fortigate_setup_state SET event_cursor=%s,updated_at=UTC_TIMESTAMP(6) WHERE id=1',(cursor,))
    return cursor,len(rows)

def main():
    with open('/run/fls-onboarding/worker.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        cred=private('onboarding-database');config=private('onboarding-collector')
        if cred.get('user')!='fls_onboarding':raise ValueError('database_user')
        database=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=cred['user'],password=cred['password'],database='fls',charset='utf8mb4',autocommit=True,connect_timeout=2,read_timeout=5,write_timeout=5,cursorclass=pymysql.cursors.DictCursor)
        try:
            with database.cursor() as c:
                c.execute('SET SESSION max_statement_time=3')
                c.execute('SELECT s.connection_id,s.revision,s.peer_ip,s.receiver_admitted,s.baseline_event_id,s.test_started_at,d.serial,d.vdom FROM fortigate_setup s JOIN fortigate_connections d ON d.id=s.connection_id ORDER BY s.connection_id LIMIT 17');setups=c.fetchall()
            if len(setups)>16:raise ValueError('device_limit')
            error=None;ips=[]
            try:
                ips=allowed_ips(config['pinned_ips'],setups);apply_sources(ips)
            except Exception:error='source_apply_failed';ips=[]
            cursor,scanned=scan(database,setups)
            state={'schema':1,'updated_at':dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),'listen_ip':ipv4(config['listen_ip']),'port':5514,'pinned_ips':config['pinned_ips'],'allowed_ips':ips,'error':error,'event_cursor':str(cursor),'scanned':scanned}
            atomic(PUBLIC,state,gid=__import__('grp').getgrnam('adm').gr_gid)
            print(json.dumps({'scanned':scanned,'source_status':error or 'ok'}))
        finally:database.close()

if __name__=='__main__':
    try:main()
    except Exception:print('FortiGate onboarding check failed (no record data logged)');raise SystemExit(1)
