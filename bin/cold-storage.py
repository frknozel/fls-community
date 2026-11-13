#!/usr/bin/python3
"""Copy-only detailed cohorts. Original SQL, raw logs and remote targets are never modified."""
import argparse,base64,contextlib,datetime as dt,fcntl,hashlib,json,os,re,signal,stat,sys,tempfile,time,uuid
from pathlib import Path
from zoneinfo import ZoneInfo
import pymysql
from cryptography.hazmat.primitives import serialization
import cold_format

UTC=dt.timezone.utc
ROOT=Path('/srv/fls-server/archive/detailed')
RAW=Path('/srv/fls-server/raw')
SOURCE_TABLES=('source_files','events','event_notes','av_event_groups','security_event_groups','traffic_event_groups','traffic_groups','mail_search_events','archive_event_index','archive_dimensions')
MAX_SOURCE_BYTES=256*1024*1024
MAX_COMPRESSED_BYTES=256*1024*1024
class ColdError(ValueError):pass

def utc(value):
    if isinstance(value,dt.datetime):return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if not isinstance(value,str) or len(value)>40:raise ColdError('acquisition_time')
    try:result=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError:raise ColdError('acquisition_time') from None
    if result.tzinfo is None:raise ColdError('acquisition_time')
    return result.astimezone(UTC)
def sqltime(value):return utc(value).replace(tzinfo=None)
def iso(value):return utc(value).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
def credential(path,limit=16384):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        s=os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid not in (0,os.geteuid()) or s.st_mode&0o037 or s.st_nlink!=1 or s.st_size>limit:raise ColdError('credential_permissions')
        return stream.read(limit+1)
def connect(config):
    if config.get('user')!='fls_cold' or not isinstance(config.get('password'),str):raise ColdError('credential_user')
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',charset='utf8mb4',autocommit=True,connect_timeout=3,read_timeout=15,write_timeout=10,cursorclass=pymysql.cursors.DictCursor)
    with db.cursor() as c:c.execute("SET time_zone='+00:00',max_statement_time=12,innodb_lock_wait_timeout=2")
    return db

class Worker:
    def __init__(self,source,catalog,root,raw,instance,private_key,raw_public_key,now=None):
        self.source=source;self.catalog=catalog;self.root=Path(root);self.raw=Path(raw);self.instance=instance;self.key=private_key
        self.now=utc(now or dt.datetime.now(UTC));self.deadline=time.monotonic()+105
        self.public=serialization.load_pem_private_key(private_key,password=None).public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.raw_public=serialization.load_pem_public_key(raw_public_key)
    def budget(self):
        if time.monotonic()>self.deadline:raise ColdError('time_budget')
    def sql(self,query,args=(),source=False,allow_expired=False):
        if not allow_expired:self.budget()
        with (self.source if source else self.catalog).cursor() as c:c.execute(query,args);return c.fetchall()
    def settings(self):
        value=self.sql('SELECT fast_days FROM retention_settings WHERE id=1')[0]['fast_days']
        # Old copy-only snapshots and policy revisions keep their original window.
        if type(value) is not int or not (value in (45,70,90) or 90<=value<=180):raise ColdError('retention_policy')
        return value
    def summary(self,days):
        cutoff=sqltime(self.now-dt.timedelta(days=days))
        condition="m.status='verified' AND m.signed_at<=%s AND s.byte_offset=s.observed_size AND s.observed_size=m.bytes AND s.invalid_rows<=s.line_number AND s.observed_size<=%s AND s.updated_at IS NOT NULL"
        row=self.sql("SELECT COUNT(*) raw_files_seen,COALESCE(SUM(m.id IS NULL OR m.status<>'verified' OR s.byte_offset<>s.observed_size OR s.observed_size<>m.bytes OR s.invalid_rows>s.line_number OR s.updated_at IS NULL OR s.observed_size>%s),0) unknown_files,COALESCE(SUM(CASE WHEN "+condition+" AND p.id IS NULL THEN 1 ELSE 0 END),0) eligible_files,COALESCE(SUM(CASE WHEN "+condition+" AND p.id IS NULL THEN s.line_number-s.invalid_rows ELSE 0 END),0) eligible_records,COALESCE(SUM(CASE WHEN "+condition+" AND p.id IS NULL THEN s.observed_size ELSE 0 END),0) eligible_bytes,COALESCE(SUM(p.id IS NOT NULL),0) completed_files FROM source_files s LEFT JOIN archive_manifests m ON m.source_file=s.name LEFT JOIN cold_snapshots p ON p.file_id=s.id AND p.purpose='archive' AND p.status='verified'",(MAX_SOURCE_BYTES,)+(cutoff,MAX_SOURCE_BYTES)*3)
        return {key:int(value) for key,value in row[0].items()}
    def heartbeat(self,status,days,summary=None,error='',snapshot=None):
        v=summary or {};good=status=='ok';cols=('eligible_files','eligible_records','eligible_bytes','raw_files_seen','unknown_files','completed_files')
        self.sql('INSERT INTO cold_storage_worker(id,checked_at,last_success_at,status,error_code,fast_days,'+','.join(cols)+',last_snapshot_id,read_below_fast_window,copy_only) VALUES(1,UTC_TIMESTAMP(6),IF(%s,UTC_TIMESTAMP(6),NULL),%s,%s,%s,'+','.join(['%s']*6)+',%s,1,1) ON DUPLICATE KEY UPDATE checked_at=VALUES(checked_at),last_success_at=IF(%s,VALUES(last_success_at),last_success_at),status=VALUES(status),error_code=VALUES(error_code),fast_days=VALUES(fast_days),'+','.join(k+'=VALUES('+k+')' for k in cols)+',last_snapshot_id=COALESCE(VALUES(last_snapshot_id),last_snapshot_id),read_below_fast_window=1,copy_only=1',(good,status,error,days,*[v.get(k) for k in cols],snapshot,good),allow_expired=status=='error')
    def candidate(self,days,canary=None):
        args=[sqltime(self.now-dt.timedelta(minutes=15) if canary else self.now-dt.timedelta(days=days))]
        where="m.status='verified' AND m.signed_at<=%s AND (c.id IS NULL OR c.status<>'verified' AND (c.next_attempt_at IS NULL OR c.next_attempt_at<=UTC_TIMESTAMP(6)))"
        if canary:where+=' AND s.id=%s';args.append(canary)
        purpose='canary' if canary else 'archive'
        rows=self.sql("SELECT s.*,m.id raw_manifest_id,m.manifest_hash raw_manifest_sha256,m.sha256 raw_sha256,m.bytes manifest_bytes,m.rows_count manifest_rows,m.signed_at manifest_signed_at,m.status manifest_status,m.manifest_json,m.signature FROM source_files s JOIN archive_manifests m ON m.source_file=s.name LEFT JOIN cold_snapshots c ON c.file_id=s.id AND c.purpose='"+purpose+"' WHERE "+where+' ORDER BY m.signed_at,s.id LIMIT 1',args)
        if canary and not rows:
            existing=self.sql("SELECT id,status FROM cold_snapshots WHERE file_id=%s AND purpose='canary'",(canary,))
            if existing and existing[0]['status']=='verified':return None
            raise ColdError('canary_not_eligible')
        return rows[0] if rows else None
    def raw_check(self,row):
        name=row['name']
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',name):raise ColdError('source_name')
        if not 0<row['observed_size']<=MAX_SOURCE_BYTES:raise ColdError('source_oversized_or_empty')
        if row['invalid_rows']>row['line_number'] or row['byte_offset']!=row['observed_size'] or row['observed_size']!=row['manifest_bytes'] or row['line_number']!=row['manifest_rows']:raise ColdError('source_checkpoint')
        try:
            manifest=json.loads(row['manifest_json']);encoded=json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
            self.raw_public.verify(base64.b64decode(row['signature'],validate=True),encoded)
            if hashlib.sha256(encoded).hexdigest()!=row['raw_manifest_sha256'] or manifest['source_file']!=name or manifest['sha256']!=row['raw_sha256'] or manifest['bytes']!=row['manifest_bytes'] or manifest['rows']!=row['manifest_rows']:raise ColdError('source_manifest')
            if utc(manifest['signed_at']).replace(microsecond=0)!=utc(row['manifest_signed_at']).replace(microsecond=0):raise ColdError('source_manifest_time')
        except Exception:raise ColdError('source_manifest') from None
        fd=os.open(self.raw/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_ino!=row['inode'] or before.st_size!=row['observed_size']:raise ColdError('source_identity')
            digest=hashlib.sha256();lines=0;minimum=maximum=None
            while True:
                self.budget();line=stream.readline(4*1024*1024+1)
                if not line:break
                if len(line)>4*1024*1024 or not line.endswith(b'\n'):raise ColdError('source_line')
                digest.update(line);lines+=1
                try:
                    env=json.loads(line);received=utc(env['received_at'])
                    if not isinstance(env.get('raw'),str) or received>self.now:raise ColdError('acquisition_time')
                except (ValueError,KeyError,TypeError,UnicodeError):raise ColdError('source_envelope') from None
                minimum=min(minimum,received) if minimum else received;maximum=max(maximum,received) if maximum else received
            after=os.fstat(stream.fileno())
            if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns) or lines!=row['line_number'] or digest.hexdigest()!=row['raw_sha256']:raise ColdError('source_hash_or_changed')
        return before,minimum,maximum
    def schema(self):
        marks=','.join(['%s']*len(SOURCE_TABLES))
        rows=self.sql('SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,EXTRA,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY TABLE_NAME,ORDINAL_POSITION',SOURCE_TABLES,source=True)
        result={name:[] for name in SOURCE_TABLES}
        for r in rows:result[r['TABLE_NAME']].append({'name':r['COLUMN_NAME'],'type':r['COLUMN_TYPE'],'nullable':r['IS_NULLABLE']=='YES','extra':r['EXTRA'],'collation':r['COLLATION_NAME']})
        if any(not value for value in result.values()):raise ColdError('schema_unavailable')
        return result
    def records(self,table,file_id):
        if table not in SOURCE_TABLES:raise ColdError('table')
        if table=='source_files':query='SELECT t.* FROM source_files t WHERE t.id=%s ORDER BY t.id'
        elif table=='events':query='SELECT t.* FROM events t FORCE INDEX(source_position) WHERE t.file_id=%s ORDER BY t.byte_offset'
        elif table=='traffic_groups':query='SELECT t.* FROM traffic_groups t WHERE t.group_key IN (SELECT m.group_key FROM events e FORCE INDEX(source_position) JOIN traffic_event_groups m ON m.event_id=e.id WHERE e.file_id=%s) ORDER BY t.group_key'
        elif table=='archive_dimensions':query='SELECT t.* FROM archive_dimensions t WHERE t.id IN (SELECT m.dimension_id FROM events e FORCE INDEX(source_position) JOIN archive_event_index m ON m.event_id=e.id WHERE e.file_id=%s) ORDER BY t.id'
        else:query='SELECT t.* FROM events e FORCE INDEX(source_position) STRAIGHT_JOIN '+table+' t ON t.event_id=e.id WHERE e.file_id=%s ORDER BY '+('t.id' if table=='event_notes' else 't.event_id')
        with self.source.cursor(pymysql.cursors.SSDictCursor) as cursor:
            cursor.execute(query,(file_id,))
            raw=None;line_no=0
            try:
                if table=='events':
                    raw=os.fdopen(os.open(self.raw/self.current['name'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb')
                    info=os.fstat(raw.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_ino!=self.current['inode'] or info.st_size!=self.current['observed_size']:raise ColdError('source_identity')
                while True:
                    batch=cursor.fetchmany(128)
                    if not batch:break
                    for row in batch:
                        self.budget()
                        if raw:
                            while raw.tell()<row['byte_offset']:
                                skipped=raw.readline(4*1024*1024+1);line_no+=1
                                if not skipped or not skipped.endswith(b'\n'):raise ColdError('event_offset')
                            if raw.tell()!=row['byte_offset']:raise ColdError('event_offset')
                            if not 1<=row['byte_length']<=4*1024*1024:raise ColdError('event_position')
                            line=raw.readline(4*1024*1024+1);line_no+=1
                            if len(line)!=row['byte_length'] or not line.endswith(b'\n') or row['line_number']!=line_no:raise ColdError('event_position')
                            env=json.loads(line)
                            if hashlib.sha256(env['raw'].encode('utf-8')).digest()!=row['raw_sha256'] or sqltime(env['received_at'])!=row['received_at']:raise ColdError('event_raw_mismatch')
                        yield row
            finally:
                if raw:raw.close()
    def snapshot(self,row,purpose,days):
        self.current=row
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',row['name']):raise ColdError('source_name')
        try:hour=dt.datetime.strptime(row['name'][:-6],'%Y-%m-%d-%H')
        except ValueError:raise ColdError('source_name') from None
        relative=hour.replace(tzinfo=UTC).astimezone(ZoneInfo('Europe/Istanbul')).strftime('%m-%Y/%d-%m-%Y/')+row['name'][:-6]+'-'+purpose
        destination=self.root/relative;destination.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
        self.sql("INSERT INTO cold_snapshots(file_id,source_file,raw_manifest_id,raw_manifest_sha256,purpose,relative_path,status,error_code,last_attempt_at) VALUES(%s,%s,%s,%s,%s,%s,'preparing','',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE status=IF(status='verified',status,'preparing'),error_code=IF(status='verified',error_code,''),last_attempt_at=UTC_TIMESTAMP(6)",(row['id'],row['name'],row['raw_manifest_id'],row['raw_manifest_sha256'],purpose,relative))
        catalog=self.sql('SELECT id,status FROM cold_snapshots WHERE file_id=%s AND purpose=%s',(row['id'],purpose))[0]
        if catalog['status']=='verified':return catalog['id']
        try:
            before,minimum,maximum=self.raw_check(row)
            age=dt.timedelta(minutes=15) if purpose=='canary' else dt.timedelta(days=days)
            if maximum>self.now-age or utc(row['manifest_signed_at'])>self.now-age:raise ColdError('source_too_recent')
            self.source.begin()
            with self.source.cursor() as c:c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
            check=self.sql('SELECT * FROM source_files WHERE id=%s',(row['id'],),source=True)[0]
            if any(check[k]!=row[k] for k in ('inode','byte_offset','observed_size','line_number','invalid_rows')):raise ColdError('source_checkpoint_changed')
            high=self.sql('SELECT MAX(id) high FROM events FORCE INDEX(source_position) WHERE file_id=%s',(row['id'],),source=True)[0]['high'] or 0
            for table,version in [('archive_index_state',3),('mail_search_state',1)]:
                state=self.sql('SELECT version,event_id,ready FROM '+table+' WHERE id=1',source=True)
                if not state or state[0]['version']!=version or not state[0]['ready'] or state[0]['event_id']<high:raise ColdError('derived_index_pending')
            at=self.sql('SELECT UTC_TIMESTAMP(6) at',source=True)[0]['at']
            metadata={'installation_uuid':self.instance,'source_file':row['name'],'source_id':row['id'],'raw_manifest_sha256':row['raw_manifest_sha256'],'raw_sha256':row['raw_sha256'],'schema_metadata':self.schema(),'snapshot_at':at,'source_received_min':iso(minimum),'source_received_max':iso(maximum),'purpose':purpose}
            with tempfile.TemporaryDirectory(prefix='.building-',dir=destination.parent) as temporary:
                working=Path(temporary)/'bundle'
                if destination.exists():
                    report=cold_format.verify_bundle(destination,self.public);working=destination
                else:
                    cold_format.build_bundle(working,{table:self.records(table,row['id']) for table in SOURCE_TABLES},metadata,self.key)
                    report=cold_format.verify_bundle(working,self.public)
                m=report['manifest']
                if m['source_id']!=row['id'] or m['raw_manifest_sha256']!=row['raw_manifest_sha256'] or m['purpose']!=purpose or m['table_counts'].get('events')!=row['line_number']-row['invalid_rows']:raise ColdError('snapshot_source_mismatch')
                if report['compressed_bytes']>MAX_COMPRESSED_BYTES:raise ColdError('snapshot_oversized')
                self.budget()
                with tempfile.TemporaryDirectory(prefix='fls-cold-restore-') as restore:
                    restored=cold_format.restore_bundle(working,Path(restore)/'restored',self.public)
                    # Independent restored-record pass; codec verifier validates signed row hashes.
                    for table in SOURCE_TABLES:
                        count=0;digest=hashlib.sha256()
                        for record in cold_format.iter_records(restored,table):
                            self.budget();digest.update(cold_format.canonical(cold_format.typed_row(record))+b'\n');count+=1
                        if count!=m['table_counts'][table] or digest.hexdigest()!=m['table_row_sha256'][table]:raise ColdError('restore_row_hash')
                after=(self.raw/row['name']).stat()
                if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):raise ColdError('source_changed')
                self.source.rollback()
                if working!=destination:
                    os.rename(working,destination);fd=os.open(destination.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
            publicmeta={key:m[key] for key in ('installation_id','source_file','source_id','raw_manifest_sha256','raw_sha256','snapshot_at','source_received_min','source_received_max','purpose')}
            publicmeta['scope_excluded']=['shared_hourly_aggregates','configuration_history','inventory','users_and_credentials'];publicmeta['copy_only']=True
            self.sql("UPDATE cold_snapshots SET payload_sha256=%s,manifest_sha256=%s,compressed_bytes=%s,expanded_bytes=%s,event_count=%s,note_count=%s,snapshot_at=%s,verified_at=UTC_TIMESTAMP(6),restore_verified_at=UTC_TIMESTAMP(6),status='verified',error_code='',tables_json=%s,metadata_json=%s,next_attempt_at=NULL WHERE id=%s",(report['payload_sha256'],report['manifest_sha256'],report['compressed_bytes'],report['expanded_bytes'],report['event_count'],report['note_count'],sqltime(m['snapshot_at']),json.dumps(m['table_counts']),json.dumps(publicmeta),catalog['id']))
            return catalog['id']
        except Exception as e:
            self.source.rollback();code=str(e) if isinstance(e,ColdError) else 'snapshot_verification_failed'
            self.sql("UPDATE cold_snapshots SET status='failed',error_code=%s,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 HOUR) WHERE id=%s AND status<>'verified'",(code,catalog['id']),allow_expired=True);raise
    def run(self,canary=None):
        days=self.settings();self.heartbeat('running',days)
        try:
            summary=self.summary(days);row=self.candidate(days,canary);sid=self.snapshot(row,'canary' if canary else 'archive',days) if row else None
            summary=self.summary(days);self.heartbeat('ok',days,summary,snapshot=sid)
            return {'status':'ok','copy_only':True,'snapshot_id':sid,'fast_days':days,**summary}
        except Exception as e:
            code=str(e) if isinstance(e,ColdError) else 'worker_unavailable'
            self.heartbeat('error',days,None,error=code);raise

def main():
    p=argparse.ArgumentParser();p.add_argument('--canary-source-id',type=int);a=p.parse_args()
    if a.canary_source_id is not None and not 1<=a.canary_source_id<=2147483647:raise ColdError('source_id')
    directory=os.environ.get('CREDENTIALS_DIRECTORY')
    if not directory:raise ColdError('credential_directory')
    config=json.loads(credential(Path(directory)/'database'));key=credential(Path(directory)/'signing-key');instance=json.loads(credential(Path(directory)/'instance'))
    identifier=instance.get('installation_id');parsed=uuid.UUID(identifier)
    if parsed.version!=4 or str(parsed)!=identifier:raise ColdError('installation_id')
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o750)
    with (ROOT/'.worker.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        source=connect(config);catalog=connect(config)
        try:
            def timeout(*_):raise ColdError('time_budget')
            signal.signal(signal.SIGALRM,timeout);signal.alarm(108)
            result=Worker(source,catalog,ROOT,RAW,identifier,key,credential(Path(directory)/'raw-public-key')).run(a.canary_source_id)
            print(json.dumps(result))
        finally:signal.alarm(0);source.close();catalog.close()
if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'status':'error','code':str(e) if isinstance(e,ColdError) else 'worker_unavailable','copy_only':True}),file=sys.stderr);raise SystemExit(1)
