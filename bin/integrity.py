#!/usr/bin/python3
"""Local Ed25519 integrity manifests. No qualified TSA / 5651 claim."""
import base64, datetime as dt, hashlib, json, logging, math, os, subprocess
from pathlib import Path
import pymysql
from cryptography.hazmat.primitives import serialization
from integrity_scrub import FileChanged, IntegrityError, Store, full_hash, verify_fast, integrity_lock

def verified_manifest(disk,key,name,previous,expected_hash=None):
    m=disk['manifest'];canonical=json.dumps(m,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    key.public_key().verify(base64.b64decode(disk['signature'],validate=True),canonical)
    digest=hashlib.sha256(canonical).hexdigest()
    if m['source_file']!=name or m['previous_manifest_sha256']!=previous or expected_hash is not None and digest!=expected_hash:
        raise ValueError('Manifest identity or chain mismatch')
    return m,canonical,digest

def verify_source(m,digest,size,rows):
    if (digest,size,rows)!=(m['sha256'],m['bytes'],m['rows']):raise ValueError('Raw log digest, size or record count mismatch')

def collector_gate_snapshot(health,now):
    """Return bounded diagnostics without copying arbitrary health content."""
    result={'current':False,'reason':'health_invalid','health_age_seconds':None,'collector_active':False,'archive_receive_lag_seconds':None,'queue_checkpoint_pending':None}
    try:
        checked=dt.datetime.fromisoformat(health['checked_at'])
        if checked.tzinfo is None:
            result['reason']='health_time_invalid';return result
        result['health_age_seconds']=(now-checked).total_seconds()
        result['collector_active']=health.get('collector',{}).get('data')=='active'
        ingestion=health['log_ingestion']
        for field in ('archive_receive_lag_seconds','queue_checkpoint_pending'):
            value=ingestion[field]
            if type(value) not in (int,float) or not math.isfinite(value):
                result['reason']=field+'_invalid';return result
            result[field]=value
        if not result['collector_active']:result['reason']='collector_inactive'
        elif not -30<=result['health_age_seconds']<=300:result['reason']='health_stale_or_future'
        elif not 0<=result['archive_receive_lag_seconds']<=60:result['reason']='archive_receive_lag_out_of_range'
        elif not 0<=result['queue_checkpoint_pending']<=64:result['reason']='queue_checkpoint_out_of_range'
        else:result.update(current=True,reason='current')
    except (KeyError,TypeError,ValueError,OverflowError,AttributeError):pass
    return result

def collector_current(health,now):
    """Unknown or stale queue measurements must never authorize a new seal."""
    return collector_gate_snapshot(health,now)['current']

def seal(db):
    key=serialization.load_pem_private_key(Path('/etc/fls/private/archive-ed25519.pem').read_bytes(),password=None)
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    keyid=hashlib.sha256(public).hexdigest()
    folder=Path('/srv/fortigate/archive/manifests');folder.mkdir(exist_ok=True)
    # Fast path: verify signed metadata, SQL bindings and source size, never
    # reread historical payloads or refresh their last full-SHA timestamp.
    with db.cursor(pymysql.cursors.DictCursor) as c:
        c.execute('SELECT * FROM archive_manifests ORDER BY source_file');existing=c.fetchall()
    previous='0'*64; known=set()
    for item in existing:
        name=item['source_file'];known.add(name)
        manifest_path=folder/(name+'.manifest.json')
        try:
            verify_fast(item,folder,Path('/srv/fortigate/raw'),key.public_key(),previous)
        except Exception as exc:
            logging.exception('Integrity metadata verification failed: %s',name)
            # Preserve the first proven corruption reason; subsequent signer
            # runs halt without replacing it with a generic previous_failure.
            if not isinstance(exc,IntegrityError) or exc.code!='previous_failure':
                Store(db).update(item,'FAILED',error=exc.code if isinstance(exc,IntegrityError) else 'manifest_invalid')
            raise RuntimeError('Integrity failure; signing halted') from exc
        previous=item['manifest_hash']
    last=existing[-1]['source_file'] if existing else ''
    health=json.loads(Path('/srv/fortigate/metrics/host-health.json').read_text())
    # Full-history hashing can outlast several health samples. Evaluate their
    # age and closed-hour eligibility at this gate, not at process start.
    now=dt.datetime.now(dt.timezone.utc)
    gate=collector_gate_snapshot(health,now)
    if not gate['current']:
        logging.warning('Existing manifests verified. New signing deferred until collector is current. gate=%s',json.dumps(gate,sort_keys=True,allow_nan=False,separators=(',',':')))
        return
    new_seals=0
    for path in sorted(Path('/srv/fortigate/raw').glob('*.jsonl')):
        if new_seals>=4:break
        if path.name in known: continue
        hour=dt.datetime.strptime(path.stem,'%Y-%m-%d-%H').replace(tzinfo=dt.timezone.utc)
        if hour+dt.timedelta(hours=1,minutes=15)>now: continue
        if path.name<last: raise RuntimeError('Late older archive file requires explicit chain review: '+path.name)
        try:digest,size,rows=hash_file(path)
        except FileChanged:
            logging.warning('Active file skipped: %s',path.name);break
        signed=dt.datetime.now(dt.timezone.utc)
        m={'schema':'fls-integrity-v1','source_file':path.name,'bytes':size,'rows':rows,'sha256':digest,'previous_manifest_sha256':previous,'signed_at':signed.isoformat(),'signature_algorithm':'Ed25519','key_id':keyid,'timestamp_authority':None,'legal_timestamp':False}
        canonical=json.dumps(m,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        manifest_hash=hashlib.sha256(canonical).hexdigest();signature=base64.b64encode(key.sign(canonical)).decode()
        disk={'manifest':m,'signature':signature}
        dest=folder/(path.name+'.manifest.json')
        if dest.exists():
            # A crash may have persisted the manifest before the DB transaction; adopt only identical content.
            old=json.loads(dest.read_text());oldm,oldcanon,_=verified_manifest(old,key,path.name,previous)
            verify_source(oldm,digest,size,rows)
            m=oldm;canonical=oldcanon;signature=old['signature'];manifest_hash=hashlib.sha256(canonical).hexdigest();signed=dt.datetime.fromisoformat(m['signed_at'])
        else:
            temp=dest.with_suffix('.tmp');temp.write_text(json.dumps(disk,ensure_ascii=False,indent=2)+'\n');os.chmod(temp,0o640)
            with temp.open('rb') as f: os.fsync(f.fileno())
            os.replace(temp,dest)
            fd=os.open(folder,os.O_RDONLY);os.fsync(fd);os.close(fd)
        with db.cursor() as c:
            c.execute('INSERT INTO archive_manifests(source_file,bytes,rows_count,sha256,previous_hash,manifest_hash,signed_at,verified_at,status,manifest_json,signature) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),%s,%s,%s)',(path.name,size,rows,digest,previous,manifest_hash,signed.replace(tzinfo=None),'verified',json.dumps(m,ensure_ascii=False),signature))
            manifest_id=c.lastrowid
            c.execute("INSERT INTO archive_integrity_checks(manifest_id,last_full_verified_at,status,error_code,progress_bytes,verification_started_at,updated_at) VALUES(%s,UTC_TIMESTAMP(6),'verified','',%s,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",(manifest_id,size))
        db.commit();new_seals+=1;previous=manifest_hash;logging.info('Signed and verified: %s (%d rows)',path.name,rows)

def main():
    logging.basicConfig(level=logging.INFO)
    config=json.loads(Path('/etc/fls/integrity.json').read_text())
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',charset='utf8mb4',autocommit=False,connect_timeout=5,read_timeout=70,write_timeout=10)
    try:
        with integrity_lock(db,60) as acquired:
            if not acquired:
                logging.warning('Archive verification lock busy; signing deferred.');return
            seal(db)
    finally:db.close()

def hash_file(path):
    return full_hash(path)

if __name__=='__main__': main()
