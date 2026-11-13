"""Verified, scoped cold-snapshot queries. No hot SQL, network or immutable-file writes."""
import base64
from dataclasses import dataclass
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time
import unicodedata
from urllib.parse import quote
from zoneinfo import ZoneInfo
import cold_format as fmt

DEFAULT_BUDGET=2*1024**3
MAX_RESULT=2*1024**2
PAGE_SIZE=50
QUERY_SECONDS=5
MODULES=frozenset(('', 'virus','webfilter','app-ctrl','dns','ips','ssl','forward','local','system','vpn','user','router','ha','connector','anomaly','voip','unknown'))
OUTCOMES=frozenset(('', 'security_block','policy_deny','local_deny','other_deny','rating_error','observed','all_blocks'))
HASH=re.compile(r'[a-f0-9]{64}\Z')
RELATIVE=re.compile(r'(0[1-9]|1[0-2])-\d{4}/(0[1-9]|[12]\d|3[01])-(0[1-9]|1[0-2])-\d{4}/(\d{4}-\d{2}-\d{2}-\d{2})-(canary|archive)\Z')

class ColdQueryError(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)

@dataclass(frozen=True)
class Prepared:
    path: Path
    manifest: dict
    snapshot_id: int
    manifest_sha256: str
    identity: tuple
    bundle: Path
    manifest_identity: tuple
    payload_identity: tuple

def _identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def _parents(path):
    for item in (Path(path),*Path(path).parents):
        try:info=item.lstat()
        except OSError:raise ColdQueryError('cache_unsafe') from None
        if not stat.S_ISDIR(info.st_mode):raise ColdQueryError('cache_unsafe')
def _private(path,directory=False):
    try:info=Path(path).lstat()
    except OSError:raise ColdQueryError('cache_unsafe') from None
    kind=stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind or info.st_uid!=os.geteuid() or info.st_mode&0o077 or (not directory and info.st_nlink!=1):raise ColdQueryError('cache_unsafe')
    return info
def _digest(path,maximum,error='cache_changed'):
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    except OSError:raise ColdQueryError(error) from None
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=maximum:raise ColdQueryError(error)
        digest=hashlib.sha256();total=0;end=time.monotonic()+90
        with os.fdopen(fd,'rb',closefd=False) as stream:
            for chunk in iter(lambda:stream.read(256*1024),b''):
                if time.monotonic()>end:raise ColdQueryError('query_timeout')
                total+=len(chunk)
                if total>maximum:raise ColdQueryError(error)
                digest.update(chunk)
        if _identity(before)!=_identity(os.fstat(fd)) or _identity(before)!=_identity(Path(path).lstat()):raise ColdQueryError(error)
        return digest.hexdigest(),total,_identity(before)
    except OSError:raise ColdQueryError(error) from None
    finally:os.close(fd)
def _uint(value,minimum=1,maximum=2**64-1):
    if isinstance(value,str) and re.fullmatch(r'0|[1-9][0-9]{0,19}',value):value=int(value)
    if type(value) is not int or not minimum<=value<=maximum:raise ColdQueryError('catalog_mismatch')
    return value
def _stamp(value):
    if not isinstance(value,(str,dt.datetime)):raise ColdQueryError('invalid_filters')
    if isinstance(value,str) and not re.fullmatch(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z?',value):raise ColdQueryError('invalid_filters')
    try:
        if isinstance(value,str):value=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if value.tzinfo is not None:value=value.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return f'{value.year:04d}-{value.month:02d}-{value.day:02d} {value.hour:02d}:{value.minute:02d}:{value.second:02d}.{value.microsecond:06d}'
    except (ValueError,OverflowError):raise ColdQueryError('invalid_filters') from None
def _iso(value):return _stamp(value).replace(' ','T')+'Z'

def _cache_entries(root):
    entries=[]
    for child in root.iterdir():
        if re.fullmatch(r'\.prepare-[A-Za-z0-9_-]{1,40}',child.name):
            _private(child,True);shutil.rmtree(child);continue
        if not HASH.fullmatch(child.name):raise ColdQueryError('cache_unsafe')
        info=_private(child,True)
        if {x.name for x in child.iterdir()}!={'payload.sqlite'}:raise ColdQueryError('cache_unsafe')
        file=_private(child/'payload.sqlite');entries.append((info.st_mtime_ns,child,file.st_size))
    return entries
def _evict(root,budget,required,keep):
    entries=_cache_entries(root);used=sum(item[2] for item in entries)
    if required>budget:raise ColdQueryError('cache_budget')
    for _,path,size in sorted(entries):
        if used+required<=budget:break
        if path.name==keep:continue
        # Only this service's private, recognized cache copy is removed.
        (path/'payload.sqlite').unlink();path.rmdir();used-=size
    if used+required>budget:raise ColdQueryError('cache_budget')

def prepare(snapshot,root,trusted_public_key,cache_root,budget=DEFAULT_BUDGET):
    """Bind signature to catalog; check both payload hashes, including every warm use."""
    try:
        if not isinstance(snapshot,dict) or snapshot.get('status')!='verified' or not snapshot.get('restore_verified_at'):raise ColdQueryError('snapshot_invalid')
        sid=_uint(snapshot.get('id'));source_id=_uint(snapshot.get('file_id'),maximum=2**32-1)
        relative=snapshot.get('relative_path');mhash=snapshot.get('manifest_sha256');payloadhash=snapshot.get('payload_sha256')
        if not isinstance(relative,str) or not RELATIVE.fullmatch(relative) or not isinstance(mhash,str) or not HASH.fullmatch(mhash) or not isinstance(payloadhash,str) or not HASH.fullmatch(payloadhash):raise ColdQueryError('catalog_mismatch')
        if type(budget) is not int or not 65536<=budget<=DEFAULT_BUDGET:raise ColdQueryError('cache_budget')
        root=Path(root).absolute();_parents(root);bundle=root/relative;_parents(bundle)
        manifest_identity=_identity((bundle/'manifest.json').lstat())
        manifest=fmt._manifest(bundle,trusted_public_key);payload=manifest['payload']
        if _identity((bundle/'manifest.json').lstat())!=manifest_identity:raise ColdQueryError('payload_changed')
        expected={'source_id':source_id,'source_file':snapshot.get('source_file'),'purpose':snapshot.get('purpose'),'raw_manifest_sha256':snapshot.get('raw_manifest_sha256')}
        if any(manifest.get(k)!=v for k,v in expected.items()) or hashlib.sha256(fmt.canonical(manifest)).hexdigest()!=mhash or payload['compressed_sha256']!=payloadhash:raise ColdQueryError('catalog_mismatch')
        if any(_uint(snapshot.get(k),0)!=v for k,v in [('event_count',manifest['table_counts'].get('events',0)),('note_count',manifest['table_counts'].get('event_notes',0)),('compressed_bytes',payload['compressed_bytes']),('expanded_bytes',payload['uncompressed_bytes'])]):raise ColdQueryError('catalog_mismatch')
        if snapshot.get('snapshot_at') is not None and _stamp(snapshot['snapshot_at'])!=_stamp(manifest['snapshot_at']):raise ColdQueryError('catalog_mismatch')
        hour=dt.datetime.strptime(manifest['source_file'],'%Y-%m-%d-%H.jsonl').replace(tzinfo=dt.timezone.utc)
        expected_relative=hour.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%m-%Y/%d-%m-%Y/')+manifest['source_file'][:-6]+'-'+manifest['purpose']
        if relative!=expected_relative:raise ColdQueryError('catalog_mismatch')
        if payload['uncompressed_bytes']>budget:raise ColdQueryError('cache_budget')
        original_digest,size,original_identity=_digest(bundle/'payload.sqlite.gz',fmt.MAX_COMPRESSED,'payload_changed')
        if original_digest!=payloadhash or size!=payload['compressed_bytes']:raise ColdQueryError('payload_changed')
        cache=Path(cache_root).absolute();_parents(cache);_private(cache,True);entry=cache/mhash
        if entry.exists() or entry.is_symlink():
            _evict(cache,budget,0,mhash)
            _private(entry,True)
            if {x.name for x in entry.iterdir()}!={'payload.sqlite'}:raise ColdQueryError('cache_unsafe')
            _private(entry/'payload.sqlite');expanded,size,identity=_digest(entry/'payload.sqlite',budget)
            if expanded!=payload['uncompressed_sha256'] or size!=payload['uncompressed_bytes']:raise ColdQueryError('cache_changed')
        else:
            _evict(cache,budget,payload['uncompressed_bytes'],mhash)
            temporary=Path(tempfile.mkdtemp(prefix='.prepare-',dir=cache));os.chmod(temporary,0o700)
            try:
                restored=fmt.restore_bundle(bundle,temporary/'restore',trusted_public_key)
                os.chmod(restored,0o600);os.chmod(restored.parent,0o700)
                expanded,size,identity=_digest(restored,budget)
                if expanded!=payload['uncompressed_sha256'] or size!=payload['uncompressed_bytes']:raise ColdQueryError('cache_changed')
                os.rename(restored.parent,entry)
            finally:shutil.rmtree(temporary)
        # The immutable source and expanded cache must still be the files verified above.
        if _identity((bundle/'payload.sqlite.gz').lstat())!=original_identity or _identity((bundle/'manifest.json').lstat())!=manifest_identity:raise ColdQueryError('payload_changed')
        _private(entry/'payload.sqlite');os.utime(entry,None)
        return Prepared(entry/'payload.sqlite',manifest,sid,mhash,identity,bundle,manifest_identity,original_identity)
    except ColdQueryError:raise
    except fmt.ColdError as e:raise ColdQueryError('snapshot_invalid') from e
    except (OSError,ValueError,TypeError,KeyError) as e:raise ColdQueryError('snapshot_invalid') from e

def _scope(serial,vdom):
    if any(not isinstance(value,str) or not 1<=len(value)<=limit or any(ord(c)<32 or ord(c)==127 for c in value) for value,limit in ((serial,40),(vdom,64))):raise ColdQueryError('invalid_scope')
def _ip(value):
    try:ip=ipaddress.ip_address(value)
    except (ValueError,TypeError):raise ColdQueryError('invalid_filters') from None
    return str(ip)
def _filters(values):
    allowed={'from','to','source','target','q','module','outcome'}
    if not isinstance(values,dict) or set(values)-allowed:raise ColdQueryError('invalid_filters')
    result={name:values.get(name,'') for name in sorted(allowed)}
    if any(not isinstance(value,str) for value in result.values()):raise ColdQueryError('invalid_filters')
    for name in ('from','to'):
        if result[name]:result[name]=_stamp(result[name])
    if result['from'] and result['to'] and result['from']>=result['to']:raise ColdQueryError('invalid_filters')
    for name in ('source','target'):
        if result[name]:result[name]=_ip(result[name])
    if len(result['q'])>160 or any(ord(c)<32 or ord(c)==127 for c in result['q']):raise ColdQueryError('invalid_filters')
    if result['module'] not in MODULES or result['outcome'] not in OUTCOMES:raise ColdQueryError('invalid_filters')
    return result
def _literal(payload,term):
    def fold(value):return ''.join(c for c in unicodedata.normalize('NFKD',value).casefold() if not unicodedata.combining(c)).replace('ı','i')
    row=fmt.decode_row(fmt.strict_json(payload.encode('utf-8'),fmt.MAX_ROW));needle=fold(term)
    for value in row.values():
        if isinstance(value,str) and needle in fold(value):return 1
        if type(value) is int and needle in str(value):return 1
        if isinstance(value,bytes) and needle in value.hex():return 1
    return 0
def _open(prepared,end):
    if not isinstance(prepared,Prepared):raise ColdQueryError('snapshot_invalid')
    _source_unchanged(prepared);_parents(prepared.path.parent);_private(prepared.path.parent,True);info=_private(prepared.path)
    if _identity(info)!=prepared.identity:raise ColdQueryError('cache_changed')
    fd=os.open(prepared.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);db=None
    try:
        if _identity(os.fstat(fd))!=prepared.identity:raise ColdQueryError('cache_changed')
        # SQLite opens this already verified descriptor, not a path another actor can swap.
        db=sqlite3.connect('file:/proc/self/fd/'+str(fd)+'?mode=ro&immutable=1',uri=True)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,fmt.MAX_ROW+16384);db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,65536)
        db.enable_load_extension(False);db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA query_only=ON');db.execute('PRAGMA cache_size=-8192')
        db.create_function('cold_contains',2,_literal,deterministic=True)
        def authorize(action,arg1,arg2,_db,_trigger):
            if action==sqlite3.SQLITE_SELECT:return sqlite3.SQLITE_OK
            if action==sqlite3.SQLITE_READ and arg1 in ('records','events','sqlite_master'):return sqlite3.SQLITE_OK
            if action==sqlite3.SQLITE_FUNCTION and (arg2 or '').lower() in ('like','count','length','json_extract','cold_contains'):return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        db.set_authorizer(authorize);db.set_progress_handler(lambda:int(time.monotonic()>end),1000);fmt._check_schema(db,integrity=False)
        return db,fd
    except BaseException:
        if db:db.close()
        os.close(fd);raise
def _unchanged(prepared,fd):
    _source_unchanged(prepared)
    if _identity(os.fstat(fd))!=prepared.identity or _identity(_private(prepared.path))!=prepared.identity:raise ColdQueryError('cache_changed')
def _source_unchanged(prepared):
    try:
        _parents(prepared.bundle)
        for name,identity in (('manifest.json',prepared.manifest_identity),('payload.sqlite.gz',prepared.payload_identity)):
            info=(prepared.bundle/name).lstat()
            if not stat.S_ISREG(info.st_mode) or _identity(info)!=identity:raise ColdQueryError('payload_changed')
    except OSError:raise ColdQueryError('payload_changed') from None
def _bounded(result):
    if len(json.dumps(result,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode())>MAX_RESULT:raise ColdQueryError('result_too_large')
    return result
def _row(payload,projection=None):
    row=fmt.decode_row(fmt.strict_json(payload.encode('utf-8'),fmt.MAX_ROW))
    if projection is not None and tuple(projection)!=fmt._projection(row,projection[0]):raise ColdQueryError('snapshot_invalid')
    return row
def _json_value(value):
    if isinstance(value,dt.datetime):return _stamp(value)
    if isinstance(value,bytes):return value.hex()
    if type(value) is int and abs(value)>2**53-1:return str(value)
    return value
def _compact(row):
    columns=('id','file_id','event_at','received_at','type','subtype','action','outcome','rating_error','policyid','poluuid','profile','srcip','srcname','dstip','dstport','hostname','app','category','reason_code','devid','vd','sessionid')
    result={key:_json_value(row[key]) for key in columns if key in row}
    for key in ('id','file_id','sessionid'):
        if key in result and result[key] is not None:result[key]=str(row[key])
    return result
def _token(value,key):
    raw=fmt.canonical(value);signature=hmac.new(key,raw,hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw+signature).decode('ascii').rstrip('=')
def _cursor(token,context,key):
    if not isinstance(token,str) or not 1<=len(token)<=4096 or not re.fullmatch(r'[A-Za-z0-9_-]+',token):raise ColdQueryError('invalid_cursor')
    try:
        raw=base64.urlsafe_b64decode(token+'='*((-len(token))%4));body,signature=raw[:-32],raw[-32:]
        if len(signature)!=32 or not hmac.compare_digest(signature,hmac.new(key,body,hashlib.sha256).digest()):raise ColdQueryError('invalid_cursor')
        value=fmt.strict_json(body,4096)
        if not isinstance(value,dict) or set(value)!={'context','at','id'} or value['context']!=context or fmt.canonical(value)!=body:raise ColdQueryError('invalid_cursor')
        return _iso(value['at']),str(_uint(value['id']))
    except (ValueError,TypeError,fmt.ColdError) as e:raise ColdQueryError('invalid_cursor') from e

def query(prepared,serial,vdom,filters,cursor=None,event_id=None,kind='list',cursor_key=None):
    _scope(serial,vdom);selected=_filters(filters)
    if kind not in ('list','detail') or (kind=='detail' and cursor is not None):raise ColdQueryError('invalid_filters')
    if kind=='list' and (not isinstance(cursor_key,bytes) or len(cursor_key)!=32):raise ColdQueryError('cursor_key')
    context={'snapshot_id':str(prepared.snapshot_id),'manifest_sha256':prepared.manifest_sha256,'serial':serial,'vdom':vdom,'filters':selected}
    where=['e.devid=? COLLATE BINARY','e.vd=? COLLATE BINARY'];args=[serial,vdom]
    for name,operator in (('from','>='),('to','<')):
        if selected[name]:where.append('e.event_at'+operator+'?');args.append(_iso(selected[name]))
    for name,column in (('source','srcip'),('target','dstip')):
        if selected[name]:where.append('e.'+column+'=?');args.append(selected[name])
    if selected['q']:where.append('cold_contains(r.payload,?)=1');args.append(selected['q'])
    if selected['module']:where.append("json_extract(r.payload,'$.subtype[1]')=?");args.append(selected['module'])
    if selected['outcome']=='all_blocks':where.append("json_extract(r.payload,'$.outcome[1]') IN ('security_block','policy_deny','local_deny')")
    elif selected['outcome']:where.append("json_extract(r.payload,'$.outcome[1]')=?");args.append(selected['outcome'])
    if kind=='detail':
        try:identifier=str(_uint(event_id))
        except ColdQueryError as e:raise ColdQueryError('invalid_filters') from e
        where.append('e.id=?');args.append(identifier)
    elif event_id is not None:raise ColdQueryError('invalid_filters')
    if cursor is not None:
        at,identifier=_cursor(cursor,context,cursor_key)
        where.append('(e.event_at<? OR (e.event_at=? AND (length(e.id)<? OR (length(e.id)=? AND e.id<? COLLATE BINARY))))');args.extend([at,at,len(identifier),len(identifier),identifier])
    end=time.monotonic()+QUERY_SECONDS;db=fd=None
    try:
        db,fd=_open(prepared,end);rows=[];last=None;has_more=False
        index='event_source' if selected['source'] else 'event_scope'
        statement="SELECT e.ordinal,e.id,e.devid,e.vd,e.event_at,e.received_at,e.srcip,e.dstip,r.payload FROM events e INDEXED BY "+index+" JOIN records r ON r.table_name='events' AND r.ordinal=e.ordinal WHERE "+' AND '.join(where)+' ORDER BY e.event_at DESC,length(e.id) DESC,e.id DESC LIMIT ?'
        found=list(db.execute(statement,args+[1 if kind=='detail' else PAGE_SIZE+1]))
        if time.monotonic()>end:raise ColdQueryError('query_timeout')
        for position,(*projection,payload) in enumerate(found):
            row=_row(payload,projection)
            if row['devid']!=serial or row['vd']!=vdom or row.get('file_id')!=prepared.manifest['source_id']:raise ColdQueryError('snapshot_invalid')
            if kind=='list':
                if position==PAGE_SIZE:has_more=True;break
                rows.append(_compact(row));last=(projection[4],projection[1])
            else:
                fields=row.get('fields','')
                if not isinstance(fields,str):raise ColdQueryError('snapshot_invalid')
                event=_compact(row)
                for key in ('raw_sha256','byte_offset','byte_length','line_number'):
                    if key in row:event[key]=row[key].hex() if key=='raw_sha256' and isinstance(row[key],bytes) else str(row[key]) if key!='raw_sha256' else _json_value(row[key])
                notes=[]
                for (note_payload,) in db.execute("SELECT payload FROM records WHERE table_name='event_notes' ORDER BY ordinal"):
                    if time.monotonic()>end:raise ColdQueryError('query_timeout')
                    note=_row(note_payload)
                    if note.get('event_id')!=row['id']:continue
                    if len(notes)>=100:raise ColdQueryError('result_too_large')
                    notes.append({k:(str(v) if k in ('id','event_id') else _json_value(v)) for k,v in note.items()})
                result={'event':event,'fields_text':fields,'notes':notes,'snapshot_id':str(prepared.snapshot_id),'manifest_sha256':prepared.manifest_sha256}
                _unchanged(prepared,fd);return _bounded(result)
        if kind=='detail':raise ColdQueryError('event_not_found')
        result={'rows':rows,'has_more':has_more,'next_cursor':_token({'context':context,'at':last[0],'id':last[1]},cursor_key) if has_more else None,'page_size':PAGE_SIZE,'snapshot_id':str(prepared.snapshot_id),'manifest_sha256':prepared.manifest_sha256,'filters':selected}
        _unchanged(prepared,fd);return _bounded(result)
    except ColdQueryError:raise
    except sqlite3.Error as e:raise ColdQueryError('query_timeout' if time.monotonic()>end else 'snapshot_invalid') from e
    except (fmt.ColdError,OSError,TypeError,ValueError,KeyError) as e:raise ColdQueryError('snapshot_invalid') from e
    finally:
        if db:db.close()
        if fd is not None:os.close(fd)

def coverage(prepared):
    end=time.monotonic()+60;db=fd=None
    try:
        db,fd=_open(prepared,end);groups={}
        for *projection,payload in db.execute("SELECT e.ordinal,e.id,e.devid,e.vd,e.event_at,e.received_at,e.srcip,e.dstip,r.payload FROM events e JOIN records r ON r.table_name='events' AND r.ordinal=e.ordinal ORDER BY e.ordinal"):
            if time.monotonic()>end:raise ColdQueryError('query_timeout')
            row=_row(payload,projection);key=(row['devid'],row['vd']);_scope(*key)
            if row.get('file_id')!=prepared.manifest['source_id']:raise ColdQueryError('snapshot_invalid')
            event_at=_stamp(row['event_at']);received_at=_stamp(row['received_at'])
            if key not in groups:
                if len(groups)>=4096:raise ColdQueryError('result_too_large')
                groups[key]={'serial':key[0],'vdom':key[1],'records':0,'first_event_at':event_at,'last_event_at':event_at,'first_received_at':received_at,'last_received_at':received_at}
            group=groups[key];group['records']+=1
            group['first_event_at']=min(group['first_event_at'],event_at);group['last_event_at']=max(group['last_event_at'],event_at)
            group['first_received_at']=min(group['first_received_at'],received_at);group['last_received_at']=max(group['last_received_at'],received_at)
        _unchanged(prepared,fd)
        if sum(v['records'] for v in groups.values())!=prepared.manifest['table_counts'].get('events',0):raise ColdQueryError('snapshot_invalid')
        return list(groups.values())
    except ColdQueryError:raise
    except (sqlite3.Error,fmt.ColdError,OSError,TypeError,ValueError,KeyError) as e:raise ColdQueryError('snapshot_invalid') from e
    finally:
        if db:db.close()
        if fd is not None:os.close(fd)
