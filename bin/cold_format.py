"""Signed, typed detailed-log copies. Never connects to production SQL or deletes logs."""
import base64
import ctypes
import datetime as dt
import errno
import gzip
import hashlib
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
from urllib.parse import quote
import uuid
import zlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA='fls-detailed-snapshot-v1'
MAX_COMPRESSED=256*1024**2
MAX_EXPANDED=8*1024**3
MAX_ROW=1024**2
MAX_MANIFEST=2*1024**2
MAX_SECONDS=180
CHUNK=256*1024
TABLE=re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
HOUR=re.compile(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl\Z')
HASH=re.compile(r'[a-f0-9]{64}\Z')
TIME=re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z')
DDL=[
 'CREATE TABLE records(table_name TEXT NOT NULL,ordinal INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(table_name,ordinal)) WITHOUT ROWID',
 'CREATE TABLE events(ordinal INTEGER PRIMARY KEY,id TEXT NOT NULL UNIQUE,devid TEXT COLLATE BINARY NOT NULL,vd TEXT COLLATE BINARY NOT NULL,event_at TEXT NOT NULL,received_at TEXT NOT NULL,srcip TEXT NOT NULL,dstip TEXT NOT NULL)',
 'CREATE INDEX event_scope ON events(devid COLLATE BINARY,vd COLLATE BINARY,event_at,ordinal)',
 'CREATE INDEX event_source ON events(devid COLLATE BINARY,vd COLLATE BINARY,srcip,event_at,ordinal)']

class ColdError(ValueError):pass

def canonical(value):
 try:return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
 except (ValueError,TypeError,UnicodeError,RecursionError) as e:raise ColdError('canonical_invalid') from e

def _pairs(items):
 result={}
 for k,v in items:
  if k in result:raise ColdError('duplicate_json_key')
  result[k]=v
 return result

def strict_json(raw,limit=MAX_MANIFEST):
 if not isinstance(raw,bytes) or not 0<len(raw)<=limit:raise ColdError('json_size')
 def nonint(_):raise ColdError('json_number')
 try:return json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_float=nonint,parse_constant=nonint)
 except (ValueError,UnicodeError,RecursionError) as e:raise ColdError('invalid_json') from e

def _deadline(end):
 if time.monotonic()>end:raise ColdError('deadline_exceeded')

def _integer(value,low=0,high=2**64-1):
 if type(value) is not int or not low<=value<=high:raise ColdError('integer_invalid')
 return value

def _time(value):
 if isinstance(value,dt.datetime):
  if value.tzinfo is not None:value=value.astimezone(dt.timezone.utc).replace(tzinfo=None)
 elif isinstance(value,str):
  try:value=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
  except ValueError as e:raise ColdError('datetime_invalid') from e
  if value.tzinfo is not None:value=value.astimezone(dt.timezone.utc).replace(tzinfo=None)
 else:raise ColdError('datetime_invalid')
 return f'{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}.{value.microsecond:06d}Z'

def typed_row(row):
 if not isinstance(row,dict) or not row or len(row)>256:raise ColdError('row_invalid')
 out={}
 for name,value in row.items():
  if not isinstance(name,str) or not TABLE.fullmatch(name):raise ColdError('column_invalid')
  if value is None:out[name]=['n']
  elif type(value) is int:out[name]=['i',str(_integer(value,-2**63))]
  elif isinstance(value,bytes):out[name]=['b',base64.b64encode(value).decode('ascii')]
  elif isinstance(value,dt.datetime):
   if value.tzinfo is not None:raise ColdError('datetime_timezone')
   out[name]=['d',_time(value)]
  elif isinstance(value,str):out[name]=['s',value]
  else:raise ColdError('cell_type')
 if len(canonical(out))>MAX_ROW:raise ColdError('row_size')
 return out

def decode_row(value):
 if not isinstance(value,dict) or not value or len(value)>256:raise ColdError('row_invalid')
 result={}
 for name,cell in value.items():
  if not isinstance(name,str) or not TABLE.fullmatch(name) or not isinstance(cell,list):raise ColdError('cell_invalid')
  if cell==['n']:result[name]=None;continue
  if len(cell)!=2 or not isinstance(cell[1],str):raise ColdError('cell_invalid')
  tag,text=cell
  if tag=='s':result[name]=text
  elif tag=='i':
   if not re.fullmatch(r'0|-?[1-9][0-9]{0,19}',text):raise ColdError('integer_invalid')
   result[name]=_integer(int(text),-2**63)
  elif tag=='b':
   try:raw=base64.b64decode(text,validate=True)
   except ValueError as e:raise ColdError('binary_invalid') from e
   if base64.b64encode(raw).decode('ascii')!=text:raise ColdError('binary_invalid')
   result[name]=raw
  elif tag=='d':
   if not TIME.fullmatch(text):raise ColdError('datetime_invalid')
   try:result[name]=dt.datetime.strptime(text,'%Y-%m-%dT%H:%M:%S.%fZ')
   except ValueError as e:raise ColdError('datetime_invalid') from e
  else:raise ColdError('cell_type')
 return result

def _parents(path):
 for p in (Path(path),*Path(path).parents):
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode):raise ColdError('directory_invalid')

def _regular(path,max_size,*,missing=False):
 p=Path(path);_parents(p.parent)
 try:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 except FileNotFoundError:
  if missing:return None
  raise ColdError('file_missing') from None
 except OSError as e:raise ColdError('file_unsafe') from e
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or not 0<s.st_size<=max_size:raise ColdError('file_unsafe')
  return os.fdopen(fd,'rb')
 except BaseException:os.close(fd);raise

def _key(value,private=False):
 if private and isinstance(value,Ed25519PrivateKey):return value
 if not private and isinstance(value,Ed25519PublicKey):return value
 if isinstance(value,(str,Path)):
  with _regular(value,16384) as f:value=f.read(16385)
 if not isinstance(value,bytes):raise ColdError('trusted_key_required')
 try:key=serialization.load_pem_private_key(value,password=None) if private else serialization.load_pem_public_key(value)
 except (ValueError,TypeError) as e:raise ColdError('key_invalid') from e
 if not isinstance(key,Ed25519PrivateKey if private else Ed25519PublicKey):raise ColdError('key_algorithm')
 return key

def _hash_file(path,limit,end):
 h=hashlib.sha256();size=0
 with _regular(path,limit) as f:
  for b in iter(lambda:f.read(CHUNK),b''):
   _deadline(end);size+=len(b)
   if size>limit:raise ColdError('file_size')
   h.update(b)
 return h.hexdigest(),size

def _schema_meta(value):
 if not isinstance(value,dict) or not 1<=len(value)<=64:raise ColdError('schema_metadata')
 for table,columns in value.items():
  if not isinstance(table,str) or not TABLE.fullmatch(table) or not isinstance(columns,list) or not 1<=len(columns)<=256:raise ColdError('schema_metadata')
  seen=set()
  for c in columns:
   if not isinstance(c,dict) or not {'name','type','extra'}<=set(c) or set(c)-{'name','type','extra','nullable','collation','ordinal','default'}:raise ColdError('schema_metadata')
   if not isinstance(c['name'],str) or not TABLE.fullmatch(c['name']) or c['name'] in seen:raise ColdError('schema_metadata')
   seen.add(c['name'])
   for name in ['type','extra']:
    if not isinstance(c[name],str) or len(c[name])>4096:raise ColdError('schema_metadata')
 # Manifest metadata must be JSON-native without floating point or executable SQL.
 strict_json(canonical(value))
 return value

def _metadata(metadata):
 allowed={'installation_id','installation_uuid','source_file','source_id','raw_manifest_sha256','raw_sha256','schema_metadata','snapshot_at','source_received_min','source_received_max','purpose'}
 if not isinstance(metadata,dict) or set(metadata)-allowed:raise ColdError('metadata_fields')
 m=dict(metadata)
 if 'installation_uuid' in m:
  if 'installation_id' in m and m['installation_id']!=m['installation_uuid']:raise ColdError('installation_invalid')
  m['installation_id']=m.pop('installation_uuid')
 if set(m)!=allowed-{'installation_uuid'}:raise ColdError('metadata_fields')
 try:u=uuid.UUID(m['installation_id'])
 except (ValueError,TypeError,AttributeError) as e:raise ColdError('installation_invalid') from e
 if u.version!=4 or str(u)!=m['installation_id']:raise ColdError('installation_invalid')
 if not isinstance(m['source_file'],str) or not HOUR.fullmatch(m['source_file']):raise ColdError('source_invalid')
 try:dt.datetime.strptime(m['source_file'],'%Y-%m-%d-%H.jsonl')
 except ValueError as e:raise ColdError('source_invalid') from e
 _integer(m['source_id'],1,2**32-1)
 for k in ['raw_manifest_sha256','raw_sha256']:
  if not isinstance(m[k],str) or not HASH.fullmatch(m[k]):raise ColdError('hash_invalid')
 if m['purpose'] not in ('canary','archive'):raise ColdError('purpose_invalid')
 for k in ['snapshot_at','source_received_min','source_received_max']:m[k]=_time(m[k])
 if m['source_received_min']>m['source_received_max'] or m['snapshot_at']<m['source_received_max']:raise ColdError('source_time_invalid')
 _schema_meta(m['schema_metadata']);return m

def _projection(row,ordinal):
 required=['id','devid','vd','event_at','received_at','srcip','dstip']
 if any(x not in row for x in required):raise ColdError('event_projection')
 identifier=str(_integer(row['id'],1))
 for k,limit in [('devid',40),('vd',64),('srcip',45),('dstip',45)]:
  if not isinstance(row[k],str) or len(row[k])>limit or any(ord(c)<32 for c in row[k]):raise ColdError('event_projection')
 return (ordinal,identifier,row['devid'],row['vd'],_time(row['event_at']),_time(row['received_at']),row['srcip'],row['dstip'])

def _open_sqlite(path):
 with _regular(path,MAX_EXPANDED):pass
 connection=sqlite3.connect('file:'+quote(str(Path(path).absolute()),safe='/')+'?mode=ro&immutable=1',uri=True)
 connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,MAX_ROW+16384);connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,65536)
 connection.enable_load_extension(False);connection.execute('PRAGMA trusted_schema=OFF');connection.execute('PRAGMA query_only=ON');connection.execute('PRAGMA cache_size=-8192')
 def authorize(action,arg1,arg2,_db,_trigger):
  if action in (sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ):return sqlite3.SQLITE_OK
  if action==sqlite3.SQLITE_FUNCTION and (arg2 or '').lower() in ('like','count'):return sqlite3.SQLITE_OK
  if action==sqlite3.SQLITE_PRAGMA and arg1=='quick_check':return sqlite3.SQLITE_OK
  return sqlite3.SQLITE_DENY
 connection.set_authorizer(authorize)
 return connection

def _check_schema(db,integrity=True):
 actual=dict(db.execute("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
 expected={'records':DDL[0],'events':DDL[1],'event_scope':DDL[2],'event_source':DDL[3]}
 if actual!=expected:raise ColdError('sqlite_schema')
 if integrity and db.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise ColdError('sqlite_integrity')

def _fsync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)

def _noreplace(source,target):
 libc=ctypes.CDLL(None,use_errno=True)
 try:rename=libc.renameat2
 except AttributeError as e:raise ColdError('atomic_publish_unsupported') from e
 rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
 if rename(-100,os.fsencode(source),-100,os.fsencode(target),1)!=0:
  value=ctypes.get_errno()
  if value in (errno.EEXIST,errno.ENOTEMPTY):raise ColdError('destination_exists')
  raise ColdError('atomic_publish_failed')

def build_bundle(destination_dir,tables,metadata,private_key):
 end=time.monotonic()+MAX_SECONDS;destination=Path(destination_dir).absolute();_parents(destination.parent)
 key=_key(private_key,True);m=_metadata(metadata)
 if not isinstance(tables,dict) or set(tables)!=set(m['schema_metadata']):raise ColdError('table_set')
 temp=Path(tempfile.mkdtemp(prefix='.cold-build-',dir=destination.parent));os.chmod(temp,0o700)
 try:
  sqlite=temp/'payload.sqlite';db=sqlite3.connect(sqlite)
  try:
   db.execute('PRAGMA page_size=4096');db.execute('PRAGMA max_page_count='+str(MAX_EXPANDED//4096))
   for statement in DDL:db.execute(statement)
   counts={};hashes={};db.execute('BEGIN')
   for name in sorted(tables):
    h=hashlib.sha256();count=0;columns={c['name'] for c in m['schema_metadata'][name]}
    for row in tables[name]:
     _deadline(end)
     if set(row)!=columns:raise ColdError('row_columns')
     typed=typed_row(row);payload=canonical(typed);h.update(payload+b'\n')
     db.execute('INSERT INTO records VALUES(?,?,?)',(name,count,payload.decode('utf-8')))
     if name=='events':db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)',_projection(row,count))
     count+=1
     if count%1024==0 and sqlite.stat().st_size>MAX_EXPANDED:raise ColdError('expanded_size')
    counts[name]=count;hashes[name]=h.hexdigest()
   db.commit()
  finally:db.close()
  raw_sha,raw_size=_hash_file(sqlite,MAX_EXPANDED,end)
  compressed=temp/'payload.sqlite.gz'
  with sqlite.open('rb') as source,compressed.open('xb') as target:
   os.chmod(compressed,0o640)
   with gzip.GzipFile(filename='',mode='wb',fileobj=target,compresslevel=1,mtime=0) as gz:
    for chunk in iter(lambda:source.read(CHUNK),b''):
     _deadline(end);gz.write(chunk)
     if target.tell()>MAX_COMPRESSED:raise ColdError('compressed_size')
   target.flush();os.fsync(target.fileno())
  compressed_sha,compressed_size=_hash_file(compressed,MAX_COMPRESSED,end)
  m.update(schema=SCHEMA,table_counts=counts,table_row_sha256=hashes,payload={'file':'payload.sqlite.gz','compressed_sha256':compressed_sha,'compressed_bytes':compressed_size,'uncompressed_sha256':raw_sha,'uncompressed_bytes':raw_size},signature_algorithm='Ed25519',key_id=hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest())
  envelope={'manifest':m,'signature':base64.b64encode(key.sign(canonical(m))).decode('ascii')};raw=canonical(envelope)+b'\n'
  if len(raw)>MAX_MANIFEST:raise ColdError('manifest_size')
  with (temp/'manifest.json').open('xb') as out:os.chmod(temp/'manifest.json',0o640);out.write(raw);out.flush();os.fsync(out.fileno())
  sqlite.unlink();os.chmod(temp,0o750);_fsync_dir(temp)
  verify_bundle(temp,key.public_key())
  try:_noreplace(temp,destination)
  except ColdError as e:
   if str(e)!='destination_exists':raise
   existing=verify_bundle(destination,key.public_key())
   if existing['manifest']!=m:raise ColdError('destination_conflict')
   return existing['manifest']
  _fsync_dir(destination.parent);return m
 finally:
  if temp.exists():shutil.rmtree(temp)

def _manifest(bundle,public_key):
 root=Path(bundle).absolute();_parents(root)
 if set(p.name for p in root.iterdir())!={'manifest.json','payload.sqlite.gz'}:raise ColdError('bundle_files')
 with _regular(root/'manifest.json',MAX_MANIFEST) as f:raw=f.read(MAX_MANIFEST+1)
 envelope=strict_json(raw)
 if not isinstance(envelope,dict) or set(envelope)!={'manifest','signature'} or canonical(envelope)+b'\n'!=raw:raise ColdError('envelope_invalid')
 m=envelope['manifest'];extra={'schema','table_counts','table_row_sha256','payload','signature_algorithm','key_id'}
 if not isinstance(m,dict) or set(m)!={'installation_id','source_file','source_id','raw_manifest_sha256','raw_sha256','schema_metadata','snapshot_at','source_received_min','source_received_max','purpose'}|extra:raise ColdError('manifest_fields')
 if m['schema']!=SCHEMA or m['signature_algorithm']!='Ed25519':raise ColdError('manifest_schema')
 original_metadata={k:v for k,v in m.items() if k not in extra}
 if _metadata(original_metadata)!=original_metadata:raise ColdError('metadata_canonical')
 key=_key(public_key)
 if m['key_id']!=hashlib.sha256(key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest():raise ColdError('key_mismatch')
 try:signature=base64.b64decode(envelope['signature'],validate=True)
 except (ValueError,TypeError) as e:raise ColdError('signature_invalid') from e
 if len(signature)!=64 or base64.b64encode(signature).decode()!=envelope['signature']:raise ColdError('signature_invalid')
 try:key.verify(signature,canonical(m))
 except Exception as e:raise ColdError('signature_invalid') from e
 p=m['payload']
 if not isinstance(p,dict) or set(p)!={'file','compressed_sha256','compressed_bytes','uncompressed_sha256','uncompressed_bytes'} or p['file']!='payload.sqlite.gz':raise ColdError('payload_fields')
 for name in ['compressed_sha256','uncompressed_sha256']:
  if not isinstance(p[name],str) or not HASH.fullmatch(p[name]):raise ColdError('hash_invalid')
 _integer(p['compressed_bytes'],1,MAX_COMPRESSED);_integer(p['uncompressed_bytes'],1,MAX_EXPANDED)
 if not isinstance(m['table_counts'],dict) or not isinstance(m['table_row_sha256'],dict) or set(m['table_counts'])!=set(m['schema_metadata']) or set(m['table_row_sha256'])!=set(m['table_counts']):raise ColdError('table_set')
 for table,count in m['table_counts'].items():
  _integer(count,0,2**40)
  if not HASH.fullmatch(str(m['table_row_sha256'][table])):raise ColdError('hash_invalid')
 return m

def _expand(bundle,path,m,end):
 p=m['payload'];source_path=Path(bundle)/p['file']
 if shutil.disk_usage(path.parent).free<p['uncompressed_bytes']+16*1024**2:raise ColdError('space_unavailable')
 dec=zlib.decompressobj(31);h=hashlib.sha256();total=0
 def identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
 try:
  with _regular(source_path,MAX_COMPRESSED) as source:
   before=identity(os.fstat(source.fileno()));compressed=hashlib.sha256();size=0
   for chunk in iter(lambda:source.read(CHUNK),b''):
    _deadline(end);size+=len(chunk);compressed.update(chunk)
    if size>MAX_COMPRESSED:raise ColdError('compressed_size')
   if compressed.hexdigest()!=p['compressed_sha256'] or size!=p['compressed_bytes']:raise ColdError('compressed_hash')
   if identity(os.fstat(source.fileno()))!=before:raise ColdError('payload_changed')
   source.seek(0)
   with path.open('xb') as out:
    os.chmod(path,0o640)
    for chunk in iter(lambda:source.read(CHUNK),b''):
     _deadline(end)
     while chunk:
      data=dec.decompress(chunk,CHUNK);chunk=dec.unconsumed_tail;total+=len(data)
      if total>p['uncompressed_bytes'] or total>MAX_EXPANDED:raise ColdError('expanded_size')
      h.update(data);out.write(data)
      if dec.eof:
       if dec.unused_data or chunk or source.read(1):raise ColdError('gzip_trailing')
       break
    if not dec.eof:raise ColdError('gzip_truncated')
    out.flush();os.fsync(out.fileno())
   if identity(os.fstat(source.fileno()))!=before or identity(source_path.lstat())!=before:raise ColdError('payload_changed')
 except zlib.error as e:raise ColdError('gzip_invalid') from e
 if total!=p['uncompressed_bytes'] or h.hexdigest()!=p['uncompressed_sha256']:raise ColdError('expanded_hash')

def _check_records(path,m,end):
 db=_open_sqlite(path)
 try:
  db.set_progress_handler(lambda:int(time.monotonic()>end),1000);_check_schema(db)
  if set(r[0] for r in db.execute('SELECT DISTINCT table_name FROM records'))!=set(k for k,v in m['table_counts'].items() if v):raise ColdError('record_tables')
  projection_count=0
  for table,count in m['table_counts'].items():
   h=hashlib.sha256();ordinal=0;columns={x['name'] for x in m['schema_metadata'][table]}
   for index,payload in db.execute('SELECT ordinal,payload FROM records WHERE table_name=? ORDER BY ordinal',(table,)):
    _deadline(end);raw=payload.encode('utf-8')
    if index!=ordinal or len(raw)>MAX_ROW:raise ColdError('record_ordinal')
    parsed=strict_json(raw,MAX_ROW);row=decode_row(parsed)
    if canonical(parsed)!=raw or canonical(typed_row(row))!=raw or set(row)!=columns:raise ColdError('record_canonical')
    h.update(raw+b'\n')
    if table=='events':
     actual=db.execute('SELECT ordinal,id,devid,vd,event_at,received_at,srcip,dstip FROM events WHERE ordinal=?',(ordinal,)).fetchone()
     if actual!=_projection(row,ordinal):raise ColdError('projection_mismatch')
     projection_count+=1
    ordinal+=1
   if ordinal!=count or h.hexdigest()!=m['table_row_sha256'][table]:raise ColdError('record_hash')
  if db.execute('SELECT COUNT(*) FROM events').fetchone()[0]!=projection_count:raise ColdError('projection_count')
 except sqlite3.Error as e:raise ColdError('deadline_exceeded' if time.monotonic()>end else 'sqlite_invalid') from e
 finally:db.close()

def _report(m):
 return {'verified':True,'manifest':m,'manifest_sha256':hashlib.sha256(canonical(m)).hexdigest(),'payload_sha256':m['payload']['compressed_sha256'],'compressed_bytes':m['payload']['compressed_bytes'],'expanded_bytes':m['payload']['uncompressed_bytes'],'event_count':m['table_counts'].get('events',0),'note_count':m['table_counts'].get('event_notes',0)}

def verify_bundle(directory,trusted_public_key):
 end=time.monotonic()+MAX_SECONDS;m=_manifest(directory,trusted_public_key)
 with tempfile.TemporaryDirectory(prefix='fls-cold-verify-') as folder:
  path=Path(folder)/'payload.sqlite';_expand(directory,path,m,end);_check_records(path,m,end)
 return _report(m)

def restore_bundle(directory,output_dir,trusted_public_key):
 end=time.monotonic()+MAX_SECONDS;m=_manifest(directory,trusted_public_key);output=Path(output_dir).absolute();_parents(output.parent)
 # Restore creates a fresh destination. Existing empty directories are accepted,
 # but existing files, symlinks and previous restorations are never overwritten.
 created=False
 if not output.exists():output.mkdir(mode=0o750);created=True
 _parents(output)
 if any(output.iterdir()):raise ColdError('restore_not_empty')
 temporary=output/'.restore.pending'
 try:
  _expand(directory,temporary,m,end);_check_records(temporary,m,end)
  final=output/'payload.sqlite';_noreplace(temporary,final);_fsync_dir(output);return final
 except BaseException:
  temporary.unlink(missing_ok=True)
  if created:
   try:output.rmdir()
   except OSError:pass
  raise

def iter_records(sqlitepath,table):
 if not isinstance(table,str) or not TABLE.fullmatch(table):raise ColdError('table_invalid')
 db=_open_sqlite(sqlitepath);end=time.monotonic()+MAX_SECONDS
 try:
  db.set_progress_handler(lambda:int(time.monotonic()>end),1000);_check_schema(db,integrity=False)
  for (payload,) in db.execute('SELECT payload FROM records WHERE table_name=? ORDER BY ordinal',(table,)):
   _deadline(end);yield decode_row(strict_json(payload.encode('utf-8'),MAX_ROW))
 except sqlite3.Error as e:raise ColdError('deadline_exceeded' if time.monotonic()>end else 'sqlite_invalid') from e
 finally:db.close()

def query_events(sqlitepath,serial,vdom,source=None,q=None,limit=100):
 if any(not isinstance(v,str) or not v or len(v)>limit_ or any(ord(c)<32 for c in v) for v,limit_ in [(serial,40),(vdom,64)]):raise ColdError('scope_invalid')
 _integer(limit,1,100);where=['e.devid=? COLLATE BINARY','e.vd=? COLLATE BINARY'];args=[serial,vdom]
 if source is not None:
  try:ipaddress.ip_address(source)
  except (ValueError,TypeError) as e:raise ColdError('source_invalid') from e
  where.append('e.srcip=?');args.append(source)
 if q is not None:
  if not isinstance(q,str) or not 1<=len(q)<=160 or any(ord(c)<32 for c in q):raise ColdError('query_invalid')
  where.append("r.payload LIKE ? ESCAPE '!'");args.append('%'+q.replace('!','!!').replace('%','!%').replace('_','!_')+'%')
 db=_open_sqlite(sqlitepath);end=time.monotonic()+5;total=0;rows=[]
 try:
  db.set_progress_handler(lambda:int(time.monotonic()>end),1000);_check_schema(db,integrity=False)
  for *projection,payload in db.execute("SELECT e.ordinal,e.id,e.devid,e.vd,e.event_at,e.received_at,e.srcip,e.dstip,r.payload FROM events e JOIN records r ON r.table_name='events' AND r.ordinal=e.ordinal WHERE "+' AND '.join(where)+' ORDER BY e.event_at DESC,e.ordinal DESC LIMIT ?',args+[limit]):
   total+=len(payload.encode('utf-8'))
   if total>8*1024**2:raise ColdError('query_result_size')
   row=decode_row(strict_json(payload.encode('utf-8'),MAX_ROW))
   if tuple(projection)!=_projection(row,projection[0]) or row['devid']!=serial or row['vd']!=vdom:raise ColdError('projection_mismatch')
   rows.append(row)
  return rows
 except sqlite3.Error as e:raise ColdError('deadline_exceeded' if time.monotonic()>end else 'query_failed') from e
 finally:db.close()
