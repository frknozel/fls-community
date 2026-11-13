#!/usr/bin/python3
"""Managed connections: encrypted credentials, bounded read-only HTTPS and isolated caches."""
import functools,base64,concurrent.futures,datetime as dt,http.client,importlib.util,ipaddress,json,os,re,socket,ssl,stat,time
from pathlib import Path
from urllib.parse import urlencode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pymysql
import fortigate_compat as compatibility
BASE=Path('/srv/fls-server/metrics/fortigate');AAD=b'FLS-FortiGate-v1'

def private_file(name,limit=16384):
    folder=os.environ.get('CREDENTIALS_DIRECTORY');path=(Path(folder)/name) if folder else Path('/etc/fls')/name
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno());forbidden=0o037 if folder or name=='credential-key' else 0o077
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode&forbidden or info.st_size>limit:raise ValueError('credential')
        return stream.read(limit+1)

def connect():
    config=json.loads(private_file('fortigate-registry.json'))
    if config.get('user')!='fls_registry':raise ValueError('credential')
    return pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',charset='utf8mb4',autocommit=True,connect_timeout=2,read_timeout=5,write_timeout=5,cursorclass=pymysql.cursors.DictCursor)

def secret(envelope,key):
    if not isinstance(envelope,str) or not envelope.startswith('v1:') or len(key)!=32:raise ValueError('credential')
    raw=base64.b64decode(envelope[3:],validate=True);value=AESGCM(key).decrypt(raw[:12],raw[12:],AAD).decode('ascii')
    if not re.fullmatch(r'[A-Za-z0-9._~+/=-]{16,512}',value):raise ValueError('credential')
    return value

def validate_device(device):
    for field in ['connect_ip','source_ip']:
        if field=='source_ip' and not device.get(field):continue
        value=ipaddress.ip_address(device[field])
        if value.is_loopback or value.is_link_local or value.is_multicast or value.is_unspecified or value.is_reserved or getattr(value,'ipv4_mapped',None):raise ValueError('destination')
    host=device['hostname']
    if not isinstance(host,str) or len(host)>253 or not re.fullmatch(r'[A-Za-z0-9.:-]+',host):raise ValueError('hostname')
    if not re.fullmatch(r'[A-Za-z0-9_-]{3,40}',device['serial']) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}',device['vdom']) or not 1<=int(device['port'])<=65535:raise ValueError('identity')

class DeviceHTTPS(http.client.HTTPSConnection):
    def __init__(self,device):
        self.device=device;super().__init__(device['hostname'],int(device['port']),timeout=4,context=ssl.create_default_context())
    def connect(self):
        d=self.device;source=(d['source_ip'],0) if d.get('source_ip') else None
        raw=socket.create_connection((d['connect_ip'],int(d['port'])),self.timeout,source)
        try:self.sock=self._context.wrap_socket(raw,server_hostname=d['hostname'])
        except BaseException:raw.close();raise

@functools.lru_cache(maxsize=1)
def load_poller():
    spec=importlib.util.spec_from_file_location('fls_managed_poller',Path(__file__).with_name('fortigate-poller.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def request(device,token,path,fields='',factory=DeviceHTTPS):
    """Fixed GET allowlist, bounded CMDB pagination, identity verified on every page."""
    poller=load_poller();allowed={entry[0] for mode in poller.ENDPOINTS.values() for entry in mode.values()}|{'monitor/system/status'}
    if path not in allowed:raise poller.PollError('endpoint')
    validate_device(device);collection=path.startswith('cmdb/') and path not in ('cmdb/system/ha','cmdb/system/sdwan')
    combined=[];seen=set();revision=None;expected_size=None;start=0;total_bytes=0;began=time.monotonic()
    for page in range(40):
        connection=factory(device)
        try:
            if time.monotonic()-began>24:raise poller.PollError('poll_budget')
            params={'vdom':device['vdom']}
            if fields:params['format']=fields
            if collection:params.update(start=start,count=500)
            connection.request('GET','/api/v2/'+path+'?'+urlencode(params),headers={'Accept':'application/json','Authorization':'Bearer '+token,'User-Agent':'FLS-managed-readonly/2'})
            response=connection.getresponse()
            if response.status!=200:raise poller.PollError('http_'+str(response.status))
            if response.headers.get_content_type()!='application/json':raise poller.PollError('json')
            body=response.read(poller.MAX_BODY+1);total_bytes+=len(body)
            if len(body)>poller.MAX_BODY or total_bytes>12*1024*1024:raise poller.PollError('response_limit')
            data=json.loads(body)
            if not isinstance(data,dict) or data.get('status')!='success':raise poller.PollError('api_status')
            if data.get('serial')!=device['serial'] or data.get('vdom')!=device['vdom']:raise poller.PollError('device_scope')
            limited=data.get('limit_reached',False)
            if not isinstance(limited,bool):raise poller.PollError('pagination_schema')
            if path=='monitor/system/status':
                try:return compatibility.inventory(data)
                except ValueError:raise poller.PollError('inventory_schema') from None
            value=data.get('results')
            if not collection:
                if limited:raise poller.PollError('incomplete_collection')
                return value
            if not isinstance(value,list) or any(not isinstance(row,dict) for row in value):raise poller.PollError('schema')
            size=data.get('size');matched=data.get('matched_count')
            if not isinstance(size,int) or isinstance(size,bool) or not 0<=size<=1000000:raise poller.PollError('pagination_schema')
            if expected_size is not None and size!=expected_size:raise poller.PollError('collection_changed')
            expected_size=size
            if size>20000:raise poller.PollError('collection_limit')
            if matched is not None and (not isinstance(matched,int) or isinstance(matched,bool) or matched!=len(value)):raise poller.PollError('pagination_schema')
            for row in value:
                identity=row.get('policyid') if path=='cmdb/firewall/policy' else row.get('name',row.get('id'))
                if isinstance(identity,bool) or not isinstance(identity,(str,int)):raise poller.PollError('pagination_identity')
                marker=(type(identity).__name__,identity)
                if marker in seen:raise poller.PollError('pagination_duplicate')
                seen.add(marker)
            combined.extend(value)
            if len(combined)>20000:raise poller.PollError('collection_limit')
            if expected_size is not None and len(combined)>expected_size:raise poller.PollError('collection_changed')
            # limit_reached describes a response byte limit, not necessarily the count window.
            # In 7.6.6 a count-limited page can set it false while size still exceeds results.
            more=limited or len(combined)<expected_size
            current=data.get('revision')
            if page or more:
                if not isinstance(current,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',current):raise poller.PollError('pagination_revision')
                if revision is not None and revision!=current:raise poller.PollError('collection_changed')
                revision=current
            if not more:return combined
            if not value:raise poller.PollError('pagination_progress')
            # No filter is used, so table-index start advances by returned rows. next_idx
            # can be the next index or the last index across FortiOS response boundaries.
            cursor=data.get('next_idx')
            if not isinstance(cursor,int) or isinstance(cursor,bool) or cursor not in (start+len(value)-1,start+len(value)):raise poller.PollError('pagination_progress')
            start+=len(value)
        except poller.PollError:raise
        except ssl.SSLCertVerificationError:raise poller.PollError('tls') from None
        except Exception:raise poller.PollError('connection_or_json') from None
        finally:connection.close()
    raise poller.PollError('collection_limit')

def poll_device(device,keys,mode,master,root=BASE,requester=request,connector=connect):
    # Each worker owns a DB connection; destinations, cache directories and histories never mix.
    poller=load_poller();start=time.monotonic();database=connector();used=set();tokens={};errors={}
    try:
        for item in keys:
            try:tokens[item['id']]=secret(item['secret_cipher'],master)
            except Exception:errors[item['id']]='credential'
        if mode=='live':
            for item in keys:
                if item['check_status']!='pending':continue
                error=errors.get(item['id']);began=dt.datetime.now(dt.timezone.utc)
                if not error:
                    try:requester(device,tokens[item['id']],'monitor/system/status')
                    except Exception as e:error=str(e) if isinstance(e,poller.PollError) else 'connection_or_json'
                with database.cursor() as c:
                    c.execute("UPDATE fortigate_credentials SET check_status=%s,check_code=%s,checked_at=UTC_TIMESTAMP(6),checked_revision=%s WHERE id=%s AND revision=%s AND test_requested_at=%s",('error' if error else 'ok',error,item['revision'],item['id'],item['revision'],item['test_requested_at']))
        if not device['enabled']:return {'device_id':device['id'],'status':'disabled'}
        eligible=[k for k in keys if k['enabled'] and k['purpose'] in ('both',mode)]
        def fetch(component,requested_mode,unused):
            if time.monotonic()-start>(42 if mode=='live' else 55):raise poller.PollError('poll_budget')
            last='no_credentials'
            for item in eligible:
                if item['id'] not in tokens:last='credential';continue
                path,fields=poller.ENDPOINTS[requested_mode][component]
                try:
                    value=requester(device,tokens[item['id']],path,fields);used.add(item['id']);return value
                except Exception as e:
                    code=str(e) if isinstance(e,poller.PollError) else 'connection_or_json';last=code
                    # Another key can fix permissions; it cannot fix TLS, identity or a network outage.
                    if code not in ('http_401','http_403'):break
            raise poller.PollError(last)
        directory=root if device.get('legacy_cache') else root/'devices'/str(device['id'])
        directory.mkdir(parents=True,mode=0o750,exist_ok=True)
        result=poller.poll(mode,root=directory,fetch=fetch,token_loader=lambda:'managed',device={'serial':device['serial'],'vdom':device['vdom']})
        if used:
            with database.cursor() as c:
                for item in keys:
                    if item['id'] in used:c.execute('UPDATE fortigate_credentials SET last_used_at=UTC_TIMESTAMP(6) WHERE id=%s AND revision=%s',(item['id'],item['revision']))
        return {'device_id':device['id'],'components':result}
    finally:database.close()

def run(mode):
    load_poller()
    database=connect()
    try:
        with database.cursor() as c:
            c.execute('SELECT * FROM fortigate_connections WHERE enabled=1 OR id IN (SELECT connection_id FROM fortigate_credentials WHERE check_status=\'pending\') ORDER BY is_default DESC,id LIMIT 16');devices=c.fetchall()
            c.execute('SELECT * FROM fortigate_credentials ORDER BY connection_id,priority,id');keys=c.fetchall()
    finally:database.close()
    master=private_file('credential-key',32)
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures={executor.submit(poll_device,d,[k for k in keys if k['connection_id']==d['id']],mode,master):d['id'] for d in devices}
        for future in concurrent.futures.as_completed(futures):
            try:results.append(future.result())
            except Exception:results.append({'device_id':futures[future],'error':'poll_failed'})
    return sorted(results,key=lambda r:r['device_id'])
