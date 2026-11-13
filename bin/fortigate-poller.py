#!/usr/bin/python3
"""Bounded read-only FortiGate polling; exports only allowlisted, non-secret data."""
import argparse
import datetime as dt
import fcntl
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
from urllib.parse import urlencode
compat_spec=importlib.util.spec_from_file_location('fls_fg_compat',Path(__file__).with_name('fortigate_compat.py'))
compatibility=importlib.util.module_from_spec(compat_spec)
compat_spec.loader.exec_module(compatibility)

spec = importlib.util.spec_from_file_location('fls_fg_transport', Path(__file__).with_name('fortigate-api.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
ROOT = Path('/srv/fls-server/metrics/fortigate')
MAX_BODY = 4 * 1024 * 1024
PROFILE_FIELDS = {'virus': 'av-profile', 'webfilter': 'webfilter-profile', 'app-ctrl': 'application-list',
                  'dns': 'dnsfilter-profile', 'ips': 'ips-sensor', 'ssl': 'ssl-ssh-profile'}
POLICY_FIELDS = 'policyid|uuid|name|status|action|utm-status|srcintf|dstintf|srcaddr|dstaddr|service|schedule|ssl-ssh-profile|av-profile|webfilter-profile|dnsfilter-profile|ips-sensor|application-list|profile-type|profile-group|inspection-mode|logtraffic'
ENDPOINTS = {
    'live': {
        'inventory': ('monitor/system/status', ''),
        'resources': ('monitor/system/resource/usage', ''), 'performance': ('monitor/system/performance/status', ''),
        'ipsec': ('monitor/vpn/ipsec', ''), 'ssl_vpn': ('monitor/vpn/ssl', ''),
        'ha': ('cmdb/system/ha', 'mode|group-id|group-name'),
        'sdwan_settings': ('cmdb/system/sdwan', 'status'),
        'sdwan_health': ('monitor/virtual-wan/health-check', ''), 'sdwan_members': ('monitor/virtual-wan/members', '')},
    'config': {
        'inventory': ('monitor/system/status', ''),
        'policies': ('cmdb/firewall/policy', POLICY_FIELDS),
        'profile_groups': ('cmdb/firewall/profile-group', 'name|' + '|'.join(PROFILE_FIELDS.values())),
        'profiles_virus': ('cmdb/antivirus/profile', 'name|comment|feature-set|http|ftp|imap|pop3|smtp|cifs|ssh'),
        'profiles_webfilter': ('cmdb/webfilter/profile', 'name|comment|feature-set|ftgd-wf|web'),
        'profiles_app-ctrl': ('cmdb/application/list', 'name|comment|options|entries|other-application-action|unknown-application-action'),
        'profiles_dns': ('cmdb/dnsfilter/profile', 'name|comment|ftgd-dns|domain-filter|block-botnet|block-action|safe-search'),
        'profiles_ips': ('cmdb/ips/sensor', 'name|comment|entries|block-malicious-url'),
        'profiles_ssl': ('cmdb/firewall/ssl-ssh-profile', 'name|comment|ssl|https|ssh'),
        'url_filters': ('cmdb/webfilter/urlfilter', 'id|name|entries'),
        'categories': ('monitor/webfilter/fortiguard-categories', '')}}


class PollError(Exception):
    pass


def history_projection(key, value):
    """Archive only explicitly selected CMDB fields; strip metadata and credentials."""
    fields=ENDPOINTS['config'][key][1].split('|')
    forbidden={'api-key','api_token','password','passwd','psksecret','private-key','secret','client-secret','token'}
    def clean(item,depth=0):
        if depth>24:raise PollError('history_depth')
        if isinstance(item,dict):return {k:clean(v,depth+1) for k,v in item.items() if k not in forbidden and not k.startswith('q_')}
        if isinstance(item,list):return [clean(v,depth+1) for v in item]
        return item
    return [clean({k:r[k] for k in fields if k in r}) for r in rows(value)]


def history_module():
    spec=importlib.util.spec_from_file_location('fls_config_history',Path(__file__).with_name('fortigate_history.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def text(value, limit=512):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ''
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', str(value))[:limit]


def number(value, maximum=10**18):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
        return None
    return value


def rows(value):
    if not isinstance(value, list) or len(value) > 20000 or any(not isinstance(x, dict) for x in value):
        raise PollError('schema')
    return value


def names(value):
    if not isinstance(value, list):
        return []
    return [text(x.get('name', x.get('id', '')) if isinstance(x, dict) else x) for x in value[:500]]


def user_identity(row):
    for field in ['user', 'eapuser', 'xauthuser', 'user_name', 'username']:
        value = text(row.get(field)).strip()
        if value.lower() in ('', 'n/a', 'unknown', 'none', '-') or re.search(r'\bCN\s*=', value):
            continue
        try:
            ipaddress.ip_address(value)
            continue
        except ValueError:
            return value
    return ''


def credential():
    folder = os.environ.get('CREDENTIALS_DIRECTORY')
    path = Path(folder) / 'fortigate-api.json' if folder else transport.CONFIG
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'r') as stream:
            info = os.fstat(stream.fileno())
            # systemd exposes credentials as 0440 inside a service-private mount;
            # the original /etc/fls file still requires root-only permissions.
            forbidden = 0o037 if folder else 0o077
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & forbidden or info.st_size > 16384:
                raise PollError('credential')
            data = json.loads(stream.read(16385))
        expected = {'schema': 1, 'hostname': transport.HOST, 'connect_ip': transport.ADDRESS, 'source_ip': transport.SOURCE,
                    'port': transport.PORT, 'vdom': 'root', 'expected_serial': transport.SERIAL}
        if not isinstance(data, dict) or any(data.get(k) != v for k, v in expected.items()):
            raise PollError('credential')
        return transport.validate_token(data.get('api_token'))
    except Exception:
        raise PollError('credential') from None


def request(key, mode, token):
    # No caller-supplied path, query, HTTP method, destination, or TLS bypass.
    path, fields = ENDPOINTS[mode][key]
    params = {'vdom': 'root'}
    if fields:
        params['format'] = fields
    connection = transport.LocalHTTPS()
    connection.timeout = 4
    try:
        connection.request('GET', '/api/v2/' + path + '?' + urlencode(params),
                           headers={'Accept': 'application/json', 'Authorization': 'Bearer ' + token, 'User-Agent': 'FLS-readonly-poller/1'})
        response = connection.getresponse()
        if response.status != 200:
            raise PollError('http_' + str(response.status))
        if response.headers.get_content_type() != 'application/json':
            raise PollError('json')
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise PollError('response_limit')
        data = json.loads(body)
        if not isinstance(data, dict) or data.get('status') != 'success':
            raise PollError('api_status')
        if data.get('serial') != transport.SERIAL or data.get('vdom') != 'root':
            raise PollError('device_scope')
        if data.get('limit_reached'):
            raise PollError('incomplete_collection')
        if key=='inventory':
            try:return compatibility.inventory(data)
            except ValueError:raise PollError('inventory_schema') from None
        return data['results']
    except PollError:
        raise
    except ssl.SSLCertVerificationError:
        raise PollError('tls') from None
    except Exception:
        raise PollError('connection_or_json') from None
    finally:
        connection.close()


def normalize(key, value):
    if key == 'inventory':
        if not isinstance(value,dict) or not value.get('model') and not value.get('model_number'):raise PollError('inventory_schema')
        return compatibility.inventory({'results':value,'version':value.get('version'),'build':value.get('build'),'serial':value.get('serial'),'vdom':value.get('vdom')})
    if key in ('ha','sdwan_settings'):
        if isinstance(value,list) and len(value)==1:value=value[0]
        if not isinstance(value,dict):raise PollError('schema')
        if key=='ha':
            if value.get('mode') not in ('standalone','a-a','a-p'):raise PollError('schema')
            return {'mode':value['mode'],'group_id':compatibility.integer(value.get('group-id'),1023),'group_name':compatibility.safe_string(value.get('group-name'))}
        if value.get('status') not in ('enable','disable'):raise PollError('schema')
        return {'status':value['status']}
    if key == 'resources':
        if not isinstance(value, dict) or not all(k in value for k in ['cpu', 'mem', 'session']):
            raise PollError('schema')
        result = {}
        for source, target in [('cpu', 'cpu_percent'), ('mem', 'memory_percent'), ('session', 'sessions_ipv4'),
                               ('session6', 'sessions_ipv6'), ('setuprate', 'session_setup_rate')]:
            records = value.get(source)
            result[target] = number(records[0].get('current'), 100 if 'percent' in target else 10**12) if isinstance(records, list) and records and isinstance(records[0], dict) else None
        return result
    if key == 'performance':
        if not isinstance(value, dict) or not isinstance(value.get('mem'), dict):
            raise PollError('schema')
        return {k: number(value['mem'].get(k)) for k in ['total', 'used', 'free', 'freeable']}
    if key == 'ipsec':
        result = []
        for row in rows(value):
            proxies = rows(row.get('proxyid', []))
            up = sum(p.get('status') == 'up' for p in proxies)
            remote = text(row.get('rgwy'))
            template = remote in ('', '0.0.0.0', '::') and not proxies and not row.get('parent')
            state = 'template' if template else 'up' if up else 'ike_only' if number(row.get('connection_count')) else 'down'
            result.append({'name': text(row.get('name')), 'parent': text(row.get('parent')), 'state': state,
                           'username': user_identity(row), 'remote_ip': remote, 'assigned_ip': text(row.get('tun_id')) if row.get('type') == 'dialup' else '',
                           'uptime_seconds': number(row.get('creation_time'), 10**9), 'auth_type': text(row.get('auth_type')),
                           'incoming_bytes': number(row.get('incoming_bytes')), 'outgoing_bytes': number(row.get('outgoing_bytes')),
                           'phase2_up': up, 'type': 'ipsec'})
        return result
    if key == 'ssl_vpn':
        if isinstance(value, dict):
            value = value.get('tunnels', value.get('users'))
        result = []
        for row in rows(value):
            user = user_identity(row)
            remote = text(row.get('remote_host', row.get('from', row.get('rmtip', row.get('remote_ip', '')))))
            if not user or not remote:
                raise PollError('ssl_schema')
            result.append({'name': 'SSL VPN', 'username': user, 'remote_ip': remote,
                           'assigned_ip': text(row.get('tunnel_ip', row.get('tunip', ''))), 'type': 'ssl', 'state': 'up',
                           'uptime_seconds': number(row.get('duration')), 'incoming_bytes': number(row.get('in_bytes')),
                           'outgoing_bytes': number(row.get('out_bytes'))})
        return result
    if key == 'sdwan_members':
        return [{'interface': text(row.get('interface')), 'member_id': number(row.get('seq_num')),
                 'state': text(row.get('link')) if row.get('link') in ('up', 'down') else 'unknown',
                 'sessions': number(row.get('session')), 'tx_bps': number(row.get('tx_bandwidth')),
                 'rx_bps': number(row.get('rx_bandwidth')), 'tx_bytes': number(row.get('tx_bytes')),
                 'rx_bytes': number(row.get('rx_bytes')), 'gateway': text(row.get('ipv4_gateway'))} for row in rows(value)]
    if key == 'sdwan_health':
        if not isinstance(value, dict):
            raise PollError('schema')
        result = []
        for check, members in value.items():
            if not isinstance(members, dict):
                raise PollError('schema')
            for interface, row in members.items():
                if not isinstance(row, dict):
                    raise PollError('schema')
                result.append({'check': text(check), 'interface': text(interface),
                               'state': text(row.get('status')) if row.get('status') in ('up', 'down') else 'unknown',
                               'latency_ms': number(row.get('latency')), 'jitter_ms': number(row.get('jitter')),
                               'packet_loss_percent': number(row.get('packet_loss'), 100),
                               'sla_targets_met': [n for n in row.get('sla_targets_met', []) if isinstance(n, int) and n >= 0][:100]})
        return result
    if key == 'categories':
        return {str(row['id']): text(row.get('name')) for row in rows(value) if isinstance(row.get('id'), int)}
    if key == 'url_filters':
        result = []
        for row in rows(value):
            entries = rows(row.get('entries', []))
            result.append({'id': number(row.get('id')), 'name': text(row.get('name')), 'rule_count': len(entries),
                           'rules_truncated': len(entries) > 500,
                           'rules': [{k: text(r.get(k)) for k in ['url', 'type', 'action', 'status']} for r in entries[:500]]})
        return result
    if key == 'profile_groups':
        return [{'name': text(row.get('name')), 'profiles': {kind: text(row.get(field)) for kind, field in PROFILE_FIELDS.items()}} for row in rows(value)]
    if key == 'policies':
        result = []
        for row in rows(value):
            if not isinstance(row.get('policyid'), int) or not re.fullmatch(r'[a-fA-F0-9-]{36}', str(row.get('uuid', ''))):
                raise PollError('policy_identity')
            result.append({**{k: text(row.get(k)) for k in ['name', 'status', 'action', 'schedule', 'inspection-mode', 'profile-type', 'profile-group', 'utm-status', 'logtraffic']},
                           'policyid': row['policyid'], 'uuid': row['uuid'].lower(),
                           **{k: names(row.get(k)) for k in ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']},
                           'profiles': {kind: text(row.get(field)) for kind, field in PROFILE_FIELDS.items()}})
        return result
    if key.startswith('profiles_'):
        return [profile(key[9:], row) for row in rows(value)]
    raise PollError('unknown_component')


def profile(kind, row):
    result = {'kind': kind, 'name': text(row.get('name')), 'comment': text(row.get('comment')), 'settings': [], 'rules': []}
    def settings(prefix, source, keys):
        if not isinstance(source, dict):
            return
        for key in keys:
            if isinstance(source.get(key), (str, int, float)):
                result['settings'].append({'label': prefix + key, 'value': text(source[key])})
    settings('', row, ['feature-set', 'options', 'block-botnet', 'block-action', 'safe-search', 'block-malicious-url',
                       'other-application-action', 'unknown-application-action'])
    if kind in ('webfilter', 'dns'):
        source = row.get('ftgd-wf' if kind == 'webfilter' else 'ftgd-dns', {})
        settings('FortiGuard · ', source, ['options'])
        for r in rows(source.get('filters', [])):
            result['rules'].append({'id': number(r.get('id')), 'category': number(r.get('category')),
                                    'match': 'Kategori #' + text(r.get('category')), 'action': text(r.get('action')) or 'belirtilmemiş', 'log': text(r.get('log'))})
        settings('Web · ', row.get('web', {}), ['urlfilter-table', 'blocklist', 'allowlist', 'safe-search'])
        if kind == 'webfilter':
            result['url_filter_table'] = number(row.get('web', {}).get('urlfilter-table'))
        settings('Domain · ', row.get('domain-filter', {}), ['domain-filter-table'])
    elif kind in ('app-ctrl', 'ips'):
        fields = ['category', 'application', 'risk', 'protocols', 'vendor', 'technology', 'behavior'] if kind == 'app-ctrl' else ['rule', 'location', 'severity', 'protocol', 'os', 'application', 'cve', 'status', 'default-action']
        for r in rows(row.get('entries', [])):
            parts = []
            for key in fields:
                value = ', '.join(names(r[key])) if isinstance(r.get(key), list) else text(r.get(key))
                if value:
                    parts.append(key + ': ' + value)
            result['rules'].append({'id': number(r.get('id')), 'match': text(' · '.join(parts), 2000) or 'Genel eşleşme',
                                    'action': text(r.get('action')) or 'belirtilmemiş', 'log': text(r.get('log'))})
    elif kind == 'virus':
        for protocol in ['http', 'ftp', 'imap', 'pop3', 'smtp', 'cifs', 'ssh']:
            source = row.get(protocol, {})
            if not isinstance(source, dict):
                continue
            result['rules'].append({'id': None, 'match': protocol.upper(), 'action': text(source.get('av-scan')) or 'belirtilmemiş',
                                    'log': '', 'details': ' · '.join(key + ': ' + text(source.get(key)) for key in ['quarantine', 'outbreak-prevention', 'fortisandbox', 'content-disarm'] if key in source)})
    elif kind == 'ssl':
        for protocol in ['ssl', 'https', 'ssh']:
            source = row.get(protocol, {})
            settings(protocol.upper() + ' · ', source, ['status', 'inspect-all', 'client-certificate', 'unsupported-ssl-version',
                     'unsupported-ssl-cipher', 'unsupported-ssl-negotiation', 'expired-server-cert', 'revoked-server-cert',
                     'untrusted-server-cert', 'cert-validation-timeout', 'cert-validation-failure', 'sni-server-cert-check',
                     'cert-probe-failure', 'encrypted-client-hello', 'min-allowed-ssl-version', 'quic'])
    result['rule_count'] = len(result['rules'])
    result['rules'] = result['rules'][:500]
    result['rules_truncated'] = result['rule_count'] > 500
    return result


def atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.fg-cache-', dir=path.parent)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def poll(mode, root=ROOT, fetch=request, token_loader=credential, device=None):
    identity=device or {'serial':transport.SERIAL,'vdom':'root'}
    root.mkdir(parents=True, exist_ok=True)
    with (root / ('.' + mode + '.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = root / (mode + '.json')
        try:
            previous = json.loads(path.read_text())
            if previous.get('schema') != 1 or previous.get('device') != identity:
                previous = {}
        except (OSError, ValueError, AttributeError):
            previous = {}
        components = previous.get('components', {})
        try:
            token = token_loader()
        except PollError:
            token = None
        for key in ENDPOINTS[mode]:
            attempted = stamp()
            try:
                if token is None:
                    raise PollError('credential')
                raw = fetch(key, mode, token)
                if key=='inventory' and (not isinstance(raw,dict) or raw.get('serial')!=identity['serial'] or raw.get('vdom')!=identity['vdom']):raise PollError('device_scope')
                value = normalize(key, raw)
                candidate={'observed_at':stamp(),'attempted_at':attempted,'error':None,'data':value,'availability':compatibility.availability(key,None)}
                if mode=='config' and key not in ('categories','inventory'):candidate['history_data']=history_projection(key,raw)
                if len(json.dumps({**components,key:candidate},ensure_ascii=False,separators=(',',':'),allow_nan=False).encode())>12*1024*1024:raise PollError('cache_limit')
                components[key]=candidate
            except Exception as error:
                old = components.get(key, {})
                code=str(error) if isinstance(error,PollError) else 'schema'
                components[key] = {**old, 'attempted_at': attempted, 'error':code, 'availability':compatibility.availability(key,code)}
        # Capabilities are tied to this poll's identity/build, never an older model guess.
        inv=components.get('inventory',{});identity_verified=not inv.get('error') and bool(inv.get('data')) and inv['data'].get('version') is not None and inv['data'].get('build') is not None
        disabled=components.get('sdwan_settings',{});sdwan_disabled=not disabled.get('error') and disabled.get('data',{}).get('status')=='disable'
        for key,component in components.items():
            component['availability']=compatibility.availability(key,component.get('error'),identity_verified,sdwan_disabled and key in ('sdwan_health','sdwan_members','sdwan_settings'))
            component['availability']['checked_at']=component.get('attempted_at')
            if identity_verified:component['capability_identity']={k:inv['data'].get(k) for k in ('serial','vdom','model','version','build')}
            else:component.pop('capability_identity',None)
        snapshot = {'schema': 1, 'device': identity, 'updated_at': stamp(), 'components': components}
        if mode=='config':history_module().enqueue(snapshot,root,device=identity)
        # Public cache retains only the UI projection; complete safe fields live in history.
        public={**snapshot,'components':{k:{name:value for name,value in v.items() if name!='history_data'} for k,v in components.items()}}
        atomic(path, public)
        if mode=='config':history_module().drain(root,device=identity)
        if mode == 'live':
            # Compact local chart points, no usernames or configuration history.
            resource = components.get('resources', {})
            sample = {'at': snapshot['updated_at'], **{k: resource.get('data', {}).get(k) if not resource.get('error') else None for k in ['cpu_percent', 'memory_percent']}}
            daily = root / (sample['at'][:10] + '.jsonl')
            with daily.open('a+b') as stream:
                stream.seek(0, os.SEEK_END)
                if stream.tell():
                    stream.seek(-1, os.SEEK_END)
                    if stream.read(1) != b'\n':
                        stream.write(b'\n')
                stream.write((json.dumps(sample, separators=(',', ':')) + '\n').encode())
            cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=90)).date().isoformat()
            for file in root.glob('????-??-??.jsonl'):
                if re.fullmatch(r'\d{4}-\d{2}-\d{2}\.jsonl', file.name) and file.stem < cutoff:
                    file.unlink()
        return {key: value.get('error') for key, value in components.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['live', 'config'])
    args = parser.parse_args()
    try:
        registry_path=Path('/etc/fls/fortigate-registry.json')
        credential_dir=os.environ.get('CREDENTIALS_DIRECTORY')
        if credential_dir:registry_path=Path(credential_dir)/'fortigate-registry.json'
        if registry_path.exists():
            import fortigate_registry
            result=fortigate_registry.run(args.mode)
        else:result = poll(args.mode)
        # Never output API payloads or exception strings; only fixed component/error codes.
        print(json.dumps({'mode': args.mode, 'components': result}))
    except Exception:
        parser.exit(1, 'FLS FortiGate cache update failed.\n')


if __name__ == '__main__':
    main()
