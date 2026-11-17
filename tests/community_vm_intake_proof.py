#!/usr/bin/env python3
"""Only on the identified new test VM: synthetic TCP intake, read-only DB/raw proof.
No SQL writes, service/config changes or reboot. send-* adds test logs AND indices.
Root-only /var/tmp state survives reboot; an attempted send is never repeated.
"""
import argparse, collections, datetime as dt, hashlib, ipaddress, json, os, re, secrets, socket, stat, subprocess, time
from pathlib import Path

RAW = Path('/srv/fls-server/raw')
def need(value, code):
    if not value: raise ValueError(code)
def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def read(path, limit=16000000):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        info=os.fstat(f.fileno()); need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022,'unsafe_root_input'); data=f.read(limit+1)
        need(len(data)<=limit,'read_limit'); return data
def save(name, value):
    with os.fdopen(os.open(a.state/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as f:
        os.fchmod(f.fileno(),0o600); f.write(canonical(value)+b'\n'); f.flush(); os.fsync(f.fileno())
def utc(value): return dt.datetime.fromisoformat(value).astimezone(dt.timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S.%f')
def guard(s):
    need(sha(read('/sys/class/dmi/id/product_uuid')).startswith(s['dmi_prefix']),'wrong_vm_dmi')
    receipt=json.loads(read('/etc/fls/release-state.json'))
    need(receipt.get('installation_id')==s['installation_id'] and receipt.get('release_sha256')==s['release_manifest_sha256']
         and receipt.get('version')=='0.76.0' and receipt.get('edition')=='community' and receipt.get('schema_version')==47,'wrong_release_receipt')
    need(sha(read('/var/www/fls/deploy/release-files.json'))==s['release_manifest_sha256'],'installed_inventory_mismatch')
    need(sha(read('/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd'))==s['collector_sha256'],'collector_mismatch')
    ip=subprocess.run(['/usr/sbin/ip','-j','-4','address','show'],capture_output=True,timeout=10)
    need(ip.returncode==0 and len(ip.stdout)<1000000 and any(r.get('local')==s['target'] for i in json.loads(ip.stdout) for r in i.get('addr_info',[])),'receiver_not_assigned_to_local_nic')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock: sock.bind((s['target'],0))
    return read('/proc/sys/kernel/random/boot_id').decode().strip()
def active(s):
    table=json.loads(read('/etc/fortigate/fls-senders.json'))['table']
    need(any(r.get('index')==s['target'] and r.get('value')=='allow' for r in table),'use_ui_source_grant')
    r=subprocess.run(['/usr/bin/systemctl','is-active','fortigate-collector.service','fls-indexer.service'],capture_output=True,timeout=10)
    need(r.returncode==0 and r.stdout.splitlines()==[b'active',b'active'],'collector_or_indexer_inactive')
    r=subprocess.run(['/usr/bin/systemctl','show','--property=MainPID','--value','fortigate-collector.service'],capture_output=True,timeout=10)
    need(r.returncode==0 and re.fullmatch(rb'[1-9][0-9]*\n?',r.stdout),'collector_pid_unknown')
    running=Path('/proc')/r.stdout.decode().strip()/'exe'; installed=Path('/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd')
    need(running.resolve(strict=True)==installed and (running.stat().st_dev,running.stat().st_ino)==(installed.stat().st_dev,installed.stat().st_ino),'running_collector_differs_from_verified_binary')
def records(s):
    result=[]
    for i in range(192):
        ns=s['base_ns']+1000*i; when=dt.datetime.fromtimestamp(ns//10**9,dt.timezone.utc).replace(microsecond=ns%10**9//1000)
        f=dict(date=when.strftime('%Y-%m-%d'),time=when.strftime('%H:%M:%S'),tz='+0000',eventtime=str(ns),
               devname='FLS-RC9-SYNTHETIC',devid=s['serial'],vd='root',type='traffic',subtype='forward',action='accept',
               level='notice',logid='0000000013',srcip='192.0.2.81',dstip='198.51.100.81',dstport='443',proto='6',
               policyid='777331',sessionid=str(int(s['token'][:10],16)*256+i),flstesttoken=s['token'],flstestseq=str(i),
               flstestphase='before' if i<96 else 'after',msg=f'FLS RC9 İstanbul "tırnak" \\ yol id={i}')
        raw='<189>'+' '.join(k+'='+json.dumps(v,ensure_ascii=False) for k,v in f.items())
        result.append(dict(number=i,raw=raw,fields=f,raw_sha256=sha(raw.encode()),event_at=utc(when.isoformat())))
    return result
def database(s):
    need(re.fullmatch(r'RC9TEST_[A-F0-9]{16}',s['serial']),'invalid_series')
    cols='type subtype action policyid srcip dstip dstport devid vd sessionid'.split()
    pairs=','.join("'%s',CAST(e.%s AS CHAR)"%(c,c) for c in cols)
    query="""SET SESSION max_statement_time=5; START TRANSACTION READ ONLY;
SELECT JSON_OBJECT('device',d.id,'enabled',d.enabled,'default',d.is_default,'vd',d.vdom,'peer',s.peer_ip,'source',s.source_ip,'receiver',s.receiver_ip,'admitted',s.receiver_admitted,'keys',(SELECT COUNT(*) FROM fortigate_credentials c WHERE c.connection_id=d.id)) FROM fortigate_connections d LEFT JOIN fortigate_setup s ON s.connection_id=d.id WHERE BINARY d.serial=BINARY 'SERIAL';
SELECT JSON_OBJECT('id',CAST(e.id AS CHAR),'file',s.name,'offset',e.byte_offset,'length',e.byte_length,'line',e.line_number,'sha',LOWER(HEX(e.raw_sha256)),'fields',HEX(e.fields),'inode',s.inode,'checkpoint',s.byte_offset,'invalid',s.invalid_rows,'event_at',DATE_FORMAT(e.event_at,'%Y-%m-%d %H:%i:%s.%f'),'received_at',DATE_FORMAT(e.received_at,'%Y-%m-%d %H:%i:%s.%f'),'outcome',e.outcome,'reason',e.reason_code,'rating',e.rating_error,PAIRS) FROM events e JOIN source_files s ON s.id=e.file_id WHERE BINARY e.devid=BINARY 'SERIAL' ORDER BY e.id LIMIT 1025;
COMMIT;""".replace('SERIAL',s['serial']).replace('PAIRS',pairs)
    env={k:v for k,v in os.environ.items() if not k.startswith(('MYSQL','MARIADB'))}
    r=subprocess.run(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--database=fls','--batch','--raw','--skip-column-names','--default-character-set=utf8mb4'],input=query.encode(),capture_output=True,timeout=20,env=env)
    need(r.returncode==0 and len(r.stdout)<8000000,'read_only_socket_query_failed')
    rows=[json.loads(line) for line in r.stdout.splitlines()]; devices=[r for r in rows if 'device' in r]
    need(len(devices)==1,'create_one_separate_dummy_device'); d=devices[0]
    need(d['enabled']==d['keys']==0 and not d['default'] and d['vd']=='root' and d['admitted']==1
         and d['peer']==d['source']==d['receiver']==s['target'],'dummy_device_or_source_grant_incorrect')
    return d['device'],[r for r in rows if 'id' in r],cols
def raw_rows(s):
    result=[]; budget=0; token=s['token'].encode()
    for path in sorted(RAW.glob('*.jsonl')):
        need(re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',path.name),'unexpected_raw_name')
        with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
            info=os.fstat(f.fileno()); need(stat.S_ISREG(info.st_mode),'raw_not_regular'); line_no=0
            while True:
                offset=f.tell(); line=f.readline(4000001)
                if not line: break
                budget+=len(line); line_no+=1; need(budget<=128*1024*1024,'fresh_vm_scan_limit')
                if token not in line: continue
                if not line.endswith(b'\n'): break
                e=json.loads(line); need(str(e.get('schema_version'))=='1' and e.get('sender_ip')==s['target'] and e.get('transport')=='tcp','envelope_mismatch')
                result.append(dict(file=path.name,offset=offset,length=len(line),line=line_no,inode=info.st_ino,env=e,sha=sha(e['raw'].encode())))
    return result
def check(s, boot):
    expected=records(s)[:192 if a.command=='check-after' else 96]; wanted={r['raw_sha256']:r for r in expected}
    before=json.loads(read(a.state/'check-before.json')) if a.command!='check-before' else None
    if before: need(before['ok'] and before['series_sha256']==sha(canonical(s)) and before['boot_id']!=boot,'new_boot_and_matching_before_proof_required')
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        active(s); device,events,cols=database(s); raw=raw_rows(s)
        for hashes in (collections.Counter(r['sha'] for r in raw),collections.Counter(r['sha'] for r in events)):
            need(set(hashes)<=set(wanted) and all(n==1 for n in hashes.values()),'unexpected_corrupt_or_duplicate_series_record')
        if len(raw)!=len(expected) or len(events)!=len(expected): time.sleep(2); continue
        positions={(r['file'],r['offset']):r for r in raw}; matched=[]
        for e in events:
            r=positions.get((e['file'],e['offset'])); w=wanted[e['sha']]
            need(r and r['env']['raw']==w['raw'] and r['sha']==e['sha'] and all(e[k]==r[k] for k in ('length','line','inode'))
                 and e['checkpoint']>=e['offset']+e['length'],'raw_bytes_offsets_checkpoint_mismatch')
            need(json.loads(bytes.fromhex(e['fields']))==w['fields'] and all(e[k]==w['fields'][k] for k in cols)
                 and e['outcome']==e['reason']=='observed' and e['rating']==0 and e['event_at']==w['event_at']
                 and e['received_at']==utc(r['env']['received_at']),'index_fields_or_timestamp_mismatch')
            matched.append(dict(number=w['number'],id=e['id'],file=e['file'],offset=e['offset'],length=e['length'],sha=e['sha']))
        matched.sort(key=lambda r:r['number']); need(len({r['id'] for r in matched})==len(expected),'duplicate_index_id')
        if before: need(matched[:96]==before['matched'],'pre_reboot_records_changed_or_reindexed')
        return dict(ok=True,stage=a.command,series_sha256=sha(canonical(s)),serial=s['serial'],device_id=device,boot_id=boot,
                    exact_raw_and_index_records=len(matched),missing=0,duplicates=0,new_boot_observed=bool(before),
                    full_raw_and_parsed_fields_verified=True,source_order_guaranteed=False,matched=matched,
                    sql_write_queries_executed=False,services_changed=False,reboot_executed=False)
    raise ValueError('timeout_waiting_for_complete_raw_and_index_series')
def main(argv=None):
    global a
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['init','send-before','check-before','check-reboot','send-after','check-after'])
    p.add_argument('--state',type=Path,default=Path('/var/tmp/fls-rc9-intake'),help='Private new state directory directly under /var/tmp.')
    for name in ('target','dmi-prefix','release-manifest-sha256','collector-sha256','installation-id'):
        p.add_argument('--'+name,help='Required for init; retained in root-owned state. '+('Local nonloopback IPv4 receiver AND sender.' if name=='target' else 'Installed inventory bytes SHA256 (receipt release_sha256).' if name=='release-manifest-sha256' else 'Expected target identity.'))
    a=p.parse_args(argv)
    try:
        need(os.geteuid()==0,'run_only_as_root_on_new_test_vm')
        need(a.state.is_absolute() and a.state.parent==Path('/var/tmp') and re.fullmatch(r'fls-rc9-intake[-A-Za-z0-9_]*',a.state.name),'use_private_var_tmp_state')
        if a.command=='init':
            s={k:getattr(a,k) for k in ('target','dmi_prefix','release_manifest_sha256','collector_sha256','installation_id')}
            need(all(isinstance(v,str) and v for v in s.values()) and re.fullmatch('[a-f0-9]{12,64}',s['dmi_prefix'])
                 and all(re.fullmatch('[a-f0-9]{64}',s[k]) for k in ('release_manifest_sha256','collector_sha256')),'expected_identity_arguments_required')
            ip=ipaddress.IPv4Address(s['target']); need(not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local),'target_must_be_local_nonloopback_ipv4')
            guard(s); a.state.mkdir(mode=0o700); a.state.chmod(0o700); s.update(token=secrets.token_hex(8),base_ns=time.time_ns())
            s['serial']='RC9TEST_'+s['token'].upper(); save('series.json',s)
            print(json.dumps(dict(ok=True,state=str(a.state),serial=s['serial'],source_and_receiver_ip=s['target'],vdom='root',records_per_phase=96)))
        else:
            info=a.state.lstat(); need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,'unsafe_root_state')
            info=(a.state/'series.json').lstat(); need(info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,'unsafe_root_series')
            s=json.loads(read(a.state/'series.json')); boot=guard(s)
            if a.command.startswith('send-'):
                active(s); database(s)
                if a.command=='send-after': need(json.loads(read(a.state/'check-reboot.json'))['boot_id']==boot,'check_reboot_before_send_after')
                save(a.command+'-attempt.json',dict(boot_id=boot,state='send_attempt_started_never_repeat_ambiguously'))
                part=records(s)[:96] if a.command=='send-before' else records(s)[96:]
                wire=b''.join(str(len(r['raw'].encode())).encode()+b' '+r['raw'].encode() for r in part)
                with socket.create_connection((s['target'],5514),timeout=15,source_address=(s['target'],0)) as sock:
                    sock.sendall(wire); sock.shutdown(socket.SHUT_WR)
                print(json.dumps(dict(ok=True,sendall_returned=True,records=96,wire_bytes=len(wire),durable_application_acceptance_proven=False)))
            else:
                proof=check(s,boot); save(a.command+'.json',proof); print(json.dumps({k:v for k,v in proof.items() if k!='matched'}))
        return 0
    except Exception as error:
        print(json.dumps(dict(ok=False,error_code=str(error) if isinstance(error,ValueError) else type(error).__name__)))
        return 1

if __name__=='__main__': raise SystemExit(main())
