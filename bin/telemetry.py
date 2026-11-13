#!/usr/bin/python3
"""Bounded, independent host samples; never changes collector, archives or the DB."""
import argparse,datetime as dt,fcntl,json,os,re,subprocess,tempfile,time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from fls_capacity import capacity_sample, update_daily
UTC=dt.timezone.utc
BACKLOG_RULE={'minimum_pending':1000,'minimum_seconds':300,'maximum_gap_seconds':95,'stale_after_seconds':120}

def backlog_settings_valid(value):
    if not isinstance(value,dict):return None
    pending=value.get('minimum_pending');seconds=value.get('minimum_seconds');revision=value.get('revision')
    if type(pending) is not int or not 1<=pending<=100000000 or type(seconds) is not int or not 60<=seconds<=86400 or seconds%60 or type(revision) is not int or revision<1:return None
    return {key:value.get(key) for key in ('minimum_pending','minimum_seconds','revision','updated_at')}

def backlog_time(value):
    try:
        parsed=dt.datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except (TypeError,ValueError):return None

def summary_backlog(previous,snapshot,at,settings=None):
    """Sampled sustained backlog, latched until a verified zero; no DB writes."""
    previous=previous if isinstance(previous,dict) else {}
    if previous.get('schema')!=1:previous={}
    settings=backlog_settings_valid(settings);rule=dict(BACKLOG_RULE)
    if settings:rule.update({key:settings[key] for key in ('minimum_pending','minimum_seconds')})
    snapshot=snapshot if isinstance(snapshot,dict) else {};pending=snapshot.get('pending_records');checked=backlog_time(snapshot.get('checked_at'))
    valid=type(pending) is int and pending>=0 and snapshot.get('status') in ('caught_up','processing','backfilling','stale') and checked is not None and abs((at-checked).total_seconds())<=10
    # A changed rule starts a new observation period on the next valid count.
    # An unknown reading must never erase an existing confirmed warning.
    if valid and previous.get('rule')!=rule:previous={}
    hold=not valid and previous.get('active') is True
    state={'schema':1,'rule':previous.get('rule') if hold else rule,'settings_revision':previous.get('settings_revision') if hold else settings['revision'] if settings else 0,'at':at.isoformat(),'status':'unknown','active':previous.get('active') is True,
           'pending_records':None,'candidate_since':None,'started_at':None,'activated_at':None,
           'last_confirmed_at':None,'last_pending_records':None,'peak_pending':None,'observed_seconds':0}
    if state['active']:
        for key in ('started_at','activated_at','last_confirmed_at','last_pending_records','peak_pending','observed_seconds'):state[key]=previous.get(key)
    if not valid:return state
    state['pending_records']=pending
    state['last_pending_records']=pending
    old_peak=previous.get('peak_pending');old_peak=old_peak if type(old_peak) is int and old_peak>=0 else 0
    if pending==0:return {**state,'status':'clear','active':False,'started_at':None,'activated_at':None,'last_confirmed_at':None,'peak_pending':None,'observed_seconds':0}
    if state['active']:
        state.update(status='active',last_confirmed_at=at.isoformat(),peak_pending=max(old_peak,pending))
        return state
    state['status']='clear'
    if pending<rule['minimum_pending']:return state
    last=backlog_time(previous.get('at'));since=backlog_time(previous.get('candidate_since'))
    continuous=last is not None and since is not None and 0<(at-last).total_seconds()<=rule['maximum_gap_seconds'] and since<=last
    if not continuous:since=at
    seconds=max(0,int((at-since).total_seconds()));peak=max(old_peak,pending) if continuous else pending
    state.update(status='watching',candidate_since=since.isoformat(),started_at=since.isoformat(),peak_pending=peak,observed_seconds=seconds,last_confirmed_at=at.isoformat())
    if seconds>=rule['minimum_seconds']:state.update(status='active',active=True,activated_at=at.isoformat(),candidate_since=None)
    return state

def memory(text):
    fields={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in text.splitlines() if ':' in line)}
    total=fields.get('MemTotal');available=fields.get('MemAvailable')
    return {'total_bytes':total,'available_bytes':available,'used_bytes':total-available if total is not None and available is not None else None,
            'used_percent':round(100*(total-available)/total,2) if total and available is not None else None,
            'cache_bytes':max(0,fields.get('Cached',0)+fields.get('SReclaimable',0)-fields.get('Shmem',0)),
            'swap_used_bytes':fields.get('SwapTotal',0)-fields.get('SwapFree',0),'dirty_bytes':fields.get('Dirty',0)}

def disk_counters(text):
    result={}
    for line in text.splitlines():
        f=line.split()
        if len(f)>=14 and __import__('re').fullmatch(r'(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)',f[2]):result[f[2]]=[int(v) for v in f[3:]]
    return result

def disk_rates(current,previous,seconds):
    rows=[]
    for name,values in current.items():
        before=previous.get(name);valid=before and seconds and 0<seconds<=180 and len(before)==len(values)
        delta=[v-b for v,b in zip(values,before)] if valid else []
        valid=bool(valid and all(delta[i]>=0 for i in [0,3,4,7,9,10]))
        reads,writes=(delta[0],delta[4]) if valid else (0,0)
        rows.append({'device':name,'read_await_ms':round(delta[3]/reads,3) if valid and reads else None,
            'write_await_ms':round(delta[7]/writes,3) if valid and writes else None,
            'util_percent':round(min(100,delta[9]/(seconds*10)),2) if valid else None,
            'average_queue':round(delta[10]/(seconds*1000),3) if valid else None,
            'reads_s':round(reads/seconds,3) if valid else None,'writes_s':round(writes/seconds,3) if valid else None})
    return rows

def tail(path,limit=131072):
    with path.open('rb') as f:
        start=max(0,os.fstat(f.fileno()).st_size-limit);f.seek(start);data=f.read(limit)
    return data.splitlines()[1:] if start else data.splitlines()

def archive_state(root,now):
    paths=sorted((root/'raw').glob('*.jsonl'))
    if not paths:return {'last_received_at':None,'last_record_age_seconds':None,'write_lag_seconds':None}
    path=paths[-1]
    for _ in range(3):
        before=path.stat();lines=tail(path,2*1024*1024)
        with path.open('rb') as f:
            if before.st_size:f.seek(-1,os.SEEK_END)
            complete=f.read(1)==b'\n'
        after=path.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):continue
        if not lines or not complete:break
        try:
            row=json.loads(lines[-1]);received=dt.datetime.fromisoformat(row['received_at']).timestamp()
            # Last-file mtime is a write-time proxy, not fsync completion or last-record age.
            difference=after.st_mtime-received
            return {'last_received_at':row['received_at'],'last_record_age_seconds':round(max(0,now-received),3),
                    'write_lag_seconds':round(max(0,difference),3) if difference>=-1 else None}
        except (ValueError,KeyError,TypeError):break
    return {'last_received_at':None,'last_record_age_seconds':None,'write_lag_seconds':None}

def queue_state(root):
    result={'depth':None,'stats_at':None,'enqueued_total':None,'processed_total':None,'discarded_total':None,'failed_total':None,'suspended':None}
    qi=root/'queue/fg-receive.qi'
    if qi.exists():
        with qi.open() as stream:match=re.search(r'\+iQueueSize:2:\d+:(\d+):',stream.read(65536))
        if match:result['depth']=int(match[1])
    paths=sorted((root/'metrics').glob('*-rsyslog.jsonl'))
    latest={}
    if paths:
        for line in tail(paths[-1]):
            try:
                offset=line.index(b'{');r=json.loads(line[offset:])
                if r.get('name') in ('fortigate','fg_raw_archive'):latest[r['name']]=(line[:offset].decode().split(' ',1)[0],r)
            except (ValueError,KeyError):continue
    if 'fortigate' in latest:
        at,q=latest['fortigate'];result.update(stats_at=at,enqueued_total=q.get('enqueued'),discarded_total=q.get('discarded.full',0)+q.get('discarded.nf',0))
        if result['depth'] is None:result['depth']=q.get('size')
    if 'fg_raw_archive' in latest:
        _,a=latest['fg_raw_archive'];result.update(processed_total=a.get('processed'),failed_total=a.get('failed'),suspended=a.get('suspended'))
    return result

def atomic(path,data):
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:json.dump(data,f,ensure_ascii=False,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
        os.chmod(tmp,0o640);os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def index_snapshot(value):
    unknown={'status':'unavailable','pending_records':None,'checked_at':None,'updated_at':None}
    if not isinstance(value,dict):return unknown
    count=value.get('pending_records');status=value.get('status')
    if status not in ('caught_up','processing','backfilling','stale') or type(count) is not int or count<0:return unknown
    return {key:value.get(key) for key in ('status','pending_records','checked_at','updated_at')}

def summary_index(reader):
    unknown=index_snapshot(None)
    try:
        result=subprocess.run(['/usr/bin/php',str(reader)],capture_output=True,timeout=6,check=True)
        data=json.loads(result.stdout)
        if not isinstance(data,dict):return {**unknown,'mail_search_index':dict(unknown)}
        return {**index_snapshot(data),'backlog_settings':backlog_settings_valid(data.get('backlog_settings')),
                'mail_search_index':index_snapshot(data.get('mail_search_index')),
                'mail_search_backlog_settings':backlog_settings_valid(data.get('mail_search_backlog_settings'))}
    except (OSError,ValueError,subprocess.SubprocessError):return {**unknown,'mail_search_index':dict(unknown)}

def sample(root,runtime,proc=Path('/proc'),summary=None):
    now=time.time();mono=time.monotonic();at=dt.datetime.fromtimestamp(now,UTC)
    boot=(proc/'sys/kernel/random/boot_id').read_text().strip();counters=disk_counters((proc/'diskstats').read_text());old={}
    try:old=json.loads((runtime/'state.json').read_text())
    except (OSError,ValueError):pass
    if not isinstance(old,dict):old={}
    seconds=mono-old.get('monotonic',mono) if old.get('boot_id')==boot else None
    summary=dict(summary) if isinstance(summary,dict) else {}
    search=index_snapshot(summary.pop('mail_search_index',None))
    mail_current=backlog_settings_valid(summary.pop('mail_search_backlog_settings',None));mail_cached=backlog_settings_valid(old.get('mail_search_backlog_settings'))
    checked=backlog_time(search.get('checked_at'))
    if checked is None or abs((at-checked).total_seconds())>10:search=index_snapshot(None)
    row={'schema':1,'at':at.isoformat(),'memory':memory((proc/'meminfo').read_text()),
         'disks':disk_rates(counters,old.get('counters',{}),seconds),'queue':queue_state(root),'archive':archive_state(root,now),
         'mail_search_index':search,'archive_index':summary or {'status':'unavailable','pending_records':None,'checked_at':None,'updated_at':None}}
    row['capacity']=capacity_sample(root,at)
    try:update_daily(root/'metrics/telemetry/capacity',row['capacity'])
    except (OSError,ValueError,TypeError,KeyError):row['capacity']['history_error']='capacity_history_unavailable'
    alert=old.get('archive_index_alert');mail_alert=old.get('mail_search_index_alert')
    current=backlog_settings_valid(row['archive_index'].get('backlog_settings'));cached=backlog_settings_valid(old.get('backlog_settings'));latest={}
    if not isinstance(alert,dict) or not current and not cached or not isinstance(mail_alert,dict) or not mail_current and not mail_cached:
        # latest.json survives a reboot or loss of /run. No history scan is
        # needed; a measurement gap still resets an unconfirmed candidate.
        try:
            latest=json.loads((root/'metrics/telemetry/latest.json').read_text())
            if not isinstance(latest,dict):latest={}
            if not isinstance(alert,dict):alert=latest.get('archive_index_alert')
            if not isinstance(mail_alert,dict):mail_alert=latest.get('mail_search_index_alert')
        except (OSError,ValueError,AttributeError):pass
    settings=current or cached or backlog_settings_valid(latest.get('backlog_settings'))
    row['backlog_settings']={**(settings or {'minimum_pending':1000,'minimum_seconds':300,'revision':0,'updated_at':None}),'source':'database' if current else 'cached' if settings else 'default'}
    row['archive_index_alert']=summary_backlog(alert,row['archive_index'],at,settings)
    # Each index keeps its own cached rule and revision during reader outages.
    mail_settings=mail_current or mail_cached or backlog_settings_valid(latest.get('mail_search_backlog_settings'))
    row['mail_search_backlog_settings']={**(mail_settings or {'minimum_pending':1000,'minimum_seconds':300,'revision':0,'updated_at':None}),'source':'database' if mail_current else 'cached' if mail_settings else 'default'}
    row['mail_search_index_alert']=summary_backlog(mail_alert,row['mail_search_index'],at,mail_settings)
    previous=old.get('queue',{});queue=row['queue'];stats_seconds=None
    queue['previous_depth']=previous.get('depth') if seconds and 0<seconds<=180 else None
    try:stats_seconds=(dt.datetime.fromisoformat(queue['stats_at'])-dt.datetime.fromisoformat(previous['stats_at'])).total_seconds()
    except (ValueError,KeyError,TypeError):pass
    for field,total in [('incoming_s','enqueued_total'),('written_s','processed_total')]:
        a=queue.get(total);b=previous.get(total)
        queue[field]=round((a-b)/stats_seconds,3) if stats_seconds and 0<stats_seconds<=180 and a is not None and b is not None and a>=b else None
    directory=root/'metrics/telemetry';directory.mkdir(mode=0o750,exist_ok=True)
    encoded=(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    path=directory/(at.strftime('%Y-%m-%d')+'.jsonl')
    fd=os.open(path,os.O_RDWR|os.O_APPEND|os.O_CREAT,0o640)
    try:
        size=os.fstat(fd).st_size
        if size and os.pread(fd,1,size-1)!=b'\n':encoded=b'\n'+encoded
        # A single bounded write. Reader skips a torn final record after an abrupt stop.
        if os.write(fd,encoded)!=len(encoded):raise OSError('Incomplete telemetry append')
    finally:os.close(fd)
    atomic(directory/'latest.json',row)
    atomic(runtime/'state.json',{'boot_id':boot,'monotonic':mono,'counters':counters,'queue':queue,'archive_index_alert':row['archive_index_alert'],'mail_search_index_alert':row['mail_search_index_alert'],'mail_search_backlog_settings':row['mail_search_backlog_settings'],'backlog_settings':row['backlog_settings']})
    cutoff=(at-dt.timedelta(days=90)).date().isoformat()
    for p in directory.glob('????-??-??.jsonl'):
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}\.jsonl',p.name) and p.stem<cutoff:p.unlink()
    return row

def main():
    from fls_storage import storage_state
    p=argparse.ArgumentParser();p.add_argument('--root',default='/srv/fls-server');p.add_argument('--runtime',default='/run/fls-telemetry');p.add_argument('--summary-reader',default=str(Path(__file__).with_name('telemetry-index.php')));args=p.parse_args()
    root=Path(args.root);runtime=Path(args.runtime);runtime.mkdir(exist_ok=True)
    if args.root=='/srv/fls-server':storage_state()
    with (runtime/'sample.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);sample(root,runtime,summary=summary_index(args.summary_reader))

if __name__=='__main__':main()
