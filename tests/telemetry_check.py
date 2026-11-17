#!/usr/bin/python3
import datetime as dt,hashlib,importlib.util,json,os,shutil,subprocess,tempfile,time,unittest
from unittest.mock import patch
from pathlib import Path
path=Path(__file__).resolve().parents[1]/'bin/telemetry.py';spec=importlib.util.spec_from_file_location('telemetry',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Telemetry(unittest.TestCase):
    def test_summary_reader_keeps_exact_zero_and_stale_nonzero(self):
        for status,count in [('caught_up',0),('stale',35001),('processing',12)]:
            with patch.object(m.subprocess,'run',return_value=m.subprocess.CompletedProcess([],0,json.dumps({'status':status,'pending_records':count}).encode(),b'')):
                self.assertEqual(m.summary_index('/private/reader')['pending_records'],count)
    def test_summary_reader_failure_timeout_and_invalid_count_are_unknown(self):
        for data in [{'status':'unknown','pending_records':0},{'status':'caught_up','pending_records':False},{'status':'processing','pending_records':-1},[]]:
            with patch.object(m.subprocess,'run',return_value=m.subprocess.CompletedProcess([],0,json.dumps(data).encode(),b'')):
                self.assertIsNone(m.summary_index('/private/reader')['pending_records'])
        for failure in [m.subprocess.TimeoutExpired('php',5),OSError('unavailable'),m.subprocess.CalledProcessError(1,'php')]:
            with patch.object(m.subprocess,'run',side_effect=failure):self.assertIsNone(m.summary_index('/private/reader')['pending_records'])
    def test_summary_snapshot_survives_sampler_restart_and_missing_does_not_become_zero(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);summary={'status':'processing','pending_records':35001,'checked_at':'2026-10-21T10:00:00Z','updated_at':'2026-10-21T09:59:59Z'}
            m.sample(root,root/'run',root/'proc',summary=summary);(root/'run/state.json').unlink();m.sample(root,root/'run',root/'proc')
            rows=[json.loads(line) for line in next((root/'metrics/telemetry').glob('*.jsonl')).read_text().splitlines()]
            self.assertEqual(rows[0]['archive_index'],summary);self.assertIsNone(rows[1]['archive_index']['pending_records'])
    def test_mail_snapshot_is_independent_of_failed_summary_reader(self):
        mail={'status':'processing','pending_records':35001,'checked_at':'2026-10-23T13:00:00Z','updated_at':'2026-10-23T12:59:59Z'}
        data={'status':'unknown','pending_records':None,'mail_search_index':mail}
        with patch.object(m.subprocess,'run',return_value=m.subprocess.CompletedProcess([],0,json.dumps(data).encode(),b'')):
            result=m.summary_index('/private/reader');self.assertIsNone(result['pending_records']);self.assertEqual(result['mail_search_index'],mail)
    def test_sampler_persists_mail_history_and_never_carries_previous_value_forward(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);at=dt.datetime(2026,10,23,13,tzinfo=dt.timezone.utc);mail={'status':'processing','pending_records':35001,'checked_at':at.isoformat(),'updated_at':at.isoformat()}
            data={'status':'caught_up','pending_records':0,'checked_at':at.isoformat(),'updated_at':at.isoformat(),'mail_search_index':mail}
            with patch.object(m.time,'time',return_value=at.timestamp()):first=m.sample(root,root/'run',root/'proc',summary=data)
            self.assertEqual(first['mail_search_index'],mail);self.assertNotIn('mail_search_index',first['archive_index']);self.assertIn('mail_search_index',data)
            (root/'run/state.json').unlink()
            with patch.object(m.time,'time',return_value=(at+dt.timedelta(seconds=30)).timestamp()):second=m.sample(root,root/'run',root/'proc')
            self.assertIsNone(second['mail_search_index']['pending_records']);rows=[json.loads(x) for x in next((root/'metrics/telemetry').glob('*.jsonl')).read_text().splitlines()];self.assertEqual(rows[0]['mail_search_index'],mail);self.assertEqual(len(rows),2)
    def test_mail_readings_reject_invalid_counts_and_old_source_times(self):
        at=dt.datetime(2026,10,23,13,tzinfo=dt.timezone.utc)
        for count,checked in [(False,at),(-1,at),(0,at-dt.timedelta(seconds=11)),(0,at+dt.timedelta(seconds=11))]:
            with tempfile.TemporaryDirectory() as f:
                root=self.tree(f);mail={'status':'processing','pending_records':count,'checked_at':checked.isoformat()}
                with patch.object(m.time,'time',return_value=at.timestamp()):row=m.sample(root,root/'run',root/'proc',summary={'mail_search_index':mail})
                self.assertIsNone(row['mail_search_index']['pending_records'])
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);mail={'status':'stale','pending_records':0,'checked_at':at.isoformat(),'updated_at':(at-dt.timedelta(minutes=2)).isoformat()}
            with patch.object(m.time,'time',return_value=at.timestamp()):row=m.sample(root,root/'run',root/'proc',summary={'mail_search_index':mail})
            self.assertEqual(row['mail_search_index'],mail)
    def test_memory_uses_available_and_keeps_cache_separate(self):
        d=m.memory('MemTotal: 1024 kB\nMemAvailable: 256 kB\nCached: 500 kB\nSReclaimable: 12 kB\nShmem: 2 kB\nSwapTotal: 100 kB\nSwapFree: 75 kB\n')
        self.assertEqual((d['used_percent'],d['cache_bytes'],d['swap_used_bytes']),(75,510*1024,25*1024))
    def test_disk_await_and_queue_are_interval_rates(self):
        a=[10,0,0,100,20,0,0,200,0,300,400];b=[12,0,0,200,24,0,0,240,0,500,900]
        d=m.disk_rates({'sda':b},{'sda':a},1)[0]
        self.assertEqual((d['read_await_ms'],d['write_await_ms'],d['util_percent'],d['average_queue']),(50,10,20,.5))
    def test_no_io_has_no_await_and_reboot_resets_deltas(self):
        a=[10]*11;d=m.disk_rates({'sda':a},{'sda':a},30)[0];self.assertIsNone(d['write_await_ms']);self.assertEqual(d['util_percent'],0)
        self.assertIsNone(m.disk_rates({'sda':[0]*11},{'sda':a},30)[0]['util_percent']);self.assertIsNone(m.disk_rates({'sda':a},{'sda':a},None)[0]['write_await_ms'])
    def tree(self,folder):
        root=Path(folder);[p.mkdir(parents=True,exist_ok=True) for p in [root/'raw',root/'queue',root/'metrics',root/'run',root/'proc/sys/kernel/random']]
        (root/'proc/meminfo').write_text('MemTotal: 1024 kB\nMemAvailable: 512 kB\n');(root/'proc/diskstats').write_text('8 0 sda '+' '.join(['1']*17)+'\n');(root/'proc/sys/kernel/random/boot_id').write_text('test-boot')
        return root
    def test_idle_record_age_does_not_increase_write_lag(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);p=root/'raw/2026-10-20-10.jsonl';stamp=dt.datetime.now(dt.timezone.utc).timestamp()-60;p.write_text(json.dumps({'received_at':dt.datetime.fromtimestamp(stamp,dt.timezone.utc).isoformat(),'raw':'unchanged'})+'\n');os.utime(p,(stamp+3,stamp+3));a=m.archive_state(root,stamp+10);b=m.archive_state(root,stamp+100)
            self.assertEqual((a['write_lag_seconds'],b['write_lag_seconds']),(3,3));self.assertEqual(b['last_record_age_seconds'],100)
    def test_partial_record_is_unknown_not_zero(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);(root/'raw/2026-10-20-10.jsonl').write_text('{"received_at":"2026-10-20T10:00:00Z"}')
            self.assertIsNone(m.archive_state(root,time.time())['write_lag_seconds'])
    def test_checkpoint_zero_is_not_a_live_queue_measurement(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);self.assertIsNone(m.queue_state(root)['depth']);(root/'queue/fg-receive.qi').write_text('+iQueueSize:2:1:0:\n')
            state=m.queue_state(root);self.assertIsNone(state['depth']);self.assertEqual(state['checkpoint_pending'],0);self.assertFalse(state['stats_fresh'])
    def test_live_queue_count_overrides_checkpoint_and_stale_stats_never_become_zero(self):
        now=dt.datetime(2026,11,17,10,tzinfo=dt.timezone.utc)
        for age,size,expected in [(0,7,7),(0,0,0),(180,3,3),(181,0,None),(-1,0,None),(0,False,None),(0,-1,None),(0,'0',None)]:
            with self.subTest(age=age,size=size),tempfile.TemporaryDirectory() as f:
                root=self.tree(f);(root/'queue/fg-receive.qi').write_text('+iQueueSize:2:1:0:\n')
                at=(now-dt.timedelta(seconds=age)).isoformat();q={'name':'fortigate','size':size,'enqueued':12,'discarded.full':0,'discarded.nf':0}
                (root/'metrics/2026-11-17-rsyslog.jsonl').write_text(at+' fixture '+json.dumps(q)+'\n')
                state=m.queue_state(root,now.timestamp());self.assertEqual(state['depth'],expected);self.assertEqual(state['stats_fresh'],expected is not None)
                self.assertEqual(state['checkpoint_pending'],0)
                if expected is None:self.assertIsNone(state['enqueued_total']);self.assertIsNone(state['discarded_total'])
    def test_invalid_or_missing_stats_time_cannot_claim_a_live_empty_queue(self):
        for at in ('invalid','2026-11-17T10:00:00',''):
            with self.subTest(at=at),tempfile.TemporaryDirectory() as f:
                root=self.tree(f);q={'name':'fortigate','size':0,'enqueued':12,'discarded.full':0,'discarded.nf':0}
                (root/'metrics/2026-11-17-rsyslog.jsonl').write_text(at+' fixture '+json.dumps(q)+'\n')
                self.assertIsNone(m.queue_state(root)['depth'])
    def test_stalled_collector_stats_remain_unknown_in_new_host_samples(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);now=dt.datetime(2026,11,17,10,tzinfo=dt.timezone.utc);q={'name':'fortigate','size':0,'enqueued':0,'discarded.full':0,'discarded.nf':0}
            (root/'metrics/2026-11-17-rsyslog.jsonl').write_text(now.isoformat()+' fixture '+json.dumps(q)+'\n')
            with patch.object(m.time,'time',return_value=now.timestamp()):first=m.sample(root,root/'run',root/'proc')
            with patch.object(m.time,'time',return_value=now.timestamp()+181):second=m.sample(root,root/'run',root/'proc')
            self.assertEqual(first['queue']['depth'],0);self.assertIsNone(second['queue']['depth']);self.assertNotEqual(first['at'],second['at'])
    def test_unreadable_or_invalid_stats_remain_unknown(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);(root/'metrics/2026-11-17-rsyslog.jsonl').write_text('invalid {"name": "fortigate"}\n')
            with patch.object(m,'tail',side_effect=OSError('storage unavailable')):
                self.assertIsNone(m.queue_state(root)['depth'])
            with patch.object(m,'tail',return_value=[b'invalid {"name": "fortigate"',b'invalid {"name":null}',b'invalid {"name":"fortigate","size":0}']):
                self.assertFalse(m.queue_state(root)['stats_fresh'])
    def test_panel_requires_fresh_queue_stats_before_describing_an_empty_queue(self):
        node=shutil.which('node');self.assertIsNotNone(node,'Node is required for the queue panel fixture')
        source=(path.parents[1]/'public/assets/app.js').read_text();start=source.index('function telemetryQueueReading(');end=source.index('\nfunction renderSystem(',start)
        at='2026-11-17T10:00:00Z';now=dt.datetime(2026,11,17,10,tzinfo=dt.timezone.utc).timestamp()*1000
        readings=[{}, {'stats_fresh':False,'depth':0},{'stats_fresh':True,'depth':0},{'stats_fresh':True,'depth':7,'previous_depth':2},{'stats_fresh':True,'depth':False}]
        cases=[[{**q,'stats_at':at},at,now] for q in readings]
        # A cached freshness flag must expire even when the sampler has stopped.
        for stats_at,sampled,clock in [(at,at,now+180001),(at,at,now+120001),('2026-11-17T09:56:59Z',at,now),('2026-11-17T10:00:01Z',at,now),(at,'invalid',now),(at,'2026-11-17T10:00:01Z',now),(None,at,now),('2026-11-17T10:00:00',at,now)]:
            cases.append([{'stats_fresh':True,'depth':0,'stats_at':stats_at},sampled,clock])
        code=source[start:end]+'\nconsole.log(JSON.stringify('+json.dumps(cases)+'.map(args=>telemetryQueueReading(...args))));'
        result=subprocess.run([node,'-e',code],capture_output=True,text=True,check=True,timeout=10);values=json.loads(result.stdout)
        for index in (0,1,4,*range(5,len(cases))):self.assertIsNone(values[index]['depth']);self.assertIn('doğrulanamıyor',values[index]['trend'])
        self.assertEqual(values[2],{'depth':0,'trend':'Kuyruk boş'});self.assertEqual(values[3],{'depth':7,'trend':'Kuyruk büyüyor'})
    def test_sampling_keeps_raw_intact_and_recovers_torn_telemetry(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);p=root/'raw/2026-10-20-10.jsonl';p.write_text(json.dumps({'received_at':dt.datetime.now(dt.timezone.utc).isoformat(),'raw':'original'})+'\n');before=hashlib.sha256(p.read_bytes()).hexdigest()
            first=m.sample(root,root/'run',root/'proc');daily=next((root/'metrics/telemetry').glob('*.jsonl'));daily.write_bytes(daily.read_bytes()+b'{partial');m.sample(root,root/'run',root/'proc')
            valid=[]
            for line in daily.read_text().splitlines():
                try:valid.append(json.loads(line))
                except ValueError:pass
            self.assertEqual(len(valid),2);self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),before);self.assertEqual(json.loads((root/'metrics/telemetry/latest.json').read_text())['schema'],1)
    def test_retention_only_removes_old_telemetry(self):
        with tempfile.TemporaryDirectory() as f:
            root=self.tree(f);folder=root/'metrics/telemetry';folder.mkdir();old=folder/'2000-01-01.jsonl';old.write_text('{}\n');other=folder/'operator-notes.jsonl';other.write_text('keep')
            m.sample(root,root/'run',root/'proc');self.assertFalse(old.exists());self.assertTrue(other.exists())

if __name__=='__main__':unittest.main()
