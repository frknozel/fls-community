#!/usr/bin/env python3
"""Offline acceptance-helper checks: /tmp synthetic files, no real DB/socket/unit/VM calls."""
import contextlib, copy, datetime as dt, importlib.util, io, json, os, tempfile, types, unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('intake_tool',ROOT/'tests/community_vm_intake_proof.py')
t=importlib.util.module_from_spec(spec); spec.loader.exec_module(t)

class Checks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fls-rc9-intake-offline-')
        self.base=Path(self.temp.name); self.raw=self.base/'raw'; self.raw.mkdir()
        self.s=dict(target='192.0.2.42',dmi_prefix='abcdef123456',release_manifest_sha256='a'*64,
                    collector_sha256='b'*64,installation_id='fixture-only',token='1234567890abcdef',
                    serial='RC9TEST_1234567890ABCDEF',base_ns=1794918900123456000)
        self.api_key_count='0'  # Actual RC9 MariaDB JSON_OBJECT(COUNT(*)) result.
        t.a=types.SimpleNamespace(command='check-before',state=self.base)
        self.patches=[patch.object(t,'RAW',self.raw),patch.object(t,'active'),patch.object(t.time,'sleep')]
        for item in self.patches:item.start()
        self.rows=[]; self.write_series(96)
    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        self.temp.cleanup()
    def write_series(self,count):
        path=self.raw/'2026-11-17-13.jsonl'; blob=b''; self.rows=[]
        for wanted in t.records(self.s)[:count]:
            line=(json.dumps(dict(schema_version='1',received_at='2026-11-17T13:00:00.123456+00:00',
                                  sender_ip=self.s['target'],transport='tcp',raw=wanted['raw']),ensure_ascii=False)+'\n').encode()
            row=dict(id=str(1000+wanted['number']),file=path.name,offset=len(blob),length=len(line),line=wanted['number']+1,
                     sha=wanted['raw_sha256'],fields=json.dumps(wanted['fields'],ensure_ascii=False).encode().hex(),
                     inode=0,checkpoint=0,invalid=0,event_at=wanted['event_at'],received_at='2026-11-17 13:00:00.123456',
                     outcome='observed',reason='observed',rating=0)
            row.update({key:wanted['fields'][key] for key in 'type subtype action policyid srcip dstip dstport devid vd sessionid'.split()})
            self.rows.append(row); blob+=line
        path.write_bytes(blob)
        for row in self.rows:row.update(inode=path.stat().st_ino,checkpoint=len(blob))
    def fake_database(self, *args, **kwargs):
        query=kwargs['input'].decode()
        self.assertIn('START TRANSACTION READ ONLY',query)
        self.assertNotIn('PASSWORD',query.upper())
        self.assertNotIn('UPDATE ',query.upper()); self.assertNotIn('INSERT ',query.upper())
        self.assertIn('--no-defaults',args[0]); self.assertIn('--protocol=SOCKET',args[0])
        device=dict(device=17,enabled=0,default=None,vd='root',peer=self.s['target'],source=self.s['target'],
                    receiver=self.s['target'],admitted=1,keys=self.api_key_count)
        return types.SimpleNamespace(returncode=0,stdout=b'\n'.join(json.dumps(row).encode() for row in [device,*self.rows]))
    def check(self, boot='boot-before'):
        with patch.object(t.subprocess,'run',side_effect=self.fake_database):return t.check(self.s,boot)
    def prepare_migration_recheck(self):
        t.save('check-before.json',self.check())
        t.a.command='check-after'; self.write_series(192)
        baseline=self.check('boot-after'); t.save('check-after.json',baseline)
        t.save('series.json',self.s)
        for phase in ('before','after'):
            t.save('send-'+phase+'-attempt.json',dict(boot_id='boot-after',state='send_attempt_started_never_repeat_ambiguously'))
        t.a.command='recheck-after-migration'
        return baseline
    def replace_migration_baseline(self,value):
        (self.base/'check-after.json').write_bytes(t.canonical(value))
    def recheck_main(self,boot='boot-after'):
        # Exercise the real CLI's ownership/permission checks on /tmp files.
        # Only the permitted /var/tmp path's representation is mapped to this fixture.
        base=self.base; virtual='/var/tmp/fls-rc9-intake-offline'
        class FixtureState:
            parent=Path('/var/tmp'); name='fls-rc9-intake-offline'
            def is_absolute(self):return True
            def lstat(self):return base.lstat()
            def __truediv__(self,name):return base/name
        def fixture_path(value):return FixtureState() if str(value)==virtual else Path(value)
        output=io.StringIO(); real_open=os.open
        def readonly_open(path,flags,*args,**kwargs):
            self.assertFalse(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND),'Recheck attempted a file write')
            return real_open(path,flags,*args,**kwargs)
        with patch.object(t,'Path',side_effect=fixture_path),patch.object(t,'guard',return_value=boot) as guard, \
             patch.object(t,'active') as active,patch.object(t.subprocess,'run',side_effect=self.fake_database), \
             patch.object(t,'save',side_effect=AssertionError('state write')) as save, \
             patch.object(t.socket,'create_connection',side_effect=AssertionError('TCP send')) as connect, \
             patch.object(t.socket,'socket',side_effect=AssertionError('unexpected socket')) as sock, \
             patch.object(t.os,'open',side_effect=readonly_open),contextlib.redirect_stdout(output):
            status=t.main(['recheck-after-migration','--state',virtual])
            save.assert_not_called(); connect.assert_not_called(); sock.assert_not_called()
        return status,json.loads(output.getvalue()),guard,active
    def test_migration_recheck_accepts_new_inode_without_requiring_a_new_boot(self):
        baseline=self.prepare_migration_recheck(); path=next(self.raw.glob('*')); old_inode=path.stat().st_ino
        data=path.read_bytes(); path.rename(self.base/'retained-before-migration.jsonl'); path.write_bytes(data)
        self.assertNotEqual(path.stat().st_ino,old_inode)
        for row in self.rows:row['inode']=path.stat().st_ino
        for boot in ('boot-after','boot-before','boot-later'):
            with self.subTest(boot=boot):
                result=self.check(boot)
                self.assertEqual(result['matched'],baseline['matched'])
                self.assertEqual(result['stage'],'recheck-after-migration')
                self.assertEqual(result['exact_raw_and_index_records'],192)
                self.assertEqual(result['new_boot_observed'],boot!='boot-after')
    def test_migration_recheck_rejects_reindexed_ids_in_both_halves(self):
        self.prepare_migration_recheck()
        for index in (0,95,96,191):
            with self.subTest(index=index):
                old=self.rows[index]['id']; self.rows[index]['id']='999999'
                with self.assertRaisesRegex(ValueError,'records_changed_or_reindexed'):self.check('boot-after')
                self.rows[index]['id']=old
    def test_migration_recheck_rejects_shifted_offsets_in_both_halves(self):
        self.prepare_migration_recheck(); path=next(self.raw.glob('*')); original=path.read_bytes(); rows=copy.deepcopy(self.rows)
        extra=b'{"unrelated":true}\n'
        for first in (0,96):
            with self.subTest(first=first):
                self.rows=copy.deepcopy(rows); offset=rows[first]['offset']
                path.write_bytes(original[:offset]+extra+original[offset:])
                for index,row in enumerate(self.rows):
                    row['checkpoint']+=len(extra)
                    if index>=first:row['offset']+=len(extra);row['line']+=1
                with self.assertRaisesRegex(ValueError,'records_changed_or_reindexed'):self.check('boot-after')
    def test_migration_recheck_requires_successful_matching_complete_baseline(self):
        baseline=self.prepare_migration_recheck()
        for key,value in (('ok',False),('stage','check-reboot'),('exact_raw_and_index_records',96),
                          ('exact_raw_and_index_records',192.0),('missing',1),('duplicates',1),('missing',False),
                          ('series_sha256','c'*64),('serial','RC9TEST_WRONG'),
                          ('matched',baseline['matched'][:96]),('boot_id','')):
            with self.subTest(key=key):
                changed=copy.deepcopy(baseline); changed[key]=value; self.replace_migration_baseline(changed)
                with self.assertRaisesRegex(ValueError,'matching_pre_migration_proof_required'):self.check('boot-after')
        self.replace_migration_baseline({**baseline,'device_id':999})
        with self.assertRaisesRegex(ValueError,'pre_migration_device_changed'):self.check('boot-after')
    def test_migration_recheck_keeps_original_before_proof_protection(self):
        self.prepare_migration_recheck(); path=self.base/'check-before.json'; before=json.loads(path.read_bytes())
        before['series_sha256']='c'*64; path.write_bytes(t.canonical(before))
        with self.assertRaisesRegex(ValueError,'matching_before_proof_required'):self.check('boot-before')
        for value in ({},None,[],{**before,'ok':False},{**before,'stage':'check-reboot'},{**before,'matched':[]}):
            with self.subTest(value=value):
                path.write_bytes(t.canonical(value))
                with self.assertRaisesRegex(ValueError,'matching_before_proof_required'):self.check('boot-after')
    def test_migration_recheck_keeps_current_raw_inode_and_bytes_checks(self):
        self.prepare_migration_recheck(); self.rows[-1]['inode']+=1
        with self.assertRaisesRegex(ValueError,'raw_bytes_offsets_checkpoint_mismatch'):self.check('boot-after')
        self.rows[-1]['inode']-=1; path=next(self.raw.glob('*'))
        path.write_bytes(path.read_bytes().replace(b'FLS RC9',b'FLS XX9',1))
        with self.assertRaisesRegex(ValueError,'corrupt'):self.check('boot-after')
    def test_migration_recheck_keeps_duplicate_and_full_field_checks(self):
        self.prepare_migration_recheck(); path=next(self.raw.glob('*')); original=path.read_bytes()
        path.write_bytes(original+original.splitlines(keepends=True)[-1])
        with self.assertRaisesRegex(ValueError,'duplicate'):self.check('boot-after')
        path.write_bytes(original); fields=json.loads(bytes.fromhex(self.rows[-1]['fields']));fields['msg']='changed'
        self.rows[-1]['fields']=json.dumps(fields).encode().hex()
        with self.assertRaisesRegex(ValueError,'index_fields'):self.check('boot-after')
    def test_migration_recheck_missing_records_fails_after_one_scan(self):
        self.prepare_migration_recheck(); self.rows.pop()
        with patch.object(t,'raw_rows',wraps=t.raw_rows) as scan:
            with self.assertRaisesRegex(ValueError,'migration_record_count_mismatch'):self.check('boot-after')
            scan.assert_called_once_with(self.s)
    def test_migration_recheck_keeps_full_history_scan_budget(self):
        self.prepare_migration_recheck(); size=next(self.raw.glob('*')).stat().st_size
        with patch.object(t,'MAX_RAW_SCAN_BYTES',size-1):
            with self.assertRaisesRegex(ValueError,'fresh_vm_scan_limit'):self.check('boot-after')
    def test_migration_recheck_cli_only_reads_state_and_prints_without_sending(self):
        self.prepare_migration_recheck()
        def snapshot():return {p.name:(p.read_bytes(),p.stat().st_mode,p.stat().st_ino,p.stat().st_mtime_ns)
                               for p in self.base.iterdir() if p.is_file()}
        before=snapshot(); status,result,guard,active=self.recheck_main()
        self.assertEqual(status,0); self.assertTrue(result['ok']); self.assertEqual(result['exact_raw_and_index_records'],192)
        self.assertEqual(result['stage'],'recheck-after-migration'); self.assertNotIn('matched',result)
        self.assertEqual(snapshot(),before)
        guard.assert_called_once_with(self.s);active.assert_called_once_with(self.s)
    def test_migration_recheck_cli_rejects_unsafe_root_state_or_series(self):
        self.prepare_migration_recheck(); series=self.base/'series.json'
        for path,mode,code in ((self.base,0o755,'unsafe_root_state'),(series,0o644,'unsafe_root_series')):
            with self.subTest(code=code):
                old=path.stat().st_mode;path.chmod(mode)
                try:
                    status,result,guard,active=self.recheck_main()
                    self.assertEqual(status,1);self.assertEqual(result['error_code'],code)
                    guard.assert_not_called();active.assert_not_called()
                finally:path.chmod(old)
    def test_migration_recheck_refuses_untrusted_baseline_metadata(self):
        self.prepare_migration_recheck(); path=self.base/'check-after.json'
        path.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'unsafe_root_input'):self.check('boot-after')
        path.chmod(0o600); os.link(path,self.base/'baseline-alias.json')
        with self.assertRaisesRegex(ValueError,'unsafe_root_input'):self.check('boot-after')
    def test_migration_recheck_cli_rejects_nonroot_state_or_series_owners(self):
        self.prepare_migration_recheck(); original=Path.lstat
        for path,code in ((self.base,'unsafe_root_state'),(self.base/'series.json','unsafe_root_series')):
            with self.subTest(path=path.name):
                def metadata(value,*args,**kwargs):
                    info=original(value,*args,**kwargs)
                    return types.SimpleNamespace(st_mode=info.st_mode,st_uid=65534) if value==path else info
                with patch.object(Path,'lstat',metadata):
                    status,result,guard,active=self.recheck_main()
                    self.assertEqual(status,1); self.assertEqual(result['error_code'],code)
                    guard.assert_not_called(); active.assert_not_called()
    def test_migration_recheck_refuses_nonroot_owned_or_symlink_baseline(self):
        self.prepare_migration_recheck(); path=self.base/'check-after.json'; expected=path.stat(); original=os.fstat
        def metadata(fd):
            info=original(fd)
            return types.SimpleNamespace(st_mode=info.st_mode,st_uid=65534,st_nlink=info.st_nlink) \
                if (info.st_dev,info.st_ino)==(expected.st_dev,expected.st_ino) else info
        with patch.object(t.os,'fstat',side_effect=metadata):
            with self.assertRaisesRegex(ValueError,'unsafe_root_input'):self.check('boot-after')
        path.rename(self.base/'retained-baseline.json'); path.symlink_to(self.base/'retained-baseline.json')
        with self.assertRaises(OSError):self.check('boot-after')
    def test_exact_unicode_escaping_and_independent_index_fields_pass(self):
        result=self.check(); self.assertEqual(result['exact_raw_and_index_records'],96)
        self.assertEqual(len(result['matched']),96); self.assertEqual(result['duplicates'],0)
    def test_api_key_zero_count_accepts_json_number_and_text(self):
        for value in (0,'0'):
            with self.subTest(value=value):
                self.api_key_count=value; self.assertTrue(self.check()['ok'])
    def test_nonzero_or_invalid_api_key_count_is_rejected(self):
        for value in (1,'1',-1,'-1',None,False,True,0.0,1.0,'','00',' 0','0 ','0.0','+0','-0',[],{}):
            with self.subTest(value=value):
                self.api_key_count=value
                with self.assertRaisesRegex(ValueError,'dummy_device_or_source_grant_incorrect'):self.check()
    def test_actual_importer_parser_preserves_all_192_original_fields(self):
        spec=importlib.util.spec_from_file_location('intake_actual_importer',ROOT/'bin/importer.py')
        importer=importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules',{'pymysql':types.ModuleType('pymysql')}):
            spec.loader.exec_module(importer)
        with patch.object(importer,'connect',side_effect=AssertionError('database call')) as connect:
            rows=t.records(self.s); self.assertEqual(len(rows),192)
            for row in rows:
                with self.subTest(number=row['number']):
                    self.assertEqual(importer.parse(row['raw']),row['fields'])
                    self.assertEqual(importer.classification(row['fields']),('observed',0,'observed'))
                    self.assertEqual(importer.event_time(row['fields'],dt.datetime(2026,1,1)).strftime('%Y-%m-%d %H:%M:%S.%f'),row['event_at'])
            connect.assert_not_called()
    def test_reboot_preserves_original_event_ids_offsets_and_then_new_96(self):
        before=self.check(); t.save('check-before.json',before)
        t.a.command='check-reboot'; result=self.check('boot-after'); self.assertTrue(result['new_boot_observed'])
        t.a.command='check-after'; self.write_series(192)
        self.assertEqual(self.check('boot-after')['exact_raw_and_index_records'],192)
    def test_same_boot_is_rejected(self):
        t.save('check-before.json',self.check()); t.a.command='check-reboot'
        with self.assertRaisesRegex(ValueError,'new_boot'):self.check()
    def test_reindexed_record_is_rejected_even_when_all_payloads_match(self):
        t.save('check-before.json',self.check()); t.a.command='check-reboot'; self.rows[0]['id']='999999'
        with self.assertRaisesRegex(ValueError,'pre_reboot_records_changed'):self.check('boot-after')
    def test_raw_duplicate_rejected(self):
        path=next(self.raw.glob('*')); data=path.read_bytes(); path.write_bytes(data+data.splitlines(keepends=True)[0])
        with self.assertRaisesRegex(ValueError,'duplicate'):self.check()
    def test_index_duplicate_rejected(self):
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaisesRegex(ValueError,'duplicate'):self.check()
    def test_mutated_raw_bytes_rejected(self):
        path=next(self.raw.glob('*')); path.write_bytes(path.read_bytes().replace(b'FLS RC9',b'FLS XX9',1))
        with self.assertRaisesRegex(ValueError,'corrupt'):self.check()
    def test_offset_mismatch_rejected(self):
        self.rows[0]['offset']+=1
        with self.assertRaisesRegex(ValueError,'offsets'):self.check()
    def test_uncommitted_source_checkpoint_rejected(self):
        self.rows[-1]['checkpoint']-=1
        with self.assertRaisesRegex(ValueError,'checkpoint'):self.check()
    def test_full_fields_mismatch_rejected(self):
        fields=json.loads(bytes.fromhex(self.rows[0]['fields'])); fields['msg']='changed'
        self.rows[0]['fields']=json.dumps(fields).encode().hex()
        with self.assertRaisesRegex(ValueError,'index_fields'):self.check()
    def test_index_timestamp_mismatch_rejected(self):
        self.rows[0]['event_at']='2026-11-17 00:00:00.000000'
        with self.assertRaisesRegex(ValueError,'timestamp'):self.check()
    def test_unrelated_source_invalid_count_does_not_falsely_fail_exact_series(self):
        self.rows[0]['invalid']=7; self.assertTrue(self.check()['ok'])
    def test_missing_record_cannot_pass(self):
        self.rows.pop()
        with patch.object(t.time,'monotonic',side_effect=[0,1,100]):
            with self.assertRaisesRegex(ValueError,'timeout'):self.check()
    def test_scan_budget_exhaustion_never_returns_a_partial_proof(self):
        size=next(self.raw.glob('*')).stat().st_size
        with patch.object(t,'MAX_RAW_SCAN_BYTES',size-1):
            with self.assertRaisesRegex(ValueError,'fresh_vm_scan_limit'):self.check()
    def test_incomplete_tail_waits_without_accepting_it(self):
        path=next(self.raw.glob('*')); path.write_bytes(path.read_bytes()[:-1]); self.rows.pop()
        with patch.object(t.time,'monotonic',side_effect=[0,1,100]):
            with self.assertRaisesRegex(ValueError,'timeout'):self.check()
    def test_intent_receipt_cannot_be_overwritten(self):
        t.save('send-before-attempt.json',{'started':True})
        with self.assertRaises(FileExistsError):t.save('send-before-attempt.json',{'started':True})
    def test_noargs_help_and_bad_state_do_not_read_host(self):
        with patch.object(t,'read',side_effect=AssertionError('host read')) as read,contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as status:t.main([])
            self.assertEqual(status.exception.code,2)
            with self.assertRaises(SystemExit) as status:t.main(['--help'])
            self.assertEqual(status.exception.code,0)
            self.assertEqual(t.main(['check-before','--state','/tmp/not-permitted']),1)
            read.assert_not_called()
    def test_nonroot_does_not_read_host(self):
        with patch.object(t.os,'geteuid',return_value=1000),patch.object(t,'read') as read,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(t.main(['check-before']),1); read.assert_not_called()
    def test_failed_identity_stops_before_any_socket_or_database_call(self):
        with patch.object(t,'read',return_value=b'wrong VM'),patch.object(t.socket,'socket') as sock:
            with self.assertRaisesRegex(ValueError,'wrong_vm_dmi'):t.guard(self.s)
            sock.assert_not_called()
    def test_writable_or_hardlinked_root_metadata_is_rejected(self):
        path=self.base/'unsafe.json'; path.write_text('{}'); path.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'unsafe_root_input'):t.read(path)
        path.chmod(0o600); os.link(path,self.base/'alias.json')
        with self.assertRaisesRegex(ValueError,'unsafe_root_input'):t.read(path)
    def test_successful_identity_checks_receipt_inventory_and_binary_separately(self):
        dmi=b'synthetic-uuid'; inventory=b'authenticated inventory'; binary=b'fixture ELF'
        self.s.update(dmi_prefix=t.sha(dmi)[:12],release_manifest_sha256=t.sha(inventory),collector_sha256=t.sha(binary))
        receipt=dict(installation_id='fixture-only',release_sha256=t.sha(inventory),version='0.76.0',edition='community',schema_version=47)
        files={'/sys/class/dmi/id/product_uuid':dmi,'/etc/fls/release-state.json':json.dumps(receipt).encode(),
               '/var/www/fls/deploy/release-files.json':inventory,'/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd':binary,
               '/proc/sys/kernel/random/boot_id':b'boot-before\n'}
        def bounded_read(name,limit=16000000):
            if str(name) in ('/sys/class/dmi/id/product_uuid','/proc/sys/kernel/random/boot_id'):
                self.assertLessEqual(limit,4096,'Kernel metadata must never use the large regular-file read size')
            return files[str(name)]
        local=types.SimpleNamespace(returncode=0,stdout=json.dumps([{'addr_info':[{'local':self.s['target']}]}]).encode())
        with patch.object(t,'read',side_effect=bounded_read),patch.object(t.subprocess,'run',return_value=local),patch.object(t.socket,'socket') as sock:
            self.assertEqual(t.guard(self.s),'boot-before'); sock.return_value.__enter__.return_value.bind.assert_called_once_with((self.s['target'],0))
        local.stdout=b'[]'
        with patch.object(t,'read',side_effect=bounded_read),patch.object(t.subprocess,'run',return_value=local),patch.object(t.socket,'socket') as sock:
            with self.assertRaisesRegex(ValueError,'receiver_not_assigned'):t.guard(self.s)
            sock.assert_not_called()
    def test_kernel_read_error_reports_errno_without_creating_state_or_sending(self):
        output=io.StringIO()
        args=['init','--target',self.s['target'],'--dmi-prefix',self.s['dmi_prefix'],
              '--release-manifest-sha256',self.s['release_manifest_sha256'],
              '--collector-sha256',self.s['collector_sha256'],'--installation-id',self.s['installation_id']]
        with patch.object(t,'read',side_effect=OSError(12,'Cannot allocate memory')),patch.object(t.socket,'socket') as sock, \
             patch.object(t,'save') as save,patch.object(t.Path,'mkdir') as mkdir,contextlib.redirect_stdout(output):
            self.assertEqual(t.main(args),1)
            self.assertEqual(json.loads(output.getvalue()),{'ok':False,'error_code':'OSError','error_errno':12})
            sock.assert_not_called();save.assert_not_called();mkdir.assert_not_called()
    def test_utf8_octet_framing_uses_byte_lengths_and_roundtrips(self):
        rows=t.records(self.s)[:96]
        wire=b''.join(str(len(r['raw'].encode())).encode()+b' '+r['raw'].encode() for r in rows)
        decoded=[]
        while wire:
            size,wire=wire.split(b' ',1); size=int(size); decoded.append(wire[:size].decode()); wire=wire[size:]
        self.assertEqual(decoded,[r['raw'] for r in rows])

if __name__=='__main__':unittest.main(verbosity=2)
