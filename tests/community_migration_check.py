#!/usr/bin/python3
"""Community migration fixtures only: no real devices, SQL, services or mounts.

The Linux executor is never invoked. Real temporary journals, SQLite inode maps,
file hashes, xattrs and hardlinks exercise the safety and checkpoint contracts.
"""
import copy
import contextlib
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
import subprocess
import struct
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / 'tools/community/overlay/bin'
sys.path.insert(0, str(OVERLAY if OVERLAY.is_dir() else ROOT / 'bin'))
import fls_primary_migration as migration
import fls_disk_ops as ops

DISK = dict(wwn='id:' + 'a'*64, serial='VM-DISK-TWO', size_bytes=64*1024**3,
            logical_sector=512, diskseq=3, major_minor='253:16', path='/dev/vdb',
            physical_identity={'kind':'serial','value':'VM-DISK-TWO'})
DISK['wwn']='id:'+__import__('hashlib').sha256(json.dumps(DISK['physical_identity'],sort_keys=True).encode()).hexdigest()
JOB = dict(id=3, request_key='04e62fda-3323-4d57-a53b-e0e8c99306d8',
           boot_id='17fd9754-d506-4d04-81e5-1cc69e7a8a20')
SOURCE = dict(schema=2, mode='system-root', root_uuid='a12d0147-a635-4432-9bb6-a3054e25a573',
              device_identity={'kind':'serial','value':'VM-DISK-ONE'})


class Cursor:
    def __init__(self, db): self.db=db;self.result=[];self.rowcount=0
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def fetchall(self): return copy.deepcopy(self.result)
    def execute(self, sql, args=()):
        self.db.statements.append((sql,args));self.rowcount=0
        if sql.startswith('SELECT id,name,inode,'):
            self.result=copy.deepcopy(self.db.files)
        elif sql.startswith('UPDATE source_files SET inode='):
            for row in self.db.files:
                if (row['id'],row['inode'])==(args[1],args[2]):row['inode']=args[0];self.rowcount=1
        elif sql.startswith('SELECT id,cursor_file,'):
            table=sql.split(' FROM ')[1].split()[0];self.result=[copy.deepcopy(self.db.history[table])]
        elif sql.startswith('UPDATE ') and ' SET cursor_inode=' in sql:
            table=sql.split()[1];row=self.db.history[table]
            if (row['id'],row['cursor_inode'])==(args[1],args[2]):row['cursor_inode']=args[0];self.rowcount=1
        elif sql.startswith('UPDATE archive_integrity_checks'):
            for row in self.db.integrity:
                if row['status'] in ('running','partial'):
                    row.update(status='pending',progress_bytes=0,error_code='',verification_started_at=None)
        else: raise AssertionError('Unexpected SQL: '+sql)


class Database:
    def __init__(self):
        self.files=[dict(id=7,name='2026-11-13-07.jsonl',inode=101,byte_offset=12,
                         line_number=2,observed_size=16,invalid_rows=0)]
        self.history={name:dict(id=1,cursor_file='2026-11-13.jsonl',cursor_inode=102,cursor_offset=6)
                      for name in ('summary_backlog_history_state','mail_search_backlog_history_state')}
        self.integrity=[dict(status='verified',progress_bytes=99),dict(status='partial',progress_bytes=4)]
        self.events=[dict(id=88,byte_offset=0),dict(id=89,byte_offset=6)]
        self.incidents=[dict(id=55,status='active',gap_count=0)]
        self.statements=[];self.commits=0;self.rollbacks=0;self.saved=None
    def cursor(self):return Cursor(self)
    def begin(self):self.saved=copy.deepcopy((self.files,self.history,self.integrity))
    def commit(self):self.commits+=1;self.saved=None
    def rollback(self):
        self.rollbacks+=1
        if self.saved:self.files,self.history,self.integrity=self.saved;self.saved=None


def sample_mapping(path):
    value=migration.open_mapping(path)
    value.execute('INSERT INTO paths VALUES(?,?,?,?,?,?)',('raw','2026-11-13-07.jsonl',101,201,16,'a'*64))
    value.execute('INSERT INTO paths VALUES(?,?,?,?,?,?)',('metrics','telemetry/2026-11-13.jsonl',102,202,8,'b'*64))
    value.commit();value.close();return path


class Adapter:
    def __init__(self, folder, journal, failure=None):
        self.folder=folder;self.journal=journal;self.failure=failure;self.calls=[]
        self.connection=Database();self.paused=False;self.formats=0;self.new_writes=False
    def stage(self,name):
        self.calls.append(name)
        if self.failure==name:raise ops.DiskOpsError('fixture_'+name)
    def preflight(self,request):self.stage('preflight');return SOURCE,DISK,16
    def quiesce(self):self.stage('quiesce');self.paused=True
    def prepare(self,request):
        self.stage('prepare');self.formats+=1
        assert self.journal.path.is_file() and self.paused
        return dict(uuid='7b762ad7-1e87-4f61-ade4-7289816cfaae',**DISK)
    def copy_verify(self,target,used):
        self.stage('copy_verify');return sample_mapping(self.folder/'inodes.sqlite3')
    def invalidate_checkpoints(self):self.stage('invalidate_checkpoints')
    def cutover(self,target):self.stage('cutover')
    def validate(self):self.stage('validate')
    def resume(self):
        self.stage('resume');self.journal.phase('resuming',new_writes_possible=True);self.new_writes=True;self.paused=False
    def fail_closed(self):self.calls.append('fail_closed');self.paused=True


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fls-community-migrate-');self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.folder.chmod(0o700)
        self.journal=migration.MigrationJournal(self.folder,owner=os.geteuid())
    def forbidden(self,*args,**kwargs):raise AssertionError('Host command is forbidden in these fixtures')
    def test_complete_orders_journal_before_format_and_sql_before_mounts(self):
        adapter=Adapter(self.folder,self.journal);claims=[]
        with patch('subprocess.run',self.forbidden):
            result=migration.migrate_primary(JOB,{},adapter,self.journal,lambda *args:claims.append(True) or True)
        self.assertTrue(result['retained_old_source']);self.assertEqual(claims,[True])
        self.assertEqual(adapter.formats,1);self.assertEqual(self.journal.value['phase'],'complete')
        self.assertEqual(adapter.connection.files[0]['inode'],201)
        self.assertEqual(adapter.calls,['preflight','quiesce','prepare','copy_verify','invalidate_checkpoints','cutover','validate','resume'])
        phases=[row['phase'] for row in self.journal.value['steps']]
        self.assertLess(phases.index('sql_committed'),phases.index('validated'))
    def test_preflight_failure_does_not_claim_or_create_journal(self):
        adapter=Adapter(self.folder,self.journal,'preflight');claims=[]
        with self.assertRaises(ops.DiskOpsError):migration.migrate_primary(JOB,{},adapter,self.journal,lambda *args:claims.append(True))
        self.assertEqual(claims,[]);self.assertFalse(self.journal.path.exists())
    def test_durable_claim_failure_never_formats(self):
        adapter=Adapter(self.folder,self.journal)
        with self.assertRaisesRegex(ops.DiskOpsError,'durable_journal_claim_failed'):
            migration.migrate_primary(JOB,{},adapter,self.journal,lambda *args:False)
        self.assertEqual(adapter.formats,0);self.assertFalse(self.journal.path.exists())
    def test_each_interruption_retains_pause_and_blocks_replay(self):
        for phase in ('quiesce','prepare','copy_verify','invalidate_checkpoints','cutover','validate','resume'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory(dir=self.folder) as folder:
                path=Path(folder);journal=migration.MigrationJournal(path,owner=os.geteuid());adapter=Adapter(path,journal,phase)
                with self.assertRaises(ops.DiskOpsError):migration.migrate_primary(JOB,{},adapter,journal,lambda *args:True)
                self.assertTrue(adapter.paused);self.assertEqual(journal.value['phase'],'reconciliation_required')
                self.assertIn('fail_closed',adapter.calls)
                replay=Adapter(path,migration.MigrationJournal(path,owner=os.geteuid()))
                with self.assertRaisesRegex(ops.DiskOpsError,'migration_already_attempted'):
                    migration.migrate_primary(JOB,{},replay,replay.journal,lambda *args:True)
                self.assertEqual(replay.formats,0)
    def test_partial_journal_is_never_reset(self):
        self.journal.path.write_bytes(b'')
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_already_attempted'):self.journal.begin(JOB,SOURCE,DISK)
        self.assertEqual(self.journal.path.read_bytes(),b'')
    def test_journal_write_failure_still_requests_emergency_pause(self):
        adapter=Adapter(self.folder,self.journal,'prepare');original=self.journal.phase
        def phase(name,**details):
            if name=='reconciliation_required':raise OSError(28,'Fixture disk full')
            return original(name,**details)
        with patch.object(self.journal,'phase',side_effect=phase),self.assertRaises(OSError):
            migration.migrate_primary(JOB,{},adapter,self.journal,lambda *args:True)
        self.assertTrue(adapter.paused);self.assertIn('fail_closed',adapter.calls)
    def test_sql_remap_preserves_offsets_events_incidents(self):
        db=Database();before=copy.deepcopy(db.__dict__)
        path=sample_mapping(self.folder/'map.sqlite3')
        with sqlite3.connect(path) as mapping:migration.remap_checkpoints(db,mapping)
        self.assertEqual(db.files[0],dict(before['files'][0],inode=201))
        for table in db.history:self.assertEqual(db.history[table],dict(before['history'][table],cursor_inode=202))
        self.assertEqual(db.events,before['events']);self.assertEqual(db.incidents,before['incidents'])
        self.assertEqual(db.integrity[0],before['integrity'][0]);self.assertEqual(db.integrity[1]['status'],'pending')
        self.assertEqual(db.commits,1)
    def test_checkpoint_mismatch_rolls_back_all_inode_changes(self):
        db=Database();db.history['mail_search_backlog_history_state']['cursor_inode']=999
        before=copy.deepcopy((db.files,db.history,db.integrity));path=sample_mapping(self.folder/'map.sqlite3')
        with sqlite3.connect(path) as mapping,self.assertRaisesRegex(ops.DiskOpsError,'migration_history_checkpoint_changed'):
            migration.remap_checkpoints(db,mapping)
        self.assertEqual((db.files,db.history,db.integrity),before);self.assertEqual(db.rollbacks,1)
    def test_source_checkpoint_change_is_not_reimported(self):
        db=Database();db.files[0]['inode']=999;path=sample_mapping(self.folder/'map.sqlite3')
        with sqlite3.connect(path) as mapping,self.assertRaisesRegex(ops.DiskOpsError,'migration_source_checkpoint_changed'):
            migration.remap_checkpoints(db,mapping)
        self.assertEqual(db.files[0]['inode'],999)
    def tree(self):
        source=self.folder/'old';target=self.folder/'new';source.mkdir();target.mkdir()
        (source/'file').write_bytes(b'unchanged signed bytes\n');os.chmod(source/'file',0o640)
        os.link(source/'file',source/'hardlink');os.setxattr(source/'file','user.fls-test',b'kept')
        shutil.copy2(source/'file',target/'file');os.link(target/'file',target/'hardlink');shutil.copystat(source,target)
        return source,target
    def verify(self,source,target):
        mapping=migration.open_mapping(self.folder/'verify.sqlite3');self.addCleanup(mapping.close)
        return migration.verify_tree(source,target,mapping,'raw',source.stat().st_dev,target.stat().st_dev)
    def test_tree_verifies_sha_acl_xattr_and_hardlinks(self):
        source,target=self.tree();files,size=self.verify(source,target)
        self.assertEqual(files,2);self.assertEqual(size,2*(source/'file').stat().st_size)
    def test_changed_signed_bytes_rejected(self):
        source,target=self.tree();(target/'file').write_bytes(b'different signed bytes\n');shutil.copystat(source/'file',target/'file')
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_content_mismatch'):self.verify(source,target)
    def test_lost_extended_attribute_rejected(self):
        source,target=self.tree();os.removexattr(target/'file','user.fls-test')
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_metadata_mismatch'):self.verify(source,target)
    def test_lost_posix_acl_rejected(self):
        source,target=self.tree()
        acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,permissions,identifier) for tag,permissions,identifier in
            ((1,6,0xffffffff),(2,4,1001),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)))
        try:os.setxattr(source/'file','system.posix_acl_access',acl)
        except OSError as error:self.skipTest('Fixture filesystem does not support POSIX ACL: '+str(error.errno))
        shutil.copystat(source/'file',target/'file');os.removexattr(target/'file','system.posix_acl_access')
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_metadata_mismatch'):self.verify(source,target)
    def test_broken_hardlink_rejected(self):
        source,target=self.tree();(target/'hardlink').unlink();shutil.copy2(source/'hardlink',target/'hardlink');shutil.copystat(source,target)
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_hardlink_mismatch'):self.verify(source,target)
    def test_symlink_does_not_escape_scope(self):
        source,target=self.tree();(source/'escape').symlink_to('/etc');(target/'escape').symlink_to('/etc');shutil.copystat(source,target)
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_special_file'):self.verify(source,target)
    def test_extra_target_file_rejected(self):
        source,target=self.tree();(target/'extra').write_bytes(b'extra');shutil.copystat(source,target)
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_tree_mismatch'):self.verify(source,target)
    def test_nested_filesystem_rejected(self):
        source,target=self.tree()
        with self.assertRaisesRegex(ops.DiskOpsError,'migration_nested_filesystem'):
            mapping=migration.open_mapping(self.folder/'nested.sqlite3')
            try:migration.verify_tree(source,target,mapping,'raw',source.stat().st_dev+1,target.stat().st_dev)
            finally:mapping.close()
    def test_serial_target_has_real_identity_not_fabricated_wwn(self):
        self.assertTrue(ops.valid_physical_identity(DISK));self.assertTrue(DISK['wwn'].startswith('id:'))
        self.assertEqual(ops.CommunityHostOps.disk_key(DISK['physical_identity']),
                         'id:'+__import__('hashlib').sha256(json.dumps(DISK['physical_identity'],sort_keys=True).encode()).hexdigest())
    def test_invalid_identity_and_unsafe_path_are_not_format_candidates(self):
        self.assertFalse(ops.valid_physical_identity(dict(DISK,path='/tmp/vdb')))
        self.assertFalse(ops.valid_physical_identity(dict(DISK,physical_identity={'kind':'serial','value':'../disk'})))
    def test_identity_token_binds_physical_identity_and_disk_sequence(self):
        token=ops.identity_token(JOB['boot_id'],DISK)
        self.assertNotEqual(token,ops.identity_token(JOB['boot_id'],dict(DISK,diskseq=4)))
        self.assertNotEqual(token,ops.identity_token(JOB['boot_id'],dict(DISK,physical_identity={'kind':'serial','value':'OTHER'})))


PHP_FIXTURE = r'''<?php
declare(strict_types=1);
$fixture=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);$job=null;$insertions=0;$actor_reads=0;
class FixturePDO extends PDO {
 public bool $transaction=false;
 public function __construct(){}
 public function beginTransaction():bool {$this->transaction=true;return true;}
 public function commit():bool {$this->transaction=false;return true;}
 public function rollBack():bool {$this->transaction=false;return true;}
 public function inTransaction():bool{return $this->transaction;}
 public function exec(string $statement):int|false{return 0;}
 public function lastInsertId(?string $name=null):string|false{return '1';}
}
$pdo=new FixturePDO();function db():PDO{global $pdo;return $pdo;}
function query(string $sql,array $args=[]):array {
 global $fixture,$job,$actor_reads;
 if(str_contains($sql,'FROM users')){$actor_reads++;return [['id'=>1,'username'=>'fixture-admin','role'=>($fixture['revoked']??false)&&$actor_reads>1?'analyst':($fixture['actor_role']??'admin'),'enabled'=>1,'session_version'=>0,'must_change'=>0]];}
 if(str_contains($sql,'@@SESSION'))return [['value'=>50]];
 if(str_contains($sql,'FROM management_lock'))return [['id'=>1]];
 if(str_contains($sql,'FROM disk_management_state'))return [$fixture['state']];
 if(str_contains($sql,'WHERE request_key='))return [];
 if(str_contains($sql,'FROM disk_management_jobs WHERE id='))return $job?[$job]:[];
 if(str_contains($sql,'FROM disk_management_jobs'))return [];
 throw new RuntimeException('Unexpected fixture query');
}
function execute(string $sql,array $args=[]):void {
 global $job,$insertions;
 if(!str_starts_with($sql,'INSERT INTO disk_management_jobs'))throw new RuntimeException('Unexpected fixture mutation');
 $insertions++;
 $job=array_combine(['request_key','action','requested_by_uid','requested_session_version','requested_by','boot_id','disk_wwn','disk_serial','disk_size_bytes','inventory_token','config_revision','confirmed'],$args);
 $job+=['id'=>1,'status'=>'queued','requested_at'=>gmdate('Y-m-d H:i:s'),'expires_at'=>gmdate('Y-m-d H:i:s',time()+300),'started_at'=>null,'completed_at'=>null,'error_code'=>'','result_json'=>null];
}
function audit(string $a,string $b):void{}
$_SESSION=['uid'=>1,'session_version'=>0,'role'=>$fixture['session_role']??'admin','csrf'=>'fixture-csrf'];
$_SERVER=['REQUEST_METHOD'=>$fixture['method']??'POST','HTTP_X_CSRF_TOKEN'=>$fixture['csrf']??'fixture-csrf'];
require __DIR__.'/disk-management.php';
try{$result=($fixture['operation']??'write')==='state'?disk_management_state($fixture['state']):disk_management_write($fixture['route']??'prepare_primary_disk',$fixture['request']);echo json_encode(['ok'=>true,'result'=>$result,'insertions'=>$insertions]);}
catch(ManagementError $error){echo json_encode(['ok'=>false,'status'=>$error->status,'insertions'=>$insertions]);}
'''


@unittest.skipUnless(shutil.which('php'),'PHP CLI needed for isolated API fixtures')
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fls-community-disk-api-');self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        source=OVERLAY.parent/'app/disk-management.php' if OVERLAY.exists() else ROOT/'app/disk-management.php'
        shutil.copy2(source,self.folder/'disk-management.php')
        shutil.copy2(ROOT/'app/management.php',self.folder/'management.php')
        (self.folder/'fixture.php').write_text(PHP_FIXTURE)
    def run_case(self,**changes):
        import datetime
        now=datetime.datetime.now(datetime.timezone.utc).isoformat()
        system=dict(wwn='id:'+'1'*64,serial='VM-ROOT',model='VM root',size_bytes=128*1024**3)
        candidate=dict(wwn=DISK['wwn'],serial=DISK['serial'],model='VM extra',size_bytes=DISK['size_bytes'],eligible=True,reasons=[],token='b'*64)
        inventory=dict(schema=1,mode='system-root',boot_id=JOB['boot_id'],generated_at_utc=now,system=system,depot=None,mirror=None,candidates=[candidate])
        state=dict(id=1,version=1,boot_id=JOB['boot_id'],status='idle',error_code='',checked_at=now,config_revision=0,inventory_json=json.dumps(inventory))
        request=dict(request_key=JOB['request_key'],boot_id=JOB['boot_id'],inventory_token='b'*64,candidate_wwn=DISK['wwn'],confirmation='TAMAM')
        value=dict(state=state,request=request)
        value.update(changes)
        result=subprocess.run(['php',str(self.folder/'fixture.php')],input=json.dumps(value),text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)
    def test_single_disk_state_accepts_generic_identity_and_absent_depot(self):
        value=self.run_case(operation='state');self.assertTrue(value['ok']);self.assertTrue(value['result']['available'])
        self.assertEqual(value['result']['mode'],'system-root');self.assertIsNone(value['result']['depot'])
    def test_admin_primary_migration_creates_distinct_job(self):
        value=self.run_case();self.assertTrue(value['ok']);self.assertEqual(value['insertions'],1)
        self.assertEqual(value['result']['job']['action'],'migrate');self.assertEqual(value['result']['job']['confirmed'],1)
    def test_wrong_session_or_database_role_denied(self):
        for change in ({'session_role':'analyst'},{'actor_role':'analyst'},{'revoked':True}):
            value=self.run_case(**change);self.assertFalse(value['ok']);self.assertEqual(value['status'],403);self.assertEqual(value['insertions'],0)
    def test_csrf_and_http_method_rejected(self):
        for change,status in (({'csrf':'wrong'},403),({'method':'GET'},405)):
            value=self.run_case(**change);self.assertFalse(value['ok']);self.assertEqual(value['status'],status);self.assertEqual(value['insertions'],0)
    def test_confirmation_must_be_exact_and_fields_closed(self):
        base=dict(request_key=JOB['request_key'],boot_id=JOB['boot_id'],inventory_token='b'*64,candidate_wwn=DISK['wwn'],confirmation='tamam')
        for request in (base,dict(base,confirmation='TAMAM',target='/dev/sda')):
            value=self.run_case(request=request);self.assertFalse(value['ok']);self.assertEqual(value['insertions'],0)
    def test_stale_token_cannot_select_generic_disk(self):
        request=dict(request_key=JOB['request_key'],boot_id=JOB['boot_id'],inventory_token='c'*64,candidate_wwn=DISK['wwn'],confirmation='TAMAM')
        value=self.run_case(request=request);self.assertFalse(value['ok']);self.assertEqual(value['status'],409);self.assertEqual(value['insertions'],0)
    def test_mirror_endpoint_cannot_bypass_primary_migration_role(self):
        value=self.run_case(route='prepare_mirror_disk');self.assertFalse(value['ok']);self.assertEqual(value['status'],409);self.assertEqual(value['insertions'],0)


class LinuxAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fls-community-host-adapter-');self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.commands=[];self.stopped=set()
        for name in ('var/lib/fls-disks','var/lib/fls-maintenance','etc/systemd/system','proc'):
            (self.folder/name).mkdir(parents=True,mode=0o700)
        self.state=self.folder/'var/lib/fls-disks';self.journal=migration.MigrationJournal(self.state,owner=os.geteuid())
        self.journal.begin(JOB,SOURCE,DISK)
        self.adapter=migration.LinuxMigration(None,Database(),self.journal,lambda:True,runner=self.runner)
        original_atomic=migration.atomic
        def fixture_path(value='.',*args):
            path=Path(value,*args)
            if path.is_absolute() and str(path).startswith(('/etc/systemd/system','/var/lib/fls','/proc')):
                return self.folder/path.relative_to('/')
            return path
        self.addCleanup(patch.stopall)
        patch.object(migration,'Path',fixture_path).start()
        patch.object(migration,'STATE',self.state).start()
        patch.object(migration,'atomic',lambda path,value,mode=0o600,**kwargs:original_atomic(path,value,mode,owner=os.geteuid())).start()
    def runner(self,args,**kwargs):
        self.commands.append(args)
        if 'list-unit-files' in args:
            output='\n'.join(name+' enabled enabled' for name in ('fortigate-collector.service','fls-indexer.service','fls-integrity.service','fls-integrity.timer','fls-cold-canary@.service','fls-maintenance.service','fls-maintenance.timer','fls-disk-management.service','mariadb.service','php8.3-fpm.service','nginx.service'))
        elif 'list-units' in args:output='fls-cold-canary@7.service loaded active running test\n'
        elif 'show' in args:
            unit=args[args.index('show')+1];stopped=unit in self.stopped
            output='ActiveState='+('inactive' if stopped else 'active')+'\nMainPID='+('0' if stopped or unit.endswith('.timer') else '44')+'\nUnitFileState=enabled\n'
        elif 'stop' in args:
            self.stopped.add(args[-1]);output=''
        elif 'systemd-escape' in args[0]:
            output=args[-1].lstrip('/').replace('-','\\x2d').replace('/','-')+'.mount\n'
        else:output=''
        return type('Result',(),dict(returncode=0,stdout=output,stderr=''))()
    def test_quiesce_guards_all_writers_templates_and_timers_but_keeps_panel_db_jobs(self):
        self.adapter.quiesce()
        self.assertIn('fortigate-collector.service',self.stopped);self.assertIn('fls-indexer.service',self.stopped)
        self.assertIn('fls-cold-canary@7.service',self.stopped);self.assertNotIn('fls-cold-canary@.service',self.stopped)
        for unit in ('mariadb.service','nginx.service','php8.3-fpm.service','fls-disk-management.service'):
            self.assertNotIn(unit,self.stopped)
        self.assertTrue((self.state/'migration-paused').exists())
        self.assertTrue((self.folder/'etc/systemd/system/fls-cold-canary@.service.d/90-fls-primary-migration.conf').exists())
        stops=[args[-1] for args in self.commands if 'stop' in args]
        self.assertLess(stops.index('fls-integrity.timer'),stops.index('fls-indexer.service'))
        self.assertTrue((self.folder/'var/lib/fls-maintenance/paused').exists())
    def test_open_write_handle_blocks_copy(self):
        process=self.folder/'proc/123';(process/'fd').mkdir(parents=True);(process/'fdinfo').mkdir()
        raw=self.folder/'migration-scope/raw';raw.mkdir(parents=True)
        (process/'fd/4').symlink_to(raw/'2026-11-13-07.jsonl')
        (process/'fdinfo/4').write_text('flags:\t0100002\n')
        with patch.object(migration,'SCOPE',((str(raw),'FLS-Logs/raw'),)),self.assertRaisesRegex(ops.DiskOpsError,'migration_writer_handle_open'):
            self.adapter.assert_no_writable_handles()
    def test_read_only_download_handle_is_allowed(self):
        process=self.folder/'proc/123';(process/'fd').mkdir(parents=True);(process/'fdinfo').mkdir()
        published=self.folder/'migration-scope/published';published.mkdir(parents=True)
        (process/'fd/4').symlink_to(published/'backup.age')
        (process/'fdinfo/4').write_text('flags:\t0100000\n')
        with patch.object(migration,'SCOPE',((str(published),'FLS-Backups/published'),)):
            self.adapter.assert_no_writable_handles()
    def test_marker_disk_full_still_stops_scope_writers(self):
        self.journal.value['writers']=[{'unit':'fortigate-collector.service'},{'unit':'fls-indexer.service'}]
        with patch.object(migration,'atomic',side_effect=OSError(28,'Fixture disk full')),self.assertRaises(OSError):
            self.adapter.fail_closed()
        self.assertEqual(self.stopped,{'fortigate-collector.service','fls-indexer.service'})
    def test_cutover_publishes_uuid_mounts_binds_dependencies_and_schema_two(self):
        self.adapter.quiesce();self.adapter.source=copy.deepcopy(SOURCE)
        patch.object(self.adapter,'config',return_value=copy.deepcopy(SOURCE)).start()
        config=self.folder/'storage.json';config.write_text(json.dumps(SOURCE));patch.object(migration,'CONFIG',config).start()
        target=dict(uuid='7b762ad7-1e87-4f61-ade4-7289816cfaae',physical_identity=DISK['physical_identity'])
        self.adapter.cutover(target)
        result=json.loads(config.read_text())
        self.assertEqual(result['schema'],2);self.assertEqual(result['queue_location'],'system')
        self.assertEqual(result['depot_identity'],DISK['physical_identity']);self.assertNotIn('depot_wwn',result)
        mount_files=list((self.folder/'etc/systemd/system').glob('*.mount'));self.assertEqual(len(mount_files),7)
        self.assertTrue(any('DB-Dump' in path.read_text() for path in mount_files))
        dependency=self.folder/'etc/systemd/system/fls-indexer.service.d/91-fls-primary-dependencies.conf'
        self.assertIn('BindsTo=srv-fls',dependency.read_text());self.assertNotIn('/srv/fortigate/queue',dependency.read_text())


class WorkerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0,'/usr/lib/python3/dist-packages')
        for name in ('disk-management-worker','provision-disk-management'):
            specification=importlib.util.spec_from_file_location(name,(OVERLAY if OVERLAY.is_dir() else ROOT/'bin')/(name+'.py'))
            module=importlib.util.module_from_spec(specification);specification.loader.exec_module(module)
            setattr(cls,'worker' if name.startswith('disk-') else 'provision',module)
    def test_worker_dispatches_migration_to_real_state_machine_and_claims_once(self):
        worker=self.worker
        with tempfile.TemporaryDirectory(prefix='fls-community-worker-') as temporary:
            folder=Path(temporary);folder.chmod(0o700)
            job=dict(JOB,action='migrate',confirmed=1,inventory_token='c'*64,
                     disk_wwn=DISK['wwn'],disk_serial=DISK['serial'],disk_size_bytes=DISK['size_bytes'])
            observed=dict(DISK,boot_id=JOB['boot_id'],observed_at='2026-11-13T00:00:00+00:00',identity_token='d'*64)
            plans=dict(boot_id=JOB['boot_id'],plans={'c'*64:observed})
            class Store:
                connection=Database()
                def guard(self,job,initial=False):return True
            class Journal:
                claims=0
                def read(self):return {'high_water':0}
                def record(self,job):self.claims+=1
            journal=Journal();host=type('Host',(),{'config':lambda self:SOURCE})()
            original=migration.MigrationJournal
            def adapter(host,connection,record,guard):return Adapter(folder,record)
            with patch.object(worker,'mirror_config',return_value=None),patch.object(worker,'safe_json',return_value=plans),\
                 patch.object(worker,'boot_id',return_value=JOB['boot_id']),patch.object(worker,'STATE',folder),\
                 patch.object(worker,'MigrationJournal',side_effect=lambda path:original(path,owner=os.geteuid())),\
                 patch.object(worker,'LinuxMigration',side_effect=adapter):
                result=worker.process(Store(),host,journal,job)
            self.assertEqual(result['phase'],'complete');self.assertEqual(journal.claims,1)
    def test_installed_role_grants_only_narrow_checkpoint_updates(self):
        class Cursor:
            statements=[]
            def execute(self,sql,args=()):self.statements.append(sql)
        cursor=Cursor();self.provision.configure_role(cursor,'fixture-no-real-password')
        self.assertIn('GRANT SELECT(id,name,inode,byte_offset,line_number,observed_size,invalid_rows),UPDATE(inode) ON fls.source_files TO fls_disks@localhost',cursor.statements)
        for table in ('summary_backlog_history_state','mail_search_backlog_history_state'):
            self.assertTrue(any('UPDATE(cursor_inode) ON fls.'+table in query for query in cursor.statements))
        self.assertFalse(any('ALL PRIVILEGES' in query and query.startswith('GRANT') for query in cursor.statements))
        self.assertFalse(any('ON fls.events ' in query for query in cursor.statements))
    def test_schema_two_hybrid_normalizes_legacy_mirror_keys_without_rewriting_configuration(self):
        config=dict(SOURCE,mode='hybrid',depot_uuid='7b762ad7-1e87-4f61-ade4-7289816cfaae',
                    depot_identity={'kind':'wwn','value':'0x2000000000000002'},depot_path='/srv/fls-storage',queue_location='system')
        host=ops.CommunityHostOps(storage_loader=lambda:True)
        with patch.object(host,'config',return_value=config):result=host._storage()
        self.assertEqual(result['depot_wwn'],'0x2000000000000002');self.assertTrue(result['device_wwn'].startswith('id:'))
        self.assertNotIn('depot_wwn',config)


class GenericMirrorTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime.datetime.now(datetime.timezone.utc);self.commands=[];self.events=[]
        self.root_uuid=SOURCE['root_uuid'];self.depot_uuid='7b762ad7-1e87-4f61-ade4-7289816cfaae'
        self.mirror_uuid='8b762ad7-1e87-4f61-ade4-7289816cfaae'
        def disk(serial,path,number):
            identity={'kind':'serial','value':serial}
            return dict(wwn=ops.CommunityHostOps.disk_key(identity),physical_identity=identity,serial=serial,model='VM disk',
                        path=path,major_minor=number,size_bytes=64*1024**3,logical_sector=512,diskseq=3,
                        partitions=[],signatures=[],blockers=[])
        self.disks=[disk('VM-DISK-ONE','/dev/vda','253:0'),disk('VM-DISK-TWO','/dev/vdb','253:16'),disk('VM-DISK-THREE','/dev/vdc','253:32')]
        config=dict(SOURCE,mode='hybrid',depot_uuid=self.depot_uuid,depot_identity=self.disks[1]['physical_identity'],depot_path='/srv/fls-storage',queue_location='system')
        fixture=self
        class Probe:
            def snapshot(self):return {'boot_id':JOB['boot_id'],'disks':copy.deepcopy(fixture.disks)}
            @contextlib.contextmanager
            def hold_disk(self,disk):yield
            def mountpoint_ready(self):pass
            def make_mountpoint(self):pass
            def partition_ready(self,disk):return disk['path']+'1'
            def mounted(self,path,identifier,physical):
                expected=(fixture.depot_uuid,fixture.disks[1]['physical_identity']) if path==ops.DEPOT else (fixture.mirror_uuid,fixture.disks[2]['physical_identity'])
                if (identifier,physical)!=expected:raise AssertionError('Filesystem identity not passed as pinned dict')
                return 100 if path==ops.DEPOT else 200
            def initialize_clone_dirs(self,a,b):fixture.events.append('initialize')
            def clone_directories(self,path,device):pass
            @contextlib.contextmanager
            def hold_filesystems(self,state,mirror):yield dict(source='/synthetic/source/',target='/synthetic/target/',pass_fds=())
        self.host=ops.CommunityHostOps(runner=self.runner,storage_loader=lambda:True,clock=lambda:self.now,
            mutation_guard=lambda request:True,producer_guard=lambda:True,probe=Probe(),mirror_loader=lambda:None)
        self.addCleanup(patch.stopall)
        patch.object(self.host,'config',return_value=config).start()
        patch.object(ops,'filesystem_identity',return_value=('253:1',Path('/synthetic/root-disk'))).start()
        patch.object(ops,'trusted_read',return_value='253:0').start()
    def runner(self,args,**kwargs):
        self.commands.append(args);self.events.append(Path(args[0]).name)
        text='TYPE=ext4\nUUID='+self.mirror_uuid+'\n' if args[0].endswith('blkid') else ''
        return type('Result',(),dict(returncode=0,stdout=text,stderr=''))()
    def request(self):
        inventory=self.host.inventory();candidate=inventory['disks'][2]
        return {**{field:candidate[field] for field in (*ops.IDENTITY_FIELDS,'identity_token')},
                'request_key':JOB['request_key'],'confirmation':'TAMAM','boot_id':JOB['boot_id'],'observed_at':inventory['observed_at']}
    def test_generic_third_disk_preparation_is_executable_and_journaled(self):
        def claimed(*args):self.events.append('durable-journal');return True
        result=self.host.prepare(self.request(),claimed)
        self.assertEqual(result['physical_identity'],self.disks[2]['physical_identity'])
        self.assertEqual(result['uuid'],self.mirror_uuid)
        self.assertLess(self.events.index('durable-journal'),self.events.index('sfdisk'))
        self.assertEqual(self.commands[0][-1],'/dev/vdc')
        self.assertFalse(any('id:' in argument for command in self.commands for argument in command if isinstance(argument,str)))
    def mirror(self):
        mirror=dict(schema=1,wwn=self.disks[2]['wwn'],physical_identity=self.disks[2]['physical_identity'],
                    serial=self.disks[2]['serial'],size_bytes=self.disks[2]['size_bytes'],uuid=self.mirror_uuid,path='/srv/fls-mirror')
        self.disks[2]['signatures']=[{'partition_table':'gpt'}]
        self.disks[2]['partitions']=[dict(type='part',fstype='ext4',uuid=self.mirror_uuid)]
        return mirror
    def test_generic_primary_and_third_sync_have_full_physical_guards(self):
        result=self.host.sync(self.mirror());self.assertEqual(result['status'],'complete')
        rsync=next(command for command in self.commands if command[0].endswith('rsync'))
        self.assertIn('-aHAXS',rsync);self.assertIn('--delete-delay',rsync)
    def test_changed_generic_mirror_identity_refuses_sync_before_commands(self):
        mirror=self.mirror();self.disks[2]['physical_identity']={'kind':'serial','value':'CHANGED-DISK'}
        with self.assertRaises(ops.DiskOpsError):self.host.sync(mirror)
        self.assertEqual(self.commands,[])


if __name__=='__main__':unittest.main()
