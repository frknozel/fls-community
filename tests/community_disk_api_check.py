#!/usr/bin/python3
"""Execute the real Community PHP readmodel against isolated in-memory fixtures.

No database, HTTP endpoint, block device, service or production file is opened.
The PDO adapter records administrator intents without executing any SQL.
"""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / 'tools/community/overlay'
PHP = os.environ.get('FLS_TEST_PHP') or shutil.which('php')
BOOT = '65d49517-bb1b-44da-8fce-88162d1301c1'
REQUEST = '6f232822-d9ec-4338-abd9-75cafec3d75f'
ROOT_KEY = 'id:' + '1' * 64
EXTRA_KEY = 'id:' + '2' * 64
TOKEN = 'a' * 64

PHP_FIXTURE = r'''<?php
declare(strict_types=1);
$fixture=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
$insertions=0;$actorReads=0;$job=null;
class FixturePDO extends PDO {
 public bool $transaction=false;
 public function __construct(){}
 public function beginTransaction():bool{$this->transaction=true;return true;}
 public function commit():bool{$this->transaction=false;return true;}
 public function rollBack():bool{$this->transaction=false;return true;}
 public function inTransaction():bool{return $this->transaction;}
 public function exec(string $statement):int|false{return 0;}
 public function lastInsertId(?string $name=null):string|false{return '1';}
}
$pdo=new FixturePDO();
function db():PDO{global $pdo;return $pdo;}
function query(string $sql,array $args=[]):array{
 global $fixture,$actorReads,$job;
 if(str_contains($sql,'FROM users')){
  $actorReads++;
  $row=['id'=>1,'username'=>'fixture-admin','role'=>'admin','enabled'=>1,'session_version'=>0,'must_change'=>0];
  $row=array_replace($row,$fixture['actor']??[]);
  if(($fixture['revoked']??false)&&$actorReads>1)$row['role']='analyst';
  return [$row];
 }
 if(str_contains($sql,'@@SESSION'))return [['value'=>50]];
 if(str_contains($sql,'FROM management_lock'))return [['id'=>1]];
 if(str_contains($sql,'FROM disk_management_state'))return isset($fixture['state'])?[$fixture['state']]:[];
 if(str_contains($sql,'FROM disk_management_jobs WHERE id='))return $job?[$job]:[];
 if(str_contains($sql,'FROM disk_management_jobs'))return [];
 throw new RuntimeException('Unexpected fixture query');
}
function execute(string $sql,array $args=[]):void{
 global $job,$insertions;
 if(!str_starts_with($sql,'INSERT INTO disk_management_jobs'))throw new RuntimeException('Unexpected fixture mutation');
 $insertions++;
 $job=array_combine(['request_key','action','requested_by_uid','requested_session_version','requested_by','boot_id','disk_wwn','disk_serial','disk_size_bytes','inventory_token','config_revision','confirmed'],$args);
 $job+=['id'=>1,'status'=>'queued','requested_at'=>gmdate('Y-m-d H:i:s'),'expires_at'=>gmdate('Y-m-d H:i:s',time()+300),'started_at'=>null,'completed_at'=>null,'error_code'=>'','result_json'=>null];
}
function audit(string $action,string $detail):void{}
$_SESSION=array_replace(['uid'=>1,'session_version'=>0,'role'=>'admin','csrf'=>'fixture-csrf'],$fixture['session']??[]);
$_SERVER=['REQUEST_METHOD'=>$fixture['method']??'GET','HTTP_X_CSRF_TOKEN'=>$fixture['csrf']??'fixture-csrf'];
require __DIR__.'/disk-management.php';
try{
 $result=match($fixture['operation']??'snapshot'){
  'state'=>disk_management_state($fixture['state']??null),
  'write'=>disk_management_write($fixture['route']??'prepare_primary_disk',$fixture['request']??[]),
  default=>disk_management_snapshot()
 };
 echo json_encode(['ok'=>true,'result'=>$result,'insertions'=>$insertions],JSON_THROW_ON_ERROR);
}catch(ManagementError $error){echo json_encode(['ok'=>false,'status'=>$error->status,'insertions'=>$insertions],JSON_THROW_ON_ERROR);}
'''


@unittest.skipUnless(PHP, 'PHP CLI is required for isolated disk API fixtures')
class DiskApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fls-community-disk-readmodel-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        source = OVERLAY / 'app/disk-management.php' if OVERLAY.is_dir() else ROOT / 'app/disk-management.php'
        shutil.copy2(source, self.folder / 'disk-management.php')
        shutil.copy2(ROOT / 'app/recovery-rehearsal.php', self.folder / 'recovery-rehearsal.php')
        shutil.copy2(ROOT / 'app/management.php', self.folder / 'management.php')
        (self.folder / 'fixture.php').write_text(PHP_FIXTURE)

    def inventory(self):
        return dict(schema=1, mode='system-root', boot_id=BOOT,
                    generated_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    system=dict(wwn=ROOT_KEY, serial='VM-ROOT', model='VMware virtual disk',
                                size_bytes=200 * 1024**3, present=True),
                    depot=None, mirror=None,
                    candidates=[dict(wwn=EXTRA_KEY, serial='VM-EXTRA', model='Extra virtual disk',
                                     size_bytes=300 * 1024**3, eligible=True, reasons=[], token=TOKEN)])

    def state(self, inventory=None, **changes):
        if inventory is None:
            inventory = self.inventory()
        result = dict(id=1, version=1, boot_id=BOOT, status='idle', error_code='', config_revision=0,
                      checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      inventory_json=json.dumps(inventory))
        return dict(result, **changes)

    def request(self, **changes):
        return dict(dict(request_key=REQUEST, boot_id=BOOT, inventory_token=TOKEN,
                         candidate_wwn=EXTRA_KEY, confirmation='TAMAM'), **changes)

    def run_case(self, **changes):
        fixture=dict(state=self.state(), request=self.request())
        fixture.update(changes)
        process=subprocess.run([PHP, str(self.folder / 'fixture.php')], input=json.dumps(fixture),
                               text=True, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, '', process.stderr)
        return json.loads(process.stdout)

    def assert_closed(self, result):
        self.assertFalse(result['available'])
        for name in ('can_migrate', 'can_prepare', 'can_sync'):
            if name in result:
                self.assertFalse(result[name], name)

    def test_unknown_state_has_no_invented_disk_or_storage_mode(self):
        value=self.run_case(state=None)['result']
        self.assert_closed(value)
        self.assertIsNone(value['mode'])
        self.assertIsNone(value['system'])
        self.assertIsNone(value['depot'])
        self.assertIsNone(value['mirror'])
        self.assertEqual(value['error_code'], 'worker_unavailable')

    def test_initial_database_row_is_unavailable(self):
        value=self.run_case(state=self.state(boot_id='', checked_at=None, inventory_json=None))['result']
        self.assert_closed(value)
        self.assertIsNone(value['mode'])
        self.assertIsNone(value['system'])

    def test_first_worker_failure_preserves_safe_code_without_roles(self):
        value=self.run_case(state=self.state(status='error', error_code='disk_operation_failed', inventory_json=None))['result']
        self.assert_closed(value)
        self.assertFalse(value['fresh'])
        self.assertEqual(value['error_code'], 'disk_operation_failed')
        self.assertEqual(value['boot_id'], BOOT)
        self.assertIsNone(value['mode'])
        self.assertIsNone(value['system'])

    def test_missing_payload_does_not_preserve_error_without_valid_metadata(self):
        for changes in (dict(boot_id='bad'), dict(id=2), dict(version=2), dict(config_revision=-1),
                        dict(checked_at='bad'), dict(checked_at=None), dict(error_code='traceback /root/key')):
            with self.subTest(changes=changes):
                state=self.state(status='error', error_code='disk_operation_failed', inventory_json=None)
                state.update(changes)
                value=self.run_case(state=state)['result']
                self.assert_closed(value)
                self.assertEqual(value['error_code'], 'state_invalid')

    def test_corrupt_or_oversized_payload_never_preserves_worker_error(self):
        for payload in ('{', 'null', '[]', '{}', '', 'x' * 262145, 0, False):
            with self.subTest(payload_type=type(payload).__name__, length=len(payload) if isinstance(payload,str) else None):
                value=self.run_case(state=self.state(status='error', error_code='disk_operation_failed', inventory_json=payload))['result']
                self.assert_closed(value)
                self.assertEqual(value['error_code'], 'state_invalid')
                self.assertIsNone(value['mode'])

    def test_missing_inventory_on_idle_is_not_a_success(self):
        value=self.run_case(state=self.state(inventory_json=None))['result']
        self.assert_closed(value)
        self.assertEqual(value['error_code'], 'state_invalid')

    def test_fresh_single_disk_with_generic_identity_is_present_and_can_migrate(self):
        value=self.run_case()['result']
        self.assertTrue(value['fresh'])
        self.assertTrue(value['available'])
        self.assertTrue(value['system']['present'])
        self.assertEqual(value['system']['wwn'], ROOT_KEY)
        self.assertEqual(value['mode'], 'system-root')
        self.assertTrue(value['can_migrate'])
        self.assertFalse(value['can_prepare'])
        self.assertFalse(value['can_sync'])

    def test_canonical_naa_accepted_but_raw_esxi_naa_rejected(self):
        inventory=self.inventory()
        inventory['system']['wwn']='0x5000c500aabbccdd'
        self.assertTrue(self.run_case(state=self.state(inventory))['result']['available'])
        inventory['system']['wwn']='0x6000c291ad565afe257e9d2e430aabdb'
        value=self.run_case(state=self.state(inventory))['result']
        self.assert_closed(value)
        self.assertEqual(value['error_code'], 'state_invalid')

    def test_role_presence_is_a_strict_boolean(self):
        for present in (None, 0, 1, 'true', 'false', '0', '1', [], {}):
            with self.subTest(present=present):
                inventory=self.inventory()
                inventory['system']['present']=present
                value=self.run_case(state=self.state(inventory))['result']
                self.assert_closed(value)
                self.assertIsNone(value['system'])
                self.assertEqual(value['error_code'], 'state_invalid')
        inventory=self.inventory()
        del inventory['system']['present']
        self.assert_closed(self.run_case(state=self.state(inventory))['result'])

    def test_explicit_missing_system_is_visible_but_never_writable(self):
        inventory=self.inventory()
        inventory['system']['present']=False
        value=self.run_case(state=self.state(inventory))['result']
        self.assertFalse(value['system']['present'])
        self.assert_closed(value)

    def test_stale_or_future_state_is_never_writable(self):
        for seconds in (-60, 60):
            moment=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=seconds)).isoformat()
            inventory=self.inventory()
            inventory['generated_at_utc']=moment
            value=self.run_case(state=self.state(inventory, checked_at=moment))['result']
            self.assert_closed(value)
            self.assertFalse(value['fresh'])

    def test_valid_inventory_in_worker_error_keeps_roles_but_blocks_actions(self):
        value=self.run_case(state=self.state(status='error', error_code='operation_interrupted'))['result']
        self.assert_closed(value)
        self.assertEqual(value['system']['wwn'], ROOT_KEY)
        self.assertEqual(value['error_code'], 'operation_interrupted')

    def test_malformed_inventory_never_leaves_a_partially_valid_storage_mode(self):
        inventory=self.inventory()
        inventory['system']['size_bytes']=0
        value=self.run_case(state=self.state(inventory))['result']
        self.assert_closed(value)
        self.assertIsNone(value['mode'])
        self.assertIsNone(value['system'])

    def test_missing_storage_mode_is_not_assumed_hybrid(self):
        inventory=self.inventory()
        del inventory['mode']
        value=self.run_case(state=self.state(inventory))['result']
        self.assert_closed(value)
        self.assertIsNone(value['mode'])

    def test_root_mode_cannot_have_a_mirror_without_depot(self):
        inventory=self.inventory()
        inventory['mirror']=dict(inventory['system'], wwn='id:'+'3'*64, serial='VM-MIRROR')
        value=self.run_case(state=self.state(inventory))['result']
        self.assert_closed(value)
        self.assertEqual(value['error_code'], 'state_invalid')

    def test_primary_source_identity_and_serial_are_never_candidates(self):
        for selector in ('wwn', 'serial'):
            with self.subTest(selector=selector):
                inventory=self.inventory()
                inventory['candidates'][0][selector]=inventory['system'][selector]
                state=self.state(inventory)
                value=self.run_case(state=state)['result']
                self.assertFalse(value['can_migrate'])
                self.assertFalse(value['candidates'][0]['eligible'])
                self.assertIn('protected_role', value['candidates'][0]['reasons'])
                request=self.request(candidate_wwn=inventory['candidates'][0]['wwn'])
                write=self.run_case(state=state, request=request, operation='write', method='POST')
                self.assertFalse(write['ok'])
                self.assertEqual(write['status'], 409)
                self.assertEqual(write['insertions'], 0)

    def hybrid(self):
        inventory=self.inventory()
        inventory['mode']='hybrid'
        inventory['depot']=dict(inventory['system'], wwn='id:'+'3'*64, serial='VM-DEPOT')
        inventory['mirror']=dict(inventory['system'], wwn='id:'+'4'*64, serial='VM-MIRROR')
        return inventory

    def test_mirror_sync_requires_explicit_present_true(self):
        inventory=self.hybrid()
        self.assertTrue(self.run_case(state=self.state(inventory))['result']['can_sync'])
        inventory['mirror']['present']=False
        value=self.run_case(state=self.state(inventory))['result']
        self.assertFalse(value['can_sync'])
        self.assertFalse(value['mirror']['present'])
        request=dict(request_key=REQUEST, boot_id=BOOT)
        write=self.run_case(state=self.state(inventory), operation='write', method='POST',
                            route='sync_mirror_disk', request=request)
        self.assertFalse(write['ok'])
        self.assertEqual(write['status'], 409)
        self.assertEqual(write['insertions'], 0)

    def test_missing_depot_stops_all_hybrid_writes(self):
        inventory=self.hybrid()
        inventory['depot']['present']=False
        self.assert_closed(self.run_case(state=self.state(inventory))['result'])

    def test_admin_session_database_and_lock_time_role_rechecked(self):
        for changes in (dict(session={'role':'analyst'}), dict(actor={'role':'analyst'}), dict(revoked=True)):
            with self.subTest(changes=changes):
                value=self.run_case(operation='write', method='POST', **changes)
                self.assertFalse(value['ok'])
                self.assertEqual(value['status'], 403)
                self.assertEqual(value['insertions'], 0)

    def test_database_boolean_and_session_values_reject_permissive_casts(self):
        for key, values in (('enabled', ('1tail', 1.5, True, False, '01', '1.0')),
                            ('must_change', ('0tail', 0.5, False, True, '00', '0.0')),
                            ('session_version', ('0tail', 0.5, False, True, '00', '0.0'))):
            for item in values:
                with self.subTest(key=key, value=item):
                    value=self.run_case(actor={key:item})
                    self.assertFalse(value['ok'])
                    self.assertEqual(value['status'], 403)
                    self.assertEqual(value['insertions'], 0)

    def test_canonical_pdo_string_flags_still_work(self):
        value=self.run_case(actor=dict(enabled='1', must_change='0', session_version='0'))
        self.assertTrue(value['ok'])
        self.assertTrue(value['result']['available'])

    def test_http_csrf_and_exact_confirmation_remain_mandatory(self):
        for changes, status in ((dict(method='GET'),405), (dict(method='POST',csrf='wrong'),403),
                                (dict(method='POST', request=self.request(confirmation='tamam')),422)):
            with self.subTest(changes=changes):
                value=self.run_case(operation='write', **changes)
                self.assertFalse(value['ok'])
                self.assertEqual(value['status'], status)
                self.assertEqual(value['insertions'], 0)

    def test_current_admin_can_queue_only_a_valid_distinct_migration(self):
        value=self.run_case(operation='write', method='POST')
        self.assertTrue(value['ok'])
        self.assertEqual(value['insertions'], 1)
        self.assertEqual(value['result']['job']['action'], 'migrate')
        self.assertEqual(value['result']['job']['confirmed'], 1)

    def test_first_worker_failure_never_queues_a_job(self):
        state=self.state(status='error', error_code='disk_operation_failed', inventory_json=None)
        value=self.run_case(state=state, operation='write', method='POST')
        self.assertFalse(value['ok'])
        self.assertEqual(value['status'], 503)
        self.assertEqual(value['insertions'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
