#!/usr/bin/python3
"""Pure PHP recovery-context fixtures; no live database, services or network."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / 'tools/community/overlay'


def variants(relative):
    paths = [ROOT / relative]
    public = OVERLAY / relative
    if public.is_file():
        paths.append(public)
    return paths


MANAGEMENT = r'''<?php
final class ManagementError extends RuntimeException {
 public function __construct(string $message, public int $status=422) { parent::__construct($message); }
}
function db() { throw new RuntimeException('fixture_database_forbidden'); }
function execute(string $sql,array $args=[]): void { throw new RuntimeException('fixture_write_forbidden'); }
function query(string $sql,array $args=[]): array {
 $GLOBALS['reads'][]=$sql;
 if(($GLOBALS['query_mode']??'')==='maintenance') {
  if(str_starts_with($sql,'SELECT requested_mode,'))return [['requested_mode'=>'paused','revision'=>1,'requested_at'=>gmdate('Y-m-d H:i:s'),'requested_by'=>'fixture']];
  if(str_starts_with($sql,'SELECT version,'))return [['version'=>1,'applied_revision'=>1,'attempted_revision'=>1,'collector_state'=>'inactive','marker_present'=>1,'checked_at'=>gmdate('Y-m-d H:i:s'),'applied_at'=>gmdate('Y-m-d H:i:s'),'error_code'=>'']];
 }
 if(($GLOBALS['query_mode']??'')==='actor'&&str_starts_with($sql,'SELECT id,username,role,enabled,session_version,must_change FROM users WHERE id='))return [['id'=>1,'username'=>'fixture','role'=>'admin','enabled'=>1,'session_version'=>0,'must_change'=>0]];
 throw new RuntimeException('fixture_query_forbidden');
}
function management_write(string $route,array $data): array { return ['fixture_passed_route'=>$route]; }
'''

BOOTSTRAP = r'''<?php
require_once __DIR__.'/recovery-rehearsal.php';
$request=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$_GET=['route'=>$request['route']];$_POST=$request['post']??[];
$_SERVER=$request['server']??[];$_SERVER['REQUEST_METHOD']=$request['method']??'POST';
session_save_path(__DIR__.'/../sessions');session_id('fixture-rehearsal');session_start();
$_SESSION=['username'=>'fixture','uid'=>1,'role'=>$request['role']??'admin','must_change'=>false,'csrf'=>'fixture-token'];
function authenticated(): bool { return true; }
function json_response(mixed $value,int $status=200): never { echo json_encode(['status'=>$status,'body'=>$value],JSON_THROW_ON_ERROR);exit; }
'''


class RehearsalFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-rehearsal-context-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'app').mkdir()
        (self.root / 'public').mkdir()
        (self.root / 'sessions').mkdir()
        shutil.copyfile(ROOT / 'app/recovery-rehearsal.php', self.root / 'app/recovery-rehearsal.php')
        (self.root / 'app/management.php').write_text(MANAGEMENT)

    def php(self, code, payload=None):
        result = subprocess.run(['php', '-d', 'display_errors=stderr', '-r', code, str(self.root)],
                                input=json.dumps(payload), capture_output=True, text=True, check=True,
                                timeout=20)
        self.assertEqual(result.stderr, '', result.stderr)
        return json.loads(result.stdout)

    def helper(self, code, server):
        return self.php("$_SERVER=json_decode(stream_get_contents(STDIN),true);require $argv[1].'/app/recovery-rehearsal.php';" + code, server)

    def test_only_exact_server_flag_enables_rehearsal(self):
        for value in ['1', 'true', '0', '', 1, True, None, ['1']]:
            with self.subTest(value=value):
                value_read = self.helper('echo json_encode(fls_recovery_rehearsal());', {'FLS_RECOVERY_REHEARSAL': value})
                self.assertEqual(value_read, isinstance(value, str) and value == '1')

    def test_http_header_query_and_port_cannot_enable_or_override_rehearsal(self):
        for server in [{}, {'HTTP_FLS_RECOVERY_REHEARSAL':'1'}, {'SERVER_PORT':'8443'},
                       {'QUERY_STRING':'FLS_RECOVERY_REHEARSAL=1'},
                       {'FLS_RECOVERY_REHEARSAL':'0','HTTP_FLS_RECOVERY_REHEARSAL':'1'}]:
            with self.subTest(server=server):
                self.assertFalse(self.helper('echo json_encode(fls_recovery_rehearsal());', server))
        self.assertTrue(self.helper('echo json_encode(fls_recovery_rehearsal());',
                                    {'FLS_RECOVERY_REHEARSAL':'1','HTTP_FLS_RECOVERY_REHEARSAL':'0'}))

    def test_only_selected_operational_posts_are_blocked(self):
        routes = ['save_maintenance','request_power','prepare_primary_disk','prepare_mirror_disk','sync_mirror_disk',
                  'create_system_backup','upload_system_backup','save_system_backup_settings','test_timestamp_profile',
                  'timestamp_balance','retry_timestamp','recheck_timestamp','test_archive_destination',
                  'retry_archive_delivery','save_fortigate_setup','retest_fortigate_setup','test_credential','cold_query_start']
        code = '$routes=' + json.dumps(routes) + ';echo json_encode(array_map(fn($r)=>[fls_recovery_write_blocked($r,"POST"),fls_recovery_write_blocked($r,"GET")],$routes));'
        self.assertEqual(self.helper(code, {'FLS_RECOVERY_REHEARSAL':'1'}), [[True, False]]*len(routes))
        self.assertEqual(self.helper(code, {}), [[False, False]]*len(routes))
        for route in ['login','password','logout','save_theme','save_fortigate_preference','save_event_columns',
                      'save_event_view','save_user','reset_user_password','maintenance_status','disk_management','unknown']:
            with self.subTest(route=route):
                self.assertFalse(self.helper('echo json_encode(fls_recovery_write_blocked(' + json.dumps(route) + ',"POST"));',
                                             {'FLS_RECOVERY_REHEARSAL':'1'}))

    def test_rehearsal_maintenance_snapshot_is_truthful_without_database_reads(self):
        shutil.copyfile(ROOT / 'app/maintenance.php', self.root / 'app/maintenance.php')
        value = self.php("$_SERVER=['FLS_RECOVERY_REHEARSAL'=>'1'];require $argv[1].'/app/maintenance.php';echo json_encode(maintenance_snapshot(true));")
        self.assertEqual(value['state'], 'rehearsal')
        self.assertEqual(value['reason'], 'recovery_rehearsal')
        self.assertTrue(value['rehearsal'] and value['read_only'])
        self.assertFalse(value['can_control'] or value['available'] or value['fresh'])
        self.assertEqual(value['worker']['collector_state'], 'unknown')
        self.assertEqual(value['worker']['error_code'], '')
        self.assertIsNone(value['worker']['checked_at'])
        self.assertIsNone(value['request']['requested_mode'])
        self.assertNotIn('requested_by', value['request'])

    def test_ordinary_paused_maintenance_and_header_spoof_keep_existing_behavior(self):
        shutil.copyfile(ROOT / 'app/maintenance.php', self.root / 'app/maintenance.php')
        for server in [{}, {'HTTP_FLS_RECOVERY_REHEARSAL':'1'}]:
            value = self.php("$_SERVER=json_decode(stream_get_contents(STDIN),true);$GLOBALS['query_mode']='maintenance';require $argv[1].'/app/maintenance.php';echo json_encode(maintenance_snapshot());", server)
            self.assertEqual(value['state'], 'paused')
            self.assertTrue(value['available'] and value['fresh'])
            self.assertNotIn('rehearsal', value)

    def test_rehearsal_disk_seed_is_explicitly_unverified_without_inventory_reads(self):
        for source in variants('app/disk-management.php'):
            with self.subTest(source=str(source.relative_to(ROOT))):
                shutil.copyfile(source, self.root / 'app/disk-management.php')
                value = self.php("$_SERVER=['FLS_RECOVERY_REHEARSAL'=>'1'];require $argv[1].'/app/disk-management.php';echo json_encode(disk_management_state(['id'=>1,'version'=>1,'boot_id'=>'']));")
                self.assertEqual(value['status'], 'rehearsal')
                self.assertEqual(value['error_code'], '')
                self.assertEqual(value['reason'], 'recovery_rehearsal')
                self.assertTrue(value['rehearsal'] and value['read_only'])
                self.assertFalse(value['available'] or value['fresh'])
                for role in ['system','depot','mirror','checked_at']:
                    self.assertIsNone(value[role])
                self.assertEqual(value['candidates'], [])
                normal = self.php("$_SERVER=[];require $argv[1].'/app/disk-management.php';echo json_encode(disk_management_state(['id'=>1,'version'=>1,'boot_id'=>'']));")
                self.assertEqual(normal['error_code'], 'state_invalid')
                self.assertEqual(normal['status'], 'error')

    def test_rehearsal_disk_snapshot_authorizes_user_but_never_reads_old_inventory(self):
        for source in variants('app/disk-management.php'):
            with self.subTest(source=str(source.relative_to(ROOT))):
                shutil.copyfile(source, self.root / 'app/disk-management.php')
                value = self.php("$_SERVER=['FLS_RECOVERY_REHEARSAL'=>'1','REQUEST_METHOD'=>'GET'];$_SESSION=['uid'=>1,'role'=>'admin','session_version'=>0];$GLOBALS['query_mode']='actor';require $argv[1].'/app/disk-management.php';$s=disk_management_snapshot();echo json_encode(['snapshot'=>$s,'reads'=>$GLOBALS['reads']]);")
                snapshot = value['snapshot']
                self.assertEqual(len(value['reads']), 1)
                self.assertEqual(snapshot['jobs'], [])
                self.assertIsNone(snapshot['active_job'])
                self.assertFalse(snapshot['can_migrate'] or snapshot['can_prepare'] or snapshot['can_sync'])

    def test_direct_maintenance_and_disk_writers_reject_before_database_access(self):
        shutil.copyfile(ROOT / 'app/maintenance.php', self.root / 'app/maintenance.php')
        for source in variants('app/disk-management.php'):
            with self.subTest(source=str(source.relative_to(ROOT))):
                shutil.copyfile(source, self.root / 'app/disk-management.php')
                value = self.php("$_SERVER=['FLS_RECOVERY_REHEARSAL'=>'1'];require $argv[1].'/app/maintenance.php';require $argv[1].'/app/disk-management.php';$out=[];foreach([fn()=>maintenance_save([]),fn()=>disk_management_write('prepare_primary_disk',[]),fn()=>disk_management_write('sync_mirror_disk',[])] as $call){try{$call();$out[]='not_rejected';}catch(ManagementError $e){$out[]=$e->status;}}echo json_encode($out);")
                self.assertEqual(value, [409, 409, 409])

    def api(self, source, route='save_maintenance', role='admin', csrf='fixture-token', flag=True):
        (self.root / 'app/bootstrap.php').write_text(BOOTSTRAP)
        shutil.copyfile(source, self.root / 'public/api.php')
        return self.php("require $argv[1].'/public/api.php';", {
            'route':route,'method':'POST','post':{'_csrf':csrf},'role':role,
            'server':{'FLS_RECOVERY_REHEARSAL':'1'} if flag else {}})

    def test_actual_api_rejects_operational_posts_without_queues_or_database(self):
        for source in variants('public/api.php'):
            for route in ['save_maintenance','request_power','prepare_primary_disk','prepare_mirror_disk',
                          'sync_mirror_disk','create_system_backup','upload_system_backup','test_timestamp_profile',
                          'test_archive_destination','save_fortigate_setup','test_credential','cold_query_start']:
                with self.subTest(source=str(source.relative_to(ROOT)), route=route):
                    result = self.api(source, route=route)
                    self.assertEqual(result['status'], 409)
                    self.assertEqual(result['body']['code'], 'recovery_rehearsal_read_only')

    def test_actual_api_preserves_role_csrf_and_personal_preferences(self):
        for source in variants('public/api.php'):
            with self.subTest(source=str(source.relative_to(ROOT))):
                self.assertEqual(self.api(source, role='analyst')['status'], 403)
                self.assertEqual(self.api(source, csrf='wrong')['status'], 403)
                self.assertEqual(self.api(source, csrf=['fixture-token'])['status'], 403)
                result = self.api(source, route='save_theme')
                self.assertEqual(result, {'status':200,'body':{'fixture_passed_route':'save_theme'}})

    def test_server_context_is_wired_into_both_page_templates(self):
        self.assertIn("require_once __DIR__.'/recovery-rehearsal.php';", (ROOT / 'app/bootstrap.php').read_text())
        for source in variants('public/index.php'):
            text = source.read_text()
            self.assertIn('data-recovery-rehearsal="<?=fls_recovery_rehearsal()', text)
            self.assertIn('id="recovery-rehearsal-banner"', text)
            self.assertIn('Log alımı ve otomatik işler kapalıdır.', text)


if __name__ == '__main__':
    unittest.main()
