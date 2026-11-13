#!/usr/bin/env python3
"""Fixture-only installation engine checks. No packages, SQL, units or disks touched."""
import contextlib
import hashlib
import importlib.util
import json
import os
import grp
import pwd
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'tools/community/overlay/bin'
if not BIN.is_dir(): BIN = ROOT / 'bin'
sys.dont_write_bytecode = True
sys.path.insert(0, str(BIN))
import community_install as engine


def source_fixture(root):
    root.mkdir(mode=0o700)
    files = {'schema.sql': b'CREATE TABLE IF NOT EXISTS example (id INT);\n', 'VERSION': b'0.76.0\n',
             'bin/product_config.py': b'# fixture\n', 'bin/fls_storage.py': b'# fixture\n'}
    files.update({'app/fixture%d.py' % index: b'# fixture\n' for index in range(12)})
    rows = []
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content); path.chmod(0o644)
        rows.append({'path': relative, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'mode': 644})
    (root / 'deploy').mkdir()
    (root / 'deploy/release-files.json').write_text(json.dumps({'schema': 'fls-community-release-files-v1',
                                                             'version': '0.76.0', 'files': rows}))
    return root


def plan_fixture():
    return {'inventory_origin': 'host', 'host_inspected': True, 'ready_for_apply': True, 'blockers': []}


class RecordingOps:
    def __init__(self, *, fail=None):
        self.calls, self.fail, self.saved = [], fail, []
        self.journal_value = None
    def admit(self, plan): self.calls.append('admit'); return {'fixture': 'no real host'}
    def guard(self, target): self.calls.append('guard')
    @contextlib.contextmanager
    def journal(self, release, target):
        self.calls.append('journal')
        self.journal_value = {'schema': 'fls-community-install-journal-v1', 'installation_id': 'fixture',
                              'version': release['version'], 'status': 'admitted', 'phase': 'admission',
                              'completed_phases': []}
        yield self.journal_value
    def save_journal(self, journal):
        self.saved.append(json.loads(json.dumps(journal)))
    def __getattr__(self, name):
        if name in engine.PHASES:
            def phase(*args):
                self.calls.append(name)
                if name == self.fail: raise engine.InstallError('injected_phase_failure')
            return phase
        raise AttributeError(name)


class EngineAdmissionChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-install-engine-test-')
        self.source = source_fixture(Path(self.temporary.name) / 'release')
    def tearDown(self): self.temporary.cleanup()
    def test_exact_release_inventory_and_decimal_modes(self):
        report = engine.verify_release(self.source)
        self.assertEqual(report['file_count'], 16)
        self.assertEqual(report['version'], '0.76.0')
    def test_checksum_change_rejected_before_any_host_operation(self):
        (self.source / 'VERSION').write_text('changed\n')
        ops = RecordingOps()
        with self.assertRaisesRegex(engine.InstallError, 'release_checksum_mismatch'):
            engine.apply(self.source, plan_fixture(), ops=ops)
        self.assertEqual(ops.calls, [])
    def test_extra_missing_and_symlink_entries_rejected(self):
        path = self.source / 'app/fixture0.py'
        original = path.read_bytes()
        for action, expected in [('extra', 'release_unlisted_file'), ('missing', 'release_missing_file'), ('symlink', 'release_symlink_forbidden')]:
            with self.subTest(action=action):
                extra = self.source / 'extra.py'
                if action == 'extra': extra.write_text('# extra\n')
                elif action == 'missing': path.unlink()
                else: path.unlink(); path.symlink_to(self.source / 'VERSION')
                with self.assertRaisesRegex(engine.InstallError, expected): engine.verify_release(self.source)
                extra.unlink(missing_ok=True)
                if not path.exists() or path.is_symlink():
                    path.unlink(missing_ok=True); path.write_bytes(original)
    def test_manifest_paths_and_duplicate_paths_cannot_escape(self):
        file = self.source / 'deploy/release-files.json'
        original = json.loads(file.read_text())
        for value in ('../outside', '/etc/shadow', 'app/../bad', 'app\\bad'):
            changed = json.loads(json.dumps(original)); changed['files'][0]['path'] = value
            file.write_text(json.dumps(changed))
            with self.subTest(value=value), self.assertRaises(engine.InstallError): engine.verify_release(self.source)
        changed = json.loads(json.dumps(original)); changed['files'].append(changed['files'][0]); file.write_text(json.dumps(changed))
        with self.assertRaises(engine.InstallError): engine.verify_release(self.source)
    def test_fixture_and_blocked_plan_rejected_before_tree_or_host_access(self):
        for change in ({'inventory_origin': 'supplied_fixture'}, {'host_inspected': False}, {'blockers': ['blocked']}, {'ready_for_apply': False}):
            ops = RecordingOps()
            with patch.object(engine, 'verify_release', side_effect=AssertionError('tree inspected')):
                with self.assertRaises(engine.InstallError): engine.apply('/not/read', plan_fixture() | change, ops=ops)
            self.assertEqual(ops.calls, [])
    def test_apply_runs_each_real_adapter_phase_once_after_intent_and_guard(self):
        ops = RecordingOps()
        result = engine.apply(self.source, plan_fixture(), ops=ops)
        self.assertTrue(result['installed'])
        self.assertFalse(result['collector_started'])
        self.assertFalse(result['disk_formatted'])
        phases = [name for name in ops.calls if name in engine.PHASES]
        self.assertEqual(phases, list(engine.PHASES))
        self.assertEqual(ops.journal_value['completed_phases'], list(engine.PHASES))
        for phase in engine.PHASES:
            self.assertTrue(any(row['phase'] == phase and phase not in row['completed_phases'] and row['status'] == 'running' for row in ops.saved))
        self.assertNotIn('password', json.dumps(result))
    def test_partial_failure_stays_failed_without_later_phases_or_sql_replay(self):
        ops = RecordingOps(fail='database')
        with self.assertRaisesRegex(engine.InstallError, 'injected_phase_failure') as error:
            engine.apply(self.source, plan_fixture(), ops=ops)
        self.assertEqual(error.exception.phase, 'database')
        self.assertEqual(ops.saved[-1]['status'], 'failed')
        self.assertNotIn('roles', ops.calls)
        self.assertEqual(ops.calls.count('database'), 1)
    def test_changed_target_before_phase_fails_without_running_phase(self):
        ops = RecordingOps()
        with patch.object(ops, 'guard', side_effect=engine.InstallError('target_identity_changed')):
            with self.assertRaisesRegex(engine.InstallError, 'target_identity_changed'):
                engine.apply(self.source, plan_fixture(), ops=ops)
        self.assertFalse(any(name in engine.PHASES for name in ops.calls))
    def test_source_checkout_without_release_inventory_cannot_install(self):
        (self.source / 'deploy/release-files.json').unlink()
        ops = RecordingOps()
        with self.assertRaises(FileNotFoundError): engine.apply(self.source, plan_fixture(), ops=ops)
        self.assertEqual(ops.calls, [])


class RealAdapterContractChecks(unittest.TestCase):
    def test_private_parent_mode_not_changed_by_atomic_write(self):
        with tempfile.TemporaryDirectory(prefix='fls-install-engine-write-') as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            ops = engine.HostOps()
            ops.write(parent / 'journal.json', '{}\n', mode=0o600, user=pwd.getpwuid(os.geteuid()).pw_name, group=grp.getgrgid(os.getegid()).gr_name)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((parent / 'journal.json').stat().st_mode), 0o600)
            with self.assertRaises(engine.InstallError): ops.write(parent / 'journal.json', '{}\n', mode=0o600, user=pwd.getpwuid(os.geteuid()).pw_name, group=grp.getgrgid(os.getegid()).gr_name)
    def test_preexisting_state_never_replayed_even_when_journal_missing(self):
        with tempfile.TemporaryDirectory(prefix='fls-install-engine-state-') as temporary:
            ops = engine.HostOps(); ops.state = Path(temporary)
            with self.assertRaisesRegex(engine.InstallError, 'previous_installation_requires_snapshot_restore'):
                with ops.journal({'version': 'fixture', 'manifest_sha256': '0' * 64}, {}): self.fail('journal reopened')
    def test_source_host_rejects_before_journal_file_or_package_mutation(self):
        ops = engine.HostOps()
        from install_plan import INVENTORY_SCHEMA
        inventory = {'root': {'uuid': 'source', 'major_minor': '8:2'}, 'machine_sha256': 'a' * 64}
        with patch.object(engine.os, 'geteuid', return_value=0), patch('install_plan.collect_inventory', return_value=inventory), patch.object(ops, 'write', side_effect=AssertionError('host write')):
            with self.assertRaisesRegex(engine.InstallError, 'target_identity_changed'):
                ops.admit({'storage': {'root': {'uuid': 'other'}}, 'machine_sha256': 'b' * 64})
    def test_base_role_grants_no_ddl_delete_logs_or_cross_database_privilege(self):
        statements = []
        class Cursor:
            def execute(self, query, params=None): statements.append(query)
        ops = engine.HostOps()
        with patch.object(ops, 'write'):
            ops.base_roles(Cursor())
        grants = [query for query in statements if query.startswith('GRANT ')]
        self.assertTrue(grants)
        self.assertTrue(all(' ON fls.' in query for query in grants))
        self.assertFalse(any('ALL PRIVILEGES' in query or 'GRANT OPTION' in query or 'DROP' in query for query in grants))
        self.assertFalse(any('DELETE ON fls.events' in query or 'DELETE ON fls.source_files' in query for query in grants))
        self.assertIn('GRANT INSERT,UPDATE ON fls.users TO fls_app@localhost', grants)
        self.assertIn('GRANT UPDATE ON fls.management_lock TO fls_app@localhost', grants)
        self.assertIn('GRANT SELECT ON fls.fortigate_connections TO fls_alerts@localhost', grants)
        self.assertTrue(any(query.startswith('GRANT UPDATE(check_status,check_code,observed_host_key,') and query.endswith('TO fls_export@localhost') for query in grants))
        self.assertIn('GRANT SELECT ON fls.archive_manifests TO fls_timestamp@localhost', grants)
        self.assertIn('GRANT SELECT ON fls.archive_deliveries TO fls_timestamp@localhost', grants)
        self.assertTrue(any(query.startswith('GRANT UPDATE(check_status,check_code,checked_revision,') and query.endswith('TO fls_timestamp@localhost') for query in grants))
    def test_application_preserves_exact_shipped_inventory_for_git_free_backups(self):
        with tempfile.TemporaryDirectory(prefix='fls-install-engine-copy-') as temporary:
            folder = Path(temporary)
            source = source_fixture(folder / 'release')
            extra = {'artifacts/linux-amd64/fls-archive-hash': b'fixture helper',
                     'artifacts/linux-amd64/fls-checked-write-collector.tar.gz': b'fixture bundle',
                     'install.sh': b'fixture bootstrap', 'bin/fortigate-health.py': b'# fixture health'}
            manifest_path = source / 'deploy/release-files.json'
            manifest = json.loads(manifest_path.read_text())
            for relative, data in extra.items():
                path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data); path.chmod(0o644)
                manifest['files'].append({'path': relative, 'bytes': len(data),
                                          'sha256': hashlib.sha256(data).hexdigest(), 'mode': 644})
            manifest_path.write_text(json.dumps(manifest))
            release = engine.verify_release(source)
            target = folder / 'never-created-target'
            copied = {}
            ops = engine.HostOps()
            with patch.object(engine, 'APP', target), patch.object(ops, 'directory'), \
                 patch.object(ops, 'write', side_effect=lambda path, data, **kwargs: copied.update({str(path): data})), \
                 patch.object(ops, 'extract_collector'):
                ops.application(source, {}, release)
            self.assertFalse(target.exists())
            for row in manifest['files']:
                self.assertEqual(hashlib.sha256(copied[str(target / row['path'])]).hexdigest(), row['sha256'])
            self.assertEqual(copied[str(target / 'deploy/release-files.json')], manifest_path.read_bytes())

    def test_storage_owns_private_queue_and_dump_paths_without_disk_operations(self):
        ops = engine.HostOps()
        directories, writes, commands = {}, {}, []
        plan = {'storage': {'root': {'uuid': 'b85ec2af-fafd-429f-a4d8-ea3feff8f382',
                                     'device_identity': {'kind': 'serial', 'value': 'VM-SYSTEM-001'}}}}
        with patch.object(ops, 'directory', side_effect=lambda path, **kw: directories.update({str(path): kw})), \
             patch.object(ops, 'write', side_effect=lambda path, data, **kw: writes.update({str(path): (data, kw)})), \
             patch.object(ops, 'run', side_effect=lambda args, **kw: commands.append(args)):
            ops.storage(None, plan, {})
        self.assertEqual(directories['/srv/fortigate/db-dumps']['mode'], 0o700)
        self.assertEqual(directories['/srv/fortigate/raw']['user'], 'syslog')
        self.assertEqual(directories['/srv/fortigate/raw']['group'], 'adm')
        self.assertEqual(directories['/var/lib/fls/sessions']['mode'], 0o700)
        self.assertEqual(directories['/var/lib/fls/sessions']['user'], 'fls-web')
        self.assertTrue(all(args[0] == '/usr/bin/setfacl' for args in commands))
        self.assertTrue(any(args[-1] == '/srv/fortigate/raw' and 'd:u:fls-export:r-x' in args[-2] for args in commands))
        self.assertTrue(any(args[-1] == '/srv/fortigate/archive/packages' and 'd:u:fls-web:r-x' in args[-2] and 'd:u:fls-tsa:r-x' in args[-2] for args in commands))
        self.assertTrue(any(args[-1] == '/srv/fortigate/archive/timestamps' and 'd:u:fls-web:r-x' in args[-2] for args in commands))
        storage = json.loads(writes['/etc/fls/storage.json'][0])
        self.assertEqual(storage['schema'], 2)
        self.assertEqual(storage['device_identity']['kind'], 'serial')
        self.assertIn('/var/lib/fls-maintenance/paused', writes)

    def test_https_probe_uses_existing_index_and_pinned_local_ca(self):
        import http.client
        import ssl
        from unittest.mock import MagicMock
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200; response.read.return_value = b'<html><head><meta name="fls-version" content="0.76.0"></head></html>'
        response.getheader.side_effect = ['text/html', 'text/css', 'application/javascript']
        with patch.object(ssl, 'create_default_context', return_value='fixture-ca') as context, \
             patch.object(http.client, 'HTTPSConnection', return_value=connection) as factory, \
             patch.object(engine.HostOps, 'disk_health') as inventory:
            engine.HostOps().health(None, {'configuration_proposal': {'bind_ip': '192.0.2.10'}}, {'version':'0.76.0'})
            inventory.assert_called_once()
        context.assert_called_once_with(cafile='/etc/nginx/fls-tls/ca.crt')
        self.assertEqual(connection.request.call_args_list[0].args[:2], ('GET', '/index.php'))
        self.assertEqual(factory.call_args.args[:2], ('192.0.2.10', 443))
        self.assertTrue(connection.close.called)

    def test_stale_visible_version_prevents_successful_install_health(self):
        import http.client
        import ssl
        from unittest.mock import MagicMock
        connection=MagicMock();response=connection.getresponse.return_value
        response.status=200;response.read.return_value=b'<meta name="fls-version" content="0.75.0">FLS 0.76.0 appears elsewhere'
        response.getheader.return_value='text/html'
        with patch.object(ssl,'create_default_context'), patch.object(http.client,'HTTPSConnection',return_value=connection), \
             patch.object(engine.HostOps,'disk_health') as inventory:
            with self.assertRaisesRegex(engine.InstallError,'initial_displayed_version_invalid'):
                engine.HostOps().health(None,{'configuration_proposal':{'bind_ip':'192.0.2.10'}},{'version':'0.76.0'})
        inventory.assert_not_called();self.assertTrue(connection.close.called)

    def test_package_failure_restores_existing_service_policy_inode_and_mode(self):
        with tempfile.TemporaryDirectory(prefix='fls-install-engine-policy-') as temporary:
            root = Path(temporary)
            policy = root / 'policy-rc.d'
            policy.write_bytes(b'#!/bin/sh\nexit 0\n'); policy.chmod(0o751)
            before = policy.stat()
            ops = engine.HostOps(); ops.state = root
            actual_path = engine.Path
            def mapped_path(value): return policy if str(value) == '/usr/sbin/policy-rc.d' else actual_path(value)
            def fake_write(path, data, **kwargs):
                self.assertEqual(path, policy)
                with path.open('x') as stream: stream.write(data)
                path.chmod(kwargs['mode'])
            with patch.object(engine, 'Path', side_effect=mapped_path), patch.object(ops, 'write', side_effect=fake_write), \
                 patch.object(ops, 'run', side_effect=engine.InstallError('injected_apt_failure')):
                with self.assertRaisesRegex(engine.InstallError, 'injected_apt_failure'):
                    ops.packages(None, {'dependencies': {'packages': ['fixture-package']}}, {})
            after = policy.stat()
            self.assertEqual(after.st_ino, before.st_ino)
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o751)
            self.assertEqual(policy.read_bytes(), b'#!/bin/sh\nexit 0\n')
            self.assertEqual(list(root.iterdir()), [policy])

    def test_all_runtime_service_users_are_explicitly_created(self):
        required = set()
        deploy = ROOT / 'deploy'
        import re
        for path in deploy.glob('*.service'):
            if path.name.startswith('fls-license'): continue
            required.update(re.findall(r'^User=(fls-[a-z-]+)$', path.read_text(), re.M))
        self.assertTrue(required.issubset(set(engine.USERS)), required - set(engine.USERS))

    def test_activation_starts_ui_but_collector_enable_is_not_now(self):
        commands = []
        ops = engine.HostOps()
        def run(args, **kwargs):
            commands.append(args)
            return b'ActiveState=inactive\nMainPID=0\n' if 'show' in args else b''
        with patch.object(ops, 'run', side_effect=run): ops.activation(None, {}, {})
        starts = [args for args in commands if '--now' in args or 'start' in args]
        self.assertFalse(any('fortigate-collector.service' in args for args in starts))
        self.assertTrue(any('nginx.service' in args and '--now' in args for args in starts))
    def test_cli_fixture_apply_rejected_before_any_probe(self):
        spec = importlib.util.spec_from_file_location('fixture_install_cli', BIN / 'fls-install.py')
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        import io
        with patch.object(cli, 'collect_inventory', side_effect=AssertionError('host inspected')), patch.object(cli, 'read_json', side_effect=AssertionError('source read')), contextlib.redirect_stdout(io.StringIO()) as output:
            status = cli.main(['--apply', '--inventory', '/not/read'])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())['error_code'], 'fixture_apply_forbidden')


class DiskHealthChecks(unittest.TestCase):
    def row(self):
        now = engine.dt.datetime.now(engine.dt.timezone.utc)
        identity = 'id:' + 'a'*64
        role = {'wwn':identity,'serial':'SYNTHETIC-VM','model':'Virtual disk','size_bytes':200*1024**3,'present':True,
                'filesystem':'ext4','filesystem_uuid':'3079e8b2-3257-462e-a6a1-e1ed88eb4def','mount_path':'/'}
        boot = '278d37a6-bfeb-4d70-bad7-a1770bfaa18c'
        inventory = {'schema':1,'boot_id':boot,'mode':'system-root','generated_at_utc':now.isoformat(),
                     'system':role,'depot':None,'mirror':None,'candidates':[],'progress':None}
        return {'id':1,'version':1,'boot_id':boot,'checked_at':now,'config_revision':0,'status':'idle',
                'error_code':'','inventory_json':json.dumps(inventory)}

    def invoke(self, row, *, jobs=0, fail_start=False):
        from unittest.mock import MagicMock
        import shutil
        ops = engine.HostOps(); connection = MagicMock(); cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [(jobs,), tuple(row.values())]
        cursor.description = [(key,) for key in row]
        commands=[]
        original_run=ops.run
        with tempfile.TemporaryDirectory(prefix='fls-disk-health-') as temporary:
            app=Path(temporary);(app/'app').mkdir()
            overlay=ROOT/'tools/community/overlay/app/disk-management.php'
            shutil.copyfile(overlay if overlay.is_file() else ROOT/'app/disk-management.php',app/'app/disk-management.php')
            shutil.copyfile(ROOT/'app/management.php',app/'app/management.php')
            def run(args, **kwargs):
                commands.append(args)
                if args[0]=='/usr/bin/systemctl':
                    if fail_start: raise engine.InstallError('injected_disk_worker_failure')
                    return b''
                self.assertEqual(args[0],'/usr/bin/php')
                return original_run(args,**kwargs)
            with patch.object(engine,'APP',app), patch.object(ops,'connect',return_value=connection), patch.object(ops,'run',side_effect=run):
                ops.disk_health()
        self.assertTrue(connection.close.called)
        return commands

    def test_fresh_worker_inventory_is_projected_by_actual_php_model(self):
        commands=self.invoke(self.row())
        self.assertEqual(commands[0],['/usr/bin/systemctl','start','fls-disk-management.service'])
        self.assertEqual(commands[1][0],'/usr/bin/php')

    def test_worker_failed_state_cannot_complete_installation(self):
        row=self.row();row.update(status='error',error_code='disk_operation_failed',inventory_json=None)
        with self.assertRaisesRegex(engine.InstallError,'initial_disk_inventory_invalid'):self.invoke(row)

    def test_stale_inventory_and_unverified_presence_cannot_complete_installation(self):
        for change in ('stale','presence'):
            row=self.row();inventory=json.loads(row['inventory_json'])
            if change=='stale': inventory['generated_at_utc']=(engine.dt.datetime.now(engine.dt.timezone.utc)-engine.dt.timedelta(minutes=2)).isoformat()
            else: inventory['system']['present']=False
            row['inventory_json']=json.dumps(inventory)
            with self.subTest(change=change), self.assertRaisesRegex(engine.InstallError,'initial_disk_inventory_invalid'):self.invoke(row)

    def test_existing_disk_intent_is_not_run_as_an_install_health_probe(self):
        with self.assertRaisesRegex(engine.InstallError,'initial_disk_jobs_not_empty'):self.invoke(self.row(),jobs=1)

    def test_worker_start_failure_is_not_hidden_by_healthy_https(self):
        with self.assertRaisesRegex(engine.InstallError,'injected_disk_worker_failure'):self.invoke(self.row(),fail_start=True)



if __name__ == '__main__': unittest.main()
