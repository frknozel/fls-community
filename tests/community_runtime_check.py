#!/usr/bin/env python3
"""Community runtime regressions using disposable metadata and archive fixtures.

No host disk, service, SQL instance, provider or network endpoint is modified.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'tools/community/overlay' if (ROOT / 'tools/community/overlay/bin/fls_storage.py').is_file() else ROOT


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


storage = load('community_storage_fixture', TREE / 'bin/fls_storage.py')
backup = load('community_backup_fixture', TREE / 'bin/system-backup.py')
engine = load('community_engine_fixture', TREE / 'bin/fls_recovery_engine.py')
bootstrap = load('community_bootstrap_fixture', TREE / 'bin/recovery-bootstrap.py')
engine_checks = load('community_engine_archive_fixtures', TREE / 'tests/recovery_engine_check.py')
# Shared fixtures exercise the community engine, not the private profile.
engine_checks.engine = engine
UUID = '3079e8b2-3257-462e-a6a1-e1ed88eb4def'
NAA = '0x5000000000000001'


class RuntimeFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-community-runtime-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / 'work'; self.work.mkdir(mode=0o700)

    def test_backup_strips_canonical_fls_mount_units_from_recovery_payload(self):
        # Restore must not reactivate another machine's data-disk mounts. The
        # project name's hyphen needs a literal systemd escape in each filename.
        expected = {
            r'srv-fls\x2dserver-raw.mount', r'srv-fls\x2dserver-archive.mount',
            r'srv-fls\x2dserver-queue.mount', r'srv-fls\x2dserver-metrics.mount',
            r'srv-fls\x2dserver-backups.mount', r'srv-fls\x2dserver-db\x2ddumps.mount',
            r'var-lib-fls\x2drecovery\x2ddownload.mount', r'srv-fls\x2dmirror.mount',
        }
        self.assertEqual(set(backup.HDD_BIND_UNITS), expected)
        self.assertEqual(backup.HDD_DEPOT_UNIT, r'srv-fls\x2dstorage.mount')

    @contextlib.contextmanager
    def disk(self, identity='serial'):
        udev = self.root / 'udev'; udev.mkdir()
        sysfs = self.root / 'sysfs'; sysfs.mkdir()
        disk = self.root / 'disk'; (disk / 'device').mkdir(parents=True)
        part = disk / 'partition1'; part.mkdir(); (part / 'partition').write_text('1\n')
        device = os.stat('/').st_dev
        major_minor = '{}:{}'.format(os.major(device), os.minor(device))
        (sysfs / major_minor).symlink_to(part, target_is_directory=True)
        properties = 'E:ID_FS_UUID=' + UUID + '\nE:ID_FS_TYPE=ext4\n'
        if identity == 'serial':
            (disk / 'serial').write_text('FLSVM-0123456789\n')
            properties += 'E:ID_SERIAL_SHORT=FLSVM-0123456789\n'
        elif identity == 'wwid':
            (disk / 'wwid').write_text('eui.1234567890123456\n')
        else:
            (disk / 'device/wwid').write_text('naa.' + NAA[2:] + '\n')
        cache = udev / ('b' + major_minor); cache.write_text(properties)
        with patch.object(storage, 'UDEV', udev), patch.object(storage, 'SYSFS', sysfs):
            yield device, disk, part, cache

    @unittest.skipUnless(os.geteuid() == 0, 'Kernel metadata ownership is part of the storage contract')
    def test_virtual_serial_pins_physical_disk_and_filesystem_uuid(self):
        with self.disk() as (device, disk, part, cache):
            actual = storage.discover_identity(device)
            self.assertEqual(actual['identity'], {'kind': 'serial', 'value': 'FLSVM-0123456789'})
            self.assertEqual(storage.filesystem_identity(device, UUID, actual['identity']), (actual['device'], disk))
            (disk / 'serial').write_text('FLSVM-another-device\n')
            with self.assertRaises(storage.StorageError):
                storage.filesystem_identity(device, UUID, actual['identity'])
            (disk / 'serial').write_text('FLSVM-0123456789\n')
            cache.write_text(cache.read_text().replace(UUID, '531c3316-a72b-4cd4-96b3-c67d004208c5'))
            with self.assertRaises(storage.StorageError):
                storage.filesystem_identity(device, UUID, actual['identity'])

    @unittest.skipUnless(os.geteuid() == 0, 'Kernel metadata ownership is part of the storage contract')
    def test_kernel_and_udev_serial_disagreement_and_missing_identity_fail_closed(self):
        with self.disk() as (device, disk, part, cache):
            cache.write_text(cache.read_text().replace('ID_SERIAL_SHORT=FLSVM-0123456789', 'ID_SERIAL_SHORT=unexpected'))
            with self.assertRaises(storage.StorageError): storage.discover_identity(device)
            (disk / 'serial').unlink()
            with self.assertRaises(storage.StorageError): storage.discover_identity(device)

    @unittest.skipUnless(os.geteuid() == 0, 'Kernel metadata ownership is part of the storage contract')
    def test_non_naa_wwid_and_legacy_naa_are_supported_without_device_nodes(self):
        for identity in ['wwid', 'naa']:
            with self.subTest(identity=identity):
                # Each subcase uses a fresh fixture tree.
                with tempfile.TemporaryDirectory(prefix='identity-', dir=self.root) as folder:
                    original = self.root; self.root = Path(folder)
                    try:
                        with self.disk(identity) as (device, disk, part, cache):
                            found = storage.discover_identity(device)
                            self.assertEqual(found['identity']['kind'], 'wwid' if identity == 'wwid' else 'wwn')
                            storage.filesystem_identity(device, UUID, found['identity'])
                            if identity == 'naa':
                                cache.write_text('E:ID_FS_UUID=' + UUID + '\n')
                                storage.filesystem_identity(device, UUID, NAA)
                    finally: self.root = original

    @unittest.skipUnless(os.geteuid() == 0, 'Kernel metadata ownership is part of the storage contract')
    def test_redirected_metadata_lvm_or_duplicate_metadata_never_authorize_storage(self):
        with self.disk() as (device, disk, part, cache):
            saved = cache.read_text()
            cache.write_text(saved + 'E:ID_FS_UUID=' + UUID + '\n')
            with self.assertRaises(storage.StorageError): storage.discover_identity(device)
            cache.write_text(saved); (part / 'partition').unlink()
            with self.assertRaises((storage.StorageError, OSError)): storage.discover_identity(device)

    def test_schema2_hybrid_requires_system_queue_and_distinct_disk(self):
        source = {'schema': 2, 'mode': 'system-root', 'root_uuid': UUID,
                  'device_identity': {'kind': 'serial', 'value': 'VMROOT'}}
        self.assertEqual(storage.validate_config(source), source)
        hybrid = source | {'mode': 'hybrid', 'depot_uuid': '810a3686-9b56-48c1-8ac9-d59a1d27a98b',
                           'depot_identity': {'kind': 'wwn', 'value': NAA},
                           'depot_path': '/srv/fls-storage', 'queue_location': 'system'}
        self.assertEqual(storage.validate_config(hybrid), hybrid)
        for changes in [{'queue_location': 'depot'}, {'depot_uuid': UUID},
                        {'depot_identity': source['device_identity']}, {'schema': True}]:
            with self.subTest(changes=changes), self.assertRaises(storage.StorageError):
                storage.validate_config(hybrid | changes)

    @unittest.skipUnless(os.geteuid() == 0, 'Bind metadata ownership is part of the storage contract')
    def test_hybrid_requires_exact_sixth_dump_bind_and_cannot_fall_back_to_system_disk(self):
        fixture_module = load('community_bind_fixture', ROOT / 'tests/storage_guard_check.py')
        fixture_module.guard = storage
        fixture = fixture_module.SystemQueueGuard()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.cache.write_text(fixture.cache.read_text() + 'E:ID_FS_TYPE=ext4\n')
        fixture.depot_cache.write_text(fixture.depot_cache.read_text() + 'E:ID_FS_TYPE=ext4\n')
        dumps = fixture.data / 'db-dumps'; dumps.mkdir(mode=0o700)
        fixture.bindings[dumps] = fixture.dump
        fixture.mount_rows[dumps] = '/DB-Dump'
        fixture.write_mounts()
        config = {'schema': 2, 'mode': 'hybrid', 'root_uuid': UUID,
                  'device_identity': {'kind':'wwn','value':fixture_module.WWN},
                  'depot_uuid':fixture.depot_uuid, 'depot_identity':{'kind':'wwn','value':fixture.depot_wwn},
                  'depot_path':'/srv/fls-storage', 'queue_location':'system'}
        fixture.config.write_text(json.dumps(config))
        with patch.object(storage, 'DUMPS', dumps):
            self.assertEqual(storage.storage_state()['mode'], 'hybrid')
            del fixture.mount_rows[dumps]; fixture.write_mounts()
            with self.assertRaises(storage.StorageError): storage.storage_state()
            fixture.mount_rows[dumps] = '/different-dump-folder'; fixture.write_mounts()
            with self.assertRaises(storage.StorageError): storage.storage_state()
            fixture.mount_rows[dumps] = '/DB-Dump'; fixture.write_mounts()
            fixture.wrong_inodes.add(dumps)
            with self.assertRaises(storage.StorageError): storage.storage_state()

    def release(self):
        source = self.root / 'release'; (source / 'deploy').mkdir(parents=True)
        (source / 'bin').mkdir(); (source / 'public').mkdir()
        (source / 'VERSION').write_text('0.75.0\n')
        (source / 'bin/tool.py').write_text('# fixture only\n'); (source / 'bin/tool.py').chmod(0o755)
        files = [{'path': name, 'sha256': hashlib.sha256((source / name).read_bytes()).hexdigest(),
                  'mode': 755 if name.startswith('bin/') else 644} for name in ['VERSION', 'bin/tool.py']]
        manifest = {'schema': 'fls-community-release-files-v1', 'version': '0.75.0', 'files': files}
        (source / 'deploy/release-files.json').write_text(json.dumps(manifest))
        return source

    def test_git_free_release_inventory_verifies_actual_shipped_bytes_and_modes(self):
        source = self.release()
        (source / 'public/archive-public-key.pem').write_text('generated public fixture\n')
        with patch.object(backup, 'SOURCE', source), patch.object(backup.subprocess, 'run', side_effect=AssertionError('no Git command')):
            result = backup.source_inventory(io.BytesIO())
            self.assertEqual(result['release_version'], '0.75.0')
            self.assertFalse(result['git_history_included'])
            (source / 'bin/tool.py').write_text('modified\n')
            with self.assertRaisesRegex(backup.BackupError, 'release_file_mismatch'):
                backup.source_inventory(io.BytesIO())

    def test_git_free_release_inventory_rejects_unlisted_files_and_symlinks(self):
        source = self.release()
        with patch.object(backup, 'SOURCE', source):
            (source / 'credentials.json').write_text('{"fixture":true}\n')
            with self.assertRaisesRegex(backup.BackupError, 'release_inventory_mismatch'):
                backup.source_inventory(io.BytesIO())
            (source / 'credentials.json').unlink()
            (source / 'public/redirect').symlink_to(source / 'VERSION')
            with self.assertRaises(backup.BackupError): backup.source_inventory(io.BytesIO())

    def test_health_uses_verified_generic_disk_node_and_marks_missing_vm_smart_unknown(self):
        health = load('community_health_fixture', TREE / 'bin/fortigate-health.py')
        disk = self.root / 'vda'; disk.mkdir(); (disk / 'dev').write_text('8:0\n')
        nodes = self.root / 'dev'; nodes.mkdir(); (nodes / 'vda').write_text('fixture node')
        real_path = health.Path; real_stat = Path.stat
        def virtual_path(value):
            return nodes if str(value) == '/dev' else real_path(value)
        def virtual_stat(path, *args, **kwargs):
            if path == nodes / 'vda':
                return types.SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(8, 0))
            return real_stat(path, *args, **kwargs)
        state = {'mode':'system-root', 'root_uuid':UUID, 'device_wwn':'',
                 'device_identity':{'kind':'serial','value':'VMROOT'}}
        with patch.object(health, 'filesystem_identity', return_value=('8:1', disk)) as probe, \
             patch.object(health, 'Path', side_effect=virtual_path), patch.object(Path, 'stat', virtual_stat), \
             patch.object(health, 'trusted_read', side_effect=lambda path, limit: path.read_text()):
            self.assertEqual(health.disk_probe_paths(state), [('system', str(nodes / 'vda'))])
            self.assertEqual(probe.call_args.args[1:], (UUID, state['device_identity']))
        unknown = health.smart_summary('system', '/dev/vda', {'exit_code':2,'data':{'model_name':'QEMU Virtual Disk'}})
        self.assertFalse(unknown['smart_available'])
        self.assertEqual(unknown['smart_status'], 'unsupported_or_unavailable')
        self.assertIsNone(unknown['passed'])
        actual_failure = health.smart_summary('system', '/dev/vda', {'exit_code':8,'data':{'smart_status':{'passed':False}}})
        self.assertTrue(actual_failure['smart_available']); self.assertFalse(actual_failure['passed'])

    def test_community_recovery_accepts_stock_ubuntu_web_identity(self):
        account = types.SimpleNamespace(pw_name='www-data',pw_uid=33,pw_gid=33,pw_dir='/var/www',pw_shell='/usr/sbin/nologin')
        group = types.SimpleNamespace(gr_name='www-data',gr_gid=33,gr_mem=[])
        with patch.object(backup.pwd, 'getpwall', return_value=[account]), patch.object(backup.grp, 'getgrall', return_value=[group]):
            inventory = backup.identity_inventory()
        self.assertEqual([user['name'] for user in inventory['users']], ['www-data'])
        commands = []
        instance = engine._Engine(self.work, self.root, {}, lambda phase: None, lambda phase: None, io.StringIO())
        instance.phase = 'identities'
        payload = self.root / 'payload'; (payload / 'inventory').mkdir(parents=True)
        (payload / 'inventory/service-identities.json').write_text(json.dumps(inventory))
        (payload / 'inventory/service-identities.json').chmod(0o600)
        with patch.object(engine.pwd, 'getpwnam', return_value=account), patch.object(engine.grp, 'getgrnam', return_value=group), \
             patch.object(instance, 'run', side_effect=lambda args, **kwargs: commands.append(args)):
            self.assertEqual(instance.identities(payload)['users'][0]['name'], 'www-data')
        self.assertEqual(commands, [])

    def test_stock_php83_profiles_and_optional_vendor_runtime_do_not_remove_real_integrity_requirements(self):
        packager = load('community_runtime_packager_fixture', TREE / 'bin/prepare-recovery-runtime.py')
        self.assertIn('php8.3-fpm', engine.PACKAGES)
        self.assertNotIn('php8.5-fpm', engine.PACKAGES)
        self.assertEqual(set(engine.PACKAGES), packager.REQUIRED)
        self.assertEqual(set(backup.REQUIRED_FILES), set(engine.REQUIRED_SYSTEM) - {'var/www/fls/VERSION'})
        for required in engine.REQUIRED_SYSTEM:
            self.assertNotIn('license-core', required)
            self.assertNotIn('opt/fls-tsa/', required)
        self.assertIn('usr/lib/fls/fls-archive-hash', engine.REQUIRED_SYSTEM)
        self.assertIn('etc/fls/private/archive-ed25519.pem', engine.REQUIRED_SYSTEM)
        self.assertIn('etc/fls/credential-key', engine.REQUIRED_SYSTEM)

    @unittest.skipUnless(os.geteuid() == 0, 'Archive input ownership is part of the admission contract')
    def test_logs_free_backup_without_vendor_sdk_or_paid_license_still_passes_and_tampering_fails(self):
        archive, digest = engine_checks.fixture(self.root)
        with patch.object(engine.subprocess, 'run', side_effect=AssertionError('no command during admission')):
            report = engine.inspect_backup(archive, digest, self.work)
            self.assertTrue(report['verified'])
            with self.assertRaisesRegex(engine.RecoveryError, 'backup_checksum_mismatch'):
                engine.inspect_backup(archive, '0' * 64, self.work)
        altered = self.root / 'second'; altered.mkdir()
        archive, digest = engine_checks.fixture(altered, inner_extra=[('var/www/fls/bin/should-not-run.py', b'raise SystemExit(99)')],
            mutate_manifest=lambda manifest: manifest['files']['system.tar'].update(sha256='0' * 64))
        with patch.object(engine.importlib.util, 'spec_from_file_location', side_effect=AssertionError('uploaded Python must not run')):
            with self.assertRaises(engine.RecoveryError): engine.inspect_backup(archive, digest, self.work)

    @unittest.skipUnless(os.geteuid() == 0, 'Kernel metadata ownership is part of the storage contract')
    def test_recovery_serial_identity_matches_guard_and_has_a_stable_lease_digest(self):
        with self.disk() as (device, disk, part, cache):
            major_minor = '{}:{}'.format(os.major(device), os.minor(device))
            real_path = engine.Path
            with patch.object(engine, 'Path', side_effect=lambda path: cache.parent if str(path) == '/run/udev/data' else real_path(path)):
                identity = engine._physical_identity(disk, major_minor)
                self.assertEqual(identity, storage.discover_identity(device)['identity'])
                first = engine._identity_digest(identity)
                self.assertNotEqual(first, engine._identity_digest(identity | {'value': 'other'}))
            (disk / 'serial').write_text('changed\n')
            with patch.object(engine, 'Path', side_effect=lambda path: cache.parent if str(path) == '/run/udev/data' else real_path(path)):
                with self.assertRaises(engine.RecoveryError): engine._physical_identity(disk, major_minor)

    def test_recovery_source_host_is_rejected_before_any_target_write_with_generic_identity(self):
        target = {'eligible': True, 'os_id': 'ubuntu', 'os_version': '24.04', 'architecture': 'x86_64',
                  'machine_sha256': 'a' * 64, 'root_uuid': UUID, 'boot_id': UUID,
                  'root_device': '/dev/vda1', 'root_major_minor': '8:1', 'root_wwn': '',
                  'root_identity': {'kind': 'serial', 'value': 'VMROOT'}, 'free_bytes': 16 * 1024 ** 3}
        target['root_identity_sha256'] = engine._identity_digest(target['root_identity'])
        plan = {'source_machine_sha256': 'a' * 64, 'backup': {'bytes': 1}, 'runtime': {'bytes': 1}}
        fake = types.SimpleNamespace(inspect_target=lambda: copy.deepcopy(target))
        with patch.object(bootstrap, 'private_write', side_effect=AssertionError('no mutation')):
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'source_machine_rejected'):
                bootstrap.target_preflight(fake, plan)
            target['machine_sha256'] = 'b' * 64
            self.assertEqual(bootstrap.target_preflight(fake, plan)['root_identity'], target['root_identity'])
            target['root_identity_sha256'] = '0' * 64
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'target_identity_invalid'):
                bootstrap.target_preflight(fake, plan)

    @unittest.skipUnless(importlib.util.find_spec('pymysql') is not None and os.geteuid() == 0,
                         'Daily SQL dump fixture needs PyMySQL and root ownership checks')
    def test_daily_dump_accepts_single_disk_and_rejects_bad_permissions_or_redirects(self):
        folder = self.root / 'bin'; folder.mkdir()
        for name in ['db-dump-worker.py', 'system-backup.py', 'system-backup-worker.py',
                     'archive_transports.py', 'fls_backup_encryption.py', 'fls_storage.py']:
            source = TREE / 'bin' / name
            if not source.is_file(): source = ROOT / 'bin' / name
            shutil.copyfile(source, folder / name)
        saved_path = sys.path[:]
        saved_module = sys.modules.pop('fls_storage', None)
        self.addCleanup(lambda: setattr(sys, 'path', saved_path))
        if saved_module is not None: self.addCleanup(lambda: sys.modules.__setitem__('fls_storage', saved_module))
        worker = load('community_dump_fixture', folder / 'db-dump-worker.py')
        dumps = self.root / 'db-dumps'; dumps.mkdir(mode=0o700)
        with patch.object(worker, 'DIRECTORY', dumps), patch.object(worker, 'storage_state', return_value={'mode': 'system-root'}):
            worker.assert_storage()
            dumps.chmod(0o755)
            with self.assertRaisesRegex(worker.DumpError, 'directory_permissions'): worker.assert_storage()
            dumps.chmod(0o700); dumps.rename(self.root / 'actual'); dumps.symlink_to(self.root / 'actual')
            with self.assertRaises(worker.DumpError): worker.assert_storage()
        for name in ['fls-db-dump.service', 'fls-db-dump-upload.service']:
            text = (TREE / 'deploy' / name).read_text()
            self.assertIn('RequiresMountsFor=/srv/fls-server/db-dumps', text)
            self.assertNotIn('/srv/fls-storage/DB-Dump', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
