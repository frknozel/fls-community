#!/usr/bin/python3
"""Storage identity failure cases; temporary data never touches live FLS paths."""
import grp
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import fls_storage as guard

UUID = '3079e8b2-3257-462e-a6a1-e1ed88eb4def'
WWN = '0x5000000000000001'


@unittest.skipUnless(os.geteuid() == 0, 'Root ownership is part of the storage contract')
class StorageGuard(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-storage-guard-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.config = self.base / 'storage.json'
        self.data = self.base / 'data'
        self.udev = self.base / 'udev'
        self.sysfs = self.base / 'sysfs'
        self.data.mkdir()
        for name in ('raw', 'queue', 'metrics', 'archive', 'database/mysql'):
            (self.data / name).mkdir(parents=True, exist_ok=True)
        self.udev.mkdir()
        self.sysfs.mkdir()
        root = os.stat('/').st_dev
        self.device = '{}:{}'.format(os.major(root), os.minor(root))
        self.cache = self.udev / ('b' + self.device)
        self.cache.write_text('E:ID_FS_UUID=' + UUID + '\n')
        disk = self.base / 'physical-disk'
        partition = disk / 'partition4'
        partition.mkdir(parents=True)
        (partition / 'partition').write_text('4\n')
        (disk / 'device').mkdir()
        self.wwid = disk / 'device/wwid'
        self.wwid.write_text('naa.' + WWN[2:] + '\n')
        (self.sysfs / self.device).symlink_to(partition, target_is_directory=True)
        for name, value in [('CONFIG', self.config), ('DATA', self.data), ('UDEV', self.udev), ('SYSFS', self.sysfs)]:
            context = patch.object(guard, name, value)
            context.start()
            self.addCleanup(context.stop)
        self.write_config()

    def write_config(self, **values):
        self.config.write_text(json.dumps({'schema': 1, 'mode': 'system-root', 'root_uuid': UUID, 'device_wwn': WWN} | values))
        self.config.chmod(0o644)

    @unittest.skipUnless(os.environ.get("FLS_STORAGE_EXPECT_PRIVATE_DEVICES") == "1", "Requires the isolated systemd namespace")
    def test_private_devices_namespace_is_real(self):
        self.assertFalse(Path("/dev/disk").exists())
        self.assertTrue(Path("/dev/null").exists())

    def test_system_root_works_without_any_dev_node_lookup(self):
        state = guard.storage_state()
        self.assertEqual(state['mode'], 'system-root')
        self.assertEqual(state['root_uuid'], UUID)
        self.assertEqual(state['device_wwn'], WWN)
        self.assertEqual(state['device'], self.device)

    def test_missing_config_retains_dedicated_mount_requirement(self):
        self.config.unlink()
        with patch.object(guard.os.path, 'ismount', return_value=False):
            with self.assertRaises(guard.StorageError):
                guard.storage_state()
        with patch.object(guard.os.path, 'ismount', return_value=True):
            self.assertEqual(guard.storage_state()['mode'], 'dedicated')

    def test_corrupt_config_never_falls_back_to_a_mount_check(self):
        self.config.write_text('{')
        with patch.object(guard.os.path, 'ismount', return_value=True):
            with self.assertRaises(guard.StorageError):
                guard.storage_state()

    def test_config_cannot_be_redirected_or_writable_by_service_accounts(self):
        self.config.chmod(0o664)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()
        self.config.chmod(0o644)
        alternate = self.base / 'alternate'
        self.config.rename(alternate)
        self.config.symlink_to(alternate)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_other_root_uuid_is_rejected_even_on_the_same_disk(self):
        self.cache.write_text('E:ID_FS_UUID=531c3316-a72b-4cd4-96b3-c67d004208c5\n')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_other_physical_disk_is_rejected_even_with_cloned_uuid(self):
        self.wwid.write_text('naa.5000c500d5d1aab4\n')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_unavailable_or_ambiguous_udev_cache_fails_closed(self):
        self.cache.unlink()
        with self.assertRaises(guard.StorageError):
            guard.storage_state()
        self.cache.write_text('E:ID_FS_UUID=' + UUID + '\nE:ID_FS_UUID=' + UUID + '\n')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_incomplete_copy_or_symlinked_data_is_rejected(self):
        raw = self.data / 'raw'
        raw.rmdir()
        with self.assertRaises(guard.StorageError):
            guard.storage_state()
        other = self.base / 'other-raw'
        other.mkdir()
        raw.symlink_to(other, target_is_directory=True)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_writable_data_root_is_rejected(self):
        self.data.chmod(0o777)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_strict_mode_and_identity_schema(self):
        for value in ({'schema': True}, {'mode': 'dedicated'}, {'root_uuid': '../../bad'}, {'device_wwn': '../../bad'}, {'unknown': 'key'}):
            with self.subTest(value=value):
                self.write_config(**value)
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()


@unittest.skipUnless(os.geteuid() == 0, 'Root ownership is part of the storage contract')
class HybridStorageGuard(unittest.TestCase):
    """Exercise the real identity parser with only filesystem metadata virtualized."""
    write_config = StorageGuard.write_config

    def setUp(self):
        StorageGuard.setUp(self)
        self.depot = self.base / 'depot'
        self.published = self.base / 'published'
        self.published.mkdir()
        self.depot.mkdir()
        (self.data / 'backups').mkdir()
        self.dump = self.depot / 'DB-Dump'
        self.dump.mkdir(mode=0o700)
        self.bindings = {}
        for name in ('raw', 'archive', 'queue', 'metrics'):
            source = self.depot / 'FLS-Logs' / name
            source.mkdir(parents=True)
            self.bindings[self.data / name] = source
        for name, target in [('staging', self.data / 'backups'), ('published', self.published)]:
            source = self.depot / 'FLS-Backups' / name
            source.mkdir(parents=True)
            self.bindings[target] = source
        self.depot_uuid = '810a3686-9b56-48c1-8ac9-d59a1d27a98b'
        self.depot_wwn = '0x5000000000000002'
        self.depot_dev = os.makedev(8, 241)
        self.depot_device = '8:241'
        self.depot_cache = self.udev / ('b' + self.depot_device)
        self.depot_cache.write_text('E:ID_FS_UUID=' + self.depot_uuid + '\n')
        disk = self.base / 'depot-disk'
        partition = disk / 'partition1'
        partition.mkdir(parents=True)
        (partition / 'partition').write_text('1\n')
        (disk / 'device').mkdir()
        self.depot_wwid = disk / 'device/wwid'
        self.depot_wwid.write_text('naa.' + self.depot_wwn[2:] + '\n')
        (self.sysfs / self.depot_device).symlink_to(partition, target_is_directory=True)
        self.mountinfo = self.base / 'mountinfo'
        self.mount_rows = {self.depot: '/'} | {
            target: '/' + str(source.relative_to(self.depot)) for target, source in self.bindings.items()}
        self.write_mounts()
        for name, value in [('DEPOT', self.depot), ('PUBLISHED', self.published), ('MOUNTINFO', self.mountinfo)]:
            context = patch.object(guard, name, value)
            context.start()
            self.addCleanup(context.stop)
        self.real_lstat = Path.lstat
        self.wrong_inodes = set()
        self.override_devices = {}
        self.override_owners = {}
        def fake_lstat(path, *args, **kwargs):
            values = list(self.real_lstat(path, *args, **kwargs))
            if path == self.depot or self.depot in path.parents:
                values[2] = self.depot_dev
            if path in self.bindings:
                values[2] = self.depot_dev
                values[1] = self.real_lstat(self.bindings[path]).st_ino + (path in self.wrong_inodes)
            if path in self.override_devices:
                values[2] = self.override_devices[path]
            if path in self.override_owners:
                values[4], values[5] = self.override_owners[path]
            return os.stat_result(values)
        context = patch.object(Path, 'lstat', fake_lstat)
        context.start()
        self.addCleanup(context.stop)
        self.hybrid_config()

    def hybrid_config(self, **values):
        self.write_config(mode='hybrid', depot_uuid=self.depot_uuid,
                          depot_wwn=self.depot_wwn, depot_path='/srv/fls-storage', **values)

    def write_mounts(self):
        self.mountinfo.write_text(''.join(
            '{} 1 {} {} {} rw - ext4 /dev/fake rw\n'.format(
                number + 2, self.depot_device, root, target)
            for number, (target, root) in enumerate(self.mount_rows.items())))

    def test_hybrid_uses_metadata_without_block_device_nodes(self):
        with patch.object(guard.os, 'listdir', side_effect=AssertionError('No private folder listing')):
            value = guard.storage_state()
        self.assertEqual(value['mode'], 'hybrid')
        self.assertEqual(value['device'], self.device)
        self.assertEqual(value['depot_device'], self.depot_device)
        self.assertEqual(value['depot_uuid'], self.depot_uuid)
        self.assertEqual(value['depot_wwn'], self.depot_wwn)
        self.assertEqual(value['depot_path'], str(self.depot))
        self.assertEqual(value['queue_location'], 'depot')

    def test_depot_on_root_filesystem_is_rejected(self):
        self.override_devices[self.depot] = os.stat('/').st_dev
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_each_of_six_missing_binds_fails_closed(self):
        for target in self.bindings:
            with self.subTest(target=target):
                root = self.mount_rows.pop(target)
                self.write_mounts()
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()
                self.mount_rows[target] = root
        self.write_mounts()
        guard.storage_state()

    def test_same_disk_bind_from_wrong_folder_is_rejected(self):
        for target in self.bindings:
            with self.subTest(target=target):
                self.wrong_inodes.add(target)
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()
                self.wrong_inodes.clear()
        target = self.data / 'raw'
        self.mount_rows[target] = '/other-raw'
        self.write_mounts()
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_clone_uuid_on_another_disk_is_rejected(self):
        self.depot_wwid.write_text('naa.5000c50000000001\n')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_wrong_or_duplicate_depot_uuid_metadata_is_rejected(self):
        for value in ('E:ID_FS_UUID=' + UUID + '\n',
                      'E:ID_FS_UUID=' + self.depot_uuid + '\nE:ID_FS_UUID=' + self.depot_uuid + '\n'):
            self.depot_cache.write_text(value)
            with self.subTest(value=value), self.assertRaises(guard.StorageError):
                guard.storage_state()

    def test_depot_must_be_partition_root_not_subdirectory_bind(self):
        self.mount_rows[self.depot] = '/some/subdirectory'
        self.write_mounts()
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_database_cannot_move_to_hdd(self):
        self.override_devices[self.data / 'database/mysql'] = self.depot_dev
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_root_uuid_and_wwn_are_checked_in_hybrid_mode(self):
        self.wwid.write_text('naa.5000c50000000001\n')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_root_only_dump_and_trusted_depot_parents(self):
        self.dump.chmod(0o750)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()
        self.dump.chmod(0o700)
        (self.depot / 'FLS-Backups').chmod(0o777)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_redirected_source_is_rejected_even_with_matching_target(self):
        source = self.depot / 'FLS-Logs/raw'
        source.rmdir()
        source.symlink_to(self.depot / 'FLS-Logs/archive', target_is_directory=True)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_missing_or_ambiguous_mount_metadata_is_rejected(self):
        self.mountinfo.unlink()
        with self.assertRaises(guard.StorageError):
            guard.storage_state()
        self.write_mounts()
        self.mountinfo.write_text(self.mountinfo.read_text() * 2)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_systemd_read_write_path_stacked_mounts_are_allowed(self):
        target = self.data / 'raw'
        lower = self.mountinfo.read_text().splitlines()[1].split()[0]
        # Same underlying filesystem/subdirectory, independently rebound by
        # systemd to make a ProtectSystem=strict path writable.
        self.mountinfo.write_text(self.mountinfo.read_text() +
            '300 {} {} /FLS-Logs/raw {} rw - ext4 /dev/fake rw\n'.format(
                lower, self.depot_device, target))
        self.assertEqual(guard.storage_state()['mode'], 'hybrid')

    def test_foreign_top_mount_rejected_even_when_lower_mount_matches(self):
        target = self.data / 'raw'
        lower = self.mountinfo.read_text().splitlines()[1].split()[0]
        self.mountinfo.write_text(self.mountinfo.read_text() +
            '300 {} {} /wrong/raw {} rw - ext4 /dev/fake rw\n'.format(
                lower, self.depot_device, target))
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_hybrid_schema_rejects_identity_reuse_and_arbitrary_paths(self):
        original = json.loads(self.config.read_text())
        for change in ({'depot_uuid': UUID}, {'depot_wwn': WWN},
                       {'depot_path': '/srv/other'}, {'depot_path': '/srv/fls-storage/../fls-storage'},
                       {'depot_uuid': '../../bad'}, {'depot_wwn': '../../bad'}):
            with self.subTest(change=change):
                self.config.write_text(json.dumps(original | change))
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()


@unittest.skipUnless(os.geteuid() == 0, 'Root ownership is part of the storage contract')
class SystemQueueGuard(unittest.TestCase):
    write_config = StorageGuard.write_config
    hybrid_config = HybridStorageGuard.hybrid_config
    write_mounts = HybridStorageGuard.write_mounts

    def setUp(self):
        HybridStorageGuard.setUp(self)
        self.queue = self.data / 'queue'
        self.bindings.pop(self.queue)
        self.mount_rows.pop(self.queue)
        self.queue.chmod(0o750)
        self.queue_owner = (pwd.getpwnam('syslog').pw_uid, grp.getgrnam('adm').gr_gid)
        self.override_owners[self.queue] = self.queue_owner
        self.write_mounts()
        self.hybrid_config(queue_location='system')

    def add_mount(self, path, root, device=None):
        self.mountinfo.write_text(self.mountinfo.read_text() +
            '300 1 {} {} {} rw - ext4 /dev/fake rw\n'.format(
                device or self.device, root, path))

    def test_ssd_queue_and_five_hdd_binds_are_accepted(self):
        state = guard.storage_state()
        self.assertEqual(state['mode'], 'hybrid')
        self.assertEqual(state['queue_location'], 'system')
        self.assertEqual(state['depot_device'], self.depot_device)
        self.assertEqual(len(self.bindings), 5)

    def test_systemd_exact_ssd_queue_rebind_is_accepted(self):
        self.add_mount(self.queue, str(self.queue))
        self.assertEqual(guard.storage_state()['queue_location'], 'system')

    def test_parent_exact_rebind_is_accepted_but_foreign_parent_is_rejected(self):
        original = self.mountinfo.read_text()
        self.add_mount(self.data, str(self.data))
        guard.storage_state()
        self.mountinfo.write_text(original)
        self.add_mount(self.data, '/other/data')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_queue_rebound_from_another_ssd_directory_is_rejected(self):
        self.add_mount(self.queue, '/other/queue')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_queue_on_hdd_or_other_device_is_rejected(self):
        for dev in (self.depot_dev, os.makedev(8, 255)):
            with self.subTest(device=dev):
                self.override_devices[self.queue] = dev
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()

    def test_queue_owner_and_group_must_match_collector(self):
        for owner in ((0, self.queue_owner[1]), (self.queue_owner[0], 0)):
            with self.subTest(owner=owner):
                self.override_owners[self.queue] = owner
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()

    def test_queue_permissions_must_remain_private(self):
        for mode in (0o777, 0o770, 0o755):
            self.queue.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(guard.StorageError):
                guard.storage_state()

    def test_missing_or_symlinked_queue_is_rejected(self):
        self.queue.rmdir()
        with self.assertRaises(guard.StorageError):
            guard.storage_state()
        other = self.data / 'other-queue'
        other.mkdir(mode=0o750)
        self.queue.symlink_to(other, target_is_directory=True)
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_each_required_hdd_bind_still_fails_closed(self):
        for target in self.bindings:
            with self.subTest(target=target):
                root = self.mount_rows.pop(target)
                self.write_mounts()
                with self.assertRaises(guard.StorageError):
                    guard.storage_state()
                self.mount_rows[target] = root

    def test_missing_hdd_still_fails_closed(self):
        self.override_devices[self.depot] = os.stat('/').st_dev
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_only_explicit_system_value_is_accepted(self):
        original = json.loads(self.config.read_text())
        for value in ('depot', 'ssd', '/srv/fls-server/queue', True, None, 1):
            self.config.write_text(json.dumps(original | {'queue_location': value}))
            with self.subTest(value=value), self.assertRaises(guard.StorageError):
                guard.storage_state()
        self.write_config(queue_location='system')
        with self.assertRaises(guard.StorageError):
            guard.storage_state()

    def test_service_identity_lookup_failure_is_closed(self):
        with patch.object(guard.pwd, 'getpwnam', side_effect=KeyError('missing')):
            with self.assertRaises(guard.StorageError):
                guard.storage_state()


if __name__ == '__main__':
    unittest.main()
