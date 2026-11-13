#!/usr/bin/env python3
"""Real inventory/parser fixtures with disposable proc/sysfs/udev metadata.

Only lsblk JSON is supplied by a fake command runner; LinuxProbe, the trusted
metadata reader, filesystem identity checks and public SQL publication run as
implemented. Device node metadata is simulated. No host devices, services,
database connections or mount operations are used.
"""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / 'tools/community/overlay'
TREE = OVERLAY if (OVERLAY / 'bin/fls_disk_ops.py').is_file() else ROOT
sys.path.insert(0, str(TREE / 'bin'))
import fls_disk_ops as ops
import fls_storage as storage

spec = importlib.util.spec_from_file_location('community_disk_inventory_worker', TREE / 'bin/disk-management-worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

BOOT = '278d37a6-bfeb-4d70-bad7-a1770bfaa18c'
UUID = '14544ce0-50d9-47a2-9cbd-541c765e1ba8'
VMWARE_WWID = 'naa.6000c29a44b6e7c20c2f023b83cb7887'
NOW = dt.datetime(2026, 11, 13, 12, 0, tzinfo=dt.timezone.utc)


class Store:
    """Capture exactly the inventory SQL write, without connecting to SQL."""
    def __init__(self):
        self.writes = []

    def rows(self, sql):
        if sql != 'SELECT COALESCE(MAX(id),0) n FROM disk_management_jobs':
            raise AssertionError('Unexpected SQL read: ' + sql)
        return [{'n': 0}]

    def execute(self, sql, args):
        if not sql.startswith('UPDATE disk_management_state SET boot_id='):
            raise AssertionError('Unexpected SQL write: ' + sql)
        self.writes.append((sql, args))


@unittest.skipUnless(os.geteuid() == 0, 'Fixture kernel metadata retains the required root ownership')
class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-community-disk-inventory-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.sys_devices = self.base / 'sys/devices'
        self.sys_block = self.base / 'sys/class/block'
        self.sys_dev_block = self.base / 'sys/dev/block'
        self.udev = self.base / 'run/udev/data'
        self.proc = self.base / 'proc'
        self.data = self.base / 'data'
        self.state = self.base / 'state'
        for directory in (self.sys_devices, self.sys_block, self.sys_dev_block, self.udev, self.proc,
                          self.data, self.state):
            directory.mkdir(parents=True, mode=0o700)
        for directory in ('database/mysql', 'raw', 'archive', 'metrics', 'queue'):
            (self.data / directory).mkdir(parents=True)
        self.boot = self.proc / 'boot-id'
        self.boot.write_text(BOOT + '\n')
        self.boot.chmod(0o444)
        (self.proc / 'swaps').write_text('Filename Type Size Used Priority\n')
        process = self.proc / '12345'
        (process / 'ns').mkdir(parents=True)
        (process / 'ns/mnt').symlink_to('mnt:[12345]')
        (process / 'fd').mkdir()
        root_device = os.stat('/').st_dev
        self.root_number = '{}:{}'.format(os.major(root_device), os.minor(root_device))
        (process / 'mountinfo').write_text(
            '1 0 ' + self.root_number + ' / / rw - ext4 /dev/sda5 rw\n')
        self.disk_numbers = {}
        self.aliases = {}
        self.nodes = []
        self.root_disk = self.add_disk('sda', '8:0', VMWARE_WWID)
        partition = self.root_disk / 'sda5'
        (partition / 'holders').mkdir(parents=True)
        (partition / 'partition').write_text('5\n')
        self.sys_block.joinpath('sda5').symlink_to(partition, target_is_directory=True)
        self.sys_dev_block.joinpath(self.root_number).symlink_to(partition, target_is_directory=True)
        (self.udev / ('b' + self.root_number)).write_text('E:ID_FS_UUID=' + UUID + '\nE:ID_FS_TYPE=ext4\n')
        self.nodes[0]['children'] = [{'path': '/dev/sda5', 'kname': 'sda5', 'type': 'part',
            'size': 193 * 1024**3, 'maj:min': self.root_number, 'fstype': 'ext4', 'uuid': UUID,
            'pttype': 'gpt', 'mountpoints': ['/']}]
        self.config = {'schema': 2, 'mode': 'system-root', 'root_uuid': UUID,
                       'device_identity': {'kind': 'wwid', 'value': VMWARE_WWID}}
        self.config_path = self.base / 'storage.json'
        self.config_path.write_text(json.dumps(self.config))
        (self.state / 'token-key.json').write_text(json.dumps({'key': 'a' * 64}))
        self.commands = []
        self.kernel_stat_size = 4096

        real_stat = Path.stat
        real_resolve = Path.resolve
        real_fstat = os.fstat

        def device_stat(path, *args, **kwargs):
            if str(path) in self.disk_numbers:
                major, minor = map(int, self.disk_numbers[str(path)].split(':'))
                return types.SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(major, minor))
            return real_stat(path, *args, **kwargs)

        def resolve(path, *args, **kwargs):
            if str(path) in self.aliases:
                return Path(self.aliases[str(path)])
            if str(path) in self.disk_numbers:
                return path
            return real_resolve(path, *args, **kwargs)

        def sysfs_fstat(descriptor):
            info = real_fstat(descriptor)
            name = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
            if self.sys_devices in name.parents and stat.S_ISREG(info.st_mode):
                # Linux sysfs advertises PAGE_SIZE, not the payload length.
                values = list(info)
                values[6] = self.kernel_stat_size
                return os.stat_result(values)
            return info

        for owner, name, value in (
            (storage, 'CONFIG', self.config_path), (storage, 'DATA', self.data),
            (storage, 'SYSFS', self.sys_dev_block), (storage, 'UDEV', self.udev),
            (ops, 'SYS_BLOCK', self.sys_block), (ops, 'UDEV_DATA', self.udev),
            (ops, 'PROC', self.proc), (ops, 'BOOT_ID', self.boot),
            (worker, 'STATE', self.state), (worker, 'MIRROR', self.base / 'no-mirror.json'),
            (Path, 'stat', device_stat), (Path, 'resolve', resolve), (os, 'fstat', sysfs_fstat)):
            context = patch.object(owner, name, value)
            context.start()
            self.addCleanup(context.stop)
        self.host = ops.CommunityHostOps(runner=self.runner, mirror_loader=lambda: None, clock=lambda: NOW)
        context = patch.object(self.host, 'config', side_effect=lambda:
            storage.validate_config(json.loads(storage.trusted_read(self.config_path, 4096))))
        context.start()
        self.addCleanup(context.stop)

    def add_disk(self, name, number, wwid):
        disk = self.sys_devices / name
        (disk / 'holders').mkdir(parents=True)
        (disk / 'device').mkdir()
        (disk / 'queue').mkdir()
        for relative, value in [('diskseq', '7'), ('size', str(200 * 1024**3 // 512)),
                                ('queue/logical_block_size', '512'), ('device/wwid', wwid),
                                ('dev', number)]:
            (disk / relative).write_text(value + '\n')
            (disk / relative).chmod(0o444)
        self.sys_block.joinpath(name).symlink_to(disk, target_is_directory=True)
        (self.udev / ('b' + number)).write_text('E:ID_SERIAL_SHORT=' + wwid[4:] + '\n')
        self.disk_numbers['/dev/' + name] = number
        self.nodes.append({'path': '/dev/' + name, 'kname': name, 'type': 'disk',
            'size': 200 * 1024**3, 'ro': False, 'rm': False, 'wwn': '0x' + wwid[4:],
            'serial': wwid[4:], 'model': 'VMware Virtual disk', 'log-sec': 512,
            'maj:min': number, 'fstype': None, 'uuid': None, 'pttype': 'gpt',
            'mountpoints': [None]})
        return disk

    def runner(self, args, **kwargs):
        self.commands.append(args)
        if (args[:5] != ['/usr/bin/lsblk', '--json', '--bytes', '--tree', '--output']
                or kwargs):
            raise AssertionError('Only the read-only lsblk query is permitted')
        return types.SimpleNamespace(returncode=0, stdout=json.dumps({'blockdevices': self.nodes}), stderr='')

    def test_page_sized_sysfs_metadata_produces_verified_system_role(self):
        observed = self.host.inventory()
        system = observed['system']
        key = 'id:' + hashlib.sha256(json.dumps(self.config['device_identity'], sort_keys=True).encode()).hexdigest()
        self.assertEqual(observed['mode'], 'system-root')
        self.assertIsNone(observed['primary'])
        self.assertEqual(system['wwn'], key)
        self.assertEqual(system['physical_identity'], self.config['device_identity'])
        self.assertIn('system_disk_protected', system['blockers'])
        self.assertIn('disk_mounted', system['blockers'])
        self.assertFalse(system['eligible'])
        self.assertEqual(system['size_bytes'], 200 * 1024**3)
        self.assertEqual(len(self.commands), 1)

    def test_actual_probe_reaches_publication_and_marks_verified_role_present(self):
        store = Store()
        with patch.object(worker, 'iso', return_value=NOW.isoformat()):
            public = worker.publish(store, self.host, None)
        self.assertTrue(public['system']['present'])
        self.assertEqual(public['system']['filesystem_uuid'], UUID)
        self.assertEqual(public['system']['mount_path'], '/')
        self.assertIsNone(public['depot'])
        self.assertIsNone(public['mirror'])
        self.assertEqual(public['candidates'], [])
        self.assertEqual(store.writes[0][1][1:3], ('idle', ''))
        self.assertEqual(json.loads(store.writes[0][1][-1]), public)
        plans = worker.safe_json(self.state / 'plans.json')
        self.assertEqual(plans['plans'], {})

    def test_second_vmware_disk_remains_separate_eligible_candidate(self):
        self.add_disk('sdb', '8:16', 'naa.6000c299999999999999999999999999')
        store = Store()
        public = worker.publish(store, self.host, None)
        self.assertTrue(public['system']['present'])
        self.assertEqual(len(public['candidates']), 1)
        self.assertTrue(public['candidates'][0]['eligible'])
        self.assertEqual(public['candidates'][0]['reasons'], [])
        self.assertNotEqual(public['candidates'][0]['wwn'], public['system']['wwn'])
        plan = next(iter(worker.safe_json(self.state / 'plans.json')['plans'].values()))
        self.assertEqual(plan['physical_identity']['value'], 'naa.6000c299999999999999999999999999')
        self.assertEqual(plan['path'], '/dev/sdb')

    def test_duplicate_vmware_identity_rejects_candidate_inventory(self):
        self.add_disk('sdb', '8:16', VMWARE_WWID)
        with self.assertRaisesRegex(ops.DiskOpsError, 'duplicate_physical_disk_identity'):
            self.host.inventory()

    def test_legacy_64bit_naa_keeps_real_wwn_and_verified_by_id_path(self):
        identity = {'kind': 'wwn', 'value': '0x5000000000000001'}
        self.config['device_identity'] = identity
        self.config_path.write_text(json.dumps(self.config))
        path = self.root_disk / 'device/wwid'
        path.chmod(0o644)
        path.write_text('naa.' + identity['value'][2:] + '\n')
        self.nodes[0]['wwn'] = identity['value']
        self.aliases['/dev/disk/by-id/wwn-' + identity['value']] = '/dev/sda'
        system = self.host.inventory()['system']
        self.assertEqual(system['wwn'], identity['value'])
        self.assertEqual(system['physical_identity'], identity)
        self.assertEqual(system['path'], '/dev/disk/by-id/wwn-' + identity['value'])
        self.assertNotIn('stable_path_mismatch', system['blockers'])
        self.assertFalse(system['eligible'])

    def test_bad_root_major_minor_is_rejected_before_publication(self):
        (self.root_disk / 'dev').chmod(0o644)
        (self.root_disk / 'dev').write_text('8:0 extra-field\n')
        with self.assertRaisesRegex(ops.DiskOpsError, 'pinned_system_disk_number_invalid'):
            self.host.inventory()

    def test_kernel_physical_identity_change_is_rejected(self):
        path = self.root_disk / 'device/wwid'
        path.chmod(0o644)
        path.write_text('naa.6000c299999999999999999999999999\n')
        with self.assertRaises(storage.StorageError):
            self.host.inventory()

    def test_pinned_filesystem_uuid_change_is_rejected(self):
        metadata = self.udev / ('b' + self.root_number)
        metadata.write_text(metadata.read_text().replace(UUID, '8e8c9c65-0c53-4f35-ac08-36091aa23f7a'))
        with self.assertRaises(storage.StorageError):
            self.host.inventory()

    def test_oversized_kernel_number_metadata_remains_rejected(self):
        path = self.root_disk / 'dev'
        path.chmod(0o644)
        path.write_text('8:0' + ' ' * 8192)
        with self.assertRaises(storage.StorageError):
            self.host.inventory()

    def test_missing_root_node_is_rejected_without_mutating_host(self):
        self.nodes.clear()
        with self.assertRaisesRegex(ops.DiskOpsError, 'pinned_system_disk_missing'):
            self.host.inventory()
        self.assertEqual(len(self.commands), 1)

    def test_missing_hardware_identity_blocks_second_disk_selection(self):
        disk = self.add_disk('sdb', '8:16', 'naa.6000c299999999999999999999999999')
        (disk / 'device/wwid').unlink()
        observed = self.host.inventory()
        candidate = observed['disks'][1]
        self.assertFalse(candidate['eligible'])
        self.assertIn('hardware_identity_unavailable', candidate['blockers'])


if __name__ == '__main__':
    unittest.main()
