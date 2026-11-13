#!/usr/bin/env python3
"""Collect real installer inventories from disposable Linux metadata fixtures.

Only the four fixed read-only inventory commands are simulated. Filesystem,
udev and sysfs parsing use the shipped collector and storage identity routines;
no HostOps, packages, services, database, network or block device is accessed.
"""
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / 'tools/community/overlay'
TREE = OVERLAY if (OVERLAY / 'bin/install_plan.py').is_file() else ROOT


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


plan = load('community_collected_inventory_fixture', TREE / 'bin/install_plan.py')
storage = load('community_inventory_storage_fixture', TREE / 'bin/fls_storage.py')
MANIFEST = plan.read_json(TREE / 'deploy/installer-components.json')
UUID = '3079e8b2-3257-462e-a6a1-e1ed88eb4def'
SERIAL = 'FLSVM-SYSTEM-0001'
ROOT_DEVICE = os.makedev(8, 5)


@unittest.skipUnless(os.geteuid() == 0,
                     'Real storage identity parsing requires root-owned kernel metadata fixtures')
class CollectedInventoryChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-community-inventory-')
        self.addCleanup(self.temporary.cleanup)
        self.host = Path(self.temporary.name) / 'host'
        self.host.mkdir(mode=0o700)
        for relative in ('etc/systemd/system', 'usr/local/lib/systemd/system',
                         'usr/lib/systemd/system', 'var/lib', 'run/udev/data',
                         'sys/dev/block', 'proc/net'):
            (self.host / relative).mkdir(parents=True, exist_ok=True)
        self.write('etc/os-release', 'ID=ubuntu\nVERSION_ID="24.04"\n')
        self.write('etc/machine-id', '0123456789abcdef0123456789abcdef\n')
        self.write('proc/meminfo', 'MemTotal:        8173000 kB\n')
        for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
            self.write('proc/net/' + protocol, '  sl  local_address rem_address st\n')

        self.disk = self.host / 'sys/devices/pci0000/host0/target0/block/sda'
        (self.disk / 'device').mkdir(parents=True)
        self.partition = self.disk / 'sda5'
        self.partition.mkdir()
        (self.partition / 'partition').write_text('5\n')
        (self.disk / 'device/serial').write_text(SERIAL + '\n')
        (self.host / 'sys/dev/block/8:5').symlink_to(self.partition, target_is_directory=True)
        self.udev = self.host / 'run/udev/data/b8:5'
        self.udev.write_text('E:ID_FS_UUID=' + UUID + '\nE:ID_FS_TYPE=ext4\n'
                             'E:ID_SERIAL_SHORT=' + SERIAL + '\n')

        self.block = {'blockdevices': [{
            'path': '/dev/sda', 'kname': 'sda', 'type': 'disk',
            'size': 200 * plan.GIB, 'ro': False, 'wwn': None, 'serial': SERIAL,
            'model': 'FLS Virtual Disk', 'fstype': None, 'uuid': None,
            'maj:min': '8:0', 'mountpoints': [None],
            'children': [{'path': '/dev/sda5', 'kname': 'sda5', 'type': 'part',
                          'size': 193 * plan.GIB, 'ro': False, 'wwn': None,
                          'serial': None, 'model': None, 'fstype': 'ext4',
                          'uuid': UUID, 'maj:min': '8:5', 'mountpoints': ['/']}]}]}
        self.mount = {'filesystems': [{'source': '/dev/sda5', 'fstype': 'ext4',
                                      'uuid': UUID, 'maj:min': '8:5'}]}
        self.command_outputs = {
            ('/usr/sbin/ip', '-json', '-4', 'address', 'show'): [
                {'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]},
                {'ifname': 'ens3', 'addr_info': [{'family': 'inet', 'local': '192.168.50.10', 'prefixlen': 24}]}],
            ('/usr/sbin/ip', '-json', '-4', 'route', 'show', 'default'): [{'dev': 'ens3'}],
            ('/usr/bin/lsblk', '--json', '--bytes', '--tree', '--output',
             'PATH,KNAME,TYPE,SIZE,RO,WWN,SERIAL,MODEL,FSTYPE,UUID,MAJ:MIN,MOUNTPOINTS'): self.block,
            ('/usr/bin/findmnt', '--json', '--target', '/', '--output',
             'SOURCE,FSTYPE,UUID,MAJ:MIN'): self.mount,
        }
        self.commands = []

    def write(self, relative, content):
        path = self.host / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def mapped_path(self, *parts):
        path = Path(*parts)
        return self.host / path.relative_to('/') if path.is_absolute() else path

    def linux_command(self, arguments, **options):
        command = tuple(arguments)
        self.assertIn(command, self.command_outputs, 'Unexpected host command')
        self.assertTrue(options.get('capture_output'))
        self.assertTrue(options.get('text'))
        self.assertEqual(options.get('timeout'), 5)
        self.commands.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(self.command_outputs[command]), stderr='')

    @contextlib.contextmanager
    def fixture_host(self):
        real_stat = os.stat

        def root_stat(path, *arguments, **options):
            if str(path) == '/':
                return SimpleNamespace(st_dev=ROOT_DEVICE)
            return real_stat(path, *arguments, **options)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(plan, 'Path', self.mapped_path))
            stack.enter_context(patch.object(plan.os, 'stat', side_effect=root_stat))
            stack.enter_context(patch.object(plan.shutil, 'disk_usage',
                                             return_value=shutil._ntuple_diskusage(193 * plan.GIB, 16 * plan.GIB, 177 * plan.GIB)))
            stack.enter_context(patch.object(plan.platform, 'machine', return_value='x86_64'))
            stack.enter_context(patch.object(plan.socket, 'gethostname', return_value='flsrecoverytest'))
            stack.enter_context(patch.object(plan.os, 'cpu_count', return_value=4))
            stack.enter_context(patch.object(plan.subprocess, 'run', side_effect=self.linux_command))
            stack.enter_context(patch.object(storage, 'UDEV', self.host / 'run/udev/data'))
            stack.enter_context(patch.object(storage, 'SYSFS', self.host / 'sys/dev/block'))
            stack.enter_context(patch.dict(sys.modules, {'fls_storage': storage}))
            yield

    def collect(self):
        with self.fixture_host():
            inventory = plan.collect_inventory()
            # Artifact packaging has separate checksum tests. Verified fixture
            # entries isolate admission of the collected host metadata here.
            components = [{'required': False, 'verified': True}]
            report = plan.assess(inventory, MANIFEST, components)
        return inventory, report

    def test_plain_ext4_vm_with_serial_is_admitted_from_actual_metadata(self):
        inventory, report = self.collect()
        self.assertEqual(inventory['probe_errors'], [])
        self.assertEqual(inventory['root']['source'], '/dev/sda5')
        self.assertEqual(inventory['root']['device_identity'], {'kind': 'serial', 'value': SERIAL})
        self.assertTrue(inventory['root']['hardware_identity_matches'])
        self.assertEqual(inventory['disks'][0]['role'], 'system')
        self.assertEqual(report['host_blockers'], [])
        self.assertTrue(report['ready_for_apply'])
        self.assertEqual(len(self.commands), 4)
        self.assertEqual(report['configuration_proposal']['bind_ip'], '192.168.50.10')

    def test_vm_without_wwn_or_serial_does_not_gain_path_based_identity(self):
        self.block['blockdevices'][0]['serial'] = None
        (self.disk / 'device/serial').unlink()
        self.udev.write_text('E:ID_FS_UUID=' + UUID + '\nE:ID_FS_TYPE=ext4\n')
        inventory, report = self.collect()
        self.assertEqual(inventory['probe_errors'], [])
        self.assertIsNone(inventory['root']['device_identity'])
        self.assertFalse(inventory['root']['hardware_identity_matches'])
        self.assertEqual(report['host_blockers'], ['stable_disk_identity_required'])
        self.assertFalse(report['ready_for_apply'])

    def test_vm_sysfs_wwid_is_accepted_without_naa_wwn_or_serial(self):
        self.block['blockdevices'][0]['serial'] = None
        (self.disk / 'device/serial').unlink()
        (self.disk / 'device/wwid').write_text('eui.1234567890abcdef\n')
        self.udev.write_text('E:ID_FS_UUID=' + UUID + '\nE:ID_FS_TYPE=ext4\n')
        inventory, report = self.collect()
        self.assertEqual(inventory['root']['device_identity'], {'kind': 'wwid', 'value': 'eui.1234567890abcdef'})
        self.assertTrue(report['ready_for_apply'])

    def test_esxi_128_bit_naa_is_pinned_as_wwid_without_legacy_truncation(self):
        identifier = '6000c29a44b6e7c20c2f023b83cb7887'
        self.block['blockdevices'][0].update(serial=None, wwn='0x' + identifier)
        (self.disk / 'device/serial').unlink()
        (self.disk / 'device/wwid').write_text('naa.' + identifier + '\n')
        self.udev.write_text('E:ID_FS_UUID=' + UUID + '\nE:ID_FS_TYPE=ext4\n')
        inventory, report = self.collect()
        self.assertEqual(inventory['root']['device_identity'], {'kind': 'wwid', 'value': 'naa.' + identifier})
        self.assertEqual(inventory['root']['disk_wwn'], '0x' + identifier)
        self.assertTrue(inventory['root']['hardware_identity_matches'])
        self.assertEqual(report['host_blockers'], [])
        self.assertTrue(report['ready_for_apply'])

    def test_lvm_root_is_not_mistaken_for_a_plain_disk_partition(self):
        physical = self.block['blockdevices'][0]['children'][0]
        physical.update(fstype='LVM2_member', uuid=None, mountpoints=[None])
        physical['children'] = [{'path': '/dev/mapper/ubuntu--vg-ubuntu--lv', 'kname': 'dm-0',
                                 'type': 'lvm', 'size': 100 * plan.GIB, 'ro': False,
                                 'fstype': 'ext4', 'uuid': UUID, 'maj:min': '253:0', 'mountpoints': ['/']}]
        self.mount['filesystems'][0].update(source='/dev/mapper/ubuntu--vg-ubuntu--lv', **{'maj:min': '253:0'})
        inventory, report = self.collect()
        self.assertFalse(inventory['root']['plain_partition'])
        self.assertFalse(inventory['root']['hardware_identity_matches'])
        self.assertIn('plain_ext4_root_partition_required', report['host_blockers'])
        self.assertIn('stable_disk_identity_required', report['host_blockers'])
        self.assertFalse(report['ready_for_apply'])

    def test_verified_bootstrap_under_tmp_is_not_an_existing_installation(self):
        self.write('tmp/fls-community.12345678/source/fls-community/bin/fls-install.py', '# temporary release source\n')
        self.write('tmp/fls-community.12345678/source/fls-community/deploy/release-files.json', '{}\n')
        inventory, report = self.collect()
        self.assertEqual(inventory['existing_paths'], [])
        self.assertTrue(report['ready_for_apply'])

    def test_real_existing_installation_is_still_rejected(self):
        (self.host / 'etc/fls').mkdir()
        self.write('var/lib/fls-community-install/journal.json', '{}\n')
        inventory, report = self.collect()
        self.assertEqual(inventory['existing_paths'], ['/etc/fls', str(self.host / 'var/lib/fls-community-install')])
        self.assertIn('existing_fls_installation_requires_upgrade', report['host_blockers'])
        self.assertFalse(report['ready_for_apply'])

    def test_kernel_root_device_disagrees_with_mount_report_and_fails_closed(self):
        self.mount['filesystems'][0]['maj:min'] = '8:6'
        self.block['blockdevices'][0]['children'][0]['maj:min'] = '8:6'
        inventory, report = self.collect()
        self.assertFalse(inventory['root']['hardware_identity_matches'])
        self.assertIsNone(inventory['root']['device_identity'])
        self.assertIn('stable_disk_identity_required', report['host_blockers'])
        self.assertFalse(report['ready_for_apply'])

    def test_kernel_disk_name_must_match_physical_lsblk_parent(self):
        self.block['blockdevices'][0]['kname'] = 'sdb'
        inventory, report = self.collect()
        self.assertFalse(inventory['root']['hardware_identity_matches'])
        self.assertIn('stable_disk_identity_required', report['host_blockers'])
        self.assertFalse(report['ready_for_apply'])

    def test_udev_filesystem_uuid_must_match_findmnt_uuid(self):
        self.udev.write_text(self.udev.read_text().replace(UUID, '810a3686-9b56-48c1-8ac9-d59a1d27a98b'))
        inventory, report = self.collect()
        self.assertFalse(inventory['root']['hardware_identity_matches'])
        self.assertIn('stable_disk_identity_required', report['host_blockers'])
        self.assertFalse(report['ready_for_apply'])

    def test_duplicate_root_match_is_not_admitted(self):
        self.block['blockdevices'].append(copy.deepcopy(self.block['blockdevices'][0]))
        inventory, report = self.collect()
        self.assertEqual(inventory['root'], {})
        self.assertIn('root_block_identity_unavailable', inventory['probe_errors'])
        self.assertIn('host_inventory_incomplete', report['host_blockers'])
        self.assertIn('root_physical_disk_unambiguous_required', report['host_blockers'])
        self.assertFalse(report['ready_for_apply'])


if __name__ == '__main__':
    unittest.main()
