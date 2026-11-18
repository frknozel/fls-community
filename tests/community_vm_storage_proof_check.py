#!/usr/bin/env python3
"""Offline underlay budget/guard tests: fake metadata and streams, no mounts."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tests/community_vm_storage_proof.py'
spec = importlib.util.spec_from_file_location('vm_readonly', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
VIEW = '/run/fls-rc9-acceptance/root-view'
SCOPE = 'srv/fls-server/raw'
MiB = 1024 * 1024


def metadata(size=0, mode=stat.S_IFREG | 0o600, inode=1, device=5):
    return SimpleNamespace(st_size=size, st_mode=mode, st_ino=inode, st_dev=device,
                           st_uid=0, st_gid=0, st_mtime_ns=1, st_ctime_ns=1, st_nlink=1)


class FakePath:
    def __init__(self, fs, path):
        self.fs, self.path = fs, PurePosixPath(path)

    def __str__(self):
        return str(self.path)

    def __eq__(self, other):
        return isinstance(other, FakePath) and self.path == other.path

    def __truediv__(self, child):
        return FakePath(self.fs, self.path / child)

    def resolve(self):
        return self

    def relative_to(self, other):
        return self.path.relative_to(other.path)

    def stat(self):
        try:
            return self.fs.entries[str(self)]
        except KeyError:
            raise FileNotFoundError(str(self)) from None

    lstat = stat

    def iterdir(self):
        return iter(self.fs.path(p) for p in self.fs.children.get(str(self), ()))

    def read_text(self):
        if str(self) != '/proc/self/mountinfo':
            raise AssertionError('Unexpected read: ' + str(self))
        return self.fs.mountinfo


class FakeStream:
    chunk = b'\0' * 65536

    def __init__(self, fs, descriptor):
        self.fs, self.descriptor = fs, descriptor
        self.position = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def fileno(self):
        return self.descriptor

    def read(self, count):
        if len(self.fs.read_calls) >= self.fs.max_read_calls:
            raise AssertionError('Offline read-call bound exceeded')
        path = self.fs.handles[self.descriptor]
        remaining = self.fs.stream_sizes.get(path, self.fs.entries[path].st_size) - self.position
        length = min(count, remaining)
        self.fs.read_calls.append((path, count, length))
        self.fs.bytes_returned += length
        if length == 0:
            return b''
        self.position += length
        if path in self.fs.contents:
            return self.fs.contents[path][self.position-length:self.position]
        return self.chunk if length == len(self.chunk) else self.chunk[:length]


class CountHash:
    def __init__(self):
        self.count = 0

    def update(self, chunk):
        self.count += len(chunk)

    def hexdigest(self):
        return 'mocked_full_stream_bytes:' + str(self.count)


class FakeFilesystem:
    def __init__(self, sizes):
        self.entries = {'/': metadata(mode=stat.S_IFDIR | 0o755),
                        VIEW: metadata(mode=stat.S_IFDIR | 0o700),
                        VIEW + '/' + SCOPE: metadata(mode=stat.S_IFDIR | 0o755)}
        self.children, self.contents, self.handles, self.open_flags = {}, {}, {}, []
        self.stream_sizes, self.after_sizes, self.fstat_calls = {}, {}, {}
        self.read_calls, self.bytes_returned = [], 0
        self.max_read_calls = 20000
        self.mountinfo = f'50 1 8:5 / {VIEW} ro,nosuid - ext4 /dev/sda5 rw\n'
        files = []
        for index, size in enumerate(sizes):
            path = f'{VIEW}/{SCOPE}/{index:04d}.jsonl'
            self.entries[path] = metadata(size=size, inode=index + 10)
            files.append(path)
        self.children[VIEW + '/' + SCOPE] = files

    def path(self, value):
        return FakePath(self, str(value))

    def open(self, path, flags):
        self.open_flags.append(flags)
        descriptor = len(self.handles) + 100
        self.handles[descriptor] = str(path)
        return descriptor

    def fstat(self, descriptor):
        path = self.handles[descriptor]
        self.fstat_calls[descriptor] = self.fstat_calls.get(descriptor, 0) + 1
        if self.fstat_calls[descriptor] > 1 and path in self.after_sizes:
            values = vars(self.entries[path]).copy()
            values['st_size'] = self.after_sizes[path]
            return SimpleNamespace(**values)
        return self.entries[path]

    def observe(self, count_hash=True, same_namespace=False):
        with patch.object(helper, 'Path', self.path), \
             patch.object(helper, 'SCOPES', (SCOPE,)), \
             patch.object(helper.os, 'readlink', side_effect=lambda p: 'mnt:1' if same_namespace or str(p) == '/proc/1/ns/mnt' else 'mnt:2'), \
             patch.object(helper.os, 'open', side_effect=self.open), \
             patch.object(helper.os, 'fstat', side_effect=self.fstat), \
             patch.object(helper.os, 'fdopen', side_effect=lambda fd, mode, buffering: FakeStream(self, fd)) as fdopen:
            self.fdopen_mock = fdopen
            if count_hash:
                with patch.object(helper.hashlib, 'sha256', CountHash):
                    return helper.underlay(self.path(VIEW))
            return helper.underlay(self.path(VIEW))


class UnderlayChecks(unittest.TestCase):
    def test_fixed_measured_headroom(self):
        self.assertEqual(helper.MAX_UNDERLAY_FILE_BYTES, 256 * MiB)
        self.assertEqual(helper.MAX_UNDERLAY_TOTAL_BYTES, 512 * MiB)
        fs = FakeFilesystem([51 * MiB + MiB // 5, 102 * MiB + 2 * MiB // 5])
        result = fs.observe()
        self.assertEqual(result['regular_file_bytes_hashed'], sum(info.st_size for info in fs.entries.values()))

    def test_file_boundary_exact_allowed(self):
        fs = FakeFilesystem([256 * MiB])
        result = fs.observe()
        entry = result['entries'][SCOPE + '/0000.jsonl']
        self.assertEqual(entry['sha256'], 'mocked_full_stream_bytes:' + str(256 * MiB))
        self.assertEqual(fs.bytes_returned, 256 * MiB)
        self.assertEqual(fs.read_calls[-1][1:], (1, 0))

    def test_file_boundary_plus_one_rejected_before_open(self):
        fs = FakeFilesystem([256 * MiB + 1])
        with self.assertRaisesRegex(RuntimeError, 'byte bound exceeded'):
            fs.observe()
        self.assertEqual(fs.open_flags, [])

    def test_total_boundary_exact_allowed(self):
        fs = FakeFilesystem([256 * MiB, 256 * MiB])
        self.assertEqual(fs.observe()['regular_file_bytes_hashed'], 512 * MiB)
        self.assertEqual(fs.bytes_returned, 512 * MiB)
        self.assertEqual(fs.read_calls[-1][1:], (1, 0))

    def test_total_boundary_plus_one_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'byte bound exceeded'):
            FakeFilesystem([256 * MiB, 256 * MiB, 1]).observe()

    def test_actual_file_read_plus_one_rejected(self):
        fs = FakeFilesystem([256 * MiB])
        path = fs.children[VIEW + '/' + SCOPE][0]
        fs.stream_sizes[path] = 256 * MiB + 1
        with self.assertRaisesRegex(RuntimeError, 'read byte bound exceeded'):
            fs.observe()
        self.assertEqual(fs.bytes_returned, 256 * MiB + 1)
        self.assertEqual(fs.read_calls[-1][1:], (1, 1))

    def test_actual_total_read_plus_one_rejected(self):
        fs = FakeFilesystem([128 * MiB, 128 * MiB, 256 * MiB])
        # Traversal is LIFO: the final 128 MiB stream grows by one byte;
        # its own file limit is not reached, so this isolates the total limit.
        path = fs.children[VIEW + '/' + SCOPE][0]
        fs.stream_sizes[path] = 128 * MiB + 1
        with self.assertRaisesRegex(RuntimeError, 'read byte bound exceeded'):
            fs.observe()
        self.assertEqual(fs.bytes_returned, 512 * MiB + 1)
        self.assertEqual(fs.read_calls[-1][1:], (1, 1))

    def test_continuously_growing_stream_stops_at_limit_plus_one(self):
        fs = FakeFilesystem([1])
        path = fs.children[VIEW + '/' + SCOPE][0]
        fs.stream_sizes[path] = float('inf')
        fs.max_read_calls = 4100
        with self.assertRaisesRegex(RuntimeError, 'read byte bound exceeded'):
            fs.observe()
        self.assertEqual(fs.bytes_returned, 256 * MiB + 1)
        self.assertEqual(len(fs.read_calls), 4097)
        self.assertEqual(fs.read_calls[-1][1:], (1, 1))

    def test_short_stream_rejected_even_if_metadata_unchanged(self):
        fs = FakeFilesystem([9])
        path = fs.children[VIEW + '/' + SCOPE][0]
        fs.stream_sizes[path] = 8
        with self.assertRaisesRegex(RuntimeError, 'file changed during observation'):
            fs.observe()

    def test_postread_metadata_change_rejected(self):
        fs = FakeFilesystem([9])
        path = fs.children[VIEW + '/' + SCOPE][0]
        fs.after_sizes[path] = 10
        with self.assertRaisesRegex(RuntimeError, 'file changed during observation'):
            fs.observe()

    def test_entry_boundary_exact_allowed(self):
        self.assertEqual(len(FakeFilesystem([0] * 4095).observe()['entries']), 4096)

    def test_entry_boundary_plus_one_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'entry bound exceeded'):
            FakeFilesystem([0] * 4096).observe()

    def test_hash_is_full_bytes_and_changed_content_differs(self):
        fs = FakeFilesystem([9])
        path = fs.children[VIEW + '/' + SCOPE][0]
        fs.contents[path] = b'old-copy!'
        before = fs.observe(count_hash=False)
        self.assertEqual(before['entries'][SCOPE + '/0000.jsonl']['sha256'], hashlib.sha256(b'old-copy!').hexdigest())
        fs.contents[path] = b'new-copy!'
        after = fs.observe(count_hash=False)
        self.assertNotEqual(before['entries'], after['entries'])
        self.assertTrue(all(flags & os.O_NOFOLLOW for flags in fs.open_flags))
        self.assertTrue(all(not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
                            for flags in fs.open_flags))
        self.assertTrue(all(call.kwargs == {'buffering': 0} for call in fs.fdopen_mock.call_args_list))

    def test_init_namespace_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'private mount namespace'):
            FakeFilesystem([]).observe(same_namespace=True)

    def test_nonreadonly_view_rejected(self):
        fs = FakeFilesystem([])
        fs.mountinfo = fs.mountinfo.replace(' ro,nosuid ', ' rw,nosuid ')
        with self.assertRaisesRegex(RuntimeError, 'read-only, nonrecursive'):
            fs.observe()

    def test_submount_rejected(self):
        fs = FakeFilesystem([])
        fs.mountinfo += f'51 50 8:6 / {VIEW}/srv rw - ext4 /dev/sdb1 rw\n'
        with self.assertRaisesRegex(RuntimeError, 'includes submounts'):
            fs.observe()

    def test_cross_device_file_rejected(self):
        fs = FakeFilesystem([0])
        fs.entries[fs.children[VIEW + '/' + SCOPE][0]].st_dev = 6
        with self.assertRaisesRegex(RuntimeError, 'unexpected filesystem'):
            fs.observe()


class InventoryChecks(unittest.TestCase):
    def test_inventory_uses_only_fixed_readonly_commands_and_product_metadata(self):
        text_files = {
            '/etc/fls/storage.json': json.dumps({'schema': 2, 'mode': 'hybrid'}),
            '/etc/fls/release-state.json': json.dumps({'edition': 'community', 'version': 'fixture-only'}),
            '/var/www/fls/VERSION': 'fixture-only\n',
        }
        byte_files = {'/sys/class/dmi/id/product_uuid': b'synthetic-dmi\n',
                      '/etc/fortigate/rsyslog.conf': b'synthetic-config',
                      '/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd': b'synthetic-binary'}
        class InventoryPath:
            def __init__(self, value): self.value = str(value)
            def read_text(self): return text_files[self.value]
            def read_bytes(self): return byte_files[self.value]
            def lstat(self): return metadata(mode=stat.S_IFDIR | 0o755)
            def exists(self):
                if self.value not in ('/var/lib/fls-maintenance/paused', '/var/lib/fls-disks/migration-paused'):
                    raise AssertionError('Unexpected metadata path')
                return False
        calls = []
        def readonly_run(arguments):
            calls.append(arguments)
            return {'argv': arguments, 'rc': 0, 'stdout': 'fixture-depot.mount\n', 'stderr': ''}
        with patch.object(helper, 'Path', InventoryPath), patch.object(helper, 'run', side_effect=readonly_run), \
             patch.object(helper.subprocess, 'run', side_effect=AssertionError('real subprocess')):
            report = helper.inventory()
        self.assertFalse(report['vm_mutations_performed'])
        self.assertEqual(report['kind'], 'read_only_inventory')
        self.assertEqual(report['collector_binary_sha256'], hashlib.sha256(b'synthetic-binary').hexdigest())
        self.assertEqual(report['dmi_product_uuid_sha256_file12'], hashlib.sha256(b'synthetic-dmi\n').hexdigest()[:12])
        self.assertEqual(calls, [
            ['systemd-escape', '--path', '--suffix=mount', '/srv/fls-storage'],
            ['hostnamectl', '--static'], ['ip', '-brief', '-4', 'address', 'show'],
            ['lsblk', '--bytes', '--json', '--output', 'PATH,NAME,PKNAME,TYPE,SIZE,FSTYPE,UUID,WWN,SERIAL,MODEL,RO,MOUNTPOINTS'],
            ['findmnt', '--json', '--target', '/', '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS'],
            ['findmnt', '--json', '--mountpoint', '/srv/fls-storage', '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS'],
            ['systemctl', 'show', 'fortigate-collector.service', 'fortigate-health.service', 'fls-indexer.service',
             'fls-archive-indexer.service', 'mariadb.service', 'nginx.service', 'php8.3-fpm.service', 'fixture-depot.mount',
             '--property=Id,LoadState,ActiveState,SubState,MainPID,Result,FragmentPath,DropInPaths,BindsTo,Requires,After,RequiresMountsFor,ConditionResult,TimeoutStopUSec,SendSIGKILL,ProtectSystem,ReadWritePaths', '--no-pager'],
            ['systemctl', 'list-units', '--all', '--no-legend', '--plain', '--no-pager', 'fls-*', 'fortigate-*'],
            ['systemctl', 'list-unit-files', '--no-legend', '--no-pager', 'fls-*', 'fortigate-*'],
            ['systemctl', '--failed', '--no-pager'],
            ['ss', '-H', '-ltnp', 'sport = :5514'],
            ['runuser', '-u', 'syslog', '-g', 'adm', '--', 'python3', '-B', '/var/www/fls/bin/fls_storage.py'],
        ])

    def test_command_capture_is_bounded_and_reports_unavailability(self):
        result = SimpleNamespace(returncode=0, stdout='fixed-readonly-result', stderr='')
        with patch.object(helper.subprocess, 'run', return_value=result) as run:
            self.assertEqual(helper.run(['systemctl', 'show'])['rc'], 0)
            self.assertEqual(run.call_args.kwargs, dict(stdin=helper.subprocess.DEVNULL, capture_output=True,
                                                       text=True, timeout=30, check=False))
        result.stdout = 'x' * (1024 * 1024 + 1)
        with patch.object(helper.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'output limit'): helper.run(['systemctl', 'show'])
        with patch.object(helper.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(helper.run(['systemctl', 'show'])['unavailable'], 'FileNotFoundError')

    def test_noargs_help_and_nonroot_do_not_observe_the_host(self):
        for arguments, expected in (([], 2), (['--help'], 0), (['inventory'], 'Run as root')):
            with self.subTest(arguments=arguments), patch.object(sys, 'argv', ['storage-proof', *arguments]), \
                 patch.object(helper.os, 'geteuid', return_value=1000), patch.object(helper, 'inventory') as inventory, \
                 patch.object(helper, 'underlay') as underlay, patch.object(helper, 'run') as run, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as status: helper.main()
                if type(expected) is int: self.assertEqual(status.exception.code, expected)
                else: self.assertIn(expected, str(status.exception))
                inventory.assert_not_called(); underlay.assert_not_called(); run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
