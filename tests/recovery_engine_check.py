#!/usr/bin/python3
"""Recovery trust-boundary regressions. No host restore or service mutation."""
import copy
import contextlib
import errno
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fls_recovery_engine_fixture', ROOT/'bin/fls_recovery_engine.py')
engine = importlib.util.module_from_spec(spec); spec.loader.exec_module(engine)


def sha(value): return hashlib.sha256(value).hexdigest()


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, value in entries:
            if isinstance(value, tarfile.TarInfo): archive.addfile(value); continue
            member = tarfile.TarInfo(name); member.size = len(value); member.mode = 0o600
            archive.addfile(member, io.BytesIO(value))
    return output.getvalue()


def link(name, target, hard=False):
    item = tarfile.TarInfo(name); item.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
    item.linkname = target; return item


def fixture(folder, *, inner_extra=(), outer_extra=(), mutate_manifest=None, inner_override=None):
    files = {name: b'fixture' for name in engine.REQUIRED_SYSTEM}
    files['var/www/fls/VERSION'] = b'0.75.0\n'
    files['var/www/fls/public/index.php'] = b'<?php /* fixture, never executed */'
    files['etc/php/8.3/mods-available/test.ini'] = b'; fixture\n'
    inner = list(files.items()) + list(inner_extra)
    if inner_override is not None: inner = inner_override
    mapping = {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in inner if isinstance(data, bytes)}
    payload = {'system.tar': tar_bytes(inner), 'database.sql.gz': gzip.compress(b'-- fixture SQL; never executed\n'),
               'database-accounts.sql': b'-- fixture only\n', 'restore-safe.sql': b'-- fixture only\n',
               'inventory/file-sha256.json': json.dumps(mapping).encode(),
               'inventory/configuration-digests.json': b'{}',
               'inventory/service-identities.json': b'{"users":[],"groups":[]}'}
    manifest = {'schema': 'fls-system-backup-v1', 'created_at_utc': '2026-11-13T09:00:00+00:00',
                'database_tables': ['users'], 'configuration_tables': list(engine.CONFIG_TABLES),
                'files': {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in payload.items()}}
    if mutate_manifest: mutate_manifest(manifest)
    entries = [('backup/' + name, data) for name, data in payload.items()]
    entries.append(('backup/MANIFEST.json', json.dumps(manifest).encode()))
    entries += list(outer_extra)
    archive = folder/'fls-system-20261113-090000Z.tar.gz'
    archive.write_bytes(gzip.compress(tar_bytes(entries))); archive.chmod(0o600)
    return archive, sha(archive.read_bytes())


class RecoveryEngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-engine-fixture-')
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        self.work = self.root/'work'; self.work.mkdir(mode=0o700)

    def tearDown(self): self.temporary.cleanup()

    def inspect(self, archive, digest): return engine.inspect_backup(archive, digest, self.work)

    @contextlib.contextmanager
    def target_fixture(self):
        root = self.root/'target'; root.mkdir()
        files = {'etc/os-release': 'ID=ubuntu\nVERSION_ID="24.04"\n', 'etc/machine-id': '1'*32+'\n',
                 'proc/sys/kernel/random/boot_id': '11111111-1111-4111-8111-111111111111\n',
                 'proc/self/mountinfo': '29 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n',
                 'sys/dev/block/8:1/partition': '1\n', 'sys/dev/block/device/wwid': 'naa.5000000000000001\n',
                 'dev/sda1': 'fixture block device', 'dev/sda2': 'second fixture device'}
        for name, value in files.items():
            path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(value)
        (root/'var/lib/fls-recovery').mkdir(parents=True)
        (root/'dev/disk/by-uuid').mkdir(parents=True)
        (root/'dev/disk/by-uuid/11111111-2222-4333-8444-555555555555').symlink_to('../../sda1')
        real_path = engine.Path
        real_stat = os.stat
        def path(value):
            value = real_path(value)
            return root/str(value).lstrip('/') if value.is_absolute() else value
        def capture(args, **kwargs):
            if args[0] == '/usr/bin/systemctl': return 'fls-recovery-bootstrap.service enabled\n'
            if args[0] == '/usr/sbin/ip': return '[]'
            raise AssertionError('unexpected host command')
        def device_stat(value, *args, **kwargs):
            value = real_path(value)
            if kwargs.get('follow_symlinks') is False: return real_stat(value, *args, **kwargs)
            resolved = real_path(os.path.realpath(value, strict=True)) if str(value).startswith(str(root/'dev')) else value
            if resolved in [root/'dev/sda1', root/'dev/sda2']:
                return types.SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(8, 1 if resolved.name == 'sda1' else 2))
            return real_stat(value, *args, **kwargs)
        with patch.object(engine, 'Path', side_effect=path), patch.object(engine, '_capture', side_effect=capture), \
             patch.object(engine.os, 'stat', side_effect=device_stat), \
             patch.object(engine.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64')), \
             patch.object(engine.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=16*1024**3,f_frsize=1)):
            yield root

    def test_target_allows_only_own_bootstrap_state_and_plain_fresh_root(self):
        with self.target_fixture() as root:
            report = engine.inspect_target()
            self.assertTrue(report['eligible'], report['reasons'])
            self.assertEqual(report['root_wwn'], '0x5000000000000001')
            self.assertEqual(report['root_uuid'], '11111111-2222-4333-8444-555555555555')
            (root/'var/lib/fls-license').mkdir()
            self.assertIn('existing_fls_state', engine.inspect_target()['reasons'])

    def test_target_rejects_stopped_existing_databases_without_connecting_to_them(self):
        with self.target_fixture() as root:
            directory = root/'var/lib/mysql'; directory.mkdir(); (directory/'ibdata1').write_bytes(b'existing')
            report = engine.inspect_target()
            self.assertFalse(report['eligible'])
            self.assertIn('existing_database_directory', report['reasons'])
            self.assertNotIn('target_inspection_failed', report['reasons'])

    def test_target_rejects_existing_app_even_when_no_service_runs(self):
        with self.target_fixture() as root:
            (root/'etc/fls').mkdir()
            self.assertIn('existing_fls_installation', engine.inspect_target()['reasons'])

    def test_identity_is_process_free_and_detects_uuid_wwn_device_reboot_and_machine_changes(self):
        with self.target_fixture() as root, patch.object(engine, '_capture', side_effect=AssertionError('identity must not fork')):
            before = engine.inspect_identity()
            (root/'sys/dev/block/device/wwid').write_text('naa.5000000000000002\n')
            self.assertNotEqual(before['root_wwn'], engine.inspect_identity()['root_wwn'])
            (root/'proc/sys/kernel/random/boot_id').write_text('22222222-1111-4111-8111-111111111111\n')
            self.assertNotEqual(before['boot_id'], engine.inspect_identity()['boot_id'])
            (root/'etc/machine-id').write_text('2'*32+'\n')
            self.assertNotEqual(before['machine_sha256'], engine.inspect_identity()['machine_sha256'])
            alias = root/'dev/disk/by-uuid/11111111-2222-4333-8444-555555555555'
            alias.rename(alias.with_name('22222222-2222-4333-8444-555555555555'))
            alias = alias.with_name('22222222-2222-4333-8444-555555555555')
            self.assertNotEqual(before['root_uuid'], engine.inspect_identity()['root_uuid'])
            (root/'sys/dev/block/8:2').mkdir(); (root/'sys/dev/block/8:2/partition').write_text('2')
            (root/'proc/self/mountinfo').write_text('29 1 8:2 / / rw - ext4 /dev/sda2 rw\n')
            alias.unlink(); alias.symlink_to('../../sda2')
            after = engine.inspect_identity()
            self.assertNotEqual(before['root_device'], after['root_device'])
            self.assertNotEqual(before['root_major_minor'], after['root_major_minor'])

    def test_identity_rejects_overlay_bind_ambiguous_uuid_and_kernel_device_mismatch(self):
        with self.target_fixture() as root:
            path = root/'proc/self/mountinfo'; original = path.read_text()
            for changed in [original.replace('ext4','overlay'), original.replace('8:1 / /','8:1 /subdir /'),
                            original + original, original.replace('8:1','8:2')]:
                path.write_text(changed)
                with self.subTest(mount=changed), self.assertRaises(Exception): engine.inspect_identity()
            path.write_text(original)
            extra = root/'dev/disk/by-uuid/22222222-2222-4333-8444-555555555555'; extra.symlink_to('../../sda1')
            with self.assertRaisesRegex(engine.RecoveryError,'root_uuid_ambiguous'): engine.inspect_identity()
            extra.unlink()
            (root/'sys/dev/block/device/wwid').write_text('t10.virtual-disk')
            self.assertEqual(engine.inspect_identity()['root_identity'], {'kind':'wwid','value':'t10.virtual-disk'})

    def test_full_target_inspection_keeps_freshness_and_bounded_probe_failure_reason(self):
        with self.target_fixture(), patch.object(engine, '_capture', side_effect=engine.subprocess.TimeoutExpired('fixture',60)) as capture:
            report = engine.inspect_target()
            self.assertFalse(report['eligible']); self.assertEqual(report['reasons'], ['target_units_timeout'])
            self.assertEqual(capture.call_args.kwargs['timeout'],60)

    def test_valid_backup_is_verified_in_private_staging_without_loading_uploaded_python(self):
        archive, digest = fixture(self.root, inner_extra=[('var/www/fls/bin/system-backup.py', b'raise AssertionError("uploaded code executed")')])
        with patch.object(engine.importlib.util, 'spec_from_file_location', side_effect=AssertionError('uploaded import forbidden')), \
             patch.object(engine.subprocess, 'run', side_effect=AssertionError('host command forbidden')):
            report = self.inspect(archive, digest)
        self.assertTrue(report['verified']); self.assertEqual(report['version'], '0.75.0')
        self.assertEqual(report['table_count'], 1); self.assertEqual(report['configuration_table_count'], 20)
        self.assertTrue(Path(report['payload_directory']).is_relative_to(self.work))
        self.assertEqual(Path(report['payload_directory']).stat().st_mode & 0o777, 0o700)
        self.assertNotIn('secret', json.dumps(report).lower())

    def test_wrong_hash_rejected_before_staging_or_tar_parsing(self):
        archive, _ = fixture(self.root)
        with patch.object(engine.tarfile, 'open', side_effect=AssertionError('not allowed before hash')):
            with self.assertRaisesRegex(engine.RecoveryError, 'backup_checksum_mismatch'): self.inspect(archive, '0'*64)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_outer_traversal_absolute_and_backslash_paths_fail_without_escape(self):
        for name in ['../outside', '/tmp/outside', 'backup/../../outside', 'backup//x', 'backup\\evil']:
            with self.subTest(name=name):
                archive, digest = fixture(self.root, outer_extra=[(name, b'no')])
                with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)
                self.assertEqual(list(self.work.iterdir()), [])

    def test_outer_links_special_files_duplicates_and_unlisted_files_are_rejected(self):
        fifo = tarfile.TarInfo('backup/fifo'); fifo.type = tarfile.FIFOTYPE
        for extra in [[('backup/escape', link('backup/escape', '/etc/passwd'))], [('backup/fifo', fifo)],
                      [('backup/database.sql.gz', b'duplicate')], [('backup/unlisted', b'hidden')]]:
            with self.subTest(extra=extra[0][0]):
                archive, digest = fixture(self.root, outer_extra=extra)
                with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)

    def test_system_links_all_members_even_uninstalled_paths_must_be_safe(self):
        bad = [link('etc/uninstalled-link', '../../etc/passwd'),
               link('etc/uninstalled-link', '/etc/missing'),
               link('etc/uninstalled-link', '/etc/uninstalled-link'),
               link('etc/hard', 'etc/missing', hard=True)]
        for member in bad:
            with self.subTest(target=member.linkname):
                archive, digest = fixture(self.root, inner_extra=[(member.name, member)])
                with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)

    def test_supported_absolute_php_symlink_and_reference_only_os_links(self):
        archive, digest = fixture(self.root, inner_extra=[
            ('etc/php/8.3/fpm/conf.d/test.ini', link('etc/php/8.3/fpm/conf.d/test.ini', '/etc/php/8.3/mods-available/test.ini')),
            ('etc/localtime', link('etc/localtime', '/usr/share/zoneinfo/Etc/UTC')),
            ('etc/nginx/modules', link('etc/nginx/modules', '/usr/lib/nginx/modules'))])
        self.assertTrue(self.inspect(archive, digest)['verified'])

    def test_literal_systemd_escaped_mount_names_are_valid_posix_reference_files(self):
        archive, digest = fixture(self.root, inner_extra=[
            (r'etc/systemd/system/srv-fls\x2dstorage.mount', b'[Mount]\n'),
            (r'etc/systemd/system/srv-fls\x2dstorage.mount.d/device-bound.conf', b'[Unit]\n'),
            (r'etc/systemd/system/var-lib-fls\x2drecovery\x2ddownload.mount', b'[Mount]\n')])
        self.assertTrue(self.inspect(archive, digest)['verified'])
        for name in [r'etc\fls\evil', r'etc/systemd/system/bad\..\evil.mount',
                     r'etc/systemd/system/evil\x2d.service', r'etc/systemd/system/evil\x2d.mount/../bad']:
            with self.subTest(name=name), self.assertRaises(engine.RecoveryError): engine._name(name)

    def test_parent_symlink_archive_write_and_duplicate_members_are_rejected(self):
        for extra in [
            [('etc/fls/bad', link('etc/fls/bad', '/etc/php/8.3/mods-available/test.ini')), ('etc/fls/bad/child', b'no')],
            [('var/www/fls/VERSION', b'duplicate')]]:
            archive, digest = fixture(self.root, inner_extra=extra)
            with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)

    def test_system_device_fifo_and_privileged_file_are_rejected(self):
        for kind in [tarfile.CHRTYPE, tarfile.FIFOTYPE]:
            item = tarfile.TarInfo('etc/bad'); item.type = kind
            archive, digest = fixture(self.root, inner_extra=[('etc/bad', item)])
            with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)
        item = tarfile.TarInfo('etc/privileged'); item.mode = 0o4755; item.size = 0
        archive, digest = fixture(self.root, inner_extra=[('etc/privileged', item)])
        with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)

    def test_expansion_limit_and_invalid_gzip_footer_are_rejected(self):
        archive, digest = fixture(self.root)
        with patch.object(engine, 'MAX_DECODED', 100):
            with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)
        archive.write_bytes(archive.read_bytes()[:-8]); digest = sha(archive.read_bytes())
        with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)

    def test_manifest_hash_scope_and_required_files_fail_closed(self):
        changes = [lambda value: value['files']['system.tar'].update(sha256='0'*64),
                   lambda value: value.update(configuration_tables=[]),
                   lambda value: value.update(database_tables=['users', 'users']),
                   lambda value: value.update(created_at_utc='not-a-date')]
        for mutate in changes:
            archive, digest = fixture(self.root, mutate_manifest=mutate)
            with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)
        archive, digest = fixture(self.root, inner_override=[('var/www/fls/VERSION', b'0.74.4')])
        with self.assertRaisesRegex(engine.RecoveryError, 'required_system_files_missing'): self.inspect(archive, digest)

    def test_archive_symlink_and_writable_input_are_rejected(self):
        archive, digest = fixture(self.root); alias = self.root/'alias'; alias.symlink_to(archive)
        with self.assertRaises(engine.RecoveryError): self.inspect(alias, digest)
        archive.chmod(0o666)
        with self.assertRaises(engine.RecoveryError): self.inspect(archive, digest)

    def test_stage_guard_runs_before_mutation_and_before_progress(self):
        calls = []
        def guard(phase): calls.append(('guard', phase)); raise engine.RecoveryError('lease_invalid', phase)
        core = engine._Engine(self.work, self.root, {}, guard, lambda phase: calls.append(('progress', phase)), io.StringIO())
        with self.assertRaisesRegex(engine.RecoveryError, 'lease_invalid'): core.stage('database')
        self.assertEqual(calls, [('guard', 'database')])
        with patch.object(engine.subprocess, 'run', side_effect=AssertionError('command must not run')):
            with self.assertRaises(engine.RecoveryError): core.run(['forbidden'])

    def test_restore_blocks_source_host_or_existing_target_before_any_write(self):
        plan = {'schema': 'fls-recovery-plan-v1', 'mode': 'single-disk-rehearsal',
                'source_machine_sha256': 'a'*64, 'backup': {'filename': 'fls-system-20261113-090000Z.tar.gz', 'bytes': 1, 'sha256': 'b'*64}}
        for target, code in [({'eligible': False}, 'target_not_fresh'),
                             ({'eligible': True, 'machine_sha256': 'a'*64}, 'source_host_forbidden')]:
            with patch.object(engine, 'inspect_target', return_value=target), \
                 patch.object(engine, '_root_directory', side_effect=AssertionError('no target write preparation')):
                with self.assertRaisesRegex(engine.RecoveryError, code):
                    engine.restore('/not/opened', plan, self.work, self.root, lambda phase: None, lambda phase: None)

    def test_invalid_plan_and_guard_failure_never_inspect_or_mutate_target(self):
        for plan in [{}, {'schema': 'fls-recovery-plan-v1', 'mode': 'production'}]:
            with patch.object(engine, 'inspect_target', side_effect=AssertionError('invalid plan rejected first')):
                with self.assertRaises(engine.RecoveryError): engine.restore('none', plan, self.work, self.root, lambda phase: None, lambda phase: None)
        plan = {'schema': 'fls-recovery-plan-v1', 'mode': 'single-disk-rehearsal', 'source_machine_sha256': 'a'*64,
                'backup': {'filename': 'fls-system-20261113-090000Z.tar.gz', 'bytes': 1, 'sha256': 'b'*64}}
        def deny(phase): raise engine.RecoveryError('lease_invalid', phase)
        with patch.object(engine, 'inspect_target', side_effect=AssertionError('lease checked first')):
            with self.assertRaisesRegex(engine.RecoveryError, 'lease_invalid'): engine.restore('none', plan, self.work, self.root, deny, lambda phase: None)

    def test_acl_numeric_service_ids_are_remapped_without_changing_permissions(self):
        acl = struct.pack('<I', 2) + struct.pack('<HHI', 1, 7, 0xffffffff) + struct.pack('<HHI', 2, 4, 981) + struct.pack('<HHI', 8, 5, 982)
        written = []
        def get(path, name, **kwargs):
            if name.endswith('default'): raise OSError(errno.ENODATA, 'fixture')
            return acl
        with patch.object(engine.os, 'getxattr', side_effect=get), \
             patch.object(engine.os, 'setxattr', side_effect=lambda path, name, value, **kwargs: written.append(value)):
            engine._remap_acl(self.root/'not-opened', {981: 1901}, {982: 1902})
        self.assertEqual(struct.unpack_from('<HHI', written[0], 12), (2, 4, 1901))
        self.assertEqual(struct.unpack_from('<HHI', written[0], 20), (8, 5, 1902))
        self.assertEqual(written[0][:12], acl[:12])

    def test_policy_rc_preserves_original_inode_mode_and_content_after_package_failure(self):
        policy = self.root/'policy-rc.d'; policy.write_bytes(b'#!/bin/sh\nexit 42\n'); policy.chmod(0o750)
        before = policy.stat(); real_path = engine.Path
        core = engine._Engine(self.work, self.root, {}, lambda phase: None, lambda phase: None, io.StringIO())
        def path(value): return policy if str(value) == '/usr/sbin/policy-rc.d' else real_path(value)
        with patch.object(engine, 'Path', side_effect=path):
            with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                with core.package_policy():
                    self.assertIn(b'exit 101', policy.read_bytes()); raise RuntimeError('fixture failure')
        self.assertEqual(policy.read_bytes(), b'#!/bin/sh\nexit 42\n')
        self.assertEqual(policy.stat().st_ino, before.st_ino); self.assertEqual(policy.stat().st_mode & 0o777, 0o750)
        self.assertFalse((self.work/'original-policy-rc.d').exists())

    def test_package_policy_absent_is_removed_after_success(self):
        policy = self.root/'policy-rc.d'; real_path = engine.Path
        core = engine._Engine(self.work, self.root, {}, lambda phase: None, lambda phase: None, io.StringIO())
        with patch.object(engine, 'Path', side_effect=lambda value: policy if str(value) == '/usr/sbin/policy-rc.d' else real_path(value)):
            with core.package_policy(): self.assertTrue(policy.exists())
        self.assertFalse(policy.exists())

    def test_policy_install_failure_does_not_leave_a_second_link_to_original(self):
        policy = self.root/'policy-rc.d'; policy.write_bytes(b'original'); policy.chmod(0o750)
        real_path = engine.Path
        core = engine._Engine(self.work, self.root, {}, lambda phase: None, lambda phase: None, io.StringIO())
        with patch.object(engine, 'Path', side_effect=lambda value: policy if str(value) == '/usr/sbin/policy-rc.d' else real_path(value)), \
             patch.object(core, 'write', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                with core.package_policy(): self.fail('policy install failed')
        self.assertEqual(policy.read_bytes(), b'original'); self.assertEqual(policy.stat().st_nlink, 1)
        self.assertFalse((self.work/'original-policy-rc.d').exists())

    def test_invalid_or_privileged_identity_late_in_inventory_never_creates_first_group(self):
        core = engine._Engine(self.work, self.root, {}, lambda phase: None, lambda phase: None, io.StringIO())
        core.phase = 'identities'
        base = {'groups':[{'name':'fls-test','gid':980,'members':[]}],
                'users':[{'name':'fls-test','uid':981,'gid':980}]}
        cases = []
        value = copy.deepcopy(base); value['users'][0]['uid'] = 0; cases.append(value)
        value = copy.deepcopy(base); value['groups'].append({'name':'root','gid':0,'members':[]}); cases.append(value)
        value = copy.deepcopy(base); value['users'][0]['name'] = 'ubuntu'; cases.append(value)
        value = copy.deepcopy(base); value['groups'].append(copy.deepcopy(value['groups'][0])); cases.append(value)
        for value in cases:
            with self.subTest(value=value), patch.object(engine, '_json', return_value=value), \
                 patch.object(core, 'run', side_effect=AssertionError('no mutation before full validation')):
                with self.assertRaisesRegex(engine.RecoveryError, 'service_identities_invalid'): core.identities(self.root)

    def test_rehearsal_web_configuration_supplies_browser_mime_types_and_persists_only_web(self):
        target = self.root/'web-target'; target.mkdir()
        for name in ['var/lib', 'var/cache', 'run', 'etc/fls', 'etc/systemd/system']:
            (target/name).mkdir(parents=True, exist_ok=True)
        for name in ['cert.pem', 'key.pem']:
            (self.work/name).write_bytes(b'private fixture'); (self.work/name).chmod(0o600)
        real_path = engine.Path
        def path(value):
            value = real_path(value)
            return target/str(value).lstrip('/') if str(value).startswith(('/var/lib/', '/var/cache/', '/run/php', '/etc/fls/', '/etc/systemd/')) else value
        calls = []
        core = engine._Engine(self.work, self.root, {'addresses':['192.0.2.1']}, lambda phase: None, lambda phase: None, io.StringIO())
        core.phase = 'web'
        with patch.object(engine, 'Path', side_effect=path), patch.object(engine.shutil, 'chown'), \
             patch.object(core, 'run', side_effect=lambda args, **kwargs: calls.append(args)):
            self.assertEqual(core.web(), 'https://192.0.2.1:8443/')
        config = (target/'etc/fls/recovery-web/nginx.conf').read_text()
        self.assertIn('include /etc/nginx/mime.types;', config)
        self.assertIn('default_type application/octet-stream;', config)
        self.assertIn('listen 8443 ssl;', config)
        unit = (target/'etc/systemd/system'/engine.WEB_UNIT).read_text()
        self.assertIn('ConditionPathExists=/var/lib/fls-maintenance/paused', unit)
        self.assertIn(['systemctl','enable','--now','php8.3-fpm.service',engine.WEB_UNIT], calls)
        self.assertNotIn('fortigate-collector', unit)


if __name__ == '__main__': unittest.main()
