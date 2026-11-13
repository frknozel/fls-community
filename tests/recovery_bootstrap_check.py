#!/usr/bin/python3
"""Synthetic recovery bootstrap tests. Never inspect/restore the real host.

Only private temporary files, a fake engine and (where permitted) local TLS
sockets are used. No service, package, SQL or production backup is accessed.
"""
import copy
from email.message import Message
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fls_bootstrap_fixture', ROOT / 'bin/recovery-bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
DATA = b'only-synthetic-backup-bytes'
KEY = 'AGE-SECRET-KEY-1FIXTURE-ONLY-NEVER-AN-ACTUAL-KEY\n'
RUN_HTTPS = '--https' in sys.argv
if RUN_HTTPS:sys.argv.remove('--https')


def plan():
    return {'schema': 'fls-recovery-plan-v1', 'mode': 'single-disk-rehearsal',
            'source_machine_sha256': 'a' * 64,
            'backup': {'filename': 'fls-system-20261113-120000Z.tar.gz', 'bytes': len(DATA),
                       'sha256': hashlib.sha256(DATA).hexdigest()},
            'encrypted_copies': [], 'runtime': {'bytes': 1, 'sha256': 'c' * 64}}


def target():
    return {'eligible': True, 'reasons': [], 'machine_sha256': 'b' * 64,
            'boot_id': '22222222-2222-4222-8222-222222222222',
            'os_id': 'ubuntu', 'os_version': '24.04', 'architecture': 'x86_64',
            'root_uuid': '11111111-1111-4111-8111-111111111111',
            'root_wwn': '0x5000000000000001',
            'root_identity': {'kind':'wwn','value':'0x5000000000000001'},
            'root_identity_sha256': hashlib.sha256(json.dumps({'kind':'wwn','value':'0x5000000000000001'},sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'root_device': '/dev/sda1',
            'root_major_minor': '8:1', 'free_bytes': 20 * 1024 ** 3,
            'hostname': 'fixture-only', 'addresses': ['127.0.0.1']}


class Engine:
    def __init__(self):
        self.target, self.inspections, self.restores, self.fail = target(), 0, 0, False
        self.identity_probes, self.target_probes = 0, 0

    def inspect_identity(self):
        self.identity_probes += 1
        return {key: copy.deepcopy(self.target[key]) for key in bootstrap.IDENTITY}

    def inspect_target(self):
        self.target_probes += 1
        return copy.deepcopy(self.target)

    def inspect_backup(self, path, sha, work):
        self.inspections += 1
        assert path.read_bytes() == DATA
        return {'schema': 'fls-recovery-inspection-v1', 'verified': True, 'version': '0.fixture',
                'table_count': 80, 'configuration_table_count': 20, 'sha256': sha,
                'payload_directory': str(work / 'private-DO-NOT-EXPOSE'),
                'filename': plan()['backup']['filename'], 'bytes': len(DATA)}

    def restore(self, archive, pinned, work, runtime, guard, progress):
        self.restores += 1
        assert (work.parent / 'apply.json').is_file(), 'journal must precede mutation'
        for phase in ('target_check', 'packages', 'database', 'web', 'complete'):
            guard(phase)
            progress(phase)
        if self.fail:
            raise bootstrap.BootstrapError('synthetic_restore_failure')
        self.target['eligible'] = False  # normal installed files do not revoke identity
        return {'ok': True, 'web_url': 'https://127.0.0.1:8443/'}


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-bootstrap-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.engine, self.time = Engine(), [10000.0]
        self.app = bootstrap.RecoveryApplication(self.engine, plan(), target(), self.root / 'state',
            owner_uid=os.geteuid(), clock=lambda: self.time[0],
            process_info=lambda: {'pid': 123, 'process_start': '456'}, spawn=lambda action: action())
        self.app.initialize()

    def upload(self):
        self.app.upload(plan()['backup']['filename'], len(DATA), io.BytesIO(DATA))

    def ready(self):
        self.upload()
        self.app.validate()
        self.assertEqual(self.app.status, 'validated')

    def test_plan_only_permits_pinned_rehearsal_artifacts(self):
        self.assertEqual(bootstrap.validate_plan(plan()), plan())
        for field, value in [('mode', 'production'), ('source_machine_sha256', 'bad'),
                             ('runtime', None), ('backup', {'filename': '../unsafe'})]:
            bad = plan(); bad[field] = value
            with self.subTest(field=field), self.assertRaises((bootstrap.BootstrapError, TypeError)):
                bootstrap.validate_plan(bad)
        bad = plan(); bad['runtime']['filename'] = 'other.tar.gz'
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'plan_runtime_name_invalid'):
            bootstrap.validate_plan(bad)

    def test_source_machine_and_used_hosts_refused_before_any_mutation(self):
        with patch.object(bootstrap, 'RecoveryApplication', side_effect=AssertionError('host write forbidden')), \
             patch.object(bootstrap.subprocess, 'run', side_effect=AssertionError('command forbidden')):
            self.engine.target['machine_sha256'] = plan()['source_machine_sha256']
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'source_machine_rejected'):
                bootstrap.target_preflight(self.engine, plan())
            self.engine.target = target(); self.engine.target['eligible'] = False
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'empty_ubuntu_target_required'):
                bootstrap.target_preflight(self.engine, plan())

    def test_prepare_source_rejection_precedes_state_copy_certificate_or_install(self):
        kit = self.root / 'kit'; (kit / 'bin').mkdir(parents=True)
        (kit / 'plan.json').write_text(json.dumps(plan()))
        for name in ('fls_recovery_engine.py', *bootstrap.HELPERS):
            (kit / 'bin' / name).write_text('# fixture only')
        self.engine.target['machine_sha256'] = plan()['source_machine_sha256']
        with patch.object(bootstrap.os, 'geteuid', return_value=0), \
             patch.object(bootstrap, 'load_engine', return_value=self.engine), \
             patch.object(bootstrap, 'private_write', side_effect=AssertionError('host write forbidden')), \
             patch.object(bootstrap, 'copy_runtime', side_effect=AssertionError('copy forbidden')):
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'source_machine_rejected'):
                bootstrap.prepare(kit, self.root / 'never-created')
        self.assertFalse((self.root / 'never-created').exists())

    def test_full_prepare_copies_pinned_runtime_and_code_into_private_state(self):
        kit = self.root / 'kit'; (kit / 'bin').mkdir(parents=True)
        runtime = kit / 'runtime.tar.gz'
        with tarfile.open(runtime, 'w:gz') as output:
            for name, content in [('runtime/guest-debs/Packages', b'fixture-index'),
                    ('runtime/guest-debs/fixture.deb', b'fixture-deb'),
                    ('runtime/tools/age', b'fixture-tool'), ('runtime/manifest.json', b'{}')]:
                item = tarfile.TarInfo(name); item.size = len(content)
                output.addfile(item, io.BytesIO(content))
        pinned = plan(); pinned['runtime'] = {'bytes': runtime.stat().st_size,
                                              'sha256': hashlib.sha256(runtime.read_bytes()).hexdigest()}
        (kit / 'plan.json').write_text(json.dumps(pinned))
        for name in ('fls_recovery_engine.py', *bootstrap.HELPERS):
            (kit / 'bin' / name).write_text('# pinned-fixture-' + name)
        factory = bootstrap.RecoveryApplication
        owner = os.geteuid()
        with patch.object(bootstrap.os, 'geteuid', return_value=0), \
             patch.object(bootstrap.os, 'umask'), patch.object(bootstrap.resource, 'setrlimit') as limits, \
             patch.object(bootstrap, 'load_engine', return_value=self.engine), \
             patch.object(bootstrap, 'RecoveryApplication', side_effect=lambda *a, **kw: factory(*a, owner_uid=owner, **kw)):
            app = bootstrap.prepare(kit, self.root / 'prepared')
        limits.assert_called_once_with(bootstrap.resource.RLIMIT_CORE, (0, 0))
        self.assertEqual(app.runtime, self.root / 'prepared/runtime')
        self.assertEqual((app.runtime / 'tools/age').stat().st_mode & 0o777, 0o700)
        for name in bootstrap.HELPERS:
            self.assertEqual((app.runtime / 'bin' / name).read_bytes(), (kit / 'bin' / name).read_bytes())
            self.assertEqual((app.runtime / 'bin' / name).stat().st_mode & 0o777, 0o600)
        (kit / 'bin/system-backup.py').write_text('changed-after-private-snapshot')
        self.assertNotEqual((app.runtime / 'bin/system-backup.py').read_bytes(), (kit / 'bin/system-backup.py').read_bytes())

    def test_lease_expires_and_target_boot_root_or_machine_changes_fail_closed(self):
        for key in bootstrap.IDENTITY:
            old = self.engine.target[key]
            self.engine.target[key] = 'changed'
            with self.subTest(key=key), self.assertRaisesRegex(bootstrap.BootstrapError, 'target_identity_changed'):
                self.app.guard('phase')
            self.engine.target[key] = old
        self.time[0] += bootstrap.LIFETIME + 1
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'recovery_session_expired'):
            self.app.guard('phase')

    def test_http_polling_and_phase_guards_never_run_full_readiness_inventory(self):
        token = self.app.authenticate(self.app.code, '192.0.2.1')
        headers = {'Cookie': 'fls_recovery=' + token}
        # Once files/databases exist during restore, readiness is expected to
        # be false. HTTP polling still validates all nine immutable fields.
        self.engine.target['eligible'] = False
        before = self.engine.identity_probes
        with patch.object(self.engine, 'inspect_target', side_effect=AssertionError('full inventory forbidden')):
            for _ in range(5):
                self.assertEqual(self.http('/api/status', headers=headers)[0], 200)
            for phase in ('upload_complete', 'backup_validation', 'packages', 'database', 'web', 'complete'):
                self.app.guard(phase)
        self.assertEqual(self.engine.target_probes, 0)
        self.assertGreaterEqual(self.engine.identity_probes - before, 11)

    def test_lightweight_guard_preserves_source_rejection_marker_and_process_lease(self):
        self.app.plan['source_machine_sha256'] = self.engine.target['machine_sha256']
        with patch.object(self.engine, 'inspect_target', side_effect=AssertionError('full inventory forbidden')):
            with self.assertRaisesRegex(bootstrap.BootstrapError, '^source_machine_rejected$'):
                self.app.guard('http')
        self.app.plan['source_machine_sha256'] = plan()['source_machine_sha256']
        with patch.object(self.app, 'process_info', return_value={'pid': 999, 'process_start': 'changed'}), \
             patch.object(self.engine, 'inspect_identity', side_effect=AssertionError('identity forbidden after bad lease')):
            with self.assertRaisesRegex(bootstrap.BootstrapError, '^recovery_marker_changed$'):
                self.app.guard('packages')

    def test_apply_rechecks_full_freshness_and_rejects_new_foreign_state_before_journal(self):
        self.ready()
        self.engine.target['eligible'] = False
        with self.assertRaisesRegex(bootstrap.BootstrapError, '^target_no_longer_empty$'):
            self.app.apply(str(uuid.uuid4()), 'TAMAM')
        self.assertEqual(self.engine.target_probes, 1)
        self.assertEqual(self.engine.restores, 0)
        self.assertIsNone(self.app.job_id)
        self.assertFalse((self.app.state / 'apply.json').exists())

    def test_apply_recompares_every_identity_field_after_full_readiness_probe(self):
        self.ready()
        for key in bootstrap.IDENTITY:
            fresh = copy.deepcopy(self.engine.target); fresh[key] = 'changed-after-identity-read'
            with self.subTest(key=key), patch.object(self.engine, 'inspect_target', return_value=fresh):
                with self.assertRaisesRegex(bootstrap.BootstrapError, '^target_identity_changed$'):
                    self.app.apply(str(uuid.uuid4()), 'TAMAM')
            self.assertIsNone(self.app.job_id)
        self.assertEqual(self.engine.restores, 0)
        self.assertFalse((self.app.state / 'apply.json').exists())

    def test_recorded_apply_status_does_not_restart_readiness_or_restore(self):
        self.ready(); request_id = str(uuid.uuid4())
        self.assertEqual(self.app.apply(request_id, 'TAMAM')['state'], 'succeeded')
        self.assertEqual(self.engine.target_probes, 1)
        with patch.object(self.engine, 'inspect_target', side_effect=AssertionError('duplicate full inventory forbidden')):
            self.assertEqual(self.app.apply(request_id, 'TAMAM')['state'], 'succeeded')
        self.assertEqual(self.engine.restores, 1)

    def test_marker_permissions_ownership_contents_and_existing_state_cannot_reset(self):
        marker = self.app.state / 'marker.json'
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.app.state.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'recovery_state_exists'):
            self.app.initialize()
        marker.chmod(0o640)
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'recovery_marker_changed'):
            self.app.guard('phase')
        marker.chmod(0o600); marker.write_text('{}')
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'recovery_marker_changed'):
            self.app.guard('phase')

    def test_one_use_code_cookie_hmac_expiry_and_login_rate_limit(self):
        code, csrf = self.app.code, self.app.csrf
        token = self.app.authenticate(code, '192.0.2.1')
        self.assertTrue(self.app.authenticated(token))
        self.assertNotEqual(self.app.csrf, csrf)
        self.assertFalse(self.app.authenticated(token[:-1] + ('0' if token[-1] != '0' else '1')))
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'bootstrap_code_invalid'):
            self.app.authenticate(code, '192.0.2.1')
        self.time[0] += bootstrap.LIFETIME + 1
        self.assertFalse(self.app.authenticated(token))

    def test_eight_bad_login_codes_rate_limit_without_using_real_code(self):
        for _ in range(8):
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'bootstrap_code_invalid'):
                self.app.authenticate('bad', '192.0.2.2')
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'login_rate_limited'):
            self.app.authenticate(self.app.code, '192.0.2.2')
        self.time[0] += 901
        self.assertTrue(self.app.authenticate(self.app.code, '192.0.2.2'))

    def test_upload_descriptor_size_short_stream_and_hash_are_exact(self):
        for filename, size, data, error in [('../unsafe', len(DATA), DATA, 'descriptor'),
                (plan()['backup']['filename'], len(DATA) + 1, DATA, 'descriptor'),
                (plan()['backup']['filename'], len(DATA), b'short', 'incomplete'),
                (plan()['backup']['filename'], len(DATA), b'x' * len(DATA), 'hash_mismatch')]:
            with self.subTest(error=error), self.assertRaisesRegex(bootstrap.BootstrapError, error):
                self.app.upload(filename, size, io.BytesIO(data))
            self.assertFalse(self.app.busy)
            self.assertIsNone(self.app.artifact)
        self.upload()
        self.assertEqual(self.app.artifact.read_bytes(), DATA)
        self.assertEqual(self.app.artifact.stat().st_mode & 0o777, 0o600)

    def test_insufficient_space_does_not_latch_busy_or_prevent_corrected_upload(self):
        with patch.object(bootstrap.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=1)):
            with self.assertRaisesRegex(bootstrap.BootstrapError, 'upload_space_insufficient'):
                self.upload()
        self.assertFalse(self.app.busy)
        self.upload()
        self.assertEqual(self.app.status, 'uploaded')

    def test_preview_redacts_private_paths_and_repeated_validation_is_idempotent(self):
        self.ready(); self.app.validate()
        self.assertEqual(self.engine.inspections, 1)
        public = json.dumps(self.app.snapshot())
        self.assertNotIn('private-DO-NOT-EXPOSE', public)
        self.assertNotIn('payload_directory', public)

    def test_apply_requires_validated_backup_and_typed_confirmation(self):
        request_id = str(uuid.uuid4())
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'confirmation_required'):
            self.app.apply(request_id, 'yes')
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'validated_backup_required'):
            self.app.apply(request_id, 'TAMAM')
        self.assertEqual(self.engine.restores, 0)

    def test_durable_singleflight_idempotency_and_no_resume_after_failure(self):
        self.ready(); self.engine.fail = True; request_id = str(uuid.uuid4())
        value = self.app.apply(request_id, 'TAMAM')
        self.assertEqual(value['state'], 'failed')
        self.assertEqual(self.engine.restores, 1)
        self.assertEqual(self.app.apply(request_id, 'TAMAM')['state'], 'failed')
        self.assertEqual(self.engine.restores, 1)
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'another_restore_recorded'):
            self.app.apply(str(uuid.uuid4()), 'TAMAM')
        self.assertEqual((self.app.state / 'apply.json').stat().st_mode & 0o777, 0o600)

    def test_apply_journal_failure_blocks_restore_and_retries(self):
        self.ready(); (self.app.state / 'apply.json').write_text('existing evidence')
        request_id = str(uuid.uuid4())
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'apply_journal_failed'):
            self.app.apply(request_id, 'TAMAM')
        self.assertEqual(self.engine.restores, 0)
        self.assertEqual(self.app.apply(request_id, 'TAMAM')['state'], 'failed')
        self.assertEqual((self.app.state / 'apply.json').read_text(), 'existing evidence')

    def test_worker_start_failure_releases_busy_and_never_replays_recorded_apply(self):
        self.upload()
        def fail(_):raise RuntimeError('synthetic thread-start failure')
        self.app.spawn = fail
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'worker_start_failed'):
            self.app.validate()
        self.assertEqual((self.app.status, self.app.busy), ('uploaded', False))
        self.app.spawn = lambda action: action(); self.app.validate()
        self.app.spawn = fail; request_id = str(uuid.uuid4())
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'worker_start_failed'):
            self.app.apply(request_id, 'TAMAM')
        self.assertEqual((self.app.status, self.app.busy), ('failed', False))
        self.assertEqual(self.app.apply(request_id, 'TAMAM')['state'], 'failed')
        self.assertEqual(self.engine.restores, 0)
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'another_restore_recorded'):
            self.app.apply(str(uuid.uuid4()), 'TAMAM')

    def test_phase_guard_checks_private_durable_journal(self):
        self.ready(); queued = []; self.app.spawn = queued.append
        self.app.apply(str(uuid.uuid4()), 'TAMAM')
        (self.app.state / 'apply.json').write_text('{}')
        queued.pop()()
        self.assertEqual(self.app.status, 'failed')
        self.assertEqual(self.app.error_code, 'apply_journal_changed')

    @unittest.skipUnless(hasattr(os, 'memfd_create'), 'Linux anonymous identity descriptor required')
    def test_identity_uses_memfd_and_never_files_argv_logs_or_public_status(self):
        encrypted = b'fixture-ciphertext'
        item = {**plan()['backup'], 'filename': plan()['backup']['filename'] + '.' + 'd' * 32 + '.age',
                'bytes': len(encrypted), 'sha256': hashlib.sha256(encrypted).hexdigest(),
                'key_id': 'd' * 32, 'recipient': 'age1' + 'q' * 58}
        self.app.plan['encrypted_copies'] = [item]
        self.app.upload(item['filename'], len(encrypted), io.BytesIO(encrypted))
        tool = self.app.runtime / 'tools/age'; tool.parent.mkdir(parents=True)
        tool.write_text('#!/usr/bin/python3\nimport sys,hashlib\nkey=open(sys.argv[sys.argv.index("--identity")+1],"rb").read()\nassert hashlib.sha256(key).hexdigest()=='+repr(hashlib.sha256(KEY.encode()).hexdigest())+'\nsys.stderr.write(key.decode())\nsys.stdout.buffer.write('+repr(DATA)+')\n')
        tool.chmod(0o700)
        self.app.decrypt(KEY)
        self.assertFalse(self.app.encrypted)
        self.assertEqual(self.app.artifact.read_bytes(), DATA)
        self.assertNotIn(KEY, json.dumps(self.app.snapshot()))
        for path in self.app.state.rglob('*'):
            if path.is_file():self.assertNotIn(KEY.encode(), path.read_bytes(), str(path))
        self.assertFalse(any('identity' in path.name for path in self.app.state.rglob('*')))

    def test_identity_bounds_reject_before_process_or_disk_write(self):
        with patch.object(bootstrap.subprocess, 'Popen', side_effect=AssertionError('decrypt forbidden')):
            for key in ['', 'x' * 4097, 'secret\x00invalid', 'ü']:
                with self.assertRaisesRegex(bootstrap.BootstrapError, 'identity_invalid'):
                    self.app.decrypt(key)

    def test_runtime_pins_and_safe_extraction_deny_traversal_links_duplicates_and_expansion(self):
        for kind in ('traversal', 'symlink', 'duplicate', 'oversize'):
            archive = self.root / (kind + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as output:
                member = tarfile.TarInfo('runtime/../../escape' if kind == 'traversal' else 'runtime/file')
                if kind == 'symlink':member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'
                elif kind == 'oversize':member.size = 100
                output.addfile(member, io.BytesIO(b'x' * member.size) if member.isfile() else None)
                if kind == 'duplicate':output.addfile(member)
            with self.subTest(kind=kind), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.extract_runtime(archive, self.root / kind, 10)
        source = self.root / 'runtime-source'; source.write_bytes(b'bad')
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'runtime_hash_mismatch'):
            bootstrap.copy_runtime(source, self.root / 'runtime-copy', {'bytes': 3, 'sha256': '0' * 64})

    def http(self, path, body=None, headers=None):
        handler = bootstrap.RecoveryHandler.__new__(bootstrap.RecoveryHandler)
        handler.server = types.SimpleNamespace(application=self.app,
            allowed_hosts={'127.0.0.1'}, server_port=8444)
        handler.path, handler.client_address = path, ('192.0.2.1', 1)
        handler.headers = Message()
        values = {'Host': '127.0.0.1:8444', **(headers or {})}
        if body is not None:
            raw = json.dumps(body).encode() if isinstance(body, dict) else body
            values.setdefault('Content-Type', 'application/json')
            values.setdefault('Content-Length', str(len(raw)))
        else:raw = b''
        for name, value in values.items():handler.headers[name] = value
        handler.rfile = io.BytesIO(raw)
        response = []
        handler.send = lambda status, value, content_type='application/json', cookie=None: response.append((status, value, cookie))
        handler.dispatch(body is not None)
        self.assertEqual(len(response), 1)
        return response[0]

    def test_fake_http_enforces_auth_host_origin_csrf_and_body_limits_without_sockets(self):
        self.assertEqual(self.http('/api/status')[0], 401)
        self.assertEqual(self.http('/api/session', headers={'Host': 'evil.invalid:8444'})[0], 403)
        common = {'Origin': 'https://127.0.0.1:8444', 'X-FLS-CSRF': self.app.csrf}
        self.assertEqual(self.http('/api/login', {'code': self.app.code}, {**common, 'Origin': 'https://evil.invalid'})[0], 403)
        self.assertEqual(self.http('/api/login', {'code': self.app.code}, {**common, 'X-FLS-CSRF': 'wrong'})[0], 403)
        status, value, token = self.http('/api/login', {'code': self.app.code}, common)
        self.assertEqual(status, 200)
        headers = {'Cookie': 'fls_recovery=' + token, 'Origin': common['Origin'], 'X-FLS-CSRF': value['csrf']}
        self.assertEqual(self.http('/api/validate', b'x' * 9000, headers)[0], 413)
        self.assertEqual(self.http('/api/validate', {}, {**headers, 'Transfer-Encoding': 'chunked'})[0], 411)
        self.assertEqual(self.http('/api/status', headers=headers)[0], 200)

    def test_fake_http_normal_flow_and_duplicate_apply_are_stable_without_sockets(self):
        common = {'Origin': 'https://127.0.0.1:8444', 'X-FLS-CSRF': self.app.csrf}
        status, value, token = self.http('/api/login', {'code': self.app.code}, common)
        headers = {'Cookie': 'fls_recovery=' + token, 'Origin': common['Origin'], 'X-FLS-CSRF': value['csrf']}
        self.assertEqual(self.http('/api/upload', DATA, {**headers,
            'Content-Type': 'application/octet-stream', 'X-FLS-Filename': self.app.plan['backup']['filename']})[0], 202)
        self.assertEqual(self.http('/api/validate', {}, headers)[0], 202)
        request = {'request_id': str(uuid.uuid4()), 'confirmation': 'TAMAM'}
        self.assertEqual(self.http('/api/apply', request, headers)[0], 202)
        self.assertEqual(self.http('/api/apply', request, headers)[0], 202)
        self.assertEqual(self.http('/api/status', headers=headers)[1]['state'], 'succeeded')
        self.assertEqual(self.engine.restores, 1)


@unittest.skipUnless(RUN_HTTPS, 'Opt-in --https; portable CI forbids all sockets')
class HTTPSFixtures(BootstrapTests):
    """Only loopback TLS and the same synthetic engine. No host recovery calls."""
    def setUp(self):
        super().setUp()
        if not shutil.which('openssl'):self.skipTest('openssl required for local TLS fixture')
        bootstrap.certificate(self.app.work, self.app.target)
        try:self.server = bootstrap.RecoveryServer(('127.0.0.1', 0), self.app, {'127.0.0.1'})
        except PermissionError:self.skipTest('loopback sockets are not permitted in this sandbox')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.app.work / 'cert.pem', self.app.work / 'key.pem')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True, do_handshake_on_connect=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.stop_server)
        self.host = '127.0.0.1:' + str(self.server.server_port)
        self.context = ssl.create_default_context(cafile=str(self.app.work / 'cert.pem'))

    def stop_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)

    def request(self, path, body=None, headers=None, method=None):
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
                                               context=self.context, timeout=3)
        values = {'Host': self.host, **(headers or {})}
        if body is not None:
            body = json.dumps(body).encode() if isinstance(body, dict) else body
            values.setdefault('Content-Type', 'application/json')
        connection.request(method or ('GET' if body is None else 'POST'), path, body=body, headers=values)
        response = connection.getresponse(); data = response.read()
        result = response.status, dict(response.getheaders()), json.loads(data) if data.startswith(b'{') else data
        connection.close(); return result

    def login(self):
        status, _, value = self.request('/api/session')
        self.assertEqual(status, 200)
        status, headers, value = self.request('/api/login', {'code': self.app.code},
            {'Origin': 'https://' + self.host, 'X-FLS-CSRF': value['csrf']})
        self.assertEqual(status, 200)
        self.assertIn('; Secure; HttpOnly; SameSite=Strict;', headers['Set-Cookie'])
        return {'Cookie': headers['Set-Cookie'].split(';')[0], 'Origin': 'https://' + self.host,
                'X-FLS-CSRF': value['csrf']}

    # Do not repeat inherited core tests using an unnecessary live socket.
    def test_https_host_origin_csrf_authentication_and_body_bounds(self):
        self.assertEqual(self.request('/api/status')[0], 401)
        self.assertEqual(self.request('/api/session', headers={'Host': 'evil.invalid:' + str(self.server.server_port)})[0], 403)
        self.assertEqual(self.request('/api/login', {'code': self.app.code}, {'Origin': 'https://evil.invalid', 'X-FLS-CSRF': self.app.csrf})[0], 403)
        headers = self.login()
        self.assertEqual(self.request('/api/validate', {}, {**headers, 'X-FLS-CSRF': 'wrong'})[0], 403)
        self.assertEqual(self.request('/api/validate', b'x' * 9000, headers)[0], 413)
        self.assertEqual(self.request('/api/status', headers=headers)[0], 200)

    def test_https_upload_validation_and_ambiguous_duplicate_apply_never_restarts(self):
        headers = self.login()
        upload = {**headers, 'Content-Type': 'application/octet-stream',
                  'X-FLS-Filename': self.app.plan['backup']['filename']}
        self.assertEqual(self.request('/api/upload', DATA, upload)[0], 202)
        self.assertEqual(self.request('/api/validate', {}, headers)[0], 202)
        request = {'request_id': str(uuid.uuid4()), 'confirmation': 'TAMAM'}
        self.assertEqual(self.request('/api/apply', request, headers)[0], 202)
        self.assertEqual(self.request('/api/apply', request, headers)[0], 202)
        self.assertEqual(self.request('/api/status', headers=headers)[2]['state'], 'succeeded')
        self.assertEqual(self.engine.restores, 1)

    def test_slow_tls_peer_does_not_block_other_https_clients(self):
        stalled = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        try:
            started = time.monotonic()
            self.assertEqual(self.request('/api/session')[0], 200)
            self.assertLess(time.monotonic() - started, 2)
        finally:stalled.close()


# Inherit fixture setup/helpers without collecting all the pure tests twice.
for name in list(BootstrapTests.__dict__):
    if name.startswith('test_') and name not in HTTPSFixtures.__dict__:
        setattr(HTTPSFixtures, name, None)


if __name__ == '__main__':
    unittest.main()
