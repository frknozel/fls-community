#!/usr/bin/python3
"""Explicit root entry point for a separate, empty Ubuntu recovery rehearsal.

No installation or restore occurs until an authenticated HTTPS user uploads the
pinned backup, reviews its inspection, and confirms TAMAM. Never run on FLS.
"""
import argparse
import base64
import collections
import fcntl
import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import secrets
import selectors
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import types
import urllib.parse
import uuid

STATE = Path('/var/lib/fls-recovery')
LIFETIME = 8 * 3600
RESERVE = 1024 ** 3
MAX_BACKUP = 64 * 1024 ** 3
MAX_RUNTIME = 2 * 1024 ** 3
HELPERS = ('system-backup.py', 'provision-disk-management.py', 'fls_storage.py')
IDENTITY = ('machine_sha256', 'boot_id', 'root_uuid', 'root_identity_sha256',
            'root_device', 'root_major_minor', 'os_id', 'os_version', 'architecture')
SUMMARY = ('schema', 'verified', 'filename', 'bytes', 'sha256', 'version',
           'table_count', 'configuration_table_count', 'created_at_utc',
           'system_file_count', 'decoded_bytes')


class BootstrapError(RuntimeError):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def require(value, code, status=400):
    if not value:
        raise BootstrapError(code, status)


def public_code(error):
    code = getattr(error, 'code', '')
    return code if isinstance(code, str) and re.fullmatch('[a-z0-9_]{1,80}', code) else 'recovery_failed'


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def positive(value, maximum):
    return type(value) is int and 0 < value <= maximum


def descriptor(value, maximum=MAX_BACKUP):
    require(isinstance(value, dict) and isinstance(value.get('filename'), str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{1,180}', value['filename'])
            and positive(value.get('bytes'), maximum)
            and isinstance(value.get('sha256'), str)
            and re.fullmatch('[a-f0-9]{64}', value['sha256']), 'plan_artifact_invalid')
    return {key: value[key] for key in ('filename', 'bytes', 'sha256')}


def validate_plan(value):
    require(isinstance(value, dict) and value.get('schema') == 'fls-recovery-plan-v1'
            and value.get('mode') == 'single-disk-rehearsal'
            and re.fullmatch('[a-f0-9]{64}', value.get('source_machine_sha256', '')),
            'rehearsal_plan_required')
    plain = descriptor(value.get('backup'))
    require(re.fullmatch(r'fls-system-\d{8}-\d{6}Z\.tar\.gz', plain['filename']),
            'plan_backup_name_invalid')
    require(isinstance(value.get('runtime'), dict), 'plan_runtime_invalid')
    runtime = descriptor({'filename': 'runtime.tar.gz', **value['runtime']}, MAX_RUNTIME)
    require(runtime['filename'] == 'runtime.tar.gz', 'plan_runtime_name_invalid')
    copies = value.get('encrypted_copies', [])
    require(isinstance(copies, list) and len(copies) <= 32, 'plan_encrypted_copies_invalid')
    seen = {plain['filename']}
    for copy in copies:
        item = descriptor(copy)
        require(re.fullmatch('[a-f0-9]{32}', copy.get('key_id', ''))
                and re.fullmatch('age1[023456789acdefghjklmnpqrstuvwxyz]{58}', copy.get('recipient', ''))
                and item['filename'] == plain['filename'] + '.' + copy['key_id'] + '.age'
                and item['filename'] not in seen, 'plan_encrypted_copy_invalid')
        seen.add(item['filename'])
    return value


def read_regular(path, maximum, owner=None):
    descriptor_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor_fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= maximum and (owner is None or before.st_uid == owner)
                and before.st_mode & 0o022 == 0, 'kit_file_unsafe')
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(value) <= maximum and (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'kit_file_changed')
        return value


def load_engine(path, content=None):
    content = read_regular(path, 2 * 1024 ** 2) if content is None else content
    module = types.ModuleType('fls_recovery_engine')
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(content, str(path), 'exec'), module.__dict__)
    return module


def target_preflight(engine, plan):
    target = engine.inspect_target()
    require(isinstance(target, dict), 'target_inspection_invalid')
    require(target.get('machine_sha256') != plan['source_machine_sha256'],
            'source_machine_rejected', 403)
    require(target.get('eligible') is True and target.get('os_id') == 'ubuntu'
            and target.get('os_version') == '24.04'
            and target.get('architecture') in ('amd64', 'x86_64'), 'empty_ubuntu_target_required', 403)
    require(all(isinstance(target.get(key), str) and target[key] for key in IDENTITY)
            and re.fullmatch('[a-f0-9]{64}', target['machine_sha256'])
            and isinstance(target.get('root_identity'), dict)
            and re.fullmatch('[a-f0-9]{64}', target['root_identity_sha256'])
            and target['root_identity_sha256'] == hashlib.sha256(json.dumps(
                target['root_identity'], sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
            and str(uuid.UUID(target['root_uuid'])) == target['root_uuid']
            and str(uuid.UUID(target['boot_id'])) == target['boot_id'], 'target_identity_invalid')
    require(type(target.get('free_bytes')) is int
            and target['free_bytes'] > plan['backup']['bytes'] * 3 + plan['runtime']['bytes'] * 4 + RESERVE,
            'target_space_insufficient')
    return target


def private_write(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def process_identity():
    return {'pid': os.getpid(), 'process_start': Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19]}


def extract_runtime(archive, destination, maximum):
    """No links, special files, alternate prefixes or unbounded decompression."""
    total, seen = 0, set()
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            parts = PurePosixPath(member.name).parts
            require(parts and parts[0] == 'runtime' and not member.name.startswith('/')
                    and '..' not in parts and member.name not in seen
                    and (member.isdir() or member.isfile()), 'runtime_archive_unsafe')
            seen.add(member.name)
            total += member.size
            require(len(seen) <= 2048 and total <= maximum, 'runtime_archive_too_large')
            path = destination.joinpath(*parts)
            if member.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with source, os.fdopen(fd, 'wb') as output:
                    remaining = member.size
                    while remaining:
                        block = source.read(min(1024 ** 2, remaining))
                        require(bool(block), 'runtime_archive_short')
                        output.write(block)
                        remaining -= len(block)
    runtime = destination / 'runtime'
    require((runtime / 'guest-debs/Packages').is_file()
            and (runtime / 'tools/age').is_file()
            and (runtime / 'manifest.json').is_file(), 'runtime_files_missing')
    (runtime / 'tools/age').chmod(0o700)
    return runtime


def copy_runtime(source, destination, expected):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_mode & 0o022 == 0 and before.st_size == expected['bytes'],
                'runtime_file_unsafe')
        digest, remaining = hashlib.sha256(), expected['bytes']
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, 'wb') as output:
            while remaining:
                block = stream.read(min(1024 ** 2, remaining))
                require(bool(block), 'runtime_file_short')
                output.write(block)
                digest.update(block)
                remaining -= len(block)
            require(not stream.read(1), 'runtime_file_changed')
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and hmac.compare_digest(digest.hexdigest(), expected['sha256']), 'runtime_hash_mismatch')


class RecoveryApplication:
    def __init__(self, engine, plan, target, state, *, owner_uid=0, clock=time.time,
                 process_info=process_identity, spawn=None, monotonic=time.monotonic):
        self.engine, self.plan, self.target, self.state = engine, plan, target, Path(state)
        self.owner_uid, self.clock, self.process_info = owner_uid, clock, process_info
        self.created = clock()
        self.monotonic, self.started_monotonic = monotonic, monotonic()
        self.lock = threading.RLock()
        self.secret = secrets.token_bytes(32)
        self.code = secrets.token_urlsafe(24)
        self.csrf = secrets.token_urlsafe(32)
        self.session_id = None
        self.failures = collections.deque(maxlen=24)
        self.phase, self.status, self.error_code = 'upload', 'waiting_upload', ''
        self.artifact, self.encrypted, self.preview = None, False, None
        self.busy, self.job_id, self.result, self.upload_bytes = False, None, None, 0
        self.input_attempts, self.validation_attempts = 0, 0
        self.spawn = spawn or self._spawn
        self.runtime = self.state / 'runtime'
        self.work = self.state / 'work'
        self.marker = {'schema': 1, 'nonce': secrets.token_hex(32), 'created_epoch': self.created,
                       **{key: target[key] for key in IDENTITY}, **process_info()}

    def _spawn(self, target):
        threading.Thread(target=target, daemon=True).start()

    def initialize(self):
        # The caller completes target_preflight before this first host write.
        require(not self.state.exists() and not self.state.is_symlink(), 'recovery_state_exists', 403)
        self.state.mkdir(mode=0o700)
        self.state.chmod(0o700)
        self.work.mkdir(mode=0o700)
        private_write(self.state / 'marker.json', json_bytes(self.marker))
        self.guard('bootstrap')

    def guard(self, phase):
        require(self.created - 5 <= self.clock() <= self.created + LIFETIME
                and 0 <= self.monotonic() - self.started_monotonic <= LIFETIME,
                'recovery_session_expired', 410)
        info = self.state.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.owner_uid
                and stat.S_IMODE(info.st_mode) == 0o700 and self.state.resolve() == self.state,
                'recovery_state_unsafe', 403)
        raw = read_regular(self.state / 'marker.json', 8192, self.owner_uid)
        require(stat.S_IMODE((self.state / 'marker.json').lstat().st_mode) == 0o600
                and json.loads(raw) == self.marker and self.process_info() == {
                key: self.marker[key] for key in ('pid', 'process_start')}, 'recovery_marker_changed', 403)
        # Polling and per-phase guards only need the immutable machine/disk
        # identity. Full service/database inventory is deliberately reserved
        # for readiness, avoiding overlapping subprocesses during a restore.
        target = self.engine.inspect_identity()
        require(isinstance(target, dict) and all(target.get(key) == self.target[key] for key in IDENTITY),
                'target_identity_changed', 403)
        require(target.get('machine_sha256') != self.plan['source_machine_sha256'], 'source_machine_rejected', 403)
        if phase == 'apply':
            fresh = self.engine.inspect_target()
            # Recompare identity across the full readiness probe as well: a
            # device/boot change between these two reads must not be admitted.
            require(isinstance(fresh, dict) and all(fresh.get(key) == self.target[key] for key in IDENTITY),
                    'target_identity_changed', 403)
            require(fresh.get('machine_sha256') != self.plan['source_machine_sha256'], 'source_machine_rejected', 403)
            require(fresh.get('eligible') is True, 'target_no_longer_empty', 403)

    def authenticate(self, code, address):
        self.guard('login')
        with self.lock:
            now = self.clock()
            while self.failures and self.failures[0][0] < now - 900:
                self.failures.popleft()
            require(len(self.failures) < 20 and sum(ip == address for _, ip in self.failures) < 8,
                    'login_rate_limited', 429)
            if (self.code is None or not isinstance(code, str) or not code.isascii()
                    or len(code) > 128 or not hmac.compare_digest(code, self.code)):
                self.failures.append((now, address))
                raise BootstrapError('bootstrap_code_invalid', 403)
            self.code = None
            self.session_id = secrets.token_hex(32)
            self.csrf = secrets.token_urlsafe(32)
            body = base64.urlsafe_b64encode(json_bytes({'sid': self.session_id, 'exp': self.created + LIFETIME})).decode().rstrip('=')
            signature = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()
            return body + '.' + signature

    def authenticated(self, value):
        if not isinstance(value, str) or len(value) > 512 or self.session_id is None:
            return False
        try:
            body, signature = value.split('.')
            require(hmac.compare_digest(hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest(), signature), 'session_invalid')
            data = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
            return (data == {'sid': self.session_id, 'exp': self.created + LIFETIME}
                    and self.created - 5 <= self.clock() <= data['exp']
                    and 0 <= self.monotonic() - self.started_monotonic <= LIFETIME)
        except (ValueError, TypeError, BootstrapError):
            return False

    def snapshot(self):
        with self.lock:
            return {'state': self.status, 'phase': self.phase, 'error_code': self.error_code,
                    'busy': self.busy, 'job_id': self.job_id, 'uploaded_bytes': self.upload_bytes,
                    'needs_key': self.artifact is not None and self.encrypted,
                    'expires_at': self.created + LIFETIME, 'mode': 'single-disk-rehearsal',
                    'target': {key: self.target.get(key) for key in
                               ('os_id', 'os_version', 'architecture', 'root_uuid', 'root_wwn', 'root_identity_sha256',
                                'root_device', 'hostname', 'addresses', 'free_bytes')},
                    'backup': self.plan['backup'], 'encrypted_copies': self.plan.get('encrypted_copies', []),
                    'preview': {key: self.preview[key] for key in SUMMARY if key in self.preview} if self.preview else None,
                    'result': self.result}

    def reserve_action(self):
        self.guard('input')
        require(not self.busy and self.job_id is None, 'operation_busy', 409)
        self.busy = True

    def log_error(self, error):
        # Exception messages/bodies may contain private archive metadata. This
        # file is root-only and never returned by HTTP. Keys are never logged.
        fd = os.open(self.work / 'private.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as output:
            os.fchmod(output.fileno(), 0o600)
            traceback.print_exception(type(error), error, error.__traceback__, file=output)

    def upload(self, filename, length, stream):
        with self.lock:
            choices = [self.plan['backup'], *self.plan.get('encrypted_copies', [])]
            expected = next((item for item in choices if item['filename'] == filename), None)
            if expected is None or length != expected['bytes']:
                raise BootstrapError('upload_descriptor_mismatch')
            require(shutil.disk_usage(self.work).free > length * 2 + RESERVE, 'upload_space_insufficient')
            require(self.input_attempts < 3, 'upload_attempt_limit', 429)
            self.reserve_action()
            self.input_attempts += 1
            self.status, self.phase, self.preview, self.upload_bytes = 'uploading', 'upload', None, 0
            if self.artifact is not None:
                self.artifact.unlink(missing_ok=True)
            self.artifact = None
        destination = self.work / ('upload-' + secrets.token_hex(8))
        try:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            digest, remaining = hashlib.sha256(), length
            with os.fdopen(fd, 'wb') as output:
                while remaining:
                    block = stream.read(min(1024 ** 2, remaining))
                    require(bool(block), 'upload_incomplete')
                    output.write(block)
                    digest.update(block)
                    remaining -= len(block)
                    self.upload_bytes = length - remaining
                output.flush()
                os.fsync(output.fileno())
            require(hmac.compare_digest(digest.hexdigest(), expected['sha256']), 'upload_hash_mismatch')
            self.guard('upload_complete')
            with self.lock:
                self.artifact, self.encrypted = destination, filename != self.plan['backup']['filename']
                self.status, self.error_code = 'uploaded', ''
        except Exception:
            destination.unlink(missing_ok=True)
            self.status = 'waiting_upload'
            raise
        finally:
            self.busy = False

    def decrypt(self, identity):
        require(isinstance(identity, str) and 0 < len(identity.encode()) <= 4096
                and '\x00' not in identity and identity.isascii(), 'identity_invalid')
        with self.lock:
            self.reserve_action()
            if not self.encrypted or self.artifact is None:
                self.busy = False
                raise BootstrapError('encrypted_upload_required', 409)
            self.status, self.phase = 'decrypting', 'decrypt'
        key = bytearray(identity.encode())
        fd, process = None, None
        destination = self.work / ('decrypted-' + secrets.token_hex(8))
        try:
            fd = os.memfd_create('fls-recovery-identity', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.write(fd, key)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
            process = subprocess.Popen([str(self.runtime / 'tools/age'), '--decrypt', '--identity',
                                        '/proc/self/fd/' + str(fd), str(self.artifact)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       pass_fds=(fd,), env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            expected, total, digest = self.plan['backup'], 0, hashlib.sha256()
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 300
            out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(out, 'wb') as output:
                    while True:
                        require(time.monotonic() < deadline, 'decrypt_timeout')
                        if not selector.select(timeout=1):
                            continue
                        block = os.read(process.stdout.fileno(), 1024 ** 2)
                        if not block:
                            break
                        total += len(block)
                        require(total <= expected['bytes'], 'decrypted_size_mismatch')
                        digest.update(block)
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                selector.close()
            require(process.wait(timeout=10) == 0, 'decrypt_failed')
            require(total == expected['bytes'] and hmac.compare_digest(digest.hexdigest(), expected['sha256']),
                    'decrypted_hash_mismatch')
            self.guard('decrypt_complete')
            self.artifact.unlink()
            self.artifact, self.encrypted, self.status, self.error_code = destination, False, 'uploaded', ''
        except Exception:
            destination.unlink(missing_ok=True)
            self.status = 'uploaded'
            raise
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                process.stdout.close()
            if fd is not None:
                os.close(fd)
            for index in range(len(key)):
                key[index] = 0
            self.busy = False

    def validate(self):
        with self.lock:
            if self.status == 'validated' and self.preview is not None:
                return
            require(self.validation_attempts < 3, 'validation_attempt_limit', 429)
            self.reserve_action()
            if self.artifact is None or self.encrypted:
                self.busy = False
                raise BootstrapError('plaintext_upload_required', 409)
            self.status, self.phase, self.error_code = 'validating', 'backup_validation', ''
            self.validation_attempts += 1
        def inspect():
            try:
                self.guard('backup_validation')
                preview = self.engine.inspect_backup(self.artifact, self.plan['backup']['sha256'], self.work)
                require(isinstance(preview, dict) and preview.get('verified') is True
                        and preview.get('sha256') == self.plan['backup']['sha256'], 'backup_inspection_invalid')
                self.guard('backup_validated')
                with self.lock:
                    self.preview, self.status = preview, 'validated'
            except Exception as error:
                self.log_error(error)
                self.status, self.error_code = 'uploaded', public_code(error)
            finally:
                self.busy = False
        try:
            self.spawn(inspect)
        except Exception as error:
            self.log_error(error)
            self.status, self.busy, self.error_code = 'uploaded', False, 'worker_start_failed'
            raise BootstrapError('worker_start_failed', 503) from None

    def apply(self, request_id, confirmation):
        require(isinstance(request_id, str) and re.fullmatch(
                '[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', request_id)
                and confirmation == 'TAMAM', 'confirmation_required')
        with self.lock:
            self.guard('apply_status')
            if self.job_id is not None:
                require(request_id == self.job_id, 'another_restore_recorded', 409)
                return self.snapshot()
            self.guard('apply')
            require(not self.busy and self.status == 'validated' and self.preview is not None
                    and self.artifact is not None and not self.encrypted, 'validated_backup_required', 409)
            self.job_id, self.status, self.phase, self.busy = request_id, 'queued', 'target_check', True
            try:
                private_write(self.state / 'apply.json', json_bytes({'schema': 1, 'request_id': request_id,
                              'created_epoch': self.clock(), 'marker_nonce': self.marker['nonce']}))
            except Exception:
                self.status, self.busy, self.error_code = 'failed', False, 'apply_journal_failed'
                raise BootstrapError('apply_journal_failed', 409)
        def restore():
            try:
                self.status = 'running'
                result = self.engine.restore(self.artifact, self.plan, self.work, self.runtime,
                                             self.restore_guard, self.progress)
                require(isinstance(result, dict) and result.get('ok') is True, 'restore_result_invalid')
                self.restore_guard('complete')
                web_url = result.get('web_url')
                allowed = {'localhost', '127.0.0.1', *self.target.get('addresses', [])}
                parsed = urllib.parse.urlsplit(web_url or '')
                require(parsed.scheme == 'https' and parsed.hostname in allowed and parsed.port == 8443
                        and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
                        'restore_url_invalid')
                with self.lock:
                    self.status, self.phase = 'succeeded', 'complete'
                    self.result = {'ok': True, 'web_url': web_url, 'mode': 'single-disk-rehearsal'}
            except Exception as error:
                self.log_error(error)
                self.status, self.error_code = 'failed', public_code(error)
            finally:
                self.busy = False
        try:
            self.spawn(restore)
        except Exception as error:
            self.log_error(error)
            self.status, self.busy, self.error_code = 'failed', False, 'worker_start_failed'
            raise BootstrapError('worker_start_failed', 503) from None
        return self.snapshot()

    def restore_guard(self, phase):
        self.guard(phase)
        journal = json.loads(read_regular(self.state / 'apply.json', 8192, self.owner_uid))
        require(journal.get('request_id') == self.job_id and journal.get('marker_nonce') == self.marker['nonce']
                and stat.S_IMODE((self.state / 'apply.json').lstat().st_mode) == 0o600,
                'apply_journal_changed', 403)

    def progress(self, phase):
        require(isinstance(phase, str) and re.fullmatch('[a-z_]{1,40}', phase), 'restore_phase_invalid')
        with self.lock:
            self.phase = phase


UI_JS = r"""'use strict';
const $=id=>document.getElementById(id);let csrf='',last=null,pendingApply=null,writing=false;
function note(value){$('message').textContent=value;}
async function request(path,body,extra={},milliseconds=15000){
 const controller=new AbortController();let timer;
 try{return await Promise.race([(async()=>{const response=await fetch(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:{...(body===undefined?{}:{'X-FLS-CSRF':csrf,'Content-Type':body instanceof File?'application/octet-stream':'application/json'}),...extra},body:body===undefined?undefined:body instanceof File?body:JSON.stringify(body)});const data=await response.json();if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Yanıt doğrulanamadı.');if(!response.ok)throw Error(data.error_code||'İstek tamamlanamadı.');return data;})(),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('Yanıt alınamadı. Durumu yeniden okuyun; işlem otomatik tekrarlanmadı.'));},milliseconds);})]);}finally{clearTimeout(timer);}
}
function render(value){
 last=value;$('login').hidden=true;$('workspace').hidden=false;
 $('target').textContent='Ubuntu '+value.target.os_version+' · '+value.target.architecture+' · '+value.target.root_device+'\nUUID: '+value.target.root_uuid+'\nDisk kimliği SHA-256: '+value.target.root_identity_sha256;
 $('status').textContent=value.state+' · '+value.phase+(value.error_code?' · '+value.error_code:'')+(value.uploaded_bytes?' · '+value.uploaded_bytes+' bayt yüklendi':'');
 $('expected').textContent='Beklenen yedek: '+value.backup.filename+' · '+value.backup.bytes+' bayt';
 $('key-row').hidden=!value.needs_key;
 $('upload').disabled=writing||value.busy||Boolean(value.job_id);
 $('decrypt').disabled=writing||value.busy||!value.needs_key;
 $('validate').disabled=writing||value.busy||value.needs_key||value.state!=='uploaded';
 $('apply').disabled=writing||value.busy||value.state!=='validated'||Boolean(value.job_id)||Boolean(pendingApply);
 $('preview').textContent=value.preview?'FLS '+value.preview.version+' · '+value.preview.table_count+' tablo · '+value.preview.configuration_table_count+' ayar tablosu\nHam log ve çalışma geçmişi geri yüklenmez. Tek diskli prova; log alımı, otomatik işler, damga ve FTP kapalı kalır.':'';
 if(value.job_id&&pendingApply===value.job_id){pendingApply=null;note('İstek kaydedildi. İşlem durumu aşağıda gösteriliyor.');}
 $('result').hidden=!value.result;if(value.result){$('result-link').href=value.result.web_url;$('result-link').textContent=value.result.web_url;}
}
async function refresh(){try{const value=await request('/api/status');render(value);}catch(error){note(error.message);}}
async function write(action){if(writing)return;writing=true;if(last)render(last);try{await action();note('');}catch(error){note(error.message);}finally{writing=false;await refresh();}}
$('login-form').onsubmit=async event=>{event.preventDefault();const code=$('code').value;$('code').value='';try{const value=await request('/api/login',{code});csrf=value.csrf;await refresh();}catch(error){note(error.message);}};
$('upload').onclick=()=>write(async()=>{const file=$('file').files[0];if(!file)throw Error('Yedek dosyasını seçin.');await request('/api/upload',file,{'X-FLS-Filename':file.name},1800000);});
$('decrypt').onclick=()=>write(async()=>{try{const file=$('key').files[0];if(!file||file.size>4096)throw Error('En fazla 4 KB kurtarma anahtarı dosyasını seçin.');const key=await file.text();await request('/api/key',{key},{},330000);}finally{$('key').value='';}});
$('validate').onclick=()=>write(()=>request('/api/validate',{}));
$('apply').onclick=()=>write(async()=>{if($('confirmation').value!=='TAMAM')throw Error('Başlatmak için TAMAM yazın.');pendingApply=crypto.randomUUID();const value=await request('/api/apply',{request_id:pendingApply,confirmation:'TAMAM'});if(value.job_id!==pendingApply||!['queued','running','succeeded','failed'].includes(value.state))throw Error('Başlatma sonucu doğrulanamadı. Durumu yeniden okuyun; işlem otomatik tekrarlanmadı.');});
$('refresh').onclick=refresh;
request('/api/session').then(value=>{csrf=value.csrf;if(value.authenticated)refresh();}).catch(error=>note(error.message));
setInterval(()=>{if(last)refresh();},2000);
"""

HTML = '''<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FLS kurtarma provası</title><style>body{font:16px system-ui;max-width:850px;margin:3rem auto;padding:0 1rem;background:#f4f6f8;color:#152333}section{background:white;padding:1.5rem;border-radius:12px;margin:1rem 0}input,button{font:inherit;padding:.65rem;margin:.4rem 0;max-width:100%;box-sizing:border-box}input{width:100%}button{cursor:pointer}button:disabled{cursor:wait;opacity:.55}pre{white-space:pre-wrap;overflow-wrap:anywhere}#message{color:#a52a25}small{display:block;color:#536273}</style><h1>FLS kurtarma provası</h1><p>Yalnız ayrı ve boş Ubuntu üzerinde tek diskli prova. Bu ekran üretim sistemini etkinleştirmez.</p><section id="login"><form id="login-form"><label>Konsolda gösterilen tek kullanımlık kod<input id="code" type="password" autocomplete="off" required></label><button>Giriş</button></form><small>Önce HTTPS sertifika parmak izini hedef konsoluyla karşılaştırın. Kod veya kurtarma anahtarını adres satırına yazmayın.</small></section><main id="workspace" hidden><section><h2>Hedef</h2><pre id="target"></pre><p id="expected"></p><label>Yedek dosyası<input type="file" id="file"></label><button id="upload">Yükle</button><div id="key-row" hidden><label>age kurtarma anahtarı dosyası<input id="key" type="file" accept=".txt,.agekey" autocomplete="off"></label><button id="decrypt">Anahtarla aç</button><small>Anahtar yalnız hedef sunucunun belleğinde kullanılır, diske kaydedilmez.</small></div><button id="validate" disabled>Yedeği doğrula ve önizle</button></section><section><pre id="preview"></pre><label>Başlatma onayı<input id="confirmation" autocomplete="off" placeholder="TAMAM"></label><button id="apply" disabled>Prova geri yüklemesini başlat</button><p id="status"></p><button id="refresh">Durumu yeniden oku</button><p id="result" hidden>Prova arayüzü: <a id="result-link" rel="noreferrer"></a></p></section></main><p id="message" role="status"></p><script src="/ui.js" defer></script></html>'''


class RecoveryHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass  # No request paths, cookies, codes, identities or bodies in logs.

    def setup(self):
        super().setup()
        self.connection.settimeout(10)
        if isinstance(self.connection, ssl.SSLSocket):
            self.connection.do_handshake()
        self.connection.settimeout(30)

    @property
    def app(self):
        return self.server.application

    def send(self, status, value, content_type='application/json', cookie=None):
        body = value if isinstance(value, bytes) else json_bytes(value)
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', 'fls_recovery=' + cookie + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=' + str(LIFETIME))
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        require(len(self.headers.get_all('Host', [])) == 1, 'host_rejected', 403)
        host = self.headers.get('Host', '')
        parsed = urllib.parse.urlsplit('https://' + host)
        require(parsed.hostname in self.server.allowed_hosts and parsed.port == self.server.server_port
                and not parsed.username and not parsed.password and parsed.path == ''
                and not parsed.query and not parsed.fragment, 'host_rejected', 403)
        return host.lower()

    def session(self):
        try:
            parsed = cookies.SimpleCookie(self.headers.get('Cookie', ''))
            return self.app.authenticated(parsed['fls_recovery'].value) if 'fls_recovery' in parsed else False
        except cookies.CookieError:
            return False

    def authorize(self, post=False, login=False):
        host = self.valid_host()
        self.app.guard('http')
        if post:
            require(len(self.headers.get_all('Origin', [])) == 1
                    and len(self.headers.get_all('X-FLS-CSRF', [])) == 1,
                    'origin_rejected', 403)
            require(self.headers.get('Origin', '').lower() == 'https://' + host,
                    'origin_rejected', 403)
            require(hmac.compare_digest(self.headers.get('X-FLS-CSRF', ''), self.app.csrf),
                    'csrf_rejected', 403)
        if not login:
            require(self.session(), 'authentication_required', 401)

    def length(self, maximum):
        raw = self.headers.get('Content-Length', '')
        require(len(self.headers.get_all('Content-Length', [])) == 1
                and not self.headers.get('Transfer-Encoding') and not self.headers.get('Content-Encoding')
                and re.fullmatch('[0-9]{1,12}', raw),
                'content_length_required', 411)
        size = int(raw)
        require(size <= maximum, 'request_too_large', 413)
        return size

    def body(self, maximum=8192):
        require(self.headers.get_content_type() == 'application/json', 'json_body_required', 415)
        size = self.length(maximum)
        raw = self.rfile.read(size)
        require(len(raw) == size, 'request_incomplete')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise BootstrapError('request_json_invalid') from None
        require(isinstance(value, dict), 'request_object_required')
        return value

    def dispatch(self, post):
        try:
            require(self.path in ('/', '/ui.js', '/api/session', '/api/status', '/api/login',
                                 '/api/upload', '/api/key', '/api/validate', '/api/apply'), 'route_not_found', 404)
            if not post:
                self.valid_host()
                self.app.guard('http')
                if self.path == '/':
                    return self.send(200, HTML.encode(), 'text/html; charset=utf-8')
                if self.path == '/ui.js':
                    return self.send(200, UI_JS.encode(), 'text/javascript; charset=utf-8')
                if self.path == '/api/session':
                    return self.send(200, {'authenticated': self.session(), 'csrf': self.app.csrf})
                self.authorize()
                require(self.path == '/api/status', 'method_not_allowed', 405)
                return self.send(200, self.app.snapshot())
            self.authorize(post=True, login=self.path == '/api/login')
            if self.path == '/api/upload':
                require(self.headers.get_content_type() == 'application/octet-stream', 'raw_upload_required', 415)
                self.app.upload(self.headers.get('X-FLS-Filename', ''), self.length(MAX_BACKUP), self.rfile)
            else:
                value = self.body()
                if self.path == '/api/login':
                    require(set(value) == {'code'}, 'request_fields_invalid')
                    cookie = self.app.authenticate(value['code'], self.client_address[0])
                    return self.send(200, {'authenticated': True, 'csrf': self.app.csrf}, cookie=cookie)
                if self.path == '/api/key':
                    require(set(value) == {'key'}, 'request_fields_invalid')
                    self.app.decrypt(value['key'])
                elif self.path == '/api/validate':
                    require(value == {}, 'request_fields_invalid')
                    self.app.validate()
                elif self.path == '/api/apply':
                    require(set(value) == {'request_id', 'confirmation'}, 'request_fields_invalid')
                    self.app.apply(value['request_id'], value['confirmation'])
                else:
                    raise BootstrapError('method_not_allowed', 405)
            return self.send(202, self.app.snapshot())
        except BootstrapError as error:
            self.close_connection = True
            self.send(error.status, {'error_code': error.code})
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True
        except Exception as error:
            self.close_connection = True
            self.app.log_error(error)
            self.send(500, {'error_code': public_code(error)})

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)


class RecoveryServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, app, hosts):
        self.application, self.allowed_hosts = app, hosts
        self.slots = threading.BoundedSemaphore(12)
        super().__init__(address, RecoveryHandler)
        self.timeout = 1

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Handshake failures have no authenticated HTTP request to report.
        pass


def certificate(work, target):
    addresses = {'127.0.0.1'}
    for value in target.get('addresses', []):
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            raise BootstrapError('target_address_invalid') from None
    san = 'DNS:localhost,' + ','.join('IP:' + value for value in sorted(addresses))
    with (work / 'private.log').open('a') as output:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:prime256v1', '-nodes', '-days', '30',
                        '-subj', '/CN=FLS recovery rehearsal', '-addext', 'subjectAltName=' + san,
                        '-keyout', str(work / 'key.pem'), '-out', str(work / 'cert.pem')],
                       check=True, stdin=subprocess.DEVNULL, stdout=output, stderr=output, timeout=60)
    (work / 'key.pem').chmod(0o600)
    (work / 'cert.pem').chmod(0o600)
    der = ssl.PEM_cert_to_DER_cert((work / 'cert.pem').read_text())
    return hashlib.sha256(der).hexdigest()


def prepare(kit, state=STATE):
    require(os.geteuid() == 0, 'root_required', 403)
    kit = Path(kit).absolute()
    require(kit.resolve() == kit and kit.is_dir() and not kit.is_symlink(), 'kit_directory_unsafe')
    files = {'plan.json': read_regular(kit / 'plan.json', 65536)}
    plan = validate_plan(json.loads(files['plan.json']))
    code = {}
    for name in ('fls_recovery_engine.py', *HELPERS):
        code[name] = read_regular(kit / 'bin' / name, 2 * 1024 ** 2)
    engine = load_engine(kit / 'bin/fls_recovery_engine.py', code['fls_recovery_engine.py'])
    target = target_preflight(engine, plan)
    require(not state.exists() and not state.is_symlink(), 'recovery_state_exists', 403)
    require(shutil.which('openssl') is not None, 'openssl_required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    app = RecoveryApplication(engine, plan, target, state)
    app.initialize()
    private_write(state / 'plan.json', json_bytes(plan))
    trusted = state / 'bin'
    trusted.mkdir(mode=0o700)
    for name, content in code.items():
        private_write(trusted / name, content)
    copy_runtime(kit / 'runtime.tar.gz', state / 'runtime.tar.gz', plan['runtime'])
    app.runtime = extract_runtime(state / 'runtime.tar.gz', state,
                                  min(4 * 1024 ** 3, max(512 * 1024 ** 2, plan['runtime']['bytes'] * 4)))
    (app.runtime / 'bin').mkdir(mode=0o700)
    for name in HELPERS:
        private_write(app.runtime / 'bin' / name, code[name])
    app.engine = load_engine(trusted / 'fls_recovery_engine.py', code['fls_recovery_engine.py'])
    app.guard('runtime_ready')
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--bind', default='0.0.0.0')
    options = parser.parse_args()
    app = None
    try:
        app = prepare(options.kit)
        fingerprint = certificate(app.work, app.target)
        hosts = {'localhost', '127.0.0.1', *app.target.get('addresses', [])}
        require(options.bind == '0.0.0.0' or options.bind in hosts, 'bind_address_invalid')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(app.work / 'cert.pem', app.work / 'key.pem')
        server = RecoveryServer((options.bind, 8444), app, hosts)
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        address = next((value for value in app.target.get('addresses', [])
                        if ':' not in value and value != '127.0.0.1'), '127.0.0.1')
        print('FLS tek diskli kurtarma provası: https://' + address + ':8444/', flush=True)
        print('TLS SHA256: ' + ':'.join(fingerprint[i:i + 2] for i in range(0, 64, 2)), flush=True)
        print('Tek kullanımlık giriş kodu: ' + app.code, flush=True)
        print('En fazla 8 saat geçerlidir. Üretim etkinleştirme ve otomatik log alımı yoktur.', flush=True)
        try:
            while (app.clock() <= app.created + LIFETIME
                   and app.monotonic() - app.started_monotonic <= LIFETIME):
                server.handle_request()
        finally:
            server.server_close()
        return 0
    except Exception as error:
        if app is not None:
            app.log_error(error)
        print('Kurtarma başlangıcı reddedildi: ' + public_code(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
