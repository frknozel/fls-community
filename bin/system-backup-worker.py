#!/usr/bin/python3
"""Consume explicit administrator system-backup jobs; never schedule a backup."""
import contextlib
import datetime as dt
import fcntl
import ftplib
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

import pymysql

sys.path.insert(0, str(Path(__file__).resolve().parent))
from archive_transports import FTP, TransferError, deliver
from fls_backup_encryption import EncryptionError, ensure_companion, load_config

STATE = Path('/var/lib/fls-backup-worker')
PUBLISHED = Path('/var/lib/fls-recovery-download')
BACKUPS = Path('/srv/fls-server/backups')
CREDENTIAL = Path('/etc/fls/system-backup.json')
FILENAME = re.compile(r'fls-system-\d{8}-\d{6}Z\.tar\.gz\Z')
SHA256 = re.compile(r'[a-f0-9]{64}\Z')
PROOF_FIELDS = (
    'all_payload_hashes_match', 'all_system_file_hashes_match',
    'independent_mariadb_restore', 'configuration_rows_roundtrip_exact',
    'non_configuration_tables_empty_before_seeds', 'safe_restore_verified',
    'signing_key_pairs_match', 'encrypted_credentials_decrypted',
    'sql_accounts_restored', 'credential_auth_verified',
    'raw_logs_archives_runtime_history_absent',
    'current_source_and_native_helpers_included',
)


class BackupJobError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise BackupJobError(code)


def relative_parts(value):
    require(isinstance(value, str) and 1 <= len(value) <= 400
            and re.fullmatch(r'[A-Za-z0-9_. ()/-]+', value) is not None,
            'remote_directory_invalid')
    parts = value.split('/')
    require(all(part and part not in ('.', '..') and part.strip() == part
                and not part.endswith('.') for part in parts),
            'remote_directory_invalid')
    return parts


def remote_directory(destination, settings):
    relative_parts(settings['system_backup_directory'])
    relative_parts(settings['db_dump_directory'])
    system = settings['system_backup_directory']
    database = settings['db_dump_directory']
    system_folded, database_folded = system.casefold(), database.casefold()
    require(system_folded != database_folded and not system_folded.startswith(database_folded + '/')
            and not database_folded.startswith(system_folded + '/'), 'remote_directory_overlap')
    root = destination.get('remote_path')
    require(isinstance(root, str) and root and not any(character in root for character in '\r\n\x00'),
            'remote_directory_invalid')
    return root.rstrip('/') + '/' + system + '/'


def validate_actor(job, actor):
    require(isinstance(actor, dict) and actor.get('id') == job['requested_by_uid']
            and actor.get('role') == 'admin' and actor.get('enabled') == 1
            and actor.get('must_change') == 0
            and actor.get('session_version') == job['requested_session_version'],
            'actor_revoked')


def validate_request_age(job, now):
    requested = job.get('requested_at')
    require(type(requested) is dt.datetime and requested.tzinfo is None
            and requested <= now + dt.timedelta(seconds=5)
            and requested >= now - dt.timedelta(minutes=30), 'request_expired')


def validate_upload(job, settings, destination):
    require(isinstance(settings, dict) and settings.get('revision') == job['settings_revision']
            and settings.get('destination_id') == job['destination_id'], 'settings_changed')
    require(isinstance(destination, dict) and destination.get('id') == job['destination_id']
            and destination.get('revision') == job['destination_revision'], 'destination_changed')
    require(destination.get('protocol') == 'ftps', 'ftps_required')
    require(destination.get('enabled') == 1 and destination.get('check_status') == 'ok'
            and destination.get('checked_revision') == destination.get('revision'),
            'destination_unverified')
    require(job['remote_directory'] == remote_directory(destination, settings),
            'settings_changed')


def read_config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                and info.st_nlink == 1 and not info.st_mode & 0o037 and info.st_size <= 16384,
                'credential_permissions')
        value = json.loads(stream.read(16385))
    require(isinstance(value, dict) and set(value) == {'user', 'password'}
            and value['user'] == 'fls_system_backup'
            and isinstance(value['password'], str) and 16 <= len(value['password']) <= 512,
            'credential_invalid')
    return value


def safe_directory(path, mode, gid=0, uid=0):
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
            and stat.S_IMODE(info.st_mode) == mode, 'directory_permissions')


def file_metadata(path, *, mode, gid, uid=0, maximum=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid
                and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1 and info.st_size > 0
                and (maximum is None or info.st_size <= maximum), 'artifact_permissions')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        current = Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(info, key) == getattr(after, key) == getattr(current, key)
                    for key in fields), 'artifact_changed')
    return {'bytes': info.st_size, 'sha256': digest}


def bundle_metadata(root, filename, expected=None, *, mode=0o640, gid=None, uid=0):
    require(isinstance(filename, str) and FILENAME.fullmatch(filename) is not None,
            'artifact_filename_invalid')
    gid = grp.getgrnam('fls-web').gr_gid if gid is None else gid
    archive = root / filename
    metadata = file_metadata(archive, mode=mode, gid=gid, uid=uid)
    if expected is not None:
        require(metadata['bytes'] == expected['bytes'] and metadata['sha256'] == expected['sha256'],
                'artifact_checksum_mismatch')
    checksum = root / (filename + '.sha256')
    report_path = root / (filename + '.verification.json')
    file_metadata(checksum, mode=mode, gid=gid, uid=uid, maximum=1024)
    file_metadata(report_path, mode=mode, gid=gid, uid=uid, maximum=4 * 1024 * 1024)
    require(checksum.read_text() == metadata['sha256'] + '  ' + filename + '\n',
            'artifact_checksum_mismatch')
    report = json.loads(report_path.read_text())
    require(report.get('schema') == 'fls-system-backup-verification-v1'
            and report.get('filename') == filename and report.get('bytes') == metadata['bytes']
            and report.get('sha256') == metadata['sha256']
            and all(report.get(field) is True for field in PROOF_FIELDS)
            and report.get('production_database_modified') is False,
            'artifact_verification_missing')
    return {'filename': filename, **metadata, 'report': report,
            'files': [archive, checksum, report_path]}


def decrypt_destination(destination, master_path=Path('/etc/fls/credential-key')):
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    fd = os.open(master_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o037
                and info.st_nlink == 1 and info.st_size == 32, 'master_key_invalid')
        master = stream.read(33)
    envelope = destination.get('secret_cipher')
    require(isinstance(envelope, str) and envelope.startswith('v1:'), 'destination_secret_invalid')
    raw = base64.b64decode(envelope[3:], validate=True)
    secret = json.loads(AESGCM(master).decrypt(raw[:12], raw[12:], b'FLS-Archive-v1'))
    require(isinstance(secret, dict) and isinstance(secret.get('password'), str),
            'destination_secret_invalid')
    return secret


class RecoveryFTP(FTP):
    """Verified FTPS with ordinary relative folders, not hourly log folders."""
    def __init__(self, destination, secret):
        require(destination.get('protocol') == 'ftps', 'ftps_required')
        super().__init__(destination, secret)

    def enter_directory(self, subdir):
        for part in relative_parts(subdir):
            try:
                self.c.cwd(part)
            except ftplib.error_perm:
                try:
                    self.c.mkd(part)
                except ftplib.error_perm:
                    pass
                try:
                    self.c.cwd(part)
                except Exception as exc:
                    raise BackupJobError('remote_directory_failed') from exc


class SQLStore:
    def __init__(self, connection):
        self.connection = connection

    def query(self, statement, values=()):
        with self.connection.cursor() as cursor:
            cursor.execute(statement, values)
            return cursor.fetchall()

    def execute(self, statement, values=()):
        with self.connection.cursor() as cursor:
            cursor.execute(statement, values)
            return cursor.lastrowid

    def heartbeat(self, status='idle', job_id=None, code=''):
        self.execute('UPDATE system_backup_worker SET checked_at=UTC_TIMESTAMP(6),status=%s,error_code=%s,job_id=%s WHERE id=1',
                     (status, code, job_id))

    def interrupt_previous(self):
        self.connection.begin()
        try:
            self.query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE')
            self.execute("UPDATE system_backup_jobs SET status='failed',completed_at=UTC_TIMESTAMP(6),error_code='worker_interrupted' WHERE status='running'")
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    @contextlib.contextmanager
    def guard(self, job, status='running'):
        self.connection.begin()
        try:
            require(bool(self.query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE')), 'management_state_missing')
            actor_rows = self.query('SELECT id,username,role,enabled,session_version,must_change FROM users WHERE id=%s FOR UPDATE',
                                    (job['requested_by_uid'],))
            actor = actor_rows[0] if actor_rows else None
            validate_actor(job, actor)
            settings_rows = self.query('SELECT * FROM system_backup_settings WHERE id=1 FOR UPDATE')
            require(bool(settings_rows), 'settings_missing')
            settings = settings_rows[0]
            destination = None
            if job['action'] == 'upload':
                rows = self.query('SELECT * FROM archive_destinations WHERE id=%s FOR UPDATE', (job['destination_id'],))
                destination = rows[0] if rows else None
                validate_upload(job, settings, destination)
            rows = self.query('SELECT * FROM system_backup_jobs WHERE id=%s FOR UPDATE', (job['id'],))
            require(bool(rows) and rows[0]['status'] == status, 'job_changed')
            actual = rows[0]
            for key in ('request_key', 'action', 'requested_by_uid', 'requested_session_version',
                        'backup_id', 'settings_revision', 'destination_id', 'destination_revision', 'remote_directory'):
                require(actual[key] == job[key], 'job_changed')
            yield {'actor': actor, 'settings': settings, 'destination': destination}
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def claim(self):
        candidates = self.query("SELECT * FROM system_backup_jobs WHERE status='queued' ORDER BY id LIMIT 1")
        if not candidates:
            return None
        job = candidates[0]
        try:
            with self.guard(job, 'queued'):
                require(job['action'] in ('create', 'upload'), 'action_invalid')
                now = self.query('SELECT UTC_TIMESTAMP(6) AS now')[0]['now']
                validate_request_age(job, now)
                self.execute("UPDATE system_backup_jobs SET status='running',started_at=UTC_TIMESTAMP(6),error_code='' WHERE id=%s", (job['id'],))
        except BackupJobError as exc:
            self.fail(job, exc.code)
            return None
        job['status'] = 'running'
        return job

    def fail(self, job, code):
        require(re.fullmatch(r'[a-z0-9_]{1,64}', code) is not None, 'error_code_invalid')
        self.execute("UPDATE system_backup_jobs SET status='failed',completed_at=UTC_TIMESTAMP(6),error_code=%s WHERE id=%s AND status IN ('queued','running')",
                     (code, job['id']))
        self.heartbeat('error', job['id'], code)

    def artifact(self, backup_id):
        rows = self.query("SELECT * FROM system_backups WHERE id=%s AND status='ready'", (backup_id,))
        require(bool(rows), 'artifact_missing')
        return rows[0]

    def catalog(self, job, bundle):
        return self.execute("INSERT INTO system_backups(filename,bytes,sha256,status,created_at,verified_at,created_by,created_job_id) VALUES(%s,%s,%s,'ready',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),%s,%s)",
                            (bundle['filename'], bundle['bytes'], bundle['sha256'], job['requested_by'], job['id']))

    def succeed(self, job, backup_id, remote_sha=''):
        self.execute("UPDATE system_backup_jobs SET status='succeeded',completed_at=UTC_TIMESTAMP(6),error_code='',backup_id=%s,remote_sha256=%s WHERE id=%s AND status='running'",
                     (backup_id, remote_sha, job['id']))


class LocalPublisher:
    def __init__(self, folder=PUBLISHED, source=BACKUPS, *, gid=None, uid=0, source_gid=0):
        self.folder = folder
        self.source = source
        self.gid = grp.getgrnam('fls-web').gr_gid if gid is None else gid
        self.uid = uid
        self.source_gid = source_gid

    def prepare(self, result):
        path = Path(result['path'])
        require(path.parent == self.source and FILENAME.fullmatch(path.name) is not None,
                'builder_result_invalid')
        require(result.get('ok') is True and result.get('independent_restore_verified') is True,
                'builder_verification_failed')
        return bundle_metadata(self.source, path.name, result, mode=0o600, gid=self.source_gid, uid=self.uid)

    @contextlib.contextmanager
    def stage(self, bundle):
        safe_directory(self.folder, 0o750, self.gid, self.uid)
        staging = Path(tempfile.mkdtemp(prefix='.pending-', dir=self.folder))
        staging.chmod(0o700)
        try:
            for original in bundle['files']:
                target = staging / original.name
                # Cross-device copy is staged privately. Originals are deleted
                # only after filesystem publication and catalog commit succeed.
                with original.open('rb') as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out, 1024 * 1024)
                    out.flush()
                    os.fsync(out.fileno())
                os.chown(target, self.uid, self.gid)
                target.chmod(0o640)
            verified = bundle_metadata(staging, bundle['filename'], bundle,
                                       gid=self.gid, uid=self.uid)
            yield verified
        finally:
            shutil.rmtree(staging)

    def publish(self, staged):
        for path in staged['files']:
            require(not (self.folder / path.name).exists() and not (self.folder / path.name).is_symlink(),
                    'artifact_conflict')
        for path in staged['files']:
            # link() provides no-clobber publication; unlink removes the extra
            # temporary link before catalog/download access becomes available.
            destination = self.folder / path.name
            os.link(path, destination, follow_symlinks=False)
            path.unlink()
        fd = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def finish(self, original):
        for path in original['files']:
            path.unlink()
        fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def create_verified_backup():
    path = Path(__file__).with_name('system-backup.py')
    specification = importlib.util.spec_from_file_location('fls_system_backup_builder', path)
    builder = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(builder)
    # Builder errors already have a private log. Never allow output from an
    # imported helper to become a service journal containing private paths/data.
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        return builder.create_backup()


def upload_bundle(store, job, bundle, snapshot, *, connector=RecoveryFTP, decrypt=decrypt_destination):
    destination = snapshot['destination']
    validate_upload(job, snapshot['settings'], destination)
    secret = decrypt(destination)
    remote = connector(dict(destination), secret)
    try:
        remote.enter_directory(snapshot['settings']['system_backup_directory'])
        for local in bundle['files']:
            # deliver's identical-existing-file shortcut does not call its
            # before_publish guard, so also guard before each file and success.
            with store.guard(job):
                pass
            with local.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            deliver(remote, local, local.name, digest, before_publish=lambda: store.guard(job))
        with store.guard(job):
            store.succeed(job, job['backup_id'], bundle['sha256'])
    finally:
        remote.close()


def encrypted_bundle(publisher, bundle, backup_id, config):
    return ensure_companion(publisher.folder, bundle['filename'], bundle, config,
                            backup_id=backup_id, uid=publisher.uid, gid=publisher.gid)


def run_once(store, publisher, *, creator=create_verified_backup, uploader=upload_bundle,
             encryption=None, encryptor=encrypted_bundle):
    store.interrupt_previous()
    store.heartbeat()
    job = store.claim()
    if job is None:
        return {'status': 'idle'}
    try:
        store.heartbeat('creating' if job['action'] == 'create' else 'uploading', job['id'])
        with store.guard(job) as snapshot:
            pass
        if job['action'] == 'create':
            result = creator()
            original = publisher.prepare(result)
            with publisher.stage(original) as staged:
                with store.guard(job):
                    publisher.publish(staged)
                    backup_id = store.catalog(job, original)
            # Encryption is intentionally outside the management transaction.
            # The verified plaintext catalog remains recoverable if encryption
            # fails; an active policy never falls back to plaintext transfer.
            if encryption is not None:
                encryptor(publisher, original, backup_id, encryption)
            with store.guard(job):
                store.succeed(job, backup_id)
            publisher.finish(original)
        elif job['action'] == 'upload':
            artifact = store.artifact(job['backup_id'])
            bundle = bundle_metadata(publisher.folder, artifact['filename'], artifact,
                                     gid=publisher.gid, uid=publisher.uid)
            if encryption is not None:
                bundle = encryptor(publisher, bundle, job['backup_id'], encryption)
            uploader(store, job, bundle, snapshot)
        else:
            raise BackupJobError('action_invalid')
        store.heartbeat()
        return {'status': 'succeeded', 'job_id': job['id']}
    except Exception as exc:
        known = exc.code if isinstance(exc, (BackupJobError, TransferError, EncryptionError)) else 'backup_job_failed'
        code = known if re.fullmatch(r'[a-z0-9_]{1,64}', known) else 'backup_job_failed'
        store.fail(job, code)
        return {'status': 'failed', 'job_id': job['id'], 'error_code': code}


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        return 1
    try:
        safe_directory(STATE, 0o700)
        fd = os.open(STATE / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'a') as lock:
            info = os.fstat(lock.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    'worker_lock_invalid')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 0
            credentials = os.environ.get('CREDENTIALS_DIRECTORY')
            config = read_config(Path(credentials) / 'database' if credentials else CREDENTIAL)
            connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',
                                         user=config['user'], password=config['password'],
                                         database='fls', charset='utf8mb4', autocommit=True,
                                         cursorclass=pymysql.cursors.DictCursor)
            try:
                # Missing configuration preserves the existing local workflow;
                # malformed or unreadable active configuration fails closed.
                run_once(SQLStore(connection), LocalPublisher(), encryption=load_config())
            finally:
                connection.close()
        return 0
    except Exception:
        # Private SQL/remote exceptions must never be included in the journal.
        print(json.dumps({'error_code': 'system_backup_worker_unavailable'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
