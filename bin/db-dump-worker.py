#!/usr/bin/python3
"""Daily verified configuration-only SQL; explicit --create or --upload required."""
import argparse
import contextlib
import datetime as dt
import fcntl
import grp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from zoneinfo import ZoneInfo

import pymysql

sys.path.insert(0, str(Path(__file__).resolve().parent))
from archive_transports import deliver
from fls_storage import storage_state


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


backup = module('fls_configuration_backup', 'system-backup.py')
recovery = module('fls_recovery_transport', 'system-backup-worker.py')
STATE = Path('/var/lib/fls-db-dump')
DIRECTORY = Path('/srv/fls-server/db-dumps')
CREDENTIAL = Path('/etc/fls/db-dump.json')
ZONE = ZoneInfo('Europe/Istanbul')
NAME = re.compile(r'fls-db-([a-f0-9]{12})-(\d{4}-\d{2}-\d{2})'
                  r'(?:-(\d{8}T\d{12}Z)-([a-f0-9]{16}))?\.sql\.gz\Z')
SIDECARS = ('', '.sha256', '.verification.json')
SCHEMA = 'fls-configuration-db-dump-v1'


class DumpError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise DumpError(code)


def date_name(scope, day):
    """Historical v1 basename, kept only for reading existing bundles."""
    require(re.fullmatch(r'[a-f0-9]{12}', scope) is not None, 'scope_invalid')
    return 'fls-db-' + scope + '-' + day.isoformat() + '.sql.gz'


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def name_identity(name, scope):
    if not isinstance(name, str):
        return None
    match = NAME.fullmatch(name)
    if match is None or match[1] != scope:
        return None
    try:
        day = dt.date.fromisoformat(match[2])
    except ValueError:
        return None
    if day.isoformat() != match[2]:
        return None
    captured = None
    if match[3]:
        try:
            captured = dt.datetime.strptime(match[3], '%Y%m%dT%H%M%S%fZ').replace(tzinfo=dt.timezone.utc)
        except ValueError:
            return None
        if captured.astimezone(ZONE).date() != day:
            return None
    return {'day': day, 'snapshot_at': captured, 'generation': match[4]}


def name_day(name, scope):
    identity = name_identity(name, scope)
    return identity['day'] if identity else None


def generation_name(scope, day, captured, generation):
    date_name(scope, day)  # Validate the historical scope and calendar format.
    require(captured.tzinfo is not None and captured.utcoffset() == dt.timedelta(0)
            and captured.astimezone(ZONE).date() == day, 'snapshot_day_invalid')
    require(re.fullmatch(r'[a-f0-9]{16}', generation) is not None, 'generation_invalid')
    return 'fls-db-' + scope + '-' + day.isoformat() + '-' + captured.strftime('%Y%m%dT%H%M%S%fZ') + '-' + generation + '.sql.gz'


def report_time(value):
    require(isinstance(value, str) and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value),
        'artifact_timestamp_invalid')
    try:
        result = dt.datetime.fromisoformat(value)
    except ValueError:
        raise DumpError('artifact_timestamp_invalid') from None
    require(result.tzinfo is not None and result.utcoffset() == dt.timedelta(0),
            'artifact_timestamp_invalid')
    return result


def instance_scope():
    raw = Path('/etc/machine-id').read_text().strip()
    require(re.fullmatch(r'[a-f0-9]{32}', raw) is not None, 'machine_identity_invalid')
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def atomic_json(path, value, mode=0o600, gid=0):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, default=backup.json_default)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, gid)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def safe_directory(path, mode, gid=0):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and value.st_gid == gid
            and stat.S_IMODE(value.st_mode) == mode and path.resolve() == path,
            'directory_permissions')


@contextlib.contextmanager
def operation_lock(directory, scope, readonly=False):
    """Serialize create/upload/publication even for direct library callers."""
    date_name(scope, dt.date(2000, 1, 1))
    safe_directory(directory, 0o700)
    flags = os.O_RDONLY if readonly else os.O_CREAT | os.O_RDWR
    try:
        fd = os.open(directory / ('.fls-db-' + scope + '.lock'),
                     flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileNotFoundError:
        if not readonly:
            raise
        # Before the first generation-aware create, the historical directory
        # has no scope lock. main() still holds STATE/worker.lock throughout
        # upload, so legacy publication cannot race a production create.
        require(not attempt_path(directory, scope).exists()
                and not attempt_path(directory, scope).is_symlink()
                and not any((identity := name_identity(path.name, scope)) is not None
                            and identity['generation'] is not None for path in directory.iterdir()),
                'operation_lock_missing')
        yield
        return
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'operation_lock_invalid')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def assert_storage():
    state = storage_state()
    require(state.get('mode') in ('system-root', 'hybrid'), 'backup_storage_unavailable')
    safe_directory(DIRECTORY, 0o700)
    if state['mode'] == 'system-root':
        require(DIRECTORY.stat().st_dev == Path('/').stat().st_dev,
                'backup_storage_identity_mismatch')
    else:
        # The schema-2 storage guard verifies the exact DB-Dump bind inode and
        # mountinfo root, not merely that this path happens to use another disk.
        require(state.get('depot_path') == '/srv/fls-storage'
                and DIRECTORY.stat().st_dev == Path('/srv/fls-storage').stat().st_dev
                and DIRECTORY.stat().st_ino == Path('/srv/fls-storage/DB-Dump').stat().st_ino
                and DIRECTORY.stat().st_dev != Path('/').stat().st_dev,
                'backup_storage_identity_mismatch')


def read_credential(path=CREDENTIAL):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o037 and info.st_nlink == 1 and info.st_size <= 2048,
                'credential_permissions')
        value = json.loads(stream.read(2049))
    require(isinstance(value, dict) and set(value) == {'user', 'password'}
            and value['user'] == 'fls_db_dump' and isinstance(value['password'], str)
            and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', value['password']) is not None,
            'credential_invalid')
    return value


def connect(credential):
    return pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', database='fls',
                           user=credential['user'], password=credential['password'],
                           charset='utf8mb4', autocommit=True,
                           cursorclass=pymysql.cursors.DictCursor)


def checked_file(path, maximum=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and info.st_size > 0 and (maximum is None or info.st_size <= maximum),
                'artifact_permissions')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        current = path.lstat()
        require(all(getattr(info, key) == getattr(after, key) == getattr(current, key)
                    for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
                'artifact_changed')
    return {'bytes': info.st_size, 'sha256': digest}


def artifact(root, name, scope):
    day = name_day(name, scope)
    require(day is not None, 'artifact_name_invalid')
    metadata = checked_file(root / name)
    checked_file(root / (name + '.sha256'), 1024)
    checked_file(root / (name + '.verification.json'), 1024 * 1024)
    require((root / (name + '.sha256')).read_text() == metadata['sha256'] + '  ' + name + '\n',
            'artifact_checksum_mismatch')
    report = json.loads((root / (name + '.verification.json')).read_text())
    validate_report(report, name, scope)
    require(report.get('sha256') == metadata['sha256'] and report.get('bytes') == metadata['bytes'],
            'artifact_verification_invalid')
    return {'filename': name, **metadata, 'report': report}


def validate_report(report, name, scope):
    identity = name_identity(name, scope)
    require(identity is not None and isinstance(report, dict), 'artifact_verification_invalid')
    day = identity['day']
    require(report.get('schema') == SCHEMA and report.get('scope') == scope
            and report.get('filename') == name and report.get('date') == day.isoformat()
            and isinstance(report.get('sha256'), str)
            and re.fullmatch(r'[a-f0-9]{64}', report['sha256']) is not None
            and type(report.get('bytes')) is int and report['bytes'] > 0
            and report.get('independent_mariadb_restore') is True
            and report.get('configuration_rows_roundtrip_exact') is True
            and report.get('non_configuration_tables_empty_before_seeds') is True
            and report.get('safe_restore_verified') is True
            and report.get('production_database_modified') is False, 'artifact_verification_invalid')
    if identity['snapshot_at'] is not None:
        captured = report_time(report.get('snapshot_at_utc'))
        verified = report_time(report.get('verified_at_utc'))
        require(captured == identity['snapshot_at'] and report.get('generation') == identity['generation']
                and captured <= verified, 'artifact_generation_mismatch')
    return identity


def attempt_path(directory, scope):
    return directory / ('.fls-db-' + scope + '-attempt.json')


def read_attempt(directory, scope):
    path = attempt_path(directory, scope)
    if not path.exists() and not path.is_symlink():
        return None
    checked_file(path, 8192)
    try:
        value = json.loads(path.read_text())
    except ValueError:
        raise DumpError('create_attempt_invalid') from None
    require(isinstance(value, dict) and value.get('schema') == SCHEMA + '-attempt'
            and value.get('scope') == scope and value.get('status') in ('running', 'failed', 'succeeded'),
            'create_attempt_invalid')
    identity = name_identity(value.get('filename', ''), scope)
    require(identity is not None and identity['snapshot_at'] is not None
            and value.get('date') == identity['day'].isoformat()
            and value.get('generation') == identity['generation']
            and report_time(value.get('snapshot_at_utc')) == identity['snapshot_at'],
            'create_attempt_invalid')
    return value


def latest_verified(directory, scope, today):
    """Never disguise a failed newer create as a fresh successful upload."""
    attempt = read_attempt(directory, scope)
    if attempt is not None and attempt['date'] == today.isoformat():
        require(attempt['status'] == 'succeeded',
                'latest_create_failed' if attempt['status'] == 'failed' else 'latest_create_incomplete')
        result = artifact(directory, attempt['filename'], scope)
        require(result['sha256'] == attempt.get('sha256'), 'latest_create_changed')
        return result
    verified = []
    for path in directory.iterdir():
        identity = name_identity(path.name, scope)
        if identity is None or identity['day'] != today:
            continue
        try:
            result = artifact(directory, path.name, scope)
            captured = identity['snapshot_at']
            if captured is None:
                when = result['report'].get('verified_at_utc')
                captured = report_time(when) if when is not None else dt.datetime.combine(
                    today, dt.time.min, ZONE).astimezone(dt.timezone.utc)
            verified.append((captured, path.name, result))
        except (OSError, ValueError):
            # Incomplete publications or edited artifacts are never candidates.
            continue
    if not verified:
        raise DumpError('today_verified_dump_missing')
    return max(verified, key=lambda entry: (entry[0], entry[1]))[2]


def dump_sql(connection, credential, output, work, stderr, socket='/run/mysqld/mysqld.sock'):
    tables = {next(iter(row.values())) for row in backup.query(connection, 'SHOW TABLES FROM fls')}
    require(set(backup.CONFIG_TABLES + backup.SEED_TABLES).issubset(tables), 'required_schema_missing')
    defaults = work / 'mariadb-client.cnf'
    defaults.write_text('[client]\nuser=' + credential['user'] + '\npassword=' + credential['password'] + '\n')
    defaults.chmod(0o600)
    command = ['mariadb-dump', '--defaults-file=' + str(defaults), '--socket=' + str(socket),
               '--single-transaction', '--quick', '--hex-blob', '--skip-lock-tables',
               '--skip-add-locks', '--skip-routines', '--skip-events', '--triggers',
               '--default-character-set=utf8mb4']
    command += ['--ignore-table-data=fls.' + table for table in sorted(tables)
                if table not in backup.CONFIG_TABLES]
    command.append('fls')
    import gzip
    for attempt in range(3):
        expected = backup.configuration_digest(connection)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr)
        try:
            with gzip.open(output, 'wb', compresslevel=1) as compressed:
                shutil.copyfileobj(process.stdout, compressed, 1024 * 1024)
            process.stdout.close()
            require(process.wait() == 0, 'database_dump_failed')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        if expected == backup.configuration_digest(connection):
            return tables, expected
    raise DumpError('configuration_changed_during_backup_retry')


def verify_and_safe_sql(path, tables, expected, stderr):
    with backup.temporary_database(stderr) as (connection, socket):
        backup.query(connection, 'CREATE DATABASE fls CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
        backup.restore_dump(path, socket, stderr)
        actual = {next(iter(row.values())) for row in backup.query(connection, 'SHOW TABLES FROM fls')}
        require(actual == tables and backup.configuration_digest(connection) == expected,
                'configuration_roundtrip_mismatch')
        empty = tables - set(backup.CONFIG_TABLES)
        require(all(backup.query(connection, 'SELECT COUNT(*) n FROM fls.' + backup.identifier(table))[0]['n'] == 0
                    for table in empty), 'non_configuration_data_in_dump')
        with connection.cursor() as cursor:
            cursor.execute('USE fls')
            for statement in backup.RESTORE_SQL.split(';'):
                if statement.strip():
                    cursor.execute(statement)
        require(backup.query(connection, 'SELECT requested_mode FROM fls.maintenance_requests')[0]['requested_mode'] == 'paused',
                'safe_restore_not_paused')
        require(backup.query(connection, 'SELECT action FROM fls.power_requests')[0]['action'] == '',
                'safe_restore_power_request')
        for table, field in (('timestamp_settings', 'enabled'), ('archive_destinations', 'enabled'),
                             ('archive_export_settings', 'packaging_enabled')):
            require(all(row[field] == 0 for row in backup.query(connection, 'SELECT ' + field + ' FROM fls.' + table)),
                    'safe_restore_automatic_action')
        require(all(backup.query(connection, 'SELECT COUNT(*) n FROM fls.' + backup.identifier(table))[0]['n'] == 0
                    for table in empty - set(backup.SEED_TABLES)), 'unexpected_restore_data')
    # Concatenated gzip members are standard and avoid holding SQL in memory.
    # The recovery reset follows the exact original configuration in the dump.
    import gzip
    with gzip.open(path, 'ab', compresslevel=1) as output:
        output.write(('\n' + backup.RESTORE_SQL).encode())
    with backup.temporary_database(stderr) as (connection, socket):
        backup.query(connection, 'CREATE DATABASE fls CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
        backup.restore_dump(path, socket, stderr)
        require(backup.query(connection, 'SELECT requested_mode FROM fls.maintenance_requests')[0]['requested_mode'] == 'paused',
                'final_restore_not_paused')
        require(all(backup.query(connection, 'SELECT COUNT(*) n FROM fls.' + backup.identifier(table))[0]['n'] == 0
                    for table in empty - set(backup.SEED_TABLES)), 'final_restore_unexpected_data')


def prune_local(root, scope, today):
    removed = []
    cutoff = today - dt.timedelta(days=6)
    for path in sorted(root.iterdir()):
        day = name_day(path.name, scope)
        if day is None or day >= cutoff:
            continue
        try:
            artifact(root, path.name, scope)
        except (OSError, ValueError):
            # An interrupted publication or edited file is never a deletion target.
            continue
        for suffix in SIDECARS:
            (root / (path.name + suffix)).unlink()
        removed.append(path.name)
    return removed


def create(connection, credential, scope, today, directory=DIRECTORY):
    with operation_lock(directory, scope):
        return create_generation(connection, credential, scope, today, directory)


def create_generation(connection, credential, scope, today, directory):
    captured = utc_now()
    generation = secrets.token_hex(8)
    name = generation_name(scope, today, captured, generation)
    attempt = {'schema': SCHEMA + '-attempt', 'scope': scope, 'date': today.isoformat(),
               'filename': name, 'snapshot_at_utc': captured.isoformat(timespec='microseconds'),
               'generation': generation, 'status': 'running'}
    atomic_json(attempt_path(directory, scope), attempt)
    try:
        result = build_generation(connection, credential, scope, today, directory, name, attempt)
    except BaseException:
        attempt['status'] = 'failed'
        atomic_json(attempt_path(directory, scope), attempt)
        raise
    attempt.update({'status': 'succeeded', 'sha256': result['sha256']})
    atomic_json(attempt_path(directory, scope), attempt)
    return {**result, 'reused': False, 'snapshot_at_utc': attempt['snapshot_at_utc'],
            'removed_local': prune_local(directory, scope, today)}


def build_generation(connection, credential, scope, today, directory, name, attempt):
    with tempfile.TemporaryDirectory(prefix='.db-create-', dir=directory) as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        output = work / name
        with (work / 'private-stderr.txt').open('wb') as stderr:
            tables, expected = dump_sql(connection, credential, output, work, stderr)
            verify_and_safe_sql(output, tables, expected, stderr)
        output.chmod(0o600)
        metadata = checked_file(output)
        report = {'schema': SCHEMA, 'scope': scope, 'filename': name, 'date': today.isoformat(),
                  'snapshot_at_utc': attempt['snapshot_at_utc'], 'generation': attempt['generation'],
                  'verified_at_utc': utc_now().isoformat(timespec='microseconds'), **metadata,
                  'all_table_schemas_restored': len(tables),
                  'configuration_tables': list(backup.CONFIG_TABLES),
                  'configuration_digests_before_recovery_reset': expected,
                  'independent_mariadb_restore': True, 'configuration_rows_roundtrip_exact': True,
                  'non_configuration_tables_empty_before_seeds': True, 'safe_restore_verified': True,
                  'production_database_modified': False, 'log_event_history_included': False,
                  'sql_account_credentials_included': False, 'os_or_software_files_included': False}
        (work / (name + '.sha256')).write_text(metadata['sha256'] + '  ' + name + '\n')
        (work / (name + '.sha256')).chmod(0o600)
        atomic_json(work / (name + '.verification.json'), report)
        artifact(work, name, scope)
        # The report is linked last. Only complete, verified three-file bundles
        # can be selected, including after a process/power interruption.
        for suffix in SIDECARS:
            source, target = work / (name + suffix), directory / (name + suffix)
            require(not target.exists() and not target.is_symlink(), 'artifact_conflict')
            with source.open('rb') as stream:
                os.fsync(stream.fileno())
            os.link(source, target, follow_symlinks=False)
            source.unlink()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return artifact(directory, name, scope)


def remote_settings(connection):
    settings = backup.query(connection, 'SELECT * FROM fls.system_backup_settings WHERE id=1')
    require(len(settings) == 1, 'settings_missing')
    settings = settings[0]
    rows = backup.query(connection, 'SELECT * FROM fls.archive_destinations WHERE id=%s',
                        (settings['destination_id'],))
    require(len(rows) == 1, 'destination_missing')
    destination = rows[0]
    recovery.validate_upload({'settings_revision': settings['revision'], 'destination_id': destination['id'],
                              'destination_revision': destination['revision'],
                              'remote_directory': recovery.remote_directory(destination, settings)},
                             settings, destination)
    # validate both sibling paths; the database uses the other sibling.
    remote = destination['remote_path'].rstrip('/') + '/' + settings['db_dump_directory'] + '/'
    return {'settings': settings, 'destination': destination, 'remote_directory': remote}


@contextlib.contextmanager
def upload_guard(connection, snapshot):
    connection.begin()
    try:
        require(bool(backup.query(connection, 'SELECT id FROM fls.management_lock WHERE id=1 FOR UPDATE')),
                'management_state_missing')
        current = remote_settings(connection)
        require(current['settings']['revision'] == snapshot['settings']['revision']
                and current['destination']['revision'] == snapshot['destination']['revision']
                and current['destination']['id'] == snapshot['destination']['id']
                and current['remote_directory'] == snapshot['remote_directory'], 'destination_changed')
        yield
        connection.commit()
    except Exception:
        connection.rollback()
        raise


class DumpFTP(recovery.RecoveryFTP):
    def names(self):
        names = self.c.nlst()
        require(len(names) <= 10000, 'remote_directory_too_large')
        # Some FTPS servers return absolute NLST paths even after CWD.
        # Operations below still use only a validated basename in this directory.
        return [name.rsplit('/', 1)[-1] for name in names
                if isinstance(name, str) and '\\' not in name]

    def read_report(self, name):
        stream = io.BytesIO()
        def receive(chunk):
            require(stream.tell() + len(chunk) <= 1024 * 1024, 'remote_report_too_large')
            stream.write(chunk)
        self.c.retrbinary('RETR ' + name, receive, 64 * 1024)
        return json.loads(stream.getvalue())


def prune_remote(remote, scope, today, guard):
    removed = []
    names = set(remote.names())
    cutoff = today - dt.timedelta(days=6)
    for name in sorted(names):
        day = name_day(name, scope)
        if day is None or day >= cutoff or any(name + suffix not in names for suffix in SIDECARS):
            continue
        try:
            report = remote.read_report(name + '.verification.json')
            # Both new immutable generations and historical v1 bundles must be
            # complete and independently verified before retention can delete.
            validate_report(report, name, scope)
        except (ValueError, TypeError):
            continue
        checksum = hashlib.sha256((report['sha256'] + '  ' + name + '\n').encode()).hexdigest()
        if remote.hash(name) != report['sha256'] or remote.hash(name + '.sha256') != checksum:
            continue
        with guard():
            for suffix in SIDECARS:
                remote.remove(name + suffix)
        removed.append(name)
    return removed


def validate_create_status(row, today):
    """Include failures before SQL/credentials could reach the bundle marker."""
    if row is None:
        return
    require(isinstance(row, dict) and row.get('status') in ('running', 'failed', 'succeeded'),
            'latest_create_status_invalid')
    started = report_time(row.get('started_at_utc'))
    if started.astimezone(ZONE).date() == today:
        require(row['status'] == 'succeeded',
                'latest_create_failed' if row['status'] == 'failed' else 'latest_create_incomplete')


def upload(connection, scope, today, directory=DIRECTORY, remote_factory=DumpFTP, create_status=None):
    validate_create_status(create_status, today)
    with operation_lock(directory, scope, readonly=True):
        return upload_latest(connection, scope, today, directory, remote_factory)


def upload_latest(connection, scope, today, directory, remote_factory):
    bundle = latest_verified(directory, scope, today)
    name = bundle['filename']
    snapshot = remote_settings(connection)
    destination = dict(snapshot['destination'])
    secret = recovery.decrypt_destination(destination)
    remote = remote_factory(destination, secret)
    guard = lambda: upload_guard(connection, snapshot)
    try:
        remote.enter_directory(snapshot['settings']['db_dump_directory'])
        for suffix in SIDECARS:
            path = directory / (name + suffix)
            metadata = checked_file(path)
            deliver(remote, path, path.name, metadata['sha256'], guard)
        # Even a resumed upload rechecks current authorization/settings.
        with guard():
            for suffix in SIDECARS:
                path = directory / (name + suffix)
                require(remote.hash(path.name) == checked_file(path)['sha256'], 'remote_hash_mismatch')
        removed = prune_remote(remote, scope, today, guard)
    finally:
        remote.close()
    return {'filename': name, 'sha256': bundle['sha256'], 'bytes': bundle['bytes'],
            'snapshot_at_utc': bundle['report'].get('snapshot_at_utc'),
            'destination_id': destination['id'], 'remote_directory': snapshot['remote_directory'],
            'readback_sha256_verified': True, 'removed_remote': removed}


def read_status():
    try:
        path = STATE / 'status.json'
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) and value.get('schema') == SCHEMA else {}
    except (OSError, ValueError):
        return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--create', action='store_true')
    action.add_argument('--upload', action='store_true')
    args = parser.parse_args()
    if not args.create and not args.upload:
        print(json.dumps({'mode': 'read-only-plan', 'create_time': '23:00 Europe/Istanbul',
                          'upload_time': '23:35 Europe/Istanbul', 'retained_calendar_days': 7,
                          'directory': str(DIRECTORY), 'configuration_only': True}))
        return 0
    require(os.geteuid() == 0, 'root_required')
    os.umask(0o077)
    safe_directory(STATE, 0o750, grp.getgrnam('fls-web').gr_gid)
    with (STATE / 'worker.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'ok': False, 'code': 'worker_busy'}))
            return 1
        state = read_status()
        kind = 'create' if args.create else 'upload'
        stamp = dt.datetime.now(dt.timezone.utc).isoformat()
        state.update({'schema': SCHEMA, 'timezone': 'Europe/Istanbul', 'retained_calendar_days': 7,
                      'create_time': '23:00', 'upload_time': '23:35'})
        state[kind] = {'status': 'running', 'started_at_utc': stamp}
        atomic_json(STATE / 'status.json', state, 0o640, grp.getgrnam('fls-web').gr_gid)
        connection = None
        try:
            assert_storage()
            credential_path = (Path(os.environ['CREDENTIALS_DIRECTORY']) / 'database'
                               if os.environ.get('CREDENTIALS_DIRECTORY') else CREDENTIAL)
            credential = read_credential(credential_path)
            connection = connect(credential)
            scope = instance_scope()
            today = dt.datetime.now(ZONE).date()
            result = create(connection, credential, scope, today) if args.create else upload(
                connection, scope, today, create_status=state.get('create'))
            state[kind].update({'status': 'succeeded', 'completed_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                                **{key: value for key, value in result.items() if key != 'report'}})
            code = 0
        except Exception as exc:
            error = str(exc) if isinstance(exc, (DumpError, backup.BackupError, recovery.BackupJobError)) else 'db_dump_failed'
            if re.fullmatch(r'[a-z0-9_]{1,64}', error) is None:
                error = 'db_dump_failed'
            state[kind].update({'status': 'failed', 'completed_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                                'error_code': error})
            code = 1
        finally:
            if connection is not None:
                connection.close()
        atomic_json(STATE / 'status.json', state, 0o640, grp.getgrnam('fls-web').gr_gid)
        print(json.dumps({'ok': code == 0, 'action': kind, 'status': state[kind]['status'],
                          'error_code': state[kind].get('error_code', '')}))
        return code


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'ok': False, 'error_code': 'db_dump_worker_unavailable'}))
        raise SystemExit(1)
