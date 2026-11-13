#!/usr/bin/python3
"""Install fixed-role administrator disk management; default is a read-only plan."""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import stat
import subprocess
import pymysql

USER = 'fls_disks'
CREDENTIAL = Path('/etc/fls/disk-management.json')
STATE = Path('/var/lib/fls-disks')
UNITS = ('fls-disk-management.service', 'fls-disk-management.timer')
PAUSE_MARKER = Path('/var/lib/fls-maintenance/paused')
MIRROR_CONFIG = Path('/etc/fls/mirror.json')
MIRROR_UNIT = Path('/etc/systemd/system/srv-fls\\x2dmirror.mount')
MIRROR_TARGET = Path('/srv/fls-mirror')
MOUNTINFO = Path('/proc/self/mountinfo')
RECOVERY_EMPTY_TABLES = ('disk_management_jobs', 'events', 'source_files', 'archive_manifests',
    'archive_packages', 'archive_event_index', 'archive_dimensions', 'allowed_event_index',
    'allowed_dimensions', 'mail_search_events', 'system_backup_jobs', 'archive_deliveries',
    'timestamp_attempts', 'timestamp_stamps', 'timestamp_deliveries')
INTENT_COLUMNS = ('request_key','action','requested_by_uid','requested_session_version',
    'requested_by','requested_at','expires_at','boot_id','disk_wwn','disk_serial',
    'disk_size_bytes','inventory_token','config_revision','confirmed')


def configure_role(cursor, password):
    cursor.execute('CREATE USER IF NOT EXISTS fls_disks@localhost IDENTIFIED BY %s', (password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM fls_disks@localhost')
    cursor.execute('GRANT SELECT,UPDATE ON fls.disk_management_state TO fls_disks@localhost')
    cursor.execute('GRANT SELECT,UPDATE ON fls.disk_management_jobs TO fls_disks@localhost')
    cursor.execute('GRANT SELECT,UPDATE(id) ON fls.management_lock TO fls_disks@localhost')
    cursor.execute('GRANT SELECT(id,role,enabled,must_change,session_version) ON fls.users TO fls_disks@localhost')
    cursor.execute('GRANT SELECT(id,name,inode,byte_offset,line_number,observed_size,invalid_rows),UPDATE(inode) ON fls.source_files TO fls_disks@localhost')
    for table in ('summary_backlog_history_state','mail_search_backlog_history_state'):
        cursor.execute('GRANT SELECT(id,cursor_file,cursor_inode,cursor_offset),UPDATE(cursor_inode) ON fls.' + table + ' TO fls_disks@localhost')
    cursor.execute('GRANT SELECT(status),UPDATE(status,progress_bytes,error_code,verification_started_at) ON fls.archive_integrity_checks TO fls_disks@localhost')
    cursor.execute('GRANT SELECT ON fls.disk_management_state TO fls_app@localhost')
    cursor.execute('GRANT SELECT ON fls.disk_management_jobs TO fls_app@localhost')
    cursor.execute('GRANT INSERT('+','.join(INTENT_COLUMNS)+') ON fls.disk_management_jobs TO fls_app@localhost')


def require_empty_state(folder):
    if folder.exists() or folder.is_symlink():
        info = folder.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700 or folder.resolve(strict=True) != folder
                or next(folder.iterdir(), None) is not None):
            raise ValueError('recovery_state_not_empty')
    else:
        info = folder.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or folder.parent.resolve(strict=True) != folder.parent):
            raise ValueError('state_parent_unsafe')


def recovery_host_guard(runner=None):
    runner = subprocess.run if runner is None else runner
    marker = PAUSE_MARKER.lstat()
    parent = PAUSE_MARKER.parent.lstat()
    if (not stat.S_ISREG(marker.st_mode) or marker.st_uid != 0 or marker.st_nlink != 1
            or stat.S_IMODE(marker.st_mode) != 0o600 or marker.st_size > 512
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) != 0o700
            or PAUSE_MARKER.resolve(strict=True) != PAUSE_MARKER):
        raise ValueError('recovery_pause_marker_unsafe')
    for path in (MIRROR_CONFIG, MIRROR_UNIT):
        if path.exists() or path.is_symlink():
            raise ValueError('recovery_mirror_configuration_present')
    if (MIRROR_TARGET.is_symlink() or os.path.ismount(MIRROR_TARGET)
            or any(len(fields) > 4 and fields[4] == str(MIRROR_TARGET)
                   for fields in (line.split() for line in MOUNTINFO.read_text().splitlines()))):
        raise ValueError('recovery_mirror_mount_present')
    for unit in (*UNITS, 'fortigate-collector.service'):
        result = runner(['/usr/bin/systemctl', 'show', unit,
                         '--property=LoadState,ActiveState,MainPID', '--no-pager'],
                        capture_output=True, text=True, timeout=10)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        absent = values.get('LoadState') == 'not-found'
        # Timers have no MainPID property; their ActiveState must still be idle.
        if ((result.returncode and not (absent and result.returncode == 1))
                or values.get('ActiveState') not in ('inactive', 'failed')
                or (unit.endswith('.service') and values.get('MainPID', '0' if absent else None) != '0')):
            raise ValueError('recovery_service_running')


def create_exclusive_json(folder, name, value):
    # Never replace an existing replay record, even if another root process
    # creates one after the empty-folder check. Partial writes remain blocked.
    parent = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'w') as output:
            os.fchmod(output.fileno(), 0o600)
            os.fchown(output.fileno(), 0, 0)
            output.write(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def initialize_recovery_state(connection, worker, *, runner=None, folder=None):
    """New logs-free recovery only; deliberately cannot repair partial/live state."""
    folder = Path(folder) if folder is not None else STATE
    recovery_host_guard(runner)
    require_empty_state(folder)
    connection.begin()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute('SELECT id FROM management_lock WHERE id=1 FOR UPDATE')
            if cursor.fetchone() != {'id': 1}:
                raise ValueError('recovery_management_lock_missing')
            cursor.execute('SELECT * FROM disk_management_state WHERE id=1 FOR UPDATE')
            state = cursor.fetchone()
            expected = {'id': 1, 'version': 1, 'boot_id': '', 'checked_at': None, 'status': 'idle',
                        'inventory_json': None, 'config_revision': 0, 'error_code': ''}
            if state != expected:
                raise ValueError('recovery_disk_state_not_pristine')
            cursor.execute('SELECT requested_mode,revision,requested_by FROM maintenance_requests WHERE id=1 FOR UPDATE')
            if cursor.fetchone() != {'requested_mode': 'paused', 'revision': 1,
                                     'requested_by': 'system-backup-restore'}:
                raise ValueError('recovery_maintenance_not_paused')
            for table in RECOVERY_EMPTY_TABLES:
                cursor.execute('SELECT 1 AS present FROM ' + table + ' LIMIT 1 FOR UPDATE')
                if cursor.fetchone() is not None:
                    raise ValueError('recovery_database_not_empty')
            recovery_host_guard(runner)
            require_empty_state(folder)
            if not folder.exists():
                folder.mkdir(mode=0o700)
            require_empty_state(folder)
            create_exclusive_json(folder, 'attempt.json', {'schema': 1, 'high_water': 0, 'last': None})
            create_exclusive_json(folder, 'token-key.json', {'key': secrets.token_hex(32)})
            worker.Journal(folder=folder).read()
            key = worker.safe_json(folder / 'token-key.json', 1024)
            if set(key) != {'key'} or not isinstance(key['key'], str) or not re.fullmatch('[0-9a-f]{64}', key['key']):
                raise ValueError('recovery_token_key_invalid')
        connection.commit()
    except Exception:
        connection.rollback()
        # No automatic unlink/rollback: a partial root journal is evidence.
        raise
    return {'recovery_state_initialized': True, 'journal_high_water': 0,
            'timer_started': False, 'disk_formatted': False, 'mirror_configured': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--start', action='store_true')
    parser.add_argument('--initialize-recovery-state', action='store_true',
                        help='Create new replay state only on a pristine, paused recovery host; never resets existing files')
    args = parser.parse_args()
    if args.start and not args.apply:
        parser.error('--start requires --apply')
    if args.start and args.initialize_recovery_state:
        parser.error('--initialize-recovery-state cannot start services')
    if not args.apply:
        print(json.dumps({'applied': False, 'sql_user': USER, 'units': UNITS,
                          'disk_formatted': False, 'mirror_configured': False,
                          'initialize_recovery_state': args.initialize_recovery_state}))
        return 0
    if os.geteuid() != 0:
        raise ValueError('root_required')
    os.umask(0o077)
    source = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('fls_disk_worker', source/'bin/disk-management-worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    parent = CREDENTIAL.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError('credential_parent')
    existing = CREDENTIAL.exists() or CREDENTIAL.is_symlink()
    credential = worker.read_credential(CREDENTIAL) if existing else {'user': USER, 'password': secrets.token_urlsafe(36)}
    if args.initialize_recovery_state:
        if not existing:
            raise ValueError('recovery_credential_required')
        login = worker.connect(credential)
        login.close()
        connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', database='fls', user='root', autocommit=True)
        try:
            result = initialize_recovery_state(connection, worker)
        finally:
            connection.close()
        print(json.dumps({'applied': True, **result}))
        return 0
    if not STATE.exists():
        STATE.mkdir(mode=0o700)
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('state_directory_unsafe')
    if not existing:
        require_empty_state(STATE)
    connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', database='fls', user='root', autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User=%s AND Host='localhost'", (USER,))
            if cursor.fetchone()[0] and not existing:
                raise ValueError('existing_account_without_credential')
            if existing:
                login = worker.connect(credential)
                login.close()
            sql = '\n'.join(line for line in (source/'migrations/046-disk-management.sql').read_text().splitlines() if not line.lstrip().startswith('--'))
            for statement in sql.split(';'):
                if statement.strip():
                    cursor.execute(statement)
            sql = '\n'.join(line for line in (source/'migrations/047-primary-storage.sql').read_text().splitlines() if not line.lstrip().startswith('--'))
            for statement in sql.split(';'):
                if statement.strip():
                    cursor.execute(statement)
            cursor.execute('SELECT COUNT(*) FROM disk_management_jobs')
            if cursor.fetchone()[0] and not existing:
                raise ValueError('existing_jobs_without_journal')
            if existing:
                worker.Journal().read()
                worker.safe_json(STATE/'token-key.json')
            else:
                if (STATE/'attempt.json').exists() or (STATE/'attempt.json').is_symlink():
                    raise ValueError('existing_journal_without_credential')
                worker.atomic(STATE/'attempt.json', {'schema': 1, 'high_water': 0, 'last': None})
                worker.atomic(STATE/'token-key.json', {'key': secrets.token_hex(32)})
                worker.atomic(CREDENTIAL, credential)
            configure_role(cursor, credential['password'])
    finally:
        connection.close()
    for unit in UNITS:
        target = Path('/etc/systemd/system')/unit
        if target.is_symlink():
            raise ValueError('unit_symlink')
        subprocess.run(['install','-o','root','-g','root','-m','0644',str(source/'deploy'/unit),str(target)],check=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    if args.start:
        subprocess.run(['systemctl','enable','--now','fls-disk-management.timer'],check=True)
    print(json.dumps({'applied':True,'timer_started':args.start,'disk_formatted':False,'mirror_configured':False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'error_code':'disk_management_provision_failed'}))
        raise SystemExit(1)
