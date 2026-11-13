#!/usr/bin/python3
"""Install only explicit system backup job control; default is a read-only plan."""
import argparse
import grp
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

import pymysql

USER = 'fls_system_backup'
CREDENTIAL = Path('/etc/fls/system-backup.json')
STATE = Path('/var/lib/fls-backup-worker')
PUBLISHED = Path('/var/lib/fls-recovery-download')
UNITS = ('fls-system-backup.service', 'fls-system-backup.timer')


def configure_role(cursor, password, database='fls', user=USER, app_user='fls_app'):
    if not all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_]+', name)
               for name in (database, user, app_user)):
        raise ValueError('sql_identity')
    if not isinstance(password, str) or not 16 <= len(password) <= 512:
        raise ValueError('credential_password')
    cursor.execute('CREATE USER IF NOT EXISTS ' + user + '@localhost IDENTIFIED BY %s', (password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM ' + user + '@localhost')
    for table, privileges in (
        ('system_backup_settings', 'SELECT'), ('system_backup_jobs', 'SELECT,UPDATE'),
        ('system_backups', 'SELECT,INSERT,UPDATE'), ('system_backup_worker', 'SELECT,UPDATE'),
        ('archive_destinations', 'SELECT'),
    ):
        cursor.execute('GRANT ' + privileges + ' ON ' + database + '.' + table + ' TO ' + user + '@localhost')
    cursor.execute('GRANT SELECT,UPDATE(id) ON ' + database + '.management_lock TO ' + user + '@localhost')
    cursor.execute('GRANT SELECT(id,username,role,enabled,session_version,must_change) ON ' + database + '.users TO ' + user + '@localhost')
    for table in ('system_backup_settings', 'system_backups', 'system_backup_jobs', 'system_backup_worker'):
        cursor.execute('GRANT SELECT ON ' + database + '.' + table + ' TO ' + app_user + '@localhost')
    cursor.execute('GRANT UPDATE ON ' + database + '.system_backup_settings TO ' + app_user + '@localhost')
    cursor.execute('GRANT INSERT ON ' + database + '.system_backup_jobs TO ' + app_user + '@localhost')


def new_credential(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def directory(path, mode, gid=0):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
        os.chown(path, 0, gid)
        path.chmod(mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError('directory_permissions')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--start', action='store_true')
    args = parser.parse_args()
    if args.start and not args.apply:
        parser.error('--start requires --apply')
    if not args.apply:
        print(json.dumps({'applied': False, 'sql_user': USER, 'units': UNITS,
                          'automatic_backups': False, 'services_started': False}))
        return 0
    if os.geteuid() != 0:
        raise ValueError('root_required')
    os.umask(0o077)
    source = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('fls_system_backup_worker', source / 'bin/system-backup-worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    info = CREDENTIAL.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('credential_parent')
    existing = CREDENTIAL.exists() or CREDENTIAL.is_symlink()
    config = worker.read_config(CREDENTIAL) if existing else {'user': USER, 'password': secrets.token_urlsafe(36)}
    # Stored credentials require the tighter on-disk mode, even though the
    # worker also accepts systemd's read-only credential mount mode.
    if existing and stat.S_IMODE(CREDENTIAL.lstat().st_mode) != 0o600:
        raise ValueError('credential_permissions')
    connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                                 database='fls', autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User=%s AND Host='localhost'", (USER,))
            account_exists = bool(cursor.fetchone()[0])
            if account_exists and not existing:
                raise ValueError('existing_account_without_credential')
            if account_exists:
                login = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',
                                        user=USER, password=config['password'])
                login.close()
            migration = source / 'migrations/045-system-backups.sql'
            sql = '\n'.join(line for line in migration.read_text().splitlines()
                            if not line.lstrip().startswith('--'))
            for statement in sql.split(';'):
                if statement.strip():
                    cursor.execute(statement)
            configure_role(cursor, config['password'])
        if not existing:
            new_credential(CREDENTIAL, config)
    finally:
        connection.close()
    directory(STATE, 0o700)
    directory(PUBLISHED, 0o750, grp.getgrnam('fls-web').gr_gid)
    for unit in UNITS:
        target = Path('/etc/systemd/system') / unit
        if target.is_symlink():
            raise ValueError('unit_symlink')
        subprocess.run(['install', '-o', 'root', '-g', 'root', '-m', '0644',
                        str(source / 'deploy' / unit), str(target)], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if args.start:
        subprocess.run(['systemctl', 'enable', '--now', 'fls-system-backup.timer'], check=True)
    print(json.dumps({'applied': True, 'timer_started': args.start,
                      'backup_requested': False, 'upload_requested': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'error_code': 'system_backup_provision_failed'}))
        raise SystemExit(1)
