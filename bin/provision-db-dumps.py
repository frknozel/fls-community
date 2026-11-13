#!/usr/bin/python3
"""Provision daily config-only dumps; default is a read-only plan."""
import argparse
import grp
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess

import pymysql

USER = 'fls_db_dump'
CREDENTIAL = Path('/etc/fls/db-dump.json')
STATE = Path('/var/lib/fls-db-dump')
UNITS = ('fls-db-dump.service', 'fls-db-dump.timer',
         'fls-db-dump-upload.service', 'fls-db-dump-upload.timer')


def configure_role(cursor, password):
    cursor.execute('CREATE USER IF NOT EXISTS fls_db_dump@localhost IDENTIFIED BY %s', (password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM fls_db_dump@localhost')
    # DDL, views and triggers must survive future schema changes. No grant permits
    # changing production FLS rows. UPDATE(id) is only for the shared lock row.
    cursor.execute('GRANT SELECT,SHOW VIEW,TRIGGER ON fls.* TO fls_db_dump@localhost')
    cursor.execute('GRANT UPDATE(id) ON fls.management_lock TO fls_db_dump@localhost')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--start', action='store_true')
    args = parser.parse_args()
    if args.start and not args.apply:
        parser.error('--start requires --apply')
    if not args.apply:
        print(json.dumps({'applied': False, 'sql_user': USER, 'units': UNITS,
                          'create_time': '23:00 Europe/Istanbul', 'upload_time': '23:35 Europe/Istanbul',
                          'retained_calendar_days': 7, 'backup_created': False, 'upload_started': False}))
        return 0
    if os.geteuid() != 0:
        raise ValueError('root_required')
    os.umask(0o077)
    source = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('fls_db_dump_worker', source / 'bin/db-dump-worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    worker.assert_storage()
    parent = CREDENTIAL.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError('credential_parent')
    existing = CREDENTIAL.exists() or CREDENTIAL.is_symlink()
    config = worker.read_credential(CREDENTIAL) if existing else {'user': USER, 'password': secrets.token_urlsafe(36)}
    if existing and stat.S_IMODE(CREDENTIAL.lstat().st_mode) != 0o600:
        raise ValueError('credential_permissions')
    connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', database='fls', autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='fls'")
            if cursor.fetchone()[0]:
                raise ValueError('unsupported_stored_routines')
            cursor.execute("SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='fls'")
            if cursor.fetchone()[0]:
                raise ValueError('unsupported_scheduled_sql_events')
            cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User=%s AND Host='localhost'", (USER,))
            account_exists = bool(cursor.fetchone()[0])
            if account_exists and not existing:
                raise ValueError('existing_account_without_credential')
            if account_exists:
                login = worker.connect(config)
                login.close()
            configure_role(cursor, config['password'])
        if not existing:
            descriptor = os.open(CREDENTIAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(config, stream)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        connection.close()
    gid = grp.getgrnam('fls-web').gr_gid
    if not STATE.exists():
        STATE.mkdir(mode=0o750)
        os.chown(STATE, 0, gid)
        STATE.chmod(0o750)
    worker.safe_directory(STATE, 0o750, gid)
    for unit in UNITS:
        target = Path('/etc/systemd/system') / unit
        if target.is_symlink():
            raise ValueError('unit_symlink')
        subprocess.run(['install', '-o', 'root', '-g', 'root', '-m', '0644',
                        str(source / 'deploy' / unit), str(target)], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if args.start:
        subprocess.run(['systemctl', 'enable', '--now', 'fls-db-dump.timer', 'fls-db-dump-upload.timer'], check=True)
    print(json.dumps({'applied': True, 'timers_started': args.start,
                      'backup_created': False, 'upload_started': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'error_code': 'db_dump_provision_failed'}))
        raise SystemExit(1)
