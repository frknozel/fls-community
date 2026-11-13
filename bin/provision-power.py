#!/usr/bin/python3
"""Install narrowly scoped host power control. The default is a read-only plan."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

import pymysql

SQL_USER = 'fls_power'
CREDENTIAL = Path('/etc/fls/power-database.json')
UNITS = ('fls-power.service', 'fls-power.timer')


def configure_role(cursor, password, database='fls', user=SQL_USER, app_user='fls_app'):
    if not all(re.fullmatch(r'[A-Za-z0-9_]+', name) for name in (database, user, app_user)):
        raise ValueError('sql_identity')
    if not isinstance(password, str) or not 16 <= len(password) <= 512:
        raise ValueError('credential_password')
    cursor.execute('CREATE USER IF NOT EXISTS '+user+'@localhost IDENTIFIED BY %s', (password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM '+user+'@localhost')
    cursor.execute('GRANT SELECT ON '+database+'.power_requests TO '+user+'@localhost')
    cursor.execute('GRANT SELECT,UPDATE ON '+database+'.power_state TO '+user+'@localhost')
    cursor.execute('GRANT SELECT(id,role,enabled,session_version) ON '+database+'.users TO '+user+'@localhost')
    for table in ('power_requests', 'power_state'):
        cursor.execute('GRANT SELECT ON '+database+'.'+table+' TO '+app_user+'@localhost')
    cursor.execute('GRANT UPDATE ON '+database+'.power_requests TO '+app_user+'@localhost')


def read_config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 16384:
            raise ValueError('credential_permissions')
        value = json.loads(stream.read(16385))
    if not isinstance(value, dict) or set(value) != {'user', 'password'} or value['user'] != SQL_USER or not isinstance(value['password'], str) or not 16 <= len(value['password']) <= 512:
        raise ValueError('credential_identity')
    return value


def write_new(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--start', action='store_true')
    args = parser.parse_args()
    if args.start and not args.apply:
        parser.error('--start requires --apply')
    if not args.apply:
        print(json.dumps({'applied': False, 'sql_user': SQL_USER, 'units': UNITS, 'power_command_executed': False, 'services_started': False}))
        return
    if os.geteuid() != 0:
        raise SystemExit('Root required for --apply')
    parent = CREDENTIAL.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError('credential_parent')
    existing = CREDENTIAL.exists() or CREDENTIAL.is_symlink()
    config = read_config(CREDENTIAL) if existing else {'user': SQL_USER, 'password': secrets.token_urlsafe(36)}
    source = Path(__file__).resolve().parents[1]
    db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', database='fls', autocommit=True, charset='utf8mb4')
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User=%s AND Host='localhost'", (SQL_USER,))
            account_exists = bool(cursor.fetchone()[0])
            if account_exists and not existing:
                raise ValueError('existing_sql_account_without_credential')
            if account_exists:
                check = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user=SQL_USER, password=config['password'])
                check.close()
            migration = (source / 'migrations/044-system-power.sql').read_text()
            for statement in '\n'.join(line for line in migration.splitlines() if not line.lstrip().startswith('--')).split(';'):
                if statement.strip():
                    cursor.execute(statement)
            configure_role(cursor, config['password'])
            if args.start:
                # Provisioning must never execute a queued host action.
                cursor.execute("SELECT COUNT(*) FROM power_requests r JOIN power_state s ON s.id=r.id WHERE r.revision>s.attempted_revision AND r.action<>'' AND r.expires_at>UTC_TIMESTAMP(6)")
                if cursor.fetchone()[0]:
                    raise ValueError('active_power_request')
        if not existing:
            write_new(CREDENTIAL, (json.dumps(config)+'\n').encode())
    finally:
        db.close()
    for name in UNITS:
        destination = Path('/etc/systemd/system') / name
        if destination.is_symlink():
            raise ValueError('unit_symlink')
        subprocess.run(['install', '-o', 'root', '-g', 'root', '-m', '0644', str(source / 'deploy' / name), str(destination)], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if args.start:
        subprocess.run(['systemctl', 'start', 'fls-power.service'], check=True)
        subprocess.run(['systemctl', 'enable', '--now', 'fls-power.timer'], check=True)
    print(json.dumps({'applied': True, 'sql_user': SQL_USER, 'timer_started': args.start, 'power_request_created': False}))


if __name__ == '__main__':
    main()
