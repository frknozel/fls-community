#!/usr/bin/python3
"""Create and independently restore-check a private, log-free FLS recovery backup.

Without --create this command only prints its fixed scope. It never changes the
production database, service state, or application settings. The original SQL
preserves configuration exactly; restore-safe.sql is a separate recovery step.
"""
import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import grp
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import traceback


CONFIG_TABLES = (
    'users', 'user_preferences', 'user_event_columns', 'user_event_views',
    'user_fortigate_preferences', 'user_fortigate_access', 'user_archive_tls_views',
    'fortigate_connections', 'fortigate_credentials', 'fortigate_setup',
    'summary_backlog_settings', 'mail_search_backlog_settings',
    'archive_tls_settings', 'archive_export_settings', 'archive_destinations',
    'timestamp_profiles', 'timestamp_settings', 'retention_settings',
    'retention_policy_versions', 'system_backup_settings',
)
SEED_TABLES = (
    'management_lock', 'archive_index_state', 'allowed_index_state',
    'mail_search_state', 'summary_backlog_history_state',
    'mail_search_backlog_history_state', 'archive_tls_history_state',
    'archive_integrity_worker', 'maintenance_requests', 'maintenance_state',
    'power_requests', 'power_state', 'system_backup_worker', 'disk_management_state',
)
SOURCE = Path('/var/www/fls')
DESTINATION = Path('/srv/fls-server/backups')
FIXED_PATHS = (
    'var/www/fls', 'etc/fls', 'etc/nginx', 'etc/php/8.3/fpm',
    'etc/php/8.3/mods-available', 'etc/mysql', 'etc/alternatives/my.cnf',
    'etc/fortigate', 'opt/fortigate', 'opt/fls-tsa', 'usr/lib/fls',
    'usr/local/share/ca-certificates', 'etc/nftables.conf', 'etc/hosts',
    'etc/hostname', 'etc/fstab', 'etc/netplan', 'etc/timezone', 'etc/localtime',
    'etc/systemd/timesyncd.conf', 'etc/systemd/timesyncd.conf.d',
    'etc/chrony', 'etc/apt/sources.list', 'etc/apt/sources.list.d',
    'etc/apt/keyrings', 'etc/apt/trusted.gpg.d', 'usr/share/keyrings',
    'etc/apparmor.d', 'etc/lvm/lvm.conf', 'etc/lvm/lvmlocal.conf',
    'etc/lvm/backup', 'etc/sysctl.conf', 'etc/sysctl.d',
)
LICENSE_FILES = ()
HDD_BIND_UNITS = (
    r'srv-fls\x2dserver-raw.mount', r'srv-fls\x2dserver-archive.mount',
    r'srv-fls\x2dserver-queue.mount', r'srv-fls\x2dserver-metrics.mount',
    r'srv-fls\x2dserver-backups.mount', r'srv-fls\x2dserver-db\x2ddumps.mount',
    r'var-lib-fls\x2drecovery\x2ddownload.mount',
    r'srv-fls\x2dmirror.mount',
)
HDD_DEPOT_UNIT = r'srv-fls\x2dstorage.mount'
HDD_DEVICE_DROPIN = 'etc/systemd/system/' + HDD_DEPOT_UNIT + '.d/device-bound.conf'
REQUIRED_FILES = (
    'etc/fls/credential-key', 'etc/fls/private/archive-ed25519.pem',
    'etc/fls/cold-signing-key.pem', 'etc/fls/cold-public-key.pem',
    'var/www/fls/public/archive-public-key.pem',
    'usr/lib/fls/fls-archive-hash',
    'opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd',
    'etc/nginx/fls-tls/server.crt', 'etc/nginx/fls-tls/server.key',
    'etc/nginx/fls-tls/ca.crt', 'etc/nginx/fls-tls/ca.key',
)
EXCLUDED_PARTS = {'__pycache__', '.pytest_cache', '.mypy_cache', 'node_modules'}
EXCLUDED_SUFFIXES = ('.pyc', '.log', '.jsonl', '.sqlite', '.sqlite3')
RESTORE_SQL = """-- Apply only to the newly restored recovery database, before starting workers.
-- Original configuration rows remain available in database.sql.gz.
SET NAMES utf8mb4;
START TRANSACTION;
INSERT INTO management_lock(id) VALUES(1);
INSERT INTO archive_index_state(id,version,event_id,ready,updated_at)
 VALUES(1,3,0,0,UTC_TIMESTAMP(6));
INSERT INTO allowed_index_state(id,version,event_id,scanned_records,ready,updated_at)
 VALUES(1,1,0,0,0,UTC_TIMESTAMP(6));
INSERT INTO mail_search_state(id,version) VALUES(1,1);
INSERT INTO summary_backlog_history_state(id) VALUES(1);
INSERT INTO mail_search_backlog_history_state(id) VALUES(1);
INSERT INTO archive_tls_history_state(id) VALUES(1);
INSERT INTO archive_integrity_worker(id) VALUES(1);
INSERT INTO maintenance_requests(id,requested_mode,revision,requested_at,requested_by)
 VALUES(1,'paused',1,UTC_TIMESTAMP(6),'system-backup-restore');
INSERT INTO maintenance_state(id) VALUES(1);
INSERT INTO power_requests(id) VALUES(1);
INSERT INTO power_state(id) VALUES(1);
INSERT INTO system_backup_worker(id) VALUES(1);
INSERT INTO disk_management_state(id) VALUES(1);
UPDATE timestamp_settings SET enabled=0,start_manifest_id=0,scope_started_at=NULL;
UPDATE archive_export_settings SET packaging_enabled=0;
UPDATE timestamp_profiles SET check_status='untested',check_code='',
 checked_revision=NULL,checked_at=NULL,test_requested_at=NULL,
 balance_requested_at=NULL,balance_status='unknown',balance=NULL,balance_at=NULL,
 balance_attempted_at=NULL,balance_basis_attempt_id=0;
UPDATE archive_destinations SET enabled=0,start_manifest_id=1,
 test_requested_at=NULL,checked_at=NULL,checked_revision=NULL,
 check_status='untested',check_code='',observed_host_key='',
 tls_peer_pem='',tls_peer_revision=NULL,tls_peer_checked_at=NULL,
 tls_peer_verified_at=NULL,tls_peer_check_code='';
UPDATE fortigate_credentials SET test_requested_at=NULL,checked_at=NULL,
 checked_revision=NULL,check_status='untested',check_code='',last_used_at=NULL;
UPDATE fortigate_setup SET baseline_event_id=0,test_started_at=UTC_TIMESTAMP(6);
COMMIT;
"""


class BackupError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise BackupError(code)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def json_default(value):
    if isinstance(value, bytes):
        return {'base64': base64.b64encode(value).decode('ascii')}
    return str(value)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    default=json_default, indent=2) + '\n')
    Path(path).chmod(0o600)


def run(command, *, stderr, **kwargs):
    result = subprocess.run(command, stderr=stderr, check=False, **kwargs)
    require(result.returncode == 0, 'command_failed_' + Path(command[0]).name)
    return result


def capture(command, stderr):
    return run(command, stderr=stderr, stdout=subprocess.PIPE).stdout


def query(connection, statement, arguments=()):
    with connection.cursor() as cursor:
        cursor.execute(statement, arguments)
        return cursor.fetchall()


def identifier(value):
    require(bool(re.fullmatch(r'[A-Za-z0-9_]+', value)), 'invalid_identifier')
    return '`' + value + '`'


def configuration_rows_digest(rows):
    encoded = sorted(json.dumps(row, sort_keys=True, default=json_default,
                                ensure_ascii=False) for row in rows)
    return {'rows': len(rows), 'sha256': hashlib.sha256(
        json.dumps(encoded, ensure_ascii=False).encode()).hexdigest()}


def configuration_snapshot(connection):
    exact, source_guard = {}, {}
    for table in CONFIG_TABLES:
        rows = query(connection, 'SELECT * FROM fls.' + identifier(table))
        exact[table] = configuration_rows_digest(rows)
        # Both baselines must describe the same rows. A second credential read
        # could capture a different revision which later passes an ABA change.
        if table == 'fortigate_credentials':
            rows = [{name: value for name, value in row.items() if name != 'last_used_at'}
                    for row in rows]
            source_guard[table] = configuration_rows_digest(rows)
        else:
            source_guard[table] = exact[table]
    return exact, source_guard


def configuration_digest(connection):
    return configuration_snapshot(connection)[0]


def configuration_source_guard(connection):
    # The SQL snapshot and its independent restore still compare every field.
    # Only the longer file-copy window ignores this registry usage heartbeat;
    # credentials, revisions and all other configuration remain guarded.
    return configuration_snapshot(connection)[1]


def excluded(name):
    parts = PurePosixPath(name).parts
    return (bool(EXCLUDED_PARTS.intersection(parts))
            or name.endswith(EXCLUDED_SUFFIXES)
            or '/.git/logs/' in '/' + name + '/'
            or '/.git/hooks/' in '/' + name + '/')


def included_paths():
    paths = [name for name in FIXED_PATHS
             if Path('/' + name).exists() or Path('/' + name).is_symlink()]
    units = Path('/etc/systemd/system')
    for path in sorted(units.iterdir()):
        if path.name.startswith(('fls-', 'fortigate-')) or path.name in (
                'mariadb.service.d', 'php8.3-fpm.service.d', 'nginx.service.d',
                HDD_DEPOT_UNIT, *HDD_BIND_UNITS):
            paths.append(str(path).lstrip('/'))
    # Include this deployment's storage dependencies even when installed on a
    # consumer outside the usual FLS/PHP service-name allowlist. Do not collect
    # unrelated service configuration from those directories.
    for path in sorted(units.glob('*.service.d/hdd-depot.conf')):
        name = str(path).lstrip('/')
        if not any(name == root or name.startswith(root.rstrip('/') + '/')
                   for root in paths):
            paths.append(name)
    if Path('/' + HDD_DEVICE_DROPIN).is_file():
        paths.append(HDD_DEVICE_DROPIN)
    paths += [str(path).lstrip('/') for path in
              sorted(Path('/usr/local/libexec').glob('fortigate*.py'))]
    require(all(not name.startswith(('srv/', 'root/', 'var/log/')) for name in paths),
            'invalid_backup_scope')
    for name in REQUIRED_FILES:
        require(Path('/' + name).is_file(), 'required_file_missing_' + Path(name).name)
    return list(dict.fromkeys(paths))


def identity_inventory():
    users = [user for user in pwd.getpwall()
             if user.pw_name.startswith('fls') or user.pw_name in ('mysql', 'nginx', 'www-data', 'syslog')]
    names = {user.pw_name for user in users}
    gids = {user.pw_gid for user in users}
    groups = [group for group in grp.getgrall()
              if group.gr_gid in gids or group.gr_name in ('adm', 'fls-web')
              or names.intersection(group.gr_mem)]
    return {'users': [{'name': user.pw_name, 'uid': user.pw_uid, 'gid': user.pw_gid,
                       'home': user.pw_dir, 'shell': user.pw_shell} for user in users],
            'groups': [{'name': group.gr_name, 'gid': group.gr_gid,
                        'members': group.gr_mem} for group in groups]}


def database_accounts(connection, payload):
    accounts = query(connection,
                     "SELECT User,Host FROM mysql.user WHERE User REGEXP '^fls_' ORDER BY User,Host")
    accounts = [account for account in accounts if not account['User'].startswith('fls_qa_')]
    require(bool(accounts), 'database_accounts_missing')
    statements = []
    for account in accounts:
        values = (account['User'], account['Host'])
        statements.append(next(iter(query(connection, 'SHOW CREATE USER %s@%s', values)[0].values())) + ';')
        statements += [next(iter(row.values())) + ';' for row in
                       query(connection, 'SHOW GRANTS FOR %s@%s', values)]
    (payload / 'database-accounts.sql').write_text('\n'.join(statements) + '\n')
    names = {account['User'] for account in accounts}
    covered = []
    for path in sorted(Path('/etc/fls').glob('*.json')):
        value = json.loads(path.read_text())
        # fortigate-api.json is an API configuration, not a SQL credential.
        if isinstance(value, dict) and 'user' in value and 'password' in value:
            require(value['user'] in names, 'database_credential_account_missing')
            covered.append(path.name)
    require('app.json' in covered, 'application_database_credential_missing')
    return accounts, covered


def dump_database(connection, payload, inventory, tables, stderr):
    command = ['mariadb-dump', '--no-defaults', '--socket=/run/mysqld/mysqld.sock',
               '--user=root', '--single-transaction', '--quick', '--hex-blob',
               '--skip-lock-tables', '--skip-add-locks', '--routines', '--events',
               '--triggers', '--default-character-set=utf8mb4']
    command += ['--ignore-table-data=fls.' + table for table in sorted(tables)
                if table not in CONFIG_TABLES]
    command.append('fls')
    for attempt in range(3):
        before, source_guard = configuration_snapshot(connection)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr)
        try:
            with gzip.open(payload / 'database.sql.gz', 'wb', compresslevel=1) as output:
                shutil.copyfileobj(process.stdout, output, 1024 * 1024)
            process.stdout.close()
            require(process.wait() == 0, 'database_dump_failed')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        if before == configuration_digest(connection):
            write_json(inventory / 'configuration-digests.json', before)
            write_json(inventory / 'configuration-source-guard.json', source_guard)
            return before
    raise BackupError('configuration_changed_during_backup_retry')


def source_inventory(stderr):
    """Inventory an authenticated release tree without requiring Git history."""
    manifest_path = SOURCE / 'deploy/release-files.json'
    descriptor = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 2 * 1024 ** 2,
                'release_manifest_invalid')
        raw = stream.read(2 * 1024 ** 2 + 1)
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'release_manifest_duplicate_field')
            result[key] = value
        return result
    manifest = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'version', 'files'}
            and manifest['schema'] == 'fls-community-release-files-v1'
            and isinstance(manifest['version'], str)
            and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', manifest['version'])
            and isinstance(manifest['files'], list) and 0 < len(manifest['files']) <= 4096,
            'release_manifest_invalid')
    require((SOURCE / 'VERSION').read_text().strip() == manifest['version'],
            'release_version_mismatch')
    seen = set()
    for row in manifest['files']:
        require(isinstance(row, dict) and set(row) == {'path', 'sha256', 'mode'},
                'release_manifest_invalid')
        name = row['path']
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9._@+/-]+', name)
                and not name.startswith('/') and all(part not in ('', '.', '..', '.git') for part in name.split('/'))
                and name != 'deploy/release-files.json' and name not in seen
                and isinstance(row['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', row['sha256'])
                and type(row['mode']) is int and row['mode'] in (644, 755), 'release_manifest_invalid')
        seen.add(name); path = SOURCE / name
        require(path.resolve(strict=True) == path, 'release_file_redirected')
        details = path.lstat()
        require(stat.S_ISREG(details.st_mode) and stat.S_IMODE(details.st_mode) == int(str(row['mode']), 8)
                and sha(path) == row['sha256'], 'release_file_mismatch')
    generated = {'deploy/release-files.json', 'public/archive-public-key.pem'}
    actual = {str(path.relative_to(SOURCE)) for path in SOURCE.rglob('*')
              if path.is_file() and not excluded(str(path.relative_to(SOURCE)))}
    require(actual == seen | (actual & generated), 'release_inventory_mismatch')
    require(not any(path.is_symlink() for path in SOURCE.rglob('*')), 'release_file_redirected')
    return {'edition': 'community', 'release_version': manifest['version'],
            'release_manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'working_tree_included': True, 'git_history_included': False}


def build_system_tar(work, payload, inventory, paths, stderr):
    # License state is atomically published by its live worker. Copy individual
    # files into a private snapshot instead of including runtime locks/history.
    staging = work / 'state-snapshot'
    for name in LICENSE_FILES:
        original = Path('/' + name)
        if original.exists():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, target)
            info = original.stat()
            os.chown(target, info.st_uid, info.st_gid)
    pathlist = work / 'paths.list'
    pathlist.write_bytes(b'\0'.join(name.encode() for name in paths) + b'\0')
    command = ['tar', '--acls', '--xattrs', '--numeric-owner',
               '--exclude=__pycache__', '--exclude=.pytest_cache', '--exclude=.mypy_cache',
               '--exclude=node_modules', '--exclude=*.pyc', '--exclude=*.log',
               '--exclude=*.jsonl', '--exclude=*.sqlite', '--exclude=*.sqlite3',
               '--exclude=*/.git/logs', '--exclude=*/.git/hooks',
               '-cpf', str(payload / 'system.tar'), '-C', '/', '--null', '-T', str(pathlist)]
    if staging.exists():
        command += ['-C', str(staging)] + [name for name in LICENSE_FILES if (staging / name).exists()]
    run(command, stderr=stderr, stdout=subprocess.DEVNULL)
    with tarfile.open(payload / 'system.tar') as archive:
        mapping = {}
        for member in archive:
            name = member.name.removeprefix('./')
            require(not name.startswith('/') and '..' not in PurePosixPath(name).parts,
                    'unsafe_system_archive_path')
            require(not excluded(name), 'excluded_file_in_system_archive')
            require(any(name == root or name.startswith(root.rstrip('/') + '/')
                        for root in paths + list(LICENSE_FILES)), 'unexpected_system_archive_path')
            if member.isfile():
                mapping[name] = {'bytes': member.size,
                                 'sha256': hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()}
            else:
                require(member.isdir() or member.issym() or member.islnk(), 'unexpected_system_file_type')
        require(set(REQUIRED_FILES).issubset(mapping), 'required_archive_files_missing')
        # Prove all current non-runtime source files are present, including
        # untracked hotfix files rather than merely the last Git commit.
        for original in SOURCE.rglob('*'):
            name = str(original).lstrip('/')
            if excluded(name) or not original.is_file() or original.is_symlink():
                continue
            require(name in mapping and mapping[name]['sha256'] == sha(original),
                    'source_changed_or_source_file_missing')
    write_json(inventory / 'file-sha256.json', mapping)
    return mapping


def inventory_files(inventory, paths, stderr):
    (inventory / 'os-release.txt').write_text(Path('/etc/os-release').read_text())
    (inventory / 'uname.txt').write_bytes(capture(['uname', '-a'], stderr))
    (inventory / 'block-devices.json').write_bytes(capture(
        ['lsblk', '--json', '--bytes', '--output',
         'NAME,PATH,TYPE,SIZE,FSTYPE,UUID,PARTUUID,MOUNTPOINTS,MODEL,SERIAL'], stderr))
    (inventory / 'mounts.json').write_bytes(capture(['findmnt', '--json', '--real'], stderr))
    (inventory / 'included-paths.txt').write_text('\n'.join(paths + list(LICENSE_FILES)) + '\n')
    (inventory / 'packages.tsv').write_bytes(capture(
        ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n'], stderr))
    write_json(inventory / 'service-identities.json', identity_inventory())
    units = capture(['systemctl', 'list-unit-files', '--no-legend', '--no-pager'], stderr).decode()
    selected = [line for line in units.splitlines()
                if line.startswith(('fls-', 'fortigate-', 'mariadb.', 'nginx.', 'php8.3-fpm.'))
                or line.split() and line.split()[0] in (*HDD_BIND_UNITS, HDD_DEPOT_UNIT)]
    (inventory / 'unit-file-states.txt').write_text('\n'.join(selected) + '\n')
    directories = [Path('/srv/fls-server'), Path('/srv/fls-server/raw'),
                   Path('/srv/fls-server/queue'), Path('/srv/fls-server/metrics'),
                   Path('/srv/fls-server/archive'), Path('/srv/fls-server/archive/manifests'),
                   Path('/srv/fls-server/archive/packages'), Path('/srv/fls-server/archive/timestamps'),
                   Path('/srv/fls-server/archive/timestamps/attempts'),
                   Path('/srv/fls-server/archive/timestamps/proofs'),
                   Path('/srv/fls-server/archive/detailed'),
                   Path('/srv/fls-server/database'), Path('/srv/fls-server/database/mysql'),
                   Path('/srv/fls-server/db-dumps'),
                   Path('/srv/fls-storage'), Path('/srv/fls-storage/FLS-Logs'),
                   Path('/srv/fls-storage/FLS-Logs/raw'),
                   Path('/srv/fls-storage/FLS-Logs/archive'),
                   Path('/srv/fls-storage/FLS-Logs/queue'),
                   Path('/srv/fls-storage/FLS-Logs/metrics'),
                   Path('/srv/fls-storage/FLS-Backups'),
                   Path('/srv/fls-storage/FLS-Backups/staging'),
                   Path('/srv/fls-storage/FLS-Backups/published'),
                   Path('/srv/fls-storage/DB-Dump')]
    directories += sorted(Path('/var/lib').glob('fls*')) + sorted(Path('/var/cache').glob('fls*'))
    directories += [Path('/var/lib/fls/sessions')]
    directories = list(dict.fromkeys(str(path) for path in directories if path.is_dir()))
    (inventory / 'data-directory-acls.txt').write_bytes(capture(['getfacl', '-p', *directories], stderr))
    write_json(inventory / 'source.json', source_inventory(stderr))


@contextlib.contextmanager
def temporary_database(stderr):
    import pymysql
    directory = Path(tempfile.mkdtemp(prefix='fls-backup-verify-', dir='/tmp'))
    directory.chmod(0o700)
    process = None
    connection = None
    try:
        data = directory / 'data'
        run(['mariadb-install-db', '--no-defaults', '--user=root',
             '--auth-root-authentication-method=normal', '--skip-test-db',
             '--datadir=' + str(data)], stderr=stderr, stdout=subprocess.DEVNULL)
        socket = directory / 'mariadb.sock'
        command = ['mariadbd', '--no-defaults', '--user=root', '--datadir=' + str(data),
                   '--socket=' + str(socket), '--pid-file=' + str(directory / 'mariadb.pid'),
                   '--skip-networking', '--skip-log-bin', '--skip-general-log',
                   '--skip-slow-query-log', '--skip-log-queries-not-using-indexes',
                   '--event-scheduler=OFF', '--innodb-buffer-pool-size=64M',
                   '--innodb-log-file-size=32M', '--aria-pagecache-buffer-size=16M',
                   '--max-connections=10', '--performance-schema=OFF',
                   '--log-error=' + str(directory / 'mariadb-private-error.txt')]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            require(process.poll() is None, 'verification_database_start_failed')
            try:
                connection = pymysql.connect(unix_socket=str(socket), user='root',
                                             autocommit=True, charset='utf8mb4',
                                             cursorclass=pymysql.cursors.DictCursor)
                break
            except pymysql.Error:
                time.sleep(0.15)
        require(connection is not None, 'verification_database_timeout')
        yield connection, socket
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        shutil.rmtree(directory)


def archive_bytes(archive, name):
    member = archive.getmember(name)
    require(member.isfile(), 'expected_regular_file')
    return archive.extractfile(member).read()


def restore_dump(path, socket, stderr):
    command = ['mariadb', '--no-defaults', '--socket=' + str(socket), '--user=root',
               '--default-character-set=utf8mb4', 'fls']
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=stderr)
    try:
        # A gzip object's fileno points at compressed bytes. Explicitly pipe
        # decompressed data, reading through EOF so the gzip CRC is checked.
        with gzip.open(path, 'rb') as dump:
            shutil.copyfileobj(dump, process.stdin, 1024 * 1024)
        process.stdin.close()
        require(process.wait() == 0, 'independent_database_restore_failed')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)


def verify_keys_and_secrets(system, connection):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    for private, public in (
        ('etc/fls/private/archive-ed25519.pem', 'var/www/fls/public/archive-public-key.pem'),
        ('etc/fls/cold-signing-key.pem', 'etc/fls/cold-public-key.pem'),
    ):
        key = serialization.load_pem_private_key(archive_bytes(system, private), password=None)
        encoded = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        require(encoded == archive_bytes(system, public), 'signing_key_pair_mismatch')
    master = archive_bytes(system, 'etc/fls/credential-key')
    require(len(master) == 32, 'credential_key_invalid')
    for table, aad in (('fortigate_credentials', b'FLS-FortiGate-v1'),
                       ('archive_destinations', b'FLS-Archive-v1'),
                       ('timestamp_profiles', b'FLS-Timestamp-v1')):
        for row in query(connection, "SELECT secret_cipher FROM fls." + identifier(table) +
                         " WHERE secret_cipher<>''"):
            envelope = row['secret_cipher']
            require(envelope.startswith('v1:'), 'unsupported_secret_envelope')
            raw = base64.b64decode(envelope[3:], validate=True)
            AESGCM(master).decrypt(raw[:12], raw[12:], aad)


def verify_archive(archive_path, expected_manifest, work, stderr):
    import pymysql
    # tar readers may stop at tar end markers before reading the gzip footer.
    run(['gzip', '-t', str(archive_path)], stderr=stderr, stdout=subprocess.DEVNULL)
    verification = work / 'verification-payload'
    verification.mkdir(mode=0o700)
    with tarfile.open(archive_path, 'r:gz') as outer:
        members = outer.getmembers()
        require(all((member.isfile() or member.isdir()) and
                    (member.name == 'backup' or member.name.startswith('backup/')) and
                    '..' not in PurePosixPath(member.name).parts for member in members),
                'unsafe_backup_archive')
        require(len({member.name for member in members}) == len(members), 'duplicate_archive_member')
        # Only generated regular files/directories; no links are extracted.
        outer.extractall(verification, filter='data')
    payload = verification / 'backup'
    actual = json.loads((payload / 'MANIFEST.json').read_text())
    require(actual == expected_manifest, 'manifest_changed')
    for name, details in actual['files'].items():
        path = payload / name
        require(path.is_file() and path.stat().st_size == details['bytes'] and
                sha(path) == details['sha256'], 'payload_checksum_mismatch')
    mapping = json.loads((payload / 'inventory/file-sha256.json').read_text())
    with tarfile.open(payload / 'system.tar') as system:
        observed = set()
        for member in system:
            require(not excluded(member.name), 'log_or_cache_in_archive')
            require(not member.name.startswith(('srv/', 'root/', 'var/log/', 'var/cache/')),
                    'runtime_data_in_archive')
            if member.isfile():
                require(member.name in mapping, 'unlisted_archive_file')
                details = mapping[member.name]
                require(member.size == details['bytes'] and hashlib.file_digest(
                    system.extractfile(member), 'sha256').hexdigest() == details['sha256'],
                        'system_file_checksum_mismatch')
                observed.add(member.name)
        require(observed == set(mapping), 'system_file_inventory_mismatch')
        require(set(REQUIRED_FILES).issubset(observed), 'required_system_files_missing')
        with temporary_database(stderr) as (connection, socket):
            query(connection, 'CREATE DATABASE fls CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
            restore_dump(payload / 'database.sql.gz', socket, stderr)
            tables = {next(iter(row.values())) for row in query(connection, 'SHOW TABLES FROM fls')}
            require(tables == set(actual['database_tables']), 'restored_schema_mismatch')
            digest = configuration_digest(connection)
            expected = json.loads((payload / 'inventory/configuration-digests.json').read_text())
            require(digest == expected, 'configuration_roundtrip_mismatch')
            empty = tables - set(CONFIG_TABLES)
            require(all(query(connection, 'SELECT COUNT(*) AS n FROM fls.' + identifier(table))[0]['n'] == 0
                        for table in empty), 'non_configuration_data_in_dump')
            verify_keys_and_secrets(system, connection)
            with (payload / 'database-accounts.sql').open('rb') as accounts:
                run(['mariadb', '--no-defaults', '--socket=' + str(socket), '--user=root'],
                    stdin=accounts, stdout=subprocess.DEVNULL, stderr=stderr)
            for credential_name in actual['database_credential_files_covered']:
                credential = json.loads(archive_bytes(system, 'etc/fls/' + credential_name))
                # Authenticate with the archived password against restored SQL
                # accounts; no credentials are printed or passed in argv.
                login = pymysql.connect(unix_socket=str(socket), user=credential['user'],
                                        password=credential['password'], database='fls')
                try:
                    with login.cursor() as cursor:
                        cursor.execute('SELECT 1')
                        require(cursor.fetchone() == (1,), 'restored_account_login_failed')
                finally:
                    login.close()
            with (payload / 'restore-safe.sql').open('rb') as safe:
                run(['mariadb', '--no-defaults', '--socket=' + str(socket), '--user=root', 'fls'],
                    stdin=safe, stdout=subprocess.DEVNULL, stderr=stderr)
            for table in SEED_TABLES:
                require(query(connection, 'SELECT COUNT(*) AS n FROM fls.' + identifier(table))[0]['n'] == 1,
                        'restore_seed_missing')
            require(query(connection, 'SELECT requested_mode FROM fls.maintenance_requests')[0]['requested_mode'] == 'paused',
                    'restore_maintenance_not_paused')
            require(query(connection, 'SELECT action FROM fls.power_requests')[0]['action'] == '',
                    'restore_power_request_not_empty')
            require(all(row['enabled'] == 0 for row in query(connection, 'SELECT enabled FROM fls.timestamp_settings')),
                    'restore_timestamp_enabled')
            require(all(row['enabled'] == 0 for row in query(connection, 'SELECT enabled FROM fls.archive_destinations')),
                    'restore_destination_enabled')
            require(all(row['packaging_enabled'] == 0 for row in query(connection, 'SELECT packaging_enabled FROM fls.archive_export_settings')),
                    'restore_packaging_enabled')
            require(all(query(connection, 'SELECT COUNT(*) AS n FROM fls.' + identifier(table))[0]['n'] == 0
                        for table in empty - set(SEED_TABLES)), 'unexpected_seed_data')
    return {'schema': 'fls-system-backup-verification-v1',
            'verified_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'all_payload_hashes_match': True, 'all_system_file_hashes_match': True,
            'independent_mariadb_restore': True, 'production_database_modified': False,
            'all_table_schemas_restored': len(tables), 'configuration_tables_restored': len(CONFIG_TABLES),
            'configuration_rows_roundtrip_exact': True, 'non_configuration_tables_empty_before_seeds': True,
            'fresh_state_tables': len(SEED_TABLES), 'safe_restore_verified': True,
            'signing_key_pairs_match': True, 'encrypted_credentials_decrypted': True,
            'sql_accounts_restored': True, 'raw_logs_archives_runtime_history_absent': True,
            'credential_auth_verified': True, 'os_boot_tested': False,
            'current_source_and_native_helpers_included': True}


def create_backup():
    from fls_storage import storage_state
    import pymysql
    require(os.geteuid() == 0, 'root_required')
    os.umask(0o077)
    storage_state()
    DESTINATION.mkdir(mode=0o700, exist_ok=True)
    info = DESTINATION.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            'backup_directory_not_private')
    name = 'fls-system-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%SZ')
    work = Path(tempfile.mkdtemp(prefix='.' + name + '-', dir=DESTINATION))
    work.chmod(0o700)
    lock = (DESTINATION / '.system-backup.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    connection = None
    published = False
    try:
        with (work / 'private-errors.txt').open('ab') as stderr:
            os.nice(15)
            run(['ionice', '-c', '3', '-p', str(os.getpid())], stderr=stderr, stdout=subprocess.DEVNULL)
            payload = work / 'backup'
            payload.mkdir(mode=0o700)
            inventory = payload / 'inventory'
            inventory.mkdir(mode=0o700)
            paths = included_paths()
            require((SOURCE / 'docs/system-backup-restore.md').is_file(), 'recovery_document_missing')
            connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                                         autocommit=True, charset='utf8mb4',
                                         cursorclass=pymysql.cursors.DictCursor)
            rows = query(connection, "SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='fls'")
            tables = {row['TABLE_NAME'] for row in rows}
            require(set(CONFIG_TABLES + SEED_TABLES).issubset(tables), 'required_schema_missing')
            require(all(row['ENGINE'] == 'InnoDB' for row in rows), 'non_transactional_tables')
            # Unexpected stored programs could re-introduce history or side
            # effects during verification; this installation has none.
            for category in ('TRIGGERS', 'ROUTINES', 'EVENTS'):
                schema_column = {'TRIGGERS': 'TRIGGER_SCHEMA', 'ROUTINES': 'ROUTINE_SCHEMA',
                                 'EVENTS': 'EVENT_SCHEMA'}[category]
                require(query(connection, 'SELECT COUNT(*) AS n FROM information_schema.' + category +
                              ' WHERE ' + schema_column + "='fls'")[0]['n'] == 0,
                        'stored_programs_require_review')
            accounts, covered = database_accounts(connection, payload)
            dump_database(connection, payload, inventory, tables, stderr)
            (payload / 'restore-safe.sql').write_text(RESTORE_SQL)
            shutil.copyfile(SOURCE / 'docs/system-backup-restore.md', payload / 'RESTORE.md')
            inventory_files(inventory, paths, stderr)
            mapping = build_system_tar(work, payload, inventory, paths, stderr)
            source_guard = json.loads((inventory / 'configuration-source-guard.json').read_text())
            require(configuration_source_guard(connection) == source_guard,
                    'configuration_changed_during_file_snapshot')
            manifest = {'schema': 'fls-system-backup-v1',
                        'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                        'scope': f'All FLS schemas, {len(CONFIG_TABLES)} exact configuration tables, current source and system configuration; no log/event/archive data.',
                        'configuration_tables': list(CONFIG_TABLES), 'database_tables': sorted(tables),
                        'fresh_restore_seed_tables': list(SEED_TABLES),
                        'database_credential_files_covered': covered,
                        'database_accounts': accounts, 'private_keys_included': True,
                        'system_files': len(mapping), 'production_configuration_modified': False,
                        'files': {str(path.relative_to(payload)): {'bytes': path.stat().st_size, 'sha256': sha(path)}
                                  for path in payload.rglob('*') if path.is_file()}}
            write_json(payload / 'MANIFEST.json', manifest)
            partial = work / (name + '.tar.gz.part')
            run(['tar', '-I', 'gzip -1', '-cf', str(partial), '-C', str(work), 'backup'],
                stderr=stderr, stdout=subprocess.DEVNULL)
            report = verify_archive(partial, manifest, work, stderr)
            result = DESTINATION / (name + '.tar.gz')
            require(not result.exists(), 'backup_name_collision')
            digest = sha(partial)
            report.update({'filename': result.name, 'bytes': partial.stat().st_size, 'sha256': digest})
            with partial.open('rb') as stream:
                os.fsync(stream.fileno())
            # Publication is the final step, after whole-archive verification.
            os.replace(partial, result)
            result.chmod(0o600)
            checksum = DESTINATION / (result.name + '.sha256')
            checksum.write_text(digest + '  ' + result.name + '\n')
            checksum.chmod(0o600)
            write_json(DESTINATION / (result.name + '.verification.json'), report)
            folder = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(folder)
            finally:
                os.close(folder)
            published = True
            return {'ok': True, 'path': str(result), 'bytes': report['bytes'], 'sha256': digest,
                    'schema_tables': len(tables), 'configuration_tables': len(CONFIG_TABLES),
                    'independent_restore_verified': True}
    except Exception as exc:
        # The path is safe to report; detailed subprocess errors remain private.
        with (work / 'private-errors.txt').open('a') as error:
            traceback.print_exc(file=error)
        print(json.dumps({'ok': False, 'code': str(exc) if isinstance(exc, BackupError) else 'backup_failed',
                          'private_work_directory': str(work)}))
        raise
    finally:
        if connection is not None:
            connection.close()
        lock.close()
        if published:
            shutil.rmtree(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create', action='store_true', help='Create and verify the private recovery backup as root.')
    args = parser.parse_args()
    if not args.create:
        print(json.dumps({'mode': 'read-only-plan', 'destination': str(DESTINATION),
                          'configuration_tables': list(CONFIG_TABLES),
                          'all_other_tables': 'schema only; no event, archive, audit, or runtime rows',
                          'system_paths': list(FIXED_PATHS), 'private_keys_included': True,
                          'verification': 'independent temporary MariaDB, exact config row and file hashes',
                          'production_changes': False}, ensure_ascii=False, indent=2))
        return 0
    try:
        print(json.dumps(create_backup(), ensure_ascii=False))
        return 0
    except Exception as exc:
        # Never print exception text: SQL and configuration errors can contain secrets.
        if isinstance(exc, BackupError) and str(exc) == 'root_required':
            print(json.dumps({'ok': False, 'code': 'root_required'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
