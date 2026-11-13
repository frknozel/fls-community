"""Fresh Ubuntu Community installer. Importing this module has no side effects.

The CLI admits an actual fresh host, authenticates every release file, then opens
an exclusive root journal. A started phase is never replayed automatically: after
an interrupted installation the operator restores the clean VM snapshot. No disk
partitioning or formatting command exists in this engine.
"""
from __future__ import annotations
import contextlib
import datetime as dt
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import time
import uuid

STATE = Path('/var/lib/fls-community-install')
APP = Path('/var/www/fls')
COLLECTOR = 'opt/fortigate/rsyslog-8.2312.0-fg1'
PHASES = ('packages', 'identities', 'application', 'storage', 'database', 'roles',
          'keys', 'services', 'web', 'validation', 'activation', 'health')
SHA = re.compile(r'[a-f0-9]{64}\Z')
ROLE_HELPERS = (
    ('provision-maintenance.py', 'maintenance-database.json', 'fls_maintenance', 'configure_role'),
    ('provision-power.py', 'power-database.json', 'fls_power', 'configure_role'),
    ('provision-system-backups.py', 'system-backup.json', 'fls_system_backup', 'configure_role'),
    ('provision-db-dumps.py', 'db-dump.json', 'fls_db_dump', 'configure_role'),
    ('provision-disk-management.py', 'disk-management.json', 'fls_disks', 'configure_role'),
    ('provision-allowed-index.py', 'allowed-index.json', 'fls_allowed', 'configure_role'),
    ('provision-integrity-scrub.py', 'integrity-scrub.json', 'fls_scrub', 'configure_role'),
    ('provision-cold-storage.py', 'cold-storage.json', 'fls_cold', 'configure_worker_role'),
)
USERS = ('fls-web', 'fls-index', 'fls-integrity', 'fls-search', 'fls-allowed',
         'fls-api', 'fls-alerts', 'fls-cold', 'fls-cold-query', 'fls-scrub', 'fls-tls-history', 'fls-export', 'fls-tsa')


class InstallError(ValueError):
    def __init__(self, code, phase='admission'):
        self.code = code if re.fullmatch(r'[a-z0-9_]{1,90}', str(code)) else 'installation_failed'
        self.phase = phase
        super().__init__(self.code)


def require(value, code):
    if not value:
        raise InstallError(code)


def _safe_path(value):
    require(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
            'release_path_invalid')
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ('', '.', '..') for part in value.split('/')),
            'release_path_invalid')
    return path


def read_regular(path, limit=16 * 1024 ** 2):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, 'release_file_redirected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                and not before.st_mode & 0o022 and before.st_size <= limit, 'release_file_unsafe')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        require(len(data) <= limit and _same(before, after) and _same(before, path.lstat()),
                'release_file_changed')
    return data


def _same(left, right):
    return all(getattr(left, field) == getattr(right, field) for field in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def verify_release(source):
    """Validate the authenticated release's exact file inventory before execution.

    The bootstrap authenticates the outer tar with the publisher signature. This
    second check prevents unpacked-tree changes and accidental checkout installs.
    """
    source = Path(source).absolute()
    require(source.resolve(strict=True) == source and source.stat().st_uid == os.geteuid() and not source.stat().st_mode & 0o022, 'release_directory_redirected')
    manifest_bytes = read_regular(source / 'deploy/release-files.json')
    try:
        manifest = json.loads(manifest_bytes)
    except (ValueError, UnicodeError):
        raise InstallError('release_manifest_invalid') from None
    require(isinstance(manifest, dict) and manifest.get('schema') == 'fls-community-release-files-v1'
            and isinstance(manifest.get('files'), list),
            'release_manifest_invalid')
    expected = {}
    for row in manifest['files']:
        require(isinstance(row, dict), 'release_manifest_invalid')
        relative = str(_safe_path(row.get('path')))
        require(relative not in expected and relative != 'deploy/release-files.json'
                and SHA.fullmatch(str(row.get('sha256'))) is not None, 'release_manifest_invalid')
        expected[relative] = row
    require(len(expected) > 10 and len(expected) <= 20000, 'release_inventory_invalid')
    actual = set()
    for path in source.rglob('*'):
        require(not path.is_symlink(), 'release_symlink_forbidden')
        if path.is_dir():
            require(not path.stat().st_mode & 0o022, 'release_directory_writable')
            continue
        relative = path.relative_to(source).as_posix()
        if relative == 'deploy/release-files.json':
            continue
        require(relative in expected, 'release_unlisted_file')
        data = read_regular(path, 512 * 1024 ** 2)
        require(hashlib.sha256(data).hexdigest() == expected[relative]['sha256'], 'release_checksum_mismatch')
        if 'bytes' in expected[relative]:
            require(type(expected[relative]['bytes']) is int and expected[relative]['bytes'] == len(data), 'release_length_mismatch')
        mode = expected[relative].get('mode')
        if mode is not None:
            target_mode = int(str(mode), 8)
            require(type(target_mode) is int and stat.S_IMODE(path.stat().st_mode) == target_mode,
                    'release_mode_mismatch')
        actual.add(relative)
    require(actual == set(expected), 'release_missing_file')
    for path in ('schema.sql', 'VERSION', 'bin/product_config.py', 'bin/fls_storage.py'):
        require(path in expected, 'release_required_file_missing')
    require(manifest.get('version') == read_regular(source / 'VERSION', 128).decode().strip(), 'release_version_mismatch')
    return {'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
            'version': read_regular(source / 'VERSION', 128).decode().strip(),
            'file_count': len(expected), 'files': expected}


def _module(path, name):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def identity(inventory):
    root = inventory['root']
    return {key: root.get(key) for key in ('uuid', 'major_minor', 'disk_path', 'disk_wwn',
                                          'device_identity', 'hardware_identity_matches')} | {
        'machine_sha256': inventory.get('machine_sha256')}


def apply(source, plan, *, ops=None):
    """Apply one admitted fresh-host plan. HostOps is injectable for safe fixtures."""
    require(plan.get('inventory_origin') == 'host' and plan.get('host_inspected') is True,
            'fixture_apply_forbidden')
    require(plan.get('ready_for_apply') is True and not plan.get('blockers'), 'installation_plan_blocked')
    ops = HostOps() if ops is None else ops
    release = verify_release(source)
    fresh = ops.admit(plan)
    with ops.journal(release, fresh) as journal:
        if journal['status'] == 'complete':
            return public_result(journal)
        try:
            for phase in PHASES:
                ops.guard(fresh)
                # Persist the intent BEFORE a phase can mutate anything.
                journal.update(status='running', phase=phase, phase_started_at=utc())
                ops.save_journal(journal)
                getattr(ops, phase)(Path(source), plan, release)
                journal['completed_phases'].append(phase)
                ops.save_journal(journal)
            journal.update(status='complete', phase='complete', completed_at=utc())
            ops.save_journal(journal)
        except BaseException as error:
            journal.update(status='failed', error_code=error.code if isinstance(error, InstallError) else 'installation_phase_failed')
            ops.save_journal(journal)
            raise InstallError(journal['error_code'], journal['phase']) from None
    return public_result(journal)


def public_result(journal):
    return {'schema': 'fls-community-install-result-v1', 'installed': journal['status'] == 'complete',
            'status': journal['status'], 'version': journal['version'],
            'installation_id': journal['installation_id'], 'phase': journal['phase'],
            'credentials_path': '/etc/fls/bootstrap-credentials.txt',
            'collector_started': False, 'disk_formatted': False, 'external_work_enabled': False}


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


class HostOps:
    """Real privileged operations. No root override or test mode is exposed by CLI."""
    def __init__(self):
        self.state = STATE
        self.credentials = {}
        self.instance_id = None

    def run(self, args, *, input=None, timeout=180, capture=False):
        try:
            result = subprocess.run(args, input=input, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=True, timeout=timeout,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                                         'DEBIAN_FRONTEND': 'noninteractive', 'PYTHONDONTWRITEBYTECODE': '1'})
        except (OSError, subprocess.SubprocessError):
            raise InstallError('installation_command_failed') from None
        return result.stdout if capture else b''

    def admit(self, plan):
        from install_plan import collect_inventory, assess, inspect_components, read_json
        require(os.geteuid() == 0, 'root_required')
        # Do not open the journal, log or any directory until this actual host is fresh.
        fresh = collect_inventory()
        expected = plan['storage']['root']
        require(identity(fresh) == identity({'root': expected, 'machine_sha256': plan.get('machine_sha256')}),
                'target_identity_changed')
        manifest = read_json(Path(__file__).resolve().parents[1] / 'deploy/installer-components.json')
        report = assess(fresh, manifest, inspect_components(manifest, Path(__file__).resolve().parents[1]),
                        origin='host', **{key: plan['configuration_proposal'][key] for key in
                                        ('bind_ip', 'hostname', 'management_network')})
        require(report['ready_for_apply'] and not report['blockers'], 'fresh_host_required')
        machine = fresh.get('machine_sha256')
        require(isinstance(machine, str) and SHA.fullmatch(machine), 'machine_identity_required')
        return identity(fresh)

    def guard(self, expected):
        from install_plan import collect_inventory
        require(identity(collect_inventory()) == expected, 'target_identity_changed')

    @contextlib.contextmanager
    def journal(self, release, target):
        if self.state.exists() or self.state.is_symlink():
            raise InstallError('previous_installation_requires_snapshot_restore')
        require(self.state.parent.resolve(strict=True) == self.state.parent
                and self.state.parent.stat().st_uid == 0 and not self.state.parent.stat().st_mode & 0o022,
                'installation_state_parent_unsafe')
        self.state.mkdir(mode=0o700)
        self.state.chmod(0o700)
        fd = os.open(self.state / 'lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.instance_id = str(uuid.uuid4())
            journal = {'schema': 'fls-community-install-journal-v1', 'installation_id': self.instance_id,
                       'version': release['version'], 'release_sha256': release['manifest_sha256'],
                       'target': target, 'status': 'admitted', 'phase': 'admission', 'started_at': utc(),
                       'completed_phases': []}
            self.save_journal(journal)
            yield journal
        finally:
            os.close(fd)

    def save_journal(self, value):
        self.write(self.state / 'journal.json', json.dumps(value, sort_keys=True) + '\n', mode=0o600, replace=True)

    def directory(self, path, *, mode=0o755, user='root', group=None):
        path = Path(path)
        missing = []
        ancestor = path
        while not ancestor.exists() and not ancestor.is_symlink():
            missing.append(ancestor)
            ancestor = ancestor.parent
        require(ancestor.resolve(strict=True) == ancestor and ancestor.is_dir()
                and not ancestor.stat().st_mode & 0o002, 'installation_parent_unsafe')
        for item in reversed(missing):
            item.mkdir(mode=0o755)
            item.chmod(0o755)
        require(not path.is_symlink() and path.is_dir(), 'installation_directory_unsafe')
        shutil.chown(path, user=user, group=group or user)
        path.chmod(mode)

    def write(self, path, data, *, mode=0o644, group='root', user='root', replace=False):
        path = Path(path)
        if not path.parent.exists():
            self.directory(path.parent)
        # Parent ownership cannot be silently changed when writing service-owned directories.
        require(path.parent.resolve(strict=True) == path.parent, 'installation_parent_redirected')
        if not replace:
            require(not path.exists() and not path.is_symlink(), 'installation_refuses_existing_file')
        else:
            require(not path.is_symlink() and (not path.exists() or path.is_file()), 'installation_file_unsafe')
        temporary = path.parent / ('.fls-install-' + secrets.token_hex(12))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data.encode() if isinstance(data, str) else data)
                os.fchmod(stream.fileno(), mode)
                os.fchown(stream.fileno(), pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
                stream.flush(); os.fsync(stream.fileno())
            if replace:
                os.replace(temporary, path)
            else:
                os.link(temporary, path, follow_symlinks=False)
                temporary.unlink()
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(parent)
            finally: os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)

    def packages(self, source, plan, release):
        policy = Path('/usr/sbin/policy-rc.d')
        original = read_regular(policy, 65536) if policy.exists() or policy.is_symlink() else None
        original_mode = stat.S_IMODE(policy.stat().st_mode) if original is not None else None
        # Preserve an existing policy inode by moving it, then restore it in finally.
        saved = self.state / 'policy-rc.d.before'
        if original is not None:
            os.rename(policy, saved)
        try:
            self.write(policy, '#!/bin/sh\nexit 101\n', mode=0o755)
            self.run(['/usr/bin/apt-get', 'update'], timeout=900)
            self.run(['/usr/bin/apt-get', '--no-install-recommends', '-y', 'install',
                      *plan['dependencies']['packages']], timeout=1800)
        finally:
            if policy.exists() and not policy.is_symlink():
                policy.unlink()
            if original is not None:
                require(read_regular(saved, 65536) == original and stat.S_IMODE(saved.stat().st_mode) == original_mode,
                        'original_service_policy_changed')
                os.rename(saved, policy)
        versions = self.run(['/usr/bin/dpkg-query', '-W', '-f=${Package} ${Version}\n',
                             'php8.3-cli', 'mariadb-server'], capture=True).decode()
        require(re.search(r'^php8\.3-cli (?:\d+:)?8\.3\.', versions, re.M)
                and re.search(r'^mariadb-server (?:\d+:)?10\.11\.', versions, re.M), 'installed_package_version_unsupported')

    def identities(self, source, plan, release):
        for user in USERS:
            try:
                pwd.getpwnam(user)
                raise InstallError('existing_service_account_rejected')
            except KeyError:
                self.run(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                          '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', user])
        for user in ('fls-index', 'fls-integrity'):
            self.run(['/usr/sbin/usermod', '-a', '-G', 'adm', user])
        # Ubuntu's stock rsyslog supplies this non-login collector identity.
        account = pwd.getpwnam('syslog')
        require(account.pw_uid != 0, 'collector_account_unsafe')
        self.directory('/etc/fls', mode=0o755)
        self.directory('/etc/fls/private', mode=0o700, user='fls-integrity')

    def application(self, source, plan, release):
        require(not APP.exists() and not APP.is_symlink(), 'existing_application_rejected')
        self.directory(APP)
        for relative, row in sorted(release['files'].items()):
            original = source / relative
            data = read_regular(original, 512 * 1024 ** 2)
            require(hashlib.sha256(data).hexdigest() == row['sha256'], 'release_changed_before_copy')
            self.write(APP / relative, data, mode=stat.S_IMODE(original.stat().st_mode))
        self.write(APP / 'deploy/release-files.json', read_regular(source / 'deploy/release-files.json'))
        self.directory('/usr/lib/fls')
        self.write('/usr/lib/fls/fls-archive-hash', read_regular(source / 'artifacts/linux-amd64/fls-archive-hash'), mode=0o755)
        self.extract_collector(source / 'artifacts/linux-amd64/fls-checked-write-collector.tar.gz')
        self.directory('/usr/local/libexec')
        self.write('/usr/local/libexec/fortigate-health.py', read_regular(source / 'bin/fortigate-health.py'), mode=0o755)

    def extract_collector(self, archive):
        # No tar.extractall: exact prefix, bounded bytes, regular files/directories only.
        seen, total = set(), 0
        with tarfile.open(archive, 'r:gz') as stream:
            for member in stream:
                relative = str(_safe_path(member.name.rstrip('/')))
                require(relative == COLLECTOR or relative.startswith(COLLECTOR + '/'), 'collector_path_invalid')
                require(relative not in seen and len(seen) < 10000, 'collector_duplicate_or_limit')
                seen.add(relative)
                require(member.isdir() or member.isfile(), 'collector_links_forbidden')
                require(not member.mode & 0o7000 and member.size >= 0, 'collector_mode_invalid')
                total += member.size
                require(total <= 512 * 1024 ** 2, 'collector_bundle_too_large')
                target = Path('/') / relative
                if member.isdir():
                    self.directory(target)
                else:
                    data = stream.extractfile(member).read(member.size + 1)
                    require(len(data) == member.size, 'collector_member_truncated')
                    self.write(target, data, mode=0o755 if member.mode & 0o111 else 0o644)
        require(COLLECTOR + '/sbin/rsyslogd' in seen, 'collector_binary_missing')

    def storage(self, source, plan, release):
        self.directory('/srv/fortigate', mode=0o755)
        for name in ('raw', 'queue', 'metrics'):
            self.directory('/srv/fortigate/' + name, mode=0o750, user='syslog', group='adm')
        self.directory('/srv/fortigate/metrics/fortigate', mode=0o750, user='fls-api', group='adm')
        self.directory('/srv/fortigate/metrics/change-alerts', mode=0o750, user='fls-alerts', group='adm')
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-api:--x,u:fls-alerts:--x', '/srv/fortigate/metrics'])
        self.directory('/srv/fortigate/metrics/telemetry', mode=0o750, user='syslog', group='adm')
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-web:r-x,d:u:fls-web:r-x', '/srv/fortigate/metrics/fortigate', '/srv/fortigate/metrics/telemetry', '/srv/fortigate/metrics/change-alerts'])
        self.directory('/srv/fortigate/archive', mode=0o755)
        for name, owner in (('manifests', 'fls-integrity'), ('detailed', 'fls-cold'),
                            ('packages', 'fls-export'), ('timestamps', 'fls-tsa')):
            self.directory('/srv/fortigate/archive/' + name, mode=0o750, user=owner)
        self.directory('/srv/fortigate/database', mode=0o711)
        self.directory('/srv/fortigate/database/mysql', mode=0o750, user='mysql')
        self.directory('/srv/fortigate/backups', mode=0o700)
        self.directory('/srv/fortigate/db-dumps', mode=0o700)
        for path, owner, group, mode in (
            ('/var/lib/fls', 'fls-web', 'fls-web', 0o700),
            ('/var/lib/fls/sessions', 'fls-web', 'fls-web', 0o700),
            ('/var/cache/fls', 'fls-web', 'fls-web', 0o700),
            ('/var/lib/fls-maintenance', 'root', 'root', 0o700),
            ('/var/lib/fls-disks', 'root', 'root', 0o700),
            ('/var/lib/fls-power', 'root', 'root', 0o700),
            ('/var/lib/fls-backup-worker', 'root', 'root', 0o700),
            ('/var/lib/fls-db-dump', 'root', 'fls-web', 0o750),
            ('/var/lib/fls-recovery-download', 'root', 'fls-web', 0o750),
            ('/var/lib/fls-integrity-scrub', 'fls-scrub', 'fls-scrub', 0o700),
            ('/var/cache/fls-cold-query', 'fls-cold-query', 'fls-cold-query', 0o700)):
            self.directory(path, user=owner, group=group, mode=mode)
        root = plan['storage']['root']
        config = {'schema': 2, 'mode': 'system-root', 'root_uuid': root['uuid'],
                  'device_identity': root['device_identity']}
        self.write('/etc/fls/storage.json', json.dumps(config) + '\n')
        self.write('/var/lib/fls-maintenance/paused', 'Initial installation: complete FortiGate onboarding before resuming.\n', mode=0o600)
        self.write('/var/lib/fls-disks/attempt.json', json.dumps({'schema': 1, 'high_water': 0, 'last': None}) + '\n', mode=0o600)
        self.write('/var/lib/fls-disks/token-key.json', json.dumps({'key': secrets.token_hex(32)}) + '\n', mode=0o600)
        for path in ('/srv/fortigate/raw', '/srv/fortigate/metrics', '/srv/fortigate/archive/manifests'):
            self.run(['/usr/bin/setfacl', '-m', 'u:fls-web:r-x,d:u:fls-web:r-x', path])
        for path in ('/srv/fortigate/raw', '/srv/fortigate/archive/manifests'):
            self.run(['/usr/bin/setfacl', '-m', 'u:fls-scrub:r-x,d:u:fls-scrub:r-x', path])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-export:r-x', '/srv/fortigate/raw', '/srv/fortigate/archive/manifests'])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-export:r-x,d:u:fls-export:r-x', '/srv/fortigate/raw'])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-web:r-x,d:u:fls-web:r-x,u:fls-tsa:r-x,d:u:fls-tsa:r-x', '/srv/fortigate/archive/packages'])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-web:r-x,d:u:fls-web:r-x', '/srv/fortigate/archive/timestamps'])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-export:r-x,d:u:fls-export:r-x', '/srv/fortigate/archive/manifests'])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-integrity:r-x,d:u:fls-integrity:r-x', '/srv/fortigate/raw'])
        self.run(['/usr/bin/setfacl', '-m', 'u:fls-cold-query:r-x,d:u:fls-cold-query:r-x,u:fls-web:r-x,d:u:fls-web:r-x',
                  '/srv/fortigate/archive/detailed'])

    def connect(self):
        import pymysql
        return pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', autocommit=True, charset='utf8mb4')

    def database(self, source, plan, release):
        self.run(['/usr/bin/systemctl', 'stop', 'mariadb.service'])
        # Package-maintainer initialization is intentionally not copied. This new
        # private datadir is initialized once, after the durable phase intent.
        self.run(['/usr/bin/mariadb-install-db', '--user=mysql', '--datadir=/srv/fortigate/database/mysql',
                  '--auth-root-authentication-method=socket', '--skip-test-db'], timeout=180)
        pool = plan['sizing_proposal']['mariadb_buffer_pool_bytes']
        self.write('/etc/mysql/mariadb.conf.d/90-fls.cnf', '[mysqld]\ndatadir=/srv/fortigate/database/mysql\n'
                   f'bind-address=127.0.0.1\ninnodb_buffer_pool_size={pool}\n'
                   'innodb_flush_log_at_trx_commit=1\ninnodb_flush_method=O_DIRECT\n'
                   'max_allowed_packet=64M\nmax_connections=40\ncharacter-set-server=utf8mb4\n'
                   'collation-server=utf8mb4_unicode_ci\nskip-name-resolve\nlocal-infile=0\n')
        self.write('/etc/systemd/system/mariadb.service.d/fls-storage.conf',
                   '[Unit]\nRequiresMountsFor=/srv/fortigate/database/mysql\n[Service]\nReadWritePaths=/srv/fortigate/database/mysql\n')
        self.run(['/usr/bin/systemctl', 'daemon-reload'])
        self.run(['/usr/bin/systemctl', 'start', 'mariadb.service'])
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='fls'")
                require(cursor.fetchone()[0] == 0, 'existing_database_rejected')
                for statement in read_regular(APP / 'schema.sql').decode().split(';'):
                    if statement.strip(): cursor.execute(statement)
                cursor.execute('USE fls')
                cursor.execute("UPDATE maintenance_requests SET requested_mode='paused',revision=revision+1,requested_by='community-install',requested_at=UTC_TIMESTAMP(6) WHERE id=1")
                cursor.execute('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=\'fls\'')
                require(cursor.fetchone()[0] == len(re.findall(r'CREATE TABLE IF NOT EXISTS\s+[a-z_]+\s*\(', read_regular(APP / 'schema.sql').decode(), re.I)), 'fresh_schema_table_count_invalid')
                self.base_roles(cursor)
                password = secrets.token_urlsafe(24)
                hashed = self.run(['/usr/bin/php', '-r', '$p=stream_get_contents(STDIN);echo password_hash($p,PASSWORD_ARGON2ID);'],
                                  input=password.encode(), capture=True).decode()
                require(hashed.startswith('$argon2id$'), 'administrator_password_hash_failed')
                cursor.execute("INSERT INTO users(username,password_hash,role,must_change,updated_at) VALUES(%s,%s,'admin',1,UTC_TIMESTAMP())", ('admin', hashed))
            self.write('/etc/fls/bootstrap-credentials.txt',
                       'Adres: https://' + plan['configuration_proposal']['bind_ip'] + '\nKullanıcı: admin\n'
                       'İlk giriş parolası: ' + password + '\nİlk girişte değiştirilmesi zorunludur.\n', mode=0o600)
        finally:
            connection.close()

    def credential(self, cursor, user, filename, *, group='root'):
        password = secrets.token_urlsafe(36)
        cursor.execute('CREATE USER %s@localhost IDENTIFIED BY %s', (user, password))
        self.write('/etc/fls/' + filename, json.dumps({'user': user, 'password': password}) + '\n',
                   mode=0o600 if group == 'root' else 0o640, group=group)
        return password

    def base_roles(self, cursor):
        for user, filename, group in (
            ('fls_app', 'app.json', 'fls-web'), ('fls_import', 'importer.json', 'fls-index'),
            ('fls_seal', 'integrity.json', 'fls-integrity'), ('fls_search', 'search-indexer.json', 'fls-search'),
            ('fls_history', 'fortigate-history.json', 'root'), ('fls_alerts', 'change-alerts.json', 'root'),
            ('fls_export', 'archive-export.json', 'root'), ('fls_timestamp', 'timestamp.json', 'root'),
            ('fls_registry', 'fortigate-registry.json', 'root')):
            self.credential(cursor, user, filename, group=group)
        grants = {
            'fls_app': [('SELECT', '*'), ('INSERT,UPDATE', 'users'), ('UPDATE', 'management_lock'), ('INSERT,UPDATE,DELETE', 'login_attempts'),
                ('INSERT', 'audit_log'), ('INSERT', 'event_notes'), ('UPDATE', 'retention_settings'),
                ('INSERT', 'retention_policy_versions'), ('INSERT,UPDATE', 'fortigate_setup'),
                ('INSERT,UPDATE,DELETE', 'fortigate_connections'), ('INSERT,UPDATE,DELETE', 'fortigate_credentials'),
                ('INSERT,UPDATE,DELETE', 'user_preferences'), ('INSERT,UPDATE', 'user_event_columns'),
                ('INSERT,UPDATE,DELETE', 'user_fortigate_preferences'), ('INSERT,DELETE', 'user_fortigate_access'),
                ('INSERT,UPDATE,DELETE', 'user_event_views'), ('INSERT,UPDATE,DELETE', 'user_archive_tls_views'),
                ('UPDATE', 'summary_backlog_settings'), ('UPDATE', 'mail_search_backlog_settings'),
                ('UPDATE', 'archive_tls_settings'), ('INSERT,UPDATE', 'archive_tls_alert_history'),
                ('INSERT,UPDATE', 'archive_tls_history_state'), ('UPDATE', 'archive_export_settings'),
                ('INSERT,UPDATE,DELETE', 'archive_destinations'), ('UPDATE', 'timestamp_settings'),
                ('UPDATE', 'timestamp_profiles'), ('UPDATE', 'timestamp_stamps'), ('UPDATE', 'archive_deliveries')],
            'fls_import': [('SELECT,INSERT', table) for table in ('events', 'av_event_groups', 'security_event_groups',
                'traffic_groups', 'traffic_event_groups', 'archive_event_index')] +
                [('SELECT,INSERT,UPDATE', table) for table in ('source_files', 'policies', 'devices', 'hourly_counts',
                 'archive_dimensions', 'archive_hour_counts', 'archive_group_hours', 'archive_index_state',
                 'device_hourly_counts', 'device_policies', 'device_sources')],
            'fls_registry': [('SELECT', 'fortigate_connections'), ('SELECT', 'fortigate_credentials'),
                             ('UPDATE(check_status,check_code,checked_at,checked_revision,last_used_at)', 'fortigate_credentials')],
            'fls_seal': [('SELECT,INSERT,UPDATE', 'archive_manifests')],
            'fls_search': [('SELECT(id,devid,vd,event_at,fields)', 'events'),
                           ('SELECT(observed_size,byte_offset)', 'source_files'),
                           ('SELECT,INSERT,UPDATE', 'mail_search_events'), ('SELECT,INSERT,UPDATE', 'mail_search_state')],
            'fls_history': [('SELECT,INSERT', table) for table in ('fg_config_versions', 'fg_config_observations', 'fg_config_changes')],
            'fls_alerts': [('SELECT', table) for table in ('events', 'source_files', 'fg_config_changes',
                         'fg_config_observations', 'security_event_groups', 'traffic_event_groups', 'traffic_groups', 'fortigate_connections')],
            'fls_export': [('SELECT', table) for table in ('archive_export_settings', 'archive_destinations', 'archive_manifests')] +
                          [('UPDATE(check_status,check_code,observed_host_key,checked_at,checked_revision,test_requested_at,tls_peer_pem,tls_peer_verified_at,tls_peer_revision,tls_peer_checked_at,tls_peer_check_code)', 'archive_destinations')] +
                          [('SELECT,INSERT,UPDATE', table) for table in ('archive_packages', 'archive_deliveries', 'archive_export_worker')],
            'fls_timestamp': [('SELECT', table) for table in ('timestamp_profiles', 'timestamp_settings', 'archive_packages', 'archive_destinations', 'archive_manifests', 'archive_deliveries')] +
                             [('UPDATE(check_status,check_code,checked_revision,checked_at,test_requested_at,balance,balance_status,balance_at,balance_attempted_at,balance_basis_attempt_id,balance_requested_at)', 'timestamp_profiles')] +
                             [('SELECT,INSERT,UPDATE', table) for table in ('timestamp_attempts', 'timestamp_stamps', 'timestamp_deliveries', 'timestamp_worker')],
        }
        for user, permissions in grants.items():
            for privileges, table in permissions:
                cursor.execute('GRANT ' + privileges + ' ON fls.' + table + ' TO ' + user + '@localhost')

    def roles(self, source, plan, release):
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                for index, (helper, filename, user, function) in enumerate(ROLE_HELPERS):
                    password = secrets.token_urlsafe(36)
                    module = _module(APP / 'bin' / helper, 'fls_install_role_' + str(index))
                    getattr(module, function)(cursor, password)
                    value = {'user': user, 'password': password}
                    if user == 'fls_scrub': value.update(module.DEFAULTS)
                    self.write('/etc/fls/' + filename, json.dumps(value) + '\n', mode=0o600)
                    if helper == 'provision-maintenance.py': module.configure_app_role(cursor)
                    if helper == 'provision-integrity-scrub.py':
                        cursor.execute('GRANT SELECT,INSERT,UPDATE ON fls.archive_integrity_checks TO fls_seal@localhost')
                for table in ('archive_integrity_checks', 'archive_integrity_worker', 'cold_snapshots',
                              'cold_storage_worker', 'allowed_dimensions', 'allowed_event_index',
                              'allowed_hour_counts', 'allowed_index_state'):
                    cursor.execute('GRANT SELECT ON fls.' + table + ' TO fls_app@localhost')
        finally:
            connection.close()
        # These narrow, fresh-host helpers create only their own role/credentials;
        # their existing credential path is absent and the journal prevents replay.
        for helper in ('provision-telemetry.py', 'provision-backlog-history.py',
                       'provision-mail-search-backlog-history.py', 'provision-fortigate-onboarding.py',
                       'provision-archive-tls-history.py', 'provision-cold-query.py'):
            self.run(['/usr/bin/python3', str(APP / 'bin' / helper)])

    def keys(self, source, plan, release):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        self.write('/etc/fls/private/archive-ed25519.pem',
                   key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
                   mode=0o600, user='fls-integrity', group='fls-integrity')
        self.write(APP / 'public/archive-public-key.pem', key.public_key().public_bytes(
                   serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        cold = Ed25519PrivateKey.generate()
        self.write('/etc/fls/cold-signing-key.pem', cold.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), mode=0o600)
        self.write('/etc/fls/cold-public-key.pem', cold.public_key().public_bytes(
                   serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.write('/etc/fls/credential-key', secrets.token_bytes(32), mode=0o640, group='fls-web')

    def services(self, source, plan, release):
        for path in sorted((APP / 'deploy').glob('*')):
            if path.is_file() and path.suffix in ('.service', '.timer', '.socket') and not path.name.startswith('fls-license'):
                content = read_regular(path).replace(b'ReadOnlyPaths=/var/lib/fls-license\n', b'')
                if path.name == 'fortigate-health.service':
                    content = content.replace(b' /run/lock/lvm /run/lvm', b' -/run/lock/lvm -/run/lvm')
                self.write(Path('/etc/systemd/system') / path.name, content)
        for name in ('fortigate-collector.service.d/fls-maintenance.conf',):
            self.write(Path('/etc/systemd/system') / name, read_regular(APP / 'deploy' / name))
        indexer = '''[Unit]
Description=FLS resumable log indexer
After=mariadb.service
Requires=mariadb.service
[Service]
User=fls-index
Group=fls-index
SupplementaryGroups=adm
RuntimeDirectory=fls-indexer
ExecStart=/usr/bin/flock --nonblock /run/fls-indexer/index.lock /usr/bin/python3 /var/www/fls/bin/importer.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_UNIX
ReadOnlyPaths=/srv/fortigate/raw
MemoryMax=1G
[Install]
WantedBy=multi-user.target
'''
        self.write('/etc/systemd/system/fls-indexer.service', indexer)
        self.write('/etc/systemd/system/fls-integrity.service', '''[Unit]
Description=FLS local archive signing
After=mariadb.service
Requires=mariadb.service
[Service]
Type=oneshot
User=fls-integrity
Group=fls-integrity
SupplementaryGroups=adm
ExecStart=/usr/bin/python3 /var/www/fls/bin/integrity.py
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/srv/fortigate/raw
ReadWritePaths=/srv/fortigate/archive/manifests
RestrictAddressFamilies=AF_UNIX
''')
        self.write('/etc/systemd/system/fortigate-health.timer', '[Unit]\nDescription=FLS local health snapshot\n[Timer]\nOnBootSec=30\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n')
        self.write('/etc/systemd/system/fls-integrity.timer', '[Unit]\nDescription=Hourly FLS integrity\n[Timer]\nOnCalendar=*-*-* *:20:00\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
        # Debian stock nginx uses www-data; its default site is disabled before start.
        self.run(['/usr/bin/systemctl', 'daemon-reload'])

    def web(self, source, plan, release):
        module = _module(APP / 'bin/product_config.py', 'fls_install_product_config')
        config = {key: plan['configuration_proposal'][key] for key in
                  ('hostname', 'bind_ip', 'collector_ip', 'collector_port', 'timezone', 'management_network', 'data_path')}
        config.update(schema=1, installation_id=self.instance_id, storage_label='Log ve yedek alanı')
        config = module.validate(config)
        rendered = module.render(config, read_regular(APP / 'deploy/fortigate-rsyslog.conf').decode())
        self.write('/etc/fls/instance.json', rendered['instance.json'])
        self.write('/etc/fls/fortigate-api.json', '{}\n', mode=0o600)
        self.write('/etc/fls/onboarding-collector.json', json.dumps({'listen_ip': config['bind_ip'], 'pinned_ips': []}) + '\n', mode=0o600)
        self.directory('/etc/fortigate', mode=0o755)
        self.write('/etc/fortigate/rsyslog.conf', rendered['fortigate-rsyslog.conf'])
        self.write('/etc/fortigate/fls-senders.json', json.dumps({'version': 1, 'nomatch': 'deny', 'type': 'string', 'table': []}) + '\n')
        self.directory('/etc/nginx/fls-tls', mode=0o700)
        # A unique local CA and SAN leaf are preserved by logs-free backups.
        tls = Path('/etc/nginx/fls-tls')
        self.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-days', '3650', '-nodes',
                  '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt'),
                  '-subj', '/CN=FLS Community ' + self.instance_id], timeout=180)
        self.run(['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
                  '-keyout', str(tls / 'server.key'), '-out', str(self.state / 'server.csr'),
                  '-subj', '/CN=' + config['hostname']], timeout=180)
        self.write(self.state / 'tls.ext', 'subjectAltName=DNS:' + config['hostname'] + ',IP:' + config['bind_ip'] +
                   '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', mode=0o600)
        self.run(['/usr/bin/openssl', 'x509', '-req', '-in', str(self.state / 'server.csr'), '-CA', str(tls / 'ca.crt'),
                  '-CAkey', str(tls / 'ca.key'), '-set_serial', str(secrets.randbits(128)), '-days', '825', '-sha256',
                  '-extfile', str(self.state / 'tls.ext'), '-out', str(tls / 'server.crt')], timeout=180)
        for name in ('ca.key', 'server.key'): (tls / name).chmod(0o600)
        for name in ('ca.crt', 'server.crt'): (tls / name).chmod(0o644)
        children = plan['sizing_proposal']['php_max_children']
        php = '''[fls]
user = fls-web
group = fls-web
listen = /run/php/fls.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = CHILDREN
pm.process_idle_timeout = 20s
pm.max_requests = 500
request_terminate_timeout = 60s
clear_env = yes
security.limit_extensions = .php
php_admin_value[session.save_path] = /var/lib/fls/sessions
php_admin_value[session.gc_maxlifetime] = 28800
php_admin_value[session.cookie_secure] = 1
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_samesite] = Strict
php_admin_value[session.use_strict_mode] = 1
php_admin_flag[session.use_only_cookies] = on
php_admin_flag[session.upload_progress.enabled] = off
php_admin_flag[file_uploads] = off
php_admin_value[post_max_size] = 64K
php_admin_value[max_input_vars] = 200
php_admin_value[max_input_nesting_level] = 16
php_admin_value[expose_php] = Off
php_admin_value[display_errors] = Off
php_admin_value[log_errors] = On
php_admin_value[memory_limit] = 256M
php_admin_value[date.timezone] = Europe/Istanbul
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
'''.replace('CHILDREN', str(children))
        self.write('/etc/php/8.3/fpm/pool.d/fls.conf', php)
        self.write('/etc/nginx/conf.d/fls.conf', rendered['fls-nginx.conf'].replace('/etc/fls/tls/', '/etc/nginx/fls-tls/'))
        default = Path('/etc/nginx/sites-enabled/default')
        if default.is_symlink() and default.resolve() == Path('/etc/nginx/sites-available/default'):
            default.unlink()
        self.write('/etc/fls/release-state.json', json.dumps({'schema': 1, 'version': release['version'],
                   'schema_version': 47, 'edition': 'community', 'release_sha256': release['manifest_sha256'],
                   'installation_id': self.instance_id}) + '\n')

    def validation(self, source, plan, release):
        self.run(['/usr/sbin/php-fpm8.3', '-t'])
        self.run(['/usr/sbin/nginx', '-t'])
        self.run(['/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd', '-N1', '-f', '/etc/fortigate/rsyslog.conf'])
        self.run(['/usr/bin/python3', str(APP / 'bin/fls_storage.py')])
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT role,must_change FROM fls.users WHERE username=\'admin\'')
                require(cursor.fetchone() == ('admin', 1), 'bootstrap_administrator_invalid')
                cursor.execute('SELECT requested_mode FROM fls.maintenance_requests WHERE id=1')
                require(cursor.fetchone() == ('paused',), 'initial_collection_not_paused')
                cursor.execute('SELECT COUNT(*) FROM fls.events')
                require(cursor.fetchone()[0] == 0, 'initial_event_table_not_empty')
        finally:
            connection.close()

    def activation(self, source, plan, release):
        # No receive listener starts until an administrator changes the password,
        # admits a FortiGate and explicitly resumes collection in the panel.
        self.run(['/usr/bin/systemctl', 'enable', '--now', 'mariadb.service', 'php8.3-fpm.service', 'nginx.service'])
        self.run(['/usr/bin/systemctl', 'enable', 'fortigate-collector.service'])
        self.run(['/usr/bin/systemctl', 'enable', '--now', 'fls-indexer.service', 'fls-archive-indexer.service',
                  'fls-mail-search.service', 'fls-allowed-index.service', 'fls-cold-query.socket',
                  'fls-maintenance.timer', 'fls-power.timer', 'fls-disk-management.timer',
                  'fls-system-backup.timer', 'fls-db-dump.timer', 'fls-db-dump-upload.timer',
                  'fls-telemetry.timer', 'fortigate-health.timer', 'fls-integrity.timer', 'fls-integrity-scrub.timer', 'fls-cold-storage.timer', 'fls-archive-export.timer',
                  'fls-fortigate-onboarding.timer', 'fls-fortigate-live.timer', 'fls-fortigate-config.timer',
                  'fls-tls-history.timer', 'fls-mail-backlog-history.timer', 'fls-change-alerts.timer'])
        self.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'mariadb.service', 'php8.3-fpm.service', 'nginx.service'])
        state = self.run(['/usr/bin/systemctl', 'show', 'fortigate-collector.service', '--property=ActiveState,MainPID'], capture=True).decode()
        require('ActiveState=inactive' in state and 'MainPID=0' in state, 'collector_started_during_installation')

    def disk_health(self):
        # Explicitly exercise the fresh worker and its actual PHP read model.
        # The new database must contain no administrative disk mutation intent.
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) FROM fls.disk_management_jobs')
                require(cursor.fetchone() == (0,), 'initial_disk_jobs_not_empty')
            self.run(['/usr/bin/systemctl', 'start', 'fls-disk-management.service'], timeout=180)
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM fls.disk_management_state WHERE id=1')
                value = cursor.fetchone()
                require(value is not None, 'initial_disk_inventory_missing')
                names = [field[0] for field in cursor.description]
                row = dict(zip(names, value))
        finally:
            connection.close()
        for key, value in list(row.items()):
            if isinstance(value, dt.datetime): row[key] = value.isoformat(sep=' ')
        probe = ("require $argv[1];$row=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);"
                 "$state=disk_management_state($row);echo json_encode(['available'=>$state['available'],"
                 "'fresh'=>$state['fresh'],'mode'=>$state['mode'],"
                 "'system_present'=>$state['system']['present']??false,"
                 "'depot'=>$state['depot'],'mirror'=>$state['mirror']],JSON_THROW_ON_ERROR);")
        raw = self.run(['/usr/bin/php', '-r', probe, str(APP / 'app/disk-management.php')],
                       input=json.dumps(row).encode(), capture=True)
        require(len(raw) <= 16384, 'initial_disk_inventory_invalid')
        try: report = json.loads(raw)
        except (ValueError, UnicodeError): raise InstallError('initial_disk_inventory_invalid') from None
        require(isinstance(report, dict) and report.get('available') is True and report.get('fresh') is True
                and report.get('mode') == 'system-root' and report.get('system_present') is True
                and report.get('depot') is None and report.get('mirror') is None,
                'initial_disk_inventory_invalid')

    def health(self, source, plan, release):
        # These requests remain on the new host and verify TLS with its own CA.
        import http.client
        import ssl
        context = ssl.create_default_context(cafile='/etc/nginx/fls-tls/ca.crt')
        connection = http.client.HTTPSConnection(plan['configuration_proposal']['bind_ip'], 443,
                                                timeout=15, context=context)
        try:
            for path, mime in (('/index.php', 'text/html'), ('/assets/app.css', 'text/css'),
                               ('/assets/app.js', 'application/javascript')):
                connection.request('GET', path, headers={'User-Agent': 'FLS-install-self-test/1'})
                response = connection.getresponse()
                data = response.read(2 * 1024 ** 2 + 1)
                content_type = response.getheader('Content-Type', '').split(';', 1)[0]
                if path == '/index.php':
                    require(b'<meta name="fls-version" content="' + str(release['version']).encode('ascii') + b'">' in data,
                            'initial_displayed_version_invalid')
                require(response.status == 200 and 0 < len(data) <= 2 * 1024 ** 2
                        and content_type in ((mime, 'text/javascript') if path.endswith('.js') else (mime,)),
                        'initial_https_self_test_failed')
        except (OSError, http.client.HTTPException):
            raise InstallError('initial_https_self_test_failed') from None
        finally:
            connection.close()
        self.disk_health()
