"""Pinned, fresh-host-only FLS recovery. Importing this module changes nothing.

The bootstrap owns human consent, its private journal and target lease. Every
mutating phase rechecks that lease through ``guard(phase)``. This module never
formats disks, copies host network/boot configuration, starts collectors, calls
providers, or imports Python from an uploaded backup.
"""
import contextlib
import datetime as dt
import errno
import fcntl
import grp
import gzip
import hashlib
import http.cookiejar
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import pwd
import re
import secrets
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import types
import urllib.parse
import urllib.request
import uuid

GIB = 1024 ** 3
MAX_ARCHIVE = 2 * GIB
MAX_DECODED = 8 * GIB
MAX_MEMBERS = 200000
MAX_JSON = 16 * 1024 ** 2
MIN_FREE = 8 * GIB
SHA = re.compile(r'[a-f0-9]{64}\Z')
NAME = re.compile(r'[a-z_][a-z0-9_]{0,63}\Z')
UNIT = re.compile(r'(?:fls|fortigate)-[A-Za-z0-9_.@-]+\.(?:service|timer|socket|path)\Z')
CONTROL_UNITS = {'fls-recovery.service', 'fls-recovery-bootstrap.service'}
WEB_UNIT = 'fls-rehearsal-web.service'
PHASES = ('target_check', 'backup_validation', 'packages', 'identities', 'files',
          'database', 'storage', 'replay', 'web', 'self_test', 'complete')
PACKAGES = ('mariadb-server', 'nginx', 'php8.3-cli', 'php8.3-fpm', 'php8.3-mysql',
            'php8.3-mbstring', 'php8.3-curl', 'php8.3-xml', 'python3-pymysql',
            'python3-cryptography', 'python3-psutil', 'rsyslog', 'acl', 'curl', 'ca-certificates')
CONFIG_TABLES = ('users', 'user_preferences', 'user_event_columns', 'user_event_views',
    'user_fortigate_preferences', 'user_fortigate_access', 'user_archive_tls_views',
    'fortigate_connections', 'fortigate_credentials', 'fortigate_setup',
    'summary_backlog_settings', 'mail_search_backlog_settings', 'archive_tls_settings',
    'archive_export_settings', 'archive_destinations', 'timestamp_profiles',
    'timestamp_settings', 'retention_settings', 'retention_policy_versions', 'system_backup_settings')
EXTERNAL_REFERENCES = {'etc/nginx/modules': 'usr/lib/nginx/modules'}
RESTORE_PREFIXES = ('var/www/fls', 'etc/fls', 'etc/php/8.3/fpm',
                    'etc/php/8.3/mods-available', 'etc/nginx/fls-tls',
                    'etc/fortigate', 'opt/fortigate', 'opt/fls-tsa', 'usr/lib/fls',
                    'var/lib/fls-license')
REQUIRED_SYSTEM = ('var/www/fls/VERSION', 'etc/fls/credential-key',
    'etc/fls/private/archive-ed25519.pem', 'etc/fls/cold-signing-key.pem',
    'etc/fls/cold-public-key.pem', 'var/www/fls/public/archive-public-key.pem',
    'usr/lib/fls/fls-archive-hash',
    'opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd', 'etc/nginx/fls-tls/server.crt',
    'etc/nginx/fls-tls/server.key', 'etc/nginx/fls-tls/ca.crt', 'etc/nginx/fls-tls/ca.key')


class RecoveryError(ValueError):
    def __init__(self, code, phase='target_check'):
        self.code = code if re.fullmatch(r'[a-z0-9_]{1,80}', str(code)) else 'recovery_failed'
        self.phase = phase if phase in PHASES else 'target_check'
        super().__init__(self.code)


def require(value, code, phase='backup_validation'):
    if not value:
        raise RecoveryError(code, phase)


def _capture(args, timeout=60):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}).stdout


def _root_directory(path):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, 'private_directory_redirected')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'private_directory_unsafe')
    return path


@contextlib.contextmanager
def _input(path, maximum=MAX_ARCHIVE):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, 'input_redirected')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= maximum, 'input_unsafe')
        yield stream
        after = os.fstat(stream.fileno())
        current = path.lstat()
        require(_same(before, after) and _same(before, current), 'input_changed')


def _same(left, right):
    return all(getattr(left, field) == getattr(right, field) for field in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def _remap_acl(path, users, groups):
    """Remap Linux numeric named ACL entries with the service UID/GID map."""
    for name in ['system.posix_acl_access', 'system.posix_acl_default']:
        try: value = os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            if error.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP): continue
            raise
        require(len(value) >= 4 and (len(value) - 4) % 8 == 0 and struct.unpack_from('<I', value)[0] == 2,
                'acl_format_unsupported', 'files')
        rewritten = bytearray(value)
        for offset in range(4, len(value), 8):
            tag, permissions, identity = struct.unpack_from('<HHI', value, offset)
            mapping = users if tag == 2 else groups if tag == 8 else {}
            struct.pack_into('<HHI', rewritten, offset, tag, permissions, mapping.get(identity, identity))
        if rewritten != value: os.setxattr(path, name, bytes(rewritten), follow_symlinks=False)


def _sha(path):
    with _input(path, MAX_DECODED) as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _json(path, maximum=MAX_JSON):
    with _input(path, maximum) as stream:
        value = json.load(stream)
    require(isinstance(value, dict), 'json_object_required')
    return value


def _machine_hash():
    machine = Path('/etc/machine-id').read_text(encoding='ascii').strip()
    require(re.fullmatch('[a-f0-9]{32}', machine), 'machine_identity_invalid', 'target_check')
    return hashlib.sha256(machine.encode('ascii')).hexdigest()


def _identity_digest(identity):
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def _physical_identity(disk, major_minor):
    """Match the schema-2 storage guard using only kernel-backed metadata."""
    def values(names):
        found = []
        for name in names:
            try:
                value = (disk / name).read_text(encoding='ascii').strip()
            except FileNotFoundError:
                continue
            require(len(value) <= 4096 and all(32 <= ord(char) <= 126 for char in value),
                    'physical_identity_invalid', 'target_check')
            if value:
                found.append(value)
        require(len(set(found)) <= 1, 'physical_identity_mismatch', 'target_check')
        return found[0] if found else ''
    wwid = values(['device/wwid', 'wwid'])
    if wwid:
        if re.fullmatch(r'naa\.[a-f0-9]{16}', wwid):
            return {'kind': 'wwn', 'value': '0x' + wwid[4:]}
        require(len(wwid) <= 256 and re.fullmatch(r'(?:naa|eui|t10|nvme)\.[A-Za-z0-9_.:+ -]{1,240}', wwid),
                'physical_identity_invalid', 'target_check')
        return {'kind': 'wwid', 'value': wwid}
    serial = values(['device/serial', 'serial'])
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:+ -]{0,127}', serial),
            'stable_physical_identity_required', 'target_check')
    properties = {}
    for line in (Path('/run/udev/data') / ('b' + major_minor)).read_text().splitlines():
        if line.startswith('E:') and '=' in line:
            key, value = line[2:].split('=', 1)
            require(key not in properties, 'physical_metadata_ambiguous', 'target_check')
            properties[key] = value
    require(properties.get('ID_SERIAL_SHORT', serial) == serial,
            'physical_identity_mismatch', 'target_check')
    return {'kind': 'serial', 'value': serial}


def inspect_identity():
    """Read immutable target identity without spawning any process.

    The kernel root mount, its block device, sysfs partition and udev UUID alias
    must all describe the same plain ext4 partition. Missing or ambiguous
    metadata fails closed; this never treats an overlay, LVM or bind as root.
    """
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    result = {'os_id': release.get('ID', '').strip('"'), 'os_version': release.get('VERSION_ID', '').strip('"'),
              'architecture': os.uname().machine, 'machine_sha256': _machine_hash(),
              'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    require(str(uuid.UUID(result['boot_id'])) == result['boot_id'], 'boot_identity_invalid', 'target_check')
    roots = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        require(len(fields) >= 10 and '-' in fields, 'mount_metadata_invalid', 'target_check')
        if fields[4] == '/': roots.append(fields)
    require(len(roots) == 1, 'root_mount_ambiguous', 'target_check')
    root = roots[0]; separator = root.index('-')
    require(separator >= 6 and len(root) == separator + 4 and root[3] == '/', 'plain_root_mount_required', 'target_check')
    require(root[separator + 1] == 'ext4', 'ext4_root_required', 'target_check')
    major_minor = root[2]
    require(re.fullmatch(r'[0-9]+:[0-9]+', major_minor), 'root_device_invalid', 'target_check')
    major, minor = map(int, major_minor.split(':'))
    source = root[separator + 2]
    require(re.fullmatch(r'/dev/[A-Za-z0-9_./+-]+', source), 'plain_root_partition_required', 'target_check')
    device = Path(source).resolve(strict=True); info = device.stat()
    require(stat.S_ISBLK(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (major, minor),
            'root_device_mismatch', 'target_check')
    block = (Path('/sys/dev/block') / major_minor).resolve(strict=True)
    require((block / 'partition').is_file() and (block / 'partition').read_text().strip().isdigit(),
            'plain_root_partition_required', 'target_check')
    identity = _physical_identity(block.parent, major_minor)
    aliases = []
    for candidate in Path('/dev/disk/by-uuid').iterdir():
        if not candidate.is_symlink(): continue
        try: candidate_info = candidate.stat()
        except FileNotFoundError: continue
        if not stat.S_ISBLK(candidate_info.st_mode) or candidate_info.st_rdev != info.st_rdev: continue
        require(candidate.resolve(strict=True) == device and candidate.lstat().st_uid == 0,
                'root_uuid_alias_mismatch', 'target_check')
        require(str(uuid.UUID(candidate.name)) == candidate.name, 'root_uuid_invalid', 'target_check')
        aliases.append(candidate.name)
    require(len(aliases) == 1, 'root_uuid_ambiguous', 'target_check')
    result.update(root_device=str(device), root_major_minor=major_minor, root_uuid=aliases[0],
                  root_identity=identity, root_identity_sha256=_identity_digest(identity),
                  root_wwn=identity['value'] if identity['kind'] == 'wwn' else '')
    return result


def _target_capture(args, code):
    try: return _capture(args, timeout=60)
    except subprocess.TimeoutExpired as error: raise RecoveryError(code + '_timeout', 'target_check') from error
    except Exception as error: raise RecoveryError(code + '_failed', 'target_check') from error


def inspect_target():
    """Full read-only admission check. Only initial preflight/apply need this."""
    result = {'eligible': False, 'reasons': [], 'os_id': '', 'os_version': '',
              'architecture': '', 'root_uuid': '', 'root_wwn': '', 'root_identity': {},
              'root_identity_sha256': '', 'root_device': '',
              'root_major_minor': '', 'machine_sha256': '', 'boot_id': '',
              'free_bytes': 0, 'hostname': socket.gethostname(), 'addresses': []}
    reasons = result['reasons']
    try:
        result.update(inspect_identity())
        if result['os_id'] != 'ubuntu' or result['os_version'] != '24.04': reasons.append('ubuntu_24_04_required')
        if result['architecture'] != 'x86_64': reasons.append('amd64_required')
        usage = os.statvfs('/'); result['free_bytes'] = usage.f_bavail * usage.f_frsize
        if result['free_bytes'] < MIN_FREE: reasons.append('insufficient_free_space')
        for path in [Path('/etc/fls'), Path('/var/www/fls'), Path('/srv/fls-server'),
                     Path('/srv/fortigate')]:
            if path.exists() or path.is_symlink(): reasons.append('existing_fls_installation'); break
        if any(path.name != 'fls-recovery' for path in Path('/var/lib').glob('fls*')):
            reasons.append('existing_fls_state')
        datadir = Path('/var/lib/mysql')
        if datadir.is_symlink() or (datadir.exists() and (not datadir.is_dir() or next(datadir.iterdir(), None) is not None)):
            reasons.append('existing_database_directory')
        units = _target_capture(['/usr/bin/systemctl', 'list-unit-files', '--no-legend', '--no-pager'], 'target_units')
        if any((name := line.split()[0]) not in CONTROL_UNITS and UNIT.fullmatch(name)
               for line in units.splitlines() if line.split()): reasons.append('existing_fls_units')
        socket_path = Path('/run/mysqld/mysqld.sock')
        if socket_path.exists():
            client = shutil.which('mariadb')
            if not client: reasons.append('existing_database_uninspectable')
            else:
                sql = "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','information_schema','performance_schema'); SELECT User FROM mysql.user WHERE User REGEXP '^fls_';"
                if _target_capture([client, '--no-defaults', '--protocol=socket', '--batch', '--skip-column-names', '--user=root', '-e', sql], 'target_database').strip():
                    reasons.append('existing_application_database')
        for entry in json.loads(_target_capture(['/usr/sbin/ip', '--json', 'address', 'show'], 'target_addresses')):
            for address in entry.get('addr_info', []):
                ip = ipaddress.ip_address(address['local'])
                if not ip.is_loopback and not ip.is_link_local: result['addresses'].append(str(ip))
    except RecoveryError as error:
        reasons.append(error.code)
    except Exception:
        reasons.append('target_inspection_failed')
    result['reasons'] = list(dict.fromkeys(reasons)); result['eligible'] = not result['reasons']
    return result


def _name(value):
    # systemd stores escaped '-' characters as literal "\\x2d" in mount-unit
    # filenames. They are ordinary POSIX bytes, never decoded or restored as
    # mount definitions. Permit only this canonical unit-file namespace.
    escaped_unit = isinstance(value, str) and re.fullmatch(
        r'etc/systemd/system/(?:[A-Za-z0-9_.@:-]|\\x[0-9a-f]{2})+\.mount(?:\.d(?:/[A-Za-z0-9_.@-]+\.conf)?)?/?', value)
    require(isinstance(value, str) and 0 < len(value.encode()) <= 4096 and ('\\' not in value or escaped_unit)
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'archive_path_invalid')
    name = value.rstrip('/')
    require(name and not name.startswith('/') and name == PurePosixPath(name).as_posix()
            and '..' not in PurePosixPath(name).parts, 'archive_path_invalid')
    return name


class _Limited:
    def __init__(self, source, maximum): self.source, self.maximum, self.count = source, maximum, 0
    def read(self, amount=-1):
        if amount < 0: amount = self.maximum - self.count + 1
        data = self.source.read(min(amount, self.maximum - self.count + 1)); self.count += len(data)
        require(self.count <= self.maximum, 'archive_expansion_limit')
        return data


def _system_members(system, mapping):
    entries = {}; total = 0; regular = set()
    for member in system:
        name = _name(member.name)
        require(name not in entries and len(entries) < MAX_MEMBERS, 'archive_duplicate_or_too_many_members')
        require(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'archive_type_forbidden')
        require(not member.issparse() and not (member.isfile() and member.mode & 0o6000), 'archive_privileged_or_sparse_file')
        require(not name.startswith(('srv/', 'root/', 'var/log/', 'var/cache/')), 'runtime_data_in_backup')
        entries[name] = member; total += member.size
        require(total <= MAX_DECODED and 0 <= member.size <= MAX_ARCHIVE, 'archive_expansion_limit')
        if member.isfile():
            details = mapping.get(name)
            require(isinstance(details, dict) and type(details.get('bytes')) is int and details['bytes'] == member.size
                    and SHA.fullmatch(details.get('sha256', '')), 'system_inventory_invalid')
            require(hashlib.file_digest(system.extractfile(member), 'sha256').hexdigest() == details['sha256'], 'system_checksum_mismatch')
            regular.add(name)
    require(regular == set(mapping), 'system_inventory_mismatch')
    for name in entries:
        for parent in PurePosixPath(name).parents:
            if str(parent) in entries: require(entries[str(parent)].isdir(), 'archive_parent_is_not_directory')

    def resolve(name, trail=()):
        require(name not in trail and len(trail) < 40, 'archive_link_cycle')
        member = entries.get(name)
        if member is None: return None
        if not (member.issym() or member.islnk()): return name
        link = member.linkname
        require(isinstance(link, str) and link and '\\' not in link and not any(ord(c) < 32 for c in link), 'archive_link_invalid')
        target = posixpath.normpath((link.lstrip('/') if link.startswith('/') or member.islnk()
                                    else posixpath.join(posixpath.dirname(name), link)))
        require(target != '..' and not target.startswith('../') and not target.startswith('/'), 'archive_link_escape')
        external = EXTERNAL_REFERENCES.get(name) == target or (name == 'etc/localtime' and target.startswith('usr/share/zoneinfo/'))
        if external: return target
        require(target in entries, 'archive_link_dangling')
        resolved = resolve(target, (*trail, name))
        if member.islnk(): require(entries[resolved].isfile(), 'archive_hardlink_target_invalid')
        return resolved
    for name, member in entries.items():
        if member.issym() or member.islnk(): resolve(name)
    return entries, total


def inspect_backup(path, expected_sha256, work):
    """Validate and unpack only into a new private staging directory.

    Uploaded Python is data. Both tar layers are checked in full, including
    members which will never be installed on this target.
    """
    require(isinstance(expected_sha256, str) and SHA.fullmatch(expected_sha256), 'expected_sha256_required')
    work = _root_directory(work); folder = None
    try:
        with _input(path) as source:
            size = os.fstat(source.fileno()).st_size
            require(hashlib.file_digest(source, 'sha256').hexdigest() == expected_sha256, 'backup_checksum_mismatch')
            source.seek(0)
            folder = Path(tempfile.mkdtemp(prefix='validated-', dir=work)); folder.chmod(0o700)
            observed = set(); directories = set(); total = 0
            with gzip.GzipFile(fileobj=source, mode='rb') as compressed:
                limited = _Limited(compressed, MAX_DECODED)
                with tarfile.open(fileobj=limited, mode='r|', ignore_zeros=True) as outer:
                    for member in outer:
                        name = _name(member.name)
                        require(name == 'backup' or name.startswith('backup/'), 'outer_archive_path_invalid')
                        require(member.isfile() or member.isdir(), 'outer_archive_type_forbidden')
                        require(name not in observed and name not in directories and len(observed) + len(directories) < MAX_MEMBERS,
                                'archive_duplicate_or_too_many_members')
                        require(0 <= member.size <= MAX_DECODED, 'archive_expansion_limit')
                        total += member.size; require(total <= MAX_DECODED, 'archive_expansion_limit')
                        for parent in PurePosixPath(name).parents: require(str(parent) not in observed, 'archive_parent_is_not_directory')
                        target = folder / name
                        if member.isdir():
                            require(not any(value.startswith(name + '/') for value in observed) or target.is_dir(), 'outer_archive_path_invalid')
                            target.mkdir(mode=0o700, parents=True, exist_ok=True); directories.add(name)
                        else:
                            require(not target.exists(), 'archive_duplicate_or_too_many_members')
                            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                            space = os.statvfs(work)
                            require(space.f_bavail * space.f_frsize >= member.size + 256 * 1024 ** 2,
                                    'insufficient_staging_space')
                            with target.open('xb') as output:
                                shutil.copyfileobj(outer.extractfile(member), output, 1024 * 1024)
                            target.chmod(0o600); observed.add(name)
                while limited.read(1024 * 1024): pass  # validate gzip footer/CRC too
            payload = folder / 'backup'; manifest = _json(payload / 'MANIFEST.json')
            require(manifest.get('schema') == 'fls-system-backup-v1', 'backup_schema_unsupported')
            files = manifest.get('files'); require(isinstance(files, dict), 'manifest_files_invalid')
            expected = {'backup/MANIFEST.json'}
            for name, details in files.items():
                name = _name(name); expected.add('backup/' + name)
                require(isinstance(details, dict) and type(details.get('bytes')) is int
                        and details['bytes'] >= 0 and SHA.fullmatch(details.get('sha256', '')), 'manifest_files_invalid')
                candidate = payload / name
                require(candidate.is_file() and candidate.stat().st_size == details['bytes']
                        and _sha(candidate) == details['sha256'], 'payload_checksum_mismatch')
            require(observed == expected, 'manifest_files_mismatch')
            require({'system.tar', 'database.sql.gz', 'database-accounts.sql', 'restore-safe.sql',
                     'inventory/file-sha256.json', 'inventory/configuration-digests.json',
                     'inventory/service-identities.json'}.issubset(files), 'required_payload_missing')
            tables = manifest.get('database_tables')
            require(isinstance(tables, list) and 1 <= len(tables) <= 256 and len(set(tables)) == len(tables)
                    and all(isinstance(table, str) and NAME.fullmatch(table) for table in tables), 'manifest_tables_invalid')
            require(manifest.get('configuration_tables') == list(CONFIG_TABLES), 'configuration_scope_unsupported')
            created = manifest.get('created_at_utc')
            require(isinstance(created, str) and len(created) <= 64 and dt.datetime.fromisoformat(created).tzinfo is not None,
                    'manifest_timestamp_invalid')
            with tarfile.open(payload / 'system.tar', 'r:', ignore_zeros=True) as system:
                entries, system_bytes = _system_members(system, _json(payload / 'inventory/file-sha256.json'))
                require(all(name in entries and entries[name].isfile() for name in REQUIRED_SYSTEM), 'required_system_files_missing')
                require('var/www/fls/VERSION' in entries and entries['var/www/fls/VERSION'].isfile(), 'backup_version_missing')
                version = system.extractfile(entries['var/www/fls/VERSION']).read(128).decode('ascii').strip()
            require(re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', version), 'backup_version_invalid')
            with gzip.open(payload / 'database.sql.gz', 'rb') as sql:
                bounded = _Limited(sql, MAX_DECODED)
                while bounded.read(1024 * 1024): pass
        return {'schema': 'fls-recovery-inspection-v1', 'verified': True, 'filename': Path(path).name,
                'bytes': size, 'sha256': expected_sha256, 'version': version,
                'table_count': len(tables), 'configuration_table_count': len(CONFIG_TABLES),
                'created_at_utc': manifest.get('created_at_utc'), 'system_file_count': len(entries),
                'decoded_bytes': total + system_bytes, 'payload_directory': str(payload)}
    except RecoveryError:
        if folder: shutil.rmtree(folder)
        raise
    except Exception as error:
        if folder: shutil.rmtree(folder)
        raise RecoveryError('backup_validation_failed', 'backup_validation') from error


def _validate_plan(plan):
    require(isinstance(plan, dict) and plan.get('schema') == 'fls-recovery-plan-v1'
            and plan.get('mode') == 'single-disk-rehearsal' and isinstance(plan.get('source_machine_sha256'), str)
            and SHA.fullmatch(plan['source_machine_sha256']),
            'recovery_plan_invalid', 'target_check')
    backup = plan.get('backup')
    require(isinstance(backup, dict) and isinstance(backup.get('filename'), str)
            and re.fullmatch(r'fls-system-\d{8}-\d{6}Z\.tar\.gz', backup['filename'])
            and type(backup.get('bytes')) is int and 0 < backup['bytes'] <= MAX_ARCHIVE
            and isinstance(backup.get('sha256'), str) and SHA.fullmatch(backup['sha256']), 'recovery_plan_invalid', 'target_check')


def _trusted_module(runtime, filename, name):
    path = Path(runtime) / 'bin' / filename
    with _input(path, 4 * 1024 ** 2): pass
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification); specification.loader.exec_module(module)
    return module


def _rehearsal_api_contract(route, value, supported):
    """Modern restored applications must report deliberately disabled workers.

    Older backups retain their original application files and UI; their worker
    masks remain the enforcement boundary. Do not claim those UIs understand
    rehearsal mode merely because an API returned HTTP 200.
    """
    require(isinstance(value, dict) and 'error' not in value,
            'restored_api_failed', 'self_test')
    if not supported or route not in ('disk_management', 'maintenance_status'):
        return
    require(value.get('rehearsal') is True and value.get('read_only') is True
            and value.get('reason') == 'recovery_rehearsal'
            and value.get('available') is False and value.get('fresh') is False,
            'restored_rehearsal_api_invalid', 'self_test')
    if route == 'disk_management':
        require(value.get('status') == 'rehearsal' and value.get('error_code') == ''
                and value.get('system') is None and value.get('depot') is None
                and value.get('mirror') is None and value.get('candidates') == []
                and all(value.get(key) is False for key in ('can_migrate', 'can_prepare', 'can_sync')),
                'restored_rehearsal_api_invalid', 'self_test')
    else:
        require(value.get('state') == 'rehearsal' and value.get('can_control') is False,
                'restored_rehearsal_api_invalid', 'self_test')


class _Engine:
    def __init__(self, work, runtime, target, guard, progress, log):
        self.work, self.runtime, self.target = work, runtime, target
        self.guard, self.progress, self.log = guard, progress, log
        self.phase = 'target_check'; self.connection = None; self.test_user = None; self.rehearsal_ui_supported = False

    def stage(self, phase):
        require(phase in PHASES, 'phase_invalid', self.phase)
        self.phase = phase; self.guard(phase); self.progress(phase)

    def run(self, args, **kwargs):
        self.guard(self.phase)
        try:
            return subprocess.run(args, check=True, stdout=self.log, stderr=self.log,
                                  timeout=kwargs.pop('timeout', 300), **kwargs)
        except (OSError, subprocess.SubprocessError) as error:
            raise RecoveryError('recovery_command_failed', self.phase) from error

    def capture(self, args, **kwargs):
        self.guard(self.phase)
        try:
            return subprocess.check_output(args, stderr=self.log, timeout=kwargs.pop('timeout', 30), **kwargs)
        except (OSError, subprocess.SubprocessError) as error:
            raise RecoveryError('recovery_command_failed', self.phase) from error

    def write(self, path, data, mode=0o600):
        self.guard(self.phase); path = Path(path)
        require(not path.is_symlink(), 'target_path_redirected', self.phase)
        descriptor, temporary = tempfile.mkstemp(prefix='.fls-recovery-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data if isinstance(data, bytes) else data.encode()); stream.flush(); os.fsync(stream.fileno())
            os.chmod(temporary, mode); os.replace(temporary, path)
        finally:
            with contextlib.suppress(FileNotFoundError): os.unlink(temporary)

    def stop(self, units):
        self.run(['systemctl', 'stop', *units])
        for unit in units:
            status = dict(line.split('=', 1) for line in self.capture(
                ['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID'], text=True).splitlines() if '=' in line)
            require(status.get('ActiveState') == 'inactive' and status.get('MainPID') == '0', 'service_not_stopped', self.phase)

    @contextlib.contextmanager
    def package_policy(self):
        policy = Path('/usr/sbin/policy-rc.d'); original = None
        if policy.exists() or policy.is_symlink():
            with _input(policy, 65536): pass
            original = self.work / 'original-policy-rc.d'
            require(not original.exists() and not original.is_symlink(), 'package_policy_staging_conflict', self.phase)
            self.guard(self.phase)
            os.link(policy, original, follow_symlinks=False)
        deny = b'#!/bin/sh\n# FLS recovery: package services stay stopped.\nexit 101\n'
        try: self.write(policy, deny, 0o755)
        except Exception:
            if original is not None: original.unlink()
            raise
        try: yield
        finally:
            self.guard(self.phase)
            with _input(policy, 65536) as stream: require(stream.read() == deny, 'package_policy_changed', self.phase)
            if original is None: policy.unlink()
            else: os.replace(original, policy)

    def packages(self):
        folder = self.runtime / 'guest-debs'; index = folder / 'Packages'
        with _input(index, MAX_JSON) as stream: text = stream.read().decode()
        packages = set()
        for paragraph in text.split('\n\n'):
            if not paragraph.strip(): continue
            fields = {}
            for line in paragraph.splitlines():
                if line and not line[0].isspace() and ': ' in line:
                    key, value = line.split(': ', 1); require(key not in fields, 'runtime_package_index_invalid', self.phase); fields[key] = value
            name = fields.get('Filename', '').removeprefix('./')
            require(re.fullmatch(r'[A-Za-z0-9%+_.:~=-]+\.deb', name) and fields.get('Size', '').isdigit()
                    and SHA.fullmatch(fields.get('SHA256', '')), 'runtime_package_index_invalid', self.phase)
            package = folder / name
            require(package.stat().st_size == int(fields['Size']) and _sha(package) == fields['SHA256'], 'runtime_package_checksum_mismatch', self.phase)
            packages.add(fields.get('Package'))
        require(set(PACKAGES).issubset(packages), 'runtime_packages_missing', self.phase)
        apt = self.work / 'apt'
        for name in ['lists/partial', 'archives/partial', 'log']: (apt / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        sources = apt / 'offline.list'; self.write(sources, 'deb [trusted=yes] file:' + str(folder) + ' ./\n')
        config = apt / 'isolated.conf'; self.write(config, 'Dir::Etc::parts "-";\nDir::Etc::main "-";\nDir::Etc::sourceparts "-";\nDir::Etc::sourcelist ' + json.dumps(str(sources)) + ';\n')
        environment = {**os.environ, 'APT_CONFIG': str(config), 'DEBIAN_FRONTEND': 'noninteractive'}
        command = ['apt-get', '-o', 'Dir::State::lists=' + str(apt / 'lists'), '-o', 'Dir::Cache::archives=' + str(apt / 'archives'),
                   '-o', 'Dir::Log=' + str(apt / 'log'), '-o', 'APT::Sandbox::User=root', '-o', 'Acquire::Languages=none',
                   '-o', 'Acquire::Retries=0', '-o', 'DPkg::Lock::Timeout=30', '-o', 'Dpkg::Options::=--force-confold']
        with self.package_policy():
            self.run(command + ['update'], env=environment, timeout=300)
            self.run(command + ['--yes', '--fix-broken', '--no-remove', '--no-install-recommends', 'install', *PACKAGES], env=environment, timeout=1200)
        self.stop(['nginx.service', 'php8.3-fpm.service'])

    def identities(self, payload):
        identities = _json(payload / 'inventory/service-identities.json')
        groups = identities.get('groups'); users = identities.get('users')
        require(isinstance(groups, list) and isinstance(users, list) and len(groups) < 200 and len(users) < 100, 'service_identities_invalid', self.phase)
        # Validate the complete inventory before creating even its first group.
        # Source root and ordinary login identities must never be remapped.
        for group in groups:
            require(isinstance(group, dict) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', group.get('name', ''))
                    and type(group.get('gid')) is int and 0 < group['gid'] < 2 ** 31
                    and isinstance(group.get('members'), list) and all(isinstance(name, str) for name in group['members']),
                    'service_identities_invalid', self.phase)
        for user in users:
            require(isinstance(user, dict) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user.get('name', ''))
                    and (user['name'].startswith('fls') or user['name'] in ('mysql', 'nginx', 'www-data', 'syslog'))
                    and type(user.get('uid')) is int and 0 < user['uid'] < 2 ** 31
                    and type(user.get('gid')) is int and user['gid'] in {group['gid'] for group in groups},
                    'service_identities_invalid', self.phase)
        require(len({item['gid'] for item in groups}) == len(groups) and len({item['name'] for item in groups}) == len(groups)
                and len({item['uid'] for item in users}) == len(users) and len({item['name'] for item in users}) == len(users),
                'service_identities_invalid', self.phase)
        names = {}
        for group in groups:
            require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', group.get('name', '')) and type(group.get('gid')) is int
                    and isinstance(group.get('members'), list), 'service_identities_invalid', self.phase)
            names[group['gid']] = group['name']
            try: grp.getgrnam(group['name'])
            except KeyError: self.run(['groupadd', '--system', group['name']])
        for user in users:
            require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user.get('name', '')) and user.get('gid') in names
                    and type(user.get('uid')) is int and user['name'] not in ('root', 'ubuntu'), 'service_identities_invalid', self.phase)
            try: pwd.getpwnam(user['name'])
            except KeyError: self.run(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--gid', names[user['gid']], user['name']])
        service_names = {user['name'] for user in users}
        for group in groups:
            for member in group['members']:
                if member in service_names: self.run(['usermod', '--append', '--groups', group['name'], '--', member])
        return identities

    def files(self, payload, identities):
        uid = {item['uid']: pwd.getpwnam(item['name']).pw_uid for item in identities['users']}
        gid = {item['gid']: grp.getgrnam(item['name']).gr_gid for item in identities['groups']}
        parent = Path('/var/www'); require(not parent.is_symlink(), 'target_path_redirected', self.phase)
        parent.mkdir(mode=0o755, exist_ok=True); parent.chmod(0o755)
        with tarfile.open(payload / 'system.tar', 'r:', ignore_zeros=True) as system:
            members = system.getmembers(); selected = [member for member in members if any(member.name == prefix or member.name.startswith(prefix + '/') for prefix in RESTORE_PREFIXES)
                and member.name not in ('etc/fls/storage.json', 'etc/fls/mirror.json')]
            require(selected, 'system_files_missing', self.phase)
            listing = self.work / 'selected-files.list'
            self.write(listing, b''.join(member.name.encode() + b'\0' for member in selected))
            self.run(['tar', '--ignore-zeros', '--acls', '--xattrs', '--numeric-owner', '--no-recursion', '--null', '-xpf', str(payload / 'system.tar'), '-C', '/', '-T', str(listing)])
            for member in selected:
                path = Path('/') / member.name; info = path.lstat()
                os.chown(path, uid.get(info.st_uid, info.st_uid), gid.get(info.st_gid, info.st_gid), follow_symlinks=False)
                if not member.issym(): _remap_acl(path, uid, gid)
            # Install source unit definitions below the /etc masks. No wants,
            # old mount units or HDD dependency drop-ins are installed.
            unit_folder = Path('/usr/local/lib/systemd/system'); unit_folder.mkdir(parents=True, exist_ok=True)
            for member in members:
                parts = PurePosixPath(member.name).parts
                if len(parts) == 4 and parts[:3] == ('etc', 'systemd', 'system') and member.isfile() and UNIT.fullmatch(parts[-1]) and parts[-1] not in CONTROL_UNITS | {WEB_UNIT}:
                    name = parts[-1]; self.write(unit_folder / name, system.extractfile(member).read(), 0o644)
                    mask = Path('/etc/systemd/system') / name
                    require(not mask.exists() and not mask.is_symlink(), 'unexpected_existing_worker_unit', self.phase)
                    mask.symlink_to('/dev/null')
        self.run(['systemctl', 'daemon-reload'])

    def database(self, payload, backup):
        self.stop(['mariadb.service'])
        for path, mode in [('/srv/fls-server', 0o755), ('/srv/fls-server/database', 0o711)]:
            directory = Path(path); directory.mkdir(parents=True, exist_ok=True); directory.chmod(mode)
        datadir = Path('/srv/fls-server/database/mysql'); original = Path('/var/lib/mysql')
        require(not datadir.exists() and not datadir.is_symlink(), 'existing_database_directory', self.phase)
        if original.exists(): shutil.move(original, datadir)
        else:
            datadir.mkdir(mode=0o750); shutil.chown(datadir, user='mysql', group='mysql')
            self.run(['mariadb-install-db', '--user=mysql', '--datadir=' + str(datadir)])
        shutil.chown(datadir, user='mysql', group='mysql')
        self.write('/etc/mysql/mariadb.conf.d/90-fls-recovery.cnf', '[mysqld]\ndatadir=' + str(datadir) + '\nskip-networking\ninnodb_buffer_pool_size=128M\nmax_connections=20\nlocal-infile=0\n', 0o644)
        self.run(['systemctl', 'start', 'mariadb.service'])
        import pymysql
        self.connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', autocommit=True, charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
        query = lambda sql, args=(): backup.query(self.connection, sql, args)
        require(query('SELECT @@datadir path')[0]['path'].rstrip('/') == str(datadir), 'database_directory_mismatch', self.phase)
        require(not query("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','information_schema','performance_schema')"), 'existing_application_database', self.phase)
        self.guard(self.phase); query('CREATE DATABASE fls CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'); self.connection.select_db('fls')
        self._sql(payload / 'database.sql.gz', compressed=True, database=True)
        manifest = _json(payload / 'MANIFEST.json')
        tables = {next(iter(row.values())) for row in query('SHOW TABLES FROM fls')}
        require(tables == set(manifest['database_tables']), 'restored_tables_mismatch', self.phase)
        require(backup.configuration_digest(self.connection) == _json(payload / 'inventory/configuration-digests.json'), 'restored_configuration_mismatch', self.phase)
        require(all(query('SELECT COUNT(*) n FROM fls.' + backup.identifier(table))[0]['n'] == 0 for table in tables - set(CONFIG_TABLES)), 'runtime_data_present', self.phase)
        with tarfile.open(payload / 'system.tar') as system: backup.verify_keys_and_secrets(system, self.connection)
        self._sql(payload / 'database-accounts.sql')
        for filename in manifest['database_credential_files_covered']:
            require(isinstance(filename, str) and re.fullmatch(r'[A-Za-z0-9_-]+\.json', filename), 'credential_name_invalid', self.phase)
            credential = _json(Path('/etc/fls') / filename, 16384)
            login = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user=credential['user'], password=credential['password'], database='fls')
            try:
                with login.cursor() as cursor: cursor.execute('SELECT 1'); require(cursor.fetchone() == (1,), 'restored_account_login_failed', self.phase)
            finally: login.close()
        self._sql(payload / 'restore-safe.sql', database=True)
        return tables

    def _sql(self, path, compressed=False, database=False):
        self.guard(self.phase)
        command = ['mariadb', '--no-defaults', '--protocol=socket', '--user=root', '--binary-mode']
        if database: command.append('--database=fls')
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)
        try:
            with (gzip.open(path, 'rb') if compressed else path.open('rb')) as source:
                bounded = _Limited(source, MAX_DECODED)
                while chunk := bounded.read(1024 * 1024): process.stdin.write(chunk)
            process.stdin.close(); require(process.wait(timeout=300) == 0, 'database_restore_failed', self.phase)
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired: process.kill(); process.wait()

    def storage(self, backup):
        directories = [('raw', 'syslog', 'adm', 0o750), ('queue', 'syslog', 'adm', 0o750),
            ('metrics', 'syslog', 'adm', 0o750), ('archive', 'fls-integrity', 'adm', 0o750),
            ('archive/manifests', 'fls-integrity', 'fls-integrity', 0o750), ('backups', 'root', 'root', 0o700), ('db-dumps', 'root', 'root', 0o700)]
        for name, user, group, mode in directories:
            path = Path('/srv/fls-server') / name; path.mkdir(mode=mode, parents=True, exist_ok=True)
            shutil.chown(path, user=user, group=group); path.chmod(mode)
        for name in ['raw', 'metrics', 'archive', 'archive/manifests']:
            self.run(['setfacl', '-m', 'u:fls-web:r-x', '/srv/fls-server/' + name])
        for name in ['/var/lib/fls-maintenance', '/var/lib/fls-power']:
            path = Path(name); path.mkdir(mode=0o700, exist_ok=True); path.chmod(0o700)
        self.write('/var/lib/fls-maintenance/paused', b'', 0o600)
        self.write('/etc/fls/storage.json', json.dumps({'schema': 2, 'mode': 'system-root',
            'root_uuid': self.target['root_uuid'], 'device_identity': self.target['root_identity']}), 0o644)
        storage = _trusted_module(self.runtime, 'fls_storage.py', 'fls_recovery_trusted_storage')
        storage.storage_state()
        self.paused(backup)

    def paused(self, backup):
        query = lambda sql: backup.query(self.connection, sql)
        require(query('SELECT requested_mode FROM fls.maintenance_requests WHERE id=1')[0]['requested_mode'] == 'paused', 'maintenance_not_paused', self.phase)
        require(query('SELECT action FROM fls.power_requests WHERE id=1')[0]['action'] == '', 'pending_power_request', self.phase)
        for table, column in [('timestamp_settings', 'enabled'), ('archive_export_settings', 'packaging_enabled'), ('archive_destinations', 'enabled')]:
            require(all(row[column] == 0 for row in query('SELECT ' + column + ' FROM fls.' + table)), 'external_work_enabled', self.phase)
        require(all(query('SELECT COUNT(*) n FROM fls.' + table)[0]['n'] == 1 for table in backup.SEED_TABLES), 'recovery_seed_missing', self.phase)

    def replay(self):
        recovery = _trusted_module(self.runtime, 'provision-disk-management.py', 'fls_recovery_trusted_disk_initializer')
        class Journal:
            def __init__(self, folder): self.folder = Path(folder)
            def read(self):
                value = _json(self.folder / 'attempt.json', 16384)
                require(value == {'schema': 1, 'high_water': 0, 'last': None}, 'fresh_journal_invalid', 'replay')
                require(stat.S_IMODE((self.folder / 'attempt.json').stat().st_mode) == 0o600, 'fresh_journal_invalid', 'replay')
                return value
        adapter = types.SimpleNamespace(Journal=Journal, safe_json=lambda path, maximum=16384: _json(path, maximum))
        self.guard(self.phase); self.connection.select_db('fls')
        recovery.initialize_recovery_state(self.connection, adapter)

    def web(self):
        for name in ['/var/lib/fls', '/var/lib/fls/sessions', '/var/cache/fls']:
            path = Path(name); path.mkdir(mode=0o700, parents=True, exist_ok=True); path.chmod(0o700); shutil.chown(path, user='fls-web', group='fls-web')
        published = Path('/var/lib/fls-recovery-download'); published.mkdir(mode=0o750, exist_ok=True)
        published.chmod(0o750); shutil.chown(published, user='root', group='fls-web')
        Path('/run/php').mkdir(mode=0o755, exist_ok=True)
        self.run(['php-fpm8.3', '-t']); self.run(['systemctl', 'start', 'php8.3-fpm.service'])
        for filename in ['cert.pem', 'key.pem']:
            with _input(self.work / filename, 65536): pass
        folder = Path('/etc/fls/recovery-web'); folder.mkdir(mode=0o700, exist_ok=True); folder.chmod(0o700)
        for filename in ['cert.pem', 'key.pem']:
            with _input(self.work / filename, 65536) as source: self.write(folder / filename, source.read())
        logs = Path('/var/lib/fls-recovery/web'); logs.mkdir(mode=0o700, parents=True, exist_ok=True); logs.chmod(0o700)
        config = folder / 'nginx.conf'
        self.write(config, 'user www-data;\npid /run/fls-rehearsal-nginx.pid;\nevents {}\nhttp {\ninclude /etc/nginx/mime.types;\ndefault_type application/octet-stream;\naccess_log off;\nerror_log ' + str(logs / 'nginx-error.log') + ';\nserver {\nlisten 8443 ssl;\nserver_name _;\nssl_certificate ' + str(folder / 'cert.pem') + ';\nssl_certificate_key ' + str(folder / 'key.pem') + ';\nroot /var/www/fls/public;\nindex index.php;\nlocation / { try_files $uri $uri/ /index.php?$query_string; }\nlocation ~ \\.php$ {\ninclude /etc/nginx/fastcgi_params;\nfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\nfastcgi_param HTTPS on;\nfastcgi_param FLS_RECOVERY_REHEARSAL 1;\nfastcgi_pass unix:/run/php/fls.sock;\n}\n}\n}\n')
        self.run(['nginx', '-t', '-c', str(config)])
        self.write(Path('/etc/systemd/system') / WEB_UNIT,
            '[Unit]\nDescription=FLS paused recovery rehearsal web\nAfter=network.target php8.3-fpm.service\nRequires=php8.3-fpm.service\nConditionPathExists=/var/lib/fls-maintenance/paused\n[Service]\nType=simple\nExecStart=/usr/sbin/nginx -c ' + str(config) + ' -g "daemon off;"\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n', 0o644)
        self.run(['systemctl', 'daemon-reload']); self.run(['systemctl', 'enable', '--now', 'php8.3-fpm.service', WEB_UNIT])
        address = next((value for value in self.target['addresses'] if ipaddress.ip_address(value).version == 4), '127.0.0.1')
        return 'https://' + address + ':8443/'

    def self_test(self, backup):
        username = 'fls-rehearsal-' + secrets.token_hex(8); password = secrets.token_urlsafe(32)
        hashed = self.capture(['php', '-r', '$p=stream_get_contents(STDIN);echo password_hash($p,PASSWORD_ARGON2ID);'], input=password.encode(), timeout=180).decode()
        self.guard(self.phase)
        backup.query(self.connection, "INSERT INTO fls.users(username,password_hash,role,enabled,must_change,session_version,updated_at) VALUES(%s,%s,'admin',1,0,0,UTC_TIMESTAMP())", (username, hashed))
        self.test_user = username
        jar = http.cookiejar.CookieJar()
        try:
            context = ssl.create_default_context(cafile=str(self.work / 'cert.pem'))
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
            base = 'https://127.0.0.1:8443/'
            page = opener.open(base, timeout=120).read(8 * 1024 ** 2).decode()
            csrf = re.search(r'name="_csrf" value="([a-f0-9]{64})"', page)
            require(csrf is not None, 'login_csrf_missing', self.phase)
            data = urllib.parse.urlencode({'mode': 'login', '_csrf': csrf[1], 'username': username, 'password': password}).encode()
            page = opener.open(urllib.request.Request(base, data=data), timeout=120).read(8 * 1024 ** 2).decode()
            require(username in page and 'name="mode" value="login"' not in page, 'https_login_failed', self.phase)
            for asset, allowed in [('app.css', {'text/css'}), ('app.js', {'application/javascript', 'text/javascript'})]:
                with opener.open(base + 'assets/' + asset, timeout=120) as response:
                    require(response.status == 200 and response.headers.get_content_type() in allowed
                            and len(response.read(200)) > 0, 'restored_asset_mime_invalid', self.phase)
            self.rehearsal_ui_supported = Path('/var/www/fls/app/recovery-rehearsal.php').is_file()
            for route in ['system_backups', 'disk_management', 'power_status', 'maintenance_status']:
                with opener.open(base + 'api.php?route=' + route, timeout=120) as response:
                    value = json.loads(response.read(8 * 1024 ** 2))
                    require(response.status == 200, 'restored_api_failed', self.phase)
                    _rehearsal_api_contract(route, value, self.rehearsal_ui_supported)
        finally:
            self.guard(self.phase)
            backup.query(self.connection, 'DELETE FROM fls.users WHERE username=%s', (username,)); self.test_user = None
            for cookie in jar:
                if cookie.name == 'fls_session' and re.fullmatch(r'[A-Za-z0-9,-]{16,256}', cookie.value):
                    path = Path('/var/lib/fls/sessions') / ('sess_' + cookie.value)
                    if path.is_file() and not path.is_symlink(): path.unlink()
        self.paused(backup)
        collector = self.capture(['systemctl', 'show', 'fortigate-collector.service', '-p', 'ActiveState', '-p', 'MainPID'], text=True)
        values = dict(line.split('=', 1) for line in collector.splitlines() if '=' in line)
        require(values.get('ActiveState') == 'inactive' and values.get('MainPID') == '0', 'collector_not_stopped', self.phase)


def restore(archive_path, plan, work, runtime, guard, progress):
    """Restore on a new, explicitly leased target. Never invoke on production."""
    _validate_plan(plan)
    require(callable(guard) and callable(progress), 'callbacks_required', 'target_check')
    guard('target_check')
    target = inspect_target()
    if not target['eligible']:
        # The bootstrap stores exception chains only in its root-private log.
        # Public errors remain a fixed code, while safe probe reasons survive.
        reasons = [code for code in target.get('reasons', []) if isinstance(code, str) and re.fullmatch(r'[a-z0-9_]{1,80}', code)]
        raise RecoveryError('target_not_fresh', 'target_check') from ValueError('target reasons: ' + ','.join(reasons))
    require(target['machine_sha256'] != plan['source_machine_sha256'], 'source_host_forbidden', 'target_check')
    require(os.geteuid() == 0, 'root_required', 'target_check')
    work = _root_directory(work); runtime = Path(runtime).absolute()
    require(runtime.resolve(strict=True) == runtime and not re.search(r'[\s";]', str(work) + str(runtime)), 'runtime_path_unsafe', 'target_check')
    for helper in ['system-backup.py', 'provision-disk-management.py', 'fls_storage.py']:
        with _input(runtime / 'bin' / helper, 4 * 1024 ** 2): pass
    descriptor = os.open(work / 'engine.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'engine_lock_unsafe', 'target_check')
        try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error: raise RecoveryError('recovery_already_running', 'target_check') from error
        log_fd = os.open(work / 'engine-private.log', os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(log_fd, 'a', encoding='utf-8') as log:
            info = os.fstat(log.fileno())
            require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    'engine_log_unsafe', 'target_check')
            engine = _Engine(work, runtime, target, guard, progress, log)
            try:
                engine.stage('backup_validation')
                summary = inspect_backup(archive_path, plan['backup']['sha256'], work)
                require(summary['bytes'] == plan['backup']['bytes'], 'backup_size_mismatch', engine.phase)
                require(target['free_bytes'] >= summary['decoded_bytes'] + 4 * GIB, 'insufficient_restore_space', engine.phase)
                payload = Path(summary['payload_directory'])
                engine.stage('packages'); engine.packages()
                backup = _trusted_module(runtime, 'system-backup.py', 'fls_recovery_trusted_backup')
                require(tuple(backup.CONFIG_TABLES) == CONFIG_TABLES, 'trusted_scope_mismatch', engine.phase)
                engine.stage('identities'); identities = engine.identities(payload)
                engine.stage('files'); engine.files(payload, identities)
                engine.stage('database'); tables = engine.database(payload, backup)
                engine.stage('storage'); engine.storage(backup)
                engine.stage('replay'); engine.replay()
                engine.stage('web'); url = engine.web()
                engine.stage('self_test'); engine.self_test(backup)
                engine.stage('complete')
                return {'ok': True, 'phase': 'complete', 'table_count': len(tables), 'version': summary['version'],
                        'web_url': url, 'mode': 'single-disk-rehearsal', 'checks': {
                        'payload_and_system_hashes': True, 'configuration_rows_exact': True,
                        'original_database_accounts': True, 'keys_and_secrets': True,
                        'fresh_replay_state': True, 'target_storage_identity': True,
                        'https_certificate_verified': True, 'administrator_login': True,
                        'read_only_api_routes': 4, 'rehearsal_ui_supported': engine.rehearsal_ui_supported,
                        'css_and_javascript_mime': True, 'maintenance_paused': True,
                        'collector_stopped': True, 'external_work_disabled': True,
                        'test_account_removed': True, 'physical_boot_tested_by_engine': False,
                        'provider_or_ftp_called': False}}
            except Exception as error:
                traceback.print_exc(file=log); log.flush()
                if isinstance(error, RecoveryError):
                    error.phase = engine.phase
                    raise
                raise RecoveryError('recovery_failed', engine.phase) from error
            finally:
                if engine.connection is not None: engine.connection.close()
    finally:
        os.close(descriptor)
