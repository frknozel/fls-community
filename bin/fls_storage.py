#!/usr/bin/python3
"""Fail-closed FLS storage checks, including explicitly configured system disks.

Without storage.json the historical separate-data-mount requirement is retained.
System-root and hybrid modes pin the root filesystem UUID and stable physical identity.
Schema 1 retains its strict NAA WWN contract. Schema 2 also accepts verified
sysfs WWIDs and serials, for ordinary virtual disks and NVMe devices.
Hybrid mode additionally pins a separate HDD and each operational bind mount.
Checks use trusted udev/sysfs metadata so PrivateDevices does not require access
or exceptions for raw block device nodes.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import uuid

CONFIG = Path('/etc/fls/storage.json')
DATA = Path('/srv/fls-server')
UDEV = Path('/run/udev/data')
SYSFS = Path('/sys/dev/block')
DEPOT = Path('/srv/fls-storage')
PUBLISHED = Path('/var/lib/fls-recovery-download')
MOUNTINFO = Path('/proc/self/mountinfo')
DUMPS = DATA / 'db-dumps'


class StorageError(RuntimeError):
    pass


def trusted_read(path, limit=65536, owner=0):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_mode & 0o022 or info.st_size > limit):
            raise StorageError('Storage metadata ownership or permissions are invalid')
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise StorageError('Storage metadata is too large')
        return raw.decode('utf-8')


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def validate_identity(value):
    if not isinstance(value, dict) or set(value) != {'kind', 'value'}:
        raise StorageError('FLS physical identity schema is invalid')
    kind, token = value['kind'], value['value']
    if not (isinstance(token, str) and 1 <= len(token) <= 256 and token == token.strip()
            and all(32 <= ord(char) <= 126 for char in token)):
        raise StorageError('FLS physical identity is invalid')
    if kind == 'wwn':
        valid = re.fullmatch(r'0x[0-9a-f]{16}', token)
    elif kind == 'wwid':
        valid = re.fullmatch(r'(?:naa|eui|t10|nvme)\.[A-Za-z0-9_.:+ -]{1,240}', token)
    elif kind == 'serial':
        valid = re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:+ -]{0,127}', token)
    else:
        valid = False
    if not valid:
        raise StorageError('FLS physical identity is invalid')
    return value


def config_identity(config, depot=False):
    if config['schema'] == 1:
        return {'kind': 'wwn', 'value': config['depot_wwn' if depot else 'device_wwn']}
    return config['depot_identity' if depot else 'device_identity']


def validate_config(value):
    if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] not in (1, 2):
        raise StorageError('FLS storage configuration schema is invalid')
    identity_key = 'device_wwn' if value['schema'] == 1 else 'device_identity'
    depot_key = 'depot_wwn' if value['schema'] == 1 else 'depot_identity'
    common = {'schema', 'mode', 'root_uuid', identity_key}
    hybrid = {'depot_uuid', depot_key, 'depot_path'}
    if 'queue_location' in value:
        if value.get('mode') != 'hybrid' or value['queue_location'] != 'system':
            raise StorageError('FLS queue location is invalid')
        hybrid.add('queue_location')
    if (value.get('mode') not in ('system-root', 'hybrid')
            or set(value) != common | (hybrid if value['mode'] == 'hybrid' else set())):
        raise StorageError('FLS storage configuration schema is invalid')
    if not canonical_uuid(value['root_uuid']):
        raise StorageError('FLS storage identity is invalid')
    validate_identity(config_identity(value))
    if value['mode'] == 'hybrid':
        if value['depot_path'] != '/srv/fls-storage' or not canonical_uuid(value['depot_uuid']):
            raise StorageError('FLS depot path or UUID is invalid')
        validate_identity(config_identity(value, True))
        if value['schema'] == 2 and value.get('queue_location') != 'system':
            raise StorageError('FLS community queue must remain on the system disk')
        if value['root_uuid'] == value['depot_uuid'] or config_identity(value) == config_identity(value, True):
            raise StorageError('FLS depot must be a different physical disk')
    return value


def _properties(dev):
    device = '{}:{}'.format(os.major(dev), os.minor(dev))
    properties = {}
    for line in trusted_read(UDEV / ('b' + device)).splitlines():
        if line.startswith('E:') and '=' in line:
            key, value = line[2:].split('=', 1)
            if key in properties:
                raise StorageError('Duplicate filesystem identity metadata')
            properties[key] = value
    block = (SYSFS / device).resolve(strict=True)
    # Plain partitions only; LVM, RAID, loop and whole-device filesystems fail.
    if not re.fullmatch(r'[1-9][0-9]*', trusted_read(block / 'partition').strip()):
        raise StorageError('FLS filesystem is not a disk partition')
    disk = block.parent
    if (disk / 'partition').exists() or not (disk / 'device').is_dir():
        raise StorageError('FLS physical disk metadata is invalid')
    return device, disk, properties


def _physical_identity(disk, properties):
    wwids = []
    for candidate in (disk / 'device/wwid', disk / 'wwid'):
        try:
            value = trusted_read(candidate, 4096).strip()
        except FileNotFoundError:
            continue
        if value:
            wwids.append(value)
    if len(set(wwids)) > 1:
        raise StorageError('FLS physical WWID metadata disagrees')
    wwid = wwids[0] if wwids else ''
    if wwid:
        identity = ({'kind': 'wwn', 'value': '0x' + wwid[4:]}
                    if re.fullmatch(r'naa\.[a-f0-9]{16}', wwid)
                    else {'kind': 'wwid', 'value': wwid})
        return validate_identity(identity)
    serials = []
    for candidate in (disk / 'device/serial', disk / 'serial'):
        try:
            value = trusted_read(candidate, 4096).strip()
        except FileNotFoundError:
            continue
        if value:
            serials.append(value)
    if not serials or len(set(serials)) != 1:
        raise StorageError('FLS stable physical identity is unavailable')
    serial = serials[0]
    if properties.get('ID_SERIAL_SHORT', serial) != serial:
        raise StorageError('FLS physical serial metadata disagrees')
    return validate_identity({'kind': 'serial', 'value': serial})


def discover_identity(dev):
    """Read a plain ext4 filesystem and kernel-backed disk identity; no commands."""
    device, disk, properties = _properties(dev)
    identifier = properties.get('ID_FS_UUID')
    if not canonical_uuid(identifier) or properties.get('ID_FS_TYPE') != 'ext4':
        raise StorageError('FLS ext4 filesystem UUID is unavailable')
    return {'uuid': identifier, 'device': device, 'disk': disk,
            'identity': _physical_identity(disk, properties)}


def filesystem_identity(dev, expected_uuid, expected_identity):
    legacy = isinstance(expected_identity, str)
    expected = validate_identity({'kind': 'wwn', 'value': expected_identity} if legacy else expected_identity)
    device, disk, properties = _properties(dev)
    if not canonical_uuid(expected_uuid) or properties.get('ID_FS_UUID') != expected_uuid:
        raise StorageError('FLS filesystem UUID does not match')
    if not legacy and properties.get('ID_FS_TYPE') != 'ext4':
        raise StorageError('FLS filesystem type does not match')
    if _physical_identity(disk, properties) != expected:
        raise StorageError('FLS physical disk identity does not match')
    return device, disk


def directory(path, device=None, trusted=False, private=False):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.resolve(strict=True) != path
            or device is not None and info.st_dev != device
            or trusted and (info.st_uid != 0 or info.st_mode & 0o022)
            or private and (info.st_uid != 0 or info.st_mode & 0o077)):
        raise StorageError('FLS data directory is missing or redirected')
    return info


def mount_points(required):
    # Kernel mountinfo remains available inside systemd PrivateDevices namespaces.
    # proc/self files belong to the service UID; only the kernel writes them.
    # ProtectSystem/ReadWritePaths can legitimately stack mounts at one path.
    points = {}
    for line in trusted_read(MOUNTINFO, 1024 * 1024, owner=os.geteuid()).splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields[6:]:
            raise StorageError('FLS mount metadata is invalid')
        decode = lambda value: re.sub(r'\\(040|011|012|134)',
                                      lambda match: chr(int(match[1], 8)), value)
        point = decode(fields[4])
        if point not in required:
            continue
        if not fields[0].isdigit() or not fields[1].isdigit():
            raise StorageError('FLS mount identity is invalid')
        separator = fields.index('-', 6)
        if len(fields) != separator + 4:
            raise StorageError('FLS mount metadata is invalid')
        super_options = set(fields[separator + 3].split(','))
        if ('rw' in super_options) == ('ro' in super_options):
            raise StorageError('FLS filesystem access metadata is invalid')
        points.setdefault(point, []).append({
            'id': fields[0], 'parent': fields[1],
            'device': fields[2], 'root': decode(fields[3]),
            'super_read_only': 'ro' in super_options})
    visible = {}
    for point, mounts in points.items():
        if len({entry['id'] for entry in mounts}) != len(mounts):
            raise StorageError('FLS mount metadata is ambiguous')
        # A stacked mount is parented to the mount immediately below it. The
        # only visible entry is the one with no child at this same mountpoint.
        parents = {entry['parent'] for entry in mounts}
        top = [entry for entry in mounts if entry['id'] not in parents]
        if len(top) != 1:
            raise StorageError('FLS mount metadata is ambiguous')
        visible[point] = top[0]
    return visible


def system_queue(root, root_device, points):
    queue = DATA / 'queue'
    info = directory(queue, root.st_dev)
    try:
        owner = pwd.getpwnam('syslog').pw_uid
        group = grp.getgrnam('adm').gr_gid
    except KeyError as error:
        raise StorageError('FLS queue service identity is unavailable') from error
    if (info.st_uid != owner or info.st_gid != group
            or stat.S_IMODE(info.st_mode) != 0o750):
        raise StorageError('FLS system queue ownership or permissions are invalid')
    # Systemd may rebind this exact path to make it writable. A bind from
    # another directory on the same SSD must never authorize the queue.
    for path in (queue, *queue.parents):
        mounted = points.get(str(path))
        if mounted:
            actual_root = Path(mounted['root']) / queue.relative_to(path)
            if mounted['device'] != root_device or actual_root != queue:
                raise StorageError('FLS system queue mount is redirected')
            break


def hybrid_state(config, root, root_device, root_disk):
    depot = directory(DEPOT, trusted=True)
    if depot.st_dev == root.st_dev:
        raise StorageError('FLS depot mount is missing')
    depot_device, depot_disk = filesystem_identity(
        depot.st_dev, config['depot_uuid'], config['depot_wwn'] if config['schema'] == 1 else config_identity(config, True))
    if depot_disk == root_disk:
        raise StorageError('FLS depot must be a different physical disk')
    for name in ('FLS-Logs', 'FLS-Backups'):
        directory(DEPOT / name, depot.st_dev, trusted=True)
    directory(DEPOT / 'DB-Dump', depot.st_dev, trusted=True, private=True)
    queue_location = config.get('queue_location', 'depot')
    names = ('raw', 'archive', 'metrics') if queue_location == 'system' else ('raw', 'archive', 'queue', 'metrics')
    bindings = [(DEPOT / 'FLS-Logs' / name, DATA / name) for name in names]
    bindings += [(DEPOT / 'FLS-Backups/staging', DATA / 'backups'),
                 (DEPOT / 'FLS-Backups/published', PUBLISHED)]
    if config['schema'] == 2:
        bindings.append((DEPOT / 'DB-Dump', DUMPS))
    required = {str(DEPOT)} | {str(target) for _, target in bindings}
    if queue_location == 'system':
        required |= {str(DATA / 'queue')} | {str(path) for path in (DATA / 'queue').parents}
    points = mount_points(required)
    if queue_location == 'system':
        system_queue(root, root_device, points)
    mounted = points.get(str(DEPOT), {})
    if mounted.get('device') != depot_device or mounted.get('root') != '/':
        raise StorageError('FLS depot partition mount is missing')
    # ProtectSystem may make a service's depot mount read-only while selected
    # operational binds stay writable. Only the filesystem-wide superblock
    # flag identifies a genuinely read-only depot, including ext4 error remounts.
    if mounted['super_read_only']:
        raise StorageError('FLS depot filesystem is read-only')
    for source, target in bindings:
        actual_source = directory(source, depot.st_dev)
        actual_target = directory(target, depot.st_dev)
        if (actual_target.st_ino != actual_source.st_ino
                or points.get(str(target), {}).get('device') != depot_device
                or points[str(target)]['root'] != '/' + str(source.relative_to(DEPOT))):
            raise StorageError('FLS operational bind mount is missing or mismatched')
    return {'mode': 'hybrid', 'data_path': str(DATA),
            'root_uuid': config['root_uuid'], 'device_identity': config_identity(config),
            'device_wwn': config_identity(config)['value'] if config_identity(config)['kind'] == 'wwn' else '',
            'device': root_device, 'depot_uuid': config['depot_uuid'],
            'depot_wwn': config_identity(config, True)['value'] if config_identity(config, True)['kind'] == 'wwn' else '',
            'depot_identity': config_identity(config, True), 'depot_path': str(DEPOT),
            'depot_device': depot_device, 'queue_location': queue_location}


def storage_state():
    try:
        raw = trusted_read(CONFIG, 4096)
    except FileNotFoundError:
        if not os.path.ismount(DATA):
            raise StorageError('Dedicated FLS data mount is missing') from None
        return {'mode': 'dedicated', 'data_path': str(DATA)}
    except (OSError, UnicodeError) as error:
        raise StorageError('FLS storage configuration cannot be read') from error
    try:
        config = validate_config(json.loads(raw))
        root = os.stat('/')
        data = DATA.lstat()
        if (not stat.S_ISDIR(data.st_mode) or DATA.resolve() != DATA
                or data.st_uid != 0 or data.st_mode & 0o022
                or data.st_dev != root.st_dev):
            raise StorageError('FLS data is not on the configured system filesystem')
        device, disk = filesystem_identity(root.st_dev, config['root_uuid'], config['device_wwn'] if config['schema'] == 1 else config_identity(config))
        directory(DATA / 'database/mysql', root.st_dev)
        if config['mode'] == 'hybrid':
            return hybrid_state(config, root, device, disk)
        for name in ('raw', 'queue', 'metrics', 'archive'):
            directory(DATA / name, root.st_dev)
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError) as error:
        raise StorageError('Configured FLS system storage is unavailable') from error
    return {'mode': 'system-root', 'data_path': str(DATA), 'root_uuid': config['root_uuid'],
            'device_identity': config_identity(config),
            'device_wwn': config_identity(config)['value'] if config_identity(config)['kind'] == 'wwn' else '', 'device': device}


if __name__ == '__main__':
    try:
        print(json.dumps(storage_state()))
    except StorageError as error:
        raise SystemExit(str(error)) from None
