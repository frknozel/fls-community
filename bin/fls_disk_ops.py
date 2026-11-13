#!/usr/bin/python3
"""Pinned local disk operations for the root disk-management worker.

No operation is performed on import. The SQL worker owns authorization, durable
at-most-once claims, persistent mount units and scheduling. Every mutation below
requires its current-authorization callback; destructive preparation additionally
requires a durable, previously-unclaimed journal receipt before the first write.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from fls_storage import storage_state, trusted_read, filesystem_identity, validate_config, _physical_identity, validate_identity

DEPOT = Path('/srv/fls-storage')
MIRROR = Path('/srv/fls-mirror')
MIRROR_CONFIG = Path('/etc/fls/mirror.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
SYS_BLOCK = Path('/sys/class/block')
PROC = Path('/proc')
REQUEST_MAX_AGE = 300
WWN = re.compile(r'0x[0-9a-f]{16}')
DISK_NAME = re.compile(r'(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)')
CLONE_DIRS = ('FLS-Logs/raw', 'FLS-Logs/archive', 'FLS-Logs/metrics',
              'FLS-Backups/staging', 'FLS-Backups/published', 'DB-Dump')
IDENTITY_FIELDS = ('wwn', 'serial', 'size_bytes', 'logical_sector', 'diskseq', 'major_minor', 'physical_identity')


class DiskOpsError(RuntimeError):
    """Stable safe error code; subprocess output can contain private filenames."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def identity_token(boot_id, disk):
    value = {'boot_id': boot_id, **{name: disk[name] for name in IDENTITY_FIELDS}}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def valid_physical_identity(disk):
    try:
        identity = validate_identity(disk.get('physical_identity', {'kind':'wwn','value':disk.get('wwn')}))
    except (ValueError, RuntimeError, TypeError, AttributeError):
        return False
    path = disk.get('path', '')
    expected_key = (identity['value'] if identity['kind'] == 'wwn' else
                    'id:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest())
    return (isinstance(disk, dict) and disk.get('wwn') == expected_key and isinstance(disk.get('serial'), str)
            and len(disk['serial']) <= 128 and all(32 <= ord(c) <= 126 for c in disk['serial'])
            and type(disk.get('size_bytes')) is int and disk['size_bytes'] > 0
            and type(disk.get('logical_sector')) is int and disk['logical_sector'] in (512, 4096)
            and type(disk.get('diskseq')) is int and disk['diskseq'] > 0
            and re.fullmatch(r'[0-9]+:[0-9]+', str(disk.get('major_minor', ''))) is not None
            and (path == '/dev/disk/by-id/wwn-' + identity['value'] if identity['kind'] == 'wwn'
                 else re.fullmatch(r'/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)', path) is not None))


def physical_identity(value, depot=False):
    """Canonical physical identity; old NAA-only configurations still work."""
    if depot:
        return validate_identity(value.get('depot_identity', {'kind':'wwn','value':value.get('depot_wwn')}))
    return validate_identity(value.get('physical_identity', {'kind':'wwn','value':value.get('wwn')}))


def identity_key_valid(value):
    try:
        return value.get('wwn') == CommunityHostOps.disk_key(physical_identity(value))
    except (ValueError, RuntimeError, TypeError, AttributeError):
        return False


def validate_mirror_layout(disk, identifier):
    signatures = disk.get('signatures', [])
    partitions = disk.get('partitions', [])
    if (not signatures or signatures[0].get('partition_table') != 'gpt'
            or len(partitions) != 1 or partitions[0].get('type') != 'part'
            or partitions[0].get('fstype') != 'ext4' or partitions[0].get('uuid') != identifier):
        raise DiskOpsError('mirror_partition_layout_invalid')


def _plain_directory(path, device=None, root_owned=False):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.resolve(strict=True) != path
            or device is not None and info.st_dev != device
            or root_owned and (info.st_uid != 0 or info.st_mode & 0o022)):
        raise DiskOpsError('directory_identity_invalid')
    return info


def _mounts(text):
    result = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields[6:]:
            raise DiskOpsError('mount_inventory_invalid')
        result.append({'device': fields[2], 'root': fields[3], 'path': fields[4]})
    return result


def _walk_nodes(node):
    yield node
    for child in node.get('children', []):
        yield from _walk_nodes(child)


class LinuxProbe:
    """Read actual host metadata; injectable as a whole for destructive tests."""
    def __init__(self, runner):
        self.runner = runner

    def snapshot(self):
        result = self.runner(['/usr/bin/lsblk', '--json', '--bytes', '--tree', '--output',
            'PATH,KNAME,TYPE,SIZE,RO,RM,WWN,SERIAL,MODEL,LOG-SEC,MAJ:MIN,FSTYPE,UUID,PTTYPE,MOUNTPOINTS'])
        if result.returncode:
            raise DiskOpsError('disk_inventory_failed')
        try:
            nodes = json.loads(result.stdout)['blockdevices']
            boot_id = trusted_read(BOOT_ID, 128).strip()
            if not canonical_uuid(boot_id):
                raise DiskOpsError('boot_identity_invalid')
        except (ValueError, KeyError, TypeError):
            raise DiskOpsError('disk_inventory_invalid') from None
        mounted = set()
        opened = set()
        unknown = False
        namespaces = set()
        for process in PROC.glob('[0-9]*'):
            try:
                namespace = (process / 'ns/mnt').readlink()
                if namespace not in namespaces:
                    namespaces.add(namespace)
                    mounted.update(row['device'] for row in _mounts((process / 'mountinfo').read_text()))
                if process.name != str(os.getpid()):
                    for descriptor in (process / 'fd').iterdir():
                        try:
                            info = descriptor.stat()
                            if stat.S_ISBLK(info.st_mode):
                                opened.add('{}:{}'.format(os.major(info.st_rdev), os.minor(info.st_rdev)))
                        except FileNotFoundError:
                            continue
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                unknown = True
        swaps = set()
        for line in (PROC / 'swaps').read_text().splitlines()[1:]:
            fields = line.split()
            try:
                info = Path(fields[0]).stat()
                if stat.S_ISBLK(info.st_mode):
                    swaps.add('{}:{}'.format(os.major(info.st_rdev), os.minor(info.st_rdev)))
            except (OSError, IndexError):
                # A swap that cannot be resolved must not authorize a wipe.
                unknown = True
        disks = []
        for node in nodes:
            if node.get('type') != 'disk':
                continue
            kname = str(node.get('kname', ''))
            children = list(_walk_nodes(node))
            numbers = {str(child.get('maj:min', '')) for child in children}
            blockers = []
            holders = []
            for child in children:
                child_name = str(child.get('kname', ''))
                if not re.fullmatch(r'[A-Za-z0-9_.!:-]+', child_name):
                    blockers.append('device_name_invalid')
                    continue
                try:
                    holders.extend(path.name for path in (SYS_BLOCK / child_name / 'holders').iterdir())
                except OSError:
                    blockers.append('holders_unavailable')
            wwn = str(node.get('wwn') or '').lower()
            serial = str(node.get('serial') or '').strip()
            size = node.get('size')
            logical = node.get('log-sec')
            try:
                sequence = int(trusted_read(SYS_BLOCK / kname / 'diskseq', 8192).strip())
                sector_size = int(trusted_read(SYS_BLOCK / kname / 'queue/logical_block_size', 8192).strip())
                physical_size = int(trusted_read(SYS_BLOCK / kname / 'size', 8192).strip()) * 512
                properties = {}
                for line in trusted_read(Path('/run/udev/data') / ('b' + node['maj:min'])).splitlines():
                    if line.startswith('E:') and '=' in line:
                        key, value = line[2:].split('=', 1)
                        if key in properties:
                            raise ValueError
                        properties[key] = value
                physical_identity = _physical_identity((SYS_BLOCK / kname).resolve(strict=True), properties)
                if sector_size != logical or physical_size != size:
                    blockers.append('hardware_identity_mismatch')
            except (OSError, ValueError, RuntimeError):
                sequence = None
                physical_identity = None
                blockers.append('hardware_identity_unavailable')
            if (not DISK_NAME.fullmatch(kname) or physical_identity is None
                    or len(serial) > 128 or any(ord(c) < 32 or ord(c) > 126 for c in serial)
                    or type(size) is not int or size <= 0 or logical not in (512, 4096)
                    or sequence is None):
                blockers.append('disk_identity_unavailable')
            if node.get('ro'):
                blockers.append('disk_read_only')
            if node.get('rm'):
                blockers.append('disk_removable')
            if numbers & mounted or any(child.get('mountpoints') and any(child['mountpoints']) for child in children):
                blockers.append('disk_mounted')
            if numbers & swaps:
                blockers.append('disk_swap_active')
            if numbers & opened:
                blockers.append('disk_open_by_process')
            if holders:
                blockers.append('disk_has_holders')
            if unknown:
                blockers.append('disk_usage_unavailable')
            if physical_identity:
                wwn = CommunityHostOps.disk_key(physical_identity)
            path = ('/dev/disk/by-id/wwn-' + physical_identity['value'] if physical_identity
                    and physical_identity['kind'] == 'wwn' else '/dev/' + kname)
            if path:
                try:
                    resolved = Path(path).resolve(strict=True)
                    info = resolved.stat()
                    actual_number = '{}:{}'.format(os.major(info.st_rdev), os.minor(info.st_rdev))
                    if resolved != Path('/dev') / kname or not stat.S_ISBLK(info.st_mode) or actual_number != node.get('maj:min'):
                        blockers.append('stable_path_mismatch')
                except OSError:
                    blockers.append('stable_path_unavailable')
            signatures = [{'path': child.get('path'), 'type': child.get('type'),
                           'fstype': child.get('fstype'), 'uuid': child.get('uuid'),
                           'partition_table': child.get('pttype'), 'major_minor': child.get('maj:min')}
                          for child in children]
            disks.append({'wwn': wwn, 'serial': serial, 'model': str(node.get('model') or '').strip()[:128], 'size_bytes': size,
                          'logical_sector': logical, 'diskseq': sequence,
                          'major_minor': node.get('maj:min'), 'path': path, 'physical_identity': physical_identity,
                          'partitions': signatures[1:], 'signatures': signatures,
                          'holders': sorted(set(holders)), 'blockers': sorted(set(blockers))})
        return {'boot_id': boot_id, 'disks': disks}

    @contextmanager
    def hold_disk(self, disk):
        # Probe exclusive availability, then release before external formatters
        # open the same disk. The root worker serializes its operations; tools
        # retain their own busy-device checks (never --force/--no-reread).
        path = Path(disk['path']).resolve(strict=True)
        descriptor = os.open(path, os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            number = '{}:{}'.format(os.major(info.st_rdev), os.minor(info.st_rdev))
            if not stat.S_ISBLK(info.st_mode) or number != disk['major_minor']:
                raise DiskOpsError('exclusive_disk_identity_mismatch')
        finally:
            os.close(descriptor)
        yield

    def mountpoint_ready(self):
        if MIRROR.exists() or MIRROR.is_symlink():
            _plain_directory(MIRROR, root_owned=True)
            if (os.path.ismount(MIRROR)
                    or any(row['path'] == str(MIRROR) for row in _mounts(Path('/proc/self/mountinfo').read_text()))
                    or next(MIRROR.iterdir(), None) is not None):
                raise DiskOpsError('mirror_mountpoint_in_use')
        else:
            _plain_directory(MIRROR.parent, root_owned=True)

    def make_mountpoint(self):
        MIRROR.mkdir(mode=0o755, exist_ok=True)
        _plain_directory(MIRROR, root_owned=True)

    def partition_ready(self, disk):
        physical = disk.get('physical_identity', {'kind':'wwn','value':disk['wwn']})
        suffix = '-part1' if physical['kind'] == 'wwn' else ('p1' if disk['path'][-1].isdigit() else '1')
        path = Path(disk['path'] + suffix)
        if path.resolve(strict=True).parent != Path('/dev'):
            raise DiskOpsError('partition_path_invalid')
        info = path.stat()
        if not stat.S_ISBLK(info.st_mode):
            raise DiskOpsError('partition_identity_invalid')
        number = '{}:{}'.format(os.major(info.st_rdev), os.minor(info.st_rdev))
        block = Path('/sys/dev/block', number).resolve(strict=True)
        if trusted_read(block / 'partition', 8192).strip() != '1':
            raise DiskOpsError('partition_number_invalid')
        if _physical_identity(block.parent, {}) != physical:
            raise DiskOpsError('partition_parent_changed')
        return str(path)

    def mounted(self, path, expected_uuid, expected_wwn):
        info = _plain_directory(path, root_owned=True)
        device, _ = filesystem_identity(info.st_dev, expected_uuid, expected_wwn)
        rows = [row for row in _mounts(Path('/proc/self/mountinfo').read_text()) if row['path'] == str(path)]
        if not rows or rows[-1]['device'] != device or rows[-1]['root'] != '/':
            raise DiskOpsError('filesystem_mount_identity_invalid')
        return info.st_dev

    def clone_directories(self, base, device):
        for name in ('FLS-Logs', 'FLS-Backups', *CLONE_DIRS):
            path = base / name
            if path.exists() or path.is_symlink():
                _plain_directory(path, device)
            elif base == DEPOT:
                raise DiskOpsError('source_directory_missing')


    def initialize_clone_dirs(self, source_device, target_device):
        for name in ('FLS-Logs', 'FLS-Backups', *CLONE_DIRS):
            source = _plain_directory(DEPOT / name, source_device)
            target = MIRROR / name
            if not target.exists():
                target.mkdir(mode=0o700)
            _plain_directory(target, target_device)
            os.chown(target, source.st_uid, source.st_gid, follow_symlinks=False)
            os.chmod(target, stat.S_IMODE(source.st_mode), follow_symlinks=False)


    @contextmanager
    def hold_filesystems(self, state, mirror):
        descriptors = []
        try:
            for path, identifier, wwn in ((DEPOT, state['depot_uuid'], physical_identity(state, True)),
                                           (MIRROR, mirror['uuid'], physical_identity(mirror))):
                before = _plain_directory(path, root_owned=True)
                descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                descriptors.append(descriptor)
                actual = os.fstat(descriptor)
                if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino):
                    raise DiskOpsError('filesystem_changed_while_opening')
                filesystem_identity(actual.st_dev, identifier, wwn)
                self.mounted(path, identifier, wwn)
            if os.fstat(descriptors[0]).st_dev == os.fstat(descriptors[1]).st_dev:
                raise DiskOpsError('source_target_same_device')
            yield {'source': '/proc/self/fd/{}/'.format(descriptors[0]),
                   'target': '/proc/self/fd/{}/'.format(descriptors[1]),
                   'pass_fds': tuple(descriptors)}
        finally:
            for descriptor in descriptors:
                os.close(descriptor)


class HostOps:
    def __init__(self, runner=None, storage_loader=None, clock=None,
                 mutation_guard=None, producer_guard=None, probe=None, mirror_loader=None):
        self.runner = runner or self._subprocess
        self.storage_loader = storage_loader or storage_state
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.mutation_guard = mutation_guard
        self.producer_guard = producer_guard
        self.probe = probe or LinuxProbe(self.runner)
        self.mirror_loader = mirror_loader or self._load_mirror

    @staticmethod
    def _subprocess(args, **kwargs):
        return subprocess.run(args, capture_output=True, text=True, timeout=kwargs.pop('timeout', 60), **kwargs)

    @staticmethod
    def _load_mirror():
        try:
            value = json.loads(trusted_read(MIRROR_CONFIG, 4096))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, RuntimeError):
            raise DiskOpsError('installed_mirror_config_invalid') from None
        if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1 or not identity_key_valid(value):
            raise DiskOpsError('installed_mirror_config_invalid')
        return value

    def _storage(self):
        state = self.storage_loader()
        if (not isinstance(state, dict) or state.get('mode') != 'hybrid'
                or not WWN.fullmatch(str(state.get('device_wwn', '')))
                or not WWN.fullmatch(str(state.get('depot_wwn', '')))
                or state['device_wwn'] == state['depot_wwn']
                or state.get('depot_path') != str(DEPOT)
                or not canonical_uuid(state.get('root_uuid'))
                or not canonical_uuid(state.get('depot_uuid'))):
            raise DiskOpsError('pinned_primary_storage_unavailable')
        return state

    def inventory(self):
        state = self._storage()
        snapshot = self.probe.snapshot()
        disks = snapshot['disks']
        if len({disk['wwn'] for disk in disks if disk.get('wwn')}) != len([disk for disk in disks if disk.get('wwn')]):
            raise DiskOpsError('duplicate_physical_disk_identity')
        system = next((disk for disk in disks if disk['wwn'] == state['device_wwn']), None)
        primary = next((disk for disk in disks if disk['wwn'] == state['depot_wwn']), None)
        if not system or not primary:
            raise DiskOpsError('pinned_primary_disk_missing')
        if any(not valid_physical_identity(disk) or any(
                blocker.startswith(('hardware_identity_', 'stable_path_', 'disk_identity_'))
                for blocker in disk.get('blockers', [])) for disk in (system, primary)):
            raise DiskOpsError('pinned_primary_disk_identity_invalid')
        installed = self.mirror_loader()
        observed = self.clock().astimezone(timezone.utc).isoformat()
        for disk in disks:
            blockers = set(disk.get('blockers', []))
            if disk['wwn'] == state['device_wwn']:
                blockers.add('system_disk_protected')
            if disk['wwn'] == state['depot_wwn']:
                blockers.add('primary_disk_protected')
            if installed:
                blockers.add('mirror_already_configured')
            if type(disk.get('size_bytes')) is not int or disk['size_bytes'] < primary['size_bytes']:
                blockers.add('mirror_disk_too_small')
            if not valid_physical_identity(disk):
                blockers.add('disk_identity_unavailable')
            disk['blockers'] = sorted(blockers)
            disk['eligible'] = not blockers
            disk['identity_token'] = identity_token(snapshot['boot_id'], disk)
        return {'schema': 1, 'boot_id': snapshot['boot_id'], 'observed_at': observed,
                'system': system, 'primary': primary, 'disks': disks}

    def _request_disk(self, request, initial=False):
        if not isinstance(request, dict) or request.get('confirmation') != 'TAMAM':
            raise DiskOpsError('explicit_confirmation_required')
        try:
            key = uuid.UUID(request['request_key'])
            when = datetime.fromisoformat(request['observed_at'])
            age = (self.clock() - when).total_seconds()
            if str(key) != request['request_key'] or key.version != 4 or when.tzinfo is None or age < -5 or initial and age > REQUEST_MAX_AGE:
                raise ValueError
        except (KeyError, ValueError, TypeError):
            raise DiskOpsError('stale_or_invalid_disk_request') from None
        current = self.inventory()
        disk = next((disk for disk in current['disks'] if disk['wwn'] == request.get('wwn')), None)
        if not disk or not disk['eligible']:
            raise DiskOpsError('disk_not_eligible')
        if (current['boot_id'] != request.get('boot_id')
                or disk['identity_token'] != request.get('identity_token')
                or any(disk[field] != request.get(field) for field in IDENTITY_FIELDS)):
            raise DiskOpsError('disk_identity_changed')
        return disk

    def _authorize(self, request):
        if self.mutation_guard is None or self.mutation_guard(request) is not True:
            raise DiskOpsError('disk_request_authorization_revoked')

    def _command(self, args, **kwargs):
        result = self.runner(args, **kwargs)
        if result.returncode:
            raise DiskOpsError('disk_command_failed')
        return result

    def prepare(self, request, journal_before_wipe):
        disk = self._request_disk(request, initial=True)
        self._authorize(request)
        self.probe.mountpoint_ready()
        if not callable(journal_before_wipe):
            raise DiskOpsError('durable_journal_required')
        with self.probe.hold_disk(disk):
            disk = self._request_disk(request)
            self._authorize(request)
            if journal_before_wipe(request, disk) is not True:
                raise DiskOpsError('durable_journal_claim_failed')
            self._authorize(request)
            disk = self._request_disk(request)
            first_sector = 1048576 // disk['logical_sector']
            script = 'label: gpt\nunit: sectors\n\nstart={}, type=linux, name="FLS-Mirror"\n'.format(first_sector)
            self._command(['/usr/sbin/sfdisk', '--wipe', 'always', '--wipe-partitions', 'always', disk['path']], input=script)
            self._command(['/usr/bin/udevadm', 'settle', '--timeout=30'])
            self._authorize(request)
            disk = self._request_disk(request)
            partition = self.probe.partition_ready(disk)
            with self.probe.hold_disk(disk):
                self._command(['/usr/sbin/mkfs.ext4', '-m', '0', '-i', '1048576',
                    '-E', 'lazy_itable_init=0,lazy_journal_init=0', '-L', 'FLS-Mirror', partition], timeout=1800)
            result = self._command(['/usr/sbin/blkid', '-p', '-o', 'export', partition])
            properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if properties.get('TYPE') != 'ext4' or not canonical_uuid(properties.get('UUID')):
                raise DiskOpsError('prepared_filesystem_identity_invalid')
            filesystem_uuid = properties['UUID']
            state = self._storage()
            if filesystem_uuid in (state['root_uuid'], state['depot_uuid']):
                raise DiskOpsError('prepared_filesystem_uuid_collision')
            self._authorize(request)
            self._request_disk(request)
            self._command(['/usr/bin/udevadm', 'trigger', '--action=change', '--name-match', partition])
            self._command(['/usr/bin/udevadm', 'settle', '--timeout=30'])
        # The formatter has exited; validate the attachment again before mount.
        self._authorize(request)
        disk = self._request_disk(request)
        self.probe.make_mountpoint()
        partition = self.probe.partition_ready(disk)
        self._command(['/usr/bin/mount', '-t', 'ext4', '-o', 'nodev,nosuid', partition, str(MIRROR)])
        target_device = self.probe.mounted(MIRROR, filesystem_uuid, physical_identity(disk))
        state = self._storage()
        source_device = self.probe.mounted(DEPOT, state['depot_uuid'], physical_identity(state, True))
        if source_device == target_device:
            raise DiskOpsError('source_target_same_device')
        self._authorize(request)
        self.probe.initialize_clone_dirs(source_device, target_device)
        return {'schema': 1, 'wwn': disk['wwn'], 'physical_identity': physical_identity(disk), 'serial': disk['serial'],
                'size_bytes': disk['size_bytes'], 'uuid': filesystem_uuid,
                'path': str(MIRROR), 'status': 'prepared'}

    def _sync_guard(self, mirror):
        state = self._storage()
        if (not isinstance(mirror, dict) or not identity_key_valid(mirror)
                or not canonical_uuid(mirror.get('uuid'))
                or mirror.get('path', str(MIRROR)) != str(MIRROR)
                or mirror['wwn'] in (state['device_wwn'], state['depot_wwn'])
                or mirror['uuid'] in (state['root_uuid'], state['depot_uuid'])):
            raise DiskOpsError('mirror_identity_invalid')
        installed = self.mirror_loader()
        if installed and any(installed.get(key) != mirror.get(key) for key in ('wwn', 'serial', 'size_bytes', 'uuid')):
            raise DiskOpsError('installed_mirror_identity_changed')
        inventory = self.inventory()
        actual = next((disk for disk in inventory['disks'] if disk['wwn'] == mirror['wwn']), None)
        if (not actual or actual['serial'] != mirror.get('serial')
                or actual['size_bytes'] != mirror.get('size_bytes')
                or physical_identity(actual) != physical_identity(mirror)
                or actual['size_bytes'] < inventory['primary']['size_bytes']):
            raise DiskOpsError('mirror_disk_identity_changed')
        validate_mirror_layout(actual, mirror['uuid'])
        self.probe.partition_ready(actual)
        source_device = self.probe.mounted(DEPOT, state['depot_uuid'], physical_identity(state, True))
        target_device = self.probe.mounted(MIRROR, mirror['uuid'], physical_identity(mirror))
        if source_device == target_device:
            raise DiskOpsError('source_target_same_device')
        self.probe.clone_directories(DEPOT, source_device)
        self.probe.clone_directories(MIRROR, target_device)
        return state

    def sync(self, mirror, initial=False):
        self._sync_guard(mirror)
        if self.producer_guard is None or self.producer_guard() is not True:
            raise DiskOpsError('backup_producer_busy')
        self._authorize({'action': 'sync', 'mirror': mirror})
        filters = []
        for name in ('FLS-Logs', 'FLS-Backups'):
            filters.append('--include=/' + name + '/')
        filters += ['--include=/' + name + '/***' for name in CLONE_DIRS]
        filters.append('--exclude=/***')
        # Keep directory descriptors anchored to the validated filesystems.
        # An unmount/hotplug between the guard and exec must never turn a source
        # into an empty SSD directory followed by deletion of the good mirror.
        state = self._sync_guard(mirror)
        with self.probe.hold_filesystems(state, mirror) as anchor:
            self._authorize({'action': 'sync', 'mirror': mirror})
            if self.producer_guard() is not True:
                raise DiskOpsError('backup_producer_busy')
            arguments = ['/usr/bin/rsync', '-aHAXS', '--numeric-ids', '--delete-delay',
                         '--stats', '--out-format=', *filters, '--', anchor['source'], anchor['target']]
            # No --ignore-errors: source I/O errors suppress deferred deletion.
            result = self.runner(arguments, timeout=86400, pass_fds=anchor['pass_fds'])
        if result.returncode in (23, 24):
            return {'status': 'partial', 'error_code': 'source_changed_or_io_error',
                    'initial': bool(initial), 'exit_code': result.returncode}
        if result.returncode:
            raise DiskOpsError('mirror_rsync_failed')
        self._sync_guard(mirror)
        if self.producer_guard() is not True:
            return {'status': 'partial', 'error_code': 'backup_producer_changed',
                    'initial': bool(initial), 'exit_code': 0}
        return {'status': 'complete', 'initial': bool(initial), 'exit_code': 0,
                'finished_at': self.clock().astimezone(timezone.utc).isoformat()}


class CommunityHostOps(HostOps):
    """Root, primary and mirror disks may have a pinned NAA, WWID or serial.

    Existing hybrid mirror operations retain their physical/capacity checks.
    A system-root machine has no primary until the explicit migration completes.
    """
    def config(self):
        return validate_config(json.loads(trusted_read(Path('/etc/fls/storage.json'), 4096)))

    @staticmethod
    def disk_key(identity):
        if isinstance(identity, str):
            return identity
        if identity.get('kind') == 'wwn':
            return identity['value']
        return 'id:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()

    def _storage(self):
        # Verify operational filesystem bindings, not just configuration text.
        self.storage_loader()
        state = self.config()
        state = dict(state)
        state['device_wwn'] = self.disk_key(state.get('device_identity', state.get('device_wwn')))
        if state['mode'] == 'hybrid':
            state['depot_wwn'] = self.disk_key(state.get('depot_identity', state.get('depot_wwn')))
        return state

    def inventory(self):
        state = self._storage()
        snapshot = self.probe.snapshot()
        disks = snapshot['disks']
        root_identity = state.get('device_identity', state['device_wwn'])
        _, root_disk = filesystem_identity(Path('/').stat().st_dev, state['root_uuid'], root_identity)
        root_number = trusted_read(root_disk / 'dev', 128).strip()
        system = next((disk for disk in disks if disk['major_minor'] == root_number), None)
        if not system:
            raise DiskOpsError('pinned_system_disk_missing')
        # Generic display fingerprints never become device paths. Every
        # erasure additionally rechecks the underlying physical identity dict.
        system['wwn'] = state['device_wwn']
        primary = None
        if state['mode'] == 'hybrid':
            primary = next((disk for disk in disks if disk['wwn'] == state['depot_wwn']), None)
            if not primary or not valid_physical_identity(primary):
                raise DiskOpsError('pinned_primary_disk_missing')
        physical = [disk['wwn'] for disk in disks if disk.get('wwn')]
        if len(physical) != len(set(physical)):
            raise DiskOpsError('duplicate_physical_disk_identity')
        serials = [disk['serial'] for disk in disks if disk.get('serial')]
        if len(serials) != len(set(serials)):
            raise DiskOpsError('duplicate_physical_disk_identity')
        installed = self.mirror_loader()
        for disk in disks:
            blockers = set(disk.get('blockers', []))
            if disk is system:
                blockers.add('system_disk_protected')
            if disk is primary:
                blockers.add('primary_disk_protected')
            if installed:
                blockers.add('mirror_already_configured')
            if primary and disk.get('size_bytes', 0) < primary['size_bytes']:
                blockers.add('mirror_disk_too_small')
            if not valid_physical_identity(disk):
                blockers.add('disk_identity_unavailable')
            disk['blockers'] = sorted(blockers)
            disk['eligible'] = not blockers
            disk['identity_token'] = identity_token(snapshot['boot_id'], disk)
        return {'schema': 1, 'mode': state['mode'], 'boot_id': snapshot['boot_id'],
                'observed_at': self.clock().astimezone(timezone.utc).isoformat(),
                'system': system, 'primary': primary, 'disks': disks}
