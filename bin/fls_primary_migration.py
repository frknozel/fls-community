#!/usr/bin/python3
"""Explicit second-disk migration. No discovery or mutation occurs on import.

The root write-ahead journal is independent of SQL. Interrupted operations stay
paused and never replay formatting, mounts or inode remapping automatically.
Original directories remain underneath bind mounts, without automatic cleanup.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile

from fls_disk_ops import DiskOpsError, DEPOT, IDENTITY_FIELDS, canonical_uuid
from fls_storage import filesystem_identity, storage_state, trusted_read, validate_config, config_identity

STATE = Path('/var/lib/fls-disks')
CONFIG = Path('/etc/fls/storage.json')
SCOPE = (
    ('/srv/fls-server/raw', 'FLS-Logs/raw'),
    ('/srv/fls-server/archive', 'FLS-Logs/archive'),
    ('/srv/fls-server/metrics', 'FLS-Logs/metrics'),
    ('/srv/fls-server/backups', 'FLS-Backups/staging'),
    ('/var/lib/fls-recovery-download', 'FLS-Backups/published'),
    ('/srv/fls-server/db-dumps', 'DB-Dump'),
)
UNIT = re.compile(r'(?:fls|fortigate)-[A-Za-z0-9@_.:-]+\.(?:service|timer)\Z')
KEEP = {'fls-disk-management.service', 'fls-disk-management.timer', 'fls-rehearsal-web.service'}
RESERVE = 1024**3
SCAFFOLD = ('FLS-Logs', 'FLS-Backups')


def require(value, code):
    if not value:
        raise DiskOpsError(code)


def atomic(path, value, mode=0o600, *, owner=0):
    """Root-private parent and same-directory atomic durable publication."""
    path = Path(path)
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == owner
            and not parent.st_mode & 0o022 and path.parent.resolve() == path.parent,
            'migration_state_unsafe')
    if path.exists() or path.is_symlink():
        old = path.lstat()
        require(stat.S_ISREG(old.st_mode) and old.st_uid == owner and old.st_nlink == 1
                and not old.st_mode & 0o022, 'migration_state_unsafe')
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            if owner == 0:
                os.fchown(output.fileno(), 0, 0)
            payload = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + '\n').encode()
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class MigrationJournal:
    def __init__(self, folder=STATE, *, owner=0):
        self.folder = Path(folder)
        self.path = self.folder / 'primary-migration.json'
        self.value = None
        self.owner = owner

    def begin(self, job, source, disk):
        require(not self.path.exists() and not self.path.is_symlink(), 'migration_already_attempted')
        self.value = {'schema': 1, 'job_id': job['id'], 'request_key': job['request_key'],
                      'boot_id': job['boot_id'], 'source': source, 'target': {
                          key: disk[key] for key in (*IDENTITY_FIELDS, 'path')},
                      'phase': 'claimed', 'new_writes_possible': False,
                      'started_at_utc': datetime.now(timezone.utc).isoformat(), 'steps': []}
        # O_EXCL creates a tombstone before atomic publication; a partial write
        # or power loss cannot turn an attempted operation back into a fresh one.
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        self.phase('claimed')

    def phase(self, phase, **details):
        require(self.value is not None, 'migration_journal_missing')
        self.value['phase'] = phase
        self.value.update(details)
        self.value['steps'].append({'phase': phase, 'at_utc': datetime.now(timezone.utc).isoformat()})
        atomic(self.path, self.value, owner=self.owner)


    def command(self, summary, *, status='started', exit_code=None):
        require(self.value is not None, 'migration_journal_missing')
        record = dict(summary, status=status)
        if exit_code is not None:
            require(type(exit_code) is int, 'migration_command_result_invalid')
            record['exit_code'] = exit_code
        self.value['last_command'] = record
        atomic(self.path, self.value, owner=self.owner)


def prepare_scaffold(folder, device, *, owner=0):
    """Create only the two fresh, shared lookup parents; preserve every leaf.

    The root worker uses umask 0077. Implicit mkdir(parents=True) would therefore
    make these parents 0700, preventing the collector's non-root storage guard
    from stat'ing its bind-source directories. Search permission is required;
    private backup/dump leaves and their ACLs are copied without modification.
    """
    folder = Path(folder)
    info = folder.lstat()
    require(folder.resolve(strict=True) == folder and stat.S_ISDIR(info.st_mode)
            and info.st_uid == owner and not info.st_mode & 0o022 and info.st_dev == device,
            'migration_scaffold_parent_unsafe')
    parent = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(parent)
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino)
                and opened.st_uid == owner and not opened.st_mode & 0o022,
                'migration_scaffold_parent_changed')
        for name in SCAFFOLD:
            try:
                os.mkdir(name, mode=0o711, dir_fd=parent)
            except FileExistsError:
                raise DiskOpsError('migration_scaffold_not_pristine') from None
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent)
            try:
                current = os.fstat(descriptor)
                require(current.st_uid == owner and current.st_dev == device
                        and not current.st_mode & 0o022, 'migration_scaffold_unsafe')
                # The exact mode is intentional and independent of umask/ACL
                # masks. Only a newly-created, empty parent is changed here.
                os.fchmod(descriptor, 0o711)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def command_summary(arguments):
    """Journal only fixed operations and safe unit names, never argv/output."""
    tool = Path(arguments[0]).name
    operations = {'systemctl': set(('list-unit-files','list-units','show','stop','start','enable','daemon-reload')),
                  'udevadm': {'settle','trigger'}}
    fixed = {'sfdisk':'partition', 'mkfs.ext4':'format', 'blkid':'filesystem_probe',
             'mount':'mount', 'rsync':'copy', 'sync':'flush', 'systemd-escape':'escape',
             'systemd-run':'storage_probe'}
    value = {'tool': tool if tool in operations or tool in fixed else 'other',
             'operation': arguments[1] if tool in operations and len(arguments) > 1
                          and arguments[1] in operations[tool] else fixed.get(tool,'other')}
    if tool == 'systemctl' and value['operation'] in ('show','stop','start','enable'):
        for argument in arguments[2:]:
            if (isinstance(argument,str) and len(argument) <= 255 and
                (UNIT.fullmatch(argument) or re.fullmatch(r'(?:[A-Za-z0-9_.@:-]|\\x[0-9a-f]{2})+\.mount', argument))):
                value['unit'] = argument
                break
    return value


def _metadata(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'migration_special_file')
    attrs = {name: os.getxattr(path, name, follow_symlinks=False).hex()
             for name in sorted(os.listxattr(path, follow_symlinks=False))}
    return info, {'kind': 'file' if stat.S_ISREG(info.st_mode) else 'directory',
                  'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                  'mtime_ns': info.st_mtime_ns, 'xattrs': attrs}


def _sha(path, expected):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns),
                'migration_source_changed')
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'migration_source_changed')
        return digest.hexdigest()


def verify_tree(source, target, mapping, scope, source_device, target_device):
    """Streaming SHA/ACL/xattr/hardlink verification and durable inode map.

    Only ordinary files and directories are accepted. This deliberately refuses
    symlinks rather than letting a managed tree redirect copying outside scope.
    SQLite bounds memory independently of the number of historical log files.
    """
    count = total = 0
    stack = [(Path(source), Path(target), '')]
    while stack:
        left, right, relative = stack.pop()
        a, am = _metadata(left)
        b, bm = _metadata(right)
        require(a.st_dev == source_device and b.st_dev == target_device,
                'migration_nested_filesystem')
        require(am == bm, 'migration_metadata_mismatch')
        if stat.S_ISDIR(a.st_mode):
            left_names = sorted(os.listdir(left))
            require(left_names == sorted(os.listdir(right)), 'migration_tree_mismatch')
            stack.extend((left / name, right / name, relative + '/' + name)
                         for name in reversed(left_names))
            continue
        digest = _sha(left, a)
        require(a.st_size == b.st_size and digest == _sha(right, b),
                'migration_content_mismatch')
        existing = mapping.execute('SELECT new_inode FROM inodes WHERE old_device=? AND old_inode=?',
                                   (a.st_dev, a.st_ino)).fetchone()
        require(existing is None or existing[0] == b.st_ino, 'migration_hardlink_mismatch')
        reverse = mapping.execute('SELECT old_inode FROM inodes WHERE new_device=? AND new_inode=?',
                                  (b.st_dev, b.st_ino)).fetchone()
        require(reverse is None or reverse[0] == a.st_ino, 'migration_hardlink_mismatch')
        mapping.execute('INSERT OR IGNORE INTO inodes VALUES(?,?,?,?)',
                        (a.st_dev, a.st_ino, b.st_dev, b.st_ino))
        mapping.execute('INSERT INTO paths VALUES(?,?,?,?,?,?)',
                        (scope, relative.lstrip('/'), a.st_ino, b.st_ino, a.st_size, digest))
        count += 1
        total += a.st_size
    return count, total


def open_mapping(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    mapping = sqlite3.connect(path)
    mapping.execute('PRAGMA synchronous=FULL')
    mapping.executescript('CREATE TABLE inodes(old_device INTEGER,old_inode INTEGER,new_device INTEGER,new_inode INTEGER,PRIMARY KEY(old_device,old_inode));'
                          'CREATE UNIQUE INDEX new_inode ON inodes(new_device,new_inode);'
                          'CREATE TABLE paths(scope TEXT,name TEXT,old_inode INTEGER,new_inode INTEGER,bytes INTEGER,sha256 TEXT,PRIMARY KEY(scope,name));')
    return mapping


def remap_checkpoints(connection, mapping):
    """Only inode columns change; offsets, events, dates and incidents persist."""
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,name,inode,byte_offset,line_number,observed_size,invalid_rows FROM source_files ORDER BY id FOR UPDATE')
            rows = cursor.fetchall()
            for row in rows:
                if not isinstance(row, dict):
                    row = dict(zip(('id','name','inode','byte_offset','line_number','observed_size','invalid_rows'), row))
                require(re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl', row['name']) is not None,
                        'migration_source_checkpoint_invalid')
                match = mapping.execute('SELECT old_inode,new_inode,bytes FROM paths WHERE scope=? AND name=?',
                                        ('raw', row['name'])).fetchone()
                require(match and match[0] == row['inode'] and match[2] >= max(row['byte_offset'], row['observed_size']),
                        'migration_source_checkpoint_changed')
                cursor.execute('UPDATE source_files SET inode=%s WHERE id=%s AND inode=%s',
                               (match[1], row['id'], row['inode']))
                require(cursor.rowcount in (0, 1), 'migration_checkpoint_update_failed')
            for table in ('summary_backlog_history_state', 'mail_search_backlog_history_state'):
                cursor.execute('SELECT id,cursor_file,cursor_inode,cursor_offset FROM ' + table + ' FOR UPDATE')
                for row in cursor.fetchall():
                    if not isinstance(row, dict):
                        row = dict(zip(('id','cursor_file','cursor_inode','cursor_offset'), row))
                    if row['cursor_file'] == '':
                        require(row['cursor_inode'] == 0 and row['cursor_offset'] == 0,
                                'migration_history_checkpoint_invalid')
                        continue
                    match = mapping.execute('SELECT old_inode,new_inode,bytes FROM paths WHERE scope=? AND name=?',
                                            ('metrics', 'telemetry/' + row['cursor_file'])).fetchone()
                    require(match and match[0] == row['cursor_inode'] and match[2] >= row['cursor_offset'],
                            'migration_history_checkpoint_changed')
                    cursor.execute('UPDATE ' + table + ' SET cursor_inode=%s WHERE id=%s AND cursor_inode=%s',
                                   (match[1], row['id'], row['cursor_inode']))
            # Opaque SHA helper state binds dev/inode. Restart only incomplete
            # verification from zero; existing signed manifests remain unchanged.
            cursor.execute("UPDATE archive_integrity_checks SET status='pending',progress_bytes=0,error_code='',verification_started_at=NULL WHERE status IN ('running','partial')")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


class LinuxMigration:
    """Fixed paths and commands only. Tests inject this adapter as a whole."""
    def __init__(self, ops, connection, journal, guard, runner=None):
        self.ops, self.connection, self.journal, self.guard = ops, connection, journal, guard
        self.runner = runner or subprocess.run
        self.source = None
        self.snapshots = []

    def command(self, args, **kwargs):
        self.guard()
        summary = command_summary(args)
        self.journal.command(summary)
        try:
            result = self.runner(args, capture_output=True, text=True, check=False,
                                 timeout=kwargs.pop('timeout', 120), **kwargs)
        except subprocess.TimeoutExpired:
            self.journal.command(summary, status='timeout')
            raise DiskOpsError('migration_command_timeout') from None
        except OSError:
            self.journal.command(summary, status='unavailable')
            raise DiskOpsError('migration_command_unavailable') from None
        self.journal.command(summary, status='succeeded' if result.returncode == 0 else 'failed',
                             exit_code=result.returncode)
        require(result.returncode == 0, 'migration_command_failed')
        return result.stdout

    def config(self):
        return validate_config(json.loads(trusted_read(CONFIG, 4096)))

    def preflight(self, request):
        self.source = self.config()
        require(self.source['mode'] == 'system-root', 'primary_migration_requires_system_root')
        storage_state()
        root = Path('/').stat().st_dev
        for name in ('/srv/fls-server/database/mysql', '/srv/fls-server/queue'):
            require(Path(name).lstat().st_dev == root and Path(name).resolve() == Path(name),
                    'migration_system_data_redirected')
        used = 0
        for source, _ in SCOPE:
            path = Path(source)
            require(path.resolve() == path and path.is_dir() and path.stat().st_dev == root
                    and not os.path.ismount(path), 'migration_source_redirected')
            for base, dirs, files in os.walk(path, followlinks=False):
                for name in (*dirs, *files):
                    item = Path(base) / name
                    info, _ = _metadata(item)
                    require(info.st_dev == root, 'migration_nested_filesystem')
                    if stat.S_ISREG(info.st_mode):
                        # Counting hardlinks more than once is conservative and
                        # keeps preview memory independent of file count.
                        used += info.st_size + 8192
        disk = self.ops._request_disk(request, initial=True)
        require(disk['size_bytes'] >= used + RESERVE + 2 * 1024**2,
                'primary_disk_too_small')
        require(not DEPOT.is_symlink() and not os.path.ismount(DEPOT)
                and (not DEPOT.exists() or next(DEPOT.iterdir(), None) is None),
                'primary_mountpoint_in_use')
        return self.source, disk, used

    def quiesce(self):
        # Discover every installed FLS unit, including provision-generated
        # importer/signer and instantiated cold workers. Keep panel/DB/job control.
        output = self.command(['/usr/bin/systemctl', 'list-unit-files', '--no-legend', '--no-pager'])
        units = {line.split()[0] for line in output.splitlines() if line.split()
                 and UNIT.fullmatch(line.split()[0]) and line.split()[0] not in KEEP}
        output = self.command(['/usr/bin/systemctl', 'list-units', '--all', '--no-legend', '--plain', '--no-pager'])
        units |= {line.split()[0] for line in output.splitlines() if line.split()
                  and UNIT.fullmatch(line.split()[0]) and line.split()[0] not in KEEP}
        require('fortigate-collector.service' in units and 'fls-indexer.service' in units,
                'migration_writers_inventory_incomplete')
        snapshot = []
        for unit in sorted(units):
            if '@.' in unit:
                # Guard templates so no new instance can start, but do not ask
                # systemd to stop an uninstantiated template name.
                snapshot.append({'unit': unit, 'active': False, 'enabled': 'template'})
                continue
            output = self.command(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,MainPID,UnitFileState', '--no-pager'])
            values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
            snapshot.append({'unit': unit, 'active': values.get('ActiveState') == 'active',
                             'enabled': values.get('UnitFileState', '')})
        self.journal.phase('writers_snapshot', writers=snapshot,
                           maintenance_was_paused=Path('/var/lib/fls-maintenance/paused').exists())
        # Publish the permanent condition before stopping; boot/restarts cannot
        # resume writes while a half-finished SQL/mount transition exists.
        atomic(STATE / 'migration-paused', b'FLS primary migration in progress.\n')
        for item in snapshot:
            folder = Path('/etc/systemd/system') / (item['unit'] + '.d')
            folder.mkdir(mode=0o755, exist_ok=True)
            require(folder.resolve() == folder and folder.stat().st_uid == 0
                    and not folder.stat().st_mode & 0o022, 'migration_unit_directory_unsafe')
            target = folder / '90-fls-primary-migration.conf'
            require(not target.exists() and not target.is_symlink(), 'migration_guard_exists')
            atomic(target, b'[Unit]\nConditionPathExists=!/var/lib/fls-disks/migration-paused\n', 0o644)
        self.command(['/usr/bin/systemctl', 'daemon-reload'])
        # Stop all timers before services. SendSIGKILL=no on collector preserves
        # its durable SSD queue. Timeout/failure leaves the pause guard in place.
        ordered = sorted(units, key=lambda unit: (not unit.endswith('.timer'), unit != 'fortigate-collector.service', unit))
        for unit in ordered:
            if '@.' not in unit:
                self.command(['/usr/bin/systemctl', 'stop', unit], timeout=300)
        for unit in sorted(units):
            if '@.' in unit:
                continue
            output = self.command(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,MainPID', '--no-pager'])
            values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
            require(values.get('ActiveState') in ('inactive', 'failed')
                    and (unit.endswith('.timer') or values.get('MainPID') == '0'),
                    'migration_writer_still_running')
        self.snapshots = snapshot
        atomic(Path('/var/lib/fls-maintenance/paused'), b'FLS collection is paused.\n')
        self.assert_no_writable_handles()

    def assert_no_writable_handles(self):
        prefixes = tuple(source.rstrip('/') + '/' for source, _ in SCOPE)
        exact = {source for source, _ in SCOPE}
        for process in Path('/proc').glob('[0-9]*'):
            try:
                descriptors = list((process / 'fd').iterdir())
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                raise DiskOpsError('migration_process_usage_unknown') from None
            for descriptor in descriptors:
                try:
                    path = os.readlink(descriptor)
                    if path not in exact and not path.startswith(prefixes):
                        continue
                    content = (process / 'fdinfo' / descriptor.name).read_text()
                    flags = next((int(line.split(':', 1)[1].strip(), 8)
                                  for line in content.splitlines() if line.startswith('flags:')), None)
                    require(flags is not None, 'migration_process_usage_unknown')
                    require(flags & os.O_ACCMODE == os.O_RDONLY, 'migration_writer_handle_open')
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except PermissionError:
                    raise DiskOpsError('migration_process_usage_unknown') from None

    def prepare(self, request):
        disk = self.ops._request_disk(request)
        self.ops._authorize(request)
        with self.ops.probe.hold_disk(disk):
            self.ops._request_disk(request)
            self.journal.phase('format_started')
            script = 'label: gpt\nunit: sectors\n\nstart={}, type=linux, name="FLS-Primary"\n'.format(1048576 // disk['logical_sector'])
            self.command(['/usr/sbin/sfdisk', '--wipe', 'always', '--wipe-partitions', 'always', disk['path']], input=script)
            self.command(['/usr/bin/udevadm', 'settle', '--timeout=30'])
            self.ops._request_disk(request)
            partition = self.ops.probe.partition_ready(disk)
            self.command(['/usr/sbin/mkfs.ext4', '-m', '0', '-i', '1048576', '-E',
                          'lazy_itable_init=0,lazy_journal_init=0', '-L', 'FLS-Primary', partition], timeout=1800)
        values = dict(line.split('=', 1) for line in self.command(
            ['/usr/sbin/blkid', '-p', '-o', 'export', partition]).splitlines() if '=' in line)
        require(values.get('TYPE') == 'ext4' and canonical_uuid(values.get('UUID'))
                and values['UUID'] != self.source['root_uuid'], 'primary_filesystem_identity_invalid')
        self.ops._request_disk(request)
        self.command(['/usr/bin/udevadm', 'trigger', '--action=change', '--name-match', partition])
        self.command(['/usr/bin/udevadm', 'settle', '--timeout=30'])
        DEPOT.mkdir(mode=0o755, exist_ok=True)
        self.command(['/usr/bin/mount', '-t', 'ext4', '-o', 'nodev,nosuid,noatime', partition, str(DEPOT)])
        target_device = self.ops.probe.mounted(DEPOT, values['UUID'], disk['physical_identity'])
        require(target_device != Path('/').stat().st_dev, 'source_target_same_device')
        return {'uuid': values['UUID'], 'wwn': disk['wwn'], 'physical_identity': disk['physical_identity'], 'serial': disk['serial'],
                'size_bytes': disk['size_bytes'], 'device': target_device}

    def copy_verify(self, target, used):
        self.assert_no_writable_handles()
        self.ops.probe.mounted(DEPOT, target['uuid'], target['physical_identity'])
        free = os.statvfs(DEPOT)
        require(free.f_bavail * free.f_frsize >= used + RESERVE, 'primary_usable_capacity_too_small')
        root_device = Path('/').stat().st_dev
        prepare_scaffold(DEPOT, target['device'])
        with ExitStack() as held:
            descriptors = []
            for source, relative in SCOPE:
                left, right = Path(source), DEPOT / relative
                right.mkdir(mode=0o700)
                for path, device in ((left, root_device), (right, target['device'])):
                    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    held.callback(os.close, fd)
                    require(os.fstat(fd).st_dev == device, 'migration_filesystem_changed')
                    descriptors.append(fd)
            # One invocation preserves hardlinks even between scope roots.
            # Stage the fixed root-relative layout, then rename the six trees
            # within this same filesystem without changing their inodes.
            root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            held.callback(os.close, root_fd)
            stage = DEPOT / '.primary-migration-tree'
            stage.mkdir(mode=0o700)
            target_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            held.callback(os.close, target_fd)
            require(os.fstat(target_fd).st_dev == target['device'], 'migration_filesystem_changed')
            arguments = ['/usr/bin/rsync', '-aHAXS', '--numeric-ids', '--one-file-system', '--relative', '--']
            arguments += ['/proc/self/fd/{}/./{}'.format(root_fd, source.lstrip('/')) for source, _ in SCOPE]
            arguments += ['/proc/self/fd/{}/'.format(target_fd)]
            self.command(arguments, timeout=86400, pass_fds=(root_fd, target_fd))
            for source, relative in SCOPE:
                right = DEPOT / relative
                right.rmdir()  # Fresh empty target made above; never remove data.
                os.rename(stage / source.lstrip('/'), right)
            mapping_path = STATE / 'primary-inodes.sqlite3'
            mapping = open_mapping(mapping_path)
            try:
                count = total = 0
                for source, relative in SCOPE:
                    scope = Path(source).name if source != '/var/lib/fls-recovery-download' else 'published'
                    files, size = verify_tree(Path(source), DEPOT / relative, mapping, scope,
                                              root_device, target['device'])
                    count += files
                    total += size
                mapping.commit()
                self.command(['/usr/bin/sync', '-f', str(DEPOT)], timeout=300)
                self.assert_no_writable_handles()
                self.journal.phase('verified', verified_files=count, verified_bytes=total,
                                   inode_mapping=str(mapping_path))
            finally:
                mapping.close()
        return mapping_path

    def invalidate_checkpoints(self):
        path = Path('/var/lib/fls-integrity-scrub/checkpoint.json')
        if path.exists() or path.is_symlink():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o077,
                    'migration_integrity_checkpoint_unsafe')
            retained = path.with_name('checkpoint.before-primary-migration.json')
            require(not retained.exists(), 'migration_checkpoint_archive_exists')
            os.rename(path, retained)
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        # Cold snapshots contain signed row data, not resumable filesystem
        # cursors. Their original bytes are preserved; active workers were stopped.

    def cutover(self, target):
        require(self.config() == self.source, 'migration_storage_config_changed')
        config = {'schema': 2, 'mode': 'hybrid', 'root_uuid': self.source['root_uuid'],
                  'device_identity': config_identity(self.source), 'depot_uuid': target['uuid'],
                  'depot_identity': target['physical_identity'],
                  'depot_path': str(DEPOT), 'queue_location': 'system'}
        validate_config(config)
        units = []
        def unit(path):
            return self.command(['/usr/bin/systemd-escape', '--path', '--suffix=mount', path]).strip()
        depot_unit = unit(str(DEPOT))
        definitions = [(depot_unit, '[Unit]\nDescription=FLS primary data disk\n\n[Mount]\nWhat=/dev/disk/by-uuid/' + target['uuid'] +
                        '\nWhere=' + str(DEPOT) + '\nType=ext4\nOptions=nodev,nosuid,noatime\nTimeoutSec=15\n\n[Install]\nWantedBy=local-fs.target\n')]
        for source, relative in SCOPE:
            name = unit(source)
            definitions.append((name, '[Unit]\nDescription=FLS managed primary storage bind\nRequires=' + depot_unit +
                '\nBindsTo=' + depot_unit + '\nAfter=' + depot_unit + '\n\n[Mount]\nWhat=' + str(DEPOT / relative) +
                '\nWhere=' + source + '\nType=none\nOptions=bind\nTimeoutSec=15\n\n[Install]\nWantedBy=local-fs.target\n'))
        for name, content in definitions:
            path = Path('/etc/systemd/system') / name
            require(not path.exists() and not path.is_symlink(), 'migration_mount_unit_exists')
            self.journal.phase('mount_unit_before', pending_unit=name)
            atomic(path, content.encode(), 0o644)
            units.append(name)
            self.journal.phase('mount_unit_published', published_units=units)
        self.command(['/usr/bin/systemctl', 'daemon-reload'])
        for name in units:
            self.command(['/usr/bin/systemctl', 'enable', name])
        for name in units[1:]:
            self.journal.phase('bind_before', pending_unit=name)
            self.command(['/usr/bin/systemctl', 'start', name])
            self.journal.phase('bind_mounted', last_mounted_unit=name)
        # Lost/unmounted primary data must stop every writer rather than let
        # an old system-root directory become an accidental fallback target.
        for item in self.snapshots:
            folder = Path('/etc/systemd/system') / (item['unit'] + '.d')
            target = folder / '91-fls-primary-dependencies.conf'
            require(not target.exists() and not target.is_symlink(), 'migration_dependency_exists')
            content = ('[Unit]\nBindsTo=' + depot_unit + '\nRequires=' + ' '.join(units) +
                       '\nAfter=' + ' '.join(units) + '\n')
            atomic(target, content.encode(), 0o644)
        self.journal.phase('config_before')
        atomic(CONFIG, config, 0o644)
        self.journal.phase('config_published')

    def validate(self):
        state = storage_state()
        require(state['mode'] == 'hybrid' and state['queue_location'] == 'system', 'migration_storage_validation_failed')
        root = Path('/').stat().st_dev
        require(all(Path(name).stat().st_dev == root for name in
                    ('/srv/fls-server/database/mysql', '/srv/fls-server/queue')), 'migration_system_data_moved')
        # Validate as the actual collector identity before lifting the pause. A
        # root-only probe misses non-searchable parent directories on the depot.
        self.command(['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                      '--property=User=syslog', '--property=Group=adm',
                      '--property=NoNewPrivileges=yes', '--property=PrivateDevices=yes',
                      '--property=ProtectSystem=strict', '--property=ProtectHome=yes',
                      '--property=ReadWritePaths=/srv/fls-server/raw /srv/fls-server/queue /srv/fls-server/metrics',
                      '/usr/bin/python3', '/var/www/fls/bin/fls_storage.py'])

    def resume(self):
        # Record the irreversible boundary BEFORE any worker may write. No
        # automatic rollback to retained old directories is permitted afterward.
        self.journal.phase('resuming', new_writes_possible=True)
        for item in self.snapshots:
            path = Path('/etc/systemd/system') / (item['unit'] + '.d') / '90-fls-primary-migration.conf'
            require(path.read_bytes() == b'[Unit]\nConditionPathExists=!/var/lib/fls-disks/migration-paused\n',
                    'migration_guard_changed')
        (STATE / 'migration-paused').unlink()
        if not self.journal.value['maintenance_was_paused']:
            Path('/var/lib/fls-maintenance/paused').unlink()
        self.command(['/usr/bin/systemctl', 'daemon-reload'])
        for item in sorted(self.snapshots, key=lambda item: (item['unit'].endswith('.timer'), item['unit'])):
            if item['active'] and not (self.journal.value['maintenance_was_paused']
                                       and item['unit'] == 'fortigate-collector.service'):
                self.command(['/usr/bin/systemctl', 'start', item['unit']], timeout=300)

    def fail_closed(self):
        # Freezing already-authorized scope remains necessary if the requester
        # loses their role halfway through. Never invoke start/copy/format here.
        try:
            atomic(STATE / 'migration-paused', b'FLS primary migration needs reconciliation.\n')
            atomic(Path('/var/lib/fls-maintenance/paused'), b'FLS collection is paused.\n')
        finally:
            # A full/broken root filesystem must not suppress the stop attempts.
            for item in self.journal.value.get('writers', []):
                if '@.' in item['unit']:
                    continue
                try:
                    self.runner(['/usr/bin/systemctl', 'stop', item['unit']], capture_output=True,
                                text=True, timeout=300, check=False)
                except (OSError, subprocess.SubprocessError):
                    pass


def migrate_primary(job, request, adapter, journal, claim):
    """One attempt only. Any failure retains journal, old data and writer pause."""
    source, disk, used = adapter.preflight(request)
    require(claim(request, disk) is True, 'durable_journal_claim_failed')
    journal.begin(job, source, disk)
    try:
        adapter.quiesce()
        journal.phase('quiesced')
        target = adapter.prepare(request)
        journal.phase('formatted', prepared=target)
        mapping_path = adapter.copy_verify(target, used)
        adapter.invalidate_checkpoints()
        journal.phase('sql_before')
        mapping = sqlite3.connect(mapping_path)
        try:
            remap_checkpoints(adapter.connection, mapping)
        finally:
            mapping.close()
        journal.phase('sql_committed')
        adapter.cutover(target)
        adapter.validate()
        journal.phase('validated')
        adapter.resume()
        journal.phase('complete', retained_old_source=True)
        return {'phase': 'complete', 'verified_files': journal.value.get('verified_files', 0),
                'retained_old_source': True, 'root_queue_and_database_retained': True}
    except BaseException as error:
        # No cleanup/rollback/retry: after SQL commit or mounts a second attempt
        # could reimport history or overwrite the only current copy.
        try:
            journal.phase('reconciliation_required', failure_phase=journal.value['phase'],
                          error_code=getattr(error, 'code', 'primary_migration_failed'))
        finally:
            adapter.fail_closed()
        raise
