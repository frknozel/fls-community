#!/usr/bin/env python3
"""Opt-in VM storage inventory and root-underlay proof. Reads state only; no VM mutation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

SCOPES = ('srv/fls-server/raw', 'srv/fls-server/archive', 'srv/fls-server/metrics',
          'srv/fls-server/backups', 'var/lib/fls-recovery-download',
          'srv/fls-server/db-dumps', 'srv/fls-storage')
MAX_UNDERLAY_FILE_BYTES = 256 * 1024 * 1024
MAX_UNDERLAY_TOTAL_BYTES = 512 * 1024 * 1024


def run(arguments):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=30, check=False)
        if len(result.stdout) + len(result.stderr) > 1024 * 1024:
            raise RuntimeError('Inventory output limit exceeded')
        return {'argv': arguments, 'rc': result.returncode,
                'stdout': result.stdout, 'stderr': result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'argv': arguments, 'unavailable': type(error).__name__}


def inventory():
    dmi = Path('/sys/class/dmi/id/product_uuid').read_bytes()
    config = json.loads(Path('/etc/fls/storage.json').read_text())
    release = json.loads(Path('/etc/fls/release-state.json').read_text())
    properties = ('Id,LoadState,ActiveState,SubState,MainPID,Result,FragmentPath,DropInPaths,'
                  'BindsTo,Requires,After,RequiresMountsFor,ConditionResult,TimeoutStopUSec,'
                  'SendSIGKILL,ProtectSystem,ReadWritePaths')
    depot_unit = run(['systemd-escape', '--path', '--suffix=mount', '/srv/fls-storage'])
    units = ['fortigate-collector.service', 'fortigate-health.service', 'fls-indexer.service',
             'fls-archive-indexer.service', 'mariadb.service', 'nginx.service', 'php8.3-fpm.service']
    if depot_unit.get('rc') == 0:
        units.append(depot_unit['stdout'].strip())
    commands = [
        ['hostnamectl', '--static'], ['ip', '-brief', '-4', 'address', 'show'],
        ['lsblk', '--bytes', '--json', '--output', 'PATH,NAME,PKNAME,TYPE,SIZE,FSTYPE,UUID,WWN,SERIAL,MODEL,RO,MOUNTPOINTS'],
        ['findmnt', '--json', '--target', '/', '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS'],
        ['findmnt', '--json', '--mountpoint', '/srv/fls-storage', '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS'],
        ['systemctl', 'show', *units, '--property=' + properties, '--no-pager'],
        ['systemctl', 'list-units', '--all', '--no-legend', '--plain', '--no-pager', 'fls-*', 'fortigate-*'],
        ['systemctl', 'list-unit-files', '--no-legend', '--no-pager', 'fls-*', 'fortigate-*'],
        ['systemctl', '--failed', '--no-pager'],
        ['ss', '-H', '-ltnp', 'sport = :5514'],
        ['runuser', '-u', 'syslog', '-g', 'adm', '--', 'python3', '-B', '/var/www/fls/bin/fls_storage.py'],
    ]
    locations = ['/', '/srv/fls-storage', '/srv/fls-server/database/mysql', '/srv/fls-server/queue']
    locations += ['/' + path for path in SCOPES if path != 'srv/fls-storage']
    path_state = {}
    for location in locations:
        try:
            info = Path(location).lstat()
            path_state[location] = {'device': f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}',
                                    'inode': info.st_ino, 'mode': oct(stat.S_IMODE(info.st_mode)),
                                    'uid': info.st_uid, 'gid': info.st_gid,
                                    'symlink': stat.S_ISLNK(info.st_mode)}
        except FileNotFoundError:
            path_state[location] = {'missing': True}
    report = {'kind': 'read_only_inventory', 'vm_mutations_performed': False,
              'dmi_product_uuid_sha256_file12': hashlib.sha256(dmi).hexdigest()[:12],
              'dmi_product_uuid_sha256_stripped12': hashlib.sha256(dmi.strip()).hexdigest()[:12],
              'version': Path('/var/www/fls/VERSION').read_text().strip(),
              'release': {key: release.get(key) for key in ('edition','version','schema_version','release_sha256')},
              'storage': config, 'paths': path_state,
              'paused': Path('/var/lib/fls-maintenance/paused').exists(),
              'migration_paused': Path('/var/lib/fls-disks/migration-paused').exists(),
              'collector_config_sha256': hashlib.sha256(Path('/etc/fortigate/rsyslog.conf').read_bytes()).hexdigest(),
              'collector_binary_sha256': hashlib.sha256(Path('/opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd').read_bytes()).hexdigest(),
              'commands': [run(command) for command in commands]}
    return report


def underlay(view):
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise RuntimeError('Underlay observation requires a private mount namespace')
    if not str(view).startswith('/run/fls-rc9-acceptance/') or view.resolve() != view:
        raise RuntimeError('Unexpected observer view path')
    root_device = Path('/').stat().st_dev
    if view.stat().st_dev != root_device:
        raise RuntimeError('The observer view is not on the root filesystem')
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    visible = [fields for fields in mounts if fields[4] == str(view)]
    if len(visible) != 1 or visible[0][3] != '/' or 'ro' not in visible[0][5].split(','):
        raise RuntimeError('The observer must be a read-only, nonrecursive bind of the root filesystem')
    if any(fields[4].startswith(str(view) + '/') for fields in mounts):
        raise RuntimeError('The observer includes submounts and cannot expose the underlay')
    entries, total_bytes, total_read_bytes = {}, 0, 0
    for scope in SCOPES:
        first = view / scope
        pending = [first]
        while pending:
            path = pending.pop()
            if len(entries) >= 4096:
                raise RuntimeError('Underlay entry bound exceeded; no partial acceptance')
            key = str(path.relative_to(view))
            try:
                info = path.lstat()
            except FileNotFoundError:
                entries[key] = {'missing': True}
                continue
            if info.st_dev != root_device:
                raise RuntimeError('An unexpected filesystem entered the observer view')
            record = {'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid,
                      'inode': info.st_ino, 'size': info.st_size, 'mtime_ns': info.st_mtime_ns,
                      'ctime_ns': info.st_ctime_ns, 'nlink': info.st_nlink}
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
            elif stat.S_ISLNK(info.st_mode):
                record['symlink'] = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                total_bytes += info.st_size
                if info.st_size > MAX_UNDERLAY_FILE_BYTES or total_bytes > MAX_UNDERLAY_TOTAL_BYTES:
                    raise RuntimeError('Underlay byte bound exceeded; no partial acceptance')
                digest = hashlib.sha256()
                file_read_bytes = 0
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, 'rb', buffering=0) as source:
                    opened = os.fstat(source.fileno())
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise RuntimeError('Underlay file changed while opening')
                    while True:
                        remaining = min(MAX_UNDERLAY_FILE_BYTES - file_read_bytes,
                                        MAX_UNDERLAY_TOTAL_BYTES - total_read_bytes)
                        # At the limit, read one byte to distinguish EOF from
                        # growth; never consume an unbounded growing stream.
                        chunk = source.read(min(65536, remaining + 1))
                        if not chunk:
                            break
                        file_read_bytes += len(chunk)
                        total_read_bytes += len(chunk)
                        if (file_read_bytes > MAX_UNDERLAY_FILE_BYTES
                                or total_read_bytes > MAX_UNDERLAY_TOTAL_BYTES):
                            raise RuntimeError('Underlay read byte bound exceeded; no partial acceptance')
                        digest.update(chunk)
                    after = os.fstat(source.fileno())
                if (file_read_bytes != info.st_size
                        or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                        != (info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
                    raise RuntimeError('Underlay file changed during observation')
                record['sha256'] = digest.hexdigest()
            entries[key] = record
    return {'kind': 'read_only_root_underlay_manifest', 'vm_data_mutations_performed': False,
            'entries': entries, 'regular_file_bytes_hashed': total_read_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('inventory')
    beneath = sub.add_parser('underlay')
    beneath.add_argument('--view', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root for complete read-only metadata visibility')
    result = inventory() if args.command == 'inventory' else underlay(args.view)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
