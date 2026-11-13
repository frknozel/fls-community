#!/usr/bin/env python3
"""Read-only fresh-host assessment for the separately invoked installation engine."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import uuid

GIB = 1024 ** 3
INVENTORY_SCHEMA = 'fls-community-install-inventory-v1'
PLAN_SCHEMA = 'fls-community-install-plan-v1'
UNAVAILABLE = 'release_artifacts_not_ready'
WWN = re.compile(r'0x[0-9a-f]{16}\Z')
HOSTNAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
LIMIT = 2 * 1024 ** 2


class PlanError(ValueError):
    """Fixed error codes only; input contents and command output are never errors."""


def read_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise PlanError('input_file_invalid')
        content = stream.read(LIMIT + 1)
        if len(content) > LIMIT:
            raise PlanError('input_file_invalid')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PlanError('input_duplicate_field')
            result[key] = value
        return result
    try:
        return json.loads(content, object_pairs_hook=unique_pairs,
                          parse_constant=lambda unused: (_ for _ in ()).throw(PlanError('input_json_invalid')))
    except (ValueError, UnicodeError) as error:
        if isinstance(error, PlanError):
            raise
        raise PlanError('input_json_invalid') from None


def _command(arguments):
    try:
        result = subprocess.run(arguments, capture_output=True, text=True,
                                check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        raise PlanError('inventory_command_failed') from None
    if result.returncode or len(result.stdout.encode()) > LIMIT:
        raise PlanError('inventory_command_failed')
    return result.stdout


def _json_command(arguments):
    try:
        return json.loads(_command(arguments))
    except (ValueError, TypeError):
        raise PlanError('inventory_command_invalid') from None


def _nodes(node, parent=None):
    yield node, parent
    for child in node.get('children', []):
        yield from _nodes(child, node)


def collect_inventory():
    """Read local metadata using fixed commands; never query SQL or change services."""
    errors = []
    release = {}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            key, separator, value = line.partition('=')
            if separator and key in ('ID', 'VERSION_ID'):
                release[key] = value.strip('"\'')
    except OSError:
        errors.append('os_release_unavailable')
    try:
        ram = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                       if line.startswith('MemTotal:'))) * 1024
    except (OSError, ValueError, StopIteration, IndexError):
        ram = 0
        errors.append('ram_unavailable')
    try:
        free = shutil.disk_usage('/').free
    except OSError:
        free = 0
        errors.append('free_space_unavailable')
    addresses, default_interface = [], None
    try:
        for row in _json_command(['/usr/sbin/ip', '-json', '-4', 'address', 'show']):
            for address in row.get('addr_info', []):
                if address.get('family') == 'inet':
                    addresses.append({'address': address.get('local'),
                                      'prefixlen': address.get('prefixlen'),
                                      'interface': row.get('ifname')})
        routes = _json_command(['/usr/sbin/ip', '-json', '-4', 'route', 'show', 'default'])
        interfaces = sorted({row['dev'] for row in routes if isinstance(row.get('dev'), str)})
        default_interface = interfaces[0] if len(interfaces) == 1 else None
    except (PlanError, KeyError, TypeError):
        errors.append('network_inventory_unavailable')
    root, disks = {}, []
    try:
        block = _json_command(['/usr/bin/lsblk', '--json', '--bytes', '--tree', '--output',
            'PATH,KNAME,TYPE,SIZE,RO,WWN,SERIAL,MODEL,FSTYPE,UUID,MAJ:MIN,MOUNTPOINTS'])
        mount = _json_command(['/usr/bin/findmnt', '--json', '--target', '/', '--output',
                               'SOURCE,FSTYPE,UUID,MAJ:MIN'])['filesystems'][0]
        found = []
        for disk in block['blockdevices']:
            if disk.get('type') != 'disk':
                continue
            descendants = list(_nodes(disk))
            mounted = any(any(item.get('mountpoints') or []) for item, unused in descendants)
            system = any(item.get('maj:min') == mount.get('maj:min') for item, unused in descendants)
            disks.append({'path': disk.get('path'), 'wwn': str(disk.get('wwn') or '').lower(),
                          'serial': str(disk.get('serial') or ''), 'model': str(disk.get('model') or ''),
                          'size_bytes': disk.get('size'), 'mounted': mounted,
                          'read_only': bool(disk.get('ro')), 'role': 'system' if system else 'unassigned'})
            for node, parent in descendants:
                if node.get('maj:min') == mount.get('maj:min'):
                    found.append((node, parent, disk))
        if len(found) == 1:
            node, parent, disk = found[0]
            plain = node.get('type') == 'part' and parent is disk
            wwn = str(disk.get('wwn') or '').lower()
            identity_matches, physical = False, None
            try:
                from fls_storage import discover_identity
                actual = discover_identity(os.stat('/').st_dev)
                if actual['uuid'] == mount.get('uuid') and actual['device'] == mount.get('maj:min') and actual['disk'].name == disk.get('kname'):
                    physical, identity_matches = actual['identity'], True
            except (ImportError, OSError, ValueError, RuntimeError):
                pass
            root = {'source': mount.get('source'), 'fstype': mount.get('fstype'),
                    'uuid': mount.get('uuid'), 'major_minor': mount.get('maj:min'),
                    'disk_path': disk.get('path'), 'disk_wwn': wwn, 'device_identity': physical,
                    'plain_partition': plain, 'hardware_identity_matches': identity_matches}
        else:
            errors.append('root_block_identity_unavailable')
    except (PlanError, KeyError, IndexError, TypeError):
        errors.append('disk_inventory_unavailable')
    existing = []
    # Old data roots are admission blockers, never migration/restore aliases.
    for folder in ('/etc/fls', '/var/www/fls', '/srv/fls-server', '/srv/fortigate', '/srv/fls-storage', '/srv/fls-mirror'):
        path = Path(folder)
        if path.exists() or path.is_symlink():
            existing.append(folder)
    for parent in ('/etc/systemd/system', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/var/lib'):
        try:
            existing.extend(str(path) for pattern in ('fls*', 'fortigate*') for path in Path(parent).glob(pattern))
        except OSError:
            errors.append('existing_installation_probe_unavailable')
    databases = []
    for name in ('/var/lib/mysql', '/srv/fls-server/database/mysql', '/srv/fortigate/database/mysql'):
        path = Path(name)
        try:
            if path.is_symlink() or path.exists() and next(path.iterdir(), None) is not None:
                databases.append(name)
        except OSError:
            databases.append(name)
    listening = []
    try:
        # Read kernel tables, including wildcard and IPv6 listeners, without opening sockets.
        for name, protocol in (('tcp', 'tcp'), ('tcp6', 'tcp'), ('udp', 'udp'), ('udp6', 'udp')):
            for line in (Path('/proc/net') / name).read_text().splitlines()[1:]:
                fields = line.split()
                if protocol == 'tcp' and fields[3] != '0A':
                    continue
                listening.append({'port': int(fields[1].rsplit(':', 1)[1], 16), 'protocol': protocol})
    except (OSError, ValueError, IndexError):
        errors.append('port_inventory_unavailable')
    try:
        machine = Path('/etc/machine-id').read_text(encoding='ascii').strip()
        if not re.fullmatch(r'[a-f0-9]{32}', machine): raise ValueError
        machine_sha = hashlib.sha256(machine.encode('ascii')).hexdigest()
    except (OSError, ValueError, UnicodeError):
        errors.append('machine_identity_unavailable')
        machine_sha = None
    return {'machine_sha256': machine_sha, 'schema': INVENTORY_SCHEMA, 'effective_uid': os.geteuid(),
            'os': {'id': release.get('ID'), 'version_id': release.get('VERSION_ID')},
            'architecture': platform.machine(), 'ram_bytes': ram, 'free_bytes': free,
            'cpu_count': os.cpu_count() or 1, 'hostname': socket.gethostname(),
            'addresses': addresses, 'default_route_interface': default_interface,
            'root': root, 'disks': disks, 'existing_paths': sorted(set(existing)),
            'database_directories': databases, 'listening_ports': listening, 'probe_errors': sorted(set(errors))}


def _number(value):
    return type(value) is int and value >= 0


def validate_inventory(value):
    if not isinstance(value, dict) or value.get('schema') != INVENTORY_SCHEMA:
        raise PlanError('inventory_schema_invalid')
    for key in ('effective_uid', 'ram_bytes', 'free_bytes', 'cpu_count'):
        if not _number(value.get(key)):
            raise PlanError('inventory_number_invalid')
    for key in ('addresses', 'disks', 'existing_paths', 'database_directories', 'listening_ports', 'probe_errors'):
        if not isinstance(value.get(key), list) or len(value[key]) > 4096:
            raise PlanError('inventory_list_invalid')
    if not isinstance(value.get('os'), dict) or not isinstance(value.get('root'), dict):
        raise PlanError('inventory_object_invalid')
    if any(not isinstance(row, dict) for key in ('addresses', 'disks', 'listening_ports') for row in value[key]):
        raise PlanError('inventory_row_invalid')
    if any(not isinstance(item, str) for key in ('existing_paths', 'database_directories', 'probe_errors') for item in value[key]):
        raise PlanError('inventory_row_invalid')
    for disk in value['disks']:
        if not _number(disk.get('size_bytes')) or disk.get('role') not in ('system', 'unassigned'):
            raise PlanError('inventory_disk_invalid')
        if any(not isinstance(disk.get(key), str) for key in ('path', 'wwn', 'serial', 'model')):
            raise PlanError('inventory_disk_invalid')
        if any(type(disk.get(key)) is not bool for key in ('mounted', 'read_only')):
            raise PlanError('inventory_disk_invalid')
    for entry in value['listening_ports']:
        if not _number(entry.get('port')) or not 1 <= entry['port'] <= 65535 or entry.get('protocol') not in ('tcp', 'udp'):
            raise PlanError('inventory_port_invalid')
    return value


def validate_components(value):
    if (not isinstance(value, dict) or value.get('schema') != 'fls-community-installer-components-v1'
            or value.get('edition') != 'community' or type(value.get('preparation_only')) is not bool
            or not isinstance(value.get('components'), list) or not isinstance(value.get('packages'), list)):
        raise PlanError('components_manifest_invalid')
    for key in ('minimum_ram_bytes', 'minimum_free_bytes'):
        if not _number(value.get(key)) or value[key] <= 0:
            raise PlanError('components_manifest_invalid')
    for package in value['packages']:
        if not isinstance(package, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', package):
            raise PlanError('components_manifest_invalid')
    identifiers = set()
    for row in value['components']:
        if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                or not re.fullmatch(r'[a-z_]+', row['id']) or row['id'] in identifiers
                or type(row.get('required')) is not bool or not isinstance(row.get('relative_path'), str)
                or not isinstance(row.get('reason'), str) or not isinstance(row.get('source_status'), str)):
            raise PlanError('components_manifest_invalid')
        identifiers.add(row['id'])
        path = Path(row['relative_path'])
        if path.is_absolute() or any(part in ('', '.', '..') for part in row['relative_path'].split('/')):
            raise PlanError('component_path_invalid')
        if row.get('sha256') is not None and not SHA.fullmatch(str(row['sha256'])):
            raise PlanError('component_checksum_invalid')
    return value


def inspect_components(manifest, source):
    """Report local release artifacts; never build, download, unpack or execute one."""
    result = []
    for item in manifest['components']:
        row = {key: item[key] for key in ('id', 'required', 'kind', 'relative_path', 'source_status', 'reason')}
        path = source / item['relative_path']
        row.update({'present': False, 'verified': False, 'status': 'missing'})
        try:
            # Every artifact ancestor stays inside this source directory and has no links.
            relative = path.relative_to(source)
            if any((source / Path(*relative.parts[:index])).is_symlink()
                   for index in range(1, len(relative.parts) + 1)):
                raise PlanError('component_path_redirected')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024 ** 2:
                    raise PlanError('component_file_invalid')
                row['present'] = True
                expected = item['sha256']
                row['verified'] = expected is not None and hashlib.file_digest(stream, 'sha256').hexdigest() == expected
                row['status'] = 'verified' if row['verified'] else 'checksum_unpinned' if expected is None else 'checksum_mismatch'
        except FileNotFoundError:
            pass
        except (OSError, PlanError):
            row['status'] = 'unsafe_or_unreadable'
        result.append(row)
    return result


def _hostname(value):
    return (isinstance(value, str) and len(value) <= 253 and HOSTNAME.fullmatch(value)
            and all(part and len(part) <= 63 and not part.startswith('-') and not part.endswith('-')
                    for part in value.split('.')))


def _address(value):
    try:
        address = ipaddress.ip_address(value)
        if (address.version != 4 or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_unspecified or address.is_reserved):
            return None
        return address
    except (ValueError, TypeError):
        return None


def configuration(inventory, *, bind_ip=None, hostname=None, management_network=None):
    errors = []
    candidates = []
    for row in inventory['addresses']:
        address = _address(row.get('address'))
        prefix = row.get('prefixlen')
        if address and type(prefix) is int and 8 <= prefix <= 32:
            candidates.append((address, prefix, row.get('interface')))
    candidates = sorted(set(candidates), key=lambda entry: (int(entry[0]), entry[1], str(entry[2])))
    selected = None
    if bind_ip is not None:
        requested = _address(bind_ip)
        matches = [row for row in candidates if row[0] == requested]
        if not requested:
            errors.append('bind_ip_invalid')
        elif len(matches) != 1:
            errors.append('bind_ip_not_uniquely_local')
        else:
            selected = matches[0]
    else:
        preferred = [row for row in candidates if row[2] == inventory.get('default_route_interface')]
        private = [row for row in preferred if row[0].is_private]
        pool = private or preferred or [row for row in candidates if row[0].is_private] or candidates
        if len(pool) == 1:
            selected = pool[0]
        else:
            errors.append('bind_ip_ambiguous' if pool else 'bind_ip_unavailable')
    proposed_hostname = hostname if hostname is not None else inventory.get('hostname')
    if not _hostname(proposed_hostname):
        if hostname is not None:
            errors.append('hostname_invalid')
        proposed_hostname = 'fls.local'
    network = None
    if management_network is not None:
        try:
            network = ipaddress.ip_network(management_network, strict=True)
            if network.version != 4 or network.prefixlen < 8 or selected is None or selected[0] not in network:
                raise ValueError
        except (ValueError, TypeError):
            errors.append('management_network_invalid')
            network = None
    elif selected:
        network = ipaddress.ip_network(f'{selected[0]}/{selected[1]}', strict=False)
    return {'hostname': proposed_hostname, 'bind_ip': str(selected[0]) if selected else None,
            'collector_ip': str(selected[0]) if selected else None, 'collector_port': 5514,
            'management_network': str(network) if network is not None else None,
            'timezone': 'Europe/Istanbul', 'data_path': '/srv/fls-server',
            'tls_subject_alternative_names': ([proposed_hostname, str(selected[0])] if selected else [proposed_hostname]),
            'installation_id': 'generated_on_apply',
            'secrets': 'generated_on_apply_never_in_plan'}, errors


def assess(inventory, manifest, components, *, origin='host', bind_ip=None,
           hostname=None, management_network=None):
    inventory = validate_inventory(inventory)
    manifest = validate_components(manifest)
    errors, warnings = [], []
    def require(condition, code):
        if not condition:
            errors.append(code)
    require(inventory['effective_uid'] == 0, 'root_required')
    require(isinstance(inventory.get('machine_sha256'), str) and SHA.fullmatch(inventory['machine_sha256']) is not None, 'machine_identity_required')
    require(inventory['os'].get('id') == 'ubuntu' and inventory['os'].get('version_id') == '24.04', 'ubuntu_24_04_required')
    require(inventory.get('architecture') in ('x86_64', 'amd64'), 'amd64_required')
    require(not inventory['existing_paths'], 'existing_fls_installation_requires_upgrade')
    require(not inventory['database_directories'], 'existing_database_directory_not_empty')
    require(not inventory['probe_errors'], 'host_inventory_incomplete')
    require(inventory['ram_bytes'] >= manifest['minimum_ram_bytes'], 'ram_below_minimum')
    require(inventory['free_bytes'] >= manifest['minimum_free_bytes'], 'free_space_below_minimum')
    if inventory['cpu_count'] < 4:
        warnings.append('cpu_below_four_cores_capacity_not_certified')
    root = inventory['root']
    require(root.get('fstype') == 'ext4' and root.get('plain_partition') is True, 'plain_ext4_root_partition_required')
    try:
        canonical = isinstance(root.get('uuid'), str) and str(uuid.UUID(root['uuid'])) == root['uuid']
    except (ValueError, TypeError, AttributeError):
        canonical = False
    require(canonical, 'root_filesystem_uuid_required')
    physical = root.get('device_identity')
    if physical is None and isinstance(root.get('disk_wwn'), str) and WWN.fullmatch(root['disk_wwn']):
        physical = {'kind': 'wwn', 'value': root['disk_wwn']}
        root = {**root, 'device_identity': physical}
    valid_identity = False
    try:
        from fls_storage import validate_identity
        validate_identity(physical)
        valid_identity = True
    except (ImportError, ValueError, RuntimeError):
        pass
    require(valid_identity and root.get('hardware_identity_matches') is True,
            'stable_disk_identity_required')
    systems = [row for row in inventory['disks'] if row['role'] == 'system']
    require(len(systems) == 1 and systems[0]['path'] == root.get('disk_path')
            and systems[0]['wwn'] == root.get('disk_wwn') and not systems[0]['read_only'], 'root_physical_disk_unambiguous_required')
    for port in (443, 5514):
        require(not any(row['protocol'] == 'tcp' and row['port'] == port for row in inventory['listening_ports']), f'tcp_port_{port}_in_use')
    config, config_errors = configuration(inventory, bind_ip=bind_ip, hostname=hostname,
                                         management_network=management_network)
    errors.extend(config_errors)
    sizing = {'mariadb_buffer_pool_bytes': max(256 * 1024 ** 2,
                min(8 * GIB, inventory['ram_bytes'] // 4 // (128 * 1024 ** 2) * (128 * 1024 ** 2))),
              'php_max_children': max(2, min(8, inventory['ram_bytes'] // (2 * GIB))),
              'indexer_memory_max_bytes': max(256 * 1024 ** 2, min(GIB, inventory['ram_bytes'] // 8)),
              'queue_limit_bytes': 10 * GIB, 'capacity_certified': False}
    host_errors = list(dict.fromkeys(errors))
    require(manifest.get('package_policy', {}).get('stock_profile_verified') is True,
            'stock_ubuntu_package_profile_unverified')
    for row in components:
        if row['required'] and not row['verified']:
            errors.append(row['reason'])
    if manifest['preparation_only']:
        errors.append(UNAVAILABLE)
    if origin == 'supplied_fixture':
        warnings.append('fixture_is_not_a_host_installation_check')
    warnings.extend(['provider_timestamp_runtime_disabled', 'additional_disks_never_formatted_automatically',
                     'extra_disk_requires_panel_confirmation'])
    disks = [{**row, 'selected_for_format': False, 'future_action': 'protected_system_disk'
              if row['role'] == 'system' else 'leave_untouched_pending_explicit_administrator_selection'}
             for row in inventory['disks']]
    return {'schema': PLAN_SCHEMA, 'edition': 'community', 'repository': 'frknozel/fls-community',
            'mode': 'fresh_install', 'machine_sha256': inventory.get('machine_sha256'), 'inventory_origin': origin, 'host_inspected': origin == 'host',
            'read_only': True, 'apply_supported': not manifest['preparation_only'], 'ready_for_apply': not errors and origin == 'host',
            'host_requirements_met': not host_errors, 'host_blockers': host_errors,
            'probe_errors': sorted(set(inventory['probe_errors'])),
            'blockers': list(dict.fromkeys(errors)), 'warnings': list(dict.fromkeys(warnings)),
            'configuration_proposal': config, 'sizing_proposal': sizing,
            'storage': {'initial_mode': 'system-root', 'single_disk_allowed': True,
                        'root': root, 'disks': disks, 'automatic_partitioning': False,
                        'later_depot_migration_available': True},
            'dependencies': {'packages': manifest['packages'], 'package_policy': manifest.get('package_policy', {}),
                             'artifacts': components, 'provider_enabled': False},
            'steps': [{'id': name, 'status': 'planned', 'implemented_apply': not manifest['preparation_only']}
                      for name in ('verify_published_release', 'check_fresh_host', 'resolve_verified_packages',
                                   'create_unique_installation_identity', 'install_application_and_native_helpers',
                                   'create_scoped_database_accounts', 'generate_local_tls_and_bootstrap_administrator',
                                   'configure_system_root_storage', 'validate_services_before_enablement')],
            'effects': {'files_written': False, 'packages_installed': False, 'services_changed': False,
                        'database_accessed': False, 'disks_modified': False, 'network_connections_opened': False}}
