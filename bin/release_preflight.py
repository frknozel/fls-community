#!/usr/bin/env python3
"""Pure, read-only assessment of an already verified FLS source candidate.

The caller MUST obtain ``verified_manifest`` from release_package.verify_package
with an explicitly trusted public key. A dict cannot prove signature provenance.
All installation observations and the assessment clock are supplied by the
caller: this module performs no file, process, database, or network operations.
A successful assessment is transient information, never permission to install.
No apply/rollback executor or publisher trust policy exists in this foundation.
"""
from datetime import datetime, timezone
import re

from release_package import ReleaseError, parse_version, validate_manifest

MAX_AGE_SECONDS = 45
MIN_RESERVE_BYTES = 1024 ** 3
MAX_BYTES = 2 ** 63 - 1
_HEX40 = re.compile(r'^[0-9a-f]{40}$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$')
_SQL_TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$')
_RUNTIME_VERSION = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$')
_INVENTORY_KEYS = {'schema', 'observed_at', 'installed', 'maintenance', 'collector',
                   'runtime', 'git', 'disk'}


def _integer(value, minimum=0, maximum=MAX_BYTES):
    return type(value) is int and minimum <= value <= maximum


def _keys(value, required, optional=()):
    return type(value) is dict and set(required) <= set(value) <= set(required) | set(optional)


def _time(value, sql=False):
    if isinstance(value, datetime):
        if sql or value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
            return None
        return value.astimezone(timezone.utc)
    if type(value) is not str or not (_SQL_TIMESTAMP if sql else _TIMESTAMP).fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def _fresh(value, now, sql=False):
    stamp = _time(value, sql=sql)
    return stamp is not None and 0 <= (now - stamp).total_seconds() <= MAX_AGE_SECONDS


def _runtime_version(value):
    if type(value) is not str or len(value) > 32 or not _RUNTIME_VERSION.fullmatch(value):
        return None
    parts = tuple(int(part) for part in value.split('.'))
    return parts + (0,) * (3 - len(parts))


def _file_map(value):
    """Validate caller supplied metadata without opening or resolving any path."""
    if type(value) is not dict or len(value) > 100000:
        return None
    result = {}
    for path, metadata in value.items():
        if (type(path) is not str or not path or len(path) > 1024 or
                path.startswith('/') or '\\' in path or '\x00' in path or
                any(part in ('', '.', '..') for part in path.split('/'))):
            return None
        if not _keys(metadata, {'bytes', 'sha256', 'mode'}):
            return None
        if (not _integer(metadata['bytes']) or type(metadata['sha256']) is not str or
                not _HEX64.fullmatch(metadata['sha256']) or
                type(metadata['mode']) is not int or metadata['mode'] not in (644, 755)):
            return None
        result[path] = metadata
    return result


def assess(verified_manifest, inventory, *, now=None):
    """Assess supplied facts; ``now`` is an explicit UTC clock, never read here.

    The inventory is a strict schema-1 mapping collected by a trusted caller.
    Missing, unknown, stale or contradictory facts fail closed. Optional ``files``
    metadata compares candidate paths only: omitted installed paths are retained,
    and this report makes no claim that obsolete files will be removed.
    """
    errors = []
    report = {
        'schema': 1,
        'validation_status': 'preflight_blocked',
        'preflight_ok': False,
        'ready_for_apply': False,
        'apply_supported': False,
        'rollback_supported': False,
        'backup_verified': False,
        'trusted_release_policy': False,
        'signature_provenance': 'verify_package_required_by_caller',
        'scope': 'source_candidate_read_only',
        'errors': errors,
        'warnings': ['apply_executor_unavailable', 'backup_not_verified',
                     'publisher_trust_policy_unconfigured'],
        'backup': {'required': True, 'verified': False,
                   'database_backup_required': True, 'secrets_backup_required': True},
        'destructive_actions': False,
        'collector_actions': False,
        'schema_actions': False,
    }
    try:
        manifest = validate_manifest(verified_manifest)
    except (ReleaseError, TypeError, ValueError, OverflowError, RecursionError):
        errors.append('candidate_manifest_invalid')
        return report
    report['candidate'] = {key: manifest[key] for key in
                           ('version', 'channel', 'source_commit', 'source_tree')}
    assessment_time = _time(now)
    if assessment_time is None:
        errors.append('assessment_time_missing_or_invalid')
    elif _time(manifest['created_at']) > assessment_time:
        errors.append('candidate_created_in_future')
    if not _keys(inventory, _INVENTORY_KEYS, {'files'}):
        errors.append('inventory_invalid')
        return report
    if type(inventory['schema']) is not int or inventory['schema'] != 1:
        errors.append('inventory_schema_invalid')
    if assessment_time is not None and not _fresh(inventory['observed_at'], assessment_time):
        errors.append('inventory_stale_or_future')

    installed = inventory['installed']
    installed_valid = _keys(installed, {'version', 'source_commit', 'source_tree',
                                        'schema_version', 'installation_mode'})
    current_version = None
    if installed_valid:
        try:
            current_version = parse_version(installed['version'])
        except (ReleaseError, TypeError, ValueError, OverflowError):
            installed_valid = False
        installed_valid = (installed_valid and
                           type(installed['source_commit']) is str and
                           _HEX40.fullmatch(installed['source_commit']) is not None and
                           type(installed['source_tree']) is str and
                           _HEX40.fullmatch(installed['source_tree']) is not None and
                           _integer(installed['schema_version'], 0, 2 ** 31 - 1) and
                           installed['installation_mode'] in ('development', 'production'))
    if not installed_valid:
        errors.append('installed_release_state_invalid')
    else:
        report['installed'] = dict(installed)
        if parse_version(manifest['version']) <= current_version:
            errors.append('candidate_version_not_newer')
        compatible = {parse_version(value) for value in manifest['compatibility']['from_versions']}
        if current_version not in compatible:
            errors.append('installed_version_not_compatible')
        before = manifest['compatibility']['schema_before']
        after = manifest['compatibility']['schema_after']
        if before != installed['schema_version']:
            errors.append('installed_schema_not_compatible')
        if before != after:
            errors.append('schema_transition_unsupported')
        if installed['installation_mode'] == 'production' and manifest['channel'] != 'stable':
            errors.append('development_candidate_on_production')

    maintenance = inventory['maintenance']
    request = maintenance.get('request') if type(maintenance) is dict else None
    worker = maintenance.get('worker') if type(maintenance) is dict else None
    maintenance_valid = (
        _keys(maintenance, {'schema', 'available', 'fresh', 'state', 'request', 'worker'}) and
        type(maintenance['schema']) is int and maintenance['schema'] == 1 and
        type(maintenance['available']) is bool and maintenance['available'] is True and
        type(maintenance['fresh']) is bool and maintenance['fresh'] is True and
        maintenance['state'] == 'paused' and
        _keys(request, {'requested_mode', 'revision', 'requested_at'}, {'requested_by'}) and
        request['requested_mode'] == 'paused' and _integer(request['revision'], 1, 2 ** 32 - 1) and
        ('requested_by' not in request or
         type(request['requested_by']) is str and 1 <= len(request['requested_by']) <= 100 and
         '\x00' not in request['requested_by']) and
        _keys(worker, {'version', 'applied_revision', 'attempted_revision', 'collector_state',
                       'marker_present', 'checked_at', 'applied_at', 'error_code', 'age_seconds'}) and
        type(worker['version']) is int and worker['version'] == 1 and
        _integer(worker['applied_revision'], 1, 2 ** 32 - 1) and
        _integer(worker['attempted_revision'], 1, 2 ** 32 - 1) and
        worker['applied_revision'] == worker['attempted_revision'] == request['revision'] and
        worker['collector_state'] == 'inactive' and worker['marker_present'] is True and
        type(worker['marker_present']) is bool and worker['error_code'] == '' and
        _integer(worker['age_seconds'], 0, MAX_AGE_SECONDS))
    if maintenance_valid and assessment_time is not None:
        requested = _time(request['requested_at'], sql=True)
        checked = _time(worker['checked_at'], sql=True)
        applied = _time(worker['applied_at'], sql=True)
        maintenance_valid = (requested is not None and checked is not None and applied is not None and
                             requested <= applied <= checked <= assessment_time and
                             _fresh(worker['checked_at'], assessment_time, sql=True))
    if not maintenance_valid:
        errors.append('maintenance_not_confirmed_paused')

    collector = inventory['collector']
    if (not _keys(collector, {'state', 'marker_present'}) or
            collector['state'] != 'inactive' or type(collector['marker_present']) is not bool or
            collector['marker_present'] is not True):
        errors.append('collector_not_confirmed_stopped')

    runtime = inventory['runtime']
    if not _keys(runtime, {'os_id', 'os_version', 'architecture', 'python_version', 'php_version'}):
        errors.append('runtime_inventory_invalid')
    else:
        python = _runtime_version(runtime['python_version'])
        php = _runtime_version(runtime['php_version'])
        if runtime['os_id'] != 'ubuntu' or runtime['os_version'] != '24.04':
            errors.append('operating_system_unsupported')
        if runtime['architecture'] != 'x86_64':
            errors.append('architecture_unsupported')
        if python is None or python < (3, 12, 0):
            errors.append('python_runtime_unsupported')
        if php is None or php[:2] != (8, 5):
            errors.append('php_runtime_unsupported')

    git = inventory['git']
    if not _keys(git, {'available', 'trusted', 'clean', 'untracked_count', 'source_commit', 'source_tree'}):
        errors.append('git_inventory_invalid')
    elif (any(type(git[key]) is not bool or git[key] is not True
              for key in ('available', 'trusted', 'clean')) or
          not _integer(git['untracked_count']) or git['untracked_count'] != 0):
        errors.append('installed_source_not_clean_and_trusted')
    elif (not installed_valid or git['source_commit'] != installed['source_commit'] or
          git['source_tree'] != installed['source_tree']):
        errors.append('installed_source_state_mismatch')

    disk = inventory['disk']
    fields = {'free_bytes', 'package_bytes', 'source_bytes', 'backup_required_bytes', 'reserve_bytes'}
    if not _keys(disk, fields) or any(not _integer(disk[key]) for key in fields):
        errors.append('disk_inventory_or_backup_estimate_unknown')
    else:
        report['backup']['estimated_required_bytes'] = disk['backup_required_bytes']
        payload_bytes = sum(entry['bytes'] for entry in manifest['files'])
        if disk['package_bytes'] < payload_bytes or disk['package_bytes'] == 0:
            errors.append('package_space_underestimated')
        if disk['source_bytes'] == 0 or disk['backup_required_bytes'] < disk['source_bytes']:
            errors.append('backup_space_underestimated')
        if disk['reserve_bytes'] < MIN_RESERVE_BYTES:
            errors.append('disk_reserve_below_minimum')
        required = disk['package_bytes'] + disk['backup_required_bytes'] + disk['reserve_bytes']
        report['disk'] = {'free_bytes': disk['free_bytes'], 'estimated_required_bytes': required,
                          'reserve_bytes': disk['reserve_bytes']}
        if disk['free_bytes'] < required:
            errors.append('insufficient_free_space')

    if 'files' in inventory:
        current_files = _file_map(inventory['files'])
        if current_files is None:
            errors.append('installed_file_inventory_invalid')
        else:
            changed, added, unchanged = [], [], 0
            for entry in manifest['files']:
                old = current_files.get(entry['path'])
                if old is None:
                    added.append(entry['path'])
                elif any(old[key] != entry[key] for key in ('bytes', 'sha256', 'mode')):
                    changed.append(entry['path'])
                else:
                    unchanged += 1
            report['files'] = {'new': added, 'changed': changed, 'unchanged_count': unchanged,
                               'deletion_supported': False,
                               'unmentioned_installed_paths': 'retained'}
    report['preflight_ok'] = not errors
    report['validation_status'] = 'preflight_passed' if not errors else 'preflight_blocked'
    return report
