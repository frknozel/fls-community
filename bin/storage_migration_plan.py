#!/usr/bin/python3
"""Evaluate supplied storage metadata; never discover or mutate a real host.

This is an offline preparation contract, not a disk-management executor. Even an
eligible result cannot authorize formatting, data copying or a service change.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import re
import sys
import uuid

REQUEST_SCHEMA = 'fls-community-storage-plan-request-v1'
RESULT_SCHEMA = 'fls-community-storage-plan-v1'
INVENTORY_SCHEMA = 'fls-community-disk-inventory-v1'
MAX_INPUT_BYTES = 262144
MAX_AGE_SECONDS = 45
MAX_INTEGER = 2**53 - 1
PARTITION_ALLOWANCE_BYTES = 2 * 1024**2
WWN = re.compile(r'0x[0-9a-f]{16}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
IDENTITY_FIELDS = ('wwn', 'serial', 'size_bytes', 'logical_sector',
                   'diskseq', 'major_minor', 'sysfs_wwid')
DISK_FIELDS = {*IDENTITY_FIELDS, 'model', 'read_only', 'removable', 'mounted',
               'swap', 'holders', 'open_handles', 'usage_known',
               'partition_table', 'partitions'}
SCOPE = [
    {'source': '/srv/fls-server/raw', 'target': '/srv/fls-storage/FLS-Logs/raw'},
    {'source': '/srv/fls-server/archive', 'target': '/srv/fls-storage/FLS-Logs/archive'},
    {'source': '/srv/fls-server/metrics', 'target': '/srv/fls-storage/FLS-Logs/metrics'},
    {'source': '/srv/fls-server/backups', 'target': '/srv/fls-storage/FLS-Backups/staging'},
    {'source': '/var/lib/fls-recovery-download', 'target': '/srv/fls-storage/FLS-Backups/published'},
    {'source': '/srv/fls-server/db-dumps', 'target': '/srv/fls-storage/DB-Dump'},
]


class PlanInputError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise PlanInputError(code)


def object_fields(value, fields, code):
    require(isinstance(value, dict) and set(value) == set(fields), code)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INTEGER


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value),
        'timestamp_invalid')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise PlanInputError('timestamp_invalid') from None
    require(parsed.utcoffset().total_seconds() == 0, 'timestamp_invalid')
    return parsed.astimezone(timezone.utc)


def printable(value, maximum, empty=True):
    return (isinstance(value, str) and len(value) <= maximum
            and (empty or bool(value)) and all(32 <= ord(c) <= 126 for c in value))


def identity_sha256(boot_id, disk):
    """Preview fingerprint only: the supplied inventory is not authenticated."""
    value = {'boot_id': boot_id, **{field: disk[field] for field in IDENTITY_FIELDS}}
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def disk_record(value):
    object_fields(value, DISK_FIELDS, 'disk_schema_invalid')
    require(printable(value['wwn'], 128) and printable(value['serial'], 128)
            and printable(value['model'], 128) and printable(value['sysfs_wwid'], 128)
            and integer(value['size_bytes'], 1) and integer(value['logical_sector'], 1)
            and integer(value['diskseq']) and printable(value['major_minor'], 32),
            'disk_values_invalid')
    for field in ('read_only', 'removable', 'mounted', 'swap', 'usage_known'):
        require(type(value[field]) is bool, 'disk_flags_invalid')
    require(integer(value['holders']) and integer(value['open_handles']), 'disk_usage_invalid')
    require(value['partition_table'] in ('', 'gpt', 'dos', 'other')
            and isinstance(value['partitions'], list) and len(value['partitions']) <= 128,
            'partition_schema_invalid')
    seen = set()
    for part in value['partitions']:
        object_fields(part, ('number', 'uuid', 'filesystem', 'layout'), 'partition_schema_invalid')
        require(integer(part['number'], 1) and part['number'] not in seen
                and printable(part['uuid'], 128) and printable(part['filesystem'], 64)
                and part['layout'] in ('plain-partition', 'lvm', 'raid', 'other'),
                'partition_values_invalid')
        seen.add(part['number'])
    return value


def identity_errors(disk):
    errors = []
    if (not WWN.fullmatch(disk['wwn']) or not disk['serial']
            or disk['logical_sector'] not in (512, 4096) or disk['diskseq'] < 1
            or not re.fullmatch(r'[0-9]+:[0-9]+', disk['major_minor'])):
        errors.append('physical_identity_unsupported')
    if disk['sysfs_wwid'] != 'naa.' + disk['wwn'].removeprefix('0x'):
        errors.append('hardware_identity_mismatch')
    return errors


def source_partition(disk, filesystem_uuid, role):
    require(not identity_errors(disk), role + '_identity_unsupported')
    matches = [part for part in disk['partitions'] if part['uuid'] == filesystem_uuid]
    require(len(matches) == 1 and matches[0]['filesystem'] == 'ext4'
            and matches[0]['layout'] == 'plain-partition', role + '_requires_plain_ext4')
    require(disk['mounted'] and not disk['read_only'] and not disk['removable']
            and disk['usage_known'], role + '_storage_unavailable')
    return matches[0]


def planned_steps(action):
    if action == 'add-mirror':
        return [
            {'phase': 'authorize', 'requirements': ['current_administrator_and_csrf',
                'refresh_and_recheck_boot_uuid_wwn_serial_diskseq_and_usage',
                'display_complete_disk_erasure_and_require_exact_TAMAM',
                'durable_at_most_once_format_receipt_before_first_disk_write']},
            {'phase': 'prepare_mirror', 'requirements': ['single_gpt_ext4_partition',
                'verify_new_uuid_and_physical_wwn', 'persist_mount_by_uuid',
                'create_fixed_managed_directories', 'recheck_actual_usable_capacity']},
            {'phase': 'synchronize', 'requirements': ['pin_open_source_and_target_filesystems',
                'source_depot_to_mirror_only', 'rsync_aHAXS_numeric_ids_delete_delay',
                'do_not_ignore_source_io_errors', 'busy_or_changed_backup_producer_is_not_success',
                'schedule_hourly_only_after_verified_preparation']},
        ]
    return [
        {'phase': 'authorize', 'requirements': ['current_administrator_and_csrf',
            'refresh_and_recheck_boot_uuid_wwn_serial_diskseq_and_usage',
            'display_complete_disk_erasure_and_require_exact_TAMAM',
            'durable_at_most_once_format_receipt_before_first_disk_write']},
        {'phase': 'prepare_primary', 'requirements': ['single_gpt_ext4_partition',
            'verify_new_uuid_and_physical_wwn', 'mount_fixed_depot_by_uuid',
            'create_fixed_managed_directories', 'recheck_actual_usable_capacity']},
        {'phase': 'initial_copy_optional', 'requirements': ['preserve_owners_modes_acl_xattrs_hardlinks',
            'initial_live_copy_is_not_final_verification']},
        {'phase': 'quiesce', 'requirements': ['persist_migration_pause_across_reboot',
            'stop_collector_gracefully_and_confirm_main_pid_zero',
            'stop_and_block_restarts_of_every_migration_scope_writer_and_timer',
            'stop_raw_and_archive_indexers_integrity_scrub_archive_export_timestamp_cold_storage',
            'stop_metrics_telemetry_both_history_recorders_fortigate_pollers_and_onboarding',
            'stop_backup_dump_upload_and_mirror_producers',
            'keep_mariadb_and_job_control_available_on_system_disk',
            'retain_complete_durable_ssd_queue_without_copy_or_reset']},
        {'phase': 'final_copy_verify', 'requirements': ['final_rsync_aHAXS_numeric_ids',
            'pin_open_source_and_target_filesystems',
            'sha256_every_copied_regular_file_and_verify_stable_source',
            'verify_owners_modes_acl_xattrs_hardlinks_and_exact_managed_tree',
            'retain_signed_archive_and_manifest_bytes_without_resigning']},
        {'phase': 'checkpoint_remap', 'requirements': ['persist_old_and_new_inode_mapping',
            'transactionally_compare_and_update_source_files_inode',
            'remap_summary_backlog_history_state_cursor_inode',
            'remap_mail_search_backlog_history_state_cursor_inode',
            'preserve_byte_offsets_line_numbers_row_ids_event_counts_and_incident_state',
            'never_reset_offsets_or_reimport_existing_records']},
        {'phase': 'cutover', 'requirements': ['journal_each_mount_sql_and_configuration_commit_boundary',
            'stage_and_compare_previous_mount_units_permissions_and_config',
            'publish_each_mount_or_config_file_atomically_with_fsync',
            'bind_five_operational_paths_to_verified_depot_sources',
            'publish_hybrid_storage_config_with_queue_location_system',
            'keep_database_and_queue_on_system_disk',
            'do_not_claim_global_atomicity_across_sql_mount_and_filesystem_changes']},
        {'phase': 'validate', 'requirements': ['storage_guard_in_host_and_real_service_namespace',
            'verify_database_and_queue_still_on_system_disk',
            'verify_admin_job_status_remains_reachable',
            'resume_importer_from_unchanged_offsets_without_duplicate_rows',
            'confirm_missing_depot_never_falls_back_to_system_disk_directories']},
        {'phase': 'retain_and_resume', 'requirements': ['retain_old_source_and_old_checkpoint_mapping',
            'record_first_write_to_new_primary', 'resume_only_previously_enabled_workers',
            'verify_live_intake_integrity_backups_and_capacity',
            'no_automatic_deletion_of_retained_old_source']},
        {'phase': 'rollback_policy', 'requirements': ['before_new_writes_restore_verified_old_mount_config_and_inode_mapping',
            'after_new_writes_never_blindly_restore_old_source',
            'after_new_writes_pause_and_reverse_copy_and_verify_current_data_before_rollback',
            'interrupted_or_unknown_phase_stays_paused_for_explicit_reconciliation',
            'never_automatically_replay_formatting_or_reset_replay_journal']},
    ]


def evaluate(request):
    result = {'schema': RESULT_SCHEMA, 'execution_available': False,
        'safe_to_execute': False, 'applied': False, 'host_inspected': False,
        'input_authenticity_verified': False, 'decision': 'invalid_input',
        'action': None, 'errors': [], 'candidates': [], 'selected_candidate': None,
        'execution_blockers': ['executor_not_implemented', 'live_inventory_not_collected',
            'current_administrator_not_authorized', 'destructive_confirmation_not_collected'],
        'support_profile': {'filesystem': 'ext4', 'layout': 'plain-partition',
            'physical_identity': 'naa.16_lowercase_hex', 'raid_supported': False,
            'lvm_supported': False, 'missing_wwn_supported': False}}
    try:
        _evaluate(request, result)
    except (PlanInputError, OverflowError, RecursionError) as error:
        result['errors'] = [str(error) if isinstance(error, PlanInputError) else 'input_bounds_invalid']
        result['decision'] = 'invalid_input'
    return result


def _evaluate(request, result):
    object_fields(request, ('schema', 'evaluated_at', 'storage', 'inventory', 'source', 'selection'),
                  'request_schema_invalid')
    require(request['schema'] == REQUEST_SCHEMA, 'request_schema_invalid')
    now = timestamp(request['evaluated_at'])
    state = request['storage']
    require(isinstance(state, dict) and state.get('mode') in ('system-root', 'hybrid'),
            'storage_mode_unsupported')
    fields = {'schema', 'mode', 'root_uuid', 'device_wwn'}
    if state['mode'] == 'hybrid':
        fields |= {'depot_uuid', 'depot_wwn', 'depot_path', 'queue_location'}
    object_fields(state, fields, 'storage_schema_invalid')
    require(type(state['schema']) is int and state['schema'] == 1
            and canonical_uuid(state['root_uuid']) and isinstance(state['device_wwn'], str)
            and WWN.fullmatch(state['device_wwn']), 'storage_identity_invalid')
    action = 'add-primary' if state['mode'] == 'system-root' else 'add-mirror'
    result.update(action=action, mode=state['mode'], planned_steps=planned_steps(action),
        excluded_paths=['/srv/fls-server/database/mysql', '/srv/fls-server/queue'],
        required_confirmation={'text': 'TAMAM', 'collected': False,
            'effect': 'selected_disk_entire_contents_erased'},
        migration_scope=[dict(item) for item in SCOPE] if action == 'add-primary' else [
            {'source': '/srv/fls-storage', 'target': '/srv/fls-mirror',
             'managed_directories': ['FLS-Logs/raw', 'FLS-Logs/archive', 'FLS-Logs/metrics',
                'FLS-Backups/staging', 'FLS-Backups/published', 'DB-Dump']}])
    if action == 'add-mirror':
        require(canonical_uuid(state['depot_uuid']) and isinstance(state['depot_wwn'], str)
                and WWN.fullmatch(state['depot_wwn']) and state['root_uuid'] != state['depot_uuid']
                and state['device_wwn'] != state['depot_wwn']
                and state['depot_path'] == '/srv/fls-storage', 'depot_identity_invalid')
        require(state['queue_location'] == 'system', 'queue_policy_requires_system')
    inventory = request['inventory']
    object_fields(inventory, ('schema', 'boot_id', 'observed_at', 'disks', 'mirror_configured'),
                  'inventory_schema_invalid')
    require(inventory['schema'] == INVENTORY_SCHEMA and canonical_uuid(inventory['boot_id'])
            and type(inventory['mirror_configured']) is bool
            and isinstance(inventory['disks'], list) and 1 <= len(inventory['disks']) <= 64,
            'inventory_schema_invalid')
    require(-5 <= (now - timestamp(inventory['observed_at'])).total_seconds() <= MAX_AGE_SECONDS,
            'inventory_stale')
    disks = [disk_record(value) for value in inventory['disks']]
    for field in ('wwn', 'serial', 'major_minor'):
        values = [disk[field] for disk in disks if disk[field]]
        require(len(values) == len(set(values)), 'inventory_duplicate_' + field)
    root = next((disk for disk in disks if disk['wwn'] == state['device_wwn']), None)
    require(root is not None, 'system_disk_missing')
    source_partition(root, state['root_uuid'], 'system')
    source_disk, source_uuid = root, state['root_uuid']
    if action == 'add-mirror':
        source_disk = next((disk for disk in disks if disk['wwn'] == state['depot_wwn']), None)
        require(source_disk is not None, 'primary_disk_missing')
        source_uuid = state['depot_uuid']
        part = source_partition(source_disk, source_uuid, 'primary')
        require(source_disk['partition_table'] == 'gpt' and len(source_disk['partitions']) == 1
                and part['number'] == 1, 'primary_requires_single_gpt_ext4_partition')
    require(not inventory['mirror_configured'], 'mirror_already_configured')
    source = request['source']
    object_fields(source, ('measured_at', 'boot_id', 'filesystem_uuid', 'wwn',
                          'data_bytes', 'metadata_bytes', 'reserve_bytes', 'file_count'),
                  'source_schema_invalid')
    require(-5 <= (now - timestamp(source['measured_at'])).total_seconds() <= MAX_AGE_SECONDS,
            'source_measurement_stale')
    require(source['boot_id'] == inventory['boot_id'] and source['filesystem_uuid'] == source_uuid
            and source['wwn'] == source_disk['wwn'], 'source_identity_changed')
    require(all(integer(source[field]) for field in ('data_bytes', 'metadata_bytes', 'reserve_bytes', 'file_count'))
            and source['reserve_bytes'] > 0, 'source_capacity_invalid')
    required_usable = source['data_bytes'] + source['metadata_bytes'] + source['reserve_bytes']
    require(required_usable <= MAX_INTEGER
            and source['data_bytes'] + source['metadata_bytes'] <= source_disk['size_bytes'],
            'source_capacity_invalid')
    required_disk = required_usable + PARTITION_ALLOWANCE_BYTES
    if action == 'add-mirror':
        required_disk = max(required_disk, source_disk['size_bytes'])
    require(required_disk <= MAX_INTEGER, 'source_capacity_invalid')
    result['capacity'] = {'data_bytes': source['data_bytes'], 'metadata_bytes': source['metadata_bytes'],
        'reserve_bytes': source['reserve_bytes'], 'file_count': source['file_count'],
        'required_usable_bytes_after_format': required_usable,
        'partition_allowance_bytes': PARTITION_ALLOWANCE_BYTES,
        'required_disk_bytes_lower_bound': required_disk,
        'actual_usable_bytes_verified': False,
        'filesystem_metadata_overhead': 'unknown_until_formatted_and_measured',
        'mirror_at_least_primary_physical_disk_bytes': action == 'add-mirror'}
    protected = {state['device_wwn'], state.get('depot_wwn')}
    for disk in disks:
        reasons = identity_errors(disk)
        if disk['wwn'] in protected:
            reasons.append('protected_role')
        for field, code in (('read_only', 'read_only'), ('removable', 'removable'),
                ('mounted', 'mounted'), ('swap', 'swap_in_use'), ('holders', 'active_holders'),
                ('open_handles', 'open_block_device')):
            if disk[field]:
                reasons.append(code)
        if not disk['usage_known']:
            reasons.append('usage_unknown')
        if disk['size_bytes'] < required_disk:
            reasons.append('capacity_too_small')
        result['candidates'].append({'wwn': disk['wwn'], 'serial': disk['serial'], 'model': disk['model'],
            'size_bytes': disk['size_bytes'], 'identity_sha256': identity_sha256(inventory['boot_id'], disk),
            'eligible_in_supplied_inventory': not reasons, 'reasons': sorted(set(reasons))})
    selection = request['selection']
    if selection is None:
        result['decision'] = ('selection_required' if any(
            disk['eligible_in_supplied_inventory'] for disk in result['candidates'])
            else 'no_eligible_candidate')
        return
    object_fields(selection, ('wwn', 'identity_sha256'), 'selection_schema_invalid')
    require(isinstance(selection['wwn'], str) and WWN.fullmatch(selection['wwn'])
            and isinstance(selection['identity_sha256'], str) and HASH.fullmatch(selection['identity_sha256']),
            'selection_identity_invalid')
    selected = next((disk for disk in result['candidates'] if disk['wwn'] == selection['wwn']), None)
    if selected is None:
        result.update(decision='rejected', errors=['selected_disk_missing'])
    elif selection['identity_sha256'] != selected['identity_sha256']:
        result.update(decision='rejected', errors=['selection_identity_stale'], selected_candidate=selected)
    elif not selected['eligible_in_supplied_inventory']:
        result.update(decision='rejected', errors=selected['reasons'], selected_candidate=selected)
    else:
        result.update(decision='eligible_in_supplied_inventory', selected_candidate=selected)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(PlanInputError('json_constant_invalid')))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, help='Supplied JSON fixture, or - for standard input')
    args = parser.parse_args(argv)
    try:
        if args.input == '-':
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with open(args.input, 'rb') as stream:
                raw = stream.read(MAX_INPUT_BYTES + 1)
        require(len(raw) <= MAX_INPUT_BYTES, 'request_too_large')
        result = evaluate(strict_json(raw))
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        result = evaluate(None)
        result['errors'] = [str(error) if isinstance(error, PlanInputError) else 'input_unreadable_or_invalid_json']
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0 if result['decision'] in ('selection_required', 'eligible_in_supplied_inventory') else 2


if __name__ == '__main__':
    raise SystemExit(main())
