#!/usr/bin/python3
"""Offline storage contract fixtures. No host discovery, mounts or disk writes."""
import ast
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_MODULE = ROOT / 'tools/community/overlay/bin/storage_migration_plan.py'
MODULE = PRIVATE_MODULE if PRIVATE_MODULE.is_file() else ROOT / 'bin/storage_migration_plan.py'
SPEC = importlib.util.spec_from_file_location('community_storage_plan_fixture', MODULE)
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)
BOOT = '11111111-1111-4111-8111-111111111111'
ROOT_UUID = '22222222-2222-4222-8222-222222222222'
DEPOT_UUID = '33333333-3333-4333-8333-333333333333'
SYSTEM_WWN = '0x5000000000000001'
PRIMARY_WWN = '0x5000000000000002'
CANDIDATE_WWN = '0x5000000000000003'
GIB = 1024**3


def disk(wwn, number, size=128 * GIB, filesystem_uuid=None):
    return {'wwn': wwn, 'serial': 'FIXTURE-' + str(number), 'model': 'Synthetic disk',
        'size_bytes': size, 'logical_sector': 512, 'diskseq': number,
        'major_minor': '8:' + str(number * 16), 'sysfs_wwid': 'naa.' + wwn[2:],
        'read_only': False, 'removable': False, 'mounted': filesystem_uuid is not None,
        'swap': False, 'holders': 0, 'open_handles': 0, 'usage_known': True,
        'partition_table': 'gpt' if filesystem_uuid else '',
        'partitions': [{'number': 1, 'uuid': filesystem_uuid, 'filesystem': 'ext4',
                        'layout': 'plain-partition'}] if filesystem_uuid else []}


def request(hybrid=False):
    value = {'schema': planner.REQUEST_SCHEMA, 'evaluated_at': '2026-01-01T00:00:30Z',
        'storage': {'schema': 1, 'mode': 'system-root', 'root_uuid': ROOT_UUID,
                    'device_wwn': SYSTEM_WWN},
        'inventory': {'schema': planner.INVENTORY_SCHEMA, 'boot_id': BOOT,
            'observed_at': '2026-01-01T00:00:00Z', 'mirror_configured': False,
            'disks': [disk(SYSTEM_WWN, 1, 128 * GIB, ROOT_UUID), disk(CANDIDATE_WWN, 3)]},
        'source': {'measured_at': '2026-01-01T00:00:00Z', 'boot_id': BOOT,
            'filesystem_uuid': ROOT_UUID, 'wwn': SYSTEM_WWN, 'data_bytes': 20 * GIB,
            'metadata_bytes': 64 * 1024**2, 'reserve_bytes': 10 * GIB, 'file_count': 200},
        'selection': None}
    if hybrid:
        value['storage'].update(mode='hybrid', depot_uuid=DEPOT_UUID, depot_wwn=PRIMARY_WWN,
                               depot_path='/srv/fls-storage', queue_location='system')
        value['inventory']['disks'].insert(1, disk(PRIMARY_WWN, 2, 128 * GIB, DEPOT_UUID))
        value['source'].update(filesystem_uuid=DEPOT_UUID, wwn=PRIMARY_WWN)
    return value


def select(value, wwn=CANDIDATE_WWN):
    selected = next(item for item in value['inventory']['disks'] if item['wwn'] == wwn)
    value['selection'] = {'wwn': wwn,
        'identity_sha256': planner.identity_sha256(value['inventory']['boot_id'], selected)}
    return value


class CommunityStoragePlanTests(unittest.TestCase):
    def assert_disabled(self, result):
        self.assertIs(result['execution_available'], False)
        self.assertIs(result['safe_to_execute'], False)
        self.assertIs(result['applied'], False)
        self.assertIs(result['host_inspected'], False)
        self.assertIs(result['input_authenticity_verified'], False)

    def test_single_disk_adds_primary_without_automatic_selection(self):
        result = planner.evaluate(request())
        self.assertEqual(result['action'], 'add-primary')
        self.assertEqual(result['decision'], 'selection_required')
        self.assertIsNone(result['selected_candidate'])
        self.assert_disabled(result)

    def test_selected_fixture_is_eligible_but_never_executable(self):
        result = planner.evaluate(select(request()))
        self.assertEqual(result['decision'], 'eligible_in_supplied_inventory')
        self.assertEqual(result['selected_candidate']['wwn'], CANDIDATE_WWN)
        self.assertEqual(result['required_confirmation']['text'], 'TAMAM')
        self.assertFalse(result['required_confirmation']['collected'])
        self.assertIn('executor_not_implemented', result['execution_blockers'])
        self.assert_disabled(result)

    def test_hybrid_adds_only_mirror_with_fixed_direction_and_managed_scope(self):
        result = planner.evaluate(select(request(hybrid=True)))
        self.assertEqual(result['action'], 'add-mirror')
        scope = result['migration_scope'][0]
        self.assertEqual((scope['source'], scope['target']), ('/srv/fls-storage', '/srv/fls-mirror'))
        self.assertNotIn('FLS-Logs/queue', scope['managed_directories'])
        self.assertEqual(len(scope['managed_directories']), 6)
        self.assert_disabled(result)

    def test_primary_may_be_smaller_than_system_when_measured_data_fits(self):
        value = request()
        value['inventory']['disks'][-1]['size_bytes'] = 40 * GIB
        result = planner.evaluate(select(value))
        self.assertEqual(result['decision'], 'eligible_in_supplied_inventory')
        capacity = result['capacity']
        self.assertEqual(capacity['required_usable_bytes_after_format'],
                         30 * GIB + 64 * 1024**2)
        self.assertFalse(capacity['actual_usable_bytes_verified'])

    def test_capacity_accounts_for_data_metadata_reserve_and_partition_allowance(self):
        value = request()
        capacity = planner.evaluate(value)['capacity']
        required = capacity['required_disk_bytes_lower_bound']
        value['inventory']['disks'][-1]['size_bytes'] = required - 1
        result = planner.evaluate(select(value))
        self.assertEqual(result['decision'], 'rejected')
        self.assertIn('capacity_too_small', result['errors'])

    def test_mirror_cannot_be_smaller_than_primary_even_when_files_fit(self):
        value = request(hybrid=True)
        value['inventory']['disks'][-1]['size_bytes'] = 128 * GIB - 1
        result = planner.evaluate(select(value))
        self.assertEqual(result['decision'], 'rejected')
        self.assertIn('capacity_too_small', result['errors'])

    def test_no_disk_is_silently_selected_when_multiple_are_available(self):
        value = request()
        value['inventory']['disks'].append(disk('0x5000000000000004', 4))
        result = planner.evaluate(value)
        self.assertEqual(result['decision'], 'selection_required')
        self.assertIsNone(result['selected_candidate'])

    def test_no_eligible_disk_does_not_report_selection_ready(self):
        value = request()
        value['inventory']['disks'].pop()
        result = planner.evaluate(value)
        self.assertEqual(result['decision'], 'no_eligible_candidate')
        self.assert_disabled(result)

    def test_system_and_existing_primary_are_protected(self):
        for wwn in (SYSTEM_WWN, PRIMARY_WWN):
            with self.subTest(wwn=wwn):
                result = planner.evaluate(select(request(hybrid=True), wwn))
                self.assertEqual(result['decision'], 'rejected')
                self.assertIn('protected_role', result['errors'])

    def test_busy_removable_readonly_and_unknown_usage_reject_candidates(self):
        cases = [('mounted', True, 'mounted'), ('swap', True, 'swap_in_use'),
            ('holders', 1, 'active_holders'), ('open_handles', 1, 'open_block_device'),
            ('removable', True, 'removable'), ('read_only', True, 'read_only'),
            ('usage_known', False, 'usage_unknown')]
        for field, value, expected in cases:
            with self.subTest(field=field):
                fixture = request()
                fixture['inventory']['disks'][-1][field] = value
                result = planner.evaluate(select(fixture))
                self.assertEqual(result['decision'], 'rejected')
                self.assertIn(expected, result['errors'])

    def test_missing_or_mismatched_naa_identity_and_sector_geometry_are_rejected(self):
        cases = [('wwn', ''), ('sysfs_wwid', 'eui.5000000000000003'),
                 ('serial', ''), ('logical_sector', 1024), ('diskseq', 0)]
        for field, replacement in cases:
            with self.subTest(field=field):
                fixture = request()
                fixture['inventory']['disks'][-1][field] = replacement
                result = planner.evaluate(fixture)
                candidate = result['candidates'][-1]
                self.assertFalse(candidate['eligible_in_supplied_inventory'])
                self.assertTrue(candidate['reasons'])

    def test_4k_sector_candidate_is_supported(self):
        value = request()
        value['inventory']['disks'][-1]['logical_sector'] = 4096
        self.assertEqual(planner.evaluate(select(value))['decision'], 'eligible_in_supplied_inventory')

    def test_selected_identity_is_bound_to_boot_diskseq_serial_size_and_device(self):
        for field, replacement in [('diskseq', 50), ('serial', 'CHANGED'),
                ('size_bytes', 129 * GIB), ('major_minor', '8:240')]:
            with self.subTest(field=field):
                value = select(request())
                value['inventory']['disks'][-1][field] = replacement
                result = planner.evaluate(value)
                self.assertEqual(result['errors'], ['selection_identity_stale'])
        value = select(request())
        value['inventory']['boot_id'] = '44444444-4444-4444-8444-444444444444'
        value['source']['boot_id'] = value['inventory']['boot_id']
        self.assertEqual(planner.evaluate(value)['errors'], ['selection_identity_stale'])

    def test_freshness_is_explicit_and_uses_supplied_clock_only(self):
        for field in ('inventory', 'source'):
            for moment in ('2025-12-31T23:59:00Z', '2026-01-01T00:00:36Z'):
                with self.subTest(field=field, moment=moment):
                    value = request()
                    value[field]['observed_at' if field == 'inventory' else 'measured_at'] = moment
                    result = planner.evaluate(value)
                    self.assertEqual(result['decision'], 'invalid_input')
                    self.assertIn('stale', result['errors'][0])

    def test_source_identity_change_never_produces_candidate_approval(self):
        for field, replacement in [('boot_id', 'bad'), ('filesystem_uuid', DEPOT_UUID),
                                    ('wwn', PRIMARY_WWN)]:
            with self.subTest(field=field):
                value = select(request())
                value['source'][field] = replacement
                result = planner.evaluate(value)
                self.assertEqual(result['errors'], ['source_identity_changed'])
                self.assertIsNone(result['selected_candidate'])

    def test_lvm_raid_other_filesystem_and_noncanonical_uuid_fail_closed(self):
        for field, replacement in [('layout', 'lvm'), ('layout', 'raid'),
                ('filesystem', 'xfs'), ('uuid', 'not-a-uuid')]:
            with self.subTest(field=field, replacement=replacement):
                value = request()
                value['inventory']['disks'][0]['partitions'][0][field] = replacement
                result = planner.evaluate(value)
                self.assertEqual(result['errors'], ['system_requires_plain_ext4'])
        value = request()
        value['storage']['root_uuid'] = ROOT_UUID.upper().replace('2', 'A', 1)
        self.assertEqual(planner.evaluate(value)['errors'], ['storage_identity_invalid'])

    def test_hybrid_requires_separate_single_gpt_ext4_primary_and_ssd_queue(self):
        cases = [('queue_location', 'depot', 'queue_policy_requires_system'),
                 ('depot_wwn', SYSTEM_WWN, 'depot_identity_invalid'),
                 ('depot_path', '/tmp/untrusted', 'depot_identity_invalid')]
        for field, replacement, error in cases:
            with self.subTest(field=field):
                value = request(hybrid=True)
                value['storage'][field] = replacement
                self.assertEqual(planner.evaluate(value)['errors'], [error])
        value = request(hybrid=True)
        value['inventory']['disks'][1]['partition_table'] = 'dos'
        self.assertEqual(planner.evaluate(value)['errors'], ['primary_requires_single_gpt_ext4_partition'])

    def test_existing_mirror_prevents_second_mirror_or_primary_role_change(self):
        for hybrid in (False, True):
            with self.subTest(hybrid=hybrid):
                value = request(hybrid)
                value['inventory']['mirror_configured'] = True
                self.assertEqual(planner.evaluate(value)['errors'], ['mirror_already_configured'])

    def test_duplicate_disk_identities_fail_closed(self):
        for field in ('wwn', 'serial', 'major_minor'):
            with self.subTest(field=field):
                value = request()
                value['inventory']['disks'][-1][field] = value['inventory']['disks'][0][field]
                self.assertEqual(planner.evaluate(value)['errors'], ['inventory_duplicate_' + field])

    def test_negative_bool_zero_reserve_and_overflow_capacity_are_invalid(self):
        for field, replacement in [('data_bytes', -1), ('metadata_bytes', True),
                ('reserve_bytes', 0), ('reserve_bytes', 2**53), ('file_count', 1.0)]:
            with self.subTest(field=field):
                value = request()
                value['source'][field] = replacement
                self.assertEqual(planner.evaluate(value)['errors'], ['source_capacity_invalid'])

    def test_request_cannot_supply_commands_paths_actions_or_confirmation(self):
        for field, replacement in [('command', 'mkfs.ext4'), ('target', '/dev/sda'),
                                    ('action', 'format'), ('confirmation', 'TAMAM')]:
            with self.subTest(field=field):
                self.assertEqual(planner.evaluate(request() | {field: replacement})['errors'],
                                 ['request_schema_invalid'])

    def test_plan_contains_required_pause_copy_inode_and_cutover_contract(self):
        result = planner.evaluate(select(request()))
        phases = {step['phase']: step['requirements'] for step in result['planned_steps']}
        self.assertIn('stop_and_block_restarts_of_every_migration_scope_writer_and_timer', phases['quiesce'])
        self.assertIn('final_rsync_aHAXS_numeric_ids', phases['final_copy_verify'])
        self.assertIn('sha256_every_copied_regular_file_and_verify_stable_source', phases['final_copy_verify'])
        self.assertIn('verify_owners_modes_acl_xattrs_hardlinks_and_exact_managed_tree', phases['final_copy_verify'])
        for expected in ('transactionally_compare_and_update_source_files_inode',
                'remap_summary_backlog_history_state_cursor_inode',
                'remap_mail_search_backlog_history_state_cursor_inode',
                'never_reset_offsets_or_reimport_existing_records'):
            self.assertIn(expected, phases['checkpoint_remap'])
        self.assertIn('journal_each_mount_sql_and_configuration_commit_boundary', phases['cutover'])
        self.assertIn('storage_guard_in_host_and_real_service_namespace', phases['validate'])
        self.assertIn('retain_old_source_and_old_checkpoint_mapping', phases['retain_and_resume'])
        self.assertIn('after_new_writes_never_blindly_restore_old_source', phases['rollback_policy'])

    def test_pure_evaluation_never_opens_files_or_invokes_processes(self):
        with (patch('builtins.open', side_effect=AssertionError('Host read forbidden')),
              patch.object(subprocess, 'run', side_effect=AssertionError('Process forbidden'))):
            result = planner.evaluate(select(request()))
        self.assertEqual(result['decision'], 'eligible_in_supplied_inventory')

    def test_result_and_input_have_no_shared_mutable_scope(self):
        value = request()
        before = deepcopy(value)
        result = planner.evaluate(value)
        result['migration_scope'][0]['target'] = '/tmp/changed'
        self.assertEqual(value, before)
        self.assertEqual(planner.evaluate(value)['migration_scope'][0]['target'],
                         '/srv/fls-storage/FLS-Logs/raw')

    def test_module_imports_no_host_operations_or_storage_executors(self):
        tree = ast.parse(MODULE.read_text())
        imports = {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports |= {item.name.split('.')[0] for node in ast.walk(tree)
                    if isinstance(node, ast.Import) for item in node.names}
        self.assertTrue(imports <= {'argparse', 'datetime', 'hashlib', 'json', 're', 'sys', 'uuid'})
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in ('exec', 'eval', '__import__') for node in ast.walk(tree)))

    def test_cli_accepts_fixture_and_never_offers_apply_switch(self):
        with tempfile.TemporaryDirectory(prefix='fls-community-storage-fixture-') as temporary:
            path = Path(temporary) / 'request.json'
            path.write_text(json.dumps(select(request())))
            completed = subprocess.run([sys.executable, str(MODULE), '--input', str(path)],
                check=True, text=True, capture_output=True)
            self.assert_disabled(json.loads(completed.stdout))
            refused = subprocess.run([sys.executable, str(MODULE), '--input', str(path), '--apply'],
                text=True, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)

    def test_cli_stdin_rejects_duplicate_keys_malformed_json_and_oversize(self):
        for raw in ('{"schema":1,"schema":2}', '{broken', 'x' * (planner.MAX_INPUT_BYTES + 1),
                    '{"not_json":NaN}'):
            with self.subTest(size=len(raw)):
                completed = subprocess.run([sys.executable, str(MODULE), '--input', '-'],
                    input=raw, text=True, capture_output=True)
                self.assertEqual(completed.returncode, 2)
                result = json.loads(completed.stdout)
                self.assertEqual(result['decision'], 'invalid_input')
                self.assert_disabled(result)


if __name__ == '__main__':
    unittest.main()
