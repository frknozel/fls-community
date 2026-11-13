#!/usr/bin/env python3
"""Community preparation checks: synthetic inventories and private temporary files only."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / 'tools/community/overlay'
SOURCE = OVERLAY if (OVERLAY / 'bin/install_plan.py').is_file() else ROOT
BIN = SOURCE / 'bin'
sys.path.insert(0, str(BIN))
import install_plan as plan

specification = importlib.util.spec_from_file_location('fls_community_install_cli', BIN / 'fls-install.py')
cli = importlib.util.module_from_spec(specification)
specification.loader.exec_module(cli)
MANIFEST = plan.read_json(SOURCE / 'deploy/installer-components.json')


def inventory():
    return {'machine_sha256': 'a' * 64, 'schema': plan.INVENTORY_SCHEMA, 'effective_uid': 0,
            'os': {'id': 'ubuntu', 'version_id': '24.04'}, 'architecture': 'x86_64',
            'ram_bytes': 16 * plan.GIB, 'free_bytes': 100 * plan.GIB, 'cpu_count': 4,
            'hostname': 'fls-test', 'default_route_interface': 'ens3',
            'addresses': [{'address': '192.168.50.10', 'prefixlen': 24, 'interface': 'ens3'}],
            'root': {'source': '/dev/sda2', 'fstype': 'ext4',
                     'uuid': 'b85ec2af-fafd-429f-a4d8-ea3feff8f382', 'major_minor': '8:2',
                     'disk_path': '/dev/sda', 'disk_wwn': '0x5000000000000001',
                     'plain_partition': True, 'hardware_identity_matches': True},
            'disks': [{'path': '/dev/sda', 'wwn': '0x5000000000000001', 'serial': 'FAKE-SYSTEM',
                       'model': 'synthetic', 'size_bytes': 240 * plan.GIB, 'mounted': True,
                       'read_only': False, 'role': 'system'}],
            'existing_paths': [], 'database_directories': [], 'listening_ports': [], 'probe_errors': []}


def components():
    return [{**{key: item[key] for key in ('id', 'required', 'kind', 'relative_path', 'source_status', 'reason')},
             'present': False, 'verified': False, 'status': 'missing'} for item in MANIFEST['components']]


def assess(value=None, **kwargs):
    return plan.assess(inventory() if value is None else value, MANIFEST, components(), **kwargs)


class PlanningChecks(unittest.TestCase):
    def test_one_disk_passes_host_requirements_but_missing_release_artifacts_block_apply(self):
        result = assess()
        self.assertTrue(result['host_requirements_met'])
        self.assertTrue(result['apply_supported'])
        self.assertFalse(result['ready_for_apply'])
        self.assertTrue(result['storage']['single_disk_allowed'])
        self.assertEqual(result['storage']['initial_mode'], 'system-root')
        self.assertIn('checked_write_collector_artifact_missing', result['blockers'])
        self.assertFalse(any(result['effects'].values()))

    def test_no_side_effect_dependencies_called_by_assessment(self):
        with patch.object(plan.subprocess, 'run', side_effect=AssertionError('host command')), \
             patch.object(plan.os, 'open', side_effect=AssertionError('host file')):
            result = assess()
        self.assertTrue(result['host_requirements_met'])

    def test_multiple_disks_are_unassigned_and_never_selected(self):
        value = inventory()
        value['disks'].extend([
            {'path': '/dev/sdb', 'wwn': '0x5000000000000002', 'serial': 'FAKE-EXTRA',
             'model': 'synthetic', 'size_bytes': 2_000 * plan.GIB, 'mounted': False,
             'read_only': False, 'role': 'unassigned'},
            {'path': '/dev/sdc', 'wwn': '0x5000000000000003', 'serial': 'FAKE-INUSE',
             'model': 'synthetic', 'size_bytes': 500 * plan.GIB, 'mounted': True,
             'read_only': False, 'role': 'unassigned'}])
        result = assess(value)
        self.assertTrue(result['host_requirements_met'])
        self.assertEqual(len(result['storage']['disks']), 3)
        self.assertTrue(all(row['selected_for_format'] is False for row in result['storage']['disks']))
        self.assertFalse(result['storage']['automatic_partitioning'])
        self.assertTrue(result['storage']['later_depot_migration_available'])

    def test_existing_fls_or_mysql_is_rejected(self):
        for field, content, code in [
                ('existing_paths', ['/etc/fls'], 'existing_fls_installation_requires_upgrade'),
                ('existing_paths', ['/etc/systemd/system/fortigate-collector.service'], 'existing_fls_installation_requires_upgrade'),
                ('database_directories', ['/var/lib/mysql'], 'existing_database_directory_not_empty')]:
            with self.subTest(field=field, content=content):
                value = inventory()
                value[field] = content
                self.assertIn(code, assess(value)['host_blockers'])

    def test_platform_privilege_and_inventory_fail_closed(self):
        cases = [('effective_uid', 1000, 'root_required'),
                 ('os', {'id': 'ubuntu', 'version_id': '22.04'}, 'ubuntu_24_04_required'),
                 ('architecture', 'aarch64', 'amd64_required'),
                 ('probe_errors', ['unavailable'], 'host_inventory_incomplete')]
        for field, content, code in cases:
            with self.subTest(field=field):
                value = inventory()
                value[field] = content
                self.assertIn(code, assess(value)['host_blockers'])

    def test_root_lvm_raid_unknown_wwn_and_uuid_are_unsupported(self):
        for change, code in [({'plain_partition': False}, 'plain_ext4_root_partition_required'),
                             ({'fstype': 'btrfs'}, 'plain_ext4_root_partition_required'),
                             ({'uuid': None}, 'root_filesystem_uuid_required'),
                             ({'disk_wwn': ''}, 'stable_disk_identity_required'),
                             ({'hardware_identity_matches': False}, 'stable_disk_identity_required')]:
            with self.subTest(change=change):
                value = inventory()
                value['root'].update(change)
                self.assertIn(code, assess(value)['host_blockers'])

    def test_readonly_or_ambiguous_system_disk_rejected(self):
        value = inventory()
        value['disks'][0]['read_only'] = True
        self.assertIn('root_physical_disk_unambiguous_required', assess(value)['host_blockers'])
        value = inventory()
        value['disks'].append(copy.deepcopy(value['disks'][0]))
        self.assertIn('root_physical_disk_unambiguous_required', assess(value)['host_blockers'])

    def test_tcp_ports_block_ipv4_or_ipv6_equally_but_udp_does_not(self):
        for port in (443, 5514):
            value = inventory()
            value['listening_ports'] = [{'port': port, 'protocol': 'tcp'}]
            self.assertIn(f'tcp_port_{port}_in_use', assess(value)['host_blockers'])
        value = inventory()
        value['listening_ports'] = [{'port': 5514, 'protocol': 'udp'}]
        self.assertTrue(assess(value)['host_requirements_met'])

    def test_ram_and_free_space_have_discrete_errors_and_bounded_dynamic_sizing(self):
        value = inventory()
        value['ram_bytes'] = 4 * plan.GIB
        value['free_bytes'] = 20 * plan.GIB
        result = assess(value)
        self.assertIn('ram_below_minimum', result['host_blockers'])
        self.assertIn('free_space_below_minimum', result['host_blockers'])
        samples = []
        for size in (8, 16, 32, 256):
            value = inventory()
            value['ram_bytes'] = size * plan.GIB
            sizing = assess(value)['sizing_proposal']
            samples.append(sizing['mariadb_buffer_pool_bytes'])
            self.assertLessEqual(sizing['mariadb_buffer_pool_bytes'], value['ram_bytes'] // 4)
            self.assertLessEqual(sizing['mariadb_buffer_pool_bytes'], 8 * plan.GIB)
            self.assertGreaterEqual(sizing['php_max_children'], 2)
            self.assertLessEqual(sizing['php_max_children'], 8)
        self.assertEqual(samples[:3], [2 * plan.GIB, 4 * plan.GIB, 8 * plan.GIB])

    def test_auto_network_uses_default_interface_and_preserves_hostname(self):
        value = inventory()
        value['addresses'].append({'address': '10.10.1.1', 'prefixlen': 24, 'interface': 'ens9'})
        proposal = assess(value)['configuration_proposal']
        self.assertEqual(proposal['bind_ip'], '192.168.50.10')
        self.assertEqual(proposal['management_network'], '192.168.50.0/24')
        self.assertEqual(proposal['hostname'], 'fls-test')
        self.assertEqual(proposal['tls_subject_alternative_names'], ['fls-test', '192.168.50.10'])

    def test_ambiguous_network_requires_explicit_existing_address(self):
        value = inventory()
        value['addresses'].append({'address': '192.168.50.11', 'prefixlen': 24, 'interface': 'ens3'})
        self.assertIn('bind_ip_ambiguous', assess(value)['host_blockers'])
        result = assess(value, bind_ip='192.168.50.11', hostname='fls.example.test',
                        management_network='192.168.50.0/25')
        self.assertTrue(result['host_requirements_met'])
        self.assertEqual(result['configuration_proposal']['bind_ip'], '192.168.50.11')
        self.assertIn('bind_ip_not_uniquely_local', assess(value, bind_ip='10.0.0.9')['host_blockers'])

    def test_invalid_host_ip_or_management_range_cannot_be_rendered(self):
        for arguments, code in [({'hostname': 'fls; return 200;'}, 'hostname_invalid'),
                                ({'bind_ip': '127.0.0.1'}, 'bind_ip_invalid'),
                                ({'management_network': '0.0.0.0/0'}, 'management_network_invalid'),
                                ({'management_network': '10.1.0.0/16'}, 'management_network_invalid')]:
            with self.subTest(arguments=arguments):
                self.assertIn(code, assess(**arguments)['host_blockers'])

    def test_dependency_blockers_are_explicit_and_provider_is_optional(self):
        result = assess()
        self.assertIn('native_archive_helper_not_packaged', result['blockers'])
        self.assertIn('checked_write_collector_artifact_missing', result['blockers'])
        self.assertEqual(result['dependencies']['package_policy']['php_version'], '8.3')
        self.assertNotIn('stock_ubuntu_package_profile_unverified', result['blockers'])
        self.assertNotIn('provider_runtime_not_distributed', result['blockers'])
        self.assertFalse(result['dependencies']['provider_enabled'])
        self.assertTrue(result['dependencies']['package_policy']['system_rsyslog_is_not_fls_collector'])

    def test_fixture_origin_never_claims_host_was_inspected(self):
        result = assess(origin='supplied_fixture')
        self.assertFalse(result['host_inspected'])
        self.assertIn('fixture_is_not_a_host_installation_check', result['warnings'])
        self.assertFalse(result['ready_for_apply'])

    def test_inventory_rejects_bool_sizes_and_malformed_rows(self):
        for key, content in [('ram_bytes', True), ('listening_ports', [{'port': 443, 'protocol': 'bad'}]),
                             ('disks', ['not a disk'])]:
            with self.subTest(key=key), self.assertRaises(plan.PlanError):
                value = inventory()
                value[key] = content
                assess(value)

    def test_component_paths_cannot_escape_source(self):
        for path in ('../private', '/etc/shadow', 'artifacts/../../private'):
            value = copy.deepcopy(MANIFEST)
            value['components'][0]['relative_path'] = path
            with self.subTest(path=path), self.assertRaises(plan.PlanError):
                plan.validate_components(value)


class FileAndCLIChecks(unittest.TestCase):
    def test_artifact_is_hash_checked_never_executed_and_links_rejected(self):
        with tempfile.TemporaryDirectory(prefix='fls-community-install-test-') as temporary:
            source = Path(temporary)
            value = copy.deepcopy(MANIFEST)
            value['components'] = [value['components'][0]]
            row = value['components'][0]
            path = source / row['relative_path']
            self.assertEqual(plan.inspect_components(value, source)[0]['status'], 'missing')
            path.parent.mkdir(parents=True)
            data = b'fixture artifact; never executable\n'
            path.write_bytes(data)
            row['sha256'] = None
            self.assertEqual(plan.inspect_components(value, source)[0]['status'], 'checksum_unpinned')
            row['sha256'] = hashlib.sha256(data).hexdigest()
            self.assertTrue(plan.inspect_components(value, source)[0]['verified'])
            path.write_bytes(data + b'changed')
            self.assertEqual(plan.inspect_components(value, source)[0]['status'], 'checksum_mismatch')
            path.unlink()
            path.symlink_to(source / 'missing')
            self.assertEqual(plan.inspect_components(value, source)[0]['status'], 'unsafe_or_unreadable')

    def test_fixture_json_duplicate_keys_and_links_rejected(self):
        with tempfile.TemporaryDirectory(prefix='fls-community-install-test-') as temporary:
            folder = Path(temporary)
            path = folder / 'inventory.json'
            path.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(plan.PlanError):
                plan.read_json(path)
            path.write_text('{"value":NaN}')
            with self.assertRaises(plan.PlanError):
                plan.read_json(path)
            link = folder / 'linked.json'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                plan.read_json(link)

    def test_apply_is_rejected_before_any_host_or_file_probe(self):
        with patch.object(cli, 'collect_inventory', side_effect=AssertionError('host inspected')), \
             patch.object(cli, 'read_json', side_effect=AssertionError('file read')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            status = cli.main(['--apply', '--inventory', '/not/read'])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())['error_code'], 'fixture_apply_forbidden')

    def test_cli_plan_and_check_read_only_fixture_contract(self):
        with tempfile.TemporaryDirectory(prefix='fls-community-install-test-') as temporary:
            folder = Path(temporary)
            path = folder / 'inventory.json'
            path.write_text(json.dumps(inventory()))
            before = path.read_bytes()
            environment = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
            for arguments, expected in [(['--plan'], 0), (['--check'], 2)]:
                result = subprocess.run([sys.executable, '-B', str(BIN / 'fls-install.py'),
                                         *arguments, '--inventory', str(path)],
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['schema'], plan.PLAN_SCHEMA)
                self.assertFalse(report['host_inspected'])
                self.assertTrue(report['host_requirements_met'])
                self.assertFalse(any(report['effects'].values()))
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(folder.iterdir()), [path])

    def test_stock_package_profile_and_vm_serial_are_supported_without_autoformat(self):
        value = inventory()
        value['root']['disk_wwn'] = ''
        value['disks'][0]['wwn'] = ''
        value['root']['device_identity'] = {'kind': 'serial', 'value': 'FLS-VM-SYSTEM-001'}
        result = assess(value)
        self.assertTrue(result['host_requirements_met'])
        self.assertFalse(result['storage']['automatic_partitioning'])
        self.assertTrue(all('php8.5' not in name for name in result['dependencies']['packages']))
        self.assertFalse(result['ready_for_apply'])

    def test_verified_artifacts_make_actual_host_plan_ready_but_fixture_never_ready(self):
        verified = [{**row, 'present': True, 'verified': True, 'status': 'verified'} for row in components()]
        result = plan.assess(inventory(), MANIFEST, verified)
        self.assertTrue(result['ready_for_apply'])
        fixture = plan.assess(inventory(), MANIFEST, verified, origin='supplied_fixture')
        self.assertFalse(fixture['ready_for_apply'])
        self.assertFalse(any(fixture['effects'].values()))

    def test_entrypoints_do_not_create_bytecode_or_any_other_source_files(self):
        with tempfile.TemporaryDirectory(prefix='fls-community-install-test-') as temporary:
            folder = Path(temporary)
            source = folder / 'source'
            (source / 'bin').mkdir(parents=True)
            (source / 'deploy').mkdir()
            for name in ('install.sh', 'bin/fls-install.py', 'bin/install_plan.py', 'deploy/installer-components.json'):
                shutil.copy2(SOURCE / name, source / name)
            fixture = folder / 'inventory.json'
            fixture.write_text(json.dumps(inventory()))
            before = {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in folder.rglob('*') if path.is_file()}
            environment = dict(os.environ)
            environment.pop('PYTHONDONTWRITEBYTECODE', None)
            for command in ([sys.executable, str(source / 'bin/fls-install.py')],):
                result = subprocess.run([*command, '--plan', '--inventory', str(fixture)],
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            after = {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in folder.rglob('*') if path.is_file()}
            self.assertEqual(after, before)
            self.assertFalse(any(folder.rglob('__pycache__')))



class AdmissionDiagnosticsChecks(unittest.TestCase):
    def invoke(self, value, argv):
        import community_install as engine
        artifacts = components()
        for item in artifacts:
            if item['required']: item.update(present=True, verified=True, status='verified')
        output = io.StringIO()
        with patch.object(cli, 'collect_inventory', return_value=value), \
             patch.object(cli, 'inspect_components', return_value=artifacts), \
             patch.object(engine, 'apply', side_effect=AssertionError('host apply must not run')) as apply, \
             contextlib.redirect_stdout(output):
            code = cli.main(argv)
        return code, json.loads(output.getvalue()), apply

    def test_missing_disk_identity_has_specific_prewrite_error_and_no_apply(self):
        value = inventory()
        value['root'].update(disk_wwn='', device_identity=None, hardware_identity_matches=False)
        value['disks'][0]['wwn'] = ''
        code, result, apply = self.invoke(value, ['--apply'])
        self.assertEqual(code, 2); apply.assert_not_called()
        self.assertEqual(result['blockers'], ['stable_disk_identity_required'])
        self.assertFalse(result['installation_started']); self.assertFalse(result['target_modified'])
        self.assertEqual(result['retry'], 'fix_preflight_and_retry')
        self.assertIn('disk.EnableUUID=TRUE', result['diagnostics'][0]['message'])
        self.assertNotIn('restore_clean_snapshot', json.dumps(result))
        for sensitive in ('FAKE-SYSTEM', '192.168.50.10', value['root']['uuid'], value['machine_sha256']):
            self.assertNotIn(sensitive, json.dumps(result))

    def test_multiple_blockers_and_inventory_probe_codes_survive(self):
        value = inventory(); value['ram_bytes'] = 2 * plan.GIB
        value['free_bytes'] = 20 * plan.GIB
        value['probe_errors'] = ['network_inventory_unavailable']
        code, result, apply = self.invoke(value, ['--apply'])
        self.assertEqual(code, 2); apply.assert_not_called()
        self.assertTrue({'ram_below_minimum', 'free_space_below_minimum', 'host_inventory_incomplete'}.issubset(result['blockers']))
        self.assertEqual(result['probe_errors'], ['network_inventory_unavailable'])

    def test_read_only_check_reports_probe_details_without_applying(self):
        value = inventory(); value['probe_errors'] = ['port_inventory_unavailable']
        code, result, apply = self.invoke(value, ['--check'])
        self.assertEqual(code, 2); apply.assert_not_called()
        self.assertTrue(result['read_only'])
        self.assertEqual(result['probe_errors'], ['port_inventory_unavailable'])
        self.assertIn('host_inventory_incomplete', result['blockers'])
        self.assertTrue(result['diagnostics'])

    def test_ready_read_only_check_returns_success_without_applying(self):
        code, result, apply = self.invoke(inventory(), ['--check'])
        self.assertEqual(code, 0); apply.assert_not_called()
        self.assertTrue(result['ready_for_apply']); self.assertFalse(any(result['effects'].values()))

    def test_unknown_diagnostic_values_are_redacted_and_bounded(self):
        result = cli.admission_failure({'blockers': ['private_token_sentinel', {'sensitive': 'fixture'}, 'stable_disk_identity_required'] * 100,
                                        'host_blockers': [], 'probe_errors': ['SECRET-FIXTURE']})
        self.assertNotIn('private_token_sentinel', json.dumps(result)); self.assertNotIn('SECRET-FIXTURE', json.dumps(result))
        self.assertEqual(result['blockers'], ['preflight_diagnostic_unavailable', 'stable_disk_identity_required'])
        self.assertEqual(result['probe_errors'], ['preflight_diagnostic_unavailable'])
        self.assertEqual(cli.diagnostic_codes(None), ['preflight_diagnostic_unavailable'])

    def test_abbreviated_apply_flag_is_rejected_before_host_inspection(self):
        with patch.object(cli, 'collect_inventory', side_effect=AssertionError('inventory must not run')), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            cli.main(['--app'])
        self.assertEqual(error.exception.code, 2)

    def test_post_start_failure_retains_snapshot_recovery_instruction(self):
        import community_install as engine
        artifacts = components()
        for item in artifacts:
            if item['required']: item.update(present=True, verified=True, status='verified')
        output = io.StringIO()
        with patch.object(cli, 'collect_inventory', return_value=inventory()), \
             patch.object(cli, 'inspect_components', return_value=artifacts), \
             patch.object(engine, 'apply', side_effect=engine.InstallError('installation_command_failed', 'packages')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['--apply']), 2)
        self.assertEqual(json.loads(output.getvalue())['retry'], 'restore_clean_snapshot_after_a_started_installation')


if __name__ == '__main__':
    unittest.main()
