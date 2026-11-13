#!/usr/bin/env python3
"""Install an authenticated FLS Community release on a fresh Ubuntu 24.04 host."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
from pathlib import Path
from install_plan import (PlanError, assess, collect_inventory, inspect_components,
                          read_json, validate_components)



# Fixed explanations only: never copy device identities, addresses or command stderr.
PREFLIGHT_HELP = {
    'stable_disk_identity_required': 'Diskin kalıcı WWN/WWID/seri kimliği doğrulanamadı. VMware ESXi kullanıyorsanız VM kapalıyken disk.EnableUUID=TRUE ayarını açıp tekrar kontrol edin.',
    'plain_ext4_root_partition_required': 'Sistem kökü düz ext4 bölüm olmalıdır. Bu sürüm LVM/RAID kökünü desteklemiyor.',
    'ram_below_minimum': 'Kullanılabilir toplam RAM yetersiz. VM için en az 8 GiB RAM ayırın.',
    'free_space_below_minimum': 'Sistem kökünde en az 40 GiB boş alan gerekiyor.',
    'existing_fls_installation_requires_upgrade': 'Mevcut FLS kurulumu veya önceki kurulum durumu bulundu. Bu kurucu yalnız temiz hedef içindir.',
    'existing_database_directory_not_empty': 'Mevcut veritabanı dizini boş değil. Temiz hedef gerekiyor.',
    'host_inventory_incomplete': 'Bazı sistem bilgileri okunamadı. probe_errors kodlarını kontrol edin.',
    'root_physical_disk_unambiguous_required': 'Sistem bölümünün bağlı olduğu tek fiziksel disk doğrulanamadı.',
    'root_filesystem_uuid_required': 'Sistem dosya sisteminin UUID kimliği okunamadı.',
    'bind_ip_ambiguous': 'Birden fazla uygun IPv4 adresi var. --bind-ip ile bu makinedeki adresi seçin.',
    'bind_ip_unavailable': 'Kullanılabilir IPv4 adresi bulunamadı.',
    'bind_ip_not_uniquely_local': '--bind-ip adresi makinede tekil olarak bulunamadı.',
    'tcp_port_443_in_use': 'HTTPS için gereken TCP 443 başka bir servis tarafından kullanılıyor.',
    'tcp_port_5514_in_use': 'Log alımı için gereken TCP 5514 başka bir servis tarafından kullanılıyor.',
}


PREFLIGHT_CODES = frozenset(PREFLIGHT_HELP) | frozenset({
    'root_required', 'machine_identity_required', 'ubuntu_24_04_required', 'amd64_required',
    'bind_ip_invalid', 'hostname_invalid', 'management_network_invalid',
    'stock_ubuntu_package_profile_unverified', 'native_archive_helper_not_packaged',
    'checked_write_collector_artifact_missing', 'release_artifacts_not_ready',
    'installation_not_ready', 'os_release_unavailable', 'ram_unavailable',
    'free_space_unavailable', 'network_inventory_unavailable',
    'root_block_identity_unavailable', 'disk_inventory_unavailable',
    'existing_installation_probe_unavailable', 'port_inventory_unavailable',
    'machine_identity_unavailable', 'preflight_diagnostic_unavailable',
})


def diagnostic_codes(values):
    if not isinstance(values, list):
        return ['preflight_diagnostic_unavailable']
    return list(dict.fromkeys(value if isinstance(value, str) and value in PREFLIGHT_CODES
                             else 'preflight_diagnostic_unavailable' for value in values[:64]))


def admission_failure(result):
    blockers = diagnostic_codes(result.get('blockers', []))
    if not blockers:
        blockers = ['installation_not_ready']
    return {'error_code': 'installation_plan_blocked', 'phase': 'admission',
            'installation_started': False, 'target_modified': False,
            'host_requirements_met': result.get('host_requirements_met') is True,
            'blockers': blockers, 'host_blockers': diagnostic_codes(result.get('host_blockers', [])),
            'probe_errors': diagnostic_codes(result.get('probe_errors', [])),
            'diagnostics': [{'code': code, 'message': PREFLIGHT_HELP.get(code, 'Ön kontrol koşulu karşılanmadı. İlgili hata kodunu inceleyin.')} for code in blockers],
            'retry': 'fix_preflight_and_retry', 'credentials_printed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true', help='Read-only plan (default).')
    modes.add_argument('--check', action='store_true', help='Read-only check; exit 2 when blocked.')
    modes.add_argument('--apply', action='store_true', help='Install once on an actual fresh host.')
    parser.add_argument('--inventory', type=Path, help='Synthetic fixture for read-only plans only.')
    parser.add_argument('--bind-ip', help='One IPv4 address already assigned to this host.')
    parser.add_argument('--hostname', help='HTTPS hostname; host networking and DNS are never changed.')
    parser.add_argument('--management-network', help='Management IPv4 CIDR containing the bind address.')
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if options.apply and options.inventory is not None:
        print(json.dumps({'error_code': 'fixture_apply_forbidden', 'files_written': False}))
        return 2
    root = Path(__file__).resolve().parents[1]
    try:
        manifest = validate_components(read_json(root / 'deploy/installer-components.json'))
        inventory = read_json(options.inventory) if options.inventory is not None else collect_inventory()
        artifacts = inspect_components(manifest, root)
        result = assess(inventory, manifest, artifacts,
                        origin='supplied_fixture' if options.inventory is not None else 'host',
                        bind_ip=options.bind_ip, hostname=options.hostname,
                        management_network=options.management_network)
        if result.get('blockers'):
            result['diagnostics'] = admission_failure(result)['diagnostics']
        if options.apply and (result.get('blockers') or result.get('ready_for_apply') is not True):
            print(json.dumps(admission_failure(result), indent=2, ensure_ascii=False, sort_keys=True))
            return 2
        if options.apply:
            from community_install import InstallError, apply
            try:
                result = apply(root, result)
            except InstallError as error:
                print(json.dumps({'error_code': error.code, 'phase': error.phase,
                                  'retry': 'restore_clean_snapshot_after_a_started_installation',
                                  'credentials_printed': False}))
                return 2
    except (PlanError, OSError, ValueError, TypeError, KeyError):
        print(json.dumps({'error_code': 'installation_input_invalid', 'read_only': not options.apply,
                          'credentials_printed': False}))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    return 2 if options.check and result.get('blockers') else 0


if __name__ == '__main__':
    raise SystemExit(main())
