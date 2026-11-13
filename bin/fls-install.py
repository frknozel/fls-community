#!/usr/bin/env python3
"""Install an authenticated FLS Community release on a fresh Ubuntu 24.04 host."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
from pathlib import Path
from install_plan import (PlanError, assess, collect_inventory, inspect_components,
                          read_json, validate_components)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
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
