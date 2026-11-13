#!/usr/bin/python3
"""Prepare an age recovery identity; activate only after explicit human custody."""
import argparse
import grp
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fls_backup_encryption import CONFIG, PRIVATE, EXPORT, EncryptionError, KeyManager, load_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('status', 'prepare', 'confirm'), default='status')
    parser.add_argument('--rotate', action='store_true')
    parser.add_argument('--key-id')
    parser.add_argument('--downloaded', action='store_true')
    parser.add_argument('--confirm-custody', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise EncryptionError('root_required')
    os.umask(0o077)
    manager = KeyManager(gid=grp.getgrnam('fls-web').gr_gid)
    if args.action == 'prepare':
        value = manager.prepare(rotate=args.rotate)
        print(json.dumps({'status': 'pending_custody', **value, 'private_identity_printed': False}))
    elif args.action == 'confirm':
        value = manager.confirm(args.key_id, downloaded=args.downloaded, custody_confirmed=args.confirm_custody)
        print(json.dumps({'status': 'active', **value, 'private_identity_retained': False}))
    else:
        value = load_config()
        pending = manager.pending() if PRIVATE.exists() else None
        print(json.dumps({'status': 'active' if value else 'pending_custody' if pending else 'disabled',
                          'active': value, 'pending': pending, 'private_identity_printed': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except EncryptionError as error:
        print(json.dumps({'error_code': error.code}))
        raise SystemExit(1)
    except Exception:
        print(json.dumps({'error_code': 'encryption_setup_failed'}))
        raise SystemExit(1)
