#!/usr/bin/python3
"""Root-owned license state publisher; all cryptographic decisions are native.

There is deliberately no activation endpoint in this release. A future approved
client must obtain an issuer-signed lease using `challenge`; ping success and
failed requests are not licensing events. No issuer private key is generated.
"""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

CORE = Path('/usr/lib/fls/fls-license-core')
INSTANCE = Path('/etc/fls/instance.json')
POLICY = Path('/etc/fls/license-policy.json')
INPUTS = Path('/etc/fls/license')
STATE_DIR = Path('/var/lib/fls-license')
MAX_DOCUMENT = 32768


class AgentError(ValueError):
    pass


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise AgentError('duplicate_json_key')
            result[key] = value
        return result
    def noninteger(value):
        raise AgentError('number_type')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_float=noninteger, parse_constant=noninteger)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AgentError('invalid_json') from exc


def directory(path, *, private=False):
    path = Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AgentError('directory_permissions')
    if private and path.stat().st_mode & 0o077:
        raise AgentError('directory_permissions')


def root_read(path, limit=MAX_DOCUMENT, *, missing=False, private=False):
    path = Path(path)
    directory(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        if missing:
            return None
        raise AgentError('input_missing') from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)
                or not 0 < info.st_size <= limit):
            raise AgentError('input_permissions')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise AgentError('document_size')
        return result
    finally:
        os.close(descriptor)


def atomic_json(path, value, mode):
    path = Path(path)
    directory(path.parent)
    # Replacing a previous symlink would not follow it, but refuse unexpected
    # existing files/links as an installation integrity error anyway.
    if path.exists() or path.is_symlink():
        root_read(path, 262144, private=mode == 0o600)
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False) + '\n').encode('utf-8')
    if len(raw) > 262144:
        raise AgentError('state_size')
    fd, temporary = tempfile.mkstemp(prefix='.license-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def identity(raw):
    obj = strict_json(raw)
    identifier = obj.get('installation_id') if isinstance(obj, dict) else None
    try:
        parsed = uuid.UUID(identifier)
    except (ValueError, TypeError, AttributeError):
        raise AgentError('instance_invalid') from None
    if type(obj.get('schema')) is not int or obj['schema'] != 1 or str(parsed) != identifier or parsed.version != 4:
        raise AgentError('instance_invalid')
    return identifier


def policy(raw):
    obj = strict_json(raw)
    if not isinstance(obj, dict) or set(obj) != {'schema', 'mode'} or type(obj['schema']) is not int or obj['schema'] != 1 or obj['mode'] not in ('development', 'commercial'):
        raise AgentError('policy_invalid')
    return obj


def state_document(raw, installation_id):
    if raw is None:
        return {}
    obj = strict_json(raw)
    allowed = {'schema', 'installation_id', 'wall_high_water', 'wall_seen', 'boottime',
               'boot_id', 'license_id', 'license_revision', 'license_issued_at',
               'lease_sequence', 'lease_digest', 'lease_issued_at', 'accepted_lease', 'pending_nonce'}
    if (not isinstance(obj, dict) or set(obj) - allowed or type(obj.get('schema')) is not int or obj.get('schema') != 1
            or obj.get('installation_id') != installation_id):
        raise AgentError('state_invalid')
    for key in ('wall_high_water', 'wall_seen', 'boottime', 'license_revision',
                'license_issued_at', 'lease_sequence', 'lease_issued_at'):
        if key in obj and (type(obj[key]) is not int or not 0 <= obj[key] <= 2**53-1):
            raise AgentError('state_invalid')
    for key, pattern in (('boot_id', r'[a-f0-9-]{36}'), ('license_id', r'[a-f0-9-]{36}'),
                         ('lease_digest', r'[a-f0-9]{64}'), ('pending_nonce', r'[A-Za-z0-9_-]{43}')):
        if key in obj and (not isinstance(obj[key], str) or not re.fullmatch(pattern, obj[key])):
            raise AgentError('state_invalid')
    return obj


def issuer_keys(root):
    directory(root)
    result = {}
    for entry in sorted(root.iterdir()):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.pub', entry.name):
            raise AgentError('issuer_filename')
        raw = root_read(entry, 32)
        if len(raw) != 32 or len(result) >= 16:
            raise AgentError('issuer_key')
        result[entry.stem] = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    return result


def native(command, request, executable=CORE):
    # The only executable is provisioned by root at a fixed path. No shell,
    # URL, feature name, path or command from a web form reaches subprocess.
    root_read(executable, 16 * 1024 * 1024)
    result = subprocess.run([str(executable), command], input=json.dumps(request, separators=(',', ':')).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    if len(result.stdout) > 262144:
        raise AgentError('native_response')
    response = strict_json(result.stdout)
    if result.returncode or not isinstance(response, dict) or 'error' in response:
        raise AgentError(response.get('error', 'native_failed') if isinstance(response, dict) else 'native_failed')
    return response


def run(command):
    if os.geteuid() != 0:
        raise AgentError('root_required')
    directory(STATE_DIR)
    lock_path = STATE_DIR / '.lock'
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock_fd)
        if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AgentError('lock_permissions')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        installation_id = identity(root_read(INSTANCE))
        mode = policy(root_read(POLICY))['mode']
        state = state_document(root_read(STATE_DIR / 'state.json', 131072, missing=True, private=True), installation_id)
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        request = {'mode': mode, 'installation_id': installation_id, 'now': int(time.time()),
                   'boottime': int(time.clock_gettime(time.CLOCK_BOOTTIME)), 'boot_id': boot_id,
                   'state': state, 'issuer_keys': issuer_keys(INPUTS / 'issuers'),
                   'license': (root_read(INPUTS / 'license.json', missing=True) or b'').decode('utf-8'),
                   'lease': (root_read(INPUTS / 'lease.json', missing=True) or b'').decode('utf-8')}
        response = native('prepare' if command == 'challenge' else 'evaluate', request)
        new_state = response.get('state')
        if not isinstance(new_state, dict):
            raise AgentError('native_response')
        if command == 'challenge':
            # prepare changes only the nonce; never grant time or entitlements.
            new_state.setdefault('schema', 1)
            new_state.setdefault('installation_id', installation_id)
            atomic_json(STATE_DIR / 'state.json', new_state, 0o600)
            print(json.dumps(response['challenge'], separators=(',', ':')))
        else:
            status = response.get('status')
            if not isinstance(status, dict) or status.get('installation_id') != installation_id:
                raise AgentError('native_response')
            atomic_json(STATE_DIR / 'state.json', new_state, 0o600)
            atomic_json(STATE_DIR / 'status.json', status, 0o644)
            print(json.dumps({'status': status['status'], 'mode': status['mode'],
                              'advanced_allowed': status['advanced_allowed']}, separators=(',', ':')))
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('refresh', 'challenge'))
    args = parser.parse_args()
    try:
        run(args.command)
    except BlockingIOError:
        print('{"error":"already_running"}')
        return 0
    except (AgentError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        code = str(exc) if isinstance(exc, AgentError) else 'license_state_unavailable'
        print(json.dumps({'error': code}, separators=(',', ':')))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
