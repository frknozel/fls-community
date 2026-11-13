"""Standard age X25519 backup companions and an explicit recovery-key handoff.

Private recovery identities exist only in the dedicated pending/export folders.
An active configuration contains one public recipient and custody confirmation.
No secret identity is ever supplied in argv, returned by this module or logged.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

CONFIG = Path('/etc/fls/backup-encryption.json')
PRIVATE = Path('/var/lib/fls-backup-encryption-private')
EXPORT = Path('/var/lib/fls-backup-key-download')
RECIPIENT = re.compile(r'age1[023456789acdefghjklmnpqrstuvwxyz]{58}\Z')
KEY_ID = re.compile(r'[a-f0-9]{32}\Z')
SHA256 = re.compile(r'[a-f0-9]{64}\Z')
SOURCE_NAME = re.compile(r'fls-system-\d{8}-\d{6}Z\.tar\.gz\Z')
SCHEMA = 'fls-backup-age-v1'


class EncryptionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise EncryptionError(code)


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def key_id(recipient):
    require(isinstance(recipient, str) and RECIPIENT.fullmatch(recipient), 'encryption_recipient_invalid')
    return hashlib.sha256(recipient.encode('ascii')).hexdigest()[:32]


def directory(path, *, uid=0, gid=None, mode=None, create=False):
    path = Path(path)
    if create and not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode or 0o700)
        os.chown(path, uid, os.getgid() if gid is None else gid)
        path.chmod(mode or 0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022
            and (gid is None or info.st_gid == gid)
            and (mode is None or stat.S_IMODE(info.st_mode) == mode), 'encryption_directory_invalid')
    # No writable ancestor or symlink may replace a trusted root directory.
    for parent in path.parents:
        node = parent.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid in (0, uid)
                and (not node.st_mode & 0o022 or node.st_mode & stat.S_ISVTX),
                'encryption_directory_invalid')
    return info


def read_file(path, *, uid=0, gid=None, mode=None, maximum=65536):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                and not info.st_mode & 0o022 and 0 < info.st_size <= maximum
                and (gid is None or info.st_gid == gid)
                and (mode is None or stat.S_IMODE(info.st_mode) == mode), 'encryption_file_invalid')
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        current = path.lstat()
        require(same_stat(info, after) and same_stat(info, current) and len(value) == info.st_size,
                'encryption_file_changed')
    return value


def same_stat(left, right):
    return all(getattr(left, field) == getattr(right, field) for field in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def digest_file(path, *, uid=0, gid=None, mode=0o640):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == mode and before.st_size > 0
                and (gid is None or before.st_gid == gid), 'encryption_file_invalid')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(same_stat(before, os.fstat(stream.fileno())) and same_stat(before, Path(path).lstat()),
                'encryption_file_changed')
    return {'bytes': before.st_size, 'sha256': digest}


def write_file(path, value, *, uid=0, gid=None, mode=0o600, replace=False):
    path = Path(path)
    require(not path.is_symlink(), 'encryption_file_invalid')
    descriptor, temporary = tempfile.mkstemp(prefix='.encryption-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, uid, os.getgid() if gid is None else gid)
        os.chmod(temporary, mode)
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
        sync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_config(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'key_id', 'recipient', 'activated_at', 'custody_confirmed'}
            and value['schema'] == 1 and type(value['schema']) is int
            and value['custody_confirmed'] is True and value['key_id'] == key_id(value['recipient'])
            and isinstance(value['activated_at'], str)
            and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['activated_at']),
            'encryption_config_invalid')
    return value


def load_config(path=CONFIG, *, uid=0, gid=None):
    path = Path(path)
    directory(path.parent, uid=uid)
    if not path.exists() and not path.is_symlink():
        return None
    try:
        value = json.loads(read_file(path, uid=uid, gid=gid, mode=0o640, maximum=4096))
        return validate_config(value)
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise EncryptionError('encryption_config_invalid') from error


class AgeTools:
    def __init__(self, age='/usr/bin/age', keygen='/usr/bin/age-keygen'):
        self.age, self.keygen = str(age), str(keygen)

    def run(self, arguments, *, data=None, stdout=subprocess.PIPE, timeout=120):
        try:
            result = subprocess.run(arguments, input=data, stdin=None if data is not None else subprocess.DEVNULL,
                                    stdout=stdout, stderr=subprocess.PIPE, timeout=timeout, check=False,
                                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EncryptionError('encryption_tool_unavailable') from error
        require(result.returncode == 0, 'encryption_tool_failed')
        return result.stdout

    def generate(self, identity):
        self.run([self.keygen, '-o', str(identity)])
        os.chmod(identity, 0o600)
        with open(identity, 'rb') as stream:
            os.fsync(stream.fileno())
        recipient = self.run([self.keygen, '-y', str(identity)]).decode('ascii').strip()
        key_id(recipient)
        return recipient

    def self_test(self, identity, recipient):
        payload = b'FLS age recovery key self-test v1\n' + os.urandom(32)
        cipher = self.run([self.age, '-r', recipient], data=payload)
        restored = self.run([self.age, '-d', '-i', str(identity)], data=cipher)
        require(restored == payload, 'encryption_self_test_failed')
        return hashlib.sha256(cipher).hexdigest()

    def encrypt(self, source, target, recipient):
        # The source descriptor is pinned and checked again by the caller. No
        # recovery identity or unencrypted data is included in a command line.
        self.run([self.age, '-r', recipient, '-o', str(target), str(source)], stdout=subprocess.DEVNULL, timeout=1200)


class KeyManager:
    def __init__(self, *, config=CONFIG, private=PRIVATE, export=EXPORT, uid=0, gid=0, tools=None):
        self.config, self.private, self.export = Path(config), Path(private), Path(export)
        self.uid, self.gid = uid, gid
        self.tools = tools or AgeTools()

    @contextlib.contextmanager
    def lock(self):
        directory(self.private, uid=self.uid, mode=0o700, create=True)
        fd = os.open(self.private / 'setup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'encryption_lock_invalid')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def pending(self):
        try:
            value = json.loads(read_file(self.private / 'pending.json', uid=self.uid, mode=0o600, maximum=4096))
        except FileNotFoundError:
            return None
        expected = {'schema', 'key_id', 'recipient', 'created_at', 'self_test_verified',
                    'self_test_sha256', 'download_filename'}
        if isinstance(value, dict) and value.get('custody_confirmed') is True:
            expected.update(('custody_confirmed', 'confirmed_at'))
        require(isinstance(value, dict) and set(value) == expected
                and type(value.get('schema')) is int and value.get('schema') == 1
                and value.get('key_id') == key_id(value.get('recipient'))
                and value.get('self_test_verified') is True
                and isinstance(value.get('self_test_sha256'), str) and SHA256.fullmatch(value['self_test_sha256'])
                and value.get('download_filename') == 'fls-backup-recovery-' + value['key_id'] + '.txt'
                and isinstance(value.get('created_at'), str)
                and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['created_at'])
                and ('confirmed_at' not in value or isinstance(value['confirmed_at'], str)
                     and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['confirmed_at'])),
                'encryption_pending_invalid')
        return value

    def prepare(self, *, rotate=False):
        with self.lock():
            pending = self.pending()
            if pending:
                return pending
            require(load_config(self.config, uid=self.uid) is None or rotate, 'encryption_rotation_requires_confirmation')
            directory(self.export, uid=self.uid, gid=self.gid, mode=0o750, create=True)
            identity = self.private / 'recovery.identity'
            require(not identity.exists() and not identity.is_symlink(), 'encryption_pending_conflict')
            recipient = self.tools.generate(identity)
            proof = self.tools.self_test(identity, recipient)
            value = {'schema': 1, 'key_id': key_id(recipient), 'recipient': recipient,
                     'created_at': timestamp(), 'self_test_verified': True, 'self_test_sha256': proof,
                     'download_filename': 'fls-backup-recovery-' + key_id(recipient) + '.txt'}
            private_data = read_file(identity, uid=self.uid, mode=0o600, maximum=4096)
            write_file(self.export / value['download_filename'], private_data, uid=self.uid, gid=self.gid, mode=0o640)
            write_file(self.private / 'pending.json', json_bytes(value), uid=self.uid)
            write_file(self.export / 'pending.json', json_bytes(value), uid=self.uid, gid=self.gid, mode=0o640)
            return value

    def confirm(self, expected_key_id, *, downloaded=False, custody_confirmed=False):
        require(downloaded is True and custody_confirmed is True and KEY_ID.fullmatch(expected_key_id or ''),
                'encryption_custody_confirmation_required')
        with self.lock():
            pending = self.pending()
            require(pending and pending['key_id'] == expected_key_id, 'encryption_pending_changed')
            directory(self.export, uid=self.uid, gid=self.gid, mode=0o750)
            private = self.private / 'recovery.identity'
            if pending.get('custody_confirmed') is not True:
                identity_bytes = read_file(private, uid=self.uid, mode=0o600, maximum=4096)
                require(identity_bytes == read_file(self.export / pending['download_filename'], uid=self.uid, gid=self.gid, mode=0o640, maximum=4096),
                        'encryption_recovery_export_changed')
                self.tools.self_test(private, pending['recipient'])
                pending = {**pending, 'custody_confirmed': True, 'confirmed_at': timestamp()}
                write_file(self.private / 'pending.json', json_bytes(pending), uid=self.uid, replace=True)
            value = validate_config({'schema': 1, 'key_id': pending['key_id'], 'recipient': pending['recipient'],
                                     'activated_at': pending['confirmed_at'], 'custody_confirmed': True})
            directory(self.config.parent, uid=self.uid)
            # Delete both identities before activation. A public-only durable
            # handoff record lets an explicitly repeated confirmation finish
            # after a crash, without generating or retaining another identity.
            for path in (private, self.export / pending['download_filename'], self.export / 'pending.json'):
                path.unlink(missing_ok=True)
            sync_directory(self.private)
            sync_directory(self.export)
            write_file(self.config, json_bytes(value), uid=self.uid, gid=self.gid, mode=0o640, replace=True)
            (self.private / 'pending.json').unlink()
            sync_directory(self.private)
            return value


def companion_name(filename, config):
    require(SOURCE_NAME.fullmatch(filename or ''), 'encryption_source_name_invalid')
    validate_config(config)
    return filename + '.' + config['key_id'] + '.age'


def companion_metadata(folder, filename, source, config, *, backup_id, uid=0, gid=0):
    name = companion_name(filename, config)
    path = Path(folder) / (name + '.encryption.json')
    value = json.loads(read_file(path, uid=uid, gid=gid, mode=0o640, maximum=8192))
    require(isinstance(value, dict) and value.get('schema') == SCHEMA and value.get('backup_id') == backup_id
            and value.get('filename') == name and value.get('source_filename') == filename
            and value.get('source_sha256') == source['sha256'] and value.get('source_bytes') == source['bytes']
            and value.get('key_id') == config['key_id'] and value.get('recipient') == config['recipient']
            and value.get('algorithm') == 'age-x25519' and value.get('custody_confirmed') is True,
            'encryption_metadata_invalid')
    actual = digest_file(Path(folder) / name, uid=uid, gid=gid)
    require(actual['bytes'] == value.get('bytes') and actual['sha256'] == value.get('sha256'), 'encryption_checksum_mismatch')
    checksum = Path(folder) / (name + '.sha256')
    require(read_file(checksum, uid=uid, gid=gid, mode=0o640, maximum=1024)
            == (actual['sha256'] + '  ' + name + '\n').encode(), 'encryption_checksum_mismatch')
    return {**value, 'files': [Path(folder) / name, checksum, path]}


def ensure_companion(folder, filename, source, config, *, backup_id, uid=0, gid=0, tools=None):
    folder = Path(folder)
    directory(folder, uid=uid, gid=gid, mode=0o750)
    name = companion_name(filename, config)
    tools = tools or AgeTools()
    fd = os.open(folder / '.age-companions.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'encryption_lock_invalid')
        fcntl.flock(fd, fcntl.LOCK_EX)
        if (folder / (name + '.encryption.json')).exists():
            return companion_metadata(folder, filename, source, config, backup_id=backup_id, uid=uid, gid=gid)
        require(not any((folder / suffix).exists() or (folder / suffix).is_symlink()
                        for suffix in (name, name + '.sha256', name + '.encryption.json')), 'encryption_artifact_conflict')
        original = folder / filename
        before = digest_file(original, uid=uid, gid=gid)
        require(before == {'bytes': source['bytes'], 'sha256': source['sha256']}, 'encryption_source_changed')
        with tempfile.TemporaryDirectory(prefix='.age-pending-', dir=folder) as staging:
            stage = Path(staging)
            cipher = stage / name
            tools.encrypt(original, cipher, config['recipient'])
            os.chown(cipher, uid, gid)
            cipher.chmod(0o640)
            with cipher.open('rb') as stream:
                os.fsync(stream.fileno())
            actual = digest_file(cipher, uid=uid, gid=gid)
            require(digest_file(original, uid=uid, gid=gid) == before, 'encryption_source_changed')
            value = {'schema': SCHEMA, 'algorithm': 'age-x25519', 'backup_id': backup_id,
                     'source_filename': filename, 'source_bytes': source['bytes'], 'source_sha256': source['sha256'],
                     'filename': name, **actual, 'key_id': config['key_id'], 'recipient': config['recipient'],
                     'custody_confirmed': True, 'created_at': timestamp()}
            write_file(stage / (name + '.sha256'), (actual['sha256'] + '  ' + name + '\n').encode(), uid=uid, gid=gid, mode=0o640)
            write_file(stage / (name + '.encryption.json'), json_bytes(value), uid=uid, gid=gid, mode=0o640)
            for suffix in (name, name + '.sha256', name + '.encryption.json'):
                os.link(stage / suffix, folder / suffix, follow_symlinks=False)
                (stage / suffix).unlink()
            sync_directory(folder)
        return companion_metadata(folder, filename, source, config, backup_id=backup_id, uid=uid, gid=gid)
    finally:
        os.close(fd)
