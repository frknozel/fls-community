#!/usr/bin/python3
"""Signed, bounded application releases. Verification never extracts or installs files."""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b'FLS-RELEASE-V1\0'
MAX_COMPRESSED = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_FILES = 4096
MAX_MANIFEST = 4 * 1024 * 1024
ROOT_DIRS = frozenset({'app', 'bin', 'deploy', 'public', 'migrations'})
ROOT_FILES = frozenset({'schema.sql', 'VERSION'})
PUBLIC_CERTIFICATES = frozenset({'deploy/tsa/kamusm-roots.pem', 'deploy/tsa/turktrust-roots.pem'})
FIELDS = frozenset({'schema', 'product', 'version', 'channel', 'source_commit', 'source_tree',
                    'created_at', 'signing_key_id', 'compatibility', 'files'})
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?\Z')


class ReleaseError(ValueError):
    """Invalid release or unsafe local input; messages contain no source/secret content."""


def parse_version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) and len(value) <= 32 else None
    if not match:
        raise ReleaseError('release_version')
    return tuple(int(part or 0) for part in match.groups())


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _path(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 248
            or not re.fullmatch(r'[A-Za-z0-9._@+/-]+', value)
            or any(part in ('', '.', '..') or part.startswith('.') for part in value.split('/'))):
        raise ReleaseError('release_path')
    return value


def _payload_path(value):
    _path(value)
    if len(value) > 240:
        raise ReleaseError('release_path')
    parts = value.split('/')
    if not (value in ROOT_FILES or len(parts) > 1 and parts[0] in ROOT_DIRS):
        raise ReleaseError('release_payload_scope')
    lower = value.lower()
    basename = parts[-1].lower()
    if (value not in PUBLIC_CERTIFICATES
            and (basename.endswith(('.pem', '.crt', '.key', '.p12', '.pfx', '.jks', '.keystore', '.env'))
                 or basename in {'config.json', 'credentials.json', 'hosts.yml', 'id_rsa', 'id_ed25519'}
                 or (not basename.endswith(('.py', '.php', '.js', '.css', '.sh', '.java'))
                     and re.search(r'(?:^|[-_.])(private|secret|secrets|credential|credentials|password|token)(?:[-_.]|$)', basename)))):
        raise ReleaseError('release_sensitive_file')
    if any(part.lower() in {'__pycache__', 'node_modules', 'vendor', 'logs', 'backups', 'runtime', 'private', 'secrets'} for part in parts):
        raise ReleaseError('release_payload_scope')
    if lower.endswith(('.pyc', '.pyo', '.sqlite', '.sqlite3', '.db', '.sql.gz', '.tar.gz', '.log')):
        raise ReleaseError('release_sensitive_file')
    return value


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ReleaseError('release_created_at')
    try:
        return dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise ReleaseError('release_created_at') from None


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != FIELDS:
        raise ReleaseError('release_manifest_fields')
    if type(manifest['schema']) is not int or manifest['schema'] != 1 or manifest['product'] != 'fls':
        raise ReleaseError('release_manifest_schema')
    parse_version(manifest['version'])
    if manifest['channel'] not in ('development', 'stable'):
        raise ReleaseError('release_channel')
    for key in ('source_commit', 'source_tree'):
        if not isinstance(manifest[key], str) or not HEX40.fullmatch(manifest[key]):
            raise ReleaseError('release_source_revision')
    if not 0 <= int(_timestamp(manifest['created_at']).timestamp()) <= 0xffffffff:
        raise ReleaseError('release_created_at')
    if not isinstance(manifest['signing_key_id'], str) or not HEX64.fullmatch(manifest['signing_key_id']):
        raise ReleaseError('release_signing_key_id')
    compat = manifest['compatibility']
    if not isinstance(compat, dict) or set(compat) != {'from_versions', 'schema_before', 'schema_after'}:
        raise ReleaseError('release_compatibility')
    versions = compat['from_versions']
    if not isinstance(versions, list) or not 1 <= len(versions) <= 64:
        raise ReleaseError('release_compatibility_versions')
    parsed = [parse_version(version) for version in versions]
    if len(set(parsed)) != len(parsed) or any(version >= parse_version(manifest['version']) for version in parsed):
        raise ReleaseError('release_compatibility_versions')
    if (any(type(compat[key]) is not int or not 0 <= compat[key] <= 100000 for key in ('schema_before', 'schema_after'))
            or compat['schema_after'] < compat['schema_before']):
        raise ReleaseError('release_schema_version')
    files = manifest['files']
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ReleaseError('release_file_count')
    paths, total = [], 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {'path', 'bytes', 'sha256', 'mode'}:
            raise ReleaseError('release_file_fields')
        paths.append(_payload_path(entry['path']))
        if type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= MAX_FILE:
            raise ReleaseError('release_file_size')
        if not isinstance(entry['sha256'], str) or not HEX64.fullmatch(entry['sha256']):
            raise ReleaseError('release_file_hash')
        if type(entry['mode']) is not int or entry['mode'] not in (644, 755):
            raise ReleaseError('release_file_mode')
        total += entry['bytes']
    if paths != sorted(set(paths)) or not ROOT_FILES.issubset(paths):
        raise ReleaseError('release_file_inventory')
    inventory = set(paths)
    if any('/'.join(path.split('/')[:index]) in inventory
           for path in paths for index in range(1, len(path.split('/')))):
        raise ReleaseError('release_file_inventory')
    if total > MAX_EXPANDED:
        raise ReleaseError('release_expanded_limit')
    return manifest


def _open_regular(path, limit, private=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ReleaseError('release_input_file') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= limit:
            raise ReleaseError('release_input_file')
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ReleaseError('release_private_key_permissions')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def load_trusted_public_key(path):
    with _open_regular(path, 16384) as handle:
        try:
            key = serialization.load_pem_public_key(handle.read(16385))
        except (ValueError, TypeError):
            raise ReleaseError('release_public_key') from None
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseError('release_public_key')
    return key


def _private_key(path):
    with _open_regular(path, 16384, private=True) as handle:
        try:
            key = serialization.load_pem_private_key(handle.read(16385), password=None)
        except (ValueError, TypeError):
            raise ReleaseError('release_private_key') from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseError('release_private_key')
    return key


def _key_id(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def _source_info(path, *, directory=False):
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022):
        raise ReleaseError('release_source_permissions')
    return info


def _inventory(source):
    files, total = [], 0
    for top in sorted(ROOT_DIRS | ROOT_FILES):
        target = source / top
        if not target.exists() and not target.is_symlink():
            continue
        if target.is_symlink():
            raise ReleaseError('release_source_link')
        if top in ROOT_FILES:
            candidates = [target]
        else:
            if not target.is_dir():
                raise ReleaseError('release_source_type')
            _source_info(target, directory=True)
            candidates = []
            for parent, dirs, names in os.walk(target, followlinks=False):
                for name in dirs:
                    if (Path(parent) / name).is_symlink():
                        raise ReleaseError('release_source_link')
                    _source_info(Path(parent) / name, directory=True)
                candidates.extend(Path(parent) / name for name in names)
                if len(candidates) > MAX_FILES:
                    raise ReleaseError('release_file_count')
        for candidate in candidates:
            relative = _payload_path(candidate.relative_to(source).as_posix())
            _source_info(candidate)
            with _open_regular(candidate, MAX_FILE) as handle:
                info = os.fstat(handle.fileno())
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
                    raise ReleaseError('release_source_permissions')
                digest = hashlib.sha256()
                count = 0
                for chunk in iter(lambda: handle.read(65536), b''):
                    count += len(chunk)
                    if count > MAX_FILE:
                        raise ReleaseError('release_file_size')
                    digest.update(chunk)
            total += count
            if total > MAX_EXPANDED:
                raise ReleaseError('release_expanded_limit')
            files.append({'path': relative, 'bytes': count, 'sha256': digest.hexdigest(),
                          'mode': 755 if info.st_mode & 0o111 else 644})
            if len(files) > MAX_FILES:
                raise ReleaseError('release_file_count')
    return sorted(files, key=lambda entry: entry['path'])


class _HashReader:
    def __init__(self, handle):
        self.handle, self.digest, self.count = handle, hashlib.sha256(), 0

    def read(self, size):
        value = self.handle.read(size)
        self.digest.update(value)
        self.count += len(value)
        return value


def build_package(source_root, output_path, private_key_path, *, version, channel,
                  source_commit, source_tree, compatibility, created_at=None):
    source = Path(source_root).absolute()
    output = Path(output_path).absolute()
    if source.is_symlink() or not source.is_dir():
        raise ReleaseError('release_source_directory')
    _source_info(source, directory=True)
    source = source.resolve()
    if output.resolve().is_relative_to(source) or Path(private_key_path).resolve().is_relative_to(source):
        raise ReleaseError('release_external_paths_required')
    try:
        parent_info = output.parent.lstat()
    except OSError:
        raise ReleaseError('release_output_directory') from None
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022):
        raise ReleaseError('release_output_directory')
    if output.exists() or output.is_symlink():
        raise ReleaseError('release_output_exists')
    key = _private_key(private_key_path)
    manifest = {'schema': 1, 'product': 'fls', 'version': version, 'channel': channel,
                'source_commit': source_commit, 'source_tree': source_tree,
                'created_at': created_at or dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'signing_key_id': _key_id(key.public_key()), 'compatibility': compatibility,
                'files': _inventory(source)}
    validate_manifest(manifest)
    with _open_regular(source / 'VERSION', 64) as handle:
        if handle.read(65) != (version + '\n').encode('ascii'):
            raise ReleaseError('release_source_version')
    encoded = _canonical(manifest)
    if len(encoded) > MAX_MANIFEST:
        raise ReleaseError('release_manifest_size')
    stamp = int(_timestamp(manifest['created_at']).timestamp())
    if stamp < 0 or stamp > 0xffffffff:
        raise ReleaseError('release_created_at')
    fd, temporary = tempfile.mkstemp(prefix='.fls-release-', dir=output.parent)
    try:
        with os.fdopen(fd, 'wb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=stamp) as compressed:
                with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                    def add(name, size, mode, handle):
                        info = tarfile.TarInfo(name)
                        info.size, info.mode, info.mtime = size, int(str(mode), 8), stamp
                        archive.addfile(info, handle)
                    add('manifest.json', len(encoded), 644, io.BytesIO(encoded))
                    add('manifest.sig', 64, 644, io.BytesIO(key.sign(DOMAIN + encoded)))
                    for entry in manifest['files']:
                        with _open_regular(source / entry['path'], MAX_FILE) as handle:
                            reader = _HashReader(handle)
                            add('payload/' + entry['path'], entry['bytes'], entry['mode'], reader)
                            if (handle.read(1) or reader.count != entry['bytes']
                                    or reader.digest.hexdigest() != entry['sha256']):
                                raise ReleaseError('release_source_changed')
            raw.flush()
            os.fsync(raw.fileno())
            if raw.tell() > MAX_COMPRESSED:
                raise ReleaseError('release_compressed_limit')
        # The verifier also checks expanded tar overhead and VERSION before publication.
        _verify(temporary, key.public_key())
        os.link(temporary, output)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, tarfile.TarError, OverflowError):
        raise ReleaseError('release_build_io') from None
    finally:
        os.unlink(temporary)
    return manifest


class _GzipReader:
    """One gzip member, bounded compressed and decompressed bytes, no hidden trailer."""
    def __init__(self, handle):
        self.handle, self.decoder = handle, zlib.decompressobj(31)
        self.buffer, self.pending = bytearray(), b''
        self.expanded = self.compressed = 0
        self.finished = False

    def read(self, size):
        while len(self.buffer) < size and not self.finished:
            chunk = self.pending or self.handle.read(65536)
            if not self.pending:
                self.compressed += len(chunk)
            if self.compressed > MAX_COMPRESSED or not chunk:
                raise ReleaseError('release_gzip_truncated_or_limit')
            try:
                value = self.decoder.decompress(chunk, min(65536, MAX_EXPANDED - self.expanded + 1))
            except zlib.error:
                raise ReleaseError('release_gzip') from None
            self.pending = self.decoder.unconsumed_tail
            self.expanded += len(value)
            if self.expanded > MAX_EXPANDED:
                raise ReleaseError('release_expanded_limit')
            self.buffer.extend(value)
            if self.decoder.eof:
                if self.decoder.unused_data or self.pending or self.handle.read(1):
                    raise ReleaseError('release_gzip_trailer')
                self.finished = True
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value


def _exact(reader, size):
    value = reader.read(size)
    if len(value) != size:
        raise ReleaseError('release_tar_truncated')
    return value


def _string(value):
    first, _, rest = value.partition(b'\0')
    if rest.strip(b'\0'):
        raise ReleaseError('release_tar_header')
    try:
        return first.decode('ascii')
    except UnicodeDecodeError:
        raise ReleaseError('release_tar_header') from None


def _number(value):
    stripped = value.strip(b'\0 ')
    if not stripped or not re.fullmatch(b'[0-7]+', stripped):
        raise ReleaseError('release_tar_header')
    return int(stripped, 8)


def _header(reader):
    block = _exact(reader, 512)
    if block == bytes(512):
        return None
    if (block[257:265] != b'ustar\00000' or block[156:157] != b'0'
            or block[157:257].strip(b'\0') or block[500:].strip(b'\0')
            or _number(block[148:156]) != sum(block[:148] + b' ' * 8 + block[156:])
            or _number(block[108:116]) != 0 or _number(block[116:124]) != 0
            or block[265:329].strip(b'\0') or block[329:345].strip(b'\0')):
        raise ReleaseError('release_tar_header')
    name, prefix = _string(block[:100]), _string(block[345:500])
    name = prefix + '/' + name if prefix else name
    _path(name)
    return {'path': name, 'bytes': _number(block[124:136]), 'mode': _number(block[100:108]),
            'mtime': _number(block[136:148])}


def _body(reader, size, *, retain=False):
    digest, chunks = hashlib.sha256(), []
    remaining = size
    while remaining:
        chunk = _exact(reader, min(65536, remaining))
        remaining -= len(chunk)
        digest.update(chunk)
        if retain:
            chunks.append(chunk)
    if _exact(reader, -size % 512).strip(b'\0'):
        raise ReleaseError('release_tar_padding')
    return (b''.join(chunks) if retain else digest.hexdigest())


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError('release_json_duplicate')
        result[key] = value
    return result


def _verify(package_path, public_key):
    with _open_regular(package_path, MAX_COMPRESSED) as handle:
        reader = _GzipReader(handle)
        first = _header(reader)
        if not first or first['path'] != 'manifest.json' or first['mode'] != 0o644 or not 1 <= first['bytes'] <= MAX_MANIFEST:
            raise ReleaseError('release_manifest_member')
        encoded = _body(reader, first['bytes'], retain=True)
        try:
            manifest = json.loads(encoded, object_pairs_hook=_pairs,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError('release_json_constant')))
        except (ValueError, UnicodeError, RecursionError):
            raise ReleaseError('release_manifest_json') from None
        validate_manifest(manifest)
        if _canonical(manifest) != encoded:
            raise ReleaseError('release_json_not_canonical')
        stamp = int(_timestamp(manifest['created_at']).timestamp())
        if first['mtime'] != stamp or manifest['signing_key_id'] != _key_id(public_key):
            raise ReleaseError('release_trust')
        signature = _header(reader)
        if signature != {'path': 'manifest.sig', 'bytes': 64, 'mode': 0o644, 'mtime': stamp}:
            raise ReleaseError('release_signature_member')
        try:
            public_key.verify(_body(reader, 64, retain=True), DOMAIN + encoded)
        except InvalidSignature:
            raise ReleaseError('release_signature') from None
        for entry in manifest['files']:
            expected = {'path': 'payload/' + entry['path'], 'bytes': entry['bytes'],
                        'mode': int(str(entry['mode']), 8), 'mtime': stamp}
            if _header(reader) != expected:
                raise ReleaseError('release_payload_inventory')
            if entry['path'] == 'VERSION':
                value = _body(reader, entry['bytes'], retain=True)
                digest = hashlib.sha256(value).hexdigest()
                if value != (manifest['version'] + '\n').encode('ascii'):
                    raise ReleaseError('release_payload_version')
            else:
                digest = _body(reader, entry['bytes'])
            if digest != entry['sha256']:
                raise ReleaseError('release_payload_hash')
        if _header(reader) is not None or _exact(reader, 512) != bytes(512):
            raise ReleaseError('release_tar_end')
        padding = 0
        while True:
            tail = reader.read(65536)
            if not tail:
                break
            padding += len(tail)
            if tail.strip(b'\0') or padding >= 10240:
                raise ReleaseError('release_tar_trailer')
        if reader.expanded % 10240:
            raise ReleaseError('release_tar_record_padding')
    return manifest


def verify_package(package_path, trusted_public_key_path):
    """Verify all members using an externally supplied PEM key; make no host changes."""
    return _verify(package_path, load_trusted_public_key(trusted_public_key_path))
