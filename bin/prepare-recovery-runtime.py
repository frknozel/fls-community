#!/usr/bin/python3
"""Publish a read-only, offline recovery runtime; never install host packages."""
import argparse
import datetime as dt
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile

DESTINATION = Path('/var/lib/fls-recovery-download/recovery-runtime')
NAME = re.compile(r'[A-Za-z0-9+_.:%~\-]+\.deb\Z')
REQUIRED = {'mariadb-server', 'nginx', 'php8.3-cli', 'php8.3-fpm', 'php8.3-mysql',
            'php8.3-mbstring', 'php8.3-curl', 'php8.3-xml', 'python3-pymysql',
            'python3-cryptography', 'python3-psutil', 'rsyslog', 'acl', 'curl',
            'ca-certificates'}


def checked(path):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError('runtime_input_symlink')
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022 or details.st_nlink < 1:
        raise ValueError('runtime_input_permissions')
    for parent in path.parents:
        current = parent.stat()
        if current.st_uid != 0 or (current.st_mode & 0o022 and not current.st_mode & stat.S_ISVTX):
            raise ValueError('runtime_input_parent_permissions')
    return path


def fingerprint(details):
    return (details.st_dev, details.st_ino, details.st_size,
            details.st_mtime_ns, details.st_ctime_ns)


def add_bytes(archive, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def add_file(archive, name, path, expected_sha, mode=0o644):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
        if digest != expected_sha:
            raise ValueError('runtime_input_changed')
        source.seek(0)
        info = tarfile.TarInfo(name)
        info.size = before.st_size
        info.mode = mode
        info.mtime = 0
        archive.addfile(info, source)
        if fingerprint(before) != fingerprint(os.fstat(source.fileno())):
            raise ValueError('runtime_input_changed')


def package_inventory(folder):
    folder = Path(folder).absolute()
    if folder.resolve(strict=True) != folder or not folder.is_dir():
        raise ValueError('runtime_package_directory')
    packages = sorted(folder.glob('*.deb'))
    if not 1 <= len(packages) <= 512:
        raise ValueError('runtime_package_count')
    rows = []
    index = []
    for candidate in packages:
        if not NAME.fullmatch(candidate.name):
            raise ValueError('runtime_package_filename')
        path = checked(candidate)
        control = subprocess.check_output(['dpkg-deb', '--field', str(path)], text=True)
        fields = dict(line.split(': ', 1) for line in control.splitlines()
                      if line and not line[0].isspace() and ': ' in line)
        if fields.get('Architecture') not in ('amd64', 'all'):
            raise ValueError('runtime_package_architecture')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        rows.append({'filename': path.name, 'package': fields['Package'],
                     'version': fields['Version'], 'architecture': fields['Architecture'],
                     'bytes': path.stat().st_size, 'sha256': digest})
        index.append(control.rstrip() + '\nFilename: ./' + path.name + '\nSize: '
                     + str(path.stat().st_size) + '\nSHA256: ' + digest + '\n\n')
    if not REQUIRED.issubset({row['package'] for row in rows}):
        raise ValueError('runtime_required_packages_missing')
    return rows, ''.join(index).encode()


def build(packages, age, output):
    rows, index = package_inventory(packages)
    age = checked(age)
    with age.open('rb') as stream:
        age_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    manifest = {'schema': 'fls-recovery-runtime-contents-v1', 'ubuntu': '24.04',
                'architecture': 'amd64', 'packages': rows,
                'age': {'bytes': age.stat().st_size, 'sha256': age_sha},
                'packages_index_sha256': hashlib.sha256(index).hexdigest()}
    with tarfile.open(output, 'w:gz', compresslevel=1) as archive:
        add_bytes(archive, 'runtime/manifest.json', json.dumps(manifest, sort_keys=True).encode())
        add_bytes(archive, 'runtime/guest-debs/Packages', index)
        add_file(archive, 'runtime/tools/age', age, age_sha, 0o755)
        for row in rows:
            add_file(archive, 'runtime/guest-debs/' + row['filename'],
                     Path(packages) / row['filename'], row['sha256'])
    with Path(output).open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'schema': 'fls-recovery-runtime-v1', 'filename': 'runtime.tar.gz',
            'bytes': Path(output).stat().st_size, 'sha256': digest,
            'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'package_count': len(rows), 'ubuntu': '24.04', 'architecture': 'amd64'}


def directory(path, gid):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750:
            raise ValueError('runtime_publication_directory')
    else:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise ValueError('runtime_publication_parent')
        path.mkdir(mode=0o750)
        os.chown(path, 0, gid)
        path.chmod(0o750)


def publish(packages, age, destination):
    if os.geteuid() != 0:
        raise ValueError('root_required')
    gid = grp.getgrnam('fls-web').gr_gid
    directory(destination, gid)
    # A private build precedes publication. Existing downloaded kits retain
    # their descriptor/expected hash; a later generation cannot change them.
    with tempfile.TemporaryDirectory(prefix='.runtime-build-', dir=destination) as temporary:
        temporary = Path(temporary)
        archive = temporary / 'runtime.tar.gz'
        metadata = build(packages, age, archive)
        description = temporary / 'runtime.json'
        description.write_text(json.dumps(metadata, indent=2) + '\n')
        for path in (archive, description):
            os.chown(path, 0, gid)
            path.chmod(0o640)
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
        os.replace(archive, Path(destination) / archive.name)
        os.replace(description, Path(destination) / description.name)
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--packages', type=Path)
    parser.add_argument('--age', type=Path, default=Path('/usr/bin/age'))
    parser.add_argument('--destination', type=Path, default=DESTINATION)
    args = parser.parse_args()
    if not args.publish:
        print(json.dumps({'mode': 'read-only-plan', 'host_packages_installed': False,
                          'destination': str(args.destination), 'required_packages': sorted(REQUIRED)}))
        return 0
    if args.packages is None:
        parser.error('--publish requires --packages containing trusted downloaded .deb files')
    os.umask(0o077)
    print(json.dumps(publish(args.packages, args.age, args.destination)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
