#!/usr/bin/python3
"""Prepare RC6 recovery downloads on its source VM; never install host packages.

The default is a read-only plan. --prepare downloads authenticated packages,
checks their offline dependency closure and publishes the panel's runtime.
Installed application files, services and databases are never changed.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import traceback
import types

sys.dont_write_bytecode = True
APP = Path('/var/www/fls')
STATE = Path('/etc/fls/release-state.json')
DESTINATION = Path('/var/lib/fls-recovery-download/recovery-runtime')
VERSION = '0.76.0'
RELEASE_SHA256 = 'cceede063de131053e064b4ebe2315f7b2c516212b492659715a239c626a11ed'
HELPERS = {
    'recovery-drill-prepare.py': '8b0b3429d2ff020a55af56aee081e27916b6b71487b7a10d1e80829dd3670828',
    'prepare-recovery-runtime.py': '6ec81662a267e8a7dc9af7315d8b64151d79308aaf7c3a36d550ffb74c8afc99',
}
ROOTS = ('mariadb-server', 'nginx', 'php8.3-cli', 'php8.3-fpm', 'php8.3-mysql',
         'php8.3-mbstring', 'php8.3-curl', 'php8.3-xml', 'python3-pymysql',
         'python3-cryptography', 'python3-psutil', 'rsyslog', 'acl', 'curl', 'ca-certificates')
OWNER = 0


class PreparationError(ValueError):
    def __init__(self, code, stage=None):
        self.code, self.stage = code, stage
        super().__init__(code)


def require(value, code):
    if not value:
        raise PreparationError(code)


def trusted_directory(path):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, 'trusted_path_redirected')
    for entry in (path, *path.parents):
        info = entry.lstat()
        sticky_tmp = entry == Path('/tmp') and info.st_mode & stat.S_ISVTX
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER
                and (not info.st_mode & 0o022 or sticky_tmp), 'trusted_directory_unsafe')
    return path


def trusted_read(path, maximum=4 * 1024 ** 2):
    path = Path(path).absolute()
    trusted_directory(path.parent)
    require(path.resolve(strict=True) == path, 'trusted_path_redirected')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == OWNER
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and 0 < before.st_size <= maximum, 'trusted_file_unsafe')
        data = stream.read(maximum + 1)
        after, current = os.fstat(stream.fileno()), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        require(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key)
                == getattr(current, key) for key in fields), 'trusted_file_changed')
        return data


def source_modules(app=APP, state=STATE, os_release=Path('/usr/lib/os-release')):
    require(os.geteuid() == 0, 'root_required')
    release = dict(line.split('=', 1) for line in trusted_read(os_release).decode().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu'
            and release.get('VERSION_ID', '').strip('"') == '24.04'
            and os.uname().machine == 'x86_64', 'ubuntu_24_04_amd64_required')
    receipt = json.loads(trusted_read(state))
    require(isinstance(receipt, dict) and receipt.get('schema') == 1
            and receipt.get('edition') == 'community' and receipt.get('version') == VERSION
            and receipt.get('schema_version') == 47
            and receipt.get('release_sha256') == RELEASE_SHA256, 'installed_community_rc6_required')
    require(trusted_read(app / 'VERSION').decode().strip() == VERSION, 'source_version_mismatch')
    inventory_bytes = trusted_read(app / 'deploy/release-files.json', 16 * 1024 ** 2)
    require(hashlib.sha256(inventory_bytes).hexdigest() == RELEASE_SHA256, 'release_inventory_changed')
    inventory = json.loads(inventory_bytes)
    require(isinstance(inventory, dict) and inventory.get('schema') == 'fls-community-release-files-v1'
            and inventory.get('version') == VERSION and isinstance(inventory.get('files'), list), 'release_inventory_invalid')
    rows = {row['path']: row for row in inventory['files'] if isinstance(row, dict) and isinstance(row.get('path'), str)}
    modules = []
    for name, expected in HELPERS.items():
        path = app / 'bin' / name
        data = trusted_read(path)
        require(hashlib.sha256(data).hexdigest() == expected
                and rows.get('bin/' + name, {}).get('sha256') == expected, 'installed_helper_changed')
        module = types.ModuleType('fls_recovery_packages_' + str(len(modules)))
        module.__file__ = str(path)
        exec(compile(data, str(path), 'exec'), module.__dict__)
        modules.append(module)
    download, runtime = modules
    require(tuple(download.GUEST_PACKAGES) == ROOTS and set(runtime.REQUIRED) == set(ROOTS)
            and runtime.DESTINATION == DESTINATION, 'community_runtime_contract_mismatch')
    trusted_directory(DESTINATION.parent)
    if DESTINATION.exists() or DESTINATION.is_symlink():
        trusted_directory(DESTINATION)
    return download, runtime


def write_private(path, text):
    with Path(path).open('x', encoding='utf-8') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(text)


def apt_config(base, *, offline):
    folder = base / ('offline-apt' if offline else 'download-apt')
    folder.mkdir(mode=0o700)
    for name in ('lists/partial', 'archives/partial', 'log'):
        (folder / name).mkdir(mode=0o700, parents=True)
    settings = {'Dir::Etc::main': '-', 'Dir::Etc::parts': '-',
                'Dir::Cache::pkgcache': str(folder / 'pkgcache.bin'),
                'Dir::Cache::srcpkgcache': str(folder / 'srcpkgcache.bin'),
                'Dir::Cache::archives': str(folder / 'archives'), 'Dir::Log': str(folder / 'log'),
                'APT::Sandbox::User': 'root', 'Acquire::Languages': 'none',
                'Acquire::Retries': '0', 'APT::Get::AllowUnauthenticated': 'false',
                'Acquire::AllowInsecureRepositories': 'false',
                'Acquire::AllowDowngradeToInsecureRepositories': 'false'}
    if offline:
        write_private(folder / 'status', '')
        write_private(folder / 'offline.list', 'deb [trusted=yes] file:' + str(base / 'guest-debs') + ' ./\n')
        settings.update({'Dir::Etc::sourcelist': str(folder / 'offline.list'), 'Dir::Etc::sourceparts': '-',
                         'Dir::State::status': str(folder / 'status'), 'Dir::State::lists': str(folder / 'lists'),
                         'Dir::State::extended_states': str(folder / 'extended_states')})
    config = folder / 'apt.conf'
    write_private(config, ''.join(key + ' ' + json.dumps(value) + ';\n' for key, value in settings.items()))
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
            'DEBIAN_FRONTEND': 'noninteractive', 'APT_CONFIG': str(config)}


def offline_validate(base, roots, log, runner=subprocess.run):
    environment = apt_config(base, offline=True)
    for command in (['/usr/bin/apt-get', 'update'],
                    ['/usr/bin/apt-get', '--simulate', '--no-remove', '--no-install-recommends', 'install', *roots]):
        result = runner(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL, timeout=300, check=False)
        require(result.returncode == 0, 'offline_dependencies_incomplete')


def prepare(modules=None, runner=subprocess.run, temporary=tempfile.mkdtemp):
    download, runtime = source_modules() if modules is None else modules
    previous_umask = os.umask(0o077)
    stage = None
    try:
        stage = Path(temporary(prefix='fls-recovery-packages-', dir='/tmp'))
        stage.chmod(0o700)
        log_path = stage / 'private.log'
        with log_path.open('x') as log:
            os.fchmod(log.fileno(), 0o600)
            try:
                online_environment = apt_config(stage, offline=False)
                def download_run(command, **options):
                    require(command[:2] in (['apt-cache', 'depends'], ['apt-get', 'download']), 'unexpected_download_command')
                    return runner(['/usr/bin/' + command[0], *command[1:]],
                                  **{**options, 'env': online_environment, 'timeout': 1200})
                # A module-local adapter leaves global subprocess and installed files untouched.
                download.subprocess = types.SimpleNamespace(run=download_run)
                with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                    download.download_packages(stage, 'guest-debs', [*ROOTS, 'age'])
                    folder = stage / 'guest-debs'
                    def metadata_read(command, **options):
                        require(len(command) == 3 and command[:2] == ['dpkg-deb', '--field']
                                and Path(command[2]).parent == folder
                                and re.fullmatch(r'[A-Za-z0-9+_.:%~\-]+\.deb', Path(command[2]).name),
                                'unexpected_metadata_command')
                        result = runner(['/usr/bin/dpkg-deb', '--field', command[2]],
                                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'},
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log,
                                        text=True, timeout=60, check=False)
                        require(result.returncode == 0, 'package_metadata_failed')
                        return result.stdout
                    runtime.subprocess = types.SimpleNamespace(check_output=metadata_read)
                    rows, index = runtime.package_inventory(folder)
                    require(1 <= len(rows) <= 512, 'runtime_package_count')
                    write_private(folder / 'Packages', index.decode('utf-8'))
                    ages = [row for row in rows if row.get('package') == 'age']
                    require(len(ages) == 1 and re.fullmatch(r'[A-Za-z0-9+_.:%~\-]+\.deb', ages[0].get('filename', '')), 'age_package_missing')
                    age_directory = stage / 'age-extracted'
                    age_directory.mkdir(mode=0o700)
                    result = runner(['/usr/bin/dpkg-deb', '--extract', str(folder / ages[0]['filename']), str(age_directory)],
                                    stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}, timeout=120, check=False)
                    require(result.returncode == 0, 'age_extraction_failed')
                    age = age_directory / 'usr/bin/age'
                    trusted_read(age, 32 * 1024 ** 2)
                    offline_validate(stage, ROOTS, log, runner)
                    result = runtime.publish(folder, age, DESTINATION)
                    require(result.get('schema') == 'fls-recovery-runtime-v1', 'runtime_publication_invalid')
                return {'ok': True, 'mode': 'prepared', 'package_count': result['package_count'],
                        'runtime_bytes': result['bytes'], 'runtime_sha256': result['sha256'],
                        'private_log': str(log_path), 'host_packages_installed': False,
                        'application_files_changed': False, 'services_changed': False}
            except Exception as error:
                traceback.print_exc(file=log)
                code = error.code if isinstance(error, PreparationError) else 'recovery_package_preparation_failed'
                raise PreparationError(code, stage) from None
    finally:
        os.umask(previous_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--plan', action='store_true')
    actions.add_argument('--prepare', action='store_true')
    options = parser.parse_args(argv)
    try:
        if options.prepare:
            result = prepare()
        else:
            source_modules()
            result = {'mode': 'read-only-plan', 'source_release': 'v0.76.0-rc.6',
                      'required_packages': [*ROOTS, 'age'], 'destination': str(DESTINATION),
                      'host_packages_installed': False, 'application_files_changed': False, 'services_changed': False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        result = {'ok': False, 'error_code': error.code if isinstance(error, PreparationError) else 'source_inspection_failed'}
        if isinstance(error, PreparationError) and error.stage is not None:
            result['private_log'] = str(error.stage / 'private.log')
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
