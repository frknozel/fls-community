#!/usr/bin/python3
"""Recovery preparation fixtures; no APT, downloads, installed imports or publication."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'tools/community/overlay' if (ROOT / 'tools/community/overlay').is_dir() else ROOT
SPEC = importlib.util.spec_from_file_location('fls_recovery_packages_fixture', TREE / 'tools/prepare-recovery-packages.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def fixture_ancestor_owner(base):
    """Translate only root-owned fixture ancestors for unprivileged runners.

    All real modes and the fixture subtree's own metadata remain unchanged.
    Production ownership checks are not weakened for fixture portability.
    """
    ancestors, original, owner = set(base.parents), Path.lstat, os.getuid()
    def inspect(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path in ancestors and info.st_uid == 0:
            return types.SimpleNamespace(st_mode=info.st_mode, st_uid=owner)
        return info
    return patch.object(Path, 'lstat', inspect)


class SourceFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-recovery-source-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.app = self.base / 'app'
        self.state = self.base / 'release-state.json'
        self.destination = self.base / 'published/runtime'
        self.destination.parent.mkdir(parents=True)
        self.os_release = self.base / 'usr/lib/os-release'
        self.os_release.parent.mkdir(parents=True)
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        etc = self.base / 'etc'; etc.mkdir()
        (etc / 'os-release').symlink_to('../usr/lib/os-release')
        self.helpers = {
            'recovery-drill-prepare.py': ('GUEST_PACKAGES = ' + repr(list(tool.ROOTS)) + '\n'
                'if __name__ == "__main__": raise AssertionError("main must not run")\n').encode(),
            'prepare-recovery-runtime.py': ('from pathlib import Path\nREQUIRED = ' + repr(set(tool.ROOTS)) + '\n'
                'DESTINATION = Path(' + repr(str(self.destination)) + ')\n'
                'if __name__ == "__main__": raise AssertionError("main must not run")\n').encode(),
        }
        (self.app / 'bin').mkdir(parents=True)
        (self.app / 'deploy').mkdir()
        (self.app / 'VERSION').write_text(tool.VERSION + '\n')
        self.hashes = {name: hashlib.sha256(data).hexdigest() for name, data in self.helpers.items()}
        for name, data in self.helpers.items():
            (self.app / 'bin' / name).write_bytes(data)
        self.inventory = {'schema': 'fls-community-release-files-v1', 'version': tool.VERSION,
                          'files': [{'path': 'bin/' + name, 'sha256': digest} for name, digest in self.hashes.items()]}
        self.inventory_bytes = json.dumps(self.inventory).encode()
        self.inventory_path = self.app / 'deploy/release-files.json'
        self.inventory_path.write_bytes(self.inventory_bytes)
        self.inner_hash = hashlib.sha256(self.inventory_bytes).hexdigest()
        self.receipt = {'schema': 1, 'edition': 'community', 'version': tool.VERSION,
                        'schema_version': 47, 'release_sha256': self.inner_hash}
        self.state.write_text(json.dumps(self.receipt))
        for replacement in (fixture_ancestor_owner(self.base), patch.object(tool, 'OWNER', os.getuid()), patch.object(tool, 'HELPERS', self.hashes),
                            patch.object(tool, 'RELEASE_SHA256', self.inner_hash),
                            patch.object(tool, 'DESTINATION', self.destination), patch.object(tool.os, 'geteuid', return_value=0),
                            patch.object(tool.os, 'uname', return_value=os.uname_result(('Linux', 'fixture', '6', 'fixture', 'x86_64')))):
            replacement.start(); self.addCleanup(replacement.stop)

    def probe(self):
        with patch.object(tool.subprocess, 'run', side_effect=AssertionError('host command attempted')):
            return tool.source_modules(self.app, self.state, self.os_release)

    def test_standard_os_release_symlink_is_not_followed_or_rejected(self):
        self.assertTrue((self.base / 'etc/os-release').is_symlink())
        download, runtime = self.probe()
        self.assertEqual(tuple(download.GUEST_PACKAGES), tool.ROOTS)
        self.assertEqual(runtime.REQUIRED, set(tool.ROOTS))
        self.assertFalse(list(self.app.rglob('__pycache__')))

    def test_receipt_is_bound_to_actual_inner_release_inventory(self):
        # A receipt with the outer metadata hash must fail before trusted imports.
        self.receipt['release_sha256'] = hashlib.sha256(b'{"outer_release":true}').hexdigest()
        self.state.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(tool.PreparationError, 'installed_community_rc6_required'):
            self.probe()
        self.receipt['release_sha256'] = self.inner_hash
        self.state.write_text(json.dumps(self.receipt))
        self.inventory_path.write_bytes(self.inventory_bytes + b' ')
        with self.assertRaisesRegex(tool.PreparationError, 'release_inventory_changed'):
            self.probe()

    def test_receipt_contract_is_derived_from_real_installer_inventory_reader(self):
        specification = importlib.util.spec_from_file_location('fls_recovery_installer_contract_fixture', TREE / 'bin/community_install.py')
        installer = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(installer)
        for name in ['schema.sql', 'bin/product_config.py', 'bin/fls_storage.py', *['fixture-' + str(i) for i in range(6)]]:
            (self.app / name).write_bytes(b'fixture only; never executed\n')
        rows = [{'path': path.relative_to(self.app).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in self.app.rglob('*') if path.is_file() and path != self.inventory_path]
        self.inventory_path.write_text(json.dumps({**self.inventory, 'files': rows}))
        with patch.object(installer.os, 'geteuid', return_value=os.getuid()):
            authenticated = installer.verify_release(self.app)
        self.assertEqual(authenticated['manifest_sha256'], hashlib.sha256(self.inventory_path.read_bytes()).hexdigest())
        self.receipt['release_sha256'] = authenticated['manifest_sha256']
        self.state.write_text(json.dumps(self.receipt))
        with patch.object(tool, 'RELEASE_SHA256', authenticated['manifest_sha256']):
            self.probe()

    def test_private_edition_or_wrong_version_is_rejected_before_staging(self):
        for key, value in [('edition', 'private'), ('version', '0.75.1'), ('schema_version', 46)]:
            receipt = {**self.receipt, key: value}
            self.state.write_text(json.dumps(receipt))
            with self.subTest(key=key), self.assertRaisesRegex(tool.PreparationError, 'installed_community_rc6_required'):
                self.probe()

    def test_helper_changes_symlinks_and_writable_ancestors_are_rejected(self):
        target = self.app / 'bin/recovery-drill-prepare.py'
        original = target.read_bytes()
        target.write_bytes(original + b'\n')
        with self.assertRaisesRegex(tool.PreparationError, 'installed_helper_changed'): self.probe()
        target.write_bytes(original)
        other = self.app / 'bin/redirect.py'; other.write_bytes(original)
        target.unlink(); target.symlink_to(other.name)
        with self.assertRaisesRegex(tool.PreparationError, 'trusted_path_redirected'): self.probe()
        target.unlink(); target.write_bytes(original)
        self.app.chmod(0o777)
        with self.assertRaisesRegex(tool.PreparationError, 'trusted_directory_unsafe'): self.probe()

    def test_php85_runtime_contract_is_rejected(self):
        changed = self.helpers['recovery-drill-prepare.py'].replace(b'php8.3', b'php8.5')
        path = self.app / 'bin/recovery-drill-prepare.py'; path.write_bytes(changed)
        self.hashes['recovery-drill-prepare.py'] = hashlib.sha256(changed).hexdigest()
        inventory = {**self.inventory, 'files': [{'path': 'bin/' + name, 'sha256': digest} for name, digest in self.hashes.items()]}
        data = json.dumps(inventory).encode(); self.inventory_path.write_bytes(data)
        self.receipt['release_sha256'] = hashlib.sha256(data).hexdigest()
        self.state.write_text(json.dumps(self.receipt))
        with patch.object(tool, 'RELEASE_SHA256', self.receipt['release_sha256']):
            with self.assertRaisesRegex(tool.PreparationError, 'community_runtime_contract_mismatch'): self.probe()


class PreparationFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-recovery-preparation-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.stage = self.base / 'new-stage'
        self.calls, self.publications = [], []
        self.simulation_code, self.extraction_code = 0, 0
        self.destination = self.base / 'published/runtime'
        self.download = types.SimpleNamespace()
        def download_packages(base, name, roots):
            self.download.subprocess.run(['apt-cache', 'depends', *roots], capture_output=True, text=True, check=True)
            folder = base / name; folder.mkdir(mode=0o700)
            self.download.subprocess.run(['apt-get', 'download', *roots], cwd=folder, stdout=io.BytesIO(), stderr=subprocess.STDOUT, check=True)
            (folder / 'age_1_amd64.deb').write_bytes(b'fixture package, never executed')
        self.download.download_packages = download_packages
        self.runtime = types.SimpleNamespace()
        def inventory(folder):
            self.runtime.subprocess.check_output(['dpkg-deb', '--field', str(folder / 'age_1_amd64.deb')], text=True)
            return [{'package': 'age', 'filename': 'age_1_amd64.deb'}], b'Package: age\n'
        self.runtime.package_inventory = inventory
        def publish(folder, age, destination):
            self.publications.append((folder, age, destination))
            return {'schema': 'fls-recovery-runtime-v1', 'package_count': 1, 'bytes': 123, 'sha256': 'a' * 64}
        self.runtime.publish = publish
        for replacement in (fixture_ancestor_owner(self.base), patch.object(tool, 'OWNER', os.getuid()), patch.object(tool, 'DESTINATION', self.destination)):
            replacement.start(); self.addCleanup(replacement.stop)

    def temporary_stage(self, **options):
        self.assertEqual(options['dir'], '/tmp')
        self.stage.mkdir(mode=0o700)
        return str(self.stage)

    def runner(self, command, **options):
        self.calls.append((command, options))
        code = 0
        if '--extract' in command:
            code = self.extraction_code
            if not code:
                age = Path(command[-1]) / 'usr/bin/age'
                age.parent.mkdir(parents=True)
                age.write_bytes(b'fixture age, never executed'); age.chmod(0o755)
        if '--simulate' in command: code = self.simulation_code
        return types.SimpleNamespace(returncode=code, stdout='Package: age\n')

    def prepare(self):
        return tool.prepare((self.download, self.runtime), self.runner, self.temporary_stage)

    def real_helpers(self):
        """Load the pinned RC6 functions, normalizing only the private PHP edition."""
        modules = []
        for name, digest in tool.HELPERS.items():
            data = (ROOT / 'bin' / name).read_bytes().replace(b'8.5', b'8.3')
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            module = types.ModuleType('fls_recovery_real_helper_fixture_' + str(len(modules)))
            module.__file__ = str(ROOT / 'bin' / name)
            exec(compile(data, module.__file__, 'exec'), module.__dict__)
            modules.append(module)
        download, runtime = modules
        self.assertEqual(tuple(download.GUEST_PACKAGES), tool.ROOTS)
        self.assertEqual(runtime.REQUIRED, set(tool.ROOTS))
        # Keep the runtime parser/build functions intact. Only ownership is
        # translated for unprivileged CI; the tool still checks every input.
        def checked(path):
            path = Path(path)
            self.assertTrue(path.is_relative_to(self.stage))
            tool.trusted_read(path, 32 * 1024 ** 2)
            return path
        runtime.checked = checked
        def publish(folder, age, destination):
            self.publications.append((folder, age, destination))
            return runtime.build(folder, age, self.stage / 'fixture-runtime.tar.gz')
        runtime.publish = publish
        return download, runtime

    def real_helper_runner(self, command, **options):
        """Fixture APT and dpkg metadata; never launch an operating-system tool."""
        if command[:2] == ['/usr/bin/apt-cache', 'depends']:
            self.calls.append((command, options))
            packages = [*tool.ROOTS, 'age']
            # Exercise the real dependency parser's nested/virtual filtering.
            return types.SimpleNamespace(returncode=0, stdout=''.join(
                name + '\n  Depends: fixture-virtual\n<fixture-virtual>\n' for name in packages))
        if command[:2] == ['/usr/bin/apt-get', 'download']:
            self.calls.append((command, options))
            for name in command[2:]:
                (Path(options['cwd']) / (name + '_1_amd64.deb')).write_bytes(
                    ('fixture package ' + name + '; never executed\n').encode())
            return types.SimpleNamespace(returncode=0)
        if command[:2] == ['/usr/bin/dpkg-deb', '--field']:
            self.calls.append((command, options))
            package = Path(command[2]).name.split('_', 1)[0]
            architecture = getattr(self, 'package_architecture', 'amd64')
            return types.SimpleNamespace(returncode=0, stdout=(
                'Package: ' + package + '\nVersion: 1\nArchitecture: ' + architecture + '\n'))
        return self.runner(command, **options)

    def test_pinned_rc6_downloader_and_runtime_use_only_local_command_adapters(self):
        modules = self.real_helpers()
        with patch.object(subprocess, 'run', side_effect=AssertionError('host command attempted')), \
             patch.object(subprocess, 'check_output', side_effect=AssertionError('host metadata command attempted')):
            result = tool.prepare(modules, self.real_helper_runner, self.temporary_stage)
        self.assertTrue(result['ok'])
        self.assertEqual(result['package_count'], len(tool.ROOTS) + 1)
        self.assertEqual(len(self.publications), 1)
        download = next((command, options) for command, options in self.calls if command[1] == 'download')
        self.assertEqual(set(download[0][2:]), {*tool.ROOTS, 'age'})
        self.assertEqual(download[1]['stderr'], subprocess.STDOUT)
        self.assertEqual(download[1]['env']['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
        metadata = [(command, options) for command, options in self.calls if command[1] == '--field']
        # The real publisher builds a second inventory through the same adapter.
        self.assertEqual(len(metadata), 2 * (len(tool.ROOTS) + 1))
        for command, options in metadata:
            self.assertEqual(len(command), 3)
            self.assertEqual(Path(command[2]).parent, self.stage / 'guest-debs')
            self.assertEqual(options['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
            self.assertEqual(options['stdin'], subprocess.DEVNULL)
        with tarfile.open(self.stage / 'fixture-runtime.tar.gz') as archive:
            manifest = json.load(archive.extractfile('runtime/manifest.json'))
            self.assertEqual({row['package'] for row in manifest['packages']}, {*tool.ROOTS, 'age'})
            self.assertEqual(archive.extractfile('runtime/tools/age').read(), b'fixture age, never executed')

    def test_pinned_runtime_metadata_parser_rejects_wrong_architecture_before_publication(self):
        self.package_architecture = 'arm64'
        with patch.object(subprocess, 'run', side_effect=AssertionError('host command attempted')), \
             patch.object(subprocess, 'check_output', side_effect=AssertionError('host metadata command attempted')):
            with self.assertRaisesRegex(tool.PreparationError, 'recovery_package_preparation_failed'):
                tool.prepare(self.real_helpers(), self.real_helper_runner, self.temporary_stage)
        self.assertEqual(self.publications, [])
        self.assertIn('runtime_package_architecture', (self.stage / 'private.log').read_text())

    def test_success_is_download_simulation_then_publication_with_no_installs(self):
        result = self.prepare()
        self.assertTrue(result['ok'])
        self.assertEqual(len(self.publications), 1)
        self.assertFalse(result['host_packages_installed'])
        self.assertFalse(result['application_files_changed'])
        self.assertFalse(result['services_changed'])
        commands = [command for command, _ in self.calls]
        self.assertTrue(any(command[1] == 'download' for command in commands))
        install = next(command for command in commands if 'install' in command)
        self.assertIn('--simulate', install)
        self.assertIn('--no-remove', install)
        self.assertIn('--no-install-recommends', install)
        self.assertTrue(all(Path(command[0]).parent == Path('/usr/bin') for command in commands))
        self.assertEqual(stat.S_IMODE(self.stage.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.stage / 'private.log').stat().st_mode), 0o600)

    def test_online_and_offline_apt_ignore_global_hooks_and_keep_output_private(self):
        self.prepare()
        for command, options in self.calls:
            self.assertEqual(options['env']['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
            self.assertNotIn('PYTHONPATH', options['env'])
            if Path(command[0]).name not in ('apt-get', 'apt-cache'): continue
            config = Path(options['env']['APT_CONFIG'])
            text = config.read_text()
            self.assertIn('Dir::Etc::main "-";', text)
            self.assertIn('Dir::Etc::parts "-";', text)
            self.assertIn('APT::Get::AllowUnauthenticated "false";', text)
            self.assertIn('Acquire::AllowInsecureRepositories "false";', text)
            self.assertNotIn('Post-Invoke', text)
            self.assertTrue(config.is_relative_to(self.stage))
            if command[1] == 'update' or '--simulate' in command:
                self.assertIn('Dir::Etc::sourceparts "-";', text)
                self.assertIn('Dir::State::status ', text)
                self.assertEqual((config.parent / 'status').read_bytes(), b'')
                source = (config.parent / 'offline.list').read_text()
                self.assertEqual(source, 'deb [trusted=yes] file:' + str(self.stage / 'guest-debs') + ' ./\n')

    def test_missing_dependencies_never_publish_and_keep_private_error(self):
        self.simulation_code = 100
        with self.assertRaisesRegex(tool.PreparationError, 'offline_dependencies_incomplete') as caught:
            self.prepare()
        self.assertEqual(self.publications, [])
        self.assertEqual(caught.exception.stage, self.stage)
        self.assertIn('offline_dependencies_incomplete', (self.stage / 'private.log').read_text())

    def test_failed_age_extraction_never_publish_or_simulate(self):
        self.extraction_code = 2
        with self.assertRaisesRegex(tool.PreparationError, 'age_extraction_failed'): self.prepare()
        self.assertEqual(self.publications, [])
        self.assertFalse(any('--simulate' in command for command, _ in self.calls))

    def test_unexpected_metadata_command_is_rejected_without_host_command(self):
        self.runtime.package_inventory = lambda folder: self.runtime.subprocess.check_output(['sh', '-c', 'never'], text=True)
        with self.assertRaisesRegex(tool.PreparationError, 'unexpected_metadata_command'): self.prepare()
        self.assertFalse(any(command[0] == 'sh' for command, _ in self.calls))
        self.assertEqual(self.publications, [])

    def test_default_plan_has_no_staging_or_command_side_effects(self):
        output = io.StringIO()
        with patch.object(tool, 'source_modules', return_value=(self.download, self.runtime)), \
             patch.object(tool, 'prepare', side_effect=AssertionError('preparation attempted')), \
             patch.object(tool.subprocess, 'run', side_effect=AssertionError('host command attempted')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(tool.main([]), 0)
        self.assertEqual(json.loads(output.getvalue())['mode'], 'read-only-plan')
        self.assertFalse(self.stage.exists())


if __name__ == '__main__':
    unittest.main()
