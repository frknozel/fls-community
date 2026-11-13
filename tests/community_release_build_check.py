#!/usr/bin/env python3
"""Release-builder fixtures: no compiler, downloads, package or service changes."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'tools/community/overlay' if (ROOT / 'tools/community/overlay').is_dir() else ROOT
spec = importlib.util.spec_from_file_location('fls_fixture_release_build', TREE / 'tools/build-release.py')
release = importlib.util.module_from_spec(spec); spec.loader.exec_module(release)


def digest_bytes(data): return hashlib.sha256(data).hexdigest()


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name); member.size = len(data); member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


class ReleaseBuilderFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-release-build-test-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.source = self.folder / 'source'; self.source.mkdir()
        self.components = self.folder / 'components'; self.components.mkdir()
        self.destination = self.folder / 'release'
        self.key = self.folder / 'fixture-signing-key.pem'
        self.key.write_bytes(b'fixture key is never executed\n'); self.key.chmod(0o600)
        component_files = {
            'artifacts/linux-amd64/fls-archive-hash': b'fixture native helper\n',
            'artifacts/linux-amd64/fls-checked-write-collector.tar.gz':
                tar_bytes([('opt/fortigate/rsyslog-8.2312.0-fg1/sbin/rsyslogd', b'fixture collector')]),
        }
        manifest = {'components': []}
        for index, (name, data) in enumerate(component_files.items()):
            path = self.components / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            manifest['components'].append({'id': 'fixture' + str(index), 'relative_path': name,
                'kind': 'native_binary' if index == 0 else 'collector_bundle',
                'required': True, 'sha256': digest_bytes(data)})
        upstream = b'fixture corresponding upstream archive\n'
        patch_bytes = b'fixture source patch\n'
        provenance = {'schema': 1, 'source_archives': [{'filename': 'fixture.orig.tar.gz',
            'bytes': len(upstream), 'sha256': digest_bytes(upstream)}],
            'local_modification': {'file': 'omfile-checked-writes.patch', 'sha256': digest_bytes(patch_bytes)}}
        self.files = {
            'VERSION': b'0.76.0\n',
            'bin/fls-install.py': b'# fixture installer\n',
            'bin/system-backup.py': (TREE / 'bin/system-backup.py').read_bytes(),
            'docs/system-backup-restore.md': (TREE / 'docs/system-backup-restore.md').read_bytes(),
            'deploy/installer-components.json': json.dumps(manifest).encode(),
            'tools/build-components.py': b'# fixture build script\n',
            'third_party/rsyslog/source.json': json.dumps(provenance).encode(),
            'third_party/rsyslog/omfile-checked-writes.patch': patch_bytes,
        }
        for name, data in self.files.items():
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(0o644)
        rows = [{'path': name, 'sha256': digest_bytes(data), 'bytes': len(data), 'mode': 644}
                for name, data in self.files.items()]
        self.baseline = self.source / '.fls-community-manifest.json'
        self.baseline.write_text(json.dumps({'schema': 'fixture-sanitized-source', 'files': rows}))
        self.offer_entries = [('rsyslog-source/fixture.orig.tar.gz', upstream),
                              ('rsyslog-source/omfile-checked-writes.patch', patch_bytes),
                              ('rsyslog-source/source.json', self.files['third_party/rsyslog/source.json']),
                              ('rsyslog-source/build-components.py', self.files['tools/build-components.py'])]
        self.offer = self.components / 'rsyslog-corresponding-source.tar.gz'
        self.offer.write_bytes(tar_bytes(self.offer_entries))
        report = {'schema': 'fls-community-component-build-v1', 'files': [
            {'path': name, 'bytes': len(data), 'sha256': digest_bytes(data)} for name, data in component_files.items()] +
            [{'path': self.offer.name, 'bytes': self.offer.stat().st_size, 'sha256': release.digest(self.offer)}]}
        (self.components / 'build-result.json').write_text(json.dumps(report))
        self.sign_calls = []

    def fake_sign(self, args, **kwargs):
        self.sign_calls.append(args)
        Path(args[args.index('-out') + 1]).write_bytes(b'0' * 64)
        return type('Completed', (), {'returncode': 0})()

    def build(self):
        with patch.object(release.subprocess, 'run', side_effect=self.fake_sign), contextlib.redirect_stdout(io.StringIO()):
            return release.build(self.source, self.components, self.destination, 'v0.76.0-rc.5', self.key)

    def test_full_builder_creates_exact_three_field_inventory_and_pinned_assets(self):
        outer = self.build()
        tree = self.destination / 'fls-community'
        inner = json.loads((tree / 'deploy/release-files.json').read_text())
        self.assertEqual(set(inner), {'schema', 'version', 'files'})
        self.assertEqual(inner['schema'], 'fls-community-release-files-v1')
        self.assertEqual(inner['version'], outer['version'])
        self.assertTrue(all(set(row) == {'path', 'sha256', 'mode'} for row in inner['files']))
        expected = {path.relative_to(tree).as_posix() for path in tree.rglob('*') if path.is_file()
                    and path.relative_to(tree).as_posix() != 'deploy/release-files.json'}
        self.assertEqual(expected, {row['path'] for row in inner['files']})
        self.assertEqual(outer['sha256'], release.digest(self.destination / outer['filename']))
        self.assertEqual(outer['collector_source']['sha256'], release.digest(self.destination / self.offer.name))
        self.assertEqual(len(self.sign_calls), 1)
        self.assertEqual(self.sign_calls[0][self.sign_calls[0].index('-inkey') + 1], str(self.key))
        self.assertEqual(outer['acceptance'], 'external_clean_vm_pending')
        with tarfile.open(self.destination / outer['filename']) as archive:
            self.assertTrue(all(member.isfile() and member.name.startswith('fls-community/')
                                and member.mode in (0o644, 0o755) for member in archive))

    def test_signed_release_carries_resources_declared_by_actual_backup_builder(self):
        # Inspect the real consumer rather than duplicate its required doc name.
        module = ast.parse((TREE / 'bin/system-backup.py').read_text())
        required_docs = {node.right.value for node in ast.walk(module)
                         if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                         and isinstance(node.left, ast.Name) and node.left.id == 'SOURCE'
                         and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
                         and node.right.value.startswith('docs/')}
        self.assertTrue(required_docs, 'Backup builder must declare its bundled recovery guide')
        self.assertTrue(required_docs.issubset(release.REQUIRED_RUNTIME_RESOURCES))
        outer = self.build()
        tree = self.destination / 'fls-community'
        inner = json.loads((tree / 'deploy/release-files.json').read_text())
        rows = {row['path']: row for row in inner['files']}
        with tarfile.open(self.destination / outer['filename']) as archive:
            for relative in required_docs:
                self.assertIn(relative, rows)
                member = archive.getmember('fls-community/' + relative)
                data = archive.extractfile(member).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), rows[relative]['sha256'])
                self.assertEqual(data, (TREE / relative).read_bytes())
                self.assertTrue(data.strip())

    def test_missing_or_unlisted_runtime_guide_never_signs_or_creates_release(self):
        for remove_file in (False, True):
            with self.subTest(remove_file=remove_file):
                # Discover resource names from the builder contract itself.
                guide = next(name for name in release.REQUIRED_RUNTIME_RESOURCES if name.startswith('docs/'))
                baseline = json.loads(self.baseline.read_text())
                original = self.baseline.read_bytes()
                data = (self.source / guide).read_bytes()
                baseline['files'] = [row for row in baseline['files'] if row['path'] != guide]
                self.baseline.write_text(json.dumps(baseline))
                if remove_file: (self.source / guide).unlink()
                try:
                    with self.assertRaisesRegex(ValueError, 'required_runtime_resource_not_listed'): self.build()
                    self.assertFalse(self.destination.exists())
                    self.assertEqual(self.sign_calls, [])
                finally:
                    self.baseline.write_bytes(original)
                    (self.source / guide).write_bytes(data)

    def test_release_inventory_is_accepted_by_actual_git_free_backup_reader(self):
        self.build()
        tree = self.destination / 'fls-community'
        spec = importlib.util.spec_from_file_location('fixture_git_free_backup', TREE / 'bin/system-backup.py')
        backup = importlib.util.module_from_spec(spec); spec.loader.exec_module(backup)
        (tree / 'public').mkdir()
        (tree / 'public/archive-public-key.pem').write_bytes(b'fixture generated public key')
        with patch.object(backup, 'SOURCE', tree), \
             patch.object(backup.subprocess, 'run', side_effect=AssertionError('host command attempted')):
            report = backup.source_inventory(None)
        self.assertEqual(report['release_version'], '0.76.0')
        self.assertFalse(report['git_history_included'])
        self.assertTrue(report['working_tree_included'])
        (tree / 'bin/fls-install.py').write_bytes(b'changed installed code')
        with patch.object(backup, 'SOURCE', tree):
            with self.assertRaises(backup.BackupError): backup.source_inventory(None)

    def test_unlisted_private_file_and_signing_key_are_not_packaged(self):
        private = self.source / 'private-installation-secret.txt'
        private.write_bytes(b'fixture private installation secret\n')
        self.build()
        for path in (self.destination / 'fls-community').rglob('*'):
            self.assertNotEqual(path.name, private.name)
            self.assertNotEqual(path.name, self.key.name)
            if path.is_file(): self.assertNotIn(private.read_bytes(), path.read_bytes())

    def test_component_checksum_failure_never_signs(self):
        component = self.components / 'artifacts/linux-amd64/fls-archive-hash'
        component.write_bytes(component.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'component_checksum_mismatch'): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_source_checksum_failure_never_signs(self):
        (self.source / 'bin/fls-install.py').write_bytes(b'changed code')
        with self.assertRaisesRegex(ValueError, 'source_inventory_mismatch'): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_changed_component_during_copy_is_not_signed(self):
        original = release.shutil.copyfile
        def changed_copy(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            if Path(source) == self.components / 'artifacts/linux-amd64/fls-archive-hash':
                Path(destination).write_bytes(b'changed component after hash check')
            return result
        with patch.object(release.shutil, 'copyfile', side_effect=changed_copy):
            with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_changed_source_offer_during_copy_is_not_signed(self):
        original = release.shutil.copyfile
        def changed_copy(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            if Path(source) == self.offer:
                Path(destination).write_bytes(tar_bytes([('rsyslog-source/unrelated.txt', b'wrong copied source')]))
            return result
        with patch.object(release.shutil, 'copyfile', side_effect=changed_copy):
            with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_signing_key_inside_source_or_readable_by_others_is_rejected_before_output(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private_key_permissions_invalid'): self.build()
        self.assertFalse(self.destination.exists())
        self.key.chmod(0o600)
        inside = self.source / 'key.pem'; inside.write_bytes(b'fixture'); inside.chmod(0o600)
        self.key = inside
        with self.assertRaisesRegex(ValueError, 'key_must_be_external'): self.build()
        self.assertFalse(self.destination.exists())

    def test_version_tag_mismatch_is_rejected_before_output(self):
        with self.assertRaisesRegex(ValueError, 'version_tag_mismatch'):
            release.build(self.source, self.components, self.destination, 'v0.75.0', self.key)
        self.assertFalse(self.destination.exists())

    def test_missing_corresponding_source_never_signs(self):
        self.offer.unlink()
        with self.assertRaises((ValueError, OSError)): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_source_ancestor_symlink_cannot_inject_outside_file(self):
        original = self.source / 'bin'; moved = self.folder / 'outside-bin'
        original.rename(moved); original.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_declared_export_mode_is_checked_before_publishing(self):
        (self.source / 'bin/fls-install.py').chmod(0o755)
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.sign_calls, [])

    def test_wrong_corresponding_source_archive_cannot_be_signed(self):
        self.offer.write_bytes(tar_bytes([('rsyslog-source/unrelated.txt', b'wrong source')]))
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.sign_calls, [])


class CompleteBootstrapFixtures(unittest.TestCase):
    """Execute the real shell flow against only local, synthetic targets.

    UID/OS/early marker paths are replaced in a private script copy. Fake curl,
    dpkg and mktemp cannot reach networks, packages or host directories. OpenSSL
    really verifies a disposable fixture key. The target installer only writes a
    fixture proof file and never imports the privileged installation engine.
    """
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-bootstrap-flow-test-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.remote = self.folder / 'remote'; self.remote.mkdir()
        self.shims = self.folder / 'shims'; self.shims.mkdir()
        self.work = self.folder / 'bootstrap-work'
        self.proof = self.folder / 'installer-proof'
        self.calls = self.folder / 'curl-calls'
        self.marker = self.folder / 'fresh-marker'
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo).decode().strip()
        script = (TREE / 'install.sh').read_text()
        script, count = re.subn(r'for marker in [^\n]+; do', "for marker in '" + str(self.marker) + "'; do", script)
        self.assertEqual(count, 1)
        script = script.replace('[[ "$EUID" == 0 ]]', '[[ 0 == 0 ]]')
        os_release = self.folder / 'os-release'; os_release.write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        script = script.replace('source /etc/os-release', "source '" + str(os_release) + "'")
        script, count = re.subn(r'-----BEGIN PUBLIC KEY-----\n.*?\n-----END PUBLIC KEY-----', public, script, flags=re.S)
        self.assertEqual(count, 1)
        self.script = self.folder / 'install.sh'; self.script.write_text(script)
        commands = {
            'dpkg': '#!/bin/sh\n[ "$1" = "--print-architecture" ] || exit 97\nprintf amd64\n',
            'mktemp': '#!/usr/bin/python3\nimport os\nfrom pathlib import Path\np=Path(os.environ["FLS_FIXTURE_WORK"]);p.mkdir(mode=0o700);print(p)\n',
            'curl': '#!/usr/bin/python3\nimport os,sys,shutil\nfrom pathlib import Path\na=sys.argv[1:];name=a[-1].rsplit("/",1)[-1]\n'
                    'assert name in {"release.json","release.json.sig","fls-community-0.76.0-rc.5-linux-amd64.tar.gz"}\n'
                    'with open(os.environ["FLS_FIXTURE_CALLS"],"a") as log:log.write(name+"\\n")\n'
                    'shutil.copyfile(Path(os.environ["FLS_FIXTURE_REMOTE"])/name,a[a.index("--output")+1])\n',
        }
        for name, content in commands.items():
            path = self.shims / name; path.write_text(content); path.chmod(0o755)
        self.environment = {**os.environ, 'PATH': str(self.shims) + ':/usr/bin:/bin',
            'FLS_FIXTURE_WORK': str(self.work), 'FLS_FIXTURE_REMOTE': str(self.remote),
            'FLS_FIXTURE_CALLS': str(self.calls), 'FLS_FIXTURE_PROOF': str(self.proof)}
        installer = (b'import os\nfrom pathlib import Path\n'
                     b'Path(os.environ["FLS_FIXTURE_PROOF"]).write_text("fixture installer reached")\n')
        self.package = self.remote / 'fls-community-0.76.0-rc.5-linux-amd64.tar.gz'
        self.package.write_bytes(tar_bytes([('fls-community/bin/fls-install.py', installer)]))
        self.manifest = {'schema': 'fls-community-release-v1', 'version': '0.76.0',
                         'tag': 'v0.76.0-rc.5', 'filename': self.package.name,
                         'bytes': self.package.stat().st_size, 'sha256': release.digest(self.package)}
        self.sign()

    def sign(self):
        payload = json.dumps(self.manifest).encode()
        (self.remote / 'release.json').write_bytes(payload)
        (self.remote / 'release.json.sig').write_bytes(self.key.sign(payload))

    def invoke(self, *arguments):
        return subprocess.run(['/bin/bash', str(self.script), *(arguments or ('--apply',))], env=self.environment,
                              capture_output=True, text=True, timeout=15)

    def downloads(self): return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_valid_signature_and_package_reach_only_fixture_installer(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.proof.read_text(), 'fixture installer reached')
        self.assertEqual(self.downloads(), ['release.json', 'release.json.sig', self.package.name])
        self.assertFalse(self.work.exists())

    def check_installer(self):
        installer = (b'import os,sys\nfrom pathlib import Path\n'
                     b'assert sys.argv[1:] == ["--check"]\n'
                     b'Path(os.environ["FLS_FIXTURE_PROOF"]).write_text("checked without apply")\n'
                     b'raise SystemExit(2)\n')
        self.package.write_bytes(tar_bytes([('fls-community/bin/fls-install.py', installer)]))
        self.manifest.update(bytes=self.package.stat().st_size, sha256=release.digest(self.package))
        self.sign()

    def test_standalone_check_verifies_signature_and_preserves_read_only_status(self):
        self.check_installer()
        result = self.invoke('--check')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.proof.read_text(), 'checked without apply')
        self.assertEqual(self.downloads(), ['release.json', 'release.json.sig', self.package.name])
        self.assertFalse(self.work.exists())
        self.assertFalse(self.marker.exists())

    def test_check_can_report_existing_host_and_repeat_without_journal(self):
        self.marker.mkdir(); self.check_installer()
        for attempt in range(2):
            result = self.invoke('--check')
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(self.proof.read_text(), 'checked without apply')
            self.assertFalse(self.work.exists())
        self.assertEqual(len(self.downloads()), 6)

    def test_conflicting_modes_reject_before_download(self):
        result = self.invoke('--check', '--apply')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.downloads(), [])
        self.assertFalse(self.proof.exists())

    def test_unsigned_manifest_change_stops_before_package_download(self):
        self.manifest['sha256'] = '0' * 64
        (self.remote / 'release.json').write_text(json.dumps(self.manifest))
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.proof.exists())
        self.assertEqual(self.downloads(), ['release.json', 'release.json.sig'])
        self.assertFalse(self.work.exists())

    def test_signed_wrong_package_hash_never_executes_installer(self):
        self.manifest['sha256'] = '0' * 64; self.sign()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.proof.exists())
        self.assertEqual(self.downloads(), ['release.json', 'release.json.sig', self.package.name])
        self.assertFalse(self.work.exists())

    def test_existing_target_refuses_before_any_download(self):
        self.marker.mkdir()
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn('Fresh Ubuntu required', result.stderr)
        self.assertFalse(self.proof.exists()); self.assertEqual(self.downloads(), [])
        self.assertFalse(self.work.exists())


if __name__ == '__main__': unittest.main()
