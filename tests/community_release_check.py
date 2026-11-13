#!/usr/bin/env python3
"""Signed release/bootstrap fixtures. Never downloads or installs software."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
TREE=ROOT/'tools/community/overlay' if (ROOT/'tools/community/overlay').is_dir() else ROOT
spec=importlib.util.spec_from_file_location('community_release',TREE/'tools/build-release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
script=(TREE/'install.sh').read_text()
code=script.split('# BEGIN FLS SAFE EXTRACTION (covered by tests/community_release_check.py)\n',1)[1].split('# END FLS SAFE EXTRACTION',1)[0]
namespace={'__name__':'fixture'};exec(compile(code,'bootstrap-extract','exec'),namespace)
extract=namespace['extract_release']

class ReleaseFixtures(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.work=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def archive(self,entries):
        package=self.work/'package.tar.gz'
        with tarfile.open(package,'w:gz') as archive:
            for name,kind,data,mode in entries:
                member=tarfile.TarInfo(name);member.type=kind;member.mode=mode
                member.size=len(data) if kind==tarfile.REGTYPE else 0
                if kind==tarfile.SYMTYPE:member.linkname='/etc/shadow'
                archive.addfile(member,io.BytesIO(data) if member.isfile() else None)
        manifest={'bytes':package.stat().st_size,'sha256':release.digest(package)}
        (self.work/'release.json').write_text(json.dumps(manifest))
    def test_valid_archive_preserves_executable(self):
        self.archive([('fls-community/bin/fls-install.py',tarfile.REGTYPE,b'print(1)\n',0o755)])
        root=extract(self.work);self.assertEqual((root/'bin/fls-install.py').stat().st_mode&0o777,0o755)
    def test_traversal_before_writes(self):
        for name in ('../outside','fls-community/../outside','/fls-community/absolute','fls-community//empty','fls-community/./dot','fls-community/back\\slash'):
            with self.subTest(name=name):
                self.archive([(name,tarfile.REGTYPE,b'x',0o644)])
                with self.assertRaisesRegex(ValueError,'member_invalid'):extract(self.work)
                self.assertFalse((self.work/'outside').exists())
                (self.work/'source').rmdir()
    def test_links_devices_directories_and_setuid_rejected(self):
        for kind,mode in ((tarfile.SYMTYPE,0o644),(tarfile.LNKTYPE,0o644),(tarfile.CHRTYPE,0o644),(tarfile.DIRTYPE,0o755),(tarfile.REGTYPE,0o4755)):
            with self.subTest(kind=kind,mode=mode):
                self.archive([('fls-community/danger',kind,b'x',mode)])
                with self.assertRaises(ValueError):extract(self.work)
                (self.work/'source').rmdir()
    def test_duplicate_member_rejected(self):
        self.archive([('fls-community/a',tarfile.REGTYPE,b'x',0o644)]*2)
        with self.assertRaises(ValueError):extract(self.work)
    def test_hash_mismatch_no_source_created(self):
        self.archive([('fls-community/a',tarfile.REGTYPE,b'x',0o644)])
        package=self.work/'package.tar.gz';raw=package.read_bytes();package.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        with self.assertRaisesRegex(ValueError,'checksum'):extract(self.work)
        self.assertFalse((self.work/'source').exists())
    def test_size_mismatch(self):
        self.archive([('fls-community/a',tarfile.REGTYPE,b'x',0o644)])
        with (self.work/'package.tar.gz').open('ab') as stream:stream.write(b'x')
        with self.assertRaisesRegex(ValueError,'size'):extract(self.work)
    def test_parent_file_directory_collision_fails(self):
        self.archive([('fls-community/a',tarfile.REGTYPE,b'x',0o644),('fls-community/a/b',tarfile.REGTYPE,b'x',0o644)])
        with self.assertRaises(OSError):extract(self.work)
    def test_missing_installer_fails(self):
        self.archive([('fls-community/a',tarfile.REGTYPE,b'x',0o644)])
        with self.assertRaisesRegex(ValueError,'installer_missing'):extract(self.work)
    def test_bootstrap_key_matches_shipped_public_key(self):
        self.assertIn((TREE/'deploy/publisher-release-key.pem').read_text().strip(),script)
    def test_signature_binds_manifest(self):
        key=self.work/'private.pem';pub=self.work/'public.pem';signed=self.work/'manifest.json';sig=self.work/'signature'
        def run(args):return subprocess.run(['openssl',*map(str,args)],capture_output=True)
        self.assertEqual(run(['genpkey','-algorithm','ED25519','-out',key]).returncode,0)
        self.assertEqual(run(['pkey','-in',key,'-pubout','-out',pub]).returncode,0)
        signed.write_bytes(b'{"sha256":"fixture"}\n')
        self.assertEqual(run(['pkeyutl','-sign','-inkey',key,'-rawin','-in',signed,'-out',sig]).returncode,0)
        args=['pkeyutl','-verify','-pubin','-inkey',pub,'-rawin','-in',signed,'-sigfile',sig]
        self.assertEqual(run(args).returncode,0)
        signed.write_bytes(b'{"sha256":"changed"}\n');self.assertNotEqual(run(args).returncode,0)
    def test_inventory_detects_modes_and_excludes_self(self):
        tree=self.work/'tree';tree.mkdir();(tree/'deploy').mkdir()
        (tree/'VERSION').write_text('0.76.0\n');(tree/'deploy/release-files.json').write_text('{}')
        (tree/'binary').write_bytes(b'fixture');(tree/'binary').chmod(0o755)
        rows={r['path']:r for r in release.inventory(tree)['files']}
        self.assertNotIn('deploy/release-files.json',rows);self.assertEqual(rows['binary']['mode'],755)
        self.assertEqual(rows['binary']['sha256'],hashlib.sha256(b'fixture').hexdigest())
    def test_inventory_refuses_symlink(self):
        (self.work/'VERSION').write_text('0.76.0\n');(self.work/'redirect').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):release.inventory(self.work)
    def test_shell_refuses_apply_on_existing_host_before_network(self):
        # This process only executes the early admission guard, never HostOps.
        if os.geteuid()!=0 or not Path('/var/www/fls').exists():self.skipTest('existing-root-host fixture unavailable')
        result=subprocess.run(['bash',str(TREE/'install.sh'),'--apply'],capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertIn('Fresh Ubuntu required',result.stderr)
        self.assertNotIn('Verifying',result.stdout)

if __name__=='__main__':unittest.main()
