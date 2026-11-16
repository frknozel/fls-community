#!/usr/bin/env python3
"""Render the Community version and asset tags with PHP; no application DB."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
OVERLAY=ROOT/'tools/community/overlay'
TREE=OVERLAY if (OVERLAY/'public/index.php').is_file() else ROOT
INDEX=(TREE/'public/index.php').read_text()
PHP=os.environ.get('FLS_TEST_PHP') or shutil.which('php')


def render(version,assets=None):
    # Execute only the real version/asset prelude and its actual HTML tags.
    # Authentication, bootstrap.php and application queries are never loaded.
    prelude=INDEX[INDEX.index('$releaseFile='):INDEX.index("$error='';$notice='';")]
    badge=re.search(r'<span class="beta">.*?</span>',INDEX).group(0)
    footer=re.search(r'<footer class="page-footer">.*?</footer>',INDEX).group(0)
    asset_tags=[re.search(r'<script src="/assets/'+re.escape(name)+r'\?v=.*?</script>',INDEX).group(0)
                for name in ('disk-management.js','settings.js','app.js')]
    with tempfile.TemporaryDirectory(prefix='fls-community-version-') as temporary:
        root=Path(temporary);public=root/'public';public.mkdir();(public/'assets').mkdir()
        if version is not None:(root/'VERSION').write_text(version)
        for name,body in (assets or {}).items():(public/'assets'/name).write_text(body)
        fixture=public/'index.php'
        fixture.write_text('<?php\ndeclare(strict_types=1);\n'+prelude+
                           '\nfunction h($value){return htmlspecialchars((string)$value,ENT_QUOTES|ENT_SUBSTITUTE,"UTF-8");}\n?>'+
                           badge+footer+''.join(asset_tags))
        return subprocess.run([PHP,'-n',str(fixture)],capture_output=True,text=True,check=True,timeout=10)


def render_guest(version):
    """Run the complete real guest page with only external bootstrap stubs."""
    with tempfile.TemporaryDirectory(prefix='fls-community-guest-') as temporary:
        root=Path(temporary);public=root/'public';public.mkdir();app=root/'app';app.mkdir()
        (public/'index.php').write_text(INDEX)
        if version is not None:(root/'VERSION').write_text(version)
        (app/'bootstrap.php').write_text('''<?php
declare(strict_types=1);
require __DIR__.'/recovery-rehearsal.php';
$_SERVER['REQUEST_METHOD']='GET';
$_SESSION=['csrf'=>'guest-fixture-csrf'];
function authenticated(){return false;}
function h($value){return htmlspecialchars((string)$value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function query(...$values){throw new RuntimeException('Guest fixture must not query the database');}
''')
        shutil.copyfile(ROOT/'app/recovery-rehearsal.php',app/'recovery-rehearsal.php')
        (app/'retention.php').write_text('<?php const FLS_RETENTION_DEFAULT_FAST_DAYS=30;')
        return subprocess.run([PHP,'-n',str(public/'index.php')],capture_output=True,text=True,check=True,timeout=10)


class CommunityDiskDisplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PHP:raise RuntimeError('PHP CLI is required for Community display tests')

    def test_badge_and_footer_follow_the_installed_version_file(self):
        for version in ('0.76.0','1.2.3-rc.7'):
            result=render(version+'\n')
            self.assertEqual(result.stderr,'')
            self.assertIn('<span class="beta">'+version+'</span>',result.stdout)
            self.assertIn('v'+version+'</span>',result.stdout)
            self.assertNotIn('0.75.0',result.stdout)

    def test_missing_or_untrusted_version_has_a_neutral_fallback(self):
        for value in (None,'','<script>alert(1)</script>','1.2.3\n<img src=x>','1.2.3/'+'a'*150):
            result=render(value)
            self.assertEqual(result.stderr,'')
            self.assertIn('<span class="beta">Sürüm bilinmiyor</span>',result.stdout)
            self.assertNotIn('<img',result.stdout)
            self.assertNotIn('alert(1)',result.stdout)
            self.assertNotIn('vSürüm',result.stdout)

    def test_changed_scripts_bust_cache_even_when_release_version_is_unchanged(self):
        names=('disk-management.js','settings.js','app.js')
        first={name:'first '+name for name in names}
        second={name:'updated '+name for name in names}
        before=render('0.76.0',first).stdout;after=render('0.76.0',second).stdout
        for name in names:
            old=hashlib.sha256(first[name].encode()).hexdigest()[:16]
            new=hashlib.sha256(second[name].encode()).hexdigest()[:16]
            self.assertIn('/assets/'+name+'?v='+old,before)
            self.assertIn('/assets/'+name+'?v='+new,after)
            self.assertNotIn(old,after)

    def test_full_guest_login_exposes_validated_version_before_authentication(self):
        for raw,expected in [('0.76.0\n','0.76.0'),(None,'Sürüm bilinmiyor'),
                             ('<script>alert(1)</script>','Sürüm bilinmiyor')]:
            result=render_guest(raw)
            self.assertEqual(result.stderr,'')
            self.assertIn('<meta name="fls-version" content="'+expected+'">',result.stdout)
            self.assertIn('Oturum aç',result.stdout)
            self.assertIn('name="mode" value="login"',result.stdout)
            self.assertNotIn('class="sidebar"',result.stdout)
            self.assertNotIn('alert(1)',result.stdout)


if __name__=='__main__':unittest.main(verbosity=2)
