#!/usr/bin/env python3
"""Community feature policy with real PHP/JS; no application DB or network."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OVERLAY=ROOT/'tools/community/overlay'
TREE=OVERLAY if (OVERLAY/'app/license.php').is_file() else ROOT


class CommunityEditionTests(unittest.TestCase):
    def test_downloaded_verifier_contains_the_matching_current_sources(self):
        with zipfile.ZipFile(TREE/'public/timestamp-verifier.zip') as archive:
            self.assertEqual(set(archive.namelist()),{'verify-timestamp.py','tsa_core.py','README.txt'})
            for name in ('verify-timestamp.py','tsa_core.py'):
                self.assertEqual(archive.read(name),(ROOT/'bin'/name).read_bytes())

    def test_known_features_have_no_expiry_and_unknown_features_are_rejected(self):
        php=shutil.which('php')
        self.assertIsNotNone(php,'PHP CLI is required for the community policy check')
        source='''require $argv[1];$s=license_snapshot();
        foreach(array_merge(FLS_LICENSE_CORE,FLS_LICENSE_ADVANCED) as $f){
          if(!license_feature_allowed($f,['advanced_allowed'=>false,'mode'=>'commercial']))exit(10);
          license_require_feature($f);
        }
        if(license_feature_allowed('arbitrary_unknown_feature'))exit(11);
        try{license_require_feature('arbitrary_unknown_feature');exit(12);}catch(LicenseRestriction $e){}
        echo json_encode($s,JSON_THROW_ON_ERROR);'''
        result=subprocess.run([php,'-r',source,str(TREE/'app/license.php')],capture_output=True,text=True,timeout=15,check=True)
        value=json.loads(result.stdout)
        self.assertEqual(value['mode'],'community')
        self.assertEqual(value['source_license'],'Apache-2.0')
        self.assertFalse(value['enforcement'])
        self.assertTrue(value['advanced_allowed'])
        self.assertEqual(value['errors'],[])
        for key in ('license_expires_at','lease_expires_at','offline_remaining_seconds','max_devices','max_offline_hours'):
            self.assertIsNone(value[key],key)

    def test_community_panel_describes_the_selected_license_and_provider_cost_boundary(self):
        node=shutil.which('node')
        self.assertIsNotNone(node,'Node is required for the community panel check')
        source=(TREE/'public/assets/license.js').read_text()
        code=source+"\nconsole.log(JSON.stringify({ok:licensePanel({mode:'community',source_license:'Apache-2.0',advanced_allowed:true}),missing:licensePanel(null)}));"
        result=subprocess.run([node,'-e',code],capture_output=True,text=True,timeout=15,check=True)
        value=json.loads(result.stdout)
        self.assertIn('Apache-2.0',value['ok'])
        self.assertIn('Açık kaynak',value['ok'])
        self.assertIn('kredileri ayrıca sağlanır',value['ok'])
        self.assertIn('Durum okunamadı',value['missing'])
        self.assertNotIn('72 saat',value['ok'])
        self.assertNotIn('fetch(',source)


if __name__=='__main__':unittest.main(verbosity=2)
