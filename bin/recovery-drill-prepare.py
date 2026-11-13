#!/usr/bin/python3
"""Download/extract drill inputs into a new private /tmp tree; never install.

Requires existing trusted APT metadata/repositories compatible with the source
appliance (including PHP8.3). No apt update, package install or host changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

TOOL_PACKAGES=['qemu-system-x86','qemu-utils','genisoimage','ovmf']
GUEST_PACKAGES=['mariadb-server','nginx','php8.3-cli','php8.3-fpm','php8.3-mysql',
                'php8.3-mbstring','php8.3-curl','php8.3-xml',
                'python3-pymysql','python3-cryptography','python3-psutil',
                'rsyslog','acl','curl','ca-certificates']


def download_packages(base,name,roots):
    folder=base/name;folder.mkdir(mode=0o700)
    result=subprocess.run(['apt-cache','depends','--recurse','--important','--no-recommends',
                           '--no-suggests','--no-conflicts','--no-breaks','--no-replaces',
                           '--no-enhances',*roots],capture_output=True,text=True,check=True)
    packages=sorted({line for line in result.stdout.splitlines()
                     if line and not line[0].isspace() and not line.startswith('<')})
    if not packages or any(not re.fullmatch(r'[A-Za-z0-9+.:-]+',p) for p in packages):
        raise ValueError('package_resolution_failed')
    with (base/(name+'-download.log')).open('wb') as log:
        subprocess.run(['apt-get','download',*packages],cwd=folder,stdout=log,stderr=subprocess.STDOUT,check=True)
    files=sorted(folder.glob('*.deb'))
    if not files:raise ValueError('packages_missing')
    return {'roots':roots,'resolved':packages,'files':{path.name:{'bytes':path.stat().st_size,
             'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest()} for path in files}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare',action='store_true');parser.add_argument('--directory',type=Path)
    parser.add_argument('--ubuntu-image-release',help='Official noble image release date, YYYYMMDD')
    options=parser.parse_args()
    if not options.prepare:
        print(json.dumps({'mode':'read-only-plan','downloads_only':True,'host_packages_installed':False,
                          'tools':TOOL_PACKAGES,'guest_packages':GUEST_PACKAGES}));return 0
    if os.geteuid()!=0 or options.directory is None or not re.fullmatch(r'\d{8}',options.ubuntu_image_release or ''):
        parser.error('--prepare requires root, a new /tmp directory and --ubuntu-image-release YYYYMMDD')
    base=options.directory.absolute()
    if base.parent!=Path('/tmp') or base.parent.resolve()!=base.parent or base.exists() or base.is_symlink():
        raise ValueError('new_private_tmp_directory_required')
    os.umask(0o077);base.mkdir(mode=0o700)
    manifest={'schema':'fls-recovery-drill-inputs-v1','host_packages_installed':False}
    manifest['tools']=download_packages(base,'tool-debs',TOOL_PACKAGES)
    manifest['guest']=download_packages(base,'guest-debs',GUEST_PACKAGES)
    tools=base/'tools';tools.mkdir(mode=0o700)
    for package in sorted((base/'tool-debs').glob('*.deb')):
        subprocess.run(['dpkg-deb','--extract',str(package),str(tools)],check=True,stdout=subprocess.DEVNULL)
    for path in tools.rglob('*'):
        if path.is_file() and not path.is_symlink():path.chmod(path.stat().st_mode&~(stat.S_ISUID|stat.S_ISGID))
    url='https://cloud-images.ubuntu.com/minimal/releases/noble/release-'+options.ubuntu_image_release+'/'
    name='ubuntu-24.04-minimal-cloudimg-amd64.img'
    for filename in ['SHA256SUMS',name]:
        subprocess.run(['curl','--fail','--location','--silent','--show-error','--max-time','300',
                        '--output',str(base/filename),url+filename],check=True)
    expected=next(line.split()[0] for line in (base/'SHA256SUMS').read_text().splitlines()
                  if line.split()[-1].lstrip('*')==name)
    actual=hashlib.file_digest((base/name).open('rb'),'sha256').hexdigest()
    if actual!=expected:raise ValueError('official_image_checksum_mismatch')
    manifest['image']={'source':url+name,'sha256':actual,'bytes':(base/name).stat().st_size}
    (base/'inputs.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'ok':True,'directory':str(base),'image':manifest['image'],
                      'tool_package_count':len(manifest['tools']['files']),
                      'guest_package_count':len(manifest['guest']['files']),
                      'host_packages_installed':False}));return 0


if __name__=='__main__':raise SystemExit(main())
