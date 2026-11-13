#!/usr/bin/env python3
"""Assemble a signed Community release from a sanitized source export.

Never installs software. Inputs are immutable; output must be a new directory.
The signing key belongs outside the source tree and is never copied to output.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

SCHEMA='fls-community-release-files-v1'


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def safe_path(value):
    if (not isinstance(value,str) or not value or '\\' in value or '\x00' in value
        or any(part in ('','.','..') for part in value.split('/'))
        or PurePosixPath(value).is_absolute()): raise ValueError('unsafe_path')
    return value


def inventory(root):
    rows=[]
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise ValueError('symlink_forbidden')
        if path.is_dir():continue
        if not path.is_file():raise ValueError('regular_file_required')
        name=path.relative_to(root).as_posix();safe_path(name)
        if name=='deploy/release-files.json':continue
        mode=stat.S_IMODE(path.stat().st_mode)
        if mode not in (0o644,0o755):raise ValueError('file_mode_invalid')
        rows.append({'path':name,'sha256':digest(path),
                     'mode':755 if mode==0o755 else 644})
    return {'schema':SCHEMA,'version':(root/'VERSION').read_text().strip(),'files':rows}


def pack(source,destination):
    with destination.open('xb') as output,gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(source.rglob('*')):
            if path.is_dir():continue
            if path.is_symlink() or not path.is_file():raise ValueError('regular_file_required')
            member=tarfile.TarInfo('fls-community/'+path.relative_to(source).as_posix())
            member.size=path.stat().st_size;member.mode=stat.S_IMODE(path.stat().st_mode)
            member.uid=member.gid=member.mtime=0
            with path.open('rb') as stream:archive.addfile(member,stream)


def verify_source_offer(source,offer):
    expected={}
    provenance=json.loads((source/'third_party/rsyslog/source.json').read_text())
    for row in provenance['source_archives']:
        expected['rsyslog-source/'+safe_path(row['filename'])]=(row['sha256'],row['bytes'])
    for path in (source/'third_party/rsyslog').iterdir():
        if path.is_file(): expected['rsyslog-source/'+path.name]=(digest(path),path.stat().st_size)
    recipe=source/'tools/build-components.py'
    expected['rsyslog-source/build-components.py']=(digest(recipe),recipe.stat().st_size)
    seen=set()
    with tarfile.open(offer,'r:gz') as archive:
        for member in archive:
            if (member.name not in expected or member.name in seen or not member.isfile()
                or member.size!=expected[member.name][1]): raise ValueError('source_offer_inventory_mismatch')
            seen.add(member.name)
            if hashlib.file_digest(archive.extractfile(member),'sha256').hexdigest()!=expected[member.name][0]:raise ValueError('source_offer_checksum_mismatch')
    if seen!=set(expected):raise ValueError('source_offer_file_missing')


def build(source,components,destination,tag,key):
    source=source.resolve(strict=True);components=components.resolve(strict=True)
    destination=destination.absolute();key=key.resolve(strict=True)
    if destination.exists() or destination.is_symlink():raise ValueError('new_destination_required')
    if key.is_relative_to(source) or key.is_relative_to(destination):raise ValueError('key_must_be_external')
    if key.stat().st_mode&0o077 or not key.is_file():raise ValueError('private_key_permissions_invalid')
    version=(source/'VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+',version) or not re.fullmatch('v'+re.escape(version)+r'(?:-rc\.\d+)?',tag):raise ValueError('version_tag_mismatch')
    baseline=json.loads((source/'.fls-community-manifest.json').read_text())
    source_rows=baseline.get('files',[])
    # The exporter manifest's map format is intentionally accepted as well.
    if isinstance(source_rows,dict):source_rows=[{'path':p,**(v if isinstance(v,dict) else {'sha256':v})} for p,v in source_rows.items()]
    if not source_rows:raise ValueError('sanitized_export_required')
    destination.mkdir(mode=0o700);tree=destination/'fls-community';tree.mkdir(mode=0o755)
    listed=set()
    for row in source_rows:
        name=safe_path(row['path']);path=source/name
        if (name in listed or path.resolve(strict=True)!=path or not path.is_file()
            or row.get('mode') not in (644,755)
            or stat.S_IMODE(path.stat().st_mode)!=int(str(row['mode']),8)
            or digest(path)!=row['sha256']):raise ValueError('source_inventory_mismatch')
        listed.add(name);target=tree/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,target);target.chmod(int(str(row['mode']),8))
        if digest(target)!=row['sha256']:raise ValueError('source_changed_during_copy')
    shutil.copyfile(source/'.fls-community-manifest.json',tree/'.fls-community-manifest.json')
    (tree/'.fls-community-manifest.json').chmod(0o644)
    manifest=json.loads((tree/'deploy/installer-components.json').read_text())
    for item in manifest['components']:
        if not item['required']:continue
        name=safe_path(item['relative_path']);path=components/name
        if path.resolve(strict=True)!=path or not path.is_file() or digest(path)!=item['sha256']:raise ValueError('component_checksum_mismatch')
        target=tree/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
        target.chmod(0o755 if item['kind']=='native_binary' else 0o644)
        if digest(target)!=item['sha256']:raise ValueError('component_changed_during_copy')
    inner=inventory(tree)
    (tree/'deploy/release-files.json').write_text(json.dumps(inner,sort_keys=True,indent=2)+'\n')
    (tree/'deploy/release-files.json').chmod(0o644)
    filename=f'fls-community-{tag[1:]}-linux-amd64.tar.gz';package=destination/filename
    pack(tree,package)
    source_offer=components/'rsyslog-corresponding-source.tar.gz'
    if source_offer.resolve(strict=True)!=source_offer or not source_offer.is_file():raise ValueError('collector_source_offer_required')
    verify_source_offer(tree,source_offer)
    offer=destination/source_offer.name;shutil.copyfile(source_offer,offer)
    verify_source_offer(tree,offer)
    manifest={'schema':'fls-community-release-v1','version':version,'tag':tag,
              'filename':filename,'bytes':package.stat().st_size,'sha256':digest(package),
              'platform':'ubuntu24.04-amd64','acceptance':'external_clean_vm_pending',
              'collector_source':{'filename':offer.name,'bytes':offer.stat().st_size,'sha256':digest(offer)}}
    signed=destination/'release.json';signed.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(signed),'-out',str(destination/'release.json.sig')],check=True)
    for path in (package,offer,signed,destination/'release.json.sig'):path.chmod(0o644)
    print(json.dumps(manifest,sort_keys=True))
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','components','destination','key'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--tag',required=True)
    args=parser.parse_args();build(args.source,args.components,args.destination,args.tag,args.key)


if __name__=='__main__':main()
