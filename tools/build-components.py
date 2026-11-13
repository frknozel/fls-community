#!/usr/bin/env python3
"""Build Community release components in a new scratch directory, never install.

Requires a trusted Ubuntu build host with build dependencies already present.
All source archives are verified against the shipped provenance before use.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

PREFIX='opt/fortigate/rsyslog-8.2312.0-fg1'


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def pack(destination,entries):
    with destination.open('xb') as output,gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
        for name,path in sorted(entries):
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode):raise ValueError('component_non_regular_file')
            member=tarfile.TarInfo(name);member.size=info.st_size;member.uid=0;member.gid=0
            member.mode=0o755 if info.st_mode&0o111 else 0o644;member.mtime=0
            with path.open('rb') as stream:archive.addfile(member,stream)


def build(source,cache,output,go):
    source=source.resolve(strict=True);cache=cache.resolve(strict=True);output=output.absolute()
    if output.exists() or output.is_symlink():raise ValueError('new_output_directory_required')
    if not go.is_file():raise ValueError('go_compiler_required')
    provenance=json.loads((source/'third_party/rsyslog/source.json').read_text())
    for item in provenance['source_archives']:
        name=item['filename']
        if not re.fullmatch(r'[A-Za-z0-9_.+-]+',name):raise ValueError('source_archive_name_invalid')
        path=cache/name
        if path.is_symlink() or path.stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:
            raise ValueError('source_archive_hash_mismatch')
    patch=source/'third_party/rsyslog'/provenance['local_modification']['file']
    if sha(patch)!=provenance['local_modification']['sha256']:raise ValueError('patch_hash_mismatch')
    output.mkdir(mode=0o700);work=output/'work';work.mkdir(mode=0o700)
    artifacts=output/'artifacts/linux-amd64';artifacts.mkdir(parents=True)
    environment={**os.environ,'LANG':'C.UTF-8','TZ':'UTC','SOURCE_DATE_EPOCH':'1794528000',
        'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','CGO_ENABLED':'0',
        'GOMAXPROCS':'2','GOCACHE':str(work/'go-cache')}
    with (output/'build.log').open('wb') as log:
        def run(args,cwd=work,env=None):
            subprocess.run(['nice','-n','15',*map(str,args)],cwd=cwd,env=env or environment,
                           check=True,stdin=subprocess.DEVNULL,stdout=log,stderr=log,timeout=1200)
        native=source/'native/archivehash'
        run([go,'test','-count=1','./...'],native)
        run([go,'build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=',
             '-o',artifacts/'fls-archive-hash','.'],native)
        dsc=next(item for item in provenance['source_archives'] if item['filename'].endswith('.dsc'))
        # --no-check skips a second network/keyring lookup; exact signed-source
        # descriptor AND both archive SHA-256 values were already checked above.
        run(['dpkg-source','--no-check','-x',cache/dsc['filename'],work/'collector-source'])
        collector=work/'collector-source'
        run(['patch','--batch','--fuzz=0','-p1','-i',patch],collector)
        cenv={**environment,'CFLAGS':'-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 '
                '-ffile-prefix-map='+str(work)+'=/usr/src/fls-community',
              'LDFLAGS':'-Wl,-z,relro,-z,now'}
        run(['./configure',*provenance['configure_arguments']],collector,cenv)
        run(['make','-j2'],collector,cenv)
        stage=work/'stage';stage.mkdir()
        run(['make','DESTDIR='+str(stage),'install'],collector,cenv)
        prefix=stage/PREFIX
        for path in prefix.rglob('*'):
            if path.is_symlink():raise ValueError('collector_symlink_unexpected')
            if path.is_file() and path.read_bytes()[:4]==b'\x7fELF':run(['strip','--strip-unneeded',path])
        notices=prefix/'share/doc/fls-collector';notices.mkdir(parents=True,exist_ok=True)
        for name in ('COPYING','COPYING.LESSER','COPYING.ASL20'):
            shutil.copyfile(collector/name,notices/name)
        shutil.copyfile(collector/'debian/copyright',notices/'ubuntu-copyright')
        for name in ('NOTICE','source.json','omfile-checked-writes.patch'):
            shutil.copyfile(source/'third_party/rsyslog'/name,notices/name)
        bundle=artifacts/'fls-checked-write-collector.tar.gz'
        pack(bundle,[(str(path.relative_to(stage)),path) for path in prefix.rglob('*') if path.is_file()])
        source_entries=[]
        for item in provenance['source_archives']:
            source_entries.append(('rsyslog-source/'+item['filename'],cache/item['filename']))
        for path in (source/'third_party/rsyslog').iterdir():
            if path.is_file():source_entries.append(('rsyslog-source/'+path.name,path))
        source_entries.append(('rsyslog-source/build-components.py',source/'tools/build-components.py'))
        pack(output/'rsyslog-corresponding-source.tar.gz',source_entries)
    listing=[]
    for path in [artifacts/'fls-archive-hash',bundle,output/'rsyslog-corresponding-source.tar.gz']:
        listing.append({'path':str(path.relative_to(output)),'bytes':path.stat().st_size,'sha256':sha(path)})
    result={'schema':'fls-community-component-build-v1','platform':'ubuntu24.04-amd64',
            'go_version':subprocess.check_output([str(go),'version'],text=True).strip(),
            'files':listing,'installed_on_build_host':False,'services_changed':False}
    (output/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--go',type=Path,required=True)
    args=parser.parse_args();build(args.source,args.cache,args.output,args.go)


if __name__=='__main__':main()
