#!/usr/bin/python3
"""Boot an offline disposable Ubuntu guest and restore a pinned FLS backup.

Default is a read-only capability plan. --run uses only new files beneath /tmp;
no host mounts, package installation, disk devices, TAP, port forwarding, SSH,
provider requests or application database connections are used.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile

SOURCE=Path(__file__).resolve().parents[1]


def prepare_boot_image(image,folder,qemu_img,env,log):
    """Mask guest network waits without mounting or exposing a block device."""
    raw=folder/'boot.raw'
    subprocess.run([str(qemu_img),'convert','-f','qcow2','-O','raw',str(image),str(raw)],
                   env=env,check=True,stdout=log,stderr=log)
    output=subprocess.check_output(['/usr/sbin/sfdisk','--json',str(raw)],stderr=log)
    table=json.loads(output)['partitiontable']
    if table['label']!='gpt' or table['sectorsize']!=512:raise ValueError('guest_partition_table_unsupported')
    candidates=[p for p in table['partitions'] if p['type'].lower()=='0fc63daf-8483-4772-8e79-3d69d8477de4']
    if len(candidates)!=1:raise ValueError('guest_root_partition_ambiguous')
    partition=candidates[0];start=partition['start']*512;size=partition['size']*512
    filesystem=folder/'guest-root.ext4'
    with raw.open('rb') as source,filesystem.open('wb') as target:
        source.seek(start);remaining=size
        while remaining:
            chunk=source.read(min(8*1024*1024,remaining))
            if not chunk:raise ValueError('guest_partition_short')
            target.write(chunk);remaining-=len(chunk)
    for name in ['systemd-networkd-wait-online.service','systemd-networkd-wait-online@.service']:
        subprocess.run(['/usr/sbin/debugfs','-w','-R','symlink /etc/systemd/system/'+name+' /dev/null',str(filesystem)],
                       stdout=log,stderr=log,check=True)
        check=subprocess.check_output(['/usr/sbin/debugfs','-R','stat /etc/systemd/system/'+name,str(filesystem)],stderr=log)
        if b'Type: symlink' not in check or b'/dev/null' not in check:raise ValueError('guest_network_wait_mask_failed')
    with filesystem.open('rb') as source,raw.open('r+b') as target:
        target.seek(start);shutil.copyfileobj(source,target,8*1024*1024);target.flush();os.fsync(target.fileno())
    filesystem.unlink()
    return raw


def checked_file(path,digest=None):
    path=path.absolute()
    if path.resolve(strict=True)!=path:raise ValueError('input_symlink_unsafe')
    for parent in path.parents:
        details=parent.lstat()
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid!=0
                or (details.st_mode&0o022 and not details.st_mode&stat.S_ISVTX)):
            raise ValueError('input_parent_unsafe')
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('input_file_unsafe')
    if digest is not None:
        if re.fullmatch('[a-f0-9]{64}',digest or '') is None:
            raise ValueError('expected_sha256_required')
        with path.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=digest:raise ValueError('input_hash_mismatch')
    return path


def validate_resume(folder,image,backup_sha256):
    folder=folder.absolute()
    info=folder.lstat()
    if (folder.parent!=Path('/tmp') or not folder.name.startswith('fls-recovery-guest-')
            or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0
            or stat.S_IMODE(info.st_mode)!=0o700 or folder.resolve()!=folder
            or image!=folder/'root.qcow2'):
        raise ValueError('resume_directory_unsafe')
    plan=json.loads(checked_file(folder/'plan.json').read_text())
    result=json.loads(checked_file(folder/'result.json').read_text())
    if (plan.get('schema')!='fls-offline-recovery-drill-plan-v1'
            or plan.get('backup_sha256')!=backup_sha256
            or result.get('schema')!='fls-offline-recovery-host-result-v1'
            or result.get('evidence_directory')!=str(folder) or result.get('ok') is not False
            or result.get('phases')!=['offline_packages']):
        raise ValueError('resume_requires_failed_package_stage')
    return folder


def execute(options):
    if os.geteuid()!=0:raise ValueError('root_required_for_private_evidence')
    if not 60<=options.timeout<=1800:raise ValueError('timeout_out_of_range')
    os.umask(0o077)
    backup=checked_file(options.backup,options.backup_sha256)
    image=checked_file(options.image,options.image_sha256)
    resumed=validate_resume(options.resume_from,image,options.backup_sha256) if options.resume_from else None
    tools=options.tools.resolve(strict=True)
    binaries={name:checked_file(tools/'usr/bin'/name) for name in ['qemu-system-x86_64','qemu-img','genisoimage']}
    firmware=checked_file(tools/'usr/share/OVMF/OVMF_CODE_4M.fd')
    vars_source=checked_file(tools/'usr/share/OVMF/OVMF_VARS_4M.fd')
    packages=sorted(options.packages.resolve(strict=True).glob('*.deb'))
    if not packages:raise ValueError('offline_packages_missing')
    for package in packages:checked_file(package)
    folder=Path(tempfile.mkdtemp(prefix='fls-recovery-guest-',dir='/tmp'));folder.chmod(0o700)
    nonce=secrets.token_hex(16)
    seed=folder/'seed';seed.mkdir(mode=0o700)
    shutil.copyfile(backup,seed/'backup.tar.gz')
    shutil.copyfile(SOURCE/'bin/recovery-drill-guest.py',seed/'guest.py')
    shutil.copyfile(SOURCE/'bin/provision-disk-management.py',seed/'provision-disk-management.py')
    (seed/'packages').mkdir(mode=0o700)
    package_index={}
    apt_index=[]
    for package in packages:
        os.link(package,seed/'packages'/package.name)
        metadata=subprocess.check_output(['dpkg-deb','--field',str(package)],text=True)
        fields=dict(line.split(': ',1) for line in metadata.splitlines()
                    if line and not line[0].isspace() and ': ' in line)
        package_index[package.name]={name:fields[name] for name in ['Package','Version']}
        with package.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        apt_index.append(metadata.rstrip()+'\nFilename: ./'+package.name+'\nSize: '+str(package.stat().st_size)
                         +'\nSHA256: '+digest+'\n\n')
    (seed/'packages.json').write_text(json.dumps(package_index,sort_keys=True))
    (seed/'packages/Packages').write_text(''.join(apt_index))
    (seed/'meta-data').write_text('instance-id: fls-recovery-'+nonce+'\nlocal-hostname: fls-recovery-drill\n')
    (seed/'network-config').write_text('version: 2\nethernets: {}\n')
    (seed/'user-data').write_text('''#cloud-config
disable_root: true
ssh_pwauth: false
bootcmd:
 - [mkdir, -p, /mnt/fls-drill]
 - [mount, -o, ro, /dev/disk/by-label/CIDATA, /mnt/fls-drill]
runcmd:
 - [/usr/bin/python3, /mnt/fls-drill/guest.py]
''')
    plan={'schema':'fls-offline-recovery-drill-plan-v1','nonce':nonce,
          'backup_sha256':options.backup_sha256,'image_sha256':options.image_sha256,
          'created_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
          'network_devices':0,'memory_mb':4096,'vcpus':1,'acceleration':'tcg',
          'physical_disk_devices':False,'guest_network_wait_masked':True,
          'resumed_from':str(resumed) if resumed else None}
    (seed/'plan.json').write_text(json.dumps(plan,sort_keys=True));(folder/'plan.json').write_text(json.dumps(plan,sort_keys=True))
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
         'LD_LIBRARY_PATH':str(tools/'usr/lib/x86_64-linux-gnu')+':'+str(tools/'lib/x86_64-linux-gnu'),
         'QEMU_MODULE_DIR':str(tools/'usr/lib/x86_64-linux-gnu/qemu')}
    with (folder/'private-host.log').open('wb') as log:
        subprocess.run([str(binaries['genisoimage']),'-quiet','-output',str(folder/'seed.iso'),
                        '-volid','CIDATA','-joliet','-rock',str(seed)],env=env,check=True,stdout=log,stderr=log)
        boot_image=image if resumed else prepare_boot_image(image,folder,binaries['qemu-img'],env,log)
        subprocess.run([str(binaries['qemu-img']),'create','-f','qcow2','-F','qcow2' if resumed else 'raw',
                        '-b',str(boot_image),str(folder/'root.qcow2'),'16G'],env=env,check=True,stdout=log,stderr=log)
        shutil.copyfile(vars_source,folder/'uefi-vars.fd')
        command=[str(binaries['qemu-system-x86_64']),'-machine','q35','-accel','tcg,thread=single',
                 '-cpu','max','-m','4096','-smp','1','-nodefaults','-no-user-config','-display','none','-monitor','none',
                 '-serial','stdio','-nic','none','-no-reboot','-L',str(tools/'usr/share/qemu'),
                 '-chardev','file,id=private-log,path='+str(folder/'private-guest.log'),
                 '-device','virtio-serial-pci','-device','virtserialport,chardev=private-log,name=fls.drill.private',
                 '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
                 '-smbios','type=1,serial=FLSRECOVERY-'+nonce,
                 '-drive','if=pflash,format=raw,readonly=on,file='+str(firmware),
                 '-drive','if=pflash,format=raw,file='+str(folder/'uefi-vars.fd'),
                 '-device','virtio-scsi-pci,id=scsi0',
                 '-drive','if=none,id=rootdisk,format=qcow2,file='+str(folder/'root.qcow2'),
                 '-device','scsi-hd,drive=rootdisk,wwn=0x5000000000000001,serial=FLS-DRILL-SYSTEM,bootindex=1',
                 '-drive','if=none,id=seed,format=raw,readonly=on,file='+str(folder/'seed.iso'),
                 '-device','scsi-cd,drive=seed']
        started=dt.datetime.now(dt.timezone.utc)
        console=folder/'private-console.log'
        with console.open('wb') as serial:
            process=subprocess.Popen(command,env=env,stdout=serial,stderr=log,start_new_session=True,
                                     preexec_fn=lambda:os.nice(15))
            try:
                subprocess.run(['/usr/bin/ionice','-c','3','-p',str(process.pid)],
                               stdout=log,stderr=log,check=True)
                try:returncode=process.wait(timeout=options.timeout)
                except subprocess.TimeoutExpired:returncode=124
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        phases=[];result=None;boot_evidence=None
        for line in console.read_text(errors='replace').splitlines():
            if 'FLS_DRILL_PHASE ' in line:phases.append(line.split('FLS_DRILL_PHASE ',1)[1].strip())
            if 'FLS_DRILL_BOOT ' in line:
                try:boot_evidence=json.loads(line.split('FLS_DRILL_BOOT ',1)[1])
                except ValueError:pass
            if 'FLS_DRILL_RESULT ' in line:
                try:result=json.loads(line.split('FLS_DRILL_RESULT ',1)[1])
                except ValueError:pass
        summary={'schema':'fls-offline-recovery-host-result-v1','evidence_directory':str(folder),
                 'backup_filename':backup.name,'backup_sha256':options.backup_sha256,
                 'image_sha256':options.image_sha256,'guest_network_wait_masked':True,
                 'resumed_from':str(resumed) if resumed else None,
                 'qemu_exit_code':returncode,'elapsed_seconds':round((dt.datetime.now(dt.timezone.utc)-started).total_seconds(),2),
                 'phases':phases,'boot_evidence':boot_evidence,'guest':result,'ok':returncode==0 and isinstance(result,dict) and result.get('ok') is True,
                 'host_database_used':False,'host_mounts_or_services_changed':False}
        (folder/'result.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
        print(json.dumps(summary,sort_keys=True))
        return 0 if summary['ok'] else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    for name in ['backup','image','tools','packages']:parser.add_argument('--'+name,type=Path)
    parser.add_argument('--backup-sha256');parser.add_argument('--image-sha256')
    parser.add_argument('--resume-from',type=Path,help='Only own failed package-stage /tmp guest, with pinned overlay hash')
    parser.add_argument('--timeout',type=int,default=1200)
    options=parser.parse_args()
    if not options.run:
        print(json.dumps({'mode':'read-only-plan','isolated_guest':'QEMU TCG UEFI Ubuntu',
                          'network_devices':0,'memory_mb':4096,'vcpus':1,'timeout_seconds':options.timeout,
                          'host_packages_installed':False,'host_database_used':False,
                          'physical_disks_tested':False}));return 0
    if not all(getattr(options,key) for key in ['backup','image','tools','packages','backup_sha256','image_sha256']):
        parser.error('--run requires pinned backup/image, tools and offline packages')
    return execute(options)


if __name__=='__main__':raise SystemExit(main())
