#!/usr/bin/env python3
"""Build/verify application releases and inspect upgrades. No install/apply command."""
import sys
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

from release_package import ReleaseError, build_package, parse_version, verify_package
from release_preflight import assess

MAX_DOCUMENT=16*1024*1024
MAX_SOURCE=512*1024*1024


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ReleaseError('document_duplicate_key')
            result[key]=value
        return result
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except (ValueError,TypeError,UnicodeError,RecursionError) as exc:raise ReleaseError('document_invalid') from exc


def trusted_parents(path,owner):
    for folder in Path(path).absolute().parents:
        info=folder.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,owner):raise ReleaseError('local_parent_untrusted')
        if info.st_mode&0o022 and not (info.st_uid==0 and info.st_mode&stat.S_ISVTX):raise ReleaseError('local_parent_untrusted')


def trusted_metadata(path,owner):
    trusted_parents(path,owner)
    info=path.lstat()
    if info.st_uid!=owner or info.st_mode&0o022 or not stat.S_ISDIR(info.st_mode):raise ReleaseError('git_metadata_untrusted')
    count=0
    for directory,folders,files in os.walk(path,followlinks=False):
        for name in folders+files:
            current=Path(directory)/name;item=current.lstat();count+=1
            if count>50000:raise ReleaseError('git_metadata_limit')
            if item.st_uid!=owner or item.st_mode&0o022 or not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)):raise ReleaseError('git_metadata_untrusted')
    if (path/'objects/info/alternates').exists():raise ReleaseError('git_alternates_unsupported')


def git_provenance(root,owner):
    marker=root/'.git';trusted_parents(marker,owner);info=marker.lstat()
    if info.st_uid!=owner or info.st_mode&0o022:raise ReleaseError('git_metadata_untrusted')
    if stat.S_ISDIR(info.st_mode):gitdir=marker
    elif stat.S_ISREG(info.st_mode):
        raw,_=read_file(marker,4096,root_owned=owner==0)
        try:value=raw.decode('ascii').strip()
        except UnicodeError as exc:raise ReleaseError('git_metadata_invalid') from exc
        if not value.startswith('gitdir: ') or not Path(value[8:]).is_absolute():raise ReleaseError('git_metadata_invalid')
        gitdir=Path(value[8:])
    else:raise ReleaseError('git_metadata_untrusted')
    trusted_metadata(gitdir,owner)
    common=gitdir
    if (gitdir/'commondir').exists():
        raw,_=read_file(gitdir/'commondir',4096,root_owned=owner==0)
        try:value=raw.decode('ascii').strip()
        except UnicodeError as exc:raise ReleaseError('git_metadata_invalid') from exc
        common=(gitdir/value).resolve(strict=True);trusted_metadata(common,owner)
    for config in [common/'config',gitdir/'config.worktree']:
        if not config.exists():continue
        raw=git(root,'config','--no-includes','--file',str(config),'--null','--list')
        for item in raw.split(b'\0'):
            key=item.split(b'\n',1)[0].lower()
            if key.startswith((b'filter.',b'include.',b'includeif.')) or key in (b'core.worktree',b'core.sshcommand',b'core.gitproxy',b'diff.external') or key.startswith(b'extensions.'):
                raise ReleaseError('git_custom_execution_configuration')


def read_file(path,limit=MAX_DOCUMENT,private=False,root_owned=False):
    if root_owned:trusted_parents(path,0)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:raise ReleaseError('local_file_invalid')
        if root_owned and (info.st_uid!=0 or info.st_mode&0o022):raise ReleaseError('local_file_untrusted')
        if private and stat.S_IMODE(info.st_mode) not in (0o600,0o640):raise ReleaseError('local_file_permissions')
        value=stream.read(limit+1)
        if len(value)>limit:raise ReleaseError('local_file_limit')
        return value,info


def command(args,*,cwd=None,limit=MAX_DOCUMENT):
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC',
         'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0'}
    try:run=subprocess.run(args,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:raise ReleaseError('inspection_command_unavailable') from exc
    if run.returncode or len(run.stdout)>limit:raise ReleaseError('inspection_command_failed')
    return run.stdout


def git(root,*args,limit=MAX_DOCUMENT):
    return command(['/usr/bin/git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',
                    '-c','core.untrackedCache=false','-c','tar.umask=0022','-c','safe.directory='+str(root),*args],cwd=root,limit=limit)


def source_inventory(root,require_root=True):
    root=Path(root).absolute();trusted_parents(root,0 if require_root else os.geteuid())
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode):raise ReleaseError('source_root_untrusted')
    if info.st_mode&0o022 or info.st_uid!=(0 if require_root else os.geteuid()):raise ReleaseError('source_root_untrusted')
    git_provenance(root,0 if require_root else os.geteuid())
    if Path(os.fsdecode(git(root,'rev-parse','--show-toplevel')).strip()).resolve()!=root:raise ReleaseError('source_git_root')
    commit=git(root,'rev-parse','HEAD').decode().strip();tree=git(root,'rev-parse',commit+'^{tree}').decode().strip()
    if not re.fullmatch('[a-f0-9]{40}',commit) or not re.fullmatch('[a-f0-9]{40}',tree):raise ReleaseError('source_git_identity')
    status=git(root,'status','--porcelain=v1','--untracked-files=all')
    files={};total=0
    for raw in git(root,'ls-files','-z','--cached').split(b'\0'):
        if not raw:continue
        name=os.fsdecode(raw);relative=Path(name)
        if relative.is_absolute() or any(part in ('..','.') for part in relative.parts):raise ReleaseError('source_path')
        path=root/relative
        for parent in list(path.parents):
            if parent==root:break
            p=parent.lstat()
            if not stat.S_ISDIR(p.st_mode) or p.st_uid!=(0 if require_root else os.geteuid()) or p.st_mode&0o022:raise ReleaseError('source_directory_untrusted')
        data,info=read_file(path,64*1024*1024,root_owned=require_root)
        if info.st_uid!=(0 if require_root else os.geteuid()) or info.st_mode&0o022 or not info.st_mode&0o400:raise ReleaseError('source_file_untrusted')
        total+=len(data)
        if total>MAX_SOURCE or len(files)>=4096:raise ReleaseError('source_inventory_limit')
        files[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':755 if info.st_mode&0o111 else 644}
    if git(root,'status','--porcelain=v1','--untracked-files=all')!=status or git(root,'rev-parse','HEAD').decode().strip()!=commit:raise ReleaseError('source_changed_during_inspection')
    return {'available':True,'trusted':True,'clean':not bool(status),'untracked_count':sum(line.startswith(b'?? ') for line in status.splitlines()),'source_commit':commit,'source_tree':tree},files,total


def build(args):
    repo=Path(args.repo).resolve(strict=True);key=Path(args.private_key).resolve(strict=True)
    if key.is_relative_to(repo) or key.is_relative_to(Path('/etc/fls')) or key.is_relative_to(Path('/srv/fls-server')):raise ReleaseError('publisher_key_location')
    status,_,_=source_inventory(repo,require_root=False)
    if not status['clean']:raise ReleaseError('source_git_dirty')
    archive=git(repo,'archive','--format=tar',status['source_commit'],limit=MAX_SOURCE)
    with tempfile.TemporaryDirectory(prefix='fls-release-source-') as temporary:
        source=Path(temporary)/'source';source.mkdir(mode=0o755)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as stream:
            for item in stream:
                relative=Path(item.name)
                if relative.is_absolute() or any(part in ('..','.') for part in relative.parts) or not item.isdir() and not item.isreg():raise ReleaseError('source_archive_member')
                target=source/relative
                if item.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o755);target.chmod(0o755);continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as output:
                    data=stream.extractfile(item)
                    if data is None:raise ReleaseError('source_archive_missing')
                    shutil.copyfileobj(data,output,1024*1024)
                target.chmod(0o755 if item.mode&0o111 else 0o644)
        # The signed identity comes from the tracked committed snapshot, never a dirty tree.
        version=read_file(source/'VERSION',64)[0].decode('ascii').strip();parse_version(version)
        if git(repo,'rev-parse','HEAD').decode().strip()!=status['source_commit'] or git(repo,'status','--porcelain=v1','--untracked-files=all'):raise ReleaseError('source_changed_during_build')
        manifest=build_package(source,args.output,args.private_key,version=version,channel=args.channel,
            source_commit=status['source_commit'],source_tree=status['source_tree'],
            compatibility={'from_versions':args.from_version,'schema_before':args.schema,'schema_after':args.schema})
    return {'schema':1,'operation':'build','manifest':manifest,'application_package_only':True,'installed':False}


def marker_present():
    folder=Path('/var/lib/fls-maintenance');info=folder.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ReleaseError('maintenance_directory_untrusted')
    try:info=(folder/'paused').lstat()
    except FileNotFoundError:return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ReleaseError('maintenance_marker_untrusted')
    return True


def collect_inventory(args,manifest):
    if os.geteuid()!=0:raise ReleaseError('inspection_requires_root')
    raw,info=read_file(args.installed_state,65536,private=True,root_owned=True)
    if stat.S_IMODE(info.st_mode)!=0o600:raise ReleaseError('installed_state_permissions')
    state=strict_json(raw)
    if type(state) is not dict or set(state)!={'schema','installed'} or type(state['schema']) is not int or state['schema']!=1:raise ReleaseError('installed_state_invalid')
    source,files,source_bytes=source_inventory(args.installed_root)
    raw,_=read_file('/etc/fls/app.json',16384,private=True,root_owned=True);credential=strict_json(raw)
    if type(credential) is not dict or credential.get('user')!='fls_app' or not isinstance(credential.get('password'),str):raise ReleaseError('database_credential_invalid')
    import pymysql
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=credential['user'],password=credential['password'],database='fls',charset='utf8mb4',autocommit=False,connect_timeout=3,read_timeout=5,write_timeout=3,cursorclass=pymysql.cursors.DictCursor)
    try:
        with db.cursor() as cursor:
            cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
            cursor.execute('SELECT requested_mode,revision,requested_at,requested_by FROM maintenance_requests WHERE id=1');request=cursor.fetchone()
            cursor.execute('SELECT version,applied_revision,attempted_revision,collector_state,marker_present,checked_at,applied_at,error_code FROM maintenance_state WHERE id=1');worker=cursor.fetchone()
            cursor.execute("SELECT SUM(COALESCE(DATA_LENGTH,0)+COALESCE(INDEX_LENGTH,0)) bytes FROM information_schema.TABLES WHERE TABLE_SCHEMA='fls'");db_bytes=cursor.fetchone()['bytes']
        db.commit()
    finally:db.close()
    if not request or not worker or db_bytes is None:raise ReleaseError('installation_inventory_unavailable')
    now=dt.datetime.now(dt.timezone.utc)
    for key in ('requested_at',):request[key]=request[key].strftime('%Y-%m-%d %H:%M:%S.%f') if isinstance(request[key],dt.datetime) else request[key]
    for key in ('checked_at','applied_at'):worker[key]=worker[key].strftime('%Y-%m-%d %H:%M:%S.%f') if isinstance(worker[key],dt.datetime) else worker[key]
    worker['marker_present']=worker['marker_present']==1
    try:age=(now-dt.datetime.fromisoformat(worker['checked_at']).replace(tzinfo=dt.timezone.utc)).total_seconds()
    except (TypeError,ValueError):age=-1
    worker['age_seconds']=int(age) if age>=0 else -1
    paused=(request['requested_mode']=='paused' and worker['collector_state']=='inactive' and worker['marker_present'] and worker['applied_revision']==worker['attempted_revision']==request['revision'] and worker['error_code']=='')
    maintenance={'schema':1,'available':True,'fresh':0<=age<=45,'state':'paused' if paused else 'unknown','request':request,'worker':worker}
    actual=command(['/usr/bin/systemctl','--system','--no-pager','show','fortigate-collector.service','--property=ActiveState','--property=LoadState']).decode('ascii')
    actual=dict(line.split('=',1) for line in actual.splitlines())
    collector={'state':actual.get('ActiveState') if actual.get('LoadState')=='loaded' else 'unknown','marker_present':marker_present()}
    os_data=platform.freedesktop_os_release()
    php=command(['/usr/bin/php','-n','-r','echo PHP_VERSION;'],limit=256).decode('ascii')
    package_bytes=Path(args.package).stat().st_size+sum(row['bytes'] for row in manifest['files'])
    inventory={'schema':1,'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'installed':state['installed'],'maintenance':maintenance,'collector':collector,
        'runtime':{'os_id':os_data.get('ID'),'os_version':os_data.get('VERSION_ID'),'architecture':platform.machine(),'python_version':platform.python_version(),'php_version':php},'git':source,
        'disk':{'free_bytes':shutil.disk_usage(args.backup_directory).free,'package_bytes':package_bytes,'source_bytes':source_bytes,'backup_required_bytes':int(db_bytes)*2+source_bytes+128*1024*1024,'reserve_bytes':args.reserve_gib*1024**3},'files':files}
    return inventory


def write_report(path,value):
    if not path:return
    data=(json.dumps(value,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    p=sub.add_parser('build');p.add_argument('--repo',required=True);p.add_argument('--private-key',required=True);p.add_argument('--output',required=True);p.add_argument('--from-version',action='append',required=True);p.add_argument('--schema',type=int,required=True);p.add_argument('--channel',choices=['development','stable'],default='development');p.add_argument('--report')
    for operation in ['verify','preflight']:
        p=sub.add_parser(operation);p.add_argument('--package',required=True);p.add_argument('--public-key',required=True);p.add_argument('--report')
        if operation=='preflight':
            p.add_argument('--inventory');p.add_argument('--installed-root',default='/var/www/fls');p.add_argument('--installed-state',default='/etc/fls/release-state.json');p.add_argument('--backup-directory',default='/srv/fls-server/backups');p.add_argument('--reserve-gib',type=int,default=4)
    args=parser.parse_args(argv)
    try:
        if args.operation=='build':result=build(args);status=0
        else:
            manifest=verify_package(args.package,args.public_key)
            if args.operation=='verify':result={'schema':1,'operation':'verify','signature_verified':True,'manifest':manifest,'installed':False};status=0
            else:
                inventory=strict_json(read_file(args.inventory)[0]) if args.inventory else collect_inventory(args,manifest)
                result=assess(manifest,inventory,now=dt.datetime.now(dt.timezone.utc));result.update(operation='preflight',signature_verified=True,inventory_source='supplied_fixture' if args.inventory else 'local_read_only',reverification_required_for_future_apply=True)
                status=0 if result['preflight_ok'] else 2
        write_report(args.report,result)
        output={key:value for key,value in result.items() if key!='manifest'}
        if 'manifest' in result:output.update(version=result['manifest']['version'],file_count=len(result['manifest']['files']),signing_key_id=result['manifest']['signing_key_id'])
        print(json.dumps(output,ensure_ascii=True,sort_keys=True));return status
    except (ReleaseError,OSError,ValueError,UnicodeError,OverflowError) as exc:
        code=str(exc) if isinstance(exc,ReleaseError) and re.fullmatch('[a-z0-9_]+',str(exc)) else 'release_operation_failed'
        print(json.dumps({'schema':1,'operation':args.operation,'ok':False,'error_code':code,'installed':False}));return 2
    except Exception:
        print(json.dumps({'schema':1,'operation':args.operation,'ok':False,'error_code':'release_inspection_unavailable','installed':False}));return 2


if __name__=='__main__':raise SystemExit(main())
