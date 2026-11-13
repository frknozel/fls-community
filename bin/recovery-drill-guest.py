#!/usr/bin/python3
"""Disposable, offline QEMU guest only. Never execute on an installed appliance."""
import gzip
import grp
import hashlib
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

SEED=Path('/mnt/fls-drill')
WORK=Path('/root/fls-drill')
PHASE='guest_safety'
RESULT={'schema':'fls-offline-recovery-drill-v1','ok':False,'os_boot_tested':True,
        'physical_hardware_tested':False,'fortigate_ingestion_tested':False,
        'provider_or_ftp_called':False}
GUEST_PACKAGES=['mariadb-server','nginx','php8.3-cli','php8.3-fpm','php8.3-mysql',
                'php8.3-mbstring','php8.3-curl','php8.3-xml',
                'python3-pymysql','python3-cryptography','python3-psutil',
                'rsyslog','acl','curl','ca-certificates']


def require(value,code):
    if not value:raise RuntimeError(code)


def run(args,**kwargs):
    return subprocess.run(args,check=True,stdout=LOG,stderr=LOG,**kwargs)


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def phase(value):
    global PHASE
    PHASE=value
    print('FLS_DRILL_PHASE '+value,flush=True)


def authorize_guest():
    plan=json.loads((SEED/'plan.json').read_text())
    require(isinstance(plan.get('nonce'),str) and re.fullmatch(r'[a-f0-9]{32}',plan['nonce']),
            'guest_nonce_invalid')
    require(os.geteuid()==0 and Path('/sys/class/dmi/id/product_serial').read_text().strip()
            =='FLSRECOVERY-'+plan['nonce'],'wrong_guest_identity')
    require({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'guest_network_present')
    require(Path('/sys/firmware/efi').exists(),'guest_not_booted_using_uefi')
    return plan


def stop_guest_services(units,error_code):
    # A resumed image can have services enabled by an earlier package install.
    # Recheck the disposable identity before stopping anything, then prove the
    # old datadir is no longer in use before moving or replacing its contents.
    authorize_guest()
    run(['systemctl','stop',*units])
    for unit in units:
        status=subprocess.check_output(['systemctl','show',unit,
                                        '-p','ActiveState','-p','MainPID'],text=True)
        fields=dict(line.split('=',1) for line in status.splitlines() if '=' in line)
        require(fields.get('ActiveState')=='inactive' and fields.get('MainPID')=='0',error_code)


def stop_guest_database_service():
    stop_guest_services(['mariadb.service'],'guest_database_not_stopped')


def prepare_guest_database_filesystem():
    stop_guest_database_service()
    for name,mode in [('/srv/fls-server',0o755),('/srv/fls-server/database',0o711)]:
        path=Path(name);path.mkdir(parents=True,exist_ok=True);path.chmod(mode)
    datadir=Path('/srv/fls-server/database/mysql')
    original=Path('/var/lib/mysql')
    if original.exists():shutil.move(original,datadir)
    else:
        datadir.mkdir()
        run(['mariadb-install-db','--user=mysql','--datadir='+str(datadir)])
    shutil.chown(datadir,user='mysql',group='mysql')
    config=Path('/etc/mysql/mariadb.conf.d/90-fls-drill.cnf')
    config.write_text('[mysqld]\ndatadir='+str(datadir)
                      +'\nskip-networking\ninnodb_buffer_pool_size=128M\nmax_connections=15\n')
    config.chmod(0o644)
    return datadir


def install_offline_packages():
    authorize_guest()
    Path('/usr/sbin/policy-rc.d').write_text('#!/bin/sh\nexit 101\n')
    Path('/usr/sbin/policy-rc.d').chmod(0o755)
    os.environ['DEBIAN_FRONTEND']='noninteractive'
    require((SEED/'packages/Packages').is_file(),'offline_package_index_missing')
    apt=WORK/'apt'
    for name in ['lists/partial','archives/partial','log']:
        (apt/name).mkdir(mode=0o700,parents=True,exist_ok=True)
    sources=apt/'offline.list'
    sources.write_text('deb [trusted=yes] file:'+str(SEED/'packages')+' ./\n')
    config=apt/'isolated.conf'
    # These settings must be read before apt's normal config directories;
    # command-line overrides arrive after their hooks have already been read.
    config.write_text('Dir::Etc::parts "-";\nDir::Etc::main "-";\n'
                      +'Dir::Etc::sourcelist '+json.dumps(str(sources))+';\n'
                      +'Dir::Etc::sourceparts "-";\n')
    environment={**os.environ,'APT_CONFIG':str(config)}
    # Use APT's dependency/pre-dependency and virtual-provider resolver. The
    # downloaded closure includes alternatives which must not all be forced
    # through dpkg (e.g. systemd and systemd-standalone-tmpfiles conflict).
    # Only this read-only seed can supply packages; no network source is read.
    command=['apt-get','-o','Dir::Etc::sourcelist='+str(sources),
             '-o','Dir::Etc::sourceparts=-','-o','Dir::Etc::parts=-','-o','Dir::Etc::main=-',
             '-o','Dir::State::lists='+str(apt/'lists'),
             '-o','Dir::Cache::archives='+str(apt/'archives'),'-o','Dir::Log='+str(apt/'log'),
             '-o','APT::Sandbox::User=root','-o','Acquire::Languages=none',
             '-o','Acquire::Retries=0','-o','DPkg::Lock::Timeout=30',
             '-o','Dpkg::Options::=--force-confold']
    run(command+['update'],env=environment)
    run(command+['--yes','--fix-broken','--no-remove','--no-install-recommends',
                 'install',*GUEST_PACKAGES],env=environment)


def record_failure(error):
    RESULT.update(phase=PHASE,error_type=type(error).__name__)
    if isinstance(error,RuntimeError) and re.fullmatch('[a-z0-9_]{1,64}',str(error)):
        RESULT['error_code']=str(error)
    import traceback
    traceback.print_exc(file=LOG)
    LOG.flush()


def restore_guest_service_identities(identities):
    authorize_guest()
    group_names={item['gid']:item['name'] for item in identities['groups']}
    for item in identities['groups']:
        try:grp.getgrnam(item['name'])
        except KeyError:run(['groupadd','--system',item['name']])
    for item in identities['users']:
        try:pwd.getpwnam(item['name'])
        except KeyError:run(['useradd','--system','--no-create-home','--home-dir','/nonexistent',
                            '--shell','/usr/sbin/nologin','--gid',group_names[item['gid']],item['name']])
    users={item['name'] for item in identities['users']}
    for item in identities['groups']:
        for member in item['members']:
            if member in users:run(['usermod','--append','--groups',item['name'],'--',member])


def system_restore_prefixes(files):
    prefixes=('var/www/fls','etc/fls','etc/php/8.3/fpm','etc/nginx/fls-tls','usr/lib/fls','opt/fls-tsa')
    if any(name.startswith('etc/php/8.3/mods-available/') for name in files):
        prefixes+=('etc/php/8.3/mods-available',)
    return prefixes


def initialize_guest_replay_state(connection,recovery,worker):
    authorize_guest()
    # Earlier backup verification queries are schema-qualified. The narrow
    # provisioning routine deliberately uses its connection's default schema.
    connection.select_db('fls')
    return recovery.initialize_recovery_state(connection,worker)


def prepare_guest_archive_parents():
    authorize_guest()
    # The backup starts at var/www/fls. Some nginx packages use /usr/share and
    # do not create /var/www; tar would create that implicit parent as 0700
    # under the drill's private umask, hiding otherwise correct PHP files.
    parent=Path('/var/www')
    require(not parent.is_symlink(),'guest_extraction_parent_unsafe')
    parent.mkdir(mode=0o755,exist_ok=True)
    parent.chmod(0o755)


def restore():
    plan=authorize_guest()
    RESULT['uefi_boot_tested']=True
    RESULT['guest_boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    RESULT['guest_kernel']=os.uname().release
    os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines()
                    if '=' in line)
    RESULT['guest_os']=os_release['PRETTY_NAME'].strip('"')
    print('FLS_DRILL_BOOT '+json.dumps({**RESULT,'guest_network_interfaces':['lo']},sort_keys=True),flush=True)
    phase('offline_packages')
    debs=sorted((SEED/'packages').glob('*.deb'))
    require(bool(debs),'offline_packages_missing')
    index=json.loads((SEED/'packages.json').read_text())
    status=subprocess.check_output(['dpkg-query','-W','-f','${Package}\t${Version}\t${db:Status-Status}\n'],text=True)
    installed={fields[0]:fields[1] for line in status.splitlines()
               if len(fields:=line.split('\t'))==3 and fields[2]=='installed'}
    pending=[p for p in debs if installed.get(index[p.name]['Package'])!=index[p.name]['Version']]
    print('FLS_DRILL_PACKAGES '+json.dumps({'total':len(debs),'pending':len(pending)}),flush=True)
    install_offline_packages()
    stop_guest_services(['nginx.service','php8.3-fpm.service'],'guest_application_service_not_stopped')
    phase('archive_validation')
    archive=SEED/'backup.tar.gz'
    require(hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()==plan['backup_sha256'],'backup_hash_mismatch')
    extracted=WORK/'payload';extracted.mkdir(mode=0o700)
    with tarfile.open(archive,'r:gz') as outer:
        members=outer.getmembers()
        require(all((m.isfile() or m.isdir()) and (m.name=='backup' or m.name.startswith('backup/'))
                    and '..' not in Path(m.name).parts for m in members),'outer_archive_unsafe')
        require(len({m.name for m in members})==len(members),'outer_archive_duplicate')
        outer.extractall(extracted,filter='data')
    payload=extracted/'backup';manifest=json.loads((payload/'MANIFEST.json').read_text())
    for name,info in manifest['files'].items():
        path=payload/name
        require(path.is_file() and path.stat().st_size==info['bytes']
                and hashlib.file_digest(path.open('rb'),'sha256').hexdigest()==info['sha256'],'payload_hash_mismatch')
    identities=json.loads((payload/'inventory/service-identities.json').read_text())
    restore_guest_service_identities(identities)
    mapping=json.loads((payload/'inventory/file-sha256.json').read_text())
    prefixes=system_restore_prefixes(mapping)
    selected=[]
    with tarfile.open(payload/'system.tar') as system:
        for member in system:
            require(not member.name.startswith('/') and '..' not in Path(member.name).parts,'system_archive_unsafe')
            if member.isfile():
                info=mapping.get(member.name)
                require(info is not None and member.size==info['bytes']
                        and hashlib.file_digest(system.extractfile(member),'sha256').hexdigest()==info['sha256'],
                        'system_hash_mismatch')
            if any(member.name==p or member.name.startswith(p+'/') for p in prefixes):selected.append(member.name)
    # Files come from the independently pinned, hash-checked local archive.
    prepare_guest_archive_parents()
    run(['tar','--acls','--xattrs','--numeric-owner','-xpf',str(payload/'system.tar'),'-C','/',*prefixes])
    uid_map={item['uid']:pwd.getpwnam(item['name']).pw_uid for item in identities['users']}
    gid_map={item['gid']:grp.getgrnam(item['name']).gr_gid for item in identities['groups']}
    for name in selected:
        path=Path('/')/name;info=path.lstat()
        os.chown(path,uid_map.get(info.st_uid,info.st_uid),gid_map.get(info.st_gid,info.st_gid),follow_symlinks=False)
    phase('restore_real_database_service')
    datadir=prepare_guest_database_filesystem()
    run(['systemctl','start','mariadb.service'])
    import pymysql
    connection=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True,
                               charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor)
    sys.path.insert(0,'/var/www/fls/bin')
    backup=load(Path('/var/www/fls/bin/system-backup.py'),'drill_archived_backup')
    require(backup.query(connection,'SELECT @@datadir path')[0]['path'].rstrip('/')==str(datadir),
            'restored_datadir_wrong')
    backup.query(connection,'CREATE DATABASE fls CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
    process=subprocess.Popen(['mariadb','--no-defaults','--user=root','--database=fls','--binary-mode'],
                             stdin=subprocess.PIPE,stdout=LOG,stderr=LOG)
    with gzip.open(payload/'database.sql.gz','rb') as source:shutil.copyfileobj(source,process.stdin)
    process.stdin.close();require(process.wait()==0,'database_restore_failed')
    tables={next(iter(row.values())) for row in backup.query(connection,'SHOW TABLES FROM fls')}
    require(tables==set(manifest['database_tables']),'restored_table_set_mismatch')
    expected=json.loads((payload/'inventory/configuration-digests.json').read_text())
    require(backup.configuration_digest(connection)==expected,'configuration_rows_mismatch')
    empty=tables-set(backup.CONFIG_TABLES)
    require(all(backup.query(connection,'SELECT COUNT(*) n FROM fls.'+backup.identifier(t))[0]['n']==0
                for t in empty),'runtime_rows_present')
    with tarfile.open(payload/'system.tar') as system:backup.verify_keys_and_secrets(system,connection)
    with (payload/'database-accounts.sql').open('rb') as source:
        run(['mariadb','--no-defaults','--user=root','--binary-mode'],stdin=source)
    for name in manifest['database_credential_files_covered']:
        credential=json.loads((Path('/etc/fls')/name).read_text())
        login=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=credential['user'],
                              password=credential['password'],database='fls')
        with login.cursor() as cursor:cursor.execute('SELECT 1');require(cursor.fetchone()==(1,),'account_login_failed')
        login.close()
    with (payload/'restore-safe.sql').open('rb') as source:
        run(['mariadb','--no-defaults','--user=root','--database=fls','--binary-mode'],stdin=source)
    require(all(backup.query(connection,'SELECT COUNT(*) n FROM fls.'+t)[0]['n']==1
                for t in backup.SEED_TABLES),'fresh_seed_mismatch')
    require(backup.query(connection,'SELECT requested_mode FROM fls.maintenance_requests')[0]['requested_mode']=='paused','maintenance_not_paused')
    require(backup.query(connection,'SELECT action FROM fls.power_requests')[0]['action']=='','power_request_present')
    require(all(row['enabled']==0 for row in backup.query(connection,'SELECT enabled FROM fls.timestamp_settings')),'timestamp_enabled')
    require(all(row['enabled']==0 for row in backup.query(connection,'SELECT enabled FROM fls.archive_destinations')),'external_destination_enabled')
    require(all(row['packaging_enabled']==0 for row in backup.query(connection,'SELECT packaging_enabled FROM fls.archive_export_settings')),'packaging_enabled')
    RESULT.update(database_tables=len(tables),configuration_rows_roundtrip_exact=True,
                  original_accounts_authenticate=True,signing_keys_and_encrypted_secrets_verified=True,
                  safe_restore_verified=True,database_service_datadir=str(datadir))
    phase('target_storage_and_replay_state')
    for name in ['raw','queue','metrics','archive','backups','database/mysql']:
        path=Path('/srv/fls-server')/name;path.mkdir(parents=True,exist_ok=True)
    Path('/srv/fls-server').chmod(0o755)
    for name in ['raw','queue','metrics']:
        path=Path('/srv/fls-server')/name;shutil.chown(path,user='syslog',group='adm');path.chmod(0o750)
    shutil.chown('/srv/fls-server/archive',user='fls-integrity',group='adm')
    Path('/srv/fls-server/archive').chmod(0o750)
    Path('/srv/fls-server/archive/manifests').mkdir(mode=0o750,exist_ok=True)
    shutil.chown('/srv/fls-server/archive/manifests',user='fls-integrity',group='fls-integrity')
    Path('/srv/fls-server/backups').chmod(0o700)
    for name in ['raw','metrics','archive','archive/manifests']:
        run(['setfacl','-m','u:fls-web:r-x','/srv/fls-server/'+name])
    for path in ['/var/lib/fls-maintenance','/var/lib/fls-power']:
        Path(path).mkdir(mode=0o700,exist_ok=True);Path(path).chmod(0o700)
    marker=Path('/var/lib/fls-maintenance/paused');marker.touch();marker.chmod(0o600)
    root_uuid=subprocess.check_output(['findmnt','-n','-o','UUID','-T','/'],text=True).strip()
    (Path('/etc/fls')/'storage.json').write_text(json.dumps({'schema':1,'mode':'system-root',
                     'root_uuid':root_uuid,'device_wwn':'0x5000000000000001'}))
    Path('/etc/fls/storage.json').chmod(0o644)
    (Path('/etc/fls')/'mirror.json').unlink(missing_ok=True)
    run(['/usr/bin/python3','/var/www/fls/bin/fls_storage.py'])
    # Use the candidate narrow bootstrap tool; the backup itself stays unchanged.
    shutil.copyfile(SEED/'provision-disk-management.py',WORK/'provision-disk-management.py')
    recovery=load(WORK/'provision-disk-management.py','drill_replay_bootstrap')
    disk_worker=load(Path('/var/www/fls/bin/disk-management-worker.py'),'drill_disk_worker')
    initialize_guest_replay_state(connection,recovery,disk_worker)
    RESULT['storage_identity_guard_verified']=True;RESULT['fresh_replay_state_verified']=True
    phase('real_php_nginx_https_login')
    for path in ['/var/lib/fls','/var/lib/fls/sessions','/var/cache/fls']:
        Path(path).mkdir(mode=0o700,parents=True,exist_ok=True)
        os.chown(path,pwd.getpwnam('fls-web').pw_uid,grp.getgrnam('fls-web').gr_gid)
    Path('/var/lib/fls-recovery-download').mkdir(mode=0o750,exist_ok=True)
    os.chown('/var/lib/fls-recovery-download',0,grp.getgrnam('fls-web').gr_gid)
    Path('/var/lib/fls-recovery-download').chmod(0o750)
    Path('/run/php').mkdir(exist_ok=True)
    run(['php-fpm8.3','-t'])
    run(['systemctl','start','php8.3-fpm.service'])
    instance=json.loads(Path('/etc/fls/instance.json').read_text());hostname=instance['hostname']
    require(re.fullmatch(r'[A-Za-z0-9.-]+',hostname),'hostname_invalid')
    with Path('/etc/hosts').open('a') as hosts:hosts.write('\n127.0.0.1 '+hostname+'\n')
    config=WORK/'nginx.conf'
    config.write_text('user nginx;\npid /run/fls-drill-nginx.pid;\nevents {}\nhttp {\naccess_log off;\nerror_log /root/fls-drill/nginx-error.log;\nserver {\nlisten 127.0.0.1:8443 ssl;\nserver_name '+hostname+';\nssl_certificate /etc/nginx/fls-tls/server.crt;\nssl_certificate_key /etc/nginx/fls-tls/server.key;\nroot /var/www/fls/public;\nindex index.php;\nlocation / { try_files $uri $uri/ /index.php?$query_string; }\nlocation ~ \\.php$ {\ninclude /etc/nginx/fastcgi_params;\nfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\nfastcgi_param HTTPS on;\nfastcgi_pass unix:/run/php/fls.sock;\n}\n}\n}\n')
    run(['nginx','-t','-c',str(config)]);run(['nginx','-c',str(config)])
    # The restored configuration was compared before this disposable guest-only
    # account is added. Existing source users/passwords are never altered.
    password=secrets.token_urlsafe(30)
    hashed=subprocess.check_output(['php','-r','$p=stream_get_contents(STDIN);echo password_hash($p,PASSWORD_ARGON2ID);'],input=password.encode()).decode()
    backup.query(connection,"INSERT INTO fls.users(username,password_hash,role,enabled,must_change,session_version,updated_at) VALUES('fls-drill-admin',%s,'admin',1,0,0,UTC_TIMESTAMP())",(hashed,))
    context=ssl.create_default_context(cafile='/etc/nginx/fls-tls/ca.crt')
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                     urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                     urllib.request.ProxyHandler({}))
    base='https://'+hostname+':8443/'
    page=opener.open(base,timeout=30).read().decode()
    csrf=re.search(r'name="_csrf" value="([a-f0-9]+)"',page)
    require(csrf is not None,'login_csrf_missing')
    data=urllib.parse.urlencode({'mode':'login','_csrf':csrf[1],'username':'fls-drill-admin','password':password}).encode()
    page=opener.open(urllib.request.Request(base,data=data),timeout=30).read().decode()
    require('fls-drill-admin' in page and 'name="mode" value="login"' not in page,'https_login_failed')
    for route in ['system_backups','disk_management','power_status','maintenance_status']:
        value=json.load(opener.open(base+'api.php?route='+route,timeout=30))
        require(isinstance(value,dict) and 'error' not in value,'restored_api_failed')
    require({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'network_isolation_lost')
    RESULT.update(https_certificate_verified=True,php_fpm_and_nginx_running=True,
                  administrator_https_login_verified=True,read_only_admin_api_routes_verified=4,
                  guest_only_test_account_created=True,
                  guest_network_interfaces=['lo'],application_version=Path('/var/www/fls/VERSION').read_text().strip(),ok=True)
    connection.close()


if __name__=='__main__':
    # Reject the host before creating files, installing packages or reaching
    # the guest-only shutdown path, including when this file is run by mistake.
    try:authorize_guest()
    except Exception:
        print('Disposable offline recovery guest required.',file=sys.stderr)
        raise SystemExit(2)
    WORK.mkdir(mode=0o700,exist_ok=True);os.umask(0o077)
    with (WORK/'private.log').open('a',encoding='utf-8') as LOG:
        try:restore()
        except Exception as error:record_failure(error)
        print('FLS_DRILL_RESULT '+json.dumps(RESULT,sort_keys=True),flush=True)
    private_channel=Path('/dev/virtio-ports/fls.drill.private')
    if private_channel.exists():
        with (WORK/'private.log').open('rb') as source,private_channel.open('wb') as target:
            shutil.copyfileobj(source,target)
    subprocess.run(['systemctl','poweroff'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
