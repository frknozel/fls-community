#!/usr/bin/python3
"""Provision only the new scoped cold-copy worker. Does not migrate or restart anything."""
import json,os,pwd,re,secrets,stat,subprocess,tempfile
from pathlib import Path
import pymysql
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

READ_TABLES=('source_files','events','event_notes','av_event_groups','security_event_groups','traffic_event_groups','traffic_groups','mail_search_events','archive_event_index','archive_dimensions','archive_index_state','mail_search_state','archive_manifests','retention_settings')
def configure_worker_role(cursor,password,database='fls',sql_user='fls_cold'):
    if not all(re.fullmatch(r'[A-Za-z0-9_]+',value) for value in (database,sql_user)):raise ValueError('sql_identity')
    if not isinstance(password,str) or not 16<=len(password)<=512:raise ValueError('credential_password')
    cursor.execute('CREATE USER IF NOT EXISTS '+sql_user+'@localhost IDENTIFIED BY %s',(password,))
    # If a crash happened before the credential file was published, the next
    # run must synchronize this dedicated role with the newly generated secret.
    cursor.execute('ALTER USER '+sql_user+'@localhost IDENTIFIED BY %s',(password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM '+sql_user+'@localhost')
    for table in READ_TABLES:cursor.execute('GRANT SELECT ON '+database+'.'+table+' TO '+sql_user+'@localhost')
    for table in ('cold_snapshots','cold_storage_worker'):cursor.execute('GRANT SELECT,INSERT,UPDATE ON '+database+'.'+table+' TO '+sql_user+'@localhost')
def existing(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&0o077 or s.st_size>16384:raise ValueError('existing_private_file_permissions')
        return f.read(16385)
def write_new(path,data,mode):
    path=Path(path)
    if path.exists() or path.is_symlink():raise ValueError('refuse_existing_file')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode);os.fchown(f.fileno(),0,0)
def main():
    if os.geteuid()!=0:raise SystemExit('Root required')
    for parent in [Path('/etc/fls'),Path('/srv/fls-server/archive')]:
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('unsafe_parent_directory')
    try:account=pwd.getpwnam('fls-cold')
    except KeyError:
        subprocess.run(['useradd','--system','--user-group','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','fls-cold'],check=True);account=pwd.getpwnam('fls-cold')
    if account.pw_shell!='/usr/sbin/nologin':raise ValueError('worker_account_shell')
    pwd.getpwnam('fls-web')
    private=Path('/etc/fls/cold-signing-key.pem');public=Path('/etc/fls/cold-public-key.pem')
    if private.exists() or private.is_symlink():key=serialization.load_pem_private_key(existing(private),password=None)
    else:
        key=Ed25519PrivateKey.generate();write_new(private,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),0o600)
    if not isinstance(key,Ed25519PrivateKey):raise ValueError('key_algorithm')
    pub=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    if public.exists() or public.is_symlink():
        info=public.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or public.read_bytes()!=pub:raise ValueError('existing_public_key_mismatch')
    else:write_new(public,pub,0o644)
    credential=Path('/etc/fls/cold-storage.json');config=json.loads(existing(credential)) if credential.exists() or credential.is_symlink() else {'user':'fls_cold','password':secrets.token_urlsafe(36)}
    if config.get('user')!='fls_cold' or not isinstance(config.get('password'),str):raise ValueError('credential_user')
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
    try:
        with db.cursor() as c:
            configure_worker_role(c,config['password'])
            for table in ['cold_snapshots','cold_storage_worker']:
                c.execute('GRANT SELECT ON fls.'+table+' TO fls_app@localhost')
    finally:db.close()
    if not credential.exists():write_new(credential,(json.dumps(config)+'\n').encode(),0o600)
    target=Path('/srv/fls-server/archive/detailed')
    if target.is_symlink():raise ValueError('unsafe_detailed_directory')
    target.mkdir(mode=0o750,exist_ok=True)
    info=target.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,account.pw_uid):raise ValueError('unsafe_detailed_directory')
    os.chown(target,account.pw_uid,account.pw_gid);os.chmod(target,0o750)
    subprocess.run(['setfacl','-m','u:fls-web:r-x,d:u:fls-web:r-x,d:u::rwx,d:g::r-x,d:o::---',str(target)],check=True)
    print(json.dumps({'worker_account':'fls-cold','sql_user':'fls_cold','dedicated_signing_key':True,'copy_only':True,'services_started':False,'old_data_changed':False}))
if __name__=='__main__':main()
