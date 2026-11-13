#!/usr/bin/python3
"""Prepare only the dedicated historical verifier. Never starts a service."""
import json,os,pwd,re,secrets,stat,subprocess
from pathlib import Path
import pymysql

DEFAULTS={'max_bytes':536870912,'max_seconds':45,'read_bytes_per_second':8388608,'target_age_days':30}
def configure_role(cursor,password,database='fls',user='fls_scrub'):
    if not all(re.fullmatch(r'[A-Za-z0-9_]+',x) for x in (database,user)):raise ValueError('sql_identity')
    if not isinstance(password,str) or not 16<=len(password)<=512:raise ValueError('credential_password')
    cursor.execute('CREATE USER IF NOT EXISTS '+user+'@localhost IDENTIFIED BY %s',(password,))
    cursor.execute('ALTER USER '+user+'@localhost IDENTIFIED BY %s',(password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM '+user+'@localhost')
    cursor.execute('GRANT SELECT ON '+database+'.archive_manifests TO '+user+'@localhost')
    cursor.execute('GRANT UPDATE(status,verified_at) ON '+database+'.archive_manifests TO '+user+'@localhost')
    for table in ('archive_integrity_checks','archive_integrity_worker'):
        cursor.execute('GRANT SELECT,INSERT,UPDATE ON '+database+'.'+table+' TO '+user+'@localhost')

def private_config(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&0o077 or s.st_size>16384:raise ValueError('credential_permissions')
        value=json.loads(f.read(16385))
    if value.get('user')!='fls_scrub' or not isinstance(value.get('password'),str) or not 16<=len(value['password'])<=512:raise ValueError('credential_identity')
    return value

def acl_fd(path,permissions,directory=False,default=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_DIRECTORY if directory else 0))
    try:
        s=os.fstat(fd)
        if directory and not stat.S_ISDIR(s.st_mode) or not directory and not stat.S_ISREG(s.st_mode):raise ValueError('acl_target_type')
        access='u:fls-scrub:'+permissions
        if default:access+=',d:u:fls-scrub:'+permissions
        subprocess.run(['setfacl','--no-mask','-m',access,'--','/proc/self/fd/'+str(fd)],pass_fds=(fd,),check=True)
    finally:os.close(fd)

def main():
    if os.geteuid()!=0:raise SystemExit('Root required')
    helper=Path('/usr/lib/fls/fls-archive-hash')
    st=helper.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or not os.access(helper,os.X_OK):raise ValueError('trusted_hash_helper_required')
    for name in ['/etc/fls','/var/lib','/srv/fortigate','/srv/fortigate/raw','/srv/fortigate/archive','/srv/fortigate/archive/manifests']:
        p=Path(name);s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_mode&0o002:raise ValueError('unsafe_parent_directory')
    try:account=pwd.getpwnam('fls-scrub')
    except KeyError:
        subprocess.run(['useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','fls-scrub'],check=True);account=pwd.getpwnam('fls-scrub')
    if account.pw_uid==0 or account.pw_shell!='/usr/sbin/nologin':raise ValueError('worker_account')
    if set(os.getgrouplist('fls-scrub',account.pw_gid))!={account.pw_gid}:raise ValueError('unexpected_supplementary_groups')
    config_path=Path('/etc/fls/integrity-scrub.json')
    config=private_config(config_path) if config_path.exists() or config_path.is_symlink() else {'user':'fls_scrub','password':secrets.token_urlsafe(36),**DEFAULTS}
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
    try:
        with db.cursor() as c:
            configure_role(c,config['password'])
            for table in ('archive_integrity_checks','archive_integrity_worker'):
                c.execute('GRANT SELECT ON fls.'+table+' TO fls_app@localhost')
            c.execute('GRANT SELECT,INSERT,UPDATE ON fls.archive_integrity_checks TO fls_seal@localhost')
    finally:db.close()
    if not config_path.exists():
        fd=os.open(config_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(config,f);f.write('\n');f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o600)
    state=Path('/var/lib/fls-integrity-scrub')
    if not state.exists():state.mkdir(mode=0o700)
    s=state.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0,account.pw_uid) or s.st_mode&0o077:raise ValueError('unsafe_state_directory')
    os.chown(state,account.pw_uid,account.pw_gid);os.chmod(state,0o700)
    # Pin every target FD: a path replacement cannot grant access to an outside
    # symlink target. The raw collector's default ACL covers future hourly files.
    acl_fd('/srv/fortigate','--x',directory=True)
    acl_fd('/srv/fortigate/archive','--x',directory=True)
    for directory,pattern in [('/srv/fortigate/raw','*.jsonl'),('/srv/fortigate/archive/manifests','*.manifest.json')]:
        acl_fd(directory,'r-x',directory=True,default=True)
        for p in Path(directory).glob(pattern):acl_fd(p,'r--')
    if subprocess.run(['runuser','-u','fls-scrub','--','test','-r','/etc/fls/private/archive-ed25519.pem']).returncode==0:raise ValueError('worker_must_not_read_signing_key')
    print(json.dumps({'worker_account':'fls-scrub','sql_user':'fls_scrub','private_signing_key_access':False,'services_started':False,'original_data_changed':False}))
if __name__=='__main__':main()
