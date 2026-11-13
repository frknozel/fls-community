#!/usr/bin/python3
"""Provision only maintenance state/credentials/SQL role. Never starts or stops services."""
import json,os,re,secrets,stat,tempfile
from pathlib import Path
import pymysql

USER='fls_maintenance'

def configure_role(cursor,password,database='fls',user=USER):
    if not all(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_]+',value) for value in (database,user)):raise ValueError('sql_identity')
    if not isinstance(password,str) or not 16<=len(password)<=512:raise ValueError('credential_password')
    cursor.execute('CREATE USER IF NOT EXISTS '+user+'@localhost IDENTIFIED BY %s',(password,));cursor.execute('ALTER USER '+user+'@localhost IDENTIFIED BY %s',(password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM '+user+'@localhost')
    cursor.execute('GRANT SELECT ON '+database+'.maintenance_requests TO '+user+'@localhost')
    cursor.execute('GRANT SELECT,INSERT,UPDATE ON '+database+'.maintenance_state TO '+user+'@localhost')

def configure_app_role(cursor,database='fls',user='fls_app'):
    if not all(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_]+',value) for value in (database,user)):raise ValueError('sql_identity')
    for table in ('maintenance_requests','maintenance_state'):
        cursor.execute('GRANT SELECT ON '+database+'.'+table+' TO '+user+'@localhost')
    cursor.execute('GRANT UPDATE(requested_mode,revision,requested_at,requested_by) ON '+database+'.maintenance_requests TO '+user+'@localhost')

def private_config(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError('credential_permissions')
        value=json.loads(stream.read(16385))
    if set(value)!={'user','password'} or value['user']!=USER or not isinstance(value['password'],str) or not 16<=len(value['password'])<=512:raise ValueError('credential_identity')
    return value

def write_new(path,value):
    fd,temp=tempfile.mkstemp(prefix='.maintenance-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(value,stream);stream.write('\n');stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o600);os.fchown(stream.fileno(),0,0)
        # Link provides no-clobber publication, including a newly appearing symlink.
        os.link(temp,path,follow_symlinks=False)
        os.unlink(temp);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        try:os.unlink(temp)
        except FileNotFoundError:pass

def main():
    if os.geteuid()!=0:raise SystemExit('Root required')
    parent=Path('/etc/fls');info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('credential_parent')
    path=parent/'maintenance-database.json';value=private_config(path) if path.exists() or path.is_symlink() else {'user':USER,'password':secrets.token_urlsafe(36)}
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
    try:
        with db.cursor() as cursor:
            configure_role(cursor,value['password']);configure_app_role(cursor)
    finally:db.close()
    if not path.exists():write_new(path,value)
    state=Path('/var/lib/fls-maintenance')
    if not state.exists():state.mkdir(mode=0o700)
    info=state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('state_permissions')
    print(json.dumps({'credential_created_or_verified':True,'sql_user':USER,'services_started':False,'collection_changed':False}))
if __name__=='__main__':main()
