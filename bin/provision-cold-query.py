#!/usr/bin/python3
"""Provision only the cold query identity, scoped reader and private cache. No service start."""
import grp
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import pymysql

USER='fls-cold-query'
SQL_USER='fls_cold_query'
CREDENTIAL=Path('/etc/fls/cold-query.json')
CACHE=Path('/var/cache/fls-cold-query')
DETAILED=Path('/srv/fls-server/archive/detailed')
READ_TABLES=('cold_snapshots','cold_snapshot_devices')
COLUMN_GRANTS={
 'users':('id','enabled','session_version'),
 'fortigate_connections':('id','serial','vdom'),
 'user_fortigate_access':('user_id','connection_id'),
}

def command(args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)

def directory(path,owners=(0,)):
 s=Path(path).lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid not in owners or s.st_mode&0o022:raise ValueError('unsafe_directory')

def directory_fd(path,owners=(0,),parent_fd=None):
 """Pin the directory inode before granting access to a mutable subtree."""
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
 try:
  s=os.fstat(fd)
  if not stat.S_ISDIR(s.st_mode) or s.st_uid not in owners or s.st_mode&0o022:raise ValueError('unsafe_directory')
  return fd
 except BaseException:
  os.close(fd);raise

def acl_fd(fd,acl):
 # Keep the existing mask: adding this reader must not activate latent rights
 # of another named user/group. /proc resolves only the inherited pinned fd.
 subprocess.run(['setfacl','--no-mask','-m',acl,'/proc/self/fd/'+str(fd)],pass_fds=(fd,),check=True,stdout=subprocess.DEVNULL)

def detailed_acls(archive_fd,detailed_fd,owners,user=USER):
 """Grant only pinned detailed-copy inodes; never follow mutable pathnames."""
 acl_fd(archive_fd,'u:'+user+':--x')
 def walk_error(error):raise error
 for current,dirs,files,fd in os.fwalk('.',dir_fd=detailed_fd,follow_symlinks=False,onerror=walk_error):
  s=os.fstat(fd)
  if not stat.S_ISDIR(s.st_mode) or s.st_uid not in owners or s.st_mode&0o022:raise ValueError('unsafe_detailed_entry')
  acl_fd(fd,'u:'+user+':r-x,d:u:'+user+':r-x')
  for name in dirs:
   if not stat.S_ISDIR(os.stat(name,dir_fd=fd,follow_symlinks=False).st_mode):raise ValueError('unsafe_detailed_entry')
  for name in files:
   item_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
   try:
    entry=os.fstat(item_fd)
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink!=1:raise ValueError('unsafe_detailed_entry')
    acl_fd(item_fd,'u:'+user+':r--')
   finally:os.close(item_fd)

def read_existing():
 fd=os.open(CREDENTIAL,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&0o077 or not 0<s.st_size<=16384:raise ValueError('credential_permissions')
  config=json.loads(f.read(16385))
 if set(config)!={'user','password'} or config['user']!=SQL_USER or not isinstance(config['password'],str) or not 16<=len(config['password'])<=512:raise ValueError('credential_invalid')
 return config

def main():
 if os.geteuid()!=0:raise SystemExit('Root required')
 for path in ['/etc/fls','/var/cache','/srv/fls-server','/srv/fls-server/archive']:directory(path)
 try:account=pwd.getpwnam(USER)
 except KeyError:
  command(['useradd','--system','--user-group','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',USER]);account=pwd.getpwnam(USER)
 memberships={g.gr_name for g in grp.getgrall() if USER in g.gr_mem}|{grp.getgrgid(account.pw_gid).gr_name}
 if account.pw_shell!='/usr/sbin/nologin' or account.pw_uid==0 or 'fls-web' in memberships or 'adm' in memberships or account.pw_gid!=grp.getgrnam(USER).gr_gid:raise ValueError('unsafe_service_identity')
 pwd.getpwnam('fls-web')
 if CACHE.is_symlink():raise ValueError('unsafe_cache')
 CACHE.mkdir(mode=0o700,exist_ok=True)
 info=CACHE.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,account.pw_uid):raise ValueError('unsafe_cache')
 os.chown(CACHE,account.pw_uid,account.pw_gid);os.chmod(CACHE,0o700)
 config=read_existing() if CREDENTIAL.exists() or CREDENTIAL.is_symlink() else {'user':SQL_USER,'password':secrets.token_urlsafe(36)}
 db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
 try:
  with db.cursor() as c:
   c.execute('CREATE USER IF NOT EXISTS fls_cold_query@localhost IDENTIFIED BY %s',(config['password'],))
   # Recover safely if an earlier run created the SQL user but stopped before
   # publishing its root-only credential file. This role belongs only to FLS.
   c.execute('ALTER USER fls_cold_query@localhost IDENTIFIED BY %s',(config['password'],))
   # This identity belongs exclusively to this component; no hot table, key,
   # administrative, filesystem or cross-database privileges are retained.
   c.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM fls_cold_query@localhost')
   for table in READ_TABLES:c.execute('GRANT SELECT ON fls.'+table+' TO fls_cold_query@localhost')
   for table,columns in COLUMN_GRANTS.items():c.execute('GRANT SELECT('+','.join(columns)+') ON fls.'+table+' TO fls_cold_query@localhost')
   c.execute('GRANT INSERT,UPDATE ON fls.cold_snapshot_devices TO fls_cold_query@localhost')
   c.execute('GRANT SELECT ON fls.cold_snapshot_devices TO fls_app@localhost')
 finally:db.close()
 if not CREDENTIAL.exists():
  fd=os.open(CREDENTIAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.write((json.dumps(config)+'\n').encode());f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o600);os.fchown(f.fileno(),0,0)
 # Only the detailed-copy subtree receives read/traverse ACLs. Neither adm
 # membership nor /etc/fls/raw/database/private-key ACLs are introduced.
 owners=(0,pwd.getpwnam('fls-cold').pw_uid)
 archive_fd=directory_fd(DETAILED.parent)
 try:
  detailed_fd=directory_fd(DETAILED.name,owners=owners,parent_fd=archive_fd)
  try:detailed_acls(archive_fd,detailed_fd,owners)
  finally:os.close(detailed_fd)
 finally:os.close(archive_fd)
 print(json.dumps({'service_user':USER,'sql_user':SQL_USER,'cache_budget_bytes':2*1024**3,'services_started':False,'hot_data_privileges':False,'private_key_access':False}))

if __name__=='__main__':main()
