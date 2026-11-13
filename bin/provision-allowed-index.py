#!/usr/bin/python3
"""Prepare only the derived allowed-evidence worker. Defaults to a non-mutating plan."""
import argparse,json,os,pwd,re,secrets,stat,subprocess
from pathlib import Path
import pymysql

USER='fls-allowed'
SQL_USER='fls_allowed'
TABLES=('allowed_dimensions','allowed_event_index','allowed_hour_counts','allowed_index_state')
EVENT_COLUMNS=('id','event_at','type','subtype','action','outcome','rating_error','policyid','poluuid','profile','srcip','dstip','dstport','hostname','app','category','devid','vd','fields')

def configure_role(cursor,password,database='fls',user=SQL_USER):
    if not all(re.fullmatch(r'[A-Za-z0-9_]+',value) for value in (database,user)):raise ValueError('sql_identity')
    if not isinstance(password,str) or not 16<=len(password)<=512:raise ValueError('credential_password')
    # Existing passwords are never rotated by this narrowly scoped provisioner.
    cursor.execute('CREATE USER IF NOT EXISTS '+user+'@localhost IDENTIFIED BY %s',(password,))
    cursor.execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM '+user+'@localhost')
    cursor.execute('GRANT SELECT('+','.join(EVENT_COLUMNS)+') ON '+database+'.events TO '+user+'@localhost')
    for table in ('allowed_dimensions','allowed_event_index'):cursor.execute('GRANT SELECT,INSERT ON '+database+'.'+table+' TO '+user+'@localhost')
    cursor.execute('GRANT SELECT,INSERT,UPDATE ON '+database+'.allowed_hour_counts TO '+user+'@localhost')
    cursor.execute('GRANT SELECT,UPDATE ON '+database+'.allowed_index_state TO '+user+'@localhost')

def read_config(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>16384:raise ValueError('credential_permissions')
        value=json.loads(stream.read(16385))
    if set(value)!=set(('user','password')) or value.get('user')!=SQL_USER or not isinstance(value.get('password'),str) or not 16<=len(value['password'])<=512:raise ValueError('credential_identity')
    return value

def write_new(path,content):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(content);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o600);os.fchown(stream.fileno(),0,0)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent)
    finally:os.close(parent)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');parser.add_argument('--start',action='store_true');args=parser.parse_args()
    if args.start and not args.apply:parser.error('--start requires --apply')
    if not args.apply:
        print(json.dumps({'applied':False,'worker_account':USER,'sql_user':SQL_USER,'tables':TABLES,'services_started':False,'original_data_changed':False,'credential_rotation':False}));return
    if os.geteuid()!=0:raise SystemExit('Root required for --apply')
    root=Path(__file__).resolve().parents[1]
    parent=Path('/etc/fls');info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('credential_parent')
    try:account=pwd.getpwnam(USER)
    except KeyError:
        subprocess.run(['useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',USER],check=True);account=pwd.getpwnam(USER)
    if account.pw_uid==0 or account.pw_shell!='/usr/sbin/nologin' or set(os.getgrouplist(USER,account.pw_gid))!={account.pw_gid}:raise ValueError('worker_account')
    path=parent/'allowed-index.json';existing=path.exists() or path.is_symlink()
    config=read_config(path) if existing else {'user':SQL_USER,'password':secrets.token_urlsafe(36)}
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',database='fls',autocommit=True)
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User=%s AND Host='localhost'",(SQL_USER,))
            sql_exists=bool(cursor.fetchone()[0])
            if sql_exists and not existing:raise ValueError('existing_sql_account_without_credential')
            if sql_exists:
                check=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=SQL_USER,password=config['password']);check.close()
            migration=(root/'migrations/043-allowed-traffic.sql').read_text()
            for statement in '\n'.join(line for line in migration.splitlines() if not line.lstrip().startswith('--')).split(';'):
                if statement.strip():cursor.execute(statement)
            configure_role(cursor,config['password'])
            for table in TABLES:cursor.execute('GRANT SELECT ON fls.'+table+' TO fls_app@localhost')
        if not existing:write_new(path,(json.dumps(config)+'\n').encode())
    finally:db.close()
    unit=Path('/etc/systemd/system/fls-allowed-index.service')
    if unit.is_symlink():raise ValueError('unit_symlink')
    subprocess.run(['install','-o','root','-g','root','-m','0644',str(root/'deploy/fls-allowed-index.service'),str(unit)],check=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    if args.start:subprocess.run(['systemctl','enable','--now','fls-allowed-index.service'],check=True)
    print(json.dumps({'applied':True,'worker_account':USER,'sql_user':SQL_USER,'services_started':args.start,'original_data_changed':False,'credential_rotation':False}))

if __name__=='__main__':main()
