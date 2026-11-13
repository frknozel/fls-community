#!/usr/bin/python3
"""Provision only the local certificate-history identity. Never prints its password."""
import json,os,pwd,secrets,subprocess,tempfile
from pathlib import Path
import pymysql
if os.geteuid()!=0:raise SystemExit('Run as root after migration 030')
try:pwd.getpwnam('fls-tls-history')
except KeyError:subprocess.run(['useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','fls-tls-history'],check=True)
path=Path('/etc/fls/archive-tls-history.json');new=not path.exists();config=json.loads(path.read_text()) if not new else {'user':'fls_tls_history','password':secrets.token_urlsafe(36)}
if config['user']!='fls_tls_history':raise SystemExit('Unexpected history database identity')
db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
try:
 with db.cursor() as c:
  if new:
   c.execute("SELECT COUNT(*) FROM mysql.user WHERE User='fls_tls_history' AND Host='localhost'")
   if c.fetchone()[0]:raise SystemExit('History identity exists without its credential file. Restore the credential first.')
 if new:
  fd,temp=tempfile.mkstemp(prefix='.tls-history-',dir=path.parent)
  try:
   with os.fdopen(fd,'w') as f:f.write(json.dumps(config)+'\n');f.flush();os.fsync(f.fileno())
   os.chmod(temp,0o600);os.replace(temp,path)
  finally:Path(temp).unlink(missing_ok=True)
 else:path.chmod(0o600)
 with db.cursor() as c:
  c.execute('CREATE USER IF NOT EXISTS %s@localhost IDENTIFIED BY %s',(config['user'],config['password']))
  columns='id,name,host,port,revision,enabled,protocol,tls_peer_pem,tls_peer_revision,tls_peer_checked_at,tls_peer_verified_at,tls_peer_check_code'
  c.execute('GRANT SELECT('+columns+') ON fls.archive_destinations TO fls_tls_history@localhost')
  c.execute('GRANT SELECT ON fls.archive_tls_settings TO fls_tls_history@localhost')
  for table in ['archive_tls_alert_history','archive_tls_history_state']:c.execute('GRANT SELECT,INSERT,UPDATE ON fls.'+table+' TO fls_tls_history@localhost')

finally:db.close()
print('Certificate history identity ready; no log, destination secret or network access granted.')
