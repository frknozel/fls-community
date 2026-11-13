#!/usr/bin/python3
"""Dedicated history writer; no original logs/settings/notes access or secrets output."""
import json,os,secrets,tempfile
from pathlib import Path
import pymysql
def main():
    path=Path('/etc/fls/mail-search-backlog-history.json');config=json.loads(path.read_text()) if path.exists() else {'user':'fls_mail_backlog_history','password':secrets.token_urlsafe(36)}
    if config.get('user')!='fls_mail_backlog_history':raise SystemExit('Unexpected history user')
    if not isinstance(config.get('password'),str) or not 16<=len(config['password'])<=512:raise ValueError('credential_password')
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
    try:
        with db.cursor() as c:
            c.execute('CREATE USER IF NOT EXISTS fls_mail_backlog_history@localhost IDENTIFIED BY %s',(config['password'],))
            c.execute('ALTER USER fls_mail_backlog_history@localhost IDENTIFIED BY %s',(config['password'],))
            for table in ['mail_search_backlog_incidents','mail_search_backlog_history_state']:c.execute('GRANT SELECT,INSERT,UPDATE ON fls.'+table+' TO fls_mail_backlog_history@localhost')
        fd,tmp=tempfile.mkstemp(prefix='.backlog-history-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as f:json.dump(config,f);f.write('\n');f.flush();os.fsync(f.fileno())
            os.chmod(tmp,0o600);os.chown(tmp,0,0);os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    finally:db.close()
    print('Scoped mail-search backlog history writer ready')
if __name__=='__main__':main()
