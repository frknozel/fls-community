#!/usr/bin/python3
"""Idempotent, narrow read-only telemetry role. Run as root; prints no secrets."""
import json,os,secrets,tempfile
from pathlib import Path
import pymysql

def main():
    path=Path('/etc/fls/telemetry.json')
    config=json.loads(path.read_text()) if path.exists() else {'user':'fls_telemetry','password':secrets.token_urlsafe(36)}
    if config.get('user')!='fls_telemetry':raise SystemExit('Unexpected telemetry credential user')
    if not isinstance(config.get('password'),str) or not 16<=len(config['password'])<=512:raise ValueError('credential_password')
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
    try:
        with db.cursor() as c:
            c.execute('CREATE USER IF NOT EXISTS fls_telemetry@localhost IDENTIFIED BY %s',(config['password'],))
            c.execute('ALTER USER fls_telemetry@localhost IDENTIFIED BY %s',(config['password'],))
            c.execute('GRANT SELECT(id) ON fls.events TO fls_telemetry@localhost')
            c.execute('GRANT SELECT ON fls.archive_index_state TO fls_telemetry@localhost')
            c.execute('GRANT SELECT ON fls.mail_search_state TO fls_telemetry@localhost')
            c.execute('GRANT SELECT ON fls.summary_backlog_settings TO fls_telemetry@localhost')
            c.execute('GRANT SELECT ON fls.mail_search_backlog_settings TO fls_telemetry@localhost')
        fd,tmp=tempfile.mkstemp(prefix='.telemetry-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as f:json.dump(config,f);f.write('\n');f.flush();os.fsync(f.fileno())
            os.chmod(tmp,0o600);os.chown(tmp,0,0);os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    finally:db.close()
    print('Read-only summary telemetry credential ready')

if __name__=='__main__':main()
