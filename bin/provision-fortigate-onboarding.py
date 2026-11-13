#!/usr/bin/python3
"""Create only the onboarding SQL role and root-private credentials. No service restart."""
import json,os,secrets,tempfile
from pathlib import Path
import pymysql

def main():
    path=Path('/etc/fls/onboarding-database.json');config=json.loads(path.read_text()) if path.exists() else {'user':'fls_onboarding','password':secrets.token_urlsafe(36)}
    if config.get('user')!='fls_onboarding':raise ValueError('unexpected_user')
    if not isinstance(config.get('password'),str) or not 16<=len(config['password'])<=512:raise ValueError('credential_password')
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True)
    try:
        with db.cursor() as c:
            c.execute('CREATE USER IF NOT EXISTS fls_onboarding@localhost IDENTIFIED BY %s',(config['password'],))
            c.execute('ALTER USER fls_onboarding@localhost IDENTIFIED BY %s',(config['password'],))
            c.execute('GRANT SELECT(connection_id,revision,peer_ip,receiver_admitted,baseline_event_id,test_started_at) ON fls.fortigate_setup TO fls_onboarding@localhost')
            c.execute('GRANT SELECT(id,serial,vdom) ON fls.fortigate_connections TO fls_onboarding@localhost')
            c.execute('GRANT SELECT(id,devid,vd,received_at,event_at,file_id,byte_offset,byte_length,raw_sha256) ON fls.events TO fls_onboarding@localhost')
            c.execute('GRANT SELECT(id,name) ON fls.source_files TO fls_onboarding@localhost')
            for table in ['fortigate_setup_receipts','fortigate_setup_state']:c.execute('GRANT SELECT,INSERT,UPDATE ON fls.'+table+' TO fls_onboarding@localhost')
            c.execute('GRANT INSERT,UPDATE ON fls.fortigate_setup TO fls_app@localhost')
        fd,tmp=tempfile.mkstemp(prefix='.onboarding-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as f:json.dump(config,f);f.write('\n');f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o600);os.fchown(f.fileno(),0,0)
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    finally:db.close()
    print('Scoped onboarding role ready')
if __name__=='__main__':main()
