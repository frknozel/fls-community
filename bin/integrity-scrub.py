#!/usr/bin/python3
"""One public-key-only, resumable archive scrub pass. Never signs or removes logs."""
import fcntl
import json
import logging
import os
from pathlib import Path
import stat
import sys

import pymysql
from integrity_scrub import IntegrityError,Store,load_config,load_public,run_scrub

STATE=Path('/var/lib/fls-integrity-scrub')

def main():
    logging.basicConfig(level=logging.INFO)
    credentials=os.environ.get('CREDENTIALS_DIRECTORY')
    config=load_config(Path(credentials)/'integrity-scrub.json' if credentials else Path('/etc/fls/integrity-scrub.json'))
    info=STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise IntegrityError('state_permissions')
    lock=os.open(STATE/'worker.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077:raise IntegrityError('lock_permissions')
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'status':'busy'}));return 0
        public=load_public('/var/www/fls/public/archive-public-key.pem')
        db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',charset='utf8mb4',autocommit=False,connect_timeout=5,read_timeout=10,write_timeout=10)
        try:result=run_scrub(Store(db),public,Path('/srv/fortigate/raw'),Path('/srv/fortigate/archive/manifests'),STATE,Path('/usr/lib/fls/fls-archive-hash'),config)
        finally:db.close()
        print(json.dumps(result));return 0 if result['status']!='failed' else 1
    finally:os.close(lock)

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        # Stable diagnostics only: no credentials, paths, raw data or exception text.
        print(json.dumps({'status':'failed','error_code':exc.code if isinstance(exc,IntegrityError) else 'worker_failed'}))
        raise SystemExit(1)
