#!/usr/bin/env python3
"""Opt-in MariaDB integration fixture. Always new /tmp datadir, no TCP networking.

No connection target option exists. Does not install packages or use systemd.
--mariadb-prefix is an extracted Ubuntu package prefix containing bin/ and sbin/.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
TREE=ROOT/'tools/community/overlay' if (ROOT/'tools/community/overlay/bin/community_install.py').is_file() else ROOT


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run_fixture(prefix):
    import pymysql
    if os.geteuid()!=0:raise ValueError('fixture_requires_root_for_private_socket_auth')
    prefix=prefix.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='fls-community-sql-') as td:
        p=Path(td);data=p/'data';data.mkdir();socket=p/'mysql.sock'
        with (p/'init.log').open('wb') as log:
            subprocess.run([str(prefix/'bin/mariadb-install-db'),'--no-defaults','--basedir='+str(prefix),'--datadir='+str(data),'--user=root','--auth-root-authentication-method=socket','--skip-test-db'],stdout=log,stderr=log,check=True,timeout=120)
        with (p/'server.log').open('wb') as log:
            process=subprocess.Popen([str(prefix/'sbin/mariadbd'),'--no-defaults','--basedir='+str(prefix),'--datadir='+str(data),'--socket='+str(socket),'--pid-file='+str(p/'pid'),'--skip-networking','--user=root','--innodb-buffer-pool-size=128M','--log-error='+str(p/'error.log')],stdout=log,stderr=log)
            try:
                for attempt in range(100):
                    if process.poll() is not None:raise RuntimeError('private_fixture_daemon_failed')
                    try:connection=pymysql.connect(unix_socket=str(socket),user='root',autocommit=True);break
                    except pymysql.MySQLError:time.sleep(.1)
                else:raise RuntimeError('private_fixture_start_timeout')
                with connection.cursor() as cursor:
                    cursor.execute('SELECT VERSION()');version=cursor.fetchone()[0]
                    assert version.startswith('10.11.'), 'expected_stock_mariadb_10_11'
                    schema=(TREE/'schema.sql').read_text()
                    for repetition in range(2):
                        for statement in schema.split(';'):
                            if statement.strip():cursor.execute(statement)
                    cursor.execute('SHOW TABLES FROM fls');count=len(cursor.fetchall());assert count==80
                    cursor.execute('SELECT COUNT(*) FROM fls.events');assert cursor.fetchone()[0]==0
                    sys.path.insert(0,str(TREE/'bin'))
                    installer=load(TREE/'bin/community_install.py','schema_install_fixture')
                    credentials={}
                    class Roles(installer.HostOps):
                        def credential(self,cursor,user,filename,**unused):
                            password='fixture-only-'+user;credentials[user]=password
                            cursor.execute('CREATE USER %s@localhost IDENTIFIED BY %s',(user,password))
                            return password
                    Roles().base_roles(cursor)
                    for index,(name,filename,user,function) in enumerate(installer.ROLE_HELPERS):
                        path=TREE/'bin'/name
                        if not path.is_file():path=ROOT/'bin'/name
                        module=load(path,'schema_role_fixture_'+str(index))
                        getattr(module,function)(cursor,'fixture-only-'+user)
                        if name=='provision-maintenance.py':module.configure_app_role(cursor)
                    cursor.execute('SELECT COUNT(*) FROM mysql.user WHERE user LIKE \'fls%\'');roles=cursor.fetchone()[0]
                    assert roles>=17
                    cursor.execute('USE fls')
                    cursor.execute("INSERT INTO source_files(name,inode) VALUES('fixture.jsonl',10)")
                for user,sql,allowed in (
                    ('fls_app','DELETE FROM fls.events',False),
                    ('fls_app','UPDATE fls.source_files SET inode=20',False),
                    ('fls_disks','UPDATE fls.source_files SET inode=20',True),
                    ('fls_disks','DELETE FROM fls.events',False),
                    ('fls_export','UPDATE fls.archive_destinations SET enabled=0',False),
                    ('fls_export','UPDATE fls.archive_destinations SET check_status=\'unknown\'',True),
                ):
                    account=pymysql.connect(unix_socket=str(socket),user=user,password=credentials.get(user,'fixture-only-'+user),autocommit=True)
                    try:
                        try:
                            with account.cursor() as cursor:cursor.execute(sql)
                        except pymysql.MySQLError as error:
                            assert not allowed,(user,error.args[0]);assert error.args[0] in (1142,1143),error.args[0]
                        else:assert allowed,user
                    finally:account.close()
                connection.close()
                return {'ok':True,'version':version,'tables':count,'roles':roles,'schema_reapply':True,'scoped_permissions':True,'network_disabled':True,'live_database_used':False}
            finally:
                process.terminate()
                try:process.wait(timeout=20)
                except subprocess.TimeoutExpired:process.kill();process.wait()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mariadb-prefix',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(run_fixture(args.mariadb_prefix)))

if __name__=='__main__':main()
