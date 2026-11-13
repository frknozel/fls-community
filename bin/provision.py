#!/usr/bin/python3
"""Run once as root after package installation. Never prints credentials."""
import argparse,datetime,json,os,pwd,secrets,shutil,subprocess
from product_config import load as load_instance
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pymysql

# The historical bootstrap must never run as an upgrade or against an initialized appliance.
parser=argparse.ArgumentParser(description='Legacy fresh-install bootstrap; use product-preflight.py first')
parser.add_argument('--apply-new-install',action='store_true');parser.add_argument('--config')
options=parser.parse_args()
if not options.apply_new_install or not options.config:raise SystemExit('Explicit --apply-new-install --config is required; existing installations must use migrations.')
instance=load_instance(options.config)
if Path('/etc/fls/app.json').exists() or Path('/etc/fls/private/archive-ed25519.pem').exists():raise SystemExit('An existing installation cannot be bootstrapped again.')
if not os.access('/usr/lib/fls/fls-archive-hash',os.X_OK):raise SystemExit('Install the compiled fls-archive-hash helper before the fresh-install bootstrap.')

def run(*a,**kw): return subprocess.run(a,check=True,**kw)
def put(path,text,mode=0o644,group=None):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);p.chmod(mode)
    if group: shutil.chown(p,group=group)

for name in ['fls-web','fls-index','fls-integrity','fls-search']:
    try: pwd.getpwnam(name)
    except KeyError: run('useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name)
run('usermod','-a','-G','adm','fls-index')
run('usermod','-a','-G','adm','fls-integrity')
for path,owner,mode in [('/etc/fls','root',0o755),('/etc/fls/private','fls-integrity',0o700),('/var/lib/fls','fls-web',0o700),('/var/lib/fls/sessions','fls-web',0o700),('/var/cache/fls','fls-web',0o700),('/srv/fortigate/archive/manifests','fls-integrity',0o750)]:
    Path(path).mkdir(parents=True,exist_ok=True);shutil.chown(path,user=owner,group=owner);Path(path).chmod(mode)
run('systemctl','stop','mariadb')
dest=Path('/srv/fortigate/database/mysql')
if not dest.exists():
    dest.mkdir();run('cp','-a','/var/lib/mysql/.',str(dest))
    run('chown','-R','mysql:mysql',str(dest))
run('chmod','0711','/srv/fortigate/database')
put('/etc/mysql/mariadb.conf.d/90-fls.cnf','''[mysqld]
datadir=/srv/fortigate/database/mysql
bind-address=127.0.0.1
innodb_buffer_pool_size=4G
innodb_log_file_size=512M
innodb_flush_log_at_trx_commit=1
innodb_flush_method=O_DIRECT
max_allowed_packet=64M
max_connections=40
character-set-server=utf8mb4
collation-server=utf8mb4_unicode_ci
skip-name-resolve
local-infile=0
''')
put('/etc/systemd/system/mariadb.service.d/fls-storage.conf','''[Unit]
RequiresMountsFor=/srv/fortigate/database/mysql
[Service]
ReadWritePaths=/srv/fortigate/database/mysql
''')
run('systemctl','daemon-reload');run('systemctl','start','mariadb')
db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',autocommit=True,charset='utf8mb4')
with db.cursor() as c:
    for sql in Path('/var/www/fls/schema.sql').read_text().split(';'):
        if sql.strip(): c.execute(sql)
    for user,group,file in [('fls_app','fls-web','app'),('fls_import','fls-index','importer'),('fls_seal','fls-integrity','integrity'),('fls_history','root','fortigate-history'),('fls_alerts','root','change-alerts'),('fls_search','fls-search','search-indexer')]:
        target=Path('/etc/fls/'+file+'.json')
        config=json.loads(target.read_text()) if target.exists() else {'user':user,'password':secrets.token_urlsafe(36)}
        c.execute('CREATE USER IF NOT EXISTS %s@localhost IDENTIFIED BY %s',(user,config['password']))
        put(str(target),json.dumps(config)+'\n',0o600 if file in ('fortigate-history','change-alerts') else 0o640,group)
    for table in ['fg_config_versions','fg_config_observations','fg_config_changes']:
        c.execute('GRANT SELECT,INSERT ON fls.'+table+' TO fls_history@localhost')
    for table in ['events','source_files','fg_config_changes','fg_config_observations','security_event_groups','traffic_event_groups','traffic_groups']:
        c.execute('GRANT SELECT ON fls.'+table+' TO fls_alerts@localhost')
    c.execute('GRANT SELECT(id,devid,vd,event_at,fields) ON fls.events TO fls_search@localhost')
    c.execute('GRANT SELECT(observed_size,byte_offset) ON fls.source_files TO fls_search@localhost')
    for table in ['mail_search_events','mail_search_state']:
        c.execute('GRANT SELECT,INSERT,UPDATE ON fls.'+table+' TO fls_search@localhost')
    c.execute('GRANT SELECT ON fls.* TO fls_app@localhost')
    c.execute('GRANT DELETE ON fls.fortigate_credentials TO fls_app@localhost')
    c.execute('GRANT UPDATE ON fls.retention_settings TO fls_app@localhost')
    c.execute('GRANT INSERT ON fls.retention_policy_versions TO fls_app@localhost')
    c.execute('GRANT INSERT,UPDATE ON fls.fortigate_setup TO fls_app@localhost')
    c.execute('GRANT UPDATE ON fls.users TO fls_app@localhost')
    c.execute('GRANT INSERT,UPDATE ON fls.user_event_columns TO fls_app@localhost')
    c.execute('GRANT INSERT,UPDATE,DELETE ON fls.user_fortigate_preferences TO fls_app@localhost')
    c.execute('GRANT INSERT,DELETE ON fls.user_fortigate_access TO fls_app@localhost')
    c.execute('GRANT INSERT,UPDATE,DELETE ON fls.user_event_views TO fls_app@localhost')
    c.execute('GRANT INSERT,UPDATE,DELETE ON fls.user_archive_tls_views TO fls_app@localhost')
    c.execute('GRANT UPDATE ON fls.summary_backlog_settings TO fls_app@localhost')
    c.execute('GRANT UPDATE ON fls.mail_search_backlog_settings TO fls_app@localhost')
    c.execute('GRANT UPDATE ON fls.archive_tls_settings TO fls_app@localhost')
    for table in ['archive_tls_alert_history','archive_tls_history_state']:
        c.execute('GRANT INSERT,UPDATE ON fls.'+table+' TO fls_app@localhost')
    c.execute('GRANT INSERT ON fls.audit_log TO fls_app@localhost')
    c.execute('GRANT INSERT ON fls.event_notes TO fls_app@localhost')
    c.execute('GRANT INSERT,UPDATE,DELETE ON fls.login_attempts TO fls_app@localhost')
    c.execute('GRANT SELECT,INSERT ON fls.events TO fls_import@localhost')
    c.execute('GRANT SELECT,INSERT ON fls.av_event_groups TO fls_import@localhost')
    c.execute('GRANT SELECT,INSERT ON fls.security_event_groups TO fls_import@localhost')
    c.execute('GRANT SELECT,INSERT ON fls.traffic_groups TO fls_import@localhost')
    c.execute('GRANT SELECT,INSERT ON fls.traffic_event_groups TO fls_import@localhost')
    for table in ['source_files','policies','devices','hourly_counts']:
        c.execute('GRANT SELECT,INSERT,UPDATE ON fls.'+table+' TO fls_import@localhost')
    for table in ['archive_dimensions','archive_hour_counts','archive_group_hours','archive_index_state','device_hourly_counts','device_policies','device_sources']:
        c.execute('GRANT SELECT,INSERT,UPDATE ON fls.'+table+' TO fls_import@localhost')
    c.execute('GRANT SELECT,INSERT ON fls.archive_event_index TO fls_import@localhost')
    c.execute('GRANT SELECT,INSERT,UPDATE ON fls.archive_manifests TO fls_seal@localhost')
    c.execute('SELECT COUNT(*) FROM fls.users')
    if c.fetchone()[0]==0:
        password=secrets.token_urlsafe(18)
        hashed=subprocess.check_output(['php','-r','$p=stream_get_contents(STDIN);echo password_hash($p,PASSWORD_ARGON2ID);'],input=password.encode()).decode()
        c.execute('INSERT INTO fls.users(username,password_hash,must_change,updated_at) VALUES(%s,%s,1,UTC_TIMESTAMP())',('admin',hashed))
        put('/etc/fls/bootstrap-credentials.txt','Adres: https://'+instance['hostname']+'\nKullanıcı: admin\nİlk giriş parolası: '+password+'\nİlk girişte değiştirilmesi zorunludur.\n',0o600)
    c.execute('DROP DATABASE IF EXISTS test')
db.close()
run('/usr/bin/python3','/var/www/fls/bin/provision-telemetry.py')
run('/usr/bin/python3','/var/www/fls/bin/provision-backlog-history.py')
keypath=Path('/etc/fls/private/archive-ed25519.pem')
if not keypath.exists():
    key=Ed25519PrivateKey.generate()
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));keypath.chmod(0o600);shutil.chown(keypath,user='fls-integrity',group='fls-integrity')
else: key=serialization.load_pem_private_key(keypath.read_bytes(),password=None)
put('/var/www/fls/public/archive-public-key.pem',key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())
run('setfacl','-m','u:fls-web:r-x','/srv/fortigate/raw','/srv/fortigate/metrics','/srv/fortigate/archive','/srv/fortigate/archive/manifests')
run('setfacl','-d','-m','u:fls-web:r-x','/srv/fortigate/raw','/srv/fortigate/metrics','/srv/fortigate/archive/manifests')
for path in list(Path('/srv/fortigate/raw').glob('*.jsonl'))+list(Path('/srv/fortigate/metrics').glob('*.json')):
    run('setfacl','-m','u:fls-web:r--',str(path))
put('/etc/php/8.3/fpm/pool.d/fls.conf','''[fls]
user = fls-web
group = fls-web
listen = /run/php/fls.sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
pm = ondemand
pm.max_children = 6
pm.process_idle_timeout = 20s
pm.max_requests = 500
request_terminate_timeout = 60s
clear_env = yes
security.limit_extensions = .php
php_admin_value[session.save_path] = /var/lib/fls/sessions
php_admin_value[session.gc_maxlifetime] = 28800
php_admin_value[session.cookie_secure] = 1
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_samesite] = Strict
php_admin_value[session.use_strict_mode] = 1
php_admin_flag[session.use_only_cookies] = on
php_admin_flag[session.upload_progress.enabled] = off
php_admin_flag[file_uploads] = off
php_admin_value[post_max_size] = 64K
php_admin_value[max_input_vars] = 200
php_admin_value[max_input_nesting_level] = 16
php_admin_value[expose_php] = Off
php_admin_value[display_errors] = Off
php_admin_value[log_errors] = On
php_admin_value[memory_limit] = 256M
php_admin_value[date.timezone] = Europe/Istanbul
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
''')
put('/etc/systemd/system/fls-indexer.service','''[Unit]
Description=FLS resumable FortiGate log indexer
After=mariadb.service fortigate-collector.service
Requires=mariadb.service
RequiresMountsFor=/srv/fortigate/raw
[Service]
User=fls-index
Group=fls-index
SupplementaryGroups=adm
RuntimeDirectory=fls-indexer
ExecStart=/usr/bin/flock --nonblock /run/fls-indexer/index.lock /usr/bin/python3 /var/www/fls/bin/importer.py
Restart=on-failure
RestartSec=5
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
CPUQuota=150%
MemoryMax=1G
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
ReadOnlyPaths=/srv/fortigate/raw
[Install]
WantedBy=multi-user.target
''')
put('/etc/systemd/system/fls-integrity.service','''[Unit]
Description=FLS local archive signature and integrity verification
After=mariadb.service
Requires=mariadb.service
RequiresMountsFor=/srv/fortigate/raw /srv/fortigate/archive
[Service]
Type=oneshot
User=fls-integrity
Group=fls-integrity
SupplementaryGroups=adm
ExecStart=/usr/bin/python3 /var/www/fls/bin/integrity.py
Nice=15
IOSchedulingClass=idle
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/srv/fortigate/raw
ReadWritePaths=/srv/fortigate/archive/manifests
RestrictAddressFamilies=AF_UNIX
''')
put('/etc/systemd/system/fls-integrity.timer','''[Unit]
Description=Hourly FLS archive verification
[Timer]
OnCalendar=*-*-* *:20:00
RandomizedDelaySec=120
Persistent=true
[Install]
WantedBy=timers.target
''')
put('/etc/systemd/system/fls-integrity.timer.d/10-retry.conf',Path('/var/www/fls/deploy/fls-integrity-retry.conf').read_text())
hosts=Path('/etc/hosts')
if instance['hostname'] not in hosts.read_text().split():
    shutil.copy2(hosts,'/etc/fls/hosts.before');hosts.write_text(hosts.read_text()+'\n'+instance['bind_ip']+' '+instance['hostname']+'\n')
run('systemctl','daemon-reload')
put('/etc/systemd/system/fls-archive-indexer.service',Path('/var/www/fls/deploy/fls-archive-indexer.service').read_text())
run('systemctl','daemon-reload')
put('/etc/systemd/system/fls-mail-search.service',Path('/var/www/fls/deploy/fls-mail-search.service').read_text())
run('systemctl','daemon-reload')
run('systemctl','enable','--now','fls-mail-search.service')
run('/usr/bin/python3','/var/www/fls/bin/provision-integrity-scrub.py')
for unit in ['fls-integrity-scrub.service','fls-integrity-scrub.timer']:
    put('/etc/systemd/system/'+unit,(Path('/var/www/fls/deploy')/unit).read_text())
run('systemctl','daemon-reload')
run('systemctl','enable','--now','fls-integrity-scrub.timer')
# Fresh installs include maintenance control; the narrow provisioner never
# starts/stops collection or overwrites the requested mode in the database.
run('/usr/bin/python3','/var/www/fls/bin/provision-maintenance.py')
for unit in ['fls-maintenance.service','fls-maintenance.timer']:
    put('/etc/systemd/system/'+unit,(Path('/var/www/fls/deploy')/unit).read_text())
put('/etc/systemd/system/fortigate-collector.service.d/fls-maintenance.conf',Path('/var/www/fls/deploy/fortigate-collector.service.d/fls-maintenance.conf').read_text())
run('systemctl','daemon-reload')
run('systemctl','enable','--now','fls-maintenance.timer')
run('systemctl','enable','--now','mariadb','php8.3-fpm','fls-indexer','fls-archive-indexer','fls-integrity.timer')
print('Database, accounts, PHP pool and indexer configured. Credentials saved root-only.')
