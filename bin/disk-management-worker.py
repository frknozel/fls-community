#!/usr/bin/python3
"""Publish disk inventory and consume explicit administrator mirror requests.

Web input contains intent only. Host commands and disk selection belong to the
root-owned host module. A durable journal prevents replay after SQL restore or
an interrupted destructive operation. No pending format resumes automatically.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import threading

import pymysql
from fls_disk_ops import CommunityHostOps as HostOps, IDENTITY_FIELDS, identity_key_valid, physical_identity
from fls_primary_migration import MigrationJournal, LinuxMigration, migrate_primary

STATE = Path('/var/lib/fls-disks')
CREDENTIAL = Path('/etc/fls/disk-management.json')
MIRROR = Path('/etc/fls/mirror.json')
TARGET = Path('/srv/fls-mirror')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
WWN = re.compile(r'0x[0-9a-f]{16}\Z')


class DiskRequestError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise DiskRequestError(code)


def utc():
    return dt.datetime.now(dt.timezone.utc)


def iso():
    return utc().isoformat()


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(UUID.fullmatch(value), 'boot_invalid')
    return value


def safe_json(path, maximum=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= maximum, 'root_state_unsafe')
        raw = stream.read(maximum + 1)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'root_state_invalid')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def atomic(path, value, mode=0o600):
    path = Path(path)
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'root_state_unsafe')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_credential(path=CREDENTIAL):
    value = safe_json(path, 16384)
    require(set(value) == {'user', 'password'} and value['user'] == 'fls_disks'
            and isinstance(value['password'], str) and 16 <= len(value['password']) <= 512,
            'credential_invalid')
    require(not path.stat().st_mode & 0o037, 'credential_permissions')
    return value


def connect(credential):
    connection = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', database='fls',
        user=credential['user'], password=credential['password'], autocommit=True,
        cursorclass=pymysql.cursors.DictCursor, read_timeout=30, write_timeout=30)
    with connection.cursor() as cursor:
        cursor.execute("SET time_zone='+00:00', innodb_lock_wait_timeout=5")
    return connection


class Journal:
    def __init__(self, folder=STATE):
        self.folder = Path(folder)
        self.path = self.folder / 'attempt.json'

    def read(self):
        value = safe_json(self.path)
        require(set(value) == {'schema', 'high_water', 'last'} and value['schema'] == 1
                and type(value['high_water']) is int and value['high_water'] >= 0
                and (value['last'] is None or isinstance(value['last'], dict)), 'journal_invalid')
        require(stat.S_IMODE(self.path.stat().st_mode) == 0o600, 'journal_unsafe')
        return value

    def record(self, job):
        old = self.read()
        require(job['id'] > old['high_water'], 'request_replayed')
        value = {'schema': 1, 'high_water': job['id'], 'last': {
            'id': job['id'], 'request_key': job['request_key'], 'action': job['action'],
            'boot_id': job['boot_id'], 'disk_wwn': job['disk_wwn'], 'at': iso()}}
        atomic(self.path, value)
        require(self.read() == value, 'journal_write_failed')


class Store:
    def __init__(self, connection):
        self.connection = connection

    def rows(self, sql, args=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.fetchall()

    def execute(self, sql, args=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.rowcount

    def actor_valid(self, job):
        actors = self.rows('SELECT role,enabled,must_change,session_version FROM users WHERE id=%s',
                           (job['requested_by_uid'],))
        return bool(actors and actors[0]['role'] == 'admin' and actors[0]['enabled'] == 1
            and actors[0]['must_change'] == 0
            and actors[0]['session_version'] == job['requested_session_version'])

    def guard(self, job, initial=False):
        require(job['boot_id'] == boot_id(), 'boot_changed')
        require(self.actor_valid(job), 'administrator_revoked')
        rows = self.rows('SELECT status,request_key FROM disk_management_jobs WHERE id=%s', (job['id'],))
        require(rows and rows[0]['status'] == 'running'
                and rows[0]['request_key'] == job['request_key'], 'request_changed')
        if initial:
            expires = job['expires_at'].replace(tzinfo=dt.timezone.utc)
            requested = job['requested_at'].replace(tzinfo=dt.timezone.utc)
            require(requested <= utc() + dt.timedelta(seconds=5)
                    and requested < expires <= requested + dt.timedelta(minutes=5)
                    and utc() < expires, 'request_expired')
        return True

    def claim(self):
        self.connection.begin()
        try:
            require(self.rows('SELECT id FROM management_lock WHERE id=1 FOR UPDATE'), 'management_lock_missing')
            # An interrupted running job is never re-executed automatically.
            self.execute("UPDATE disk_management_jobs SET status='failed',error_code='operation_interrupted',completed_at=UTC_TIMESTAMP(6) WHERE status='running'")
            rows = self.rows("SELECT * FROM disk_management_jobs WHERE status='queued' ORDER BY id LIMIT 1 FOR UPDATE")
            if not rows:
                self.connection.commit()
                return None
            job = rows[0]
            self.execute("UPDATE disk_management_jobs SET status='running',started_at=UTC_TIMESTAMP(6) WHERE id=%s AND status='queued'", (job['id'],))
            self.connection.commit()
            return job
        except Exception:
            self.connection.rollback()
            raise

    def phase(self, phase, error=''):
        self.execute('UPDATE disk_management_state SET boot_id=%s,checked_at=UTC_TIMESTAMP(6),status=%s,error_code=%s WHERE id=1',
                     (boot_id(), phase, error))

    def finish(self, job, result=None, error=''):
        self.execute('UPDATE disk_management_jobs SET status=%s,completed_at=UTC_TIMESTAMP(6),error_code=%s,result_json=%s WHERE id=%s AND status=\'running\'',
                     ('failed' if error else 'succeeded', error, json.dumps(result) if result is not None else None, job['id']))


@contextlib.contextmanager
def heartbeat(credential, phase):
    stopped = threading.Event()
    def beat():
        while not stopped.wait(10):
            try:
                connection = connect(credential)
                try:
                    Store(connection).execute("UPDATE disk_management_state SET checked_at=UTC_TIMESTAMP(6) WHERE boot_id=%s AND status IN ('preparing','syncing','migrating')", (boot_id(),))
                finally:
                    connection.close()
            except Exception:
                pass
    thread = threading.Thread(target=beat, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join(timeout=1)


def mirror_config():
    try:
        value = safe_json(MIRROR, 16384)
    except FileNotFoundError:
        return None
    require(value.get('schema') == 1 and value.get('mode') == 'depot-rsync'
            and identity_key_valid(value) and UUID.fullmatch(value.get('uuid', ''))
            and value.get('mount_path') == str(TARGET) and value.get('config_revision') == 1,
            'mirror_config_invalid')
    return value


def role(value, mount, filesystem_uuid):
    result = {key: value.get(key) for key in ('wwn', 'serial', 'model', 'size_bytes')}
    result['model'] = result['model'] or ''
    result.update({'mount_path': mount, 'filesystem': 'ext4', 'filesystem_uuid': filesystem_uuid})
    return result


def publish(store, ops, journal):
    observed = ops.inventory()
    config = mirror_config()
    generation = store.rows('SELECT COALESCE(MAX(id),0) n FROM disk_management_jobs')[0]['n']
    secret = safe_json(STATE / 'token-key.json', 1024)['key'].encode()
    require(len(secret) == 64, 'token_key_invalid')
    source = ops._storage()
    candidates, plans = [], {}
    for disk in observed['disks']:
        if disk.get('wwn') in (source['device_wwn'], source.get('depot_wwn'), config['wwn'] if config else None):
            continue
        fingerprint = str(disk.get('identity_token', ''))
        token = hmac.new(secret, (observed['boot_id'] + ':' + str(generation) + ':' + fingerprint).encode(), hashlib.sha256).hexdigest()
        item = {key: disk.get(key) for key in ('wwn', 'serial', 'model', 'size_bytes')}
        item.update({'eligible': bool(disk.get('eligible')) and config is None,
                     'reasons': disk.get('blockers', []) + (['mirror_already_configured'] if config else []), 'token': token})
        candidates.append(item)
        if item['eligible']:
            plans[token] = {**disk, 'boot_id': observed['boot_id'], 'observed_at': observed['observed_at']}
    system = role(observed['system'], '/', source['root_uuid'])
    depot = role(observed['primary'], source['depot_path'], source['depot_uuid']) if observed['primary'] else None
    for result, path in ((system, '/'), *(([(depot, source['depot_path'])]) if depot else [])):
        usage = __import__('shutil').disk_usage(path)
        result.update({'total_bytes': usage.total, 'free_bytes': usage.free})
    mirror = None
    if config:
        mirror = role(config, str(TARGET), config['uuid'])
        mirror.update({key: config.get(key) for key in ('last_sync_at', 'last_sync_status', 'last_sync_error')})
        # No formatting or silent path fallback is triggered by a missing disk.
        mounted = TARGET.is_mount() and str(config['uuid']) == subprocess.check_output(
            ['findmnt', '-n', '-o', 'UUID', '-T', str(TARGET)], text=True).strip()
        mirror['present'] = mounted
        if not mounted:
            mirror['last_sync_error'] = 'mirror_not_mounted'
            mirror['last_sync_status'] = 'unavailable'
        else:
            usage = __import__('shutil').disk_usage(TARGET)
            mirror.update({'total_bytes': usage.total, 'free_bytes': usage.free})
    public = {'schema': 1, 'mode': source['mode'], 'boot_id': observed['boot_id'], 'generated_at_utc': iso(),
              'system': system, 'depot': depot, 'mirror': mirror, 'candidates': candidates}
    atomic(STATE / 'plans.json', {'schema': 1, 'boot_id': observed['boot_id'], 'plans': plans})
    blocked = False
    migration = STATE / 'primary-migration.json'
    if migration.exists() or migration.is_symlink():
        blocked = safe_json(migration).get('phase') != 'complete'
    store.execute("UPDATE disk_management_state SET boot_id=%s,checked_at=UTC_TIMESTAMP(6),status=%s,error_code=%s,config_revision=%s,inventory_json=%s WHERE id=1",
                  (observed['boot_id'], 'error' if blocked else 'idle', 'migration_reconciliation_required' if blocked else '',
                   config['config_revision'] if config else 0, json.dumps(public)))
    return public


def persist_mirror(result, source):
    require(identity_key_valid(result) and UUID.fullmatch(result.get('uuid', ''))
            and result['wwn'] not in (source['device_wwn'], source['depot_wwn']), 'mirror_result_invalid')
    require(not MIRROR.exists() and not MIRROR.is_symlink(), 'mirror_already_configured')
    config = {key: result[key] for key in ('wwn', 'serial', 'size_bytes', 'uuid')}
    config['physical_identity'] = physical_identity(result)
    config.update({'schema': 1, 'mode': 'depot-rsync', 'mount_path': str(TARGET), 'config_revision': 1,
                   'source_uuid': source['depot_uuid'], 'source_wwn': source['depot_wwn'],
                   'source_identity': physical_identity(source, True),
                   'last_sync_at': None, 'last_sync_status': 'never', 'last_sync_error': ''})
    unit = subprocess.check_output(['systemd-escape', '--path', '--suffix=mount', str(TARGET)], text=True).strip()
    device = subprocess.check_output(['systemd-escape', '--path', '--suffix=device', '/dev/disk/by-uuid/' + config['uuid']], text=True).strip()
    content = ('[Unit]\nDescription=FLS optional rsync clone disk\nBindsTo=' + device + '\nAfter=' + device +
        '\n\n[Mount]\nWhat=/dev/disk/by-uuid/' + config['uuid'] + '\nWhere=' + str(TARGET) +
        '\nType=ext4\nOptions=nodev,nosuid,noatime\nTimeoutSec=15\n\n[Install]\nWantedBy=local-fs.target\n')
    path = Path('/etc/systemd/system') / unit
    require(not path.exists() and not path.is_symlink(), 'mirror_unit_already_exists')
    # This is a fixed systemd unit; no path or command text comes from the web.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    atomic(MIRROR, config, 0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', unit], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'start', unit], check=True)
    return config


def producer_guard():
    baseline = None
    def ready():
        nonlocal baseline
        for unit in ('fls-system-backup.service', 'fls-db-dump.service'):
            result = subprocess.run(['systemctl', 'show', unit, '-p', 'ActiveState', '--value'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode or result.stdout.strip() in ('active','activating','deactivating'):
                return False
        paths = (Path('/srv/fortigate/backups'), Path('/var/lib/fls-recovery-download'),
                 Path('/srv/fls-storage/DB-Dump'))
        markers = [(str(p), p.stat().st_dev, p.stat().st_ino, p.stat().st_mtime_ns) for p in paths]
        if baseline is None:
            baseline = markers
        return markers == baseline
    return ready


def perform_sync(ops, config, initial=False):
    require(config is not None, 'mirror_not_configured')
    source = ops._storage()
    require((config['source_uuid'], config['source_wwn']) ==
            (source['depot_uuid'], source['depot_wwn']), 'mirror_source_changed')
    require(config.get('source_identity', {'kind':'wwn','value':config['source_wwn']}) == physical_identity(source, True),
            'mirror_source_changed')
    ops.producer_guard = producer_guard()
    try:
        result = ops.sync(config, initial=initial)
        require(isinstance(result, dict) and result.get('status') == 'complete',
                result.get('error_code', 'mirror_copy_incomplete') if isinstance(result, dict) else 'mirror_copy_incomplete')
    except Exception as error:
        config.update({'last_attempt_at': iso(), 'last_sync_status': 'failed', 'last_sync_error': error_code(error)})
        atomic(MIRROR, config, 0o644)
        raise
    config.update({'last_attempt_at': iso(), 'last_sync_at': iso(), 'last_sync_status': 'succeeded', 'last_sync_error': ''})
    atomic(MIRROR, config, 0o644)
    return result


def process(store, ops, journal, job):
    store.guard(job, initial=True)
    require(job['id'] > journal.read()['high_water'], 'request_replayed')
    config = mirror_config()
    if job['action'] in ('prepare', 'migrate'):
        require(job['confirmed'] == 1 and config is None, 'prepare_not_permitted')
        plans = safe_json(STATE / 'plans.json')
        require(plans['boot_id'] == boot_id(), 'inventory_changed')
        plan = plans['plans'].get(job['inventory_token'])
        require(plan is not None and (plan['wwn'], plan['serial'], plan['size_bytes']) ==
                (job['disk_wwn'], job['disk_serial'], job['disk_size_bytes']), 'inventory_changed')
        claimed = []
        def claim(request, disk):
            store.guard(job, initial=True)
            require(not claimed, 'request_replayed')
            journal.record(job)
            claimed.append(True)
            return True
        ops.mutation_guard = lambda request: store.guard(job)
        request = {key: plan[key] for key in (*IDENTITY_FIELDS, 'identity_token', 'boot_id', 'observed_at')}
        request.update({'request_key': job['request_key'], 'confirmation': 'TAMAM'})
        if job['action'] == 'migrate':
            require(ops.config()['mode'] == 'system-root', 'primary_migration_requires_system_root')
            migration = MigrationJournal(STATE)
            adapter = LinuxMigration(ops, store.connection, migration, lambda: store.guard(job))
            return migrate_primary(job, request, adapter, migration, claim)
        require(ops.config()['mode'] == 'hybrid', 'mirror_requires_primary_storage')
        result = ops.prepare(request, journal_before_wipe=claim)
        require(claimed, 'destructive_journal_missing')
        store.guard(job)
        config = persist_mirror(result, ops._storage())
        store.phase('syncing')
        perform_sync(ops, config, initial=True)
        return {'prepared': True, 'wwn': config['wwn'], 'uuid': config['uuid'], 'initial_sync': 'succeeded'}
    require(job['action'] == 'sync' and config is not None and job['confirmed'] == 0,
            'sync_not_permitted')
    require((job['disk_wwn'], job['disk_serial'], job['disk_size_bytes'], job['config_revision']) ==
            (config['wwn'], config['serial'], config['size_bytes'], config['config_revision']), 'mirror_changed')
    journal.record(job)
    ops.mutation_guard = lambda request: store.guard(job)
    return perform_sync(ops, config)


def error_code(error):
    value = getattr(error, 'code', str(error))
    return value if isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', value) else 'disk_operation_failed'


def run_once(store, ops, journal, credential):
    journal.read()  # Missing/corrupt high-water mark must never reset itself.
    migration = STATE / 'primary-migration.json'
    if migration.exists() or migration.is_symlink():
        if safe_json(migration).get('phase') != 'complete':
            publish(store, ops, journal)
            return
    job = store.claim()
    if job:
        phase = 'migrating' if job['action'] == 'migrate' else 'preparing' if job['action'] == 'prepare' else 'syncing'
        store.phase(phase)
        try:
            with heartbeat(credential, phase):
                result = process(store, ops, journal, job)
            store.finish(job, result=result)
        except Exception as error:
            store.finish(job, error=error_code(error))
    else:
        config = mirror_config()
        if config:
            last = config.get('last_attempt_at') or config.get('last_sync_at')
            interval = 300 if config.get('last_sync_status') == 'failed' else 3600
            due = last is None or (utc() - dt.datetime.fromisoformat(last)).total_seconds() >= interval
            if due and not Path('/var/lib/fls-maintenance/paused').exists():
                store.phase('syncing')
                try:
                    ops.mutation_guard = lambda request: request.get('action') == 'sync' and all(
                        mirror_config().get(key) == config.get(key) for key in ('wwn','serial','size_bytes','uuid','source_uuid','source_wwn'))
                    with heartbeat(credential, 'syncing'):
                        perform_sync(ops, config)
                except Exception:
                    pass  # Preserve the per-mirror failure; retry on the next hour.
    publish(store, ops, journal)


def main():
    require(os.geteuid() == 0, 'root_required')
    os.umask(0o077)
    info = STATE.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'state_directory_unsafe')
    credential = read_credential()
    with (STATE / 'worker.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        connection = connect(credential)
        store = Store(connection)
        try:
            run_once(store, HostOps(), Journal(), credential)
        except Exception as error:
            store.phase('error', error_code(error))
            print(json.dumps({'error_code': error_code(error)}))
            return 1
        finally:
            connection.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
