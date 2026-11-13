#!/usr/bin/python3
"""Consume explicit, short-lived administrator power requests at most once.

Only systemd controls the normal service shutdown order. This worker never
stops FLS units individually and never executes command text from the database.
"""
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

import pymysql

STATE = Path('/var/lib/fls-power')
CREDENTIAL = Path('/etc/fls/power-database.json')
BOOT_FILE = Path('/proc/sys/kernel/random/boot_id')
ACTIONS = frozenset(('poweroff', 'reboot'))
STATUSES = frozenset(('idle', 'waiting', 'submitted', 'failed', 'rejected', 'uncertain'))
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
MAX_REVISION = 2**32 - 1
MIN_DELAY = 10
MAX_AGE = 60


class PowerError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise PowerError('config_invalid')
            value[key] = item
        return value
    try:
        if len(raw) > 16384:
            raise PowerError('config_invalid')
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, PowerError):
            raise
        raise PowerError('config_invalid') from exc


def read_config(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            # systemd credentials can be root:root 0440 inside a private mount.
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1 or info.st_mode & 0o037 or info.st_size > 16384):
                raise PowerError('config_permissions')
            value = strict_json(stream.read(16385))
    except OSError as exc:
        raise PowerError('config_unavailable') from exc
    if (not isinstance(value, dict) or set(value) != {'user', 'password'}
            or value.get('user') != 'fls_power' or not isinstance(value.get('password'), str)
            or not 16 <= len(value['password']) <= 512):
        raise PowerError('config_invalid')
    return value


def boot_id(path=BOOT_FILE):
    try:
        value = path.read_text(encoding='ascii').strip()
    except (OSError, UnicodeError) as exc:
        raise PowerError('boot_unavailable') from exc
    if not UUID.fullmatch(value):
        raise PowerError('boot_invalid')
    return value


class AttemptJournal:
    """A durable, root-private high-water mark survives SQL rollback and reboot.

    Production requires uid 0. The uid argument only permits unprivileged fixtures.
    Entries are never cleared automatically: restoring an old SQL backup must
    fail closed instead of authorizing previously consumed revision numbers.
    """
    def __init__(self, folder=STATE, uid=0):
        self.folder = Path(folder)
        self.path = self.folder / 'attempt.json'
        self.uid = uid

    def directory(self):
        try:
            info = self.folder.lstat()
        except OSError as exc:
            raise PowerError('journal_unsafe') from exc
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise PowerError('journal_unsafe')

    def sync(self):
        fd = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self):
        self.directory()
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PowerError('journal_unsafe') from exc
        try:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                        or info.st_size > 1024):
                    raise PowerError('journal_unsafe')
                value = strict_json(stream.read(1025))
            if (not isinstance(value, dict) or set(value) != {'schema', 'revision', 'boot_id', 'action'}
                    or type(value['schema']) is not int or value['schema'] != 1
                    or type(value['revision']) is not int or not 1 <= value['revision'] <= MAX_REVISION
                    or not isinstance(value['boot_id'], str) or not UUID.fullmatch(value['boot_id'])
                    or not isinstance(value['action'], str) or value['action'] not in ACTIONS):
                raise PowerError('journal_invalid')
            return value
        except PowerError as exc:
            if exc.code.startswith('journal_'):
                raise
            raise PowerError('journal_invalid') from exc
        except OSError as exc:
            raise PowerError('journal_io') from exc

    def record(self, revision, current_boot, action):
        if (type(revision) is not int or not 1 <= revision <= MAX_REVISION
                or not isinstance(current_boot, str) or not UUID.fullmatch(current_boot)
                or not isinstance(action, str) or action not in ACTIONS):
            raise PowerError('journal_invalid')
        previous = self.read()
        if previous and previous['revision'] >= revision:
            raise PowerError('journal_conflict')
        value = {'schema': 1, 'revision': revision, 'boot_id': current_boot, 'action': action}
        fd, temporary = tempfile.mkstemp(prefix='.attempt-', dir=self.folder)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.sync()
            if self.read() != value:
                raise PowerError('journal_io')
        except OSError as exc:
            raise PowerError('journal_io') from exc
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


class Systemd:
    def __init__(self, runner=subprocess.run):
        self.runner = runner

    def change(self, action):
        if not isinstance(action, str) or action not in ACTIONS:
            raise PowerError('request_invalid')
        try:
            result = self.runner(
                ['/usr/bin/systemctl', '--system', '--no-block', action],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=3, check=False,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'SYSTEMD_PAGER': ''})
        except subprocess.TimeoutExpired as exc:
            # systemd may have accepted the request before its client timed out.
            raise PowerError('command_timeout') from exc
        except OSError as exc:
            raise PowerError('command_failed') from exc
        if result.returncode != 0:
            raise PowerError('command_failed')


def initial_result(previous, current_boot):
    if (not isinstance(previous, dict) or previous.get('version') != 1
            or type(previous.get('attempted_revision')) is not int
            or not 0 <= previous['attempted_revision'] <= MAX_REVISION
            or previous.get('status') not in STATUSES):
        raise PowerError('state_invalid')
    return {'attempted_revision': previous['attempted_revision'], 'boot_id': current_boot,
            'status': previous['status'], 'error_code': previous.get('error_code', '')}


def evaluate(request, previous, actor, now, current_boot, journal):
    """Validate a locked SQL snapshot; return (published state, dispatch action)."""
    result = initial_result(previous, current_boot)
    if not isinstance(current_boot, str) or not UUID.fullmatch(current_boot):
        raise PowerError('boot_invalid')
    if (not isinstance(request, dict) or type(request.get('revision')) is not int
            or not 0 <= request['revision'] <= MAX_REVISION
            or request['revision'] < previous['attempted_revision']):
        raise PowerError('request_invalid')
    revision = request['revision']
    if previous.get('boot_id') != current_boot:
        # A submitted reboot from a previous boot must not block the next
        # explicit request after startup. Its old request is still consumed.
        result.update(status='idle', error_code='')
    durable = journal.read()
    if durable and durable['revision'] > revision:
        result.update(status='failed', error_code='journal_conflict')
        return result, None
    if durable and durable['revision'] == revision and revision > previous['attempted_revision']:
        same_boot = request.get('boot_id') == current_boot and durable['boot_id'] == current_boot
        result.update(attempted_revision=revision,
                      status='uncertain' if same_boot else 'rejected',
                      error_code='dispatch_incomplete' if same_boot else 'boot_mismatch')
        return result, None
    if revision <= previous['attempted_revision']:
        if revision == 0:
            result.update(status='idle', error_code='')
        return result, None

    if (previous.get('boot_id') == current_boot and previous['attempted_revision'] > 0
            and previous['status'] in ('submitted', 'uncertain')):
        # API serialization is helpful, but the privileged worker enforces this
        # too: no second power command while an accepted/ambiguous command may
        # still be progressing. Reboot or explicit root repair clears this.
        result.update(error_code='power_already_requested')
        return result, None

    error = ''
    if not isinstance(request.get('action'), str) or request['action'] not in ACTIONS:
        error = 'request_invalid'
    elif request.get('boot_id') != current_boot:
        error = 'boot_mismatch'
    elif any(type(request.get(field)) is not dt.datetime or request[field].tzinfo is not None
             for field in ('requested_at', 'not_before', 'expires_at')):
        error = 'request_invalid'
    elif (type(now) is not dt.datetime or now.tzinfo is not None
          or request['requested_at'] > now
          or request['not_before'] < request['requested_at'] + dt.timedelta(seconds=MIN_DELAY)
          or request['expires_at'] > request['requested_at'] + dt.timedelta(seconds=MAX_AGE)
          or request['not_before'] >= request['expires_at']):
        error = 'request_invalid'
    elif now >= request['expires_at']:
        error = 'request_expired'
    elif (type(request.get('requested_by_uid')) is not int or request['requested_by_uid'] < 1
          or type(request.get('requested_session_version')) is not int
          or request['requested_session_version'] < 0
          or not isinstance(actor, dict) or actor.get('id') != request['requested_by_uid']
          or actor.get('role') != 'admin' or actor.get('enabled') != 1
          or actor.get('session_version') != request['requested_session_version']):
        error = 'authorization_changed'
    if error:
        result.update(attempted_revision=revision, status='rejected', error_code=error)
        return result, None
    if now < request['not_before']:
        result.update(status='waiting', error_code='')
        return result, None
    # A root-private write-ahead record precedes the SQL consumption commit and
    # the fixed command. Neither rollback nor crash may authorize a retry.
    journal.record(revision, current_boot, request['action'])
    result.update(attempted_revision=revision, status='uncertain', error_code='dispatch_incomplete')
    return result, request['action']


class Store:
    def __init__(self, db):
        self.db = db

    def begin(self):
        self.db.begin()
        with self.db.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute('SELECT revision,action,boot_id,requested_at,not_before,expires_at,'
                           'requested_by_uid,requested_session_version FROM power_requests WHERE id=1 FOR UPDATE')
            request = cursor.fetchone()
            cursor.execute('SELECT version,attempted_revision,boot_id,status,error_code FROM power_state WHERE id=1 FOR UPDATE')
            previous = cursor.fetchone()
            actor = None
            if request and type(request.get('requested_by_uid')) is int and request['requested_by_uid'] > 0:
                cursor.execute('SELECT id,role,enabled,session_version FROM users WHERE id=%s FOR UPDATE',
                               (request['requested_by_uid'],))
                actor = cursor.fetchone()
            cursor.execute('SELECT UTC_TIMESTAMP(6) AS worker_now')
            now = cursor.fetchone()['worker_now']
        return request, previous, actor, now

    def publish(self, result):
        with self.db.cursor() as cursor:
            cursor.execute('UPDATE power_state SET version=1,attempted_revision=%s,boot_id=%s,'
                           'status=%s,error_code=%s,checked_at=UTC_TIMESTAMP(6) WHERE id=1',
                           (result['attempted_revision'], result['boot_id'], result['status'], result['error_code']))
            if cursor.rowcount != 1:
                raise PowerError('state_invalid')
        self.db.commit()

    def finish(self, result):
        with self.db.cursor() as cursor:
            cursor.execute('UPDATE power_state SET status=%s,error_code=%s,checked_at=UTC_TIMESTAMP(6) '
                           'WHERE id=1 AND attempted_revision=%s AND boot_id=%s',
                           (result['status'], result['error_code'], result['attempted_revision'], result['boot_id']))
            if cursor.rowcount != 1:
                raise PowerError('state_invalid')
        self.db.commit()

    def rollback(self):
        self.db.rollback()


def run_once(store, journal, system, current_boot, clock=time.monotonic):
    """Publish consumption before dispatch; a disconnect means no automatic retry."""
    try:
        request, previous, actor, now = store.begin()
        captured = clock()
        result, action = evaluate(request, previous, actor, now, current_boot, journal)
        store.publish(result)
        if action is None:
            return result
        # Slow storage/commit may exhaust a short request's remaining lifetime.
        # It is already consumed; publish expiry without sending an OS command.
        if now + dt.timedelta(seconds=max(0, clock() - captured)) >= request['expires_at']:
            result.update(status='rejected', error_code='request_expired')
        else:
            try:
                system.change(action)
                result.update(status='submitted', error_code='')
            except PowerError as exc:
                result.update(status='uncertain' if exc.code == 'command_timeout' else 'failed', error_code=exc.code)
        store.finish(result)
        return result
    except BaseException:
        # The write-ahead journal deliberately survives any rollback, including
        # a commit whose success could not be observed by the client.
        store.rollback()
        raise


def main():
    if os.geteuid() != 0:
        raise PowerError('root_required')
    directory = os.environ.get('CREDENTIALS_DIRECTORY')
    config = read_config(Path(directory) / 'power-database.json' if directory else CREDENTIAL)
    journal = AttemptJournal()
    journal.directory()
    current_boot = boot_id()
    lock = os.open(STATE / 'worker.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise PowerError('lock_unsafe')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status': 'busy'}
        db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user=config['user'],
                             password=config['password'], database='fls', charset='utf8mb4',
                             autocommit=False, connect_timeout=3, read_timeout=3, write_timeout=3)
        try:
            with db.cursor() as cursor:
                cursor.execute('SET SESSION innodb_lock_wait_timeout=2')
            return run_once(Store(db), journal, Systemd(), current_boot)
        finally:
            db.close()
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        outcome = main()
        print(json.dumps(outcome))
        raise SystemExit(1 if outcome.get('error_code') else 0)
    except Exception as exc:
        print(json.dumps({'error_code': exc.code if isinstance(exc, PowerError) else 'worker_unavailable'}))
        raise SystemExit(1)
