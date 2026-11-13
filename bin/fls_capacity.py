"""Bounded capacity metadata and daily history; no event reads or deletions."""
import datetime as dt
import json
import os
from pathlib import Path
import stat
import tempfile

UTC = dt.timezone.utc


def database_capacity(connect=None):
    """Called by the root health service using its local socket identity."""
    result = {'available': False, 'measured_at': dt.datetime.now(UTC).isoformat()}
    connection = None
    try:
        if connect is None:
            import pymysql
            connect = pymysql.connect
        connection = connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                             database='fls', connect_timeout=3, read_timeout=3,
                             write_timeout=3, autocommit=True)
        with connection.cursor() as cursor:
            cursor.execute('SET SESSION max_statement_time=2')
            cursor.execute("SELECT COUNT(*),COALESCE(SUM(data_length),0),COALESCE(SUM(index_length),0) "
                           "FROM information_schema.tables WHERE table_schema=DATABASE()")
            tables, data, indexes = map(int, cursor.fetchone())
        if tables > 0 and min(data, indexes) >= 0:
            result.update(available=True, tables=tables, data_bytes=data,
                          index_bytes=indexes, total_bytes=data + indexes,
                          statistics='estimated')
    except Exception:
        result['error_code'] = 'database_capacity_unavailable'
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                result = {'available': False, 'measured_at': result['measured_at'],
                          'error_code': 'database_capacity_unavailable'}
    return result


def moment(value):
    try:
        value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value.astimezone(UTC) if value.tzinfo is not None else None
    except (TypeError, ValueError, AttributeError, OverflowError):
        return None


def trusted_health(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or not 0 < info.st_size <= 1048576):
            raise ValueError('capacity_health_unsafe')
        return json.loads(stream.read(1048577))


def valid_volume(value):
    # f_bavail excludes root-reserved ext4 blocks; shutil used+free need not equal total.
    return (isinstance(value, dict)
            and all(type(value.get(key)) is int for key in ('total', 'free', 'used'))
            and value['total'] > 0 and 0 <= value['free'] <= value['total']
            and 0 <= value['used'] <= value['total'] - value['free'])


def valid_database(value):
    return (isinstance(value, dict) and value.get('available') is True
            and value.get('statistics') == 'estimated' and moment(value.get('measured_at')) is not None
            and all(type(value.get(key)) is int and value[key] >= 0
                    for key in ('data_bytes', 'index_bytes', 'total_bytes'))
            and value['total_bytes'] == value['data_bytes'] + value['index_bytes'])


def capacity_sample(root, at, reader=trusted_health):
    result = {'schema': 1, 'at': at.isoformat(), 'available': False,
              'volumes': {}, 'database': {'available': False}}
    try:
        health = reader(Path(root) / 'metrics/host-health.json')
        measured = moment(health.get('checked_at'))
        if measured is None or not -5 <= (at - measured).total_seconds() <= 150:
            return result
        mode = health.get('storage', {}).get('mode')
        if mode not in ('hybrid', 'system-root', 'dedicated'):
            return result
        values = {'logs': health.get('disk_space')}
        if mode == 'hybrid':
            values['system'] = health.get('system_disk_space')
        elif mode == 'system-root':
            values = {'system': health.get('disk_space')}
        for role, value in values.items():
            if valid_volume(value):
                result['volumes'][role] = {key: value[key] for key in ('total', 'free', 'used')}
        database = health.get('database_capacity', {})
        captured = moment(database.get('measured_at')) if isinstance(database, dict) else None
        if valid_database(database) and -5 <= (at - captured).total_seconds() <= 150:
            result['database'] = {key: database[key] for key in
                                  ('available', 'measured_at', 'data_bytes', 'index_bytes', 'total_bytes', 'statistics')}
        result.update(available=len(result['volumes']) == len(values), storage_mode=mode)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    return result


def update_daily(directory, sample):
    """One small file per UTC day; failed/unknown samples never become zero."""
    if not isinstance(sample, dict):
        raise ValueError('capacity_sample_invalid')
    at = moment(sample.get('at'))
    if at is None:
        raise ValueError('capacity_sample_time')
    if sample.get('available') is not True:
        return False
    expected = {'hybrid': {'system', 'logs'}, 'system-root': {'system'}, 'dedicated': {'logs'}}.get(sample.get('storage_mode'))
    volumes = sample.get('volumes')
    if (type(sample.get('schema')) is not int or sample['schema'] != 1 or expected is None
            or not isinstance(volumes, dict) or set(volumes) != expected
            or not all(valid_volume(value) for value in volumes.values())
            or not isinstance(sample.get('database'), dict)
            or (sample['database'].get('available') is True and not valid_database(sample['database']))):
        raise ValueError('capacity_sample_invalid')
    directory = Path(directory)
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError('capacity_directory_unsafe')
    path = directory / (at.date().isoformat() + '.json')
    previous = {}
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
                or not 0 < info.st_size <= 16384):
            raise ValueError('capacity_day_unsafe')
        try:
            previous = json.loads(path.read_text())
        except (ValueError, OSError):
            raise ValueError('capacity_day_invalid') from None
        if (not isinstance(previous, dict) or type(previous.get('schema')) is not int
                or previous['schema'] != 1 or previous.get('day') != at.date().isoformat()
                or not isinstance(previous.get('metrics'), dict)
                or type(previous.get('samples')) is not int or previous['samples'] < 1):
            raise ValueError('capacity_day_invalid')
        last = moment(previous.get('last_at'))
        if last is None or at < last:
            raise ValueError('capacity_clock_regressed')
        first = moment(previous.get('first_at'))
        if first is None or first > last or first.date() != at.date() or last.date() != at.date():
            raise ValueError('capacity_day_invalid')
        for role, values in previous['metrics'].items():
            if (role not in ('system', 'logs', 'database') or not isinstance(values, dict)
                    or any(type(values.get(key)) is not int or values[key] < 0
                           for key in ('first_used', 'last_used', 'used'))
                    or (role != 'database' and not valid_volume(values))):
                raise ValueError('capacity_day_invalid')
            first_at, last_at = moment(values.get('first_at')), moment(values.get('last_at'))
            if (first_at is None or last_at is None or first_at > last_at or last_at > last
                    or first_at.date() != at.date() or values['used'] != values['last_used']):
                raise ValueError('capacity_day_invalid')
    records = dict(sample.get('volumes', {}))
    if sample.get('database', {}).get('available') is True:
        records['database'] = {'used': sample['database']['total_bytes']}
    metrics = {}
    for role, values in records.items():
        before = previous.get('metrics', {}).get(role, {})
        # A replaced/resized filesystem starts a new baseline for this day.
        same = role == 'database' or before.get('total') == values.get('total')
        used = values['used']
        metrics[role] = {'first_at': before.get('first_at', sample['at']) if same else sample['at'],
                         'first_used': before.get('first_used', used) if same else used,
                         'last_at': sample['at'], 'last_used': used, **values}
    # A missing DB measurement is not carried forward as a current sample.
    value = {'schema': 1, 'day': at.date().isoformat(),
             'first_at': previous.get('first_at', sample['at']), 'last_at': sample['at'],
             'samples': int(previous.get('samples', 0)) + 1, 'metrics': metrics,
             'database_statistics': 'estimated'}
    descriptor, temporary = tempfile.mkstemp(prefix='.capacity-', dir=directory)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'))
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    cutoff = (at - dt.timedelta(days=90)).date().isoformat()
    for candidate in directory.glob('????-??-??.json'):
        try:
            day = dt.date.fromisoformat(candidate.stem).isoformat()
        except ValueError:
            continue
        if day < cutoff and candidate.is_file() and not candidate.is_symlink():
            candidate.unlink()
    return True
