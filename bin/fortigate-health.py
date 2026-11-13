#!/usr/bin/env python3
"""Fixed, local-only inventory for the collector. Installed root-owned."""
from datetime import datetime, timezone
import grp
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import stat
import tempfile
import sys
# Source checkout and installed libexec use the same guarded runtime module.
_runtime = Path(__file__).resolve().parent
sys.path.insert(0, str(_runtime if (_runtime / 'fls_storage.py').is_file() else Path('/var/www/fls/bin')))
from fls_storage import StorageError, filesystem_identity, storage_state, trusted_read


def command(args, structured=False):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    value = result.stdout.strip()
    if structured:
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = None
    return {"exit_code": result.returncode, "data": value, "stderr": result.stderr.strip()[-2000:]}


def disk_probe_paths(storage):
    """Resolve SMART targets only after checking the configured physical identity.

    A VM serial is useful for storage binding even when SMART is not exposed.
    Missing SMART support must never be rendered as a failed physical disk.
    """
    if storage.get('mode') not in ('system-root', 'hybrid'):
        raise StorageError('Configured Community storage identity is unavailable')
    roles = [('system', Path('/'), 'root_uuid', 'device_identity', 'device_wwn')]
    if storage['mode'] == 'hybrid':
        if storage.get('depot_path') != '/srv/fls-storage':
            raise StorageError('Configured Community depot path is invalid')
        roles.append(('depot', Path('/srv/fls-storage'), 'depot_uuid', 'depot_identity', 'depot_wwn'))
    result = []
    for role, mount, uuid_key, identity_key, legacy_key in roles:
        identity = storage.get(identity_key) or storage.get(legacy_key)
        _, disk = filesystem_identity(mount.stat().st_dev, storage[uuid_key], identity)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', disk.name):
            raise StorageError('Configured Community disk node is invalid')
        major_minor = trusted_read(disk / 'dev', 4096).strip()
        if not re.fullmatch(r'[0-9]+:[0-9]+', major_minor):
            raise StorageError('Configured Community disk number is invalid')
        major, minor = map(int, major_minor.split(':'))
        node = Path('/dev') / disk.name
        details = node.stat()
        if not stat.S_ISBLK(details.st_mode) or details.st_rdev != os.makedev(major, minor):
            raise StorageError('Configured Community disk node does not match')
        result.append((role, str(node)))
    return result


def smart_summary(role, disk, report):
    data = report.get('data')
    data = data if isinstance(data, dict) else {}
    health = data.get('smart_status')
    health = health.get('passed') if isinstance(health, dict) else None
    available = type(health) is bool
    attrs = data.get('ata_smart_attributes', {})
    rows = attrs.get('table', []) if isinstance(attrs, dict) else []
    rows = rows if isinstance(rows, list) else []
    hours = data.get('power_on_time')
    temperature = data.get('temperature')
    return {'role': role, 'device': disk, 'exit_code': report.get('exit_code'),
            'smart_available': available,
            'smart_status': 'available' if available else 'unsupported_or_unavailable',
            'serial': data.get('serial_number'), 'passed': health if available else None,
            'hours': hours.get('hours') if isinstance(hours, dict) else None,
            'temperature': temperature.get('current') if isinstance(temperature, dict) else None,
            'attributes': {str(row['id']): row.get('raw', {}).get('value') for row in rows
                           if isinstance(row, dict) and row.get('id') in (5, 187, 197, 198, 199)}}


def main():
    storage = storage_state()
    status = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "data_mounted": True,
        "storage": storage,
        "collector": command(["/usr/bin/systemctl", "is-active", "fortigate-collector.service"]),
        "ntp_synchronized": command(["/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"]),
        "volumes": command(["/usr/bin/findmnt", "--json", "--target", storage.get("depot_path", "/srv/fortigate"), "-o", "SOURCE,TARGET,FSTYPE,UUID,OPTIONS"], True),
        "disks": [],
    }
    try:
        disks = disk_probe_paths(storage)
    except (OSError, ValueError, StorageError):
        disks = []
        status['smart_error'] = 'disk_identity_unavailable'
    for role, disk in disks:
        try:
            report = command(["/usr/sbin/smartctl", "-a", "-j", disk], True)
            status["disks"].append(smart_summary(role, disk, report))
        except (OSError, ValueError, subprocess.SubprocessError):
            status["disks"].append(smart_summary(role, disk, {'exit_code': None, 'data': None}))
    usage = shutil.disk_usage(storage.get("depot_path", "/srv/fortigate"))
    status["disk_space"] = {"total": usage.total, "used": usage.used, "free": usage.free}
    if storage["mode"] == "hybrid":
        usage = shutil.disk_usage("/")
        status["system_disk_space"] = {"total": usage.total, "used": usage.used, "free": usage.free}
    # Bounded reads expose archive/queue delay in the existing health snapshot.
    from fls_capacity import database_capacity
    status['database_capacity'] = database_capacity()
    status["log_ingestion"] = {}
    try:
        root = Path("/srv/fortigate")
        detail = status["log_ingestion"]
        qi = root / "queue/fg-receive.qi"
        if qi.exists():
            match = re.search(r"\+iQueueSize:2:\d+:(\d+):", qi.read_text())
            detail["queue_checkpoint_pending"] = int(match.group(1)) if match else None
        latest = {}
        for path in sorted((root / "metrics").glob("*-rsyslog.jsonl"))[-1:]:
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 65536))
                lines = stream.read().splitlines()[1:]
            for line in lines:
                try:
                    offset = line.index(b"{")
                    row = json.loads(line[offset:])
                    if row.get("name") in ("fortigate", "fg_raw_archive"):
                        latest[row["name"]] = row
                        detail["stats_at"] = line[:offset].decode().split(" ", 1)[0]
                except (ValueError, json.JSONDecodeError):
                    continue
        detail["stats"] = latest
        for path in sorted((root / "raw").glob("*.jsonl"))[-1:]:
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 2 * 1024 * 1024))
                lines = stream.read().splitlines()
            for line in reversed(lines):
                try:
                    row = json.loads(line)
                    received = datetime.fromisoformat(row["received_at"])
                    detail["archive_file"] = str(path)
                    detail["last_received_at"] = row["received_at"]
                    now = datetime.now(timezone.utc)
                    detail["archive_receive_lag_seconds"] = round((now - received).total_seconds(), 3)
                    event = re.search(r"(?:^| )eventtime=(\d+)", row["raw"])
                    if event:
                        epoch = int(event.group(1)) / 1e9
                        detail["last_event_utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
                        detail["archive_event_lag_seconds"] = round(now.timestamp() - epoch, 3)
                    break
                except (ValueError, KeyError, TypeError, OverflowError):
                    continue
    except (OSError, ValueError, TypeError) as error:
        status["log_ingestion"]["read_error"] = str(error)

    directory = Path("/srv/fortigate/metrics")
    descriptor, name = tempfile.mkstemp(prefix=".health-", dir=directory)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(status, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, 0o640)
        os.chown(name, 0, grp.getgrnam("adm").gr_gid)
        os.replace(name, directory / "host-health.json")
    finally:
        if os.path.exists(name):
            os.unlink(name)


if __name__ == "__main__":
    main()
