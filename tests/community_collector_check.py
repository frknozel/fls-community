#!/usr/bin/env python3
"""Opt-in checked-write collector proof using only temporary paths and loopback.

Example: python3 tests/community_collector_check.py --collector-prefix /tmp/stage/opt/fortigate/rsyslog-8.2312.0-fg1
No installed collector, host unit, FLS database or existing log is accessed.
"""
import argparse
import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--collector-prefix', type=Path)
parser.add_argument('--output', type=Path)
options, remaining = parser.parse_known_args()
sys.argv = [sys.argv[0], *remaining]
PREFIX = options.collector_prefix
RESULT = {'schema': 'fls-community-collector-proof-v1', 'tests_executed': False,
          'host_services_changed': False, 'existing_logs_read': False,
          'network_scope': '127.0.0.1_ephemeral_port_only'}


def wait_until(predicate, timeout, label):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError(label)


def own_listener(process, port):
    """Check the child's socket inode before connecting to an ephemeral port."""
    if process.poll() is not None:
        raise AssertionError('fixture collector exited before opening its listener')
    inodes = set()
    try:
        for descriptor in (Path('/proc') / str(process.pid) / 'fd').iterdir():
            try: match = re.fullmatch(r'socket:\[([0-9]+)\]', os.readlink(descriptor))
            except FileNotFoundError: continue
            if match: inodes.add(match[1])
    except FileNotFoundError:
        return False
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == '0100007F:' + format(port, '04X') and fields[3] == '0A' and fields[9] in inodes:
            return True
    return False


@unittest.skipUnless(PREFIX is not None, 'Explicit --collector-prefix is required for the real collector fixture')
class CheckedWriteCollector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('cc')
        if compiler is None:
            raise AssertionError('A C compiler is required for the opt-in syscall fault fixture')
        cls.injector_work = tempfile.TemporaryDirectory(prefix='fls-collector-fault-module-')
        cls.addClassCleanup(cls.injector_work.cleanup)
        cls.collector_prefix = Path(cls.injector_work.name) / 'collector'
        shutil.copytree(PREFIX.absolute(), cls.collector_prefix)
        RESULT.update(collector_sha256=hashlib.sha256((cls.collector_prefix / 'sbin/rsyslogd').read_bytes()).hexdigest(),
                      production_template_sha256=hashlib.sha256((ROOT / 'deploy/fortigate-rsyslog.conf').read_bytes()).hexdigest())
        cls.injector = Path(cls.injector_work.name) / 'collector-fault.so'
        subprocess.run([compiler, '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-o', str(cls.injector), str(ROOT / 'tests/collector_fault_injector.c'), '-ldl'],
                       check=True, capture_output=True, timeout=30)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-community-collector-', dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.binary = self.collector_prefix / 'sbin/rsyslogd'
        self.modules = self.collector_prefix / 'lib/rsyslog'
        self.assertTrue(self.binary.is_file())
        self.assertTrue(self.modules.is_dir())
        self.assertTrue(stat.S_ISCHR(Path('/dev/full').stat().st_mode))
        self.processes = []
        self.handles = []
        self.addCleanup(self.stop_all)
        for name in ('raw', 'queue', 'metrics'):
            (self.base / name).mkdir(mode=0o700)
        self.nonce = secrets.token_hex(16)
        self.expected_messages = {}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        senders = self.base / 'senders.json'
        senders.write_text(json.dumps({'version':1,'nomatch':'deny','type':'string',
                                     'table':[{'index':'127.0.0.1','value':'allow'}]}))
        source = (ROOT / 'deploy/fortigate-rsyslog.conf').read_text()
        source = source.replace('/srv/fls-server', str(self.base))
        source = source.replace('/etc/fortigate/fls-senders.json', str(senders))
        source, changes = re.subn(r'Address="[^"\n]+" Port="5514"',
                                 'Address="127.0.0.1" Port="' + str(self.port) + '"', source)
        self.assertEqual(changes, 1, 'The production collector template must have one explicit TCP listener')
        source = source.replace('action.resumeInterval="5"', 'action.resumeInterval="1"')
        for guard in ['queue.type="Disk"', 'queue.checkpointInterval="1"', 'queue.syncQueueFiles="on"',
                      'queue.saveOnShutdown="on"', 'dynafile.donotsuspend="off"', 'flushOnTXEnd="on" sync="on"']:
            self.assertIn(guard, source)
        self.assertNotIn('/srv/', source)
        self.assertNotIn('/etc/fortigate', source)
        self.config = self.base / 'collector.conf'
        self.config.write_text(source)
        self.environment = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C.UTF-8', 'TZ':'UTC'}
        validation = subprocess.run([str(self.binary), '-M', str(self.modules), '-N1', '-f', str(self.config)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment,
                                    timeout=15, check=False)
        self.assertEqual(validation.returncode, 0, 'The published production collector configuration must validate')

    def start(self, fault=None, *, wait_for_listener=True):
        output = (self.base / ('process-' + str(len(self.processes)) + '.log')).open('wb')
        self.handles.append(output)
        environment = dict(self.environment)
        if fault is not None:
            environment.update(LD_PRELOAD=str(self.injector), FLS_FIXTURE_FAULT_ROOT=str(self.base),
                               FLS_FIXTURE_FAULT_GATE=str(self.fault_gate),
                               FLS_FIXTURE_FAULT_EVENTS=str(self.fault_events), FLS_FIXTURE_FAULT_MODE=fault)
        process = subprocess.Popen([str(self.binary), '-M', str(self.modules), '-n', '-iNONE', '-f', str(self.config)],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   env=environment, start_new_session=True)
        self.processes.append(process)
        if wait_for_listener:
            wait_until(lambda: own_listener(process, self.port), 10, 'fixture listener did not become ready')
        return process

    def stop(self, process):
        if process.poll() is not None:
            self.assertEqual(process.returncode, 0)
            return
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
            RESULT['forced_process_kill'] = True
            raise AssertionError('fixture collector failed to stop gracefully in twenty seconds')
        self.assertEqual(process.returncode, 0)

    def stop_all(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
        for handle in self.handles: handle.close()

    def messages(self, *, allow_incomplete=False):
        found = []
        for path in sorted((self.base / 'raw').glob('*.jsonl')):
            if path.is_symlink(): continue
            self.assertLess(path.stat().st_size, 32 * 1024 * 1024)
            data = path.read_bytes()
            lines = data.split(b'\n')
            if allow_incomplete:
                lines.pop()  # Only complete rows are observable while a write is in flight.
            else:
                self.assertEqual(lines.pop(), b'', 'A stopped collector left an incomplete JSON row')
            for line in lines:
                row = json.loads(line)
                match = re.search(r'FLS-CHECK-' + self.nonce + r'-([0-9]+)', row['raw'])
                if match:
                    self.assertEqual(set(row), {'schema_version', 'received_at', 'sender_ip', 'transport', 'raw'})
                    self.assertEqual(row['schema_version'], '1')
                    self.assertEqual(row['sender_ip'], '127.0.0.1')
                    self.assertEqual(row['transport'], 'tcp')
                    self.assertIsNotNone(dt.datetime.fromisoformat(row['received_at']).tzinfo)
                    index = int(match[1])
                    self.assertIn(index, self.expected_messages)
                    self.assertEqual(row['raw'].encode('utf-8'), self.expected_messages[index],
                                     'The complete original message must survive JSON encoding, disk queuing and replay')
                    found.append(index)
        return found

    def send_messages(self, now, count, *, padding=0, start=0, progress=None):
        variants = ('plain message', 'quotes="value" slash=\\ unicode=Türkçe ğüşİöç',
                    'tab=\t embedded-line=\nnext line', 'trailing newline\n')
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as connection:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            connection.settimeout(30)
            for index in range(start, start + count):
                message = ('<134>1 ' + now.isoformat().replace('+00:00', 'Z') +
                           ' fixture fls - - - FLS-CHECK-' + self.nonce + '-' + str(index) +
                           ' ' + variants[index % len(variants)] + 'x' * padding).encode('utf-8')
                self.expected_messages[index] = message
                if progress is not None:
                    progress(index, len(message), False)
                connection.sendall(str(len(message)).encode() + b' ' + message)
                if progress is not None:
                    progress(index, len(message), True)
            connection.shutdown(socket.SHUT_WR)

    def private_log(self):
        data = b''
        for path in list((self.base / 'metrics').glob('*')) + list(self.base.glob('process-*.log')):
            if path.is_file() and not path.is_symlink():
                self.assertLess(path.stat().st_size, 1024 * 1024)
                data += path.read_bytes()
        return data

    def stats(self):
        latest = {}
        for line in self.private_log().splitlines():
            offset = line.find(b'{')
            if offset < 0:
                continue
            try:
                row = json.loads(line[offset:])
            except (ValueError, UnicodeError):
                continue
            if isinstance(row, dict) and 'name' in row:
                latest[row['name']] = row
        return latest

    def assert_healthy_counters(self, count):
        def complete():
            rows = self.stats()
            inputs = [row for row in rows.values() if row.get('origin') == 'imtcp']
            queue = rows.get('fortigate', {})
            return (len(inputs) == 1 and inputs[0].get('submitted') == count
                    and queue.get('size') == 0 and queue.get('enqueued') == count)
        wait_until(complete, 10, 'Healthy input/queue counters did not settle after recovery')
        rows = self.stats()
        queue = rows['fortigate']
        self.assertEqual(queue.get('discarded.full'), 0)
        self.assertEqual(queue.get('discarded.nf'), 0)
        return {'submitted': count, 'enqueued': queue['enqueued'], 'size': queue['size'], 'full': queue['full'],
                'discarded.full': queue['discarded.full'], 'discarded.nf': queue['discarded.nf']}

    def enable_fault(self):
        self.fault_gate = self.base / 'fault.enabled'
        self.fault_events = self.base / 'fault.events'
        self.fault_gate.write_text('Only this synthetic collector child is affected.\n')
        self.fault_gate.chmod(0o600)
        self.fault_events.write_bytes(b'')
        self.fault_events.chmod(0o600)
        self.config.write_text(self.config.read_text().replace('impstats" interval="60"', 'impstats" interval="1"'))

    def fault_records(self):
        return self.fault_events.read_text().splitlines()

    def record_scenario(self, name, **details):
        RESULT.setdefault('scenarios', {})[name] = details
        RESULT.update(tests_executed=True, configuration_validated=True,
                      collector_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                      production_template_sha256=hashlib.sha256((ROOT / 'deploy/fortigate-rsyslog.conf').read_bytes()).hexdigest(),
                      physical_source_order_guaranteed=False, tcp_durable_application_acknowledgement=False,
                      injected_dynamic_write_failure='raw_enospc' in RESULT['scenarios'],
                      injected_missing_raw_directory='missing_raw_directory' in RESULT['scenarios'])

    def assert_exact_recovery(self, count):
        wait_until(lambda: len(self.messages(allow_incomplete=True)) >= count, 15, 'Queued records did not recover after repairing the syscall fault')
        self.assertEqual(collections.Counter(self.messages(allow_incomplete=True)), collections.Counter(range(count)))

    def capacity_failure_snapshot(self, process, progress, progress_lock, errors, reason, repair_started=None):
        """Preserve bounded synthetic-fixture observations before cleanup repairs/stops it."""
        now = time.monotonic()
        with progress_lock:
            sender = dict(progress)
        if 'last_progress_monotonic' in sender:
            sender['last_progress_age_seconds'] = round(now - sender['last_progress_monotonic'], 3)
        snapshot = {'reason': reason, 'captured_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'seconds_after_repair': None if repair_started is None else round(now - repair_started, 3),
                    'sender': sender, 'sender_errors': [repr(error) for error in errors],
                    'collector_returncode': process.poll(), 'fault_gate_exists': self.fault_gate.exists(),
                    'scope': 'private_temporary_fixture_only', 'queue_files': [],
                    'impstats_freshness_not_assumed': True}
        try:
            for path in sorted((self.base / 'queue').iterdir()):
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    snapshot['queue_files'].append({'name': path.name, 'bytes': info.st_size})
        except OSError as error:
            snapshot['queue_files_error'] = type(error).__name__
        for name, operation in {
            'raw_ids': lambda: self.messages(allow_incomplete=True), 'impstats': self.stats,
            'fault_events': lambda: dict(collections.Counter(self.fault_records())),
            'private_log_tail': lambda: self.private_log().decode(errors='replace')[-8192:],
        }.items():
            try:
                snapshot[name] = operation()
            except Exception as error:
                snapshot[name + '_error'] = type(error).__name__
        if 'raw_ids' in snapshot:
            snapshot['raw_count'] = len(snapshot['raw_ids'])
            snapshot['raw_duplicate_count'] = len(snapshot['raw_ids']) - len(set(snapshot['raw_ids']))
        snapshot['queued_data_bytes'] = sum(row['bytes'] for row in snapshot['queue_files']
                                            if re.fullmatch(r'fg-receive\.[0-9]+', row['name']))
        return snapshot

    def assert_storage_fault_recovers(self, mode, *, terminate_while_faulted=False, backpressure=False, capacity=None, rollover=False):
        self.enable_fault()
        count = 128 if capacity else 96
        scenario_name = mode + ('_' + capacity if capacity else '_sigterm' if terminate_while_faulted else '_backpressure' if backpressure else '')
        if capacity or rollover:
            source = self.config.read_text().replace('queue.dequeueBatchSize="512"', 'queue.dequeueBatchSize="1"')
            source = source.replace('queue.minDequeueBatchSize="64"', 'queue.minDequeueBatchSize="1"')
            if rollover:
                source = source.replace('queue.maxFileSize="64m"', 'queue.maxFileSize="64k"')
            elif capacity == 'disk_capacity':
                source = source.replace('queue.maxDiskSpace="10g"', 'queue.maxDiskSpace="256k"')
                source = source.replace('queue.maxFileSize="64m"', 'queue.maxFileSize="64k"')
            else:
                # Disable the input's earlier fullDelay watermark to exercise
                # the hard queue.size limit and its negative enqueue timeout.
                source = source.replace('queue.type="Disk"', 'queue.type="Disk" queue.size="4"')
                source = source.replace('FlowControl="on"', 'FlowControl="off"')
            self.config.write_text(source)
        if terminate_while_faulted:
            self.fault_gate.unlink()
        process = self.start(mode)
        if terminate_while_faulted:
            # TCP send completion alone does not prove collector admission.
            # Observe 95 archived records, then fault exactly one final record.
            self.send_messages(dt.datetime.now(dt.timezone.utc), count - 1)
            self.assert_exact_recovery(count - 1)
            self.assert_healthy_counters(count - 1)
            self.fault_gate.touch(mode=0o600)
        errors = []
        finished = threading.Event()
        progress_lock = threading.Lock()
        progress = {'completed_records': 0, 'completed_payload_bytes': 0}
        def sender_progress(index, size, complete):
            with progress_lock:
                progress.update(current_frame_id=index, last_progress_monotonic=time.monotonic())
                if complete:
                    progress['completed_records'] += 1
                    progress['completed_payload_bytes'] += size
                    progress['last_completed_frame_id'] = index
        def send():
            try:
                self.send_messages(dt.datetime.now(dt.timezone.utc), 1 if terminate_while_faulted else count,
                                   padding=128 * 1024 if backpressure or capacity or rollover else 0,
                                   start=count - 1 if terminate_while_faulted else 0,
                                   progress=sender_progress if capacity else None)
            except Exception as error:
                errors.append(error)
            finally:
                with progress_lock:
                    progress['finished_monotonic'] = time.monotonic()
                finished.set()
        sender = threading.Thread(target=send, daemon=True)
        sender.start()
        try:
            wait_until(lambda: len(self.fault_records()) >= 2, 10, 'The requested syscall fault was not observed repeatedly: ' + mode)
            RESULT.setdefault('fault_attempts', {})[scenario_name] = {
                'observed_events': dict(collections.Counter(self.fault_records())), 'recovery_verified': False}
            if rollover:
                observed = self.messages(allow_incomplete=True)
                self.assertLess(len(observed), count, 'Rollover cleanup fault did not hold back completion')
                self.assertEqual(len(observed), len(set(observed)))
            elif mode.startswith('raw_') and not capacity:
                def pending_checkpoint():
                    checkpoint = self.base / 'queue/fg-receive.qi'
                    if not checkpoint.is_file():
                        return False
                    pending = re.search(rb'\+iQueueSize:2:[0-9]+:([0-9]+):', checkpoint.read_bytes())
                    return pending is not None and int(pending[1]) == (1 if terminate_while_faulted else count)
                wait_until(pending_checkpoint, 5, 'The failed raw output was acknowledged before its storage fault was repaired')
            else:
                self.assertEqual(self.messages(), list(range(count - 1)) if terminate_while_faulted else [],
                                 'Output completed before the queue/storage fault was repaired')
            if backpressure or capacity:
                self.assertFalse(finished.wait(0.5), 'TCP sender completed the bounded stream despite a persistent storage/capacity fault')
                self.assertFalse(errors)
            if terminate_while_faulted:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=0.75)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    self.fail('Collector exited while a failed synchronous queue write still held pending input')
            if capacity == 'disk_capacity':
                # Repeated raw-output failures do not prove that a slow writer
                # has already reached the disk cap. Observe that cause before repair.
                try:
                    wait_until(lambda: sum(path.stat().st_size for path in (self.base / 'queue').glob('fg-receive.[0-9]*')) >= 256 * 1024,
                               10, 'The configured disk capacity was never reached')
                except AssertionError:
                    RESULT['fault_attempts'][scenario_name]['failure_before_cleanup'] = self.capacity_failure_snapshot(
                        process, progress, progress_lock, errors, 'disk_capacity_precondition_not_reached')
                    raise
            queued_bytes = sum(path.stat().st_size for path in (self.base / 'queue').glob('fg-receive.[0-9]*'))
            events = self.fault_records()
            if 'short_write' in mode:
                self.assertIn('partial_write', events)
            self.fault_gate.unlink()
            repair_started = time.monotonic()
            sender_finished = finished.wait(30)
            if capacity:
                attempt = RESULT['fault_attempts'][scenario_name]
                with progress_lock:
                    sender_finished_at = progress.get('finished_monotonic')
                sender_finished = (sender_finished and sender_finished_at is not None
                                   and sender_finished_at <= repair_started + 30)
                attempt.update(sender_deadline_seconds=30, sender_wait_elapsed_seconds=round(time.monotonic() - repair_started, 3),
                               sender_finished_within_deadline=sender_finished,
                               sender_finished_after_repair_seconds=None if sender_finished_at is None else round(sender_finished_at - repair_started, 3))
                if not sender_finished or errors:
                    attempt['failure_before_cleanup'] = self.capacity_failure_snapshot(
                        process, progress, progress_lock, errors, 'sender_deadline_or_send_error', repair_started)
            self.assertTrue(sender_finished, 'TCP sender remained blocked after the queue was repaired')
            sender.join(timeout=1)
            self.assertFalse(errors, repr(errors))
            if terminate_while_faulted:
                self.stop(process)
                process = self.start()
            self.assert_exact_recovery(count)
            counters = None if terminate_while_faulted else self.assert_healthy_counters(count)
            if capacity:
                self.assertGreater(counters['full'], 0, 'The absolute queue capacity branch was not exercised')
            self.stop(process)
            self.assert_exact_recovery(count)
            process = self.start()
            wait_until(lambda: 'fortigate' in self.stats(), 5, 'Restarted collector did not publish fresh queue statistics')
            self.stop(process)
            self.assertEqual(collections.Counter(self.messages()), collections.Counter(range(count)),
                             'A clean restart duplicated or lost the repaired queue output')
            RESULT['fault_attempts'][scenario_name]['recovery_verified'] = True
            self.record_scenario(scenario_name,
                                 injected_fault_events=len(events), complete_raw_content_verified=True,
                                 unique_recovered_messages=count, duplicate_messages=0, counters=counters,
                                 backpressure_observed=bool(backpressure or capacity), configured_capacity=capacity, rollover_cleanup_fault_verified=rollover, queued_bytes_before_repair=queued_bytes,
                                 pending_sigterm_wait_verified=terminate_while_faulted,
                                 observed_before_fault=count - 1 if terminate_while_faulted else 0,
                                 repaired_then_graceful_restart=True)
        finally:
            self.fault_gate.unlink(missing_ok=True)
            finished.wait(2)

    def test_failed_dynamic_write_remains_durable_then_replays_after_restart(self):
        self.assert_storage_fault_recovers('raw_enospc')

    def test_queue_enospc_remains_pending_then_recovers_exactly_once(self):
        self.assert_storage_fault_recovers('queue_enospc')

    def test_queue_partial_write_preserves_pending_suffix(self):
        self.assert_storage_fault_recovers('queue_short_write')

    def test_queue_reader_metadata_failure_remains_pending_then_recovers(self):
        self.assert_storage_fault_recovers('queue_reader_fstat')

    def test_queue_reader_io_failure_remains_pending_then_recovers(self):
        self.assert_storage_fault_recovers('queue_reader_read')

    def test_queue_sync_failure_remains_pending_then_recovers(self):
        self.assert_storage_fault_recovers('queue_sync')

    def test_checkpoint_write_failure_remains_pending_then_recovers(self):
        self.assert_storage_fault_recovers('checkpoint_write')

    def test_checkpoint_sync_failure_remains_pending_then_recovers(self):
        self.assert_storage_fault_recovers('checkpoint_sync')

    def test_checkpoint_rename_failure_remains_pending_then_recovers(self):
        self.assert_storage_fault_recovers('checkpoint_rename')

    def test_checkpoint_directory_sync_waits_before_completion(self):
        self.assert_storage_fault_recovers('checkpoint_directory_sync')

    def test_pending_queue_fault_does_not_silently_exit_on_sigterm(self):
        self.assert_storage_fault_recovers('queue_enospc', terminate_while_faulted=True)

    def test_pending_queue_reader_fault_waits_on_sigterm(self):
        self.assert_storage_fault_recovers('queue_reader_read', terminate_while_faulted=True)

    def test_pending_raw_partial_write_does_not_exit_on_sigterm(self):
        self.assert_storage_fault_recovers('raw_short_write', terminate_while_faulted=True)

    def test_queue_fault_applies_bounded_tcp_backpressure(self):
        self.assert_storage_fault_recovers('queue_enospc', backpressure=True)

    def test_configured_disk_capacity_applies_backpressure_without_drops(self):
        self.assert_storage_fault_recovers('raw_enospc', capacity='disk_capacity')

    def test_configured_message_capacity_applies_backpressure_without_drops(self):
        self.assert_storage_fault_recovers('raw_enospc', capacity='message_capacity')

    def test_spool_rollover_stat_failure_preserves_pending_records(self):
        self.assert_storage_fault_recovers('queue_rollover_stat', rollover=True)

    def test_spool_rollover_unlink_failure_preserves_pending_records(self):
        self.assert_storage_fault_recovers('queue_rollover_unlink', rollover=True)

    def test_raw_partial_write_preserves_json_and_original_bytes(self):
        self.assert_storage_fault_recovers('raw_short_write')

    def test_raw_sync_failure_waits_for_durable_repair(self):
        self.assert_storage_fault_recovers('raw_sync')

    def test_missing_raw_directory_remains_durable_then_replays_after_restart(self):
        self.assert_failed_output_replays('missing_raw_directory')

    def assert_failed_output_replays(self, failure):
        self.assertEqual(failure, 'missing_raw_directory')
        self.config.write_text(self.config.read_text().replace('impstats" interval="60"', 'impstats" interval="1"'))
        (self.base / 'raw').rmdir()
        process = self.start()
        count = 96
        self.send_messages(dt.datetime.now(dt.timezone.utc), count)
        wait_until(lambda: b'no such file or directory' in self.private_log().lower()
                   or b'cannot be opened' in self.private_log().lower(), 10,
                   'The missing raw output directory failure was not observed')
        self.assertEqual(self.messages(), [])
        def pending_checkpoint():
            checkpoint = self.base / 'queue/fg-receive.qi'
            if not checkpoint.is_file():
                return False
            pending = re.search(rb'\+iQueueSize:2:[0-9]+:([0-9]+):', checkpoint.read_bytes())
            return pending is not None and int(pending[1]) == count
        wait_until(pending_checkpoint, 5, 'The queue did not retain the records while their raw directory was missing')
        # Synchronous output retries preserve their in-flight buffer, including
        # hour-rotation transactions. Repair before requesting a graceful stop.
        (self.base / 'raw').mkdir(mode=0o700)
        self.assert_exact_recovery(count)
        counters = self.assert_healthy_counters(count)
        self.stop(process)
        process = self.start()
        self.stop(process)
        self.assertEqual(collections.Counter(self.messages()), collections.Counter(range(count)))
        self.record_scenario('missing_raw_directory', disk_queue_checkpoint_pending=count,
                             unique_recovered_messages=count, duplicate_messages=0,
                             complete_raw_content_verified=True, counters=counters,
                             repaired_then_graceful_restart=True)

    def test_corrupt_queue_checkpoint_aborts_before_accepting_tcp(self):
        self.assertIn('abortOnFailedQueueStartup="on"', self.config.read_text())
        (self.base / 'queue/fg-receive.qi').write_bytes(b'not-a-valid-rsyslog-checkpoint\n')
        validation = subprocess.run([str(self.binary), '-M', str(self.modules), '-N1', '-f', str(self.config)],
                                    capture_output=True, env=self.environment, timeout=15, check=False)
        self.assertEqual(validation.returncode, 0, 'The checkpoint fault must reach runtime after valid configuration parsing')
        process = self.start(wait_for_listener=False)
        deadline = time.monotonic() + 10
        while process.poll() is None and time.monotonic() < deadline:
            try:
                listener = own_listener(process, self.port)
            except AssertionError:
                if process.poll() is None:
                    raise
                break
            self.assertFalse(listener, 'A failed durable queue was replaced by an accepting TCP listener')
            time.sleep(0.01)
        self.assertEqual(process.poll(), 1, 'Corrupt durable-queue startup must exit with failure')
        self.assertIn(b'abortonfailedqueuestartup is set', self.private_log().lower())
        self.record_scenario('corrupt_queue_startup', configuration_validated=True,
                             startup_exit_code=1, listener_opened=False)

    def test_normal_receiver_counters_and_original_bytes(self):
        self.config.write_text(self.config.read_text().replace('impstats" interval="60"', 'impstats" interval="1"'))
        process = self.start()
        self.send_messages(dt.datetime.now(dt.timezone.utc), 96)
        self.assert_exact_recovery(96)
        counters = self.assert_healthy_counters(96)
        self.stop(process)
        self.record_scenario('normal_receive', unique_recovered_messages=96, duplicate_messages=0,
                             complete_raw_content_verified=True, counters=counters)


if __name__ == '__main__':
    result = unittest.main(verbosity=2, exit=False).result
    RESULT.update(ok=result.wasSuccessful(), tests_run=result.testsRun, skipped=len(result.skipped),
                  tests_executed=result.testsRun > len(result.skipped),
                  failures=len(result.failures), errors=len(result.errors))
    if options.output:
        options.output.write_text(json.dumps(RESULT, sort_keys=True, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
