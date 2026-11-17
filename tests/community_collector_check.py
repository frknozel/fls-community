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
import signal
import socket
import stat
import subprocess
import sys
import tempfile
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
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fls-community-collector-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.binary = PREFIX.absolute() / 'sbin/rsyslogd'
        self.modules = PREFIX.absolute() / 'lib/rsyslog'
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

    def start(self):
        output = (self.base / ('process-' + str(len(self.processes)) + '.log')).open('wb')
        self.handles.append(output)
        process = subprocess.Popen([str(self.binary), '-M', str(self.modules), '-n', '-iNONE', '-f', str(self.config)],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   env=self.environment, start_new_session=True)
        self.processes.append(process)
        wait_until(lambda: own_listener(process, self.port), 10, 'fixture listener did not become ready')
        return process

    def stop(self, process):
        if process.poll() is not None:
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

    def messages(self):
        found = []
        for path in sorted((self.base / 'raw').glob('*.jsonl')):
            if path.is_symlink(): continue
            self.assertLess(path.stat().st_size, 1024 * 1024)
            for line in path.read_bytes().splitlines():
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

    def send_messages(self, now, count):
        variants = ('plain message', 'quotes="value" slash=\\ unicode=Türkçe ğüşİöç',
                    'tab=\t embedded-line=\nnext line', 'trailing newline\n')
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as connection:
            for index in range(count):
                message = ('<134>1 ' + now.isoformat().replace('+00:00', 'Z') +
                           ' fixture fls - - - FLS-CHECK-' + self.nonce + '-' + str(index) +
                           ' ' + variants[index % len(variants)]).encode('utf-8')
                self.expected_messages[index] = message
                connection.sendall(str(len(message)).encode() + b' ' + message)
            connection.shutdown(socket.SHUT_WR)

    def private_log(self):
        data = b''
        for path in list((self.base / 'metrics').glob('*')) + list(self.base.glob('process-*.log')):
            if path.is_file() and not path.is_symlink():
                self.assertLess(path.stat().st_size, 1024 * 1024)
                data += path.read_bytes()
        return data

    def test_failed_dynamic_write_remains_durable_then_replays_after_restart(self):
        self.assert_failed_output_replays('dynamic_write_enospc')

    def test_missing_raw_directory_remains_durable_then_replays_after_restart(self):
        self.assert_failed_output_replays('missing_raw_directory')

    def assert_failed_output_replays(self, failure):
        now = dt.datetime.now(dt.timezone.utc)
        broken = []
        if failure == 'dynamic_write_enospc':
            for offset in (-1, 0, 1):
                path = self.base / 'raw' / ((now + dt.timedelta(hours=offset)).strftime('%Y-%m-%d-%H') + '.jsonl')
                path.symlink_to('/dev/full'); broken.append(path)
            error_terms = (b'write error', b'write failed', b'no space left')
        else:
            (self.base / 'raw').rmdir()
            error_terms = (b'no such file or directory', b'cannot be opened')
        process = self.start()
        count = 96
        self.send_messages(now, count)
        wait_until(lambda: any(term in self.private_log().lower() for term in error_terms), 10,
                   'The injected output failure was not observed: ' + failure)
        self.assertEqual(self.messages(), [])
        self.stop(process)
        queue_files = list((self.base / 'queue').glob('fg-receive*'))
        checkpoints = [path for path in queue_files if path.name.endswith('.qi')]
        self.assertEqual(len(checkpoints), 1)
        self.assertTrue(any(path.stat().st_size > 0 and not path.name.endswith('.qi') for path in queue_files))
        checkpoint = checkpoints[0].read_bytes()
        self.assertLess(len(checkpoint), 65536)
        pending = re.search(rb'\+iQueueSize:2:[0-9]+:([0-9]+):', checkpoint)
        self.assertIsNotNone(pending, 'A durable queue checkpoint must retain its queued message count')
        self.assertEqual(int(pending[1]), count)
        for path in broken: path.unlink()
        if failure == 'missing_raw_directory':
            (self.base / 'raw').mkdir(mode=0o700)
        process = self.start()
        wait_until(lambda: set(self.messages()) == set(range(count)), 15,
                   'Messages were lost when the failed output was repaired and the collector restarted')
        self.stop(process)
        recovered = self.messages()
        counts = collections.Counter(recovered)
        self.assertEqual(counts, collections.Counter(range(count)))
        scenario = {'disk_queue_checkpoint_pending': count, 'recovered_after_restart': count,
                    'unique_recovered_messages': len(counts), 'duplicate_messages': sum(counts.values())-len(counts),
                    'complete_raw_content_verified': True, 'source_order_preserved': recovered == list(range(count))}
        RESULT.setdefault('scenarios', {})[failure] = scenario
        RESULT.update(tests_executed=True, configuration_validated=True,
                      injected_dynamic_write_failure='dynamic_write_enospc' in RESULT['scenarios'],
                      injected_missing_raw_directory='missing_raw_directory' in RESULT['scenarios'],
                      disk_queue_checkpoint_pending=count, graceful_stop=True, recovered_after_restart=count,
                      unique_recovered_messages=len(counts), duplicate_messages=sum(counts.values())-len(counts),
                      complete_raw_content_verified=True, physical_source_order_guaranteed=False,
                      source_order_preserved=all(row['source_order_preserved'] for row in RESULT['scenarios'].values()),
                      payload_variants=['plain', 'quotes_backslash_unicode', 'tab_embedded_newline', 'trailing_newline'],
                      collector_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                      production_template_sha256=hashlib.sha256((ROOT / 'deploy/fortigate-rsyslog.conf').read_bytes()).hexdigest())


if __name__ == '__main__':
    result = unittest.main(verbosity=2, exit=False).result
    RESULT['ok'] = result.wasSuccessful()
    if options.output:
        options.output.write_text(json.dumps(RESULT, sort_keys=True, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
