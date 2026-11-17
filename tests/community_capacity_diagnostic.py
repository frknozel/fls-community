#!/usr/bin/env python3
"""One RC9 isolated disk-capacity diagnostic. Never edits installed FLS bytes.

A run after the original 30s sender deadline is diagnostic recovery, not a
passing result for that original deadline. Temporary collector files are kept.
"""
import argparse
import collections
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest

EXPECTED = {
    'tests/community_collector_check.py': 'cbf60d7c6b4a091b9309033254a97fbd564e14f299bcf0cba62a02a7594a4352',
    'tests/collector_fault_injector.c': 'e43f9bd7bc804f79f6895a60e60bbd909f50866050b9280a63c01970f05b86cc',
    'deploy/fortigate-rsyslog.conf': '9ede66871df05ccc860779dead3e120ec1654940f7fef403ddb492d8ac62581b',
}
BINARY_SHA = '61fbe08a03e13d3f89b839756563f57ee6a8bf754f30ea092f20a51ab4a75587'
METHOD = 'test_configured_disk_capacity_applies_backpressure_without_drops'
PATCHES = {
    "                finished.set()": "                fixture_diagnostic_finished(self)\n                finished.set()",
    "            self.fault_gate.unlink()\n            self.assertTrue(finished.wait(30), 'TCP sender remained blocked after the queue was repaired')":
        "            fixture_diagnostic_sample(self, 'before_repair')\n            self.fault_gate.unlink()\n            self.assertTrue(fixture_diagnostic_wait(self, finished, errors), 'Diagnostic sender did not finish within 120s after repair')",
    "                connection.sendall(str(len(message)).encode() + b' ' + message)":
        "                fixture_diagnostic_progress(self, index, len(message), False)\n                connection.sendall(str(len(message)).encode() + b' ' + message)\n                fixture_diagnostic_progress(self, index, len(message), True)",
}
STATE = {'schema': 'fls-rc9-capacity-diagnostic-v1', 'original_deadline_seconds': 30,
         'maximum_observation_seconds_after_repair': 120, 'sample_interval_seconds': 5,
         'installed_files_modified': False, 'host_services_changed': False,
         'real_production_logs_read': False, 'scope': 'one_isolated_tmp_collector_fixture',
         'original_30s_sender_bound_passed': None, 'samples': []}
LOCK = threading.Lock()


def safe_read(path, limit=1024 * 1024):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError('unsafe_or_oversize_input:' + str(path))
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError('read_limit:' + str(path))
        return data


def save_state():
    destination = OUTPUT / 'diagnostic.json'
    temporary = OUTPUT / 'diagnostic.json.tmp'
    temporary.write_text(json.dumps(STATE, sort_keys=True, indent=2) + '\n')
    temporary.chmod(0o600)
    os.replace(temporary, destination)


def progress(owner, index, length, complete):
    now = time.monotonic()
    with LOCK:
        current = getattr(owner, '_diagnostic_sender', {'completed_frames': 0, 'completed_payload_bytes': 0})
        current.update(current_frame_id=index, last_progress_monotonic=now)
        if complete:
            current['completed_frames'] += 1
            current['completed_payload_bytes'] += length
            current.update(last_completed_frame_id=index, last_completed_monotonic=now)
        owner._diagnostic_sender = current


def sender_finished(owner):
    owner._diagnostic_finished_monotonic = time.monotonic()


def process_state(process, base):
    result = {'pid': process.pid, 'returncode': process.poll()}
    if process.poll() is not None:
        return result
    proc = Path('/proc') / str(process.pid)
    for name in ['io', 'status']:
        try:
            data = safe_read(proc / name, 16384).decode(errors='replace')
            if name == 'status':
                data = '\n'.join(line for line in data.splitlines() if line.split(':')[0] in
                                 {'State','Threads','VmRSS','voluntary_ctxt_switches','nonvoluntary_ctxt_switches'})
            result[name] = data
        except OSError as error:
            result[name] = type(error).__name__
    result['threads'] = {}
    try:
        for task in (proc / 'task').iterdir():
            item = {}
            for name in ['comm', 'wchan', 'stack']:
                try:
                    item[name] = safe_read(task / name, 8192).decode(errors='replace').strip()
                except OSError as error:
                    item[name] = type(error).__name__
            result['threads'][task.name] = item
    except FileNotFoundError:
        pass
    result['fixture_fdinfo'] = {}
    try:
        for fd in (proc / 'fd').iterdir():
            try:
                target = os.readlink(fd)
                if target.startswith(str(base) + '/'):
                    result['fixture_fdinfo'][fd.name] = {'path': target,
                        'fdinfo': safe_read(proc / 'fdinfo' / fd.name, 4096).decode(errors='replace')}
            except (OSError, RuntimeError):
                continue
    except FileNotFoundError:
        pass
    return result


def sample(owner, phase):
    now = time.monotonic()
    row = {'phase': phase, 'monotonic': now, 'unix_time': time.time(),
           'seconds_after_repair': None if not hasattr(owner, '_repair_start') else round(now-owner._repair_start, 3),
           'fixture': str(owner.base), 'fault_gate_exists': owner.fault_gate.exists(),
           'cpu_count': os.cpu_count(), 'load_average': os.getloadavg()}
    with LOCK:
        row['sender'] = dict(getattr(owner, '_diagnostic_sender', {}))
    for name in ['last_completed_monotonic', 'last_progress_monotonic']:
        if name in row['sender']:
            row['sender'][name.replace('_monotonic','_age_s')] = round(now-row['sender'][name],3)
    for key, operation in {
        'raw_ids': lambda: owner.messages(allow_incomplete=True),
        'stats': owner.stats,
        'fault_events': owner.fault_records,
    }.items():
        try:
            row[key] = operation()
        except Exception as error:
            row[key+'_error'] = type(error).__name__ + ': ' + str(error)
    row['raw_count'] = len(row.get('raw_ids', []))
    row['raw_duplicate_count'] = len(row.get('raw_ids', []))-len(set(row.get('raw_ids', [])))
    for name in ['raw','queue','metrics']:
        files = []
        for path in sorted((owner.base/name).iterdir()):
            try:
                info = path.lstat()
                files.append({'name':path.name,'size':info.st_size,'mtime_ns':info.st_mtime_ns,
                              'mtime_age_s':round(time.time()-info.st_mtime,3),'inode':info.st_ino})
            except FileNotFoundError:
                continue
        row[name+'_files'] = files
        row[name+'_bytes'] = sum(item['size'] for item in files)
    qi = owner.base/'queue/fg-receive.qi'
    if qi.is_file():
        row['checkpoint_text'] = safe_read(qi, 65536).decode(errors='replace')
    row['processes'] = [process_state(process, owner.base) for process in owner.processes]
    try:
        row['private_log_tail'] = owner.private_log().decode(errors='replace')[-16384:]
    except Exception as error:
        row['private_log_error'] = type(error).__name__ + ': ' + str(error)
    for name in ['io','cpu','memory']:
        try:
            row['pressure_'+name] = safe_read(Path('/proc/pressure')/name,4096).decode(errors='replace')
        except OSError:
            pass
    if 'stats' in row:
        encoded = json.dumps(row['stats'],sort_keys=True).encode()
        row['stats_sha256'] = hashlib.sha256(encoded).hexdigest()
        if getattr(owner,'_last_stats_hash',None) != row['stats_sha256']:
            owner._last_stats_changed = now
            owner._last_stats_hash = row['stats_sha256']
        row['stats_unchanged_s'] = round(now-owner._last_stats_changed,3)
    STATE['samples'].append(row)
    STATE['fixture_paths'] = [str(owner.base), owner.injector_work.name]
    save_state()
    print(json.dumps({'phase':phase,'elapsed':row['seconds_after_repair'],
                      'sender_completed':row['sender'].get('completed_frames',0),
                      'raw_count':row['raw_count'],'queue_bytes':row['queue_bytes'],
                      'queue':row.get('stats',{}).get('fortigate'),
                      'processes':[{'pid':p['pid'],'returncode':p['returncode']} for p in row['processes']]},sort_keys=True),flush=True)
    return row


def diagnostic_wait(owner, finished, errors):
    owner._repair_start = time.monotonic()
    next_at = 0
    while True:
        elapsed = time.monotonic()-owner._repair_start
        if elapsed >= next_at or finished.is_set():
            sample(owner,'after_repair')
            elapsed = time.monotonic()-owner._repair_start
            if elapsed >= 30 and STATE['original_30s_sender_bound_passed'] is None:
                finished_at = getattr(owner, '_diagnostic_finished_monotonic', None)
                STATE['original_30s_sender_bound_passed'] = finished_at is not None and finished_at-owner._repair_start <= 30
                STATE['state_at_30s'] = STATE['samples'][-1]
            if finished.is_set():
                if STATE['original_30s_sender_bound_passed'] is None:
                    finished_at = getattr(owner, '_diagnostic_finished_monotonic', None)
                    STATE['original_30s_sender_bound_passed'] = finished_at is not None and finished_at-owner._repair_start <= 30
                finished_at = getattr(owner, '_diagnostic_finished_monotonic', None)
                finished_elapsed = None if finished_at is None else finished_at-owner._repair_start
                STATE['sender_finished_after_repair_s'] = None if finished_elapsed is None else round(finished_elapsed,3)
                STATE['sender_errors'] = [repr(error) for error in errors]
                save_state()
                return finished_elapsed is not None and finished_elapsed <= 120
            if elapsed >= 120:
                STATE['sender_finished_after_repair_s'] = None
                STATE['sender_errors'] = [repr(error) for error in errors]
                save_state()
                return False
            next_at = min(120,next_at+5)
        finished.wait(max(0,min(next_at,120)-(time.monotonic()-owner._repair_start)))


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,default=Path('/var/www/fls'))
    parser.add_argument('--collector-prefix',type=Path,default=Path('/opt/fortigate/rsyslog-8.2312.0-fg1'))
    parser.add_argument('--dmi-prefix',required=True,help='Expected 12 lowercase hex characters of SHA256(product_uuid file bytes).')
    parser.add_argument('--verify-only',action='store_true')
    args = parser.parse_args()
    if re.fullmatch(r'[a-f0-9]{12}',args.dmi_prefix) is None:
        raise RuntimeError('dmi_prefix_must_be12_lowercase_hex')
    sources = {name:safe_read(args.source_root/name,1024*1024) for name in EXPECTED}
    actual = {name:hashlib.sha256(data).hexdigest() for name,data in sources.items()}
    if actual != EXPECTED:
        raise RuntimeError('source_hash_mismatch:' + json.dumps(actual,sort_keys=True))
    binary_sha = hashlib.sha256(safe_read(args.collector_prefix/'sbin/rsyslogd',4*1024*1024)).hexdigest()
    if binary_sha != BINARY_SHA:
        raise RuntimeError('collector_hash_mismatch:' + binary_sha)
    text = sources['tests/community_collector_check.py'].decode()
    for old,new in PATCHES.items():
        if text.count(old) != 1:
            raise RuntimeError('controlled_scratch_patch_match_count')
        text = text.replace(old,new)
    compile(text,'scratch_community_collector_check.py','exec')
    if args.verify_only:
        print(json.dumps({'verified_source_hashes':actual,'verified_collector_sha256':binary_sha,
                          'controlled_scratch_patch_count':len(PATCHES),'native_test_executed':False},indent=2))
        return 0
    if os.geteuid() != 0:
        raise RuntimeError('run_as_root_only_on_identified_test_vm_for_proc_diagnostics')
    dmi = hashlib.sha256(safe_read(Path('/sys/class/dmi/id/product_uuid'),4096)).hexdigest()
    if not dmi.startswith(args.dmi_prefix):
        raise RuntimeError('wrong_vm_dmi')
    OUTPUT = Path(tempfile.mkdtemp(prefix='fls-rc9-capacity-diag-',dir='/var/tmp'))
    OUTPUT.chmod(0o700)
    scratch = OUTPUT/'source'
    for name,data in sources.items():
        path = scratch/name
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(data);path.chmod(0o600)
    scratch_script = scratch/'tests/community_collector_check.py'
    scratch_script.write_text(text)
    STATE.update(source_sha256=actual,collector_sha256=binary_sha,dmi_sha256=dmi,
                 output_directory=str(OUTPUT),diagnostic_source_sha256=hashlib.sha256(text.encode()).hexdigest())
    preserved_class = tempfile.TemporaryDirectory
    class PreservedTemporaryDirectory(preserved_class):
        def cleanup(self):
            self._finalizer.detach()
    tempfile.TemporaryDirectory = PreservedTemporaryDirectory
    namespace = {'__file__':str(scratch_script),'__name__':'fls_capacity_diagnostic_scratch',
                 'fixture_diagnostic_sample':sample,'fixture_diagnostic_progress':progress,
                 'fixture_diagnostic_wait':diagnostic_wait,'fixture_diagnostic_finished':sender_finished}
    prior_argv = sys.argv
    try:
        sys.argv = [str(scratch_script),'--collector-prefix',str(args.collector_prefix)]
        exec(compile(text,str(scratch_script),'exec'),namespace)
    finally:
        sys.argv = prior_argv
    cls = namespace['CheckedWriteCollector']
    captured = []
    original_setup = cls.setUp
    def capture_setup(owner):
        original_setup(owner)
        captured.append(owner)
        STATE['fixture_paths'] = [str(owner.base), owner.injector_work.name]
        save_state()
    cls.setUp = capture_setup
    def no_force_stop_all(owner):
        for process in owner.processes:
            if process.poll() is None:
                # Failure cleanup must not change the state being diagnosed.
                STATE.setdefault('fixture_processes_left_alive',[]).append(process.pid)
        for handle in owner.handles:
            handle.close()
    def no_force_stop(owner,process):
        if process.poll() is not None:
            owner.assertEqual(process.returncode,0)
            return
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            raise AssertionError('Fixture did not stop gracefully in original 20s; left alive, never force-killed')
        owner.assertEqual(process.returncode,0)
    cls.stop_all = no_force_stop_all
    cls.stop = no_force_stop
    suite = unittest.TestSuite([cls(METHOD)])
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if captured and hasattr(captured[0], 'fault_gate'):
        try:
            sample(captured[0], 'after_test_cleanup')
        except Exception as error:
            STATE['final_sample_error'] = repr(error)
    STATE.update(total_elapsed_s=round(time.monotonic()-started,3),
                 diagnostic_recovery_checks_passed=result.wasSuccessful(),
                 original_test_passed=result.wasSuccessful() and STATE['original_30s_sender_bound_passed'] is True,
                 tests_run=result.testsRun,skipped=len(result.skipped),
                 failures=[{'test':str(test),'traceback':trace} for test,trace in result.failures],
                 errors=[{'test':str(test),'traceback':trace} for test,trace in result.errors],
                 fixture_result=namespace['RESULT'])
    STATE['classification'] = ('original_30s_bound_passed' if STATE['original_test_passed'] else
        'late_recovery_after_original_deadline_not_original_pass' if result.wasSuccessful() else
        'recovery_failed_or_incomplete_needs_source_triage')
    save_state()
    print(json.dumps({'diagnostic':str(OUTPUT/'diagnostic.json'),'classification':STATE['classification'],
                      'original_test_passed':STATE['original_test_passed'],
                      'diagnostic_recovery_checks_passed':result.wasSuccessful(),
                      'fixture_paths':STATE.get('fixture_paths'),
                      'fixture_processes_left_alive':STATE.get('fixture_processes_left_alive',[])},indent=2),flush=True)
    return 0 if STATE['original_test_passed'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(2)
