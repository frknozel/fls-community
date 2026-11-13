#!/usr/bin/python3
"""Apply explicit collection maintenance requests. Never reads logs or calls a firewall."""
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

import pymysql

UNIT='fortigate-collector.service'
STATE=Path('/var/lib/fls-maintenance')
CREDENTIAL=Path('/etc/fls/maintenance-database.json')
TRANSITION_SECONDS=8
STATES={'unknown','active','inactive','failed','activating','deactivating'}

class MaintenanceError(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)

def strict_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise MaintenanceError('config_invalid')
            result[key]=value
        return result
    try:
        if len(data)>16384:raise MaintenanceError('config_invalid')
        return json.loads(data,object_pairs_hook=pairs)
    except (ValueError,TypeError,UnicodeError,RecursionError) as exc:
        if isinstance(exc,MaintenanceError):raise
        raise MaintenanceError('config_invalid') from exc

def read_config(path):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            # systemd credentials can be root:root 0440 in a private mount.
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or info.st_mode&0o037 or info.st_size>16384:raise MaintenanceError('config_permissions')
            value=strict_json(stream.read(16385))
    except OSError as exc:raise MaintenanceError('config_unavailable') from exc
    if not isinstance(value,dict) or set(value)!={'user','password'} or value.get('user')!='fls_maintenance' or not isinstance(value.get('password'),str) or not 16<=len(value['password'])<=512:raise MaintenanceError('config_invalid')
    return value

class Marker:
    """Production caller always uses root ownership; uid injection is fixture-only."""
    def __init__(self,folder=STATE,uid=0):self.folder=Path(folder);self.path=self.folder/'paused';self.uid=uid
    def directory(self):
        try:info=self.folder.lstat()
        except OSError as exc:raise MaintenanceError('marker_unsafe') from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.uid or stat.S_IMODE(info.st_mode)!=0o700:raise MaintenanceError('marker_unsafe')
    def present(self):
        self.directory()
        try:info=self.path.lstat()
        except FileNotFoundError:return False
        except OSError as exc:raise MaintenanceError('marker_io') from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=self.uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise MaintenanceError('marker_unsafe')
        return True
    def sync(self):
        directory=os.open(self.folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    def pause(self):
        if self.present():return
        fd,temp=tempfile.mkstemp(prefix='.paused-',dir=self.folder)
        try:
            with os.fdopen(fd,'wb') as stream:
                os.fchmod(stream.fileno(),0o600);stream.write(b'FLS collection is paused.\n');stream.flush();os.fsync(stream.fileno())
            # Root-private directory and the worker flock serialize publication.
            os.replace(temp,self.path);self.sync()
            if not self.present():raise MaintenanceError('marker_io')
        except OSError as exc:raise MaintenanceError('marker_io') from exc
        finally:
            try:os.unlink(temp)
            except FileNotFoundError:pass
    def resume(self):
        if self.present():
            try:self.path.unlink();self.sync()
            except OSError as exc:raise MaintenanceError('marker_io') from exc
        if self.present():raise MaintenanceError('marker_io')
    def visible(self):
        # An unsafe symlink/directory is reported as present without following it.
        try:self.path.lstat();return True
        except OSError:return False

class AttemptJournal:
    """Root-private write-ahead record; SQL rollback cannot erase an attempted start."""
    def __init__(self,marker):self.marker=marker;self.path=marker.folder/'attempt.json'
    def read(self):
        self.marker.directory()
        try:fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        except FileNotFoundError:return 0
        except OSError as exc:raise MaintenanceError('journal_unsafe') from exc
        try:
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=self.marker.uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>1024:raise MaintenanceError('journal_unsafe')
                value=strict_json(stream.read(1025))
            if not isinstance(value,dict) or set(value)!={'schema','attempted_revision'} or type(value['schema']) is not int or value['schema']!=1 or type(value['attempted_revision']) is not int or not 1<=value['attempted_revision']<=2**32-1:raise MaintenanceError('journal_invalid')
            return value['attempted_revision']
        except MaintenanceError as exc:
            if exc.code.startswith('journal_'):raise
            raise MaintenanceError('journal_invalid') from exc
        except OSError as exc:raise MaintenanceError('journal_io') from exc
    def record(self,revision):
        current=self.read()
        if current>revision:raise MaintenanceError('journal_conflict')
        if current==revision:return
        fd,temp=tempfile.mkstemp(prefix='.attempt-',dir=self.marker.folder)
        try:
            with os.fdopen(fd,'wb') as stream:
                os.fchmod(stream.fileno(),0o600)
                stream.write((json.dumps({'schema':1,'attempted_revision':revision},sort_keys=True,separators=(',',':'))+'\n').encode())
                stream.flush();os.fsync(stream.fileno())
            os.replace(temp,self.path);self.marker.sync()
            if self.read()!=revision:raise MaintenanceError('journal_io')
        except OSError as exc:raise MaintenanceError('journal_io') from exc
        finally:
            try:os.unlink(temp)
            except FileNotFoundError:pass
    def clear_committed(self,attempted_revision):
        current=self.read()
        if current and current<=attempted_revision:
            try:self.path.unlink();self.marker.sync()
            except OSError as exc:raise MaintenanceError('journal_io') from exc


class Systemd:
    def __init__(self,runner=subprocess.run,clock=time.monotonic):self.runner=runner;self.clock=clock
    def command(self,args,deadline):
        remaining=deadline-self.clock()
        if remaining<=0:raise MaintenanceError('command_timeout')
        try:
            result=self.runner(['/usr/bin/systemctl','--system','--no-pager',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=min(1.5,remaining),check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','SYSTEMD_PAGER':''})
        except subprocess.TimeoutExpired as exc:raise MaintenanceError('command_timeout') from exc
        except OSError as exc:raise MaintenanceError('command_failed') from exc
        if result.returncode!=0 or len(result.stdout)>4096:raise MaintenanceError('command_failed')
        return result.stdout
    def observe(self,deadline):
        raw=self.command(['show','--property=LoadState','--property=ActiveState','--property=SubState',UNIT],deadline)
        try:
            pairs=[line.split('=',1) for line in raw.decode('ascii').splitlines() if line]
            if any(len(pair)!=2 for pair in pairs):raise ValueError()
            data=dict(pairs)
            if len(data)!=len(pairs) or set(data)!={'LoadState','ActiveState','SubState'} or data['LoadState']!='loaded':raise ValueError()
            state=data['ActiveState']
            if state=='active' and data['SubState']!='running':return 'unknown'
            return state if state in STATES else 'unknown'
        except (ValueError,UnicodeError):raise MaintenanceError('state_unavailable')
    def change(self,mode,deadline):
        self.command(['--no-block','stop' if mode=='paused' else 'start',UNIT],deadline)

def valid_request(request,state):
    if not isinstance(request,dict) or request.get('requested_mode') not in ('normal','paused') or type(request.get('revision')) is not int or not 1<=request['revision']<=2**32-1:raise MaintenanceError('request_invalid')
    for field in ('applied_revision','attempted_revision'):
        if type(state.get(field)) is not int or not 0<=state[field]<=request['revision']:raise MaintenanceError('state_invalid')
    if state['applied_revision']>state['attempted_revision']:raise MaintenanceError('state_invalid')

def apply_request(request,previous,marker,system,clock=time.monotonic,sleep=time.sleep,journal=None):
    """Return observed truth; a failed normal attempt requires a newer explicit request."""
    result={'applied_revision':previous.get('applied_revision',0),'attempted_revision':previous.get('attempted_revision',0),'collector_state':'unknown','marker_present':False,'error_code':'','newly_applied':False}
    deadline=clock()+TRANSITION_SECONDS
    desired=None;journal=journal or AttemptJournal(marker)
    try:
        valid_request(request,previous);desired=request['requested_mode'];revision=request['revision']
        previous_attempt=result['attempted_revision']
        # A handled request publishes its error against the current revision,
        # even if observation/journal validation fails before any OS action.
        # New-attempt authorization still uses only the previous SQL/journal.
        result['attempted_revision']=revision
        if desired=='paused':marker.pause()
        durable_attempt=journal.read()
        if durable_attempt>revision:raise MaintenanceError('journal_conflict')
        new_attempt=revision>max(previous_attempt,durable_attempt)
        result['marker_present']=marker.present()
        current=system.observe(deadline);result['collector_state']=current
        matches=lambda:result['collector_state']==('inactive' if desired=='paused' else 'active') and result['marker_present']==(desired=='paused')
        if desired=='normal':
            # Observe first: a crashed prior normal transition may already have
            # completed. Never restart an externally stopped applied revision.
            if current=='active' and not result['marker_present']:
                result['attempted_revision']=max(result['attempted_revision'],revision)
            elif not new_attempt:
                if current in ('activating','deactivating'):result['error_code']='transition_pending'
                elif current=='unknown':result['error_code']='state_unavailable'
                elif result['applied_revision']<revision:
                    previous_error=previous.get('error_code','')
                    result['error_code']=previous_error if previous_error in ('command_failed','command_timeout','marker_unsafe','marker_io','state_unavailable') else 'transition_failed'
                else:result['error_code']=''
                return result
            else:
                # Persist before removing the boot guard or submitting a start.
                # A crash/rollback after either action must not replay this revision.
                journal.record(revision);result['attempted_revision']=revision
                marker.resume();result['marker_present']=marker.present()
                if current!='active':system.change(desired,deadline)
        elif current!='inactive':system.change(desired,deadline)
        while not matches() and clock()<deadline:
            sleep(min(0.2,max(0,deadline-clock())))
            if clock()>=deadline:break
            result['collector_state']=system.observe(deadline);result['marker_present']=marker.present()
        if matches():
            result['newly_applied']=result['applied_revision']!=revision
            result['applied_revision']=revision;result['error_code']=''
        else:result['error_code']='transition_pending'
    except MaintenanceError as exc:
        result['error_code']=exc.code;result['marker_present']=marker.visible()
        # A queued command can complete after its client timed out. A final
        # bounded observation reports its actual state without claiming apply.
        if clock()<deadline:
            try:result['collector_state']=system.observe(deadline)
            except MaintenanceError:pass
        if exc.code.startswith('marker_') or desired=='paused':
            # Keep unknown/unsafe pause evidence in place; never remove it or start.
            if clock()<deadline:
                try:
                    system.change('paused',deadline)
                    if clock()<deadline:result['collector_state']=system.observe(deadline)
                except MaintenanceError:pass
    return result

class Store:
    def __init__(self,db):self.db=db
    def begin(self):
        self.db.begin()
        with self.db.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute('SELECT requested_mode,revision FROM maintenance_requests WHERE id=1 FOR UPDATE');request=cursor.fetchone()
            cursor.execute('SELECT version,applied_revision,attempted_revision,collector_state,marker_present,error_code FROM maintenance_state WHERE id=1 FOR UPDATE');state=cursor.fetchone()
        if not state or state.get('version')!=1:raise MaintenanceError('state_invalid')
        return request,state
    def publish(self,result):
        with self.db.cursor() as cursor:
            cursor.execute('UPDATE maintenance_state SET version=1,applied_revision=%s,attempted_revision=%s,collector_state=%s,marker_present=%s,checked_at=UTC_TIMESTAMP(6),applied_at='+('UTC_TIMESTAMP(6)' if result['newly_applied'] else 'applied_at')+',error_code=%s WHERE id=1',(result['applied_revision'],result['attempted_revision'],result['collector_state'],int(result['marker_present']),result['error_code']))
        self.db.commit()
    def rollback(self):self.db.rollback()

def run_once(store,marker,system,clock=time.monotonic,sleep=time.sleep):
    journal=AttemptJournal(marker)
    try:
        request,state=store.begin();result=apply_request(request,state,marker,system,clock,sleep,journal);store.publish(result)
        # Do not erase malformed/future evidence. Clear only after SQL commit
        # proves that this attempt revision has been durably recorded there.
        if not result['error_code'].startswith('journal_'):journal.clear_committed(result['attempted_revision'])
        return result
    except BaseException:store.rollback();raise

def main():
    if os.geteuid()!=0:raise MaintenanceError('root_required')
    credentials=os.environ.get('CREDENTIALS_DIRECTORY');config=read_config(Path(credentials)/'maintenance-database.json' if credentials else CREDENTIAL)
    marker=Marker();marker.directory()
    lock=os.open(STATE/'worker.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise MaintenanceError('lock_unsafe')
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'status':'busy'}
        db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user=config['user'],password=config['password'],database='fls',charset='utf8mb4',autocommit=False,connect_timeout=3,read_timeout=3,write_timeout=3)
        try:
            with db.cursor() as cursor:cursor.execute('SET SESSION innodb_lock_wait_timeout=2')
            return run_once(Store(db),marker,Systemd())
        finally:db.close()
    finally:os.close(lock)

if __name__=='__main__':
    try:
        result=main();print(json.dumps(result));raise SystemExit(1 if result.get('error_code') else 0)
    except Exception as exc:
        print(json.dumps({'error_code':exc.code if isinstance(exc,MaintenanceError) else 'worker_unavailable'}));raise SystemExit(1)
