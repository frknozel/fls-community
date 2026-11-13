"""Bounded streaming backup transports. No credentials in process arguments or logs."""
import base64,contextlib,datetime as dt,ftplib,hashlib,io,os,shlex,socket,ssl,subprocess,tempfile,time,re,stat
from pathlib import Path
from zoneinfo import ZoneInfo

class TransferError(Exception):
 def __init__(self,code):self.code=code;super().__init__(code)
def digest(stream):
 h=hashlib.sha256()
 for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def archive_subdir(source_file):
 # Archive names describe UTC receive hours; browse folders by Istanbul day.
 if not re.fullmatch(r'\d{4}-\d{2}-\d{2}-\d{2}\.jsonl',source_file):raise TransferError('archive_hour_invalid')
 try:hour=dt.datetime.strptime(source_file,'%Y-%m-%d-%H.jsonl').replace(tzinfo=dt.timezone.utc).astimezone(ZoneInfo('Europe/Istanbul'))
 except ValueError:raise TransferError('archive_hour_invalid')
 return hour.strftime('%m-%Y/%d-%m-%Y/')
def calendar_parts(subdir):
 if subdir=='':return []
 if not re.fullmatch(r'\d{2}-\d{4}/\d{2}-\d{2}-\d{4}/',subdir):raise TransferError('remote_directory_invalid')
 parts=subdir.strip('/').split('/')
 try:day=dt.datetime.strptime(parts[1],'%d-%m-%Y')
 except ValueError:raise TransferError('remote_directory_invalid')
 if day.strftime('%m-%Y')!=parts[0]:raise TransferError('remote_directory_invalid')
 return parts
def archive_remote_directory(base,subdir):
 calendar_parts(subdir)
 return base.rstrip('/')+'/'+subdir if subdir else base

def ftp_tls_context(d):
 context=ssl.create_default_context()
 # Additional trust belongs to this destination only. Keep certificate lifetime,
 # hostname/IP and chain verification on for both control and data channels.
 if d.get('tls_trust_pem'):context.load_verify_locations(cadata=d['tls_trust_pem'])
 return context

def ftps_peer_certificate(d):
 # AUTH TLS verifies the actual server certificate without sending USER/PASS or
 # touching remote files. Never derive server expiry from a CA trust anchor.
 c=ftplib.FTP_TLS(context=ftp_tls_context(d))
 try:
  c.connect(d['host'],int(d['port']),timeout=10);c.auth()
  pem=ssl.DER_cert_to_PEM_cert(c.sock.getpeercert(binary_form=True))
  if len(pem)>32000:raise TransferError('tls_verification_failed')
  return pem
 finally:
  try:c.quit()
  except Exception:c.close()

class FTP:
 def __init__(self,d,secret):
  if d['protocol']=='ftps':self.c=ftplib.FTP_TLS(context=ftp_tls_context(d))
  else:self.c=ftplib.FTP()
  try:
   self.c.connect(d['host'],int(d['port']),timeout=30);self.c.login(d['username'],secret['password'])
   if d['protocol']=='ftps':self.c.prot_p()
   self.c.cwd(d['remote_path'])
  except Exception:
   self.c.close();raise
 def enter_directory(self,subdir):
  for part in calendar_parts(subdir):
   try:self.c.cwd(part)
   except ftplib.error_perm:
    try:self.c.mkd(part)
    except ftplib.error_perm:pass
    try:self.c.cwd(part)
    except Exception:raise TransferError('remote_directory_failed')
 def hash(self,name):
  h=hashlib.sha256()
  try:self.c.retrbinary('RETR '+name,h.update,1024*1024)
  except ftplib.error_perm as e:
   # Only a directory listing can establish absence; 550 may also mean access denied.
   if not str(e).startswith('550'):raise
   names=self.c.nlst()
   if name not in [n.rsplit('/',1)[-1] for n in names]:return None
   raise
  return h.hexdigest()
 def put(self,local,name):
  with open(local,'rb') as f:self.c.storbinary('STOR '+name,f,1024*1024)
 def rename(self,src,dst):self.c.rename(src,dst)
 def remove(self,name):self.c.delete(name)
 def close(self):
  try:self.c.quit()
  except Exception:self.c.close()

class SSH:
 def __init__(self,d,secret):
  import paramiko
  self.d=d;self.s=None;self.t=None;self.sock=socket.create_connection((d['host'],int(d['port'])),timeout=30)
  try:
   self.t=paramiko.Transport(self.sock);self.t.banner_timeout=30;self.t.auth_timeout=30;self.t.start_client(timeout=30)
   pin='SHA256:'+base64.b64encode(hashlib.sha256(self.t.get_remote_server_key().asbytes()).digest()).decode().rstrip('=');self.observed_host_key=pin
   if not d['host_key']:
    e=TransferError('host_key_required');e.observed_host_key=pin;raise e
   if pin!=d['host_key']:
    e=TransferError('host_key_mismatch');e.observed_host_key=pin;raise e
   if secret.get('private_key'):
    key=None
    for cls in [paramiko.Ed25519Key,paramiko.ECDSAKey,paramiko.RSAKey]:
     try:key=cls.from_private_key(io.StringIO(secret['private_key']),password=secret.get('password') or None);break
     except (paramiko.SSHException,ValueError):pass
    if key is None:raise TransferError('private_key_invalid')
    self.t.auth_publickey(d['username'],key)
   else:self.t.auth_password(d['username'],secret['password'],fallback=False)
   self.t.set_keepalive(15)
   if d['protocol']=='sftp':self.s=paramiko.SFTPClient.from_transport(self.t);self.s.get_channel().settimeout(30);self.s.chdir(d['remote_path'])
  except Exception:
   self.close();raise
 def enter_directory(self,subdir):
  parts=calendar_parts(subdir)
  if not parts:return
  if self.s:
   for part in parts:
    try:attrs=self.s.lstat(part)
    except OSError as e:
     if e.errno!=2:raise TransferError('remote_directory_failed')
     try:self.s.mkdir(part,mode=0o750)
     except OSError:pass  # A concurrent worker may have created the directory.
     attrs=self.s.lstat(part)
    if not stat.S_ISDIR(attrs.st_mode):raise TransferError('remote_directory_failed')
    self.s.chdir(part)
  else:
   base=shlex.quote(self.d['remote_path']);path=archive_remote_directory(self.d['remote_path'],subdir);full=shlex.quote(path)
   ch=self.command('test -d '+base+' && mkdir -p -- '+full+' && test -d '+full)
   try:
    if ch.recv_exit_status():raise TransferError('remote_directory_failed')
   finally:ch.close()
   self.d=dict(self.d,remote_path=path)
 def path(self,name):return self.d['remote_path']+name
 def command(self,cmd):
  ch=self.t.open_session(timeout=30);ch.settimeout(30);ch.exec_command(cmd);return ch
 def hash(self,name):
  if self.s:
   try:
    with self.s.open(name,'rb') as f:return digest(f)
   except OSError as e:
    if e.errno==2:return None
    raise
  # A fixed command and individually quoted paths; a remote checksum alone is not
  # used as evidence. Stream the remote file back through the SSH channel.
  p=shlex.quote(self.path(name));ch=self.command('if test -f '+p+'; then cat -- '+p+'; elif test ! -e '+p+'; then exit 44; else exit 45; fi')
  h=hashlib.sha256()
  try:
   while b:=ch.recv(1024*1024):h.update(b)
   code=ch.recv_exit_status()
   if code==44:return None
   if code:raise TransferError('remote_read_failed')
   return h.hexdigest()
  finally:ch.close()
 def put(self,local,name):
  if self.s:
   self.s.put(str(local),name,confirm=True);return
  ch=self.command('scp -t -- '+shlex.quote(self.path(name)))
  def ack():
   if ch.recv(1)!=b'\x00':raise TransferError('scp_rejected')
  try:
   ack();size=Path(local).stat().st_size;ch.sendall(('C0600 '+str(size)+' '+name+'\n').encode());ack()
   with open(local,'rb') as f:
    while b:=f.read(1024*1024):ch.sendall(b)
   ch.sendall(b'\x00');ack();ch.shutdown_write()
   if ch.recv_exit_status():raise TransferError('scp_failed')
  finally:ch.close()
 def rename(self,src,dst):
  if self.s:self.s.rename(src,dst);return
  ch=self.command('test ! -e '+shlex.quote(self.path(dst))+' && mv -- '+shlex.quote(self.path(src))+' '+shlex.quote(self.path(dst)))
  try:
   if ch.recv_exit_status():raise TransferError('remote_rename_failed')
  finally:ch.close()
 def remove(self,name):
  if self.s:self.s.remove(name);return
  ch=self.command('rm -- '+shlex.quote(self.path(name)))
  try:
   if ch.recv_exit_status():raise TransferError('remote_remove_failed')
  finally:ch.close()
 def close(self):
  if self.s:self.s.close()
  if self.t:self.t.close()
  self.sock.close()

class SMB:
 def __init__(self,d,secret):
  self.d=d;self.tmp=tempfile.TemporaryDirectory(prefix='fls-smb-');root=Path(self.tmp.name);self.auth=root/'auth';self.auth.write_text('username = '+d['username']+'\npassword = '+secret['password']+'\ndomain = '+d['domain_name']+'\n');self.auth.chmod(0o600)
 def run(self,command):
  d=self.d;cmd=['/usr/bin/smbclient','//'+d['host']+'/'+d['share_name'],'-p',str(d['port']),'-A',str(self.auth),'--use-kerberos=off','--client-protection=encrypt','--option=client min protocol=SMB3','-t','30','-c',command]
  return subprocess.run(cmd,capture_output=True,timeout=300)
 def enter_directory(self,subdir):
  parts=calendar_parts(subdir)
  if not parts:return
  path=self.d['remote_path'].strip('/')
  if self.run('cd "'+(path or '/')+'"').returncode:raise TransferError('remote_directory_failed')
  for part in parts:
   path=(path+'/' if path else '')+part
   if self.run('cd "'+path+'"').returncode:
    self.run('mkdir "'+path+'"')
    if self.run('cd "'+path+'"').returncode:raise TransferError('remote_directory_failed')
  self.d=dict(self.d,remote_path=path+'/')
 def remote_path(self,name):return self.d['remote_path'].strip('/')+'/'+name
 def hash(self,name):
  p=Path(self.tmp.name)/'readback';p.unlink(missing_ok=True)
  r=self.run('get "'+self.remote_path(name)+'" "'+str(p)+'"')
  if r.returncode:
   output=r.stdout+r.stderr
   if b'NT_STATUS_OBJECT_NAME_NOT_FOUND' in output:return None
   raise TransferError('smb_read_failed')
  try:
   with p.open('rb') as f:return digest(f)
  finally:p.unlink(missing_ok=True)
 def put(self,local,name):
  if self.run('put "'+str(local)+'" "'+self.remote_path(name)+'"').returncode:raise TransferError('smb_write_failed')
 def rename(self,src,dst):
  if self.run('rename "'+self.remote_path(src)+'" "'+self.remote_path(dst)+'"').returncode:raise TransferError('smb_rename_failed')
 def remove(self,name):
  if self.run('del "'+self.remote_path(name)+'"').returncode:raise TransferError('smb_remove_failed')
 def close(self):self.tmp.cleanup()

def connect(d,secret):
 if d['protocol'] in ('ftp','ftps'):return FTP(d,secret)
 if d['protocol'] in ('sftp','scp'):return SSH(d,secret)
 if d['protocol']=='smb':return SMB(d,secret)
 raise TransferError('protocol_invalid')

def deliver(remote,local,name,sha256,before_publish=lambda:contextlib.nullcontext()):
 # Never overwrite a published backup with different content. Retrying after a
 # crash reuses the same immutable filename and recognizes an existing good copy.
 present=remote.hash(name)
 if present is not None:
  if present!=sha256:raise TransferError('remote_conflict')
  return
 part=name+'.part';remote.put(local,part)
 if remote.hash(part)!=sha256:raise TransferError('remote_hash_mismatch')
 with before_publish():
  existing=remote.hash(name)
  if existing is None:remote.rename(part,name)
  elif existing!=sha256:raise TransferError('remote_conflict')
  else:remote.remove(part)
  if remote.hash(name)!=sha256:raise TransferError('remote_hash_mismatch')
