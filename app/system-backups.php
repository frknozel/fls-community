<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
require_once __DIR__.'/backup-encryption.php';
require_once __DIR__.'/backup-schedule.php';

const SYSTEM_BACKUPS_JS_MAX=9007199254740991;
const SYSTEM_BACKUPS_DIRECTORY='/var/lib/fls-recovery-download';

function system_backups_number(mixed $value,int $minimum=0,int $maximum=SYSTEM_BACKUPS_JS_MAX): ?int {
 if(!is_int($value)&&(!is_string($value)||!preg_match('/^(?:0|[1-9][0-9]{0,15})$/D',$value)))return null;
 $n=filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>$minimum,'max_range'=>$maximum]]);return $n===false?null:$n;
}
function system_backups_int(array $data,string $key,int $minimum=1,int $maximum=SYSTEM_BACKUPS_JS_MAX): int {
 $value=system_backups_number($data[$key]??null,$minimum,$maximum);if($value===null)throw new ManagementError('Yedekleme istek bilgisi geçersiz.');return $value;
}
function system_backups_uuid(mixed $value): bool {return is_string($value)&&preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D',$value)===1;}
function system_backups_time(mixed $value): ?string {
 if($value===null)return null;
 if(!is_string($value)||!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/D',$value))throw new ManagementError('Yedekleme durumu okunamadı.',503);
 try{$at=new DateTimeImmutable($value,new DateTimeZone('UTC'));$e=DateTimeImmutable::getLastErrors();if($e&&($e['warning_count']||$e['error_count']))throw new RuntimeException();return $value;}catch(Throwable $e){throw new ManagementError('Yedekleme durumu okunamadı.',503);}
}
function system_backups_text(mixed $value,int $maximum): string {
 if(!is_string($value)||!mb_check_encoding($value,'UTF-8')||mb_strlen($value)>$maximum||preg_match('/[\x00-\x1f\x7f]/u',$value))throw new ManagementError('Yedekleme durumu okunamadı.',503);return $value;
}
function system_backups_error(mixed $value): string {return is_string($value)&&preg_match('/^[a-z0-9_]{0,64}$/D',$value)?$value:'state_invalid';}
function system_backups_path(mixed $value): string {
 if(!is_string($value)||strlen($value)>401||preg_match('/[^A-Za-z0-9_ .()\/-]/D',$value))throw new ManagementError('Klasör yolu en fazla 400 karakter olmalı; harf, rakam, boşluk, /, _, -, nokta ve parantez kullanılabilir.');
 $value=trim($value);if(str_ends_with($value,'/'))$value=substr($value,0,-1);
 if($value===''||strlen($value)>400||str_starts_with($value,'/')||str_ends_with($value,'/'))throw new ManagementError('Klasör yolunu kök klasöre göre, başında / olmadan girin.');
 foreach(explode('/',$value) as $part)if($part===''||$part==='.'||$part==='..'||trim($part)!==$part||str_ends_with($part,'.'))throw new ManagementError('Klasör bölümleri boş olamaz; . veya .., başında/sonunda boşluk ya da sonunda nokta kullanılamaz.');
 return $value;
}
function system_backups_fields(array $data,array $allowed): void {
 foreach($data as $key=>$value)if(!in_array($key,[...$allowed,'_csrf'],true)||(!is_string($value)&&!is_int($value)))throw new ManagementError('Yedekleme isteğinde bilinmeyen veya geçersiz alan var.');
 if(array_key_exists('_csrf',$data)&&!is_string($data['_csrf']))throw new ManagementError('Oturum doğrulaması başarısız.',403);
}
/** Current user gates apply even when helpers are called outside the HTTP adapter. */
function system_backups_admin(string $method,bool $lock=false): array {
 if(($_SERVER['REQUEST_METHOD']??'')!==$method){header('Allow: '.$method);throw new ManagementError('Bu işlem için '.$method.' kullanılmalı.',405);}
 $uid=system_backups_number($_SESSION['uid']??null,1,4294967295);$session=system_backups_number($_SESSION['session_version']??null,0,4294967295);
 if($uid===null)throw new ManagementError('Oturum açmanız gerekiyor.',401);
 if(($_SESSION['role']??'')!=='admin'||$session===null)throw new ManagementError('Sistem yedekleme yönetici yetkisi gerektirir.',403);
 $actor=query('SELECT id,username,role,enabled,session_version,must_change FROM users WHERE id=?'.($lock?' FOR UPDATE':''),[$uid])[0]??null;
 if(!$actor||$actor['role']!=='admin'||(int)$actor['enabled']!==1||(int)$actor['session_version']!==$session||(int)$actor['must_change']!==0)throw new ManagementError('Yönetim yetkiniz değişti.',403);
 return $actor;
}
function system_backups_settings(array $row): array {
 $id=system_backups_number($row['id']??null,1,1);$revision=system_backups_number($row['revision']??null,1,4294967295);$destination=($row['destination_id']??null)===null?null:system_backups_number($row['destination_id'],1,4294967295);
 if($id===null||$revision===null||(($row['destination_id']??null)!==null&&$destination===null))throw new ManagementError('Yedekleme ayarları hazır değil.',503);
 return ['id'=>$id,'revision'=>$revision,'destination_id'=>$destination,'db_dump_directory'=>system_backups_text($row['db_dump_directory']??null,400),'system_backup_directory'=>system_backups_text($row['system_backup_directory']??null,400),'updated_at'=>system_backups_time($row['updated_at']??null),'updated_by'=>system_backups_text($row['updated_by']??null,64)];
}
function system_backups_job(array $row): array {
 $out=[];foreach(['id','requested_by_uid','requested_session_version','backup_id','settings_revision','destination_id','destination_revision'] as $key){$raw=$row[$key]??null;$out[$key]=$raw===null&&in_array($key,['backup_id','destination_id'],true)?null:system_backups_number($raw,in_array($key,['id','requested_by_uid','backup_id','destination_id'],true)?1:0);if($out[$key]===null&&!($raw===null&&in_array($key,['backup_id','destination_id'],true)))throw new ManagementError('Yedekleme iş durumu okunamadı.',503);}
 if(!system_backups_uuid($row['request_key']??null)||!in_array($row['action']??null,['create','upload'],true)||!in_array($row['status']??null,['queued','running','succeeded','failed'],true))throw new ManagementError('Yedekleme iş durumu okunamadı.',503);
 $out['request_key']=$row['request_key'];$out['action']=$row['action'];$out['status']=$row['status'];$out['requested_by']=system_backups_text($row['requested_by']??null,64);
 foreach(['requested_at','started_at','completed_at'] as $key)$out[$key]=system_backups_time($row[$key]??null);
 $out['error_code']=system_backups_error($row['error_code']??null);$out['remote_directory']=system_backups_text($row['remote_directory']??null,850);
 $sha=$row['remote_sha256']??null;$out['remote_sha256']=is_string($sha)&&preg_match('/^(?:[a-f0-9]{64})?$/D',$sha)?$sha:'';
 return $out;
}
function system_backups_daily_age(array $daily,?DateTimeImmutable $now=null): array {
 $now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));
 foreach(['create'=>'23:00','upload'=>'23:35'] as $action=>$clock){
  $due=operations_last_due($now,$clock);$sourceDue=$action==='upload'?operations_last_due($due,'23:00'):$due;
  $row=$daily[$action]??null;$state=operations_job_state($row,$sourceDue,$now);
  if($action==='upload'&&$state==='overdue'&&$now<$due->modify('+30 minutes'))$state='waiting';
  if($action==='upload'&&$state==='current'&&($row['readback_sha256_verified']??false)!==true)$state='unknown';
  if(is_array($row)){$daily[$action]['age_state']=$state;$daily[$action]['due_at_utc']=$due->format('Y-m-d\TH:i:s\Z');}
 }
 return $daily;
}
function system_backups_worker(?array $row): array {
 $out=['id'=>1,'version'=>null,'checked_at'=>null,'status'=>'error','error_code'=>'worker_unavailable','job_id'=>null,'available'=>false];if(!$row)return $out;
 $out['version']=system_backups_number($row['version']??null,1,4294967295);$out['checked_at']=system_backups_time($row['checked_at']??null);$out['status']=in_array($row['status']??null,['idle','creating','uploading','error'],true)?$row['status']:'error';$out['error_code']=system_backups_error($row['error_code']??null);$out['job_id']=($row['job_id']??null)===null?null:system_backups_number($row['job_id'],1);
 if($out['checked_at']!==null){$age=microtime(true)-(float)(new DateTimeImmutable($out['checked_at'],new DateTimeZone('UTC')))->format('U.u');$out['available']=$out['version']===1&&in_array($row['status']??null,['idle','creating','uploading','error'],true)&&$out['error_code']!=='state_invalid'&&$age>=-5&&$age<=(in_array($out['status'],['creating','uploading'],true)?1800:45);}
 return $out;
}
/** Read-only, root-published daily backup status; never starts a job. */
function system_backups_db_dump(): array {
 $enabled=true;foreach(['fls-db-dump.timer','fls-db-dump-upload.timer'] as $unit){$link='/etc/systemd/system/timers.target.wants/'.$unit;if(!is_link($link)||realpath($link)!=='/etc/systemd/system/'.$unit)$enabled=false;}
 $out=['enabled'=>$enabled,'timezone'=>'Europe/Istanbul','create_time'=>'23:00','upload_time'=>'23:35','retained_calendar_days'=>7,'create'=>null,'upload'=>null];
 $path='/var/lib/fls-db-dump/status.json';$parent=@lstat(dirname($path));$before=@lstat($path);
 if(!$parent||($parent['mode']&0170000)!==0040000||$parent['uid']!==0||($parent['mode']&0007)!==0||($parent['mode']&0022)!==0||!$before||($before['mode']&0170000)!==0100000||$before['uid']!==0||($before['mode']&0037)!==0||$before['nlink']!==1||$before['size']<1||$before['size']>65536)return $out;
 $text=@file_get_contents($path);$after=@lstat($path);if(!is_string($text)||!$after||$before['ino']!==$after['ino']||$before['dev']!==$after['dev']||$before['size']!==$after['size'])return $out;
 try{$value=json_decode($text,true,16,JSON_THROW_ON_ERROR);}catch(Throwable $e){return $out;}if(!is_array($value)||($value['schema']??null)!=='fls-configuration-db-dump-v1')return $out;
 foreach(['create','upload'] as $action){$row=$value[$action]??null;if(!is_array($row)||!in_array($row['status']??null,['running','succeeded','failed'],true))continue;$safe=['status'=>$row['status']];foreach(['started_at_utc','completed_at_utc','snapshot_at_utc'] as $key){$time=$row[$key]??null;if(is_string($time)&&preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$/D',$time))$safe[$key]=$time;}$safe['error_code']=system_backups_error($row['error_code']??'');$filename=$row['filename']??null;if(is_string($filename)&&preg_match('/^fls-db-[a-f0-9]{12}-\d{4}-\d{2}-\d{2}(?:-\d{8}T\d{12}Z-[a-f0-9]{16})?\.sql\.gz$/D',$filename))$safe['filename']=$filename;if($action==='upload')$safe['readback_sha256_verified']=($row['readback_sha256_verified']??false)===true;$out[$action]=$safe;}
 return system_backups_daily_age($out);
}
function system_backups_snapshot(): array {
 system_backups_admin('GET');
 try{
  $raw=query('SELECT * FROM system_backup_settings WHERE id=1')[0]??null;if(!$raw)throw new ManagementError('Yedekleme ayarları hazır değil.',503);$settings=system_backups_settings($raw);
  $destinations=query("SELECT id,name,protocol,host,port,remote_path,enabled,revision,check_status,checked_revision FROM archive_destinations WHERE protocol='ftps' ORDER BY id");
  foreach($destinations as &$d){foreach(['id','port','enabled','revision','checked_revision'] as $key){$d[$key]=$d[$key]===null?null:system_backups_number($d[$key],$key==='enabled'?0:1,$key==='enabled'?1:4294967295);if($d[$key]===null&&$key!=='checked_revision')throw new ManagementError('Yedekleme hedefi okunamadı.',503);}foreach(['name'=>100,'host'=>253,'remote_path'=>400,'check_status'=>24] as $key=>$maximum)$d[$key]=system_backups_text($d[$key],$maximum);}unset($d);
  $jobs=array_map('system_backups_job',query('SELECT * FROM system_backup_jobs ORDER BY id DESC LIMIT 25'));$active=query("SELECT * FROM system_backup_jobs WHERE status IN ('queued','running') ORDER BY id LIMIT 1")[0]??null;$active=$active?system_backups_job($active):null;
  $backups=query('SELECT * FROM system_backups ORDER BY id DESC LIMIT 25');
  foreach($backups as &$b){
   foreach(['id','bytes'] as $key){$b[$key]=system_backups_number($b[$key],1);if($b[$key]===null)throw new ManagementError('Yedek kaydı okunamadı.',503);}
   if(!is_string($b['filename'])||!preg_match('/^fls-system-\d{8}-\d{6}Z\.tar\.gz$/D',$b['filename'])||!is_string($b['sha256'])||!preg_match('/^[a-f0-9]{64}$/D',$b['sha256'])||!in_array($b['status'],['ready','missing'],true))throw new ManagementError('Yedek kaydı okunamadı.',503);
   $b=array_intersect_key($b,array_flip(['id','filename','bytes','sha256','status','created_at','verified_at','created_by']));foreach(['created_at','verified_at'] as $key)$b[$key]=system_backups_time($b[$key]);$b['created_by']=system_backups_text($b['created_by'],64);
   $url='/api.php?route=system_backup_file&id='.$b['id'];$b['download_url']=$url;$b['checksum_url']=$url.'&part=sha256';$b['report_url']=$url.'&part=report';$b['encrypted_copies']=backup_encryption_companions($b);
   $upload=query("SELECT status,completed_at,error_code,remote_directory,destination_id,destination_revision FROM system_backup_jobs WHERE action='upload' AND backup_id=? ORDER BY id DESC LIMIT 1",[$b['id']])[0]??null;
   if($upload){foreach(['destination_id','destination_revision'] as $key)$upload[$key]=system_backups_number($upload[$key],1);$upload['completed_at']=system_backups_time($upload['completed_at']);$upload['error_code']=system_backups_error($upload['error_code']);$upload['remote_directory']=system_backups_text($upload['remote_directory'],850);}$b['last_upload']=$upload;
  }unset($b);
  $dbDump=system_backups_db_dump();
  return ['settings'=>$settings,'destinations'=>$destinations,'backups'=>$backups,'jobs'=>$jobs,'active_job'=>$active,'worker'=>system_backups_worker(query('SELECT * FROM system_backup_worker WHERE id=1')[0]??null),'db_dump_schedule_enabled'=>$dbDump['enabled'],'db_dump'=>$dbDump,'encryption'=>backup_encryption_state()];
 }catch(PDOException $e){if((int)($e->errorInfo[1]??0)===1146)throw new ManagementError('Sistem yedekleme henüz hazır değil.',503);throw $e;}
}
function system_backups_write(string $route,array $data): array {
 system_backups_admin('POST');$token=$data['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||$token===''||!is_string($_SESSION['csrf']??null)||$_SESSION['csrf']===''||!hash_equals($_SESSION['csrf'],$token))throw new ManagementError('Oturum doğrulaması başarısız.',403);
 if($route!=='save_system_backup_settings'&&backup_encryption_state()['status']==='error')throw new ManagementError('Yedek şifreleme durumu doğrulanamadı. Yönetici yapılandırmayı kontrol etmeli.',503);
 $settingsRoute=$route==='save_system_backup_settings';$action=match($route){'create_system_backup'=>'create','upload_system_backup'=>'upload','save_system_backup_settings'=>'',default=>throw new ManagementError('Yedekleme işlemi bulunamadı.',404)};
 system_backups_fields($data,$settingsRoute?['revision','destination_id','db_dump_directory','system_backup_directory']:($action==='create'?['request_key']:['request_key','backup_id','settings_revision','destination_id','destination_revision']));
 $key=$data['request_key']??null;if(!$settingsRoute&&!system_backups_uuid($key))throw new ManagementError('Yedekleme istek kimliği geçersiz.');
 $destinationId=null;$backupId=null;
 if($settingsRoute){$revision=system_backups_int($data,'revision',1,4294967294);$destinationId=($data['destination_id']??null)===''?null:system_backups_int($data,'destination_id',1,4294967295);$dump=system_backups_path($data['db_dump_directory']??null);$system=system_backups_path($data['system_backup_directory']??null);$lowerDump=strtolower($dump);$lowerSystem=strtolower($system);if($lowerDump===$lowerSystem||str_starts_with($lowerDump,$lowerSystem.'/')||str_starts_with($lowerSystem,$lowerDump.'/'))throw new ManagementError('DB Dump ve sistem yedeği klasörleri ayrı olmalı; biri diğerinin içinde olamaz.');}
 elseif($action==='upload'){$backupId=system_backups_int($data,'backup_id');$revision=system_backups_int($data,'settings_revision',1,4294967295);$destinationId=system_backups_int($data,'destination_id',1,4294967295);$destinationRevision=system_backups_int($data,'destination_revision',1,4294967295);}
 $pdo=db();$previous=(int)query('SELECT @@SESSION.innodb_lock_wait_timeout value')[0]['value'];$pdo->exec('SET SESSION innodb_lock_wait_timeout=5');
 try{
  $pdo->beginTransaction();if(!query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE'))throw new ManagementError('Yedekleme yönetimi hazır değil.',503);
  $actor=system_backups_admin('POST',true);$raw=query('SELECT * FROM system_backup_settings WHERE id=1 FOR UPDATE')[0]??null;if(!$raw)throw new ManagementError('Yedekleme ayarları hazır değil.',503);$settings=system_backups_settings($raw);
  $destination=$destinationId===null?null:(query('SELECT id,protocol,revision,enabled,check_status,checked_revision,remote_path FROM archive_destinations WHERE id=? FOR UPDATE',[$destinationId])[0]??null);
  if($settingsRoute){
   if($settings['revision']!==$revision)throw new ManagementError('Yedekleme ayarı başka bir oturumda değişti. Ekranı yenileyin.',409);
   if($destinationId!==null&&(!$destination||$destination['protocol']!=='ftps'))throw new ManagementError('Yedekleme için tanımlı bir FTPS hedefi seçin.');
   execute('UPDATE system_backup_settings SET destination_id=?,db_dump_directory=?,system_backup_directory=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6),updated_by=? WHERE id=1',[$destinationId,$dump,$system,$actor['username']]);audit('system_backup_settings','revision='.$revision.'->'.($revision+1).';destination_id='.($destinationId??'none'));
   $saved=system_backups_settings(query('SELECT * FROM system_backup_settings WHERE id=1')[0]);$pdo->commit();return ['saved'=>true,'settings'=>$saved];
  }
  $existing=query('SELECT * FROM system_backup_jobs WHERE request_key=? FOR UPDATE',[$key])[0]??null;
  if($existing){
   if((int)$existing['requested_by_uid']!==(int)$actor['id']||$existing['action']!==$action||($action==='upload'&&((int)$existing['backup_id']!==$backupId||(int)$existing['settings_revision']!==$revision||(int)$existing['destination_id']!==$destinationId||(int)$existing['destination_revision']!==$destinationRevision)))throw new ManagementError('Bu istek kimliği başka bir yedekleme işlemi için kullanılmış.',409);
   $job=system_backups_job($existing);$pdo->commit();return ['saved'=>true,'job'=>$job,'duplicate'=>true,'http_status'=>202];
  }
  if(!system_backups_worker(query('SELECT * FROM system_backup_worker WHERE id=1')[0]??null)['available'])throw new ManagementError('Yedekleme hizmeti şu anda hazır değil. Durumu yenileyin.',503);
  if(query("SELECT id FROM system_backup_jobs WHERE status IN ('queued','running') ORDER BY id LIMIT 1 FOR UPDATE"))throw new ManagementError('Başka bir sistem yedekleme işlemi sürüyor. Tamamlanmasını bekleyin.',409);
  $remote='';
  if($action==='upload'){
   if($settings['revision']!==$revision||$settings['destination_id']!==$destinationId)throw new ManagementError('Yedekleme hedefi veya klasör ayarı değişti. Ekranı yenileyin.',409);
   if(!$destination||$destination['protocol']!=='ftps'||(int)$destination['enabled']!==1||$destination['check_status']!=='ok'||(int)$destination['checked_revision']!==(int)$destination['revision']||(int)$destination['revision']!==$destinationRevision)throw new ManagementError('FTPS hedefi güncel ve doğrulanmış olmalı. Hedef ayarlarını kontrol edin.',409);
   $backup=query('SELECT id,status FROM system_backups WHERE id=?',[$backupId])[0]??null;if(!$backup||$backup['status']!=='ready')throw new ManagementError('İndirilebilir sistem yedeği bulunamadı.',404);
   $directory=system_backups_path($settings['system_backup_directory']);$remote=rtrim(system_backups_text($destination['remote_path'],400),'/').'/'.$directory.'/';
  }
  execute('INSERT INTO system_backup_jobs(request_key,action,requested_by_uid,requested_session_version,requested_by,backup_id,settings_revision,destination_id,destination_revision,remote_directory) VALUES(?,?,?,?,?,?,?,?,?,?)',[$key,$action,(int)$actor['id'],(int)$actor['session_version'],$actor['username'],$backupId,$action==='upload'?$revision:0,$action==='upload'?$destinationId:null,$action==='upload'?$destinationRevision:0,$remote]);$id=(int)$pdo->lastInsertId();
  audit('system_backup_request','action='.$action.';job_id='.$id.';backup_id='.($backupId??'none').';destination_id='.($action==='upload'?$destinationId:'none').';request_key='.$key);$job=system_backups_job(query('SELECT * FROM system_backup_jobs WHERE id=?',[$id])[0]);$pdo->commit();return ['saved'=>true,'job'=>$job,'duplicate'=>false,'http_status'=>202];
 }catch(PDOException $e){if($pdo->inTransaction())$pdo->rollBack();$code=(int)($e->errorInfo[1]??0);if($code===1146)throw new ManagementError('Sistem yedekleme henüz hazır değil.',503);if(in_array($code,[1205,1213,1062],true))throw new ManagementError('Başka bir yedekleme işlemi sürüyor. Durumu yenileyin.',409);throw $e;}
 catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
 finally{try{$pdo->exec('SET SESSION innodb_lock_wait_timeout='.$previous);}catch(Throwable $e){error_log('FLS system backup lock timeout restore failed');}}
}
function system_backups_download(): never {
 system_backups_admin('GET');foreach($_GET as $key=>$value)if(!in_array($key,['route','id','part','key_id'],true)||!is_string($value))throw new ManagementError('İndirme isteği geçersiz.');$id=system_backups_int($_GET,'id');$part=$_GET['part']??'archive';
 $encrypted=in_array($part,['encrypted','encrypted_sha256','encryption_report'],true);if(!in_array($part,['archive','sha256','report','encrypted','encrypted_sha256','encryption_report'],true)||(!$encrypted&&isset($_GET['key_id']))||($encrypted&&!backup_encryption_key_id($_GET['key_id']??null)))throw new ManagementError('İndirme bölümü geçersiz.');
 $row=query("SELECT filename,bytes,sha256 FROM system_backups WHERE id=? AND status='ready'",[$id])[0]??null;
 if(!$row||!is_string($row['filename'])||!preg_match('/^fls-system-\d{8}-\d{6}Z\.tar\.gz$/D',$row['filename'])||!is_string($row['sha256'])||!preg_match('/^[a-f0-9]{64}$/D',$row['sha256'])||system_backups_number($row['bytes'],1)===null)throw new ManagementError('Doğrulanmış sistem yedeği bulunamadı.',404);
 $stream=null;
 try{
  $directory=recovery_download_directory(SYSTEM_BACKUPS_DIRECTORY);$body=null;$archiveSha=$row['sha256'];$name=$row['filename'];$expected=(int)$row['bytes'];
  if($encrypted){$copy=backup_encryption_companion(['id'=>$id]+$row,$_GET['key_id']);$name=$copy['filename'];$expected=$copy['bytes'];$archiveSha=$copy['sha256'];}
  $checksum=in_array($part,['sha256','encrypted_sha256'],true);$report=in_array($part,['report','encryption_report'],true);
  if($checksum){$body=$archiveSha.'  '.$name."\n";$name.='.sha256';$size=strlen($body);$sha=hash('sha256',$body);}
  else{
   if($report)$name.=$encrypted?'.encryption.json':'.verification.json';
   $stream=recovery_download_open(SYSTEM_BACKUPS_DIRECTORY.'/'.$name,$directory['gid'],$report?4194304:$expected,$report?null:$expected);
   @set_time_limit(0);$before=fstat($stream);$hash=hash_init('sha256');$read=hash_update_stream($hash,$stream);$sha=hash_final($hash);$after=fstat($stream);
   if(!$before||!$after||$read!==$before['size']||!recovery_download_same_stat($before,$after)||(!$report&&!hash_equals($archiveSha,$sha))||!rewind($stream))throw new RecoveryDownloadError(409);$size=$before['size'];
  }
  // Long hashing must not let a revoked administrator receive a backup.
  system_backups_admin('GET');$pdo=db();$previous=(int)query('SELECT @@SESSION.innodb_lock_wait_timeout value')[0]['value'];$pdo->exec('SET SESSION innodb_lock_wait_timeout=5');
  try{$pdo->beginTransaction();if(!query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE'))throw new ManagementError('Yedekleme yönetimi hazır değil.',503);system_backups_admin('GET',true);audit('system_backup_download','backup_id='.$id.';part='.$part.($encrypted?';key_id='.$_GET['key_id']:''));$pdo->commit();}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}finally{$pdo->exec('SET SESSION innodb_lock_wait_timeout='.$previous);}
  recovery_download_headers($name,$checksum?'text/plain; charset=utf-8':($report?'application/json; charset=utf-8':($encrypted?'application/octet-stream':'application/gzip')),$size,$sha,$archiveSha);
 }catch(RecoveryDownloadError $e){if(is_resource($stream))fclose($stream);throw new ManagementError('Sistem yedeği şu anda indirilemiyor.',$e->status);}
 catch(Throwable $e){if(is_resource($stream))fclose($stream);throw $e;}
 if($body!==null)echo $body;elseif(@fpassthru($stream)===false)error_log('FLS system backup stream interrupted.');if(is_resource($stream))fclose($stream);exit;
}
