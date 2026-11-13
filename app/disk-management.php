<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';

const DISK_MANAGEMENT_JS_MAX=9007199254740991;

function disk_management_number(mixed $value,int $minimum=0,int $maximum=DISK_MANAGEMENT_JS_MAX): ?int {
 if(!is_int($value)&&(!is_string($value)||preg_match('/^(?:0|[1-9][0-9]{0,15})$/D',$value)!==1))return null;
 $number=filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>$minimum,'max_range'=>$maximum]]);return $number===false?null:$number;
}
function disk_management_uuid(mixed $value,bool $request=false): bool {
 return is_string($value)&&preg_match($request?'/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D':'/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/D',$value)===1;
}
function disk_management_wwn(mixed $value): bool {return is_string($value)&&preg_match('/^0x[a-f0-9]{16}$/D',$value)===1;}
function disk_management_disk_key(mixed $value): bool {return disk_management_wwn($value)||(is_string($value)&&preg_match('/^id:[a-f0-9]{64}$/D',$value)===1);}
function disk_management_token(mixed $value): bool {return is_string($value)&&preg_match('/^[a-f0-9]{64}$/D',$value)===1;}
function disk_management_text(mixed $value,int $maximum): string {
 if(!is_string($value)||!mb_check_encoding($value,'UTF-8')||mb_strlen($value)>$maximum||preg_match('/[\x00-\x1f\x7f]/u',$value))throw new ManagementError('Disk yönetimi durumu okunamadı.',503);return $value;
}
function disk_management_error(mixed $value): string {return is_string($value)&&preg_match('/^[a-z0-9_]{0,64}$/D',$value)?$value:'state_invalid';}
function disk_management_time(mixed $value): ?string {
 if($value===null)return null;
 if(!is_string($value)||preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)?$/D',$value)!==1)throw new ManagementError('Disk yönetimi durumu okunamadı.',503);
 try{$time=new DateTimeImmutable($value,new DateTimeZone('UTC'));$errors=DateTimeImmutable::getLastErrors();if($errors&&($errors['warning_count']||$errors['error_count']))throw new RuntimeException();return $time->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');}catch(Throwable $e){throw new ManagementError('Disk yönetimi durumu okunamadı.',503);}
}
function disk_management_age(?string $time): ?float {return $time===null?null:microtime(true)-(float)(new DateTimeImmutable($time))->format('U.u');}
function disk_management_admin(string $method,bool $lock=false): array {
 if(($_SERVER['REQUEST_METHOD']??'')!==$method){header('Allow: '.$method);throw new ManagementError('Bu işlem için '.$method.' kullanılmalı.',405);}
 $uid=disk_management_number($_SESSION['uid']??null,1,4294967295);$session=disk_management_number($_SESSION['session_version']??null,0,4294967295);
 if($uid===null)throw new ManagementError('Oturum açmanız gerekiyor.',401);
 if(($_SESSION['role']??'')!=='admin'||$session===null)throw new ManagementError('Disk yönetimi yönetici yetkisi gerektirir.',403);
 $actor=query('SELECT id,username,role,enabled,session_version,must_change FROM users WHERE id=?'.($lock?' FOR UPDATE':''),[$uid])[0]??null;
 if(!$actor||($actor['role']??null)!=='admin'||disk_management_number($actor['enabled']??null,0,1)!==1||disk_management_number($actor['session_version']??null,0,4294967295)!==$session||disk_management_number($actor['must_change']??null,0,1)!==0)throw new ManagementError('Yönetim yetkiniz değişti.',403);return $actor;
}
/** Never return command output, arbitrary worker metadata or credentials. */
function disk_management_role(array $row,bool $candidate=false): array {
 $eligible=$candidate&&($row['eligible']??null)===true;
 $wwn=$row['wwn']??null;if(!disk_management_disk_key($wwn)&&!($candidate&&!$eligible&&$wwn===''))throw new ManagementError('Disk kimliği okunamadı.',503);
 $size=disk_management_number($row['size_bytes']??null,1);if($size===null)throw new ManagementError('Disk kapasitesi okunamadı.',503);
 $out=['wwn'=>$wwn,'serial'=>disk_management_text($row['serial']??null,128),'model'=>disk_management_text($row['model']??null,128),'size_bytes'=>$size];
 foreach(['mount_path'=>256,'filesystem'=>32,'filesystem_uuid'=>64,'last_sync_status'=>32] as $key=>$maximum)if(isset($row[$key]))$out[$key]=disk_management_text($row[$key],$maximum);
 foreach(['total_bytes','free_bytes'] as $key)if(isset($row[$key])){$out[$key]=disk_management_number($row[$key]);if($out[$key]===null)throw new ManagementError('Disk kapasitesi okunamadı.',503);}
 if(!$candidate||array_key_exists('present',$row)){if(!is_bool($row['present']??null))throw new ManagementError('Disk durumu okunamadı.',503);$out['present']=$row['present'];}
 if(array_key_exists('last_sync_at',$row))$out['last_sync_at']=disk_management_time($row['last_sync_at']);
 if(array_key_exists('last_sync_error',$row))$out['last_sync_error']=disk_management_error($row['last_sync_error']);
 if($candidate){
  if(!is_bool($row['eligible']??null)||!is_array($row['reasons']??null)||!array_is_list($row['reasons'])||count($row['reasons'])>24)throw new ManagementError('Disk uygunluğu okunamadı.',503);
  $reasons=[];foreach($row['reasons'] as $reason){if(!is_string($reason)||preg_match('/^[a-z0-9_]{1,64}$/D',$reason)!==1)throw new ManagementError('Disk uygunluğu okunamadı.',503);$reasons[]=$reason;}
  $token=$row['token']??null;if(!disk_management_token($token)&&!(!$eligible&&$token===''))throw new ManagementError('Disk önizlemesi okunamadı.',503);
  $out+=['eligible'=>$eligible,'reasons'=>array_values(array_unique($reasons)),'token'=>$token];
 }
 return $out;
}
function disk_management_progress(mixed $value): ?array {
 if(!is_array($value))return null;$out=[];
 if(isset($value['phase'])){$phase=disk_management_error($value['phase']);if($phase==='state_invalid')return null;$out['phase']=$phase;}
 if(isset($value['percent'])){if(!is_int($value['percent'])&&!is_float($value['percent']))return null;$percent=(float)$value['percent'];if(!is_finite($percent)||$percent<0||$percent>100)return null;$out['percent']=$percent;}
 foreach(['bytes_copied','bytes_total','verified_files'] as $key)if(isset($value[$key])){$number=disk_management_number($value[$key]);if($number===null)return null;$out[$key]=$number;}
 return $out?:null;
}
function disk_management_job(array $row): array {
 if(!disk_management_uuid($row['request_key']??null,true)||!disk_management_uuid($row['boot_id']??null)||!disk_management_disk_key($row['disk_wwn']??null)||!in_array($row['action']??null,['prepare','sync','migrate'],true)||!in_array($row['status']??null,['queued','running','succeeded','failed','rejected'],true))throw new ManagementError('Disk işi okunamadı.',503);
 $out=[];foreach(['id'=>1,'requested_by_uid'=>1,'requested_session_version'=>0,'disk_size_bytes'=>1,'config_revision'=>0,'confirmed'=>0] as $key=>$minimum){$out[$key]=disk_management_number($row[$key]??null,$minimum,$key==='confirmed'?1:DISK_MANAGEMENT_JS_MAX);if($out[$key]===null)throw new ManagementError('Disk işi okunamadı.',503);}
 foreach(['request_key','boot_id','disk_wwn','action','status'] as $key)$out[$key]=$row[$key];
 $out['disk_serial']=disk_management_text($row['disk_serial']??null,128);$out['requested_by']=disk_management_text($row['requested_by']??null,64);$out['error_code']=disk_management_error($row['error_code']??'');
 foreach(['requested_at','expires_at','started_at','completed_at'] as $key)$out[$key]=disk_management_time($row[$key]??null);
 if($out['requested_at']===null||$out['expires_at']===null)throw new ManagementError('Disk işi okunamadı.',503);
 $out['expired']=new DateTimeImmutable($out['expires_at'])<=new DateTimeImmutable('now',new DateTimeZone('UTC'));
 $out['result']=null;if(is_string($row['result_json']??null)&&strlen($row['result_json'])<=65536){try{$out['result']=disk_management_progress(json_decode($row['result_json'],true,16,JSON_THROW_ON_ERROR));}catch(Throwable $e){}}
 return $out;
}
function disk_management_state(?array $row): array {
 $out=['schema'=>1,'mode'=>null,'boot_id'=>null,'checked_at'=>null,'generated_at_utc'=>null,'config_revision'=>0,'status'=>'error','error_code'=>'worker_unavailable','available'=>false,'fresh'=>false,'system'=>null,'depot'=>null,'mirror'=>null,'candidates'=>[],'progress'=>null];
 if(!$row)return $out;
 try{
  if(disk_management_number($row['id']??null,1,1)!==1||disk_management_number($row['version']??null,1,1)!==1||!disk_management_uuid($row['boot_id']??null)||!in_array($row['status']??null,['idle','preparing','syncing','migrating','error'],true))throw new ManagementError('Disk durumu hazır değil.',503);
  $revision=disk_management_number($row['config_revision']??null,0,4294967295);if($revision===null)throw new ManagementError('Disk durumu hazır değil.',503);
  $error=$row['error_code']??null;if(!is_string($error)||preg_match('/^(?:|[a-z][a-z0-9_]{0,63})$/D',$error)!==1)throw new ManagementError('Disk durumu hazır değil.',503);
  $checked=disk_management_time($row['checked_at']??null);if($checked===null)throw new ManagementError('Disk durumu hazır değil.',503);
  $out['boot_id']=$row['boot_id'];$out['status']=$row['status'];$out['error_code']=$error;$out['config_revision']=$revision;$out['checked_at']=$checked;
  $json=$row['inventory_json']??null;
  // A first inventory failure can have a valid worker status without a payload.
  // Preserve only its bounded code; unavailable roles never imply disconnection.
  if($json===null&&$out['status']==='error'&&$error!=='')return $out;
  if(!is_string($json)||strlen($json)>262144)throw new ManagementError('Disk envanteri hazır değil.',503);
  $inventory=json_decode($json,true,24,JSON_THROW_ON_ERROR);if(!is_array($inventory)||($inventory['schema']??null)!==1||($inventory['boot_id']??null)!==$out['boot_id']||!is_array($inventory['system']??null)||!array_key_exists('depot',$inventory)||($inventory['depot']!==null&&!is_array($inventory['depot']))||!array_key_exists('mirror',$inventory)||!is_array($inventory['candidates']??null)||!array_is_list($inventory['candidates'])||count($inventory['candidates'])>64)throw new ManagementError('Disk envanteri hazır değil.',503);
  $out['mode']=$inventory['mode']??null;if(!in_array($out['mode'],['system-root','hybrid'],true)||($out['mode']==='system-root'&&($inventory['depot']!==null||$inventory['mirror']!==null))||($out['mode']==='hybrid'&&$inventory['depot']===null))throw new ManagementError('Disk rolleri doğrulanamadı.',503);
  $out['generated_at_utc']=disk_management_time($inventory['generated_at_utc']??null);$out['system']=disk_management_role($inventory['system']);$out['depot']=$inventory['depot']===null?null:disk_management_role($inventory['depot']);$out['mirror']=$inventory['mirror']===null?null:disk_management_role($inventory['mirror']);
  if(($out['depot']!==null&&$out['system']['wwn']===($out['depot']['wwn']??null))||($out['mirror']!==null&&in_array($out['mirror']['wwn'],[$out['system']['wwn'],($out['depot']['wwn']??null)],true)))throw new ManagementError('Disk rolleri doğrulanamadı.',503);
  $seen=[];foreach($inventory['candidates'] as $candidate){if(!is_array($candidate))throw new ManagementError('Disk envanteri okunamadı.',503);$candidate=disk_management_role($candidate,true);if($candidate['wwn']!==''){if(isset($seen[$candidate['wwn']]))throw new ManagementError('Disk kimliği yineleniyor.',503);$seen[$candidate['wwn']]=true;}
   if(in_array($candidate['wwn'],[$out['system']['wwn'],($out['depot']['wwn']??null),$out['mirror']['wwn']??null],true)||($candidate['serial']!==''&&in_array($candidate['serial'],[$out['system']['serial'],($out['depot']['serial']??null),$out['mirror']['serial']??null],true))){$candidate['eligible']=false;$candidate['reasons'][]='protected_role';}
   if($out['depot']!==null&&$candidate['size_bytes']<$out['depot']['size_bytes']){$candidate['eligible']=false;$candidate['reasons'][]='too_small';}
   if($candidate['reasons'])$candidate['eligible']=false;$candidate['reasons']=array_values(array_unique($candidate['reasons']));$out['candidates'][]=$candidate;
  }
  $out['progress']=disk_management_progress($inventory['progress']??null);
  $ages=[disk_management_age($out['checked_at']),disk_management_age($out['generated_at_utc'])];$out['fresh']=true;foreach($ages as $age)if($age===null||$age< -5||$age>45)$out['fresh']=false;
  $out['available']=$out['fresh']&&$out['status']!=='error'&&$out['error_code']===''&&$out['system']['present']===true&&($out['depot']===null||$out['depot']['present']===true);
 }catch(Throwable $e){$out['available']=false;$out['fresh']=false;$out['error_code']='state_invalid';$out['status']='error';$out['mode']=null;$out['system']=null;$out['depot']=null;$out['mirror']=null;$out['candidates']=[];$out['progress']=null;}
 return $out;
}
function disk_management_snapshot(): array {
 disk_management_admin('GET');
 try{$state=disk_management_state(query('SELECT * FROM disk_management_state WHERE id=1')[0]??null);$jobs=array_map('disk_management_job',query('SELECT * FROM disk_management_jobs ORDER BY id DESC LIMIT 25'));$active=query("SELECT * FROM disk_management_jobs WHERE status IN ('queued','running') ORDER BY id LIMIT 1")[0]??null;$active=$active?disk_management_job($active):null;}
 catch(PDOException $e){if((int)($e->errorInfo[1]??0)!==1146)throw $e;$state=disk_management_state(null);$jobs=[];$active=null;}
 $idle=$state['available']&&$state['status']==='idle'&&$active===null;
 return $state+['jobs'=>$jobs,'active_job'=>$active,'can_migrate'=>$idle&&$state['mode']==='system-root'&&$state['mirror']===null&&count(array_filter($state['candidates'],fn($row)=>$row['eligible']))>0,'can_prepare'=>$idle&&$state['mode']==='hybrid'&&$state['mirror']===null&&count(array_filter($state['candidates'],fn($row)=>$row['eligible']))>0,'can_sync'=>$idle&&$state['mirror']!==null&&($state['mirror']['present']??null)===true];
}
function disk_management_write(string $route,array $data): array {
 disk_management_admin('POST');$csrf=$data['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($csrf)||$csrf===''||!is_string($_SESSION['csrf']??null)||$_SESSION['csrf']===''||!hash_equals($_SESSION['csrf'],$csrf))throw new ManagementError('Oturum doğrulaması başarısız.',403);
 $action=match($route){'prepare_primary_disk'=>'migrate','prepare_mirror_disk'=>'prepare','sync_mirror_disk'=>'sync',default=>throw new ManagementError('Disk işlemi bulunamadı.',404)};
 $allowed=in_array($action,['prepare','migrate'],true)?['request_key','boot_id','inventory_token','candidate_wwn','confirmation','_csrf']:['request_key','boot_id','_csrf'];
 foreach($data as $key=>$value)if(!in_array($key,$allowed,true)||!is_string($value))throw new ManagementError('Disk isteğinde bilinmeyen veya geçersiz alan var.');
 $request=$data['request_key']??null;$boot=$data['boot_id']??null;if(!disk_management_uuid($request,true)||!disk_management_uuid($boot))throw new ManagementError('Disk istek kimliği geçersiz.');
 $token=in_array($action,['prepare','migrate'],true)?($data['inventory_token']??null):null;$wwn=in_array($action,['prepare','migrate'],true)?($data['candidate_wwn']??null):null;
 if(in_array($action,['prepare','migrate'],true)&&(!disk_management_token($token)||!disk_management_disk_key($wwn)))throw new ManagementError('Disk önizlemesi geçersiz.');
 if(in_array($action,['prepare','migrate'],true)&&($data['confirmation']??null)!=='TAMAM')throw new ManagementError('Diski hazırlamak için TAMAM yazın.');
 $pdo=db();$previous=(int)query('SELECT @@SESSION.innodb_lock_wait_timeout value')[0]['value'];$pdo->exec('SET SESSION innodb_lock_wait_timeout=5');
 try{
  $pdo->beginTransaction();if(!query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE'))throw new ManagementError('Disk yönetimi hazır değil.',503);$actor=disk_management_admin('POST',true);
  $existing=query('SELECT * FROM disk_management_jobs WHERE request_key=? FOR UPDATE',[$request])[0]??null;
  if($existing){if((int)$existing['requested_by_uid']!==(int)$actor['id']||(int)$existing['requested_session_version']!==(int)$actor['session_version']||$existing['action']!==$action||$existing['boot_id']!==$boot||(in_array($action,['prepare','migrate'],true)&&($existing['disk_wwn']!==$wwn||$existing['inventory_token']!==$token||(int)$existing['confirmed']!==1)))throw new ManagementError('Bu istek kimliği başka bir disk işlemi için kullanılmış.',409);$job=disk_management_job($existing);$pdo->commit();return ['saved'=>true,'duplicate'=>true,'job'=>$job,'http_status'=>202];}
  $state=disk_management_state(query('SELECT * FROM disk_management_state WHERE id=1 FOR UPDATE')[0]??null);
  if(!$state['available'])throw new ManagementError('Disk envanteri güncel değil. Durumu yenileyin.',503);
  if($state['boot_id']!==$boot)throw new ManagementError('Sunucu yeniden açılmış. Disk durumunu yenileyin.',409);
  if($state['status']!=='idle'||query("SELECT id FROM disk_management_jobs WHERE status IN ('queued','running') ORDER BY id LIMIT 1 FOR UPDATE"))throw new ManagementError('Başka bir disk işlemi sürüyor. Tamamlanmasını bekleyin.',409);
  if(in_array($action,['prepare','migrate'],true)){
   if(($action==='migrate')!==($state['mode']==='system-root'))throw new ManagementError('Disk rolü değişti. Durumu yenileyin.',409);
   if($state['mirror']!==null)throw new ManagementError('Aynalama diski zaten tanımlı.',409);
   $matches=array_values(array_filter($state['candidates'],fn($candidate)=>$candidate['wwn']===$wwn&&hash_equals($candidate['token'],$token)));if(count($matches)!==1)throw new ManagementError('Disk kimliği veya önizlemesi değişti. Ekranı yenileyin.',409);$disk=$matches[0];
   if(!$disk['eligible']||$disk['reasons']||in_array($disk['wwn'],[$state['system']['wwn'],($state['depot']['wwn']??null)],true)||($disk['serial']!==''&&in_array($disk['serial'],[$state['system']['serial'],($state['depot']['serial']??null)],true))||($state['depot']!==null&&$disk['size_bytes']<$state['depot']['size_bytes']))throw new ManagementError('Bu disk aynalama için uygun değil.',409);
   if(query('SELECT id FROM disk_management_jobs WHERE inventory_token=? LIMIT 1 FOR UPDATE',[$token]))throw new ManagementError('Bu disk önizlemesi daha önce kullanılmış. Ekranı yenileyin.',409);
  }else{$disk=$state['mirror'];if($disk===null||($disk['present']??null)!==true)throw new ManagementError('Kullanılabilir aynalama diski tanımlı değil.',409);if(in_array($disk['wwn'],[$state['system']['wwn'],($state['depot']['wwn']??null)],true)||$state['depot']===null||$disk['size_bytes']<$state['depot']['size_bytes'])throw new ManagementError('Aynalama diski doğrulanamadı.',409);}
  execute('INSERT INTO disk_management_jobs(request_key,action,requested_by_uid,requested_session_version,requested_by,requested_at,expires_at,boot_id,disk_wwn,disk_serial,disk_size_bytes,inventory_token,config_revision,confirmed) VALUES(?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 5 MINUTE,?,?,?,?,?,?,?)',[$request,$action,(int)$actor['id'],(int)$actor['session_version'],$actor['username'],$boot,$disk['wwn'],$disk['serial'],$disk['size_bytes'],$token,$state['config_revision'],in_array($action,['prepare','migrate'],true)?1:0]);$id=(int)$pdo->lastInsertId();
  audit('disk_management_request','action='.$action.';job_id='.$id.';disk_wwn='.$disk['wwn'].';boot_id='.$boot.';request_key='.$request);$job=disk_management_job(query('SELECT * FROM disk_management_jobs WHERE id=?',[$id])[0]);$pdo->commit();return ['saved'=>true,'duplicate'=>false,'job'=>$job,'http_status'=>202];
 }catch(PDOException $e){if($pdo->inTransaction())$pdo->rollBack();$code=(int)($e->errorInfo[1]??0);if($code===1146)throw new ManagementError('Disk yönetimi henüz hazır değil.',503);if(in_array($code,[1205,1213,1062],true))throw new ManagementError('Başka bir disk işlemi sürüyor veya önizleme kullanılmış. Durumu yenileyin.',409);throw $e;}
 catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
 finally{try{$pdo->exec('SET SESSION innodb_lock_wait_timeout='.$previous);}catch(Throwable $e){error_log('FLS disk management SQL timeout reset failed');}}
}
