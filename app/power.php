<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';

function power_number(mixed $value,int $minimum=0,int $maximum=4294967295): ?int {
 if(!is_int($value)&&(!is_string($value)||!preg_match('/^(?:0|[1-9][0-9]{0,9})$/D',$value)))return null;
 if(is_int($value)&&($value<$minimum||$value>$maximum))return null;
 $n=filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>$minimum,'max_range'=>$maximum]]);return $n===false?null:$n;
}
function power_uuid(mixed $value,bool $request=false): bool {
 return is_string($value)&&preg_match($request?'/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D':'/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/D',$value)===1;
}
function power_time(mixed $value): ?string {
 if(!is_string($value)||!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/D',$value))return null;
 try{$date=new DateTimeImmutable($value,new DateTimeZone('UTC'));$e=DateTimeImmutable::getLastErrors();return $e&&($e['warning_count']||$e['error_count'])?null:$value;}catch(Throwable $e){return null;}
}
function power_epoch(string $value): float {return (float)(new DateTimeImmutable($value,new DateTimeZone('UTC')))->format('U.u');}
/** Normalize SQL metadata only. The web account never invokes host commands. */
function power_snapshot_rows(?array $r,?array $s): array {
 $out=['schema'=>1,'available'=>false,'fresh'=>false,'boot_id'=>'','revision'=>null,'worker'=>['status'=>'idle','attempted_revision'=>null,'checked_at'=>null,'error_code'=>'','age_seconds'=>null],'request'=>null];
 if(!$r||!$s)return $out;
 $now=microtime(true);$revision=power_number($r['revision']??null);$attempted=power_number($s['attempted_revision']??null);$boot=$s['boot_id']??null;
 $status=in_array($s['status']??null,['idle','waiting','submitted','failed','rejected','uncertain'],true)?$s['status']:null;
 $checked=power_time($s['checked_at']??null);$ageValue=$checked===null?null:$now-power_epoch($checked);$age=$ageValue===null?null:(int)floor($ageValue);
 $error=is_string($s['error_code']??null)&&preg_match('/^[a-z0-9_]{0,64}$/D',$s['error_code'])?$s['error_code']:null;
 $out['revision']=$revision;$out['boot_id']=power_uuid($boot)?$boot:'';
 $out['worker']=['status'=>$status??'idle','attempted_revision'=>$attempted,'checked_at'=>$checked,'error_code'=>$error??'state_invalid','age_seconds'=>$age];
 $valid=power_number($s['version']??null)===1&&power_uuid($boot)&&$revision!==null&&$attempted!==null&&$attempted<=$revision&&$status!==null&&$error!==null&&$checked!==null;
 $action=$r['action']??null;
 if($revision===0){
  $valid=$valid&&$action===''&&($r['boot_id']??null)===''&&($r['request_key']??null)===''&&($r['requested_by']??null)===''&&($r['requested_at']??null)===null&&($r['not_before']??null)===null&&($r['expires_at']??null)===null&&($r['requested_by_uid']??null)===null&&($r['requested_session_version']??null)===null&&$status==='idle';
 }else{
  $at=power_time($r['requested_at']??null);$notBefore=power_time($r['not_before']??null);$expires=power_time($r['expires_at']??null);$by=$r['requested_by']??null;
  $requestValid=in_array($action,['poweroff','reboot'],true)&&power_uuid($r['boot_id']??null)&&power_uuid($r['request_key']??null,true)&&power_number($r['requested_by_uid']??null,1)!==null&&power_number($r['requested_session_version']??null)!==null&&is_string($by)&&$by!==''&&mb_check_encoding($by,'UTF-8')&&mb_strlen($by)<=100&&!preg_match('/[\x00-\x1f\x7f]/u',$by)&&$at!==null&&$notBefore!==null&&$expires!==null;
  if($requestValid)$requestValid=power_epoch($at)<=$now+5&&abs(power_epoch($notBefore)-power_epoch($at)-10)<0.001&&abs(power_epoch($expires)-power_epoch($at)-60)<0.001;
  $valid=$valid&&$requestValid;
  if($requestValid&&$r['boot_id']===$boot){
   $requestStatus=$revision>$attempted?'pending':($status??'uncertain');
   if($requestStatus==='idle')$valid=false;
   $out['request']=['id'=>$revision,'action'=>$action,'status'=>$requestStatus,'request_key'=>$r['request_key'],'requested_at'=>$at,'requested_by'=>$by,'not_before'=>$notBefore,'expires_at'=>$expires,'error_code'=>$revision>$attempted?'':($error??'state_invalid')];
  }
 }
 $out['available']=$valid;$out['fresh']=$valid&&$ageValue!==null&&$ageValue>=-5&&$ageValue<=30;
 return $out;
}
function power_snapshot(): array {
 try{return power_snapshot_rows(query('SELECT * FROM power_requests WHERE id=1')[0]??null,query('SELECT * FROM power_state WHERE id=1')[0]??null);}
 catch(Throwable $e){return power_snapshot_rows(null,null);}
}
function power_response(int $status,string $code,string $message,array $snapshot): array {return ['http_status'=>$status,'code'=>$code,'error'=>$message,'power'=>$snapshot];}
function power_save(array $input): array {
 foreach($input as $key=>$value)if(!in_array($key,['action','revision','boot_id','request_key','confirmation','_csrf'],true))throw new ManagementError('Güç isteğinde bilinmeyen alan var.');
 $action=$input['action']??null;$revision=power_number($input['revision']??null,0,4294967294);$boot=$input['boot_id']??null;$key=$input['request_key']??null;$confirmation=$input['confirmation']??null;
 if(!is_string($action)||!in_array($action,['poweroff','reboot'],true)||$revision===null||!power_uuid($boot)||!power_uuid($key,true)||!is_string($confirmation)||$confirmation!==($action==='poweroff'?'KAPAT':'YENİDEN BAŞLAT')||isset($input['_csrf'])&&!is_string($input['_csrf']))throw new ManagementError('Güç işlemi, onay metni veya istek bilgileri geçersiz.');
 $pdo=db();$previous=(int)query('SELECT @@SESSION.innodb_lock_wait_timeout value')[0]['value'];$pdo->exec('SET SESSION innodb_lock_wait_timeout=5');
 try{
  $pdo->beginTransaction();
  // Match the privileged worker lock order; authorization is rechecked under lock.
  $old=query('SELECT * FROM power_requests WHERE id=1 FOR UPDATE')[0]??null;
  $state=query('SELECT * FROM power_state WHERE id=1 FOR UPDATE')[0]??null;
  $actor=query('SELECT username,role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[(int)($_SESSION['uid']??0)])[0]??null;
  if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??-1))throw new ManagementError('Yönetim yetkiniz değişti.',403);
  $snapshot=power_snapshot_rows($old,$state);
  if(!$snapshot['available']){$pdo->rollBack();return power_response(503,'power_unavailable','Güç yönetimi hazır değil. Durumu yenileyin.',$snapshot);}
  if($snapshot['boot_id']!==$boot){$pdo->rollBack();return power_response(409,'power_boot_changed','Sistem yeniden açılmış. Güncel durumu kontrol edip işlemi yeniden onaylayın.',$snapshot);}
  if(($old['request_key']??'')===$key){
   if((int)$old['requested_by_uid']!==(int)$_SESSION['uid']||$old['action']!==$action||$old['boot_id']!==$boot){$pdo->rollBack();return power_response(409,'power_key_conflict','Bu istek kimliği başka bir işlem için kullanılmış. Durumu yenileyin.',$snapshot);}
   $pdo->commit();return ['http_status'=>202,'power'=>$snapshot,'duplicate'=>true];
  }
  if($snapshot['revision']!==$revision){$pdo->rollBack();return power_response(409,'power_conflict','Güç isteği başka bir oturumda değişti. Güncel durumu kontrol edin.',$snapshot);}
  if(!$snapshot['fresh']){$pdo->rollBack();return power_response(503,'power_stale','Güç yönetimi yanıtı güncel değil. Durumu yenileyin.',$snapshot);}
  if($snapshot['request']!==null&&in_array($snapshot['request']['status'],['pending','waiting','submitted','uncertain'],true)){$pdo->rollBack();return power_response(409,'power_busy','Bu açılış için güç işlemi zaten bekliyor veya başlatılmış. Durumu yenileyin.',$snapshot);}
  execute('UPDATE power_requests SET revision=revision+1,action=?,boot_id=?,requested_at=UTC_TIMESTAMP(6),not_before=UTC_TIMESTAMP(6)+INTERVAL 10 SECOND,expires_at=UTC_TIMESTAMP(6)+INTERVAL 60 SECOND,requested_by_uid=?,requested_session_version=?,request_key=?,requested_by=? WHERE id=1',[$action,$boot,(int)$_SESSION['uid'],(int)$actor['session_version'],$key,$actor['username']]);
  audit('power_request','action='.$action.';boot_id='.$boot.';revision='.$revision.'->'.($revision+1).';request_key='.$key);
  $snapshot=power_snapshot();$pdo->commit();return ['http_status'=>202,'power'=>$snapshot,'duplicate'=>false];
 }catch(PDOException $e){
  if($pdo->inTransaction())$pdo->rollBack();$code=(int)($e->errorInfo[1]??0);
  if($code===1146)throw new ManagementError('Güç yönetimi hazır değil. Yeniden deneyin.',503);
  if(in_array($code,[1205,1213],true))throw new ManagementError('Başka bir güç işlemi sürüyor. Durumu yenileyip tekrar deneyin.',409);
  throw $e;
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
 finally{try{$pdo->exec('SET SESSION innodb_lock_wait_timeout='.$previous);}catch(Throwable $e){error_log('FLS power lock timeout restore failed');}}
}
