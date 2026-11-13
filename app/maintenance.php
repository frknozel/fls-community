<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';

function maintenance_number(mixed $value,int $minimum=0,int $maximum=4294967295): ?int {
 if(!is_string($value)&&!is_int($value))return null;
 $n=filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>$minimum,'max_range'=>$maximum]]);return $n===false?null:$n;
}
function maintenance_time(mixed $value): ?string {
 if(!is_string($value)||!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/D',$value))return null;
 try{$date=new DateTimeImmutable($value,new DateTimeZone('UTC'));$e=DateTimeImmutable::getLastErrors();return $e&&($e['warning_count']||$e['error_count'])?null:$value;}catch(Throwable $e){return null;}
}
/** SQL metadata only; the web process never opens a marker or starts/stops a service. */
function maintenance_snapshot(bool $public=false): array {
 $result=['schema'=>1,'available'=>false,'fresh'=>false,'state'=>'unknown','request'=>['requested_mode'=>null,'revision'=>null,'requested_at'=>null,'requested_by'=>null],
 'worker'=>['version'=>null,'applied_revision'=>null,'attempted_revision'=>null,'collector_state'=>'unknown','marker_present'=>null,'checked_at'=>null,'applied_at'=>null,'error_code'=>'','age_seconds'=>null]];
 try{
  $r=query('SELECT requested_mode,revision,requested_at,requested_by FROM maintenance_requests WHERE id=1')[0]??null;
  $s=query('SELECT version,applied_revision,attempted_revision,collector_state,marker_present,checked_at,applied_at,error_code FROM maintenance_state WHERE id=1')[0]??null;
  if($r){$mode=in_array($r['requested_mode'],['normal','paused'],true)?$r['requested_mode']:null;$revision=maintenance_number($r['revision'],1);$by=is_string($r['requested_by'])&&mb_check_encoding($r['requested_by'],'UTF-8')&&mb_strlen($r['requested_by'])<=100?$r['requested_by']:null;$result['request']=['requested_mode'=>$mode,'revision'=>$revision,'requested_at'=>maintenance_time($r['requested_at']),'requested_by'=>$by];}
  if($s){
   $w=$result['worker'];$w['version']=maintenance_number($s['version'],1);foreach(['applied_revision','attempted_revision'] as $key)$w[$key]=maintenance_number($s[$key]);
   $w['collector_state']=in_array($s['collector_state'],['unknown','active','inactive','failed','activating','deactivating'],true)?$s['collector_state']:'unknown';
   $marker=maintenance_number($s['marker_present'],0,1);$w['marker_present']=$marker===null?null:$marker===1;
   foreach(['checked_at','applied_at'] as $key)$w[$key]=maintenance_time($s[$key]);
   $w['error_code']=is_string($s['error_code'])&&preg_match('/^[a-z0-9_]{0,64}$/D',$s['error_code'])?$s['error_code']:'state_invalid';
   if($w['checked_at']!==null)$w['age_seconds']=time()-(new DateTimeImmutable($w['checked_at'],new DateTimeZone('UTC')))->getTimestamp();$result['worker']=$w;
  }
  $r=$result['request'];$w=$result['worker'];
  $future=false;foreach([$r['requested_at'],$w['applied_at']] as $at)if($at!==null&&(new DateTimeImmutable($at,new DateTimeZone('UTC')))->getTimestamp()>time()+5)$future=true;
  $valid=!$future&&$r['requested_mode']!==null&&$r['revision']!==null&&$r['requested_at']!==null&&$w['version']===1&&$w['applied_revision']!==null&&$w['attempted_revision']!==null&&$w['applied_revision']<=$w['attempted_revision']&&$w['attempted_revision']<=$r['revision']&&$w['marker_present']!==null&&$w['age_seconds']!==null;
  $result['available']=$valid;$result['fresh']=$valid&&$w['age_seconds']>=-5&&$w['age_seconds']<=45;
  if(!$valid)$result['state']='unknown';
  elseif(!$result['fresh'])$result['state']='stale';
  elseif($w['collector_state']==='unknown')$result['state']='unknown';
  elseif($w['attempted_revision']===$r['revision']&&$w['error_code']!==''&&$w['error_code']!=='transition_pending')$result['state']='error';
  elseif($w['applied_revision']<$r['revision']||in_array($w['collector_state'],['activating','deactivating'],true)||$w['error_code']==='transition_pending')$result['state']='pending';
  elseif($r['requested_mode']==='paused'&&$w['collector_state']==='inactive'&&$w['marker_present'])$result['state']='paused';
  elseif($r['requested_mode']==='normal'&&$w['collector_state']==='active'&&!$w['marker_present'])$result['state']='normal';
  elseif($r['requested_mode']==='normal'&&$w['collector_state']==='inactive')$result['state']='inactive';
  else $result['state']='error';
 }catch(Throwable $e){/* During an upgrade or outage, unknown must never become active. */}
 if($public)unset($result['request']['requested_by']);return $result;
}
function maintenance_save(array $input): array {
 foreach($input as $key=>$value)if(!in_array($key,['requested_mode','revision','_csrf'],true))throw new ManagementError('Bakım isteğinde bilinmeyen alan var.');
 $mode=$input['requested_mode']??null;$rawRevision=$input['revision']??null;$revision=(is_int($rawRevision)||is_string($rawRevision)&&preg_match('/^[1-9][0-9]{0,9}$/D',$rawRevision))?maintenance_number($rawRevision,1,4294967294):null;
 if(!is_string($mode)||!in_array($mode,['normal','paused'],true)||$revision===null)throw new ManagementError('Bakım modu veya sürüm numarası geçersiz.');
 $pdo=db();$previous=(int)query('SELECT @@SESSION.innodb_lock_wait_timeout value')[0]['value'];$pdo->exec('SET SESSION innodb_lock_wait_timeout=5');
 try{
  $pdo->beginTransaction();
  $actor=query('SELECT username,role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[(int)($_SESSION['uid']??0)])[0]??null;
  if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??-1))throw new ManagementError('Yönetim yetkiniz değişti.',403);
  $old=query('SELECT requested_mode,revision FROM maintenance_requests WHERE id=1 FOR UPDATE')[0]??null;
  if(!$old)throw new ManagementError('Bakım durumu hazır değil. Yeniden deneyin.',503);
  if((int)$old['revision']!==$revision){$snapshot=maintenance_snapshot();$pdo->rollBack();return ['http_status'=>409,'code'=>'maintenance_conflict','error'=>'Bakım isteği başka bir oturumda değişti. Güncel durumu kontrol edin.','maintenance'=>$snapshot];}
  execute('UPDATE maintenance_requests SET requested_mode=?,revision=revision+1,requested_at=UTC_TIMESTAMP(6),requested_by=? WHERE id=1',[$mode,$actor['username']]);
  audit('maintenance_request','collector_only;mode='.$mode.';revision='.$revision.'->'.($revision+1));$snapshot=maintenance_snapshot();$pdo->commit();
  return ['http_status'=>202,'maintenance'=>$snapshot];
 }catch(PDOException $e){if($pdo->inTransaction())$pdo->rollBack();if((int)($e->errorInfo[1]??0)===1146)throw new ManagementError('Bakım durumu hazır değil. Yeniden deneyin.',503);if(in_array((int)($e->errorInfo[1]??0),[1205,1213],true))throw new ManagementError('Bakım işlemi sürüyor. Durumu yenileyip tekrar deneyin.',409);throw $e;}
 catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
 finally{try{$pdo->exec('SET SESSION innodb_lock_wait_timeout='.$previous);}catch(Throwable $e){error_log('FLS maintenance lock timeout restore failed');}}
}
