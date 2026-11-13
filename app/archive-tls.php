<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
// Host-wide status. The archive worker verifies the actual peer;
// web requests perform no network I/O and never read destination credentials.
function archive_tls_settings_read(bool $lock=false): array {
 $row=query('SELECT warning_days,critical_days,revision,updated_at,updated_by FROM archive_tls_settings WHERE id=1'.($lock?' FOR UPDATE':''))[0]??null;
 if(!$row)throw new RuntimeException('FTPS alert settings unavailable');
 foreach(['warning_days','critical_days','revision'] as $key)$row[$key]=(int)$row[$key];return $row;
}
function archive_tls_target(array $row,int $now,array $settings=['warning_days'=>30,'critical_days'=>7]): array {
 $current=$row['tls_peer_revision']!==null&&(int)$row['tls_peer_revision']===(int)$row['revision'];
 $certificate=$current&&$row['tls_peer_pem']!==''?@openssl_x509_read($row['tls_peer_pem']):false;
 $info=$certificate?@openssl_x509_parse($certificate):false;
 $checked=$current?$row['tls_peer_checked_at']:null;$verified=$current?$row['tls_peer_verified_at']:null;
 $code=$current?$row['tls_peer_check_code']:'';
 $age=$verified?$now-(new DateTimeImmutable($verified,new DateTimeZone('UTC')))->getTimestamp():null;
 $fresh=$info&&$age!==null&&$age>=-30&&$age<=7200&&$code==='';
 $remaining=$info?((int)$info['validTo_time_t']-$now):null;
 $state=$remaining===null?'unknown':($remaining<=0?'expired':($remaining<=$settings['critical_days']*86400?'critical':($remaining<=$settings['warning_days']*86400?'expiring':'healthy')));
 $days=$remaining===null?null:(int)ceil($remaining/86400);
 $target=['id'=>(int)$row['id'],'name'=>$row['name'],'host'=>$row['host'],'port'=>(int)$row['port'],'revision'=>(int)$row['revision'],'state'=>$state,'fresh'=>(bool)$fresh,'checked_at'=>$checked,'verified_at'=>$verified,'check_code'=>$code,'expires_at'=>$info?gmdate('Y-m-d H:i:s',(int)$info['validTo_time_t']):null,'days_remaining'=>$days,'seconds_remaining'=>$remaining,'sha256'=>$certificate?openssl_x509_fingerprint($certificate,'sha256'):null];
 $alerts=[];$add=function(string $code,string $severity,string $message)use(&$alerts,$target){$alerts[]=['destination_id'=>$target['id'],'code'=>$code,'severity'=>$severity,'message'=>$message];};
 if($state==='expired')$add('certificate_expired','error',$row['name'].': FTPS sertifikasının süresi doldu.');
 elseif($state==='critical'||$state==='expiring')$add('certificate_expiring',$state==='critical'?'error':'warning',$row['name'].': FTPS sertifikasının bitmesine '.($remaining<86400?'24 saatten az':$days.' gün').' kaldı.');
 if($code!=='')$add('certificate_check_failed','error',$row['name'].': FTPS sertifikasının son kontrolü başarısız.');
 elseif(!$info)$add('certificate_unknown','warning',$row['name'].': FTPS sunucu sertifikası henüz doğrulanmadı.');
 elseif(!$fresh)$add('certificate_check_stale','warning',$row['name'].($age!==null&&$age< -30?': FTPS sertifika kontrolünün zamanı doğrulanamıyor.':': FTPS sertifika kontrolü iki saattir güncellenmedi.'));
 $target['alerts']=$alerts;return $target;
}
function archive_tls_health(?int $now=null,?array $settings=null): array {
 $now??=time();$settings??=archive_tls_settings_read();$rows=query("SELECT id,name,host,port,revision,tls_peer_pem,tls_peer_revision,tls_peer_checked_at,tls_peer_verified_at,tls_peer_check_code FROM archive_destinations WHERE enabled=1 AND protocol='ftps' ORDER BY id");
 $targets=array_map(fn($r)=>archive_tls_target($r,$now,$settings),$rows);$alerts=[];foreach($targets as $target)array_push($alerts,...$target['alerts']);
 return ['scope'=>'server','checked_at'=>gmdate('Y-m-d H:i:s',$now),'settings'=>$settings,'warning_days'=>$settings['warning_days'],'critical_days'=>$settings['critical_days'],'refresh_minutes'=>60,'targets'=>$targets,'alerts'=>$alerts];
}
function archive_tls_settings_save(array $input): array {
 $warning=management_int($input,'warning_days',1,3650);$critical=management_int($input,'critical_days',1,3650);$revision=management_int($input,'revision');
 if($critical>$warning)throw new ManagementError('Kritik uyarı eşiği, uyarı eşiğinden büyük olamaz.');
 $pdo=db();$pdo->beginTransaction();
 try {
  query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');
  $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[$_SESSION['uid']])[0]??null;
  if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti.',403);
  $old=archive_tls_settings_read(true);
  if($old['revision']!==$revision){$response=archive_tls_health(null,$old);$pdo->rollBack();return ['http_status'=>409,'error'=>'Eşikler başka bir oturumda değiştirildi. Güncel ayarları yükleyip yeniden deneyin.']+$response;}
  $changed=$warning!==$old['warning_days']||$critical!==$old['critical_days'];
  if($changed){
   execute('UPDATE archive_tls_settings SET warning_days=?,critical_days=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6),updated_by=? WHERE id=1',[$warning,$critical,$_SESSION['username']]);
   audit('archive_tls_settings','revision='.$old['revision'].'->'.($old['revision']+1).';warning_days='.$old['warning_days'].'->'.$warning.';critical_days='.$old['critical_days'].'->'.$critical);
  }
  $settings=archive_tls_settings_read(true);
  if($changed){require_once __DIR__.'/archive-tls-history.php';$response=archive_tls_history_reconcile(null,$settings);}else $response=archive_tls_health(null,$settings);
  $pdo->commit();return ['changed'=>$changed]+$response;
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
