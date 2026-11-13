<?php
declare(strict_types=1);
require_once __DIR__.'/archive-tls.php';

function archive_tls_history_closure(array $old,?array $target,?array $next,array $settings): string {
 if(!$target)return 'destination_inactive';
 if((int)$old['destination_revision']!==$target['revision'])return 'destination_changed';
 if((int)$old['settings_revision']!==$settings['revision'])return 'settings_changed';
 if($old['certificate_sha256']!==null&&$target['sha256']!==null&&$old['certificate_sha256']!==$target['sha256'])return 'certificate_changed';
 if($next&&$old['severity']!==$next['alert']['severity'])return 'severity_changed';
 if($target['state']==='unknown')return 'unconfirmed';
 $expiry=in_array($old['alert_code'],['certificate_expiring','certificate_expired'],true);
 foreach($target['alerts'] as $alert)if($expiry===in_array($alert['code'],['certificate_expiring','certificate_expired'],true))return 'condition_changed';
 return $target['fresh']?'recovered':'unconfirmed';
}

function archive_tls_history_key(array $target,array $settings,array $alert): string {
 return hash('sha256',json_encode([$target['revision'],$settings['revision'],$target['sha256'],$alert['code'],$alert['severity']],JSON_THROW_ON_ERROR));
}

// Match the exact current condition; a previous threshold, certificate or
// severity period must never supply the start time of a new warning.
function archive_tls_alert_snapshot(): array {
 $now=time();$health=archive_tls_health($now);$open=[];$targets=[];
 foreach(query('SELECT id,destination_id,alert_code,condition_key,triggered_at,last_seen_at FROM archive_tls_alert_history WHERE closed_at IS NULL') as $row)$open[$row['destination_id'].':'.$row['alert_code']]=$row;
 foreach($health['targets'] as $target)$targets[$target['id']]=$target;
 foreach($health['alerts'] as &$alert){
  $row=$open[$alert['destination_id'].':'.$alert['code']]??null;
  $matched=$row&&hash_equals($row['condition_key'],archive_tls_history_key($targets[$alert['destination_id']],$health['settings'],$alert));
  $alert['history_id']=$matched?(int)$row['id']:null;
  $alert['triggered_at']=$matched?$row['triggered_at']:null;
  $alert['duration_seconds']=$matched?max(0,$now-(new DateTimeImmutable($row['triggered_at'],new DateTimeZone('UTC')))->getTimestamp()):null;
 }
 unset($alert);return $health;
}

// The caller owns the transaction. The shared state lock serializes the worker
// and admin writes; GET endpoints never reconcile or invent past observations.
function archive_tls_history_reconcile(?int $now=null,?array $settings=null,bool $worker=false): array {
 if(!db()->inTransaction())throw new LogicException('History recording requires a transaction');
 $state=query('SELECT * FROM archive_tls_history_state WHERE id=1 FOR UPDATE')[0]??null;
 if(!$state)throw new RuntimeException('FTPS history state unavailable');
 $now??=time();$at=gmdate('Y-m-d H:i:s',$now);
 $settings??=archive_tls_settings_read();$health=archive_tls_health($now,$settings);$targets=[];$conditions=[];
 foreach($health['targets'] as $target){
  $targets[$target['id']]=$target;
  foreach($target['alerts'] as $alert){
   $key=$target['id'].':'.$alert['code'];
   $hash=archive_tls_history_key($target,$settings,$alert);
   $conditions[$key]=['target'=>$target,'alert'=>$alert,'hash'=>$hash];
  }
 }
 $open=query('SELECT * FROM archive_tls_alert_history WHERE closed_at IS NULL FOR UPDATE');
 foreach($open as $old){
  $key=$old['destination_id'].':'.$old['alert_code'];$next=$conditions[$key]??null;$target=$targets[(int)$old['destination_id']]??null;
  if($next&&hash_equals($old['condition_key'],$next['hash'])){
   execute('UPDATE archive_tls_alert_history SET last_seen_at=? WHERE id=?',[$at,$old['id']]);unset($conditions[$key]);continue;
  }
  $reason=archive_tls_history_closure($old,$target,$next,$settings);
  execute('UPDATE archive_tls_alert_history SET closed_at=?,closure_reason=? WHERE id=?',[$at,$reason,$old['id']]);
 }
 foreach($conditions as $condition){
  $target=$condition['target'];$alert=$condition['alert'];
  execute('INSERT INTO archive_tls_alert_history(destination_id,destination_name,host,port,destination_revision,alert_code,severity,message,condition_key,warning_days,critical_days,settings_revision,certificate_sha256,expires_at,days_remaining_at_start,triggered_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[$target['id'],$target['name'],$target['host'],$target['port'],$target['revision'],$alert['code'],$alert['severity'],$alert['message'],$condition['hash'],$settings['warning_days'],$settings['critical_days'],$settings['revision'],$target['sha256'],$target['expires_at'],$target['days_remaining'],$at,$at]);
 }
 execute('UPDATE archive_tls_history_state SET coverage_from_at=COALESCE(coverage_from_at,?),checked_at=?,worker_checked_at=IF(?, ?,worker_checked_at) WHERE id=1',[$at,$at,$worker?1:0,$at]);
 return $health;
}

function archive_tls_history_date(mixed $value): string {
 if(!is_string($value))throw new ManagementError('Geçerli bir geçmiş tarihi seçin.');
 if($value==='')return '';
 if(!preg_match('/^[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}$/D',$value))throw new ManagementError('Geçerli bir geçmiş tarihi seçin.');
 $date=DateTimeImmutable::createFromFormat('!Y-m-d',$value,new DateTimeZone('Europe/Istanbul'));
 if(!$date||$date->format('Y-m-d')!==$value)throw new ManagementError('Geçerli bir geçmiş tarihi seçin.');
 return $value;
}
function archive_tls_history_filters(array $input): array {
 $page=$input['tls_history_page']??'1';$target=$input['tls_history_target']??'0';$status=$input['tls_history_status']??'all';$severity=$input['tls_history_severity']??'all';
 if(!is_string($page)||!preg_match('/^[1-9][0-9]{0,5}$/D',$page)||(int)$page>100000)throw new ManagementError('Geçerli bir geçmiş sayfası seçin.');
 if(!is_string($target)||!preg_match('/^(0|[1-9][0-9]{0,9})$/D',$target)||(float)$target>4294967295)throw new ManagementError('Geçerli bir yedekleme hedefi seçin.');
 if(!in_array($status,['all','active','closed'],true))throw new ManagementError('Geçerli bir geçmiş durumu seçin.');
 if(!in_array($severity,['all','warning','error'],true))throw new ManagementError('Geçerli bir uyarı seviyesi seçin.');
 $from=archive_tls_history_date($input['tls_history_from']??'');$to=archive_tls_history_date($input['tls_history_to']??'');
 if($from!==''&&$to!==''&&$from>$to)throw new ManagementError('Başlangıç tarihi bitişten sonra olamaz.');
 return ['target'=>(int)$target,'status'=>$status,'severity'=>$severity,'from'=>$from,'to'=>$to,'page'=>(int)$page];
}
// Period overlap: local start is inclusive; the end date includes its whole day.
// Keep indexed UTC columns bare so date filtering can use the existing indexes.
function archive_tls_history_where(array $filters,bool $withStatus=true): array {
 $where=['1=1'];$args=[];$zone=new DateTimeZone('Europe/Istanbul');$utc=new DateTimeZone('UTC');
 if($filters['target']){$where[]='destination_id=?';$args[]=$filters['target'];}
 if($filters['severity']!=='all'){$where[]='severity=?';$args[]=$filters['severity'];}
 if($filters['from']!==''){$where[]='(closed_at IS NULL OR closed_at>?)';$args[]=(new DateTimeImmutable($filters['from'],$zone))->setTimezone($utc)->format('Y-m-d H:i:s');}
 if($filters['to']!==''&&$filters['to']!=='9999-12-31'){$where[]='triggered_at<?';$args[]=(new DateTimeImmutable($filters['to'],$zone))->modify('+1 day')->setTimezone($utc)->format('Y-m-d H:i:s');}
 if($withStatus&&$filters['status']!=='all')$where[]=$filters['status']==='active'?'closed_at IS NULL':'closed_at IS NOT NULL';
 return [implode(' AND ',$where),$args];
}
function archive_tls_history_columns(): string {return 'id,destination_id,destination_name,host,port,destination_revision,alert_code,severity,message,warning_days,critical_days,settings_revision,certificate_sha256,expires_at,days_remaining_at_start,triggered_at,last_seen_at,closed_at,closure_reason';}
function archive_tls_history_rows(array $rows,int $now): array {
 foreach($rows as &$row){
  foreach(['id','destination_id','port','destination_revision','warning_days','critical_days','settings_revision','days_remaining_at_start'] as $key)if($row[$key]!==null)$row[$key]=(int)$row[$key];
  $start=(new DateTimeImmutable($row['triggered_at'],new DateTimeZone('UTC')))->getTimestamp();
  $end=$row['closed_at']?(new DateTimeImmutable($row['closed_at'],new DateTimeZone('UTC')))->getTimestamp():$now;
  $row['duration_seconds']=max(0,$end-$start);
 }unset($row);return $rows;
}
function archive_tls_history_report(): array {
 $filters=archive_tls_history_filters($_GET);[$baseWhere,$baseArgs]=archive_tls_history_where($filters,false);[$where,$args]=archive_tls_history_where($filters);
 $totals=query('SELECT COUNT(*) total,COALESCE(SUM(closed_at IS NULL),0) active,COALESCE(SUM(closed_at IS NOT NULL),0) closed FROM archive_tls_alert_history WHERE '.$baseWhere,$baseArgs)[0];
 foreach($totals as &$value)$value=(int)$value;unset($value);
 $total=$totals[$filters['status']==='all'?'total':$filters['status']];$pages=max(1,(int)ceil($total/20));$page=min($filters['page'],$pages);
 $rows=archive_tls_history_rows(query('SELECT '.archive_tls_history_columns().' FROM archive_tls_alert_history WHERE '.$where.' ORDER BY triggered_at DESC,id DESC LIMIT 20 OFFSET '.(($page-1)*20),$args),time());
 $targets=[];
 foreach(query('SELECT h.destination_id id,h.destination_name name,h.host FROM archive_tls_alert_history h JOIN (SELECT destination_id,MAX(id) id FROM archive_tls_alert_history GROUP BY destination_id) latest ON latest.id=h.id') as $row)$targets[(int)$row['id']]=$row;
 foreach(query("SELECT id,name,host FROM archive_destinations WHERE protocol='ftps'") as $row)$targets[(int)$row['id']]=$row;
 foreach($targets as &$row)$row['id']=(int)$row['id'];unset($row);ksort($targets);
 $state=query('SELECT coverage_from_at,checked_at,worker_checked_at FROM archive_tls_history_state WHERE id=1')[0]??null;
 $age=$state&&$state['worker_checked_at']?max(0,time()-(new DateTimeImmutable($state['worker_checked_at'],new DateTimeZone('UTC')))->getTimestamp()):null;
 unset($filters['page']);
 return ['rows'=>$rows,'total'=>$total,'totals'=>$totals,'page'=>$page,'pages'=>$pages,'page_size'=>20,'filters'=>$filters,'targets'=>array_values($targets),'coverage_from_at'=>$state['coverage_from_at']??null,'checked_at'=>$state['checked_at']??null,'worker_checked_at'=>$state['worker_checked_at']??null,'fresh'=>$age!==null&&$age<=180];
}
function archive_tls_history_csv_cell(mixed $value): mixed {
 if(!is_string($value))return $value;
 if(preg_match('/^[\x00-\x20\x{FEFF}]*[=+@-]|^[\t\r\n]/u',$value))return "'".$value;
 return $value;
}
function archive_tls_history_csv_time(?string $value): string {return $value?(new DateTimeImmutable($value,new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Europe/Istanbul'))->format('Y-m-d H:i:sP'):'';}
// Build a complete export before sending headers. Large CSVs spill to the
// private PHP temporary directory; SQL rows are fetched in 500-row batches.
function archive_tls_history_export(array $input): array {
 if(!db()->inTransaction())throw new LogicException('CSV export requires a consistent read transaction');
 $filters=archive_tls_history_filters($input);[$where,$args]=archive_tls_history_where($filters);$selection=$input['selection']??'filtered';$raw=$input['ids']??'';
 if(!in_array($selection,['filtered','selected'],true)||!is_string($raw)||strlen($raw)>20000)throw new ManagementError('CSV seçimi geçersiz.');
 $ids=[];
 if($selection==='selected'){
  if($raw==='')throw new ManagementError('CSV için en az bir kayıt seçin.');
  $parts=explode(',',$raw);if(count($parts)>1000)throw new ManagementError('Tek seferde en fazla 1.000 kayıt işaretlenebilir.');
  foreach($parts as $id){if(!preg_match('/^[1-9][0-9]{0,18}$/D',$id)||(strlen($id)===19&&strcmp($id,(string)PHP_INT_MAX)>0))throw new ManagementError('CSV kayıt seçimi geçersiz.');$ids[(int)$id]=true;}
  $ids=array_keys($ids);$where.=' AND id IN ('.implode(',',array_fill(0,count($ids),'?')).')';array_push($args,...$ids);
 }elseif($raw!=='')throw new ManagementError('Filtrelenen kayıtlar için satır seçimi gönderilemez.');
 $count=(int)query('SELECT COUNT(*) total FROM archive_tls_alert_history WHERE '.$where,$args)[0]['total'];
 if($selection==='selected'&&$count!==count($ids))throw new ManagementError('Bazı kayıtlar artık seçili filtreye uymuyor. Geçmişi yenileyip yeniden seçin.',409);
 if($count>50000)throw new ManagementError('CSV en fazla 50.000 kayıt içerebilir. Tarih aralığını daraltın.');
 $out=fopen('php://temp/maxmemory:2097152','w+b');if(!$out)throw new RuntimeException('CSV temporary stream unavailable');
 $reasons=['recovered'=>'Koşul ortadan kalktı','settings_changed'=>'Eşikler değişti','severity_changed'=>'Uyarı seviyesi değişti','certificate_changed'=>'Sertifika değişti','destination_changed'=>'Hedef ayarı değişti','destination_inactive'=>'Hedef kapalı veya FTPS dışında','unconfirmed'=>'Koşul artık doğrulanamıyor','condition_changed'=>'Uyarı türü değişti'];
 $write=function(array $line)use($out):void {if(fputcsv($out,array_map('archive_tls_history_csv_cell',$line),';','"','',"\r\n")===false)throw new RuntimeException('CSV write failed');};
 try {
  if(fwrite($out,"\xEF\xBB\xBF")!==3)throw new RuntimeException('CSV write failed');
  $write(['Kayıt ID','Hedef ID','Hedef','Sunucu','Port','Uyarı kodu','Seviye','Uyarı','Durum','Başlangıç (İstanbul)','Son gözlem (İstanbul)','Kapanış (İstanbul)','Süre (saniye)','Uyarı eşiği (gün)','Kritik eşik (gün)','Kalan gün (başlangıç)','Kapanış kodu','Kapanış nedeni','Hedef sürümü','Eşik sürümü','Sertifika SHA-256','Sertifika bitişi (İstanbul)']);
  $cursor=null;$written=0;$now=time();
  do {
   $seek=$cursor?' AND (triggered_at<? OR (triggered_at=? AND id<?))':'';$seekArgs=$cursor?[$cursor['triggered_at'],$cursor['triggered_at'],$cursor['id']]:[];
   $rows=archive_tls_history_rows(query('SELECT '.archive_tls_history_columns().' FROM archive_tls_alert_history WHERE '.$where.$seek.' ORDER BY triggered_at DESC,id DESC LIMIT 500',[...$args,...$seekArgs]),$now);
   foreach($rows as $row){$write([$row['id'],$row['destination_id'],$row['destination_name'],$row['host'],$row['port'],$row['alert_code'],$row['severity']==='error'?'Kritik':'Uyarı',$row['message'],$row['closed_at']?'Kapalı':'Açık',archive_tls_history_csv_time($row['triggered_at']),archive_tls_history_csv_time($row['last_seen_at']),archive_tls_history_csv_time($row['closed_at']),$row['duration_seconds'],$row['warning_days'],$row['critical_days'],$row['days_remaining_at_start'],$row['closure_reason'],$reasons[$row['closure_reason']]??$row['closure_reason'],$row['destination_revision'],$row['settings_revision'],$row['certificate_sha256'],archive_tls_history_csv_time($row['expires_at'])]);++$written;}
   if($rows)$cursor=end($rows);
  }while(count($rows)===500);
  if($written!==$count)throw new RuntimeException('CSV snapshot count mismatch');
  rewind($out);return ['stream'=>$out,'rows'=>$written,'filename'=>'fls-ftps-alert-history-'.gmdate('Ymd-His').'.csv'];
 }catch(Throwable $e){fclose($out);throw $e;}
}
