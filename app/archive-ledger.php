<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
require_once __DIR__.'/integrity-status.php';
function archive_ledger_choice(string $key,array $values,string $default='all'): string {
 $v=$_GET[$key]??$default;if(!is_string($v)||!in_array($v,$values,true))throw new ManagementError('Geçersiz arşiv filtresi: '.$key);return $v;
}
function archive_ledger_date(string $key): string {
 $v=$_GET[$key]??'';if(!is_string($v))throw new ManagementError('Arşiv tarihi geçersiz.');if($v==='')return '';
 $date=DateTimeImmutable::createFromFormat('!Y-m-d',$v,new DateTimeZone('Europe/Istanbul'));
 if(!$date||$date->format('Y-m-d')!==$v)throw new ManagementError('Arşiv tarihi geçersiz.');return $v;
}
function archive_ledger_cte(): string {
 $rawColumns=archive_integrity_raw_columns();$rawJoin=archive_integrity_checks_available()?'LEFT JOIN archive_integrity_checks ic ON ic.manifest_id=m.id':'';
 return <<<SQL
WITH backups AS (
 SELECT m.id,
 COUNT(d.id) required_targets,
 COALESCE(SUM(j.status='verified' AND j.remote_sha256=p.sha256 AND (s.status IS NULL OR s.status<>'verified' OR (tj.status='verified' AND tj.remote_sha256=s.sha256))),0) completed_targets,
 COALESCE(SUM(j.status IN ('retry','error','cancelled') OR (j.status='verified' AND j.remote_sha256<>p.sha256) OR (s.status='verified' AND (tj.status IN ('retry','error','cancelled') OR (tj.status='verified' AND tj.remote_sha256<>s.sha256)))),0) failed_targets
 FROM archive_manifests m JOIN archive_destinations d ON d.enabled=1 AND m.id>=d.start_manifest_id
 LEFT JOIN archive_packages p ON p.manifest_id=m.id
 LEFT JOIN timestamp_stamps s ON s.manifest_id=m.id
 LEFT JOIN archive_deliveries j ON j.manifest_id=m.id AND j.destination_id=d.id AND j.destination_revision=d.revision
 LEFT JOIN timestamp_deliveries tj ON tj.stamp_id=s.id AND tj.destination_id=d.id AND tj.destination_revision=d.revision
 GROUP BY m.id
), states AS (
 SELECT m.id,m.source_file,m.bytes raw_bytes,m.rows_count,m.signed_at,m.verified_at,m.status manifest_status,m.sha256 raw_sha256,
 $rawColumns,
 p.filename,p.sha256 package_sha256,p.bytes package_bytes,p.status package_status,p.error_code package_error,
 s.id stamp_id,s.status stamp_status,s.provider,s.stamp_at,s.error_code stamp_error,
 CASE WHEN m.status='verified' THEN 'verified' ELSE 'attention' END local_state,
 CASE WHEN s.status='verified' THEN 'verified' WHEN s.status IN ('error','uncertain') THEN 'attention' WHEN s.status IN ('pending','processing') THEN 'pending'
 WHEN ts.signing_mode='local' THEN 'local_only' WHEN ts.enabled=0 THEN 'disabled'
 WHEN ts.start_manifest_id>0 AND m.id>=ts.start_manifest_id THEN 'missing' ELSE 'outside_scope' END timestamp_state,
 COALESCE(b.required_targets,0) required_targets,COALESCE(b.completed_targets,0) completed_targets,COALESCE(b.failed_targets,0) failed_targets,
 CASE WHEN b.failed_targets>0 THEN 'attention' WHEN b.required_targets>0 AND b.completed_targets=b.required_targets THEN 'verified'
 WHEN b.completed_targets>0 THEN 'partial' WHEN b.required_targets>0 THEN 'pending'
 WHEN EXISTS(SELECT 1 FROM archive_destinations WHERE enabled=1) THEN 'outside_scope' ELSE 'unconfigured' END backup_state
 FROM archive_manifests m $rawJoin LEFT JOIN archive_packages p ON p.manifest_id=m.id LEFT JOIN timestamp_stamps s ON s.manifest_id=m.id
 JOIN timestamp_settings ts ON ts.id=1 LEFT JOIN backups b ON b.id=m.id
), ledger AS (
 SELECT states.*,CASE WHEN local_state='attention' OR BINARY raw_check_status=BINARY 'FAILED' OR package_status IN ('retry','quarantined','error') OR timestamp_state='attention' OR backup_state='attention' THEN 'attention'
 WHEN package_status IS NULL OR package_status<>'ready' OR timestamp_state IN ('pending','missing') OR backup_state IN ('partial','pending','unconfigured') THEN 'missing' ELSE 'complete' END overall_state FROM states
)
SQL;
}
function archive_ledger_snapshot(): array {
 $filters=['status'=>archive_ledger_choice('ledger_status',['all','issues','missing','attention','complete']),
 'local'=>archive_ledger_choice('ledger_local',['all','verified','attention']),
 'timestamp'=>archive_ledger_choice('ledger_timestamp',['all','verified','missing','attention','local_only']),
 'backup'=>archive_ledger_choice('ledger_backup',['all','verified','missing','attention']),
 'from'=>archive_ledger_date('ledger_from'),'to'=>archive_ledger_date('ledger_to')];
 if($filters['from']!==''&&$filters['to']!==''&&$filters['from']>$filters['to'])throw new ManagementError('Başlangıç tarihi bitişten sonra olamaz.');
 $page=$_GET['ledger_page']??'1';if(!is_string($page)||!preg_match('/^[1-9][0-9]{0,6}$/D',$page))throw new ManagementError('Sayfa numarası geçersiz.');
 $where=['1'];$args=[];
 foreach(['status'=>'overall_state','local'=>'local_state','timestamp'=>'timestamp_state','backup'=>'backup_state'] as $key=>$column){
  if($filters[$key]==='all')continue;
  if($key==='status'&&$filters[$key]==='issues')$where[]="overall_state IN ('missing','attention')";
  elseif($key==='timestamp'&&$filters[$key]==='missing')$where[]="timestamp_state<>'verified'";
  elseif($key==='backup'&&$filters[$key]==='missing')$where[]="backup_state IN ('pending','partial','unconfigured')";
  else{$where[]=$column.'=?';$args[]=$filters[$key];}
 }
 foreach(['from','to'] as $key)if($filters[$key]!==''){
  $date=new DateTimeImmutable($filters[$key],new DateTimeZone('Europe/Istanbul'));if($key==='to')$date=$date->modify('+1 day');
  $where[]='source_file'.($key==='from'?'>=':'<').'?';$args[]=$date->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d-H').'.jsonl';
 }
 $where=implode(' AND ',$where);$cte=archive_ledger_cte();
 // Only archive metadata is read. Neither raw log files nor the event index are scanned.
 $pdo=db();$pdo->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
 try{
  $count=(int)query($cte.' SELECT COUNT(*) n FROM ledger WHERE '.$where,$args)[0]['n'];$pages=max(1,(int)ceil($count/25));$page=min((int)$page,$pages);
  $rows=query($cte.' SELECT * FROM ledger WHERE '.$where.' ORDER BY source_file DESC,id DESC LIMIT 25 OFFSET '.(($page-1)*25),$args);
  $targets=query('SELECT id,name,protocol,remote_path,revision,enabled,start_manifest_id FROM archive_destinations ORDER BY id');
  $ids=array_column($rows,'id');$copies=[];
  if($ids){$marks=implode(',',array_fill(0,count($ids),'?'));
   // A job may not yet exist. Use the requested manifest ID, not a nullable job ID.
   $copies=query("SELECT m.id manifest_id,d.id destination_id,d.name,d.protocol,d.revision,d.remote_path base_path,d.start_manifest_id,a.id delivery_id,a.status,a.error_code,a.completed_at,a.next_attempt_at,a.remote_sha256,a.remote_subdir,a.remote_directory,tj.id proof_delivery_id,tj.status proof_status,tj.error_code proof_error,tj.completed_at proof_completed_at,tj.remote_sha256 proof_remote_sha256 FROM archive_manifests m JOIN archive_destinations d ON d.enabled=1 AND m.id>=d.start_manifest_id LEFT JOIN archive_deliveries a ON a.manifest_id=m.id AND a.destination_id=d.id AND a.destination_revision=d.revision LEFT JOIN timestamp_stamps s ON s.manifest_id=m.id LEFT JOIN timestamp_deliveries tj ON tj.stamp_id=s.id AND tj.destination_id=d.id AND tj.destination_revision=d.revision WHERE m.id IN ($marks)",$ids);
  }
  foreach($rows as &$row){foreach(['id','raw_bytes','rows_count','package_bytes','required_targets','completed_targets','failed_targets','stamp_id','raw_progress_bytes'] as $field)if($row[$field]!==null)$row[$field]=(int)$row[$field];$row['copies']=array_values(array_filter($copies,fn($c)=>(int)$c['manifest_id']===(int)$row['id']));
   $hour=DateTimeImmutable::createFromFormat('!Y-m-d-H\\.\\j\\s\\o\\n\\l',$row['source_file'],new DateTimeZone('UTC'));
   $row['hour_at']=$hour?$hour->format('Y-m-d H:i:s'):null;
  }unset($row);
  $metrics=query("SELECT COUNT(*) files,COALESCE(SUM(bytes),0) bytes,COALESCE(SUM(rows_count),0) records,COALESCE(SUM(status<>'verified'),0) failures,MAX(verified_at) verified_at FROM archive_manifests")[0];
  $integrity=archive_integrity_snapshot();
  $pdo->commit();return ['integrity'=>$integrity,'rows'=>$rows,'filters'=>$filters,'pagination'=>['page'=>$page,'pages'=>$pages,'total'=>$count,'per_page'=>25],'metrics'=>$metrics,'scope'=>'server','timezone'=>'Europe/Istanbul','destinations'=>$targets,'checked_at'=>gmdate('Y-m-d H:i:s')];
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
