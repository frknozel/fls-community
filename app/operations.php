<?php
declare(strict_types=1);
require_once __DIR__.'/system-backups.php';
require_once __DIR__.'/disk-management.php';
require_once __DIR__.'/backup-schedule.php';

/** Host-wide administrator metadata. No log reads, mutations or external calls. */
function operations_capacity(mixed $value,DateTimeImmutable $now): ?array {
    if(!is_array($value)||($value['schema']??null)!==1||($value['available']??null)!==true)return null;
    $at=operations_time($value['at']??null);$mode=$value['storage_mode']??null;
    if(!$at||$at>$now->modify('+5 seconds')||$at<$now->modify('-150 seconds')||!in_array($mode,['hybrid','system-root','dedicated'],true))return null;
    $expected=$mode==='hybrid'?['system','logs']:[$mode==='system-root'?'system':'logs'];$volumes=$value['volumes']??null;
    if(!is_array($volumes)||count($volumes)!==count($expected))return null;$safe=[];
    foreach($expected as $role){
        $v=$volumes[$role]??null;if(!is_array($v))return null;
        foreach(['total','free','used'] as $key)if(!is_int($v[$key]??null)||$v[$key]<0||$v[$key]>DISK_MANAGEMENT_JS_MAX)return null;
        // statvfs available bytes exclude reserved blocks; used+free may be less than total.
        if($v['total']===0||$v['free']>$v['total']||$v['used']>$v['total']-$v['free'])return null;
        $safe[$role]=array_intersect_key($v,array_flip(['total','free','used']));
    }
    $database=['available'=>false];$db=$value['database']??null;
    if(is_array($db)&&($db['available']??null)===true&&($db['statistics']??null)==='estimated'){
        $captured=operations_time($db['measured_at']??null);$valid=$captured&&$captured<=$now->modify('+5 seconds')&&$captured>=$now->modify('-150 seconds');
        foreach(['data_bytes','index_bytes','total_bytes'] as $key)$valid=$valid&&is_int($db[$key]??null)&&$db[$key]>=0&&$db[$key]<=DISK_MANAGEMENT_JS_MAX;
        if($valid&&$db['total_bytes']===$db['data_bytes']+$db['index_bytes'])$database=array_intersect_key($db,array_flip(['available','measured_at','data_bytes','index_bytes','total_bytes','statistics']));
    }
    return ['schema'=>1,'at'=>$value['at'],'available'=>true,'storage_mode'=>$mode,'volumes'=>$safe,'database'=>$database,'history_error'=>isset($value['history_error'])?'capacity_history_unavailable':null];
}
function operations_evaluate(array $facts,DateTimeImmutable $now): array {
    $alerts=[];$checks=[];
    $add=function(string $id,string $level,string $title,string $detail,string $url)use(&$alerts):void{$alerts[]=['id'=>$id,'level'=>$level,'title'=>$title,'detail'=>$detail,'url'=>$url];};
    $capacity=operations_capacity($facts['capacity']??null,$now);$fresh=$capacity!==null;
    if(!$fresh)$add('capacity_unknown','warning','Disk ölçümü güncel değil','Son kapasite ölçümü doğrulanamadı.','/?view=system&system_tab=resources');
    if($fresh&&$capacity['database']['available']!==true)$add('database_capacity_unknown','warning','Veritabanı kapasitesi doğrulanamadı','Son tahmini veritabanı ölçümü güncel değil.','/?view=system&system_tab=resources');
    if($fresh&&$capacity['history_error']!==null)$add('capacity_history_unknown','warning','Kapasite geçmişi güncellenemedi','Anlık ölçüm mevcut; günlük eğilim kaydı doğrulanamadı.','/?view=system&system_tab=resources');
    foreach($fresh?($capacity['volumes']??[]):[] as $role=>$volume){
        $total=$volume['total']??null;$free=$volume['free']??null;
        if(!is_int($total)||!is_int($free)||$total<=0||$free<0||$free>$total)continue;
        $label=$role==='system'?'Sistem diski':'Log ve yedek diski';$used=1-$free/$total;
        $critical=$used>=0.95||$free<5*1024**3;$warning=$used>=0.85||$free<10*1024**3;
        if($critical||$warning)$add('space_'.$role,$critical?'critical':'warning',$label.' alanı azalıyor',round(100*$used,1).'% dolu · '.round($free/1024**3,1).' GiB boş.','/?view=settings&settings_tab=product');
        $checks[]=['id'=>'space_'.$role,'state'=>$critical?'critical':($warning?'warning':'current'),'label'=>$label,'free_bytes'=>$free,'total_bytes'=>$total];
    }
    $daily=is_array($facts['daily']??null)?$facts['daily']:[];
    if(($daily['enabled']??false)!==true)$add('daily_disabled','warning','Günlük DB yedeği etkin değil','23:00 yedek ve 23:35 FTPS zamanlayıcılarını kontrol edin.','/?view=settings&settings_tab=archive');
    foreach(['create'=>['23:00','Günlük DB yedeği'],'upload'=>['23:35','DB yedeği FTPS aktarımı']] as $action=>[$clock,$label]){
        $due=operations_last_due($now,$clock);
        // Upload completes after 23:35, but its source snapshot belongs to 23:00.
        $sourceDue=$action==='upload'?operations_last_due($due,'23:00'):$due;
        $state=operations_job_state($daily[$action]??null,$sourceDue,$now);
        if($action==='upload'&&$state==='overdue'&&$now<$due->modify('+30 minutes'))$state='waiting';
        if($action==='upload'&&$state==='current'&&($daily[$action]['readback_sha256_verified']??false)!==true)$state='unknown';
        $checks[]=['id'=>'daily_'.$action,'state'=>$state,'label'=>$label,'at'=>$daily[$action]['completed_at_utc']??null];
        if(in_array($state,['failed','stuck','overdue','never','unknown'],true))$add('daily_'.$action,$state==='stuck'?'critical':'warning',$label.' · '.(['failed'=>'Başarısız','stuck'=>'Beklenenden uzun sürüyor','overdue'=>'Gecikmiş','never'=>'Henüz çalışmadı','unknown'=>'Doğrulanamadı'][$state]),'Planlanan saat '.$clock.' · İstanbul.','/?view=settings&settings_tab=archive');
    }
    $full=$facts['full_backup']??null;$created=operations_time($full['created_at']??null);
    if(!$created||$created>$now->modify('+5 seconds')||$created<$now->modify('-7 days'))$add('system_backup_age','warning','FLS sistem yedeği güncellenmeli','Son doğrulanmış logsuz sistem yedeği yok, zamanı doğrulanamadı veya yedi günden eski.','/?view=settings&settings_tab=archive');
    $job=$facts['system_job']??null;
    if(($job['status']??'')==='failed')$add('system_backup_job','warning','Son sistem yedeği işlemi başarısız','Yerel yedek ve FTPS iş geçmişini kontrol edin.','/?view=settings&settings_tab=archive');
    if(in_array($job['status']??'',['running','queued'],true)){
        $started=operations_time($job['started_at']??$job['requested_at']??null);
        if(!$started||$started>$now->modify('+5 seconds')||$started<$now->modify('-35 minutes'))$add('system_backup_job','critical','Sistem yedeği işi doğrulanmalı','İş süresini ve yedek işçisini kontrol edin.','/?view=settings&settings_tab=archive');
    }
    $inventory=$facts['disk_inventory']??null;$inventoryFresh=is_array($inventory)&&($inventory['fresh']??null)===true&&($inventory['available']??null)===true;
    foreach(['checked_at','generated_at_utc'] as $key){$at=operations_time($inventory[$key]??null);if(!$at||$at>$now->modify('+5 seconds')||$at<$now->modify('-45 seconds'))$inventoryFresh=false;}
    $checks[]=['id'=>'disk_inventory','state'=>$inventoryFresh?'current':'unknown','label'=>'Disk envanteri'];
    if(!$inventoryFresh)$add('disk_inventory_unknown','warning','Disk envanteri güncel değil','Eşleme diskinin varlığı ve güncel durumu doğrulanamadı.','/?view=settings&settings_tab=storage');
    $mirror=$facts['mirror']??null;
    if($mirror!==null){
        $synced=operations_time($mirror['last_sync_at']??null);$status=$mirror['last_sync_status']??'never';
        if(!is_array($mirror)||($mirror['present']??null)!==true||$status!=='succeeded'||!$synced||$synced>$now->modify('+5 seconds')||$synced<$now->modify('-3 hours'))$add('mirror_lag','warning','Eşleme kopyası güncel değil','Son başarılı rsync zamanı ve disk bağlantısını kontrol edin.','/?view=settings&settings_tab=storage');
    }
    foreach(['archive_delivery'=>'Saatlik arşiv FTPS aktarımı','timestamp_delivery'=>'Damga belgesi aktarımı'] as $key=>$label){
        $pending=$facts[$key]??null;$oldest=operations_time($pending['oldest_at']??null);
        if($oldest&&$oldest<$now->modify('-2 hours'))$add($key,'warning',$label.' gecikiyor','Toplam '.(int)($pending['pending']??0).' bekleyen iş; en eskisi iki saati aşıyor.','/?view=archive');
    }
    usort($alerts,fn($a,$b)=>(($b['level']==='critical')<=>($a['level']==='critical'))?:strcmp($a['id'],$b['id']));
    return ['schema'=>1,'checked_at'=>$now->format('c'),'state'=>$alerts?($alerts[0]['level']==='critical'?'critical':'warning'):'healthy','alerts'=>$alerts,'checks'=>$checks,'capacity'=>$fresh?$capacity:null,'thresholds'=>['disk_warning_percent'=>85,'disk_critical_percent'=>95,'minimum_warning_free_gib'=>10,'minimum_critical_free_gib'=>5,'daily_grace_minutes'=>30,'system_backup_max_age_days'=>7,'mirror_max_age_hours'=>3]];
}

function operations_capacity_history(string $directory='/srv/fls-server/metrics/telemetry/capacity',?DateTimeImmutable $now=null): array {
    $now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));$days=[];
    // Fixed day names and bounds; never scan arbitrary files or event payloads.
    for($offset=30;$offset>=0;$offset--){
        $day=$now->modify('-'.$offset.' days')->format('Y-m-d');$file=$directory.'/'.$day.'.json';$info=@lstat($file);
        if(!$info||($info['mode']&0170000)!==0100000||$info['nlink']!==1||$info['size']<1||$info['size']>16384)continue;
        try{$row=json_decode((string)file_get_contents($file),true,16,JSON_THROW_ON_ERROR);}catch(Throwable){continue;}
        if(is_array($row)&&($row['schema']??null)===1&&($row['day']??null)===$day&&is_array($row['metrics']??null))$days[]=$row;
    }
    $growth=[];
    foreach(['system','logs','database'] as $role){
        $samples=[];foreach($days as $day){$m=$day['metrics'][$role]??null;if(!is_array($m))continue;$at=operations_time($m['last_at']??null);$used=$m['last_used']??null;$total=$m['total']??null;$free=$m['free']??null;
            if(!$at||$at->format('Y-m-d')!==$day['day']||$at>$now->modify('+5 seconds')||!is_int($used)||$used<0||$used>DISK_MANAGEMENT_JS_MAX)continue;
            if($role!=='database'&&(!is_int($total)||$total<=0||$total>DISK_MANAGEMENT_JS_MAX||!is_int($free)||$free<0||$free>$total||$used>$total-$free))continue;
            // Ignore measurements before a disk replacement/resize in this window.
            if($role!=='database'&&$samples&&$samples[array_key_last($samples)]['total']!==$total)$samples=[];
            $samples[]=['at'=>$at,'used'=>$used,'total'=>$total,'free'=>$free];}
        $value=['role'=>$role,'days_observed'=>count($samples),'state'=>'insufficient_history','bytes_per_day'=>null,'estimated_days_remaining'=>null];
        if($samples&&$samples[array_key_last($samples)]['at']<$now->modify('-150 seconds')){$value['state']='stale_history';$growth[]=$value;continue;}
        if(count($samples)>=7){$first=$samples[0];$last=$samples[array_key_last($samples)];$span=$last['at']->getTimestamp()-$first['at']->getTimestamp();$same=$role==='database'||$first['total']===$last['total'];
            if($span>=6*86400&&$same&&$last['at']>=$now->modify('-2 days')){
                $rate=($last['used']-$first['used'])/($span/86400);$value['state']=$rate>0?'growing':'stable_or_decreasing';$value['bytes_per_day']=(int)round($rate);
                if($role!=='database'&&$rate>0&&is_int($last['free'])&&$last['free']>=0)$value['estimated_days_remaining']=(int)min(36500,floor($last['free']/$rate));
            }
        }
        $growth[]=$value;
    }
    return ['days'=>$days,'growth'=>$growth,'minimum_calendar_samples'=>7,'database_statistics'=>'estimated','physical_cleanup_enabled'=>false];
}

function operations_snapshot(): array {
    system_backups_admin('GET');$now=new DateTimeImmutable('now',new DateTimeZone('UTC'));
    $latest=json_decode(@file_get_contents('/srv/fls-server/metrics/telemetry/latest.json')?:'null',true);
    $facts=['capacity'=>$latest['capacity']??null,'daily'=>system_backups_db_dump(),
        'full_backup'=>query("SELECT created_at FROM system_backups WHERE status='ready' ORDER BY id DESC LIMIT 1")[0]??null,
        'system_job'=>query('SELECT status,requested_at,started_at FROM system_backup_jobs ORDER BY id DESC LIMIT 1')[0]??null];
    $disk=disk_management_state(query('SELECT * FROM disk_management_state WHERE id=1')[0]??null);$facts['mirror']=$disk['mirror'];$facts['disk_inventory']=array_intersect_key($disk,array_flip(['fresh','available','checked_at','generated_at_utc']));
    foreach(['archive_delivery'=>['archive_deliveries','archive_packages a ON a.manifest_id=x.manifest_id'], 'timestamp_delivery'=>['timestamp_deliveries','timestamp_stamps a ON a.id=x.stamp_id']] as $key=>[$deliveries,$artifactJoin]){
        $facts[$key]=query("SELECT COUNT(*) pending,MIN(m.signed_at) oldest_at FROM $deliveries x JOIN archive_destinations d ON d.id=x.destination_id AND d.revision=x.destination_revision JOIN $artifactJoin JOIN archive_manifests m ON m.id=a.manifest_id WHERE d.enabled=1 AND x.status<>'verified'")[0]??null;
    }
    return operations_evaluate($facts,$now)+['history'=>operations_capacity_history(now:$now)];
}
