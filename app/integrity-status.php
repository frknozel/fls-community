<?php
declare(strict_types=1);

/** Archive metadata only. This helper never opens a raw log or starts a scan. */
function archive_integrity_checks_available(): bool {
    static $available;
    if($available!==null)return $available;
    try{query('SELECT manifest_id,last_full_verified_at,status,error_code,progress_bytes,verification_started_at,updated_at FROM archive_integrity_checks LIMIT 0');return $available=true;}
    catch(Throwable $e){return $available=false;}
}
function archive_integrity_integer(mixed $value,int $minimum=0,int $maximum=PHP_INT_MAX): ?int {
    if(!is_int($value)&&!is_string($value))return null;
    $number=filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>$minimum,'max_range'=>$maximum]]);
    return $number===false?null:$number;
}
function archive_integrity_time(mixed $value): ?string {
    if(!is_string($value)||!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/D',$value))return null;
    try{$date=new DateTimeImmutable($value,new DateTimeZone('UTC'));$errors=DateTimeImmutable::getLastErrors();return $errors&&($errors['warning_count']||$errors['error_count'])?null:$value;}
    catch(Throwable $e){return null;}
}
function archive_integrity_age(?string $value): ?int {
    if($value===null)return null;
    try{return time()-(new DateTimeImmutable($value,new DateTimeZone('UTC')))->getTimestamp();}
    catch(Throwable $e){return null;}
}
function archive_integrity_error(mixed $value): string {
    return is_string($value)&&preg_match('/^[A-Za-z0-9_.:-]{0,64}$/D',$value)?$value:($value===null?'':'unknown');
}
function archive_integrity_raw_columns(): string {
    if(!archive_integrity_checks_available())return "NULL raw_last_full_verified_at,'unknown' raw_check_status,'' raw_check_error,NULL raw_progress_bytes";
    return "ic.last_full_verified_at raw_last_full_verified_at,CASE WHEN BINARY ic.status IN (BINARY 'pending',BINARY 'partial',BINARY 'verified',BINARY 'FAILED') THEN ic.status ELSE 'unknown' END raw_check_status,COALESCE(ic.error_code,'') raw_check_error,ic.progress_bytes raw_progress_bytes";
}
function archive_integrity_snapshot(): array {
    $empty=['total_files'=>null,'never_verified'=>null,'overdue'=>null,'failed'=>null,'partial'=>null,'pending'=>null,'unknown'=>null,'oldest_full_verified_at'=>null,'latest_full_verified_at'=>null];
    $result=['schema'=>1,'metadata_available'=>false,'state'=>'unknown','target_age_days'=>30,
        'methods'=>['signature_chain'=>'SHA-256 + Ed25519 · manifest zinciri','raw_full_hash'=>'SHA-256 · ham dosyanın tamamı'],
        'worker'=>['status'=>'unknown','fresh'=>false,'age_seconds'=>null,'last_started_at'=>null,'last_finished_at'=>null,'heartbeat_at'=>null,'bytes_read'=>null,'files_verified'=>null,'current_manifest_id'=>null,'max_bytes'=>null,'max_seconds'=>null,'read_bytes_per_second'=>null,'last_error_code'=>''],
        'metrics'=>$empty,'current'=>null,'checked_at'=>gmdate('Y-m-d H:i:s')];
    try{
        $row=query('SELECT version,status,last_started_at,last_finished_at,heartbeat_at,bytes_read,files_verified,current_manifest_id,max_bytes,max_seconds,read_bytes_per_second,target_age_days,last_error_code FROM archive_integrity_worker WHERE id=1')[0]??null;
        if($row){
            $status=in_array($row['status'],['idle','running','paused','failed'],true)?$row['status']:'unknown';
            $worker=$result['worker'];$worker['status']=$status;
            foreach(['last_started_at','last_finished_at','heartbeat_at'] as $key)$worker[$key]=archive_integrity_time($row[$key]);
            foreach(['bytes_read','files_verified'] as $key)$worker[$key]=archive_integrity_integer($row[$key]);
            foreach(['max_bytes'=>[1048576,2147483648],'max_seconds'=>[1,60],'read_bytes_per_second'=>[1048576,67108864]] as $key=>$range)$worker[$key]=archive_integrity_integer($row[$key],$range[0],$range[1]);
            $id=archive_integrity_integer($row['current_manifest_id'],1);$worker['current_manifest_id']=$id===null?null:(string)$id;
            $worker['last_error_code']=archive_integrity_error($row['last_error_code']);
            $target=archive_integrity_integer($row['target_age_days'],1,365);if($target!==null)$result['target_age_days']=$target;
            $worker['age_seconds']=archive_integrity_age($status==='running'?$worker['heartbeat_at']:$worker['last_finished_at']);
            $age=$worker['age_seconds'];$valid=archive_integrity_integer($row['version'],1,1)===1&&$target!==null&&$worker['max_bytes']!==null&&$worker['max_seconds']!==null&&$worker['read_bytes_per_second']!==null;
            $worker['fresh']=$valid&&$age!==null&&$age>=-5&&(($status==='running'&&$age<=120)||($status==='idle'&&$age<=600));
            $result['worker']=$worker;
        }
    }catch(Throwable $e){/* A missing/older schema is an unknown measurement. */}
    if(!archive_integrity_checks_available())return $result;
    try{
        $days=$result['target_age_days'];
        $metrics=query("SELECT COUNT(*) total_files,COALESCE(SUM(ic.last_full_verified_at IS NULL),0) never_verified,COALESCE(SUM(ic.last_full_verified_at<UTC_TIMESTAMP(6)-INTERVAL $days DAY),0) overdue,COALESCE(SUM(BINARY ic.status=BINARY 'FAILED'),0) failed,COALESCE(SUM(BINARY ic.status=BINARY 'partial'),0) partial,COALESCE(SUM(ic.manifest_id IS NULL OR BINARY ic.status=BINARY 'pending'),0) pending,COALESCE(SUM(ic.manifest_id IS NOT NULL AND (BINARY ic.status NOT IN (BINARY 'pending',BINARY 'partial',BINARY 'verified',BINARY 'FAILED') OR ic.last_full_verified_at>UTC_TIMESTAMP(6)+INTERVAL 5 SECOND)),0) unknown,MIN(ic.last_full_verified_at) oldest_full_verified_at,MAX(ic.last_full_verified_at) latest_full_verified_at FROM archive_manifests m LEFT JOIN archive_integrity_checks ic ON ic.manifest_id=m.id")[0];
        foreach(['total_files','never_verified','overdue','failed','partial','pending','unknown'] as $key)$metrics[$key]=(int)$metrics[$key];
        foreach(['oldest_full_verified_at','latest_full_verified_at'] as $key)$metrics[$key]=archive_integrity_time($metrics[$key]);
        $result['metrics']=$metrics;$result['metadata_available']=true;
        $current=$result['worker']['current_manifest_id'];
        if($current!==null){
            $active=query('SELECT m.id,m.source_file,m.bytes raw_bytes,ic.status,ic.error_code,ic.progress_bytes,ic.verification_started_at,ic.last_full_verified_at FROM archive_manifests m LEFT JOIN archive_integrity_checks ic ON ic.manifest_id=m.id WHERE m.id=?',[$current])[0]??null;
            if($active){
                $bytes=archive_integrity_integer($active['raw_bytes']);$progress=archive_integrity_integer($active['progress_bytes']);
                $result['current']=['manifest_id'=>(string)$active['id'],'source_file'=>$active['source_file'],'raw_bytes'=>$bytes,'progress_bytes'=>$progress,'status'=>in_array($active['status'],['pending','partial','verified','FAILED'],true)?$active['status']:'unknown','error_code'=>archive_integrity_error($active['error_code']),'verification_started_at'=>archive_integrity_time($active['verification_started_at']),'last_full_verified_at'=>archive_integrity_time($active['last_full_verified_at'])];
            }
        }
        $worker=$result['worker'];
        $result['state']=$metrics['failed']>0||$worker['status']==='failed'?'attention':(!$worker['fresh']?($worker['status']==='unknown'?'unknown':'stale'):($metrics['unknown']>0?'unknown':($metrics['never_verified']>0||$metrics['overdue']>0||$metrics['partial']>0||$metrics['pending']>0?'pending':'healthy')));
    }catch(Throwable $e){$result['state']='unknown';}
    return $result;
}
