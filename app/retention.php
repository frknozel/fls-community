<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';

const FLS_RETENTION_FAST_CHOICES=[45,70,90];
const FLS_RETENTION_YEAR_CHOICES=[2,3,4];
const FLS_RETENTION_DEFAULT_FAST_DAYS=45;
const FLS_RETENTION_DEFAULT_YEARS=2;

/** Existing policies remain readable; new writes use the narrower choice lists. */
function retention_valid_fast_days(int $days): bool {
    return in_array($days,FLS_RETENTION_FAST_CHOICES,true)||($days>=90&&$days<=180);
}

function retention_admin(bool $lock=false): void {
    if(($_SESSION['role']??'')!=='admin')throw new ManagementError('Saklama yönetimi yönetici yetkisi gerektirir.',403);
    $actor=query('SELECT role,enabled,session_version FROM users WHERE id=?'.($lock?' FOR UPDATE':''),[(int)($_SESSION['uid']??0)])[0]??null;
    if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti. Yeniden oturum açın.',403);
}
function retention_datetime(string $value): DateTimeImmutable {
    if(!preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z?$/D',$value))throw new InvalidArgumentException('Alım zamanı UTC tarih/saat olmalı.');
    $date=new DateTimeImmutable($value,new DateTimeZone('UTC'));$errors=DateTimeImmutable::getLastErrors();
    if($errors&&($errors['warning_count']||$errors['error_count']))throw new InvalidArgumentException('Alım zamanı geçersiz.');
    return $date->setTimezone(new DateTimeZone('UTC'));
}
/** Calendar anniversary, clamping 29 February to 28 February in a non-leap year. */
function retention_anniversary(DateTimeImmutable $acquired,int $years): DateTimeImmutable {
    if($years<2||$years>5)throw new InvalidArgumentException('Saklama süresi 2–5 takvim yılı olmalı.');
    $year=(int)$acquired->format('Y')+$years;$month=(int)$acquired->format('m');
    $last=(int)$acquired->setDate($year,$month,1)->format('t');
    return $acquired->setDate($year,$month,min((int)$acquired->format('d'),$last));
}
function retention_settings(bool $lock=false): array {
    $row=query('SELECT retention_years,fast_days,revision,updated_at,updated_by FROM retention_settings WHERE id=1'.($lock?' FOR UPDATE':''))[0]??null;
    if(!$row)throw new RuntimeException('Retention settings unavailable');
    foreach(['retention_years','fast_days','revision'] as $key)$row[$key]=(int)$row[$key];
    return $row;
}
function retention_versions(): array {
    $rows=query('SELECT revision,retention_years,fast_days,archive_existing,analysis_existing,effective_at,recorded_at,recorded_by FROM retention_policy_versions ORDER BY effective_at,revision');
    foreach($rows as &$row)foreach(['retention_years','fast_days','revision','archive_existing','analysis_existing'] as $key)$row[$key]=(int)$row[$key];unset($row);return $rows;
}
/** A reduction always needs an explicit choice; applying it affects only reduced dimensions. */
function retention_existing_effect(array $input,array $old,int $years,int $days): array {
    $decreasing=$years<$old['retention_years']||$days<$old['fast_days'];
    if($decreasing&&!array_key_exists('existing_data',$input))throw new ManagementError('Süre azaltılırken mevcut kayıtlar için bir seçim yapın.');
    $mode=array_key_exists('existing_data',$input)?management_enum($input,'existing_data',['preserve','apply']):'preserve';
    if(!$decreasing&&$mode==='apply')throw new ManagementError('Mevcut kayıtlara uygulama yalnız süre azaltılırken seçilebilir.');
    return ['existing_data'=>$mode,'decreasing'=>$decreasing,'archive_existing'=>(int)($mode==='apply'&&$years<$old['retention_years']),'analysis_existing'=>(int)($mode==='apply'&&$days<$old['fast_days'])];
}
/** Public query-preset metadata only; unavailable pre-migration tables use the safe default. */
function retention_fast_days(): int {
    try{$value=query('SELECT fast_days FROM retention_settings WHERE id=1')[0]['fast_days']??FLS_RETENTION_DEFAULT_FAST_DAYS;}
    catch(PDOException $e){
        $missing=$e->getCode()==='42S02'||(($e->errorInfo[1]??null)===1&&str_contains($e->getMessage(),'no such table: retention_settings'));
        if(!$missing)throw $e;$value=FLS_RETENTION_DEFAULT_FAST_DAYS;
    }
    if(!is_numeric($value)||!retention_valid_fast_days((int)$value))return FLS_RETENTION_DEFAULT_FAST_DAYS;
    return (int)$value;
}
/**
 * Non-destructive guard for future lifecycle workers. Only receiver acquisition time
 * is accepted; FortiGate event time and a backdated filename are never a substitute.
 * Every policy which applied while a cohort existed can extend its deadline.
 * An explicit, audited archive_existing reduction can reset an older cohort's
 * deadline. Otherwise reducing the current policy preserves its older protection.
 */
function retention_protection(?string $acquiredAt,array $versions,?DateTimeImmutable $now=null,bool $hold=false): array {
    return retention_dimension_protection('archive',$acquiredAt,$versions,$now,$hold);
}
/** Analysis deadlines follow their own history and never change archive protection. */
function retention_analysis_protection(?string $acquiredAt,array $versions,?DateTimeImmutable $now=null,bool $hold=false): array {
    return retention_dimension_protection('analysis',$acquiredAt,$versions,$now,$hold);
}
function retention_dimension_protection(string $dimension,?string $acquiredAt,array $versions,?DateTimeImmutable $now=null,bool $hold=false): array {
    if(!in_array($dimension,['archive','analysis'],true))throw new InvalidArgumentException('dimension');
    $now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));
    $deny=['deletion_allowed'=>false,'automatic_deletion_enabled'=>false,'remote_deletion_allowed'=>false];
    if($hold)return $deny+['status'=>'held','not_before'=>null];
    try{
        if($acquiredAt===null)throw new InvalidArgumentException('unknown');
        $acquired=retention_datetime($acquiredAt);if($acquired>$now||!$versions)throw new InvalidArgumentException('unknown');
        $latest=null;$units=$dimension==='archive'?2:45;$previous=null;$previousYears=null;$previousDays=null;$covered=false;$expectedRevision=1;
        foreach($versions as $i=>$v){
            if(($v['revision']??null)!==$expectedRevision++||!is_int($v['retention_years']??null)||$v['retention_years']<2||$v['retention_years']>5)throw new InvalidArgumentException('policy');
            $archiveExisting=array_key_exists('archive_existing',$v)?$v['archive_existing']:0;$analysisExisting=array_key_exists('analysis_existing',$v)?$v['analysis_existing']:0;
            if(!in_array($archiveExisting,[0,1],true)||!in_array($analysisExisting,[0,1],true))throw new InvalidArgumentException('policy_flags');
            if(($dimension==='analysis'||array_key_exists('fast_days',$v))&&(!is_int($v['fast_days']??null)||!retention_valid_fast_days($v['fast_days'])))throw new InvalidArgumentException('analysis_policy');
            if($archiveExisting&&($previousYears===null||$v['retention_years']>=$previousYears))throw new InvalidArgumentException('archive_reduction');
            if($analysisExisting&&($previousDays===null||!is_int($v['fast_days']??null)||$v['fast_days']>=$previousDays))throw new InvalidArgumentException('analysis_reduction');
            $previousYears=$v['retention_years'];$previousDays=is_int($v['fast_days']??null)?$v['fast_days']:null;
            $effective=retention_datetime($v['effective_at']);if($previous!==null&&$effective<$previous)throw new InvalidArgumentException('order');$previous=$effective;
            if($effective>$now)continue;
            $next=isset($versions[$i+1])?retention_datetime($versions[$i+1]['effective_at']):null;
            if($effective<=$acquired&&($next===null||$next>$acquired))$covered=true;
            if($next!==null&&$next<=$acquired)continue;
            $candidate=$dimension==='archive'?retention_anniversary($acquired,$v['retention_years']):$acquired->modify('+'.$v['fast_days'].' days');
            $appliesExisting=$dimension==='archive'?$archiveExisting:$analysisExisting;
            if(($appliesExisting&&$effective>=$acquired)||$latest===null||$candidate>$latest){$latest=$candidate;$units=$dimension==='archive'?$v['retention_years']:$v['fast_days'];}
        }
        if(!$covered||$latest===null)throw new InvalidArgumentException('coverage');
        return $deny+['status'=>$now<$latest?'protected':'period_elapsed','not_before'=>$latest->format('Y-m-d\TH:i:s.u\Z'),($dimension==='archive'?'protected_years':'protected_days')=>$units,'basis'=>'receiver_acquired_at'];
    }catch(Throwable){return $deny+['status'=>'unknown_acquisition_or_policy','not_before'=>null];}
}
/** Fast query range is independent of retained data. Archive mode keeps full dates. */
function retention_query_window(string $from,string $to,string $tier='fast',?DateTimeImmutable $now=null,?int $fastDays=null): array {
    if(!in_array($tier,['fast','archive'],true))throw new ManagementError('Sorgu alanı geçersiz.');
    $fastDays??=retention_settings()['fast_days'];if(!retention_valid_fast_days($fastDays))throw new RuntimeException('Invalid fast window');
    $now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));$cutoff=$now->modify('-'.$fastDays.' days')->format('Y-m-d H:i:s.u');
    $from=retention_datetime($from)->format('Y-m-d H:i:s.u');$to=retention_datetime($to)->format('Y-m-d H:i:s.u');
    if($from>=$to)throw new ManagementError('Başlangıç, bitişten önce olmalı.');
    return ['tier'=>$tier,'from'=>$tier==='fast'?max($from,$cutoff):$from,'to'=>$to,'fast_cutoff'=>$cutoff,'requested_from'=>$from,'outside_fast_window'=>$from<$cutoff,'empty'=>$tier==='fast'&&$to<=$cutoff,'fast_days'=>$fastDays];
}
function retention_save(array $input): array {
    retention_admin();
    foreach(array_keys($input) as $key)if(!in_array($key,['retention_years','fast_days','revision','existing_data','preview_token','_csrf'],true))throw new ManagementError('Desteklenmeyen saklama ayarı.');
    $years=management_int($input,'retention_years',2,4);$days=management_int($input,'fast_days',45,90);$revision=management_int($input,'revision');
    if(!in_array($years,FLS_RETENTION_YEAR_CHOICES,true)||!in_array($days,FLS_RETENTION_FAST_CHOICES,true))throw new ManagementError('Geçersiz saklama süresi seçimi.');
    $pdo=db();$pdo->beginTransaction();
    try{
        query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');retention_admin(true);$old=retention_settings(true);
        if($old['revision']!==$revision)throw new ManagementError('Saklama ayarları başka bir oturumda değişti. Güncel ayarları yükleyin.',409);
        $effect=retention_existing_effect($input,$old,$years,$days);
        if($years===$old['retention_years']&&$days===$old['fast_days']){$pdo->commit();return ['saved'=>true,'changed'=>false,'settings'=>$old];}
        if($effect['decreasing']){require_once __DIR__.'/retention-preview.php';retention_preview_verify($input,$old,$years,$days);}
        // Lock order matches other administrative writes. Version insertion and audit
        // are in the same transaction; the web account has no history UPDATE/DELETE.
        $at=query('SELECT UTC_TIMESTAMP(6) at')[0]['at'];
        $previous=query('SELECT effective_at FROM retention_policy_versions WHERE revision=?',[$revision])[0]['effective_at']??null;
        if($previous===null||$at<$previous)throw new ManagementError('Sistem saati veya saklama geçmişi doğrulanamadı. Ayarlar kaydedilmedi.',503);
        execute('INSERT INTO retention_policy_versions(revision,retention_years,fast_days,archive_existing,analysis_existing,effective_at,recorded_at,recorded_by) VALUES(?,?,?,?,?,?,?,?)',[$revision+1,$years,$days,$effect['archive_existing'],$effect['analysis_existing'],$at,$at,$_SESSION['username']]);
        execute('UPDATE retention_settings SET retention_years=?,fast_days=?,revision=revision+1,updated_at=?,updated_by=? WHERE id=1',[$years,$days,$at,$_SESSION['username']]);
        audit('update_retention_policy','revision='.$revision.'->'.($revision+1).';years='.$old['retention_years'].'->'.$years.';fast_days='.$old['fast_days'].'->'.$days.';existing_data='.$effect['existing_data'].';archive_existing='.$effect['archive_existing'].';analysis_existing='.$effect['analysis_existing'].';automatic_deletion=off;remote_rotation=off');
        $saved=retention_settings();$pdo->commit();return ['saved'=>true,'changed'=>true,'settings'=>$saved];
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
/** Fixed paths only: never present the SSD fallback as the configured HDD. */
function retention_storage_mode(): string {
    $path='/etc/fls/storage.json';$info=@lstat($path);
    if($info===false)return 'dedicated';
    if(($info['mode']&0170000)!==0100000||$info['uid']!==0||($info['mode']&0022)!==0||$info['nlink']!==1||$info['size']>4096)return 'unavailable';
    $raw=@file_get_contents($path,false,null,0,4097);if($raw===false||strlen($raw)>4096)return 'unavailable';
    try{$config=json_decode($raw,true,32,JSON_THROW_ON_ERROR);}catch(Throwable){return 'unavailable';}
    if(!is_array($config)||($config['schema']??null)!==1||!in_array($config['mode']??null,['system-root','hybrid'],true))return 'unavailable';
    return $config['mode'];
}
function retention_volume_probe(string $path): array {
    $info=@lstat($path);$canonical=realpath($path);$free=@disk_free_space($path);$total=@disk_total_space($path);
    $good=$info!==false&&($info['mode']&0170000)===0040000&&$canonical===$path&&is_numeric($free)&&is_numeric($total)&&is_finite((float)$free)&&is_finite((float)$total)&&$free>=0&&$total>0&&$free<=$total;
    return ['path'=>$path,'available'=>$good,'device'=>$good?$info['dev']:null,'free_bytes'=>$good?(int)$free:null,'total_bytes'=>$good?(int)$total:null];
}
/** Callable seams allow separate filesystem/absence fixtures without live mounts. */
function retention_storage_capacity(?callable $probe=null,?callable $layout=null): array {
    $probe??=retention_volume_probe(...);$layout??=retention_storage_mode(...);$mode=$layout();
    $system=$probe('/');$logs=$probe('/srv/fls-server/raw');
    $shared=($system['available']??false)&&($logs['available']??false)?$system['device']===$logs['device']:null;
    $expected=in_array($mode,['hybrid','dedicated'],true)?$shared===false:($mode==='system-root'&&$shared===true);
    if(!$expected){$logs=['path'=>'/srv/fls-server/raw','available'=>false,'device'=>null,'free_bytes'=>null,'total_bytes'=>null];$shared=null;}
    unset($system['device'],$logs['device']);
    return ['storage_mode'=>in_array($mode,['hybrid','dedicated','system-root'],true)?$mode:'unavailable','system_volume'=>$system,'log_volume'=>$logs,'volumes_shared'=>$shared,'volume'=>$logs];
}
function retention_capacity(?DateTimeImmutable $now=null): array {
    $now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));$today=$now->setTime(0,0);
    $raw=query('SELECT COUNT(*) files,COALESCE(SUM(observed_size),0) bytes,COALESCE(SUM(byte_offset),0) indexed_bytes,MIN(name) oldest,MAX(name) newest FROM source_files')[0];
    $recent=query('SELECT COUNT(*) hours,COALESCE(SUM(observed_size),0) bytes FROM source_files WHERE name>=? AND name<?',[$today->modify('-7 days')->format('Y-m-d-H').'.jsonl',$today->format('Y-m-d-H').'.jsonl'])[0];
    $packages=query("SELECT COUNT(*) files,COALESCE(SUM(bytes),0) bytes,COALESCE(SUM(status='ready'),0) ready FROM archive_packages")[0];
    $signed=query("SELECT COUNT(*) files,COALESCE(SUM(bytes),0) bytes,COALESCE(SUM(status='verified'),0) verified FROM archive_manifests")[0];
    // InnoDB statistics are approximate. Do not COUNT(*) or scan event payloads.
    $database=query("SELECT COALESCE(SUM(data_length),0) data_bytes,COALESCE(SUM(index_length),0) index_bytes,COALESCE(SUM(CASE WHEN table_name='events' THEN table_rows ELSE 0 END),0) estimated_events FROM information_schema.tables WHERE table_schema=DATABASE()")[0];
    foreach([&$raw,&$recent,&$packages,&$signed,&$database] as &$row)foreach($row as $key=>$value)if(!in_array($key,['oldest','newest'],true))$row[$key]=(int)$value;unset($row);
    return ['raw'=>$raw,'last_seven_complete_utc_days'=>$recent,'daily_raw_bytes'=>$recent['hours']>=24?(int)round($recent['bytes']/$recent['hours']*24):null,'packages'=>$packages,'signed'=>$signed,'database'=>$database,'database_statistics'=>'estimated',...retention_storage_capacity(),'projection_note'=>'Günlük ham log tahmini, son yedi tam UTC gününde kayıt bulunan saatlerin ortalamasından hesaplanır. En az 24 saatlik veri gerekir. Veritabanı, indeks, paket ve disk yedekliliği ayrıca hesaplanır.'];
}
function retention_snapshot(): array {
    retention_admin();$pdo=db();$pdo->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{
        $settings=retention_settings();$versions=retention_versions();$capacity=retention_capacity();$pdo->commit();
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
    $now=new DateTimeImmutable('now',new DateTimeZone('UTC'));$days=(int)$now->diff(retention_anniversary($now,$settings['retention_years']))->format('%a');
    return ['settings'=>$settings,'choices'=>['retention_years'=>FLS_RETENTION_YEAR_CHOICES,'fast_days'=>FLS_RETENTION_FAST_CHOICES],'defaults'=>['retention_years'=>FLS_RETENTION_DEFAULT_YEARS,'fast_days'=>FLS_RETENTION_DEFAULT_FAST_DAYS],'limits'=>['retention_years'=>[2,4],'fast_days'=>[45,90]],'policy'=>['retained'=>['raw_logs','detailed_database','signed_packages'],'basis'=>'receiver_acquired_at','calendar_years'=>true,'analysis_window_days'=>$settings['fast_days'],'signed_archive_years'=>$settings['retention_years'],'physical_cleanup_enabled'=>false,'automatic_deletion_enabled'=>false,'external_rotation'=>'customer_managed','remote_delete_enabled'=>false,'previous_protection_can_shorten'=>true,'reduction_requires_existing_data_choice'=>true,'explicit_existing_data_confirmation_required'=>true,'fast_cutoff'=>$now->modify('-'.$settings['fast_days'].' days')->format('Y-m-d\TH:i:s.u\Z')],'history'=>array_reverse($versions),'capacity'=>$capacity+['retention_raw_projection_bytes'=>$capacity['daily_raw_bytes']===null?null:$capacity['daily_raw_bytes']*$days],'checked_at'=>$now->format('Y-m-d\TH:i:s.u\Z')];
}
/** Route adapter keeps authorization, method and CSRF checks testable together. */
function retention_request(string $route,string $method,array $input,mixed $csrfToken): array {
    retention_admin();$expected=in_array($route,['retention_policy','preview_retention_policy'],true)?'GET':($route==='save_retention_policy'?'POST':null);
    if($expected===null)throw new ManagementError('Saklama işlemi bulunamadı.',404);
    if($method!==$expected)throw new ManagementError('Bu işlem için '.$expected.' kullanılmalı.',405);
    if($method==='POST'&&(!is_string($csrfToken)||!is_string($_SESSION['csrf']??null)||!hash_equals($_SESSION['csrf'],$csrfToken)))throw new ManagementError('Oturum doğrulaması başarısız.',403);
    if($route==='preview_retention_policy'){require_once __DIR__.'/retention-preview.php';return retention_preview($input);}
    return $route==='retention_policy'?retention_snapshot():retention_save($input);
}
