<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
require_once __DIR__.'/retention.php';
const FLS_COLD_ROOT='/srv/fortigate/archive/detailed';
const FLS_COLD_PUBLIC='/etc/fls/cold-public-key.pem';
const FLS_COLD_MAX_PACKAGE=268435456;
function cold_storage_admin(): void {
    if(($_SESSION['role']??'')!=='admin')throw new ManagementError('Ayrıntılı arşiv yönetici yetkisi gerektirir.',403);
}
function cold_storage_snapshot(): array {
    $page=management_int(['page'=>$_GET['cold_page']??'1'],'page',1,100000);$size=20;
    db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{
        $configuredDays=retention_settings()['fast_days'];
        $worker=query('SELECT *,UTC_TIMESTAMP(6) measured_at FROM cold_storage_worker WHERE id=1')[0]??null;
        $counts=query("SELECT COUNT(*) total,COALESCE(SUM(status='verified'),0) verified,COALESCE(SUM(status='verified' AND restore_verified_at IS NOT NULL),0) restored,COALESCE(SUM(status='verified' AND purpose='canary'),0) canary,COALESCE(SUM(CASE WHEN status='verified' THEN compressed_bytes ELSE 0 END),0) stored_bytes FROM cold_snapshots")[0];
        $pages=max(1,(int)ceil((int)$counts['total']/$size));$page=min($page,$pages);$offset=($page-1)*$size;
        $rows=query("SELECT id,file_id,source_file,purpose,event_count,note_count,compressed_bytes,expanded_bytes,snapshot_at,verified_at,restore_verified_at,status,error_code FROM cold_snapshots ORDER BY id DESC LIMIT $size OFFSET $offset");
        db()->commit();
    }catch(Throwable $e){if(db()->inTransaction())db()->rollBack();throw $e;}
    $age=$worker&&$worker['checked_at']!==null?strtotime($worker['measured_at'].' UTC')-strtotime($worker['checked_at'].' UTC'):null;
    $fresh=$age!==null&&$age>=-5&&$age<=900;$policyCurrent=isset($worker['fast_days'])&&(int)$worker['fast_days']===$configuredDays;$valid=$fresh&&$policyCurrent&&($worker['status']??'')==='ok';
    $summary=['copy_only'=>true,'automatic_removal'=>false,'physical_cold_tier'=>false,'worker_fresh'=>$fresh,'worker_policy_current'=>$policyCurrent,'configured_fast_days'=>$configuredDays,'worker_status'=>$worker['status']??'missing','worker_age_seconds'=>$age===null?null:max(0,$age),'checked_at'=>$worker['checked_at']??null,'last_success_at'=>$worker['last_success_at']??null,'error_code'=>$worker['error_code']??'', 'fast_days'=>isset($worker['fast_days'])?(int)$worker['fast_days']:null];
    foreach(['eligible_files','eligible_records','eligible_bytes','raw_files_seen','unknown_files'] as $key)$summary[$key]=$valid&&$worker[$key]!==null?(int)$worker[$key]:null;
    foreach(['verified_copies'=>'verified','restored_copies'=>'restored','canary_copies'=>'canary','stored_bytes'=>'stored_bytes'] as $key=>$column)$summary[$key]=(int)$counts[$column];
    foreach($rows as &$row){$row['id']=(string)$row['id'];$row['file_id']=(string)$row['file_id'];foreach(['event_count','note_count','compressed_bytes','expanded_bytes'] as $key)$row[$key]=(int)$row[$key];}unset($row);
    return ['summary'=>$summary,'snapshots'=>$rows,'pagination'=>['page'=>$page,'page_size'=>$size,'pages'=>$pages,'total'=>(int)$counts['total']]];
}
function cold_storage_open(string $path,int $maximum,bool $trusted=false) {
    $s=@lstat($path);
    if(!$s||($s['mode']&0170000)!==0100000||$s['nlink']!==1||$s['size']<1||$s['size']>$maximum||($trusted&&($s['uid']!==0||($s['mode']&0022)!==0)))throw new ManagementError('Arşiv dosyası okunamadı veya güvenli değil.',409);
    $f=@fopen($path,'rb');if(!$f)throw new ManagementError('Arşiv dosyası okunamadı.',409);
    $opened=fstat($f);if(!$opened||$opened['ino']!==$s['ino']||$opened['dev']!==$s['dev']||$opened['size']!==$s['size']){fclose($f);throw new ManagementError('Arşiv dosyası değişti.',409);}return $f;
}
function cold_storage_public(): array {
    $f=cold_storage_open(FLS_COLD_PUBLIC,4096,true);try{$pem=stream_get_contents($f);}finally{fclose($f);}
    if(!preg_match('/\A-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+\/=\r\n]+)-----END PUBLIC KEY-----\r?\n?\z/D',$pem,$m))throw new ManagementError('Arşiv açık anahtarı geçersiz.',409);
    $der=base64_decode(preg_replace('/\s+/','',$m[1]),true);
    if($der===false||strlen($der)!==44||substr($der,0,12)!==hex2bin('302a300506032b6570032100'))throw new ManagementError('Arşiv açık anahtarı geçersiz.',409);
    return [$pem,substr($der,12)];
}
function cold_storage_canonical(mixed $v): string {
    $sort=function(mixed $value)use(&$sort): mixed {
        if(is_object($value)){$parts=get_object_vars($value);ksort($parts,SORT_STRING);foreach($parts as &$part)$part=$sort($part);unset($part);return (object)$parts;}
        if(is_array($value))return array_map($sort,$value);
        if(is_float($value))throw new ManagementError('Arşiv manifesti geçersiz.',409);
        return $value;
    };
    return json_encode($sort($v),JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_LINE_TERMINATORS|JSON_THROW_ON_ERROR);
}
function cold_storage_bundle(array $row): array {
    if(!preg_match('/\A\d{4}-\d{2}-\d{2}-\d{2}\.jsonl\z/D',$row['source_file']))throw new ManagementError('Arşiv kaynak adı geçersiz.',409);
    $relative=$row['relative_path'];
    if(!preg_match('~\A(0[1-9]|1[0-2])-\d{4}/(0[1-9]|[12]\d|3[01])-(0[1-9]|1[0-2])-\d{4}/(\d{4}-\d{2}-\d{2}-\d{2})-(canary|archive)\z~D',$relative))throw new ManagementError('Arşiv konumu geçersiz.',409);
    $base=FLS_COLD_ROOT;
    foreach(explode('/',$relative) as $part){$base.='/'.$part;$s=@lstat($base);if(!$s||($s['mode']&0170000)!==0040000)throw new ManagementError('Arşiv dizini güvenli değil.',409);}
    $rootInfo=@lstat(FLS_COLD_ROOT);if(!$rootInfo||($rootInfo['mode']&0170000)!==0040000)throw new ManagementError('Arşiv dizini güvenli değil.',409);
    $f=cold_storage_open($base.'/manifest.json',1048576);try{$raw=stream_get_contents($f);}finally{fclose($f);}
    try{$envelope=json_decode($raw,false,64,JSON_THROW_ON_ERROR);$manifest=$envelope->manifest??null;
        if(!$envelope instanceof stdClass||count(get_object_vars($envelope))!==2||!$manifest instanceof stdClass||!is_string($envelope->signature??null))throw new RuntimeException();
        if(!hash_equals(cold_storage_canonical($envelope)."\n",$raw))throw new RuntimeException();
        $canonical=cold_storage_canonical($manifest);[$pem,$public]=cold_storage_public();$sig=base64_decode($envelope->signature,true);
        if($sig===false||strlen($sig)!==64||!sodium_crypto_sign_verify_detached($sig,$canonical,$public)||!hash_equals($row['manifest_sha256'],hash('sha256',$canonical)))throw new RuntimeException();
        $payload=$manifest->payload??null;
        if(($manifest->signature_algorithm??null)!=='Ed25519'||($manifest->key_id??null)!==hash('sha256',$public)||($manifest->table_counts->events??null)!==(int)$row['event_count']||($manifest->table_counts->event_notes??null)!==(int)$row['note_count']||($payload->uncompressed_bytes??null)!==(int)$row['expanded_bytes'])throw new RuntimeException();
        if(($manifest->schema??null)!=='fls-detailed-snapshot-v1'||($manifest->source_file??null)!==$row['source_file']||(string)($manifest->source_id??'')!==(string)$row['file_id']||($manifest->purpose??null)!==$row['purpose']||($manifest->raw_manifest_sha256??null)!==$row['raw_manifest_sha256']||($payload->file??null)!=='payload.sqlite.gz'||($payload->compressed_sha256??null)!==$row['payload_sha256']||($payload->compressed_bytes??null)!==(int)$row['compressed_bytes'])throw new RuntimeException();
    }catch(Throwable $e){throw new ManagementError('Arşiv imzası veya katalog eşleşmesi doğrulanamadı.',409);}
    return [$base,$raw,$manifest];
}
function cold_storage_download(string $route): never {
    if($route==='cold_snapshot_public_key'){[$body]=cold_storage_public();header('Content-Type: application/x-pem-file');header('Content-Disposition: attachment; filename="fls-cold-public-key.pem"');echo $body;exit;}
    $id=management_int(['id'=>$_GET['id']??''],'id');$row=query('SELECT * FROM cold_snapshots WHERE id=?',[$id])[0]??null;
    if(!$row)throw new ManagementError('Ayrıntılı arşiv bulunamadı.',404);
    if($row['status']!=='verified'||!$row['restore_verified_at'])throw new ManagementError('Ayrıntılı arşivin doğrulaması tamamlanmadı.',409);
    [$base,$manifest]=cold_storage_bundle($row);
    if($route==='cold_snapshot_manifest'){header('Content-Type: application/json; charset=utf-8');header('Content-Disposition: attachment; filename="fls-detail-'.$row['source_file'].'-'.$row['purpose'].'.manifest.json"');echo $manifest;exit;}
    $f=cold_storage_open($base.'/payload.sqlite.gz',FLS_COLD_MAX_PACKAGE);
    try{
        $before=fstat($f);$hash=hash_init('sha256');hash_update_stream($hash,$f);$digest=hash_final($hash);$after=fstat($f);
        if($before['size']!==(int)$row['compressed_bytes']||!hash_equals($row['payload_sha256'],$digest)||$before['ino']!==$after['ino']||$before['size']!==$after['size']||$before['mtime']!==$after['mtime'])throw new ManagementError('Ayrıntılı arşiv dosyasının karması eşleşmiyor.',409);
        rewind($f);header('Content-Type: application/gzip');header('Content-Disposition: attachment; filename="fls-detail-'.$row['source_file'].'-'.$row['purpose'].'.sqlite.gz"');header('Content-Length: '.$before['size']);fpassthru($f);
    }finally{fclose($f);}exit;
}
