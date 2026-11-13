<?php
declare(strict_types=1);
require_once __DIR__.'/retention.php';

/** Review tokens are separate from log signatures and never authorize physical deletion. */
function retention_preview_key(): string {
    $key=@file_get_contents('/etc/fls/credential-key');
    if($key===false||strlen($key)!==32)throw new ManagementError('Önizleme doğrulaması hazır değil.',503);
    return hash_hmac('sha256','FLS-Retention-Review-v1',$key,true);
}
function retention_preview_context(array $old,int $years,int $days): array {
    return ['uid'=>(int)($_SESSION['uid']??0),'sv'=>(int)($_SESSION['session_version']??-1),
        'session'=>hash('sha256',(string)($_SESSION['csrf']??'')),
        'revision'=>(int)$old['revision'],'old_years'=>(int)$old['retention_years'],'old_days'=>(int)$old['fast_days'],
        'years'=>$years,'days'=>$days];
}
function retention_preview_token(array $old,int $years,int $days,int $issued): string {
    $payload=retention_preview_context($old,$years,$days)+['iat'=>$issued,'exp'=>$issued+600];
    $encoded=rtrim(strtr(base64_encode(json_encode($payload,JSON_THROW_ON_ERROR)),'+/','-_'),'=');
    return $encoded.'.'.hash_hmac('sha256',$encoded,retention_preview_key());
}
function retention_preview_verify(array $input,array $old,int $years,int $days): void {
    $token=$input['preview_token']??null;
    if(!is_string($token)||strlen($token)>2048||!preg_match('/^([A-Za-z0-9_-]+)\.([a-f0-9]{64})$/D',$token,$parts))throw new ManagementError('Süre azaltmadan önce güncel önizlemeyi onaylayın.');
    if(!hash_equals(hash_hmac('sha256',$parts[1],retention_preview_key()),$parts[2]))throw new ManagementError('Önizleme doğrulanamadı. Yeniden önizleyin.',409);
    try{$raw=base64_decode(strtr($parts[1],'-_','+/'),true);$payload=json_decode($raw===false?'':$raw,true,32,JSON_THROW_ON_ERROR);}catch(Throwable){throw new ManagementError('Önizleme geçersiz. Yeniden önizleyin.',409);}
    $expected=retention_preview_context($old,$years,$days);
    if(!is_array($payload)||array_diff(array_keys($payload),[...array_keys($expected),'iat','exp']))throw new ManagementError('Önizleme geçersiz. Yeniden önizleyin.',409);
    foreach($expected as $key=>$value)if(($payload[$key]??null)!==$value)throw new ManagementError('Ayarlar veya oturum değişti. Yeniden önizleyin.',409);
    $now=time();if(!is_int($payload['iat']??null)||!is_int($payload['exp']??null)||$payload['exp']!==$payload['iat']+600||$payload['iat']>$now+5||$payload['exp']<=$now)throw new ManagementError('Önizlemenin süresi doldu. Yeniden önizleyin.',409);
}
/** Metadata only: no events scan, raw-file read, signature rewrite or delete. */
function retention_preview_impact(int $years,int $days,DateTimeImmutable $now): array {
    $analysisCutoff=$now->modify('-'.$days.' days');
    $targetYear=(int)$now->format('Y')-$years;$month=(int)$now->format('m');
    $last=(int)$now->setDate($targetYear,$month,1)->format('t');
    $archiveCutoff=$now->setDate($targetYear,$month,min((int)$now->format('d'),$last));
    $valid="m.status='verified' AND s.byte_offset=s.observed_size AND s.observed_size=m.bytes AND s.invalid_rows<=s.line_number AND m.signed_at IS NOT NULL";
    $parts=['COUNT(*) catalog_files',"COALESCE(SUM(CASE WHEN $valid THEN 0 ELSE 1 END),0) unknown_files"];$args=[];
    foreach(['analysis'=>$analysisCutoff,'archive'=>$archiveCutoff] as $kind=>$cutoff){
        foreach(['files'=>'1','records'=>'s.line_number-s.invalid_rows','raw_bytes'=>'s.observed_size'] as $metric=>$expr){
            $parts[]="COALESCE(SUM(CASE WHEN ($valid) AND m.signed_at<=? THEN $expr ELSE 0 END),0) {$kind}_{$metric}";
            $args[]=$cutoff->format('Y-m-d H:i:s.u');
        }
    }
    $row=query('SELECT '.implode(',',$parts).' FROM source_files s LEFT JOIN archive_manifests m ON m.source_file=s.name',$args)[0];
    $impact=['unknown_files'=>(int)$row['unknown_files'],'measured_at'=>$now->format('Y-m-d\TH:i:s.u\Z'),'exact_deletion_plan'=>false,'reclaimable_bytes'=>null];
    foreach(['analysis'=>$analysisCutoff,'archive'=>$archiveCutoff] as $kind=>$cutoff){
        $impact[$kind]=['cutoff_utc'=>$cutoff->format('Y-m-d\TH:i:s.u\Z'),'basis'=>'manifest_signed_at_catalog'];
        foreach(['files','records','raw_bytes'] as $metric)$impact[$kind][$metric]=(int)$row[$kind.'_'.$metric];
    }
    return $impact;
}
function retention_preview(array $input): array {
    retention_admin();
    foreach(array_keys($input) as $key)if(!in_array($key,['retention_years','fast_days','revision'],true))throw new ManagementError('Desteklenmeyen önizleme alanı.');
    $years=management_int($input,'retention_years',2,4);$days=management_int($input,'fast_days',45,90);$revision=management_int($input,'revision');
    if(!in_array($years,FLS_RETENTION_YEAR_CHOICES,true)||!in_array($days,FLS_RETENTION_FAST_CHOICES,true))throw new ManagementError('Geçersiz saklama süresi seçimi.');
    db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{
        $old=retention_settings();if($old['revision']!==$revision)throw new ManagementError('Ayarlar değişti. Güncel ayarları yükleyin.',409);
        $now=new DateTimeImmutable('now',new DateTimeZone('UTC'));$impact=retention_preview_impact($years,$days,$now);
        $token=retention_preview_token($old,$years,$days,(int)$now->format('U'));db()->commit();
    }catch(Throwable $e){if(db()->inTransaction())db()->rollBack();throw $e;}
    return ['before'=>array_intersect_key($old,array_flip(['retention_years','fast_days','revision'])),
        'after'=>['retention_years'=>$years,'fast_days'=>$days],
        'reduced'=>['analysis'=>$days<$old['fast_days'],'archive'=>$years<$old['retention_years']],
        'preview_token'=>$token,'checked_at'=>$now->format('Y-m-d\TH:i:s.u\Z'),
        'expires_at'=>$now->modify('+600 seconds')->format('Y-m-d\TH:i:s.u\Z'),
        'impact'=>$impact,'physical_cleanup_enabled'=>false];
}
