<?php
declare(strict_types=1);
require_once __DIR__.'/telemetry.php';

final class BacklogSettingsAuthorizationError extends RuntimeException {}
/** Serialize a settings write with account revocation, including a lock wait. */
function backlog_settings_authorize_write(): void {
    $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[(int)($_SESSION['uid']??0)])[0]??null;
    if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new BacklogSettingsAuthorizationError('Yönetim yetkiniz değişti. Yeniden oturum açın.');
}

function backlog_settings_row(array $row): array {
    return ['minimum_pending'=>(int)$row['minimum_pending'],'minimum_seconds'=>(int)$row['minimum_seconds'],
        'minimum_minutes'=>intdiv((int)$row['minimum_seconds'],60),'revision'=>(int)$row['revision'],
        'updated_at'=>(new DateTimeImmutable($row['updated_at'],new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z'),'updated_by'=>$row['updated_by']];
}
function backlog_settings_read(bool $lock=false): array {
    $row=query('SELECT minimum_pending,minimum_seconds,revision,updated_at,updated_by FROM summary_backlog_settings WHERE id=1'.($lock?' FOR UPDATE':''))[0]??null;
    if(!$row)throw new RuntimeException('Backlog settings unavailable');
    return backlog_settings_row($row);
}
function backlog_settings_response(?array $settings=null): array {
    $settings??=backlog_settings_read();$sample=telemetry_latest();$loaded=$sample['backlog_settings']??[];$alert=$sample['archive_index_alert']??[];
    $applied=['status'=>'unknown','revision'=>null,'at'=>null];
    try{
        $at=new DateTimeImmutable($sample['at']??'invalid',new DateTimeZone('UTC'));$age=microtime(true)-(float)$at->format('U.u');
        if($age>=-5&&$age<=120&&is_int($loaded['revision']??null)){
            $applied=['status'=>'pending','revision'=>$loaded['revision'],'at'=>$sample['at']];
            if($loaded['revision']===$settings['revision']&&($alert['settings_revision']??null)===$settings['revision']&&($alert['status']??'unknown')!=='unknown'&&($alert['rule']['minimum_pending']??null)===$settings['minimum_pending']&&($alert['rule']['minimum_seconds']??null)===$settings['minimum_seconds'])$applied['status']='applied';
        }
    }catch(Throwable){}
    return ['settings'=>$settings,'application'=>$applied];
}
function backlog_settings_integer(mixed $value,int $min,int $max,string $label): int {
    if(!is_string($value)||!preg_match('/^[1-9][0-9]*$/D',$value)||strlen($value)>18)throw new InvalidArgumentException($label.' geçerli bir tam sayı olmalı.');
    $number=filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>$min,'max_range'=>$max]]);
    if($number===false)throw new InvalidArgumentException($label.' '.$min.'–'.$max.' aralığında olmalı.');
    return $number;
}
/** Settings and their audit record commit together. Version protects other edits. */
function backlog_settings_save(array $input,string $username): array {
    $pending=backlog_settings_integer($input['minimum_pending']??null,1,100000000,'Bekleyen kayıt eşiği');
    $minutes=backlog_settings_integer($input['minimum_minutes']??null,1,1440,'Bekleme süresi (dakika)');
    $revision=backlog_settings_integer($input['revision']??null,1,PHP_INT_MAX-1,'Ayar sürümü');
    $pdo=db();$pdo->beginTransaction();
    try{
        backlog_settings_authorize_write();
        $old=backlog_settings_read(true);
        if($old['revision']!==$revision){$pdo->rollBack();return ['http_status'=>409,'error'=>'Ayarlar başka bir oturumda değiştirildi. Güncel ayarları yükleyip yeniden deneyin.']+backlog_settings_response($old);}
        if($old['minimum_pending']===$pending&&$old['minimum_seconds']===$minutes*60){$pdo->commit();return ['changed'=>false]+backlog_settings_response($old);}
        execute('UPDATE summary_backlog_settings SET minimum_pending=?,minimum_seconds=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6),updated_by=? WHERE id=1',[$pending,$minutes*60,$username]);
        audit('update_backlog_settings','revision='.$old['revision'].'->'.($old['revision']+1).';pending='.$old['minimum_pending'].'->'.$pending.';seconds='.$old['minimum_seconds'].'->'.($minutes*60));
        $settings=backlog_settings_read();$pdo->commit();return ['changed'=>true]+backlog_settings_response($settings);
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
