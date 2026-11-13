<?php
declare(strict_types=1);
require_once __DIR__.'/backlog-settings.php';

function mail_search_backlog_settings_read(bool $lock=false): array {
    $row=query('SELECT minimum_pending,minimum_seconds,revision,updated_at,updated_by FROM mail_search_backlog_settings WHERE id=1'.($lock?' FOR UPDATE':''))[0]??null;
    if(!$row)throw new RuntimeException('Backlog settings unavailable');
    return backlog_settings_row($row);
}
function mail_search_backlog_settings_response(?array $settings=null): array {
    $settings??=mail_search_backlog_settings_read();$sample=telemetry_latest();$loaded=$sample['mail_search_backlog_settings']??[];$alert=$sample['mail_search_index_alert']??[];
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
/** Settings and their audit record commit together. Version protects other edits. */
function mail_search_backlog_settings_save(array $input,string $username): array {
    $pending=backlog_settings_integer($input['minimum_pending']??null,1,100000000,'Bekleyen kayıt eşiği');
    $minutes=backlog_settings_integer($input['minimum_minutes']??null,1,1440,'Bekleme süresi (dakika)');
    $revision=backlog_settings_integer($input['revision']??null,1,PHP_INT_MAX-1,'Ayar sürümü');
    $pdo=db();$pdo->beginTransaction();
    try{
        backlog_settings_authorize_write();
        $old=mail_search_backlog_settings_read(true);
        if($old['revision']!==$revision){$pdo->rollBack();return ['http_status'=>409,'error'=>'Ayarlar başka bir oturumda değiştirildi. Güncel ayarları yükleyip yeniden deneyin.']+mail_search_backlog_settings_response($old);}
        if($old['minimum_pending']===$pending&&$old['minimum_seconds']===$minutes*60){$pdo->commit();return ['changed'=>false]+mail_search_backlog_settings_response($old);}
        execute('UPDATE mail_search_backlog_settings SET minimum_pending=?,minimum_seconds=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6),updated_by=? WHERE id=1',[$pending,$minutes*60,$username]);
        audit('update_mail_search_backlog_settings','revision='.$old['revision'].'->'.($old['revision']+1).';pending='.$old['minimum_pending'].'->'.$pending.';seconds='.$old['minimum_seconds'].'->'.($minutes*60));
        $settings=mail_search_backlog_settings_read();$pdo->commit();return ['changed'=>true]+mail_search_backlog_settings_response($settings);
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
