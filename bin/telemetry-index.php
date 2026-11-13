<?php
declare(strict_types=1);
// Private CLI reader. The service supplies a credential with SELECT(id) on
// events and SELECT on the two index state tables; no raw payload or write privileges.
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
$directory=getenv('CREDENTIALS_DIRECTORY');
define('FLS_CLI_WORKER',true);
define('FLS_DATABASE_CREDENTIAL',($directory?:'/run/credentials/fls-telemetry.service').'/database');
require __DIR__.'/../app/bootstrap.php';
require __DIR__.'/../app/archive-status.php';
require __DIR__.'/../app/backlog-settings.php';
require __DIR__.'/../app/mail-search-backlog-settings.php';
try{
    if(!is_readable(FLS_DATABASE_CREDENTIAL))throw new RuntimeException('Telemetry credential unavailable');
    db()->exec('SET SESSION max_statement_time=3');
    db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{$settings=backlog_settings_read();}catch(PDOException){$settings=null;}
    $result=archive_index_status();
    $result['mail_search_index']=mail_search_index_status();
    try{$mailSettings=mail_search_backlog_settings_read();}catch(Throwable){$mailSettings=null;}
    $result['mail_search_backlog_settings']=$mailSettings?array_intersect_key($mailSettings,array_flip(['minimum_pending','minimum_seconds','revision','updated_at'])):null;
    $result['backlog_settings']=$settings?array_intersect_key($settings,array_flip(['minimum_pending','minimum_seconds','revision','updated_at'])):null;
    db()->commit();
}catch(Throwable $e){
    // Do not echo connection details or secrets to the telemetry journal.
    $result=['status'=>'unavailable','pending_records'=>null,'checked_at'=>gmdate('c'),'updated_at'=>null,'mail_search_index'=>['status'=>'unavailable','pending_records'=>null,'checked_at'=>null,'updated_at'=>null]];
}
echo json_encode($result,JSON_THROW_ON_ERROR)."\n";
