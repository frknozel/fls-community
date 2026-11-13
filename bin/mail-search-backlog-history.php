<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
define('FLS_CLI_WORKER',true);
define('FLS_DATABASE_CREDENTIAL',(getenv('CREDENTIALS_DIRECTORY')?:'/run/credentials/fls-mail-backlog-history.service').'/history-database');
require __DIR__.'/../app/bootstrap.php';
require __DIR__.'/../app/mail-search-backlog-history-index.php';
$lock=fopen('/run/fls-mail-backlog-history/history.lock','c');
if(!$lock||!flock($lock,LOCK_EX|LOCK_NB))exit;
try{db()->exec('SET SESSION max_statement_time=3');mail_search_backlog_history_index();}
catch(Throwable $e){error_log('FLS mail-search backlog history recording failed: '.get_class($e));exit(1);}
