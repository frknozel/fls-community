#!/usr/bin/php
<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
$options=getopt('',['credential:']);
if(!is_string($options['credential']??null)){fwrite(STDERR,"Usage: archive-tls-history.php --credential FILE\n");exit(2);}
define('FLS_CLI_WORKER',true);define('FLS_DATABASE_CREDENTIAL',$options['credential']);
require __DIR__.'/../app/bootstrap.php';
require __DIR__.'/../app/archive-tls-history.php';
try {
 $pdo=db();$pdo->exec('SET SESSION max_statement_time=10,innodb_lock_wait_timeout=5');$pdo->beginTransaction();
 archive_tls_history_reconcile(null,null,true);$pdo->commit();
}catch(Throwable $e){if(isset($pdo)&&$pdo->inTransaction())$pdo->rollBack();error_log('FLS FTPS alert history recording failed: '.get_class($e));exit(1);}
