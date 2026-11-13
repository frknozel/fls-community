#!/usr/bin/php
<?php
declare(strict_types=1);
define('FLS_CLI_WORKER',true);
define('FLS_DATABASE_CREDENTIAL',getenv('FLS_SEARCH_CREDENTIAL')?:'/etc/fls/search-indexer.json');
require __DIR__.'/../app/bootstrap.php';
/** Commit sparse rows and their checkpoint together; do not write original log tables. */
function mail_search_index_batch(int $batch=5000): array {
 $batch=max(1,min(10000,$batch));$pdo=db();$start=microtime(true);$pdo->beginTransaction();
 try{
  $state=query('SELECT * FROM mail_search_state WHERE id=1 FOR UPDATE')[0]??null;
  if(!$state||(int)$state['version']!==1)throw new RuntimeException('Unsupported mail search index');
  $ids=query("SELECT id FROM events FORCE INDEX(PRIMARY) WHERE id>? ORDER BY id LIMIT $batch",[$state['event_id']]);
  if(!$ids){execute('UPDATE mail_search_state SET ready=1,updated_at=UTC_TIMESTAMP(6),last_batch_ms=0 WHERE id=1');$pdo->commit();return ['scanned'=>0,'indexed'=>0,'event_id'=>(int)$state['event_id'],'ready'=>true];}
  $high=(int)$ids[count($ids)-1]['id'];
  $rows=query("SELECT id,devid,vd,event_at,fields FROM events FORCE INDEX(PRIMARY) WHERE id>? AND id<=? AND JSON_CONTAINS_PATH(fields,'one','$.from','$.to','$.filename','$.messageid')",[$state['event_id'],$high]);
  $values=[];$args=[];
  foreach($rows as $row){
   $fields=json_decode($row['fields'],true,512,JSON_THROW_ON_ERROR);$mail=[];
   foreach(['from','to','filename','messageid'] as $key)$mail[]=is_string($fields[$key]??null)?$fields[$key]:'';
   if(!array_filter($mail,fn($v)=>$v!==''))continue;
   $values[]='(?,?,?,?,?,?,?,?)';array_push($args,$row['id'],$row['devid'],$row['vd'],$row['event_at'],...$mail);
  }
  if($values)execute('INSERT INTO mail_search_events(event_id,devid,vd,event_at,sender,recipient,filename,message_id) VALUES'.implode(',',$values),$args);
  $ms=(int)round(1000*(microtime(true)-$start));
  execute('UPDATE mail_search_state SET event_id=?,scanned_records=scanned_records+?,indexed_records=indexed_records+?,last_batch_ms=?,updated_at=UTC_TIMESTAMP(6) WHERE id=1',[$high,count($ids),count($values),$ms]);
  $pdo->commit();return ['scanned'=>count($ids),'indexed'=>count($values),'event_id'=>$high,'ready'=>(bool)$state['ready']];
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
/** Keep transient database pressure from turning a resumable batch into a crash. */
function mail_search_index_tick(int &$batch): array {
 try{
  $gap=(int)query('SELECT COALESCE(SUM(GREATEST(observed_size-byte_offset,0)),0) n FROM source_files')[0]['n'];
  if($gap>33554432)return ['deferred'=>'original_ingestion'];
  $result=mail_search_index_batch($batch);
  if($batch<5000&&$result['scanned']===$batch)$batch=min(5000,$batch+100);
  return $result;
 }catch(PDOException $e){
  // MariaDB statement timeout, lock wait timeout and deadlock. SQL/schema or
  // credential failures still fail visibly and use the service restart policy.
  $code=(int)($e->errorInfo[1]??0);
  if(!in_array($code,[1205,1213,1969],true))throw $e;
  $batch=max(100,intdiv($batch,2));
  return ['deferred'=>'database_busy','error_code'=>$code];
 }
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){
 if((int)query("SELECT GET_LOCK(CONCAT(DATABASE(),':mail-search-index'),0) locked")[0]['locked']!==1)exit(0);
 db()->exec('SET SESSION max_statement_time=3,innodb_lock_wait_timeout=2');
 $once=in_array('--once',$argv,true);$drain=in_array('--drain',$argv,true);$lastLog=0;$lastDeferredLog=0;$batch=5000;
 do{
  // Yield to the original importer if its existing file checkpoints fall behind.
  $result=mail_search_index_tick($batch);
  if(isset($result['deferred'])){
   if($result['deferred']==='database_busy'){
    if(time()-$lastDeferredLog>=30){fwrite(STDERR,'FLS mail search batch deferred: database error '.$result['error_code'].', checkpoint preserved, batch '.$batch.".\n");$lastDeferredLog=time();}
    if($once)exit(75);
   }elseif($once)break;
   usleep(2000000);continue;
  }
  if(time()-$lastLog>=30){fwrite(STDOUT,json_encode($result)."\n");$lastLog=time();}
  if(!$result['scanned']){if($once||$drain)break;usleep(3000000);}elseif($once)break;else usleep(100000);
 }while(true);
}
