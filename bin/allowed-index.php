#!/usr/bin/php
<?php
declare(strict_types=1);
// Separate least-privilege worker. No source event, parser or archive is modified.
define('FLS_CLI_WORKER',true);
define('FLS_DATABASE_CREDENTIAL',getenv('FLS_ALLOWED_CREDENTIAL')?:'/etc/fls/allowed-index.json');
require __DIR__.'/../app/bootstrap.php';
require_once __DIR__.'/../app/allowed-model.php';

function allowed_index_primary_sql(): string {
    $modules=[];foreach(FLS_ALLOWED_UTM_ACTIONS as $module=>$actions)$modules[]="(subtype='$module' AND action IN ('".implode("','",$actions)."'))";
    return "outcome NOT IN ('security_block','policy_deny','local_deny','other_deny','rating_error') AND rating_error=0 AND ((type='traffic' AND subtype='forward' AND action IN ('".implode("','",FLS_ALLOWED_FORWARD_ACTIONS)."')) OR (type='utm' AND (".implode(' OR ',$modules).')))';
}

function allowed_index_batch(int $batch=2000): array {
    if($batch<1||$batch>2000)throw new InvalidArgumentException('allowed_batch_size');
    $pdo=db();$pdo->beginTransaction();
    try{
        $state=query('SELECT * FROM allowed_index_state WHERE id=1 FOR UPDATE')[0]??null;
        if(!$state||(int)$state['version']!==FLS_ALLOWED_MODEL_VERSION)throw new RuntimeException('allowed_index_version');
        $rows=[];$dimensions=[];$scanned=0;$high=(string)$state['event_id'];
        $pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);
        $statement=null;
        try{
            $candidate=allowed_index_primary_sql();
            $statement=$pdo->prepare("SELECT id event_id,event_at,type,subtype,action,outcome,rating_error,policyid,poluuid,profile,srcip,dstip,dstport,hostname,app,category,devid,vd,CASE WHEN $candidate THEN fields ELSE NULL END fields FROM events FORCE INDEX(PRIMARY) WHERE id>? ORDER BY id LIMIT $batch");
            $statement->execute([$state['event_id']]);
            while($event=$statement->fetch()){
                $scanned++;$high=(string)$event['event_id'];$projected=allowed_model_projection($event);
                if($projected===null)continue;
                $fingerprint=bin2hex($projected['fingerprint']);$dimensions[$fingerprint]=$projected;
                $rows[]=['event_id'=>(string)$event['event_id'],'event_at'=>$event['event_at'],'fingerprint'=>$fingerprint];
            }
        }finally{if($statement!==null)$statement->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
        if($dimensions){
            ksort($dimensions,SORT_STRING);
            $columns=['fingerprint',...FLS_ALLOWED_IDENTITY_COLUMNS,'target_key','target_json'];$parameters=[];
            foreach($dimensions as $dimension)foreach($columns as $column)$parameters[]=$dimension[$column];
            execute('INSERT IGNORE INTO allowed_dimensions('.implode(',',$columns).') VALUES'.implode(',',array_fill(0,count($dimensions),'('.implode(',',array_fill(0,count($columns),'?')).')')),$parameters);
            $found=query('SELECT id,HEX(fingerprint) fingerprint FROM allowed_dimensions WHERE fingerprint IN ('.implode(',',array_fill(0,count($dimensions),'?')).')',array_column(array_values($dimensions),'fingerprint'));
            $map=[];foreach($found as $dimension)$map[strtolower($dimension['fingerprint'])]=(string)$dimension['id'];
            if(count($map)!==count($dimensions))throw new RuntimeException('allowed_dimension_catalog');
            $parameters=[];$hours=[];
            foreach($rows as $event){
                $dimension=$map[$event['fingerprint']];array_push($parameters,$event['event_id'],$dimension,$event['event_at']);
                $hour=substr($event['event_at'],0,13).':00:00';$key=$dimension.'|'.$hour;
                if(!isset($hours[$key]))$hours[$key]=[$dimension,$hour,0,$event['event_at'],$event['event_at'],$event['event_id']];
                $hours[$key][2]++;$hours[$key][3]=min($hours[$key][3],$event['event_at']);$hours[$key][4]=max($hours[$key][4],$event['event_at']);
                if(strlen($event['event_id'])>strlen($hours[$key][5])||strlen($event['event_id'])===strlen($hours[$key][5])&&strcmp($event['event_id'],$hours[$key][5])>0)$hours[$key][5]=$event['event_id'];
            }
            execute('INSERT INTO allowed_event_index(event_id,dimension_id,event_at) VALUES'.implode(',',array_fill(0,count($rows),'(?,?,?)')),$parameters);
            $parameters=[];foreach($hours as $hour)array_push($parameters,...$hour);
            execute('INSERT INTO allowed_hour_counts(dimension_id,hour_at,records,first_event_at,last_event_at,last_event_id) VALUES'.implode(',',array_fill(0,count($hours),'(?,?,?,?,?,?)')).' ON DUPLICATE KEY UPDATE records=records+VALUES(records),first_event_at=LEAST(first_event_at,VALUES(first_event_at)),last_event_at=GREATEST(last_event_at,VALUES(last_event_at)),last_event_id=GREATEST(last_event_id,VALUES(last_event_id))',$parameters);
        }
        $caughtUp=$scanned===0||!query('SELECT id FROM events FORCE INDEX(PRIMARY) WHERE id>? ORDER BY id LIMIT 1',[$high]);
        execute('UPDATE allowed_index_state SET event_id=?,scanned_records=scanned_records+?,ready=GREATEST(ready,?),updated_at=UTC_TIMESTAMP(6) WHERE id=1',[$high,$scanned,(int)$caughtUp]);
        $pdo->commit();
        return ['scanned'=>$scanned,'allowed'=>count($rows),'event_id'=>$high,'caught_up'=>$caughtUp];
    }catch(Throwable $error){if($pdo->inTransaction())$pdo->rollBack();throw $error;}
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){
    require_once __DIR__.'/../app/license.php';
    $once=in_array('--once',$argv,true);$drain=in_array('--drain',$argv,true);$lastLog=0;
    do{
        if(!license_feature_allowed('analysis')){
            execute('UPDATE allowed_index_state SET updated_at=UTC_TIMESTAMP(6) WHERE id=1');
            if(time()-$lastLog>=30){fwrite(STDOUT,json_encode(['status'=>'license_restricted'],JSON_THROW_ON_ERROR)."\n");$lastLog=time();}
            if($once||$drain)break;sleep(10);continue;
        }
        $result=allowed_index_batch();
        if(time()-$lastLog>=30){fwrite(STDOUT,json_encode($result,JSON_THROW_ON_ERROR)."\n");$lastLog=time();}
        if($once||$drain&&!$result['scanned'])break;
        usleep($result['scanned']?100000:3000000);
    }while(true);
}
