#!/usr/bin/php
<?php
declare(strict_types=1);
// Separate derived-data worker: the collector and original importer stay unchanged.
define('FLS_CLI_WORKER',true);
define('FLS_DATABASE_CREDENTIAL',getenv('FLS_ARCHIVE_CREDENTIAL')?:'/etc/fls/importer.json');
require __DIR__.'/../app/bootstrap.php';
require_once __DIR__.'/../app/device-rollup.php';
require __DIR__.'/../app/source-summary.php';
require_once __DIR__.'/../app/archive-query.php';

function archive_index_batch(int $batch=2000): array {
    $pdo=db();$pdo->beginTransaction();
    try{
        $state=query('SELECT * FROM archive_index_state WHERE id=1 FOR UPDATE')[0];
        if((int)$state['version']!==3)throw new RuntimeException('Unsupported archive index version');
        $ids=query("SELECT id FROM events WHERE id>? ORDER BY id LIMIT $batch",[$state['event_id']]);
        if(!$ids){execute('UPDATE archive_index_state SET ready=1,updated_at=UTC_TIMESTAMP(6) WHERE id=1');$pdo->commit();return ['scanned'=>0,'blocks'=>0,'event_id'=>(int)$state['event_id']];}
        $high=(int)$ids[count($ids)-1]['id'];$raw=archive_raw_projection();$joins=archive_raw_joins();
        $rows=query("SELECT $raw FROM events e FORCE INDEX(PRIMARY) $joins WHERE e.id>? AND e.id<=? AND e.outcome IN ('security_block','policy_deny','local_deny')",[$state['event_id'],$high]);
        device_rollup_events(query("SELECT e.devid,e.vd,e.event_at,e.type,e.subtype,e.outcome,e.rating_error,e.policyid,e.poluuid,e.profile,e.reason_code,e.srcip,e.srcname,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.policyname')),'') policy_name FROM events e FORCE INDEX(PRIMARY) WHERE e.id>? AND e.id<=?",[$state['event_id'],$high]));
        $dimensions=[];
        foreach($rows as &$r){
            $r['fingerprint']=device_dimension_key($r);
            $dimensions[bin2hex($r['fingerprint'])]=$r;
        }unset($r);
        if($dimensions){
            $parameters=[];
            foreach($dimensions as $r){array_push($parameters,$r['fingerprint'],$r['devid'],$r['vd'],$r['srcip'],$r['policyid'],$r['profile'],$r['subtype'],$r['outcome'],$r['reason_code'],$r['family'],hash('sha256',$r['target_json'],true),hash('sha256',$r['subtype'].'|'.$r['reason_json'],true),$r['target_json'],$r['reason_json']);}
            // Device and VDOM participate in every dimension fingerprint.
            $values=array_fill(0,count($dimensions),'('.implode(',',array_fill(0,14,'?')).')');
            execute('INSERT IGNORE INTO archive_dimensions(fingerprint,devid,vd,srcip,policyid,profile,subtype,outcome,reason_code,family,target_key,reason_key,target_json,reason_json) VALUES'.implode(',',$values),$parameters);
            $found=query('SELECT HEX(fingerprint) fingerprint,id FROM archive_dimensions WHERE fingerprint IN ('.implode(',',array_fill(0,count($dimensions),'?')).')',array_column(array_values($dimensions),'fingerprint'));
            $map=[];foreach($found as $r)$map[strtolower($r['fingerprint'])]=(int)$r['id'];
            $values=[];$parameters=[];$hours=[];$groupHours=[];
            foreach($rows as $r){
                $dimension=$map[bin2hex($r['fingerprint'])];$values[]='(?,?,?,?)';array_push($parameters,$r['event_id'],$dimension,$r['event_at'],$r['group_key']);
                $hour=substr($r['event_at'],0,13).':00:00';$key=$dimension.'|'.$hour;
                if(!isset($hours[$key]))$hours[$key]=[$dimension,$hour,0,$r['event_at'],$r['event_at']];
                if($r['group_key']!==null){
                    $groupKey=$key.'|'.bin2hex($r['group_key']);$last=$r['event_at'].str_pad((string)$r['event_id'],20,'0',STR_PAD_LEFT);
                    if(!isset($groupHours[$groupKey]))$groupHours[$groupKey]=[$dimension,$r['group_key'],$hour,0,$r['event_at'],$r['event_at'],$last];
                    $groupHours[$groupKey][3]++;$groupHours[$groupKey][4]=min($groupHours[$groupKey][4],$r['event_at']);$groupHours[$groupKey][5]=max($groupHours[$groupKey][5],$r['event_at']);$groupHours[$groupKey][6]=max($groupHours[$groupKey][6],$last);
                }
                $hours[$key][2]++;$hours[$key][3]=min($hours[$key][3],$r['event_at']);$hours[$key][4]=max($hours[$key][4],$r['event_at']);
            }
            execute('INSERT INTO archive_event_index(event_id,dimension_id,event_at,group_key) VALUES'.implode(',',$values),$parameters);
            $parameters=[];foreach($hours as $r)array_push($parameters,...$r);
            execute('INSERT INTO archive_hour_counts(dimension_id,hour_at,records,first_event_at,last_event_at) VALUES'.implode(',',array_fill(0,count($hours),'(?,?,?,?,?)')).' ON DUPLICATE KEY UPDATE records=records+VALUES(records),first_event_at=LEAST(first_event_at,VALUES(first_event_at)),last_event_at=GREATEST(last_event_at,VALUES(last_event_at))',$parameters);
            if($groupHours){
                $parameters=[];foreach($groupHours as $r)array_push($parameters,...$r);
                execute('INSERT INTO archive_group_hours(dimension_id,group_key,hour_at,records,first_event_at,last_event_at,last_record) VALUES'.implode(',',array_fill(0,count($groupHours),'(?,?,?,?,?,?,?)')).' ON DUPLICATE KEY UPDATE records=records+VALUES(records),first_event_at=LEAST(first_event_at,VALUES(first_event_at)),last_event_at=GREATEST(last_event_at,VALUES(last_event_at)),last_record=GREATEST(last_record,VALUES(last_record))',$parameters);
            }
        }
        execute('UPDATE archive_index_state SET event_id=?,updated_at=UTC_TIMESTAMP(6) WHERE id=1',[$high]);
        $pdo->commit();return ['scanned'=>count($ids),'blocks'=>count($rows),'event_id'=>$high];
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){
    $once=in_array('--once',$argv,true);$drain=in_array('--drain',$argv,true);$lastLog=0;
    do{
        $result=archive_index_batch();
        if(time()-$lastLog>=30){fwrite(STDOUT,json_encode($result)."\n");$lastLog=time();}
        if(!$result['scanned']){if($once||$drain)break;sleep(3);}elseif($once)break;
    }while(true);
}
