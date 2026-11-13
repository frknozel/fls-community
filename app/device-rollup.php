<?php
declare(strict_types=1);
const DEVICE_METRIC_FIELDS=['devid','vd','hour_at','type','subtype','outcome','rating_error','policyid','profile','reason_code'];
function device_metric_key(array $r): string {return hash('sha256',json_encode(array_map(fn($k)=>(string)$r[$k],DEVICE_METRIC_FIELDS),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),true);}
function device_dimension_key(array $r): string {return hash('sha256',json_encode(array_map(fn($k)=>(string)$r[$k],['devid','vd','srcip','policyid','profile','subtype','outcome','reason_code','family','target_json','reason_json']),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),true);}
function device_metric_write(array $buckets): void {
    foreach(array_chunk($buckets,300) as $chunk){
        $params=[];foreach($chunk as $r){$params[]=device_metric_key($r);foreach(DEVICE_METRIC_FIELDS as $key)$params[]=$r[$key];$params[]=$r['records'];}
        execute('INSERT INTO device_hourly_counts(dimension,'.implode(',',DEVICE_METRIC_FIELDS).',records) VALUES '.implode(',',array_fill(0,count($chunk),'('.implode(',',array_fill(0,12,'?')).')')).' ON DUPLICATE KEY UPDATE records=records+VALUES(records)',$params);
    }
}
function device_rollup_events(array $rows): void {
    $buckets=[];$policies=[];$sources=[];
    foreach($rows as $r){
        $r['hour_at']=substr($r['event_at'],0,13).':00:00';$key=bin2hex(device_metric_key($r));
        if(!isset($buckets[$key]))$buckets[$key]=$r+['records'=>0];$buckets[$key]['records']++;
        $name=$r['policy_name']??'';
        if($name!==''){$key=json_encode([$r['devid'],$r['vd'],$r['policyid'],$r['poluuid']]);if(!isset($policies[$key])||$r['event_at']>=$policies[$key][5])$policies[$key]=[$r['devid'],$r['vd'],$r['policyid'],$r['poluuid'],mb_substr($name,0,160),$r['event_at']];}
        if($r['srcip']!==''&&$r['srcname']!==''){$key=json_encode([$r['devid'],$r['vd'],$r['srcip']]);if(!isset($sources[$key])||$r['event_at']>=$sources[$key][4])$sources[$key]=[$r['devid'],$r['vd'],$r['srcip'],$r['srcname'],$r['event_at']];}
    }
    device_metric_write(array_values($buckets));
    foreach([['device_policies','devid,vd,policyid,poluuid,name,observed_at',$policies,6],['device_sources','devid,vd,ip,name,observed_at',$sources,5]] as [$table,$fields,$values,$n]){
        foreach(array_chunk(array_values($values),300) as $chunk){$params=[];foreach($chunk as $r)array_push($params,...$r);execute("INSERT INTO $table($fields) VALUES ".implode(',',array_fill(0,count($chunk),'('.implode(',',array_fill(0,$n,'?')).')')).' ON DUPLICATE KEY UPDATE name=IF(VALUES(observed_at)>=observed_at,VALUES(name),name),observed_at=GREATEST(observed_at,VALUES(observed_at))',$params);}
    }
}
