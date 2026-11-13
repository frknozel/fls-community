#!/usr/bin/php
<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit(1);
require __DIR__.'/../app/change-alerts.php';
$lock=fopen(FGA_ROOT.'/.worker.lock','c');if(!$lock||!flock($lock,LOCK_EX|LOCK_NB))exit(0);
try{
    $directory=getenv('CREDENTIALS_DIRECTORY');$credential=$directory?$directory.'/change-alerts.json':'/etc/fls/change-alerts.json';$stat=@lstat($credential);
    if(!$stat||($stat['mode']&0170000)!==0100000||$stat['uid']!==0||($stat['mode']&($directory?0037:0077))!==0||$stat['size']>16384)throw new RuntimeException('credential');
    $value=json_decode(file_get_contents($credential),true,512,JSON_THROW_ON_ERROR);if(($value['user']??'')!=='fls_alerts'||!is_string($value['password']??null))throw new RuntimeException('credential');unset($value);
    define('FLS_CLI_WORKER',true);define('FLS_DATABASE_CREDENTIAL',$credential);require __DIR__.'/../app/bootstrap.php';
    db()->exec('SET max_statement_time=12');
    $devices=query('SELECT id,name,serial,vdom,enabled,is_default,legacy_cache,1 active_keys FROM fortigate_connections WHERE enabled=1 ORDER BY is_default DESC,id LIMIT 16');
    $cursorPath=FGA_ROOT.'/.round-robin.json';$cursor=json_decode(@file_get_contents($cursorPath)?:'null',true);$last=is_array($cursor)?(int)($cursor['last_id']??0):0;
    usort($devices,fn($a,$b)=>(($a['id']<=$last)<=>($b['id']<=$last))?:($a['id']<=>$b['id']));
    $started=microtime(true);$results=[];
    foreach($devices as $device){
        if(microtime(true)-$started>=65)break;
        $result=fg_with_device($device,function()use($device,$started){
            $root=!empty($device['legacy_cache'])?FGA_ROOT:FGA_ROOT.'/devices/'.(int)$device['id'];
            if(!is_dir($root)&&!mkdir($root,0750,true)&&!is_dir($root))throw new RuntimeException('cache_directory');
            $previous=fga_file($root.'/state.json')??fga_empty();$now=new DateTimeImmutable('now',new DateTimeZone('UTC'));
            try{
                $kinds="'".implode("','",FGI_KINDS)."'";$from=fgi_stamp($now->modify('-'.FGA_RULE['lookback_hours'].' hours'));
                $where="device=? AND vd=? AND BINARY device=BINARY ? AND BINARY vd=BINARY ? AND action<>'baseline' AND object_kind IN ($kinds) AND observed_at>=? AND observed_at<=?";
                $args=[$device['serial'],$device['vdom'],$device['serial'],$device['vdom'],$from,fgi_stamp($now)];
                $count=(int)query("SELECT COUNT(*) n FROM fg_config_changes WHERE $where",$args)[0]['n'];
                $changes=query("SELECT id,object_kind,object_name,policyid,poluuid,action,last_confirmed_at,observed_at FROM fg_config_changes WHERE $where ORDER BY observed_at DESC,id DESC LIMIT 1000",$args);
                $budget=min(40,max(0,65-(microtime(true)-$started)));
                $state=fga_generate($previous,$changes,function($change){$_GET=['impact_change'=>(string)$change['id'],'impact_minutes'=>(string)FGA_RULE['window_minutes'],'impact_direction'=>'increase'];return configuration_impact(FGA_RULE);},$now,10,$budget,$count>1000);
                $observations=query('SELECT component,MAX(observed_at) last_success_at,MAX(CASE WHEN error_code IS NOT NULL THEN attempted_at END) last_failure_at FROM fg_config_observations WHERE device=? AND vd=? AND BINARY device=BINARY ? AND BINARY vd=BINARY ? GROUP BY component',[$device['serial'],$device['vdom'],$device['serial'],$device['vdom']]);
                $state['configuration_source']=fga_source_health($observations,new DateTimeImmutable('now',new DateTimeZone('UTC')));if($state['configuration_source']['stale_components'])$state['status']='partial';
            }catch(Throwable $exception){$state=fga_failure($previous,$now);fwrite(STDERR,"FLS device change alert evaluation unavailable\n");}
            fga_atomic($root.'/state.json',$state,0600);fga_atomic($root.'/alerts.json',fga_publish($state,$now),0640);
            return ['device_id'=>(int)$device['id'],'status'=>$state['status'],'processed'=>$state['processed']??0];
        });
        $results[]=$result;fga_atomic($cursorPath,['last_id'=>(int)$device['id']],0600);
    }
    echo json_encode(['devices'=>$results],JSON_THROW_ON_ERROR)."\n";
}catch(Throwable $exception){fwrite(STDERR,"FLS managed change alert worker unavailable\n");exit(1);}
