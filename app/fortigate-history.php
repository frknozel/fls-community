<?php
declare(strict_types=1);
require_once __DIR__.'/fortigate.php';
const FGH_COMPONENTS=['policies','profile_groups','profiles_virus','profiles_webfilter','profiles_app-ctrl','profiles_dns','profiles_ips','profiles_ssl','url_filters'];
const FGH_KINDS=['policy','policy_order','profile_group','virus','webfilter','app-ctrl','dns','ips','ssl','url_filter'];

function fgh_mapping(array $items): ?array {
    if(!$items)return null;
    foreach(['id','label','match'] as $field){
        $map=[];$valid=true;foreach($items as $item){$value=is_object($item)?($item->$field??null):null;if($value===null||!is_scalar($value)||isset($map[(string)$value])){$valid=false;break;}$map[(string)$value]=$item;}
        if($valid)return [$field,$map];
    }
    return null;
}
function fgh_diff(mixed $before,mixed $after,array $path=[],bool $beforeExists=true,bool $afterExists=true): array {
    if($beforeExists&&$afterExists&&json_encode($before,JSON_PRESERVE_ZERO_FRACTION)===json_encode($after,JSON_PRESERVE_ZERO_FRACTION))return [];
    if((is_object($before)||!$beforeExists)&&(is_object($after)||!$afterExists)){
        $a=$beforeExists?get_object_vars($before):[];$b=$afterExists?get_object_vars($after):[];$keys=array_unique(array_merge(array_keys($a),array_keys($b)));sort($keys,SORT_STRING);$out=[];
        foreach($keys as $key)$out=array_merge($out,fgh_diff($a[$key]??null,$b[$key]??null,[...$path,(string)$key],array_key_exists($key,$a),array_key_exists($key,$b)));
        return $out;
    }
    if((is_array($before)||!$beforeExists)&&(is_array($after)||!$afterExists)){
        $a=$beforeExists?fgh_mapping($before):null;$b=$afterExists?fgh_mapping($after):null;
        if(!$beforeExists&&$b){[$field,$items]=$b;$out=[];foreach($items as $key=>$item)$out=array_merge($out,fgh_diff(null,$item,[...$path,$field.'='.$key],false,true));return $out;}
        if(!$afterExists&&$a){[$field,$items]=$a;$out=[];foreach($items as $key=>$item)$out=array_merge($out,fgh_diff($item,null,[...$path,$field.'='.$key],true,false));return $out;}
        if($a&&$b&&$a[0]===$b[0]){
            [$field,$a]=$a;[,$b]=$b;$out=[];
            if(in_array(end($path),['rules','entries','filters'],true)&&array_keys($a)!==array_keys($b))$out=fgh_diff(array_map('strval',array_keys($a)),array_map('strval',array_keys($b)),[...$path,'_order']);
            $keys=array_unique(array_merge(array_keys($a),array_keys($b)));sort($keys,SORT_STRING);
            foreach($keys as $key)$out=array_merge($out,fgh_diff($a[$key]??null,$b[$key]??null,[...$path,$field.'='.$key],array_key_exists($key,$a),array_key_exists($key,$b)));
            return $out;
        }
    }
    return [['path'=>$path,'before_exists'=>$beforeExists,'after_exists'=>$afterExists,'before'=>$beforeExists?$before:null,'after'=>$afterExists?$after:null]];
}
function fgh_status(): array {
    $queue=json_decode(@file_get_contents(FG_CACHE_ROOT.'/history-status.json')?:'{}',true);
    $stats=query('SELECT MIN(observed_at) first_observed,MAX(observed_at) last_observed,COUNT(*) observations,SUM(error_code IS NOT NULL) failed_observations FROM fg_config_observations WHERE device=? AND vd=?',[fg_serial(),fg_vdom()])[0];
    $latest=query('SELECT o.component,o.attempted_at,o.observed_at,o.error_code FROM fg_config_observations o JOIN (SELECT component,MAX(id) id FROM fg_config_observations WHERE device=? AND vd=? GROUP BY component) newest ON newest.id=o.id',[fg_serial(),fg_vdom()]);
    $unhealthy=[];foreach($latest as $row)if($row['error_code']!==null||!$row['observed_at']||time()-strtotime($row['observed_at'].' UTC')>660)$unhealthy[]=$row['component'];
    return ['first_observed'=>$stats['first_observed'],'last_observed'=>$stats['last_observed'],'observations'=>(int)$stats['observations'],
            'failed_observations'=>(int)$stats['failed_observations'],'unhealthy_components'=>$unhealthy,'pending'=>(int)($queue['pending']??0),'writer_error'=>$queue['error']??null,'writer_checked_at'=>$queue['checked_at']??null,'poll_seconds'=>300];
}
function fgh_feed(): array {
    [$from,$to]=scope();$where=['device=?','vd=?','observed_at>=?','observed_at<?'];$args=[fg_serial(),fg_vdom(),$from,$to];
    $kind=$_GET['history_kind']??'';$key=$_GET['history_object']??'';$search=$_GET['history_q']??'';
    if(!is_string($kind)||!in_array($kind,['',...FGH_KINDS],true))throw new InvalidArgumentException('Geçmiş nesne türü geçersiz.');
    if(!is_string($key)||($key!==''&&!preg_match('/^[a-f0-9]{64}$/D',$key)))throw new InvalidArgumentException('Geçmiş nesne anahtarı geçersiz.');
    if(!is_string($search)||!mb_check_encoding($search,'UTF-8')||mb_strlen($search)>160)throw new InvalidArgumentException('Geçmiş araması geçersiz.');
    if($kind!==''){$where[]='object_kind=?';$args[]=$kind;}
    if($key!==''){$where[]='object_key=UNHEX(?)';$args[]=$key;}
    if($search!==''){$where[]="(object_name LIKE ? ESCAPE '!' OR CAST(policyid AS CHAR)=?)";$args[]='%'.str_replace(['!','%','_'],['!!','!%','!_'],$search).'%';$args[]=$search;}
    $clause=implode(' AND ',$where);
    $totals=query("SELECT COUNT(*) records,SUM(action='baseline') baselines,SUM(action='modified') modified,SUM(action='added') added,SUM(action='removed') removed FROM fg_config_changes WHERE $clause",$args)[0];
    if(($_GET['history_baseline']??'0')!=='1')$clause.=" AND action<>'baseline'";
    $total=(int)query("SELECT COUNT(*) n FROM fg_config_changes WHERE $clause",$args)[0]['n'];$page=max(1,min(100000,(int)($_GET['history_page']??1)));$offset=($page-1)*50;
    $rows=query("SELECT id,observation_id,component,HEX(object_key) object_key,object_kind,object_name,policyid,poluuid,action,last_confirmed_at,observed_at,JSON_LENGTH(diff_json) field_count FROM fg_config_changes WHERE $clause ORDER BY observed_at DESC,id DESC LIMIT 50 OFFSET $offset",$args);
    foreach($rows as &$row)$row['object_key']=strtolower($row['object_key']);unset($row);
    return ['scope'=>['from_utc'=>$from,'to_utc'=>$to],'status'=>fgh_status(),'totals'=>$totals,'rows'=>$rows,'total'=>$total,'page'=>$page,'page_size'=>50,
            'note'=>'Zamanlar API gözlem zamanlarıdır. Değişiklik önceki sorgu ile yeni gözlem arasında yapılmış olabilir. İzlenen API alanları saklanır; iki sorgu arasında yapılıp geri alınan değişiklikler görünmeyebilir.'];
}
function fgh_change(int $id,int $page): ?array {
    $row=query('SELECT c.*,o.attempted_at FROM fg_config_changes c JOIN fg_config_observations o ON o.id=c.observation_id WHERE c.id=? AND c.device=? AND c.vd=?',[$id,fg_serial(),fg_vdom()])[0]??null;if(!$row)return null;
    $fields=json_decode($row['diff_json'],true,512,JSON_THROW_ON_ERROR);$count=count($fields);$page=max(1,min(100000,$page));
    $gap=(int)query('SELECT COUNT(*) n FROM fg_config_observations WHERE device=? AND vd=? AND component=? AND error_code IS NOT NULL AND attempted_at>=? AND attempted_at<=?',[fg_serial(),fg_vdom(),$row['component'],$row['last_confirmed_at']??$row['attempted_at'],$row['observed_at']])[0]['n'];
    return ['mode'=>'change','id'=>(int)$row['id'],'object_key'=>bin2hex($row['object_key']),'object_kind'=>$row['object_kind'],'object_name'=>$row['object_name'],
            'policyid'=>$row['policyid'],'poluuid'=>$row['poluuid'],'action'=>$row['action'],'last_confirmed_at'=>$row['last_confirmed_at'],'attempted_at'=>$row['attempted_at'],'observed_at'=>$row['observed_at'],
            'failed_attempts'=>$gap,'page'=>$page,'page_size'=>100,'total_fields'=>$count,'fields'=>array_slice($fields,($page-1)*100,100)];
}
function fgh_find_object(string $json,string $key): ?array {
    $values=json_decode($json,false,512,JSON_THROW_ON_ERROR);if(!is_array($values))return null;
    foreach($values as $obj)if(($obj->key??'')===$key){
        return ['key'=>$obj->key,'kind'=>$obj->kind,'name'=>$obj->name,'policyid'=>$obj->policyid,'uuid'=>$obj->uuid,
                'document'=>$obj->document,'display'=>json_decode(json_encode($obj->display,JSON_THROW_ON_ERROR),true,512,JSON_THROW_ON_ERROR)];
    }
    return null;
}
function fgh_point(string $component,string $at,bool $after,string $key): ?array {
    if(!in_array($component,FGH_COMPONENTS,true))return null;
    $op=$after?'>':'<=';$order=$after?'ASC':'DESC';
    $row=query("SELECT o.id,o.attempted_at,o.observed_at,o.version_id,v.content_json FROM fg_config_observations o JOIN fg_config_versions v ON v.id=o.version_id WHERE o.device=? AND o.vd=? AND o.component=? AND o.observed_at $op ? ORDER BY o.observed_at $order,o.id $order LIMIT 1",[fg_serial(),fg_vdom(),$component,$at])[0]??null;
    if(!$row)return null;$row['object']=fgh_find_object($row['content_json'],$key);unset($row['content_json']);return $row;
}
function fgh_public_point(?array $point): ?array {
    if(!$point)return null;$o=$point['object'];return ['id'=>(int)$point['id'],'version_id'=>(int)$point['version_id'],'attempted_at'=>$point['attempted_at'],'observed_at'=>$point['observed_at'],
        'object'=>$o?['key'=>$o['key'],'kind'=>$o['kind'],'name'=>$o['name'],'policyid'=>$o['policyid'],'uuid'=>$o['uuid']]:null];
}
function fgh_assess(?array $before,?array $after,string $at,int $failures): array {
    if(!$before)return ['status'=>'no_prior_snapshot','gap'=>false];
    $distance=(strtotime(($after['observed_at']??$at).' UTC')-strtotime($before['observed_at'].' UTC'));
    $gap=$failures>0||$distance>660;
    if($after){
        $a=$before['object']['document']??null;$b=$after['object']['document']??null;
        if(json_encode($a,JSON_PRESERVE_ZERO_FRACTION)!==json_encode($b,JSON_PRESERVE_ZERO_FRACTION))return ['status'=>'transition_window','gap'=>$gap];
        if(strtotime($after['attempted_at'].' UTC')<=strtotime($at.' UTC'))return ['status'=>'sample_window','gap'=>$gap];
        if($gap)return ['status'=>'observation_gap','gap'=>true];
        return ['status'=>$before['object']?'bracket_same':'object_absent','gap'=>false];
    }
    return ['status'=>$gap?'observation_gap':($before['object']?'awaiting_confirmation':'object_absent'),'gap'=>$gap];
}
function fgh_span(string $component,string $key,string $at): array {
    $before=fgh_point($component,$at,false,$key);$after=fgh_point($component,$at,true,$key);$latest=fgh_point($component,gmdate('Y-m-d H:i:s').'.999999',false,$key);
    $start=$before['attempted_at']??$at;$end=$after['observed_at']??$at;
    $failures=(int)query('SELECT COUNT(*) n FROM fg_config_observations WHERE device=? AND vd=? AND component=? AND error_code IS NOT NULL AND attempted_at>=? AND attempted_at<=?',[fg_serial(),fg_vdom(),$component,$start,$end])[0]['n'];
    $assessment=fgh_assess($before,$after,$at,$failures);$fields=[];$window=[];
    if($before&&$before['object']&&$latest){$fields=fgh_diff($before['object']['document'],$latest['object']['document']??null,[],true,$latest['object']!==null);}
    if($before&&$after)$window=fgh_diff($before['object']['document']??null,$after['object']['document']??null,[],$before['object']!==null,$after['object']!==null);
    return $assessment+['component'=>$component,'object_key'=>$key,'before'=>fgh_public_point($before),'after'=>fgh_public_point($after),'latest'=>fgh_public_point($latest),
            'failed_attempts'=>$failures,'window_changes'=>['total_fields'=>count($window),'fields'=>array_slice($window,0,100),'truncated'=>count($window)>100],
            'comparison'=>['total_fields'=>count($fields),'fields'=>array_slice($fields,0,100),'truncated'=>count($fields)>100]];
}
function fgh_event(array $event,array $fields): array {
    $result=['event_at'=>$event['event_at'],'policy'=>null,'profile'=>null,'profile_group'=>null,'url_filter'=>null,
             'note'=>'Gösterilenler olay zamanını çevreleyen API gözlemleridir; kesin değişiklik anını veya arada yapılıp geri alınan ayarları kanıtlamaz. Olayın özgün eylemi ve gerekçesi logdan alınır.'];
    if(($event['devid']??'')!==fg_serial()||($event['vd']??'')!==fg_vdom())return $result+['status'=>'device_scope'];
    if(($event['subtype']??'')==='local'||!in_array((string)($fields['policytype']??'policy'),['','policy'],true))return $result+['status'=>'policy_scope'];
    if(isset($event['received_at'])&&strtotime($event['event_at'].' UTC')>strtotime($event['received_at'].' UTC')+120)return $result+['status'=>'clock_scope'];
    $uuid=strtolower((string)($event['poluuid']??''));$id=(int)($event['policyid']??-1);$at=$event['event_at'];
    if($id>0&&preg_match('/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/D',$uuid)){
        $key=hash('sha256','policy:'.$id.':'.$uuid);$result['policy']=fgh_span('policies',$key,$at);
        $point=fgh_point('policies',$at,false,$key);$display=$point['object']['display']??null;
        if(($display['profile-type']??'')==='group'&&($name=$display['profile-group']??''))$result['profile_group']=fgh_span('profile_groups',hash('sha256','profile_groups:'.$name),$at);
    }
    $kind=$event['subtype'];$name=$event['profile'];
    if(in_array($kind,FG_PROFILE_KINDS,true)&&$name!==''){
        $key=hash('sha256','profiles_'.$kind.':'.$name);$result['profile']=fgh_span('profiles_'.$kind,$key,$at);
        if($kind==='webfilter'){$point=fgh_point('profiles_webfilter',$at,false,$key);$table=$point['object']['display']['url_filter_table']??0;if($table)$result['url_filter']=fgh_span('url_filters',hash('sha256','url_filters:'.$table),$at);}
    }
    return $result+['status'=>'observed'];
}
function fgh_event_safe(array $event,array $fields): array {
    try{return fgh_event($event,$fields);}catch(Throwable $exception){error_log('FLS configuration history lookup failed');return ['status'=>'unavailable','note'=>'Yapılandırma geçmişi şu anda okunamadı; özgün log ve güncel kopya ayrı gösteriliyor.'];}
}
function fgh_observation_object(int $id,string $key,int $page): ?array {
    $row=query('SELECT o.id,o.component,o.attempted_at,o.observed_at,v.content_json FROM fg_config_observations o JOIN fg_config_versions v ON v.id=o.version_id WHERE o.id=? AND o.device=? AND o.vd=?',[$id,fg_serial(),fg_vdom()])[0]??null;
    if(!$row)return null;$obj=fgh_find_object($row['content_json'],$key);if(!$obj)return null;
    $fields=fgh_diff(null,$obj['document'],[],false,true);$page=max(1,min(100000,$page));
    return ['mode'=>'snapshot','id'=>(int)$row['id'],'object_key'=>$key,'object_kind'=>$obj['kind'],'object_name'=>$obj['name'],'policyid'=>$obj['policyid'],'poluuid'=>$obj['uuid'],
            'attempted_at'=>$row['attempted_at'],'observed_at'=>$row['observed_at'],'page'=>$page,'page_size'=>100,'total_fields'=>count($fields),'fields'=>array_slice($fields,($page-1)*100,100)];
}
