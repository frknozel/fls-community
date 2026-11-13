<?php
declare(strict_types=1);
require_once __DIR__.'/config-impact.php';
const FGA_ROOT='/srv/fortigate/metrics/change-alerts';
const FGA_RULE=['minimum_delta'=>20,'minimum_percent'=>50,'minimum_seconds'=>900,'window_minutes'=>1440,'lookback_hours'=>48,'refresh_seconds'=>300];

function fga_empty(): array {return ['schema'=>1,'device'=>['serial'=>fg_serial(),'vdom'=>fg_vdom()],'checked_at'=>null,'last_success_at'=>null,'status'=>'missing','jobs'=>[],'limited'=>false];}
function fga_source_health(array $observations,DateTimeImmutable $now): array {
    $components=['policies',...array_map(fn($kind)=>'profiles_'.$kind,array_slice(FGI_KINDS,1))];$by=[];$stale=[];
    foreach($observations as $row)$by[$row['component']]=$row;
    foreach($components as $component){
        $row=$by[$component]??[];$success=isset($row['last_success_at'])?fgi_time($row['last_success_at']):null;
        $age=$success?$now->getTimestamp()-$success->getTimestamp():PHP_INT_MAX;
        if($age<0||$age>660||isset($row['last_failure_at'])&&(!$success||fgi_time($row['last_failure_at'])>$success))$stale[]=$component;
    }
    return ['stale_components'=>$stale];
}
function fga_file(string $path): ?array {
    if(!is_file($path)||filesize($path)>16*1024*1024)return null;
    try{$value=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR);}catch(Throwable $e){return null;}
    if(!is_array($value)||($value['schema']??null)!==1||($value['device']??null)!==['serial'=>fg_serial(),'vdom'=>fg_vdom()]||isset($value['jobs'])&&!is_array($value['jobs']))return null;
    try{foreach(['checked_at','last_success_at'] as $field)if(isset($value[$field])&&(!is_string($value[$field])||fgi_iso(fgi_time($value[$field]))!==$value[$field]))return null;}catch(Throwable $e){return null;}
    return $value;
}
function fga_assess(array $report,array $rule=FGA_RULE): array {
    if(($report['change']['action']??'baseline')==='baseline'||!in_array($report['change']['object_kind']??'',FGI_KINDS,true))return ['state'=>'ignored'];
    if(($report['status']??'')!=='ready')return ['state'=>in_array($report['status']??'',['collecting','no_before_logs','no_log_coverage'],true)?'waiting':'unavailable'];
    if(($report['actual_seconds']??0)<$rule['minimum_seconds'])return ['state'=>'waiting'];
    if(($report['data']['index_pending_bytes']??0)>0)return ['state'=>'unavailable','reason'=>'index_pending'];
    $total=fgi_surge($report['totals']['before'],$report['totals']['after'],$rule);$dimensions=[];$top=[];$score=max(0,$report['totals']['delta']);
    foreach(['sources','targets','reasons'] as $dimension){
        $ranking=$report['rankings'][$dimension];$surges=$ranking['surges']??['total'=>0,'rows'=>[]];
        if($surges['total']>0)$dimensions[]=$dimension;
        $top[$dimension]=array_map(function($row)use(&$score){
            $score=max($score,$row['delta']);$row=array_intersect_key($row,array_flip(['key','label','module','target_kind','before','after','delta','percent','new_in_window']));
            $row['label']=mb_strimwidth($row['label'],0,320,'…','UTF-8');return $row;
        },array_slice($surges['rows']?:$ranking['rows'],0,3));
    }
    if(!$total&&!$dimensions)return ['state'=>'clear'];
    return ['state'=>'alert','alert'=>['change'=>$report['change'],'as_of_utc'=>$report['as_of_utc'],'snapshot_max_id'=>$report['snapshot_max_id'],
        'actual_seconds'=>$report['actual_seconds'],'windows'=>$report['windows'],'excluded'=>$report['excluded'],'totals'=>$report['totals'],
        'total_trigger'=>$total,'trigger_dimensions'=>$dimensions,'top'=>$top,'score'=>$score,
        'other_changes'=>(int)($report['other_changes']['total']??0),'observation_gaps'=>(int)($report['observation_gaps']??0),
        'failed_observations'=>(int)($report['failed_observations']??0),'invalid_rows'=>(int)($report['data']['invalid_rows']??0),
        'before_config_history'=>(bool)($report['before_config_history']??false)]];
}
/** One job per real change; bounded round-robin work prevents bursts from starving earlier changes. */
function fga_generate(array $previous,array $changes,callable $evaluate,DateTimeImmutable $now,int $maximum=10,float $budget=40,bool $limited=false): array {
    $stamp=fgi_iso($now);$state=fga_empty();$state['checked_at']=$stamp;$state['last_success_at']=$stamp;$state['status']='ok';$state['limited']=$limited;
    $cutoff=fgi_stamp($now->modify('-'.FGA_RULE['lookback_hours'].' hours'));$jobs=[];
    foreach($changes as $change){
        if($change['action']==='baseline'||!in_array($change['object_kind'],FGI_KINDS,true)||$change['observed_at']<$cutoff||fgi_time($change['observed_at'])>$now)continue;
        $id=(string)$change['id'];$job=$previous['jobs'][$id]??['checked_at'=>null,'first_detected_at'=>null,'alert'=>null,'state'=>'pending'];$job['change']=$change;
        if((float)$now->format('U.u')-(float)fgi_time($change['observed_at'])->format('U.u')<FGA_RULE['minimum_seconds']){$job['state']='waiting';$job['checked_at']=$stamp;}
        $jobs[$id]=$job;
    }
    $ordered=array_keys($jobs);usort($ordered,fn($a,$b)=>strcmp($jobs[$a]['checked_at']??'',$jobs[$b]['checked_at']??'')?:strcmp($jobs[$b]['change']['observed_at'],$jobs[$a]['change']['observed_at'])?:((int)$a<=>(int)$b));
    $started=microtime(true);$processed=0;
    foreach($ordered as $id){
        $job=&$jobs[$id];$age=$job['checked_at']?$now->getTimestamp()-fgi_time($job['checked_at'])->getTimestamp():PHP_INT_MAX;
        if($age<FGA_RULE['refresh_seconds']){unset($job);continue;}
        if($processed>=$maximum||microtime(true)-$started>$budget){unset($job);break;}
        try{
            $assessment=fga_assess($evaluate($job['change']));$job['state']=$assessment['state'];$job['reason']=$assessment['reason']??null;
            if($job['state']==='alert'){
                $job['first_detected_at']??=$stamp;$job['alert']=$assessment['alert']+['first_detected_at'=>$job['first_detected_at'],'last_confirmed_at'=>$stamp];
            }elseif(in_array($job['state'],['clear','ignored'],true))$job['alert']=null;
        }catch(Throwable $exception){$job['state']='unavailable';$job['reason']='evaluation_failed';}
        $job['checked_at']=$stamp;$processed++;unset($job);
    }
    $state['jobs']=$jobs;$state['processed']=$processed;
    foreach($jobs as $job)if($job['state']==='unavailable'||!$job['checked_at']||$now->getTimestamp()-fgi_time($job['checked_at'])->getTimestamp()>=FGA_RULE['refresh_seconds']){$state['status']='partial';break;}
    if($limited)$state['status']='partial';return $state;
}
function fga_failure(array $previous,DateTimeImmutable $now): array {
    $previous['checked_at']=fgi_iso($now);$previous['status']='error';return $previous;
}
function fga_publish(array $state,DateTimeImmutable $now): array {
    $alerts=[];$counts=['monitored'=>0,'waiting'=>0,'pending'=>0,'failed'=>0];$cutoff=fgi_stamp($now->modify('-'.FGA_RULE['lookback_hours'].' hours'));
    foreach($state['jobs']??[] as $job){
        if(($job['change']['observed_at']??'')<$cutoff)continue;$counts['monitored']++;
        $age=$job['checked_at']?$now->getTimestamp()-fgi_time($job['checked_at'])->getTimestamp():PHP_INT_MAX;
        if($job['state']==='waiting')$counts['waiting']++;if($age>=FGA_RULE['refresh_seconds'])$counts['pending']++;if($job['state']==='unavailable')$counts['failed']++;
        if($job['alert'])$alerts[]=$job['alert']+['confirmed'=>$job['state']==='alert'&&$age<=660&&$state['status']!=='error'];
    }
    usort($alerts,fn($a,$b)=>($b['score']<=>$a['score'])?:strcmp($b['change']['observed_at'],$a['change']['observed_at'])?:((int)$b['change']['id']<=>(int)$a['change']['id']));
    return array_intersect_key($state,array_flip(['schema','device','checked_at','last_success_at','status','limited','configuration_source']))+['rules'=>FGA_RULE,'counts'=>$counts,'alerts'=>$alerts];
}
function fga_atomic(string $path,array $data,int $mode): void {
    $temporary=tempnam(dirname($path),'.alert-');if($temporary===false)throw new RuntimeException('cache_write');
    try{
        $stream=fopen($temporary,'wb');if(!$stream)throw new RuntimeException('cache_write');
        try{chmod($temporary,$mode);$bytes=json_encode($data,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)."\n";if(fwrite($stream,$bytes)!==strlen($bytes)||!fflush($stream)||!fsync($stream))throw new RuntimeException('cache_write');}finally{fclose($stream);}
        if(!rename($temporary,$path))throw new RuntimeException('cache_write');
        $directory=fopen(dirname($path),'r');if($directory){fsync($directory);fclose($directory);}
    }finally{if(is_file($temporary))unlink($temporary);}
}
function configuration_alerts(string $path=FGA_ROOT.'/alerts.json',?DateTimeImmutable $now=null): array {
    $page=fgi_integer('alert_page',1,1,200);$now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));$selected=fg_selected_device();if($path===FGA_ROOT.'/alerts.json'&&empty($selected['legacy_cache']))$path=FGA_ROOT.'/devices/'.(int)$selected['id'].'/alerts.json';$cache=fga_file($path);
    $unavailable=['status'=>'unavailable','fresh'=>false,'checked_at'=>null,'rules'=>FGA_RULE,'counts'=>[],'alerts'=>[],'total'=>0,'page'=>$page,'page_size'=>5];
    if(!$cache||!is_array($cache['counts']??null)||!is_array($cache['alerts']??null)||!in_array($cache['status']??null,['ok','partial','error'],true))return $unavailable;
    try{foreach($cache['alerts'] as $alert){
        if(!is_array($alert)||!is_array($alert['change']??null)||!is_array($alert['top']??null)||!is_array($alert['totals']??null)||!isset($alert['as_of_utc'],$alert['snapshot_max_id'],$alert['change']['id'],$alert['change']['observed_at'])||!is_array($alert['trigger_dimensions']??null)||!is_bool($alert['confirmed']??null))return $unavailable;
        foreach(['as_of_utc','first_detected_at','last_confirmed_at'] as $field)if(!is_string($alert[$field]??null)||fgi_iso(fgi_time($alert[$field]))!==$alert[$field])return $unavailable;
        if(!is_string($alert['change']['observed_at'])||fgi_stamp(fgi_time($alert['change']['observed_at']))!==$alert['change']['observed_at'])return $unavailable;
        foreach(['sources','targets','reasons'] as $dimension){if(!is_array($alert['top'][$dimension]??null))return $unavailable;foreach($alert['top'][$dimension] as $row)if(!is_array($row)||!is_string($row['label']??null)||!is_string($row['key']??null)||!preg_match('/^[a-f0-9]{64}$/D',$row['key']))return $unavailable;}
    }}catch(Throwable $exception){return $unavailable;}
    $age=$cache['checked_at']?$now->getTimestamp()-fgi_time($cache['checked_at'])->getTimestamp():PHP_INT_MAX;
    $fresh=$age>=0&&$age<=660&&$cache['status']!=='error';$cutoff=fgi_stamp($now->modify('-'.FGA_RULE['lookback_hours'].' hours'));
    $alerts=array_values(array_filter($cache['alerts'],fn($a)=>($a['change']['observed_at']??'')>=$cutoff));
    foreach($alerts as &$alert)if(!$fresh)$alert['confirmed']=false;unset($alert);
    $page=min($page,max(1,(int)ceil(count($alerts)/5)));
    return array_intersect_key($cache,array_flip(['status','checked_at','last_success_at','counts','limited','configuration_source']))+['fresh'=>$fresh,'rules'=>FGA_RULE,'alerts'=>array_slice($alerts,($page-1)*5,5),'total'=>count($alerts),'page'=>$page,'page_size'=>5];
}
