<?php
declare(strict_types=1);
const TELEMETRY_ROOT='/srv/fls-server/metrics/telemetry';

function telemetry_latest(): ?array {
    $value=json_decode(@file_get_contents(TELEMETRY_ROOT.'/latest.json')?:'null',true);
    return is_array($value)?$value:null;
}
function telemetry_history(): array {
    [$from,$to]=scope();$start=strtotime($from.' UTC');$end=strtotime($to.' UTC');$paths=glob(TELEMETRY_ROOT.'/????-??-??.jsonl')?:[];$oldest=null;
    if($paths && ($f=fopen($paths[0],'rb'))){$firstRow=json_decode(fgets($f,32769)?:'null',true);fclose($f);$oldest=isset($firstRow['at'])?strtotime($firstRow['at']):null;}
    $width=max(30,(int)ceil((min($end,time())-max($start,$oldest?:time()-91*86400))/360));
    $buckets=[];$count=0;$first=null;$last=null;$previous=null;$episodes=[];$episode=null;$gaps=0;$peak=null;$lastEmpty=null;
    $summary=['samples'=>0,'unknown_samples'=>0,'stale_samples'=>0,'first_sample'=>null,'last_sample'=>null,'last_pending'=>null,'peak_pending'=>null,'last_empty_at'=>null,'gaps'=>0];
    $searchHistory=index_history_empty();
    $summaryBuckets=[];$summaryEpisodes=[];$summaryEpisode=null;$summaryEmpty=false;
    foreach($paths as $path){
        $day=basename($path,'.jsonl');if($day<substr($from,0,10)||$day>substr($to,0,10))continue;
        $stream=fopen($path,'rb');if(!$stream)continue;
        try{
            while(($line=fgets($stream,32769))!==false){
                if(!str_ends_with($line,"\n"))continue;
                $r=json_decode($line,true);if(!is_array($r)||!isset($r['at']))continue;
                $t=strtotime($r['at']);if($t===false||$t<$start||$t>=$end)continue;
                $count++;$first??=$r['at'];$last=$r['at'];$gap=$previous!==null&&$t-$previous>95;
                if($gap){$gaps++;if($episode){$episode['status']='gap';$episodes[]=$episode;$episode=null;}}
                index_history_sample($searchHistory,$r['mail_search_index']??null,$r['at'],$t,$width,$gap);
                $previous=$t;$q=$r['queue']['depth']??null;
                $s=$r['archive_index']??[];$pending=$s['pending_records']??null;
                $known=is_int($pending)&&$pending>=0&&in_array($s['status']??null,['caught_up','processing','backfilling','stale'],true);
                if($gap||!$known){
                    if($gap)$summary['gaps']++;
                    if($summaryEpisode){$summaryEpisode['status']='gap';$summaryEpisodes[]=$summaryEpisode;$summaryEpisode=null;}
                    $summaryEmpty=false;
                }
                if($known){
                    $summary['samples']++;$summary['first_sample']??=$r['at'];$summary['last_sample']=$r['at'];$summary['last_pending']=$pending;
                    if($s['status']==='stale')$summary['stale_samples']++;
                    $summary['peak_pending']=max($summary['peak_pending']??0,$pending);
                    if($pending===0){
                        $summary['last_empty_at']=$r['at'];$summaryEmpty=true;
                        if($summaryEpisode){$summaryEpisode['end']=$r['at'];$summaryEpisode['status']='drained';$summaryEpisodes[]=$summaryEpisode;$summaryEpisode=null;}
                    }elseif(!$summaryEpisode){
                        $summaryEpisode=['start'=>$r['at'],'end'=>null,'peak'=>$pending,'status'=>'pending','start_bounded'=>$summaryEmpty];$summaryEmpty=false;
                    }else $summaryEpisode['peak']=max($summaryEpisode['peak'],$pending);
                }else $summary['unknown_samples']++;
                if(count($summaryEpisodes)>15)array_shift($summaryEpisodes);
                $summaryKey=(int)floor($t/$width);
                if(!isset($summaryBuckets[$summaryKey]))$summaryBuckets[$summaryKey]=['first'=>null,'peak'=>null,'last'=>null,'gap'=>false,'at'=>$r['at']];
                $sb=&$summaryBuckets[$summaryKey];$sb['gap']=$sb['gap']||$gap||!$known;
                if($known){
                    $point=['at'=>$r['at'],'pending_records'=>$pending];$sb['first']??=$point;$sb['last']=$point;
                    if(!$sb['peak']||$pending>$sb['peak']['pending_records'])$sb['peak']=$point;
                }unset($sb);
                if($q!==null){$peak=max($peak??0,$q);if($q===0){$lastEmpty=$r['at'];if($episode){$episode['end']=$r['at'];$episode['status']='drained';$episodes[]=$episode;$episode=null;}}elseif(!$episode){$episode=['start'=>$r['at'],'end'=>null,'peak'=>$q,'status'=>'pending'];}else $episode['peak']=max($episode['peak'],$q);}
                $disk=array_values(array_filter(array_column($r['disks']??[],'write_await_ms'),fn($v)=>$v!==null));
                $values=['ram_percent'=>$r['memory']['used_percent']??null,'disk_write_ms'=>$disk?max($disk):null,'queue_depth'=>$q,'archive_write_seconds'=>$r['archive']['write_lag_seconds']??null];
                $key=(int)floor($t/$width);if(!isset($buckets[$key]))$buckets[$key]=['at'=>gmdate('c',$key*$width),'samples'=>0,'gap'=>$gap]+array_fill_keys(array_keys($values),null);
                $b=&$buckets[$key];$b['samples']++;$b['gap']=$b['gap']||$gap;
                foreach($values as $k=>$v)if($v!==null)$b[$k]=max($b[$k]??$v,$v);unset($b);
            }
        }finally{fclose($stream);}
    }
    if($episode)$episodes[]=$episode;ksort($buckets);
    if($summaryEpisode)$summaryEpisodes[]=$summaryEpisode;ksort($summaryBuckets);$summaryPoints=[];
    foreach($summaryBuckets as $sb){
        if(!$sb['first']){$summaryPoints[]=['at'=>$sb['at'],'pending_records'=>null];continue;}
        // Keep first, peak and last at their actual sample times: a peak and a
        // drain in one bucket remain visible. An uncertain bucket is isolated,
        // so downsampling cannot draw a line across missing measurements.
        $points=[];foreach(['first','peak','last'] as $key)$points[$sb[$key]['at']]=$sb[$key];ksort($points);
        foreach($points as $point)$summaryPoints[]=$point+['gap'=>$sb['gap'],'gap_after'=>$sb['gap']];
    }
    $summary['points']=$summaryPoints;$summary['episodes']=array_slice(array_reverse($summaryEpisodes),0,15);
    return ['scope'=>['from_utc'=>$from,'to_utc'=>$to],'points'=>array_values($buckets),'samples'=>$count,'first_sample'=>$first,'last_sample'=>$last,'bucket_seconds'=>$width,'peak_queue'=>$peak,'last_empty_at'=>$lastEmpty,'gaps'=>$gaps,'episodes'=>array_slice(array_reverse($episodes),0,15),'archive_index'=>$summary,'mail_search_index'=>index_history_finish($searchHistory),'latest'=>telemetry_latest(),'retention_days'=>90,'sample_seconds'=>30];
}

/** Bounded accumulation for the mail-search queue, using actual sample times. */
function index_history_empty(): array {
    return ['samples'=>0,'unknown_samples'=>0,'stale_samples'=>0,'first_sample'=>null,'last_sample'=>null,
        'last_pending'=>null,'peak_pending'=>null,'last_empty_at'=>null,'gaps'=>0,
        '_buckets'=>[],'_episodes'=>[],'_episode'=>null,'_empty'=>false,'_previous'=>null];
}
function index_history_sample(array &$h,mixed $snapshot,string $at,int $time,int $width,bool $gap): void {
    $snapshot=is_array($snapshot)?$snapshot:[];$pending=$snapshot['pending_records']??null;
    $checked=isset($snapshot['checked_at'])&&is_string($snapshot['checked_at'])?strtotime($snapshot['checked_at']):false;
    $known=is_int($pending)&&$pending>=0&&in_array($snapshot['status']??null,['caught_up','processing','backfilling','stale'],true)&&$checked!==false&&abs($time-$checked)<=10;
    $gap=$gap||($h['_previous']!==null&&$time<=$h['_previous']);$h['_previous']=$time;
    if($gap)$h['gaps']++;
    if($gap||!$known){
        if($h['_episode']){$h['_episode']['status']='gap';$h['_episodes'][]=$h['_episode'];$h['_episode']=null;}
        $h['_empty']=false;
    }
    if($known){
        $h['samples']++;$h['first_sample']??=$at;$h['last_sample']=$at;$h['last_pending']=$pending;
        if($snapshot['status']==='stale')$h['stale_samples']++;
        $h['peak_pending']=max($h['peak_pending']??0,$pending);
        if($pending===0){
            $h['last_empty_at']=$at;$h['_empty']=true;
            if($h['_episode']){$h['_episode']['end']=$at;$h['_episode']['status']='drained';$h['_episodes'][]=$h['_episode'];$h['_episode']=null;}
        }elseif(!$h['_episode']){
            $h['_episode']=['start'=>$at,'end'=>null,'peak'=>$pending,'status'=>'pending','start_bounded'=>$h['_empty']];$h['_empty']=false;
        }else $h['_episode']['peak']=max($h['_episode']['peak'],$pending);
    }else $h['unknown_samples']++;
    if(count($h['_episodes'])>15)array_shift($h['_episodes']);
    $key=(int)floor($time/$width);
    if(!isset($h['_buckets'][$key]))$h['_buckets'][$key]=['first'=>null,'peak'=>null,'last'=>null,'gap'=>false,'at'=>$at];
    $bucket=&$h['_buckets'][$key];$bucket['gap']=$bucket['gap']||$gap||!$known;
    if($known){
        $point=['at'=>$at,'pending_records'=>$pending];$bucket['first']??=$point;$bucket['last']=$point;
        if(!$bucket['peak']||$pending>$bucket['peak']['pending_records'])$bucket['peak']=$point;
    }
}
function index_history_finish(array $h): array {
    if($h['_episode'])$h['_episodes'][]=$h['_episode'];ksort($h['_buckets']);$points=[];
    foreach($h['_buckets'] as $bucket){
        if(!$bucket['first']){$points[]=['at'=>$bucket['at'],'pending_records'=>null];continue;}
        $selected=[];foreach(['first','peak','last'] as $kind)$selected[$bucket[$kind]['at']]=$bucket[$kind];ksort($selected);
        foreach($selected as $point)$points[]=$point+['gap'=>$bucket['gap'],'gap_after'=>$bucket['gap']];
    }
    $h['points']=$points;$h['episodes']=array_slice(array_reverse($h['_episodes']),0,15);
    foreach(array_keys($h) as $key)if(str_starts_with($key,'_'))unset($h[$key]);return $h;
}
