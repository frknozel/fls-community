<?php
declare(strict_types=1);
require_once __DIR__.'/fortigate-history.php';

const FGI_KINDS=['policy','virus','webfilter','app-ctrl','dns','ips','ssl'];
const FGI_WINDOWS=[15,60,360,1440];

function fgi_time(string $value): DateTimeImmutable {return new DateTimeImmutable($value,new DateTimeZone('UTC'));}
function fgi_stamp(DateTimeImmutable $value): string {return $value->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');}
function fgi_iso(DateTimeImmutable $value): string {return $value->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');}
function fgi_integer(string $name,int $default,int $minimum=1,int $maximum=PHP_INT_MAX): int {
    $raw=$_GET[$name]??(string)$default;
    if(!is_string($raw)||!preg_match('/^[0-9]{1,19}$/D',$raw)||filter_var($raw,FILTER_VALIDATE_INT)===false||(int)$raw<$minimum||(int)$raw>$maximum)throw new InvalidArgumentException('Karşılaştırma parametresi geçersiz: '.$name);
    return (int)$raw;
}
function fgi_change_public(array $row): array {
    return array_intersect_key($row,array_flip(['id','object_kind','object_name','policyid','poluuid','action','last_confirmed_at','observed_at']));
}
function fgi_choices(): array {
    $kinds="'".implode("','",FGI_KINDS)."'";
    return query("SELECT id,object_kind,object_name,policyid,poluuid,action,last_confirmed_at,observed_at FROM fg_config_changes WHERE device=? AND vd=? AND action<>'baseline' AND object_kind IN ($kinds) ORDER BY observed_at DESC,id DESC LIMIT 100",[fg_serial(),fg_vdom()]);
}
function fgi_delta(int $before,int $after,float $seconds): array {
    return ['before'=>$before,'after'=>$after,'delta'=>$after-$before,'percent'=>$before?round(100*($after-$before)/$before,2):null,
            'new_in_window'=>$before===0&&$after>0,'before_per_hour'=>$seconds>0?round($before*3600/$seconds,2):null,'after_per_hour'=>$seconds>0?round($after*3600/$seconds,2):null];
}
/** Same UUID for policy changes; a named profile is shared across all policies in this VDOM. */
function fgi_scope(array $change): array {
    $where=['BINARY e.devid=BINARY ?','BINARY e.vd=BINARY ?','e.event_at<=DATE_ADD(e.received_at,INTERVAL 120 SECOND)'];$args=[fg_serial(),fg_vdom()];
    if($change['object_kind']==='policy'){
        $where[]='e.policyid=?';$args[]=(int)$change['policyid'];$where[]='BINARY LOWER(e.poluuid)=BINARY ?';$args[]=strtolower($change['poluuid']);
        $where[]="((e.type='utm' AND e.outcome='security_block') OR (e.type='traffic' AND e.subtype='forward' AND e.outcome='policy_deny'))";
        $where[]="COALESCE(JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.policytype')),'policy') IN ('','policy')";
    }else{
        $where[]="e.type='utm' AND e.outcome='security_block'";$where[]='e.subtype=?';$args[]=$change['object_kind'];
        $where[]='e.profile=? AND BINARY e.profile=BINARY ?';$args[]=$change['object_name'];$args[]=$change['object_name'];
    }
    return [implode(' AND ',$where),$args];
}
function fgi_label(array $reason): string {
    $parts=array_filter([$reason['virus']??'',$reason['attack']??'',$reason['catdesc']??'',$reason['app']??'',$reason['certdesc']??'',$reason['reason']??'',$reason['error']??'',$reason['msg']??''],fn($v)=>is_string($v)&&$v!=='');
    if($parts)return implode(' · ',array_unique($parts));
    if(($reason['attackid']??'')!=='')return 'Saldırı imzası #'.$reason['attackid'];
    if(($reason['cat']??'')!=='')return 'Kategori #'.$reason['cat'];
    return 'Ayrıntılı gerekçe logda belirtilmemiş';
}
function fgi_surge(int $before,int $after,array $rule): bool {
    $delta=$after-$before;return $delta>=$rule['minimum_delta']&&($before===0||$delta*100>=$before*$rule['minimum_percent']);
}
function fgi_rank(array $values,string $direction,int $page,float $seconds,?array $surgeRule=null,string $focus=''): array {
    $rows=[];$increases=0;$decreases=0;$surges=[];
    foreach($values as $key=>$value){
        $row=$value+['key'=>$key]+fgi_delta($value['before'],$value['after'],$seconds);
        if($row['delta']>0)$increases++;if($row['delta']<0)$decreases++;
        if($surgeRule&&fgi_surge($row['before'],$row['after'],$surgeRule))$surges[]=$row;
        if($direction==='increase'&&$row['delta']<=0||$direction==='decrease'&&$row['delta']>=0)continue;
        $rows[]=$row;
    }
    usort($rows,function($a,$b)use($direction){$cmp=$direction==='decrease'?($a['delta']<=>$b['delta']):($b['delta']<=>$a['delta']);return $cmp?:($b['after']<=>$a['after'])?:strcmp($a['key'],$b['key']);});
    $found=false;if($focus!=='')foreach($rows as $i=>$row)if(hash_equals($row['key'],$focus)){$page=intdiv($i,25)+1;$found=true;break;}
    $result=['rows'=>array_slice($rows,($page-1)*25,25),'total'=>count($rows),'all_total'=>count($values),'increases'=>$increases,'decreases'=>$decreases,'page'=>$page,'page_size'=>25];
    if($focus!=='')$result+=['focus_key'=>$focus,'focus_found'=>$found];
    if($surgeRule){usort($surges,fn($a,$b)=>($b['delta']<=>$a['delta'])?:strcmp($a['key'],$b['key']));$result['surges']=['total'=>count($surges),'rows'=>array_slice($surges,0,3)];}
    return $result;
}
/** Stream grouped counts; each original event belongs to exactly one time window. */
function fgi_counts(array $change,array $windows,int $maximumId,float $seconds,string $direction,?array $surgeRule=null): array {
    [$scope,$args]=fgi_scope($change);$before=$windows['before'];$after=$windows['after'];
    $reasonObject=function(array $keys): string {$parts=["'code'",'e.reason_code'];foreach($keys as $key){$parts[]="'$key'";$parts[]="COALESCE(JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.$key')),'')";}return 'JSON_OBJECT('.implode(',',$parts).')';};
    $reasonKeys=['action','eventtype','eventsubtype','cat','catdesc','appid','app','appcat','reason','error','msg','filteridx','urlfilteridx','filtertype'];
    $fallback="CASE WHEN e.subtype='ips' THEN ".$reasonObject(['eventtype','eventsubtype','attackid','attack','direction'])." WHEN e.subtype='dns' THEN ".$reasonObject([...$reasonKeys,'domainfilteridx','domainfilterlist','botnetdomain','botnetip'])." WHEN e.subtype='ssl' THEN ".$reasonObject([...$reasonKeys,'certhash','certdesc','tlsver'])." WHEN e.type='traffic' THEN ".$reasonObject(['action','reason','error','msg']).' ELSE '.$reasonObject($reasonKeys).' END';
    $reason="CASE WHEN e.subtype='virus' THEN ".antivirus_reason_sql('e')." ELSE COALESCE(JSON_EXTRACT(s.identity_json,'$.reason'),JSON_EXTRACT(t.identity_json,'$.reason'),$fallback) END";
    // DNS targets are qname, never resolver/answer IPs. IPS, mail and policy denials use destination IP.
    $normalizeHost=fn(string $value)=>"NULLIF(LOWER(TRIM(TRAILING '.' FROM TRIM($value))), '')";
    $host=$normalizeHost("COALESCE(JSON_UNQUOTE(JSON_EXTRACT(s.identity_json,'$.target')),e.hostname)");
    $dns=$normalizeHost("JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.qname'))");
    $target="CASE WHEN e.subtype='dns' THEN COALESCE($dns,'') WHEN e.subtype IN ('ips','virus','forward') THEN e.dstip ELSE COALESCE($host,e.dstip) END";
    $targetKind="CASE WHEN e.subtype='dns' THEN 'dns' WHEN e.subtype IN ('ips','virus','forward') THEN 'ip' WHEN $host IS NOT NULL THEN COALESCE(JSON_UNQUOTE(JSON_EXTRACT(s.identity_json,'$.target_kind')),'hostname') ELSE 'ip' END";
    // Filter identity/outcome in the covering index before reading JSON for the matching blocked rows.
    $index='current_policy_cover';
    $sql="SELECT CASE WHEN e.event_at<? THEN 'before' ELSE 'after' END side,e.srcip,$target target,$targetKind target_kind,e.subtype,$reason reason_json,COUNT(*) n,MAX(e.id) sample_id FROM events e FORCE INDEX($index) LEFT JOIN security_event_groups s ON s.event_id=e.id LEFT JOIN traffic_event_groups tm ON tm.event_id=e.id LEFT JOIN traffic_groups t ON t.group_key=tm.group_key WHERE $scope AND e.id<=? AND ((e.event_at>=? AND e.event_at<?) OR (e.event_at>=? AND e.event_at<?)) GROUP BY side,e.srcip,target,target_kind,e.subtype,reason_json";
    $pdo=db();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);$statement=null;
    $maps=['sources'=>[],'targets'=>[],'reasons'=>[]];$totals=['before'=>0,'after'=>0];
    $add=function(string $dimension,string $key,array $facts,string $side,int $count,int $sample)use(&$maps):void{
        if(!isset($maps[$dimension][$key])){
            if(count($maps[$dimension])>=30000)throw new InvalidArgumentException('Karşılaştırmada çok fazla farklı değer var. Daha kısa bir süre seçin.');
            $maps[$dimension][$key]=$facts+['before'=>0,'after'=>0,'before_sample_id'=>null,'after_sample_id'=>null];
        }
        $maps[$dimension][$key][$side]+=$count;$maps[$dimension][$key][$side.'_sample_id']=max($maps[$dimension][$key][$side.'_sample_id']??0,$sample);
    };
    try{
        $statement=$pdo->prepare($sql);$statement->execute([$before['to_utc'],...$args,$maximumId,$before['from_utc'],$before['to_utc'],$after['from_utc'],$after['to_utc']]);
        while($row=$statement->fetch()){
            $side=$row['side'];$count=(int)$row['n'];$sample=(int)$row['sample_id'];$totals[$side]+=$count;
            $source=$row['srcip'];$target=$row['target'];$kind=$row['target_kind'];$reason=json_decode($row['reason_json'],true,512,JSON_THROW_ON_ERROR);
            // Metadata whitespace, absent empty fields and JSON property order must not create a new reason.
            $reason=array_map(fn($value)=>is_string($value)?trim($value):$value,$reason);
            if($row['subtype']==='ips'&&isset($reason['attackid']))$reason['attackid']=(int)$reason['attackid']>0?(string)(int)$reason['attackid']:'';
            if(isset($reason['certhash'])&&ctype_xdigit($reason['certhash']))$reason['certhash']=strtolower($reason['certhash']);
            $reason=array_filter($reason,fn($value)=>$value!==''&&$value!==null);ksort($reason,SORT_STRING);
            $add('sources',hash('sha256',$source),['label'=>$source?:'Kaynak IP alanı yok'],$side,$count,$sample);
            $add('targets',hash('sha256',$kind.':'.$target),['label'=>$target?:($kind==='dns'?'DNS qname alanı yok':'Hedef alanı yok'),'target_kind'=>$kind],$side,$count,$sample);
            $add('reasons',hash('sha256',$row['subtype'].'|'.json_encode($reason,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)),['label'=>fgi_label($reason),'module'=>$row['subtype'],'reason_code'=>$reason['code']??''],$side,$count,$sample);
        }
    }finally{if($statement)$statement->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
    $rankings=[];foreach($maps as $dimension=>$values)$rankings[$dimension]=fgi_rank($values,$direction,fgi_integer('impact_'.$dimension.'_page',1,1,1200),$seconds,$surgeRule,($_GET['impact_tab']??'sources')===$dimension?($_GET['impact_focus']??''):'');
    return ['totals'=>fgi_delta($totals['before'],$totals['after'],$seconds),'rankings'=>$rankings];
}
function fgi_report(?array $surgeRule=null): array {
    $minutes=fgi_integer('impact_minutes',60,15,1440);if(!in_array($minutes,FGI_WINDOWS,true))throw new InvalidArgumentException('Karşılaştırma süresi geçersiz.');
    $direction=$_GET['impact_direction']??'increase';if(!is_string($direction)||!in_array($direction,['increase','decrease','all'],true))throw new InvalidArgumentException('Karşılaştırma yönü geçersiz.');
    $tab=$_GET['impact_tab']??'sources';$focus=$_GET['impact_focus']??'';
    if(!is_string($tab)||!in_array($tab,['sources','targets','reasons'],true)||!is_string($focus)||($focus!==''&&!preg_match('/^[a-f0-9]{64}$/D',$focus)))throw new InvalidArgumentException('Karşılaştırma odağı geçersiz.');
    foreach(['sources','targets','reasons'] as $dimension)fgi_integer('impact_'.$dimension.'_page',1,1,1200);
    $now=new DateTimeImmutable('now',new DateTimeZone('UTC'));$asof=$now;
    if(isset($_GET['impact_asof'])){
        $input=$_GET['impact_asof'];if(!is_string($input)||!preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/D',$input))throw new InvalidArgumentException('Rapor zamanı geçersiz.');
        try{$asof=fgi_time($input);}catch(Exception $exception){throw new InvalidArgumentException('Rapor zamanı geçersiz.');}if(fgi_iso($asof)!==$input||$asof>$now)throw new InvalidArgumentException('Rapor zamanı geçersiz.');
    }
    $base=['status'=>'choose_change','choices'=>fgi_choices(),'requested_minutes'=>$minutes,'direction'=>$direction,
           'note'=>'Özgün engel kayıtları sayılır. Eşit süreli pencereler, değişikliğin belirsiz aralığını dışarıda bırakır. Trafik hacmi veya başka ayarlar sonucu etkileyebilir; bu karşılaştırma tek başına nedensellik kanıtı değildir.'];
    if(!isset($_GET['impact_change']))return $base;
    $id=fgi_integer('impact_change',1);
    $change=query("SELECT * FROM fg_config_changes WHERE id=? AND device=? AND vd=?",[$id,fg_serial(),fg_vdom()])[0]??null;
    if(!$change)return $base+['error'=>'Değişiklik kaydı bulunamadı.','http_status'=>404];
    $base['change']=fgi_change_public($change);
    if($change['action']==='baseline')return array_replace($base,['status'=>'not_change']);
    if(!in_array($change['object_kind'],FGI_KINDS,true))return array_replace($base,['status'=>'unsupported']);
    if(!$change['last_confirmed_at'])return array_replace($base,['status'=>'no_previous_observation']);
    if($change['object_kind']==='policy'&&((int)$change['policyid']<=0||!preg_match('/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/Di',$change['poluuid']??'')))return array_replace($base,['status'=>'invalid_identity']);
    $maximum=(int)query('SELECT MAX(id) n FROM events')[0]['n'];
    $maximumId=fgi_integer('impact_max_id',$maximum,0);if($maximumId>$maximum)throw new InvalidArgumentException('Rapor kayıt sınırı geçersiz.');
    $base['as_of_utc']=fgi_iso($asof);$base['snapshot_max_id']=$maximumId;
    $beforeEnd=fgi_time($change['last_confirmed_at']);$afterStart=fgi_time($change['observed_at']);
    if($beforeEnd>$afterStart)throw new RuntimeException('Invalid configuration observation interval');
    $base['excluded']=['from_utc'=>fgi_stamp($beforeEnd),'to_utc'=>fgi_stamp($afterStart)];
    $base['scope']=$change['object_kind']==='policy'?['kind'=>'policy','policyid'=>(int)$change['policyid'],'uuid'=>$change['poluuid'],'description'=>'Aynı cihaz, seçili VDOM, policy ID ve UUID içindeki UTM engelleri ile iletilen trafik policy retleri. Local deny ve UTM içeren trafik özetleri sayılmaz.']:['kind'=>'profile','module'=>$change['object_kind'],'profile'=>$change['object_name'],'description'=>'Bu cihaz ve seçili VDOM içinde logda bu profil adı geçen aynı modülün engelleri; profili paylaşan tüm policy’ler dahildir.'];
    $boundary="BINARY devid=BINARY ? AND BINARY vd=BINARY ? AND id<=? AND event_at<=? AND event_at<=DATE_ADD(received_at,INTERVAL 120 SECOND)";
    $boundaryArgs=[fg_serial(),fg_vdom(),$maximumId,fgi_stamp($asof)];
    $first=query("SELECT event_at FROM events FORCE INDEX(event_time) WHERE $boundary ORDER BY event_at,id LIMIT 1",$boundaryArgs)[0]['event_at']??null;
    $last=query("SELECT event_at FROM events FORCE INDEX(event_time) WHERE $boundary ORDER BY event_at DESC,id DESC LIMIT 1",$boundaryArgs)[0]['event_at']??null;
    $index=query('SELECT COALESCE(SUM(GREATEST(observed_size-byte_offset,0)),0) pending_bytes,COALESCE(SUM(invalid_rows),0) invalid_rows FROM source_files')[0];
    $base['data']=['first_event_utc'=>$first,'last_event_utc'=>$last,'index_pending_bytes'=>(int)$index['pending_bytes'],'invalid_rows'=>(int)$index['invalid_rows']];
    $available=$first&&$last?floor(min((float)$asof->format('U.u')-(float)$afterStart->format('U.u'),(float)fgi_time($last)->format('U.u')-(float)$afterStart->format('U.u'),(float)$beforeEnd->format('U.u')-(float)fgi_time($first)->format('U.u'))):0;
    $seconds=(int)max(0,min($minutes*60,$available));$base['actual_seconds']=$seconds;$base['partial']=$seconds<$minutes*60;
    if($seconds<60){$status=$first&&$last?((float)$beforeEnd->format('U.u')-(float)fgi_time($first)->format('U.u')<60?'no_before_logs':'collecting'):'no_log_coverage';return array_replace($base,['status'=>$status]);}
    $windows=['before'=>['from_utc'=>fgi_stamp($beforeEnd->modify('-'.$seconds.' seconds')),'to_utc'=>fgi_stamp($beforeEnd)],'after'=>['from_utc'=>fgi_stamp($afterStart),'to_utc'=>fgi_stamp($afterStart->modify('+'.$seconds.' seconds'))]];
    $base['windows']=$windows;
    $from=$windows['before']['from_utc'];$to=$windows['after']['to_utc'];
    $conflictWhere="device=? AND vd=? AND action<>'baseline' AND id<>? AND observed_at>=? AND COALESCE(last_confirmed_at,observed_at)<? AND observed_at<=?";
    $conflictArgs=[fg_serial(),fg_vdom(),$id,$from,$to,fgi_stamp($asof)];
    $base['other_changes']=['total'=>(int)query("SELECT COUNT(*) n FROM fg_config_changes WHERE $conflictWhere",$conflictArgs)[0]['n'],
                            'rows'=>query("SELECT id,object_kind,object_name,policyid,action,last_confirmed_at,observed_at FROM fg_config_changes WHERE $conflictWhere ORDER BY observed_at,id LIMIT 10",$conflictArgs)];
    $base['failed_observations']=(int)query("SELECT COUNT(*) n FROM fg_config_observations WHERE device=? AND vd=? AND component=? AND error_code IS NOT NULL AND attempted_at>=? AND attempted_at<?",[fg_serial(),fg_vdom(),$change['component'],$from,$to])[0]['n'];
    $previous=query("SELECT observed_at FROM fg_config_observations WHERE device=? AND vd=? AND component=? AND observed_at<? ORDER BY observed_at DESC,id DESC LIMIT 1",[fg_serial(),fg_vdom(),$change['component'],$from])[0]['observed_at']??$from;
    $gaps=0;foreach(query("SELECT observed_at FROM fg_config_observations WHERE device=? AND vd=? AND component=? AND observed_at>=? AND observed_at<? ORDER BY observed_at,id",[fg_serial(),fg_vdom(),$change['component'],$from,$to]) as $observation){if((float)fgi_time($observation['observed_at'])->format('U.u')-(float)fgi_time($previous)->format('U.u')>660)$gaps++;$previous=$observation['observed_at'];}
    if((float)fgi_time($to)->format('U.u')-(float)fgi_time($previous)->format('U.u')>660)$gaps++;$base['observation_gaps']=$gaps;
    $firstConfig=query("SELECT MIN(observed_at) first_at FROM fg_config_observations WHERE device=? AND vd=? AND component=?",[fg_serial(),fg_vdom(),$change['component']])[0]['first_at'];
    $base['before_config_history']=$firstConfig!==null&&$from<$firstConfig;
    return array_replace($base,['status'=>'ready'])+fgi_counts($change,$windows,$maximumId,$seconds,$direction,$surgeRule);
}
function configuration_impact(?array $surgeRule=null): array {
    // Counts, interval limits and examples must come from one importer checkpoint.
    $pdo=db();$pdo->exec('SET TRANSACTION READ ONLY');$pdo->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT');
    try{return fgi_report($surgeRule);}finally{if($pdo->inTransaction())$pdo->rollBack();}
}
