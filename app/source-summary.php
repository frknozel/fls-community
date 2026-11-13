<?php
declare(strict_types=1);
require_once __DIR__.'/archive-query.php';
require_once __DIR__.'/report-ranking.php';

/** A target is an exact, typed identity, never a free-text search of the log. */
function source_target_sql(string $e): string {
    $field=fn(string $name)=>"TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT($e.fields,'$.$name')),''))";
    $host="COALESCE(NULLIF(".$field('hostname').",''),NULLIF(".$field('sni').",''),NULLIF(".$field('servername').",''),'')";
    $tls="COALESCE(NULLIF(".$field('sni').",''),NULLIF(".$field('hostname').",''),NULLIF(".$field('servername').",''),'')";
    $domain="LOWER(TRIM(TRAILING '.' FROM (CASE WHEN $e.subtype='dns' THEN ".$field('qname')." WHEN $e.subtype='ssl' THEN $tls WHEN $e.subtype IN ('webfilter','app-ctrl') THEN $host ELSE '' END)))";
    $ip="COALESCE(INET6_NTOA(INET6_ATON($e.dstip)),TRIM($e.dstip))";
    $kind="CASE WHEN $domain<>'' THEN 'domain' WHEN $e.subtype='dns' THEN 'dns_missing' WHEN $ip<>'' THEN 'ip' ELSE 'missing' END";
    $value="CASE WHEN $domain<>'' THEN $domain WHEN $e.subtype='dns' THEN '' ELSE $ip END";
    return "JSON_OBJECT('kind',$kind,'value',$value)";
}

/** Existing reason identities remain authoritative; ungrouped records still contribute. */
function source_reason_sql(string $e): string {
    $fallback="JSON_OBJECT('code',$e.reason_code,'action',$e.action";
    foreach(['reason','error','msg','virus','virusid','attack','attackid','catdesc','app','certdesc'] as $key)$fallback.=",'$key',COALESCE(JSON_UNQUOTE(JSON_EXTRACT($e.fields,'$.$key')),'')";
    $fallback.=')';
    return "COALESCE((SELECT JSON_EXTRACT(sr.identity_json,'$.reason') FROM security_event_groups sr WHERE sr.event_id=$e.id),(SELECT JSON_EXTRACT(tr.identity_json,'$.reason') FROM traffic_event_groups tm JOIN traffic_groups tr ON tr.group_key=tm.group_key WHERE tm.event_id=$e.id),CASE WHEN $e.subtype='virus' THEN ".antivirus_reason_sql($e)." ELSE $fallback END)";
}
function source_reason_label(array $r): string {
    $parts=array_filter(array_intersect_key($r,array_flip(['virus','attack','catdesc','app','certdesc','reason','error','msg'])),fn($v)=>is_string($v)&&$v!=='');
    if($parts)return implode(' · ',array_unique($parts));
    if(($r['attackid']??'')!=='')return 'Saldırı imzası #'.$r['attackid'];
    if(($r['cat']??'')!=='')return 'Kategori #'.$r['cat'];
    return 'Ayrıntılı gerekçe logda belirtilmemiş';
}
function source_hash_filter(string $name): ?string {
    $value=$_GET[$name]??'';
    if($value==='')return null;
    if(!is_string($value)||!preg_match('/^[a-f0-9]{64}$/D',$value))throw new InvalidArgumentException('İnceleme filtresi geçersiz.');
    return $value;
}
function source_summary(): array { return investigation_summary('source'); }
function target_summary(): array { return investigation_summary('target'); }
function policy_summary(): array { return investigation_summary('policy'); }
function profile_summary(): array { return investigation_summary('profile'); }
function reason_summary(): array { return investigation_summary('reason'); }
function investigation_profile_name(): string {
    $name=$_GET['profile_name']??'';
    if(!is_string($name)||strlen($name)>640||!preg_match('/^.{1,160}$/usD',$name))throw new InvalidArgumentException('Geçerli bir profil adı seçin.');
    return $name;
}
function profile_candidate_where(string $e,string $name,string $module,string $from,string $to,string $outcome): array {
    $where=[fg_event_scope($e),"$e.profile=?","BINARY $e.profile=BINARY ?","$e.event_at>=?","$e.event_at<?"];$args=[$name,$name,$from,$to];
    if($module!=='' && $module!=='all'){$where[]="$e.subtype=?";$args[]=$module;}
    if($outcome==='all_blocks')$where[]="$e.outcome IN ('security_block','policy_deny','local_deny')";
    elseif($outcome==='rating_error')$where[]="$e.rating_error=1";
    elseif($outcome!==''){$where[]="$e.outcome=?";$args[]=$outcome;}
    return [implode(' AND ',$where),$args];
}
function investigation_policy_id(string $name): int {
    $value=$_GET[$name]??'';
    if(!is_string($value)||!preg_match('/^(?:-1|0|[1-9][0-9]{0,9})$/D',$value)||(float)$value>2147483647)throw new InvalidArgumentException('Geçerli bir policy numarası seçin.');
    return (int)$value;
}
/** Bound policy candidates by the existing policy/time index before payload reads. */
function policy_candidate_where(string $e,int $policy,string $scope,string $from,string $to,string $outcome): array {
    $where=[fg_event_scope($e),"$e.policyid=?","$e.event_at>=?","$e.event_at<?","$e.subtype".($scope==='local'?"='local'":"<>'local'")];$args=[$policy,$from,$to];
    if($outcome==='all_blocks')$where[]="$e.outcome IN ('security_block','policy_deny','local_deny')";
    elseif(in_array($outcome,['security_block','policy_deny','local_deny','observed','other_deny'],true)){$where[]="$e.outcome=?";$args[]=$outcome;}
    elseif($outcome==='rating_error')$where[]="$e.rating_error=1";
    return [implode(' AND ',$where),$args];
}
function investigation_summary(string $mode): array {
    $targetMode=$mode==='target';$policyMode=$mode==='policy';$profileMode=$mode==='profile';$reasonMode=$mode==='reason';
    $ip=$_GET['source_ip']??'';$kind=$_GET[$policyMode?'policy_block_scope':($profileMode?'profile_block_scope':$mode.'_scope')]??($profileMode?'security':'all');
    if($mode==='source' && (!is_string($ip)||!filter_var($ip,FILTER_VALIDATE_IP)))throw new InvalidArgumentException('Geçerli bir kaynak IP girin.');
    $hash=$targetMode?source_hash_filter('target_key'):null;
    if($targetMode && !$hash)throw new InvalidArgumentException('Geçerli bir hedef seçin.');
    $outcomes=['all'=>'all_blocks','security'=>'security_block','policy'=>'policy_deny','local'=>'local_deny'];
    if(!is_string($kind)||!isset($outcomes[$kind]))throw new InvalidArgumentException('Engel kapsamı geçersiz.');
    $profileName=$profileMode?investigation_profile_name():null;$profileModule=$_GET['profile_module']??'all';
    if($profileMode && (!is_string($profileModule)||!in_array($profileModule,['all','virus','webfilter','app-ctrl','dns','ssl','ips','forward','local'],true)))throw new InvalidArgumentException('Profil modülü geçersiz.');
    $reasonRef=$reasonMode?investigation_reason_ref():null;$reasonInfo=null;
    $policyId=$policyMode?investigation_policy_id('policy_id'):null;
    $policyScope=$_GET['policy_scope']??'forward';
    if($policyMode && (!is_string($policyScope)||!in_array($policyScope,['local','forward'],true)))throw new InvalidArgumentException('Policy kapsamı geçersiz.');
    [$from,$to]=scope();$args=[$targetMode?$hash:$ip,$from,$to];
    $index=$targetMode?'target_time':'source_time';
    $subject=$targetMode?'e.target_fingerprint=UNHEX(?)':'e.srcip=?';
    $where=fg_event_scope('e')." AND $subject AND e.event_at>=? AND e.event_at<? AND ".($kind==='all'?"e.outcome IN ('security_block','policy_deny','local_deny')":"e.outcome=?");
    if($kind!=='all')$args[]=$outcomes[$kind];
    if($policyMode){[$where,$args]=policy_candidate_where('e',$policyId,$policyScope,$from,$to,$outcomes[$kind]);$index='policy_time';}
    if($profileMode){[$where,$args]=profile_candidate_where('e',$profileName,$profileModule,$from,$to,$outcomes[$kind]);$index='profile_time';}
    $targetInfo=null;
    if($targetMode){
        $identity=query('SELECT '.source_target_sql('e').' identity_json FROM events e FORCE INDEX(target_time) WHERE '.fg_event_scope('e').' AND e.target_fingerprint=UNHEX(?) LIMIT 1',[$hash])[0]['identity_json']??null;
        $targetInfo=$identity?json_decode($identity,true,512,JSON_THROW_ON_ERROR):['kind'=>'unknown','value'=>''];
        $targetInfo+=['key'=>$hash,'label'=>$targetInfo['value']!==''?$targetInfo['value']:($targetInfo['kind']==='dns_missing'?'Sorgu adı logda yok':($identity?'Hedef alanı logda yok':'Kayıt bulunmayan hedef'))];
    }
    $names=[];foreach(query('SELECT policyid,name FROM '.fg_scoped_table('device_policies').' p ORDER BY policyid,name') as $p)$names[$p['policyid']][$p['name']]=true;
    $observed=$mode!=='source'?[]:query("SELECT name,last_seen FROM (SELECT e.srcname name,e.event_at last_seen FROM events e FORCE INDEX(source_time) WHERE ".fg_event_scope('e')." AND e.srcip=? AND e.event_at>=? AND e.event_at<? ORDER BY e.event_at DESC,e.id DESC LIMIT 200) recent WHERE name<>'' ORDER BY last_seen DESC LIMIT 1",[$ip,$from,$to]);
    $devices=[];if($targetMode||$policyMode||$profileMode||$reasonMode)foreach(query('SELECT ip,name FROM '.fg_scoped_table('device_sources').' d') as $device)$devices[$device['ip']]=$device['name'];
    $rankings=$reasonMode?['sources'=>[],'targets'=>[],'policies'=>[],'profiles'=>[]]:($profileMode?['sources'=>[],'targets'=>[],'policies'=>[],'reasons'=>[]]:($policyMode?['sources'=>[],'targets'=>[],'profiles'=>[],'reasons'=>[]]:[$targetMode?'sources':'targets'=>[],'policies'=>[],'profiles'=>[],'reasons'=>[]]));$totals=['records'=>0,'first_event_at'=>null,'last_event_at'=>null];
    $spool=new ReportRankingSpool();foreach($rankings as &$ranking)$ranking=new ReportRanking($spool);unset($ranking);
    $families=array_fill_keys(['security_block','policy_deny','local_deny'],0);
    $add=function(string $dimension,string $key,array $facts,array $bucket)use(&$rankings):void{
        $rankings[$dimension]->add($key,$facts,(int)$bucket['n'],$bucket['first_event_at'],$bucket['last_event_at']);
    };
    $target=$targetMode?'NULL':source_target_sql('e');$reason=source_reason_sql('e');
    $sql="SELECT $target target_json,$reason reason_json,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,COUNT(*) n,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM events e FORCE INDEX($index) WHERE $where GROUP BY SHA2(target_json,256),SHA2(reason_json,256),e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome";
    $queries=[[$sql,$args]];
    if($targetMode){
        $queries=[];
        if(in_array($kind,['all','policy','local'],true) && in_array($targetInfo['kind'],['ip','missing'],true)){
            $trafficWhere=fg_identity_scope('g').' AND '.($kind==='all'?"g.outcome IN ('local_deny','policy_deny')":"g.outcome=?");
            $trafficArgs=[$hash,$from,$to];if($kind!=='all')$trafficArgs[]=$outcomes[$kind];
            $buckets="SELECT m.group_key,m.profile,COUNT(*) n,MIN(candidate.event_at) first_event_at,MAX(candidate.event_at) last_event_at FROM events candidate FORCE INDEX(target_time) STRAIGHT_JOIN traffic_event_groups m ON m.event_id=candidate.id WHERE ".fg_event_scope('candidate')." AND candidate.target_fingerprint=UNHEX(?) AND candidate.event_at>=? AND candidate.event_at<? GROUP BY m.group_key,BINARY m.profile";
            $queries[]=["SELECT 't' reason_family,NULL target_json,JSON_EXTRACT(g.identity_json,'$.reason') reason_json,g.srcip,g.policyid,b.profile,g.subtype,g.outcome,SUM(b.n) n,MIN(b.first_event_at) first_event_at,MAX(b.last_event_at) last_event_at FROM ($buckets) b STRAIGHT_JOIN traffic_groups g ON g.group_key=b.group_key WHERE $trafficWhere GROUP BY SHA2(reason_json,256),g.srcip,g.policyid,BINARY b.profile,g.subtype,g.outcome",$trafficArgs];
        }
        // Covering ID lookup excludes mapped traffic before fetching any original JSON.
        // LIMIT prevents derived-table merging, so the raw fallback only reads residual events.
        $ids="SELECT candidate.id FROM events candidate FORCE INDEX(target_time) LEFT JOIN traffic_event_groups member ON member.event_id=candidate.id WHERE ".fg_event_scope('candidate')." AND candidate.target_fingerprint=UNHEX(?) AND candidate.event_at>=? AND candidate.event_at<? AND member.event_id IS NULL LIMIT 18446744073709551615";
        $fallbackSql="SELECT NULL target_json,$reason reason_json,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,COUNT(*) n,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id WHERE $where GROUP BY SHA2(reason_json,256),e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome";
        $queries[]=[$fallbackSql,array_merge([$hash,$from,$to],$args)];
    }
    if($policyMode){
        [$candidateWhere,$candidateArgs]=policy_candidate_where('candidate',$policyId,$policyScope,$from,$to,$outcomes[$kind]);
        $queries=[];
        if(in_array($kind,['all','policy','local'],true)){
            $rawIp="COALESCE(JSON_UNQUOTE(JSON_EXTRACT(g.identity_json,'$.target')),'')";
            $targetIp="COALESCE(INET6_NTOA(INET6_ATON($rawIp)),TRIM($rawIp))";
            $trafficTarget="JSON_OBJECT('kind',IF($targetIp='','missing','ip'),'value',$targetIp)";
            $trafficWhere=fg_identity_scope('pg')." AND pg.policyid=? AND pg.subtype".($policyScope==='local'?"='local'":"<>'local'");
            $trafficArgs=[$from,$to,$policyId];
            if($kind==='all')$trafficWhere.=" AND pg.outcome IN ('policy_deny','local_deny')";
            else{$trafficWhere.=' AND pg.outcome=?';$trafficArgs[]=$outcomes[$kind];}
            $buckets="SELECT m.group_key,m.profile,COUNT(*) n,MIN(m.event_at) first_event_at,MAX(m.event_at) last_event_at FROM traffic_groups pg STRAIGHT_JOIN traffic_event_groups m FORCE INDEX(summary_cover) ON m.group_key=pg.group_key AND m.event_at>=? AND m.event_at<? WHERE $trafficWhere GROUP BY m.group_key,BINARY m.profile";
            $queries[]=["SELECT 't' reason_family,$trafficTarget target_json,JSON_EXTRACT(g.identity_json,'$.reason') reason_json,g.srcip,g.policyid,b.profile,g.subtype,g.outcome,SUM(b.n) n,MIN(b.first_event_at) first_event_at,MAX(b.last_event_at) last_event_at FROM ($buckets) b STRAIGHT_JOIN traffic_groups g ON g.group_key=b.group_key GROUP BY SHA2(target_json,256),SHA2(reason_json,256),g.srcip,g.policyid,BINARY b.profile,g.subtype,g.outcome",$trafficArgs];
        }
        $ids="SELECT candidate.id FROM events candidate FORCE INDEX(policy_time) LEFT JOIN traffic_event_groups member ON member.event_id=candidate.id WHERE $candidateWhere AND member.event_id IS NULL LIMIT 18446744073709551615";
        $queries[]=["SELECT $target target_json,$reason reason_json,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,COUNT(*) n,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id WHERE $where GROUP BY SHA2(target_json,256),SHA2(reason_json,256),e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome",array_merge($candidateArgs,$args)];
    }
    if($profileMode){
        [$candidateWhere,$candidateArgs]=profile_candidate_where('candidate',$profileName,$profileModule,$from,$to,$outcomes[$kind]);
        // The profile/time index bounds subject IDs before fetching any raw JSON.
        $ids="SELECT candidate.id FROM events candidate FORCE INDEX(profile_time) WHERE $candidateWhere LIMIT 18446744073709551615";
        $queries=[["SELECT $target target_json,$reason reason_json,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,COUNT(*) n,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id GROUP BY SHA2(target_json,256),SHA2(reason_json,256),e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome",$candidateArgs]];
    }
    if($reasonMode)$queries=reason_summary_queries($reasonRef,$from,$to,$kind);
    $fastQueries=archive_investigation_queries($mode,$kind,$from,$to);if($fastQueries!==null)$queries=$fastQueries;
    // Stream buckets; exact external merges bound memory even with many identities.
    $pdo=db();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);$s=null;
    try{
      foreach($queries as [$sql,$queryArgs]){
        $s=$pdo->prepare($sql);$s->execute($queryArgs);
        while($r=$s->fetch()){
            if($reasonMode && $reasonInfo===null)$reasonInfo=reason_descriptor($reasonRef,$r['subtype'],$r['reason_json']);
            $totals['records']+=(int)$r['n'];$families[$r['outcome']]+=(int)$r['n'];
            $totals['first_event_at']=$totals['first_event_at']===null?$r['first_event_at']:min($totals['first_event_at'],$r['first_event_at']);
            $totals['last_event_at']=max($totals['last_event_at']??'',$r['last_event_at']);
            $t=$targetMode?$targetInfo:json_decode($r['target_json'],true,512,JSON_THROW_ON_ERROR);$key=$targetMode?$hash:hash('sha256',$r['target_json']);
            $label=$t['value']!==''?$t['value']:($t['kind']==='dns_missing'?'Sorgu adı logda yok':'Hedef alanı logda yok');
            if($targetMode||$policyMode||$profileMode||$reasonMode){$source=$r['srcip'];$add('sources',$source,['label'=>$source!==''?$source:'Kaynak IP alanı yok','name'=>$devices[$source]??'','filter'=>$source!==''?['source'=>$source]:['source_missing'=>'1']],$r);}
            if(!$targetMode)$add('targets',$key,['label'=>$label,'kind'=>$t['kind'],'target'=>$t+['key'=>$key,'label'=>$label],'filter'=>['target_key'=>$key,'target_label'=>$label]],$r);
            $local=$r['subtype']==='local';$scope=$local?'local':'forward';$policy=(int)$r['policyid'];
            if(!$policyMode)$add('policies',$scope.':'.$policy,['label'=>$policy>=0?'Policy '.$policy:'Policy alanı yok','name'=>$local?'Local trafik':implode(' / ',array_keys($names[$policy]??[])),'policy_scope'=>$scope,'filter'=>['policy'=>(string)$policy,'policy_scope'=>$scope]],$r);
            $profile=$r['profile'];if(!$profileMode)$add('profiles',$profile,['label'=>$profile!==''?$profile:'Profil alanı yok','missing'=>$profile==='','filter'=>$profile!==''?['profile'=>$profile]:['profile_missing'=>'1']],$r);
            $key=hash('sha256',$r['subtype'].'|'.$r['reason_json']);$rr=json_decode($r['reason_json'],true,512,JSON_THROW_ON_ERROR);$label=source_reason_label($rr);
            $reasonFilter=($r['reason_family']??'')==='t'?['block_reason'=>'t:'.$key,'block_reason_label'=>$label]:['source_reason'=>$key,'source_reason_label'=>$label];
            if(!$reasonMode)$add('reasons',$key,['label'=>$label,'module'=>$r['subtype'],'reason_code'=>$rr['code']??$r['outcome'],'filter'=>$reasonFilter],$r);
        }
        $s->closeCursor();
      }
    }finally{if($s)$s->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
    if($reasonMode && $reasonInfo===null)$reasonInfo=reason_lookup($reasonRef);
    $distinct=[];
    foreach($rankings as $dimension=>&$rows){
        $result=$rows->finish();$distinct[$dimension]=$result['distinct'];$rows=$result['rows'];
        foreach($rows as &$r){$r['percent']=$totals['records']?round(100*$r['records']/$totals['records'],2):0;$r['filter']=['outcome'=>$outcomes[$kind]]+($reasonMode?reason_subject_filter($reasonRef,$reasonInfo['label']):($profileMode?(['profile'=>$profileName]+($profileModule==='all'?[]:['module'=>$profileModule])):($policyMode?['policy'=>(string)$policyId,'policy_scope'=>$policyScope]:($targetMode?['target_key'=>$hash,'target_label'=>$targetInfo['label']]:['source'=>$ip]))))+$r['filter'];}unset($r);
    }unset($rows);
    return ($reasonMode?['reason'=>$reasonInfo]:($profileMode?['profile'=>['name'=>$profileName,'label'=>$profileName,'module'=>$profileModule,'identity'=>'exact_profile_name_and_module']]:($policyMode?['policy'=>['id'=>$policyId,'scope'=>$policyScope,'label'=>$policyId>=0?'Policy '.$policyId:'Policy alanı yok','observed_names'=>$policyScope==='local'?[]:array_keys($names[$policyId]??[]),'identity'=>'policy_id_and_traffic_scope']]:($targetMode?['target'=>$targetInfo]:['source'=>['ip'=>$ip,'observed_names'=>$observed]]))))+['scope'=>['from_utc'=>$from,'to_utc'=>$to,'kind'=>$kind],'totals'=>$totals,'families'=>$families,'distinct'=>$distinct,'rankings'=>$rankings,'counting'=>'original_block_records','generated_at'=>gmdate('c')];
}

/** Source investigations use original events first, preserving unmatched legacy members too. */
function source_event_candidates(string $where,array $args,int $size,int $offset): array {
    $mailSearch=mail_search_requested();
    if(!$mailSearch && archive_events_available())return archive_event_candidates($size,$offset);
    if(!$mailSearch && !empty($_GET['target_key']) && empty($_GET['q']) && ($_GET['outcome']??'')!=='rating_error' && ($_GET['reason']??'')!=='rating_error')return target_event_candidates($where,$args,$size,$offset);
    if(!$mailSearch && reason_request_ref()!==null && empty($_GET['q']) && empty($_GET['target_key']) && in_array($_GET['outcome']??'',['all_blocks','security_block','policy_deny','local_deny'],true))return reason_event_candidates($where,$args,$size,$offset);
    if(!$mailSearch && ($_GET['policy']??'')!=='' && ($_GET['policy_scope']??'')!=='' && empty($_GET['q']) && ($_GET['reason']??'')!=='rating_error')return target_event_candidates($where,$args,$size,$offset,true);
    $joins=[];$keys=[];$kinds=[];
    foreach(['av'=>['av_event_groups','a','group_av'],'security'=>['security_event_groups','s','group_security'],'traffic'=>['traffic_event_groups','t','group_traffic']] as $kind=>[$table,$prefix,$flag]){
        if(($_GET[$flag]??'0')!=='1')continue;
        $joins[]="LEFT JOIN $table sx_$prefix ON sx_$prefix.event_id=e.id";
        $keys[]="WHEN sx_$prefix.event_id IS NOT NULL THEN CONCAT('$prefix:',HEX(sx_$prefix.group_key))";
        $kinds[]="WHEN sx_$prefix.event_id IS NOT NULL THEN '$kind'";
    }
    $key=$keys?'CASE '.implode(' ',$keys)." ELSE CONCAT('event:',e.id) END":"CONCAT('event:',e.id)";
    $kind=$kinds?'CASE '.implode(' ',$kinds).' ELSE NULL END':'NULL';
    $index=!empty($_GET['source'])?' FORCE INDEX(source_time)':(!empty($_GET['target_key'])?' FORCE INDEX(target_time)':'');
    $eventFrom="events e$index";
    if($mailSearch){require_once __DIR__.'/mail-search.php';[$ids,$searchArgs]=mail_search_candidates(array_slice($args,0,2));$eventFrom="($ids) mail_ids STRAIGHT_JOIN events e ON e.id=mail_ids.event_id";$args=array_merge($searchArgs,$args);}
    if(!$mailSearch && ($_GET['profile']??'')!=='' && empty($_GET['source']) && empty($_GET['target_key'])){
        [$from,$to]=scope();[$candidateWhere,$candidateArgs]=profile_candidate_where('candidate',$_GET['profile'],$_GET['module']??'all',$from,$to,$_GET['outcome']??'');
        $eventFrom="(SELECT candidate.id FROM events candidate FORCE INDEX(profile_time) WHERE $candidateWhere LIMIT 18446744073709551615) ids STRAIGHT_JOIN events e ON e.id=ids.id";
        $args=array_merge($candidateArgs,$args);
    }
    $cte="WITH matched AS (SELECT e.id,e.event_at,$key group_key,$kind group_kind FROM $eventFrom ".implode(' ',$joins)." WHERE $where),stats AS (SELECT group_key,group_kind,COUNT(*) matched_records,MIN(event_at) first_event_at,MAX(event_at) last_event_at FROM matched GROUP BY group_key,group_kind) ";
    $counts=query($cte.'SELECT COUNT(*) total,COALESCE(SUM(matched_records),0) total_records FROM stats',$args)[0];
    $rows=query($cte."SELECT MAX(m.id) id,s.group_kind,s.matched_records,s.first_event_at,s.last_event_at FROM stats s JOIN matched m ON m.group_key=s.group_key AND m.event_at=s.last_event_at GROUP BY s.group_key,s.group_kind,s.matched_records,s.first_event_at,s.last_event_at ORDER BY s.last_event_at DESC,id DESC LIMIT $size OFFSET $offset",$args);
    return ['keys'=>$rows,'total'=>(int)$counts['total'],'total_records'=>(int)$counts['total_records'],'grouped'=>(bool)$joins];
}

/** Bound subject IDs and use native traffic metadata before reading original payloads. */
function target_event_candidates(string $where,array $args,int $size,int $offset,bool $policyMode=false): array {
    [$from,$to]=scope();
    if($policyMode){[$candidateWhere,$candidateArgs]=policy_candidate_where('candidate',investigation_policy_id('policy'),$_GET['policy_scope'],$from,$to,$_GET['outcome']??'');$index='policy_time';}
    else{$candidateWhere=fg_event_scope('candidate').' AND candidate.target_fingerprint=UNHEX(?) AND candidate.event_at>=? AND candidate.event_at<?';$candidateArgs=[source_hash_filter('target_key'),$from,$to];$index='target_time';}
    $tw=[$candidateWhere];$tp=$candidateArgs;
    foreach(['source'=>'g.srcip','policy'=>'g.policyid','profile'=>'m.profile','module'=>'g.subtype','reason'=>'g.reason_code'] as $param=>$column){
        if(($_GET[$param]??'')==='')continue;
        $tw[]="$column=?";$tp[]=$_GET[$param];
        if($param==='profile'){$tw[]='BINARY m.profile=BINARY ?';$tp[]=$_GET[$param];}
    }
    if(($_GET['source_missing']??'')==='1')$tw[]="g.srcip=''";
    if(($_GET['profile_missing']??'')==='1')$tw[]="m.profile=''";
    if(($_GET['policy_scope']??'')!=='')$tw[]="g.subtype".($_GET['policy_scope']==='local'?"='local'":"<>'local'");
    $outcome=$_GET['outcome']??'';
    if(in_array($outcome,['local_deny','policy_deny'],true)){$tw[]='g.outcome=?';$tp[]=$outcome;}
    elseif(!in_array($outcome,['','all_blocks'],true))$tw[]='0';
    if($filter=block_reason_filter()){
        if($filter[0]!=='t')$tw[]='0';
        else{$tw[]=block_reason_hash_sql('g.subtype',"JSON_EXTRACT(g.identity_json,'$.reason')").'=?';$tp[]=$filter[1];}
    }
    if($filter=source_hash_filter('source_reason')){$tw[]=block_reason_hash_sql('g.subtype',"JSON_EXTRACT(g.identity_json,'$.reason')").'=?';$tp[]=$filter;}
    $trafficGrouped=($_GET['group_traffic']??'0')==='1';
    $trafficKey=$trafficGrouped?"CONCAT('t:',HEX(m.group_key))":"CONCAT('event:',candidate.id)";
    $trafficKind=$trafficGrouped?"'traffic'":'NULL';
    if($policyMode){
        $nativeWhere=strtr(implode(' AND ',$tw),['candidate.event_at'=>'m.event_at','candidate.policyid'=>'g.policyid','candidate.subtype'=>'g.subtype','candidate.outcome'=>'g.outcome','candidate.rating_error'=>'0','candidate.devid'=>"JSON_UNQUOTE(JSON_EXTRACT(g.identity_json,'$.devid'))",'candidate.vd'=>"JSON_UNQUOTE(JSON_EXTRACT(g.identity_json,'$.vd'))"]);
        $trafficFrom="FROM traffic_groups g STRAIGHT_JOIN traffic_event_groups m FORCE INDEX(group_time) ON m.group_key=g.group_key WHERE $nativeWhere";
        $trafficKey=str_replace('candidate.id','m.event_id',$trafficKey);
        $traffic="SELECT m.event_id id,m.event_at,$trafficKey group_key,$trafficKind group_kind $trafficFrom";
    }else $traffic="SELECT candidate.id id,candidate.event_at,$trafficKey group_key,$trafficKind group_kind FROM events candidate FORCE INDEX($index) STRAIGHT_JOIN traffic_event_groups m ON m.event_id=candidate.id STRAIGHT_JOIN traffic_groups g ON g.group_key=m.group_key WHERE ".implode(' AND ',$tw);
    $joins=[];$keys=[];$kinds=[];
    foreach(['av'=>['av_event_groups','a','group_av'],'security'=>['security_event_groups','s','group_security']] as $kind=>[$table,$prefix,$flag]){
        if(($_GET[$flag]??'0')!=='1')continue;
        $joins[]="LEFT JOIN $table sx_$prefix ON sx_$prefix.event_id=e.id";
        $keys[]="WHEN sx_$prefix.event_id IS NOT NULL THEN CONCAT('$prefix:',HEX(sx_$prefix.group_key))";
        $kinds[]="WHEN sx_$prefix.event_id IS NOT NULL THEN '$kind'";
    }
    $key=$keys?'CASE '.implode(' ',$keys)." ELSE CONCAT('event:',e.id) END":"CONCAT('event:',e.id)";
    $kind=$kinds?'CASE '.implode(' ',$kinds).' ELSE NULL END':'NULL';
    // Materialize subject/time candidate IDs before payload reads; legacy traffic is retained here.
    $ids="SELECT candidate.id FROM events candidate FORCE INDEX($index) LEFT JOIN traffic_event_groups member ON member.event_id=candidate.id WHERE $candidateWhere AND member.event_id IS NULL LIMIT 18446744073709551615";
    $fallback="SELECT e.id,e.event_at,$key group_key,$kind group_kind FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id ".implode(' ',$joins)." WHERE $where";
    $params=array_merge($tp,$candidateArgs,$args);
    if($policyMode){
        // Aggregate native binary membership keys before combining families. Materializing
        // a million textual per-event group keys causes disk spills on mechanical storage.
        $last="CONCAT(DATE_FORMAT(m.event_at,'%Y%m%d%H%i%s%f'),LPAD(m.event_id,20,'0'))";
        $trafficStats=$trafficGrouped?"SELECT MAX($last) last_record,'traffic' group_kind,COUNT(*) matched_records,MIN(m.event_at) first_event_at,MAX(m.event_at) last_event_at $trafficFrom GROUP BY m.group_key":"SELECT $last last_record,NULL group_kind,1 matched_records,m.event_at first_event_at,m.event_at last_event_at $trafficFrom";
        $fallbackStats="SELECT MAX(CONCAT(DATE_FORMAT(event_at,'%Y%m%d%H%i%s%f'),LPAD(id,20,'0'))) last_record,group_kind,COUNT(*) matched_records,MIN(event_at) first_event_at,MAX(event_at) last_event_at FROM ($fallback) residual GROUP BY group_key,group_kind";
        $stats="WITH stats AS ($trafficStats UNION ALL $fallbackStats) ";
        $counts=query($stats.'SELECT COUNT(*) total,COALESCE(SUM(matched_records),0) total_records FROM stats',$params)[0];
        $rows=query($stats."SELECT CAST(RIGHT(last_record,20) AS UNSIGNED) id,group_kind,matched_records,first_event_at,last_event_at FROM stats ORDER BY last_event_at DESC,id DESC LIMIT $size OFFSET $offset",$params);
        return ['keys'=>$rows,'total'=>(int)$counts['total'],'total_records'=>(int)$counts['total_records'],'grouped'=>$trafficGrouped||(bool)$joins];
    }
    $cte="WITH matched AS ($traffic UNION ALL $fallback),stats AS (SELECT group_key,group_kind,COUNT(*) matched_records,MIN(event_at) first_event_at,MAX(event_at) last_event_at FROM matched GROUP BY group_key,group_kind) ";
    $counts=query($cte.'SELECT COUNT(*) total,COALESCE(SUM(matched_records),0) total_records FROM stats',$params)[0];
    $rows=query($cte."SELECT MAX(m.id) id,s.group_kind,s.matched_records,s.first_event_at,s.last_event_at FROM stats s JOIN matched m ON m.group_key=s.group_key AND m.event_at=s.last_event_at GROUP BY s.group_key,s.group_kind,s.matched_records,s.first_event_at,s.last_event_at ORDER BY s.last_event_at DESC,id DESC LIMIT $size OFFSET $offset",$params);
    return ['keys'=>$rows,'total'=>(int)$counts['total'],'total_records'=>(int)$counts['total_records'],'grouped'=>$trafficGrouped||(bool)$joins];
}

/** A reason reference preserves native group filters and canonical original-event filters. */
function investigation_reason_ref(): string {
    $ref=$_GET['reason_ref']??'';
    if(!is_string($ref)||!preg_match('/^[star]:[a-f0-9]{64}$/D',$ref))throw new InvalidArgumentException('Geçerli bir engelleme gerekçesi seçin.');
    return $ref;
}
function reason_request_ref(): ?string {
    if($hash=source_hash_filter('source_reason'))return 'r:'.$hash;
    if($filter=block_reason_filter())return $filter[0].':'.$filter[1];
    return null;
}
function reason_subject_filter(string $ref,string $label): array {
    return $ref[0]==='r'?['source_reason'=>substr($ref,2),'source_reason_label'=>$label]:['block_reason'=>$ref,'block_reason_label'=>$label];
}
function reason_descriptor(string $ref,string $module,string $json): array {
    $details=json_decode($json,true,512,JSON_THROW_ON_ERROR);
    return ['reference'=>$ref,'module'=>$module,'label'=>source_reason_label($details),'reason_code'=>$details['code']??'','details'=>$details,'known'=>true];
}
/** Native metadata selects matches first; only unmatched legacy blocks use the raw fallback. */
function reason_member_sources(string $ref,string $from,string $to): array {
    $family=$ref[0];$hash=substr($ref,2);$blocks="IN ('security_block','policy_deny','local_deny')";
    $trafficWhere='0';$trafficArgs=[];
    if(in_array($family,['r','t'],true)){$trafficWhere=fg_identity_scope('g')." AND m.event_at>=? AND m.event_at<? AND ".block_reason_hash_sql('g.subtype',"JSON_EXTRACT(g.identity_json,'$.reason')").'=?';$trafficArgs=[$from,$to,$hash];}
    $others=[];$otherArgs=[];
    if(in_array($family,['r','s'],true)){
        $match="SELECT sm.event_id id FROM security_event_groups sm WHERE ".block_reason_hash_sql("JSON_UNQUOTE(JSON_EXTRACT(sm.identity_json,'$.module'))","JSON_EXTRACT(sm.identity_json,'$.reason')").'=? LIMIT 18446744073709551615';
        $others[]="SELECT e.id,e.event_at FROM ($match) selected STRAIGHT_JOIN events e ON e.id=selected.id WHERE ".fg_event_scope('e')." AND e.event_at>=? AND e.event_at<? AND e.outcome $blocks";$otherArgs=array_merge($otherArgs,[$hash,$from,$to]);
    }
    if(in_array($family,['r','a'],true)){
        $ids="SELECT candidate.id FROM events candidate FORCE INDEX(current_policy_cover) WHERE ".fg_event_scope('candidate')." AND candidate.type='utm' AND candidate.subtype='virus' AND candidate.event_at>=? AND candidate.event_at<? AND candidate.outcome $blocks LIMIT 18446744073709551615";
        $membership=$family==='a'?' JOIN av_event_groups am ON am.event_id=e.id':'';
        $others[]="SELECT e.id,e.event_at FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id $membership WHERE ".block_reason_hash_sql('e.subtype',antivirus_reason_sql('e')).'=?';$otherArgs=array_merge($otherArgs,[$from,$to,$hash]);
    }
    if($family==='r'){
        $ids="SELECT candidate.id FROM events candidate FORCE INDEX(current_policy_cover) LEFT JOIN security_event_groups sm ON sm.event_id=candidate.id LEFT JOIN traffic_event_groups tm ON tm.event_id=candidate.id WHERE ".fg_event_scope('candidate')." AND candidate.subtype<>'virus' AND candidate.event_at>=? AND candidate.event_at<? AND candidate.outcome $blocks AND sm.event_id IS NULL AND tm.event_id IS NULL LIMIT 18446744073709551615";
        $others[]="SELECT e.id,e.event_at FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id WHERE ".block_reason_hash_sql('e.subtype',source_reason_sql('e')).'=?';$otherArgs=array_merge($otherArgs,[$from,$to,$hash]);
    }
    return ['traffic_where'=>$trafficWhere,'traffic_args'=>$trafficArgs,'other_sql'=>$others?implode(' UNION ALL ',$others):'SELECT id,event_at FROM events WHERE 0','other_args'=>$otherArgs];
}
function reason_summary_queries(string $ref,string $from,string $to,string $kind): array {
    $parts=reason_member_sources($ref,$from,$to);$outcomes=['security'=>'security_block','policy'=>'policy_deny','local'=>'local_deny'];
    $restrict=$kind==='all'?"g.outcome IN ('policy_deny','local_deny')":"g.outcome='".$outcomes[$kind]."'";
    $buckets="SELECT m.group_key,m.profile,COUNT(*) n,MIN(m.event_at) first_event_at,MAX(m.event_at) last_event_at FROM traffic_groups g STRAIGHT_JOIN traffic_event_groups m FORCE INDEX(summary_cover) ON m.group_key=g.group_key WHERE ".$parts['traffic_where']." AND $restrict GROUP BY m.group_key,BINARY m.profile";
    $rawIp="COALESCE(JSON_UNQUOTE(JSON_EXTRACT(g.identity_json,'$.target')),'')";$ip="COALESCE(INET6_NTOA(INET6_ATON($rawIp)),TRIM($rawIp))";
    $target="JSON_OBJECT('kind',IF($ip='','missing','ip'),'value',$ip)";
    $traffic="SELECT $target target_json,JSON_EXTRACT(g.identity_json,'$.reason') reason_json,g.srcip,g.policyid,b.profile,g.subtype,g.outcome,SUM(b.n) n,MIN(b.first_event_at) first_event_at,MAX(b.last_event_at) last_event_at FROM ($buckets) b STRAIGHT_JOIN traffic_groups g ON g.group_key=b.group_key GROUP BY SHA2(target_json,256),g.srcip,g.policyid,BINARY b.profile,g.subtype,g.outcome";
    $target=source_target_sql('e');$reason=source_reason_sql('e');$restrict=$kind==='all'?'1':"e.outcome='".$outcomes[$kind]."'";
    $other="SELECT $target target_json,$reason reason_json,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,COUNT(*) n,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM (".$parts['other_sql'].") ids STRAIGHT_JOIN events e ON e.id=ids.id WHERE $restrict GROUP BY SHA2(target_json,256),e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome";
    return [[$traffic,$parts['traffic_args']],[$other,$parts['other_args']]];
}
function reason_lookup(string $ref): array {
    $family=$ref[0];$hash=substr($ref,2);$queries=[];
    if(archive_watermark()!==null){
        $known=query("SELECT subtype module,reason_json FROM archive_dimensions d WHERE ".fg_event_scope('d')." AND reason_key=UNHEX(?)".($family==='r'?'':' AND family=?').' LIMIT 1',$family==='r'?[$hash]:[$hash,$family])[0]??null;
        if($known)return reason_descriptor($ref,$known['module'],$known['reason_json']);
    }
    if(in_array($family,['r','t'],true))$queries[]=["SELECT g.subtype module,JSON_EXTRACT(g.identity_json,'$.reason') reason_json FROM traffic_groups g WHERE ".fg_identity_scope('g')." AND ".block_reason_hash_sql('g.subtype',"JSON_EXTRACT(g.identity_json,'$.reason')").'=? LIMIT 1',[$hash]];
    if(in_array($family,['r','s'],true))$queries[]=["SELECT JSON_UNQUOTE(JSON_EXTRACT(g.identity_json,'$.module')) module,JSON_EXTRACT(g.identity_json,'$.reason') reason_json FROM security_event_groups g WHERE ".fg_identity_scope('g')." AND ".block_reason_hash_sql("JSON_UNQUOTE(JSON_EXTRACT(g.identity_json,'$.module'))","JSON_EXTRACT(g.identity_json,'$.reason')").'=? LIMIT 1',[$hash]];
    if(in_array($family,['r','a'],true)){
        $membership=$family==='a'?' JOIN av_event_groups am ON am.event_id=e.id':'';$json=antivirus_reason_sql('e');
        $queries[]=["SELECT e.subtype module,$json reason_json FROM events e FORCE INDEX(current_policy_cover) $membership WHERE ".fg_event_scope('e')." AND e.type='utm' AND e.subtype='virus' AND e.outcome='security_block' AND ".block_reason_hash_sql('e.subtype',$json).'=? LIMIT 1',[$hash]];
    }
    foreach($queries as [$sql,$args]){if($row=query($sql,$args)[0]??null)return reason_descriptor($ref,$row['module'],$row['reason_json']);}
    if($family==='r'){
        $parts=reason_member_sources($ref,'1000-01-01 00:00:00.000000','9999-12-31 23:59:59.999999');
        $row=query("SELECT e.subtype module,".source_reason_sql('e')." reason_json FROM (".$parts['other_sql'].") ids STRAIGHT_JOIN events e ON e.id=ids.id LIMIT 1",$parts['other_args'])[0]??null;
        if($row)return reason_descriptor($ref,$row['module'],$row['reason_json']);
    }
    return ['reference'=>$ref,'module'=>'','label'=>'Kayıt bulunmayan gerekçe','reason_code'=>'','details'=>(object)[],'known'=>false];
}
/** Build exact native traffic and original-event candidates for all investigation filters. */
function reason_record_parts(string $where,array $args,string $ref): array {
    [$from,$to]=scope();$parts=reason_member_sources($ref,$from,$to);$tw=[$parts['traffic_where']];$tp=$parts['traffic_args'];
    foreach(['source'=>'g.srcip','policy'=>'g.policyid','profile'=>'m.profile','module'=>'g.subtype','reason'=>'g.reason_code'] as $param=>$column){
        if(($_GET[$param]??'')==='')continue;$tw[]="$column=?";$tp[]=$_GET[$param];
        if($param==='profile'){$tw[]='BINARY m.profile=BINARY ?';$tp[]=$_GET[$param];}
    }
    if(($_GET['source_missing']??'')==='1')$tw[]="g.srcip=''";
    if(($_GET['profile_missing']??'')==='1')$tw[]="m.profile=''";
    if(($_GET['policy_scope']??'')!=='')$tw[]='g.subtype'.($_GET['policy_scope']==='local'?"='local'":"<>'local'");
    $outcome=$_GET['outcome']??'';
    if(in_array($outcome,['policy_deny','local_deny'],true)){$tw[]='g.outcome=?';$tp[]=$outcome;}
    elseif(!in_array($outcome,['','all_blocks'],true))$tw[]='0';
    if($ref[0]==='r' && ($native=block_reason_filter())){
        if($native[0]!=='t')$tw[]='0';else{$tw[]=block_reason_hash_sql('g.subtype',"JSON_EXTRACT(g.identity_json,'$.reason')").'=?';$tp[]=$native[1];}
    }
    $trafficFrom="FROM traffic_groups g STRAIGHT_JOIN traffic_event_groups m FORCE INDEX(summary_cover) ON m.group_key=g.group_key WHERE ".implode(' AND ',$tw);
    $joins=[];$keys=[];$kinds=[];
    foreach(['av'=>['av_event_groups','a','group_av'],'security'=>['security_event_groups','s','group_security'],'traffic'=>['traffic_event_groups','t','group_traffic']] as $kind=>[$table,$prefix,$flag]){
        if(($_GET[$flag]??'0')!=='1')continue;$joins[]="LEFT JOIN $table rx_$prefix ON rx_$prefix.event_id=e.id";$keys[]="WHEN rx_$prefix.event_id IS NOT NULL THEN CONCAT('$prefix:',HEX(rx_$prefix.group_key))";$kinds[]="WHEN rx_$prefix.event_id IS NOT NULL THEN '$kind'";
    }
    $key=$keys?'CASE '.implode(' ',$keys)." ELSE CONCAT('event:',e.id) END":"CONCAT('event:',e.id)";$kind=$kinds?'CASE '.implode(' ',$kinds).' ELSE NULL END':'NULL';
    $other="SELECT e.id,e.event_at,$key group_key,$kind group_kind FROM (".$parts['other_sql'].") ids STRAIGHT_JOIN events e ON e.id=ids.id ".implode(' ',$joins)." WHERE $where";
    return ['traffic_from'=>$trafficFrom,'traffic_args'=>$tp,'other_sql'=>$other,'other_args'=>array_merge($parts['other_args'],$args),'grouped'=>($_GET['group_traffic']??'0')==='1'||(bool)$joins];
}
function reason_event_candidates(string $where,array $args,int $size,int $offset): array {
    $parts=reason_record_parts($where,$args,reason_request_ref());$from=$parts['traffic_from'];$last="CONCAT(DATE_FORMAT(m.event_at,'%Y%m%d%H%i%s%f'),LPAD(m.event_id,20,'0'))";
    $traffic=($_GET['group_traffic']??'0')==='1'?"SELECT MAX($last) last_record,'traffic' group_kind,COUNT(*) matched_records,MIN(m.event_at) first_event_at,MAX(m.event_at) last_event_at $from GROUP BY m.group_key":"SELECT $last last_record,NULL group_kind,1 matched_records,m.event_at first_event_at,m.event_at last_event_at $from";
    $other="SELECT MAX(CONCAT(DATE_FORMAT(event_at,'%Y%m%d%H%i%s%f'),LPAD(id,20,'0'))) last_record,group_kind,COUNT(*) matched_records,MIN(event_at) first_event_at,MAX(event_at) last_event_at FROM (".$parts['other_sql'].") matched GROUP BY group_key,group_kind";
    $cte="WITH stats AS ($traffic UNION ALL $other) ";$params=array_merge($parts['traffic_args'],$parts['other_args']);
    $counts=query($cte.'SELECT COUNT(*) total,COALESCE(SUM(matched_records),0) total_records FROM stats',$params)[0];
    $rows=$size?query($cte."SELECT CAST(RIGHT(last_record,20) AS UNSIGNED) id,group_kind,matched_records,first_event_at,last_event_at FROM stats ORDER BY last_event_at DESC,id DESC LIMIT $size OFFSET $offset",$params):[];
    return ['keys'=>$rows,'total'=>(int)$counts['total'],'total_records'=>(int)$counts['total_records'],'grouped'=>$parts['grouped']];
}
