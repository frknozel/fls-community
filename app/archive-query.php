<?php
declare(strict_types=1);

/** A committed watermark and an original-event tail form one exact snapshot. */
function archive_watermark(): ?int {
    if(PHP_SAPI==='cli' && defined('FLS_ARCHIVE_QUERIES_DISABLED') && FLS_ARCHIVE_QUERIES_DISABLED)return null;
    try{$r=query('SELECT event_id,ready FROM archive_index_state WHERE id=1 AND version=3')[0]??null;}
    catch(PDOException $e){if($e->getCode()==='42S02')return null;throw $e;}
    if(!$r || !$r['ready'])return null;
    // A stopped worker must degrade to the original queries, not an unbounded raw tail.
    $last=(int)(query('SELECT id FROM events ORDER BY id DESC LIMIT 1')[0]['id']??0);
    return (int)$r['event_id']<=$last && $last-(int)$r['event_id']<=10000?(int)$r['event_id']:null;
}
function archive_raw_projection(): string {
    return "e.id event_id,e.event_at,e.devid,e.vd,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,e.reason_code,".
        "CASE WHEN sm.event_id IS NOT NULL THEN 's' WHEN tm.event_id IS NOT NULL THEN 't' WHEN am.event_id IS NOT NULL THEN 'a' ELSE '' END family,".
        "COALESCE(sm.group_key,tm.group_key,am.group_key) group_key,".source_target_sql('e')." target_json,".source_reason_sql('e').' reason_json';
}
function archive_raw_joins(): string {
    return 'LEFT JOIN security_event_groups sm ON sm.event_id=e.id LEFT JOIN traffic_event_groups tm ON tm.event_id=e.id LEFT JOIN av_event_groups am ON am.event_id=e.id';
}
function archive_dimension_filter(array $filters,string $alias='d'): array {
    $w=[fg_event_scope($alias)];$a=[];
    foreach(['source'=>'srcip','policy'=>'policyid','profile'=>'profile','module'=>'subtype','reason'=>'reason_code','outcome'=>'outcome'] as $param=>$column){
        $v=$filters[$param]??'';if($v==='')continue;
        if($param==='outcome' && $v==='all_blocks')continue;
        $w[]="$alias.$column=?";$a[]=$v;
        if($param==='profile'){$w[]="BINARY $alias.profile=BINARY ?";$a[]=$v;}
    }
    foreach(['source_missing'=>'srcip','profile_missing'=>'profile'] as $param=>$column)if(($filters[$param]??'')==='1')$w[]="$alias.$column=''";
    if(($filters['policy_scope']??'')!=='')$w[]="$alias.subtype".($filters['policy_scope']==='local'?"='local'":"<>'local'");
    foreach(['target_key'=>'target_key','source_reason'=>'reason_key'] as $param=>$column)if(($filters[$param]??'')!==''){$w[]="$alias.$column=UNHEX(?)";$a[]=$filters[$param];}
    if(($filters['block_reason']??'')!==''){
        $w[]="$alias.family=? AND $alias.reason_key=UNHEX(?)";$a[]=$filters['block_reason'][0];$a[]=substr($filters['block_reason'],2);
    }
    return [$w?implode(' AND ',$w):'1',$a];
}
function archive_tail(int $watermark,string $from,string $to): array {
    $raw=archive_raw_projection();$joins=archive_raw_joins();
    return ["SELECT original.*,UNHEX(SHA2(original.target_json,256)) target_key,UNHEX(SHA2(CONCAT(original.subtype,'|',original.reason_json),256)) reason_key FROM (SELECT $raw FROM events e FORCE INDEX(PRIMARY) $joins WHERE e.id>? AND e.event_at>=? AND e.event_at<? AND e.outcome IN ('security_block','policy_deny','local_deny')) original",[$watermark,$from,$to]];
}
/** Broad fractional-hour edges start with time, not every historical dimension. */
function archive_edge_from(array $filters): string {
    // Forward/local scope alone still covers many dimensions and is filtered
    // after the time range. Treat only identity/detail filters as selective.
    foreach(['source','policy','profile','module','reason','target_key','source_reason','block_reason','source_missing','profile_missing'] as $key)
        if(($filters[$key]??'')!=='')return 'archive_dimensions d STRAIGHT_JOIN archive_event_index f FORCE INDEX(dimension_time) ON f.dimension_id=d.id';
    return 'archive_event_index f FORCE INDEX(event_time) STRAIGHT_JOIN archive_dimensions d ON d.id=f.dimension_id';
}
/** Whole UTC hours use compact counts; fractional edges use narrow per-event indexes. */
function archive_summary_query(array $filters,string $from,string $to,int $watermark,bool $nativeOnly=false,bool $countsOnly=false,?callable $restrict=null): array {
    [$w,$args]=archive_dimension_filter($filters);if($nativeOnly)$w.=" AND d.family<>''";
    if($restrict){[$extra,$values]=$restrict('d');$w.=' AND ('.$extra.')';array_push($args,...$values);}
    $start=new DateTimeImmutable($from,new DateTimeZone('UTC'));$end=new DateTimeImmutable($to,new DateTimeZone('UTC'));
    $floorStart=$start->setTime((int)$start->format('H'),0);$ceil=$start==$floorStart?$start:$floorStart->modify('+1 hour');$floorEnd=$end->setTime((int)$end->format('H'),0);
    $parts=[];$params=[];
    if($ceil<$floorEnd){
        $parts[]="SELECT h.dimension_id,SUM(h.records) n,MIN(h.first_event_at) first_event_at,MAX(h.last_event_at) last_event_at FROM archive_dimensions d STRAIGHT_JOIN archive_hour_counts h ON h.dimension_id=d.id WHERE $w AND h.hour_at>=? AND h.hour_at<? GROUP BY h.dimension_id";
        $params=array_merge($params,$args,[$ceil->format('Y-m-d H:i:s.u'),$floorEnd->format('Y-m-d H:i:s.u')]);
        $edges=[[$from,$ceil->format('Y-m-d H:i:s.u')],[$floorEnd->format('Y-m-d H:i:s.u'),$to]];
    }else $edges=[[$from,$to]];
    foreach($edges as [$a,$b])if($a<$b){
        $parts[]="SELECT f.dimension_id,COUNT(*) n,MIN(f.event_at) first_event_at,MAX(f.event_at) last_event_at FROM ".archive_edge_from($filters)." WHERE $w AND f.event_at>=? AND f.event_at<? GROUP BY f.dimension_id";
        $params=array_merge($params,$args,[$a,$b]);
    }
    $buckets=implode(' UNION ALL ',$parts);
    // Aggregate narrow numeric/time buckets before joining TEXT identities;
    // joining the JSON first forces a disk temporary table for every broad view.
    $aggregated="SELECT dimension_id,SUM(n) n,MIN(first_event_at) first_event_at,MAX(last_event_at) last_event_at FROM ($buckets) buckets GROUP BY dimension_id";
    $indexed="SELECT d.target_json,d.reason_json,d.srcip,d.policyid,d.profile,d.subtype,d.outcome,d.reason_code,d.family reason_family,NULL group_key,b.n,b.first_event_at,b.last_event_at FROM ($aggregated) b JOIN archive_dimensions d ON d.id=b.dimension_id";
    if($countsOnly)$indexed="SELECT COALESCE(SUM(b.n),0) n FROM ($buckets) b";
    [$tail,$tailArgs]=archive_tail($watermark,$from,$to);[$tw,$ta]=archive_dimension_filter($filters,'t');if($nativeOnly)$tw.=" AND t.family<>''";
    if($restrict){[$extra,$values]=$restrict('t');$tw.=' AND ('.$extra.')';array_push($ta,...$values);}
    $tailSource=$tail;
    $tail="SELECT t.target_json,t.reason_json,t.srcip,t.policyid,t.profile,t.subtype,t.outcome,t.reason_code,t.family reason_family,NULL group_key,COUNT(*) n,MIN(t.event_at) first_event_at,MAX(t.event_at) last_event_at FROM ($tail) t WHERE $tw GROUP BY t.target_key,t.reason_key,t.srcip,t.policyid,BINARY t.profile,t.subtype,t.outcome,t.family";
    if($countsOnly)$tail="SELECT COUNT(*) n FROM (".$tailSource.") t WHERE $tw";
    return ["$indexed UNION ALL $tail",array_merge($params,$tailArgs,$ta)];
}
function archive_investigation_queries(string $mode,string $kind,string $from,string $to): ?array {
    $watermark=archive_watermark();if($watermark===null)return null;
    $filters=['outcome'=>['all'=>'all_blocks','security'=>'security_block','policy'=>'policy_deny','local'=>'local_deny'][$kind]];
    if($mode==='source')$filters['source']=$_GET['source_ip'];
    elseif($mode==='target')$filters['target_key']=$_GET['target_key'];
    elseif($mode==='policy')$filters+=['policy'=>$_GET['policy_id'],'policy_scope'=>$_GET['policy_scope']??'forward'];
    elseif($mode==='profile'){$filters['profile']=$_GET['profile_name'];if(($_GET['profile_module']??'all')!=='all')$filters['module']=$_GET['profile_module'];}
    else{$ref=investigation_reason_ref();$filters[$ref[0]==='r'?'source_reason':'block_reason']=$ref[0]==='r'?substr($ref,2):$ref;}
    [$sql,$args]=archive_summary_query($filters,$from,$to,$watermark);
    // Preserve existing link families in source/profile versus target/policy summaries.
    if(in_array($mode,['source','profile'],true))$sql=str_replace(['d.family reason_family','t.family reason_family'],'NULL reason_family',$sql);
    return [[$sql,$args]];
}
function archive_events_available(): bool {
    return ($_GET['q']??'')==='' && ($_GET['reason']??'')!=='rating_error' && in_array($_GET['outcome']??'',['all_blocks','security_block','policy_deny','local_deny'],true) && archive_watermark()!==null;
}
/** Native binary group keys avoid a million-row textual CTE and a second self join. */
function archive_event_candidates(int $size,int $offset): array {
    [$from,$to]=scope();$watermark=archive_watermark();[$w,$args]=archive_dimension_filter($_GET);
    [$summary,$summaryArgs]=archive_summary_query($_GET,$from,$to,$watermark,false,true);
    $originals=(int)query("SELECT COALESCE(SUM(n),0) n FROM ($summary) counts",$summaryArgs)[0]['n'];
    $enabled=[];foreach(['a'=>'group_av','s'=>'group_security','t'=>'group_traffic'] as $family=>$flag)if(($_GET[$flag]??'0')==='1')$enabled[]="'$family'";
    [$tail,$tailArgs]=archive_tail($watermark,$from,$to);[$tw,$ta]=archive_dimension_filter($_GET,'d');
    $groupedRecords=0;$groupedCount=0;$keys=[];$limit=$offset+$size;
    if($enabled && $originals){
        [$stats,$params]=archive_native_stats($_GET,$from,$to,$watermark,$enabled);
        if($size===0){$r=query("SELECT COUNT(*) total,COALESCE(SUM(matched_records),0) records FROM ($stats) stats",$params)[0];$groupedCount=(int)$r['total'];$groupedRecords=(int)$r['records'];}
        else{
            $rows=query("SELECT CAST(RIGHT(last_record,20) AS UNSIGNED) id,CASE family WHEN 'a' THEN 'av' WHEN 's' THEN 'security' WHEN 't' THEN 'traffic' END group_kind,matched_records,first_event_at,last_event_at,COUNT(*) OVER() total,SUM(matched_records) OVER() total_records FROM ($stats) stats ORDER BY last_event_at DESC,id DESC LIMIT $limit",$params);
            if($rows){$groupedCount=(int)$rows[0]['total'];$groupedRecords=(int)$rows[0]['total_records'];foreach($rows as &$row)unset($row['total'],$row['total_records']);unset($row);$keys=$rows;}
        }
    }
    if($size>0 && $originals>$groupedRecords){
        $exclude=$enabled?'NOT (d.family IN ('.implode(',',$enabled).') AND f.group_key IS NOT NULL)':'1';
        // Broad ungrouped searches walk the date index and stop at the page bound.
        $factFrom=$originals-$groupedRecords>100000?"archive_event_index f FORCE INDEX(event_time) STRAIGHT_JOIN archive_dimensions d ON d.id=f.dimension_id":"archive_dimensions d STRAIGHT_JOIN archive_event_index f FORCE INDEX(dimension_time) ON f.dimension_id=d.id";
        $indexed="SELECT f.event_id id,f.event_at FROM $factFrom WHERE $w AND f.event_at>=? AND f.event_at<? AND $exclude ORDER BY f.event_at DESC,f.event_id DESC LIMIT $limit";
        $exclude=str_replace('f.group_key','d.group_key',$exclude);
        $pending="SELECT d.event_id id,d.event_at FROM ($tail) d WHERE $tw AND $exclude ORDER BY d.event_at DESC,d.event_id DESC LIMIT $limit";
        $raw=query("SELECT id,NULL group_kind,1 matched_records,event_at first_event_at,event_at last_event_at FROM (($indexed) UNION ALL ($pending)) candidates ORDER BY event_at DESC,id DESC LIMIT $limit",array_merge($args,[$from,$to],$tailArgs,$ta));
        $keys=array_merge($keys,$raw);
        usort($keys,fn($a,$b)=>strcmp($b['last_event_at'],$a['last_event_at'])?:((int)$b['id']<=>(int)$a['id']));
    }
    return ['keys'=>array_slice($keys,$offset,$size),'total'=>$groupedCount+$originals-$groupedRecords,'total_records'=>$originals,'grouped'=>(bool)$enabled];
}
/** Native group counts and pages share a compact rollup with exact boundary/tail records. */
function archive_native_stats(array $filters,string $from,string $to,int $watermark,array $families,bool $countsOnly=false): array {
    [$w,$args]=archive_dimension_filter($filters);$native="d.family IN (".implode(',',$families).")";
    $start=new DateTimeImmutable($from,new DateTimeZone('UTC'));$end=new DateTimeImmutable($to,new DateTimeZone('UTC'));
    $floor=$start->setTime((int)$start->format('H'),0);$ceil=$start==$floor?$start:$floor->modify('+1 hour');$last=$end->setTime((int)$end->format('H'),0);
    // Internal ASCII enums keep UNION/COUNT DISTINCT work rows narrow. Labels and original fields remain UTF-8.
    $identity='CAST(d.family AS CHAR(1) CHARACTER SET ascii) family,CAST(d.outcome AS CHAR(32) CHARACTER SET ascii) outcome';
    $parts=[];$params=[];
    if($ceil<$last){
        $columns=$countsOnly?$identity.',h.group_key':'d.family,d.outcome,h.group_key,h.records matched_records,h.first_event_at,h.last_event_at,h.last_record';
        $parts[]="SELECT $columns FROM archive_dimensions d STRAIGHT_JOIN archive_group_hours h ON h.dimension_id=d.id WHERE $w AND $native AND h.hour_at>=? AND h.hour_at<?";
        $params=array_merge($params,$args,[$ceil->format('Y-m-d H:i:s.u'),$last->format('Y-m-d H:i:s.u')]);
        $edges=[[$from,$ceil->format('Y-m-d H:i:s.u')],[$last->format('Y-m-d H:i:s.u'),$to]];
    }else $edges=[[$from,$to]];
    foreach($edges as [$a,$b])if($a<$b){
        $columns=$countsOnly?$identity.',f.group_key':"d.family,d.outcome,f.group_key,COUNT(*) matched_records,MIN(f.event_at) first_event_at,MAX(f.event_at) last_event_at,MAX(CONCAT(f.event_at,LPAD(f.event_id,20,'0'))) last_record";
        $parts[]="SELECT $columns FROM ".archive_edge_from($filters)." WHERE $w AND $native AND f.event_at>=? AND f.event_at<? AND f.group_key IS NOT NULL GROUP BY d.family,d.outcome,f.group_key";
        $params=array_merge($params,$args,[$a,$b]);
    }
    [$tail,$ta]=archive_tail($watermark,$from,$to);[$tw,$tp]=archive_dimension_filter($filters,'d');
    $columns=$countsOnly?$identity.',d.group_key':"d.family,d.outcome,d.group_key,COUNT(*) matched_records,MIN(d.event_at) first_event_at,MAX(d.event_at) last_event_at,MAX(CONCAT(d.event_at,LPAD(d.event_id,20,'0'))) last_record";
    $parts[]="SELECT $columns FROM ($tail) d WHERE $tw AND $native AND d.group_key IS NOT NULL GROUP BY d.family,d.outcome,d.group_key";
    $params=array_merge($params,$ta,$tp);
    if($countsOnly){
        return ['SELECT family,outcome,COUNT(DISTINCT group_key) n FROM ('.implode(' UNION ALL ',$parts).') buckets GROUP BY family,outcome',$params];
    }
    return ['SELECT family,outcome,group_key,SUM(matched_records) matched_records,MIN(first_event_at) first_event_at,MAX(last_event_at) last_event_at,MAX(last_record) last_record FROM ('.implode(' UNION ALL ',$parts).') buckets GROUP BY family,outcome,group_key',$params];
}
function archive_group_counts(array $filters,string $from,string $to,int $watermark): array {
    [$stats,$params]=archive_native_stats($filters,$from,$to,$watermark,["'a'","'s'","'t'"],true);
    return query($stats,$params);
}

/** Device rollups and the bounded raw tail share the same committed watermark. */
function archive_metric_source(string $from,string $to): ?array {
    $watermark=archive_watermark();if($watermark===null)return null;
    foreach(['q','source','source_missing','block_reason','target_key','source_reason'] as $key)if(($_GET[$key]??'')!=='')return null;
    $start=new DateTimeImmutable($from,new DateTimeZone('UTC'));$end=new DateTimeImmutable($to,new DateTimeZone('UTC'));
    $floor=$start->setTime((int)$start->format('H'),0);$ceil=$start==$floor?$start:$floor->modify('+1 hour');$last=$end->setTime((int)$end->format('H'),0);
    if($ceil>=$last)return null;
    [$hw,$hp]=conditions('h',true);$hp[0]=$ceil->format('Y-m-d H:i:s.u');$hp[1]=$last->format('Y-m-d H:i:s.u');
    $columns=['type','subtype','outcome','rating_error','policyid','profile','reason_code'];
    $parts=['SELECT h.hour_at,'.implode(',',array_map(fn($v)=>'h.'.$v,$columns)).",h.records FROM device_hourly_counts h WHERE $hw"];$params=$hp;
    foreach([[$from,$hp[0],false],[$hp[1],$to,false],[$hp[0],$hp[1],true]] as [$a,$b,$tail])if($a<$b){
        [$ew,$ep]=conditions('e');$ep[0]=$a;$ep[1]=$b;
        $parts[]="SELECT CAST(DATE_FORMAT(e.event_at,'%Y-%m-%d %H:00:00') AS DATETIME) hour_at,".implode(',',array_map(fn($v)=>'e.'.$v,$columns)).",1 records FROM events e ".($tail?'FORCE INDEX(PRIMARY)':'')." WHERE $ew".($tail?' AND e.id>?':'');$params=array_merge($params,$ep,$tail?[$watermark]:[]);
    }
    return [implode(' UNION ALL ',$parts),$params];
}

/** Reuse device-specific block buckets for broad dashboard rankings and hints. */
function archive_dashboard_blocks(string $from,string $to): ?array {
    if(($_GET['q']??'')!==''||in_array($_GET['reason']??'',['rating_error'],true)||!in_array($_GET['outcome']??'',['','all_blocks','security_block'],true))return null;
    $watermark=archive_watermark();if($watermark===null)return null;
    return archive_summary_query(array_replace($_GET,['outcome'=>'security_block']),$from,$to,$watermark);
}
