<?php
declare(strict_types=1);

function vpn_value(mixed $v): string {
    $v=trim((string)($v??''));return in_array(strtolower($v),['','n/a','none','unknown','-','(null)'],true)?'':$v;
}
function vpn_identity(array $f): array {
    foreach(['eapuser','xauthuser','user','useralt'] as $field){
        $value=vpn_value($f[$field]??'');
        if($value!=='' && !filter_var($value,FILTER_VALIDATE_IP))return ['username'=>$value,'identity_field'=>$field,'identity_type'=>'user'];
    }
    return ['username'=>'','identity_field'=>'','identity_type'=>'unidentified'];
}
function vpn_type(array $f): string {
    $explicit=strtolower((string)($f['tunneltype']??''));if(str_starts_with($explicit,'ipsec'))return 'ipsec';if(str_starts_with($explicit,'ssl'))return 'ssl';
    $text=strtolower(($f['tunneltype']??'').' '.($f['logdesc']??'').' '.($f['msg']??''));
    return str_contains($text,'ipsec')?'ipsec':(str_contains($text,'ssl')?'ssl':'other');
}
function vpn_stamp(float $t): string { return DateTimeImmutable::createFromFormat('U.u',sprintf('%.6F',$t))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u'); }
function vpn_epoch(string $t): float { return (float)(new DateTimeImmutable($t,new DateTimeZone('UTC')))->format('U.u'); }
function vpn_union_seconds(array $intervals): int {
    usort($intervals,fn($a,$b)=>$a[0]<=>$b[0]);$total=0;$current=null;
    foreach($intervals as [$a,$b]){if($b<=$a)continue;if($current && $a<=$current[1])$current[1]=max($b,$current[1]);else{if($current)$total+=$current[1]-$current[0];$current=[$a,$b];}}
    if($current)$total+=$current[1]-$current[0];return (int)floor($total+0.00001);
}

/** Missing optional identity fields are not contradictions; populated different fields are. */
function vpn_connection_compatible(array $session,array $identity,string $assignedIp,string $clientUid): bool {
    foreach([[$session['username'],$identity['username']],[$session['assigned_ip'],$assignedIp],[$session['fctuid'],$clientUid]] as [$known,$incoming]){
        if($known!=='' && $incoming!=='' && $known!==$incoming)return false;
    }
    return true;
}

/** Pair proof records over the whole available history before clipping to the requested interval. */
function vpn_model(array $events,float $from,float $to,array $filter=[]): array {
    usort($events,fn($a,$b)=>strcmp($a['event_at'],$b['event_at'])?:((int)$a['id']<=>(int)$b['id']));
    $sessions=[];$active=[];$seen=[];
    foreach($events as $event){
        $f=is_array($event['fields'])?$event['fields']:json_decode($event['fields'],true,512,JSON_THROW_ON_ERROR);$action=$f['action']??'';
        if(!in_array($action,['tunnel-up','tunnel-down','tunnel-stats'],true))continue;
        $t=vpn_epoch($event['event_at']);$identity=vpn_identity($f);$type=vpn_type($f);$id=vpn_value($f['tunnelid']??'');$complete=$id!==''&&$id!=='0';
        $parts=[vpn_value($f['devid']??''),vpn_value($f['vd']??''),vpn_value($f['tunneltype']??$type),$id,vpn_value($f['vpntunnel']??''),vpn_value($f['remip']??'')];$complete=$complete&&$parts[0]!==''&&$parts[1]!=='';
        $baseKey=hash('sha256',json_encode($parts,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR));
        if(!$complete)$baseKey='event:'.$event['id'];
        $cookies=vpn_value($f['cookies']??'');$clientUid=vpn_value($f['fctuid']??'');
        $assignedIp=vpn_value($f['tunnelip']??'')?:vpn_value($f['assignip']??'');
        $key=$baseKey.'|'.$cookies;
        $duration=isset($f['duration']) && preg_match('/^\d+$/D',(string)$f['duration'])?(float)$f['duration']:null;
        $inferred=$duration!==null && $t-$duration>=946684800?$t-$duration:null;
        $duplicate=hash('sha256',json_encode([$key,$event['event_at'],$action,$duration,$identity['username'],$assignedIp,$clientUid],JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR));
        if(isset($seen[$duplicate]))continue;$seen[$duplicate]=true;
        $candidates=$active[$baseKey]??[];$associationAmbiguous=false;
        $index=$cookies!==''?($candidates[$cookies]??null):null;
        if($index!==null && !vpn_connection_compatible($sessions[$index],$identity,$assignedIp,$clientUid))$index=null;
        // A FortiGate tunnel-down may omit cookies. Match only one compatible association;
        // never let that omission close an arbitrary concurrent IKE association.
        if($index===null && ($cookies==='' || isset($candidates['']))){
            $matches=[];
            foreach($candidates as $candidateCookie=>$candidate){
                $s=$sessions[$candidate];
                if($cookies!=='' && $candidateCookie!=='')continue;
                if($s['ended_at_epoch']!==null && $t>$s['ended_at_epoch']+2)continue;
                if(vpn_connection_compatible($s,$identity,$assignedIp,$clientUid))$matches[$candidate]=$candidate;
            }
            if(count($matches)===1)$index=array_values($matches)[0];
            elseif(count($matches)>1)$associationAmbiguous=true;
        }
        $new=$index===null;
        if(!$new){
            $s=$sessions[$index];
            $new=($s['ended_at_epoch']!==null && $t>$s['ended_at_epoch']+2)
                ||($action==='tunnel-up' && $s['up_epoch']!==null && $t>$s['up_epoch']+2)
                ||($identity['username']!=='' && $s['username']!=='' && $identity['username']!==$s['username'])
                // A newer inferred start contradicts the old association even if its
                // previous counter was zero. Do not stretch a missing reconnect.
                ||($s['start_basis']!=='unknown' && $inferred!==null && $inferred>$s['start_epoch']+5);
        }
        if($new){
            $index=count($sessions);
            $sessions[]=$identity+['key'=>$key.':'.$event['id'],'device'=>$parts[0],'vdom'=>$parts[1],'type'=>$type,'tunnel_type'=>$parts[2],'tunnel_id'=>$id,'tunnel_name'=>$parts[4],'remote_ip'=>$parts[5],
                'assigned_ip'=>$assignedIp,'cookies'=>$cookies,'fctuid'=>$clientUid,'logid'=>'','last_action'=>'','complete_key'=>$complete,'association_ambiguous'=>$associationAmbiguous,'up_epoch'=>null,'start_epoch'=>$inferred??$t,'start_basis'=>$inferred!==null?'duration':'unknown','ended_at_epoch'=>null,'last_epoch'=>$t,'last_duration'=>null,'event_id'=>(int)$event['id'],'records'=>0];
        }
        $s=&$sessions[$index];
        if($s['cookies']==='' && $cookies!==''){$s['cookies']=$cookies;unset($active[$baseKey]['']);}
        if($s['assigned_ip']==='' && $assignedIp!=='')$s['assigned_ip']=$assignedIp;
        if($s['fctuid']==='' && $clientUid!=='')$s['fctuid']=$clientUid;
        // Unresolved evidence must not become a new matching association. A later
        // event with an assigned IP or client UID may identify one real candidate.
        if(!$s['association_ambiguous'])$active[$baseKey][$s['cookies']]=$index;
        if($identity['username']!=='' && $s['username']===''){$s['username']=$identity['username'];$s['identity_field']=$identity['identity_field'];$s['identity_type']='user';}
        if($action==='tunnel-up'){$s['up_epoch']=$t;$s['start_epoch']=$t;$s['start_basis']='up';}
        elseif($s['up_epoch']===null && $inferred!==null){$s['start_epoch']=min($s['start_epoch'],$inferred);$s['start_basis']='duration';}
        if($action==='tunnel-down')$s['ended_at_epoch']=$t;
        $s['last_epoch']=max($s['last_epoch'],$t);if($duration!==null)$s['last_duration']=$duration;
        $s['event_id']=(int)$event['id'];$s['logid']=vpn_value($f['logid']??'');$s['last_action']=$action;$s['records']++;unset($s);
    }
    $rows=[];$users=[];$intervals=[];$unidentified=0;$incomplete=0;
    foreach($sessions as &$s){
        $start=$s['start_epoch'];$end=$s['ended_at_epoch']??$s['last_epoch'];
        if($start>=$to || $end<$from || ($end===$from && $end>$start))continue;
        if(($filter['vpn_user']??'')!=='' && $s['username']!==$filter['vpn_user'])continue;
        if(($filter['vpn_peer']??'')!=='' && $s['remote_ip']!==$filter['vpn_peer'])continue;
        if(($filter['vpn_type']??'')!=='' && $s['type']!==$filter['vpn_type'])continue;
        $a=max($from,$start);$b=min($to,$end);$seconds=(int)floor(max(0,$b-$a)+.00001);$closed=$s['ended_at_epoch']!==null;
        $s['start_at']=vpn_stamp($start);$s['end_at']=$closed?vpn_stamp($end):null;$s['last_seen_at']=vpn_stamp($s['last_epoch']);
        $s['range_seconds']=$s['start_basis']==='unknown'&&$end===$start?null:$seconds;$s['start_inferred']=$s['start_basis']==='duration';$s['status']=$closed?'closed':($end>$start?'last_evidence':'start_only');
        $s['total_seconds']=$s['start_basis']==='unknown'?null:(int)floor(max(0,$end-$start)+.00001);
        $s['carried_over']=$start<$from;$s['closed']=$closed;$s['evidence_end_at']=$s['last_seen_at'];
        $s['range_start_at']=vpn_stamp($a);$s['range_end_at']=vpn_stamp(max($a,$b));
        if(!$closed)$incomplete++;if($s['username']==='')$unidentified++;
        $userKey=$s['username']!==''?'user:'.$s['username']:'unidentified:'.$s['device'].':'.$s['vdom'].':'.$s['tunnel_name'].':'.$s['remote_ip'];
        if(!isset($users[$userKey]))$users[$userKey]=['username'=>$s['username'],'label'=>$s['username']?:'Kimlik yok · '.($s['tunnel_name']?:$s['remote_ip']),'identity_type'=>$s['identity_type'],'sessions'=>0,'incomplete_sessions'=>0,'seconds'=>0,'last_seen_at'=>$s['last_seen_at']];
        $u=&$users[$userKey];$u['sessions']++;if(!$closed)$u['incomplete_sessions']++;$u['last_seen_at']=max($u['last_seen_at'],$s['last_seen_at']);unset($u);
        $intervals[$userKey][]=[$a,$b];unset($s['up_epoch'],$s['start_epoch'],$s['ended_at_epoch'],$s['last_epoch'],$s['last_duration']);$rows[]=$s;
    }
    unset($s,$sessions);$totalSeconds=0;$identifiedUsers=0;
    foreach($users as $key=>&$u){$u['seconds']=vpn_union_seconds($intervals[$key]);if($u['identity_type']==='user'){$identifiedUsers++;$totalSeconds+=$u['seconds'];}}unset($u);
    usort($users,fn($a,$b)=>($b['seconds']<=>$a['seconds'])?:strcmp($a['label'],$b['label']));
    usort($rows,fn($a,$b)=>strcmp($b['last_seen_at'],$a['last_seen_at'])?:($b['event_id']<=>$a['event_id']));
    return ['users'=>array_values($users),'sessions'=>$rows,'totals'=>['users'=>$identifiedUsers,'sessions'=>count($rows),'user_seconds'=>$totalSeconds,'incomplete_sessions'=>$incomplete,'unidentified_sessions'=>$unidentified]];
}

function vpn_username_sql(string $alias='e'): string {
    $parts=[];
    foreach(['eapuser','xauthuser','user','useralt'] as $k){$v="TRIM(JSON_UNQUOTE(JSON_EXTRACT($alias.fields,'$.$k')))";$parts[]="CASE WHEN LOWER($v) NOT IN ('','n/a','none','unknown','-','(null)') AND INET6_ATON($v) IS NULL THEN $v END";}
    return 'COALESCE('.implode(',',$parts).',\'\')';
}
function vpn_report(): array {
    [$from,$to]=scope();$filters=[];
    foreach(['vpn_user'=>256,'vpn_peer'=>45,'vpn_type'=>16] as $key=>$max){$v=$_GET[$key]??'';if(!is_string($v)||!mb_check_encoding($v,'UTF-8')||mb_strlen($v)>$max)throw new InvalidArgumentException('VPN filtresi geçersiz.');$filters[$key]=trim($v);}
    if($filters['vpn_peer']!=='' && !filter_var($filters['vpn_peer'],FILTER_VALIDATE_IP))throw new InvalidArgumentException('Geçerli bir uzak IP girin.');
    if(!in_array($filters['vpn_type'],['','ipsec','ssl','other'],true))throw new InvalidArgumentException('VPN türü geçersiz.');
    $fields=[];foreach(['devid','vd','action','tunneltype','tunnelid','vpntunnel','remip','duration','eapuser','xauthuser','user','useralt','tunnelip','assignip','msg','logdesc','logid','cookies','fctuid'] as $field){$fields[]="'$field',JSON_UNQUOTE(JSON_EXTRACT(fields,'$.$field'))";}
    $context=query("SELECT id,event_at,JSON_OBJECT(".implode(',',$fields).") fields FROM events e FORCE INDEX(module_time) WHERE ".fg_event_scope('e')." AND subtype='vpn' AND action IN ('tunnel-up','tunnel-down','tunnel-stats') AND event_at<=UTC_TIMESTAMP(6) ORDER BY event_at,id LIMIT 50001");
    if(count($context)>50000)throw new InvalidArgumentException('VPN oturum geçmişi bu sürümün sınırını aştı; rapor indeksinin genişletilmesi gerekiyor.');
    $model=vpn_model($context,vpn_epoch($from),vpn_epoch($to),$filters);$names=[];
    foreach($context as $e){$f=json_decode($e['fields'],true);$u=vpn_identity($f)['username'];if($u!=='')$names[$u]=true;}ksort($names);
    $where=fg_event_scope('e')." AND e.subtype='vpn' AND e.event_at>=? AND e.event_at<?";$args=[$from,$to];
    if($filters['vpn_user']!==''){$where.=' AND BINARY '.vpn_username_sql().'=BINARY ?';$args[]=$filters['vpn_user'];}
    if($filters['vpn_peer']!==''){$where.=" AND JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.remip'))=?";$args[]=$filters['vpn_peer'];}
    if($filters['vpn_type']!==''){
        $text="LOWER(CONCAT_WS(' ',JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.tunneltype')),JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.logdesc')),JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.msg'))))";
        $explicit="LOWER(JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.tunneltype')))";
        $where.=" AND CASE WHEN $explicit LIKE 'ipsec%' THEN 'ipsec' WHEN $explicit LIKE 'ssl%' THEN 'ssl' WHEN $text LIKE '%ipsec%' THEN 'ipsec' WHEN $text LIKE '%ssl%' THEN 'ssl' ELSE 'other' END=?";$args[]=$filters['vpn_type'];
    }
    $logsTotal=(int)query("SELECT COUNT(*) n FROM events e FORCE INDEX(module_time) WHERE $where",$args)[0]['n'];
    $page=max(1,min(1000,(int)($_GET['vpn_page']??1)));$logPage=max(1,min(100000,(int)($_GET['vpn_log_page']??1)));$offset=($logPage-1)*50;
    $logs=query("SELECT e.id,e.event_at,e.action,e.fields FROM events e FORCE INDEX(module_time) WHERE $where ORDER BY e.event_at DESC,e.id DESC LIMIT 50 OFFSET $offset",$args);
    foreach($logs as &$e){$f=json_decode($e['fields'],true);$e+=vpn_identity($f);$e['remote_ip']=vpn_value($f['remip']??'');$e['type']=vpn_type($f);$e['tunnel_name']=vpn_value($f['vpntunnel']??'');$e['message']=implode(' · ',array_unique(array_filter([$f['status']??'',$f['reason']??'',$f['msg']??''])));unset($e['fields']);}unset($e);
    // These timestamps describe the selected device's data coverage, independently of
    // the report range. received_at belongs to the latest event, not the latest arrival.
    $lastVpn=query("SELECT e.event_at FROM events e FORCE INDEX(module_time) WHERE ".fg_event_scope('e')." AND e.subtype='vpn' AND e.event_at<=UTC_TIMESTAMP(6) ORDER BY e.event_at DESC,e.id DESC LIMIT 1")[0]??null;
    $lastEvent=query("SELECT e.event_at,e.received_at FROM events e FORCE INDEX(device_time) WHERE ".fg_event_scope('e')." AND e.event_at<=UTC_TIMESTAMP(6) ORDER BY e.event_at DESC,e.id DESC LIMIT 1")[0]??null;
    require_once __DIR__.'/maintenance.php';
    $dataStatus=['last_vpn_event_at'=>$lastVpn['event_at']??null,'last_ingested_event_at'=>$lastEvent['event_at']??null,'last_ingested_received_at'=>$lastEvent['received_at']??null,'ingested_timestamp_basis'=>'latest_event','maintenance'=>maintenance_snapshot(true)];
    return ['scope'=>['from_utc'=>$from,'to_utc'=>$to],'totals'=>$model['totals'],'users'=>$model['users'],'user_options'=>array_keys($names),'sessions'=>array_slice($model['sessions'],($page-1)*50,50),'page'=>$page,'page_size'=>50,'logs'=>$logs,'log_total'=>$logsTotal,'log_page'=>$logPage,'context_records'=>count($context),'data_status'=>$dataStatus];
}
