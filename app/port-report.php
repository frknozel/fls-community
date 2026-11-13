<?php
declare(strict_types=1);
require_once __DIR__.'/source-summary.php';

const PORT_CATEGORIES=['all'=>'Tüm portlar','transfer'=>'Dosya aktarımı','remote'=>'Uzaktan erişim','web'=>'Web','dns'=>'DNS','mail'=>'E-posta','database'=>'Veritabanı','infrastructure'=>'Ağ servisleri','other'=>'Diğer portlar','no_port'=>'Port bilgisi yok / portsuz'];
function port_integer(mixed $value,int $max): ?int {
    $v=is_int($value)?(string)$value:$value;
    return is_string($v)&&preg_match('/^[0-9]{1,5}$/D',$v)&&(int)$v<=$max?(int)$v:null;
}
function port_ip(string $ip): string {return ($packed=@inet_pton($ip))!==false?inet_ntop($packed):$ip;}
function port_filters(): array {
    $f=[];
    foreach(['source','target','number','proto','policy','category','denial'] as $key){
        $v=$_GET['port_'.$key]??'';
        if(!is_string($v)||strlen($v)>64)throw new InvalidArgumentException('Port inceleme filtresi geçersiz.');
        if(in_array($key,['source','target'],true)&&$v!==''){
            if($v!=='missing'&&!filter_var($v,FILTER_VALIDATE_IP))throw new InvalidArgumentException('Geçerli bir kaynak / hedef IP girin.');
            if($v!=='missing')$v=port_ip($v);
        }
        if(in_array($key,['number','proto'],true)&&$v!==''&&$v!=='missing'){
            $n=port_integer($v,$key==='number'?65535:255);if($n===null)throw new InvalidArgumentException('Port / protokol geçersiz.');$v=(string)$n;
        }
        if($key==='policy'&&$v!==''&&(!preg_match('/^(?:-1|0|[1-9][0-9]{0,9})$/D',$v)||(float)$v>2147483647))throw new InvalidArgumentException('Ret policy numarası geçersiz.');
        if($key==='category'&&!array_key_exists($v?:'all',PORT_CATEGORIES))throw new InvalidArgumentException('Port kategorisi geçersiz.');
        if($key==='denial'&&!in_array($v,['','all','implicit','explicit','unknown'],true))throw new InvalidArgumentException('Ret türü geçersiz.');
        $f[$key]=$v;
    }
    return $f;
}
/** A conventional port label never claims application identification. UDP/21 is not FTP. */
function port_service(?int $protocol,?int $port): array {
    if($port===null)return ['category'=>'no_port','service'=>'Port kullanılmıyor veya logda belirtilmemiş'];
    $tcp=[20=>['transfer','FTP veri'],21=>['transfer','FTP kontrol'],22=>['remote','SSH / SFTP'],23=>['remote','Telnet'],3389=>['remote','RDP'],5900=>['remote','VNC'],25=>['mail','SMTP'],110=>['mail','POP3'],143=>['mail','IMAP'],465=>['mail','SMTPS'],587=>['mail','SMTP gönderim'],993=>['mail','IMAPS'],995=>['mail','POP3S'],80=>['web','HTTP'],443=>['web','HTTPS'],8080=>['web','Alternatif HTTP'],8443=>['web','Alternatif HTTPS'],53=>['dns','DNS'],445=>['transfer','SMB'],139=>['transfer','NetBIOS oturumu'],1433=>['database','MS SQL'],3306=>['database','MySQL / MariaDB'],5432=>['database','PostgreSQL'],6379=>['database','Redis'],9200=>['database','Elasticsearch'],389=>['infrastructure','LDAP'],636=>['infrastructure','LDAPS']];
    $udp=[53=>['dns','DNS'],123=>['infrastructure','NTP'],67=>['infrastructure','DHCP sunucu'],68=>['infrastructure','DHCP istemci'],161=>['infrastructure','SNMP'],500=>['infrastructure','IKE'],4500=>['infrastructure','IPsec NAT-T'],443=>['web','QUIC'],3389=>['remote','RDP']];
    [$category,$name]=($protocol===6?$tcp:($protocol===17?$udp:[]))[$port]??['other','Özel / diğer port'];
    return ['category'=>$category,'service'=>$name];
}
function port_fact(array $identity,string $key,int $sample,int $records,string $first,string $last): array {
    $proto=port_integer($identity['protocol']??null,255);$port=in_array($proto,[6,17],true)?port_integer($identity['port']??null,65535):null;
    $pid=(string)($identity['policyid']??'-1');$policy=preg_match('/^(?:-1|[0-9]{1,10})$/D',$pid)&&(float)$pid<=2147483647?(int)$pid:-1;$type=$identity['policytype']??'';
    $denial=$policy===0&&in_array($type,['','policy','policy6'],true)?'implicit':($policy>0?'explicit':'unknown');
    $reason=$identity['reason']??[];$details=implode(' · ',array_unique(array_filter(array_intersect_key($reason,array_flip(['reason','error','msg'])),fn($v)=>is_string($v)&&$v!=='')));
    $label=['implicit'=>'Hiçbir izin kuralı eşleşmedi','explicit'=>'Firewall policy reddi','unknown'=>'Ret policy bilgisi belirsiz'][$denial];
    return ['key'=>$key,'sample_id'=>$sample,'records'=>$records,'first_event_at'=>$first,'last_event_at'=>$last,'source'=>port_ip($identity['source']??''),'target'=>port_ip($identity['target']??''),'protocol'=>$proto,'protocol_label'=>[6=>'TCP',17=>'UDP',1=>'ICMP',58=>'ICMPv6'][$proto]??($proto===null?'Protokol yok':'IP protokol '.$proto),'port'=>$port,'policyid'=>$policy,'poluuid'=>$identity['poluuid']??'','denial'=>$denial,'reason'=>$label,'reason_detail'=>$details,'source_interface'=>$identity['source_interface']??'','target_interface'=>$identity['target_interface']??'']+port_service($proto,$port);
}
function port_matches(array $r,array $f): bool {
    foreach(['source','target'] as $key)if($f[$key]!==''&&$r[$key]!==($f[$key]==='missing'?'':$f[$key]))return false;
    foreach(['number'=>'port','proto'=>'protocol'] as $key=>$column)if($f[$key]!==''&&($f[$key]==='missing'?$r[$column]!==null:$r[$column]===null||(string)$r[$column]!==$f[$key]))return false;
    if($f['policy']!==''&&(string)$r['policyid']!==$f['policy'])return false;
    if(!in_array($f['category'],['','all'],true)&&$r['category']!==$f['category'])return false;
    return in_array($f['denial'],['','all'],true)||$r['denial']===$f['denial'];
}
function port_raw_rows(string $from,string $to,array $filters): array {
    $w=fg_event_scope('e')." AND e.event_at>=? AND e.event_at<? AND e.type='traffic' AND e.subtype='forward' AND e.outcome='policy_deny'";$args=[$from,$to];
    foreach(['source'=>'srcip','policy'=>'policyid'] as $k=>$col)if($filters[$k]!==''&&$filters[$k]!=='missing'){$w.=" AND e.$col=?";$args[]=$filters[$k];}
    // Only denied forwarded traffic is read. Local-in and UTM blocks stay in their existing reports.
    return ["SELECT e.id,e.event_at,e.fields,HEX(m.group_key) native_key,g.identity_json FROM events e FORCE INDEX(outcome_time) LEFT JOIN traffic_event_groups m ON m.event_id=e.id LEFT JOIN traffic_groups g ON g.group_key=m.group_key WHERE $w",$args];
}
function port_raw_identity(array $f): array {
    return ['source'=>$f['srcip']??'','target'=>$f['dstip']??'','protocol'=>$f['proto']??'','port'=>$f['dstport']??'','policyid'=>$f['policyid']??'-1','poluuid'=>$f['poluuid']??'','policytype'=>$f['policytype']??'','source_interface'=>$f['srcintf']??'','target_interface'=>$f['dstintf']??'','reason'=>array_intersect_key($f,array_flip(['action','reason','error','msg']))];
}
function port_stream(string $sql,array $args): Generator {
    $pdo=db();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);$statement=null;
    try{$statement=$pdo->prepare($sql);$statement->execute($args);while($row=$statement->fetch())yield $row;}
    finally{if($statement)$statement->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
}
function port_report(bool $dashboard=false): array {
    [$from,$to]=scope();$filters=$dashboard?array_fill_keys(['source','target','number','proto','policy','category','denial'],''):port_filters();$page=$dashboard?1:port_page('port_page');$rows=[];$nativeRecords=0;
    $base=['outcome'=>'policy_deny','policy_scope'=>'forward'];
    foreach(['source','policy'] as $k)if($filters[$k]!==''&&$filters[$k]!=='missing')$base[$k]=$filters[$k];
    $wm=archive_watermark();$originals=null;
    if($wm!==null){
        [$sql,$args]=archive_summary_query($base,$from,$to,$wm,false,true);$originals=(int)query("SELECT COALESCE(SUM(n),0) n FROM ($sql) counts",$args)[0]['n'];
        if($originals){
            [$sql,$args]=archive_native_stats($base,$from,$to,$wm,["'t'"]);
            $sql="SELECT HEX(s.group_key) native_key,s.matched_records,s.first_event_at,s.last_event_at,CAST(RIGHT(s.last_record,20) AS UNSIGNED) sample_id,g.identity_json FROM ($sql) s JOIN traffic_groups g ON g.group_key=s.group_key WHERE g.outcome='policy_deny' AND g.subtype='forward' AND ".fg_identity_scope('g');
            foreach(port_stream($sql,$args) as $bucket){
                $n=(int)$bucket['matched_records'];$nativeRecords+=$n;$identity=json_decode($bucket['identity_json'],true,512,JSON_THROW_ON_ERROR);
                $r=port_fact($identity,'t:'.strtolower($bucket['native_key']),(int)$bucket['sample_id'],$n,$bucket['first_event_at'],$bucket['last_event_at']);if(port_matches($r,$filters))$rows[$r['key']]=$r;
            }
        }
    }
    // Missing old membership or an unavailable derived index must never silently drop a record.
    if($wm===null||$nativeRecords!==$originals){
        $rows=[];[$sql,$args]=port_raw_rows($from,$to,$filters);
        foreach(port_stream($sql,$args) as $event){
            $identity=$event['identity_json']!==null?json_decode($event['identity_json'],true,512,JSON_THROW_ON_ERROR):port_raw_identity(json_decode($event['fields'],true,512,JSON_THROW_ON_ERROR));
            $key=$event['identity_json']!==null?'t:'.strtolower($event['native_key']):'e:'.$event['id'];$r=port_fact($identity,$key,(int)$event['id'],1,$event['event_at'],$event['event_at']);if(!port_matches($r,$filters))continue;
            if(!isset($rows[$key]))$rows[$key]=$r;
            else{$old=&$rows[$key];$old['records']++;$old['first_event_at']=min($old['first_event_at'],$r['first_event_at']);if([$r['last_event_at'],$r['sample_id']]>[$old['last_event_at'],$old['sample_id']]){$old['last_event_at']=$r['last_event_at'];$old['sample_id']=$r['sample_id'];}unset($old);}
        }
    }
    $names=[];if(!$dashboard)foreach(query('SELECT policyid,poluuid,name FROM '.fg_scoped_table('device_policies').' p ORDER BY policyid,poluuid,name') as $p)if($p['poluuid']!=='')$names[(int)$p['policyid']][strtolower($p['poluuid'])]=$p['name'];
    $devices=[];foreach(query('SELECT ip,name FROM '.fg_scoped_table('device_sources').' s') as $s)$devices[port_ip($s['ip'])]=$s['name'];
    $rank=['ports'=>[],'sources'=>[],'targets'=>[],'policies'=>[]];$categories=[];$denials=[];$total=['records'=>0,'groups'=>count($rows),'repeated_groups'=>0,'sources'=>0,'targets'=>0,'ports'=>0,'first_event_at'=>null,'last_event_at'=>null];
    foreach($rows as &$r){
        $r['source_name']=$devices[$r['source']]??'';$r['policy_name']=$r['poluuid']!==''?($names[$r['policyid']][strtolower($r['poluuid'])]??''):'';$n=$r['records'];$total['records']+=$n;$total['repeated_groups']+=(int)($n>1);$total['first_event_at']=$total['first_event_at']===null?$r['first_event_at']:min($total['first_event_at'],$r['first_event_at']);$total['last_event_at']=max($total['last_event_at']??'',$r['last_event_at']);
        $categories[$r['category']]=($categories[$r['category']]??0)+$n;$denials[$r['denial']]=($denials[$r['denial']]??0)+$n;
        if($dashboard)continue;
        $spec=['ports'=>[$r['protocol_label'].'/'.($r['port']??'missing'),['label'=>$r['protocol_label'].' · '.($r['port']??'Port yok'),'detail'=>$r['service'],'filter'=>['proto'=>$r['protocol']===null?'missing':(string)$r['protocol'],'number'=>$r['port']===null?'missing':(string)$r['port']]]],'sources'=>[$r['source'],['label'=>$r['source']?:'Kaynak IP yok','detail'=>$r['source_name'],'filter'=>['source'=>$r['source']?:'missing']]],'targets'=>[$r['target'],['label'=>$r['target']?:'Hedef IP yok','detail'=>'Engellenen hedef IP','filter'=>['target'=>$r['target']?:'missing']]],'policies'=>[(string)$r['policyid'],['label'=>$r['policyid']>=0?'Policy '.$r['policyid']:'Policy bilgisi yok','detail'=>$r['policyid']===0?$r['reason']:$r['policy_name'],'filter'=>['policy'=>(string)$r['policyid']]]]];
        foreach($spec as $dimension=>[$key,$facts]){if(!isset($rank[$dimension][$key]))$rank[$dimension][$key]=$facts+['key'=>$key,'records'=>0];$rank[$dimension][$key]['records']+=$n;}
    }unset($r);
    foreach(['sources','targets','ports'] as $k)$total[$k]=count($rank[$k]);
    if($dashboard)return port_dashboard($rows,$total,$from,$to);
    foreach($rank as &$items){usort($items,fn($a,$b)=>($b['records']<=>$a['records'])?:strcmp($a['key'],$b['key']));$items=array_slice($items,0,8);}unset($items);
    usort($rows,fn($a,$b)=>($b['records']<=>$a['records'])?:strcmp($b['last_event_at'],$a['last_event_at'])?:strcmp($a['key'],$b['key']));$size=50;$pages=max(1,(int)ceil(count($rows)/$size));$page=min($page,$pages);$rows=array_slice($rows,($page-1)*$size,$size);
    if($rows){$samples=query('SELECT id,fields FROM events e WHERE '.fg_event_scope('e').' AND id IN ('.implode(',',array_fill(0,count($rows),'?')).')',array_column($rows,'sample_id'));$byId=[];foreach($samples as $s)$byId[$s['id']]=json_decode($s['fields'],true);foreach($rows as &$r)$r['log_service']=$byId[$r['sample_id']]['service']??'';unset($r);}
    $ordered=[];foreach(PORT_CATEGORIES as $k=>$label)if(isset($categories[$k]))$ordered[$k]=$categories[$k];$categories=$ordered;
    $allow=[];$config=event_feature_allowed('api_polling')?fg_cached_config():['policies'=>[]];foreach($config['policies'] as $p)if(($p['action']??'')==='accept'&&($p['status']??'enable')==='enable'&&($p['service']??[])&&$p['service']!==['ALL'])$allow[]=['id'=>$p['policyid'],'name'=>$p['name']??'','services'=>$p['service']];
    return ['scope'=>['from_utc'=>$from,'to_utc'=>$to,'traffic'=>'forward','outcome'=>'policy_deny'],'filters'=>$filters,'totals'=>$total,'rankings'=>$rank,'categories'=>array_map(fn($key,$n)=>['key'=>$key,'label'=>PORT_CATEGORIES[$key],'records'=>$n],array_keys($categories),array_values($categories)),'denials'=>$denials,'groups'=>$rows,'page'=>$page,'page_size'=>$size,'pages'=>$pages,'current_allow_policies'=>array_slice($allow,0,50),'current_policy_fresh'=>(bool)($config['health']['policies']['fresh']??false),'current_policy_observed_at'=>$config['health']['policies']['observed_at']??null,'counting'=>'original_denied_forward_records','generated_at'=>gmdate('c')];
}
/** One source/port pair can span destinations, policies and native repeat groups. */
function port_dashboard(array $groups,array $total,string $from,string $to): array {
    $ports=[];$pairs=[];$transportRecords=0;
    foreach($groups as $r){
        if($r['port']===null||!in_array($r['protocol'],[6,17],true))continue;
        $key=$r['protocol'].'/'.$r['port'];$n=$r['records'];$transportRecords+=$n;
        $filter=['number'=>(string)$r['port'],'proto'=>(string)$r['protocol']];
        if(!isset($ports[$key]))$ports[$key]=['key'=>$key,'port'=>$r['port'],'protocol'=>$r['protocol'],'label'=>$r['protocol_label'].' · '.$r['port'],'service'=>$r['service'],'records'=>0,'groups'=>0,'source_ips'=>[],'filter'=>$filter,'first_event_at'=>$r['first_event_at'],'last_event_at'=>$r['last_event_at']];
        $p=&$ports[$key];$p['records']+=$n;$p['groups']++;$p['first_event_at']=min($p['first_event_at'],$r['first_event_at']);$p['last_event_at']=max($p['last_event_at'],$r['last_event_at']);
        if(filter_var($r['source'],FILTER_VALIDATE_IP)){
            $p['source_ips'][$r['source']]=true;$pair=$key.'|'.$r['source'];
            if(!isset($pairs[$pair]))$pairs[$pair]=['key'=>$pair,'port_key'=>$key,'source'=>$r['source'],'name'=>$r['source_name'],'port'=>$r['port'],'protocol'=>$r['protocol'],'port_label'=>$p['label'],'records'=>0,'groups'=>0,'filter'=>['source'=>$r['source']]+$filter,'first_event_at'=>$r['first_event_at'],'last_event_at'=>$r['last_event_at']];
            $q=&$pairs[$pair];$q['records']+=$n;$q['groups']++;$q['first_event_at']=min($q['first_event_at'],$r['first_event_at']);$q['last_event_at']=max($q['last_event_at'],$r['last_event_at']);unset($q);
        }
        unset($p);
    }
    foreach($ports as &$p){$p['sources']=count($p['source_ips']);unset($p['source_ips']);}unset($p);
    $sort=fn($a,$b)=>($b['records']<=>$a['records'])?:strcmp($a['key'],$b['key']);
    usort($ports,$sort);$repeats=array_values(array_filter($pairs,fn($p)=>$p['records']>=2));usort($repeats,$sort);
    $portCount=count($ports);$repeatCount=count($repeats);$ports=array_slice($ports,0,5);$shown=array_fill_keys(array_column($ports,'key'),true);
    $repeats=array_slice(array_values(array_filter($repeats,fn($p)=>isset($shown[$p['port_key']]))),0,5);
    return ['device_id'=>(int)fg_selected_device()['id'],'scope'=>['from_utc'=>$from,'to_utc'=>$to,'traffic'=>'forward','outcome'=>'policy_deny'],'totals'=>['records'=>$total['records'],'transport_records'=>$transportRecords,'unclassified_records'=>$total['records']-$transportRecords,'groups'=>$total['groups'],'ports'=>$portCount,'repeated_source_ports'=>$repeatCount],'ports'=>$ports,'repeated_sources'=>$repeats,'repeat_minimum'=>2,'source_ranking_scope'=>'displayed_ports','limit'=>5,'counting'=>'original_denied_forward_records','generated_at'=>gmdate('c')];
}
function port_page(string $name): int {
    $value=$_GET[$name]??'1';if(!is_string($value)||!preg_match('/^[1-9][0-9]{0,5}$/D',$value))throw new InvalidArgumentException('Sayfa numarası geçersiz.');return (int)$value;
}
/** A report group expands only within the selected half-open time range and device. */
function port_records(string $select,string $join,bool $export=false): array {
    [$from,$to]=scope();$filters=port_filters();$key=$_GET['port_group']??'';
    if(!is_string($key)||!preg_match('/^(?:t:[a-f0-9]{64}|e:[1-9][0-9]{0,19})$/D',$key))throw new InvalidArgumentException('Geçerli bir port grubu seçin.');
    $params=[];
    if($key[0]==='t'){
        $g=query("SELECT identity_json FROM traffic_groups g WHERE ".fg_identity_scope('g')." AND g.outcome='policy_deny' AND g.subtype='forward' AND g.group_key=UNHEX(?)",[substr($key,2)])[0]??null;
        if(!$g)return ['http_status'=>404,'error'=>'Port grubu bu cihazda bulunamadı.'];
        $identity=json_decode($g['identity_json'],true,512,JSON_THROW_ON_ERROR);$where='tgm.group_key=UNHEX(?)';$params[] = substr($key,2);
    }else{
        $g=query("SELECT fields FROM events e WHERE ".fg_event_scope('e')." AND e.id=? AND e.type='traffic' AND e.subtype='forward' AND e.outcome='policy_deny'",[substr($key,2)])[0]??null;
        if(!$g)return ['http_status'=>404,'error'=>'Port kaydı bu cihazda bulunamadı.'];
        $identity=port_raw_identity(json_decode($g['fields'],true,512,JSON_THROW_ON_ERROR));$where='e.id=?';$params[]=substr($key,2);
    }
    if(!port_matches(port_fact($identity,$key,0,0,$from,$to),$filters))return ['http_status'=>404,'error'=>'Bu grup seçili filtrelere ait değil.'];
    $where.=' AND '.fg_event_scope('e')." AND e.type='traffic' AND e.subtype='forward' AND e.outcome='policy_deny' AND e.event_at>=? AND e.event_at<?";array_push($params,$from,$to);
    $count=(int)query("SELECT COUNT(*) n FROM events e LEFT JOIN traffic_event_groups tgm ON tgm.event_id=e.id WHERE $where",$params)[0]['n'];
    if($export&&$count>10000)return ['http_status'=>422,'error'=>'Dışa aktarım 10.000 kayıtla sınırlı; tarih aralığını daraltın.'];
    $size=$export?10000:50;$page=min(port_page('port_records_page'),max(1,(int)ceil($count/$size)));$offset=($page-1)*$size;
    $rows=query("SELECT $select FROM events e $join WHERE $where ORDER BY e.event_at DESC,e.id DESC LIMIT $size OFFSET $offset",$params);
    foreach($rows as &$r){$f=json_decode($r['fields'],true);$r['protocol']=$f['proto']??'';$r['service']=$f['service']??'';$r['srcport']=$f['srcport']??'';$r=decorate($r);}unset($r);
    return ['rows'=>$rows,'total'=>$count,'page'=>$page,'page_size'=>$size,'pages'=>max(1,(int)ceil($count/$size)),'group'=>$key,'scope'=>['from_utc'=>$from,'to_utc'=>$to]];
}
