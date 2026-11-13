<?php
declare(strict_types=1);

final class AllowedTrafficUnavailable extends RuntimeException {}
const ALLOWED_TRAFFIC_KINDS=['traffic'=>'Trafik izni / kapanış kaydı','web'=>'Web filtresi gözlemi','app'=>'Uygulama kontrolü gözlemi','dns'=>'DNS sorgusu','tls'=>'TLS denetim gözlemi','security'=>'Güvenlik profili gözlemi'];
const ALLOWED_TRAFFIC_MODULES=['forward','local','webfilter','app-ctrl','dns','ssl','ips','virus'];
const ALLOWED_TRAFFIC_RISKS=['low','elevated','medium','high','critical','unknown','high_or_critical'];
const ALLOWED_TRAFFIC_RANK_LIMIT=50000;

/** Reports use the same committed index snapshot; they never infer permission from observed. */
function allowed_traffic_read(callable $work): array {
    fg_require_access();$own=!db()->inTransaction();if($own)db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{$value=$work();if($own)db()->commit();return $value;}
    catch(Throwable $e){if($own&&db()->inTransaction())db()->rollBack();if($e instanceof PDOException&&$e->getCode()==='42S02')throw new AllowedTrafficUnavailable('İzin verilen trafik indeksi hazır değil.');throw $e;}
}
function allowed_traffic_text(string $key,int $max): string {
    $value=$_GET['allowed_'.$key]??'';
    if(!is_string($value)||strlen($value)>$max||!mb_check_encoding($value,'UTF-8')||preg_match('/[\x00-\x1f\x7f]/u',$value))throw new InvalidArgumentException('Trafik inceleme filtresi geçersiz.');
    return $value;
}
function allowed_traffic_filters(): array {
    $limits=['source'=>45,'target_key'=>64,'policy'=>11,'poluuid'=>40,'profile'=>640,'profile_missing'=>1,'module'=>40,'action'=>48,'evidence'=>24,'risk'=>32,'category'=>640,'web'=>1,'group'=>64];$filters=[];
    foreach($limits as $key=>$limit)$filters[$key]=allowed_traffic_text($key,$limit);
    if($filters['source']!==''&&$filters['source']!=='missing'){
        if(!filter_var($filters['source'],FILTER_VALIDATE_IP))throw new InvalidArgumentException('Geçerli bir kaynak IP girin.');
        $filters['source']=inet_ntop(inet_pton($filters['source']));
    }
    foreach(['target_key','group'] as $key)if($filters[$key]!==''&&!preg_match('/^[a-f0-9]{64}$/D',$filters[$key]))throw new InvalidArgumentException('Trafik grubu / hedef anahtarı geçersiz.');
    if($filters['policy']!==''&&(!preg_match('/^(?:-1|0|[1-9][0-9]{0,9})$/D',$filters['policy'])||(float)$filters['policy']>2147483647))throw new InvalidArgumentException('Policy numarası geçersiz.');
    foreach(['profile_missing','web'] as $key)if(!in_array($filters[$key],['','0','1'],true))throw new InvalidArgumentException('Trafik kapsamı geçersiz.');
    if($filters['profile']!==''&&$filters['profile_missing']==='1')throw new InvalidArgumentException('Profil filtreleri birbiriyle çelişiyor.');
    if($filters['module']!==''&&!in_array($filters['module'],ALLOWED_TRAFFIC_MODULES,true))throw new InvalidArgumentException('Trafik modülü geçersiz.');
    if($filters['evidence']!==''&&!array_key_exists($filters['evidence'],ALLOWED_TRAFFIC_KINDS))throw new InvalidArgumentException('Trafik kanıtı türü geçersiz.');
    if($filters['risk']!==''&&!in_array($filters['risk'],ALLOWED_TRAFFIC_RISKS,true))throw new InvalidArgumentException('Risk filtresi geçersiz.');
    return $filters;
}
function allowed_traffic_where(array $filters,string $alias='d'): array {
    $where=[fg_event_scope($alias)];$args=[];
    foreach(['source'=>'srcip','policy'=>'policyid','poluuid'=>'poluuid','profile'=>'profile','module'=>'subtype','action'=>'action','evidence'=>'evidence_kind','category'=>'category'] as $key=>$column){
        if($filters[$key]==='')continue;
        if($key==='source'&&$filters[$key]==='missing'){$where[]="$alias.srcip=''";continue;}
        if($key==='poluuid'&&$filters[$key]==='missing'){$where[]="$alias.poluuid=''";continue;}
        $where[]="$alias.$column=?";$args[]=$filters[$key];
        if(in_array($key,['poluuid','profile','category'],true)){$where[]="BINARY $alias.$column=BINARY ?";$args[]=$filters[$key];}
    }
    if($filters['profile_missing']==='1')$where[]="$alias.profile=''";
    if($filters['risk']==='high_or_critical')$where[]="$alias.risk IN ('high','critical')";
    elseif($filters['risk']!==''){$where[]="$alias.risk=?";$args[]=$filters['risk'];}
    if($filters['web']!==''){$where[]="$alias.web_observation=?";$args[]=(int)$filters['web'];}
    foreach(['target_key'=>'target_key','group'=>'fingerprint'] as $key=>$column)if($filters[$key]!==''){$where[]="$alias.$column=UNHEX(?)";$args[]=$filters[$key];}
    return [implode(' AND ',$where),$args];
}
function allowed_traffic_index(): array {
    $row=query('SELECT version,event_id,scanned_records,ready,updated_at,UTC_TIMESTAMP(6) measured_at FROM allowed_index_state WHERE id=1')[0]??null;
    if(!$row||(int)$row['version']!==1)throw new AllowedTrafficUnavailable('İzin verilen trafik indeksi hazır değil.');
    $watermark=(string)$row['event_id'];
    if(!preg_match('/^(?:0|[1-9][0-9]{0,19})$/D',$watermark))throw new AllowedTrafficUnavailable('Trafik indeksinin durumu doğrulanamadı.');
    $total=query('SELECT COALESCE(SUM(line_number-invalid_rows),0) records FROM source_files')[0]['records'];$scanned=(int)$row['scanned_records'];$total=(int)$total;
    $pending=$total>=$scanned?$total-$scanned:null;$age=$row['updated_at']===null?null:strtotime($row['measured_at'].' UTC')-strtotime($row['updated_at'].' UTC');$fresh=$age!==null&&$age>=-5&&$age<=180;$ready=(bool)$row['ready'];
    return ['available'=>true,'ready'=>$ready,'fresh'=>$fresh,'partial'=>!$ready||!$fresh||$pending===null||$pending>0,'pending_records'=>$pending,'pending_scope'=>'all_devices_index','updated_at'=>$row['updated_at'],'watermark'=>$watermark,'raw_tail_included'=>false];
}
/** Whole hours use compact counts; fractional edges retain exact original-event bounds. */
function allowed_traffic_buckets(array $filters,string $from,string $to,string $watermark): array {
    [$where,$values]=allowed_traffic_where($filters);$start=new DateTimeImmutable($from,new DateTimeZone('UTC'));$end=new DateTimeImmutable($to,new DateTimeZone('UTC'));
    $floor=$start->setTime((int)$start->format('H'),0);$ceil=$start==$floor?$start:$floor->modify('+1 hour');$last=$end->setTime((int)$end->format('H'),0);$parts=[];$args=[];
    $selective=false;foreach(['source','target_key','policy','poluuid','profile','profile_missing','module','action','evidence','risk','category','group'] as $key)if(!in_array($filters[$key],['','0'],true)){$selective=true;break;}
    // Broad reports aggregate narrow time buckets before looking up dimensions.
    // This avoids reading the same historical identity for every event/hour.
    $dimensionWhere=$selective?"$where AND ":'';$dimensionArgs=$selective?$values:[];
    if($ceil<$last){
        $hourFrom=$selective?'allowed_dimensions d JOIN allowed_hour_counts h ON h.dimension_id=d.id':'allowed_hour_counts h';
        $parts[]="SELECT h.dimension_id,SUM(h.records) records,MIN(h.first_event_at) first_event_at,MAX(h.last_event_at) last_event_at FROM $hourFrom WHERE {$dimensionWhere}h.hour_at>=? AND h.hour_at<? AND h.last_event_id<=? GROUP BY h.dimension_id";
        array_push($args,...array_merge($dimensionArgs,[$ceil->format('Y-m-d H:i:s.u'),$last->format('Y-m-d H:i:s.u'),$watermark]));$edges=[[$from,$ceil->format('Y-m-d H:i:s.u')],[$last->format('Y-m-d H:i:s.u'),$to]];
    }else $edges=[[$from,$to]];
    $factFrom=$selective?'allowed_dimensions d STRAIGHT_JOIN allowed_event_index f FORCE INDEX(dimension_time) ON f.dimension_id=d.id':'allowed_event_index f FORCE INDEX(event_time)';
    foreach($edges as [$a,$b])if($a<$b){
        $parts[]="SELECT f.dimension_id,COUNT(*) records,MIN(f.event_at) first_event_at,MAX(f.event_at) last_event_at FROM $factFrom WHERE {$dimensionWhere}f.event_at>=? AND f.event_at<? AND f.event_id<=? GROUP BY f.dimension_id";
        array_push($args,...array_merge($dimensionArgs,[$a,$b,$watermark]));
    }
    $buckets='SELECT dimension_id,SUM(records) records,MIN(first_event_at) first_event_at,MAX(last_event_at) last_event_at FROM ('.implode(' UNION ALL ',$parts).') buckets GROUP BY dimension_id';
    if(!$selective)return ["SELECT b.* FROM ($buckets) b JOIN allowed_dimensions d ON d.id=b.dimension_id WHERE $where",array_merge($args,$values)];
    return [$buckets,$args];
}
function allowed_traffic_page(string $key): int {
    $value=allowed_traffic_text($key,6);if($value==='')return 1;
    if(!preg_match('/^[1-9][0-9]{0,5}$/D',$value)||(int)$value>100000)throw new InvalidArgumentException('Trafik sayfası geçersiz.');return (int)$value;
}
function allowed_traffic_target_label(string $kind,string $value): string {
    if($value!=='')return $value;return $kind==='dns_missing'?'DNS sorgu adı logda yok':'Hedef alanı logda yok';
}
function allowed_traffic_names(array $rows): array {
    $ips=[];$identities=[];foreach($rows as $row){$source=$row['source']??$row['srcip']??'';if($source!=='')$ips[$source]=true;if(isset($row['policyid'])&&($row['poluuid']??'')!=='')$identities[(int)$row['policyid'].'|'.$row['poluuid']]=[(int)$row['policyid'],$row['poluuid']];}
    $sources=[];$policies=[];
    if($ips){$keys=array_keys($ips);foreach(query('SELECT ip,name FROM '.fg_scoped_table('device_sources').' s WHERE ip IN ('.implode(',',array_fill(0,count($keys),'?')).')',$keys) as $row)$sources[$row['ip']]=$row['name'];}
    if($identities){$parts=[];$args=[];foreach($identities as [$id,$uuid]){$parts[]='(policyid=? AND poluuid=? AND BINARY poluuid=BINARY ?)';array_push($args,$id,$uuid,$uuid);}foreach(query('SELECT policyid,poluuid,name FROM '.fg_scoped_table('device_policies').' p WHERE '.implode(' OR ',$parts),$args) as $row)$policies[$row['policyid'].'|'.strtolower($row['poluuid'])]=$row['name'];}
    return [$sources,$policies];
}
function allowed_summary(): array {
    return allowed_traffic_read(function():array{
        $filters=allowed_traffic_filters();[$from,$to]=scope();$index=allowed_traffic_index();[$buckets,$args]=allowed_traffic_buckets($filters,$from,$to,$index['watermark']);
        $totals=['records'=>0,'groups'=>0,'sources'=>0,'web_records'=>0,'first_event_at'=>null,'last_event_at'=>null];$rankings=['targets'=>[],'sources'=>[],'policies'=>[],'profiles'=>[]];$rankKeys=0;$kindCounts=[];$reviewCounts=['high_risk'=>0,'tls_bypass'=>0,'monitor'=>0];
        $add=function(string $dimension,string $key,string $label,string $detail,array $filter,array $bucket)use(&$rankings,&$rankKeys):void{
            if(!isset($rankings[$dimension][$key])){
                if($rankKeys>=ALLOWED_TRAFFIC_RANK_LIMIT)throw new InvalidArgumentException('Bu aralıkta çok fazla farklı kaynak, hedef veya profil var. Tarih aralığını ya da kaynak / policy filtresini daraltın.');
                $rankKeys++;$rankings[$dimension][$key]=['key'=>$key,'label'=>$label,'detail'=>$detail,'records'=>0,'first_event_at'=>$bucket['first_event_at'],'last_event_at'=>$bucket['last_event_at'],'filter'=>$filter];
            }
            $item=&$rankings[$dimension][$key];$item['records']+=(int)$bucket['records'];$item['first_event_at']=min($item['first_event_at'],$bucket['first_event_at']);$item['last_event_at']=max($item['last_event_at'],$bucket['last_event_at']);
        };
        // One aggregate pass. Memory depends on distinct IPs/hostnames/profiles,
        // not raw records, URL paths or the richer source/target/port group count.
        $sql="SELECT d.srcip,d.policyid,d.poluuid,d.profile,d.subtype,d.evidence_kind,d.risk,d.action,d.target_kind,d.target_value,LOWER(HEX(d.target_key)) target_key,d.web_observation,b.records,b.first_event_at,b.last_event_at FROM ($buckets) b JOIN allowed_dimensions d ON d.id=b.dimension_id WHERE ".fg_event_scope('d');
        $pdo=db();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);$statement=null;
        try{$statement=$pdo->prepare($sql);$statement->execute($args);while($row=$statement->fetch()){
            $n=(int)$row['records'];$totals['records']+=$n;$totals['groups']++;$totals['first_event_at']=$totals['first_event_at']===null?$row['first_event_at']:min($totals['first_event_at'],$row['first_event_at']);$totals['last_event_at']=max($totals['last_event_at']??'',$row['last_event_at']);
            $kindCounts[$row['evidence_kind']]=($kindCounts[$row['evidence_kind']]??0)+$n;
            $source=$row['srcip'];$add('sources',$source,$source!==''?$source:'Kaynak IP alanı yok','',['allowed_source'=>$source!==''?$source:'missing'],$row);
            if((int)$row['web_observation']===1){$totals['web_records']+=$n;$add('targets',$row['target_key'],allowed_traffic_target_label($row['target_kind'],$row['target_value']),$row['target_kind']==='domain'?'Web hedefi':'Web kaydındaki hedef',['allowed_target_key'=>$row['target_key'],'allowed_web'=>'1'],$row);}
            $policyKey=$row['policyid'].'|'.$row['poluuid'];$policyFilter=['allowed_policy'=>(string)$row['policyid'],'allowed_poluuid'=>$row['poluuid']!==''?$row['poluuid']:'missing'];
            $add('policies',$policyKey,(int)$row['policyid']>=0?'Policy '.$row['policyid']:'Policy alanı yok','',$policyFilter,$row);
            $profileKey=hash('sha256',json_encode([$row['subtype'],$row['profile']],JSON_THROW_ON_ERROR));$add('profiles',$profileKey,$row['profile']!==''?$row['profile']:'Profil alanı yok',$row['subtype'],['allowed_module'=>$row['subtype'],'allowed_profile'=>$row['profile'],'allowed_profile_missing'=>$row['profile']!==''?'0':'1'],$row);
            if(in_array($row['risk'],['high','critical'],true))$reviewCounts['high_risk']+=$n;
            if($row['subtype']==='ssl'&&$row['action']==='bypass')$reviewCounts['tls_bypass']+=$n;
            if($row['action']==='monitor')$reviewCounts['monitor']+=$n;
        }}finally{if($statement)$statement->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
        $totals['sources']=count($rankings['sources'])-(isset($rankings['sources'][''])?1:0);
        foreach($rankings as &$rows){usort($rows,fn($a,$b)=>($b['records']<=>$a['records'])?:strcmp($a['key'],$b['key']));$rows=array_slice($rows,0,10);}unset($rows);
        $named=[];foreach($rankings['sources'] as $row)if($row['key']!=='')$named[]=['source'=>$row['key']];
        foreach($rankings['policies'] as $row)if(($row['filter']['allowed_poluuid']??'missing')!=='missing')$named[]=['policyid'=>(int)$row['filter']['allowed_policy'],'poluuid'=>$row['filter']['allowed_poluuid']];
        [$sourceNames,$policyNames]=allowed_traffic_names($named);
        foreach($rankings['sources'] as &$row)$row['detail']=$sourceNames[$row['key']]??'';unset($row);
        foreach($rankings['policies'] as &$row)$row['detail']=$policyNames[$row['filter']['allowed_policy'].'|'.strtolower($row['filter']['allowed_poluuid'])]??'';unset($row);
        $kinds=[];foreach($kindCounts as $key=>$count)$kinds[]=['key'=>$key,'label'=>ALLOWED_TRAFFIC_KINDS[$key]??'Log gözlemi','records'=>$count];usort($kinds,fn($a,$b)=>($b['records']<=>$a['records'])?:strcmp($a['key'],$b['key']));
        $review=[];$cases=[['high_risk','Yüksek / kritik risk',['allowed_risk'=>'high_or_critical'],'Risk seviyesi logdaki sınıflandırmadır; tek başına ihlal kanıtı değildir.'],['tls_bypass','TLS bypass',['allowed_module'=>'ssl','allowed_action'=>'bypass'],'TLS modülünün bypass eylemi kaydedildi.'],['monitor','Monitor eylemleri',['allowed_action'=>'monitor'],'Monitor kaydı gözlemdir; diğer güvenlik kontrollerinin sonucunu kanıtlamaz.']];
        foreach($cases as [$key,$label,$filter,$explanation])if($reviewCounts[$key]>0)$review[]=['key'=>$key,'label'=>$label,'records'=>$reviewCounts[$key],'filter'=>$filter,'explanation'=>$explanation];
        return ['scope'=>['from_utc'=>$from,'to_utc'=>$to,'connection_id'=>(int)fg_selected_device()['id']],'index'=>$index,'totals'=>$totals,'kinds'=>$kinds,'rankings'=>$rankings,'review'=>$review,'counting'=>'positive_log_observations','raw_tail_included'=>false];
    });
}
function allowed_groups(): array {
    return allowed_traffic_read(function():array{
        $filters=allowed_traffic_filters();[$from,$to]=scope();$index=allowed_traffic_index();$page=allowed_traffic_page('page');$size=50;[$buckets,$args]=allowed_traffic_buckets($filters,$from,$to,$index['watermark']);
        $totals=query("SELECT COUNT(*) total,COALESCE(SUM(records),0) records FROM ($buckets) b",$args)[0];$total=(int)$totals['total'];$pages=max(1,(int)ceil($total/$size));$page=min($page,$pages);$offset=($page-1)*$size;
        $rows=query("SELECT LOWER(HEX(d.fingerprint)) `key`,d.srcip source,d.target_kind,d.target_value,d.dstip,d.dstport,LOWER(HEX(d.target_key)) target_key,d.policyid,d.poluuid,d.profile,d.subtype module,d.evidence_kind kind,d.risk,d.action,d.app,d.category,b.records,b.first_event_at,b.last_event_at FROM ($buckets) b JOIN allowed_dimensions d ON d.id=b.dimension_id WHERE ".fg_event_scope('d')." ORDER BY b.records DESC,b.last_event_at DESC,d.fingerprint LIMIT $size OFFSET $offset",$args);[$sources,$policies]=allowed_traffic_names($rows);
        foreach($rows as &$row){$row['records']=(int)$row['records'];$row['policyid']=(int)$row['policyid'];$row['dstport']=$row['dstport']===null?null:(int)$row['dstport'];$row['source_name']=$sources[$row['source']]??'';$row['policy_name']=$row['poluuid']!==''?($policies[$row['policyid'].'|'.strtolower($row['poluuid'])]??''):'';$row['target_label']=allowed_traffic_target_label($row['target_kind'],$row['target_value']);$row['evidence']=$row['kind'];unset($row['target_value']);}unset($row);
        return ['scope'=>['from_utc'=>$from,'to_utc'=>$to,'connection_id'=>(int)fg_selected_device()['id']],'rows'=>$rows,'total'=>$total,'total_records'=>(int)$totals['records'],'page'=>$page,'pages'=>$pages,'page_size'=>$size,'index'=>$index];
    });
}
function allowed_group_events(): array {
    return allowed_traffic_read(function():array{
        $filters=allowed_traffic_filters();if($filters['group']==='')throw new InvalidArgumentException('Geçerli bir trafik grubu seçin.');[$from,$to]=scope();$index=allowed_traffic_index();$page=allowed_traffic_page('records_page');$size=50;[$where,$args]=allowed_traffic_where($filters);
        $where.=' AND '.fg_event_scope('e').' AND f.event_at>=? AND f.event_at<? AND f.event_id<=? AND e.event_at=f.event_at';array_push($args,$from,$to,$index['watermark']);
        $joined="FROM allowed_dimensions d JOIN allowed_event_index f FORCE INDEX(dimension_time) ON f.dimension_id=d.id JOIN events e ON e.id=f.event_id WHERE $where";
        $total=(int)query("SELECT COUNT(*) total $joined",$args)[0]['total'];$pages=max(1,(int)ceil($total/$size));$page=min($page,$pages);$offset=($page-1)*$size;
        $rows=query("SELECT CAST(e.id AS CHAR) id,e.event_at,e.srcip,e.dstip,e.dstport,e.hostname,e.policyid,e.profile,e.subtype module,e.action $joined ORDER BY e.event_at DESC,e.id DESC LIMIT $size OFFSET $offset",$args);
        foreach($rows as &$row){$row['policyid']=(int)$row['policyid'];$row['dstport']=$row['dstport']===null?null:(int)$row['dstport'];}unset($row);
        return ['scope'=>['from_utc'=>$from,'to_utc'=>$to,'connection_id'=>(int)fg_selected_device()['id']],'rows'=>$rows,'total'=>$total,'page'=>$page,'pages'=>$pages,'page_size'=>$size,'index'=>$index];
    });
}
